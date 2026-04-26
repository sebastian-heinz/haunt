//! Unified breakpoint subsystem: software int3, hardware (DR0–DR3), and page (PAGE_GUARD).
//!
//! Install ordering keeps the registry consistent with on-CPU / in-memory state when
//! the VEH handler runs:
//! - Software / page: registry lock held across the memory write.
//! - Hardware: registry entry inserted before any thread's DR registers are set.

pub mod halt;

mod arch;
mod hardware;
mod page;
mod software;
mod veh;

pub use hardware::apply_current_thread as apply_hw_to_current_thread;
pub use hardware::{attach_counters, can_apply, enumerate_threads, read_dr_state};

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use haunt_core::{BpError, BpHooks, BpId, BpKind, BpOptions, BpSpec, BreakpointInfo};
use windows_sys::Win32::System::Diagnostics::Debug::AddVectoredExceptionHandler;

pub(crate) struct Entry {
    pub id: BpId,
    pub addr: usize,
    pub kind: BpKind,
    pub options: BpOptions,
    /// Shared via `Arc` so the VEH hot path can clone in O(1) (refcount
    /// bump) instead of deep-cloning the parsed AST per hit.
    pub hooks: Arc<BpHooks>,
    pub hits: u64,
    pub state: KindState,
    /// Original `name=module!symbol` if the BP was set by name. Surfaced
    /// by `bp list` so users can see what they asked for next to the
    /// resolved address — important when the resolution went through a
    /// forwarder (e.g. `kernel32!ExitProcess` lands on
    /// `ntdll!RtlExitUserProcess`).
    pub requested_name: Option<String>,
}

impl Entry {
    fn new(
        id: BpId,
        addr: usize,
        kind: BpKind,
        options: BpOptions,
        hooks: BpHooks,
        state: KindState,
        requested_name: Option<String>,
    ) -> Self {
        Self {
            id,
            addr,
            kind,
            options,
            hooks: Arc::new(hooks),
            hits: 0,
            state,
            requested_name,
        }
    }
}

pub(crate) enum KindState {
    Software(software::State),
    Hardware(hardware::State),
    Page(page::State),
}

static REGISTRY: OnceLock<Mutex<HashMap<BpId, Entry>>> = OnceLock::new();
static VEH_INSTALLED: OnceLock<()> = OnceLock::new();
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) fn registry() -> &'static Mutex<HashMap<BpId, Entry>> {
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn ensure_veh() {
    VEH_INSTALLED.get_or_init(|| {
        unsafe { AddVectoredExceptionHandler(1, Some(veh::handler)) };
    });
}

pub fn set(spec: BpSpec) -> Result<BpId, BpError> {
    ensure_veh();
    let id = BpId(NEXT_ID.fetch_add(1, Ordering::Relaxed));
    let BpSpec { addr, kind, options, hooks, requested_name } = spec;
    match kind {
        BpKind::Software => set_software(id, addr, options, hooks, requested_name),
        BpKind::Hardware { access, size } => {
            set_hardware(id, addr, access, size, options, hooks, requested_name)
        }
        BpKind::Page { access, size } => {
            set_page(id, addr, access, size, options, hooks, requested_name)
        }
    }
}

fn set_software(
    id: BpId,
    addr: usize,
    options: BpOptions,
    hooks: BpHooks,
    requested_name: Option<String>,
) -> Result<BpId, BpError> {
    let mut reg = registry().lock().map_err(|_| BpError::Internal)?;
    reject_addr_conflict(&reg, addr)?;
    // SW install runs `VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE)` which
    // strips PAGE_GUARD off the entire page (Win32 protections are
    // page-granular, not byte-granular). Even a transient strip silently
    // disables an overlapping page BP between the install and the protect-
    // restore. Reject up front rather than ship a footgun.
    reject_sw_overlapping_page_bp(&reg, addr)?;
    let state = software::install(addr)?;
    reg.insert(
        id,
        Entry::new(
            id,
            addr,
            BpKind::Software,
            options,
            hooks,
            KindState::Software(state),
            requested_name,
        ),
    );
    Ok(id)
}

fn set_page(
    id: BpId,
    addr: usize,
    access: haunt_core::BpAccess,
    size: usize,
    options: BpOptions,
    hooks: BpHooks,
    requested_name: Option<String>,
) -> Result<BpId, BpError> {
    let mut reg = registry().lock().map_err(|_| BpError::Internal)?;
    reject_addr_conflict(&reg, addr)?;
    // Symmetric with set_software: a page BP whose pages contain a SW BP
    // address would race with that BP's int3 rearm (which VirtualProtects
    // the page back to its original protection, dropping PAGE_GUARD on
    // every hit).
    reject_page_covering_sw_bp(&reg, addr, size)?;
    let state = page::install(addr, access, size)?;
    reg.insert(
        id,
        Entry::new(
            id,
            addr,
            BpKind::Page { access, size },
            options,
            hooks,
            KindState::Page(state),
            requested_name,
        ),
    );
    Ok(id)
}

fn set_hardware(
    id: BpId,
    addr: usize,
    access: haunt_core::BpAccess,
    size: u8,
    options: BpOptions,
    hooks: BpHooks,
    requested_name: Option<String>,
) -> Result<BpId, BpError> {
    let slot = {
        let mut reg = registry().lock().map_err(|_| BpError::Internal)?;
        reject_addr_conflict(&reg, addr)?;
        let slot = allocate_hw_slot(&reg)?;
        reg.insert(
            id,
            Entry::new(
                id,
                addr,
                BpKind::Hardware { access, size },
                options,
                hooks,
                KindState::Hardware(hardware::State { slot }),
                requested_name,
            ),
        );
        slot
    };
    match hardware::install(addr, access, size, slot) {
        Ok(()) => Ok(id),
        Err(e) => {
            if let Ok(mut reg) = registry().lock() {
                reg.remove(&id);
            }
            Err(e)
        }
    }
}

fn reject_addr_conflict(reg: &HashMap<BpId, Entry>, addr: usize) -> Result<(), BpError> {
    if reg.values().any(|e| e.addr == addr) {
        Err(BpError::Conflict)
    } else {
        Ok(())
    }
}

fn reject_sw_overlapping_page_bp(
    reg: &HashMap<BpId, Entry>,
    sw_addr: usize,
) -> Result<(), BpError> {
    let sw_page = page::page_base(sw_addr);
    for e in reg.values() {
        if let KindState::Page(s) = &e.state {
            if s.pages.iter().any(|&(base, _)| base == sw_page) {
                return Err(BpError::Conflict);
            }
        }
    }
    Ok(())
}

fn reject_page_covering_sw_bp(
    reg: &HashMap<BpId, Entry>,
    page_addr: usize,
    page_size: usize,
) -> Result<(), BpError> {
    let ps = page::page_size();
    let start = page::page_base(page_addr);
    let end = page_addr.checked_add(page_size).ok_or(BpError::Unsupported)?;
    let end_page = end.saturating_add(ps - 1) & !(ps - 1);
    for e in reg.values() {
        if !matches!(e.state, KindState::Software(_)) {
            continue;
        }
        let sw_page = page::page_base(e.addr);
        if sw_page >= start && sw_page < end_page {
            return Err(BpError::Conflict);
        }
    }
    Ok(())
}

fn allocate_hw_slot(reg: &HashMap<BpId, Entry>) -> Result<u8, BpError> {
    let mut used = [false; 4];
    for e in reg.values() {
        if let KindState::Hardware(s) = &e.state {
            if (s.slot as usize) < 4 {
                used[s.slot as usize] = true;
            }
        }
    }
    used.iter()
        .position(|&b| !b)
        .map(|i| i as u8)
        .ok_or(BpError::NoHwSlot)
}

pub fn clear(id: BpId) -> Result<(), BpError> {
    // Restore on-CPU / in-memory state BEFORE removing the entry so VEH never
    // sees "byte still 0xCC / page still PAGE_GUARD but no matching registry
    // entry" (which would propagate the exception unhandled and crash the host).
    // HW differs: clearing DR registers requires suspending other threads, which
    // we can't do under the registry lock — but the race is benign there
    // (`slot_fired` with no matching entry just clears DR6 and resumes).
    let mut reg = registry().lock().map_err(|_| BpError::Internal)?;
    let entry = reg.get(&id).ok_or(BpError::NotFound)?;
    match &entry.state {
        KindState::Software(s) => {
            unsafe { software::write_byte(entry.addr, s.original_byte) }
                .map_err(|_| BpError::Internal)?;
        }
        KindState::Page(s) => {
            page::restore(&s.pages)?;
        }
        KindState::Hardware(_) => {
            // Defer: DR clear happens after lock release.
        }
    }
    // Removed instead of `expect("present, just verified")`: panic=abort on a
    // cdylib means *any* panic kills the host, and the project's no-panic
    // policy applies even when an invariant looks bulletproof.
    let entry = match reg.remove(&id) {
        Some(e) => e,
        None => return Err(BpError::Internal),
    };
    drop(reg);

    if let KindState::Hardware(s) = entry.state {
        hardware::uninstall(s)?;
    }
    Ok(())
}

pub fn list() -> Vec<BreakpointInfo> {
    let reg = match registry().lock() {
        Ok(g) => g,
        Err(_) => return Vec::new(),
    };
    reg.values()
        .map(|e| BreakpointInfo {
            id: e.id,
            addr: e.addr,
            kind: e.kind,
            options: e.options,
            hits: e.hits,
            log: e.hooks.log_text().map(|s| s.to_string()),
            cond: e.hooks.cond_text().map(|s| s.to_string()),
            requested_name: e.requested_name.clone(),
        })
        .collect()
}

/// Remove a breakpoint entry by id from the registry without touching platform state.
/// Used by the VEH handler's one-shot cleanup path — the byte has already been
/// restored by the time we get here.
pub(crate) fn remove_entry_internal(id: BpId) {
    if let Ok(mut reg) = registry().lock() {
        reg.remove(&id);
    }
}
