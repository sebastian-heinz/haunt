//! Unified breakpoint subsystem: software int3, hardware (DR0–DR3), and page (PAGE_GUARD).
//!
//! Install ordering keeps the registry consistent with on-CPU / in-memory state when
//! the VEH handler runs:
//! - Software / page: registry lock held across the memory write.
//! - Hardware: registry entry inserted before any thread's DR registers are set.

pub mod halt;

mod hardware;
mod page;
mod software;
mod veh;

pub use hardware::apply_current_thread as apply_hw_to_current_thread;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use haunt_core::{BpError, BpId, BpKind, BpOptions, BpSpec, BreakpointInfo};
use windows_sys::Win32::System::Diagnostics::Debug::AddVectoredExceptionHandler;

pub(crate) struct Entry {
    pub id: BpId,
    pub addr: usize,
    pub kind: BpKind,
    pub options: BpOptions,
    pub hits: u64,
    pub state: KindState,
}

impl Entry {
    fn new(id: BpId, addr: usize, kind: BpKind, options: BpOptions, state: KindState) -> Self {
        Self { id, addr, kind, options, hits: 0, state }
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
    match spec.kind {
        BpKind::Software => set_software(id, spec.addr, spec.options),
        BpKind::Hardware { access, size } => set_hardware(id, spec.addr, access, size, spec.options),
        BpKind::Page { access, size } => set_page(id, spec.addr, access, size, spec.options),
    }
}

fn set_software(id: BpId, addr: usize, options: BpOptions) -> Result<BpId, BpError> {
    let mut reg = registry().lock().map_err(|_| BpError::Internal)?;
    let state = software::install(addr)?;
    reg.insert(id, Entry::new(id, addr, BpKind::Software, options, KindState::Software(state)));
    Ok(id)
}

fn set_page(
    id: BpId,
    addr: usize,
    access: haunt_core::BpAccess,
    size: usize,
    options: BpOptions,
) -> Result<BpId, BpError> {
    let mut reg = registry().lock().map_err(|_| BpError::Internal)?;
    let state = page::install(addr, access, size)?;
    reg.insert(
        id,
        Entry::new(id, addr, BpKind::Page { access, size }, options, KindState::Page(state)),
    );
    Ok(id)
}

fn set_hardware(
    id: BpId,
    addr: usize,
    access: haunt_core::BpAccess,
    size: u8,
    options: BpOptions,
) -> Result<BpId, BpError> {
    let slot = {
        let mut reg = registry().lock().map_err(|_| BpError::Internal)?;
        let slot = allocate_hw_slot(&reg)?;
        reg.insert(
            id,
            Entry::new(
                id,
                addr,
                BpKind::Hardware { access, size },
                options,
                KindState::Hardware(hardware::State { slot }),
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
    let mut reg = registry().lock().map_err(|_| BpError::Internal)?;
    let entry = reg.remove(&id).ok_or(BpError::NotFound)?;
    drop(reg);
    match entry.state {
        KindState::Software(s) => software::uninstall(entry.addr, s),
        KindState::Hardware(s) => hardware::uninstall(s),
        KindState::Page(s) => page::uninstall(s),
    }
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
