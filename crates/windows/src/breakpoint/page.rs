//! Page breakpoint via PAGE_GUARD over a range of pages. Fires EXCEPTION_GUARD_PAGE
//! on any access; re-armed in the single-step handler.
//!
//! Unlike hardware BPs, there is no per-access selectivity — PAGE_GUARD
//! traps reads, writes, and executes uniformly. The HTTP layer rejects
//! `access=` for `kind=page` so users with a write-only intent are not
//! quietly given any-access behaviour.

use std::collections::HashSet;
use std::mem::{size_of, MaybeUninit};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use haunt_core::{warn, BpError};

use windows_sys::Win32::System::Memory::{
    VirtualProtect, VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD,
    PAGE_PROTECTION_FLAGS,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

pub struct State {
    pub pages: Vec<(usize, u32)>, // (page_base, original_protect)
}

static PAGE_SIZE: AtomicUsize = AtomicUsize::new(0);

/// Pages we set `PAGE_GUARD` on during an install attempt that then failed
/// AND that we couldn't restore via `VirtualProtect` during rollback. The
/// VEH consults this set on a guard fault that doesn't match any
/// registered page BP — without that recovery hook, the orphan would fall
/// through `EXCEPTION_CONTINUE_SEARCH` and kill the host.
///
/// Single global `Mutex<HashSet>`: install rollback is rare (a "second
/// `VirtualProtect` failed on a page the first one succeeded on" is a
/// memory-pressure or address-space-corruption corner case), and the
/// guard fault check is a single `contains` per orphan, both off the
/// hot path. Keeping the data structure simple avoids subtle races.
static ORPHAN_PAGES: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();

fn orphans() -> &'static Mutex<HashSet<usize>> {
    ORPHAN_PAGES.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Soft cap on the orphan set so a degenerate workflow (millions of
/// failed installs, or millions of clears with no fault to consume the
/// recovery marker) can't grow it unboundedly. When full, evict an
/// arbitrary existing entry rather than refusing the new one — keeping
/// the most recent entries gives racing threads the best chance of a
/// matching marker. The cap is high enough that any realistic session
/// stays well below it.
const ORPHAN_CAP: usize = 4096;

fn insert_orphan_capped(g: &mut HashSet<usize>, base: usize) {
    if g.len() >= ORPHAN_CAP {
        // Drop one arbitrary entry. HashSet has no FIFO; this is a
        // best-effort eviction.
        if let Some(&v) = g.iter().next() {
            g.remove(&v);
        }
    }
    g.insert(base);
}

/// Record `base` as a known orphan whose `PAGE_GUARD` we couldn't
/// restore. The VEH will clear it on first fault.
fn record_orphan(base: usize) {
    if let Ok(mut g) = orphans().lock() {
        insert_orphan_capped(&mut g, base);
    }
}

/// Mark each page in the BP's page list as an orphan so a thread
/// currently parked in `on_guard_page` waiting for the registry lock
/// can recover via the orphan path after we release the lock and
/// remove the registry entry. Without this, a `clear()` racing an
/// in-flight guard fault leaves the racing thread with no registry
/// match and no orphan match → `EXCEPTION_CONTINUE_SEARCH` → host kill.
///
/// Each entry is consumed by the first `take_orphan` call, so a
/// subsequent unrelated `PAGE_GUARD` on the same page (an antivirus
/// sentinel, etc.) is at most a one-time false positive.
pub fn mark_pages_for_clear_race_recovery(pages: &[(usize, u32)]) {
    if let Ok(mut g) = orphans().lock() {
        for &(base, _) in pages {
            insert_orphan_capped(&mut g, base);
        }
    }
}

/// If `addr` falls on a tracked orphan page, remove it from the set and
/// return `true`. The kernel auto-clears `PAGE_GUARD` on the fault that
/// got us here, so once the entry is removed the page is back to its
/// pre-install protection — no further `VirtualProtect` needed. Used by
/// the VEH's `on_guard_page` to recover hosts that would otherwise crash
/// on a leftover from a failed install.
pub fn take_orphan(addr: usize) -> bool {
    let base = page_base(addr);
    match orphans().lock() {
        Ok(mut g) => g.remove(&base),
        Err(_) => false,
    }
}

pub fn page_size() -> usize {
    let cached = PAGE_SIZE.load(Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }
    let mut si: MaybeUninit<SYSTEM_INFO> = MaybeUninit::uninit();
    unsafe { GetSystemInfo(si.as_mut_ptr()) };
    let sz = unsafe { si.assume_init() }.dwPageSize as usize;
    let sz = if sz == 0 { 4096 } else { sz };
    PAGE_SIZE.store(sz, Ordering::Relaxed);
    sz
}

/// Page base containing `addr`.
pub fn page_base(addr: usize) -> usize {
    let ps = page_size();
    addr & !(ps - 1)
}

pub fn install(addr: usize, size: usize) -> Result<State, BpError> {
    let ps = page_size();
    let start = addr & !(ps - 1);
    let end = addr.checked_add(size).ok_or(BpError::Unsupported)?;
    // `end + ps - 1` would wrap for `end` near `usize::MAX`, producing an
    // `end_page` of 0 and a silently-empty BP that never fires. Reject
    // up front instead.
    let end_page = end
        .checked_add(ps - 1)
        .ok_or(BpError::Unsupported)?
        & !(ps - 1);

    // Two failure modes both have to roll back, not just the second:
    // - `query_protect` failure mid-loop (uncommitted page, etc.) used to
    //   bail with `?` and leak `PAGE_GUARD` on every page we'd already
    //   set, with no entry in the registry — so the next access to any
    //   of those pages fell through `on_guard_page` and killed the host.
    // - `set_protect` failure rolls back, but if any rollback
    //   `VirtualProtect` itself fails the page stays guarded as an
    //   orphan with the same host-kill outcome.
    //
    // Both now go through a single rollback path that records any
    // unreversible page in `ORPHAN_PAGES`, where the VEH can recover it.
    let mut pages: Vec<(usize, u32)> = Vec::new();
    let mut cursor = start;
    let mut error: Option<BpError> = None;
    while cursor < end_page {
        let original = match query_protect(cursor) {
            Some(o) => o,
            None => {
                error = Some(BpError::Unwritable);
                break;
            }
        };
        if unsafe { set_protect(cursor, ps, original | PAGE_GUARD) }.is_err() {
            error = Some(BpError::Unwritable);
            break;
        }
        pages.push((cursor, original));
        cursor += ps;
    }

    if let Some(e) = error {
        warn!("page bp install: rolling back {} page(s)", pages.len());
        for (p, orig) in &pages {
            if unsafe { set_protect(*p, ps, *orig) }.is_err() {
                warn!(
                    "page bp install rollback: VirtualProtect(0x{p:x}) failed; \
                     tracking as orphan for VEH recovery"
                );
                record_orphan(*p);
            }
        }
        return Err(e);
    }
    Ok(State { pages })
}

/// Restore the original protection on each page, leaving the registry entry
/// untouched. Used by `clear()` to drop PAGE_GUARD before removing the entry,
/// closing the race where on_guard_page would find no matching entry.
pub fn restore(pages: &[(usize, u32)]) -> Result<(), BpError> {
    let ps = page_size();
    let mut overall = Ok(());
    for &(base, original) in pages {
        if unsafe { set_protect(base, ps, original) }.is_err() {
            warn!("page bp restore: VirtualProtect(0x{base:x}) failed; page state inconsistent");
            overall = Err(BpError::Internal);
        }
    }
    overall
}

pub fn rearm(base: usize, original_protect: u32) {
    if unsafe { set_protect(base, page_size(), original_protect | PAGE_GUARD) }.is_err() {
        warn!("page bp rearm: VirtualProtect(0x{base:x}) failed; bp will not fire again");
    }
}

fn query_protect(addr: usize) -> Option<u32> {
    let mut info = MaybeUninit::<MEMORY_BASIC_INFORMATION>::uninit();
    let written = unsafe {
        VirtualQuery(
            addr as *const _,
            info.as_mut_ptr(),
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if written == 0 {
        return None;
    }
    let info = unsafe { info.assume_init() };
    if info.State != MEM_COMMIT {
        return None;
    }
    Some(info.Protect)
}

unsafe fn set_protect(addr: usize, size: usize, protect: u32) -> Result<(), ()> {
    let mut old: PAGE_PROTECTION_FLAGS = 0;
    if VirtualProtect(addr as _, size, protect, &mut old) == 0 {
        Err(())
    } else {
        Ok(())
    }
}
