//! Page breakpoint via PAGE_GUARD over a range of pages. Fires EXCEPTION_GUARD_PAGE
//! on any access; re-armed in the single-step handler.
//!
//! `BpAccess` is informational only — PAGE_GUARD catches every access kind.

use std::mem::{size_of, MaybeUninit};
use std::sync::atomic::{AtomicUsize, Ordering};

use haunt_core::{warn, BpAccess, BpError};

// `access` is accepted for the public API symmetry with hardware BPs but PAGE_GUARD
// can only fire on any access, so the value is discarded.
use windows_sys::Win32::System::Memory::{
    VirtualProtect, VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD,
    PAGE_PROTECTION_FLAGS,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

pub struct State {
    pub pages: Vec<(usize, u32)>, // (page_base, original_protect)
}

static PAGE_SIZE: AtomicUsize = AtomicUsize::new(0);

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

pub fn install(addr: usize, _access: BpAccess, size: usize) -> Result<State, BpError> {
    let ps = page_size();
    let start = addr & !(ps - 1);
    let end = addr.checked_add(size).ok_or(BpError::Unsupported)?;
    let end_page = (end + ps - 1) & !(ps - 1);

    let mut pages = Vec::new();
    let mut cursor = start;
    while cursor < end_page {
        let original = query_protect(cursor).ok_or(BpError::Unwritable)?;
        if unsafe { set_protect(cursor, ps, original | PAGE_GUARD) }.is_err() {
            warn!("page bp install: VirtualProtect(0x{cursor:x}) failed; rolling back");
            for (p, orig) in pages {
                if unsafe { set_protect(p, ps, orig) }.is_err() {
                    warn!("page bp install rollback: VirtualProtect(0x{p:x}) failed; page left unprotected");
                }
            }
            return Err(BpError::Unwritable);
        }
        pages.push((cursor, original));
        cursor += ps;
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

/// Find the page BP containing `addr`. Returns (page_base, original_protect).
pub fn find_containing(addr: usize) -> Option<(usize, u32)> {
    let ps = page_size();
    let page = addr & !(ps - 1);
    let reg = super::registry().lock().ok()?;
    for entry in reg.values() {
        if let super::KindState::Page(s) = &entry.state {
            for &(base, orig) in &s.pages {
                if base == page {
                    return Some((base, orig));
                }
            }
        }
    }
    None
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
