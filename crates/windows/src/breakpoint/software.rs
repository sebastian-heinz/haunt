//! Software breakpoint: overwrite byte with 0xCC, catch EXCEPTION_BREAKPOINT.

use std::mem::{size_of, MaybeUninit};

use haunt_core::BpError;
use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows_sys::Win32::System::Memory::{
    VirtualProtect, VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READWRITE,
    PAGE_GUARD, PAGE_PROTECTION_FLAGS,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

pub const INT3: u8 = 0xCC;

pub struct State {
    pub original_byte: u8,
    /// `false` while the original byte is currently in memory (we're between
    /// int3 hit and single-step rearm). Lets the VEH avoid restoring twice.
    pub active: bool,
}

pub fn install(addr: usize) -> Result<State, BpError> {
    // Refuse to install on a page that already has PAGE_GUARD. Win32
    // protections are page-granular, so `write_byte`'s
    // `VirtualProtect(PAGE_EXECUTE_READWRITE)` would strip PAGE_GUARD off
    // the whole page for the duration of the byte write — silently
    // breaking whatever set the guard. The most important consumer is
    // the OS's own stack-growth guard (a stripped guard means a stack
    // overflow goes undetected and the host runs off into adjacent
    // memory), but the same applies to AV hooks, JIT runtime traps, and
    // foreign debuggers.
    //
    // The symmetric "page BP overlapping a SW BP" rejection lives in
    // `breakpoint::reject_sw_overlapping_page_bp` — that one only sees
    // *haunt's* page BPs. This check catches third-party guards.
    if let Some(protect) = page_protect(addr) {
        if protect & PAGE_GUARD != 0 {
            return Err(BpError::Conflict);
        }
    }
    // (No protect info → either uncommitted or VirtualQuery failure;
    // `write_byte` will fail loudly via VirtualProtect, so we don't
    // need to short-circuit here.)

    let original = unsafe { write_byte(addr, INT3) }.map_err(|_| BpError::Unwritable)?;
    // Reject if the byte was already int3 (compiler-emitted, third-party
    // hook, etc.). The VEH path restores `original_byte` before returning
    // EXCEPTION_CONTINUE_EXECUTION, so the CPU would re-execute 0xCC,
    // raise EXCEPTION_BREAKPOINT again, and loop forever — TF never gets
    // a chance because the int3 fires before the single-step.
    if original == INT3 {
        // We didn't change anything (we wrote 0xCC over 0xCC), so no
        // restore is needed.
        return Err(BpError::Conflict);
    }
    Ok(State { original_byte: original, active: true })
}

/// `Some(protect_flags)` for committed pages, `None` otherwise. Used by
/// `install` to detect pre-existing PAGE_GUARD before we accidentally
/// strip it.
fn page_protect(addr: usize) -> Option<u32> {
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

pub unsafe fn write_byte(addr: usize, byte: u8) -> Result<u8, ()> {
    let mut old_protect: PAGE_PROTECTION_FLAGS = 0;
    if VirtualProtect(addr as _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect) == 0 {
        return Err(());
    }
    let original = std::ptr::read_volatile(addr as *const u8);
    std::ptr::write_volatile(addr as *mut u8, byte);

    let mut discard: PAGE_PROTECTION_FLAGS = 0;
    VirtualProtect(addr as _, 1, old_protect, &mut discard);
    FlushInstructionCache(GetCurrentProcess(), addr as _, 1);
    Ok(original)
}
