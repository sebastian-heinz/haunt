//! Software breakpoint: overwrite byte with 0xCC, catch EXCEPTION_BREAKPOINT.

use haunt_core::BpError;
use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows_sys::Win32::System::Memory::{
    VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
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
    let original = unsafe { write_byte(addr, INT3) }.map_err(|_| BpError::Unwritable)?;
    Ok(State { original_byte: original, active: true })
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
