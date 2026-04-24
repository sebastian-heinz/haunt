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
    pub active: bool,
}

pub fn install(addr: usize) -> Result<State, BpError> {
    let original = unsafe { write_byte(addr, INT3) }.map_err(|_| BpError::Unwritable)?;
    Ok(State { original_byte: original, active: true })
}

pub fn uninstall(addr: usize, state: State) -> Result<(), BpError> {
    if state.active {
        unsafe { write_byte(addr, state.original_byte) }.map_err(|_| BpError::Internal)?;
    }
    Ok(())
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
