//! Hardware breakpoint via DR0–DR3.
//!
//! Maintains an atomic snapshot of DR0–3 + DR7 so that `DLL_THREAD_ATTACH` on new
//! threads can apply them without taking any lock.
//!
//! Slot allocation happens in the parent module under the registry lock; this
//! module just applies a given slot to existing threads.

use std::mem::{size_of, zeroed};
use std::sync::atomic::{AtomicU64, Ordering};

use haunt_core::{BpAccess, BpError};
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, CONTEXT,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, GetCurrentThreadId, OpenThread, ResumeThread, SuspendThread,
    THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
};

// x86_64: CONTEXT_AMD64 (0x100000) | DEBUG_REGISTERS_BIT (0x10)
const CONTEXT_DEBUG_REGISTERS_X64: u32 = 0x0010_0010;

pub struct State {
    pub slot: u8, // 0..=3
}

static SNAP_DR: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static SNAP_DR7: AtomicU64 = AtomicU64::new(0);

pub fn install(addr: usize, access: BpAccess, size: u8, slot: u8) -> Result<(), BpError> {
    let rw = encode_access(access)?;
    let len = encode_size(size)?;
    if size != 1 && addr % size as usize != 0 {
        return Err(BpError::Unsupported);
    }
    snapshot_write(slot, addr as u64, rw, len, true);
    apply_to_all_threads(|ctx| {
        set_dr_addr(ctx, slot, addr as u64);
        set_dr7(ctx, slot, rw, len, true);
    });
    Ok(())
}

pub fn uninstall(state: State) -> Result<(), BpError> {
    snapshot_write(state.slot, 0, 0, 0, false);
    apply_to_all_threads(|ctx| {
        set_dr_addr(ctx, state.slot, 0);
        set_dr7(ctx, state.slot, 0, 0, false);
    });
    Ok(())
}

/// True if any of DR6's B0..B3 status bits are set.
pub fn dr6_has_bp(dr6: u64) -> bool {
    dr6 & 0xF != 0
}

/// True if the given slot's status bit is set in DR6.
pub fn slot_fired(dr6: u64, slot: u8) -> bool {
    dr6 & (1u64 << slot) != 0
}

/// Apply the current snapshot to the calling thread. Safe to call from
/// `DLL_THREAD_ATTACH` — no allocation, no locking, no toolhelp.
pub fn apply_current_thread() {
    let dr7 = SNAP_DR7.load(Ordering::Relaxed);
    if dr7 == 0 {
        return;
    }
    let tid = unsafe { GetCurrentThreadId() };
    unsafe {
        let h = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 0, tid);
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            return;
        }
        let mut ctx: CONTEXT = zeroed();
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_X64;
        if GetThreadContext(h, &mut ctx) != 0 {
            ctx.Dr0 = SNAP_DR[0].load(Ordering::Relaxed);
            ctx.Dr1 = SNAP_DR[1].load(Ordering::Relaxed);
            ctx.Dr2 = SNAP_DR[2].load(Ordering::Relaxed);
            ctx.Dr3 = SNAP_DR[3].load(Ordering::Relaxed);
            ctx.Dr7 = dr7;
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_X64;
            SetThreadContext(h, &ctx);
        }
        CloseHandle(h);
    }
}

fn snapshot_write(slot: u8, addr: u64, rw: u8, len: u8, enable: bool) {
    SNAP_DR[slot as usize].store(if enable { addr } else { 0 }, Ordering::Relaxed);

    let local_bit = 1u64 << (slot * 2);
    let rw_shift = 16 + slot * 4;
    let len_shift = 18 + slot * 4;
    let rw_mask = 0b11u64 << rw_shift;
    let len_mask = 0b11u64 << len_shift;

    let mut current = SNAP_DR7.load(Ordering::Relaxed);
    loop {
        let mut new_val = current & !(local_bit | rw_mask | len_mask);
        if enable {
            new_val |= local_bit;
            new_val |= (rw as u64 & 0b11) << rw_shift;
            new_val |= (len as u64 & 0b11) << len_shift;
            new_val |= 1u64 << 8; // LE
        } else if new_val & 0xFFu64 == 0 {
            new_val &= !(1u64 << 8); // no slots active, drop LE
        }
        match SNAP_DR7.compare_exchange_weak(
            current, new_val, Ordering::Relaxed, Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(v) => current = v,
        }
    }
}

fn encode_access(access: BpAccess) -> Result<u8, BpError> {
    match access {
        BpAccess::Execute => Ok(0b00),
        BpAccess::Write => Ok(0b01),
        BpAccess::ReadWrite | BpAccess::Any => Ok(0b11),
    }
}

fn encode_size(size: u8) -> Result<u8, BpError> {
    match size {
        1 => Ok(0b00),
        2 => Ok(0b01),
        8 => Ok(0b10),
        4 => Ok(0b11),
        _ => Err(BpError::Unsupported),
    }
}

fn apply_to_all_threads<F>(mut modify: F)
where
    F: FnMut(&mut CONTEXT),
{
    let tid_self = unsafe { GetCurrentThreadId() };
    enumerate_threads(|tid| {
        if tid == tid_self {
            return;
        }
        unsafe {
            let h = OpenThread(
                THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                0,
                tid,
            );
            if h.is_null() || h == INVALID_HANDLE_VALUE {
                return;
            }
            if SuspendThread(h) == u32::MAX {
                CloseHandle(h);
                return;
            }
            let mut ctx: CONTEXT = zeroed();
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_X64;
            if GetThreadContext(h, &mut ctx) != 0 {
                modify(&mut ctx);
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_X64;
                SetThreadContext(h, &ctx);
            }
            ResumeThread(h);
            CloseHandle(h);
        }
    });
}

fn enumerate_threads<F>(mut cb: F)
where
    F: FnMut(u32),
{
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snap == INVALID_HANDLE_VALUE {
            return;
        }
        let pid_self = GetCurrentProcessId();
        let mut te: THREADENTRY32 = zeroed();
        te.dwSize = size_of::<THREADENTRY32>() as u32;
        if Thread32First(snap, &mut te) != 0 {
            loop {
                if te.th32OwnerProcessID == pid_self {
                    cb(te.th32ThreadID);
                }
                te.dwSize = size_of::<THREADENTRY32>() as u32;
                if Thread32Next(snap, &mut te) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
}

fn set_dr_addr(ctx: &mut CONTEXT, slot: u8, addr: u64) {
    match slot {
        0 => ctx.Dr0 = addr,
        1 => ctx.Dr1 = addr,
        2 => ctx.Dr2 = addr,
        3 => ctx.Dr3 = addr,
        _ => {}
    }
}

fn set_dr7(ctx: &mut CONTEXT, slot: u8, rw: u8, len: u8, enable: bool) {
    let local_bit = 1u64 << (slot * 2);
    let rw_shift = 16 + slot * 4;
    let len_shift = 18 + slot * 4;
    let rw_mask = 0b11u64 << rw_shift;
    let len_mask = 0b11u64 << len_shift;

    let mut dr7 = ctx.Dr7;
    dr7 &= !(local_bit | rw_mask | len_mask);
    if enable {
        dr7 |= local_bit;
        dr7 |= (rw as u64 & 0b11) << rw_shift;
        dr7 |= (len as u64 & 0b11) << len_shift;
        dr7 |= 1u64 << 8; // LE
    }
    ctx.Dr7 = dr7;
}
