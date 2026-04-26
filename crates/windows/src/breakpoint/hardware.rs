//! Hardware breakpoint via DR0–DR3.
//!
//! Maintains an atomic snapshot of DR0–3 + DR7 so that `DLL_THREAD_ATTACH` on new
//! threads can apply them without taking any lock.
//!
//! Slot allocation happens in the parent module under the registry lock; this
//! module just applies a given slot to existing threads.

use std::mem::{size_of, zeroed};
use std::sync::atomic::{AtomicU64, Ordering};

use haunt_core::{warn, BpAccess, BpError};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
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

use super::arch;

// DLL_THREAD_ATTACH HW propagation runs under loader lock, so it can't log
// safely. Counters let /threads surface "X attaches succeeded, Y failed".
static ATTACH_OK: AtomicU64 = AtomicU64::new(0);
static ATTACH_FAIL: AtomicU64 = AtomicU64::new(0);

pub fn attach_counters() -> (u64, u64) {
    (ATTACH_OK.load(Ordering::Relaxed), ATTACH_FAIL.load(Ordering::Relaxed))
}

/// Read the current debug-register state for a thread we already opened. Returns
/// (dr0..3, dr7) on success. Used by the /threads diagnostics endpoint.
pub fn read_dr_state(tid: u32) -> Option<([u64; 4], u64)> {
    unsafe {
        let h = OpenThread(THREAD_GET_CONTEXT, 0, tid);
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut ctx: CONTEXT = zeroed();
        arch::init_debug_context(&mut ctx);
        let ok = GetThreadContext(h, &mut ctx) != 0;
        CloseHandle(h);
        if !ok {
            return None;
        }
        // arch::set_dr_addr-style accessors for read; do it inline since the
        // arch module only exposes setters for DR addresses.
        #[cfg(target_arch = "x86_64")]
        let drs = [ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3];
        #[cfg(target_arch = "x86")]
        let drs = [ctx.Dr0 as u64, ctx.Dr1 as u64, ctx.Dr2 as u64, ctx.Dr3 as u64];
        Some((drs, arch::dr7(&ctx)))
    }
}

/// True if `OpenThread(GET|SET|SUSPEND)` would succeed for this tid.
pub fn can_apply(tid: u32) -> bool {
    unsafe {
        let h = OpenThread(
            THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
            0,
            tid,
        );
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            false
        } else {
            CloseHandle(h);
            true
        }
    }
}

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
        arch::set_dr_addr(ctx, slot, addr as u64);
        set_ctx_dr7(ctx, slot, rw, len, true);
    });
    Ok(())
}

pub fn uninstall(state: State) -> Result<(), BpError> {
    snapshot_write(state.slot, 0, 0, 0, false);
    apply_to_all_threads(|ctx| {
        arch::set_dr_addr(ctx, state.slot, 0);
        set_ctx_dr7(ctx, state.slot, 0, 0, false);
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

/// Apply the current snapshot to the calling thread. Called from
/// `DLL_THREAD_ATTACH` under the loader lock.
///
/// Does not take any haunt-internal locks and does not allocate user-mode
/// memory, so it can't deadlock against the rest of the agent. It does,
/// however, syscall into the kernel via `OpenThread`, `GetThreadContext`,
/// `SetThreadContext`, and `CloseHandle`, each of which touches ntdll-
/// internal synchronization we don't control. This pattern
/// (`SetThreadContext` on self from a `DllMain` callback) is documented
/// as fragile and empirically reliable on modern Windows; the README's
/// `Status` section says the same. If a real-world `DLL_THREAD_ATTACH`
/// deadlock ever traces here, this is the function to suspect.
///
/// Failures are silently counted because the loader lock forbids logging
/// from inside DllMain (`format!` would allocate). See `attach_counters`
/// and the `/threads` endpoint for visibility.
pub fn apply_current_thread() {
    let dr7 = SNAP_DR7.load(Ordering::Relaxed);
    if dr7 == 0 {
        return;
    }
    let tid = unsafe { GetCurrentThreadId() };
    let ok = unsafe {
        let h = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 0, tid);
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            false
        } else {
            let mut ctx: CONTEXT = zeroed();
            arch::init_debug_context(&mut ctx);
            let mut applied = false;
            if GetThreadContext(h, &mut ctx) != 0 {
                for slot in 0..4u8 {
                    arch::set_dr_addr(
                        &mut ctx,
                        slot,
                        SNAP_DR[slot as usize].load(Ordering::Relaxed),
                    );
                }
                arch::set_dr7(&mut ctx, dr7);
                arch::init_debug_context(&mut ctx);
                applied = SetThreadContext(h, &ctx) != 0;
            }
            CloseHandle(h);
            applied
        }
    };
    if ok {
        ATTACH_OK.fetch_add(1, Ordering::Relaxed);
    } else {
        ATTACH_FAIL.fetch_add(1, Ordering::Relaxed);
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
        // DR7 LEN=10 means 8 bytes on x64; reserved on x86.
        #[cfg(target_arch = "x86_64")]
        8 => Ok(0b10),
        4 => Ok(0b11),
        _ => Err(BpError::Unsupported),
    }
}

/// Per-thread failure record we accumulate while threads are suspended.
/// Critical: we must NOT call `format!` / `warn!` / any allocator while a
/// foreign thread is suspended. If that thread holds the process heap lock,
/// our allocation will deadlock the agent permanently. Buffer the (tid,
/// reason, errno) onto a stack-friendly Vec (one entry per failure across
/// the whole sweep, allocated AFTER the matching ResumeThread for that tid)
/// and `warn!` once the sweep is done.
struct ApplyFailure {
    tid: u32,
    reason: &'static str,
    errno: u32,
}

fn apply_to_all_threads<F>(mut modify: F)
where
    F: FnMut(&mut CONTEXT),
{
    let tid_self = unsafe { GetCurrentThreadId() };
    let mut applied = 0u32;
    let mut skipped = 0u32;
    let mut failures: Vec<ApplyFailure> = Vec::new();
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
                // No thread suspended yet; safe to allocate.
                failures.push(ApplyFailure { tid, reason: "OpenThread", errno: GetLastError() });
                skipped += 1;
                return;
            }
            if SuspendThread(h) == u32::MAX {
                // SuspendThread returned MAX without actually suspending.
                let errno = GetLastError();
                CloseHandle(h);
                failures.push(ApplyFailure { tid, reason: "SuspendThread", errno });
                skipped += 1;
                return;
            }
            // From here until ResumeThread, the foreign thread is frozen.
            // ABSOLUTELY NO heap allocation, formatting, logging, mutex
            // acquisitions, or stdio in this window. Buffer everything
            // onto stack locals; alloc after Resume.
            let mut fail_reason: Option<&'static str> = None;
            let mut fail_errno: u32 = 0;
            let mut ctx: CONTEXT = zeroed();
            arch::init_debug_context(&mut ctx);
            if GetThreadContext(h, &mut ctx) == 0 {
                fail_reason = Some("GetThreadContext");
                fail_errno = GetLastError();
            } else {
                modify(&mut ctx);
                arch::init_debug_context(&mut ctx);
                if SetThreadContext(h, &ctx) == 0 {
                    fail_reason = Some("SetThreadContext");
                    fail_errno = GetLastError();
                }
            }
            // Resume FIRST, log SECOND. The order is load-bearing.
            ResumeThread(h);
            CloseHandle(h);
            if let Some(reason) = fail_reason {
                failures.push(ApplyFailure { tid, reason, errno: fail_errno });
                skipped += 1;
            } else {
                applied += 1;
            }
        }
    });
    for f in &failures {
        warn!("hw apply: {}(tid={}) failed: errno={}", f.reason, f.tid, f.errno);
    }
    haunt_core::info!("hw apply: {applied} threads updated, {skipped} skipped");
}

pub fn enumerate_threads<F>(mut cb: F)
where
    F: FnMut(u32),
{
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snap == INVALID_HANDLE_VALUE {
            warn!("CreateToolhelp32Snapshot failed: errno={}", GetLastError());
            return;
        }
        let pid_self = GetCurrentProcessId();
        let mut te: THREADENTRY32 = zeroed();
        te.dwSize = size_of::<THREADENTRY32>() as u32;
        if Thread32First(snap, &mut te) == 0 {
            warn!("Thread32First failed: errno={}", GetLastError());
            CloseHandle(snap);
            return;
        }
        loop {
            if te.th32OwnerProcessID == pid_self {
                cb(te.th32ThreadID);
            }
            te.dwSize = size_of::<THREADENTRY32>() as u32;
            if Thread32Next(snap, &mut te) == 0 {
                break;
            }
        }
        CloseHandle(snap);
    }
}

fn set_ctx_dr7(ctx: &mut CONTEXT, slot: u8, rw: u8, len: u8, enable: bool) {
    let local_bit = 1u64 << (slot * 2);
    let rw_shift = 16 + slot * 4;
    let len_shift = 18 + slot * 4;
    let rw_mask = 0b11u64 << rw_shift;
    let len_mask = 0b11u64 << len_shift;

    let mut dr7 = arch::dr7(ctx);
    dr7 &= !(local_bit | rw_mask | len_mask);
    if enable {
        dr7 |= local_bit;
        dr7 |= (rw as u64 & 0b11) << rw_shift;
        dr7 |= (len as u64 & 0b11) << len_shift;
        dr7 |= 1u64 << 8; // LE
    }
    arch::set_dr7(ctx, dr7);
}
