//! Stack unwinding.
//!
//! - **x64**: real unwinder via `RtlLookupFunctionEntry` + `RtlVirtualUnwind`
//!   over the loaded modules' `.pdata` exception tables. Walks correctly
//!   through frame-pointer-omitted (FPO) functions, leaf functions, and
//!   functions that adjust SP without saving RBP.
//! - **x86**: PE32 has no `.pdata`; falls back to walking the saved-EBP
//!   chain. Truncates on FPO functions (`/Oy` is the MSVC release default
//!   and rustc's release default), so frames may be missing. Producing a
//!   PDB-aware unwinder for x86 is on the roadmap.

use haunt_core::{Registers, StackFrame};

#[cfg(target_arch = "x86_64")]
pub fn walk(initial: &Registers, max_frames: usize) -> Vec<StackFrame> {
    use std::mem::zeroed;
    use windows_sys::Win32::System::Diagnostics::Debug::{
        ReadProcessMemory, RtlLookupFunctionEntry, RtlVirtualUnwind, CONTEXT,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    // CONTEXT_AMD64 (0x100000) | CONTROL (0x1) | INTEGER (0x2) | FLOATING_POINT (0x8) = 0x10000B
    const CONTEXT_FULL: u32 = 0x0010_000B;

    let mut frames = Vec::with_capacity(max_frames.min(64));
    let mut ctx: CONTEXT = unsafe { zeroed() };
    ctx.ContextFlags = CONTEXT_FULL;
    ctx.Rip = initial.rip;
    ctx.Rsp = initial.rsp;
    ctx.Rbp = initial.rbp;
    ctx.Rbx = initial.rbx;
    ctx.Rsi = initial.rsi;
    ctx.Rdi = initial.rdi;
    ctx.R12 = initial.r12;
    ctx.R13 = initial.r13;
    ctx.R14 = initial.r14;
    ctx.R15 = initial.r15;
    ctx.EFlags = initial.eflags;

    for _ in 0..max_frames {
        frames.push(StackFrame { rip: ctx.Rip, rsp: ctx.Rsp, rbp: ctx.Rbp });
        if ctx.Rip == 0 {
            break;
        }

        let mut image_base: u64 = 0;
        let rf = unsafe {
            RtlLookupFunctionEntry(ctx.Rip, &mut image_base, std::ptr::null_mut())
        };

        let prev_rsp = ctx.Rsp;
        if rf.is_null() {
            // x64 ABI leaf function: no frame, return address sits at [rsp].
            let mut buf = [0u8; 8];
            let mut read: usize = 0;
            let ok = unsafe {
                ReadProcessMemory(
                    GetCurrentProcess(),
                    ctx.Rsp as *const _,
                    buf.as_mut_ptr() as *mut _,
                    8,
                    &mut read,
                )
            } != 0
                && read == 8;
            if !ok {
                break;
            }
            let ret = u64::from_le_bytes(buf);
            if ret == 0 {
                break;
            }
            ctx.Rip = ret;
            ctx.Rsp = ctx.Rsp.wrapping_add(8);
        } else {
            let mut handler_data: *mut std::ffi::c_void = std::ptr::null_mut();
            let mut establisher_frame: u64 = 0;
            unsafe {
                RtlVirtualUnwind(
                    0, // UNW_FLAG_NHANDLER
                    image_base,
                    ctx.Rip,
                    rf,
                    &mut ctx,
                    &mut handler_data,
                    &mut establisher_frame,
                    std::ptr::null_mut(),
                );
            }
        }
        // Stack grows down → unwind must increase rsp. If it didn't, the
        // unwind tables are inconsistent or we're past the top frame; stop
        // rather than loop on the same frame forever.
        if ctx.Rsp <= prev_rsp {
            break;
        }
    }
    frames
}

#[cfg(target_arch = "x86")]
pub fn walk(initial: &Registers, max_frames: usize) -> Vec<StackFrame> {
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    let mut frames = Vec::with_capacity(max_frames.min(64));
    frames.push(StackFrame { rip: initial.rip, rsp: initial.rsp, rbp: initial.rbp });

    let mut ebp = initial.rbp;
    for _ in 1..max_frames {
        // Reject obviously-bogus EBP values to avoid syscall churn.
        if ebp == 0 || ebp < 0x1000 {
            break;
        }
        let read_ebp_chain = |addr: u64| -> Option<u32> {
            let mut buf = [0u8; 4];
            let mut read: usize = 0;
            let ok = unsafe {
                ReadProcessMemory(
                    GetCurrentProcess(),
                    addr as *const _,
                    buf.as_mut_ptr() as *mut _,
                    4,
                    &mut read,
                )
            } != 0
                && read == 4;
            if !ok { None } else { Some(u32::from_le_bytes(buf)) }
        };
        let ret = match read_ebp_chain(ebp.wrapping_add(4)) {
            Some(v) if v != 0 => v as u64,
            _ => break,
        };
        let prev = match read_ebp_chain(ebp) {
            Some(v) => v as u64,
            None => break,
        };
        frames.push(StackFrame {
            rip: ret,
            rsp: ebp.wrapping_add(8),
            rbp: prev,
        });
        if prev <= ebp {
            break;
        }
        ebp = prev;
    }
    frames
}
