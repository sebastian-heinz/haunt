//! Halted-hit registry: when a BP fires with `halt=true`, the VEH handler
//! parks the faulting thread on a per-hit event; the HTTP side can inspect
//! and resume it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use haunt_core::{BpError, BpId, HaltSummary, Registers, ResumeMode};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;
use windows_sys::Win32::System::Threading::{
    CreateEventA, GetCurrentThreadId, SetEvent, WaitForSingleObject, INFINITE,
};

pub struct HaltedHit {
    pub hit_id: u64,
    pub bp_id: Option<BpId>,
    pub tid: u32,
    pub rip: u64,
    pub regs: Registers,
    pub event: HANDLE,
    pub resume_mode: Option<ResumeMode>,
    pub modified: bool, // if true, `regs` has been edited — apply back before resume
}

// HANDLE is a raw pointer, but we own it and only ever access it via Win32.
unsafe impl Send for HaltedHit {}
unsafe impl Sync for HaltedHit {}

static HALTS: OnceLock<Mutex<HashMap<u64, HaltedHit>>> = OnceLock::new();
static CV: OnceLock<Condvar> = OnceLock::new();
static NEXT_HIT_ID: AtomicU64 = AtomicU64::new(1);

fn halts() -> &'static Mutex<HashMap<u64, HaltedHit>> {
    HALTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cv() -> &'static Condvar {
    CV.get_or_init(Condvar::new)
}

/// Park the calling thread. Returns the `ResumeMode` requested by the client.
/// On wake, any register modifications are written back into `ctx`.
pub fn halt_and_wait(bp_id: Option<BpId>, ctx: &mut CONTEXT) -> ResumeMode {
    let hit_id = NEXT_HIT_ID.fetch_add(1, Ordering::Relaxed);
    let tid = unsafe { GetCurrentThreadId() };

    // auto-reset event, initially not signaled
    let event = unsafe { CreateEventA(std::ptr::null(), 0, 0, std::ptr::null()) };
    if event.is_null() || event == INVALID_HANDLE_VALUE {
        return ResumeMode::Continue;
    }

    let hit = HaltedHit {
        hit_id,
        bp_id,
        tid,
        rip: ctx.Rip,
        regs: extract_regs(ctx),
        event,
        resume_mode: None,
        modified: false,
    };

    if let Ok(mut guard) = halts().lock() {
        guard.insert(hit_id, hit);
        cv().notify_all();
    } else {
        unsafe { CloseHandle(event) };
        return ResumeMode::Continue;
    }

    // Park.
    let wait_result = unsafe { WaitForSingleObject(event, INFINITE) };
    let _ = wait_result;

    // Collect the resume mode + any modifications, then remove & free the event.
    let (mode, regs_to_apply) = match halts().lock() {
        Ok(mut guard) => match guard.remove(&hit_id) {
            Some(h) => {
                let regs = if h.modified { Some(h.regs) } else { None };
                (h.resume_mode.unwrap_or(ResumeMode::Continue), regs)
            }
            None => (ResumeMode::Continue, None),
        },
        Err(_) => (ResumeMode::Continue, None),
    };

    unsafe { CloseHandle(event) };

    if let Some(r) = regs_to_apply {
        apply_regs(ctx, &r);
    }

    mode
}

pub fn list() -> Vec<HaltSummary> {
    let g = match halts().lock() {
        Ok(g) => g,
        Err(_) => return Vec::new(),
    };
    g.values()
        .map(|h| HaltSummary { hit_id: h.hit_id, bp_id: h.bp_id, tid: h.tid, rip: h.rip })
        .collect()
}

/// Block until a new halt arrives. Returns the most recent one if several exist.
pub fn wait(timeout_ms: u64) -> Option<HaltSummary> {
    let guard = halts().lock().ok()?;
    let already: Vec<u64> = guard.keys().copied().collect();
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);

    let mut guard = guard;
    loop {
        // Any new id?
        if let Some((_, h)) = guard.iter().find(|(id, _)| !already.contains(id)) {
            return Some(HaltSummary {
                hit_id: h.hit_id,
                bp_id: h.bp_id,
                tid: h.tid,
                rip: h.rip,
            });
        }
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        let remaining = deadline - now;
        let (g, res) = cv().wait_timeout(guard, remaining).ok()?;
        guard = g;
        if res.timed_out() {
            // Check once more before returning (a halt could have been inserted
            // just before the timeout fired).
            if let Some((_, h)) = guard.iter().find(|(id, _)| !already.contains(id)) {
                return Some(HaltSummary {
                    hit_id: h.hit_id,
                    bp_id: h.bp_id,
                    tid: h.tid,
                    rip: h.rip,
                });
            }
            return None;
        }
    }
}

pub fn get_regs(hit_id: u64) -> Option<Registers> {
    let g = halts().lock().ok()?;
    g.get(&hit_id).map(|h| h.regs)
}

pub fn set_regs(hit_id: u64, regs: Registers) -> Result<(), BpError> {
    let mut g = halts().lock().map_err(|_| BpError::Internal)?;
    let h = g.get_mut(&hit_id).ok_or(BpError::NotFound)?;
    h.regs = regs;
    h.modified = true;
    Ok(())
}

pub fn resume(hit_id: u64, mode: ResumeMode) -> Result<(), BpError> {
    let event = {
        let mut g = halts().lock().map_err(|_| BpError::Internal)?;
        let h = g.get_mut(&hit_id).ok_or(BpError::NotFound)?;
        h.resume_mode = Some(mode);
        h.event
    };
    if unsafe { SetEvent(event) } == 0 {
        return Err(BpError::Internal);
    }
    Ok(())
}

pub fn extract_regs(ctx: &CONTEXT) -> Registers {
    Registers {
        rax: ctx.Rax, rcx: ctx.Rcx, rdx: ctx.Rdx, rbx: ctx.Rbx,
        rsp: ctx.Rsp, rbp: ctx.Rbp, rsi: ctx.Rsi, rdi: ctx.Rdi,
        r8: ctx.R8, r9: ctx.R9, r10: ctx.R10, r11: ctx.R11,
        r12: ctx.R12, r13: ctx.R13, r14: ctx.R14, r15: ctx.R15,
        rip: ctx.Rip,
        eflags: ctx.EFlags,
    }
}

pub fn apply_regs(ctx: &mut CONTEXT, r: &Registers) {
    ctx.Rax = r.rax; ctx.Rcx = r.rcx; ctx.Rdx = r.rdx; ctx.Rbx = r.rbx;
    ctx.Rsp = r.rsp; ctx.Rbp = r.rbp; ctx.Rsi = r.rsi; ctx.Rdi = r.rdi;
    ctx.R8 = r.r8; ctx.R9 = r.r9; ctx.R10 = r.r10; ctx.R11 = r.r11;
    ctx.R12 = r.r12; ctx.R13 = r.r13; ctx.R14 = r.r14; ctx.R15 = r.r15;
    ctx.Rip = r.rip;
    ctx.EFlags = r.eflags;
}

