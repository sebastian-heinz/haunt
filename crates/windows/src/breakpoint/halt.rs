//! Halted-hit registry: when a BP fires with `halt=true`, the VEH handler
//! parks the faulting thread on a per-hit event; the HTTP side can inspect
//! and resume it.

use std::collections::HashMap;
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use haunt_core::{BpError, BpId, HaltSummary, Registers, ResumeMode};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;
use windows_sys::Win32::System::Threading::{
    CreateEventA, GetCurrentThreadId, SetEvent, WaitForSingleObject, INFINITE,
};

use super::arch;

/// Cap on `/halts/wait` long-poll. Without it, a client sending
/// `?timeout=u64::MAX` parks an agent worker for ~584 million years.
/// `events::poll` already enforces the same cap.
pub const MAX_WAIT_TIMEOUT_MS: u64 = 60_000;

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

struct State {
    halts: HashMap<u64, HaltedHit>,
    next_hit_id: u64,
    /// Set by `shutdown()` so `wait` long-pollers return immediately rather
    /// than spinning to their timeout while the agent is being torn down.
    /// Lives under the same mutex as `halts` so the check-and-park dance in
    /// `halt_and_wait` and the flag-and-resume dance in the shutdown handler
    /// can be made atomic — without that, a hit could insert itself between
    /// the shutdown handler's snapshot and the flag store, then park forever.
    shutting_down: bool,
}

static HALTS: OnceLock<Mutex<State>> = OnceLock::new();
static CV: OnceLock<Condvar> = OnceLock::new();

fn halts() -> &'static Mutex<State> {
    HALTS.get_or_init(|| {
        Mutex::new(State { halts: HashMap::new(), next_hit_id: 1, shutting_down: false })
    })
}

fn cv() -> &'static Condvar {
    CV.get_or_init(Condvar::new)
}

/// Park the calling thread. Returns the `ResumeMode` requested by the client.
/// On wake, any register modifications are written back into `ctx`. Refuses
/// to park if `shutdown()` was called — a halt that arrives during teardown
/// would never receive its `resume` and would zombie the thread.
pub fn halt_and_wait(bp_id: Option<BpId>, ctx: &mut CONTEXT) -> ResumeMode {
    let tid = unsafe { GetCurrentThreadId() };

    // auto-reset event, initially not signaled. Created before the lock so
    // we don't hold the registry while syscalling, but freed via CloseHandle
    // on every error path below.
    let event = unsafe { CreateEventA(std::ptr::null(), 0, 0, std::ptr::null()) };
    if event.is_null() || event == INVALID_HANDLE_VALUE {
        return ResumeMode::Continue;
    }

    // Insert under the lock and re-check shutdown there. The combined
    // (check + insert) under the same mutex that `shutdown()` holds when
    // setting the flag means a hit can never slip in between the shutdown
    // handler's "resume all" sweep and the flag store.
    let hit_id = match halts().lock() {
        Ok(mut guard) => {
            if guard.shutting_down {
                unsafe { CloseHandle(event) };
                return ResumeMode::Continue;
            }
            let hit_id = guard.next_hit_id;
            guard.next_hit_id = guard.next_hit_id.wrapping_add(1);
            let hit = HaltedHit {
                hit_id,
                bp_id,
                tid,
                rip: arch::ip(ctx),
                regs: arch::extract_regs(ctx),
                event,
                resume_mode: None,
                modified: false,
            };
            guard.halts.insert(hit_id, hit);
            cv().notify_all();
            hit_id
        }
        Err(_) => {
            unsafe { CloseHandle(event) };
            return ResumeMode::Continue;
        }
    };

    // Park.
    let _ = unsafe { WaitForSingleObject(event, INFINITE) };

    // Collect the resume mode + any modifications, then remove & free the event.
    // We hold the lock while CloseHandle runs so a `resume()` that already
    // looked up the event but hasn't yet called SetEvent must wait — see the
    // matching ordering in `resume`.
    let (mode, regs_to_apply) = match halts().lock() {
        Ok(mut guard) => {
            let result = match guard.halts.remove(&hit_id) {
                Some(h) => {
                    unsafe { CloseHandle(h.event) };
                    let regs = if h.modified { Some(h.regs) } else { None };
                    (h.resume_mode.unwrap_or(ResumeMode::Continue), regs)
                }
                None => {
                    // Should not happen — only this thread or `shutdown()`
                    // (under the same lock) can remove. Close the handle
                    // anyway so we don't leak.
                    unsafe { CloseHandle(event) };
                    (ResumeMode::Continue, None)
                }
            };
            // Wake any /halts/wait long-pollers — the set of parked halts
            // just changed.
            cv().notify_all();
            result
        }
        Err(_) => {
            unsafe { CloseHandle(event) };
            (ResumeMode::Continue, None)
        }
    };

    if let Some(r) = regs_to_apply {
        arch::apply_regs(ctx, &r);
    }

    mode
}

pub fn list() -> Vec<HaltSummary> {
    let g = match halts().lock() {
        Ok(g) => g,
        Err(_) => return Vec::new(),
    };
    g.halts
        .values()
        .map(|h| HaltSummary { hit_id: h.hit_id, bp_id: h.bp_id, tid: h.tid, rip: h.rip })
        .collect()
}

/// Return the oldest parked halt whose `hit_id > since`, blocking up to
/// `timeout_ms` (capped at `MAX_WAIT_TIMEOUT_MS`) if none qualify yet.
/// Determinism matters: at high BP rate a caller polling `wait, regs,
/// resume, wait` needs to know it gets the next hit in order, not a random
/// hash-bucket pick.
pub fn wait(timeout_ms: u64, since: u64) -> Option<HaltSummary> {
    let timeout_ms = timeout_ms.min(MAX_WAIT_TIMEOUT_MS);
    let mut guard = halts().lock().ok()?;
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);

    loop {
        if guard.shutting_down {
            return None;
        }
        if let Some(h) = oldest_after(&guard.halts, since) {
            return Some(h);
        }
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        let remaining = deadline - now;
        let (g, res) = cv().wait_timeout(guard, remaining).ok()?;
        guard = g;
        if res.timed_out() {
            return oldest_after(&guard.halts, since);
        }
    }
}

/// Mark the subsystem as shutting down, signal every currently parked halt
/// with `Continue`, and wake all waiters. Called from the HTTP `/shutdown`
/// handler. Doing all three under a single `halts()` lock acquisition is
/// what closes the original race: any `halt_and_wait` that arrives during
/// teardown either wins the lock first (and is in the snapshot we sweep
/// here) or loses it (and sees `shutting_down=true` on its own
/// check-and-park, returning `Continue` without parking). Without this
/// atomicity, a hit could insert itself between the orchestrator's
/// snapshot and the flag store, then sit in `WaitForSingleObject(INFINITE)`
/// forever.
pub fn shutdown() {
    if let Ok(mut g) = halts().lock() {
        g.shutting_down = true;
        for h in g.halts.values_mut() {
            // Idempotent — if the user already requested a Step/Ret resume,
            // honor it. We don't override; we only fill in a default.
            if h.resume_mode.is_none() {
                h.resume_mode = Some(ResumeMode::Continue);
            }
            // SetEvent on a still-owned handle: parked thread will wake,
            // re-acquire this same lock (so it serialises after we drop it),
            // remove its entry, and CloseHandle.
            unsafe { SetEvent(h.event) };
        }
        cv().notify_all();
    }
}

fn oldest_after(map: &HashMap<u64, HaltedHit>, since: u64) -> Option<HaltSummary> {
    map.values()
        .filter(|h| h.hit_id > since)
        .min_by_key(|h| h.hit_id)
        .map(|h| HaltSummary { hit_id: h.hit_id, bp_id: h.bp_id, tid: h.tid, rip: h.rip })
}

pub fn get_regs(hit_id: u64) -> Option<Registers> {
    let g = halts().lock().ok()?;
    g.halts.get(&hit_id).map(|h| h.regs)
}

pub fn set_regs(hit_id: u64, regs: Registers) -> Result<(), BpError> {
    let mut g = halts().lock().map_err(|_| BpError::Internal)?;
    let h = g.halts.get_mut(&hit_id).ok_or(BpError::NotFound)?;
    h.regs = regs;
    h.modified = true;
    Ok(())
}

pub fn resume(hit_id: u64, mode: ResumeMode) -> Result<(), BpError> {
    // We MUST hold the lock across SetEvent. Without it, two concurrent
    // resume() calls could both copy the same HANDLE, then the parked
    // thread would wake on the first SetEvent, remove the entry, and
    // CloseHandle the event — leaving the second SetEvent to fire on a
    // closed (and possibly recycled) handle.
    let mut g = halts().lock().map_err(|_| BpError::Internal)?;
    let h = g.halts.get_mut(&hit_id).ok_or(BpError::NotFound)?;
    h.resume_mode = Some(mode);
    let event = h.event;
    let ok = unsafe { SetEvent(event) } != 0;
    if !ok {
        return Err(BpError::Internal);
    }
    Ok(())
}


