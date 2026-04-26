//! Per-thread "is this an agent thread?" tag, plus a process-wide registry
//! of agent OS thread IDs.
//!
//! Threads spawned by the agent (the HTTP accept loop in `haunt-core::run`
//! plus every per-request worker) call `mark_agent(tid)` on entry. Two
//! consumers:
//! - The platform VEH reads `is_agent()` to refuse halting an agent-owned
//!   thread — halting one would deadlock the server (the parked thread
//!   would be the same one that needs to handle `resume`).
//! - The `/threads` endpoint reads `agent_tids()` so users can see which
//!   threads belong to the agent (and therefore got excluded from HW BP
//!   propagation by the platform impl).
//!
//! Lifetime: `mark_agent` returns an `AgentGuard` that on `Drop` removes
//! the thread's tid from the global set. Per-request workers exit between
//! requests, so the set stays accurate without polling. The accept thread
//! holds its guard for the lifetime of the process.

use std::cell::Cell;
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

static AGENT_TIDS: OnceLock<Mutex<HashSet<u32>>> = OnceLock::new();

fn agent_tids_set() -> &'static Mutex<HashSet<u32>> {
    AGENT_TIDS.get_or_init(|| Mutex::new(HashSet::new()))
}

thread_local! {
    // VEH hot-path read; `Cell<bool>` is lock-free.
    static AGENT_FLAG: Cell<bool> = const { Cell::new(false) };
}

/// Drop guard returned by `mark_agent`. Stash it in a
/// `let _agent = mark_agent(tid)` binding for the lifetime of the agent
/// thread; dropping it unregisters the tid and clears the per-thread flag.
/// `!Send` so it can't escape its owning thread (the invariant `tid ==
/// GetCurrentThreadId() at construction` would otherwise rot).
#[must_use = "the guard must be held for the lifetime of the agent thread; dropping it immediately unregisters the tid"]
pub struct AgentGuard {
    tid: u32,
    _not_send: std::marker::PhantomData<*const ()>,
}

impl Drop for AgentGuard {
    fn drop(&mut self) {
        if let Ok(mut s) = agent_tids_set().lock() {
            s.remove(&self.tid);
        }
        // `try_with` instead of `with` because `AGENT_FLAG` may already be
        // mid-destruction during thread exit; `with` would panic in that
        // window and panic=abort would kill the host.
        let _ = AGENT_FLAG.try_with(|f| f.set(false));
    }
}

/// Tag the calling thread as agent-owned and register `tid` in the
/// agent-tid set. Call exactly once per agent thread; calling twice on the
/// same thread will leave the set in a confused state when the guards
/// drop.
pub fn mark_agent(tid: u32) -> AgentGuard {
    AGENT_FLAG.with(|f| f.set(true));
    if let Ok(mut s) = agent_tids_set().lock() {
        s.insert(tid);
    }
    AgentGuard { tid, _not_send: std::marker::PhantomData }
}

/// True if the calling thread was tagged via `mark_agent`.
pub fn is_agent() -> bool {
    AGENT_FLAG.with(|f| f.get())
}

/// Snapshot of all currently-agent thread IDs. Used by `/threads` so users
/// can see which OS tids belong to the agent (and therefore got excluded
/// from HW BP propagation). The snapshot can be momentarily stale — a
/// worker may have exited between snapshot and the caller reading it —
/// but converges on the next call.
pub fn agent_tids() -> Vec<u32> {
    match agent_tids_set().lock() {
        Ok(s) => s.iter().copied().collect(),
        Err(_) => Vec::new(),
    }
}
