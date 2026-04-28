//! Agent log ring buffer, drained by `GET /logs`.
//!
//! Sibling of `events` for trace records. The agent's own `info!` / `warn!` /
//! `error!` lines accumulate here; clients tail them over HTTP via
//! `haunt logs`. The ring is bounded — oldest record is evicted on overflow
//! — and each record carries a monotonic `id` so callers can long-poll with
//! `since=<last_seen>`.
//!
//! Why a ring instead of `OutputDebugStringA`: that Win32 channel can BLOCK
//! the writer if a debugger is attached but not draining the LPC queue,
//! mixes output across every process on the box, and requires DebugView /
//! WinDbg to consume. The ring stays under haunt's own back-pressure
//! controls and reaches the user through the same HTTP transport as
//! everything else.
//!
//! Re-entry: a `--log` BP that fires inside the allocator (or any code path
//! the log emit itself touches) would re-enter `push` on the same thread and
//! deadlock on the ring's mutex. The `IN_PUSH` thread-local guards against
//! that — recursive calls drop the inner record.

use std::cell::Cell;
use std::collections::VecDeque;
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::log::Level;
use crate::{MAX_LONG_POLL_TIMEOUT_MS, MAX_TRACE_BATCH};

/// Ring capacity = `MAX_TRACE_BATCH` so a single `limit=N` call can
/// drain the whole ring. Sourced from a shared constant in `lib.rs`
/// so the HTTP-edge validator and the ring stay in lockstep.
const RING_CAP: usize = MAX_TRACE_BATCH;

#[derive(Debug, Clone)]
pub struct LogRecord {
    pub id: u64,
    /// Milliseconds since the logs module first observed activity.
    pub millis: u64,
    pub level: Level,
    /// OS thread id of the emitter. Useful for tying log lines back to a
    /// specific worker, especially for sweep-style operations like
    /// `apply_to_all_threads` that emit a burst of warns from one thread.
    pub tid: u32,
    pub msg: String,
}

static RING: OnceLock<Mutex<Inner>> = OnceLock::new();
static CV: OnceLock<Condvar> = OnceLock::new();
static EPOCH: OnceLock<Instant> = OnceLock::new();

struct Inner {
    deque: VecDeque<LogRecord>,
    next_id: u64,
    /// Set by `shutdown()` so long-pollers return immediately rather than
    /// re-looping until their per-call timeout. Mirrors the same pattern
    /// in `events` and `breakpoint::halt`.
    shutting_down: bool,
}

thread_local! {
    static IN_PUSH: Cell<bool> = const { Cell::new(false) };
}

fn ring() -> &'static Mutex<Inner> {
    RING.get_or_init(|| {
        Mutex::new(Inner {
            deque: VecDeque::with_capacity(RING_CAP),
            next_id: 1,
            shutting_down: false,
        })
    })
}

fn cv() -> &'static Condvar {
    CV.get_or_init(Condvar::new)
}

fn epoch() -> Instant {
    *EPOCH.get_or_init(Instant::now)
}

/// Push a log record onto the ring. Cheap on the hot path: one mutex
/// acquire, no notify cost when no one is waiting. Re-entrant calls on the
/// same thread are dropped (see `IN_PUSH`).
///
/// `tid` is the OS thread id of the caller; the platform integration
/// supplies it so this module stays platform-agnostic.
pub fn push(level: Level, tid: u32, msg: String) {
    if IN_PUSH.with(|f| f.replace(true)) {
        return;
    }
    let millis = epoch().elapsed().as_millis() as u64;
    if let Ok(mut g) = ring().lock() {
        let id = g.next_id;
        g.next_id = g.next_id.wrapping_add(1);
        if g.deque.len() == RING_CAP {
            g.deque.pop_front();
        }
        g.deque.push_back(LogRecord { id, millis, level, tid, msg });
        cv().notify_all();
    }
    IN_PUSH.with(|f| f.set(false));
}

/// Return records with `id > since`, up to `limit`. If none qualify and
/// `timeout_ms > 0`, blocks waiting for new records; returns whatever has
/// arrived by then (possibly empty). Capped at `MAX_LONG_POLL_TIMEOUT_MS`.
pub fn poll(since: u64, limit: usize, timeout_ms: u64) -> Vec<LogRecord> {
    let timeout_ms = timeout_ms.min(MAX_LONG_POLL_TIMEOUT_MS);
    let mut g = match ring().lock() {
        Ok(g) => g,
        Err(_) => return Vec::new(),
    };
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);

    loop {
        if g.shutting_down {
            return Vec::new();
        }
        let collected: Vec<LogRecord> = g
            .deque
            .iter()
            .filter(|r| r.id > since)
            .take(limit)
            .cloned()
            .collect();
        if !collected.is_empty() || timeout_ms == 0 {
            return collected;
        }
        let now = Instant::now();
        if now >= deadline {
            return Vec::new();
        }
        let remaining = deadline - now;
        let (g_next, res) = match cv().wait_timeout(g, remaining) {
            Ok(p) => p,
            Err(_) => return Vec::new(),
        };
        g = g_next;
        if res.timed_out() {
            return g
                .deque
                .iter()
                .filter(|r| r.id > since)
                .take(limit)
                .cloned()
                .collect();
        }
    }
}

/// Mark the ring as shutting down and wake every waiting poller. Pollers
/// re-check `shutting_down` at the top of the loop and return promptly
/// rather than re-looping until their per-call timeout expires.
pub fn shutdown() {
    if let Ok(mut g) = ring().lock() {
        g.shutting_down = true;
    }
    cv().notify_all();
}
