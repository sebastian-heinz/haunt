//! Trace event ring buffer for `--log` breakpoint hits.
//!
//! Producers (the agent's VEH on a hot path) call `push`. Consumers (HTTP
//! `GET /events?since=&limit=&timeout=`) call `poll`. Bounded capacity —
//! oldest record is evicted on overflow. Each record carries a monotonic
//! `id` so callers can long-poll with `since=<last_seen>`.

use std::cell::Cell;
use std::collections::VecDeque;
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::MAX_LONG_POLL_TIMEOUT_MS;

const RING_CAP: usize = 4096;

#[derive(Debug, Clone)]
pub struct Event {
    pub id: u64,
    /// Originating breakpoint id, if attributable.
    pub bp_id: Option<u64>,
    pub tid: u32,
    pub rip: u64,
    pub msg: String,
    /// Milliseconds since the events module first observed activity.
    pub millis: u64,
}

static RING: OnceLock<Mutex<Inner>> = OnceLock::new();
static CV: OnceLock<Condvar> = OnceLock::new();
static EPOCH: OnceLock<Instant> = OnceLock::new();

struct Inner {
    deque: VecDeque<Event>,
    /// Monotonic id source. Owned by the lock so push order matches id order;
    /// allocating it outside the lock allowed an inversion where a producer
    /// that took id=N could be pushed after id=N+1, and any consumer that
    /// advanced past N+1 would lose the N record forever (`id > since` rejects
    /// it on the next poll).
    next_id: u64,
    /// Set by `shutdown()` so long-pollers return immediately rather than
    /// re-looping until their per-call timeout. Without it, a `notify_all`
    /// alone wakes pollers but they re-check the (still empty) ring,
    /// re-test the not-yet-expired deadline, and `wait_timeout` again.
    shutting_down: bool,
}

thread_local! {
    /// Re-entry guard: if a `--log` BP fires inside a function the events
    /// path itself calls (allocator, mutex internals, ...), the same thread
    /// would try to lock RING twice and deadlock — `std::sync::Mutex` is not
    /// reentrant. Drop the inner record instead.
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

/// Push a new event. Cheap on the hot path: one mutex acquire, no notify cost
/// when no one is waiting. Re-entrant calls on the same thread are dropped
/// (see `IN_PUSH`).
pub fn push(bp_id: Option<u64>, tid: u32, rip: u64, msg: String) {
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
        g.deque.push_back(Event { id, bp_id, tid, rip, msg, millis });
        cv().notify_all();
    }
    IN_PUSH.with(|f| f.set(false));
}

/// Return events matching the optional filters, up to `limit`.
///
/// Filters:
/// - `since`: only events with `id > since` (forward / long-poll mode).
/// - `bp_id`: only events from this BP (server-side filter — matters
///   when several BPs fire at high rate and the client only cares about
///   one).
/// - `tail`: if `Some(n)`, return the *most recent* up to `n` matching
///   records in chronological order regardless of `since`. Disables
///   long-polling — "give me what's already there" is a snapshot, not
///   a wait. Solves the ring-overflow foot-shape where `since=0` slid
///   off the front while the caller was setting up.
///
/// Long-poll only applies when `tail` is `None` and no records match.
/// Returns whatever has arrived by `timeout_ms` (possibly empty).
pub fn poll(
    since: u64,
    limit: usize,
    timeout_ms: u64,
    bp_id: Option<u64>,
    tail: Option<usize>,
) -> Vec<Event> {
    let timeout_ms = timeout_ms.min(MAX_LONG_POLL_TIMEOUT_MS);
    let mut g = match ring().lock() {
        Ok(g) => g,
        Err(_) => return Vec::new(),
    };

    if let Some(n) = tail {
        return collect_tail(&g.deque, n.min(limit), bp_id);
    }

    let deadline = Instant::now() + Duration::from_millis(timeout_ms);

    loop {
        if g.shutting_down {
            return Vec::new();
        }
        let collected = collect_forward(&g.deque, since, limit, bp_id);
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
            return collect_forward(&g.deque, since, limit, bp_id);
        }
    }
}

fn collect_forward(
    deque: &VecDeque<Event>,
    since: u64,
    limit: usize,
    bp_id: Option<u64>,
) -> Vec<Event> {
    deque
        .iter()
        .filter(|e| e.id > since)
        .filter(|e| match bp_id {
            Some(want) => e.bp_id == Some(want),
            None => true,
        })
        .take(limit)
        .cloned()
        .collect()
}

/// Last `n` matching records in chronological (oldest-first) order.
/// Iterates from the back of the deque, takes the first `n` that match
/// the optional `bp_id` filter, then reverses so the caller gets ids
/// in ascending order — same shape `collect_forward` returns.
fn collect_tail(
    deque: &VecDeque<Event>,
    n: usize,
    bp_id: Option<u64>,
) -> Vec<Event> {
    let mut out: Vec<Event> = deque
        .iter()
        .rev()
        .filter(|e| match bp_id {
            Some(want) => e.bp_id == Some(want),
            None => true,
        })
        .take(n)
        .cloned()
        .collect();
    out.reverse();
    out
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
