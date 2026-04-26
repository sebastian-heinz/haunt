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

const RING_CAP: usize = 4096;
const MAX_TIMEOUT_MS: u64 = 60_000;

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
        Mutex::new(Inner { deque: VecDeque::with_capacity(RING_CAP), next_id: 1 })
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

/// Return events with `id > since`, up to `limit`. If none qualify and
/// `timeout_ms > 0`, blocks waiting for new events; returns whatever has
/// arrived by then (possibly empty).
pub fn poll(since: u64, limit: usize, timeout_ms: u64) -> Vec<Event> {
    let timeout_ms = timeout_ms.min(MAX_TIMEOUT_MS);
    let mut g = match ring().lock() {
        Ok(g) => g,
        Err(_) => return Vec::new(),
    };
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);

    loop {
        let collected: Vec<Event> = g
            .deque
            .iter()
            .filter(|e| e.id > since)
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
                .filter(|e| e.id > since)
                .take(limit)
                .cloned()
                .collect();
        }
    }
}

/// Wake any waiting pollers. Called from the shutdown path so they return
/// promptly rather than blocking until their timeout expires.
pub fn shutdown() {
    cv().notify_all();
}
