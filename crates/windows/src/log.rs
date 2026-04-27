//! Windows log sink: drops records onto the agent's `/logs` ring buffer.
//!
//! Replaces the old `OutputDebugStringA` sink. That channel could BLOCK the
//! emitter when a debugger was attached but not draining the LPC queue,
//! mixed output across every process on the box, and required DebugView /
//! a real debugger to observe. The ring buffer is bounded, never blocks,
//! per-process, and reaches the user through the same HTTP transport
//! (`haunt logs` / `GET /logs`) as everything else.

use haunt_core::log::{Level, Sink};
use haunt_core::logs;
use windows_sys::Win32::System::Threading::GetCurrentThreadId;

pub struct RingSink;

impl Sink for RingSink {
    fn log(&self, level: Level, msg: &str) {
        // Capture the OS tid here rather than threading it through the
        // platform-agnostic `Sink` trait. core stays Win32-free; only this
        // file knows about `GetCurrentThreadId`.
        let tid = unsafe { GetCurrentThreadId() };
        logs::push(level, tid, msg.to_string());
    }
}
