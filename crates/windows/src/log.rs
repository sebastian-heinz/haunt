//! Windows-specific log sinks.
//!
//! `OutputDebugStringA` writes to the debugger's output channel. Under a
//! real debugger (WinDbg, Visual Studio) it appears in the output pane;
//! DebugView attaches without a debugger. Under WINE, set
//! `WINEDEBUG=+debugstr` on the host to route these to stderr.

use std::ffi::CString;

use haunt_core::log::{Level, Sink};
use windows_sys::Win32::System::Diagnostics::Debug::OutputDebugStringA;

pub struct DebugStringSink;

impl Sink for DebugStringSink {
    fn log(&self, level: Level, msg: &str) {
        // CString rejects interior NULs; strip them rather than dropping
        // the whole record.
        let sanitized: String = msg.chars().filter(|c| *c != '\0').collect();
        let line = format!("{} haunt: {}\n", level.as_str(), sanitized);
        if let Ok(c) = CString::new(line) {
            unsafe { OutputDebugStringA(c.as_ptr() as *const u8) };
        }
    }
}
