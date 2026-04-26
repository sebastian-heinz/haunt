//! Minimal logging pipeline. Zero dependencies.
//!
//! A single global `Sink` receives every record above the configured level.
//! Add backends (file, syslog, network) by composing them into a `FanOut`.
//!
//! ```no_run
//! use haunt_core::log::{set_sink, set_level, Level, FanOut, StderrSink};
//! set_level(Level::Debug);
//! set_sink(Box::new(FanOut::new(vec![Box::new(StderrSink)])));
//! haunt_core::info!("agent starting");
//! ```
//!
//! Panics are never raised from this module: logging failures are swallowed,
//! matching the agent's `panic = "abort"` policy.

use std::io::Write;
use std::sync::{atomic::{AtomicU8, Ordering}, OnceLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        }
    }
}

pub trait Sink: Send + Sync {
    fn log(&self, level: Level, msg: &str);
}

/// Fans a record out to multiple sinks. Later additions (file, syslog)
/// plug in here without changing call sites.
pub struct FanOut {
    sinks: Vec<Box<dyn Sink>>,
}

impl FanOut {
    pub fn new(sinks: Vec<Box<dyn Sink>>) -> Self {
        Self { sinks }
    }
}

impl Sink for FanOut {
    fn log(&self, level: Level, msg: &str) {
        for s in &self.sinks {
            s.log(level, msg);
        }
    }
}

/// Writes records to stderr. Safe default for CLI-adjacent tools.
pub struct StderrSink;

impl Sink for StderrSink {
    fn log(&self, level: Level, msg: &str) {
        let mut out = std::io::stderr().lock();
        let _ = writeln!(out, "{} haunt: {}", level.as_str(), msg);
    }
}

static SINK: OnceLock<Box<dyn Sink>> = OnceLock::new();
static MAX_LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);

/// Install the process-wide sink. First caller wins; subsequent calls are
/// ignored. Returns `true` if installation succeeded.
pub fn set_sink(sink: Box<dyn Sink>) -> bool {
    SINK.set(sink).is_ok()
}

/// Set the minimum level that reaches the sink. Records below this level
/// short-circuit without formatting.
pub fn set_level(level: Level) {
    MAX_LEVEL.store(level as u8, Ordering::Relaxed);
}

pub fn max_level() -> Level {
    match MAX_LEVEL.load(Ordering::Relaxed) {
        0 => Level::Error,
        1 => Level::Warn,
        2 => Level::Info,
        3 => Level::Debug,
        _ => Level::Trace,
    }
}

/// Emit a record. Returns immediately if the level is below `max_level`
/// or no sink is installed.
pub fn emit(level: Level, msg: &str) {
    if !enabled(level) {
        return;
    }
    if let Some(s) = SINK.get() {
        s.log(level, msg);
    }
}

/// Cheap level check. Use to gate `format!` allocations in hot paths:
/// `if log::enabled(Level::Debug) { debug!("…"); }`. The macros below
/// already inline this check.
pub fn enabled(level: Level) -> bool {
    (level as u8) <= MAX_LEVEL.load(Ordering::Relaxed)
}

// Macros gate `format!()` on `enabled()` so a filtered-out `info!`/`debug!`
// in the VEH hot path doesn't allocate. The default level is `Info`, so
// `info!` still allocates by default — set `Level::Warn` or `Level::Error`
// to suppress per-hit allocations from `--log` breakpoints.
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::log::Level::Error) {
            $crate::log::emit($crate::log::Level::Error, &format!($($arg)*))
        }
    };
}
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::log::Level::Warn) {
            $crate::log::emit($crate::log::Level::Warn, &format!($($arg)*))
        }
    };
}
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::log::Level::Info) {
            $crate::log::emit($crate::log::Level::Info, &format!($($arg)*))
        }
    };
}
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::log::Level::Debug) {
            $crate::log::emit($crate::log::Level::Debug, &format!($($arg)*))
        }
    };
}
#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {
        if $crate::log::enabled($crate::log::Level::Trace) {
            $crate::log::emit($crate::log::Level::Trace, &format!($($arg)*))
        }
    };
}
