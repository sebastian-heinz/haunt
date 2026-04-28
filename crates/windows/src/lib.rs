#![cfg(windows)]

mod breakpoint;
mod log;
mod modules;
mod process;
mod regions;
mod safe_read;
mod stack;

use std::ffi::c_void;
use std::sync::Arc;
use std::thread;

use haunt_core::log::set_sink;
use haunt_core::{info, Config, DEFAULT_BIND};
use windows_sys::Win32::Foundation::{BOOL, HINSTANCE, TRUE};
use windows_sys::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH,
};
use windows_sys::Win32::System::Threading::GetCurrentProcessId;
// `core::run` calls `process.current_os_tid()` for the accept thread's
// agent-tid registration, so this DllMain spawn doesn't need to call
// `mark_agent` itself.

use log::RingSink;
use process::SelfProcess;

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
pub extern "system" fn DllMain(
    hinst: HINSTANCE,
    reason: u32,
    _reserved: *mut c_void,
) -> BOOL {
    match reason {
        DLL_PROCESS_ATTACH => {
            // Do NOT call DisableThreadLibraryCalls — we need DLL_THREAD_ATTACH
            // to propagate hardware breakpoints onto newly created threads.
            thread::spawn(|| {
                // Single sink: the agent's own /logs ring buffer. Stderr in
                // an injected process usually goes nowhere visible (no
                // console on most GUI targets); OutputDebugStringA can
                // block the agent if a debugger is attached but not draining
                // the queue and would mix with every other process's debug
                // output. Drain via `haunt logs` instead.
                set_sink(Box::new(RingSink));
                info!(
                    "v{} attached to pid {}",
                    env!("CARGO_PKG_VERSION"),
                    unsafe { GetCurrentProcessId() },
                );
                let config = Config {
                    bind: DEFAULT_BIND.into(),
                    token: std::env::var("HAUNT_TOKEN").ok().filter(|s| !s.is_empty()),
                };
                haunt_core::run(Arc::new(SelfProcess), config);
            });
        }
        DLL_THREAD_ATTACH => {
            // Runs under loader lock on every new thread. Lock-free and allocation-free.
            breakpoint::apply_hw_to_current_thread();
        }
        DLL_PROCESS_DETACH => {}
        _ => {}
    }
    TRUE
}
