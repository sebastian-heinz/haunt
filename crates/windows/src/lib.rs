#![cfg(windows)]

mod breakpoint;
mod modules;
mod process;
mod regions;

use std::ffi::c_void;
use std::sync::Arc;
use std::thread;

use haunt_core::{Config, DEFAULT_BIND};
use windows_sys::Win32::Foundation::{BOOL, HINSTANCE, TRUE};
use windows_sys::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH,
};

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
