//! haunt-inject — load a DLL into a running Windows process via the classic
//! CreateRemoteThread(LoadLibraryA) pattern.
//!
//! Usage: haunt-inject --pid <n> <path-to-dll>

#![cfg(windows)]

use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, OpenProcess, WaitForSingleObject, INFINITE,
    LPTHREAD_START_ROUTINE, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, PROCESS_VM_WRITE,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("haunt-inject: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let (pid, dll_path) = parse_args()?;
    let abs = dll_path
        .canonicalize()
        .map_err(|e| format!("cannot resolve dll path: {e}"))?;
    let abs_str = abs.to_str().ok_or("dll path contains non-UTF-8")?;
    let cstr = CString::new(abs_str).map_err(|_| "dll path contains NUL")?;
    inject(pid, &cstr)
}

fn parse_args() -> Result<(u32, PathBuf), String> {
    let mut args = std::env::args().skip(1);
    let mut pid: Option<u32> = None;
    let mut dll: Option<PathBuf> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--pid" => {
                let v = args.next().ok_or("--pid requires a value")?;
                pid = Some(v.parse().map_err(|_| "--pid not numeric")?);
            }
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other if other.starts_with("--") => {
                return Err(format!("unknown flag: {other}"));
            }
            other => {
                if dll.is_some() {
                    return Err("only one dll path expected".into());
                }
                dll = Some(Path::new(other).to_path_buf());
            }
        }
    }
    let pid = pid.ok_or("missing --pid")?;
    let dll = dll.ok_or("missing dll path")?;
    Ok((pid, dll))
}

fn print_help() {
    println!("haunt-inject --pid <pid> <path-to-dll>");
    println!();
    println!("Loads a DLL into the target process using CreateRemoteThread(LoadLibraryA).");
}

fn inject(pid: u32, dll_path: &CString) -> Result<(), String> {
    let proc = unsafe {
        OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ,
            FALSE,
            pid,
        )
    };
    if proc.is_null() || proc == INVALID_HANDLE_VALUE {
        return Err(format!("OpenProcess({pid}) failed: error {}", last_error()));
    }
    let guard = ProcGuard(proc);

    let raw = unsafe {
        let k32 = GetModuleHandleA(c"kernel32.dll".as_ptr() as *const u8);
        if k32.is_null() {
            return Err("GetModuleHandleA(kernel32) failed".into());
        }
        GetProcAddress(k32, c"LoadLibraryA".as_ptr() as *const u8)
    };
    if raw.is_none() {
        return Err("GetProcAddress(LoadLibraryA) failed".into());
    }
    // FARPROC and LPTHREAD_START_ROUTINE are both Option<fn-pointer> of the same size.
    let load_library: LPTHREAD_START_ROUTINE = unsafe { std::mem::transmute(raw) };

    let path_bytes = dll_path.as_bytes_with_nul();
    let remote = unsafe {
        VirtualAllocEx(
            guard.0,
            std::ptr::null(),
            path_bytes.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if remote.is_null() {
        return Err(format!("VirtualAllocEx failed: error {}", last_error()));
    }
    let mem_guard = RemoteMemGuard { proc: guard.0, addr: remote };

    let mut written: usize = 0;
    let ok = unsafe {
        WriteProcessMemory(
            guard.0,
            remote,
            path_bytes.as_ptr() as *const _,
            path_bytes.len(),
            &mut written,
        ) != 0
    };
    if !ok || written != path_bytes.len() {
        return Err(format!(
            "WriteProcessMemory wrote {written}/{} bytes: error {}",
            path_bytes.len(),
            last_error()
        ));
    }

    let mut tid: u32 = 0;
    let thread = unsafe {
        CreateRemoteThread(
            guard.0,
            std::ptr::null(),
            0,
            load_library,
            remote,
            0,
            &mut tid,
        )
    };
    if thread.is_null() {
        return Err(format!("CreateRemoteThread failed: error {}", last_error()));
    }
    let thread_guard = ThreadGuard(thread);

    unsafe { WaitForSingleObject(thread_guard.0, INFINITE) };

    let mut exit_code: u32 = 0;
    unsafe { GetExitCodeThread(thread_guard.0, &mut exit_code) };
    drop(thread_guard);
    drop(mem_guard);
    drop(guard);

    // On x64, LoadLibraryA returns HMODULE (64-bit) but GetExitCodeThread truncates
    // to 32-bit. Non-zero = success; zero = failure (more often: DLL not found or
    // DllMain returned FALSE).
    if exit_code == 0 {
        return Err(
            "LoadLibraryA returned NULL in target (DLL not found or DllMain failed)".into(),
        );
    }
    println!("injected pid={pid} remote_tid={tid} loadlib_ret=0x{:x}", exit_code);
    Ok(())
}

fn last_error() -> u32 {
    use windows_sys::Win32::Foundation::GetLastError;
    unsafe { GetLastError() }
}

struct ProcGuard(HANDLE);
impl Drop for ProcGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

struct ThreadGuard(HANDLE);
impl Drop for ThreadGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

struct RemoteMemGuard {
    proc: HANDLE,
    addr: *mut core::ffi::c_void,
}
impl Drop for RemoteMemGuard {
    fn drop(&mut self) {
        if !self.addr.is_null() {
            unsafe { VirtualFreeEx(self.proc, self.addr, 0, MEM_RELEASE) };
        }
    }
}
