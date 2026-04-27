//! haunt-inject — load a DLL into a running Windows process via the classic
//! CreateRemoteThread(LoadLibraryA) pattern.
//!
//! Usage: haunt-inject --pid <n> <path-to-dll>

#![cfg(windows)]

use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use haunt_core::log::{set_sink, StderrSink};
use haunt_core::{error, info};
use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};
use windows_sys::Win32::System::SystemInformation::{
    IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_UNKNOWN,
};
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, IsWow64Process2, OpenProcess, WaitForSingleObject,
    LPTHREAD_START_ROUTINE, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, PROCESS_VM_WRITE,
};

/// Hard cap on how long we wait for the remote `LoadLibraryW` thread to
/// finish. `INFINITE` would hang the injector if the target is suspended,
/// holds the loader lock, or is otherwise wedged. 30 s is generous for a
/// real load and short enough that a stuck inject surfaces in CI.
const WAIT_TIMEOUT_MS: u32 = 30_000;
const WAIT_TIMEOUT_RET: u32 = 0x0000_0102;
const WAIT_FAILED_RET: u32 = 0xFFFF_FFFF;

/// Architecture string of THIS injector binary, picked at build time.
/// Compared against the target process's architecture (via
/// `IsWow64Process2`) before injection — a mismatch (e.g. running
/// `haunt-inject.exe` against an x86 process from an x64 build) gets a
/// clear error instead of a successful `CreateRemoteThread` followed by
/// `LoadLibraryW` returning NULL inside the target.
#[cfg(target_arch = "x86_64")]
const INJECTOR_MACHINE: u16 = IMAGE_FILE_MACHINE_AMD64;
#[cfg(target_arch = "x86")]
const INJECTOR_MACHINE: u16 = IMAGE_FILE_MACHINE_I386;

fn main() -> ExitCode {
    set_sink(Box::new(StderrSink));
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let (pid, dll_path) = parse_args()?;
    let abs = dll_path
        .canonicalize()
        .map_err(|e| format!("cannot resolve dll path: {e}"))?;
    // UTF-16 (with NUL terminator) for LoadLibraryW. No to_str() round-trip
    // means non-ASCII paths work. We still reject embedded NULs because a
    // NUL inside the string would truncate the path inside the target.
    let mut wide: Vec<u16> = abs.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err("dll path contains NUL".into());
    }
    wide.push(0);
    inject(pid, &wide)
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

fn inject(pid: u32, dll_path_wide: &[u16]) -> Result<(), String> {
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

    check_bitness(guard.0)?;

    // Resolve LoadLibraryW in the local kernel32. The address is the same
    // in the target because kernel32 is mapped at a process-wide base
    // (ASLR slides it per-boot, not per-process).
    let raw = unsafe {
        let k32 = GetModuleHandleA(c"kernel32.dll".as_ptr() as *const u8);
        if k32.is_null() {
            return Err("GetModuleHandleA(kernel32) failed".into());
        }
        GetProcAddress(k32, c"LoadLibraryW".as_ptr() as *const u8)
    };
    if raw.is_none() {
        return Err("GetProcAddress(LoadLibraryW) failed".into());
    }
    // FARPROC and LPTHREAD_START_ROUTINE are both Option<fn-pointer> of the same size.
    let load_library: LPTHREAD_START_ROUTINE = unsafe { std::mem::transmute(raw) };

    let bytes_len = dll_path_wide.len() * std::mem::size_of::<u16>();
    let remote = unsafe {
        VirtualAllocEx(
            guard.0,
            std::ptr::null(),
            bytes_len,
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
            dll_path_wide.as_ptr() as *const _,
            bytes_len,
            &mut written,
        ) != 0
    };
    if !ok || written != bytes_len {
        return Err(format!(
            "WriteProcessMemory wrote {written}/{bytes_len} bytes: error {}",
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

    let wait_ret = unsafe { WaitForSingleObject(thread_guard.0, WAIT_TIMEOUT_MS) };
    match wait_ret {
        WAIT_TIMEOUT_RET => {
            // Remote thread is still running. LoadLibraryW may be in the
            // middle of reading `dll_path_wide` out of `remote`, or stuck
            // on the loader lock waiting for another module's DllMain.
            // Freeing `remote` would be use-after-free; killing the thread
            // with TerminateThread can leave the loader lock held forever.
            // Leak the remote memory (~MAX_PATH * 2 bytes) and surface the
            // timeout — the user can investigate the wedged thread by tid.
            std::mem::forget(mem_guard);
            return Err(format!(
                "inject timed out after {}s; remote thread tid={tid} still running, leaked path memory at 0x{:x} in target",
                WAIT_TIMEOUT_MS / 1000,
                remote as usize,
            ));
        }
        WAIT_FAILED_RET => {
            return Err(format!("WaitForSingleObject failed: error {}", last_error()));
        }
        _ => {}
    }

    let mut exit_code: u32 = 0;
    unsafe { GetExitCodeThread(thread_guard.0, &mut exit_code) };
    drop(thread_guard);
    drop(mem_guard);
    drop(guard);

    // On x64, LoadLibraryW returns HMODULE (64-bit) but GetExitCodeThread truncates
    // to 32-bit. Non-zero = success; zero = failure (more often: DLL not found or
    // DllMain returned FALSE).
    if exit_code == 0 {
        return Err(
            "LoadLibraryW returned NULL in target (DLL not found or DllMain failed)".into(),
        );
    }
    info!("injected pid={pid} remote_tid={tid} loadlib_ret=0x{:x}", exit_code);
    Ok(())
}

/// Refuse to inject if the target process's architecture differs from the
/// injector's. Without this check, `CreateRemoteThread` succeeds but the
/// remote `LoadLibraryW` returns NULL with an unhelpful error — the user
/// is left guessing whether the path is wrong or the bitness is wrong.
/// `IsWow64Process2` (Win10 1709+) gives us the architecture directly.
fn check_bitness(proc: HANDLE) -> Result<(), String> {
    let mut process_machine: u16 = 0;
    let mut native_machine: u16 = 0;
    let ok = unsafe { IsWow64Process2(proc, &mut process_machine, &mut native_machine) };
    if ok == 0 {
        // IsWow64Process2 missing on pre-1709 Windows would crash on
        // import resolution, not return 0; a 0 here means a real failure
        // (target died, handle invalid, etc.).
        return Err(format!("IsWow64Process2 failed: error {}", last_error()));
    }
    // If process_machine is UNKNOWN, the process is NOT under WOW64, so
    // it matches the host architecture.
    let target_machine = if process_machine == IMAGE_FILE_MACHINE_UNKNOWN {
        native_machine
    } else {
        process_machine
    };
    if target_machine != INJECTOR_MACHINE {
        return Err(format!(
            "bitness mismatch: injector is {} ({:#x}), target process is {} ({:#x}). \
             Use the matching haunt-inject-x86.exe / haunt-inject.exe build for the target.",
            machine_name(INJECTOR_MACHINE),
            INJECTOR_MACHINE,
            machine_name(target_machine),
            target_machine,
        ));
    }
    Ok(())
}

fn machine_name(m: u16) -> &'static str {
    match m {
        IMAGE_FILE_MACHINE_AMD64 => "x86_64",
        IMAGE_FILE_MACHINE_I386 => "x86",
        _ => "unknown",
    }
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
