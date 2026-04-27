use std::collections::HashSet;
use std::ffi::CString;

use haunt_core::thread_role;
use haunt_core::{
    BpError, BpId, BpSpec, BreakpointInfo, ExportInfo, HaltSummary, MemError, ModuleInfo, Process,
    RegName, RegionInfo, Registers, ResolveError, ResumeMode, StackFrame, ThreadInfo, ThreadStats,
};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId};

use crate::{breakpoint, modules, regions, stack};

pub struct SelfProcess;

impl Process for SelfProcess {
    fn read_memory(&self, addr: usize, len: usize) -> Result<Vec<u8>, MemError> {
        if addr.checked_add(len).is_none() {
            return Err(MemError::InvalidRange);
        }
        let mut buf = vec![0u8; len];
        let mut read: usize = 0;
        let ok = unsafe {
            ReadProcessMemory(
                GetCurrentProcess(),
                addr as *const _,
                buf.as_mut_ptr() as *mut _,
                len,
                &mut read,
            ) != 0
        };
        if ok {
            Ok(buf)
        } else if read > 0 {
            // Hand the readable prefix back so the caller doesn't have to
            // bisect across an unmapped page boundary.
            buf.truncate(read);
            Err(MemError::Partial(buf))
        } else {
            Err(MemError::Fault)
        }
    }

    fn write_memory(&self, addr: usize, bytes: &[u8]) -> Result<(), MemError> {
        if addr.checked_add(bytes.len()).is_none() {
            return Err(MemError::InvalidRange);
        }
        let mut written: usize = 0;
        let ok = unsafe {
            WriteProcessMemory(
                GetCurrentProcess(),
                addr as *const _,
                bytes.as_ptr() as *const _,
                bytes.len(),
                &mut written,
            ) != 0
        };
        if ok {
            Ok(())
        } else if written > 0 {
            Err(MemError::PartialWritten(written))
        } else {
            Err(MemError::Fault)
        }
    }

    fn set_breakpoint(&self, spec: BpSpec) -> Result<BpId, BpError> {
        breakpoint::set(spec)
    }

    fn clear_breakpoint(&self, id: BpId) -> Result<(), BpError> {
        breakpoint::clear(id)
    }

    fn breakpoints(&self) -> Vec<BreakpointInfo> {
        breakpoint::list()
    }

    fn halts(&self) -> Vec<HaltSummary> {
        breakpoint::halt::list()
    }

    fn wait_halt(&self, timeout_ms: u64, since: u64) -> Option<HaltSummary> {
        breakpoint::halt::wait(timeout_ms, since)
    }

    fn halt_regs(&self, hit_id: u64) -> Option<Registers> {
        breakpoint::halt::get_regs(hit_id)
    }

    fn halt_set_regs(&self, hit_id: u64, patch: &[(RegName, u64)]) -> Result<(), BpError> {
        breakpoint::halt::set_regs(hit_id, patch)
    }

    fn halt_resume(&self, hit_id: u64, mode: ResumeMode) -> Result<(), BpError> {
        breakpoint::halt::resume(hit_id, mode)
    }

    fn modules(&self) -> Vec<ModuleInfo> {
        modules::list()
    }

    fn module_exports(&self, name: &str) -> Option<Vec<ExportInfo>> {
        modules::exports(name)
    }

    fn memory_regions(&self) -> Vec<RegionInfo> {
        regions::list()
    }

    fn threads(&self) -> Vec<ThreadInfo> {
        // Snapshot agent tids ONCE before enumerating, so the per-thread
        // `is_agent` flag reflects a consistent view (a worker exiting
        // mid-enumeration shouldn't make some entries true and others false
        // for what should be the same logical question).
        let agents: HashSet<u32> = thread_role::agent_tids().into_iter().collect();
        let mut out = Vec::new();
        breakpoint::enumerate_threads(|tid| {
            let accessible = breakpoint::can_apply(tid);
            let dr_state = if accessible { breakpoint::read_dr_state(tid) } else { None };
            out.push(ThreadInfo {
                tid,
                accessible,
                dr: dr_state.map(|(d, _)| d),
                dr7: dr_state.map(|(_, d7)| d7),
                is_agent: agents.contains(&tid),
            });
        });
        out
    }

    fn thread_stats(&self) -> ThreadStats {
        let (ok, fail) = breakpoint::attach_counters();
        ThreadStats { attach_ok: ok, attach_fail: fail }
    }

    fn stack_walk(&self, hit_id: u64, max_frames: usize) -> Vec<StackFrame> {
        let regs = match breakpoint::halt::get_regs(hit_id) {
            Some(r) => r,
            None => return Vec::new(),
        };
        stack::walk(&regs, max_frames)
    }

    fn search_memory(
        &self,
        pattern: &[Option<u8>],
        start: usize,
        end: usize,
        limit: usize,
    ) -> Vec<usize> {
        regions::search(pattern, start, end, limit)
    }

    fn shutdown_halts(&self) {
        breakpoint::halt::shutdown();
    }

    fn pid(&self) -> u32 {
        unsafe { GetCurrentProcessId() }
    }

    fn current_os_tid(&self) -> u32 {
        unsafe { GetCurrentThreadId() }
    }

    fn resolve_symbol(&self, module: &str, symbol: &str) -> Result<usize, ResolveError> {
        // GetProcAddress is the canonical resolver: it follows export
        // forwarders (kernel32!ExitProcess → ntdll!RtlExitUserProcess)
        // and API-set redirection (api-ms-win-* → kernelbase / kernel32)
        // that the manual export-table walk in `module_exports` cannot.
        // Without this, `bp set kernel32.dll!ExitProcess` and similar
        // forward-via-API-set names would 404 even though they resolve
        // to a real address at link time in every other process.
        let (base, _size) = modules::find_module(module).ok_or(ResolveError::ModuleNotFound)?;
        let sym_cstr = CString::new(symbol).map_err(|_| ResolveError::SymbolNotFound)?;
        // HMODULE on Windows is just the module's base address.
        match unsafe { GetProcAddress(base as *mut _, sym_cstr.as_ptr() as *const u8) } {
            Some(p) => Ok(p as usize),
            None => Err(ResolveError::SymbolNotFound),
        }
    }
}
