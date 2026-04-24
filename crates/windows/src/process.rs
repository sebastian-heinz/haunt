use haunt_core::{
    BpError, BpId, BpSpec, BreakpointInfo, ExportInfo, HaltSummary, MemError, ModuleInfo, Process,
    RegionInfo, Registers, ResumeMode,
};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use crate::{breakpoint, modules, regions};

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
            buf.truncate(read);
            Err(MemError::Partial(read))
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
            Err(MemError::Partial(written))
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

    fn wait_halt(&self, timeout_ms: u64) -> Option<HaltSummary> {
        breakpoint::halt::wait(timeout_ms)
    }

    fn halt_regs(&self, hit_id: u64) -> Option<Registers> {
        breakpoint::halt::get_regs(hit_id)
    }

    fn halt_set_regs(&self, hit_id: u64, regs: Registers) -> Result<(), BpError> {
        breakpoint::halt::set_regs(hit_id, regs)
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
}
