//! Single VEH handler multiplexing software / hardware / page breakpoints,
//! plus halt / resume / step / run-to-ret.

use std::cell::Cell;

use haunt_core::{BpId, BpKind, BpOptions, BpSpec, ResumeMode};
use windows_sys::Win32::Foundation::{
    EXCEPTION_BREAKPOINT, EXCEPTION_GUARD_PAGE, EXCEPTION_SINGLE_STEP,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ReadProcessMemory, CONTEXT, EXCEPTION_POINTERS,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentThreadId};

use super::{halt, hardware, page, software, KindState};

const TRAP_FLAG: u32 = 0x100;
const RESUME_FLAG: u32 = 0x1_0000;
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

#[derive(Clone, Copy)]
enum Rearm {
    Software { addr: usize, one_shot_id: Option<BpId> },
    Page { base: usize, original_protect: u32 },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StepMode {
    None,
    Step,
}

thread_local! {
    static PENDING: Cell<Option<Rearm>> = const { Cell::new(None) };
    static STEP: Cell<StepMode> = const { Cell::new(StepMode::None) };
}

pub(super) unsafe extern "system" fn handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    let record = &*(*info).ExceptionRecord;
    let context = &mut *(*info).ContextRecord;

    match record.ExceptionCode {
        EXCEPTION_BREAKPOINT => on_int3(record.ExceptionAddress as usize, context),
        EXCEPTION_SINGLE_STEP => on_single_step(context),
        EXCEPTION_GUARD_PAGE => on_guard_page(record.ExceptionAddress as usize, context),
        _ => EXCEPTION_CONTINUE_SEARCH,
    }
}

unsafe fn on_int3(addr: usize, context: &mut CONTEXT) -> i32 {
    // Find the SW BP at this address — regardless of tid filter, because the
    // int3 byte is in memory and any thread hitting it must have its execution
    // recovered or the process crashes.
    let (bp_id, options, tid_matches) = {
        let mut reg = match super::registry().lock() {
            Ok(g) => g,
            Err(_) => return EXCEPTION_CONTINUE_SEARCH,
        };
        let tid = GetCurrentThreadId();
        let entry = match reg.values_mut().find(|e| {
            e.addr == addr && matches!(e.state, KindState::Software(_))
        }) {
            Some(e) => e,
            None => return EXCEPTION_CONTINUE_SEARCH,
        };
        let KindState::Software(sw) = &mut entry.state else {
            return EXCEPTION_CONTINUE_SEARCH;
        };
        if software::write_byte(addr, sw.original_byte).is_err() {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        sw.active = false;
        entry.hits += 1;
        let tid_matches = entry.options.tid_filter.map(|t| t == tid).unwrap_or(true);
        (entry.id, entry.options, tid_matches)
    };

    context.Rip = addr as u64;
    context.EFlags |= TRAP_FLAG;
    // One-shot only fires for the matching thread; a filter-mismatched hit
    // leaves the BP installed so our target thread can still hit it later.
    let one_shot_id = if options.one_shot && tid_matches { Some(bp_id) } else { None };
    PENDING.with(|p| p.set(Some(Rearm::Software { addr, one_shot_id })));

    if options.halt && tid_matches {
        let mode = halt::halt_and_wait(Some(bp_id), context);
        apply_resume_mode(mode, context);
    }

    EXCEPTION_CONTINUE_EXECUTION
}

unsafe fn on_single_step(context: &mut CONTEXT) -> i32 {
    // 1. Process pending re-arm from a previous SW / page BP hit.
    let had_rearm = if let Some(task) = PENDING.with(|p| p.take()) {
        match task {
            Rearm::Software { addr, one_shot_id } => {
                if let Some(id) = one_shot_id {
                    // One-shot: byte has already been restored in on_int3; just drop the entry.
                    super::remove_entry_internal(id);
                } else if let Ok(mut reg) = super::registry().lock() {
                    if let Some(entry) = reg.values_mut().find(|e| {
                        e.addr == addr && matches!(e.state, KindState::Software(_))
                    }) {
                        if let KindState::Software(sw) = &mut entry.state {
                            if software::write_byte(addr, software::INT3).is_ok() {
                                sw.active = true;
                            }
                        }
                    }
                }
            }
            Rearm::Page { base, original_protect } => {
                page::rearm(base, original_protect);
            }
        }
        context.EFlags &= !TRAP_FLAG;
        true
    } else {
        false
    };

    // 2. If the user had requested a step, the single-step we just handled (either
    //    a re-arm step or a bare step) is the user's step. Halt now.
    if STEP.with(|s| s.replace(StepMode::None)) == StepMode::Step {
        let mode = halt::halt_and_wait(None, context);
        apply_resume_mode(mode, context);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if had_rearm {
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // 3. Otherwise, this is a hardware breakpoint hit. DR6's B0–B3 say which slot(s).
    if hardware::dr6_has_bp(context.Dr6) {
        let mut hit_ids: Vec<(BpId, BpOptions)> = Vec::new();
        if let Ok(mut reg) = super::registry().lock() {
            let tid = GetCurrentThreadId();
            for entry in reg.values_mut() {
                if let KindState::Hardware(s) = &entry.state {
                    if hardware::slot_fired(context.Dr6, s.slot) {
                        entry.hits += 1;
                        let tid_match = entry.options.tid_filter.map(|t| t == tid).unwrap_or(true);
                        if tid_match {
                            hit_ids.push((entry.id, entry.options));
                        }
                    }
                }
            }
        }
        context.Dr6 &= !0xFu64;
        context.EFlags |= RESUME_FLAG;

        // Halt on the first hitting BP (if any) that wants to halt. Multiple
        // concurrent hits on one thread are rare — we pick the first for UX.
        if let Some((bp_id, _opts)) = hit_ids.into_iter().find(|(_, o)| o.halt) {
            let mode = halt::halt_and_wait(Some(bp_id), context);
            apply_resume_mode(mode, context);
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    EXCEPTION_CONTINUE_SEARCH
}

unsafe fn on_guard_page(addr: usize, context: &mut CONTEXT) -> i32 {
    let Some((base, original_protect)) = page::find_containing(addr) else {
        return EXCEPTION_CONTINUE_SEARCH;
    };

    let (bp_id, options) = {
        let mut reg = match super::registry().lock() {
            Ok(g) => g,
            Err(_) => return EXCEPTION_CONTINUE_SEARCH,
        };
        let tid = GetCurrentThreadId();
        let Some(entry) = reg.values_mut().find(|e| match &e.state {
            KindState::Page(s) => s.pages.iter().any(|&(b, _)| b == base),
            _ => false,
        }) else {
            return EXCEPTION_CONTINUE_SEARCH;
        };
        entry.hits += 1;
        let tid_match = entry.options.tid_filter.map(|t| t == tid).unwrap_or(true);
        if !tid_match {
            // Still need to re-arm the page; just don't halt.
            PENDING.with(|p| p.set(Some(Rearm::Page { base, original_protect })));
            context.EFlags |= TRAP_FLAG;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        (entry.id, entry.options)
    };

    context.EFlags |= TRAP_FLAG;
    PENDING.with(|p| p.set(Some(Rearm::Page { base, original_protect })));

    if options.halt {
        let mode = halt::halt_and_wait(Some(bp_id), context);
        apply_resume_mode(mode, context);
    }

    EXCEPTION_CONTINUE_EXECUTION
}

fn apply_resume_mode(mode: ResumeMode, context: &mut CONTEXT) {
    match mode {
        ResumeMode::Continue => {
            STEP.with(|s| s.set(StepMode::None));
        }
        ResumeMode::Step => {
            // TF will fire after the next instruction; on_single_step checks
            // STEP_MODE and re-halts.
            STEP.with(|s| s.set(StepMode::Step));
            context.EFlags |= TRAP_FLAG;
        }
        ResumeMode::Ret => {
            STEP.with(|s| s.set(StepMode::None));
            install_run_to_ret(context);
        }
    }
}

fn install_run_to_ret(context: &mut CONTEXT) {
    // Read the current [RSP] — the return address that RET will pop.
    let mut buf = [0u8; 8];
    let mut read: usize = 0;
    let ok = unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            context.Rsp as *const _,
            buf.as_mut_ptr() as *mut _,
            8,
            &mut read,
        ) != 0
            && read == 8
    };
    if !ok {
        return;
    }
    let ret_addr = u64::from_le_bytes(buf) as usize;
    let tid = unsafe { GetCurrentThreadId() };
    let _ = super::set(BpSpec {
        addr: ret_addr,
        kind: BpKind::Software,
        options: BpOptions { halt: true, one_shot: true, tid_filter: Some(tid) },
    });
}
