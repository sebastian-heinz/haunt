//! Single VEH handler multiplexing software / hardware / page breakpoints,
//! plus halt / resume / step / run-to-ret.

use std::cell::Cell;
use std::sync::Arc;

use haunt_core::dsl::{self, TemplatePart};
use haunt_core::events;
use haunt_core::thread_role;
use haunt_core::{debug, warn, BpHooks, BpId, BpKind, BpOptions, BpSpec, Registers, ResumeMode};
use windows_sys::Win32::Foundation::{
    EXCEPTION_BREAKPOINT, EXCEPTION_GUARD_PAGE, EXCEPTION_SINGLE_STEP,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ReadProcessMemory, CONTEXT, EXCEPTION_POINTERS,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentThreadId};

use super::{arch, halt, hardware, page, software, KindState};
use crate::modules;

const TRAP_FLAG: u32 = 0x100;
const RESUME_FLAG: u32 = 0x1_0000;
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

#[derive(Clone, Copy)]
struct SoftwareRearm {
    addr: usize,
    one_shot_id: Option<BpId>,
}

#[derive(Clone, Copy)]
struct PageRearm {
    base: usize,
    original_protect: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StepMode {
    None,
    Step,
}

// One slot per kind so a single TF interrupt can carry both a SW rearm
// and a page rearm. Previously a single `Cell<Option<Rearm>>` would
// silently lose the earlier rearm when on_int3 overwrote a page rearm
// from on_guard_page (or vice versa).
thread_local! {
    static PENDING_SW: Cell<Option<SoftwareRearm>> = const { Cell::new(None) };
    static PENDING_PAGE: Cell<Option<PageRearm>> = const { Cell::new(None) };
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
    let (bp_id, options, tid_matches, hooks) = {
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
        // Refcount-bump the hooks Arc so the registry lock can be released
        // before the (potentially expensive) DSL eval, log, and halt_and_wait
        // calls — without paying for a deep AST clone on every hit.
        (entry.id, entry.options, tid_matches, Arc::clone(&entry.hooks))
    };

    arch::set_ip(context, addr as u64);
    context.EFlags |= TRAP_FLAG;
    let one_shot_id = if options.one_shot && tid_matches { Some(bp_id) } else { None };
    PENDING_SW.with(|p| p.set(Some(SoftwareRearm { addr, one_shot_id })));

    if tid_matches {
        let _ = run_hooks_then_maybe_halt(bp_id, options, &hooks, context);
    }

    EXCEPTION_CONTINUE_EXECUTION
}

unsafe fn on_single_step(context: &mut CONTEXT) -> i32 {
    // 1. Process all pending re-arms accumulated since the last single-
    // step. Page and SW rearms can both be live simultaneously when a
    // page BP and a SW BP fire on the same instruction (e.g. a write
    // to a code page that also has an int3). Lose neither.
    let sw_rearm = PENDING_SW.with(|p| p.take());
    let page_rearm = PENDING_PAGE.with(|p| p.take());
    let had_rearm = sw_rearm.is_some() || page_rearm.is_some();

    if let Some(rearm) = sw_rearm {
        if let Some(id) = rearm.one_shot_id {
            // Byte already restored in on_int3; just drop the entry.
            super::remove_entry_internal(id);
        } else if let Ok(mut reg) = super::registry().lock() {
            if let Some(entry) = reg.values_mut().find(|e| {
                e.addr == rearm.addr && matches!(e.state, KindState::Software(_))
            }) {
                if let KindState::Software(sw) = &mut entry.state {
                    match software::write_byte(rearm.addr, software::INT3) {
                        Ok(_) => sw.active = true,
                        Err(_) => warn!(
                            "sw bp rearm at 0x{:x} failed; bp will not fire again",
                            rearm.addr,
                        ),
                    }
                }
            }
        }
    }
    if let Some(rearm) = page_rearm {
        page::rearm(rearm.base, rearm.original_protect);
    }
    if had_rearm {
        context.EFlags &= !TRAP_FLAG;
    }

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
    let dr6 = arch::dr6(context);
    if hardware::dr6_has_bp(dr6) {
        let mut hits: Vec<(BpId, BpOptions, Arc<BpHooks>)> = Vec::new();
        if let Ok(mut reg) = super::registry().lock() {
            let tid = GetCurrentThreadId();
            for entry in reg.values_mut() {
                if let KindState::Hardware(s) = &entry.state {
                    if hardware::slot_fired(dr6, s.slot) {
                        entry.hits += 1;
                        let tid_match = entry.options.tid_filter.map(|t| t == tid).unwrap_or(true);
                        if tid_match {
                            hits.push((entry.id, entry.options, Arc::clone(&entry.hooks)));
                        }
                    }
                }
            }
        }
        // HashMap iteration is undefined order. Two HW BPs that fire on the
        // same instruction would otherwise dispatch in a different order
        // each run — surprises users with `--if`-conditional halts where
        // ordering decides which BP wins. Sort by BpId (creation order).
        hits.sort_by_key(|(id, _, _)| id.0);
        arch::clear_dr6_status(context);
        context.EFlags |= RESUME_FLAG;

        // Run hooks for every fired slot. We must not break early just
        // because a BP has `options.halt = true` — its `cond` may have
        // failed, in which case no halt actually happened and any
        // subsequent --no-halt --log BPs in `hits` would be silently
        // skipped. Only stop iterating once a hook *actually* halted.
        for (bp_id, options, hooks) in hits {
            if run_hooks_then_maybe_halt(bp_id, options, &hooks, context) {
                break;
            }
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    EXCEPTION_CONTINUE_SEARCH
}

unsafe fn on_guard_page(addr: usize, context: &mut CONTEXT) -> i32 {
    let Some((base, original_protect)) = page::find_containing(addr) else {
        return EXCEPTION_CONTINUE_SEARCH;
    };

    let (bp_id, options, hooks, tid_matches) = {
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
        (entry.id, entry.options, Arc::clone(&entry.hooks), tid_match)
    };

    context.EFlags |= TRAP_FLAG;
    PENDING_PAGE.with(|p| p.set(Some(PageRearm { base, original_protect })));

    if tid_matches {
        let _ = run_hooks_then_maybe_halt(bp_id, options, &hooks, context);
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

/// Evaluate the BP's `cond` hook (if any), render its `log` template (if any),
/// emit the rendered record to the log pipeline + the events ring buffer, then
/// halt the thread iff `options.halt` AND the condition passed. Returns `true`
/// only when the thread was actually parked — used by the HW path to decide
/// whether to keep running other BPs that fired in the same VEH invocation.
///
/// Cond semantics: if `cond` is set and evaluates to zero, the BP is treated
/// as a no-fire — no log, no event, no halt — though `entry.hits` was already
/// incremented by the caller so the bare hit count still reflects reality.
unsafe fn run_hooks_then_maybe_halt(
    bp_id: BpId,
    options: BpOptions,
    hooks: &BpHooks,
    context: &mut CONTEXT,
) -> bool {
    let regs = arch::extract_regs(context);
    let ctx = HitEvalCtx { regs };

    let cond_passed = match &hooks.cond {
        Some(cond) => dsl::eval(&cond.expr, &ctx).unwrap_or(0) != 0,
        None => true,
    };
    if !cond_passed {
        return false;
    }

    if let Some(template) = &hooks.log {
        emit_log_event(bp_id, &ctx, &template.parts);
    }

    if options.halt {
        // Refuse to park if this hit fired on an agent-owned thread —
        // the agent's HTTP server (or one of its per-request workers)
        // would deadlock waiting for a `resume` that itself can only
        // arrive via the parked thread. Auto-promote to no-halt + warn.
        if thread_role::is_agent() {
            warn!(
                "bp {} would halt agent thread (tid={}); auto-promoting to no-halt",
                bp_id.0,
                unsafe { GetCurrentThreadId() },
            );
            return false;
        }
        let mode = halt::halt_and_wait(Some(bp_id), context);
        apply_resume_mode(mode, context);
        true
    } else {
        false
    }
}

fn emit_log_event(bp_id: BpId, ctx: &HitEvalCtx, template: &[TemplatePart]) {
    let rendered = dsl::render(template, ctx);
    let tid = unsafe { GetCurrentThreadId() };
    // The events ring is the primary high-rate trace channel. The log
    // pipeline mirror is at debug! level so it's filtered out by the
    // default Info threshold — keeps `--no-halt --log` BPs from going
    // through stderr lock + OutputDebugStringA on every hit (the latter
    // can BLOCK on debugger ack), and dramatically shrinks the recursion
    // surface if the user BPs a function called by the logging path.
    debug!("bp {} hit (tid={tid} rip=0x{:x}): {rendered}", bp_id.0, ctx.regs.rip);
    events::push(Some(bp_id.0), tid, ctx.regs.rip, rendered);
}

struct HitEvalCtx {
    regs: Registers,
}

impl dsl::Eval for HitEvalCtx {
    fn reg(&self, name: &str) -> Option<u64> {
        match name {
            "rax" | "eax" => Some(self.regs.rax),
            "rcx" | "ecx" => Some(self.regs.rcx),
            "rdx" | "edx" => Some(self.regs.rdx),
            "rbx" | "ebx" => Some(self.regs.rbx),
            "rsp" | "esp" => Some(self.regs.rsp),
            "rbp" | "ebp" => Some(self.regs.rbp),
            "rsi" | "esi" => Some(self.regs.rsi),
            "rdi" | "edi" => Some(self.regs.rdi),
            "r8" => Some(self.regs.r8),
            "r9" => Some(self.regs.r9),
            "r10" => Some(self.regs.r10),
            "r11" => Some(self.regs.r11),
            "r12" => Some(self.regs.r12),
            "r13" => Some(self.regs.r13),
            "r14" => Some(self.regs.r14),
            "r15" => Some(self.regs.r15),
            "rip" | "eip" => Some(self.regs.rip),
            "eflags" => Some(self.regs.eflags as u64),
            _ => None,
        }
    }

    fn read_ptr(&self, addr: u64) -> Option<u64> {
        const PTR_BYTES: usize = std::mem::size_of::<usize>();
        let mut buf = [0u8; 8];
        let mut read: usize = 0;
        let ok = unsafe {
            ReadProcessMemory(
                GetCurrentProcess(),
                addr as *const _,
                buf.as_mut_ptr() as *mut _,
                PTR_BYTES,
                &mut read,
            ) != 0
                && read == PTR_BYTES
        };
        if !ok {
            return None;
        }
        Some(u64::from_le_bytes(buf))
    }
}

fn install_run_to_ret(context: &mut CONTEXT) {
    // Read [xSP] — assumed to be the return address. This holds at function
    // entry or right before `ret`; mid-function, [xSP] is whatever local was
    // pushed last. We sanity-check that the read points into an executable
    // module rather than spawning a one-shot SW BP at a junk address (which
    // would 0xCC random memory).
    const PTR_BYTES: usize = std::mem::size_of::<usize>();
    let sp = arch::sp(context) as usize;
    let mut buf = [0u8; PTR_BYTES];
    let mut read: usize = 0;
    let ok = unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            sp as *const _,
            buf.as_mut_ptr() as *mut _,
            PTR_BYTES,
            &mut read,
        ) != 0
            && read == PTR_BYTES
    };
    if !ok {
        warn!("ret mode: ReadProcessMemory at xSP=0x{sp:x} failed");
        return;
    }
    let ret_addr = usize::from_le_bytes(buf);
    if !addr_in_any_module(ret_addr) {
        warn!(
            "ret mode: [xSP]=0x{ret_addr:x} not in any loaded module — \
             refusing to plant SW BP at junk address. Likely caused by \
             halting mid-function (only safe at function entry / right \
             before ret)."
        );
        return;
    }
    let tid = unsafe { GetCurrentThreadId() };
    let _ = super::set(BpSpec {
        addr: ret_addr,
        kind: BpKind::Software,
        options: BpOptions { halt: true, one_shot: true, tid_filter: Some(tid) },
        hooks: BpHooks::default(),
        requested_name: None,
    });
}

fn addr_in_any_module(addr: usize) -> bool {
    modules::list()
        .iter()
        .any(|m| addr >= m.base && addr < m.base.saturating_add(m.size))
}
