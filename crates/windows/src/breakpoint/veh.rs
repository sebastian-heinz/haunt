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
use windows_sys::Win32::System::Memory::{
    VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentThreadId};

use super::{arch, halt, hardware, page, software, KindState};

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
//
// `PENDING_PAGE` is a Vec because a single instruction can fault on
// multiple guarded pages before the next TF fires: a misaligned load
// crossing a page boundary (or `rep movs` etc.) traps once per page,
// and each `on_guard_page` invocation must record a rearm. A scalar
// Option would lose every page after the first — silently making the
// BP one-shot for the lost pages on the very first multi-page hit.
//
// Cell (not RefCell) on purpose: RefCell::borrow_mut panics if the
// cell is already borrowed, and `panic = "abort"` on the cdylib means
// any panic kills the host. The take/set pattern below is panic-free.
thread_local! {
    static PENDING_SW: Cell<Option<SoftwareRearm>> = const { Cell::new(None) };
    static PENDING_PAGE: Cell<Vec<PageRearm>> = const { Cell::new(Vec::new()) };
    static STEP: Cell<StepMode> = const { Cell::new(StepMode::None) };
}

pub(super) unsafe extern "system" fn handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    let record = &*(*info).ExceptionRecord;
    let context = &mut *(*info).ContextRecord;

    match record.ExceptionCode {
        EXCEPTION_BREAKPOINT => on_int3(record.ExceptionAddress as usize, context),
        EXCEPTION_SINGLE_STEP => on_single_step(context),
        EXCEPTION_GUARD_PAGE => {
            // ExceptionAddress is the *instruction pointer* at fault time —
            // useless for read/write page BPs because the IP is on a code
            // page, not the guarded data page. The actual address that
            // tripped PAGE_GUARD lives in ExceptionInformation[1]; [0] is
            // the access type (0=read, 1=write, 8=DEP). Without this, page
            // BPs on data pages fall through to EXCEPTION_CONTINUE_SEARCH
            // and the OS terminates the host.
            if record.NumberParameters < 2 {
                return EXCEPTION_CONTINUE_SEARCH;
            }
            on_guard_page(record.ExceptionInformation[1], context)
        }
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
            None => {
                // Race recovery: `clear()` may have removed this BP and
                // restored the byte after the int3 fired but before our
                // lookup acquired the registry lock. The CPU's saved IP
                // points past the int3 byte (int3 is a trap, not a
                // fault), so resuming as-is would either skip the
                // single-byte instruction at `addr` or land mid-
                // instruction on a multi-byte original — silent
                // corruption. Detect by inspecting the byte: if it's no
                // longer 0xCC, clear() restored it; rewinding IP to
                // `addr` re-executes the original instruction and
                // closes the race. If the byte is still 0xCC, the int3
                // belongs to someone else (compiler-emitted, third-
                // party tool); propagate so their handler / OS can
                // deal with it. Reading via `ReadProcessMemory` rather
                // than direct deref so a concurrent unmap can't AV us
                // inside the VEH.
                drop(reg);
                if matches!(read_byte(addr), Some(b) if b != software::INT3) {
                    arch::set_ip(context, addr as u64);
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
                return EXCEPTION_CONTINUE_SEARCH;
            }
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
    // Invariant: on_single_step exits with TRAP_FLAG cleared. The flag's
    // sole legitimate post-handler use is "the user asked for another
    // step", which `apply_resume_mode(Step)` re-sets explicitly. Clearing
    // here unconditionally closes a host-kill path: if TF were left set
    // after a step→continue (HW BP halt path, or any step sequence with
    // no pending rearm to clear it), the next TF trap would land here
    // with no rearm, no STEP, and no DR slot fired, fall through to
    // EXCEPTION_CONTINUE_SEARCH, and the OS would terminate the host.
    context.EFlags &= !TRAP_FLAG;

    // 1. Process all pending re-arms accumulated since the last single-
    // step. Page and SW rearms can both be live simultaneously when a
    // page BP and a SW BP fire on the same instruction (e.g. a write
    // to a code page that also has an int3). Lose neither.
    let sw_rearm = PENDING_SW.with(|p| p.take());
    // `try_with` rather than `with` because `Vec<PageRearm>` has a
    // destructor that the thread-local runtime runs at thread exit.
    // After that destructor has run, `with` would panic — and a panic
    // under `panic = "abort"` on the cdylib kills the host. Our VEH
    // can theoretically fire on a thread mid-teardown (e.g., a SW BP
    // on a function called from `DLL_THREAD_DETACH` of another DLL);
    // silently treating PENDING_PAGE as empty in that window is the
    // correct degradation.
    let page_rearms: Vec<PageRearm> = PENDING_PAGE
        .try_with(|p| p.take())
        .unwrap_or_default();
    let had_rearm = sw_rearm.is_some() || !page_rearms.is_empty();

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
    for rearm in page_rearms {
        page::rearm(rearm.base, rearm.original_protect);
    }

    // 2. If the user had requested a step, the single-step we just handled (either
    //    a re-arm step or a bare step) is the user's step. Halt now.
    if STEP.with(|s| s.replace(StepMode::None)) == StepMode::Step {
        if let Some(mode) = halt::halt_and_wait(None, context) {
            apply_resume_mode(mode, context);
        } else {
            warn!("step halt could not park (event/lock/shutdown); thread continues");
        }
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
    // Single lock acquisition: previously this did `find_containing`
    // (which took the registry lock, returned, and dropped it) and then
    // re-acquired the lock to mutate the entry. A concurrent `clear()`
    // in that window left us with no entry → EXCEPTION_CONTINUE_SEARCH
    // → host kill (the kernel auto-cleared PAGE_GUARD before invoking
    // the VEH, so nothing else handles the exception).
    let page = page::page_base(addr);
    let (bp_id, options, hooks, tid_matches, base, original_protect) = {
        let mut reg = match super::registry().lock() {
            Ok(g) => g,
            Err(_) => return EXCEPTION_CONTINUE_SEARCH,
        };
        let tid = GetCurrentThreadId();
        let mut matched: Option<(usize, u32)> = None;
        let entry = reg.values_mut().find(|e| match &e.state {
            KindState::Page(s) => match s.pages.iter().find(|&&(b, _)| b == page) {
                Some(&(b, orig)) => {
                    matched = Some((b, orig));
                    true
                }
                None => false,
            },
            _ => false,
        });
        let entry = match entry {
            Some(e) => e,
            None => {
                // No registered BP covers this page. Before propagating,
                // check whether this is a known orphan from a failed
                // install (a page we set PAGE_GUARD on and couldn't
                // restore via VirtualProtect during rollback). If so,
                // the kernel already cleared PAGE_GUARD on this fault
                // — removing the entry is enough; the access will
                // succeed on retry. Without this recovery, the orphan
                // would propagate to EXCEPTION_CONTINUE_SEARCH and the
                // OS unhandled-exception filter would kill the host.
                drop(reg);
                if page::take_orphan(addr) {
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
                return EXCEPTION_CONTINUE_SEARCH;
            }
        };
        let (b, orig) = match matched {
            Some(m) => m,
            None => return EXCEPTION_CONTINUE_SEARCH,
        };
        entry.hits += 1;
        let tid_match = entry.options.tid_filter.map(|t| t == tid).unwrap_or(true);
        (entry.id, entry.options, Arc::clone(&entry.hooks), tid_match, b, orig)
    };

    context.EFlags |= TRAP_FLAG;
    push_page_rearm(PageRearm { base, original_protect });

    if tid_matches {
        let _ = run_hooks_then_maybe_halt(bp_id, options, &hooks, context);
    }

    EXCEPTION_CONTINUE_EXECUTION
}

/// Append a page rearm to this thread's pending-rearm list.
///
/// Implemented via `Cell::take` + push + `Cell::set` rather than
/// `RefCell::borrow_mut` to stay panic-free under `panic = "abort"`. If
/// the page-rearm path ever recurses on the same thread (e.g. a page BP
/// covering memory that `Vec::push` allocates into), the inner call's
/// `take` would observe the empty default and the outer call's `set`
/// would later overwrite the inner's recorded entry — losing it. That
/// is preferable to a `RefCell::already_borrowed` panic, which would
/// kill the host. The "user PAGE_GUARDed their own heap" case is a
/// clear footgun and acceptable to degrade.
///
/// Uses `try_with` for the same reason as the drain side: `Vec` has a
/// destructor, so accessing PENDING_PAGE during/after thread-local
/// teardown would panic. Silently dropping a rearm there is fine — the
/// page BP becomes one-shot for this teardown-bound thread.
fn push_page_rearm(rearm: PageRearm) {
    let _ = PENDING_PAGE.try_with(|p| {
        let mut v = p.take();
        // Guard against a runaway producer (e.g. a buggy instruction
        // looping in fault — should be impossible but cheap to bound).
        // 64 entries is far more than any real instruction touches and
        // far less than would matter for memory pressure.
        const PENDING_PAGE_CAP: usize = 64;
        if v.len() < PENDING_PAGE_CAP {
            v.push(rearm);
        }
        p.set(v);
    });
}

/// Translate a user-selected resume mode into the post-halt CONTEXT and
/// per-thread step state.
///
/// Deliberately does NOT touch `TRAP_FLAG` for `Continue` / `Ret`. The
/// flag's lifecycle is owned end-to-end by the trap handlers:
/// - `on_int3` and `on_guard_page` set TF before they return so the next
///   instruction single-steps and `on_single_step` can re-arm.
/// - `on_single_step` clears TF at entry, so any path through it (rearm,
///   user step, HW BP, fall-through) leaves TF correct on resume.
/// - Only `apply_resume_mode(Step)` re-sets TF here, after the handler
///   has cleared it.
///
/// Clearing TF here would defeat `on_int3`'s rearm step: a SW BP halt
/// followed by `Continue` would resume with TF=0, the original
/// instruction would execute without a TF trap, and the rearm in
/// `on_single_step` would never fire — turning every halt-then-continue
/// into a one-shot BP and leaking a stale `PENDING_SW` until some
/// unrelated TF later "consumed" it on the wrong instruction.
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

/// Evaluate the BP's split gates, render its `log` template (gated by
/// `log_cond`), emit the rendered record to the log pipeline + the events
/// ring buffer, then halt the thread iff `options.halt` AND `halt_cond`
/// passed. Returns `true` only when the thread was actually parked —
/// used by the HW path to decide whether to keep running other BPs that
/// fired in the same VEH invocation.
///
/// Gate semantics:
/// - `log_cond` (Some/zero): no log, no event. Halt is independent.
/// - `halt_cond` (Some/zero): no park, even when `options.halt = true`.
///   Log + event are independent.
/// - `entry.hits` is incremented by the caller before either gate, so
///   the bare hit count is the raw fire count — independent of gates
///   and independent of `tid_filter`.
unsafe fn run_hooks_then_maybe_halt(
    bp_id: BpId,
    options: BpOptions,
    hooks: &BpHooks,
    context: &mut CONTEXT,
) -> bool {
    let regs = arch::extract_regs(context);
    let ctx = HitEvalCtx { regs };

    // log gate first: rendering happens unconditionally so `--log` works
    // without any condition, and is suppressed by `--log-if` when set
    // and zero. Halt path is fully independent below.
    let log_passed = match &hooks.log_cond {
        Some(c) => dsl::eval(&c.expr, &ctx).unwrap_or(0) != 0,
        None => true,
    };
    if log_passed {
        if let Some(template) = &hooks.log {
            emit_log_event(bp_id, &ctx, &template.parts);
        }
    }

    if !options.halt {
        return false;
    }
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
    let halt_passed = match &hooks.halt_cond {
        Some(c) => dsl::eval(&c.expr, &ctx).unwrap_or(0) != 0,
        None => true,
    };
    if !halt_passed {
        return false;
    }
    match halt::halt_and_wait(Some(bp_id), context) {
        Some(mode) => {
            apply_resume_mode(mode, context);
            true
        }
        None => {
            // Park failed (event creation, lock, or shutdown). The
            // thread will continue without halting; return false so
            // the HW-BP dispatch loop keeps running other BPs that
            // fired on the same instruction instead of breaking
            // early on a halt that didn't actually happen.
            warn!(
                "bp {} halt could not park; thread continues",
                bp_id.0,
            );
            false
        }
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

/// Read a single byte at `addr` without faulting. Returns `None` if the
/// page is unmapped, which here means "give up gracefully" rather than
/// AV inside the VEH.
unsafe fn read_byte(addr: usize) -> Option<u8> {
    let mut buf = [0u8; 1];
    let mut read: usize = 0;
    let ok = ReadProcessMemory(
        GetCurrentProcess(),
        addr as *const _,
        buf.as_mut_ptr() as *mut _,
        1,
        &mut read,
    ) != 0
        && read == 1;
    if ok { Some(buf[0]) } else { None }
}

fn install_run_to_ret(context: &mut CONTEXT) {
    // Read [xSP] — assumed to be the return address. This holds at function
    // entry or right before `ret`; mid-function, [xSP] is whatever local was
    // pushed last. We sanity-check that the address points into committed,
    // executable memory rather than spawning a one-shot SW BP at a junk
    // address (which would 0xCC random memory).
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
    if !addr_is_executable(ret_addr) {
        warn!(
            "ret mode: [xSP]=0x{ret_addr:x} is not committed-executable — \
             refusing to plant SW BP at junk address. Likely caused by \
             halting mid-function (only safe at function entry / right \
             before ret)."
        );
        return;
    }
    let tid = unsafe { GetCurrentThreadId() };
    if let Err(e) = super::set(BpSpec {
        addr: ret_addr,
        kind: BpKind::Software,
        options: BpOptions { halt: true, one_shot: true, tid_filter: Some(tid) },
        hooks: BpHooks::default(),
        requested_name: None,
    }) {
        // Silent failure here is the worst outcome — `resume --ret`
        // returns 200 to the client and the thread runs free past the
        // function with no halt. Common causes: an existing BP at the
        // return address (Conflict), unwritable code page, or VEH
        // install having failed earlier. Surface the failure so it
        // shows up in `haunt logs`.
        warn!(
            "ret mode: failed to plant one-shot SW BP at 0x{ret_addr:x}: {e:?}"
        );
    }
}

/// True if `addr` is in a committed, executable memory region. Used to
/// gate run-to-ret against junk return addresses.
///
/// This deliberately uses `VirtualQuery` rather than walking the loaded-
/// module list:
/// - `VirtualQuery` does not take the PEB loader lock. The previous
///   `modules::list()`-based check called `CreateToolhelp32Snapshot`,
///   which does — and it ran from the VEH path on the resuming thread,
///   creating a deadlock vector if any other thread was in our VEH
///   blocked on the registry lock while holding the loader lock (e.g.,
///   faulted inside `LdrpLoadDll`).
/// - It accepts JIT regions (V8, .NET CLR, JVM, runtime-patched code)
///   in addition to image-mapped modules. The previous check rejected
///   those — a footgun for anyone instrumenting JIT'd targets.
/// - It rejects the actually-bad cases: uncommitted memory, stack/data
///   pages without execute permission, `PAGE_NOACCESS`, `PAGE_GUARD`.
fn addr_is_executable(addr: usize) -> bool {
    use std::mem::{size_of, MaybeUninit};
    let mut info = MaybeUninit::<MEMORY_BASIC_INFORMATION>::uninit();
    let written = unsafe {
        VirtualQuery(
            addr as *const _,
            info.as_mut_ptr(),
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if written == 0 {
        return false;
    }
    let info = unsafe { info.assume_init() };
    if info.State != MEM_COMMIT {
        return false;
    }
    // PAGE_GUARD is a flag ORed onto the base protection. A guarded page
    // is meant to fault on access; planting a SW BP on it would interfere
    // with whatever set up the guard (haunt's own page BPs, a third-party
    // tool, or stack-growth guards) and corrupt the byte for one hit
    // before being silently auto-cleared by the kernel.
    if info.Protect & PAGE_GUARD != 0 {
        return false;
    }
    const EXEC_MASK: u32 =
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    info.Protect & EXEC_MASK != 0
}
