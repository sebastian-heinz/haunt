//! Platform-agnostic core: HTTP server, protocol, breakpoint bookkeeping.
//!
//! Policy: no panics. `panic = "abort"` is set in the release profile, so any panic
//! kills the injected host. Every error path must return a `Result`.

pub mod dsl;
pub mod events;
pub mod log;
pub mod logs;
pub mod schema;
pub mod thread_role;

// MinGW i686 + panic=abort still references `_Unwind_Resume` from stdlib's
// alloc; libgcc_eh doesn't resolve it under static linking. Stub it here
// (panic=abort already guarantees any unwind path ends in process abort)
// so every haunt-core consumer — the cdylib agent, the injector, any
// future binary — picks up one definition through the normal dependency
// graph instead of hand-rolling the same stub per crate.
#[cfg(all(target_arch = "x86", target_env = "gnu"))]
#[no_mangle]
pub extern "C" fn _Unwind_Resume() -> ! {
    std::process::abort()
}

use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use tiny_http::{Header, Method, Request, Response, Server};

pub const DEFAULT_BIND: &str = "127.0.0.1:7878";
pub const MAX_READ_LEN: usize = 16 * 1024 * 1024;
pub const MAX_WRITE_LEN: usize = 16 * 1024 * 1024;
/// Hard cap on `POST /halts/<id>/regs` body. A real patch is dozens of
/// bytes (one `name=value` line per register, ≤18 registers). 64 KB is
/// well above any plausible scripted use; anything larger is either
/// abuse or a runaway script. Without a cap the handler's
/// `read_to_string` would allocate without bound and `panic = "abort"`
/// would turn an OOM into a host kill.
pub const MAX_REGS_BODY: usize = 64 * 1024;

/// Hard cap on every long-poll endpoint's `timeout` parameter
/// (`/halts/wait`, `/events`, `/logs`). A client sending
/// `?timeout=u64::MAX` would otherwise pin an agent worker thread
/// for ~584 million years. Defended at the HTTP edge (`handle_halts_
/// wait` / `handle_events` / `handle_logs`) and again in the
/// platform-side `wait_halt` / `events::poll` / `logs::poll` impls
/// — defending at both layers is cheap and means a buggy direct
/// `events::poll` caller can't bypass the edge check.
pub const MAX_LONG_POLL_TIMEOUT_MS: u64 = 300_000;

/// Hard cap on `limit` and `tail` for `/events` and `/logs`. Matches
/// the underlying ring capacity in `events::RING_CAP` / `logs::RING_CAP`,
/// so a single call can drain the whole ring (a `tail=N` snapshot, or
/// `limit=N` after a long-poll catches up). Keeping the bound and the
/// ring size in one constant prevents drift — bumping the ring without
/// bumping the bound would silently cap clients to the old value.
pub const MAX_TRACE_BATCH: usize = 40_960;

/// Hard cap on `limit` for `/memory/search`. Smaller than the trace
/// ring on purpose: every search hit is a usize, so a single call
/// returning many thousands of addresses would still be cheap on the
/// wire, but the search itself is `O(scope_size * pattern_len)`
/// against committed memory and a runaway `--all --limit` is the
/// obvious way to wedge an agent worker. 4096 covers any realistic
/// reverse-engineering use (a single signature hits a handful of
/// times in any one module); bigger asks should narrow scope, not
/// raise the limit. Named constant rather than a literal so the
/// HTTP-edge validator and any future client / docs share one source
/// of truth — same drift-avoidance reasoning as `MAX_TRACE_BATCH`.
pub const MAX_SEARCH_LIMIT: usize = 4096;

/// Hard cap on total concurrent worker threads. Each request runs on its
/// own worker (~1 MB stack VM on Windows x64); the long-poll endpoints
/// (`/halts/wait`, `/events`) can hold one for up to 60 s. Worst-case VM
/// pressure is ~80 MB, capping threads at 80.
pub const MAX_IN_FLIGHT: usize = 80;

/// Sub-cap on long-poll endpoints. The remaining `MAX_IN_FLIGHT -
/// MAX_LONG_POLL = 16` slots are reserved for short requests, so a buggy
/// or malicious client flooding `/halts/wait` can never lock the user
/// out of issuing `bp clear`, `resume`, or `regs` on their own halts.
/// This is the failure mode without a sub-pool: the user's own polling
/// loop deadlocks because their `resume` calls 503-out behind 64 stuck
/// `wait` requests.
pub const MAX_LONG_POLL: usize = 64;

static LONG_IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
static SHORT_IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy)]
enum SlotKind {
    /// Endpoints that hold the worker on a `Condvar`: `/halts/wait`,
    /// `/events`. Capped at `MAX_LONG_POLL` so they can never consume
    /// the entire worker pool.
    LongPoll,
    /// Everything else. Short requests can use up to the full
    /// `MAX_IN_FLIGHT`, but the long-poll counter is read into the
    /// admission decision so they implicitly share with long-polls.
    Short,
}

/// Build-time architecture string surfaced via `/info`. Lets clients pick
/// the correct calling convention without guessing at the agent's bitness
/// (the same agent build can run inside x64 or x86 hosts depending on the
/// DLL the user injected).
#[cfg(target_arch = "x86_64")]
pub const ARCH: &str = "x86_64";
#[cfg(target_arch = "x86")]
pub const ARCH: &str = "x86";
#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
pub const ARCH: &str = "unknown";

static AGENT_START: OnceLock<Instant> = OnceLock::new();

fn agent_uptime_ms() -> u64 {
    match AGENT_START.get() {
        Some(t) => t.elapsed().as_millis() as u64,
        None => 0,
    }
}

#[derive(Debug)]
pub enum MemError {
    /// Read crossed an unreadable boundary; the readable prefix is returned
    /// so the caller doesn't have to bisect. Length of the prefix == bytes
    /// successfully read; on Windows this is what `ReadProcessMemory` writes
    /// into the second-to-last out param. For writes, the `Vec` is empty
    /// (the n-bytes-written value rides in the variant the caller picks
    /// from `MemError::Partial(_).0.len()` on read paths only — write paths
    /// use `PartialWritten(usize)` to keep the type honest).
    Partial(Vec<u8>),
    /// `WriteProcessMemory` returned a short count. Writes can't usefully
    /// return "the bytes that were written" — the caller already had them.
    PartialWritten(usize),
    Fault,
    InvalidRange,
}

#[derive(Debug)]
pub enum BpError {
    Unsupported,
    Unwritable,
    NoHwSlot,
    NotFound,
    Internal,
    /// Conflict at the requested address: either another haunt breakpoint
    /// already covers it, or the byte already contains `0xCC` (a
    /// compiler-emitted `int 3`, a third-party hook, etc.). Either case
    /// would corrupt `original_byte` tracking — the install would read
    /// `0xCC` and remember it as the original, then on the first hit
    /// restore `0xCC`, re-trigger the int3, and infinite-loop.
    Conflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BpAccess {
    Execute,
    Write,
    ReadWrite,
    Any,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BpKind {
    Software,
    Hardware { access: BpAccess, size: u8 },
    /// `PAGE_GUARD` (or platform equivalent) over a range of pages. Fires on
    /// any access kind — there is no read/write/exec selectivity at the page
    /// granularity, unlike `Hardware`. The HTTP layer rejects `access=` for
    /// `kind=page` rather than silently ignoring it.
    Page { size: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BpOptions {
    pub halt: bool,
    pub one_shot: bool,
    pub tid_filter: Option<u32>,
}

impl Default for BpOptions {
    fn default() -> Self {
        Self { halt: true, one_shot: false, tid_filter: None }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BpId(pub u64);

pub struct BpSpec {
    pub addr: usize,
    pub kind: BpKind,
    pub options: BpOptions,
    pub hooks: BpHooks,
    /// If the BP was set via `name=module!symbol`, this carries the
    /// original requested string so `bp list` / `bp info` can show what
    /// the user asked for next to the resolved address. `None` when the
    /// BP was set by raw address.
    pub requested_name: Option<String>,
}

/// Server-side evaluated DSL hooks attached to a breakpoint.
///
/// - `log` is a template rendered on hit and emitted to both the log
///   pipeline and the `/events` ring buffer (gated by `log_cond` if
///   set).
/// - `log_cond` gates log + event emission. If `Some(expr)` and the
///   expression evaluates to zero on hit, no log line and no event
///   record. Halt is independent.
/// - `halt_cond` gates halt only. If `Some(expr)` and zero, the BP
///   does not park the firing thread even when `options.halt = true`.
///   Log + event emission are independent.
///
/// `entry.hits` is incremented on every fire regardless of either
/// gate — it's the raw fire count.
///
/// Splitting the gates lets the user log everything but halt only on
/// a specific subset (the original feedback that drove this design):
/// `--log "..." --halt-if "[ecx] == 0x..."` logs every call, halts
/// only on the runs that match.
///
/// Each hook keeps both the parsed AST (used by VEH at hit-time) and
/// the original source text (surfaced by `bp list` / `bp info` so
/// users can audit what a BP is doing without re-issuing it).
#[derive(Debug, Clone, Default)]
pub struct BpHooks {
    pub log: Option<dsl::TemplateHook>,
    pub log_cond: Option<dsl::CondHook>,
    pub halt_cond: Option<dsl::CondHook>,
    /// Per-BP struct bindings. Each entry is `name=Type@expr`; `expr` is
    /// evaluated each hit to get a base address, `Type` is looked up in
    /// the schema registry for field offsets. Consumed by upcoming
    /// `%[name.field]` template support.
    pub struct_bindings: Vec<dsl::StructBinding>,
}

impl BpHooks {
    pub fn is_empty(&self) -> bool {
        self.log.is_none()
            && self.log_cond.is_none()
            && self.halt_cond.is_none()
            && self.struct_bindings.is_empty()
    }

    pub fn log_text(&self) -> Option<&str> {
        self.log.as_ref().map(|h| h.source.as_str())
    }

    pub fn log_cond_text(&self) -> Option<&str> {
        self.log_cond.as_ref().map(|h| h.source.as_str())
    }

    pub fn halt_cond_text(&self) -> Option<&str> {
        self.halt_cond.as_ref().map(|h| h.source.as_str())
    }
}

pub struct BreakpointInfo {
    pub id: BpId,
    pub addr: usize,
    pub kind: BpKind,
    pub options: BpOptions,
    pub hits: u64,
    pub log: Option<String>,
    pub log_if: Option<String>,
    pub halt_if: Option<String>,
    pub requested_name: Option<String>,
    /// One entry per `--struct` flag, in declaration order. Surfaced by
    /// `bp list` / `bp info`. The parsed `Expr` lives on `BpHooks`; this
    /// snapshot keeps only what the listing format needs.
    pub struct_bindings: Vec<BindingInfo>,
}

#[derive(Debug, Clone)]
pub struct BindingInfo {
    pub name: String,
    pub type_name: String,
    /// Original `expr` source text (e.g. `[rcx]`). Round-trips through
    /// session save back into a `--struct` flag verbatim.
    pub expr_source: String,
}

#[derive(Clone, Copy, Debug)]
pub struct HaltSummary {
    pub hit_id: u64,
    pub bp_id: Option<BpId>,
    pub tid: u32,
    pub rip: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Registers {
    pub rax: u64, pub rcx: u64, pub rdx: u64, pub rbx: u64,
    pub rsp: u64, pub rbp: u64, pub rsi: u64, pub rdi: u64,
    pub r8: u64, pub r9: u64, pub r10: u64, pub r11: u64,
    pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
    pub rip: u64,
    pub eflags: u32,
}

/// Identifies a single register slot in `Registers`. Used by `halt_set_regs`
/// so partial edits (the common case — patch one field, leave the rest) can
/// merge into the parked thread's saved CONTEXT instead of clobbering it.
///
/// Names are unified across x64 and x86: `Rax` covers both `rax` and `eax`,
/// `Rip` covers both `rip` and `eip`, etc. The platform layer projects
/// these onto whichever CONTEXT field exists for the agent's bitness.
///
/// `EFlags` is deliberately NOT in this enum. The VEH stores its own
/// state inside `EFlags` (TF for the rearm-step dance, RF for HW-BP
/// resume) and writes the saved CONTEXT back to the CPU on resume, so a
/// user-supplied `eflags=` would silently disable BPs (TF cleared →
/// no rearm), infinite-loop in our VEH (RF cleared → same DR slot
/// re-fires), or kill the host (TF set with no matching rearm →
/// `EXCEPTION_CONTINUE_SEARCH` → OS unhandled-exception filter). The
/// natural footgun is `regs` showing TF=1 in a dump and the user
/// piping it back through `setregs`. Rejected at `parse_regs` with a
/// pointed message instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegName {
    Rax, Rcx, Rdx, Rbx,
    Rsp, Rbp, Rsi, Rdi,
    R8, R9, R10, R11, R12, R13, R14, R15,
    Rip,
}

impl RegName {
    /// Parse a register name from either the x64 (`rax`, `rip`) or x86
    /// (`eax`, `eip`) spelling. The unified eight 32-bit names map to the
    /// corresponding `R*` slot. Unknown names return `None` so the caller
    /// can surface "no such register: foo" instead of silently dropping
    /// the edit.
    ///
    /// `eflags` is deliberately not parsed here — see the type-level
    /// comment on `RegName`. `parse_regs` intercepts `eflags` ahead of
    /// this call with a pointed error so the user gets "eflags is
    /// VEH-managed" instead of "unknown register `eflags`".
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "rax" | "eax" => Self::Rax,
            "rcx" | "ecx" => Self::Rcx,
            "rdx" | "edx" => Self::Rdx,
            "rbx" | "ebx" => Self::Rbx,
            "rsp" | "esp" => Self::Rsp,
            "rbp" | "ebp" => Self::Rbp,
            "rsi" | "esi" => Self::Rsi,
            "rdi" | "edi" => Self::Rdi,
            "r8"  => Self::R8,
            "r9"  => Self::R9,
            "r10" => Self::R10,
            "r11" => Self::R11,
            "r12" => Self::R12,
            "r13" => Self::R13,
            "r14" => Self::R14,
            "r15" => Self::R15,
            "rip" | "eip" => Self::Rip,
            _ => return None,
        })
    }

    /// Apply this register's slot in `regs` to `value`. Used by the
    /// platform-side merge that turns a partial patch into a full
    /// `Registers` snapshot before resuming the parked thread.
    pub fn write(self, regs: &mut Registers, value: u64) {
        match self {
            Self::Rax => regs.rax = value,
            Self::Rcx => regs.rcx = value,
            Self::Rdx => regs.rdx = value,
            Self::Rbx => regs.rbx = value,
            Self::Rsp => regs.rsp = value,
            Self::Rbp => regs.rbp = value,
            Self::Rsi => regs.rsi = value,
            Self::Rdi => regs.rdi = value,
            Self::R8  => regs.r8  = value,
            Self::R9  => regs.r9  = value,
            Self::R10 => regs.r10 = value,
            Self::R11 => regs.r11 = value,
            Self::R12 => regs.r12 = value,
            Self::R13 => regs.r13 = value,
            Self::R14 => regs.r14 = value,
            Self::R15 => regs.r15 = value,
            Self::Rip => regs.rip = value,
        }
    }

    /// Lowercase canonical name. Unified across architectures (`Rip` →
    /// `"rip"`, never `"eip"`). Used to build user-facing error
    /// messages — `Debug` prints the variant name (`Rip`) which doesn't
    /// match the `name=value` syntax the user typed.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rax => "rax", Self::Rcx => "rcx", Self::Rdx => "rdx", Self::Rbx => "rbx",
            Self::Rsp => "rsp", Self::Rbp => "rbp", Self::Rsi => "rsi", Self::Rdi => "rdi",
            Self::R8 => "r8", Self::R9 => "r9", Self::R10 => "r10", Self::R11 => "r11",
            Self::R12 => "r12", Self::R13 => "r13", Self::R14 => "r14", Self::R15 => "r15",
            Self::Rip => "rip",
        }
    }

    /// `true` for x64-only registers (R8–R15). The x86 platform impl
    /// silently ignores writes to these slots (its CONTEXT has no R8+
    /// fields), so accepting them on a 32-bit agent would be a silent
    /// no-op — the strict-validation policy says reject up front and
    /// name the offending register instead.
    pub fn is_x64_only(self) -> bool {
        matches!(
            self,
            Self::R8 | Self::R9 | Self::R10 | Self::R11
            | Self::R12 | Self::R13 | Self::R14 | Self::R15
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResumeMode {
    Continue,
    Step,
    Ret,
}

#[derive(Debug)]
pub struct ModuleInfo {
    pub name: String,
    pub base: usize,
    pub size: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct StackFrame {
    pub rip: u64,
    pub rsp: u64,
    pub rbp: u64,
}

#[derive(Debug)]
pub struct ExportInfo {
    pub name: String,
    /// Resolved address. `0` for forwarded entries — there is no kernel32
    /// code for `kernel32!ExitProcess`, just an export-table string
    /// pointing at `ntdll!RtlExitUserProcess`. The actual callable address
    /// is what `GetProcAddress` returns, surfaced via `resolve_symbol`.
    pub addr: usize,
    /// `Some("ntdll.RtlExitUserProcess")` for forwarded exports; `None`
    /// for direct ones. Lets `/modules/<m>/exports` show forwarders
    /// instead of silently dropping them.
    pub forward: Option<String>,
}

/// Distinguishes "you asked for the wrong module" from "you asked for the
/// wrong symbol" so the CLI / HTTP layer can return distinct messages.
#[derive(Debug)]
pub enum ResolveError {
    ModuleNotFound,
    SymbolNotFound,
}

#[derive(Debug)]
pub struct RegionInfo {
    pub base: usize,
    pub size: usize,
    pub state: u32,
    pub protect: u32,
    pub ty: u32,
}

#[derive(Debug)]
pub struct ThreadInfo {
    pub tid: u32,
    /// True if `OpenThread(GET|SET|SUSPEND)` would succeed for this thread
    /// from inside the agent — i.e., the agent could apply HW breakpoints.
    pub accessible: bool,
    /// Current debug-register state if accessible. `None` if not accessible.
    pub dr: Option<[u64; 4]>,
    pub dr7: Option<u64>,
    /// `true` if this thread belongs to the agent (the HTTP accept thread
    /// or any in-flight per-request worker). Sourced from
    /// `thread_role::agent_tids()`, which tracks tids registered via
    /// `mark_agent` and removed on `AgentGuard` drop. Useful for confirming
    /// the agent excluded itself from HW-BP propagation, and for filtering
    /// "user" threads in client tooling.
    pub is_agent: bool,
}

#[derive(Debug, Default)]
pub struct ThreadStats {
    /// Successful `DLL_THREAD_ATTACH` HW BP applies since DLL load.
    pub attach_ok: u64,
    /// Failed `DLL_THREAD_ATTACH` HW BP applies since DLL load.
    pub attach_fail: u64,
}

pub trait Process: Send + Sync {
    fn read_memory(&self, addr: usize, len: usize) -> Result<Vec<u8>, MemError>;
    fn write_memory(&self, addr: usize, bytes: &[u8]) -> Result<(), MemError>;

    fn set_breakpoint(&self, spec: BpSpec) -> Result<BpId, BpError>;
    fn clear_breakpoint(&self, id: BpId) -> Result<(), BpError>;
    fn breakpoints(&self) -> Vec<BreakpointInfo>;

    fn halts(&self) -> Vec<HaltSummary>;
    /// Return the oldest parked halt with `hit_id > since`, blocking up to
    /// `timeout_ms` if none exist yet. `since=0` returns the oldest pending
    /// halt (or any new one that arrives during the wait).
    fn wait_halt(&self, timeout_ms: u64, since: u64) -> Option<HaltSummary>;
    fn halt_regs(&self, hit_id: u64) -> Option<Registers>;
    /// Apply a partial register patch to the parked thread's saved CONTEXT.
    /// Each `(name, value)` pair overwrites exactly one slot; every other
    /// register keeps its captured-at-halt value. Returns `NotFound` if
    /// `hit_id` is not parked.
    fn halt_set_regs(&self, hit_id: u64, patch: &[(RegName, u64)]) -> Result<(), BpError>;
    fn halt_resume(&self, hit_id: u64, mode: ResumeMode) -> Result<(), BpError>;

    fn modules(&self) -> Vec<ModuleInfo>;
    fn module_exports(&self, name: &str) -> Option<Vec<ExportInfo>>;
    fn memory_regions(&self) -> Vec<RegionInfo>;
    fn threads(&self) -> Vec<ThreadInfo>;
    fn thread_stats(&self) -> ThreadStats;
    /// Walk the call stack starting from `hit_id`'s frame. Returns frames
    /// with frame 0 = innermost (current PC). Empty vec means the hit is
    /// unknown. The unwinder is platform-specific: x64 uses
    /// `RtlVirtualUnwind` against `.pdata` (FPO-safe); x86 falls back to
    /// the rbp chain (truncates on FPO functions).
    fn stack_walk(&self, hit_id: u64, max_frames: usize) -> Vec<StackFrame>;
    /// Scan committed, readable memory in `[start, end)` for `pattern`,
    /// returning up to `limit` matching addresses in ascending order.
    /// `pattern[i] == None` is a wildcard byte.
    fn search_memory(
        &self,
        pattern: &[Option<u8>],
        start: usize,
        end: usize,
        limit: usize,
    ) -> Vec<usize>;
    /// Wake any blocked `wait_halt` long-pollers so they return immediately
    /// instead of spinning to their timeout. Called from the `/shutdown`
    /// handler. Default is a no-op for impls that don't have their own
    /// halt machinery yet.
    fn shutdown_halts(&self) {}

    /// OS-level pid surfaced via `/info`. Conceptually constant for the
    /// lifetime of the agent.
    fn pid(&self) -> u32;

    /// Pointer width of the target process in bytes (4 on x86, 8 on x64).
    /// Default returns the host pointer width via `size_of::<usize>()`,
    /// which is correct for in-process agents like `haunt-windows`. Used
    /// by `bp set --struct` to reject `ptr32` schemas against an x64
    /// agent (or vice versa) before the BP arms.
    fn pointer_width(&self) -> u8 {
        std::mem::size_of::<usize>() as u8
    }

    /// OS thread id of the *calling* thread. Used by `core::run` to register
    /// agent-spawned threads (the accept thread + per-request workers) into
    /// the agent-tid set so `/threads` can mark them and the VEH path can
    /// refuse to halt them. Has to live on the trait because `core` is
    /// platform-agnostic and can't call `GetCurrentThreadId` etc. directly.
    fn current_os_tid(&self) -> u32;

    /// Resolve `symbol` in `module` to its loaded address. Platforms
    /// should override with the OS's symbol resolver — on Windows that's
    /// `GetProcAddress`, which follows forwarders (e.g. `kernel32!ExitProcess`
    /// → `ntdll!RtlExitUserProcess`) and API-set redirection that the
    /// raw export-table walk in `module_exports` cannot. The default
    /// implementation falls back to the export walk for non-overriding
    /// platforms; it returns `SymbolNotFound` for forwarded entries
    /// because their `addr` is not a real callable address.
    fn resolve_symbol(&self, module: &str, symbol: &str) -> Result<usize, ResolveError> {
        let exports = self.module_exports(module).ok_or(ResolveError::ModuleNotFound)?;
        for e in exports {
            if e.name == symbol {
                if e.forward.is_some() {
                    return Err(ResolveError::SymbolNotFound);
                }
                return Ok(e.addr);
            }
        }
        Err(ResolveError::SymbolNotFound)
    }
}

pub struct Config {
    pub bind: String,
    pub token: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self { bind: DEFAULT_BIND.into(), token: None }
    }
}

pub fn run(process: Arc<dyn Process>, config: Config) {
    let _ = AGENT_START.set(Instant::now());
    // Bind to a name (not `let _ = ...`) so the guard lives for the
    // entire body of `run`. `let _ = ...` would drop it immediately,
    // unregistering the accept thread before it ever processed a request.
    let _agent_guard = thread_role::mark_agent(process.current_os_tid());
    let server = match Server::http(&config.bind) {
        Ok(s) => {
            info!("listening on http://{}", config.bind);
            Arc::new(s)
        }
        Err(e) => {
            error!("bind {} failed: {}", config.bind, e);
            return;
        }
    };
    let token = Arc::new(config.token);
    for request in server.incoming_requests() {
        // Thread-per-request so a long-polling `wait` or `events` doesn't
        // hold the server hostage. Capped via two pools:
        //   - long-poll endpoints: at most MAX_LONG_POLL (64)
        //   - everyone else: total in-flight at most MAX_IN_FLIGHT (80)
        // The 16-slot gap means short requests always have headroom even
        // when long-poll is fully saturated, so a stuck poll loop can
        // never lock the user out of issuing `bp clear` or `resume`.
        let kind = classify_request(request.method(), request.url());
        let slot = match try_acquire_slot(kind) {
            Some(s) => s,
            None => {
                let _ = request.respond(text(503, "too busy"));
                continue;
            }
        };
        let process = Arc::clone(&process);
        let server = Arc::clone(&server);
        let token = Arc::clone(&token);
        // `std::thread::spawn` is `Builder::new().spawn().unwrap()`, which
        // panics on thread-creation failure (kernel handle/quota exhaustion,
        // low memory, etc.). Under `panic = "abort"` that kills the host.
        // Use `Builder::spawn` and recover by responding 503 + releasing
        // the slot.
        let spawn_result = std::thread::Builder::new().spawn(move || {
            // Hold the slot for the lifetime of this worker; Drop releases
            // it whether we return normally or the worker thread is torn
            // down. Move (not borrow) into the closure.
            let _slot = slot;
            // Drop guard removes this worker's tid from the agent set when
            // the thread exits, so /threads stays accurate as workers come
            // and go.
            let _agent = thread_role::mark_agent(process.current_os_tid());
            let mut request = request;
            let response = route(
                &mut request,
                process.as_ref(),
                (*token).as_deref(),
                &server,
            );
            let _ = request.respond(response);
        });
        if let Err(e) = spawn_result {
            // The closure was dropped on Err, taking the request, slot, and
            // arcs with it. The slot guard's Drop already decremented the
            // counter; we just have to log and move on. The client sees a
            // dropped TCP connection (tiny_http reaps the request when the
            // closure drops), which is the same outcome as a 503 from the
            // pool-exhaustion path.
            warn!("worker spawn failed: {e}; dropping request");
        }
    }
    info!("http server stopped");
}

/// RAII handle on one of the request slots. Construct via
/// `try_acquire_slot`; release happens automatically on drop.
/// Remembers which counter to decrement.
struct SlotGuard {
    kind: SlotKind,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let counter = match self.kind {
            SlotKind::LongPoll => &LONG_IN_FLIGHT,
            SlotKind::Short => &SHORT_IN_FLIGHT,
        };
        counter.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Classify a request by its method + URL path so the accept loop can
/// admit it to the right pool. Hardcodes the long-poll endpoints rather
/// than threading classification through `route` — there are exactly two
/// of them and they're load-bearing. If new long-polls are ever added,
/// they MUST be added here too or they'll occupy short slots and
/// reintroduce the starvation bug this pool exists to prevent.
fn classify_request(method: &Method, url: &str) -> SlotKind {
    if !matches!(method, Method::Get) {
        return SlotKind::Short;
    }
    let path = match url.find('?') {
        Some(i) => &url[..i],
        None => url,
    };
    match path {
        "/halts/wait" | "/events" | "/logs" => SlotKind::LongPoll,
        _ => SlotKind::Short,
    }
}

/// Atomically reserve one slot in the matching pool. Returns `None` if
/// the cap is reached. Lock-free CAS loop on the relevant atomic.
///
/// Relaxed ordering: counts are atomic but don't synchronise any other
/// memory. A spurious "full" reading (slot freed concurrently but our
/// load is stale) just produces a 503 the client retries.
///
/// The short path reads the long-poll counter inside the loop, so a
/// concurrent long-poll arrival can race the admission decision; worst
/// case is a transient over-commit by 1, which is acceptable — sustained
/// total still tracks `MAX_IN_FLIGHT`.
fn try_acquire_slot(kind: SlotKind) -> Option<SlotGuard> {
    match kind {
        SlotKind::LongPoll => {
            let mut cur = LONG_IN_FLIGHT.load(Ordering::Relaxed);
            loop {
                if cur >= MAX_LONG_POLL {
                    return None;
                }
                match LONG_IN_FLIGHT.compare_exchange_weak(
                    cur,
                    cur + 1,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return Some(SlotGuard { kind: SlotKind::LongPoll }),
                    Err(actual) => cur = actual,
                }
            }
        }
        SlotKind::Short => {
            let mut cur = SHORT_IN_FLIGHT.load(Ordering::Relaxed);
            loop {
                let long = LONG_IN_FLIGHT.load(Ordering::Relaxed);
                if cur + long >= MAX_IN_FLIGHT {
                    return None;
                }
                match SHORT_IN_FLIGHT.compare_exchange_weak(
                    cur,
                    cur + 1,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return Some(SlotGuard { kind: SlotKind::Short }),
                    Err(actual) => cur = actual,
                }
            }
        }
    }
}

type Body = std::io::Cursor<Vec<u8>>;

fn route(
    req: &mut Request,
    process: &dyn Process,
    token: Option<&str>,
    server: &Arc<Server>,
) -> Response<Body> {
    if let Err(resp) = check_request(req, token) {
        return resp;
    }

    let method = req.method().clone();
    let url = req.url().to_string();
    let (path, query) = split_query(&url);

    // Strict query well-formedness: every pair must be `key=value`.
    // Doing this once in the dispatcher beats per-handler checks; the
    // failure mode without it is `?foo` (missing `=`) being silently
    // dropped by `parse_query`, so `bp set ?addr=...&halft_if=...`
    // sets a BP with no halt gate when the user typoed `halt_if`.
    if let Err(e) = validate_query(query) {
        return text(400, &e);
    }

    // Static routes first. Doing this before the dynamic prefix matchers
    // avoids the trap where `/halts/wait` gets routed to handle_halt_sub
    // which can't parse "wait" as a hit_id.
    //
    // No-arg static endpoints route through `noarg(query, ...)`, which
    // 400s on any non-empty query — `/ping?foo=1` returning `pong` was
    // a silent typo footgun.
    let static_match = match (&method, path) {
        (Method::Get, "/ping") => Some(noarg(query, || text(200, "pong"))),
        (Method::Get, "/version") => {
            Some(noarg(query, || text(200, env!("CARGO_PKG_VERSION"))))
        }
        (Method::Get, "/info") => Some(noarg(query, || handle_info(process))),
        (Method::Get, "/memory/read") => Some(handle_read(process, query)),
        (Method::Post, "/memory/write") => Some(handle_write(process, query, req)),
        (Method::Post, "/bp/set") => Some(handle_bp_set(process, query)),
        (Method::Post, "/bp/clear") => Some(handle_bp_clear(process, query)),
        (Method::Get, "/bp/list") => Some(noarg(query, || handle_bp_list(process))),
        (Method::Get, "/symbols/resolve") => Some(handle_symbol_resolve(process, query)),
        (Method::Get, "/symbols/lookup") => Some(handle_symbol_lookup(process, query)),
        (Method::Get, "/events") => Some(handle_events(query)),
        (Method::Get, "/logs") => Some(handle_logs(query)),
        (Method::Get, "/halts") => Some(noarg(query, || handle_halts_list(process))),
        (Method::Get, "/halts/wait") => Some(handle_halts_wait(process, query)),
        (Method::Get, "/modules") => Some(noarg(query, || handle_modules(process))),
        (Method::Get, "/memory/regions") => Some(noarg(query, || handle_regions(process))),
        (Method::Get, "/memory/search") => Some(handle_memory_search(process, query)),
        (Method::Get, "/threads") => Some(noarg(query, || handle_threads(process))),
        (Method::Post, "/schemas") => Some(handle_schema_set(query, req)),
        (Method::Get, "/schemas") => Some(noarg(query, handle_schema_list)),
        (Method::Delete, "/schemas") => Some(noarg(query, || handle_schema_clear(process))),
        (Method::Post, "/shutdown") => Some(noarg(query, || {
            // Order matters: `shutdown_halts` must run BEFORE we stop
            // accepting requests. The platform impl is responsible for both
            // refusing new parks AND resuming any already-parked threads in
            // a single atomic step (otherwise a halt that races shutdown
            // could park forever — the previous "snapshot halts(); resume
            // each; set flag" sequence had exactly that gap).
            process.shutdown_halts();
            events::shutdown();
            logs::shutdown();
            server.unblock();
            text(200, "shutting down")
        })),
        _ => None,
    };
    if let Some(r) = static_match {
        return r;
    }

    // Dynamic /bp/<id> for single-BP inspection.
    if let Some(rest) = path.strip_prefix("/bp/") {
        if method == Method::Get {
            if let Ok(id) = rest.parse::<u64>() {
                return noarg(query, || handle_bp_info(process, BpId(id)));
            }
        }
    }

    // Dynamic /halts/<id>/... routes
    if let Some(rest) = path.strip_prefix("/halts/") {
        return handle_halt_sub(&method, rest, query, process, req);
    }

    // Dynamic /modules/<name>/exports
    if let Some(rest) = path.strip_prefix("/modules/") {
        if method == Method::Get {
            if let Some(name) = rest.strip_suffix("/exports") {
                return noarg(query, || handle_module_exports(process, &percent_decode(name)));
            }
        }
    }

    // Dynamic /schemas/<TypeName> — GET shows, DELETE drops.
    if let Some(rest) = path.strip_prefix("/schemas/") {
        let name = percent_decode(rest);
        return match method {
            Method::Get => noarg(query, || handle_schema_show(&name)),
            Method::Delete => noarg(query, || handle_schema_drop(process, &name)),
            _ => text(405, "method not allowed"),
        };
    }

    text(404, "not found")
}

fn handle_halt_sub(
    method: &Method,
    rest: &str,
    query: &str,
    process: &dyn Process,
    req: &mut Request,
) -> Response<Body> {
    let (id_str, action) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };
    let Ok(hit_id) = id_str.parse::<u64>() else {
        return text(400, "invalid hit_id");
    };
    match (method, action) {
        (Method::Get, "") => match process.halt_regs(hit_id) {
            Some(regs) => {
                let modules = process.modules();
                text(200, &format_regs(&regs, &modules))
            }
            None => text(404, "not found"),
        },
        (Method::Get, "stack") => handle_halt_stack(process, hit_id, query),
        (Method::Post, "regs") => {
            // Cap the body so a malicious or buggy client can't OOM-abort the
            // host with a multi-GB POST. A real setregs body is dozens of
            // bytes; 64 KB is generous enough for any plausible scripted use.
            let mut body = String::new();
            if req.as_reader().take(MAX_REGS_BODY as u64 + 1).read_to_string(&mut body).is_err() {
                return text(400, "body read error");
            }
            if body.len() > MAX_REGS_BODY {
                return text(400, "body too large");
            }
            let patch = match parse_regs(&body) {
                Ok(p) => p,
                Err(e) => return text(400, &e),
            };
            if let Err(e) = validate_patch_for_arch(&patch, process.pointer_width()) {
                return text(400, &e);
            }
            match process.halt_set_regs(hit_id, &patch) {
                Ok(()) => text(200, "ok"),
                Err(BpError::NotFound) => text(404, "not found"),
                _ => text(500, "internal"),
            }
        }
        (Method::Post, "resume") => {
            let mode = match parse_resume_mode(query) {
                Ok(m) => m,
                Err(e) => return text(400, &e),
            };
            match process.halt_resume(hit_id, mode) {
                Ok(()) => text(200, "resumed"),
                Err(BpError::NotFound) => text(404, "not found"),
                _ => text(500, "internal"),
            }
        }
        _ => text(404, "not found"),
    }
}

const STACK_DEFAULT_DEPTH: usize = 32;
const STACK_MAX_DEPTH: usize = 256;

fn handle_halt_stack(process: &dyn Process, hit_id: u64, query: &str) -> Response<Body> {
    // Distinguish missing (use default) from present-but-invalid (400). The
    // previous `unwrap_or(default)` swallowed parse errors silently so a
    // typo like `?depth=abc` gave a 32-frame walk when the user meant `256`,
    // with no signal that the limit fell back.
    let mut depth = STACK_DEFAULT_DEPTH;
    for (k, v) in parse_query(query) {
        match k {
            "depth" => match v.parse::<usize>() {
                Ok(n) => depth = n,
                Err(_) => return text(400, "depth: not a number"),
            },
            _ => return text(400, &format!("unknown query param: {k}")),
        }
    }
    if depth == 0 {
        return text(400, "depth: must be > 0");
    }
    if depth > STACK_MAX_DEPTH {
        return text(400, &format!("depth: must be <= {STACK_MAX_DEPTH}"));
    }

    let frames = process.stack_walk(hit_id, depth);
    if frames.is_empty() {
        return text(404, "not found");
    }
    let modules = process.modules();
    let mut body = String::new();
    for (i, f) in frames.iter().enumerate() {
        body.push_str(&format!("#{i} rip=0x{:x}", f.rip));
        if let Some((name, off)) = resolve_addr(&modules, f.rip) {
            body.push_str(&format!(" {name}+0x{off:x}"));
        }
        body.push('\n');
    }
    // Disambiguate "stack ended naturally" from "depth limit hit". An
    // unwinder always returns a final frame whose unwind couldn't proceed
    // (rip=0, unreadable, or rsp didn't increase), so a result equal in
    // length to the requested depth almost certainly hit the limit.
    if frames.len() >= depth {
        body.push_str(&format!("... (truncated at depth={depth})\n"));
    }
    text(200, &body)
}

fn resolve_addr(modules: &[ModuleInfo], addr: u64) -> Option<(&str, usize)> {
    let a = addr as usize;
    modules.iter().find_map(|m| {
        if a >= m.base && a < m.base.saturating_add(m.size) {
            Some((m.name.as_str(), a - m.base))
        } else {
            None
        }
    })
}

/// Parse `?mode=` for the resume endpoint. Distinguishes the two failure
/// modes the previous `Option` collapsed:
/// - `Ok(Continue)` when no `mode` param was supplied — the documented
///   default.
/// - `Err(_)` when `mode` was present but unrecognised — a typo like
///   `?mode=stp` (instead of `step`) used to silently `Continue`, which
///   meant the user thought they single-stepped while the thread ran free.
fn parse_resume_mode(query: &str) -> Result<ResumeMode, String> {
    let mut raw: Option<String> = None;
    for (k, v) in parse_query(query) {
        match k {
            "mode" => raw = Some(v),
            _ => return Err(format!("unknown query param: {k}")),
        }
    }
    match raw.as_deref() {
        None => Ok(ResumeMode::Continue),
        Some("continue") => Ok(ResumeMode::Continue),
        Some("step") => Ok(ResumeMode::Step),
        Some("ret") => Ok(ResumeMode::Ret),
        Some(other) => Err(format!(
            "mode: expected continue|step|ret, got `{other}`"
        )),
    }
}

fn handle_info(process: &dyn Process) -> Response<Body> {
    // Surface trace-ring drop counters so users can tell whether a
    // shorter-than-expected `/events` or `/logs` stream means "BPs
    // didn't fire" vs. "fires hit the re-entry guard" vs. "ring
    // overflowed before the consumer drained it." Both are silent
    // record losses by construction (re-entry to avoid a deadlock,
    // overflow to bound memory); making them visible is the project's
    // standard answer to silent-default risks.
    let (ev_re, ev_ov) = events::drop_counters();
    let (lg_re, lg_ov) = logs::drop_counters();
    let body = format!(
        "version={}\narch={}\npid={}\nuptime_ms={}\n\
         events_dropped_reentry={ev_re}\nevents_dropped_overflow={ev_ov}\n\
         logs_dropped_reentry={lg_re}\nlogs_dropped_overflow={lg_ov}\n",
        env!("CARGO_PKG_VERSION"),
        ARCH,
        process.pid(),
        agent_uptime_ms(),
    );
    text(200, &body)
}

fn handle_modules(process: &dyn Process) -> Response<Body> {
    let mut body = String::new();
    for m in process.modules() {
        body.push_str(&format!("name={} base=0x{:x} size={}\n", m.name, m.base, m.size));
    }
    text(200, &body)
}

fn handle_module_exports(process: &dyn Process, name: &str) -> Response<Body> {
    match process.module_exports(name) {
        Some(exports) => {
            let mut body = String::new();
            for e in exports {
                if let Some(fwd) = e.forward {
                    // Forwarded entry — addr would be 0; show the target
                    // string instead so users can `bp set` against the
                    // forwarded module directly if they want.
                    body.push_str(&format!("name={} forward={}\n", e.name, fwd));
                } else {
                    body.push_str(&format!("name={} addr=0x{:x}\n", e.name, e.addr));
                }
            }
            text(200, &body)
        }
        None => text(404, "module not found"),
    }
}

fn handle_threads(process: &dyn Process) -> Response<Body> {
    let stats = process.thread_stats();
    let mut body = format!(
        "attach_ok={} attach_fail={}\n",
        stats.attach_ok, stats.attach_fail,
    );
    for t in process.threads() {
        body.push_str(&format!("tid={} accessible={}", t.tid, t.accessible));
        if t.is_agent {
            body.push_str(" agent=true");
        }
        if let (Some(dr), Some(dr7)) = (t.dr, t.dr7) {
            body.push_str(&format!(
                " dr0=0x{:x} dr1=0x{:x} dr2=0x{:x} dr3=0x{:x} dr7=0x{:x}",
                dr[0], dr[1], dr[2], dr[3], dr7,
            ));
        }
        body.push('\n');
    }
    text(200, &body)
}

fn handle_memory_search(process: &dyn Process, query: &str) -> Response<Body> {
    let mut pattern_str: Option<String> = None;
    let mut module: Option<String> = None;
    let mut start: Option<usize> = None;
    let mut end: Option<usize> = None;
    let mut all: bool = false;
    let mut limit: usize = 256;
    for (k, v) in parse_query(query) {
        match k {
            "pattern" => pattern_str = Some(v),
            "module" => module = Some(v),
            "start" => match parse_usize(&v) {
                Some(a) => start = Some(a),
                None => return text(400, "start: not a number"),
            },
            "end" => match parse_usize(&v) {
                Some(a) => end = Some(a),
                None => return text(400, "end: not a number"),
            },
            "all" => match parse_bool(&v) {
                Some(b) => all = b,
                None => return text(400, "all: expected true/false"),
            },
            "limit" => match v.parse::<usize>() {
                Ok(n) => {
                    if n == 0 {
                        return text(400, "limit: must be > 0");
                    }
                    if n > MAX_SEARCH_LIMIT {
                        return text(400, &format!("limit: must be <= {MAX_SEARCH_LIMIT}"));
                    }
                    limit = n;
                }
                Err(_) => return text(400, "limit: not a number"),
            },
            _ => return text(400, &format!("unknown query param: {k}")),
        }
    }
    let Some(pat_str) = pattern_str else {
        return text(400, "missing pattern");
    };
    let pattern = match parse_byte_pattern(&pat_str) {
        Ok(p) => p,
        Err(e) => return text(400, &format!("pattern: {e}")),
    };

    // Scope precedence: module > start/end > all. Any of those is fine; no
    // scope at all is rejected — a whole-address-space scan on a multi-GB
    // target can pin a worker for minutes (one ReadProcessMemory chunk at a
    // time, no cancel mechanism), and "search with no scope" being the
    // default footgun is exactly the kind of "rm -rf without flags" UX we
    // don't want for a tool people drop into running production targets.
    // Users who genuinely want a whole-AS scan opt in with `all=true`
    // (CLI: `--all`).
    let (scope_start, scope_end) = if let Some(name) = &module {
        let mods = process.modules();
        let m = match mods.iter().find(|m| m.name.eq_ignore_ascii_case(name)) {
            Some(m) => m,
            None => return text(404, "module not found"),
        };
        (m.base, m.base.saturating_add(m.size))
    } else if start.is_some() || end.is_some() {
        (start.unwrap_or(0), end.unwrap_or(usize::MAX))
    } else if all {
        (0, usize::MAX)
    } else {
        return text(
            400,
            "scope required: pass module=<name>, start=<addr>&end=<addr>, or all=true",
        );
    };
    if scope_start >= scope_end {
        return text(400, "empty scope");
    }

    let hits = process.search_memory(&pattern, scope_start, scope_end, limit);
    let mut body = String::new();
    for addr in hits {
        body.push_str(&format!("addr=0x{addr:x}\n"));
    }
    text(200, &body)
}

fn handle_regions(process: &dyn Process) -> Response<Body> {
    let mut body = String::new();
    for r in process.memory_regions() {
        body.push_str(&format!(
            "base=0x{:x} size={} state=0x{:x} protect=0x{:x} type=0x{:x}\n",
            r.base, r.size, r.state, r.protect, r.ty,
        ));
    }
    text(200, &body)
}

fn handle_halts_list(process: &dyn Process) -> Response<Body> {
    let mut body = String::new();
    for h in process.halts() {
        body.push_str(&format_halt(&h));
    }
    text(200, &body)
}

fn handle_halts_wait(process: &dyn Process, query: &str) -> Response<Body> {
    let mut timeout: u64 = 30_000;
    let mut since: u64 = 0;
    for (k, v) in parse_query(query) {
        match k {
            "timeout" => match v.parse::<u64>() {
                Ok(t) => timeout = t,
                Err(_) => return text(400, "timeout: not a number"),
            },
            "since" => match v.parse::<u64>() {
                Ok(s) => since = s,
                Err(_) => return text(400, "since: not a number"),
            },
            _ => return text(400, &format!("unknown query param: {k}")),
        }
    }
    if timeout > MAX_LONG_POLL_TIMEOUT_MS {
        return text(400, &format!("timeout: must be <= {MAX_LONG_POLL_TIMEOUT_MS}"));
    }
    match process.wait_halt(timeout, since) {
        Some(h) => text(200, &format_halt(&h)),
        None => text(204, ""),
    }
}

fn format_halt(h: &HaltSummary) -> String {
    let bp = match h.bp_id {
        Some(id) => format!("bp_id={}", id.0),
        None => "bp_id=none".into(),
    };
    // Trailing newline matches `format_bp` and every other line-formatted
    // endpoint, so `/halts/wait` (single record) and `/halts` (list) emit
    // identically-shaped lines — clients that consume both with
    // line-oriented parsers don't need a special case.
    format!("hit_id={} {} tid={} rip=0x{:x}\n", h.hit_id, bp, h.tid, h.rip)
}

fn format_regs(r: &Registers, modules: &[ModuleInfo]) -> String {
    let mut s = String::with_capacity(512);
    let mut emit = |name: &str, v: u64| {
        s.push_str(&format!("{name}=0x{v:016x}"));
        if let Some((m, off)) = resolve_addr(modules, v) {
            s.push_str(&format!(" {m}+0x{off:x}"));
        }
        s.push('\n');
    };
    macro_rules! line { ($($name:ident),* $(,)?) => { $( emit(stringify!($name), r.$name); )* }; }
    line!(rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15, rip);
    s.push_str(&format!("eflags=0x{:08x}\n", r.eflags));
    s
}

/// Parse a `setregs` body into a list of `(register, new_value)` patches.
/// One line per register. Either x64 (`rax=...`) or x86 (`eax=...`) names
/// are accepted and unified by `RegName::parse`.
///
/// Errors:
/// - any line missing `=`
/// - any value that doesn't parse as decimal or `0x`-prefixed hex
/// - any unknown register name (so a typo like `rxx=0` is surfaced rather
///   than silently dropped — the previous behaviour combined with a blind
///   overwrite turned typos into target-process crashes)
/// - `eflags` (see below)
///
/// `eflags` is rejected outright. The VEH stores its rearm-step bit (TF)
/// and HW-BP resume bit (RF) inside `EFlags`, and the saved CONTEXT is
/// written back to the CPU on resume. A user `eflags=` patch would clear
/// TF mid-rearm (silently disabling the BP and leaking a stale
/// `PENDING_SW`/`PENDING_PAGE` rearm into a future unrelated TF), clear
/// RF mid-HW-BP (infinite loop in our VEH), or set TF with no matching
/// rearm pending (host kill via `EXCEPTION_CONTINUE_SEARCH`). The
/// natural footgun is `regs` showing TF=1 and the user piping that line
/// back through `setregs`. There is no documented user need to edit
/// `eflags` mid-halt; if one materialises later, add a separate
/// explicit knob that masks VEH-managed bits.
fn parse_regs(body: &str) -> Result<Vec<(RegName, u64)>, String> {
    let mut out = Vec::new();
    for (lineno, raw) in body.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| format!("line {}: expected `name=value`", lineno + 1))?;
        let name = name.trim();
        if name == "eflags" {
            return Err(format!(
                "line {}: refusing to setregs `eflags`: it carries VEH-managed bits \
                 (TF for BP rearm, RF for HW-BP resume) that the agent rewrites on \
                 every halt. Editing it can silently disable BPs or kill the host. \
                 Drop the eflags line; every other register merges normally.",
                lineno + 1,
            ));
        }
        let value = parse_u64(value.trim())
            .ok_or_else(|| format!("line {}: bad value for {name}", lineno + 1))?;
        let reg = RegName::parse(name)
            .ok_or_else(|| format!("line {}: unknown register `{name}`", lineno + 1))?;
        out.push((reg, value));
    }
    Ok(out)
}

fn parse_u64(s: &str) -> Option<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

/// Reject patch entries that would silently no-op or truncate on the
/// target agent's pointer width. Two cases:
///
/// - `R8`–`R15` on a 32-bit agent: those slots have no x86 CONTEXT
///   field, so the merge is a silent no-op. The natural footgun is a
///   user pasting an x64 `regs` dump into an x86 `setregs` and not
///   realising those lines did nothing.
/// - Any value > `u32::MAX` on a 32-bit agent: the platform writes
///   `r.foo as u32` into the CONTEXT, silently discarding the high
///   half. Same x64-dump-into-x86-setregs footgun, but for the address
///   value rather than the register name.
///
/// Other widths fall through (only x86 and x64 are supported targets;
/// adding a future ARM64 would have its own check). 64-bit agents
/// accept the full u64 range — every register slot is 64 bits.
fn validate_patch_for_arch(
    patch: &[(RegName, u64)],
    ptr_width: u8,
) -> Result<(), String> {
    if ptr_width != 4 {
        return Ok(());
    }
    for &(name, value) in patch {
        if name.is_x64_only() {
            return Err(format!(
                "register `{}` is x64-only; agent is 32-bit (the merge would be a silent no-op). \
                 Drop this line; if you copied from an x64 regs dump, only the e* / rax-rdi / rsp / rbp / rsi / rdi / rip lines apply.",
                name.as_str(),
            ));
        }
        if value > u32::MAX as u64 {
            return Err(format!(
                "value 0x{value:x} for `{}` exceeds 32-bit range on this x86 agent (would silently truncate to 0x{:x}). \
                 Re-check the source — common cause is piping an x64 regs dump into an x86 setregs.",
                name.as_str(),
                value as u32,
            ));
        }
    }
    Ok(())
}

/// Front-door checks applied to every request. Three independent gates:
///
/// 1. **Origin**: refuse if the `Origin` header is set to anything other
///    than empty / `null`. The agent binds to loopback, but a webpage in
///    the user's browser can `fetch('http://127.0.0.1:7878/...')`. Browsers
///    always send `Origin` on cross-origin requests; the CLI does not.
///    Returning `403` here closes drive-by exfiltration via cross-origin
///    GETs and drive-by mutation via simple cross-origin POSTs.
/// 2. **`X-Haunt-Client`**: must be present (any value). Browsers can't
///    add custom headers to a "simple" request without triggering CORS
///    preflight, which the agent doesn't support — so a missing header
///    indicates either a non-CLI client or a malicious page that can't
///    preflight. CLI scripts and `curl` users add `-H 'X-Haunt-Client: ...'`.
/// 3. **`Authorization: Bearer <token>`**: enforced only when the agent
///    was started with `HAUNT_TOKEN`. Constant-time comparison.
///
/// Distinct status codes for each failure so users can diagnose without
/// guessing.
fn check_request(req: &Request, expected: Option<&str>) -> Result<(), Response<Body>> {
    for h in req.headers() {
        if h.field.equiv("Origin") {
            let v = h.value.as_str();
            if !v.is_empty() && v != "null" {
                return Err(text(403, "cross-origin request rejected"));
            }
        }
    }
    let mut has_client = false;
    for h in req.headers() {
        if h.field.equiv("X-Haunt-Client") {
            has_client = true;
            break;
        }
    }
    if !has_client {
        return Err(text(
            400,
            "missing X-Haunt-Client header (CLI sets this; curl users add -H 'X-Haunt-Client: curl')",
        ));
    }
    if let Some(expected) = expected {
        if !auth_token_ok(req, expected) {
            return Err(text(401, "unauthorized"));
        }
    }
    Ok(())
}

fn auth_token_ok(req: &Request, expected: &str) -> bool {
    for h in req.headers() {
        if h.field.equiv("Authorization") {
            // RFC 7235 §2.1: auth-scheme is case-insensitive.
            let v = h.value.as_str();
            let mut parts = v.splitn(2, ' ');
            let scheme = parts.next().unwrap_or("");
            let token = parts.next().unwrap_or("");
            if scheme.eq_ignore_ascii_case("Bearer") {
                return constant_time_eq(token.as_bytes(), expected.as_bytes());
            }
        }
    }
    false
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn handle_read(process: &dyn Process, query: &str) -> Response<Body> {
    let mut addr = None;
    let mut len = None;
    let mut raw = false;
    for (k, v) in parse_query(query) {
        match k {
            "addr" => match parse_usize(&v) {
                Some(a) => addr = Some(a),
                None => return text(400, "addr: not a number"),
            },
            "len" => match parse_usize(&v) {
                Some(a) => len = Some(a),
                None => return text(400, "len: not a number"),
            },
            "format" => match v.as_str() {
                "hex" => raw = false,
                "raw" => raw = true,
                other => return text(400, &format!(
                    "format: expected hex|raw, got `{other}`"
                )),
            },
            _ => return text(400, &format!("unknown query param: {k}")),
        }
    }
    let (Some(addr), Some(len)) = (addr, len) else {
        return text(400, "missing addr or len");
    };
    if len == 0 || len > MAX_READ_LEN {
        return text(400, "invalid len");
    }
    let (status, bytes) = match process.read_memory(addr, len) {
        Ok(b) => (200, b),
        // Return the readable prefix as the body so the caller doesn't have
        // to bisect across an unmapped page. Status 206 (partial content) is
        // the signal; clients can also compare returned len to requested len.
        Err(MemError::Partial(prefix)) => (206, prefix),
        Err(MemError::PartialWritten(_)) => return text(500, "internal: write-partial on read"),
        Err(MemError::Fault) => return text(403, "unreadable"),
        Err(MemError::InvalidRange) => return text(400, "invalid range"),
    };
    if raw {
        binary(status, bytes)
    } else {
        text(status, &hex_encode(&bytes))
    }
}

fn handle_write(process: &dyn Process, query: &str, req: &mut Request) -> Response<Body> {
    let mut addr: Option<usize> = None;
    for (k, v) in parse_query(query) {
        match k {
            "addr" => match parse_usize(&v) {
                Some(a) => addr = Some(a),
                None => return text(400, "addr: not a number"),
            },
            _ => return text(400, &format!("unknown query param: {k}")),
        }
    }
    let Some(addr) = addr else {
        return text(400, "missing addr");
    };

    let mut body = Vec::new();
    let limit = (MAX_WRITE_LEN as u64) + 1;
    if req.as_reader().take(limit).read_to_end(&mut body).is_err() {
        return text(500, "body read error");
    }
    if body.len() > MAX_WRITE_LEN {
        return text(400, "body too large");
    }
    match process.write_memory(addr, &body) {
        Ok(()) => text(200, &format!("wrote {} bytes", body.len())),
        Err(MemError::PartialWritten(n)) => text(206, &format!("partial: {n} bytes written")),
        Err(MemError::Partial(_)) => text(500, "internal: read-partial on write"),
        Err(MemError::Fault) => text(403, "unwritable"),
        Err(MemError::InvalidRange) => text(400, "invalid range"),
    }
}

fn handle_bp_set(process: &dyn Process, query: &str) -> Response<Body> {
    let mut addr: Option<usize> = None;
    let mut name: Option<String> = None;
    let mut kind_str: Option<String> = None;
    let mut access_str: Option<String> = None;
    let mut size_u: Option<usize> = None;
    let mut halt_flag: Option<bool> = None;
    let mut one_shot: Option<bool> = None;
    let mut tid_filter: Option<u32> = None;
    let mut log_raw: Option<String> = None;
    let mut log_if_raw: Option<String> = None;
    let mut halt_if_raw: Option<String> = None;
    let mut struct_raw: Vec<String> = Vec::new();
    for (k, v) in parse_query(query) {
        match k {
            "addr" => match parse_usize(&v) {
                Some(a) => addr = Some(a),
                None => return text(400, "addr: not a number"),
            },
            "name" => name = Some(v),
            "kind" => kind_str = Some(v),
            "access" => access_str = Some(v),
            "size" => match parse_usize(&v) {
                Some(s) => size_u = Some(s),
                None => return text(400, "size: not a number"),
            },
            "halt" => match parse_bool(&v) {
                Some(b) => halt_flag = Some(b),
                None => return text(400, "halt: expected true/false/1/0/yes/no/on/off"),
            },
            "one_shot" => match parse_bool(&v) {
                Some(b) => one_shot = Some(b),
                None => return text(400, "one_shot: expected true/false/1/0/yes/no/on/off"),
            },
            "tid" => match v.parse::<u32>() {
                Ok(t) => tid_filter = Some(t),
                Err(_) => return text(400, "tid: not a u32"),
            },
            "log" => log_raw = Some(v),
            "log_if" => log_if_raw = Some(v),
            "halt_if" => halt_if_raw = Some(v),
            "struct" => struct_raw.push(v),
            _ => return text(400, &format!("unknown query param: {k}")),
        }
    }
    let (addr, requested_name) = match (addr, name) {
        (Some(_), Some(_)) => return text(400, "addr and name are exclusive"),
        (Some(a), None) => (a, None),
        (None, Some(n)) => match resolve_symbol(process, &n) {
            Ok(a) => (a, Some(n)),
            Err((status, msg)) => return text(status, msg),
        },
        (None, None) => return text(400, "missing addr or name"),
    };

    // Reject access/size against kind=sw up front. Without this, a user who
    // intends a hardware write watchpoint and types
    // `bp set 0x... --access w --size 4` would silently get a software int3
    // because `--kind` defaults to `sw` and the hw-only flags were dropped
    // on the floor.
    let kind = match kind_str.as_deref().unwrap_or("sw") {
        "sw" | "software" => {
            if access_str.is_some() {
                return text(400, "access is only valid with kind=hw or kind=page");
            }
            if size_u.is_some() {
                return text(400, "size is only valid with kind=hw or kind=page");
            }
            BpKind::Software
        }
        "hw" | "hardware" => {
            let access = match parse_access(access_str.as_deref().unwrap_or("exec")) {
                Some(a) => a,
                None => return text(400, "access: expected x|exec|w|write|rw|readwrite|any"),
            };
            let size = size_u.unwrap_or(1) as u8;
            if !matches!(size, 1 | 2 | 4 | 8) {
                return text(400, "size must be 1|2|4|8");
            }
            BpKind::Hardware { access, size }
        }
        "page" => {
            // PAGE_GUARD fires on any access kind; there's no per-kind
            // selectivity at the page granularity. Reject `access=` rather
            // than silently treating it as "any" — a user intending only
            // writes would otherwise see hits on every read and execute too.
            if access_str.is_some() {
                return text(400, "access is not supported with kind=page (PAGE_GUARD fires on any access)");
            }
            let size = size_u.unwrap_or(1);
            if size == 0 {
                return text(400, "size must be > 0");
            }
            BpKind::Page { size }
        }
        _ => return text(400, "invalid kind"),
    };

    let options = BpOptions {
        halt: halt_flag.unwrap_or(true),
        one_shot: one_shot.unwrap_or(false),
        tid_filter,
    };

    let log = match log_raw {
        Some(s) => match dsl::parse_template(&s) {
            Ok(parts) => Some(dsl::TemplateHook { source: s, parts }),
            Err(e) => return text(400, &format!("log: {e}")),
        },
        None => None,
    };
    let log_cond = match log_if_raw {
        Some(s) => match dsl::parse_expr(&s) {
            Ok(expr) => Some(dsl::CondHook { source: s, expr }),
            Err(e) => return text(400, &format!("log_if: {e}")),
        },
        None => None,
    };
    let halt_cond = match halt_if_raw {
        Some(s) => match dsl::parse_expr(&s) {
            Ok(expr) => Some(dsl::CondHook { source: s, expr }),
            Err(e) => return text(400, &format!("halt_if: {e}")),
        },
        None => None,
    };

    // Validate `--struct` bindings against the schema registry, then
    // hold the schema lock across the BP install. Each binding is
    // `name=Type@expr`: name is a fresh local binding (must be unique
    // per BP), Type must already exist in the registry, expr must parse,
    // and every pointer field reachable through that type must match the
    // agent's pointer width (rejects `ptr32` schemas on x64 / vice versa).
    //
    // The schema lock is held across `set_breakpoint` to close the
    // TOCTOU where a concurrent `schema drop` (which now also holds the
    // schema lock across its bp-list scan) could remove a referenced
    // type between our validation and the BP install. Lock order is
    // schema → bp throughout: this handler is the only place we hold
    // schema across a bp-registry mutation, and `schema drop` /
    // `schema clear` only acquire bp-registry under the schema lock
    // for a brief read. SW/page installs are microsecond-scale; HW
    // installs suspend other threads but those threads can't be in the
    // schema lock (only this handler and `schema drop`/`clear` hold it,
    // all of which are agent-thread-only).
    let mut struct_bindings: Vec<dsl::StructBinding> = Vec::new();
    let target_ptr_width = process.pointer_width();
    let reg = schema::registry::lock();
    {
        let mut seen_names: std::collections::HashSet<String> =
            std::collections::HashSet::with_capacity(struct_raw.len());
        for s in &struct_raw {
            let b = match dsl::parse_struct_binding(s) {
                Ok(b) => b,
                Err(e) => return text(400, &format!("--struct '{s}': {e}")),
            };
            if !seen_names.insert(b.name.clone()) {
                return text(
                    400,
                    &format!("--struct '{s}': binding name '{}' already used", b.name),
                );
            }
            let resolved = match reg.get(&b.type_name) {
                Some(r) => r,
                None => {
                    return text(
                        400,
                        &format!(
                            "--struct '{s}': struct '{}' not in schema registry (load it with `haunt schema load`)",
                            b.type_name
                        ),
                    );
                }
            };
            if let Some((field_name, w)) = mismatched_ptr_field(resolved, target_ptr_width) {
                return text(
                    400,
                    &format!(
                        "--struct '{s}': struct '{}' has ptr{w} field '{field_name}' but agent is {}-bit",
                        b.type_name,
                        target_ptr_width * 8,
                    ),
                );
            }
            struct_bindings.push(b);
        }
    }

    let hooks = BpHooks {
        log,
        log_cond,
        halt_cond,
        struct_bindings,
    };

    // Validate every `%[binding.field.subfield]` reference in the log
    // template now, against the bindings + live schema registry. Without
    // this, a typo'd field name surfaces only at hit time as a `<no field
    // 'X'>` marker — fine for a typo you spot in the live log, terrible
    // for a typo you don't notice for hours.
    //
    // Pass the held registry through; `validate_field_paths` requires
    // the caller to own the lock so the schema state validated here
    // remains the schema state used by `set_breakpoint` below.
    if let Some(template) = &hooks.log {
        if let Err(e) = dsl::validate_field_paths(template, &hooks.struct_bindings, &reg) {
            return text(400, &format!("--log: {e}"));
        }
    }

    let result = process.set_breakpoint(BpSpec { addr, kind, options, hooks, requested_name });
    drop(reg);
    match result {
        // Echo the resolved address back so the user can sanity-check what
        // a `name=module!symbol` lookup actually landed on. Forwarded
        // exports (kernel32!ExitProcess → ntdll!RtlExitUserProcess) make
        // this non-obvious; without the echo the user has to cross-check
        // against `haunt resolve`.
        Ok(id) => text(200, &format!("id={} addr=0x{:x}\n", id.0, addr)),
        Err(BpError::Unsupported) => text(400, "unsupported combination"),
        Err(BpError::Unwritable) => text(403, "unwritable"),
        Err(BpError::NoHwSlot) => text(409, "no hardware slot"),
        Err(BpError::Conflict) => text(409, "address conflicts with an existing breakpoint, a pre-existing 0xCC byte, or a page that already has PAGE_GUARD set"),
        Err(BpError::NotFound) => text(404, "not found"),
        Err(BpError::Internal) => text(500, "internal error"),
    }
}

fn handle_symbol_resolve(process: &dyn Process, query: &str) -> Response<Body> {
    let mut name: Option<String> = None;
    for (k, v) in parse_query(query) {
        match k {
            "name" => name = Some(v),
            _ => return text(400, &format!("unknown query param: {k}")),
        }
    }
    let Some(name) = name else {
        return text(400, "missing name");
    };
    match resolve_symbol(process, &name) {
        Ok(addr) => text(200, &format!("addr=0x{:x}\n", addr)),
        Err((status, msg)) => text(status, msg),
    }
}

fn handle_symbol_lookup(process: &dyn Process, query: &str) -> Response<Body> {
    let mut addr: Option<usize> = None;
    for (k, v) in parse_query(query) {
        match k {
            "addr" => match parse_usize(&v) {
                Some(a) => addr = Some(a),
                None => return text(400, "addr: not a number"),
            },
            _ => return text(400, &format!("unknown query param: {k}")),
        }
    }
    let Some(addr) = addr else {
        return text(400, "missing addr");
    };
    let modules = process.modules();
    match resolve_addr(&modules, addr as u64) {
        Some((name, offset)) => {
            let base = addr - offset;
            text(200, &format!("module={name} base=0x{base:x} offset=0x{offset:x}\n"))
        }
        None => text(404, "no module contains this address"),
    }
}

fn resolve_symbol(process: &dyn Process, name: &str) -> Result<usize, (u16, &'static str)> {
    let (module, symbol) = name
        .split_once('!')
        .ok_or((400, "name must be module!symbol"))?;
    process.resolve_symbol(module, symbol).map_err(|e| match e {
        ResolveError::ModuleNotFound => (404, "module not found"),
        ResolveError::SymbolNotFound => (404, "symbol not found"),
    })
}

fn handle_bp_clear(process: &dyn Process, query: &str) -> Response<Body> {
    let mut id: Option<u64> = None;
    for (k, v) in parse_query(query) {
        match k {
            "id" => match v.parse::<u64>() {
                Ok(n) => id = Some(n),
                Err(_) => return text(400, "id: not a number"),
            },
            _ => return text(400, &format!("unknown query param: {k}")),
        }
    }
    let Some(id) = id else {
        return text(400, "missing id");
    };
    match process.clear_breakpoint(BpId(id)) {
        Ok(()) => text(200, "cleared"),
        Err(BpError::NotFound) => text(404, "not found"),
        _ => text(500, "internal error"),
    }
}

fn handle_bp_list(process: &dyn Process) -> Response<Body> {
    let mut body = String::new();
    for bp in process.breakpoints() {
        body.push_str(&format_bp(&bp));
    }
    text(200, &body)
}

fn handle_bp_info(process: &dyn Process, id: BpId) -> Response<Body> {
    match process.breakpoints().into_iter().find(|b| b.id == id) {
        Some(bp) => text(200, &format_bp(&bp)),
        None => text(404, "not found"),
    }
}

fn format_bp(bp: &BreakpointInfo) -> String {
    let mut s = format!(
        "id={} addr=0x{:x} kind={} halt={} one_shot={} tid_filter={} hits={}",
        bp.id.0,
        bp.addr,
        format_kind(&bp.kind),
        bp.options.halt,
        bp.options.one_shot,
        bp.options.tid_filter.map(|t| t.to_string()).unwrap_or_else(|| "-".into()),
        bp.hits,
    );
    if let Some(log) = &bp.log {
        s.push_str(&format!(" log={}", quote_msg(log)));
    }
    if let Some(c) = &bp.log_if {
        s.push_str(&format!(" log_if={}", quote_msg(c)));
    }
    if let Some(c) = &bp.halt_if {
        s.push_str(&format!(" halt_if={}", quote_msg(c)));
    }
    if let Some(req) = &bp.requested_name {
        s.push_str(&format!(" requested={}", quote_msg(req)));
    }
    for b in &bp.struct_bindings {
        // `name=Type@expr` is the canonical binding form — quote it whole
        // so the `=` and `@` separators don't collide with the line's
        // outer `key=value` syntax. Session save parses this back via the
        // same quoted-string handler used by `log` / `requested`.
        s.push_str(&format!(
            " struct={}",
            quote_msg(&format!("{}={}@{}", b.name, b.type_name, b.expr_source))
        ));
    }
    s.push('\n');
    s
}

fn handle_logs(query: &str) -> Response<Body> {
    let mut since: u64 = 0;
    let mut limit: usize = 256;
    let mut timeout: u64 = 0;
    for (k, v) in parse_query(query) {
        match k {
            "since" => match v.parse::<u64>() {
                Ok(n) => since = n,
                Err(_) => return text(400, "since: not a number"),
            },
            "limit" => match v.parse::<usize>() {
                Ok(n) => {
                    if n == 0 {
                        return text(400, "limit: must be > 0");
                    }
                    if n > MAX_TRACE_BATCH {
                        return text(400, &format!("limit: must be <= {MAX_TRACE_BATCH}"));
                    }
                    limit = n;
                }
                Err(_) => return text(400, "limit: not a number"),
            },
            "timeout" => match v.parse::<u64>() {
                Ok(n) => timeout = n,
                Err(_) => return text(400, "timeout: not a number"),
            },
            _ => return text(400, &format!("unknown query param: {k}")),
        }
    }
    if timeout > MAX_LONG_POLL_TIMEOUT_MS {
        return text(400, &format!("timeout: must be <= {MAX_LONG_POLL_TIMEOUT_MS}"));
    }
    let records = logs::poll(since, limit, timeout);
    let mut body = String::new();
    for r in records {
        body.push_str(&format!(
            "id={} t={}ms level={} tid={} msg={}\n",
            r.id, r.millis, r.level.as_str(), r.tid,
            quote_msg(&r.msg),
        ));
    }
    text(200, &body)
}

fn handle_events(query: &str) -> Response<Body> {
    let mut since: u64 = 0;
    let mut limit: usize = 256;
    let mut timeout: u64 = 0;
    let mut bp_id: Option<u64> = None;
    let mut tail: Option<usize> = None;
    for (k, v) in parse_query(query) {
        match k {
            "since" => match v.parse::<u64>() {
                Ok(n) => since = n,
                Err(_) => return text(400, "since: not a number"),
            },
            "limit" => match v.parse::<usize>() {
                Ok(n) => {
                    if n == 0 {
                        return text(400, "limit: must be > 0");
                    }
                    if n > MAX_TRACE_BATCH {
                        return text(400, &format!("limit: must be <= {MAX_TRACE_BATCH}"));
                    }
                    limit = n;
                }
                Err(_) => return text(400, "limit: not a number"),
            },
            "timeout" => match v.parse::<u64>() {
                Ok(n) => timeout = n,
                Err(_) => return text(400, "timeout: not a number"),
            },
            "bp_id" => match v.parse::<u64>() {
                Ok(n) => bp_id = Some(n),
                Err(_) => return text(400, "bp_id: not a number"),
            },
            "tail" => match v.parse::<usize>() {
                Ok(n) => {
                    if n == 0 {
                        return text(400, "tail: must be > 0");
                    }
                    if n > MAX_TRACE_BATCH {
                        return text(400, &format!("tail: must be <= {MAX_TRACE_BATCH}"));
                    }
                    tail = Some(n);
                }
                Err(_) => return text(400, "tail: not a number"),
            },
            _ => return text(400, &format!("unknown query param: {k}")),
        }
    }
    if timeout > MAX_LONG_POLL_TIMEOUT_MS {
        return text(400, &format!("timeout: must be <= {MAX_LONG_POLL_TIMEOUT_MS}"));
    }
    let evts = events::poll(since, limit, timeout, bp_id, tail);
    let mut body = String::new();
    for e in evts {
        let bp = match e.bp_id {
            Some(id) => format!("bp_id={id}"),
            None => "bp_id=none".into(),
        };
        body.push_str(&format!(
            "id={} {} tid={} rip=0x{:x} t={}ms msg={}\n",
            e.id, bp, e.tid, e.rip, e.millis,
            quote_msg(&e.msg),
        ));
    }
    text(200, &body)
}

// --- Schemas (struct-layout registry) ----------------------------------
//
// `POST /schemas` — body is a `.layouts` source. `?replace=true` overwrites
// colliding struct names atomically; otherwise collisions reject the whole
// upload (409). The agent re-validates regardless of what the CLI did.
//
// `GET /schemas` — flat list, name-sorted.
// `GET /schemas/<Type>` — fields of one struct.
// `DELETE /schemas/<Type>` — drop one.
// `DELETE /schemas` — wipe.

const MAX_SCHEMA_BODY: usize = 1024 * 1024;

fn handle_schema_set(query: &str, req: &mut Request) -> Response<Body> {
    let mut replace = false;
    for (k, v) in parse_query(query) {
        match k {
            "replace" => match parse_bool(&v) {
                Some(b) => replace = b,
                None => return text(400, "replace: expected true|false"),
            },
            _ => return text(400, &format!("unknown query param: {k}")),
        }
    }

    let mut body = Vec::new();
    let limit = (MAX_SCHEMA_BODY as u64) + 1;
    if req.as_reader().take(limit).read_to_end(&mut body).is_err() {
        return text(500, "body read error");
    }
    if body.len() > MAX_SCHEMA_BODY {
        return text(400, &format!("body too large (max {MAX_SCHEMA_BODY} bytes)"));
    }
    let src = match std::str::from_utf8(&body) {
        Ok(s) => s,
        Err(_) => return text(400, "body: not valid UTF-8"),
    };

    let schema = match schema::compile(src) {
        Ok(s) => s,
        Err(err) => {
            let mut buf: Vec<u8> = Vec::new();
            if schema::render_compile_error(&err, "schema", src, false, &mut buf).is_err() {
                return text(500, "diag render error");
            }
            let body = String::from_utf8(buf).unwrap_or_else(|_| "schema invalid".into());
            return text(400, &body);
        }
    };

    let policy = if replace {
        schema::registry::ReplacePolicy::Replace
    } else {
        schema::registry::ReplacePolicy::Reject
    };

    let mut reg = schema::registry::lock();
    match reg.add(schema, policy) {
        Ok(out) => {
            let mut body = String::new();
            body.push_str(&format!("added={} replaced={}\n", out.added.len(), out.replaced.len()));
            for n in &out.added {
                body.push_str(&format!("+ {n}\n"));
            }
            for n in &out.replaced {
                body.push_str(&format!("~ {n}\n"));
            }
            text(200, &body)
        }
        Err(schema::registry::RegistryError::NameCollision { existing }) => {
            let names = existing.join(", ");
            text(
                409,
                &format!(
                    "name collision: struct(s) already defined: {names} \
                     (re-upload with ?replace=true to overwrite)\n"
                ),
            )
        }
        Err(schema::registry::RegistryError::NotFound { name }) => {
            // Unreachable in `add`, but exhaustive match for safety.
            text(500, &format!("internal: unexpected NotFound for '{name}'"))
        }
    }
}

fn handle_schema_list() -> Response<Body> {
    let reg = schema::registry::lock();
    let mut body = String::new();
    for s in reg.iter_sorted() {
        body.push_str(&format!(
            "{} size=0x{:X} fields={}\n",
            s.name,
            s.size,
            s.fields().len()
        ));
    }
    text(200, &body)
}

fn handle_schema_show(name: &str) -> Response<Body> {
    let reg = schema::registry::lock();
    let Some(s) = reg.get(name) else {
        return text(404, &format!("struct '{name}' not in registry"));
    };
    text(200, &emit_struct_source(s))
}

/// Render a `ResolvedStruct` back to canonical `.layouts` source. Lossless
/// for layout (re-uploadable byte-for-byte equivalent), lossy for comments
/// and exact whitespace. Round-trips through `GET /schemas/<Type>` →
/// `POST /schemas` identically.
///
/// Two-pass formatter: first pass measures the widest type token and the
/// widest `name[arr]` so the second pass can column-align them. Same shape
/// as a hand-aligned source file — easier to scan than the prior
/// single-space form, still re-parseable byte-for-byte.
fn emit_struct_source(s: &schema::layout::ResolvedStruct) -> String {
    let rows: Vec<(String, String, u64)> = s
        .fields()
        .iter()
        .map(|f| {
            let ty = format_field_kind(f);
            // Field-level array dim (`name[N]`) — distinct from `cstr[N]` /
            // `bytes[N]`, which is part of the type token itself.
            let name_arr = if f.array_count > 1 {
                format!("{}[{}]", f.name, f.array_count)
            } else {
                f.name.clone()
            };
            (ty, name_arr, f.offset)
        })
        .collect();

    let ty_w = rows.iter().map(|(t, _, _)| t.len()).max().unwrap_or(0);
    let name_w = rows.iter().map(|(_, n, _)| n.len()).max().unwrap_or(0);

    let mut out = format!("struct {} size=0x{:X} {{\n", s.name, s.size);
    for (ty, name_arr, off) in &rows {
        out.push_str(&format!(
            "    {ty:<ty_w$}  {name_arr:<name_w$}  @0x{off:X}\n",
            ty_w = ty_w,
            name_w = name_w,
        ));
    }
    out.push_str("}\n");
    out
}

fn handle_schema_drop(process: &dyn Process, name: &str) -> Response<Body> {
    // Reject the drop while any active BP binds to this struct — the BP's
    // template would render `<unknown type>` markers at next hit, which is
    // exactly the silent breakage AGENTS.md warns against.
    //
    // The BP scan and the registry mutation must happen under the SAME
    // schema-registry lock acquisition, otherwise a `bp set --struct`
    // racing this handler can slip in between the scan and the remove:
    // it acquires schema-lock, sees `name` valid, drops schema-lock,
    // takes bp-registry-lock, registers the BP — and our drop, which
    // saw an empty referencing-list, deletes the schema out from under
    // it. Lock order is schema → bp throughout (`handle_bp_set` follows
    // the same order at the `--struct` validation site), so holding
    // schema across the bp-list scan can't deadlock.
    let mut reg = schema::registry::lock();
    let referencing = bps_referencing(process, &[name.to_string()]);
    if !referencing.is_empty() {
        return text(
            409,
            &format!(
                "struct '{name}' is referenced by {} active breakpoint(s) (ids {}); \
                 clear them before dropping the struct\n",
                referencing.len(),
                referencing
                    .iter()
                    .map(|id| id.0.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
        );
    }
    match reg.remove(name) {
        Ok(()) => text(200, &format!("dropped={name}\n")),
        Err(_) => text(404, &format!("struct '{name}' not in registry")),
    }
}

fn handle_schema_clear(process: &dyn Process) -> Response<Body> {
    // Same rationale as drop: every BP binding silently breaks if its
    // type vanishes. Listing the BPs in the error lets the user run
    // `haunt bp clear <id>` for each before retrying.
    //
    // Same lock-ordering rationale as `handle_schema_drop`: schema lock
    // held across both the BP scan and the wipe so a concurrent
    // `bp set --struct` can't slip a new binding in between.
    let mut reg = schema::registry::lock();
    let bound: Vec<BpId> = process
        .breakpoints()
        .into_iter()
        .filter(|b| !b.struct_bindings.is_empty())
        .map(|b| b.id)
        .collect();
    if !bound.is_empty() {
        return text(
            409,
            &format!(
                "{} active breakpoint(s) bind to schema structs (ids {}); \
                 clear them before wiping the registry\n",
                bound.len(),
                bound
                    .iter()
                    .map(|id| id.0.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
        );
    }
    let n = reg.len();
    reg.clear();
    text(200, &format!("cleared={n}\n"))
}

/// Find every BP whose `--struct` bindings reference any of `names`.
/// Returns the BP IDs in `bp list` order. Pure-data so it's testable
/// without a `Process` mock.
fn bps_referencing(process: &dyn Process, names: &[String]) -> Vec<BpId> {
    bps_referencing_in(&process.breakpoints(), names)
}

/// Return the first pointer field whose width disagrees with `target_width`.
/// Both `Ptr` (opaque) and `PtrTyped` participate. Returns `(field_name,
/// declared_width)` so the caller can render an actionable error.
fn mismatched_ptr_field(
    s: &schema::layout::ResolvedStruct,
    target_width: u8,
) -> Option<(String, u8)> {
    for f in s.fields() {
        if let Some(w) = f.pointer_width() {
            if w != target_width {
                return Some((f.name.clone(), w));
            }
        }
    }
    None
}

fn bps_referencing_in(bps: &[BreakpointInfo], names: &[String]) -> Vec<BpId> {
    bps.iter()
        .filter(|bp| {
            bp.struct_bindings
                .iter()
                .any(|b| names.iter().any(|n| n == &b.type_name))
        })
        .map(|bp| bp.id)
        .collect()
}

fn format_field_kind(f: &schema::layout::ResolvedField) -> String {
    use schema::layout::FieldKind::*;
    let prim = match (f.kind, f.element_size) {
        (UInt, 1) => "u8".to_string(),
        (UInt, 2) => "u16".to_string(),
        (UInt, 4) => "u32".to_string(),
        (UInt, 8) => "u64".to_string(),
        (SInt, 1) => "i8".to_string(),
        (SInt, 2) => "i16".to_string(),
        (SInt, 4) => "i32".to_string(),
        (SInt, 8) => "i64".to_string(),
        (Float, 4) => "f32".to_string(),
        (Float, 8) => "f64".to_string(),
        (Bool, 1) => "bool8".to_string(),
        (Bool, 4) => "bool32".to_string(),
        (Ptr, 4) => "ptr32".to_string(),
        (Ptr, 8) => "ptr64".to_string(),
        (PtrTyped, 4) => format!("ptr32<{}>", f.pointee.as_deref().unwrap_or("?")),
        (PtrTyped, 8) => format!("ptr64<{}>", f.pointee.as_deref().unwrap_or("?")),
        (Cstr, n) => format!("cstr[{n}]"),
        (Bytes, n) => format!("bytes[{n}]"),
        (k, n) => format!("{k:?}/{n}"),
    };
    prim
}

fn quote_msg(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Accepted spellings, matching the README/USAGE-documented surface:
///   x|exec  w|write  rw|readwrite  any
/// The previously-undocumented `r` alias for `Any` is removed — a user
/// reading `r` as "read-only" was getting any-access behaviour silently,
/// which mismatched both the documented vocabulary and Intel SDM HW BP
/// semantics (no read-only watchpoint exists at the hardware level).
fn parse_access(s: &str) -> Option<BpAccess> {
    match s {
        "exec" | "x" => Some(BpAccess::Execute),
        "write" | "w" => Some(BpAccess::Write),
        "rw" | "readwrite" => Some(BpAccess::ReadWrite),
        "any" => Some(BpAccess::Any),
        _ => None,
    }
}

fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn format_kind(k: &BpKind) -> String {
    match k {
        BpKind::Software => "sw".into(),
        BpKind::Hardware { access, size } => {
            format!("hw/{}/size={}", access_str(*access), size)
        }
        BpKind::Page { size } => {
            format!("page/size={size}")
        }
    }
}

fn access_str(a: BpAccess) -> &'static str {
    match a {
        BpAccess::Execute => "exec",
        BpAccess::Write => "write",
        BpAccess::ReadWrite => "rw",
        BpAccess::Any => "any",
    }
}

fn split_query(url: &str) -> (&str, &str) {
    match url.find('?') {
        Some(i) => (&url[..i], &url[i + 1..]),
        None => (url, ""),
    }
}

fn parse_query(q: &str) -> impl Iterator<Item = (&str, String)> {
    // `validate_query` runs in `route` before any handler iterates this,
    // so a malformed pair (no `=`) is a 400 at the dispatcher and we can
    // safely `filter_map` here. If `parse_query` is ever called outside
    // a route (e.g. a test), the worst outcome is silently dropping a
    // bad pair — the validator is the load-bearing guard.
    q.split('&').filter(|s| !s.is_empty()).filter_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        Some((k, percent_decode(v)))
    })
}

/// Reject queries with malformed pairs (missing `=`). Run at the
/// dispatcher entry so per-handler `parse_query` loops can stay simple
/// and so a typo like `?halt_if` (missing the `=expr`) surfaces as 400
/// instead of being silently dropped.
fn validate_query(q: &str) -> Result<(), String> {
    for pair in q.split('&').filter(|s| !s.is_empty()) {
        if pair.split_once('=').is_none() {
            return Err(format!(
                "malformed query pair (expected `key=value`): `{pair}`"
            ));
        }
    }
    Ok(())
}

/// Wrap a handler that takes no query parameters. Returns 400 for any
/// non-empty query so a typo on a no-arg endpoint (`/ping?foo=1`) can't
/// silently succeed. `validate_query` has already verified the pair
/// shape; here we only check that there are no pairs at all.
fn noarg<F>(query: &str, handler: F) -> Response<Body>
where
    F: FnOnce() -> Response<Body>,
{
    if let Some((k, _)) = parse_query(query).next() {
        return text(400, &format!("unknown query param: {k}"));
    }
    handler()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match (hex_nib(bytes[i + 1]), hex_nib(bytes[i + 2])) {
                (Some(hi), Some(lo)) => {
                    out.push((hi << 4) | lo);
                    i += 3;
                    continue;
                }
                _ => out.push(bytes[i]),
            },
            b'+' => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(&e.into_bytes()).into_owned())
}

fn hex_nib(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn parse_usize(s: &str) -> Option<usize> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        usize::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

/// Parse an IDA-style byte pattern: hex bytes separated by optional
/// whitespace, with `??` as a wildcard byte. Returns one entry per byte
/// (`None` for wildcards). Empty patterns are rejected.
pub fn parse_byte_pattern(s: &str) -> Result<Vec<Option<u8>>, String> {
    let cleaned: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if cleaned.is_empty() {
        return Err("empty pattern".into());
    }
    if cleaned.len() % 2 != 0 {
        return Err("odd number of hex chars in pattern".into());
    }
    let bytes = cleaned.as_bytes();
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for chunk in bytes.chunks(2) {
        if chunk[0] == b'?' && chunk[1] == b'?' {
            out.push(None);
        } else {
            let hi = pattern_nib(chunk[0])?;
            let lo = pattern_nib(chunk[1])?;
            out.push(Some((hi << 4) | lo));
        }
    }
    Ok(out)
}

fn pattern_nib(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("bad hex char: {:?}", b as char)),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn text(status: u16, body: &str) -> Response<Body> {
    Response::from_string(body).with_status_code(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_emit_source_roundtrips() {
        // Compile, emit, recompile — every struct should be identical.
        let src = r#"
            struct GamePlayer size=0x54 {
                ptr32         vtable        @0x00
                ptr32         m_pGameObject @0x44
                ptr32<GameActor> m_pActor      @0x48
                u32           m_entityId    @0x4C
                u32           m_pad         @0x50
            }
            struct GameActor size=0x10 {
                u32  m_health     @0x00
                u32  m_maxHealth  @0x04
                f32  m_scale      @0x08
                bool32 m_inv      @0x0C
            }
            struct WithArrays size=0x18 {
                u32      arr[3]  @0x00
                cstr[8]  name    @0x0C
                bytes[4] tag     @0x14
            }
        "#;
        let s1 = schema::compile(src).expect("compile");
        let mut emitted = String::new();
        for st in s1.structs() {
            emitted.push_str(&emit_struct_source(st));
        }
        let s2 = schema::compile(&emitted).expect("recompile emitted source");
        for st in s1.structs() {
            let got = s2.get(&st.name).expect("missing on roundtrip");
            assert_eq!(st.size, got.size, "size mismatch: {}", st.name);
            assert_eq!(st.fields().len(), got.fields().len(), "field count: {}", st.name);
            for (a, b) in st.fields().iter().zip(got.fields()) {
                assert_eq!(a.name, b.name);
                assert_eq!(a.offset, b.offset);
                assert_eq!(a.element_size, b.element_size);
                assert_eq!(a.array_count, b.array_count);
                assert_eq!(a.kind, b.kind);
                assert_eq!(a.pointee, b.pointee);
            }
        }
    }

    #[test]
    fn schema_emit_aligns_columns() {
        // Mixed type-token widths (ptr32<GameActor> is wider than u32)
        // and name widths force the formatter to pad both columns. The
        // padding makes every type, name, and offset start at the same
        // column.
        let s = schema::compile(
            r#"
            struct align_test size=0x10 {
                u32              a       @0x00
                ptr32<GameActor> m_pAct  @0x04
                u32              long_name @0x08
                u32              z       @0x0C
            }
        "#,
        )
        .expect("compile");
        let r = s.get("align_test").unwrap();
        let out = emit_struct_source(r);
        let lines: Vec<&str> = out.lines().collect();
        // Field lines start with 4-space indent; type column starts at col 4.
        // Whichever line is widest sets the columns; other lines are padded.
        let field_lines: Vec<&str> = lines
            .iter()
            .copied()
            .filter(|l| l.starts_with("    "))
            .collect();
        assert_eq!(field_lines.len(), 4);
        // The `@` for the offset must be at the same column on every row.
        let at_cols: Vec<usize> = field_lines
            .iter()
            .map(|l| l.find('@').expect("@ in field line"))
            .collect();
        assert!(
            at_cols.windows(2).all(|w| w[0] == w[1]),
            "@ columns not aligned: {at_cols:?}\n{out}"
        );
    }

    fn bp_with_bindings(id: u64, types: &[&str]) -> BreakpointInfo {
        BreakpointInfo {
            id: BpId(id),
            addr: 0,
            kind: BpKind::Software,
            options: BpOptions::default(),
            hits: 0,
            log: None,
            log_if: None,
            halt_if: None,
            requested_name: None,
            struct_bindings: types
                .iter()
                .enumerate()
                .map(|(i, t)| BindingInfo {
                    name: format!("b{i}"),
                    type_name: (*t).to_string(),
                    expr_source: "rcx".into(),
                })
                .collect(),
        }
    }

    #[test]
    fn bps_referencing_finds_matches() {
        let bps = vec![
            bp_with_bindings(1, &["GamePlayer"]),
            bp_with_bindings(2, &["GameEnemy", "GameActor"]),
            bp_with_bindings(3, &["GameActor"]),
            bp_with_bindings(4, &[]),
        ];
        let ids = bps_referencing_in(&bps, &["GameActor".to_string()]);
        assert_eq!(ids, vec![BpId(2), BpId(3)]);
        let ids = bps_referencing_in(&bps, &["GamePlayer".to_string()]);
        assert_eq!(ids, vec![BpId(1)]);
    }

    #[test]
    fn bps_referencing_empty_when_no_overlap() {
        let bps = vec![bp_with_bindings(1, &["Foo"]), bp_with_bindings(2, &["Bar"])];
        assert!(bps_referencing_in(&bps, &["Baz".to_string()]).is_empty());
    }

    #[test]
    fn ptr_width_check_passes_when_match() {
        let s = schema::compile(
            "struct ptr_test_64 size=0x10 { ptr64 a @0x00 ptr64<other> b @0x08 }",
        )
        .expect("compile");
        let r = s.get("ptr_test_64").unwrap();
        assert!(mismatched_ptr_field(r, 8).is_none());
    }

    #[test]
    fn ptr_width_check_finds_mismatch() {
        let s = schema::compile(
            "struct ptr_test_32 size=0x8 { ptr32 vt @0x00 ptr32 b @0x04 }",
        )
        .expect("compile");
        let r = s.get("ptr_test_32").unwrap();
        // Agent is 64-bit; struct uses ptr32 — first ptr field flagged.
        let (name, w) = mismatched_ptr_field(r, 8).expect("expected mismatch");
        assert_eq!(name, "vt");
        assert_eq!(w, 4);
    }

    #[test]
    fn ptr_width_check_ignores_non_ptr_fields() {
        let s = schema::compile(
            "struct ptr_test_no_ptr size=0x10 { u32 a @0x00 u64 b @0x08 }",
        )
        .expect("compile");
        let r = s.get("ptr_test_no_ptr").unwrap();
        assert!(mismatched_ptr_field(r, 8).is_none());
        assert!(mismatched_ptr_field(r, 4).is_none());
    }

    #[test]
    fn bps_referencing_handles_multiple_names() {
        let bps = vec![
            bp_with_bindings(1, &["Foo"]),
            bp_with_bindings(2, &["Bar"]),
            bp_with_bindings(3, &["Quux"]),
        ];
        let ids = bps_referencing_in(&bps, &["Foo".to_string(), "Bar".to_string()]);
        assert_eq!(ids, vec![BpId(1), BpId(2)]);
    }

    #[test]
    fn parse_regs_accepts_x64_and_x86_names() {
        let p = parse_regs("rax=0x10\neax=0x20\n").unwrap();
        assert_eq!(p, vec![(RegName::Rax, 0x10), (RegName::Rax, 0x20)]);
    }

    #[test]
    fn parse_regs_rejects_unknown_register() {
        let err = parse_regs("rxx=0\n").unwrap_err();
        assert!(err.contains("unknown register"), "{err}");
        assert!(err.contains("rxx"), "{err}");
    }

    #[test]
    fn parse_regs_rejects_missing_equals() {
        let err = parse_regs("rax 5\n").unwrap_err();
        assert!(err.contains("name=value"), "{err}");
    }

    #[test]
    fn parse_regs_rejects_bad_value() {
        let err = parse_regs("rax=xyz\n").unwrap_err();
        assert!(err.contains("bad value"), "{err}");
    }

    #[test]
    fn parse_regs_skips_blank_lines() {
        let p = parse_regs("\n\nrip=0x401000\n  \n").unwrap();
        assert_eq!(p, vec![(RegName::Rip, 0x401000)]);
    }

    #[test]
    fn reg_name_write_only_touches_named_slot() {
        let mut r = Registers { rax: 1, rcx: 2, rip: 3, ..Default::default() };
        RegName::Rcx.write(&mut r, 0xdead);
        assert_eq!(r.rax, 1);
        assert_eq!(r.rcx, 0xdead);
        assert_eq!(r.rip, 3);
    }

    #[test]
    fn validate_patch_x64_accepts_everything() {
        // 64-bit agent: full u64 range and r8-r15 are all legal.
        let patch = vec![
            (RegName::Rip, 0x7fff_ffff_ffff_ffff),
            (RegName::R8, 0xdead_beef_dead_beef),
            (RegName::R15, 1),
        ];
        assert!(validate_patch_for_arch(&patch, 8).is_ok());
    }

    #[test]
    fn validate_patch_x86_rejects_x64_only_register() {
        // The footgun: user pasted an x64 regs dump into an x86 setregs.
        // Lines naming r8..r15 would silently no-op; reject up front.
        let patch = vec![(RegName::R8, 0)];
        let err = validate_patch_for_arch(&patch, 4).unwrap_err();
        assert!(err.contains("r8"), "{err}");
        assert!(err.contains("x64-only"), "{err}");
        assert!(err.contains("32-bit"), "{err}");
    }

    #[test]
    fn validate_patch_x86_rejects_oversized_value() {
        // The footgun: rip from an x64 dump is 0x7ff... — would truncate
        // to a low-32 value silently and the thread resumes into junk.
        let patch = vec![(RegName::Rip, 0x1_0000_0000)];
        let err = validate_patch_for_arch(&patch, 4).unwrap_err();
        assert!(err.contains("rip"), "{err}");
        assert!(err.contains("32-bit"), "{err}");
        assert!(err.contains("truncate"), "{err}");
    }

    #[test]
    fn validate_patch_x86_accepts_in_range_value() {
        // Anything that fits in u32 is fine on x86.
        let patch = vec![
            (RegName::Rip, 0x4012_3456),
            (RegName::Rax, 0xffff_ffff),
            (RegName::Rsp, 0),
        ];
        assert!(validate_patch_for_arch(&patch, 4).is_ok());
    }

    #[test]
    fn reg_name_is_x64_only_classification() {
        // Defensive: any future shuffle of variants must keep the
        // r8..r15 set marked correctly. Caller sites depend on this.
        for r in [
            RegName::R8, RegName::R9, RegName::R10, RegName::R11,
            RegName::R12, RegName::R13, RegName::R14, RegName::R15,
        ] {
            assert!(r.is_x64_only(), "{r:?} should be x64-only");
        }
        for r in [
            RegName::Rax, RegName::Rcx, RegName::Rdx, RegName::Rbx,
            RegName::Rsp, RegName::Rbp, RegName::Rsi, RegName::Rdi,
            RegName::Rip,
        ] {
            assert!(!r.is_x64_only(), "{r:?} should not be x64-only");
        }
    }

    #[test]
    fn parse_regs_rejects_eflags_with_explanation() {
        // `eflags` carries VEH-managed bits (TF/RF). A blind merge would
        // silently disable BPs (TF off → no rearm) or kill the host (TF
        // on with no pending rearm → unhandled-exception filter). The
        // natural footgun is `regs` showing TF=1 in a dump and a script
        // piping it back through setregs. Reject at parse time with a
        // pointed message rather than a generic "unknown register".
        let err = parse_regs("rax=0\neflags=0x100\n").unwrap_err();
        assert!(err.contains("eflags"), "{err}");
        assert!(err.contains("VEH-managed"), "{err}");
        // And the reject must be a hard stop — partial accept (rax merged,
        // eflags rejected) would leave the caller thinking the request
        // half-applied.
        assert!(parse_regs("rax=0\neflags=0x100\n").is_err());
    }

    #[test]
    fn parse_resume_mode_defaults_when_missing() {
        assert!(matches!(parse_resume_mode(""), Ok(ResumeMode::Continue)));
    }

    #[test]
    fn parse_resume_mode_rejects_unknown_param() {
        // Strict-validation policy: unknown params are 400, not silently
        // ignored — a typo like `?moed=step` (instead of `mode`) used to
        // pass through and resume as Continue, masking the user's intent.
        let err = parse_resume_mode("foo=bar").unwrap_err();
        assert!(err.contains("unknown query param"), "{err}");
        assert!(err.contains("foo"), "{err}");
    }

    #[test]
    fn parse_resume_mode_accepts_each_mode() {
        assert!(matches!(parse_resume_mode("mode=continue"), Ok(ResumeMode::Continue)));
        assert!(matches!(parse_resume_mode("mode=step"), Ok(ResumeMode::Step)));
        assert!(matches!(parse_resume_mode("mode=ret"), Ok(ResumeMode::Ret)));
    }

    #[test]
    fn parse_resume_mode_rejects_typo() {
        let err = parse_resume_mode("mode=stp").unwrap_err();
        assert!(err.contains("stp"), "{err}");
        assert!(err.contains("continue|step|ret"), "{err}");
    }

    #[test]
    fn validate_query_accepts_well_formed() {
        assert!(validate_query("").is_ok());
        assert!(validate_query("a=1").is_ok());
        assert!(validate_query("a=1&b=2").is_ok());
        assert!(validate_query("a=").is_ok()); // empty value is fine
    }

    #[test]
    fn validate_query_rejects_missing_equals() {
        let err = validate_query("foo").unwrap_err();
        assert!(err.contains("malformed"), "{err}");
        assert!(err.contains("foo"), "{err}");

        let err = validate_query("a=1&bare").unwrap_err();
        assert!(err.contains("bare"), "{err}");
    }
}

fn binary(status: u16, bytes: Vec<u8>) -> Response<Body> {
    let mut r = Response::from_data(bytes).with_status_code(status);
    static HDR: OnceLock<Option<Header>> = OnceLock::new();
    let hdr = HDR.get_or_init(|| {
        Header::from_bytes(&b"Content-Type"[..], &b"application/octet-stream"[..]).ok()
    });
    if let Some(h) = hdr {
        r = r.with_header(h.clone());
    }
    r
}
