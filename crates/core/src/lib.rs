//! Platform-agnostic core: HTTP server, protocol, breakpoint bookkeeping.
//!
//! Policy: no panics. `panic = "abort"` is set in the release profile, so any panic
//! kills the injected host. Every error path must return a `Result`.

pub mod dsl;
pub mod events;
pub mod log;
pub mod thread_role;

use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use tiny_http::{Header, Method, Request, Response, Server};

pub const DEFAULT_BIND: &str = "127.0.0.1:7878";
pub const MAX_READ_LEN: usize = 16 * 1024 * 1024;
pub const MAX_WRITE_LEN: usize = 16 * 1024 * 1024;

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
    /// A breakpoint already exists at the requested address. Permitting two
    /// SW breakpoints at the same address would silently corrupt the
    /// `original_byte` tracking in the second install (it would read the
    /// `0xCC` placed by the first and remember that as the original).
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
    Page { access: BpAccess, size: usize },
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

/// Server-side evaluated DSL hooks attached to a breakpoint. `cond` gates
/// halt + log + event emission; if `cond` is `Some(expr)` and the expression
/// evaluates to zero on hit, the breakpoint silently rearms. `log` is a
/// template rendered on hit and emitted to both the log pipeline and the
/// `/events` ring buffer.
///
/// Each hook keeps both the parsed AST (used by VEH at hit-time) and the
/// original source text (surfaced by `bp list` / `bp info` so users can
/// audit what a BP is doing without re-issuing it).
#[derive(Debug, Clone, Default)]
pub struct BpHooks {
    pub log: Option<dsl::TemplateHook>,
    pub cond: Option<dsl::CondHook>,
}

impl BpHooks {
    pub fn is_empty(&self) -> bool {
        self.log.is_none() && self.cond.is_none()
    }

    pub fn log_text(&self) -> Option<&str> {
        self.log.as_ref().map(|h| h.source.as_str())
    }

    pub fn cond_text(&self) -> Option<&str> {
        self.cond.as_ref().map(|h| h.source.as_str())
    }
}

pub struct BreakpointInfo {
    pub id: BpId,
    pub addr: usize,
    pub kind: BpKind,
    pub options: BpOptions,
    pub hits: u64,
    pub log: Option<String>,
    pub cond: Option<String>,
    pub requested_name: Option<String>,
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
    fn halt_set_regs(&self, hit_id: u64, regs: Registers) -> Result<(), BpError>;
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
        std::thread::spawn(move || {
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
        "/halts/wait" | "/events" => SlotKind::LongPoll,
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

    // Static routes first. Doing this before the dynamic prefix matchers
    // avoids the trap where `/halts/wait` gets routed to handle_halt_sub
    // which can't parse "wait" as a hit_id.
    let static_match = match (&method, path) {
        (Method::Get, "/ping") => Some(text(200, "pong")),
        (Method::Get, "/version") => Some(text(200, env!("CARGO_PKG_VERSION"))),
        (Method::Get, "/info") => Some(handle_info(process)),
        (Method::Get, "/memory/read") => Some(handle_read(process, query)),
        (Method::Post, "/memory/write") => Some(handle_write(process, query, req)),
        (Method::Post, "/bp/set") => Some(handle_bp_set(process, query)),
        (Method::Post, "/bp/clear") => Some(handle_bp_clear(process, query)),
        (Method::Get, "/bp/list") => Some(handle_bp_list(process)),
        (Method::Get, "/symbols/resolve") => Some(handle_symbol_resolve(process, query)),
        (Method::Get, "/symbols/lookup") => Some(handle_symbol_lookup(process, query)),
        (Method::Get, "/events") => Some(handle_events(query)),
        (Method::Get, "/halts") => Some(handle_halts_list(process)),
        (Method::Get, "/halts/wait") => Some(handle_halts_wait(process, query)),
        (Method::Get, "/modules") => Some(handle_modules(process)),
        (Method::Get, "/memory/regions") => Some(handle_regions(process)),
        (Method::Get, "/memory/search") => Some(handle_memory_search(process, query)),
        (Method::Get, "/threads") => Some(handle_threads(process)),
        (Method::Post, "/shutdown") => Some({
            // Order matters: `shutdown_halts` must run BEFORE we stop
            // accepting requests. The platform impl is responsible for both
            // refusing new parks AND resuming any already-parked threads in
            // a single atomic step (otherwise a halt that races shutdown
            // could park forever — the previous "snapshot halts(); resume
            // each; set flag" sequence had exactly that gap).
            process.shutdown_halts();
            events::shutdown();
            server.unblock();
            text(200, "shutting down")
        }),
        _ => None,
    };
    if let Some(r) = static_match {
        return r;
    }

    // Dynamic /bp/<id> for single-BP inspection.
    if let Some(rest) = path.strip_prefix("/bp/") {
        if method == Method::Get {
            if let Ok(id) = rest.parse::<u64>() {
                return handle_bp_info(process, BpId(id));
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
                return handle_module_exports(process, &percent_decode(name));
            }
        }
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
            let mut body = String::new();
            if req.as_reader().read_to_string(&mut body).is_err() {
                return text(400, "body read error");
            }
            let regs = match parse_regs(&body) {
                Some(r) => r,
                None => return text(400, "invalid regs body"),
            };
            match process.halt_set_regs(hit_id, regs) {
                Ok(()) => text(200, "ok"),
                Err(BpError::NotFound) => text(404, "not found"),
                _ => text(500, "internal"),
            }
        }
        (Method::Post, "resume") => {
            let mode = parse_resume_mode(query).unwrap_or(ResumeMode::Continue);
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
    let depth = parse_query(query)
        .find(|(k, _)| *k == "depth")
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(STACK_DEFAULT_DEPTH)
        .clamp(1, STACK_MAX_DEPTH);

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

fn parse_resume_mode(query: &str) -> Option<ResumeMode> {
    parse_query(query)
        .find(|(k, _)| *k == "mode")
        .and_then(|(_, v)| match v.as_str() {
            "continue" => Some(ResumeMode::Continue),
            "step" => Some(ResumeMode::Step),
            "ret" => Some(ResumeMode::Ret),
            _ => None,
        })
}

fn handle_info(process: &dyn Process) -> Response<Body> {
    let body = format!(
        "version={}\narch={}\npid={}\nuptime_ms={}\n",
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
            "start" => start = parse_usize(&v),
            "end" => end = parse_usize(&v),
            "all" => match parse_bool(&v) {
                Some(b) => all = b,
                None => return text(400, "all: expected true/false"),
            },
            "limit" => limit = v.parse::<usize>().unwrap_or(256).clamp(1, 4096),
            _ => {}
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

/// Hard cap on `/halts/wait` timeout. `events::poll` enforces the same
/// number internally; mirror it at the HTTP edge so a malicious client
/// can't pin an agent worker thread for billions of years by sending
/// `?timeout=u64::MAX`. The platform `wait_halt` impl is also expected to
/// clamp, but defending at both layers is cheap.
const MAX_WAIT_TIMEOUT_MS: u64 = 60_000;

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
            _ => {}
        }
    }
    let timeout = timeout.min(MAX_WAIT_TIMEOUT_MS);
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

fn parse_regs(body: &str) -> Option<Registers> {
    let mut r = Registers::default();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once('=')?;
        let value = parse_u64(value.trim())?;
        match name.trim() {
            "rax" => r.rax = value,
            "rcx" => r.rcx = value,
            "rdx" => r.rdx = value,
            "rbx" => r.rbx = value,
            "rsp" => r.rsp = value,
            "rbp" => r.rbp = value,
            "rsi" => r.rsi = value,
            "rdi" => r.rdi = value,
            "r8" => r.r8 = value,
            "r9" => r.r9 = value,
            "r10" => r.r10 = value,
            "r11" => r.r11 = value,
            "r12" => r.r12 = value,
            "r13" => r.r13 = value,
            "r14" => r.r14 = value,
            "r15" => r.r15 = value,
            "rip" => r.rip = value,
            "eflags" => r.eflags = value as u32,
            _ => {}
        }
    }
    Some(r)
}

fn parse_u64(s: &str) -> Option<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
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
            "addr" => addr = parse_usize(&v),
            "len" => len = parse_usize(&v),
            "format" => raw = v == "raw",
            _ => {}
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
    let addr = parse_query(query)
        .find(|(k, _)| *k == "addr")
        .and_then(|(_, v)| parse_usize(&v));
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
    let mut cond_raw: Option<String> = None;
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
            "cond" => cond_raw = Some(v),
            _ => {}
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

    let kind = match kind_str.as_deref().unwrap_or("sw") {
        "sw" | "software" => BpKind::Software,
        "hw" | "hardware" => {
            let access = match parse_access(access_str.as_deref().unwrap_or("exec")) {
                Some(a) => a,
                None => return text(400, "invalid access"),
            };
            let size = size_u.unwrap_or(1) as u8;
            if !matches!(size, 1 | 2 | 4 | 8) {
                return text(400, "size must be 1|2|4|8");
            }
            BpKind::Hardware { access, size }
        }
        "page" => {
            let access = match parse_access(access_str.as_deref().unwrap_or("any")) {
                Some(a) => a,
                None => return text(400, "invalid access"),
            };
            let size = size_u.unwrap_or(1);
            if size == 0 {
                return text(400, "size must be > 0");
            }
            BpKind::Page { access, size }
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
    let cond = match cond_raw {
        Some(s) => match dsl::parse_expr(&s) {
            Ok(expr) => Some(dsl::CondHook { source: s, expr }),
            Err(e) => return text(400, &format!("cond: {e}")),
        },
        None => None,
    };
    let hooks = BpHooks { log, cond };

    match process.set_breakpoint(BpSpec { addr, kind, options, hooks, requested_name }) {
        // Echo the resolved address back so the user can sanity-check what
        // a `name=module!symbol` lookup actually landed on. Forwarded
        // exports (kernel32!ExitProcess → ntdll!RtlExitUserProcess) make
        // this non-obvious; without the echo the user has to cross-check
        // against `haunt resolve`.
        Ok(id) => text(200, &format!("id={} addr=0x{:x}", id.0, addr)),
        Err(BpError::Unsupported) => text(400, "unsupported combination"),
        Err(BpError::Unwritable) => text(403, "unwritable"),
        Err(BpError::NoHwSlot) => text(409, "no hardware slot"),
        Err(BpError::Conflict) => text(409, "breakpoint already exists at this address"),
        Err(BpError::NotFound) => text(404, "not found"),
        Err(BpError::Internal) => text(500, "internal error"),
    }
}

fn handle_symbol_resolve(process: &dyn Process, query: &str) -> Response<Body> {
    let name = parse_query(query).find(|(k, _)| *k == "name").map(|(_, v)| v);
    let Some(name) = name else {
        return text(400, "missing name");
    };
    match resolve_symbol(process, &name) {
        Ok(addr) => text(200, &format!("addr=0x{:x}\n", addr)),
        Err((status, msg)) => text(status, msg),
    }
}

fn handle_symbol_lookup(process: &dyn Process, query: &str) -> Response<Body> {
    let addr = parse_query(query)
        .find(|(k, _)| *k == "addr")
        .and_then(|(_, v)| parse_usize(&v));
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
    let id = parse_query(query)
        .find(|(k, _)| *k == "id")
        .and_then(|(_, v)| v.parse::<u64>().ok());
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
    if let Some(cond) = &bp.cond {
        s.push_str(&format!(" cond={}", quote_msg(cond)));
    }
    if let Some(req) = &bp.requested_name {
        s.push_str(&format!(" requested={}", quote_msg(req)));
    }
    s.push('\n');
    s
}

fn handle_events(query: &str) -> Response<Body> {
    let mut since: u64 = 0;
    let mut limit: usize = 256;
    let mut timeout: u64 = 0;
    for (k, v) in parse_query(query) {
        match k {
            "since" => since = v.parse().unwrap_or(0),
            "limit" => limit = v.parse::<usize>().unwrap_or(256).clamp(1, 4096),
            "timeout" => timeout = v.parse().unwrap_or(0),
            _ => {}
        }
    }
    let evts = events::poll(since, limit, timeout);
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

fn parse_access(s: &str) -> Option<BpAccess> {
    match s {
        "exec" | "x" => Some(BpAccess::Execute),
        "write" | "w" => Some(BpAccess::Write),
        "rw" | "readwrite" => Some(BpAccess::ReadWrite),
        "any" | "r" => Some(BpAccess::Any),
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
        BpKind::Page { access, size } => {
            format!("page/{}/size={}", access_str(*access), size)
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
    q.split('&').filter(|s| !s.is_empty()).filter_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        Some((k, percent_decode(v)))
    })
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
