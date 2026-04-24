//! Platform-agnostic core: HTTP server, protocol, breakpoint bookkeeping.
//!
//! Policy: no panics. `panic = "abort"` is set in the release profile, so any panic
//! kills the injected host. Every error path must return a `Result`.

use std::io::Read;
use std::sync::{Arc, OnceLock};

use tiny_http::{Header, Method, Request, Response, Server};

pub const DEFAULT_BIND: &str = "127.0.0.1:7878";
pub const MAX_READ_LEN: usize = 16 * 1024 * 1024;
pub const MAX_WRITE_LEN: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub enum MemError {
    Partial(usize),
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
}

pub struct BreakpointInfo {
    pub id: BpId,
    pub addr: usize,
    pub kind: BpKind,
    pub options: BpOptions,
    pub hits: u64,
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

#[derive(Debug)]
pub struct ExportInfo {
    pub name: String,
    pub addr: usize,
}

#[derive(Debug)]
pub struct RegionInfo {
    pub base: usize,
    pub size: usize,
    pub state: u32,
    pub protect: u32,
    pub ty: u32,
}

pub trait Process: Send + Sync {
    fn read_memory(&self, addr: usize, len: usize) -> Result<Vec<u8>, MemError>;
    fn write_memory(&self, addr: usize, bytes: &[u8]) -> Result<(), MemError>;

    fn set_breakpoint(&self, spec: BpSpec) -> Result<BpId, BpError>;
    fn clear_breakpoint(&self, id: BpId) -> Result<(), BpError>;
    fn breakpoints(&self) -> Vec<BreakpointInfo>;

    fn halts(&self) -> Vec<HaltSummary>;
    fn wait_halt(&self, timeout_ms: u64) -> Option<HaltSummary>;
    fn halt_regs(&self, hit_id: u64) -> Option<Registers>;
    fn halt_set_regs(&self, hit_id: u64, regs: Registers) -> Result<(), BpError>;
    fn halt_resume(&self, hit_id: u64, mode: ResumeMode) -> Result<(), BpError>;

    fn modules(&self) -> Vec<ModuleInfo>;
    fn module_exports(&self, name: &str) -> Option<Vec<ExportInfo>>;
    fn memory_regions(&self) -> Vec<RegionInfo>;
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
    let server = match Server::http(&config.bind) {
        Ok(s) => Arc::new(s),
        Err(_) => return,
    };
    for mut request in server.incoming_requests() {
        let response = route(&mut request, process.as_ref(), config.token.as_deref(), &server);
        let _ = request.respond(response);
    }
}

type Body = std::io::Cursor<Vec<u8>>;

fn route(
    req: &mut Request,
    process: &dyn Process,
    token: Option<&str>,
    server: &Arc<Server>,
) -> Response<Body> {
    if let Some(expected) = token {
        if !auth_ok(req, expected) {
            return text(401, "unauthorized");
        }
    }

    let method = req.method().clone();
    let url = req.url().to_string();
    let (path, query) = split_query(&url);

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

    match (&method, path) {
        (Method::Get, "/ping") => text(200, "pong"),
        (Method::Get, "/version") => text(200, env!("CARGO_PKG_VERSION")),
        (Method::Get, "/memory/read") => handle_read(process, query),
        (Method::Post, "/memory/write") => handle_write(process, query, req),
        (Method::Post, "/bp/set") => handle_bp_set(process, query),
        (Method::Post, "/bp/clear") => handle_bp_clear(process, query),
        (Method::Get, "/bp/list") => handle_bp_list(process),
        (Method::Get, "/symbols/resolve") => handle_symbol_resolve(process, query),
        (Method::Get, "/halts") => handle_halts_list(process),
        (Method::Get, "/halts/wait") => handle_halts_wait(process, query),
        (Method::Get, "/modules") => handle_modules(process),
        (Method::Get, "/memory/regions") => handle_regions(process),
        (Method::Post, "/shutdown") => {
            // Release any parked threads so they don't hang forever once the
            // HTTP server stops accepting resume requests.
            for h in process.halts() {
                let _ = process.halt_resume(h.hit_id, ResumeMode::Continue);
            }
            server.unblock();
            text(200, "shutting down")
        }
        _ => text(404, "not found"),
    }
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
            Some(regs) => text(200, &format_regs(&regs)),
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

    let Some(regs) = process.halt_regs(hit_id) else {
        return text(404, "not found");
    };

    // rbp-chain walk. Fragile on code built with frame pointers omitted
    // (MSVC /Oy, rustc release default); surface what we can and bail on
    // the first unreadable frame.
    let modules = process.modules();
    let mut body = String::new();
    let push_frame = |idx: usize, rip: u64, body: &mut String| {
        body.push_str(&format!("#{idx} rip=0x{:x}", rip));
        if let Some((name, off)) = resolve_addr(&modules, rip) {
            body.push_str(&format!(" {name}+0x{off:x}"));
        }
        body.push('\n');
    };

    push_frame(0, regs.rip, &mut body);

    let mut rbp = regs.rbp;
    for i in 1..depth {
        if rbp == 0 {
            break;
        }
        let ret = match read_u64(process, rbp.wrapping_add(8) as usize) {
            Some(v) if v != 0 => v,
            _ => break,
        };
        let prev = match read_u64(process, rbp as usize) {
            Some(v) => v,
            None => break,
        };
        push_frame(i, ret, &mut body);
        // Stack grows down on x64 — a non-increasing rbp chain is a sentinel
        // or a non-frame-pointer function; stop rather than loop.
        if prev <= rbp {
            break;
        }
        rbp = prev;
    }
    text(200, &body)
}

fn read_u64(process: &dyn Process, addr: usize) -> Option<u64> {
    let bytes = process.read_memory(addr, 8).ok()?;
    if bytes.len() < 8 {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    Some(u64::from_le_bytes(buf))
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
                body.push_str(&format!("name={} addr=0x{:x}\n", e.name, e.addr));
            }
            text(200, &body)
        }
        None => text(404, "module not found"),
    }
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
        body.push('\n');
    }
    text(200, &body)
}

fn handle_halts_wait(process: &dyn Process, query: &str) -> Response<Body> {
    let timeout = parse_query(query)
        .find(|(k, _)| *k == "timeout")
        .and_then(|(_, v)| v.parse::<u64>().ok())
        .unwrap_or(30_000);
    match process.wait_halt(timeout) {
        Some(h) => text(200, &format_halt(&h)),
        None => text(204, ""),
    }
}

fn format_halt(h: &HaltSummary) -> String {
    let bp = match h.bp_id {
        Some(id) => format!("bp_id={}", id.0),
        None => "bp_id=none".into(),
    };
    format!("hit_id={} {} tid={} rip=0x{:x}", h.hit_id, bp, h.tid, h.rip)
}

fn format_regs(r: &Registers) -> String {
    let mut s = String::with_capacity(512);
    macro_rules! line {
        ($($name:ident),* $(,)?) => {
            $( s.push_str(&format!("{}=0x{:016x}\n", stringify!($name), r.$name)); )*
        };
    }
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

fn auth_ok(req: &Request, expected: &str) -> bool {
    for h in req.headers() {
        if h.field.equiv("Authorization") {
            if let Some(t) = h.value.as_str().strip_prefix("Bearer ") {
                return constant_time_eq(t.as_bytes(), expected.as_bytes());
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
    let bytes = match process.read_memory(addr, len) {
        Ok(b) => b,
        Err(MemError::Partial(n)) => return text(206, &format!("partial: {n} bytes readable")),
        Err(MemError::Fault) => return text(403, "unreadable"),
        Err(MemError::InvalidRange) => return text(400, "invalid range"),
    };
    if raw {
        binary(200, bytes)
    } else {
        text(200, &hex_encode(&bytes))
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
        Err(MemError::Partial(n)) => text(206, &format!("partial: {n} bytes written")),
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
    for (k, v) in parse_query(query) {
        match k {
            "addr" => addr = parse_usize(&v),
            "name" => name = Some(v),
            "kind" => kind_str = Some(v),
            "access" => access_str = Some(v),
            "size" => size_u = parse_usize(&v),
            "halt" => halt_flag = parse_bool(&v),
            "one_shot" | "oneshot" => one_shot = parse_bool(&v),
            "tid" | "tid_filter" => tid_filter = v.parse().ok(),
            _ => {}
        }
    }
    let addr = match (addr, name) {
        (Some(_), Some(_)) => return text(400, "addr and name are exclusive"),
        (Some(a), None) => a,
        (None, Some(n)) => match resolve_symbol(process, &n) {
            Ok(a) => a,
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

    match process.set_breakpoint(BpSpec { addr, kind, options }) {
        Ok(id) => text(200, &format!("id={}", id.0)),
        Err(BpError::Unsupported) => text(400, "unsupported combination"),
        Err(BpError::Unwritable) => text(403, "unwritable"),
        Err(BpError::NoHwSlot) => text(409, "no hardware slot"),
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

fn resolve_symbol(process: &dyn Process, name: &str) -> Result<usize, (u16, &'static str)> {
    let (module, symbol) = name
        .split_once('!')
        .ok_or((400, "name must be module!symbol"))?;
    let exports = process
        .module_exports(module)
        .ok_or((404, "module not found"))?;
    exports
        .into_iter()
        .find(|e| e.name == symbol)
        .map(|e| e.addr)
        .ok_or((404, "symbol not found"))
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
        body.push_str(&format!(
            "id={} addr=0x{:x} kind={} halt={} one_shot={} tid_filter={} hits={}\n",
            bp.id.0,
            bp.addr,
            format_kind(&bp.kind),
            bp.options.halt,
            bp.options.one_shot,
            bp.options.tid_filter.map(|t| t.to_string()).unwrap_or_else(|| "-".into()),
            bp.hits,
        ));
    }
    text(200, &body)
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
