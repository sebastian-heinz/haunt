//! haunt — command-line client for haunt.dll's HTTP protocol.
//!
//! Env:
//!   HAUNT_URL    base URL (default http://127.0.0.1:7878)
//!   HAUNT_TOKEN  Bearer token for auth (default none)

use std::collections::HashMap;
use std::io::{IsTerminal, Read, Write};
use std::net::TcpStream;
use std::process::ExitCode;
use std::time::Duration;

/// Hard ceiling on how long the CLI will block on a single response. Long-
/// poll endpoints (`wait`, `events`) have their own timeout knob and the
/// agent caps it at 60s, so 90s here gives a safety margin without hanging
/// indefinitely if the agent crashes mid-response.
const SOCKET_READ_TIMEOUT_SECS: u64 = 90;

const USAGE: &str = "\
haunt <command> [args]

CLI client for the haunt agent injected into a Windows process.

Env:
  HAUNT_URL    base URL (default http://127.0.0.1:7878)
  HAUNT_TOKEN  Bearer token for auth (default: none)

Typical loop:
  haunt bp set <addr|module!symbol>     # install breakpoint
  haunt wait                            # block until a thread halts
  haunt regs <hit_id>                   # inspect registers
  haunt stack <hit_id>                  # backtrace
  haunt resume <hit_id>                 # release the thread

Connect / introspect:
  ping                       liveness check
  info                       version, arch (x86_64|x86), pid, uptime_ms
  version                    version string
  modules                    loaded modules: name, base, size
  exports <module>           module's exports. Forwarded entries appear
                             as `name=Foo forward=other.dll.RealName`.
  regions                    committed memory regions (base, size, prot)
  threads                    per-thread DR0..DR3 + DR7, `agent` flag,
                             DLL_THREAD_ATTACH success/fail counters
  resolve <module!symbol>    name -> address (uses GetProcAddress, so
                             forwarders and API-set redirection follow)
  addr <addr>                reverse: address -> module+0xoffset
  shutdown                   resume all parked threads, stop the agent

Memory:
  read <addr> [len]          hex output; default len=16. Partial reads
                             return only the readable prefix (status 206).
  read-raw <addr> <len>      same but binary to stdout
  write <addr> <hex>         write hex-encoded bytes (whitespace ignored)
  search <pattern> [--module <name>] [--start <addr>] [--end <addr>]
                   [--all] [--limit N]
                             find an IDA-style hex pattern; `??` is a
                             wildcard byte. SCOPE REQUIRED — pick one:
                               --module     scope to one DLL's image
                                            (typical use)
                               --start/--end  arbitrary range
                               --all        whole address space — slow
                                            on multi-GB targets, no
                                            progress, no cancel
                             --limit default 256, max 4096.

Breakpoints:
  bp set <addr|module!symbol> [--kind sw|hw|page] [--no-halt]
         [--one-shot] [--access x|w|rw|any] [--size N] [--tid N]
         [--log <template>] [--if <expr>]
                             Install a BP. Returns `id=N addr=0x...`
                             (the resolved address, useful when name
                             lookup crossed a forwarder).
                             Defaults: --kind sw, halt=true.
                             --no-halt    record the hit, do not park
                                          the firing thread (use this
                                          for high-rate tracing)
                             --one-shot   remove the BP after one hit
                             --tid N      only fire on that OS thread
                             HW: --access controls trigger condition
                                 (`x|exec` `w|write` `rw|readwrite`
                                 `any`); --size in {1,2,4,8} (8 is x64-
                                 only); addr aligned to size for size>1.
                             page: --size is bytes, rounded up to pages.
                                   PAGE_GUARD fires on any access kind.
                             SW + page BPs covering the same page are
                             rejected with 409 Conflict.

  bp list                    all BPs, one per line; includes hit count
                             and `requested=\"...\"` for name-resolved BPs
  bp info <id>               single BP, same format
  bp clear <id>              remove a BP

  --log template:
    %name      register value (e.g. %rcx, %eip)
    %[expr]    deref expr, substitute pointed-to value
    %{expr}    raw expression value
    %%         literal %
  --if takes the same expression syntax; non-zero passes the gate
  (no halt, no log, no event when it fails).
  Operators: + - * & | ^ << >> ~ == != < <= > >= ()
  over hex/decimal literals, register names, [deref] subexpressions.
  Parser depth capped at 32 levels.

Halts (parked threads):
  wait [--timeout <ms>] [--since <hit_id>]
                             long-poll the next halt with id > since.
                             Default timeout 30000 ms; agent caps at
                             60000 ms. Returns 204 (empty body) on
                             timeout.
  halts                      list currently parked hits
  regs <hit_id>              register dump; pointers into a loaded
                             module are auto-annotated as
                             module+0xoffset
  stack <hit_id> [--depth N] backtrace. Default 32 frames, max 256.
                             x64: real unwinder via RtlVirtualUnwind +
                             .pdata (FPO-safe). x86: EBP chain (frames
                             may be missing on FPO functions).
  args <hit_id> [--conv <c>] [--count N]
                             Read register- and stack-passed call args
                             per calling convention.
                             Default --count 4. --conv defaults from
                             /info: win64 on x64 agents, cdecl on x86.
                             Convs:
                               x64: win64, sysv (sysv64)
                               x86: thiscall, fastcall, stdcall, cdecl
  setregs <hit_id>           apply `name=value` lines from stdin to a
                             parked thread; takes effect on resume.
                             Example:
                               printf 'rax=0\\n' | haunt setregs 7
                             TTY input prints a hint; pipe for scripts.
  resume <hit_id> [--continue|--step|--ret]
                             release a parked thread.
                               --continue  (default) keep running
                               --step      single-step, then re-halt
                               --ret       run to return: plants a
                                           one-shot SW BP at [xSP] and
                                           continues; refused if [xSP]
                                           is not inside a loaded
                                           module (junk-address guard)

Trace events (from `--log` BPs):
  events [--since <id>] [--limit N] [--timeout <ms>]
                             tail the 4096-record ring buffer; oldest
                             record is evicted on overflow. Long-polls
                             up to timeout (agent caps at 60000 ms).
                             Each record: id, bp_id, tid, rip, t (ms
                             since first event), msg (the rendered
                             template).

See README for full workflows (range watchpoint, dtrace-style tracing,
return-value patching) and the \"Halts and global locks\" warning
before setting halts on allocator or loader paths.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    }
    match dispatch(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("haunt: {e}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(args: &[String]) -> Result<(), String> {
    let cmd = args[0].as_str();
    let rest = &args[1..];
    match cmd {
        "ping" => get("/ping").map(print_ok),
        "version" => get("/version").map(print_ok),
        "info" => get("/info").map(print_ok),
        "shutdown" => post("/shutdown", &[]).map(print_ok),

        "read" => cmd_read(rest, false),
        "read-raw" => cmd_read(rest, true),
        "write" => cmd_write(rest),
        "search" => cmd_search(rest),

        "bp" => cmd_bp(rest),

        "halts" => get("/halts").map(print_ok),
        "wait" => cmd_wait(rest),
        "regs" => cmd_regs(rest),
        "stack" => cmd_stack(rest),
        "setregs" => cmd_setregs(rest),
        "resume" => cmd_resume(rest),

        "modules" => get("/modules").map(print_ok),
        "exports" => {
            let name = rest.first().ok_or("exports <module>")?;
            get(&format!("/modules/{name}/exports")).map(print_ok)
        }
        "regions" => get("/memory/regions").map(print_ok),
        "threads" => get("/threads").map(print_ok),
        "events" => cmd_events(rest),
        "resolve" => {
            let name = rest.first().ok_or("resolve <module!symbol>")?;
            get(&format!("/symbols/resolve?name={}", url_encode(name))).map(print_ok)
        }
        "addr" => {
            let a = rest.first().ok_or("addr <addr>")?;
            get(&format!("/symbols/lookup?addr={}", url_encode(a))).map(print_ok)
        }
        "args" => cmd_args(rest),

        "-h" | "--help" | "help" => {
            println!("{USAGE}");
            Ok(())
        }
        _ => Err(format!("unknown command: {cmd}")),
    }
}

fn print_ok(body: Vec<u8>) {
    std::io::stdout().write_all(&body).ok();
    if body.last().copied() != Some(b'\n') {
        println!();
    }
}

fn cmd_read(args: &[String], raw: bool) -> Result<(), String> {
    let addr = args.first().ok_or("read <addr> [len]")?;
    let len: &str = match (args.get(1), raw) {
        (Some(l), _) => l,
        (None, false) => "16",
        (None, true) => return Err("read-raw <addr> <len>".into()),
    };
    let path = if raw {
        format!("/memory/read?addr={addr}&len={len}&format=raw")
    } else {
        format!("/memory/read?addr={addr}&len={len}")
    };
    let body = get(&path)?;
    std::io::stdout().write_all(&body).ok();
    if !raw && body.last().copied() != Some(b'\n') {
        println!();
    }
    Ok(())
}

fn cmd_write(args: &[String]) -> Result<(), String> {
    let addr = args.first().ok_or("write <addr> <hex>")?;
    let hex = args.get(1).ok_or("write <addr> <hex>")?;
    let bytes = hex_decode(hex).ok_or("invalid hex")?;
    let body = post(&format!("/memory/write?addr={addr}"), &bytes)?;
    print_ok(body);
    Ok(())
}

fn cmd_bp(args: &[String]) -> Result<(), String> {
    let sub = args.first().ok_or("bp <list|set|clear>")?.as_str();
    let rest = &args[1..];
    match sub {
        "list" => get("/bp/list").map(print_ok),
        "info" => {
            let id = rest.first().ok_or("bp info <id>")?;
            get(&format!("/bp/{id}")).map(print_ok)
        }
        "clear" => {
            let id = rest.first().ok_or("bp clear <id>")?;
            post(&format!("/bp/clear?id={id}"), &[]).map(print_ok)
        }
        "set" => {
            let target = rest.first().ok_or("bp set <addr|module!symbol> [opts]")?;
            let mut query = if target.contains('!') {
                format!("name={}", url_encode(target))
            } else {
                format!("addr={target}")
            };
            let mut i = 1;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--kind" => {
                        i += 1;
                        query.push_str(&format!("&kind={}", rest.get(i).ok_or("--kind value")?));
                    }
                    "--access" => {
                        i += 1;
                        query.push_str(&format!("&access={}", rest.get(i).ok_or("--access value")?));
                    }
                    "--size" => {
                        i += 1;
                        query.push_str(&format!("&size={}", rest.get(i).ok_or("--size value")?));
                    }
                    "--tid" => {
                        i += 1;
                        query.push_str(&format!("&tid={}", rest.get(i).ok_or("--tid value")?));
                    }
                    "--no-halt" => query.push_str("&halt=false"),
                    "--one-shot" => query.push_str("&one_shot=true"),
                    "--log" => {
                        i += 1;
                        let v = rest.get(i).ok_or("--log value")?;
                        query.push_str(&format!("&log={}", url_encode(v)));
                    }
                    "--if" => {
                        i += 1;
                        let v = rest.get(i).ok_or("--if value")?;
                        query.push_str(&format!("&cond={}", url_encode(v)));
                    }
                    other => return Err(format!("unknown flag: {other}")),
                }
                i += 1;
            }
            post(&format!("/bp/set?{query}"), &[]).map(print_ok)
        }
        _ => Err(format!("unknown bp subcommand: {sub} (try list/info/set/clear)")),
    }
}

fn cmd_wait(args: &[String]) -> Result<(), String> {
    let mut timeout = 30_000u64;
    let mut since: u64 = 0;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--timeout" => {
                timeout = args.get(i + 1).ok_or("--timeout value")?.parse().map_err(|_| "bad timeout")?;
                i += 2;
            }
            "--since" => {
                since = args.get(i + 1).ok_or("--since value")?.parse().map_err(|_| "bad since")?;
                i += 2;
            }
            other => return Err(format!("unknown flag: {other}")),
        }
    }
    get(&format!("/halts/wait?timeout={timeout}&since={since}")).map(print_ok)
}

fn cmd_regs(args: &[String]) -> Result<(), String> {
    let id = args.first().ok_or("regs <hit_id>")?;
    get(&format!("/halts/{id}")).map(print_ok)
}

fn cmd_stack(args: &[String]) -> Result<(), String> {
    let id = args.first().ok_or("stack <hit_id> [--depth N]")?;
    let mut depth: Option<&str> = None;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--depth" {
            depth = Some(args.get(i + 1).ok_or("--depth value")?);
            i += 2;
        } else {
            return Err(format!("unknown flag: {}", args[i]));
        }
    }
    let path = match depth {
        Some(n) => format!("/halts/{id}/stack?depth={n}"),
        None => format!("/halts/{id}/stack"),
    };
    get(&path).map(print_ok)
}

fn cmd_setregs(args: &[String]) -> Result<(), String> {
    let id = args.first().ok_or("setregs <hit_id>")?;
    // When stdin is a TTY there's no piped input — without a hint, a user
    // who types `haunt setregs 7` sits waiting for an EOF that never comes.
    // Print to stderr (not stdout) so it doesn't pollute the output if the
    // command is being piped or scripted with a connected TTY for some
    // reason.
    if std::io::stdin().is_terminal() {
        eprintln!("(reading regs from stdin as `name=value` lines; Ctrl-D to send)");
    }
    let mut body = Vec::new();
    std::io::stdin().read_to_end(&mut body).map_err(|e| format!("stdin: {e}"))?;
    post(&format!("/halts/{id}/regs"), &body).map(print_ok)
}

fn cmd_search(args: &[String]) -> Result<(), String> {
    let pattern = args.first().ok_or("search <pattern> [opts]")?;
    let mut module: Option<&str> = None;
    let mut start: Option<&str> = None;
    let mut end: Option<&str> = None;
    let mut limit: Option<&str> = None;
    let mut all = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--module" => { i += 1; module = Some(args.get(i).ok_or("--module value")?); }
            "--start" => { i += 1; start = Some(args.get(i).ok_or("--start value")?); }
            "--end" => { i += 1; end = Some(args.get(i).ok_or("--end value")?); }
            "--limit" => { i += 1; limit = Some(args.get(i).ok_or("--limit value")?); }
            "--all" => { all = true; }
            other => return Err(format!("unknown flag: {other}")),
        }
        i += 1;
    }
    // The agent enforces scope-required at the protocol layer too, but
    // failing client-side gives a faster, clearer error and saves a round
    // trip.
    if module.is_none() && start.is_none() && end.is_none() && !all {
        return Err(
            "scope required: pass --module <name>, --start/--end, or --all (slow!)".into(),
        );
    }
    let mut q = format!("pattern={}", url_encode(pattern));
    if let Some(m) = module { q.push_str(&format!("&module={}", url_encode(m))); }
    if let Some(s) = start { q.push_str(&format!("&start={}", url_encode(s))); }
    if let Some(e) = end { q.push_str(&format!("&end={}", url_encode(e))); }
    if all { q.push_str("&all=true"); }
    if let Some(l) = limit { q.push_str(&format!("&limit={l}")); }
    get(&format!("/memory/search?{q}")).map(print_ok)
}

fn cmd_args(args: &[String]) -> Result<(), String> {
    let id_str = args.first().ok_or("args <hit_id> [--conv c] [--count N]")?;
    let id: u64 = id_str.parse().map_err(|_| "bad hit_id")?;
    let mut conv: Option<String> = None;
    let mut count: usize = 4;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--conv" => {
                conv = Some(args.get(i + 1).ok_or("--conv value")?.clone());
                i += 2;
            }
            "--count" => {
                count = args.get(i + 1).ok_or("--count value")?.parse().map_err(|_| "bad count")?;
                i += 2;
            }
            other => return Err(format!("unknown flag: {other}")),
        }
    }

    // Fetch the agent's arch so we can default `--conv` correctly and
    // reject obviously-wrong combos (e.g. `--conv thiscall` against an x64
    // agent silently picks the wrong register set).
    let arch = fetch_agent_arch()?;
    let conv = conv.unwrap_or_else(|| default_conv_for(&arch).to_string());
    check_conv_matches_arch(&conv, &arch)?;

    let body = get(&format!("/halts/{id}"))?;
    let regs = parse_regs_lines(&body)?;
    let (reg_args, stack_offset, ptr_size) = layout_for_conv(&conv, &regs)?;

    // Bulk-fetch stack slots in one round trip rather than N.
    let stack_count = count.saturating_sub(reg_args.len());
    let stack_bytes = if stack_count > 0 {
        let sp = regs
            .get("rsp")
            .copied()
            .ok_or("no stack pointer in regs")?;
        let len = stack_count * ptr_size;
        let stack_addr = sp.wrapping_add(stack_offset as u64);
        let body = get(&format!("/memory/read?addr=0x{stack_addr:x}&len={len}"))?;
        let s = std::str::from_utf8(&body).map_err(|_| "non-utf8 memory body")?;
        hex_decode(s.trim()).ok_or("bad hex from /memory/read")?
    } else {
        Vec::new()
    };

    for (i, &v) in reg_args.iter().take(count).enumerate() {
        println!("arg{}: 0x{v:x}", i + 1);
    }
    for i in 0..stack_count {
        let off = i * ptr_size;
        let bytes = &stack_bytes[off..off + ptr_size];
        let v = match ptr_size {
            8 => u64::from_le_bytes(bytes.try_into().unwrap()),
            4 => u32::from_le_bytes(bytes.try_into().unwrap()) as u64,
            _ => 0,
        };
        println!("arg{}: 0x{v:x}", reg_args.len() + i + 1);
    }
    Ok(())
}

fn parse_regs_lines(body: &[u8]) -> Result<HashMap<String, u64>, String> {
    let s = std::str::from_utf8(body).map_err(|_| "non-utf8 regs body")?;
    let mut out = HashMap::new();
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (name, rest) = match line.split_once('=') {
            Some(p) => p,
            None => continue,
        };
        let value_str = rest.split_whitespace().next().unwrap_or("");
        let value = if let Some(hex) = value_str.strip_prefix("0x") {
            u64::from_str_radix(hex, 16).map_err(|_| format!("bad hex: {line}"))?
        } else {
            value_str.parse::<u64>().map_err(|_| format!("bad int: {line}"))?
        };
        out.insert(name.trim().to_string(), value);
    }
    Ok(out)
}

fn fetch_agent_arch() -> Result<String, String> {
    let body = get("/info")?;
    let s = std::str::from_utf8(&body).map_err(|_| "non-utf8 /info body")?;
    for line in s.lines() {
        if let Some(v) = line.trim().strip_prefix("arch=") {
            return Ok(v.to_string());
        }
    }
    Err("agent /info did not include arch".into())
}

fn default_conv_for(arch: &str) -> &'static str {
    match arch {
        "x86_64" => "win64",
        "x86" => "cdecl",
        // Sensible fallback — same default as before this code was added.
        _ => "win64",
    }
}

fn check_conv_matches_arch(conv: &str, arch: &str) -> Result<(), String> {
    let conv_arch = match conv {
        "win64" | "sysv" | "sysv64" => "x86_64",
        "thiscall" | "fastcall" | "stdcall" | "cdecl" => "x86",
        _ => return Ok(()), // unknown convs fall through to layout_for_conv to error
    };
    if conv_arch != arch {
        return Err(format!(
            "calling convention `{conv}` is for {conv_arch} but agent is {arch}"
        ));
    }
    Ok(())
}

/// Returns (reg-passed args in order, byte-offset of first stack arg from SP,
/// pointer size in bytes).
fn layout_for_conv(
    conv: &str,
    regs: &HashMap<String, u64>,
) -> Result<(Vec<u64>, usize, usize), String> {
    let g = |n: &str| regs.get(n).copied().ok_or_else(|| format!("reg {n} missing"));
    match conv {
        "win64" => {
            // rcx, rdx, r8, r9; stack args start past return addr (8) + 32-byte
            // shadow space = 0x28.
            Ok((vec![g("rcx")?, g("rdx")?, g("r8")?, g("r9")?], 0x28, 8))
        }
        "sysv" | "sysv64" => {
            // rdi, rsi, rdx, rcx, r8, r9; stack args start past return addr.
            Ok((
                vec![g("rdi")?, g("rsi")?, g("rdx")?, g("rcx")?, g("r8")?, g("r9")?],
                8,
                8,
            ))
        }
        "thiscall" => Ok((vec![g("rcx")?], 4, 4)),
        "fastcall" => Ok((vec![g("rcx")?, g("rdx")?], 4, 4)),
        "stdcall" | "cdecl" => Ok((vec![], 4, 4)),
        _ => Err(format!("unknown calling convention: {conv}")),
    }
}

fn cmd_events(args: &[String]) -> Result<(), String> {
    let mut since: u64 = 0;
    let mut limit: u64 = 256;
    let mut timeout: u64 = 0;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--since" => {
                since = args.get(i + 1).ok_or("--since value")?.parse().map_err(|_| "bad since")?;
                i += 2;
            }
            "--limit" => {
                limit = args.get(i + 1).ok_or("--limit value")?.parse().map_err(|_| "bad limit")?;
                i += 2;
            }
            "--timeout" => {
                timeout = args.get(i + 1).ok_or("--timeout value")?.parse().map_err(|_| "bad timeout")?;
                i += 2;
            }
            other => return Err(format!("unknown flag: {other}")),
        }
    }
    get(&format!("/events?since={since}&limit={limit}&timeout={timeout}")).map(print_ok)
}

fn cmd_resume(args: &[String]) -> Result<(), String> {
    let id = args.first().ok_or("resume <hit_id> [--step|--ret]")?;
    let mode = args.iter().skip(1).find_map(|a| match a.as_str() {
        "--step" => Some("step"),
        "--ret" => Some("ret"),
        "--continue" => Some("continue"),
        _ => None,
    }).unwrap_or("continue");
    post(&format!("/halts/{id}/resume?mode={mode}"), &[]).map(print_ok)
}

// --- HTTP ---------------------------------------------------------------

fn base_url() -> String {
    std::env::var("HAUNT_URL").unwrap_or_else(|_| "http://127.0.0.1:7878".into())
}

fn token() -> Option<String> {
    std::env::var("HAUNT_TOKEN").ok().filter(|s| !s.is_empty())
}

fn get(path: &str) -> Result<Vec<u8>, String> {
    request("GET", path, None)
}

fn post(path: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    request("POST", path, Some(body))
}

fn request(method: &str, path: &str, body: Option<&[u8]>) -> Result<Vec<u8>, String> {
    let base = base_url();
    let rest = base.strip_prefix("http://").ok_or("HAUNT_URL must be http://...")?;
    let host_port = match rest.find('/') {
        Some(i) => &rest[..i],
        None => rest,
    };

    let stream = TcpStream::connect(host_port).map_err(|e| format!("connect: {e}"))?;
    let timeout = Duration::from_secs(SOCKET_READ_TIMEOUT_SECS);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let mut stream = stream;

    let mut req = format!("{method} {path} HTTP/1.1\r\n");
    req.push_str(&format!("Host: {host_port}\r\n"));
    req.push_str("Connection: close\r\n");
    // The agent rejects requests without `X-Haunt-Client` (CSRF defense:
    // browsers can't add custom headers to a simple request without CORS
    // preflight, which the agent doesn't support — so this header acts as
    // a "yes, this is a real client" signal). curl users must add
    // `-H 'X-Haunt-Client: curl'` to do the same.
    req.push_str("X-Haunt-Client: cli\r\n");
    if let Some(t) = token() {
        req.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    if let Some(b) = body {
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
        req.push_str("Content-Type: application/octet-stream\r\n");
    }
    req.push_str("\r\n");

    stream.write_all(req.as_bytes()).map_err(|e| format!("write: {e}"))?;
    if let Some(b) = body {
        stream.write_all(b).map_err(|e| format!("write body: {e}"))?;
    }

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|e| format!("read: {e}"))?;

    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("response has no header terminator")?;
    let header = std::str::from_utf8(&raw[..header_end]).map_err(|_| "non-UTF8 header")?;
    let status_line = header.lines().next().ok_or("empty response")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or("bad status")?;

    let body_start = header_end + 4;
    let body_bytes = raw[body_start..].to_vec();

    if !(200..300).contains(&status) {
        let s = String::from_utf8_lossy(&body_bytes);
        return Err(format!("HTTP {status}: {}", s.trim()));
    }
    Ok(body_bytes)
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let safe = b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'_' | b'.' | b'~' | b'!');
        if safe {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let trimmed: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if trimmed.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(trimmed.len() / 2);
    let bytes = trimmed.as_bytes();
    for chunk in bytes.chunks(2) {
        let s = std::str::from_utf8(chunk).ok()?;
        out.push(u8::from_str_radix(s, 16).ok()?);
    }
    Some(out)
}
