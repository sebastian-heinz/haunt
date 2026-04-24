//! haunt — command-line client for haunt.dll's HTTP protocol.
//!
//! Env:
//!   HAUNT_URL    base URL (default http://127.0.0.1:7878)
//!   HAUNT_TOKEN  Bearer token for auth (default none)

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::ExitCode;

const USAGE: &str = "\
haunt <command> [args]

memory:
  read <addr> [len]          read bytes (default len=16), hex output
  read-raw <addr> <len>      read bytes, binary to stdout
  write <addr> <hex>         write hex-encoded bytes

breakpoints:
  bp list
  bp set <addr|module!symbol> [--kind sw|hw|page] [--no-halt] [--one-shot]
         [--access x|w|rw|any] [--size N] [--tid N]
  bp clear <id>

symbols:
  resolve <module!symbol>     print address of an export

halts:
  halts                      list currently parked hits
  wait [--timeout <ms>]      block until a new halt (or timeout, default 30000)
  regs <hit_id>              dump registers
  stack <hit_id> [--depth N] backtrace from rbp chain (default 32, max 256)
  setregs <hit_id>           read key=value lines from stdin and apply
  resume <hit_id> [--step|--ret]

introspection:
  modules
  exports <module>
  regions

misc:
  ping
  version
  shutdown
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
        "shutdown" => post("/shutdown", &[]).map(print_ok),

        "read" => cmd_read(rest, false),
        "read-raw" => cmd_read(rest, true),
        "write" => cmd_write(rest),

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
        "resolve" => {
            let name = rest.first().ok_or("resolve <module!symbol>")?;
            get(&format!("/symbols/resolve?name={}", url_encode(name))).map(print_ok)
        }

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
                    "--halt" => query.push_str("&halt=true"),
                    "--one-shot" | "--oneshot" => query.push_str("&one_shot=true"),
                    other => return Err(format!("unknown flag: {other}")),
                }
                i += 1;
            }
            post(&format!("/bp/set?{query}"), &[]).map(print_ok)
        }
        _ => Err(format!("unknown bp subcommand: {sub}")),
    }
}

fn cmd_wait(args: &[String]) -> Result<(), String> {
    let mut timeout = 30_000u64;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--timeout" {
            timeout = args.get(i + 1).ok_or("--timeout value")?.parse().map_err(|_| "bad timeout")?;
            i += 2;
        } else {
            return Err(format!("unknown flag: {}", args[i]));
        }
    }
    get(&format!("/halts/wait?timeout={timeout}")).map(print_ok)
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
    let mut body = Vec::new();
    std::io::stdin().read_to_end(&mut body).map_err(|e| format!("stdin: {e}"))?;
    post(&format!("/halts/{id}/regs"), &body).map(print_ok)
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

    let mut stream = TcpStream::connect(host_port).map_err(|e| format!("connect: {e}"))?;

    let mut req = format!("{method} {path} HTTP/1.1\r\n");
    req.push_str(&format!("Host: {host_port}\r\n"));
    req.push_str("Connection: close\r\n");
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
