//! `haunt session save` / `haunt session restore`.
//!
//! Snapshots the agent's struct registry and active breakpoints into a
//! single JSON file, and replays them onto a fresh agent. Schemas are
//! re-emitted as canonical `.layouts` source (lossy on comments, lossless
//! on layout). Breakpoints are saved as their flag set, restored via the
//! existing `POST /bp/set` flow.

use serde::{Deserialize, Serialize};

use crate::{get, post, url_encode};

const SESSION_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
pub struct Session {
    pub version: u32,
    pub agent: AgentInfo,
    pub structs: Vec<StructEntry>,
    pub breakpoints: Vec<BpEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct AgentInfo {
    pub version: String,
    pub arch: String,
}

#[derive(Serialize, Deserialize)]
pub struct StructEntry {
    pub name: String,
    pub source: String,
}

#[derive(Serialize, Deserialize)]
pub struct BpEntry {
    /// Symbolic target if the BP was set by name (`requested=` field), else
    /// the resolved hex address. Restore prefers symbolic so re-injection
    /// at a different load address still hits the right code.
    pub target: String,
    pub kind: String,
    pub halt: bool,
    pub one_shot: bool,
    pub tid_filter: Option<u32>,
    /// Hardware-BP options. Present only when `kind == "hw"`.
    pub access: Option<String>,
    pub size: Option<u32>,
    pub log: Option<String>,
    pub log_if: Option<String>,
    pub halt_if: Option<String>,
    /// `--struct name=Type@expr` bindings, in declaration order.
    /// Optional with `default` so older session files (no field) still
    /// parse; absent and empty are equivalent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub struct_bindings: Vec<String>,
}

pub fn cmd(args: &[String]) -> Result<(), String> {
    let sub = args.first().ok_or("session <save|restore> <file>")?.as_str();
    let rest = &args[1..];
    match sub {
        "save" => {
            let path = rest.first().ok_or("session save <file>")?;
            save(path)
        }
        "restore" => {
            let path = rest.first().ok_or("session restore <file>")?;
            restore(path)
        }
        _ => Err(format!("unknown session subcommand: {sub} (try save|restore)")),
    }
}

fn save(path: &str) -> Result<(), String> {
    let agent = fetch_agent_info()?;
    let structs = fetch_structs()?;
    let breakpoints = fetch_breakpoints()?;

    let session = Session {
        version: SESSION_VERSION,
        agent,
        structs,
        breakpoints,
    };
    let json = serde_json::to_string_pretty(&session)
        .map_err(|e| format!("serialize session: {e}"))?;
    std::fs::write(path, json).map_err(|e| format!("write {path}: {e}"))?;

    println!(
        "saved {} struct(s), {} breakpoint(s) → {path}",
        session.structs.len(),
        session.breakpoints.len(),
    );
    Ok(())
}

fn restore(path: &str) -> Result<(), String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let session: Session = serde_json::from_str(&raw)
        .map_err(|e| format!("parse {path}: {e}"))?;
    if session.version != SESSION_VERSION {
        return Err(format!(
            "unsupported session version {} (this build expects {SESSION_VERSION})",
            session.version
        ));
    }

    // Light arch sanity check — restoring an x86 session against an x64
    // agent (or vice versa) will fail later in obvious ways; bail early
    // with a clear message instead.
    let live = fetch_agent_info()?;
    if live.arch != session.agent.arch {
        return Err(format!(
            "arch mismatch: session was saved against '{}', live agent is '{}'",
            session.agent.arch, live.arch
        ));
    }

    // Schemas first so any future BP --struct refs have what they need.
    for s in &session.structs {
        // `replace=true` is the right default on restore: the saved state
        // wins over whatever's currently in the registry.
        post("/schemas?replace=true", s.source.as_bytes())
            .map_err(|e| format!("restore struct '{}': {e}", s.name))?;
        println!("+ struct {}", s.name);
    }

    for bp in &session.breakpoints {
        let query = encode_bp(bp);
        post(&format!("/bp/set?{query}"), &[])
            .map_err(|e| format!("restore bp '{}': {e}", bp.target))?;
        println!("+ bp {}", bp.target);
    }

    println!(
        "restored {} struct(s), {} breakpoint(s)",
        session.structs.len(),
        session.breakpoints.len(),
    );
    Ok(())
}

// --- save helpers --------------------------------------------------------

fn fetch_agent_info() -> Result<AgentInfo, String> {
    let body = get("/info")?;
    let text = String::from_utf8_lossy(&body);
    let mut version = String::new();
    let mut arch = String::new();
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("version=") {
            version = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("arch=") {
            arch = v.trim().to_string();
        }
    }
    if arch.is_empty() {
        return Err("agent /info: missing 'arch'".into());
    }
    if version.is_empty() {
        version = "unknown".into();
    }
    Ok(AgentInfo { version, arch })
}

fn fetch_structs() -> Result<Vec<StructEntry>, String> {
    let list = get("/schemas")?;
    let listing = String::from_utf8_lossy(&list);
    let mut out = Vec::new();
    for line in listing.lines() {
        // Each line: `<Name> size=0xN fields=N`. We only need the name.
        let name = match line.split_whitespace().next() {
            Some(n) => n.to_string(),
            None => continue,
        };
        let body = get(&format!("/schemas/{}", url_encode(&name)))
            .map_err(|e| format!("fetch struct '{name}': {e}"))?;
        let source = String::from_utf8(body).map_err(|_| {
            format!("struct '{name}': agent returned non-UTF8 source")
        })?;
        out.push(StructEntry { name, source });
    }
    Ok(out)
}

fn fetch_breakpoints() -> Result<Vec<BpEntry>, String> {
    let body = get("/bp/list")?;
    let listing = String::from_utf8_lossy(&body);
    let mut out = Vec::new();
    for line in listing.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let pairs = parse_kv_line(line)
            .map_err(|e| format!("parse /bp/list: {e}\nline: {line}"))?;
        out.push(bp_entry_from_pairs(&pairs)?);
    }
    Ok(out)
}

/// Parse one line of `key=value` pairs as emitted by `format_bp`. Values
/// may be unquoted (no whitespace) or double-quoted with `\\`, `\n`, `\r`,
/// `\t`, `\"` escapes — matching `quote_msg`'s output.
fn parse_kv_line(line: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Skip leading spaces.
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        // Read key.
        let key_start = i;
        while i < bytes.len() && bytes[i] != b'=' && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            return Err(format!("expected '=' after key '{}'", &line[key_start..i.min(line.len())]));
        }
        let key = line[key_start..i].to_string();
        i += 1; // skip '='

        // Read value.
        let value = if i < bytes.len() && bytes[i] == b'"' {
            i += 1; // skip opening "
            let mut s = String::new();
            while i < bytes.len() {
                let c = bytes[i];
                if c == b'"' {
                    i += 1;
                    break;
                }
                if c == b'\\' && i + 1 < bytes.len() {
                    let next = bytes[i + 1];
                    let unescaped = match next {
                        b'\\' => '\\',
                        b'"' => '"',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        other => return Err(format!("unknown escape \\{}", other as char)),
                    };
                    s.push(unescaped);
                    i += 2;
                } else {
                    s.push(c as char);
                    i += 1;
                }
            }
            s
        } else {
            let v_start = i;
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            line[v_start..i].to_string()
        };

        out.push((key, value));
    }
    Ok(out)
}

fn bp_entry_from_pairs(pairs: &[(String, String)]) -> Result<BpEntry, String> {
    let lookup = |k: &str| -> Option<&str> {
        pairs.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str())
    };

    // Prefer the symbolic name when the BP was set by `module!symbol`.
    let target = match lookup("requested") {
        Some(name) => name.to_string(),
        None => lookup("addr")
            .ok_or("bp line: missing both 'requested' and 'addr'")?
            .to_string(),
    };

    let raw_kind = lookup("kind").ok_or("bp line: missing 'kind'")?;
    let (kind, access, size) = parse_bp_kind(raw_kind)?;
    let halt = parse_bool_field("halt", lookup("halt"))?;
    let one_shot = parse_bool_field("one_shot", lookup("one_shot"))?;
    let tid_filter = match lookup("tid_filter") {
        Some("-") | None => None,
        Some(s) => Some(s.parse::<u32>().map_err(|_| format!("bad tid_filter: {s}"))?),
    };
    let log = lookup("log").map(str::to_string);
    let log_if = lookup("log_if").map(str::to_string);
    let halt_if = lookup("halt_if").map(str::to_string);
    // `struct=` may appear multiple times; collect all in declaration order.
    let struct_bindings: Vec<String> = pairs
        .iter()
        .filter_map(|(k, v)| (k == "struct").then(|| v.clone()))
        .collect();

    Ok(BpEntry {
        target,
        kind,
        halt,
        one_shot,
        tid_filter,
        access,
        size,
        log,
        log_if,
        halt_if,
        struct_bindings,
    })
}

fn parse_bool_field(name: &str, v: Option<&str>) -> Result<bool, String> {
    match v {
        Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(other) => Err(format!("{name}: expected true|false, got '{other}'")),
        None => Err(format!("{name}: missing")),
    }
}

/// `kind=` field shapes:
///   `sw`
///   `hw/<access>/size=<n>`     where access in x|w|rw|any and n in 1,2,4,8
///   `page/size=<n>`
fn parse_bp_kind(raw: &str) -> Result<(String, Option<String>, Option<u32>), String> {
    if raw == "sw" {
        return Ok(("sw".into(), None, None));
    }
    if let Some(rest) = raw.strip_prefix("hw/") {
        let parts: Vec<&str> = rest.splitn(2, '/').collect();
        if parts.len() != 2 {
            return Err(format!("malformed hw kind: {raw}"));
        }
        let access = parts[0].to_string();
        let size = parts[1]
            .strip_prefix("size=")
            .ok_or_else(|| format!("hw kind missing size=: {raw}"))?
            .parse::<u32>()
            .map_err(|_| format!("hw kind bad size: {raw}"))?;
        return Ok(("hw".into(), Some(access), Some(size)));
    }
    if let Some(rest) = raw.strip_prefix("page/") {
        let size = rest
            .strip_prefix("size=")
            .ok_or_else(|| format!("page kind missing size=: {raw}"))?
            .parse::<u32>()
            .map_err(|_| format!("page kind bad size: {raw}"))?;
        return Ok(("page".into(), None, Some(size)));
    }
    Err(format!("unknown bp kind: {raw}"))
}

// --- restore helpers -----------------------------------------------------

fn encode_bp(bp: &BpEntry) -> String {
    let mut q = if bp.target.contains('!') {
        format!("name={}", url_encode(&bp.target))
    } else {
        format!("addr={}", url_encode(&bp.target))
    };
    q.push_str(&format!("&kind={}", url_encode(&bp.kind)));
    q.push_str(&format!("&halt={}", bp.halt));
    q.push_str(&format!("&one_shot={}", bp.one_shot));
    if let Some(t) = bp.tid_filter {
        q.push_str(&format!("&tid={t}"));
    }
    if let Some(a) = &bp.access {
        q.push_str(&format!("&access={}", url_encode(a)));
    }
    if let Some(s) = bp.size {
        q.push_str(&format!("&size={s}"));
    }
    if let Some(v) = &bp.log {
        q.push_str(&format!("&log={}", url_encode(v)));
    }
    if let Some(v) = &bp.log_if {
        q.push_str(&format!("&log_if={}", url_encode(v)));
    }
    if let Some(v) = &bp.halt_if {
        q.push_str(&format!("&halt_if={}", url_encode(v)));
    }
    for b in &bp.struct_bindings {
        q.push_str(&format!("&struct={}", url_encode(b)));
    }
    q
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kv_simple() {
        let p = parse_kv_line("id=4 addr=0x401234 kind=sw halt=true").unwrap();
        assert_eq!(p[0], ("id".into(), "4".into()));
        assert_eq!(p[1], ("addr".into(), "0x401234".into()));
        assert_eq!(p[2], ("kind".into(), "sw".into()));
        assert_eq!(p[3], ("halt".into(), "true".into()));
    }

    #[test]
    fn parse_kv_quoted_with_spaces_and_escapes() {
        let line = r#"log="type=%ecx [esp+4]=%[esp+4]" requested="kernel32.dll!CreateFileW""#;
        let p = parse_kv_line(line).unwrap();
        assert_eq!(p[0].1, "type=%ecx [esp+4]=%[esp+4]");
        assert_eq!(p[1].1, "kernel32.dll!CreateFileW");
    }

    #[test]
    fn parse_kv_quoted_escapes() {
        let p = parse_kv_line(r#"msg="line1\nquote\"inside""#).unwrap();
        assert_eq!(p[0].1, "line1\nquote\"inside");
    }

    #[test]
    fn parse_kind_sw() {
        let (k, a, s) = parse_bp_kind("sw").unwrap();
        assert_eq!(k, "sw");
        assert!(a.is_none());
        assert!(s.is_none());
    }

    #[test]
    fn parse_kind_hw() {
        let (k, a, s) = parse_bp_kind("hw/w/size=4").unwrap();
        assert_eq!(k, "hw");
        assert_eq!(a.as_deref(), Some("w"));
        assert_eq!(s, Some(4));
    }

    #[test]
    fn parse_kind_page() {
        let (k, a, s) = parse_bp_kind("page/size=4096").unwrap();
        assert_eq!(k, "page");
        assert!(a.is_none());
        assert_eq!(s, Some(4096));
    }

    #[test]
    fn bp_entry_with_symbolic_target() {
        let line = r#"id=1 addr=0x7ffe0000 kind=sw halt=true one_shot=false tid_filter=- hits=0 requested="kernel32.dll!CreateFileW""#;
        let pairs = parse_kv_line(line).unwrap();
        let bp = bp_entry_from_pairs(&pairs).unwrap();
        assert_eq!(bp.target, "kernel32.dll!CreateFileW");
        assert!(bp.halt);
    }

    #[test]
    fn bp_entry_with_addr_only() {
        let line = "id=1 addr=0x7ffe0000 kind=sw halt=false one_shot=true tid_filter=42 hits=0";
        let pairs = parse_kv_line(line).unwrap();
        let bp = bp_entry_from_pairs(&pairs).unwrap();
        assert_eq!(bp.target, "0x7ffe0000");
        assert_eq!(bp.tid_filter, Some(42));
        assert!(bp.one_shot);
    }

    #[test]
    fn session_json_roundtrip() {
        let s = Session {
            version: SESSION_VERSION,
            agent: AgentInfo {
                version: "0.5.2".into(),
                arch: "x86_64".into(),
            },
            structs: vec![StructEntry {
                name: "GamePlayer".into(),
                source: "struct GamePlayer size=0x4 {\n    u32 x @0x00\n}\n".into(),
            }],
            breakpoints: vec![BpEntry {
                target: "kernel32.dll!CreateFileW".into(),
                kind: "sw".into(),
                halt: true,
                one_shot: false,
                tid_filter: None,
                access: None,
                size: None,
                log: Some("rcx=%rcx".into()),
                log_if: None,
                halt_if: Some("rcx == 0".into()),
                struct_bindings: Vec::new(),
            }],
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: Session = serde_json::from_str(&json).unwrap();
        assert_eq!(back.version, SESSION_VERSION);
        assert_eq!(back.structs.len(), 1);
        assert_eq!(back.structs[0].name, "GamePlayer");
        assert_eq!(back.breakpoints[0].target, "kernel32.dll!CreateFileW");
        assert_eq!(back.breakpoints[0].halt_if.as_deref(), Some("rcx == 0"));
    }

    #[test]
    fn encode_bp_uses_name_for_symbolic_target() {
        let bp = BpEntry {
            target: "kernel32.dll!CreateFileW".into(),
            kind: "sw".into(),
            halt: true,
            one_shot: false,
            tid_filter: None,
            access: None,
            size: None,
            log: None,
            log_if: None,
            halt_if: None,
            struct_bindings: Vec::new(),
        };
        let q = encode_bp(&bp);
        assert!(q.starts_with("name="));
        assert!(!q.contains("addr="));
    }

    #[test]
    fn encode_bp_uses_addr_for_hex_target() {
        let bp = BpEntry {
            target: "0x401234".into(),
            kind: "sw".into(),
            halt: false,
            one_shot: true,
            tid_filter: Some(7),
            access: None,
            size: None,
            log: None,
            log_if: None,
            halt_if: None,
            struct_bindings: Vec::new(),
        };
        let q = encode_bp(&bp);
        assert!(q.starts_with("addr="));
        assert!(q.contains("&halt=false"));
        assert!(q.contains("&one_shot=true"));
        assert!(q.contains("&tid=7"));
    }

    #[test]
    fn parse_struct_binding_pairs_collected() {
        let line = r#"id=1 addr=0x401234 kind=sw halt=true one_shot=false tid_filter=- hits=0 struct="enemy=GameEnemy@[rcx]" struct="player=GamePlayer@[rdx]""#;
        let pairs = parse_kv_line(line).unwrap();
        let bp = bp_entry_from_pairs(&pairs).unwrap();
        assert_eq!(bp.struct_bindings.len(), 2);
        assert_eq!(bp.struct_bindings[0], "enemy=GameEnemy@[rcx]");
        assert_eq!(bp.struct_bindings[1], "player=GamePlayer@[rdx]");
    }

    #[test]
    fn encode_struct_bindings_round_trip() {
        let bp = BpEntry {
            target: "0x401234".into(),
            kind: "sw".into(),
            halt: true,
            one_shot: false,
            tid_filter: None,
            access: None,
            size: None,
            log: None,
            log_if: None,
            halt_if: None,
            struct_bindings: vec![
                "enemy=GameEnemy@[rcx]".into(),
                "player=GamePlayer@[rdx]".into(),
            ],
        };
        let q = encode_bp(&bp);
        // Each binding shows up as a separate `&struct=` parameter so the
        // server's repeated-key handling stays consistent with `bp set`.
        let count = q.matches("&struct=").count();
        assert_eq!(count, 2, "expected two &struct= occurrences in: {q}");
    }
}
