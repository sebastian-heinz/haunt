//! Tiny expression / template DSL used by `--log` and `--if` on breakpoints.
//!
//! Templates: `"text %reg %[expr] %{expr} text"`. `%name` substitutes a
//! register (hex). `%[expr]` substitutes the value **at address expr**
//! (deref then substitute — same `[]` semantics as in the expression
//! grammar). `%{expr}` substitutes the raw expression value with no deref.
//! `%%` is a literal `%`.
//!
//! Expressions:
//! - Literals: decimal `123` or hex `0x...`
//! - Register references: `eax`, `rcx`, `rip`, `eflags`, ... (case-sensitive).
//!   `rN` and `eN` are interchangeable for the eight 32-bit names.
//! - Memory deref: `[expr]` reads pointer-width from the evaluated address.
//! - Binary: `+`, `-`, `*`, `<<`, `>>`, `&`, `|`, `^`, `==`, `!=`, `<`, `<=`,
//!   `>`, `>=`. Standard precedence (mul > add > shift > & > ^ > | > compare).
//! - Unary: `~` (bitwise not), `-` (negate, wrapping over u64).
//!
//! Used by both the agent (server-side eval inside VEH) and any client that
//! wants to validate templates before sending them.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add, Sub, Mul,
    Shl, Shr,
    BitAnd, BitOr, BitXor,
    Eq, Ne, Lt, Le, Gt, Ge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Not,
    Neg,
}

#[derive(Debug, Clone)]
pub enum Expr {
    Lit(u64),
    Reg(String),
    Deref(Box<Expr>),
    Unary(UnaryOp, Box<Expr>),
    Binary(BinOp, Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone)]
pub enum TemplatePart {
    Literal(String),
    Reg(String),
    Expr(Expr),
    /// Schema-bound field reference: `%[binding.field.subfield...]`.
    /// Resolved at render time against the BP's `StructBinding`s and
    /// the schema registry. Each intermediate path step must be a typed
    /// pointer (`ptr32<T>` / `ptr64<T>`) that the renderer follows; the
    /// terminal step's value is formatted by its `FieldKind`.
    Field { binding: String, path: Vec<String> },
}

/// A parsed expression bundled with the source text it came from. Used as a
/// breakpoint condition: VEH evaluates `expr`; `bp list` / `bp info` show
/// `source` so users can audit what a BP is actually doing.
#[derive(Debug, Clone)]
pub struct CondHook {
    pub source: String,
    pub expr: Expr,
}

/// A parsed log template bundled with its source text.
#[derive(Debug, Clone)]
pub struct TemplateHook {
    pub source: String,
    pub parts: Vec<TemplatePart>,
}

/// Per-breakpoint struct binding: `name=Type@expr`.
///
/// Resolved at BP set time against the schema registry; consumed at hit
/// time by template references like `%[name.field]`. The `expr` evaluates
/// against the live CONTEXT to produce a base address; the registry
/// supplies field offsets within that base.
#[derive(Debug, Clone)]
pub struct StructBinding {
    /// Binding name used in `%[name.field]` references.
    pub name: String,
    /// Struct type name; must exist in the schema registry at BP set time.
    pub type_name: String,
    /// Parsed expression for the base address, evaluated each hit.
    pub expr: Expr,
    /// Original `expr` source text, for `bp list` round-tripping.
    pub expr_source: String,
}

/// Parse a `name=Type@expr` triple. Each piece is required and must be
/// non-empty; missing `=`, missing `@`, empty name/type/expr, or a
/// malformed expression all reject with a message naming the problem.
///
/// `=` and `@` are reserved separators — neither appears in legal
/// identifiers or in the expression grammar — so a left-most split on
/// each is unambiguous even when the expression contains comparison
/// operators (`==`, `<=`, etc.) or arithmetic.
pub fn parse_struct_binding(s: &str) -> Result<StructBinding, String> {
    let eq = s
        .find('=')
        .ok_or_else(|| format!("expected '<name>=<Type>@<expr>', got '{s}'"))?;
    let name = s[..eq].trim();
    if name.is_empty() {
        return Err("missing binding name before '='".into());
    }
    if !is_ident(name) {
        return Err(format!("binding name '{name}' is not a valid identifier"));
    }

    let rest = &s[eq + 1..];
    let at = rest
        .find('@')
        .ok_or_else(|| format!("missing '@' in binding '{s}'"))?;
    let type_name = rest[..at].trim();
    if type_name.is_empty() {
        return Err("missing struct type between '=' and '@'".into());
    }
    if !is_ident(type_name) {
        return Err(format!(
            "struct type '{type_name}' is not a valid identifier"
        ));
    }

    let expr_src = rest[at + 1..].trim();
    if expr_src.is_empty() {
        return Err("missing expression after '@'".into());
    }
    let expr = parse_expr(expr_src)
        .map_err(|e| format!("expression '{expr_src}': {e}"))?;

    Ok(StructBinding {
        name: name.to_string(),
        type_name: type_name.to_string(),
        expr,
        expr_source: expr_src.to_string(),
    })
}

fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Verify every `%[binding.field.subfield]` reference in `template`
/// resolves against `bindings` and the live schema registry. Returns
/// `Err` with a message naming the offending reference; `Ok` if there
/// are no field parts or every path resolves cleanly.
///
/// Run at BP set time so typos surface as a 400 instead of `<no field
/// 'X' in T>` markers in the rendered log line at hit time.
///
/// Takes an explicit `&Registry` so the caller can hold the schema
/// lock across both this check and the subsequent BP install, closing
/// the TOCTOU where a concurrent `schema drop` could remove a
/// referenced type between validation and install. There is
/// deliberately no convenience variant that acquires the lock
/// internally — a caller that doesn't already hold it is racing
/// `schema drop`/`clear` and the bug would be invisible until hit
/// time.
pub fn validate_field_paths(
    template: &TemplateHook,
    bindings: &[StructBinding],
    reg: &crate::schema::registry::Registry,
) -> Result<(), String> {
    for part in &template.parts {
        if let TemplatePart::Field { binding, path } = part {
            validate_one_field_path(binding, path, bindings, reg)?;
        }
    }
    Ok(())
}

fn validate_one_field_path(
    binding: &str,
    path: &[String],
    bindings: &[StructBinding],
    reg: &crate::schema::registry::Registry,
) -> Result<(), String> {
    let display = || format!("%[{}.{}]", binding, path.join("."));
    let b = bindings
        .iter()
        .find(|b| b.name == binding)
        .ok_or_else(|| {
            format!(
                "{}: unknown binding '{binding}' (declare it with `--struct {binding}=Type@expr`)",
                display()
            )
        })?;
    let mut current = reg.get(&b.type_name).ok_or_else(|| {
        format!(
            "{}: binding '{binding}' references type '{}' which is not in the schema registry",
            display(),
            b.type_name
        )
    })?;
    if path.is_empty() {
        return Err(format!("{}: empty field path", display()));
    }
    let last = path.len() - 1;
    for (i, step) in path.iter().enumerate() {
        let field = current.field(step).ok_or_else(|| {
            format!(
                "{}: '{step}' is not a field of '{}'",
                display(),
                current.name
            )
        })?;
        if i == last {
            return Ok(());
        }
        match field.kind {
            crate::schema::layout::FieldKind::PtrTyped => {
                let pointee = field.pointee.as_deref().ok_or_else(|| {
                    format!("{}: typed pointer at '{step}' has no target name", display())
                })?;
                current = reg.get(pointee).ok_or_else(|| {
                    format!(
                        "{}: '{step}' is ptr<{pointee}> but '{pointee}' is not in the schema registry",
                        display()
                    )
                })?;
            }
            crate::schema::layout::FieldKind::Ptr => {
                return Err(format!(
                    "{}: can't chain through opaque pointer at '{step}' (use `ptr32<T>` / `ptr64<T>` in the schema)",
                    display()
                ));
            }
            _ => {
                return Err(format!(
                    "{}: can't chain through scalar field at '{step}'",
                    display()
                ));
            }
        }
    }
    Ok(())
}

/// Recognize `binding.field(.field)+` inside a `%[...]` block. Returns
/// `Some((binding, [field, ...]))` if the input is a non-empty sequence
/// of dot-separated identifiers with at least one dot. Anything else —
/// no dot, embedded operators, whitespace mid-ident, brackets — returns
/// `None` so the caller falls back to the expression parser.
fn try_field_path(s: &str) -> Option<(String, Vec<String>)> {
    let trimmed = s.trim();
    if !trimmed.contains('.') {
        return None;
    }
    let parts: Vec<&str> = trimmed.split('.').collect();
    let mut idents = Vec::with_capacity(parts.len());
    for p in parts {
        let t = p.trim();
        if !is_ident(t) {
            return None;
        }
        idents.push(t.to_string());
    }
    if idents.len() < 2 {
        return None;
    }
    let binding = idents.remove(0);
    Some((binding, idents))
}

/// Evaluation environment supplied by the caller (agent VEH or a test harness).
pub trait Eval {
    /// Resolve a register by name, e.g. "rax", "eip". Return `None` for
    /// unknown names so the caller can render `?`.
    fn reg(&self, name: &str) -> Option<u64>;
    /// Read pointer-width (8 bytes on x64, 4 on x86) at `addr` from the
    /// target's address space. Returns the value zero-extended to u64.
    fn read_ptr(&self, addr: u64) -> Option<u64>;
    /// Read `len` bytes from `addr`. Returns `None` on any failure
    /// (unmapped page, partial read, address overflow). Used by template
    /// `Field` parts to read scalar field bytes; the renderer interprets
    /// the bytes per `FieldKind`. Default returns `None` so existing
    /// test `Eval` impls without struct fields aren't forced to
    /// implement it; callers that want field rendering must override.
    fn read_bytes(&self, _addr: u64, _len: usize) -> Option<Vec<u8>> {
        None
    }
}

pub fn eval(expr: &Expr, ctx: &dyn Eval) -> Option<u64> {
    match expr {
        Expr::Lit(v) => Some(*v),
        Expr::Reg(name) => ctx.reg(name),
        Expr::Deref(inner) => {
            let addr = eval(inner, ctx)?;
            ctx.read_ptr(addr)
        }
        Expr::Unary(op, inner) => {
            let v = eval(inner, ctx)?;
            Some(match op {
                UnaryOp::Not => !v,
                UnaryOp::Neg => 0u64.wrapping_sub(v),
            })
        }
        Expr::Binary(op, lhs, rhs) => {
            let l = eval(lhs, ctx)?;
            let r = eval(rhs, ctx)?;
            Some(match op {
                BinOp::Add => l.wrapping_add(r),
                BinOp::Sub => l.wrapping_sub(r),
                BinOp::Mul => l.wrapping_mul(r),
                // `wrapping_shl` reduces the shift amount mod 64, so
                // `1 << 64` evaluates to 1 rather than 0 — surprising
                // for anyone reasoning in C/Intel-shift semantics, and
                // a silent default the strict-validation policy
                // forbids. Reject out-of-range shifts (≥ 64 bits, or
                // exceeding u32 entirely) by returning `None`; the
                // template renderer surfaces that as `?`, the gate
                // evaluators treat it as "predicate didn't pass" via
                // `unwrap_or(0)` — same handling as a missing register
                // or unreadable deref. `checked_shl`/`checked_shr`
                // return `None` for any shift ≥ 64.
                BinOp::Shl => l.checked_shl(r.try_into().ok()?)?,
                BinOp::Shr => l.checked_shr(r.try_into().ok()?)?,
                BinOp::BitAnd => l & r,
                BinOp::BitOr => l | r,
                BinOp::BitXor => l ^ r,
                BinOp::Eq => (l == r) as u64,
                BinOp::Ne => (l != r) as u64,
                BinOp::Lt => (l < r) as u64,
                BinOp::Le => (l <= r) as u64,
                BinOp::Gt => (l > r) as u64,
                BinOp::Ge => (l >= r) as u64,
            })
        }
    }
}

/// Render a template using `ctx` for register / memory access. Templates
/// without `Field` parts are unaffected by `bindings`; pass `&[]`.
pub fn render(parts: &[TemplatePart], bindings: &[StructBinding], ctx: &dyn Eval) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    for part in parts {
        match part {
            TemplatePart::Literal(s) => out.push_str(s),
            // `write!` to a `String` is infallible (`fmt::Write for String`
            // never returns Err), but the project's no-`unwrap` policy
            // applies even where the unwrap is provably safe — a future
            // refactor could swap the sink for something fallible, and a
            // panic here under `panic = "abort"` would kill the host.
            TemplatePart::Reg(name) => match ctx.reg(name) {
                Some(v) => { let _ = write!(out, "0x{v:x}"); }
                None => out.push('?'),
            },
            TemplatePart::Expr(e) => match eval(e, ctx) {
                Some(v) => { let _ = write!(out, "0x{v:x}"); }
                None => out.push('?'),
            },
            TemplatePart::Field { binding, path } => {
                out.push_str(&render_field(binding, path, bindings, ctx));
            }
        }
    }
    out
}

/// Walk a `binding.field.subfield` chain against the schema registry,
/// reading bytes via `ctx.read_bytes` and following typed pointers along
/// the way. Every error path returns a `<...>` marker; nothing is allowed
/// to panic (panic = abort kills the host).
fn render_field(
    binding_name: &str,
    path: &[String],
    bindings: &[StructBinding],
    ctx: &dyn Eval,
) -> String {
    if path.is_empty() {
        return "<empty path>".into();
    }
    let binding = match bindings.iter().find(|b| b.name == binding_name) {
        Some(b) => b,
        None => return format!("<unknown binding '{binding_name}'>"),
    };
    let base = match eval(&binding.expr, ctx) {
        Some(v) => v,
        None => return format!("<unreadable: {binding_name} base>"),
    };

    let reg = crate::schema::registry::lock();
    let mut current_struct = match reg.get(&binding.type_name) {
        Some(s) => s,
        None => return format!("<unknown type '{}' in registry>", binding.type_name),
    };
    let mut current_addr = base;

    let last = path.len() - 1;
    for (i, step) in path.iter().enumerate() {
        let field = match current_struct.field(step) {
            Some(f) => f,
            None => {
                return format!("<no field '{step}' in {}>", current_struct.name);
            }
        };
        let field_addr = current_addr.wrapping_add(field.offset);

        if i == last {
            return format_field_value(field, field_addr, ctx);
        }

        // Intermediate step — must be a typed pointer to chain through.
        match field.kind {
            crate::schema::layout::FieldKind::PtrTyped => {
                let bytes = match ctx.read_bytes(field_addr, field.element_size as usize) {
                    Some(b) if b.len() == field.element_size as usize => b,
                    _ => {
                        return format!(
                            "<unreadable at {binding_name}.{}>",
                            joined_so_far(path, i)
                        );
                    }
                };
                let next = bytes_to_u64_le(&bytes);
                if next == 0 {
                    return format!(
                        "<null at {binding_name}.{}>",
                        joined_so_far(path, i)
                    );
                }
                let pointee = match field.pointee.as_deref() {
                    Some(p) => p,
                    None => return "<typed pointer with no target name>".to_string(),
                };
                current_struct = match reg.get(pointee) {
                    Some(s) => s,
                    None => return format!("<missing type '{pointee}'>"),
                };
                current_addr = next;
            }
            crate::schema::layout::FieldKind::Ptr => {
                return format!(
                    "<can't chain through opaque ptr at {binding_name}.{}>",
                    joined_so_far(path, i)
                );
            }
            _ => {
                return format!(
                    "<can't chain through scalar at {binding_name}.{}>",
                    joined_so_far(path, i)
                );
            }
        }
    }
    "<empty path>".into()
}

/// Render a single field's value by `FieldKind`. Reads `field.total_size()`
/// bytes from `addr`. Arrays render as `[v0, v1, ...]` per element; scalars
/// render directly.
fn format_field_value(
    field: &crate::schema::layout::ResolvedField,
    addr: u64,
    ctx: &dyn Eval,
) -> String {
    let total = field.total_size() as usize;
    let bytes = match ctx.read_bytes(addr, total) {
        Some(b) if b.len() == total => b,
        _ => return format!("<unreadable at 0x{addr:x}>"),
    };

    if field.array_count > 1 {
        // Render element-by-element so the user sees the structure.
        let elem = field.element_size as usize;
        let mut out = String::from("[");
        for i in 0..field.array_count as usize {
            if i > 0 {
                out.push_str(", ");
            }
            let chunk = &bytes[i * elem..(i + 1) * elem];
            out.push_str(&format_one_element(field.kind, chunk));
        }
        out.push(']');
        return out;
    }

    format_one_element(field.kind, &bytes)
}

fn format_one_element(kind: crate::schema::layout::FieldKind, bytes: &[u8]) -> String {
    use crate::schema::layout::FieldKind::*;
    match kind {
        UInt => match bytes.len() {
            1 => format!("0x{:x}", bytes[0]),
            2 => format!("0x{:x}", u16_le(bytes)),
            4 => format!("0x{:x}", u32_le(bytes)),
            8 => format!("0x{:x}", u64_le(bytes)),
            n => format!("<bad uint size {n}>"),
        },
        SInt => match bytes.len() {
            1 => format!("{}", bytes[0] as i8),
            2 => format!("{}", u16_le(bytes) as i16),
            4 => format!("{}", u32_le(bytes) as i32),
            8 => format!("{}", u64_le(bytes) as i64),
            n => format!("<bad sint size {n}>"),
        },
        Float => match bytes.len() {
            4 => format!("{}", f32::from_bits(u32_le(bytes))),
            8 => format!("{}", f64::from_bits(u64_le(bytes))),
            n => format!("<bad float size {n}>"),
        },
        Bool => {
            if bytes.iter().any(|&b| b != 0) {
                "true".into()
            } else {
                "false".into()
            }
        }
        Ptr | PtrTyped => match bytes.len() {
            4 => format!("0x{:x}", u32_le(bytes)),
            8 => format!("0x{:x}", u64_le(bytes)),
            n => format!("<bad ptr size {n}>"),
        },
        Cstr => {
            // Stop at first NUL or end of buffer.
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            format!("{:?}", String::from_utf8_lossy(&bytes[..end]))
        }
        Bytes => {
            // Bytes fields are typically short (a few bytes); per-byte
            // format calls are negligible here. If a hot path ever
            // materializes, swap to a single fold with `write!`.
            bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ")
        }
    }
}

fn joined_so_far(path: &[String], up_to: usize) -> String {
    path[..=up_to].join(".")
}

fn u16_le(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
fn u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
fn u64_le(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

fn bytes_to_u64_le(b: &[u8]) -> u64 {
    match b.len() {
        4 => u32_le(b) as u64,
        8 => u64_le(b),
        _ => 0,
    }
}

// ----- Tokenizer + parser ------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Int(u64),
    Ident(String),
    LParen, RParen,
    LBracket, RBracket,
    Add, Sub, Mul,
    Shl, Shr,
    BitAnd, BitOr, BitXor,
    Tilde,
    Eq, Ne, Lt, Le, Gt, Ge,
}

fn tokenize(s: &str) -> Result<Vec<Tok>, String> {
    let mut tokens = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if c.is_ascii_digit() {
            let start = i;
            while i < bytes.len() && (bytes[i] as char).is_ascii_alphanumeric() {
                i += 1;
            }
            let lit = &s[start..i];
            let v = if let Some(hex) = lit.strip_prefix("0x").or_else(|| lit.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16).map_err(|e| format!("bad hex {lit}: {e}"))?
            } else {
                lit.parse::<u64>().map_err(|e| format!("bad int {lit}: {e}"))?
            };
            tokens.push(Tok::Int(v));
            continue;
        }
        if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < bytes.len() {
                let b = bytes[i] as char;
                if b.is_ascii_alphanumeric() || b == '_' { i += 1; } else { break; }
            }
            tokens.push(Tok::Ident(s[start..i].to_string()));
            continue;
        }
        i += 1;
        match c {
            '(' => tokens.push(Tok::LParen),
            ')' => tokens.push(Tok::RParen),
            '[' => tokens.push(Tok::LBracket),
            ']' => tokens.push(Tok::RBracket),
            '+' => tokens.push(Tok::Add),
            '-' => tokens.push(Tok::Sub),
            '*' => tokens.push(Tok::Mul),
            '~' => tokens.push(Tok::Tilde),
            '&' => tokens.push(Tok::BitAnd),
            '|' => tokens.push(Tok::BitOr),
            '^' => tokens.push(Tok::BitXor),
            '<' => match bytes.get(i).map(|&b| b as char) {
                Some('<') => { i += 1; tokens.push(Tok::Shl); }
                Some('=') => { i += 1; tokens.push(Tok::Le); }
                _ => tokens.push(Tok::Lt),
            },
            '>' => match bytes.get(i).map(|&b| b as char) {
                Some('>') => { i += 1; tokens.push(Tok::Shr); }
                Some('=') => { i += 1; tokens.push(Tok::Ge); }
                _ => tokens.push(Tok::Gt),
            },
            '=' => match bytes.get(i).map(|&b| b as char) {
                Some('=') => { i += 1; tokens.push(Tok::Eq); }
                _ => return Err("expected '==' (single '=' is not assignment)".into()),
            },
            '!' => match bytes.get(i).map(|&b| b as char) {
                Some('=') => { i += 1; tokens.push(Tok::Ne); }
                _ => return Err("bare '!' not supported; use '!=' or '~'".into()),
            },
            other => return Err(format!("unexpected char: {other:?}")),
        }
    }
    Ok(tokens)
}

impl BinOp {
    fn prec(self) -> u8 {
        match self {
            BinOp::Mul => 6,
            BinOp::Add | BinOp::Sub => 5,
            BinOp::Shl | BinOp::Shr => 4,
            BinOp::BitAnd => 3,
            BinOp::BitXor => 2,
            BinOp::BitOr => 1,
            BinOp::Eq | BinOp::Ne | BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge => 0,
        }
    }
}

/// Cap on recursive descent into `(...)` and `[...]`. Hit-time eval is also
/// recursive over the resulting AST, so the same cap bounds eval depth (the
/// VEH path runs on the faulting thread's stack, which can be small for
/// non-default-stack threads).
const MAX_PARSE_DEPTH: u32 = 32;

struct Parser {
    tokens: Vec<Tok>,
    pos: usize,
    depth: u32,
}

impl Parser {
    fn new(tokens: Vec<Tok>) -> Self { Self { tokens, pos: 0, depth: 0 } }
    fn peek(&self) -> Option<&Tok> { self.tokens.get(self.pos) }
    fn bump(&mut self) -> Option<Tok> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() { self.pos += 1; }
        t
    }

    fn expr(&mut self) -> Result<Expr, String> { self.bin(0) }

    fn bin(&mut self, min_prec: u8) -> Result<Expr, String> {
        let mut lhs = self.unary()?;
        loop {
            let op = match self.peek_op() {
                Some(op) => op,
                None => break,
            };
            if op.prec() < min_prec { break; }
            self.bump();
            let rhs = self.bin(op.prec() + 1)?;
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn peek_op(&self) -> Option<BinOp> {
        Some(match self.peek()? {
            Tok::Add => BinOp::Add,
            Tok::Sub => BinOp::Sub,
            Tok::Mul => BinOp::Mul,
            Tok::Shl => BinOp::Shl,
            Tok::Shr => BinOp::Shr,
            Tok::BitAnd => BinOp::BitAnd,
            Tok::BitOr => BinOp::BitOr,
            Tok::BitXor => BinOp::BitXor,
            Tok::Eq => BinOp::Eq,
            Tok::Ne => BinOp::Ne,
            Tok::Lt => BinOp::Lt,
            Tok::Le => BinOp::Le,
            Tok::Gt => BinOp::Gt,
            Tok::Ge => BinOp::Ge,
            _ => return None,
        })
    }

    fn unary(&mut self) -> Result<Expr, String> {
        match self.peek() {
            Some(Tok::Tilde) => { self.bump(); Ok(Expr::Unary(UnaryOp::Not, Box::new(self.unary()?))) }
            Some(Tok::Sub) => { self.bump(); Ok(Expr::Unary(UnaryOp::Neg, Box::new(self.unary()?))) }
            _ => self.atom(),
        }
    }

    fn enter(&mut self) -> Result<(), String> {
        if self.depth >= MAX_PARSE_DEPTH {
            return Err(format!("expression nests deeper than {MAX_PARSE_DEPTH}"));
        }
        self.depth += 1;
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn atom(&mut self) -> Result<Expr, String> {
        match self.bump().ok_or_else(|| "unexpected end of expression".to_string())? {
            Tok::Int(v) => Ok(Expr::Lit(v)),
            Tok::Ident(name) => Ok(Expr::Reg(name)),
            Tok::LParen => {
                self.enter()?;
                let inner = self.expr();
                self.leave();
                let inner = inner?;
                match self.bump() {
                    Some(Tok::RParen) => Ok(inner),
                    _ => Err("missing ')'".into()),
                }
            }
            Tok::LBracket => {
                self.enter()?;
                let inner = self.expr();
                self.leave();
                let inner = inner?;
                match self.bump() {
                    Some(Tok::RBracket) => Ok(Expr::Deref(Box::new(inner))),
                    _ => Err("missing ']'".into()),
                }
            }
            other => Err(format!("expected literal/register/( or [, got {other:?}")),
        }
    }
}

pub fn parse_expr(s: &str) -> Result<Expr, String> {
    let tokens = tokenize(s)?;
    let len = tokens.len();
    let mut p = Parser::new(tokens);
    let e = p.expr()?;
    if p.pos != len {
        return Err(format!("trailing tokens after expression at position {}", p.pos));
    }
    Ok(e)
}

pub fn parse_template(s: &str) -> Result<Vec<TemplatePart>, String> {
    let mut parts = Vec::new();
    let mut buf = String::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '%' {
            buf.push(chars[i]);
            i += 1;
            continue;
        }
        i += 1;
        if i >= chars.len() {
            return Err("trailing '%'".into());
        }
        if chars[i] == '%' {
            buf.push('%');
            i += 1;
            continue;
        }
        if !buf.is_empty() {
            parts.push(TemplatePart::Literal(std::mem::take(&mut buf)));
        }
        if chars[i] == '[' || chars[i] == '{' {
            let (open, close, deref) = if chars[i] == '[' {
                ('[', ']', true)
            } else {
                ('{', '}', false)
            };
            let mut depth = 1;
            let start = i + 1;
            let mut j = start;
            while j < chars.len() && depth > 0 {
                let c = chars[j];
                if c == open {
                    depth += 1;
                } else if c == close {
                    depth -= 1;
                    if depth == 0 { break; }
                }
                j += 1;
            }
            if depth != 0 {
                return Err(format!("unmatched '{open}' in template"));
            }
            let expr_str: String = chars[start..j].iter().collect();
            // Try field-access form first: `binding.field.subfield...`.
            // Only matches a pure dotted-ident path; mixed expressions
            // (any operator, whitespace inside an ident, brackets) fall
            // through to the general expression parser.
            if let Some((binding, path)) = try_field_path(&expr_str) {
                parts.push(TemplatePart::Field { binding, path });
            } else {
                let expr = parse_expr(&expr_str)?;
                let part = if deref {
                    TemplatePart::Expr(Expr::Deref(Box::new(expr)))
                } else {
                    TemplatePart::Expr(expr)
                };
                parts.push(part);
            }
            i = j + 1;
        } else if chars[i].is_ascii_alphabetic() || chars[i] == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let name: String = chars[start..i].iter().collect();
            parts.push(TemplatePart::Reg(name));
        } else {
            return Err(format!("expected register name or '[' after '%', got {:?}", chars[i]));
        }
    }
    if !buf.is_empty() {
        parts.push(TemplatePart::Literal(buf));
    }
    Ok(parts)
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::Lit(v) => write!(f, "0x{v:x}"),
            Expr::Reg(n) => write!(f, "{n}"),
            Expr::Deref(e) => write!(f, "[{e}]"),
            Expr::Unary(UnaryOp::Not, e) => write!(f, "~{e}"),
            Expr::Unary(UnaryOp::Neg, e) => write!(f, "-{e}"),
            Expr::Binary(op, l, r) => {
                let sym = match op {
                    BinOp::Add => "+", BinOp::Sub => "-", BinOp::Mul => "*",
                    BinOp::Shl => "<<", BinOp::Shr => ">>",
                    BinOp::BitAnd => "&", BinOp::BitOr => "|", BinOp::BitXor => "^",
                    BinOp::Eq => "==", BinOp::Ne => "!=",
                    BinOp::Lt => "<", BinOp::Le => "<=", BinOp::Gt => ">", BinOp::Ge => ">=",
                };
                write!(f, "({l} {sym} {r})")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCtx { regs: std::collections::HashMap<&'static str, u64> }
    impl Eval for TestCtx {
        fn reg(&self, name: &str) -> Option<u64> { self.regs.get(name).copied() }
        fn read_ptr(&self, _addr: u64) -> Option<u64> { Some(0xCAFE) }
    }

    fn ctx(regs: &[(&'static str, u64)]) -> TestCtx {
        TestCtx { regs: regs.iter().copied().collect() }
    }

    #[test]
    fn parse_and_eval_basic() {
        let e = parse_expr("ecx == 0x281").unwrap();
        let c = ctx(&[("ecx", 0x281)]);
        assert_eq!(eval(&e, &c), Some(1));
        let c2 = ctx(&[("ecx", 0x282)]);
        assert_eq!(eval(&e, &c2), Some(0));
    }

    #[test]
    fn parse_arithmetic_precedence() {
        let e = parse_expr("1 + 2 * 3").unwrap();
        let c = ctx(&[]);
        assert_eq!(eval(&e, &c), Some(7));
    }

    #[test]
    fn shift_in_range_evaluates_normally() {
        let c = ctx(&[]);
        assert_eq!(eval(&parse_expr("1 << 0").unwrap(), &c), Some(1));
        assert_eq!(eval(&parse_expr("1 << 63").unwrap(), &c), Some(1u64 << 63));
        assert_eq!(eval(&parse_expr("0xff00 >> 4").unwrap(), &c), Some(0x0ff0));
    }

    #[test]
    fn shift_out_of_range_returns_none() {
        // `wrapping_shl` would silently wrap the shift amount mod 64,
        // so `1 << 64` would yield 1 rather than 0 — surprising and
        // forbidden by the strict-validation policy. Out-of-range
        // shifts return None instead, surfacing as `?` in templates
        // and as a failed gate (`unwrap_or(0)`) in conditions.
        let c = ctx(&[]);
        assert_eq!(eval(&parse_expr("1 << 64").unwrap(), &c), None);
        assert_eq!(eval(&parse_expr("1 << 100").unwrap(), &c), None);
        assert_eq!(eval(&parse_expr("1 >> 64").unwrap(), &c), None);
        // u32::MAX + 1 — doesn't fit even before the < 64 check.
        assert_eq!(eval(&parse_expr("1 << 0x100000000").unwrap(), &c), None);
    }

    #[test]
    fn parse_deref() {
        let e = parse_expr("[ecx + 8]").unwrap();
        let c = ctx(&[("ecx", 0x1000)]);
        assert_eq!(eval(&e, &c), Some(0xCAFE));
    }

    #[test]
    fn parse_template_simple() {
        let parts = parse_template("ecx=%ecx [ecx+8]=%[ecx+8]").unwrap();
        let c = ctx(&[("ecx", 0x1000)]);
        let s = render(&parts, &[], &c);
        assert_eq!(s, "ecx=0x1000 [ecx+8]=0xcafe");
    }

    #[test]
    fn parse_template_escape() {
        let parts = parse_template("100%% done %eax").unwrap();
        let c = ctx(&[("eax", 0x42)]);
        assert_eq!(render(&parts, &[], &c), "100% done 0x42");
    }

    #[test]
    fn parse_unknown_reg_renders_question_mark() {
        let parts = parse_template("%nope").unwrap();
        let c = ctx(&[]);
        assert_eq!(render(&parts, &[], &c), "?");
    }

    #[test]
    fn parse_template_raw_expr() {
        let parts = parse_template("addr=%{ecx+8}").unwrap();
        let c = ctx(&[("ecx", 0x1000)]);
        assert_eq!(render(&parts, &[], &c), "addr=0x1008");
    }

    #[test]
    fn parse_errors() {
        assert!(parse_expr("1 + ").is_err());
        assert!(parse_expr("(1 + 2").is_err());
        assert!(parse_template("trailing %").is_err());
        assert!(parse_template("unmatched %[1 + 2").is_err());
    }

    #[test]
    fn parse_depth_limit_rejects_deep_nesting() {
        // Without a depth cap, recursive descent would blow the stack and
        // (under panic=abort) kill the host. Verify we error out instead.
        let deep = "(".repeat(MAX_PARSE_DEPTH as usize + 5)
            + "1"
            + &")".repeat(MAX_PARSE_DEPTH as usize + 5);
        assert!(parse_expr(&deep).is_err());

        // Same via templates (parse_template defers nested expr to parse_expr).
        let deep_tpl = format!("%[{}]", "[".repeat(MAX_PARSE_DEPTH as usize + 5));
        assert!(parse_template(&deep_tpl).is_err());
    }

    #[test]
    fn struct_binding_basic() {
        // `[expr]` is the dsl deref syntax — same as `--log "%[rcx]"`.
        let b = parse_struct_binding("enemy=GameEnemy@[rcx]").unwrap();
        assert_eq!(b.name, "enemy");
        assert_eq!(b.type_name, "GameEnemy");
        assert_eq!(b.expr_source, "[rcx]");
        match b.expr {
            Expr::Deref(_) => {}
            other => panic!("expected Deref, got {other:?}"),
        }
    }

    #[test]
    fn struct_binding_handles_complex_expressions() {
        // Demonstrates that `=` and `@` inside the expression don't break
        // the splitter — only the first `=` and first `@` are separators.
        let b = parse_struct_binding("p=Player@[rcx + 0x40]").unwrap();
        assert_eq!(b.name, "p");
        assert_eq!(b.type_name, "Player");
        assert_eq!(b.expr_source, "[rcx + 0x40]");
    }

    #[test]
    fn struct_binding_rejects_missing_pieces() {
        assert!(parse_struct_binding("foo").is_err());
        assert!(parse_struct_binding("foo=").is_err());
        assert!(parse_struct_binding("foo=Bar").is_err());
        assert!(parse_struct_binding("foo=Bar@").is_err());
        assert!(parse_struct_binding("=Bar@rcx").is_err());
        assert!(parse_struct_binding("foo=@rcx").is_err());
    }

    #[test]
    fn struct_binding_rejects_invalid_identifiers() {
        // Spaces and punctuation in name/type are not allowed.
        assert!(parse_struct_binding("my var=Foo@rcx").is_err());
        assert!(parse_struct_binding("v=My Type@rcx").is_err());
        assert!(parse_struct_binding("9var=Foo@rcx").is_err());
    }

    #[test]
    fn struct_binding_rejects_bad_expression() {
        // Expression is delegated to parse_expr; bad expressions surface
        // with the parser's own error message.
        assert!(parse_struct_binding("enemy=Foo@(unbalanced").is_err());
        assert!(parse_struct_binding("enemy=Foo@1 +").is_err());
    }

    // --- Field-template tests --------------------------------------------
    //
    // These tests exercise `parse_template` + `render` against a backing
    // memory map and the schema registry. Test struct names are unique
    // per test (suffixed with the test name) so parallel-running tests
    // don't collide on the global registry — `cargo test` parallelizes
    // by default and the registry is process-wide.

    use std::sync::Mutex;

    /// Test `Eval` impl with a bytes-by-address map. Reads return whatever
    /// has been pre-loaded; un-poked addresses fail like real unmapped
    /// memory would.
    struct MemCtx {
        regs: std::collections::HashMap<&'static str, u64>,
        mem: Mutex<std::collections::HashMap<u64, u8>>,
    }
    impl MemCtx {
        fn new() -> Self {
            Self {
                regs: std::collections::HashMap::new(),
                mem: Mutex::new(std::collections::HashMap::new()),
            }
        }
        fn with_reg(mut self, name: &'static str, v: u64) -> Self {
            self.regs.insert(name, v);
            self
        }
        fn poke(&self, addr: u64, bytes: &[u8]) {
            let mut m = self.mem.lock().unwrap();
            for (i, b) in bytes.iter().enumerate() {
                m.insert(addr + i as u64, *b);
            }
        }
    }
    impl Eval for MemCtx {
        fn reg(&self, name: &str) -> Option<u64> { self.regs.get(name).copied() }
        fn read_ptr(&self, addr: u64) -> Option<u64> {
            let mut buf = [0u8; 8];
            for i in 0..8 {
                buf[i] = *self.mem.lock().unwrap().get(&(addr + i as u64))?;
            }
            Some(u64::from_le_bytes(buf))
        }
        fn read_bytes(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
            let m = self.mem.lock().unwrap();
            let mut out = Vec::with_capacity(len);
            for i in 0..len {
                out.push(*m.get(&(addr + i as u64))?);
            }
            Some(out)
        }
    }

    fn load_schema(src: &str) {
        let s = crate::schema::compile(src).expect("schema compile");
        let mut reg = crate::schema::registry::lock();
        // Replace so reruns of the same test don't collide.
        reg.add(s, crate::schema::registry::ReplacePolicy::Replace).unwrap();
    }

    #[test]
    fn try_field_path_recognizes_dotted_paths() {
        assert_eq!(
            try_field_path("e.m_health"),
            Some(("e".into(), vec!["m_health".into()])),
        );
        assert_eq!(
            try_field_path("a.b.c"),
            Some(("a".into(), vec!["b".into(), "c".into()])),
        );
    }

    #[test]
    fn try_field_path_rejects_non_paths() {
        assert!(try_field_path("rcx").is_none());            // single ident, no dot
        assert!(try_field_path("[rcx]").is_none());          // brackets
        assert!(try_field_path("1 + 2").is_none());          // operators
        assert!(try_field_path("e.foo + 1").is_none());      // mixed
        assert!(try_field_path("").is_none());               // empty
        assert!(try_field_path(".foo").is_none());           // empty leading ident
        assert!(try_field_path("foo.").is_none());           // empty trailing ident
    }

    #[test]
    fn render_field_uint_scalar() {
        load_schema("struct field_test_uint size=0x10 { u32 a @0x00 u32 b @0x04 u64 c @0x08 }");
        let ctx = MemCtx::new().with_reg("rcx", 0x1000);
        // Lay out: a=0xDEAD at +0, b=0xBEEF at +4, c=0x1122334455667788 at +8
        ctx.poke(0x1000, &[0xAD, 0xDE, 0x00, 0x00,
                            0xEF, 0xBE, 0x00, 0x00,
                            0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]);

        let bindings = vec![StructBinding {
            name: "m".into(),
            type_name: "field_test_uint".into(),
            expr: parse_expr("rcx").unwrap(),
            expr_source: "rcx".into(),
        }];
        let parts = parse_template("a=%[m.a] b=%[m.b] c=%[m.c]").unwrap();
        let out = render(&parts, &bindings, &ctx);
        assert_eq!(out, "a=0xdead b=0xbeef c=0x1122334455667788");
    }

    #[test]
    fn render_field_signed_and_float() {
        load_schema(
            "struct field_test_sign size=0x10 { i32 a @0x00 f32 b @0x04 i64 c @0x08 }",
        );
        let ctx = MemCtx::new().with_reg("rcx", 0x2000);
        // a = -1, b = 3.5, c = -42
        ctx.poke(0x2000, &(-1i32).to_le_bytes());
        ctx.poke(0x2004, &(3.5f32).to_le_bytes());
        ctx.poke(0x2008, &(-42i64).to_le_bytes());

        let bindings = vec![StructBinding {
            name: "x".into(),
            type_name: "field_test_sign".into(),
            expr: parse_expr("rcx").unwrap(),
            expr_source: "rcx".into(),
        }];
        let parts = parse_template("a=%[x.a] b=%[x.b] c=%[x.c]").unwrap();
        assert_eq!(render(&parts, &bindings, &ctx), "a=-1 b=3.5 c=-42");
    }

    #[test]
    fn render_field_bool_and_ptr() {
        load_schema("struct field_test_bp size=0xC { bool32 a @0x00 ptr32 b @0x04 ptr32 c @0x08 }");
        let ctx = MemCtx::new().with_reg("rcx", 0x3000);
        ctx.poke(0x3000, &[0x01, 0x00, 0x00, 0x00,         // bool32 nonzero
                            0xCC, 0xCC, 0xCC, 0xCC,        // ptr32 = 0xCCCCCCCC
                            0x00, 0x00, 0x00, 0x00]);     // ptr32 = 0
        let bindings = vec![StructBinding {
            name: "x".into(),
            type_name: "field_test_bp".into(),
            expr: parse_expr("rcx").unwrap(),
            expr_source: "rcx".into(),
        }];
        let parts = parse_template("a=%[x.a] b=%[x.b] c=%[x.c]").unwrap();
        assert_eq!(render(&parts, &bindings, &ctx), "a=true b=0xcccccccc c=0x0");
    }

    #[test]
    fn render_field_unreadable_memory_renders_marker() {
        load_schema("struct field_test_unr size=0x4 { u32 a @0x00 }");
        let ctx = MemCtx::new().with_reg("rcx", 0x4000);
        // Don't poke — read_bytes returns None.
        let bindings = vec![StructBinding {
            name: "x".into(),
            type_name: "field_test_unr".into(),
            expr: parse_expr("rcx").unwrap(),
            expr_source: "rcx".into(),
        }];
        let parts = parse_template("a=%[x.a]").unwrap();
        let out = render(&parts, &bindings, &ctx);
        assert!(out.contains("<unreadable"), "got: {out}");
    }

    #[test]
    fn render_field_chains_typed_pointer() {
        load_schema(
            "struct field_test_chain_inner size=0x4 { u32 v @0x00 }
             struct field_test_chain_outer size=0x8 { ptr32 vt @0x00 ptr32<field_test_chain_inner> p @0x04 }",
        );
        let ctx = MemCtx::new().with_reg("rcx", 0x5000);
        // outer at 0x5000: vt junk, p = 0x6000. inner at 0x6000: v = 0xCAFE.
        ctx.poke(0x5000, &[0xAA, 0xAA, 0xAA, 0xAA,
                            0x00, 0x60, 0x00, 0x00]);
        ctx.poke(0x6000, &(0xCAFEu32).to_le_bytes());
        let bindings = vec![StructBinding {
            name: "o".into(),
            type_name: "field_test_chain_outer".into(),
            expr: parse_expr("rcx").unwrap(),
            expr_source: "rcx".into(),
        }];
        let parts = parse_template("v=%[o.p.v]").unwrap();
        assert_eq!(render(&parts, &bindings, &ctx), "v=0xcafe");
    }

    #[test]
    fn render_field_null_pointer_in_chain() {
        load_schema(
            "struct field_test_null_inner size=0x4 { u32 v @0x00 }
             struct field_test_null_outer size=0x4 { ptr32<field_test_null_inner> p @0x00 }",
        );
        let ctx = MemCtx::new().with_reg("rcx", 0x7000);
        // outer.p = 0 (null)
        ctx.poke(0x7000, &[0; 4]);
        let bindings = vec![StructBinding {
            name: "o".into(),
            type_name: "field_test_null_outer".into(),
            expr: parse_expr("rcx").unwrap(),
            expr_source: "rcx".into(),
        }];
        let parts = parse_template("v=%[o.p.v]").unwrap();
        let out = render(&parts, &bindings, &ctx);
        assert!(out.contains("<null"), "got: {out}");
    }

    #[test]
    fn render_field_array() {
        load_schema("struct field_test_arr size=0xC { u32 vals[3] @0x00 }");
        let ctx = MemCtx::new().with_reg("rcx", 0x8000);
        ctx.poke(0x8000, &[0x01, 0, 0, 0,  0x02, 0, 0, 0,  0x03, 0, 0, 0]);
        let bindings = vec![StructBinding {
            name: "a".into(),
            type_name: "field_test_arr".into(),
            expr: parse_expr("rcx").unwrap(),
            expr_source: "rcx".into(),
        }];
        let parts = parse_template("vals=%[a.vals]").unwrap();
        assert_eq!(render(&parts, &bindings, &ctx), "vals=[0x1, 0x2, 0x3]");
    }

    #[test]
    fn render_field_unknown_binding() {
        load_schema("struct field_test_uk size=0x4 { u32 v @0x00 }");
        let parts = parse_template("v=%[noSuchBinding.v]").unwrap();
        let ctx = MemCtx::new();
        let out = render(&parts, &[], &ctx);
        assert!(out.contains("<unknown binding"), "got: {out}");
    }

    #[test]
    fn render_field_unknown_field() {
        load_schema("struct field_test_uf size=0x4 { u32 v @0x00 }");
        let bindings = vec![StructBinding {
            name: "x".into(),
            type_name: "field_test_uf".into(),
            expr: parse_expr("0x9000").unwrap(),
            expr_source: "0x9000".into(),
        }];
        let parts = parse_template("v=%[x.bogus]").unwrap();
        let ctx = MemCtx::new();
        let out = render(&parts, &bindings, &ctx);
        assert!(out.contains("<no field 'bogus'"), "got: {out}");
    }

    #[test]
    fn render_field_cstr() {
        load_schema("struct field_test_cs size=0x10 { cstr[16] name @0x00 }");
        let ctx = MemCtx::new().with_reg("rcx", 0xB000);
        // "hello\0" plus padding garbage that should be ignored
        ctx.poke(0xB000, b"hello\0\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff");
        let bindings = vec![StructBinding {
            name: "x".into(),
            type_name: "field_test_cs".into(),
            expr: parse_expr("rcx").unwrap(),
            expr_source: "rcx".into(),
        }];
        let parts = parse_template("name=%[x.name]").unwrap();
        // Cstr renders via Debug formatting → quoted form.
        assert_eq!(render(&parts, &bindings, &ctx), r#"name="hello""#);
    }

    #[test]
    fn render_field_bytes() {
        load_schema("struct field_test_by size=0x4 { bytes[4] tag @0x00 }");
        let ctx = MemCtx::new().with_reg("rcx", 0xC000);
        ctx.poke(0xC000, &[0xDE, 0xAD, 0xBE, 0xEF]);
        let bindings = vec![StructBinding {
            name: "x".into(),
            type_name: "field_test_by".into(),
            expr: parse_expr("rcx").unwrap(),
            expr_source: "rcx".into(),
        }];
        let parts = parse_template("tag=%[x.tag]").unwrap();
        assert_eq!(render(&parts, &bindings, &ctx), "tag=de ad be ef");
    }

    #[test]
    fn render_field_chain_through_opaque_ptr_rejected() {
        load_schema("struct field_test_op size=0x4 { ptr32 vt @0x00 }");
        let ctx = MemCtx::new().with_reg("rcx", 0xA000);
        ctx.poke(0xA000, &[0xCC, 0xCC, 0xCC, 0xCC]);
        let bindings = vec![StructBinding {
            name: "x".into(),
            type_name: "field_test_op".into(),
            expr: parse_expr("rcx").unwrap(),
            expr_source: "rcx".into(),
        }];
        // `vt` is opaque ptr32; can't chain through it.
        let parts = parse_template("v=%[x.vt.something]").unwrap();
        let out = render(&parts, &bindings, &ctx);
        assert!(out.contains("opaque ptr"), "got: {out}");
    }

    // --- validate_field_paths tests --------------------------------------
    //
    // `validate_field_paths` requires a held `&Registry`. Tests acquire
    // the lock via `with_reg` rather than re-implementing the lock-and-
    // forward dance per test — keeps the assertions readable while
    // exercising the same code path production callers use.

    fn template_hook(s: &str) -> TemplateHook {
        TemplateHook {
            source: s.to_string(),
            parts: parse_template(s).unwrap(),
        }
    }

    fn vfp(t: &TemplateHook, bindings: &[StructBinding]) -> Result<(), String> {
        let reg = crate::schema::registry::lock();
        validate_field_paths(t, bindings, &reg)
    }

    #[test]
    fn validate_passes_clean_template() {
        load_schema("struct vfp_clean size=0x4 { u32 v @0x00 }");
        let bindings = vec![StructBinding {
            name: "e".into(),
            type_name: "vfp_clean".into(),
            expr: parse_expr("rcx").unwrap(),
            expr_source: "rcx".into(),
        }];
        let t = template_hook("v=%[e.v]");
        assert!(vfp(&t, &bindings).is_ok());
    }

    #[test]
    fn validate_passes_when_template_has_no_fields() {
        let t = template_hook("ecx=%ecx [ecx+8]=%[ecx+8]");
        assert!(vfp(&t, &[]).is_ok());
    }

    #[test]
    fn validate_rejects_unknown_binding() {
        load_schema("struct vfp_uk size=0x4 { u32 v @0x00 }");
        let t = template_hook("v=%[bogus.v]");
        let err = vfp(&t, &[]).unwrap_err();
        assert!(err.contains("unknown binding 'bogus'"), "got: {err}");
    }

    #[test]
    fn validate_rejects_unknown_type() {
        // Binding refers to a type not in the registry. (Don't load it.)
        let bindings = vec![StructBinding {
            name: "e".into(),
            type_name: "vfp_missing_type".into(),
            expr: parse_expr("rcx").unwrap(),
            expr_source: "rcx".into(),
        }];
        let t = template_hook("v=%[e.v]");
        let err = vfp(&t, &bindings).unwrap_err();
        assert!(err.contains("not in the schema registry"), "got: {err}");
    }

    #[test]
    fn validate_rejects_unknown_field() {
        load_schema("struct vfp_uf size=0x4 { u32 v @0x00 }");
        let bindings = vec![StructBinding {
            name: "e".into(),
            type_name: "vfp_uf".into(),
            expr: parse_expr("rcx").unwrap(),
            expr_source: "rcx".into(),
        }];
        let t = template_hook("v=%[e.bogus]");
        let err = vfp(&t, &bindings).unwrap_err();
        assert!(err.contains("'bogus' is not a field"), "got: {err}");
    }

    #[test]
    fn validate_rejects_chain_through_opaque_ptr() {
        load_schema("struct vfp_op size=0x4 { ptr32 vt @0x00 }");
        let bindings = vec![StructBinding {
            name: "e".into(),
            type_name: "vfp_op".into(),
            expr: parse_expr("rcx").unwrap(),
            expr_source: "rcx".into(),
        }];
        let t = template_hook("v=%[e.vt.something]");
        let err = vfp(&t, &bindings).unwrap_err();
        assert!(err.contains("opaque pointer"), "got: {err}");
    }

    #[test]
    fn validate_rejects_chain_through_scalar() {
        load_schema("struct vfp_sc size=0x4 { u32 v @0x00 }");
        let bindings = vec![StructBinding {
            name: "e".into(),
            type_name: "vfp_sc".into(),
            expr: parse_expr("rcx").unwrap(),
            expr_source: "rcx".into(),
        }];
        let t = template_hook("v=%[e.v.tail]");
        let err = vfp(&t, &bindings).unwrap_err();
        assert!(err.contains("can't chain through scalar"), "got: {err}");
    }

    #[test]
    fn validate_rejects_chain_through_typed_ptr_to_missing_type() {
        load_schema("struct vfp_dangling size=0x4 { ptr32<vfp_NoSuchTarget> p @0x00 }");
        let bindings = vec![StructBinding {
            name: "e".into(),
            type_name: "vfp_dangling".into(),
            expr: parse_expr("rcx").unwrap(),
            expr_source: "rcx".into(),
        }];
        let t = template_hook("v=%[e.p.something]");
        let err = vfp(&t, &bindings).unwrap_err();
        assert!(err.contains("vfp_NoSuchTarget"), "got: {err}");
        assert!(err.contains("not in the schema registry"), "got: {err}");
    }

    #[test]
    fn validate_passes_typed_pointer_chain_when_pointee_loaded() {
        load_schema(
            "struct vfp_inner size=0x4 { u32 v @0x00 }
             struct vfp_outer size=0x4 { ptr32<vfp_inner> p @0x00 }",
        );
        let bindings = vec![StructBinding {
            name: "e".into(),
            type_name: "vfp_outer".into(),
            expr: parse_expr("rcx").unwrap(),
            expr_source: "rcx".into(),
        }];
        let t = template_hook("v=%[e.p.v]");
        assert!(vfp(&t, &bindings).is_ok());
    }
}
