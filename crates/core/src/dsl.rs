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

/// Evaluation environment supplied by the caller (agent VEH or a test harness).
pub trait Eval {
    /// Resolve a register by name, e.g. "rax", "eip". Return `None` for
    /// unknown names so the caller can render `?`.
    fn reg(&self, name: &str) -> Option<u64>;
    /// Read pointer-width (8 bytes on x64, 4 on x86) at `addr` from the
    /// target's address space. Returns the value zero-extended to u64.
    fn read_ptr(&self, addr: u64) -> Option<u64>;
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
                BinOp::Shl => l.wrapping_shl(r as u32),
                BinOp::Shr => l.wrapping_shr(r as u32),
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

pub fn render(parts: &[TemplatePart], ctx: &dyn Eval) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    for part in parts {
        match part {
            TemplatePart::Literal(s) => out.push_str(s),
            TemplatePart::Reg(name) => match ctx.reg(name) {
                Some(v) => write!(out, "0x{v:x}").unwrap(),
                None => out.push('?'),
            },
            TemplatePart::Expr(e) => match eval(e, ctx) {
                Some(v) => write!(out, "0x{v:x}").unwrap(),
                None => out.push('?'),
            },
        }
    }
    out
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
            let expr = parse_expr(&expr_str)?;
            let part = if deref {
                TemplatePart::Expr(Expr::Deref(Box::new(expr)))
            } else {
                TemplatePart::Expr(expr)
            };
            parts.push(part);
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
    fn parse_deref() {
        let e = parse_expr("[ecx + 8]").unwrap();
        let c = ctx(&[("ecx", 0x1000)]);
        assert_eq!(eval(&e, &c), Some(0xCAFE));
    }

    #[test]
    fn parse_template_simple() {
        let parts = parse_template("ecx=%ecx [ecx+8]=%[ecx+8]").unwrap();
        let c = ctx(&[("ecx", 0x1000)]);
        let s = render(&parts, &c);
        assert_eq!(s, "ecx=0x1000 [ecx+8]=0xcafe");
    }

    #[test]
    fn parse_template_escape() {
        let parts = parse_template("100%% done %eax").unwrap();
        let c = ctx(&[("eax", 0x42)]);
        assert_eq!(render(&parts, &c), "100% done 0x42");
    }

    #[test]
    fn parse_unknown_reg_renders_question_mark() {
        let parts = parse_template("%nope").unwrap();
        let c = ctx(&[]);
        assert_eq!(render(&parts, &c), "?");
    }

    #[test]
    fn parse_template_raw_expr() {
        let parts = parse_template("addr=%{ecx+8}").unwrap();
        let c = ctx(&[("ecx", 0x1000)]);
        assert_eq!(render(&parts, &c), "addr=0x1008");
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
}
