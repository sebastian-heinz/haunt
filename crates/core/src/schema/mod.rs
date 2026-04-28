//! Layout schema: parser, validator, resolved layout.
//!
//! Files describe `struct` definitions used by `--struct name=Type@expr` on
//! breakpoints. Parsing happens at CLI time; the runtime reader in the DLL
//! consumes only the resolved offset table and never sees a parser.
//!
//! Pipeline: `parse` → `validate` → `layout::resolve`. The convenience
//! [`compile`] wraps all three; on failure it returns a structured error
//! that callers render via [`diag`] for ariadne output.

pub mod ast;
pub mod diag;
pub mod layout;
pub mod parse;
pub mod registry;
pub mod validate;

pub use layout::{FieldKind, MissingTarget, ResolvedField, ResolvedStruct, Schema};

use std::io;

/// Reasons `compile` can fail. Each variant carries the diagnostics needed
/// to render a useful message via [`diag`].
#[derive(Debug)]
pub enum CompileError {
    /// Source did not parse. Errors are owned for `'static` lifetime.
    Parse(Vec<chumsky::error::Rich<'static, char>>),
    /// Source parsed but failed validation.
    Validate(Vec<validate::ValidationError>),
}

/// Parse, validate, and resolve a schema source. Returns a `Schema` ready
/// for runtime use, or `CompileError` carrying every diagnostic found.
pub fn compile(src: &str) -> Result<Schema, CompileError> {
    let (file, parse_errs) = parse::parse(src);
    if !parse_errs.is_empty() {
        return Err(CompileError::Parse(parse_errs));
    }
    let file = match file {
        Some(f) => f,
        None => return Err(CompileError::Parse(Vec::new())),
    };
    let v_errs = validate::validate(&file);
    if !v_errs.is_empty() {
        return Err(CompileError::Validate(v_errs));
    }
    Ok(layout::resolve(&file))
}

/// Render a `CompileError` to a writer using ariadne. `src_name` is the
/// label that appears at the top of each report (typically a file path).
/// `color = true` emits ANSI escapes (right for terminals); `false` emits
/// plain text (right for HTTP response bodies).
pub fn render_compile_error<W: io::Write>(
    err: &CompileError,
    src_name: &str,
    src: &str,
    color: bool,
    out: &mut W,
) -> io::Result<()> {
    match err {
        CompileError::Parse(errs) => diag::render_parse_errors(src_name, src, errs, color, out),
        CompileError::Validate(errs) => diag::render_validation_errors(src_name, src, errs, color, out),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_smoke() {
        let src = r#"
            struct GamePlayer size=0x54 {
                ptr32         vtable        @0x00
                ptr32<GameActor> m_pActor      @0x44
                ptr32         m_pEntity     @0x48
                u32           m_entityId    @0x4C
                u32           m_pad         @0x50
            }
            struct GameActor size=0x10 {
                u32 m_health @0x00
                u32 m_max    @0x04
                u64 m_pad    @0x08
            }
        "#;
        let s = compile(src).expect("compile");
        let p = s.get("GamePlayer").unwrap();
        let actor = p.field("m_pActor").unwrap();
        assert!(matches!(actor.kind, FieldKind::PtrTyped));
        assert!(s.missing_pointee_targets().is_empty());
    }

    #[test]
    fn compile_propagates_validation() {
        let src = "struct A size=0x10 { u32 a @0x00 u32 b @0x02 }";
        let err = compile(src).err().expect("should fail");
        match err {
            CompileError::Validate(errs) => assert!(!errs.is_empty()),
            other => panic!("expected Validate, got {other:?}"),
        }
    }
}
