//! chumsky parser: source text → `ast::File`.
//!
//! Comments (`# ...` to end of line) are blanked to spaces before parsing
//! so that error spans line up byte-for-byte with the original source.

use chumsky::prelude::*;

use super::ast::{FieldDef, File, Span, StructDef, TypeKind};

pub type ParseError<'a> = Rich<'a, char>;

/// Parse a `.layouts` source. Returns the AST and any errors.
///
/// The returned `File` is fully owned (every string and span is `String`/
/// `Range<usize>`), and errors are converted to `'static` at the boundary
/// via `Rich::into_owned`. The previous implementation `Box::leak`-ed the
/// cleaned source per call to satisfy chumsky's lifetime requirement —
/// fine for the CLI's single-shot `schema check`, but a slow leak in the
/// agent (every `POST /schemas` retained up to `MAX_SCHEMA_BODY` bytes
/// for the rest of the process's life). `into_owned` lets the cleaned
/// source drop normally at the end of this function.
pub fn parse(src: &str) -> (Option<File>, Vec<Rich<'static, char>>) {
    let cleaned = strip_comments(src);
    let (out, errs) = parser().parse(cleaned.as_str()).into_output_errors();
    let owned_errs = errs.into_iter().map(|e| e.into_owned()).collect();
    (out, owned_errs)
}

/// Replace every byte of `# ... \n` comments (excluding the newline) with
/// ASCII spaces. Preserves byte offsets so chumsky's spans match the
/// original source byte-for-byte — load-bearing for ariadne's caret
/// rendering at the correct columns.
///
/// Implementation note: builds a `Vec<u8>` and reuses the source bytes
/// verbatim outside comments rather than `out.push(b as char)`. The
/// previous char-cast was wrong for non-ASCII bytes: a single source
/// byte ≥ 0x80 became a multi-byte UTF-8 encoding of the codepoint with
/// that value, so 1 source byte → 2 cleaned bytes and the docstring
/// claim of "preserves byte offsets" was a lie for any non-ASCII input.
/// Real schemas are ASCII (the grammar enforces it), but a non-ASCII
/// byte in a comment would shift every subsequent span and ariadne
/// would point at the wrong column. Source is already validated UTF-8
/// upstream (`handle_schema_set` checks via `from_utf8`), so the
/// resulting `Vec<u8>` is too — `String::from_utf8` is infallible here
/// in practice, but we use the checked variant to stay panic-free.
fn strip_comments(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'#' {
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    // Source was valid UTF-8; replacing only ASCII `#`-run bytes with
    // ASCII spaces preserves UTF-8 validity. Use the checked variant
    // anyway: a panic here under `panic = "abort"` would kill the host,
    // and the cost (a single UTF-8 validation pass) is negligible.
    String::from_utf8(out).unwrap_or_else(|_| String::new())
}

fn span_of(s: SimpleSpan) -> Span {
    s.start..s.end
}

fn parser<'a>() -> impl Parser<'a, &'a str, File, extra::Err<ParseError<'a>>> {
    let ident_str = text::ascii::ident().to_slice();
    // chumsky's `text::ascii::keyword` has an `S: Borrow<I::Slice>` bound that
    // forces `'a` to outlive `'static` when combined with `try_map` returns.
    // Hand-roll a keyword: `just(s)` followed by a negative lookahead for any
    // identifier-continuation char. Same semantics, plays nicely with `'a`.
    let kw = |s: &'static str| {
        let cont = any().filter(|c: &char| c.is_ascii_alphanumeric() || *c == '_');
        just(s).then_ignore(cont.not().rewind())
    };

    let hex = just("0x")
        .ignore_then(text::digits(16).to_slice())
        .try_map(|s: &str, span: SimpleSpan| {
            u64::from_str_radix(s, 16)
                .map_err(|_| Rich::custom(span, format!("invalid hex literal '0x{s}'")))
        });

    let dec = text::digits(10).to_slice().try_map(|s: &str, span: SimpleSpan| {
        s.parse::<u32>()
            .map_err(|_| Rich::custom(span, format!("integer out of range: '{s}'")))
    });

    let bracketed_int = dec
        .padded()
        .delimited_by(just('[').padded(), just(']').padded());

    let pointee = ident_str
        .map(|s: &str| s.to_string())
        .padded()
        .delimited_by(just('<').padded(), just('>').padded());

    // ---- types ----
    let cstr_ty = kw("cstr")
        .ignore_then(bracketed_int)
        .map(|len| TypeKind::Cstr { len });
    let bytes_ty = kw("bytes")
        .ignore_then(bracketed_int)
        .map(|len| TypeKind::Bytes { len });
    let ptr32_ty = kw("ptr32")
        .ignore_then(pointee.or_not())
        .map(|pointee| TypeKind::Ptr32 { pointee });
    let ptr64_ty = kw("ptr64")
        .ignore_then(pointee.or_not())
        .map(|pointee| TypeKind::Ptr64 { pointee });

    // Bare-ident type fallback. Try after the keyword-typed forms above so
    // that `cstr` / `ptr32` / etc. don't get swallowed as primitives.
    let prim_ty = ident_str.try_map(|s: &str, span: SimpleSpan| match s {
        "u8" => Ok(TypeKind::U8),
        "u16" => Ok(TypeKind::U16),
        "u32" => Ok(TypeKind::U32),
        "u64" => Ok(TypeKind::U64),
        "i8" => Ok(TypeKind::I8),
        "i16" => Ok(TypeKind::I16),
        "i32" => Ok(TypeKind::I32),
        "i64" => Ok(TypeKind::I64),
        "f32" => Ok(TypeKind::F32),
        "f64" => Ok(TypeKind::F64),
        "bool8" => Ok(TypeKind::Bool8),
        "bool32" => Ok(TypeKind::Bool32),
        other => Err(Rich::custom(
            span,
            format!(
                "unknown type '{other}' (expected u8/u16/u32/u64, i8..i64, f32, f64, \
                 bool8, bool32, ptr32, ptr64, cstr[N], bytes[N])"
            ),
        )),
    });

    let ty = choice((cstr_ty, bytes_ty, ptr32_ty, ptr64_ty, prim_ty))
        .map_with(|t, e| (t, span_of(e.span())));

    // ---- field ----
    let name = ident_str
        .map(|s: &str| s.to_string())
        .map_with(|n, e| (n, span_of(e.span())));

    let array = bracketed_int.or_not();

    let offset = just('@')
        .padded()
        .ignore_then(hex.map_with(|v, e| (v, span_of(e.span()))));

    let field = ty
        .padded()
        .then(name.padded())
        .then(array.padded())
        .then(offset.padded())
        .map_with(
            |((((ty, ty_span), (name, name_span)), array_len), (offset, offset_span)), e| FieldDef {
                name,
                name_span,
                ty,
                ty_span,
                array_len,
                offset,
                offset_span,
                span: span_of(e.span()),
            },
        );

    // ---- struct ----
    let size_clause = kw("size")
        .padded()
        .ignore_then(just('=').padded())
        .ignore_then(hex.map_with(|v, e| (v, span_of(e.span()))));

    let header = kw("struct")
        .padded()
        .ignore_then(name.padded())
        .then(size_clause.padded());

    let body = field
        .padded()
        .repeated()
        .collect::<Vec<_>>()
        .delimited_by(just('{').padded(), just('}').padded());

    let struct_def = header
        .then(body)
        .map_with(|(((name, name_span), (size, size_span)), fields), e| StructDef {
            name,
            name_span,
            size,
            size_span,
            fields,
            span: span_of(e.span()),
        });

    struct_def
        .padded()
        .repeated()
        .collect::<Vec<_>>()
        .map(|structs| File { structs })
        .then_ignore(end())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(src: &str) -> File {
        let (out, errs) = parse(src);
        assert!(errs.is_empty(), "unexpected parse errors: {errs:?}");
        out.expect("parser returned no AST")
    }

    #[test]
    fn empty_file() {
        let f = parse_ok("");
        assert!(f.structs.is_empty());
    }

    #[test]
    fn single_struct() {
        let src = r#"
            struct GamePlayer size=0x54 {
                ptr32 vtable        @0x00
                ptr32 m_pGameObject @0x44
                u32   m_entityId    @0x4C
            }
        "#;
        let f = parse_ok(src);
        assert_eq!(f.structs.len(), 1);
        let s = &f.structs[0];
        assert_eq!(s.name, "GamePlayer");
        assert_eq!(s.size, 0x54);
        assert_eq!(s.fields.len(), 3);
        assert_eq!(s.fields[2].name, "m_entityId");
        assert_eq!(s.fields[2].offset, 0x4C);
        assert_eq!(s.fields[2].ty, TypeKind::U32);
    }

    #[test]
    fn typed_pointer() {
        let src = r#"
            struct A size=0x4 {
                ptr32<GameActor> p @0x00
            }
        "#;
        let f = parse_ok(src);
        match &f.structs[0].fields[0].ty {
            TypeKind::Ptr32 { pointee } => assert_eq!(pointee.as_deref(), Some("GameActor")),
            other => panic!("expected ptr32<GameActor>, got {other:?}"),
        }
    }

    #[test]
    fn array_dim() {
        let src = r#"
            struct A size=0xC {
                u32 arr[3] @0x00
            }
        "#;
        let f = parse_ok(src);
        assert_eq!(f.structs[0].fields[0].array_len, Some(3));
    }

    #[test]
    fn cstr_and_bytes() {
        let src = r#"
            struct A size=0x18 {
                cstr[16]  name  @0x00
                bytes[8]  blob  @0x10
            }
        "#;
        let f = parse_ok(src);
        assert_eq!(f.structs[0].fields[0].ty, TypeKind::Cstr { len: 16 });
        assert_eq!(f.structs[0].fields[1].ty, TypeKind::Bytes { len: 8 });
    }

    #[test]
    fn comments_blanked() {
        let src = r#"
            # top comment
            struct A size=0x4 {  # inline
                u32 x @0x00 # trailing
            }
        "#;
        let f = parse_ok(src);
        assert_eq!(f.structs.len(), 1);
        assert_eq!(f.structs[0].fields[0].name, "x");
    }

    #[test]
    fn strip_comments_preserves_byte_offsets_with_non_ascii() {
        // Non-ASCII bytes in a comment must not shift offsets. Previously
        // `out.push(b as char)` re-encoded each byte as a Unicode
        // codepoint, doubling the byte count for any byte ≥ 0x80 and
        // breaking ariadne span alignment for the rest of the source.
        let src = "# café\nstruct A size=0x4 { u32 x @0x00 }";
        let cleaned = super::strip_comments(src);
        assert_eq!(
            cleaned.len(),
            src.len(),
            "strip_comments must be byte-length preserving (got {} from {})",
            cleaned.len(),
            src.len(),
        );
        // The struct definition (after the comment) survives intact.
        assert!(cleaned.contains("struct A size=0x4"));
    }

    #[test]
    fn strip_comments_preserves_offsets_for_ascii() {
        // The common case — make sure the byte-buffer rewrite didn't
        // regress ASCII handling.
        let src = "struct A size=0x4 { # comment here\n  u32 x @0x00\n}\n";
        let cleaned = super::strip_comments(src);
        assert_eq!(cleaned.len(), src.len());
        // `# comment here` becomes `              ` (14 spaces).
        let comment_start = src.find('#').unwrap();
        let comment_end = src[comment_start..].find('\n').unwrap() + comment_start;
        for b in &cleaned.as_bytes()[comment_start..comment_end] {
            assert_eq!(*b, b' ');
        }
    }

    #[test]
    fn bad_type_keyword_rejected() {
        let (_out, errs) = parse(
            r#"
            struct A size=0x4 {
                widget x @0x00
            }
        "#,
        );
        assert!(!errs.is_empty(), "expected an error for unknown type 'widget'");
    }
}
