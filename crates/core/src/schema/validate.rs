//! Validation rules over a parsed `File`. Runs before any breakpoint arms.
//!
//! Per AGENTS.md: every rejection names the offending construct so the user
//! can fix it. No silent normalization, no "best-guess" recovery.

use std::collections::HashMap;

use super::ast::{File, Span, StructDef, TypeKind};

#[derive(Debug, Clone)]
pub enum ValidationError {
    /// Struct's declared `size=N` doesn't match where the last field ends.
    SizeMismatch {
        struct_name: String,
        struct_span: Span,
        size_span: Span,
        declared: u64,
        computed: u64,
    },
    /// A field starts inside another field's bytes.
    OverlappingFields {
        struct_name: String,
        a_name: String,
        a_span: Span,
        a_end: u64,
        b_name: String,
        b_span: Span,
        b_offset: u64,
    },
    /// Fields are not in ascending offset order.
    UnsortedFields {
        struct_name: String,
        a_name: String,
        a_offset: u64,
        b_name: String,
        b_span: Span,
        b_offset: u64,
    },
    /// A field's offset+size runs past the declared struct size.
    FieldExceedsStructSize {
        struct_name: String,
        field_name: String,
        field_span: Span,
        end: u64,
        struct_size: u64,
    },
    /// Two fields share the same name within one struct.
    DuplicateFieldName {
        struct_name: String,
        field_name: String,
        first_span: Span,
        second_span: Span,
    },
    /// Two structs share the same name across the loaded set.
    DuplicateStructName {
        name: String,
        first_span: Span,
        second_span: Span,
    },
    /// Array dimension or `cstr[N]` / `bytes[N]` length is zero.
    ZeroLengthArray { span: Span, kind: &'static str },
    /// Field's total byte footprint (element size × array count)
    /// exceeds the per-field cap. Caps the allocation at hit-time
    /// render — a typo'd `bytes[1000000000]`, `u32 arr[1000000]`, or
    /// `bytes[100] arr[1000000]` would otherwise allocate hundreds
    /// of MB to GB on every BP hit and OOM-abort the host under
    /// `panic = "abort"`. Applies to ALL field kinds because the
    /// allocation is element_size × array_count regardless of kind.
    FieldTooLarge {
        span: Span,
        field_name: String,
        total_bytes: u32,
        cap: u32,
    },
}

/// Per-field upper bound on `element_size × array_count`.
/// `format_field_value` allocates this many bytes per render, so a
/// typo here multiplies into a host-process allocation on every BP
/// hit. 64 KiB is generous for a path / blob / small lookup-table
/// field (Windows MAX_PATH is 260, widened paths fit in a few KB,
/// game entity arrays usually fit in tens of KB) and keeps the
/// worst case bounded — at `MAX_TRACE_BATCH` (~40K) hits queued,
/// total memory pressure stays in the MB range. Schemas with
/// genuine multi-MB blobs should split into smaller fields or
/// re-think whether render-on-every-hit is the right tool.
///
/// Cap applies to the field's TOTAL bytes (`element_size *
/// array_count`), not just `cstr.len` / `bytes.len` — `u32 arr[N]`
/// or `bytes[K] arr[N]` can both exceed the cap via the array
/// dimension alone.
pub const MAX_FIELD_LENGTH: u32 = 64 * 1024;

impl ValidationError {
    pub fn primary_span(&self) -> &Span {
        use ValidationError::*;
        match self {
            SizeMismatch { size_span, .. } => size_span,
            OverlappingFields { b_span, .. } => b_span,
            UnsortedFields { b_span, .. } => b_span,
            FieldExceedsStructSize { field_span, .. } => field_span,
            DuplicateFieldName { second_span, .. } => second_span,
            DuplicateStructName { second_span, .. } => second_span,
            ZeroLengthArray { span, .. } => span,
            FieldTooLarge { span, .. } => span,
        }
    }

    pub fn message(&self) -> String {
        use ValidationError::*;
        match self {
            SizeMismatch {
                struct_name,
                declared,
                computed,
                ..
            } => format!(
                "struct '{struct_name}': declared size 0x{declared:X} but fields end at 0x{computed:X}"
            ),
            OverlappingFields {
                struct_name,
                a_name,
                a_end,
                b_name,
                b_offset,
                ..
            } => format!(
                "struct '{struct_name}': field '{b_name}' at 0x{b_offset:X} overlaps '{a_name}' (ends at 0x{a_end:X})"
            ),
            UnsortedFields {
                struct_name,
                a_name,
                a_offset,
                b_name,
                b_offset,
                ..
            } => format!(
                "struct '{struct_name}': field '{b_name}' at 0x{b_offset:X} comes after '{a_name}' at 0x{a_offset:X} — fields must be in ascending offset order"
            ),
            FieldExceedsStructSize {
                struct_name,
                field_name,
                end,
                struct_size,
                ..
            } => format!(
                "struct '{struct_name}': field '{field_name}' ends at 0x{end:X}, past declared size 0x{struct_size:X}"
            ),
            DuplicateFieldName {
                struct_name,
                field_name,
                ..
            } => format!("struct '{struct_name}': duplicate field '{field_name}'"),
            DuplicateStructName { name, .. } => format!("duplicate struct '{name}'"),
            ZeroLengthArray { kind, .. } => format!("{kind} length must be greater than zero"),
            FieldTooLarge { field_name, total_bytes, cap, .. } => format!(
                "field '{field_name}' is {total_bytes} bytes total (element_size × array_count), \
                 exceeds the per-field cap of {cap} bytes — would allocate {total_bytes} bytes \
                 on every BP hit. Split into smaller fields or shrink the array dimension."
            ),
        }
    }
}

pub fn validate(file: &File) -> Vec<ValidationError> {
    let mut errs = Vec::new();
    let mut seen_struct: HashMap<&str, &StructDef> = HashMap::new();

    for s in &file.structs {
        if let Some(prev) = seen_struct.insert(s.name.as_str(), s) {
            errs.push(ValidationError::DuplicateStructName {
                name: s.name.clone(),
                first_span: prev.name_span.clone(),
                second_span: s.name_span.clone(),
            });
        }
        validate_struct(s, &mut errs);
    }

    errs
}

fn validate_struct(s: &StructDef, errs: &mut Vec<ValidationError>) {
    // Zero-length cstr / bytes / arrays.
    for f in &s.fields {
        if let Some(0) = f.array_len {
            errs.push(ValidationError::ZeroLengthArray {
                span: f.span.clone(),
                kind: "array",
            });
        }
        match &f.ty {
            TypeKind::Cstr { len: 0 } => errs.push(ValidationError::ZeroLengthArray {
                span: f.ty_span.clone(),
                kind: "cstr",
            }),
            TypeKind::Bytes { len: 0 } => errs.push(ValidationError::ZeroLengthArray {
                span: f.ty_span.clone(),
                kind: "bytes",
            }),
            _ => {}
        }
    }

    // Total field-size cap. Applies to ALL kinds because the hit-time
    // allocation is `element_size × array_count` regardless of kind —
    // capping `cstr.len` / `bytes.len` alone would let `bytes[K] arr[N]`
    // or `u32 arr[N]` slip through and allocate gigabytes per render.
    // Use `f.size()` (saturating multiply over u32) to avoid overflow
    // on the multiplication itself; `> MAX_FIELD_LENGTH` then catches
    // any field whose byte footprint is too large.
    for f in &s.fields {
        let total = f.size();
        if total > MAX_FIELD_LENGTH {
            errs.push(ValidationError::FieldTooLarge {
                span: f.span.clone(),
                field_name: f.name.clone(),
                total_bytes: total,
                cap: MAX_FIELD_LENGTH,
            });
        }
    }

    // Duplicate field names within struct.
    let mut name_first: HashMap<&str, &Span> = HashMap::new();
    for f in &s.fields {
        if let Some(first_span) = name_first.insert(f.name.as_str(), &f.name_span) {
            errs.push(ValidationError::DuplicateFieldName {
                struct_name: s.name.clone(),
                field_name: f.name.clone(),
                first_span: first_span.clone(),
                second_span: f.name_span.clone(),
            });
        }
    }

    // Sort and overlap checks. Compare adjacent in declared order; both
    // out-of-order and overlap surface here.
    for pair in s.fields.windows(2) {
        let a = &pair[0];
        let b = &pair[1];
        let a_size = a.size() as u64;
        let a_end = a.offset.saturating_add(a_size);
        if b.offset < a.offset {
            errs.push(ValidationError::UnsortedFields {
                struct_name: s.name.clone(),
                a_name: a.name.clone(),
                a_offset: a.offset,
                b_name: b.name.clone(),
                b_span: b.offset_span.clone(),
                b_offset: b.offset,
            });
        } else if b.offset < a_end {
            errs.push(ValidationError::OverlappingFields {
                struct_name: s.name.clone(),
                a_name: a.name.clone(),
                a_span: a.span.clone(),
                a_end,
                b_name: b.name.clone(),
                b_span: b.span.clone(),
                b_offset: b.offset,
            });
        }
    }

    // Field bounded by struct size; struct size matches last field's end.
    if let Some(last) = s.fields.last() {
        let end = last.offset.saturating_add(last.size() as u64);
        if end > s.size {
            errs.push(ValidationError::FieldExceedsStructSize {
                struct_name: s.name.clone(),
                field_name: last.name.clone(),
                field_span: last.span.clone(),
                end,
                struct_size: s.size,
            });
        } else if end != s.size {
            errs.push(ValidationError::SizeMismatch {
                struct_name: s.name.clone(),
                struct_span: s.span.clone(),
                size_span: s.size_span.clone(),
                declared: s.size,
                computed: end,
            });
        }
    } else if s.size != 0 {
        // Empty struct with non-zero declared size.
        errs.push(ValidationError::SizeMismatch {
            struct_name: s.name.clone(),
            struct_span: s.span.clone(),
            size_span: s.size_span.clone(),
            declared: s.size,
            computed: 0,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::super::parse::parse;
    use super::*;

    fn errs_for(src: &str) -> Vec<ValidationError> {
        let (file, parse_errs) = parse(src);
        assert!(parse_errs.is_empty(), "parse errors: {parse_errs:?}");
        validate(&file.expect("AST"))
    }

    #[test]
    fn clean_struct_passes() {
        let src = r#"
            struct A size=0x10 {
                u32 a @0x00
                u32 b @0x04
                u64 c @0x08
            }
        "#;
        assert!(errs_for(src).is_empty());
    }

    #[test]
    fn size_mismatch_low() {
        let errs = errs_for(
            r#"
            struct A size=0x20 {
                u32 a @0x00
            }
        "#,
        );
        assert!(matches!(errs[0], ValidationError::SizeMismatch { declared: 0x20, computed: 0x4, .. }));
    }

    #[test]
    fn field_exceeds_struct_size() {
        let errs = errs_for(
            r#"
            struct A size=0x4 {
                u64 too_big @0x00
            }
        "#,
        );
        assert!(matches!(errs[0], ValidationError::FieldExceedsStructSize { .. }));
    }

    #[test]
    fn overlapping_fields() {
        let errs = errs_for(
            r#"
            struct A size=0x8 {
                u32 a @0x00
                u32 b @0x02
            }
        "#,
        );
        assert!(matches!(errs[0], ValidationError::OverlappingFields { .. }));
    }

    #[test]
    fn unsorted_fields() {
        let errs = errs_for(
            r#"
            struct A size=0x8 {
                u32 b @0x04
                u32 a @0x00
            }
        "#,
        );
        assert!(matches!(errs[0], ValidationError::UnsortedFields { .. }));
    }

    #[test]
    fn duplicate_field_name() {
        let errs = errs_for(
            r#"
            struct A size=0x8 {
                u32 x @0x00
                u32 x @0x04
            }
        "#,
        );
        assert!(matches!(errs[0], ValidationError::DuplicateFieldName { .. }));
    }

    #[test]
    fn duplicate_struct_name() {
        let errs = errs_for(
            r#"
            struct A size=0x4 { u32 x @0x00 }
            struct A size=0x4 { u32 y @0x00 }
        "#,
        );
        assert!(matches!(errs[0], ValidationError::DuplicateStructName { .. }));
    }

    #[test]
    fn cstr_length_over_cap_rejected() {
        // 1 GiB cstr would allocate 1 GiB on every BP hit at render
        // time. Per-field cap (currently 64 KiB) blocks the typo at
        // upload time so the host doesn't OOM-abort under
        // `panic = "abort"`. Use a value that spans the cap to keep
        // the test stable across cap tweaks.
        let cap = super::MAX_FIELD_LENGTH;
        let over = cap + 1;
        let src = format!("struct A size=0x{over:X} {{ cstr[{over}] s @0x00 }}");
        let errs = errs_for(&src);
        assert!(
            errs.iter().any(|e| matches!(e, ValidationError::FieldTooLarge { .. })),
            "expected FieldTooLarge, got {errs:?}"
        );
    }

    #[test]
    fn bytes_length_over_cap_rejected() {
        let cap = super::MAX_FIELD_LENGTH;
        let over = cap + 1;
        let src = format!("struct A size=0x{over:X} {{ bytes[{over}] b @0x00 }}");
        let errs = errs_for(&src);
        assert!(
            errs.iter().any(|e| matches!(e, ValidationError::FieldTooLarge { .. })),
            "expected FieldTooLarge, got {errs:?}"
        );
    }

    #[test]
    fn array_dimension_bypass_rejected() {
        // The array_count escape hatch: a small element with a huge
        // array dimension multiplies into a giant render allocation.
        // `bytes[100] arr[1000000]` = 100 MB per render, must reject.
        // Same for `u32 arr[N]`. The cap applies to TOTAL bytes, not
        // just `cstr.len`/`bytes.len`.
        let src = "struct A size=0x5F5E100 { bytes[100] arr[1000000] @0x00 }";
        let errs = errs_for(src);
        assert!(
            errs.iter().any(|e| matches!(e, ValidationError::FieldTooLarge { .. })),
            "expected FieldTooLarge for bytes[100] arr[1000000], got {errs:?}"
        );

        // Also catches plain primitive arrays.
        let src2 = "struct B size=0x400000 { u32 arr[1048576] @0x00 }";
        let errs2 = errs_for(src2);
        assert!(
            errs2.iter().any(|e| matches!(e, ValidationError::FieldTooLarge { .. })),
            "expected FieldTooLarge for u32 arr[1048576], got {errs2:?}"
        );
    }

    #[test]
    fn field_at_cap_accepted() {
        // Boundary check: exactly the cap is allowed. Use bytes[N]
        // with N == cap so the struct size matches the cap exactly.
        let cap = super::MAX_FIELD_LENGTH;
        let src = format!("struct A size=0x{cap:X} {{ bytes[{cap}] s @0x00 }}");
        let errs = errs_for(&src);
        assert!(
            !errs.iter().any(|e| matches!(e, ValidationError::FieldTooLarge { .. })),
            "cap-sized field should pass, got {errs:?}"
        );
    }

    #[test]
    fn zero_length_array() {
        let errs = errs_for(
            r#"
            struct A size=0x0 {
                u32 a[0] @0x00
            }
        "#,
        );
        assert!(errs.iter().any(|e| matches!(e, ValidationError::ZeroLengthArray { .. })));
    }

    #[test]
    fn gaps_allowed() {
        // 0x04..0x44 is an unnamed gap; we don't reject it.
        let errs = errs_for(
            r#"
            struct A size=0x48 {
                u32 a @0x00
                u32 b @0x44
            }
        "#,
        );
        assert!(errs.is_empty());
    }
}
