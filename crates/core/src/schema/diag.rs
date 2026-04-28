//! Render parse and validation errors via ariadne. CLI-only — never invoked
//! inside the host process.

use std::io::{self, Write};

use ariadne::{Color, Config, Label, Report, ReportKind, Source};
use chumsky::error::Rich;

use super::ast::Span;
use super::validate::ValidationError;

/// Source identifier used in ariadne reports. Anything `Display + Clone`
/// works; we use `&str` so the file path printed at the top of each report
/// matches what the user passed on the command line.
pub type SrcId<'a> = &'a str;

fn config(color: bool) -> Config {
    Config::new().with_color(color)
}

pub fn render_parse_errors<W: Write>(
    src_name: &str,
    src: &str,
    errs: &[Rich<'_, char>],
    color: bool,
    out: &mut W,
) -> io::Result<()> {
    for e in errs {
        let span = e.span();
        let range = span.start..span.end;
        let mut report =
            Report::<(SrcId, std::ops::Range<usize>)>::build(ReportKind::Error, (src_name, range.clone()))
                .with_config(config(color))
                .with_message(e.to_string());

        let label_msg = e.reason().to_string();
        report = report.with_label(
            Label::new((src_name, range))
                .with_message(label_msg)
                .with_color(Color::Red),
        );

        for ctx in e.contexts() {
            let cspan = ctx.1;
            report = report.with_label(
                Label::new((src_name, cspan.start..cspan.end))
                    .with_message(format!("while parsing {}", ctx.0))
                    .with_color(Color::Blue),
            );
        }

        report
            .finish()
            .write((src_name, Source::from(src)), &mut *out)?;
    }
    Ok(())
}

pub fn render_validation_errors<W: Write>(
    src_name: &str,
    src: &str,
    errs: &[ValidationError],
    color: bool,
    out: &mut W,
) -> io::Result<()> {
    for e in errs {
        let primary = e.primary_span().clone();
        let mut report = Report::<(SrcId, std::ops::Range<usize>)>::build(
            ReportKind::Error,
            (src_name, primary.clone()),
        )
        .with_config(config(color))
        .with_message(e.message());

        report = report.with_label(
            Label::new((src_name, primary))
                .with_message(label_for(e))
                .with_color(Color::Red),
        );

        // Add a secondary label pointing at the related construct, when one
        // exists. Helps the user see *both* halves of a duplicate / overlap.
        if let Some((span, msg)) = secondary_label(e) {
            report = report.with_label(
                Label::new((src_name, span))
                    .with_message(msg)
                    .with_color(Color::Yellow),
            );
        }

        report
            .finish()
            .write((src_name, Source::from(src)), &mut *out)?;
    }
    Ok(())
}

fn label_for(e: &ValidationError) -> String {
    use ValidationError::*;
    match e {
        SizeMismatch { computed, declared, .. } => {
            format!("fields end at 0x{computed:X}, but size is 0x{declared:X}")
        }
        OverlappingFields { b_offset, .. } => {
            format!("this field at 0x{b_offset:X} overlaps the previous one")
        }
        UnsortedFields { b_offset, a_offset, .. } => {
            format!("0x{b_offset:X} is before previous field's offset 0x{a_offset:X}")
        }
        FieldExceedsStructSize { end, struct_size, .. } => {
            format!("ends at 0x{end:X}, past struct size 0x{struct_size:X}")
        }
        DuplicateFieldName { field_name, .. } => format!("'{field_name}' already used"),
        DuplicateStructName { name, .. } => format!("'{name}' already defined"),
        ZeroLengthArray { kind, .. } => format!("{kind} length cannot be zero"),
        FieldTooLarge { total_bytes, cap, .. } => {
            format!("{total_bytes} bytes total, exceeds cap of {cap}")
        }
    }
}

fn secondary_label(e: &ValidationError) -> Option<(Span, String)> {
    use ValidationError::*;
    match e {
        OverlappingFields { a_span, a_name, a_end, .. } => Some((
            a_span.clone(),
            format!("'{a_name}' ends at 0x{a_end:X}"),
        )),
        DuplicateFieldName { first_span, .. } => {
            Some((first_span.clone(), "first defined here".to_string()))
        }
        DuplicateStructName { first_span, .. } => {
            Some((first_span.clone(), "first defined here".to_string()))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::super::parse::parse;
    use super::super::validate::validate;
    use super::*;

    #[test]
    fn render_validation_errors_smoke() {
        let src = "struct A size=0x10 { u32 a @0x00 u32 b @0x02 }";
        let (file, _) = parse(src);
        let errs = validate(&file.unwrap());
        let mut buf: Vec<u8> = Vec::new();
        render_validation_errors("test.layouts", src, &errs, false, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        // ariadne writes ANSI but the message text should still appear.
        assert!(s.contains("overlaps"), "expected overlap report, got:\n{s}");
    }

    #[test]
    fn render_parse_errors_smoke() {
        let src = "struct A size=0x4 { widget x @0x00 }";
        let (_file, errs) = parse(src);
        assert!(!errs.is_empty());
        let mut buf: Vec<u8> = Vec::new();
        render_parse_errors("test.layouts", src, &errs, false, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("widget") || s.contains("unknown type"));
    }
}
