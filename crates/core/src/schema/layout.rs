//! Resolved layout: validated AST → runtime-ready offset table.
//!
//! Consumed at runtime by the field reader (`pkt.foo.bar` template lookups).
//! Typed-pointer resolution is lazy: we only verify the pointee struct exists
//! the first time it's needed (BP arm time), not at file load. That lets you
//! ship a partial schema where some types reference still-unmapped structs.

use std::collections::HashMap;

use super::ast::{File, TypeKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    UInt,
    SInt,
    Float,
    Bool,
    /// Opaque pointer (`ptr32` / `ptr64` with no `<T>`).
    Ptr,
    /// Typed pointer (`ptr32<T>` / `ptr64<T>`). Pointee name on the field.
    PtrTyped,
    /// Fixed-buffer NUL-terminated string.
    Cstr,
    /// Opaque blob.
    Bytes,
}

#[derive(Debug, Clone)]
pub struct ResolvedField {
    pub name: String,
    pub offset: u64,
    /// Size of one element in bytes (`u32` → 4, `cstr[16]` → 16).
    pub element_size: u32,
    /// `1` for scalar; `N` for `name[N]` array dim.
    pub array_count: u32,
    pub kind: FieldKind,
    /// Pointee struct name when `kind == PtrTyped`, else `None`.
    pub pointee: Option<String>,
}

impl ResolvedField {
    /// Total bytes the field occupies (one element × array_count).
    pub fn total_size(&self) -> u64 {
        self.element_size as u64 * self.array_count as u64
    }

    pub fn pointer_width(&self) -> Option<u8> {
        match self.kind {
            FieldKind::Ptr | FieldKind::PtrTyped => Some(self.element_size as u8),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedStruct {
    pub name: String,
    pub size: u64,
    fields: Vec<ResolvedField>,
    by_name: HashMap<String, usize>,
}

impl ResolvedStruct {
    pub fn fields(&self) -> &[ResolvedField] {
        &self.fields
    }

    pub fn field(&self, name: &str) -> Option<&ResolvedField> {
        self.by_name.get(name).map(|&i| &self.fields[i])
    }
}

#[derive(Debug, Clone, Default)]
pub struct Schema {
    structs: Vec<ResolvedStruct>,
    by_name: HashMap<String, usize>,
}

impl Schema {
    pub fn structs(&self) -> &[ResolvedStruct] {
        &self.structs
    }

    pub fn get(&self, name: &str) -> Option<&ResolvedStruct> {
        self.by_name.get(name).map(|&i| &self.structs[i])
    }

    /// Walk the schema once, returning every typed-pointer reference whose
    /// target struct is missing. Empty result means the schema is closed
    /// under typed-pointer resolution.
    pub fn missing_pointee_targets(&self) -> Vec<MissingTarget<'_>> {
        let mut out = Vec::new();
        for s in &self.structs {
            for f in &s.fields {
                if f.kind == FieldKind::PtrTyped {
                    let target = f.pointee.as_deref().unwrap_or("");
                    if !target.is_empty() && !self.by_name.contains_key(target) {
                        out.push(MissingTarget {
                            struct_name: &s.name,
                            field_name: &f.name,
                            target,
                        });
                    }
                }
            }
        }
        out
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MissingTarget<'a> {
    pub struct_name: &'a str,
    pub field_name: &'a str,
    pub target: &'a str,
}

/// Build a resolved schema from a parsed file. Caller is responsible for
/// running `validate::validate` first; this function assumes the AST is
/// well-formed (no duplicate names, no overlaps, sizes match).
pub fn resolve(file: &File) -> Schema {
    let mut structs = Vec::with_capacity(file.structs.len());
    let mut by_name = HashMap::with_capacity(file.structs.len());

    for s in &file.structs {
        let mut fields = Vec::with_capacity(s.fields.len());
        let mut field_index = HashMap::with_capacity(s.fields.len());
        for f in &s.fields {
            let (kind, element_size, pointee) = resolve_type(&f.ty);
            let array_count = f.array_len.unwrap_or(1);
            field_index.insert(f.name.clone(), fields.len());
            fields.push(ResolvedField {
                name: f.name.clone(),
                offset: f.offset,
                element_size,
                array_count,
                kind,
                pointee,
            });
        }
        let resolved = ResolvedStruct {
            name: s.name.clone(),
            size: s.size,
            fields,
            by_name: field_index,
        };
        by_name.insert(s.name.clone(), structs.len());
        structs.push(resolved);
    }

    Schema { structs, by_name }
}

fn resolve_type(t: &TypeKind) -> (FieldKind, u32, Option<String>) {
    match t {
        TypeKind::U8 => (FieldKind::UInt, 1, None),
        TypeKind::U16 => (FieldKind::UInt, 2, None),
        TypeKind::U32 => (FieldKind::UInt, 4, None),
        TypeKind::U64 => (FieldKind::UInt, 8, None),
        TypeKind::I8 => (FieldKind::SInt, 1, None),
        TypeKind::I16 => (FieldKind::SInt, 2, None),
        TypeKind::I32 => (FieldKind::SInt, 4, None),
        TypeKind::I64 => (FieldKind::SInt, 8, None),
        TypeKind::F32 => (FieldKind::Float, 4, None),
        TypeKind::F64 => (FieldKind::Float, 8, None),
        TypeKind::Bool8 => (FieldKind::Bool, 1, None),
        TypeKind::Bool32 => (FieldKind::Bool, 4, None),
        TypeKind::Ptr32 { pointee } => match pointee {
            Some(name) => (FieldKind::PtrTyped, 4, Some(name.clone())),
            None => (FieldKind::Ptr, 4, None),
        },
        TypeKind::Ptr64 { pointee } => match pointee {
            Some(name) => (FieldKind::PtrTyped, 8, Some(name.clone())),
            None => (FieldKind::Ptr, 8, None),
        },
        TypeKind::Cstr { len } => (FieldKind::Cstr, *len, None),
        TypeKind::Bytes { len } => (FieldKind::Bytes, *len, None),
    }
}

#[cfg(test)]
mod tests {
    use super::super::parse::parse;
    use super::super::validate::validate;
    use super::*;

    fn schema(src: &str) -> Schema {
        let (file, errs) = parse(src);
        assert!(errs.is_empty(), "parse errs: {errs:?}");
        let file = file.expect("AST");
        let v = validate(&file);
        assert!(v.is_empty(), "validate errs: {v:?}");
        resolve(&file)
    }

    #[test]
    fn resolves_player() {
        let s = schema(
            r#"
            struct GamePlayer size=0x54 {
                ptr32 vtable        @0x00
                ptr32 m_pGameObject @0x44
                ptr32<GameActor> m_pActor @0x48
                u32   m_entityId    @0x4C
                u32   m_pad         @0x50
            }
        "#,
        );
        let p = s.get("GamePlayer").expect("struct");
        assert_eq!(p.size, 0x54);

        let actor = p.field("m_pActor").expect("field");
        assert_eq!(actor.kind, FieldKind::PtrTyped);
        assert_eq!(actor.element_size, 4);
        assert_eq!(actor.pointee.as_deref(), Some("GameActor"));

        let eid = p.field("m_entityId").expect("field");
        assert_eq!(eid.kind, FieldKind::UInt);
        assert_eq!(eid.offset, 0x4C);
    }

    #[test]
    fn missing_pointee_target_reported() {
        let s = schema(
            r#"
            struct A size=0x4 { ptr32<B> p @0x00 }
        "#,
        );
        let missing = s.missing_pointee_targets();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].target, "B");
        assert_eq!(missing[0].field_name, "p");
    }

    #[test]
    fn closed_schema_has_no_missing() {
        let s = schema(
            r#"
            struct A size=0x4 { ptr32<B> p @0x00 }
            struct B size=0x4 { u32 v @0x00 }
        "#,
        );
        assert!(s.missing_pointee_targets().is_empty());
    }

    #[test]
    fn array_field_total_size() {
        let s = schema(
            r#"
            struct A size=0xC { u32 arr[3] @0x00 }
        "#,
        );
        let f = s.get("A").unwrap().field("arr").unwrap();
        assert_eq!(f.array_count, 3);
        assert_eq!(f.element_size, 4);
        assert_eq!(f.total_size(), 12);
    }
}
