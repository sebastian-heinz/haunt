//! AST produced by the parser. Plain data; no chumsky types leak out.

use std::ops::Range;

pub type Span = Range<usize>;

/// Width of a primitive integer / float / bool field, in bytes.
pub fn primitive_size(t: &TypeKind) -> Option<u32> {
    Some(match t {
        TypeKind::U8 | TypeKind::I8 | TypeKind::Bool8 => 1,
        TypeKind::U16 | TypeKind::I16 => 2,
        TypeKind::U32 | TypeKind::I32 | TypeKind::F32 | TypeKind::Bool32 => 4,
        TypeKind::U64 | TypeKind::I64 | TypeKind::F64 => 8,
        TypeKind::Ptr32 { .. } => 4,
        TypeKind::Ptr64 { .. } => 8,
        TypeKind::Cstr { len } | TypeKind::Bytes { len } => *len,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeKind {
    U8, U16, U32, U64,
    I8, I16, I32, I64,
    F32, F64,
    Bool8, Bool32,
    Ptr32 { pointee: Option<String> },
    Ptr64 { pointee: Option<String> },
    Cstr { len: u32 },
    Bytes { len: u32 },
}

impl TypeKind {
    pub fn pointer_width(&self) -> Option<u8> {
        match self {
            TypeKind::Ptr32 { .. } => Some(4),
            TypeKind::Ptr64 { .. } => Some(8),
            _ => None,
        }
    }

    pub fn pointee(&self) -> Option<&str> {
        match self {
            TypeKind::Ptr32 { pointee } | TypeKind::Ptr64 { pointee } => pointee.as_deref(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FieldDef {
    pub name: String,
    pub name_span: Span,
    pub ty: TypeKind,
    pub ty_span: Span,
    /// Field-level `[N]` array dimension (`u32 m_arr[3]`). `None` if scalar.
    /// Disjoint from the type-internal length on `cstr[N]` / `bytes[N]`.
    pub array_len: Option<u32>,
    pub offset: u64,
    pub offset_span: Span,
    /// Whole field span: type through offset.
    pub span: Span,
}

impl FieldDef {
    /// Total bytes this field occupies, accounting for `array_len`.
    pub fn size(&self) -> u32 {
        let one = primitive_size(&self.ty).unwrap_or(0);
        one.saturating_mul(self.array_len.unwrap_or(1))
    }
}

#[derive(Debug, Clone)]
pub struct StructDef {
    pub name: String,
    pub name_span: Span,
    pub size: u64,
    pub size_span: Span,
    pub fields: Vec<FieldDef>,
    pub span: Span,
}

#[derive(Debug, Clone, Default)]
pub struct File {
    pub structs: Vec<StructDef>,
}
