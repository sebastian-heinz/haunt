//! Process-wide registry of resolved structs.
//!
//! Flat namespace: every struct lives at the top by name. Files are pure
//! upload conduits — once parsed, the file identity is gone. Manage by
//! struct name, not by file.
//!
//! Mutation paths:
//!   - `add(schema, ReplacePolicy::Reject)` — strict; collides on overlap.
//!   - `add(schema, ReplacePolicy::Replace)` — overwrites colliding names
//!     atomically. Future: rejects when removal would orphan an active BP.
//!   - `drop(name)` — remove one struct by name.
//!   - `clear()` — wipe the registry.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, OnceLock};

use super::layout::{ResolvedStruct, Schema};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplacePolicy {
    /// Collisions reject the upload as a whole. No partial application.
    Reject,
    /// Collisions overwrite existing definitions atomically.
    Replace,
}

#[derive(Debug, Clone)]
pub struct AddOutcome {
    pub added: Vec<String>,
    pub replaced: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum RegistryError {
    /// `Reject` policy and one or more names already exist.
    NameCollision { existing: Vec<String> },
    /// `drop` / `replace` would remove a name that doesn't exist.
    NotFound { name: String },
}

#[derive(Default)]
pub struct Registry {
    structs: HashMap<String, ResolvedStruct>,
}

impl Registry {
    pub fn len(&self) -> usize {
        self.structs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.structs.is_empty()
    }

    pub fn get(&self, name: &str) -> Option<&ResolvedStruct> {
        self.structs.get(name)
    }

    /// Iterate structs in name-sorted order. Stable for `GET /schemas`.
    pub fn iter_sorted(&self) -> Vec<&ResolvedStruct> {
        let mut v: Vec<&ResolvedStruct> = self.structs.values().collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    /// Add every struct from `schema` according to `policy`. Atomic: on
    /// rejection, the registry is unchanged.
    pub fn add(&mut self, schema: Schema, policy: ReplacePolicy) -> Result<AddOutcome, RegistryError> {
        let incoming: Vec<ResolvedStruct> = schema.structs().to_vec();

        if policy == ReplacePolicy::Reject {
            let existing: Vec<String> = incoming
                .iter()
                .filter(|s| self.structs.contains_key(&s.name))
                .map(|s| s.name.clone())
                .collect();
            if !existing.is_empty() {
                return Err(RegistryError::NameCollision { existing });
            }
        }

        let mut added = Vec::new();
        let mut replaced = Vec::new();
        for s in incoming {
            if self.structs.contains_key(&s.name) {
                replaced.push(s.name.clone());
            } else {
                added.push(s.name.clone());
            }
            self.structs.insert(s.name.clone(), s);
        }
        added.sort();
        replaced.sort();
        Ok(AddOutcome { added, replaced })
    }

    pub fn remove(&mut self, name: &str) -> Result<(), RegistryError> {
        if self.structs.remove(name).is_some() {
            Ok(())
        } else {
            Err(RegistryError::NotFound {
                name: name.to_string(),
            })
        }
    }

    pub fn clear(&mut self) {
        self.structs.clear();
    }
}

/// Process-wide registry. Lazy-initialized on first access.
static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();

/// Acquire the registry lock. Returns a `MutexGuard` so callers can call
/// the `Registry` API directly without an extra hop.
pub fn lock() -> MutexGuard<'static, Registry> {
    REGISTRY
        .get_or_init(|| Mutex::new(Registry::default()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::super::compile;
    use super::*;

    fn fresh() -> Registry {
        Registry::default()
    }

    fn schema(src: &str) -> Schema {
        compile(src).expect("compile")
    }

    #[test]
    fn add_then_get() {
        let mut r = fresh();
        let s = schema("struct A size=0x4 { u32 x @0x00 }");
        let out = r.add(s, ReplacePolicy::Reject).unwrap();
        assert_eq!(out.added, vec!["A".to_string()]);
        assert!(out.replaced.is_empty());
        assert!(r.get("A").is_some());
    }

    #[test]
    fn reject_collision() {
        let mut r = fresh();
        r.add(
            schema("struct A size=0x4 { u32 x @0x00 }"),
            ReplacePolicy::Reject,
        )
        .unwrap();
        let err = r
            .add(
                schema("struct A size=0x8 { u64 y @0x00 }"),
                ReplacePolicy::Reject,
            )
            .unwrap_err();
        assert!(matches!(err, RegistryError::NameCollision { existing } if existing == vec!["A".to_string()]));
        // First version untouched.
        assert_eq!(r.get("A").unwrap().size, 0x4);
    }

    #[test]
    fn replace_overwrites() {
        let mut r = fresh();
        r.add(
            schema("struct A size=0x4 { u32 x @0x00 }"),
            ReplacePolicy::Reject,
        )
        .unwrap();
        let out = r
            .add(
                schema("struct A size=0x8 { u64 y @0x00 }"),
                ReplacePolicy::Replace,
            )
            .unwrap();
        assert!(out.added.is_empty());
        assert_eq!(out.replaced, vec!["A".to_string()]);
        assert_eq!(r.get("A").unwrap().size, 0x8);
    }

    #[test]
    fn add_is_atomic_on_collision() {
        // First registers A. Second tries to add B + A; A collides, so
        // neither A nor B should be touched.
        let mut r = fresh();
        r.add(
            schema("struct A size=0x4 { u32 x @0x00 }"),
            ReplacePolicy::Reject,
        )
        .unwrap();
        let err = r
            .add(
                schema(
                    r#"
                    struct B size=0x4 { u32 y @0x00 }
                    struct A size=0x8 { u64 z @0x00 }
                "#,
                ),
                ReplacePolicy::Reject,
            )
            .unwrap_err();
        assert!(matches!(err, RegistryError::NameCollision { .. }));
        assert_eq!(r.get("A").unwrap().size, 0x4);
        assert!(r.get("B").is_none());
    }

    #[test]
    fn drop_and_clear() {
        let mut r = fresh();
        r.add(
            schema(
                r#"
                struct A size=0x4 { u32 x @0x00 }
                struct B size=0x4 { u32 y @0x00 }
            "#,
            ),
            ReplacePolicy::Reject,
        )
        .unwrap();
        r.remove("A").unwrap();
        assert!(r.get("A").is_none());
        assert!(r.get("B").is_some());
        let err = r.remove("A").unwrap_err();
        assert!(matches!(err, RegistryError::NotFound { .. }));
        r.clear();
        assert!(r.is_empty());
    }
}
