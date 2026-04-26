//! Architecture-specific CONTEXT field accessors.
//!
//! Centralises the x64 ↔ x86 register-name and width differences so the rest of
//! the breakpoint module can treat `CONTEXT` uniformly. The haunt-core `Registers`
//! protocol is always 64-bit-wide; on x86 the R8..R15 fields are zeroed and the
//! E*X registers are zero-extended into the R*X slots.

#[cfg(target_arch = "x86_64")]
mod x64;
#[cfg(target_arch = "x86_64")]
pub use x64::*;

#[cfg(target_arch = "x86")]
mod x86;
#[cfg(target_arch = "x86")]
pub use x86::*;
