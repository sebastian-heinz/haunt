//! Panic-free typed reads for VEH-path field accesses.
//!
//! Hit-time field reads (`pkt.foo.m_health`) walk addresses derived from
//! live registers and follow user-supplied pointer chains. Any of those
//! steps may target an unmapped page, a freed object, or a misaligned
//! address. Per AGENTS.md (`panic = "abort"` in the host's address space),
//! a single panic kills the host, so these reads MUST fail soft.
//!
//! Implementation: `ReadProcessMemory` against the current process. The
//! kernel does the AV-safe copy on our behalf, returns `false` on any
//! fault, and never raises a structured exception in user mode. Slower
//! than a raw `read_volatile` (one kernel transition per call) but
//! correct without SEH/longjmp tricks that don't compose with Rust's
//! `panic = "abort"` runtime.
//!
//! All multi-byte typed helpers assume little-endian, matching every
//! Windows target haunt supports (x86, x64, ARM64).
//!
//! `read_into` and `read_ptr` are wired into the `HitEvalCtx` field
//! reader; the typed scalar helpers (`read_u8` / `read_u32_le` / ...)
//! aren't called yet — the dsl renderer reads bytes via `read_into`
//! and interprets them itself for one consistent code path. Suppress
//! their dead-code warnings; they're cheap to keep and natural for
//! future direct callers.

#![allow(dead_code)]

use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Threading::GetCurrentProcess;

/// Read `out.len()` bytes from `addr`. Returns `true` on a full read; on
/// any failure (unmapped page, partial read, address overflow), returns
/// `false` and the buffer's contents are unspecified.
///
/// Empty `out` short-circuits to `true` without a syscall.
pub fn read_into(addr: usize, out: &mut [u8]) -> bool {
    if out.is_empty() {
        return true;
    }
    if addr.checked_add(out.len()).is_none() {
        return false;
    }
    let mut read: usize = 0;
    let ok = unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            addr as *const _,
            out.as_mut_ptr() as *mut _,
            out.len(),
            &mut read,
        ) != 0
    };
    ok && read == out.len()
}

/// Read exactly `N` bytes into a fixed-width array. The hot path for the
/// typed helpers below; one stack-allocated buffer, no `Vec`.
pub fn read_array<const N: usize>(addr: usize) -> Option<[u8; N]> {
    let mut buf = [0u8; N];
    if read_into(addr, &mut buf) {
        Some(buf)
    } else {
        None
    }
}

/// Pointer-width dereference. `width` must be 4 or 8; any other value
/// returns `None` instead of silently picking a default.
pub fn read_ptr(addr: usize, width: u8) -> Option<usize> {
    match width {
        4 => read_u32_le(addr).map(|v| v as usize),
        8 => read_u64_le(addr).map(|v| v as usize),
        _ => None,
    }
}

#[inline]
pub fn read_u8(addr: usize) -> Option<u8> {
    read_array::<1>(addr).map(|b| b[0])
}

#[inline]
pub fn read_u16_le(addr: usize) -> Option<u16> {
    read_array::<2>(addr).map(u16::from_le_bytes)
}

#[inline]
pub fn read_u32_le(addr: usize) -> Option<u32> {
    read_array::<4>(addr).map(u32::from_le_bytes)
}

#[inline]
pub fn read_u64_le(addr: usize) -> Option<u64> {
    read_array::<8>(addr).map(u64::from_le_bytes)
}

#[inline]
pub fn read_i8(addr: usize) -> Option<i8> {
    read_u8(addr).map(|v| v as i8)
}

#[inline]
pub fn read_i16_le(addr: usize) -> Option<i16> {
    read_array::<2>(addr).map(i16::from_le_bytes)
}

#[inline]
pub fn read_i32_le(addr: usize) -> Option<i32> {
    read_array::<4>(addr).map(i32::from_le_bytes)
}

#[inline]
pub fn read_i64_le(addr: usize) -> Option<i64> {
    read_array::<8>(addr).map(i64::from_le_bytes)
}

#[inline]
pub fn read_f32_le(addr: usize) -> Option<f32> {
    read_array::<4>(addr).map(f32::from_le_bytes)
}

#[inline]
pub fn read_f64_le(addr: usize) -> Option<f64> {
    read_array::<8>(addr).map(f64::from_le_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-test confirming the primitive returns `None` on a wildly
    /// invalid address rather than panicking. Pages near 0 and the very
    /// top of the address space are never mapped on Windows.
    #[test]
    fn null_and_kernel_addresses_fail_safely() {
        assert_eq!(read_u32_le(0x0), None);
        assert_eq!(read_u32_le(0x1), None);
        assert_eq!(read_ptr(0x0, 8), None);
        assert_eq!(read_ptr(0x0, 4), None);
        // Some bits set in the high half of the address — kernel space on
        // x64, never mapped to user-mode.
        assert_eq!(read_u64_le(0xFFFF_FFFF_FFFF_FFF8), None);
    }

    #[test]
    fn invalid_pointer_width_rejected() {
        assert_eq!(read_ptr(0x1000, 0), None);
        assert_eq!(read_ptr(0x1000, 1), None);
        assert_eq!(read_ptr(0x1000, 2), None);
        assert_eq!(read_ptr(0x1000, 16), None);
    }

    /// A read against our own stack should succeed — proves the primitive
    /// returns `Some` for legitimately mapped memory.
    #[test]
    fn reads_own_stack() {
        let local: u32 = 0xDEADBEEF;
        let addr = (&local as *const u32) as usize;
        assert_eq!(read_u32_le(addr), Some(0xDEADBEEF));
    }

    #[test]
    fn reads_own_heap() {
        let buf: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let addr = buf.as_ptr() as usize;
        assert_eq!(read_u64_le(addr), Some(0x0807060504030201));
        let arr = read_array::<4>(addr).unwrap();
        assert_eq!(arr, [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn empty_read_short_circuits() {
        let mut empty: [u8; 0] = [];
        assert!(read_into(0xDEAD_BEEF, &mut empty));
    }

    #[test]
    fn address_overflow_rejected() {
        let mut buf = [0u8; 8];
        assert!(!read_into(usize::MAX - 4, &mut buf));
    }

    #[test]
    fn signed_helpers() {
        let v: i32 = -42;
        let addr = (&v as *const i32) as usize;
        assert_eq!(read_i32_le(addr), Some(-42));
    }

    #[test]
    fn float_helpers() {
        let v: f32 = 3.5;
        let addr = (&v as *const f32) as usize;
        assert_eq!(read_f32_le(addr), Some(3.5));
    }
}
