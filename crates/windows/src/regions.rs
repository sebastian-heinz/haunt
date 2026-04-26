//! Memory region enumeration via VirtualQuery walk across the whole AS,
//! plus byte-pattern search restricted to committed/readable regions.

use std::mem::{size_of, MaybeUninit};

use haunt_core::RegionInfo;
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Memory::{
    VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

pub fn list() -> Vec<RegionInfo> {
    let mut out = Vec::new();
    let mut cursor: usize = 0;
    loop {
        let mut info = MaybeUninit::<MEMORY_BASIC_INFORMATION>::uninit();
        let written = unsafe {
            VirtualQuery(
                cursor as *const _,
                info.as_mut_ptr(),
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if written == 0 {
            break;
        }
        let info = unsafe { info.assume_init() };
        let base = info.BaseAddress as usize;
        let size = info.RegionSize;
        out.push(RegionInfo {
            base,
            size,
            state: info.State,
            protect: info.Protect,
            ty: info.Type,
        });
        let next = base.saturating_add(size);
        if next <= cursor {
            break;
        }
        cursor = next;
    }
    out
}

const SEARCH_CHUNK: usize = 256 * 1024;

pub fn search(
    pattern: &[Option<u8>],
    start: usize,
    end: usize,
    limit: usize,
) -> Vec<usize> {
    if pattern.is_empty() || start >= end || limit == 0 {
        return Vec::new();
    }
    let mut hits = Vec::new();
    let pat_len = pattern.len();
    // Reuse one scratch buffer across all chunks of all regions — search
    // is called per request, but a request can sweep dozens of regions.
    let max_read = SEARCH_CHUNK.saturating_add(pat_len.saturating_sub(1));
    let mut buf = vec![0u8; max_read];
    for r in list() {
        if r.state != MEM_COMMIT {
            continue;
        }
        if r.protect & (PAGE_NOACCESS | PAGE_GUARD) != 0 {
            continue;
        }
        let region_start = r.base.max(start);
        let region_end = r.base.saturating_add(r.size).min(end);
        if region_start >= region_end || region_end - region_start < pat_len {
            continue;
        }
        let mut offset = region_start;
        while offset < region_end {
            let remaining = region_end - offset;
            let read_len = max_read.min(remaining);
            let mut got: usize = 0;
            let ok = unsafe {
                ReadProcessMemory(
                    GetCurrentProcess(),
                    offset as *const _,
                    buf.as_mut_ptr() as *mut _,
                    read_len,
                    &mut got,
                )
            } != 0
                && got == read_len;
            if !ok {
                break;
            }
            let view = &buf[..read_len];
            // Tail of a region can be smaller than pat_len after the previous
            // chunk advanced by SEARCH_CHUNK — at which point no match can
            // start within this view (any candidate would have started in the
            // previous chunk's pat_len-1 overlap). Skip rather than slice OOB.
            if view.len() >= pat_len {
                let scan_end = view.len() - pat_len + 1;
                for i in 0..scan_end {
                    if matches_window(pattern, &view[i..i + pat_len]) {
                        hits.push(offset + i);
                        if hits.len() >= limit {
                            return hits;
                        }
                    }
                }
            }
            // Advance by CHUNK (not read_len) so the pat_len-1 overlap is
            // preserved in the next read — matches straddling chunk
            // boundaries get caught.
            offset = offset.saturating_add(SEARCH_CHUNK);
        }
    }
    hits
}

fn matches_window(pattern: &[Option<u8>], window: &[u8]) -> bool {
    pattern
        .iter()
        .zip(window)
        .all(|(p, b)| p.map_or(true, |v| v == *b))
}
