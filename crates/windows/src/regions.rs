//! Memory region enumeration via VirtualQuery walk across the whole AS.

use std::mem::{size_of, MaybeUninit};

use haunt_core::RegionInfo;
use windows_sys::Win32::System::Memory::{VirtualQuery, MEMORY_BASIC_INFORMATION};

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
