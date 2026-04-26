//! Module enumeration and export parsing. All in-process (we're injected).

use std::mem::{size_of, zeroed};

use haunt_core::{ExportInfo, ModuleInfo};
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
// PE32 (x86) and PE32+ (x64) modules use different IMAGE_NT_HEADERS layouts —
// the OptionalHeader is shorter on x86, putting DataDirectory at a different
// offset. Pick the right one for the agent's bitness; loaded modules in this
// process always match it.
#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64 as IMAGE_NT_HEADERS;
#[cfg(target_arch = "x86")]
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32 as IMAGE_NT_HEADERS;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
use windows_sys::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE,
};
use windows_sys::Win32::System::Threading::GetCurrentProcessId;

const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;

pub fn list() -> Vec<ModuleInfo> {
    let pid = unsafe { GetCurrentProcessId() };
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid) };
    if snap == INVALID_HANDLE_VALUE {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut me: MODULEENTRY32W = unsafe { zeroed() };
    me.dwSize = size_of::<MODULEENTRY32W>() as u32;
    let mut ok = unsafe { Module32FirstW(snap, &mut me) } != 0;
    while ok {
        out.push(ModuleInfo {
            name: wide_to_string(&me.szModule),
            base: me.modBaseAddr as usize,
            size: me.modBaseSize as usize,
        });
        me.dwSize = size_of::<MODULEENTRY32W>() as u32;
        ok = unsafe { Module32NextW(snap, &mut me) } != 0;
    }
    unsafe { CloseHandle(snap) };
    out
}

pub fn exports(name: &str) -> Option<Vec<ExportInfo>> {
    let (base, size) = find_module(name)?;
    // SAFETY: the module is loaded in this process; pages within
    // [base, base+size) are mapped. We bound every pointer arithmetic
    // against `size` before dereferencing, so a forged/corrupted PE header
    // can't make us read off the end of the mapping (an AV inside
    // parse_exports would crash the host under panic=abort).
    unsafe { parse_exports(base, size) }
}

/// Look up `name` (case-insensitive) and return `(base, size)`. Used by
/// `process::resolve_symbol` to find the HMODULE to feed into
/// `GetProcAddress`. Pub(crate) because `process.rs` is the only
/// out-of-module caller.
pub(crate) fn find_module(name: &str) -> Option<(usize, usize)> {
    let wanted = name.to_ascii_lowercase();
    list()
        .into_iter()
        .find(|m| m.name.to_ascii_lowercase() == wanted)
        .map(|m| (m.base, m.size))
        .or_else(|| {
            // GetModuleHandleA fast-path returns just the base; we still
            // need a size to bounds-check exports against. Look it up via
            // the module list.
            std::ffi::CString::new(name).ok().and_then(|cstr| {
                let h = unsafe { GetModuleHandleA(cstr.as_ptr() as *const u8) };
                if h.is_null() { return None; }
                let base = h as usize;
                list().into_iter().find(|m| m.base == base).map(|m| (m.base, m.size))
            })
        })
}

unsafe fn parse_exports(base: usize, size: usize) -> Option<Vec<ExportInfo>> {
    // Reject obviously-too-small mappings before any deref.
    if size < std::mem::size_of::<IMAGE_DOS_HEADER>() {
        return None;
    }
    let dos = &*(base as *const IMAGE_DOS_HEADER);
    if dos.e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }
    let nt_off = dos.e_lfanew as usize;
    if !in_module(nt_off, std::mem::size_of::<IMAGE_NT_HEADERS>(), size) {
        return None;
    }
    let nt = &*((base + nt_off) as *const IMAGE_NT_HEADERS);
    if nt.Signature != IMAGE_NT_SIGNATURE {
        return None;
    }
    let dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if dir.VirtualAddress == 0 || dir.Size == 0 {
        return Some(Vec::new());
    }
    let export_off = dir.VirtualAddress as usize;
    let export_size = dir.Size as usize;
    if !in_module(export_off, export_size, size)
        || !in_module(export_off, std::mem::size_of::<IMAGE_EXPORT_DIRECTORY>(), size)
    {
        return None;
    }
    let export_start = base + export_off;
    let export_end = export_start + export_size;
    let export_dir = &*(export_start as *const IMAGE_EXPORT_DIRECTORY);

    let num_names = export_dir.NumberOfNames as usize;
    if num_names == 0 {
        return Some(Vec::new());
    }
    let names_rva = export_dir.AddressOfNames as usize;
    let ords_rva = export_dir.AddressOfNameOrdinals as usize;
    let funcs_rva = export_dir.AddressOfFunctions as usize;
    let funcs_len = export_dir.NumberOfFunctions as usize;
    if !in_module(names_rva, num_names.saturating_mul(4), size)
        || !in_module(ords_rva, num_names.saturating_mul(2), size)
        || !in_module(funcs_rva, funcs_len.saturating_mul(4), size)
    {
        return None;
    }

    let names = std::slice::from_raw_parts((base + names_rva) as *const u32, num_names);
    let ordinals = std::slice::from_raw_parts((base + ords_rva) as *const u16, num_names);
    let funcs = std::slice::from_raw_parts((base + funcs_rva) as *const u32, funcs_len);

    let mut out = Vec::with_capacity(num_names);
    for i in 0..num_names {
        let name_rva = names[i] as usize;
        let ord = ordinals[i] as usize;
        if ord >= funcs_len {
            continue;
        }
        let func_rva = funcs[ord] as usize;
        let func_addr = base + func_rva;
        // The name string is NUL-terminated, but we don't know how long; cap
        // at the remaining mapped bytes from name_rva so a corrupt RVA can't
        // walk us off the end of the module.
        if name_rva >= size {
            continue;
        }
        let name = match read_cstr_bounded(base + name_rva, size - name_rva) {
            Some(s) => s,
            None => continue,
        };
        // Forwarded export: the function RVA points INTO the export
        // directory at a NUL-terminated "module.symbol" string. Surface
        // these in the listing rather than dropping them — `bp set`-by-name
        // resolves them via GetProcAddress so users can still set BPs on
        // forwarded names, but seeing them in the enumeration is what
        // makes the resolution trail debuggable.
        if func_addr >= export_start && func_addr < export_end {
            let max = export_end - func_addr;
            let forward = read_cstr_bounded(func_addr, max);
            out.push(ExportInfo { name, addr: 0, forward });
        } else {
            out.push(ExportInfo { name, addr: func_addr, forward: None });
        }
    }
    Some(out)
}

fn in_module(offset: usize, length: usize, module_size: usize) -> bool {
    match offset.checked_add(length) {
        Some(end) => end <= module_size,
        None => false,
    }
}

unsafe fn read_cstr_bounded(ptr: usize, max: usize) -> Option<String> {
    let bytes = std::slice::from_raw_parts(ptr as *const u8, max);
    let nul = bytes.iter().position(|&b| b == 0)?;
    std::str::from_utf8(&bytes[..nul]).ok().map(|s| s.to_string())
}

fn wide_to_string(w: &[u16]) -> String {
    let len = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..len])
}
