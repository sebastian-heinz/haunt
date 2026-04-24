//! Module enumeration and export parsing. All in-process (we're injected).

use std::ffi::CStr;
use std::mem::{size_of, zeroed};

use haunt_core::{ExportInfo, ModuleInfo};
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
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
    let base = find_module_base(name)?;
    // SAFETY: the module is loaded in this process, pages are mapped.
    unsafe { parse_exports(base) }
}

fn find_module_base(name: &str) -> Option<usize> {
    // Try the fast path: GetModuleHandleA for an exact ASCII match.
    if let Ok(cstr) = std::ffi::CString::new(name) {
        let h = unsafe { GetModuleHandleA(cstr.as_ptr() as *const u8) };
        if !h.is_null() {
            return Some(h as usize);
        }
    }
    // Fall back to case-insensitive search in the module list.
    let wanted = name.to_ascii_lowercase();
    list()
        .into_iter()
        .find(|m| m.name.to_ascii_lowercase() == wanted)
        .map(|m| m.base)
}

unsafe fn parse_exports(base: usize) -> Option<Vec<ExportInfo>> {
    let dos = &*(base as *const IMAGE_DOS_HEADER);
    if dos.e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }
    let nt = &*((base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
    if nt.Signature != IMAGE_NT_SIGNATURE {
        return None;
    }
    let dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if dir.VirtualAddress == 0 || dir.Size == 0 {
        return Some(Vec::new());
    }
    let export_start = base + dir.VirtualAddress as usize;
    let export_end = export_start + dir.Size as usize;
    let export_dir = &*(export_start as *const IMAGE_EXPORT_DIRECTORY);

    let num_names = export_dir.NumberOfNames as usize;
    if num_names == 0 {
        return Some(Vec::new());
    }
    let names_rva = export_dir.AddressOfNames as usize;
    let ords_rva = export_dir.AddressOfNameOrdinals as usize;
    let funcs_rva = export_dir.AddressOfFunctions as usize;

    let names = std::slice::from_raw_parts((base + names_rva) as *const u32, num_names);
    let ordinals = std::slice::from_raw_parts((base + ords_rva) as *const u16, num_names);
    let funcs_len = export_dir.NumberOfFunctions as usize;
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
        // Forwarded export: RVA points inside the export directory.
        if func_addr >= export_start && func_addr < export_end {
            continue;
        }
        let name_ptr = (base + name_rva) as *const i8;
        let name = match CStr::from_ptr(name_ptr).to_str() {
            Ok(s) => s.to_string(),
            Err(_) => continue,
        };
        out.push(ExportInfo { name, addr: func_addr });
    }
    Some(out)
}

fn wide_to_string(w: &[u16]) -> String {
    let len = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..len])
}
