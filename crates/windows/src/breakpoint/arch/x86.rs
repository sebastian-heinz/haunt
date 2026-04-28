use haunt_core::Registers;
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;

// CONTEXT_i386 (0x10000) | DEBUG_REGISTERS_BIT (0x10)
pub const CONTEXT_DEBUG_REGISTERS: u32 = 0x0001_0010;

pub fn init_debug_context(ctx: &mut CONTEXT) {
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
}

pub fn ip(ctx: &CONTEXT) -> u64 {
    ctx.Eip as u64
}

pub fn set_ip(ctx: &mut CONTEXT, v: u64) {
    ctx.Eip = v as u32;
}

pub fn sp(ctx: &CONTEXT) -> u64 {
    ctx.Esp as u64
}

pub fn dr6(ctx: &CONTEXT) -> u64 {
    ctx.Dr6 as u64
}

pub fn clear_dr6_status(ctx: &mut CONTEXT) {
    ctx.Dr6 &= !0xFu32;
}

pub fn dr7(ctx: &CONTEXT) -> u64 {
    ctx.Dr7 as u64
}

pub fn set_dr7(ctx: &mut CONTEXT, v: u64) {
    ctx.Dr7 = v as u32;
}

pub fn set_dr_addr(ctx: &mut CONTEXT, slot: u8, addr: u64) {
    let a = addr as u32;
    match slot {
        0 => ctx.Dr0 = a,
        1 => ctx.Dr1 = a,
        2 => ctx.Dr2 = a,
        3 => ctx.Dr3 = a,
        _ => {}
    }
}

pub fn dr_addr(ctx: &CONTEXT, slot: u8) -> u64 {
    match slot {
        0 => ctx.Dr0 as u64,
        1 => ctx.Dr1 as u64,
        2 => ctx.Dr2 as u64,
        3 => ctx.Dr3 as u64,
        _ => 0,
    }
}

pub fn extract_regs(ctx: &CONTEXT) -> Registers {
    Registers {
        rax: ctx.Eax as u64, rcx: ctx.Ecx as u64, rdx: ctx.Edx as u64, rbx: ctx.Ebx as u64,
        rsp: ctx.Esp as u64, rbp: ctx.Ebp as u64, rsi: ctx.Esi as u64, rdi: ctx.Edi as u64,
        r8: 0, r9: 0, r10: 0, r11: 0,
        r12: 0, r13: 0, r14: 0, r15: 0,
        rip: ctx.Eip as u64,
        eflags: ctx.EFlags,
    }
}

pub fn apply_regs(ctx: &mut CONTEXT, r: &Registers) {
    ctx.Eax = r.rax as u32; ctx.Ecx = r.rcx as u32; ctx.Edx = r.rdx as u32; ctx.Ebx = r.rbx as u32;
    ctx.Esp = r.rsp as u32; ctx.Ebp = r.rbp as u32; ctx.Esi = r.rsi as u32; ctx.Edi = r.rdi as u32;
    ctx.Eip = r.rip as u32;
    ctx.EFlags = r.eflags;
}
