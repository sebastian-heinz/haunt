use haunt_core::Registers;
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;

// CONTEXT_AMD64 (0x100000) | DEBUG_REGISTERS_BIT (0x10)
pub const CONTEXT_DEBUG_REGISTERS: u32 = 0x0010_0010;

pub fn init_debug_context(ctx: &mut CONTEXT) {
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
}

pub fn ip(ctx: &CONTEXT) -> u64 {
    ctx.Rip
}

pub fn set_ip(ctx: &mut CONTEXT, v: u64) {
    ctx.Rip = v;
}

pub fn sp(ctx: &CONTEXT) -> u64 {
    ctx.Rsp
}

pub fn dr6(ctx: &CONTEXT) -> u64 {
    ctx.Dr6
}

pub fn clear_dr6_status(ctx: &mut CONTEXT) {
    ctx.Dr6 &= !0xFu64;
}

pub fn dr7(ctx: &CONTEXT) -> u64 {
    ctx.Dr7
}

pub fn set_dr7(ctx: &mut CONTEXT, v: u64) {
    ctx.Dr7 = v;
}

pub fn set_dr_addr(ctx: &mut CONTEXT, slot: u8, addr: u64) {
    match slot {
        0 => ctx.Dr0 = addr,
        1 => ctx.Dr1 = addr,
        2 => ctx.Dr2 = addr,
        3 => ctx.Dr3 = addr,
        _ => {}
    }
}

pub fn extract_regs(ctx: &CONTEXT) -> Registers {
    Registers {
        rax: ctx.Rax, rcx: ctx.Rcx, rdx: ctx.Rdx, rbx: ctx.Rbx,
        rsp: ctx.Rsp, rbp: ctx.Rbp, rsi: ctx.Rsi, rdi: ctx.Rdi,
        r8: ctx.R8, r9: ctx.R9, r10: ctx.R10, r11: ctx.R11,
        r12: ctx.R12, r13: ctx.R13, r14: ctx.R14, r15: ctx.R15,
        rip: ctx.Rip,
        eflags: ctx.EFlags,
    }
}

pub fn apply_regs(ctx: &mut CONTEXT, r: &Registers) {
    ctx.Rax = r.rax; ctx.Rcx = r.rcx; ctx.Rdx = r.rdx; ctx.Rbx = r.rbx;
    ctx.Rsp = r.rsp; ctx.Rbp = r.rbp; ctx.Rsi = r.rsi; ctx.Rdi = r.rdi;
    ctx.R8 = r.r8; ctx.R9 = r.r9; ctx.R10 = r.r10; ctx.R11 = r.r11;
    ctx.R12 = r.r12; ctx.R13 = r.r13; ctx.R14 = r.r14; ctx.R15 = r.r15;
    ctx.Rip = r.rip;
    ctx.EFlags = r.eflags;
}
