usingnamespace @cImport({
    @cInclude("sys/ptrace.h");
});

const arch = @import("std").Target.current.cpu.arch;

// Regular register type
pub const regT = switch (arch) {
    .x86_64 => c_ulonglong,
    .i386 => c_long,
    else => @compileError("Unsupported CPU architecture"),
};

// Signed register type
pub const sregT = switch (arch) {
    .x86_64 => c_longlong,
    .i386 => c_long,
    else => @compileError("Unsupported CPU architecture"),
};

pub const registers = switch (arch) {
    .x86_64 => x86_64_registers,
    // .i386 => _i386_registers,
    else => @compileError("Unsupported CPU architecture"),
};

pub const x86_64_registers = extern struct {
    r15: c_ulonglong,
    r14: c_ulonglong,
    r13: c_ulonglong,
    r12: c_ulonglong,
    rbp: c_ulonglong,
    rbx: c_ulonglong,
    r11: c_ulonglong,
    arg4: c_ulonglong, // r10
    arg6: c_ulonglong, // r9
    arg5: c_ulonglong, // r8
    result: c_ulonglong, // syscall result after execution
    rcx: c_ulonglong,
    arg3: c_ulonglong, // rdx
    arg2: c_ulonglong, // rsi
    arg1: c_ulonglong, // rdi
    syscall: c_ulonglong, // the syscall number
    rip: c_ulonglong,
    cs: c_ulonglong,
    eflags: c_ulonglong,
    rsp: c_ulonglong,
    ss: c_ulonglong,
    fs_base: c_ulonglong,
    gs_base: c_ulonglong,
    ds: c_ulonglong,
    es: c_ulonglong,
    fs: c_ulonglong,
    gs: c_ulonglong,
};

const _i386_registers = extern struct {
    arg1: c_long, // ebx
    arg2: c_long, // ecx
    arg3: c_long, // edx
    arg4: c_long, // esi
    arg5: c_long, // edi
    arg6: c_long, // ebp
    result: c_long, // syscall result after execution
    xds: c_long,
    xes: c_long,
    xfs: c_long,
    xgs: c_long,
    syscall: c_long, // the syscall number
    eip: c_long,
    xcs: c_long,
    eflags: c_long,
    esp: c_long,
    xss: c_long,
};
// .
// BACKUPS
// .

// Taken from zig-cache/o/*/cimport.zig:'user_regs_struct' after building with @cInclude("sys/user.h")
const x86_64_registers_original = extern struct {
    r15: c_ulonglong,
    r14: c_ulonglong,
    r13: c_ulonglong,
    r12: c_ulonglong,
    rbp: c_ulonglong,
    rbx: c_ulonglong,
    r11: c_ulonglong,
    r10: c_ulonglong,
    r9: c_ulonglong,
    r8: c_ulonglong,
    rax: c_ulonglong,
    rcx: c_ulonglong,
    rdx: c_ulonglong,
    rsi: c_ulonglong,
    rdi: c_ulonglong,
    orig_rax: c_ulonglong,
    rip: c_ulonglong,
    cs: c_ulonglong,
    eflags: c_ulonglong,
    rsp: c_ulonglong,
    ss: c_ulonglong,
    fs_base: c_ulonglong,
    gs_base: c_ulonglong,
    ds: c_ulonglong,
    es: c_ulonglong,
    fs: c_ulonglong,
    gs: c_ulonglong,
};

// Taken from zig-cache/o/*/cimport.zig after building with @cInclude("sys/user.h") and referencing user_regs_struct
const _i386_registers_original = extern struct {
    ebx: c_long,
    ecx: c_long,
    edx: c_long,
    esi: c_long,
    edi: c_long,
    ebp: c_long,
    eax: c_long,
    xds: c_long,
    xes: c_long,
    xfs: c_long,
    xgs: c_long,
    orig_eax: c_long,
    eip: c_long,
    xcs: c_long,
    eflags: c_long,
    esp: c_long,
    xss: c_long,
};
