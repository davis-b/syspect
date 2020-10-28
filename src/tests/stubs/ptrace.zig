const std = @import("std");
const os = std.os;

const c = @import("../../c.zig");

pub fn ptrace(request: c_int, pid: os.pid_t, addr: var, data: var) anyerror!c_long {
    return 0;
}

fn ptraceInternal(request: c_int, pid: os.pid_t, addr: var, data: var) c_long {
    return 0;
}

pub fn syscall(pid: os.pid_t) anyerror!void {
    return;
}

pub var orig_rax: c_ulonglong = 0;
pub fn getregs(pid: os.pid_t) anyerror!c.user_regs_struct {
    var registers: c.user_regs_struct = undefined;
    inline for (std.meta.fields(c.user_regs_struct)) |f| {
        @field(registers, f.name) = 0;
    }
    registers.orig_rax = orig_rax;
    return registers;
}

pub fn setregs(pid: os.pid_t, registers: c.user_regs_struct) anyerror!void {
    return;
}
