const std = @import("std");
const os = std.os;

const c = @import("c.zig");

pub const Event = extern enum {
    clone = c.PTRACE_EVENT_CLONE,
    exec = c.PTRACE_EVENT_EXEC,
    exit = c.PTRACE_EVENT_EXIT,
    fork = c.PTRACE_EVENT_FORK,
    vfork = c.PTRACE_EVENT_VFORK,
    vfork_done = c.PTRACE_EVENT_VFORK_DONE,
    seccomp = c.PTRACE_EVENT_SECCOMP,
};

pub fn ptrace(request: c_int, pid: os.pid_t, addr: var, data: var) !c_long {
    const result = ptraceInternal(request, pid, addr, data);
    if (result == -1) {
        const err = os.errno(result);
        try processErrorNumber(err);
    }
    return result;
}

fn ptraceInternal(request: c_int, pid: os.pid_t, addr: var, data: var) c_long {
    const needs_addr_type: bool = @TypeOf(addr) == comptime_int;
    const needs_data_type: bool = @TypeOf(data) == comptime_int;
    const request_enum = @intToEnum(c.enum___ptrace_request, request);

    const new_addr = if (needs_addr_type) @as(c_int, addr) else addr;
    const new_data = if (needs_data_type) @as(c_int, data) else data;
    return c.ptrace(request_enum, pid, new_addr, new_data);
}

fn processErrorNumber(err: u16) !void {
    switch (err) {
        os.ESRCH => return error.NoSuchProcess,
        else => {
            std.debug.warn("Error number \"{}\"; ", .{err});
            std.debug.warn("Unknown error\n", .{});
            return error.UnknownError;
        },
    }
}

pub fn syscall(pid: os.pid_t) !void {
    _ = try ptrace(c.PTRACE_SYSCALL, pid, 0, 0);
}

pub fn getregs(pid: os.pid_t) !c.user_regs_struct {
    var registers: c.user_regs_struct = undefined;
    _ = try ptrace(c.PTRACE_GETREGS, pid, 0, &registers);
    return registers;
}

pub fn setregs(pid: os.pid_t, registers: c.user_regs_struct) !void {
    _ = try ptrace(c.PTRACE_SETREGS, pid, 0, &registers);
}
