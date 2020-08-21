const std = @import("std");
const os = std.os;
const warn = std.debug.warn;

const waitpid_file = @import("waitpid.zig");
const waitpid = waitpid_file.waitpid;
const WIFSTOPPED = waitpid_file.WIFSTOPPED;

const ptrace = @import("ptrace.zig");
const c = @import("c.zig");

const EventAction = enum {
    CONT,
    EXIT,
    NORMAL,
    INSPECT,
};

const ProcState = enum {
    RUNNING,
    EXECUTING_CALL,
};

const Tracee = struct {
    pid: os.pid_t,
    state: ProcState,
};

pub const TraceeMap = std.AutoHashMap(os.pid_t, Tracee);

pub fn next_event(tracee_map: *TraceeMap, pid: *os.pid_t, registers: *c.user_regs_struct) !EventAction {
    const wr = waitpid(-1, 0) catch |err| {
        if (tracee_map.count() == 0) return EventAction.EXIT;
        return EventAction.CONT;
    };

    const tracee: *Tracee = try get_or_make_tracee(tracee_map, wr.pid);
    std.debug.assert(tracee.pid == wr.pid);
    pid.* = tracee.pid;

    // Process exited normally
    if (os.WIFEXITED(wr.status)) {
        // warn("exit status: {}\n", .{os.WEXITSTATUS(wr.status)});
        _ = tracee_map.remove(tracee.pid);
        return if (tracee_map.count() == 0) .EXIT else .CONT;
    }

    // If we get stopped for a non-syscall event.
    // We want to keep our state tracking in sync with reality.
    // Thus we return early to maintain our current SYSCALL state.
    // TODO audit this code, ensure it is acting as we would like
    // Child process was stopped by the delivery of a signal
    if (WIFSTOPPED(@intCast(c_int, wr.status))) {
        const stopsig = os.WSTOPSIG(wr.status);
        if (stopsig != 133) {
            warn("[{}] status: {}  stopsig: {} {}\n", .{ wr.pid, wr.status, stopsig, stopsig & 0x80 });
            try ptrace.syscall(tracee.pid);
            return EventAction.NORMAL;
        }
    } else warn("[{}] wait no stop!\n", .{wr.pid});

    switch (tracee.state) {
        .RUNNING => {
            registers.* = try begin_syscall(tracee.pid);
            tracee.state = .EXECUTING_CALL;
            if (registers.*.orig_rax == @enumToInt(os.SYS.connect)) return EventAction.INSPECT;
        },
        .EXECUTING_CALL => {
            try end_syscall(tracee.pid);
            tracee.state = .RUNNING;
        },
    }
    return EventAction.NORMAL;
}

/// Tracee has stopped execution right before
///  executing a syscall.
fn begin_syscall(pid: os.pid_t) !c.user_regs_struct {
    // Collect syscall arguments
    const registers = try ptrace.getregs(pid);
    print_call_info(pid, registers);

    //  Tracee will now conduct the syscall
    try ptrace.syscall(pid);
    return registers;
}

fn print_call_info(pid: os.pid_t, registers: c.user_regs_struct) void {
    const call_name = @tagName(@intToEnum(os.SYS, registers.orig_rax));
    warn("[{}] {}() \n", .{ pid, call_name });
}

/// Tracee has finished its syscall
/// Collect information and resume tracee
fn end_syscall(pid: os.pid_t) !void {
    const registers = try ptrace.getregs(pid);

    warn("[{}] = {}\n", .{ pid, @intCast(c_long, registers.rax) });

    // Resume tracee
    try ptrace.syscall(pid);
}

pub fn get_or_make_tracee(tracee_map: *TraceeMap, pid: os.pid_t) !*Tracee {
    if (tracee_map.get(pid)) |kv| {
        return &kv.value;
    } else {
        const tracee = Tracee{ .pid = pid, .state = .RUNNING };
        _ = try tracee_map.put(pid, tracee);
        if (tracee_map.get(pid)) |kv| {
            return &kv.value;
        } else unreachable;
    }
    unreachable;
}
