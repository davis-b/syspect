const std = @import("std");
const os = std.os;
const warn = std.debug.warn;

const waitpid_file = @import("waitpid.zig");
const waitpid = waitpid_file.waitpid;
const WIFSTOPPED = waitpid_file.WIFSTOPPED;

const ptrace = @import("ptrace.zig");
const c = @import("c.zig");

const ProcState = enum {
    RUNNING,
    EXECUTING_CALL,
};

const Tracee = struct {
    pid: os.pid_t,
    state: ProcState,
};

pub const EventAction = enum {
    CONT,
    EXIT,
    INSPECT,
};

/// Used to encapsulate and share information to
///  the caller of next_event.
pub const Context = struct {
    pid: os.pid_t,
    registers: c.user_regs_struct,
};

pub const TraceeMap = std.AutoHashMap(os.pid_t, Tracee);

pub const Inspections = struct {
    /// If inverse is true, any syscalls outside of .calls will be inspected
    /// Inverse turns .calls into a do-not-inspect list.
    inverse: bool = false,
    /// Syscalls to be inspected
    calls: []const os.SYS,
};

pub fn next_event(tracee_map: *TraceeMap, ctx: *Context, inspections: Inspections) !EventAction {
    const wr = waitpid(-1, 0) catch |err| {
        if (tracee_map.count() == 0) return EventAction.EXIT;
        return EventAction.CONT;
    };

    const tracee: *Tracee = try get_or_make_tracee(tracee_map, wr.pid);
    std.debug.assert(tracee.pid == wr.pid);
    ctx.pid = tracee.pid;

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
            warn("[{}] status: {}  stopsig: {} {}\n", .{ tracee.pid, wr.status, stopsig, stopsig & 0x80 });
            try ptrace.syscall(tracee.pid);
            return EventAction.CONT;
        }
    } else warn("[{}] wait no stop!\n", .{tracee.pid});

    switch (tracee.state) {
        .RUNNING => {
            // Collect syscall arguments
            ctx.registers = try ptrace.getregs(tracee.pid);

            // "!= inverse" causes bool to flip only when inverse is true
            if (in(ctx.registers.orig_rax, inspections.calls) != inspections.inverse) {
                return EventAction.INSPECT;
            }

            try begin_syscall(tracee.pid, &ctx.registers);
            tracee.state = .EXECUTING_CALL;
        },
        .EXECUTING_CALL => {
            try end_syscall(tracee.pid);
            tracee.state = .RUNNING;
        },
    }
    return EventAction.CONT;
}

fn in(needle: c_ulonglong, haystack: []const os.SYS) bool {
    for (haystack) |hay| {
        if (needle == @enumToInt(hay)) return true;
    }
    return false;
}

// TODO replace this with @suspend and resume in next_event and caller code respectively
/// Must be called after next_event returns INSPECTION.
pub fn resume_from_inspection(tracee_map: *TraceeMap, ctx: *Context) !void {
    const tracee: *Tracee = try get_or_make_tracee(tracee_map, ctx.pid);
    try begin_syscall(tracee.pid, &ctx.registers);
    // TODO see if switching the comment state on the following five lines of code
    //  makes any difference.
    // Specifically, if we are checking registers after an inspection.
    //  Maybe we should return ptrace.getregs after ending the syscall?
    // Alternatively, we could add a EventAction.INSPECT_RESULT value to the enum,
    //  placing it before the end_syscall line in next_event().
    tracee.state = .EXECUTING_CALL;
    // const wr = try waitpid(tracee.pid, 0);
    // const registers = try ptrace.getregs(pid);
    // try end_syscall(tracee.pid);
    // return registers;
}

/// Tracee has stopped execution right before
///  executing a syscall.
fn begin_syscall(pid: os.pid_t, registers: *c.user_regs_struct) !void {
    // print_call_info(pid, registers);
    //  Tracee will now conduct the syscall
    try ptrace.syscall(pid);
}

fn print_call_info(pid: os.pid_t, registers: *c.user_regs_struct) void {
    const call_name = @tagName(@intToEnum(os.SYS, registers.orig_rax));
    warn("[{}] {}() \n", .{ pid, call_name });
}

/// Tracee has finished its syscall
/// Collect information and resume tracee
fn end_syscall(pid: os.pid_t) !void {
    const registers = try ptrace.getregs(pid);

    // warn("[{}] = {}\n", .{ pid, @intCast(c_long, registers.rax) });

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
        } else @panic("Very unexpected event. Could not get value we just placed in a hashmap");
    }
    @panic("Very unexpected event. This should never happen");
}
