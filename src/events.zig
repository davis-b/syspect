const std = @import("std");
const os = std.os;

const builtin = @import("builtin");
fn no_op_print(fmt: []const u8, args: anytype) void {}
const print = if (builtin.is_test or builtin.mode != .Debug) no_op_print else std.debug.warn;

const waitpid_file = @import("waitpid.zig");
const waitpid = waitpid_file.waitpid;
const WIFSTOPPED = waitpid_file.WIFSTOPPED;

const index = @import("index.zig");
const ptrace = index.ptrace;
const c = index.c;

const ProcState = enum {
    RUNNING,
    EXECUTING_CALL,
};

const Tracee = struct {
    pid: os.pid_t,
    state: ProcState,
};

pub const EventAction = enum {
    // Syscall was not made.
    CONT,
    // All child processes died.
    EXIT,
    // Syscall may be inspected and *should be resumed*.
    INSPECT,
    // Syscall has finished, results may be inspected.
    INSPECT_RESULT,
    // INSPECT_RESULT, except the syscall id is -1. Intended for use in nullifying syscalls.
    INSPECT_RESULT_UNKNOWN_SYSCALL,
    // Syscall started or ended normally.
    NORMAL,
};

/// Used to encapsulate and share information to
///  the caller of next_event.
pub const Context = struct {
    pid: os.pid_t,
    registers: c.registers,
};

pub const TraceeMap = std.AutoHashMap(os.pid_t, Tracee);

pub const Inspections = struct {
    /// If inverse is true, any syscalls outside of .calls will be inspected
    /// Inverse turns .calls into a do-not-inspect list.
    inverse: bool = false,
    /// Syscalls to be inspected
    calls: []const os.SYS,
};

pub fn next_event(pid: ?os.pid_t, tracee_map: *TraceeMap, ctx: *Context, inspections: Inspections) !EventAction {
    // This allows a caller to wait for the result of a syscall on a specific pid,
    //  defaults to -1 (any pid available)
    const waiton: os.pid_t = if (pid) |p| p else -1;
    const wr = waitpid(waiton, 0) catch |err| {
        if (tracee_map.count() == 0) return EventAction.EXIT;
        return EventAction.CONT;
    };
    return try handle_wait_result(wr, tracee_map, ctx, inspections);
}

pub fn handle_wait_result(wr: waitpid_file.WaitResult, tracee_map: *TraceeMap, ctx: *Context, inspections: Inspections) !EventAction {
    const tracee: *Tracee = try get_or_make_tracee(tracee_map, wr.pid);
    std.debug.assert(tracee.pid == wr.pid);
    ctx.pid = tracee.pid;

    switch (wr.status) {
        // Process exited normally
        .exit => |signal| {
            print("> {} exit signal: {}\n", .{ tracee.pid, signal });
            return handle_dying_process(tracee, tracee_map);
        },
        // Process was terminated by a signal
        .kill => |signal| {
            print("> {} kill signal: {}\n", .{ tracee.pid, signal });
            return handle_dying_process(tracee, tracee_map);
        },

        // Ptrace has stopped the process
        .ptrace => |signal| {
            switch (signal) {
                .syscall_trap => {
                    // Continue through to the typical next step
                    errdefer print("> [{}] error while handling syscall trap for syscall: {}\n", .{ tracee.pid, ctx.registers });
                    return try handle_event(tracee, tracee_map, ctx, inspections);
                },
                // Is there any scenario where we receive this event and the tracee survives? Should we check for that?
                else => {
                    // We have received a PTRACE event.
                    // We want to continue the process as normal and ignore the event.
                    print("> [{}] has received PTRACE signal {}\n", .{ tracee.pid, signal });
                    try ptrace.syscall(tracee.pid);
                    return EventAction.CONT;
                },
            }
        },

        // Process was stopped by the delivery of a signal.
        .stop => |signal| {
            print("> [{}] has received linux signal: {s}\n", .{ tracee.pid, @tagName(signal) });

            switch (signal) {
                // These signals are associated with the death of the tracee process.
                .quit, .segv => {
                    print("> {} quitting because of signal: {}\n", .{ tracee.pid, signal });
                    // Is this neccessary to be called?
                    try ptrace.syscall(tracee.pid);
                    return handle_dying_process(tracee, tracee_map);
                },
                // The remaining signals should be effectively ignored.
                else => {
                    try ptrace.syscall(tracee.pid);
                    return EventAction.CONT;
                },
            }
        },
    }
}

fn handle_dying_process(tracee: *Tracee, tracee_map: *TraceeMap) EventAction {
    _ = tracee_map.remove(tracee.pid);
    return if (tracee_map.count() == 0) .EXIT else .CONT;
}

pub fn handle_event(tracee: *Tracee, tracee_map: *TraceeMap, ctx: *Context, inspections: Inspections) !EventAction {
    switch (tracee.state) {
        .RUNNING => {
            // Collect syscall arguments.
            ctx.registers = try ptrace.getregs(tracee.pid);

            if (in(ctx.registers.syscall, inspections.calls) != inspections.inverse) {
                return EventAction.INSPECT;
            }

            try begin_syscall(tracee);
        },
        .EXECUTING_CALL => {
            // Collect syscall result.
            ctx.registers = try ptrace.getregs(tracee.pid);

            // Allows inspecting syscall results without resorting to blocking.
            const sc = ctx.registers.syscall;
            if (sc == @bitCast(c.regT, @as(c.sregT, -1))) {
                return EventAction.INSPECT_RESULT_UNKNOWN_SYSCALL;
            }

            if (in(sc, inspections.calls) != inspections.inverse) {
                return EventAction.INSPECT_RESULT;
            }

            try end_syscall(tracee);
        },
    }
    return EventAction.NORMAL;
}

fn in(needle: anytype, haystack: []const os.SYS) bool {
    for (haystack) |hay| {
        if (needle == @enumToInt(hay)) return true;
    }
    return false;
}

// TODO replace this with @suspend and resume in handle_event and caller code respectively
/// Must be called after next_event returns INSPECT or INSPECT_RESULT
/// Resumes tracee before or after the system call, as would normally happen in handle_event() with non-inspected calls.
pub fn resume_from_inspection(tracee_map: *TraceeMap, pid: os.pid_t) !void {
    const tracee: *Tracee = try get_or_make_tracee(tracee_map, pid);
    switch (tracee.state) {
        .RUNNING => try begin_syscall(tracee),
        .EXECUTING_CALL => try end_syscall(tracee),
    }
}

/// Tracee has stopped execution right before
///  executing a syscall.
fn begin_syscall(tracee: *Tracee) !void {
    //  Tracee will now conduct the syscall
    try ptrace.syscall(tracee.pid);
    tracee.state = .EXECUTING_CALL;
}

/// Tracee has finished its syscall
fn end_syscall(tracee: *Tracee) !void {
    // Resume tracee
    try ptrace.syscall(tracee.pid);
    tracee.state = .RUNNING;
}

pub fn get_or_make_tracee(tracee_map: *TraceeMap, pid: os.pid_t) !*Tracee {
    if (tracee_map.getPtr(pid)) |v| {
        return v;
    } else {
        const tracee = Tracee{ .pid = pid, .state = .RUNNING };
        _ = try tracee_map.put(pid, tracee);
        if (tracee_map.getPtr(pid)) |v| {
            return v;
        } else @panic("Very unexpected event. Could not get value we just placed in a hashmap");
    }
    @panic("Very unexpected event. This should never happen");
}
