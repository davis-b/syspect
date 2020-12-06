const std = @import("std");
const os = std.os;

// TODO
// If the bug caused by using (test "test name") instead of creating and running executables is fixed:
// We would prefer to not print output if (std.builtin.is_test) is true.
fn no_op_warn(fmt: []const u8, args: var) void {}
const warn = switch (@import("builtin").mode) {
    .Debug => std.debug.warn,
    else => no_op_warn,
};

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
    // Syscall started or ended normally.
    NORMAL,
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
            warn("> {} exit signal: {}\n", .{ tracee.pid, signal });
            return handle_dying_process(tracee, tracee_map);
        },
        // Process was terminated by a signal
        .kill => |signal| {
            warn("> {} kill signal: {}\n", .{ tracee.pid, signal });
            return handle_dying_process(tracee, tracee_map);
        },

        // Ptrace has stopped the process
        .ptrace => |signal| {
            switch (signal) {
                .syscall_trap => {
                    // Continue through to the typical next step
                    return try handle_event(tracee, tracee_map, ctx, inspections);
                },
                // Is there any scenario where we receive this event and the tracee survives? Should we check for that?
                else => {
                    // We have received a PTRACE event.
                    // We want to continue the process as normal and ignore the event.
                    warn("> [{}] has received PTRACE signal {}\n", .{ tracee.pid, signal });
                    try ptrace.syscall(tracee.pid);
                    return EventAction.CONT;
                },
            }
        },

        // Process was stopped by the delivery of a signal
        .stop => |signal| {
            warn("> [{}] has received linux signal {}\n", .{ tracee.pid, signal });

            switch (signal) {
                .quit => {
                    warn("> {} quit signal\n", .{tracee.pid});
                    // Is this neccessary to be called?
                    try ptrace.syscall(tracee.pid);
                    return handle_dying_process(tracee, tracee_map);
                },
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

            if (in(ctx.registers.orig_rax, inspections.calls) != inspections.inverse) {
                return EventAction.INSPECT;
            }

            try begin_syscall(tracee);
        },
        .EXECUTING_CALL => {
            // Collect syscall result.
            ctx.registers = try ptrace.getregs(tracee.pid);

            // Allows inspecting syscall results without resorting to blocking.
            if (in(ctx.registers.orig_rax, inspections.calls) != inspections.inverse) {
                return EventAction.INSPECT_RESULT;
            }

            try end_syscall(tracee);
        },
    }
    return EventAction.NORMAL;
}

fn in(needle: c_ulonglong, haystack: []const os.SYS) bool {
    for (haystack) |hay| {
        if (needle == @enumToInt(hay)) return true;
    }
    return false;
}

// TODO replace this with @suspend and resume in handle_event and caller code respectively
/// Must be called after next_event returns INSPECT.
/// Executes the system call, as would normally happen in handle_event() with non-inspected calls.
pub fn resume_from_inspection(tracee_map: *TraceeMap, pid: os.pid_t) !void {
    const tracee: *Tracee = try get_or_make_tracee(tracee_map, pid);
    try begin_syscall(tracee);
}

/// Must be called after next_event returns INSPECT_RESULT.
/// Executes the system call, as would normally happen in handle_event() with non-inspected calls.
pub fn resume_from_inspection_result(tracee_map: *TraceeMap, pid: os.pid_t) !void {
    const tracee: *Tracee = try get_or_make_tracee(tracee_map, pid);
    try end_syscall(tracee);
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
