const std = @import("std");
const os = std.os;
const warn = std.debug.warn;

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
    INSPECT,
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
            _ = tracee_map.remove(tracee.pid);
            return if (tracee_map.count() == 0) .EXIT else .CONT;
        },
        .kill => |signal| {
            warn("> {} kill signal: {}\n", .{ tracee.pid, signal });
            _ = tracee_map.remove(tracee.pid);
            return if (tracee_map.count() == 0) .EXIT else .CONT;
        },

        // Ptrace has stopped the process
        .ptrace => |signal| {
            switch (signal) {
                .syscall_trap => {
                    // Continue through to the typical next step
                    return try handle_event(tracee, tracee_map, ctx, inspections);
                },
                else => {
                    warn("> [{}] has received PTRACE signal {}\n", .{ tracee.pid, signal });
                    warn("> [{}] Resuming process without changing tracee state\n", .{tracee.pid});
                    try ptrace.syscall(tracee.pid);
                    return EventAction.CONT;
                },
            }
        },

        // Process was stopped by the delivery of a signal
        .stop => |signal| {
            warn("> [{}] has received signal {}\n", .{ tracee.pid, signal });
            warn("> [{}] Resuming process without changing tracee state\n", .{tracee.pid});
            try ptrace.syscall(tracee.pid);
            return EventAction.CONT;
        },
    }
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

            try end_syscall(tracee);

            // Would this feature be used, or just add bloat?
            // Its purpose would be to allow resume_from_inspection to see inspect syscall results.
            // We would bypass the blocking nature of resume_and_finish_from_inspection,
            //  however, it would require the caller to do pid management.
            // When would it ever be used? What is a good use case for this feature?
            //     if (in(ctx.registers.orig_rax, inspections.calls) != inspections.inverse) {
            //         return EventAction.INSPECT_RESULT;
            //     }
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
/// Must be called after next_event returns INSPECTION.
/// Executes the system call, as would normally happen in handle_event() with non-inspected calls.
pub fn resume_from_inspection(tracee_map: *TraceeMap, pid: os.pid_t) !void {
    const tracee: *Tracee = try get_or_make_tracee(tracee_map, pid);
    try begin_syscall(tracee);
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

fn print_call_info(pid: os.pid_t, registers: *c.user_regs_struct) void {
    const call_name = @tagName(@intToEnum(os.SYS, registers.orig_rax));
    warn("[{}] {}() \n", .{ pid, call_name });
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
