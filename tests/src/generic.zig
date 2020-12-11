const std = @import("std");
const testing = std.testing;
const SYS = std.os.SYS;

const allocator = std.testing.allocator;

const syspect = @import("syspect");
const utils = @import("utils.zig");

/// Runs 'target_argv' program using syspect.Inspector.
/// Inspects each syscall.
/// Ensures any 'gettid()' calls return the same tid we think called it.
pub fn ensure_pid_properly_tracked(target_argv: []const []const u8) !void {
    const syscalls = &[_]SYS{};

    var inspector = syspect.Inspector.init(allocator, syscalls, .{ .inverse = true });
    defer inspector.deinit();

    const child_pid = try inspector.spawn_process(allocator, target_argv);

    while (try inspector.next_syscall()) |syscall| {
        switch (syscall) {
            .pre_call => |context| {
                try inspector.start_syscall(context.pid);
            },
            .post_call => |context| {
                if (context.registers.orig_rax == @enumToInt(SYS.gettid)) {
                    testing.expectEqual(@intCast(c_ulonglong, context.pid), context.registers.rax);
                }
                try inspector.resume_tracee(context.pid);
            },
        }
    }
}

/// Runs and inspects a program, tracking specific calls.
/// Runs applicable tests on every inspected syscall.
/// Expects syscalls to show up in order.
/// Expects the expected syscalls to be the only ones inspected from program start to end.
pub fn test_specific_calls(target_argv: []const []const u8, expected_calls: []const Syscall) !void {
    // Create a buffer, we are unlikely to use its entire size.
    // We would receive an "index out of bounds" error if we used more syscalls than allocated for here.
    var tracked_syscalls: [100]SYS = undefined;
    var unique_calls: usize = 0;

    // Creates a unique set of syscalls from 'expected_calls'.
    for (expected_calls) |expected| {
        // Check to see if expected call id is already tracked.
        for (tracked_syscalls) |tracked| {
            if (expected.id != tracked) {
                tracked_syscalls[unique_calls] = expected.id;
                unique_calls += 1;
                break;
            }
        }
    }
    var inspector = syspect.Inspector.init(allocator, tracked_syscalls[0..unique_calls], .{ .inverse = false });
    defer inspector.deinit();

    _ = try inspector.spawn_process(allocator, target_argv);

    try test_some_calls(&inspector, expected_calls);
    if ((try inspector.next_syscall()) != null) return error.TooManySyscalls;
}

/// Gathers next_syscall for each expected syscall; Compares what we expect with what we get.
/// Has no protection against race conditions.
/// Takes an 'Inspector' that has already attached to or spawned a process.
/// Does not guarantee the process has ended.
pub fn test_some_calls(inspector: *syspect.Inspector, expected_calls: []const Syscall) !void {
    for (expected_calls) |expected| {
        const pre_call = (try inspector.next_syscall()).?.pre_call;
        utils.expectEnumEqual(SYS, expected.id, pre_call.registers.orig_rax);
        try inspector.start_syscall(pre_call.pid);

        const post_call = (try inspector.next_syscall()).?.post_call;
        if (post_call.registers.orig_rax == @enumToInt(SYS.gettid)) {
            testing.expectEqual(@intCast(c_ulonglong, post_call.pid), post_call.registers.rax);
        }
        utils.expectEnumEqual(SYS, expected.id, post_call.registers.orig_rax);
        try inspector.resume_tracee(post_call.pid);
    }
}

pub const Syscall = struct {
    id: SYS,

    // Expected PID of this syscalls caller. Null means we do not test against PID.
    pid: ?std.os.pid_t = null,

    // Expected result. Null means we do not test against the result.
    result: ?c_int = null,

    // Has the syscall been started? Used and changed internally.
    started: bool = false,
};

/// Out of order call tracking
/// Tracks system calls in a way that ignores potential race conditions.
pub fn ooo_call_tracking(inspector: *syspect.Inspector, calls: []Syscall) !void {
    var remaining: usize = calls.len * 2;
    while (remaining > 0) : (remaining -= 1) {
        const syscall = (try inspector.next_syscall()).?;
        switch (syscall) {
            .pre_call => |context| {
                const id = @intToEnum(SYS, context.registers.orig_rax);
                const call = try verify(calls, Syscall{ .id = id, .pid = context.pid, .started = false });
                call.started = !call.started;
                try inspector.start_syscall(context.pid);
            },
            .post_call => |context| {
                const id = @intToEnum(SYS, context.registers.orig_rax);
                const call = try verify(calls, Syscall{ .id = id, .pid = context.pid, .started = true });
                call.started = !call.started;
                try inspector.resume_tracee(context.pid);
            },
        }
    }
}

/// Verifies a syscall falls within expected boundaries
fn verify(syscalls: []Syscall, syscall: Syscall) !*Syscall {
    for (syscalls) |*hay| {
        var needle = syscall;
        if (hay.pid == null) needle.pid = null;
        if (hay.result == null) needle.result = null;

        if (std.meta.eql(needle, hay.*)) {
            return hay;
        }
    }
    std.debug.warn("syscall unmatched: {} {}\n", .{ @tagName(syscall.id), syscall });
    return error.UnmatchedSyscall;
}
