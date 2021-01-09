const std = @import("std");
const testing = std.testing;
const SYS = std.os.SYS;

const syspect = @import("syspect");

const generic = @import("generic.zig");
const utils = @import("utils.zig");

const target_argv = [_][]const u8{"zig-cache/bin/tests/example-child_signals"};
const allocator = std.testing.allocator;

test "generic pid tracking" {
    try generic.ensure_pid_properly_tracked(target_argv[0..]);
}

test "main test" {
    const tracked_syscalls = &[_]SYS{
        .fork,
        .gettid,
        .rt_sigprocmask,
        .kill,
        .wait4,
        .rt_sigtimedwait,
    };

    var inspector = syspect.Inspector.init(allocator, tracked_syscalls, .{});
    defer inspector.deinit();

    const thread_leader_pid = try inspector.spawn_process(allocator, target_argv[0..]);

    // Ensure we call sigprocmask and gettid
    {
        const expected_calls = [_]generic.Syscall{
            .{ .id = .rt_sigprocmask },
            .{ .id = .gettid },
        };
        try generic.test_some_calls(&inspector, expected_calls[0..]);
    }

    // Gather child pid from the fork result
    const child_pid = fork: {
        const pre_call = (try inspector.next_syscall()).?.pre_call;
        utils.expectEnumEqual(SYS, SYS.fork, pre_call.registers.orig_syscall);
        try inspector.resume_tracee(pre_call.pid);

        const post_call = (try inspector.next_syscall()).?.post_call;
        utils.expectEnumEqual(SYS, SYS.fork, post_call.registers.orig_syscall);
        testing.expectEqual(thread_leader_pid, post_call.pid);
        try inspector.resume_tracee(post_call.pid);
        break :fork @intCast(std.os.pid_t, post_call.registers.syscall_then_result);
    };

    // These calls could happen in almost any order, use ooo_call_tracking to test with that in mind.
    var syscalls = [_]generic.Syscall{
        .{ .id = .kill, .pid = thread_leader_pid },
        .{ .id = .wait4, .pid = thread_leader_pid },
        .{ .id = .gettid, .pid = child_pid },
        .{ .id = .rt_sigtimedwait, .pid = child_pid },
    };
    try generic.ooo_call_tracking(&inspector, syscalls[0..]);

    // Final sanity test for gettid.
    gettid: {
        const pre_call = (try inspector.next_syscall()).?.pre_call;
        utils.expectEnumEqual(SYS, SYS.gettid, pre_call.registers.orig_syscall);
        try inspector.resume_tracee(pre_call.pid);

        const post_call = (try inspector.next_syscall()).?.post_call;
        utils.expectEnumEqual(SYS, SYS.gettid, post_call.registers.orig_syscall);
        testing.expectEqual(thread_leader_pid, post_call.pid);
        testing.expectEqual(@intCast(syspect.c.regT, post_call.pid), post_call.registers.syscall_then_result);
        try inspector.resume_tracee(post_call.pid);
    }

    // Expect program has exited.
    testing.expectEqual(try inspector.next_syscall(), null);
}
