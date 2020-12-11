const std = @import("std");
const testing = std.testing;
const SYS = std.os.SYS;

const syspect = @import("syspect");

const generic = @import("generic.zig");
const utils = @import("utils.zig");

const target_argv = [_][]const u8{"zig-cache/bin/tests/example-fork"};
const allocator = std.testing.allocator;

test "generic pid tracking" {
    try generic.ensure_pid_properly_tracked(target_argv[0..]);
}

test "track specific calls" {
    const tracked_syscalls = &[_]SYS{
        .fork,
        .gettid,
    };

    const expected_syscalls = [_]SYS{
        .gettid,
        .fork,
        .gettid,
        .gettid,
    };

    var inspector = syspect.Inspector.init(allocator, tracked_syscalls, .{ .inverse = false });
    defer inspector.deinit();
    _ = try inspector.spawn_process(allocator, target_argv[0..]);

    try generic.track_some_calls(&inspector, expected_syscalls[0..]);
    if ((try inspector.next_syscall()) != null) return error.TooManySyscalls;
}
