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
    const expected_syscalls = [_]generic.Syscall{
        .{ .id = .gettid },
        .{ .id = .fork },
        .{ .id = .gettid },
        .{ .id = .gettid },
    };

    try generic.test_specific_calls(target_argv[0..], expected_syscalls[0..]);
}
