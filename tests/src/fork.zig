const std = @import("std");
const testing = std.testing;
const SYS = std.os.SYS;

const syspect = @import("syspect");

const generic = @import("generic.zig");
const utils = @import("utils.zig");
const expectEnumEqual = utils.expectEnumEqual;

/// We would prefer to run this code as a test.
/// However, when ran as a test, there is a strange issue where
///  we repeatedly receive an exit signal of 0 on pid -10.
pub fn main() !void {
    const target_argv = [_][]const u8{"zig-cache/bin/tests/example-fork"};
    try specific_calls(target_argv[0..]);
    try generic.ensure_pid_properly_tracked(target_argv[0..]);
}

fn specific_calls(target_argv: []const []const u8) !void {
    const allocator = std.testing.allocator;

    const syscalls = &[_]SYS{
        .fork,
        .gettid,
    };

    var inspector = syspect.Inspector.init(allocator, syscalls, .{ .inverse = false });
    defer inspector.deinit();

    const child_pid = try inspector.spawn_process(allocator, target_argv);

    const expected_syscalls = [_]SYS{
        .gettid,
        .fork,
        .gettid,
        .gettid,
    };

    var call_index: usize = 0;
    while (try inspector.next_syscall()) |syscall| {
        switch (syscall) {
            .pre_call => |context| {
                expectEnumEqual(SYS, expected_syscalls[call_index], context.registers.orig_rax);
                try inspector.start_syscall(context.pid);
            },
            .post_call => |context| {
                if (context.registers.orig_rax == @enumToInt(SYS.gettid)) {
                    testing.expectEqual(@intCast(c_ulonglong, context.pid), context.registers.rax);
                }
                expectEnumEqual(SYS, expected_syscalls[call_index], context.registers.orig_rax);
                call_index += 1;
                try inspector.resume_tracee(context.pid);
            },
        }
    }
}
