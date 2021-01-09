const std = @import("std");
const testing = std.testing;
const SYS = std.os.SYS;

const syspect = @import("syspect");

const generic = @import("generic.zig");
const utils = @import("utils.zig");

const target_argv = [_][]const u8{"zig-cache/bin/tests/example-nullify_syscall"};
const allocator = std.testing.allocator;

test "nullify a syscall" {
    const syscalls = &[_]SYS{
        .kill,
    };

    var inspector = syspect.Inspector.init(allocator, syscalls, .{});
    defer inspector.deinit();

    const child_pid = try inspector.spawn_process(allocator, target_argv[0..]);

    while (try inspector.next_syscall()) |syscall| {
        switch (syscall) {
            .pre_call => |context| {
                try inspector.nullify_syscall(context, std.os.EPERM);
                try inspector.resume_tracee(context.pid);
            },
            .post_call => |context| {
                try inspector.resume_tracee(context.pid);
            },
        }
    }

    // Ensure we properly acknowledge a state where all tracees have exited.
    testing.expectEqual(false, inspector.has_tracees);
    testing.expectEqual(try inspector.next_syscall(), null);
}
