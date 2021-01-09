const std = @import("std");
const os = std.os;
const testing = std.testing;
const SYS = std.os.SYS;

const syspect = @import("syspect");

const utils = @import("utils.zig");

const target_argv = [_][]const u8{"zig-cache/bin/tests/example-modify_result"};
const allocator = std.testing.allocator;

test "change syscall result" {
    const syscalls = &[_]SYS{
        .gettid,
    };

    var inspector = syspect.Inspector.init(allocator, syscalls, .{});
    defer inspector.deinit();

    const child_pid = try inspector.spawn_process(allocator, target_argv[0..]);

    var first_result: ?os.pid_t = null;
    while (try inspector.next_syscall()) |syscall| {
        switch (syscall) {
            .pre_call => |context| {
                try inspector.resume_tracee(context.pid);
            },
            .post_call => |context| {
                if (first_result == null) {
                    first_result = @intCast(os.pid_t, context.registers.result);
                    testing.expectEqual(child_pid, first_result.?);
                } else {
                    var new_regs = context.registers;
                    new_regs.result = @intCast(syspect.c.regT, first_result.? - 1);
                    try syspect.ptrace.setregs(context.pid, new_regs);
                    testing.expectEqual(child_pid, @intCast(os.pid_t, context.registers.result));
                }
                try inspector.resume_tracee(context.pid);
            },
        }
    }

    // Ensure we properly acknowledge a state where all tracees have exited.
    testing.expectEqual(false, inspector.has_tracees);
    testing.expectEqual(try inspector.next_syscall(), null);
}
