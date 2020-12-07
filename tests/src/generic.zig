const std = @import("std");
const testing = std.testing;
const SYS = std.os.SYS;

const syspect = @import("syspect");

pub fn ensure_pid_properly_tracked(target_argv: []const []const u8) !void {
    const allocator = std.testing.allocator;

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
