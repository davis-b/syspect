const std = @import("std");
const testing = std.testing;
const SYS = std.os.SYS;

const allocator = std.testing.allocator;

const syspect = @import("syspect");
const utils = @import("utils.zig");

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

pub fn track_specific_calls(target_argv: []const []const u8, tracked_syscalls: []const SYS, expected_calls: []const SYS) !void {
    var inspector = syspect.Inspector.init(allocator, tracked_syscalls, .{ .inverse = false });
    defer inspector.deinit();

    _ = try inspector.spawn_process(allocator, target_argv);

    var call_index: usize = 0;
    while (try inspector.next_syscall()) |syscall| {
        switch (syscall) {
            .pre_call => |context| {
                utils.expectEnumEqual(SYS, expected_calls[call_index], context.registers.orig_rax);
                try inspector.start_syscall(context.pid);
            },
            .post_call => |context| {
                if (context.registers.orig_rax == @enumToInt(SYS.gettid)) {
                    testing.expectEqual(@intCast(c_ulonglong, context.pid), context.registers.rax);
                }
                utils.expectEnumEqual(SYS, expected_calls[call_index], context.registers.orig_rax);
                call_index += 1;
                try inspector.resume_tracee(context.pid);
            },
        }
    }
}
