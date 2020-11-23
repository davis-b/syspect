/// Example program using syspect.Inspector
/// Prints (unformatted) all system calls except for a chosen few.
const std = @import("std");
const os = std.os;
const warn = std.debug.warn;

const syspect = @import("syspect");

pub fn main() !void {
    const allocator = std.heap.c_allocator;

    const ignore_list = &[_]os.SYS{
        .write,
        .mprotect,
        .mmap,
        .munmap,
        .brk,
        .access,
    };
    // Setting inverse to true changes how Inspector itneracts with ignore_list.
    // Usually, list of syscalls passed in would be the inspected syscalls.
    // When inversed, everything outside of the list is inspected, and the list items are ignored.

    var inspector = syspect.Inspector.init(allocator, ignore_list, .{ .inverse = true });

    try init(allocator, &inspector);
    defer inspector.deinit();

    while (try inspector.next_syscall()) |*syscall| {
        switch (syscall.*) {
            .pre_call => |context| {
                warn("[{}] starting {}\n", .{ context.pid, enumName(context.registers.orig_rax) });
                try inspector.start_syscall(context.pid);
            },
            .post_call => |context| {
                // Arguments may not be accurate, syscall return value will be accurate.
                // Argument registers may have been changed between the initial call and this point in time.
                // Unless the system resets registers to their state at the initial call? Seems unlikely.
                print_info(context);
                warn("[{}] finished {}\n", .{ context.pid, enumName(context.registers.orig_rax) });
            },
        }
    }
}

fn enumName(int: var) []const u8 {
    inline for (std.meta.fields(os.SYS)) |f| {
        if (int == f.value) return f.name;
    }
    return "???";
}

fn usage(our_name: [*:0]u8) void {
    warn("{} requires an argument\n", .{our_name});
}

fn init(allocator: *std.mem.Allocator, inspector: *syspect.Inspector) !void {
    if (os.argv.len <= 1) {
        usage(os.argv[0]);
        os.exit(1);
    }

    const maybe_pid: ?os.pid_t = std.fmt.parseInt(os.pid_t, std.mem.span(os.argv[1]), 10) catch null;
    if (maybe_pid) |pid| {
        inspector.attach_to_process(pid) catch |err| {
            switch (err) {
                error.OperationNotPermitted => {
                    warn("Operation not permitted. Usually caused by insufficient privileges. Try running the program as sudo!\n", .{});
                    os.exit(1);
                },
                else => return err,
            }
        };
        warn("Attached to pid: {}\n", .{pid});
    } else {
        var target_argv = try allocator.alloc([]u8, os.argv.len - 1);
        defer allocator.free(target_argv);
        for (os.argv[1..os.argv.len]) |arg, index| {
            target_argv[index] = std.mem.span(arg);
        }

        _ = try inspector.spawn_process(allocator, target_argv);
    }
}

/// Prints the system call name and its first four arguments
fn print_info(context: syspect.Context) void {
    warn("[{}] ", .{context.pid});
    warn("{} ( ", .{enumName(context.registers.orig_rax)});
    warn("{}, ", .{context.registers.rdi});
    warn("{}, ", .{context.registers.rsi});
    warn("{}, ", .{context.registers.rdx});
    warn("{}", .{context.registers.r10});
    warn(" ) = ", .{});
    warn("{}\n", .{@intCast(isize, context.registers.rax)});
}
