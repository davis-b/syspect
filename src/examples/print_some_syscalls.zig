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

    var inspector = syspect.Inspector.init(allocator, .{ .inverse = true }, ignore_list);

    try init(allocator, &inspector);
    defer inspector.deinit();

    // What if strace doesn't print which one starts first, but which one finishes first?
    while (try inspector.next_syscall()) |*syscall| {
        switch (syscall.*) {
            .pre_call => |context| {
                warn("[{}] starting {}\n", .{ context.pid, @tagName(@intToEnum(os.SYS, context.registers.orig_rax)) });
                try inspector.start_syscall(context);
            },
            .post_call => |context| {
                // Make sure registers are set to calling values here, otherwise we need to split print_info to a start and a finish section
                print_info(context);
                warn("[{}] finished {}\n", .{ context.pid, @tagName(@intToEnum(os.SYS, context.registers.orig_rax)) });
            },
        }
    }
}

fn usage(our_name: [*:0]u8) void {
    warn("{} requires an argument\n", .{our_name});
}

fn init(allocator: *std.mem.Allocator, inspector: *syspect.Inspector) !void {
    if (os.argv.len <= 1) {
        usage(os.argv[0]);
        os.exit(1);
    }

    var target_argv = try allocator.alloc([]u8, os.argv.len - 1);
    defer allocator.free(target_argv);
    for (os.argv[1..os.argv.len]) |arg, index| {
        target_argv[index] = std.mem.span(arg);
    }

    _ = try inspector.spawn_process(allocator, target_argv);
}

/// Prints the system call name and its first four arguments
fn print_info(context: syspect.Context) void {
    warn("[{}] ", .{context.pid});
    warn("{} ( ", .{@tagName(@intToEnum(os.SYS, context.registers.orig_rax))});
    warn("{}, ", .{context.registers.rdi});
    warn("{}, ", .{context.registers.rsi});
    warn("{}, ", .{context.registers.rdx});
    warn("{}", .{context.registers.r10});
    warn(" ) = ", .{});
    warn("{}\n", .{@intCast(isize, context.registers.rax)});
}
