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
    // Usually, the os.SYS list passed in would be the inspected syscalls.
    // When inversed, everything outside of the list is inspected, and the list items are ignored.
    var inspector = syspect.Inspector.init(allocator, .{ .inverse = true }, ignore_list);
    try init(allocator, &inspector);
    defer inspector.deinit();

    while (try inspector.next_syscall()) |*context| {
        print_info(context.*);
        try inspector.finish_syscall(context);
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

    try inspector.spawn_process(allocator, target_argv);
}

/// Prints the system call name and its first four arguments
fn print_info(context: syspect.Context) void {
    warn("{} ( ", .{@tagName(@intToEnum(os.SYS, context.registers.orig_rax))});
    warn("{}, ", .{context.registers.rdi});
    warn("{}, ", .{context.registers.rsi});
    warn("{}, ", .{context.registers.rdx});
    warn("{}", .{context.registers.r10});
    warn(" )\n", .{});
}
