/// Example program using syspect.Inspector
/// Allows user to change ip and port on each connect syscall
const std = @import("std");
const os = std.os;
const warn = std.debug.warn;

const syspect = @import("syspect");

/// Syscall only points to memory address, instead of directly containing values.
/// To edit the ip/port, we need to edit the other process' memory.
const sockaddr_rw = @import("memory_rw_netaddress.zig");

pub fn main() !void {
    const allocator = std.heap.c_allocator;

    const syscalls = &[_]os.SYS{
        .connect,
    };
    var inspector = syspect.Inspector.init(allocator, syscalls, .{});
    try init(allocator, &inspector);
    defer inspector.deinit();

    while (try inspector.next_syscall()) |*syscall| {
        switch (syscall.*) {
            .pre_call => |context| {
                try redirectConnectCall(context);
                try inspector.resume_tracee(context.pid);
            },
            .post_call => |context| {
                try inspector.resume_tracee(context.pid);
            },
        }
    }
}

fn usage(our_name: [*:0]u8) void {
    warn("{s} requires an argument\n", .{our_name});
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

fn redirectConnectCall(context: syspect.Context) !void {
    const sockaddr_register_ptr = @intCast(usize, context.registers.arg2);
    const sockaddr = try sockaddr_rw.readSockaddr_PVReadv(context.pid, sockaddr_register_ptr);

    if (sockaddr.family != os.AF_INET and sockaddr.family != os.AF_INET6) {
        return;
    }
    var address = std.net.Address.initPosix(@alignCast(4, &sockaddr));
    warn("[{}] connect( {} )\n", .{ context.pid, address });

    var buffer = [_]u8{0} ** 20;
    const stdin = std.io.getStdIn();
    while (true) {
        warn("Please enter a port number (leave blank for unchanged):\n", .{});
        var read_bytes = try stdin.read(buffer[0..]);
        if (buffer[read_bytes - 1] == '\n') read_bytes -= 1;
        if (read_bytes == 0) break;
        const user_input = buffer[0..read_bytes];
        const new_port = std.fmt.parseInt(u16, user_input, 10) catch |err| {
            warn("\"{s}\" is an invalid port number\n", .{user_input});
            continue;
        };
        address.setPort(new_port);
        break;
    }
    while (true) {
        warn("Please enter an ip address (leave blank for unchanged):\n", .{});
        var read_bytes = try stdin.read(buffer[0..]);
        if (buffer[read_bytes - 1] == '\n') read_bytes -= 1;
        if (read_bytes == 0) break;
        const user_input = buffer[0..read_bytes];
        const new_addr = std.net.Address.parseIp(user_input, address.getPort()) catch |err| {
            warn("\"{s}\" is an invalid ip\n", .{user_input});
            continue;
        };
        address = new_addr;
        break;
    }
    warn("New address: {}\n", .{address});
    _ = try sockaddr_rw.writeSockaddr_PVWritev(context.pid, sockaddr_register_ptr, address.any);
}
