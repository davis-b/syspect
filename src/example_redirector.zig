/// Example program using syspect.Inspector
/// Allows user to change ip and port on each connect syscall
const std = @import("std");
const os = std.os;
const warn = std.debug.warn;

const syspect = @import("syspect.zig");

/// Syscall only points to memory address, instead of directly containing values.
/// To edit the ip/port, we need to edit the other process' memory.
const mem_rw = @import("memory_rw.zig");

pub fn main() !void {
    const allocator = std.heap.c_allocator;

    const syscalls = &[_]os.SYS{
        .connect,
    };
    var inspector = syspect.Inspector.init(allocator, .{}, syscalls);
    try init(allocator, &inspector);
    defer inspector.deinit();

    while (try inspector.next_syscall()) |*context| {
        try redirectConnectCall(context.*);
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
        var len: usize = 0;
        while (arg[len] != 0) len += 1;
        target_argv[index] = arg[0..len];
    }

    try inspector.spawn_process(allocator, target_argv);
}

fn redirectConnectCall(context: syspect.Context) !void {
    // rsi register contains pointer to a sockaddr (connect syscall on x86_64)
    const sockaddr_register_ptr = context.registers.rsi;
    const sockaddr = try mem_rw.readSockaddr_PVReadv(context.pid, sockaddr_register_ptr);

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
            warn("\"{}\" is an invalid port number\n", .{user_input});
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
            warn("\"{}\" is an invalid ip\n", .{user_input});
            continue;
        };
        address = new_addr;
        break;
    }
    warn("New address: {}\n", .{address});
    try mem_rw.writeSockaddr_Ptrace(context.pid, sockaddr_register_ptr, address.any);
}
