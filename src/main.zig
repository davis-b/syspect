// Notice: This program only works on x86_64 linux.
// It can be patched to work on other architectures.
//  However, it would require a redesign to work on Windows.
// Program traces linux system calls of target program

// TODO:

// Our 'connect' syscall options for redirecting network traffic:
// read calls only and then set iptables to modify network info
// maybe we could modify the fd of the syscall while keeping the structure intact, point it to a named pipe or a psuedo file or something?
// simply rewrite the memory in the tracee; might be detectable

// allow user to attach to active program by supplying a PID
// ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_flags);

// understand and then implement TRACEFORK support:
// PTRACE_O_TRACEFORK (since Linux 2.5.46)
// Stop the tracee at the next fork(2) and automatically start tracing the newly forked process, which will start with a SIGSTOP, or PTRACE_EVENT_STOP if PTRACE_SEIZE was used.
// A waitpid(2) by the tracer will return a status value such that //
// status>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8)) //
// The PID of the new process can be retrieved with PTRACE_GETEVENTMSG.

const std = @import("std");
const os = std.os;
const warn = std.debug.warn;

const ptrace = @import("ptrace.zig");
const c = @import("c.zig");
const mem_rw = @import("memory_rw.zig");

const events = @import("events.zig");

fn usage(our_name: [*:0]u8) void {
    warn("{} requires an argument\n", .{our_name});
}

fn init(allocator: *std.mem.Allocator) !os.pid_t {
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

    const tracee_pid = try fork(allocator, target_argv);
    var opts = c.PTRACE_O_EXITKILL | c.PTRACE_O_TRACEFORK | c.PTRACE_O_TRACECLONE;
    opts |= c.PTRACE_O_TRACESYSGOOD | c.PTRACE_O_TRACEEXEC;
    _ = try ptrace.ptrace(c.PTRACE_SETOPTIONS, tracee_pid, 0, opts);

    return tracee_pid;
}

pub fn main() !void {
    const allocator = std.heap.c_allocator;
    const tracee_pid = try init(allocator);
    warn("target pid: {}\n", .{tracee_pid});

    // Resume tracee
    _ = try ptrace.syscall(tracee_pid);

    var tracee_map = events.TraceeMap.init(allocator);
    defer tracee_map.deinit();
    const tracee = try events.get_or_make_tracee(&tracee_map, tracee_pid);

    var context = events.Context{
        .pid = undefined,
        .registers = undefined,
    };
    const inspect_these = [_]os.SYS{
        .connect,
    };

    while (true) {
        const action = try events.next_event(&tracee_map, &context, inspect_these[0..]);
        switch (action) {
            .CONT => continue,
            .EXIT => break,
            .INSPECT => {
                try redirectConnectCall(context);
                try events.resume_from_inspection(&tracee_map, &context);
            },
        }
    }
}

/// Modifies 'connect' syscalls to change the sockaddr struct in the tracee's memory
fn redirectConnectCall(context: events.Context) !void {
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

/// Forks and initiates ptrace from the child program.
/// Child then executes the target process.
/// Parent syncs with child, and then returns the child's PID
fn fork(allocator: *std.mem.Allocator, argv: []const []const u8) !os.pid_t {
    const child_pid = try os.fork();
    const envmap = try std.process.getEnvMap(allocator);
    switch (child_pid) {
        -1 => return error.UnknownForkingError,
        // child process
        0 => {
            _ = try ptrace.ptrace(c.PTRACE_TRACEME, 0, 0, 0);
            const err = os.execvpe(allocator, argv, &envmap);
            return err;
        },
        else => {
            _ = os.waitpid(child_pid, 0);
            return child_pid;
        },
    }
}
