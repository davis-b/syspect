// Notice: This program only works on x86_64 linux.
// It can be patched to work on other architectures. Would require a redesign to work on Windows.
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

const ptrace = @import("ptrace.zig").ptrace;
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
    const our_name = os.argv[0];

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
    _ = try ptrace(c.PTRACE_SETOPTIONS, tracee_pid, 0, opts);

    return tracee_pid;
}
pub fn main() !void {
    const allocator = std.heap.c_allocator;
    const tracee_pid = try init(allocator);
    warn("target pid: {}\n", .{tracee_pid});

    // Resume tracee
    _ = try ptrace(c.PTRACE_SYSCALL, tracee_pid, 0, 0);

    var tracee_map = events.TraceeMap.init(allocator);
    defer tracee_map.deinit();
    const tracee = try events.get_or_make_tracee(&tracee_map, tracee_pid);

    while (true) {
        const action = try events.next_event(&tracee_map);
        switch (action) {
            .CONT => continue,
            .EXIT => break,
            .NORMAL => {},
            .INSPECT => {
                warn("TODO: inspect this syscall\n", .{});
            },
        }
    }
}

/// Returns true to indicate caller should 'continue' to their next loop
fn handleSignals(wait_result: WaitResult) !bool {
    var siginfo: os.siginfo_t = undefined;
    _ = try ptrace(c.PTRACE_GETSIGINFO, wait_result.pid, 0, &siginfo);
    switch (siginfo.signo) {
        os.SIGSTOP => {
            warn("||\nSIGSTOP\n||\n", .{});
            _ = try ptrace(c.PTRACE_SYSCALL, wait_result.pid, 0, 0);
            return true;
        },
        os.SIGABRT => {
            warn("|| SIGABRT\n", .{});
            _ = try ptrace(c.PTRACE_SYSCALL, wait_result.pid, 0, 0);
            return true;
        },
        else => {},
    }
    return false;
}

/// Handle attaching to new processes/threads
fn handleCloning(wait_result: WaitResult) !void {
    if ((@intCast(c_int, wait_result.status) >> 8) == (os.SIGTRAP | (c.PTRACE_EVENT_CLONE << 8))) {
        warn("| | CLONE\n", .{});
    }
    const event = @intCast(c_int, wait_result.status) >> 16;

    if (event == c.PTRACE_EVENT_EXEC) {
        warn("| | EXEC event! {}\n", .{wait_result});
    }

    if (event == c.PTRACE_EVENT_CLONE or event == c.PTRACE_EVENT_FORK or event == c.PTRACE_EVENT_VFORK) {
        var child_pid: os.pid_t = 0;
        _ = try ptrace(c.PTRACE_GETEVENTMSG, wait_result.pid, 0, &child_pid);
        warn("attached {} to {}\n", .{ wait_result.pid, child_pid });
    }
}

/// Modifies 'connect' syscalls to change the sockaddr struct in the tracee's memory
fn handleSyscall(regs: *c.user_regs_struct, pid: os.pid_t) !void {
    // rsi register contains pointer to a sockaddr (connect syscall on x86_64)
    const sockaddr_register_ptr = regs.rsi;
    const sockaddr = try mem_rw.readSockaddr_PVReadv(pid, sockaddr_register_ptr);
    //const sockaddr = try mem_rw.readSockaddr_Ptrace(pid, sockaddr_register_ptr);

    if (sockaddr.family == os.AF_INET or sockaddr.family == os.AF_INET6) {
        var address = std.net.Address.initPosix(@alignCast(4, &sockaddr));
        warn("{} connect( {} )\n", .{ pid, address });
    }
    //  address.setPort(9988);
    //  try mem_rw.writeSockaddr_Ptrace(pid, sockaddr_register_ptr, address.any);

    //    const connect_fd: c_int = regs.rdi;
    //    const connect_addrlen : os.socklen_t = regs.rdx;
    // warn("{} {} {} {} {} {}\n", .{ registers.rdi, registers.rsi, registers.rdx, registers.r10, registers.r8, registers.r9 });
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
            _ = try ptrace(c.PTRACE_TRACEME, 0, 0, 0);
            const err = os.execvpe(allocator, argv, &envmap);
            return err;
        },
        else => {
            _ = os.waitpid(child_pid, 0);
            return child_pid;
        },
    }
}
