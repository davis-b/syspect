// This program prints the name of whichever path is being supplied to open, openat, and creat system calls.
// Program takes an executable name or active PID as input.
const std = @import("std");
const os = std.os;
const warn = std.debug.warn;

const syspect = @import("syspect");

pub fn main() !void {
    const allocator = std.heap.c_allocator;

    const syscalls = &[_]os.SYS{
        .open,
        .openat,
    };

    var inspector = syspect.Inspector.init(allocator, syscalls, .{ .multithread = true });
    defer inspector.deinit();
    try init(allocator, &inspector);

    while (try next_syscall(&inspector)) |position_context| {
        // Here we are unwrapping a tagged union, which tells us if the syscall has been executed or not.
        switch (position_context) {
            // The syscall will be executed after we resume the tracee.
            // Now is our chance to inspect and even modify the arguments or tracee's memory.
            .pre_call => |context| {
                var buffer = [_]u8{0} ** std.fs.MAX_PATH_BYTES;
                // openat(2) and open(2) share all arguments/argument positions, except for openat(2)'s first argument.
                const pathname = switch (@intToEnum(os.SYS, context.registers.syscall)) {
                    .open, .creat => try readString(context.pid, context.registers.arg1, buffer[0..]),
                    .openat => try readString(context.pid, context.registers.arg2, buffer[0..]),
                    else => unreachable,
                };
                warn("pid = {}, '{s}' path = '{s}'\n", .{ context.pid, @tagName(@intToEnum(os.SYS, context.registers.syscall)), pathname });

                try inspector.resume_tracee(context.pid);
            },
            // The syscall has finished and the result will be returned to the tracee when resumed.
            // Here we can view the result as well as modify what the tracee will see as the return value.
            .post_call => |context| {
                warn("pid = {}, '{s}' = {}\n\n", .{ context.pid, @tagName(@intToEnum(os.SYS, context.registers.syscall)), @bitCast(isize, context.registers.result) });
                try inspector.resume_tracee(context.pid);
            },
        }
    }
}

// Currently Steam returns error.NoSuchProcess when we call ptrace.getRegister during a ptrace syscall trap.
// We are unsure why this happens. However, this is a working bandaid, for now.
fn next_syscall(inspector: *syspect.Inspector) anyerror!?syspect.Inspector.SyscallContext {
    return inspector.next_syscall() catch |err| {
        return switch (err) {
            error.NoSuchProcess => next_syscall(inspector),
            else => err,
        };
    };
}

/// Reads data as a string until we reach a null termination character.
/// Takes a pointer to a string. The pointer does not have to point to our memory space.
/// Can read data from other processes by utilizing "syspect.interprocess_rw"
pub fn readString(pid: os.pid_t, ptr: usize, buffer: []u8) ![]u8 {
    const vmreadv_result = try syspect.interprocess_rw.readv(pid, buffer[0..], ptr);

    for (buffer) |i, index| {
        if (i == 0) return buffer[0..index];
    }
    return error.FilenameEndNotFound;
}

/// Handles argument parsing.
/// Can either spawn a new process or attach to a running process, given the PID.
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

        // Spawns the process with associated arguments; immediately begins tracing the process.
        const tracee_pid = try inspector.spawn_process(allocator, target_argv);
    }
}

fn usage(our_name: [*:0]u8) void {
    warn("To use {s}, call it with either: another program's path, or a running process' PID\n", .{our_name});
}
