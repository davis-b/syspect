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

    // Setting inverse to true changes how Inspector interacts with ignore_list.
    // Usually, the list of syscalls passed in would be the inspected syscalls.
    // When inversed, everything outside of the list is inspected, and the syscalls passed in are ignored.
    var inspector = syspect.Inspector.init(allocator, ignore_list, .{ .inverse = true });

    try init(allocator, &inspector);
    defer inspector.deinit();

    // We will be caching names so we don't have to do unnecessary work in code that is likely to be hot.
    var pid_name_cache = std.AutoHashMap(os.pid_t, []u8).init(allocator);
    defer pid_name_cache.deinit();
    defer {
        var iter = pid_name_cache.iterator();
        while (iter.next()) |kv| {
            allocator.free(kv.value);
        }
    }

    while (try inspector.next_syscall()) |*syscall| {
        switch (syscall.*) {
            .pre_call => |context| {
                const pid_name = processName(allocator, &pid_name_cache, context.pid);
                warn("[{} - {}] starting {}\n", .{ context.pid, pid_name, enumName(context.registers.syscall) });
                try inspector.resume_tracee(context.pid);
            },
            .post_call => |context| {
                // Arguments may not be accurate, syscall return value will be accurate.
                // Argument registers may have been changed between the initial call and this point in time.
                // Unless the system resets registers to their state at the initial call? Seems unlikely.
                print_info(context);
                const pid_name = processName(allocator, &pid_name_cache, context.pid);
                warn("[{} - {}] finished {}\n\n", .{ context.pid, pid_name, enumName(context.registers.syscall) });
                try inspector.resume_tracee(context.pid);
            },
        }
    }
}

fn processName(allocator: *std.mem.Allocator, cache: *std.AutoHashMap(os.pid_t, []u8), pid: os.pid_t) ![]const u8 {
    if (cache.getValue(pid)) |name| {
        return name;
    }

    var buffer = [_]u8{0} ** 30;
    var fbs = std.io.fixedBufferStream(buffer[0..]);
    try std.fmt.format(fbs.outStream(), "/proc/{}/comm", .{pid});

    const fd = try std.os.open(buffer[0..fbs.pos], 0, os.O_RDONLY);
    defer std.os.close(fd);

    var chars = try std.os.read(fd, buffer[0..]);
    // Remove trailing newlines or spaces
    while (chars > 0 and (buffer[chars - 1] == '\n' or buffer[chars - 1] == ' ')) chars -= 1;
    var name = try allocator.alloc(u8, chars);
    std.mem.copy(u8, name, buffer[0..chars]);

    _ = try cache.put(pid, name);
    return name;
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
    warn("{} ( ", .{enumName(context.registers.syscall)});
    warn("{}, ", .{context.registers.arg1});
    warn("{}, ", .{context.registers.arg2});
    warn("{}, ", .{context.registers.arg3});
    warn("{}", .{context.registers.arg4});
    warn(" ) = ", .{});
    warn("{}\n", .{@intCast(isize, context.registers.result)});
}
