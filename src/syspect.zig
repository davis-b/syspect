// Notice: This program only works on x86_64 linux.
// It can be patched to work on other architectures.
//  However, it would require a redesign to work on Windows.

const std = @import("std");
const os = std.os;

const ptrace = @import("ptrace.zig");
const c = @import("c.zig");
const events = @import("events.zig");

pub const Context = events.Context;

pub const Options = struct {
    multithread: bool = true,
    inverse: bool = false,
};

/// Intercepts syscalls, filtering them as the caller sees fit.
/// Expected use:
///
///     var inspector = syspect.Inspector.init(allocator, options, &[_]os.SYS{ .connect });
///     defer inspector.deinit();
///
///     while (try inspector.next_syscall()) |*context| {
///         warn("{} attempting syscall with registers {}\n", .{context.pid, context.registers});
///         // work with registers or process here [...]
///         inspector.finish_syscall(context);
///     }
pub const Inspector = struct {
    syscalls: []const os.SYS,
    multithread: bool,
    inverse: bool,
    tracee_map: events.TraceeMap,

    pub fn init(allocator: *std.mem.Allocator, options: Options, syscalls: []const os.SYS) Inspector {
        return Inspector{
            .syscalls = syscalls,
            .multithread = options.multithread,
            .inverse = options.inverse,
            .tracee_map = events.TraceeMap.init(allocator),
        };
    }

    pub fn deinit(self: *Inspector) void {
        self.tracee_map.deinit();
    }

    pub fn spawn_process(self: *Inspector, allocator: *std.mem.Allocator, argv: [][]const u8) !void {
        const tracee_pid = try fork_spawn_process(allocator, argv);

        var opts = c.PTRACE_O_EXITKILL;
        // TODO Further research these two options
        opts |= c.PTRACE_O_TRACESYSGOOD | c.PTRACE_O_TRACEEXEC;
        if (self.multithread) opts |= c.PTRACE_O_TRACEFORK | c.PTRACE_O_TRACECLONE;
        _ = try ptrace.ptrace(c.PTRACE_SETOPTIONS, tracee_pid, 0, opts);

        _ = try events.get_or_make_tracee(&self.tracee_map, tracee_pid);

        // Resume/Set off tracee
        _ = try ptrace.syscall(tracee_pid);
    }

    pub fn attach_to_process(self: *Inspector, pid: os.pid_t) !void {
        @compileLog("Not yet implemented");
    }

    pub fn next_syscall(self: *Inspector) !?events.Context {
        var context = events.Context{
            .pid = undefined,
            .registers = undefined,
        };
        while (true) {
            const action = try events.next_event(&self.tracee_map, &context, .{ .inverse = self.inverse, .calls = self.syscalls });
            switch (action) {
                .CONT => continue,
                .EXIT => return null,
                .INSPECT => {
                    return context;
                },
            }
        }
    }

    /// Executes a syscall that has been inspected.
    /// Updates context.registers with new result.
    pub fn finish_syscall(self: *Inspector, context: *events.Context) !void {
        try events.resume_from_inspection(&self.tracee_map, context);
    }
};

/// Forks and initiates ptrace from the child program.
/// Child then executes the target process.
/// Parent syncs with child, and then returns the child's PID
fn fork_spawn_process(allocator: *std.mem.Allocator, argv: []const []const u8) !os.pid_t {
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
