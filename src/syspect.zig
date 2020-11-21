// Notice: This program only works on x86_64 linux.
// It can be patched to work on other architectures.
//  However, it would require a redesign to work on Windows.

const std = @import("std");
const os = std.os;

const index = @import("index.zig");
const ptrace = index.ptrace;
const c = index.c;
const events = @import("events.zig");
const waitpid = @import("waitpid.zig").waitpid;

pub const Context = events.Context;

pub const Options = struct {
    multithread: bool = true,
    inverse: bool = false,
};

/// Intercepts syscalls, filtering them as the caller sees fit.
/// Expected use:
///
///     var inspector = syspect.Inspector.init(allocator, &[_]os.SYS{.connect, .read, .write}, options);
///     defer inspector.deinit();
///
///     const target_argv = &[_][]const u8{ "program to run", "arg for program" };
///     _ = try inspector.spawn_process(allocator, target_argv);
///
///     while (try inspector.next_syscall()) |*syscall| {
///         switch (syscall.*) {
///             .pre_call => |context| {
///                 warn("{} attempting syscall with registers {}\n", .{ context.pid, context.registers });
///
///                 can_modify_registers_here(context);
///
///                 if (do_not_want_block) {
///                     inspector.start_syscall(context);
///                 } else if (block_until_syscall_finishes) {
///                     const maybe_registers = try inspector.start_and_finish_syscall(context);
///                     if (maybe_registers) |regs| {
///                         warn("Syscall result: {}\n", .{regs});
///                     }
///                 } else {
///                     @compileError("One of (start_syscall, start_and_finish_syscall_blocking) must be called to conclude the next_syscall function.");
///                 }
///             },
///             .post_call => |context| {
///                 warn("Syscall result: {}\n", .{context.registers});
///             },
///         }
///     }
pub const Inspector = struct {
    syscalls: []const os.SYS,
    multithread: bool,
    inverse: bool,
    tracee_map: events.TraceeMap,
    has_tracees: bool,

    pub const SyscallContext = union(enum) {
        pre_call: Context,
        post_call: Context,
    };

    pub fn init(allocator: *std.mem.Allocator, syscalls: []const os.SYS, options: Options) Inspector {
        return Inspector{
            .syscalls = syscalls,
            .multithread = options.multithread,
            .inverse = options.inverse,
            .tracee_map = events.TraceeMap.init(allocator),
            .has_tracees = false,
        };
    }

    pub fn deinit(self: *Inspector) void {
        self.tracee_map.deinit();
    }

    pub fn spawn_process(self: *Inspector, allocator: *std.mem.Allocator, argv: []const []const u8) !os.pid_t {
        const tracee_pid = try fork_spawn_process(allocator, argv);

        try self.set_ptrace_options(tracee_pid);

        _ = try events.get_or_make_tracee(&self.tracee_map, tracee_pid);
        self.has_tracees = true;

        // Resume/Set off tracee
        _ = try ptrace.syscall(tracee_pid);

        return tracee_pid;
    }

    fn set_ptrace_options(self: *Inspector, tracee_pid: os.pid_t) !void {
        var opts = c.PTRACE_O_EXITKILL | c.PTRACE_O_TRACESYSGOOD;
        opts |= c.PTRACE_O_TRACEEXEC;
        if (self.multithread) opts |= c.PTRACE_O_TRACEFORK | c.PTRACE_O_TRACECLONE;
        _ = try ptrace.ptrace(c.PTRACE_SETOPTIONS, tracee_pid, 0, opts);
    }

    /// Attach to a running process, setting it as our tracee
    pub fn attach_to_process(self: *Inspector, pid: os.pid_t) !void {
        // Try to attach
        _ = try ptrace.ptrace(c.PTRACE_ATTACH, pid, 0, 0);

        // Wait for tracee to receive STOPSIG
        const wait_result = try waitpid(pid, 0);

        try self.set_ptrace_options(pid);

        // Ensure we are at the spot we're expecting.
        switch (wait_result.status) {
            .stop => |signal| {
                switch (signal) {
                    .stop => {},
                    else => return error.PtraceAttachError,
                }
            },
            else => return error.PtraceAttachError,
        }

        // Resume/Set off tracee
        _ = try ptrace.syscall(pid);

        self.has_tracees = true;
    }

    pub fn next_syscall(self: *Inspector) !?SyscallContext {
        if (!self.has_tracees) return null;

        var context = events.Context{
            .pid = undefined,
            .registers = undefined,
        };
        while (true) {
            const action = try events.next_event(null, &self.tracee_map, &context, .{ .inverse = self.inverse, .calls = self.syscalls });
            switch (action) {
                .CONT, .NORMAL => continue,
                .EXIT => return null,
                .INSPECT => {
                    return SyscallContext{ .pre_call = context };
                },
                .INSPECT_RESULT => {
                    return SyscallContext{ .post_call = context };
                },
            }
        }
    }

    /// Executes a syscall that has been inspected.
    pub fn start_syscall(self: *Inspector, context: events.Context) !void {
        try events.resume_from_inspection(&self.tracee_map, context.pid);
    }

    /// This will block while trying to finish the syscall.
    /// Make sure you are only using this method on non-blocking syscalls.
    /// Executes a syscall that has been inspected and waits for syscall to finish.
    /// Updates context.registers with new result.
    /// If result is null, program has concluded.
    pub fn start_and_finish_syscall_blocking(self: *Inspector, context: events.Context) !?c.user_regs_struct {
        try self.start_syscall(context);
        var new_ctx = context;

        while (true) {
            const action = try events.next_event(context.pid, &self.tracee_map, &new_ctx, .{ .inverse = self.inverse, .calls = self.syscalls });
            switch (action) {
                .CONT => {
                    // If tracee exists, it must have had an unexpected stop that did not kill the process.
                    // Therefore, we want to wait for the next event again until it is the event we expected.
                    if (self.tracee_map.get(context.pid)) |_| {
                        continue;
                    }
                    // Otherwise, the traced process is dead.
                    return null;
                },
                .EXIT => {
                    self.has_tracees = false;
                    return null;
                },
                // NORMAL action means a non-inspected syscall has started or ended.
                // Is this even possible while we're in the middle of a different syscall?
                .NORMAL => continue,
                .INSPECT => @panic("This should not occur. Inspecting a call that should be finished"),
                .INSPECT_RESULT => return new_ctx.registers,
            }
        }
    }
};

/// Forks and initiates ptrace from the child program.
/// Child then executes the target process.
/// Parent syncs with child, and then returns the child's PID
fn fork_spawn_process(allocator: *std.mem.Allocator, argv: []const []const u8) !os.pid_t {
    const child_pid = try os.fork();
    var envmap = try std.process.getEnvMap(allocator);
    defer envmap.deinit();
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
