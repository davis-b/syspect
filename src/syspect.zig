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
///                 if (block_until_syscall_finishes) {
///                     const maybe_registers = try inspector.start_and_finish_syscall(context.pid);
///                     if (maybe_registers) |regs| {
///                         warn("Syscall result: {}\n", .{regs});
///                     } else {
///                         continue;
///                     }
///                 inspector.resume_tracee(context.pid);
///             },
///             .post_call => |context| {
///                 warn("Syscall result: {}\n", .{context.registers});
///                 // Tracee is paused after finishing the syscall. Resume it here.
///                 inspector.resume_tracee(context)
///             },
///         }
///     }
pub const Inspector = struct {
    /// The syscalls we filter in or out.
    syscalls: []const os.SYS,

    /// If true, our syscalls field is what we filter out.
    /// Otherwise, we ignore syscalls that are not in our syscalls field.
    inverse: bool,

    /// If true, automatically follow child threads and processes.
    multithread: bool,

    /// Stores process info about our tracees.
    /// Maps a pid to an events.Tracee struct.
    tracee_map: events.TraceeMap,

    /// Written to internally. Read internally and externally.
    /// Indicates if the Inspector has at least one active tracee.
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

        // Resume/Set off tracee
        _ = try ptrace.syscall(tracee_pid);

        _ = try events.get_or_make_tracee(&self.tracee_map, tracee_pid);
        self.has_tracees = true;

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

    /// Relinquishes ptrace control of the pid.
    /// Tracee must be in ptrace-stop state when calling this function.
    /// Tracee will be in a ptrace-stop state when next_syscall returns.
    pub fn detach_from_process(self: *Inspector, pid: os.pid_t) !void {
        _ = try ptrace.ptrace(c.PTRACE_DETACH, pid, 0, 0);
        // TODO:
        // Detect tracee state, if it is not in a prace-stop state,
        //  send a signal in order to move it to the required state.
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
                .CONT, .NORMAL, .INSPECT_RESULT_UNKNOWN_SYSCALL => continue,
                .EXIT => {
                    if (self.tracee_map.count() == 0) self.has_tracees = false;
                    return null;
                },
                .INSPECT => {
                    return SyscallContext{ .pre_call = context };
                },
                .INSPECT_RESULT => {
                    return SyscallContext{ .post_call = context };
                },
            }
        }
    }

    /// Resumes Tracee after a syscall or syscall result has been inspected.
    pub fn resume_tracee(self: *Inspector, pid: os.pid_t) !void {
        try events.resume_from_inspection(&self.tracee_map, pid);
    }

    /// This will block while trying to finish the syscall.
    /// Make sure you are only using this method on non-blocking syscalls.
    /// Executes a syscall that has been inspected and waits for syscall to finish.
    /// Returns resulting registers on success.
    /// If result is null, program has concluded.
    pub fn start_and_finish_syscall_blocking(self: *Inspector, context: events.Context) !?c.registers {
        try self.resume_tracee(context.pid);
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
                    if (self.tracee_map.count() == 0) self.has_tracees = false;
                    return null;
                },
                // NORMAL action means a non-inspected syscall has started or ended.
                // Is this even possible while we're in the middle of a different syscall?
                .NORMAL => continue,
                .INSPECT => @panic("This should not occur. Inspecting a call that should be finished"),
                .INSPECT_RESULT => return new_ctx.registers,
                .INSPECT_RESULT_UNKNOWN_SYSCALL => return error.NonExistentSyscall,
            }
        }
    }

    /// Nullifies the syscall, returning an error provided by the caller.
    /// Only works on calls that are in a 'pre_call' state.
    /// When this call finishes successfully, the tracee will have just exited its 'post_call' state.
    pub fn nullify_syscall(self: *Inspector, context: events.Context, errno: c.sregT) !void {
        var newregs = context.registers;
        newregs.syscall = @bitCast(c.regT, @as(c.sregT, -1)); // set syscall identifier to one that doesn't exist
        try ptrace.setregs(context.pid, newregs);

        _ = self.start_and_finish_syscall_blocking(context) catch |err| {
            switch (err) {
                error.NonExistentSyscall => {
                    newregs.syscall = context.registers.syscall;
                    newregs.result = @bitCast(c.regT, -errno);
                    try ptrace.setregs(context.pid, newregs);
                    return;
                },
                else => return err,
            }
        };
        return error.ErrorNullifyingSyscall;
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
