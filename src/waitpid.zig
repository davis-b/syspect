const std = @import("std");
const os = std.os;

pub const WaitResult = struct {
    pid: os.pid_t,
    status: Status,
};

pub const Status = union(enum) {
    exit: u32,
    kill: u32,
    stop: u32,
};

pub fn waitpid(pid: os.pid_t, flags: u32) !WaitResult {
    var status: u32 = 0;
    const pid_from_wait = os.linux.waitpid(pid, &status, flags);
    const err = os.errno(status);
    if (status == -1) {
        switch (err) {
            os.ESRCH => return error.NoSuchProcess,
            else => {
                std.debug.warn("Error number \"{}\"; ", .{err});
                std.debug.warn("Unknown error\n", .{});
                return error.UnknownWaitPidError;
            },
        }
    }
    return WaitResult{ .pid = @intCast(os.pid_t, pid_from_wait), .status = try interpret_status(status) };
}

// Using this because os.WIFSTOPPED resulted in @intCast truncation errors
// Function taken from /usr/include/x86_64-linux-gnu/bits/waitstatus.h
pub fn WIFSTOPPED(wstatus: u32) bool {
    return (wstatus & 0xff) == 0x7f;
}

pub fn interpret_status(wstatus: u32) !Status {
    if (os.WIFEXITED(wstatus)) {
        return Status{ .exit = os.WEXITSTATUS(wstatus) };
    } else if (os.WIFSIGNALED(wstatus)) {
        return Status{ .kill = os.WTERMSIG(wstatus) };
    } else if (WIFSTOPPED(wstatus)) {
        return Status{ .stop = os.WSTOPSIG(wstatus) };
    }
    @panic("Unrecognized status. 'interpret_status' fn not finished.");
    // return error.UnrecognizedStatus;
    // os.WIFCONTINUED does not exist in x86_64-linux zig std library. We will try ignoring it for now.
}
