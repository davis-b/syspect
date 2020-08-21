const std = @import("std");
const os = std.os;

pub const WaitResult = struct {
    pid: os.pid_t,
    status: u32,
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
    return WaitResult{ .pid = @intCast(os.pid_t, pid_from_wait), .status = status };
}

// using this because os.WIFSTOPPED resulted in @intCast truncation errors
pub fn WIFSTOPPED(status: c_int) bool {
    return (status & 0xff) == 0x7f;
}
