const std = @import("std");
const os = std.os;

const c = @import("c.zig");

// From the man page:

// The data to be transferred  is  identified  by  remote_iov  and  riovcnt:
// remote_iov is a pointer to an array describing address ranges in the process pid,

// The data is transferred to the locations specified by local_iov and liovcnt:
// local_iov is a pointer to an array describing address ranges in the calling process,
pub fn readv(pid: os.pid_t, buffer: []u8, remote_addr: usize, read_len: usize) !usize {
    var local_iov = c.iovec{ .iov_base = @ptrCast(*c_void, buffer), .iov_len = read_len };
    var remote_iov = c.iovec{ .iov_base = @intToPtr(*c_void, remote_addr), .iov_len = read_len };

    var write_arr = [_]c.iovec{local_iov};
    var read_arr = [_]c.iovec{remote_iov};

    // These two values could be different from each other.
    // However, for our purposes, this is sufficient.
    const liovcnt: c_ulong = write_arr.len;
    const riovcnt: c_ulong = read_arr.len;

    const result = os.linux.syscall6(
        os.SYS.process_vm_readv,
        @intCast(usize, pid),
        // @ptrToInt(&local_iov),
        @ptrToInt(&write_arr),
        liovcnt,
        // @ptrToInt(&remote_iov),
        @ptrToInt(&read_arr),
        riovcnt,
        0,
    );
    try handleError(result);
    return result;
}

pub fn writev(pid: os.pid_t, buffer: []u8, remote_addr: usize, read_len: usize) !usize {
    var local_iov = c.iovec{ .iov_base = @ptrCast(*c_void, buffer), .iov_len = read_len };
    var remote_iov = c.iovec{ .iov_base = @intToPtr(*c_void, remote_addr), .iov_len = read_len };

    var read_arr = [_]c.iovec{local_iov};
    var write_arr = [_]c.iovec{remote_iov};

    // These two values could be different from each other.
    // However, for our purposes, this is sufficient.
    const liovcnt: c_ulong = write_arr.len;
    const riovcnt: c_ulong = read_arr.len;

    const result = os.linux.syscall6(
        os.SYS.process_vm_readv,
        @intCast(usize, pid),
        @ptrToInt(&read_arr),
        liovcnt,
        @ptrToInt(&write_arr),
        riovcnt,
        0,
    );
    try handleError(result);
    return result;
}

fn handleError(result: usize) !void {
    const err = os.errno(result);
    return switch (err) {
        0 => {},
        os.EFAULT => error.InvalidMemorySpace,
        os.EINVAL => error.EINVAL,
        os.ENOMEM => error.MemoryError,
        os.EPERM => error.InsufficientPermission,
        os.ESRCH => error.NoPIDExists,
        else => error.UnknownPVReadvError,
    };
}
