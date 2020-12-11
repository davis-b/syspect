const std = @import("std");
const os = std.os;
const warn = std.debug.warn;

// How this should appear from a ptracing program:
// pid - syscall
// 0 - sigprocmask
// 0 - gettid
// 0 - fork
// 0 - kill | waitpid || 1 - gettid | rt_sigtimedwait
// 0 - gettid
pub fn main() anyerror!void {
    // Ignore SIGUSR1 until we specifically wait for it in child fork later on
    var mask = os.linux.empty_sigset;
    sigaddset(&mask, os.SIGUSR1);
    const sigproc_result = os.linux.sigprocmask(os.SIG_BLOCK, &mask, null);
    if (sigproc_result != 0) @panic("sigproc error");

    const original_parent_pid = os.linux.gettid();
    const pid = try os.fork();

    const signal = os.SIGUSR1;
    if (pid == 0) {
        wait_for_signal(signal);
    } else {
        try os.kill(pid, signal);
        const wstatus = os.waitpid(pid, 0);
        std.testing.expect(os.WIFEXITED(wstatus));
        std.testing.expectEqual(@as(u32, 2), os.WEXITSTATUS(wstatus));
        _ = os.linux.gettid();
    }
}

fn wait_for_signal(signal: u6) void {
    _ = os.linux.gettid();

    var mask = os.linux.empty_sigset;
    sigaddset(&mask, signal);

    const sigsetsize = os.linux.NSIG / 8;
    var info: os.linux.siginfo_t = undefined;
    var timeout = os.linux.timespec{
        .tv_sec = 3,
        .tv_nsec = 0,
    };
    const status = @intCast(c_int, os.linux.syscall4(.rt_sigtimedwait, @ptrToInt(&mask), @ptrToInt(&info), @ptrToInt(&timeout), sigsetsize));
    if (status < 0) @panic("child spent too much time waiting for signal!");
    if (status != signal) {
        @panic("child received incorrect signal!\n");
    }
    os.exit(2);
}

/// Copied from zig version "0.6.0+ed357f989" std library.
/// Reason: 0.6.0's sigaddset fn results in a compile error.
const usize_bits = @typeInfo(usize).Int.bits;
pub fn sigaddset(set: *os.sigset_t, sig: u6) void {
    const s = sig - 1;
    const shift = @intCast(u5, s & (usize_bits - 1));
    const val = @intCast(u32, 1) << shift;
    (set.*)[@intCast(usize, s) / usize_bits] |= val;
}
