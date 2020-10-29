const std = @import("std");
const os = std.os;

pub const WaitResult = struct {
    pid: os.pid_t,
    status: Status,
};

pub const Status = union(enum) {
    exit: u32,
    kill: u32,
    stop: Signal,
};

// Signal delivered on syscalls.
// Would otherwise be a regular SIGTRAP if the caller does not set PTRACE_O_TRACESYSGOOD.
// It is important that users of the "events.zig" code ensure that option has been set.
//  The "events.zig" code will only be treating SIGTRAP and PTRACE_SIGTRAP differently.
const PTRACE_SIGTRAP = os.SIGTRAP | 0x80;

const Signal = extern enum {
    hup = os.SIGHUP,
    int = os.SIGINT,
    quit = os.SIGQUIT,
    ill = os.SIGILL,
    trap = os.SIGTRAP,
    abrt = os.SIGABRT,
    iot = os.SIGIOT,
    bus = os.SIGBUS,
    fpe = os.SIGFPE,
    kill = os.SIGKILL,
    usr1 = os.SIGUSR1,
    segv = os.SIGSEGV,
    usr2 = os.SIGUSR2,
    pipe = os.SIGPIPE,
    alrm = os.SIGALRM,
    term = os.SIGTERM,
    stkflt = os.SIGSTKFLT,
    chld = os.SIGCHLD,
    cont = os.SIGCONT,
    stop = os.SIGSTOP,
    tstp = os.SIGTSTP,
    ttin = os.SIGTTIN,
    ttou = os.SIGTTOU,
    urg = os.SIGURG,
    xcpu = os.SIGXCPU,
    xfsz = os.SIGXFSZ,
    vtalrm = os.SIGVTALRM,
    prof = os.SIGPROF,
    winch = os.SIGWINCH,
    io = os.SIGIO,
    poll = os.SIGPOLL,
    pwr = os.SIGPWR,
    sys = os.SIGSYS,
    unused = os.SIGUNUSED,

    ptrace_trap = os.SIGTRAP | 0x80,
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
        const signal = @intToEnum(Signal, @intCast(c_int, os.WSTOPSIG(wstatus)));
        return Status{ .stop = signal };
    }
    @panic("Unrecognized status. 'interpret_status' fn not finished.");
    // return error.UnrecognizedStatus;
    // os.WIFCONTINUED does not exist in x86_64-linux zig std library. We will try ignoring it for now.
}
