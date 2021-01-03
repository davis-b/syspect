const std = @import("std");
const index = @import("../index.zig");
const events = @import("events");
const waitpid = @import("waitpid");
const WaitResult = waitpid.WaitResult;

const Status = struct {
    const normal = try waitpid.interpret_status(34175);
    const exit = try waitpid.interpret_status(0);

    // these are related to clone andmaybe futex;
    const stop = try waitpid.interpret_status(4991);
    // TODO find difference in how these numbers are generated,
    //  and what they mean.
    // They both end up as sigtrap,
    //  but what other information do they contain?
    const sigtrap = try waitpid.interpret_status(198015);
    const sigtrap2 = try waitpid.interpret_status(66943);
};

const EventInfo = struct {
    wait_result: WaitResult, // pid: int, status: int
    syscall: std.os.SYS,
    expected_action: events.EventAction,
};

test "clone and futex" {
    const allocator = std.testing.allocator;

    var tmap = events.TraceeMap.init(allocator);
    defer tmap.deinit();
    var context = events.Context{ .pid = undefined, .registers = undefined };
    const inspections = events.Inspections{
        .calls = &[_]std.os.SYS{ .fork, .getpid },
    };

    const test_events = [_]EventInfo{
        .{ .wait_result = .{ .pid = 2, .status = Status.normal }, .syscall = .clone, .expected_action = .INSPECT },
        .{ .wait_result = .{ .pid = 2, .status = Status.sigtrap2 }, .syscall = .clone, .expected_action = .CONT },

        .{ .wait_result = .{ .pid = 3, .status = Status.stop }, .syscall = .clone, .expected_action = .CONT },

        .{ .wait_result = .{ .pid = 2, .status = Status.normal }, .syscall = .wait4, .expected_action = .NORMAL },
    };

    for (test_events) |ei| {
        // std.debug.warn("ei: {}\n", .{ei});
        // Set orig_rax result of future "ptrace.getregs()" calls.
        index.ptrace.orig_rax = @enumToInt(ei.syscall);

        const action = try events.handle_wait_result(ei.wait_result, &tmap, &context, inspections);
        if (action == .INSPECT) {
            try events.resume_from_inspection(&tmap, context.pid);
        }

        std.testing.expectEqual(ei.expected_action, action);
        std.testing.expectEqual(@enumToInt(ei.syscall), context.registers.orig_syscall);
        std.testing.expectEqual(ei.wait_result.pid, context.pid);
    }
}

// TODO

// Check out Group-stop man page, especially the PTRACE_LISTEN portion.

// Also from man page of ptrace(2)
//    PTRACE_EVENT stops
//         If the tracer sets PTRACE_O_TRACE_* options, the tracee will enter ptrace-stops called PTRACE_EVENT stops.
//
//         PTRACE_EVENT  stops  are  observed  by  the tracer as waitpid(2) returning with WIFSTOPPED(status), and WSTOPSIG(status) returns SIGTRAP.  An additional bit is set in the
//         higher byte of the status word: the value status>>8 will be
//
//             (SIGTRAP | PTRACE_EVENT_foo << 8).
//
//         The following events exist: [...]
//
//         PTRACE_EVENT_FORK
//                Stop before return from fork(2) or clone(2) with the exit signal set to SIGCHLD.
//
//         PTRACE_EVENT_CLONE
//                Stop before return from clone(2).

// We might not be adding tracee's to the tracee_map on clone/thread/etc
// This guess is based on .EXIT being returned by next_event when we clone.
// Either that, or we are not properly handling the clone call, possibly related to the above man page excerpt

// TODO
// Fix issue in multithreaded/multiprocess environment where program stalls
// Known states of occurrance:

//  [12805] starting clone
//  > [12805] has received signal Signal.trap
//  > [12805] Resuming process without changing tracee state
//  [12805] finished clone
//  > [12806] has received signal Signal.stop
//  > [12806] Resuming process without changing tracee state
//  [12806] [... finish at least some work ...]
//  [12805] starting futex
//  ^C

//  [12808] starting clone
//  > [12808] has received signal Signal.trap
//  > [12808] Resuming process without changing tracee state
//  [12808] finished clone
//  > [12809] has received signal Signal.stop
//  > [12809] Resuming process without changing tracee state
//  [12808] starting futex // This is where, I suspect, main thread waits on alt thread. Maybe alt thread has not properly started
//  ^C
