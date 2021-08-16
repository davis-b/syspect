const std = @import("std");
const os = std.os;

/// This test expects its tracer to nullify our os.kill call and return EPERM error as a result.
pub fn main() anyerror!void {
    // temporary band-aid.
    // Currently we need to run test programs to install them correctly.
    // When doing this, we give them an extra argument signifying they are not currently being tested.
    if (os.argv.len == 2) return;

    const tid = os.linux.gettid();
    _ = os.kill(tid, os.SIGSTOP) catch |err| {
        switch (err) {
            error.PermissionDenied => return,
            else => return err,
        }
    };
    @panic("test failed");
}
