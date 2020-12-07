const std = @import("std");
const os = std.os;
const warn = std.debug.warn;

pub fn main() anyerror!void {
    const original_parent_tid = os.linux.gettid();
    const tid = try os.fork();

    if (tid == 0) {
        const child_tid = os.linux.gettid();
        os.exit(2);
    } else {
        while (true) {
            const status = os.waitpid(tid, 0);
            if (os.WIFEXITED(status)) {
                break;
            }
        }
        const parent_tid = os.linux.gettid();
    }
}
