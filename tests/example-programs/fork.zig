const std = @import("std");
const os = std.os;
const warn = std.debug.warn;

pub fn main() anyerror!void {
    const original_parent_pid = os.linux.getpid();
    const pid = try os.fork();

    if (pid == 0) {
        const child_pid = os.linux.getpid();
        os.exit(2);
    } else {
        const parent_pid = os.linux.getpid();
        while (true) {
            const status = os.waitpid(pid, 0);
            if (os.WIFEXITED(status)) {
                break;
            }
        }
    }
}
