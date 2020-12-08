const std = @import("std");
const os = std.os;
const warn = std.debug.warn;
const thread = std.Thread;

pub fn main() anyerror!void {
    getTid(0);
    const thread1 = try thread.spawn(@as(u8, 1), getTid);
    thread1.wait();
    getTid(2);
}

fn getTid(arg: u8) void {
    const tid = os.linux.gettid();
}
