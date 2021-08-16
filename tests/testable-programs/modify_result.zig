const std = @import("std");
const os = std.os;

pub fn main() anyerror!void {
    // temporary band-aid.
    // Currently we need to run test programs to install them correctly.
    // When doing this, we give them an extra argument signifying they are not currently being tested.
    if (os.argv.len == 2) return;

    const tid = os.linux.gettid();
    const modified = os.linux.gettid();
    try std.testing.expect(tid != modified);
    try std.testing.expect(modified == tid - 1);
}
