const std = @import("std");
const net = std.net;

pub fn main() !void {
    var argv_len: usize = 0;
    for (std.os.argv) |_| argv_len += 1;

    var port: u16 = undefined;
    if (argv_len == 1) {
        port = 9885;
    } else {
        const str_port = std.mem.span(std.os.argv[1]);
        port = try std.fmt.parseInt(u16, str_port, 10);
    }
    const addr = try net.Address.parseIp("127.0.0.1", port);

    var server = net.StreamServer.init(.{ .reuse_address = true });
    defer server.deinit();
    try server.listen(addr);
    defer server.close();

    const connection = try server.accept();
    std.debug.warn("connected! {}\n", .{connection});
}
