const std = @import("std");
const net = std.net;

pub fn main() !void {
    const ip = "127.0.0.1";
    connect(.{ .ip = ip, .port = 9885 });
    var ctx = Ctx{ .ip = ip, .port = 9887 };
    for ([_]u1{0} ** 3) |_| {
        ctx.port += 1;
        var t = try std.Thread.spawn(ctx, connect);
        t.wait();
    }
}

const Ctx = struct {
    ip: []const u8,
    port: u16,
};

fn connect(ctx: Ctx) void {
    const addr = net.Address.parseIp(ctx.ip, ctx.port) catch return;
    const connection = net.tcpConnectToAddress(addr) catch null;
    // std.debug.warn("client addr: {}\n", .{addr.in});
}
