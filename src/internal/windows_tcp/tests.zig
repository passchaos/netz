//! Native refusal paths shared by generic and prebound TCP entry points.
const std = @import("std");
const tcp = @import("../tcp_connect.zig");
const zio = @import("zio");
const net = std.Io.net;

fn exercise(io: std.Io, bound: bool) !void {
    var families: usize = 0;
    for ([_]net.IpAddress{ .{ .ip4 = .loopback(0) }, .{ .ip6 = .loopback(0) } }) |local| {
        var listener = local.listen(io, .{}) catch |err| switch (err) {
            error.AddressFamilyUnsupported, error.AddressUnavailable => continue,
            else => return err,
        };
        const refused = listener.socket.address;
        listener.deinit(io);
        // Windows may retry a refused loopback SYN before publishing the
        // refusal. Keep the test's deadline above that platform delay.
        const refusal_budget = std.Io.Duration.fromSeconds(5);
        if (bound)
            try std.testing.expectError(error.ConnectionRefused, tcp.ipBound(io, refused, local, refusal_budget))
        else
            try std.testing.expectError(error.ConnectionRefused, tcp.ip(io, refused, refusal_budget));
        families += 1;
    }
    if (families == 0) return error.SkipZigTest;
}

test "Windows TCP native Threaded refusal remains recoverable for both families" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try exercise(threaded.io(), false);
}

test "Windows TCP native prebound refusal remains recoverable for both families" {
    var runtime = try zio.Runtime.init(std.testing.allocator, .{});
    defer runtime.deinit();
    try exercise(runtime.io(), true);
}
