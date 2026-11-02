//! Ordinary health admission against the independent Node HTTP/2 peer.
const std = @import("std");
const netz = @import("netz");

pub fn run(allocator: std.mem.Allocator, io: std.Io, port: u16) !void {
    var channel = try netz.grpc.Channel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(port) } } }, .{ .health_check_service = "demo.Echo" });
    defer channel.deinit();
    const sync = channel.health_sync.?;
    const until: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
    while (true) {
        const generation = sync.snapshot();
        if (channel.healthServingAt(0) == false) break;
        if (until.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
        try sync.wait(io, generation, until);
    }
    try std.testing.expectError(error.ConnectionUnavailable, channel.unary(.{ .path = "/fixture.Health/Echo", .message = "ping", .timeout = .{ .value = 1, .unit = .second } }));
    try std.testing.expectError(error.ConnectionUnavailable, channel.startStreaming(.{ .path = "/fixture.Health/Echo", .timeout = .{ .value = 1, .unit = .second } }));
    try std.testing.expectError(error.ConnectionUnavailable, channel.startDuplex(.{ .path = "/fixture.Health/Echo", .timeout = .{ .value = 1, .unit = .second } }));
    std.debug.print("netz grpc health retry rejected: unary+streaming+duplex\n", .{});
    for (0..2) |_| {
        var response = try channel.unary(.{ .path = "/fixture.Health/Echo", .message = "ping", .wait_for_ready = true, .timeout = .{ .value = 5, .unit = .second } });
        defer response.deinit();
        try std.testing.expectEqual(netz.grpc.Status.ok, response.status);
        try std.testing.expectEqualStrings("pong", response.message.?.payload);
        try std.testing.expectEqual(@as(?bool, true), channel.healthServingAt(0));
    }
    std.debug.print("netz grpc health gate complete: retry+ready+disabled-close calls=2 reuse=true\n", .{});
}
