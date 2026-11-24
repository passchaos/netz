const std = @import("std");
const builtin = @import("builtin");
const zio = @import("zio");
const runtime = @import("../runtime.zig");
const checks = @import("../../internal/network_interface_test_support.zig");
const net = std.Io.net;

test "QUIC network interface binds IPv4 and IPv6 send and receive sockets" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos and builtin.os.tag != .windows) return error.SkipZigTest;
    var backend = try zio.Runtime.init(std.testing.allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    inline for (.{ net.IpAddress{ .ip4 = .loopback(0) }, net.IpAddress{ .ip6 = .loopback(0) } }) |local| {
        const index = (try checks.loopback().resolve(io)).index;
        var server = try runtime.Server.bind(std.testing.allocator, io, local, .{ .network_interface = checks.loopback() });
        defer server.deinit();
        var client = try runtime.Client.connect(std.testing.allocator, io, local, server.address(), .{ .network_interface = .{ .index = index } });
        defer client.deinit();
        try checks.expectBound(io, server.endpoint.socket);
        try checks.expectBound(io, client.endpoint.socket);
        try client.sendFrames(&.{.{ .ping = {} }});
        var request = try server.receiveWithDeadline(.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
        defer request.deinit(std.testing.allocator);
        try std.testing.expect(request.frames[0] == .ping);
        try server.sendFrames(request.from, &.{.{ .ping = {} }});
        var response = try client.receiveWithDeadline(.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
        defer response.deinit(std.testing.allocator);
        try std.testing.expect(response.frames[0] == .ping);
    }
}

test "QUIC network interface rejects invalid configuration without leaking sockets" {
    var backend = try zio.Runtime.init(std.testing.allocator, .{});
    defer backend.deinit();
    inline for (.{ @import("../../runtime.zig").NetworkInterface{ .name = "" }, @import("../../runtime.zig").NetworkInterface{ .index = 0 } }) |interface| {
        try std.testing.expectError(error.InvalidNetworkInterface, runtime.Endpoint.bind(std.testing.allocator, backend.io(), .{ .ip4 = .loopback(0) }, .{ .network_interface = interface }));
    }
}

test "QUIC network interface rejects foreign backends before UDP bind" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(error.OptionUnsupported, runtime.Endpoint.bind(std.testing.allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{ .network_interface = checks.loopback() }));
}
