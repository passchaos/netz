const std = @import("std");
const builtin = @import("builtin");
const zio = @import("zio");
const tcp = @import("../tcp_connect.zig");
const checks = @import("../network_interface_test_support.zig");
const net = std.Io.net;

test "TCP network interface survives ordered and Happy Eyeballs fallback" {
    if (!checks.supportedTcp()) return error.SkipZigTest;
    var backend = try zio.Runtime.init(std.testing.allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    var refused = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
    const refused_address = refused.socket.address;
    refused.deinit(io);
    const local = net.IpAddress{ .ip4 = .loopback(0) };
    const binding: tcp.Binding = .{ .local_address = local, .network_interface = checks.loopback() };
    inline for (.{ tcp.AddressConnectPolicy.ordered, tcp.AddressConnectPolicy{ .happy_eyeballs = .{ .attempt_delay = .fromMilliseconds(1) } } }) |policy| {
        const stream = try tcp.resolvedWithOptions(std.testing.allocator, io, &.{ .{ .ip6 = .loopback(listener.socket.address.getPort()) }, refused_address, listener.socket.address }, .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }), policy, binding);
        defer stream.close(io);
        const accepted = try listener.accept(io);
        defer accepted.close(io);
        try checks.expectBound(io, stream.socket);
        try std.testing.expectEqualSlices(u8, &local.ip4.bytes, &accepted.socket.address.ip4.bytes);
        try std.testing.expectEqual(stream.socket.address.getPort(), accepted.socket.address.getPort());
        try @import("../stream_io.zig").writeAllParts(io, stream, "bound", "");
        var reader = accepted.reader(io, &.{});
        var buffer: [5]u8 = undefined;
        try reader.interface.readSliceAll(&buffer);
        try std.testing.expectEqualStrings("bound", &buffer);
    }
}

test "TCP network interface rejects unsupported backend and expired deadline" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const binding: tcp.Binding = .{ .network_interface = checks.loopback() };
    try std.testing.expectError(error.OptionUnsupported, tcp.ipWithOptions(threaded.io(), .{ .ip4 = .loopback(1) }, null, binding));
    try std.testing.expectError(error.Timeout, tcp.ipWithDeadlineAndOptions(threaded.io(), .{ .ip4 = .loopback(1) }, .{ .clock = .awake, .raw = .zero }, binding));
    try std.testing.expectError(error.OptionUnsupported, tcp.validateUnixOptions(binding));
    if (comptime builtin.os.tag == .windows) {
        var backend = try zio.Runtime.init(std.testing.allocator, .{});
        defer backend.deinit();
        try std.testing.expectError(error.OptionUnsupported, tcp.ipWithOptions(backend.io(), .{ .ip4 = .loopback(1) }, null, binding));
    }
}

test "TCP network interface name and resolved index constrain IPv6 and hostname sockets" {
    if (!checks.supportedTcp()) return error.SkipZigTest;
    var backend = try zio.Runtime.init(std.testing.allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    var listener = try (net.IpAddress{ .ip6 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const index = (try checks.loopback().resolve(io)).index;
    const binding: tcp.Binding = .{ .local_address = .{ .ip6 = .loopback(0) }, .network_interface = .{ .index = index } };
    const stream = try tcp.hostWithOptions(io, try net.HostName.init("localhost"), listener.socket.address.getPort(), .fromSeconds(2), binding);
    defer stream.close(io);
    const accepted = try listener.accept(io);
    defer accepted.close(io);
    try checks.expectBound(io, stream.socket);
    try std.testing.expectEqual(stream.socket.address.getPort(), accepted.socket.address.getPort());
}
