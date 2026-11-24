const std = @import("std");
const http = @import("../mod.zig");
const http1 = @import("../../http1/runtime.zig");
const http2 = @import("../../http2/runtime.zig");
const zio = @import("zio");

fn checkPeerAddresses(io: std.Io, address: std.Io.net.IpAddress) !void {
    const allocator = std.testing.allocator;
    var listener = address.listen(io, .{ .reuse_address = true }) catch |err| switch (err) {
        error.AddressFamilyUnsupported, error.AddressUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    var h1 = http.Connection{
        .allocator = allocator,
        .value = .{ .http1 = try http1.Client.adoptStream(allocator, io, client_stream, "local.test", .{}) },
    };
    defer h1.close();
    var accepted = http1.Connection{
        .io = io,
        .allocator = allocator,
        .stream = try listener.accept(io),
    };
    defer accepted.close();

    const before = client_stream.socket.address;
    const peer = h1.peerAddress();
    if (@import("builtin").os.tag == .windows) {
        try std.testing.expect(peer == null);
        return;
    }
    try std.testing.expect(peer.?.eql(&listener.socket.address));
    try std.testing.expect(accepted.peerAddress().?.getPort() != peer.?.getPort());
    // The facade reads metadata without consuming HTTP bytes or changing std's
    // recorded endpoint. Repeat queries remain allocation-free.
    try std.testing.expect(before.eql(&h1.value.http1.stream.socket.address));
    try std.testing.expectEqual(@as(usize, 0), h1.value.http1.inbuf.items.len);

    // Borrow the same live stream to exercise the HTTP/2 branch without
    // transferring its ownership or emitting a preface.
    const h2 = http.Connection{
        .allocator = allocator,
        .value = .{ .http2 = http2.Connection{
            .io = io,
            .allocator = allocator,
            .stream = client_stream,
            .role = .client,
        } },
    };
    try std.testing.expect(h2.peerAddress().?.eql(&peer.?));
    try std.testing.expect(h2.peerAddress().?.getPort() != accepted.peerAddress().?.getPort());
}

test "unified HTTP peer address reports the remote IPv4 and IPv6 endpoint" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try checkPeerAddresses(threaded.io(), .{ .ip4 = .loopback(0) });
    try checkPeerAddresses(threaded.io(), .{ .ip6 = .loopback(0) });
}

test "unified HTTP peer address works with zio streams" {
    var backend = try zio.Runtime.init(std.testing.allocator, .{});
    defer backend.deinit();
    try checkPeerAddresses(backend.io(), .{ .ip4 = .loopback(0) });
    try checkPeerAddresses(backend.io(), .{ .ip6 = .loopback(0) });
}
