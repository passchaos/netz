//! Connection-level close budget convenience forms.
const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../runtime.zig");

const net = std.Io.net;

fn cleartextPair(io: std.Io) !struct { sender: net.Stream, peer: net.Stream } {
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const sender = try listener.socket.address.connect(io, .{ .mode = .stream });
    errdefer sender.close(io);
    const peer = try listener.accept(io);
    return .{ .sender = sender, .peer = peer };
}

test "HTTP/2 closeWithTimeout retires the connection on an expired budget" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const pair = try cleartextPair(io);
    defer pair.peer.close(io);

    var connection = runtime.Connection{
        .io = io,
        .allocator = allocator,
        .stream = pair.sender,
        .role = .client,
    };
    try std.testing.expectError(
        error.Timeout,
        connection.closeWithTimeout(.zero),
    );
}

test "HTTP/2 closeWithTimeout closes a cleartext lease" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const pair = try cleartextPair(io);
    defer pair.peer.close(io);

    var connection = runtime.Connection{
        .io = io,
        .allocator = allocator,
        .stream = pair.sender,
        .role = .client,
    };
    try connection.closeWithTimeout(.fromMilliseconds(20));

    var one: [1]u8 = undefined;
    var buffers = [_][]u8{&one};
    const count = try io.vtable.netRead(io.userdata, pair.peer.socket.handle, &buffers);
    try std.testing.expectEqual(@as(usize, 0), count);
}
