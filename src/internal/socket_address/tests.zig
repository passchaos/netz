const std = @import("std");
const socket_address = @import("../socket_address.zig");
const net = std.Io.net;

fn checkPair(io: std.Io, address: net.IpAddress) !void {
    var listener = address.listen(io, .{ .reuse_address = true }) catch |err| switch (err) {
        error.AddressFamilyUnsupported, error.AddressUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer listener.deinit(io);
    const client = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    const server = try listener.accept(io);
    defer server.close(io);

    const server_peer = socket_address.accepted(server).?;
    try std.testing.expect(server_peer.getPort() != listener.socket.address.getPort());
    if (@import("builtin").os.tag == .windows) {
        try std.testing.expect(socket_address.connected(client) == null);
        return;
    }
    try std.testing.expect(listener.socket.address.eql(&socket_address.connected(client).?));
    try std.testing.expect(server_peer.eql(&socket_address.connected(server).?));
    // Querying metadata must preserve std.Io's local sockname on the client.
    try std.testing.expectEqual(client.socket.address.getPort(), server_peer.getPort());
}

test "socket peer address distinguishes both ends of IPv4 and IPv6 TCP" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try checkPair(threaded.io(), .{ .ip4 = .loopback(0) });
    try checkPair(threaded.io(), .{ .ip6 = .loopback(0) });
}

test "socket peer address excludes Unix streams" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var storage: [std.fs.max_path_bytes]u8 = undefined;
    const directory_length = try tmp.dir.realPath(io, &storage);
    const suffix = try std.fmt.bufPrint(storage[directory_length..], "/peer.sock", .{});
    const path = storage[0 .. directory_length + suffix.len];
    const address = try net.UnixAddress.init(path);
    var listener = try address.listen(io, .{});
    defer {
        listener.deinit(io);
        std.Io.Dir.deleteFileAbsolute(io, path) catch {};
    }
    const client = try address.connect(io);
    defer client.close(io);
    const server = try listener.accept(io);
    defer server.close(io);
    try std.testing.expect(socket_address.connected(client) == null);
    try std.testing.expect(socket_address.connected(server) == null);
    try std.testing.expect(socket_address.accepted(server) == null);
}

test "socket peer address is absent on an unconnected socket" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const socket = try (net.IpAddress{ .ip4 = .loopback(0) }).bind(io, .{ .mode = .stream });
    defer socket.close(io);
    try std.testing.expect(socket_address.connected(.{ .socket = socket }) == null);
}
