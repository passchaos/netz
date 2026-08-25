const std = @import("std");
const runtime = @import("../runtime.zig");

test "WebTransport connection close is distinct from session close" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid =
        [_]u8{ 0x57, 0x54, 0xc0, 0x01, 0x57, 0x54, 0xc0, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0xc0, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0xc0, 0x04 };

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xc3} ** 32,
            .x25519_secret_key = [_]u8{0xc4} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            const close = try session.receivePeerConnectionClose();
            switch (close) {
                .application => |application| {
                    try std.testing.expectEqual(
                        @as(u64, 0x4242),
                        application.error_code,
                    );
                    try std.testing.expectEqualStrings(
                        "connection done",
                        application.reason_phrase,
                    );
                },
                .transport => return error.UnexpectedConnectionClose,
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/connection-close",
            .h3 = .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xc1} ** 32,
                .x25519_secret_key = [_]u8{0xc2} ** 32,
            } },
        },
    );
    defer client.deinit();
    try client.closeConnection(0x4242, "connection done");
    try std.testing.expectError(
        error.ConnectionClosed,
        client.sendDatagram("too late"),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport connection close bounds retained reason text" {
    var client: runtime.HandshakeClientSession = undefined;
    const oversized = [_]u8{'x'} ** (runtime.max_connection_close_reason + 1);
    try std.testing.expectError(
        error.InvalidSessionState,
        client.closeConnection(1, &oversized),
    );
}
