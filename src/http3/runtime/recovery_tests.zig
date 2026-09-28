const std = @import("std");
const runtime = @import("../runtime.zig");
const quic = @import("../../quic/mod.zig");

test "HTTP/3 client recovery drain ignores pure receive credit" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{
        0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
    };
    const client_cid = [_]u8{ 0x89, 0x8a, 0x8b, 0x8c };
    const server_cid = [_]u8{ 0x8d, 0x8e, 0x8f, 0x90 };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .initial_one_rtt_config = .{
                .max_datagram_size = 1400,
                .enable_pacing = false,
            },
            .random = [_]u8{0x91} ** 32,
            .x25519_secret_key = [_]u8{0x92} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        io: std.Io,
        response_sent: std.Io.Event = .unset,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.response_sent.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            var request = try session.receiveRequest();
            defer request.deinit(allocator);
            try session.sendResponse(request.stream_id, .{
                .status = 200,
                .body = "ready",
            });
            self.response_sent.set(self.io);
            try self.release.wait(self.io);
        }
    };
    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer {
        shared.release.set(io);
        if (!joined) thread.join();
    }

    var client = try runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .initial_one_rtt_config = .{
                .max_datagram_size = 1400,
                .enable_pacing = false,
            },
            .random = [_]u8{0x93} ** 32,
            .x25519_secret_key = [_]u8{0x94} ** 32,
        } },
    );
    defer client.deinit();

    var response = try client.requestWithTimeout(.{
        .method = "GET",
        .path = "/credit-only-recovery",
        .authority = "localhost",
    }, .fromSeconds(2));
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("ready", response.response.body);
    try shared.response_sent.wait(io);
    if (shared.err) |err| return err;
    try std.testing.expectEqual(
        @as(usize, 0),
        client.established.connection.pendingRecoveryCount(),
    );

    try client.established.connection.send(&.{.{
        .max_data = .{ .maximum_data = quic.varint.max_value },
    }});
    try std.testing.expect(
        client.established.connection.pendingRecoveryCount() != 0,
    );
    try std.testing.expect(
        !client.established.connection.pendingDeliveryRecovery(),
    );

    try client.waitForRecoveryIdleWithTimeout(.fromMilliseconds(20));
    try std.testing.expect(
        client.established.connection.pendingRecoveryCount() != 0,
    );

    shared.release.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
