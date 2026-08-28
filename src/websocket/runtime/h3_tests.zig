const std = @import("std");
const websocket = @import("../mod.zig");
const h3 = @import("h3.zig");
const http3 = @import("../../http3/mod.zig");

test "WebSocket over HTTP3 extended CONNECT exchanges frames" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    const client_cid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3 };
    const server_cid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3 };
    const request_text = "hello over h3 hello over h3 hello over h3 hello over h3";
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xc4} ** 32,
                .x25519_secret_key = [_]u8{0xc5} ** 32,
            },
            .session = .{ .max_stream_frame_data = 5 },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *h3.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{
                .protocols = &.{"chat"},
                .allowed_origins = &.{"https://example.test"},
                .enable_permessage_deflate = true,
                .compression_threshold = 1,
            });
            defer connection.deinit();
            try std.testing.expectEqualStrings(
                "chat",
                connection.selectedProtocol().?,
            );
            try std.testing.expectEqualStrings(
                "h3",
                connection.negotiatedAlpn(),
            );
            try std.testing.expect(connection.permessage_deflate);

            var text = try connection.receiveMessageWithTimeout(
                .fromSeconds(5),
            );
            defer text.deinit(allocator);
            try std.testing.expectEqual(websocket.Opcode.text, text.opcode);
            try std.testing.expectEqualStrings(request_text, text.payload);
            try std.testing.expect(text.was_compressed);
            try connection.sendText("hello client");

            var ping = try connection.receiveFrameWithTimeout(
                .fromSeconds(5),
            );
            defer ping.deinit(allocator);
            try std.testing.expectEqual(websocket.Opcode.ping, ping.header.opcode);
            try std.testing.expectEqualStrings("probe", ping.payload);

            var close = try connection.receiveFrameWithTimeout(
                .fromSeconds(5),
            );
            defer close.deinit(allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
            const parsed = (try websocket.parseClosePayload(close.payload)).?;
            try std.testing.expectEqual(websocket.CloseCode.normal_closure, parsed.code);
            try std.testing.expectEqualStrings("done", parsed.reason);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xc2} ** 32,
                .x25519_secret_key = [_]u8{0xc3} ** 32,
            },
            .session = .{ .max_stream_frame_data = 5 },
        },
        .{
            .authority = "localhost",
            .path = "/chat",
            .origin = "https://example.test",
            .protocols = &.{"chat"},
            .enable_permessage_deflate = true,
            .compression_threshold = 1,
        },
    );
    defer client.deinit();
    try std.testing.expectEqualStrings("chat", client.selectedProtocol().?);
    try std.testing.expectEqualStrings("h3", client.negotiatedAlpn());
    try std.testing.expect(client.permessage_deflate);

    try client.sendFragmented(.text, &.{
        request_text[0..20],
        request_text[20..],
    });
    var reply = try client.receiveFrameWithTimeout(.fromSeconds(5));
    defer reply.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, reply.header.opcode);
    try std.testing.expectEqualStrings("hello client", reply.payload);
    try client.sendPing("probe");
    var pong = try client.receiveFrameWithTimeout(.fromSeconds(5));
    defer pong.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
    try std.testing.expectEqualStrings("probe", pong.payload);
    try client.sendClose(.normal_closure, "done");
    var close = try client.receiveFrameWithTimeout(.fromSeconds(5));
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP3 validates reserved handshake metadata" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const client_cid = [_]u8{ 0xe0, 0xe1, 0xe2, 0xe3 };
    const server_cid = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3 };
    const limits: http3.runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try h3.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xf4} ** 32,
            .x25519_secret_key = [_]u8{0xf5} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *h3.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.transport.accept() catch |err| {
                self.err = err;
                return;
            };
            connection.deinit();
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    try std.testing.expectError(
        error.InvalidHandshake,
        h3.Client.connect(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            limits,
            .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xf2} ** 32,
                .x25519_secret_key = [_]u8{0xf3} ** 32,
            } },
            .{
                .authority = "localhost",
                .extra_headers = &.{.{
                    .name = "sec-websocket-version",
                    .value = "12",
                }},
            },
        ),
    );
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
