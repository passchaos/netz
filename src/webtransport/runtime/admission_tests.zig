const std = @import("std");
const http3 = @import("../../http3/mod.zig");
const runtime = @import("../runtime.zig");

fn findHeader(
    headers: []const http3.Qpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

test "WebTransport server admission exposes request and response metadata" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid =
        [_]u8{ 0x57, 0x54, 0xa0, 0x01, 0x57, 0x54, 0xa0, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0xa0, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0xa0, 0x04 };

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xa3} ** 32,
            .x25519_secret_key = [_]u8{0xa4} ** 32,
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
            var pending = try self.server.receiveSessionRequest();
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            try std.testing.expect(std.mem.startsWith(
                u8,
                pending.authority().?,
                "127.0.0.1:",
            ));
            try std.testing.expectEqualStrings(
                "/authorized?room=7",
                pending.path(),
            );
            try std.testing.expectEqualStrings(
                "https://example.test",
                pending.origin().?,
            );
            try std.testing.expectEqualStrings(
                "netz-admission-test",
                pending.userAgent().?,
            );
            try std.testing.expectEqualStrings(
                "Bearer permitted",
                findHeader(pending.headers(), "authorization").?,
            );

            var accepted = try pending.acceptWithHeaders(&.{
                .{ .name = "x-admission", .value = "accepted" },
            });
            pending_owned = false;
            defer accepted.deinit();
            const event = try accepted.receiveSessionEvent();
            try std.testing.expect(event == .closed);
            try std.testing.expectEqual(@as(u32, 71), event.closed.code);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const uri = try std.fmt.allocPrint(
        allocator,
        "https://127.0.0.1:{d}/authorized?room=7",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var client = try runtime.HandshakeClientSession.connectUri(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        uri,
        .{
            .origin = "https://example.test",
            .headers = &.{
                .{ .name = "authorization", .value = "Bearer permitted" },
                .{ .name = "user-agent", .value = "netz-admission-test" },
            },
            .h3 = .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .random = [_]u8{0xa1} ** 32,
                .x25519_secret_key = [_]u8{0xa2} ** 32,
            } },
        },
    );
    defer client.deinit();
    try std.testing.expectEqual(@as(u16, 200), client.response.status);
    try std.testing.expectEqual(client.session_id, client.sessionId());
    try std.testing.expectEqual(server.address(), client.remoteAddress());
    try std.testing.expect(client.remoteAddressValidated());
    try std.testing.expect(client.rttNanos() != null);
    try std.testing.expectEqualStrings(
        "accepted",
        client.responseHeader("x-admission").?,
    );
    try client.close(71, "done");
    const peer_fin = try client.receiveSessionEvent();
    try std.testing.expect(peer_fin == .closed);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport server admission sends explicit rejection response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid =
        [_]u8{ 0x57, 0x54, 0xb0, 0x01, 0x57, 0x54, 0xb0, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0xb0, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0xb0, 0x04 };

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xb3} ** 32,
            .x25519_secret_key = [_]u8{0xb4} ** 32,
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
            var pending = try self.server.receiveSessionRequest();
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            try std.testing.expectEqualStrings(
                "/missing",
                pending.path(),
            );
            var rejected = try pending.reject(404, &.{
                .{ .name = "x-rejection", .value = "route-not-found" },
            });
            pending_owned = false;
            defer rejected.deinit();
            try std.testing.expectEqual(@as(u16, 404), rejected.status);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    try std.testing.expectError(
        error.SessionRejected,
        runtime.HandshakeClientSession.connect(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            .{
                .authority = "localhost",
                .path = "/missing",
                .h3 = .{ .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .server_name = "localhost",
                    .random = [_]u8{0xb1} ** 32,
                    .x25519_secret_key = [_]u8{0xb2} ** 32,
                } },
            },
        ),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
