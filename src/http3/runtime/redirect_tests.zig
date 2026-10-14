const std = @import("std");
const http3 = @import("../mod.zig");
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

test "HTTP3 URI redirect establishes fresh authenticated connection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const first_server_cid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
    const second_server_cid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
    var first_server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } },
        .{ .handshake = .{
            .local_connection_id = &first_server_cid,
            .random = [_]u8{0x35} ** 32,
            .x25519_secret_key = [_]u8{0x36} ** 32,
        } },
    );
    defer first_server.deinit();
    var second_server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } },
        .{ .handshake = .{
            .local_connection_id = &second_server_cid,
            .random = [_]u8{0x45} ** 32,
            .x25519_secret_key = [_]u8{0x46} ** 32,
        } },
    );
    defer second_server.deinit();
    const second_uri = try std.fmt.allocPrint(
        allocator,
        "https://127.0.0.1:{d}/final",
        .{second_server.address().getPort()},
    );
    defer allocator.free(second_uri);

    const Shared = struct {
        first: *runtime.HandshakeServer,
        second: *runtime.HandshakeServer,
        second_uri: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var first_session = try self.first.accept();
            defer first_session.deinit();
            var first_request = try first_session.receiveRequest();
            defer first_request.deinit(allocator);
            try std.testing.expectEqualStrings("POST", first_request.request.method);
            try std.testing.expectEqualStrings("payload", first_request.request.body);
            try std.testing.expectEqualStrings(
                "Bearer first-origin",
                findHeader(first_request.request.headers, "authorization").?,
            );
            try first_session.sendResponse(first_request.stream_id, .{
                .status = 303,
                .headers = &.{.{
                    .name = "location",
                    .value = self.second_uri,
                }},
                .body = "redirect",
                .request_method = first_request.request.method,
            });

            var second_session = try self.second.accept();
            defer second_session.deinit();
            var second_request = try second_session.receiveRequest();
            defer second_request.deinit(allocator);
            try std.testing.expectEqualStrings("GET", second_request.request.method);
            try std.testing.expectEqualStrings("/final", second_request.request.path);
            try std.testing.expectEqual(@as(usize, 0), second_request.request.body.len);
            try std.testing.expect(
                findHeader(second_request.request.headers, "authorization") == null,
            );
            try std.testing.expect(
                findHeader(second_request.request.headers, "content-type") == null,
            );
            try second_session.sendResponse(second_request.stream_id, .{
                .status = 200,
                .body = "accepted",
                .request_method = second_request.request.method,
            });
        }
    };
    var shared = Shared{
        .first = &first_server,
        .second = &second_server,
        .second_uri = second_uri,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const initial_uri_text = try std.fmt.allocPrint(
        allocator,
        "https://127.0.0.1:{d}/start",
        .{first_server.address().getPort()},
    );
    defer allocator.free(initial_uri_text);
    const initial_uri = try std.Uri.parse(initial_uri_text);
    const original_dcid = [_]u8{ 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58 };
    const client_cid = [_]u8{ 0x61, 0x62, 0x63, 0x64 };
    var result = try runtime.HandshakeClient
        .requestUriFollowingRedirectsDetailedWithTimeout(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        initial_uri,
        .{
            .method = "POST",
            .headers = &.{
                .{ .name = "authorization", .value = "Bearer first-origin" },
                .{ .name = "content-type", .value = "text/plain" },
            },
            .body = "payload",
        },
        .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } },
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .random = [_]u8{0x65} ** 32,
            .x25519_secret_key = [_]u8{0x66} ** 32,
        } },
        .{},
        .fromSeconds(5),
    );
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 1), result.redirect_count);
    try std.testing.expectEqualStrings("accepted", result.response.response.body);
    try std.testing.expectEqualStrings(second_uri, result.final_uri);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP3 redirect timeout rejects zero budget before I/O" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const original_dcid = [_]u8{0x71} ** 8;
    const client_cid = [_]u8{0x72} ** 4;
    try std.testing.expectError(
        error.Timeout,
        runtime.HandshakeClient.requestUriFollowingRedirectsWithTimeout(
            std.testing.allocator,
            threaded.io(),
            .{ .ip4 = .loopback(0) },
            try std.Uri.parse("https://127.0.0.1:1/"),
            .{},
            .{},
            .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
            } },
            .{},
            .zero,
        ),
    );
}
