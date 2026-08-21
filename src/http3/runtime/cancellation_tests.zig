const std = @import("std");
const runtime = @import("../runtime.zig");

const http3 = @import("../mod.zig");

test "HTTP/3 handshake server observes response cancellation and reuses connection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    };
    const client_cid = [_]u8{ 0x39, 0x3a, 0x3b, 0x3c };
    const server_cid = [_]u8{ 0x3d, 0x3e, 0x3f, 0x40 };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x41} ** 32,
            .x25519_secret_key = [_]u8{0x42} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var session = try shared.server.accept();
            defer session.deinit();

            var canceled = try session.receiveRequest();
            defer canceled.deinit(allocator);
            try std.testing.expectEqualStrings(
                "/cancel-response",
                canceled.request.path,
            );
            try session.startResponse(
                canceled.stream_id,
                .{ .status = 200 },
                64,
            );
            try session.sendResponseBodyPaced(
                canceled.stream_id,
                "partial",
                false,
            );
            const cancellation = try session
                .receivePeerResponseCancellation(canceled.stream_id);
            try std.testing.expectEqual(
                canceled.stream_id,
                cancellation.stream_id,
            );
            try std.testing.expectEqual(
                @as(u64, http3.ApplicationErrorCode.request_cancelled),
                cancellation.application_error_code,
            );
            try std.testing.expectError(
                error.RequestCancelled,
                session.sendResponseBody(
                    canceled.stream_id,
                    "must-not-send",
                    false,
                ),
            );

            var followup = try session.receiveRequest();
            defer followup.deinit(allocator);
            try std.testing.expectEqualStrings(
                "/after-cancel",
                followup.request.path,
            );
            try session.sendResponse(followup.stream_id, .{ .status = 204 });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x43} ** 32,
            .x25519_secret_key = [_]u8{0x44} ** 32,
        } },
    );
    defer client.deinit();

    const canceled_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/cancel-response",
        .authority = "localhost",
    });
    while (true) {
        var event = (try client.receiveResponseEvent(canceled_id)) orelse
            continue;
        defer event.deinit(allocator);
        if (event == .head) break;
    }
    try client.established.connection.sendStopSending(
        canceled_id,
        http3.ApplicationErrorCode.request_cancelled,
    );

    var response = try client.request(.{
        .method = "GET",
        .path = "/after-cancel",
        .authority = "localhost",
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), response.response.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
