const std = @import("std");
const runtime = @import("../../../runtime.zig");
const quic = @import("../../../../quic/mod.zig");

test "HTTP/3 protected client streams large response through small window" {
    const allocator = std.testing.allocator;
    const body_len: usize = 1024 * 1024;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xc9, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xca, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xcb} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xcc} ** quic.protection.secret_len,
    );
    var server = try runtime.ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
            .peer_stream_flow_window = 1024,
            .max_stream_frame_data = 480,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.ProtectedServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *runtime.ProtectedServer) !void {
            var request = try server_ptr.receiveRequest();
            defer request.deinit(
                server_ptr.quic_server.endpoint.allocator,
            );
            try server_ptr.startResponse(
                request.from,
                request.stream_id,
                .{ .status = 200 },
                body_len,
            );
            var chunk: [400]u8 = undefined;
            for (&chunk, 0..) |*byte, index| byte.* = @truncate(index);
            var remaining = body_len;
            while (remaining != 0) {
                const count = @min(chunk.len, remaining);
                try server_ptr.sendResponseBodyPaced(
                    request.from,
                    request.stream_id,
                    chunk[0..count],
                    false,
                );
                remaining -= count;
            }
            try server_ptr.finishResponseTrailersPaced(
                request.from,
                request.stream_id,
                &.{.{ .name = "x-stream-finished", .value = "yes" }},
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try runtime.ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .quic = .{
                .max_datagram_size = 4096,
                .max_frames_per_datagram = 8,
            },
            .max_stream_buffer = 1024,
        },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
            .max_stream_buffer = 1024,
            .max_stream_frame_data = 480,
        },
    );
    defer client.deinit();

    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/large-stream",
        .authority = "localhost",
    });
    var saw_head = false;
    var saw_trailers = false;
    var body_read: usize = 0;
    var body_skipped: usize = 0;
    var checksum: u64 = 0;
    var read_buf: [113]u8 = undefined;
    while (client.request_lifecycle.contains(stream_id)) {
        const event = (try client.receiveResponseEvent(stream_id)) orelse
            continue;
        var owned_event = event;
        defer owned_event.deinit(allocator);
        switch (owned_event) {
            .head => |head| {
                try std.testing.expectEqual(@as(u16, 200), head.response.status);
                try std.testing.expectEqual(
                    @as(?usize, body_len),
                    head.response.content_length,
                );
                saw_head = true;
            },
            .push_promise => return error.TestUnexpectedResult,
            .data_available => {
                while (true) {
                    const active = client.streaming_responses.find(stream_id).?;
                    if (!active.reader.hasPendingFrame()) break;
                    if (body_skipped == 0) {
                        const skipped = try client.skipResponseData(stream_id);
                        if (skipped == 0) break;
                        body_skipped += skipped;
                        continue;
                    }
                    const read = try client.readResponseData(
                        stream_id,
                        &read_buf,
                    );
                    if (read == 0) break;
                    for (read_buf[0..read]) |byte| checksum +%= byte;
                    body_read += read;
                }
                const active = client.streaming_responses.find(stream_id).?;
                try std.testing.expect(
                    active.reader.bufferedBytes() <= 1024,
                );
            },
            .trailers => |trailers| {
                try std.testing.expectEqualStrings(
                    "yes",
                    trailers.fields[0].value,
                );
                saw_trailers = true;
            },
            .finished => {},
        }
    }
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(saw_head);
    try std.testing.expect(saw_trailers);
    try std.testing.expect(body_skipped != 0);
    try std.testing.expectEqual(body_len, body_read + body_skipped);
    try std.testing.expect(checksum != 0);
    try std.testing.expectEqual(
        @as(usize, 0),
        client.streaming_responses.entryCount(),
    );
}
