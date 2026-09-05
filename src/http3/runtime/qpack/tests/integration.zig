const std = @import("std");
const runtime = @import("../../../runtime.zig");
const quic = @import("../../../../quic/mod.zig");
const control_sender = @import("../../control/send.zig");

const client_control_stream_id: u62 = 2;
const server_control_stream_id: u62 = 3;

test "HTTP/3 protected runtime sends a speculative QPACK request" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xb1, 0x71, 0x72, 0x73 };
    const server_cid = [_]u8{ 0xb2, 0x71, 0x72, 0x73 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb3} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb4} ** quic.protection.secret_len,
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
            .local_settings = .{
                .qpack_max_table_capacity = 256,
                .qpack_blocked_streams = 1,
            },
            .max_stream_frame_data = 1024,
        },
    );
    defer server.deinit();
    var client = try runtime.ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
            .local_settings = .{
                .qpack_max_table_capacity = 256,
                .qpack_blocked_streams = 1,
            },
            .max_stream_frame_data = 1024,
        },
    );
    defer client.deinit();

    try control_sender.sendProtectedSettings(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config,
        &client.control,
        &client.control_send,
        &client.qpack_encoder_send,
        &client.qpack_encoder_prefix_sent,
        &client.qpack_decoder_send,
        &client.qpack_decoder_prefix_sent,
        &client.next_packet_number,
        &client.protected_send,
        client_control_stream_id,
    );
    try control_sender.sendProtectedSettings(
        &server.quic_server.endpoint,
        client.quic_client.endpoint.address(),
        server.config,
        &server.control,
        &server.control_send,
        &server.qpack_encoder_send,
        &server.qpack_encoder_prefix_sent,
        &server.qpack_decoder_send,
        &server.qpack_decoder_prefix_sent,
        &server.next_packet_number,
        &server.protected_send,
        server_control_stream_id,
    );
    try std.testing.expectError(
        error.Timeout,
        client.receivePeerSettingsWithDeadline(.{
            .clock = .real,
            .raw = .zero,
        }),
    );
    const peer_settings = try client.receivePeerSettingsWithTimeout(
        .fromSeconds(1),
    );
    try std.testing.expectEqual(
        @as(?u64, 1),
        client.qpack_encode.peer_max_blocked_streams,
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        peer_settings.qpack_blocked_streams,
    );

    _ = try client.qpack_encode.insertField(
        "x-speculative-runtime",
        "sent-before-feedback",
    );
    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/speculative-qpack",
        .authority = "localhost",
        .headers = &.{.{
            .name = "x-speculative-runtime",
            .value = "sent-before-feedback",
        }},
    });
    try std.testing.expectEqual(@as(u62, 0), stream_id);
    try std.testing.expectEqual(
        @as(u64, 0),
        client.qpack_encode.known_received_count,
    );
    try std.testing.expectEqual(
        @as(?usize, 1),
        client.qpack_encode.blocked_section_counts.get(stream_id),
    );

    var request = try server.receiveRequest();
    defer request.deinit(allocator);
    try std.testing.expectEqualStrings(
        "/speculative-qpack",
        request.request.path,
    );
    var value: ?[]const u8 = null;
    for (request.request.headers) |header| {
        if (std.mem.eql(u8, header.name, "x-speculative-runtime")) {
            value = header.value;
        }
    }
    try std.testing.expectEqualStrings(
        "sent-before-feedback",
        value orelse return error.TestUnexpectedResult,
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        request.request.qpack_section_acknowledgments,
    );
}

test "HTTP/3 protected runtime reuses acknowledged dynamic QPACK entries" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xc1, 0x11, 0x22, 0x33 };
    const server_cid = [_]u8{ 0xc2, 0x11, 0x22, 0x33 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc3} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc4} ** quic.protection.secret_len,
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
            .local_settings = .{ .qpack_max_table_capacity = 512 },
            // Exercise instruction fragmentation and the persistent encoder
            // stream offset rather than relying on one-frame instructions.
            .max_stream_frame_data = 5,
            .max_frames_per_packet = 2,
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
            var encoded_capacity: usize = 0;
            var frame_capacity: usize = 0;
            var encoded_ptr: [*]u8 = undefined;
            var frame_ptr: [*]quic.Frame = undefined;
            for (0..3) |exchange| {
                var request = try server_ptr.receiveRequest();
                defer request.deinit(
                    server_ptr.quic_server.endpoint.allocator,
                );
                try std.testing.expectEqualStrings(
                    "/protected-dynamic",
                    request.request.path,
                );
                var repeated_value: ?[]const u8 = null;
                for (request.request.headers) |header| {
                    if (std.mem.eql(u8, header.name, "x-runtime-request")) {
                        repeated_value = header.value;
                    }
                }
                try std.testing.expectEqualStrings(
                    "repeated-request-value",
                    repeated_value orelse return error.TestUnexpectedResult,
                );

                if (exchange == 1) {
                    // Request two carries inserts but remains literal because
                    // SETTINGS_QPACK_BLOCKED_STREAMS is zero. Its feedback
                    // enables request three to use those entries.
                    try std.testing.expectEqual(
                        @as(usize, 0),
                        request.request.qpack_section_acknowledgments,
                    );
                    try std.testing.expect(
                        server_ptr.qpack_decode.table.insert_count != 0,
                    );
                    // Feedback for response one is consumed while waiting for
                    // request two, so response two can already be dynamic.
                    try std.testing.expect(
                        server_ptr.qpack_encode.known_received_count != 0,
                    );
                } else if (exchange == 2) {
                    try std.testing.expect(
                        request.request.qpack_section_acknowledgments != 0,
                    );
                }

                try server_ptr.sendResponse(
                    request.from,
                    request.stream_id,
                    .{
                        .status = 200,
                        .headers = &.{.{
                            .name = "x-runtime-response",
                            .value = "repeated-response-value",
                        }},
                        .body = "ok",
                    },
                );
                if (exchange == 0) {
                    encoded_capacity =
                        server_ptr.stream_send_scratch.encoded.capacity;
                    frame_capacity =
                        server_ptr.stream_send_scratch.frames.capacity;
                    try std.testing.expect(encoded_capacity != 0);
                    try std.testing.expect(frame_capacity != 0);
                    encoded_ptr = server_ptr.stream_send_scratch.encoded
                        .allocatedSlice().ptr;
                    frame_ptr = server_ptr.stream_send_scratch.frames
                        .allocatedSlice().ptr;
                } else {
                    try std.testing.expectEqual(
                        encoded_capacity,
                        server_ptr.stream_send_scratch.encoded.capacity,
                    );
                    try std.testing.expectEqual(
                        frame_capacity,
                        server_ptr.stream_send_scratch.frames.capacity,
                    );
                    try std.testing.expectEqual(
                        encoded_ptr,
                        server_ptr.stream_send_scratch.encoded
                            .allocatedSlice().ptr,
                    );
                    try std.testing.expectEqual(
                        frame_ptr,
                        server_ptr.stream_send_scratch.frames
                            .allocatedSlice().ptr,
                    );
                }
                if (exchange != 0) {
                    try std.testing.expect(
                        server_ptr.qpack_encode.pending_sections.items.len != 0,
                    );
                }
            }
            try std.testing.expect(
                server_ptr.qpack_encoder_send.next_offset > 1,
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
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
            .local_settings = .{ .qpack_max_table_capacity = 512 },
            .max_stream_frame_data = 5,
            .max_frames_per_packet = 2,
        },
    );
    defer client.deinit();

    var encoded_capacity: usize = 0;
    var frame_capacity: usize = 0;
    var encoded_ptr: [*]u8 = undefined;
    var frame_ptr: [*]quic.Frame = undefined;
    for (0..3) |exchange| {
        var response = try client.request(.{
            .method = "GET",
            .path = "/protected-dynamic",
            .authority = "example.test",
            .headers = &.{.{
                .name = "x-runtime-request",
                .value = "repeated-request-value",
            }},
        });
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), response.response.status);
        var repeated_value: ?[]const u8 = null;
        for (response.response.headers) |header| {
            if (std.mem.eql(u8, header.name, "x-runtime-response")) {
                repeated_value = header.value;
            }
        }
        try std.testing.expectEqualStrings(
            "repeated-response-value",
            repeated_value orelse return error.TestUnexpectedResult,
        );
        if (exchange == 0) {
            encoded_capacity = client.stream_send_scratch.encoded.capacity;
            frame_capacity = client.stream_send_scratch.frames.capacity;
            try std.testing.expect(encoded_capacity != 0);
            try std.testing.expect(frame_capacity != 0);
            encoded_ptr = client.stream_send_scratch.encoded
                .allocatedSlice().ptr;
            frame_ptr = client.stream_send_scratch.frames
                .allocatedSlice().ptr;
        } else {
            try std.testing.expectEqual(
                encoded_capacity,
                client.stream_send_scratch.encoded.capacity,
            );
            try std.testing.expectEqual(
                frame_capacity,
                client.stream_send_scratch.frames.capacity,
            );
            try std.testing.expectEqual(
                encoded_ptr,
                client.stream_send_scratch.encoded.allocatedSlice().ptr,
            );
            try std.testing.expectEqual(
                frame_ptr,
                client.stream_send_scratch.frames.allocatedSlice().ptr,
            );
        }
    }

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(client.qpack_encode.known_received_count != 0);
    try std.testing.expect(client.qpack_decode.table.insert_count != 0);
    try std.testing.expectEqual(
        @as(usize, 0),
        client.qpack_encode.pending_sections.items.len,
    );
    try std.testing.expect(client.qpack_encoder_send.next_offset > 1);
}
