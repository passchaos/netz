const std = @import("std");
const webtransport = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const quic = @import("../../quic/mod.zig");

const stream_payload_len: usize = 96 * 1024;
const stream_window: u64 = 8 * 1024;

test "WebTransport handshake streams read incrementally and exchange cancellation" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x30, 0x01, 0x57, 0x54, 0x30, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x30, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x30, 0x04 };
    const stream_payload = try allocator.alloc(u8, stream_payload_len);
    defer allocator.free(stream_payload);
    for (stream_payload, 0..) |*byte, index| {
        byte.* = expectedByte(index);
    }

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .http3 = .{
                .quic = .{
                    .max_datagram_size = 4096,
                    .max_frames_per_datagram = 8,
                },
            },
        },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .local_transport_parameters = smallWindowTransportParameters(),
                .initial_one_rtt_config = .{
                    .stream_receive_window = stream_window,
                },
                .random = [_]u8{0xa3} ** 32,
                .x25519_secret_key = [_]u8{0xa4} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var session = try shared.server.accept();
            defer session.deinit();
            var read_buffer: [3072]u8 = undefined;
            var received: usize = 0;
            var data_events: usize = 0;
            while (true) {
                const event = try session.readStream(&read_buffer);
                switch (event) {
                    .data => |data| {
                        try std.testing.expectEqual(@as(u62, 4), data.stream_id);
                        try std.testing.expectEqual(
                            webtransport.StreamDirection.bidirectional,
                            data.direction,
                        );
                        try std.testing.expect(!data.locally_initiated);
                        try std.testing.expect(data.bytes != 0 or data.fin);
                        try std.testing.expectEqualSlices(
                            u8,
                            shared.expected[received..][0..data.bytes],
                            read_buffer[0..data.bytes],
                        );
                        received += data.bytes;
                        data_events += 1;
                        if (data.fin) break;
                    },
                    else => return error.UnexpectedStreamEvent,
                }
            }
            try std.testing.expectEqual(shared.expected.len, received);
            try std.testing.expect(data_events > 1);
            try std.testing.expect(shared.expected.len > stream_window);

            const stop_stream = try session.openUnidirectionalStream();
            try session.sendStream(stop_stream, "stop me", false);
            while (true) {
                const event = try session.readStream(&read_buffer);
                switch (event) {
                    .stopped => |stopped| {
                        try std.testing.expectEqual(
                            stop_stream,
                            stopped.stream_id,
                        );
                        try std.testing.expectEqual(
                            @as(?u32, 7),
                            stopped.error_info.application_code,
                        );
                        break;
                    },
                    .data => {},
                    else => return error.UnexpectedStreamEvent,
                }
            }
            try std.testing.expectError(
                error.InvalidStreamState,
                session.sendStream(stop_stream, "late", false),
            );

            const reset_stream = try session.openBidirectionalStream();
            try session.sendStream(reset_stream, "before reset", false);
            try session.resetStream(reset_stream, 42);
        }
    };

    var shared = Shared{
        .server = &server,
        .expected = stream_payload,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-incremental",
            .limits = .{
                .http3 = .{
                    .quic = .{
                        .max_datagram_size = 4096,
                        .max_frames_per_datagram = 8,
                    },
                },
            },
            .h3 = .{
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .local_transport_parameters = smallWindowTransportParameters(),
                    .initial_one_rtt_config = .{
                        .stream_receive_window = stream_window,
                    },
                    .server_name = "localhost",
                    .random = [_]u8{0xa1} ** 32,
                    .x25519_secret_key = [_]u8{0xa2} ** 32,
                },
            },
        },
    );
    defer client.deinit();
    const streamed = try client.openBidirectionalStream();
    try std.testing.expectEqual(@as(u62, 4), streamed);
    try client.sendStream(streamed, stream_payload, true);

    var read_buffer: [2048]u8 = undefined;
    var saw_stop_payload = false;
    while (!saw_stop_payload) {
        const event = try client.readStream(&read_buffer);
        switch (event) {
            .data => |data| {
                if (data.direction == .unidirectional and
                    !data.locally_initiated)
                {
                    try std.testing.expectEqualStrings(
                        "stop me",
                        read_buffer[0..data.bytes],
                    );
                    try std.testing.expect(!data.fin);
                    saw_stop_payload = true;
                    try client.stopStream(data.stream_id, 7);
                }
            },
            else => return error.UnexpectedStreamEvent,
        }
    }

    var reset_stream_id: ?u62 = null;
    var saw_stop_reset = false;
    while (true) {
        const event = try client.readStream(&read_buffer);
        switch (event) {
            .data => |data| {
                if (data.direction == .bidirectional and
                    !data.locally_initiated)
                {
                    try std.testing.expectEqualStrings(
                        "before reset",
                        read_buffer[0..data.bytes],
                    );
                    try std.testing.expect(!data.fin);
                    reset_stream_id = data.stream_id;
                }
            },
            .reset => |reset| {
                if (reset.error_info.application_code == 7) {
                    try std.testing.expectEqual(
                        webtransport.StreamDirection.unidirectional,
                        reset.direction,
                    );
                    saw_stop_reset = true;
                    continue;
                }
                if (reset_stream_id) |stream_id| {
                    try std.testing.expectEqual(stream_id, reset.stream_id);
                }
                try std.testing.expectEqual(
                    @as(?u32, 42),
                    reset.error_info.application_code,
                );
                try std.testing.expectEqual(
                    webtransport.applicationErrorCodeToHttp3(42),
                    reset.error_info.http3_code,
                );
                break;
            },
            else => return error.UnexpectedStreamEvent,
        }
    }
    try std.testing.expect(saw_stop_reset);
    // RESET_STREAM can overtake its preceding STREAM packet. Both outcomes are
    // valid: when data arrives first it is delivered before reset; otherwise
    // the reset terminates the read direction without fabricating payload.

    thread.join();
    if (shared.err) |err| return err;
}

test "WebTransport stream direction guards reject invalid reset and stop" {
    const allocator = std.testing.allocator;
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        .init(0),
        .client,
        .{},
    );
    defer registry.deinit();
    const local_uni = try registry.openLocal(.unidirectional);
    const peer_uni = try registry.registerPeer(3, .unidirectional);

    // Direction checks happen before the QUIC operation, so these focused
    // calls need no socket-backed connection.
    var connection: quic.one_rtt.Connection = undefined;
    try std.testing.expectError(
        error.InvalidStreamState,
        @import("stream_incremental.zig").stop(
            &connection,
            &registry,
            local_uni.stream_id,
            1,
        ),
    );
    try std.testing.expectError(
        error.InvalidStreamState,
        @import("stream_incremental.zig").reset(
            &connection,
            &registry,
            peer_uni.stream_id,
            1,
        ),
    );
}

test "WebTransport batch validation rejects duplicates before I/O" {
    const allocator = std.testing.allocator;
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        .init(0),
        .client,
        .{},
    );
    defer registry.deinit();
    const stream = try registry.openLocal(.bidirectional);
    const writes = [_]runtime.StreamWrite{
        .{ .stream_id = stream.stream_id, .data = "one" },
        .{ .stream_id = stream.stream_id, .data = "two" },
    };
    try std.testing.expectError(
        error.DuplicateStream,
        @import("stream_batch.zig").validate(&registry, &writes),
    );
    try std.testing.expect(!stream.prefix_sent);
    try std.testing.expectEqual(@as(u64, 0), stream.send_offset);
}

test "WebTransport stream registry rolls back peer association" {
    const allocator = std.testing.allocator;
    var registry = try webtransport.StreamRegistry.init(
        allocator,
        .init(0),
        .server,
        .{ .max_peer_bidi = 1 },
    );
    defer registry.deinit();

    const first = try registry.registerPeer(4, .bidirectional);
    try std.testing.expectEqual(@as(u62, 4), first.stream_id);
    registry.removeLastPeer(4);
    try std.testing.expect(registry.get(4) == null);
    const replacement = try registry.registerPeer(8, .bidirectional);
    try std.testing.expectEqual(@as(u62, 8), replacement.stream_id);
}

test "WebTransport partial writes interleave streams and finish independently" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x50, 0x01, 0x57, 0x54, 0x50, 0x02 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x50, 0x03 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x50, 0x04 };
    const first_payload = [_]u8{0xa5} ** (24 * 1024);
    const second_payload = [_]u8{0x5a} ** (24 * 1024);

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .http3 = .{
                .quic = .{
                    .max_datagram_size = 4096,
                    .max_frames_per_datagram = 8,
                },
            },
        },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .local_transport_parameters = smallWindowTransportParameters(),
                .initial_one_rtt_config = .{
                    .stream_receive_window = stream_window,
                },
                .random = [_]u8{0xb3} ** 32,
                .x25519_secret_key = [_]u8{0xb4} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        first: []const u8,
        second: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var session = try shared.server.accept();
            defer session.deinit();
            var buffer: [4096]u8 = undefined;
            var first_received: usize = 0;
            var second_received: usize = 0;
            var first_fin = false;
            var second_fin = false;
            while (!first_fin or !second_fin) {
                const event = try session.readStream(&buffer);
                if (event != .data) return error.UnexpectedStreamEvent;
                const data = event.data;
                if (data.stream_id == 4) {
                    try std.testing.expectEqualSlices(
                        u8,
                        shared.first[first_received..][0..data.bytes],
                        buffer[0..data.bytes],
                    );
                    first_received += data.bytes;
                    first_fin = data.fin;
                } else if (data.stream_id == 8) {
                    try std.testing.expectEqualSlices(
                        u8,
                        shared.second[second_received..][0..data.bytes],
                        buffer[0..data.bytes],
                    );
                    second_received += data.bytes;
                    second_fin = data.fin;
                } else return error.UnexpectedStream;
            }
            try std.testing.expectEqual(shared.first.len, first_received);
            try std.testing.expectEqual(shared.second.len, second_received);
        }
    };

    var shared = Shared{
        .server = &server,
        .first = &first_payload,
        .second = &second_payload,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-partial",
            .limits = .{
                .http3 = .{
                    .quic = .{
                        .max_datagram_size = 4096,
                        .max_frames_per_datagram = 8,
                    },
                },
            },
            .h3 = .{
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .local_transport_parameters = smallWindowTransportParameters(),
                    .initial_one_rtt_config = .{
                        .stream_receive_window = stream_window,
                    },
                    .server_name = "localhost",
                    .random = [_]u8{0xb1} ** 32,
                    .x25519_secret_key = [_]u8{0xb2} ** 32,
                },
            },
        },
    );
    defer client.deinit();

    const first = try client.openBidirectionalStream();
    const second = try client.openBidirectionalStream();
    try std.testing.expectEqual(@as(u62, 4), first);
    try std.testing.expectEqual(@as(u62, 8), second);
    var first_written: usize = 0;
    var second_written: usize = 0;
    var turns: usize = 0;
    while (first_written < first_payload.len or
        second_written < second_payload.len)
    {
        if (first_written < first_payload.len) {
            const count = try client.writeStream(
                first,
                first_payload[first_written..],
            );
            try std.testing.expect(count > 0);
            try std.testing.expect(count < first_payload.len);
            first_written += count;
        }
        if (second_written < second_payload.len) {
            const count = try client.writeStream(
                second,
                second_payload[second_written..],
            );
            try std.testing.expect(count > 0);
            try std.testing.expect(count < second_payload.len);
            second_written += count;
        }
        turns += 1;
    }
    try std.testing.expect(turns > 1);
    try client.finishStream(second);
    try client.finishStream(first);
    try std.testing.expectError(
        error.InvalidStreamState,
        client.writeStream(first, "late"),
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "WebTransport batched writes commit concurrent stream progress" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x42, 0x11, 0x57, 0x54, 0x42, 0x12 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x42, 0x13 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x42, 0x14 };
    const first_payload = [_]u8{0xc3} ** (32 * 1024);
    const second_payload = [_]u8{0x3c} ** (32 * 1024);

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .local_transport_parameters = smallWindowTransportParameters(),
            .initial_one_rtt_config = .{
                .stream_receive_window = stream_window,
                .enable_pacing = false,
            },
            .random = [_]u8{0xd3} ** 32,
            .x25519_secret_key = [_]u8{0xd4} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        first: []const u8,
        second: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var session = try shared.server.accept();
            defer session.deinit();
            var buffer: [4096]u8 = undefined;
            var received = [_]usize{ 0, 0 };
            var finished = [_]bool{ false, false };
            while (!finished[0] or !finished[1]) {
                const event = try session.readStream(&buffer);
                if (event != .data) return error.UnexpectedStreamEvent;
                const data = event.data;
                const index: usize = if (data.stream_id == 4)
                    0
                else if (data.stream_id == 8)
                    1
                else
                    return error.UnexpectedStream;
                const expected = if (index == 0)
                    shared.first
                else
                    shared.second;
                try std.testing.expectEqualSlices(
                    u8,
                    expected[received[index]..][0..data.bytes],
                    buffer[0..data.bytes],
                );
                received[index] += data.bytes;
                if (data.fin) finished[index] = true;
            }
            try std.testing.expectEqual(shared.first.len, received[0]);
            try std.testing.expectEqual(shared.second.len, received[1]);
        }
    };

    var shared = Shared{
        .server = &server,
        .first = &first_payload,
        .second = &second_payload,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-batch",
            .limits = .{ .http3 = .{ .quic = .{
                .max_datagram_size = 4096,
                .max_frames_per_datagram = 8,
            } } },
            .h3 = .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .local_transport_parameters = smallWindowTransportParameters(),
                .initial_one_rtt_config = .{
                    .stream_receive_window = stream_window,
                    .enable_pacing = false,
                },
                .server_name = "localhost",
                .random = [_]u8{0xd1} ** 32,
                .x25519_secret_key = [_]u8{0xd2} ** 32,
            } },
        },
    );
    defer client.deinit();

    const first = try client.openBidirectionalStream();
    const second = try client.openBidirectionalStream();
    var offsets = [_]usize{ 0, 0 };
    var saw_two_packet_batch = false;
    while (offsets[0] < first_payload.len or
        offsets[1] < second_payload.len)
    {
        const writes = [_]runtime.StreamWrite{
            .{ .stream_id = first, .data = first_payload[offsets[0]..] },
            .{ .stream_id = second, .data = second_payload[offsets[1]..] },
        };
        var counts: [2]usize = undefined;
        const result = try client.writeStreams(&writes, &counts);
        if (result.send_error) |err| return err;
        try std.testing.expect(result.progressed != 0);
        saw_two_packet_batch = saw_two_packet_batch or
            result.progressed == 2;
        offsets[0] += counts[0];
        offsets[1] += counts[1];
    }
    try std.testing.expect(saw_two_packet_batch);
    try client.finishStream(first);
    try client.finishStream(second);

    thread.join();
    if (shared.err) |err| return err;
}

fn smallWindowTransportParameters() quic.TransportParameters {
    var parameters = quic.practical_transport_parameters;
    parameters.initial_max_data = stream_window * 2;
    parameters.initial_max_stream_data_bidi_local = stream_window;
    parameters.initial_max_stream_data_bidi_remote = stream_window;
    parameters.initial_max_stream_data_uni = stream_window;
    return parameters;
}

fn expectedByte(index: usize) u8 {
    return @truncate((index *% 131) ^ (index >> 3));
}
