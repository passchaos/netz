const std = @import("std");
const runtime = @import("../runtime.zig");

const http3 = @import("../mod.zig");
const quic = @import("../../quic/mod.zig");

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
            try std.testing.expectError(
                error.Timeout,
                session.receivePeerResponseCancellationWithTimeout(
                    canceled.stream_id,
                    .fromMilliseconds(10),
                ),
            );
            const cancellation = try session
                .receivePeerResponseCancellationWithTimeout(
                canceled.stream_id,
                .fromSeconds(2),
            );
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
    try std.Io.sleep(io, .fromMilliseconds(50), .awake);
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

test "HTTP/3 handshake client resets malformed response and reuses connection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
    };
    const client_cid = [_]u8{ 0x59, 0x5a, 0x5b, 0x5c };
    const server_cid = [_]u8{ 0x5d, 0x5e, 0x5f, 0x60 };
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
            .random = [_]u8{0x61} ** 32,
            .x25519_secret_key = [_]u8{0x62} ** 32,
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

            var malformed = try session.receiveRequest();
            defer malformed.deinit(allocator);
            // Establish the server control stream before injecting the
            // deliberately malformed response field section.
            try session.sendOrigins(&.{});
            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(allocator);
            var table = http3.Qpack.DynamicTable.init(allocator, 0);
            defer table.deinit();
            var promise_fields: std.ArrayList(u8) = .empty;
            defer promise_fields.deinit(allocator);
            try http3.Qpack.encodeDynamicBlock(
                &promise_fields,
                allocator,
                &.{
                    .{ .name = ":method", .value = "GET" },
                    .{ .name = ":scheme", .value = "https" },
                    .{ .name = ":path", .value = "/unused-push" },
                    .{ .name = ":authority", .value = "localhost" },
                },
                table,
            );
            try http3.writePushPromiseFrame(
                &encoded,
                allocator,
                0,
                promise_fields.items,
            );
            var field_section: std.ArrayList(u8) = .empty;
            defer field_section.deinit(allocator);
            try http3.Qpack.encodeDynamicBlock(
                &field_section,
                allocator,
                &.{
                    .{ .name = ":status", .value = "200" },
                    .{ .name = "content-length", .value = "2" },
                },
                table,
            );
            try (http3.Frame{
                .frame_type = http3.FrameType.headers,
                .payload = field_section.items,
                .consumed = 0,
            }).write(&encoded, allocator);
            try (http3.Frame{
                .frame_type = http3.FrameType.data,
                .payload = "x",
                .consumed = 0,
            }).write(&encoded, allocator);
            try session.established.connection.send(&.{.{ .stream = .{
                .stream_id = malformed.stream_id,
                .data = encoded.items,
                .fin = true,
            } }});

            var saw_stop = false;
            while (!saw_stop) {
                var packet = try session.established.connection
                    .receivePacketTimeout(.{ .duration = .{
                    .clock = .awake,
                    .raw = .fromSeconds(2),
                } });
                defer packet.deinit(allocator);
                for (packet.frames) |frame| switch (frame) {
                    .stop_sending => |stop| if (stop.stream_id == malformed.stream_id) {
                        try std.testing.expectEqual(
                            @as(u64, http3.ApplicationErrorCode.message_error),
                            stop.application_error_code,
                        );
                        saw_stop = true;
                    },
                    else => {},
                };
            }

            var sibling = try session.receiveRequest();
            defer sibling.deinit(allocator);
            try std.testing.expectEqualStrings(
                "/after-malformed-response",
                sibling.request.path,
            );
            try session.sendResponse(sibling.stream_id, .{ .status = 204 });
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
            .random = [_]u8{0x63} ** 32,
            .x25519_secret_key = [_]u8{0x64} ** 32,
        } },
    );
    defer client.deinit();

    try client.sendMaxPushId(0);
    const malformed_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/malformed-response",
        .authority = "localhost",
    });
    try std.testing.expectError(
        error.InvalidContentLength,
        client.receiveResponse(malformed_id),
    );
    try std.testing.expect(!client.established.connection.closing());
    try std.testing.expectEqual(@as(usize, 0), client.request_lifecycle.count());
    try std.testing.expect(client.push_streams.isIdle());

    var response = try client.request(.{
        .method = "GET",
        .path = "/after-malformed-response",
        .authority = "localhost",
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), response.response.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client closes on malformed QPACK response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
    };
    const client_cid = [_]u8{ 0x79, 0x7a, 0x7b, 0x7c };
    const server_cid = [_]u8{ 0x7d, 0x7e, 0x7f, 0x80 };
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
            .random = [_]u8{0x81} ** 32,
            .x25519_secret_key = [_]u8{0x82} ** 32,
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
            var request = try session.receiveRequest();
            defer request.deinit(allocator);
            try session.sendOrigins(&.{});

            var malformed: std.ArrayList(u8) = .empty;
            defer malformed.deinit(allocator);
            try (http3.Frame{
                .frame_type = http3.FrameType.headers,
                // Valid HTTP/3 framing, truncated QPACK field-section prefix.
                .payload = &.{0x00},
                .consumed = 0,
            }).write(&malformed, allocator);
            try session.established.connection.send(&.{.{ .stream = .{
                .stream_id = request.stream_id,
                .data = malformed.items,
                .fin = true,
            } }});

            while (!session.established.connection.draining()) {
                var packet = session.established.connection
                    .receivePacketTimeout(.{ .duration = .{
                    .clock = .awake,
                    .raw = .fromSeconds(2),
                } }) catch |err| switch (err) {
                    error.ConnectionClosed => {
                        if (session.established.connection.draining()) break;
                        return err;
                    },
                    else => return err,
                };
                packet.deinit(allocator);
            }
            const close = session.established.connection.peerCloseInfo() orelse
                return error.TestUnexpectedResult;
            try std.testing.expect(close == .application);
            try std.testing.expectEqual(
                @as(
                    u64,
                    http3.ApplicationErrorCode.qpack_decompression_failed,
                ),
                close.application.error_code,
            );
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
            .random = [_]u8{0x83} ** 32,
            .x25519_secret_key = [_]u8{0x84} ** 32,
        } },
    );
    defer client.deinit();

    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/malformed-qpack-response",
        .authority = "localhost",
    });
    try std.testing.expectError(
        error.QpackDecompressionFailed,
        client.receiveResponse(stream_id),
    );
    const close = quic.one_rtt.testing.localCloseInfo(
        &client.established.connection,
    ) orelse return error.TestUnexpectedResult;
    try std.testing.expect(close.application);
    try std.testing.expectEqual(
        @as(u64, http3.ApplicationErrorCode.qpack_decompression_failed),
        close.error_code,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake server resets malformed request and accepts sibling" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{
        0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
    };
    const client_cid = [_]u8{ 0x99, 0x9a, 0x9b, 0x9c };
    const server_cid = [_]u8{ 0x9d, 0x9e, 0x9f, 0xa0 };
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
            .random = [_]u8{0xa1} ** 32,
            .x25519_secret_key = [_]u8{0xa2} ** 32,
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
            try std.testing.expectError(
                error.MissingPath,
                session.receiveRequest(),
            );
            try std.testing.expect(!session.established.connection.closing());

            var sibling = try session.receiveRequest();
            defer sibling.deinit(allocator);
            try std.testing.expectEqualStrings(
                "/after-malformed-request",
                sibling.request.path,
            );
            try session.sendResponse(sibling.stream_id, .{ .status = 204 });
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
            .random = [_]u8{0xa3} ** 32,
            .x25519_secret_key = [_]u8{0xa4} ** 32,
        } },
    );
    defer client.deinit();

    try client.sendMaxPushId(0);
    const malformed_id = try client.openClientBidirectionalStream();
    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();
    var field_section: std.ArrayList(u8) = .empty;
    defer field_section.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(
        &field_section,
        allocator,
        &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "localhost" },
        },
        table,
    );
    var malformed: std.ArrayList(u8) = .empty;
    defer malformed.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = field_section.items,
        .consumed = 0,
    }).write(&malformed, allocator);
    try client.established.connection.send(&.{.{ .stream = .{
        .stream_id = malformed_id,
        .data = malformed.items,
        .fin = true,
    } }});

    var saw_reset = false;
    var saw_stop = false;
    while (!saw_reset or !saw_stop) {
        var packet = try client.established.connection.receivePacketTimeout(.{
            .duration = .{
                .clock = .awake,
                .raw = .fromSeconds(2),
            },
        });
        defer packet.deinit(allocator);
        for (packet.frames) |frame| switch (frame) {
            .reset_stream => |reset| if (reset.stream_id == malformed_id) {
                try std.testing.expectEqual(
                    @as(u64, http3.ApplicationErrorCode.message_error),
                    reset.application_error_code,
                );
                saw_reset = true;
            },
            .stop_sending => |stop| if (stop.stream_id == malformed_id) {
                try std.testing.expectEqual(
                    @as(u64, http3.ApplicationErrorCode.message_error),
                    stop.application_error_code,
                );
                saw_stop = true;
            },
            else => {},
        };
    }

    var response = try client.request(.{
        .method = "GET",
        .path = "/after-malformed-request",
        .authority = "localhost",
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), response.response.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake streaming response error preserves sibling" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{
        0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
    };
    const client_cid = [_]u8{ 0xb9, 0xba, 0xbb, 0xbc };
    const server_cid = [_]u8{ 0xbd, 0xbe, 0xbf, 0xc0 };
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
            .random = [_]u8{0xc1} ** 32,
            .x25519_secret_key = [_]u8{0xc2} ** 32,
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
            var first = try session.receiveRequest();
            defer first.deinit(allocator);
            var second = try session.receiveRequest();
            defer second.deinit(allocator);
            const malformed = if (std.mem.eql(
                u8,
                first.request.path,
                "/streaming-malformed",
            )) first.stream_id else second.stream_id;
            const sibling = if (malformed == first.stream_id)
                second.stream_id
            else
                first.stream_id;

            // Emit SETTINGS before bypassing the response writer with
            // deliberately malformed application bytes.
            try session.sendOrigins(&.{});
            var malformed_bytes: std.ArrayList(u8) = .empty;
            defer malformed_bytes.deinit(allocator);
            var table = http3.Qpack.DynamicTable.init(allocator, 0);
            defer table.deinit();
            var field_section: std.ArrayList(u8) = .empty;
            defer field_section.deinit(allocator);
            try http3.Qpack.encodeDynamicBlock(
                &field_section,
                allocator,
                &.{
                    .{ .name = ":status", .value = "200" },
                    .{ .name = "content-length", .value = "2" },
                },
                table,
            );
            try (http3.Frame{
                .frame_type = http3.FrameType.headers,
                .payload = field_section.items,
                .consumed = 0,
            }).write(&malformed_bytes, allocator);
            try (http3.Frame{
                .frame_type = http3.FrameType.data,
                .payload = "x",
                .consumed = 0,
            }).write(&malformed_bytes, allocator);

            var sibling_bytes: std.ArrayList(u8) = .empty;
            defer sibling_bytes.deinit(allocator);
            try (http3.Response{ .status = 204 }).write(
                &sibling_bytes,
                allocator,
            );
            try session.established.connection.send(&.{
                .{ .stream = .{
                    .stream_id = sibling,
                    .data = sibling_bytes.items,
                    .fin = true,
                } },
                .{ .stream = .{
                    .stream_id = malformed,
                    .data = malformed_bytes.items,
                    .fin = true,
                } },
            });

            var saw_stop = false;
            while (!saw_stop) {
                var packet = try session.established.connection
                    .receivePacketTimeout(.{ .duration = .{
                    .clock = .awake,
                    .raw = .fromSeconds(2),
                } });
                defer packet.deinit(allocator);
                for (packet.frames) |frame| switch (frame) {
                    .stop_sending => |stop| if (stop.stream_id == malformed) {
                        try std.testing.expectEqual(
                            @as(u64, http3.ApplicationErrorCode.message_error),
                            stop.application_error_code,
                        );
                        saw_stop = true;
                    },
                    else => {},
                };
            }
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
            .random = [_]u8{0xc3} ** 32,
            .x25519_secret_key = [_]u8{0xc4} ** 32,
        } },
    );
    defer client.deinit();

    const malformed = try client.sendRequest(.{
        .method = "GET",
        .path = "/streaming-malformed",
        .authority = "localhost",
    });
    const sibling = try client.sendRequest(.{
        .method = "GET",
        .path = "/streaming-sibling",
        .authority = "localhost",
    });
    var saw_head = false;
    var saw_data = false;
    while (!saw_data) {
        var event = (try client.receiveResponseEvent(malformed)) orelse
            continue;
        defer event.deinit(allocator);
        switch (event) {
            .head => saw_head = true,
            .data_available => {
                var byte: [1]u8 = undefined;
                try std.testing.expectEqual(
                    @as(usize, 1),
                    try client.readResponseData(malformed, &byte),
                );
                try std.testing.expectEqualStrings("x", &byte);
                saw_data = true;
            },
            else => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expect(saw_head);
    try std.testing.expectError(
        error.InvalidContentLength,
        client.receiveResponseEvent(malformed),
    );
    try std.testing.expect(!client.request_lifecycle.contains(malformed));
    try std.testing.expect(client.request_lifecycle.contains(sibling));

    var sibling_response = try client.receiveResponse(sibling);
    defer sibling_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), sibling_response.response.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake server aborts incomplete request and accepts sibling" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{
        0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
    };
    const client_cid = [_]u8{ 0xd9, 0xda, 0xdb, 0xdc };
    const server_cid = [_]u8{ 0xdd, 0xde, 0xdf, 0xe0 };
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
            .random = [_]u8{0xe1} ** 32,
            .x25519_secret_key = [_]u8{0xe2} ** 32,
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
            try std.testing.expectError(
                error.RequestIncomplete,
                session.receiveRequest(),
            );
            try std.testing.expect(!session.established.connection.closing());

            var sibling = try session.receiveRequest();
            defer sibling.deinit(allocator);
            try std.testing.expectEqualStrings(
                "/after-incomplete-request",
                sibling.request.path,
            );
            try session.sendResponse(sibling.stream_id, .{ .status = 204 });
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
            .random = [_]u8{0xe3} ** 32,
            .x25519_secret_key = [_]u8{0xe4} ** 32,
        } },
    );
    defer client.deinit();

    try client.sendMaxPushId(0);
    const incomplete = try client.openClientBidirectionalStream();
    try client.established.connection.send(&.{.{ .stream = .{
        .stream_id = incomplete,
        .data = &.{},
        .fin = true,
    } }});
    const sibling = try client.sendRequest(.{
        .method = "GET",
        .path = "/after-incomplete-request",
        .authority = "localhost",
    });

    var saw_incomplete = false;
    while (!saw_incomplete) {
        var packet = try client.established.connection.receivePacketTimeout(.{
            .duration = .{
                .clock = .awake,
                .raw = .fromSeconds(2),
            },
        });
        defer packet.deinit(allocator);
        for (packet.frames) |frame| switch (frame) {
            .reset_stream => |reset| if (reset.stream_id == incomplete) {
                try std.testing.expectEqual(
                    @as(u64, http3.ApplicationErrorCode.request_incomplete),
                    reset.application_error_code,
                );
                saw_incomplete = true;
            },
            else => {},
        };
    }

    var response = try client.receiveResponse(sibling);
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), response.response.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client resets response without headers and preserves sibling" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{
        0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
    };
    const client_cid = [_]u8{ 0xf9, 0xfa, 0xfb, 0xfc };
    const server_cid = [_]u8{ 0xfd, 0xfe, 0xef, 0xe0 };
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
            .random = [_]u8{0xf1} ** 32,
            .x25519_secret_key = [_]u8{0xf2} ** 32,
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
            var first = try session.receiveRequest();
            defer first.deinit(allocator);
            var second = try session.receiveRequest();
            defer second.deinit(allocator);
            const missing = if (std.mem.eql(
                u8,
                first.request.path,
                "/missing-response",
            )) first.stream_id else second.stream_id;
            const sibling = if (missing == first.stream_id)
                second.stream_id
            else
                first.stream_id;
            try session.sendOrigins(&.{});
            var sibling_bytes: std.ArrayList(u8) = .empty;
            defer sibling_bytes.deinit(allocator);
            try (http3.Response{ .status = 204 }).write(
                &sibling_bytes,
                allocator,
            );
            try session.established.connection.send(&.{
                .{ .stream = .{
                    .stream_id = sibling,
                    .data = sibling_bytes.items,
                    .fin = true,
                } },
                .{ .stream = .{
                    .stream_id = missing,
                    .data = &.{},
                    .fin = true,
                } },
            });

            var saw_stop = false;
            while (!saw_stop) {
                var packet = try session.established.connection
                    .receivePacketTimeout(.{ .duration = .{
                    .clock = .awake,
                    .raw = .fromSeconds(2),
                } });
                defer packet.deinit(allocator);
                for (packet.frames) |frame| switch (frame) {
                    .stop_sending => |stop| if (stop.stream_id == missing) {
                        try std.testing.expectEqual(
                            @as(u64, http3.ApplicationErrorCode.message_error),
                            stop.application_error_code,
                        );
                        saw_stop = true;
                    },
                    else => {},
                };
            }
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
            .random = [_]u8{0xf3} ** 32,
            .x25519_secret_key = [_]u8{0xf4} ** 32,
        } },
    );
    defer client.deinit();

    const missing = try client.sendRequest(.{
        .method = "GET",
        .path = "/missing-response",
        .authority = "localhost",
    });
    const sibling = try client.sendRequest(.{
        .method = "GET",
        .path = "/valid-response",
        .authority = "localhost",
    });
    try std.testing.expectError(
        error.MissingStatus,
        client.receiveResponse(missing),
    );
    try std.testing.expect(!client.established.connection.closing());
    try std.testing.expect(!client.request_lifecycle.contains(missing));
    try std.testing.expect(client.request_lifecycle.contains(sibling));

    var response = try client.receiveResponse(sibling);
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), response.response.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
