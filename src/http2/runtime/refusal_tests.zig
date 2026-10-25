const std = @import("std");

test {
    _ = @import("headers/refusal_isolation_tests.zig");
}
const http2 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const flag_end_stream: u8 = 0x1;
const flag_end_headers: u8 = 0x4;

fn writeAll(
    io: std.Io,
    stream: std.Io.net.Stream,
    bytes: []const u8,
) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        const count = try io.vtable.netWrite(
            io.userdata,
            stream.socket.handle,
            bytes[written..],
            &.{""},
            0,
        );
        if (count == 0) return error.SocketUnconnected;
        written += count;
    }
}

fn writeFrame(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,
    frame_type: http2.FrameType,
    flags: u8,
    stream_id: u31,
    payload: []const u8,
) !void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http2.Frame{
        .header = .{
            .length = 0,
            .frame_type = frame_type,
            .flags = flags,
            .stream_id = stream_id,
        },
        .payload = payload,
    }).write(&encoded, allocator);
    try writeAll(io, stream, encoded.items);
}

fn writeEncodedHeaders(
    client: *runtime.Connection,
    stream_id: u31,
    fields: []const http2.Hpack.HeaderField,
    end_stream: bool,
) !void {
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(client.allocator);
    try client.hpack_encoder.encodeBlock(
        &block,
        client.allocator,
        fields,
    );
    try writeFrame(
        client.allocator,
        client.io,
        client.stream,
        .headers,
        flag_end_headers | if (end_stream) flag_end_stream else 0,
        stream_id,
        block.items,
    );
}

fn expectRefusedReset(
    client: *runtime.Connection,
    stream_id: u31,
) !void {
    var reset = try client.readResetStreamWithTimeout(.fromSeconds(2));
    defer reset.deinit(client.allocator);
    try std.testing.expectEqual(stream_id, reset.reset.stream_id);
    try std.testing.expectEqual(
        http2.ErrorCode.refused_stream,
        reset.reset.error_code,
    );
}

fn expectRefusedStateGone(
    connection: *runtime.Connection,
    stream_id: u31,
) !void {
    try std.testing.expect(
        !runtime.testing.hasActivePeerStream(connection, stream_id),
    );
    try std.testing.expect(
        !runtime.testing.hasStreamWindow(connection, stream_id),
    );
    try std.testing.expect(
        !runtime.testing.hasResponseSemantics(connection, stream_id),
    );
    try std.testing.expect(
        !runtime.testing.hasPeerPriority(connection, stream_id),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        runtime.testing.pendingRequestCount(connection),
    );
}

const ReaderPath = enum {
    aggregate_queued,
    streaming,
    batch,
    extended_connect,
};

fn ignoreRequestData(_: void, _: []const u8) !void {}

fn ignoreBatchRequestData(_: void, _: u31, _: []const u8) !void {}

fn exerciseReaderRefusal(path: ReaderPath) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const limits: runtime.Limits = .{
        .max_concurrent_streams = 1,
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
        // Capacity-driven REFUSED_STREAM now consumes the same peer-caused
        // reset budget as current h2. Leave room for this test's one refusal;
        // a zero budget intentionally upgrades it to terminal GOAWAY.
        .max_local_error_reset_streams = 4,
        .enable_connect_protocol = path == .extended_connect,
    };
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        path: ReaderPath,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn expectLaterRequest(
            self: *@This(),
            connection: *runtime.Connection,
            stream_id: u31,
            request_path: []const u8,
        ) !void {
            try std.testing.expectEqual(@as(u31, 5), stream_id);
            try std.testing.expectEqualStrings("/accepted", request_path);
            try std.testing.expect(
                !runtime.testing.hasActivePeerStream(connection, 1),
            );
            try expectRefusedStateGone(connection, 3);
            try std.testing.expectEqual(
                @as(u31, 5),
                runtime.testing.lastPeerClientStreamId(connection),
            );
            _ = self;
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();

            switch (self.path) {
                .aggregate_queued => {
                    // Stream 3 arrives while stream 1's aggregate body loop is
                    // active, exercising queueCompletePeerRequestFrameUntil.
                    var first = try connection.readRequest();
                    defer first.deinit(self.server.allocator);
                    try std.testing.expectEqual(@as(u31, 1), first.stream_id);
                    try std.testing.expectEqualStrings("body", first.body);
                    try connection.writeResponse(first.stream_id, .{
                        .status = 204,
                    });

                    var next = try connection.readRequest();
                    defer next.deinit(self.server.allocator);
                    try self.expectLaterRequest(
                        &connection,
                        next.stream_id,
                        next.path,
                    );
                    try connection.writeResponse(next.stream_id, .{
                        .body = "accepted",
                    });
                },
                .streaming => {
                    var first = try connection.readRequestStreaming(
                        {},
                        ignoreRequestData,
                    );
                    defer first.deinit(self.server.allocator);
                    try std.testing.expectEqual(@as(u31, 1), first.stream_id);
                    try std.testing.expectEqual(@as(usize, 4), first.body_bytes);
                    try connection.writeResponse(first.stream_id, .{
                        .status = 204,
                    });

                    var next = try connection.readRequestStreaming(
                        {},
                        ignoreRequestData,
                    );
                    defer next.deinit(self.server.allocator);
                    try self.expectLaterRequest(
                        &connection,
                        next.stream_id,
                        next.path,
                    );
                    try connection.writeResponse(next.stream_id, .{
                        .body = "accepted",
                    });
                },
                .batch => {
                    var requests: [1]runtime.StreamingRequest = undefined;
                    var initialized = false;
                    defer if (initialized) requests[0].deinit(
                        self.server.allocator,
                    );
                    try connection.readRequestBatchStreamingInto(
                        &requests,
                        {},
                        ignoreBatchRequestData,
                    );
                    initialized = true;
                    try self.expectLaterRequest(
                        &connection,
                        requests[0].stream_id,
                        requests[0].path,
                    );
                    try connection.writeResponse(requests[0].stream_id, .{
                        .body = "accepted",
                    });
                },
                .extended_connect => {
                    var first = try connection.readRequest();
                    defer first.deinit(self.server.allocator);
                    try std.testing.expectEqual(@as(u31, 1), first.stream_id);

                    var next = try connection.readExtendedConnectRequest(
                        "websocket",
                    );
                    defer next.deinit(self.server.allocator);
                    try self.expectLaterRequest(
                        &connection,
                        next.stream_id,
                        next.path,
                    );
                    try std.testing.expectEqualStrings(
                        "websocket",
                        next.protocol,
                    );
                    try connection.rejectExtendedConnect(
                        next.stream_id,
                        403,
                        &.{},
                    );
                },
            }
        }
    };

    var shared = Shared{ .server = &server, .path = path };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();

    var held_writer: ?runtime.RequestWriter = null;
    defer if (held_writer) |*writer| writer.deinit();
    switch (path) {
        .aggregate_queued, .streaming => held_writer = try client.startRequest(.{
            .path = "/held",
            .authority = "localhost",
            .body_length = 4,
        }),
        .batch => held_writer = try client.startRequest(.{
            .path = "/held",
            .authority = "localhost",
        }),
        .extended_connect => {
            _ = try runtime.testing.sendCompleteRequest(&client, .{
                .path = "/held",
                .authority = "localhost",
            });
        },
    }

    if (path == .extended_connect) {
        try writeEncodedHeaders(&client, 3, &.{
            .{ .name = ":method", .value = "CONNECT" },
            .{ .name = ":protocol", .value = "websocket" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":path", .value = "/refused" },
            .{ .name = ":authority", .value = "localhost" },
        }, false);
    } else {
        try writeEncodedHeaders(&client, 3, &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":path", .value = "/refused" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":authority", .value = "localhost" },
        }, true);
    }
    try expectRefusedReset(&client, 3);

    switch (path) {
        .aggregate_queued, .streaming => {
            try held_writer.?.finishData("body");
            var response = try held_writer.?.readResponseWithTimeout(
                .fromSeconds(2),
            );
            defer response.deinit(allocator);
            try std.testing.expectEqual(@as(u16, 204), response.status);
        },
        .batch => held_writer.?.deinit(),
        .extended_connect => {
            var reset_one: [http2.ResetStreamPayload.encoded_len]u8 = undefined;
            const encoded = try http2.ResetStreamPayload.writeInto(
                &reset_one,
                1,
                .cancel,
            );
            try writeAll(io, client.stream, encoded);
            runtime.testing.releaseLocalStream(&client, 1);
        },
    }
    // The client intentionally never consumes a response on stream 1. Its
    // local reset closed that stream, so the server can safely send stream 5.
    // Mark stream 5 active locally before injecting its raw HPACK block, as a
    // normal client request API would do before waiting for the response.
    try runtime.testing.addActiveLocalStream(&client, 5);

    if (path == .extended_connect) {
        try writeEncodedHeaders(&client, 5, &.{
            .{ .name = ":method", .value = "CONNECT" },
            .{ .name = ":protocol", .value = "websocket" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":path", .value = "/accepted" },
            .{ .name = ":authority", .value = "localhost" },
        }, false);
    } else {
        try writeEncodedHeaders(&client, 5, &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":path", .value = "/accepted" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":authority", .value = "localhost" },
        }, true);
    }

    var response = try client.readResponseWithTimeout(
        5,
        if (path == .extended_connect) "CONNECT" else "GET",
        path == .extended_connect,
        .fromSeconds(2),
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(
        if (path == .extended_connect) @as(u16, 403) else @as(u16, 200),
        response.status,
    );
    if (path != .extended_connect) {
        try std.testing.expectEqualStrings("accepted", response.body);
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 aggregate body reader refuses interleaved queued sibling" {
    try exerciseReaderRefusal(.aggregate_queued);
}

test "HTTP/2 streaming request reader skips refused stream" {
    try exerciseReaderRefusal(.streaming);
}

test "HTTP/2 batch request reader replaces refused stream" {
    try exerciseReaderRefusal(.batch);
}

test "HTTP/2 Extended CONNECT reader skips refused stream" {
    try exerciseReaderRefusal(.extended_connect);
}

test "HTTP/2 refuses excess fragmented request without leaking stream state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const limits: runtime.Limits = .{
        .max_concurrent_streams = 1,
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
        .no_rfc7540_priorities = true,
    };
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();

            // Stream 1 deliberately remains active while the aggregate reader
            // encounters stream 3. Stream 3 must be refused rather than
            // turning this valid capacity race into a connection error.
            var first = try connection.readRequest();
            defer first.deinit(self.server.allocator);
            try std.testing.expectEqual(@as(u31, 1), first.stream_id);
            try std.testing.expectEqualStrings("/held", first.path);

            // The client resets stream 1 after observing REFUSED_STREAM. The
            // same aggregate read pumps that reset, freeing the sole slot,
            // discards stream 3's late DATA/trailers, and returns stream 5.
            var next = try connection.readRequest();
            defer next.deinit(self.server.allocator);
            try std.testing.expectEqual(@as(u31, 5), next.stream_id);
            try std.testing.expectEqualStrings("/after-refusal", next.path);
            try std.testing.expectEqualStrings(
                "from-refused-stream",
                runtime.testing.findHeader(next.headers, "x-shared").?,
            );

            try std.testing.expect(
                !runtime.testing.hasActivePeerStream(&connection, 1),
            );
            try std.testing.expect(
                !runtime.testing.hasActivePeerStream(&connection, 3),
            );
            try std.testing.expect(
                !runtime.testing.hasStreamWindow(&connection, 3),
            );
            try std.testing.expect(
                !runtime.testing.hasResponseSemantics(&connection, 3),
            );
            try std.testing.expect(
                !runtime.testing.hasPeerPriority(&connection, 3),
            );
            try std.testing.expectEqual(
                @as(usize, 0),
                runtime.testing.pendingRequestCount(&connection),
            );
            try std.testing.expectEqual(
                @as(u31, 5),
                runtime.testing.lastPeerClientStreamId(&connection),
            );
            try std.testing.expectEqual(
                @as(usize, 1),
                runtime.testing.localErrorResetCount(&connection),
            );

            try connection.writeResponse(next.stream_id, .{
                .body = "connection-reused",
            });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(allocator, io, server.address(), limits);
    defer client.close();

    _ = try runtime.testing.sendCompleteRequest(&client, .{
        .method = "GET",
        .path = "/held",
        .authority = "localhost",
    });

    // One encoder owns all three blocks. In particular, stream 5 encodes
    // x-shared as a dynamic-table reference to the entry inserted by the
    // refused stream 3, proving the receiver decoded the refused block.
    const refused_block = try allocator.dupe(
        u8,
        try client.hpack_encoder.encodeBlockRetained(allocator, &.{
            .{ .name = ":method", .value = "POST" },
            .{ .name = ":path", .value = "/refused" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":authority", .value = "localhost" },
            .{ .name = "x-shared", .value = "from-refused-stream" },
        }),
    );
    defer allocator.free(refused_block);
    const trailer_block = try allocator.dupe(
        u8,
        try client.hpack_encoder.encodeBlockRetained(allocator, &.{
            .{ .name = "x-late-trailer", .value = "ignored" },
        }),
    );
    defer allocator.free(trailer_block);
    const accepted_block = try allocator.dupe(
        u8,
        try client.hpack_encoder.encodeBlockRetained(allocator, &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":path", .value = "/after-refusal" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":authority", .value = "localhost" },
            .{ .name = "x-shared", .value = "from-refused-stream" },
        }),
    );
    defer allocator.free(accepted_block);

    const split = refused_block.len / 2;
    try std.testing.expect(split != 0 and split < refused_block.len);
    try writeFrame(allocator, io, client.stream, .headers, 0, 3, refused_block[0..split]);
    try writeFrame(allocator, io, client.stream, .continuation, flag_end_headers, 3, refused_block[split..]);

    var reset = try client.readResetStreamWithTimeout(.fromSeconds(2));
    defer reset.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 3), reset.reset.stream_id);
    try std.testing.expectEqual(
        http2.ErrorCode.refused_stream,
        reset.reset.error_code,
    );

    // These frames can already have been in flight when the reset arrived.
    // They must consume no persistent per-stream state and must not obscure
    // the later admissible request.
    try writeFrame(allocator, io, client.stream, .data, 0, 3, "late");
    try writeFrame(allocator, io, client.stream, .headers, flag_end_headers | flag_end_stream, 3, trailer_block);

    try client.sendResetStream(1, .cancel);
    try writeFrame(allocator, io, client.stream, .headers, flag_end_headers | flag_end_stream, 5, accepted_block);

    var reused_response = try client.readResponseWithTimeout(
        5,
        "GET",
        false,
        .fromSeconds(2),
    );
    defer reused_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), reused_response.status);
    try std.testing.expectEqualStrings("connection-reused", reused_response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
