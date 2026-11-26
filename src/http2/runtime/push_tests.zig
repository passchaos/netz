const std = @import("std");
const forwarded_io = @import("../../internal/testing/forwarded_io.zig");
const native_protocol_io = @import("../../internal/testing/native_protocol_io.zig");
const http2 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const Server = runtime.Server;
const Client = runtime.Client;
const Connection = runtime.Connection;
test "HTTP/2 explicit server push delivers promise and pushed response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            var request = connection.readRequest() catch |err| {
                shared.err = err;
                return;
            };
            defer request.deinit(shared.server.allocator);
            const pushed_stream = connection.promisePush(
                request.stream_id,
                &.{
                    .{ .name = ":method", .value = "GET" },
                    .{ .name = ":path", .value = "/style.css" },
                    .{ .name = ":scheme", .value = "http" },
                    .{ .name = ":authority", .value = "localhost" },
                },
            ) catch |err| {
                shared.err = err;
                return;
            };
            connection.writeResponse(request.stream_id, .{
                .body = "parent",
            }) catch |err| {
                shared.err = err;
                return;
            };
            connection.writePushedResponse(pushed_stream, .{
                .body = "css",
            }) catch |err| {
                shared.err = err;
                return;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .enable_push = true,
        },
    );
    defer client.close();
    var parent = try client.request(.{
        .path = "/",
        .authority = "localhost",
    });
    defer parent.deinit(allocator);
    try std.testing.expectEqualStrings("parent", parent.body);

    var promise = client.takePromisedRequest() orelse
        return error.TestUnexpectedResult;
    defer promise.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 2), promise.promised_stream_id);
    try std.testing.expectEqualStrings(
        "/style.css",
        runtime.testing.findHeader(promise.headers, ":path").?,
    );
    var pushed = try client.readPushedResponse(promise);
    defer pushed.deinit(allocator);
    try std.testing.expectEqualStrings("css", pushed.body);
    try std.testing.expectEqual(
        @as(usize, 29),
        runtime.testing.findHeader(pushed.headers, "date").?.len,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 push promises require monotonic server stream IDs" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .limits = .{ .enable_push = true },
    };
    defer {
        connection.push_state.deinit(allocator);
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
    }
    try runtime.testing.addActiveLocalStream(&connection, 1);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/push" },
        .{ .name = ":scheme", .value = "http" },
    });
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try http2.PushPromisePayload.write(
        &encoded,
        allocator,
        1,
        2,
        block.items,
        .{},
    );
    const frame = try http2.Frame.parse(encoded.items);
    try runtime.testing.receivePushPromise(&connection, frame);
    try std.testing.expectError(
        error.InvalidStreamId,
        runtime.testing.receivePushPromise(&connection, frame),
    );
}

test "HTTP/2 reserved push promises consume peer stream capacity" {
    try native_protocol_io.runStream(reservedPushPromisesConsumePeerStreamCapacity);
}

fn reservedPushPromisesConsumePeerStreamCapacity(io: std.Io) !void {
    const allocator = std.testing.allocator;
    const RecordingWriter = struct {
        delegate: std.Io,
        bytes: std.ArrayList(u8) = .empty,

        fn write(
            context: ?*anyopaque,
            _: std.Io.net.Socket.Handle,
            header: []const u8,
            data: []const []const u8,
            splat: usize,
        ) std.Io.net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            var total = header.len;
            self.bytes.appendSlice(allocator, header) catch
                return error.SystemResources;
            for (data[0 .. data.len - 1]) |part| {
                total += part.len;
                self.bytes.appendSlice(allocator, part) catch
                    return error.SystemResources;
            }
            for (0..splat) |_| {
                const part = data[data.len - 1];
                total += part.len;
                self.bytes.appendSlice(allocator, part) catch
                    return error.SystemResources;
            }
            return total;
        }
    };

    var writer: RecordingWriter = .{ .delegate = io };
    defer writer.bytes.deinit(allocator);
    var connection = Connection{
        .io = forwarded_io.observer(&writer, .{ .netWrite = RecordingWriter.write }),
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .limits = .{
            .enable_push = true,
            .max_concurrent_streams = 1,
            .max_local_error_reset_streams = 2,
        },
    };
    defer {
        connection.push_state.deinit(allocator);
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
    }
    try runtime.testing.addActiveLocalStream(&connection, 1);

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/push" },
        .{ .name = ":scheme", .value = "http" },
    });
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try http2.PushPromisePayload.write(
        &encoded,
        allocator,
        1,
        2,
        block.items,
        .{},
    );
    try runtime.testing.receivePushPromise(
        &connection,
        try http2.Frame.parse(encoded.items),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        connection.push_state.remoteReservedCount(),
    );

    encoded.clearRetainingCapacity();
    try http2.PushPromisePayload.write(
        &encoded,
        allocator,
        1,
        4,
        block.items,
        .{},
    );
    try runtime.testing.receivePushPromise(
        &connection,
        try http2.Frame.parse(encoded.items),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        connection.push_state.remoteReservedCount(),
    );
    try std.testing.expectEqual(@as(usize, 1), connection.local_error_reset_streams);
    const refused = try http2.Frame.parse(writer.bytes.items);
    const reset = try http2.ResetStreamPayload.parse(refused);
    try std.testing.expectEqual(@as(u31, 4), reset.stream_id);
    try std.testing.expectEqual(http2.ErrorCode.refused_stream, reset.error_code);

    // Releasing the first reservation restores capacity, and the refused ID
    // still advances monotonic peer-stream validation for the next promise.
    try std.testing.expect(connection.push_state.cancelRemote(allocator, 2));
    encoded.clearRetainingCapacity();
    try http2.PushPromisePayload.write(
        &encoded,
        allocator,
        1,
        6,
        block.items,
        .{},
    );
    try runtime.testing.receivePushPromise(
        &connection,
        try http2.Frame.parse(encoded.items),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        connection.push_state.remoteReservedCount(),
    );
}

test "HTTP/2 server push fragments large promised request headers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 128,
            .max_body_bytes = 4096,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            var request = connection.readRequest() catch |err| {
                shared.err = err;
                return;
            };
            defer request.deinit(shared.server.allocator);
            const large_value = [_]u8{'x'} ** 512;
            const pushed_stream = connection.promisePush(
                request.stream_id,
                &.{
                    .{ .name = ":method", .value = "GET" },
                    .{ .name = ":path", .value = "/large.css" },
                    .{ .name = ":scheme", .value = "http" },
                    .{ .name = "x-large", .value = &large_value },
                },
            ) catch |err| {
                shared.err = err;
                return;
            };
            connection.writeResponse(request.stream_id, .{
                .body = "parent",
            }) catch |err| {
                shared.err = err;
                return;
            };
            connection.writePushedResponse(pushed_stream, .{
                .body = "large",
            }) catch |err| {
                shared.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .max_frame_payload = 128,
            .max_body_bytes = 4096,
            .enable_push = true,
        },
    );
    defer client.close();
    var parent = try client.request(.{
        .path = "/",
        .authority = "localhost",
    });
    defer parent.deinit(allocator);
    var promise = client.takePromisedRequest() orelse
        return error.TestUnexpectedResult;
    defer promise.deinit(allocator);
    try std.testing.expectEqual(
        @as(usize, 512),
        runtime.testing.findHeader(promise.headers, "x-large").?.len,
    );
    var pushed = try client.readPushedResponse(promise);
    defer pushed.deinit(allocator);
    try std.testing.expectEqualStrings("large", pushed.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 client cancels a reserved promised push" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        canceled_stream_id: ?u31 = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var request = try connection.readRequest();
            defer request.deinit(shared.server.allocator);
            const pushed_stream = try connection.promisePush(
                request.stream_id,
                &.{
                    .{ .name = ":method", .value = "GET" },
                    .{ .name = ":path", .value = "/unused.css" },
                    .{ .name = ":scheme", .value = "http" },
                    .{ .name = ":authority", .value = "localhost" },
                },
            );
            try connection.writeResponse(request.stream_id, .{
                .body = "parent",
            });

            var reset = try connection.readResetStream();
            defer reset.deinit(shared.server.allocator);
            try std.testing.expectEqual(
                pushed_stream,
                reset.reset.stream_id,
            );
            try std.testing.expectEqual(
                http2.ErrorCode.cancel,
                reset.reset.error_code,
            );
            shared.canceled_stream_id = reset.reset.stream_id;

            // The reservation remains as a cancellation tombstone until the
            // producer attempts to fulfill it. This prevents an application
            // race from turning a consumed RST_STREAM into pushed HEADERS.
            try std.testing.expectError(
                error.StreamReset,
                connection.writePushedResponse(pushed_stream, .{
                    .body = "must not be sent",
                }),
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .enable_push = true,
        },
    );
    defer client.close();
    var parent = try client.request(.{
        .path = "/",
        .authority = "localhost",
    });
    defer parent.deinit(allocator);
    try std.testing.expectEqualStrings("parent", parent.body);

    var promise = client.takePromisedRequest() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(
        "/unused.css",
        runtime.testing.findHeader(promise.headers, ":path").?,
    );
    const promised_stream_id = promise.promised_stream_id;
    try std.testing.expectError(
        error.Timeout,
        client.cancelPushWithTimeout(&promise, .zero),
    );
    try client.cancelPushWithTimeout(&promise, .fromSeconds(1));

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(
        promised_stream_id,
        shared.canceled_stream_id.?,
    );
}
