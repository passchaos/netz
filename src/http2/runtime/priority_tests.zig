const std = @import("std");
const http2 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const Client = runtime.Client;
const Connection = runtime.Connection;
const Server = runtime.Server;

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

test "HTTP/2 PRIORITY_UPDATE before request is retained and replaced" {
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
            .max_concurrent_streams = 4,
            .no_rfc7540_priorities = true,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        priority: ?http2.ExtensiblePriority = null,
        field_value: [64]u8 = undefined,
        field_value_len: usize = 0,
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
            try std.testing.expectEqual(@as(u31, 1), request.stream_id);
            try std.testing.expectEqual(@as(u3, 1), request.priority.urgency);
            try std.testing.expect(request.priority.incremental);
            shared.priority = connection.peerPriority(request.stream_id);
            const field_value =
                connection.peerPriorityFieldValue(request.stream_id) orelse
                return error.TestUnexpectedResult;
            @memcpy(
                shared.field_value[0..field_value.len],
                field_value,
            );
            shared.field_value_len = field_value.len;
            try connection.writeResponse(request.stream_id, .{
                .body = "prioritized",
            });
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
            .no_rfc7540_priorities = true,
        },
    );
    defer client.close();
    try client.sendPriorityUpdate(1, .{ .urgency = 6 });
    try client.sendPriorityUpdateRaw(1, "u=1, i, custom=?1");
    var response = try client.request(.{
        .path = "/priority",
        .authority = "localhost",
        .priority = .{ .urgency = 4 },
    });
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("prioritized", response.body);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u3, 1), shared.priority.?.urgency);
    try std.testing.expect(shared.priority.?.incremental);
    try std.testing.expectEqualStrings(
        "u=1, i, custom=?1",
        shared.field_value[0..shared.field_value_len],
    );
}

test "HTTP/2 PRIORITY_UPDATE reprioritizes a promised push" {
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
            .no_rfc7540_priorities = true,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        pushed_stream: ?u31 = null,
        priority: ?http2.ExtensiblePriority = null,
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
                    .{ .name = ":path", .value = "/priority.css" },
                    .{ .name = ":scheme", .value = "http" },
                    .{ .name = ":authority", .value = "localhost" },
                },
            );
            shared.pushed_stream = pushed_stream;
            try connection.writeResponse(request.stream_id, .{
                .body = "parent",
            });
            const update = try connection.readPriorityUpdate();
            try std.testing.expectEqual(
                pushed_stream,
                update.prioritized_stream_id,
            );
            shared.priority = connection.peerPriority(pushed_stream);
            try connection.writePushedResponse(pushed_stream, .{
                .body = "css",
            });
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
            .no_rfc7540_priorities = true,
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
    try client.sendPriorityUpdate(
        promise.promised_stream_id,
        .{ .urgency = 0 },
    );
    var pushed = try client.readPushedResponse(promise);
    defer pushed.deinit(allocator);
    try std.testing.expectEqualStrings("css", pushed.body);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u31, 2), shared.pushed_stream.?);
    try std.testing.expectEqual(@as(u3, 0), shared.priority.?.urgency);
}

test "HTTP/2 bounded PRIORITY_UPDATE resumes a partial frame" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .no_rfc7540_priorities = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        prefix_sent: std.Io.Event = .unset,
        timed_out: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.prefix_sent.set(self.server.io);
                self.timed_out.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(self.server.allocator);
            try http2.PriorityUpdatePayload.write(
                &encoded,
                self.server.allocator,
                1,
                "u=2, i",
            );
            const split = http2.FrameHeader.encoded_len - 2;
            try writeAll(
                self.server.io,
                connection.stream,
                encoded.items[0..split],
            );
            self.prefix_sent.set(self.server.io);
            try self.timed_out.wait(self.server.io);
            try writeAll(
                self.server.io,
                connection.stream,
                encoded.items[split..],
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    client.role = .server;
    client.limits.no_rfc7540_priorities = true;
    defer client.close();
    try shared.prefix_sent.wait(io);
    try std.testing.expectError(
        error.Timeout,
        client.readPriorityUpdateWithTimeout(.fromMilliseconds(20)),
    );
    shared.timed_out.set(io);
    const update = try client.readPriorityUpdateWithDeadline(.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    ));
    try std.testing.expectEqual(@as(u31, 1), update.prioritized_stream_id);
    try std.testing.expectEqualStrings("u=2, i", update.field_value);
    try std.testing.expectEqual(
        http2.ExtensiblePriority{ .urgency = 2, .incremental = true },
        client.peerPriority(1).?,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 PRIORITY_UPDATE enforces negotiation and target direction" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.push_state.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }

    try std.testing.expectError(
        error.UnexpectedFrame,
        connection.sendPriorityUpdate(1, .{ .urgency = 1 }),
    );
    connection.peer_no_rfc7540_priorities = true;
    try std.testing.expectError(
        error.InvalidStreamId,
        connection.sendPriorityUpdate(0, .{ .urgency = 1 }),
    );
    try std.testing.expectError(
        error.InvalidStreamId,
        connection.sendPriorityUpdate(2, .{ .urgency = 1 }),
    );
}

test "HTTP/2 client opens lower streams before a pre-prioritized stream" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .peer_max_concurrent_streams = 4,
    };
    defer {
        connection.push_state.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }

    try connection.priority_state.reserveIdleRequest(
        allocator,
        3,
        0,
        connection.peer_max_concurrent_streams,
        connection.limits.max_idle_priority_updates,
    );
    try std.testing.expectEqual(
        @as(u31, 1),
        try runtime.testing.reserveNextClientStreamId(&connection),
    );
    try std.testing.expect(
        connection.priority_state.containsIdleRequest(3),
    );
    runtime.testing.releaseLocalStream(&connection, 1);
    try std.testing.expectEqual(
        @as(u31, 3),
        try runtime.testing.reserveNextClientStreamId(&connection),
    );
    try std.testing.expect(
        !connection.priority_state.containsIdleRequest(3),
    );
}

test "HTTP/2 PRIORITY_UPDATE rejects server frames and idle pushes" {
    const allocator = std.testing.allocator;
    var client = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        client.push_state.deinit(allocator);
        client.priority_state.deinit(allocator);
        client.active_local_streams.deinit(allocator);
        client.active_peer_streams.deinit(allocator);
        client.hpack_decoder.deinit(allocator);
        client.hpack_encoder.deinit(allocator);
    }
    try std.testing.expectError(
        error.InvalidFrame,
        runtime.testing.receivePriorityUpdate(
            &client,
            try priorityUpdateFrame(allocator, 1),
        ),
    );

    var server = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{ .no_rfc7540_priorities = true },
    };
    defer {
        server.push_state.deinit(allocator);
        server.priority_state.deinit(allocator);
        server.active_local_streams.deinit(allocator);
        server.active_peer_streams.deinit(allocator);
        server.hpack_decoder.deinit(allocator);
        server.hpack_encoder.deinit(allocator);
    }
    try std.testing.expectError(
        error.InvalidFrame,
        runtime.testing.receivePriorityUpdate(
            &server,
            try priorityUpdateFrame(allocator, 2),
        ),
    );
}

test "HTTP/2 PRIORITY_UPDATE bounds speculative idle requests" {
    const allocator = std.testing.allocator;
    var server = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{
            .no_rfc7540_priorities = true,
            .max_idle_priority_updates = 1,
        },
    };
    defer {
        server.push_state.deinit(allocator);
        server.priority_state.deinit(allocator);
        server.active_local_streams.deinit(allocator);
        server.active_peer_streams.deinit(allocator);
        server.hpack_decoder.deinit(allocator);
        server.hpack_encoder.deinit(allocator);
    }

    try runtime.testing.receivePriorityUpdate(
        &server,
        try priorityUpdateFrame(allocator, 1),
    );
    try std.testing.expectError(
        error.PriorityCapacityExceeded,
        runtime.testing.receivePriorityUpdate(
            &server,
            try priorityUpdateFrame(allocator, 3),
        ),
    );
}

fn priorityUpdateFrame(
    allocator: std.mem.Allocator,
    stream_id: u31,
) !http2.Frame {
    _ = allocator;
    const payload = switch (stream_id) {
        1 => &[_]u8{ 0, 0, 0, 1, 'u', '=', '1' },
        2 => &[_]u8{ 0, 0, 0, 2, 'u', '=', '1' },
        3 => &[_]u8{ 0, 0, 0, 3, 'u', '=', '1' },
        else => return error.TestUnexpectedResult,
    };
    return .{
        .header = .{
            .length = @intCast(payload.len),
            .frame_type = .priority_update,
            .flags = 0,
            .stream_id = 0,
        },
        .payload = payload,
    };
}
