const std = @import("std");
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
        connection.active_peer_streams.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
    }
    try connection.active_local_streams.append(allocator, 1);
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
