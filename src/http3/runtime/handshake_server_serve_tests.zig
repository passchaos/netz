const std = @import("std");
const http3 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const net = std.Io.net;

test "HTTP/3 handshake serveConnection handles bounded persistent requests" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };
    const client_cid = [_]u8{ 0x49, 0x4a, 0x4b, 0x4c };
    const server_cid = [_]u8{ 0x4d, 0x4e, 0x4f, 0x50 };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x51} ** 32,
            .x25519_secret_key = [_]u8{0x52} ** 32,
        } },
    );
    defer server.deinit();

    const Context = struct {
        calls: usize = 0,

        fn handle(
            self: *@This(),
            request: runtime.OwnedHandshakeRequest,
        ) runtime.Error!http3.Response {
            self.calls += 1;
            if (std.mem.eql(u8, request.request.path, "/first")) {
                return .{ .status = 201, .body = "first-response" };
            }
            if (std.mem.eql(u8, request.request.path, "/second")) {
                return .{
                    .status = 202,
                    .body = "second-response",
                    .trailers = &.{.{
                        .name = "x-finished",
                        .value = "yes",
                    }},
                };
            }
            return .{ .status = 404 };
        }
    };
    const Shared = struct {
        server: *runtime.HandshakeServer,
        context: Context = .{},
        served: ?usize = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.served = shared.server.serveConnection(
                Context,
                &shared.context,
                Context.handle,
                2,
            ) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x53} ** 32,
            .x25519_secret_key = [_]u8{0x54} ** 32,
        } },
    );
    defer client.deinit();

    var first = try client.request(.{
        .method = "GET",
        .path = "/first",
        .authority = "localhost",
    });
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 201), first.response.status);
    try std.testing.expectEqualStrings("first-response", first.response.body);

    var second = try client.request(.{
        .method = "POST",
        .path = "/second",
        .authority = "localhost",
        .body = "request-body",
    });
    defer second.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 202), second.response.status);
    try std.testing.expectEqualStrings("second-response", second.response.body);
    try std.testing.expectEqualStrings(
        "yes",
        second.response.trailers[0].value,
    );

    while (client.control.peer_goaway_id == null or
        client.control.peer_goaway_id.? != 8)
    {
        try client.receiveProgress();
    }
    try std.testing.expectEqual(@as(?u64, 8), client.control.peer_goaway_id);
    try std.testing.expectError(error.GoAwayReceived, client.sendRequest(.{
        .method = "GET",
        .path = "/third",
        .authority = "localhost",
    }));

    server_thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(?usize, 2), shared.served);
    try std.testing.expectEqual(@as(usize, 2), shared.context.calls);
}

test "HTTP/3 handshake serveOne propagates handler failure" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68 };
    const client_cid = [_]u8{ 0x69, 0x6a, 0x6b, 0x6c };
    const server_cid = [_]u8{ 0x6d, 0x6e, 0x6f, 0x70 };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x71} ** 32,
            .x25519_secret_key = [_]u8{0x72} ** 32,
        } },
    );
    defer server.deinit();

    const Context = struct {
        fn handle(
            _: *@This(),
            request: runtime.OwnedHandshakeRequest,
        ) runtime.Error!http3.Response {
            if (!std.mem.eql(u8, request.request.path, "/handler-error")) {
                return error.InvalidUri;
            }
            return error.InvalidHeader;
        }
    };
    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *runtime.HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            var context = Context{};
            try std.testing.expectError(
                error.InvalidHeader,
                session.serveOne(Context, &context, Context.handle),
            );
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x73} ** 32,
            .x25519_secret_key = [_]u8{0x74} ** 32,
        } },
    );
    defer client.deinit();

    _ = try client.sendRequest(.{
        .method = "GET",
        .path = "/handler-error",
        .authority = "localhost",
    });
    server_thread.join();
    if (shared.err) |err| return err;
}
