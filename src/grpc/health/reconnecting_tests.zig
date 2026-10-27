const std = @import("std");
const grpc = @import("../mod.zig");
const http2 = @import("../../http2/mod.zig");
const reconnecting = @import("reconnecting.zig");
const allocator = std.testing.allocator;

const Collector = struct {
    count: usize = 0,
    fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
        try std.testing.expectEqualStrings("demo.Echo", (try grpc.health.decodeRequest(message.payload)).service);
        self.count += 1;
    }
};

fn readWatch(connection: *grpc.runtime.ServerConnection) !grpc.stream.Request {
    var collector: Collector = .{};
    var request = try connection.readStreamingWithTimeout(.fromSeconds(3), &collector, Collector.consume);
    errdefer request.deinit();
    try std.testing.expectEqualStrings(grpc.health.watch_path, request.path);
    try std.testing.expectEqual(@as(usize, 1), collector.count);
    // A next-event deadline must not become a lifetime for Health/Watch.
    try std.testing.expectEqual(@as(?grpc.Timeout, null), request.timeout);
    return request;
}

fn listen(io: std.Io) !grpc.runtime.Server {
    return grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
}

fn watchOptions() reconnecting.Options {
    return .{
        .watch = .{ .service = "demo.Echo" },
        .backoff = .{
            .initial_backoff = .fromMilliseconds(100),
            .max_backoff = .fromSeconds(1),
            .multiplier = 2,
            .jitter = 0,
        },
    };
}

fn sendStatus(writer: *grpc.stream.ServerWriter, status: grpc.health.ServingStatus) !void {
    const message = try grpc.health.encodeResponseAlloc(allocator, .{ .status = status });
    defer allocator.free(message);
    try writer.writeMessage(message);
}

test "gRPC reconnecting health Watch backs off resets and disables on UNIMPLEMENTED" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try listen(io);
    defer server.deinit();
    const Peer = struct {
        fn run(server_ptr: *grpc.runtime.Server) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            for (0..4) |attempt| {
                var request = try readWatch(&connection);
                defer request.deinit();
                try std.testing.expectEqual(@as(u31, @intCast(1 + 2 * attempt)), request.transport.stream_id);
                if (attempt == 2) {
                    var writer = try connection.startStreamingResponse(request.transport.stream_id, .{});
                    defer writer.deinit();
                    try sendStatus(&writer, .not_serving);
                    try sendStatus(&writer, .serving);
                    try writer.finishWithOptions(.{ .status = .unavailable });
                } else if (attempt == 1) {
                    // Streaming RPCs may finish OK without any message. The
                    // unary helper correctly requires a unary response body.
                    try connection.connection.writeResponse(request.transport.stream_id, .{
                        .headers = &.{
                            .{ .name = "content-type", .value = "application/grpc" },
                            .{ .name = "grpc-status", .value = "0" },
                        },
                    });
                } else {
                    try connection.writeUnary(request.transport.stream_id, .{
                        .status = switch (attempt) {
                            0 => .unavailable,
                            else => .unimplemented,
                        },
                        .trailers_only = true,
                    });
                }
            }
        }
    };
    var peer = io.async(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};
    var service = [_]u8{ 'd', 'e', 'm', 'o', '.', 'E', 'c', 'h', 'o' };
    var options = watchOptions();
    options.watch.service = &service;
    var watch = try grpc.health.ReconnectingWatch.init(allocator, io, .{
        .cleartext_ip = .{ .address = server.address() },
    }, options);
    defer watch.deinit();
    @memset(&service, 'x');

    const first = try watch.nextWithTimeout(.fromSeconds(3));
    try std.testing.expectEqual(grpc.Status.unavailable, first.retrying.failure.rpc.status);
    try std.testing.expectEqual(@as(usize, 1), first.retrying.consecutive_failures);
    try std.testing.expect(!watch.isServing());
    try std.testing.expectError(error.Timeout, watch.nextWithTimeout(.fromMilliseconds(1)));
    try std.testing.expectEqualDeep(first.retrying.deadline, watch.retry_at.?);
    const second = try watch.nextWithTimeout(.fromSeconds(3));
    const second_rpc = switch (second.retrying.failure) {
        .rpc => |rpc| rpc,
        .transport => |err| return err,
    };
    try std.testing.expectEqual(grpc.Status.ok, second_rpc.status);
    try std.testing.expectEqual(@as(usize, 2), second.retrying.consecutive_failures);
    try std.testing.expectEqual(grpc.health.ServingStatus.not_serving, (try watch.nextWithTimeout(.fromSeconds(3))).status.status);
    try std.testing.expect(!watch.isServing());
    try std.testing.expectEqual(grpc.health.ServingStatus.serving, (try watch.nextWithTimeout(.fromSeconds(3))).status.status);
    try std.testing.expect(watch.isServing());
    const restart = try watch.nextWithTimeout(.fromSeconds(3));
    try std.testing.expectEqual(@as(usize, 0), restart.retrying.consecutive_failures);
    try std.testing.expect(!watch.isServing());
    try std.testing.expectEqual(reconnecting.Event.disabled, try watch.nextWithTimeout(.fromSeconds(3)));
    try std.testing.expect(watch.isServing());
    try watch.waitForServingWithTimeout(.fromMilliseconds(1));
    try std.testing.expectError(error.HealthWatchDisabled, watch.nextWithTimeout(.fromSeconds(1)));
    try peer.await(io);
}

test "gRPC reconnecting health Watch reconnects after transport EOF" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try listen(io);
    defer server.deinit();
    const Peer = struct {
        fn run(server_ptr: *grpc.runtime.Server) !void {
            for (0..2) |attempt| {
                var connection = try server_ptr.acceptWithTimeout(.fromSeconds(3));
                defer connection.deinit();
                var request = try readWatch(&connection);
                defer request.deinit();
                var writer = try connection.startStreamingResponse(request.transport.stream_id, .{});
                defer writer.deinit();
                try sendStatus(&writer, .serving);
                if (attempt == 1) try writer.finishWithOptions(.{ .status = .unimplemented });
                // Close the first transport without grpc-status or END_STREAM.
                if (attempt == 0) writer.transport.finished = true;
            }
        }
    };
    var peer = io.async(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};
    var watch = try grpc.health.ReconnectingWatch.init(allocator, io, .{
        .cleartext_ip = .{ .address = server.address() },
    }, watchOptions());
    defer watch.deinit();
    try watch.waitForServingWithTimeout(.fromSeconds(3));
    const retry = try watch.nextWithTimeout(.fromSeconds(3));
    try std.testing.expectEqual(@as(usize, 0), retry.retrying.consecutive_failures);
    try std.testing.expect(!watch.isServing());
    try watch.waitForServingWithTimeout(.fromSeconds(3));
    try std.testing.expectEqual(reconnecting.Event.disabled, try watch.nextWithTimeout(.fromSeconds(3)));
    try peer.await(io);
}

test "gRPC reconnecting health Watch preserves active reads across timeout and cancellation is terminal" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var registry = try grpc.health.Registry.init(allocator, io);
    defer registry.deinit();
    _ = try registry.setStatus("demo.Echo", .not_serving);
    var server = try listen(io);
    defer server.deinit();
    const Peer = struct {
        fn run(server_ptr: *grpc.runtime.Server, registry_ptr: *grpc.health.Registry) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var stream = try connection.acceptDuplexWithTimeout(.fromSeconds(3));
            defer stream.deinit();
            try connection.serveHealthWatch(registry_ptr, &stream);
        }
    };
    var peer = io.async(Peer.run, .{ &server, &registry });
    defer _ = peer.cancel(io) catch {};
    var watch = try grpc.health.ReconnectingWatch.init(allocator, io, .{
        .cleartext_ip = .{ .address = server.address() },
    }, watchOptions());
    defer watch.deinit();
    try std.testing.expectEqual(grpc.health.ServingStatus.not_serving, (try watch.nextWithTimeout(.fromSeconds(3))).status.status);
    const stream_id = watch.watch.?.stream.transport.streamId();
    try std.testing.expectError(error.Timeout, watch.waitForServingWithTimeout(.fromMilliseconds(1)));
    try std.testing.expectEqual(stream_id, watch.watch.?.stream.transport.streamId());
    _ = try registry.setStatus("demo.Echo", .serving);
    try watch.waitForServingWithTimeout(.fromSeconds(3));
    try watch.cancel();
    try std.testing.expect(!watch.isServing());
    try std.testing.expectError(error.HealthWatchStopped, watch.nextWithTimeout(.fromSeconds(1)));
    try std.testing.expectError(error.HealthWatchStopped, watch.waitForServingWithTimeout(.fromSeconds(1)));
    try peer.await(io);
}

test "gRPC reconnecting health Watch retains retry deadlines across task cancellation" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const Unavailable = struct {
        calls: usize = 0,
        fn connect(context: ?*anyopaque, _: std.mem.Allocator, _: std.Io, _: std.Io.Clock.Timestamp) http2.runtime.Error!http2.runtime.Connection {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            return error.ConnectionRefused;
        }
    };
    var unavailable: Unavailable = .{};
    var options = watchOptions();
    options.backoff.initial_backoff = .fromSeconds(2);
    options.backoff.max_backoff = .fromSeconds(2);
    var watch = try grpc.health.ReconnectingWatch.init(allocator, io, .{
        .custom = .{ .context = &unavailable, .connect_fn = Unavailable.connect },
    }, options);
    defer watch.deinit();
    const first = try watch.nextWithTimeout(.fromSeconds(3));
    try std.testing.expectEqual(error.ConnectionRefused, first.retrying.failure.transport);
    const Await = struct {
        fn run(watch_ptr: *grpc.health.ReconnectingWatch) !reconnecting.Event {
            return watch_ptr.nextWithTimeout(.fromSeconds(3));
        }
    };
    var pending = io.async(Await.run, .{&watch});
    try std.testing.expectError(error.Canceled, pending.cancel(io));
    try std.testing.expectEqualDeep(first.retrying.deadline, watch.retry_at.?);
    try std.testing.expectError(error.Timeout, watch.nextWithTimeout(.fromMilliseconds(1)));
    try std.testing.expectEqual(@as(usize, 1), unavailable.calls);
    try watch.cancel();
}

test "gRPC health Watch request output obeys its operation deadline without grpc-timeout" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .initial_window_size = 0 }, 4096);
    defer server.deinit();
    const Peer = struct {
        fn ignore(_: void, _: grpc.StreamingMessage) !void {
            return error.UnexpectedMessage;
        }
        fn run(server_ptr: *grpc.runtime.Server) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var stream = try connection.acceptDuplexWithTimeout(.fromSeconds(3));
            defer stream.deinit();
            try std.testing.expectEqual(@as(?grpc.Timeout, null), stream.timeout);
            var event = try stream.readRequestEventWithTimeout(.fromSeconds(3), {}, ignore);
            defer event.deinit();
            try std.testing.expectEqual(http2.ErrorCode.cancel, event.reset.error_code);
        }
    };
    var peer = io.async(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};
    var client: grpc.runtime.Client = .{ .connection = try http2.runtime.Client.connectWithTimeout(
        allocator,
        io,
        server.address(),
        .{},
        .fromSeconds(3),
    ) };
    defer client.deinit();
    try std.testing.expectError(error.Timeout, client.startHealthWatchWithTimeout(.{ .service = "demo.Echo" }, .fromMilliseconds(10)));
    try peer.await(io);
}

test "gRPC reconnecting health Watch retires malformed status messages before retry" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try listen(io);
    defer server.deinit();
    const Peer = struct {
        fn run(server_ptr: *grpc.runtime.Server) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var first = try readWatch(&connection);
            defer first.deinit();
            var writer = try connection.startStreamingResponse(first.transport.stream_id, .{});
            defer writer.deinit();
            try writer.writeMessage(&.{ 0x08, 0x7f });
            try writer.finishOk();
            var second = try readWatch(&connection);
            defer second.deinit();
            try connection.writeUnary(second.transport.stream_id, .{ .status = .unimplemented, .trailers_only = true });
        }
    };
    var peer = io.async(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};
    var watch = try grpc.health.ReconnectingWatch.init(allocator, io, .{
        .cleartext_ip = .{ .address = server.address() },
    }, watchOptions());
    defer watch.deinit();
    const retry = try watch.nextWithTimeout(.fromSeconds(3));
    try std.testing.expectEqual(error.InvalidServingStatus, retry.retrying.failure.transport);
    try std.testing.expectEqual(@as(usize, 1), retry.retrying.consecutive_failures);
    try std.testing.expect(watch.watch == null);
    try std.testing.expect(!watch.isServing());
    try std.testing.expectEqual(reconnecting.Event.disabled, try watch.nextWithTimeout(.fromSeconds(3)));
    try peer.await(io);
}

test "gRPC reconnecting health Watch preserves TLS verification and authority on reconnect" {
    const tls_testing = @import("../../tls/testing.zig");
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate_der, tls_testing.certificate_base64);
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var server = try grpc.runtime.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .transport = .{
        .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
        },
    } });
    defer server.deinit();
    const Peer = struct {
        fn run(server_ptr: *grpc.runtime.TlsServer) !void {
            for (0..2) |attempt| {
                var connection = try server_ptr.acceptWithTimeout(.fromSeconds(3));
                defer connection.deinit();
                var request = try readWatch(&connection);
                defer request.deinit();
                try std.testing.expectEqualStrings("health.example", request.transport.authority.?);
                try std.testing.expectEqualStrings("h2", connection.negotiatedAlpn().?);
                var writer = try connection.startStreamingResponse(request.transport.stream_id, .{});
                defer writer.deinit();
                try sendStatus(&writer, .serving);
                if (attempt == 1) {
                    try writer.finishWithOptions(.{ .status = .unimplemented });
                } else {
                    writer.transport.finished = true;
                }
            }
        }
    };
    var peer = io.async(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};
    var watch = try grpc.health.ReconnectingWatch.init(allocator, io, .{
        .tls_address = .{
            .address = server.address(),
            .tls_host = "localhost",
            .authority = "health.example",
            .tls = .{ .server_verifier = .{ .pinned_ecdsa_p256_public_key = public_key } },
        },
    }, watchOptions());
    defer watch.deinit();
    try watch.waitForServingWithTimeout(.fromSeconds(3));
    try std.testing.expectEqualStrings("h2", watch.owner.negotiatedAlpn().?);
    _ = (try watch.nextWithTimeout(.fromSeconds(3))).retrying;
    try watch.waitForServingWithTimeout(.fromSeconds(3));
    try std.testing.expectEqualStrings("h2", watch.owner.negotiatedAlpn().?);
    try std.testing.expect(watch.owner.peerCertificates() != null);
    try std.testing.expectEqual(reconnecting.Event.disabled, try watch.nextWithTimeout(.fromSeconds(3)));
    try peer.await(io);
}
