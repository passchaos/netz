const std = @import("std");
const grpc = @import("../mod.zig");
const allocator = std.testing.allocator;
const reply = "scheduled:" ++ "r" ** 128;

fn before(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .raw = .fromSeconds(3), .clock = .awake });
}

test "gRPC duplex event pump progresses business RPC while Health Watch is silent" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var release_health: std.Io.Event = .unset;
    const Peer = struct {
        fn healthRequest(_: void, message: grpc.StreamingMessage) !void {
            try std.testing.expectEqualStrings("demo.Echo", (try grpc.health.decodeRequest(message.payload)).service);
        }
        fn rpcRequest(_: void, message: grpc.StreamingMessage) !void {
            try std.testing.expectEqualStrings("request", message.payload);
        }
        fn run(server_ptr: *grpc.runtime.Server, released: *std.Io.Event) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var health = try connection.readStreamingWithTimeout(.fromSeconds(3), {}, healthRequest);
            defer health.deinit();
            var rpc = try connection.readStreamingWithTimeout(.fromSeconds(3), {}, rpcRequest);
            defer rpc.deinit();
            var health_writer = try connection.startStreamingResponse(health.transport.stream_id, .{ .compression = .gzip, .accepted_encodings = .supported });
            defer health_writer.deinit();
            var rpc_writer = try connection.startStreamingResponse(rpc.transport.stream_id, .{ .compression = .deflate, .accepted_encodings = .supported });
            defer rpc_writer.deinit();
            try rpc_writer.writeMessage(reply);
            try rpc_writer.finishOk();
            // No health message is sent until the client has completed the
            // sibling RPC. A stream-specific blocking Watch read deadlocks.
            try released.waitTimeout(connection.connection.io, .{ .deadline = before(connection.connection.io) });
            const serving = try grpc.health.encodeResponseAlloc(allocator, .{ .status = .serving });
            defer allocator.free(serving);
            try health_writer.writeMessage(serving);
            var reset = try connection.connection.readResetStreamWithTimeout(.fromSeconds(3));
            defer reset.deinit(allocator);
            try std.testing.expectEqual(health.transport.stream_id, reset.reset.stream_id);
            health_writer.transport.finished = true;
        }
    };
    var peer = io.async(Peer.run, .{ &server, &release_health });
    defer _ = peer.cancel(io) catch {};
    var client = try grpc.runtime.Client.connect(allocator, io, server.address(), .{});
    defer client.deinit();
    var watch = try client.startHealthWatchWithTimeout(.{ .service = "demo.Echo" }, .fromSeconds(3));
    defer watch.deinit();
    var rpc = try client.startDuplex(.{ .path = "/demo.Echo/Duplex" });
    defer rpc.deinit();
    try std.testing.expectEqual(grpc.DuplexWriteResult.complete, try rpc.writeFinalMessage("request"));
    const Collector = struct {
        count: usize = 0,
        fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
            try std.testing.expectEqualStrings(reply, message.payload);
            self.count += 1;
        }
    };
    var collector: Collector = .{};
    var finished = false;
    const rpc_before = before(io);
    while (!finished) {
        try std.testing.expect((try watch.pollNextWithDeadline(rpc_before)) == null);
        while (try rpc.pollResponseEventWithDeadline(rpc_before, &collector, Collector.consume)) |ready| {
            var event = ready;
            defer event.deinit(allocator);
            if (event == .terminal) {
                try std.testing.expectEqual(grpc.Status.ok, event.terminal.status);
                finished = true;
                break;
            }
        }
        if (!finished) _ = try client.connection.pumpClientDuplexWithDeadline(rpc_before);
    }
    try std.testing.expectEqual(@as(usize, 1), collector.count);
    try std.testing.expectEqual(@as(usize, 1), client.connection.activeClientDuplexCount());
    release_health.set(io);
    const health_before = before(io);
    while (true) {
        if (try watch.pollNextWithDeadline(health_before)) |ready| {
            var event = ready;
            defer event.deinit();
            try std.testing.expectEqual(grpc.health.ServingStatus.serving, event.status.status);
            break;
        }
        _ = try client.connection.pumpClientDuplexWithDeadline(health_before);
    }
    try watch.cancel();
    try peer.await(io);
}

test "gRPC duplex event poll enforces RPC deadline without socket input" {
    const Fixture = @import("../../http2/runtime/duplex/testing.zig").Fixture;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io());
    defer fixture.deinit();
    var stream = try grpc.startDuplex(&fixture.connection, allocator, .{ .path = "/demo.Echo/Duplex", .authority = "localhost" });
    defer stream.deinit();
    const Sink = struct {
        fn consume(_: void, _: grpc.StreamingMessage) !void {
            return error.UnexpectedMessage;
        }
    };
    stream.deadline = .fromNow(fixture.io, .{ .raw = .zero, .clock = .awake });
    try std.testing.expectError(error.Timeout, stream.pollResponseEvent({}, Sink.consume));
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.activeClientDuplexCount());
    try std.testing.expectError(error.ConnectionClosed, stream.pollResponseEvent({}, Sink.consume));
}
