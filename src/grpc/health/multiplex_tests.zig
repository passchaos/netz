const std = @import("std");
const grpc = @import("../mod.zig");
const allocator = std.testing.allocator;
const reply = "reply:" ++ "r" ** 128;

test "gRPC multiplexed Health Watch shares one channel with a duplex RPC" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    const Peer = struct {
        fn healthMessage(_: void, message: grpc.StreamingMessage) !void {
            try std.testing.expectEqualStrings("demo.Echo", (try grpc.health.decodeRequest(message.payload)).service);
        }
        fn rpcMessage(_: void, message: grpc.StreamingMessage) !void {
            try std.testing.expectEqualStrings("request", message.payload);
        }
        fn run(server_ptr: *grpc.runtime.Server) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var health_request = try connection.readStreamingWithTimeout(.fromSeconds(3), {}, healthMessage);
            defer health_request.deinit();
            try std.testing.expectEqualStrings(grpc.health.watch_path, health_request.path);
            var rpc_request = try connection.readStreamingWithTimeout(.fromSeconds(3), {}, rpcMessage);
            defer rpc_request.deinit();
            try std.testing.expectEqualStrings("/demo.Echo/Duplex", rpc_request.path);
            var health_writer = try connection.startStreamingResponse(health_request.transport.stream_id, .{
                .compression = .gzip,
                .accepted_encodings = .supported,
            });
            defer health_writer.deinit();
            var rpc_writer = try connection.startStreamingResponse(rpc_request.transport.stream_id, .{
                .compression = .deflate,
                .accepted_encodings = .supported,
            });
            defer rpc_writer.deinit();
            try rpc_writer.writeMessage(reply);
            const serving = try grpc.health.encodeResponseAlloc(allocator, .{ .status = .serving });
            defer allocator.free(serving);
            try health_writer.writeMessage(serving);
            const unhealthy = try grpc.health.encodeResponseAlloc(allocator, .{ .status = .not_serving });
            defer allocator.free(unhealthy);
            try health_writer.writeMessage(unhealthy);
            try rpc_writer.finishOk();
            var reset = try connection.connection.readResetStreamWithTimeout(.fromSeconds(3));
            defer reset.deinit(allocator);
            try std.testing.expectEqual(health_request.transport.stream_id, reset.reset.stream_id);
            try std.testing.expectEqual(@import("../../http2/mod.zig").ErrorCode.cancel, reset.reset.error_code);
            health_writer.transport.finished = true;
        }
    };
    var peer = io.async(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};
    var client = try grpc.runtime.Client.connect(allocator, io, server.address(), .{});
    defer client.deinit();
    var watch = try client.startHealthWatchWithTimeout(.{ .service = "demo.Echo" }, .fromSeconds(3));
    defer watch.deinit();
    var rpc = try client.startDuplex(.{ .path = "/demo.Echo/Duplex" });
    defer rpc.deinit();
    try std.testing.expectEqual(grpc.DuplexWriteResult.complete, try rpc.writeFinalMessage("request"));
    try std.testing.expectEqual(@as(usize, 2), client.connection.activeClientDuplexCount());
    var serving = try watch.nextWithTimeout(.fromSeconds(3));
    defer serving.deinit();
    try std.testing.expectEqual(grpc.health.ServingStatus.serving, serving.status.status);

    const Collector = struct {
        messages: usize = 0,
        fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
            try std.testing.expectEqualStrings(reply, message.payload);
            self.messages += 1;
        }
    };
    var collector: Collector = .{};
    var terminal_seen = false;
    while (!terminal_seen) {
        var event = try rpc.readResponseEventWithTimeout(.fromSeconds(3), &collector, Collector.consume);
        defer event.deinit(allocator);
        if (event == .terminal) {
            try std.testing.expectEqual(grpc.Status.ok, event.terminal.status);
            terminal_seen = true;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), collector.messages);
    try std.testing.expectEqual(@as(usize, 1), client.connection.activeClientDuplexCount());
    try std.testing.expect(client.connection.duplex_reader_active);
    var unhealthy = try watch.nextWithTimeout(.fromSeconds(3));
    defer unhealthy.deinit();
    try std.testing.expectEqual(grpc.health.ServingStatus.not_serving, unhealthy.status.status);
    try watch.cancel();
    try peer.await(io);
}
