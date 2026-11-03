const std = @import("std");
const grpc = @import("../../mod.zig");
const bootstrap = @import("../bootstrap.zig");
const control = @import("../control_plane.zig");
const lrs = @import("../lrs.zig");
const codec = lrs.codec;
const allocator = std.testing.allocator;

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
}

const Collector = struct {
    request: ?codec.OwnedRequest = null,
    fn consume(self: *Collector, message: grpc.StreamingMessage) !void {
        if (self.request != null) return error.UnexpectedRequest;
        self.request = try codec.decodeRequest(allocator, message.payload, .{});
    }
};

fn request(stream: anytype) !codec.OwnedRequest {
    var collector: Collector = .{};
    errdefer if (collector.request) |*value| value.deinit();
    while (collector.request == null) {
        var event = try stream.readRequestEventWithTimeout(.fromSeconds(3), &collector, Collector.consume);
        defer event.deinit();
        if (event == .finished or event == .reset) return error.EndedEarly;
    }
    return collector.request.?;
}

fn send(stream: anytype, response: codec.Response) !void {
    const encoded = try codec.encodeResponse(allocator, response, .{});
    defer allocator.free(encoded);
    try std.testing.expectEqual(grpc.DuplexWriteResult.complete, try stream.writeMessage(encoded));
}

const Peer = struct {
    fn run(listener: *grpc.runtime.Server, terminal: grpc.Status) !void {
        var connection = try listener.acceptWithTimeout(.fromSeconds(3));
        defer connection.deinit();
        var duplex = try connection.acceptDuplexWithTimeout(.fromSeconds(3));
        defer duplex.deinit();
        try std.testing.expectEqualStrings(lrs.path, duplex.transport.path);
        var initial = try request(&duplex);
        defer initial.deinit();
        try std.testing.expect(initial.value.node != null);
        try std.testing.expectEqual(@as(usize, 0), initial.value.clusters.len);
        try duplex.startResponse(.{});
        try send(&duplex, .{ .clusters = &.{"a"}, .interval_ns = 50 * std.time.ns_per_ms });
        if (terminal == .ok) try duplex.finishOk() else try duplex.finishWithOptions(.{ .status = terminal, .status_message = "restart" });
    }
};

test "gRPC LRS client follows ControlPlane failover" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var first = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer first.deinit();
    var second = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer second.deinit();
    const json = try std.fmt.allocPrint(allocator, "{{\"xds_servers\":[{{\"server_uri\":\"http://127.0.0.1:{d}\",\"channel_creds\":[{{\"type\":\"insecure\"}}]}},{{\"server_uri\":\"http://127.0.0.1:{d}\",\"channel_creds\":[{{\"type\":\"insecure\"}}]}}],\"node\":{{\"id\":\"node-1\"}}}}", .{ first.address().getPort(), second.address().getPort() });
    defer allocator.free(json);
    const configuration = try bootstrap.parse(allocator, json, .{});
    defer configuration.deinit();
    const plane = try control.ControlPlane.init(allocator, io, configuration, .{});
    defer plane.deinit();
    var first_task = io.async(Peer.run, .{ &first, grpc.Status.unavailable });
    defer _ = first_task.cancel(io) catch {};
    var second_task = io.async(Peer.run, .{ &second, grpc.Status.ok });
    defer _ = second_task.cancel(io) catch {};
    var sender = plane.sender();
    defer sender.deinit();
    var client = try lrs.Client.init(allocator, sender, .{ .node = .{ .id = "node-1" } });
    defer client.deinit();
    try client.connectWithDeadline(deadline(io));
    var response = try client.nextWithDeadline(deadline(io));
    defer response.deinit();
    try std.testing.expect(response == .response);
    var terminal = try client.nextWithDeadline(deadline(io));
    defer terminal.deinit();
    try std.testing.expectEqual(grpc.Status.unavailable, terminal.terminal.status);

    try plane.moveToNextServer(deadline(io));
    try std.testing.expectEqual(second.address().getPort(), plane.server().target.port);
    try plane.rebindLrs(&client, .{ .path = lrs.path });
    try client.connectWithDeadline(deadline(io));
    var replay = try client.nextWithDeadline(deadline(io));
    defer replay.deinit();
    try std.testing.expect(replay == .response);
    try std.testing.expectEqual(@as(usize, 1), replay.response.value.clusters.len);
    var ended = try client.nextWithDeadline(deadline(io));
    defer ended.deinit();
    try std.testing.expectEqual(grpc.Status.ok, ended.terminal.status);
    try first_task.await(io);
    try second_task.await(io);
}
