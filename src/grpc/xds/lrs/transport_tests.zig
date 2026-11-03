const std = @import("std");
const grpc = @import("../../mod.zig");
const lrs = @import("../lrs.zig");
const allocator = std.testing.allocator;
const codec = lrs.codec;

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

test "gRPC LRS real duplex reports stats and replays the node on reconnect" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    const Peer = struct {
        fn run(listener: *grpc.runtime.Server) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var first = try connection.acceptDuplexWithTimeout(.fromSeconds(3));
            defer first.deinit();
            try std.testing.expectEqualStrings(lrs.path, first.transport.path);
            var initial = try request(&first);
            defer initial.deinit();
            try std.testing.expect(initial.value.node != null);
            try std.testing.expect(std.mem.indexOf(u8, initial.value.node.?, "envoy.lrs.supports_send_all_clusters") != null);
            try std.testing.expectEqual(@as(usize, 0), initial.value.clusters.len);
            try first.startResponse(.{});
            try send(&first, .{ .clusters = &.{ "a", "b" }, .interval_ns = 100 * std.time.ns_per_ms, .report_endpoint_granularity = true });

            var report = try request(&first);
            defer report.deinit();
            try std.testing.expect(report.value.node == null);
            try std.testing.expectEqual(@as(usize, 1), report.value.clusters.len);
            const cluster = report.value.clusters[0];
            try std.testing.expectEqualStrings("a", cluster.name);
            try std.testing.expectEqual(@as(u64, 1), cluster.total_dropped);
            try std.testing.expectEqual(@as(usize, 1), cluster.localities.len);
            try std.testing.expectEqualStrings("r", cluster.localities[0].locality.region);
            try std.testing.expectEqual(@as(u64, 1), cluster.localities[0].successful);
            try std.testing.expectEqual(@as(u64, 1), cluster.localities[0].issued);
            try std.testing.expectEqual(@as(usize, 1), cluster.dropped.len);
            try std.testing.expectEqualStrings("throttle", cluster.dropped[0].category);
            try send(&first, .{ .clusters = &.{}, .send_all_clusters = true });
            try first.finishWithOptions(.{ .status = .unavailable, .status_message = "restart" });

            var second = try connection.acceptDuplexWithTimeout(.fromSeconds(3));
            defer second.deinit();
            var replay = try request(&second);
            defer replay.deinit();
            try std.testing.expect(replay.value.node != null);
            try std.testing.expectEqual(@as(usize, 0), replay.value.clusters.len);
            try second.startResponse(.{});
            try send(&second, .{ .clusters = &.{"a"}, .interval_ns = 100 * std.time.ns_per_ms });
            try second.finishOk();
        }
    };
    var task = io.async(Peer.run, .{&server});
    defer _ = task.cancel(io) catch {};
    var channel = try grpc.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try lrs.Client.init(allocator, sender, .{ .node = .{ .id = "node-1", .client_features = &.{"envoy.lrs.supports_send_all_clusters"} } });
    defer client.deinit();
    try client.connectWithDeadline(deadline(io));
    var first = try client.nextWithDeadline(deadline(io));
    defer first.deinit();
    try std.testing.expect(first == .response);
    try std.testing.expectEqual(@as(usize, 2), first.response.value.clusters.len);
    try std.testing.expectEqual(@as(u64, 100 * std.time.ns_per_ms), first.response.value.interval_ns.?);
    try std.testing.expect(first.response.value.report_endpoint_granularity);
    try std.testing.expect(!first.response.value.send_all_clusters);

    const localities = [_]codec.LocalityStats{.{
        .locality = .{ .region = "r" },
        .successful = 1,
        .issued = 1,
    }};
    const dropped = [_]codec.Dropped{.{ .category = "throttle", .count = 1 }};
    const clusters = [_]codec.ClusterStats{.{
        .name = "a",
        .localities = &localities,
        .total_dropped = 1,
        .dropped = &dropped,
        .interval_ns = 100 * std.time.ns_per_ms,
    }};
    try client.reportWithDeadline(&clusters, deadline(io));
    var second = try client.nextWithDeadline(deadline(io));
    defer second.deinit();
    try std.testing.expect(second == .response);
    try std.testing.expect(second.response.value.send_all_clusters);

    var terminal = try client.nextWithDeadline(deadline(io));
    defer terminal.deinit();
    try std.testing.expectEqual(grpc.Status.unavailable, terminal.terminal.status);
    try client.connectWithTimeout(.fromMilliseconds(50));
    var replay = try client.nextWithDeadline(deadline(io));
    defer replay.deinit();
    try std.testing.expect(replay == .response);
    var ended = try client.nextWithDeadline(deadline(io));
    defer ended.deinit();
    try std.testing.expectEqual(grpc.Status.ok, ended.terminal.status);
    try task.await(io);
}
