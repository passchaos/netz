const std = @import("std");
const grpc = @import("../../mod.zig");
const bootstrap = @import("../bootstrap.zig");
const control_plane = @import("../control_plane.zig");
const lrs = @import("../lrs.zig");
const codec = lrs.codec;
const allocator = std.testing.allocator;

const Collector = struct {
    request: ?codec.OwnedRequest = null,
    fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
        if (self.request != null) return error.UnexpectedRequest;
        self.request = try codec.decodeRequest(allocator, message.payload, .{});
    }
};

fn nextRequest(stream: anytype) !codec.OwnedRequest {
    var collector: Collector = .{};
    errdefer if (collector.request) |*value| value.deinit();
    while (collector.request == null) {
        var event = try stream.readRequestEventWithTimeout(
            .fromSeconds(3),
            &collector,
            Collector.consume,
        );
        defer event.deinit();
        if (event == .finished or event == .reset) return error.EndedEarly;
    }
    return collector.request.?;
}

fn send(stream: anytype, response: codec.Response) !void {
    const encoded = try codec.encodeResponse(allocator, response, .{});
    defer allocator.free(encoded);
    try std.testing.expectEqual(
        grpc.DuplexWriteResult.complete,
        try stream.writeMessage(encoded),
    );
}

const Peer = struct {
    fn run(
        io: std.Io,
        listener: *grpc.runtime.Server,
        reported: *std.Io.Event,
        hold: *std.Io.Event,
    ) !void {
        var connection = try listener.acceptWithTimeout(.fromSeconds(5));
        defer connection.deinit();
        var duplex = try connection.acceptDuplexWithTimeout(.fromSeconds(5));
        defer duplex.deinit();
        var initial = try nextRequest(&duplex);
        defer initial.deinit();
        try duplex.startResponse(.{});
        try send(&duplex, .{
            .clusters = &.{"a"},
            .interval_ns = 20 * std.time.ns_per_ms,
        });
        var report = try nextRequest(&duplex);
        defer report.deinit();
        try std.testing.expectEqual(@as(usize, 1), report.value.clusters.len);
        try std.testing.expectEqualStrings("a", report.value.clusters[0].name);
        reported.set(io);
        try hold.wait(io);
        try duplex.finishOk();
    }
};

const UnaryPeer = struct {
    fn run(listener: *grpc.runtime.Server) !void {
        var connection = try listener.acceptWithTimeout(.fromSeconds(3));
        defer connection.deinit();
        var unary = try connection.readUnaryWithTimeout(.fromSeconds(3));
        defer unary.deinit();
        try connection.writeUnary(unary.transport.stream_id, .{ .message = "ok" });
    }
};

test "gRPC LRS runner owns a background report loop" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var control = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer control.deinit();
    var destination = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer destination.deinit();
    var reported: std.Io.Event = .unset;
    var hold: std.Io.Event = .unset;
    var peer_task = io.async(Peer.run, .{ io, &control, &reported, &hold });
    defer _ = peer_task.cancel(io) catch {};
    var destination_task = io.async(UnaryPeer.run, .{&destination});
    defer _ = destination_task.cancel(io) catch {};
    const path = [_][]const u8{"cluster:a"};
    const endpoint: @import("../../channel.zig").Endpoint = .{ .cleartext_ip = .{
        .address = destination.address(),
        .hierarchical_path = &path,
    } };
    var source = try grpc.SharedChannel.init(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &.{endpoint} } },
        .{ .enable_lrs_stats = true },
    );
    defer source.deinit();
    var source_sender = source.sender();
    defer source_sender.deinit();
    var call = try source_sender.unary(.{
        .path = "/demo.Lrs/Call",
        .message = "ok",
        .wait_for_ready = true,
    });
    defer call.deinit();
    try std.testing.expectEqual(grpc.Status.ok, call.status);

    const json = try std.fmt.allocPrint(
        allocator,
        "{{\"xds_servers\":[{{\"server_uri\":\"http://127.0.0.1:{d}\",\"channel_creds\":[{{\"type\":\"insecure\"}}]}}],\"node\":{{\"id\":\"node-1\"}}}}",
        .{control.address().getPort()},
    );
    defer allocator.free(json);
    const configuration = try bootstrap.parse(allocator, json, .{});
    defer configuration.deinit();
    var plane = try control_plane.ControlPlane.init(
        allocator,
        io,
        configuration,
        .{},
    );
    defer plane.deinit();
    var plane_sender = plane.sender();
    defer plane_sender.deinit();
    var runner = try lrs.Runner.create(
        allocator,
        io,
        plane_sender,
        plane,
        source,
        .{
            .client = .{ .node = .{ .id = "node-1" } },
            .reporter = .{ .interval_ns = std.time.ns_per_s },
        },
    );
    defer runner.deinit();
    try runner.start();
    try reported.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(5),
        .clock = .awake,
    } });
    try std.testing.expect(runner.failureReason() == null);
    runner.stop();
    hold.set(io);
    try peer_task.await(io);
    try destination_task.await(io);
}
