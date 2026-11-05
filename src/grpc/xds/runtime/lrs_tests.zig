//! The controller owns the LRS runner lifetime alongside discovery.
const std = @import("std");
const grpc = @import("../../mod.zig");
const runtime = @import("../runtime.zig");
const ads = @import("../ads.zig");
const delta = @import("../ads/delta.zig");
const bootstrap = @import("../bootstrap.zig");
const control_plane = @import("../control_plane.zig");
const lrs = @import("../lrs.zig");
const allocator = std.testing.allocator;

const Collector = struct {
    request: ?lrs.codec.OwnedRequest = null,
    fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
        if (self.request != null) return error.UnexpectedRequest;
        self.request = try lrs.codec.decodeRequest(allocator, message.payload, .{});
    }
};

fn nextRequest(stream: anytype) !lrs.codec.OwnedRequest {
    var collector: Collector = .{};
    errdefer if (collector.request) |*value| value.deinit();
    while (collector.request == null) {
        var event = try stream.readRequestEventWithTimeout(
            .fromSeconds(5),
            &collector,
            Collector.consume,
        );
        defer event.deinit();
        if (event == .finished or event == .reset) return error.EndedEarly;
    }
    return collector.request.?;
}

const Peer = struct {
    fn run(
        io: std.Io,
        listener: *grpc.runtime.Server,
        connected: *std.Io.Event,
        hold: *std.Io.Event,
    ) !void {
        var connection = try listener.acceptWithTimeout(.fromSeconds(5));
        defer connection.deinit();
        var duplex = try connection.acceptDuplexWithTimeout(.fromSeconds(5));
        defer duplex.deinit();
        var initial = try nextRequest(&duplex);
        defer initial.deinit();
        try std.testing.expect(initial.value.node != null);
        try std.testing.expectEqual(@as(usize, 0), initial.value.clusters.len);
        try duplex.startResponse(.{});
        const encoded = try lrs.codec.encodeResponse(allocator, .{
            .clusters = &.{"a"},
            .interval_ns = 20 * std.time.ns_per_ms,
        }, .{});
        defer allocator.free(encoded);
        try std.testing.expectEqual(
            grpc.DuplexWriteResult.complete,
            try duplex.writeMessage(encoded),
        );
        connected.set(io);
        try hold.wait(io);
        duplex.finishOk() catch {};
    }
};

const Mode = enum { sotw, delta };

fn runOwned(comptime mode: Mode) !void {
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
    var connected: std.Io.Event = .unset;
    var hold: std.Io.Event = .unset;
    var peer_task = io.async(Peer.run, .{ io, &control, &connected, &hold });
    defer _ = peer_task.cancel(io) catch {};

    const json = try std.fmt.allocPrint(
        allocator,
        "{{\"xds_servers\":[{{\"server_uri\":\"http://127.0.0.1:{d}\",\"channel_creds\":[{{\"type\":\"insecure\"}}]}}],\"node\":{{\"id\":\"node-1\"}}}}",
        .{control.address().getPort()},
    );
    defer allocator.free(json);
    const configuration = try bootstrap.parse(allocator, json, .{});
    defer configuration.deinit();
    var plane = try control_plane.ControlPlane.init(allocator, io, configuration, .{});
    defer plane.deinit();
    var plane_sender = plane.sender();
    defer plane_sender.deinit();

    var destination = try grpc.SharedChannel.init(
        allocator,
        io,
        .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } },
        .{ .enable_lrs_stats = true },
    );
    defer destination.deinit();
    var sender = destination.sender();
    defer sender.deinit();

    const controller = try runtime.Controller.create(allocator, .{
        .listener_name = "frontend",
        .target = .{ .authority = "backend.test" },
        .lrs = .{
            .sender = plane_sender,
            .control_plane = plane,
            .client = .{ .node = .{ .id = "node-1" } },
            .reporter = .{ .interval_ns = 20 * std.time.ns_per_ms },
            .poll_interval = .fromMilliseconds(50),
        },
    });
    var live = true;
    defer if (live) controller.deinit();

    switch (mode) {
        .sotw => {
            var client = try ads.Client.init(allocator, sender, .{ .node = .{ .id = "node-1" } });
            defer client.deinit();
            _ = try controller.startWithDeadline(
                &client,
                destination,
                .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) }),
            );
        },
        .delta => {
            var client = try delta.Client.init(allocator, sender, .{ .node = .{ .id = "node-1" } });
            defer client.deinit();
            _ = try controller.startDeltaWithDeadline(
                &client,
                destination,
                .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) }),
            );
        },
    }

    try connected.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(5),
        .clock = .awake,
    } });
    try std.testing.expect(controller.lrs_runner != null);
    try std.testing.expect(controller.lrs_runner.?.failureReason() == null);

    controller.deinit();
    live = false;
    hold.set(io);
    try peer_task.await(io);
}

test "gRPC xDS runtime controller owns the SotW LRS runner" {
    try runOwned(.sotw);
}

test "gRPC xDS runtime controller owns the delta LRS runner" {
    try runOwned(.delta);
}
