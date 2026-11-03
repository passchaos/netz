const std = @import("std");
const grpc = @import("../../mod.zig");
const bootstrap = @import("../bootstrap.zig");
const control_plane = @import("../control_plane.zig");
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

fn runScheduler(scheduler: *lrs.Scheduler, until: std.Io.Clock.Timestamp) !void {
    return scheduler.run(until);
}

fn runSchedulerWithControlPlane(scheduler: *lrs.Scheduler, plane: *control_plane.ControlPlane, until: std.Io.Clock.Timestamp) !void {
    return scheduler.runWithControlPlane(plane, until);
}

const ReportingPeer = struct {
    fn run(io: std.Io, listener: *grpc.runtime.Server, terminal: grpc.Status, reported: ?*std.Io.Event, hold: ?*std.Io.Event) !void {
        var connection = try listener.acceptWithTimeout(.fromSeconds(3));
        defer connection.deinit();
        var duplex = try connection.acceptDuplexWithTimeout(.fromSeconds(3));
        defer duplex.deinit();
        var initial = try request(&duplex);
        defer initial.deinit();
        try std.testing.expect(initial.value.node != null);
        try duplex.startResponse(.{});
        try send(&duplex, .{ .clusters = &.{"a"}, .interval_ns = 20 * std.time.ns_per_ms });
        var report = try request(&duplex);
        defer report.deinit();
        try std.testing.expectEqual(@as(usize, 1), report.value.clusters.len);
        try std.testing.expectEqualStrings("a", report.value.clusters[0].name);
        try std.testing.expectEqual(@as(u64, 1), report.value.clusters[0].localities[0].successful);
        try std.testing.expectEqual(@as(u64, 1), report.value.clusters[0].localities[0].issued);
        if (reported) |event| event.set(io);
        if (hold) |event| try event.wait(io);
        if (terminal == .ok) try duplex.finishOk() else try duplex.finishWithOptions(.{ .status = terminal, .status_message = "restart" });
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

test "gRPC LRS scheduler emits interval reports and surfaces terminal" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var control = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer control.deinit();
    var destination = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer destination.deinit();
    var lrs_task = io.async(ReportingPeer.run, .{ io, &control, grpc.Status.ok, null, null });
    defer _ = lrs_task.cancel(io) catch {};
    var destination_task = io.async(UnaryPeer.run, .{&destination});
    defer _ = destination_task.cancel(io) catch {};
    const path = [_][]const u8{"cluster:a"};
    const endpoint: @import("../../channel.zig").Endpoint = .{ .cleartext_ip = .{ .address = destination.address(), .hierarchical_path = &path } };
    var source = try grpc.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &.{endpoint} } }, .{ .enable_lrs_stats = true });
    defer source.deinit();
    var source_sender = source.sender();
    defer source_sender.deinit();
    var call = try source_sender.unary(.{ .path = "/demo.Lrs/Call", .message = "ok", .wait_for_ready = true });
    defer call.deinit();
    try std.testing.expectEqual(grpc.Status.ok, call.status);

    var control_channel = try grpc.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = control.address() } }, .{});
    defer control_channel.deinit();
    var control_sender = control_channel.sender();
    defer control_sender.deinit();
    var client = try lrs.Client.init(allocator, control_sender, .{ .node = .{ .id = "node-1" } });
    defer client.deinit();
    try client.connectWithDeadline(deadline(io));
    var scheduler = lrs.Scheduler.init(allocator, &client, source, .{ .interval_ns = std.time.ns_per_s });
    defer scheduler.deinit();
    var scheduler_task = try io.concurrent(runScheduler, .{ &scheduler, deadline(io) });
    defer _ = scheduler_task.cancel(io) catch {};
    try std.testing.expectError(error.LrsTerminal, scheduler_task.await(io));
    try lrs_task.await(io);
    try destination_task.await(io);
}

test "gRPC LRS scheduler fails over after a terminal stream" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var first = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer first.deinit();
    var second = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer second.deinit();
    var destination = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer destination.deinit();
    const json = try std.fmt.allocPrint(allocator, "{{\"xds_servers\":[{{\"server_uri\":\"http://127.0.0.1:{d}\",\"channel_creds\":[{{\"type\":\"insecure\"}}]}},{{\"server_uri\":\"http://127.0.0.1:{d}\",\"channel_creds\":[{{\"type\":\"insecure\"}}]}}],\"node\":{{\"id\":\"node-1\"}}}}", .{ first.address().getPort(), second.address().getPort() });
    defer allocator.free(json);
    const configuration = try bootstrap.parse(allocator, json, .{});
    defer configuration.deinit();
    const plane = try control_plane.ControlPlane.init(allocator, io, configuration, .{});
    defer plane.deinit();
    var reported: std.Io.Event = .unset;
    var hold: std.Io.Event = .unset;
    var first_task = io.async(ReportingPeer.run, .{ io, &first, grpc.Status.unavailable, null, null });
    defer _ = first_task.cancel(io) catch {};
    var second_task = io.async(ReportingPeer.run, .{ io, &second, grpc.Status.ok, &reported, &hold });
    defer _ = second_task.cancel(io) catch {};
    var destination_task = io.async(UnaryPeer.run, .{&destination});
    defer _ = destination_task.cancel(io) catch {};
    const path = [_][]const u8{"cluster:a"};
    const endpoint: @import("../../channel.zig").Endpoint = .{ .cleartext_ip = .{ .address = destination.address(), .hierarchical_path = &path } };
    var source = try grpc.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &.{endpoint} } }, .{ .enable_lrs_stats = true });
    defer source.deinit();
    var source_sender = source.sender();
    defer source_sender.deinit();
    var call = try source_sender.unary(.{ .path = "/demo.Lrs/Call", .message = "ok", .wait_for_ready = true });
    defer call.deinit();
    try std.testing.expectEqual(grpc.Status.ok, call.status);

    var plane_sender = plane.sender();
    defer plane_sender.deinit();
    var client = try lrs.Client.init(allocator, plane_sender, .{ .node = .{ .id = "node-1" } });
    defer client.deinit();
    const until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(10) });
    try client.connectWithDeadline(until);
    var scheduler = lrs.Scheduler.init(allocator, &client, source, .{ .interval_ns = std.time.ns_per_s });
    defer scheduler.deinit();
    var scheduler_task = try io.concurrent(runSchedulerWithControlPlane, .{ &scheduler, plane, until });
    defer _ = scheduler_task.cancel(io) catch {};
    while (!reported.isSet()) {
        if (until.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
        try std.Io.sleep(io, .fromMilliseconds(5), .awake);
    }
    try std.testing.expectEqual(second.address().getPort(), plane.server().target.port);
    _ = scheduler_task.cancel(io) catch {};
    hold.set(io);
    try first_task.await(io);
    try second_task.await(io);
    try destination_task.await(io);
}
