//! Real generated routing must supply the accepted EDS identity to LRS capture.
const std = @import("std");
const grpc = @import("../../../mod.zig");
const control_plane = @import("../../control_plane.zig");
const cds = @import("../../cds.zig");
const eds = @import("../../eds.zig");
const orca = @import("../../../orca.zig");
const fixture = @import("../../cds/testing.zig");
const support = @import("testing.zig");
const gpa = std.testing.allocator;

const Backend = struct {
    fn run(listener: *grpc.runtime.Server, admitted: *std.Io.Event, finish: *std.Io.Event, io: std.Io) !void {
        var connection = try listener.acceptWithTimeout(.fromSeconds(5));
        defer connection.deinit();
        const report = try orca.encodeAlloc(gpa, .{ .cpu_utilization = 0.5, .named_metrics = &.{.{ .name = "load", .value = 2.0 }} });
        defer gpa.free(report);
        const metadata = [_]grpc.BinaryMetadata{.{ .name = orca.name, .value = report }};
        var first = try connection.readUnaryWithTimeout(.fromSeconds(5));
        defer first.deinit();
        try std.testing.expectEqualStrings("first", first.request.message.payload);
        try connection.writeUnary(first.transport.stream_id, .{ .message = "ok", .trailing_binary_metadata = &metadata });
        var held = try connection.readUnaryWithTimeout(.fromSeconds(5));
        defer held.deinit();
        try std.testing.expectEqualStrings("held", held.request.message.payload);
        admitted.set(io);
        var cached = try connection.readUnaryWithTimeout(.fromSeconds(5));
        defer cached.deinit();
        try std.testing.expectEqualStrings("cached", cached.request.message.payload);
        try connection.writeUnary(cached.transport.stream_id, .{ .message = "ok", .trailing_binary_metadata = &metadata });
        try finish.wait(io);
        try connection.writeUnary(held.transport.stream_id, .{ .message = "ok", .trailing_binary_metadata = &metadata });
        var stream = try connection.acceptDuplexWithTimeout(.fromSeconds(5));
        defer stream.deinit();
        try stream.startResponse(.{});
        try stream.finishWithOptions(.{ .status = .ok, .trailing_binary_metadata = &metadata });
    }
};

fn unary(sender: grpc.SharedChannelSender, payload: []const u8) !grpc.UnaryResponse {
    return sender.unary(.{ .path = "/demo.Routed/Unary", .authority = "backend.test", .message = payload, .wait_for_ready = true, .timeout = .{ .value = 5, .unit = .second } });
}

fn runRouting(comptime mode: support.Mode) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var control = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer control.deinit();
    var backend = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer backend.deinit();
    const configuration = try support.configuration(&control);
    defer configuration.deinit();
    const plane = try control_plane.ControlPlane.init(gpa, io, configuration, .{});
    defer plane.deinit();
    var observed: support.Observed = .{ .io = io, .category = "routing", .endpoint_port = backend.address().getPort(), .scenario = "generated-route", .mode = @tagName(mode) };
    var peer = try io.concurrent(support.Peer.run, .{ &control, &observed });
    defer _ = peer.cancel(io) catch {};
    var admitted: std.Io.Event = .unset;
    var release: std.Io.Event = .unset;
    var backend_task = try io.concurrent(Backend.run, .{ &backend, &admitted, &release, io });
    defer _ = backend_task.cancel(io) catch {};
    var h = try support.Harness(mode).init(io, plane, gpa, false, false);
    var live = true;
    defer if (live) h.deinit();
    try h.discover();
    var extra: fixture.Builder = .{ .allocator = gpa };
    defer extra.deinit();
    try extra.data.appendSlice(gpa, support.self_lrs);
    try extra.bytes(57, "cpu_utilization");
    try extra.bytes(57, "named_metrics.load");
    const cluster = try fixture.cluster(gpa, "a", "eds-a", extra.data.items);
    defer gpa.free(cluster);
    try h.accept(cds.type_url, "a", "self", cluster);
    const assignment = try fixture.assignment(gpa, "eds-a", "127.0.0.1", backend.address().getPort());
    defer gpa.free(assignment);
    try h.accept(eds.type_url, "eds-a", "endpoints", assignment);
    var sender = h.channel.sender();
    defer sender.deinit();
    var first = try unary(sender, "first");
    defer first.deinit();
    try std.testing.expectEqual(grpc.Status.ok, first.status);
    var held = try io.concurrent(unary, .{ sender, "held" });
    var held_live = true;
    defer if (held_live) if (held.cancel(io)) |value| {
        var response = value;
        response.deinit();
    } else |_| {};
    try support.wait(io, &admitted);
    var cached = try unary(sender, "cached");
    defer cached.deinit();
    try std.testing.expectEqual(grpc.Status.ok, cached.status);
    {
        var snapshot = try h.channel.lrsStatsSnapshot(gpa);
        defer snapshot.deinit();
        try std.testing.expectEqual(@as(usize, 1), snapshot.entries.len);
        const entry = snapshot.entries[0];
        try std.testing.expectEqualStrings("a", entry.cluster);
        try std.testing.expectEqualStrings("eds-a", entry.service_name);
        try std.testing.expectEqualSlices(u8, h.client.source.?.key, entry.source_key);
        try std.testing.expectEqual(@as(u64, 3), entry.issued);
        try std.testing.expectEqual(@as(u64, 2), entry.successful);
        try std.testing.expectEqual(@as(u64, 1), entry.in_progress);
        try std.testing.expectEqual(@as(u64, 2), entry.cpu_utilization.count);
        try std.testing.expectEqual(@as(f64, 1.0), entry.cpu_utilization.sum);
        try std.testing.expectEqual(@as(usize, 1), entry.load_metrics.len);
        try std.testing.expectEqualStrings("named_metrics.load", entry.load_metrics[0].name);
        try std.testing.expectEqual(@as(u64, 2), entry.load_metrics[0].count);
    }
    _ = try observed.awaitCounts(2, 0); // Actual encoded reports reached the peer.
    const reported = try observed.metricSnapshot();
    try std.testing.expectEqual(@as(u64, 1), reported.in_progress);
    try std.testing.expectEqual(@as(u64, 2), reported.cpu_count);
    try std.testing.expectEqual(@as(f64, 1.0), reported.cpu_sum);
    release.set(io);
    var completed = try held.await(io);
    held_live = false;
    defer completed.deinit();
    try std.testing.expectEqual(grpc.Status.ok, completed.status);
    var stream = try sender.startDuplex(.{ .path = "/demo.Routed/Stream", .authority = "backend.test", .wait_for_ready = true, .timeout = .{ .value = 5, .unit = .second } });
    defer stream.deinit();
    var reader = stream.reader();
    defer reader.deinit();
    while (true) {
        var event = try reader.nextWithTimeout(.fromSeconds(5));
        defer event.deinit(gpa);
        if (event == .terminal) {
            try std.testing.expectEqual(grpc.Status.ok, event.terminal.status);
            break;
        }
    }
    try std.testing.expectEqual(support.Counts{ .issued = 4, .successful = 4 }, try observed.awaitCounts(4, 0));
    try backend_task.await(io);
    try observed.expectClose(.{ .issued = 4, .successful = 4 });
    h.deinit();
    live = false;
    try observed.awaitPeer(&peer);
}

test "gRPC automatic LRS captures real generated unary and streaming route service identities" {
    try runRouting(.sotw);
    try runRouting(.delta);
}
