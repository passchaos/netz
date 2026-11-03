const std = @import("std");
const grpc = @import("../../mod.zig");
const channel_endpoint = @import("../../channel.zig").Endpoint;
const lrs_stats = @import("lrs_stats.zig");
const allocator = std.testing.allocator;

const PeerUnary = struct {
    fn run(listener: *grpc.runtime.Server) !void {
        var connection = try listener.acceptWithTimeout(.fromSeconds(3));
        defer connection.deinit();
        var unary = try connection.readUnaryWithTimeout(.fromSeconds(3));
        defer unary.deinit();
        try connection.writeUnary(unary.transport.stream_id, .{ .message = "ok" });
    }
};

fn readTerminal(reader: anytype) !void {
    while (true) {
        var event = try reader.nextWithTimeout(.fromSeconds(3));
        defer event.deinit(allocator);
        if (event == .terminal) return;
    }
}

test "gRPC LRS counters aggregate per cluster" {
    var stats: lrs_stats.Stats = .{ .allocator = allocator };
    defer stats.deinit();
    const io = std.testing.io;
    const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(1001) };
    stats.recordStarted(io, "a", "", address);
    stats.recordCompletion(io, "a", "", address, true);
    stats.recordStarted(io, "a", "", address);
    stats.recordCompletion(io, "a", "", address, false);
    stats.recordStarted(io, "b", "", null);
    stats.recordCompletion(io, "b", "", null, true);
    stats.recordDropped(io, "a", "", "throttle");
    stats.recordDropped(io, "a", "", "throttle");
    var snapshot = try stats.snapshot(allocator, io);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(usize, 2), snapshot.entries.len);
    for (snapshot.entries) |entry| {
        if (std.mem.eql(u8, entry.cluster, "a")) {
            try std.testing.expectEqual(@as(u64, 2), entry.issued);
            try std.testing.expectEqual(@as(u64, 1), entry.successful);
            try std.testing.expectEqual(@as(u64, 1), entry.error_requests);
            try std.testing.expectEqual(@as(u64, 0), entry.in_progress);
            try std.testing.expectEqual(@as(u64, 2), entry.dropped);
            try std.testing.expectEqual(@as(usize, 1), entry.endpoints.len);
            try std.testing.expectEqualStrings("127.0.0.1", entry.endpoints[0].host);
            try std.testing.expectEqual(@as(u16, 1001), entry.endpoints[0].port);
            try std.testing.expectEqual(@as(u64, 2), entry.endpoints[0].issued);
            try std.testing.expectEqual(@as(u64, 1), entry.endpoints[0].successful);
            try std.testing.expectEqual(@as(u64, 1), entry.endpoints[0].error_requests);
            try std.testing.expectEqual(@as(u64, 0), entry.endpoints[0].in_progress);
            try std.testing.expectEqual(@as(usize, 1), entry.categories.len);
            try std.testing.expectEqualStrings("throttle", entry.categories[0].category);
            try std.testing.expectEqual(@as(u64, 2), entry.categories[0].count);
        } else {
            try std.testing.expectEqualStrings("b", entry.cluster);
            try std.testing.expectEqual(@as(u64, 1), entry.issued);
            try std.testing.expectEqual(@as(u64, 1), entry.successful);
        }
    }
}

test "gRPC LRS delta snapshots report only new counters" {
    var stats: lrs_stats.Stats = .{ .allocator = allocator };
    defer stats.deinit();
    const io = std.testing.io;
    const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(1001) };
    stats.recordStarted(io, "a", "", address);
    stats.recordCompletion(io, "a", "", address, true);
    stats.recordDropped(io, "a", "", "throttle");
    var first = try stats.snapshotDelta(allocator, io);
    defer first.deinit();
    try std.testing.expectEqual(@as(usize, 1), first.entries.len);
    try std.testing.expectEqual(@as(u64, 1), first.entries[0].issued);
    try std.testing.expectEqual(@as(u64, 1), first.entries[0].successful);
    try std.testing.expectEqual(@as(u64, 1), first.entries[0].dropped);
    try std.testing.expectEqual(@as(u64, 1), first.entries[0].categories[0].count);
    try std.testing.expectEqual(@as(u64, 1), first.entries[0].endpoints[0].issued);

    var idle = try stats.snapshotDelta(allocator, io);
    defer idle.deinit();
    try std.testing.expectEqual(@as(u64, 0), idle.entries[0].issued);
    try std.testing.expectEqual(@as(u64, 0), idle.entries[0].successful);
    try std.testing.expectEqual(@as(u64, 0), idle.entries[0].dropped);
    try std.testing.expectEqual(@as(u64, 0), idle.entries[0].categories[0].count);
    try std.testing.expectEqual(@as(u64, 0), idle.entries[0].endpoints[0].issued);

    stats.recordStarted(io, "a", "", address);
    stats.recordCompletion(io, "a", "", address, false);
    stats.recordDropped(io, "a", "", "throttle");
    var second = try stats.snapshotDelta(allocator, io);
    defer second.deinit();
    try std.testing.expectEqual(@as(u64, 1), second.entries[0].issued);
    try std.testing.expectEqual(@as(u64, 0), second.entries[0].successful);
    try std.testing.expectEqual(@as(u64, 1), second.entries[0].error_requests);
    try std.testing.expectEqual(@as(u64, 1), second.entries[0].dropped);
    try std.testing.expectEqual(@as(u64, 1), second.entries[0].categories[0].count);
    try std.testing.expectEqual(@as(u64, 1), second.entries[0].endpoints[0].issued);
    try std.testing.expectEqual(@as(u64, 1), second.entries[0].endpoints[0].error_requests);

    var cumulative = try stats.snapshot(allocator, io);
    defer cumulative.deinit();
    try std.testing.expectEqual(@as(u64, 2), cumulative.entries[0].issued);
    try std.testing.expectEqual(@as(u64, 2), cumulative.entries[0].dropped);
}

test "gRPC LRS delta snapshots report ORCA utilization deltas" {
    var stats: lrs_stats.Stats = .{ .allocator = allocator };
    defer stats.deinit();
    const io = std.testing.io;
    stats.setPropagation(io, "a", .{ .cpu_utilization = true, .memory_utilization = true, .named_metrics_all = true });
    stats.recordOrca(io, "a", .{ .cpu_utilization = 0.5, .memory_utilization = 0.25, .named_metrics = &.{.{ .name = "util", .value = 2.0 }} });
    var first = try stats.snapshotDelta(allocator, io);
    defer first.deinit();
    try std.testing.expectEqual(@as(f64, 0.5), first.entries[0].cpu_utilization.sum);
    try std.testing.expectEqual(@as(u64, 1), first.entries[0].cpu_utilization.count);
    try std.testing.expectEqual(@as(f64, 0.25), first.entries[0].memory_utilization.sum);
    try std.testing.expectEqual(@as(f64, 2.0), first.entries[0].load_metrics[0].sum);
    try std.testing.expectEqual(@as(u64, 1), first.entries[0].load_metrics[0].count);
    stats.recordOrca(io, "a", .{ .cpu_utilization = 0.7, .named_metrics = &.{.{ .name = "util", .value = 3.0 }} });
    var second = try stats.snapshotDelta(allocator, io);
    defer second.deinit();
    try std.testing.expectEqual(@as(f64, 0.7), second.entries[0].cpu_utilization.sum);
    try std.testing.expectEqual(@as(u64, 1), second.entries[0].cpu_utilization.count);
    try std.testing.expectEqual(@as(f64, 3.0), second.entries[0].load_metrics[0].sum);
    try std.testing.expectEqual(@as(u64, 1), second.entries[0].load_metrics[0].count);
    var cumulative = try stats.snapshot(allocator, io);
    defer cumulative.deinit();
    try std.testing.expectEqual(@as(f64, 1.2), cumulative.entries[0].cpu_utilization.sum);
    try std.testing.expectEqual(@as(u64, 2), cumulative.entries[0].cpu_utilization.count);
    try std.testing.expectEqual(@as(f64, 5.0), cumulative.entries[0].load_metrics[0].sum);
    try std.testing.expectEqual(@as(u64, 2), cumulative.entries[0].load_metrics[0].count);
}

test "gRPC LRS ORCA propagation is opt-in and filters metrics" {
    var stats: lrs_stats.Stats = .{ .allocator = allocator };
    defer stats.deinit();
    const io = std.testing.io;
    stats.recordOrca(io, "a", .{ .cpu_utilization = 0.5, .named_metrics = &.{.{ .name = "util", .value = 2.0 }} });
    var none = try stats.snapshot(allocator, io);
    defer none.deinit();
    try std.testing.expectEqual(@as(usize, 0), none.entries.len);

    stats.setPropagation(io, "a", .{ .cpu_utilization = true, .named_metrics = &.{"util"} });
    stats.recordOrca(io, "a", .{
        .cpu_utilization = 0.5,
        .memory_utilization = 0.25,
        .named_metrics = &.{ .{ .name = "util", .value = 2.0 }, .{ .name = "other", .value = 9.0 } },
    });
    var selected = try stats.snapshot(allocator, io);
    defer selected.deinit();
    try std.testing.expectEqual(@as(f64, 0.5), selected.entries[0].cpu_utilization.sum);
    try std.testing.expectEqual(@as(u64, 0), selected.entries[0].memory_utilization.count);
    try std.testing.expectEqual(@as(usize, 1), selected.entries[0].load_metrics.len);
    try std.testing.expectEqualStrings("util", selected.entries[0].load_metrics[0].name);

    // Clearing the selection removes the entry and stops accumulation.
    stats.setPropagation(io, "a", .{});
    stats.recordOrca(io, "a", .{ .cpu_utilization = 0.9 });
    var cleared = try stats.snapshot(allocator, io);
    defer cleared.deinit();
    try std.testing.expectEqual(@as(f64, 0.5), cleared.entries[0].cpu_utilization.sum);
    try std.testing.expectEqual(@as(u64, 1), cleared.entries[0].cpu_utilization.count);
}

test "gRPC LRS records unary ORCA trailers" {
    const orca = @import("../../orca.zig");
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    const Peer = struct {
        fn run(listener: *grpc.runtime.Server) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var unary = try connection.readUnaryWithTimeout(.fromSeconds(3));
            defer unary.deinit();
            const encoded = try orca.encodeAlloc(allocator, .{ .cpu_utilization = 0.5, .named_metrics = &.{.{ .name = "util", .value = 2.0 }} });
            defer allocator.free(encoded);
            try connection.writeUnary(unary.transport.stream_id, .{ .message = "ok", .trailing_binary_metadata = &.{.{ .name = orca.name, .value = encoded }} });
        }
    };
    var task = io.async(Peer.run, .{&server});
    defer _ = task.cancel(io) catch {};
    const path = [_][]const u8{"cluster:a"};
    const endpoint: channel_endpoint = .{ .cleartext_ip = .{ .address = server.address(), .hierarchical_path = &path } };
    var channel = try grpc.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &.{endpoint} } }, .{ .enable_lrs_stats = true });
    defer channel.deinit();
    channel.setLrsPropagation("a", .{ .cpu_utilization = true, .named_metrics_all = true });
    var sender = channel.sender();
    defer sender.deinit();
    var response = try sender.unary(.{ .path = "/demo.Lrs/Call", .message = "ok", .wait_for_ready = true });
    defer response.deinit();
    try std.testing.expectEqual(grpc.Status.ok, response.status);
    var snapshot = try channel.lrsStatsDeltaSnapshot(allocator);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(f64, 0.5), snapshot.entries[0].cpu_utilization.sum);
    try std.testing.expectEqual(@as(u64, 1), snapshot.entries[0].cpu_utilization.count);
    try std.testing.expectEqual(@as(f64, 2.0), snapshot.entries[0].load_metrics[0].sum);
    try std.testing.expectEqual(@as(u64, 1), snapshot.entries[0].load_metrics[0].count);
    try task.await(io);
}

test "gRPC LRS counters retain the EDS service name" {
    var stats: lrs_stats.Stats = .{ .allocator = allocator };
    defer stats.deinit();
    const io = std.testing.io;
    stats.recordStarted(io, "a", "eds-a", null);
    var snapshot = try stats.snapshot(allocator, io);
    defer snapshot.deinit();
    try std.testing.expectEqualStrings("a", snapshot.entries[0].cluster);
    try std.testing.expectEqualStrings("eds-a", snapshot.entries[0].service_name);
    stats.recordStarted(io, "b", "", null);
    var with_empty = try stats.snapshot(allocator, io);
    defer with_empty.deinit();
    try std.testing.expectEqual(@as(usize, 2), with_empty.entries.len);
}

test "gRPC LRS counters resolve the EDS service name from service config" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var task = io.async(PeerUnary.run, .{&server});
    defer _ = task.cancel(io) catch {};
    const path = [_][]const u8{"cluster:impl-a"};
    const endpoint: channel_endpoint = .{ .cleartext_ip = .{ .address = server.address(), .hierarchical_path = &path } };
    var channel = try grpc.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &.{endpoint} } }, .{
        .enable_lrs_stats = true,
        .service_config_json = "{\"loadBalancingConfig\":[{\"xds_cluster_impl_experimental\":{\"clusterName\":\"impl-a\",\"edsServiceName\":\"eds-a\",\"childPolicy\":[{\"round_robin\":{}}]}}]}",
    });
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var response = try sender.unary(.{ .path = "/demo.Lrs/Call", .message = "ok", .wait_for_ready = true });
    defer response.deinit();
    try std.testing.expectEqual(grpc.Status.ok, response.status);
    var snapshot = try channel.lrsStatsDeltaSnapshot(allocator);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(usize, 1), snapshot.entries.len);
    try std.testing.expectEqualStrings("impl-a", snapshot.entries[0].cluster);
    try std.testing.expectEqualStrings("eds-a", snapshot.entries[0].service_name);
    try task.await(io);
}

test "gRPC LRS counters attribute unary completions to the endpoint cluster" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    const Peer = struct {
        fn run(listener: *grpc.runtime.Server) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var first = try connection.readUnaryWithTimeout(.fromSeconds(3));
            defer first.deinit();
            try connection.writeUnary(first.transport.stream_id, .{ .message = "ok" });
            var second = try connection.readUnaryWithTimeout(.fromSeconds(3));
            defer second.deinit();
            try connection.writeUnary(second.transport.stream_id, .{ .status = .internal, .status_message = "fail" });
        }
    };
    var task = io.async(Peer.run, .{&server});
    defer _ = task.cancel(io) catch {};
    const path = [_][]const u8{"cluster:a"};
    const endpoint: channel_endpoint = .{ .cleartext_ip = .{ .address = server.address(), .hierarchical_path = &path } };
    var channel = try grpc.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &.{endpoint} } }, .{ .enable_lrs_stats = true });
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var ok = try sender.unary(.{ .path = "/demo.Lrs/Call", .message = "ok", .wait_for_ready = true });
    defer ok.deinit();
    try std.testing.expectEqual(grpc.Status.ok, ok.status);
    var snapshot = try channel.lrsStatsSnapshot(allocator);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(usize, 1), snapshot.entries.len);
    try std.testing.expectEqualStrings("a", snapshot.entries[0].cluster);
    try std.testing.expectEqual(@as(u64, 1), snapshot.entries[0].successful);
    try std.testing.expectEqual(@as(usize, 1), snapshot.entries[0].endpoints.len);
    try std.testing.expectEqualStrings("127.0.0.1", snapshot.entries[0].endpoints[0].host);
    try std.testing.expectEqual(server.address().getPort(), snapshot.entries[0].endpoints[0].port);
    var failed = try sender.unary(.{ .path = "/demo.Lrs/Call", .message = "fail", .wait_for_ready = true });
    defer failed.deinit();
    try std.testing.expectEqual(grpc.Status.internal, failed.status);
    var after = try channel.lrsStatsSnapshot(allocator);
    defer after.deinit();
    try std.testing.expectEqual(@as(usize, 1), after.entries.len);
    try std.testing.expectEqual(@as(u64, 2), after.entries[0].issued);
    try std.testing.expectEqual(@as(u64, 1), after.entries[0].successful);
    try std.testing.expectEqual(@as(u64, 1), after.entries[0].error_requests);
    try std.testing.expectEqual(@as(usize, 1), after.entries[0].endpoints.len);
    try std.testing.expectEqual(@as(u64, 2), after.entries[0].endpoints[0].issued);
    try std.testing.expectEqual(@as(u64, 1), after.entries[0].endpoints[0].successful);
    try std.testing.expectEqual(@as(u64, 1), after.entries[0].endpoints[0].error_requests);
    try std.testing.expectEqual(@as(u64, 0), after.entries[0].endpoints[0].in_progress);
    try task.await(io);
}

test "gRPC LRS counters attribute streaming completions" {
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
            try first.startResponse(.{});
            try first.finishOk();
            var second = try connection.acceptDuplexWithTimeout(.fromSeconds(3));
            defer second.deinit();
            try second.startResponse(.{});
            try second.finishWithOptions(.{ .status = .internal, .status_message = "fail" });
        }
    };
    var task = io.async(Peer.run, .{&server});
    defer _ = task.cancel(io) catch {};
    const path = [_][]const u8{"cluster:a"};
    const endpoint: channel_endpoint = .{ .cleartext_ip = .{ .address = server.address(), .hierarchical_path = &path } };
    var channel = try grpc.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &.{endpoint} } }, .{ .enable_lrs_stats = true });
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var first = try sender.startDuplex(.{ .path = "/demo.Lrs/Stream", .timeout = .{ .value = 5, .unit = .second }, .wait_for_ready = true });
    defer first.deinit();
    var first_reader = first.reader();
    defer first_reader.deinit();
    try readTerminal(first_reader);
    var second = try sender.startDuplex(.{ .path = "/demo.Lrs/Stream", .timeout = .{ .value = 5, .unit = .second }, .wait_for_ready = true });
    defer second.deinit();
    var second_reader = second.reader();
    defer second_reader.deinit();
    try readTerminal(second_reader);
    var snapshot = try channel.lrsStatsSnapshot(allocator);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(usize, 1), snapshot.entries.len);
    try std.testing.expectEqualStrings("a", snapshot.entries[0].cluster);
    try std.testing.expectEqual(@as(u64, 2), snapshot.entries[0].issued);
    try std.testing.expectEqual(@as(u64, 1), snapshot.entries[0].successful);
    try std.testing.expectEqual(@as(u64, 1), snapshot.entries[0].error_requests);
    try task.await(io);
}

test "gRPC LRS counters attribute channel drops to the selected cluster" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{
        .enable_lrs_stats = true,
        .channel = .{ .drop_categories = &.{.{ .category = "throttle", .requests_per_million = 1_000_000 }} },
    });
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var response = try sender.unary(.{ .path = "/demo.Lrs/Drop", .message = "drop", .wait_for_ready = false, .xds_cluster = "cluster:a" });
    defer response.deinit();
    try std.testing.expect(response.was_dropped);
    var snapshot = try channel.lrsStatsSnapshot(allocator);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(usize, 1), snapshot.entries.len);
    try std.testing.expectEqualStrings("a", snapshot.entries[0].cluster);
    try std.testing.expectEqual(@as(u64, 1), snapshot.entries[0].dropped);
    try std.testing.expectEqual(@as(usize, 1), snapshot.entries[0].categories.len);
    try std.testing.expectEqualStrings("throttle", snapshot.entries[0].categories[0].category);
    try std.testing.expectEqual(@as(u64, 1), snapshot.entries[0].categories[0].count);
    try std.testing.expectEqual(@as(u64, 0), snapshot.entries[0].issued);
}

fn callUnary(sender: grpc.SharedChannelSender) !grpc.UnaryResponse {
    return sender.unary(.{ .path = "/demo.Lrs/Call", .message = "held", .wait_for_ready = true });
}

test "gRPC LRS counters report unary in-progress while a call is held" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var admitted: std.Io.Event = .unset;
    var release: std.Io.Event = .unset;
    const Peer = struct {
        fn run(listener: *grpc.runtime.Server, entered: *std.Io.Event, finish: *std.Io.Event) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var request = try connection.readUnaryWithTimeout(.fromSeconds(3));
            defer request.deinit();
            entered.set(connection.connection.io);
            try finish.wait(connection.connection.io);
            try connection.writeUnary(request.transport.stream_id, .{ .message = "ok" });
        }
    };
    var task = io.async(Peer.run, .{ &server, &admitted, &release });
    defer _ = task.cancel(io) catch {};
    const path = [_][]const u8{"cluster:a"};
    const endpoint: channel_endpoint = .{ .cleartext_ip = .{ .address = server.address(), .hierarchical_path = &path } };
    var channel = try grpc.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &.{endpoint} } }, .{ .enable_lrs_stats = true });
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var call = try io.concurrent(callUnary, .{sender});
    defer _ = call.cancel(io) catch {};
    try admitted.waitTimeout(io, .{ .deadline = .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }) });
    var active = try channel.lrsStatsSnapshot(allocator);
    defer active.deinit();
    try std.testing.expectEqual(@as(u64, 1), active.entries[0].in_progress);
    try std.testing.expectEqual(@as(u64, 1), active.entries[0].issued);
    try std.testing.expectEqual(@as(u64, 0), active.entries[0].successful);
    release.set(io);
    var response = try call.await(io);
    defer response.deinit();
    try std.testing.expectEqual(grpc.Status.ok, response.status);
    var done = try channel.lrsStatsSnapshot(allocator);
    defer done.deinit();
    try std.testing.expectEqual(@as(u64, 0), done.entries[0].in_progress);
    try std.testing.expectEqual(@as(u64, 1), done.entries[0].issued);
    try std.testing.expectEqual(@as(u64, 1), done.entries[0].successful);
    try task.await(io);
}
