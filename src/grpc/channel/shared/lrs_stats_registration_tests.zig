//! Admission registrations survive publication while disabled traffic is absent.
const std = @import("std");
const grpc = @import("../../mod.zig");
const lrs = @import("../../xds/lrs.zig");
const stats = @import("lrs_stats.zig");
const allocator = std.testing.allocator;

test "gRPC LRS selection owns input and metric strings across allocation failures" {
    const Scenario = struct {
        fn run(gpa: std.mem.Allocator) !void {
            var cluster: [1]u8 = .{'a'};
            var service: [3]u8 = "eds".*;
            var metric: [4]u8 = "load".*;
            const selected = try stats.Selection.create(gpa, &.{.{ .cluster = &cluster, .service_name = &service, .propagation = .{ .named_metrics = &.{&metric} } }});
            defer selected.release();
            @memset(&cluster, 'x');
            @memset(&service, 'x');
            @memset(&metric, 'x');
            const identity = selected.find("a", "eds").?;
            try std.testing.expectEqualStrings("load", identity.propagation.named_metrics[0]);
            try std.testing.expect(selected.find("a", "other") == null);
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, Scenario.run, .{});
}

fn select(channel: grpc.SharedChannel, selected: *stats.Selection) !void {
    _ = try channel.updateWithTimeout(.{ .lrs_selection = .{ .replace = selected } }, .fromSeconds(3));
}

fn unary(sender: grpc.SharedChannelSender) !grpc.UnaryResponse {
    return sender.unary(.{ .path = "/demo.Lrs/Call", .message = "ok", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } });
}

test "gRPC LRS unary completion retains admitted selection while disabled calls stay unreported" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var admitted: std.Io.Event = .unset;
    var release: std.Io.Event = .unset;
    const Peer = struct {
        fn run(listener: *grpc.runtime.Server, started: *std.Io.Event, finish: *std.Io.Event, run_io: std.Io) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var disabled = try connection.readUnaryWithTimeout(.fromSeconds(3));
            defer disabled.deinit();
            try connection.writeUnary(disabled.transport.stream_id, .{ .message = "ok" });
            var held = try connection.readUnaryWithTimeout(.fromSeconds(3));
            defer held.deinit();
            started.set(run_io);
            var later = try connection.readUnaryWithTimeout(.fromSeconds(3));
            defer later.deinit();
            try connection.writeUnary(later.transport.stream_id, .{ .message = "ok" });
            try finish.wait(run_io);
            try connection.writeUnary(held.transport.stream_id, .{ .message = "ok" });
            var enabled = try connection.readUnaryWithTimeout(.fromSeconds(3));
            defer enabled.deinit();
            try connection.writeUnary(enabled.transport.stream_id, .{ .message = "ok" });
        }
    };
    var peer = try io.concurrent(Peer.run, .{ &server, &admitted, &release, io });
    defer _ = peer.cancel(io) catch {};
    const path = [_][]const u8{"cluster:a"};
    const endpoint: grpc.ChannelEndpoint = .{ .cleartext_ip = .{ .address = server.address(), .hierarchical_path = &path } };
    var channel = try grpc.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &.{endpoint} } }, .{ .enable_lrs_stats = true });
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    const disabled = try stats.Selection.create(allocator, &.{});
    defer disabled.release();
    const enabled = try stats.Selection.create(allocator, &.{.{ .cluster = "a" }});
    defer enabled.release();
    try select(channel, disabled);
    var before = try unary(sender);
    defer before.deinit();
    var empty = try channel.lrsStatsDeltaSnapshot(allocator);
    defer empty.deinit();
    try std.testing.expectEqual(@as(usize, 0), empty.entries.len);
    try select(channel, enabled);
    var held = try io.concurrent(unary, .{sender});
    var held_live = true;
    defer if (held_live) if (held.cancel(io)) |response_value| {
        var response = response_value;
        response.deinit();
    } else |_| {};
    try admitted.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(3) } });
    try select(channel, disabled);
    var later = try unary(sender);
    defer later.deinit();
    var pending = try channel.lrsStatsDeltaSnapshot(allocator);
    defer pending.deinit();
    try std.testing.expectEqual(@as(usize, 1), pending.entries.len);
    try std.testing.expectEqual(@as(u64, 1), pending.entries[0].issued);
    try std.testing.expectEqual(@as(u64, 1), pending.entries[0].in_progress);
    release.set(io);
    var completed = try held.await(io);
    held_live = false;
    defer completed.deinit();
    var final = try channel.lrsStatsDeltaSnapshot(allocator);
    defer final.deinit();
    var reports = try lrs.integration.build(allocator, &final, .{}, std.time.ns_per_s);
    defer reports.deinit();
    const bytes = try lrs.codec.encodeRequest(allocator, .{ .clusters = reports.clusters }, .{});
    defer allocator.free(bytes);
    var wire = try lrs.codec.decodeRequest(allocator, bytes, .{});
    defer wire.deinit();
    try std.testing.expectEqual(@as(usize, 1), wire.value.clusters.len);
    try std.testing.expectEqual(@as(u64, 1), wire.value.clusters[0].localities[0].successful);
    try std.testing.expectEqual(@as(u64, 0), wire.value.clusters[0].localities[0].issued);
    try std.testing.expectEqual(@as(u64, 0), wire.value.clusters[0].localities[0].in_progress);
    var retired = try channel.lrsStatsDeltaSnapshot(allocator);
    defer retired.deinit();
    try std.testing.expectEqual(@as(usize, 0), retired.entries.len);
    try select(channel, enabled);
    var resumed = try unary(sender);
    defer resumed.deinit();
    var latest = try channel.lrsStatsDeltaSnapshot(allocator);
    defer latest.deinit();
    try std.testing.expectEqual(@as(usize, 1), latest.entries.len);
    try std.testing.expectEqual(@as(u64, 1), latest.entries[0].issued);
    try std.testing.expectEqual(@as(u64, 1), latest.entries[0].successful);
    try peer.await(io);
}

fn terminal(reader: anytype) !void {
    while (true) {
        var event = try reader.nextWithTimeout(.fromSeconds(3));
        defer event.deinit(allocator);
        if (event == .terminal) return;
    }
}

test "gRPC LRS streaming completion retains admitted metrics after CDS selection is disabled" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var admitted: std.Io.Event = .unset;
    var release: std.Io.Event = .unset;
    const Peer = struct {
        fn run(listener: *grpc.runtime.Server, started: *std.Io.Event, finish: *std.Io.Event, run_io: std.Io) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var held = try connection.acceptDuplexWithTimeout(.fromSeconds(3));
            defer held.deinit();
            try held.startResponse(.{});
            started.set(run_io);
            var disabled = try connection.acceptDuplexWithTimeout(.fromSeconds(3));
            defer disabled.deinit();
            try disabled.startResponse(.{});
            try disabled.finishOk();
            try finish.wait(run_io);
            const orca = @import("../../orca.zig");
            const encoded = try orca.encodeAlloc(allocator, .{ .cpu_utilization = 0.5 });
            defer allocator.free(encoded);
            try held.finishWithOptions(.{ .status = .ok, .trailing_binary_metadata = &.{.{ .name = orca.name, .value = encoded }} });
        }
    };
    var peer = try io.concurrent(Peer.run, .{ &server, &admitted, &release, io });
    defer _ = peer.cancel(io) catch {};
    const path = [_][]const u8{"cluster:a"};
    const endpoint: grpc.ChannelEndpoint = .{ .cleartext_ip = .{ .address = server.address(), .hierarchical_path = &path } };
    var channel = try grpc.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &.{endpoint} } }, .{ .enable_lrs_stats = true });
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    const enabled = try stats.Selection.create(allocator, &.{.{ .cluster = "a", .propagation = .{ .cpu_utilization = true } }});
    defer enabled.release();
    const disabled = try stats.Selection.create(allocator, &.{});
    defer disabled.release();
    try select(channel, enabled);
    var held = try sender.startDuplex(.{ .path = "/demo.Lrs/Stream", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } });
    defer held.deinit();
    try admitted.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(3) } });
    try select(channel, disabled);
    var later = try sender.startDuplex(.{ .path = "/demo.Lrs/Stream", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } });
    defer later.deinit();
    var later_reader = later.reader();
    defer later_reader.deinit();
    try terminal(later_reader);
    release.set(io);
    var held_reader = held.reader();
    defer held_reader.deinit();
    try terminal(held_reader);
    var snapshot = try channel.lrsStatsDeltaSnapshot(allocator);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(usize, 1), snapshot.entries.len);
    try std.testing.expectEqual(@as(u64, 1), snapshot.entries[0].issued);
    try std.testing.expectEqual(@as(u64, 1), snapshot.entries[0].successful);
    try std.testing.expectEqual(@as(u64, 0), snapshot.entries[0].in_progress);
    try std.testing.expectEqual(@as(u64, 1), snapshot.entries[0].cpu_utilization.count);
    try std.testing.expectEqual(@as(f64, 0.5), snapshot.entries[0].cpu_utilization.sum);
    try peer.await(io);
}
