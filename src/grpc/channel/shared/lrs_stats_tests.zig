const std = @import("std");
const grpc = @import("../../mod.zig");
const channel_endpoint = @import("../../channel.zig").Endpoint;
const lrs_stats = @import("lrs_stats.zig");
const allocator = std.testing.allocator;

test "gRPC LRS counters aggregate per cluster" {
    var stats: lrs_stats.Stats = .{ .allocator = allocator };
    defer stats.deinit();
    const io = std.testing.io;
    stats.record(io, "a", true);
    stats.record(io, "a", false);
    stats.record(io, "b", true);
    var snapshot = try stats.snapshot(allocator, io);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(usize, 2), snapshot.entries.len);
    for (snapshot.entries) |entry| {
        if (std.mem.eql(u8, entry.cluster, "a")) {
            try std.testing.expectEqual(@as(u64, 2), entry.issued);
            try std.testing.expectEqual(@as(u64, 1), entry.successful);
            try std.testing.expectEqual(@as(u64, 1), entry.error_requests);
        } else {
            try std.testing.expectEqualStrings("b", entry.cluster);
            try std.testing.expectEqual(@as(u64, 1), entry.issued);
            try std.testing.expectEqual(@as(u64, 1), entry.successful);
        }
    }
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
    var failed = try sender.unary(.{ .path = "/demo.Lrs/Call", .message = "fail", .wait_for_ready = true });
    defer failed.deinit();
    try std.testing.expectEqual(grpc.Status.internal, failed.status);
    var after = try channel.lrsStatsSnapshot(allocator);
    defer after.deinit();
    try std.testing.expectEqual(@as(usize, 1), after.entries.len);
    try std.testing.expectEqual(@as(u64, 2), after.entries[0].issued);
    try std.testing.expectEqual(@as(u64, 1), after.entries[0].successful);
    try std.testing.expectEqual(@as(u64, 1), after.entries[0].error_requests);
    try task.await(io);
}
