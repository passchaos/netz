const std = @import("std");
const grpc = @import("../../../mod.zig");
const shared = @import("../../shared.zig");

const allocator = std.testing.allocator;

test "gRPC SharedChannel weighted target outlier ejects only failing child endpoint" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var bad_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer bad_server.deinit();
    var good_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer good_server.deinit();
    var stop: std.Io.Event = .unset;
    var bad_task = io.async(Peer.run, .{ &bad_server, &stop, false });
    defer _ = bad_task.cancel(io) catch {};
    var good_task = io.async(Peer.run, .{ &good_server, &stop, true });
    defer _ = good_task.cancel(io) catch {};
    const path = [_][]const u8{"wrapped"};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = bad_server.address(), .hierarchical_path = &path } },
        .{ .cleartext_ip = .{ .address = good_server.address(), .hierarchical_path = &path } },
    };
    var client = try shared.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{
        .service_config_json =
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{
        \\ "targets":{"wrapped":{"weight":1,"childPolicy":[
        \\  {"outlier_detection_experimental":{
        \\   "interval":"0.02s","baseEjectionTime":"0.2s",
        \\   "maxEjectionTime":"0.2s","maxEjectionPercent":100,
        \\   "failurePercentageEjection":{"threshold":50,
        \\    "enforcementPercentage":100,"minimumHosts":1,
        \\    "requestVolume":2},
        \\   "childPolicy":[{"round_robin":{}}]}}]}}
        \\ }}]}
        ,
    });
    var client_live = true;
    defer if (client_live) client.deinit();
    try client.connectWithTimeout(.fromSeconds(5));
    var watches: [2]grpc.ChannelConnectivityWatch = undefined;
    var watch_count: usize = 0;
    defer for (watches[0..watch_count]) |*watch| watch.deinit();
    for (&watches, 0..) |*watch, index| {
        watch.* = client.watchEndpointConnectivity(index).?;
        watch_count += 1;
        try watch.waitForReadyWithTimeout(.fromSeconds(5));
    }
    var sender = client.sender();
    defer sender.deinit();
    var initial = [_]usize{ 0, 0 };
    for (0..4) |_| {
        var response = try call(sender);
        defer response.deinit();
        initial[@intFromBool(response.status == .ok)] += 1;
    }
    try std.testing.expectEqualSlices(usize, &.{ 2, 2 }, &initial);
    try std.Io.sleep(io, .fromMilliseconds(30), .awake);
    for (0..5) |_| {
        var response = try call(sender);
        defer response.deinit();
        try std.testing.expectEqual(grpc.Status.ok, response.status);
        try std.testing.expectEqualStrings("good", response.message.?.payload);
    }
    {
        client.state.lock();
        defer client.state.unlock();
        var ejected: usize = 0;
        for (client.state.workers.items) |worker| {
            try std.testing.expectEqual(
                @as(usize, 1),
                worker.weighted_outliers.len,
            );
            ejected += @intFromBool(worker.weighted_outliers[0].isEjected());
        }
        try std.testing.expectEqual(@as(usize, 1), ejected);
    }
    try std.Io.sleep(io, .fromMilliseconds(250), .awake);
    var after_expiry = try call(sender);
    defer after_expiry.deinit();
    {
        client.state.lock();
        defer client.state.unlock();
        for (client.state.workers.items) |worker| {
            try std.testing.expect(!worker.weighted_outliers[0].isEjected());
        }
    }
    client.deinit();
    client_live = false;
    stop.set(io);
    try bad_task.await(io);
    try good_task.await(io);
}

test "gRPC SharedChannel weighted target sibling outlier buckets are isolated" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var a_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a_server.deinit();
    var b_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer b_server.deinit();
    var stop: std.Io.Event = .unset;
    var a_task = io.async(Peer.run, .{ &a_server, &stop, true });
    defer _ = a_task.cancel(io) catch {};
    var b_task = io.async(Peer.run, .{ &b_server, &stop, true });
    defer _ = b_task.cancel(io) catch {};
    const a_path = [_][]const u8{"a"};
    const b_path = [_][]const u8{"b"};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = a_server.address(), .hierarchical_path = &a_path } },
        .{ .cleartext_ip = .{ .address = b_server.address(), .hierarchical_path = &b_path } },
    };
    const config =
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{
        \\ "targets":{
        \\  "a":{"weight":1,"childPolicy":[
        \\   {"outlier_detection_experimental":{"interval":"10s",
        \\    "maxEjectionPercent":100,"failurePercentageEjection":{
        \\     "threshold":50,"minimumHosts":1,"requestVolume":1},
        \\    "childPolicy":[{"pick_first":{}}]}}]},
        \\  "b":{"weight":1,"childPolicy":[
        \\   {"outlier_detection_experimental":{"interval":"10s",
        \\    "maxEjectionPercent":100,"failurePercentageEjection":{
        \\     "threshold":50,"minimumHosts":1,"requestVolume":1},
        \\    "childPolicy":[{"pick_first":{}}]}}]}
        \\ }}}]}
    ;
    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &endpoints } },
        .{ .service_config_json = config },
    );
    var client_live = true;
    defer if (client_live) client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    for (0..100) |_| {
        var response = try call(sender);
        defer response.deinit();
        try std.testing.expectEqual(grpc.Status.ok, response.status);
    }
    {
        client.state.lock();
        defer client.state.unlock();
        for (client.state.workers.items) |worker| {
            const path = client.state.sources[worker.source_index]
                .endpoint.hierarchicalPath();
            try std.testing.expectEqual(
                @as(usize, 2),
                worker.weighted_outliers.len,
            );
            const own: usize = @intFromBool(std.mem.eql(u8, path[0], "b"));
            const other = 1 - own;
            try std.testing.expect(
                worker.weighted_outliers[own].successes.load(.acquire) != 0,
            );
            try std.testing.expectEqual(
                @as(u64, 0),
                worker.weighted_outliers[other].successes.load(.acquire),
            );
            try std.testing.expectEqual(
                @as(u64, 0),
                worker.weighted_outliers[other].failures.load(.acquire),
            );
        }
    }
    client.deinit();
    client_live = false;
    stop.set(io);
    try a_task.await(io);
    try b_task.await(io);
}

fn call(sender: shared.Sender) !grpc.UnaryResponse {
    return sender.unary(.{
        .path = "/demo.WeightedTarget/Unary",
        .message = "request",
        .wait_for_ready = true,
        .timeout = try grpc.Timeout.init(5, .second),
    });
}

const Peer = struct {
    fn run(
        server: *grpc.runtime.Server,
        stop: *std.Io.Event,
        healthy: bool,
    ) !void {
        var connection = try server.acceptWithTimeout(.fromSeconds(5));
        defer connection.deinit();
        while (!stop.isSet()) {
            var request = connection.readUnaryWithTimeout(
                .fromMilliseconds(100),
            ) catch |err| switch (err) {
                error.Timeout => continue,
                error.ConnectionClosed,
                error.ConnectionResetByPeer,
                error.SocketUnconnected,
                error.UnexpectedEof,
                => return,
                else => return err,
            };
            defer request.deinit();
            try connection.writeUnary(request.request.stream_id, if (healthy)
                .{ .message = "good" }
            else
                .{ .status = .unavailable, .trailers_only = true });
        }
    }
};
