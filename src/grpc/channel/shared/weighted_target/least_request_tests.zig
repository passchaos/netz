const std = @import("std");
const grpc = @import("../../../mod.zig");
const shared = @import("../../shared.zig");
const Peer = @import("test_support.zig").Peer;

const allocator = std.testing.allocator;

test "gRPC SharedChannel weighted target least request is child local" {
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var slow_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer slow_server.deinit();
    var fast_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer fast_server.deinit();
    var stop: std.Io.Event = .unset;
    var slow_peer = io.async(Peer.run, .{ &slow_server, &stop, "slow", @as(?std.Io.Duration, .fromMilliseconds(20)) });
    defer _ = slow_peer.cancel(io) catch {};
    var fast_peer = io.async(Peer.run, .{ &fast_server, &stop, "fast", @as(?std.Io.Duration, null) });
    defer _ = fast_peer.cancel(io) catch {};
    const path = [_][]const u8{"least"};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = slow_server.address(), .hierarchical_path = &path } },
        .{ .cleartext_ip = .{ .address = fast_server.address(), .hierarchical_path = &path } },
    };
    var client = try shared.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{
        .max_active_calls_per_endpoint = 32,
        .service_config_json =
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{
        \\ "targets":{"least":{"weight":1,"childPolicy":[
        \\  {"least_request_experimental":{"choiceCount":10}}]}}
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
    var counts = [_]std.atomic.Value(usize){ .init(0), .init(0) };
    var runners: [2]std.Io.Future(Caller.Result) = undefined;
    var started: usize = 0;
    defer for (runners[0..started]) |*runner| {
        _ = runner.cancel(io) catch {};
    };
    for (&runners) |*runner| {
        runner.* = try io.concurrent(Caller.run, .{ client.sender(), 50, &counts });
        started += 1;
    }
    for (&runners) |*runner| try runner.await(io);
    started = 0;
    const slow = counts[0].load(.acquire);
    const fast = counts[1].load(.acquire);
    try std.testing.expectEqual(@as(usize, 100), slow + fast);
    if (fast <= slow * 2) {
        std.debug.print("weighted-target least-request distribution: slow={d} fast={d}\n", .{ slow, fast });
        return error.TestUnexpectedResult;
    }
    {
        client.state.lock();
        defer client.state.unlock();
        for (client.state.workers.items) |worker| {
            try std.testing.expectEqual(@as(usize, 0), worker.outstanding_requests);
        }
    }
    client.deinit();
    client_live = false;
    stop.set(io);
    try slow_peer.await(io);
    try fast_peer.await(io);
}

const Caller = struct {
    const Result = anyerror!void;

    fn run(sender: shared.Sender, count: usize, results: *[2]std.atomic.Value(usize)) Result {
        var owned = sender;
        defer owned.deinit();
        for (0..count) |_| {
            var response = try owned.unary(.{
                .path = "/demo.WeightedTarget/Unary",
                .authority = "localhost",
                .message = "request",
                .wait_for_ready = true,
                .timeout = try grpc.Timeout.init(10, .second),
            });
            defer response.deinit();
            const payload = response.message.?.payload;
            const index: usize = if (std.mem.eql(u8, payload, "slow")) 0 else if (std.mem.eql(u8, payload, "fast")) 1 else return error.UnexpectedBackend;
            _ = results[index].fetchAdd(1, .release);
        }
    }
};
