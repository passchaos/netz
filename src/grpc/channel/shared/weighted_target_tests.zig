const std = @import("std");
const grpc = @import("../../mod.zig");
const shared = @import("../shared.zig");

const allocator = std.testing.allocator;

test "gRPC SharedChannel weighted target delegates nested ready children" {
    const call_count = 400;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var a1_server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer a1_server.deinit();
    var a2_server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer a2_server.deinit();
    var b_server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer b_server.deinit();
    var stop: std.Io.Event = .unset;
    var a1_peer = io.async(Peer.run, .{ &a1_server, &stop, "a1" });
    defer _ = a1_peer.cancel(io) catch {};
    var a2_peer = io.async(Peer.run, .{ &a2_server, &stop, "a2" });
    defer _ = a2_peer.cancel(io) catch {};
    var b_peer = io.async(Peer.run, .{ &b_server, &stop, "b" });
    defer _ = b_peer.cancel(io) catch {};

    const a_path = [_][]const u8{ "a", "inner" };
    const b_path = [_][]const u8{"b"};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{
            .address = a1_server.address(),
            .hierarchical_path = &a_path,
        } },
        .{ .cleartext_ip = .{
            .address = a2_server.address(),
            .hierarchical_path = &a_path,
        } },
        .{ .cleartext_ip = .{
            .address = b_server.address(),
            .hierarchical_path = &b_path,
        } },
    };
    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &endpoints } },
        .{ .service_config_json =
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{
        \\ "targets":{
        \\  "a":{"weight":1,"childPolicy":[
        \\   {"weighted_target_experimental":{"targets":{
        \\    "inner":{"weight":1,"childPolicy":[{"round_robin":{}}]}
        \\   }}}]},
        \\  "b":{"weight":3,"childPolicy":[{"pick_first":{}}]}
        \\ }}}]}
        },
    );
    var client_live = true;
    defer if (client_live) client.deinit();
    try std.testing.expectEqual(
        grpc.ChannelSelectionPolicy.weighted_target,
        client.selectionPolicy(),
    );
    try client.connectWithTimeout(.fromSeconds(5));
    var watches: [3]grpc.ChannelConnectivityWatch = undefined;
    var watch_count: usize = 0;
    defer for (watches[0..watch_count]) |*watch| watch.deinit();
    for (&watches, 0..) |*watch, index| {
        watch.* = client.watchEndpointConnectivity(index).?;
        watch_count += 1;
        try watch.waitForReadyWithTimeout(.fromSeconds(5));
    }

    var sender = client.sender();
    var counts = [_]usize{ 0, 0, 0 };
    for (0..call_count) |_| {
        var response = try sender.unary(.{
            .path = "/demo.WeightedTarget/Unary",
            .authority = "localhost",
            .message = "request",
            .wait_for_ready = true,
            .timeout = try grpc.Timeout.init(5, .second),
        });
        defer response.deinit();
        const payload = response.message.?.payload;
        const index: usize = if (std.mem.eql(u8, payload, "a1"))
            0
        else if (std.mem.eql(u8, payload, "a2"))
            1
        else if (std.mem.eql(u8, payload, "b"))
            2
        else
            return error.UnexpectedBackend;
        counts[index] += 1;
    }
    const a_count = counts[0] + counts[1];
    try std.testing.expect(counts[2] > a_count * 2);
    try std.testing.expect(counts[2] < a_count * 4);
    const a_difference = if (counts[0] > counts[1])
        counts[0] - counts[1]
    else
        counts[1] - counts[0];
    try std.testing.expect(a_difference <= 1);

    sender.deinit();
    client.deinit();
    client_live = false;
    stop.set(io);
    try a1_peer.await(io);
    try a2_peer.await(io);
    try b_peer.await(io);
}

test "gRPC SharedChannel weighted target excludes unavailable heavy child" {
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer server.deinit();
    var stop: std.Io.Event = .unset;
    var peer = io.async(Peer.run, .{ &server, &stop, "ready" });
    defer _ = peer.cancel(io) catch {};
    const ready_path = [_][]const u8{"ready"};
    const failed_path = [_][]const u8{"failed"};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{
            .address = server.address(),
            .hierarchical_path = &ready_path,
        } },
        .{ .cleartext_ip = .{
            .address = .{ .ip4 = .loopback(1) },
            .hierarchical_path = &failed_path,
        } },
    };
    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &endpoints } },
        .{
            .channel = .{ .backoff = .{
                .initial_backoff = .fromMilliseconds(20),
                .max_backoff = .fromMilliseconds(20),
                .multiplier = 1,
                .jitter = 0,
                .min_connect_timeout = .fromMilliseconds(50),
            } },
            .service_config_json =
            \\{"loadBalancingConfig":[{"weighted_target_experimental":{
            \\ "targets":{
            \\  "ready":{"weight":1,"childPolicy":[{"pick_first":{}}]},
            \\  "failed":{"weight":100,"childPolicy":[{"pick_first":{}}]}
            \\ }}}]}
            ,
        },
    );
    var client_live = true;
    defer if (client_live) client.deinit();
    var sender = client.sender();
    for (0..20) |_| {
        var response = try sender.unary(.{
            .path = "/demo.WeightedTarget/Unary",
            .authority = "localhost",
            .message = "request",
            .wait_for_ready = true,
            .timeout = try grpc.Timeout.init(5, .second),
        });
        defer response.deinit();
        try std.testing.expectEqualStrings(
            "ready",
            response.message.?.payload,
        );
    }
    sender.deinit();
    client.deinit();
    client_live = false;
    stop.set(io);
    try peer.await(io);
}

const Peer = struct {
    fn run(
        listener: *grpc.runtime.Server,
        stop: *std.Io.Event,
        label: []const u8,
    ) !void {
        var connection = try listener.acceptWithTimeout(.fromSeconds(5));
        defer connection.deinit();
        while (!stop.isSet()) {
            var request = connection.acceptDuplexWithTimeout(
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
            var seen = false;
            const Consumer = struct {
                seen: *bool,
                fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
                    if (self.seen.* or
                        !std.mem.eql(u8, "request", message.payload))
                    {
                        return error.UnexpectedPayload;
                    }
                    self.seen.* = true;
                }
            };
            var consumer = Consumer{ .seen = &seen };
            while (true) {
                var event = try request.readRequestEventWithTimeout(
                    .fromSeconds(3),
                    &consumer,
                    Consumer.consume,
                );
                defer event.deinit();
                switch (event) {
                    .messages => {},
                    .finished => break,
                    .reset => return error.UnexpectedReset,
                }
            }
            if (!seen) return error.UnexpectedPayload;
            try request.startResponse(.{});
            if (try request.writeMessage(label) != .complete) {
                return error.UnexpectedFlowControl;
            }
            try request.finishOk();
        }
    }
};
