const std = @import("std");
const grpc = @import("../mod.zig");
const channel = @import("../channel.zig");
const Peer = @import("shared/weighted_target/test_support.zig").Peer;

const allocator = std.testing.allocator;

test "gRPC ordinary weighted target warms and delegates nested ready children" {
    const call_count = 400;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var a1_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a1_server.deinit();
    var a2_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a2_server.deinit();
    var b_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer b_server.deinit();
    var stop: std.Io.Event = .unset;
    var a1_peer = io.async(Peer.run, .{ &a1_server, &stop, "a1", null });
    defer _ = a1_peer.cancel(io) catch {};
    var a2_peer = io.async(Peer.run, .{ &a2_server, &stop, "a2", null });
    defer _ = a2_peer.cancel(io) catch {};
    var b_peer = io.async(Peer.run, .{ &b_server, &stop, "b", null });
    defer _ = b_peer.cancel(io) catch {};
    const a_path = [_][]const u8{ "a", "inner" };
    const b_path = [_][]const u8{"b"};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = a1_server.address(), .hierarchical_path = &a_path } },
        .{ .cleartext_ip = .{ .address = a2_server.address(), .hierarchical_path = &a_path } },
        .{ .cleartext_ip = .{ .address = b_server.address(), .hierarchical_path = &b_path } },
    };
    var config = try grpc.ServiceConfig.parse(allocator,
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{
        \\ "targets":{
        \\  "a":{"weight":1,"childPolicy":[
        \\   {"weighted_target_experimental":{"targets":{
        \\    "inner":{"weight":1,"childPolicy":[{"round_robin":{}}]}
        \\   }}}]},
        \\  "b":{"weight":3,"childPolicy":[{"pick_first":{}}]}
        \\ }}}]}
    );
    var client = try channel.Channel.initWithServiceConfig(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &endpoints } },
        .{ .connection_attempt_delay = .fromMilliseconds(100) },
        &config,
    );
    config.deinit();
    var client_live = true;
    defer if (client_live) client.deinit();
    try std.testing.expectEqual(
        grpc.ChannelSelectionPolicy.weighted_target,
        client.selectionPolicy(),
    );
    var counts = [_]usize{ 0, 0, 0 };
    for (0..call_count) |_| {
        var response = try call(&client);
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
    try std.testing.expect(counts[2] > call_count * 6 / 10);
    try std.testing.expect(counts[2] < call_count * 9 / 10);
    const difference = if (counts[0] > counts[1])
        counts[0] - counts[1]
    else
        counts[1] - counts[0];
    try std.testing.expect(difference <= 1);
    client.deinit();
    client_live = false;
    stop.set(io);
    try a1_peer.await(io);
    try a2_peer.await(io);
    try b_peer.await(io);
}

test "gRPC ordinary weighted target executes child least request" {
    const call_count = 200;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var a_server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer a_server.deinit();
    var b_server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer b_server.deinit();
    var stop: std.Io.Event = .unset;
    var a_peer = io.async(Peer.run, .{ &a_server, &stop, "a", null });
    defer _ = a_peer.cancel(io) catch {};
    var b_peer = io.async(Peer.run, .{ &b_server, &stop, "b", null });
    defer _ = b_peer.cancel(io) catch {};
    const path = [_][]const u8{"least"};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{
            .address = a_server.address(),
            .hierarchical_path = &path,
        } },
        .{ .cleartext_ip = .{
            .address = b_server.address(),
            .hierarchical_path = &path,
        } },
    };
    var config = try grpc.ServiceConfig.parse(allocator,
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{
        \\ "targets":{"least":{"weight":1,"childPolicy":[
        \\  {"least_request_experimental":{"choiceCount":10}}]}}
        \\ }}]}
    );
    var client = try channel.Channel.initWithServiceConfig(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &endpoints } },
        .{ .connection_attempt_delay = .fromMilliseconds(100) },
        &config,
    );
    config.deinit();
    var client_live = true;
    defer if (client_live) client.deinit();
    var counts = [_]usize{ 0, 0 };
    for (0..call_count) |_| {
        var response = try call(&client);
        defer response.deinit();
        const payload = response.message.?.payload;
        const index: usize = if (std.mem.eql(u8, payload, "a"))
            0
        else if (std.mem.eql(u8, payload, "b"))
            1
        else
            return error.UnexpectedBackend;
        counts[index] += 1;
    }
    try std.testing.expect(counts[0] > call_count / 5);
    try std.testing.expect(counts[1] > call_count / 5);
    client.deinit();
    client_live = false;
    stop.set(io);
    try a_peer.await(io);
    try b_peer.await(io);
}

test "gRPC ordinary weighted target ring hash owns hash and fallback" {
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var a_server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer a_server.deinit();
    var b_server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer b_server.deinit();
    var stop: std.Io.Event = .unset;
    var a_peer = io.async(Peer.run, .{ &a_server, &stop, "a", null });
    defer _ = a_peer.cancel(io) catch {};
    var b_peer = io.async(Peer.run, .{ &b_server, &stop, "b", null });
    defer _ = b_peer.cancel(io) catch {};
    const path = [_][]const u8{"ring"};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{
            .address = a_server.address(),
            .ring_hash_key = "a",
            .hierarchical_path = &path,
        } },
        .{ .cleartext_ip = .{
            .address = b_server.address(),
            .ring_hash_key = "b",
            .hierarchical_path = &path,
        } },
        .{ .cleartext_ip = .{
            .address = .{ .ip4 = .loopback(1) },
            .ring_hash_key = "c",
            .hierarchical_path = &path,
        } },
    };
    var config = try grpc.ServiceConfig.parse(allocator,
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{
        \\ "targets":{"ring":{"weight":1,"childPolicy":[
        \\  {"ring_hash_experimental":{"minRingSize":16,
        \\   "maxRingSize":16,"requestHashHeader":"x-shard"}}]}}
        \\ }}]}
    );
    var client = try channel.Channel.initWithServiceConfig(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &endpoints } },
        .{
            .backoff = .{
                .initial_backoff = .fromMilliseconds(20),
                .max_backoff = .fromMilliseconds(20),
                .multiplier = 1,
                .jitter = 0,
                .min_connect_timeout = .fromMilliseconds(50),
            },
            .connection_attempt_delay = .fromMilliseconds(50),
        },
        &config,
    );
    config.deinit();
    var client_live = true;
    defer if (client_live) client.deinit();
    {
        var response = try ringCall(&client, "a_0", grpc.ringHash("b_0"));
        defer response.deinit();
        try std.testing.expectEqualStrings("a", response.message.?.payload);
    }
    {
        var response = try ringCall(&client, "b_0", grpc.ringHash("a_0"));
        defer response.deinit();
        try std.testing.expectEqualStrings("b", response.message.?.payload);
    }
    {
        var response = try ringCall(&client, "c_0", null);
        defer response.deinit();
        const label = response.message.?.payload;
        try std.testing.expect(
            std.mem.eql(u8, label, "a") or std.mem.eql(u8, label, "b"),
        );
    }
    {
        var response = try call(&client);
        defer response.deinit();
        const label = response.message.?.payload;
        try std.testing.expect(
            std.mem.eql(u8, label, "a") or std.mem.eql(u8, label, "b"),
        );
    }
    {
        var stream = try client.startDuplex(.{
            .path = "/demo.WeightedTarget/Duplex",
            .authority = "localhost",
            .metadata = &.{.{ .name = "x-shard", .value = "b_0" }},
            .request_hash = grpc.ringHash("a_0"),
            .wait_for_ready = true,
            .timeout = try grpc.Timeout.init(5, .second),
        });
        defer stream.deinit();
        try std.testing.expectEqual(
            grpc.DuplexWriteResult.complete,
            try stream.writeFinalMessage("request"),
        );
        const Consumer = struct {
            messages: usize = 0,

            fn consume(
                self: *@This(),
                message: grpc.StreamingMessage,
            ) !void {
                try std.testing.expectEqualStrings("b", message.payload);
                self.messages += 1;
            }
        };
        var consumer: Consumer = .{};
        while (true) {
            var event = try stream.readResponseEventWithTimeout(
                .fromSeconds(5),
                &consumer,
                Consumer.consume,
            );
            defer event.deinit(allocator);
            switch (event) {
                .terminal => |response| {
                    try std.testing.expectEqual(
                        grpc.Status.ok,
                        response.status,
                    );
                    try std.testing.expectEqual(
                        @as(usize, 1),
                        consumer.messages,
                    );
                    break;
                },
                else => {},
            }
        }
    }
    client.deinit();
    client_live = false;
    stop.set(io);
    try a_peer.await(io);
    try b_peer.await(io);
}

test "gRPC ordinary weighted target excludes unavailable heavy child" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var stop: std.Io.Event = .unset;
    var peer = io.async(Peer.run, .{ &server, &stop, "ready", null });
    defer _ = peer.cancel(io) catch {};
    const ready_path = [_][]const u8{"ready"};
    const failed_path = [_][]const u8{"failed"};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = server.address(), .hierarchical_path = &ready_path } },
        .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) }, .hierarchical_path = &failed_path } },
    };
    var config = try grpc.ServiceConfig.parse(allocator,
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{
        \\ "targets":{
        \\  "ready":{"weight":1,"childPolicy":[{"pick_first":{}}]},
        \\  "failed":{"weight":100,"childPolicy":[{"pick_first":{}}]}
        \\ }}}]}
    );
    defer config.deinit();
    var client = try channel.Channel.initWithServiceConfig(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &endpoints } },
        .{ .connection_attempt_delay = .fromMilliseconds(50) },
        &config,
    );
    var client_live = true;
    defer if (client_live) client.deinit();
    for (0..20) |_| {
        var response = try call(&client);
        defer response.deinit();
        try std.testing.expectEqualStrings("ready", response.message.?.payload);
    }
    client.deinit();
    client_live = false;
    stop.set(io);
    try peer.await(io);
}

fn call(client: *channel.Channel) !grpc.UnaryResponse {
    return client.unary(.{
        .path = "/demo.WeightedTarget/Unary",
        .message = "request",
        .wait_for_ready = true,
        .timeout = try grpc.Timeout.init(5, .second),
    });
}

fn ringCall(
    client: *channel.Channel,
    shard: []const u8,
    explicit: ?u64,
) !grpc.UnaryResponse {
    return client.unary(.{
        .path = "/demo.WeightedTarget/Unary",
        .authority = "localhost",
        .message = "request",
        .metadata = &.{.{ .name = "x-shard", .value = shard }},
        .request_hash = explicit,
        .wait_for_ready = true,
        .timeout = try grpc.Timeout.init(5, .second),
    });
}
