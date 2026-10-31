const std = @import("std");
const grpc = @import("../mod.zig");
const channel = @import("../channel.zig");
const http2 = @import("../../http2/mod.zig");
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

test "gRPC ordinary weighted target WRR filters per-RPC ORCA slots" {
    const weighted_calls = 200;
    const fallback_calls = 40;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var a_server = try http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer a_server.deinit();
    var b_server = try http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer b_server.deinit();
    var outside_server = try http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer outside_server.deinit();
    var reporting: std.atomic.Value(bool) = .init(true);
    var a_task = io.async(WrrServer.run, .{
        &a_server,
        "a",
        1.0,
        &reporting,
    });
    defer _ = a_task.cancel(io) catch {};
    var b_task = io.async(WrrServer.run, .{
        &b_server,
        "b",
        3.0,
        &reporting,
    });
    defer _ = b_task.cancel(io) catch {};
    var outside_task = io.async(WrrServer.run, .{
        &outside_server,
        "outside",
        100.0,
        &reporting,
    });
    defer _ = outside_task.cancel(io) catch {};
    const wrr_path = [_][]const u8{"wrr"};
    const outside_path = [_][]const u8{"outside"};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{
            .address = a_server.address(),
            .hierarchical_path = &wrr_path,
        } },
        .{ .cleartext_ip = .{
            .address = b_server.address(),
            .hierarchical_path = &wrr_path,
        } },
        .{ .cleartext_ip = .{
            .address = outside_server.address(),
            .hierarchical_path = &outside_path,
        } },
    };
    var config = try grpc.ServiceConfig.parse(allocator,
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{
        \\ "targets":{"wrr":{"weight":1,"childPolicy":[
        \\  {"weighted_round_robin":{"enableOobLoadReport":false,
        \\   "blackoutPeriod":"0s","weightUpdatePeriod":"0.1s",
        \\   "weightExpirationPeriod":"2s",
        \\   "metricNamesForComputingUtilization":[
        \\    "cpu_utilization"]}}]}}
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
    var learned = [_]bool{ false, false };
    for (0..20) |_| {
        var response = try call(&client);
        defer response.deinit();
        learned[try weightedBackendIndex(&response)] = true;
        if (learned[0] and learned[1]) break;
    }
    try std.testing.expect(learned[0] and learned[1]);
    try std.Io.sleep(io, .fromMilliseconds(120), .awake);

    var counts = [_]usize{ 0, 0 };
    for (0..weighted_calls) |_| {
        var response = try call(&client);
        defer response.deinit();
        counts[try weightedBackendIndex(&response)] += 1;
    }
    try std.testing.expect(counts[1] > weighted_calls * 6 / 10);
    try std.testing.expect(counts[1] < weighted_calls * 9 / 10);

    reporting.store(false, .release);
    try std.Io.sleep(io, .fromMilliseconds(2100), .awake);
    var fallback = [_]usize{ 0, 0 };
    for (0..fallback_calls) |_| {
        var response = try call(&client);
        defer response.deinit();
        fallback[try weightedBackendIndex(&response)] += 1;
    }
    try std.testing.expectEqual(fallback[0], fallback[1]);
    client.deinit();
    client_live = false;
    try a_task.await(io);
    try b_task.await(io);
    try outside_task.await(io);
}

test "gRPC ordinary weighted target OOB WRR stays leaf local RR" {
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
    const path = [_][]const u8{"wrr"};
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
        \\ "targets":{"wrr":{"weight":1,"childPolicy":[
        \\  {"weighted_round_robin":{"enableOobLoadReport":true,
        \\   "oobReportingPeriod":"1s","blackoutPeriod":"0s"}}]}}
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
    for (0..40) |_| {
        var response = try call(&client);
        defer response.deinit();
        counts[try weightedBackendIndex(&response)] += 1;
    }
    try std.testing.expectEqualSlices(usize, &.{ 20, 20 }, &counts);
    client.deinit();
    client_live = false;
    stop.set(io);
    try a_peer.await(io);
    try b_peer.await(io);
}

test "gRPC ordinary weighted target outlier ejects and restores child slot" {
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var bad_server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer bad_server.deinit();
    var good_server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer good_server.deinit();
    var stop: std.Io.Event = .unset;
    var bad_task = io.async(OutlierPeer.run, .{
        &bad_server,
        &stop,
        false,
    });
    defer _ = bad_task.cancel(io) catch {};
    var good_task = io.async(OutlierPeer.run, .{
        &good_server,
        &stop,
        true,
    });
    defer _ = good_task.cancel(io) catch {};
    const path = [_][]const u8{"wrapped"};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{
            .address = bad_server.address(),
            .hierarchical_path = &path,
        } },
        .{ .cleartext_ip = .{
            .address = good_server.address(),
            .hierarchical_path = &path,
        } },
    };
    var config = try grpc.ServiceConfig.parse(allocator,
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
    {
        var stream = try client.startDuplex(.{
            .path = "/demo.WeightedTarget/OutlierDuplex",
            .wait_for_ready = true,
            .timeout = try grpc.Timeout.init(5, .second),
        });
        defer stream.deinit();
        try std.testing.expectEqual(
            grpc.DuplexWriteResult.complete,
            try stream.writeFinalMessage("request"),
        );
        const Consumer = struct {
            fn consume(_: void, _: grpc.StreamingMessage) !void {
                return error.UnexpectedMessage;
            }
        };
        while (true) {
            var event = try stream.readResponseEventWithTimeout(
                .fromSeconds(5),
                {},
                Consumer.consume,
            );
            defer event.deinit(allocator);
            if (event == .terminal) {
                try std.testing.expectEqual(
                    grpc.Status.unavailable,
                    event.terminal.status,
                );
                break;
            }
        }
    }
    var initial = [_]usize{ 0, 0 };
    for (0..2) |_| {
        var response = try call(&client);
        defer response.deinit();
        initial[@intFromBool(response.status == .ok)] += 1;
    }
    try std.testing.expectEqualSlices(usize, &.{ 1, 1 }, &initial);
    try std.Io.sleep(io, .fromMilliseconds(30), .awake);
    for (0..5) |_| {
        var response = try call(&client);
        defer response.deinit();
        try std.testing.expectEqual(grpc.Status.ok, response.status);
        try std.testing.expectEqualStrings("good", response.message.?.payload);
    }
    try std.Io.sleep(io, .fromMilliseconds(250), .awake);
    var restored_bad = false;
    for (0..2) |_| {
        var response = try call(&client);
        defer response.deinit();
        restored_bad = restored_bad or response.status == .unavailable;
    }
    try std.testing.expect(restored_bad);
    client.deinit();
    client_live = false;
    stop.set(io);
    try bad_task.await(io);
    try good_task.await(io);
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

fn weightedBackendIndex(response: *const grpc.UnaryResponse) !usize {
    const label = response.message.?.payload;
    if (std.mem.eql(u8, label, "a")) return 0;
    if (std.mem.eql(u8, label, "b")) return 1;
    return error.UnexpectedBackend;
}

const WrrServer = struct {
    fn run(
        listener: *http2.runtime.Server,
        label: []const u8,
        qps: f64,
        reporting: *const std.atomic.Value(bool),
    ) !void {
        const encoded = try grpc.orca.encodeAlloc(listener.allocator, .{
            .cpu_utilization = 1,
            .rps_fractional = qps,
        });
        defer listener.allocator.free(encoded);
        var connection = try listener.acceptWithTimeout(.fromSeconds(5));
        defer connection.close();
        while (true) {
            var request = connection.readRequestWithTimeout(
                .fromSeconds(10),
            ) catch |err| switch (err) {
                error.ConnectionClosed,
                error.ConnectionResetByPeer,
                error.SocketUnconnected,
                error.UnexpectedEof,
                => return,
                else => return err,
            };
            defer request.deinit(listener.allocator);
            var parsed = try grpc.parseUnaryRequest(
                listener.allocator,
                &request,
                1024,
            );
            defer parsed.deinit();
            try grpc.writeUnaryResponse(
                &connection,
                listener.allocator,
                request.stream_id,
                if (reporting.load(.acquire)) .{
                    .message = label,
                    .trailing_binary_metadata = &.{.{
                        .name = grpc.orca.name,
                        .value = encoded,
                    }},
                } else .{ .message = label },
            );
        }
    }
};

const OutlierPeer = struct {
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
