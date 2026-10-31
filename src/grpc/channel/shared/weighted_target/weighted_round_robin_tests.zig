const std = @import("std");
const grpc = @import("../../../mod.zig");
const shared = @import("../../shared.zig");
const http2 = @import("../../../../http2/mod.zig");
const Peer = @import("test_support.zig").Peer;

const allocator = std.testing.allocator;

test "gRPC SharedChannel weighted target WRR filters per-RPC ORCA workers" {
    const weighted_calls = 200;
    const fallback_calls = 40;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var a_server = try http2.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer a_server.deinit();
    var b_server = try http2.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer b_server.deinit();
    var outside_server = try http2.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer outside_server.deinit();
    var reporting: std.atomic.Value(bool) = .init(true);
    var a_task = io.async(Server.run, .{ &a_server, "a", 1.0, &reporting });
    defer _ = a_task.cancel(io) catch {};
    var b_task = io.async(Server.run, .{ &b_server, "b", 3.0, &reporting });
    defer _ = b_task.cancel(io) catch {};
    var outside_task = io.async(Server.run, .{ &outside_server, "outside", 100.0, &reporting });
    defer _ = outside_task.cancel(io) catch {};
    const wrr_path = [_][]const u8{"wrr"};
    const outside_path = [_][]const u8{"outside"};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = a_server.address(), .hierarchical_path = &wrr_path } },
        .{ .cleartext_ip = .{ .address = b_server.address(), .hierarchical_path = &wrr_path } },
        .{ .cleartext_ip = .{ .address = outside_server.address(), .hierarchical_path = &outside_path } },
    };
    var client = try shared.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{
        .service_config_json =
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{
        \\ "targets":{"wrr":{"weight":1,"childPolicy":[
        \\  {"weighted_round_robin":{"enableOobLoadReport":false,
        \\   "blackoutPeriod":"0s","weightUpdatePeriod":"0.1s",
        \\   "weightExpirationPeriod":"2s",
        \\   "metricNamesForComputingUtilization":["cpu_utilization"]}}]}}
        \\ }}]}
        ,
    });
    var client_live = true;
    defer if (client_live) client.deinit();
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
    defer sender.deinit();
    var learned = [_]bool{ false, false };
    for (0..20) |_| {
        var response = try call(sender);
        defer response.deinit();
        learned[try backendIndex(&response)] = true;
        if (learned[0] and learned[1]) break;
    }
    try std.testing.expect(learned[0] and learned[1]);
    {
        client.state.lock();
        defer client.state.unlock();
        var matching_updates: usize = 0;
        var outside_updates: usize = 0;
        for (client.state.workers.items) |worker| {
            const worker_path = worker.source
                .endpoint.hierarchicalPath();
            if (std.mem.eql(u8, worker_path[0], "wrr")) {
                matching_updates += @intFromBool(
                    worker.wrr_weight.last_update_ns != null,
                );
            } else {
                outside_updates += @intFromBool(
                    worker.wrr_weight.last_update_ns != null,
                );
            }
        }
        try std.testing.expectEqual(@as(usize, 2), matching_updates);
        try std.testing.expectEqual(@as(usize, 0), outside_updates);
    }
    try std.Io.sleep(io, .fromMilliseconds(120), .awake);
    var counts = [_]usize{ 0, 0 };
    for (0..weighted_calls) |_| {
        var response = try call(sender);
        defer response.deinit();
        counts[try backendIndex(&response)] += 1;
    }
    if (counts[1] <= weighted_calls * 6 / 10 or
        counts[1] >= weighted_calls * 9 / 10)
    {
        std.debug.print("weighted-target WRR distribution: a={d} b={d}\n", .{
            counts[0], counts[1],
        });
        return error.TestUnexpectedResult;
    }
    reporting.store(false, .release);
    try std.Io.sleep(io, .fromMilliseconds(2100), .awake);
    var fallback = [_]usize{ 0, 0 };
    for (0..fallback_calls) |_| {
        var response = try call(sender);
        defer response.deinit();
        fallback[try backendIndex(&response)] += 1;
    }
    try std.testing.expectEqual(fallback[0], fallback[1]);

    client.deinit();
    client_live = false;
    try a_task.await(io);
    try b_task.await(io);
    try outside_task.await(io);
}

test "gRPC SharedChannel weighted target WRR owns child OOB stream" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var wrr_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer wrr_server.deinit();
    var outside_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer outside_server.deinit();
    var wrr_task = io.async(OobServer.run, .{&wrr_server});
    defer _ = wrr_task.cancel(io) catch {};
    var stop: std.Io.Event = .unset;
    var outside_task = io.async(Peer.run, .{ &outside_server, &stop, "outside", null });
    defer _ = outside_task.cancel(io) catch {};
    const wrr_path = [_][]const u8{"wrr"};
    const outside_path = [_][]const u8{"outside"};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = wrr_server.address(), .hierarchical_path = &wrr_path } },
        .{ .cleartext_ip = .{ .address = outside_server.address(), .hierarchical_path = &outside_path } },
    };
    var client = try shared.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{
        .service_config_json =
        \\{"loadBalancingConfig":[{"weighted_target_experimental":{
        \\ "targets":{"wrr":{"weight":1,"childPolicy":[
        \\  {"weighted_round_robin":{"enableOobLoadReport":true,
        \\   "oobReportingPeriod":"1s","blackoutPeriod":"0s"}}]}}
        \\ }}]}
        ,
    });
    var client_live = true;
    defer if (client_live) client.deinit();
    var watch = client.watchEndpointOrca(0).?;
    defer watch.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var pending = try io.concurrent(call, .{sender});
    defer _ = pending.cancel(io) catch {};
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .raw = .fromSeconds(10), .clock = .awake });
    while (true) {
        var update = try watch.nextWithDeadline(deadline);
        defer update.deinit();
        if (update.header.status == .ready and update.report != null) break;
    }
    var response = try pending.await(io);
    defer response.deinit();
    try std.testing.expectEqualStrings("wrr", response.message.?.payload);
    {
        client.state.lock();
        defer client.state.unlock();
        var matching_updates: usize = 0;
        var outside_updates: usize = 0;
        for (client.state.workers.items) |worker| {
            const path = worker.source
                .endpoint.hierarchicalPath();
            if (std.mem.eql(u8, path[0], "wrr")) {
                matching_updates += @intFromBool(worker.wrr_weight.last_update_ns != null);
            } else {
                outside_updates += @intFromBool(worker.wrr_weight.last_update_ns != null);
            }
        }
        try std.testing.expectEqual(@as(usize, 1), matching_updates);
        try std.testing.expectEqual(@as(usize, 0), outside_updates);
    }
    client.deinit();
    client_live = false;
    stop.set(io);
    try wrr_task.await(io);
    try outside_task.await(io);
}

fn call(sender: shared.Sender) !grpc.UnaryResponse {
    return sender.unary(.{
        .path = "/demo.WeightedTarget/Unary",
        .message = "request",
        .wait_for_ready = true,
        .timeout = try grpc.Timeout.init(5, .second),
    });
}

fn backendIndex(response: *const grpc.UnaryResponse) !usize {
    const label = response.message.?.payload;
    if (std.mem.eql(u8, label, "a")) return 0;
    if (std.mem.eql(u8, label, "b")) return 1;
    return error.UnexpectedBackend;
}

const Server = struct {
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
            var request = connection.readRequestWithTimeout(.fromSeconds(10)) catch |err| switch (err) {
                error.ConnectionClosed,
                error.ConnectionResetByPeer,
                error.SocketUnconnected,
                error.UnexpectedEof,
                => return,
                else => return err,
            };
            defer request.deinit(listener.allocator);
            var parsed = try grpc.parseUnaryRequest(listener.allocator, &request, 1024);
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

const OobServer = struct {
    fn run(listener: *grpc.runtime.Server) !void {
        var connection = try listener.acceptWithTimeout(.fromSeconds(5));
        defer connection.deinit();
        var reports: ?grpc.orca_oob.ServerSession = null;
        var business_done = false;
        while (reports == null or !business_done) {
            var accepted = try connection.acceptDuplexWithTimeout(.fromSeconds(10));
            if (std.mem.eql(u8, accepted.path, grpc.orca_oob.path)) {
                reports = try grpc.orca_oob.accept(accepted);
                if (try reports.?.writeReport(.{
                    .cpu_utilization = 1,
                    .rps_fractional = 5,
                }) != .complete) return error.UnexpectedFlowControl;
            } else {
                respond(&accepted, "wrr") catch |err| {
                    accepted.deinit();
                    return err;
                };
                accepted.deinit();
                business_done = true;
            }
        }
        defer reports.?.deinit();
    }

    fn respond(business: *grpc.ServerDuplex, label: []const u8) !void {
        var seen = false;
        const Consumer = struct {
            seen: *bool,
            fn consume(self: *@This(), _: grpc.StreamingMessage) !void {
                if (self.seen.*) return error.UnexpectedRequest;
                self.seen.* = true;
            }
        };
        var consumer = Consumer{ .seen = &seen };
        while (true) {
            var event = try business.readRequestEventWithTimeout(
                .fromSeconds(10),
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
        try business.startResponse(.{});
        if (try business.writeMessage(label) != .complete) {
            return error.UnexpectedFlowControl;
        }
        try business.finishOk();
    }
};
