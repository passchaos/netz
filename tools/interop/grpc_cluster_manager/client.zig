//! Exercise per-RPC cluster dispatch against independent grpc-js backends.
const std = @import("std");
const netz = @import("netz");
const grpc = netz.grpc;
const allocator = std.heap.c_allocator;
const json = "{\"loadBalancingConfig\":[{\"xds_cluster_manager_experimental\":{\"children\":{\"a\":{\"childPolicy\":[{\"round_robin\":{}}]},\"b\":{\"childPolicy\":[{\"pick_first\":{}}]},\"failed\":{\"childPolicy\":[{\"round_robin\":{}}]}}}}]}";
const without_a = "{\"loadBalancingConfig\":[{\"xds_cluster_manager_experimental\":{\"children\":{\"b\":{\"childPolicy\":[{\"pick_first\":{}}]},\"failed\":{\"childPolicy\":[{\"round_robin\":{}}]}}}}]}";

fn unary(client: anytype, cluster: ?[]const u8) !grpc.UnaryResponse {
    return client.unary(.{ .path = "/fixture.Cluster/Unary", .authority = "localhost", .xds_cluster = cluster, .message = "request", .wait_for_ready = true, .timeout = .{ .value = 2, .unit = .second } });
}
fn blocked(sender: grpc.SharedChannelSender) !grpc.UnaryResponse {
    return sender.unary(.{ .path = "/fixture.Cluster/Unary", .authority = "localhost", .xds_cluster = "failed", .message = "request", .wait_for_ready = true, .timeout = .{ .value = 150, .unit = .millisecond } });
}
fn record(counts: *[3]usize, response: *grpc.UnaryResponse) !void {
    const value = response.message.?.payload;
    const index: usize = if (std.mem.eql(u8, value, "a1")) 0 else if (std.mem.eql(u8, value, "a2")) 1 else if (std.mem.eql(u8, value, "b")) 2 else return error.UnexpectedBackend;
    counts[index] += 1;
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 6) return error.InvalidArgument;
    const is_shared = std.mem.eql(u8, args[1], "shared");
    var backend = try netz.runtime.Backend.initZio(allocator);
    defer backend.deinit();
    const io = backend.io();
    var endpoints: [4]grpc.ChannelEndpoint = undefined;
    for (&endpoints, args[2..], 0..) |*endpoint, port, index| endpoint.* = .{ .cleartext_ip = .{
        .address = .{ .ip4 = .loopback(try std.fmt.parseInt(u16, port, 10)) },
        .hierarchical_path = if (index < 2) &.{"a"} else if (index == 2) &.{"b"} else &.{"failed"},
    } };
    var config = try grpc.ServiceConfig.parse(allocator, json);
    defer config.deinit();
    var ordinary = if (!is_shared) try grpc.Channel.initWithServiceConfig(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{}, &config) else null;
    defer if (ordinary) |*client| client.deinit();
    var shared = if (is_shared) try grpc.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .service_config_json = json }) else null;
    defer if (shared) |*client| client.deinit();
    var sender = if (shared) |client| client.sender() else null;
    defer if (sender) |*value| value.deinit();
    if (shared) |client| {
        client.connect();
        for (0..3) |index| {
            var watch = client.watchEndpointConnectivity(index).?;
            defer watch.deinit();
            while (watch.snapshot().state != .ready) _ = try watch.nextWithTimeout(.fromSeconds(3));
        }
    }
    for ([_]?[]const u8{ null, "missing" }) |cluster| {
        if (sender) |value| try std.testing.expectError(error.UnknownCluster, unary(value, cluster)) else try std.testing.expectError(error.UnknownCluster, unary(&ordinary.?, cluster));
    }
    var counts = [_]usize{ 0, 0, 0 };
    for (0..40) |index| {
        var response = if (sender) |value| try unary(value, "a") else try unary(&ordinary.?, "a");
        defer response.deinit();
        try record(&counts, &response);
        if (index % 2 == 0) {
            var b_response = if (sender) |value| try unary(value, "b") else try unary(&ordinary.?, "b");
            defer b_response.deinit();
            try std.testing.expectEqualStrings("b", b_response.message.?.payload);
            try record(&counts, &b_response);
        }
    }
    try std.testing.expectEqual(@as(usize, 20), counts[0]);
    try std.testing.expectEqual(@as(usize, 20), counts[1]);
    const stream_options: grpc.StreamingRequestOptions = .{ .path = "/fixture.Cluster/Duplex", .authority = "localhost", .xds_cluster = "b", .timeout = .{ .value = 2, .unit = .second }, .wait_for_ready = true };
    if (sender) |value| {
        var duplex = try value.startDuplex(stream_options);
        defer duplex.deinit();
        var writer = duplex.writer();
        defer writer.deinit();
        var reader = duplex.reader();
        defer reader.deinit();
        try writer.writeFinalMessage("request");
        var seen: usize = 0;
        while (true) {
            var event = try reader.nextWithTimeout(.fromSeconds(2));
            defer event.deinit(allocator);
            switch (event) {
                .message => |message| {
                    try std.testing.expectEqualStrings("b", message.payload);
                    seen += 1;
                },
                .terminal => |terminal| {
                    try std.testing.expectEqual(grpc.Status.ok, terminal.status);
                    try std.testing.expectEqual(@as(usize, 1), seen);
                    break;
                },
                else => {},
            }
        }
        counts[2] += 1;
        var pending = try io.concurrent(blocked, .{value});
        defer _ = pending.cancel(io) catch {};
        // Wait for the actual failed child call to reach the shared queue.
        const until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
        while (true) {
            shared.?.state.mutex.lockUncancelable(io);
            const queued = shared.?.state.head != null;
            shared.?.state.mutex.unlock(io);
            if (queued) break;
            if (until.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
            try std.Io.sleep(io, .fromMilliseconds(1), .awake);
        }
        var healthy = try unary(value, "b");
        defer healthy.deinit();
        try record(&counts, &healthy);
        try std.testing.expectError(error.Timeout, pending.await(io));
        try std.testing.expectError(error.ConnectionUnavailable, value.unary(.{ .path = "/fixture.Cluster/Unary", .message = "request", .xds_cluster = "failed", .wait_for_ready = false, .timeout = .{ .value = 1, .unit = .second } }));
        _ = try shared.?.updateWithTimeout(.{ .service_config = .{ .replace = without_a } }, .fromSeconds(2));
        try std.testing.expectError(error.UnknownCluster, unary(value, "a"));
        var surviving = try unary(value, "b");
        defer surviving.deinit();
        try record(&counts, &surviving);
        _ = try shared.?.updateWithTimeout(.{ .service_config = .{ .replace = json } }, .fromSeconds(2));
        var restored = try unary(value, "a");
        defer restored.deinit();
        try record(&counts, &restored);
    } else {
        var duplex = try ordinary.?.startDuplex(stream_options);
        defer duplex.deinit();
        try std.testing.expectEqual(grpc.DuplexWriteResult.complete, try duplex.writeFinalMessage("request"));
        const Consumer = struct {
            count: usize = 0,
            fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
                try std.testing.expectEqualStrings("b", message.payload);
                self.count += 1;
            }
        };
        var consumer: Consumer = .{};
        while (true) {
            var event = try duplex.readResponseEventWithTimeout(.fromSeconds(2), &consumer, Consumer.consume);
            defer event.deinit(allocator);
            if (event == .terminal) {
                try std.testing.expectEqual(grpc.Status.ok, event.terminal.status);
                try std.testing.expectEqual(@as(usize, 1), consumer.count);
                break;
            }
        }
        counts[2] += 1;
    }
    std.debug.print("CLUSTER_RESULT {{\"mode\":\"{s}\",\"counts\":[{d},{d},{d}],\"unknown_cluster\":true,\"duplex\":true,\"queue_isolation\":{s},\"removed_restored\":{s}}}\n", .{ args[1], counts[0], counts[1], counts[2], if (is_shared) "true" else "false", if (is_shared) "true" else "false" });
}
