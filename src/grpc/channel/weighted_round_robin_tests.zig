const std = @import("std");
const grpc = @import("../mod.zig");
const channel = @import("../channel.zig");
const http2 = @import("../../http2/mod.zig");

test "gRPC Channel weighted round robin follows per-RPC ORCA weights" {
    const weighted_calls = 200;
    const fallback_calls = 40;
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var a_listener = try http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer a_listener.deinit();
    var b_listener = try http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer b_listener.deinit();
    var reporting: std.atomic.Value(bool) = .init(true);
    var a_task = io.async(Server.run, .{
        &a_listener,
        "a",
        1.0,
        &reporting,
    });
    defer _ = a_task.cancel(io) catch {};
    var b_task = io.async(Server.run, .{
        &b_listener,
        "b",
        3.0,
        &reporting,
    });
    defer _ = b_task.cancel(io) catch {};
    const endpoints = [_]channel.Endpoint{
        .{ .cleartext_ip = .{ .address = a_listener.address() } },
        .{ .cleartext_ip = .{ .address = b_listener.address() } },
    };
    var config = try grpc.ServiceConfig.parse(allocator,
        \\{"loadBalancingConfig":[{"weighted_round_robin":{
        \\ "enableOobLoadReport":false,"blackoutPeriod":"0s",
        \\ "weightUpdatePeriod":"0.1s","weightExpirationPeriod":"2s",
        \\ "metricNamesForComputingUtilization":["cpu_utilization"]}}]}
    );
    var client = try channel.Channel.initWithServiceConfig(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &endpoints } },
        .{},
        &config,
    );
    // Channel retains custom metric names instead of borrowing the parsed
    // service-config arena for later per-RPC reports.
    config.deinit();
    var client_live = true;
    defer if (client_live) client.deinit();
    try std.testing.expectEqual(
        @as(usize, 2),
        try client.warmWithTimeout(.fromSeconds(2)),
    );

    var learned = [_]bool{ false, false };
    for (0..20) |_| {
        var response = try call(&client);
        defer response.deinit();
        learned[try backendIndex(&response)] = true;
        if (learned[0] and learned[1]) break;
    }
    try std.testing.expect(learned[0] and learned[1]);
    try std.Io.sleep(io, .fromMilliseconds(120), .awake);

    var counts = [_]usize{ 0, 0 };
    for (0..weighted_calls) |_| {
        var response = try call(&client);
        defer response.deinit();
        counts[try backendIndex(&response)] += 1;
    }
    try std.testing.expect(counts[1] > counts[0] * 2);
    try std.testing.expect(counts[1] < counts[0] * 4);

    reporting.store(false, .release);
    try std.Io.sleep(io, .fromMilliseconds(2100), .awake);
    var fallback = [_]usize{ 0, 0 };
    for (0..fallback_calls) |_| {
        var response = try call(&client);
        defer response.deinit();
        fallback[try backendIndex(&response)] += 1;
    }
    try std.testing.expectEqual(fallback[0], fallback[1]);

    client.deinit();
    client_live = false;
    try a_task.await(io);
    try b_task.await(io);
}

test "gRPC Channel weighted round robin config ownership is transactional" {
    var config = try grpc.ServiceConfig.parse(std.testing.allocator,
        \\{"loadBalancingConfig":[{"weighted_round_robin":{
        \\ "metricNamesForComputingUtilization":["named_metrics.queue"]}}]}
    );
    defer config.deinit();
    const Harness = struct {
        fn run(
            allocator: std.mem.Allocator,
            source: *const grpc.ServiceConfig,
        ) !void {
            const endpoints = [_]channel.Endpoint{.{
                .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } },
            }};
            var client = try channel.Channel.initWithServiceConfig(
                allocator,
                undefined,
                .{ .resolved = .{ .endpoints = &endpoints } },
                .{},
                source,
            );
            client.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        Harness.run,
        .{&config},
    );
}

test "gRPC Channel retry repicks a weighted round robin endpoint" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var a_listener = try http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer a_listener.deinit();
    var b_listener = try http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer b_listener.deinit();
    var a_peer = RetryPeer{ .listener = &a_listener, .status = .unavailable };
    var b_peer = RetryPeer{ .listener = &b_listener, .status = .ok };
    var a_task = io.async(RetryPeer.run, .{&a_peer});
    defer _ = a_task.cancel(io) catch {};
    var b_task = io.async(RetryPeer.run, .{&b_peer});
    defer _ = b_task.cancel(io) catch {};
    const endpoints = [_]channel.Endpoint{
        .{ .cleartext_ip = .{ .address = a_listener.address() } },
        .{ .cleartext_ip = .{ .address = b_listener.address() } },
    };
    var config = try grpc.ServiceConfig.parse(allocator,
        \\{"loadBalancingConfig":[{"weighted_round_robin":{}}],
        \\ "methodConfig":[{"name":[{"service":"demo.Wrr","method":"Unary"}],
        \\ "retryPolicy":{"maxAttempts":2,"initialBackoff":"0.001s",
        \\ "maxBackoff":"0.001s","backoffMultiplier":1,
        \\ "retryableStatusCodes":["UNAVAILABLE"]}}]}
    );
    defer config.deinit();
    var client = try channel.Channel.initWithServiceConfig(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &endpoints } },
        .{},
        &config,
    );
    var client_live = true;
    defer if (client_live) client.deinit();
    try std.testing.expectEqual(
        @as(usize, 2),
        try client.warmWithTimeout(.fromSeconds(2)),
    );
    var response = try client.unaryWithServiceConfig(.{
        .path = "/demo.Wrr/Unary",
        .message = "request",
        .timeout = try grpc.Timeout.init(5, .second),
    }, &config);
    defer response.deinit();
    try std.testing.expectEqualStrings("b", response.message.?.payload);
    try std.testing.expect(!a_peer.previous_attempt);
    try std.testing.expect(b_peer.previous_attempt);
    client.deinit();
    client_live = false;
    try a_task.await(io);
    try b_task.await(io);
}

fn call(client: *channel.Channel) !grpc.UnaryResponse {
    return client.unary(.{
        .path = "/demo.Wrr/Unary",
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

const RetryPeer = struct {
    listener: *http2.runtime.Server,
    status: grpc.Status,
    previous_attempt: bool = false,

    fn run(self: *@This()) !void {
        var connection = try self.listener.acceptWithTimeout(.fromSeconds(5));
        defer connection.close();
        var request = try connection.readRequestWithTimeout(.fromSeconds(5));
        defer request.deinit(self.listener.allocator);
        var parsed = try grpc.parseUnaryRequest(
            self.listener.allocator,
            &request,
            1024,
        );
        defer parsed.deinit();
        self.previous_attempt = if (grpc.call.headerValue(
            request.headers,
            "grpc-previous-rpc-attempts",
        )) |value| std.mem.eql(u8, value, "1") else false;
        try grpc.writeUnaryResponse(
            &connection,
            self.listener.allocator,
            request.stream_id,
            if (self.status == .ok) .{
                .message = "b",
            } else .{
                .status = self.status,
                .trailers_only = true,
            },
        );
    }
};
