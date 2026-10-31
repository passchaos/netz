const std = @import("std");
const grpc = @import("../mod.zig");
const channel = @import("../channel.zig");

const allocator = std.testing.allocator;
const config_json =
    \\{"loadBalancingConfig":[{"outlier_detection_experimental":{
    \\ "interval":"0.05s","baseEjectionTime":"0.1s",
    \\ "maxEjectionTime":"0.1s","maxEjectionPercent":50,
    \\ "failurePercentageEjection":{"threshold":0,
    \\  "enforcementPercentage":100,"minimumHosts":1,
    \\  "requestVolume":1},
    \\ "childPolicy":[{"round_robin":{}}]}}]}
;

test "gRPC ordinary Channel outlier detection ejects and restores endpoint" {
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
    var a_task = io.async(Server.run, .{ &a_server, "a", true, 2 });
    defer _ = a_task.cancel(io) catch {};
    var b_task = io.async(Server.run, .{ &b_server, "b", false, 2 });
    defer _ = b_task.cancel(io) catch {};
    var config = try grpc.ServiceConfig.parse(allocator, config_json);
    defer config.deinit();
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = a_server.address() } },
        .{ .cleartext_ip = .{ .address = b_server.address() } },
    };
    var client = try channel.Channel.initWithServiceConfig(
        allocator,
        io,
        .{ .resolved = .{
            .policy = .round_robin,
            .endpoints = &endpoints,
        } },
        .{},
        &config,
    );
    defer client.deinit();

    var first = try unary(&client, &config, true);
    defer first.deinit();
    try std.testing.expectEqual(grpc.Status.unavailable, first.status);
    try std.Io.sleep(io, .fromMilliseconds(70), .awake);
    for (0..2) |_| {
        var response = try unary(&client, &config, true);
        defer response.deinit();
        try expectBackend(&response, "b");
    }
    try std.Io.sleep(io, .fromMilliseconds(120), .awake);
    var restored = try unary(&client, &config, true);
    defer restored.deinit();
    try expectBackend(&restored, "a");
    try a_task.await(io);
    try b_task.await(io);
}

test "gRPC ordinary Channel observes sequential and duplex streaming completion" {
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
    var peer = io.async(Server.run, .{ &server, "unused", true, 2 });
    defer _ = peer.cancel(io) catch {};
    var config = try grpc.ServiceConfig.parse(allocator,
        \\{"loadBalancingConfig":[{"outlier_detection_experimental":{
        \\ "interval":"0.03s","baseEjectionTime":"0.04s",
        \\ "maxEjectionPercent":100,
        \\ "failurePercentageEjection":{"threshold":0,
        \\  "enforcementPercentage":100,"minimumHosts":1,
        \\  "requestVolume":1},
        \\ "childPolicy":[{"pick_first":{}}]}}]}
    );
    defer config.deinit();
    var client = try channel.Channel.initWithServiceConfig(
        allocator,
        io,
        .{ .cleartext_ip = .{ .address = server.address() } },
        .{},
        &config,
    );
    defer client.deinit();

    var writer = try client.startStreamingWithServiceConfig(.{
        .path = "/demo.Outlier/Sequential",
        .authority = "localhost",
        .timeout = try grpc.Timeout.init(3, .second),
    }, &config);
    defer writer.deinit();
    try writer.writeMessage("request");
    const Consumer = struct {
        fn consume(_: *@This(), _: grpc.StreamingMessage) !void {
            return error.UnexpectedMessage;
        }
    };
    var consumer: Consumer = .{};
    var sequential = try writer.finishAndRead(&consumer, Consumer.consume);
    defer sequential.deinit();
    try std.testing.expectEqual(grpc.Status.unavailable, sequential.status);
    try std.Io.sleep(io, .fromMilliseconds(40), .awake);
    try std.testing.expectError(
        error.ConnectionUnavailable,
        unary(&client, &config, false),
    );
    try std.testing.expectEqual(
        grpc.ChannelConnectivityState.transient_failure,
        client.connectivityState(),
    );

    try std.Io.sleep(io, .fromMilliseconds(50), .awake);
    var stream = try client.startDuplexWithServiceConfig(.{
        .path = "/demo.Outlier/Duplex",
        .authority = "localhost",
        .timeout = try grpc.Timeout.init(3, .second),
    }, &config);
    defer stream.deinit();
    try std.testing.expectEqual(
        grpc.DuplexWriteResult.complete,
        try stream.writeFinalMessage("request"),
    );
    while (true) {
        var event = try stream.readResponseEventWithTimeout(
            .fromSeconds(3),
            &consumer,
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
    try std.Io.sleep(io, .fromMilliseconds(40), .awake);
    try std.testing.expectError(
        error.ConnectionUnavailable,
        unary(&client, &config, false),
    );
    try std.testing.expectEqual(
        grpc.ChannelConnectivityState.transient_failure,
        client.connectivityState(),
    );
    try peer.await(io);
}

fn unary(
    client: *channel.Channel,
    config: *grpc.ServiceConfig,
    wait_for_ready: bool,
) !grpc.UnaryResponse {
    return client.unaryWithServiceConfig(.{
        .path = "/demo.Outlier/Unary",
        .authority = "localhost",
        .message = "request",
        .wait_for_ready = wait_for_ready,
        .timeout = try grpc.Timeout.init(3, .second),
    }, config);
}

fn expectBackend(response: *const grpc.UnaryResponse, expected: []const u8) !void {
    try std.testing.expectEqual(grpc.Status.ok, response.status);
    try std.testing.expectEqualStrings(expected, response.message.?.payload);
}

const Server = struct {
    fn run(
        listener: *grpc.runtime.Server,
        label: []const u8,
        fail_first: bool,
        count: usize,
    ) !void {
        var connection = try listener.acceptWithTimeout(.fromSeconds(3));
        defer connection.deinit();
        for (0..count) |index| {
            {
                var stream = try connection.acceptDuplexWithTimeout(
                    .fromSeconds(3),
                );
                defer stream.deinit();
                try consumeRequest(&stream);
                if (fail_first and index == 0 or
                    std.mem.eql(u8, label, "unused"))
                {
                    try stream.finish(.unavailable, "eject", &.{}, &.{});
                    continue;
                }
                try stream.startResponse(.{});
                try std.testing.expect(
                    try stream.writeMessage(label) == .complete,
                );
                try stream.finishOk();
            }
        }
    }

    fn consumeRequest(stream: *grpc.ServerDuplex) !void {
        var seen = false;
        const Consumer = struct {
            seen: *bool,
            fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
                try std.testing.expect(!self.seen.*);
                try std.testing.expectEqualStrings("request", message.payload);
                self.seen.* = true;
            }
        };
        var consumer = Consumer{ .seen = &seen };
        while (true) {
            var event = try stream.readRequestEventWithTimeout(
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
        try std.testing.expect(seen);
    }
};
