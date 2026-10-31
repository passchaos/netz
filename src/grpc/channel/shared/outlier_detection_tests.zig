const std = @import("std");
const grpc = @import("../../mod.zig");
const connectivity = @import("../connectivity.zig");
const shared = @import("../shared.zig");

const allocator = std.testing.allocator;

test "gRPC SharedChannel outlier detection ejects and restores a failing endpoint" {
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
    var b_task = io.async(Server.run, .{ &b_server, "b", false, 3 });
    defer _ = b_task.cancel(io) catch {};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = a_server.address() } },
        .{ .cleartext_ip = .{ .address = b_server.address() } },
    };
    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .resolved = .{
            .policy = .round_robin,
            .endpoints = &endpoints,
        } },
        .{ .service_config_json =
        \\{"loadBalancingConfig":[{"outlier_detection_experimental":{
        \\ "interval":"0.05s","baseEjectionTime":"0.1s",
        \\ "maxEjectionTime":"0.1s","maxEjectionPercent":50,
        \\ "failurePercentageEjection":{"threshold":0,
        \\  "enforcementPercentage":100,"minimumHosts":1,
        \\  "requestVolume":1},
        \\ "childPolicy":[{"round_robin":{}}]}}]}
        },
    );
    defer client.deinit();
    var a_watch = client.watchEndpointConnectivity(0).?;
    defer a_watch.deinit();
    var b_watch = client.watchEndpointConnectivity(1).?;
    defer b_watch.deinit();
    try client.connectWithTimeout(.fromSeconds(3));
    try waitForState(&a_watch, .ready);
    try waitForState(&b_watch, .ready);

    var sender = client.sender();
    defer sender.deinit();
    var first = try call(sender);
    defer first.deinit();
    try std.testing.expectEqual(grpc.Status.unavailable, first.status);
    var second = try call(sender);
    defer second.deinit();
    try expectBackend(&second, "b");

    try waitForState(&a_watch, .transient_failure);
    for (0..2) |_| {
        var response = try call(sender);
        defer response.deinit();
        try expectBackend(&response, "b");
    }
    try waitForState(&a_watch, .ready);
    var restored = try call(sender);
    defer restored.deinit();
    try expectBackend(&restored, "a");

    try a_task.await(io);
    try b_task.await(io);
}

test "gRPC SharedChannel outlier detection counts streaming terminal status" {
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
    const Peer = struct {
        fn run(listener: *grpc.runtime.Server) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var stream = try connection.acceptDuplexWithTimeout(
                .fromSeconds(3),
            );
            defer stream.deinit();
            try Server.consumeRequest(&stream);
            try stream.finish(.unavailable, "stream-eject", &.{}, &.{});
        }
    };
    var peer = io.async(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};
    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .cleartext_ip = .{ .address = server.address() } },
        .{ .service_config_json =
        \\{"loadBalancingConfig":[{"outlier_detection_experimental":{
        \\ "interval":"0.05s","baseEjectionTime":"1s",
        \\ "maxEjectionPercent":100,
        \\ "failurePercentageEjection":{"threshold":0,
        \\  "enforcementPercentage":100,"minimumHosts":1,
        \\  "requestVolume":1},
        \\ "childPolicy":[{"pick_first":{}}]}}]}
        },
    );
    defer client.deinit();
    var watch = client.watchEndpointConnectivity(0).?;
    defer watch.deinit();
    try client.connectWithTimeout(.fromSeconds(3));
    try waitForState(&watch, .ready);
    var sender = client.sender();
    defer sender.deinit();
    var rpc = try sender.startDuplex(.{
        .path = "/demo.Outlier/Stream",
        .authority = "localhost",
        .wait_for_ready = true,
        .timeout = try grpc.Timeout.init(3, .second),
    });
    defer rpc.deinit();
    var writer = rpc.writer();
    defer writer.deinit();
    var reader = rpc.reader();
    defer reader.deinit();
    try writer.writeFinalMessage("request");
    while (true) {
        var event = try reader.nextWithTimeout(.fromSeconds(3));
        defer event.deinit(allocator);
        if (event == .terminal) {
            try std.testing.expectEqual(
                grpc.Status.unavailable,
                event.terminal.status,
            );
            break;
        }
    }
    try waitForState(&watch, .transient_failure);
    try peer.await(io);
}

fn call(sender: shared.Sender) !grpc.UnaryResponse {
    return sender.unary(.{
        .path = "/demo.Outlier/Unary",
        .authority = "localhost",
        .message = "request",
        .wait_for_ready = true,
        .timeout = try grpc.Timeout.init(3, .second),
    });
}

fn expectBackend(response: *const grpc.UnaryResponse, expected: []const u8) !void {
    try std.testing.expectEqual(grpc.Status.ok, response.status);
    try std.testing.expectEqualStrings(expected, response.message.?.payload);
}

fn waitForState(
    watch: *connectivity.Watch,
    expected: connectivity.State,
) !void {
    const deadline = std.Io.Clock.Timestamp.fromNow(
        watch.tracker.io,
        .{ .raw = .fromSeconds(3), .clock = .awake },
    );
    while (watch.snapshot().state != expected) {
        const snapshot = try watch.nextWithDeadline(deadline);
        if (snapshot.state == expected) return;
    }
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
                if (fail_first and index == 0) {
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

    pub fn consumeRequest(stream: *grpc.ServerDuplex) !void {
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
