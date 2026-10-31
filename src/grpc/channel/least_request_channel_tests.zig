const std = @import("std");
const grpc = @import("../mod.zig");
const channel = @import("../channel.zig");
const connectivity = @import("connectivity.zig");
const shared = @import("shared.zig");

test "gRPC channels adopt least request service config" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } },
        .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } },
        .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(2) } } },
    };
    var config = try grpc.ServiceConfig.parse(allocator,
        \\{"loadBalancingConfig":[{"least_request_experimental":
        \\ {"choiceCount":6}}]}
    );
    defer config.deinit();
    var ordinary = try channel.Channel.initWithServiceConfig(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &endpoints } },
        .{},
        &config,
    );
    defer ordinary.deinit();
    try std.testing.expectEqual(
        grpc.ChannelSelectionPolicy.least_request,
        ordinary.selectionPolicy(),
    );

    var background = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &endpoints } },
        .{ .service_config_json =
        \\{"loadBalancingConfig":[{"least_request_experimental":
        \\ {"choiceCount":6}}]}
        },
    );
    defer background.deinit();
    try std.testing.expectEqual(
        grpc.ChannelSelectionPolicy.least_request,
        background.selectionPolicy(),
    );
    try std.testing.expectEqual(@as(usize, 2), background.endpointCount());
}

test "gRPC least request shifts concurrent RPCs away from a loaded endpoint" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var slow_server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer slow_server.deinit();
    var fast_server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer fast_server.deinit();
    var stop: std.Io.Event = .unset;
    var slow_peer = io.async(Peer.run, .{
        &slow_server,
        &stop,
        "slow",
        @as(?std.Io.Duration, .fromMilliseconds(20)),
    });
    defer _ = slow_peer.cancel(io) catch {};
    var fast_peer = io.async(Peer.run, .{
        &fast_server,
        &stop,
        "fast",
        @as(?std.Io.Duration, null),
    });
    defer _ = fast_peer.cancel(io) catch {};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = slow_server.address() } },
        .{ .cleartext_ip = .{ .address = fast_server.address() } },
    };
    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &endpoints } },
        .{
            .max_active_calls_per_endpoint = 32,
            .service_config_json =
            \\{"loadBalancingConfig":[{"least_request_experimental":
            \\ {"choiceCount":10}}]}
            ,
        },
    );
    var client_live = true;
    defer if (client_live) client.deinit();
    var slow_watch = client.watchEndpointConnectivity(0).?;
    defer slow_watch.deinit();
    var fast_watch = client.watchEndpointConnectivity(1).?;
    defer fast_watch.deinit();
    try client.connectWithTimeout(.fromSeconds(3));
    try waitForState(&slow_watch, .ready);
    try waitForState(&fast_watch, .ready);

    // Two rolling callers are enough to keep one slow RPC outstanding while
    // the other caller repeatedly completes on the idle endpoint. Keeping at
    // most one accepted RPC per endpoint also respects ServerConnection's
    // single-owner application read contract.
    const runner_count = 2;
    const calls_per_runner = 100;
    var counts = [_]std.atomic.Value(usize){
        .init(0),
        .init(0),
    };
    var runners: [runner_count]std.Io.Future(Caller.Result) = undefined;
    var started: usize = 0;
    defer for (runners[0..started]) |*runner| {
        _ = runner.cancel(io) catch {};
    };
    for (&runners) |*runner| {
        runner.* = try io.concurrent(Caller.run, .{
            client.sender(),
            calls_per_runner,
            &counts,
        });
        started += 1;
    }
    for (&runners, 0..) |*runner, index| {
        runner.await(io) catch |err| {
            std.debug.print(
                "least-request runner {d} failed: {s}; slow={d} fast={d}\n",
                .{
                    index,
                    @errorName(err),
                    counts[0].load(.acquire),
                    counts[1].load(.acquire),
                },
            );
            return err;
        };
    }
    started = 0;

    const slow = counts[0].load(.acquire);
    const fast = counts[1].load(.acquire);
    try std.testing.expectEqual(
        @as(usize, runner_count * calls_per_runner),
        slow + fast,
    );
    try std.testing.expect(fast > slow * 2);

    stop.set(io);
    client.deinit();
    client_live = false;
    try slow_peer.await(io);
    try fast_peer.await(io);
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

const Caller = struct {
    const Result = anyerror!void;

    fn run(
        sender: shared.Sender,
        count: usize,
        results: *[2]std.atomic.Value(usize),
    ) Result {
        var owned = sender;
        defer owned.deinit();
        for (0..count) |_| {
            var response = owned.unary(.{
                .path = "/demo.LeastRequest/Unary",
                .authority = "localhost",
                .message = "request",
                .wait_for_ready = true,
                .timeout = try grpc.Timeout.init(10, .second),
            }) catch |err| {
                std.debug.print("least-request RPC failed: {s}\n", .{
                    @errorName(err),
                });
                return err;
            };
            defer response.deinit();
            try std.testing.expectEqual(grpc.Status.ok, response.status);
            const payload = response.message.?.payload;
            const index: usize = if (std.mem.eql(u8, payload, "slow"))
                0
            else if (std.mem.eql(u8, payload, "fast"))
                1
            else
                return error.UnexpectedBackend;
            _ = results[index].fetchAdd(1, .release);
        }
    }
};

const Peer = struct {
    fn run(
        listener: *grpc.runtime.Server,
        stop: *std.Io.Event,
        label: []const u8,
        delay: ?std.Io.Duration,
    ) !void {
        var connection = try listener.acceptWithTimeout(.fromSeconds(3));
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
                else => {
                    std.debug.print("least-request {s} peer read failed: {s}\n", .{
                        label,
                        @errorName(err),
                    });
                    return err;
                },
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
            if (delay) |duration| try std.Io.sleep(ioFor(&connection), duration, .awake);
            try request.startResponse(.{});
            if (try request.writeMessage(label) != .complete) {
                return error.UnexpectedFlowControl;
            }
            try request.finishOk();
        }
    }

    fn ioFor(connection: *grpc.runtime.ServerConnection) std.Io {
        return connection.connection.io;
    }
};
