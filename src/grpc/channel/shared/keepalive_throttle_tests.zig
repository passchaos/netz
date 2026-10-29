const std = @import("std");
const channel = @import("../../channel.zig");
const http2 = @import("../../../http2/mod.zig");
const shared = @import("../shared.zig");

const allocator = std.testing.allocator;

fn waitForThrottle(client: shared.SharedChannel) !shared.KeepAliveStats {
    const deadline = std.Io.Clock.Timestamp.fromNow(client.state.io, .{
        .raw = .fromSeconds(3),
        .clock = .awake,
    });
    while (true) {
        const stats = client.keepAliveStats();
        if (stats.throttles == 1 and stats.acknowledgements >= 1) return stats;
        if (deadline.durationFromNow(client.state.io).raw.nanoseconds <= 0) {
            return error.Timeout;
        }
        try std.Io.sleep(client.state.io, .fromMilliseconds(1), .awake);
    }
}

test "gRPC shared duplicate keepalive throttle proposals apply once" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel_owner = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } },
        .{ .keepalive = .{ .interval = .fromMilliseconds(100) } },
    );
    defer channel_owner.deinit();
    try std.testing.expect(channel_owner.state.applyKeepAliveThrottle(
        .fromMilliseconds(100),
    ));
    try std.testing.expect(!channel_owner.state.applyKeepAliveThrottle(
        .fromMilliseconds(100),
    ));
    try std.testing.expectEqual(
        std.Io.Duration.fromMilliseconds(200),
        channel_owner.keepAliveInterval().?,
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        channel_owner.keepAliveStats().throttles,
    );
    try std.testing.expect(channel_owner.state.applyKeepAliveThrottle(
        .fromMilliseconds(200),
    ));
    try std.testing.expectEqual(
        std.Io.Duration.fromMilliseconds(400),
        channel_owner.keepAliveInterval().?,
    );
}

test "gRPC shared too_many_pings GOAWAY throttles every endpoint" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var rejecting = try http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer rejecting.deinit();
    var observing = try http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer observing.deinit();
    var goaway_sent: std.Io.Event = .unset;
    const Peer = struct {
        fn reject(server: *http2.runtime.Server, ready: *std.Io.Event) !void {
            var connection = try server.acceptWithTimeout(.fromSeconds(2));
            defer connection.close();
            try connection.sendGoAway(
                0,
                .enhance_your_calm,
                "too_many_pings",
            );
            ready.set(connection.io);
        }

        fn observe(server: *http2.runtime.Server, ready: *std.Io.Event) !void {
            try ready.waitTimeout(server.io, .{ .duration = .{
                .raw = .fromSeconds(2),
                .clock = .awake,
            } });
            var connection = try server.acceptWithTimeout(.fromSeconds(2));
            defer connection.close();
            const connected = std.Io.Clock.awake.now(connection.io);
            _ = try connection.readPingWithTimeout(.fromSeconds(2));
            const elapsed = connected.durationTo(
                std.Io.Clock.awake.now(connection.io),
            );
            // The original interval is 100 ms. Leave scheduling margin while
            // proving this sibling endpoint observed the doubled interval.
            try std.testing.expect(
                elapsed.nanoseconds >=
                    std.Io.Duration.fromMilliseconds(150).nanoseconds,
            );
        }
    };
    var reject_task = io.async(Peer.reject, .{ &rejecting, &goaway_sent });
    defer _ = reject_task.cancel(io) catch {};
    var observe_task = io.async(Peer.observe, .{ &observing, &goaway_sent });
    defer _ = observe_task.cancel(io) catch {};

    const endpoints = [_]channel.Endpoint{
        .{ .cleartext_ip = .{ .address = rejecting.address() } },
        .{ .cleartext_ip = .{ .address = observing.address() } },
    };
    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .resolved = .{
            .endpoints = &endpoints,
            .policy = .round_robin,
        } },
        .{
            .channel = .{ .backoff = .{
                .initial_backoff = .fromMilliseconds(1),
                .multiplier = 1,
                .jitter = 0,
                .max_backoff = .fromMilliseconds(1),
                .min_connect_timeout = .fromSeconds(1),
            } },
            .keepalive = .{
                .interval = .fromMilliseconds(100),
                .timeout = .fromSeconds(1),
                .permit_without_calls = true,
            },
        },
    );
    defer client.deinit();
    client.connect();
    const stats = try waitForThrottle(client);
    try std.testing.expectEqual(@as(u64, 1), stats.probes_sent);
    try std.testing.expectEqual(@as(u64, 0), stats.timeouts);
    try std.testing.expectEqual(
        std.Io.Duration.fromMilliseconds(200),
        client.keepAliveInterval().?,
    );
    try reject_task.await(io);
    try observe_task.await(io);
}
