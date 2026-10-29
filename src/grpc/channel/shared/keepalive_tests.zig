const std = @import("std");
const grpc = @import("../../mod.zig");
const shared = @import("../shared.zig");

const allocator = std.testing.allocator;

fn waitReady(client: shared.SharedChannel, timeout: std.Io.Duration) !void {
    var watch = client.watchConnectivity();
    defer watch.deinit();
    const deadline = std.Io.Clock.Timestamp.fromNow(client.state.io, .{
        .raw = timeout,
        .clock = .awake,
    });
    while ((try watch.nextWithDeadline(deadline)).state != .ready) {}
}

fn waitForAcknowledgements(
    client: shared.SharedChannel,
    minimum: u64,
) !shared.KeepAliveStats {
    const deadline = std.Io.Clock.Timestamp.fromNow(client.state.io, .{
        .raw = .fromSeconds(3),
        .clock = .awake,
    });
    while (true) {
        const stats = client.keepAliveStats();
        if (stats.acknowledgements >= minimum) return stats;
        if (deadline.durationFromNow(client.state.io).raw.nanoseconds <= 0) {
            return error.Timeout;
        }
        try std.Io.sleep(client.state.io, .fromMilliseconds(1), .awake);
    }
}

fn waitForTimeouts(
    client: shared.SharedChannel,
    minimum: u64,
) !shared.KeepAliveStats {
    const deadline = std.Io.Clock.Timestamp.fromNow(client.state.io, .{
        .raw = .fromSeconds(3),
        .clock = .awake,
    });
    while (true) {
        const stats = client.keepAliveStats();
        if (stats.timeouts >= minimum) return stats;
        if (deadline.durationFromNow(client.state.io).raw.nanoseconds <= 0) {
            return error.Timeout;
        }
        try std.Io.sleep(client.state.io, .fromMilliseconds(1), .awake);
    }
}

test "gRPC shared keepalive suppresses probes on an idle channel by default" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listenWithOptions(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_message_size = 4096, .keepalive_enforcement = null },
    );
    defer server.deinit();
    const Peer = struct {
        fn run(server_ptr: *grpc.runtime.Server) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(2));
            defer connection.deinit();
            try std.testing.expectError(
                error.Timeout,
                connection.connection.readPingWithTimeout(
                    .fromMilliseconds(80),
                ),
            );
        }
    };
    var peer = io.async(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};

    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .cleartext_ip = .{ .address = server.address() } },
        .{ .keepalive = .{
            .interval = .fromMilliseconds(10),
            .timeout = .fromMilliseconds(40),
        } },
    );
    defer client.deinit();
    client.connect();
    try waitReady(client, .fromSeconds(2));
    try peer.await(io);
    try std.testing.expectEqualDeep(
        shared.KeepAliveStats{
            .probes_sent = 0,
            .acknowledgements = 0,
            .timeouts = 0,
        },
        client.keepAliveStats(),
    );
}

test "gRPC shared keepalive ACK does not delay an active RPC deadline" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listenWithOptions(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_message_size = 4096, .keepalive_enforcement = null },
    );
    defer server.deinit();
    const Peer = struct {
        fn run(server_ptr: *grpc.runtime.Server) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(2));
            defer connection.deinit();
            var request = try connection.readUnaryWithTimeout(.fromSeconds(2));
            defer request.deinit();
            const payload = try connection.connection.readPingWithTimeout(
                .fromSeconds(2),
            );
            try std.testing.expectEqualSlices(
                u8,
                "NZGK",
                payload[0..4],
            );
            var reset = try connection.connection.readResetStreamWithTimeout(
                .fromSeconds(2),
            );
            defer reset.deinit(allocator);
            try std.testing.expectEqual(request.request.stream_id, reset.reset.stream_id);
        }
    };
    var peer = io.async(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};

    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .cleartext_ip = .{ .address = server.address() } },
        .{ .keepalive = .{
            .interval = .fromMilliseconds(10),
            .timeout = .fromSeconds(1),
        } },
    );
    defer client.deinit();
    var sender = client.sender();
    defer sender.deinit();

    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectError(
        error.Timeout,
        sender.unary(.{
            .path = "/demo.KeepAlive/Silent",
            .message = "request",
            .timeout = .{ .value = 80, .unit = .millisecond },
            .wait_for_ready = true,
        }),
    );
    try std.testing.expect(
        started.durationTo(std.Io.Clock.awake.now(io)).nanoseconds <
            std.Io.Duration.fromMilliseconds(500).nanoseconds,
    );
    try peer.await(io);
    const stats = try waitForAcknowledgements(client, 1);
    try std.testing.expect(stats.probes_sent >= 1);
    try std.testing.expectEqual(@as(u64, 0), stats.timeouts);
}

test "gRPC shared keepalive timeout retires and reconnects the endpoint" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listenWithOptions(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_message_size = 4096, .keepalive_enforcement = null },
    );
    defer server.deinit();
    const Peer = struct {
        fn run(server_ptr: *grpc.runtime.Server) !void {
            {
                var silent = try server_ptr.acceptWithTimeout(.fromSeconds(2));
                defer silent.deinit();
                try std.Io.sleep(
                    silent.connection.io,
                    .fromMilliseconds(120),
                    .awake,
                );
            }
            var healthy = try server_ptr.acceptWithTimeout(.fromSeconds(2));
            defer healthy.deinit();
            var request = try healthy.readUnaryWithTimeout(.fromSeconds(2));
            defer request.deinit();
            try healthy.writeUnary(request.request.stream_id, .{
                .message = "reconnected",
            });
        }
    };
    var peer = io.async(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};

    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .cleartext_ip = .{ .address = server.address() } },
        .{
            .channel = .{ .backoff = .{
                .initial_backoff = .fromMilliseconds(1),
                .multiplier = 1,
                .jitter = 0,
                .max_backoff = .fromMilliseconds(1),
                .min_connect_timeout = .fromSeconds(1),
            } },
            .keepalive = .{
                .interval = .fromMilliseconds(10),
                .timeout = .fromMilliseconds(30),
                .permit_without_calls = true,
            },
        },
    );
    defer client.deinit();
    client.connect();
    try waitReady(client, .fromSeconds(2));
    const timed_out = try waitForTimeouts(client, 1);
    try std.testing.expect(timed_out.probes_sent >= 1);

    var sender = client.sender();
    defer sender.deinit();
    var response = try sender.unary(.{
        .path = "/demo.KeepAlive/Unary",
        .message = "request",
        .timeout = .{ .value = 3, .unit = .second },
        .wait_for_ready = true,
    });
    defer response.deinit();
    try std.testing.expectEqualStrings("reconnected", response.message.?.payload);
    try peer.await(io);
}
