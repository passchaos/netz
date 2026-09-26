const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");
const source_peer = @import("source_peer.zig");
const target_peer = @import("target_peer.zig");

const mqtt = netz.mqtt;
const outbound = mqtt.bridge.outbound;
const runtime = mqtt.runtime;

pub fn runSequence(input: []const u8) !model.Summary {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var source_server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    var target_server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    var servers_open = true;
    defer if (servers_open) {
        target_server.deinit();
        source_server.deinit();
    };

    const sequence = input[0..@min(input.len, model.max_operations)];
    var signals = model.Signals{};
    var source = source_peer.State{
        .server = &source_server,
        .allocator = allocator,
        .io = io,
        .input = sequence,
        .signals = &signals,
    };
    var target = target_peer.State{
        .server = &target_server,
        .allocator = allocator,
        .io = io,
        .input = sequence,
        .signals = &signals,
    };
    const source_thread = try std.Thread.spawn(
        .{},
        source_peer.State.run,
        .{&source},
    );
    const target_thread = std.Thread.spawn(
        .{},
        target_peer.State.run,
        .{&target},
    ) catch |err| {
        source_server.deinit();
        target_server.deinit();
        servers_open = false;
        source_thread.join();
        return err;
    };
    var joined = false;

    var shutdown: std.Io.Event = .unset;
    const session_expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 60,
    } }};
    var bridge: ?outbound.Bridge = outbound.Bridge.initMany(
        allocator,
        io,
        source_server.address(),
        target_server.address(),
        .{
            .source_connect = .{
                .protocol = .v5,
                .client_id = "fuzz-outbound-source",
                .clean_start = false,
                .connect_timeout = model.packet_timeout,
                .properties = &session_expiry,
            },
            .target_connect = .{
                .protocol = .v5,
                .client_id = "fuzz-outbound-target",
                .clean_start = false,
                .connect_timeout = model.packet_timeout,
                .properties = &session_expiry,
            },
            .source_reconnect_policy = .{
                .initial_delay = .fromMilliseconds(1),
                .max_delay = .fromMilliseconds(1),
                .max_attempts = 1,
            },
            .target_reconnect_policy = .{
                .initial_delay = .fromMilliseconds(1),
                .max_delay = .fromMilliseconds(1),
                .max_attempts = 1,
            },
            .rules = &.{
                .{
                    .filter = model.bridge_filters[0],
                    .qos = .at_least_once,
                    .local_prefix = "local/",
                    .remote_prefix = "remote/",
                },
                .{
                    .filter = model.bridge_filters[1],
                    .qos = .at_least_once,
                    .local_prefix = "local/",
                    .remote_prefix = "remote/",
                },
            },
        },
        &shutdown,
    ) catch |err| {
        source_server.deinit();
        target_server.deinit();
        servers_open = false;
        source_thread.join();
        target_thread.join();
        return err;
    };
    defer if (bridge) |*value| value.deinit();
    defer if (!joined) {
        if (bridge) |*value| {
            value.deinit();
            bridge = null;
        }
        target_server.deinit();
        source_server.deinit();
        servers_open = false;
        source_thread.join();
        target_thread.join();
    };

    const connected = try bridge.?.connect();
    try std.testing.expect(!connected.source_session_present);
    try std.testing.expect(!connected.target_session_present);

    for (sequence, 0..) |_, index| {
        var attempts: usize = 0;
        while (signals.source_completed.load(.acquire) < index + 1 or
            signals.target_completed.load(.acquire) < index + 1)
        {
            if (source.err) |err| return err;
            if (target.err) |err| return err;
            if (attempts == 64) return error.BridgeProgressLimitExceeded;
            _ = try bridge.?.step(.{
                .timeout = model.packet_timeout,
                .cancellation_check_interval = .fromMilliseconds(5),
            });
            attempts += 1;
        }
    }

    try bridge.?.disconnect(0);
    source_thread.join();
    target_thread.join();
    joined = true;
    if (source.err) |err| return err;
    if (target.err) |err| return err;

    var summary = target.summary;
    summary.source_resumed = source.summary.source_resumed;
    summary.source_fresh = source.summary.source_fresh;
    summary.source_subscription_replays = source.summary
        .source_subscription_replays;
    return summary;
}
