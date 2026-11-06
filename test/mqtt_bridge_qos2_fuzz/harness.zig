const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");
const peer = @import("peer.zig");
const transport = @import("transport.zig");

const mqtt = netz.mqtt;
const bridge_mod = mqtt.bridge;
const Broker = mqtt.broker.Broker;
const runtime = mqtt.runtime;

const BrokerRunner = struct {
    broker: *Broker,
    input: []const u8,
    tls: bool,
    shutdown: std.Io.Event = .unset,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.broker.serveListenersUntil(&.{.{
            .source = self.broker.server.?.pendingSource(),
            .accept_concurrency = 2,
        }}, .{
            .shutdown = &self.shutdown,
            .error_observer = .{ .context = self, .observe = observeError },
        }) catch |err| {
            self.err = err;
        };
    }

    fn observeError(context: *anyopaque, event: mqtt.broker.ListenerErrorEvent) void {
        const self: *BrokerRunner = @ptrCast(@alignCast(context));
        std.debug.print(
            "MQTT bridge QoS2 local error: tls={} sequence={x} listener={} stage={s} error={s}\n",
            .{ self.tls, self.input, event.listener_index, @tagName(event.stage), @errorName(event.err) },
        );
    }

    fn stop(self: *@This(), io: std.Io, thread: std.Thread) ?anyerror {
        self.shutdown.set(io);
        thread.join();
        return self.err;
    }
};

pub fn runSequence(input: []const u8) !model.Summary {
    return runSequenceWithTransport(input, false);
}

pub fn runTlsSequence(input: []const u8) !model.Summary {
    return runSequenceWithTransport(input, true);
}

fn runSequenceWithTransport(
    input: []const u8,
    comptime tls: bool,
) anyerror!model.Summary {
    const sequence = input[0..@min(input.len, model.max_operations)];
    var phase: []const u8 = "local broker setup";
    var operation_index: usize = 0;
    var failure_reported = false;
    errdefer |err| if (!failure_reported) std.debug.print(
        "MQTT bridge QoS2 failure: tls={} sequence={x} operation={} phase={s} error={s}\n",
        .{ tls, sequence, operation_index, phase, @errorName(err) },
    );
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var local = try Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 2,
                .max_queued_deliveries_per_connection = model.max_operations,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{ .protocol = .v5 },
        },
    );
    defer local.deinit();
    try local.createCommitLog(tmp.dir, "bridge-qos2.log", .{});
    var local_runner = BrokerRunner{ .broker = &local, .input = sequence, .tls = tls };
    const local_thread = try std.Thread.spawn(
        .{},
        BrokerRunner.run,
        .{&local_runner},
    );
    var local_joined = false;
    defer if (!local_joined) {
        local_runner.shutdown.set(io);
        local_thread.join();
    };

    phase = "subscriber connect";
    var subscriber = try runtime.Client.connectWithTimeout(
        allocator,
        io,
        local.address(),
        .{
            .protocol = .v5,
            .client_id = "fuzz-qos2-subscriber",
            .topic_alias_maximum = 0,
        },
        model.packet_timeout,
    );
    defer subscriber.close();
    phase = "subscriber subscribe";
    var suback = try subscriber.subscribe(&.{.{
        .topic_filter = "mirror/#",
        .qos = .exactly_once,
        .retain_as_published = true,
    }}, .{});
    defer suback.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &.{0x02},
        suback.suback.reason_codes,
    );

    phase = "remote peer setup";
    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const key_pair = try netz.tls.testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const certificate_chain = [_][]const u8{&certificate_der};
    var remote = try transport.listen(
        tls,
        allocator,
        io,
        &certificate_chain,
        key_pair,
    );
    var remote_open = true;
    defer if (remote_open) remote.deinit();
    const PeerState = peer.State(transport.Server(tls), tls);
    var peer_state = PeerState{
        .server = &remote,
        .input = sequence,
    };
    const peer_thread = try std.Thread.spawn(.{}, PeerState.run, .{&peer_state});
    var peer_joined = false;

    var shutdown: std.Io.Event = .unset;
    var connector = if (tls) transport.tlsConnector(
        remote.address(),
        public_key,
    ) else {};
    var bridge: ?bridge_mod.Bridge = initBridge(
        tls,
        allocator,
        io,
        &local,
        remote.address(),
        if (tls) &connector else {},
        &shutdown,
    ) catch |err| {
        transport.shutdownListener(&remote, io);
        peer_thread.join();
        remote.deinit();
        remote_open = false;
        return @as(anyerror!model.Summary, err);
    };
    defer if (bridge) |*value| value.deinit();
    defer if (!peer_joined) {
        if (bridge) |*value| {
            if (value.client.connection()) |connection| {
                connection.shutdown() catch {};
            }
        }
        transport.shutdownListener(&remote, io);
        peer_thread.join();
        remote.deinit();
        remote_open = false;
    };
    phase = "initial bridge connect";
    errdefer |err| {
        failure_reported = true;
        std.debug.print(
            "MQTT bridge QoS2 failure: tls={} sequence={x} operation={} phase={s} error={s} peer_error={s}\n",
            .{
                tls,
                sequence,
                operation_index,
                phase,
                @errorName(err),
                if (peer_state.failed.load(.acquire)) @errorName(peer_state.err.?) else "none",
            },
        );
    }
    const initial = try bridge.?.connect();
    try std.testing.expect(!initial.session_present);
    if (tls) try transport.validateBridge(&bridge.?, &certificate_der);

    var state = model.State{};
    var summary = model.Summary{};
    for (sequence, 0..) |operation, index| {
        operation_index = index;
        phase = "stage incoming PUBLISH";
        const kind = operation & 0x03;
        try std.testing.expect(try stepBridge(&bridge.?, &peer_state));
        phase = "pending journal and publication count";
        try std.testing.expectEqual(
            summary.released,
            local.stats().publish_messages_received,
        );
        try expectTransactionCount(
            allocator,
            &local,
            bridge.?.session_epoch,
            1,
        );
        phase = "subscriber before PUBREL";
        try drainSubscriber(&subscriber, null);

        phase = "recover and complete PUBREL";
        switch (kind) {
            0 => {
                try std.testing.expect(try stepBridge(&bridge.?, &peer_state));
                summary.ordinary += 1;
            },
            1 => {
                try std.testing.expect(try stepBridge(&bridge.?, &peer_state));
                try std.testing.expect(try stepBridge(&bridge.?, &peer_state));
                summary.transport_resumes += 1;
            },
            2 => {
                bridge.?.deinit();
                bridge = null;
                bridge = try initBridge(
                    tls,
                    allocator,
                    io,
                    &local,
                    remote.address(),
                    if (tls) &connector else {},
                    &shutdown,
                );
                const resumed = try bridge.?.connect();
                try std.testing.expect(resumed.session_present);
                if (tls) {
                    try transport.validateBridge(&bridge.?, &certificate_der);
                }
                try std.testing.expect(try stepBridge(&bridge.?, &peer_state));
                summary.process_resumes += 1;
            },
            3 => {
                try std.testing.expect(try stepBridge(&bridge.?, &peer_state));
                summary.fresh_session_discards += 1;
                try expectTransactionCount(
                    allocator,
                    &local,
                    bridge.?.session_epoch,
                    0,
                );
                continue;
            },
            else => unreachable,
        }
        if (tls) try transport.validateBridge(&bridge.?, &certificate_der);

        state.release(operation, index);
        summary.released += 1;
        summary.duplicate_inputs += @intFromBool(operation & 0x10 != 0);
        summary.retained_writes += @intFromBool(operation & 0x08 != 0);
        phase = "subscriber released delivery";
        try drainSubscriber(
            &subscriber,
            .{
                .operation = operation,
                .index = index,
                .retained = operation & 0x08 != 0,
            },
        );
        phase = "completed journal and publication count";
        try std.testing.expectEqual(
            summary.released,
            local.stats().publish_messages_received,
        );
        try expectTransactionCount(
            allocator,
            &local,
            bridge.?.session_epoch,
            0,
        );
    }

    operation_index = sequence.len;
    phase = "bridge disconnect";
    try bridge.?.disconnect(0);
    phase = "peer shutdown";
    peer_thread.join();
    peer_joined = true;
    if (peer_state.err) |err| return @as(anyerror!model.Summary, err);
    summary.subscription_replays = peer_state.summary.subscription_replays;

    phase = "retained probe";
    try verifyRetainedState(allocator, io, local, state, &summary, &phase);
    phase = "subscriber disconnect";
    try subscriber.disconnect(0);
    phase = "broker shutdown";
    const local_error = local_runner.stop(io, local_thread);
    local_joined = true;
    if (local_error) |err| return @as(anyerror!model.Summary, err);
    return summary;
}

fn stepBridge(bridge: *bridge_mod.Bridge, peer_state: anytype) !bool {
    if (peer_state.failed.load(.acquire)) return peer_state.err.?;
    const progressed = bridge.step(.{
        .timeout = model.packet_timeout,
    }) catch |err| {
        if (peer_state.failed.load(.acquire)) return peer_state.err.?;
        return err;
    };
    if (peer_state.failed.load(.acquire)) return peer_state.err.?;
    return progressed;
}

fn expectTransactionCount(
    allocator: std.mem.Allocator,
    local: *Broker,
    session_epoch: u64,
    expected: usize,
) !void {
    const transactions = try local.bridgeQoS2SessionTransactionsAlloc(
        allocator,
        model.bridge_id,
        session_epoch,
    );
    defer allocator.free(transactions);
    try std.testing.expectEqual(expected, transactions.len);
    if (expected == 1) {
        try std.testing.expect(transactions[0].phase == .pending);
    }
}

fn initBridge(
    comptime tls: bool,
    allocator: std.mem.Allocator,
    io: std.Io,
    local: *Broker,
    remote_address: std.Io.net.IpAddress,
    connector: if (tls) *mqtt.tls_runtime.ReconnectConnector else void,
    shutdown: *std.Io.Event,
) !bridge_mod.Bridge {
    const properties = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 60,
    } }};
    const options: bridge_mod.MultiOptions = .{
        .connect = .{
            .protocol = .v5,
            .client_id = "fuzz-qos2-bridge",
            .clean_start = false,
            .connect_timeout = model.packet_timeout,
            .properties = &properties,
        },
        .reconnect_policy = .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(1),
            .max_attempts = 1,
        },
        .rules = &.{
            .{
                .filter = model.remote_topics[0],
                .qos = .exactly_once,
                .local_prefix = "mirror/",
            },
            .{
                .filter = model.remote_topics[1],
                .qos = .exactly_once,
                .local_prefix = "mirror/",
            },
        },
        .bridge_id = model.bridge_id,
    };
    return if (tls)
        bridge_mod.Bridge.initConnectorMany(
            allocator,
            io,
            local,
            connector.connector(),
            options,
            shutdown,
        )
    else
        bridge_mod.Bridge.initMany(
            allocator,
            io,
            local,
            remote_address,
            options,
            shutdown,
        );
}

const Expected = struct {
    operation: u8,
    index: usize,
    retained: bool,
};

fn drainSubscriber(
    connection: *runtime.Connection,
    expected: ?Expected,
) !void {
    try connection.writePingReq();
    var saw_publish = false;
    var pending_id: ?u16 = null;
    while (true) {
        var event = try connection.readClientPacketEventWithTimeout(
            model.packet_timeout,
        );
        defer event.deinit(std.testing.allocator);
        switch (event) {
            .publish => |delivery| {
                if (saw_publish or pending_id != null) {
                    return error.UnexpectedBridgeDelivery;
                }
                try validateDelivery(
                    delivery.publish,
                    expected orelse return error.UnexpectedBridgeDelivery,
                );
                pending_id = delivery.publish.packet_id.?;
                try connection.writePubRec(pending_id.?, 0);
            },
            .pubrel => |release| {
                try std.testing.expectEqual(pending_id.?, release.ack.packet_id);
                try connection.writePubComp(release.ack.packet_id, 0);
                pending_id = null;
                saw_publish = true;
            },
            .pingresp => {
                if (pending_id != null) {
                    // The first request was already queued when PUBREC made
                    // PUBREL eligible. A second response is the ordering
                    // barrier for the completed two-phase exchange.
                    try connection.writePingReq();
                    continue;
                }
                try std.testing.expectEqual(expected != null, saw_publish);
                return;
            },
            else => return error.UnexpectedClientPacket,
        }
    }
}

fn validateDelivery(publish: mqtt.Publish, expected: Expected) !void {
    const topic_index: usize = (expected.operation >> 2) & 0x01;
    const payload = model.Payload.init(expected.operation, expected.index);
    try std.testing.expectEqualStrings(
        model.local_topics[topic_index],
        publish.topic,
    );
    try std.testing.expectEqualSlices(u8, &payload.bytes, publish.payload);
    try std.testing.expectEqual(mqtt.QoS.exactly_once, publish.qos);
    try std.testing.expectEqual(expected.retained, publish.retain);
    try std.testing.expect(!publish.dup);
    var user_property_count: usize = 0;
    for (publish.properties) |property| switch (property) {
        .utf8_pair => |value| if (value.id == .user_property) {
            try std.testing.expectEqualStrings("origin", value.key);
            try std.testing.expectEqualStrings("remote-qos2", value.value);
            user_property_count += 1;
        },
        .varint => |value| if (value.id == .subscription_identifier) {
            return error.RemoteSubscriptionIdentifierLeaked;
        },
        .two_byte => |value| if (value.id == .topic_alias) {
            return error.RemoteTopicAliasLeaked;
        },
        else => {},
    };
    try std.testing.expectEqual(@as(usize, 1), user_property_count);
}

fn verifyRetainedState(
    allocator: std.mem.Allocator,
    io: std.Io,
    local: Broker,
    state: model.State,
    summary: *model.Summary,
    phase: *[]const u8,
) !void {
    phase.* = "retained probe connect";
    var probe = try runtime.Client.connectWithTimeout(
        allocator,
        io,
        local.address(),
        .{
            .protocol = .v5,
            .client_id = "fuzz-qos2-retained-probe",
            .topic_alias_maximum = 0,
        },
        model.packet_timeout,
    );
    defer probe.close();
    for (model.local_topics, 0..) |topic, topic_index| {
        phase.* = "retained probe subscribe";
        var suback = try probe.subscribe(&.{.{
            .topic_filter = topic,
            .qos = .exactly_once,
            .retain_as_published = true,
        }}, .{});
        defer suback.deinit(allocator);
        phase.* = "retained probe delivery fence";
        if (state.retained[topic_index]) |retained| {
            try drainSubscriber(
                &probe,
                .{
                    .operation = retained.payload.bytes[0],
                    .index = retained.payload.bytes[1],
                    .retained = true,
                },
            );
            summary.retained_probe_deliveries += 1;
        } else {
            try drainSubscriber(&probe, null);
        }
    }
    phase.* = "retained probe disconnect";
    try probe.disconnect(0);
}
