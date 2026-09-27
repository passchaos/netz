const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");
const oracle = @import("oracle.zig");
const transport = @import("transport.zig");

const mqtt = netz.mqtt;
const outbound = mqtt.bridge.outbound;
const Broker = mqtt.broker.Broker;
const runtime = mqtt.runtime;

const BrokerRunner = struct {
    broker: *Broker,
    source: runtime.PendingSource,
    accept_concurrency: usize,
    shutdown: std.Io.Event = .unset,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.broker.serveListenersUntil(&.{.{
            .source = self.source,
            .accept_concurrency = self.accept_concurrency,
        }}, .{
            .shutdown = &self.shutdown,
        }) catch |err| {
            self.err = err;
        };
    }

    fn stop(self: *@This(), io: std.Io, thread: std.Thread) !void {
        self.shutdown.set(io);
        thread.join();
        if (self.err) |err| return err;
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
) !model.Summary {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const key_pair = try netz.tls.testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const certificate_chain = [_][]const u8{&certificate_der};

    var source = try initBroker(allocator, io, 2);
    defer source.deinit();
    var target = try initBroker(allocator, io, 3);
    defer target.deinit();
    var source_server = try transport.listen(
        tls,
        allocator,
        io,
        &certificate_chain,
        key_pair,
    );
    defer source_server.deinit();
    var target_server = try transport.listen(
        tls,
        allocator,
        io,
        &certificate_chain,
        key_pair,
    );
    defer target_server.deinit();
    var source_runner = BrokerRunner{
        .broker = &source,
        .source = source_server.pendingSource(),
        .accept_concurrency = 2,
    };
    var target_runner = BrokerRunner{
        .broker = &target,
        .source = target_server.pendingSource(),
        .accept_concurrency = 3,
    };
    const source_thread = try std.Thread.spawn(
        .{},
        BrokerRunner.run,
        .{&source_runner},
    );
    var source_joined = false;
    defer if (!source_joined) {
        source_runner.shutdown.set(io);
        source_thread.join();
    };
    const target_thread = try std.Thread.spawn(
        .{},
        BrokerRunner.run,
        .{&target_runner},
    );
    var target_joined = false;
    defer if (!target_joined) {
        target_runner.shutdown.set(io);
        target_thread.join();
    };

    var subscriber = try transport.connect(
        tls,
        allocator,
        io,
        target_server.address(),
        "fuzz-outbound-qos2-subscriber",
        public_key,
    );
    defer subscriber.close();
    const subscription_properties = [_]mqtt.Property{.{ .varint = .{
        .id = .subscription_identifier,
        .value = model.local_subscription_id,
    } }};
    var suback = try subscriber.subscribe(&.{.{
        .topic_filter = "remote/#",
        .qos = .exactly_once,
        .retain_as_published = true,
    }}, .{ .properties = &subscription_properties });
    defer suback.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &.{0x02},
        suback.suback.reason_codes,
    );

    var publisher = try transport.connect(
        tls,
        allocator,
        io,
        source_server.address(),
        "fuzz-outbound-qos2-publisher",
        public_key,
    );
    defer publisher.close();

    var shutdown: std.Io.Event = .unset;
    var source_connector = if (tls) transport.tlsConnector(
        source_server.address(),
        public_key,
    ) else {};
    var target_connector = if (tls) transport.tlsConnector(
        target_server.address(),
        public_key,
    ) else {};
    var bridge: ?outbound.Bridge = try initBridge(
        tls,
        allocator,
        io,
        source_server.address(),
        target_server.address(),
        if (tls) &source_connector else {},
        if (tls) &target_connector else {},
        &shutdown,
        tmp.dir,
        .create,
    );
    defer if (bridge) |*value| value.deinit();
    const connected = try bridge.?.connect();
    try std.testing.expect(!connected.source_session_present);
    try std.testing.expect(!connected.target_session_present);
    if (tls) try transport.validateBridge(&bridge.?);

    const sequence = input[0..@min(input.len, model.max_operations)];
    var state = model.State{};
    var summary = model.Summary{};
    for (sequence, 0..) |operation, index| {
        const payload = model.Payload.init(operation, index);
        const properties = [_]mqtt.Property{
            .{ .two_byte = .{ .id = .topic_alias, .value = 1 } },
            .{ .utf8_pair = .{
                .id = .user_property,
                .key = "origin",
                .value = "source-broker",
            } },
        };
        try publisher.publish(
            model.source_topics[model.topicIndex(operation)],
            if (model.deletesRetained(operation)) &.{} else &payload.bytes,
            .{
                .qos = .exactly_once,
                .retain = model.retain(operation),
                .properties = &properties,
            },
        );

        if (model.reconnectSource(operation)) {
            bridge.?.source.disconnectTransport();
            const resumed = try bridge.?.connect();
            try std.testing.expect(resumed.source_session_present);
            if (tls) try transport.validateBridge(&bridge.?);
            summary.source_resumes += 1;
        }

        try outbound.testing.stageNextDurableQoS2(&bridge.?, .{
            .timeout = model.packet_timeout,
        });
        try std.testing.expect(bridge.?.hasPendingDurableQoS2());
        switch (model.mode(operation)) {
            0 => {
                try outbound.testing.flushDurableTarget(&bridge.?);
                try finishTransaction(io, &bridge.?);
                summary.ordinary += 1;
            },
            1 => {
                try recreateBridge(
                    tls,
                    allocator,
                    io,
                    &bridge,
                    source_server.address(),
                    target_server.address(),
                    if (tls) &source_connector else {},
                    if (tls) &target_connector else {},
                    &shutdown,
                    tmp.dir,
                );
                try finishTransaction(io, &bridge.?);
                summary.pre_wire_restores += 1;
            },
            2 => {
                try outbound.testing.flushDurableTarget(&bridge.?);
                try outbound.testing.stageTargetPubRec(&bridge.?, .{
                    .timeout = model.packet_timeout,
                });
                try recreateBridge(
                    tls,
                    allocator,
                    io,
                    &bridge,
                    source_server.address(),
                    target_server.address(),
                    if (tls) &source_connector else {},
                    if (tls) &target_connector else {},
                    &shutdown,
                    tmp.dir,
                );
                try finishTransaction(io, &bridge.?);
                summary.pubrel_restores += 1;
            },
            3 => {
                try outbound.testing.flushDurableTarget(&bridge.?);
                bridge.?.target.disconnectTransport();
                try finishTransaction(io, &bridge.?);
                summary.target_resumes += 1;
            },
        }
        try std.testing.expect(!bridge.?.hasPendingDurableQoS2());
        if (tls) try transport.validateBridge(&bridge.?);
        state.apply(operation, index);
        summary.retained_writes += @intFromBool(model.retain(operation) and
            !model.deletesRetained(operation));
        summary.retained_deletes += @intFromBool(
            model.deletesRetained(operation),
        );
        try oracle.drainSubscriber(&subscriber, operation, index);
        summary.delivered += 1;
    }
    try oracle.drainNoDelivery(&subscriber);

    try bridge.?.disconnect(0);
    try publisher.disconnect(0);
    try oracle.verifyRetainedState(
        allocator,
        io,
        target_server.address(),
        public_key,
        tls,
        state,
        &summary,
    );
    try subscriber.disconnect(0);
    try source_runner.stop(io, source_thread);
    source_joined = true;
    try target_runner.stop(io, target_thread);
    target_joined = true;
    return summary;
}

fn initBroker(
    allocator: std.mem.Allocator,
    io: std.Io,
    max_connections: usize,
) !Broker {
    return Broker.init(allocator, io, .{
        .limits = .{
            .max_connections = max_connections,
            .max_queued_deliveries_per_connection = model.max_operations,
            .runtime = .{ .max_packet_size = 4096 },
        },
        .accept = .{ .protocol = .v5 },
    });
}

fn initBridge(
    comptime tls: bool,
    allocator: std.mem.Allocator,
    io: std.Io,
    source_address: std.Io.net.IpAddress,
    target_address: std.Io.net.IpAddress,
    source_connector: if (tls) *mqtt.tls_runtime.ReconnectConnector else void,
    target_connector: if (tls) *mqtt.tls_runtime.ReconnectConnector else void,
    shutdown: *std.Io.Event,
    dir: std.Io.Dir,
    mode: outbound.CoordinatorMode,
) !outbound.Bridge {
    const session_expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 60,
    } }};
    const options: outbound.MultiOptions = .{
        .source_connect = .{
            .protocol = .v5,
            .client_id = "fuzz-outbound-qos2-source",
            .clean_start = false,
            .connect_timeout = model.packet_timeout,
            .properties = &session_expiry,
        },
        .target_connect = .{
            .protocol = .v5,
            .client_id = "fuzz-outbound-qos2-target",
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
                .qos = .exactly_once,
                .local_prefix = "local/",
                .remote_prefix = "remote/",
            },
            .{
                .filter = model.bridge_filters[1],
                .qos = .exactly_once,
                .local_prefix = "local/",
                .remote_prefix = "remote/",
            },
        },
        .coordinator = .{
            .bridge_id = model.bridge_id,
            .dir = dir,
            .sub_path = "outbound-qos2-fuzz.log",
            .mode = mode,
        },
    };
    return if (tls)
        outbound.Bridge.initConnectorMany(
            allocator,
            io,
            source_connector.connector(),
            target_connector.connector(),
            options,
            shutdown,
        )
    else
        outbound.Bridge.initMany(
            allocator,
            io,
            source_address,
            target_address,
            options,
            shutdown,
        );
}

fn recreateBridge(
    comptime tls: bool,
    allocator: std.mem.Allocator,
    io: std.Io,
    bridge: *?outbound.Bridge,
    source_address: std.Io.net.IpAddress,
    target_address: std.Io.net.IpAddress,
    source_connector: if (tls) *mqtt.tls_runtime.ReconnectConnector else void,
    target_connector: if (tls) *mqtt.tls_runtime.ReconnectConnector else void,
    shutdown: *std.Io.Event,
    dir: std.Io.Dir,
) !void {
    bridge.*.?.deinit();
    bridge.* = null;
    bridge.* = try initBridge(
        tls,
        allocator,
        io,
        source_address,
        target_address,
        source_connector,
        target_connector,
        shutdown,
        dir,
        .restore,
    );
    const connected = try bridge.*.?.connect();
    try std.testing.expect(connected.source_session_present);
    try std.testing.expect(connected.target_session_present);
    if (tls) try transport.validateBridge(&bridge.*.?);
}

fn finishTransaction(io: std.Io, bridge: *outbound.Bridge) !void {
    const deadline = std.Io.Clock.awake.now(io).addDuration(
        model.coordination_timeout,
    );
    var attempts: usize = 0;
    while (bridge.hasPendingDurableQoS2()) {
        if (attempts == 64) return error.BridgeProgressLimitExceeded;
        const remaining = std.Io.Clock.awake.now(io).durationTo(deadline);
        if (remaining.nanoseconds <= 0) {
            return error.BridgeProgressLimitExceeded;
        }
        _ = try bridge.step(.{
            .timeout = remaining,
            .cancellation_check_interval = .fromMilliseconds(5),
        });
        attempts += 1;
    }
}
