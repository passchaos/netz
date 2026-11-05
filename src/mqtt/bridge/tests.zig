const std = @import("std");
const test_tmp = @import("../../internal/test_tmp_dir.zig");
const mqtt = @import("../mod.zig");
const bridge_mod = @import("../bridge.zig");
const broker_mod = @import("../broker.zig");
const runtime = @import("../runtime.zig");
const mqtt_tls = @import("../tls_runtime.zig");
const tls_test = @import("../testing/tls13_server.zig");

const Rule = bridge_mod.Rule;
const CertificateBundle = std.crypto.Certificate.Bundle;
const session_expiry_properties = [_]mqtt.Property{.{ .four_byte = .{
    .id = .session_expiry_interval,
    .value = 60,
} }};

const BrokerRunner = struct {
    broker: *broker_mod.Broker,
    accept_concurrency: usize,
    shutdown: std.Io.Event = .unset,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.broker.serveListenersUntil(&.{.{
            .source = self.broker.server.?.pendingSource(),
            .accept_concurrency = self.accept_concurrency,
        }}, .{
            .shutdown = &self.shutdown,
        }) catch |err| {
            self.err = err;
        };
    }

    fn stop(
        self: *@This(),
        io: std.Io,
        thread: std.Thread,
    ) !void {
        self.shutdown.set(io);
        thread.join();
        if (self.err) |err| return err;
    }
};

fn expectUserProperty(
    properties: []const mqtt.Property,
    key: []const u8,
    value: []const u8,
) !void {
    for (properties) |property| {
        if (property == .utf8_pair and
            property.utf8_pair.id == .user_property and
            std.mem.eql(u8, property.utf8_pair.key, key) and
            std.mem.eql(u8, property.utf8_pair.value, value))
        {
            return;
        }
    }
    return error.TestExpectedEqual;
}

fn expectNoTopicAlias(properties: []const mqtt.Property) !void {
    for (properties) |property| {
        try std.testing.expect(!(property == .two_byte and
            property.two_byte.id == .topic_alias));
    }
}

fn expectSubscriptionIdentifier(
    properties: []const mqtt.Property,
    expected: usize,
) !void {
    var count: usize = 0;
    for (properties) |property| {
        if (property == .varint and
            property.varint.id == .subscription_identifier)
        {
            try std.testing.expectEqual(expected, property.varint.value);
            count += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), count);
}

fn expectNoPublish(
    connection: *runtime.Connection,
    timeout: std.Io.Duration,
) !void {
    try std.testing.expectError(
        error.Timeout,
        connection.readClientPacketEventWithTimeout(timeout),
    );
}

const InjectFailure = struct {
    seen: bool = false,
    packet_id: u16 = 0,

    fn failOnce(context: *anyopaque, remote: *const mqtt.Publish) bool {
        const self: *InjectFailure = @ptrCast(@alignCast(context));
        if (self.seen) return false;
        self.seen = true;
        self.packet_id = remote.packet_id.?;
        return true;
    }
};

fn localCaBundle(
    allocator: std.mem.Allocator,
    io: std.Io,
) !struct { CertificateBundle, std.Io.RwLock } {
    var certificate_der: [tls_test.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_test.certificate_base64,
    );
    var pem_storage: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&pem_storage);
    try writer.writeAll("-----BEGIN CERTIFICATE-----\n");
    const encoded_len = std.base64.standard.Encoder.calcSize(
        certificate_der.len,
    );
    const encoded = try writer.writableSliceGreedy(encoded_len);
    _ = std.base64.standard.Encoder.encode(
        encoded[0..encoded_len],
        &certificate_der,
    );
    writer.advance(encoded_len);
    try writer.writeAll("\n-----END CERTIFICATE-----\n");

    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "ca.pem",
        .data = writer.buffered(),
    });
    var bundle: CertificateBundle = .empty;
    errdefer bundle.deinit(allocator);
    try bundle.addCertsFromFilePath(
        allocator,
        io,
        std.Io.Timestamp.now(io, .real),
        tmp.dir,
        "ca.pem",
    );
    return .{ bundle, .init };
}

const TlsBridgePeer = struct {
    server: *mqtt_tls.Server,
    local: *broker_mod.Broker,
    injected: std.Io.Event = .unset,
    allow_ack_read: std.Io.Event = .unset,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.runFallible() catch |err| {
            self.err = err;
        };
    }

    fn runFallible(self: *@This()) !void {
        var accepted = try self.server.accept(.{ .protocol = .v5 });
        defer accepted.deinit(self.server.allocator);
        try std.testing.expectEqualStrings(
            "tls-hostname-bridge",
            accepted.connect.connect.client_id,
        );
        var subscribe = try accepted.connection.readSubscribe();
        defer subscribe.deinit(self.server.allocator);
        try std.testing.expectEqualStrings(
            "secure/#",
            subscribe.subscribe.subscriptions[0].topic_filter,
        );
        try accepted.connection.writeSubAck(
            subscribe.subscribe.packet_id,
            &.{0x01},
            &.{},
        );

        const packet_id = (try accepted.connection.writePublish(
            "secure/device/state",
            "online",
            .{ .qos = .at_least_once },
        )).?;
        self.injected.set(self.server.io);
        self.allow_ack_read.waitUncancelable(self.server.io);
        var acknowledgement = try accepted.connection.readPubAck();
        defer acknowledgement.deinit(self.server.allocator);
        try std.testing.expectEqual(
            packet_id,
            acknowledgement.ack.packet_id,
        );
        // The bridge writes PUBACK only after local injection returns, so
        // observing it here is also an ordering barrier for broker state.
        try std.testing.expectEqual(
            @as(usize, 1),
            self.local.stats().publish_messages_received,
        );
        var disconnect = try accepted.connection.readDisconnect();
        defer disconnect.deinit(self.server.allocator);
    }
};

test "bridge rule validates bounded inbound mappings" {
    try (Rule{
        .filter = "remote/sensors/+/state",
        .qos = .at_least_once,
        .local_prefix = "upstream/",
        .remote_prefix = "remote/",
    }).validate();
    try (Rule{
        .filter = "#",
        .qos = .at_most_once,
    }).validate();

    try std.testing.expectError(
        error.InvalidSubscription,
        (Rule{ .filter = "sensors/#/bad" }).validate(),
    );
    try (Rule{ .filter = "#", .qos = .exactly_once }).validate();
    try std.testing.expectError(
        error.InvalidTopic,
        (Rule{ .filter = "#", .local_prefix = "bad/+" }).validate(),
    );
    try std.testing.expectError(
        error.InvalidUtf8,
        (Rule{
            .filter = "#",
            .local_prefix = &[_]u8{ 0xff, '/' },
        }).validate(),
    );
    try std.testing.expectError(
        error.InvalidTopic,
        (Rule{ .filter = "remote/#", .remote_prefix = "bad/+" }).validate(),
    );
    try std.testing.expectError(
        error.InvalidBridgePrefix,
        (Rule{ .filter = "other/#", .remote_prefix = "remote/" }).validate(),
    );
    try (Rule{
        .filter = "$share/workers/remote/#",
        .remote_prefix = "remote/",
    }).validate();
}

test "bridge rule strips remote prefix before adding local prefix" {
    const allocator = std.testing.allocator;
    const rule = Rule{
        .filter = "remote/sensors/#",
        .qos = .at_least_once,
        .local_prefix = "local/",
        .remote_prefix = "remote/",
    };
    const mapped = try rule.mapTopicAlloc(
        allocator,
        "remote/sensors/room-1/state",
    );
    defer allocator.free(mapped);
    try std.testing.expectEqualStrings("local/sensors/room-1/state", mapped);

    const parent = try (Rule{
        .filter = "remote/#",
        .local_prefix = "local/",
        .remote_prefix = "remote/",
    }).mapTopicAlloc(allocator, "remote");
    defer allocator.free(parent);
    try std.testing.expectEqualStrings("local/", parent);

    try std.testing.expectError(
        error.EmptyMappedTopic,
        (Rule{
            .filter = "remote/#",
            .remote_prefix = "remote/",
        }).mapTopicAlloc(allocator, "remote"),
    );
}

test "bridge rule maps only matching remote Topic Names" {
    const allocator = std.testing.allocator;
    const rule = Rule{
        .filter = "sensors/+/state",
        .qos = .at_least_once,
        .local_prefix = "remote/site-a/",
    };
    const mapped = try rule.mapTopicAlloc(
        allocator,
        "sensors/room-1/state",
    );
    defer allocator.free(mapped);
    try std.testing.expectEqualStrings(
        "remote/site-a/sensors/room-1/state",
        mapped,
    );
    try std.testing.expectError(
        error.TopicOutsideBridgeRule,
        rule.mapTopicAlloc(allocator, "commands/room-1"),
    );
    try std.testing.expectError(
        error.InvalidTopic,
        rule.mapTopicAlloc(allocator, "sensors/+/state"),
    );

    const system_rule = Rule{
        .filter = "+/#",
        .local_prefix = "remote/",
    };
    try std.testing.expectError(
        error.TopicOutsideBridgeRule,
        system_rule.mapTopicAlloc(allocator, "$SYS/broker/uptime"),
    );
}

test "bridge filter intersection follows MQTT wildcard semantics" {
    const Case = struct {
        left: []const u8,
        right: []const u8,
        overlaps: bool,
    };
    const cases = [_]Case{
        .{ .left = "a/+", .right = "a/b", .overlaps = true },
        .{ .left = "a/+", .right = "a/b/c", .overlaps = false },
        .{ .left = "a/#", .right = "a", .overlaps = true },
        .{ .left = "a/#", .right = "a/b/c", .overlaps = true },
        .{ .left = "a/+", .right = "b/+", .overlaps = false },
        .{ .left = "a//+", .right = "a//b", .overlaps = true },
        // `/#` can consume zero levels only after its leading empty level.
        // The sole common level with `+` would produce an invalid empty Topic
        // Name, so these filters are disjoint despite terminal `#`.
        .{ .left = "+", .right = "/#", .overlaps = false },
        .{ .left = "/#", .right = "+", .overlaps = false },
        .{ .left = "+", .right = "/+", .overlaps = false },
        .{ .left = "#", .right = "/#", .overlaps = true },
        .{ .left = "+/+", .right = "/#", .overlaps = true },
        .{ .left = "a/+", .right = "a//#", .overlaps = true },
        .{ .left = "a/+", .right = "a//+", .overlaps = false },
        .{ .left = "+/status", .right = "$SYS/status", .overlaps = false },
        .{ .left = "#", .right = "$SYS/#", .overlaps = false },
        .{ .left = "$SYS/+", .right = "$SYS/#", .overlaps = true },
        .{
            .left = "$share/a/sensors/+",
            .right = "$share/b/sensors/room",
            .overlaps = true,
        },
        .{
            .left = "$share/a/+",
            .right = "$share/b//#",
            .overlaps = false,
        },
        .{
            .left = "$share/a//#",
            .right = "$share/b/+",
            .overlaps = false,
        },
        .{
            .left = "$share/a/#",
            .right = "$share/b//#",
            .overlaps = true,
        },
    };
    for (cases, 0..) |case, index| {
        errdefer std.debug.print(
            "intersection case {d}: {s} vs {s}\n",
            .{ index, case.left, case.right },
        );
        try std.testing.expectEqual(
            case.overlaps,
            try (Rule{ .filter = case.left }).overlaps(.{
                .filter = case.right,
            }),
        );
    }
}

test "bridge filter intersection agrees with matcher over representative languages" {
    const filters = [_][]const u8{
        "#",
        "+",
        "/",
        "/#",
        "/+",
        "+/",
        "+/+",
        "+/#",
        "a",
        "a/#",
        "a/+",
        "a/",
        "a//",
        "a//#",
        "a//+",
        "a/b",
        "a/b/#",
        "b/+",
        "$SYS/#",
        "$SYS/+",
        "$SYS/a",
        "$share/g/+",
        "$share/g//#",
        "$share/h/a/#",
    };
    for (filters, 0..) |left, left_index| {
        for (filters[left_index..]) |right| {
            const expected = filtersShareRepresentativeTopic(left, right);
            errdefer std.debug.print(
                "representative intersection: {s} vs {s}\n",
                .{ left, right },
            );
            try std.testing.expectEqual(
                expected,
                try (Rule{ .filter = left }).overlaps(.{ .filter = right }),
            );
        }
    }
}

fn filtersShareRepresentativeTopic(
    left: []const u8,
    right: []const u8,
) bool {
    // Every literal used by the filter matrix appears here. Four levels are
    // sufficient to witness an intersection because no tested fixed prefix
    // is deeper than three levels; terminal `#` never requires extra depth.
    const levels = [_][]const u8{ "", "a", "b", "$SYS" };
    for (1..5) |depth| {
        var combination_count: usize = 1;
        for (0..depth) |_| combination_count *= levels.len;
        for (0..combination_count) |combination| {
            var digits = combination;
            var selected: [4][]const u8 = undefined;
            for (selected[0..depth]) |*level| {
                level.* = levels[digits % levels.len];
                digits /= levels.len;
            }
            var storage: [64]u8 = undefined;
            var length: usize = 0;
            for (selected[0..depth], 0..) |level, index| {
                if (index != 0) {
                    storage[length] = '/';
                    length += 1;
                }
                @memcpy(storage[length..][0..level.len], level);
                length += level.len;
            }
            if (length == 0) continue;
            const topic = storage[0..length];
            if (mqtt.topicMatchesFilter(topic, left) and
                mqtt.topicMatchesFilter(topic, right)) return true;
        }
    }
    return false;
}

test "bridge rejects empty duplicate and overlapping rule sets" {
    try std.testing.expectError(
        error.NoBridgeRules,
        bridge_mod.testing.validateRules(&.{}),
    );
    try std.testing.expectError(
        error.DuplicateBridgeFilter,
        bridge_mod.testing.validateRules(&.{
            .{ .filter = "devices/+" },
            .{ .filter = "devices/+", .local_prefix = "other/" },
        }),
    );
    try std.testing.expectError(
        error.OverlappingBridgeFilters,
        bridge_mod.testing.validateRules(&.{
            .{ .filter = "devices/+" },
            .{ .filter = "devices/room" },
        }),
    );
    try bridge_mod.testing.validateRules(&.{
        .{ .filter = "sensors/#", .local_prefix = "telemetry/" },
        .{ .filter = "commands/#", .local_prefix = "control/" },
        .{ .filter = "$SYS/#", .local_prefix = "remote-system/" },
    });
}

test "bridge public configuration retains MQTT types" {
    const options = bridge_mod.Options{
        .connect = .{ .client_id = "bridge-test" },
        .rule = .{
            .filter = "remote/#",
            .qos = .at_least_once,
            .local_prefix = "local/",
        },
    };
    try std.testing.expectEqual(mqtt.QoS.at_least_once, options.rule.qos);
}

test "bridge QoS2 requires stable identity and persistent Session" {
    const allocator = std.testing.allocator;
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var local = try broker_mod.Broker.init(allocator, io, .{});
    defer local.deinit();
    var shutdown: std.Io.Event = .unset;
    const address = std.Io.net.IpAddress{ .ip4 = .loopback(1883) };
    const qos2_rule = Rule{
        .filter = "durable/#",
        .qos = .exactly_once,
    };

    try std.testing.expectError(
        error.MissingBridgeIdentifier,
        bridge_mod.Bridge.init(
            allocator,
            io,
            &local,
            address,
            .{
                .connect = .{
                    .protocol = .v5,
                    .client_id = "qos2-missing-id",
                    .clean_start = false,
                    .properties = &session_expiry_properties,
                },
                .rule = qos2_rule,
            },
            &shutdown,
        ),
    );
    try std.testing.expectError(
        error.QoS2RequiresPersistentSession,
        bridge_mod.Bridge.init(
            allocator,
            io,
            &local,
            address,
            .{
                .connect = .{
                    .protocol = .v5,
                    .client_id = "qos2-clean-session",
                },
                .rule = qos2_rule,
                .bridge_id = [_]u8{0x11} ** 16,
            },
            &shutdown,
        ),
    );
    try std.testing.expectError(
        error.QoS2RequiresCommitLog,
        bridge_mod.Bridge.init(
            allocator,
            io,
            &local,
            address,
            .{
                .connect = .{
                    .protocol = .v5,
                    .client_id = "qos2-no-commit-log",
                    .clean_start = false,
                    .properties = &session_expiry_properties,
                },
                .rule = qos2_rule,
                .bridge_id = [_]u8{0x22} ** 16,
            },
            &shutdown,
        ),
    );
    try local.createCommitLog(tmp.dir, "bridge-qos2.log", .{});

    var bridge = try bridge_mod.Bridge.init(
        allocator,
        io,
        &local,
        address,
        .{
            .connect = .{
                .protocol = .v5,
                .client_id = "qos2-valid",
                .clean_start = false,
                .properties = &session_expiry_properties,
            },
            .rule = qos2_rule,
            .bridge_id = [_]u8{0x22} ** 16,
        },
        &shutdown,
    );
    defer bridge.deinit();
    try std.testing.expectEqual(@as(usize, 1), bridge.client.subscriptionCount());
}

test "bridge multi-rule constructor owns every filter and prefix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var local = try broker_mod.Broker.init(allocator, io, .{});
    defer local.deinit();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    var first_filter: [8]u8 = "sensor/#".*;
    var first_prefix: [4]u8 = "one/".*;
    var first_remote_prefix: [7]u8 = "sensor/".*;
    var second_filter: [9]u8 = "command/#".*;
    var second_prefix: [4]u8 = "two/".*;
    var shutdown: std.Io.Event = .unset;
    var bridge = try bridge_mod.Bridge.initMany(
        allocator,
        io,
        &local,
        server.address(),
        .{
            .connect = .{ .client_id = "owned-many" },
            .rules = &.{
                .{
                    .filter = &first_filter,
                    .local_prefix = &first_prefix,
                    .remote_prefix = &first_remote_prefix,
                },
                .{ .filter = &second_filter, .local_prefix = &second_prefix },
            },
        },
        &shutdown,
    );
    defer bridge.deinit();
    @memset(&first_filter, 'x');
    @memset(&first_prefix, 'x');
    @memset(&first_remote_prefix, 'x');
    @memset(&second_filter, 'x');
    @memset(&second_prefix, 'x');

    try std.testing.expectEqual(@as(usize, 2), bridge.rules.len);
    try std.testing.expectEqualStrings("sensor/#", bridge.rule.filter);
    try std.testing.expectEqualStrings("one/", bridge.rule.local_prefix);
    try std.testing.expectEqualStrings("sensor/", bridge.rule.remote_prefix);
    try std.testing.expectEqualStrings("command/#", bridge.rules[1].filter);
    try std.testing.expectEqualStrings("two/", bridge.rules[1].local_prefix);
}

test "bridge owns notifications and publishes initial local offline state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var local = try broker_mod.Broker.init(allocator, io, .{});
    defer local.deinit();
    var remote = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer remote.deinit();
    var topic = "$SYS/broker/connection/unit/state".*;
    var shutdown: std.Io.Event = .unset;
    var bridge = try bridge_mod.Bridge.init(
        allocator,
        io,
        &local,
        remote.address(),
        .{
            .connect = .{ .client_id = "notification-unit" },
            .rule = .{ .filter = "source/#" },
            .notifications = .{
                .topic = &topic,
                .publish_remote = false,
            },
        },
        &shutdown,
    );
    defer bridge.deinit();
    @memset(&topic, 'x');
    try std.testing.expectEqualStrings(
        "$SYS/broker/connection/unit/state",
        bridge.notifications.?.topic,
    );
    try std.testing.expectEqual(@as(usize, 1), local.stats().retained_messages);
}

test "bridge remote notifications reject a caller Will" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var local = try broker_mod.Broker.init(allocator, io, .{});
    defer local.deinit();
    var shutdown: std.Io.Event = .unset;
    try std.testing.expectError(
        error.BridgeNotificationWillConflict,
        bridge_mod.Bridge.init(
            allocator,
            io,
            &local,
            .{ .ip4 = .loopback(1883) },
            .{
                .connect = .{
                    .client_id = "notification-conflict",
                    .will = .{ .topic = "caller/will", .payload = "value" },
                },
                .rule = .{ .filter = "source/#" },
                .notifications = .{ .topic = "bridge/state" },
            },
            &shutdown,
        ),
    );
}

test "inbound bridge subscribes once and maps two disjoint rules" {
    const allocator = std.testing.allocator;
    const operation_timeout = std.Io.Duration.fromSeconds(2);
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var local = try broker_mod.Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .limits = .{ .max_connections = 1 } },
    );
    defer local.deinit();
    var local_runner = BrokerRunner{
        .broker = &local,
        .accept_concurrency = 1,
    };
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

    var remote = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer remote.deinit();
    const Peer = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = .v5 });
            defer accepted.deinit(self.server.allocator);
            var subscribe = try accepted.connection.readSubscribe();
            defer subscribe.deinit(self.server.allocator);
            try std.testing.expectEqual(
                @as(usize, 2),
                subscribe.subscribe.subscriptions.len,
            );
            try std.testing.expectEqualStrings(
                "sensors/#",
                subscribe.subscribe.subscriptions[0].topic_filter,
            );
            try std.testing.expect(
                subscribe.subscribe.subscriptions[0].retain_as_published,
            );
            try std.testing.expectEqualStrings(
                "commands/#",
                subscribe.subscribe.subscriptions[1].topic_filter,
            );
            try std.testing.expect(
                subscribe.subscribe.subscriptions[1].retain_as_published,
            );
            try accepted.connection.writeSubAck(
                subscribe.subscribe.packet_id,
                &.{ 0x01, 0x01 },
                &.{},
            );
            const first = (try accepted.connection.writePublish(
                "sensors/room/state",
                "online",
                .{ .qos = .at_least_once },
            )).?;
            var first_ack = try accepted.connection.readPubAck();
            defer first_ack.deinit(self.server.allocator);
            try std.testing.expectEqual(first, first_ack.ack.packet_id);
            const second = (try accepted.connection.writePublish(
                "commands/room/restart",
                "now",
                .{ .qos = .at_least_once },
            )).?;
            var second_ack = try accepted.connection.readPubAck();
            defer second_ack.deinit(self.server.allocator);
            try std.testing.expectEqual(second, second_ack.ack.packet_id);
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };
    var peer = Peer{ .server = &remote };
    const peer_thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var peer_joined = false;
    defer if (!peer_joined) peer_thread.join();

    var subscriber = try runtime.Client.connectWithTimeout(
        allocator,
        io,
        local.address(),
        .{ .protocol = .v5, .client_id = "many-local" },
        operation_timeout,
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{ .topic_filter = "mirror/#", .qos = .at_least_once }},
        .{},
    );
    defer suback.deinit(allocator);

    var shutdown: std.Io.Event = .unset;
    var bridge = try bridge_mod.Bridge.initMany(
        allocator,
        io,
        &local,
        remote.address(),
        .{
            .connect = .{
                .protocol = .v5,
                .client_id = "many-bridge",
                .connect_timeout = operation_timeout,
            },
            .rules = &.{
                .{
                    .filter = "sensors/#",
                    .qos = .at_least_once,
                    .local_prefix = "mirror/telemetry/",
                },
                .{
                    .filter = "commands/#",
                    .qos = .at_least_once,
                    .local_prefix = "mirror/control/",
                },
            },
        },
        &shutdown,
    );
    defer bridge.deinit();
    _ = try bridge.connect();
    for (0..2) |_| try std.testing.expect(try bridge.step(.{
        .timeout = operation_timeout,
    }));

    var first_event = try subscriber.readClientPacketEventWithTimeout(
        operation_timeout,
    );
    defer first_event.deinit(allocator);
    switch (first_event) {
        .publish => |first| {
            try std.testing.expectEqualStrings(
                "mirror/telemetry/sensors/room/state",
                first.publish.topic,
            );
            try subscriber.writePubAck(first.publish.packet_id.?, 0);
        },
        else => return error.TestUnexpectedResult,
    }
    var second_event = try subscriber.readClientPacketEventWithTimeout(
        operation_timeout,
    );
    defer second_event.deinit(allocator);
    switch (second_event) {
        .publish => |second| {
            try std.testing.expectEqualStrings(
                "mirror/control/commands/room/restart",
                second.publish.topic,
            );
            try subscriber.writePubAck(second.publish.packet_id.?, 0);
        },
        else => return error.TestUnexpectedResult,
    }

    try bridge.client.disconnect(0);
    try subscriber.disconnect(0);
    peer_thread.join();
    peer_joined = true;
    if (peer.err) |err| return err;
    try local_runner.stop(io, local_thread);
    local_joined = true;
}

test "bridge disconnects after a partially refused multi-rule SUBACK" {
    const allocator = std.testing.allocator;
    const operation_timeout = std.Io.Duration.fromSeconds(2);
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var local = try broker_mod.Broker.init(allocator, io, .{});
    defer local.deinit();
    var remote = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer remote.deinit();

    const Peer = struct {
        server: *runtime.Server,
        saw_close: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = .v5 });
            defer accepted.deinit(self.server.allocator);
            var subscribe = try accepted.connection.readSubscribe();
            defer subscribe.deinit(self.server.allocator);
            try std.testing.expectEqual(
                @as(usize, 2),
                subscribe.subscribe.subscriptions.len,
            );
            try accepted.connection.writeSubAck(
                subscribe.subscribe.packet_id,
                &.{ 0x01, 0x87 },
                &.{},
            );
            var scratch: [1]u8 = undefined;
            var bufs = [_][]u8{&scratch};
            while (true) {
                const read = accepted.connection.transport.tcp.io.vtable.netRead(
                    accepted.connection.transport.tcp.io.userdata,
                    accepted.connection.transport.tcp.stream.socket.handle,
                    &bufs,
                ) catch |err| switch (err) {
                    error.ConnectionResetByPeer, error.SocketUnconnected => {
                        self.saw_close = true;
                        return;
                    },
                    else => return err,
                };
                if (read == 0) {
                    self.saw_close = true;
                    return;
                }
            }
        }
    };
    var peer = Peer{ .server = &remote };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();

    var shutdown: std.Io.Event = .unset;
    var bridge = try bridge_mod.Bridge.initMany(
        allocator,
        io,
        &local,
        remote.address(),
        .{
            .connect = .{
                .protocol = .v5,
                .client_id = "partial-suback-bridge",
                .connect_timeout = operation_timeout,
            },
            .rules = &.{
                .{ .filter = "accepted/#", .qos = .at_least_once },
                .{ .filter = "refused/#", .qos = .at_least_once },
            },
        },
        &shutdown,
    );
    defer bridge.deinit();
    try std.testing.expectError(error.SubscriptionRefused, bridge.connect());
    try std.testing.expect(bridge.client.connection() == null);
    try std.testing.expect(bridge.client.hasSubscription("accepted/#"));
    try std.testing.expect(!bridge.client.hasSubscription("refused/#"));

    thread.join();
    joined = true;
    if (peer.err) |err| return err;
    try std.testing.expect(peer.saw_close);
}

test "bridge hostname constructor owns endpoint and configuration strings" {
    const allocator = std.testing.allocator;
    const operation_timeout = std.Io.Duration.fromSeconds(2);

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var local = try broker_mod.Broker.init(allocator, io, .{});
    defer local.deinit();
    var remote = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer remote.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = .v5 });
            defer accepted.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "owned-host-bridge",
                accepted.connect.connect.client_id,
            );
            var subscribe = try accepted.connection.readSubscribe();
            defer subscribe.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "owned/#",
                subscribe.subscribe.subscriptions[0].topic_filter,
            );
            try accepted.connection.writeSubAck(
                subscribe.subscribe.packet_id,
                &.{0x01},
                &.{},
            );
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };
    var shared = Shared{ .server = &remote };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const hostname = try allocator.dupe(u8, "localhost");
    defer allocator.free(hostname);
    const client_id = try allocator.dupe(u8, "owned-host-bridge");
    defer allocator.free(client_id);
    const filter = try allocator.dupe(u8, "owned/#");
    defer allocator.free(filter);
    const prefix = try allocator.dupe(u8, "mirror/");
    defer allocator.free(prefix);
    var shutdown: std.Io.Event = .unset;
    var bridge = try bridge_mod.Bridge.initHost(
        allocator,
        io,
        &local,
        hostname,
        remote.address().ip4.port,
        .{
            .connect = .{
                .protocol = .v5,
                .client_id = client_id,
                .connect_timeout = operation_timeout,
                .network_connect_timeout = operation_timeout,
            },
            .rule = .{
                .filter = filter,
                .qos = .at_least_once,
                .local_prefix = prefix,
            },
        },
        &shutdown,
    );
    defer bridge.deinit();
    @memset(hostname, 'x');
    @memset(client_id, 'x');
    @memset(filter, 'x');
    @memset(prefix, 'x');

    try std.testing.expectEqualStrings("owned/#", bridge.rule.filter);
    try std.testing.expectEqualStrings("mirror/", bridge.rule.local_prefix);
    _ = try bridge.connect();
    try bridge.client.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "inbound bridge accepts QoS 1 over a verified TLS hostname connector" {
    const allocator = std.testing.allocator;
    const operation_timeout = std.Io.Duration.fromSeconds(2);

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var local = try broker_mod.Broker.init(allocator, io, .{});
    defer local.deinit();

    var certificate_der: [tls_test.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_test.certificate_base64,
    );
    const key_pair = try tls_test.serverKeyPair();
    var remote = try mqtt_tls.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
        } },
    );
    defer remote.deinit();

    var shared = TlsBridgePeer{ .server = &remote, .local = &local };
    const thread = try std.Thread.spawn(.{}, TlsBridgePeer.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    var connector = mqtt_tls.HostReconnectConnector{
        .host = "localhost",
        .port = remote.address().ip4.port,
        .options = .{
            // Reconnect connectors retain their own network-attempt budget
            // while replacing the remaining MQTT CONNECT fields with the
            // reconnect client's owned options. Keep this placeholder fully
            // initialized because `reconnectOptions` reads that timeout.
            .mqtt = .{
                .client_id = "",
                .network_connect_timeout = operation_timeout,
            },
            .tls = .{ .ca_bundle = .{
                .bundle = &ca_bundle,
                .lock = &ca_lock,
            } },
        },
    };
    var shutdown: std.Io.Event = .unset;
    var bridge = try bridge_mod.Bridge.initConnector(
        allocator,
        io,
        &local,
        connector.connector(),
        .{
            .connect = .{
                .protocol = .v5,
                .client_id = "tls-hostname-bridge",
                .connect_timeout = operation_timeout,
                .network_connect_timeout = operation_timeout,
            },
            .rule = .{
                .filter = "secure/#",
                .qos = .at_least_once,
                .local_prefix = "mirror/",
            },
        },
        &shutdown,
    );
    defer bridge.deinit();

    _ = try bridge.connect();
    shared.injected.waitUncancelable(io);
    try std.testing.expect(try bridge.step(.{
        .timeout = operation_timeout,
        .cancellation_check_interval = .fromMilliseconds(20),
    }));
    shared.allow_ack_read.set(io);
    try bridge.client.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "inbound bridge mirrors retained MQTT 5 QoS 1 publication end to end" {
    const allocator = std.testing.allocator;
    const operation_timeout = std.Io.Duration.fromSeconds(2);

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var local = try broker_mod.Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 1,
                .max_queued_deliveries_per_connection = 4,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{ .protocol = .v5 },
        },
    );
    defer local.deinit();
    var local_runner = BrokerRunner{
        .broker = &local,
        .accept_concurrency = 1,
    };
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

    var remote = try broker_mod.Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 2,
                .max_queued_deliveries_per_connection = 4,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{ .protocol = .v5 },
        },
    );
    defer remote.deinit();
    var remote_runner = BrokerRunner{
        .broker = &remote,
        .accept_concurrency = 2,
    };
    const remote_thread = try std.Thread.spawn(
        .{},
        BrokerRunner.run,
        .{&remote_runner},
    );
    var remote_joined = false;
    defer if (!remote_joined) {
        remote_runner.shutdown.set(io);
        remote_thread.join();
    };

    var subscriber = try runtime.Client.connectWithTimeout(
        allocator,
        io,
        local.address(),
        .{
            .protocol = .v5,
            .client_id = "bridge-local-subscriber",
            // Disable locally generated Topic Aliases so the assertion below
            // can prove the remote connection's alias did not cross brokers.
            .topic_alias_maximum = 0,
        },
        operation_timeout,
    );
    defer subscriber.close();
    var local_suback = try subscriber.subscribe(
        &.{.{
            .topic_filter = "mirror/source/#",
            .qos = .at_least_once,
            .retain_as_published = true,
        }},
        .{ .properties = &.{.{ .varint = .{
            .id = .subscription_identifier,
            .value = 71,
        } }} },
    );
    defer local_suback.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 1), local_suback.suback.reason_codes[0]);

    // Seed the upstream retained store before the bridge subscribes. This
    // requires the bridge's MQTT 5 subscription to request RAP and makes the
    // resulting retained bit observable at the local subscriber.
    var publisher = try runtime.Client.connectWithTimeout(
        allocator,
        io,
        remote.address(),
        .{ .protocol = .v5, .client_id = "bridge-remote-publisher" },
        operation_timeout,
    );
    defer publisher.close();
    const remote_packet_id = (try publisher.writePublish(
        "source/device/state",
        "online",
        .{
            .qos = .at_least_once,
            .retain = true,
            .properties = &.{
                .{ .utf8_pair = .{
                    .id = .user_property,
                    .key = "origin",
                    .value = "remote",
                } },
                .{ .two_byte = .{
                    .id = .topic_alias,
                    .value = 1,
                } },
            },
        },
    )).?;
    var publisher_event = try publisher.readClientPacketEventWithTimeout(
        operation_timeout,
    );
    defer publisher_event.deinit(allocator);
    switch (publisher_event) {
        .puback => |ack| {
            try std.testing.expectEqual(remote_packet_id, ack.ack.packet_id);
            try publisher.applyPubAck(ack.ack);
        },
        else => return error.TestUnexpectedResult,
    }
    try publisher.disconnect(0);

    var bridge_shutdown: std.Io.Event = .unset;
    var bridge = try bridge_mod.Bridge.init(
        allocator,
        io,
        &local,
        remote.address(),
        .{
            .connect = .{
                .protocol = .v5,
                .client_id = "inbound-bridge-e2e",
                .connect_timeout = operation_timeout,
                .network_connect_timeout = operation_timeout,
            },
            .rule = .{
                .filter = "source/#",
                .qos = .at_least_once,
                .local_prefix = "mirror/",
            },
        },
        &bridge_shutdown,
    );
    defer bridge.deinit();

    _ = try bridge.connect();
    try std.testing.expect(try bridge.step(.{
        .timeout = operation_timeout,
        .cancellation_check_interval = .fromMilliseconds(20),
    }));

    // PINGRESP is ordered after the bridge's PUBACK on the remote stream. Its
    // arrival therefore provides a deterministic barrier before inspecting
    // the remote broker's outgoing QoS state.
    try bridge.client.connection().?.pingWithTimeout(operation_timeout);
    try std.testing.expectEqual(
        @as(usize, 0),
        remote.stats().session_inflight_messages,
    );

    var local_event = try subscriber.readClientPacketEventWithTimeout(
        operation_timeout,
    );
    defer local_event.deinit(allocator);
    switch (local_event) {
        .publish => |delivery| {
            try std.testing.expectEqualStrings(
                "mirror/source/device/state",
                delivery.publish.topic,
            );
            try std.testing.expectEqualStrings(
                "online",
                delivery.publish.payload,
            );
            try std.testing.expectEqual(
                mqtt.QoS.at_least_once,
                delivery.publish.qos,
            );
            try std.testing.expect(delivery.publish.retain);
            try expectUserProperty(
                delivery.publish.properties,
                "origin",
                "remote",
            );
            try expectNoTopicAlias(delivery.publish.properties);
            try expectSubscriptionIdentifier(
                delivery.publish.properties,
                71,
            );
            try subscriber.writePubAck(delivery.publish.packet_id.?, 0);
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 1), local.stats().retained_messages);

    try bridge.client.disconnect(0);
    try subscriber.disconnect(0);
    try remote_runner.stop(io, remote_thread);
    remote_joined = true;
    try local_runner.stop(io, local_thread);
    local_joined = true;
}

fn exerciseInboundBridgeQoS2ExactlyOnce(
    protocol: mqtt.ProtocolVersion,
) !void {
    const allocator = std.testing.allocator;
    const operation_timeout = std.Io.Duration.fromSeconds(2);
    const short_timeout = std.Io.Duration.fromMilliseconds(100);
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var local = try broker_mod.Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 1,
                .max_queued_deliveries_per_connection = 4,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{ .protocol = protocol },
        },
    );
    defer local.deinit();
    try local.createCommitLog(tmp.dir, "bridge-qos2.log", .{});
    var local_runner = BrokerRunner{
        .broker = &local,
        .accept_concurrency = 1,
    };
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

    var remote = try broker_mod.Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 2,
                .max_queued_deliveries_per_connection = 4,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{ .protocol = protocol },
        },
    );
    defer remote.deinit();
    var remote_runner = BrokerRunner{
        .broker = &remote,
        .accept_concurrency = 2,
    };
    const remote_thread = try std.Thread.spawn(
        .{},
        BrokerRunner.run,
        .{&remote_runner},
    );
    var remote_joined = false;
    defer if (!remote_joined) {
        remote_runner.shutdown.set(io);
        remote_thread.join();
    };

    var subscriber = try runtime.Client.connectWithTimeout(
        allocator,
        io,
        local.address(),
        .{
            .protocol = protocol,
            .client_id = "bridge-qos2-local-subscriber",
        },
        operation_timeout,
    );
    defer subscriber.close();
    var local_suback = try subscriber.subscribe(
        &.{.{
            .topic_filter = "mirror/qos2/#",
            .qos = .exactly_once,
        }},
        .{},
    );
    defer local_suback.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 2), local_suback.suback.reason_codes[0]);

    var bridge_shutdown: std.Io.Event = .unset;
    var bridge = try bridge_mod.Bridge.init(
        allocator,
        io,
        &local,
        remote.address(),
        .{
            .connect = .{
                .protocol = protocol,
                .client_id = "inbound-qos2-bridge",
                .clean_start = false,
                .properties = if (protocol == .v5)
                    &session_expiry_properties
                else
                    &.{},
                .connect_timeout = operation_timeout,
                .network_connect_timeout = operation_timeout,
            },
            .rule = .{
                .filter = "qos2/#",
                .qos = .exactly_once,
                .local_prefix = "mirror/",
            },
            .bridge_id = [_]u8{0xb2} ** 16,
        },
        &bridge_shutdown,
    );
    defer bridge.deinit();
    const connected = try bridge.connect();
    try std.testing.expect(!connected.session_present);

    var publisher = try runtime.Client.connectWithTimeout(
        allocator,
        io,
        remote.address(),
        .{ .protocol = protocol, .client_id = "bridge-qos2-publisher" },
        operation_timeout,
    );
    defer publisher.close();
    const packet_id = (try publisher.writePublish(
        "qos2/device/state",
        "exactly-once",
        .{ .qos = .exactly_once },
    )).?;
    var publisher_pubrec = try publisher.readPubRec();
    defer publisher_pubrec.deinit(allocator);
    try publisher.applyPubRec(publisher_pubrec.ack);

    // PUBLISH stages in the local durable store and produces upstream PUBREC,
    // but the local subscriber cannot see it before PUBREL is processed.
    try std.testing.expect(try bridge.step(.{
        .timeout = operation_timeout,
        .cancellation_check_interval = .fromMilliseconds(20),
    }));
    try expectNoPublish(&subscriber, short_timeout);
    try std.testing.expectEqual(@as(usize, 0), local.stats().publish_messages_received);
    const staged = try local.bridgeQoS2SessionTransactionsAlloc(
        allocator,
        [_]u8{0xb2} ** 16,
        bridge.session_epoch,
    );
    try std.testing.expectEqual(@as(usize, 1), staged.len);
    var changed_duplicate = mqtt.Publish{
        .dup = true,
        .qos = .exactly_once,
        .retain = false,
        .topic = "qos2/device/state",
        .packet_id = staged[0].packet_id,
        .payload = "tampered",
    };
    try std.testing.expectError(
        error.InvalidPacketIdentifier,
        bridge_mod.testing.injectPublish(&bridge, &changed_duplicate),
    );
    try std.testing.expect(bridge.client.connection() == null);
    const staged_packet_id = staged[0].packet_id;
    allocator.free(staged);

    // Drop the upstream transport and recreate the Bridge after PUBREC but
    // before it consumes PUBREL. The new reconnect client has no in-memory
    // receive marker, so it must rebuild that marker from the local broker's
    // durable transaction before accepting the upstream release leg.
    bridge.deinit();
    bridge = try bridge_mod.Bridge.init(
        allocator,
        io,
        &local,
        remote.address(),
        .{
            .connect = .{
                .protocol = protocol,
                .client_id = "inbound-qos2-bridge",
                .clean_start = false,
                .properties = if (protocol == .v5)
                    &session_expiry_properties
                else
                    &.{},
                .connect_timeout = operation_timeout,
                .network_connect_timeout = operation_timeout,
            },
            .rule = .{
                .filter = "qos2/#",
                .qos = .exactly_once,
                .local_prefix = "mirror/",
            },
            .bridge_id = [_]u8{0xb2} ** 16,
        },
        &bridge_shutdown,
    );
    const resumed = try bridge.connect();
    try std.testing.expect(resumed.session_present);
    try std.testing.expect(try bridge.step(.{
        .timeout = operation_timeout,
        .cancellation_check_interval = .fromMilliseconds(20),
    }));
    var publisher_pubcomp = try publisher.readPubComp();
    defer publisher_pubcomp.deinit(allocator);
    try std.testing.expectEqual(packet_id, publisher_pubcomp.ack.packet_id);
    try publisher.applyPubComp(publisher_pubcomp.ack);
    try std.testing.expect(!local.containsBridgeQoS2(.{
        .bridge_id = [_]u8{0xb2} ** 16,
        .session_epoch = bridge.session_epoch,
        .packet_id = staged_packet_id,
    }));

    var local_event = try subscriber.readClientPacketEventWithTimeout(
        operation_timeout,
    );
    defer local_event.deinit(allocator);
    switch (local_event) {
        .publish => |delivery| {
            try std.testing.expectEqualStrings(
                "mirror/qos2/device/state",
                delivery.publish.topic,
            );
            try std.testing.expectEqualStrings(
                "exactly-once",
                delivery.publish.payload,
            );
            try std.testing.expectEqual(
                mqtt.QoS.exactly_once,
                delivery.publish.qos,
            );
            try subscriber.writePubRec(delivery.publish.packet_id.?, 0);
        },
        else => return error.TestUnexpectedResult,
    }
    var downstream_pubrel = try subscriber.readPubRel();
    defer downstream_pubrel.deinit(allocator);
    try subscriber.writePubComp(downstream_pubrel.ack.packet_id, 0);
    try std.testing.expectEqual(@as(usize, 1), local.stats().publish_messages_received);

    try bridge.disconnect(0);
    try subscriber.disconnect(0);
    try publisher.disconnect(0);
    try remote_runner.stop(io, remote_thread);
    remote_joined = true;
    try local_runner.stop(io, local_thread);
    local_joined = true;
}

test "inbound bridge releases QoS2 exactly once across restart" {
    try exerciseInboundBridgeQoS2ExactlyOnce(.v3_1_1);
    try exerciseInboundBridgeQoS2ExactlyOnce(.v5);
}

test "inbound bridge withholds upstream PUBACK until local injection succeeds" {
    const allocator = std.testing.allocator;
    const operation_timeout = std.Io.Duration.fromSeconds(2);
    const short_timeout = std.Io.Duration.fromMilliseconds(150);

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var local = try broker_mod.Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 1,
                .max_queued_deliveries_per_connection = 4,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{ .protocol = .v5 },
        },
    );
    defer local.deinit();
    var local_runner = BrokerRunner{
        .broker = &local,
        .accept_concurrency = 1,
    };
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

    var remote = try broker_mod.Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 2,
                .max_queued_deliveries_per_connection = 4,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{ .protocol = .v5 },
        },
    );
    defer remote.deinit();
    var remote_runner = BrokerRunner{
        .broker = &remote,
        .accept_concurrency = 2,
    };
    const remote_thread = try std.Thread.spawn(
        .{},
        BrokerRunner.run,
        .{&remote_runner},
    );
    var remote_joined = false;
    defer if (!remote_joined) {
        remote_runner.shutdown.set(io);
        remote_thread.join();
    };

    var bridge_shutdown: std.Io.Event = .unset;
    var bridge = try bridge_mod.Bridge.init(
        allocator,
        io,
        &local,
        remote.address(),
        .{
            .connect = .{
                .protocol = .v5,
                .client_id = "inbound-bridge-retry",
                .clean_start = false,
                .properties = &session_expiry_properties,
                .connect_timeout = operation_timeout,
                .network_connect_timeout = operation_timeout,
            },
            .reconnect_policy = .{
                .initial_delay = .fromMilliseconds(1),
                .max_delay = .fromMilliseconds(8),
            },
            .rule = .{
                .filter = "retry/#",
                .qos = .at_least_once,
                .local_prefix = "mirror/",
            },
        },
        &bridge_shutdown,
    );
    defer bridge.deinit();

    const connected = try bridge.connect();
    try std.testing.expect(!connected.session_present);

    var upstream_publisher = try runtime.Client.connectWithTimeout(
        allocator,
        io,
        remote.address(),
        .{
            .protocol = .v5,
            .client_id = "bridge-upstream-retry-publisher",
            .clean_start = false,
            .properties = &session_expiry_properties,
        },
        operation_timeout,
    );
    defer upstream_publisher.close();
    const upstream_packet_id = (try upstream_publisher.writePublish(
        "retry/device/state",
        "retry-once",
        .{
            .qos = .at_least_once,
            .properties = &.{.{ .utf8_pair = .{
                .id = .user_property,
                .key = "attempt",
                .value = "first",
            } }},
        },
    )).?;
    var upstream_ack = try upstream_publisher.readClientPacketEventWithTimeout(
        operation_timeout,
    );
    defer upstream_ack.deinit(allocator);
    switch (upstream_ack) {
        .puback => |ack| {
            try std.testing.expectEqual(upstream_packet_id, ack.ack.packet_id);
            try upstream_publisher.applyPubAck(ack.ack);
        },
        else => return error.TestUnexpectedResult,
    }

    var first_delivery = (try bridge.client.pollWithTimeout(operation_timeout)).?;
    defer first_delivery.deinit(allocator);
    try std.testing.expect(first_delivery == .publish);
    try std.testing.expect(!first_delivery.publish.publish.dup);
    var inject_failure = InjectFailure{};
    try std.testing.expectError(
        error.TestExpectedError,
        bridge_mod.testing.injectPublishWithFault(
            &bridge,
            &first_delivery.publish.publish,
            .{
                .context = &inject_failure,
                .fail_once = InjectFailure.failOnce,
            },
        ),
    );
    try std.testing.expect(inject_failure.seen);
    try std.testing.expectEqual(
        first_delivery.publish.publish.packet_id.?,
        inject_failure.packet_id,
    );
    try std.testing.expectEqual(@as(usize, 0), local.stats().publish_messages_received);
    try std.testing.expectEqual(
        @as(usize, 1),
        remote.stats().session_inflight_messages,
    );

    bridge.client.disconnectTransport();
    const reconnected = try bridge.client.connectWithTimeout(operation_timeout);
    try std.testing.expect(reconnected.session_present);

    var redelivery = (try bridge.client.pollWithTimeout(operation_timeout)).?;
    defer redelivery.deinit(allocator);
    try std.testing.expect(redelivery == .publish);
    try std.testing.expect(redelivery.publish.publish.dup);
    try std.testing.expectEqual(
        inject_failure.packet_id,
        redelivery.publish.publish.packet_id.?,
    );
    try std.testing.expectEqualStrings(
        "retry/device/state",
        redelivery.publish.publish.topic,
    );
    try std.testing.expectEqualStrings(
        "retry-once",
        redelivery.publish.publish.payload,
    );

    var local_subscriber = try runtime.Client.connectWithTimeout(
        allocator,
        io,
        local.address(),
        .{
            .protocol = .v5,
            .client_id = "bridge-local-retry-subscriber",
            .clean_start = false,
            .properties = &session_expiry_properties,
        },
        operation_timeout,
    );
    defer local_subscriber.close();
    var local_suback = try local_subscriber.subscribe(
        &.{.{
            .topic_filter = "mirror/retry/#",
            .qos = .at_least_once,
        }},
        .{},
    );
    defer local_suback.deinit(allocator);
    try std.testing.expectEqual(
        @as(u8, 1),
        local_suback.suback.reason_codes[0],
    );
    try expectNoPublish(&local_subscriber, short_timeout);

    try bridge_mod.testing.injectPublish(
        &bridge,
        &redelivery.publish.publish,
    );

    var local_event = try local_subscriber.readClientPacketEventWithTimeout(
        operation_timeout,
    );
    defer local_event.deinit(allocator);
    switch (local_event) {
        .publish => |delivery| {
            try std.testing.expectEqualStrings(
                "mirror/retry/device/state",
                delivery.publish.topic,
            );
            try std.testing.expectEqualStrings(
                "retry-once",
                delivery.publish.payload,
            );
            try std.testing.expectEqual(
                mqtt.QoS.at_least_once,
                delivery.publish.qos,
            );
            try std.testing.expect(!delivery.publish.dup);
            try expectUserProperty(
                delivery.publish.properties,
                "attempt",
                "first",
            );
            try local_subscriber.writePubAck(
                delivery.publish.packet_id.?,
                0,
            );
        },
        else => return error.TestUnexpectedResult,
    }
    try expectNoPublish(&local_subscriber, short_timeout);
    try std.testing.expectEqual(@as(usize, 1), local.stats().publish_messages_received);

    // A PINGREQ/PINGRESP round trip provides a deterministic barrier after the
    // bridge's upstream PUBACK and local flush sequence.
    try bridge.client.connection().?.pingWithTimeout(operation_timeout);
    try std.testing.expectEqual(
        @as(usize, 0),
        remote.stats().session_inflight_messages,
    );

    try bridge.client.disconnect(0);
    try local_subscriber.disconnect(0);
    try upstream_publisher.disconnect(0);
    try remote_runner.stop(io, remote_thread);
    remote_joined = true;
    try local_runner.stop(io, local_thread);
    local_joined = true;
}
