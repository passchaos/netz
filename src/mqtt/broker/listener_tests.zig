const std = @import("std");
const context = @import("../broker_tests.zig");
const tls_testing = @import("../../tls/testing.zig");

const mqtt = context.TestContext.mqtt_mod;
const Broker = context.TestContext.BrokerType;
const runtime = context.TestContext.runtime_mod;
const disconnectAll = context.TestContext.disconnectAllFn;
const waitForPeerClose = context.TestContext.waitForPeerCloseFn;

const session_expiry = [_]mqtt.Property{
    .{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 30,
    } },
};

const ListenerServeState = struct {
    broker: *Broker,
    listeners: []const mqtt.broker.Listener,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.broker.serveListeners(self.listeners) catch |err| {
            self.err = err;
        };
    }
};

test "broker shares mounted WSS and global TCP listener namespaces" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var broker = try Broker.init(allocator, io, .{
        .limits = .{
            .max_connections = 3,
            .max_queued_deliveries_per_connection = 8,
            .runtime = .{ .max_packet_size = 4096 },
        },
    });
    defer broker.deinit();
    var global_server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer global_server.deinit();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var mounted_server = try mqtt.websocket_runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .limits = .{ .max_packet_size = 4096 },
            .max_head_bytes = 4096,
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer mounted_server.deinit();

    const listeners = [_]mqtt.broker.Listener{
        .{
            .source = global_server.pendingSource(),
            .connection_count = 1,
        },
        .{
            .source = mounted_server.pendingSource(),
            .namespace = try mqtt.listener_namespace.Namespace.init(
                "secure/",
            ),
            .connection_count = 2,
        },
    };
    var shared = ListenerServeState{
        .broker = &broker,
        .listeners = &listeners,
    };
    const thread = try std.Thread.spawn(
        .{},
        ListenerServeState.run,
        .{&shared},
    );
    var joined = false;
    defer if (!joined) thread.join();

    var global = try runtime.Client.connect(
        allocator,
        io,
        global_server.address(),
        .{ .protocol = .v5, .client_id = "global-tcp" },
    );
    defer global.close();

    const uri = try std.fmt.allocPrint(
        allocator,
        "wss://localhost:{d}/mqtt",
        .{mounted_server.address().ip4.port},
    );
    defer allocator.free(uri);
    const wss_options: mqtt.websocket_runtime.ConnectOptions = .{
        .mqtt = .{
            .protocol = .v5,
            .client_id = "mounted-wss-subscriber",
            .limits = .{ .max_packet_size = 4096 },
        },
        // Pinning keeps this test hermetic while still exercising the real
        // TLS 1.3 and HTTP Upgrade path used by a production WSS listener.
        .use_vail_tls = true,
        .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        },
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .max_head_bytes = 4096,
    };
    var mounted = try mqtt.websocket_runtime.Client.connectUri(
        allocator,
        io,
        uri,
        wss_options,
    );
    defer mounted.close();
    var publisher_options = wss_options;
    publisher_options.mqtt.client_id = "mounted-wss-publisher";
    var publisher = try mqtt.websocket_runtime.Client.connectUri(
        allocator,
        io,
        uri,
        publisher_options,
    );
    defer publisher.close();

    var global_suback = try global.subscribe(
        &.{.{ .topic_filter = "secure/#" }},
        .{},
    );
    defer global_suback.deinit(allocator);
    var mounted_suback = try mounted.subscribe(
        &.{.{ .topic_filter = "#" }},
        .{},
    );
    defer mounted_suback.deinit(allocator);
    try publisher.publish("room/value", "over-wss", .{});

    var global_delivery = try global.readPublish();
    defer global_delivery.deinit(allocator);
    try std.testing.expectEqualStrings(
        "secure/room/value",
        global_delivery.publish.topic,
    );
    try std.testing.expectEqualStrings(
        "over-wss",
        global_delivery.publish.payload,
    );
    var mounted_delivery = try mounted.readPublish();
    defer mounted_delivery.deinit(allocator);
    try std.testing.expectEqualStrings(
        "room/value",
        mounted_delivery.publish.topic,
    );
    try std.testing.expectEqualStrings(
        "over-wss",
        mounted_delivery.publish.payload,
    );

    try disconnectAll(&.{ &global, &mounted, &publisher });
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "durable Session projects queued topics through reconnect listener" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var broker = try Broker.init(allocator, io, .{
        .limits = .{
            .max_connections = 3,
            .max_queued_deliveries_per_connection = 8,
            .runtime = .{ .max_packet_size = 4096 },
        },
    });
    defer broker.deinit();
    var global_server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer global_server.deinit();
    var mounted_server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer mounted_server.deinit();

    const listeners = [_]mqtt.broker.Listener{
        .{
            .source = global_server.pendingSource(),
            .connection_count = 2,
        },
        .{
            .source = mounted_server.pendingSource(),
            .namespace = try mqtt.listener_namespace.Namespace.init(
                "tenant/",
            ),
            .connection_count = 1,
        },
    };
    var shared = ListenerServeState{
        .broker = &broker,
        .listeners = &listeners,
    };
    const thread = try std.Thread.spawn(
        .{},
        ListenerServeState.run,
        .{&shared},
    );
    var joined = false;
    defer if (!joined) thread.join();

    // Session subscriptions live in canonical broker space, rather than being
    // tied to the transport that happened to establish them. This global
    // subscription is therefore safe to resume through the mounted listener.
    var first = try runtime.Client.connect(
        allocator,
        io,
        global_server.address(),
        .{
            .protocol = .v5,
            .client_id = "cross-listener-session",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    defer first.close();
    var suback = try first.subscribe(
        &.{.{
            .topic_filter = "tenant/offline/#",
            .qos = .at_least_once,
        }},
        .{},
    );
    defer suback.deinit(allocator);
    try first.disconnect(0);
    try waitForPeerClose(&first);

    var publisher = try runtime.Client.connect(
        allocator,
        io,
        global_server.address(),
        .{ .protocol = .v5, .client_id = "cross-listener-publisher" },
    );
    defer publisher.close();
    try publisher.publish(
        "tenant/offline/value",
        "queued",
        .{ .qos = .at_least_once },
    );

    var resumed_result = try runtime.Client.connectWithConnAck(
        allocator,
        io,
        mounted_server.address(),
        .{
            .protocol = .v5,
            .client_id = "cross-listener-session",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    var resumed = resumed_result.connection;
    defer resumed.close();
    defer resumed_result.connack.deinit(allocator);
    try std.testing.expect(resumed_result.connack.connack.session_present);
    var delivery = try resumed.readPublish();
    defer delivery.deinit(allocator);
    try std.testing.expectEqualStrings(
        "offline/value",
        delivery.publish.topic,
    );
    try std.testing.expectEqualStrings("queued", delivery.publish.payload);
    try resumed.writePubAck(delivery.publish.packet_id.?, 0);

    try disconnectAll(&.{ &publisher, &resumed });
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "durable Session drops queued topics outside reconnect namespace" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var broker = try Broker.init(allocator, io, .{
        .limits = .{
            .max_connections = 3,
            .max_queued_deliveries_per_connection = 8,
            .runtime = .{ .max_packet_size = 4096 },
        },
    });
    defer broker.deinit();
    var global_server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer global_server.deinit();
    var mounted_server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer mounted_server.deinit();

    const listeners = [_]mqtt.broker.Listener{
        .{
            .source = global_server.pendingSource(),
            .connection_count = 2,
        },
        .{
            .source = mounted_server.pendingSource(),
            .namespace = try mqtt.listener_namespace.Namespace.init(
                "tenant/",
            ),
            .connection_count = 1,
        },
    };
    var shared = ListenerServeState{
        .broker = &broker,
        .listeners = &listeners,
    };
    const thread = try std.Thread.spawn(
        .{},
        ListenerServeState.run,
        .{&shared},
    );
    var joined = false;
    defer if (!joined) thread.join();

    var first = try runtime.Client.connect(
        allocator,
        io,
        global_server.address(),
        .{
            .protocol = .v5,
            .client_id = "cross-namespace-session",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    defer first.close();
    var suback = try first.subscribe(
        &.{.{
            .topic_filter = "#",
            .qos = .at_least_once,
        }},
        .{},
    );
    defer suback.deinit(allocator);
    try first.disconnect(0);
    try waitForPeerClose(&first);

    var publisher = try runtime.Client.connect(
        allocator,
        io,
        global_server.address(),
        .{ .protocol = .v5, .client_id = "namespace-filter-publisher" },
    );
    defer publisher.close();
    try publisher.publish(
        "outside/value",
        "hidden",
        .{ .qos = .at_least_once },
    );
    try publisher.publish(
        "tenant/inside/value",
        "visible",
        .{ .qos = .at_least_once },
    );

    var resumed_result = try runtime.Client.connectWithConnAck(
        allocator,
        io,
        mounted_server.address(),
        .{
            .protocol = .v5,
            .client_id = "cross-namespace-session",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    var resumed = resumed_result.connection;
    defer resumed.close();
    defer resumed_result.connack.deinit(allocator);
    try std.testing.expect(resumed_result.connack.connack.session_present);
    var delivery = try resumed.readPublish();
    defer delivery.deinit(allocator);
    try std.testing.expectEqualStrings(
        "inside/value",
        delivery.publish.topic,
    );
    try std.testing.expectEqualStrings("visible", delivery.publish.payload);
    try resumed.writePubAck(delivery.publish.packet_id.?, 0);
    try resumed.ping();

    try disconnectAll(&.{ &publisher, &resumed });
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "mounted listeners keep shared subscription groups namespace-local" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var broker = try Broker.init(allocator, io, .{
        .limits = .{
            .max_connections = 3,
            .max_queued_deliveries_per_connection = 8,
            .runtime = .{ .max_packet_size = 4096 },
        },
    });
    defer broker.deinit();
    var first_server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer first_server.deinit();
    var second_server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer second_server.deinit();

    const listeners = [_]mqtt.broker.Listener{
        .{
            .source = first_server.pendingSource(),
            .namespace = try mqtt.listener_namespace.Namespace.init(
                "east/",
            ),
            .connection_count = 2,
        },
        .{
            .source = second_server.pendingSource(),
            .namespace = try mqtt.listener_namespace.Namespace.init(
                "west/",
            ),
            .connection_count = 1,
        },
    };
    var shared = ListenerServeState{
        .broker = &broker,
        .listeners = &listeners,
    };
    const thread = try std.Thread.spawn(
        .{},
        ListenerServeState.run,
        .{&shared},
    );
    var joined = false;
    defer if (!joined) thread.join();

    var east = try runtime.Client.connect(
        allocator,
        io,
        first_server.address(),
        .{ .protocol = .v5, .client_id = "east-worker" },
    );
    defer east.close();
    var publisher = try runtime.Client.connect(
        allocator,
        io,
        first_server.address(),
        .{ .protocol = .v5, .client_id = "east-publisher" },
    );
    defer publisher.close();
    var west = try runtime.Client.connect(
        allocator,
        io,
        second_server.address(),
        .{ .protocol = .v5, .client_id = "west-worker" },
    );
    defer west.close();

    // The shared wrapper is routing metadata. Mapping the filter below must
    // produce `$share/workers/east/jobs/#`, not prefix `$share` itself. The
    // same client-visible group/filter on west therefore remains independent.
    var east_suback = try east.subscribe(
        &.{.{ .topic_filter = "$share/workers/jobs/#" }},
        .{},
    );
    defer east_suback.deinit(allocator);
    var west_suback = try west.subscribe(
        &.{.{ .topic_filter = "$share/workers/jobs/#" }},
        .{},
    );
    defer west_suback.deinit(allocator);

    try publisher.publish("jobs/one", "east-only", .{});
    var delivery = try east.readPublish();
    defer delivery.deinit(allocator);
    try std.testing.expectEqualStrings(
        "jobs/one",
        delivery.publish.topic,
    );
    try std.testing.expectEqualStrings(
        "east-only",
        delivery.publish.payload,
    );
    // A PING round trip proves west has no unexpected PUBLISH queued ahead of
    // PINGRESP, so identically named shared groups did not cross namespaces.
    try west.ping();

    try disconnectAll(&.{ &east, &publisher, &west });
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "listeners apply independent Maximum QoS policies" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var broker = try Broker.init(allocator, io, .{
        .limits = .{
            .max_connections = 3,
            .max_queued_deliveries_per_connection = 8,
            .runtime = .{ .max_packet_size = 4096 },
        },
    });
    defer broker.deinit();
    var unrestricted_server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer unrestricted_server.deinit();
    var qos0_server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer qos0_server.deinit();

    var qos0_accept = broker.options.accept;
    qos0_accept.maximum_qos = .at_most_once;
    const listeners = [_]mqtt.broker.Listener{
        .{
            .source = unrestricted_server.pendingSource(),
            .connection_count = 2,
        },
        .{
            .source = qos0_server.pendingSource(),
            .accept = qos0_accept,
            .connection_count = 1,
        },
    };
    var shared = ListenerServeState{
        .broker = &broker,
        .listeners = &listeners,
    };
    const thread = try std.Thread.spawn(
        .{},
        ListenerServeState.run,
        .{&shared},
    );
    var joined = false;
    defer if (!joined) thread.join();

    var qos0_result = try runtime.Client.connectWithConnAck(
        allocator,
        io,
        qos0_server.address(),
        .{ .protocol = .v5, .client_id = "qos0-listener-subscriber" },
    );
    var qos0_subscriber = qos0_result.connection;
    defer qos0_subscriber.close();
    defer qos0_result.connack.deinit(allocator);
    try std.testing.expectEqual(
        mqtt.QoS.at_most_once,
        mqtt.maximumQoS(qos0_result.connack.connack.properties).?,
    );
    var qos0_suback = try qos0_subscriber.subscribe(
        &.{.{
            .topic_filter = "listener/qos",
            .qos = .at_least_once,
        }},
        .{},
    );
    defer qos0_suback.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &.{@intFromEnum(mqtt.QoS.at_most_once)},
        qos0_suback.suback.reason_codes,
    );

    var unrestricted = try runtime.Client.connect(
        allocator,
        io,
        unrestricted_server.address(),
        .{ .protocol = .v5, .client_id = "unrestricted-subscriber" },
    );
    defer unrestricted.close();
    var unrestricted_suback = try unrestricted.subscribe(
        &.{.{
            .topic_filter = "listener/qos",
            .qos = .at_least_once,
        }},
        .{},
    );
    defer unrestricted_suback.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &.{@intFromEnum(mqtt.QoS.at_least_once)},
        unrestricted_suback.suback.reason_codes,
    );

    var publisher = try runtime.Client.connect(
        allocator,
        io,
        unrestricted_server.address(),
        .{ .protocol = .v5, .client_id = "listener-policy-publisher" },
    );
    defer publisher.close();
    try publisher.publish(
        "listener/qos",
        "per-listener",
        .{ .qos = .at_least_once },
    );

    var restricted_delivery = try qos0_subscriber.readPublish();
    defer restricted_delivery.deinit(allocator);
    try std.testing.expectEqual(
        mqtt.QoS.at_most_once,
        restricted_delivery.publish.qos,
    );
    var unrestricted_delivery = try unrestricted.readPublish();
    defer unrestricted_delivery.deinit(allocator);
    try std.testing.expectEqual(
        mqtt.QoS.at_least_once,
        unrestricted_delivery.publish.qos,
    );
    try unrestricted.writePubAck(
        unrestricted_delivery.publish.packet_id.?,
        0,
    );

    try disconnectAll(&.{ &qos0_subscriber, &unrestricted, &publisher });
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "listeners apply independent CONNECT authorization policies" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const GlobalPolicy = struct {
        calls: std.atomic.Value(usize) = .init(0),

        fn authorize(
            context_ptr: *anyopaque,
            connect: mqtt.Connect,
        ) bool {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            _ = self.calls.fetchAdd(1, .monotonic);
            return connect.password != null and
                std.mem.eql(u8, connect.password.?, "global-secret");
        }
    };
    const PrivatePolicy = struct {
        calls: std.atomic.Value(usize) = .init(0),

        fn authorize(
            context_ptr: *anyopaque,
            connect: mqtt.Connect,
        ) bool {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            _ = self.calls.fetchAdd(1, .monotonic);
            return connect.username != null and
                std.mem.eql(u8, connect.username.?, "private-user");
        }
    };

    var global_policy: GlobalPolicy = .{};
    var private_policy: PrivatePolicy = .{};
    var broker = try Broker.init(allocator, io, .{
        .limits = .{
            .max_connections = 3,
            .max_queued_deliveries_per_connection = 8,
            .runtime = .{ .max_packet_size = 4096 },
        },
        .connect_authorization = .{
            .context = &global_policy,
            .authorize = GlobalPolicy.authorize,
        },
    });
    defer broker.deinit();
    var public_server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer public_server.deinit();
    var private_server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer private_server.deinit();

    const listeners = [_]mqtt.broker.Listener{
        .{
            .source = public_server.pendingSource(),
            .connection_count = 1,
        },
        .{
            .source = private_server.pendingSource(),
            .authorization = .{
                .connect = .{
                    .context = &private_policy,
                    .authorize = PrivatePolicy.authorize,
                },
            },
            .connection_count = 2,
        },
    };
    var shared = ListenerServeState{
        .broker = &broker,
        .listeners = &listeners,
    };
    const thread = try std.Thread.spawn(
        .{},
        ListenerServeState.run,
        .{&shared},
    );
    var joined = false;
    defer if (!joined) thread.join();

    // The global policy applies to every listener, while the public endpoint
    // has no extra credential requirement.
    var public = try runtime.Client.connect(
        allocator,
        io,
        public_server.address(),
        .{
            .protocol = .v5,
            .client_id = "listener-auth-public",
            .password = "global-secret",
        },
    );
    defer public.close();
    try public.ping();

    // The same globally valid credential is refused on the private listener
    // until its additional listener-local username policy is also satisfied.
    var refused = try runtime.Client.connectAttempt(
        allocator,
        io,
        private_server.address(),
        .{
            .protocol = .v5,
            .client_id = "listener-auth-denied",
            .username = "wrong-user",
            .password = "global-secret",
        },
    );
    defer refused.deinit(allocator);
    try std.testing.expect(!refused.accepted());
    try std.testing.expectEqual(
        @as(u8, 0x87),
        refused.connack.connack.reason_code,
    );

    var private = try runtime.Client.connect(
        allocator,
        io,
        private_server.address(),
        .{
            .protocol = .v5,
            .client_id = "listener-auth-private",
            .username = "private-user",
            .password = "global-secret",
        },
    );
    defer private.close();
    try private.ping();

    try disconnectAll(&.{ &public, &private });
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(
        @as(usize, 3),
        global_policy.calls.load(.monotonic),
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        private_policy.calls.load(.monotonic),
    );
    try std.testing.expectEqual(@as(usize, 0), broker.sessions.count());
}

test "durable Session delivery uses reconnect listener Maximum QoS" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var broker = try Broker.init(allocator, io, .{
        .limits = .{
            .max_connections = 1,
            .max_queued_deliveries_per_connection = 8,
            .runtime = .{ .max_packet_size = 4096 },
        },
    });
    defer broker.deinit();
    var setup_server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer setup_server.deinit();

    const setup_listeners = [_]mqtt.broker.Listener{.{
        .source = setup_server.pendingSource(),
        .connection_count = 1,
    }};
    var setup_serve = ListenerServeState{
        .broker = &broker,
        .listeners = &setup_listeners,
    };
    const setup_thread = try std.Thread.spawn(
        .{},
        ListenerServeState.run,
        .{&setup_serve},
    );
    var setup_joined = false;
    defer if (!setup_joined) setup_thread.join();

    var first = try runtime.Client.connect(
        allocator,
        io,
        setup_server.address(),
        .{
            .protocol = .v5,
            .client_id = "listener-qos-session",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    defer first.close();
    var suback = try first.subscribe(
        &.{.{
            .topic_filter = "listener/durable",
            .qos = .at_least_once,
        }},
        .{},
    );
    defer suback.deinit(allocator);
    try first.disconnect(0);
    try waitForPeerClose(&first);
    setup_thread.join();
    setup_joined = true;
    if (setup_serve.err) |err| return err;

    try broker.enqueueSessionPublish(
        "listener-qos-session",
        .{
            .dup = false,
            .qos = .at_least_once,
            .retain = false,
            .topic = "listener/durable",
            .packet_id = 1,
            .payload = "queued",
        },
        .at_least_once,
        false,
        null,
    );

    var qos0_server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer qos0_server.deinit();
    var qos0_accept = broker.options.accept;
    qos0_accept.maximum_qos = .at_most_once;
    const reconnect_listeners = [_]mqtt.broker.Listener{.{
        .source = qos0_server.pendingSource(),
        .accept = qos0_accept,
        .connection_count = 1,
    }};
    var reconnect_serve = ListenerServeState{
        .broker = &broker,
        .listeners = &reconnect_listeners,
    };
    const reconnect_thread = try std.Thread.spawn(
        .{},
        ListenerServeState.run,
        .{&reconnect_serve},
    );
    var reconnect_joined = false;
    defer if (!reconnect_joined) reconnect_thread.join();

    var resumed_result = try runtime.Client.connectWithConnAck(
        allocator,
        io,
        qos0_server.address(),
        .{
            .protocol = .v5,
            .client_id = "listener-qos-session",
            .clean_start = false,
            .properties = &session_expiry,
        },
    );
    var resumed = resumed_result.connection;
    defer resumed.close();
    defer resumed_result.connack.deinit(allocator);
    try std.testing.expect(resumed_result.connack.connack.session_present);
    try std.testing.expectEqual(
        mqtt.QoS.at_most_once,
        mqtt.maximumQoS(resumed_result.connack.connack.properties).?,
    );
    var delivery = try resumed.readPublish();
    defer delivery.deinit(allocator);
    try std.testing.expectEqual(mqtt.QoS.at_most_once, delivery.publish.qos);
    try std.testing.expect(delivery.publish.packet_id == null);
    try std.testing.expectEqualStrings("queued", delivery.publish.payload);

    try resumed.disconnect(0);
    reconnect_thread.join();
    reconnect_joined = true;
    if (reconnect_serve.err) |err| return err;
}

test "refused listener admission releases the only broker slot" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var broker = try Broker.init(allocator, io, .{
        .limits = .{
            .max_connections = 1,
            .max_queued_deliveries_per_connection = 1,
            .runtime = .{ .max_packet_size = 4096 },
        },
        .accept = .{ .allow_zero_length_client_id = false },
    });
    defer broker.deinit();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer server.deinit();

    const listener = mqtt.broker.Listener{
        .source = server.pendingSource(),
        .namespace = try mqtt.listener_namespace.Namespace.init("mount/"),
        .connection_count = 1,
    };
    var first_serve = ListenerServeState{
        .broker = &broker,
        .listeners = &.{listener},
    };
    const first_thread = try std.Thread.spawn(
        .{},
        ListenerServeState.run,
        .{&first_serve},
    );
    var first_joined = false;
    defer if (!first_joined) first_thread.join();

    var refused = try runtime.Client.connectAttempt(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "",
            .clean_start = true,
        },
    );
    defer refused.deinit(allocator);
    try std.testing.expect(!refused.accepted());
    first_thread.join();
    first_joined = true;
    if (first_serve.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 0), broker.stats().active_connections);

    // Reusing the same Broker and listener in a second finite batch proves the
    // refused CONNECT released both transport ownership and the reserved slot.
    var second_serve = ListenerServeState{
        .broker = &broker,
        .listeners = &.{listener},
    };
    const second_thread = try std.Thread.spawn(
        .{},
        ListenerServeState.run,
        .{&second_serve},
    );
    var second_joined = false;
    defer if (!second_joined) second_thread.join();
    var accepted = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .protocol = .v5, .client_id = "accepted-after-refusal" },
    );
    defer accepted.close();
    try accepted.ping();
    try accepted.disconnect(0);
    second_thread.join();
    second_joined = true;
    if (second_serve.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 0), broker.stats().active_connections);
}

test "listener supervisor replaces clients until graceful shutdown" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var broker = try Broker.init(allocator, io, .{
        .limits = .{
            .max_connections = 1,
            .max_queued_deliveries_per_connection = 1,
            .runtime = .{ .max_packet_size = 4096 },
        },
    });
    defer broker.deinit();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer server.deinit();

    const Supervisor = struct {
        broker: *Broker,
        endpoint: mqtt.broker.ListenerEndpoint,
        shutdown: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.broker.serveListenersUntil(&.{self.endpoint}, .{
                .shutdown = &self.shutdown,
            }) catch |err| {
                self.err = err;
            };
        }
    };
    var supervisor = Supervisor{
        .broker = &broker,
        .endpoint = .{ .source = server.pendingSource() },
    };
    const thread = try std.Thread.spawn(.{}, Supervisor.run, .{&supervisor});
    var joined = false;
    defer if (!joined) {
        supervisor.shutdown.set(io);
        thread.join();
    };

    var first = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .protocol = .v5, .client_id = "supervised-first" },
    );
    defer first.close();
    try first.ping();
    try first.disconnect(0);
    try waitForPeerClose(&first);

    // `accept_concurrency=1` is a permanent accept/connection worker rather
    // than a finite connection budget: it must accept again after teardown.
    var second = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .protocol = .v5, .client_id = "supervised-second" },
    );
    defer second.close();
    try second.ping();
    // Shutdown cancels both a blocked accept and this active connection, then
    // waits for broker unregister/transport cleanup before returning.
    supervisor.shutdown.set(io);
    try waitForPeerClose(&second);

    thread.join();
    joined = true;
    if (supervisor.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 0), broker.stats().active_connections);
}

test "listener supervisor isolates malformed CONNECT errors" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var broker = try Broker.init(allocator, io, .{
        .limits = .{
            .max_connections = 1,
            .max_queued_deliveries_per_connection = 1,
            .runtime = .{ .max_packet_size = 4096 },
        },
    });
    defer broker.deinit();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer server.deinit();

    const Observer = struct {
        io: std.Io,
        observed: std.Io.Event = .unset,
        count: std.atomic.Value(usize) = .init(0),
        listener_index: usize = std.math.maxInt(usize),
        stage: mqtt.broker.ListenerErrorStage = .connection,
        err: ?anyerror = null,

        fn observe(context_ptr: *anyopaque, event: mqtt.broker.ListenerErrorEvent) void {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            self.listener_index = event.listener_index;
            self.stage = event.stage;
            self.err = event.err;
            _ = self.count.fetchAdd(1, .release);
            self.observed.set(self.io);
        }
    };
    const Supervisor = struct {
        broker: *Broker,
        endpoint: mqtt.broker.ListenerEndpoint,
        shutdown: std.Io.Event = .unset,
        observer: *Observer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.broker.serveListenersUntil(&.{self.endpoint}, .{
                .shutdown = &self.shutdown,
                .error_observer = .{
                    .context = self.observer,
                    .observe = Observer.observe,
                },
            }) catch |err| {
                self.err = err;
            };
        }
    };
    var observer = Observer{ .io = io };
    var supervisor = Supervisor{
        .broker = &broker,
        .endpoint = .{ .source = server.pendingSource() },
        .observer = &observer,
    };
    const thread = try std.Thread.spawn(.{}, Supervisor.run, .{&supervisor});
    var joined = false;
    defer if (!joined) {
        supervisor.shutdown.set(io);
        thread.join();
    };

    const malformed = try server.address().connect(io, .{ .mode = .stream });
    const malformed_bytes = [_]u8{ 0xc0, 0x00 };
    var malformed_writer = malformed.writer(io, &.{});
    try malformed_writer.interface.writeAll(&malformed_bytes);
    malformed.close(io);
    try observer.observed.wait(io);
    try std.testing.expectEqual(@as(usize, 1), observer.count.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), observer.listener_index);
    try std.testing.expectEqual(
        mqtt.broker.ListenerErrorStage.accept,
        observer.stage,
    );
    try std.testing.expect(observer.err != null);

    // The default policy treats malformed peers as connection-local. The same
    // accept worker must remain alive and admit a subsequent valid client.
    var accepted = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .protocol = .v5, .client_id = "valid-after-malformed" },
    );
    defer accepted.close();
    try accepted.ping();
    supervisor.shutdown.set(io);
    try waitForPeerClose(&accepted);

    thread.join();
    joined = true;
    if (supervisor.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 0), broker.stats().active_connections);
}

test "listener supervisor can stop on an accept error" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var broker = try Broker.init(allocator, io, .{
        .limits = .{
            .max_connections = 1,
            .max_queued_deliveries_per_connection = 1,
            .runtime = .{ .max_packet_size = 4096 },
        },
    });
    defer broker.deinit();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer server.deinit();

    const Supervisor = struct {
        broker: *Broker,
        endpoint: mqtt.broker.ListenerEndpoint,
        shutdown: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.broker.serveListenersUntil(&.{self.endpoint}, .{
                .shutdown = &self.shutdown,
                .accept_error_policy = .stop,
            }) catch |err| {
                self.err = err;
            };
        }
    };
    var supervisor = Supervisor{
        .broker = &broker,
        .endpoint = .{ .source = server.pendingSource() },
    };
    const thread = try std.Thread.spawn(.{}, Supervisor.run, .{&supervisor});

    const malformed = try server.address().connect(io, .{ .mode = .stream });
    const malformed_bytes = [_]u8{ 0xc0, 0x00 };
    var malformed_writer = malformed.writer(io, &.{});
    try malformed_writer.interface.writeAll(&malformed_bytes);
    malformed.close(io);

    thread.join();
    try std.testing.expectEqual(error.UnexpectedPacket, supervisor.err.?);
    try std.testing.expectEqual(@as(usize, 0), broker.stats().active_connections);
}
