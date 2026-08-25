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
