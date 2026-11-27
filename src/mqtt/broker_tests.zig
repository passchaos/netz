const std = @import("std");
const test_tmp = @import("../internal/test_tmp_dir.zig");
const mqtt = @import("mod.zig");
const broker_mod = @import("broker.zig");
const runtime = @import("runtime.zig");
const runtime_backend = @import("../runtime.zig");

const Broker = broker_mod.Broker;

pub const TestContext = struct {
    pub const mqtt_mod = mqtt;
    pub const BrokerType = Broker;
    pub const DeliveryAuthorization = broker_mod.DeliveryAuthorization;
    pub const ConnectContext = broker_mod.ConnectContext;
    pub const WillAuthorization = broker_mod.WillAuthorization;
    pub const RetainedSourceAuthorization =
        broker_mod.RetainedSourceAuthorization;
    pub const runtime_mod = runtime;
    pub const ServeStateType = ServeState;

    pub const testBrokerFn = testBroker;
    pub const connectFn = connect;
    pub const connectWithOptionsFn = connectWithOptions;
    pub const disconnectAllFn = disconnectAll;
    pub const waitForPeerCloseFn = waitForPeerClose;
    pub const joinServerFn = joinServer;
    pub const writeDuplicatePublishFn = writeDuplicatePublish;
    pub const writePublishWithPacketIdFn = writePublishWithPacketId;
};

pub fn connectWithOptions(
    allocator: std.mem.Allocator,
    io: std.Io,
    broker: Broker,
    options: runtime.ConnectOptions,
) !runtime.Connection {
    return runtime.Client.connect(
        allocator,
        io,
        broker.address(),
        options,
    );
}

const ServeState = struct {
    broker: *Broker,
    connection_count: usize,
    err: ?anyerror = null,

    pub fn run(self: *@This()) void {
        self.broker.serve(self.connection_count) catch |err| {
            self.err = err;
        };
    }
};

fn testBroker(
    allocator: std.mem.Allocator,
    io: std.Io,
    connection_count: usize,
    max_outgoing_inflight: u16,
) !Broker {
    return Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = connection_count,
                .max_queued_deliveries_per_connection = 8,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{
                .protocol = .v5,
                .max_outgoing_inflight = max_outgoing_inflight,
            },
        },
    );
}

fn connect(
    allocator: std.mem.Allocator,
    io: std.Io,
    broker: Broker,
    client_id: []const u8,
    properties: []const mqtt.Property,
) !runtime.Connection {
    return runtime.Client.connect(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = client_id,
            .properties = properties,
        },
    );
}

fn disconnectAll(connections: []const *runtime.Connection) !void {
    for (connections) |connection| try connection.disconnect(0);
}

fn waitForPeerClose(connection: *runtime.Connection) !void {
    while (true) {
        var scratch: [1]u8 = undefined;
        var bufs = [_][]u8{&scratch};
        const result = connection.transport.tcp.io.vtable.netRead(
            connection.transport.tcp.io.userdata,
            connection.transport.tcp.stream.socket.handle,
            &bufs,
        );
        if (result) |read_count| {
            if (read_count == 0) return;
        } else |err| switch (err) {
            error.SocketUnconnected,
            error.ConnectionResetByPeer,
            => return,
            else => return err,
        }
    }
}

fn joinServer(
    thread: std.Thread,
    joined: *bool,
    state: *const ServeState,
) !void {
    thread.join();
    joined.* = true;
    if (state.err) |err| return err;
}

fn writeDuplicatePublish(
    connection: *runtime.Connection,
    topic_name: []const u8,
    payload: []const u8,
    packet_id: u16,
) !void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try mqtt.writePublish(
        &encoded,
        std.testing.allocator,
        .v5,
        topic_name,
        payload,
        .{
            .qos = .exactly_once,
            .dup = true,
            .packet_id = packet_id,
        },
    );
    try connection.transport.writePacket(encoded.items);
}

fn writePublishWithPacketId(
    connection: *runtime.Connection,
    topic_name: []const u8,
    payload: []const u8,
    packet_id: u16,
) !void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try mqtt.writePublish(
        &encoded,
        std.testing.allocator,
        connection.protocol,
        topic_name,
        payload,
        .{
            .qos = .exactly_once,
            .packet_id = packet_id,
        },
    );
    try connection.transport.writePacket(encoded.items);
}

fn subscribeWithIdentifier(
    connection: *runtime.Connection,
    subscription: mqtt.Subscription,
    identifier: usize,
) !runtime.OwnedSubAck {
    return connection.subscribe(
        &.{subscription},
        .{ .properties = &.{.{ .varint = .{
            .id = .subscription_identifier,
            .value = identifier,
        } }} },
    );
}

test "broker rejects unconfigured Enhanced Authentication with CONNACK" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var broker = try testBroker(allocator, io, 1, 16);
    defer broker.deinit();
    var serve = ServeState{
        .broker = &broker,
        .connection_count = 1,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    const properties = [_]mqtt.Property{
        .{ .utf8 = .{
            .id = .authentication_method,
            .value = "unsupported",
        } },
        .{ .binary = .{
            .id = .authentication_data,
            .value = "test",
        } },
    };
    var attempt = try runtime.Client.connectAttempt(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "p",
            .properties = &properties,
        },
    );
    defer attempt.deinit(allocator);
    try std.testing.expect(!attempt.accepted());
    try std.testing.expectEqual(@as(u8, 0x8c), attempt.connack.connack.reason_code);
    try std.testing.expectEqual(@as(usize, 0), attempt.connack.connack.properties.len);

    try joinServer(thread, &joined, &serve);
}

test "broker authentication policy rejects before Session admission" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const Policy = struct {
        calls: usize = 0,

        fn start(
            context: *anyopaque,
            pending: *runtime.PendingAcceptedClient,
        ) broker_mod.Error!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            try pending.rejectAuthentication(0x87);
        }

        fn handle(
            _: *anyopaque,
            _: *runtime.Connection,
            _: mqtt.Auth,
            _: bool,
        ) broker_mod.Error!void {
            return error.InvalidAuthenticationState;
        }
    };
    var policy: Policy = .{};
    var broker = try Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 1,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .authentication = .{
                .context = &policy,
                .start = Policy.start,
                .handle = Policy.handle,
            },
        },
    );
    defer broker.deinit();
    var serve = ServeState{
        .broker = &broker,
        .connection_count = 1,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var attempt = try runtime.Client.connectAttempt(
        allocator,
        io,
        broker.address(),
        .{
            .protocol = .v5,
            .client_id = "policy-rejected-auth",
            .properties = &.{
                .{ .utf8 = .{
                    .id = .authentication_method,
                    .value = "single",
                } },
                .{ .binary = .{
                    .id = .authentication_data,
                    .value = "baddata",
                } },
            },
        },
    );
    defer attempt.deinit(allocator);
    try std.testing.expect(!attempt.accepted());
    try std.testing.expectEqual(
        @as(u8, 0x87),
        attempt.connack.connack.reason_code,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        attempt.connack.connack.properties.len,
    );
    try std.testing.expectEqual(@as(usize, 1), policy.calls);

    try joinServer(thread, &joined, &serve);
}

test "broker administrative reauthorization is selective and suppresses Will" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var broker = try testBroker(allocator, io, 3, 16);
    defer broker.deinit();
    var serve = ServeState{
        .broker = &broker,
        .connection_count = 3,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var observer = try connectWithOptions(allocator, io, broker, .{
        .protocol = .v5,
        .client_id = "reauthorize-observer",
        .username = "stable",
    });
    defer observer.close();
    var suback = try observer.subscribe(&.{.{
        .topic_filter = "reauthorize/will",
    }}, .{});
    defer suback.deinit(allocator);

    var revoked = try connectWithOptions(allocator, io, broker, .{
        .protocol = .v5,
        .client_id = "reauthorize-revoked",
        .username = "revoked",
        .will = .{
            .topic = "reauthorize/will",
            .payload = "must-not-publish",
        },
    });
    defer revoked.close();
    var legacy_revoked = try connectWithOptions(allocator, io, broker, .{
        .protocol = .v3_1_1,
        .client_id = "reauthorize-revoked-v311",
        .username = "revoked",
        .will = .{
            .topic = "reauthorize/will",
            .payload = "legacy-must-not-publish",
        },
    });
    defer legacy_revoked.close();

    const Policy = struct {
        fn stillAuthorized(
            _: *anyopaque,
            connection: broker_mod.ActiveConnectionAuthorization,
        ) bool {
            const username = connection.username orelse return true;
            return !std.mem.eql(u8, username, "revoked");
        }
    };
    var context: u8 = 0;
    try std.testing.expectEqual(
        @as(usize, 2),
        broker.disconnectUnauthorizedConnections(.{
            .context = &context,
            .still_authorized = Policy.stillAuthorized,
        }),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        broker.disconnectUnauthorizedConnections(.{
            .context = &context,
            .still_authorized = Policy.stillAuthorized,
        }),
    );
    var disconnect = try revoked.readDisconnect();
    defer disconnect.deinit(allocator);
    try std.testing.expectEqual(
        @as(u8, 0x98),
        disconnect.disconnect.reason_code,
    );
    try waitForPeerClose(&legacy_revoked);

    // PING is an ordering barrier for prior routed traffic. If the
    // administrative close were treated as a transport failure, the revoked
    // client's Will would be queued before this PINGRESP.
    try observer.ping();
    try std.testing.expectError(
        error.Timeout,
        observer.readClientPacketEventWithTimeout(.fromMilliseconds(20)),
    );
    try observer.disconnect(0);

    try joinServer(thread, &joined, &serve);
}

test "broker shares mounted and global TCP listener namespaces" {
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
    const mount = try mqtt.listener_namespace.Namespace.init("mount/");
    const listeners = [_]broker_mod.Listener{
        .{
            .source = global_server.pendingSource(),
            .connection_count = 1,
        },
        .{
            .source = mounted_server.pendingSource(),
            .namespace = mount,
            .connection_count = 2,
        },
    };

    const Shared = struct {
        broker: *Broker,
        listeners: []const broker_mod.Listener,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.broker.serveListeners(self.listeners) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{
        .broker = &broker,
        .listeners = &listeners,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var global = try runtime.Client.connect(
        allocator,
        io,
        global_server.address(),
        .{ .protocol = .v5, .client_id = "global" },
    );
    defer global.close();
    var mounted = try runtime.Client.connect(
        allocator,
        io,
        mounted_server.address(),
        .{ .protocol = .v5, .client_id = "mounted" },
    );
    defer mounted.close();
    var publisher = try runtime.Client.connect(
        allocator,
        io,
        mounted_server.address(),
        .{ .protocol = .v5, .client_id = "publisher" },
    );
    defer publisher.close();

    var global_suback = try global.subscribe(
        &.{.{ .topic_filter = "mount/#" }},
        .{},
    );
    defer global_suback.deinit(allocator);
    var mounted_suback = try mounted.subscribe(
        &.{.{ .topic_filter = "#" }},
        .{},
    );
    defer mounted_suback.deinit(allocator);
    try publisher.publish("room/value", "payload", .{});

    var global_delivery = try global.readPublish();
    defer global_delivery.deinit(allocator);
    try std.testing.expectEqualStrings(
        "mount/room/value",
        global_delivery.publish.topic,
    );
    var mounted_delivery = try mounted.readPublish();
    defer mounted_delivery.deinit(allocator);
    try std.testing.expectEqualStrings(
        "room/value",
        mounted_delivery.publish.topic,
    );

    try disconnectAll(&.{ &global, &mounted, &publisher });
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "mounted listener keeps retained and Will topics inside its namespace" {
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
    const listeners = [_]broker_mod.Listener{
        .{
            .source = global_server.pendingSource(),
            .connection_count = 1,
        },
        .{
            .source = mounted_server.pendingSource(),
            .namespace = try mqtt.listener_namespace.Namespace.init("mount/"),
            .connection_count = 2,
        },
    };
    const Shared = struct {
        broker: *Broker,
        listeners: []const broker_mod.Listener,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.broker.serveListeners(self.listeners) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .broker = &broker, .listeners = &listeners };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var global = try runtime.Client.connect(
        allocator,
        io,
        global_server.address(),
        .{ .protocol = .v5, .client_id = "global-observer" },
    );
    defer global.close();
    var mounted_publisher = try runtime.Client.connect(
        allocator,
        io,
        mounted_server.address(),
        .{
            .protocol = .v5,
            .client_id = "mounted-will",
            .will = .{
                .topic = "status",
                .payload = "offline",
            },
        },
    );
    defer mounted_publisher.close();

    var global_suback = try global.subscribe(
        &.{.{ .topic_filter = "mount/#" }},
        .{},
    );
    defer global_suback.deinit(allocator);
    try mounted_publisher.publish(
        "retained/value",
        "saved",
        .{ .retain = true },
    );
    var live = try global.readPublish();
    defer live.deinit(allocator);
    try std.testing.expectEqualStrings(
        "mount/retained/value",
        live.publish.topic,
    );

    // Abrupt close publishes the namespaced Will through the same canonical
    // route used by ordinary traffic.
    try mounted_publisher.shutdown();
    var will = try global.readPublish();
    defer will.deinit(allocator);
    try std.testing.expectEqualStrings("mount/status", will.publish.topic);
    try std.testing.expectEqualStrings("offline", will.publish.payload);

    var mounted_subscriber = try runtime.Client.connect(
        allocator,
        io,
        mounted_server.address(),
        .{ .protocol = .v5, .client_id = "mounted-replay" },
    );
    defer mounted_subscriber.close();
    var mounted_suback = try mounted_subscriber.subscribe(
        &.{.{ .topic_filter = "retained/#" }},
        .{},
    );
    defer mounted_suback.deinit(allocator);
    var replay = try mounted_subscriber.readPublish();
    defer replay.deinit(allocator);
    try std.testing.expectEqualStrings(
        "retained/value",
        replay.publish.topic,
    );
    try std.testing.expectEqualStrings("saved", replay.publish.payload);

    try disconnectAll(&.{ &global, &mounted_subscriber });
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "broker routes QoS 1 across live TCP clients" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 2, 64);
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 2,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var subscriber = try connect(
        allocator,
        io,
        broker,
        "subscriber",
        &.{},
    );
    defer subscriber.close();
    var publisher = try connect(
        allocator,
        io,
        broker,
        "publisher",
        &.{},
    );
    defer publisher.close();

    var suback = try subscriber.subscribe(
        &.{.{ .topic_filter = "bench/+", .qos = .at_least_once }},
        .{},
    );
    defer suback.deinit(allocator);
    try publisher.publish(
        "bench/value",
        "payload",
        .{ .qos = .at_least_once },
    );
    var delivered = try subscriber.readPublish();
    defer delivered.deinit(allocator);
    try std.testing.expectEqualStrings(
        "payload",
        delivered.publish.payload,
    );
    try subscriber.writePubAck(delivered.publish.packet_id.?, 0);

    try disconnectAll(&.{ &subscriber, &publisher });
    try joinServer(thread, &joined, &serve);
}

test "broker merges overlapping live subscriptions at the queue tail" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 2, 64);
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 2,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var subscriber = try connect(
        allocator,
        io,
        broker,
        "overlap-subscriber",
        &.{},
    );
    defer subscriber.close();
    var publisher = try connect(
        allocator,
        io,
        broker,
        "overlap-publisher",
        &.{},
    );
    defer publisher.close();

    var first_suback = try subscribeWithIdentifier(
        &subscriber,
        .{ .topic_filter = "overlap/#", .qos = .at_least_once },
        3,
    );
    defer first_suback.deinit(allocator);
    var second_suback = try subscribeWithIdentifier(
        &subscriber,
        .{ .topic_filter = "overlap/+", .qos = .at_least_once },
        9,
    );
    defer second_suback.deinit(allocator);

    try publisher.publish(
        "overlap/value",
        "merged",
        .{ .qos = .at_least_once },
    );
    var delivered = try subscriber.readPublish();
    defer delivered.deinit(allocator);
    try std.testing.expectEqualStrings("merged", delivered.publish.payload);
    var identifiers: [2]usize = undefined;
    var identifier_count: usize = 0;
    for (delivered.publish.properties) |property| {
        if (property == .varint and
            property.varint.id == .subscription_identifier)
        {
            if (identifier_count == identifiers.len) {
                return error.TestUnexpectedResult;
            }
            identifiers[identifier_count] = property.varint.value;
            identifier_count += 1;
        }
    }
    try std.testing.expectEqualSlices(
        usize,
        &.{ 3, 9 },
        identifiers[0..identifier_count],
    );
    try subscriber.writePubAck(delivered.publish.packet_id.?, 0);
    try std.testing.expectError(
        error.Timeout,
        subscriber.readClientPacketEventWithTimeout(.fromMilliseconds(50)),
    );

    try disconnectAll(&.{ &subscriber, &publisher });
    try joinServer(thread, &joined, &serve);
}

test "broker trusted local publication uses normal live routing" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 1, 64);
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 1,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var subscriber = try connect(
        allocator,
        io,
        broker,
        "local-injection-subscriber",
        &.{},
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{
            .topic_filter = "bridge/in/#",
            .qos = .at_least_once,
        }},
        .{},
    );
    defer suback.deinit(allocator);

    var source_properties = [_]mqtt.Property{.{ .utf8_pair = .{
        .id = .user_property,
        .key = "source",
        .value = "remote",
    } }};
    try broker.publishLocal(.{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "bridge/in/value",
        .packet_id = null,
        .properties = &source_properties,
        .payload = "forwarded",
    });
    var delivered = try subscriber.readPublish();
    defer delivered.deinit(allocator);
    try std.testing.expectEqualStrings(
        "bridge/in/value",
        delivered.publish.topic,
    );
    try std.testing.expectEqualStrings(
        "forwarded",
        delivered.publish.payload,
    );
    try std.testing.expectEqual(mqtt.QoS.at_least_once, delivered.publish.qos);
    var found_source = false;
    for (delivered.publish.properties) |property| {
        if (property == .utf8_pair and
            property.utf8_pair.id == .user_property and
            std.mem.eql(u8, property.utf8_pair.key, "source") and
            std.mem.eql(u8, property.utf8_pair.value, "remote"))
        {
            found_source = true;
        }
    }
    try std.testing.expect(found_source);
    try subscriber.writePubAck(delivered.publish.packet_id.?, 0);

    const stats = broker.stats();
    try std.testing.expectEqual(@as(usize, 1), stats.publish_messages_received);
    try std.testing.expectEqual(
        @as(usize, "forwarded".len),
        stats.publish_payload_bytes_received,
    );

    try disconnectAll(&.{&subscriber});
    try joinServer(thread, &joined, &serve);
}

test "broker trusted local publication rejects connection-scoped metadata" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var broker = try Broker.init(allocator, threaded.io(), .{});
    defer broker.deinit();

    const base = mqtt.Publish{
        .dup = false,
        .qos = .at_most_once,
        .retain = false,
        .topic = "bridge/value",
        .packet_id = null,
        .payload = "payload",
    };
    var invalid = base;
    invalid.dup = true;
    try std.testing.expectError(
        error.InvalidPacketIdentifier,
        broker.publishLocal(invalid),
    );
    invalid = base;
    invalid.packet_id = 7;
    try std.testing.expectError(
        error.InvalidPacketIdentifier,
        broker.publishLocal(invalid),
    );
    invalid = base;
    var alias_properties = [_]mqtt.Property{.{ .two_byte = .{
        .id = .topic_alias,
        .value = 1,
    } }};
    invalid.properties = &alias_properties;
    try std.testing.expectError(
        error.InvalidProperty,
        broker.publishLocal(invalid),
    );
    invalid = base;
    var subscription_properties = [_]mqtt.Property{.{ .varint = .{
        .id = .subscription_identifier,
        .value = 1,
    } }};
    invalid.properties = &subscription_properties;
    try std.testing.expectError(
        error.InvalidProperty,
        broker.publishLocal(invalid),
    );
    invalid = base;
    var payload_properties = [_]mqtt.Property{.{ .byte = .{
        .id = .payload_format_indicator,
        .value = 1,
    } }};
    invalid.properties = &payload_properties;
    invalid.payload = &.{0xff};
    try std.testing.expectError(
        error.InvalidUtf8,
        broker.publishLocal(invalid),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        broker.stats().publish_messages_received,
    );
}

test "broker bridge QoS2 stages durably and releases once" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 1, 64);
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 1,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();
    var subscriber = try connect(
        allocator,
        io,
        broker,
        "bridge-qos2-subscriber",
        &.{},
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{ .topic_filter = "bridge/qos2/#", .qos = .exactly_once }},
        .{},
    );
    defer suback.deinit(allocator);

    const key = broker_mod.BridgeQoS2Key{
        .bridge_id = [_]u8{0x61} ** 16,
        .session_epoch = 1,
        .packet_id = 7,
    };
    try std.testing.expectEqual(
        broker_mod.BridgeQoS2StageResult.inserted,
        try broker.stageBridgeQoS2(key, .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "bridge/qos2/value",
            .packet_id = null,
            .payload = "once",
        }, .{}),
    );
    try std.testing.expectEqual(
        broker_mod.BridgeQoS2StageResult.duplicate,
        try broker.stageBridgeQoS2(key, .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "bridge/qos2/value",
            .packet_id = null,
            .payload = "once",
        }, .{ .duplicate = true }),
    );
    try std.testing.expectEqual(
        broker_mod.BridgeQoS2ReleaseResult.applied,
        (try broker.releaseBridgeQoS2(key)).disposition,
    );
    var delivered = try subscriber.readPublish();
    defer delivered.deinit(allocator);
    try std.testing.expectEqualStrings(
        "bridge/qos2/value",
        delivered.publish.topic,
    );
    try std.testing.expectEqualStrings("once", delivered.publish.payload);
    try subscriber.writePubRec(delivered.publish.packet_id.?, 0);
    var pubrel = try subscriber.readPubRel();
    defer pubrel.deinit(allocator);
    try subscriber.writePubComp(pubrel.ack.packet_id, 0);

    try std.testing.expectEqual(
        broker_mod.BridgeQoS2ReleaseResult.already_applied,
        (try broker.releaseBridgeQoS2(key)).disposition,
    );
    try std.testing.expectError(
        error.Timeout,
        subscriber.readClientPacketEventWithTimeout(
            .fromMilliseconds(20),
        ),
    );
    try std.testing.expect(try broker.completeBridgeQoS2(key));
    try std.testing.expect(!(try broker.completeBridgeQoS2(key)));
    try std.testing.expectEqual(
        broker_mod.BridgeQoS2ReleaseResult.unknown,
        (try broker.releaseBridgeQoS2(key)).disposition,
    );

    try disconnectAll(&.{&subscriber});
    try joinServer(thread, &joined, &serve);
}

test "transient Session fanout does not consume durable queue bytes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 2,
                .max_queued_deliveries_per_connection = 8,
                .runtime = .{ .max_packet_size = 4096 },
            },
            // The payload below intentionally exceeds this per-Session owned
            // byte limit. Expiry-zero clients must deliver it from the shared
            // live Publication rather than cloning it into durable storage.
            .session = .{ .max_session_bytes = 64 },
            .accept = .{ .max_outgoing_inflight = 64 },
        },
    );
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 2,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var subscriber = try connect(
        allocator,
        io,
        broker,
        "transient-sub",
        &.{},
    );
    defer subscriber.close();
    var publisher = try connect(
        allocator,
        io,
        broker,
        "transient-pub",
        &.{},
    );
    defer publisher.close();
    var suback = try subscriber.subscribe(
        &.{.{
            .topic_filter = "transient/value",
            .qos = .at_least_once,
        }},
        .{},
    );
    defer suback.deinit(allocator);

    var payload: [256]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index);
    try publisher.publish(
        "transient/value",
        &payload,
        .{ .qos = .at_least_once },
    );
    var delivered = try subscriber.readPublish();
    defer delivered.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &payload,
        delivered.publish.payload,
    );
    try subscriber.writePubAck(delivered.publish.packet_id.?, 0);

    try disconnectAll(&.{ &subscriber, &publisher });
    try joinServer(thread, &joined, &serve);
}

test "transient inflight payload bytes gate QoS 1 delivery" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 2,
                .max_queued_deliveries_per_connection = 8,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .max_inflight_payload_bytes_per_connection = 10,
            .accept = .{ .max_outgoing_inflight = 5 },
        },
    );
    defer broker.deinit();

    var serve = ServeState{ .broker = &broker, .connection_count = 2 };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var subscriber = try connect(allocator, io, broker, "byte-qos1-sub", &.{});
    defer subscriber.close();
    var publisher = try connect(allocator, io, broker, "byte-qos1-pub", &.{});
    defer publisher.close();
    var suback = try subscriber.subscribe(
        &.{.{ .topic_filter = "inflight/bytes/qos1", .qos = .at_least_once }},
        .{},
    );
    defer suback.deinit(allocator);

    for ([_][]const u8{ "123456", "789012", "third" }) |payload| {
        try publisher.publish(
            "inflight/bytes/qos1",
            payload,
            .{ .qos = .at_least_once },
        );
    }

    var first = try subscriber.readPublish();
    defer first.deinit(allocator);
    var second = try subscriber.readPublish();
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("123456", first.publish.payload);
    try std.testing.expectEqualStrings("789012", second.publish.payload);
    try std.testing.expectError(
        error.Timeout,
        subscriber.readClientPacketEventWithTimeout(.fromMilliseconds(50)),
    );

    try subscriber.writePubAck(first.publish.packet_id.?, 0);
    var third = try subscriber.readPublish();
    defer third.deinit(allocator);
    try std.testing.expectEqualStrings("third", third.publish.payload);
    try subscriber.writePubAck(second.publish.packet_id.?, 0);
    try subscriber.writePubAck(third.publish.packet_id.?, 0);

    try disconnectAll(&.{ &subscriber, &publisher });
    try joinServer(thread, &joined, &serve);
}

test "transient inflight payload bytes remain charged through PUBCOMP" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 2,
                .max_queued_deliveries_per_connection = 8,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .max_inflight_payload_bytes_per_connection = 10,
            .accept = .{ .max_outgoing_inflight = 5 },
        },
    );
    defer broker.deinit();

    var serve = ServeState{ .broker = &broker, .connection_count = 2 };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var subscriber = try connect(allocator, io, broker, "byte-qos2-sub", &.{});
    defer subscriber.close();
    var publisher = try connect(allocator, io, broker, "byte-qos2-pub", &.{});
    defer publisher.close();
    var suback = try subscriber.subscribe(
        &.{.{ .topic_filter = "inflight/bytes/qos2", .qos = .exactly_once }},
        .{},
    );
    defer suback.deinit(allocator);

    for ([_][]const u8{ "123456", "789012", "third" }) |payload| {
        try publisher.publish(
            "inflight/bytes/qos2",
            payload,
            .{ .qos = .exactly_once },
        );
    }

    var first = try subscriber.readPublish();
    defer first.deinit(allocator);
    var second = try subscriber.readPublish();
    defer second.deinit(allocator);
    try subscriber.writePubRec(first.publish.packet_id.?, 0);
    var first_pubrel = try subscriber.readPubRel();
    defer first_pubrel.deinit(allocator);
    try std.testing.expectEqual(
        first.publish.packet_id.?,
        first_pubrel.ack.packet_id,
    );
    try std.testing.expectError(
        error.Timeout,
        subscriber.readClientPacketEventWithTimeout(.fromMilliseconds(50)),
    );

    try subscriber.writePubComp(first_pubrel.ack.packet_id, 0);
    var third = try subscriber.readPublish();
    defer third.deinit(allocator);
    try std.testing.expectEqualStrings("third", third.publish.payload);

    try subscriber.writePubRec(second.publish.packet_id.?, 0);
    var second_pubrel = try subscriber.readPubRel();
    defer second_pubrel.deinit(allocator);
    try subscriber.writePubComp(second_pubrel.ack.packet_id, 0);
    try subscriber.writePubRec(third.publish.packet_id.?, 0);
    var third_pubrel = try subscriber.readPubRel();
    defer third_pubrel.deinit(allocator);
    try subscriber.writePubComp(third_pubrel.ack.packet_id, 0);

    try disconnectAll(&.{ &subscriber, &publisher });
    try joinServer(thread, &joined, &serve);
}

test "broker applies No Local while acknowledging the matched subscription" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 1, 64);
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 1,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try connect(allocator, io, broker, "self", &.{});
    defer client.close();
    var suback = try client.subscribe(
        &.{.{
            .topic_filter = "self/#",
            .qos = .at_least_once,
            .no_local = true,
        }},
        .{},
    );
    defer suback.deinit(allocator);

    const packet_id = (try client.writePublish(
        "self/value",
        "not-looped-back",
        .{ .qos = .at_least_once },
    )).?;
    var puback = try client.readPubAck();
    defer puback.deinit(allocator);
    try std.testing.expectEqual(packet_id, puback.ack.packet_id);
    try std.testing.expectEqual(@as(u8, 0), puback.ack.reason_code);
    try client.applyPubAck(puback.ack);

    try disconnectAll(&.{&client});
    try joinServer(thread, &joined, &serve);
}

test "broker rotates shared subscriptions across live clients" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 3, 64);
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 3,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var first = try connect(allocator, io, broker, "worker-a", &.{});
    defer first.close();
    var second = try connect(allocator, io, broker, "worker-b", &.{});
    defer second.close();
    var publisher = try connect(
        allocator,
        io,
        broker,
        "shared-publisher",
        &.{},
    );
    defer publisher.close();

    var first_suback = try first.subscribe(
        &.{.{
            .topic_filter = "$share/work/jobs/+",
            .qos = .at_least_once,
        }},
        .{},
    );
    defer first_suback.deinit(allocator);
    var second_suback = try second.subscribe(
        &.{.{
            .topic_filter = "$share/work/jobs/+",
            .qos = .at_least_once,
        }},
        .{},
    );
    defer second_suback.deinit(allocator);

    try publisher.publish(
        "jobs/one",
        "first",
        .{ .qos = .at_least_once },
    );
    var first_delivery = try first.readPublish();
    defer first_delivery.deinit(allocator);
    try std.testing.expectEqualStrings(
        "first",
        first_delivery.publish.payload,
    );
    try first.writePubAck(first_delivery.publish.packet_id.?, 0);

    try publisher.publish(
        "jobs/two",
        "second",
        .{ .qos = .at_least_once },
    );
    var second_delivery = try second.readPublish();
    defer second_delivery.deinit(allocator);
    try std.testing.expectEqualStrings(
        "second",
        second_delivery.publish.payload,
    );
    try second.writePubAck(second_delivery.publish.packet_id.?, 0);

    try disconnectAll(&.{ &first, &second, &publisher });
    try joinServer(thread, &joined, &serve);
}

test "broker queues QoS 1 delivery until Receive Maximum credit returns" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 2, 64);
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 2,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var subscriber = try connect(
        allocator,
        io,
        broker,
        "slow-subscriber",
        &.{.{ .two_byte = .{
            .id = .receive_maximum,
            .value = 1,
        } }},
    );
    defer subscriber.close();
    var publisher = try connect(
        allocator,
        io,
        broker,
        "queue-publisher",
        &.{},
    );
    defer publisher.close();
    var suback = try subscriber.subscribe(
        &.{.{
            .topic_filter = "queue",
            .qos = .at_least_once,
        }},
        .{},
    );
    defer suback.deinit(allocator);

    // Both publisher acknowledgements arrive even though the subscriber has
    // only one outgoing slot. The second delivery remains broker-owned until
    // the first PUBACK returns credit.
    try publisher.publish(
        "queue",
        "one",
        .{ .qos = .at_least_once },
    );
    try publisher.publish(
        "queue",
        "two",
        .{ .qos = .at_least_once },
    );

    var first = try subscriber.readPublish();
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("one", first.publish.payload);
    try subscriber.writePubAck(first.publish.packet_id.?, 0);

    var second = try subscriber.readPublish();
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("two", second.publish.payload);
    try subscriber.writePubAck(second.publish.packet_id.?, 0);

    try disconnectAll(&.{ &subscriber, &publisher });
    try joinServer(thread, &joined, &serve);
}

test "broker statistics report coherent state and completed traffic" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 2, 64);
    defer broker.deinit();

    const empty = broker.stats();
    try std.testing.expectEqual(@as(usize, 0), empty.active_connections);
    try std.testing.expectEqual(
        @as(usize, 0),
        empty.maximum_active_connections,
    );
    try std.testing.expectEqual(@as(usize, 0), empty.expired_sessions);
    try std.testing.expectEqual(@as(u64, 0), empty.messages_received);
    try std.testing.expectEqual(@as(u64, 0), empty.messages_sent);
    try std.testing.expectEqual(@as(u64, 0), empty.bytes_received);
    try std.testing.expectEqual(@as(u64, 0), empty.bytes_sent);
    try std.testing.expectEqual(@as(usize, 0), empty.publish_messages_received);
    try std.testing.expectEqual(@as(usize, 0), empty.publish_messages_sent);
    try std.testing.expectEqual(@as(usize, 0), empty.publish_messages_dropped);
    try std.testing.expectEqual(
        @as(usize, 0),
        empty.publish_payload_bytes_received,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        empty.publish_payload_bytes_sent,
    );
    try std.testing.expectEqual(@as(usize, 0), empty.sessions);
    try std.testing.expectEqual(@as(usize, 0), empty.subscriptions);

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 2,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var subscriber = try connectWithOptions(
        allocator,
        io,
        broker,
        .{
            .protocol = .v5,
            .client_id = "stats-subscriber",
            .clean_start = false,
            .properties = &.{.{ .four_byte = .{
                .id = .session_expiry_interval,
                .value = 60,
            } }},
        },
    );
    defer subscriber.close();
    var publisher = try connect(
        allocator,
        io,
        broker,
        "stats-publisher",
        &.{},
    );
    defer publisher.close();
    var suback = try subscriber.subscribe(
        &.{
            .{
                .topic_filter = "metrics/#",
                .qos = .at_least_once,
            },
            .{
                .topic_filter = "$share/observers/metrics/+",
                .qos = .at_least_once,
            },
        },
        .{},
    );
    defer suback.deinit(allocator);
    try publisher.publish(
        "metrics/value",
        "retained-metric",
        .{ .qos = .at_least_once, .retain = true },
    );
    var delivered = try subscriber.readPublish();
    defer delivered.deinit(allocator);
    // Receiving bytes does not imply the peer's successful write syscall has
    // returned and published its traffic counters yet. A PING on the publisher
    // crosses the same broker task after both PUBACK and subscriber fanout. Its
    // own PINGRESP may still be between write and counter update when observed.
    // Leave the delivery unacknowledged to preserve the inflight gauge below.
    try publisher.ping();

    const stats_deadline = std.Io.Clock.awake.now(io).addDuration(
        .fromSeconds(2),
    );
    var live = broker.stats();
    while (live.messages_received < 5 or
        live.messages_sent < 6 or
        live.publish_messages_sent < 1)
    {
        if (std.Io.Clock.awake.now(io).nanoseconds >=
            stats_deadline.nanoseconds)
        {
            break;
        }
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
        live = broker.stats();
    }
    try std.testing.expectEqual(@as(usize, 2), live.active_connections);
    try std.testing.expectEqual(
        @as(usize, 2),
        live.maximum_active_connections,
    );
    try std.testing.expectEqual(@as(usize, 0), live.expired_sessions);
    // The finite broker wires its aggregate counter into every accept. Both
    // CONNECT packets, SUBSCRIBE, publisher PUBLISH, and the
    // synchronization PING have been read. The first five responses are
    // guaranteed counted; bounded convergence below admits the final PINGRESP.
    try std.testing.expectEqual(@as(u64, 5), live.messages_received);
    try std.testing.expectEqual(@as(u64, 6), live.messages_sent);
    try std.testing.expect(live.bytes_received > 0);
    try std.testing.expect(live.bytes_sent > 0);
    try std.testing.expectEqual(@as(usize, 1), live.publish_messages_received);
    try std.testing.expectEqual(@as(usize, 1), live.publish_messages_sent);
    try std.testing.expectEqual(@as(usize, 0), live.publish_messages_dropped);
    try std.testing.expectEqual(
        "retained-metric".len,
        live.publish_payload_bytes_received,
    );
    try std.testing.expectEqual(
        "retained-metric".len,
        live.publish_payload_bytes_sent,
    );
    try std.testing.expectEqual(@as(usize, 2), live.sessions);
    try std.testing.expectEqual(@as(usize, 2), live.connected_sessions);
    try std.testing.expectEqual(@as(usize, 0), live.disconnected_sessions);
    try std.testing.expectEqual(@as(usize, 2), live.subscriptions);
    try std.testing.expectEqual(@as(usize, 1), live.shared_subscriptions);
    try std.testing.expectEqual(@as(usize, 1), live.retained_messages);
    try std.testing.expect(live.retained_bytes > 0);
    try std.testing.expectEqual(@as(usize, 0), live.live_queued_deliveries);
    try std.testing.expectEqual(@as(usize, 0), live.session_queued_messages);
    try std.testing.expectEqual(@as(usize, 1), live.session_inflight_messages);
    try std.testing.expectEqual(
        "retained-metric".len,
        live.session_inflight_payload_bytes,
    );
    try std.testing.expectEqual(@as(usize, 0), live.pending_incoming_qos2);
    try std.testing.expectEqual(@as(usize, 0), live.scheduled_wills);
    try std.testing.expect(live.session_owned_bytes > 0);

    try subscriber.writePubAck(delivered.publish.packet_id.?, 0);
    try disconnectAll(&.{ &subscriber, &publisher });
    try joinServer(thread, &joined, &serve);

    const offline = broker.stats();
    try std.testing.expectEqual(@as(usize, 0), offline.active_connections);
    try std.testing.expectEqual(
        @as(usize, 2),
        offline.maximum_active_connections,
    );
    try std.testing.expectEqual(@as(usize, 0), offline.expired_sessions);
    try std.testing.expectEqual(@as(u64, 8), offline.messages_received);
    try std.testing.expectEqual(@as(u64, 6), offline.messages_sent);
    try std.testing.expectEqual(@as(u64, 2), offline.connections_received);
    try std.testing.expectEqual(@as(usize, 1), offline.sessions);
    try std.testing.expectEqual(@as(usize, 0), offline.connected_sessions);
    try std.testing.expectEqual(@as(usize, 1), offline.disconnected_sessions);
    try std.testing.expectEqual(@as(usize, 2), offline.subscriptions);
    try std.testing.expectEqual(@as(usize, 1), offline.shared_subscriptions);
    try std.testing.expectEqual(
        @as(usize, 0),
        offline.session_inflight_messages,
    );
}

test "broker publish counters include rejected ingress and wire delivery" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 2,
                .max_queued_deliveries_per_connection = 8,
                .max_payload_size = 4,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .accept = .{ .protocol = .v5 },
        },
    );
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 2,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var subscriber = try connect(
        allocator,
        io,
        broker,
        "counter-sub",
        &.{},
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{
            .topic_filter = "counter/#",
            .qos = .at_least_once,
        }},
        .{},
    );
    defer suback.deinit(allocator);

    var publisher = try connect(
        allocator,
        io,
        broker,
        "counter-pub",
        &.{},
    );
    defer publisher.close();
    try publisher.publish("counter/accepted", "good", .{});
    var delivered = try subscriber.readPublish();
    defer delivered.deinit(allocator);
    try std.testing.expectEqualStrings("good", delivered.publish.payload);

    // Mosquitto counts a parsed inbound PUBLISH even when policy later drops
    // it. QoS 0 has no negative acknowledgement and must not reach the peer.
    try publisher.publish("counter/rejected", "large", .{});
    try publisher.ping();
    try subscriber.ping();

    const stats = broker.stats();
    try std.testing.expectEqual(@as(usize, 2), stats.publish_messages_received);
    try std.testing.expectEqual(@as(usize, 1), stats.publish_messages_sent);
    try std.testing.expectEqual(
        "good".len + "large".len,
        stats.publish_payload_bytes_received,
    );
    try std.testing.expectEqual(
        "good".len,
        stats.publish_payload_bytes_sent,
    );

    try disconnectAll(&.{ &subscriber, &publisher });
    try joinServer(thread, &joined, &serve);
}

test "broker publishes coherent retained system statistics" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var broker = try testBroker(allocator, io, 1, 64);
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 1,
    };
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

    var subscriber = try connect(
        allocator,
        io,
        broker,
        "sys-subscriber",
        &.{},
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{
            .topic_filter = "$SYS/broker/clients/#",
            .qos = .at_most_once,
        }},
        .{},
    );
    defer suback.deinit(allocator);

    try broker.publishSystemStats();
    var received: usize = 0;
    while (received < 7) : (received += 1) {
        var publish = try subscriber.readPublish();
        defer publish.deinit(allocator);
        // Live subscribers follow normal MQTT routing semantics: retained
        // state is updated, while RETAIN is cleared unless the subscription
        // requested Retain As Published.
        try std.testing.expect(!publish.publish.retain);
        if (std.mem.eql(
            u8,
            publish.publish.topic,
            "$SYS/broker/clients/connected",
        )) {
            try std.testing.expectEqualStrings("1", publish.publish.payload);
        } else if (std.mem.eql(
            u8,
            publish.publish.topic,
            "$SYS/broker/clients/active",
        )) {
            try std.testing.expectEqualStrings("1", publish.publish.payload);
        } else if (std.mem.eql(
            u8,
            publish.publish.topic,
            "$SYS/broker/clients/inactive",
        )) {
            try std.testing.expectEqualStrings("0", publish.publish.payload);
        } else if (std.mem.eql(
            u8,
            publish.publish.topic,
            "$SYS/broker/clients/maximum",
        )) {
            try std.testing.expectEqualStrings("1", publish.publish.payload);
        } else if (std.mem.eql(
            u8,
            publish.publish.topic,
            "$SYS/broker/clients/disconnected",
        )) {
            try std.testing.expectEqualStrings("0", publish.publish.payload);
        } else if (std.mem.eql(
            u8,
            publish.publish.topic,
            "$SYS/broker/clients/expired",
        )) {
            try std.testing.expectEqualStrings("0", publish.publish.payload);
        } else if (std.mem.eql(
            u8,
            publish.publish.topic,
            "$SYS/broker/clients/total",
        )) {
            try std.testing.expectEqualStrings("1", publish.publish.payload);
        } else return error.UnexpectedSystemMetric;
    }

    try subscriber.disconnect(0);
    try joinServer(thread, &joined, &serve);

    const retained_count_before = broker.retained.count();
    try broker.publishSystemStats();
    try std.testing.expectEqual(
        retained_count_before,
        broker.retained.count(),
    );
    var storage: [1]mqtt.retained.Match = undefined;
    const retained = try broker.retained.matchInto(
        "$SYS/broker/clients/connected",
        std.Io.Clock.awake.now(io),
        &storage,
    );
    try std.testing.expectEqual(@as(usize, 1), retained.len);
    try std.testing.expectEqualStrings("0", retained[0].payload);
    try std.testing.expectEqual(mqtt.QoS.at_most_once, retained[0].qos);
    const connection_count = try broker.retained.matchInto(
        "$SYS/broker/load/connections/1min",
        std.Io.Clock.awake.now(io),
        &storage,
    );
    try std.testing.expectEqual(@as(usize, 1), connection_count.len);
    try std.testing.expect(
        (try std.fmt.parseFloat(f64, connection_count[0].payload)) > 0,
    );

    const traffic_metrics = [_]broker_mod.SystemMetric{
        .messages_received,
        .messages_sent,
        .messages_stored,
        .store_messages_count,
        .store_messages_bytes,
        .packet_out_count,
        .packet_out_bytes,
        .bytes_received,
        .bytes_sent,
        .publish_messages_received,
        .publish_messages_dropped,
        .publish_messages_sent,
        .publish_bytes_received,
        .publish_bytes_sent,
    };
    for (traffic_metrics) |metric| {
        const matched = try broker.retained.matchInto(
            metric.topic(),
            std.Io.Clock.awake.now(io),
            &storage,
        );
        try std.testing.expectEqual(@as(usize, 1), matched.len);
        const expected = switch (metric) {
            // Before the first snapshot the subscriber sent CONNECT and
            // SUBSCRIBE. It then sent DISCONNECT, so the second snapshot sees
            // all three complete inbound packets.
            .messages_received => "3",
            // CONNACK, SUBACK, and seven selected client metric PUBLISH
            // packets were complete before this second snapshot was captured.
            .messages_sent, .packet_out_count => "9",
            // One subscriber transport was accepted by the listener.
            .connections_socket_count => "1",
            // The subscriber's transient Session leaves no durable message
            // store behind after disconnect.
            .messages_stored,
            .store_messages_count,
            .store_messages_bytes,
            .publish_messages_received,
            .publish_messages_dropped,
            .publish_bytes_received,
            => "0",
            // The first snapshot delivered seven selected client metrics to
            // this subscriber. Those real wire PUBLISH packets contribute to
            // the following sent count/byte snapshot, as they do in Mosquitto.
            .publish_messages_sent, .publish_bytes_sent => "7",
            .bytes_received, .bytes_sent, .packet_out_bytes => {
                try std.testing.expect(try std.fmt.parseInt(
                    u64,
                    matched[0].payload,
                    10,
                ) > 0);
                continue;
            },
            else => unreachable,
        };
        try std.testing.expectEqualStrings(expected, matched[0].payload);
    }

    const uptime = try broker.retained.matchInto(
        broker_mod.SystemMetric.uptime.topic(),
        std.Io.Clock.awake.now(io),
        &storage,
    );
    try std.testing.expectEqual(@as(usize, 1), uptime.len);
    try std.testing.expect(std.mem.endsWith(u8, uptime[0].payload, " seconds"));
    _ = try std.fmt.parseInt(
        u64,
        uptime[0].payload[0 .. uptime[0].payload.len - " seconds".len],
        10,
    );

    const load_metrics_to_check = [_]broker_mod.SystemMetric{
        .load_connections_1min,
        .load_connections_5min,
        .load_connections_15min,
        .load_messages_received_1min,
        .load_messages_received_5min,
        .load_messages_received_15min,
        .load_messages_sent_1min,
        .load_messages_sent_5min,
        .load_messages_sent_15min,
        .load_publish_dropped_1min,
        .load_publish_dropped_5min,
        .load_publish_dropped_15min,
        .load_publish_received_1min,
        .load_publish_received_5min,
        .load_publish_received_15min,
        .load_publish_sent_1min,
        .load_publish_sent_5min,
        .load_publish_sent_15min,
        .load_bytes_received_1min,
        .load_bytes_received_5min,
        .load_bytes_received_15min,
        .load_bytes_sent_1min,
        .load_bytes_sent_5min,
        .load_bytes_sent_15min,
    };
    for (load_metrics_to_check) |metric| {
        const matched = try broker.retained.matchInto(
            metric.topic(),
            std.Io.Clock.awake.now(io),
            &storage,
        );
        try std.testing.expectEqual(@as(usize, 1), matched.len);
        const value = try std.fmt.parseFloat(f64, matched[0].payload);
        try std.testing.expect(std.math.isFinite(value));
        try std.testing.expect(value >= 0);
    }
    const sampled = broker.stats().load;
    try std.testing.expect(
        sampled.one_minute.messages_received >
            sampled.five_minutes.messages_received,
    );
    try std.testing.expect(
        sampled.five_minutes.messages_received >
            sampled.fifteen_minutes.messages_received,
    );
}

test "broker periodically publishes system statistics" {
    const allocator = std.testing.allocator;
    var backend = try runtime_backend.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var broker = try Broker.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .limits = .{
                .max_connections = 1,
                .max_queued_deliveries_per_connection = 32,
                .runtime = .{ .max_packet_size = 4096 },
            },
            .system_stats_interval = .fromMilliseconds(75),
        },
    );
    defer broker.deinit();

    var serve = ServeState{
        .broker = &broker,
        .connection_count = 1,
    };
    var server_task = io.async(ServeState.run, .{&serve});
    defer server_task.cancel(io);

    var subscriber = try connect(
        allocator,
        io,
        broker,
        "periodic-sys",
        &.{},
    );
    defer subscriber.close();
    var suback = try subscriber.subscribe(
        &.{.{
            .topic_filter = "$SYS/broker/clients/connected",
            .qos = .at_most_once,
        }},
        .{},
    );
    defer suback.deinit(allocator);

    var publish = try subscriber.readPublish();
    defer publish.deinit(allocator);
    try std.testing.expectEqualStrings(
        "$SYS/broker/clients/connected",
        publish.publish.topic,
    );
    try std.testing.expectEqualStrings("1", publish.publish.payload);
    try subscriber.disconnect(0);
    server_task.await(io);
    if (serve.err) |err| return err;
}

test "broker runtime delivery policy commits atomically" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var broker = try Broker.init(allocator, io, .{
        .limits = .{ .max_payload_size = 1 },
        .persistent_session_expiry_seconds = 10,
    });
    defer broker.deinit();

    const initial = broker.runtimeDeliveryPolicy();
    try std.testing.expectEqual(@as(usize, 1), initial.max_payload_size);
    try std.testing.expect(!initial.queue_qos0_messages);
    try std.testing.expect(!initial.upgrade_outgoing_qos);
    try std.testing.expect(initial.check_retain_source);
    try std.testing.expectEqual(
        @as(?u32, 10),
        initial.persistent_session_expiry_seconds,
    );

    try std.testing.expectError(
        error.InvalidProperty,
        broker.setRuntimeDeliveryPolicy(.{
            .max_payload_size = 2,
            .queue_qos0_messages = true,
            .upgrade_outgoing_qos = true,
            .check_retain_source = false,
            .persistent_session_expiry_seconds = 0,
        }),
    );
    try std.testing.expectEqualDeep(
        initial,
        broker.runtimeDeliveryPolicy(),
    );

    const updated = broker_mod.RuntimeDeliveryPolicy{
        .max_payload_size = 2,
        .queue_qos0_messages = true,
        .upgrade_outgoing_qos = true,
        .check_retain_source = false,
        .persistent_session_expiry_seconds = 1,
    };
    try broker.setRuntimeDeliveryPolicy(updated);
    try std.testing.expectEqualDeep(updated, broker.runtimeDeliveryPolicy());
}

test "broker persistent autosave target prepares and commits ownership" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();

    var broker = try Broker.init(allocator, io, .{});
    defer broker.deinit();
    try std.testing.expectError(
        error.InvalidProperty,
        broker.preparePersistentChangeAutosaveTarget(.{
            .dir = tmp.dir,
            .sub_path = "",
            .max_changes = 1,
        }),
    );

    var enabled = try broker.preparePersistentChangeAutosaveTarget(.{
        .dir = tmp.dir,
        .sub_path = "dynamic.db",
        .max_changes = 2,
        .enabled = true,
    });
    defer enabled.deinit();
    broker.commitPersistentChangeAutosaveTarget(&enabled);
    try std.testing.expectEqual(
        @as(?usize, 2),
        broker.persistentChangeAutosaveThreshold(),
    );
    try std.testing.expectEqualStrings(
        "dynamic.db",
        broker.options.persistent_change_autosave.?.sub_path,
    );

    var disabled = try broker.preparePersistentChangeAutosaveTarget(null);
    defer disabled.deinit();
    broker.commitPersistentChangeAutosaveTarget(&disabled);
    try std.testing.expectEqual(
        @as(?usize, null),
        broker.persistentChangeAutosaveThreshold(),
    );
    try std.testing.expect(broker.options.persistent_change_autosave == null);
}

test "broker required Client ID prefix prepares and commits ownership" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var broker = try Broker.init(allocator, io, .{
        .client_id_prefix = "initial-",
    });
    defer broker.deinit();

    var prepared = try broker.prepareRequiredClientIdPrefix("reloaded-");
    defer prepared.deinit();
    var prefix = try broker.requiredClientIdPrefixAlloc(allocator);
    try std.testing.expectEqualStrings("initial-", prefix);
    allocator.free(prefix);

    broker.commitRequiredClientIdPrefix(&prepared);
    prefix = try broker.requiredClientIdPrefixAlloc(allocator);
    try std.testing.expectEqualStrings("reloaded-", prefix);
    allocator.free(prefix);

    try std.testing.expectError(
        error.InvalidProperty,
        broker.setRequiredClientIdPrefix("bad\x00prefix"),
    );
    prefix = try broker.requiredClientIdPrefixAlloc(allocator);
    try std.testing.expectEqualStrings("reloaded-", prefix);
    allocator.free(prefix);

    try broker.setRequiredClientIdPrefix("");
    prefix = try broker.requiredClientIdPrefixAlloc(allocator);
    defer allocator.free(prefix);
    try std.testing.expectEqual(@as(usize, 0), prefix.len);
}

test "broker runtime scheduling policy resets deadlines atomically" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var broker = try Broker.init(allocator, io, .{});
    defer broker.deinit();

    const initial_driver_generation =
        broker.deadline_driver.currentGeneration();
    const enabled_before = std.Io.Clock.awake.now(io);
    try broker.setRuntimeSchedulingPolicy(.{
        .retained_expiry_interval = .fromMilliseconds(200),
        .system_stats_interval = .fromMilliseconds(300),
    });
    const enabled_after = std.Io.Clock.awake.now(io);
    const enabled = broker.runtimeSchedulingPolicy();
    try std.testing.expect(
        enabled.retained_expiry_interval.?.nanoseconds ==
            std.Io.Duration.fromMilliseconds(200).nanoseconds,
    );
    try std.testing.expect(
        enabled.system_stats_interval.?.nanoseconds ==
            std.Io.Duration.fromMilliseconds(300).nanoseconds,
    );
    try std.testing.expect(
        broker.next_retained_expiry_ns.? >= enabled_before
            .addDuration(.fromMilliseconds(200)).nanoseconds,
    );
    try std.testing.expect(
        broker.next_retained_expiry_ns.? <= enabled_after
            .addDuration(.fromMilliseconds(200)).nanoseconds,
    );
    try std.testing.expect(
        broker.next_system_stats_ns.? >= enabled_before
            .addDuration(.fromMilliseconds(300)).nanoseconds,
    );
    try std.testing.expect(
        broker.next_system_stats_ns.? <= enabled_after
            .addDuration(.fromMilliseconds(300)).nanoseconds,
    );
    try std.testing.expectEqual(
        initial_driver_generation +% 1,
        broker.deadline_driver.currentGeneration(),
    );

    const shortened_before = std.Io.Clock.awake.now(io);
    try broker.setRuntimeSchedulingPolicy(.{
        .retained_expiry_interval = .fromMilliseconds(20),
        .system_stats_interval = .fromMilliseconds(30),
    });
    const shortened_after = std.Io.Clock.awake.now(io);
    try std.testing.expect(
        broker.next_retained_expiry_ns.? >= shortened_before
            .addDuration(.fromMilliseconds(20)).nanoseconds,
    );
    try std.testing.expect(
        broker.next_retained_expiry_ns.? <= shortened_after
            .addDuration(.fromMilliseconds(20)).nanoseconds,
    );
    try std.testing.expect(
        broker.next_system_stats_ns.? >= shortened_before
            .addDuration(.fromMilliseconds(30)).nanoseconds,
    );
    try std.testing.expect(
        broker.next_system_stats_ns.? <= shortened_after
            .addDuration(.fromMilliseconds(30)).nanoseconds,
    );

    const valid = broker.runtimeSchedulingPolicy();
    const valid_retained_deadline = broker.next_retained_expiry_ns;
    const valid_system_stats_deadline = broker.next_system_stats_ns;
    const valid_driver_generation =
        broker.deadline_driver.currentGeneration();
    try std.testing.expectError(
        error.InvalidProperty,
        broker.setRuntimeSchedulingPolicy(.{
            .retained_expiry_interval = .fromMilliseconds(1),
            .system_stats_interval = .fromNanoseconds(0),
        }),
    );
    const after_invalid = broker.runtimeSchedulingPolicy();
    try std.testing.expectEqual(
        valid.retained_expiry_interval.?.nanoseconds,
        after_invalid.retained_expiry_interval.?.nanoseconds,
    );
    try std.testing.expectEqual(
        valid.system_stats_interval.?.nanoseconds,
        after_invalid.system_stats_interval.?.nanoseconds,
    );
    try std.testing.expectEqual(
        valid_retained_deadline,
        broker.next_retained_expiry_ns,
    );
    try std.testing.expectEqual(
        valid_system_stats_deadline,
        broker.next_system_stats_ns,
    );
    try std.testing.expectEqual(
        valid_driver_generation,
        broker.deadline_driver.currentGeneration(),
    );

    try broker.setRuntimeSchedulingPolicy(.{});
    const disabled = broker.runtimeSchedulingPolicy();
    try std.testing.expect(disabled.retained_expiry_interval == null);
    try std.testing.expect(disabled.system_stats_interval == null);
    try std.testing.expect(broker.next_retained_expiry_ns == null);
    try std.testing.expect(broker.next_system_stats_ns == null);
    try std.testing.expectEqual(
        valid_driver_generation +% 1,
        broker.deadline_driver.currentGeneration(),
    );
}

test "broker rejects non-positive system statistics interval" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(
        error.InvalidProperty,
        Broker.listen(
            allocator,
            threaded.io(),
            .{ .ip4 = .loopback(0) },
            .{ .system_stats_interval = .zero },
        ),
    );
}

test "broker rejects non-positive retained expiry scan interval" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(
        error.InvalidProperty,
        Broker.init(allocator, threaded.io(), .{
            .retained_expiry_interval = .zero,
        }),
    );
}

test "broker rejects an empty accepted protocol set" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(
        error.InvalidProperty,
        Broker.init(allocator, threaded.io(), .{
            .accept = .{ .accepted_protocol_versions = .{
                .v3_1 = false,
                .v3_1_1 = false,
                .v5 = false,
            } },
        }),
    );
}

test "broker rejects zero persistent Session expiry cap" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(
        error.InvalidProperty,
        Broker.init(allocator, threaded.io(), .{
            .persistent_session_expiry_seconds = 0,
        }),
    );
}

test "MQTT broker publishes heap gauges only with a heap source" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const Heap = struct {
        current: usize = 1_536,
        maximum: usize = 4_096,
        fn snapshot(context: *anyopaque) broker_mod.HeapSnapshot {
            const self: *@This() = @ptrCast(@alignCast(context));
            return .{
                .current_bytes = self.current,
                .maximum_bytes = self.maximum,
            };
        }
    };
    var heap = Heap{};
    var broker = try Broker.init(allocator, io, .{
        .limits = .{
            .max_connections = 1,
            .max_queued_deliveries_per_connection = 8,
            .runtime = .{ .max_packet_size = 4096 },
        },
        .heap_source = .{
            .context = &heap,
            .snapshot_fn = Heap.snapshot,
        },
        .accept = .{ .max_outgoing_inflight = 64 },
    });
    defer broker.deinit();

    const stats_value = broker.stats();
    try std.testing.expectEqual(@as(?usize, 1_536), stats_value.heap_current_bytes);
    try std.testing.expectEqual(@as(?usize, 4_096), stats_value.heap_maximum_bytes);

    try broker.publishSystemStats();
    var storage: [1]mqtt.retained.Match = undefined;
    const current = try broker.retained.matchInto(
        "$SYS/broker/heap/current",
        std.Io.Clock.awake.now(io),
        &storage,
    );
    try std.testing.expectEqual(@as(usize, 1), current.len);
    try std.testing.expectEqualStrings("1536", current[0].payload);
    const maximum = try broker.retained.matchInto(
        "$SYS/broker/heap/maximum",
        std.Io.Clock.awake.now(io),
        &storage,
    );
    try std.testing.expectEqual(@as(usize, 1), maximum.len);
    try std.testing.expectEqualStrings("4096", maximum[0].payload);

    heap.current = 2_048;
    heap.maximum = 8_192;
    try broker.publishSystemStats();
    const updated = try broker.retained.matchInto(
        "$SYS/broker/heap/current",
        std.Io.Clock.awake.now(io),
        &storage,
    );
    try std.testing.expectEqualStrings("2048", updated[0].payload);

    var plain = try Broker.init(allocator, io, .{
        .limits = .{
            .max_connections = 1,
            .max_queued_deliveries_per_connection = 8,
            .runtime = .{ .max_packet_size = 4096 },
        },
        .accept = .{ .max_outgoing_inflight = 64 },
    });
    defer plain.deinit();
    try std.testing.expect(plain.stats().heap_current_bytes == null);
    try plain.publishSystemStats();
    const absent = try plain.retained.matchInto(
        "$SYS/broker/heap/current",
        std.Io.Clock.awake.now(io),
        &storage,
    );
    try std.testing.expectEqual(@as(usize, 0), absent.len);
}

test {
    _ = @import("broker/admission_deadline_tests.zig");
    _ = @import("broker/connect_admission_tests.zig");
    _ = @import("broker/connack_admission_tests.zig");
    _ = @import("broker/subscription_admission_tests.zig");
    _ = @import("broker/subscription_change_tests.zig");
    _ = @import("broker/registration_persistence_tests.zig");
    _ = @import("broker/listener_tests.zig");
    _ = @import("broker/connection_observer_tests.zig");
    _ = @import("broker/unix_listener_tests.zig");
    _ = @import("broker/capability_tests.zig");
    _ = @import("broker/client_policy_tests.zig");
    _ = @import("broker/protocol_tests.zig");
    _ = @import("broker/qos2_tests.zig");
    _ = @import("broker/retained_tests.zig");
    _ = @import("broker/will_tests.zig");
    _ = @import("broker/will_snapshot_tests.zig");
    _ = @import("broker/disconnect_completion_tests.zig");
    _ = @import("broker/session_tests.zig");
    _ = @import("broker/subscription_identifier_tests.zig");
}
