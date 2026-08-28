const std = @import("std");
const mqtt = @import("mod.zig");
const broker_mod = @import("broker.zig");
const runtime = @import("runtime.zig");

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

test "broker statistics form one coherent live and offline snapshot" {
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

    const live = broker.stats();
    try std.testing.expectEqual(@as(usize, 2), live.active_connections);
    try std.testing.expectEqual(
        @as(usize, 2),
        live.maximum_active_connections,
    );
    try std.testing.expectEqual(@as(usize, 0), live.expired_sessions);
    // The finite broker wires its aggregate counter into every accept. Both
    // CONNECT packets plus the subscriber's SUBSCRIBE and publisher's PUBLISH
    // have completed before this snapshot.
    try std.testing.expectEqual(@as(u64, 4), live.messages_received);
    try std.testing.expectEqual(@as(u64, 5), live.messages_sent);
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
    try std.testing.expectEqual(@as(u64, 7), offline.messages_received);
    try std.testing.expectEqual(@as(u64, 5), offline.messages_sent);
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
    while (received < 5) : (received += 1) {
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

    const traffic_metrics = [_]broker_mod.SystemMetric{
        .messages_received,
        .messages_sent,
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
            // CONNACK, SUBACK, and five selected client metric PUBLISH packets
            // were complete before this second snapshot was captured.
            .messages_sent => "7",
            .publish_messages_received,
            .publish_messages_dropped,
            .publish_bytes_received,
            => "0",
            // The first snapshot delivered five selected client metrics to
            // this subscriber. Those real wire PUBLISH packets contribute to
            // the following sent count/byte snapshot, as they do in Mosquitto.
            .publish_messages_sent, .publish_bytes_sent => "5",
            .bytes_received, .bytes_sent => {
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
}

test "broker periodically publishes system statistics" {
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
    const thread = try std.Thread.spawn(.{}, ServeState.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();

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
    try joinServer(thread, &joined, &serve);
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

test {
    _ = @import("broker/listener_tests.zig");
    _ = @import("broker/unix_listener_tests.zig");
    _ = @import("broker/capability_tests.zig");
    _ = @import("broker/protocol_tests.zig");
    _ = @import("broker/qos2_tests.zig");
    _ = @import("broker/retained_tests.zig");
    _ = @import("broker/will_tests.zig");
    _ = @import("broker/session_tests.zig");
}
