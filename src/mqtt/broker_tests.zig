const std = @import("std");
const mqtt = @import("mod.zig");
const broker_mod = @import("broker.zig");
const runtime = @import("runtime.zig");

const Broker = broker_mod.Broker;

pub const TestContext = struct {
    pub const mqtt_mod = mqtt;
    pub const BrokerType = Broker;
    pub const runtime_mod = runtime;
    pub const ServeStateType = ServeState;

    pub const testBrokerFn = testBroker;
    pub const connectFn = connect;
    pub const connectWithOptionsFn = connectWithOptions;
    pub const disconnectAllFn = disconnectAll;
    pub const waitForPeerCloseFn = waitForPeerClose;
    pub const joinServerFn = joinServer;
    pub const writeDuplicatePublishFn = writeDuplicatePublish;
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

test {
    _ = @import("broker/capability_tests.zig");
    _ = @import("broker/protocol_tests.zig");
    _ = @import("broker/qos2_tests.zig");
    _ = @import("broker/retained_tests.zig");
    _ = @import("broker/will_tests.zig");
    _ = @import("broker/session_tests.zig");
}
