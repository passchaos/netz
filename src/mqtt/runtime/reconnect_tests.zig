const std = @import("std");
const mqtt = @import("../mod.zig");
const reconnect = @import("../reconnect.zig");
const runtime = @import("../runtime.zig");

fn sessionExpiryProperty(seconds: u32) mqtt.Property {
    return .{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = seconds,
    } };
}

test "MQTT reconnect client retries TCP and resumes QoS1 with DUP" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        first_packet_id: u16 = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.server.accept(.{ .protocol = .v5 });
            defer first.deinit(self.server.allocator);
            try std.testing.expect(!first.connect.connect.clean_start);
            var publish = try first.connection.readPublish();
            defer publish.deinit(self.server.allocator);
            try std.testing.expect(!publish.publish.dup);
            self.first_packet_id = publish.publish.packet_id.?;
            // Simulate a broker that received the Application Message but
            // lost the PUBACK together with the Network Connection.
            first.connection.shutdown() catch {};

            var pending = try self.server.acceptPending(.{
                .protocol = .v5,
            });
            var second = try pending.finish(.{
                .protocol = .v5,
                .session_present = true,
            });
            defer second.deinit(self.server.allocator);
            var retry = try second.connection.readPublish();
            defer retry.deinit(self.server.allocator);
            try std.testing.expect(retry.publish.dup);
            try std.testing.expectEqual(
                self.first_packet_id,
                retry.publish.packet_id.?,
            );
            try std.testing.expectEqualStrings(
                "reconnect/qos1",
                retry.publish.topic,
            );
            try std.testing.expectEqualStrings("durable", retry.publish.payload);
            try second.connection.writePubAck(retry.publish.packet_id.?, 0);
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    var shutdown: std.Io.Event = .unset;
    const properties = [_]mqtt.Property{sessionExpiryProperty(60)};
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "reconnect-qos1",
            .clean_start = false,
            .properties = &properties,
            .connect_timeout = .fromSeconds(1),
        },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
    );
    defer client.deinit();
    const initial = try client.connect();
    try std.testing.expect(!initial.session_present);
    const packet_id = (try client.publish(
        "reconnect/qos1",
        "durable",
        .{ .qos = .at_least_once },
    )).?;
    try std.testing.expectEqual(packet_id, try client.completeNextPublish());
    const stats = try client.outgoingStats();
    try std.testing.expectEqual(@as(usize, 0), stats.inflight_count);

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT reconnect client resumes QoS2 directly at PUBREL" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.server.accept(.{ .protocol = .v5 });
            defer first.deinit(self.server.allocator);
            var publish = try first.connection.readPublish();
            defer publish.deinit(self.server.allocator);
            const packet_id = publish.publish.packet_id.?;
            try first.connection.writePubRec(packet_id, 0);
            var pubrel = try first.connection.readPubRel();
            defer pubrel.deinit(self.server.allocator);
            try std.testing.expectEqual(packet_id, pubrel.ack.packet_id);
            first.connection.shutdown() catch {};

            var pending = try self.server.acceptPending(.{
                .protocol = .v5,
            });
            var second = try pending.finish(.{
                .protocol = .v5,
                .session_present = true,
            });
            defer second.deinit(self.server.allocator);
            var retry = try second.connection.readSessionPubRel();
            defer retry.deinit(self.server.allocator);
            try std.testing.expectEqual(packet_id, retry.ack.packet_id);
            try second.connection.writePubComp(packet_id, 0);
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    var shutdown: std.Io.Event = .unset;
    const properties = [_]mqtt.Property{sessionExpiryProperty(60)};
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "reconnect-qos2",
            .clean_start = false,
            .properties = &properties,
            .connect_timeout = .fromSeconds(1),
        },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
    );
    defer client.deinit();
    _ = try client.connect();
    const packet_id = (try client.publish(
        "reconnect/qos2",
        "exactly-once",
        .{ .qos = .exactly_once },
    )).?;
    try std.testing.expectEqual(packet_id, try client.completeNextPublish());
    // The first completion consumed PUBREC and sent PUBREL. The lost PUBCOMP
    // makes the next call reconnect and replay PUBREL, not the PUBLISH body.
    try std.testing.expectEqual(packet_id, try client.completeNextPublish());
    try std.testing.expectEqual(
        @as(usize, 0),
        (try client.outgoingStats()).inflight_count,
    );

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT reconnect drops old QoS state when session is absent" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.server.accept(.{ .protocol = .v5 });
            defer first.deinit(self.server.allocator);
            var publish = try first.connection.readPublish();
            defer publish.deinit(self.server.allocator);
            first.connection.shutdown() catch {};

            var second = try self.server.accept(.{
                .protocol = .v5,
                .session_present = false,
            });
            defer second.deinit(self.server.allocator);
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    var shutdown: std.Io.Event = .unset;
    const properties = [_]mqtt.Property{sessionExpiryProperty(60)};
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "reconnect-session-reset",
            .clean_start = false,
            .properties = &properties,
            .connect_timeout = .fromSeconds(1),
        },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
    );
    defer client.deinit();
    _ = try client.connect();
    _ = try client.publish(
        "reconnect/lost-session",
        "discard-me",
        .{ .qos = .at_least_once },
    );
    try std.testing.expectError(
        error.SessionLost,
        client.completeNextPublish(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        (try client.outgoingStats()).inflight_count,
    );

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT reconnect replays accepted subscriptions only for a fresh session" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.server.accept(.{ .protocol = .v5 });
            defer first.deinit(self.server.allocator);
            var subscription = try first.connection.readSubscribe();
            defer subscription.deinit(self.server.allocator);
            try std.testing.expectEqual(@as(usize, 2), subscription.subscribe.subscriptions.len);
            try first.connection.writeSubAck(
                subscription.subscribe.packet_id,
                &.{ 0x01, 0x87 },
                &.{},
            );
            first.connection.shutdown() catch {};

            var second = try self.server.accept(.{
                .protocol = .v5,
                .session_present = false,
            });
            defer second.deinit(self.server.allocator);
            var replay = try second.connection.readSubscribe();
            defer replay.deinit(self.server.allocator);
            try std.testing.expectEqual(@as(usize, 1), replay.subscribe.subscriptions.len);
            try std.testing.expectEqualStrings(
                "devices/+/state",
                replay.subscribe.subscriptions[0].topic_filter,
            );
            try std.testing.expectEqual(
                mqtt.QoS.at_least_once,
                replay.subscribe.subscriptions[0].qos,
            );
            try std.testing.expectEqual(
                @as(?usize, 37),
                mqtt.subscriptionIdentifier(replay.subscribe.properties),
            );
            try std.testing.expectEqualStrings(
                "first",
                replay.subscribe.properties[1].utf8_pair.value,
            );
            try second.connection.writeSubAck(
                replay.subscribe.packet_id,
                &.{0x01},
                &.{},
            );
            second.connection.shutdown() catch {};

            var third = try self.server.accept(.{
                .protocol = .v5,
                .session_present = true,
            });
            defer third.deinit(self.server.allocator);
            try third.connection.readPingReq();
            try third.connection.writePingResp();
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    var shutdown: std.Io.Event = .unset;
    const properties = [_]mqtt.Property{sessionExpiryProperty(60)};
    var replay_property_value: [5]u8 = "first".*;
    const subscribe_properties = [_]mqtt.Property{
        .{ .varint = .{ .id = .subscription_identifier, .value = 37 } },
        .{ .utf8_pair = .{
            .id = .user_property,
            .key = "source",
            .value = &replay_property_value,
        } },
    };
    var client = try reconnect.Client.initWithOptions(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "reconnect-subscriptions",
            .clean_start = false,
            .properties = &properties,
            .connect_timeout = .fromSeconds(1),
        },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
        .{ .max_subscriptions = 2 },
    );
    defer client.deinit();
    _ = try client.connect();
    var suback = try client.subscribe(&.{
        .{ .topic_filter = "devices/+/state", .qos = .at_least_once },
        .{ .topic_filter = "denied/#", .qos = .at_least_once },
    }, .{ .properties = &subscribe_properties });
    defer suback.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), client.subscriptionCount());
    @memcpy(&replay_property_value, "later");

    const fresh = try client.reconnect();
    try std.testing.expect(!fresh.session_present);
    const resumed = try client.reconnect();
    try std.testing.expect(resumed.session_present);
    try client.connection().?.pingWithTimeout(.fromSeconds(1));

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT reconnect backoff is canceled promptly" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    // Reserve a loopback port, then close the listener so connect fails
    // immediately without depending on an external address or firewall.
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    const address = server.address();
    server.deinit();
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(
        allocator,
        io,
        address,
        .{ .protocol = .v5, .client_id = "reconnect-cancel" },
        .{
            .initial_delay = .fromSeconds(30),
            .max_delay = .fromSeconds(30),
        },
        &shutdown,
    );
    defer client.deinit();
    const Shared = struct {
        client: *reconnect.Client,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            _ = self.client.connect() catch |err| {
                self.err = err;
                return;
            };
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .client = &client };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    try std.Io.sleep(io, .fromMilliseconds(20), .awake);
    const started = std.Io.Clock.awake.now(io);
    shutdown.set(io);
    thread.join();
    const elapsed = started.durationTo(std.Io.Clock.awake.now(io));
    try std.testing.expectEqual(error.Canceled, shared.err.?);
    try std.testing.expect(elapsed.nanoseconds < std.time.ns_per_s);
}

test "MQTT reconnect poll preserves inbound publish across keep alive" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer server.deinit();

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
            try accepted.connection.publish(
                "poll/inbound",
                "before-ping",
                .{ .qos = .at_least_once },
            );
            try accepted.connection.readPingReq();
            try accepted.connection.writePingResp();
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "poll-inbound",
            .keep_alive_seconds = 1,
        },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
    );
    defer client.deinit();

    var connected = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer connected.deinit(allocator);
    try std.testing.expect(connected == .connected);

    var publish = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer publish.deinit(allocator);
    try std.testing.expect(publish == .publish);
    try std.testing.expectEqualStrings(
        "poll/inbound",
        publish.publish.publish.topic,
    );
    try std.testing.expectEqualStrings(
        "before-ping",
        publish.publish.publish.payload,
    );

    try std.Io.sleep(io, .fromMilliseconds(1100), .awake);
    var pingreq = (try client.pollWithTimeout(.fromMilliseconds(300))).?;
    defer pingreq.deinit(allocator);
    try std.testing.expect(pingreq == .pingreq);
    var pingresp = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer pingresp.deinit(allocator);
    try std.testing.expect(pingresp == .pingresp);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT reconnect poll reconnects after silent ping timeout and keeps QoS" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        first_packet_id: u16 = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.server.accept(.{ .protocol = .v5 });
            defer first.deinit(self.server.allocator);
            var publish = try first.connection.readPublish();
            defer publish.deinit(self.server.allocator);
            self.first_packet_id = publish.publish.packet_id.?;
            try first.connection.readPingReq();
            // Intentionally withhold PINGRESP. The client must retire this
            // transport and resume the durable Session itself.

            var second = try self.server.accept(.{
                .protocol = .v5,
                .session_present = true,
            });
            defer second.deinit(self.server.allocator);
            var retry = try second.connection.readPublish();
            defer retry.deinit(self.server.allocator);
            try std.testing.expect(retry.publish.dup);
            try std.testing.expectEqual(
                self.first_packet_id,
                retry.publish.packet_id.?,
            );
            try second.connection.writePubAck(retry.publish.packet_id.?, 0);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var shutdown: std.Io.Event = .unset;
    const properties = [_]mqtt.Property{sessionExpiryProperty(60)};
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "poll-silent",
            .clean_start = false,
            .keep_alive_seconds = 1,
            .properties = &properties,
            .connect_timeout = .fromSeconds(1),
        },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
    );
    defer client.deinit();

    var connected = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer connected.deinit(allocator);
    try std.testing.expect(connected == .connected);
    _ = try client.publish(
        "poll/durable",
        "payload",
        .{ .qos = .at_least_once },
    );
    try std.Io.sleep(io, .fromMilliseconds(1100), .awake);
    var pingreq = (try client.pollWithOptions(.{
        .timeout = .fromMilliseconds(300),
        .ping_response_timeout = .fromMilliseconds(75),
    })).?;
    defer pingreq.deinit(allocator);
    try std.testing.expect(pingreq == .pingreq);
    var reconnected = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer reconnected.deinit(allocator);
    try std.testing.expect(reconnected == .connected);
    try std.testing.expect(reconnected.connected.session_present);

    var puback = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer puback.deinit(allocator);
    try std.testing.expect(puback == .puback);
    try std.testing.expectEqual(
        shared.first_packet_id,
        puback.puback.ack.packet_id,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        (try client.outgoingStats()).inflight_count,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT reconnect poll resumes inbound QoS2 at PUBREL" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.server.accept(.{ .protocol = .v5 });
            defer first.deinit(self.server.allocator);
            const packet_id = (try first.connection.writePublish(
                "poll/inbound-qos2",
                "exactly-once",
                .{ .qos = .exactly_once },
            )).?;
            var pubrec = try first.connection.readPubRec();
            defer pubrec.deinit(self.server.allocator);
            try std.testing.expectEqual(packet_id, pubrec.ack.packet_id);
            first.connection.shutdown() catch {};

            var second = try self.server.accept(.{
                .protocol = .v5,
                .session_present = true,
            });
            defer second.deinit(self.server.allocator);
            try second.connection.writePubRel(packet_id, 0);
            var pubcomp = try second.connection.readPubComp();
            defer pubcomp.deinit(self.server.allocator);
            try std.testing.expectEqual(packet_id, pubcomp.ack.packet_id);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var shutdown: std.Io.Event = .unset;
    const properties = [_]mqtt.Property{sessionExpiryProperty(60)};
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "poll-inbound-qos2",
            .clean_start = false,
            .properties = &properties,
            .connect_timeout = .fromSeconds(1),
        },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
    );
    defer client.deinit();

    var connected = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer connected.deinit(allocator);
    var publish = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer publish.deinit(allocator);
    try std.testing.expect(publish == .publish);
    try std.testing.expectEqual(mqtt.QoS.exactly_once, publish.publish.publish.qos);

    var reconnected = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer reconnected.deinit(allocator);
    try std.testing.expect(reconnected == .connected);
    try std.testing.expect(reconnected.connected.session_present);
    var pubrel = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer pubrel.deinit(allocator);
    try std.testing.expect(pubrel == .pubrel);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT reconnect poll timeout preserves a fragmented TCP packet" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer server.deinit();

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
            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(self.server.allocator);
            try mqtt.writePublish(
                &encoded,
                self.server.allocator,
                .v5,
                "poll/fragmented",
                "survives-timeout",
                .{},
            );
            const tcp = accepted.connection.transport.tcp;
            _ = try tcp.io.vtable.netWrite(
                tcp.io.userdata,
                tcp.stream.socket.handle,
                encoded.items[0..1],
                &.{""},
                0,
            );
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(80),
                .awake,
            );
            var written: usize = 1;
            while (written < encoded.items.len) {
                const count = try tcp.io.vtable.netWrite(
                    tcp.io.userdata,
                    tcp.stream.socket.handle,
                    encoded.items[written..],
                    &.{""},
                    0,
                );
                if (count == 0) return error.SocketUnconnected;
                written += count;
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{ .protocol = .v5, .client_id = "poll-fragmented" },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
    );
    defer client.deinit();
    var connected = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer connected.deinit(allocator);

    try std.testing.expect((try client.pollWithTimeout(
        .fromMilliseconds(30),
    )) == null);
    var publish = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer publish.deinit(allocator);
    try std.testing.expect(publish == .publish);
    try std.testing.expectEqualStrings(
        "poll/fragmented",
        publish.publish.publish.topic,
    );
    try std.testing.expectEqualStrings(
        "survives-timeout",
        publish.publish.publish.payload,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT reconnect poll observes cancellation while idle" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

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
            try std.Io.sleep(self.server.io, .fromMilliseconds(300), .awake);
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var server_joined = false;
    defer if (!server_joined) server_thread.join();

    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "poll-cancel",
            .keep_alive_seconds = 0,
        },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
    );
    defer client.deinit();
    var connected = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer connected.deinit(allocator);

    const Polling = struct {
        client: *reconnect.Client,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            _ = self.client.pollWithOptions(.{
                .timeout = .fromSeconds(30),
                .cancellation_check_interval = .fromMilliseconds(10),
            }) catch |err| {
                self.err = err;
                return;
            };
            self.err = error.TestUnexpectedResult;
        }
    };
    var polling = Polling{ .client = &client };
    const poll_thread = try std.Thread.spawn(.{}, Polling.run, .{&polling});
    try std.Io.sleep(io, .fromMilliseconds(25), .awake);
    const started = std.Io.Clock.awake.now(io);
    shutdown.set(io);
    poll_thread.join();
    const elapsed = started.durationTo(std.Io.Clock.awake.now(io));
    try std.testing.expectEqual(error.Canceled, polling.err.?);
    try std.testing.expect(elapsed.nanoseconds < std.time.ns_per_s);

    server_thread.join();
    server_joined = true;
    if (shared.err) |err| return err;
}

test "MQTT reconnect poll automatically continues live reauthentication" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const method = "mirror";
    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.acceptPending(.{ .protocol = .v5 });
            var pending_owned = true;
            defer if (pending_owned) pending.deinit(self.server.allocator);
            try pending.authorizeAuthentication();
            var accepted = try pending.finish(.{ .protocol = .v5 });
            pending_owned = false;
            defer accepted.deinit(self.server.allocator);

            try accepted.connection.beginReauthentication("server-step");
            var response =
                try accepted.connection.receiveReauthentication();
            defer response.auth.deinit(self.server.allocator);
            try std.testing.expect(!response.complete);
            try std.testing.expectEqualStrings(
                "client-step",
                mqtt.authenticationData(
                    response.auth.auth.properties,
                ).?,
            );
            try std.testing.expectEqualStrings(
                "kept",
                response.auth.auth.properties[2].utf8_pair.value,
            );
            try accepted.connection.continueReauthentication(
                0,
                "server-final",
            );
        }
    };
    const Handler = struct {
        calls: usize = 0,

        fn respond(
            context: *anyopaque,
            challenge: mqtt.Auth,
        ) runtime.Error![]const mqtt.Property {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            if (!std.mem.eql(
                u8,
                "server-step",
                mqtt.authenticationData(challenge.properties) orelse
                    return error.InvalidAuthenticationState,
            )) return error.InvalidAuthenticationState;
            return &.{
                .{ .utf8 = .{
                    .id = .authentication_method,
                    .value = method,
                } },
                .{ .binary = .{
                    .id = .authentication_data,
                    .value = "client-step",
                } },
                .{ .utf8_pair = .{
                    .id = .user_property,
                    .key = "trace",
                    .value = "kept",
                } },
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var handler: Handler = .{};
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "poll-reauth",
            .properties = &.{.{ .utf8 = .{
                .id = .authentication_method,
                .value = method,
            } }},
            .authentication = .{
                .context = &handler,
                .respond = Handler.respond,
            },
        },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
    );
    defer client.deinit();

    var connected = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer connected.deinit(allocator);
    var challenge = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer challenge.deinit(allocator);
    try std.testing.expect(challenge == .auth);
    try std.testing.expectEqual(@as(usize, 1), handler.calls);
    try std.testing.expectEqualStrings(
        "server-step",
        mqtt.authenticationData(challenge.auth.auth.properties).?,
    );
    var complete = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer complete.deinit(allocator);
    try std.testing.expect(complete == .auth);
    try std.testing.expectEqual(@as(u8, 0), complete.auth.auth.reason_code);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT reconnect poll requires a reauthentication handler" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.acceptPending(.{ .protocol = .v5 });
            var pending_owned = true;
            defer if (pending_owned) pending.deinit(self.server.allocator);
            try pending.authorizeAuthentication();
            var accepted = try pending.finish(.{ .protocol = .v5 });
            pending_owned = false;
            defer accepted.deinit(self.server.allocator);
            try accepted.connection.beginReauthentication("challenge");
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "poll-reauth-missing",
            .properties = &.{.{ .utf8 = .{
                .id = .authentication_method,
                .value = "mirror",
            } }},
        },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
    );
    defer client.deinit();
    var connected = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer connected.deinit(allocator);
    try std.testing.expectError(
        error.AuthenticationNotConfigured,
        client.pollWithTimeout(.fromSeconds(1)),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT reconnect poll completes client initiated reauthentication" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const method = "mirror";
    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.acceptPending(.{ .protocol = .v5 });
            var pending_owned = true;
            defer if (pending_owned) pending.deinit(self.server.allocator);
            try pending.authorizeAuthentication();
            var accepted = try pending.finish(.{ .protocol = .v5 });
            pending_owned = false;
            defer accepted.deinit(self.server.allocator);

            var initial = try accepted.connection.acceptReauthentication();
            defer initial.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "client-first",
                mqtt.authenticationData(initial.auth.properties).?,
            );
            try std.testing.expectEqualStrings(
                "kept",
                initial.auth.properties[2].utf8_pair.value,
            );
            try accepted.connection.continueReauthentication(
                0x18,
                "server-step",
            );
            var response =
                try accepted.connection.receiveReauthentication();
            defer response.auth.deinit(self.server.allocator);
            try std.testing.expect(!response.complete);
            try std.testing.expectEqualStrings(
                "client-final",
                mqtt.authenticationData(
                    response.auth.auth.properties,
                ).?,
            );
            try accepted.connection.continueReauthentication(
                0,
                "server-final",
            );
        }
    };
    const Handler = struct {
        calls: usize = 0,

        fn respond(
            context: *anyopaque,
            challenge: mqtt.Auth,
        ) runtime.Error![]const mqtt.Property {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            if (!std.mem.eql(
                u8,
                "server-step",
                mqtt.authenticationData(challenge.properties) orelse
                    return error.InvalidAuthenticationState,
            )) return error.InvalidAuthenticationState;
            return &.{
                .{ .utf8 = .{
                    .id = .authentication_method,
                    .value = method,
                } },
                .{ .binary = .{
                    .id = .authentication_data,
                    .value = "client-final",
                } },
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var handler: Handler = .{};
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "poll-client-reauth",
            .properties = &.{.{ .utf8 = .{
                .id = .authentication_method,
                .value = method,
            } }},
            .authentication = .{
                .context = &handler,
                .respond = Handler.respond,
            },
        },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
    );
    defer client.deinit();
    var connected = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer connected.deinit(allocator);

    try client.beginReauthentication(&.{
        .{ .utf8 = .{
            .id = .authentication_method,
            .value = method,
        } },
        .{ .binary = .{
            .id = .authentication_data,
            .value = "client-first",
        } },
        .{ .utf8_pair = .{
            .id = .user_property,
            .key = "trace",
            .value = "kept",
        } },
    });
    var challenge = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer challenge.deinit(allocator);
    try std.testing.expect(challenge == .auth);
    try std.testing.expectEqual(@as(usize, 1), handler.calls);
    var complete = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer complete.deinit(allocator);
    try std.testing.expect(complete == .auth);
    try std.testing.expectEqual(@as(u8, 0), complete.auth.auth.reason_code);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT reconnect serveUntil dispatches owned events and shuts down" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

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
            try accepted.connection.publish(
                "serve/event",
                "payload",
                .{ .qos = .at_least_once },
            );
        }
    };
    const Handler = struct {
        io: std.Io,
        shutdown: *std.Io.Event,
        connected: usize = 0,
        publishes: usize = 0,

        fn handle(
            self: *@This(),
            _: *reconnect.Client,
            event: *reconnect.ClientEvent,
        ) !void {
            switch (event.*) {
                .connected => self.connected += 1,
                .publish => |owned| {
                    try std.testing.expectEqualStrings(
                        "serve/event",
                        owned.publish.topic,
                    );
                    try std.testing.expectEqualStrings(
                        "payload",
                        owned.publish.payload,
                    );
                    self.publishes += 1;
                    self.shutdown.set(self.io);
                },
                else => return error.UnexpectedPacket,
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{ .protocol = .v5, .client_id = "serve-until" },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
    );
    defer client.deinit();
    var handler = Handler{ .io = io, .shutdown = &shutdown };
    try client.serveUntil(Handler, &handler, Handler.handle, .{
        .timeout = .fromSeconds(1),
    });
    try std.testing.expectEqual(@as(usize, 1), handler.connected);
    try std.testing.expectEqual(@as(usize, 1), handler.publishes);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT queued reconnect loop serializes concurrent producers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const publish_count = 8;
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
            for (0..publish_count) |_| {
                var publish = try accepted.connection.readPublish();
                defer publish.deinit(self.server.allocator);
                try std.testing.expectEqualStrings(
                    "queued/publish",
                    publish.publish.topic,
                );
                try accepted.connection.writePubAck(
                    publish.publish.packet_id.?,
                    0,
                );
            }
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var server_joined = false;
    defer if (!server_joined) server_thread.join();

    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{ .protocol = .v5, .client_id = "queued-loop" },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
    );
    defer client.deinit();
    var queue = try reconnect.CommandQueue.init(allocator, io, 2);
    defer queue.deinit();

    const Handler = struct {
        io: std.Io,
        shutdown: *std.Io.Event,
        acknowledgements: usize = 0,

        fn handle(
            self: *@This(),
            _: *reconnect.Client,
            event: *reconnect.ClientEvent,
        ) !void {
            switch (event.*) {
                .connected => {},
                .puback => {
                    self.acknowledgements += 1;
                    if (self.acknowledgements == publish_count) {
                        self.shutdown.set(self.io);
                    }
                },
                else => return error.UnexpectedPacket,
            }
        }
    };
    const Producer = struct {
        queue: *reconnect.CommandQueue,
        payload: []const u8,
        packet_id: ?u16 = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.packet_id = self.queue.publish(
                "queued/publish",
                self.payload,
                .{ .qos = .at_least_once },
            ) catch |err| {
                self.err = err;
                return;
            };
        }
    };
    var handler = Handler{ .io = io, .shutdown = &shutdown };
    const Loop = struct {
        client: *reconnect.Client,
        queue: *reconnect.CommandQueue,
        handler: *Handler,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.client.serveQueuedUntil(
                self.queue,
                Handler,
                self.handler,
                Handler.handle,
                .{ .poll = .{ .timeout = .fromMilliseconds(50) } },
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var loop = Loop{
        .client = &client,
        .queue = &queue,
        .handler = &handler,
    };
    const loop_thread = try std.Thread.spawn(.{}, Loop.run, .{&loop});

    var producers: [publish_count]Producer = undefined;
    var producer_threads: [publish_count]std.Thread = undefined;
    for (&producers, 0..) |*producer, index| {
        producer.* = .{
            .queue = &queue,
            .payload = if (index % 2 == 0) "even" else "odd",
        };
        producer_threads[index] = try std.Thread.spawn(
            .{},
            Producer.run,
            .{producer},
        );
    }
    for (&producer_threads) |*thread| thread.join();
    loop_thread.join();
    try std.testing.expect(loop.err == null);
    for (producers) |producer| {
        if (producer.err) |err| return err;
        try std.testing.expect(producer.packet_id != null);
    }
    try std.testing.expectEqual(publish_count, handler.acknowledgements);

    server_thread.join();
    server_joined = true;
    if (shared.err) |err| return err;
}

test "MQTT managed queued run owns worker lifecycle" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

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
            var publish = try accepted.connection.readPublish();
            defer publish.deinit(self.server.allocator);
            try accepted.connection.writePubAck(
                publish.publish.packet_id.?,
                0,
            );
        }
    };
    const Handler = struct {
        io: std.Io,
        shutdown: *std.Io.Event,
        fn handle(
            self: *@This(),
            _: *reconnect.Client,
            event: *reconnect.ClientEvent,
        ) !void {
            if (event.* == .puback) self.shutdown.set(self.io);
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var server_joined = false;
    defer if (!server_joined) server_thread.join();
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{ .protocol = .v5, .client_id = "managed-queue" },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
    );
    defer client.deinit();
    var handler = Handler{ .io = io, .shutdown = &shutdown };
    var run = try client.runQueued(
        Handler,
        &handler,
        Handler.handle,
        .{
            .queue_capacity = 1,
            .serve = .{
                .poll = .{ .timeout = .fromMilliseconds(50) },
            },
        },
    );
    const packet_id = try run.publish(
        "managed/queue",
        "payload",
        .{ .qos = .at_least_once },
    );
    try std.testing.expect(packet_id != null);
    if (run.deinit()) |err| return err;

    server_thread.join();
    server_joined = true;
    if (shared.err) |err| return err;
}

test "MQTT queued run owns asynchronous publish until completion" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

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
            var publish = try accepted.connection.readPublish();
            defer publish.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "async/original",
                publish.publish.topic,
            );
            try std.testing.expectEqualStrings(
                "owned-payload",
                publish.publish.payload,
            );
            try accepted.connection.writePubAck(
                publish.publish.packet_id.?,
                0,
            );
        }
    };
    const Handler = struct {
        io: std.Io,
        shutdown: *std.Io.Event,
        fn handle(
            self: *@This(),
            _: *reconnect.Client,
            event: *reconnect.ClientEvent,
        ) !void {
            if (event.* == .puback) self.shutdown.set(self.io);
        }
    };
    const Completion = struct {
        event: std.Io.Event = .unset,
        io: std.Io,
        command_id: u64 = 0,
        packet_id: ?u16 = null,
        err: ?anyerror = null,

        fn complete(
            context: *anyopaque,
            completion: reconnect.CommandCompletion,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.command_id = completion.command_id;
            const result = completion.result catch |err| {
                self.err = err;
                self.event.set(self.io);
                return;
            };
            self.packet_id = switch (result) {
                .publish => |packet_id| packet_id,
                else => blk: {
                    self.err = error.UnexpectedPacket;
                    break :blk null;
                },
            };
            self.event.set(self.io);
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var server_joined = false;
    defer if (!server_joined) server_thread.join();
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{ .protocol = .v5, .client_id = "async-queue" },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
    );
    defer client.deinit();
    var handler = Handler{ .io = io, .shutdown = &shutdown };
    var run = try client.runQueued(
        Handler,
        &handler,
        Handler.handle,
        .{
            .queue_capacity = 2,
            .serve = .{
                .poll = .{ .timeout = .fromMilliseconds(50) },
            },
        },
    );
    var completion = Completion{ .io = io };
    var topic: [14]u8 = "async/original".*;
    var payload: [13]u8 = "owned-payload".*;
    const command_id = try run.publishAsync(
        &topic,
        &payload,
        .{ .qos = .at_least_once },
        .{ .context = &completion, .complete = Completion.complete },
    );
    @memcpy(&topic, "async/modified");
    @memcpy(&payload, "changed-value");
    completion.event.waitUncancelable(io);
    try std.testing.expect(completion.err == null);
    try std.testing.expectEqual(command_id, completion.command_id);
    try std.testing.expect(completion.packet_id != null);
    if (run.deinit()) |err| return err;

    server_thread.join();
    server_joined = true;
    if (shared.err) |err| return err;
}

test "MQTT queued run owns async subscription commands and results" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

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
            var subscribe = try accepted.connection.readSubscribe();
            defer subscribe.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "async/subscription",
                subscribe.subscribe.subscriptions[0].topic_filter,
            );
            try std.testing.expectEqualStrings(
                "original",
                subscribe.subscribe.properties[0].utf8_pair.value,
            );
            try accepted.connection.writeSubAck(
                subscribe.subscribe.packet_id,
                &.{0x01},
                &.{.{ .utf8 = .{
                    .id = .reason_string,
                    .value = "subscribed",
                } }},
            );
            var unsubscribe = try accepted.connection.readUnsubscribe();
            defer unsubscribe.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "async/subscription",
                unsubscribe.unsubscribe.topic_filters[0],
            );
            try std.testing.expectEqualStrings(
                "unsubscribe",
                unsubscribe.unsubscribe.properties[0].utf8_pair.key,
            );
            try std.testing.expectEqualStrings(
                "original",
                unsubscribe.unsubscribe.properties[0].utf8_pair.value,
            );
            try accepted.connection.writeUnsubAck(
                unsubscribe.unsubscribe.packet_id,
                &.{0x00},
                &.{.{ .utf8 = .{
                    .id = .reason_string,
                    .value = "unsubscribed",
                } }},
            );
        }
    };
    const Completion = struct {
        io: std.Io,
        shutdown: *std.Io.Event,
        event: std.Io.Event = .unset,
        calls: usize = 0,
        subscribe_id: u64 = 0,
        unsubscribe_id: u64 = 0,
        subscribe_packet_id: u16 = 0,
        unsubscribe_packet_id: u16 = 0,
        err: ?anyerror = null,

        fn complete(
            context: *anyopaque,
            completion: reconnect.CommandCompletion,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            const result = completion.result catch |err| {
                self.err = err;
                self.event.set(self.io);
                self.shutdown.set(self.io);
                return;
            };
            switch (result) {
                .subscribe => |ack| {
                    if (ack.reason_codes.len != 1 or
                        ack.reason_codes[0] != 0x01 or
                        ack.properties.len != 1 or
                        !std.mem.eql(
                            u8,
                            ack.properties[0].utf8.value,
                            "subscribed",
                        ))
                    {
                        self.err = error.UnexpectedPacket;
                    }
                    self.subscribe_id = completion.command_id;
                    self.subscribe_packet_id = ack.packet_id;
                },
                .unsubscribe => |ack| {
                    if (ack.reason_codes.len != 1 or
                        ack.reason_codes[0] != 0x00 or
                        ack.properties.len != 1 or
                        !std.mem.eql(
                            u8,
                            ack.properties[0].utf8.value,
                            "unsubscribed",
                        ))
                    {
                        self.err = error.UnexpectedPacket;
                    }
                    self.unsubscribe_id = completion.command_id;
                    self.unsubscribe_packet_id = ack.packet_id;
                    self.shutdown.set(self.io);
                },
                else => self.err = error.UnexpectedPacket,
            }
            self.calls += 1;
            self.event.set(self.io);
        }
    };
    const Handler = struct {
        fn handle(
            _: *@This(),
            _: *reconnect.Client,
            _: *reconnect.ClientEvent,
        ) !void {}
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{ .protocol = .v5, .client_id = "async-subscriptions" },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
    );
    defer client.deinit();
    var handler: Handler = .{};
    var run = try client.runQueued(
        Handler,
        &handler,
        Handler.handle,
        .{
            .queue_capacity = 2,
            .serve = .{
                .poll = .{ .timeout = .fromMilliseconds(50) },
            },
        },
    );
    var completion = Completion{ .io = io, .shutdown = &shutdown };
    var filter: [18]u8 = "async/subscription".*;
    var property_value: [8]u8 = "original".*;
    const subscribe_id = try run.subscribeAsync(
        &.{.{
            .topic_filter = &filter,
            .qos = .at_least_once,
        }},
        .{ .properties = &.{.{ .utf8_pair = .{
            .id = .user_property,
            .key = "source",
            .value = &property_value,
        } }} },
        .{ .context = &completion, .complete = Completion.complete },
    );
    @memcpy(&filter, "changed/filter-now");
    @memcpy(&property_value, "modified");
    completion.event.waitUncancelable(io);
    try std.testing.expect(completion.err == null);
    try std.testing.expectEqual(subscribe_id, completion.subscribe_id);
    completion.event.reset();

    @memcpy(&property_value, "original");
    const unsubscribe_id = try run.unsubscribeAsync(
        &.{"async/subscription"},
        .{ .properties = &.{.{ .utf8_pair = .{
            .id = .user_property,
            .key = "unsubscribe",
            .value = &property_value,
        } }} },
        .{ .context = &completion, .complete = Completion.complete },
    );
    @memcpy(&property_value, "modified");
    completion.event.waitUncancelable(io);
    try std.testing.expect(completion.err == null);
    try std.testing.expectEqual(unsubscribe_id, completion.unsubscribe_id);
    try std.testing.expect(completion.subscribe_packet_id != 0);
    try std.testing.expect(completion.unsubscribe_packet_id != 0);
    try std.testing.expect(
        completion.subscribe_packet_id != completion.unsubscribe_packet_id,
    );
    try std.testing.expectEqual(@as(usize, 2), completion.calls);
    if (run.deinit()) |err| return err;

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT queued run exposes awaitable owned command completions" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

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
            var publish = try accepted.connection.readPublish();
            defer publish.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "awaitable/publish",
                publish.publish.topic,
            );
            var subscribe = try accepted.connection.readSubscribe();
            defer subscribe.deinit(self.server.allocator);
            try accepted.connection.writeSubAck(
                subscribe.subscribe.packet_id,
                &.{0x00},
                &.{.{ .utf8 = .{
                    .id = .reason_string,
                    .value = "owned ack",
                } }},
            );
            var unsubscribe = try accepted.connection.readUnsubscribe();
            defer unsubscribe.deinit(self.server.allocator);
            try accepted.connection.writeUnsubAck(
                unsubscribe.unsubscribe.packet_id,
                &.{0x00},
                &.{},
            );
        }
    };
    const Handler = struct {
        fn handle(
            _: *@This(),
            _: *reconnect.Client,
            _: *reconnect.ClientEvent,
        ) !void {}
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{ .protocol = .v5, .client_id = "completion-queue" },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
    );
    defer client.deinit();
    var handler: Handler = .{};
    var run = try client.runQueued(
        Handler,
        &handler,
        Handler.handle,
        .{
            .queue_capacity = 1,
            .serve = .{
                .poll = .{ .timeout = .fromMilliseconds(50) },
            },
        },
    );
    var completions = try reconnect.CompletionQueue.init(allocator, io, 3);
    defer completions.deinit();
    const publish_id = try run.publishQueued(
        &completions,
        "awaitable/publish",
        "payload",
        .{},
    );
    var publish_completion = try completions.receive();
    defer publish_completion.deinit();
    try std.testing.expectEqual(publish_id, publish_completion.command_id);
    switch (try publish_completion.result) {
        .publish => |packet_id| try std.testing.expect(packet_id == null),
        else => return error.UnexpectedPacket,
    }

    const command_id = try run.subscribeQueued(
        &completions,
        &.{.{ .topic_filter = "awaitable/+" }},
        .{},
    );
    var completion = try completions.receive();
    defer completion.deinit();
    const unsubscribe_id = try run.unsubscribeQueued(
        &completions,
        &.{"awaitable/+"},
        .{},
    );
    var unsubscribe_completion = try completions.receive();
    defer unsubscribe_completion.deinit();
    // Stop the network worker before inspecting the result to prove the queue
    // owns the ACK bytes beyond the callback and connection lifetime.
    if (run.deinit()) |err| return err;

    try std.testing.expectEqual(command_id, completion.command_id);
    switch (try completion.result) {
        .subscribe => |ack| {
            try std.testing.expectEqual(@as(u8, 0x00), ack.reason_codes[0]);
            try std.testing.expectEqualStrings(
                "owned ack",
                ack.properties[0].utf8.value,
            );
        },
        else => return error.UnexpectedPacket,
    }
    try std.testing.expectEqual(
        unsubscribe_id,
        unsubscribe_completion.command_id,
    );
    switch (try unsubscribe_completion.result) {
        .unsubscribe => |ack| {
            try std.testing.expectEqual(@as(u8, 0x00), ack.reason_codes[0]);
        },
        else => return error.UnexpectedPacket,
    }

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT queued disconnect writes owned MQTT5 properties and stops" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

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
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
            try std.testing.expectEqual(
                @as(u8, 0x04),
                disconnect.disconnect.reason_code,
            );
            try std.testing.expectEqualStrings(
                "original",
                disconnect.disconnect.properties[0].utf8.value,
            );
        }
    };
    const Handler = struct {
        fn handle(
            _: *@This(),
            _: *reconnect.Client,
            _: *reconnect.ClientEvent,
        ) !void {}
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{ .protocol = .v5, .client_id = "queued-disconnect" },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
    );
    defer client.deinit();
    var handler: Handler = .{};
    var run = try client.runQueued(
        Handler,
        &handler,
        Handler.handle,
        .{
            .queue_capacity = 1,
            .serve = .{
                .poll = .{ .timeout = .fromMilliseconds(50) },
            },
        },
    );
    var completions = try reconnect.CompletionQueue.init(allocator, io, 1);
    defer completions.deinit();
    var reason: [8]u8 = "original".*;
    const command_id = try run.disconnectQueued(
        &completions,
        0x04,
        &.{.{ .utf8 = .{
            .id = .reason_string,
            .value = &reason,
        } }},
    );
    @memcpy(&reason, "modified");
    var completion = try completions.receive();
    defer completion.deinit();
    try std.testing.expectEqual(command_id, completion.command_id);
    switch (try completion.result) {
        .disconnect => {},
        else => return error.UnexpectedPacket,
    }
    if (run.deinit()) |err| return err;
    try std.testing.expect(client.connection() == null);

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT queued disconnect emits the MQTT311 minimal packet" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = .v3_1_1 });
            defer accepted.deinit(self.server.allocator);
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
            try std.testing.expectEqual(@as(u8, 0), disconnect.disconnect.reason_code);
            try std.testing.expectEqual(@as(usize, 0), disconnect.disconnect.properties.len);
            try std.testing.expectEqual(@as(usize, 2), disconnect.packet.bytes.len);
        }
    };
    const Handler = struct {
        fn handle(
            _: *@This(),
            _: *reconnect.Client,
            _: *reconnect.ClientEvent,
        ) !void {}
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{ .protocol = .v3_1_1, .client_id = "queued-disconnect-v4" },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
    );
    defer client.deinit();
    var handler: Handler = .{};
    var run = try client.runQueued(
        Handler,
        &handler,
        Handler.handle,
        .{
            .queue_capacity = 1,
            .serve = .{
                .poll = .{ .timeout = .fromMilliseconds(50) },
            },
        },
    );
    try run.disconnect(0, &.{});
    if (run.deinit()) |err| return err;

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT queued disconnect validation failure keeps worker connected" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

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
            var publish = try accepted.connection.readPublish();
            defer publish.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "still/connected",
                publish.publish.topic,
            );
        }
    };
    const Handler = struct {
        fn handle(
            _: *@This(),
            _: *reconnect.Client,
            _: *reconnect.ClientEvent,
        ) !void {}
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{ .protocol = .v5, .client_id = "invalid-disconnect" },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
    );
    defer client.deinit();
    var handler: Handler = .{};
    var run = try client.runQueued(
        Handler,
        &handler,
        Handler.handle,
        .{
            .queue_capacity = 1,
            .serve = .{
                .poll = .{ .timeout = .fromMilliseconds(50) },
            },
        },
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        run.disconnect(0x01, &.{}),
    );
    _ = try run.publish("still/connected", "ok", .{});
    if (run.deinit()) |err| return err;

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT queued manual acknowledgements preserve QoS state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,
        qos1_id: u16 = 0,
        qos2_id: u16 = 0,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = .v5 });
            defer accepted.deinit(self.server.allocator);
            self.qos1_id = (try accepted.connection.writePublish(
                "manual/qos1",
                "one",
                .{ .qos = .at_least_once },
            )).?;
            var puback = try accepted.connection.readPubAck();
            defer puback.deinit(self.server.allocator);
            try std.testing.expectEqual(self.qos1_id, puback.ack.packet_id);
            try std.testing.expectEqual(@as(u8, 0x10), puback.ack.reason_code);
            try std.testing.expectEqualStrings(
                "accepted one",
                puback.ack.properties[0].utf8.value,
            );

            self.qos2_id = (try accepted.connection.writePublish(
                "manual/qos2",
                "two",
                .{ .qos = .exactly_once },
            )).?;
            var pubrec = try accepted.connection.readPubRec();
            defer pubrec.deinit(self.server.allocator);
            try std.testing.expectEqual(self.qos2_id, pubrec.ack.packet_id);
            try std.testing.expectEqualStrings(
                "accepted two",
                pubrec.ack.properties[0].utf8.value,
            );

            try accepted.connection.writePubRel(self.qos2_id, 0);
            var pubcomp = try accepted.connection.readPubComp();
            defer pubcomp.deinit(self.server.allocator);
            try std.testing.expectEqual(self.qos2_id, pubcomp.ack.packet_id);
        }
    };
    const EventHandler = struct {
        io: std.Io,
        queue: ?*reconnect.CommandQueue = null,
        ready: std.Io.Event = .unset,
        qos2_done: std.Io.Event = .unset,
        completions: *reconnect.CompletionQueue,
        ack_count: usize = 0,
        err: ?anyerror = null,

        fn handle(
            self: *@This(),
            _: *reconnect.Client,
            event: *reconnect.ClientEvent,
        ) !void {
            if (event.* == .pubrel) {
                self.qos2_done.set(self.io);
                return;
            }
            if (event.* != .publish) return;
            self.ready.waitUncancelable(self.io);
            const publish = event.publish.publish;
            const packet_id = publish.packet_id.?;
            const reason = if (publish.qos == .at_least_once)
                "accepted one"
            else
                "accepted two";
            _ = self.queue.?.acknowledgeAsync(
                packet_id,
                publish.qos,
                .{
                    .reason_code = if (publish.qos == .at_least_once) 0x10 else 0,
                    .properties = &.{.{ .utf8 = .{
                        .id = .reason_string,
                        .value = reason,
                    } }},
                },
                self.completions.handler(),
            ) catch |err| {
                self.err = err;
                return err;
            };
            self.ack_count += 1;
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.initWithOptions(
        allocator,
        io,
        server.address(),
        .{ .protocol = .v5, .client_id = "manual-acks" },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
        .{ .manual_acknowledgements = true },
    );
    defer client.deinit();
    var completions = try reconnect.CompletionQueue.init(allocator, io, 2);
    defer completions.deinit();
    var handler = EventHandler{
        .io = io,
        .completions = &completions,
    };
    var run = try client.runQueued(
        EventHandler,
        &handler,
        EventHandler.handle,
        .{
            .queue_capacity = 2,
            .serve = .{
                .poll = .{ .timeout = .fromMilliseconds(50) },
            },
        },
    );
    handler.queue = run.queue;
    handler.ready.set(io);

    var first = try completions.receive();
    defer first.deinit();
    var second = try completions.receive();
    defer second.deinit();
    try std.testing.expect(try first.result == .acknowledge);
    try std.testing.expect(try second.result == .acknowledge);
    try std.testing.expectEqual(@as(usize, 2), handler.ack_count);
    try std.testing.expect(handler.err == null);
    handler.qos2_done.waitUncancelable(io);
    if (run.deinit()) |err| return err;

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT manual QoS2 duplicate is not redelivered after PUBREC" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

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
            const packet_id = (try accepted.connection.writePublish(
                "manual/duplicate",
                "once",
                .{ .qos = .exactly_once },
            )).?;
            var first_pubrec = try accepted.connection.readPubRec();
            defer first_pubrec.deinit(self.server.allocator);
            try std.testing.expectEqual(packet_id, first_pubrec.ack.packet_id);

            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(self.server.allocator);
            try mqtt.writePublish(
                &encoded,
                self.server.allocator,
                .v5,
                "manual/duplicate",
                "once",
                .{
                    .qos = .exactly_once,
                    .dup = true,
                    .packet_id = packet_id,
                },
            );
            try accepted.connection.transport.writePacket(encoded.items);
            var repeated_pubrec = try accepted.connection.readPubRec();
            defer repeated_pubrec.deinit(self.server.allocator);
            try std.testing.expectEqual(
                packet_id,
                repeated_pubrec.ack.packet_id,
            );
            try accepted.connection.writePubRel(packet_id, 0);
            var pubcomp = try accepted.connection.readPubComp();
            defer pubcomp.deinit(self.server.allocator);
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.initWithOptions(
        allocator,
        io,
        server.address(),
        .{ .protocol = .v5, .client_id = "manual-duplicate" },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
        .{ .manual_acknowledgements = true },
    );
    defer client.deinit();
    var connected = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer connected.deinit(allocator);
    var publish = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer publish.deinit(allocator);
    const packet_id = publish.publish.publish.packet_id.?;
    try std.testing.expectError(
        error.InvalidReasonCode,
        client.acknowledge(
            packet_id,
            .exactly_once,
            .{ .reason_code = 0x01 },
        ),
    );
    try client.acknowledge(packet_id, .exactly_once, .{});
    var pubrel = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer pubrel.deinit(allocator);
    try std.testing.expect(pubrel == .pubrel);

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT manual acknowledgement rejects invalid state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
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
            try std.Io.sleep(self.server.io, .fromMilliseconds(100), .awake);
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{ .protocol = .v5, .client_id = "automatic-acks" },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
    );
    defer client.deinit();
    _ = try client.connect();
    try client.acknowledge(0, .at_most_once, .{});
    try std.testing.expectError(
        error.ManualAcknowledgementsDisabled,
        client.acknowledge(1, .at_least_once, .{}),
    );

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT manual QoS2 acknowledgement resumes PUBREL after reconnect" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,
        packet_id: u16 = 0,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var first = try self.server.accept(.{ .protocol = .v5 });
            defer first.deinit(self.server.allocator);
            self.packet_id = (try first.connection.writePublish(
                "manual/resume",
                "durable",
                .{ .qos = .exactly_once },
            )).?;
            var pubrec = try first.connection.readPubRec();
            defer pubrec.deinit(self.server.allocator);
            first.connection.shutdown() catch {};

            var second = try self.server.accept(.{
                .protocol = .v5,
                .session_present = true,
            });
            defer second.deinit(self.server.allocator);
            try second.connection.writePubRel(self.packet_id, 0);
            var pubcomp = try second.connection.readPubComp();
            defer pubcomp.deinit(self.server.allocator);
            try std.testing.expectEqual(self.packet_id, pubcomp.ack.packet_id);
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();
    var shutdown: std.Io.Event = .unset;
    const properties = [_]mqtt.Property{sessionExpiryProperty(60)};
    var client = try reconnect.Client.initWithOptions(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "manual-resume",
            .clean_start = false,
            .properties = &properties,
        },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
        .{ .manual_acknowledgements = true },
    );
    defer client.deinit();
    var connected = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer connected.deinit(allocator);
    var publish = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer publish.deinit(allocator);
    try client.acknowledge(
        publish.publish.publish.packet_id.?,
        .exactly_once,
        .{},
    );
    var reconnected = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer reconnected.deinit(allocator);
    try std.testing.expect(reconnected == .connected);
    try std.testing.expect(reconnected.connected.session_present);
    var pubrel = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer pubrel.deinit(allocator);
    try std.testing.expect(pubrel == .pubrel);

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
