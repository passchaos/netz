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
