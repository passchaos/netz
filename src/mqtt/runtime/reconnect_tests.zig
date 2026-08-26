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
