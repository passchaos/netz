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

test "MQTT reconnect Session snapshot resumes outgoing QoS2 on the wire" {
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
        packet_id: u16 = 0,
        first_publish_seen: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.first_publish_seen.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.server.accept(.{ .protocol = .v5 });
            defer first.deinit(self.server.allocator);
            var publish = try first.connection.readPublish();
            defer publish.deinit(self.server.allocator);
            try std.testing.expectEqual(mqtt.QoS.exactly_once, publish.publish.qos);
            try std.testing.expect(!publish.publish.dup);
            self.packet_id = publish.publish.packet_id.?;
            self.first_publish_seen.set(self.server.io);
            first.connection.shutdown() catch {};

            var second = try self.server.accept(.{
                .protocol = .v5,
                .session_present = true,
            });
            defer second.deinit(self.server.allocator);
            var replay = try second.connection.readPublish();
            defer replay.deinit(self.server.allocator);
            try std.testing.expectEqual(self.packet_id, replay.publish.packet_id.?);
            try std.testing.expect(replay.publish.dup);
            try std.testing.expectEqualStrings("snapshot/qos2", replay.publish.topic);
            try std.testing.expectEqualStrings("durable", replay.publish.payload);
            try second.connection.writePubRec(self.packet_id, 0);
            var pubrel = try second.connection.readPubRel();
            defer pubrel.deinit(self.server.allocator);
            try std.testing.expectEqual(self.packet_id, pubrel.ack.packet_id);
            try second.connection.writePubComp(self.packet_id, 0);
            var disconnect = try second.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    const properties = [_]mqtt.Property{sessionExpiryProperty(60)};
    const connect_options: runtime.ConnectOptions = .{
        .protocol = .v5,
        .client_id = "snapshot-wire",
        .clean_start = false,
        .properties = &properties,
    };
    var shutdown: std.Io.Event = .unset;
    var first_client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        connect_options,
        .{},
        &shutdown,
    );
    defer first_client.deinit();
    _ = try first_client.connectWithTimeout(.fromSeconds(1));
    const attempt = try first_client.publishOneAttempt(
        "snapshot/qos2",
        "durable",
        .{ .qos = .exactly_once },
    );
    try shared.first_publish_seen.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    } });
    var busy_snapshot: std.ArrayList(u8) = .empty;
    defer busy_snapshot.deinit(allocator);
    try std.testing.expectError(
        error.SnapshotBusy,
        first_client.writeSessionSnapshot(&busy_snapshot),
    );
    first_client.disconnectTransport();

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try first_client.writeSessionSnapshotAt(
        &encoded,
        std.Io.Timestamp.fromNanoseconds(std.time.ns_per_s),
        std.Io.Timestamp.fromNanoseconds(100 * std.time.ns_per_s),
    );
    try std.testing.expectError(
        error.SessionStateNotEmpty,
        first_client.restoreSessionSnapshotAt(
            encoded.items,
            std.Io.Timestamp.fromNanoseconds(2 * std.time.ns_per_s),
            std.Io.Timestamp.fromNanoseconds(101 * std.time.ns_per_s),
        ),
    );

    var restored = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        connect_options,
        .{},
        &shutdown,
    );
    defer restored.deinit();
    try restored.restoreSessionSnapshotAt(
        encoded.items,
        std.Io.Timestamp.fromNanoseconds(2 * std.time.ns_per_s),
        std.Io.Timestamp.fromNanoseconds(101 * std.time.ns_per_s),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        (try restored.outgoingStats()).inflight_count,
    );
    const connected = try restored.connectWithTimeout(.fromSeconds(1));
    try std.testing.expect(connected.session_present);
    var pubrec = (try restored.pollWithTimeout(.fromSeconds(1))).?;
    defer pubrec.deinit(allocator);
    try std.testing.expect(pubrec == .pubrec);
    try std.testing.expectEqual(attempt.packet_id.?, pubrec.pubrec.ack.packet_id);
    var pubcomp = (try restored.pollWithTimeout(.fromSeconds(1))).?;
    defer pubcomp.deinit(allocator);
    try std.testing.expect(pubcomp == .pubcomp);
    try std.testing.expectEqual(attempt.packet_id.?, pubcomp.pubcomp.ack.packet_id);
    try std.testing.expectEqual(
        @as(usize, 0),
        (try restored.outgoingStats()).inflight_count,
    );
    try restored.disconnect(0);

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT reconnect Session snapshot restore is fail closed" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var shutdown: std.Io.Event = .unset;
    const properties = [_]mqtt.Property{sessionExpiryProperty(60)};
    const unused = std.Io.net.IpAddress{ .ip4 = .loopback(1) };
    var persistent = try reconnect.Client.init(
        allocator,
        io,
        unused,
        .{
            .protocol = .v5,
            .client_id = "snapshot-identity",
            .clean_start = false,
            .properties = &properties,
        },
        .{},
        &shutdown,
    );
    defer persistent.deinit();
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try persistent.writeSessionSnapshotAt(&encoded, .zero, .zero);

    var other = try reconnect.Client.init(
        allocator,
        io,
        unused,
        .{
            .protocol = .v5,
            .client_id = "snapshot-other",
            .clean_start = false,
            .properties = &properties,
        },
        .{},
        &shutdown,
    );
    defer other.deinit();
    try std.testing.expectError(
        error.SnapshotClientMismatch,
        other.restoreSessionSnapshotAt(encoded.items, .zero, .zero),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        (try other.outgoingStats()).inflight_count,
    );
    // A rejected foreign snapshot leaves the destination empty and able to
    // accept its own valid image later; restore is transactional rather than
    // partially mutating identity or Session storage.
    var other_encoded: std.ArrayList(u8) = .empty;
    defer other_encoded.deinit(allocator);
    try other.writeSessionSnapshotAt(&other_encoded, .zero, .zero);
    var trailing: std.ArrayList(u8) = .empty;
    defer trailing.deinit(allocator);
    try trailing.appendSlice(
        allocator,
        other_encoded.items[0 .. other_encoded.items.len - @sizeOf(u32)],
    );
    try trailing.append(allocator, 0xaa);
    var checksum: [4]u8 = undefined;
    std.mem.writeInt(
        u32,
        &checksum,
        std.hash.crc.Crc32.hash(trailing.items),
        .big,
    );
    try trailing.appendSlice(allocator, &checksum);
    try std.testing.expectError(
        error.CorruptSnapshot,
        other.restoreSessionSnapshotAt(trailing.items, .zero, .zero),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        (try other.outgoingStats()).inflight_count,
    );
    try other.restoreSessionSnapshotAt(other_encoded.items, .zero, .zero);
    try std.testing.expectEqual(
        @as(usize, 0),
        (try other.outgoingStats()).inflight_count,
    );

    var transient = try reconnect.Client.init(
        allocator,
        io,
        unused,
        .{ .protocol = .v5, .client_id = "snapshot-transient" },
        .{},
        &shutdown,
    );
    defer transient.deinit();
    try std.testing.expectError(
        error.SessionPersistenceDisabled,
        transient.writeSessionSnapshotAt(&encoded, .zero, .zero),
    );
}

test "MQTT reconnect Session snapshot resumes deferred inbound QoS2" {
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
        packet_id: u16 = 0,
        pubrec_seen: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.pubrec_seen.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.server.accept(.{ .protocol = .v5 });
            defer first.deinit(self.server.allocator);
            self.packet_id = (try first.connection.writePublish(
                "snapshot/inbound",
                "deferred",
                .{ .qos = .exactly_once },
            )).?;
            var pubrec = try first.connection.readPubRec();
            defer pubrec.deinit(self.server.allocator);
            try std.testing.expectEqual(self.packet_id, pubrec.ack.packet_id);
            self.pubrec_seen.set(self.server.io);
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
            var disconnect = try second.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    const properties = [_]mqtt.Property{sessionExpiryProperty(60)};
    const connect_options: runtime.ConnectOptions = .{
        .protocol = .v5,
        .client_id = "snapshot-inbound",
        .clean_start = false,
        .properties = &properties,
    };
    const client_options: reconnect.ClientOptions = .{
        .manual_acknowledgements = true,
        .inbound_qos2_release_policy = .deferred,
    };
    var shutdown: std.Io.Event = .unset;
    var first_client = try reconnect.Client.initWithOptions(
        allocator,
        io,
        server.address(),
        connect_options,
        .{},
        &shutdown,
        client_options,
    );
    defer first_client.deinit();
    var connected = (try first_client.pollWithTimeout(.fromSeconds(1))).?;
    defer connected.deinit(allocator);
    var publish = (try first_client.pollWithTimeout(.fromSeconds(1))).?;
    defer publish.deinit(allocator);
    const packet_id = publish.publish.publish.packet_id.?;
    try first_client.acknowledge(packet_id, .exactly_once, .{});
    try shared.pubrec_seen.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    } });
    first_client.disconnectTransport();
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try first_client.writeSessionSnapshotAt(
        &encoded,
        std.Io.Timestamp.fromNanoseconds(std.time.ns_per_s),
        std.Io.Timestamp.fromNanoseconds(100 * std.time.ns_per_s),
    );

    var restored = try reconnect.Client.initWithOptions(
        allocator,
        io,
        server.address(),
        connect_options,
        .{},
        &shutdown,
        client_options,
    );
    defer restored.deinit();
    try restored.restoreSessionSnapshotAt(
        encoded.items,
        std.Io.Timestamp.fromNanoseconds(2 * std.time.ns_per_s),
        std.Io.Timestamp.fromNanoseconds(101 * std.time.ns_per_s),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        (try restored.outgoingStats()).incoming_qos2_count,
    );
    const resumed = try restored.connectWithTimeout(.fromSeconds(1));
    try std.testing.expect(resumed.session_present);
    var pubrel = (try restored.pollWithTimeout(.fromSeconds(1))).?;
    defer pubrel.deinit(allocator);
    try std.testing.expect(pubrel == .pubrel);
    try std.testing.expectEqual(packet_id, pubrel.pubrel.ack.packet_id);
    try restored.completeIncomingQoS2(packet_id, .{});
    try std.testing.expectEqual(
        @as(usize, 0),
        (try restored.outgoingStats()).incoming_qos2_count,
    );
    try restored.disconnect(0);

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
