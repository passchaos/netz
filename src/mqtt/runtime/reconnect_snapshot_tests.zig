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

test "MQTT inbound QoS2 staging holds PUBREC and permits pre-wire rollback" {
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
        staged: std.Io.Event = .unset,
        prewire_checked: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.prewire_checked.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = .v5 });
            defer accepted.deinit(self.server.allocator);
            const packet_id = (try accepted.connection.writePublish(
                "snapshot/staged-inbound",
                "durable source",
                .{ .qos = .exactly_once },
            )).?;
            self.staged.waitUncancelable(self.server.io);
            try std.testing.expectError(
                error.Timeout,
                accepted.connection.readBrokerEventWithTimeout(
                    .fromMilliseconds(20),
                ),
            );
            self.prewire_checked.set(self.server.io);
            var pubrec = try accepted.connection.readPubRec();
            defer pubrec.deinit(self.server.allocator);
            try std.testing.expectEqual(packet_id, pubrec.ack.packet_id);
            try accepted.connection.writePubRel(packet_id, 0);
            var pubcomp = try accepted.connection.readPubComp();
            defer pubcomp.deinit(self.server.allocator);
            try std.testing.expectEqual(packet_id, pubcomp.ack.packet_id);
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer {
        shared.staged.set(io);
        if (!joined) server_thread.join();
    }

    const properties = [_]mqtt.Property{sessionExpiryProperty(60)};
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.initWithOptions(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "snapshot-staged-inbound",
            .clean_start = false,
            .properties = &properties,
        },
        .{},
        &shutdown,
        .{
            .manual_acknowledgements = true,
            .inbound_qos2_release_policy = .deferred,
        },
    );
    defer client.deinit();
    var connected = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer connected.deinit(allocator);
    var publish = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer publish.deinit(allocator);
    const packet_id = publish.publish.publish.packet_id.?;

    try client.stageIncomingQoS2(packet_id);
    try std.testing.expectEqual(
        @as(usize, 1),
        (try client.outgoingStats()).incoming_qos2_count,
    );
    try client.discardStagedIncomingQoS2(packet_id);
    try std.testing.expectEqual(
        @as(usize, 0),
        (try client.outgoingStats()).incoming_qos2_count,
    );
    try client.stageIncomingQoS2(packet_id);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try client.writeSessionSnapshot(&encoded);
    shared.staged.set(io);
    try shared.prewire_checked.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    } });
    try client.acknowledge(packet_id, .exactly_once, .{});
    try std.testing.expectError(
        error.InvalidAcknowledgement,
        client.discardStagedIncomingQoS2(packet_id),
    );
    var pubrel = (try client.pollWithTimeout(.fromSeconds(1))).?;
    defer pubrel.deinit(allocator);
    try std.testing.expect(pubrel == .pubrel);
    try client.completeIncomingQoS2(packet_id, .{});
    try client.disconnect(0);

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT snapshot restores a staged inbound QoS2 before PUBREC" {
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
        staged: std.Io.Event = .unset,
        first_closed: std.Io.Event = .unset,
        reconnected_no_pubrec: std.Io.Event = .unset,
        snapshot_written: std.Io.Event = .unset,
        second_closed: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.first_closed.set(self.server.io);
                self.reconnected_no_pubrec.set(self.server.io);
                self.second_closed.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            const packet_id: u16 = 1;
            {
                var first = try self.server.accept(.{ .protocol = .v5 });
                defer first.deinit(self.server.allocator);
                try std.testing.expectEqual(
                    packet_id,
                    (try first.connection.writePublish(
                        "snapshot/staged-inbound-restore",
                        "durable source",
                        .{ .qos = .exactly_once },
                    )).?,
                );
                self.staged.waitUncancelable(self.server.io);
                try std.testing.expectError(
                    error.Timeout,
                    first.connection.readBrokerEventWithTimeout(
                        .fromMilliseconds(20),
                    ),
                );
                first.connection.shutdown() catch {};
            }
            self.first_closed.set(self.server.io);

            {
                var second = try self.server.accept(.{
                    .protocol = .v5,
                    .session_present = true,
                });
                defer second.deinit(self.server.allocator);
                try std.testing.expectEqual(
                    packet_id,
                    (try second.connection.writePublish(
                        "snapshot/staged-inbound-restore",
                        "durable source",
                        .{
                            .qos = .exactly_once,
                            .dup = true,
                        },
                    )).?,
                );
                try std.testing.expectError(
                    error.Timeout,
                    second.connection.readBrokerEventWithTimeout(
                        .fromMilliseconds(20),
                    ),
                );
                self.reconnected_no_pubrec.set(self.server.io);
                self.snapshot_written.waitUncancelable(self.server.io);
                second.connection.shutdown() catch {};
            }
            self.second_closed.set(self.server.io);

            var third = try self.server.accept(.{
                .protocol = .v5,
                .session_present = true,
            });
            defer third.deinit(self.server.allocator);
            try std.testing.expectEqual(
                packet_id,
                (try third.connection.writePublish(
                    "snapshot/staged-inbound-restore",
                    "durable source",
                    .{
                        .qos = .exactly_once,
                        .dup = true,
                    },
                )).?,
            );
            var pubrec = try third.connection.readPubRec();
            defer pubrec.deinit(self.server.allocator);
            try std.testing.expectEqual(packet_id, pubrec.ack.packet_id);
            try third.connection.writePubRel(packet_id, 0);
            var pubcomp = try third.connection.readPubComp();
            defer pubcomp.deinit(self.server.allocator);
            var disconnect = try third.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer {
        shared.staged.set(io);
        shared.snapshot_written.set(io);
        if (!joined) server_thread.join();
    }

    const properties = [_]mqtt.Property{sessionExpiryProperty(60)};
    const connect_options: runtime.ConnectOptions = .{
        .protocol = .v5,
        .client_id = "snapshot-staged-inbound-restore",
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
    try first_client.stageIncomingQoS2(packet_id);
    shared.staged.set(io);
    try shared.first_closed.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    } });
    first_client.disconnectTransport();
    const reconnected = try first_client.connectWithTimeout(.fromSeconds(1));
    try std.testing.expect(reconnected.session_present);
    var duplicate = (try first_client.pollWithTimeout(.fromSeconds(1))).?;
    defer duplicate.deinit(allocator);
    try std.testing.expect(duplicate == .publish);
    try std.testing.expect(duplicate.publish.publish.dup);
    try std.testing.expectEqual(
        packet_id,
        duplicate.publish.publish.packet_id.?,
    );
    try shared.reconnected_no_pubrec.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    } });
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try first_client.writeSessionSnapshot(&encoded);
    shared.snapshot_written.set(io);
    try shared.second_closed.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    } });
    first_client.disconnectTransport();

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
    try restored.restoreSessionSnapshot(encoded.items);
    const resumed = try restored.connectWithTimeout(.fromSeconds(1));
    try std.testing.expect(resumed.session_present);
    var pubrel = (try restored.pollWithTimeout(.fromSeconds(1))).?;
    defer pubrel.deinit(allocator);
    try std.testing.expect(pubrel == .pubrel);
    try restored.completeIncomingQoS2(packet_id, .{});
    try restored.disconnect(0);

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

fn runDeferredOutgoingQoS2SnapshotCase(
    restore_before_pubrel: bool,
) !void {
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
        restore_before_pubrel: bool,
        reconnect_requested: std.Io.Event = .unset,
        snapshot_written: std.Io.Event = .unset,
        no_pubrel_seen: std.Io.Event = .unset,
        first_closed: std.Io.Event = .unset,
        reconnected_no_pubrel: std.Io.Event = .unset,
        second_closed: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.no_pubrel_seen.set(self.server.io);
                self.first_closed.set(self.server.io);
                self.reconnected_no_pubrel.set(self.server.io);
                self.second_closed.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.server.accept(.{ .protocol = .v5 });
            defer first.deinit(self.server.allocator);
            var publish = try first.connection.readPublish();
            defer publish.deinit(self.server.allocator);
            const packet_id = publish.publish.packet_id.?;
            try std.testing.expectEqual(
                mqtt.QoS.exactly_once,
                publish.publish.qos,
            );
            try first.connection.writePubRec(packet_id, 0);
            try std.testing.expectError(
                error.Timeout,
                first.connection.readBrokerEventWithTimeout(
                    .fromMilliseconds(20),
                ),
            );
            self.no_pubrel_seen.set(self.server.io);

            if (!self.restore_before_pubrel) {
                var pubrel = try first.connection.readPubRel();
                defer pubrel.deinit(self.server.allocator);
                try std.testing.expectEqual(packet_id, pubrel.ack.packet_id);
                try first.connection.writePubComp(packet_id, 0);
                var disconnect = try first.connection.readDisconnect();
                defer disconnect.deinit(self.server.allocator);
                return;
            }

            self.reconnect_requested.waitUncancelable(self.server.io);
            first.connection.shutdown() catch {};
            self.first_closed.set(self.server.io);
            var second = try self.server.accept(.{
                .protocol = .v5,
                .session_present = true,
            });
            defer second.deinit(self.server.allocator);
            try std.testing.expectError(
                error.Timeout,
                second.connection.readBrokerEventWithTimeout(
                    .fromMilliseconds(20),
                ),
            );
            self.reconnected_no_pubrel.set(self.server.io);
            self.snapshot_written.waitUncancelable(self.server.io);
            second.connection.shutdown() catch {};
            self.second_closed.set(self.server.io);

            var third = try self.server.accept(.{
                .protocol = .v5,
                .session_present = true,
            });
            defer third.deinit(self.server.allocator);
            try third.connection.resumeIncomingQoS2(packet_id);
            var pubrel = try third.connection.readPubRel();
            defer pubrel.deinit(self.server.allocator);
            try std.testing.expectEqual(packet_id, pubrel.ack.packet_id);
            try third.connection.writePubComp(packet_id, 0);
            var disconnect = try third.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };
    var shared = Shared{
        .server = &server,
        .restore_before_pubrel = restore_before_pubrel,
    };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer {
        shared.reconnect_requested.set(io);
        shared.snapshot_written.set(io);
        if (!joined) server_thread.join();
    }

    const properties = [_]mqtt.Property{sessionExpiryProperty(60)};
    const connect_options: runtime.ConnectOptions = .{
        .protocol = .v5,
        .client_id = if (restore_before_pubrel)
            "snapshot-deferred-restore"
        else
            "snapshot-deferred-flush",
        .clean_start = false,
        .properties = &properties,
    };
    const client_options: reconnect.ClientOptions = .{
        .outbound_qos2_release_policy = .deferred,
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
    _ = try first_client.connectWithTimeout(.fromSeconds(1));
    const packet_id = try first_client.stagePublish(
        "snapshot/deferred-pubrel",
        "durable transition",
        .{ .qos = .exactly_once },
    );
    try first_client.flushPending();
    var pubrec = (try first_client.pollWithTimeout(.fromSeconds(1))).?;
    defer pubrec.deinit(allocator);
    try std.testing.expect(pubrec == .pubrec);
    try std.testing.expectEqual(packet_id, pubrec.pubrec.ack.packet_id);
    try shared.no_pubrel_seen.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    } });

    if (!restore_before_pubrel) {
        try first_client.flushPending();
        var pubcomp = (try first_client.pollWithTimeout(.fromSeconds(1))).?;
        defer pubcomp.deinit(allocator);
        try std.testing.expect(pubcomp == .pubcomp);
        try std.testing.expectEqual(packet_id, pubcomp.pubcomp.ack.packet_id);
        try first_client.disconnect(0);
    } else {
        shared.reconnect_requested.set(io);
        try shared.first_closed.waitTimeout(io, .{ .duration = .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        } });
        first_client.disconnectTransport();
        const reconnected = try first_client.connectWithTimeout(
            .fromSeconds(1),
        );
        try std.testing.expect(reconnected.session_present);
        try shared.reconnected_no_pubrel.waitTimeout(io, .{ .duration = .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        } });
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try first_client.writeSessionSnapshot(&encoded);
        shared.snapshot_written.set(io);
        try shared.second_closed.waitTimeout(io, .{ .duration = .{
            .raw = .fromSeconds(1),
            .clock = .awake,
        } });
        first_client.disconnectTransport();
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
        try restored.restoreSessionSnapshot(encoded.items);
        const connected = try restored.connectWithTimeout(.fromSeconds(1));
        try std.testing.expect(connected.session_present);
        var pubcomp = (try restored.pollWithTimeout(.fromSeconds(1))).?;
        defer pubcomp.deinit(allocator);
        try std.testing.expect(pubcomp == .pubcomp);
        try std.testing.expectEqual(packet_id, pubcomp.pubcomp.ack.packet_id);
        try restored.disconnect(0);
    }

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT deferred outgoing QoS2 writes PUBREL only after flush" {
    try runDeferredOutgoingQoS2SnapshotCase(false);
}

test "MQTT snapshot restores deferred outgoing QoS2 at PUBREL" {
    try runDeferredOutgoingQoS2SnapshotCase(true);
}

test "MQTT reconnect Session snapshot stages QoS2 before first wire write" {
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
        expected_packet_id: u16 = 0,
        staged: std.Io.Event = .unset,
        prewire_checked: std.Io.Event = .unset,
        first_publish_seen: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.prewire_checked.set(self.server.io);
                self.first_publish_seen.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.server.accept(.{ .protocol = .v5 });
            defer first.deinit(self.server.allocator);
            try self.staged.waitTimeout(self.server.io, .{ .duration = .{
                .raw = .fromSeconds(1),
                .clock = .awake,
            } });
            try std.testing.expectError(
                error.Timeout,
                first.connection.readBrokerEventWithTimeout(
                    .fromMilliseconds(20),
                ),
            );
            self.prewire_checked.set(self.server.io);
            var publish = try first.connection.readPublish();
            defer publish.deinit(self.server.allocator);
            try std.testing.expectEqual(mqtt.QoS.exactly_once, publish.publish.qos);
            try std.testing.expect(!publish.publish.dup);
            try std.testing.expectEqual(
                self.expected_packet_id,
                publish.publish.packet_id.?,
            );
            self.first_publish_seen.set(self.server.io);
            first.connection.shutdown() catch {};

            var second = try self.server.accept(.{
                .protocol = .v5,
                .session_present = true,
            });
            defer second.deinit(self.server.allocator);
            var replay = try second.connection.readPublish();
            defer replay.deinit(self.server.allocator);
            try std.testing.expectEqual(
                self.expected_packet_id,
                replay.publish.packet_id.?,
            );
            try std.testing.expect(replay.publish.dup);
            try std.testing.expectEqualStrings("snapshot/qos2", replay.publish.topic);
            try std.testing.expectEqualStrings("durable", replay.publish.payload);
            try second.connection.writePubRec(self.expected_packet_id, 0);
            var pubrel = try second.connection.readPubRel();
            defer pubrel.deinit(self.server.allocator);
            try std.testing.expectEqual(
                self.expected_packet_id,
                pubrel.ack.packet_id,
            );
            try second.connection.writePubComp(self.expected_packet_id, 0);
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
    const active = first_client.connection().?;
    const runtime_packet_id_before = active.next_packet_id;
    const runtime_inflight_before = active.outgoing_inflight;
    const alias_count_before = active.outgoing_topic_aliases.count();
    try std.testing.expectError(
        error.InvalidQoS,
        first_client.stagePublish(
            "snapshot/qos0",
            "not-durable",
            .{},
        ),
    );
    const packet_id = try first_client.stagePublish(
        "snapshot/qos2",
        "durable",
        .{ .qos = .exactly_once },
    );
    try std.testing.expectEqual(
        runtime_packet_id_before,
        active.next_packet_id,
    );
    try std.testing.expectEqual(
        runtime_inflight_before,
        active.outgoing_inflight,
    );
    try std.testing.expectEqual(
        alias_count_before,
        active.outgoing_topic_aliases.count(),
    );
    shared.expected_packet_id = packet_id;
    shared.staged.set(io);
    try shared.prewire_checked.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    } });
    try std.testing.expectEqual(
        @as(usize, 1),
        (try first_client.outgoingStats()).inflight_count,
    );
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try first_client.writeSessionSnapshotAt(
        &encoded,
        std.Io.Timestamp.fromNanoseconds(std.time.ns_per_s),
        std.Io.Timestamp.fromNanoseconds(100 * std.time.ns_per_s),
    );
    try first_client.flushPending();
    try std.testing.expectError(
        error.InvalidAcknowledgement,
        first_client.discardStagedPublish(packet_id),
    );
    try shared.first_publish_seen.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    } });
    first_client.disconnectTransport();

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
    try std.testing.expectEqual(packet_id, pubrec.pubrec.ack.packet_id);
    var pubcomp = (try restored.pollWithTimeout(.fromSeconds(1))).?;
    defer pubcomp.deinit(allocator);
    try std.testing.expect(pubcomp == .pubcomp);
    try std.testing.expectEqual(packet_id, pubcomp.pubcomp.ack.packet_id);
    try std.testing.expectEqual(
        @as(usize, 0),
        (try restored.outgoingStats()).inflight_count,
    );
    try restored.disconnect(0);

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT reconnect staged publish can be discarded before selection" {
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
        rollback_complete: std.Io.Event = .unset,
        prewire_checked: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.prewire_checked.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = .v5 });
            defer accepted.deinit(self.server.allocator);
            try self.rollback_complete.waitTimeout(
                self.server.io,
                .{ .duration = .{
                    .raw = .fromSeconds(1),
                    .clock = .awake,
                } },
            );
            try std.testing.expectError(
                error.Timeout,
                accepted.connection.readBrokerEventWithTimeout(
                    .fromMilliseconds(20),
                ),
            );
            self.prewire_checked.set(self.server.io);
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    const properties = [_]mqtt.Property{sessionExpiryProperty(60)};
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "snapshot-rollback",
            .clean_start = false,
            .properties = &properties,
        },
        .{},
        &shutdown,
    );
    defer client.deinit();
    _ = try client.connectWithTimeout(.fromSeconds(1));
    const packet_id = try client.stagePublish(
        "snapshot/rollback",
        "discarded",
        .{ .qos = .at_least_once },
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        (try client.outgoingStats()).inflight_count,
    );
    try client.discardStagedPublish(packet_id);
    try std.testing.expectEqual(
        @as(usize, 0),
        (try client.outgoingStats()).inflight_count,
    );
    try std.testing.expectError(
        error.InvalidAcknowledgement,
        client.discardStagedPublish(packet_id),
    );
    shared.rollback_complete.set(io);
    try shared.prewire_checked.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    } });
    try client.disconnect(0);

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
