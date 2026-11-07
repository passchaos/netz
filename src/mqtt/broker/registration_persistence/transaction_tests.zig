//! Locked QoS transactions exclude provisional admission before mutation.
const std = @import("std");
const test_tmp = @import("../../../internal/test_tmp_dir.zig");
const timed_mutex = @import("../../../internal/timed_mutex.zig");
const context = @import("../../broker_tests.zig").TestContext;
const mqtt = context.mqtt_mod;
const runtime = context.runtime_mod;
const session_route = @import("../session_route.zig");
const admission = @import("../persistence_admission.zig");
const support = @import("test_support.zig");
const allocator = std.testing.allocator;
const topic = "txn/incoming";
const payload = "only-once";
const packet_id: u16 = 19;

fn offlineSession(broker: *context.BrokerType) !void {
    const now = std.Io.Clock.awake.now(broker.io);
    const opened = try broker.sessions.open("txn-offline", false, 120, now);
    const subscription = mqtt.Subscription{ .topic_filter = "txn/#", .qos = .at_least_once };
    _ = try broker.sessions.setSubscription(opened.handle, subscription, null);
    _ = try broker.router.subscribeWithIdentifierStatus(session_route.sessionSubscriberId(opened.route_id), subscription, null);
    try broker.sessions.disconnect(opened.handle, null, now);
}

fn publisher(broker: *context.BrokerType, io: std.Io) !runtime.Connection {
    return runtime.Client.connect(allocator, io, broker.address(), .{
        .protocol = .v5,
        .client_id = "txn-publisher",
        .clean_start = false,
        .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 120 } }},
    });
}

fn sendPublish(connection: *runtime.Connection) !void {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try mqtt.writePublish(&bytes, allocator, .v5, topic, payload, .{ .qos = .exactly_once, .retain = true, .packet_id = packet_id });
    try connection.transport.writePacket(bytes.items);
}

fn sendPubrel(connection: *runtime.Connection) !void {
    var bytes = [_]u8{ 0x62, 0x02, 0x00, @intCast(packet_id) };
    try connection.transport.writePacket(&bytes);
}

fn expectAck(connection: *runtime.Connection, kind: mqtt.PacketType) !void {
    var packet = try connection.transport.readPacketWithDeadline(allocator, 4096, connection.transport.deadlineFromNow(.fromSeconds(5)));
    defer packet.deinit(allocator);
    try std.testing.expectEqual(kind, packet.fixed.packet_type);
    var ack = try mqtt.AckPacket.parsePayload(allocator, .v5, kind, packet.fixed.flags, packet.remainingBytes());
    defer ack.deinit(allocator);
    try std.testing.expectEqual(packet_id, ack.packet_id);
    try std.testing.expectEqual(@as(u8, 0), ack.reason_code);
}

fn expectNoAck(connection: *runtime.Connection) !void {
    var packet = connection.transport.readPacketWithDeadline(allocator, 4096, connection.transport.deadlineFromNow(.fromMilliseconds(10))) catch |err| {
        try std.testing.expect(err == error.Timeout);
        return;
    };
    defer packet.deinit(allocator);
    return error.PrematureAcknowledgement;
}

fn queuedCount(broker: *context.BrokerType) !usize {
    broker.state_mutex.lockUncancelable(broker.io);
    defer broker.state_mutex.unlock(broker.io);
    const handle = broker.sessions.find("txn-offline", std.Io.Clock.awake.now(broker.io)) orelse return error.SessionNotFound;
    return (try broker.sessions.stats(handle)).queued_count;
}

fn verifyOneDelivery(broker: *context.BrokerType) !void {
    try std.testing.expectEqual(@as(usize, 1), try queuedCount(broker));
    const now = std.Io.Clock.awake.now(broker.io);
    const opened = try broker.sessions.open("txn-offline", false, 120, now);
    try std.testing.expect(opened.session_present);
    var output: [2]mqtt.session.Transmission = undefined;
    const deliveries = try broker.sessions.drainInto(opened.handle, now, 2, &output);
    try std.testing.expectEqual(@as(usize, 1), deliveries.len);
    try std.testing.expect(deliveries[0] == .publish);
    try std.testing.expectEqualStrings(topic, deliveries[0].publish.topic);
    try std.testing.expectEqualStrings(payload, deliveries[0].publish.payload);
    try std.testing.expectEqual(mqtt.QoS.at_least_once, deliveries[0].publish.qos);
}

const WireCase = enum { existing_admission, reservation_during_sync, sync_failure };

test "broker locked PUBREL waits before mutation for a provisional CONNECT" {
    try pubrelOverlap(.existing_admission);
}

test "broker locked PUBREL fsync excludes new reservations and permits cancellation before claim" {
    try pubrelOverlap(.reservation_during_sync);
}

test "broker locked PUBREL keeps fsync errors observable and withholds PUBCOMP" {
    try pubrelOverlap(.sync_failure);
}

fn pubrelOverlap(mode: WireCase) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var observer = support.AdmissionOverlap{ .delegate = io, .park_second = mode == .existing_admission };
    support.AdmissionOverlap.active = &observer;
    defer support.AdmissionOverlap.active = null;
    var table = io.vtable.*;
    table.netWrite = support.AdmissionOverlap.netWrite;
    table.netClose = support.AdmissionOverlap.netClose;
    table.sleep = support.AdmissionOverlap.sleep;
    table.fileSync = support.AdmissionOverlap.fileSync;
    table.futexWait = support.AdmissionOverlap.waitCancelable;
    table.futexWaitUncancelable = support.AdmissionOverlap.waitUncancelable;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &table };
    var broker = try context.testBrokerFn(allocator, observed_io, 2, 64);
    defer broker.deinit();
    try offlineSession(&broker);
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try broker.createCommitLog(tmp.dir, "pubrel-txn.log", .{});
    var service = support.OverlapService{ .broker = &broker, .stop_on_error = mode == .sync_failure };
    const server_thread = try std.Thread.spawn(.{}, support.OverlapService.run, .{&service});
    var server_joined = false;
    defer if (!server_joined) {
        observer.unblock();
        service.shutdown.set(io);
        server_thread.join();
    };
    var source = try publisher(&broker, io);
    defer source.close();
    try sendPublish(&source);
    try expectAck(&source, .pubrec);
    try std.testing.expectEqual(@as(usize, 0), try queuedCount(&broker));
    var client = support.OverlapClient{ .io = io, .address = broker.address(), .client_id = "txn-admission" };
    var client_thread: ?std.Thread = null;
    var client_joined = false;
    defer {
        observer.unblock();
        if (client_thread) |thread| if (!client_joined) thread.join();
        if (client.result) |*result| result.deinit(allocator);
    }
    switch (mode) {
        .existing_admission => {
            client_thread = try std.Thread.spawn(.{}, support.OverlapClient.run, .{&client});
            try support.waitOverlap(&observer.connack_parked, io);
            try sendPubrel(&source);
            try support.waitOverlap(&observer.retry_entered, io);
            const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
            try timed_mutex.lock(&broker.persistence_mutex, io, deadline);
            broker.persistence_mutex.unlock(io);
            const pending = state: {
                try timed_mutex.lock(&broker.state_mutex, io, deadline);
                defer broker.state_mutex.unlock(io);
                break :state broker.pending_qos2.count();
            };
            try std.testing.expectEqual(@as(usize, 1), pending);
            try std.testing.expectEqual(@as(usize, 0), try queuedCount(&broker));
            try std.testing.expectError(error.SnapshotBusy, broker.appendCommit());
            try std.testing.expectError(error.SnapshotBusy, broker.saveLiveSnapshot(tmp.dir, "busy-pubrel.db"));
            try expectNoAck(&source);
            observer.release_connack.set(io);
            client_thread.?.join();
            client_joined = true;
            if (client.err) |err| return err;
            observer.release_retry.set(io);
            try expectAck(&source, .pubcomp);
        },
        .reservation_during_sync => {
            observer.old_writer.store(&broker.persistence_mutex, .release);
            observer.sync_armed.store(true, .release);
            try sendPubrel(&source);
            try support.waitOverlap(&observer.sync_entered, io);
            const Attempt = struct {
                const Context = struct {
                    pub const BrokerType = context.BrokerType;
                };
                fn run(owner: *context.BrokerType) !usize {
                    return admission.claimSlot(Context, owner);
                }
            };
            var canceled_claim = try io.concurrent(Attempt.run, .{&broker});
            var claim_pending = true;
            defer if (claim_pending) {
                _ = canceled_claim.cancel(io) catch {};
            };
            try support.waitOverlap(&observer.writer_parked, io);
            try std.testing.expectError(error.Canceled, canceled_claim.cancel(io));
            claim_pending = false;
            try assertOnlyPublisherReserved(&broker);
            observer.writer_parked.reset();
            client_thread = try std.Thread.spawn(.{}, support.OverlapClient.run, .{&client});
            try support.waitOverlap(&observer.writer_parked, io);
            try assertOnlyPublisherReserved(&broker);
            try expectNoAck(&source);
            observer.release_sync.set(io);
            try expectAck(&source, .pubcomp);
            try std.testing.expect(observer.sync_complete.isSet());
            client_thread.?.join();
            client_joined = true;
            if (client.err) |err| return err;
        },
        .sync_failure => {
            observer.fail_sync.store(true, .release);
            try sendPubrel(&source);
            try support.waitOverlap(&observer.first_retired, io);
            try support.expectOverlapEof(&source);
            try support.waitOverlap(&service.done, io);
            server_thread.join();
            server_joined = true;
            try std.testing.expectEqual(@as(?anyerror, error.InputOutput), service.err);
        },
    }
    if (mode != .sync_failure) {
        try source.ping();
        try std.testing.expectEqual(@as(usize, 1), try queuedCount(&broker));
        try sendPubrel(&source);
        try expectAck(&source, .pubcomp);
        try source.ping();
        try std.testing.expectEqual(@as(usize, 1), try queuedCount(&broker));
        try support.writeOverlapDisconnect(&source);
        try support.waitOverlap(&observer.first_retired, io);
        try support.expectOverlapEof(&source);
        try support.writeOverlapDisconnect(&client.result.?.connection);
        try support.waitOverlap(&observer.second_retired, io);
        try support.expectOverlapEof(&client.result.?.connection);
        service.shutdown.set(io);
        server_thread.join();
        server_joined = true;
        if (service.err) |err| return err;
    }
    var restored = try context.testBrokerFn(allocator, io, 1, 64);
    defer restored.deinit();
    try restored.restoreCommitLog(tmp.dir, "pubrel-txn.log", .{});
    try std.testing.expectEqual(@as(usize, 0), restored.pending_qos2.count());
    try std.testing.expectEqual(@as(usize, 1), restored.retained.count());
    try verifyOneDelivery(&restored);
}

fn assertOnlyPublisherReserved(broker: *context.BrokerType) !void {
    broker.state_mutex.lockUncancelable(broker.io);
    defer broker.state_mutex.unlock(broker.io);
    try std.testing.expectEqual(@as(u64, 1), broker.connections_received);
    try std.testing.expect(broker.slots[0].state.active);
    try std.testing.expect(!broker.slots[1].state.active);
}

const BridgeCase = enum { stage, release, complete, begin_session };
const key = mqtt.broker.bridge_qos2_mod.Key{ .bridge_id = [_]u8{0x73} ** 16, .session_epoch = 7, .packet_id = 9 };

fn bridgePublish() mqtt.Publish {
    return .{ .dup = false, .qos = .exactly_once, .retain = true, .topic = topic, .packet_id = null, .payload = payload };
}

test "broker bridge transaction entry points wait for admission before changing durable state" {
    for (std.enums.values(BridgeCase)) |mode| try bridgeOverlap(mode);
}

fn bridgeOverlap(mode: BridgeCase) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var observer = support.AdmissionOverlap{ .delegate = io, .park_second = true };
    support.AdmissionOverlap.active = &observer;
    defer support.AdmissionOverlap.active = null;
    var table = io.vtable.*;
    table.netWrite = support.AdmissionOverlap.netWrite;
    table.netClose = support.AdmissionOverlap.netClose;
    table.sleep = support.AdmissionOverlap.sleep;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &table };
    var broker = try context.testBrokerFn(allocator, observed_io, 2, 64);
    defer broker.deinit();
    try offlineSession(&broker);
    if (mode != .stage) _ = try broker.bridge_qos2.stage(key, bridgePublish(), std.Io.Clock.awake.now(io));
    if (mode == .complete) try std.testing.expect(broker.bridge_qos2.markReleased(key));
    const before = broker.bridge_qos2.stats();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try broker.createCommitLog(tmp.dir, "bridge-txn.log", .{});
    var service = support.OverlapService{ .broker = &broker };
    const server_thread = try std.Thread.spawn(.{}, support.OverlapService.run, .{&service});
    var server_joined = false;
    defer if (!server_joined) {
        observer.unblock();
        service.shutdown.set(io);
        server_thread.join();
    };
    var source = try publisher(&broker, io);
    defer source.close();
    var client = support.OverlapClient{ .io = io, .address = broker.address(), .client_id = "bridge-admission" };
    const client_thread = try std.Thread.spawn(.{}, support.OverlapClient.run, .{&client});
    var client_joined = false;
    defer {
        observer.unblock();
        if (!client_joined) client_thread.join();
        if (client.result) |*result| result.deinit(allocator);
    }
    try support.waitOverlap(&observer.connack_parked, io);
    const Operation = struct {
        broker: *context.BrokerType,
        mode: BridgeCase,
        err: ?anyerror = null,
        done: std.Io.Event = .unset,
        fn run(self: *@This()) void {
            defer self.done.set(self.broker.io);
            self.execute() catch |err| {
                self.err = err;
            };
        }
        fn execute(self: *@This()) !void {
            switch (self.mode) {
                .stage => try std.testing.expectEqual(mqtt.broker.bridge_qos2_mod.StageResult.inserted, try self.broker.stageBridgeQoS2(key, bridgePublish(), .{})),
                .release => {
                    const released = try self.broker.releaseBridgeQoS2(key);
                    try std.testing.expect(released.disposition == .applied and released.delivery_error == null);
                },
                .complete => try std.testing.expect(try self.broker.completeBridgeQoS2(key)),
                .begin_session => try std.testing.expectEqual(@as(u64, 8), try self.broker.beginBridgeQoS2Session(key.bridge_id)),
            }
        }
    };
    var operation = Operation{ .broker = &broker, .mode = mode };
    const operation_thread = try std.Thread.spawn(.{}, Operation.run, .{&operation});
    var operation_joined = false;
    defer if (!operation_joined) {
        observer.unblock();
        operation_thread.join();
    };
    try support.waitOverlap(&observer.retry_entered, io);
    broker.state_mutex.lockUncancelable(io);
    const pending = broker.bridge_qos2.stats();
    broker.state_mutex.unlock(io);
    try std.testing.expectEqual(before.entries, pending.entries);
    try std.testing.expectEqual(before.pending, pending.pending);
    try std.testing.expectEqual(before.released, pending.released);
    try std.testing.expectEqual(@as(usize, 0), try queuedCount(&broker));
    try std.testing.expect(!operation.done.isSet());
    observer.release_connack.set(io);
    client_thread.join();
    client_joined = true;
    if (client.err) |err| return err;
    observer.release_retry.set(io);
    try support.waitOverlap(&operation.done, io);
    operation_thread.join();
    operation_joined = true;
    if (operation.err) |err| return err;
    try support.writeOverlapDisconnect(&source);
    try support.waitOverlap(&observer.first_retired, io);
    try support.expectOverlapEof(&source);
    try support.writeOverlapDisconnect(&client.result.?.connection);
    try support.waitOverlap(&observer.second_retired, io);
    try support.expectOverlapEof(&client.result.?.connection);
    service.shutdown.set(io);
    server_thread.join();
    server_joined = true;
    if (service.err) |err| return err;
    var restored = try context.testBrokerFn(allocator, io, 1, 64);
    defer restored.deinit();
    try restored.restoreCommitLog(tmp.dir, "bridge-txn.log", .{});
    switch (mode) {
        .stage => try std.testing.expect(restored.bridge_qos2.getPhase(key) == .pending),
        .release => {
            try std.testing.expect(restored.bridge_qos2.getPhase(key) == .released);
            try verifyOneDelivery(&restored);
        },
        .complete => try std.testing.expect(restored.bridge_qos2.getPhase(key) == null),
        .begin_session => {
            try std.testing.expect(restored.bridge_qos2.getPhase(key) == null);
            try std.testing.expectEqual(@as(?u64, 8), restored.latestBridgeQoS2SessionEpoch(key.bridge_id));
        },
    }
}
