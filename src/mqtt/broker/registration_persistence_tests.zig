const std = @import("std");
const test_tmp = @import("../../internal/test_tmp_dir.zig");
const context = @import("../broker_tests.zig").TestContext;
const mqtt = context.mqtt_mod;
const runtime = context.runtime_mod;
const session_route = @import("session_route.zig");

const RejectConnAck = struct {
    delegate: std.Io,
    rejected: std.atomic.Value(bool) = .init(false),
    calls: std.atomic.Value(usize) = .init(0),
    park_first: bool = false,
    parked: std.Io.Event = .unset,
    release: std.Io.Event = .unset,
    fail_sync: std.atomic.Value(bool) = .init(false),
    sync_failed: std.atomic.Value(bool) = .init(false),
    fail_rollback_sync: bool = false,
    gate_close: std.atomic.Value(bool) = .init(false),
    close_gated: std.atomic.Value(bool) = .init(false),
    closed: std.Io.Event = .unset,
    release_close: std.Io.Event = .unset,

    // Keep Threaded's userdata intact for deadline and receive callbacks.
    var active: ?*RejectConnAck = null;

    fn netWrite(
        userdata: ?*anyopaque,
        handle: std.Io.net.Socket.Handle,
        header: []const u8,
        data: []const []const u8,
        splat: usize,
    ) std.Io.net.Stream.Writer.Error!usize {
        const self = active.?;
        const first = if (header.len != 0) header[0] else blk: {
            for (data) |part| {
                if (part.len == 0) continue;
                break :blk part[0];
            }
            break :blk null;
        };
        if (first == 0x20) {
            const ordinal = self.calls.fetchAdd(1, .acq_rel);
            if (self.park_first and ordinal == 0) {
                self.parked.set(self.delegate);
                self.release.waitTimeout(self.delegate, .{ .duration = .{
                    .raw = .fromSeconds(5),
                    .clock = .awake,
                } }) catch |err| switch (err) {
                    error.Timeout => return error.ConnectionResetByPeer,
                    error.Canceled => return error.Canceled,
                };
                return self.delegate.vtable.netWrite(userdata, handle, header, data, splat);
            }
            self.rejected.store(true, .release);
            if (self.fail_rollback_sync) self.fail_sync.store(true, .release);
            return error.ConnectionResetByPeer;
        }
        return self.delegate.vtable.netWrite(userdata, handle, header, data, splat);
    }

    fn fileSync(userdata: ?*anyopaque, file: std.Io.File) std.Io.File.SyncError!void {
        const self = active.?;
        if (self.fail_sync.swap(false, .acq_rel)) {
            self.sync_failed.store(true, .release);
            return error.InputOutput;
        }
        return self.delegate.vtable.fileSync(userdata, file);
    }

    fn netClose(userdata: ?*anyopaque, handles: []const std.Io.net.Socket.Handle) void {
        const self = active.?;
        self.delegate.vtable.netClose(userdata, handles);
        if (self.gate_close.load(.acquire) and !self.close_gated.swap(true, .acq_rel)) {
            // The peer sees EOF, but pending.deinit has not returned to the
            // admission caller, so its reserved slot has not been released.
            self.closed.set(self.delegate);
            self.release_close.waitUncancelable(self.delegate);
        }
    }
};

test "broker failed CONNACK journals rollback before restart" {
    for ([_]SessionMode{ .fresh, .clean_start, .continued }) |mode| {
        try failedConnAck(mode, .connack_write);
    }
}

test "broker failed provisional journal sync appends rollback image" {
    for ([_]SessionMode{ .fresh, .clean_start, .continued }) |mode| {
        try failedConnAck(mode, .provisional_sync);
    }
}

test "broker retries failed rollback journal sync without replacing CONNECT error" {
    for ([_]SessionMode{ .fresh, .clean_start, .continued }) |mode| {
        try failedConnAck(mode, .rollback_sync);
    }
}

const SessionMode = enum { fresh, clean_start, continued };
const Failure = enum { connack_write, provisional_sync, rollback_sync };

fn failedConnAck(mode: SessionMode, failure: Failure) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var observer = RejectConnAck{ .delegate = io, .fail_rollback_sync = failure == .rollback_sync };
    RejectConnAck.active = &observer;
    defer RejectConnAck.active = null;
    var vtable = io.vtable.*;
    vtable.netWrite = RejectConnAck.netWrite;
    vtable.fileSync = RejectConnAck.fileSync;
    vtable.netClose = RejectConnAck.netClose;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    var broker = try context.BrokerType.listen(allocator, observed_io, .{ .ip4 = .loopback(0) }, .{
        .limits = .{ .max_connections = 1, .max_queued_deliveries_per_connection = 8 },
        .accept = .{ .protocol = .v5, .max_outgoing_inflight = 64 },
        .persistent_change_autosave = .{ .dir = tmp.dir, .sub_path = "rollback.db", .max_changes = 1 },
    });
    defer broker.deinit();
    if (mode != .fresh) {
        const now = std.Io.Clock.awake.now(io);
        const old = try broker.sessions.open("failed-connack", false, 120, now);
        const subscription = mqtt.Subscription{ .topic_filter = "failed/connack/value", .qos = .at_least_once };
        _ = try broker.sessions.setSubscription(old.handle, subscription, null);
        _ = try broker.router.subscribeWithIdentifierStatus(session_route.sessionSubscriberId(old.route_id), subscription, null);
        _ = try broker.sessions.enqueuePublish(old.handle, "failed/connack/value", "queued", .{ .qos = .at_least_once, .now = now });
        try broker.sessions.disconnect(old.handle, null, now);
    }
    try broker.createCommitLog(tmp.dir, "failed-connack.log", .{});
    try broker.saveLiveSnapshot(tmp.dir, "rollback.db");
    observer.fail_sync.store(failure == .provisional_sync, .release);

    var serve = context.ServeStateType{ .broker = &broker, .connection_count = 1 };
    const thread = try std.Thread.spawn(.{}, context.ServeStateType.run, .{&serve});
    var joined = false;
    defer if (!joined) thread.join();
    observer.gate_close.store(true, .release);
    defer observer.release_close.set(io);
    var will_properties = [_]mqtt.Property{.{ .four_byte = .{ .id = .will_delay_interval, .value = 30 } }};
    const result = runtime.Client.connectAttemptWithTimeout(allocator, io, broker.address(), .{
        .protocol = .v5,
        .client_id = "failed-connack",
        .clean_start = mode != .continued,
        .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 120 } }},
        .will = .{ .topic = "failed/connack/will", .payload = "must-not-revive", .retain = true, .properties = &will_properties },
    }, .fromSeconds(5));
    if (result) |value| {
        var unexpected = value;
        unexpected.deinit(allocator);
        return error.TestUnexpectedResult;
    } else |err| {
        try std.testing.expectEqual(error.ConnectionClosed, err);
    }
    try observer.closed.waitTimeout(io, .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } });
    try std.testing.expect(broker.slots[0].state.active);
    try std.testing.expect(broker.slots[0].state.registration_aborted);
    try expectRolledBack(&broker, mode);
    // Public snapshots and autosave are already safe before release. A
    // failed corrective sync retains journal debt until the caller retries.
    try broker.saveLiveSnapshot(tmp.dir, "during-rollback.db");
    if (failure != .rollback_sync) {
        var before_release = try context.testBrokerFn(allocator, io, 1, 64);
        defer before_release.deinit();
        try before_release.restoreCommitLog(tmp.dir, "failed-connack.log", .{});
        try expectRolledBack(&before_release, mode);
    } else {
        try std.testing.expect(broker.registration_rollback_commit_pending);
    }
    observer.release_close.set(io);
    if (failure == .provisional_sync) {
        try std.testing.expectError(error.InputOutput, context.joinServerFn(thread, &joined, &serve));
        try std.testing.expect(observer.sync_failed.load(.acquire));
        try std.testing.expect(!observer.rejected.load(.acquire));
    } else {
        try std.testing.expectError(error.ConnectionResetByPeer, context.joinServerFn(thread, &joined, &serve));
        try std.testing.expect(observer.rejected.load(.acquire));
        if (failure == .rollback_sync) try std.testing.expect(observer.sync_failed.load(.acquire));
    }
    try expectRolledBack(&broker, mode);
    try std.testing.expect(!broker.registration_rollback_commit_pending);

    var restored = try context.testBrokerFn(allocator, io, 1, 64);
    defer restored.deinit();
    try restored.restoreCommitLog(tmp.dir, "failed-connack.log", .{});
    try expectRolledBack(&restored, mode);
    var checkpoint = try context.testBrokerFn(allocator, io, 1, 64);
    defer checkpoint.deinit();
    try checkpoint.restoreSnapshot(tmp.dir, "rollback.db");
    try expectRolledBack(&checkpoint, mode);
}

fn expectRolledBack(broker: *context.BrokerType, mode: SessionMode) !void {
    broker.state_mutex.lockUncancelable(broker.io);
    defer broker.state_mutex.unlock(broker.io);
    const session_count: usize = @intFromBool(mode == .continued);
    try std.testing.expectEqual(session_count, broker.sessions.count());
    try std.testing.expectEqual(session_count, broker.router.subscriptionCount());
    try std.testing.expectEqual(@as(usize, 0), broker.wills.count());
    try std.testing.expectEqual(@as(usize, 0), broker.will_publishers.count());
    try std.testing.expectEqual(@as(usize, 0), broker.session_owners.count());
    try std.testing.expectEqual(@as(usize, 0), broker.retained.count());
    if (mode == .continued) {
        const handle = broker.sessions.find("failed-connack", std.Io.Clock.awake.now(broker.io)).?;
        const stats = try broker.sessions.stats(handle);
        try std.testing.expect(!stats.connected);
        try std.testing.expectEqual(@as(usize, 1), stats.queued_count);
    }
}

test "broker retries rollback journal after concurrent CONNECT settles" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var observer = RejectConnAck{ .delegate = io, .park_first = true };
    RejectConnAck.active = &observer;
    defer RejectConnAck.active = null;
    var vtable = io.vtable.*;
    vtable.netWrite = RejectConnAck.netWrite;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    var broker = try context.testBrokerFn(allocator, observed_io, 2, 64);
    defer broker.deinit();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try broker.createCommitLog(tmp.dir, "concurrent-rollback.log", .{});

    var shutdown: std.Io.Event = .unset;
    const Service = struct {
        broker: *context.BrokerType,
        shutdown: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.broker.serveListenersUntil(&.{.{
                .source = self.broker.server.?.pendingSource(),
                .accept_concurrency = 2,
            }}, .{ .shutdown = self.shutdown }) catch |err| {
                self.err = err;
            };
        }
    };
    var service = Service{ .broker = &broker, .shutdown = &shutdown };
    const server_thread = try std.Thread.spawn(.{}, Service.run, .{&service});
    var server_joined = false;
    defer if (!server_joined) {
        observer.release.set(io);
        shutdown.set(io);
        server_thread.join();
    };

    const Client = struct {
        io: std.Io,
        address: std.Io.net.IpAddress,
        result: ?runtime.ConnectResult = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.result = runtime.Client.connectWithConnAckWithTimeout(std.testing.allocator, self.io, self.address, .{
                .protocol = .v5,
                .client_id = "still-admitting",
                .clean_start = false,
                .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 120 } }},
            }, .fromSeconds(5)) catch |err| {
                self.err = err;
                return;
            };
        }
    };
    var first_client = Client{ .io = io, .address = broker.address() };
    const client_thread = try std.Thread.spawn(.{}, Client.run, .{&first_client});
    var client_joined = false;
    defer if (!client_joined) {
        observer.release.set(io);
        client_thread.join();
        if (first_client.result) |*result| result.deinit(allocator);
    };
    try observer.parked.waitTimeout(io, .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } });

    var will_properties = [_]mqtt.Property{.{ .four_byte = .{ .id = .will_delay_interval, .value = 30 } }};
    const rejected = runtime.Client.connectAttemptWithTimeout(allocator, io, broker.address(), .{
        .protocol = .v5,
        .client_id = "aborted-concurrent",
        .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 120 } }},
        .will = .{ .topic = "concurrent/will", .payload = "must-not-revive", .retain = true, .properties = &will_properties },
    }, .fromSeconds(5));
    if (rejected) |result| {
        var unexpected = result;
        unexpected.deinit(allocator);
        return error.TestUnexpectedResult;
    } else |err| {
        try std.testing.expectEqual(error.ConnectionClosed, err);
    }
    // An aborted slot can be encoded, but the first CONNECT still owns real
    // provisional state. Neither journal correction nor public snapshots may
    // bypass that independent admission's visibility boundary.
    try std.testing.expectError(error.SnapshotBusy, broker.saveLiveSnapshot(tmp.dir, "busy.db"));
    broker.persistence_mutex.lockUncancelable(io);
    const pending_before = broker.registration_rollback_commit_pending;
    broker.persistence_mutex.unlock(io);
    try std.testing.expect(pending_before);

    observer.release.set(io);
    client_thread.join();
    client_joined = true;
    if (first_client.err) |err| return err;
    var first = first_client.result.?;
    defer first.deinit(allocator);
    // This barrier passes through the attached client's broker task, after
    // registration retried the correction. No further durable mutation is
    // needed to remove the failed peer from the journal.
    try first.connection.ping();
    broker.persistence_mutex.lockUncancelable(io);
    const pending_after = broker.registration_rollback_commit_pending;
    broker.persistence_mutex.unlock(io);
    try std.testing.expect(!pending_after);

    var restored = try context.testBrokerFn(allocator, io, 1, 64);
    defer restored.deinit();
    try restored.restoreCommitLog(tmp.dir, "concurrent-rollback.log", .{});
    try std.testing.expectEqual(@as(usize, 1), restored.sessions.count());
    try std.testing.expect(restored.sessions.find("still-admitting", std.Io.Clock.awake.now(io)) != null);
    try std.testing.expect(restored.sessions.find("aborted-concurrent", std.Io.Clock.awake.now(io)) == null);
    try std.testing.expectEqual(@as(usize, 0), restored.wills.count());
    try first.connection.disconnect(0);
    shutdown.set(io);
    server_thread.join();
    server_joined = true;
    if (service.err) |err| return err;
}
