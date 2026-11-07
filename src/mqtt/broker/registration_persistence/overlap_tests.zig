//! Concurrent admission barriers for durable reader and takeover cleanup.
const std = @import("std");
const test_tmp = @import("../../../internal/test_tmp_dir.zig");
const timed_mutex = @import("../../../internal/timed_mutex.zig");
const context = @import("../../broker_tests.zig").TestContext;
const mqtt = context.mqtt_mod;
const runtime = context.runtime_mod;

const AdmissionOverlap = struct {
    delegate: std.Io,
    freeze_disconnect: bool = false,
    park_second: bool = false,
    connacks: std.atomic.Value(usize) = .init(0),
    disconnect_gated: std.atomic.Value(bool) = .init(false),
    retry_gated: std.atomic.Value(bool) = .init(false),
    disconnect_read: std.Io.Event = .unset,
    release_disconnect: std.Io.Event = .unset,
    connack_parked: std.Io.Event = .unset,
    release_connack: std.Io.Event = .unset,
    retry_entered: std.Io.Event = .unset,
    release_retry: std.Io.Event = .unset,
    old_writer: std.atomic.Value(?*std.Io.Mutex) = .init(null),
    writer_parked: std.Io.Event = .unset,
    close_count: std.atomic.Value(usize) = .init(0),
    first_retired: std.Io.Event = .unset,
    second_retired: std.Io.Event = .unset,
    var active: ?*AdmissionOverlap = null;

    fn unblock(self: *AdmissionOverlap) void {
        self.release_disconnect.set(self.delegate);
        self.release_connack.set(self.delegate);
        self.release_retry.set(self.delegate);
    }

    fn netRead(userdata: ?*anyopaque, handle: std.Io.net.Socket.Handle, data: [][]u8) std.Io.net.Stream.Reader.Error!usize {
        const self = active.?;
        const count = try self.delegate.vtable.netRead(userdata, handle, data);
        if (count != 0 and self.freeze_disconnect) {
            const first = for (data) |part| {
                if (part.len != 0) break part[0];
            } else null;
            if (first == 0xe0 and !self.disconnect_gated.swap(true, .acq_rel)) {
                // Receive DISCONNECT first, but hold its processing until the
                // following CONNECT reaches the real CONNACK write boundary.
                self.disconnect_read.set(self.delegate);
                self.release_disconnect.waitTimeout(self.delegate, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(5) } }) catch return error.Canceled;
            }
        }
        return count;
    }

    fn netWrite(userdata: ?*anyopaque, handle: std.Io.net.Socket.Handle, header: []const u8, data: []const []const u8, splat: usize) std.Io.net.Stream.Writer.Error!usize {
        const self = active.?;
        const first = if (header.len != 0) header[0] else for (data) |part| {
            if (part.len != 0) break part[0];
        } else null;
        if (first == 0x20) {
            const ordinal = self.connacks.fetchAdd(1, .acq_rel);
            if (self.park_second and ordinal == 1) {
                self.connack_parked.set(self.delegate);
                self.release_connack.waitTimeout(self.delegate, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(5) } }) catch return error.Canceled;
            }
        }
        return self.delegate.vtable.netWrite(userdata, handle, header, data, splat);
    }

    fn sleep(userdata: ?*anyopaque, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self = active.?;
        if (self.park_second and self.connack_parked.isSet() and !self.retry_gated.swap(true, .acq_rel)) {
            self.retry_entered.set(self.delegate);
            self.release_retry.waitTimeout(self.delegate, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(5) } }) catch return error.Canceled;
        }
        return self.delegate.vtable.sleep(userdata, timeout);
    }

    fn waitUncancelable(userdata: ?*anyopaque, pointer: *const u32, expected: u32) void {
        const self = active.?;
        if (self.old_writer.load(.acquire)) |writer| {
            const target: *const u32 = @ptrCast(&writer.state.raw);
            if (pointer == target) self.writer_parked.set(self.delegate);
        }
        self.delegate.vtable.futexWaitUncancelable(userdata, pointer, expected);
    }

    fn netClose(userdata: ?*anyopaque, handles: []const std.Io.net.Socket.Handle) void {
        const self = active.?;
        self.delegate.vtable.netClose(userdata, handles);
        const before = self.close_count.fetchAdd(handles.len, .acq_rel);
        if (before < 1 and before + handles.len >= 1) self.first_retired.set(self.delegate);
        if (before < 2 and before + handles.len >= 2) self.second_retired.set(self.delegate);
    }
};

const OverlapService = struct {
    broker: *context.BrokerType,
    shutdown: std.Io.Event = .unset,
    err: ?anyerror = null,

    fn run(self: *OverlapService) void {
        self.broker.serveListenersUntil(&.{.{ .source = self.broker.server.?.pendingSource(), .accept_concurrency = 2 }}, .{ .shutdown = &self.shutdown }) catch |err| {
            self.err = err;
        };
    }
};

const OverlapClient = struct {
    io: std.Io,
    address: std.Io.net.IpAddress,
    client_id: []const u8,
    clean_start: bool = true,
    expiry: u32 = 0,
    result: ?runtime.ConnectResult = null,
    err: ?anyerror = null,

    fn run(self: *OverlapClient) void {
        const properties = [_]mqtt.Property{.{ .four_byte = .{ .id = .session_expiry_interval, .value = self.expiry } }};
        self.result = runtime.Client.connectWithConnAckWithTimeout(std.testing.allocator, self.io, self.address, .{
            .protocol = .v5,
            .client_id = self.client_id,
            .clean_start = self.clean_start,
            .properties = if (self.expiry == 0) &.{} else &properties,
        }, .fromSeconds(5)) catch |err| {
            self.err = err;
            return;
        };
    }
};

fn waitOverlap(event: *std.Io.Event, io: std.Io) !void {
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
    while (true) {
        event.waitTimeout(io, .{ .deadline = deadline }) catch |err| {
            if (err == error.Timeout and deadline.durationFromNow(io).raw.nanoseconds > 0) continue;
            return err;
        };
        return;
    }
}

fn expectOverlapEof(connection: *runtime.Connection) !void {
    var packet = connection.transport.readPacketWithDeadline(std.testing.allocator, 4096, connection.transport.deadlineFromNow(.fromSeconds(5))) catch |err| {
        try std.testing.expect(err == error.ConnectionClosed);
        return;
    };
    defer packet.deinit(std.testing.allocator);
    return error.ExpectedPeerClose;
}

fn writeOverlapDisconnect(connection: *runtime.Connection) !void {
    // Match the Python fixture's sendall(E0 00): keep the local socket open.
    // Connection.disconnect deliberately shuts down its transport afterward.
    var packet = [_]u8{ 0xe0, 0x00 };
    try connection.transport.writePacket(&packet);
}

test "broker durable DISCONNECT waits for the following provisional CONNECT without holding persistence locks" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var observer = AdmissionOverlap{ .delegate = io, .freeze_disconnect = true, .park_second = true };
    AdmissionOverlap.active = &observer;
    defer AdmissionOverlap.active = null;
    var vtable = io.vtable.*;
    vtable.netRead = AdmissionOverlap.netRead;
    vtable.netWrite = AdmissionOverlap.netWrite;
    vtable.sleep = AdmissionOverlap.sleep;
    vtable.netClose = AdmissionOverlap.netClose;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    var broker = try context.testBrokerFn(allocator, observed_io, 2, 64);
    defer broker.deinit();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try broker.createCommitLog(tmp.dir, "disconnect-overlap.log", .{});
    var service = OverlapService{ .broker = &broker };
    const server_thread = try std.Thread.spawn(.{}, OverlapService.run, .{&service});
    var server_joined = false;
    defer if (!server_joined) {
        observer.unblock();
        service.shutdown.set(io);
        server_thread.join();
    };
    var will_properties = [_]mqtt.Property{.{ .four_byte = .{ .id = .will_delay_interval, .value = 30 } }};
    var first = try runtime.Client.connect(allocator, io, broker.address(), .{
        .protocol = .v5,
        .client_id = "disconnect-before-connect",
        .clean_start = false,
        .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 120 } }},
        .will = .{ .topic = "overlap/will", .payload = "must-not-revive", .retain = true, .properties = &will_properties },
    });
    defer first.close();
    try first.ping();
    try writeOverlapDisconnect(&first);
    try waitOverlap(&observer.disconnect_read, io);
    try std.testing.expectError(error.Timeout, first.transport.readPacketWithDeadline(allocator, 4096, first.transport.deadlineFromNow(.fromMilliseconds(10))));
    // Preserve the fixture's DISCONNECT-before-CONNECT wire order. No EOF
    // barrier is inserted before starting this second admission.
    var client = OverlapClient{ .io = io, .address = broker.address(), .client_id = "overlap-replay" };
    const client_thread = try std.Thread.spawn(.{}, OverlapClient.run, .{&client});
    var client_joined = false;
    defer {
        observer.unblock();
        if (!client_joined) client_thread.join();
        if (client.result) |*result| result.deinit(allocator);
    }
    try waitOverlap(&observer.connack_parked, io);
    try std.testing.expectError(error.SnapshotBusy, broker.appendCommit());
    try std.testing.expectError(error.SnapshotBusy, broker.saveLiveSnapshot(tmp.dir, "busy-overlap.db"));
    observer.release_disconnect.set(io);
    try waitOverlap(&observer.retry_entered, io);
    const lock_deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    try timed_mutex.lock(&broker.persistence_mutex, io, lock_deadline);
    broker.persistence_mutex.unlock(io);
    const observed = state: {
        try timed_mutex.lock(&broker.state_mutex, io, lock_deadline);
        defer broker.state_mutex.unlock(io);
        const handle = broker.sessions.find("disconnect-before-connect", std.Io.Clock.awake.now(io)) orelse return error.SessionNotFound;
        break :state .{ .disconnected = !(try broker.sessions.stats(handle)).connected, .wills = broker.wills.count() };
    };
    try std.testing.expect(observed.disconnected);
    try std.testing.expectEqual(@as(usize, 0), observed.wills);
    observer.release_connack.set(io);
    client_thread.join();
    client_joined = true;
    if (client.err) |err| return err;
    var second = client.result.?;
    client.result = null;
    defer second.deinit(allocator);
    observer.release_retry.set(io);
    // Receiving DISCONNECT shuts down the server read transport before the
    // broker mutation completes. Physical close in unregister follows its
    // journal fsync, so wait for that retirement before ending the service.
    try waitOverlap(&observer.first_retired, io);
    try expectOverlapEof(&first);
    try second.connection.ping();
    try writeOverlapDisconnect(&second.connection);
    try waitOverlap(&observer.second_retired, io);
    try expectOverlapEof(&second.connection);
    service.shutdown.set(io);
    server_thread.join();
    server_joined = true;
    if (service.err) |err| return err;
    var restored = try context.testBrokerFn(allocator, io, 1, 64);
    defer restored.deinit();
    try restored.restoreCommitLog(tmp.dir, "disconnect-overlap.log", .{});
    try std.testing.expectEqual(@as(usize, 1), restored.sessions.count());
    const recovered = restored.sessions.find("disconnect-before-connect", std.Io.Clock.awake.now(io)).?;
    try std.testing.expect(!(try restored.sessions.stats(recovered)).connected);
    try std.testing.expectEqual(@as(usize, 0), restored.wills.count());
    try std.testing.expectEqual(@as(usize, 0), restored.will_publishers.count());
}

test "broker accepted takeover attaches before waiting for the displaced durable writer" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var observer = AdmissionOverlap{ .delegate = io };
    AdmissionOverlap.active = &observer;
    defer AdmissionOverlap.active = null;
    var vtable = io.vtable.*;
    vtable.futexWaitUncancelable = AdmissionOverlap.waitUncancelable;
    vtable.netClose = AdmissionOverlap.netClose;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    var broker = try context.testBrokerFn(allocator, observed_io, 2, 64);
    defer broker.deinit();
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try broker.createCommitLog(tmp.dir, "takeover-overlap.log", .{});
    var service = OverlapService{ .broker = &broker };
    const server_thread = try std.Thread.spawn(.{}, OverlapService.run, .{&service});
    var server_joined = false;
    defer if (!server_joined) {
        service.shutdown.set(io);
        server_thread.join();
    };
    var first = try runtime.Client.connect(allocator, io, broker.address(), .{
        .protocol = .v5,
        .client_id = "held-writer-takeover",
        .clean_start = false,
        .properties = &.{.{ .four_byte = .{ .id = .session_expiry_interval, .value = 120 } }},
    });
    defer first.close();
    try first.ping();
    const old_writer = &broker.slots[0].writer_mutex;
    observer.old_writer.store(old_writer, .release);
    old_writer.lockUncancelable(io);
    var writer_held = true;
    defer if (writer_held) old_writer.unlock(io);
    var client = OverlapClient{ .io = io, .address = broker.address(), .client_id = "held-writer-takeover", .clean_start = false, .expiry = 120 };
    const client_thread = try std.Thread.spawn(.{}, OverlapClient.run, .{&client});
    var client_joined = false;
    defer {
        if (!client_joined) client_thread.join();
        if (client.result) |*result| result.deinit(allocator);
    }
    try waitOverlap(&observer.writer_parked, io);
    client_thread.join();
    client_joined = true;
    if (client.err) |err| return err;
    var second = client.result.?;
    client.result = null;
    defer second.deinit(allocator);
    try std.testing.expect(second.connack.connack.session_present);
    // The replacement has received CONNACK but cannot close the old transport
    // or start its ClientTask until this held writer is released. Its attached
    // state must already support another caller's coherent durable boundary.
    try broker.saveLiveSnapshot(tmp.dir, "attached-takeover.db");
    _ = try broker.appendCommit();
    var restored = try context.testBrokerFn(allocator, io, 1, 64);
    defer restored.deinit();
    try restored.restoreCommitLog(tmp.dir, "takeover-overlap.log", .{});
    try std.testing.expectEqual(@as(usize, 1), restored.sessions.count());
    const handle = restored.sessions.find("held-writer-takeover", std.Io.Clock.awake.now(io)).?;
    try std.testing.expect(!(try restored.sessions.stats(handle)).connected);
    old_writer.unlock(io);
    writer_held = false;
    var packet = try first.transport.readPacketWithDeadline(allocator, 4096, first.transport.deadlineFromNow(.fromSeconds(5)));
    defer packet.deinit(allocator);
    var terminal = try mqtt.Disconnect.parse(allocator, .v5, packet.bytes);
    defer terminal.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x8e), terminal.reason_code);
    try waitOverlap(&observer.first_retired, io);
    try expectOverlapEof(&first);
    try second.connection.ping();
    try writeOverlapDisconnect(&second.connection);
    try waitOverlap(&observer.second_retired, io);
    try expectOverlapEof(&second.connection);
    service.shutdown.set(io);
    server_thread.join();
    server_joined = true;
    if (service.err) |err| return err;
}
