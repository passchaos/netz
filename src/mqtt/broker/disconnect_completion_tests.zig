//! Peer-visible close follows the Broker's durable normal-Will cancellation.
const std = @import("std");
const test_tmp = @import("../../internal/test_tmp_dir.zig");
const context = @import("../broker_tests.zig").TestContext;
const mqtt = context.mqtt_mod;
const runtime = context.runtime_mod;
const support = @import("registration_persistence/test_support.zig");
const allocator = std.testing.allocator;
const Mode = enum { success, fail_once, fail_repeatedly, writer_held };

const CloseObserver = struct {
    delegate: std.Io,
    broker: *context.BrokerType,
    mode: Mode,
    armed: std.atomic.Value(bool) = .init(false),
    target: std.Io.net.Socket.Handle = undefined,
    baseline_sequence: u64 = 0,
    sync_calls: std.atomic.Value(usize) = .init(0),
    synced: std.atomic.Value(bool) = .init(false),
    sync_started: std.Io.Event = .unset,
    release_sync: std.Io.Event = .unset,
    shutdown_calls: std.atomic.Value(usize) = .init(0),
    shutdown_seen: std.Io.Event = .unset,
    release_shutdown: std.Io.Event = .unset,
    retired: std.Io.Event = .unset,
    validation_error: ?anyerror = null,
    writer_mutex: std.atomic.Value(?*std.Io.Mutex) = .init(null),
    writer_waiting: std.Io.Event = .unset,
    var active: ?*CloseObserver = null;

    fn unblock(self: *CloseObserver) void {
        self.release_sync.set(self.delegate);
        self.release_shutdown.set(self.delegate);
    }

    fn fileSync(userdata: ?*anyopaque, file: std.Io.File) std.Io.File.SyncError!void {
        const self = active.?;
        if (!self.armed.load(.acquire)) return self.delegate.vtable.fileSync(userdata, file);
        const ordinal = self.sync_calls.fetchAdd(1, .acq_rel);
        if (ordinal == 0) {
            self.sync_started.set(self.delegate);
            support.waitOverlap(&self.release_sync, self.delegate) catch return error.InputOutput;
        }
        if (self.mode == .fail_repeatedly or (self.mode == .fail_once and ordinal == 0)) return error.InputOutput;
        try self.delegate.vtable.fileSync(userdata, file);
        self.synced.store(true, .release);
    }

    fn netShutdown(userdata: ?*anyopaque, handle: std.Io.net.Socket.Handle, how: std.Io.net.ShutdownHow) std.Io.net.ShutdownError!void {
        const self = active.?;
        if (self.armed.load(.acquire) and handle == self.target) {
            const ordinal = self.shutdown_calls.fetchAdd(1, .acq_rel);
            if (ordinal == 0) {
                self.inspect() catch |err| {
                    self.validation_error = err;
                };
                self.shutdown_seen.set(self.delegate);
                // An invalid early close is allowed to proceed so the test
                // reports the ordering error without stranding its reader.
                if (self.validation_error == null) {
                    support.waitOverlap(&self.release_shutdown, self.delegate) catch return error.SocketUnconnected;
                }
            }
        }
        return self.delegate.vtable.netShutdown(userdata, handle, how);
    }

    fn inspect(self: *CloseObserver) !void {
        const expected_calls: usize = if (self.mode == .fail_once or self.mode == .fail_repeatedly) 2 else 1;
        if (self.sync_calls.load(.acquire) != expected_calls) return error.ShutdownBeforePersistenceDecision;
        self.broker.persistence_mutex.lockUncancelable(self.delegate);
        defer self.broker.persistence_mutex.unlock(self.delegate);
        const log = &self.broker.commit_log.?;
        if (self.mode == .fail_repeatedly) {
            if (self.synced.load(.acquire) or log.next_sequence != self.baseline_sequence) return error.FailedTerminationReportedCommitted;
            return;
        }
        if (!self.synced.load(.acquire) or log.next_sequence != self.baseline_sequence + 1) return error.ShutdownBeforePersistenceDecision;
        const bytes = try log.latestAlloc();
        defer allocator.free(bytes);
        var restored = try mqtt.persistence.decode(allocator, bytes, self.broker.options.retained, self.broker.options.session, self.broker.options.will, self.broker.options.limits.max_pending_incoming_qos2, self.broker.options.bridge_qos2, std.Io.Clock.awake.now(self.delegate), std.Io.Clock.real.now(self.delegate));
        defer restored.retained.deinit();
        defer restored.sessions.deinit();
        defer restored.wills.deinit();
        defer restored.will_publishers.deinit(allocator);
        defer restored.pending_qos2.deinit();
        defer restored.bridge_qos2.deinit();
        if (restored.wills.count() != 0 or restored.will_publishers.count() != 0 or restored.sessions.count() != 0) return error.UnsyncedWillCancellation;
    }

    fn netClose(userdata: ?*anyopaque, handles: []const std.Io.net.Socket.Handle) void {
        const self = active.?;
        self.delegate.vtable.netClose(userdata, handles);
        if (!self.armed.load(.acquire)) return;
        for (handles) |handle| if (handle == self.target) self.retired.set(self.delegate);
    }

    fn waitUncancelable(userdata: ?*anyopaque, pointer: *const u32, expected: u32) void {
        const self = active.?;
        if (self.writer_mutex.load(.acquire)) |mutex| {
            const target: *const u32 = @ptrCast(&mutex.state.raw);
            if (pointer == target) self.writer_waiting.set(self.delegate);
        }
        self.delegate.vtable.futexWaitUncancelable(userdata, pointer, expected);
    }
};

const HeldWriter = struct {
    broker: *context.BrokerType,
    io: std.Io,
    held: std.Io.Event = .unset,
    interrupt_requested: std.Io.Event = .unset,
    interrupt_done: std.Io.Event = .unset,
    release: std.Io.Event = .unset,
    err: ?anyerror = null,

    fn run(self: *HeldWriter) void {
        self.execute() catch |err| {
            self.err = err;
        };
    }

    fn execute(self: *HeldWriter) !void {
        const slot = &self.broker.slots[0];
        slot.writer_mutex.lockUncancelable(self.io);
        defer slot.writer_mutex.unlock(self.io);
        const connection = state: {
            self.broker.state_mutex.lockUncancelable(self.io);
            defer self.broker.state_mutex.unlock(self.io);
            break :state slot.connection orelse return error.ConnectionClosed;
        };
        self.held.set(self.io);
        try support.waitOverlap(&self.interrupt_requested, self.io);
        try connection.interrupt();
        self.interrupt_done.set(self.io);
        try support.waitOverlap(&self.release, self.io);
        // The old writer still owns this pointer after physical shutdown;
        // unregister cannot free or reuse the socket while its lock is held.
        try std.testing.expectEqual(mqtt.ProtocolVersion.v5, connection.protocol);
    }
};

test "broker normal DISCONNECT syncs clean-session Will cancellation before netShutdown" {
    try normalClose(.success);
}

test "broker normal DISCONNECT repairs one-shot sync failure while preserving its first error" {
    try normalClose(.fail_once);
}

test "broker normal DISCONNECT repeated sync failure remains an observable failed termination" {
    try normalClose(.fail_repeatedly);
}

test "broker normal DISCONNECT defers writer interruption and waits for socket quiescence" {
    try normalClose(.writer_held);
}

fn expectOpen(connection: *runtime.Connection) !void {
    var packet = connection.transport.readPacketWithDeadline(allocator, 4096, connection.transport.deadlineFromNow(.fromMilliseconds(10))) catch |err| {
        try std.testing.expect(err == error.Timeout);
        return;
    };
    defer packet.deinit(allocator);
    return error.UnexpectedPacketBeforeClose;
}

fn normalClose(mode: Mode) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var observer: CloseObserver = .{ .delegate = io, .broker = undefined, .mode = mode };
    CloseObserver.active = &observer;
    defer CloseObserver.active = null;
    var table = io.vtable.*;
    table.fileSync = CloseObserver.fileSync;
    table.netShutdown = CloseObserver.netShutdown;
    table.netClose = CloseObserver.netClose;
    table.futexWaitUncancelable = CloseObserver.waitUncancelable;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &table };
    var broker = try context.testBrokerFn(allocator, observed_io, 1, 64);
    defer broker.deinit();
    observer.broker = &broker;
    var tmp = test_tmp.tmpDir(.{});
    defer tmp.cleanup();
    try broker.createCommitLog(tmp.dir, "clean-will-close.log", .{});
    var service = support.OverlapService{ .broker = &broker, .stop_on_error = mode == .fail_once or mode == .fail_repeatedly };
    const server_thread = try std.Thread.spawn(.{}, support.OverlapService.run, .{&service});
    var service_joined = false;
    defer if (!service_joined) {
        observer.unblock();
        service.shutdown.set(io);
        server_thread.join();
    };
    var properties = [_]mqtt.Property{.{ .four_byte = .{ .id = .will_delay_interval, .value = 30 } }};
    var client = try runtime.Client.connectWithTimeout(allocator, io, broker.address(), .{
        .protocol = .v5,
        .client_id = "durable-clean-will-close",
        .clean_start = true,
        .keep_alive_seconds = 1,
        .will = .{ .topic = "close/will", .payload = "must-not-revive", .qos = .at_least_once, .retain = true, .properties = &properties },
    }, .fromSeconds(5));
    defer client.close();
    try client.pingWithTimeout(.fromSeconds(5));
    broker.state_mutex.lockUncancelable(io);
    const connection = broker.slots[0].connection.?;
    observer.target = connection.transport.tcp.stream.socket.handle;
    broker.state_mutex.unlock(io);
    broker.persistence_mutex.lockUncancelable(io);
    observer.baseline_sequence = broker.commit_log.?.next_sequence;
    broker.persistence_mutex.unlock(io);
    var writer = HeldWriter{ .broker = &broker, .io = io };
    var writer_thread: ?std.Thread = null;
    var writer_joined = false;
    defer if (writer_thread) |thread| {
        if (!writer_joined) {
            writer.interrupt_requested.set(io);
            writer.release.set(io);
            thread.join();
        }
    };
    if (mode == .writer_held) {
        observer.writer_mutex.store(&broker.slots[0].writer_mutex, .release);
        writer_thread = try std.Thread.spawn(.{}, HeldWriter.run, .{&writer});
        try support.waitOverlap(&writer.held, io);
    }
    observer.armed.store(true, .release);
    try support.writeOverlapDisconnect(&client);
    try support.waitOverlap(&observer.sync_started, io);
    try std.testing.expectEqual(@as(usize, 0), observer.shutdown_calls.load(.acquire));
    try expectOpen(&client);
    if (mode == .writer_held) {
        writer.interrupt_requested.set(io);
        try support.waitOverlap(&writer.interrupt_done, io);
        try std.testing.expectEqual(@as(usize, 0), observer.shutdown_calls.load(.acquire));
        try expectOpen(&client);
    }
    observer.release_sync.set(io);
    try support.waitOverlap(&observer.shutdown_seen, io);
    if (observer.validation_error) |err| return err;
    try expectOpen(&client);
    observer.release_shutdown.set(io);
    try support.expectOverlapEof(&client);
    if (mode == .writer_held) {
        try support.waitOverlap(&observer.writer_waiting, io);
        broker.state_mutex.lockUncancelable(io);
        const still_owned = broker.slots[0].state.active and broker.slots[0].connection == connection;
        broker.state_mutex.unlock(io);
        try std.testing.expect(still_owned);
        writer.release.set(io);
        writer_thread.?.join();
        writer_joined = true;
        if (writer.err) |err| return err;
    }
    try support.waitOverlap(&observer.retired, io);
    if (mode == .fail_once or mode == .fail_repeatedly) {
        try support.waitOverlap(&service.done, io);
    } else {
        service.shutdown.set(io);
    }
    server_thread.join();
    service_joined = true;
    if (mode == .fail_once or mode == .fail_repeatedly) {
        try std.testing.expectEqual(@as(?anyerror, error.InputOutput), service.err);
    } else if (service.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 0), broker.stats().active_connections);
    try std.testing.expectEqual(@as(usize, 0), broker.wills.count());
    try std.testing.expectEqual(@as(usize, 0), broker.retained.count());
    if (mode != .fail_repeatedly) {
        var restored = try context.testBrokerFn(allocator, io, 1, 64);
        defer restored.deinit();
        try restored.restoreCommitLog(tmp.dir, "clean-will-close.log", .{});
        try std.testing.expectEqual(@as(usize, 0), restored.sessions.count());
        try std.testing.expectEqual(@as(usize, 0), restored.wills.count());
        try std.testing.expectEqual(@as(usize, 0), restored.will_publishers.count());
    }
}
