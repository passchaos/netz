//! Concurrent admission barriers for durable reader and takeover cleanup.
const std = @import("std");
const context = @import("../../broker_tests.zig").TestContext;
const mqtt = context.mqtt_mod;
const runtime = context.runtime_mod;

pub const AdmissionOverlap = struct {
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
    sync_armed: std.atomic.Value(bool) = .init(false),
    fail_sync: std.atomic.Value(bool) = .init(false),
    sync_entered: std.Io.Event = .unset,
    release_sync: std.Io.Event = .unset,
    sync_complete: std.Io.Event = .unset,
    pub var active: ?*AdmissionOverlap = null;

    pub fn unblock(self: *AdmissionOverlap) void {
        self.release_disconnect.set(self.delegate);
        self.release_connack.set(self.delegate);
        self.release_retry.set(self.delegate);
        self.release_sync.set(self.delegate);
    }

    pub fn netRead(userdata: ?*anyopaque, handle: std.Io.net.Socket.Handle, data: [][]u8) std.Io.net.Stream.Reader.Error!usize {
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

    pub fn netWrite(userdata: ?*anyopaque, handle: std.Io.net.Socket.Handle, header: []const u8, data: []const []const u8, splat: usize) std.Io.net.Stream.Writer.Error!usize {
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

    pub fn sleep(userdata: ?*anyopaque, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self = active.?;
        if (self.park_second and self.connack_parked.isSet() and !self.retry_gated.swap(true, .acq_rel)) {
            self.retry_entered.set(self.delegate);
            self.release_retry.waitTimeout(self.delegate, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(5) } }) catch return error.Canceled;
        }
        return self.delegate.vtable.sleep(userdata, timeout);
    }

    pub fn waitUncancelable(userdata: ?*anyopaque, pointer: *const u32, expected: u32) void {
        const self = active.?;
        if (self.old_writer.load(.acquire)) |writer| {
            const target: *const u32 = @ptrCast(&writer.state.raw);
            if (pointer == target) self.writer_parked.set(self.delegate);
        }
        self.delegate.vtable.futexWaitUncancelable(userdata, pointer, expected);
    }

    pub fn waitCancelable(userdata: ?*anyopaque, pointer: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self = active.?;
        if (self.old_writer.load(.acquire)) |mutex| {
            const target: *const u32 = @ptrCast(&mutex.state.raw);
            if (pointer == target) self.writer_parked.set(self.delegate);
        }
        return self.delegate.vtable.futexWait(userdata, pointer, expected, timeout);
    }

    pub fn fileSync(userdata: ?*anyopaque, file: std.Io.File) std.Io.File.SyncError!void {
        const self = active.?;
        const gated = self.sync_armed.swap(false, .acq_rel);
        if (gated) {
            self.sync_entered.set(self.delegate);
            self.release_sync.waitTimeout(self.delegate, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(5) } }) catch return error.InputOutput;
        }
        if (self.fail_sync.swap(false, .acq_rel)) return error.InputOutput;
        try self.delegate.vtable.fileSync(userdata, file);
        if (gated) self.sync_complete.set(self.delegate);
    }

    pub fn netClose(userdata: ?*anyopaque, handles: []const std.Io.net.Socket.Handle) void {
        const self = active.?;
        self.delegate.vtable.netClose(userdata, handles);
        const before = self.close_count.fetchAdd(handles.len, .acq_rel);
        if (before < 1 and before + handles.len >= 1) self.first_retired.set(self.delegate);
        if (before < 2 and before + handles.len >= 2) self.second_retired.set(self.delegate);
    }
};

pub const OverlapService = struct {
    broker: *context.BrokerType,
    shutdown: std.Io.Event = .unset,
    err: ?anyerror = null,
    done: std.Io.Event = .unset,
    stop_on_error: bool = false,

    pub fn run(self: *OverlapService) void {
        defer self.done.set(self.broker.io);
        self.broker.serveListenersUntil(&.{.{ .source = self.broker.server.?.pendingSource(), .accept_concurrency = 2 }}, .{
            .shutdown = &self.shutdown,
            .connection_error_policy = if (self.stop_on_error) .stop else .continue_serving,
        }) catch |err| {
            self.err = err;
        };
    }
};

pub const OverlapClient = struct {
    io: std.Io,
    address: std.Io.net.IpAddress,
    client_id: []const u8,
    clean_start: bool = true,
    expiry: u32 = 0,
    result: ?runtime.ConnectResult = null,
    err: ?anyerror = null,

    pub fn run(self: *OverlapClient) void {
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

pub fn waitOverlap(event: *std.Io.Event, io: std.Io) !void {
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
    while (true) {
        event.waitTimeout(io, .{ .deadline = deadline }) catch |err| {
            if (err == error.Timeout and deadline.durationFromNow(io).raw.nanoseconds > 0) continue;
            return err;
        };
        return;
    }
}

pub fn expectOverlapEof(connection: *runtime.Connection) !void {
    var packet = connection.transport.readPacketWithDeadline(std.testing.allocator, 4096, connection.transport.deadlineFromNow(.fromSeconds(5))) catch |err| {
        try std.testing.expect(err == error.ConnectionClosed);
        return;
    };
    defer packet.deinit(std.testing.allocator);
    return error.ExpectedPeerClose;
}

pub fn writeOverlapDisconnect(connection: *runtime.Connection) !void {
    // Match the Python fixture's sendall(E0 00): keep the local socket open.
    // Connection.disconnect deliberately shuts down its transport afterward.
    var packet = [_]u8{ 0xe0, 0x00 };
    try connection.transport.writePacket(&packet);
}
