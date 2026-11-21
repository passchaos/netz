const std = @import("std");
const websocket = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const h3 = @import("h3.zig");
const http2 = @import("../../http2/mod.zig");
const http3 = @import("../../http3/mod.zig");
const quic = @import("../../quic/mod.zig");
const allocator = std.testing.allocator;
const Operation = enum { binary, text, generic, slices, inplace, fragments, ping, pong, close, ping_wait, close_wait, retained_close_wait };

test {
    _ = @import("../../internal/timed_mutex_tests.zig");
}

fn exercise(connection: anytype, io: std.Io, role: runtime.Role, operation: Operation) !void {
    if (operation == .inplace and role != .client) return;
    const queued = operation == .retained_close_wait;
    if (queued) {
        connection.pending_auto_control = .{ .opcode = .close, .delivery = .close_wait };
        const pending = &connection.pending_auto_control.?;
        const bytes = try websocket.writeFrameInto(&pending.bytes, .close, &.{}, .{ .mask_key = if (role == .client) .{ 1, 2, 3, 4 } else null });
        pending.len = bytes.len;
        connection.automatic_write_pending.store(true, .release);
    }
    defer if (queued) {
        connection.pending_auto_control = null;
        connection.automatic_write_pending.store(false, .release);
    };
    connection.send_mutex.lockUncancelable(io);
    var locked = true;
    defer if (locked) connection.send_mutex.unlock(io);
    const Task = struct {
        connection: @TypeOf(connection),
        io: std.Io,
        operation: Operation,
        started: std.Io.Event = .unset,
        done: std.Io.Event = .unset,
        err: ?anyerror = null,
        progress: runtime.MessageWriteProgress = .{},
        mutable: [8]u8 = "unmasked".*,
        fn send(self: *@This()) !void {
            const deadline = std.Io.Clock.Timestamp.fromNow(self.io, .{ .clock = .awake, .raw = .fromMilliseconds(10) });
            switch (self.operation) {
                .binary => try self.connection.sendBinaryWithDeadline("data", &self.progress, deadline),
                .text => try self.connection.sendTextWithDeadline("text", &self.progress, deadline),
                .generic => try self.connection.sendMessageWithDeadline(.binary, "data", &self.progress, deadline),
                .slices => try self.connection.sendBinarySlicesWithDeadline(&.{ "one", "two" }, &self.progress, deadline),
                .inplace => try self.connection.sendBinaryInPlaceWithDeadline(&self.mutable, &self.progress, deadline),
                .fragments => try self.connection.sendFragmentedWithDeadline(.binary, &.{ "one", "two" }, &self.progress, deadline),
                .ping => try self.connection.sendPingWithDeadline("probe", &self.progress, deadline),
                .pong => try self.connection.sendPongWithDeadline("probe", &self.progress, deadline),
                .close => try self.connection.sendCloseFrameWithDeadline(null, &self.progress, deadline),
                .ping_wait => _ = try self.connection.pingWithDeadline("probe", deadline),
                .close_wait, .retained_close_wait => _ = try self.connection.closeWithDeadline(null, deadline),
            }
        }
        fn run(self: *@This()) void {
            self.started.set(self.io);
            self.send() catch |err| {
                self.err = err;
            };
            self.done.set(self.io);
        }
    };
    var task = Task{ .connection = connection, .io = io, .operation = operation };
    var future = try io.concurrent(Task.run, .{&task});
    defer _ = future.cancel(io);
    try task.started.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    const observed = if (task.done.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(100) } })) |_| true else |err| switch (err) {
        error.Timeout => false,
        else => return err,
    };
    try std.testing.expect(!connection.send_mutex.tryLock());
    connection.send_mutex.unlock(io);
    locked = false;
    future.await(io);
    try std.testing.expect(observed);
    try std.testing.expectEqual(@as(?anyerror, error.Timeout), task.err);
    try std.testing.expectEqual(@as(usize, 0), task.progress.committed_bytes);
    try std.testing.expectEqualStrings("unmasked", &task.mutable);
    try std.testing.expect(connection.pending_write.isNone());
    try std.testing.expect(!connection.close_sent.load(.acquire));
    if (queued) {
        try std.testing.expect(connection.pending_auto_control != null);
        try std.testing.expectEqual(@as(usize, 0), connection.pending_auto_control.?.committed);
        try std.testing.expect(connection.automatic_write_pending.load(.acquire));
    }
}

test "WebSocket bounded send mutex admission covers HTTP1 operations and both roles" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    for (std.enums.values(runtime.Role)) |role| {
        var connection = runtime.Connection{ .allocator = allocator, .io = threaded.io(), .stream = undefined, .role = role };
        for (std.enums.values(Operation)) |operation| try exercise(&connection, threaded.io(), role, operation);
    }
}

test "WebSocket bounded send mutex admission covers HTTP2 operations and both roles" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var transport: http2.runtime.Connection = undefined;
    transport.io = threaded.io();
    for (std.enums.values(runtime.Role)) |role| {
        var connection = runtime.H2Connection{ .allocator = allocator, .tunnel = .{ .connection = &transport, .stream_id = 1 }, .role = role };
        for (std.enums.values(Operation)) |operation| try exercise(&connection, threaded.io(), role, operation);
    }
}

test "WebSocket bounded send mutex admission covers HTTP3 operations and both roles" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0x34} ** quic.protection.secret_len);
    inline for (.{ runtime.Role.client, runtime.Role.server }) |role| {
        var connection = h3.Connection(role){ .allocator = allocator, .h3 = undefined, .stream_id = 0 };
        connection.h3.established.connection = try quic.one_rtt.Connection.init(&endpoint, .{ .peer = endpoint.address(), .receive_keys = keys, .send_keys = keys, .local_connection_id = "mutex-deadline", .peer_connection_id = "mutex-peer", .local_endpoint = if (role == .client) .client else .server, .enable_pacing = false });
        defer connection.h3.established.connection.deinit();
        for (std.enums.values(Operation)) |operation| try exercise(&connection, io, role, operation);
    }
}
