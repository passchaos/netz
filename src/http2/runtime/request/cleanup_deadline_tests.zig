//! Discarding admitted parser state must not block on its terminal control write.
const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../../runtime.zig");
const http2 = @import("../../mod.zig");
const wire = @import("../frame/wire.zig");
const BlockedOutput = @import("../testing/blocked_output.zig").BlockedOutput;
const allocator = std.testing.allocator;
const Mode = enum { aggregate, streaming, batch };

fn headers(connection: *runtime.Connection, id: u31) !void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&encoded, allocator, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = ":path", .value = "/cleanup" },
    });
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 4, id, encoded.items);
}

test "HTTP/2 request discard cleanup bounds blocked cancellation after read timeout" {
    if (comptime builtin.os.tag != .linux) return;
    for (std.enums.values(Mode)) |mode| {
        var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
        defer threaded.deinit();
        var fixture = try BlockedOutput.init(threaded.io(), .server);
        defer fixture.deinit();
        const connection = &fixture.connection;
        try headers(connection, 1);
        if (mode == .batch) try headers(connection, 3);
        try fixture.saturate();
        try fixture.startRescue();
        const Consumer = struct {
            fn consume(_: void, _: []const u8) !void {}
            fn batch(_: void, _: u31, _: []const u8) !void {}
        };
        const started = std.Io.Clock.awake.now(connection.io);
        switch (mode) {
            .aggregate => try std.testing.expectError(error.Timeout, connection.readRequestWithTimeout(.fromMilliseconds(30))),
            .streaming => try std.testing.expectError(error.Timeout, connection.readRequestStreamingWithTimeout(.fromMilliseconds(30), {}, Consumer.consume)),
            .batch => {
                var requests: [2]runtime.StreamingRequest = undefined;
                try std.testing.expectError(error.Timeout, connection.readRequestBatchStreamingIntoWithTimeout(&requests, .fromMilliseconds(30), {}, Consumer.batch));
            },
        }
        try std.testing.expect(started.untilNow(connection.io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
        try std.testing.expect(connection.aggregate_timeout_unusable);
        try std.testing.expect(connection.terminal_write_failed);
        try std.testing.expectEqual(@as(usize, 0), connection.activePeerStreamCount());
        try std.testing.expectEqual(@as(usize, 0), connection.recv_stream_windows.items.len);
        try std.testing.expectEqual(@as(usize, 0), connection.pending_requests.items.len);
    }
}

test "HTTP/2 request discard cleanup zero budget skips resets and releases owners" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var fixture = try BlockedOutput.init(threaded.io(), .server);
    defer fixture.deinit();
    const connection = &fixture.connection;
    connection.limits.terminal_cleanup_timeout = .zero;
    try headers(connection, 1);
    try headers(connection, 3);
    var requests: [2]runtime.StreamingRequest = undefined;
    const Consumer = struct {
        fn consume(_: void, _: u31, _: []const u8) !void {}
    };
    try std.testing.expectError(error.Timeout, connection.readRequestBatchStreamingIntoWithTimeout(&requests, .fromMilliseconds(5), {}, Consumer.consume));
    try std.testing.expect(connection.aggregate_timeout_unusable and connection.terminal_write_failed);
    try std.testing.expectEqual(@as(usize, 0), connection.activePeerStreamCount());
    try std.testing.expectEqual(@as(usize, 0), connection.pending_requests.items.len);
    try connection.stream.shutdown(connection.io, .send);
    var read_buffer: [1]u8 = undefined;
    var reader = fixture.peer.reader(connection.io, &read_buffer);
    try std.testing.expectError(error.EndOfStream, reader.interface.takeByte());
}

test "HTTP/2 CONNECT abandonment bounds a blocked reset in both roles" {
    if (comptime builtin.os.tag != .linux) return;
    inline for (.{ runtime.Role.client, runtime.Role.server }) |role| {
        var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
        defer threaded.deinit();
        var fixture = try BlockedOutput.init(threaded.io(), role);
        defer fixture.deinit();
        const connection = &fixture.connection;
        if (role == .client) {
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 4, 1, &.{0x88});
            var response = try connection.openExtendedConnect(.{ .method = "CONNECT", .protocol = "websocket", .authority = "localhost" });
            response.deinit(allocator);
        } else {
            connection.limits.enable_connect_protocol = true;
            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(allocator);
            try http2.Hpack.encodeLiteralBlock(&encoded, allocator, &.{
                .{ .name = ":method", .value = "CONNECT" },
                .{ .name = ":protocol", .value = "websocket" },
                .{ .name = ":scheme", .value = "http" },
                .{ .name = ":path", .value = "/" },
                .{ .name = ":authority", .value = "localhost" },
            });
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 4, 1, encoded.items);
            var stream = try connection.acceptDuplexRequestWithTimeout(.fromSeconds(1));
            // The direct connection abandonment below becomes its sole owner.
            http2.Hpack.freeOwnedFields(allocator, stream.headers);
            stream.released = true;
            connection.duplex_reader_active = false;
        }
        try fixture.saturate();
        try fixture.startRescue();
        const started = std.Io.Clock.awake.now(connection.io);
        connection.abandonExtendedConnect(1);
        try std.testing.expect(started.untilNow(connection.io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
        try std.testing.expect(connection.aggregate_timeout_unusable and connection.terminal_write_failed);
        try std.testing.expectEqual(@as(usize, 0), connection.activePeerStreamCount());
        try std.testing.expectEqual(@as(usize, 0), connection.activeLocalStreamCount());
    }
}

test "HTTP/2 request cleanup budget never renews an expired or disabled deadline" {
    const cleanup = @import("cleanup.zig");
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var state = struct { io: std.Io, limits: runtime.Limits }{ .io = threaded.io(), .limits = .{ .terminal_cleanup_timeout = .fromMilliseconds(5) } };
    const connection = &state;
    var budget: cleanup.Budget = .{};
    const first = budget.get(connection, null, true).?;
    try first.wait(connection.io);
    const future = std.Io.Clock.Timestamp.fromNow(connection.io, .{ .raw = .fromSeconds(10), .clock = .awake });
    try std.testing.expect(std.Io.Clock.Timestamp.compare(first, .eq, budget.get(connection, future, false).?));
    connection.limits.terminal_cleanup_timeout = .zero;
    var disabled: cleanup.Budget = .{};
    try std.testing.expect(disabled.get(connection, future, false) == null);
    connection.limits.terminal_cleanup_timeout = .fromSeconds(1);
    try std.testing.expect(disabled.get(connection, null, true) == null);
    const response_cleanup = @import("../response/cleanup.zig");
    try std.testing.expect(std.Io.Clock.Timestamp.compare(first, .eq, response_cleanup.limitDeadline(connection, first).?));
}

test "HTTP/2 request callback cleanup stops resets after a partial refund" {
    if (comptime builtin.os.tag != .linux) return;
    const Failure = enum { network, expired };
    const Reject = struct {
        var active: ?*@This() = null;
        connection: *runtime.Connection,
        io: std.Io,
        vtable: std.Io.VTable,
        failure: Failure,
        calls: std.atomic.Value(usize) = .init(0),
        first_type: u8 = 0,

        fn consume(self: *@This(), _: []const u8) !void {
            self.connection.io = .{ .userdata = self.io.userdata, .vtable = &self.vtable };
            return error.ApplicationRejected;
        }
        fn batch(self: *@This(), _: u31, bytes: []const u8) !void {
            return self.consume(bytes);
        }
        fn now(_: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
            const self = active.?;
            const current = self.io.vtable.now(self.io.userdata, clock);
            if (clock == .awake and self.failure == .expired and self.calls.load(.acquire) != 0) {
                return current.addDuration(.fromSeconds(2));
            }
            return current;
        }
        fn write(_: ?*anyopaque, _: std.Io.net.Socket.Handle, bytes: []const u8, _: []const []const u8, _: usize) std.Io.net.Stream.Writer.Error!usize {
            const self = active.?;
            if (self.calls.fetchAdd(1, .monotonic) == 0) {
                self.first_type = bytes[3];
                return @min(bytes.len, 4);
            }
            return error.NetworkDown;
        }
    };
    inline for (.{ false, true }) |batch| {
        for (std.enums.values(Failure)) |failure| {
            var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
            defer threaded.deinit();
            const io = threaded.io();
            var fixture = try BlockedOutput.init(io, .server);
            defer fixture.deinit();
            const connection = &fixture.connection;
            // The injected network error must win over task scheduling latency.
            // The expired case advances only this connection's clock after the
            // committed prefix, proving cleanup does not renew its captured budget.
            connection.limits.terminal_cleanup_timeout = .fromSeconds(1);
            try headers(connection, 1);
            if (batch) try headers(connection, 3);
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 0, 1, "abc");
            var reject: Reject = .{ .connection = connection, .io = io, .vtable = io.vtable.*, .failure = failure };
            reject.vtable.netWrite = Reject.write;
            reject.vtable.now = Reject.now;
            Reject.active = &reject;
            defer Reject.active = null;
            defer connection.io = io;
            if (batch) {
                var requests: [2]runtime.StreamingRequest = undefined;
                try std.testing.expectError(error.ApplicationRejected, connection.readRequestBatchStreamingInto(&requests, &reject, Reject.batch));
            } else {
                try std.testing.expectError(error.ApplicationRejected, connection.readRequestStreaming(&reject, Reject.consume));
            }
            try std.testing.expectEqual(@as(usize, if (failure == .network) 2 else 1), reject.calls.load(.acquire));
            try std.testing.expectEqual(@as(u8, @intFromEnum(http2.FrameType.window_update)), reject.first_type);
            try std.testing.expect(connection.aggregate_timeout_unusable and connection.terminal_write_failed);
            try std.testing.expectEqual(@as(usize, 0), connection.activePeerStreamCount());
            try std.testing.expectEqual(@as(i64, 65_535), connection.recv_connection_window.value);
        }
    }
}
