const std = @import("std");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");
const allocator = std.testing.allocator;

const Fixture = struct {
    connection: runtime.Connection,
    peer: std.Io.net.Stream,

    fn init(io: std.Io) !Fixture {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);
        const peer = try listener.accept(io);
        errdefer peer.close(io);
        var connection: runtime.Connection = .{ .io = io, .allocator = allocator, .stream = stream, .role = .client };
        errdefer connection.close();
        try runtime.testing.addActiveLocalStream(&connection, 1);
        // A complete response head followed by a silent body forces timeout
        // after admission and allocation, rather than failing preflight.
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 4, 1, &.{0x88});
        return .{ .connection = connection, .peer = peer };
    }

    fn deinit(self: *@This()) void {
        self.connection.allocator = allocator;
        self.peer.close(self.connection.io);
        self.connection.close();
    }
};

const Writer = struct {
    var active: std.atomic.Value(?*Writer) = .init(null);
    io: std.Io,
    mode: enum { blocked, partial, forbidden },
    calls: std.atomic.Value(usize) = .init(0),
    cancelled: std.atomic.Value(bool) = .init(false),
    wait: std.Io.Event = .unset,

    fn write(_: ?*anyopaque, _: std.Io.net.Socket.Handle, header: []const u8, _: []const []const u8, _: usize) std.Io.net.Stream.Writer.Error!usize {
        const self = active.load(.acquire).?;
        const call = self.calls.fetchAdd(1, .monotonic);
        switch (self.mode) {
            .blocked => {
                self.wait.wait(self.io) catch |err| {
                    self.cancelled.store(true, .release);
                    return err;
                };
                return header.len;
            },
            .partial => return if (call == 0) @min(4, header.len) else error.NetworkDown,
            .forbidden => return error.NetworkDown,
        }
    }
};

test "HTTP/2 response timeout cleanup bounds a blocked cancellation and retires state" {
    try failedCleanup(false, .blocked, false);
}

test "HTTP/2 response OOM cleanup retains the earlier operation deadline" {
    try failedCleanup(true, .blocked, false);
}

test "HTTP/2 response timeout cleanup rejects later writes after a partial reset" {
    try failedCleanup(false, .partial, false);
}

test "HTTP/2 response timeout cleanup can skip the control write" {
    try failedCleanup(false, .forbidden, true);
}

test "HTTP/2 response timeout cleanup shares refund budget and forbids reset after failure" {
    try failedCleanup(false, .blocked, true);
    try failedCleanup(false, .partial, true);
}

fn failedCleanup(oom: bool, mode: @FieldType(Writer, "mode"), data: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try Fixture.init(io);
    defer fixture.deinit();
    if (data) try wire.appendFrame(&fixture.connection.frame_reader.buffer, allocator, .data, 0, 1, "abc");
    var writer: Writer = .{ .io = io, .mode = mode };
    var vtable = io.vtable.*;
    vtable.netWrite = Writer.write;
    fixture.connection.io = .{ .userdata = io.userdata, .vtable = &vtable };
    fixture.connection.limits.terminal_cleanup_timeout = if (mode == .forbidden) .zero else if (oom) .fromSeconds(2) else .fromMilliseconds(20);
    Writer.active.store(&writer, .release);
    defer Writer.active.store(null, .release);
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    if (oom) fixture.connection.allocator = failing.allocator();

    const started = std.Io.Clock.Timestamp.now(io, .awake);
    const result = fixture.connection.readResponseWithTimeout(1, "POST", false, .fromMilliseconds(if (oom) 40 else 5));
    const elapsed = started.durationTo(std.Io.Clock.Timestamp.now(io, .awake)).raw;
    fixture.connection.allocator = allocator;
    fixture.connection.io = io;
    try std.testing.expectError(if (oom) error.OutOfMemory else error.Timeout, result);
    // A 2-second cleanup cap in the OOM case must still honor the 40-ms
    // operation deadline. Blocked work must be canceled and joined on return.
    try std.testing.expect(elapsed.nanoseconds < std.Io.Duration.fromMilliseconds(500).nanoseconds);
    try std.testing.expect(fixture.connection.aggregate_timeout_unusable);
    try std.testing.expect(fixture.connection.terminal_write_failed);
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.active_local_streams.items.len);
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.recv_stream_windows.items.len);
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.send_stream_windows.items.len);
    if (mode == .forbidden) try std.testing.expectEqual(@as(i64, 65_535), fixture.connection.recv_connection_window.value);
    const calls = writer.calls.load(.acquire);
    try std.testing.expectEqual(@as(usize, switch (mode) {
        .blocked => 1,
        .partial => 2,
        .forbidden => 0,
    }), calls);
    if (mode == .blocked) try std.testing.expect(writer.cancelled.load(.acquire));
    try std.testing.expectError(error.ConnectionClosed, fixture.connection.readResponseWithTimeout(3, "POST", false, .fromSeconds(1)));
    try std.testing.expectEqual(calls, writer.calls.load(.acquire));
}
