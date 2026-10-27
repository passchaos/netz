//! Bootstrap owns its socket even when terminal protocol output cannot finish.
const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../../runtime.zig");
const http2 = @import("../../mod.zig");
const wire = @import("../frame/wire.zig");
const BlockedOutput = @import("../testing/blocked_output.zig").BlockedOutput;
const allocator = std.testing.allocator;
const Fault = enum { preface, envelope, settings };

const Fixture = struct {
    socket: BlockedOutput,
    transferred: bool = false,

    fn init(io: std.Io) !Fixture {
        return .{ .socket = try BlockedOutput.init(io, .server) };
    }

    fn takeStream(self: *@This()) std.Io.net.Stream {
        std.debug.assert(!self.transferred);
        // BlockedOutput.init has not allocated connection/parser state. Only
        // its fresh socket moves into bootstrap, which owns close on failure.
        self.transferred = true;
        return self.socket.connection.stream;
    }

    fn deinit(self: *@This()) void {
        if (!self.transferred) return self.socket.deinit();
        if (self.socket.rescue) |thread| thread.join() else self.socket.peer.close(self.socket.connection.io);
    }

    fn queueFault(self: *@This(), fault: Fault) !void {
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(allocator);
        try bytes.appendSlice(allocator, if (fault == .preface) "x" ** http2.connection_preface.len else http2.connection_preface);
        switch (fault) {
            .preface => {},
            .envelope => try wire.appendFrame(&bytes, allocator, .ping, 0, 0, "1234567"),
            .settings => try wire.appendFrame(&bytes, allocator, .settings, 0, 0, &.{ 0, 4, 0x80, 0, 0, 0 }),
        }
        var writer = self.socket.peer.writer(self.socket.connection.io, &.{});
        try writer.interface.writeAll(bytes.items);
    }
};

test "HTTP/2 handshake protocol error bounds GOAWAY and preserves original cause" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    for (std.enums.values(Fault)) |fault| {
        for ([_]bool{ false, true }) |timed| try blocked(io, fault, timed);
    }
}

fn blocked(io: std.Io, fault: Fault, timed: bool) !void {
    var fixture = try Fixture.init(io);
    defer fixture.deinit();
    try fixture.queueFault(fault);
    try fixture.socket.saturate();
    try fixture.socket.startRescue();
    var server = runtime.Server{ .io = io, .allocator = allocator, .listener = undefined };
    const started = std.Io.Clock.awake.now(io);
    const result = if (timed) server.acceptStreamWithTimeout(fixture.takeStream(), .fromSeconds(1)) else server.acceptStream(fixture.takeStream());
    try std.testing.expectError(cause(fault), result);
    try std.testing.expect(started.untilNow(io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
}

fn cause(fault: Fault) anyerror {
    return switch (fault) {
        .preface => error.InvalidPreface,
        .envelope => error.InvalidFrame,
        .settings => error.InvalidSetting,
    };
}

test "HTTP/2 handshake protocol error zero budget closes without GOAWAY" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    for (std.enums.values(Fault)) |fault| {
        var fixture = try Fixture.init(io);
        defer fixture.deinit();
        try fixture.queueFault(fault);
        var server = runtime.Server{ .io = io, .allocator = allocator, .listener = undefined, .limits = .{ .terminal_cleanup_timeout = .zero } };
        try std.testing.expectError(cause(fault), server.acceptStream(fixture.takeStream()));
        var buffer: [1]u8 = undefined;
        var reader = fixture.socket.peer.reader(io, &buffer);
        try std.testing.expectError(error.EndOfStream, reader.interface.takeByte());
    }
}

test "HTTP/2 handshake protocol error emits exact GOAWAY without allocation" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    for (std.enums.values(Fault)) |fault| {
        var fixture = try Fixture.init(io);
        defer fixture.deinit();
        try fixture.queueFault(fault);
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        // A bad preface is rejected before inbound frame allocation begins.
        const output_allocator = if (fault == .preface) failing.allocator() else allocator;
        var server = runtime.Server{ .io = io, .allocator = output_allocator, .listener = undefined };
        try std.testing.expectError(cause(fault), server.acceptStream(fixture.takeStream()));
        try std.testing.expect(!failing.has_induced_failure);
        var buffer: [128]u8 = undefined;
        var reader = fixture.socket.peer.reader(io, &buffer);
        const header = try http2.FrameHeader.parse(try reader.interface.take(9));
        const payload = try reader.interface.take(header.length);
        const goaway = try http2.GoAwayPayload.parse(.{ .header = header, .payload = payload });
        try std.testing.expectEqual(http2.FrameType.goaway, header.frame_type);
        try std.testing.expectEqual(@as(u31, 0), goaway.last_stream_id);
        try std.testing.expectEqual(switch (fault) {
            .preface => http2.ErrorCode.protocol_error,
            .envelope => http2.ErrorCode.frame_size_error,
            .settings => http2.ErrorCode.flow_control_error,
        }, goaway.error_code);
        try std.testing.expectEqualStrings(switch (fault) {
            .preface => "invalid-preface",
            .envelope => "frame-envelope",
            .settings => "settings-value",
        }, goaway.debug_data);
        try std.testing.expectError(error.EndOfStream, reader.interface.takeByte());
    }
}
