//! Protocol rejection must preserve its cause without blocking on GOAWAY.
const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../../runtime.zig");
const http2 = @import("../../mod.zig");
const wire = @import("../frame/wire.zig");
const BlockedOutput = @import("../testing/blocked_output.zig").BlockedOutput;
const allocator = std.testing.allocator;
const Fault = enum { envelope, continuation, window, settings, reset_budget, data_budget, push_hpack, push_continuation_hpack, reserved_push_data, reserved_push_window };

test "HTTP/2 protocol error GOAWAY zero budget emits no terminal bytes" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    for (std.enums.values(Fault)) |fault| {
        var fixture = try BlockedOutput.init(threaded.io(), .server);
        defer fixture.deinit();
        const connection = &fixture.connection;
        connection.limits.terminal_cleanup_timeout = .zero;
        try prepareFault(connection, fault);
        try rejectFault(connection, fault);
        try std.testing.expect(connection.aggregate_timeout_unusable and connection.terminal_write_failed);
        try connection.stream.shutdown(connection.io, .send);
        var buffer: [1]u8 = undefined;
        var reader = fixture.peer.reader(connection.io, &buffer);
        try std.testing.expectError(error.EndOfStream, reader.interface.takeByte());
    }
}

test "HTTP/2 protocol error GOAWAY stops output after terminal write failure" {
    const protocol_error = @import("protocol_error.zig");
    const Connection = struct {
        aggregate_timeout_unusable: bool = false,
        terminal_write_failed: bool = false,
        calls: usize = 0,

        fn send(self: *@This(), _: u31, _: http2.ErrorCode, _: []const u8, _: std.Io.Clock.Timestamp) !void {
            self.calls += 1;
            return error.NetworkDown;
        }
    };
    var connection: Connection = .{};
    const before: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .zero };
    protocol_error.goAway(&connection, 1, http2.ErrorCode.protocol_error, "sequence", before, Connection.send);
    protocol_error.goAway(&connection, 1, http2.ErrorCode.compression_error, "decode", before, Connection.send);
    try std.testing.expectEqual(@as(usize, 1), connection.calls);
    try std.testing.expect(connection.aggregate_timeout_unusable and connection.terminal_write_failed);
}

test "HTTP/2 protocol error GOAWAY bounds blocked output and preserves causes" {
    if (comptime builtin.os.tag != .linux) return;
    for (std.enums.values(Fault)) |fault| {
        var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
        defer threaded.deinit();
        const io = threaded.io();
        var fixture = try BlockedOutput.init(io, .server);
        defer fixture.deinit();
        const connection = &fixture.connection;
        try prepareFault(connection, fault);
        try fixture.saturate();
        try fixture.startRescue();
        const started = std.Io.Clock.awake.now(io);
        try rejectFault(connection, fault);
        try std.testing.expect(started.untilNow(io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
        try std.testing.expect(connection.aggregate_timeout_unusable);
        try std.testing.expect(connection.terminal_write_failed);
    }
}

fn prepareFault(connection: *runtime.Connection, fault: Fault) !void {
    switch (fault) {
        .envelope => try wire.appendFrame(&connection.frame_reader.buffer, allocator, .ping, 0, 0, "1234567"),
        .window => {
            runtime.testing.setSendConnectionWindow(connection, std.math.maxInt(i32));
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .window_update, 0, 0, &.{ 0, 0, 0, 1 });
        },
        .settings => try wire.appendFrame(&connection.frame_reader.buffer, allocator, .settings, 0, 0, &.{ 0, 4, 0x80, 0, 0, 0 }),
        .reset_budget => {
            connection.limits.max_local_error_reset_streams = 0;
            try runtime.testing.addActivePeerStream(connection, 1);
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .window_update, 0, 1, &.{ 0, 0, 0, 0 });
        },
        .data_budget => connection.limits.data_frame_budget = 0,
        .continuation => {
            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(allocator);
            try http2.Hpack.encodeLiteralBlock(&encoded, allocator, &.{
                .{ .name = ":method", .value = "POST" },
                .{ .name = ":scheme", .value = "http" },
                .{ .name = ":authority", .value = "localhost" },
                .{ .name = ":path", .value = "/headers" },
            });
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 0, 1, encoded.items);
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 0, 1, "");
        },
        .push_hpack, .push_continuation_hpack, .reserved_push_data, .reserved_push_window => {
            connection.role = .client;
            connection.limits.enable_push = true;
            try runtime.testing.addActiveLocalStream(connection, 1);
            var promise: std.ArrayList(u8) = .empty;
            defer promise.deinit(allocator);
            try promise.appendSlice(allocator, &.{ 0, 0, 0, 2 });
            try http2.Hpack.encodeLiteralBlock(&promise, allocator, &.{
                .{ .name = ":method", .value = "GET" },
                .{ .name = ":scheme", .value = "http" },
                .{ .name = ":authority", .value = "localhost" },
                .{ .name = ":path", .value = "/push" },
            });
            try runtime.testing.receivePushPromise(connection, .{
                .header = .{ .length = @intCast(promise.items.len), .frame_type = .push_promise, .flags = 4, .stream_id = 1 },
                .payload = promise.items,
            });
            switch (fault) {
                .push_hpack => try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 5, 2, "\x80"),
                .push_continuation_hpack => {
                    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 1, 2, "");
                    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .continuation, 4, 2, "\x80");
                },
                .reserved_push_data => try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 0, 2, "x"),
                .reserved_push_window => try wire.appendFrame(&connection.frame_reader.buffer, allocator, .window_update, 0, 2, &.{ 0, 0, 0, 1 }),
                else => unreachable,
            }
        },
    }
}

fn rejectFault(connection: *runtime.Connection, fault: Fault) !void {
    switch (fault) {
        .continuation => try std.testing.expectError(error.UnexpectedFrame, connection.acceptDuplexRequestWithTimeout(.fromSeconds(1))),
        .data_budget => try std.testing.expectError(error.ConnectionGoAway, runtime.testing.receiveDataPayload(connection, 1, .{
            .header = .{ .length = 1, .frame_type = .data, .flags = 0, .stream_id = 1 },
            .payload = "x",
        })),
        else => try std.testing.expectError(switch (fault) {
            .window => error.ConnectionGoAway,
            .settings => error.InvalidSetting,
            .push_hpack, .push_continuation_hpack => error.InvalidEncoding,
            else => error.InvalidFrame,
        }, connection.readWindowUpdateWithTimeout(.fromSeconds(1))),
    }
}

test "HTTP/2 protocol error reset bounds output and retires only rejected stream" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const Mode = enum { healthy, disabled, blocked };
    for (std.enums.values(Mode)) |mode| {
        var fixture = try BlockedOutput.init(threaded.io(), .server);
        defer fixture.deinit();
        const connection = &fixture.connection;
        if (mode == .disabled) connection.limits.terminal_cleanup_timeout = .zero;
        try runtime.testing.addActivePeerStream(connection, 1);
        try runtime.testing.addActivePeerStream(connection, 3);
        _ = try runtime.testing.recvStreamWindow(connection, 1);
        _ = try runtime.testing.sendStreamWindow(connection, 1);
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .window_update, 0, 1, &.{ 0, 0, 0, 0 });
        if (mode == .blocked) {
            try fixture.saturate();
            try fixture.startRescue();
        }
        const started = std.Io.Clock.awake.now(connection.io);
        try std.testing.expectError(error.InvalidFrame, connection.readWindowUpdateWithTimeout(.fromSeconds(1)));
        try std.testing.expect(started.untilNow(connection.io, .awake).nanoseconds < 400 * std.time.ns_per_ms);
        try std.testing.expect(!runtime.testing.hasActivePeerStream(connection, 1));
        try std.testing.expect(!runtime.testing.hasStreamWindow(connection, 1));
        try std.testing.expect(runtime.testing.hasActivePeerStream(connection, 3));
        if (mode == .healthy) {
            try std.testing.expect(!connection.aggregate_timeout_unusable and !connection.terminal_write_failed);
        } else {
            try std.testing.expect(connection.aggregate_timeout_unusable and connection.terminal_write_failed);
        }
        if (mode != .blocked) {
            try connection.stream.shutdown(connection.io, .send);
            var buffer: [http2.ResetStreamPayload.encoded_len]u8 = undefined;
            var reader = fixture.peer.reader(connection.io, &buffer);
            if (mode == .healthy) {
                const frame = try http2.Frame.parse(try reader.interface.take(buffer.len));
                const reset = try http2.ResetStreamPayload.parse(frame);
                try std.testing.expectEqual(@as(u31, 1), reset.stream_id);
                try std.testing.expectEqual(http2.ErrorCode.protocol_error, reset.error_code);
            }
            try std.testing.expectError(error.EndOfStream, reader.interface.takeByte());
        }
    }
}
