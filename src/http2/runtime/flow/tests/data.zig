const std = @import("std");
const http2 = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const budget = @import("../../data_frame_budget.zig");
const window = @import("../window.zig");

const Mode = enum { committed_abort, deferred_abort, failed_write, accepted_budget, skipped_connection_grant };

test "HTTP/2 DATA termination preserves a committed adaptive window grant" {
    try exercise(.committed_abort);
}

test "HTTP/2 DATA termination rolls back a deferred adaptive window grant" {
    try exercise(.deferred_abort);
}

test "HTTP/2 DATA adaptive write failure preserves local windows and retires connection" {
    try exercise(.failed_write);
}

test "HTTP/2 DATA budget uses the committed adaptive window target" {
    try exercise(.accepted_budget);
}

test "HTTP/2 DATA reports only adaptive connection credit actually granted" {
    try exercise(.skipped_connection_grant);
}

fn exercise(mode: Mode) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const Recorder = struct {
        bytes: std.ArrayList(u8) = .empty,
        fail_prefix: bool = false,
        calls: usize = 0,

        fn now(_: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
            return .zero;
        }

        fn write(context: ?*anyopaque, _: std.Io.net.Socket.Handle, header: []const u8, parts: []const []const u8, splat: usize) std.Io.net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            if (self.fail_prefix) {
                self.calls += 1;
                if (self.calls == 1) {
                    self.bytes.appendSlice(allocator, header[0..4]) catch return error.SystemResources;
                    return 4;
                }
                return error.NetworkDown;
            }
            var count = header.len;
            self.bytes.appendSlice(allocator, header) catch return error.SystemResources;
            for (parts[0 .. parts.len - 1]) |part| {
                count += part.len;
                self.bytes.appendSlice(allocator, part) catch return error.SystemResources;
            }
            for (0..splat) |_| {
                const part = parts[parts.len - 1];
                count += part.len;
                self.bytes.appendSlice(allocator, part) catch return error.SystemResources;
            }
            return count;
        }
    };
    var recorder: Recorder = .{};
    defer recorder.bytes.deinit(allocator);
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = Recorder.write;
    vtable.now = Recorder.now;
    var connection = runtime.Connection{
        .io = .{ .userdata = &recorder, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .last_peer_processed_stream_id = 1,
    };
    defer {
        connection.recv_stream_windows.deinit(allocator);
        connection.recv_stream_window_index.deinit(allocator);
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
    }
    try runtime.testing.addActivePeerStream(&connection, 1);
    const stream_window = try runtime.testing.recvStreamWindow(&connection, 1);
    const initial_value = if (mode == .skipped_connection_grant) window.default_value else window.max_value - @intFromBool(mode == .accepted_budget);
    const initial_increment: u31 = @intCast(initial_value - window.default_value);
    try connection.sendWindowUpdate(0, if (mode == .skipped_connection_grant) @intCast(window.max_value - window.default_value) else initial_increment);
    if (initial_increment != 0) try connection.sendWindowUpdate(1, initial_increment);
    try std.testing.expectEqual(initial_value, stream_window.value);
    if (mode == .deferred_abort) {
        try runtime.testing.addActivePeerStream(&connection, 3);
        _ = try runtime.testing.recvStreamWindow(&connection, 3);
        try connection.sendWindowUpdate(3, initial_increment);
    }
    const before_grant = recorder.bytes.items.len;
    // Defer SETTINGS until DATA processing, either at the stream maximum or
    // behind an outstanding ACK. The latter can advance the logical target
    // without a connection grant when explicit credit is already near maximum.
    if (mode == .skipped_connection_grant) connection.awaiting_settings_ack = true;
    try runtime.testing.queueAdaptiveWindowTarget(&connection, 65_537);
    if (mode == .skipped_connection_grant) connection.awaiting_settings_ack = false;
    try std.testing.expectEqual(before_grant, recorder.bytes.items.len);
    try std.testing.expectEqual(@as(?u32, 65_537), connection.adaptive_queued_target);
    if (mode == .accepted_budget) {
        connection.data_frame_budget.spent = budget.maximum(budget.automatic, 65_535) - 254;
    } else if (mode != .skipped_connection_grant) {
        // Real content leaves room for the adaptive grant. Exhaust the byte
        // budget afterward; pure padding reserves this room for its refund.
        connection.data_frame_budget.spent = 32_768;
    }
    recorder.fail_prefix = mode == .failed_write;
    const accepted = mode == .accepted_budget or mode == .skipped_connection_grant;
    const payload: []const u8 = if (accepted) "x" else "xy";
    const received = runtime.testing.receiveDataPayload(&connection, 1, .{
        .header = .{ .length = @intCast(payload.len), .frame_type = .data, .flags = 0, .stream_id = 1 },
        .payload = payload,
    });
    if (accepted) {
        const data = try received;
        try std.testing.expectEqualStrings("x", data.data);
        try std.testing.expectEqual(@as(u31, if (mode == .skipped_connection_grant) 0 else 2), data.adaptive_connection_increment);
        // The old target's 32767-byte budget would reject this charge. The
        // real committed target raises it to 32768 before DATA validation.
        if (mode == .accepted_budget) try std.testing.expectEqual(@as(u32, 32768), connection.data_frame_budget.spent);
        connection.data_frame_budget.release(data.budget_charge);
        try std.testing.expect(!connection.aggregate_timeout_unusable);
    } else {
        try std.testing.expectError(if (mode == .failed_write) error.NetworkDown else error.ConnectionGoAway, received);
        try std.testing.expect(connection.aggregate_timeout_unusable);
    }
    if (mode == .skipped_connection_grant) {
        try std.testing.expectEqual(window.max_value - 1, connection.recv_connection_window.value);
        try std.testing.expectEqual(window.default_value + 1, stream_window.value);
        try std.testing.expectEqual(@as(u32, 65_537), connection.recv_connection_window_target);
        try std.testing.expectEqual(@as(?u32, null), connection.adaptive_queued_target);
        const settings = try http2.Frame.parse(recorder.bytes.items[before_grant..]);
        try std.testing.expect(settings.header.frame_type == .settings);
        try std.testing.expectEqual(http2.FrameHeader.encoded_len + 6, recorder.bytes.items.len - before_grant);
        return;
    }
    try std.testing.expectEqual(window.max_value, connection.recv_connection_window.value);
    try std.testing.expectEqual(window.max_value, stream_window.value);
    if (mode == .failed_write) {
        try std.testing.expectEqual(before_grant + 4, recorder.bytes.items.len);
        try std.testing.expectEqual(@as(u32, 65_535), connection.recv_connection_window_target);
        try std.testing.expectEqual(@as(u32, 65_535), connection.recv_stream_window_target);
        return;
    }
    if (mode == .deferred_abort) {
        const goaway = try http2.Frame.parse(recorder.bytes.items[before_grant..]);
        try std.testing.expectEqual(http2.ErrorCode.enhance_your_calm, (try http2.GoAwayPayload.parse(goaway)).error_code);
        try std.testing.expectEqual(@as(?u32, 65_537), connection.adaptive_queued_target);
        try std.testing.expectEqual(window.max_value, (try runtime.testing.recvStreamWindow(&connection, 3)).value);
        return;
    }
    // DATA made room for the queued grant. Decode the actual advertised
    // WINDOW_UPDATE/SETTINGS before the terminal ENHANCE_YOUR_CALM GOAWAY.
    const update = try http2.Frame.parse(recorder.bytes.items[before_grant..]);
    try std.testing.expectEqual(@as(u31, 2), (try http2.WindowUpdatePayload.parse(update)).increment);
    const settings = try http2.Frame.parse(recorder.bytes.items[before_grant + (http2.FrameHeader.encoded_len + update.payload.len) ..]);
    try std.testing.expect(settings.header.frame_type == .settings);
    try std.testing.expectEqual(@as(u32, 65_537), std.mem.readInt(u32, settings.payload[2..6], .big));
    if (mode == .accepted_budget) return;
    const goaway = try http2.Frame.parse(recorder.bytes.items[before_grant + (http2.FrameHeader.encoded_len + update.payload.len) + (http2.FrameHeader.encoded_len + settings.payload.len) ..]);
    try std.testing.expectEqual(http2.ErrorCode.enhance_your_calm, (try http2.GoAwayPayload.parse(goaway)).error_code);
    try std.testing.expectError(error.ConnectionClosed, connection.sendWindowUpdate(0, 1));
}
