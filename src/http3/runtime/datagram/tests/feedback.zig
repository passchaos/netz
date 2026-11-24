//! Feedback backpressure cannot hide a terminal signal already received.
const std = @import("std");
const Backend = @import("../../../../runtime.zig").Backend;
const quic = @import("../../../../quic/mod.zig");
const support = @import("../test_support/pair.zig");
const Pair = support.Pair;
const send = @import("../test_support/send.zig").withinBudget;

test "HTTP/3 CONNECT DATAGRAM pacing wait preserves queued QPACK feedback at STOP_SENDING" {
    try exercise(true);
}

test "HTTP/3 CONNECT DATAGRAM wait retains its deadline while QPACK feedback is blocked" {
    try exercise(false);
}

fn exercise(stop: bool) !void {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        for ([_]bool{ false, true }) |pacing| {
            for ([_]bool{ false, true }) |batch| {
                var pair: Pair = undefined;
                try pair.init(backend.io());
                defer pair.deinit();
                const sender = if (role == .client) &pair.client else &pair.server;
                try sender.qpack_decode.recordStreamCancellation(0);
                try pair.sendPeer(role, if (stop) &.{.{ .stop_sending = .{ .stream_id = 0, .application_error_code = 91 } }} else &.{.ping});
                const connection = pair.connection(role);
                const previous = connection.congestion.congestion_window;
                defer connection.congestion.congestion_window = previous;
                if (pacing) {
                    connection.pacer.enabled = true;
                    connection.setMaxPacingRateBytesPerSecond(1);
                    quic.one_rtt.testing.exhaustPacingAt(connection, @intCast(std.Io.Clock.awake.now(backend.io()).nanoseconds));
                } else connection.congestion.congestion_window = 0;
                const before = connection.datagramsSent();
                var committed: usize = 99;
                try std.testing.expectError(if (stop) error.StreamStopped else error.Timeout, send(sender, backend.io(), batch, true, 0, &.{ "late", "also late" }, &committed));
                try std.testing.expectEqual(before, connection.datagramsSent());
                if (batch) try std.testing.expectEqual(@as(usize, 0), committed);
                try std.testing.expectEqual(@as(u64, 0), sender.qpack_decoder_send.next_offset);
                try std.testing.expectEqual(@as(usize, 1), sender.qpack_decode.pendingDecoderInstructions().len);
                try std.testing.expect(!connection.closing());
                connection.pacer.enabled = false;
                connection.congestion.congestion_window = previous;
                try pair.sendPeer(role, &.{.ping});
                if (role == .client) try sender.receiveDetachedResponseProgressWithTimeout(0, .fromSeconds(1)) else try sender.receiveDetachedRequestProgressWithTimeout(0, .fromSeconds(1));
                try std.testing.expectEqual(@as(u64, 1), sender.qpack_decoder_send.next_offset);
                try std.testing.expectEqual(@as(usize, 0), sender.qpack_decode.pendingDecoderInstructions().len);
            }
        }
    }
}

test "HTTP/3 CONNECT DATAGRAM batch preserves its prefix with QPACK feedback and STOP_SENDING" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        var pair: Pair = undefined;
        try pair.init(backend.io());
        defer pair.deinit();
        const sender = if (role == .client) &pair.client else &pair.server;
        try sender.qpack_decode.recordStreamCancellation(0);
        try pair.sendPeer(role, &.{.{ .stop_sending = .{ .stream_id = 0, .application_error_code = 91 } }});
        const connection = pair.connection(role);
        const previous = connection.congestion.congestion_window;
        defer connection.congestion.congestion_window = previous;
        const first = "a" ** 800;
        const packet_size = try connection.packetLenForFramesAtOffset(0, &.{.{ .datagram = .{ .data = "\x00" ++ first } }});
        connection.congestion.congestion_window = connection.congestion.bytes_in_flight + packet_size;
        const before = connection.datagramsSent();
        var committed: usize = 99;
        try std.testing.expectError(error.StreamStopped, send(sender, backend.io(), true, true, 0, &.{ first, "b" ** 800, "c" ** 800 }, &committed));
        try std.testing.expectEqual(@as(usize, 1), committed);
        try std.testing.expectEqual(before + 1, connection.datagramsSent());
        try std.testing.expect(!connection.closing());
    }
}

test "HTTP/3 CONNECT DATAGRAM pacing wake resumes QPACK feedback without another peer packet" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        var pair: Pair = undefined;
        try pair.init(backend.io());
        defer pair.deinit();
        const sender = if (role == .client) &pair.client else &pair.server;
        try sender.qpack_decode.recordStreamCancellation(0);
        try pair.sendPeer(role, &.{.ping});
        const connection = pair.connection(role);
        connection.pacer.enabled = true;
        // Keep the refill well below one datagram for the whole call. A
        // 100 kB/s ceiling refilled the deficit in ~350 us, so a scheduling
        // delay between exhausting the budget and sending could let the first
        // attempt succeed and skip the QPACK flush this test observes.
        connection.setMaxPacingRateBytesPerSecond(20_000);
        quic.one_rtt.testing.exhaustPacingAt(connection, @intCast(std.Io.Clock.awake.now(backend.io()).nanoseconds));
        var committed: usize = 0;
        try send(sender, backend.io(), false, false, 0, &.{"resumed"}, &committed);
        try std.testing.expectEqual(@as(usize, 0), sender.qpack_decode.pendingDecoderInstructions().len);
        try std.testing.expectEqual(@as(u64, 1), sender.qpack_decoder_send.next_offset);
    }
}
