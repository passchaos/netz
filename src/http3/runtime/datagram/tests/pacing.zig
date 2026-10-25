//! Pacing waits must retain the HTTP/3 receive owner and terminal state.
const std = @import("std");
const quic = @import("../../../../quic/mod.zig");
const support = @import("../test_support/pair.zig");
const Pair = support.Pair;
const send = @import("../test_support/send.zig").withinBudget;

test "HTTP/3 CONNECT DATAGRAM pacing wait observes peer connection close" {
    try exercise(true);
}

test "HTTP/3 CONNECT DATAGRAM pacing wait observes peer STOP_SENDING" {
    try exercise(false);
}

fn exercise(close: bool) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        for ([_]bool{ false, true }) |batch| {
            for ([_]bool{ false, true }) |bounded| {
                var pair: Pair = undefined;
                try pair.init(threaded.io());
                defer pair.deinit();
                try pair.sendPeer(role, if (close) &.{.{ .application_close = .{ .error_code = 91, .reason_phrase = "during pacing" } }} else &.{.{ .stop_sending = .{ .stream_id = 0, .application_error_code = 91 } }});
                const connection = pair.connection(role);
                connection.pacer.enabled = true;
                connection.setMaxPacingRateBytesPerSecond(if (bounded) 1 else 1000);
                quic.one_rtt.testing.exhaustPacingAt(connection, @intCast(std.Io.Clock.awake.now(threaded.io()).nanoseconds));
                const sender = if (role == .client) &pair.client else &pair.server;
                const before = connection.datagramsSent();
                var committed: usize = 99;
                const result = send(sender, threaded.io(), batch, bounded, 0, &.{ "late", "also late" }, &committed);
                try std.testing.expectError(if (close) error.ConnectionClosed else error.StreamStopped, result);
                try std.testing.expectEqual(before, connection.datagramsSent());
                if (batch) try std.testing.expectEqual(@as(usize, 0), committed);
                if (close) {
                    const info = connection.peerCloseInfo().?;
                    try std.testing.expect(info == .application);
                    try std.testing.expectEqual(@as(u64, 91), info.application.error_code);
                    try std.testing.expectEqualStrings("during pacing", info.application.reason_phrase);
                } else try std.testing.expect(!connection.closing());
            }
        }
    }
}

test "HTTP/3 CONNECT DATAGRAM pacing wait resumes at a local timer" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        for ([_]bool{ false, true }) |batch| {
            for ([_]bool{ false, true }) |bounded| {
                var pair: Pair = undefined;
                try pair.init(threaded.io());
                defer pair.deinit();
                const connection = pair.connection(role);
                connection.pacer.enabled = true;
                connection.setMaxPacingRateBytesPerSecond(100000);
                quic.one_rtt.testing.exhaustPacingAt(connection, @intCast(std.Io.Clock.awake.now(threaded.io()).nanoseconds));
                const sender = if (role == .client) &pair.client else &pair.server;
                const receiver = if (role == .client) &pair.server else &pair.client;
                var committed: usize = 99;
                try send(sender, threaded.io(), batch, bounded, 0, &.{ "first", "second" }, &committed);
                if (batch) try std.testing.expectEqual(@as(usize, 2), committed);
                var first = try receiver.receiveConnectDatagramWithTimeout(0, .fromSeconds(1));
                defer first.deinit(std.testing.allocator);
                try std.testing.expectEqualStrings("first", first.payload);
                if (batch) {
                    var second = try receiver.receiveConnectDatagramWithTimeout(0, .fromSeconds(1));
                    defer second.deinit(std.testing.allocator);
                    try std.testing.expectEqualStrings("second", second.payload);
                }
            }
        }
    }
}

test "HTTP/3 CONNECT DATAGRAM pacing wait preserves sibling datagrams and detached DATA" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        try pair.addConnect();
        const connection = pair.connection(role);
        try pair.sendPeer(role, &.{
            .{ .datagram = .{ .data = "\x01sibling" } },
            .{ .stream = .{ .stream_id = 0, .offset = connection.recvStreamStats(0).?.highest_received_offset, .data = "\x00\x07capsule" } },
            .{ .stop_sending = .{ .stream_id = 0, .application_error_code = 91 } },
        });
        connection.pacer.enabled = true;
        connection.setMaxPacingRateBytesPerSecond(1);
        quic.one_rtt.testing.exhaustPacingAt(connection, @intCast(std.Io.Clock.awake.now(threaded.io()).nanoseconds));
        const sender = if (role == .client) &pair.client else &pair.server;
        var committed: usize = 99;
        try std.testing.expectError(error.StreamStopped, send(sender, threaded.io(), false, true, 0, &.{"late"}, &committed));
        var datagram = (try sender.pollConnectDatagram(4)).?;
        defer datagram.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("sibling", datagram.payload);
        try std.testing.expectEqualStrings("\x00\x07capsule", connection.availableReceivedStream(0).?);
        connection.pacer.enabled = false;
        try sender.sendConnectDatagram(4, "still writable");
        try std.testing.expect(!connection.closing());
    }
}

test "HTTP/3 CONNECT DATAGRAM pacing wait retains caller timeout without peer traffic" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        const connection = pair.connection(role);
        connection.pacer.enabled = true;
        connection.setMaxPacingRateBytesPerSecond(1);
        quic.one_rtt.testing.exhaustPacingAt(connection, @intCast(std.Io.Clock.awake.now(threaded.io()).nanoseconds));
        const sender = if (role == .client) &pair.client else &pair.server;
        const before = connection.datagramsSent();
        var committed: usize = 99;
        try std.testing.expectError(error.Timeout, sender.sendConnectDatagramsWithTimeout(0, &.{ "first", "second" }, &committed, .fromMilliseconds(10)));
        try std.testing.expectEqual(@as(usize, 0), committed);
        try std.testing.expectEqual(before, connection.datagramsSent());
        try std.testing.expect(!connection.closing());
    }
}
