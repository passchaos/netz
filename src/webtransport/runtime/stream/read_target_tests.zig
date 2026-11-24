//! Targeted control events remain independent of the receive reader mode.
const std = @import("std");
const Backend = @import("../../../runtime.zig").Backend;
const support = @import("../session_control/test_support/handshake_pair.zig");
const Pair = support.Pair;
const budget = @import("../flow/progress/support.zig").withinBudgetFor;

const Mode = enum { ordinary, timeout, deadline };

fn Reader(comptime Session: type) type {
    return struct {
        fn run(session: Session, mode: Mode, id: u62, output: []u8) !void {
            const event = switch (mode) {
                .ordinary => try session.readStreamId(id, output),
                .timeout => try session.readStreamIdWithTimeout(id, output, .fromMilliseconds(100)),
                .deadline => try session.readStreamIdWithDeadline(id, output, .fromNow(session.h3.established.connection.endpoint.io, .{ .clock = .awake, .raw = .fromMilliseconds(100) })),
            };
            try std.testing.expect(event == .stopped and event.stopped.stream_id == id);
            try std.testing.expectEqual(@as(?u32, 91), event.stopped.error_info.application_code);
        }
    };
}

fn sendAndReceive(pair: *Pair, comptime role: support.Role, id: u62, bytes: []const u8) !void {
    const sender = if (role == .client) &pair.server else &pair.client;
    try sender.sendStream(id, bytes, false);
    const source = pair.connection(if (role == .client) .server else .client);
    const expected = source.sendStreamStats(id).?.highest_sent_offset;
    const receiver = pair.connection(role);
    const until: std.Io.Clock.Timestamp = .fromNow(receiver.endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    while ((if (receiver.recvStreamStats(id)) |stats| stats.highest_received_offset else 0) < expected) try pair.receiveProgress(role, until);
}

test "WebTransport stream read target admission permits local unidirectional STOP events" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        for (std.enums.values(Mode)) |mode| {
            var pair: Pair = undefined;
            try pair.init(backend.io());
            defer pair.deinit();
            const session = if (role == .client) &pair.client else &pair.server;
            const peer = if (role == .client) &pair.server else &pair.client;
            const id = try session.openUnidirectionalStream();
            try session.sendStream(id, "outgoing", false);
            var output: [32]u8 = undefined;
            _ = try peer.readStreamIdWithTimeout(id, &output, .fromSeconds(1));
            try peer.stopStream(id, 91);
            @memset(&output, 0xaa);
            try budget(backend.io(), .fromMilliseconds(500), Reader(@TypeOf(session)).run, .{ session, mode, id, &output });
            try std.testing.expectEqualSlices(u8, &([_]u8{0xaa} ** 32), &output);
        }
    }
}

test "WebTransport stream read target admission preserves whole data while delivering STOP" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        for (std.enums.values(Mode)) |mode| {
            var pair: Pair = undefined;
            try pair.init(backend.io());
            defer pair.deinit();
            const session = if (role == .client) &pair.client else &pair.server;
            const peer = if (role == .client) &pair.server else &pair.client;
            const id = try session.openBidirectionalStream();
            try session.sendStream(id, "to peer", false);
            var output: [32]u8 = undefined;
            _ = try peer.readStreamIdWithTimeout(id, &output, .fromSeconds(1));
            try sendAndReceive(&pair, role, id, "whole reader");
            try std.testing.expect((try session.pollCompleteStream()) == null);
            try std.testing.expect(session.streams.get(id).?.receive_mode == .whole);
            const before = pair.connection(role).recvStreamStats(id).?.bytes_read;
            try peer.stopStream(id, 91);
            @memset(&output, 0xaa);
            try budget(backend.io(), .fromMilliseconds(500), Reader(@TypeOf(session)).run, .{ session, mode, id, &output });
            try std.testing.expectEqualSlices(u8, &([_]u8{0xaa} ** 32), &output);
            try std.testing.expectEqual(before, pair.connection(role).recvStreamStats(id).?.bytes_read);
            try std.testing.expect(session.streams.get(id).?.receive_mode == .whole);
            try peer.finishStream(id);
            const until: std.Io.Clock.Timestamp = .fromNow(backend.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
            while (pair.connection(role).recvStreamStats(id).?.final_size == null) try pair.receiveProgress(role, until);
            var stream = (try session.pollCompleteStream()).?;
            defer stream.deinit();
            try std.testing.expectEqualStrings("whole reader", stream.payload);
        }
    }
}

test "WebTransport stream read target admission preserves reverse bidirectional RESET" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        var pair: Pair = undefined;
        try pair.init(backend.io());
        defer pair.deinit();
        const session = if (role == .client) &pair.client else &pair.server;
        const peer = if (role == .client) &pair.server else &pair.client;
        const id = try session.openBidirectionalStream();
        try session.sendStream(id, "to peer", false);
        var output: [32]u8 = undefined;
        _ = try peer.readStreamIdWithTimeout(id, &output, .fromSeconds(1));
        try peer.resetStream(id, 73);
        @memset(&output, 0xaa);
        const reset = try session.readStreamIdWithTimeout(id, &output, .fromSeconds(1));
        try std.testing.expect(reset == .reset and reset.reset.stream_id == id);
        try std.testing.expectEqual(@as(?u32, 73), reset.reset.error_info.application_code);
        try std.testing.expectEqualSlices(u8, &([_]u8{0xaa} ** 32), &output);
        try session.sendStream(id, "still open", true);
        var received: usize = 0;
        const finish_deadline: std.Io.Clock.Timestamp = .fromNow(backend.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
        while (true) {
            const data = try peer.readStreamIdWithDeadline(id, output[received..], finish_deadline);
            try std.testing.expect(data == .data);
            received += data.data.bytes;
            if (data.data.fin) break;
        }
        try std.testing.expectEqualStrings("still open", output[0..received]);
    }
}
