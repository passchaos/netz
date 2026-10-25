//! Cancellation retries preserve wire codes, reliable prefixes, and budgets.
const std = @import("std");
const webtransport = @import("../../../mod.zig");
const control = @import("../../session_control.zig");
const support = @import("../../flow/progress/support.zig");
const Pair = support.Pair;
const Operation = enum { reset, reliable, stop };

fn prepare(pair: *Pair, io: std.Io) !u62 {
    try pair.init(io);
    errdefer pair.deinit();
    const id = try pair.client.openBidirectionalStream();
    try pair.client.sendStream(id, "seed", false);
    var buffer: [16]u8 = undefined;
    _ = try pair.server.readStreamWithTimeout(&buffer, .fromSeconds(1));
    try pair.server.sendStream(id, "seed", false);
    _ = try pair.client.readStreamWithTimeout(&buffer, .fromSeconds(1));
    return id;
}

fn cancel(session: anytype, id: u62, operation: Operation, deadline: std.Io.Clock.Timestamp) !void {
    switch (operation) {
        .reset => try session.resetStreamWithDeadline(id, 71, deadline),
        .reliable => try session.resetStreamReliablyWithDeadline(id, 71, 2, deadline),
        .stop => try session.stopStreamWithDeadline(id, 72, deadline),
    }
}

test "WebTransport cancellation pacing wake submits mapped control after DRAIN" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        for (std.enums.values(Operation)) |operation| {
            var pair: Pair = undefined;
            const id = try prepare(&pair, threaded.io());
            defer pair.deinit();
            const session = if (role == .client) &pair.client else &pair.server;
            const peer_role: support.Role = if (role == .client) .server else .client;
            const peer = pair.connection(peer_role);
            var storage: [16]u8 = undefined;
            const drain = try control.writeDrainInto(&storage);
            if (role == .client) try pair.server.h3.sendResponseBodyPaced(0, drain, false) else try pair.client.h3.sendRequestBodyPaced(0, drain, false);
            support.pace(pair.connection(role), threaded.io(), 100000);
            const Canceller = struct {
                fn run(target: @TypeOf(session), stream_id: u62, kind: Operation) !void {
                    try cancel(target, stream_id, kind, .fromNow(target.h3.established.connection.endpoint.io, .{ .clock = .awake, .raw = .fromMilliseconds(100) }));
                }
            };
            try support.withinBudget(threaded.io(), Canceller.run, .{ session, id, operation });
            const deadline: std.Io.Clock.Timestamp = .fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
            if (operation == .stop) {
                while (peer.streamStopped(id) == null) {
                    var packet = try peer.receivePacketServicingTimersDeadline(deadline);
                    packet.deinit(std.testing.allocator);
                }
                try std.testing.expectEqual(webtransport.applicationErrorCodeToHttp3(72), peer.streamStopped(id).?.application_error_code);
                try std.testing.expectEqual(@as(?u32, 72), session.streams.get(id).?.stop_sent.?.application_code);
            } else {
                while ((if (peer.recvStreamStats(id)) |stats| stats.reset else null) == null) {
                    var packet = try peer.receivePacketServicingTimersDeadline(deadline);
                    packet.deinit(std.testing.allocator);
                }
                const reset = peer.recvStreamStats(id).?.reset.?;
                const prefix: u64 = if (role == .client) 3 else 0;
                try std.testing.expectEqual(webtransport.applicationErrorCodeToHttp3(71), reset.application_error_code);
                try std.testing.expectEqual(prefix + 4, reset.final_size);
                try std.testing.expectEqual(prefix + @as(u64, if (operation == .reliable) 2 else 0), reset.reliable_size);
                try std.testing.expectEqual(@as(?u32, 71), session.streams.get(id).?.send_reset.?.application_code);
            }
            pair.connection(role).pacer.enabled = false;
            try std.testing.expect((try pair.poll(role)).? == .draining);
            try std.testing.expect(session.control.state.draining and !session.control.state.closed);
            try session.sendDatagram("alive");
        }
    }
}

test "WebTransport cancellation timeout preserves state for retry" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        for (std.enums.values(Operation)) |operation| {
            var pair: Pair = undefined;
            const id = try prepare(&pair, threaded.io());
            defer pair.deinit();
            const session = if (role == .client) &pair.client else &pair.server;
            support.pace(pair.connection(role), threaded.io(), 1);
            try std.testing.expectError(error.Timeout, cancel(session, id, operation, .fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromMilliseconds(10) })));
            try std.testing.expect(session.streams.get(id).?.send_reset == null and session.streams.get(id).?.stop_sent == null);
            pair.connection(role).pacer.enabled = false;
            try cancel(session, id, operation, .fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromMilliseconds(100) }));
            if (operation == .stop) try std.testing.expect(session.streams.get(id).?.stop_sent != null) else try std.testing.expect(session.streams.get(id).?.send_reset != null);
            try std.testing.expect(!session.control.state.closed);
        }
    }
}
