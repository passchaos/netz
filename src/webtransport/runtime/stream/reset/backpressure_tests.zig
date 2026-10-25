//! Ordinary cancellation leaves socket input to its caller on congestion.
const std = @import("std");
const control = @import("../../session_control.zig");
const support = @import("../../flow/progress/support.zig");
const Pair = support.Pair;

test "WebTransport ordinary cancellation exposes congestion without consuming peer CLOSE" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        inline for (.{ false, true }) |reliable| {
            var pair: Pair = undefined;
            try pair.init(threaded.io());
            defer pair.deinit();
            const session = if (role == .client) &pair.client else &pair.server;
            const id = try session.openUnidirectionalStream();
            try session.sendStream(id, "seed", false);
            var storage: [64]u8 = undefined;
            const close = try control.writeCloseInto(&storage, 91, "input retained");
            if (role == .client) try pair.server.h3.sendResponseBodyPaced(0, close, false) else try pair.client.h3.sendRequestBodyPaced(0, close, false);
            const connection = pair.connection(role);
            const previous = connection.congestion.congestion_window;
            defer connection.congestion.congestion_window = previous;
            connection.congestion.congestion_window = 0;
            const result = if (reliable) session.resetStreamReliably(id, 71, 2) else session.resetStream(id, 71);
            try std.testing.expectError(error.CongestionLimited, result);
            try std.testing.expect(!session.control.state.closed);
            try std.testing.expect(session.streams.get(id).?.send_reset == null);
            connection.congestion.congestion_window = previous;
            const deadline: std.Io.Clock.Timestamp = .fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
            try pair.receiveProgress(role, deadline);
            const event = (try pair.poll(role)).?;
            try std.testing.expect(event == .closed);
            try std.testing.expectEqualStrings("input retained", event.closed.reason);
        }
    }
}

test "WebTransport cancellation on an unwritten stream preserves the reliable association prefix" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        inline for (.{ false, true }) |reliable| {
            var pair: Pair = undefined;
            try pair.init(threaded.io());
            defer pair.deinit();
            const session = if (role == .client) &pair.client else &pair.server;
            const id = try session.openUnidirectionalStream();
            support.pace(pair.connection(role), threaded.io(), 100000);
            const Canceller = struct {
                fn run(target: @TypeOf(session), stream_id: u62) !void {
                    if (reliable) try target.resetStreamReliablyWithTimeout(stream_id, 71, 0, .fromMilliseconds(100)) else try target.resetStreamWithTimeout(stream_id, 71, .fromMilliseconds(100));
                }
            };
            try support.withinBudget(threaded.io(), Canceller.run, .{ session, id });
            try std.testing.expect(session.streams.get(id).?.prefix_sent);
            try std.testing.expectEqual(@as(u64, 0), session.streams.get(id).?.bytes_sent);
            const peer = pair.connection(if (role == .client) .server else .client);
            const deadline: std.Io.Clock.Timestamp = .fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
            while ((if (peer.recvStreamStats(id)) |stats| stats.reset else null) == null) {
                var packet = try peer.receivePacketServicingTimersDeadline(deadline);
                packet.deinit(std.testing.allocator);
            }
            const reset = peer.recvStreamStats(id).?.reset.?;
            try std.testing.expectEqual(@as(u64, 3), reset.final_size);
            try std.testing.expectEqual(@as(u64, 3), reset.reliable_size);
            try std.testing.expectEqualStrings("\x40\x54\x00", peer.retainedReceivedStream(id).?);
            try std.testing.expect(!session.control.state.closed);
        }
    }
}
