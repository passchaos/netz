//! Session termination must interrupt cancellation while it waits for pacing.
const std = @import("std");
const control = @import("../../session_control.zig");
const support = @import("../../flow/progress/support.zig");
const Pair = support.Pair;
const Operation = enum { reset, reliable, stop };

test "WebTransport cancellation pacing wait propagates peer connection close" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        const session = if (role == .client) &pair.client else &pair.server;
        const id = try session.openUnidirectionalStream();
        try session.sendStream(id, "seed", false);
        try pair.connection(if (role == .client) .server else .client).closeApplication(91, "connection end");
        support.pace(pair.connection(role), threaded.io(), 1);
        const Canceller = struct {
            fn run(target: @TypeOf(session), stream_id: u62) !void {
                try target.resetStreamWithTimeout(stream_id, 71, .fromMilliseconds(100));
            }
        };
        try std.testing.expectError(error.ConnectionClosed, support.withinBudget(threaded.io(), Canceller.run, .{ session, id }));
        try std.testing.expect(session.control.connection_terminated);
        try std.testing.expect(session.streams.get(id).?.send_reset == null);
        const close = pair.connection(role).peerCloseInfo().?;
        try std.testing.expect(close == .application);
        try std.testing.expectEqual(@as(u64, 91), close.application.error_code);
        try std.testing.expectEqualStrings("connection end", close.application.reason_phrase);
    }
}

test "WebTransport cancellation pacing wait observes peer CLOSE before submission" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        inline for (std.enums.values(Operation)) |operation| {
            for ([_]bool{ false, true }) |bounded| {
                var pair: Pair = undefined;
                try pair.init(threaded.io());
                defer pair.deinit();
                const id = try pair.client.openBidirectionalStream();
                try pair.client.sendStream(id, "seed", false);
                var buffer: [16]u8 = undefined;
                _ = try pair.server.readStreamWithTimeout(&buffer, .fromSeconds(1));
                try pair.server.sendStream(id, "seed", false);
                _ = try pair.client.readStreamWithTimeout(&buffer, .fromSeconds(1));
                const session = if (role == .client) &pair.client else &pair.server;
                var storage: [64]u8 = undefined;
                const close = try control.writeCloseInto(&storage, 91, "during cancellation");
                if (role == .client) try pair.server.h3.sendResponseBodyPaced(0, close, false) else try pair.client.h3.sendRequestBodyPaced(0, close, false);
                support.pace(pair.connection(role), threaded.io(), if (bounded) 1 else 1000);
                const Canceller = struct {
                    fn run(target: @TypeOf(session), stream_id: u62, timed: bool) !void {
                        switch (operation) {
                            .reset => if (timed) try target.resetStreamWithTimeout(stream_id, 71, .fromMilliseconds(100)) else try target.resetStream(stream_id, 71),
                            .reliable => if (timed) try target.resetStreamReliablyWithTimeout(stream_id, 71, 2, .fromMilliseconds(100)) else try target.resetStreamReliably(stream_id, 71, 2),
                            .stop => if (timed) try target.stopStreamWithTimeout(stream_id, 72, .fromMilliseconds(100)) else try target.stopStream(stream_id, 72),
                        }
                    }
                };
                try std.testing.expectError(error.InvalidSessionState, support.withinBudget(threaded.io(), Canceller.run, .{ session, id, bounded }));
                try std.testing.expect(session.control.pending_closed);
                try std.testing.expect(session.streams.get(id).?.send_reset == null);
                try std.testing.expect(session.streams.get(id).?.stop_sent == null);
                pair.connection(role).pacer.enabled = false;
                const event = (try pair.poll(role)).?;
                try std.testing.expect(event == .closed);
                try std.testing.expectEqualStrings("during cancellation", event.closed.reason);
                try std.testing.expect(!pair.connection(role).closing());
            }
        }
    }
}
