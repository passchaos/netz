//! Pacing wakes retry application sends without spending the caller budget.
const std = @import("std");
const control = @import("../../session_control.zig");
const support = @import("../../flow/progress/support.zig");
const Pair = support.Pair;

test "WebTransport stream send pacing wake resumes sends and retains DRAIN" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        for ([_]bool{ false, true }) |drain| {
            var pair: Pair = undefined;
            try pair.init(threaded.io());
            defer pair.deinit();
            const session = if (role == .client) &pair.client else &pair.server;
            const peer = if (role == .client) &pair.server else &pair.client;
            const id = try session.openUnidirectionalStream();
            if (drain) {
                var storage: [16]u8 = undefined;
                const capsule = try control.writeDrainInto(&storage);
                if (role == .client) try pair.server.h3.sendResponseBodyPaced(0, capsule, false) else try pair.client.h3.sendRequestBodyPaced(0, capsule, false);
            }
            support.pace(pair.connection(role), threaded.io(), 100000);
            const Sender = struct {
                fn run(target: @TypeOf(session), stream_id: u62) !void {
                    var committed: usize = 99;
                    try target.sendStreamSlicesWithTimeout(stream_id, &.{ "pa", "ced" }, true, &committed, .fromMilliseconds(100));
                    try std.testing.expectEqual(@as(usize, 5), committed);
                }
            };
            try support.withinBudget(threaded.io(), Sender.run, .{ session, id });
            var stream = try peer.receiveStreamWithTimeout(.fromSeconds(1));
            defer stream.deinit();
            try std.testing.expectEqualStrings("paced", stream.payload);
            try std.testing.expect(session.streams.get(id).?.local_fin);
            if (drain) {
                try std.testing.expect((try pair.poll(role)).? == .draining);
                try std.testing.expect(session.control.state.draining and !session.control.state.closed);
            }
        }
    }
}

test "WebTransport stream send pacing timeout preserves a retryable association and FIN" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        const session = if (role == .client) &pair.client else &pair.server;
        const peer = if (role == .client) &pair.server else &pair.client;
        const id = try session.openUnidirectionalStream();
        support.pace(pair.connection(role), threaded.io(), 1);
        var committed: usize = 99;
        try std.testing.expectError(error.Timeout, session.sendStreamWithTimeout(id, "retry", true, &committed, .fromMilliseconds(10)));
        try std.testing.expectEqual(@as(usize, 0), committed);
        try std.testing.expect(!session.streams.get(id).?.prefix_sent and !session.streams.get(id).?.local_fin);
        pair.connection(role).pacer.enabled = false;
        try session.sendStreamWithTimeout(id, "retry", true, &committed, .fromMilliseconds(100));
        try std.testing.expectEqual(@as(usize, 5), committed);
        var stream = try peer.receiveStreamWithTimeout(.fromSeconds(1));
        defer stream.deinit();
        try std.testing.expectEqualStrings("retry", stream.payload);
        try std.testing.expect(session.streams.get(id).?.local_fin);
    }
}
