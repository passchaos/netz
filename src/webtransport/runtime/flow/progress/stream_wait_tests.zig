//! Partial or sibling stream input must leave grant timers live.
const std = @import("std");
const support = @import("support.zig");
const Pair = support.Pair;

test "WebTransport automatic grant pacing wait completes a whole stream after its grant" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        var pair: Pair = undefined;
        _ = try support.pendingWithCredit(&pair, threaded.io(), role, 12);
        defer pair.deinit();
        const session = if (role == .client) &pair.client else &pair.server;
        const peer = if (role == .client) &pair.server else &pair.client;
        const id = try peer.openUnidirectionalStream();
        var committed: usize = 0;
        try peer.sendStreamWithTimeout(id, "tail", false, &committed, .fromMilliseconds(100));
        support.pace(pair.connection(role), threaded.io(), 5000);
        const Peer = struct {
            fn run(value: *Pair, stream_id: u62) !void {
                const peer_role: support.Role = if (role == .client) .server else .client;
                const target = if (role == .client) &value.server else &value.client;
                const deadline: std.Io.Clock.Timestamp = .fromNow(value.connection(peer_role).endpoint.io, .{ .clock = .awake, .raw = .fromMilliseconds(500) });
                while (target.streams.flow.?.send_limit.data < 18) {
                    try value.receiveProgress(peer_role, deadline);
                    try std.testing.expect((try value.poll(peer_role)) == null);
                }
                try target.finishStream(stream_id);
            }
        };
        var peer_work = try std.Io.concurrent(threaded.io(), Peer.run, .{ &pair, id });
        defer peer_work.cancel(threaded.io()) catch {};
        const Receiver = struct {
            fn run(target: @TypeOf(session)) !void {
                var stream = try target.receiveStreamWithTimeout(.fromMilliseconds(200));
                defer stream.deinit();
                try std.testing.expectEqualStrings("tail", stream.payload);
            }
        };
        try support.withinBudget(threaded.io(), Receiver.run, .{session});
        try peer_work.await(threaded.io());
        try std.testing.expectEqual(@as(u64, 18), session.streams.flow.?.receive_limit.data);
    }
}

test "WebTransport automatic grant pacing wait keeps targeted reads live beside a ready sibling" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        var pair: Pair = undefined;
        _ = try support.pendingWithCredit(&pair, threaded.io(), role, 12);
        defer pair.deinit();
        const session = if (role == .client) &pair.client else &pair.server;
        const peer = if (role == .client) &pair.server else &pair.client;
        const sibling = try peer.openUnidirectionalStream();
        const id = try peer.openUnidirectionalStream();
        try peer.sendStream(sibling, "held", false);
        support.pace(pair.connection(role), threaded.io(), 5000);
        const Peer = struct {
            fn run(value: *Pair, stream_id: u62) !void {
                const peer_role: support.Role = if (role == .client) .server else .client;
                const target = if (role == .client) &value.server else &value.client;
                const deadline: std.Io.Clock.Timestamp = .fromNow(value.connection(peer_role).endpoint.io, .{ .clock = .awake, .raw = .fromMilliseconds(500) });
                while (target.streams.flow.?.send_limit.data < 18) {
                    try value.receiveProgress(peer_role, deadline);
                    try std.testing.expect((try value.poll(peer_role)) == null);
                }
                var committed: usize = 0;
                try target.sendStreamWithTimeout(stream_id, "chosen", false, &committed, .fromMilliseconds(100));
            }
        };
        var peer_work = try std.Io.concurrent(threaded.io(), Peer.run, .{ &pair, id });
        defer peer_work.cancel(threaded.io()) catch {};
        const Receiver = struct {
            fn run(target: @TypeOf(session), stream_id: u62) !void {
                var storage: [16]u8 = undefined;
                const event = try target.readStreamIdWithTimeout(stream_id, &storage, .fromMilliseconds(200));
                try std.testing.expect(event == .data and event.data.bytes == 6);
                try std.testing.expectEqualStrings("chosen", storage[0..event.data.bytes]);
            }
        };
        try support.withinBudget(threaded.io(), Receiver.run, .{ session, id });
        try peer_work.await(threaded.io());
        var storage: [16]u8 = undefined;
        const held = try session.readStreamIdWithTimeout(sibling, &storage, .fromMilliseconds(100));
        try std.testing.expect(held == .data and held.data.bytes == 4);
        try std.testing.expectEqualStrings("held", storage[0..held.data.bytes]);
        try std.testing.expect(!session.control.state.closed);
    }
}
