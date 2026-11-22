//! Grant waits retain protocol input, deadlines, and application ownership.
const std = @import("std");
const control = @import("../../session_control.zig");
const progress = @import("../progress.zig");
const support = @import("support.zig");
const Pair = support.Pair;

test "WebTransport automatic grant pacing wait observes peer CLOSE" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        for ([_]bool{ false, true }) |bounded| {
            var pair: Pair = undefined;
            _ = try support.pending(&pair, threaded.io(), role);
            defer pair.deinit();
            const session = if (role == .client) &pair.client else &pair.server;
            const connection = pair.connection(role);
            var storage: [64]u8 = undefined;
            const close = try control.writeCloseInto(&storage, 91, "during grant");
            if (role == .client) try pair.server.h3.sendResponseBodyPaced(0, close, false) else try pair.client.h3.sendRequestBodyPaced(0, close, false);
            const previous_offset = connection.sendStreamStats(0).?.highest_sent_offset;
            const Receiver = struct {
                fn run(target: @TypeOf(session), timed: bool) !void {
                    var buffer: [16]u8 = undefined;
                    _ = if (timed) try target.receiveDatagramIntoWithTimeout(&buffer, .fromMilliseconds(100)) else try target.receiveDatagramInto(&buffer);
                }
            };
            try std.testing.expectError(error.InvalidSessionState, support.withinBudget(threaded.io(), Receiver.run, .{ session, bounded }));
            try std.testing.expect(session.control.pending_closed);
            try std.testing.expectEqual(@as(u64, 6), session.streams.flow.?.receive_limit.data);
            try std.testing.expectEqual(previous_offset, connection.sendStreamStats(0).?.highest_sent_offset);
            connection.pacer.enabled = false;
            const event = (try pair.poll(role)).?;
            try std.testing.expect(event == .closed);
            try std.testing.expectEqualStrings("during grant", event.closed.reason);
            try std.testing.expect(!connection.closing());
        }
    }
}

test "WebTransport automatic grant pacing wait delivers datagrams without another peer packet" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        for ([_]bool{ false, true }) |bounded| {
            for ([_]bool{ false, true }) |into| {
                var pair: Pair = undefined;
                _ = try support.pending(&pair, threaded.io(), role);
                defer pair.deinit();
                const session = if (role == .client) &pair.client else &pair.server;
                try pair.connection(if (role == .client) .server else .client).send(&.{.{ .datagram = .{ .data = "\x00ready" } }});
                const Receiver = struct {
                    fn run(target: @TypeOf(session), timed: bool, caller_buffer: bool) !void {
                        if (caller_buffer) {
                            var buffer: [16]u8 = undefined;
                            const data = if (timed) try target.receiveDatagramIntoWithTimeout(&buffer, .fromMilliseconds(100)) else try target.receiveDatagramInto(&buffer);
                            try std.testing.expectEqualStrings("ready", data);
                        } else {
                            var data = if (timed) try target.receiveDatagramWithTimeout(.fromMilliseconds(100)) else try target.receiveDatagram();
                            defer data.deinit(std.testing.allocator);
                            try std.testing.expectEqualStrings("ready", data.datagram.payload);
                        }
                    }
                };
                try support.withinBudget(threaded.io(), Receiver.run, .{ session, bounded, into });
                try std.testing.expectEqual(@as(?u64, 12), session.streams.flow.?.automaticDataGrant());
                try std.testing.expect(!session.control.state.closed and !pair.connection(role).closing());
            }
        }
    }
}

test "WebTransport automatic grant pacing wait preserves an exact received batch prefix" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        var pair: Pair = undefined;
        _ = try support.pending(&pair, threaded.io(), role);
        defer pair.deinit();
        const session = if (role == .client) &pair.client else &pair.server;
        try pair.connection(if (role == .client) .server else .client).send(&.{ .{ .datagram = .{ .data = "\x00first" } }, .{ .datagram = .{ .data = "\x00second" } } });
        const Receiver = struct {
            fn run(target: @TypeOf(session)) !void {
                var storage: [3][16]u8 = undefined;
                var outputs = [_][]u8{ &storage[0], &storage[1], &storage[2] };
                var received: usize = 99;
                try std.testing.expectError(error.Timeout, target.receiveDatagramsIntoWithTimeout(&outputs, &received, .fromMilliseconds(100)));
                try std.testing.expectEqual(@as(usize, 2), received);
                try std.testing.expectEqualStrings("first", outputs[0]);
                try std.testing.expectEqualStrings("second", outputs[1]);
            }
        };
        try support.withinBudget(threaded.io(), Receiver.run, .{session});
        try std.testing.expectEqual(@as(?u64, 12), session.streams.flow.?.automaticDataGrant());
    }
}

test "WebTransport automatic grant pacing wait resumes its grant at a timer without peer traffic" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        var pair: Pair = undefined;
        _ = try support.pending(&pair, threaded.io(), role);
        defer pair.deinit();
        const session = if (role == .client) &pair.client else &pair.server;
        support.pace(pair.connection(role), threaded.io(), 100000);
        const Maintenance = struct {
            fn run(target: @TypeOf(session)) !void {
                var context = progress.Context(@TypeOf(&target.h3)){ .control = &target.control, .h3 = &target.h3, .registry = &target.streams };
                const deadline: std.Io.Clock.Timestamp = .fromNow(target.h3.established.connection.endpoint.io, .{ .clock = .awake, .raw = .fromMilliseconds(100) });
                try context.progress().maintain(deadline);
            }
        };
        try support.withinBudget(threaded.io(), Maintenance.run, .{session});
        try std.testing.expectEqual(@as(u64, 12), session.streams.flow.?.receive_limit.data);
        try std.testing.expect(session.streams.flow.?.automaticDataGrant() == null);
        const deadline: std.Io.Clock.Timestamp = .fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
        const peer = if (role == .client) &pair.server else &pair.client;
        while (peer.streams.flow.?.send_limit.data < 12) {
            try pair.receiveProgress(if (role == .client) .server else .client, deadline);
            try std.testing.expect((try pair.poll(if (role == .client) .server else .client)) == null);
        }
        try std.testing.expectEqual(@as(u64, 12), peer.streams.flow.?.send_limit.data);
    }
}

test "WebTransport automatic grant pacing wait retries after unrelated peer traffic" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        var pair: Pair = undefined;
        _ = try support.pending(&pair, threaded.io(), role);
        defer pair.deinit();
        const session = if (role == .client) &pair.client else &pair.server;
        support.pace(pair.connection(role), threaded.io(), 5000);
        try pair.connection(if (role == .client) .server else .client).send(&.{.ping});
        const Peer = struct {
            fn run(value: *Pair) !void {
                const peer_role: support.Role = if (role == .client) .server else .client;
                const target = if (role == .client) &value.server else &value.client;
                const deadline: std.Io.Clock.Timestamp = .fromNow(value.connection(peer_role).endpoint.io, .{ .clock = .awake, .raw = .fromMilliseconds(500) });
                while (target.streams.flow.?.send_limit.data < 12) {
                    try value.receiveProgress(peer_role, deadline);
                    try std.testing.expect((try value.poll(peer_role)) == null);
                }
                try target.sendDatagram("grant arrived");
            }
        };
        var peer_work = try std.Io.concurrent(threaded.io(), Peer.run, .{&pair});
        defer peer_work.cancel(threaded.io()) catch {};
        const Receiver = struct {
            fn run(target: @TypeOf(session)) !void {
                var buffer: [16]u8 = undefined;
                const datagram = try target.receiveDatagramIntoWithTimeout(&buffer, .fromMilliseconds(100));
                try std.testing.expectEqualStrings("grant arrived", datagram);
            }
        };
        try support.withinBudget(threaded.io(), Receiver.run, .{session});
        try peer_work.await(threaded.io());
        try std.testing.expectEqual(@as(u64, 12), session.streams.flow.?.receive_limit.data);
        try std.testing.expect(session.streams.flow.?.automaticDataGrant() == null);
        try std.testing.expect(!session.control.state.closed);
    }
}

test "WebTransport control progress timeout forms reject zero budgets before I/O" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        const session = if (role == .client) &pair.client else &pair.server;
        const local_close_before = session.control.local_close_sent;
        try std.testing.expectError(
            error.Timeout,
            session.receiveControlProgressWithTimeout(.fromNanoseconds(0)),
        );
        try std.testing.expectError(
            error.Timeout,
            session.finishPolledSessionEventWithTimeout(
                .{ .closed = .{ .code = 0, .reason = "" } },
                .fromNanoseconds(0),
            ),
        );
        // A rejected budget must not start the terminal handshake or consume
        // the pending CLOSE event.
        try std.testing.expectEqual(
            local_close_before,
            session.control.local_close_sent,
        );
        try std.testing.expect(!session.control.pending_closed);
    }
}
