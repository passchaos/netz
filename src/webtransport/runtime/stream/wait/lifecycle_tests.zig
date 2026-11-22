//! Send cancellation retains the committed prefix and the one receive owner.
const std = @import("std");
const quic = @import("../../../../quic/mod.zig");
const control = @import("../../session_control.zig");
const support = @import("../../flow/progress/support.zig");
const Pair = support.Pair;

test "WebTransport stream partial send retains its exact committed prefix at CLOSE" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        inline for (.{ false, true }) |slices| {
            var pair: Pair = undefined;
            try pair.init(threaded.io());
            defer pair.deinit();
            const session = if (role == .client) &pair.client else &pair.server;
            const connection = pair.connection(role);
            const id = try session.openUnidirectionalStream();
            try session.sendStream(id, "seed", false);
            const before_offset = session.streams.get(id).?.send_offset;
            const before_bytes = session.streams.get(id).?.bytes_sent;
            const payload = "x" ** 2400;
            const first = connection.currentSendDatagramSize() -| 128;
            const packet_len = try connection.packetLenForFramesAtOffset(0, &.{.{ .stream = .{ .stream_id = id, .offset = before_offset, .data = payload[0..first] } }});
            var storage: [64]u8 = undefined;
            const close = try control.writeCloseInto(&storage, 91, "after prefix");
            if (role == .client) try pair.server.h3.sendResponseBodyPaced(0, close, false) else try pair.client.h3.sendRequestBodyPaced(0, close, false);
            const previous = connection.congestion.congestion_window;
            defer connection.congestion.congestion_window = previous;
            connection.congestion.congestion_window = connection.congestion.bytes_in_flight + packet_len;
            var committed: usize = 99;
            const Sender = struct {
                fn run(target: @TypeOf(session), stream_id: u62, data: []const u8, count: *usize) !void {
                    if (slices) try target.sendStreamSlicesWithTimeout(stream_id, &.{data}, true, count, .fromMilliseconds(100)) else try target.sendStreamWithTimeout(stream_id, data, true, count, .fromMilliseconds(100));
                }
            };
            try std.testing.expectError(error.InvalidSessionState, support.withinBudget(threaded.io(), Sender.run, .{ session, id, payload, &committed }));
            try std.testing.expect(committed > 0 and committed < payload.len);
            if (!slices) try std.testing.expectEqual(first, committed);
            try std.testing.expectEqual(before_offset + committed, session.streams.get(id).?.send_offset);
            try std.testing.expectEqual(before_bytes + committed, session.streams.get(id).?.bytes_sent);
            try std.testing.expect(!session.streams.get(id).?.local_fin);
            connection.congestion.congestion_window = previous;
            // Independently correlate the reported application prefix with
            // actual protected STREAM bytes observed by the peer.
            const peer_role: support.Role = if (role == .client) .server else .client;
            const peer = pair.connection(peer_role);
            const deadline: std.Io.Clock.Timestamp = .fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
            while ((if (peer.recvStreamStats(id)) |stats| stats.highest_received_offset else 0) < before_offset + committed) {
                var packet = try peer.receivePacketServicingTimersDeadline(deadline);
                packet.deinit(std.testing.allocator);
            }
            try std.testing.expectEqual(before_offset + committed, peer.recvStreamStats(id).?.highest_received_offset);
            try std.testing.expectEqualStrings(payload[0..committed], peer.availableReceivedStream(id).?[@intCast(before_offset)..]);
            try std.testing.expect((try pair.poll(role)).? == .closed);
            try std.testing.expect(!connection.closing());
        }
    }
}

test "WebTransport stream send wait observes a queued CLOSE under outbound pacing" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        const session = if (role == .client) &pair.client else &pair.server;
        const connection = pair.connection(role);
        const peer = pair.connection(if (role == .client) .server else .client);
        const id = try session.openUnidirectionalStream();
        try session.sendStream(id, "seed", false);
        try peer.send(&.{.{ .datagram = .{ .data = "\x00retained" } }});
        var storage: [64]u8 = undefined;
        const close = try control.writeCloseInto(&storage, 91, "cursor close");
        if (role == .client) try pair.server.h3.sendResponseBodyPaced(0, close, false) else try pair.client.h3.sendRequestBodyPaced(0, close, false);
        const deadline: std.Io.Clock.Timestamp = .fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
        while (try session.h3.connect_datagrams.queuedCount(0) == 0) try pair.receiveProgress(role, deadline);
        // The CLOSE capsule may share the receive batch with the DATAGRAM or
        // still be queued in the socket; both interleavings are legitimate.
        // Either way the pacing-blocked send wait below must service the
        // receive owner instead of blocking on outbound ACK pacing.
        support.pace(connection, threaded.io(), 1);
        const Sender = struct {
            fn run(target: @TypeOf(session), stream_id: u62) !void {
                // The write's own timeout bounds the wait for the CLOSE to
                // reach its progress turn; the outer budget only guards
                // against a regression that ignores that deadline.
                _ = try target.writeStreamWithTimeout(stream_id, "late", .fromSeconds(1));
            }
        };
        try std.testing.expectError(error.InvalidSessionState, support.withinBudgetFor(threaded.io(), .fromSeconds(10), Sender.run, .{ session, id }));
        try std.testing.expect(session.control.pending_closed);
        connection.pacer.enabled = false;
        try std.testing.expect((try pair.poll(role)).? == .closed);
    }
}

test "WebTransport stream send pacing wait observes STOP without closing its session" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        const session = if (role == .client) &pair.client else &pair.server;
        const id = try session.openUnidirectionalStream();
        try session.sendStream(id, "seed", false);
        try pair.connection(if (role == .client) .server else .client).send(&.{.{ .stop_sending = .{ .stream_id = id, .application_error_code = 91 } }});
        support.pace(pair.connection(role), threaded.io(), 1);
        const Sender = struct {
            fn run(target: @TypeOf(session), stream_id: u62) !void {
                try target.finishStreamWithTimeout(stream_id, .fromMilliseconds(100));
            }
        };
        try std.testing.expectError(error.InvalidStreamState, support.withinBudget(threaded.io(), Sender.run, .{ session, id }));
        pair.connection(role).pacer.enabled = false;
        try session.sendDatagram("session alive");
        try std.testing.expect(!session.control.state.closed and !pair.connection(role).closing());
    }
}

test "WebTransport stream opening wait observes CLOSE without reserving an ID" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        for ([_]bool{ false, true }) |pacing| {
            var pair: Pair = undefined;
            try pair.init(threaded.io());
            defer pair.deinit();
            const session = if (role == .client) &pair.client else &pair.server;
            const connection = pair.connection(role);
            const expected = connection.nextLocalUnidirectionalStreamId();
            const old_limit = connection.peer_max_streams_uni;
            defer connection.peer_max_streams_uni = old_limit;
            connection.peer_max_streams_uni = expected / 4;
            var storage: [64]u8 = undefined;
            const close = try control.writeCloseInto(&storage, 91, "opening wait");
            if (role == .client) try pair.server.h3.sendResponseBodyPaced(0, close, false) else try pair.client.h3.sendRequestBodyPaced(0, close, false);
            if (pacing) support.pace(connection, threaded.io(), 1);
            const Opener = struct {
                fn run(target: @TypeOf(session)) !void {
                    _ = try target.openUnidirectionalStreamWithTimeout(.fromMilliseconds(100));
                }
            };
            try std.testing.expectError(error.InvalidSessionState, support.withinBudget(threaded.io(), Opener.run, .{session}));
            try std.testing.expectEqual(expected, connection.nextLocalUnidirectionalStreamId());
            try std.testing.expect(session.streams.get(@intCast(expected)) == null);
            connection.pacer.enabled = false;
            try std.testing.expect((try pair.poll(role)).? == .closed);
        }
    }
}
