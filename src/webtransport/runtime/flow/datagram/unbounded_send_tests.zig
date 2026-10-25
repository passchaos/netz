//! Ordinary sends retain the same CLOSE boundary as bounded sends.
const std = @import("std");
const control = @import("../../session_control.zig");
const quic = @import("../../../../quic/mod.zig");
const Pair = @import("../../session_control/test_support/handshake_pair.zig").Pair;
const Fixture = @import("../../endpoint_client/test_support.zig").Fixture;
const client_mod = @import("../../endpoint_client.zig");
const http3 = @import("../../../../http3/mod.zig");

fn sendWithinBudget(session: anytype, io: std.Io, batch: bool, payloads: []const []const u8, committed: *usize) !void {
    const Sender = struct {
        fn run(target: @TypeOf(session), many: bool, values: []const []const u8, count: *usize) !void {
            if (many) {
                try target.sendDatagrams(values, count);
            } else try target.sendDatagram(values[0]);
        }
    };
    const Wake = union(enum) { done: anyerror!void, expired: std.Io.Cancelable!void };
    var buffer: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &buffer);
    defer select.cancelDiscard();
    try select.concurrent(.done, Sender.run, .{ session, batch, payloads, committed });
    try select.concurrent(.expired, std.Io.sleep, .{ io, std.Io.Duration.fromSeconds(1), std.Io.Clock.awake });
    switch (try select.await()) {
        .done => |result| try result,
        .expired => |result| {
            try result;
            return error.Timeout;
        },
    }
}

test "WebTransport ordinary DATAGRAM pacing wait observes peer CLOSE before send" {
    try exercise(false, true);
}

test "WebTransport ordinary DATAGRAM batch congestion wait observes peer CLOSE" {
    try exercise(true, false);
}

test "WebTransport ordinary DATAGRAM batch pacing wait observes peer CLOSE" {
    try exercise(true, true);
}

fn exercise(batch: bool, pacing: bool) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    inline for (.{ .client, .server }) |role| {
        var pair: Pair = undefined;
        try pair.init(io);
        defer pair.deinit();
        var storage: [64]u8 = undefined;
        const capsule = try control.writeCloseInto(&storage, 91, "ordinary wait");
        // Queue only UDP input, so the initial buffered preflight remains open.
        if (role == .client) try pair.server.h3.sendResponseBodyPaced(0, capsule, false) else try pair.client.h3.sendRequestBodyPaced(0, capsule, false);
        const session = if (role == .client) &pair.client else &pair.server;
        const connection = pair.connection(role);
        const previous = connection.congestion.congestion_window;
        defer connection.congestion.congestion_window = previous;
        if (!pacing) {
            connection.congestion.congestion_window = 0;
        } else {
            connection.pacer.enabled = true;
            connection.setMaxPacingRateBytesPerSecond(1000);
            quic.one_rtt.testing.exhaustPacingAt(connection, @intCast(std.Io.Clock.awake.now(io).nanoseconds));
        }
        const sent = connection.datagramsSent();
        var committed: usize = 99;
        try std.testing.expectError(error.InvalidSessionState, sendWithinBudget(session, io, batch, &.{ "late", "also late" }, &committed));
        try std.testing.expectEqual(sent, connection.datagramsSent());
        if (batch) try std.testing.expectEqual(@as(usize, 0), committed);
        connection.congestion.congestion_window = previous;
        connection.pacer.enabled = false;
        try std.testing.expect(session.control.pending_closed);
        const event = (try pair.poll(role)).?;
        try std.testing.expect(event == .closed);
        try std.testing.expectEqualStrings("ordinary wait", event.closed.reason);
        try std.testing.expect(!connection.closing());
    }
}

test "WebTransport ordinary DATAGRAM retains congestion backpressure without reading" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    inline for (.{ .client, .server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        const session = if (role == .client) &pair.client else &pair.server;
        const connection = pair.connection(role);
        var storage: [64]u8 = undefined;
        const capsule = try control.writeCloseInto(&storage, 91, "queued close");
        if (role == .client) try pair.server.h3.sendResponseBodyPaced(0, capsule, false) else try pair.client.h3.sendRequestBodyPaced(0, capsule, false);
        const previous = connection.congestion.congestion_window;
        connection.congestion.congestion_window = 0;
        defer connection.congestion.congestion_window = previous;
        const before = connection.datagramsSent();
        try std.testing.expectError(error.CongestionLimited, session.sendDatagram("retry later"));
        try std.testing.expectEqual(before, connection.datagramsSent());
        try std.testing.expect(!session.control.state.closed);
        connection.congestion.congestion_window = previous;
        if (role == .client) try pair.client.h3.receiveDetachedResponseProgressWithTimeout(0, .fromSeconds(1)) else try pair.server.h3.receiveDetachedRequestProgressWithTimeout(0, .fromSeconds(1));
        const event = (try pair.poll(role)).?;
        try std.testing.expect(event == .closed);
        try std.testing.expectEqualStrings("queued close", event.closed.reason);
    }
}

test "WebTransport ordinary DATAGRAM pacing timer resumes with no peer traffic" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ .client, .server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        const session = if (role == .client) &pair.client else &pair.server;
        const receiver = if (role == .client) &pair.server else &pair.client;
        const connection = pair.connection(role);
        connection.pacer.enabled = true;
        connection.setMaxPacingRateBytesPerSecond(5000);
        quic.one_rtt.testing.exhaustPacingAt(connection, @intCast(std.Io.Clock.awake.now(threaded.io()).nanoseconds));
        var committed: usize = 0;
        try sendWithinBudget(session, threaded.io(), false, &.{"paced"}, &committed);
        var datagram = try receiver.receiveDatagramWithTimeout(.fromSeconds(1));
        defer datagram.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("paced", datagram.datagram.payload);
    }
}

test "WebTransport ordinary DATAGRAM batch preserves its committed prefix at CLOSE" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ .client, .server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        const session = if (role == .client) &pair.client else &pair.server;
        const connection = pair.connection(role);
        var storage: [64]u8 = undefined;
        const capsule = try control.writeCloseInto(&storage, 91, "after prefix");
        if (role == .client) try pair.server.h3.sendResponseBodyPaced(0, capsule, false) else try pair.client.h3.sendRequestBodyPaced(0, capsule, false);
        const first = "a" ** 800;
        const packet_size = try connection.packetLenForFramesAtOffset(0, &.{.{ .datagram = .{ .data = "\x00" ++ first, .length_present = true } }});
        const previous = connection.congestion.congestion_window;
        defer connection.congestion.congestion_window = previous;
        connection.congestion.congestion_window = connection.congestion.bytes_in_flight + packet_size;
        const sent = connection.datagramsSent();
        var committed: usize = 99;
        try std.testing.expectError(error.InvalidSessionState, sendWithinBudget(session, threaded.io(), true, &.{ first, "b" ** 800, "c" ** 800 }, &committed));
        try std.testing.expectEqual(@as(usize, 1), committed);
        try std.testing.expectEqual(sent + 1, connection.datagramsSent());
        connection.congestion.congestion_window = previous;
        const event = (try pair.poll(role)).?;
        try std.testing.expect(event == .closed);
        try std.testing.expectEqualStrings("after prefix", event.closed.reason);
    }
}

test "WebTransport ordinary shared DATAGRAM wait preserves sibling events" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const sibling = try fixture.addSession();
    try fixture.queueDatagram(sibling, "still readable");
    const connection = &fixture.client.h3.established.connection;
    var storage: [64]u8 = undefined;
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try (http3.Frame{ .frame_type = http3.FrameType.data, .payload = try control.writeCloseInto(&storage, 91, "shared ordinary"), .consumed = 0 }).write(&bytes, std.testing.allocator);
    try fixture.peer.send(&.{.{ .stream = .{ .stream_id = session.session_id.value, .offset = connection.recvStreamStats(session.session_id.value).?.highest_received_offset, .data = bytes.items } }});
    connection.pacer.enabled = true;
    connection.setMaxPacingRateBytesPerSecond(1000);
    quic.one_rtt.testing.exhaustPacingAt(connection, @intCast(std.Io.Clock.awake.now(threaded.io()).nanoseconds));
    const Sender = struct {
        session: *client_mod.Session,
        client: *client_mod.Client,

        fn sendDatagram(self: *@This(), payload: []const u8) !void {
            try self.session.sendDatagram(self.client, payload);
        }

        fn sendDatagrams(_: *@This(), _: []const []const u8, _: *usize) !void {
            return error.TestUnexpectedResult;
        }
    };
    var sender = Sender{ .session = session, .client = &fixture.client };
    var committed: usize = 99;
    try std.testing.expectError(error.InvalidSessionState, sendWithinBudget(&sender, threaded.io(), false, &.{"late"}, &committed));
    connection.pacer.enabled = false;
    var output: [32]u8 = undefined;
    const event = (try fixture.client.poll(session.session_id, &output)).?;
    try std.testing.expect(event == .session and event.session == .closed);
    try std.testing.expectEqualStrings("shared ordinary", event.session.closed.reason);
    var ready = (try fixture.client.poll(sibling.session_id, &output)).?;
    defer ready.deinit(std.testing.allocator);
    try std.testing.expect(ready == .datagram);
    try std.testing.expectEqualStrings("still readable", ready.datagram.payload);
    try sibling.sendDatagram(&fixture.client, "still writable");
    try std.testing.expect(!connection.closing() and !sibling.control.state.closed);
}
