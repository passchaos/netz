const std = @import("std");
const quic = @import("../../../quic/mod.zig");
const runtime = @import("../../runtime.zig");
const support = @import("test_support/handshake_pair.zig");
const Pair = support.Pair;
const Role = support.Role;

fn opposite(role: Role) Role {
    return switch (role) {
        .client => .server,
        .server => .client,
    };
}

fn closeConnection(pair: *Pair, role: Role) !void {
    switch (role) {
        .client => try pair.client.closeConnection(0x5151, "connection done"),
        .server => try pair.server.closeConnection(0x5151, "connection done"),
    }
}

fn queueDatagram(pair: *Pair, receiver: Role) !void {
    switch (receiver) {
        .client => try pair.server.sendDatagram("queued"),
        .server => try pair.client.sendDatagram("queued"),
    }
    const deadline = std.Io.Clock.Timestamp.fromNow(pair.connection(receiver).endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    while (try switch (receiver) {
        .client => pair.client.h3.connect_datagrams.queuedCount(0),
        .server => pair.server.h3.connect_datagrams.queuedCount(0),
    } == 0) try pair.receiveProgress(receiver, deadline);
}

fn assertTerminated(pair: *Pair, role: Role) !void {
    const ctrl = pair.control(role);
    try std.testing.expect(ctrl.connection_terminated and ctrl.state.closed);
    try std.testing.expectError(error.ConnectionClosed, ctrl.ensureOpen());
    try std.testing.expectError(error.ConnectionClosed, pair.poll(role));
    var output = [_]u8{0xaa} ** 16;
    var outputs = [_][]u8{&output};
    var count: usize = 99;
    switch (role) {
        .client => {
            try std.testing.expectError(error.ConnectionClosed, pair.client.pollDatagram());
            try std.testing.expectError(error.ConnectionClosed, pair.client.pollStream(&output));
            try std.testing.expectError(error.ConnectionClosed, pair.client.pollCompleteStream());
            try std.testing.expectError(error.ConnectionClosed, pair.client.receiveDatagramsIntoWithTimeout(&outputs, &count, .fromSeconds(1)));
            try std.testing.expectEqual(@as(usize, 0), try pair.client.h3.connect_datagrams.queuedCount(0));
        },
        .server => {
            try std.testing.expectError(error.ConnectionClosed, pair.server.pollDatagram());
            try std.testing.expectError(error.ConnectionClosed, pair.server.pollStream(&output));
            try std.testing.expectError(error.ConnectionClosed, pair.server.pollCompleteStream());
            try std.testing.expectError(error.ConnectionClosed, pair.server.receiveDatagramsIntoWithTimeout(&outputs, &count, .fromSeconds(1)));
            try std.testing.expectEqual(@as(usize, 0), try pair.server.h3.connect_datagrams.queuedCount(0));
        },
    }
    try std.testing.expectEqual(@as(usize, 0), count);
    try std.testing.expectEqualSlices(u8, &([_]u8{0xaa} ** 16), &output);
}

test "WebTransport connection termination drops queued datagrams in both endpoint roles" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]Role{ .client, .server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        try queueDatagram(&pair, role);
        try closeConnection(&pair, opposite(role));
        const info = switch (role) {
            .client => try pair.client.receivePeerConnectionCloseWithTimeout(.fromSeconds(1)),
            .server => try pair.server.receivePeerConnectionCloseWithTimeout(.fromSeconds(1)),
        };
        try std.testing.expect(info == .application);
        try std.testing.expectEqual(@as(u64, 0x5151), info.application.error_code);
        try std.testing.expectEqualStrings("connection done", info.application.reason_phrase);
        try assertTerminated(&pair, role);
        try std.testing.expectError(error.ConnectionClosed, pair.receiveWithTimeout(role, .fromSeconds(1)));
    }
}

test "WebTransport local connection termination closes its application receive surfaces" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]Role{ .client, .server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        try queueDatagram(&pair, role);
        try closeConnection(&pair, role);
        try assertTerminated(&pair, role);
        try std.testing.expect(pair.connection(role).peerCloseInfo() == null);
    }
}

test "WebTransport stream read does not return data carried before QUIC close in one packet" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]Role{ .client, .server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        const id = try pair.openStream();
        var consumed: [16]u8 = undefined;
        _ = (try pair.server.pollStream(&consumed)) orelse return error.TestUnexpectedResult;
        const sender = pair.connection(opposite(role));
        const offset = if (sender.sendStreamStats(id)) |stats| stats.highest_sent_offset else 0;
        try sender.send(&.{
            .{ .stream = .{ .stream_id = id, .offset = offset, .data = "queued", .fin = true } },
            .{ .application_close = .{ .error_code = 0x5151, .reason_phrase = "connection done" } },
        });
        var output = [_]u8{0xaa} ** 16;
        switch (role) {
            .client => try std.testing.expectError(error.ConnectionClosed, pair.client.readStreamWithTimeout(&output, .fromSeconds(1))),
            .server => try std.testing.expectError(error.ConnectionClosed, pair.server.readStreamWithTimeout(&output, .fromSeconds(1))),
        }
        try std.testing.expectEqualSlices(u8, &([_]u8{0xaa} ** 16), &output);
        try assertTerminated(&pair, role);
        try std.testing.expect(pair.connection(role).peerCloseInfo() != null);
    }
}

test "WebTransport connection termination resolves an already-decoded CLOSE event" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]Role{ .client, .server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        var close_bytes: [64]u8 = undefined;
        const close = try @import("../session_control.zig").writeCloseInto(&close_bytes, 77, "decoded close");
        try pair.sendCapsules(role, close);
        const conn = pair.connection(role);
        conn.pacer = .initWithRateLimit(true, 1200, 1, 0);
        conn.pacer.budget = 0;
        conn.pacer.setLastSentTimeNs(0);
        try std.testing.expectError(error.Timeout, pair.receiveWithTimeout(role, .fromMilliseconds(5)));
        // A pending decoded event remains authoritative even if subsequent
        // transport failure makes its response FIN impossible to submit.
        const pending = switch (role) {
            .client => pair.client.pending_session_event,
            .server => pair.server.pending_session_event,
        };
        if (pending == null) {
            // Receive-credit pacing can precede event retention. Feed the
            // capsule and retain its actual decoded metadata explicitly.
            const event = (try pair.control(role).feedCapsulePayload(close)).event.?;
            switch (role) {
                .client => pair.client.pending_session_event = event,
                .server => pair.server.pending_session_event = event,
            }
        }
        conn.failClosedApplication(0x5151, "local failure");
        const event = try pair.receiveWithTimeout(role, .fromSeconds(1));
        try std.testing.expect(event == .closed);
        try std.testing.expectEqual(@as(u32, 77), event.closed.code);
        try std.testing.expectEqualStrings("decoded close", event.closed.reason);
        try assertTerminated(&pair, role);
    }
}

test "WebTransport connection termination during datagram receive leaves caller buffer untouched" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]Role{ .client, .server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        try pair.connection(opposite(role)).send(&.{
            .{ .application_close = .{ .error_code = 0x5151, .reason_phrase = "connection done" } },
            .{ .datagram = .{ .data = "\x00queued" } },
        });
        var output = [_]u8{0xaa} ** 16;
        switch (role) {
            .client => try std.testing.expectError(error.ConnectionClosed, pair.client.receiveDatagramIntoWithTimeout(&output, .fromSeconds(1))),
            .server => try std.testing.expectError(error.ConnectionClosed, pair.server.receiveDatagramIntoWithTimeout(&output, .fromSeconds(1))),
        }
        try std.testing.expectEqualSlices(u8, &([_]u8{0xaa} ** 16), &output);
        try assertTerminated(&pair, role);
    }
}

test "WebTransport completed datagram receive synchronizes a following QUIC close" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]Role{ .client, .server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        try pair.connection(opposite(role)).send(&.{
            .{ .datagram = .{ .data = "\x00queued" } },
            .{ .application_close = .{ .error_code = 0x5151, .reason_phrase = "connection done" } },
        });
        var output: [16]u8 = undefined;
        const received = switch (role) {
            .client => try pair.client.receiveDatagramIntoWithTimeout(&output, .fromSeconds(1)),
            .server => try pair.server.receiveDatagramIntoWithTimeout(&output, .fromSeconds(1)),
        };
        try std.testing.expectEqualStrings("queued", received);
        try assertTerminated(&pair, role);
    }
}

test "WebTransport connection termination retains pending malformed Capsule notification" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]Role{ .client, .server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        _ = try pair.openStream();
        try pair.sendCapsules(role, &.{ 0x68, 0x43, 3 });
        const conn = pair.connection(role);
        const ctrl = pair.control(role);
        try std.testing.expectError(error.InvalidCapsule, ctrl.pollOnce(conn));
        const streams = switch (role) {
            .client => &pair.client.streams,
            .server => &pair.server.streams,
        };
        try std.testing.expect(!try @import("rejection.zig").finishOnce(ctrl, conn, streams));
        try std.testing.expect(ctrl.capsule_error_rejected and !ctrl.capsule_error_reported);
        conn.failClosedApplication(0x5151, "local failure");
        const packet_number = conn.next_packet_number;
        try std.testing.expectError(error.InvalidCapsule, pair.receiveWithTimeout(role, .fromSeconds(1)));
        try std.testing.expect(ctrl.capsule_error_reported);
        try assertTerminated(&pair, role);
        try std.testing.expectEqual(packet_number, conn.next_packet_number);
    }
}

test "WebTransport whole-stream read stops before copying data from a QUIC close packet" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const id = try pair.openStream();
    var consumed: [16]u8 = undefined;
    _ = (try pair.server.pollStream(&consumed)) orelse return error.TestUnexpectedResult;
    try pair.connection(.server).send(&.{
        .{ .stream = .{ .stream_id = id, .data = "queued", .fin = true } },
        .{ .application_close = .{ .error_code = 0x5151, .reason_phrase = "connection done" } },
    });
    try std.testing.expectError(error.ConnectionClosed, pair.client.receiveStreamWithTimeout(.fromSeconds(1)));
    try assertTerminated(&pair, .client);
}
