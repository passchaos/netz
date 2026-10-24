const std = @import("std");
const webtransport = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const Fixture = @import("test_support.zig").Fixture;
const Session = @import("../endpoint_client.zig").Session;
const ObservedSend = @import("../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;

const Operation = enum { reset, reliable, stop };

fn cancel(fixture: *Fixture, session: *Session, id: u62, operation: Operation, absolute: bool, timeout: std.Io.Duration) !void {
    const deadline = std.Io.Clock.Timestamp.fromNow(fixture.client.h3.established.connection.endpoint.io, .{ .raw = timeout, .clock = .awake });
    switch (operation) {
        .reset => if (absolute) try session.resetStreamWithDeadline(&fixture.client, id, 71, deadline) else try session.resetStreamWithTimeout(&fixture.client, id, 71, timeout),
        .reliable => if (absolute) try session.resetStreamReliablyWithDeadline(&fixture.client, id, 71, 3, deadline) else try session.resetStreamReliablyWithTimeout(&fixture.client, id, 71, 3, timeout),
        .stop => if (absolute) try session.stopStreamWithDeadline(&fixture.client, id, 72, deadline) else try session.stopStreamWithTimeout(&fixture.client, id, 72, timeout),
    }
}

fn prepare(fixture: *Fixture, session: *Session, operation: Operation) !u62 {
    const connection = &fixture.client.h3.established.connection;
    connection.config.reliable_reset = .{ .local = true, .peer = true };
    fixture.peer.config.reliable_reset = .{ .local = true, .peer = true };
    if (operation == .stop) {
        const id: u62 = 3;
        try quic.one_rtt.testing.applyReceivedFrames(connection, 91, &.{.{ .stream = .{ .stream_id = id, .data = "body" } }}, null, .not_ect);
        _ = try session.streams.registerPeer(id, .unidirectional);
        return id;
    }
    const id = try session.openBidirectionalStream(&fixture.client);
    try session.sendStream(&fixture.client, id, "abcdef", false);
    return id;
}

test "WebTransport shared client cancellation exposes deadlines and reliable application prefix" {
    for (std.enums.values(Operation)) |operation| {
        for ([_]bool{ false, true }) |absolute| {
            var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
            defer threaded.deinit();
            var fixture: Fixture = undefined;
            try fixture.init(threaded.io());
            defer fixture.deinit();
            const first = try fixture.addSession();
            const second = try fixture.addSession();
            const target = try prepare(&fixture, first, operation);
            const sibling = try second.openBidirectionalStream(&fixture.client);
            try second.sendStream(&fixture.client, sibling, "sibling", false);
            const before = second.streams.flow.?.sent.data;
            try std.testing.expectError(error.UnknownStream, cancel(&fixture, second, target, operation, absolute, .fromSeconds(1)));
            try cancel(&fixture, first, target, operation, absolute, .fromSeconds(1));
            const connection = &fixture.client.h3.established.connection;
            if (operation == .stop) {
                try std.testing.expectEqual(@as(?u32, 72), first.streams.get(target).?.stop_sent.?.application_code);
                try std.testing.expectEqual(webtransport.applicationErrorCodeToHttp3(72), connection.recvStreamStats(target).?.stop_sending_sent.?.application_error_code);
            } else {
                const reset = connection.sendStreamStats(target).?.reset.?;
                try std.testing.expectEqual(webtransport.applicationErrorCodeToHttp3(71), reset.application_error_code);
                try std.testing.expectEqual(@as(u64, 9), reset.final_size);
                try std.testing.expectEqual(@as(u64, if (operation == .reliable) 6 else 3), reset.reliable_size);
                try std.testing.expectEqual(@as(u64, 6), first.streams.flow.?.sent.data);
                // Independently receive encrypted UDP frames at the peer.
                while ((if (fixture.peer.recvStreamStats(target)) |stats| stats.reset else null) == null) {
                    var packet = try fixture.peer.receivePacketTimeout(.{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } });
                    packet.deinit(std.testing.allocator);
                }
                const received = fixture.peer.recvStreamStats(target).?.reset.?;
                try std.testing.expectEqual(reset, received);
                try std.testing.expectEqualStrings("\x40\x41\x00abcdef", fixture.peer.retainedReceivedStream(target).?);
            }
            try std.testing.expect(second.streams.get(sibling).?.send_reset == null);
            try std.testing.expectEqual(before, second.streams.flow.?.sent.data);
            try second.sendStream(&fixture.client, sibling, "live", true);
            try std.testing.expect(!first.control.state.closed and !second.control.state.closed and !connection.closing());
        }
    }
}

test "WebTransport shared client cancellation timeout and socket failure preserve retry state" {
    for (std.enums.values(Operation)) |operation| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const session = try fixture.addSession();
        const id = try prepare(&fixture, session, operation);
        const connection = &fixture.client.h3.established.connection;
        const window = connection.congestion.congestion_window;
        connection.congestion.congestion_window = 0;
        try std.testing.expectError(error.Timeout, cancel(&fixture, session, id, operation, true, .fromMilliseconds(5)));
        connection.congestion.congestion_window = window;
        try std.testing.expect(session.streams.get(id).?.send_reset == null);
        try std.testing.expect(session.streams.get(id).?.stop_sent == null);
        const original_io = connection.endpoint.io;
        var observed = ObservedSend{ .delegate = original_io, .fail_on_call = 1 };
        var vtable = original_io.vtable.*;
        vtable.netSend = ObservedSend.netSend;
        connection.endpoint.io = .{ .userdata = &observed, .vtable = &vtable };
        {
            defer connection.endpoint.io = original_io;
            try std.testing.expectError(error.NetworkDown, cancel(&fixture, session, id, operation, false, .fromSeconds(1)));
        }
        try std.testing.expect(session.streams.get(id).?.send_reset == null);
        try std.testing.expect(session.streams.get(id).?.stop_sent == null);
        try cancel(&fixture, session, id, operation, false, .fromSeconds(1));
    }
}

test "WebTransport shared client reliable reset validates negotiation bounds and receive ownership" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const id = try prepare(&fixture, session, .reliable);
    const connection = &fixture.client.h3.established.connection;
    try std.testing.expectError(error.InvalidStreamState, session.resetStreamReliably(&fixture.client, id, 71, 7));
    connection.config.reliable_reset.peer = false;
    try std.testing.expectError(error.InvalidFrame, session.resetStreamReliably(&fixture.client, id, 71, 3));
    connection.config.reliable_reset.peer = true;
    fixture.client.h3.callback_reader_active = true;
    try std.testing.expectError(error.ConcurrentRead, cancel(&fixture, session, id, .reliable, true, .fromSeconds(1)));
    fixture.client.h3.callback_reader_active = false;
    try std.testing.expectError(error.Timeout, cancel(&fixture, session, id, .reliable, false, .zero));
    try std.testing.expect(connection.sendStreamStats(id).?.reset == null);
    try session.resetStreamReliably(&fixture.client, id, 71, 3);
    try std.testing.expectEqual(@as(u64, 6), connection.sendStreamStats(id).?.reset.?.reliable_size);
}

test "WebTransport shared client reliable reset associates unwritten uni streams with zero data credit" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.initWithSettings(threaded.io(), try webtransport.settingsWithInitialFlowLimits(.{}, 2, .{ .data = 0, .bidi = 4, .uni = 4 }));
    defer fixture.deinit();
    const session = try fixture.addSession();
    const connection = &fixture.client.h3.established.connection;
    connection.config.reliable_reset = .{ .local = true, .peer = true };
    fixture.peer.config.reliable_reset = .{ .local = true, .peer = true };
    const id = try session.openUnidirectionalStream(&fixture.client);
    try session.resetStreamReliablyWithTimeout(&fixture.client, id, 73, 0, .fromSeconds(1));
    const reset = connection.sendStreamStats(id).?.reset.?;
    try std.testing.expectEqual(@as(u64, 3), reset.final_size);
    try std.testing.expectEqual(@as(u64, 3), reset.reliable_size);
    try std.testing.expectEqual(@as(u64, 0), session.streams.flow.?.sent.data);
    while ((if (fixture.peer.recvStreamStats(id)) |stats| stats.reset else null) == null) {
        var packet = try fixture.peer.receivePacketTimeout(.{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } });
        packet.deinit(std.testing.allocator);
    }
    try std.testing.expectEqualStrings("\x40\x54\x00", fixture.peer.retainedReceivedStream(id).?);
    try std.testing.expectEqual(reset, fixture.peer.recvStreamStats(id).?.reset.?);
}

test "WebTransport shared client cancellation validates owner and rejects closed sessions before I/O" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const id = try prepare(&fixture, session, .reliable);
    const connection = &fixture.client.h3.established.connection;
    var clone = session.*;
    try std.testing.expectError(error.InvalidSessionState, clone.resetStreamReliably(&fixture.client, id, 71, 3));
    try std.testing.expectError(error.InvalidSessionState, cancel(&fixture, &clone, id, .reset, false, .fromSeconds(1)));
    session.control.state.close(0);
    try std.testing.expectError(error.InvalidSessionState, cancel(&fixture, session, id, .reset, true, .fromSeconds(1)));
    try std.testing.expectError(error.InvalidSessionState, session.resetStreamReliably(&fixture.client, id, 71, 3));
    try std.testing.expect(connection.sendStreamStats(id).?.reset == null);
}

test "WebTransport shared client cancellation progress preserves sibling DATAGRAM while congested" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const first = try fixture.addSession();
    const second = try fixture.addSession();
    const id = try prepare(&fixture, first, .reliable);
    fixture.peer.config.peer_max_datagram_frame_size = 1200;
    try fixture.peer.send(&.{.{ .datagram = .{ .data = "\x01sibling" } }});
    const connection = &fixture.client.h3.established.connection;
    const window = connection.congestion.congestion_window;
    connection.congestion.congestion_window = 0;
    try std.testing.expectError(error.Timeout, first.resetStreamReliablyWithTimeout(&fixture.client, id, 71, 3, .fromMilliseconds(10)));
    connection.congestion.congestion_window = window;
    try std.testing.expect(first.streams.get(id).?.send_reset == null);
    var event = (try fixture.poll(second)) orelse return error.TestUnexpectedResult;
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .datagram);
    try std.testing.expectEqualStrings("sibling", event.datagram.payload);
    try first.resetStreamReliablyWithTimeout(&fixture.client, id, 71, 3, .fromSeconds(1));
}
