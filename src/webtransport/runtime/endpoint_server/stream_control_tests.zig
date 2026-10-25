//! Shared server stream cancellation must observe its buffered CONNECT state.
const std = @import("std");
const runtime = @import("../../runtime.zig");
const control = @import("../session_control.zig");
const webtransport = @import("../../mod.zig");
const Fixture = @import("test_support.zig").Fixture;
const quic = @import("../../../quic/mod.zig");
const http3 = @import("../../../http3/mod.zig");
const ObservedSend = @import("../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;

const Operation = enum { reset, reliable, stop };

fn cancel(session: *runtime.EndpointAcceptedSession, id: u62, operation: Operation) !void {
    switch (operation) {
        .reset => try session.resetStream(id, 71),
        .reliable => try session.resetStreamReliably(id, 71, 0),
        .stop => try session.stopStream(id, 72),
    }
}

fn prepare(fixture: *Fixture, session: *runtime.EndpointAcceptedSession) !u62 {
    const id = try fixture.openPeerStream(session);
    fixture.connectionSession().established.connection.config.reliable_reset = .{ .local = true, .peer = true };
    try session.sendStream(id, "reply", false);
    return id;
}

fn buffer(fixture: *Fixture, session: *runtime.EndpointAcceptedSession, bytes: []const u8, fin: bool) !void {
    const connection = &fixture.connectionSession().established.connection;
    try fixture.client.sendRequestBodyPaced(session.session_id.value, bytes, fin);
    while ((connection.availableReceivedStream(session.session_id.value) orelse @as([]const u8, &.{})).len == 0 and
        connection.recvStreamStats(session.session_id.value).?.final_size == null) try fixture.routeTransport();
}

fn expectUncancelled(session: *runtime.EndpointAcceptedSession, id: u62) !void {
    try std.testing.expect(session.streams.get(id).?.send_reset == null);
    try std.testing.expect(session.streams.get(id).?.stop_sent == null);
}

test "WebTransport shared server cancellation preserves buffered CLOSE and sibling usability" {
    for (std.enums.values(Operation)) |operation| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const first = try fixture.addSession();
        const sibling = try fixture.addSession();
        const id = try prepare(&fixture, first);
        const connection = &fixture.connectionSession().established.connection;
        var bytes: [64]u8 = undefined;
        try buffer(&fixture, first, try control.writeCloseInto(&bytes, 91, "done"), false);
        const before = connection.next_packet_number;
        try std.testing.expectError(error.InvalidSessionState, cancel(first, id, operation));
        try std.testing.expectEqual(before, connection.next_packet_number);
        try expectUncancelled(first, id);
        var output: [16]u8 = undefined;
        const event = (try runtime.EndpointServer.testing.pollAcceptedSessionEntry(first, &output)).?;
        try std.testing.expect(event == .session and event.session == .closed);
        try std.testing.expectEqual(@as(u32, 91), event.session.closed.code);
        try std.testing.expectEqualStrings("done", event.session.closed.reason);
        for (0..16) |_| {
            const state = first.streams.get(id).?;
            if (state.send_reset != null and state.stop_sent != null) break;
            try std.testing.expect((try runtime.EndpointServer.testing.pollAcceptedSessionEntry(first, &output)) == null);
        }
        try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, first.streams.get(id).?.send_reset.?.http3_code);
        try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, first.streams.get(id).?.stop_sent.?.http3_code);
        try sibling.sendDatagram("still open");
        _ = try sibling.openBidirectionalStream();
        try std.testing.expect(!connection.closing() and !sibling.control.state.closed);
    }
}

test "WebTransport shared server cancellation preserves DRAIN and ordered CLOSE" {
    for (std.enums.values(Operation)) |operation| {
        for ([_]bool{ false, true }) |closing| {
            var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
            defer threaded.deinit();
            var fixture: Fixture = undefined;
            try fixture.init(threaded.io());
            defer fixture.deinit();
            const session = try fixture.addSession();
            const id = try prepare(&fixture, session);
            var bytes: [80]u8 = undefined;
            const drain_len = (try control.writeDrainInto(&bytes)).len;
            const len = if (closing) drain_len + (try control.writeCloseInto(bytes[drain_len..], 92, "after drain")).len else drain_len;
            try buffer(&fixture, session, bytes[0..len], false);
            if (closing) {
                try std.testing.expectError(error.InvalidSessionState, cancel(session, id, operation));
                try expectUncancelled(session, id);
            } else {
                try cancel(session, id, operation);
                try std.testing.expect(session.control.state.draining and !session.control.state.closed);
                if (operation == .stop) try std.testing.expectEqual(@as(?u32, 72), session.streams.get(id).?.stop_sent.?.application_code) else {
                    try std.testing.expectEqual(@as(?u32, 71), session.streams.get(id).?.send_reset.?.application_code);
                    const reset = fixture.connectionSession().established.connection.sendStreamStats(id).?.reset.?;
                    try std.testing.expectEqual(webtransport.applicationErrorCodeToHttp3(71), reset.application_error_code);
                    // The reverse direction of a peer-created bidirectional
                    // stream has no association prefix of its own.
                    if (operation == .reliable) try std.testing.expectEqual(@as(u64, 0), reset.reliable_size);
                }
            }
            var output: [16]u8 = undefined;
            const event = (try runtime.EndpointServer.testing.pollAcceptedSessionEntry(session, &output)).?;
            try std.testing.expect(event == .session and event.session == .draining);
            if (closing) {
                const closed = (try runtime.EndpointServer.testing.pollAcceptedSessionEntry(session, &output)).?;
                try std.testing.expect(closed == .session and closed.session == .closed);
                try std.testing.expectEqualStrings("after drain", closed.session.closed.reason);
                try std.testing.expectEqual(@as(u32, 92), closed.session.closed.code);
            }
        }
    }
}

test "WebTransport shared server cancellation leaves buffered CLOSE intact on allocation failure" {
    for (std.enums.values(Operation)) |operation| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const session = try fixture.addSession();
        const id = try prepare(&fixture, session);
        const reason = [_]u8{'r'} ** 200;
        var bytes: [240]u8 = undefined;
        try buffer(&fixture, session, try control.writeCloseInto(&bytes, 93, &reason), false);
        const connection = &fixture.connectionSession().established.connection;
        const previous = connection.recvStreamStats(session.session_id.value).?.bytes_read;
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        session.control.allocator = failing.allocator();
        try std.testing.expectError(error.OutOfMemory, cancel(session, id, operation));
        try std.testing.expectEqual(previous, connection.recvStreamStats(session.session_id.value).?.bytes_read);
        try std.testing.expect(!session.control.state.closed);
        try expectUncancelled(session, id);
        failing.fail_index = std.math.maxInt(usize);
        try std.testing.expectError(error.InvalidSessionState, cancel(session, id, operation));
        try expectUncancelled(session, id);
        var output: [16]u8 = undefined;
        const event = (try runtime.EndpointServer.testing.pollAcceptedSessionEntry(session, &output)).?;
        try std.testing.expect(event == .session and event.session == .closed);
        try std.testing.expectEqual(@as(u32, 93), event.session.closed.code);
        try std.testing.expectEqualStrings(&reason, event.session.closed.reason);
    }
}

test "WebTransport shared server cancellation retains retry state through backpressure and socket failure" {
    for (std.enums.values(Operation)) |operation| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const session = try fixture.addSession();
        const id = try prepare(&fixture, session);
        const connection = &fixture.connectionSession().established.connection;
        const window = connection.congestion.congestion_window;
        connection.congestion.congestion_window = 0;
        try std.testing.expectError(error.CongestionLimited, cancel(session, id, operation));
        try expectUncancelled(session, id);
        connection.congestion.congestion_window = window;
        const original_io = connection.endpoint.io;
        var observed = ObservedSend{ .delegate = original_io, .fail_on_call = 1 };
        var vtable = original_io.vtable.*;
        vtable.netSend = ObservedSend.netSend;
        connection.endpoint.io = .{ .userdata = &observed, .vtable = &vtable };
        {
            defer connection.endpoint.io = original_io;
            try std.testing.expectError(error.NetworkDown, cancel(session, id, operation));
        }
        try expectUncancelled(session, id);
        try cancel(session, id, operation);
        try std.testing.expect(!session.control.state.closed);
    }
}

test "WebTransport shared server cancellation rejects malformed Capsule without cancelling a sibling" {
    for (std.enums.values(Operation)) |operation| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const session = try fixture.addSession();
        const sibling = try fixture.addSession();
        const id = try prepare(&fixture, session);
        // WT_DRAIN_SESSION is known and requires an empty value.
        try buffer(&fixture, session, &.{ 0x80, 0x00, 0x78, 0xae, 0x01, 0x00 }, false);
        try std.testing.expectError(error.InvalidCapsule, cancel(session, id, operation));
        try expectUncancelled(session, id);
        const connection = &fixture.connectionSession().established.connection;
        try std.testing.expectEqual(http3.ApplicationErrorCode.message_error, connection.sendStreamStats(session.session_id.value).?.reset.?.application_error_code);
        try sibling.sendDatagram("live");
        try std.testing.expect(!connection.closing() and !sibling.control.state.closed);
    }
}
