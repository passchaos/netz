//! Received CONNECT and connection termination precede application cancel.
const std = @import("std");
const runtime = @import("../../runtime.zig");
const webtransport = @import("../../mod.zig");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const Fixture = @import("test_support.zig").Fixture;

const Operation = enum { reset, reliable, stop };
const Termination = enum { fin, reset, stop, connection };

fn cancel(session: *runtime.EndpointAcceptedSession, id: u62, operation: Operation) !void {
    switch (operation) {
        .reset => try session.resetStream(id, 71),
        .reliable => try session.resetStreamReliably(id, 71, 0),
        .stop => try session.stopStream(id, 72),
    }
}

test "WebTransport shared server cancellation observes CONNECT termination before submitting application codes" {
    for (std.enums.values(Operation)) |operation| {
        for (std.enums.values(Termination)) |termination| {
            var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
            defer threaded.deinit();
            var fixture: Fixture = undefined;
            try fixture.init(threaded.io());
            defer fixture.deinit();
            const session = try fixture.addSession();
            const sibling = try fixture.addSession();
            const id = try fixture.openPeerStream(session);
            const connection = &fixture.connectionSession().established.connection;
            connection.config.reliable_reset = .{ .local = true, .peer = true };
            try session.sendStream(id, "reply", false);
            const connect_id = session.session_id.value;
            const peer = &fixture.client.established.connection;
            switch (termination) {
                .fin => try fixture.client.sendRequestBodyPaced(connect_id, &.{}, true),
                .reset => try peer.tryResetStream(connect_id, webtransport.applicationErrorCodeToHttp3(94)),
                .stop => try peer.trySendStopSending(connect_id, webtransport.ApplicationErrorCode.session_gone),
                .connection => try peer.closeApplication(99, "all sessions"),
            }
            while (true) {
                const observed = switch (termination) {
                    .fin => connection.recvStreamStats(connect_id).?.final_size != null,
                    .reset => connection.recvStreamStats(connect_id).?.reset != null,
                    .stop => connection.sendStreamStats(connect_id).?.stopped != null,
                    .connection => connection.draining(),
                };
                if (observed) break;
                try fixture.routeTransport();
            }
            try std.testing.expectError(if (termination == .connection) error.ConnectionClosed else error.InvalidSessionState, cancel(session, id, operation));
            try std.testing.expect(session.control.state.closed);
            try std.testing.expect(session.streams.get(id).?.send_reset == null);
            try std.testing.expect(session.streams.get(id).?.stop_sent == null);
            if (termination == .connection) {
                try std.testing.expectError(error.ConnectionClosed, sibling.sendDatagram("late"));
                try std.testing.expect(sibling.control.state.closed);
            } else {
                var output: [16]u8 = undefined;
                const event = (try runtime.EndpointServer.testing.pollAcceptedSessionEntry(session, &output)).?;
                try std.testing.expect(event == .session);
                if (termination == .fin) {
                    try std.testing.expect(event.session == .closed);
                    try std.testing.expectEqual(@as(u32, 0), event.session.closed.code);
                } else {
                    try std.testing.expect(event.session == .reset);
                    try std.testing.expectEqual(if (termination == .reset) webtransport.applicationErrorCodeToHttp3(94) else webtransport.ApplicationErrorCode.session_gone, event.session.reset.http3_code);
                }
                try sibling.sendDatagram("live");
                try std.testing.expect(!sibling.control.state.closed and !connection.closing());
            }
        }
    }
}

test "WebTransport shared server cancellation preserves connection-scoped HTTP3 errors" {
    for (std.enums.values(Operation)) |operation| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const session = try fixture.addSession();
        const id = try fixture.openPeerStream(session);
        const connection = &fixture.connectionSession().established.connection;
        connection.config.reliable_reset = .{ .local = true, .peer = true };
        try session.sendStream(id, "reply", false);
        const start = fixture.client.established.connection.sendStreamStats(session.session_id.value).?.highest_sent_offset;
        // A SETTINGS frame is prohibited on the accepted CONNECT stream.
        try fixture.client.established.connection.send(&.{.{ .stream = .{ .stream_id = session.session_id.value, .offset = start, .data = "\x04\x00" } }});
        while ((connection.availableReceivedStream(session.session_id.value) orelse @as([]const u8, &.{})).len == 0) try fixture.routeTransport();
        try std.testing.expectError(error.UnexpectedFrame, cancel(session, id, operation));
        try std.testing.expect(connection.closing() and session.control.connection_terminated);
        try std.testing.expectEqual(http3.ApplicationErrorCode.frame_unexpected, quic.one_rtt.testing.localCloseInfo(connection).?.error_code);
        try std.testing.expect(session.streams.get(id).?.send_reset == null);
    }
}
