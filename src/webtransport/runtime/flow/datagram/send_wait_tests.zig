//! DATAGRAM backpressure must not delay session termination behind credit.
const std = @import("std");
const http3 = @import("../../../../http3/mod.zig");
const control = @import("../../session_control.zig");
const Pair = @import("../../session_control/test_support/handshake_pair.zig").Pair;
const Fixture = @import("../../endpoint_client/test_support.zig").Fixture;
const quic = @import("../../../../quic/mod.zig");

test "WebTransport DATAGRAM backpressure wait observes CLOSE on either endpoint role" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    inline for (.{ .client, .server }) |role| {
        for ([_]bool{ false, true }) |pacing| {
            for ([_]bool{ false, true }) |batch| {
                var pair: Pair = undefined;
                try pair.init(threaded.io());
                defer pair.deinit();
                var bytes: [64]u8 = undefined;
                const close = try control.writeCloseInto(&bytes, 91, "during wait");
                // Leave CLOSE on UDP, after the initial buffered-control check.
                if (role == .client) try pair.server.h3.sendResponseBodyPaced(0, close, false) else try pair.client.h3.sendRequestBodyPaced(0, close, false);
                const session = if (role == .client) &pair.client else &pair.server;
                const connection = pair.connection(role);
                const previous_window = connection.congestion.congestion_window;
                const sent = connection.datagramsSent();
                if (pacing) {
                    connection.pacer.enabled = true;
                    connection.setMaxPacingRateBytesPerSecond(1);
                    quic.one_rtt.testing.exhaustPacingAt(connection, @intCast(std.Io.Clock.awake.now(threaded.io()).nanoseconds));
                } else connection.congestion.congestion_window = 0;
                defer connection.congestion.congestion_window = previous_window;
                if (batch) {
                    var committed: usize = 99;
                    try std.testing.expectError(error.InvalidSessionState, session.sendDatagramsWithTimeout(&.{ "late", "also late" }, &committed, .fromMilliseconds(100)));
                    try std.testing.expectEqual(@as(usize, 0), committed);
                } else try std.testing.expectError(error.InvalidSessionState, session.sendDatagramWithTimeout("late", .fromMilliseconds(100)));
                connection.congestion.congestion_window = previous_window;
                connection.pacer.enabled = false;
                try std.testing.expectEqual(sent, connection.datagramsSent());
                try std.testing.expect(session.control.pending_closed);
                const event = (try pair.poll(role)).?;
                try std.testing.expect(event == .closed);
                try std.testing.expectEqual(@as(u32, 91), event.closed.code);
                try std.testing.expectEqualStrings("during wait", event.closed.reason);
                try std.testing.expect(!connection.closing());
            }
        }
    }
}

test "WebTransport DATAGRAM partial batch stops its uncommitted suffix after CLOSE" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    inline for (.{ .client, .server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        var storage: [64]u8 = undefined;
        const close = try control.writeCloseInto(&storage, 91, "after prefix");
        if (role == .client) try pair.server.h3.sendResponseBodyPaced(0, close, false) else try pair.client.h3.sendRequestBodyPaced(0, close, false);
        const session = if (role == .client) &pair.client else &pair.server;
        const connection = pair.connection(role);
        const previous_window = connection.congestion.congestion_window;
        defer connection.congestion.congestion_window = previous_window;
        const first = "one" ++ "a" ** 797;
        const second = "two" ++ "b" ** 797;
        const third = "end" ++ "c" ** 797;
        // Two payloads cannot share one packet; keep the receive frame limit
        // unchanged so an ACK+STREAM CLOSE remains valid on the peer side.
        const packet_len = try connection.packetLenForFramesAtOffset(0, &.{.{ .datagram = .{ .data = "\x00" ++ first, .length_present = true } }});
        connection.congestion.congestion_window = connection.congestion.bytes_in_flight + packet_len;
        const before = connection.datagramsSent();
        var committed: usize = 99;
        try std.testing.expectError(error.InvalidSessionState, session.sendDatagramsWithTimeout(&.{ first, second, third }, &committed, .fromSeconds(1)));
        try std.testing.expectEqual(@as(usize, 1), committed);
        try std.testing.expectEqual(before + 1, connection.datagramsSent());
        connection.congestion.congestion_window = previous_window;
        const event = (try pair.poll(role)).?;
        try std.testing.expect(event == .closed);
        try std.testing.expectEqualStrings("after prefix", event.closed.reason);
    }
}

test "WebTransport DATAGRAM pacing wait resumes at its wakeup and preserves DRAIN" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    inline for (.{ .client, .server }) |role| {
        for ([_]bool{ false, true }) |drain| {
            var pair: Pair = undefined;
            try pair.init(threaded.io());
            defer pair.deinit();
            const session = if (role == .client) &pair.client else &pair.server;
            const peer = if (role == .client) &pair.server else &pair.client;
            if (drain) {
                var storage: [16]u8 = undefined;
                const capsule = try control.writeDrainInto(&storage);
                if (role == .client) try pair.server.h3.sendResponseBodyPaced(0, capsule, false) else try pair.client.h3.sendRequestBodyPaced(0, capsule, false);
            }
            const connection = pair.connection(role);
            connection.pacer.enabled = true;
            connection.setMaxPacingRateBytesPerSecond(5000);
            quic.one_rtt.testing.exhaustPacingAt(connection, @intCast(std.Io.Clock.awake.now(threaded.io()).nanoseconds));
            const before = connection.datagramsSent();
            try session.sendDatagramWithTimeout("paced", .fromSeconds(1));
            try std.testing.expectEqual(before + 1, connection.datagramsSent());
            var received = try peer.receiveDatagramWithTimeout(.fromSeconds(1));
            defer received.deinit(std.testing.allocator);
            try std.testing.expectEqualStrings("paced", received.datagram.payload);
            if (drain) {
                try std.testing.expect(session.control.state.draining and !session.control.state.closed);
                try std.testing.expect((try pair.poll(role)).? == .draining);
            }
        }
    }
}

test "WebTransport shared DATAGRAM congestion wait retains CLOSE and sibling events" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const sibling = try fixture.addSession();
    try fixture.queueDatagram(sibling, "sibling");
    const connection = &fixture.client.h3.established.connection;
    var bytes: [64]u8 = undefined;
    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(std.testing.allocator);
    try (http3.Frame{ .frame_type = http3.FrameType.data, .payload = try control.writeCloseInto(&bytes, 91, "during wait"), .consumed = 0 }).write(&data, std.testing.allocator);
    try fixture.peer.send(&.{.{ .stream = .{ .stream_id = session.session_id.value, .offset = connection.recvStreamStats(session.session_id.value).?.highest_received_offset, .data = data.items } }});
    const previous_window = connection.congestion.congestion_window;
    connection.congestion.congestion_window = 0;
    defer connection.congestion.congestion_window = previous_window;
    try std.testing.expectError(error.InvalidSessionState, session.sendDatagramWithTimeout(&fixture.client, "late", .fromMilliseconds(100)));
    connection.congestion.congestion_window = previous_window;
    var output: [32]u8 = undefined;
    const event = (try fixture.client.poll(session.session_id, &output)).?;
    try std.testing.expect(event == .session and event.session == .closed);
    try std.testing.expectEqualStrings("during wait", event.session.closed.reason);
    var ready = (try fixture.client.poll(sibling.session_id, &output)).?;
    defer ready.deinit(std.testing.allocator);
    try std.testing.expect(ready == .datagram);
    try std.testing.expectEqualStrings("sibling", ready.datagram.payload);
    try sibling.sendDatagram(&fixture.client, "still open");
    try std.testing.expect(!connection.closing() and !sibling.control.state.closed);
}
