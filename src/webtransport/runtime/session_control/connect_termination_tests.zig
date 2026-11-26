const std = @import("std");
const native_protocol_io = @import("../../../internal/testing/native_protocol_io.zig");
const support = @import("test_support/handshake_pair.zig");
const webtransport = @import("../../mod.zig");
const control_mod = @import("../session_control.zig");
const quic = @import("../../../quic/mod.zig");

fn stopConnect(pair: *support.Pair, receiver: support.Role, code: u64) !void {
    const sender: support.Role = if (receiver == .client) .server else .client;
    try pair.connection(sender).trySendStopSending(0, code);
    const connection = pair.connection(receiver);
    const deadline = std.Io.Clock.Timestamp.fromNow(connection.endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    while (connection.sendStreamStats(0).?.stopped == null) try pair.receiveProgress(receiver, deadline);
    try std.testing.expect(connection.recvStreamStats(0).?.final_size == null);
    try std.testing.expect(connection.recvStreamStats(0).?.reset == null);
}

test "WebTransport CONNECT STOP_SENDING blocks application sends before event polling" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]support.Role{ .client, .server }) |role| {
        var pair: support.Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        try stopConnect(&pair, role, webtransport.ApplicationErrorCode.session_gone);
        switch (role) {
            .client => {
                try std.testing.expectError(error.InvalidSessionState, pair.client.openBidirectionalStream());
                try std.testing.expectError(error.InvalidSessionState, pair.client.sendDatagram("late"));
            },
            .server => {
                try std.testing.expectError(error.InvalidSessionState, pair.server.openBidirectionalStream());
                try std.testing.expectError(error.InvalidSessionState, pair.server.sendDatagram("late"));
            },
        }
    }
}

test "WebTransport CONNECT STOP_SENDING emits one session reset with peer code" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]support.Role{ .client, .server }) |role| {
        var pair: support.Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        const code = (@as(u64, 1) << 62) - 1;
        try stopConnect(&pair, role, code);
        const control = pair.control(role);
        const event = (try control.pollOnce(pair.connection(role))) orelse return error.TestUnexpectedResult;
        try std.testing.expect(event == .reset);
        try std.testing.expectEqual(@as(u64, code), event.reset.http3_code);
        try std.testing.expect(control.state.closed and !control.connection_terminated);
        try std.testing.expect((try control.pollOnce(pair.connection(role))) == null);
    }
}

test "WebTransport CONNECT local FIN and RESET terminate with the peer receive direction open" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]support.Role{ .client, .server }) |role| {
        for ([_]bool{ false, true }) |reset| {
            var pair: support.Pair = undefined;
            try pair.init(threaded.io());
            defer pair.deinit();
            const connection = pair.connection(role);
            const offset = connection.sendStreamStats(0).?.highest_sent_offset;
            if (reset) {
                try connection.tryResetStream(0, 0x10c);
            } else {
                try connection.send(&.{.{ .stream = .{ .stream_id = 0, .offset = offset, .data = &.{}, .fin = true } }});
            }
            const event = (try pair.poll(role)) orelse return error.TestUnexpectedResult;
            if (reset) {
                try std.testing.expect(event == .reset);
                try std.testing.expectEqual(@as(u64, 0x10c), event.reset.http3_code);
            } else {
                try std.testing.expect(event == .closed);
                try std.testing.expectEqual(@as(u32, 0), event.closed.code);
                try std.testing.expectEqual(@as(usize, 0), event.closed.reason.len);
            }
            try std.testing.expect(connection.recvStreamStats(0).?.final_size == null);
            try std.testing.expect(pair.control(role).state.closed and !pair.control(role).connection_terminated);
            try std.testing.expect((try pair.poll(role)) == null);
        }
    }
}

test "WebTransport CONNECT STOP_SENDING preserves buffered DRAIN and CLOSE metadata" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]support.Role{ .client, .server }) |role| {
        var pair: support.Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        var bytes: [80]u8 = undefined;
        const drain = try control_mod.writeDrainInto(&bytes);
        const close = try control_mod.writeCloseInto(bytes[drain.len..], 77, "buffered close");
        try pair.sendCapsules(role, bytes[0 .. drain.len + close.len]);
        try stopConnect(&pair, role, webtransport.ApplicationErrorCode.session_gone);
        try std.testing.expect((try pair.poll(role)).? == .draining);
        const event = try pair.receiveWithTimeout(role, .fromSeconds(1));
        try std.testing.expect(event == .closed);
        try std.testing.expectEqual(@as(u32, 77), event.closed.code);
        try std.testing.expectEqualStrings("buffered close", event.closed.reason);
        try std.testing.expect(pair.control(role).local_close_failed);
        try std.testing.expect((try pair.poll(role)) == null);
    }
}

test "WebTransport CONNECT STOP_SENDING cleans associated streams and blocks queued datagram reads" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]support.Role{ .client, .server }) |role| {
        var pair: support.Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        const id = try pair.openStream();
        var output = [_]u8{0xaa} ** 16;
        _ = (try pair.server.pollStream(&output)) orelse return error.TestUnexpectedResult;
        const h3 = if (role == .client) &pair.client.h3.connect_datagrams else &pair.server.h3.connect_datagrams;
        try h3.route("\x00queued");
        try stopConnect(&pair, role, webtransport.ApplicationErrorCode.session_gone);
        const event = try pair.receiveWithTimeout(role, .fromSeconds(1));
        try std.testing.expect(event == .reset);
        const registry = if (role == .client) &pair.client.streams else &pair.server.streams;
        const stream = registry.get(id).?;
        try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.session_gone), stream.send_reset.?.http3_code);
        try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.session_gone), stream.stop_sent.?.http3_code);
        @memset(&output, 0xaa);
        switch (role) {
            .client => {
                try std.testing.expectError(error.ConnectDatagramAssociationClosed, pair.client.pollDatagram());
                try std.testing.expectError(error.InvalidSessionState, pair.client.pollStream(&output));
            },
            .server => {
                try std.testing.expectError(error.ConnectDatagramAssociationClosed, pair.server.pollDatagram());
                try std.testing.expectError(error.InvalidSessionState, pair.server.pollStream(&output));
            },
        }
        try std.testing.expectEqualSlices(u8, &([_]u8{0xaa} ** 16), &output);
        try std.testing.expect(!pair.connection(role).closing());
    }
}

test "WebTransport CONNECT STOP_SENDING terminates before its paced RESET response commits" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: support.Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const connection = pair.connection(.client);
    connection.pacer = .initWithRateLimit(true, 1200, 1, 0);
    connection.pacer.budget = 0;
    connection.pacer.setLastSentTimeNs(0);
    try quic.one_rtt.testing.applyReceivedFrames(connection, 20, &.{.{ .stop_sending = .{
        .stream_id = 0,
        .application_error_code = 0x10c,
    } }}, null, .not_ect);
    try std.testing.expect(connection.sendStreamStats(0).?.reset == null);
    try std.testing.expectError(error.InvalidSessionState, pair.client.openBidirectionalStream());
    const event = (try pair.control(.client).pollOnce(connection)).?;
    try std.testing.expect(event == .reset);
    try std.testing.expectEqual(@as(u64, 0x10c), event.reset.http3_code);
    try std.testing.expect(connection.sendStreamStats(0).?.reset == null);
}

test "WebTransport CONNECT STOP_SENDING discards subsequent peer data without inventing a CLOSE violation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]support.Role{ .client, .server }) |role| {
        var pair: support.Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        // An unfinished Capsule is allowed when the Session ends abruptly.
        try pair.sendCapsules(role, &.{0x40});
        try stopConnect(&pair, role, webtransport.ApplicationErrorCode.session_gone);
        const control = pair.control(role);
        const connection = pair.connection(role);
        try std.testing.expect((try control.pollOnce(connection)).? == .reset);
        try pair.sendCapsules(role, &.{0xff});
        try std.testing.expect((try control.pollOnce(connection)) == null);
        try std.testing.expectEqual(@as(usize, 0), (connection.availableReceivedStream(0) orelse @as([]const u8, &.{})).len);
        try std.testing.expect(!control.post_terminal_data_pending and !control.post_terminal_data_rejected);
        try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.session_gone), connection.sendStreamStats(0).?.reset.?.application_error_code);
    }
}

test "WebTransport CONNECT STOP_SENDING retains post-CLOSE protocol rejection" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: support.Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    var bytes: [64]u8 = undefined;
    const close = try control_mod.writeCloseInto(&bytes, 77, "peer close");
    bytes[close.len] = 0xff;
    try pair.sendCapsules(.client, bytes[0 .. close.len + 1]);
    try stopConnect(&pair, .client, webtransport.ApplicationErrorCode.session_gone);
    const connection = pair.connection(.client);
    const control = pair.control(.client);
    const event = (try control.pollOnce(connection)).?;
    try std.testing.expect(event == .closed);
    try std.testing.expectEqualStrings("peer close", event.closed.reason);
    try std.testing.expectError(error.InvalidCapsule, control.pollOnce(connection));
    try std.testing.expect(control.post_terminal_data_rejected);
    try std.testing.expectEqual(@as(u64, @import("../../../http3/mod.zig").ApplicationErrorCode.message_error), connection.recvStreamStats(0).?.stop_sending_sent.?.application_error_code);
}

test "WebTransport CONNECT STOP_SENDING retains its reset event across cleanup socket failure" {
    try native_protocol_io.run(retainedConnectReset);
}

fn retainedConnectReset(io: std.Io) !void {
    const ObservedBatchSend = @import("../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;
    for ([_]support.Role{ .client, .server }) |role| {
        var pair: support.Pair = undefined;
        try pair.init(io);
        defer pair.deinit();
        const id = try pair.openStream();
        var output: [16]u8 = undefined;
        _ = (try pair.server.pollStream(&output)) orelse return error.TestUnexpectedResult;
        try stopConnect(&pair, role, webtransport.ApplicationErrorCode.session_gone);
        const connection = pair.connection(role);
        const endpoint = connection.endpoint;
        const original_io = endpoint.io;
        var observed = ObservedBatchSend{ .delegate = original_io, .fail_on_call = 1 };
        endpoint.io = observed.io();
        defer endpoint.io = original_io;
        try std.testing.expectError(error.NetworkDown, pair.receiveWithTimeout(role, .fromSeconds(1)));
        const registry = if (role == .client) &pair.client.streams else &pair.server.streams;
        try std.testing.expect(registry.get(id).?.send_reset == null);
        observed.fail_on_call = null;
        const event = try pair.receiveWithTimeout(role, .fromSeconds(1));
        try std.testing.expect(event == .reset);
        try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.session_gone), event.reset.http3_code);
        try std.testing.expect(registry.get(id).?.send_reset != null);
        try std.testing.expect((try pair.poll(role)) == null);
        try std.testing.expect(!connection.closing());
    }
}
