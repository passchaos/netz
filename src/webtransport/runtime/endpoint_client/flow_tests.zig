const std = @import("std");
const webtransport = @import("../../mod.zig");
const http3 = @import("../../../http3/mod.zig");
const Fixture = @import("test_support.zig").Fixture;
test {
    _ = @import("reset_credit_tests.zig");
}

test "WebTransport endpoint client routes flow grants to one shared session" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const first = try fixture.addSession();
    const second = try fixture.addSession();
    const initial = first.streams.flow.?.send_limit.bidi;
    var capsule_bytes: [32]u8 = undefined;
    const grant = try (webtransport.Capsule{ .max_streams_bidi = initial + 1 }).writeInto(&capsule_bytes);
    var framed: std.ArrayList(u8) = .empty;
    defer framed.deinit(std.testing.allocator);
    try (http3.Frame{ .frame_type = http3.FrameType.data, .payload = grant, .consumed = 0 }).write(&framed, std.testing.allocator);
    try fixture.appendConnect(first, framed.items, false);
    try std.testing.expect((try fixture.poll(first)) == null);
    try std.testing.expectEqual(initial + 1, first.streams.flow.?.send_limit.bidi);
    try std.testing.expectEqual(initial, second.streams.flow.?.send_limit.bidi);
    // A duplicate update terminates only the affected CONNECT.
    try fixture.appendConnect(first, framed.items, false);
    try std.testing.expectError(error.FlowControlViolation, fixture.poll(first));
    try std.testing.expect(first.control.state.closed);
    try std.testing.expect(!second.control.state.closed);
    _ = try second.openBidirectionalStream(&fixture.client);
    try std.testing.expect(!fixture.client.h3.established.connection.closing());
}

test "WebTransport endpoint client receive flow violation leaves sibling session open" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    fixture.client.h3.options.local_settings.webtransport_initial_max_data = 6;
    const first = try fixture.addSession();
    const second = try fixture.addSession();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try webtransport.BidirectionalStreamHeader.write(&bytes, std.testing.allocator, first.session_id);
    try bytes.appendSlice(std.testing.allocator, "1234567");
    try fixture.peer.send(&.{.{ .stream = .{ .stream_id = 1, .data = bytes.items } }});
    var packet = try fixture.client.h3.established.connection.receivePacketTimeout(.{
        .duration = .{ .raw = .fromSeconds(1), .clock = .awake },
    });
    defer packet.deinit(std.testing.allocator);
    try fixture.client.h3.processDetachedResponsePacket(first.session_id.value, &packet);
    try std.testing.expectError(error.FlowControlViolation, fixture.poll(first));
    try std.testing.expect(first.control.state.closed);
    try std.testing.expect(!second.control.state.closed);
    try std.testing.expectEqual(@as(u64, 0), first.streams.flow.?.received.data);
    try std.testing.expectEqual(@as(u64, 0), second.streams.flow.?.received.data);
    const reset = fixture.client.h3.established.connection.sendStreamStats(first.session_id.value).?.reset.?;
    try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.flow_control_error), reset.application_error_code);
    _ = try second.openBidirectionalStream(&fixture.client);
    try std.testing.expect(!fixture.client.h3.established.connection.closing());
}

test "WebTransport endpoint client send flow grants preserve independent shared budgets" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.initWithSettings(threaded.io(), try webtransport.settingsWithInitialFlowLimits(.{}, 2, .{ .data = 0, .bidi = 4, .uni = 4 }));
    defer fixture.deinit();
    const first = try fixture.addSession();
    const second = try fixture.addSession();
    const first_stream = try first.openBidirectionalStream(&fixture.client);
    var committed: usize = 99;
    try std.testing.expectError(error.Timeout, first.sendStreamWithTimeout(&fixture.client, first_stream, "data", true, &committed, .fromMilliseconds(5)));
    try std.testing.expectEqual(@as(usize, 0), committed);
    var storage: [16]u8 = undefined;
    const grant = try (webtransport.Capsule{ .max_data = 4 }).writeInto(&storage);
    var framed: std.ArrayList(u8) = .empty;
    defer framed.deinit(std.testing.allocator);
    try (http3.Frame{ .frame_type = http3.FrameType.data, .payload = grant, .consumed = 0 }).write(&framed, std.testing.allocator);
    try fixture.appendConnect(second, framed.items, false);
    try std.testing.expect((try fixture.poll(second)) == null);
    const second_stream = try second.openBidirectionalStream(&fixture.client);
    try second.sendStreamWithTimeout(&fixture.client, second_stream, "data", true, &committed, .fromSeconds(1));
    try std.testing.expectEqual(@as(usize, 4), committed);
    try std.testing.expectEqual(@as(u64, 0), first.streams.flow.?.sent.data);
    try std.testing.expectEqual(@as(u64, 0), first.streams.flow.?.send_limit.data);
    try std.testing.expectEqual(@as(u64, 4), second.streams.flow.?.sent.data);
    try std.testing.expect(!first.control.state.closed and !second.control.state.closed);
}

test "WebTransport endpoint existing transport rejects mismatched initial quotas before CONNECT" {
    const runtime = @import("../../runtime.zig");
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    _ = try fixture.addSession();
    const before = fixture.client.h3.established.connection.nextLocalBidirectionalStreamId();
    try std.testing.expectError(error.InvalidSessionState, runtime.HandshakeClientSession.connectSessionAttempt(&fixture.client.h3, .{
        .authority = "localhost",
        .path = "/mismatched-initial-quotas",
        .limits = .{ .initial_flow_limits = .{ .data = 0, .bidi = 1, .uni = 1 } },
    }));
    try std.testing.expectEqual(before, fixture.client.h3.established.connection.nextLocalBidirectionalStreamId());
    try std.testing.expectEqual(@as(usize, 1), fixture.client.sessions.count());
}

test "WebTransport endpoint client retired stream grants stay within one shared session" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    const settings = try webtransport.settingsWithSessionCapacity(.{ .webtransport_initial_max_streams_uni = 1 }, 2);
    try fixture.initWithSettings(threaded.io(), settings);
    defer fixture.deinit();
    const first = try fixture.addSession();
    const second = try fixture.addSession();
    for ([_]@TypeOf(first){ first, second }, 0..) |session, index| {
        const id: u62 = @intCast(3 + index * 4);
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(std.testing.allocator);
        try webtransport.UnidirectionalStreamHeader.writeWebTransport(&bytes, std.testing.allocator, session.session_id);
        try bytes.append(std.testing.allocator, @intCast(index));
        try fixture.peer.send(&.{.{ .stream = .{ .stream_id = id, .data = bytes.items, .fin = true } }});
        var packet = try fixture.client.h3.established.connection.receivePacketTimeout(.{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } });
        defer packet.deinit(std.testing.allocator);
        try fixture.client.h3.processDetachedResponsePacket(session.session_id.value, &packet);
        const event = (try fixture.poll(session)) orelse return error.TestUnexpectedResult;
        try std.testing.expect(event == .stream and event.stream == .data and event.stream.data.fin);
        try std.testing.expect(session.streams.get(id) == null);
        try std.testing.expectEqual(@as(u64, 1), session.streams.flow.?.retired_peer.uni);
        try std.testing.expectEqual(@as(u64, 2), session.streams.flow.?.receive_limit.uni);
        if (index == 0) {
            try std.testing.expectEqual(@as(u64, 0), second.streams.flow.?.retired_peer.uni);
            try std.testing.expectEqual(@as(u64, 1), second.streams.flow.?.receive_limit.uni);
        }
    }
    try std.testing.expectEqual(@as(u64, 1), first.streams.flow.?.received.data);
    try std.testing.expectEqual(@as(u64, 1), second.streams.flow.?.received.data);
    try std.testing.expect(!fixture.client.h3.established.connection.closing());
}
