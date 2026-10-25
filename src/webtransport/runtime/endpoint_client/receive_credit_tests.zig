//! Shared sessions deliver ready stream data despite blocked QUIC feedback.
const std = @import("std");
const webtransport = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const prefix = @import("../stream/prefix.zig");
const Fixture = @import("test_support.zig").Fixture;
const ObservedSend = @import("../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;

test "WebTransport shared client reads sibling streams while MAX_DATA feedback fails" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var fixture: Fixture = undefined;
    try fixture.init(io);
    defer fixture.deinit();
    const first = try fixture.addSession();
    const second = try fixture.addSession();
    const connection = &fixture.client.h3.established.connection;
    for ([_]@TypeOf(first){ first, second }, 0..) |session, index| {
        var storage: [16]u8 = undefined;
        const id: u62 = @intCast(3 + index * 4);
        const header = try prefix.header(session.session_id, .unidirectional, &storage);
        var bytes: [32]u8 = undefined;
        @memcpy(bytes[0..header.len], header);
        @memcpy(bytes[header.len..][0..6], if (index == 0) "first!" else "second");
        try fixture.peer.send(&.{.{ .stream = .{ .stream_id = id, .data = bytes[0 .. header.len + 6] } }});
        var packet = try connection.receivePacketTimeout(.{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } });
        packet.deinit(std.testing.allocator);
        const entry = connection.stream_recv_index.get(id).?;
        connection.stream_recv_flows.items[entry].flow.limit = connection.stream_recv_flows.items[entry].flow.highest_received;
    }
    const original_io = connection.endpoint.io;
    var failed_send = ObservedSend{ .delegate = original_io, .fail_after_prefix = 0 };
    var vtable = original_io.vtable.*;
    vtable.netSend = ObservedSend.netSend;
    connection.endpoint.io = .{ .userdata = &failed_send, .vtable = &vtable };
    defer connection.endpoint.io = original_io;
    var output: [16]u8 = undefined;
    var event = (try fixture.client.poll(first.session_id, &output)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(event == .stream and event.stream == .data);
    try std.testing.expectEqualStrings("first!", output[0..event.stream.data.bytes]);
    try std.testing.expectEqual(@as(u64, 6), first.streams.flow.?.consumed_data);
    try std.testing.expectEqual(@as(u64, 0), second.streams.flow.?.consumed_data);
    try std.testing.expect(second.streams.get(7) == null);
    event = (try fixture.client.poll(second.session_id, &output)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(event == .stream and event.stream == .data);
    try std.testing.expectEqualStrings("second", output[0..event.stream.data.bytes]);
    try std.testing.expectEqual(@as(u64, 6), second.streams.flow.?.consumed_data);
    try std.testing.expect(failed_send.calls >= 2);
    try std.testing.expect(connection.receive_credit_retry_deadline_ns != null);
    try std.testing.expect(!connection.closing());
    try std.testing.expect((try fixture.client.poll(first.session_id, &output)) == null);
    try std.testing.expect((try fixture.client.poll(second.session_id, &output)) == null);
    connection.endpoint.io = original_io;
    for (0..16) |_| {
        if (connection.receive_credit_retry_deadline_ns == null) break;
        const timer = connection.nextTimerDeadline().?;
        _ = try connection.serviceNextTimerAt(timer.deadline_ns);
    }
    try std.testing.expect(connection.receive_credit_retry_deadline_ns == null);
    try first.sendDatagram(&fixture.client, "still live");
    try second.sendDatagram(&fixture.client, "sibling live");
}
