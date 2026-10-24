const std = @import("std");
const webtransport = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const association = @import("../stream_association.zig");
const lifecycle = @import("../connection_lifecycle.zig");
const Fixture = @import("test_support.zig").Fixture;

test "WebTransport shared client maintenance settles reset credit only for its session" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    const settings = try webtransport.settingsWithSessionCapacity(.{ .webtransport_initial_max_data = 4 }, 2);
    try fixture.initWithSettings(threaded.io(), settings);
    defer fixture.deinit();
    const first = try fixture.addSession();
    const second = try fixture.addSession();
    const connection = &fixture.client.h3.established.connection;
    for ([_]@TypeOf(first){ first, second }, 0..) |session, index| {
        const id: u62 = @intCast(3 + index * 4);
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(std.testing.allocator);
        try webtransport.UnidirectionalStreamHeader.writeWebTransport(&bytes, std.testing.allocator, session.session_id);
        try bytes.appendSlice(std.testing.allocator, "body");
        try quic.one_rtt.testing.applyReceivedFrames(connection, index + 10, &.{.{ .stream = .{ .stream_id = id, .data = bytes.items } }}, null, .not_ect);
        try association.discoverBuffered(connection, &session.streams);
        try quic.one_rtt.testing.applyReceivedFrames(connection, index + 20, &.{.{ .reset_stream = .{
            .stream_id = id,
            .application_error_code = webtransport.applicationErrorCodeToHttp3(71),
            .final_size = bytes.items.len,
        } }}, null, .not_ect);
    }
    _ = lifecycle.observe(&first.control, &fixture.client.h3, &first.streams);
    try std.testing.expectEqual(@as(u64, 4), first.streams.flow.?.consumed_data);
    try std.testing.expectEqual(@as(u64, 8), first.streams.flow.?.receive_limit.data);
    try std.testing.expectEqual(@as(u64, 0), second.streams.flow.?.consumed_data);
    try std.testing.expectEqual(@as(u64, 4), second.streams.flow.?.receive_limit.data);
    try std.testing.expect(!first.streams.get(3).?.reset_reported);
    try std.testing.expect(!second.streams.get(7).?.reset_reported);
    _ = lifecycle.observe(&second.control, &fixture.client.h3, &second.streams);
    try std.testing.expectEqual(@as(u64, 4), second.streams.flow.?.consumed_data);
    try std.testing.expectEqual(@as(u64, 8), second.streams.flow.?.receive_limit.data);
    const event_first = (try fixture.poll(first)) orelse return error.TestUnexpectedResult;
    const event_second = (try fixture.poll(second)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(event_first == .stream and event_first.stream == .reset and event_first.stream.reset.stream_id == 3);
    try std.testing.expect(event_second == .stream and event_second.stream == .reset and event_second.stream.reset.stream_id == 7);
    try std.testing.expectEqual(@as(?u32, 71), event_first.stream.reset.error_info.application_code);
    try std.testing.expectEqual(@as(?u32, 71), event_second.stream.reset.error_info.application_code);
    try std.testing.expect((try fixture.poll(first)) == null);
    try std.testing.expect((try fixture.poll(second)) == null);
    try std.testing.expect(!connection.closing());
}
