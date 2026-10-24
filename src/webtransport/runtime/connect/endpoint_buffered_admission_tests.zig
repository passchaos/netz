const std = @import("std");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const Fixture = @import("test_support/endpoint_pair.zig").Fixture;

test "WebTransport endpoint rejects one coalesced CONNECT and admits the buffered sibling without another packet" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    var peer = try fixture.addPeer(91, "buffered-client", "buffered-server");
    defer peer.deinit();
    var invalid_bytes: std.ArrayList(u8) = .empty;
    defer invalid_bytes.deinit(allocator);
    var valid_bytes: std.ArrayList(u8) = .empty;
    defer valid_bytes.deinit(allocator);
    const invalid = http3.Request{
        .method = "CONNECT",
        .scheme = "https",
        .authority = "localhost",
        .path = "/invalid",
        .headers = &.{
            .{ .name = ":protocol", .value = "webtransport" },
            .{ .name = "origin", .value = "https://localhost" },
        },
    };
    var valid = invalid;
    valid.path = "/valid";
    valid.headers = &.{
        .{ .name = ":protocol", .value = "webtransport-h3" },
        .{ .name = "origin", .value = "https://localhost" },
    };
    try invalid.writeWithSettings(&invalid_bytes, allocator, peer.client.control.settings.peer);
    try valid.writeWithSettings(&valid_bytes, allocator, peer.client.control.settings.peer);
    try peer.client.established.connection.send(&.{
        .{ .stream = .{ .stream_id = 0, .data = invalid_bytes.items } },
        .{ .stream = .{ .stream_id = 4, .data = valid_bytes.items } },
    });
    const versions = [_]u32{quic.Version.version_1.wireValue()};
    var buffer: [16]u8 = undefined;
    try std.testing.expectError(error.InvalidConnect, fixture.endpoint.receiveWithTimeout(&versions, .fromSeconds(1), &buffer));
    try std.testing.expect(peer.server.established.connection.recvStreamStats(4).?.highest_received_offset != 0);
    // Both requests arrived in one protected packet. No second receive may be
    // required merely because the first request was scoped out of admission.
    var event = (try fixture.endpoint.receiveOnce(&versions, .{ .clock = .awake, .raw = .fromMilliseconds(1) }, &buffer)) orelse return error.TestUnexpectedResult;
    defer event.deinit(allocator);
    try std.testing.expect(event == .session_request);
    const accepted = try fixture.endpoint.accept(peer.handle);
    try std.testing.expectEqual(@as(u62, 4), accepted.session_id.value);
    try std.testing.expect(!accepted.control.state.closed);
    try std.testing.expect(peer.server.established.connection.sendStreamStats(4).?.reset == null);
}
