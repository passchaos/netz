const std = @import("std");
const webtransport = @import("../mod.zig");
const http3 = @import("../../http3/mod.zig");
const Pair = @import("session_control/test_support/handshake_pair.zig").Pair;

test "WebTransport negotiation rejects disjoint versions before allocating transport IDs" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const client_settings = pair.client.h3.options.local_settings;
    const server_settings = pair.server.h3.options.local_settings;
    const client_peer = pair.client.h3.control.settings.peer;
    const server_peer = pair.server.h3.control.settings.peer;
    pair.client.h3.options.local_settings.webtransport_versions = .{ .draft16 = true };
    pair.server.h3.options.local_settings.webtransport_versions = .{ .draft16 = true };
    const legacy_peer = http3.Settings.fromList(&.{
        .{ .id = @intFromEnum(http3.SettingId.webtransport_max_sessions), .value = 1 },
        .{ .id = @intFromEnum(http3.SettingId.h3_datagram), .value = 1 },
    });
    pair.client.h3.control.settings.peer = legacy_peer;
    pair.server.h3.control.settings.peer = legacy_peer;
    const client_bidi = pair.connection(.client).nextLocalBidirectionalStreamId();
    const client_uni = pair.connection(.client).nextLocalUnidirectionalStreamId();
    const server_bidi = pair.connection(.server).nextLocalBidirectionalStreamId();
    const server_uni = pair.connection(.server).nextLocalUnidirectionalStreamId();
    try std.testing.expectError(error.WebTransportNotNegotiated, pair.client.openBidirectionalStream());
    try std.testing.expectError(error.WebTransportNotNegotiated, pair.client.openUnidirectionalStream());
    try std.testing.expectError(error.WebTransportNotNegotiated, pair.server.openBidirectionalStream());
    try std.testing.expectError(error.WebTransportNotNegotiated, pair.server.openUnidirectionalStream());
    try std.testing.expectEqual(client_bidi, pair.connection(.client).nextLocalBidirectionalStreamId());
    try std.testing.expectEqual(client_uni, pair.connection(.client).nextLocalUnidirectionalStreamId());
    try std.testing.expectEqual(server_bidi, pair.connection(.server).nextLocalBidirectionalStreamId());
    try std.testing.expectEqual(server_uni, pair.connection(.server).nextLocalUnidirectionalStreamId());
    try std.testing.expectEqual(@as(usize, 0), pair.client.streams.streams.items.len);
    try std.testing.expectEqual(@as(usize, 0), pair.server.streams.streams.items.len);
    pair.client.h3.options.local_settings = client_settings;
    pair.server.h3.options.local_settings = server_settings;
    pair.client.h3.control.settings.peer = client_peer;
    pair.server.h3.control.settings.peer = server_peer;
    const id = try pair.client.openBidirectionalStream();
    try std.testing.expectEqual(client_bidi, id);
    try pair.client.sendStream(id, "still usable", false);
    var out: [32]u8 = undefined;
    const event = try pair.server.readStreamWithTimeout(&out, .fromSeconds(1));
    try std.testing.expect(event == .data);
    try std.testing.expectEqual(id, event.data.stream_id);
    try std.testing.expectEqualStrings("still usable", out[0..event.data.bytes]);
    try std.testing.expectEqual(webtransport.Version.draft16, try webtransport.negotiatedVersion(client_settings, client_peer));
}
