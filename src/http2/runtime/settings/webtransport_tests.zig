const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const allocator = std.testing.allocator;
const initial: http2.WebTransportSettings = .{ .enabled = true, .max_data = 100, .max_stream_data_uni = 11, .max_stream_data_bidi_local = 12, .max_stream_data_bidi_remote = 13, .max_streams_uni = 2, .max_streams_bidi = 3 };
const updated: http2.WebTransportSettings = .{ .enabled = true, .max_data = 200, .max_stream_data_uni = 21, .max_stream_data_bidi_local = 22, .max_stream_data_bidi_remote = 23, .max_streams_uni = 4, .max_streams_bidi = 5 };

test "HTTP/2 WebTransport SETTINGS preserve independent acknowledged snapshots on both roles" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .enable_connect_protocol = true, .webtransport = initial });
    defer server.deinit();
    const Peer = struct {
        server: *runtime.Server,
        fn run(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(3));
            defer connection.close();
            try std.testing.expectEqualDeep(initial, connection.peerWebTransportSettings());
            _ = try connection.readPingWithTimeout(.fromSeconds(3));
            try std.testing.expectEqualDeep(initial, connection.localWebTransportSettings());
            const retained = connection.localWebTransportSettings();
            try connection.updateWebTransportSettingsWithTimeout(updated, .fromSeconds(3));
            try std.testing.expectEqualDeep(initial, connection.localWebTransportSettings());
            try std.testing.expectError(error.SettingsAckPending, connection.updateWebTransportSettingsWithTimeout(initial, .fromSeconds(3)));
            _ = try connection.pingWithTimeout("srvproof".*, .fromSeconds(3));
            try std.testing.expectEqualDeep(updated, connection.localWebTransportSettings());
            try std.testing.expectEqualDeep(initial, retained);
            _ = try connection.readPingWithTimeout(.fromSeconds(3));
            try std.testing.expectEqualDeep(updated, connection.peerWebTransportSettings());
        }
    };
    var peer = Peer{ .server = &server };
    var task = io.async(Peer.run, .{&peer});
    defer _ = task.cancel(io) catch {};
    var client = try runtime.Client.connect(allocator, io, server.address(), .{ .enable_connect_protocol = true, .webtransport = initial });
    defer client.close();
    try std.testing.expectEqualDeep(initial, client.peerWebTransportSettings());
    try std.testing.expectEqualDeep(initial, client.localWebTransportSettings());
    const retained = client.peerWebTransportSettings();
    _ = try client.pingWithTimeout("barrier1".*, .fromSeconds(3));
    _ = try client.pingWithTimeout("barrier2".*, .fromSeconds(3));
    try std.testing.expectEqualDeep(updated, client.peerWebTransportSettings());
    try std.testing.expectEqualDeep(initial, retained);
    try client.updateWebTransportSettingsWithTimeout(updated, .fromSeconds(3));
    try std.testing.expectEqualDeep(initial, client.localWebTransportSettings());
    _ = try client.pingWithTimeout("barrier3".*, .fromSeconds(3));
    try std.testing.expectEqualDeep(updated, client.localWebTransportSettings());
    try task.await(io);
}

test "HTTP/2 WebTransport SETTINGS use assigned codepoints and reject invalid capability values" {
    var fields: [7]http2.Setting = undefined;
    const settings = initial.write(&fields);
    const ids = [_]u16{ 0x2b60, 0x2b61, 0x2b62, 0x2b63, 0x2b66, 0x2b64, 0x2b65 };
    var parsed: http2.WebTransportSettings = .{};
    for (settings, ids) |setting, id| {
        try std.testing.expectEqual(id, @intFromEnum(setting.id));
        try parsed.apply(setting);
    }
    try std.testing.expectEqualDeep(initial, parsed);
    const snapshot = parsed;
    try std.testing.expectError(error.InvalidSetting, parsed.apply(.{ .id = .webtransport_enabled, .value = 2 }));
    try std.testing.expectEqualDeep(snapshot, parsed);
    try std.testing.expectError(error.InvalidSetting, http2.validateSetting(.webtransport_enabled, 2));
    try parsed.apply(.{ .id = .webtransport_enabled, .value = 0 });
    try std.testing.expect(!parsed.enabled);
}

test "HTTP/2 WebTransport settings update rejects invalid admission without output allocation" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    var connection: runtime.Connection = .{ .allocator = failing.allocator(), .io = io, .stream = undefined, .role = .client, .awaiting_settings_ack = true, .local_webtransport_sent = initial, .local_webtransport_acknowledged = initial };
    try std.testing.expectError(error.SettingsAckPending, connection.updateWebTransportSettingsWithTimeout(updated, .fromSeconds(1)));
    try std.testing.expectError(error.Timeout, connection.updateWebTransportSettingsWithTimeout(updated, .zero));
    connection.awaiting_settings_ack = false;
    try std.testing.expectError(error.InvalidSetting, connection.updateWebTransportSettingsWithTimeout(updated, .fromSeconds(1)));
    try std.testing.expectEqualDeep(initial, connection.localWebTransportSettings());
    try std.testing.expectEqualDeep(initial, connection.local_webtransport_sent);
    try std.testing.expect(!failing.has_induced_failure);
}

test "HTTP/2 WebTransport settings failed output leaves acknowledged and submitted quotas unchanged" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try @import("../testing/blocked_output.zig").BlockedOutput.init(io, .client);
    defer fixture.deinit();
    fixture.connection.limits.enable_connect_protocol = true;
    fixture.connection.local_webtransport_sent = initial;
    fixture.connection.local_webtransport_acknowledged = initial;
    try fixture.saturate();
    try std.testing.expectError(error.Timeout, fixture.connection.updateWebTransportSettingsWithTimeout(updated, .fromMilliseconds(10)));
    try std.testing.expectEqualDeep(initial, fixture.connection.local_webtransport_sent);
    try std.testing.expectEqualDeep(initial, fixture.connection.localWebTransportSettings());
    try std.testing.expect(!fixture.connection.awaiting_settings_ack);
    try std.testing.expect(!fixture.connection.isReusable());
}
