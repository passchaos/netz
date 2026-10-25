const std = @import("std");
const runtime = @import("../../../runtime.zig");
const http2 = @import("../../../mod.zig");
const window = @import("../window.zig");
const allocator = std.testing.allocator;

test "HTTP/2 adaptive growth leaves room for pending padding refunds at maximum windows" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    const peer = try listener.accept(io);
    defer peer.close(io);
    var connection = runtime.Connection{ .io = io, .allocator = allocator, .stream = stream, .role = .server };
    defer connection.close();
    try runtime.testing.addActivePeerStream(&connection, 1);
    connection.recv_connection_window.value = window.max_value;
    (try runtime.testing.recvStreamWindow(&connection, 1)).value = window.max_value;
    try runtime.testing.queueAdaptiveWindowTarget(&connection, 65_537);
    const padding = try runtime.testing.receiveDataPayload(&connection, 1, .{ .header = .{ .frame_type = .data, .stream_id = 1, .flags = 8, .length = 2 }, .payload = "\x01\x00" });
    try std.testing.expectEqual(@as(u31, 0), padding.adaptive_connection_increment);
    try std.testing.expectEqual(@as(?u32, 65_537), connection.adaptive_queued_target);
    try runtime.testing.releaseReceivedDataCapacity(&connection, 1, padding, false);
    try std.testing.expectEqual(window.max_value, connection.recv_connection_window.value);
    try std.testing.expectEqual(window.max_value, (try runtime.testing.recvStreamWindow(&connection, 1)).value);
    // Real content leaves enough headroom to commit the queued two-byte grant.
    const content = try runtime.testing.receiveDataPayload(&connection, 1, .{ .header = .{ .frame_type = .data, .stream_id = 1, .flags = 0, .length = 2 }, .payload = "ab" });
    try std.testing.expectEqual(@as(u31, 2), content.adaptive_connection_increment);
    try runtime.testing.releaseReceivedDataCapacity(&connection, 1, content, false);
    try std.testing.expectEqual(window.max_value, connection.recv_connection_window.value);
    try std.testing.expectEqual(@as(?u32, null), connection.adaptive_queued_target);
    var bytes: [256]u8 = @splat(0);
    bytes[0] = 255;
    const maximum = try runtime.testing.receiveDataPayload(&connection, 1, .{ .header = .{ .frame_type = .data, .stream_id = 1, .flags = 8, .length = 256 }, .payload = &bytes });
    try std.testing.expectEqual(@as(u9, 256), maximum.padding_bytes);
    try runtime.testing.releaseReceivedDataCapacity(&connection, 1, maximum, false);
    try std.testing.expectEqual(window.max_value, connection.recv_connection_window.value);
    try std.testing.expectEqual(window.max_value, (try runtime.testing.recvStreamWindow(&connection, 1)).value);
}

test "HTTP/2 padding credit counts Pad Length byte up to maximum padding" {
    var bytes: [256]u8 = @splat(0);
    bytes[0] = 255;
    const parsed = try http2.DataPayload.parse(.{ .header = .{ .frame_type = .data, .flags = 8, .stream_id = 1, .length = 256 }, .payload = &bytes });
    try std.testing.expectEqual(@as(usize, 0), parsed.data.len);
    try std.testing.expectEqual(@as(u8, 255), parsed.padding_len);
}
