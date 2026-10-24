const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const allocator = std.testing.allocator;

test "HTTP/2 frame retention owned copy OOM preserves current and following frames" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var connection = runtime.Connection{ .io = threaded.io(), .allocator = allocator, .stream = undefined, .role = .server, .last_peer_frame_at = .zero };
    defer connection.frame_reader.deinit(allocator);
    try (http2.Frame{ .header = .{ .length = 5, .frame_type = .data, .flags = 0, .stream_id = 1 }, .payload = "first" }).write(&connection.frame_reader.buffer, allocator);
    try (http2.Frame{ .header = .{ .length = 4, .frame_type = .data, .flags = 1, .stream_id = 1 }, .payload = "next" }).write(&connection.frame_reader.buffer, allocator);
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    connection.allocator = failing.allocator();
    try std.testing.expectError(error.OutOfMemory, runtime.testing.readOwnedFrame(&connection));
    try std.testing.expect(failing.has_induced_failure);
    const received_at = connection.last_peer_frame_at;
    const start = connection.frame_reader.start;
    try std.testing.expectError(error.OutOfMemory, runtime.testing.readOwnedFrame(&connection));
    try std.testing.expectEqual(start, connection.frame_reader.start);
    try std.testing.expectEqual(received_at, connection.last_peer_frame_at);
    connection.allocator = allocator;
    var first = try runtime.testing.readOwnedFrame(&connection);
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("first", first.frame.payload);
    try std.testing.expectEqual(received_at, connection.last_peer_frame_at);
    var next = try runtime.testing.readOwnedFrame(&connection);
    defer next.deinit(allocator);
    try std.testing.expectEqualStrings("next", next.frame.payload);
}

test "HTTP/2 frame retention real TCP copy OOM keeps received bytes after peer FIN" {
    const stream_io = @import("../../../internal/stream_io.zig");
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const sender = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer sender.close(io);
    const peer = try listener.accept(io);
    defer peer.close(io);
    var connection = runtime.Connection{ .io = io, .allocator = allocator, .stream = sender, .role = .server };
    defer connection.frame_reader.deinit(allocator);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try (http2.Frame{ .header = .{ .length = 5, .frame_type = .data, .flags = 0, .stream_id = 1 }, .payload = "first" }).write(&bytes, allocator);
    try (http2.Frame{ .header = .{ .length = 4, .frame_type = .data, .flags = 1, .stream_id = 1 }, .payload = "next" }).write(&bytes, allocator);
    try stream_io.writeAllSlices(io, peer, &.{bytes.items});
    try peer.shutdown(io, .send);
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 1 });
    connection.allocator = failing.allocator();
    try std.testing.expectError(error.OutOfMemory, runtime.testing.readOwnedFrame(&connection));
    connection.allocator = allocator;
    var first = try runtime.testing.readOwnedFrame(&connection);
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("first", first.frame.payload);
    var next = try runtime.testing.readOwnedFrame(&connection);
    defer next.deinit(allocator);
    try std.testing.expectEqualStrings("next", next.frame.payload);
    try std.testing.expectError(error.ConnectionClosed, runtime.testing.readOwnedFrame(&connection));
}

test "HTTP/2 frame retention SETTINGS processing needs no secondary allocation" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const sender = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer sender.close(io);
    const receiver = try listener.accept(io);
    defer receiver.close(io);
    var connection = runtime.Connection{ .io = io, .allocator = allocator, .stream = sender, .role = .client };
    defer connection.frame_reader.deinit(allocator);
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try http2.writeSettings(&payload, allocator, &.{
        .{ .id = .max_frame_size, .value = 32768 },
        .{ .id = .max_concurrent_streams, .value = 7 },
        .{ .id = .enable_connect_protocol, .value = 1 },
        .{ .id = .max_concurrent_streams, .value = 9 },
        .{ .id = @enumFromInt(0xffff), .value = 0xffffffff },
        .{ .id = .no_rfc7540_priorities, .value = 1 },
    });
    try (http2.Frame{ .header = .{ .length = @intCast(payload.items.len), .frame_type = .settings, .flags = 0, .stream_id = 0 }, .payload = payload.items }).write(&connection.frame_reader.buffer, allocator);
    const probe: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    try (http2.Frame{ .header = .{ .length = 8, .frame_type = .ping, .flags = 1, .stream_id = 0 }, .payload = &probe }).write(&connection.frame_reader.buffer, allocator);
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    connection.allocator = failing.allocator();
    defer connection.allocator = allocator;
    try std.testing.expectEqualSlices(u8, &probe, &(try connection.pingWithTimeout(probe, .fromSeconds(1))));
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 32768), connection.peer_max_frame_size);
    try std.testing.expectEqual(@as(?u32, 9), connection.peerMaxConcurrentStreams());
    try std.testing.expect(connection.peerExtendedConnectEnabled());
    try std.testing.expect(connection.peer_no_rfc7540_priorities);
}

test "HTTP/2 frame retention PING queue copy OOM retains application frame" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const sender = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer sender.close(io);
    const peer = try listener.accept(io);
    defer peer.close(io);
    var connection = runtime.Connection{ .io = io, .allocator = allocator, .stream = sender, .role = .server };
    defer connection.frame_reader.deinit(allocator);
    try (http2.Frame{ .header = .{ .length = 5, .frame_type = .data, .flags = 1, .stream_id = 1 }, .payload = "first" }).write(&connection.frame_reader.buffer, allocator);
    const probe: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };
    try (http2.Frame{ .header = .{ .length = 8, .frame_type = .ping, .flags = 1, .stream_id = 0 }, .payload = &probe }).write(&connection.frame_reader.buffer, allocator);
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    connection.allocator = failing.allocator();
    try std.testing.expectError(error.OutOfMemory, connection.pingWithTimeout(probe, .fromSeconds(1)));
    connection.allocator = allocator;
    var first = try runtime.testing.readOwnedFrame(&connection);
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("first", first.frame.payload);
    var ack = try runtime.testing.readOwnedFrame(&connection);
    defer ack.deinit(allocator);
    try std.testing.expectEqual(http2.FrameType.ping, ack.frame.header.frame_type);
    try std.testing.expectEqualSlices(u8, &probe, ack.frame.payload);
}

test "HTTP/2 frame retention SETTINGS validates all values before application" {
    var payload = [_]u8{ 0, 3, 0, 0, 0, 9, 0, 4, 0x80, 0, 0, 0 };
    try std.testing.expectError(error.InvalidSetting, http2.SettingsIterator.init(&payload));
    try std.testing.expectError(error.InvalidSetting, http2.parseSettings(std.testing.failing_allocator, &payload));
    try std.testing.expectError(error.InvalidSetting, http2.SettingsIterator.init(payload[0..11]));
    payload[8] = 0;
    var iterator = try http2.SettingsIterator.init(&payload);
    try std.testing.expectEqual(http2.SettingId.max_concurrent_streams, iterator.next().?.id);
    try std.testing.expectEqual(@as(u32, 0), iterator.next().?.value);
    try std.testing.expect(iterator.next() == null);
}

test "HTTP/2 frame retention queued owning borrow transfers without allocation" {
    var connection = runtime.Connection{ .io = undefined, .allocator = allocator, .stream = undefined, .role = .server };
    defer runtime.testing.deinitPendingApplicationFrames(&connection);
    var bytes: std.ArrayList(u8) = .empty;
    try (http2.Frame{ .header = .{ .length = 5, .frame_type = .data, .flags = 0, .stream_id = 1 }, .payload = "first" }).write(&bytes, allocator);
    const owned = try bytes.toOwnedSlice(allocator);
    const frame = try http2.Frame.parse(owned);
    connection.borrowed_pending_frame.value = .{ .bytes = owned, .frame = frame };
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    connection.allocator = failing.allocator();
    var copied = try runtime.testing.copyBorrowedFrame(&connection, .{ .bytes = owned, .frame = frame });
    defer copied.deinit(allocator);
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(owned.ptr, copied.bytes.ptr);
    try std.testing.expectEqual(@as(usize, 0), connection.borrowed_pending_frame.value.bytes.len);
}

test "HTTP/2 frame retention direct copy retry commits the retained span once" {
    const Reader = @import("io.zig").Reader;
    var reader: Reader = .{};
    defer reader.deinit(allocator);
    try (http2.Frame{ .header = .{ .length = 5, .frame_type = .data, .flags = 0, .stream_id = 1 }, .payload = "first" }).write(&reader.buffer, allocator);
    try (http2.Frame{ .header = .{ .length = 4, .frame_type = .data, .flags = 1, .stream_id = 1 }, .payload = "next" }).write(&reader.buffer, allocator);
    const first = try reader.read(allocator, undefined, undefined, 1024);
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, reader.copyOwned(failing.allocator(), first));
    var copied = try reader.copyOwned(allocator, first);
    defer copied.deinit(allocator);
    try std.testing.expectEqualStrings("first", copied.frame.payload);
    const next = try reader.read(allocator, undefined, undefined, 1024);
    try std.testing.expectEqualStrings("next", next.frame.payload);
}
