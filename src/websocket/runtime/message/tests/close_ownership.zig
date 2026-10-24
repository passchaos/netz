const std = @import("std");
const websocket = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const h3 = @import("../../h3.zig");
const http2 = @import("../../../../http2/mod.zig").runtime;
const quic = @import("../../../../quic/mod.zig");

const allocator = std.testing.allocator;
const Read = enum { typed, typed_timeout, typed_deadline, ping, close_wait };

fn receive(connection: anytype, operation: Read, io: std.Io) !?websocket.OwnedCloseFrame {
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    return switch (operation) {
        .typed => connection.receiveCloseFrame(),
        .typed_timeout => connection.receiveCloseFrameWithTimeout(.fromSeconds(1)),
        .typed_deadline => connection.receiveCloseFrameWithDeadline(deadline),
        .ping => blk: {
            const event = try connection.continuePingWithDeadline("probe", deadline);
            if (event != .closed) return error.TestUnexpectedResult;
            break :blk event.closed;
        },
        .close_wait => blk: {
            const event = try connection.closeWithDeadline(null, deadline);
            if (event != .closed) return error.TestUnexpectedResult;
            break :blk event.closed;
        },
    };
}

fn exercise(connection: anytype, role: runtime.Role, io: std.Io) !void {
    const longest = [_]u8{'x'} ** 123;
    for ([_]?[]const u8{ null, "", "peer diagnosis", &longest }) |reason| {
        for (std.enums.values(Read)) |operation| {
            connection.close_sent.store(true, .release);
            connection.close_received.store(false, .release);
            connection.inbuf_consumed = 0;
            connection.incoming_frame_validated = 0;
            connection.inbuf.clearRetainingCapacity();
            var storage: [125]u8 = undefined;
            const payload = try websocket.writeClosePayloadInto(&storage, if (reason) |text| .{ .code = .going_away, .reason = text } else null);
            try websocket.writeFrame(&connection.inbuf, allocator, .close, payload, .{ .mask_key = if (role == .server) .{ 1, 2, 3, 4 } else null });
            // The existing frame payload allocation succeeds. A second allocation
            // for Close metadata must not be needed after the frame is consumed.
            var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 1 });
            connection.allocator = failing.allocator();
            defer connection.allocator = allocator;
            var close = try receive(connection, operation, io);
            defer if (close) |*value| value.deinit(connection.allocator);
            try std.testing.expect(!failing.has_induced_failure);
            try std.testing.expectEqual(@as(usize, if (reason != null) 1 else 0), failing.allocations);
            if (reason) |text| {
                try std.testing.expectEqual(websocket.CloseCode.going_away, close.?.code);
                try std.testing.expectEqualStrings(text, close.?.reason);
            } else try std.testing.expect(close == null);
            try std.testing.expect(connection.close_received.load(.acquire));
            // Reusing the receive buffer must not affect the owned diagnosis.
            @memset(connection.inbuf.items, 0xaa);
            if (reason) |text| try std.testing.expectEqualStrings(text, close.?.reason);
            try std.testing.expectError(error.ConnectionClosed, connection.receiveCloseFrame());
        }
    }
}

test "WebSocket HTTP1 Close metadata takes frame ownership without post-consume allocation" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for (std.enums.values(runtime.Role)) |role| {
        var connection = runtime.Connection{ .allocator = allocator, .io = threaded.io(), .stream = undefined, .role = role };
        defer connection.inbuf.deinit(allocator);
        try exercise(&connection, role, threaded.io());
    }
}

test "WebSocket HTTP2 Close metadata takes frame ownership without post-consume allocation" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var transport: http2.Connection = undefined;
    transport.io = threaded.io();
    for (std.enums.values(runtime.Role)) |role| {
        var connection = runtime.H2Connection{ .allocator = allocator, .tunnel = .{ .connection = &transport, .stream_id = 1 }, .role = role };
        defer connection.inbuf.deinit(allocator);
        try exercise(&connection, role, threaded.io());
    }
}

test "WebSocket HTTP3 Close metadata takes frame ownership without post-consume allocation" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{});
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0x31} ** quic.protection.secret_len);
    inline for (.{ runtime.Role.client, runtime.Role.server }) |role| {
        var connection = h3.Connection(role){ .allocator = allocator, .stream_id = 0, .h3 = undefined };
        connection.h3.established.connection = try quic.one_rtt.Connection.init(&endpoint, .{ .peer = endpoint.address(), .receive_keys = keys, .send_keys = keys, .local_connection_id = "close-owner", .peer_connection_id = "close-peer", .local_endpoint = if (role == .client) .client else .server, .enable_pacing = false });
        defer connection.h3.established.connection.deinit();
        defer connection.inbuf.deinit(allocator);
        try exercise(&connection, role, threaded.io());
    }
}

test "WebSocket real TCP Close diagnosis survives the connection owner" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    inline for (.{ runtime.Role.client, runtime.Role.server }) |role| {
        inline for (.{ .typed, .ping, .close_wait }) |operation| {
            var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
            defer listener.deinit(io);
            const sender = try listener.socket.address.connect(io, .{ .mode = .stream });
            defer sender.close(io);
            const stream = try listener.accept(io);
            var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 1 });
            var connection = runtime.testing.initDirectConnection(allocator, io, stream, role, .{});
            var owned = true;
            defer if (owned) connection.close();
            try connection.inbuf.ensureTotalCapacityPrecise(allocator, 256);
            connection.allocator = failing.allocator();
            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(allocator);
            var storage: [125]u8 = undefined;
            const payload = try websocket.writeClosePayloadInto(&storage, .{ .code = .going_away, .reason = "peer diagnosis" });
            try websocket.writeFrame(&encoded, allocator, .close, payload, .{ .mask_key = if (role == .server) .{ 1, 2, 3, 4 } else null });
            var writer = sender.writer(io, &.{});
            try writer.interface.writeAll(encoded.items);
            var close = (switch (operation) {
                .typed => try connection.receiveCloseFrameWithTimeout(.fromSeconds(1)),
                .ping => blk: {
                    const event = try connection.pingWithTimeout("probe", .fromSeconds(1));
                    try std.testing.expect(event == .closed);
                    break :blk event.closed;
                },
                .close_wait => blk: {
                    const event = try connection.closeWithTimeout(.{ .code = .normal_closure }, .fromSeconds(1));
                    try std.testing.expect(event == .closed);
                    break :blk event.closed;
                },
                else => unreachable,
            }).?;
            defer close.deinit(allocator);
            try std.testing.expect(!failing.has_induced_failure);
            try std.testing.expectEqual(@as(usize, 1), failing.allocations);
            connection.close();
            owned = false;
            try std.testing.expectEqual(websocket.CloseCode.going_away, close.code);
            try std.testing.expectEqualStrings("peer diagnosis", close.reason);
        }
    }
}

test "WebSocket Close frame allocation failure preserves a typed diagnostic retry" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var connection = runtime.Connection{ .allocator = allocator, .io = threaded.io(), .stream = undefined, .role = .client, .close_sent = .init(true) };
    defer connection.inbuf.deinit(allocator);
    try websocket.writeFrame(&connection.inbuf, allocator, .close, "\x03\xe9diagnosis", .{});
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    connection.allocator = failing.allocator();
    try std.testing.expectError(error.OutOfMemory, connection.receiveCloseFrame());
    try std.testing.expect(!connection.close_received.load(.acquire));
    try std.testing.expect(!connection.receive_failed.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), connection.inbuf_consumed);
    failing.fail_index = std.math.maxInt(usize);
    var close = (try connection.receiveCloseFrame()).?;
    defer close.deinit(allocator);
    try std.testing.expectEqualStrings("diagnosis", close.reason);
}
