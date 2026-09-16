const std = @import("std");
const quic = @import("../../mod.zig");
const one_rtt = @import("../../one_rtt.zig");

test "QUIC one-RTT connection omits plaintext staging scratch" {
    const allocator = std.testing.allocator;
    const max_datagram_size: usize = 1400;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd1} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "scratch-local",
        .peer_connection_id = "scratch-peer",
        .max_datagram_size = max_datagram_size,
    });
    defer connection.deinit();

    try std.testing.expect(
        connection.scratch.send_packet.capacity >= max_datagram_size,
    );
    try std.testing.expect(connection.scratch.receive_packet.capacity >= 4096);
    try std.testing.expect(connection.scratch.receive_ack_ranges.capacity >= 64);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.scratch.receive_frames.capacity,
    );
}

test "QUIC mixed send encodes directly into protected scratch" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd2} ** quic.protection.secret_len,
    );

    var connection = try one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "scratch-local",
        .peer_connection_id = "scratch-peer",
        .enable_pacing = false,
    });
    defer connection.deinit();
    try connection.sent.packets.ensureTotalCapacity(allocator, 2);

    const warm_frames = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = "transactional",
    } }};
    try connection.sendAt(&warm_frames, 50);
    var warm = try receiver.receiveBytes();
    defer warm.deinit(allocator);
    var opened_warm = try one_rtt.openReceivedBytes(
        &receiver,
        warm.from,
        warm.bytes,
        keys,
        "scratch-peer".len,
        0,
        8,
    );
    defer opened_warm.deinit(allocator);
    const ack = quic.AckFrame{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    };
    _ = try connection.recovery.applyAck(ack);
    _ = try connection.sent.applyAck(ack);

    const frames = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = 0,
            .offset = "transactional".len,
            .data = "transactional",
            .fin = true,
        } },
        .{ .padding = .{ .len = 8 } },
    };
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    sender.allocator = failing.allocator();
    defer sender.allocator = allocator;
    failing.fail_index = failing.alloc_index;
    failing.resize_fail_index = failing.resize_index;
    try connection.sendAt(&frames, 100);
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(
        @as(u64, 2),
        one_rtt.testing.nextPacketNumber(&connection),
    );
    try std.testing.expectEqual(@as(usize, 2), connection.sent.packets.items.len);
    try std.testing.expect(connection.bytesInFlight() > 0);
    try std.testing.expectEqual(@as(?u64, 26), one_rtt.testing.sendStreamUsed(&connection, 0));

    var received = try receiver.receiveBytes();
    defer received.deinit(allocator);
    var opened = try one_rtt.openReceivedBytes(
        &receiver,
        received.from,
        received.bytes,
        keys,
        "scratch-peer".len,
        1,
        8,
    );
    defer opened.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), opened.frames.len);
    try std.testing.expect(opened.frames[0] == .stream);
    try std.testing.expectEqual(@as(u64, 13), opened.frames[0].stream.offset);
    try std.testing.expectEqualStrings(
        "transactional",
        opened.frames[0].stream.data,
    );
    try std.testing.expect(opened.frames[0].stream.fin);
    try std.testing.expect(opened.frames[1] == .padding);
    try std.testing.expectEqual(@as(usize, 8), opened.frames[1].padding.len);
}

test "QUIC one-RTT connection reuses protected send scratch" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();

    var counting = std.testing.FailingAllocator.init(allocator, .{});
    const connection_allocator = counting.allocator();
    var local_endpoint = try quic.runtime.Endpoint.bind(
        connection_allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer local_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x7a} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&local_endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
        .max_datagram_size = 4096,
    });
    defer connection.deinit();
    try connection.sent.packets.ensureTotalCapacity(connection_allocator, 2);

    const payload = [_]quic.Frame{.{ .padding = .{ .len = 32 } }};
    try connection.sendAt(&payload, 100);
    const packet_capacity = connection.scratch.send_packet.capacity;
    const packet_ptr = connection.scratch.send_packet.allocatedSlice().ptr;
    counting.fail_index = counting.alloc_index;
    counting.resize_fail_index = counting.resize_index;
    try connection.sendAt(&payload, 200);
    try std.testing.expect(!counting.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 2), connection.sent.packets.items.len);
    try std.testing.expectEqual(packet_capacity, connection.scratch.send_packet.capacity);
    try std.testing.expectEqual(packet_ptr, connection.scratch.send_packet.allocatedSlice().ptr);
}

test "QUIC one-RTT connection reuses receive scratch" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();
    const client_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const server_cid = [_]u8{ 0x81, 0x82, 0x83, 0x84 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x91} ** quic.protection.secret_len,
    );
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    var receive_storage: ?[*]u8 = null;
    var frame_storage: ?[*]quic.Frame = null;
    var ack_storage: ?[*]quic.AckRange = null;
    for (0..2) |packet_number| {
        try one_rtt.sendFrames(
            &client_endpoint,
            server_endpoint.address(),
            keys,
            .{
                .destination_connection_id = &server_cid,
                .packet_number = packet_number,
                .frames = &.{.{ .stream = .{
                    .stream_id = 0,
                    .offset = packet_number,
                    .data = "x",
                    .fin = packet_number == 1,
                } }},
            },
        );
        try server.servicePacketAt(1_000 + packet_number);
        if (receive_storage) |expected| {
            try std.testing.expectEqual(
                expected,
                server.scratch.receive_packet.allocatedSlice().ptr,
            );
            try std.testing.expectEqual(
                frame_storage.?,
                server.scratch.receive_frames.allocatedSlice().ptr,
            );
            try std.testing.expectEqual(
                ack_storage.?,
                server.scratch.receive_ack_ranges.allocatedSlice().ptr,
            );
        } else {
            receive_storage = server.scratch.receive_packet.allocatedSlice().ptr;
            frame_storage = server.scratch.receive_frames.allocatedSlice().ptr;
            ack_storage = server.scratch.receive_ack_ranges.allocatedSlice().ptr;
        }
    }
    try std.testing.expectEqualStrings(
        "xx",
        server.availableReceivedStream(0).?,
    );
}
