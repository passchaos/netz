const std = @import("std");
const quic = @import("../../mod.zig");
const one_rtt = @import("../../one_rtt.zig");
const net = std.Io.net;
const ObservedBatchSend = @import("observed_batch_send.zig").ObservedBatchSend;

test "QUIC peer stream identifier predicate honors role direction and limit" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0x81} ** 32);
    var server = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "server",
        .peer_connection_id = "client",
        .local_endpoint = .server,
        .initial_receive_max_streams_bidi = 2,
        .initial_receive_max_streams_uni = 1,
    });
    defer server.deinit();

    try std.testing.expect(server.isPeerInitiatedStreamIdWithinLimit(0));
    try std.testing.expect(server.isPeerInitiatedStreamIdWithinLimit(4));
    try std.testing.expect(!server.isPeerInitiatedStreamIdWithinLimit(8));
    try std.testing.expect(server.isPeerInitiatedStreamIdWithinLimit(2));
    try std.testing.expect(
        server.isPeerInitiatedBidirectionalStreamIdWithinLimit(0),
    );
    try std.testing.expect(
        !server.isPeerInitiatedBidirectionalStreamIdWithinLimit(2),
    );
    try std.testing.expect(!server.isPeerInitiatedStreamIdWithinLimit(6));
    try std.testing.expect(!server.isPeerInitiatedStreamIdWithinLimit(1));
    try std.testing.expect(
        !server.isPeerInitiatedStreamIdWithinLimit(std.math.maxInt(u64)),
    );

    var client = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "client",
        .peer_connection_id = "server",
        .local_endpoint = .client,
        .initial_receive_max_streams_bidi = 2,
        .initial_receive_max_streams_uni = 1,
    });
    defer client.deinit();
    try std.testing.expect(
        client.isPeerInitiatedBidirectionalStreamIdWithinLimit(1),
    );
    try std.testing.expect(
        client.isPeerInitiatedBidirectionalStreamIdWithinLimit(5),
    );
    try std.testing.expect(
        !client.isPeerInitiatedBidirectionalStreamIdWithinLimit(9),
    );
    try std.testing.expect(client.isPeerInitiatedStreamIdWithinLimit(3));
    try std.testing.expect(!client.isPeerInitiatedStreamIdWithinLimit(7));
    try std.testing.expect(!client.isPeerInitiatedStreamIdWithinLimit(0));
}

test "QUIC local close information is available before peer acknowledgement" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0x82} ** 32);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
        .enable_pacing = false,
    });
    defer connection.deinit();

    try std.testing.expect(one_rtt.testing.localCloseInfo(&connection) == null);
    try connection.closeApplication(0x108, "invalid element");
    const close = one_rtt.testing.localCloseInfo(&connection) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(close.application);
    try std.testing.expectEqual(@as(u64, 0x108), close.error_code);
    try std.testing.expectEqual(@as(u64, 0), close.frame_type);
    try std.testing.expectEqualStrings("invalid element", close.reason_phrase);
}

const PayloadSendOptionsForTest = struct {
    destination_connection_id: []const u8,
    packet_number: u64,
    packet_number_len: u8 = 4,
    spin_bit: bool = false,
    key_phase: bool = false,
    payload: []const u8,
};

fn allEqualForTest(comptime T: type, values: []const T, expected: T) bool {
    for (values) |value| {
        if (value != expected) return false;
    }
    return true;
}

fn sendPayloadForTest(
    endpoint: *quic.runtime.Endpoint,
    peer: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    options: PayloadSendOptionsForTest,
) one_rtt.Error!void {
    const packet = try quic.protection.sealShortPacket(
        endpoint.allocator,
        keys,
        .{
            .destination_connection_id = options.destination_connection_id,
            .packet_number = options.packet_number,
            .packet_number_len = options.packet_number_len,
            .spin_bit = options.spin_bit,
            .key_phase = options.key_phase,
            .payload = options.payload,
        },
    );
    defer endpoint.allocator.free(packet);
    try endpoint.sendBytes(peer, packet);
}

fn trafficSecretForSuiteForTest(
    suite: quic.protection.CipherSuite,
) quic.tls.secret.Secret {
    return switch (suite.hash()) {
        .sha256 => .fromSha256([_]u8{0x84} ** 32),
        .sha384 => .fromSha384([_]u8{0x85} ** 48),
        .sm3 => .fromSm3([_]u8{0x86} ** 32),
    };
}

fn expectSingleStreamReceiveForSuite(
    allocator: std.mem.Allocator,
    io: std.Io,
    suite: quic.protection.CipherSuite,
) !void {
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

    const keys = try quic.protection.deriveKeysForSecretForVersion(
        quic.Version.version_1.wireValue(),
        suite,
        trafficSecretForSuiteForTest(suite),
    );
    const client_cid = [_]u8{ 0x81, 0x82, 0x83, 0x84 };
    const server_cid = [_]u8{ 0x85, 0x86, 0x87, 0x88 };
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();
    const expects_prepared =
        quic.protection.prepared_packet_protection_enabled and switch (suite) {
            .aes_128_gcm_sha256, .aes_256_gcm_sha384 => true,
            else => false,
        };
    try std.testing.expectEqual(
        expects_prepared,
        one_rtt.testing.hasPreparedSendPacketProtection(&client),
    );
    try std.testing.expectEqual(
        expects_prepared,
        one_rtt.testing.hasPreparedReceivePacketProtection(&client),
    );
    try std.testing.expectEqual(
        expects_prepared,
        one_rtt.testing.hasPreparedSendPacketProtection(&server),
    );
    try std.testing.expectEqual(
        expects_prepared,
        one_rtt.testing.hasPreparedReceivePacketProtection(&server),
    );

    try client.send(&[_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = "suite stream",
        .fin = true,
    } }});
    var packet = try server.receivePacket();
    defer packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), packet.frames.len);
    try std.testing.expectEqualStrings(
        "suite stream",
        packet.frames[0].stream.data,
    );

    var storage: [32]u8 = undefined;
    const event = (try server.pollStreamId(0, &storage)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(event == .data);
    try std.testing.expectEqualStrings(
        "suite stream",
        storage[0..event.data.bytes],
    );
    try std.testing.expect(event.data.fin);

    try client.initiateKeyUpdate();
    try client.send(&[_]quic.Frame{.{ .stream = .{
        .stream_id = 4,
        .data = "updated suite stream",
        .fin = true,
    } }});
    var updated = try server.receivePacket();
    defer updated.deinit(allocator);
    try std.testing.expect(updated.peer_initiated_key_update);
    try std.testing.expect(updated.packet.key_phase);

    const updated_event = (try server.pollStreamId(4, &storage)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(updated_event == .data);
    try std.testing.expectEqualStrings(
        "updated suite stream",
        storage[0..updated_event.data.bytes],
    );
    try std.testing.expect(updated_event.data.fin);

    // The first updated packet takes the owning key-transition path above. A
    // second packet in that generation must use the refreshed prepared current
    // key in servicePacket's allocation-free receive path.
    try client.send(&[_]quic.Frame{.{ .stream = .{
        .stream_id = 8,
        .data = "prepared current generation",
        .fin = true,
    } }});
    try server.servicePacket();
    const current_event = (try server.pollStreamId(8, &storage)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(current_event == .data);
    try std.testing.expectEqualStrings(
        "prepared current generation",
        storage[0..current_event.data.bytes],
    );
    try std.testing.expect(current_event.data.fin);
}

test "QUIC 1-RTT single STREAM receive and key update support every traffic suite" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const suites = [_]quic.protection.CipherSuite{
        .aes_128_gcm_sha256,
        .aes_256_gcm_sha384,
        .chacha20_poly1305_sha256,
        .sm4_gcm_sm3,
    };
    inline for (suites) |suite| {
        try expectSingleStreamReceiveForSuite(allocator, io, suite);
    }
}

test "QUIC 1-RTT consumes a preloaded coalesced-handshake suffix first" {
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
        [_]u8{0x8f} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "server",
        .peer_connection_id = "client",
    });
    defer connection.deinit();

    const payload = [_]quic.Frame{.{ .stream = .{
        .stream_id = 3,
        .data = "client control",
        .fin = false,
    } }};
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try payload[0].write(&encoded, allocator);
    const packet = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = "server",
        .packet_number = 3,
        .payload = encoded.items,
    });
    defer allocator.free(packet);
    // `preloadReceivedDatagram` takes a copy, matching the handshake's need to
    // release the larger coalesced UDP receive buffer before returning.
    try connection.preloadReceivedDatagram(sender.address(), packet, .ect0);
    try std.testing.expectError(
        error.InvalidPacket,
        connection.preloadReceivedDatagram(sender.address(), packet, .not_ect),
    );

    const Visitor = struct {
        fn visit(called: *usize, _: one_rtt.ReceivedPacketView) error{}!void {
            called.* += 1;
        }
    };
    var visitor_calls: usize = 0;
    const wrong_clock: std.Io.Clock.Timestamp = .{
        .clock = .real,
        .raw = .zero,
    };
    const expired: std.Io.Clock.Timestamp = .{
        .clock = .awake,
        .raw = .zero,
    };
    try std.testing.expectError(
        error.Timeout,
        connection.receivePacketServicingTimersDeadline(wrong_clock),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.receivePacketBatchServicingTimersDeadline(expired),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.servicePacketBatchServicingTimersDeadline(wrong_clock),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.visitPacketServicingTimersDeadline(
            expired,
            &visitor_calls,
            Visitor.visit,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.servicePacketServicingTimersDeadline(wrong_clock),
    );
    try std.testing.expectEqual(@as(usize, 0), visitor_calls);

    // Every rejected operation above must leave the preloaded datagram intact.
    var received = try connection.receivePacketServicingTimersDeadline(
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    defer received.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 3), received.packet.packet_number);
    try std.testing.expectEqual(@as(usize, 1), received.frames.len);
    try std.testing.expectEqualStrings(
        "client control",
        received.frames[0].stream.data,
    );

    try connection.preloadReceivedDatagram(sender.address(), packet, .ect0);
    const fresh = [_]quic.Frame{.{ .ping = {} }};
    try one_rtt.sendFrames(&sender, receiver.address(), keys, .{
        .destination_connection_id = "server",
        .packet_number = 4,
        .frames = &fresh,
    });
    var after_duplicate = try connection
        .receivePacketBatchServicingTimersDeadline(.fromNow(io, .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    }));
    defer after_duplicate.deinit();
    try std.testing.expectEqual(@as(usize, 1), after_duplicate.packets.len);
    try std.testing.expectEqual(
        @as(u64, 4),
        after_duplicate.packets[0].packet.packet_number,
    );
    try std.testing.expectError(
        error.InvalidPacket,
        connection.preloadReceivedDatagram(sender.address(), &.{}, .not_ect),
    );
}

test "QUIC 1-RTT batch send protects consecutive packets" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var receiver = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer sender.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0xb1} ** quic.protection.secret_len);
    const packet0 = [_]quic.Frame{
        .{ .ping = {} },
        .{ .stream = .{ .stream_id = 0, .data = "first", .fin = false } },
    };
    const packet1 = [_]quic.Frame{.{ .datagram = .{ .data = "second", .length_present = true } }};
    const packet2 = [_]quic.Frame{.{ .path_challenge = .{ .data = [_]u8{3} ** 8 } }};
    const packets = [_][]const quic.Frame{ &packet0, &packet1, &packet2 };
    const options: one_rtt.BatchSendOptions = .{
        .destination_connection_id = "batch-cid",
        .first_packet_number = 40,
        .packet_number_len = 2,
        .packets = &packets,
    };
    const sizes = try one_rtt.batchStorageSizes(options);
    const payload_storage = try allocator.alloc(u8, sizes.payload);
    defer allocator.free(payload_storage);
    const packet_storage = try allocator.alloc(u8, sizes.packet);
    defer allocator.free(packet_storage);

    const written = try one_rtt.sendFramesBatchInto(
        &sender,
        receiver.address(),
        keys,
        options,
        payload_storage,
        packet_storage,
    );
    try std.testing.expectEqual(sizes.packet, written);

    for (packets, 0..) |expected_frames, i| {
        var received = try one_rtt.receive(&receiver, keys, "batch-cid".len, 40 + i, 8);
        defer received.deinit(allocator);
        try std.testing.expectEqual(@as(u64, @intCast(40 + i)), received.packet.packet_number);
        try std.testing.expectEqual(expected_frames.len, received.frames.len);
        for (expected_frames, received.frames) |expected, actual| {
            try std.testing.expectEqual(@intFromEnum(expected), @intFromEnum(actual));
        }
    }
}

test "QUIC 1-RTT batch progress retains protected count after interceptor allocation failure" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const AlwaysHold = struct {
        fn hold(_: *anyopaque, _: []const u8) bool {
            return true;
        }
    };
    var interceptor_context: u8 = 0;
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 4096,
            .send_interceptor = .{
                .context = &interceptor_context,
                .should_hold = AlwaysHold.hold,
            },
        },
    );
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb2} ** quic.protection.secret_len,
    );
    const first = [_]quic.Frame{.{ .ping = {} }};
    const second = [_]quic.Frame{.{ .ping = {} }};
    const packets = [_][]const quic.Frame{ &first, &second };
    const options: one_rtt.BatchSendOptions = .{
        .destination_connection_id = "batch-cid",
        .first_packet_number = 9,
        .packets = &packets,
    };
    const sizes = try one_rtt.batchStorageSizes(options);
    const payload_storage = try allocator.alloc(u8, sizes.payload);
    defer allocator.free(payload_storage);
    const packet_storage = try allocator.alloc(u8, sizes.packet);
    defer allocator.free(packet_storage);

    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    endpoint.allocator = failing.allocator();
    defer endpoint.allocator = allocator;
    const result = try one_rtt.sendFramesBatchIntoProgress(
        &endpoint,
        endpoint.address(),
        keys,
        options,
        payload_storage,
        packet_storage,
    );
    try std.testing.expectEqual(@as(usize, 0), result.sent_count);
    try std.testing.expectEqual(@as(usize, 2), result.protected_count);
    try std.testing.expectEqual(@as(usize, 0), result.sent_bytes);
    try std.testing.expect(result.send_error.? == error.OutOfMemory);
    try std.testing.expect(failing.has_induced_failure);
}

test "QUIC 1-RTT caller-buffer single send matches wire and allocates nothing" {
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
        [_]u8{0x93} ** quic.protection.secret_len,
    );
    const frames = [_]quic.Frame{
        .{ .ping = {} },
        .{ .datagram = .{ .data = "caller storage", .length_present = true } },
    };
    const options: one_rtt.SendOptions = .{
        .destination_connection_id = "single-cid",
        .packet_number = 17,
        .packet_number_len = 2,
        .frames = &frames,
    };
    const sizes = try one_rtt.framePacketStorageSizes(options);
    var packet_storage: [256]u8 = undefined;
    try std.testing.expect(sizes.packet <= packet_storage.len);

    var fail = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    const original_allocator = sender.allocator;
    sender.allocator = fail.allocator();
    errdefer sender.allocator = original_allocator;
    try one_rtt.sendFramesInto(
        &sender,
        receiver.address(),
        keys,
        options,
        &packet_storage,
    );
    sender.allocator = original_allocator;
    try std.testing.expect(!fail.has_induced_failure);

    var received = try one_rtt.receive(
        &receiver,
        keys,
        "single-cid".len,
        17,
        4,
    );
    defer received.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 17), received.packet.packet_number);
    try std.testing.expectEqual(@as(usize, 2), received.frames.len);
    try std.testing.expectEqualStrings(
        "caller storage",
        received.frames[1].datagram.data,
    );
}

test "QUIC 1-RTT caller-buffer single send rejects short storage before I/O" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x94} ** quic.protection.secret_len,
    );
    const options: one_rtt.SendOptions = .{
        .destination_connection_id = "cid",
        .packet_number = 1,
        .frames = &.{.{ .ping = {} }},
    };
    const sizes = try one_rtt.framePacketStorageSizes(options);
    var packet: [64]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooShort,
        one_rtt.sendFramesInto(
            &endpoint,
            endpoint.address(),
            keys,
            options,
            packet[0 .. sizes.packet - 1],
        ),
    );
}

test "QUIC 1-RTT compatibility single send allocates once" {
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
        [_]u8{0x95} ** quic.protection.secret_len,
    );
    var fail = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 1 },
    );
    const original_allocator = sender.allocator;
    sender.allocator = fail.allocator();
    errdefer sender.allocator = original_allocator;
    try one_rtt.sendFrames(
        &sender,
        receiver.address(),
        keys,
        .{
            .destination_connection_id = "receiver",
            .packet_number = 3,
            .frames = &.{.{ .ping = {} }},
        },
    );
    sender.allocator = original_allocator;
    try std.testing.expect(!fail.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 1), fail.alloc_index);

    var received = try one_rtt.receive(
        &receiver,
        keys,
        "receiver".len,
        3,
        2,
    );
    defer received.deinit(allocator);
    try std.testing.expect(received.frames[0] == .ping);
}

test "QUIC 1-RTT connection greases and accepts the fixed bit" {
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
        [_]u8{0xb7} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "sender",
        .peer_connection_id = "receiver",
        .accept_zero_fixed_bit = true,
        .grease_fixed_bit = true,
        .enable_pacing = false,
    });
    defer connection.deinit();
    try std.testing.expect(connection.fixed_bit_generator.enabled());
    const route = connection.route(7, 3);
    try std.testing.expect(route.accept_zero_fixed_bit);
    try std.testing.expectEqual(@as(usize, 7), route.connection_index);

    try connection.send(&.{.{ .ping = {} }});
    var first = try receiver.receiveBytes();
    defer first.deinit(allocator);
    // The PRNG output itself is intentionally unpredictable; the codec-level
    // test deterministically covers zero. Here, authenticate whichever value
    // the connection selected to prove runtime negotiation reaches the opener.
    var opened = try quic.protection.openShortPacketWithFixedBitPolicy(
        allocator,
        keys,
        first.bytes,
        "receiver".len,
        0,
        true,
    );
    defer opened.deinit(allocator);
    try std.testing.expectEqual(
        (first.bytes[0] & 0x40) != 0,
        opened.fixed_bit,
    );

    const zero_packet = try quic.protection.sealShortPacket(
        allocator,
        keys,
        .{
            .destination_connection_id = "sender",
            .packet_number = 0,
            .fixed_bit = false,
            .payload = &.{@intFromEnum(quic.FrameType.ping)},
        },
    );
    defer allocator.free(zero_packet);
    try std.testing.expectError(
        error.InvalidInitialPacket,
        one_rtt.openReceivedBytes(
            &sender,
            receiver.address(),
            zero_packet,
            keys,
            "sender".len,
            0,
            4,
        ),
    );
    var accepted = try one_rtt.testing.processReceivedBytesAt(
        &connection,
        receiver.address(),
        zero_packet,
        .not_ect,
        1,
    );
    defer accepted.deinit(allocator);
    try std.testing.expect(!accepted.packet.fixed_bit);
    try std.testing.expect(accepted.frames[0] == .ping);
}

test "QUIC 1-RTT receive pumps discard late long-header packets" {
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
        [_]u8{0xba} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "client",
        .peer_connection_id = "server",
        .enable_pacing = false,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "server",
        .peer_connection_id = "client",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();

    // Established connections have discarded Initial and Handshake keys. A
    // delayed retransmission in either long-header space must not be handed to
    // the 1-RTT short-header decoder or fail an otherwise healthy receive.
    try sender.sendBytes(receiver.address(), &.{0xc0});
    try client.send(&.{.{ .ping = {} }});
    var packet = try server.receivePacketServicingTimers();
    defer packet.deinit(allocator);
    try std.testing.expect(packet.frames[0] == .ping);

    try sender.sendBytes(receiver.address(), &.{0xe0});
    try client.send(&.{.{ .ping = {} }});
    try server.servicePacketServicingTimers();
    try std.testing.expectEqual(@as(u64, 2), server.stats().packets_received);

    try sender.sendBytes(receiver.address(), &.{0xc0});
    try client.send(&.{.{ .ping = {} }});
    var timed = try server.receivePacketTimeout(.{ .duration = .{
        .clock = .awake,
        .raw = .fromMilliseconds(100),
    } });
    defer timed.deinit(allocator);
    try std.testing.expect(timed.frames[0] == .ping);
    try std.testing.expectEqual(@as(u64, 3), server.stats().packets_received);

    try sender.sendBytes(receiver.address(), &.{0xc0});
    try client.send(&.{.{ .ping = {} }});
    var serviced_timed = try server.receivePacketServicingTimersTimeout(.{
        .duration = .{
            .clock = .awake,
            .raw = .fromMilliseconds(100),
        },
    });
    defer serviced_timed.deinit(allocator);
    try std.testing.expect(serviced_timed.frames[0] == .ping);
    try std.testing.expectEqual(@as(u64, 4), server.stats().packets_received);

    try sender.sendBytes(receiver.address(), &.{0xe0});
    try client.send(&.{.{ .ping = {} }});
    var batch = try server.receivePacketBatchServicingTimers();
    defer batch.deinit();
    try std.testing.expectEqual(@as(usize, 1), batch.packets.len);
    try std.testing.expect(batch.packets[0].frames[0] == .ping);
    try std.testing.expectEqual(@as(u64, 5), server.stats().packets_received);
}

test "QUIC timer-servicing receive honors caller timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x91} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "timed-local",
        .peer_connection_id = "timed-peer",
        .local_endpoint = .server,
        .tls_handshake_complete = true,
        .keep_alive_period_ms = 1,
        .enable_pacing = false,
    });
    defer connection.deinit();
    connection.markPeerActivity(0);

    try std.testing.expectError(
        error.Timeout,
        connection.servicePacketServicingTimersTimeout(.{ .duration = .{
            .clock = .awake,
            .raw = .fromMilliseconds(400),
        } }),
    );
    try std.testing.expect(connection.keepAlivePingOutstanding());
}

test "QUIC 1-RTT batch send preflights storage and all packets" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var receiver = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer sender.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0xb2} ** quic.protection.secret_len);
    const valid = [_]quic.Frame{.{ .ping = {} }};
    const invalid = [_]quic.Frame{.{ .ack_frequency = .{
        .sequence_number = std.math.maxInt(u64),
        .ack_eliciting_threshold = 1,
        .request_max_ack_delay = 1,
        .reordering_threshold = 0,
    } }};
    const packets = [_][]const quic.Frame{ &valid, &invalid };
    const options: one_rtt.BatchSendOptions = .{
        .destination_connection_id = "cid",
        .first_packet_number = 0,
        .packets = &packets,
    };
    var payload_storage: [128]u8 = undefined;
    var packet_storage: [256]u8 = undefined;
    @memset(&payload_storage, 0xa5);
    @memset(&packet_storage, 0x5a);
    try std.testing.expectError(
        error.InvalidFrameLength,
        one_rtt.sendFramesBatchInto(&sender, receiver.address(), keys, options, &payload_storage, &packet_storage),
    );
    try std.testing.expect(allEqualForTest(u8, &payload_storage, 0xa5));
    try std.testing.expect(allEqualForTest(u8, &packet_storage, 0x5a));

    const only_valid = [_][]const quic.Frame{&valid};
    const valid_options: one_rtt.BatchSendOptions = .{
        .destination_connection_id = "cid",
        .first_packet_number = 0,
        .packets = &only_valid,
    };
    const sizes = try one_rtt.batchStorageSizes(valid_options);
    try std.testing.expectError(
        error.BufferTooShort,
        one_rtt.sendFramesBatchInto(
            &sender,
            receiver.address(),
            keys,
            valid_options,
            payload_storage[0 .. sizes.payload - 1],
            &packet_storage,
        ),
    );
}

test "QUIC 1-RTT batch send allocating wrapper uses one allocation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var receiver = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer receiver.deinit();
    var counting = std.testing.FailingAllocator.init(allocator, .{});
    const sender_allocator = counting.allocator();
    var sender = try quic.runtime.Endpoint.bind(sender_allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer sender.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0xb3} ** quic.protection.secret_len);
    const ping = [_]quic.Frame{.{ .ping = {} }};
    const packets = [_][]const quic.Frame{ &ping, &ping };
    const options: one_rtt.BatchSendOptions = .{
        .destination_connection_id = "cid",
        .first_packet_number = 10,
        .packets = &packets,
    };
    const allocations_before = counting.allocations;
    try one_rtt.sendFramesBatch(&sender, receiver.address(), keys, options);
    try std.testing.expectEqual(@as(usize, 1), counting.allocations - allocations_before);
}

test "QUIC 1-RTT batch send reports a socket-sent prefix" {
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
        .{ .max_datagram_size = 4096, .enable_gso_send = false },
    );
    defer sender.deinit();

    var partial_send = ObservedBatchSend{
        .delegate = sender.io,
        .fail_after_prefix = 1,
    };
    sender.io = partial_send.io();
    defer sender.io = partial_send.delegate;

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb4} ** quic.protection.secret_len,
    );
    const first = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = "first",
    } }};
    const second = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .offset = 5,
        .data = "second",
    } }};
    const packets = [_][]const quic.Frame{ &first, &second };
    const options: one_rtt.BatchSendOptions = .{
        .destination_connection_id = "cid",
        .first_packet_number = 20,
        .packets = &packets,
    };
    const sizes = try one_rtt.batchStorageSizes(options);
    const storage = try allocator.alloc(u8, sizes.payload + sizes.packet);
    defer allocator.free(storage);

    const result = try one_rtt.sendFramesBatchIntoProgress(
        &sender,
        receiver.address(),
        keys,
        options,
        storage[0..sizes.payload],
        storage[sizes.payload..],
    );
    try std.testing.expectEqual(@as(usize, 1), result.sent_count);
    try std.testing.expectEqual(@as(usize, 2), result.protected_count);
    try std.testing.expect(result.sent_bytes != 0);
    try std.testing.expectEqual(error.NetworkDown, result.send_error.?);

    var received = try one_rtt.receive(&receiver, keys, "cid".len, 20, 8);
    defer received.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 20), received.packet.packet_number);
    try std.testing.expectEqualStrings(
        "first",
        received.frames[0].stream.data,
    );
}

test "QUIC 1-RTT STREAM frame exchange over UDP endpoint" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try quic.runtime.Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server.deinit();
    var client = try quic.runtime.Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{ .max_datagram_size = 4096 });
    defer client.deinit();

    const client_dcid = [_]u8{ 0xca, 0xfe, 0xba, 0xbe };
    const server_dcid = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0x61} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0x62} ** quic.protection.secret_len);

    const request_frames = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "GET /", .fin = true } }};
    try one_rtt.sendFrames(&client.endpoint, server.address(), client_keys, .{
        .destination_connection_id = &server_dcid,
        .packet_number = 0,
        .frames = &request_frames,
    });

    var request = try one_rtt.receive(&server.endpoint, client_keys, server_dcid.len, 0, 8);
    defer request.deinit(allocator);
    try std.testing.expect(request.from.eql(&client.address()));
    try std.testing.expectEqualSlices(u8, &server_dcid, request.packet.destination_connection_id);
    try std.testing.expectEqualStrings("GET /", request.frames[0].stream.data);

    const response_frames = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "OK", .fin = true } }};
    try one_rtt.sendFrames(&server.endpoint, request.from, server_keys, .{
        .destination_connection_id = &client_dcid,
        .packet_number = 0,
        .frames = &response_frames,
    });

    var response = try one_rtt.receive(&client.endpoint, server_keys, client_dcid.len, 0, 8);
    defer response.deinit(allocator);
    try std.testing.expect(response.from.eql(&server.address()));
    try std.testing.expectEqualSlices(u8, &client_dcid, response.packet.destination_connection_id);
    try std.testing.expectEqualStrings("OK", response.frames[0].stream.data);
}

test "QUIC 1-RTT spin bit follows enabled single-path policy" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4 };
    const server_cid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xab} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_endpoint = .client,
        .enable_spin_bit = true,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .enable_spin_bit = true,
    });
    defer server.deinit();

    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .spin_bit = true,
        .frames = &[_]quic.Frame{.{ .ping = {} }},
    });
    var first = try server.receivePacket();
    defer first.deinit(allocator);
    try std.testing.expect(first.packet.spin_bit);
    try std.testing.expect(server.nextSpinBit());

    try server.send(&[_]quic.Frame{.{ .ping = {} }});
    var response = try client.receivePacket();
    defer response.deinit(allocator);
    try std.testing.expect(response.packet.spin_bit);
    try std.testing.expect(!client.nextSpinBit());

    client.resetSpinBit();
    try std.testing.expect(!client.nextSpinBit());
}

test "QUIC 1-RTT spin bit ignores reordered lower packet numbers" {
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

    const local_cid = [_]u8{ 0xc5, 0xc6, 0xc7, 0xc8 };
    const peer_cid = [_]u8{ 0xd5, 0xd6, 0xd7, 0xd8 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xad} ** quic.protection.secret_len,
    );
    var server = try one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &local_cid,
        .peer_connection_id = &peer_cid,
        .local_endpoint = .server,
        .enable_spin_bit = true,
    });
    defer server.deinit();

    const payload = try one_rtt.encodeFrames(
        allocator,
        &.{.{ .ping = {} }},
    );
    defer allocator.free(payload);
    const newest = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = &local_cid,
        .packet_number = 2,
        .packet_number_len = 4,
        .spin_bit = true,
        .payload = payload,
    });
    defer allocator.free(newest);
    var newest_packet = try one_rtt.testing.processReceivedBytesAt(
        &server,
        sender.address(),
        newest,
        .not_ect,
        10,
    );
    newest_packet.deinit(allocator);
    try std.testing.expect(server.nextSpinBit());

    const reordered = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = &local_cid,
        .packet_number = 1,
        .packet_number_len = 4,
        .spin_bit = false,
        .payload = payload,
    });
    defer allocator.free(reordered);
    var reordered_packet = try one_rtt.testing.processReceivedBytesAt(
        &server,
        sender.address(),
        reordered,
        .not_ect,
        11,
    );
    reordered_packet.deinit(allocator);
    try std.testing.expect(server.nextSpinBit());
}

test "QUIC 1-RTT spin bit remains disabled by default" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4 };
    const server_cid = [_]u8{ 0xf1, 0xf2, 0xf3, 0xf4 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xac} ** quic.protection.secret_len);

    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .spin_bit = true,
        .frames = &[_]quic.Frame{.{ .ping = {} }},
    });
    var packet = try server.receivePacket();
    defer packet.deinit(allocator);
    try std.testing.expect(packet.packet.spin_bit);
    try std.testing.expect(!server.nextSpinBit());
}

test "QUIC 1-RTT connection receives a UDP GRO packet batch" {
    if (!quic.runtime.udpGroSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 4096,
            .enable_gro_receive = true,
        },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();
    if (!server_endpoint.groReceiveEnabled() or !client_endpoint.gsoSendEnabled()) {
        return error.SkipZigTest;
    }

    const client_cid = [_]u8{ 0x81, 0x82, 0x83, 0x84 };
    const server_cid = [_]u8{ 0x85, 0x86, 0x87, 0x88 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x89} ** quic.protection.secret_len);
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    const ping = [_]quic.Frame{.{ .ping = {} }};
    const packet_frames = [_][]const quic.Frame{ &ping, &ping };
    try one_rtt.sendFramesBatch(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .first_packet_number = 0,
        .packet_number_len = 4,
        .packets = &packet_frames,
    });

    var received = try server.receivePacketBatchAt(10_000_000);
    defer received.deinit();
    try std.testing.expectEqual(@as(usize, 2), received.packets.len);
    try std.testing.expectEqual(@as(u64, 0), received.packets[0].packet.packet_number);
    try std.testing.expectEqual(@as(u64, 1), received.packets[1].packet.packet_number);
    try std.testing.expect(received.packets[0].frames[0] == .ping);
    try std.testing.expect(received.packets[1].frames[0] == .ping);
    try std.testing.expectEqual(@as(usize, 2), received.remaining());
    var taken = received.takeNext() orelse return error.TestUnexpectedResult;
    defer taken.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), taken.packet.packet_number);
    try std.testing.expectEqual(@as(usize, 1), received.remaining());

    const ack = try server.received.ackFrame(allocator, 0);
    defer allocator.free(ack.ranges);
    try std.testing.expectEqual(@as(u64, 1), ack.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 1), ack.first_ack_range);

    try one_rtt.sendFramesBatch(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .first_packet_number = 1,
        .packet_number_len = 4,
        .packets = &packet_frames,
    });
    var duplicate_then_fresh = try server.receivePacketBatchAt(20_000_000);
    defer duplicate_then_fresh.deinit();
    try std.testing.expectEqual(
        @as(usize, 1),
        duplicate_then_fresh.packets.len,
    );
    try std.testing.expectEqual(
        @as(u64, 2),
        duplicate_then_fresh.packets[0].packet.packet_number,
    );

    try one_rtt.sendFramesBatch(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .first_packet_number = 2,
        .packet_number_len = 4,
        .packets = &packet_frames,
    });
    try std.testing.expectEqual(
        @as(usize, 1),
        try server.servicePacketBatchAt(30_000_000),
    );
    const second_ack = try server.received.ackFrame(allocator, 0);
    defer allocator.free(second_ack.ranges);
    try std.testing.expectEqual(@as(u64, 3), second_ack.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 3), second_ack.first_ack_range);
}

test "QUIC 1-RTT timer-aware receive preserves UDP GRO batch" {
    if (!quic.runtime.udpGroSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = 4096,
            .enable_gro_receive = true,
        },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();
    if (!server_endpoint.groReceiveEnabled() or
        !client_endpoint.gsoSendEnabled())
    {
        return error.SkipZigTest;
    }

    const client_cid = [_]u8{ 0x8a, 0x8b, 0x8c, 0x8d };
    const server_cid = [_]u8{ 0x8e, 0x8f, 0x90, 0x91 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x92} ** quic.protection.secret_len,
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

    // Seed a future ACK-delay timer. The batch receive must arm a timed socket
    // operation while still returning both GRO segments in one owning batch.
    const now = std.Io.Clock.awake.now(io).nanoseconds;
    server.ack_delay_start_ns = @intCast(now);
    server.ack_delay_deadline_ns = @intCast(now + std.time.ns_per_s);
    const ping = [_]quic.Frame{.{ .ping = {} }};
    const packet_frames = [_][]const quic.Frame{ &ping, &ping };
    try one_rtt.sendFramesBatch(
        &client_endpoint,
        server_endpoint.address(),
        keys,
        .{
            .destination_connection_id = &server_cid,
            .first_packet_number = 0,
            .packet_number_len = 4,
            .packets = &packet_frames,
        },
    );

    var received = try server.receivePacketBatchServicingTimers();
    defer received.deinit();
    try std.testing.expectEqual(@as(usize, 2), received.packets.len);
    try std.testing.expectEqual(
        @as(u64, 0),
        received.packets[0].packet.packet_number,
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        received.packets[1].packet.packet_number,
    );
}

test "QUIC 1-RTT timer-aware state-only receive applies UDP GRO batch" {
    if (!quic.runtime.udpGroSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096, .enable_gro_receive = true },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();
    if (!server_endpoint.groReceiveEnabled() or
        !client_endpoint.gsoSendEnabled())
    {
        return error.SkipZigTest;
    }

    const client_cid = [_]u8{ 0x93, 0x94, 0x95, 0x96 };
    const server_cid = [_]u8{ 0x97, 0x98, 0x99, 0x9a };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x9b} ** quic.protection.secret_len,
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

    const ping = [_]quic.Frame{.{ .ping = {} }};
    const packets = [_][]const quic.Frame{ &ping, &ping };
    try one_rtt.sendFramesBatch(
        &client_endpoint,
        server_endpoint.address(),
        keys,
        .{
            .destination_connection_id = &server_cid,
            .first_packet_number = 0,
            .packet_number_len = 4,
            .packets = &packets,
        },
    );

    try std.testing.expectEqual(
        @as(usize, 2),
        try server.servicePacketBatchServicingTimersDeadline(
            .fromNow(io, .{
                .clock = .awake,
                .raw = .fromSeconds(1),
            }),
        ),
    );
    try std.testing.expectEqual(@as(u64, 2), server.stats().packets_received);

    var ack = try one_rtt.receive(
        &client_endpoint,
        keys,
        client_cid.len,
        0,
        8,
    );
    defer ack.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), ack.frames.len);
    try std.testing.expect(ack.frames[0] == .ack);
    try std.testing.expectEqual(
        @as(u64, 1),
        ack.frames[0].ack.largest_acknowledged,
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        ack.frames[0].ack.first_ack_range,
    );
}

test "QUIC 1-RTT state-only GRO receive reuses connection storage" {
    if (!quic.runtime.udpGroSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var counting = std.testing.FailingAllocator.init(allocator, .{});
    const connection_allocator = counting.allocator();
    var server_endpoint = try quic.runtime.Endpoint.bind(
        connection_allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096, .enable_gro_receive = true },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();
    if (!server_endpoint.groReceiveEnabled() or
        !client_endpoint.gsoSendEnabled())
    {
        return error.SkipZigTest;
    }

    const client_cid = [_]u8{ 0x9c, 0x9d, 0x9e, 0x9f };
    const server_cid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa4} ** quic.protection.secret_len,
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

    const ping = [_]quic.Frame{.{ .ping = {} }};
    const packets = [_][]const quic.Frame{ &ping, &ping };
    try one_rtt.sendFramesBatch(
        &client_endpoint,
        server_endpoint.address(),
        keys,
        .{
            .destination_connection_id = &server_cid,
            .first_packet_number = 0,
            .packet_number_len = 4,
            .packets = &packets,
        },
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        try server.servicePacketBatchServicingTimers(),
    );
    var first_ack = try one_rtt.receive(
        &client_endpoint,
        keys,
        client_cid.len,
        0,
        8,
    );
    first_ack.deinit(allocator);

    counting.fail_index = counting.alloc_index;
    counting.resize_fail_index = counting.resize_index;
    try one_rtt.sendFramesBatch(
        &client_endpoint,
        server_endpoint.address(),
        keys,
        .{
            .destination_connection_id = &server_cid,
            .first_packet_number = 2,
            .packet_number_len = 4,
            .packets = &packets,
        },
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        try server.servicePacketBatchServicingTimers(),
    );
    try std.testing.expect(!counting.has_induced_failure);
    try std.testing.expectEqual(@as(u64, 4), server.stats().packets_received);
}

test "QUIC 1-RTT connection sends ACK and marks sent packet acknowledged" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const server_cid = [_]u8{ 0x05, 0x06, 0x07, 0x08 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0x71} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0x72} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .local_ack_delay_exponent = 3,
    });
    defer server.deinit();

    const frames = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "ack me", .fin = true } }};
    try client.send(&frames);
    try std.testing.expectEqual(@as(usize, 1), client.sent.packets.items.len);
    try std.testing.expect(!client.sent.packets.items[0].acknowledged);
    try std.testing.expect(client.congestion.bytes_in_flight > 0);

    var received = try server.receivePacket();
    defer received.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), received.packet.packet_number);
    try std.testing.expectEqual(@as(u64, 25), try server.encodedLocalAckDelayNanos(200_000));
    try server.sendAckForDelayNs(200_000);

    var ack_packet = try client.receivePacket();
    defer ack_packet.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), ack_packet.frames[0].ack.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 25), ack_packet.frames[0].ack.ack_delay);
    try std.testing.expect(client.sent.packets.items[0].acknowledged);
    try std.testing.expectEqual(@as(usize, 0), client.pendingRecoveryCount());
    try std.testing.expectEqual(@as(usize, 0), client.congestion.bytes_in_flight);
}

test "QUIC 1-RTT connection exposes stable stats counters" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x81, 0x82, 0x83, 0x84 };
    const server_cid = [_]u8{ 0x85, 0x86, 0x87, 0x88 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0x81} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0x82} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .enable_pacing = false,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();

    const initial = client.stats();
    try std.testing.expectEqual(@as(u64, 0), initial.packets_sent);
    try std.testing.expectEqual(@as(?u64, null), initial.smoothed_rtt_ns);
    try std.testing.expectEqual(
        @as(?u64, null),
        initial.pacing_rate_bytes_per_second,
    );
    try std.testing.expectEqual(
        @as(?u64, null),
        initial.max_pacing_rate_bytes_per_second,
    );
    try std.testing.expectEqual(@as(f64, 0.0), initial.lossRate());
    try std.testing.expect(client.getSendStreamStats(0) == null);
    try std.testing.expect(client.streamStopped(0) == null);
    const initial_credit = client.streamSendCredit(0);
    try std.testing.expectEqual(
        initial_credit.connection,
        client.connectionSendAvailable(),
    );
    try std.testing.expectEqual(
        initial_credit.stream,
        client.streamSendAvailable(0),
    );
    try std.testing.expect(initial_credit.connection >= 5);
    try std.testing.expect(initial_credit.stream >= 5);
    try std.testing.expect(initial_credit.congestion > 0);
    try std.testing.expectEqual(
        quic.congestion.default_max_datagram_size,
        initial_credit.max_datagram_size,
    );
    try std.testing.expect(server.getRecvStreamStats(0) == null);
    try std.testing.expect(server.availableReceivedStream(0) == null);
    try std.testing.expect(!server.receivedStreamComplete(0));
    try std.testing.expect((try server.copyReceivedStream(allocator, 0)) == null);
    try std.testing.expect(server.streamResetReceived(0) == null);

    const request = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = "stats",
        .fin = true,
    } }};
    try client.sendAt(&request, 100_000_000);
    const client_after_send = client.getStats();
    try std.testing.expectEqual(@as(u64, 1), client_after_send.packets_sent);
    try std.testing.expect(client_after_send.bytes_sent > 0);
    try std.testing.expectEqual(@as(u64, 1), client_after_send.outgoing_streams_created);
    try std.testing.expectEqual(@as(usize, 1), client_after_send.pending_recovery_count);
    try std.testing.expectEqual(@as(usize, 1), client_after_send.recovery_queue_stats.pending_groups);
    try std.testing.expectEqual(@as(usize, 1), client_after_send.recovery_queue_stats.packet_number_copies);
    try std.testing.expect(client_after_send.bytes_in_flight > 0);
    try std.testing.expectEqual(@as(usize, 1), client_after_send.sent_packet_stats.tracked_packets);
    try std.testing.expectEqual(@as(usize, 1), client_after_send.sent_packet_stats.ack_eliciting_packets);
    try std.testing.expectEqual(@as(usize, 1), client_after_send.sent_packet_stats.ack_eliciting_in_flight_packets);
    try std.testing.expectEqual(
        @as(?u64, 100_000_000),
        client_after_send.sent_packet_stats.latest_ack_eliciting_in_flight_sent_time_ns,
    );
    try std.testing.expectEqual(client_after_send.bytes_in_flight, client_after_send.sent_packet_stats.bytes_in_flight);
    try std.testing.expectEqual(@as(?usize, 0), client.stream_send_index.get(0));
    const send_stream_stats = client.getSendStreamStats(0).?;
    try std.testing.expectEqual(@as(u64, 5), send_stream_stats.bytes_sent);
    try std.testing.expectEqual(@as(u64, 5), send_stream_stats.highest_sent_offset);
    try std.testing.expectEqual(
        @as(?u64, 5),
        send_stream_stats.final_size,
    );
    try std.testing.expect(send_stream_stats.send_limit > 5);
    try std.testing.expectEqual(
        send_stream_stats.send_limit - 5,
        send_stream_stats.send_available,
    );
    const remaining_credit = client.streamSendCredit(0);
    try std.testing.expectEqual(
        remaining_credit.connection,
        client.connectionSendAvailable(),
    );
    try std.testing.expectEqual(
        remaining_credit.stream,
        client.streamSendAvailable(0),
    );
    try std.testing.expectEqual(
        initial_credit.connection - 5,
        remaining_credit.connection,
    );
    try std.testing.expectEqual(
        initial_credit.stream - 5,
        remaining_credit.stream,
    );
    try std.testing.expect(client.getSendStreamStats(4) == null);
    try std.testing.expect(client.streamStopped(0) == null);

    var received = try server.receivePacketAt(150_000_000);
    defer received.deinit(allocator);
    const server_after_receive = server.stats();
    try std.testing.expectEqual(@as(u64, 1), server_after_receive.packets_received);
    try std.testing.expectEqual(client_after_send.bytes_sent, server_after_receive.bytes_received);
    try std.testing.expectEqual(@as(u64, 1), server_after_receive.incoming_streams_created);
    try std.testing.expectEqual(@as(u64, 0), server_after_receive.packets_lost);
    try std.testing.expectEqual(@as(usize, 1), server_after_receive.received_packet_stats.ack_ranges);
    try std.testing.expectEqual(@as(u64, 1), server_after_receive.received_packet_stats.retained_packets);
    try std.testing.expectEqual(@as(?u64, 0), server_after_receive.received_packet_stats.largest_received);
    try std.testing.expectEqual(@as(?usize, 0), server.stream_recv_index.get(0));
    var recv_stream_stats = server.getRecvStreamStats(0).?;
    try std.testing.expectEqual(@as(u64, 5), recv_stream_stats.bytes_received);
    try std.testing.expectEqual(@as(u64, 0), recv_stream_stats.bytes_read);
    try std.testing.expectEqual(@as(u64, 5), recv_stream_stats.highest_received_offset);
    try std.testing.expectEqual(@as(usize, 5), recv_stream_stats.available_bytes);
    try std.testing.expectEqual(
        recv_stream_stats.receive_limit - 5,
        recv_stream_stats.receive_window_available,
    );
    try std.testing.expect(server.getRecvStreamStats(4) == null);
    try std.testing.expectEqualStrings(
        "stats",
        server.availableReceivedStream(0).?,
    );
    try std.testing.expect(!server.receivedStreamComplete(0));
    try std.testing.expect(server.availableReceivedStream(4) == null);
    try std.testing.expect(!server.receivedStreamComplete(4));
    const copied = (try server.copyReceivedStream(allocator, 0)).?;
    defer allocator.free(copied);
    try std.testing.expectEqualStrings("stats", copied);
    try std.testing.expect((try server.copyReceivedStream(allocator, 4)) == null);
    try std.testing.expect(server.streamResetReceived(0) == null);
    try server.releaseReceivedCapacity(0, 5);
    recv_stream_stats = server.getRecvStreamStats(0).?;
    try std.testing.expectEqual(@as(u64, 5), recv_stream_stats.bytes_read);
    try std.testing.expectEqual(@as(usize, 0), recv_stream_stats.available_bytes);
    try std.testing.expectEqual(@as(usize, 0), server.availableReceivedStream(0).?.len);
    try std.testing.expect(server.receivedStreamComplete(0));
    try std.testing.expectEqual(
        recv_stream_stats.receive_limit - 5,
        recv_stream_stats.receive_window_available,
    );

    try server.sendAck(0);
    const server_after_ack = server.stats();
    try std.testing.expectEqual(@as(u64, 1), server_after_ack.packets_sent);
    try std.testing.expect(server_after_ack.bytes_sent > 0);

    var ack = try client.receivePacketAt(250_000_000);
    defer ack.deinit(allocator);
    const client_after_ack = client.stats();
    try std.testing.expectEqual(@as(u64, 1), client_after_ack.packets_received);
    try std.testing.expectEqual(server_after_ack.bytes_sent, client_after_ack.bytes_received);
    try std.testing.expectEqual(@as(usize, 0), client_after_ack.pending_recovery_count);
    try std.testing.expectEqual(@as(usize, 0), client_after_ack.recovery_queue_stats.pending_groups);
    try std.testing.expectEqual(@as(usize, 1), client_after_ack.sent_packet_stats.acknowledged_packets);
    try std.testing.expectEqual(@as(usize, 0), client_after_ack.sent_packet_stats.in_flight_packets);
    try std.testing.expectEqual(@as(usize, 0), client_after_ack.sent_packet_stats.ack_eliciting_in_flight_packets);
    try std.testing.expectEqual(
        @as(?u64, null),
        client_after_ack.sent_packet_stats.latest_ack_eliciting_in_flight_sent_time_ns,
    );
    try std.testing.expectEqual(@as(usize, 0), client_after_ack.sent_packet_stats.bytes_in_flight);
    try std.testing.expectEqual(@as(u64, 0), client_after_ack.packets_lost);
    try std.testing.expectEqual(@as(f64, 0.0), client_after_ack.lossRate());
    try std.testing.expectEqual(@as(?u64, 150_000_000), client_after_ack.latest_rtt_ns);
    try std.testing.expect(client_after_ack.smoothed_rtt_ns != null);
}

test "QUIC 1-RTT connection delivers FIN-only stream packet" {
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

    const client_cid = [_]u8{ 0x91, 0x92, 0x93, 0x94 };
    const server_cid = [_]u8{ 0x95, 0x96, 0x97, 0x98 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x93} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .enable_pacing = false,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();

    try client.send(&.{.{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .data = "payload",
    } }});
    try client.send(&.{.{ .stream = .{
        .stream_id = 0,
        .offset = "payload".len,
        .data = &.{},
        .fin = true,
    } }});
    var data = try server.receivePacket();
    defer data.deinit(allocator);
    var fin = try server.receivePacket();
    defer fin.deinit(allocator);
    try std.testing.expectEqualStrings(
        "payload",
        server.availableReceivedStream(0).?,
    );
    const stats = server.recvStreamStats(0).?;
    try std.testing.expectEqual(@as(?u64, "payload".len), stats.final_size);
    try std.testing.expectError(
        error.FinalSizeMismatch,
        client.send(&.{.{ .stream = .{
            .stream_id = 0,
            .offset = "payload".len,
            .data = "late",
        } }}),
    );
}

test "QUIC 1-RTT pollStream reports data FIN and reset once" {
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
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x94} ** quic.protection.secret_len,
    );
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "poll-client",
        .peer_connection_id = "poll-server",
        .enable_pacing = false,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "poll-server",
        .peer_connection_id = "poll-client",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();

    var empty: [0]u8 = .{};
    try std.testing.expectError(error.BufferTooShort, server.pollStream(&empty));
    var out: [4]u8 = undefined;
    try std.testing.expect((try server.pollStream(&out)) == null);
    try std.testing.expectError(
        error.Timeout,
        server.receiveStreamWithTimeout(&out, .zero),
    );
    try std.testing.expectError(
        error.Timeout,
        server.receiveStreamIdWithTimeout(0, &out, .zero),
    );

    try client.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "abcdef",
        .fin = true,
    } }});
    var packet = try server.receivePacket();
    defer packet.deinit(allocator);
    try std.testing.expectError(
        error.Timeout,
        server.receiveStreamWithDeadline(&out, .{
            .clock = .real,
            .raw = .zero,
        }),
    );
    try std.testing.expectError(
        error.Timeout,
        server.receiveStreamIdWithDeadline(0, &out, .{
            .clock = .awake,
            .raw = .zero,
        }),
    );
    const first = (try server.pollStream(&out)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(first == .data);
    try std.testing.expectEqual(@as(u62, 0), first.data.stream_id);
    try std.testing.expectEqual(@as(usize, 4), first.data.bytes);
    try std.testing.expect(!first.data.fin);
    try std.testing.expectEqualStrings("abcd", out[0..first.data.bytes]);
    const final = (try server.pollStream(&out)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(final == .data);
    try std.testing.expectEqual(@as(usize, 2), final.data.bytes);
    try std.testing.expect(final.data.fin);
    try std.testing.expectEqualStrings("ef", out[0..final.data.bytes]);
    try std.testing.expect((try server.pollStream(&out)) == null);

    try client.send(&.{.{ .stream = .{
        .stream_id = 4,
        .data = &.{},
        .fin = true,
    } }});
    var fin_packet = try server.receivePacket();
    defer fin_packet.deinit(allocator);
    const fin = (try server.pollStream(&out)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(fin == .data);
    try std.testing.expectEqual(@as(u62, 4), fin.data.stream_id);
    try std.testing.expectEqual(@as(usize, 0), fin.data.bytes);
    try std.testing.expect(fin.data.fin);
    try std.testing.expect((try server.pollStream(&out)) == null);

    try client.resetStream(8, 77);
    var reset_packet = try server.receivePacket();
    defer reset_packet.deinit(allocator);
    const reset = (try server.pollStream(&out)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(reset == .reset);
    try std.testing.expectEqual(@as(u62, 8), reset.reset.stream_id);
    try std.testing.expectEqual(@as(u64, 77), reset.reset.application_error_code);
    try std.testing.expectEqual(@as(u64, 0), reset.reset.final_size);
    try std.testing.expect((try server.pollStream(&out)) == null);

    try client.send(&.{
        .{ .stream = .{ .stream_id = 12, .data = "aaaaaa" } },
        .{ .stream = .{ .stream_id = 16, .data = "bbbbbb" } },
    });
    var fair_packet = try server.receivePacket();
    defer fair_packet.deinit(allocator);
    const fair_first = (try server.pollStream(&out)) orelse
        return error.TestUnexpectedResult;
    const fair_second = (try server.pollStream(&out)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(fair_first == .data);
    try std.testing.expect(fair_second == .data);
    try std.testing.expect(fair_first.data.stream_id !=
        fair_second.data.stream_id);

    const targeted = (try server.pollStreamId(12, &out)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(targeted == .data);
    try std.testing.expectEqual(@as(u62, 12), targeted.data.stream_id);
    try std.testing.expectEqualStrings("aa", out[0..targeted.data.bytes]);
    try std.testing.expect((try server.pollStreamId(999, &out)) == null);

    try client.send(&.{.{ .stream = .{
        .stream_id = 20,
        .data = "bounded",
        .fin = true,
    } }});
    const bounded = try server.receiveStreamIdWithDeadline(
        20,
        &out,
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    try std.testing.expect(bounded == .data);
    try std.testing.expectEqual(@as(u62, 20), bounded.data.stream_id);
    try std.testing.expectEqualStrings("boun", out[0..bounded.data.bytes]);
    const bounded_final = try server.receiveStreamIdWithTimeout(
        20,
        &out,
        .fromSeconds(1),
    );
    try std.testing.expect(bounded_final == .data);
    try std.testing.expect(bounded_final.data.fin);
    try std.testing.expectEqualStrings("ded", out[0..bounded_final.data.bytes]);

    try client.send(&.{.{ .stream = .{
        .stream_id = 24,
        .data = "deadline-packet",
        .fin = true,
    } }});
    var deadline_packet = try server.receivePacketServicingTimersDeadline(
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    defer deadline_packet.deinit(allocator);
    try std.testing.expectEqualStrings(
        "deadline-packet",
        server.availableReceivedStream(24).?,
    );
}

test "QUIC 1-RTT reset after FIN preserves the first delivered terminal event" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x9d} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "fin-reset-local",
        .peer_connection_id = "fin-reset-peer",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();

    try one_rtt.testing.applyReceivedFrames(&connection, 0, &.{.{
        .stream = .{
            .stream_id = 0,
            .data = "done",
            .fin = true,
        },
    }}, null, .not_ect);
    var out: [8]u8 = undefined;
    const finished = (try connection.pollStreamId(0, &out)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(finished == .data);
    try std.testing.expect(finished.data.fin);
    try std.testing.expectEqualStrings(
        "done",
        out[0..finished.data.bytes],
    );

    try one_rtt.testing.applyReceivedFrames(&connection, 1, &.{.{
        .reset_stream = .{
            .stream_id = 0,
            .application_error_code = 77,
            .final_size = 4,
        },
    }}, null, .not_ect);
    try std.testing.expect((try connection.pollStreamId(0, &out)) == null);
    try std.testing.expectEqual(
        @as(u64, 77),
        connection.streamResetReceived(0).?.application_error_code,
    );

    // A reset still supersedes an unread FIN and must remain observable.
    try one_rtt.testing.applyReceivedFrames(&connection, 2, &.{.{
        .stream = .{
            .stream_id = 4,
            .data = "unread",
            .fin = true,
        },
    }}, null, .not_ect);
    try one_rtt.testing.applyReceivedFrames(&connection, 3, &.{.{
        .reset_stream = .{
            .stream_id = 4,
            .application_error_code = 78,
            .final_size = 6,
        },
    }}, null, .not_ect);
    const reset = (try connection.pollStreamId(4, &out)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(reset == .reset);
    try std.testing.expectEqual(
        @as(u64, 78),
        reset.reset.application_error_code,
    );
    try std.testing.expect((try connection.pollStreamId(4, &out)) == null);
}

test "QUIC 1-RTT optionally drains buffered stream data before reset" {
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
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x9d} ** quic.protection.secret_len,
    );

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "reset-partial-client",
        .peer_connection_id = "reset-partial-server",
        .enable_pacing = false,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "reset-partial-server",
        .peer_connection_id = "reset-partial-client",
        .local_endpoint = .server,
        .enable_pacing = false,
        .enable_reset_partial_delivery = true,
    });
    defer server.deinit();

    // Deliver STREAM and RESET_STREAM in separate packets so the receive
    // buffer demonstrably predates the terminal signal. RESET_STREAM's final
    // size equals the sender's highest offset, as required by RFC 9000.
    try client.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "abcdef",
    } }});
    var data_packet = try server.receivePacket();
    defer data_packet.deinit(allocator);
    try client.resetStream(0, 91);
    var reset_packet = try server.receivePacket();
    defer reset_packet.deinit(allocator);

    var out: [2]u8 = undefined;
    const first = (try server.pollStream(&out)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(first == .data);
    try std.testing.expectEqual(@as(u62, 0), first.data.stream_id);
    try std.testing.expectEqual(@as(usize, 2), first.data.bytes);
    try std.testing.expect(!first.data.fin);
    try std.testing.expectEqualStrings("ab", out[0..first.data.bytes]);

    const second = (try server.pollStreamId(0, &out)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(second == .data);
    try std.testing.expectEqualStrings("cd", out[0..second.data.bytes]);
    const third = (try server.pollStreamId(0, &out)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(third == .data);
    try std.testing.expectEqualStrings("ef", out[0..third.data.bytes]);
    // A reset is not a FIN even when all bytes before its final size happened
    // to arrive; applications must still observe the peer's error code.
    try std.testing.expect(!third.data.fin);

    const reset = (try server.pollStreamId(0, &out)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(reset == .reset);
    try std.testing.expectEqual(@as(u62, 0), reset.reset.stream_id);
    try std.testing.expectEqual(@as(u64, 91), reset.reset.application_error_code);
    try std.testing.expectEqual(@as(u64, 6), reset.reset.final_size);
    try std.testing.expect((try server.pollStreamId(0, &out)) == null);

    const stats = server.recvStreamStats(0).?;
    try std.testing.expectEqual(@as(u64, 6), stats.bytes_read);
    try std.testing.expectEqual(@as(usize, 0), stats.available_bytes);
}

test "QUIC 1-RTT reset-first default hides buffered data from polling" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0x9e} ** 32);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "reset-default-local",
        .peer_connection_id = "reset-default-peer",
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer connection.deinit();

    try one_rtt.testing.applyReceivedFrames(&connection, 0, &.{
        .{ .stream = .{ .stream_id = 0, .data = "kept" } },
    }, null, .not_ect);
    try one_rtt.testing.applyReceivedFrames(&connection, 1, &.{
        .{ .reset_stream = .{
            .stream_id = 0,
            .application_error_code = 92,
            .final_size = 4,
        } },
    }, null, .not_ect);

    var out: [2]u8 = undefined;
    const reset = (try connection.pollStream(&out)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(reset == .reset);
    try std.testing.expectEqual(@as(u64, 92), reset.reset.application_error_code);
    try std.testing.expect((try connection.pollStream(&out)) == null);
    // Every application read surface follows the historical reset-first view.
    // Diagnostic stats still retain the bytes for reordered/duplicate checks.
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.availableReceivedStream(0).?.len,
    );
    try std.testing.expectEqual(
        @as(usize, 4),
        connection.recvStreamStats(0).?.available_bytes,
    );
}

test "QUIC 1-RTT partial reset delivery preserves fair polling" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0x9f} ** 32);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "reset-fair-local",
        .peer_connection_id = "reset-fair-peer",
        .local_endpoint = .server,
        .enable_pacing = false,
        .enable_reset_partial_delivery = true,
    });
    defer connection.deinit();

    try one_rtt.testing.applyReceivedFrames(&connection, 0, &.{
        .{ .stream = .{ .stream_id = 0, .data = "aaaa" } },
        .{ .reset_stream = .{
            .stream_id = 0,
            .application_error_code = 93,
            .final_size = 4,
        } },
        .{ .stream = .{ .stream_id = 4, .data = "bbbb" } },
    }, null, .not_ect);

    var out: [2]u8 = undefined;
    const first = (try connection.pollStream(&out)) orelse
        return error.TestUnexpectedResult;
    const second = (try connection.pollStream(&out)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(first == .data);
    try std.testing.expect(second == .data);
    try std.testing.expectEqual(@as(u62, 0), first.data.stream_id);
    try std.testing.expectEqual(@as(u62, 4), second.data.stream_id);
}

test "QUIC 1-RTT partial reset delivery excludes reordered late data" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0xa0} ** 32);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "reset-late-local",
        .peer_connection_id = "reset-late-peer",
        .local_endpoint = .server,
        .enable_pacing = false,
        .enable_reset_partial_delivery = true,
    });
    defer connection.deinit();

    try one_rtt.testing.applyReceivedFrames(&connection, 0, &.{
        .{ .stream = .{ .stream_id = 0, .data = "abc" } },
    }, null, .not_ect);
    try one_rtt.testing.applyReceivedFrames(&connection, 1, &.{
        .{ .reset_stream = .{
            .stream_id = 0,
            .application_error_code = 94,
            .final_size = 6,
        } },
    }, null, .not_ect);
    const charged_at_reset = one_rtt.testing.receiveDataTotal(&connection);
    const stream_received_at_reset = connection.recvStreamStats(0).?.bytes_received;
    try one_rtt.testing.applyReceivedFrames(&connection, 2, &.{
        .{ .stream = .{ .stream_id = 0, .offset = 3, .data = "def" } },
    }, null, .not_ect);
    try std.testing.expectEqual(
        charged_at_reset,
        one_rtt.testing.receiveDataTotal(&connection),
    );
    try std.testing.expectEqual(
        stream_received_at_reset + 3,
        connection.recvStreamStats(0).?.bytes_received,
    );
    try one_rtt.testing.applyReceivedFrames(&connection, 3, &.{
        .{ .reset_stream = .{
            .stream_id = 0,
            .application_error_code = 94,
            .final_size = 6,
        } },
    }, null, .not_ect);
    try std.testing.expectEqual(
        charged_at_reset,
        one_rtt.testing.receiveDataTotal(&connection),
    );

    var out: [8]u8 = undefined;
    const data = (try connection.pollStreamId(0, &out)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(data == .data);
    try std.testing.expectEqualStrings("abc", out[0..data.data.bytes]);
    try std.testing.expect(!data.data.fin);
    const reset = (try connection.pollStreamId(0, &out)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(reset == .reset);
    try std.testing.expectEqual(@as(u64, 94), reset.reset.application_error_code);
    try std.testing.expect((try connection.pollStreamId(0, &out)) == null);
    try std.testing.expectEqual(@as(usize, 0), connection.availableReceivedStream(0).?.len);
    const copied = (try connection.copyReceivedStream(allocator, 0)) orelse
        return error.TestUnexpectedResult;
    defer allocator.free(copied);
    try std.testing.expectEqual(@as(usize, 0), copied.len);
    // Diagnostic statistics continue to expose retained transport evidence,
    // which is distinct from the application-readable prefix above.
    try std.testing.expectEqual(
        @as(usize, 3),
        connection.recvStreamStats(0).?.available_bytes,
    );
}

test "QUIC 1-RTT stats include byte-bounded datagram queue drops" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x91, 0x92, 0x93, 0x94 };
    const server_cid = [_]u8{ 0x95, 0x96, 0x97, 0x98 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x91} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .peer_max_datagram_frame_size = 64,
        .enable_pacing = false,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .local_max_datagram_frame_size = 64,
        .max_datagram_queue_items = 2,
        .max_datagram_queue_bytes = 5,
        .enable_pacing = false,
    });
    defer server.deinit();

    try client.sendDatagram("one");
    var first = try server.receivePacket();
    defer first.deinit(allocator);
    try client.sendDatagram("two");
    var second = try server.receivePacket();
    defer second.deinit(allocator);

    const client_stats = client.stats();
    try std.testing.expectEqual(@as(u64, 2), client_stats.datagrams_sent);
    try std.testing.expectEqual(@as(u64, 2), client_stats.packets_sent);

    const server_stats = server.stats();
    try std.testing.expectEqual(@as(u64, 2), server_stats.datagrams_received);
    try std.testing.expectEqual(@as(u64, 1), server_stats.datagrams_dropped_incoming);
    try std.testing.expectEqual(@as(usize, 1), server_stats.datagram_receive_queue_len);
    try std.testing.expectEqual(@as(usize, 3), server_stats.datagram_receive_queue_bytes);

    var out: [8]u8 = undefined;
    const popped = (try server.popDatagram(&out)).?;
    try std.testing.expectEqualStrings("two", popped);
    try std.testing.expectEqual(@as(usize, 0), server.stats().datagram_receive_queue_len);
    try std.testing.expectEqual(
        @as(usize, 0),
        server.stats().datagram_receive_queue_bytes,
    );
}

test "QUIC 1-RTT padding-only packets are in flight but non-eliciting" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x73, 0x74, 0x75, 0x76 };
    const server_cid = [_]u8{ 0x77, 0x78, 0x79, 0x7a };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0x7b} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0x7c} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try client.send(&[_]quic.Frame{.{ .padding = .{ .len = 16 } }});
    try std.testing.expectEqual(@as(usize, 1), client.sent.packets.items.len);
    try std.testing.expect(!client.sent.packets.items[0].ack_eliciting);
    try std.testing.expect(client.sent.packets.items[0].in_flight);
    const protected_packet_len = client.sent.packets.items[0].datagram_size;
    try std.testing.expectEqual(
        protected_packet_len,
        client.sent.packets.items[0].bytes,
    );
    try std.testing.expectEqual(
        1 + server_cid.len + 1 + 16 + quic.protection.aead_tag_len,
        protected_packet_len,
    );
    try std.testing.expectEqual(@as(usize, 0), client.pendingRecoveryCount());
    try std.testing.expectEqual(@as(?one_rtt.LossDetectionTimerDeadline, null), client.lossDetectionTimerDeadline());
    try std.testing.expectEqual(
        protected_packet_len,
        client.congestion.bytes_in_flight,
    );

    var padded = try server.receivePacket();
    defer padded.deinit(allocator);
    try std.testing.expectEqual(quic.Frame.padding, std.meta.activeTag(padded.frames[0]));
    try std.testing.expectEqual(@as(usize, 16), padded.frames[0].padding.len);

    try server.sendAck(0);
    var ack_packet = try client.receivePacket();
    defer ack_packet.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), ack_packet.frames[0].ack.largest_acknowledged);
    try std.testing.expect(client.sent.packets.items[0].acknowledged);
    try std.testing.expectEqual(@as(usize, 0), client.congestion.bytes_in_flight);
}

test "QUIC 1-RTT connection accounts only new overlapping stream bytes" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x09, 0x0a, 0x0b, 0x0c };
    const server_cid = [_]u8{ 0x0d, 0x0e, 0x0f, 0x10 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x70} ** quic.protection.secret_len);

    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .initial_receive_max_data = 8,
        .initial_receive_max_stream_data = 8,
    });
    defer server.deinit();

    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .stream = .{ .stream_id = 0, .offset = 0, .data = "abcdef", .fin = false } }},
    });
    var first = try server.receivePacket();
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 6), server.recv_data_total);
    try std.testing.expectEqual(@as(u64, 6), server.stream_recv_flows.items[0].recv_state.receivedByteCount());

    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 1,
        .frames = &[_]quic.Frame{.{ .stream = .{ .stream_id = 0, .offset = 3, .data = "defgh", .fin = false } }},
    });
    var overlap = try server.receivePacket();
    defer overlap.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 8), server.recv_data_total);
    try std.testing.expectEqual(@as(u64, 8), server.stream_recv_flows.items[0].recv_state.receivedByteCount());

    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 2,
        .frames = &[_]quic.Frame{.{ .stream = .{ .stream_id = 0, .offset = 4, .data = "ZZ", .fin = false } }},
    });
    try std.testing.expectError(error.ConflictingStreamData, server.receivePacket());
    try std.testing.expectEqual(@as(u64, 8), server.recv_data_total);
    try std.testing.expectEqual(@as(usize, 1), server.received.ranges.items.len);
    try std.testing.expect(server.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.protocol_violation), server.close_info.?.error_code);
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(quic.FrameType.stream) | 0x06),
        server.close_info.?.frame_type,
    );
    try std.testing.expectEqualStrings("stream data", server.close_info.?.reason_phrase);
}

test "QUIC 1-RTT connection charges sparse stream gaps to MAX_DATA" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
    const server_cid = [_]u8{ 0x25, 0x26, 0x27, 0x28 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x78} ** quic.protection.secret_len);

    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .initial_receive_max_data = 8,
        .initial_receive_max_stream_data = 16,
    });
    defer server.deinit();

    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .stream = .{
            .stream_id = 0,
            .offset = 7,
            .data = "h",
            .fin = false,
        } }},
    });
    var sparse = try server.receivePacket();
    defer sparse.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 8), server.recv_data_total);
    try std.testing.expectEqual(@as(u64, 8), server.stream_recv_flows.items[0].highest_received_end);
    try std.testing.expectEqual(@as(u64, 1), server.stream_recv_flows.items[0].recv_state.receivedByteCount());

    // Filling the already charged gap must not consume connection credit a
    // second time.
    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 1,
        .frames = &[_]quic.Frame{.{ .stream = .{
            .stream_id = 0,
            .offset = 0,
            .data = "abcdefg",
            .fin = false,
        } }},
    });
    var gap_fill = try server.receivePacket();
    defer gap_fill.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 8), server.recv_data_total);
    try std.testing.expectEqual(@as(u64, 8), server.stream_recv_flows.items[0].recv_state.receivedByteCount());

    // A new byte on another stream exceeds the exhausted MAX_DATA limit.
    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 2,
        .frames = &[_]quic.Frame{.{ .stream = .{
            .stream_id = 4,
            .data = "x",
            .fin = false,
        } }},
    });
    try std.testing.expectError(error.FlowControlViolation, server.receivePacket());
    try std.testing.expectEqual(@as(u64, 8), server.recv_data_total);
    try std.testing.expectEqual(@as(usize, 1), server.stream_recv_flows.items.len);
    try std.testing.expect(server.closing());
    try std.testing.expectEqual(
        @intFromEnum(quic.TransportErrorCode.flow_control_error),
        server.close_info.?.error_code,
    );
}

test "QUIC 1-RTT sparse MAX_DATA preflight is packet transactional" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x29, 0x2a, 0x2b, 0x2c };
    const server_cid = [_]u8{ 0x2d, 0x2e, 0x2f, 0x30 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x79} ** quic.protection.secret_len);

    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .initial_receive_max_data = 9,
        .initial_receive_max_stream_data = 16,
    });
    defer server.deinit();

    // Stream 0 advances to offset 5 and then final size 7; stream 4 advances
    // to offset 3. Their aggregate offset is 10 even though only two payload
    // bytes are present. The complete packet must be rejected before mutation.
    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{
            .{ .stream = .{
                .stream_id = 0,
                .offset = 4,
                .data = "a",
                .fin = false,
            } },
            .{ .reset_stream = .{
                .stream_id = 0,
                .application_error_code = 91,
                .final_size = 7,
            } },
            .{ .stream = .{
                .stream_id = 4,
                .offset = 2,
                .data = "b",
                .fin = false,
            } },
        },
    });
    try std.testing.expectError(error.FlowControlViolation, server.receivePacket());
    try std.testing.expectEqual(@as(u64, 0), server.recv_data_total);
    try std.testing.expectEqual(@as(usize, 0), server.stream_recv_flows.items.len);
    try std.testing.expect(server.closing());
    try std.testing.expectEqual(
        @intFromEnum(quic.TransportErrorCode.flow_control_error),
        server.close_info.?.error_code,
    );
}

test "QUIC 1-RTT RESET_STREAM charges only remaining highest offset" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
    const server_cid = [_]u8{ 0x35, 0x36, 0x37, 0x38 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x7a} ** quic.protection.secret_len);

    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .initial_receive_max_data = 8,
        .initial_receive_max_stream_data = 16,
    });
    defer server.deinit();

    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .stream = .{
            .stream_id = 0,
            .offset = 5,
            .data = "f",
            .fin = false,
        } }},
    });
    var sparse = try server.receivePacket();
    defer sparse.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 6), server.recv_data_total);

    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 1,
        .frames = &[_]quic.Frame{.{ .reset_stream = .{
            .stream_id = 0,
            .application_error_code = 92,
            .final_size = 8,
        } }},
    });
    var reset = try server.receivePacket();
    defer reset.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 8), server.recv_data_total);
    try std.testing.expectEqual(@as(u64, 8), server.stream_recv_flows.items[0].highest_received_end);
    try std.testing.expectEqual(@as(u64, 8), server.streamResetReceived(0).?.final_size);

    // Reordered data below the reset final size was already charged and must
    // not consume more MAX_DATA.
    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 2,
        .frames = &[_]quic.Frame{.{ .stream = .{
            .stream_id = 0,
            .offset = 0,
            .data = "abcde",
            .fin = false,
        } }},
    });
    var reordered = try server.receivePacket();
    defer reordered.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 8), server.recv_data_total);
}

test "QUIC 1-RTT connection drops duplicate packet numbers before frame effects" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x11, 0x12, 0x13, 0x14 };
    const server_cid = [_]u8{ 0x15, 0x16, 0x17, 0x18 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0x73} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0x74} ** quic.protection.secret_len);

    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    const frames = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "once", .fin = false } }};
    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), client_keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .frames = &frames,
    });
    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), client_keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .frames = &frames,
    });

    var first = try server.receivePacket();
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), first.packet.packet_number);
    try std.testing.expectEqual(@as(u64, 4), server.recv_data_total);
    try std.testing.expectEqual(@as(usize, 1), server.received.ranges.items.len);

    try std.testing.expectError(error.DuplicatePacket, server.receivePacket());
    try std.testing.expectEqual(@as(u64, 4), server.recv_data_total);
    try std.testing.expectEqual(@as(usize, 1), server.received.ranges.items.len);

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), client_keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .frames = &ping,
    });
    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), client_keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 1,
        .frames = &ping,
    });
    const Visitor = struct {
        fn visit(packet_number: *?u64, packet: one_rtt.ReceivedPacketView) !void {
            packet_number.* = packet.packet_number;
        }
    };
    var visited_packet_number: ?u64 = null;
    try server.visitPacketServicingTimersDeadline(
        .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }),
        &visited_packet_number,
        Visitor.visit,
    );
    try std.testing.expectEqual(@as(?u64, 1), visited_packet_number);
    try std.testing.expectEqual(@as(u64, 2), server.stats().packets_received);
}

test "QUIC 1-RTT connection preflights ACK frames before receive-side effects" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x19, 0x1a, 0x1b, 0x1c };
    const server_cid = [_]u8{ 0x1d, 0x1e, 0x1f, 0x20 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0x75} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0x76} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_endpoint = .client,
    });
    defer client.deinit();

    try one_rtt.sendFrames(&server_endpoint, client_endpoint.address(), server_keys, .{
        .destination_connection_id = &client_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{
            .{ .stream = .{ .stream_id = 1, .data = "poison", .fin = false } },
            .{ .ack = .{
                .largest_acknowledged = 0,
                .ack_delay = 0,
                .first_ack_range = 0,
                .ecn_counts = .{
                    .ect0_count = 0,
                    .ect1_count = 0,
                    .ecn_ce_count = 0,
                },
            } },
            .{ .ping = {} },
        },
    });

    try std.testing.expectError(error.InvalidAckFrame, client.receivePacket());
    try std.testing.expectEqual(@as(u64, 0), client.recv_data_total);
    try std.testing.expectEqual(@as(usize, 0), client.stream_recv_flows.items.len);
    try std.testing.expectEqual(@as(usize, 0), client.received.ranges.items.len);
    try std.testing.expectEqual(@as(u64, 0), client.expected_packet_number);
    try std.testing.expect(client.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.protocol_violation), client.close_info.?.error_code);
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(quic.FrameType.ack_ecn)),
        client.close_info.?.frame_type,
    );
    try std.testing.expectEqualStrings("ack", client.close_info.?.reason_phrase);
}

test "QUIC 1-RTT connection preflights stream frames before receive-side effects" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x29, 0x2a, 0x2b, 0x2c };
    const server_cid = [_]u8{ 0x2d, 0x2e, 0x2f, 0x30 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x77} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_endpoint = .client,
        .initial_receive_max_streams_bidi = 1,
    });
    defer client.deinit();

    try one_rtt.sendFrames(&server_endpoint, client_endpoint.address(), keys, .{
        .destination_connection_id = &client_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{
            .{ .stream = .{ .stream_id = 1, .data = "first", .fin = false } },
            .{ .stream = .{
                .stream_id = 5,
                .offset = 7,
                .data = "over-limit",
                .fin = true,
            } },
            .{ .ping = {} },
        },
    });

    try std.testing.expectError(error.StreamLimitExceeded, client.receivePacket());
    try std.testing.expectEqual(@as(u64, 0), client.recv_data_total);
    try std.testing.expectEqual(@as(usize, 0), client.stream_recv_flows.items.len);
    try std.testing.expectEqual(@as(usize, 0), client.received.ranges.items.len);
    try std.testing.expectEqual(@as(u64, 0), client.expected_packet_number);
    try std.testing.expect(client.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.stream_limit_error), client.close_info.?.error_code);
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(quic.FrameType.stream) | 0x07),
        client.close_info.?.frame_type,
    );
    try std.testing.expectEqualStrings("stream limit", client.close_info.?.reason_phrase);
}

test "QUIC 1-RTT connection rejects invalid unidirectional stream controls before effects" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x31, 0x3a, 0x3b, 0x3c };
    const server_cid = [_]u8{ 0x35, 0x3e, 0x3f, 0x40 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x7a} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_endpoint = .client,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try one_rtt.sendFrames(&server_endpoint, client_endpoint.address(), keys, .{
        .destination_connection_id = &client_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{
            .{ .stream = .{ .stream_id = 1, .data = "before-max-stream-error", .fin = false } },
            .{ .max_stream_data = .{ .stream_id = 3, .maximum_stream_data = 64 } },
            .{ .ping = {} },
        },
    });
    try std.testing.expectError(error.StreamStateError, client.receivePacket());
    try std.testing.expectEqual(@as(u64, 0), client.recv_data_total);
    try std.testing.expectEqual(@as(usize, 0), client.stream_recv_flows.items.len);
    try std.testing.expectEqual(@as(usize, 0), client.received.ranges.items.len);
    try std.testing.expect(client.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.stream_state_error), client.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.max_stream_data)), client.close_info.?.frame_type);
    try std.testing.expectEqualStrings("stream state", client.close_info.?.reason_phrase);

    var client2_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client2_endpoint.deinit();
    const client2_cid = [_]u8{ 0x41, 0x4a, 0x4b, 0x4c };
    var client2 = try one_rtt.Connection.init(&client2_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client2_cid,
        .peer_connection_id = &server_cid,
        .local_endpoint = .client,
    });
    defer client2.deinit();

    try one_rtt.sendFrames(&server_endpoint, client2_endpoint.address(), keys, .{
        .destination_connection_id = &client2_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{
            .{ .stream = .{ .stream_id = 1, .data = "before-stop-error", .fin = false } },
            .{ .stop_sending = .{ .stream_id = 3, .application_error_code = 7 } },
        },
    });
    try std.testing.expectError(error.StreamStateError, client2.receivePacket());
    try std.testing.expectEqual(@as(u64, 0), client2.recv_data_total);
    try std.testing.expectEqual(@as(usize, 0), client2.stream_recv_flows.items.len);
    try std.testing.expectEqual(@as(usize, 0), client2.received.ranges.items.len);
    try std.testing.expect(client2.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.stream_state_error), client2.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.stop_sending)), client2.close_info.?.frame_type);

    var client3_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client3_endpoint.deinit();
    var server3_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server3_endpoint.deinit();
    const client3_cid = [_]u8{ 0x51, 0x5a, 0x5b, 0x5c };
    const server3_cid = [_]u8{ 0x55, 0x5e, 0x5f, 0x60 };
    var server3 = try one_rtt.Connection.init(&server3_endpoint, .{
        .peer = client3_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server3_cid,
        .peer_connection_id = &client3_cid,
        .local_endpoint = .server,
    });
    defer server3.deinit();

    try one_rtt.sendFrames(&client3_endpoint, server3_endpoint.address(), keys, .{
        .destination_connection_id = &server3_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{
            .{ .stream = .{ .stream_id = 0, .data = "before-blocked-error", .fin = false } },
            .{ .stream_data_blocked = .{ .stream_id = 3, .maximum_stream_data = 64 } },
        },
    });
    try std.testing.expectError(error.StreamStateError, server3.receivePacket());
    try std.testing.expectEqual(@as(u64, 0), server3.recv_data_total);
    try std.testing.expectEqual(@as(usize, 0), server3.stream_recv_flows.items.len);
    try std.testing.expectEqual(@as(usize, 0), server3.received.ranges.items.len);
    try std.testing.expect(server3.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.stream_state_error), server3.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.stream_data_blocked)), server3.close_info.?.frame_type);
}

test "QUIC 1-RTT connection preflights CID frames before receive-side effects" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x39, 0x3a, 0x3b, 0x3c };
    const server_cid = [_]u8{ 0x3d, 0x3e, 0x3f, 0x40 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x78} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_endpoint = .client,
    });
    defer client.deinit();

    try one_rtt.sendFrames(&server_endpoint, client_endpoint.address(), keys, .{
        .destination_connection_id = &client_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{
            .{ .stream = .{ .stream_id = 1, .data = "before-cid-error", .fin = false } },
            .{ .new_connection_id = .{
                .sequence_number = 1,
                .retire_prior_to = 0,
                .connection_id = &server_cid,
                .stateless_reset_token = [_]u8{0x99} ** 16,
            } },
        },
    });

    try std.testing.expectError(error.DuplicateConnectionId, client.receivePacket());
    try std.testing.expectEqual(@as(u64, 0), client.recv_data_total);
    try std.testing.expectEqual(@as(usize, 0), client.stream_recv_flows.items.len);
    try std.testing.expectEqual(@as(usize, 0), client.received.ranges.items.len);
    try std.testing.expectEqual(@as(u64, 0), client.expected_packet_number);
    try std.testing.expectEqual(@as(usize, 1), client.peer_connection_ids.count());
}

test "QUIC 1-RTT connection rejects role errors and ignores unmatched path responses" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x49, 0x4a, 0x4b, 0x4c };
    const server_cid = [_]u8{ 0x4d, 0x4e, 0x4f, 0x50 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x79} ** quic.protection.secret_len);

    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{
            .{ .stream = .{ .stream_id = 0, .data = "before-role-error", .fin = false } },
            .{ .handshake_done = {} },
        },
    });

    try std.testing.expectError(error.InvalidFrame, server.receivePacket());
    try std.testing.expectEqual(@as(u64, 0), server.recv_data_total);
    try std.testing.expectEqual(@as(usize, 0), server.stream_recv_flows.items.len);
    try std.testing.expectEqual(@as(usize, 0), server.received.ranges.items.len);
    try std.testing.expectEqual(@as(u64, 0), server.expected_packet_number);
    try std.testing.expect(!server.handshakeConfirmed());
    try std.testing.expect(server.closing());
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.handshake_done)), server.close_info.?.frame_type);

    var path_server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer path_server_endpoint.deinit();
    const path_server_cid = [_]u8{ 0x51, 0x52, 0x53, 0x54 };
    var path_server = try one_rtt.Connection.init(&path_server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &path_server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer path_server.deinit();

    try one_rtt.sendFrames(&client_endpoint, path_server_endpoint.address(), keys, .{
        .destination_connection_id = &path_server_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{
            .{ .stream = .{ .stream_id = 0, .data = "before-path-error", .fin = false } },
            .{ .path_response = .{ .data = [_]u8{0xaa} ** 8 } },
        },
    });

    var ignored = try path_server.receivePacket();
    ignored.deinit(allocator);
    try std.testing.expectEqual(@as(u64, "before-path-error".len), path_server.recv_data_total);
    try std.testing.expectEqual(@as(usize, 1), path_server.stream_recv_flows.items.len);
    try std.testing.expectEqual(@as(usize, 1), path_server.received.ranges.items.len);
    try std.testing.expectEqual(@as(u64, 1), path_server.expected_packet_number);
    try std.testing.expectEqual(@as(usize, 0), path_server.path_validation.outstandingChallengeCount());
    try std.testing.expect(!path_server.closing());
}

test "QUIC 1-RTT receivePacketAt updates RTT from ACK" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0xda, 0xdb, 0xdc, 0xdd };
    const server_cid = [_]u8{ 0xde, 0xdf, 0xe0, 0xe1 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xd3} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .peer_ack_delay_exponent = 3,
    });
    defer client.deinit();

    try client.sent.sentAtWithDatagramSizeAndPathEpoch(
        0,
        true,
        1200,
        1200,
        .not_ect,
        1_000_000,
        one_rtt.testing.currentPathEpoch(&client),
    );
    try one_rtt.sendFrames(&server_endpoint, client_endpoint.address(), keys, .{
        .destination_connection_id = &client_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .ack = .{
            .largest_acknowledged = 0,
            .ack_delay = 5,
            .first_ack_range = 0,
        } }},
    });

    var packet = try client.receivePacketAt(101_000_000);
    defer packet.deinit(allocator);
    try std.testing.expect(client.rtt_stats.has_measurement);
    try std.testing.expectEqual(@as(u64, 100_000_000), client.rtt_stats.latest_rtt);
    try std.testing.expect(client.sent.packets.items[0].acknowledged);
}

test "QUIC 1-RTT connection updates RTT from ACK samples" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0xd2} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
        .peer_ack_delay_exponent = 3,
        .peer_max_ack_delay_ms = 10,
    });
    defer connection.deinit();

    try connection.sent.sentAtWithDatagramSizeAndPathEpoch(
        0,
        true,
        1200,
        1200,
        .not_ect,
        1_000_000,
        one_rtt.testing.currentPathEpoch(&connection),
    );
    const ack = quic.AckFrame{ .largest_acknowledged = 0, .ack_delay = 5, .first_ack_range = 0 };
    try std.testing.expect(try connection.updateRttFromAck(ack, 101_000_000));
    try std.testing.expect(connection.rtt_stats.has_measurement);
    try std.testing.expectEqual(@as(u64, 100_000_000), connection.rtt_stats.latest_rtt);
    try std.testing.expectEqual(@as(u64, 10_000_000), connection.rtt_stats.max_ack_delay);
    const acked = try connection.sent.applyAckDetailed(ack);
    connection.congestion.onAcked(acked.bytes);
    try std.testing.expect(!(try connection.updateRttFromAck(ack, 102_000_000)));
    try std.testing.expectEqual(@as(u64, 100_000_000), connection.rtt_stats.latest_rtt);

    connection.markTlsHandshakeComplete();
    try connection.sent.sentAtWithDatagramSizeAndPathEpoch(
        1,
        true,
        1200,
        1200,
        .not_ect,
        201_000_000,
        one_rtt.testing.currentPathEpoch(&connection),
    );
    const ack2 = quic.AckFrame{ .largest_acknowledged = 1, .ack_delay = 5, .first_ack_range = 0 };
    try std.testing.expect(try connection.updateRttFromAck(ack2, 331_000_000));
    try std.testing.expect(connection.rtt_stats.smoothed_rtt > 100_000_000);

    const missing = quic.AckFrame{ .largest_acknowledged = 99, .ack_delay = 0, .first_ack_range = 0 };
    try std.testing.expect(!(try connection.updateRttFromAck(missing, 400_000_000)));
}

test "QUIC 1-RTT connection decodes peer ACK delay" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0xd1} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
        .peer_ack_delay_exponent = 4,
    });
    defer connection.deinit();

    const ack = quic.AckFrame{ .largest_acknowledged = 0, .ack_delay = 7, .first_ack_range = 0 };
    try std.testing.expectEqual(@as(u64, 7 * 16 * 1_000), try connection.decodedPeerAckDelayNanos(ack));

    connection.config.peer_ack_delay_exponent = quic.rtt.max_ack_delay_exponent + 1;
    try std.testing.expectError(error.InvalidFrame, connection.decodedPeerAckDelayNanos(ack));
}

test "QUIC 1-RTT closing state can retransmit close" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0xbb} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
    });
    defer connection.deinit();

    try connection.closeTransport(42, @intFromEnum(quic.FrameType.stream), "closing");
    try std.testing.expect(connection.closing());
    try std.testing.expectEqual(
        @as(?one_rtt.PeerCloseInfo, null),
        connection.peerCloseInfo(),
    );
    const before = connection.next_packet_number;
    try connection.resendClose();
    try std.testing.expectEqual(before + 1, connection.next_packet_number);

    try one_rtt.testing.applyReceivedFrames(&connection, 0, &.{.{ .connection_close = .{
        .error_code = 0,
        .frame_type = 0,
        .reason_phrase = "peer-close",
    } }}, null, .not_ect);
    try std.testing.expect(connection.draining());
    switch (connection.peerCloseInfo().?) {
        .transport => |close| {
            try std.testing.expectEqual(@as(u64, 0), close.error_code);
            try std.testing.expectEqual(@as(u64, 0), close.frame_type);
            try std.testing.expectEqualStrings(
                "peer-close",
                close.reason_phrase,
            );
        },
        .application => return error.TestUnexpectedResult,
    }
    try std.testing.expectError(error.ConnectionClosed, connection.resendClose());
}

test "QUIC 1-RTT draining state drops subsequent packets" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0xaa} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
    });
    defer connection.deinit();

    try one_rtt.testing.applyReceivedFrames(&connection, 0, &.{.{ .connection_close = .{
        .error_code = 0,
        .frame_type = 0,
        .reason_phrase = "bye",
    } }}, null, .not_ect);
    try std.testing.expect(connection.draining());
    try std.testing.expectError(error.ConnectionClosed, connection.receivePacket());
    try std.testing.expect((try connection.receivePacketOrDropAfterClose()) == null);
}

test "QUIC 1-RTT receive closes on frame payload errors" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
    const server_cid = [_]u8{ 0x35, 0x36, 0x37, 0x38 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xb4} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xb5} ** quic.protection.secret_len);

    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try sendPayloadForTest(&client_endpoint, server_endpoint.address(), client_keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .payload = &.{0x21},
    });

    try std.testing.expectError(error.InvalidFrame, server.receivePacketAt(1_000_000));
    try std.testing.expect(server.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.frame_encoding_error), server.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, 0x21), server.close_info.?.frame_type);
    try std.testing.expectEqualStrings("frame encoding", server.close_info.?.reason_phrase);

    var close_packet = try one_rtt.receive(&client_endpoint, server_keys, client_cid.len, 0, 8);
    defer close_packet.deinit(allocator);
    try std.testing.expectEqual(quic.Frame.connection_close, std.meta.activeTag(close_packet.frames[0]));
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.frame_encoding_error), close_packet.frames[0].connection_close.error_code);
    try std.testing.expectEqual(@as(u64, 0x21), close_packet.frames[0].connection_close.frame_type);
}

test "QUIC 1-RTT connection models idle timeout deadlines" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0x77} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
        .local_max_idle_timeout_ms = 1000,
        .peer_max_idle_timeout_ms = 2500,
    });
    defer connection.deinit();

    try std.testing.expectEqual(@as(?u64, 1000), connection.effectiveIdleTimeoutMillis());
    try std.testing.expectEqual(@as(?u64, null), connection.idleTimeoutDeadlineMillis());
    connection.markActivity(10);
    try std.testing.expectEqual(@as(?u64, 1010), connection.idleTimeoutDeadlineMillis());
    try std.testing.expect(!connection.checkIdleTimeout(1009));
    try std.testing.expect(!connection.closed());
    try std.testing.expect(connection.checkIdleTimeout(1010));
    try std.testing.expect(connection.closed());
    try std.testing.expectError(error.ConnectionClosed, connection.send(&[_]quic.Frame{.{ .ping = {} }}));
}

test "QUIC 1-RTT idle timeout restarts only on first ack-eliciting send" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0x74} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
        .local_max_idle_timeout_ms = 1000,
        .peer_max_idle_timeout_ms = 2500,
        .enable_pacing = false,
    });
    defer connection.deinit();

    connection.markPeerActivity(0);
    try std.testing.expectEqual(@as(?u64, 1000), connection.idleTimeoutDeadlineMillis());

    try connection.sendAt(&.{.{ .padding = .{ .len = 1 } }}, 10_000_000);
    try std.testing.expectEqual(@as(?u64, 1000), connection.idleTimeoutDeadlineMillis());

    try connection.sendAt(&.{.{ .ping = {} }}, 20_000_000);
    try std.testing.expectEqual(@as(?u64, 1020), connection.idleTimeoutDeadlineMillis());

    try connection.sendAt(&.{.{ .ping = {} }}, 30_000_000);
    try std.testing.expectEqual(@as(?u64, 1020), connection.idleTimeoutDeadlineMillis());

    connection.markPeerActivity(40);
    try connection.sendAt(&.{.{ .ping = {} }}, 50_000_000);
    try std.testing.expectEqual(@as(?u64, 1050), connection.idleTimeoutDeadlineMillis());
}

test "QUIC 1-RTT idle timeout is raised to three application PTOs" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x75} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "idle-local",
        .peer_connection_id = "idle-peer",
        .local_max_idle_timeout_ms = 1,
        .peer_max_idle_timeout_ms = 2,
    });
    defer connection.deinit();

    // With no RTT sample the 1-RTT PTO is the 300-ms initial base plus the
    // peer's default 25-ms max ACK delay. RFC 9000 requires a 975-ms lower
    // bound rather than expiring at the negotiated 1-ms preference.
    try std.testing.expectEqual(@as(u64, 325_000_000), connection.ptoPeriod());
    try std.testing.expectEqual(@as(?u64, 975), connection.effectiveIdleTimeoutMillis());
    connection.markActivity(10);
    try std.testing.expectEqual(@as(?u64, 985), connection.idleTimeoutDeadlineMillis());
    try std.testing.expect(!connection.checkIdleTimeout(984));
    try std.testing.expect(connection.checkIdleTimeout(985));
}

test "QUIC 1-RTT idle negotiation ignores a disabled peer value" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x79} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "idle-single-local",
        .peer_connection_id = "idle-single-peer",
        .local_max_idle_timeout_ms = 0,
        .peer_max_idle_timeout_ms = 1500,
    });
    defer connection.deinit();

    try std.testing.expectEqual(@as(?u64, 1500), connection.effectiveIdleTimeoutMillis());
    connection.config.peer_max_idle_timeout_ms = 0;
    try std.testing.expectEqual(@as(?u64, null), connection.effectiveIdleTimeoutMillis());
}

test "QUIC 1-RTT PTO jitter validates configuration and keeps armed deadline stable" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0x7a} ** quic.protection.secret_len);

    try std.testing.expectError(error.InvalidPtoJitter, one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "jitter-invalid-local",
        .peer_connection_id = "jitter-invalid-peer",
        .pto_jitter_percentage = 51,
    }));

    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "jitter-local",
        .peer_connection_id = "jitter-peer",
        .pto_jitter_percentage = 25,
    });
    defer connection.deinit();
    const ping = [_]quic.Frame{.{ .ping = {} }};
    try connection.sendAt(&ping, 10_000_000);

    const first = connection.ptoDeadline() orelse return error.TestUnexpectedResult;
    const first_epoch = connection.pto_jitter_state.epoch;
    try std.testing.expectEqual(first, connection.ptoDeadline().?);
    try std.testing.expectEqual(first, connection.nextTimerDeadline().?.deadline_ns);
    try std.testing.expect(first >= 253_750_000 and first <= 416_250_000);

    // A later packet at the exact same timestamp is nevertheless a distinct
    // timer-arm event. The explicit epoch avoids relying on clock resolution.
    try connection.sendAt(&ping, 10_000_000);
    try std.testing.expectEqual(first_epoch + 1, connection.pto_jitter_state.epoch);
    const rearmed = connection.ptoDeadline() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(rearmed, connection.ptoDeadline().?);
    try std.testing.expect(rearmed >= 253_750_000 and rearmed <= 416_250_000);
}

test "QUIC 1-RTT idle floor follows current RTT base PTO" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x76} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "idle-rtt-local",
        .peer_connection_id = "idle-rtt-peer",
        .local_max_idle_timeout_ms = 100,
        .peer_max_idle_timeout_ms = 200,
        .peer_max_ack_delay_ms = 50,
    });
    defer connection.deinit();

    connection.rtt_stats.update(100_000_000, 0, false);
    // smoothed RTT 100 ms + 4*variance 200 ms + peer ACK delay 50 ms.
    try std.testing.expectEqual(@as(u64, 350_000_000), connection.ptoPeriod());
    try std.testing.expectEqual(@as(?u64, 1050), connection.effectiveIdleTimeoutMillis());

    // PTO backoff protects retransmission scheduling but does not permanently
    // inflate the negotiated connection idle timeout.
    connection.pto_count = 1;
    try std.testing.expectEqual(@as(u64, 700_000_000), connection.ptoPeriod());
    try std.testing.expectEqual(@as(?u64, 1050), connection.effectiveIdleTimeoutMillis());
}

test "QUIC 1-RTT idle floor converts nanoseconds with ceiling" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x78} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "idle-ceil-local",
        .peer_connection_id = "idle-ceil-peer",
        .local_max_idle_timeout_ms = 1,
        .peer_max_ack_delay_ms = 0,
    });
    defer connection.deinit();

    connection.rtt_stats.has_measurement = true;
    connection.rtt_stats.smoothed_rtt = 1_000_001;
    connection.rtt_stats.rtt_var = 0;
    // PTO is 2,000,001 ns; 3*PTO must round upward to 7 ms so the millisecond
    // deadline cannot expire before the RFC-required nanosecond duration.
    try std.testing.expectEqual(@as(u64, 2_000_001), connection.ptoPeriod());
    try std.testing.expectEqual(@as(?u64, 7), connection.effectiveIdleTimeoutMillis());
}

test "QUIC 1-RTT keep-alive sends one PING after peer silence" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const server_cid = [_]u8{ 0xa5, 0xa6, 0xa7, 0xa8 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xa9} ** quic.protection.secret_len);

    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .local_max_idle_timeout_ms = 1000,
        .keep_alive_period_ms = 900,
        .tls_handshake_complete = true,
        .enable_pacing = false,
    });
    defer server.deinit();

    try std.testing.expect(server.keepAliveEnabled());
    // 900ms is capped to half of the 1000ms idle timeout. The initial 325-ms
    // application PTO yields a 487.5-ms floor, so the cap remains effective.
    try std.testing.expectEqual(@as(?u64, 500), server.keepAliveIntervalMillis());
    try std.testing.expectEqual(@as(?u64, null), server.keepAliveDeadlineMillis());

    server.markPeerActivity(10);
    try std.testing.expectEqual(@as(?u64, 510), server.keepAliveDeadlineMillis());
    try std.testing.expect(!try server.serviceKeepAliveAt(509));
    try std.testing.expect(try server.serviceKeepAliveAt(510));
    try std.testing.expect(server.keepAlivePingOutstanding());
    try std.testing.expectEqual(@as(?u64, null), server.keepAliveDeadlineMillis());
    try std.testing.expectEqual(@as(u64, 1), server.stats().packets_sent);

    var keep_alive = try one_rtt.receive(&client_endpoint, keys, client_cid.len, 0, 4);
    defer keep_alive.deinit(allocator);
    try std.testing.expectEqual(quic.Frame.ping, std.meta.activeTag(keep_alive.frames[0]));
    // A server that has just completed TLS can coalesce HANDSHAKE_DONE with
    // the keep-alive PING without delaying either reliability requirement.
    try std.testing.expectEqual(quic.Frame.handshake_done, std.meta.activeTag(keep_alive.frames[1]));

    try one_rtt.sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .frames = &.{.{ .ping = {} }},
    });
    var peer_packet = try server.receivePacketAt(700_000_000);
    defer peer_packet.deinit(allocator);
    try std.testing.expect(!server.keepAlivePingOutstanding());
    try std.testing.expectEqual(@as(?u64, 1200), server.keepAliveDeadlineMillis());
}

test "QUIC 1-RTT keep-alive waits for handshake confirmation" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0xab} ** quic.protection.secret_len);
    var client = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "ka-local",
        .peer_connection_id = "ka-peer",
        .keep_alive_period_ms = 1,
        .tls_handshake_complete = true,
        .enable_pacing = false,
    });
    defer client.deinit();

    try std.testing.expect(client.handshakeComplete());
    try std.testing.expect(!client.handshakeConfirmed());
    client.markPeerActivity(5);
    try std.testing.expectEqual(@as(?u64, null), client.keepAliveDeadlineMillis());
    try std.testing.expect(!try client.serviceKeepAliveAt(1_000));
}

test "QUIC 1-RTT next timer deadline selects earliest work" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const server_cid = [_]u8{ 0xb5, 0xb6, 0xb7, 0xb8 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xb9} ** quic.protection.secret_len);

    var connection = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .local_max_idle_timeout_ms = 1000,
        .keep_alive_period_ms = 900,
        .tls_handshake_complete = true,
        .enable_pacing = false,
    });
    defer connection.deinit();

    connection.markPeerActivity(0);
    try connection.sendAt(&.{.{ .ping = {} }}, 100_000_000);
    const pto = connection.nextTimerDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(one_rtt.TimerDeadlineKind.pto, pto.kind);
    try std.testing.expectEqual(@as(u64, 425_000_000), pto.deadline_ns);

    try connection.queuePathChallenge([_]u8{1} ** 8);
    try connection.sendPendingPathChallengeAt(10, 20);
    const path = connection.nextTimerDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(one_rtt.TimerDeadlineKind.path_validation, path.kind);
    try std.testing.expectEqual(@as(u64, 30), path.deadline_ns);

    try std.testing.expectEqual(@as(?one_rtt.TimerDeadline, null), try connection.serviceNextTimerAt(29));
    const serviced = (try connection.serviceNextTimerAt(30)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(one_rtt.TimerDeadlineKind.path_validation, serviced.kind);
    try std.testing.expectEqual(@as(usize, 0), connection.path_validation.pendingChallengeCount());
    try std.testing.expectEqual(@as(usize, 1), connection.path_validation.outstandingChallengeCount());
    try std.testing.expectEqual(
        @as(?u64, 30 + connection.ptoPeriod()),
        connection.pathValidationDeadline(),
    );
}

test "QUIC 1-RTT next timer deadline includes key discard" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0xba} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "deadline-local",
        .peer_connection_id = "deadline-peer",
        .enable_pacing = false,
    });
    defer connection.deinit();

    try connection.initiateKeyUpdate();
    connection.schedulePreviousOneRttKeyDiscard(7);
    const deadline = connection.nextTimerDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(one_rtt.TimerDeadlineKind.key_discard, deadline.kind);
    try std.testing.expectEqual(@as(u64, 7), deadline.deadline_ns);

    try std.testing.expectEqual(@as(?one_rtt.TimerDeadline, null), try connection.serviceNextTimerAt(6));
    const serviced = (try connection.serviceNextTimerAt(7)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(one_rtt.TimerDeadlineKind.key_discard, serviced.kind);
    try std.testing.expectEqual(@as(?i64, null), connection.oneRttKeyDiscardDeadline());
}

test "QUIC 1-RTT connection selects and exposes CUBIC congestion control" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0x79} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
    });
    defer connection.deinit();

    try std.testing.expectEqual(quic.congestion.Algorithm.cubic, connection.congestionAlgorithm());
    try std.testing.expectEqual(quic.congestion.initialWindow(1200), connection.congestionWindow());
    try std.testing.expectEqual(connection.congestionWindow(), connection.congestionAvailable());
    try std.testing.expectEqual(@as(usize, 0), connection.bytesInFlight());

    // The convenience send path must attach monotonic time automatically;
    // otherwise CUBIC and RFC 9002 loss detection silently degrade unless every
    // caller uses the lower-level sendAt API.
    try connection.send(&[_]quic.Frame{.{ .ping = {} }});
    try std.testing.expect(connection.bytesInFlight() > 0);
    try std.testing.expect(connection.congestionAvailable() < connection.congestionWindow());
    try std.testing.expect(connection.sent.packets.items[0].sent_time_ns != null);

    var reno = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local-reno",
        .peer_connection_id = "peer-reno",
        .congestion_algorithm = .new_reno,
    });
    defer reno.deinit();
    try std.testing.expectEqual(quic.congestion.Algorithm.new_reno, reno.congestionAlgorithm());
}

test "QUIC 1-RTT STREAM send keeps rollback credit on stack" {
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
    var local_endpoint = try quic.runtime.Endpoint.bind(
        counting.allocator(),
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer local_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x4a} ** quic.protection.secret_len,
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
    try connection.sendAt(&.{.{ .stream = .{
        .stream_id = 0,
        .data = &.{},
    } }}, 50);
    try connection.sent.packets.ensureTotalCapacity(counting.allocator(), 4);
    try connection.sendAt(&.{.{ .stream = .{
        .stream_id = 0,
        .data = &.{},
    } }}, 75);
    // Two acknowledged-style sends populate the cache's bounded free stack,
    // so the guarded send below exercises rollback metadata rather than a
    // first-use recovery allocation.
    _ = try connection.recovery.applyAck(.{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 1,
    });
    counting.fail_index = counting.alloc_index;

    try connection.sendAt(&.{.{ .stream = .{
        .stream_id = 0,
        .data = &.{},
    } }}, 100);
    try std.testing.expect(!counting.has_induced_failure);
}

test "QUIC 1-RTT pacing gates in-flight packets transactionally" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var peer_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer peer_endpoint.deinit();
    var local_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer local_endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0x7b} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&local_endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
        .max_datagram_size = 1200,
        .pacing_max_burst_packets = 1,
    });
    defer connection.deinit();

    const frames = [_]quic.Frame{.{ .padding = .{ .len = 1160 } }};
    try std.testing.expect(connection.pacingEnabled());
    try connection.sendAt(&frames, 1_000_000);
    const packet_len = connection.sent.packets.items[0].bytes;
    try std.testing.expectEqual(@as(u64, 1), connection.next_packet_number);
    try std.testing.expect(connection.pacingBudgetAt(1_000_000) < packet_len);

    const deadline = connection.pacingDeadlineAt(1_000_000, packet_len) orelse return error.TestUnexpectedResult;
    try std.testing.expect(deadline > 1_000_000);
    const sent_count = connection.sent.packets.items.len;
    const in_flight = connection.bytesInFlight();
    const blocked_data = [_]u8{0xa5} ** 128;
    const blocked_stream = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = &blocked_data,
        .fin = false,
    } }};
    try std.testing.expectError(error.PacingLimited, connection.sendAt(&blocked_stream, 1_000_000));
    try std.testing.expectEqual(@as(u64, 1), connection.next_packet_number);
    try std.testing.expectEqual(sent_count, connection.sent.packets.items.len);
    try std.testing.expectEqual(in_flight, connection.bytesInFlight());
    try std.testing.expectEqual(@as(usize, 0), connection.pendingRecoveryCount());
    try std.testing.expectEqual(@as(usize, 0), connection.stream_send_flows.items.len);
    try std.testing.expectEqual(@as(u64, 0), connection.send_flow.used);

    try connection.sendAt(&frames, deadline);
    try std.testing.expectEqual(@as(u64, 2), connection.next_packet_number);

    // Pure ACK packets are not in flight and must bypass pacing so a data burst
    // cannot delay feedback needed by the peer's recovery loop.
    const ack = [_]quic.Frame{.{ .ack = .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    } }};
    try connection.sendAt(&ack, deadline);
    try std.testing.expectEqual(@as(u64, 3), connection.next_packet_number);
}

test "QUIC 1-RTT trySend reports pacing without waiting" {
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
    var local_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer local_endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x7c} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&local_endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "try-local",
        .peer_connection_id = "try-peer",
        .max_datagram_size = 1200,
        .pacing_max_burst_packets = 1,
    });
    defer connection.deinit();

    const first = [_]quic.Frame{.{ .padding = .{ .len = 1160 } }};
    const now_ns: u64 = @intCast(@max(
        @as(i96, 0),
        std.Io.Clock.awake.now(io).nanoseconds,
    ));
    try connection.sendAt(&first, now_ns);
    const next_packet_number = connection.next_packet_number;
    const sent_count = connection.sent.packets.items.len;
    const in_flight = connection.bytesInFlight();
    const blocked = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = "payload",
    } }};

    // Keep the non-blocking assertion independent of how long this test was
    // descheduled after the first socket write. The fixed-time send above
    // intentionally seeded a synthetic pacing epoch; anchor it to the real
    // clock used by `trySend` immediately before checking the fast failure.
    one_rtt.testing.exhaustPacingAt(&connection, @intCast(@max(
        @as(i96, 0),
        std.Io.Clock.awake.now(io).nanoseconds,
    )));
    try std.testing.expectError(error.PacingLimited, connection.trySend(&blocked));
    try std.testing.expect(connection.pacing_blocked_until_ns != null);
    try std.testing.expectEqual(next_packet_number, connection.next_packet_number);
    try std.testing.expectEqual(sent_count, connection.sent.packets.items.len);
    try std.testing.expectEqual(in_flight, connection.bytesInFlight());
    try std.testing.expectEqual(@as(usize, 0), connection.pendingRecoveryCount());
    try std.testing.expectEqual(@as(usize, 0), connection.stream_send_flows.items.len);
}

test "QUIC 1-RTT can disable pacing" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0x7c} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
        .enable_pacing = false,
    });
    defer connection.deinit();

    try std.testing.expect(!connection.pacingEnabled());
    try std.testing.expectEqual(@as(?u64, null), try connection.nextPacketPacingDeadlineAt(0, std.math.maxInt(u32)));
}

test "QUIC 1-RTT send paths reject packet number exhaustion before mutation" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0x78} ** quic.protection.secret_len);
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
        .enable_ack_frequency = true,
        .enable_pmtud = true,
        .pmtud_max_probe_size = 1300,
        .max_datagram_size = 1400,
    });
    defer connection.deinit();

    const exhausted_packet_number = quic.protection.max_packet_number + 1;
    connection.next_packet_number = exhausted_packet_number;

    try std.testing.expectError(error.InvalidPacketNumber, connection.send(&[_]quic.Frame{.{ .ping = {} }}));
    try std.testing.expectEqual(exhausted_packet_number, connection.next_packet_number);
    try std.testing.expectEqual(@as(usize, 0), connection.sent.packets.items.len);
    try std.testing.expectEqual(@as(usize, 0), connection.pendingRecoveryCount());
    try std.testing.expectEqual(@as(usize, 0), connection.congestion.bytes_in_flight);

    try std.testing.expectError(error.InvalidPacketNumber, connection.send(&[_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = "must-not-open",
        .fin = false,
    } }}));
    try std.testing.expectEqual(@as(usize, 0), connection.stream_send_flows.items.len);
    try std.testing.expectEqual(@as(u64, 0), connection.send_flow.used);

    try std.testing.expectError(error.InvalidPacketNumber, connection.sendAckFrequency(4, 12_000, 5));
    try std.testing.expectEqual(@as(u64, 0), connection.ack_frequency_send_next_sequence);

    try std.testing.expectError(error.InvalidPacketNumber, connection.sendNewConnectionId("new-cid", [_]u8{0x71} ** 16));
    try std.testing.expectEqual(@as(usize, 1), connection.local_connection_ids.count());
    try std.testing.expectEqual(@as(u64, 1), connection.local_connection_ids.next_sequence_number);

    try std.testing.expect(connection.pmtudShouldProbe());
    try std.testing.expectError(error.InvalidPacketNumber, connection.sendPmtuProbeAt(1300, 100));
    try std.testing.expect(connection.pmtudShouldProbe());
    try std.testing.expectEqual(@as(?usize, null), connection.pmtud.probe_size);

    const challenge = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    try connection.queuePathChallenge(challenge);
    try std.testing.expectError(error.InvalidPacketNumber, connection.sendPendingPathChallengeAt(200, 50));
    try std.testing.expectEqual(@as(usize, 1), connection.path_validation.pendingChallengeCount());
    try std.testing.expectEqual(@as(usize, 0), connection.path_validation.outstandingChallengeCount());
}

test "QUIC 1-RTT connection rejects ACK for unsent packet numbers" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
    const server_cid = [_]u8{ 0x25, 0x26, 0x27, 0x28 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0x51} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0x52} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();

    try client.send(&[_]quic.Frame{.{ .ping = {} }});
    try std.testing.expectEqual(@as(usize, 1), client.sent.packets.items.len);
    try std.testing.expectEqual(@as(usize, 1), client.pendingRecoveryCount());
    const in_flight = client.congestion.bytes_in_flight;

    try one_rtt.sendFrames(&server_endpoint, client_endpoint.address(), server_keys, .{
        .destination_connection_id = &client_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .ack = .{
            .largest_acknowledged = 1,
            .ack_delay = 0,
            .first_ack_range = 0,
        } }},
    });

    try std.testing.expectError(error.InvalidAckFrame, client.receivePacket());
    try std.testing.expectEqual(@as(usize, 2), client.sent.packets.items.len);
    try std.testing.expect(!client.sent.packets.items[0].acknowledged);
    try std.testing.expect(!client.sent.packets.items[1].ack_eliciting);
    try std.testing.expectEqual(@as(usize, 1), client.pendingRecoveryCount());
    try std.testing.expectEqual(in_flight, client.congestion.bytes_in_flight);
    try std.testing.expectEqual(@as(?u64, null), client.sent.largestAcknowledged());
    try std.testing.expect(client.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.protocol_violation), client.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.ack)), client.close_info.?.frame_type);
    try std.testing.expectEqualStrings("ack", client.close_info.?.reason_phrase);
}

test "QUIC 1-RTT connection sends ACK_ECN for received ECN-marked packets" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x8a, 0x8b, 0x8c, 0x8d };
    const server_cid = [_]u8{ 0x8e, 0x8f, 0x90, 0x91 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0x85} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0x86} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try client.sendWithEcn(&ping, .ect0);
    try client.sendWithEcn(&ping, .ect1);
    try client.sendWithEcn(&ping, .ce);

    const marks = [_]quic.packet_space.EcnCodepoint{ .ect0, .ect1, .ce };
    for (marks) |mark| {
        var raw = try server_endpoint.receiveBytes();
        defer raw.deinit(allocator);
        const routed = quic.runtime.RoutedBytes{
            .datagram = raw,
            .route = .{ .connection_index = 0 },
            .destination_connection_id = &server_cid,
        };
        var packet = (try server.receiveRoutedDatagramWithEcnAt(
            routed,
            null,
            mark,
        )).?;
        defer packet.deinit(allocator);
    }
    try std.testing.expectEqual(@as(u64, 1), server.received.latestEcnCounts().?.ect0_count);
    try std.testing.expectEqual(@as(u64, 1), server.received.latestEcnCounts().?.ect1_count);
    try std.testing.expectEqual(@as(u64, 1), server.received.latestEcnCounts().?.ecn_ce_count);

    try server.sendAck(0);
    var ack = try client.receivePacket();
    defer ack.deinit(allocator);
    const counts = ack.frames[0].ack.ecn_counts orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 1), counts.ect0_count);
    try std.testing.expectEqual(@as(u64, 1), counts.ect1_count);
    try std.testing.expectEqual(@as(u64, 1), counts.ecn_ce_count);
}

test "QUIC 1-RTT receivePacket records socket ECN marks" {
    if (!quic.runtime.socketEcnSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();
    if (!server_endpoint.receive_ecn_enabled) return error.SkipZigTest;

    const client_cid = [_]u8{ 0x7a, 0x7b, 0x7c, 0x7d };
    const server_cid = [_]u8{ 0x7e, 0x7f, 0x80, 0x81 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0x87} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0x88} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    const ping = [_]quic.Frame{.{ .ping = {} }};
    client.sendWithEcn(&ping, .ect0) catch |err| switch (err) {
        error.EcnUnavailable => return error.SkipZigTest,
        else => return err,
    };

    var packet = try server.receivePacket();
    defer packet.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), packet.packet.packet_number);

    const counts = server.received.latestEcnCounts() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 1), counts.ect0_count);
    try std.testing.expectEqual(@as(u64, 0), counts.ect1_count);
    try std.testing.expectEqual(@as(u64, 0), counts.ecn_ce_count);
}

test "QUIC 1-RTT send automatically marks eligible packets ECT(0)" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x91} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "auto-ecn-local",
        .peer_connection_id = "auto-ecn-peer",
        .enable_pacing = false,
    });
    defer connection.deinit();

    try std.testing.expectEqual(
        quic.ecn.ValidationState.testing,
        one_rtt.testing.ecnPathState(&connection),
    );
    try connection.send(&.{.{ .ping = {} }});
    try std.testing.expectEqual(
        quic.packet_space.EcnCodepoint.ect0,
        one_rtt.testing.lastSentPacketEcn(&connection).?,
    );
    try std.testing.expectEqual(@as(u64, 1), connection.sent.stats().sent_ect0_count);

    try connection.send(&.{.{ .ack = .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    } }});
    try std.testing.expectEqual(
        quic.packet_space.EcnCodepoint.not_ect,
        one_rtt.testing.lastSentPacketEcn(&connection).?,
    );

    try connection.send(&.{.{ .path_challenge = .{
        .data = [_]u8{0x17} ** 8,
    } }});
    try std.testing.expectEqual(
        quic.packet_space.EcnCodepoint.not_ect,
        one_rtt.testing.lastSentPacketEcn(&connection).?,
    );

    try connection.sendWithEcn(&.{.{ .ping = {} }}, .ect1);
    try std.testing.expectEqual(
        quic.packet_space.EcnCodepoint.ect1,
        one_rtt.testing.lastSentPacketEcn(&connection).?,
    );
}

test "QUIC 1-RTT automatic ECN batch marks only an all-eligible batch" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x93} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "auto-ecn-batch-local",
        .peer_connection_id = "auto-ecn-batch-peer",
        .enable_pacing = false,
    });
    defer connection.deinit();

    const first = [_]quic.Frame{.{ .ping = {} }};
    const second = [_]quic.Frame{.{ .ping = {} }};
    const eligible = [_][]const quic.Frame{ &first, &second };
    const sent = try connection.sendManyProgressAt(&eligible, 1_000);
    try std.testing.expectEqual(@as(usize, 2), sent.sent_count);
    try std.testing.expectEqual(
        quic.packet_space.EcnCodepoint.ect0,
        connection.sent.packets.items[0].ecn,
    );
    try std.testing.expectEqual(
        quic.packet_space.EcnCodepoint.ect0,
        connection.sent.packets.items[1].ecn,
    );

    const ack_only = [_]quic.Frame{.{ .ack = .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    } }};
    const mixed = [_][]const quic.Frame{ &first, &ack_only };
    const mixed_sent = try connection.sendManyProgressAt(&mixed, 2_000);
    try std.testing.expectEqual(@as(usize, 2), mixed_sent.sent_count);
    try std.testing.expectEqual(
        quic.packet_space.EcnCodepoint.not_ect,
        connection.sent.packets.items[2].ecn,
    );
    try std.testing.expectEqual(
        quic.packet_space.EcnCodepoint.not_ect,
        connection.sent.packets.items[3].ecn,
    );
}

test "QUIC 1-RTT automatic ECN disabled policy keeps convenience sends Not-ECT" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x92} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "auto-ecn-off-local",
        .peer_connection_id = "auto-ecn-off-peer",
        .enable_pacing = false,
        .automatic_ecn_policy = .disabled,
    });
    defer connection.deinit();

    try std.testing.expectEqual(
        quic.ecn.ValidationState.disabled,
        one_rtt.testing.ecnPathState(&connection),
    );
    try connection.send(&.{.{ .ping = {} }});
    try std.testing.expectEqual(
        quic.packet_space.EcnCodepoint.not_ect,
        one_rtt.testing.lastSentPacketEcn(&connection).?,
    );
}

test "QUIC 1-RTT automatic ECN unavailable falls back without changing explicit sends" {
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
        [_]u8{0x94} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "ecn-fallback-local",
        .peer_connection_id = "ecn-fallback-peer",
        .enable_pacing = false,
    });
    defer connection.deinit();

    quic.runtime.testing.forceEcnUnavailable(&sender, true);
    try connection.send(&.{.{ .ping = {} }});
    try std.testing.expectEqual(
        quic.ecn.ValidationState.failed,
        one_rtt.testing.ecnPathState(&connection),
    );
    try std.testing.expectEqual(
        quic.packet_space.EcnCodepoint.not_ect,
        one_rtt.testing.lastSentPacketEcn(&connection).?,
    );
    try std.testing.expectEqual(@as(u64, 0), connection.sent.stats().sent_ect0_count);
    var delivered = try receiver.receiveBytes();
    delivered.deinit(allocator);

    // Explicit ECN is a strict caller request: it reports platform failure,
    // does not emit a Not-ECT substitute, and rolls back tracker state.
    const tracked_before = connection.sent.stats().tracked_packets;
    try std.testing.expectError(
        error.EcnUnavailable,
        connection.sendWithEcn(&.{.{ .ping = {} }}, .ect1),
    );
    try std.testing.expectEqual(
        tracked_before,
        connection.sent.stats().tracked_packets,
    );
    try std.testing.expectEqual(@as(u64, 0), connection.sent.stats().sent_ect1_count);
}

test "QUIC 1-RTT automatic ECN batch fallback rewrites every packet ledger" {
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
        [_]u8{0x95} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&sender, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "ecn-batch-fallback",
        .peer_connection_id = "ecn-batch-peer",
        .enable_pacing = false,
    });
    defer connection.deinit();

    quic.runtime.testing.forceEcnUnavailable(&sender, true);
    const first = [_]quic.Frame{.{ .ping = {} }};
    const second = [_]quic.Frame{.{ .ping = {} }};
    const packets = [_][]const quic.Frame{ &first, &second };
    const result = try connection.sendManyProgressAt(&packets, 1_000);
    try std.testing.expectEqual(@as(usize, 2), result.sent_count);
    try std.testing.expectEqual(
        quic.ecn.ValidationState.failed,
        one_rtt.testing.ecnPathState(&connection),
    );
    try std.testing.expectEqual(@as(u64, 0), connection.sent.stats().sent_ect0_count);
    for (connection.sent.packets.items) |packet| {
        try std.testing.expectEqual(
            quic.packet_space.EcnCodepoint.not_ect,
            packet.ecn,
        );
    }
    var first_datagram = try receiver.receiveBytes();
    first_datagram.deinit(allocator);
    var second_datagram = try receiver.receiveBytes();
    second_datagram.deinit(allocator);
    try std.testing.expectError(
        error.Timeout,
        receiver.receiveBytesWithTimeout(.fromMilliseconds(1)),
    );
}

test "QUIC 1-RTT connection validates ACK_ECN counters" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x2a, 0x2b, 0x2c, 0x2d };
    const server_cid = [_]u8{ 0x2e, 0x2f, 0x30, 0x31 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0x53} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0x54} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();

    try client.sendWithEcn(&[_]quic.Frame{.{ .ping = {} }}, .ect0);
    try one_rtt.sendFrames(&server_endpoint, client_endpoint.address(), server_keys, .{
        .destination_connection_id = &client_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .ack = .{
            .largest_acknowledged = 0,
            .ack_delay = 0,
            .first_ack_range = 0,
            .ecn_counts = .{ .ect0_count = 1, .ect1_count = 0, .ecn_ce_count = 0 },
        } }},
    });

    var valid = try client.receivePacket();
    defer valid.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), client.sent.latest_ecn_counts.ect0_count);
    try std.testing.expect(client.sent.packets.items[0].acknowledged);
    try std.testing.expectEqual(
        quic.ecn.ValidationState.capable,
        one_rtt.testing.ecnPathState(&client),
    );

    try client.sendWithEcn(&[_]quic.Frame{.{ .ping = {} }}, .ect1);
    const bytes_in_flight = client.congestion.bytes_in_flight;
    try one_rtt.sendFrames(&server_endpoint, client_endpoint.address(), server_keys, .{
        .destination_connection_id = &client_cid,
        .packet_number = 1,
        .frames = &[_]quic.Frame{.{ .ack = .{
            .largest_acknowledged = 1,
            .ack_delay = 0,
            .first_ack_range = 0,
            .ecn_counts = .{ .ect0_count = 1, .ect1_count = 2, .ecn_ce_count = 0 },
        } }},
    });

    var invalid_ecn_ack = try client.receivePacket();
    defer invalid_ecn_ack.deinit(allocator);
    try std.testing.expect(client.sent.packets.items[1].acknowledged);
    try std.testing.expect(client.congestion.bytes_in_flight < bytes_in_flight);
    try std.testing.expectEqual(@as(u64, 0), client.sent.latest_ecn_counts.ect1_count);
    try std.testing.expectEqual(
        quic.ecn.ValidationState.failed,
        one_rtt.testing.ecnPathState(&client),
    );
    try client.sendWithEcn(&[_]quic.Frame{.{ .ping = {} }}, .ect0);
    try std.testing.expectEqual(
        quic.packet_space.EcnCodepoint.ect0,
        one_rtt.testing.lastSentPacketEcn(&client).?,
    );
    try client.send(&[_]quic.Frame{.{ .ping = {} }});
    try std.testing.expectEqual(
        quic.packet_space.EcnCodepoint.not_ect,
        one_rtt.testing.lastSentPacketEcn(&client).?,
    );
}

test "QUIC 1-RTT plain ACK fails only automatic ECN on the current path" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();
    const client_cid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const server_cid = [_]u8{ 0xb5, 0xb6, 0xb7, 0xb8 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xb9} ** quic.protection.secret_len);
    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .enable_pacing = false,
    });
    defer client.deinit();

    try client.send(&.{.{ .ping = {} }});
    try one_rtt.testing.applyReceivedFrames(&client, 10, &.{.{ .ack = .{
        .largest_acknowledged = 0,
        .ack_delay = 0,
        .first_ack_range = 0,
    } }}, null, .not_ect);
    try std.testing.expectEqual(
        quic.ecn.ValidationState.failed,
        one_rtt.testing.ecnPathState(&client),
    );

    try client.send(&.{.{ .ping = {} }});
    try std.testing.expectEqual(
        quic.packet_space.EcnCodepoint.not_ect,
        one_rtt.testing.lastSentPacketEcn(&client).?,
    );
    try client.sendWithEcn(&.{.{ .ping = {} }}, .ect1);
    try std.testing.expectEqual(
        quic.packet_space.EcnCodepoint.ect1,
        one_rtt.testing.lastSentPacketEcn(&client).?,
    );
}

test "QUIC 1-RTT legacy ECN disable remains an explicit-send compatibility latch" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xba} ** quic.protection.secret_len,
    );
    var connection = try one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "legacy-ecn-local",
        .peer_connection_id = "legacy-ecn-peer",
        .enable_pacing = false,
    });
    defer connection.deinit();

    connection.sent.disableEcnValidation();
    try std.testing.expect(connection.sent.ecnDisabled());
    try std.testing.expect(connection.sent.stats().ecn_validation_failed);
    try std.testing.expectError(
        error.EcnDisabled,
        connection.sendWithEcn(&.{.{ .ping = {} }}, .ect0),
    );
    // The compatibility latch does not silently disable the new path policy.
    try connection.send(&.{.{ .ping = {} }});
    try std.testing.expectEqual(
        quic.packet_space.EcnCodepoint.ect0,
        one_rtt.testing.lastSentPacketEcn(&connection).?,
    );
}

test "QUIC 1-RTT ACK_ECN CE increase enters congestion recovery" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x2a, 0x2c, 0x2e, 0x30 };
    const server_cid = [_]u8{ 0x31, 0x33, 0x35, 0x37 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0x63} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0x64} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();

    try client.sendWithEcnAt(&[_]quic.Frame{.{ .ping = {} }}, .ect0, 100);
    const initial_window = client.congestion.congestion_window;
    try one_rtt.sendFrames(&server_endpoint, client_endpoint.address(), server_keys, .{
        .destination_connection_id = &client_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .ack = .{
            .largest_acknowledged = 0,
            .ack_delay = 0,
            .first_ack_range = 0,
            .ecn_counts = .{ .ect0_count = 0, .ect1_count = 0, .ecn_ce_count = 1 },
        } }},
    });

    var ack = try client.receivePacketAt(1_000);
    defer ack.deinit(allocator);
    const recovery_window = client.congestion.congestion_window;
    try std.testing.expectEqual(@as(usize, 0), client.congestion.bytes_in_flight);
    try std.testing.expectEqual(@max(initial_window * 7 / 10, quic.congestion.minimumWindow(client.config.max_datagram_size)), recovery_window);
    try std.testing.expectEqual(recovery_window, client.congestion.slow_start_threshold);
    try std.testing.expectEqual(@as(?u64, 1_000), client.congestion.congestion_recovery_start_time_ns);
    try std.testing.expectEqual(@as(u64, 1), client.sent.latest_ecn_counts.ecn_ce_count);
}

test "QUIC 1-RTT ACK_ECN CE increase respects congestion recovery" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x42, 0x44, 0x46, 0x48 };
    const server_cid = [_]u8{ 0x49, 0x4b, 0x4d, 0x4f };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0x73} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0x74} ** quic.protection.secret_len);

    var client = try one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();

    try client.sendWithEcnAt(&[_]quic.Frame{.{ .ping = {} }}, .ect0, 100); // packet 0
    try client.sendWithEcnAt(&[_]quic.Frame{.{ .ping = {} }}, .ect0, 200); // packet 1

    try one_rtt.sendFrames(&server_endpoint, client_endpoint.address(), server_keys, .{
        .destination_connection_id = &client_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .ack = .{
            .largest_acknowledged = 0,
            .ack_delay = 0,
            .first_ack_range = 0,
            .ecn_counts = .{ .ect0_count = 0, .ect1_count = 0, .ecn_ce_count = 1 },
        } }},
    });
    var first_ack = try client.receivePacketAt(1_000);
    defer first_ack.deinit(allocator);
    const recovery_window = client.congestion.congestion_window;

    try one_rtt.sendFrames(&server_endpoint, client_endpoint.address(), server_keys, .{
        .destination_connection_id = &client_cid,
        .packet_number = 1,
        .frames = &[_]quic.Frame{.{ .ack = .{
            .largest_acknowledged = 1,
            .ack_delay = 0,
            .first_ack_range = 0,
            .ecn_counts = .{ .ect0_count = 0, .ect1_count = 0, .ecn_ce_count = 2 },
        } }},
    });
    var second_ack = try client.receivePacketAt(1_500);
    defer second_ack.deinit(allocator);
    try std.testing.expectEqual(recovery_window, client.congestion.congestion_window);
    try std.testing.expectEqual(@as(u64, 2), client.sent.latest_ecn_counts.ecn_ce_count);
}

test "QUIC single-packet service applies stream data without owned packet" {
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
    const client_cid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const server_cid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc1} ** quic.protection.secret_len,
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
    try one_rtt.sendFrames(
        &client_endpoint,
        server_endpoint.address(),
        keys,
        .{
            .destination_connection_id = &server_cid,
            .packet_number = 0,
            .frames = &.{.{ .stream = .{
                .stream_id = 0,
                .data = "serviced",
                .fin = true,
            } }},
        },
    );
    try server.servicePacketAt(1_000);
    try std.testing.expectEqualStrings(
        "serviced",
        server.availableReceivedStream(0).?,
    );
    try std.testing.expectEqual(@as(u64, 1), server.expected_packet_number);
}

test "QUIC packet visitor exposes borrowed frames after transport apply" {
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
    const client_cid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };
    const server_cid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf1} ** quic.protection.secret_len,
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
    try one_rtt.sendFrames(
        &client_endpoint,
        server_endpoint.address(),
        keys,
        .{
            .destination_connection_id = &server_cid,
            .packet_number = 0,
            .frames = &.{.{ .stream = .{
                .stream_id = 0,
                .data = "visited",
                .fin = true,
            } }},
        },
    );

    const Observed = struct {
        connection: *one_rtt.Connection,
        from: ?std.Io.net.IpAddress = null,
        packet_number: ?u64 = null,
        stream_state_was_applied: bool = false,
        data: [7]u8 = undefined,

        fn visit(
            observed: *@This(),
            packet: one_rtt.ReceivedPacketView,
        ) !void {
            observed.from = packet.from;
            observed.packet_number = packet.packet_number;
            observed.stream_state_was_applied =
                observed.connection.availableReceivedStream(0) != null;
            try std.testing.expectEqual(@as(usize, 1), packet.frames.len);
            try std.testing.expect(packet.frames[0] == .stream);
            @memcpy(&observed.data, packet.frames[0].stream.data);
        }
    };
    var observed: Observed = .{ .connection = &server };
    try server.visitPacketAt(1_000, &observed, Observed.visit);
    try std.testing.expect(observed.from.?.eql(&client_endpoint.address()));
    try std.testing.expectEqual(@as(?u64, 0), observed.packet_number);
    try std.testing.expect(observed.stream_state_was_applied);
    try std.testing.expectEqualStrings("visited", &observed.data);
}
