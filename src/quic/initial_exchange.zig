const std = @import("std");
const quic = @import("mod.zig");

const net = std.Io.net;

pub const Error = quic.runtime.Error || quic.protection.Error || quic.crypto_stream.Error || quic.zero_rtt.Error || error{
    MissingCryptoFrame,
};

pub const min_initial_udp_datagram_size: usize = 1200;

pub const SendInitialOptions = struct {
    version: u32 = quic.Version.version_1.wireValue(),
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    token: []const u8 = &.{},
    packet_number: u64,
    packet_number_len: u8 = 4,
    crypto_offset: u64 = 0,
    max_crypto_frame_data_len: usize = 1024,
    /// Minimum UDP datagram size for an Initial packet. RFC 9000 requires
    /// clients to send Initial UDP datagrams of at least 1200 bytes; server
    /// callers can also set this when coalescing an Initial with Handshake data.
    min_datagram_size: usize = 0,
    crypto_data: []const u8,
};

pub const ReceivedInitialCrypto = struct {
    from: net.IpAddress,
    packet: quic.protection.OpenedInitialPacket,
    crypto_data: []u8,

    pub fn deinit(self: *ReceivedInitialCrypto, allocator: std.mem.Allocator) void {
        self.packet.deinit(allocator);
        allocator.free(self.crypto_data);
        self.* = undefined;
    }
};

pub const ReceivedHandshakeCrypto = struct {
    from: net.IpAddress,
    packet: quic.protection.OpenedHandshakePacket,
    crypto_data: []u8,

    pub fn deinit(self: *ReceivedHandshakeCrypto, allocator: std.mem.Allocator) void {
        self.packet.deinit(allocator);
        allocator.free(self.crypto_data);
        self.* = undefined;
    }
};

pub const ReceivedCoalescedInitialHandshakeCrypto = struct {
    from: net.IpAddress,
    initial: ?ReceivedInitialCrypto = null,
    handshake: ?ReceivedHandshakeCrypto = null,

    pub fn deinit(self: *ReceivedCoalescedInitialHandshakeCrypto, allocator: std.mem.Allocator) void {
        if (self.initial) |*initial| initial.deinit(allocator);
        if (self.handshake) |*handshake| handshake.deinit(allocator);
        self.* = undefined;
    }
};

pub fn sendInitialCrypto(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    options: SendInitialOptions,
) Error!void {
    const packet = try sealInitialCryptoPacket(endpoint.allocator, keys, options);
    defer endpoint.allocator.free(packet);
    try endpoint.sendBytes(to, packet);
}

pub fn sendCoalescedInitialHandshakeCrypto(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    initial_keys: quic.protection.PacketProtectionKeys,
    initial_options: SendInitialOptions,
    handshake_keys: quic.protection.PacketProtectionKeys,
    handshake_options: SendInitialOptions,
) Error!void {
    const initial_packet = try sealInitialCryptoPacket(endpoint.allocator, initial_keys, initial_options);
    defer endpoint.allocator.free(initial_packet);

    var handshake_payload: std.ArrayList(u8) = .empty;
    defer handshake_payload.deinit(endpoint.allocator);
    try quic.crypto_stream.writeCryptoFrames(
        &handshake_payload,
        endpoint.allocator,
        handshake_options.crypto_offset,
        handshake_options.crypto_data,
        handshake_options.max_crypto_frame_data_len,
    );
    const handshake_packet = try quic.protection.sealHandshakePacket(endpoint.allocator, handshake_keys, .{
        .version = handshake_options.version,
        .destination_connection_id = handshake_options.destination_connection_id,
        .source_connection_id = handshake_options.source_connection_id,
        .packet_number = handshake_options.packet_number,
        .packet_number_len = handshake_options.packet_number_len,
        .payload = handshake_payload.items,
    });
    defer endpoint.allocator.free(handshake_packet);

    var coalesced: std.ArrayList(u8) = .empty;
    defer coalesced.deinit(endpoint.allocator);
    try coalesced.appendSlice(endpoint.allocator, initial_packet);
    try coalesced.appendSlice(endpoint.allocator, handshake_packet);
    try endpoint.sendBytes(to, coalesced.items);
}

pub fn sendCoalescedInitialZeroRtt(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    initial_keys: quic.protection.PacketProtectionKeys,
    initial_options: SendInitialOptions,
    zero_rtt_keys: quic.protection.PacketProtectionKeys,
    zero_rtt_options: quic.zero_rtt.SendOptions,
) Error!void {
    for (zero_rtt_options.frames) |frame| {
        try quic.validateFrameForPacketType(frame, .zero_rtt);
    }

    const zero_rtt_payload = try quic.zero_rtt.encodeFrames(
        endpoint.allocator,
        zero_rtt_options.frames,
    );
    defer endpoint.allocator.free(zero_rtt_payload);
    const zero_rtt_packet = try quic.protection.sealZeroRttPacket(
        endpoint.allocator,
        zero_rtt_keys,
        .{
            .version = zero_rtt_options.version,
            .destination_connection_id = zero_rtt_options.destination_connection_id,
            .source_connection_id = zero_rtt_options.source_connection_id,
            .packet_number = zero_rtt_options.packet_number,
            .packet_number_len = zero_rtt_options.packet_number_len,
            .payload = zero_rtt_payload,
        },
    );
    defer endpoint.allocator.free(zero_rtt_packet);

    var unpadded_initial_options = initial_options;
    unpadded_initial_options.min_datagram_size = 0;
    var initial_packet = try sealInitialCryptoPacket(
        endpoint.allocator,
        initial_keys,
        unpadded_initial_options,
    );
    defer endpoint.allocator.free(initial_packet);

    const unpadded_len = std.math.add(
        usize,
        initial_packet.len,
        zero_rtt_packet.len,
    ) catch return error.DatagramTooLarge;
    if (unpadded_len < initial_options.min_datagram_size) {
        unpadded_initial_options.min_datagram_size =
            initial_options.min_datagram_size - zero_rtt_packet.len;
        const padded_initial_packet = try sealInitialCryptoPacket(
            endpoint.allocator,
            initial_keys,
            unpadded_initial_options,
        );
        endpoint.allocator.free(initial_packet);
        initial_packet = padded_initial_packet;
    }

    const coalesced_len = std.math.add(
        usize,
        initial_packet.len,
        zero_rtt_packet.len,
    ) catch return error.DatagramTooLarge;
    var coalesced: std.ArrayList(u8) = .empty;
    defer coalesced.deinit(endpoint.allocator);
    try coalesced.ensureTotalCapacity(
        endpoint.allocator,
        coalesced_len,
    );
    coalesced.appendSliceAssumeCapacity(initial_packet);
    coalesced.appendSliceAssumeCapacity(zero_rtt_packet);
    try endpoint.sendBytes(to, coalesced.items);
}

fn sealInitialCryptoPacket(
    allocator: std.mem.Allocator,
    keys: quic.protection.PacketProtectionKeys,
    options: SendInitialOptions,
) Error![]u8 {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try quic.crypto_stream.writeCryptoFrames(
        &payload,
        allocator,
        options.crypto_offset,
        options.crypto_data,
        options.max_crypto_frame_data_len,
    );

    while (true) {
        const packet = try quic.protection.sealInitialPacket(allocator, keys, .{
            .version = options.version,
            .destination_connection_id = options.destination_connection_id,
            .source_connection_id = options.source_connection_id,
            .token = options.token,
            .packet_number = options.packet_number,
            .packet_number_len = options.packet_number_len,
            .payload = payload.items,
        });
        if (packet.len >= options.min_datagram_size) return packet;
        const missing = options.min_datagram_size - packet.len;
        allocator.free(packet);
        // PADDING frames are encrypted payload bytes.  Adding at least the
        // observed shortfall converges quickly even when the long-header Length
        // varint grows by a byte at a boundary.
        try payload.appendNTimes(allocator, @intFromEnum(quic.FrameType.padding), missing);
    }
}

pub fn receiveInitialCrypto(
    endpoint: *quic.runtime.Endpoint,
    keys: quic.protection.PacketProtectionKeys,
    expected_packet_number: u64,
    max_crypto_buffer: usize,
) Error!ReceivedInitialCrypto {
    var datagram = try endpoint.receiveBytes();
    defer datagram.deinit(endpoint.allocator);
    return openInitialCrypto(endpoint, datagram.from, datagram.bytes, keys, expected_packet_number, max_crypto_buffer);
}

pub fn sendHandshakeCrypto(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    options: SendInitialOptions,
) Error!void {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(endpoint.allocator);
    try quic.crypto_stream.writeCryptoFrames(
        &payload,
        endpoint.allocator,
        options.crypto_offset,
        options.crypto_data,
        options.max_crypto_frame_data_len,
    );
    const packet = try quic.protection.sealHandshakePacket(endpoint.allocator, keys, .{
        .version = options.version,
        .destination_connection_id = options.destination_connection_id,
        .source_connection_id = options.source_connection_id,
        .packet_number = options.packet_number,
        .packet_number_len = options.packet_number_len,
        .payload = payload.items,
    });
    defer endpoint.allocator.free(packet);
    try endpoint.sendBytes(to, packet);
}

pub fn receiveHandshakeCrypto(
    endpoint: *quic.runtime.Endpoint,
    keys: quic.protection.PacketProtectionKeys,
    expected_packet_number: u64,
    max_crypto_buffer: usize,
) Error!ReceivedHandshakeCrypto {
    var datagram = try endpoint.receiveBytes();
    defer datagram.deinit(endpoint.allocator);
    return openHandshakeCrypto(endpoint, datagram.from, datagram.bytes, keys, expected_packet_number, max_crypto_buffer);
}

pub fn receiveCoalescedInitialHandshakeCrypto(
    endpoint: *quic.runtime.Endpoint,
    initial_keys: quic.protection.PacketProtectionKeys,
    handshake_keys: quic.protection.PacketProtectionKeys,
    expected_initial_packet_number: u64,
    expected_handshake_packet_number: u64,
    max_crypto_buffer: usize,
) Error!ReceivedCoalescedInitialHandshakeCrypto {
    var datagram = try endpoint.receiveBytes();
    defer datagram.deinit(endpoint.allocator);
    return openCoalescedInitialHandshakeCrypto(
        endpoint,
        datagram.from,
        datagram.bytes,
        initial_keys,
        handshake_keys,
        expected_initial_packet_number,
        expected_handshake_packet_number,
        max_crypto_buffer,
    );
}

pub fn openCoalescedInitialHandshakeCrypto(
    endpoint: *quic.runtime.Endpoint,
    from: net.IpAddress,
    bytes: []const u8,
    initial_keys: quic.protection.PacketProtectionKeys,
    handshake_keys: quic.protection.PacketProtectionKeys,
    expected_initial_packet_number: u64,
    expected_handshake_packet_number: u64,
    max_crypto_buffer: usize,
) Error!ReceivedCoalescedInitialHandshakeCrypto {
    var result = ReceivedCoalescedInitialHandshakeCrypto{ .from = from };
    errdefer result.deinit(endpoint.allocator);

    var offset: usize = 0;
    while (offset < bytes.len) {
        const info = try quic.protection.peekProtectedLongPacketInfo(bytes[offset..]);
        if (info.len == 0) return error.InvalidInitialPacket;
        const packet_bytes = bytes[offset..][0..info.len];
        switch (info.packet_type) {
            .initial => {
                if (result.initial != null) return error.InvalidInitialPacket;
                result.initial = try openInitialCrypto(
                    endpoint,
                    from,
                    packet_bytes,
                    initial_keys,
                    expected_initial_packet_number,
                    max_crypto_buffer,
                );
            },
            .handshake => {
                if (result.handshake != null) return error.InvalidInitialPacket;
                result.handshake = try openHandshakeCrypto(
                    endpoint,
                    from,
                    packet_bytes,
                    handshake_keys,
                    expected_handshake_packet_number,
                    max_crypto_buffer,
                );
            },
            .zero_rtt, .retry => return error.InvalidInitialPacket,
        }
        offset += info.len;
    }

    if (result.initial == null and result.handshake == null) return error.MissingCryptoFrame;
    return result;
}

pub fn openInitialCrypto(
    endpoint: *quic.runtime.Endpoint,
    from: net.IpAddress,
    bytes: []const u8,
    keys: quic.protection.PacketProtectionKeys,
    expected_packet_number: u64,
    max_crypto_buffer: usize,
) Error!ReceivedInitialCrypto {
    var packet = try quic.protection.openInitialPacket(endpoint.allocator, keys, bytes, expected_packet_number);
    errdefer packet.deinit(endpoint.allocator);
    const crypto_data = try cryptoDataFromPayload(endpoint.allocator, packet.payload, max_crypto_buffer, .initial);
    errdefer endpoint.allocator.free(crypto_data);
    return .{ .from = from, .packet = packet, .crypto_data = crypto_data };
}

pub fn openHandshakeCrypto(
    endpoint: *quic.runtime.Endpoint,
    from: net.IpAddress,
    bytes: []const u8,
    keys: quic.protection.PacketProtectionKeys,
    expected_packet_number: u64,
    max_crypto_buffer: usize,
) Error!ReceivedHandshakeCrypto {
    var packet = try quic.protection.openHandshakePacket(endpoint.allocator, keys, bytes, expected_packet_number);
    errdefer packet.deinit(endpoint.allocator);
    const crypto_data = try cryptoDataFromPayload(endpoint.allocator, packet.payload, max_crypto_buffer, .handshake);
    errdefer endpoint.allocator.free(crypto_data);
    return .{ .from = from, .packet = packet, .crypto_data = crypto_data };
}

fn cryptoDataFromPayload(
    allocator: std.mem.Allocator,
    payload: []const u8,
    max_crypto_buffer: usize,
    packet_type: quic.FramePacketType,
) Error![]u8 {
    var reassembler = quic.crypto_stream.Reassembler.init(allocator, max_crypto_buffer);
    defer reassembler.deinit();

    var pos: usize = 0;
    var saw_crypto = false;
    while (pos < payload.len) {
        var parsed = try quic.parseFrameOwned(allocator, payload[pos..]);
        defer parsed.deinitOwned(allocator);
        try quic.validateFrameForPacketType(parsed.frame, packet_type);
        if (parsed.frame == .crypto) {
            saw_crypto = true;
            try reassembler.insert(parsed.frame.crypto);
        }
        pos += parsed.consumed;
    }
    if (!saw_crypto) return error.MissingCryptoFrame;
    return reassembler.readAllAvailable(allocator);
}

test "QUIC Initial CRYPTO bytes exchange over UDP endpoint" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try quic.runtime.Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer server.deinit();

    var client = try quic.runtime.Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer client.deinit();

    const original_dcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const client_scid = [_]u8{ 9, 9, 9, 9 };
    const server_scid = [_]u8{ 7, 7, 7, 7 };
    const secrets = quic.protection.deriveInitialSecrets(&original_dcid);

    try sendInitialCrypto(&client.endpoint, server.address(), secrets.client, .{
        .destination_connection_id = &original_dcid,
        .source_connection_id = &client_scid,
        .packet_number = 0,
        .crypto_data = "client hello",
        .max_crypto_frame_data_len = 4,
    });

    var server_received = try receiveInitialCrypto(&server.endpoint, secrets.client, 0, 1024);
    defer server_received.deinit(allocator);
    try std.testing.expect(server_received.from.eql(&client.address()));
    try std.testing.expectEqual(@as(u64, 0), server_received.packet.packet_number);
    try std.testing.expectEqualStrings("client hello", server_received.crypto_data);

    try sendInitialCrypto(&server.endpoint, server_received.from, secrets.server, .{
        .destination_connection_id = &client_scid,
        .source_connection_id = &server_scid,
        .packet_number = 0,
        .crypto_data = "server hello",
        .max_crypto_frame_data_len = 5,
    });

    var client_received = try receiveInitialCrypto(&client.endpoint, secrets.server, 0, 1024);
    defer client_received.deinit(allocator);
    try std.testing.expect(client_received.from.eql(&server.address()));
    try std.testing.expectEqualStrings("server hello", client_received.crypto_data);
}

test "QUIC Initial CRYPTO sender pads datagrams to requested minimum" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try quic.runtime.Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_datagram_size = 4096,
    });
    defer server.deinit();

    var client = try quic.runtime.Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .max_datagram_size = 4096,
    });
    defer client.deinit();

    const dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02 };
    const scid = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    const keys = quic.protection.deriveInitialSecrets(&dcid).client;

    try sendInitialCrypto(&client.endpoint, server.address(), keys, .{
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 0,
        .crypto_data = "hello",
        .min_datagram_size = min_initial_udp_datagram_size,
    });

    var raw = try server.endpoint.receiveBytes();
    defer raw.deinit(allocator);
    try std.testing.expect(raw.bytes.len >= min_initial_udp_datagram_size);

    var opened = try openInitialCrypto(&server.endpoint, raw.from, raw.bytes, keys, 0, 1024);
    defer opened.deinit(allocator);
    try std.testing.expectEqualStrings("hello", opened.crypto_data);
}

test "QUIC Initial CRYPTO exchange supports QUIC v2 packet protection" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try quic.runtime.Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_datagram_size = 4096,
    });
    defer server.deinit();

    var client = try quic.runtime.Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .max_datagram_size = 4096,
    });
    defer client.deinit();

    const version = quic.Version.version_2.wireValue();
    const dcid = [_]u8{ 0xba, 0xdc, 0x0f, 0xfe, 0xe0, 0xdd, 0xf0, 0x0d };
    const scid = [_]u8{ 0x01, 0x03, 0x03, 0x07 };
    const keys = (try quic.protection.deriveInitialSecretsForVersion(version, &dcid)).client;

    try sendInitialCrypto(&client.endpoint, server.address(), keys, .{
        .version = version,
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 0,
        .crypto_data = "v2 client hello",
    });

    var raw = try server.endpoint.receiveBytes();
    defer raw.deinit(allocator);
    const info = try quic.protection.peekProtectedLongPacketInfo(raw.bytes);
    try std.testing.expectEqual(version, info.version);
    try std.testing.expectEqual(quic.protection.ProtectedLongPacketType.initial, info.packet_type);

    var opened = try openInitialCrypto(&server.endpoint, raw.from, raw.bytes, keys, 0, 1024);
    defer opened.deinit(allocator);
    try std.testing.expectEqual(version, opened.packet.version);
    try std.testing.expectEqualStrings("v2 client hello", opened.crypto_data);
}

test "QUIC long-header CRYPTO receive rejects forbidden frame contexts" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_datagram_size = 4096,
    });
    defer endpoint.deinit();

    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const scid = [_]u8{ 0x05, 0x06, 0x07, 0x08 };
    const initial_keys = quic.protection.deriveInitialSecrets(&dcid).client;

    var bad_initial_payload: std.ArrayList(u8) = .empty;
    defer bad_initial_payload.deinit(allocator);
    try (quic.Frame{ .stream = .{ .stream_id = 0, .data = "not allowed", .fin = false } }).write(&bad_initial_payload, allocator);
    const bad_initial = try quic.protection.sealInitialPacket(allocator, initial_keys, .{
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 0,
        .packet_number_len = 4,
        .payload = bad_initial_payload.items,
    });
    defer allocator.free(bad_initial);
    try std.testing.expectError(error.InvalidFrame, openInitialCrypto(
        &endpoint,
        endpoint.address(),
        bad_initial,
        initial_keys,
        0,
        1024,
    ));

    const handshake_keys = quic.protection.deriveAes128Keys([_]u8{0xd4} ** quic.protection.secret_len);
    var bad_handshake_payload: std.ArrayList(u8) = .empty;
    defer bad_handshake_payload.deinit(allocator);
    try (quic.Frame{ .application_close = .{ .error_code = 1, .reason_phrase = "nope" } }).write(&bad_handshake_payload, allocator);
    const bad_handshake = try quic.protection.sealHandshakePacket(allocator, handshake_keys, .{
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 0,
        .packet_number_len = 4,
        .payload = bad_handshake_payload.items,
    });
    defer allocator.free(bad_handshake);
    try std.testing.expectError(error.InvalidFrame, openHandshakeCrypto(
        &endpoint,
        endpoint.address(),
        bad_handshake,
        handshake_keys,
        0,
        1024,
    ));
}

test "QUIC coalesced Initial and Handshake CRYPTO exchange over UDP endpoint" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try quic.runtime.Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer server.deinit();

    var client = try quic.runtime.Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer client.deinit();

    const original_dcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
    const client_scid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const secrets = quic.protection.deriveInitialSecrets(&original_dcid);
    const handshake_keys = quic.protection.deriveAes128Keys([_]u8{0xc7} ** quic.protection.secret_len);

    try sendCoalescedInitialHandshakeCrypto(
        &client.endpoint,
        server.address(),
        secrets.client,
        .{
            .destination_connection_id = &original_dcid,
            .source_connection_id = &client_scid,
            .packet_number = 0,
            .crypto_data = "coalesced initial",
            .max_crypto_frame_data_len = 5,
        },
        handshake_keys,
        .{
            .destination_connection_id = &original_dcid,
            .source_connection_id = &client_scid,
            .packet_number = 0,
            .crypto_data = "coalesced handshake",
            .max_crypto_frame_data_len = 7,
        },
    );

    var received = try receiveCoalescedInitialHandshakeCrypto(&server.endpoint, secrets.client, handshake_keys, 0, 0, 1024);
    defer received.deinit(allocator);
    try std.testing.expect(received.from.eql(&client.address()));
    try std.testing.expect(received.initial != null);
    try std.testing.expect(received.handshake != null);
    try std.testing.expectEqualStrings("coalesced initial", received.initial.?.crypto_data);
    try std.testing.expectEqualStrings("coalesced handshake", received.handshake.?.crypto_data);
    try std.testing.expectEqual(@as(u64, 0), received.initial.?.packet.packet_number);
    try std.testing.expectEqual(@as(u64, 0), received.handshake.?.packet.packet_number);
    try std.testing.expectEqualSlices(u8, &original_dcid, received.initial.?.packet.destination_connection_id);
    try std.testing.expectEqualSlices(u8, &original_dcid, received.handshake.?.packet.destination_connection_id);
}
