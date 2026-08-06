const std = @import("std");
const quic = @import("mod.zig");

const net = std.Io.net;

pub const Error = quic.runtime.Error || quic.protection.Error || quic.crypto_stream.Error || error{
    MissingCryptoFrame,
};

pub const SendInitialOptions = struct {
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    token: []const u8 = &.{},
    packet_number: u64,
    packet_number_len: u8 = 4,
    crypto_offset: u64 = 0,
    max_crypto_frame_data_len: usize = 1024,
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
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(endpoint.allocator);
    try quic.crypto_stream.writeCryptoFrames(
        &payload,
        endpoint.allocator,
        options.crypto_offset,
        options.crypto_data,
        options.max_crypto_frame_data_len,
    );
    const packet = try quic.protection.sealInitialPacket(endpoint.allocator, keys, .{
        .destination_connection_id = options.destination_connection_id,
        .source_connection_id = options.source_connection_id,
        .token = options.token,
        .packet_number = options.packet_number,
        .packet_number_len = options.packet_number_len,
        .payload = payload.items,
    });
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
    var initial_payload: std.ArrayList(u8) = .empty;
    defer initial_payload.deinit(endpoint.allocator);
    try quic.crypto_stream.writeCryptoFrames(
        &initial_payload,
        endpoint.allocator,
        initial_options.crypto_offset,
        initial_options.crypto_data,
        initial_options.max_crypto_frame_data_len,
    );
    const initial_packet = try quic.protection.sealInitialPacket(endpoint.allocator, initial_keys, .{
        .destination_connection_id = initial_options.destination_connection_id,
        .source_connection_id = initial_options.source_connection_id,
        .token = initial_options.token,
        .packet_number = initial_options.packet_number,
        .packet_number_len = initial_options.packet_number_len,
        .payload = initial_payload.items,
    });
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
    const crypto_data = try cryptoDataFromPayload(endpoint.allocator, packet.payload, max_crypto_buffer);
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
    const crypto_data = try cryptoDataFromPayload(endpoint.allocator, packet.payload, max_crypto_buffer);
    errdefer endpoint.allocator.free(crypto_data);
    return .{ .from = from, .packet = packet, .crypto_data = crypto_data };
}

fn cryptoDataFromPayload(allocator: std.mem.Allocator, payload: []const u8, max_crypto_buffer: usize) Error![]u8 {
    var reassembler = quic.crypto_stream.Reassembler.init(allocator, max_crypto_buffer);
    defer reassembler.deinit();

    var pos: usize = 0;
    var saw_crypto = false;
    while (pos < payload.len) {
        const parsed = try quic.parseFrame(payload[pos..]);
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
