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

pub fn receiveInitialCrypto(
    endpoint: *quic.runtime.Endpoint,
    keys: quic.protection.PacketProtectionKeys,
    expected_packet_number: u64,
    max_crypto_buffer: usize,
) Error!ReceivedInitialCrypto {
    var datagram = try endpoint.receiveBytes();
    defer datagram.deinit(endpoint.allocator);
    var packet = try quic.protection.openInitialPacket(endpoint.allocator, keys, datagram.bytes, expected_packet_number);
    errdefer packet.deinit(endpoint.allocator);

    var reassembler = quic.crypto_stream.Reassembler.init(endpoint.allocator, max_crypto_buffer);
    defer reassembler.deinit();
    var pos: usize = 0;
    var saw_crypto = false;
    while (pos < packet.payload.len) {
        const parsed = try quic.parseFrame(packet.payload[pos..]);
        if (parsed.frame == .crypto) {
            saw_crypto = true;
            try reassembler.insert(parsed.frame.crypto);
        }
        pos += parsed.consumed;
    }
    if (!saw_crypto) return error.MissingCryptoFrame;
    const crypto_data = try reassembler.readAllAvailable(endpoint.allocator);
    errdefer endpoint.allocator.free(crypto_data);
    return .{ .from = datagram.from, .packet = packet, .crypto_data = crypto_data };
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
