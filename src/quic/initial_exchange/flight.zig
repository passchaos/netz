//! MTU-bounded QUIC Initial CRYPTO flight packetization and reassembly.
//!
//! Each flight datagram contains one complete protected Initial packet. This
//! avoids IP fragmentation for large TLS messages while preserving CRYPTO
//! stream offsets across packet boundaries.

const std = @import("std");
const quic = @import("../mod.zig");

const net = std.Io.net;

pub const Error = quic.runtime.Error ||
    quic.protection.Error ||
    quic.crypto_stream.Error ||
    quic.Error ||
    error{MissingCryptoFrame};

pub const min_initial_udp_datagram_size: usize = 1200;

pub const SendInitialOptions = struct {
    version: u32 = quic.Version.version_1.wireValue(),
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    token: []const u8 = &.{},
    packet_number: u64,
    packet_number_len: u8 = 4,
    fixed_bit: bool = true,
    crypto_offset: u64 = 0,
    max_crypto_frame_data_len: usize = 1024,
    /// Minimum UDP datagram size for an Initial packet. RFC 9000 requires
    /// clients to send Initial UDP datagrams of at least 1200 bytes.
    min_datagram_size: usize = 0,
    crypto_data: []const u8,
};

pub const SendOptions = struct {
    initial: SendInitialOptions,
    /// Upper bound for every UDP datagram in the flight.
    max_datagram_size: usize = min_initial_udp_datagram_size,
    /// Bounds work and packet-number consumption for adversarially large input.
    max_datagrams: usize = 64,
};

pub const Sent = struct {
    packet_count: usize,
    last_packet_number: u64,
};

pub const ReceiveOptions = struct {
    expected_packet_number: u64,
    max_crypto_buffer: usize,
    /// Exact bytes required before returning. When null, the first contiguous
    /// TLS handshake header supplies the target length.
    expected_crypto_len: ?usize = null,
    /// Minimum length for each standalone received datagram.
    min_datagram_size: usize = 0,
    max_datagrams: usize = 64,
    allow_zero_fixed_bit: bool = false,
};

pub const Received = struct {
    from: net.IpAddress,
    first_packet: quic.protection.OpenedInitialPacket,
    crypto_data: []u8,
    packet_count: usize,
    next_expected_packet_number: u64,

    pub fn deinit(self: *Received, allocator: std.mem.Allocator) void {
        self.first_packet.deinit(allocator);
        allocator.free(self.crypto_data);
        self.* = undefined;
    }
};

pub fn send(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    options: SendOptions,
) Error!Sent {
    if (options.initial.crypto_data.len == 0 or
        options.max_datagram_size == 0 or
        options.max_datagrams == 0 or
        options.initial.max_crypto_frame_data_len == 0 or
        options.initial.min_datagram_size > options.max_datagram_size)
    {
        return error.InvalidCryptoRange;
    }

    // Protect the complete flight before the first socket write. This makes
    // allocation/protection failure transactional and lets Endpoint submit
    // the packet slice through its portable batch/sendmmsg path.
    var packets: std.ArrayList([]u8) = .empty;
    defer {
        for (packets.items) |packet| endpoint.allocator.free(packet);
        packets.deinit(endpoint.allocator);
    }

    var sent: usize = 0;
    var packet_number = options.initial.packet_number;
    while (sent < options.initial.crypto_data.len) {
        if (packets.items.len == options.max_datagrams) {
            return error.CryptoBufferTooLarge;
        }
        if (packet_number > quic.protection.max_packet_number) {
            return error.InvalidPacketNumber;
        }
        const chunk_len = try largestChunk(
            endpoint.allocator,
            keys,
            options,
            sent,
            packet_number,
        );
        if (chunk_len == 0) return error.DatagramTooLarge;

        var packet_options = options.initial;
        packet_options.packet_number = packet_number;
        packet_options.crypto_offset =
            std.math.add(u64, options.initial.crypto_offset, sent) catch
                return error.InvalidCryptoRange;
        packet_options.crypto_data =
            options.initial.crypto_data[sent .. sent + chunk_len];
        packet_options.max_crypto_frame_data_len = chunk_len;
        const packet = try sealPacket(
            endpoint.allocator,
            keys,
            packet_options,
        );
        errdefer endpoint.allocator.free(packet);
        std.debug.assert(packet.len <= options.max_datagram_size);
        try packets.append(endpoint.allocator, packet);

        sent += chunk_len;
        if (sent < options.initial.crypto_data.len) packet_number += 1;
    }

    try endpoint.sendManyBytes(to, packets.items);
    return .{
        .packet_count = packets.items.len,
        .last_packet_number = packet_number,
    };
}

fn largestChunk(
    allocator: std.mem.Allocator,
    keys: quic.protection.PacketProtectionKeys,
    options: SendOptions,
    sent: usize,
    packet_number: u64,
) Error!usize {
    const remaining = options.initial.crypto_data.len - sent;
    var low: usize = 0;
    var high: usize = @min(
        remaining,
        options.initial.max_crypto_frame_data_len,
    );
    while (low < high) {
        const candidate = low + (high - low + 1) / 2;
        var packet_options = options.initial;
        packet_options.packet_number = packet_number;
        packet_options.crypto_offset =
            std.math.add(u64, options.initial.crypto_offset, sent) catch
                return error.InvalidCryptoRange;
        packet_options.crypto_data =
            options.initial.crypto_data[sent .. sent + candidate];
        packet_options.max_crypto_frame_data_len = candidate;
        const packet = try sealPacket(allocator, keys, packet_options);
        defer allocator.free(packet);
        if (packet.len <= options.max_datagram_size) {
            low = candidate;
        } else {
            high = candidate - 1;
        }
    }
    return low;
}

pub fn receive(
    endpoint: *quic.runtime.Endpoint,
    keys: quic.protection.PacketProtectionKeys,
    options: ReceiveOptions,
) Error!Received {
    var first = try endpoint.receiveBytes();
    defer first.deinit(endpoint.allocator);
    if (first.bytes.len < options.min_datagram_size) {
        return error.InvalidInitialPacket;
    }
    return open(
        endpoint,
        first.from,
        first.bytes,
        keys,
        options,
    );
}

/// Open a caller-provided first datagram, then receive additional Initial
/// datagrams from the endpoint until the CRYPTO flight is complete.
pub fn open(
    endpoint: *quic.runtime.Endpoint,
    first_from: net.IpAddress,
    first_bytes: []const u8,
    keys: quic.protection.PacketProtectionKeys,
    options: ReceiveOptions,
) Error!Received {
    if (options.max_crypto_buffer == 0 or options.max_datagrams == 0) {
        return error.InvalidCryptoRange;
    }
    if (options.expected_crypto_len) |expected| {
        if (expected == 0 or expected > options.max_crypto_buffer) {
            return error.CryptoBufferTooLarge;
        }
    }

    var reassembler = quic.crypto_stream.Reassembler.init(
        endpoint.allocator,
        options.max_crypto_buffer,
    );
    defer reassembler.deinit();
    var first_packet: ?quic.protection.OpenedInitialPacket = null;
    errdefer if (first_packet) |*packet| {
        packet.deinit(endpoint.allocator);
    };
    var peer: ?net.IpAddress = null;
    var next_expected = options.expected_packet_number;
    var packet_count: usize = 0;
    var target_len = options.expected_crypto_len;

    while (packet_count < options.max_datagrams) {
        var received: ?quic.runtime.OwnedBytes = null;
        defer if (received) |*datagram| {
            datagram.deinit(endpoint.allocator);
        };
        const datagram_from, const datagram_bytes = if (packet_count == 0)
            .{ first_from, first_bytes }
        else blk: {
            received = try endpoint.receiveBytes();
            break :blk .{ received.?.from, received.?.bytes };
        };

        // The caller-provided first packet can be the Initial prefix of a
        // coalesced datagram already validated at the UDP boundary.
        if (packet_count != 0 and
            datagram_bytes.len < options.min_datagram_size)
        {
            return error.InvalidInitialPacket;
        }
        if (peer) |expected_peer| {
            if (!datagram_from.eql(&expected_peer)) {
                return error.InvalidInitialPacket;
            }
        } else {
            peer = datagram_from;
        }

        const info = try quic.protection.peekProtectedLongPacketInfoWithFixedBitPolicy(
            datagram_bytes,
            options.allow_zero_fixed_bit,
        );
        if (info.packet_type != .initial or info.len != datagram_bytes.len) {
            return error.InvalidInitialPacket;
        }
        var packet = try quic.protection.openInitialPacketWithFixedBitPolicy(
            endpoint.allocator,
            keys,
            datagram_bytes,
            next_expected,
            options.allow_zero_fixed_bit,
        );
        var packet_owned = true;
        errdefer if (packet_owned) packet.deinit(endpoint.allocator);
        if (first_packet) |first| {
            if (packet.version != first.version or
                !std.mem.eql(
                    u8,
                    packet.destination_connection_id,
                    first.destination_connection_id,
                ) or
                !std.mem.eql(
                    u8,
                    packet.source_connection_id,
                    first.source_connection_id,
                ))
            {
                return error.InvalidInitialPacket;
            }
        }
        const after_packet = std.math.add(
            u64,
            packet.packet_number,
            1,
        ) catch return error.InvalidPacketNumber;
        next_expected = @max(next_expected, after_packet);
        try insertCryptoPayload(
            endpoint.allocator,
            &reassembler,
            packet.payload,
            .initial,
        );
        packet_count += 1;
        if (first_packet == null) {
            first_packet = packet;
            packet_owned = false;
        } else {
            packet.deinit(endpoint.allocator);
            packet_owned = false;
        }

        if (target_len == null and reassembler.available().len >= 4) {
            target_len = try tlsHandshakeMessageLen(
                reassembler.available()[0..4],
                options.max_crypto_buffer,
            );
        }
        if (target_len) |expected| {
            if (reassembler.available().len >= expected) {
                if (reassembler.available().len != expected) {
                    return error.InvalidCryptoRange;
                }
                return .{
                    .from = peer.?,
                    .first_packet = first_packet.?,
                    .crypto_data = try reassembler.readAllAvailable(
                        endpoint.allocator,
                    ),
                    .packet_count = packet_count,
                    .next_expected_packet_number = next_expected,
                };
            }
        }
    }
    return error.MissingCryptoFrame;
}

fn tlsHandshakeMessageLen(
    prefix: *const [4]u8,
    max_crypto_buffer: usize,
) Error!usize {
    const body_len =
        (@as(usize, prefix[1]) << 16) |
        (@as(usize, prefix[2]) << 8) |
        prefix[3];
    const total = std.math.add(usize, 4, body_len) catch
        return error.InvalidCryptoRange;
    if (total > max_crypto_buffer) return error.CryptoBufferTooLarge;
    return total;
}

pub fn sealPacket(
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
        const packet = try quic.protection.sealInitialPacket(
            allocator,
            keys,
            .{
                .version = options.version,
                .destination_connection_id = options.destination_connection_id,
                .source_connection_id = options.source_connection_id,
                .token = options.token,
                .packet_number = options.packet_number,
                .packet_number_len = options.packet_number_len,
                .fixed_bit = options.fixed_bit,
                .payload = payload.items,
            },
        );
        if (packet.len >= options.min_datagram_size) return packet;
        const missing = options.min_datagram_size - packet.len;
        allocator.free(packet);
        try payload.appendNTimes(
            allocator,
            @intFromEnum(quic.FrameType.padding),
            missing,
        );
    }
}

pub fn insertCryptoPayload(
    allocator: std.mem.Allocator,
    reassembler: *quic.crypto_stream.Reassembler,
    payload: []const u8,
    packet_type: quic.FramePacketType,
) Error!void {
    var pos: usize = 0;
    var saw_crypto = false;
    while (pos < payload.len) {
        var parsed = try quic.parseFrameOwned(
            allocator,
            payload[pos..],
        );
        defer parsed.deinitOwned(allocator);
        try quic.validateFrameForPacketType(parsed.frame, packet_type);
        if (parsed.frame == .crypto) {
            saw_crypto = true;
            try reassembler.insert(parsed.frame.crypto);
        }
        pos += parsed.consumed;
    }
    if (!saw_crypto) return error.MissingCryptoFrame;
}

test {
    _ = @import("flight_tests.zig");
}
