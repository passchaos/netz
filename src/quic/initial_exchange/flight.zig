//! MTU-bounded QUIC Initial CRYPTO flight packetization and reassembly.
//!
//! Each flight datagram contains one complete protected Initial packet. This
//! avoids IP fragmentation for large TLS messages while preserving CRYPTO
//! stream offsets across packet boundaries.

const std = @import("std");
const quic = @import("../mod.zig");
const wire = @import("../../internal/wire.zig");

const net = std.Io.net;

pub const Error = quic.runtime.Error ||
    quic.protection.Error ||
    quic.crypto_stream.Error ||
    quic.Error ||
    error{MissingCryptoFrame};
pub const ReceiveError = Error || error{
    HandshakeTimeout,
    DiscardedInitialPacket,
};

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

/// Protection and socket progress for one Initial CRYPTO flight. Every packet
/// in `protected_count` has consumed its packet number, including an unsent
/// suffix after a partial batch syscall.
pub const SendProgress = struct {
    sent_count: usize,
    protected_count: usize,
    sent_bytes: usize,
    protected_bytes: usize,
    last_packet_number: u64,
    send_error: ?quic.runtime.Error = null,
};

const PacketPlan = struct {
    crypto_start: usize,
    crypto_len: usize,
    packet_number: u64,
    crypto_offset: u64,
    payload_len: usize,
    packet_len: usize,
};

const PacketLayout = struct {
    payload_len: usize,
    packet_len: usize,
};

const stack_packet_capacity: usize = 64;

pub const ReceiveOptions = struct {
    expected_packet_number: u64,
    max_crypto_buffer: usize,
    /// Exact bytes required before returning. When null, the first contiguous
    /// TLS handshake header supplies the target length.
    expected_crypto_len: ?usize = null,
    /// Minimum length for each standalone received datagram.
    min_datagram_size: usize = 0,
    /// The caller passed only the first QUIC packet from a UDP datagram whose
    /// complete length already satisfied `min_datagram_size`. This is needed
    /// for peers that pad an Initial datagram with trailing bytes outside the
    /// first packet's Length field. Continuation datagrams remain subject to
    /// the normal minimum-size check.
    first_datagram_size_validated: bool = false,
    max_datagrams: usize = 64,
    allow_zero_fixed_bit: bool = false,
    /// Convert an unauthenticated or invalid first candidate into a stable
    /// discard signal. Handshake receive owners use this to continue without
    /// accidentally swallowing errors from authenticated CRYPTO frames.
    discard_invalid_first: bool = false,
    /// Optional absolute bound shared with the enclosing handshake. This is
    /// needed when one TLS CRYPTO message spans several Initial datagrams: the
    /// caller's budget must cover the continuation packets as well as the
    /// first UDP receive.
    deadline: ?std.Io.Clock.Timestamp = null,
};

pub const Received = struct {
    from: net.IpAddress,
    first_packet: quic.protection.OpenedInitialPacket,
    crypto_data: []u8,
    packet_count: usize,
    /// Full UDP payload bytes consumed from this path while assembling the
    /// Initial CRYPTO flight, including datagrams later discarded.
    bytes_received: usize,
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
    const progress = try sendProgress(endpoint, to, keys, options);
    if (progress.send_error) |err| return err;
    std.debug.assert(progress.sent_count == progress.protected_count);
    return .{
        .packet_count = progress.protected_count,
        .last_packet_number = progress.last_packet_number,
    };
}

/// Protect and submit a complete Initial CRYPTO flight while preserving a
/// socket-accepted prefix. Validation and protection finish before the first
/// send, so errors in the error union imply zero socket progress.
pub fn sendProgress(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    options: SendOptions,
) Error!SendProgress {
    if (options.initial.crypto_data.len == 0 or
        options.max_datagram_size == 0 or
        options.max_datagrams == 0 or
        options.initial.max_crypto_frame_data_len == 0 or
        options.initial.min_datagram_size > options.max_datagram_size)
    {
        return error.InvalidCryptoRange;
    }
    try validateSealOptions(keys, options.initial);

    // Finish packetization, packet-number validation, and every allocation
    // before protecting the first packet. Once AEAD protection starts, no
    // fallible allocator operation may strand a consumed nonce behind an
    // ordinary error that a caller could retry with the same options.
    var plan_stack: [stack_packet_capacity]PacketPlan = undefined;
    var plan_heap: std.ArrayList(PacketPlan) = .empty;
    defer plan_heap.deinit(endpoint.allocator);
    const plans_use_stack = options.max_datagrams <= plan_stack.len;
    var plan_count: usize = 0;
    var sent: usize = 0;
    var packet_number = options.initial.packet_number;
    var storage_len: usize = 0;
    var protected_bytes: usize = 0;
    while (sent < options.initial.crypto_data.len) {
        if (plan_count == options.max_datagrams) {
            return error.CryptoBufferTooLarge;
        }
        if (packet_number > quic.protection.max_packet_number) {
            return error.InvalidPacketNumber;
        }
        const chunk_len = try largestChunk(
            options,
            sent,
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
        const layout = try packetLayout(packet_options);
        if (layout.packet_len > options.max_datagram_size) {
            return error.DatagramTooLarge;
        }
        if (layout.packet_len > endpoint.limits.max_datagram_size) {
            return error.DatagramTooLarge;
        }
        storage_len = std.math.add(
            usize,
            storage_len,
            std.math.add(
                usize,
                layout.payload_len,
                layout.packet_len,
            ) catch return error.InvalidFrameLength,
        ) catch return error.InvalidFrameLength;
        protected_bytes = std.math.add(
            usize,
            protected_bytes,
            layout.packet_len,
        ) catch return error.InvalidFrameLength;
        const plan = PacketPlan{
            .crypto_start = sent,
            .crypto_len = chunk_len,
            .packet_number = packet_number,
            .crypto_offset = packet_options.crypto_offset,
            .payload_len = layout.payload_len,
            .packet_len = layout.packet_len,
        };
        if (plans_use_stack) {
            plan_stack[plan_count] = plan;
        } else {
            try plan_heap.append(endpoint.allocator, plan);
        }
        plan_count += 1;

        sent += chunk_len;
        if (sent < options.initial.crypto_data.len) packet_number += 1;
    }

    const plans: []const PacketPlan = if (plans_use_stack)
        plan_stack[0..plan_count]
    else
        plan_heap.items;
    const storage = try endpoint.allocator.alloc(u8, storage_len);
    defer endpoint.allocator.free(storage);
    var packet_stack: [stack_packet_capacity][]const u8 = undefined;
    const packet_heap: ?[][]const u8 = if (plans.len > packet_stack.len)
        try endpoint.allocator.alloc([]const u8, plans.len)
    else
        null;
    defer if (packet_heap) |packets| endpoint.allocator.free(packets);
    const packets: [][]const u8 = packet_heap orelse
        packet_stack[0..plans.len];

    var storage_offset: usize = 0;
    for (plans, 0..) |plan, index| {
        const item_storage_len = std.math.add(
            usize,
            plan.payload_len,
            plan.packet_len,
        ) catch return error.InvalidFrameLength;
        const item_storage =
            storage[storage_offset..][0..item_storage_len];
        var packet_options = options.initial;
        packet_options.packet_number = plan.packet_number;
        packet_options.crypto_offset = plan.crypto_offset;
        packet_options.crypto_data = options.initial.crypto_data[plan.crypto_start..][0..plan.crypto_len];
        packet_options.max_crypto_frame_data_len = plan.crypto_len;
        packets[index] = try sealPacketInto(
            item_storage,
            keys,
            packet_options,
            .{
                .payload_len = plan.payload_len,
                .packet_len = plan.packet_len,
            },
        );
        storage_offset += item_storage_len;
    }
    std.debug.assert(storage_offset == storage.len);

    const send_result = endpoint.sendManyBytesProgress(to, packets) catch |err| {
        return .{
            .sent_count = 0,
            .protected_count = packets.len,
            .sent_bytes = 0,
            .protected_bytes = protected_bytes,
            .last_packet_number = packet_number,
            .send_error = err,
        };
    };
    var sent_bytes: usize = 0;
    for (packets[0..send_result.sent_count]) |packet| {
        sent_bytes += packet.len;
    }
    return .{
        .sent_count = send_result.sent_count,
        .protected_count = packets.len,
        .sent_bytes = sent_bytes,
        .protected_bytes = protected_bytes,
        .last_packet_number = packet_number,
        .send_error = send_result.send_error,
    };
}

/// Return the exact total wire bytes emitted by `send` without allocating or
/// protecting packets. Handshake anti-amplification uses this to reserve a
/// complete flight before any datagram becomes visible on the socket.
pub fn wireLen(options: SendOptions) Error!usize {
    if (options.initial.crypto_data.len == 0 or
        options.max_datagram_size == 0 or
        options.max_datagrams == 0 or
        options.initial.max_crypto_frame_data_len == 0 or
        options.initial.min_datagram_size > options.max_datagram_size)
    {
        return error.InvalidCryptoRange;
    }

    var total: usize = 0;
    var sent: usize = 0;
    var packet_number = options.initial.packet_number;
    var packet_count: usize = 0;
    while (sent < options.initial.crypto_data.len) {
        if (packet_count == options.max_datagrams) {
            return error.CryptoBufferTooLarge;
        }
        if (packet_number > quic.protection.max_packet_number) {
            return error.InvalidPacketNumber;
        }
        const chunk_len = try largestChunk(options, sent);
        if (chunk_len == 0) return error.DatagramTooLarge;
        var packet_options = options.initial;
        packet_options.packet_number = packet_number;
        packet_options.crypto_offset = std.math.add(
            u64,
            options.initial.crypto_offset,
            sent,
        ) catch return error.InvalidCryptoRange;
        var payload_len = try cryptoFrameWireLen(
            packet_options.crypto_offset,
            chunk_len,
        );
        var packet_len = try protectedInitialPacketWireLen(
            packet_options,
            payload_len,
        );
        while (packet_len < packet_options.min_datagram_size) {
            payload_len = std.math.add(
                usize,
                payload_len,
                packet_options.min_datagram_size - packet_len,
            ) catch return error.InvalidFrameLength;
            packet_len = try protectedInitialPacketWireLen(
                packet_options,
                payload_len,
            );
        }
        if (packet_len > options.max_datagram_size) {
            return error.DatagramTooLarge;
        }
        total = std.math.add(usize, total, packet_len) catch
            return error.InvalidFrameLength;
        sent += chunk_len;
        packet_count += 1;
        if (sent < options.initial.crypto_data.len) packet_number += 1;
    }
    return total;
}

pub fn largestChunk(
    options: SendOptions,
    sent: usize,
) Error!usize {
    if (sent > options.initial.crypto_data.len) {
        return error.InvalidCryptoRange;
    }
    const remaining = options.initial.crypto_data.len - sent;
    const upper_bound = @min(
        remaining,
        options.initial.max_crypto_frame_data_len,
    );
    const frame_offset = std.math.add(
        u64,
        options.initial.crypto_offset,
        sent,
    ) catch return error.InvalidCryptoRange;

    // The protected packet length is deterministic from header fields and the
    // CRYPTO frame's varint widths. Compute the largest fitting payload from
    // wire lengths instead of repeatedly allocating, encrypting and freeing
    // candidate packets in a binary search. The final packet is still sealed
    // normally, so this only removes speculative work.
    var low: usize = 0;
    var high = upper_bound;
    while (low < high) {
        const candidate = low + (high - low + 1) / 2;
        const packet_len = try initialPacketWireLen(
            options.initial,
            frame_offset,
            candidate,
        );
        if (packet_len <= options.max_datagram_size) {
            low = candidate;
        } else {
            high = candidate - 1;
        }
    }
    return low;
}

fn initialPacketWireLen(
    options: SendInitialOptions,
    frame_offset: u64,
    data_len: usize,
) Error!usize {
    const frame_len = try cryptoFrameWireLen(frame_offset, data_len);
    return protectedInitialPacketWireLen(options, frame_len);
}

fn protectedInitialPacketWireLen(
    options: SendInitialOptions,
    frame_len: usize,
) Error!usize {
    return quic.protection.protectedLongPacketCapacity(
        options.destination_connection_id.len,
        options.source_connection_id.len,
        options.token.len,
        true,
        options.packet_number_len,
        frame_len,
    );
}

fn cryptoFrameWireLen(offset: u64, data_len: usize) Error!usize {
    const data_len_u64 = std.math.cast(u64, data_len) orelse
        return error.InvalidCryptoRange;
    const end = std.math.add(u64, offset, data_len_u64) catch
        return error.InvalidCryptoRange;
    if (end > quic.varint.max_value) return error.InvalidCryptoRange;
    var len: usize = 1;
    len = std.math.add(usize, len, try quic.varint.length(offset)) catch
        return error.InvalidFrameLength;
    len = std.math.add(usize, len, try quic.varint.length(data_len)) catch
        return error.InvalidFrameLength;
    return std.math.add(usize, len, data_len) catch
        return error.InvalidFrameLength;
}

pub fn receive(
    endpoint: *quic.runtime.Endpoint,
    keys: quic.protection.PacketProtectionKeys,
    options: ReceiveOptions,
) ReceiveError!Received {
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
) ReceiveError!Received {
    return openFrom(
        endpoint,
        quic.runtime.DatagramSource.fromEndpoint(endpoint),
        first_from,
        first_bytes,
        keys,
        options,
    );
}

pub fn openFrom(
    endpoint: *quic.runtime.Endpoint,
    source: quic.runtime.DatagramSource,
    first_from: net.IpAddress,
    first_bytes: []const u8,
    keys: quic.protection.PacketProtectionKeys,
    options: ReceiveOptions,
) ReceiveError!Received {
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
    var datagram_count: usize = 0;
    var bytes_received: usize = 0;
    var target_len = options.expected_crypto_len;
    var use_first_datagram = true;

    while (datagram_count < options.max_datagrams) {
        var received: ?quic.runtime.OwnedBytes = null;
        defer if (received) |*datagram| {
            datagram.deinit(endpoint.allocator);
        };
        const is_first_datagram = use_first_datagram;
        const datagram_from, const datagram_bytes = if (use_first_datagram) blk: {
            use_first_datagram = false;
            break :blk .{ first_from, first_bytes };
        } else blk: {
            received = source.receiveTimeout(if (options.deadline) |deadline|
                .{ .deadline = deadline }
            else
                .none) catch |err| switch (err) {
                error.Timeout => return error.HandshakeTimeout,
                error.ConcurrencyUnavailable => return error.Unexpected,
                else => |other| return @errorCast(other),
            };
            break :blk .{ received.?.from, received.?.bytes };
        };
        datagram_count += 1;

        if (peer) |expected_peer| {
            if (!datagram_from.eql(&expected_peer)) {
                continue;
            }
        }
        bytes_received = std.math.add(
            usize,
            bytes_received,
            datagram_bytes.len,
        ) catch std.math.maxInt(usize);

        // The caller-provided first packet can be the Initial prefix of a
        // coalesced datagram already validated at the UDP boundary.
        if (!is_first_datagram and
            datagram_bytes.len < options.min_datagram_size)
        {
            continue;
        }
        if (is_first_datagram and
            !options.first_datagram_size_validated and
            datagram_bytes.len < options.min_datagram_size)
        {
            if (options.discard_invalid_first) {
                return error.DiscardedInitialPacket;
            }
            return error.InvalidInitialPacket;
        }
        const info = quic.protection.peekProtectedLongPacketInfoWithFixedBitPolicy(
            datagram_bytes,
            options.allow_zero_fixed_bit,
        ) catch |err| {
            if (isDiscardableLongHeaderParseError(err)) {
                if (is_first_datagram) {
                    if (options.discard_invalid_first) {
                        return error.DiscardedInitialPacket;
                    }
                    return err;
                }
                continue;
            }
            return err;
        };
        if (info.packet_type != .initial or
            (info.len != datagram_bytes.len and
                !std.mem.allEqual(u8, datagram_bytes[info.len..], 0)))
        {
            if (is_first_datagram) {
                if (options.discard_invalid_first) {
                    return error.DiscardedInitialPacket;
                }
                return error.InvalidInitialPacket;
            }
            continue;
        }
        var packet = quic.protection.openInitialPacketWithFixedBitPolicy(
            endpoint.allocator,
            keys,
            datagram_bytes[0..info.len],
            next_expected,
            options.allow_zero_fixed_bit,
        ) catch |err| {
            if (quic.protection.isUnauthenticatedOpenError(err)) {
                if (is_first_datagram) {
                    if (options.discard_invalid_first) {
                        return error.DiscardedInitialPacket;
                    }
                    return err;
                }
                continue;
            }
            // RFC 9000 section 10.2.3 permits silently discarding an invalid
            // Initial because its public keys do not provide strong peer
            // authentication. Keep the pure one-shot API diagnostic unless a
            // handshake receive owner explicitly selects discard mode.
            if (err == error.InvalidReservedBits and
                options.discard_invalid_first)
            {
                if (is_first_datagram) return error.DiscardedInitialPacket;
                continue;
            }
            return err;
        };
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
                packet.deinit(endpoint.allocator);
                packet_owned = false;
                continue;
            }
        }
        if (peer == null) peer = datagram_from;
        const after_packet = std.math.add(
            u64,
            packet.packet_number,
            1,
        ) catch return error.InvalidPacketNumber;
        next_expected = @max(next_expected, after_packet);
        packet_count += 1;
        insertCryptoPayload(
            endpoint.allocator,
            &reassembler,
            packet.payload,
            .initial,
        ) catch |err| switch (err) {
            error.MissingCryptoFrame => {
                if (is_first_datagram and first_packet == null) {
                    if (!options.discard_invalid_first) return err;
                }
                packet.deinit(endpoint.allocator);
                packet_owned = false;
                continue;
            },
            else => |other| return other,
        };
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
                    .bytes_received = bytes_received,
                    .next_expected_packet_number = next_expected,
                };
            }
        }
    }
    return error.MissingCryptoFrame;
}

fn isDiscardableLongHeaderParseError(err: anyerror) bool {
    return switch (err) {
        error.BufferTooShort,
        error.IntegerOverflow,
        error.InvalidConnectionIdLength,
        error.InvalidEncoding,
        error.InvalidFrame,
        error.InvalidFrameLength,
        error.InvalidVersionNegotiation,
        error.MalformedVarInt,
        error.VarIntTooLarge,
        => true,
        else => false,
    };
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
    return sealPacketPrepared(
        allocator,
        keys,
        options,
        try packetLayout(options),
    );
}

fn sealPacketInto(
    storage: []u8,
    keys: quic.protection.PacketProtectionKeys,
    options: SendInitialOptions,
    layout: PacketLayout,
) Error![]u8 {
    if (storage.len < layout.payload_len + layout.packet_len) {
        return error.BufferTooShort;
    }
    const payload_storage = storage[0..layout.payload_len];
    var payload = std.ArrayList(u8).initBuffer(payload_storage);
    var no_extra_storage: [0]u8 = .{};
    var no_extra_allocations = std.heap.FixedBufferAllocator.init(
        &no_extra_storage,
    );
    try writePacketPayload(
        &payload,
        no_extra_allocations.allocator(),
        options,
        layout,
    );
    return quic.protection.sealInitialPacketInto(
        storage[layout.payload_len..],
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
}

fn sealPacketPrepared(
    allocator: std.mem.Allocator,
    keys: quic.protection.PacketProtectionKeys,
    options: SendInitialOptions,
    layout: PacketLayout,
) Error![]u8 {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try payload.ensureTotalCapacityPrecise(allocator, layout.payload_len);
    try writePacketPayload(&payload, allocator, options, layout);
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
    std.debug.assert(packet.len == layout.packet_len);
    return packet;
}

fn writePacketPayload(
    payload: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    options: SendInitialOptions,
    layout: PacketLayout,
) Error!void {
    try quic.crypto_stream.writeCryptoFrames(
        payload,
        allocator,
        options.crypto_offset,
        options.crypto_data,
        options.max_crypto_frame_data_len,
    );
    if (payload.items.len > layout.payload_len) {
        return error.InvalidFrameLength;
    }
    try quic.appendPadding(
        payload,
        allocator,
        layout.payload_len - payload.items.len,
    );
}

fn packetLayout(options: SendInitialOptions) Error!PacketLayout {
    var payload_len = try quic.crypto_stream.cryptoFramesWireLen(
        options.crypto_offset,
        options.crypto_data.len,
        options.max_crypto_frame_data_len,
    );
    var packet_len = try protectedInitialPacketWireLen(options, payload_len);
    while (packet_len < options.min_datagram_size) {
        payload_len = std.math.add(
            usize,
            payload_len,
            options.min_datagram_size - packet_len,
        ) catch return error.InvalidFrameLength;
        packet_len = try protectedInitialPacketWireLen(options, payload_len);
    }
    return .{
        .payload_len = payload_len,
        .packet_len = packet_len,
    };
}

fn validateSealOptions(
    keys: quic.protection.PacketProtectionKeys,
    options: SendInitialOptions,
) Error!void {
    if (keys.suite != .aes_128_gcm_sha256) {
        return error.InvalidCipherSuite;
    }
    if (options.version != quic.Version.version_1.wireValue() and
        options.version != quic.Version.version_2.wireValue())
    {
        return error.UnsupportedVersion;
    }
    if (options.packet_number_len == 0 or options.packet_number_len > 4) {
        return error.InvalidPacketNumberLength;
    }
    if (options.destination_connection_id.len > 20 or
        options.source_connection_id.len > 20)
    {
        return error.InvalidInitialPacket;
    }
}

pub fn insertCryptoPayload(
    allocator: std.mem.Allocator,
    reassembler: *quic.crypto_stream.Reassembler,
    payload: []const u8,
    packet_type: quic.FramePacketType,
) Error!void {
    switch (packet_type) {
        .initial, .handshake => return insertInitialHandshakeCryptoPayload(
            reassembler,
            payload,
        ),
        else => {},
    }

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

fn insertInitialHandshakeCryptoPayload(
    reassembler: *quic.crypto_stream.Reassembler,
    payload: []const u8,
) Error!void {
    var cursor = wire.Cursor.init(payload);
    var saw_crypto = false;
    while (!cursor.eof()) {
        const frame_type_len = quic.varint.encodedLen(try cursor.peekByte());
        const frame_type = try quic.varint.decode(&cursor);
        try validateFrameTypeEncoding(frame_type, frame_type_len);

        if (frame_type == @intFromEnum(quic.FrameType.padding)) {
            // Long runs of Initial datagram padding are common.  Skip the
            // entire run with one library scan instead of looping byte-wise.
            cursor.pos = std.mem.indexOfNonePos(
                u8,
                cursor.buf,
                cursor.pos,
                &.{@intFromEnum(quic.FrameType.padding)},
            ) orelse cursor.buf.len;
            continue;
        }
        if (frame_type == @intFromEnum(quic.FrameType.ping)) continue;
        if (frame_type == @intFromEnum(quic.FrameType.ack) or
            frame_type == @intFromEnum(quic.FrameType.ack_ecn))
        {
            try skipAckFrame(
                &cursor,
                frame_type == @intFromEnum(quic.FrameType.ack_ecn),
            );
            continue;
        }
        if (frame_type == @intFromEnum(quic.FrameType.crypto)) {
            const offset = try quic.varint.decode(&cursor);
            const len = try usizeFromVarint(try quic.varint.decode(&cursor));
            try validateEndOffset(offset, len);
            const data = try cursor.readSlice(len);
            saw_crypto = true;
            try reassembler.insert(.{ .offset = offset, .data = data });
            continue;
        }
        if (frame_type == @intFromEnum(quic.FrameType.connection_close)) {
            _ = try quic.varint.decode(&cursor);
            _ = try quic.varint.decode(&cursor);
            const reason_len = try usizeFromVarint(try quic.varint.decode(&cursor));
            try cursor.skip(reason_len);
            continue;
        }
        if (!quic.FrameType.known(frame_type)) return error.UnsupportedFrameType;
        return error.InvalidFrame;
    }
    if (!saw_crypto) return error.MissingCryptoFrame;
}

fn skipAckFrame(cursor: *wire.Cursor, has_ecn: bool) Error!void {
    const largest_acknowledged = try quic.varint.decode(cursor);
    _ = try quic.varint.decode(cursor); // ack_delay
    const range_count = try usizeFromVarint(try quic.varint.decode(cursor));
    const first_ack_range = try quic.varint.decode(cursor);
    try validateAckRangePayloadFits(cursor.remaining(), range_count, has_ecn);
    if (first_ack_range > largest_acknowledged) return error.InvalidAckRange;

    // Validate range arithmetic while skipping it.  This mirrors the general
    // ACK parser without allocating the `AckRange` slice that handshake CRYPTO
    // extraction never reads.
    var smallest = largest_acknowledged - first_ack_range;
    var index: usize = 0;
    while (index < range_count) : (index += 1) {
        const gap = try quic.varint.decode(cursor);
        const ack_range_length = try quic.varint.decode(cursor);
        const skipped = std.math.add(u64, gap, 2) catch
            return error.InvalidAckRange;
        if (smallest < skipped) return error.InvalidAckRange;

        const range_largest = smallest - skipped;
        if (ack_range_length > range_largest) return error.InvalidAckRange;
        smallest = range_largest - ack_range_length;
    }

    if (has_ecn) {
        _ = try quic.varint.decode(cursor);
        _ = try quic.varint.decode(cursor);
        _ = try quic.varint.decode(cursor);
    }
}

fn validateFrameTypeEncoding(frame_type: u64, encoded_len: u8) Error!void {
    const shortest = quic.varint.length(frame_type) catch
        return error.UnsupportedFrameType;
    if (encoded_len != shortest) return error.InvalidFrame;
}

fn usizeFromVarint(value: u64) Error!usize {
    return std.math.cast(usize, value) orelse error.IntegerOverflow;
}

fn validateEndOffset(offset: u64, data_len: usize) Error!void {
    const data_len_u64 = std.math.cast(u64, data_len) orelse
        return error.InvalidFrameLength;
    const end = std.math.add(u64, offset, data_len_u64) catch
        return error.InvalidFrameLength;
    if (end > quic.varint.max_value) return error.InvalidFrameLength;
}

fn validateAckRangePayloadFits(
    remaining: usize,
    range_count: usize,
    has_ecn: bool,
) Error!void {
    const min_range_bytes = std.math.mul(usize, range_count, 2) catch
        return error.InvalidFrameLength;
    const min_ecn_bytes: usize = if (has_ecn) 3 else 0;
    const min_bytes = std.math.add(usize, min_range_bytes, min_ecn_bytes) catch
        return error.InvalidFrameLength;
    if (remaining < min_bytes) return error.InvalidFrameLength;
}

test {
    _ = @import("flight_tests.zig");
}
