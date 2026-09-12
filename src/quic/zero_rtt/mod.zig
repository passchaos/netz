//! QUIC 0-RTT packet transport and resumption-lease adapter.
//!
//! This module owns long-header early-data send/open/receive behavior. It is
//! intentionally separate from the much larger established 1-RTT connection
//! state machine.

const std = @import("std");
const quic = @import("../mod.zig");

const net = std.Io.net;

pub const handshake = @import("handshake.zig");
pub const replay_filter = @import("replay_filter.zig");
pub const ReplayFilter = replay_filter.Filter;

pub const Error = quic.runtime.Error || quic.protection.Error || quic.Error || error{
    MissingFrame,
};

pub const SendOptions = struct {
    version: u32 = quic.Version.version_1.wireValue(),
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    packet_number: u64,
    packet_number_len: u8 = 4,
    fixed_bit: bool = true,
    frames: []const quic.Frame,
};

pub const Packet = struct {
    from: net.IpAddress,
    packet: quic.protection.OpenedZeroRttPacket,
    frames: []quic.Frame,

    pub fn deinit(self: *Packet, allocator: std.mem.Allocator) void {
        quic.deinitOwnedFrameSlice(self.frames, allocator);
        allocator.free(self.frames);
        self.packet.deinit(allocator);
        self.* = undefined;
    }
};

pub const PreparedSend = struct {
    storage: []u8,
    packet: []u8,

    pub fn deinit(self: *PreparedSend, allocator: std.mem.Allocator) void {
        allocator.free(self.storage);
        self.* = undefined;
    }
};

pub const SendProgress = struct {
    sent_count: usize,
    protected_count: usize,
    packet_len: usize,
    send_error: ?quic.runtime.Error = null,
};

pub const EarlyDataSender = struct {
    cache: *quic.resumption.Cache,
    lease: *quic.resumption.EarlyDataLease,
    packet_number: u64 = 0,
    offered: bool = false,

    pub fn send(
        self: *EarlyDataSender,
        endpoint: *quic.runtime.Endpoint,
        to: net.IpAddress,
        keys: quic.protection.PacketProtectionKeys,
        options: struct {
            version: u32 = quic.Version.version_1.wireValue(),
            destination_connection_id: []const u8,
            source_connection_id: []const u8,
            packet_number_len: u8 = 4,
            fixed_bit: bool = true,
            frames: []const quic.Frame,
        },
    ) Error!void {
        if (!self.offered) {
            if (!self.cache.ownsActiveLease(self.lease.*)) {
                return error.InvalidPacket;
            }
        } else if (self.lease.state != .consumed) {
            return error.InvalidPacket;
        }
        if (!self.lease.session.permitsEarlyData()) return error.InvalidPacket;
        if (self.packet_number > quic.protection.max_packet_number) {
            return error.InvalidPacketNumber;
        }
        const packet_number = self.packet_number;
        const progress = try sendFramesProgress(endpoint, to, keys, .{
            .version = options.version,
            .destination_connection_id = options.destination_connection_id,
            .source_connection_id = options.source_connection_id,
            .packet_number = packet_number,
            .packet_number_len = options.packet_number_len,
            .fixed_bit = options.fixed_bit,
            .frames = options.frames,
        });
        std.debug.assert(progress.protected_count == 1);
        // The first protected packet makes this ticket unavailable to every
        // future 0-RTT attempt, regardless of socket or handshake acceptance.
        if (!self.offered) {
            self.cache.consumeEarlyData(self.lease) catch unreachable;
            self.offered = true;
        }
        self.packet_number = packet_number + 1;
        if (progress.send_error) |err| return err;
    }
};

pub fn sendFrames(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    options: SendOptions,
) Error!void {
    const progress = try sendFramesProgress(
        endpoint,
        to,
        keys,
        options,
    );
    if (progress.send_error) |err| return err;
    std.debug.assert(progress.sent_count == 1);
}

pub fn prepareFrames(
    endpoint: *quic.runtime.Endpoint,
    keys: quic.protection.PacketProtectionKeys,
    options: SendOptions,
) Error!PreparedSend {
    var payload_len: usize = 0;
    for (options.frames) |frame| {
        try quic.validateFrameForPacketType(frame, .zero_rtt);
        payload_len = std.math.add(
            usize,
            payload_len,
            try frame.wireLen(),
        ) catch return error.InvalidFrameLength;
    }
    if (options.frames.len == 0) return error.MissingFrame;
    const packet_len = try quic.protection.protectedLongPacketCapacity(
        options.destination_connection_id.len,
        options.source_connection_id.len,
        0,
        false,
        options.packet_number_len,
        payload_len,
    );
    if (packet_len > endpoint.limits.max_datagram_size) {
        return error.DatagramTooLarge;
    }
    const storage_len = std.math.add(
        usize,
        payload_len,
        packet_len,
    ) catch return error.InvalidFrameLength;
    const storage = try endpoint.allocator.alloc(u8, storage_len);
    errdefer endpoint.allocator.free(storage);
    var payload = std.ArrayList(u8).initBuffer(storage[0..payload_len]);
    var no_extra_storage: [0]u8 = .{};
    var no_extra_allocations = std.heap.FixedBufferAllocator.init(
        &no_extra_storage,
    );
    for (options.frames) |frame| {
        try frame.write(&payload, no_extra_allocations.allocator());
    }
    const packet = try quic.protection.sealZeroRttPacketInto(
        storage[payload_len..],
        keys,
        .{
            .version = options.version,
            .destination_connection_id = options.destination_connection_id,
            .source_connection_id = options.source_connection_id,
            .packet_number = options.packet_number,
            .packet_number_len = options.packet_number_len,
            .fixed_bit = options.fixed_bit,
            .payload = payload.items,
        },
    );
    std.debug.assert(packet.len == packet_len);
    return .{ .storage = storage, .packet = storage[payload_len..] };
}

pub fn sendPreparedFramesProgress(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    prepared: PreparedSend,
) SendProgress {
    const send_result = endpoint.sendManyBytesProgress(
        to,
        &.{prepared.packet},
    ) catch |err| {
        return .{
            .sent_count = 0,
            .protected_count = 1,
            .packet_len = prepared.packet.len,
            .send_error = err,
        };
    };
    return .{
        .sent_count = send_result.sent_count,
        .protected_count = 1,
        .packet_len = prepared.packet.len,
        .send_error = send_result.send_error,
    };
}

/// Protect and submit one 0-RTT packet while preserving the distinction
/// between packet-number consumption and socket progress.
pub fn sendFramesProgress(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    options: SendOptions,
) Error!SendProgress {
    var prepared = try prepareFrames(endpoint, keys, options);
    defer prepared.deinit(endpoint.allocator);
    return sendPreparedFramesProgress(endpoint, to, prepared);
}

pub fn receive(
    endpoint: *quic.runtime.Endpoint,
    keys: quic.protection.PacketProtectionKeys,
    expected_packet_number: u64,
    max_frames: usize,
) Error!Packet {
    var datagram = try endpoint.receiveBytes();
    defer datagram.deinit(endpoint.allocator);
    return openBytes(
        endpoint,
        datagram.from,
        datagram.bytes,
        keys,
        expected_packet_number,
        max_frames,
    );
}

pub fn openBytes(
    endpoint: *quic.runtime.Endpoint,
    from: net.IpAddress,
    bytes: []const u8,
    keys: quic.protection.PacketProtectionKeys,
    expected_packet_number: u64,
    max_frames: usize,
) Error!Packet {
    return openBytesWithFixedBitPolicy(
        endpoint,
        from,
        bytes,
        keys,
        expected_packet_number,
        max_frames,
        false,
    );
}

pub fn openBytesWithFixedBitPolicy(
    endpoint: *quic.runtime.Endpoint,
    from: net.IpAddress,
    bytes: []const u8,
    keys: quic.protection.PacketProtectionKeys,
    expected_packet_number: u64,
    max_frames: usize,
    allow_zero_fixed_bit: bool,
) Error!Packet {
    const packet = try quic.protection.openZeroRttPacketWithFixedBitPolicy(
        endpoint.allocator,
        keys,
        bytes,
        expected_packet_number,
        allow_zero_fixed_bit,
    );
    return fromOpenedPacket(endpoint, from, packet, max_frames);
}

/// Parse authenticated 0-RTT payload bytes without re-opening packet
/// protection. Handshake receive owners use this to keep pre-authentication
/// packet discard policy separate from authenticated frame validation.
pub fn fromOpenedPacket(
    endpoint: *quic.runtime.Endpoint,
    from: net.IpAddress,
    opened_packet: quic.protection.OpenedZeroRttPacket,
    max_frames: usize,
) Error!Packet {
    var packet = opened_packet;
    errdefer packet.deinit(endpoint.allocator);
    const frames = try parseFrames(
        endpoint.allocator,
        packet.payload,
        max_frames,
    );
    return .{
        .from = from,
        .packet = packet,
        .frames = frames,
    };
}

pub fn encodeFrames(
    allocator: std.mem.Allocator,
    frames: []const quic.Frame,
) Error![]u8 {
    var payload_len: usize = 0;
    for (frames) |frame| {
        payload_len = std.math.add(
            usize,
            payload_len,
            try frame.wireLen(),
        ) catch return error.InvalidFrameLength;
    }
    var payload: std.ArrayList(u8) = .empty;
    errdefer payload.deinit(allocator);
    try payload.ensureTotalCapacity(allocator, payload_len);
    for (frames) |frame| try frame.write(&payload, allocator);
    return payload.toOwnedSlice(allocator);
}

fn parseFrames(
    allocator: std.mem.Allocator,
    payload: []const u8,
    max_frames: usize,
) Error![]quic.Frame {
    var frames: std.ArrayList(quic.Frame) = .empty;
    errdefer {
        quic.deinitOwnedFrameSlice(frames.items, allocator);
        frames.deinit(allocator);
    }

    var pos: usize = 0;
    while (pos < payload.len) {
        if (frames.items.len >= max_frames) return error.MissingFrame;
        var parsed = try quic.parseFrameOwned(allocator, payload[pos..]);
        var appended = false;
        defer if (!appended) parsed.deinitOwned(allocator);
        try quic.validateFrameForPacketType(parsed.frame, .zero_rtt);
        try frames.append(allocator, parsed.frame);
        appended = true;
        pos += parsed.consumed;
    }
    if (frames.items.len == 0) return error.MissingFrame;
    return frames.toOwnedSlice(allocator);
}

test {
    _ = @import("tests.zig");
    _ = @import("handshake_tests.zig");
}
