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
        try sendFrames(endpoint, to, keys, .{
            .version = options.version,
            .destination_connection_id = options.destination_connection_id,
            .source_connection_id = options.source_connection_id,
            .packet_number = self.packet_number,
            .packet_number_len = options.packet_number_len,
            .fixed_bit = options.fixed_bit,
            .frames = options.frames,
        });
        // The first successful socket write makes this ticket unavailable to
        // every future 0-RTT attempt, regardless of handshake acceptance.
        if (!self.offered) {
            self.cache.consumeEarlyData(self.lease) catch unreachable;
            self.offered = true;
        }
        self.packet_number += 1;
    }
};

pub fn sendFrames(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    options: SendOptions,
) Error!void {
    for (options.frames) |frame| {
        try quic.validateFrameForPacketType(frame, .zero_rtt);
    }
    const payload = try encodeFrames(endpoint.allocator, options.frames);
    defer endpoint.allocator.free(payload);
    const packet = try quic.protection.sealZeroRttPacket(
        endpoint.allocator,
        keys,
        .{
            .version = options.version,
            .destination_connection_id = options.destination_connection_id,
            .source_connection_id = options.source_connection_id,
            .packet_number = options.packet_number,
            .packet_number_len = options.packet_number_len,
            .fixed_bit = options.fixed_bit,
            .payload = payload,
        },
    );
    defer endpoint.allocator.free(packet);
    try endpoint.sendBytes(to, packet);
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
    var packet = try quic.protection.openZeroRttPacketWithFixedBitPolicy(
        endpoint.allocator,
        keys,
        bytes,
        expected_packet_number,
        allow_zero_fixed_bit,
    );
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
