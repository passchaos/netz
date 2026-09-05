const std = @import("std");
const quic = @import("../../../quic/mod.zig");
const runtime_error = @import("../error.zig");
const packetizer = @import("packetizer.zig");

const net = std.Io.net;
const Error = runtime_error.Error;

/// Reusable protection scratch for the preconfigured-key HTTP/3 runtime.
///
/// The handshake-backed runtime owns equivalent storage inside
/// `one_rtt.Connection`; the lightweight protected runtime keeps it explicitly
/// so repeated control, QPACK, and request packets reuse stable allocations.
pub const State = struct {
    allocator: std.mem.Allocator,
    unusable: bool = false,
    /// Control and QPACK STREAM descriptors borrow these bytes until packet
    /// protection finishes. Keep them separate from the wire scratch below.
    critical_stream_payload: std.ArrayList(u8) = .empty,
    critical_stream_frames: std.ArrayList(quic.Frame) = .empty,
    payload_scratch: std.ArrayList(u8) = .empty,
    packet_scratch: std.ArrayList(u8) = .empty,

    pub fn init(allocator: std.mem.Allocator) State {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *State) void {
        self.payload_scratch.deinit(self.allocator);
        self.packet_scratch.deinit(self.allocator);
        self.critical_stream_frames.deinit(self.allocator);
        self.critical_stream_payload.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn resetCriticalStreamScratch(self: *State) void {
        self.critical_stream_payload.clearRetainingCapacity();
        self.critical_stream_frames.clearRetainingCapacity();
    }

    pub fn sendFrames(
        self: *State,
        endpoint: *quic.runtime.Endpoint,
        to: net.IpAddress,
        keys: quic.protection.PacketProtectionKeys,
        destination_connection_id: []const u8,
        next_packet_number: *u64,
        frames: []const quic.Frame,
        max_frames_per_packet: usize,
    ) Error!void {
        if (self.unusable) return error.ConnectionUnusable;
        var backend = Backend{
            .send = self,
            .endpoint = endpoint,
            .to = to,
            .keys = keys,
            .destination_connection_id = destination_connection_id,
            .next_packet_number = next_packet_number,
        };
        packetizer.sendWithBackend(
            self.allocator,
            &backend,
            frames,
            max_frames_per_packet,
        ) catch |err| {
            if (backend.visible_packet_sent) self.unusable = true;
            return err;
        };
    }

    /// Protect and submit one explicit packet batch while exposing the exact
    /// socket-visible prefix. Protection consumes every staged packet number,
    /// even when the socket accepts only a prefix.
    pub fn sendPacketBatchProgress(
        self: *State,
        endpoint: *quic.runtime.Endpoint,
        to: net.IpAddress,
        keys: quic.protection.PacketProtectionKeys,
        destination_connection_id: []const u8,
        next_packet_number: *u64,
        packets: []const []const quic.Frame,
    ) Error!quic.one_rtt.BatchSendResult {
        if (self.unusable) return error.ConnectionUnusable;
        const options: quic.one_rtt.BatchSendOptions = .{
            .destination_connection_id = destination_connection_id,
            .first_packet_number = next_packet_number.*,
            .packets = packets,
        };
        const sizes = try quic.one_rtt.batchStorageSizes(options);
        try self.payload_scratch.ensureTotalCapacity(
            self.allocator,
            sizes.payload,
        );
        try self.packet_scratch.ensureTotalCapacity(
            self.allocator,
            sizes.packet,
        );
        self.payload_scratch.items.len = sizes.payload;
        defer self.payload_scratch.items.len = 0;
        self.packet_scratch.items.len = sizes.packet;
        defer self.packet_scratch.items.len = 0;

        const result = try quic.one_rtt.sendFramesBatchIntoProgress(
            endpoint,
            to,
            keys,
            options,
            self.payload_scratch.items,
            self.packet_scratch.items,
        );
        next_packet_number.* = std.math.add(
            u64,
            next_packet_number.*,
            result.protected_count,
        ) catch return error.InvalidPacketNumber;
        return result;
    }

    pub fn isUsable(self: State) bool {
        return !self.unusable;
    }
};

const Backend = struct {
    send: *State,
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    destination_connection_id: []const u8,
    next_packet_number: *u64,
    visible_packet_sent: bool = false,

    pub fn maxDatagramSize(self: Backend) usize {
        return self.endpoint.limits.max_datagram_size;
    }

    pub fn packetLenForFramesAtOffset(
        self: Backend,
        packet_offset: usize,
        frames: []const quic.Frame,
    ) quic.one_rtt.Error!usize {
        const packet_number = std.math.add(
            u64,
            self.next_packet_number.*,
            packet_offset,
        ) catch return error.InvalidPacketNumber;
        var payload_len: usize = 0;
        for (frames) |frame| {
            payload_len = std.math.add(
                usize,
                payload_len,
                try frame.wireLen(),
            ) catch return error.InvalidFrameLength;
        }
        return quic.protection.shortPacketLenForPayloadLen(
            self.destination_connection_id.len,
            packet_number,
            4,
            payload_len,
        );
    }

    pub fn sendPackets(
        self: *Backend,
        packets: []const []const quic.Frame,
    ) Error!void {
        const result = try self.send.sendPacketBatchProgress(
            self.endpoint,
            self.to,
            self.keys,
            self.destination_connection_id,
            self.next_packet_number,
            packets,
        );
        self.visible_packet_sent = self.visible_packet_sent or
            result.sent_count != 0;
        if (result.send_error) |err| {
            if (self.visible_packet_sent) self.send.unusable = true;
            return err;
        }
        if (result.sent_count != packets.len) {
            if (self.visible_packet_sent) self.send.unusable = true;
            return error.Unexpected;
        }
    }
};
