const std = @import("std");
const quic = @import("mod.zig");

const net = std.Io.net;

pub const Error = quic.runtime.Error || quic.protection.Error || quic.packet_space.Error || quic.flow_control.Error || quic.recovery.Error || quic.congestion.Error || quic.path_validation.Error || quic.connection_id.Error || quic.stream_state.Error || quic.Error || error{
    MissingFrame,
    ConnectionClosed,
    FinalSizeMismatch,
    StreamStopped,
    StreamLimitExceeded,
    StreamStateError,
    EcnDisabled,
    AntiAmplificationLimited,
    ActiveMigrationDisabled,
    DatagramsNotEnabled,
    DatagramQueueFull,
    DatagramBufferTooSmall,
    AckFrequencyDisabled,
};

pub const SendOptions = struct {
    destination_connection_id: []const u8,
    packet_number: u64,
    packet_number_len: u8 = 4,
    spin_bit: bool = false,
    key_phase: bool = false,
    frames: []const quic.Frame,
};

const PayloadSendOptions = struct {
    destination_connection_id: []const u8,
    packet_number: u64,
    packet_number_len: u8 = 4,
    spin_bit: bool = false,
    key_phase: bool = false,
    payload: []const u8,
};

const RetransmitMode = enum {
    congestion_controlled,
    pto_probe,
};

pub const ReceivedPacket = struct {
    from: net.IpAddress,
    packet: quic.protection.OpenedShortPacket,
    frames: []quic.Frame,
    peer_initiated_key_update: bool = false,

    pub fn deinit(self: *ReceivedPacket, allocator: std.mem.Allocator) void {
        quic.deinitOwnedFrameSlice(self.frames, allocator);
        allocator.free(self.frames);
        self.packet.deinit(allocator);
        self.* = undefined;
    }
};

pub const ZeroRttSendOptions = struct {
    version: u32 = quic.Version.version_1.wireValue(),
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    packet_number: u64,
    packet_number_len: u8 = 4,
    frames: []const quic.Frame,
};

pub const ReceivedZeroRttPacket = struct {
    from: net.IpAddress,
    packet: quic.protection.OpenedZeroRttPacket,
    frames: []quic.Frame,

    pub fn deinit(self: *ReceivedZeroRttPacket, allocator: std.mem.Allocator) void {
        quic.deinitOwnedFrameSlice(self.frames, allocator);
        allocator.free(self.frames);
        self.packet.deinit(allocator);
        self.* = undefined;
    }
};

pub const ConnectionConfig = struct {
    pub const EndpointRole = enum { client, server };

    peer: net.IpAddress,
    receive_keys: quic.protection.PacketProtectionKeys,
    send_keys: quic.protection.PacketProtectionKeys,
    local_connection_id: []const u8,
    peer_connection_id: []const u8,
    local_endpoint: EndpointRole = .client,
    max_ack_ranges: usize = 64,
    max_frames_per_packet: usize = 16,
    initial_send_max_data: u64 = std.math.maxInt(u62),
    initial_receive_max_data: u64 = std.math.maxInt(u62),
    receive_window: u64 = 64 * 1024,
    /// Back-compat fallback used when stream-direction-specific limits below
    /// are not supplied.  Real handshakes should prefer the specific fields so
    /// client/server and uni/bidi stream rules follow RFC 9000 Section 18.2.
    initial_send_max_stream_data: u64 = std.math.maxInt(u62),
    initial_receive_max_stream_data: u64 = std.math.maxInt(u62),
    initial_send_max_stream_data_bidi_local: ?u64 = null,
    initial_send_max_stream_data_bidi_remote: ?u64 = null,
    initial_send_max_stream_data_uni: ?u64 = null,
    initial_receive_max_stream_data_bidi_local: ?u64 = null,
    initial_receive_max_stream_data_bidi_remote: ?u64 = null,
    initial_receive_max_stream_data_uni: ?u64 = null,
    initial_send_max_streams_bidi: u64 = std.math.maxInt(u60),
    initial_send_max_streams_uni: u64 = std.math.maxInt(u60),
    initial_receive_max_streams_bidi: u64 = std.math.maxInt(u60),
    initial_receive_max_streams_uni: u64 = std.math.maxInt(u60),
    stream_receive_window: u64 = 64 * 1024,
    max_datagram_size: usize = quic.congestion.default_max_datagram_size,
    max_stored_new_tokens: usize = 4,
    enable_spin_bit: bool = false,
    active_connection_id_limit: usize = quic.default_active_connection_id_limit,
    local_max_idle_timeout_ms: u64 = 0,
    peer_max_idle_timeout_ms: u64 = 0,
    local_ack_delay_exponent: u64 = quic.default_ack_delay_exponent,
    peer_ack_delay_exponent: u64 = quic.default_ack_delay_exponent,
    peer_max_ack_delay_ms: u64 = quic.default_max_ack_delay_ms,
    enable_pmtud: bool = false,
    pmtud_max_probe_size: usize = quic.pmtu.max_ipv4_udp_payload_size,
    peer_disable_active_migration: bool = false,
    peer_preferred_address: ?quic.PreferredAddress = null,
    local_max_datagram_frame_size: ?usize = null,
    peer_max_datagram_frame_size: ?usize = null,
    max_datagram_queue_items: usize = 16,
    enable_ack_frequency: bool = false,
    local_min_ack_delay: ?u64 = null,
    peer_min_ack_delay: ?u64 = null,
};

const StreamFlowEntry = struct {
    stream_id: u64,
    flow: quic.flow_control.SendFlow,
    highest_sent_end: u64 = 0,
    stopped: ?StopSendingInfo = null,
    reset_sent: ?StreamResetInfo = null,
};

const StreamRecvFlowEntry = struct {
    stream_id: u64,
    flow: quic.flow_control.RecvFlow,
    recv_state: quic.stream_state.RecvState,
    highest_received_end: u64 = 0,
    final_size: ?u64 = null,
    reset: ?StreamResetInfo = null,
    stop_sending_sent: ?StopSendingInfo = null,

    fn deinit(self: *StreamRecvFlowEntry) void {
        self.recv_state.deinit();
        self.* = undefined;
    }
};

const RecvStreamPreflightEntry = struct {
    stream_id: u64,
    flow_limit: u64,
    recv_state: quic.stream_state.RecvState,
    highest_received_end: u64 = 0,
    final_size: ?u64 = null,

    fn deinit(self: *RecvStreamPreflightEntry) void {
        self.recv_state.deinit();
        self.* = undefined;
    }
};

pub const StreamResetInfo = struct {
    application_error_code: u64,
    final_size: u64,
};

pub const StopSendingInfo = struct {
    application_error_code: u64,
};

const ReservedStreamCredit = struct {
    stream_id: u64,
    bytes: u64,
};

pub const CloseInfo = struct {
    application: bool = false,
    error_code: u64,
    frame_type: u64 = 0,
    reason_phrase: []u8,
    state: CloseState = .closing,
    started_ms: ?u64 = null,
    expires_ms: ?u64 = null,

    pub fn deinit(self: *CloseInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.reason_phrase);
        self.* = undefined;
    }
};

pub const CloseState = enum {
    closing,
    draining,
    closed,
};

pub const LossDetectionTimerKind = enum {
    loss_time,
    pto,
};

pub const LossDetectionTimerDeadline = struct {
    kind: LossDetectionTimerKind,
    deadline_ns: u64,
};

pub const anti_amplification_multiplier: usize = 3;

pub const Connection = struct {
    endpoint: *quic.runtime.Endpoint,
    config: ConnectionConfig,
    next_packet_number: u64 = 0,
    expected_packet_number: u64 = 0,
    received: quic.packet_space.ReceivedPacketTracker,
    sent: quic.packet_space.SentPacketTracker,
    recovery: quic.recovery.Queue,
    congestion: quic.congestion.Controller,
    rtt_stats: quic.rtt.Stats,
    path_validation: quic.path_validation.State,
    peer_connection_ids: quic.connection_id.PeerPool = .{},
    local_connection_ids: quic.connection_id.LocalPool = .{},
    send_flow: quic.flow_control.SendFlow,
    recv_flow: quic.flow_control.RecvFlow,
    recv_data_total: u64 = 0,
    stream_send_flows: std.ArrayList(StreamFlowEntry) = .empty,
    stream_recv_flows: std.ArrayList(StreamRecvFlowEntry) = .empty,
    close_info: ?CloseInfo = null,
    send_key_phase: quic.protection.Aes128KeyPhaseState,
    receive_key_phase: quic.protection.Aes128KeyPhaseState,
    pending_key_update_ack_threshold: ?u64 = null,
    stored_new_tokens: std.ArrayList([]u8) = .empty,
    handshake_confirmed: bool = false,
    peer_max_streams_bidi: u64,
    peer_max_streams_uni: u64,
    recv_max_streams_bidi: u64,
    recv_max_streams_uni: u64,
    spin_bit_value: bool = false,
    last_activity_ms: ?u64 = null,
    idle_timed_out: bool = false,
    last_persistent_congestion_packet_number: ?u64 = null,
    pto_count: u8 = 0,
    peer_address_validated: bool = true,
    peer_address_bytes_received: usize = 0,
    peer_address_bytes_sent: usize = 0,
    pmtud: quic.pmtu.State = .{},
    datagram_recv_queue: std.ArrayList([]u8) = .empty,
    datagrams_sent_count: u64 = 0,
    datagrams_received_count: u64 = 0,
    datagrams_dropped_incoming_count: u64 = 0,
    ack_frequency_send_next_sequence: u64 = 0,
    ack_frequency_recv_next_sequence: u64 = 0,
    ack_eliciting_threshold: u64 = 1,
    requested_max_ack_delay: u64 = 0,
    ack_reordering_threshold: u64 = quic.packet_space.default_packet_threshold,
    immediate_ack_requested: bool = false,

    pub fn init(endpoint: *quic.runtime.Endpoint, config: ConnectionConfig) Error!Connection {
        var connection = Connection{
            .endpoint = endpoint,
            .config = config,
            .received = .init(endpoint.allocator, config.max_ack_ranges),
            .sent = .init(endpoint.allocator),
            .recovery = .init(endpoint.allocator),
            .congestion = .init(config.max_datagram_size),
            .rtt_stats = .init(std.math.mul(u64, config.peer_max_ack_delay_ms, 1_000_000) catch quic.rtt.default_max_ack_delay_ns),
            .pmtud = .init(.{ .enabled = config.enable_pmtud, .max_probe_size = config.pmtud_max_probe_size }),
            .path_validation = .init(endpoint.allocator),
            .send_flow = .init(config.initial_send_max_data),
            .recv_flow = try .init(config.initial_receive_max_data, config.receive_window),
            .send_key_phase = .init(config.send_keys, false),
            .receive_key_phase = .init(config.receive_keys, false),
            .peer_max_streams_bidi = config.initial_send_max_streams_bidi,
            .peer_max_streams_uni = config.initial_send_max_streams_uni,
            .recv_max_streams_bidi = config.initial_receive_max_streams_bidi,
            .recv_max_streams_uni = config.initial_receive_max_streams_uni,
        };
        try connection.local_connection_ids.registerInitial(config.local_connection_id, [_]u8{0} ** 16);
        try connection.peer_connection_ids.add(0, config.peer_connection_id, [_]u8{0} ** 16);
        try connection.peer_connection_ids.markInUse(0);
        return connection;
    }

    pub fn deinit(self: *Connection) void {
        self.received.deinit();
        self.sent.deinit();
        self.recovery.deinit();
        self.path_validation.deinit();
        if (self.close_info) |*close_info| close_info.deinit(self.endpoint.allocator);
        for (self.stored_new_tokens.items) |token| self.endpoint.allocator.free(token);
        self.stored_new_tokens.deinit(self.endpoint.allocator);
        self.stream_send_flows.deinit(self.endpoint.allocator);
        for (self.stream_recv_flows.items) |*entry| entry.deinit();
        self.stream_recv_flows.deinit(self.endpoint.allocator);
        for (self.datagram_recv_queue.items) |payload| self.endpoint.allocator.free(payload);
        self.datagram_recv_queue.deinit(self.endpoint.allocator);
        self.* = undefined;
    }

    pub fn send(self: *Connection, frames: []const quic.Frame) Error!void {
        try self.sendWithEcn(frames, .not_ect);
    }

    pub fn sendWithEcn(self: *Connection, frames: []const quic.Frame, ecn: quic.packet_space.EcnCodepoint) Error!void {
        try self.sendWithEcnAt(frames, ecn, null);
    }

    pub fn sendAt(self: *Connection, frames: []const quic.Frame, sent_time_ns: u64) Error!void {
        try self.sendWithEcnAt(frames, .not_ect, sent_time_ns);
    }

    pub fn sendWithEcnAt(self: *Connection, frames: []const quic.Frame, ecn: quic.packet_space.EcnCodepoint, sent_time_ns: ?u64) Error!void {
        if (self.close_info != null or self.idle_timed_out) return error.ConnectionClosed;
        if (ecn != .not_ect and self.sent.ecnDisabled()) return error.EcnDisabled;
        const stream_bytes = countStreamBytes(frames);
        for (frames) |frame| {
            if (frame != .stream) continue;
            const entry = try self.sendStreamEntry(frame.stream.stream_id);
            if (entry.stopped != null or entry.reset_sent != null) return error.StreamStopped;
        }

        var reserved_connection: u64 = 0;
        var reserved_streams: std.ArrayList(ReservedStreamCredit) = .empty;
        defer reserved_streams.deinit(self.endpoint.allocator);
        errdefer {
            for (reserved_streams.items) |reserved| {
                if (self.findSendStreamEntry(reserved.stream_id)) |entry| {
                    entry.flow.used -|= reserved.bytes;
                }
            }
            self.send_flow.used -|= reserved_connection;
        }

        if (stream_bytes > 0) {
            self.send_flow.reserve(stream_bytes) catch |err| {
                try self.sendDataBlocked();
                return err;
            };
            reserved_connection = stream_bytes;
        }
        for (frames) |frame| {
            if (frame != .stream or frame.stream.data.len == 0) continue;
            const entry = (self.findSendStreamEntry(frame.stream.stream_id) orelse unreachable);
            // Record a zero-sized reservation before mutating stream flow so an
            // allocator failure cannot leave `entry.flow.used` inflated.  Once
            // reserve succeeds, update the rollback byte count in place.
            try reserved_streams.append(self.endpoint.allocator, .{
                .stream_id = frame.stream.stream_id,
                .bytes = 0,
            });
            const reserved_index = reserved_streams.items.len - 1;
            entry.flow.reserve(frame.stream.data.len) catch |err| {
                try self.sendStreamDataBlocked(frame.stream.stream_id, entry.flow.limit);
                return err;
            };
            reserved_streams.items[reserved_index].bytes = frame.stream.data.len;
        }
        try self.sendTrackedFramesEcnAt(frames, ecn, sent_time_ns);
        self.noteSentStreams(frames);
    }

    pub fn datagramSendEnabled(self: Connection) bool {
        return self.config.peer_max_datagram_frame_size != null;
    }

    pub fn datagramReceiveEnabled(self: Connection) bool {
        return self.config.local_max_datagram_frame_size != null;
    }

    pub fn datagramsEnabled(self: Connection) bool {
        return self.datagramSendEnabled() and self.datagramReceiveEnabled();
    }

    pub fn maxDatagramPayloadSize(self: Connection) ?usize {
        const frame_limit = self.config.peer_max_datagram_frame_size orelse return null;
        return maxDatagramPayloadForFrameSize(@min(frame_limit, self.config.max_datagram_size));
    }

    pub fn sendDatagram(self: *Connection, data: []const u8) Error!void {
        const max_payload = self.maxDatagramPayloadSize() orelse return error.DatagramsNotEnabled;
        if (data.len > max_payload) return error.DatagramTooLarge;
        const frames = [_]quic.Frame{.{ .datagram = .{ .data = data, .length_present = true } }};
        try self.send(&frames);
        self.datagrams_sent_count +|= 1;
    }

    pub fn popDatagram(self: *Connection, out: []u8) Error!?[]u8 {
        if (self.datagram_recv_queue.items.len == 0) return null;
        const payload = self.datagram_recv_queue.orderedRemove(0);
        defer self.endpoint.allocator.free(payload);
        if (payload.len > out.len) return error.DatagramBufferTooSmall;
        @memcpy(out[0..payload.len], payload);
        return out[0..payload.len];
    }

    pub fn datagramReceiveQueueLen(self: Connection) usize {
        return self.datagram_recv_queue.items.len;
    }

    pub fn datagramsSent(self: Connection) u64 {
        return self.datagrams_sent_count;
    }

    pub fn datagramsReceived(self: Connection) u64 {
        return self.datagrams_received_count;
    }

    pub fn datagramsDroppedIncoming(self: Connection) u64 {
        return self.datagrams_dropped_incoming_count;
    }

    pub fn sendAckFrequency(self: *Connection, ack_eliciting_threshold: u64, request_max_ack_delay: u64, reordering_threshold: u64) Error!u64 {
        if (!self.config.enable_ack_frequency) return error.AckFrequencyDisabled;
        const sequence_number = self.ack_frequency_send_next_sequence;
        self.ack_frequency_send_next_sequence +|= 1;
        const frames = [_]quic.Frame{.{ .ack_frequency = .{
            .sequence_number = sequence_number,
            .ack_eliciting_threshold = ack_eliciting_threshold,
            .request_max_ack_delay = request_max_ack_delay,
            .reordering_threshold = reordering_threshold,
        } }};
        try self.send(&frames);
        return sequence_number;
    }

    pub fn sendImmediateAck(self: *Connection) Error!void {
        if (!self.config.enable_ack_frequency) return error.AckFrequencyDisabled;
        try self.send(&[_]quic.Frame{.{ .immediate_ack = {} }});
    }

    pub fn ackFrequencyThreshold(self: Connection) u64 {
        return self.ack_eliciting_threshold;
    }

    pub fn requestedMaxAckDelay(self: Connection) u64 {
        return self.requested_max_ack_delay;
    }

    pub fn ackReorderingThreshold(self: Connection) u64 {
        return self.ack_reordering_threshold;
    }

    pub fn immediateAckRequested(self: Connection) bool {
        return self.immediate_ack_requested;
    }

    fn sendDataBlocked(self: *Connection) Error!void {
        const frames = [_]quic.Frame{self.send_flow.dataBlockedFrame()};
        try self.sendTrackedFrames(&frames);
    }

    fn sendStreamDataBlocked(self: *Connection, stream_id: u64, limit: u64) Error!void {
        const frames = [_]quic.Frame{.{ .stream_data_blocked = .{ .stream_id = stream_id, .maximum_stream_data = limit } }};
        try self.sendTrackedFrames(&frames);
    }

    fn sendTrackedFrames(self: *Connection, frames: []const quic.Frame) Error!void {
        try self.sendTrackedFramesEcn(frames, .not_ect);
    }

    fn sendTrackedFramesEcn(self: *Connection, frames: []const quic.Frame, ecn: quic.packet_space.EcnCodepoint) Error!void {
        try self.sendTrackedFramesEcnAt(frames, ecn, null);
    }

    fn sendTrackedFramesEcnAt(self: *Connection, frames: []const quic.Frame, ecn: quic.packet_space.EcnCodepoint, sent_time_ns: ?u64) Error!void {
        const packet_number = self.next_packet_number;
        const payload = try encodeFrames(self.endpoint.allocator, frames);
        defer self.endpoint.allocator.free(payload);

        const is_ack_eliciting = ackEliciting(frames);
        var tracked_congestion = false;
        if (is_ack_eliciting) {
            try self.congestion.reserve(payload.len);
            tracked_congestion = true;
        }
        errdefer {
            if (tracked_congestion) self.congestion.discard(payload.len);
        }
        var tracked_recovery = false;
        if (is_ack_eliciting) {
            try self.recovery.trackSent(packet_number, payload);
            tracked_recovery = true;
        }
        errdefer {
            if (tracked_recovery) _ = self.recovery.forgetPacketNumber(packet_number);
        }
        try self.sent.sentAt(packet_number, is_ack_eliciting, if (is_ack_eliciting) payload.len else 0, ecn, sent_time_ns);
        errdefer _ = self.sent.forget(packet_number);
        try self.sendPayloadPacket(packet_number, payload);
        self.next_packet_number += 1;
    }

    pub fn pmtudCurrentSize(self: Connection) usize {
        return self.pmtud.currentSize();
    }

    pub fn pmtudShouldProbe(self: Connection) bool {
        return self.pmtud.shouldProbe();
    }

    pub fn sendPmtuProbeAt(self: *Connection, peer_max_udp_payload: usize, sent_time_ns: ?u64) Error!?usize {
        const probe_size = self.pmtud.probeSize(peer_max_udp_payload) orelse return null;
        if (probe_size > self.config.max_datagram_size) return error.DatagramTooLarge;

        const packet_number = self.next_packet_number;
        const packet_number_len: u8 = 4;
        const overhead = 1 + self.config.peer_connection_id.len + packet_number_len + quic.protection.aead_tag_len;
        if (probe_size <= overhead + 1) return null;
        const target_payload_len = probe_size - overhead;

        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(self.endpoint.allocator);
        try (quic.Frame{ .ping = {} }).write(&payload, self.endpoint.allocator);
        try payload.appendNTimes(self.endpoint.allocator, @intFromEnum(quic.FrameType.padding), target_payload_len - payload.items.len);

        try self.congestion.reserve(payload.items.len);
        errdefer self.congestion.discard(payload.items.len);
        try self.recovery.trackSent(packet_number, payload.items);
        errdefer _ = self.recovery.forgetPacketNumber(packet_number);
        try self.sent.sentAtWithPmtu(packet_number, true, payload.items.len, .not_ect, sent_time_ns, probe_size);
        errdefer _ = self.sent.forget(packet_number);
        try self.sendPayloadPacketWithPacketNumberLen(packet_number, payload.items, packet_number_len);
        self.next_packet_number += 1;
        self.pmtud.onProbeSent(probe_size);
        return probe_size;
    }

    pub fn peerAddressValidated(self: Connection) bool {
        return self.peer_address_validated;
    }

    pub fn setPeerAddressValidated(self: *Connection, validated: bool) void {
        self.peer_address_validated = validated;
        if (validated) {
            self.peer_address_bytes_received = 0;
            self.peer_address_bytes_sent = 0;
        }
    }

    pub fn recordPeerAddressBytesReceived(self: *Connection, bytes: usize) void {
        if (self.peer_address_validated) return;
        self.peer_address_bytes_received = std.math.add(usize, self.peer_address_bytes_received, bytes) catch std.math.maxInt(usize);
    }

    pub fn recordPeerAddressDatagramReceived(self: *Connection, now_ns: u64, bytes: usize) Error!?LossDetectionTimerDeadline {
        const was_blocked = self.antiAmplificationLimitRemaining() == 0;
        self.recordPeerAddressBytesReceived(bytes);
        if (!was_blocked) return null;
        return try self.serviceLossDetectionTimer(now_ns);
    }

    pub fn antiAmplificationLimitRemaining(self: Connection) ?usize {
        if (self.peer_address_validated) return null;
        const limit = std.math.mul(usize, self.peer_address_bytes_received, anti_amplification_multiplier) catch std.math.maxInt(usize);
        if (self.peer_address_bytes_sent >= limit) return 0;
        return limit - self.peer_address_bytes_sent;
    }

    fn reserveAntiAmplification(self: *Connection, bytes: usize) Error!void {
        const remaining = self.antiAmplificationLimitRemaining() orelse return;
        if (bytes > remaining) return error.AntiAmplificationLimited;
        self.peer_address_bytes_sent = std.math.add(usize, self.peer_address_bytes_sent, bytes) catch std.math.maxInt(usize);
    }

    fn releaseAntiAmplification(self: *Connection, bytes: usize) void {
        if (self.peer_address_validated) return;
        self.peer_address_bytes_sent -|= bytes;
    }

    fn sendPayloadPacket(self: *Connection, packet_number: u64, payload: []const u8) Error!void {
        try self.sendPayloadPacketWithPacketNumberLen(
            packet_number,
            payload,
            quic.protection.packetNumberLenForPayload(packet_number, self.sent.largestAcknowledged(), payload.len),
        );
    }

    fn sendPayloadPacketWithPacketNumberLen(self: *Connection, packet_number: u64, payload: []const u8, packet_number_len: u8) Error!void {
        try self.reserveAntiAmplification(payload.len);
        errdefer self.releaseAntiAmplification(payload.len);
        try sendPayload(self.endpoint, self.config.peer, self.send_key_phase.currentKeys(), .{
            .destination_connection_id = self.config.peer_connection_id,
            .packet_number = packet_number,
            .packet_number_len = packet_number_len,
            .spin_bit = self.nextSpinBit(),
            .key_phase = self.send_key_phase.currentKeyPhase(),
            .payload = payload,
        });
    }

    pub fn retransmitPto(self: *Connection) Error!bool {
        return self.retransmitPtoAt(null);
    }

    pub fn retransmitPtoAt(self: *Connection, now_ns: ?u64) Error!bool {
        return (try self.retransmitPtoProbesAt(now_ns, 1)) != 0;
    }

    pub fn retransmitPtoProbesAt(self: *Connection, now_ns: ?u64, max_probes: usize) Error!usize {
        if (max_probes == 0) return 0;
        const limit = @min(max_probes, self.recovery.pendingCount());
        var sent_count: usize = 0;
        while (sent_count < limit) : (sent_count += 1) {
            const candidate = self.recovery.ptoCandidateAt(sent_count) orelse break;
            try self.retransmitCandidateAt(candidate, .pto_probe, now_ns);
        }
        if (sent_count != 0) self.incrementPtoCount();
        return sent_count;
    }

    pub fn retransmitPacketThresholdLoss(self: *Connection) Error!bool {
        const largest = self.sent.largestAcknowledged() orelse return false;
        const candidate = self.recovery.packetThresholdCandidate(largest, quic.packet_space.default_packet_threshold) orelse return false;
        try self.retransmitCandidate(candidate, .congestion_controlled);
        return true;
    }

    pub fn retransmitTimeThresholdLoss(self: *Connection, now_ns: u64, loss_delay_ns: u64) Error!bool {
        const largest = self.sent.largestAcknowledged() orelse return false;
        const lost = self.sent.detectTimeThresholdLoss(now_ns, loss_delay_ns, largest);
        if (lost.bytes > 0) {
            self.congestion.onLostAt(lost.bytes, lost.largest_sent_time_ns, now_ns);
            if (lost.largest_pmtu_probe_size) |probe_size| {
                self.pmtud.onProbeLost(probe_size, self.config.max_datagram_size);
            }
            _ = self.applyPersistentCongestionIfDetected();
        }
        for (self.sent.packets.items) |packet| {
            if (!packet.lost) continue;
            const candidate = self.recovery.packetNumberCandidate(packet.packet_number) orelse continue;
            if (candidate.packet_number != packet.packet_number) continue;
            try self.retransmitCandidate(candidate, .congestion_controlled);
            return true;
        }
        return false;
    }

    pub fn timeThresholdLossDeadline(self: Connection, loss_delay_ns: u64) ?u64 {
        const largest = self.sent.largestAcknowledged() orelse return null;
        return self.sent.timeThresholdLossDeadline(loss_delay_ns, largest);
    }

    pub fn ptoBackoffCount(self: Connection) u8 {
        return self.pto_count;
    }

    pub fn ptoPeriod(self: Connection) u64 {
        var period = self.rtt_stats.pto(true);
        var remaining = self.pto_count;
        while (remaining != 0) : (remaining -= 1) {
            period = std.math.mul(u64, period, 2) catch return std.math.maxInt(u64);
        }
        return @max(period, quic.rtt.timer_granularity_ns);
    }

    pub fn ptoDeadline(self: Connection) ?u64 {
        if (self.close_info != null or self.idle_timed_out or self.recovery.pendingCount() == 0) return null;
        const sent_time = self.sent.latestAckElicitingInFlightSentTime() orelse return null;
        return std.math.add(u64, sent_time, self.ptoPeriod()) catch std.math.maxInt(u64);
    }

    pub fn lossDetectionTimerDeadline(self: Connection) ?LossDetectionTimerDeadline {
        if (self.close_info != null or self.idle_timed_out or self.recovery.pendingCount() == 0) return null;

        const loss_time = self.timeThresholdLossDeadline(self.rtt_stats.lossDelay());
        const pto_time = self.ptoDeadline();
        if (loss_time) |loss_deadline| {
            if (pto_time == null or loss_deadline <= pto_time.?) {
                return .{ .kind = .loss_time, .deadline_ns = loss_deadline };
            }
        }
        if (pto_time) |pto_deadline| return .{ .kind = .pto, .deadline_ns = pto_deadline };
        return null;
    }

    pub fn serviceLossDetectionTimer(self: *Connection, now_ns: u64) Error!?LossDetectionTimerDeadline {
        const deadline = self.lossDetectionTimerDeadline() orelse return null;
        if (now_ns < deadline.deadline_ns) return null;
        switch (deadline.kind) {
            .loss_time => {
                _ = try self.retransmitTimeThresholdLoss(now_ns, self.rtt_stats.lossDelay());
            },
            .pto => {
                _ = try self.retransmitPtoProbesAt(now_ns, 2);
            },
        }
        return deadline;
    }

    fn retransmitCandidate(self: *Connection, candidate: quic.recovery.Candidate, mode: RetransmitMode) Error!void {
        try self.retransmitCandidateAt(candidate, mode, null);
    }

    fn retransmitCandidateAt(self: *Connection, candidate: quic.recovery.Candidate, mode: RetransmitMode, sent_time_ns: ?u64) Error!void {
        const packet_number = self.next_packet_number;
        switch (mode) {
            .congestion_controlled => try self.congestion.reserve(candidate.payload.len),
            .pto_probe => self.congestion.onPtoProbeSent(candidate.payload.len),
        }
        errdefer self.congestion.discard(candidate.payload.len);

        try self.recovery.recordRetransmission(candidate.group_index, packet_number);
        errdefer _ = self.recovery.forgetPacketNumber(packet_number);
        try self.sent.sentAt(packet_number, true, candidate.payload.len, .not_ect, sent_time_ns);
        errdefer _ = self.sent.forget(packet_number);
        try self.sendPayloadPacket(packet_number, candidate.payload);
        self.next_packet_number += 1;
    }

    fn incrementPtoCount(self: *Connection) void {
        if (self.pto_count != std.math.maxInt(u8)) self.pto_count += 1;
    }

    pub fn markPacketAcknowledged(self: *Connection, packet_number: u64) bool {
        const marked_sent = self.sent.markAcknowledged(packet_number);
        const removed_recovery = self.recovery.acknowledgePacketNumber(packet_number);
        if (marked_sent) {
            if (self.pending_key_update_ack_threshold) |threshold| {
                if (packet_number >= threshold) self.pending_key_update_ack_threshold = null;
            }
        }
        return marked_sent or removed_recovery;
    }

    pub fn pendingRecoveryCount(self: Connection) usize {
        return self.recovery.pendingCount();
    }

    pub fn sendAck(self: *Connection, ack_delay: u64) Error!void {
        const ack = try self.received.ackFrame(self.endpoint.allocator, ack_delay);
        defer self.endpoint.allocator.free(ack.ranges);
        const frames = [_]quic.Frame{.{ .ack = ack }};
        try self.send(&frames);
    }

    pub fn sendAckWithEcn(self: *Connection, ack_delay: u64, ecn_counts: quic.EcnCounts) Error!void {
        var ack = try self.received.ackFrame(self.endpoint.allocator, ack_delay);
        defer self.endpoint.allocator.free(ack.ranges);
        ack.ecn_counts = ecn_counts;
        const frames = [_]quic.Frame{.{ .ack = ack }};
        try self.send(&frames);
    }

    pub fn sendAckForDelayNs(self: *Connection, ack_delay_ns: u64) Error!void {
        try self.sendAck(try self.encodedLocalAckDelayNanos(ack_delay_ns));
    }

    pub fn sendAckWithEcnForDelayNs(self: *Connection, ack_delay_ns: u64, ecn_counts: quic.EcnCounts) Error!void {
        try self.sendAckWithEcn(try self.encodedLocalAckDelayNanos(ack_delay_ns), ecn_counts);
    }

    pub fn encodedLocalAckDelayNanos(self: Connection, ack_delay_ns: u64) Error!u64 {
        return quic.rtt.encodeAckDelayNanos(ack_delay_ns, self.config.local_ack_delay_exponent) catch |err| switch (err) {
            error.InvalidAckDelayExponent => error.InvalidFrame,
        };
    }

    pub fn resetStream(self: *Connection, stream_id: u64, application_error_code: u64) Error!void {
        const entry = try self.sendStreamEntry(stream_id);
        try self.sendResetStream(stream_id, application_error_code, entry.highest_sent_end);
    }

    pub fn sendStopSending(self: *Connection, stream_id: u64, application_error_code: u64) Error!void {
        var recv_stream = try self.recvStreamFlow(stream_id);
        const info: StopSendingInfo = .{ .application_error_code = application_error_code };
        if (recv_stream.stop_sending_sent) |existing| {
            if (existing.application_error_code == application_error_code) return;
        }

        const frames = [_]quic.Frame{.{ .stop_sending = .{
            .stream_id = stream_id,
            .application_error_code = application_error_code,
        } }};
        try self.sendTrackedFrames(&frames);
        recv_stream.stop_sending_sent = info;
    }

    pub fn streamResetReceived(self: Connection, stream_id: u64) ?StreamResetInfo {
        for (self.stream_recv_flows.items) |entry| {
            if (entry.stream_id == stream_id) return entry.reset;
        }
        return null;
    }

    pub fn streamStopped(self: Connection, stream_id: u64) ?StopSendingInfo {
        for (self.stream_send_flows.items) |entry| {
            if (entry.stream_id == stream_id) return entry.stopped;
        }
        return null;
    }

    pub fn queuePathChallenge(self: *Connection, data: [8]u8) Error!void {
        try self.path_validation.queueChallenge(data);
    }

    pub fn peerActiveMigrationDisabled(self: Connection) bool {
        return self.config.peer_disable_active_migration;
    }

    pub fn peerPreferredAddress(self: Connection) ?quic.PreferredAddress {
        return self.config.peer_preferred_address;
    }

    pub fn preferredAddressIp4(preferred: quic.PreferredAddress) ?net.IpAddress {
        if (preferred.ipv4_port == 0 or allZero(u8, &preferred.ipv4_address)) return null;
        return .{ .ip4 = .{
            .bytes = preferred.ipv4_address,
            .port = preferred.ipv4_port,
        } };
    }

    pub fn preferredAddressIp6(preferred: quic.PreferredAddress) ?net.IpAddress {
        if (preferred.ipv6_port == 0 or allZero(u8, &preferred.ipv6_address)) return null;
        return .{ .ip6 = .{
            .bytes = preferred.ipv6_address,
            .port = preferred.ipv6_port,
        } };
    }

    pub fn beginPeerPreferredAddressMigration(self: *Connection, challenge: [8]u8, family: enum { ipv4, ipv6 }) Error!void {
        const preferred = self.config.peer_preferred_address orelse return error.InvalidTransportParameter;
        try self.peer_connection_ids.addWithLimit(1, preferred.connection_id, preferred.stateless_reset_token, self.config.active_connection_id_limit);
        try self.peer_connection_ids.markInUse(1);
        self.config.peer_connection_id = preferred.connection_id;
        const new_peer = switch (family) {
            .ipv4 => preferredAddressIp4(preferred) orelse return error.InvalidTransportParameter,
            .ipv6 => preferredAddressIp6(preferred) orelse return error.InvalidTransportParameter,
        };
        try self.beginPeerMigration(new_peer, challenge);
    }

    pub fn beginPeerMigration(self: *Connection, new_peer: net.IpAddress, challenge: [8]u8) Error!void {
        if (self.config.peer_disable_active_migration) return error.ActiveMigrationDisabled;
        self.config.peer = new_peer;
        self.peer_address_validated = false;
        self.peer_address_bytes_received = 0;
        self.peer_address_bytes_sent = 0;
        self.pmtud.resetForPath();
        try self.queuePathChallenge(challenge);
    }

    pub fn sendPendingPathChallenge(self: *Connection) Error!void {
        try self.sendPendingPathChallengeAt(null, null);
    }

    pub fn sendPendingPathChallengeAt(self: *Connection, now_ns: ?u64, timeout_ns: ?u64) Error!void {
        const frame = try self.path_validation.nextChallengeFrameAt(now_ns, timeout_ns);
        const frames = [_]quic.Frame{frame};
        try self.send(&frames);
    }

    pub fn pathValidationDeadline(self: Connection) ?u64 {
        return self.path_validation.earliestChallengeDeadline();
    }

    pub fn checkPathValidationTimeouts(self: *Connection, now_ns: u64) Error!usize {
        return try self.path_validation.checkTimeouts(now_ns);
    }

    pub fn sendPendingPathResponse(self: *Connection) Error!void {
        const frame = try self.path_validation.nextResponseFrame();
        const frames = [_]quic.Frame{frame};
        try self.send(&frames);
    }

    pub fn closeTransport(self: *Connection, error_code: u64, frame_type: u64, reason_phrase: []const u8) Error!void {
        try self.closeTransportAt(error_code, frame_type, reason_phrase, null, null);
    }

    pub fn closeTransportAt(
        self: *Connection,
        error_code: u64,
        frame_type: u64,
        reason_phrase: []const u8,
        now_ms: ?u64,
        pto_ms: ?u64,
    ) Error!void {
        const frames = [_]quic.Frame{.{ .connection_close = .{
            .error_code = error_code,
            .frame_type = frame_type,
            .reason_phrase = reason_phrase,
        } }};
        try self.sendTrackedFrames(&frames);
        try self.setCloseInfo(.{
            .application = false,
            .error_code = error_code,
            .frame_type = frame_type,
            .reason_phrase = reason_phrase,
            .state = .closing,
            .now_ms = now_ms,
            .pto_ms = pto_ms,
        });
    }

    pub fn resendClose(self: *Connection) Error!void {
        const close_info = self.close_info orelse return error.ConnectionClosed;
        if (close_info.state != .closing) return error.ConnectionClosed;
        const frame: quic.Frame = if (close_info.application) .{ .application_close = .{
            .error_code = close_info.error_code,
            .reason_phrase = close_info.reason_phrase,
        } } else .{ .connection_close = .{
            .error_code = close_info.error_code,
            .frame_type = close_info.frame_type,
            .reason_phrase = close_info.reason_phrase,
        } };
        try self.sendTrackedFramesAllowClosing(&.{frame});
    }

    pub fn closeApplication(self: *Connection, error_code: u64, reason_phrase: []const u8) Error!void {
        try self.closeApplicationAt(error_code, reason_phrase, null, null);
    }

    pub fn closeApplicationAt(self: *Connection, error_code: u64, reason_phrase: []const u8, now_ms: ?u64, pto_ms: ?u64) Error!void {
        const frames = [_]quic.Frame{.{ .application_close = .{
            .error_code = error_code,
            .reason_phrase = reason_phrase,
        } }};
        try self.sendTrackedFrames(&frames);
        try self.setCloseInfo(.{
            .application = true,
            .error_code = error_code,
            .reason_phrase = reason_phrase,
            .state = .closing,
            .now_ms = now_ms,
            .pto_ms = pto_ms,
        });
    }

    pub fn closed(self: Connection) bool {
        if (self.idle_timed_out) return true;
        return self.close_info != null and self.close_info.?.state == .closed;
    }

    pub fn closing(self: Connection) bool {
        return self.close_info != null and self.close_info.?.state == .closing;
    }

    pub fn draining(self: Connection) bool {
        return self.close_info != null and self.close_info.?.state == .draining;
    }

    pub fn closeExpiryDeadlineMillis(self: Connection) ?u64 {
        return if (self.close_info) |close_info| close_info.expires_ms else null;
    }

    pub fn checkCloseExpired(self: *Connection, now_ms: u64) bool {
        if (self.close_info) |*close_info| {
            const deadline = close_info.expires_ms orelse return false;
            if (now_ms < deadline) return false;
            close_info.state = .closed;
            return true;
        }
        return false;
    }

    pub fn decodedPeerAckDelayNanos(self: Connection, ack: quic.AckFrame) Error!u64 {
        return quic.rtt.decodeAckDelayNanos(ack.ack_delay, self.config.peer_ack_delay_exponent) catch |err| switch (err) {
            error.InvalidAckDelayExponent => error.InvalidFrame,
            error.AckDelayOverflow => error.InvalidFrame,
        };
    }

    pub fn ackRttSample(self: Connection, ack: quic.AckFrame, now_ns: u64) Error!?quic.packet_space.SentPacketTracker.RttSample {
        return try self.sent.ackRttSample(ack, now_ns, self.config.peer_ack_delay_exponent);
    }

    pub fn updateRttFromAck(self: *Connection, ack: quic.AckFrame, now_ns: u64) Error!bool {
        const sample = try self.ackRttSample(ack, now_ns) orelse return false;
        self.rtt_stats.updateAt(sample.latest_rtt_ns, sample.ack_delay_ns, self.handshake_confirmed, now_ns);
        return true;
    }

    pub fn persistentCongestionPeriod(self: Connection) ?quic.packet_space.SentPacketTracker.PersistentCongestionPeriod {
        const largest = self.sent.largestAcknowledged() orelse return null;
        const period = self.sent.persistentCongestionPeriod(
            self.rtt_stats.first_rtt_sample_time_ns,
            largest,
            self.last_persistent_congestion_packet_number,
        ) orelse return null;
        if (period.durationNs() <= self.rtt_stats.persistentCongestionThreshold()) return null;
        return period;
    }

    pub fn effectiveIdleTimeoutMillis(self: Connection) ?u64 {
        const local = self.config.local_max_idle_timeout_ms;
        const peer = self.config.peer_max_idle_timeout_ms;
        if (local == 0 and peer == 0) return null;
        if (local == 0) return peer;
        if (peer == 0) return local;
        return @min(local, peer);
    }

    pub fn markActivity(self: *Connection, now_ms: u64) void {
        if (self.idle_timed_out) return;
        self.last_activity_ms = now_ms;
    }

    pub fn idleTimeoutDeadlineMillis(self: Connection) ?u64 {
        const timeout = self.effectiveIdleTimeoutMillis() orelse return null;
        const last_activity = self.last_activity_ms orelse return null;
        return std.math.add(u64, last_activity, timeout) catch std.math.maxInt(u64);
    }

    pub fn checkIdleTimeout(self: *Connection, now_ms: u64) bool {
        const deadline = self.idleTimeoutDeadlineMillis() orelse return false;
        if (now_ms < deadline) return false;
        self.idle_timed_out = true;
        return true;
    }

    pub fn sendNewConnectionId(self: *Connection, connection_id: []const u8, stateless_reset_token: [16]u8) Error!void {
        const frame = try self.local_connection_ids.issue(connection_id, stateless_reset_token);
        const frames = [_]quic.Frame{frame};
        try self.send(&frames);
    }

    pub fn sendHandshakeDone(self: *Connection) Error!void {
        if (self.config.local_endpoint != .server) return error.InvalidFrame;
        const frames = [_]quic.Frame{.{ .handshake_done = {} }};
        try self.send(&frames);
    }

    pub fn sendNewToken(self: *Connection, token: []const u8) Error!void {
        if (self.config.local_endpoint != .server) return error.InvalidFrame;
        if (token.len == 0) return error.InvalidFrame;
        const frames = [_]quic.Frame{.{ .new_token = .{ .token = token } }};
        try self.send(&frames);
    }

    pub fn sendAddressValidationToken(
        self: *Connection,
        secret: quic.address_validation_token.Secret,
        issued_ns: i64,
        lifetime_ns: u64,
        peer_address: []const u8,
        nonce: quic.address_validation_token.Nonce,
    ) Error!void {
        if (self.config.local_endpoint != .server) return error.InvalidFrame;
        const token = quic.address_validation_token.encode(self.endpoint.allocator, secret, .{
            .kind = .new_token,
            .issued_ns = issued_ns,
            .lifetime_ns = lifetime_ns,
            .peer_address = peer_address,
            .nonce = nonce,
        }) catch return error.InvalidFrame;
        defer self.endpoint.allocator.free(token);
        try self.sendNewToken(token);
    }

    pub fn switchToNextPeerConnectionId(self: *Connection) bool {
        const entry = self.peer_connection_ids.consumeUnused() orelse return false;
        self.config.peer_connection_id = entry.slice();
        return true;
    }

    pub fn pendingRetireConnectionIdCount(self: Connection) usize {
        return self.peer_connection_ids.pendingRetireCount();
    }

    pub fn sendPendingRetireConnectionIds(self: *Connection) Error!usize {
        var sent: usize = 0;
        while (self.peer_connection_ids.peekRetireFrame()) |frame| {
            try self.send(&[_]quic.Frame{frame});
            self.peer_connection_ids.discardRetireFrame();
            sent += 1;
        }
        return sent;
    }

    pub fn detectStatelessReset(self: Connection, datagram: []const u8) ?u64 {
        return self.peer_connection_ids.detectStatelessReset(datagram);
    }

    pub fn processStatelessResetDatagram(self: *Connection, datagram: []const u8, now_ms: ?u64, pto_ms: ?u64) ?u64 {
        if (self.closed()) return null;
        const sequence_number = self.detectStatelessReset(datagram) orelse return null;
        self.enterStatelessResetDraining(now_ms, pto_ms) catch return null;
        return sequence_number;
    }

    pub fn latestNewToken(self: Connection) ?[]const u8 {
        if (self.stored_new_tokens.items.len == 0) return null;
        return self.stored_new_tokens.items[self.stored_new_tokens.items.len - 1];
    }

    pub fn handshakeConfirmed(self: Connection) bool {
        return self.handshake_confirmed;
    }

    pub fn localOneRttKeyPhase(self: Connection) bool {
        return self.send_key_phase.currentKeyPhase();
    }

    pub fn peerOneRttKeyPhase(self: Connection) bool {
        return self.receive_key_phase.currentKeyPhase();
    }

    pub fn localOneRttKeyUpdateCount(self: Connection) u64 {
        return self.send_key_phase.keyUpdateCount();
    }

    pub fn peerOneRttKeyUpdateCount(self: Connection) u64 {
        return self.receive_key_phase.keyUpdateCount();
    }

    pub fn pendingOneRttKeyUpdateAckThreshold(self: Connection) ?u64 {
        return self.pending_key_update_ack_threshold;
    }

    pub fn localOneRttRetainsKeyGeneration(self: Connection, generation: u64) bool {
        return self.send_key_phase.retainsKeyGeneration(generation);
    }

    pub fn peerOneRttRetainsKeyGeneration(self: Connection, generation: u64) bool {
        return self.receive_key_phase.retainsKeyGeneration(generation);
    }

    pub fn initiateKeyUpdate(self: *Connection) Error!void {
        if (self.close_info != null) return error.ConnectionClosed;
        if (self.pending_key_update_ack_threshold != null) return error.InvalidPacket;
        self.send_key_phase.initiateKeyUpdate();
        self.pending_key_update_ack_threshold = self.next_packet_number;
    }

    pub fn schedulePreviousOneRttKeyDiscard(self: *Connection, deadline_nanos: i64) void {
        self.send_key_phase.schedulePreviousDiscard(deadline_nanos);
        self.receive_key_phase.schedulePreviousDiscard(deadline_nanos);
    }

    pub fn oneRttKeyDiscardDeadline(self: Connection) ?i64 {
        var deadline: ?i64 = self.send_key_phase.previousDiscardDeadline();
        if (self.receive_key_phase.previousDiscardDeadline()) |peer_deadline| {
            if (deadline == null or peer_deadline < deadline.?) deadline = peer_deadline;
        }
        return deadline;
    }

    pub fn discardExpiredOneRttKeys(self: *Connection, now_nanos: i64) bool {
        var discarded = self.send_key_phase.discardExpiredPrevious(now_nanos);
        discarded = self.receive_key_phase.discardExpiredPrevious(now_nanos) or discarded;
        return discarded;
    }

    pub fn receivePacket(self: *Connection) Error!ReceivedPacket {
        return self.receivePacketAt(null);
    }

    pub fn receivePacketOrDropAfterClose(self: *Connection) Error!?ReceivedPacket {
        return self.receivePacketOrDropAfterCloseAt(null);
    }

    pub fn receivePacketOrDropAfterCloseAt(self: *Connection, now_ns: ?u64) Error!?ReceivedPacket {
        if (self.close_info != null or self.idle_timed_out) return null;
        return try self.receivePacketAt(now_ns);
    }

    pub fn receivePacketAt(self: *Connection, now_ns: ?u64) Error!ReceivedPacket {
        if (self.close_info != null or self.idle_timed_out) return error.ConnectionClosed;
        var packet = try receiveWithKeyUpdate(
            self.endpoint,
            self.receive_key_phase.keyUpdateKeys(),
            self.config.local_connection_id.len,
            self.expected_packet_number,
            self.config.max_frames_per_packet,
        );
        errdefer packet.deinit(self.endpoint.allocator);
        try self.applyReceivedFramesForDestination(packet.packet.packet_number, packet.frames, now_ns, .not_ect, packet.packet.destination_connection_id);
        self.updateSpinBitAfterReceive(packet.packet.spin_bit);
        if (packet.peer_initiated_key_update) {
            _ = self.receive_key_phase.updateAfterReceiving(packet.packet.key_phase);
        }
        return packet;
    }

    pub fn receiveRoutedDatagram(self: *Connection, routed: quic.runtime.RoutedBytes) Error!ReceivedPacket {
        return self.receiveRoutedDatagramAt(routed, null);
    }

    pub fn receiveRoutedDatagramOrDropAfterClose(self: *Connection, routed: quic.runtime.RoutedBytes) Error!?ReceivedPacket {
        return self.receiveRoutedDatagramOrDropAfterCloseAt(routed, null);
    }

    pub fn receiveRoutedDatagramOrDropAfterCloseAt(self: *Connection, routed: quic.runtime.RoutedBytes, now_ns: ?u64) Error!?ReceivedPacket {
        if (self.close_info != null or self.idle_timed_out) return null;
        return try self.receiveRoutedDatagramAt(routed, now_ns);
    }

    pub const RoutedReceiveResult = union(enum) {
        packet: ReceivedPacket,
        stateless_reset: u64,
        dropped_after_close,
    };

    pub fn receiveRoutedDatagramOrStatelessReset(self: *Connection, routed: quic.runtime.RoutedBytes, now_ms: ?u64, pto_ms: ?u64) Error!RoutedReceiveResult {
        if (self.close_info != null or self.idle_timed_out) return .dropped_after_close;
        if (self.processStatelessResetDatagram(routed.datagram.bytes, now_ms, pto_ms)) |sequence_number| {
            return .{ .stateless_reset = sequence_number };
        }
        return .{ .packet = try self.receiveRoutedDatagramAt(routed, null) };
    }

    pub fn receiveRoutedDatagramAt(self: *Connection, routed: quic.runtime.RoutedBytes, now_ns: ?u64) Error!ReceivedPacket {
        if (self.close_info != null or self.idle_timed_out) return error.ConnectionClosed;
        var packet = try openReceivedBytesWithKeyUpdate(
            self.endpoint,
            routed.datagram.from,
            routed.datagram.bytes,
            self.receive_key_phase.keyUpdateKeys(),
            routed.destination_connection_id.len,
            self.expected_packet_number,
            self.config.max_frames_per_packet,
        );
        errdefer packet.deinit(self.endpoint.allocator);
        try self.applyReceivedFramesForDestination(packet.packet.packet_number, packet.frames, now_ns, .not_ect, packet.packet.destination_connection_id);
        self.updateSpinBitAfterReceive(packet.packet.spin_bit);
        if (packet.peer_initiated_key_update) {
            _ = self.receive_key_phase.updateAfterReceiving(packet.packet.key_phase);
        }
        return packet;
    }

    pub fn receiveRoutedDatagramWithEcnAt(self: *Connection, routed: quic.runtime.RoutedBytes, now_ns: ?u64, ecn: quic.packet_space.EcnCodepoint) Error!ReceivedPacket {
        if (self.close_info != null or self.idle_timed_out) return error.ConnectionClosed;
        var packet = try openReceivedBytesWithKeyUpdate(
            self.endpoint,
            routed.datagram.from,
            routed.datagram.bytes,
            self.receive_key_phase.keyUpdateKeys(),
            routed.destination_connection_id.len,
            self.expected_packet_number,
            self.config.max_frames_per_packet,
        );
        errdefer packet.deinit(self.endpoint.allocator);
        try self.applyReceivedFramesForDestination(packet.packet.packet_number, packet.frames, now_ns, ecn, packet.packet.destination_connection_id);
        self.updateSpinBitAfterReceive(packet.packet.spin_bit);
        if (packet.peer_initiated_key_update) {
            _ = self.receive_key_phase.updateAfterReceiving(packet.packet.key_phase);
        }
        return packet;
    }

    fn applyReceivedFrames(self: *Connection, packet_number: u64, frames: []const quic.Frame, now_ns: ?u64, ecn: quic.packet_space.EcnCodepoint) Error!void {
        try self.applyReceivedFramesForDestination(packet_number, frames, now_ns, ecn, null);
    }

    fn applyReceivedFramesForDestination(
        self: *Connection,
        packet_number: u64,
        frames: []const quic.Frame,
        now_ns: ?u64,
        ecn: quic.packet_space.EcnCodepoint,
        packet_destination_connection_id: ?[]const u8,
    ) Error!void {
        if (!try self.received.wouldRecordFresh(packet_number)) return error.DuplicatePacket;
        try self.validateReceivedFramePreconditions(frames);
        if (!try self.received.recordWithEcn(packet_number, ecn)) return error.DuplicatePacket;
        if (packet_number >= self.expected_packet_number) {
            self.expected_packet_number = packet_number + 1;
        }
        for (frames) |frame| {
            switch (frame) {
                .ack => {
                    if (now_ns) |now| _ = try self.updateRttFromAck(frame.ack, now);
                    const acked = self.sent.applyAckDetailed(frame.ack) catch |err| switch (err) {
                        error.InvalidAckFrame => try self.applyAckWithEcnFailure(frame.ack),
                        else => return err,
                    };
                    if (acked.ack_eliciting_packets > 0) self.pto_count = 0;
                    if (acked.largest_pmtu_probe_size) |probe_size| {
                        self.pmtud.onProbeAcked(probe_size, self.config.max_datagram_size);
                    }
                    if (acked.ecn_ce_delta > 0) {
                        self.congestion.onExplicitCongestion(now_ns);
                    }
                    self.congestion.onAckedAt(acked.bytes, acked.largest_sent_time_ns);
                    const lost = self.sent.detectPacketThresholdLoss(frame.ack.largest_acknowledged, quic.packet_space.default_packet_threshold);
                    if (lost.bytes > 0) {
                        self.congestion.onLostAt(lost.bytes, lost.largest_sent_time_ns, now_ns);
                        if (lost.largest_pmtu_probe_size) |probe_size| {
                            self.pmtud.onProbeLost(probe_size, self.config.max_datagram_size);
                        }
                        _ = self.applyPersistentCongestionIfDetected();
                    }
                    if (now_ns) |now| {
                        const timed_lost = self.sent.detectTimeThresholdLoss(now, self.rtt_stats.lossDelay(), frame.ack.largest_acknowledged);
                        if (timed_lost.bytes > 0) {
                            self.congestion.onLostAt(timed_lost.bytes, timed_lost.largest_sent_time_ns, now);
                            if (timed_lost.largest_pmtu_probe_size) |probe_size| {
                                self.pmtud.onProbeLost(probe_size, self.config.max_datagram_size);
                            }
                            _ = self.applyPersistentCongestionIfDetected();
                        }
                    }
                    _ = try self.recovery.applyAck(frame.ack);
                    if (self.pending_key_update_ack_threshold) |threshold| {
                        if (self.hasAcknowledgedPacketAtOrAbove(threshold)) {
                            self.pending_key_update_ack_threshold = null;
                        }
                    }
                },
                .max_data => |max_data| self.send_flow.updateLimit(max_data.maximum_data),
                .max_stream_data => |max_stream_data| {
                    const flow = try self.sendStreamFlow(max_stream_data.stream_id);
                    flow.updateLimit(max_stream_data.maximum_stream_data);
                },
                .max_streams_bidi => |max_streams| try self.receiveMaxStreams(max_streams.maximum_streams, .bidirectional),
                .max_streams_uni => |max_streams| try self.receiveMaxStreams(max_streams.maximum_streams, .unidirectional),
                .streams_blocked_bidi => |blocked| try self.receiveStreamsBlocked(blocked.maximum_streams, .bidirectional),
                .streams_blocked_uni => |blocked| try self.receiveStreamsBlocked(blocked.maximum_streams, .unidirectional),
                .new_connection_id => |new_connection_id| {
                    try self.peer_connection_ids.addWithRetirePriorTo(
                        new_connection_id.sequence_number,
                        new_connection_id.retire_prior_to,
                        new_connection_id.connection_id,
                        new_connection_id.stateless_reset_token,
                        self.config.active_connection_id_limit,
                    );
                },
                .retire_connection_id => |retire| try self.local_connection_ids.retireExceptPacketDestination(retire.sequence_number, packet_destination_connection_id),
                .path_challenge => |path_challenge| try self.path_validation.receiveChallenge(path_challenge.data),
                .path_response => |path_response| {
                    if (!self.path_validation.receiveResponseValidated(path_response.data)) return error.UnknownPathResponse;
                    self.setPeerAddressValidated(true);
                },
                .reset_stream => |reset| try self.receiveResetStream(reset),
                .stop_sending => |stop| try self.receiveStopSending(stop),
                .new_token => |new_token| try self.receiveNewToken(new_token),
                .handshake_done => try self.receiveHandshakeDone(),
                .datagram => |datagram| try self.receiveDatagramFrame(datagram),
                .ack_frequency => |ack_frequency| try self.receiveAckFrequency(ack_frequency),
                .immediate_ack => self.receiveImmediateAck(),
                .connection_close => |close| try self.setCloseInfo(.{
                    .application = false,
                    .error_code = close.error_code,
                    .frame_type = close.frame_type,
                    .reason_phrase = close.reason_phrase,
                    .state = .draining,
                }),
                .application_close => |close| try self.setCloseInfo(.{
                    .application = true,
                    .error_code = close.error_code,
                    .reason_phrase = close.reason_phrase,
                    .state = .draining,
                }),
                .stream => |stream| {
                    var recv_stream = try self.recvStreamFlow(stream.stream_id);
                    const data_len = std.math.cast(u64, stream.data.len) orelse return error.InvalidFrameLength;
                    const stream_end = std.math.add(u64, stream.offset, data_len) catch return error.InvalidFrameLength;
                    try self.applyFinalSize(recv_stream, stream_end, stream.fin);
                    try recv_stream.flow.receive(stream_end);
                    const newly_received = try recv_stream.recv_state.insertTracked(stream);

                    // QUIC flow control is byte-range based, not highest-offset
                    // based.  Retransmissions or partially overlapping frames
                    // must not consume connection credit again, while conflicting
                    // overlaps are rejected by RecvState before this counter moves.
                    if (newly_received != 0) {
                        const next_total = std.math.add(u64, self.recv_data_total, newly_received) catch return error.FlowControlViolation;
                        try self.recv_flow.receive(next_total);
                        self.recv_data_total = next_total;
                    }
                    recv_stream.highest_received_end = @max(recv_stream.highest_received_end, stream_end);
                },
                else => {},
            }
        }
    }

    fn validateReceivedFramePreconditions(self: *Connection, frames: []const quic.Frame) Error!void {
        var recv_data_total = self.recv_data_total;
        var recv_streams: std.ArrayList(RecvStreamPreflightEntry) = .empty;
        defer {
            for (recv_streams.items) |*entry| entry.deinit();
            recv_streams.deinit(self.endpoint.allocator);
        }
        var peer_connection_ids = self.peer_connection_ids;
        var local_connection_ids = self.local_connection_ids;
        var path_validation = try self.path_validation.clone(self.endpoint.allocator);
        defer path_validation.deinit();

        for (frames) |frame| {
            switch (frame) {
                .ack => |ack| {
                    // ACK handling mutates sent-packet, recovery, congestion, and
                    // key-update state.  Validate peer-provided ACK ranges before
                    // any earlier frame in the same packet can apply
                    // receive-side effects; mature stacks such as quicz use the
                    // same validate-before-mutate boundary for malformed
                    // multi-frame packets.
                    try self.sent.validateAckCoversSentPackets(ack);
                },
                .stream => |stream| try self.validateStreamFramePrecondition(stream, &recv_streams, &recv_data_total),
                .reset_stream => |reset| try self.validateResetStreamPrecondition(reset, &recv_streams, &recv_data_total),
                .stream_data_blocked => |blocked| try self.validateStreamReceiveFrameId(blocked.stream_id),
                .max_stream_data => |max_stream_data| try self.validateStreamSendControlId(max_stream_data.stream_id),
                .stop_sending => |stop| try self.validateStreamSendControlId(stop.stream_id),
                .new_connection_id => |new_connection_id| {
                    // CID frames mutate fixed-size pools and can fail because of
                    // duplicate CIDs/tokens, active_connection_id_limit, or
                    // retire-prior-to queue pressure. Apply them to shadow pools
                    // first so an invalid CID frame later in the packet cannot
                    // leave earlier STREAM/ACK effects committed.
                    try peer_connection_ids.addWithRetirePriorTo(
                        new_connection_id.sequence_number,
                        new_connection_id.retire_prior_to,
                        new_connection_id.connection_id,
                        new_connection_id.stateless_reset_token,
                        self.config.active_connection_id_limit,
                    );
                },
                .retire_connection_id => |retire| try local_connection_ids.retire(retire.sequence_number),
                .path_challenge => |path_challenge| try path_validation.receiveChallenge(path_challenge.data),
                .path_response => |path_response| try path_validation.receiveResponse(path_response.data),
                .new_token => |new_token| {
                    if (self.config.local_endpoint == .server) return error.InvalidFrame;
                    if (new_token.token.len == 0) return error.InvalidFrame;
                },
                .handshake_done => {
                    if (self.config.local_endpoint == .server) return error.InvalidFrame;
                },
                .datagram => |datagram| try self.validateDatagramFrame(datagram),
                .ack_frequency, .immediate_ack => if (!self.config.enable_ack_frequency) return error.AckFrequencyDisabled,
                else => {},
            }
        }
    }

    fn validateStreamFramePrecondition(
        self: *Connection,
        stream: quic.StreamFrame,
        recv_streams: *std.ArrayList(RecvStreamPreflightEntry),
        recv_data_total: *u64,
    ) Error!void {
        try self.validateStreamReceiveFrameId(stream.stream_id);
        const recv_stream = try self.preflightRecvStreamEntry(recv_streams, stream.stream_id);
        const data_len = std.math.cast(u64, stream.data.len) orelse return error.InvalidFrameLength;
        const stream_end = std.math.add(u64, stream.offset, data_len) catch return error.InvalidFrameLength;

        try preflightApplyFinalSize(recv_stream, stream_end, stream.fin);
        if (stream_end > recv_stream.flow_limit) return error.FlowControlViolation;
        const newly_received = try recv_stream.recv_state.insertTracked(stream);
        try self.preflightRecvCredit(recv_stream, newly_received, recv_data_total);
        recv_stream.highest_received_end = @max(recv_stream.highest_received_end, stream_end);
    }

    fn validateResetStreamPrecondition(
        self: *Connection,
        reset: quic.ResetStreamFrame,
        recv_streams: *std.ArrayList(RecvStreamPreflightEntry),
        recv_data_total: *u64,
    ) Error!void {
        try self.validateStreamReceiveFrameId(reset.stream_id);
        const recv_stream = try self.preflightRecvStreamEntry(recv_streams, reset.stream_id);
        try preflightApplyFinalSize(recv_stream, reset.final_size, true);
        if (reset.final_size > recv_stream.flow_limit) return error.FlowControlViolation;
        const received = recv_stream.recv_state.receivedByteCount();
        if (reset.final_size < received) return error.FinalSizeMismatch;
        try self.preflightRecvCredit(recv_stream, reset.final_size - received, recv_data_total);
        recv_stream.highest_received_end = @max(recv_stream.highest_received_end, reset.final_size);
    }

    fn preflightRecvStreamEntry(
        self: *Connection,
        recv_streams: *std.ArrayList(RecvStreamPreflightEntry),
        stream_id: u64,
    ) Error!*RecvStreamPreflightEntry {
        for (recv_streams.items) |*entry| {
            if (entry.stream_id == stream_id) return entry;
        }

        if (self.findRecvStreamEntry(stream_id)) |existing| {
            var recv_state = try existing.recv_state.clone(self.endpoint.allocator);
            var appended = false;
            errdefer if (!appended) recv_state.deinit();
            try recv_streams.append(self.endpoint.allocator, .{
                .stream_id = stream_id,
                .flow_limit = existing.flow.limit,
                .recv_state = recv_state,
                .highest_received_end = existing.highest_received_end,
                .final_size = existing.final_size,
            });
            appended = true;
        } else {
            try self.validatePeerStreamCount(stream_id);
            const flow_limit = self.initialReceiveStreamDataLimit(stream_id);
            try recv_streams.append(self.endpoint.allocator, .{
                .stream_id = stream_id,
                .flow_limit = flow_limit,
                .recv_state = quic.stream_state.RecvState.init(
                    self.endpoint.allocator,
                    stream_id,
                    maxBufferedForLimit(flow_limit),
                ),
            });
        }
        return &recv_streams.items[recv_streams.items.len - 1];
    }

    fn preflightRecvCredit(
        self: Connection,
        _: *RecvStreamPreflightEntry,
        newly_received: u64,
        recv_data_total: *u64,
    ) Error!void {
        if (newly_received == 0) return;
        const next_total = std.math.add(u64, recv_data_total.*, newly_received) catch return error.FlowControlViolation;
        if (next_total > self.recv_flow.limit) return error.FlowControlViolation;
        recv_data_total.* = next_total;
    }

    fn preflightApplyFinalSize(recv_stream: *RecvStreamPreflightEntry, final_size: u64, final: bool) Error!void {
        if (final and final_size < recv_stream.highest_received_end) return error.FinalSizeMismatch;
        if (recv_stream.final_size) |known| {
            if (final_size > known) return error.FinalSizeMismatch;
            if (final and final_size != known) return error.FinalSizeMismatch;
            return;
        }
        if (final) recv_stream.final_size = final_size;
    }

    fn receiveMaxStreams(self: *Connection, maximum_streams: u64, direction: enum { bidirectional, unidirectional }) Error!void {
        if (maximum_streams > quic.max_stream_count) return error.InvalidFrame;
        switch (direction) {
            .bidirectional => self.peer_max_streams_bidi = @max(self.peer_max_streams_bidi, maximum_streams),
            .unidirectional => self.peer_max_streams_uni = @max(self.peer_max_streams_uni, maximum_streams),
        }
    }

    pub fn nextSpinBit(self: Connection) bool {
        return self.config.enable_spin_bit and self.spin_bit_value;
    }

    pub fn resetSpinBit(self: *Connection) void {
        self.spin_bit_value = false;
    }

    fn updateSpinBitAfterReceive(self: *Connection, peer_spin_bit: bool) void {
        if (!self.config.enable_spin_bit) return;
        self.spin_bit_value = switch (self.config.local_endpoint) {
            .client => !peer_spin_bit,
            .server => peer_spin_bit,
        };
    }

    fn receiveStreamsBlocked(self: *Connection, maximum_streams: u64, direction: enum { bidirectional, unidirectional }) Error!void {
        if (maximum_streams > quic.max_stream_count) return error.InvalidFrame;
        const current_limit = switch (direction) {
            .bidirectional => self.recv_max_streams_bidi,
            .unidirectional => self.recv_max_streams_uni,
        };
        if (maximum_streams < current_limit) {
            const frame = switch (direction) {
                .bidirectional => quic.Frame{ .max_streams_bidi = .{ .maximum_streams = current_limit } },
                .unidirectional => quic.Frame{ .max_streams_uni = .{ .maximum_streams = current_limit } },
            };
            try self.sendTrackedFrames(&[_]quic.Frame{frame});
        }
    }

    fn hasAcknowledgedPacketAtOrAbove(self: Connection, threshold: u64) bool {
        for (self.sent.packets.items) |packet| {
            if (packet.acknowledged and packet.packet_number >= threshold) return true;
        }
        return false;
    }

    fn receiveNewToken(self: *Connection, new_token: quic.NewTokenFrame) Error!void {
        if (self.config.local_endpoint == .server) return error.InvalidFrame;
        if (new_token.token.len == 0) return error.InvalidFrame;
        if (self.stored_new_tokens.items.len >= self.config.max_stored_new_tokens) return;
        const owned = try self.endpoint.allocator.dupe(u8, new_token.token);
        errdefer self.endpoint.allocator.free(owned);
        try self.stored_new_tokens.append(self.endpoint.allocator, owned);
    }

    fn receiveHandshakeDone(self: *Connection) Error!void {
        if (self.config.local_endpoint == .server) return error.InvalidFrame;
        self.handshake_confirmed = true;
    }

    fn receiveDatagramFrame(self: *Connection, datagram: quic.DatagramFrame) Error!void {
        try self.validateDatagramFrame(datagram);
        if (self.datagram_recv_queue.items.len >= self.config.max_datagram_queue_items) {
            self.datagrams_dropped_incoming_count +|= 1;
            return;
        }
        const owned = try self.endpoint.allocator.dupe(u8, datagram.data);
        errdefer self.endpoint.allocator.free(owned);
        try self.datagram_recv_queue.append(self.endpoint.allocator, owned);
        self.datagrams_received_count +|= 1;
    }

    fn validateDatagramFrame(self: Connection, datagram: quic.DatagramFrame) Error!void {
        const frame_limit = self.config.local_max_datagram_frame_size orelse return error.InvalidFrame;
        const frame_size = datagramFrameWireSize(datagram) orelse return error.InvalidFrameLength;
        if (frame_size > frame_limit) return error.InvalidFrame;
    }

    fn receiveAckFrequency(self: *Connection, ack_frequency: quic.AckFrequencyFrame) Error!void {
        if (!self.config.enable_ack_frequency) return error.AckFrequencyDisabled;
        if (ack_frequency.sequence_number < self.ack_frequency_recv_next_sequence) return;
        self.ack_frequency_recv_next_sequence = ack_frequency.sequence_number +| 1;
        self.ack_eliciting_threshold = @max(@as(u64, 1), ack_frequency.ack_eliciting_threshold);
        self.requested_max_ack_delay = ack_frequency.request_max_ack_delay;
        self.ack_reordering_threshold = @max(@as(u64, 1), ack_frequency.reordering_threshold);
    }

    fn receiveImmediateAck(self: *Connection) void {
        self.immediate_ack_requested = true;
    }

    fn receiveResetStream(self: *Connection, reset: quic.ResetStreamFrame) Error!void {
        var recv_stream = try self.recvStreamFlow(reset.stream_id);
        try self.applyFinalSize(recv_stream, reset.final_size, true);
        try recv_stream.flow.receive(reset.final_size);

        const received = recv_stream.recv_state.receivedByteCount();
        if (reset.final_size < received) return error.FinalSizeMismatch;
        const new_stream_credit = reset.final_size - received;
        if (new_stream_credit != 0) {
            const next_total = std.math.add(u64, self.recv_data_total, new_stream_credit) catch return error.FlowControlViolation;
            try self.recv_flow.receive(next_total);
            self.recv_data_total = next_total;
        }
        recv_stream.highest_received_end = @max(recv_stream.highest_received_end, reset.final_size);

        recv_stream.reset = .{
            .application_error_code = reset.application_error_code,
            .final_size = reset.final_size,
        };
    }

    fn receiveStopSending(self: *Connection, stop: quic.StopSendingFrame) Error!void {
        const entry = try self.sendStreamEntry(stop.stream_id);
        entry.stopped = .{ .application_error_code = stop.application_error_code };
        if (entry.reset_sent == null) {
            // RFC 9000 requires a peer that receives STOP_SENDING to answer
            // with RESET_STREAM unless the send side is already terminal.  The
            // reset uses the current stream final size (highest sent offset)
            // so the peer can account stream and connection flow control even
            // when locally generated STREAM frames use explicit offsets.
            try self.sendResetStream(stop.stream_id, stop.application_error_code, entry.highest_sent_end);
        }
    }

    fn applyFinalSize(_: *Connection, recv_stream: *StreamRecvFlowEntry, final_size: u64, final: bool) Error!void {
        if (final and final_size < recv_stream.highest_received_end) return error.FinalSizeMismatch;
        if (recv_stream.final_size) |known| {
            if (final_size > known) return error.FinalSizeMismatch;
            if (final and final_size != known) return error.FinalSizeMismatch;
            return;
        }
        if (final) recv_stream.final_size = final_size;
    }

    fn sendResetStream(self: *Connection, stream_id: u64, application_error_code: u64, final_size: u64) Error!void {
        const entry = try self.sendStreamEntry(stream_id);
        const info: StreamResetInfo = .{
            .application_error_code = application_error_code,
            .final_size = final_size,
        };
        if (entry.reset_sent) |existing| {
            if (existing.application_error_code == info.application_error_code and existing.final_size == info.final_size) return;
            return error.FinalSizeMismatch;
        }

        const frames = [_]quic.Frame{.{ .reset_stream = .{
            .stream_id = stream_id,
            .application_error_code = application_error_code,
            .final_size = final_size,
        } }};
        try self.sendTrackedFrames(&frames);
        entry.reset_sent = info;
    }

    fn sendTrackedFramesAllowClosing(self: *Connection, frames: []const quic.Frame) Error!void {
        if (self.idle_timed_out or self.closed() or self.draining()) return error.ConnectionClosed;
        try self.sendTrackedFramesEcnAt(frames, .not_ect, null);
    }

    fn noteSentStreams(self: *Connection, frames: []const quic.Frame) void {
        for (frames) |frame| {
            if (frame != .stream) continue;
            const entry = self.findSendStreamEntry(frame.stream.stream_id) orelse continue;
            const data_len = std.math.cast(u64, frame.stream.data.len) orelse continue;
            const stream_end = std.math.add(u64, frame.stream.offset, data_len) catch continue;
            entry.highest_sent_end = @max(entry.highest_sent_end, stream_end);
        }
    }

    fn setCloseInfo(self: *Connection, close: struct {
        application: bool,
        error_code: u64,
        frame_type: u64 = 0,
        reason_phrase: []const u8,
        state: CloseState,
        now_ms: ?u64 = null,
        pto_ms: ?u64 = null,
    }) Error!void {
        if (self.close_info) |*existing| {
            // RFC 9000: receipt of CONNECTION_CLOSE moves the endpoint into
            // draining, where no further packets are sent.  A locally initiated
            // close starts in `closing`; if the peer answers with its own close,
            // do not ignore that transition merely because close_info exists.
            if (close.state == .draining and existing.state == .closing) {
                existing.state = .draining;
                existing.started_ms = close.now_ms;
                existing.expires_ms = closeExpiryMillis(close.now_ms, close.pto_ms);
            }
            return;
        }
        const expires_ms = closeExpiryMillis(close.now_ms, close.pto_ms);
        self.close_info = .{
            .application = close.application,
            .error_code = close.error_code,
            .frame_type = close.frame_type,
            .reason_phrase = try self.endpoint.allocator.dupe(u8, close.reason_phrase),
            .state = close.state,
            .started_ms = close.now_ms,
            .expires_ms = expires_ms,
        };
    }

    fn enterStatelessResetDraining(self: *Connection, now_ms: ?u64, pto_ms: ?u64) Error!void {
        if (self.close_info) |*close_info| {
            close_info.state = .draining;
            close_info.started_ms = now_ms;
            close_info.expires_ms = closeExpiryMillis(now_ms, pto_ms);
            return;
        }
        try self.setCloseInfo(.{
            .application = false,
            .error_code = 0,
            .frame_type = 0,
            .reason_phrase = "stateless reset",
            .state = .draining,
            .now_ms = now_ms,
            .pto_ms = pto_ms,
        });
    }

    fn applyPersistentCongestionIfDetected(self: *Connection) bool {
        const period = self.persistentCongestionPeriod() orelse return false;
        self.congestion.onPersistentCongestion();
        self.rtt_stats.onPersistentCongestion();
        self.last_persistent_congestion_packet_number = period.end_packet_number;
        return true;
    }

    fn applyAckWithEcnFailure(self: *Connection, ack: quic.AckFrame) Error!quic.packet_space.SentPacketTracker.AckResult {
        if (ack.ecn_counts == null or !self.sent.validateAckEcnFrameWouldFail(ack)) return error.InvalidAckFrame;
        var plain_ack = ack;
        plain_ack.ecn_counts = null;
        const result = try self.sent.applyAckDetailed(plain_ack);
        self.sent.disableEcnValidation();
        return result;
    }

    pub fn consumeReceived(self: *Connection, amount: u64) ?quic.Frame {
        if (self.recv_flow.consume(amount)) |_| return self.recv_flow.maxDataFrame();
        return null;
    }

    pub fn consumeStreamReceived(self: *Connection, stream_id: u64, amount: u64) Error!?quic.Frame {
        var recv_stream = try self.recvStreamFlow(stream_id);
        if (recv_stream.flow.consume(amount)) |_| return recv_stream.flow.maxStreamDataFrame(stream_id);
        return null;
    }

    fn sendStreamFlow(self: *Connection, stream_id: u64) Error!*quic.flow_control.SendFlow {
        const entry = try self.sendStreamEntry(stream_id);
        return &entry.flow;
    }

    fn sendStreamEntry(self: *Connection, stream_id: u64) Error!*StreamFlowEntry {
        if (self.findSendStreamEntry(stream_id)) |entry| return entry;
        if (streamInitiatedByLocal(self.config.local_endpoint, stream_id)) {
            try self.validateLocalStreamCount(stream_id);
        }
        try self.stream_send_flows.append(self.endpoint.allocator, .{
            .stream_id = stream_id,
            .flow = .init(self.initialSendStreamDataLimit(stream_id)),
        });
        return &self.stream_send_flows.items[self.stream_send_flows.items.len - 1];
    }

    fn validateLocalStreamCount(self: *Connection, stream_id: u64) Error!void {
        const count = streamCountForId(stream_id);
        if (streamDirection(stream_id) == .bidirectional) {
            if (count <= self.peer_max_streams_bidi) return;
            try self.sendStreamsBlocked(.bidirectional);
            return error.StreamLimitExceeded;
        }
        if (count <= self.peer_max_streams_uni) return;
        try self.sendStreamsBlocked(.unidirectional);
        return error.StreamLimitExceeded;
    }

    fn sendStreamsBlocked(self: *Connection, direction: enum { bidirectional, unidirectional }) Error!void {
        const frame = switch (direction) {
            .bidirectional => quic.Frame{ .streams_blocked_bidi = .{ .maximum_streams = self.peer_max_streams_bidi } },
            .unidirectional => quic.Frame{ .streams_blocked_uni = .{ .maximum_streams = self.peer_max_streams_uni } },
        };
        try self.sendTrackedFrames(&[_]quic.Frame{frame});
    }

    fn findSendStreamEntry(self: *Connection, stream_id: u64) ?*StreamFlowEntry {
        for (self.stream_send_flows.items) |*entry| {
            if (entry.stream_id == stream_id) return entry;
        }
        return null;
    }

    fn recvStreamFlow(self: *Connection, stream_id: u64) Error!*StreamRecvFlowEntry {
        if (self.findRecvStreamEntry(stream_id)) |entry| return entry;
        try self.validateStreamReceiveFrameId(stream_id);
        try self.validatePeerStreamCount(stream_id);
        try self.stream_recv_flows.append(self.endpoint.allocator, .{
            .stream_id = stream_id,
            .flow = try .init(self.initialReceiveStreamDataLimit(stream_id), self.config.stream_receive_window),
            .recv_state = quic.stream_state.RecvState.init(
                self.endpoint.allocator,
                stream_id,
                maxBufferedForLimit(self.initialReceiveStreamDataLimit(stream_id)),
            ),
        });
        return &self.stream_recv_flows.items[self.stream_recv_flows.items.len - 1];
    }

    fn findRecvStreamEntry(self: *Connection, stream_id: u64) ?*StreamRecvFlowEntry {
        for (self.stream_recv_flows.items) |*entry| {
            if (entry.stream_id == stream_id) return entry;
        }
        return null;
    }

    fn validateStreamReceiveFrameId(self: *Connection, stream_id: u64) Error!void {
        if (!streamHasReceiveSide(self.config.local_endpoint, stream_id)) return error.StreamStateError;
        if (streamInitiatedByLocal(self.config.local_endpoint, stream_id)) {
            // STREAM/RESET/STREAM_DATA_BLOCKED on a locally initiated
            // bidirectional stream is valid only after the local endpoint has
            // opened that stream.  This matches the state checks in quicz/tquic
            // and prevents a peer from creating local stream IDs on our behalf.
            if (self.findSendStreamEntry(stream_id) == null) return error.StreamStateError;
            return;
        }
        try self.validatePeerStreamCount(stream_id);
    }

    fn validateStreamSendControlId(self: *Connection, stream_id: u64) Error!void {
        if (!streamHasSendSide(self.config.local_endpoint, stream_id)) return error.StreamStateError;
        if (streamInitiatedByLocal(self.config.local_endpoint, stream_id)) {
            if (self.findSendStreamEntry(stream_id) == null) return error.StreamStateError;
            return;
        }
        try self.validatePeerStreamCount(stream_id);
    }

    fn validatePeerStreamCount(self: Connection, stream_id: u64) Error!void {
        if (streamInitiatedByLocal(self.config.local_endpoint, stream_id)) return;
        const count = streamCountForId(stream_id);
        if (streamDirection(stream_id) == .bidirectional) {
            if (count > self.recv_max_streams_bidi) return error.StreamLimitExceeded;
            return;
        }
        if (count > self.recv_max_streams_uni) return error.StreamLimitExceeded;
    }

    fn initialSendStreamDataLimit(self: Connection, stream_id: u64) u64 {
        if (streamDirection(stream_id) == .unidirectional) {
            if (!streamInitiatedByLocal(self.config.local_endpoint, stream_id)) return 0;
            return self.config.initial_send_max_stream_data_uni orelse self.config.initial_send_max_stream_data;
        }
        if (streamInitiatedByLocal(self.config.local_endpoint, stream_id)) {
            return self.config.initial_send_max_stream_data_bidi_remote orelse self.config.initial_send_max_stream_data;
        }
        return self.config.initial_send_max_stream_data_bidi_local orelse self.config.initial_send_max_stream_data;
    }

    fn initialReceiveStreamDataLimit(self: Connection, stream_id: u64) u64 {
        if (streamDirection(stream_id) == .unidirectional) {
            if (streamInitiatedByLocal(self.config.local_endpoint, stream_id)) return 0;
            return self.config.initial_receive_max_stream_data_uni orelse self.config.initial_receive_max_stream_data;
        }
        if (streamInitiatedByLocal(self.config.local_endpoint, stream_id)) {
            return self.config.initial_receive_max_stream_data_bidi_local orelse self.config.initial_receive_max_stream_data;
        }
        return self.config.initial_receive_max_stream_data_bidi_remote orelse self.config.initial_receive_max_stream_data;
    }
};

fn streamInitiatedByLocal(local_endpoint: ConnectionConfig.EndpointRole, stream_id: u64) bool {
    const client_initiated = (stream_id & 0x01) == 0;
    return switch (local_endpoint) {
        .client => client_initiated,
        .server => !client_initiated,
    };
}

fn streamHasSendSide(local_endpoint: ConnectionConfig.EndpointRole, stream_id: u64) bool {
    return streamDirection(stream_id) == .bidirectional or streamInitiatedByLocal(local_endpoint, stream_id);
}

fn streamHasReceiveSide(local_endpoint: ConnectionConfig.EndpointRole, stream_id: u64) bool {
    return streamDirection(stream_id) == .bidirectional or !streamInitiatedByLocal(local_endpoint, stream_id);
}

fn streamDirection(stream_id: u64) enum { bidirectional, unidirectional } {
    return if ((stream_id & 0x02) == 0) .bidirectional else .unidirectional;
}

fn streamCountForId(stream_id: u64) u64 {
    return (stream_id >> 2) + 1;
}

fn maxBufferedForLimit(limit: u64) usize {
    return std.math.cast(usize, limit) orelse std.math.maxInt(usize);
}

fn allZero(comptime T: type, values: []const T) bool {
    for (values) |value| {
        if (value != 0) return false;
    }
    return true;
}

fn closeExpiryMillis(now_ms: ?u64, pto_ms: ?u64) ?u64 {
    const now = now_ms orelse return null;
    const pto = pto_ms orelse return null;
    const duration = std.math.mul(u64, pto, 3) catch return std.math.maxInt(u64);
    return std.math.add(u64, now, duration) catch std.math.maxInt(u64);
}

pub fn sendFrames(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    options: SendOptions,
) Error!void {
    const payload = try encodeFrames(endpoint.allocator, options.frames);
    defer endpoint.allocator.free(payload);
    try sendPayload(endpoint, to, keys, .{
        .destination_connection_id = options.destination_connection_id,
        .packet_number = options.packet_number,
        .packet_number_len = options.packet_number_len,
        .spin_bit = options.spin_bit,
        .key_phase = options.key_phase,
        .payload = payload,
    });
}

pub fn sendZeroRttFrames(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    options: ZeroRttSendOptions,
) Error!void {
    for (options.frames) |frame| try quic.validateFrameForPacketType(frame, .zero_rtt);
    const payload = try encodeFrames(endpoint.allocator, options.frames);
    defer endpoint.allocator.free(payload);
    const packet = try quic.protection.sealZeroRttPacket(endpoint.allocator, keys, .{
        .version = options.version,
        .destination_connection_id = options.destination_connection_id,
        .source_connection_id = options.source_connection_id,
        .packet_number = options.packet_number,
        .packet_number_len = options.packet_number_len,
        .payload = payload,
    });
    defer endpoint.allocator.free(packet);
    try endpoint.sendBytes(to, packet);
}

pub fn encodeFrames(allocator: std.mem.Allocator, frames: []const quic.Frame) Error![]u8 {
    var payload: std.ArrayList(u8) = .empty;
    errdefer payload.deinit(allocator);
    for (frames) |frame| try frame.write(&payload, allocator);
    return payload.toOwnedSlice(allocator);
}

fn sendPayload(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    options: PayloadSendOptions,
) Error!void {
    const packet = try quic.protection.sealShortPacket(endpoint.allocator, keys, .{
        .destination_connection_id = options.destination_connection_id,
        .packet_number = options.packet_number,
        .packet_number_len = options.packet_number_len,
        .spin_bit = options.spin_bit,
        .key_phase = options.key_phase,
        .payload = options.payload,
    });
    defer endpoint.allocator.free(packet);
    try endpoint.sendBytes(to, packet);
}

fn ackEliciting(frames: []const quic.Frame) bool {
    for (frames) |frame| {
        switch (frame) {
            .ack, .padding => {},
            else => return true,
        }
    }
    return false;
}

fn countStreamBytes(frames: []const quic.Frame) u64 {
    var total: u64 = 0;
    for (frames) |frame| {
        if (frame == .stream) total += frame.stream.data.len;
    }
    return total;
}

fn datagramFrameWireSize(datagram: quic.DatagramFrame) ?usize {
    const type_len = quic.varint.length(if (datagram.length_present) @intFromEnum(quic.FrameType.datagram_len) else @intFromEnum(quic.FrameType.datagram)) catch return null;
    var total = std.math.add(usize, type_len, datagram.data.len) catch return null;
    if (datagram.length_present) {
        const len_len = quic.varint.length(datagram.data.len) catch return null;
        total = std.math.add(usize, total, len_len) catch return null;
    }
    return total;
}

fn maxDatagramPayloadForFrameSize(frame_size: usize) ?usize {
    const type_len = quic.varint.length(@intFromEnum(quic.FrameType.datagram_len)) catch return null;
    if (frame_size <= type_len) return null;
    var len_len: usize = 1;
    while (true) {
        if (frame_size <= type_len + len_len) return null;
        const candidate = frame_size - type_len - len_len;
        const candidate_len = quic.varint.length(candidate) catch return null;
        if (candidate_len == len_len) return candidate;
        len_len = candidate_len;
    }
}

pub fn receiveZeroRtt(
    endpoint: *quic.runtime.Endpoint,
    keys: quic.protection.PacketProtectionKeys,
    expected_packet_number: u64,
    max_frames: usize,
) Error!ReceivedZeroRttPacket {
    var datagram = try endpoint.receiveBytes();
    defer datagram.deinit(endpoint.allocator);
    return openZeroRttBytes(endpoint, datagram.from, datagram.bytes, keys, expected_packet_number, max_frames);
}

pub fn openZeroRttBytes(
    endpoint: *quic.runtime.Endpoint,
    from: net.IpAddress,
    bytes: []const u8,
    keys: quic.protection.PacketProtectionKeys,
    expected_packet_number: u64,
    max_frames: usize,
) Error!ReceivedZeroRttPacket {
    var packet = try quic.protection.openZeroRttPacket(endpoint.allocator, keys, bytes, expected_packet_number);
    errdefer packet.deinit(endpoint.allocator);
    const frames = try parsePacketFramesForType(endpoint, packet.payload, max_frames, .zero_rtt);
    return .{
        .from = from,
        .packet = packet,
        .frames = frames,
    };
}

pub fn receive(
    endpoint: *quic.runtime.Endpoint,
    keys: quic.protection.PacketProtectionKeys,
    destination_connection_id_len: usize,
    expected_packet_number: u64,
    max_frames: usize,
) Error!ReceivedPacket {
    var datagram = try endpoint.receiveBytes();
    defer datagram.deinit(endpoint.allocator);
    return openReceivedBytes(endpoint, datagram.from, datagram.bytes, keys, destination_connection_id_len, expected_packet_number, max_frames);
}

pub fn receiveWithKeyUpdate(
    endpoint: *quic.runtime.Endpoint,
    keys: quic.protection.ShortPacketKeyUpdateKeys,
    destination_connection_id_len: usize,
    expected_packet_number: u64,
    max_frames: usize,
) Error!ReceivedPacket {
    var datagram = try endpoint.receiveBytes();
    defer datagram.deinit(endpoint.allocator);
    return openReceivedBytesWithKeyUpdate(endpoint, datagram.from, datagram.bytes, keys, destination_connection_id_len, expected_packet_number, max_frames);
}

pub fn openReceivedBytes(
    endpoint: *quic.runtime.Endpoint,
    from: net.IpAddress,
    bytes: []const u8,
    keys: quic.protection.PacketProtectionKeys,
    destination_connection_id_len: usize,
    expected_packet_number: u64,
    max_frames: usize,
) Error!ReceivedPacket {
    var packet = try quic.protection.openShortPacket(endpoint.allocator, keys, bytes, destination_connection_id_len, expected_packet_number);
    errdefer packet.deinit(endpoint.allocator);
    const frames = try parsePacketFramesForType(endpoint, packet.payload, max_frames, .one_rtt);
    return .{
        .from = from,
        .packet = packet,
        .frames = frames,
    };
}

pub fn openReceivedBytesWithKeyUpdate(
    endpoint: *quic.runtime.Endpoint,
    from: net.IpAddress,
    bytes: []const u8,
    keys: quic.protection.ShortPacketKeyUpdateKeys,
    destination_connection_id_len: usize,
    expected_packet_number: u64,
    max_frames: usize,
) Error!ReceivedPacket {
    var decoded = try quic.protection.openShortPacketWithKeyUpdate(endpoint.allocator, keys, bytes, destination_connection_id_len, expected_packet_number);
    errdefer decoded.deinit(endpoint.allocator);
    const frames = try parsePacketFramesForType(endpoint, decoded.packet.payload, max_frames, .one_rtt);
    return .{
        .from = from,
        .packet = decoded.packet,
        .frames = frames,
        .peer_initiated_key_update = decoded.peer_initiated_key_update,
    };
}

fn parsePacketFramesForType(
    endpoint: *quic.runtime.Endpoint,
    payload: []const u8,
    max_frames: usize,
    packet_type: quic.FramePacketType,
) Error![]quic.Frame {
    var frames: std.ArrayList(quic.Frame) = .empty;
    errdefer {
        quic.deinitOwnedFrameSlice(frames.items, endpoint.allocator);
        frames.deinit(endpoint.allocator);
    }

    var pos: usize = 0;
    while (pos < payload.len) {
        if (frames.items.len >= max_frames) return error.MissingFrame;
        var parsed = try quic.parseFrameOwned(endpoint.allocator, payload[pos..]);
        var appended = false;
        defer if (!appended) parsed.deinitOwned(endpoint.allocator);
        try quic.validateFrameForPacketType(parsed.frame, packet_type);
        try frames.append(endpoint.allocator, parsed.frame);
        appended = true;
        pos += parsed.consumed;
    }
    if (frames.items.len == 0) return error.MissingFrame;
    return frames.toOwnedSlice(endpoint.allocator);
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
    try sendFrames(&client.endpoint, server.address(), client_keys, .{
        .destination_connection_id = &server_dcid,
        .packet_number = 0,
        .frames = &request_frames,
    });

    var request = try receive(&server.endpoint, client_keys, server_dcid.len, 0, 8);
    defer request.deinit(allocator);
    try std.testing.expect(request.from.eql(&client.address()));
    try std.testing.expectEqualSlices(u8, &server_dcid, request.packet.destination_connection_id);
    try std.testing.expectEqualStrings("GET /", request.frames[0].stream.data);

    const response_frames = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "OK", .fin = true } }};
    try sendFrames(&server.endpoint, request.from, server_keys, .{
        .destination_connection_id = &client_dcid,
        .packet_number = 0,
        .frames = &response_frames,
    });

    var response = try receive(&client.endpoint, server_keys, client_dcid.len, 0, 8);
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

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_endpoint = .client,
        .enable_spin_bit = true,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .enable_spin_bit = true,
    });
    defer server.deinit();

    try sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
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

    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
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

test "QUIC 0-RTT long-header frame exchange enforces packet context" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try quic.runtime.Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server.deinit();
    var client = try quic.runtime.Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{ .max_datagram_size = 4096 });
    defer client.deinit();

    const dcid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3 };
    const scid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x8a} ** quic.protection.secret_len);

    try sendZeroRttFrames(&client.endpoint, server.address(), keys, .{
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "early", .fin = false } }},
    });

    var received = try receiveZeroRtt(&server.endpoint, keys, 0, 8);
    defer received.deinit(allocator);
    try std.testing.expect(received.from.eql(&client.address()));
    try std.testing.expectEqual(@as(u64, 0), received.packet.packet_number);
    try std.testing.expectEqualSlices(u8, &dcid, received.packet.destination_connection_id);
    try std.testing.expectEqualSlices(u8, &scid, received.packet.source_connection_id);
    try std.testing.expectEqualStrings("early", received.frames[0].stream.data);

    try std.testing.expectError(error.InvalidFrame, sendZeroRttFrames(&client.endpoint, server.address(), keys, .{
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 1,
        .frames = &[_]quic.Frame{.{ .ack = .{ .largest_acknowledged = 0, .ack_delay = 0, .first_ack_range = 0 } }},
    }));

    const invalid_payload = try encodeFrames(allocator, &[_]quic.Frame{.{ .crypto = .{ .offset = 0, .data = "forbidden" } }});
    defer allocator.free(invalid_payload);
    const invalid_packet = try quic.protection.sealZeroRttPacket(allocator, keys, .{
        .destination_connection_id = &dcid,
        .source_connection_id = &scid,
        .packet_number = 1,
        .payload = invalid_payload,
    });
    defer allocator.free(invalid_packet);
    try std.testing.expectError(error.InvalidFrame, openZeroRttBytes(&server.endpoint, client.address(), invalid_packet, keys, 1, 8));
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

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
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

    var server = try Connection.init(&server_endpoint, .{
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

    try sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .stream = .{ .stream_id = 0, .offset = 0, .data = "abcdef", .fin = false } }},
    });
    var first = try server.receivePacket();
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 6), server.recv_data_total);
    try std.testing.expectEqual(@as(u64, 6), server.stream_recv_flows.items[0].recv_state.receivedByteCount());

    try sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 1,
        .frames = &[_]quic.Frame{.{ .stream = .{ .stream_id = 0, .offset = 3, .data = "defgh", .fin = false } }},
    });
    var overlap = try server.receivePacket();
    defer overlap.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 8), server.recv_data_total);
    try std.testing.expectEqual(@as(u64, 8), server.stream_recv_flows.items[0].recv_state.receivedByteCount());

    try sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 2,
        .frames = &[_]quic.Frame{.{ .stream = .{ .stream_id = 0, .offset = 4, .data = "ZZ", .fin = false } }},
    });
    try std.testing.expectError(error.ConflictingStreamData, server.receivePacket());
    try std.testing.expectEqual(@as(u64, 8), server.recv_data_total);
    try std.testing.expectEqual(@as(usize, 1), server.received.ranges.items.len);
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

    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    const frames = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "once", .fin = false } }};
    try sendFrames(&client_endpoint, server_endpoint.address(), client_keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .frames = &frames,
    });
    try sendFrames(&client_endpoint, server_endpoint.address(), client_keys, .{
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

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_endpoint = .client,
    });
    defer client.deinit();

    try sendFrames(&server_endpoint, client_endpoint.address(), server_keys, .{
        .destination_connection_id = &client_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{
            .{ .stream = .{ .stream_id = 1, .data = "poison", .fin = false } },
            .{ .ack = .{
                .largest_acknowledged = 0,
                .ack_delay = 0,
                .first_ack_range = 0,
            } },
        },
    });

    try std.testing.expectError(error.InvalidAckFrame, client.receivePacket());
    try std.testing.expectEqual(@as(u64, 0), client.recv_data_total);
    try std.testing.expectEqual(@as(usize, 0), client.stream_recv_flows.items.len);
    try std.testing.expectEqual(@as(usize, 0), client.received.ranges.items.len);
    try std.testing.expectEqual(@as(u64, 0), client.expected_packet_number);
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

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_endpoint = .client,
        .initial_receive_max_streams_bidi = 1,
    });
    defer client.deinit();

    try sendFrames(&server_endpoint, client_endpoint.address(), keys, .{
        .destination_connection_id = &client_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{
            .{ .stream = .{ .stream_id = 1, .data = "first", .fin = false } },
            .{ .stream = .{ .stream_id = 5, .data = "over-limit", .fin = false } },
        },
    });

    try std.testing.expectError(error.StreamLimitExceeded, client.receivePacket());
    try std.testing.expectEqual(@as(u64, 0), client.recv_data_total);
    try std.testing.expectEqual(@as(usize, 0), client.stream_recv_flows.items.len);
    try std.testing.expectEqual(@as(usize, 0), client.received.ranges.items.len);
    try std.testing.expectEqual(@as(u64, 0), client.expected_packet_number);
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

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_endpoint = .client,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try sendFrames(&server_endpoint, client_endpoint.address(), keys, .{
        .destination_connection_id = &client_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{
            .{ .stream = .{ .stream_id = 1, .data = "before-max-stream-error", .fin = false } },
            // Server-initiated unidirectional stream 3 is receive-only for the
            // client, so MAX_STREAM_DATA/STOP_SENDING are stream-state errors.
            .{ .max_stream_data = .{ .stream_id = 3, .maximum_stream_data = 64 } },
        },
    });
    try std.testing.expectError(error.StreamStateError, client.receivePacket());
    try std.testing.expectEqual(@as(u64, 0), client.recv_data_total);
    try std.testing.expectEqual(@as(usize, 0), client.stream_recv_flows.items.len);
    try std.testing.expectEqual(@as(usize, 0), client.received.ranges.items.len);

    try sendFrames(&server_endpoint, client_endpoint.address(), keys, .{
        .destination_connection_id = &client_cid,
        .packet_number = 1,
        .frames = &[_]quic.Frame{
            .{ .stream = .{ .stream_id = 1, .data = "before-stop-error", .fin = false } },
            .{ .stop_sending = .{ .stream_id = 3, .application_error_code = 7 } },
        },
    });
    try std.testing.expectError(error.StreamStateError, client.receivePacket());
    try std.testing.expectEqual(@as(u64, 0), client.recv_data_total);
    try std.testing.expectEqual(@as(usize, 0), client.stream_recv_flows.items.len);
    try std.testing.expectEqual(@as(usize, 0), client.received.ranges.items.len);

    try sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{
            .{ .stream = .{ .stream_id = 0, .data = "before-blocked-error", .fin = false } },
            // Server-initiated unidirectional stream 3 is send-only for the
            // server, so STREAM_DATA_BLOCKED is invalid on its receive side.
            .{ .stream_data_blocked = .{ .stream_id = 3, .maximum_stream_data = 64 } },
        },
    });
    try std.testing.expectError(error.StreamStateError, server.receivePacket());
    try std.testing.expectEqual(@as(u64, 0), server.recv_data_total);
    try std.testing.expectEqual(@as(usize, 0), server.stream_recv_flows.items.len);
    try std.testing.expectEqual(@as(usize, 0), server.received.ranges.items.len);
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

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_endpoint = .client,
    });
    defer client.deinit();

    try sendFrames(&server_endpoint, client_endpoint.address(), keys, .{
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

test "QUIC 1-RTT connection preflights role and path control frames before receive-side effects" {
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

    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
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

    try sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{
            .{ .stream = .{ .stream_id = 0, .data = "before-path-error", .fin = false } },
            .{ .path_response = .{ .data = [_]u8{0xaa} ** 8 } },
        },
    });

    try std.testing.expectError(error.UnknownPathResponse, server.receivePacket());
    try std.testing.expectEqual(@as(u64, 0), server.recv_data_total);
    try std.testing.expectEqual(@as(usize, 0), server.stream_recv_flows.items.len);
    try std.testing.expectEqual(@as(usize, 0), server.received.ranges.items.len);
    try std.testing.expectEqual(@as(u64, 0), server.expected_packet_number);
    try std.testing.expectEqual(@as(usize, 0), server.path_validation.outstandingChallengeCount());
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

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .peer_ack_delay_exponent = 3,
    });
    defer client.deinit();

    try client.sent.sentAt(0, true, 1200, .not_ect, 1_000_000);
    try sendFrames(&server_endpoint, client_endpoint.address(), keys, .{
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
    var connection = try Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
        .peer_ack_delay_exponent = 3,
        .peer_max_ack_delay_ms = 10,
    });
    defer connection.deinit();

    try connection.sent.sentAt(0, true, 1200, .not_ect, 1_000_000);
    const ack = quic.AckFrame{ .largest_acknowledged = 0, .ack_delay = 5, .first_ack_range = 0 };
    try std.testing.expect(try connection.updateRttFromAck(ack, 101_000_000));
    try std.testing.expect(connection.rtt_stats.has_measurement);
    try std.testing.expectEqual(@as(u64, 100_000_000), connection.rtt_stats.latest_rtt);
    try std.testing.expectEqual(@as(u64, 10_000_000), connection.rtt_stats.max_ack_delay);
    const acked = try connection.sent.applyAckDetailed(ack);
    connection.congestion.onAcked(acked.bytes);
    try std.testing.expect(!(try connection.updateRttFromAck(ack, 102_000_000)));
    try std.testing.expectEqual(@as(u64, 100_000_000), connection.rtt_stats.latest_rtt);

    connection.handshake_confirmed = true;
    try connection.sent.sentAt(1, true, 1200, .not_ect, 201_000_000);
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
    var connection = try Connection.init(&endpoint, .{
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
    var connection = try Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
    });
    defer connection.deinit();

    try connection.closeTransport(42, @intFromEnum(quic.FrameType.stream), "closing");
    try std.testing.expect(connection.closing());
    const before = connection.next_packet_number;
    try connection.resendClose();
    try std.testing.expectEqual(before + 1, connection.next_packet_number);

    try connection.applyReceivedFrames(0, &.{.{ .connection_close = .{
        .error_code = 0,
        .frame_type = 0,
        .reason_phrase = "peer-close",
    } }}, null, .not_ect);
    try std.testing.expect(connection.draining());
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
    var connection = try Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
    });
    defer connection.deinit();

    try connection.applyReceivedFrames(0, &.{.{ .connection_close = .{
        .error_code = 0,
        .frame_type = 0,
        .reason_phrase = "bye",
    } }}, null, .not_ect);
    try std.testing.expect(connection.draining());
    try std.testing.expectError(error.ConnectionClosed, connection.receivePacket());
    try std.testing.expect((try connection.receivePacketOrDropAfterClose()) == null);
}

test "QUIC 1-RTT connection models idle timeout deadlines" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0x77} ** quic.protection.secret_len);
    var connection = try Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
        .local_max_idle_timeout_ms = 100,
        .peer_max_idle_timeout_ms = 250,
    });
    defer connection.deinit();

    try std.testing.expectEqual(@as(?u64, 100), connection.effectiveIdleTimeoutMillis());
    try std.testing.expectEqual(@as(?u64, null), connection.idleTimeoutDeadlineMillis());
    connection.markActivity(10);
    try std.testing.expectEqual(@as(?u64, 110), connection.idleTimeoutDeadlineMillis());
    try std.testing.expect(!connection.checkIdleTimeout(109));
    try std.testing.expect(!connection.closed());
    try std.testing.expect(connection.checkIdleTimeout(110));
    try std.testing.expect(connection.closed());
    try std.testing.expectError(error.ConnectionClosed, connection.send(&[_]quic.Frame{.{ .ping = {} }}));
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

    var client = try Connection.init(&client_endpoint, .{
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

    try sendFrames(&server_endpoint, client_endpoint.address(), server_keys, .{
        .destination_connection_id = &client_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .ack = .{
            .largest_acknowledged = 1,
            .ack_delay = 0,
            .first_ack_range = 0,
        } }},
    });

    try std.testing.expectError(error.InvalidAckFrame, client.receivePacket());
    try std.testing.expectEqual(@as(usize, 1), client.sent.packets.items.len);
    try std.testing.expect(!client.sent.packets.items[0].acknowledged);
    try std.testing.expectEqual(@as(usize, 1), client.pendingRecoveryCount());
    try std.testing.expectEqual(in_flight, client.congestion.bytes_in_flight);
    try std.testing.expectEqual(@as(?u64, null), client.sent.largestAcknowledged());
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

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
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
        var packet = try server.receiveRoutedDatagramWithEcnAt(routed, null, mark);
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

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();

    try client.sendWithEcn(&[_]quic.Frame{.{ .ping = {} }}, .ect0);
    try sendFrames(&server_endpoint, client_endpoint.address(), server_keys, .{
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

    try client.sendWithEcn(&[_]quic.Frame{.{ .ping = {} }}, .ect1);
    const bytes_in_flight = client.congestion.bytes_in_flight;
    try sendFrames(&server_endpoint, client_endpoint.address(), server_keys, .{
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
    try std.testing.expect(client.sent.ecnDisabled());
    try std.testing.expectError(error.EcnDisabled, client.sendWithEcn(&[_]quic.Frame{.{ .ping = {} }}, .ect0));
    try client.send(&[_]quic.Frame{.{ .ping = {} }});
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

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();

    try client.sendWithEcnAt(&[_]quic.Frame{.{ .ping = {} }}, .ect0, 100);
    const initial_window = client.congestion.congestion_window;
    try sendFrames(&server_endpoint, client_endpoint.address(), server_keys, .{
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

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();

    try client.sendWithEcnAt(&[_]quic.Frame{.{ .ping = {} }}, .ect0, 100); // packet 0
    try client.sendWithEcnAt(&[_]quic.Frame{.{ .ping = {} }}, .ect0, 200); // packet 1

    try sendFrames(&server_endpoint, client_endpoint.address(), server_keys, .{
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

    try sendFrames(&server_endpoint, client_endpoint.address(), server_keys, .{
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

test "QUIC 1-RTT connection performs key update and clears ACK gate" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
    const server_cid = [_]u8{ 0x45, 0x46, 0x47, 0x48 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0x57} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0x58} ** quic.protection.secret_len);

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try client.initiateKeyUpdate();
    try std.testing.expect(client.localOneRttKeyPhase());
    try std.testing.expectEqual(@as(u64, 1), client.localOneRttKeyUpdateCount());
    try std.testing.expectEqual(@as(?u64, 0), client.pendingOneRttKeyUpdateAckThreshold());
    try std.testing.expectError(error.InvalidPacket, client.initiateKeyUpdate());

    const frames = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "updated", .fin = true } }};
    try client.send(&frames);

    var updated = try server.receivePacket();
    defer updated.deinit(allocator);
    try std.testing.expect(updated.peer_initiated_key_update);
    try std.testing.expect(updated.packet.key_phase);
    try std.testing.expect(server.peerOneRttKeyPhase());
    try std.testing.expectEqual(@as(u64, 1), server.peerOneRttKeyUpdateCount());
    try std.testing.expectEqualStrings("updated", updated.frames[0].stream.data);

    try server.sendAck(0);
    var ack = try client.receivePacket();
    defer ack.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), ack.frames[0].ack.largest_acknowledged);
    try std.testing.expectEqual(@as(?u64, null), client.pendingOneRttKeyUpdateAckThreshold());

    try client.initiateKeyUpdate();
    try std.testing.expect(!client.localOneRttKeyPhase());
    try std.testing.expectEqual(@as(u64, 2), client.localOneRttKeyUpdateCount());
}

test "QUIC 1-RTT connection accepts delayed previous-key packets until discard" {
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
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0x5a} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0x5b} ** quic.protection.secret_len);
    const next_client_keys = quic.protection.nextAes128PacketProtectionKeys(client_keys);

    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    const old_payload = try encodeFrames(allocator, &[_]quic.Frame{.{ .ping = {} }});
    defer allocator.free(old_payload);
    const old_packet = try quic.protection.sealShortPacket(allocator, client_keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .packet_number_len = 4,
        .key_phase = false,
        .payload = old_payload,
    });
    defer allocator.free(old_packet);

    const updated_payload = try encodeFrames(allocator, &[_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .offset = 1,
        .data = "new",
        .fin = false,
    } }});
    defer allocator.free(updated_payload);
    const updated_packet = try quic.protection.sealShortPacket(allocator, next_client_keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 1,
        .packet_number_len = 4,
        .key_phase = true,
        .payload = updated_payload,
    });
    defer allocator.free(updated_packet);

    const route = quic.connection_router.Route{ .connection_index = 0 };
    var updated = try server.receiveRoutedDatagram(.{
        .datagram = .{ .from = client_endpoint.address(), .bytes = updated_packet },
        .route = route,
        .destination_connection_id = &server_cid,
    });
    defer updated.deinit(allocator);
    try std.testing.expect(updated.peer_initiated_key_update);
    try std.testing.expect(server.peerOneRttKeyPhase());
    try std.testing.expectEqual(@as(u64, 1), server.peerOneRttKeyUpdateCount());
    try std.testing.expect(server.peerOneRttRetainsKeyGeneration(0));

    var delayed_old = try server.receiveRoutedDatagram(.{
        .datagram = .{ .from = client_endpoint.address(), .bytes = old_packet },
        .route = route,
        .destination_connection_id = &server_cid,
    });
    defer delayed_old.deinit(allocator);
    try std.testing.expect(!delayed_old.peer_initiated_key_update);
    try std.testing.expect(!delayed_old.packet.key_phase);
    try std.testing.expect(server.peerOneRttKeyPhase());

    server.schedulePreviousOneRttKeyDiscard(10);
    try std.testing.expectEqual(@as(?i64, 10), server.oneRttKeyDiscardDeadline());
    try std.testing.expect(server.discardExpiredOneRttKeys(10));
    try std.testing.expect(!server.peerOneRttRetainsKeyGeneration(0));
    try std.testing.expectError(error.KeyUpdateError, server.receiveRoutedDatagram(.{
        .datagram = .{ .from = client_endpoint.address(), .bytes = old_packet },
        .route = route,
        .destination_connection_id = &server_cid,
    }));
}

test "QUIC 1-RTT connection sends and validates PMTU probes" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0xba, 0xbb, 0xbc, 0xbd };
    const server_cid = [_]u8{ 0xbe, 0xbf, 0xc0, 0xc1 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xba} ** quic.protection.secret_len);

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .enable_pmtud = true,
        .pmtud_max_probe_size = 1300,
        .max_datagram_size = 1400,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .max_datagram_size = 1400,
    });
    defer server.deinit();

    try std.testing.expect(client.pmtudShouldProbe());
    const probe_size = (try client.sendPmtuProbeAt(1300, 10)).?;
    try std.testing.expectEqual(@as(usize, 1300), probe_size);
    try std.testing.expect(!client.pmtudShouldProbe());

    var raw = try server_endpoint.receiveBytes();
    defer raw.deinit(allocator);
    try std.testing.expectEqual(probe_size, raw.bytes.len);
    var received = try openReceivedBytes(
        &server_endpoint,
        raw.from,
        raw.bytes,
        keys,
        server.config.local_connection_id.len,
        server.expected_packet_number,
        server.config.max_frames_per_packet,
    );
    defer received.deinit(allocator);
    try server.applyReceivedFrames(received.packet.packet_number, received.frames, null, .not_ect);
    try std.testing.expectEqual(@as(u64, 0), received.packet.packet_number);
    try std.testing.expectEqual(@as(usize, 1300), client.sent.packets.items[0].pmtu_probe_size.?);

    const ack_frame = try server.received.ackFrame(allocator, 0);
    defer allocator.free(ack_frame.ranges);
    const ack_frames = [_]quic.Frame{.{ .ack = ack_frame }};
    try client.applyReceivedFrames(99, &ack_frames, null, .not_ect);
    try std.testing.expectEqual(@as(usize, 1300), client.pmtudCurrentSize());
}

test "QUIC 1-RTT PMTU probe loss lowers next probe size" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0xbb} ** quic.protection.secret_len);
    var connection = try Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "pmtu-local",
        .peer_connection_id = "pmtu-peer",
        .enable_pmtud = true,
        .pmtud_max_probe_size = 1400,
        .max_datagram_size = 1500,
    });
    defer connection.deinit();
    connection.pmtud.max_probe_failures = 2;

    const probe_size = (try connection.sendPmtuProbeAt(1400, 100)).?;
    connection.sent.packets.items[0].lost = false;
    const lost1 = connection.sent.detectTimeThresholdLoss(1_000, 1, 0);
    if (lost1.largest_pmtu_probe_size) |size| connection.pmtud.onProbeLost(size, connection.config.max_datagram_size);
    try std.testing.expect(connection.pmtudShouldProbe());
    try std.testing.expectEqual(probe_size, connection.pmtud.probeSize(1400).?);

    connection.pmtud.onProbeSent(probe_size);
    connection.pmtud.onProbeLost(probe_size, 1400);
    try std.testing.expect(connection.pmtudShouldProbe());
    const next = connection.pmtud.probeSize(1400).?;
    try std.testing.expect(next < probe_size);
    try std.testing.expect(next > quic.pmtu.min_udp_payload_size);
}

test "QUIC 1-RTT connection enforces anti-amplification budget" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x9a, 0x9b, 0x9c, 0x9d };
    const server_cid = [_]u8{ 0x9e, 0x9f, 0xa0, 0xa1 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x9a} ** quic.protection.secret_len);

    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();
    try std.testing.expect(server.peerAddressValidated());
    server.setPeerAddressValidated(false);
    try std.testing.expect(!server.peerAddressValidated());
    try std.testing.expectEqual(@as(?usize, 0), server.antiAmplificationLimitRemaining());

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try std.testing.expectError(error.AntiAmplificationLimited, server.sendAt(&ping, 10));
    try std.testing.expectEqual(@as(usize, 0), server.pendingRecoveryCount());
    try std.testing.expectEqual(@as(usize, 0), server.congestion.bytes_in_flight);

    server.recordPeerAddressBytesReceived(10);
    try std.testing.expectEqual(@as(?usize, 30), server.antiAmplificationLimitRemaining());
    try server.sendAt(&ping, 20);
    try std.testing.expectEqual(@as(usize, 1), server.pendingRecoveryCount());
    try std.testing.expectEqual(@as(?usize, 29), server.antiAmplificationLimitRemaining());

    var sent = try client_endpoint.receiveBytes();
    defer sent.deinit(allocator);
    try std.testing.expect(sent.bytes.len > 0);

    server.setPeerAddressValidated(true);
    try std.testing.expectEqual(@as(?usize, null), server.antiAmplificationLimitRemaining());
}

test "QUIC 1-RTT anti-amplification credit services expired PTO" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0xaa, 0xab, 0xac, 0xad };
    const server_cid = [_]u8{ 0xae, 0xaf, 0xb0, 0xb1 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xaa} ** quic.protection.secret_len);

    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();
    server.setPeerAddressValidated(false);

    const ping = [_]quic.Frame{.{ .ping = {} }};
    server.recordPeerAddressBytesReceived(1);
    try server.sendAt(&ping, 10_000_000);
    try std.testing.expectEqual(@as(?usize, 2), server.antiAmplificationLimitRemaining());

    // Consume the tiny remaining budget so the server is blocked exactly when
    // another datagram arrives with enough credit to service the already-due PTO.
    server.peer_address_bytes_sent = 3;
    const serviced = (try server.recordPeerAddressDatagramReceived(210_000_000, 10)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(LossDetectionTimerKind.pto, serviced.kind);
    try std.testing.expectEqual(@as(u8, 1), server.ptoBackoffCount());
    try std.testing.expect(server.antiAmplificationLimitRemaining().? < 30);

    var original = try client_endpoint.receiveBytes();
    defer original.deinit(allocator);
    var probe = try client_endpoint.receiveBytes();
    defer probe.deinit(allocator);
    try std.testing.expect(original.bytes.len > 0);
    try std.testing.expect(probe.bytes.len > 0);
}

test "QUIC 1-RTT connection enforces congestion send window" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x51, 0x52, 0x53, 0x54 };
    const server_cid = [_]u8{ 0x55, 0x56, 0x57, 0x58 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xc1} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xc2} ** quic.protection.secret_len);

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    client.congestion.congestion_window = 0;

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try std.testing.expectError(error.CongestionLimited, client.send(&ping));
    try std.testing.expectEqual(@as(usize, 0), client.congestion.bytes_in_flight);
    try std.testing.expectEqual(@as(u64, 0), client.next_packet_number);
}

test "QUIC 1-RTT routed datagrams dispatch to separate connections" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_a_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_a_endpoint.deinit();
    var client_b_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_b_endpoint.deinit();

    const client_a_cid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4 };
    const client_b_cid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const server_a_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4 };
    const server_b_cid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };
    const keys_a = quic.protection.deriveAes128Keys([_]u8{0x31} ** quic.protection.secret_len);
    const keys_b = quic.protection.deriveAes128Keys([_]u8{0x32} ** quic.protection.secret_len);

    var server_a = try Connection.init(&server_endpoint, .{
        .peer = client_a_endpoint.address(),
        .receive_keys = keys_a,
        .send_keys = keys_a,
        .local_connection_id = &server_a_cid,
        .peer_connection_id = &client_a_cid,
        .local_endpoint = .server,
    });
    defer server_a.deinit();
    var server_b = try Connection.init(&server_endpoint, .{
        .peer = client_b_endpoint.address(),
        .receive_keys = keys_b,
        .send_keys = keys_b,
        .local_connection_id = &server_b_cid,
        .peer_connection_id = &client_b_cid,
        .local_endpoint = .server,
    });
    defer server_b.deinit();

    var router = quic.connection_router.Router.init(allocator);
    defer router.deinit();
    try router.register(&server_a_cid, .{ .connection_index = 0 });
    try router.register(&server_b_cid, .{ .connection_index = 1 });

    const a_frames = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "for-a", .fin = true } }};
    const b_frames = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "for-b", .fin = true } }};
    try sendFrames(&client_a_endpoint, server_endpoint.address(), keys_a, .{
        .destination_connection_id = &server_a_cid,
        .packet_number = 0,
        .frames = &a_frames,
    });
    try sendFrames(&client_b_endpoint, server_endpoint.address(), keys_b, .{
        .destination_connection_id = &server_b_cid,
        .packet_number = 0,
        .frames = &b_frames,
    });

    var saw_a = false;
    var saw_b = false;
    for (0..2) |_| {
        var routed = try server_endpoint.receiveRoutedBytes(router);
        defer routed.deinit(allocator);
        switch (routed.route.connection_index) {
            0 => {
                var packet = try server_a.receiveRoutedDatagram(routed);
                defer packet.deinit(allocator);
                try std.testing.expectEqualStrings("for-a", packet.frames[0].stream.data);
                saw_a = true;
            },
            1 => {
                var packet = try server_b.receiveRoutedDatagram(routed);
                defer packet.deinit(allocator);
                try std.testing.expectEqualStrings("for-b", packet.frames[0].stream.data);
                saw_b = true;
            },
            else => return error.NoConnectionRoute,
        }
    }
    try std.testing.expect(saw_a);
    try std.testing.expect(saw_b);
}

test "QUIC 1-RTT path validation timeout retries then fails" {
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
    const keys = quic.protection.deriveAes128Keys([_]u8{0xdd} ** quic.protection.secret_len);

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    client.path_validation.max_challenge_transmissions = 2;

    const challenge = [_]u8{ 0xda, 1, 2, 3, 4, 5, 6, 7 };
    try client.queuePathChallenge(challenge);
    try client.sendPendingPathChallengeAt(100, 50);
    try std.testing.expectEqual(@as(?u64, 150), client.pathValidationDeadline());
    try std.testing.expectEqual(@as(usize, 0), try client.checkPathValidationTimeouts(149));
    try std.testing.expectEqual(@as(usize, 1), try client.checkPathValidationTimeouts(150));
    try std.testing.expectEqual(@as(usize, 1), client.path_validation.pendingChallengeCount());
    try std.testing.expectEqual(@as(usize, 0), client.path_validation.failedChallengeCount());

    try client.sendPendingPathChallengeAt(200, 50);
    try std.testing.expectEqual(@as(?u64, 250), client.pathValidationDeadline());
    try std.testing.expectEqual(@as(usize, 1), try client.checkPathValidationTimeouts(250));
    try std.testing.expectEqual(@as(usize, 0), client.path_validation.pendingChallengeCount());
    try std.testing.expectEqual(@as(usize, 1), client.path_validation.failedChallengeCount());
}

test "QUIC 1-RTT beginPeerMigration obeys disable_active_migration" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();
    var peer_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer peer_endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0xee} ** quic.protection.secret_len);
    var connection = try Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
        .peer_disable_active_migration = true,
    });
    defer connection.deinit();

    try std.testing.expect(connection.peerActiveMigrationDisabled());
    try std.testing.expectError(error.ActiveMigrationDisabled, connection.beginPeerMigration(peer_endpoint.address(), [_]u8{0} ** 8));
    try std.testing.expect(connection.peerAddressValidated());
    try std.testing.expectEqual(endpoint.address(), connection.config.peer);
    try std.testing.expectEqual(@as(usize, 0), connection.path_validation.pendingChallengeCount());
}

test "QUIC 1-RTT migration resets path state and validates on PATH_RESPONSE" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var first_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer first_endpoint.deinit();
    var migrated_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer migrated_endpoint.deinit();

    const local_cid = [_]u8{ 0xca, 0xcb, 0xcc, 0xcd };
    const peer_cid = [_]u8{ 0xce, 0xcf, 0xd0, 0xd1 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xcc} ** quic.protection.secret_len);

    var connection = try Connection.init(&first_endpoint, .{
        .peer = first_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &local_cid,
        .peer_connection_id = &peer_cid,
        .enable_pmtud = true,
        .pmtud_max_probe_size = 1300,
    });
    defer connection.deinit();
    connection.setPeerAddressValidated(true);
    connection.pmtud.onProbeAcked(1300, 1300);
    try std.testing.expectEqual(@as(usize, 1300), connection.pmtudCurrentSize());

    const challenge = [_]u8{ 0xc0, 1, 2, 3, 4, 5, 6, 7 };
    try connection.beginPeerMigration(migrated_endpoint.address(), challenge);
    try std.testing.expectEqual(migrated_endpoint.address(), connection.config.peer);
    try std.testing.expect(!connection.peerAddressValidated());
    try std.testing.expectEqual(@as(?usize, 0), connection.antiAmplificationLimitRemaining());
    try std.testing.expectEqual(quic.pmtu.min_udp_payload_size, connection.pmtudCurrentSize());
    try std.testing.expect(connection.pmtudShouldProbe());
    try std.testing.expectEqual(@as(usize, 1), connection.path_validation.pendingChallengeCount());

    var challenge_frame = try connection.path_validation.nextChallengeFrame();
    try std.testing.expectEqualSlices(u8, &challenge, &challenge_frame.path_challenge.data);
    try std.testing.expectEqual(@as(usize, 1), connection.path_validation.outstandingChallengeCount());

    const frames = [_]quic.Frame{.{ .path_response = .{ .data = challenge } }};
    try connection.applyReceivedFrames(0, &frames, null, .not_ect);
    try std.testing.expect(connection.peerAddressValidated());
    try std.testing.expectEqual(@as(usize, 0), connection.path_validation.outstandingChallengeCount());
    try std.testing.expectEqual(@as(?usize, null), connection.antiAmplificationLimitRemaining());
}

test "QUIC 1-RTT preferred address migration selects address and CID" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var original_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer original_endpoint.deinit();
    var preferred_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer preferred_endpoint.deinit();

    const local_cid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3 };
    const peer_cid = [_]u8{ 0xa4, 0xa5, 0xa6, 0xa7 };
    const preferred_cid = [_]u8{ 0xa8, 0xa9, 0xaa, 0xab };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xa0} ** quic.protection.secret_len);

    const preferred_address = quic.PreferredAddress{
        .ipv4_address = [_]u8{ 127, 0, 0, 1 },
        .ipv4_port = preferred_endpoint.address().ip4.port,
        .connection_id = &preferred_cid,
        .stateless_reset_token = [_]u8{0x5a} ** 16,
    };
    var connection = try Connection.init(&original_endpoint, .{
        .peer = original_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &local_cid,
        .peer_connection_id = &peer_cid,
        .peer_preferred_address = preferred_address,
        .active_connection_id_limit = 4,
    });
    defer connection.deinit();

    try std.testing.expect(connection.peerPreferredAddress() != null);
    try std.testing.expectEqual(preferred_endpoint.address(), Connection.preferredAddressIp4(preferred_address).?);
    try std.testing.expect(Connection.preferredAddressIp6(preferred_address) == null);

    const challenge = [_]u8{ 0xa0, 1, 2, 3, 4, 5, 6, 7 };
    try connection.beginPeerPreferredAddressMigration(challenge, .ipv4);
    try std.testing.expectEqual(preferred_endpoint.address(), connection.config.peer);
    try std.testing.expectEqualSlices(u8, &preferred_cid, connection.config.peer_connection_id);
    try std.testing.expectEqual(@as(usize, 2), connection.peer_connection_ids.count());
    try std.testing.expect(!connection.peerAddressValidated());
    try std.testing.expectEqual(@as(?usize, 0), connection.antiAmplificationLimitRemaining());
    var challenge_frame = try connection.path_validation.nextChallengeFrame();
    try std.testing.expectEqualSlices(u8, &challenge, &challenge_frame.path_challenge.data);

    var missing = try Connection.init(&original_endpoint, .{
        .peer = original_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &local_cid,
        .peer_connection_id = &peer_cid,
    });
    defer missing.deinit();
    try std.testing.expectError(error.InvalidTransportParameter, missing.beginPeerPreferredAddressMigration(challenge, .ipv4));
}

test "QUIC 1-RTT connection exchanges PATH_CHALLENGE and PATH_RESPONSE" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x61, 0x62, 0x63, 0x64 };
    const server_cid = [_]u8{ 0x65, 0x66, 0x67, 0x68 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xd1} ** quic.protection.secret_len);

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    const challenge = [_]u8{ 1, 3, 5, 7, 9, 11, 13, 15 };
    try client.queuePathChallenge(challenge);
    try client.sendPendingPathChallenge();

    var challenge_packet = try server.receivePacket();
    defer challenge_packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), server.path_validation.pendingResponseCount());
    try server.sendPendingPathResponse();

    var response_packet = try client.receivePacket();
    defer response_packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), client.path_validation.outstandingChallengeCount());
}

test "QUIC 1-RTT connection handles NEW and RETIRE connection IDs" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const server_cid = [_]u8{ 0x75, 0x76, 0x77, 0x78 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xe1} ** quic.protection.secret_len);

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try server.sendNewConnectionId("server-new-cid", [_]u8{0xaa} ** 16);
    var new_cid_packet = try client.receivePacket();
    defer new_cid_packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), client.peer_connection_ids.count());
    try std.testing.expect(client.switchToNextPeerConnectionId());
    try std.testing.expectEqualStrings("server-new-cid", client.config.peer_connection_id);
    var reset_datagram: std.ArrayList(u8) = .empty;
    defer reset_datagram.deinit(allocator);
    try quic.stateless_reset.encode(&reset_datagram, allocator, &.{ 0x40, 1, 2, 3, 4 }, [_]u8{0xaa} ** 16);
    try std.testing.expectEqual(@as(?u64, 1), client.detectStatelessReset(reset_datagram.items));

    const retire = [_]quic.Frame{.{ .retire_connection_id = .{ .sequence_number = 0 } }};
    try client.send(&retire);
    var router = quic.connection_router.Router.init(allocator);
    defer router.deinit();
    try router.register("server-new-cid", .{ .connection_index = 0, .sequence_number = 1 });
    var routed = try server_endpoint.receiveRoutedBytes(router);
    defer routed.deinit(allocator);
    var retire_packet = try server.receiveRoutedDatagram(routed);
    defer retire_packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), server.local_connection_ids.count());
}

test "QUIC 1-RTT queues RETIRE_CONNECTION_ID for retired peer IDs" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x79, 0x7a, 0x7b, 0x7c };
    const server_cid = [_]u8{ 0x7d, 0x7e, 0x7f, 0x80 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xe7} ** quic.protection.secret_len);

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .active_connection_id_limit = 4,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try sendFrames(&server_endpoint, client_endpoint.address(), keys, .{
        .destination_connection_id = &client_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .new_connection_id = .{
            .sequence_number = 2,
            .retire_prior_to = 1,
            .connection_id = "server-cid-two",
            .stateless_reset_token = [_]u8{0x77} ** 16,
        } }},
    });
    var new_cid_packet = try client.receivePacket();
    defer new_cid_packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), client.pendingRetireConnectionIdCount());
    try std.testing.expect(client.switchToNextPeerConnectionId());
    try std.testing.expectEqualStrings("server-cid-two", client.config.peer_connection_id);

    try std.testing.expectEqual(@as(usize, 1), try client.sendPendingRetireConnectionIds());
    try std.testing.expectEqual(@as(usize, 0), client.pendingRetireConnectionIdCount());

    var router = quic.connection_router.Router.init(allocator);
    defer router.deinit();
    try router.register("server-cid-two", .{ .connection_index = 0, .sequence_number = 2 });
    var routed = try server_endpoint.receiveRoutedBytes(router);
    defer routed.deinit(allocator);
    var retire_packet = try server.receiveRoutedDatagram(routed);
    defer retire_packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), server.local_connection_ids.count());
}

test "QUIC 1-RTT stateless reset enters draining" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0xe2} ** quic.protection.secret_len);
    var connection = try Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local-cid",
        .peer_connection_id = "peer-cid",
    });
    defer connection.deinit();

    try connection.peer_connection_ids.addWithLimit(1, "reset-cid", [_]u8{0xaa} ** 16, 4);
    try connection.peer_connection_ids.markInUse(1);
    var reset_datagram: std.ArrayList(u8) = .empty;
    defer reset_datagram.deinit(allocator);
    try quic.stateless_reset.encode(&reset_datagram, allocator, &.{ 0x40, 1, 2, 3, 4 }, [_]u8{0xaa} ** 16);

    try std.testing.expectEqual(@as(?u64, 1), connection.processStatelessResetDatagram(reset_datagram.items, 10, 25));
    try std.testing.expect(connection.draining());
    try std.testing.expectEqual(@as(?u64, 85), connection.closeExpiryDeadlineMillis());
    try std.testing.expectError(error.ConnectionClosed, connection.send(&[_]quic.Frame{.{ .ping = {} }}));
    try std.testing.expectEqual(@as(?u64, null), connection.processStatelessResetDatagram(&.{ 0x40, 1, 2 }, 11, 25));
}

test "QUIC routed receive detects stateless reset before decrypt" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0xe3} ** quic.protection.secret_len);
    var connection = try Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local-cid",
        .peer_connection_id = "peer-cid",
    });
    defer connection.deinit();

    const token = [_]u8{0x5d} ** 16;
    try connection.peer_connection_ids.addWithLimit(2, "reset-cid", token, 4);
    try connection.peer_connection_ids.markInUse(2);
    var reset_datagram: std.ArrayList(u8) = .empty;
    defer reset_datagram.deinit(allocator);
    try quic.stateless_reset.encode(&reset_datagram, allocator, &.{ 0x40, 9, 8, 7, 6 }, token);

    const raw = quic.runtime.OwnedBytes{
        .from = endpoint.address(),
        .bytes = try allocator.dupe(u8, reset_datagram.items),
    };
    var routed = quic.runtime.RoutedBytes{
        .datagram = raw,
        .route = .{ .connection_index = 0, .sequence_number = 2 },
        .destination_connection_id = "reset-cid",
    };
    defer routed.deinit(allocator);

    const result = try connection.receiveRoutedDatagramOrStatelessReset(routed, 20, 30);
    try std.testing.expectEqual(@as(u64, 2), result.stateless_reset);
    try std.testing.expect(connection.draining());
    try std.testing.expectEqual(@as(?u64, 110), connection.closeExpiryDeadlineMillis());
}

test "QUIC routed receive drops after stateless reset" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0xe4} ** quic.protection.secret_len);
    var connection = try Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local-cid",
        .peer_connection_id = "peer-cid",
    });
    defer connection.deinit();

    try connection.applyReceivedFrames(0, &.{.{ .connection_close = .{
        .error_code = 0,
        .frame_type = 0,
        .reason_phrase = "done",
    } }}, null, .not_ect);
    try std.testing.expect(connection.draining());

    const raw = quic.runtime.OwnedBytes{
        .from = endpoint.address(),
        .bytes = try allocator.dupe(u8, &.{ 0x40, 1, 2, 3, 4, 5 }),
    };
    var routed = quic.runtime.RoutedBytes{
        .datagram = raw,
        .route = .{ .connection_index = 0 },
        .destination_connection_id = "local-cid",
    };
    defer routed.deinit(allocator);

    const result = try connection.receiveRoutedDatagramOrStatelessReset(routed, 20, 30);
    try std.testing.expect(result == .dropped_after_close);
}

test "QUIC 1-RTT rejects invalid NEW_CONNECTION_ID lifecycle updates" {
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
    const keys = quic.protection.deriveAes128Keys([_]u8{0xe2} ** quic.protection.secret_len);
    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .active_connection_id_limit = 2,
    });
    defer client.deinit();

    try sendFrames(&server_endpoint, client_endpoint.address(), keys, .{
        .destination_connection_id = &client_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .new_connection_id = .{
            .sequence_number = 1,
            .retire_prior_to = 0,
            .connection_id = "cid-1",
            .stateless_reset_token = [_]u8{0x11} ** 16,
        } }},
    });
    var first = try client.receivePacket();
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), client.peer_connection_ids.count());

    try sendFrames(&server_endpoint, client_endpoint.address(), keys, .{
        .destination_connection_id = &client_cid,
        .packet_number = 1,
        .frames = &[_]quic.Frame{.{ .new_connection_id = .{
            .sequence_number = 1,
            .retire_prior_to = 0,
            .connection_id = "cid-1",
            .stateless_reset_token = [_]u8{0x22} ** 16,
        } }},
    });
    try std.testing.expectError(error.DuplicateResetToken, client.receivePacket());
    try std.testing.expectEqual(@as(usize, 2), client.peer_connection_ids.count());

    try sendFrames(&server_endpoint, client_endpoint.address(), keys, .{
        .destination_connection_id = &client_cid,
        .packet_number = 2,
        .frames = &[_]quic.Frame{.{ .new_connection_id = .{
            .sequence_number = 2,
            .retire_prior_to = 0,
            .connection_id = "cid-2",
            .stateless_reset_token = [_]u8{0x33} ** 16,
        } }},
    });
    try std.testing.expectError(error.ActiveConnectionIdLimit, client.receivePacket());
    try std.testing.expectEqual(@as(usize, 2), client.peer_connection_ids.count());
}

test "QUIC 1-RTT handles server-only NEW_TOKEN and HANDSHAKE_DONE roles" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x11, 0x22, 0x33, 0x44 };
    const server_cid = [_]u8{ 0x55, 0x66, 0x77, 0x88 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xa4} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xa5} ** quic.protection.secret_len);

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_endpoint = .client,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try std.testing.expectError(error.InvalidFrame, client.sendHandshakeDone());
    try std.testing.expectError(error.InvalidFrame, client.sendNewToken("client-token"));
    try std.testing.expectError(error.InvalidFrame, server.sendNewToken(""));

    try server.sendNewToken("future-token");
    var token_packet = try client.receivePacket();
    defer token_packet.deinit(allocator);
    try std.testing.expectEqualStrings("future-token", client.latestNewToken().?);

    const secret: quic.address_validation_token.Secret = [_]u8{0xc1} ** quic.address_validation_token.secret_len;
    const nonce: quic.address_validation_token.Nonce = [_]u8{0xc2} ** quic.address_validation_token.nonce_len;
    try server.sendAddressValidationToken(secret, 1_000, 5_000, "client-path", nonce);
    var address_token_packet = try client.receivePacket();
    defer address_token_packet.deinit(allocator);
    const issued = client.latestNewToken() orelse return error.TestUnexpectedResult;
    const validation = try quic.address_validation_token.validate(secret, .new_token, .version_1, 1_100, "client-path", issued);
    try std.testing.expectEqual(quic.address_validation_token.Kind.new_token, validation.kind);

    try server.sendHandshakeDone();
    var done_packet = try client.receivePacket();
    defer done_packet.deinit(allocator);
    try std.testing.expect(client.handshakeConfirmed());

    try sendFrames(&client_endpoint, server_endpoint.address(), client_keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .handshake_done = {} }},
    });
    try std.testing.expectError(error.InvalidFrame, server.receivePacket());
    try std.testing.expect(!server.handshakeConfirmed());

    try sendFrames(&client_endpoint, server_endpoint.address(), client_keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 1,
        .frames = &[_]quic.Frame{.{ .new_token = .{ .token = "illegal" } }},
    });
    try std.testing.expectError(error.InvalidFrame, server.receivePacket());
    try std.testing.expectEqual(@as(?[]const u8, null), server.latestNewToken());
}

test "QUIC 1-RTT connection closes with transport and application close frames" {
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
    const keys = quic.protection.deriveAes128Keys([_]u8{0xf1} ** quic.protection.secret_len);

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try client.closeTransport(0x100, @intFromEnum(quic.FrameType.stream), "done");
    var close_packet = try server.receivePacket();
    defer close_packet.deinit(allocator);
    try std.testing.expect(server.draining());
    try std.testing.expect(!server.closed());
    try std.testing.expectEqual(@as(u64, 0x100), server.close_info.?.error_code);
    try std.testing.expectEqualStrings("done", server.close_info.?.reason_phrase);
    try std.testing.expectError(error.ConnectionClosed, server.send(&[_]quic.Frame{.{ .ping = {} }}));

    var client2_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client2_endpoint.deinit();
    var server2_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server2_endpoint.deinit();
    const c2 = [_]u8{ 0x91, 0x92, 0x93, 0x94 };
    const s2 = [_]u8{ 0x95, 0x96, 0x97, 0x98 };
    var client2 = try Connection.init(&client2_endpoint, .{
        .peer = server2_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &c2,
        .peer_connection_id = &s2,
    });
    defer client2.deinit();
    var server2 = try Connection.init(&server2_endpoint, .{
        .peer = client2_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &s2,
        .peer_connection_id = &c2,
        .local_endpoint = .server,
    });
    defer server2.deinit();

    try server2.closeApplication(42, "app done");
    var app_close = try client2.receivePacket();
    defer app_close.deinit(allocator);
    try std.testing.expect(client2.draining());
    try std.testing.expect(!client2.closed());
    try std.testing.expect(client2.close_info.?.application);
    try std.testing.expectEqual(@as(u64, 42), client2.close_info.?.error_code);
    try std.testing.expectEqualStrings("app done", client2.close_info.?.reason_phrase);
}

test "QUIC 1-RTT close lifecycle expires after three PTOs" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0xc1} ** quic.protection.secret_len);
    var connection = try Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
    });
    defer connection.deinit();

    try connection.closeTransportAt(0x10, @intFromEnum(quic.FrameType.stream), "closing", 100, 25);
    try std.testing.expect(connection.closing());
    try std.testing.expectEqual(@as(?u64, 175), connection.closeExpiryDeadlineMillis());
    try std.testing.expectError(error.ConnectionClosed, connection.send(&[_]quic.Frame{.{ .ping = {} }}));
    try std.testing.expect(!connection.checkCloseExpired(174));
    try std.testing.expect(connection.closing());
    try std.testing.expect(connection.checkCloseExpired(175));
    try std.testing.expect(connection.closed());
}

test "QUIC 1-RTT connection handles RESET_STREAM final size" {
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
    const keys = quic.protection.deriveAes128Keys([_]u8{0x4a} ** quic.protection.secret_len);

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try client.send(&[_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "abcde", .fin = false } }});
    var stream_packet = try server.receivePacket();
    defer stream_packet.deinit(allocator);
    try std.testing.expectEqualStrings("abcde", stream_packet.frames[0].stream.data);
    try std.testing.expectEqual(@as(u64, 5), server.recv_data_total);

    try client.resetStream(0, 77);
    var reset_packet = try server.receivePacket();
    defer reset_packet.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), reset_packet.frames[0].reset_stream.stream_id);
    try std.testing.expectEqual(@as(u64, 77), reset_packet.frames[0].reset_stream.application_error_code);
    try std.testing.expectEqual(@as(u64, 5), reset_packet.frames[0].reset_stream.final_size);
    const reset = server.streamResetReceived(0).?;
    try std.testing.expectEqual(@as(u64, 77), reset.application_error_code);
    try std.testing.expectEqual(@as(u64, 5), reset.final_size);
    try std.testing.expectEqual(@as(u64, 5), server.recv_data_total);

    // A later RESET_STREAM with a different final size violates RFC 9000's
    // invariant that the final size, once known, is immutable.
    try sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 2,
        .frames = &[_]quic.Frame{.{ .reset_stream = .{
            .stream_id = 0,
            .application_error_code = 78,
            .final_size = 4,
        } }},
    });
    try std.testing.expectError(error.FinalSizeMismatch, server.receivePacket());
}

test "QUIC 1-RTT connection answers STOP_SENDING with RESET_STREAM" {
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
    const keys = quic.protection.deriveAes128Keys([_]u8{0x4b} ** quic.protection.secret_len);

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try client.send(&[_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "payload", .fin = false } }});
    var payload = try server.receivePacket();
    defer payload.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 7), server.recv_data_total);

    try server.sendStopSending(0, 44);
    var stop = try client.receivePacket();
    defer stop.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), stop.frames[0].stop_sending.stream_id);
    try std.testing.expectEqual(@as(u64, 44), stop.frames[0].stop_sending.application_error_code);
    try std.testing.expectEqual(@as(u64, 44), client.streamStopped(0).?.application_error_code);

    var reset = try server.receivePacket();
    defer reset.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), reset.frames[0].reset_stream.stream_id);
    try std.testing.expectEqual(@as(u64, 44), reset.frames[0].reset_stream.application_error_code);
    try std.testing.expectEqual(@as(u64, 7), reset.frames[0].reset_stream.final_size);
    try std.testing.expectEqual(@as(u64, 7), server.streamResetReceived(0).?.final_size);

    try std.testing.expectError(error.StreamStopped, client.send(&[_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "more", .fin = false } }}));
    try std.testing.expectEqual(@as(u64, 7), client.send_flow.used);
}

test "QUIC 1-RTT connection applies sparse ACK ranges from peer" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
    const server_cid = [_]u8{ 0x45, 0x46, 0x47, 0x48 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xb1} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xb2} ** quic.protection.secret_len);

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try client.send(&ping); // packet 0
    try client.send(&ping); // packet 1, deliberately dropped below
    try client.send(&ping); // packet 2
    try std.testing.expectEqual(@as(usize, 3), client.pendingRecoveryCount());

    var first = try server.receivePacket();
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), first.packet.packet_number);

    // Simulate a lost middle packet by removing packet 1 from the UDP receive
    // queue without recording it in the peer's ACK tracker.
    var dropped = try server_endpoint.receiveBytes();
    defer dropped.deinit(allocator);

    var third = try server.receivePacket();
    defer third.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), third.packet.packet_number);

    try server.sendAck(0);
    var ack_packet = try client.receivePacket();
    defer ack_packet.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), ack_packet.frames[0].ack.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 0), ack_packet.frames[0].ack.first_ack_range);
    try std.testing.expectEqual(@as(usize, 1), ack_packet.frames[0].ack.ranges.len);
    try std.testing.expectEqual(@as(u64, 0), ack_packet.frames[0].ack.ranges[0].gap);
    try std.testing.expectEqual(@as(u64, 0), ack_packet.frames[0].ack.ranges[0].ack_range_length);
    try std.testing.expect(client.sent.packets.items[0].acknowledged);
    try std.testing.expect(!client.sent.packets.items[1].acknowledged);
    try std.testing.expect(client.sent.packets.items[2].acknowledged);
    try std.testing.expectEqual(@as(usize, 1), client.pendingRecoveryCount());
    try std.testing.expectEqual(@as(u64, 1), client.recovery.pending.items[0].packet_numbers.items[0]);
}

test "QUIC 1-RTT connection retransmits PTO payload and clears recovery on ACK" {
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
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xa1} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xa2} ** quic.protection.secret_len);

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .initial_receive_max_data = 4,
        .initial_receive_max_stream_data = 4,
        .local_endpoint = .server,
    });
    defer server.deinit();

    const frames = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .offset = 0, .data = "lost", .fin = false } }};
    try client.send(&frames);
    try std.testing.expectEqual(@as(usize, 1), client.pendingRecoveryCount());

    var first = try server.receivePacket();
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), first.packet.packet_number);
    try std.testing.expectEqualStrings("lost", first.frames[0].stream.data);

    try std.testing.expect(try client.retransmitPto());
    try std.testing.expectEqual(@as(usize, 1), client.pendingRecoveryCount());
    try std.testing.expectEqual(@as(usize, 2), client.recovery.pending.items[0].packet_numbers.items.len);

    var retransmitted = try server.receivePacket();
    defer retransmitted.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), retransmitted.packet.packet_number);
    try std.testing.expectEqualStrings("lost", retransmitted.frames[0].stream.data);
    try std.testing.expectEqual(@as(u64, 4), server.recv_data_total);

    try server.sendAck(0);
    var ack_packet = try client.receivePacket();
    defer ack_packet.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), ack_packet.frames[0].ack.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 1), ack_packet.frames[0].ack.first_ack_range);
    try std.testing.expect(client.sent.packets.items[0].acknowledged);
    try std.testing.expect(client.sent.packets.items[1].acknowledged);
    try std.testing.expectEqual(@as(usize, 0), client.pendingRecoveryCount());
    try std.testing.expect(!(try client.retransmitPto()));
}

test "QUIC 1-RTT PTO service sends up to two probes" {
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

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try client.sendAt(&ping, 10_000_000);
    try client.sendAt(&ping, 10_000_000);
    try std.testing.expectEqual(@as(usize, 2), client.pendingRecoveryCount());

    const serviced = (try client.serviceLossDetectionTimer(210_000_000)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(LossDetectionTimerKind.pto, serviced.kind);
    try std.testing.expectEqual(@as(u8, 1), client.ptoBackoffCount());
    try std.testing.expectEqual(@as(usize, 2), client.recovery.pending.items[0].packet_numbers.items.len);
    try std.testing.expectEqual(@as(usize, 2), client.recovery.pending.items[1].packet_numbers.items.len);

    var original0 = try server.receivePacket();
    defer original0.deinit(allocator);
    var original1 = try server.receivePacket();
    defer original1.deinit(allocator);
    var probe0 = try server.receivePacket();
    defer probe0.deinit(allocator);
    var probe1 = try server.receivePacket();
    defer probe1.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), original0.packet.packet_number);
    try std.testing.expectEqual(@as(u64, 1), original1.packet.packet_number);
    try std.testing.expectEqual(@as(u64, 2), probe0.packet.packet_number);
    try std.testing.expectEqual(@as(u64, 3), probe1.packet.packet_number);
}

test "QUIC 1-RTT connection exposes PTO backoff deadlines and services timer" {
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

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try client.sendAt(&ping, 10_000_000);
    try std.testing.expectEqual(@as(u8, 0), client.ptoBackoffCount());
    try std.testing.expectEqual(@as(u64, 200_000_000), client.ptoPeriod());
    try std.testing.expectEqual(@as(?u64, 210_000_000), client.ptoDeadline());
    const first_deadline = client.lossDetectionTimerDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(LossDetectionTimerKind.pto, first_deadline.kind);
    try std.testing.expectEqual(@as(u64, 210_000_000), first_deadline.deadline_ns);

    try std.testing.expectEqual(@as(?LossDetectionTimerDeadline, null), try client.serviceLossDetectionTimer(209_999_999));
    const serviced = (try client.serviceLossDetectionTimer(210_000_000)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(LossDetectionTimerKind.pto, serviced.kind);
    try std.testing.expectEqual(@as(u8, 1), client.ptoBackoffCount());

    var first = try server.receivePacket();
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), first.packet.packet_number);
    var probe = try server.receivePacket();
    defer probe.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), probe.packet.packet_number);
    try std.testing.expectEqual(@as(?u64, 610_000_000), client.ptoDeadline());

    try server.sendAck(0);
    var ack = try client.receivePacket();
    defer ack.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), client.ptoBackoffCount());
    try std.testing.expectEqual(@as(?LossDetectionTimerDeadline, null), client.lossDetectionTimerDeadline());
}

test "QUIC 1-RTT loss detection timer reports earliest loss or PTO deadline" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0x92} ** quic.protection.secret_len);
    var connection = try Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "timer-local",
        .peer_connection_id = "timer-peer",
    });
    defer connection.deinit();

    connection.rtt_stats.updateAt(100_000_000, 0, true, 100_000_000);
    try connection.sent.sentAt(0, true, 1200, .not_ect, 0);
    try connection.recovery.trackSent(0, "zero");
    try connection.sent.sentAt(1, true, 1200, .not_ect, 200_000_000);
    try connection.recovery.trackSent(1, "one");
    _ = connection.sent.markAcknowledged(1);

    const loss_first = connection.lossDetectionTimerDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(LossDetectionTimerKind.loss_time, loss_first.kind);
    try std.testing.expectEqual(@as(u64, 112_500_000), loss_first.deadline_ns);

    connection.sent.packets.items[0].lost = true;
    try connection.sent.sentAt(2, true, 1200, .not_ect, 200_000_000);
    try connection.recovery.trackSent(2, "two");
    const pto_first = connection.lossDetectionTimerDeadline() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(LossDetectionTimerKind.pto, pto_first.kind);
    try std.testing.expectEqual(@as(u64, 525_000_000), pto_first.deadline_ns);
}

test "QUIC 1-RTT connection retransmits time-threshold losses" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x4a, 0x4b, 0x4c, 0x4d };
    const server_cid = [_]u8{ 0x4e, 0x4f, 0x50, 0x51 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xbe} ** quic.protection.secret_len);

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try client.sendAt(&ping, 100); // packet 0, deliberately old enough below.
    try client.sendAt(&ping, 300); // packet 1, used to establish largest acked.

    var dropped = try server_endpoint.receiveBytes();
    dropped.deinit(allocator);
    var second = try server.receivePacket();
    defer second.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), second.packet.packet_number);
    try server.sendAck(0);

    var ack = try client.receivePacket();
    defer ack.deinit(allocator);
    try std.testing.expect(client.sent.packets.items[1].acknowledged);
    try std.testing.expect(!client.sent.packets.items[0].lost);

    try std.testing.expect(try client.retransmitTimeThresholdLoss(260, 150));
    try std.testing.expect(client.sent.packets.items[0].lost);
    var retransmitted = try server.receivePacket();
    defer retransmitted.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), retransmitted.packet.packet_number);
    try std.testing.expectEqual(@as(usize, 2), client.recovery.pending.items[0].packet_numbers.items.len);
    try std.testing.expect(!(try client.retransmitTimeThresholdLoss(1_000, 150)));
    try std.testing.expectEqual(@as(usize, 2), client.recovery.pending.items[0].packet_numbers.items.len);
}

test "QUIC 1-RTT ACK processing detects time-threshold losses" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x7a, 0x7b, 0x7c, 0x7d };
    const server_cid = [_]u8{ 0x7e, 0x7f, 0x80, 0x81 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x7c} ** quic.protection.secret_len);

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    // Use already-populated RTT state so ACK-driven time loss uses the real
    // RFC 9002 9/8 loss delay instead of the larger initial fallback.
    client.rtt_stats.updateAt(100_000_000, 0, true, 100_000_000);
    const loss_delay = client.rtt_stats.lossDelay();

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try client.sendAt(&ping, 100_000_000); // packet 0, should be lost by time threshold.
    try client.sendAt(&ping, 300_000_000); // packet 1, newest ACKed packet.

    var dropped = try server_endpoint.receiveBytes();
    dropped.deinit(allocator);
    var second = try server.receivePacket();
    defer second.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), second.packet.packet_number);
    try server.sendAck(0);

    var ack = try client.receivePacketAt(100_000_000 + loss_delay);
    defer ack.deinit(allocator);
    try std.testing.expect(client.sent.packets.items[1].acknowledged);
    try std.testing.expect(client.sent.packets.items[0].lost);
    try std.testing.expectEqual(@as(usize, 1), client.pendingRecoveryCount());

    try std.testing.expect(try client.retransmitTimeThresholdLoss(500_000_000, loss_delay));
    var retransmitted = try server.receivePacket();
    defer retransmitted.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), retransmitted.packet.packet_number);
}

test "QUIC 1-RTT connection retransmits packet-threshold losses" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x3a, 0x3b, 0x3c, 0x3d };
    const server_cid = [_]u8{ 0x3e, 0x3f, 0x40, 0x41 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xab} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xac} ** quic.protection.secret_len);

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    const ping = [_]quic.Frame{.{ .ping = {} }};
    for (0..5) |_| try client.send(&ping);
    try std.testing.expectEqual(@as(usize, 5), client.pendingRecoveryCount());

    for (0..4) |_| {
        var dropped = try server_endpoint.receiveBytes();
        dropped.deinit(allocator);
    }

    var fifth = try server.receivePacket();
    defer fifth.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 4), fifth.packet.packet_number);
    try server.sendAck(0);

    var ack_packet = try client.receivePacket();
    defer ack_packet.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 4), ack_packet.frames[0].ack.largest_acknowledged);
    try std.testing.expect(client.sent.packets.items[0].lost);
    try std.testing.expect(client.sent.packets.items[1].lost);
    try std.testing.expect(!client.sent.packets.items[2].lost);
    try std.testing.expect(client.sent.packets.items[4].acknowledged);
    try std.testing.expectEqual(@as(usize, 4), client.pendingRecoveryCount());

    try std.testing.expect(try client.retransmitPacketThresholdLoss());
    var first_retransmit = try server.receivePacket();
    defer first_retransmit.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 5), first_retransmit.packet.packet_number);
    try std.testing.expectEqual(@as(usize, 2), client.recovery.pending.items[0].packet_numbers.items.len);

    try std.testing.expect(try client.retransmitPacketThresholdLoss());
    var second_retransmit = try server.receivePacket();
    defer second_retransmit.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 6), second_retransmit.packet.packet_number);
    try std.testing.expectEqual(@as(usize, 2), client.recovery.pending.items[1].packet_numbers.items.len);
    try std.testing.expect(!(try client.retransmitPacketThresholdLoss()));

    try server.sendAck(0);
    var second_ack = try client.receivePacket();
    defer second_ack.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 6), second_ack.frames[0].ack.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 2), second_ack.frames[0].ack.first_ack_range);
    try std.testing.expectEqual(@as(usize, 2), client.pendingRecoveryCount());
    try std.testing.expectEqual(@as(u64, 2), client.recovery.pending.items[0].packet_numbers.items[0]);
}

test "QUIC 1-RTT connection applies persistent congestion response" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x6a, 0x6b, 0x6c, 0x6d };
    const server_cid = [_]u8{ 0x6e, 0x6f, 0x70, 0x71 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x6c} ** quic.protection.secret_len);

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try client.sendAt(&ping, 0);
    var first = try server.receivePacket();
    defer first.deinit(allocator);
    try server.sendAck(0);

    var first_ack = try client.receivePacketAt(100_000_000);
    defer first_ack.deinit(allocator);
    try std.testing.expect(client.rtt_stats.has_measurement);
    try std.testing.expectEqual(@as(?u64, 100_000_000), client.rtt_stats.first_rtt_sample_time_ns);

    try client.sendAt(&ping, 200_000_000); // packet 1, first lost boundary after the RTT sample.
    try client.sendAt(&ping, 500_000_000); // packet 2, interior lost packet.
    try client.sendAt(&ping, 1_200_000_000); // packet 3, last lost boundary.
    try client.sendAt(&ping, 1_300_000_000); // packet 4, largest acknowledged.

    for (0..3) |_| {
        var dropped = try server_endpoint.receiveBytes();
        dropped.deinit(allocator);
    }
    var acknowledged = try server.receivePacket();
    defer acknowledged.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 4), acknowledged.packet.packet_number);

    client.congestion.congestion_window = 24_000;
    client.congestion.slow_start_threshold = 24_000;
    try server.sendAck(0);

    var ack = try client.receivePacketAt(1_400_000_000);
    defer ack.deinit(allocator);
    try std.testing.expect(try client.retransmitTimeThresholdLoss(1_400_000_000, client.rtt_stats.lossDelay()));

    try std.testing.expect(client.sent.packets.items[1].lost);
    try std.testing.expect(client.sent.packets.items[2].lost);
    try std.testing.expect(client.sent.packets.items[3].lost);
    try std.testing.expectEqual(quic.congestion.minimumWindow(client.config.max_datagram_size), client.congestion.congestion_window);
    try std.testing.expectEqual(@as(?u64, null), client.rtt_stats.first_rtt_sample_time_ns);
    try std.testing.expectEqual(@as(?u64, 3), client.last_persistent_congestion_packet_number);

    var retransmitted = try server.receivePacket();
    defer retransmitted.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 5), retransmitted.packet.packet_number);

    const old_min = client.rtt_stats.min_rtt;
    try client.sendAt(&ping, 1_500_000_000);
    var sample_packet = try server.receivePacket();
    defer sample_packet.deinit(allocator);
    try server.sendAck(0);

    var sample_ack = try client.receivePacketAt(1_700_000_000);
    defer sample_ack.deinit(allocator);
    try std.testing.expect(old_min != 200_000_000);
    try std.testing.expectEqual(@as(u64, 200_000_000), client.rtt_stats.min_rtt);
    try std.testing.expectEqual(@as(u64, 200_000_000), client.rtt_stats.smoothed_rtt);
    try std.testing.expectEqual(@as(?u64, 1_700_000_000), client.rtt_stats.first_rtt_sample_time_ns);
}

test "QUIC 1-RTT connection emits DATA_BLOCKED and applies MAX_DATA" {
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
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0x81} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0x82} ** quic.protection.secret_len);

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .initial_send_max_data = 5,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    const too_much = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "123456", .fin = false } }};
    try std.testing.expectError(error.FlowControlBlocked, client.send(&too_much));
    var blocked = try server.receivePacket();
    defer blocked.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 5), blocked.frames[0].data_blocked.maximum_data);

    const grant = [_]quic.Frame{.{ .max_data = .{ .maximum_data = 10 } }};
    try server.send(&grant);
    var grant_packet = try client.receivePacket();
    defer grant_packet.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 10), client.send_flow.limit);

    try client.send(&too_much);
    var data = try server.receivePacket();
    defer data.deinit(allocator);
    try std.testing.expectEqualStrings("123456", data.frames[0].stream.data);
}

test "QUIC 1-RTT connection handles stream-level flow control" {
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
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0x91} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0x92} ** quic.protection.secret_len);

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .initial_send_max_stream_data = 3,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .initial_receive_max_stream_data = 6,
        .stream_receive_window = 6,
        .local_endpoint = .server,
    });
    defer server.deinit();

    const too_much = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "abcd", .fin = false } }};
    try std.testing.expectError(error.FlowControlBlocked, client.send(&too_much));
    var blocked = try server.receivePacket();
    defer blocked.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), blocked.frames[0].stream_data_blocked.stream_id);
    try std.testing.expectEqual(@as(u64, 3), blocked.frames[0].stream_data_blocked.maximum_stream_data);

    const grant = [_]quic.Frame{.{ .max_stream_data = .{ .stream_id = 0, .maximum_stream_data = 8 } }};
    try server.send(&grant);
    var grant_packet = try client.receivePacket();
    defer grant_packet.deinit(allocator);

    try client.send(&too_much);
    var data = try server.receivePacket();
    defer data.deinit(allocator);
    try std.testing.expectEqualStrings("abcd", data.frames[0].stream.data);
    const max_stream = (try server.consumeStreamReceived(0, 4)).?;
    try std.testing.expectEqual(@as(u64, 0), max_stream.max_stream_data.stream_id);
    try std.testing.expectEqual(@as(u64, 10), max_stream.max_stream_data.maximum_stream_data);
}

test "QUIC 1-RTT connection enforces stream count limits and MAX_STREAMS" {
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
    const keys = quic.protection.deriveAes128Keys([_]u8{0xb1} ** quic.protection.secret_len);

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .initial_send_max_streams_bidi = 1,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .initial_receive_max_streams_bidi = 2,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try client.send(&[_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "first", .fin = false } }});
    var first = try server.receivePacket();
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("first", first.frames[0].stream.data);

    try std.testing.expectError(error.StreamLimitExceeded, client.send(&[_]quic.Frame{.{ .stream = .{ .stream_id = 4, .data = "blocked", .fin = false } }}));
    var blocked = try server.receivePacket();
    defer blocked.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), blocked.frames[0].streams_blocked_bidi.maximum_streams);

    try server.send(&[_]quic.Frame{.{ .max_streams_bidi = .{ .maximum_streams = 2 } }});
    var grant = try client.receivePacket();
    defer grant.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), client.peer_max_streams_bidi);

    try client.send(&[_]quic.Frame{.{ .stream = .{ .stream_id = 4, .data = "second", .fin = false } }});
    var second = try server.receivePacket();
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("second", second.frames[0].stream.data);

    try std.testing.expectError(error.StreamLimitExceeded, client.send(&[_]quic.Frame{.{ .stream = .{ .stream_id = 8, .data = "third", .fin = false } }}));
}

test "QUIC 1-RTT connection rejects peer-created streams beyond receive limit" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
    const server_cid = [_]u8{ 0x45, 0x46, 0x47, 0x48 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xb2} ** quic.protection.secret_len);

    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .initial_receive_max_streams_bidi = 1,
    });
    defer server.deinit();

    try sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .stream = .{ .stream_id = 4, .data = "too many", .fin = false } }},
    });
    try std.testing.expectError(error.StreamLimitExceeded, server.receivePacket());
    try std.testing.expectEqual(@as(usize, 0), server.stream_recv_flows.items.len);
}

test "QUIC 1-RTT DATAGRAM send receive and queue limits" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4 };
    const server_cid = [_]u8{ 0xd5, 0xd6, 0xd7, 0xd8 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xd0} ** quic.protection.secret_len);

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .max_datagram_queue_items = 2,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .max_datagram_queue_items = 2,
    });
    defer server.deinit();

    try std.testing.expect(client.datagramsEnabled());
    try std.testing.expect(server.datagramReceiveEnabled());
    try std.testing.expect((client.maxDatagramPayloadSize() orelse 0) > 1000);

    try client.sendDatagram("one");
    var received = try server.receivePacket();
    defer received.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), client.datagramsSent());
    try std.testing.expectEqual(@as(u64, 1), server.datagramsReceived());
    try std.testing.expectEqual(@as(usize, 1), server.datagramReceiveQueueLen());
    var out: [16]u8 = undefined;
    const popped = (try server.popDatagram(&out)).?;
    try std.testing.expectEqualStrings("one", popped);
    try std.testing.expectEqual(@as(usize, 0), server.datagramReceiveQueueLen());

    try client.send(&.{
        .{ .datagram = .{ .data = "two", .length_present = true } },
        .{ .datagram = .{ .data = "three", .length_present = true } },
        .{ .datagram = .{ .data = "drop", .length_present = true } },
    });
    var queued = try server.receivePacket();
    defer queued.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 3), server.datagramsReceived());
    try std.testing.expectEqual(@as(u64, 1), server.datagramsDroppedIncoming());
    try std.testing.expectEqual(@as(usize, 2), server.datagramReceiveQueueLen());

    try std.testing.expect((try server.popDatagram(&out)) != null);
    try std.testing.expectError(error.DatagramBufferTooSmall, server.popDatagram(out[0..2]));
}

test "QUIC 1-RTT DATAGRAM enforces negotiation and frame-size limits" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const cid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xe0} ** quic.protection.secret_len);

    var no_dgram = try Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &cid,
        .peer_connection_id = &cid,
    });
    defer no_dgram.deinit();
    try std.testing.expectError(error.DatagramsNotEnabled, no_dgram.sendDatagram("disabled"));

    var limited = try Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &cid,
        .peer_connection_id = &cid,
        .local_max_datagram_frame_size = 8,
        .peer_max_datagram_frame_size = 8,
    });
    defer limited.deinit();
    try std.testing.expectEqual(@as(?usize, 6), limited.maxDatagramPayloadSize());
    try std.testing.expectError(error.DatagramTooLarge, limited.sendDatagram("1234567"));
    try std.testing.expectError(error.InvalidFrame, limited.validateDatagramFrame(.{ .data = "1234567", .length_present = true }));
    try limited.validateDatagramFrame(.{ .data = "1234567", .length_present = false });
    try std.testing.expectError(error.InvalidFrame, limited.validateDatagramFrame(.{ .data = "12345678", .length_present = false }));
}

test "QUIC 1-RTT ACK_FREQUENCY and IMMEDIATE_ACK state" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0xf1, 0xf2, 0xf3, 0xf4 };
    const server_cid = [_]u8{ 0xf5, 0xf6, 0xf7, 0xf8 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xf0} ** quic.protection.secret_len);

    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .enable_ack_frequency = true,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .enable_ack_frequency = true,
    });
    defer server.deinit();

    const sequence = try client.sendAckFrequency(4, 12_000, 5);
    try std.testing.expectEqual(@as(u64, 0), sequence);
    var frequency = try server.receivePacket();
    defer frequency.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 4), server.ackFrequencyThreshold());
    try std.testing.expectEqual(@as(u64, 12_000), server.requestedMaxAckDelay());
    try std.testing.expectEqual(@as(u64, 5), server.ackReorderingThreshold());

    const reverse_sequence = try server.sendAckFrequency(6, 34_000, 7);
    try std.testing.expectEqual(@as(u64, 0), reverse_sequence);
    var reverse_frequency = try client.receivePacket();
    defer reverse_frequency.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 6), client.ackFrequencyThreshold());
    try std.testing.expectEqual(@as(u64, 34_000), client.requestedMaxAckDelay());
    try std.testing.expectEqual(@as(u64, 7), client.ackReorderingThreshold());

    try client.sendImmediateAck();
    var immediate = try server.receivePacket();
    defer immediate.deinit(allocator);
    try std.testing.expect(server.immediateAckRequested());

    try sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 2,
        .frames = &[_]quic.Frame{.{ .ack_frequency = .{
            .sequence_number = 0,
            .ack_eliciting_threshold = 99,
            .request_max_ack_delay = 99,
            .reordering_threshold = 99,
        } }},
    });
    var stale = try server.receivePacket();
    defer stale.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 4), server.ackFrequencyThreshold());

    var disabled = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer disabled.deinit();
    try sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 3,
        .frames = &[_]quic.Frame{.{ .immediate_ack = {} }},
    });
    try std.testing.expectError(error.AckFrequencyDisabled, disabled.receivePacket());
}
