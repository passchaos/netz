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
    PacingLimited,
    AeadLimitReached,
};

pub const SendOptions = struct {
    destination_connection_id: []const u8,
    packet_number: u64,
    packet_number_len: u8 = 4,
    spin_bit: bool = false,
    key_phase: bool = false,
    frames: []const quic.Frame,
};

pub const BatchSendOptions = struct {
    destination_connection_id: []const u8,
    first_packet_number: u64,
    packet_number_len: u8 = 4,
    spin_bit: bool = false,
    key_phase: bool = false,
    /// One frame slice per UDP datagram.
    packets: []const []const quic.Frame,
};

pub const BatchSendResult = struct {
    /// Number of consecutive packets handed to the socket. Packet numbers in
    /// this prefix must never be reused, even when `send_error` is non-null.
    sent_count: usize,
    /// Protected bytes corresponding to `sent_count`.
    sent_bytes: usize,
    /// A sendmmsg-style backend can accept a prefix before failing.
    send_error: ?net.Socket.SendError = null,
};

pub const ConnectionBatchSendResult = struct {
    /// Datagrams accepted by the socket, always a prefix of the protected
    /// packet batch.
    sent_count: usize,
    /// Input packet groups protected by this call.
    ///
    /// This can exceed `sent_count` after a partial send. Every protected QUIC
    /// packet number is consumed even when its datagram was not accepted:
    /// reusing an AEAD nonce with different plaintext would be unsafe.
    protected_count: usize,
    send_error: ?net.Socket.SendError = null,
};

pub const max_batch_packets: usize = 64;

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

const StreamDirection = enum {
    bidirectional,
    unidirectional,
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

pub const ReceivedPacketBatch = struct {
    allocator: std.mem.Allocator,
    packets: []ReceivedPacket,
    next_index: usize = 0,

    pub fn deinit(self: *ReceivedPacketBatch) void {
        for (self.packets[self.next_index..]) |*packet| {
            packet.deinit(self.allocator);
        }
        self.allocator.free(self.packets);
        self.* = undefined;
    }

    pub fn remaining(self: ReceivedPacketBatch) usize {
        return self.packets.len - self.next_index;
    }

    /// Transfer one packet out of the owning GRO batch.
    ///
    /// HTTP/3 uses this cursor to amortize one kernel receive/decryption batch
    /// while routing only one packet at a time into bounded stream windows.
    pub fn takeNext(self: *ReceivedPacketBatch) ?ReceivedPacket {
        if (self.next_index == self.packets.len) return null;
        const packet = self.packets[self.next_index];
        self.next_index += 1;
        return packet;
    }
};

const zero_rtt = quic.zero_rtt;
pub const ZeroRttSendOptions = zero_rtt.SendOptions;
pub const ReceivedZeroRttPacket = zero_rtt.Packet;
pub const EarlyDataSender = zero_rtt.EarlyDataSender;
pub const sendZeroRttFrames = zero_rtt.sendFrames;
pub const receiveZeroRtt = zero_rtt.receive;
pub const openZeroRttBytes = zero_rtt.openBytes;

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
    /// CUBIC is the high-throughput default; NewReno remains selectable for
    /// compatibility-sensitive deployments.
    congestion_algorithm: quic.congestion.Algorithm = .cubic,
    enable_hystart: bool = true,
    enable_pacing: bool = true,
    pacing_max_burst_packets: usize = quic.pacing.Pacer.default_max_burst_packets,
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
    local_stateless_reset_key: ?[quic.stateless_reset.static_key_len]u8 = null,
    peer_active_connection_id_limit: usize = quic.default_active_connection_id_limit,
    /// Per-generation AEAD encryption cap. Values above the RFC 9001
    /// AES-128-GCM limit are clamped; lower values support conservative policy
    /// and deterministic boundary tests.
    aead_confidentiality_limit: u64 = quic.protection.aes_128_gcm_confidentiality_limit,
    /// Lifetime count of packets that fail 1-RTT authentication before the
    /// connection is closed with AEAD_LIMIT_REACHED. Also clamped to the RFC
    /// AES-128-GCM integrity limit.
    aead_integrity_limit: u64 = quic.protection.aes_128_gcm_integrity_limit,
    qlog_observer: ?*quic.qlog.Observer = null,
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

const DatagramRecvQueue = struct {
    slots: std.ArrayList(?[]u8) = .empty,
    head: usize = 0,
    len: usize = 0,

    fn deinit(self: *DatagramRecvQueue, allocator: std.mem.Allocator) void {
        for (self.slots.items) |maybe_payload| {
            if (maybe_payload) |payload| allocator.free(payload);
        }
        self.slots.deinit(allocator);
        self.* = undefined;
    }

    fn count(self: DatagramRecvQueue) usize {
        return self.len;
    }

    /// Insert a payload into a bounded FIFO queue, returning an evicted oldest
    /// payload when the queue is already full. s2n-quic's default receiver
    /// favors the newest unreliable DATAGRAM data on overflow; mirroring that
    /// behavior here also keeps receive-pop O(1) by avoiding `orderedRemove(0)`.
    fn pushDroppingOldest(
        self: *DatagramRecvQueue,
        allocator: std.mem.Allocator,
        payload: []u8,
        capacity: usize,
    ) std.mem.Allocator.Error!?[]u8 {
        std.debug.assert(capacity > 0);
        std.debug.assert(self.len <= capacity);

        if (self.len < capacity) {
            const tail = if (self.slots.items.len == 0) 0 else (self.head + self.len) % capacity;
            if (tail < self.slots.items.len) {
                std.debug.assert(self.slots.items[tail] == null);
                self.slots.items[tail] = payload;
            } else {
                std.debug.assert(tail == self.slots.items.len);
                try self.slots.append(allocator, payload);
            }
            self.len += 1;
            return null;
        }

        const dropped = self.slots.items[self.head].?;
        self.slots.items[self.head] = payload;
        self.head = (self.head + 1) % self.slots.items.len;
        return dropped;
    }

    fn pop(self: *DatagramRecvQueue) ?[]u8 {
        if (self.len == 0) return null;
        const payload = self.slots.items[self.head].?;
        self.slots.items[self.head] = null;
        self.len -= 1;
        if (self.len == 0) {
            self.head = 0;
        } else {
            self.head = (self.head + 1) % self.slots.items.len;
        }
        return payload;
    }
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
const max_short_packet_overhead: usize = 1 + 20 + 4 + quic.protection.aead_tag_len;

pub const Connection = struct {
    endpoint: *quic.runtime.Endpoint,
    config: ConnectionConfig,
    next_packet_number: u64 = 0,
    expected_packet_number: u64 = 0,
    received: quic.packet_space.ReceivedPacketTracker,
    sent: quic.packet_space.SentPacketTracker,
    recovery: quic.recovery.Queue,
    congestion: quic.congestion.Controller,
    pacer: quic.pacing.Pacer,
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
    send_key_generation_encrypted_packets: u64 = 0,
    receive_authentication_failures: u64 = 0,
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
    datagram_recv_queue: DatagramRecvQueue = .{},
    datagrams_sent_count: u64 = 0,
    datagrams_received_count: u64 = 0,
    datagrams_dropped_incoming_count: u64 = 0,
    ack_frequency_send_next_sequence: u64 = 0,
    ack_frequency_recv_next_sequence: u64 = 0,
    ack_eliciting_threshold: u64 = 1,
    requested_max_ack_delay: u64 = 0,
    ack_reordering_threshold: u64 = quic.packet_space.default_packet_threshold,
    immediate_ack_requested: bool = false,
    pacing_blocked_until_ns: ?u64 = null,
    /// Reused plaintext frame storage. ACK-eliciting payloads are copied only
    /// when recovery needs stable ownership; transient encoding itself is
    /// allocation-free after connection initialization.
    send_frame_buffer: std.ArrayList(u8) = .empty,
    /// Reused protected-datagram storage. Packet protection writes directly
    /// into this buffer, avoiding one heap allocation/free pair per 1-RTT send.
    send_packet_buffer: std.ArrayList(u8) = .empty,
    /// Reused flow-credit aggregation for stateful packet batches.
    ///
    /// A packet may carry STREAM frames for several streams, and later packets
    /// may continue any of them. Keeping both aggregate levels on the
    /// connection makes steady-state HTTP/3 batching allocation-free outside
    /// recovery's required stable payload ownership.
    send_batch_stream_scratch: std.ArrayList(ReservedStreamCredit) = .empty,
    send_batch_packet_stream_scratch: std.ArrayList(ReservedStreamCredit) = .empty,
    /// Borrowed frame views used only by `servicePacketBatch`. They never
    /// outlive the current decrypted GRO segment and therefore avoid one frame
    /// slice allocation per packet on the event-loop fast path.
    receive_frame_buffer: std.ArrayList(quic.Frame) = .empty,

    pub fn init(endpoint: *quic.runtime.Endpoint, config: ConnectionConfig) Error!Connection {
        const send_buffer_capacity = std.math.add(usize, config.max_datagram_size, max_short_packet_overhead) catch return error.OutOfMemory;
        var connection = Connection{
            .endpoint = endpoint,
            .config = config,
            .received = .init(endpoint.allocator, config.max_ack_ranges),
            .sent = .init(endpoint.allocator),
            .recovery = .init(endpoint.allocator),
            .congestion = .initWithOptions(config.max_datagram_size, config.congestion_algorithm, config.enable_hystart),
            .pacer = .init(config.enable_pacing, send_buffer_capacity, config.pacing_max_burst_packets),
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
        errdefer connection.deinit();
        try connection.send_frame_buffer.ensureTotalCapacity(endpoint.allocator, config.max_datagram_size);
        try connection.send_packet_buffer.ensureTotalCapacity(endpoint.allocator, send_buffer_capacity);
        if (config.local_stateless_reset_key) |key| {
            try connection.local_connection_ids.registerInitialWithStaticKey(config.local_connection_id, key);
        } else {
            try connection.local_connection_ids.registerInitial(config.local_connection_id, [_]u8{0} ** 16);
        }
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
        self.datagram_recv_queue.deinit(self.endpoint.allocator);
        self.send_frame_buffer.deinit(self.endpoint.allocator);
        self.send_packet_buffer.deinit(self.endpoint.allocator);
        self.send_batch_stream_scratch.deinit(self.endpoint.allocator);
        self.send_batch_packet_stream_scratch.deinit(
            self.endpoint.allocator,
        );
        self.receive_frame_buffer.deinit(self.endpoint.allocator);
        self.* = undefined;
    }

    pub fn takeQlogError(self: *Connection) ?anyerror {
        const observer = self.config.qlog_observer orelse return null;
        return observer.takeError();
    }

    pub fn qlogFailed(self: Connection) bool {
        const observer = self.config.qlog_observer orelse return false;
        return observer.failure != null;
    }

    pub fn send(self: *Connection, frames: []const quic.Frame) Error!void {
        try self.sendWithEcn(frames, .not_ect);
    }

    /// Send one frame slice per QUIC packet through a stateful socket batch.
    ///
    /// Pacing can split the input into several batches transparently. Flow or
    /// congestion exhaustion remains observable, as with repeated `send`
    /// calls, because this compact connection does not own an application send
    /// queue that could wait for MAX_DATA or ACK processing.
    pub fn sendMany(
        self: *Connection,
        packets: []const []const quic.Frame,
    ) Error!void {
        var offset: usize = 0;
        while (offset < packets.len) {
            const now_ns = self.monotonicNowNs();
            const result = self.sendManyProgressAt(
                packets[offset..],
                now_ns,
            ) catch |err| switch (err) {
                error.PacingLimited => {
                    try self.waitForPacing(now_ns);
                    continue;
                },
                else => return err,
            };
            if (result.protected_count == 0) return error.MissingFrame;
            offset += result.protected_count;
            if (result.send_error) |err| return err;
            if (result.sent_count != result.protected_count) {
                return error.Unexpected;
            }
            if (offset < packets.len and
                self.pacing_blocked_until_ns != null)
            {
                try self.waitForPacing(now_ns);
            }
        }
    }

    /// Protect and submit one stateful packet batch with explicit progress.
    ///
    /// All fallible transport bookkeeping is completed before the socket call.
    /// On a partial send, recovery, congestion, flow-control, pacing, and
    /// highest-stream-offset state retain only the socket-visible prefix. AEAD
    /// usage and packet numbers retain the entire protected batch.
    pub fn sendManyProgressAt(
        self: *Connection,
        packets: []const []const quic.Frame,
        sent_time_ns: ?u64,
    ) Error!ConnectionBatchSendResult {
        if (packets.len == 0) {
            return .{ .sent_count = 0, .protected_count = 0 };
        }
        self.pacing_blocked_until_ns = null;
        if (self.close_info != null or self.idle_timed_out) {
            return error.ConnectionClosed;
        }
        try self.validateNextPacketNumber();

        const batch_limit = @min(packets.len, max_batch_packets);
        const confidentiality_limit = self.aeadConfidentialityLimit();
        const encrypted = self.send_key_generation_encrypted_packets;
        const needs_key_update = encrypted >= confidentiality_limit;
        const encryptable_u64 = if (!needs_key_update)
            confidentiality_limit - encrypted
        else blk: {
            if (confidentiality_limit == 0 or
                self.pending_key_update_ack_threshold != null)
            {
                try self.enterAeadLimitReached(
                    "confidentiality limit",
                    null,
                    false,
                );
                return error.AeadLimitReached;
            }
            break :blk confidentiality_limit;
        };
        const encryptable = @min(
            batch_limit,
            std.math.cast(usize, encryptable_u64) orelse batch_limit,
        );
        if (encryptable == 0) return error.AeadLimitReached;

        const last_packet_number = std.math.add(
            u64,
            self.next_packet_number,
            encryptable - 1,
        ) catch return error.InvalidPacketNumber;
        if (last_packet_number > quic.protection.max_packet_number) {
            return error.InvalidPacketNumber;
        }

        // Stream-limit checks can emit STREAMS_BLOCKED through the ordinary
        // one-packet path, so perform all of them while batch scratch is empty.
        for (packets[0..encryptable]) |frames| {
            try self.validateOutboundFrames(frames);
            for (frames) |frame| {
                if (frame != .stream) continue;
                try self.validateStreamFrameForSend(frame.stream);
            }
        }

        const PreparedPacket = struct {
            frames: []const quic.Frame,
            packet_number: u64,
            packet_number_len: u8,
            payload_offset: usize,
            payload_len: usize,
            packet_len: usize,
            ack_eliciting: bool,
            in_flight: bool,
            stream_bytes: u64,
        };
        var prepared: [max_batch_packets]PreparedPacket = undefined;
        std.debug.assert(self.send_batch_stream_scratch.items.len == 0);
        std.debug.assert(
            self.send_batch_packet_stream_scratch.items.len == 0,
        );
        const planned_streams = &self.send_batch_stream_scratch;
        defer planned_streams.clearRetainingCapacity();
        const packet_streams = &self.send_batch_packet_stream_scratch;
        defer packet_streams.clearRetainingCapacity();
        var simulated_pacer = self.pacer;
        const now_ns = sent_time_ns orelse self.monotonicNowNs();
        const smoothed_rtt = self.rtt_stats.smoothedOrInitial();
        var next_pacing_deadline: ?u64 = null;
        var count: usize = 0;
        var total_stream_bytes: u64 = 0;
        var total_in_flight: usize = 0;
        var total_payload_len: usize = 0;
        var total_packet_len: usize = 0;
        std.debug.assert(self.send_frame_buffer.items.len == 0);
        defer self.send_frame_buffer.items.len = 0;

        while (count < encryptable) {
            const frames = packets[count];
            var payload_len: usize = 0;
            for (frames) |frame| {
                payload_len = std.math.add(
                    usize,
                    payload_len,
                    try frame.wireLen(),
                ) catch return error.InvalidFrameLength;
            }
            const packet_number = self.next_packet_number + count;
            const packet_number_len =
                quic.protection.packetNumberLenForPayload(
                    packet_number,
                    self.sent.largestAcknowledged(),
                    payload_len,
                );
            const overhead = try quic.protection.shortPacketLen(.{
                .destination_connection_id = self.config.peer_connection_id,
                .packet_number = packet_number,
                .packet_number_len = packet_number_len,
                .payload = &.{},
            });
            const packet_len = std.math.add(
                usize,
                overhead,
                payload_len,
            ) catch return error.InvalidPayloadLength;
            if (packet_len > self.endpoint.limits.max_datagram_size) {
                return error.DatagramTooLarge;
            }

            const in_flight = packetInFlight(frames);
            if (in_flight) {
                if (simulated_pacer.deadlineAt(
                    now_ns,
                    packet_len,
                    self.congestion.congestion_window,
                    smoothed_rtt,
                )) |deadline| {
                    self.pacing_blocked_until_ns = deadline;
                    if (count == 0) return error.PacingLimited;
                    next_pacing_deadline = deadline;
                    break;
                }
                if (payload_len > self.congestion.available() -
                    @min(self.congestion.available(), total_in_flight))
                {
                    if (count == 0) return error.CongestionLimited;
                    break;
                }
            }

            packet_streams.clearRetainingCapacity();
            var packet_stream_bytes: u64 = 0;
            for (frames) |frame| {
                if (frame != .stream) continue;
                const bytes = std.math.cast(
                    u64,
                    frame.stream.data.len,
                ) orelse return error.InvalidFrameLength;
                packet_stream_bytes = std.math.add(
                    u64,
                    packet_stream_bytes,
                    bytes,
                ) catch return error.InvalidFrameLength;
                try addReservedStreamCredit(
                    packet_streams,
                    self.endpoint.allocator,
                    frame.stream.stream_id,
                    bytes,
                );
            }
            if (packet_stream_bytes > self.send_flow.available() -
                @min(self.send_flow.available(), total_stream_bytes))
            {
                if (count == 0) {
                    try self.sendDataBlocked();
                    return error.FlowControlBlocked;
                }
                break;
            }
            var blocked_stream: ?struct { id: u64, limit: u64 } = null;
            for (packet_streams.items) |credit| {
                const planned = reservedStreamBytes(
                    planned_streams.items,
                    credit.stream_id,
                );
                const available = if (self.findSendStreamEntry(
                    credit.stream_id,
                )) |entry|
                    entry.flow.available()
                else
                    self.initialSendStreamDataLimit(credit.stream_id);
                if (credit.bytes > available - @min(available, planned)) {
                    blocked_stream = .{
                        .id = credit.stream_id,
                        .limit = available,
                    };
                    break;
                }
            }
            if (blocked_stream) |blocked| {
                if (count == 0) {
                    try self.sendStreamDataBlocked(
                        blocked.id,
                        blocked.limit,
                    );
                    return error.FlowControlBlocked;
                }
                break;
            }

            for (packet_streams.items) |credit| {
                try addReservedStreamCredit(
                    planned_streams,
                    self.endpoint.allocator,
                    credit.stream_id,
                    credit.bytes,
                );
            }
            const payload_offset = self.send_frame_buffer.items.len;
            for (frames) |frame| {
                try frame.write(
                    &self.send_frame_buffer,
                    self.endpoint.allocator,
                );
            }
            std.debug.assert(
                self.send_frame_buffer.items.len - payload_offset ==
                    payload_len,
            );
            prepared[count] = .{
                .frames = frames,
                .packet_number = packet_number,
                .packet_number_len = packet_number_len,
                .payload_offset = payload_offset,
                .payload_len = payload_len,
                .packet_len = packet_len,
                .ack_eliciting = ackEliciting(frames),
                .in_flight = in_flight,
                .stream_bytes = packet_stream_bytes,
            };
            total_stream_bytes += packet_stream_bytes;
            total_payload_len += payload_len;
            total_packet_len += packet_len;
            if (in_flight) {
                total_in_flight += payload_len;
                simulated_pacer.onPacketSentAt(
                    now_ns,
                    packet_len,
                    self.congestion.congestion_window,
                    smoothed_rtt,
                );
            }
            count += 1;
        }
        if (count == 0) return error.MissingFrame;

        try self.send_packet_buffer.ensureTotalCapacity(
            self.endpoint.allocator,
            total_packet_len,
        );
        for (planned_streams.items) |credit| {
            _ = try self.sendStreamEntry(credit.stream_id);
        }

        var connection_flow_reserved = false;
        var reserved_stream_count: usize = 0;
        errdefer {
            if (connection_flow_reserved) {
                self.send_flow.used -|= total_stream_bytes;
            }
            for (planned_streams.items[0..reserved_stream_count]) |credit| {
                const entry =
                    self.findSendStreamEntry(credit.stream_id) orelse continue;
                entry.flow.used -|= credit.bytes;
            }
        }
        if (total_stream_bytes != 0) {
            try self.send_flow.reserve(total_stream_bytes);
            connection_flow_reserved = true;
        }
        for (planned_streams.items) |credit| {
            const entry = self.findSendStreamEntry(credit.stream_id).?;
            try entry.flow.reserve(credit.bytes);
            reserved_stream_count += 1;
        }

        var congestion_reserved = false;
        errdefer if (congestion_reserved) {
            self.congestion.discard(total_in_flight);
        };
        if (total_in_flight != 0) {
            try self.congestion.reserve(total_in_flight);
        }
        congestion_reserved = true;

        var tracked_recovery_count: usize = 0;
        errdefer for (prepared[0..tracked_recovery_count]) |packet| {
            _ = self.recovery.forgetPacketNumber(packet.packet_number);
        };
        var tracked_sent_count: usize = 0;
        errdefer for (prepared[0..tracked_sent_count]) |packet| {
            _ = self.sent.forget(packet.packet_number);
        };
        for (prepared[0..count]) |packet| {
            const payload = self.send_frame_buffer.items[packet.payload_offset..][0..packet.payload_len];
            if (packet.ack_eliciting) {
                try self.recovery.trackSent(packet.packet_number, payload);
            }
            tracked_recovery_count += 1;
            try self.sent.sentInFlightAt(
                packet.packet_number,
                packet.ack_eliciting,
                packet.in_flight,
                packet.payload_len,
                .not_ect,
                sent_time_ns,
            );
            tracked_sent_count += 1;
        }

        try self.reserveAntiAmplification(total_payload_len);
        var anti_amplification_reserved = true;
        errdefer if (anti_amplification_reserved) {
            self.releaseAntiAmplification(total_payload_len);
        };

        if (needs_key_update) {
            try self.prepareAeadForEncryption(
                self.next_packet_number,
                sent_time_ns,
            );
        }
        self.send_packet_buffer.items.len =
            self.send_packet_buffer.capacity;
        defer self.send_packet_buffer.items.len = 0;
        var datagrams: [max_batch_packets][]const u8 = undefined;
        var packet_offset: usize = 0;
        var protected_count: usize = 0;
        errdefer if (protected_count != 0) {
            self.next_packet_number += protected_count;
            if (needs_key_update) {
                self.pending_key_update_ack_threshold =
                    self.next_packet_number;
            }
        };
        for (prepared[0..count], 0..) |packet, i| {
            const payload = self.send_frame_buffer.items[packet.payload_offset..][0..packet.payload_len];
            const sealed = try quic.protection.sealShortPacketInto(
                self.send_packet_buffer.items[packet_offset..][0..packet.packet_len],
                self.send_key_phase.currentKeys(),
                .{
                    .destination_connection_id = self.config.peer_connection_id,
                    .packet_number = packet.packet_number,
                    .packet_number_len = packet.packet_number_len,
                    .spin_bit = self.nextSpinBit(),
                    .key_phase = self.send_key_phase.currentKeyPhase(),
                    .payload = payload,
                },
            );
            self.recordPacketEncrypted();
            protected_count += 1;
            datagrams[i] = sealed;
            packet_offset += sealed.len;
        }

        const send_result = try self.endpoint.sendManyBytesProgress(
            self.config.peer,
            datagrams[0..count],
        );
        std.debug.assert(send_result.sent_count <= count);

        var sent_payload_len: usize = 0;
        var sent_in_flight: usize = 0;
        var sent_stream_bytes: u64 = 0;
        for (prepared[0..send_result.sent_count]) |packet| {
            sent_payload_len += packet.payload_len;
            sent_stream_bytes += packet.stream_bytes;
            if (packet.in_flight) {
                sent_in_flight += packet.payload_len;
                self.pacer.onPacketSentAt(
                    now_ns,
                    packet.packet_len,
                    self.congestion.congestion_window,
                    smoothed_rtt,
                );
                self.congestion.onPacketSent(packet.packet_number);
            }
            self.noteSentStreams(packet.frames);
        }
        self.releaseAntiAmplification(
            total_payload_len - sent_payload_len,
        );
        anti_amplification_reserved = false;
        self.congestion.discard(total_in_flight - sent_in_flight);
        congestion_reserved = false;

        self.send_flow.used -|= total_stream_bytes - sent_stream_bytes;
        for (prepared[send_result.sent_count..count]) |packet| {
            for (packet.frames) |frame| {
                if (frame != .stream or frame.stream.data.len == 0) continue;
                const entry = self.findSendStreamEntry(
                    frame.stream.stream_id,
                ) orelse continue;
                entry.flow.used -|= frame.stream.data.len;
            }
            _ = self.recovery.forgetPacketNumber(packet.packet_number);
            _ = self.sent.forget(packet.packet_number);
        }
        connection_flow_reserved = false;
        reserved_stream_count = 0;
        tracked_recovery_count = 0;
        tracked_sent_count = 0;

        // Protection itself consumes the nonce even if sendmmsg accepts only a
        // prefix. QUIC permits packet-number gaps, so skip the unsent suffix.
        self.next_packet_number += protected_count;
        protected_count = 0;
        if (needs_key_update and send_result.sent_count == 0) {
            self.pending_key_update_ack_threshold =
                self.next_packet_number;
        }
        self.pacing_blocked_until_ns = next_pacing_deadline;
        return .{
            .sent_count = send_result.sent_count,
            .protected_count = count,
            .send_error = send_result.send_error,
        };
    }

    pub fn sendWithEcn(self: *Connection, frames: []const quic.Frame, ecn: quic.packet_space.EcnCodepoint) Error!void {
        while (true) {
            const now_ns = self.monotonicNowNs();
            self.sendWithEcnAt(frames, ecn, now_ns) catch |err| switch (err) {
                error.PacingLimited => {
                    try self.waitForPacing(now_ns);
                    continue;
                },
                else => return err,
            };
            return;
        }
    }

    pub fn sendAt(self: *Connection, frames: []const quic.Frame, sent_time_ns: u64) Error!void {
        try self.sendWithEcnAt(frames, .not_ect, sent_time_ns);
    }

    pub fn sendWithEcnAt(self: *Connection, frames: []const quic.Frame, ecn: quic.packet_space.EcnCodepoint, sent_time_ns: ?u64) Error!void {
        self.pacing_blocked_until_ns = null;
        if (self.close_info != null or self.idle_timed_out) return error.ConnectionClosed;
        if (ecn != .not_ect and self.sent.ecnDisabled()) return error.EcnDisabled;
        try self.validateNextPacketNumber();
        try self.validateOutboundFrames(frames);
        const stream_bytes = countStreamBytes(frames);
        for (frames) |frame| {
            if (frame != .stream) continue;
            try self.validateStreamFrameForSend(frame.stream);
        }
        const prepared = try self.prepareFramesForSend(frames, sent_time_ns);
        defer self.send_frame_buffer.items.len = 0;
        const qlog_now_ns = sent_time_ns orelse self.monotonicNowNs();

        // Pacing preflight above is deliberately mutation-free. Once it
        // succeeds, materialize any new stream entries before flow-control
        // checks so MAX_STREAM_DATA can subsequently refer to a stream whose
        // first attempted write was flow-control blocked.
        for (frames) |frame| {
            if (frame != .stream) continue;
            _ = try self.sendStreamEntry(frame.stream.stream_id);
        }

        if (stream_bytes > self.send_flow.available()) {
            self.send_frame_buffer.items.len = 0;
            try self.sendDataBlocked();
            return error.FlowControlBlocked;
        }
        for (frames) |frame| {
            if (frame != .stream or frame.stream.data.len == 0) continue;
            const available = if (self.findSendStreamEntry(frame.stream.stream_id)) |entry|
                entry.flow.available()
            else
                self.initialSendStreamDataLimit(frame.stream.stream_id);
            if (frame.stream.data.len > available) {
                self.send_frame_buffer.items.len = 0;
                try self.sendStreamDataBlocked(frame.stream.stream_id, available);
                return error.FlowControlBlocked;
            }
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
            try self.send_flow.reserve(stream_bytes);
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
            try entry.flow.reserve(frame.stream.data.len);
            reserved_streams.items[reserved_index].bytes = frame.stream.data.len;
        }
        try self.sendPreparedFramesEcnAtUnchecked(prepared, ecn, sent_time_ns);
        self.observePacketSent(
            qlog_now_ns,
            self.next_packet_number - 1,
            prepared.packet_len,
            frames,
        );
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
        const payload = self.datagram_recv_queue.pop() orelse return null;
        defer self.endpoint.allocator.free(payload);
        if (payload.len > out.len) return error.DatagramBufferTooSmall;
        @memcpy(out[0..payload.len], payload);
        return out[0..payload.len];
    }

    pub fn datagramReceiveQueueLen(self: Connection) usize {
        return self.datagram_recv_queue.count();
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

    pub fn congestionAlgorithm(self: Connection) quic.congestion.Algorithm {
        return self.congestion.algorithm;
    }

    pub fn congestionWindow(self: Connection) usize {
        return self.congestion.congestion_window;
    }

    pub fn congestionAvailable(self: Connection) usize {
        return self.congestion.available();
    }

    pub fn bytesInFlight(self: Connection) usize {
        return self.congestion.bytes_in_flight;
    }

    pub fn hystartEnabled(self: Connection) bool {
        return self.congestion.hystart.enabled;
    }

    pub fn hystartPhase(self: Connection) quic.hystart.Phase {
        return self.congestion.hystart.phase;
    }

    pub fn pacingEnabled(self: Connection) bool {
        return self.pacer.enabled;
    }

    pub fn pacingBudgetAt(self: Connection, now_ns: u64) usize {
        return self.pacer.budgetAt(now_ns, self.congestion.congestion_window, self.rtt_stats.smoothedOrInitial());
    }

    pub fn pacingDeadlineAt(self: Connection, now_ns: u64, packet_size: usize) ?u64 {
        return self.pacer.deadlineAt(
            now_ns,
            packet_size,
            self.congestion.congestion_window,
            self.rtt_stats.smoothedOrInitial(),
        );
    }

    pub fn nextPacketPacingDeadlineAt(self: Connection, now_ns: u64, payload_len: usize) Error!?u64 {
        const packet_number_len = quic.protection.packetNumberLenForPayload(
            self.next_packet_number,
            self.sent.largestAcknowledged(),
            payload_len,
        );
        const packet_len = try quic.protection.shortPacketLen(.{
            .destination_connection_id = self.config.peer_connection_id,
            .packet_number = self.next_packet_number,
            .packet_number_len = packet_number_len,
            .payload = &.{},
        });
        const full_packet_len = std.math.add(usize, packet_len, payload_len) catch return error.InvalidPayloadLength;
        return self.pacingDeadlineAt(now_ns, full_packet_len);
    }

    pub fn sendAckFrequency(self: *Connection, ack_eliciting_threshold: u64, request_max_ack_delay: u64, reordering_threshold: u64) Error!u64 {
        if (!self.config.enable_ack_frequency) return error.AckFrequencyDisabled;
        try self.validateNextPacketNumber();
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
        while (true) {
            const now_ns = self.monotonicNowNs();
            self.sendTrackedFramesEcnAt(frames, ecn, now_ns) catch |err| switch (err) {
                error.PacingLimited => {
                    try self.waitForPacing(now_ns);
                    continue;
                },
                else => return err,
            };
            return;
        }
    }

    fn sendTrackedFramesEcnAt(self: *Connection, frames: []const quic.Frame, ecn: quic.packet_space.EcnCodepoint, sent_time_ns: ?u64) Error!void {
        try self.validateOutboundFrames(frames);
        try self.sendTrackedFramesEcnAtUnchecked(frames, ecn, sent_time_ns);
    }

    fn sendTrackedFramesEcnAtUnchecked(self: *Connection, frames: []const quic.Frame, ecn: quic.packet_space.EcnCodepoint, sent_time_ns: ?u64) Error!void {
        try self.validateNextPacketNumber();
        const prepared = try self.prepareFramesForSend(frames, sent_time_ns);
        defer self.send_frame_buffer.items.len = 0;
        const qlog_now_ns = sent_time_ns orelse self.monotonicNowNs();
        try self.sendPreparedFramesEcnAtUnchecked(prepared, ecn, sent_time_ns);
        self.observePacketSent(
            qlog_now_ns,
            self.next_packet_number - 1,
            prepared.packet_len,
            frames,
        );
    }

    const PreparedFrames = struct {
        payload: []const u8,
        packet_number_len: u8,
        packet_len: usize,
        is_ack_eliciting: bool,
        is_in_flight: bool,
    };

    fn prepareFramesForSend(self: *Connection, frames: []const quic.Frame, sent_time_ns: ?u64) Error!PreparedFrames {
        std.debug.assert(self.send_frame_buffer.items.len == 0);
        errdefer self.send_frame_buffer.items.len = 0;
        for (frames) |frame| try frame.write(&self.send_frame_buffer, self.endpoint.allocator);
        const payload = self.send_frame_buffer.items;
        const is_ack_eliciting = ackEliciting(frames);
        const is_in_flight = packetInFlight(frames);
        const packet_number_len = quic.protection.packetNumberLenForPayload(
            self.next_packet_number,
            self.sent.largestAcknowledged(),
            payload.len,
        );
        const packet_len = try quic.protection.shortPacketLen(.{
            .destination_connection_id = self.config.peer_connection_id,
            .packet_number = self.next_packet_number,
            .packet_number_len = packet_number_len,
            .payload = payload,
        });
        if (is_in_flight) if (sent_time_ns) |now_ns| {
            if (self.pacingDeadlineAt(now_ns, packet_len)) |deadline| {
                self.pacing_blocked_until_ns = deadline;
                return error.PacingLimited;
            }
        };

        return .{
            .payload = payload,
            .packet_number_len = packet_number_len,
            .packet_len = packet_len,
            .is_ack_eliciting = is_ack_eliciting,
            .is_in_flight = is_in_flight,
        };
    }

    fn sendPreparedFramesEcnAtUnchecked(
        self: *Connection,
        prepared: PreparedFrames,
        ecn: quic.packet_space.EcnCodepoint,
        sent_time_ns: ?u64,
    ) Error!void {
        const packet_number = self.next_packet_number;
        const payload = prepared.payload;
        var tracked_congestion = false;
        if (prepared.is_in_flight) {
            try self.congestion.reserve(payload.len);
            tracked_congestion = true;
        }
        errdefer {
            if (tracked_congestion) self.congestion.discard(payload.len);
        }
        var tracked_recovery = false;
        if (prepared.is_ack_eliciting) {
            try self.recovery.trackSent(packet_number, payload);
            tracked_recovery = true;
        }
        errdefer {
            if (tracked_recovery) _ = self.recovery.forgetPacketNumber(packet_number);
        }
        try self.sent.sentInFlightAt(packet_number, prepared.is_ack_eliciting, prepared.is_in_flight, payload.len, ecn, sent_time_ns);
        errdefer _ = self.sent.forget(packet_number);
        try self.sendPayloadPacketWithPacketNumberLenAt(
            packet_number,
            payload,
            prepared.packet_number_len,
            ecn,
            sent_time_ns,
            prepared.is_in_flight,
        );
        self.next_packet_number += 1;
    }

    fn validateOutboundFrames(self: Connection, frames: []const quic.Frame) Error!void {
        if (frames.len == 0) return error.MissingFrame;
        for (frames) |frame| {
            try quic.validateFrameForPacketType(frame, .one_rtt);
            switch (frame) {
                .new_token => |new_token| {
                    // RFC 9000 server-only frames should be blocked before the
                    // packet is encoded.  s2n-quic/tquic gate HANDSHAKE_DONE
                    // and NEW_TOKEN at transmission time; doing so here keeps
                    // generic send() from bypassing the dedicated helpers.
                    if (self.config.local_endpoint != .server) return error.InvalidFrame;
                    if (new_token.token.len == 0) return error.InvalidFrame;
                },
                .handshake_done => {
                    if (self.config.local_endpoint != .server) return error.InvalidFrame;
                },
                .datagram => |datagram| {
                    const frame_limit = self.config.peer_max_datagram_frame_size orelse return error.DatagramsNotEnabled;
                    const frame_size = datagramFrameWireSize(datagram) orelse return error.InvalidFrameLength;
                    if (frame_size > frame_limit) return error.DatagramTooLarge;
                },
                .ack_frequency, .immediate_ack => if (!self.config.enable_ack_frequency) return error.AckFrequencyDisabled,
                else => {},
            }
        }
    }

    pub fn pmtudCurrentSize(self: Connection) usize {
        return self.pmtud.currentSize();
    }

    pub fn pmtudShouldProbe(self: Connection) bool {
        return self.pmtud.shouldProbe();
    }

    pub fn sendPmtuProbeAt(self: *Connection, peer_max_udp_payload: usize, sent_time_ns: ?u64) Error!?usize {
        try self.validateNextPacketNumber();
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
        try self.sendPayloadPacketWithPacketNumberLenAt(packet_number, payload.items, packet_number_len, .not_ect, sent_time_ns, true);
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

    fn sendPayloadPacketAt(self: *Connection, packet_number: u64, payload: []const u8, sent_time_ns: ?u64, pace_packet: bool) Error!void {
        try self.sendPayloadPacketWithPacketNumberLenAt(
            packet_number,
            payload,
            quic.protection.packetNumberLenForPayload(packet_number, self.sent.largestAcknowledged(), payload.len),
            .not_ect,
            sent_time_ns,
            pace_packet,
        );
    }

    fn sendPayloadPacketWithPacketNumberLenAt(
        self: *Connection,
        packet_number: u64,
        payload: []const u8,
        packet_number_len: u8,
        ecn: quic.packet_space.EcnCodepoint,
        sent_time_ns: ?u64,
        pace_packet: bool,
    ) Error!void {
        try self.prepareAeadForEncryption(packet_number, sent_time_ns);
        try self.reserveAntiAmplification(payload.len);
        errdefer self.releaseAntiAmplification(payload.len);
        const packet_options: quic.protection.ShortPacketOptions = .{
            .destination_connection_id = self.config.peer_connection_id,
            .packet_number = packet_number,
            .packet_number_len = packet_number_len,
            .spin_bit = self.nextSpinBit(),
            .key_phase = self.send_key_phase.currentKeyPhase(),
            .payload = payload,
        };
        const packet_len = try quic.protection.shortPacketLen(packet_options);
        try self.send_packet_buffer.ensureTotalCapacity(self.endpoint.allocator, packet_len);
        self.send_packet_buffer.items.len = self.send_packet_buffer.capacity;
        defer self.send_packet_buffer.items.len = 0;
        const packet = try quic.protection.sealShortPacketInto(
            self.send_packet_buffer.items,
            self.send_key_phase.currentKeys(),
            packet_options,
        );
        self.recordPacketEncrypted();
        const now_ns = sent_time_ns orelse self.monotonicNowNs();
        if (pace_packet) {
            if (self.pacer.deadlineAt(
                now_ns,
                packet.len,
                self.congestion.congestion_window,
                self.rtt_stats.smoothedOrInitial(),
            )) |deadline| {
                self.pacing_blocked_until_ns = deadline;
                return error.PacingLimited;
            }
        }
        try self.endpoint.sendBytesWithEcn(self.config.peer, packet, ecn);
        if (pace_packet) {
            self.pacer.onPacketSentAt(
                now_ns,
                packet.len,
                self.congestion.congestion_window,
                self.rtt_stats.smoothedOrInitial(),
            );
            self.congestion.onPacketSent(packet_number);
        }
        self.pacing_blocked_until_ns = null;
    }

    fn aeadConfidentialityLimit(self: Connection) u64 {
        return @min(
            self.config.aead_confidentiality_limit,
            quic.protection.aes_128_gcm_confidentiality_limit,
        );
    }

    fn aeadIntegrityLimit(self: Connection) u64 {
        return @min(
            self.config.aead_integrity_limit,
            quic.protection.aes_128_gcm_integrity_limit,
        );
    }

    fn prepareAeadForEncryption(
        self: *Connection,
        packet_number: u64,
        now_ns: ?u64,
    ) Error!void {
        const limit = self.aeadConfidentialityLimit();
        if (self.send_key_generation_encrypted_packets < limit) return;
        if (limit == 0 or self.pending_key_update_ack_threshold != null) {
            try self.enterAeadLimitReached("confidentiality limit", null, false);
            return error.AeadLimitReached;
        }
        self.advanceSendKeyPhase(packet_number, now_ns);
    }

    fn recordPacketEncrypted(self: *Connection) void {
        self.send_key_generation_encrypted_packets +|= 1;
    }

    fn advanceSendKeyPhase(
        self: *Connection,
        first_packet_number: u64,
        now_ns: ?u64,
    ) void {
        self.send_key_phase.initiateKeyUpdate();
        self.pending_key_update_ack_threshold = first_packet_number;
        self.send_key_generation_encrypted_packets = 0;
        if (self.config.qlog_observer) |observer| {
            observer.keyUpdated(
                self.qlogEventTime(now_ns orelse self.monotonicNowNs()),
                "local_update",
                oneRttKeyType(self.config.local_endpoint),
                self.send_key_phase.keyUpdateCount(),
            );
        }
    }

    fn recordAuthenticationFailureAt(self: *Connection, now_ns: ?u64) Error!void {
        self.receive_authentication_failures +|= 1;
        if (self.receive_authentication_failures < self.aeadIntegrityLimit()) return;
        try self.enterAeadLimitReached("integrity limit", nsToMs(now_ns), true);
        return error.AeadLimitReached;
    }

    fn enterAeadLimitReached(
        self: *Connection,
        reason_phrase: []const u8,
        now_ms: ?u64,
        send_close: bool,
    ) Error!void {
        const code = @intFromEnum(quic.TransportErrorCode.aead_limit_reached);
        if (send_close and self.close_info == null) {
            // Integrity exhaustion counts failed decryptions and does not
            // consume outgoing confidentiality budget, so RFC 9001 permits a
            // final protected CONNECTION_CLOSE. Socket/allocation failure must
            // not prevent the mandatory local terminal transition.
            const frames = [_]quic.Frame{.{ .connection_close = .{
                .error_code = code,
                .frame_type = 0,
                .reason_phrase = reason_phrase,
            } }};
            self.sendTrackedFrames(&frames) catch {};
        }
        // Once outgoing confidentiality keys are exhausted, even a close
        // packet would exceed their AEAD limit. In both cases record terminal
        // state locally so no further packet can be processed or emitted.
        try self.setCloseInfo(.{
            .application = false,
            .error_code = code,
            .frame_type = 0,
            .reason_phrase = reason_phrase,
            .state = .closing,
            .now_ms = now_ms,
            .pto_ms = null,
        });
    }

    pub fn retransmitPto(self: *Connection) Error!bool {
        return self.retransmitPtoAt(self.monotonicNowNs());
    }

    pub fn retransmitPtoAt(self: *Connection, now_ns: ?u64) Error!bool {
        return (try self.retransmitPtoProbesAt(now_ns, 1)) != 0;
    }

    pub fn retransmitPtoProbesAt(self: *Connection, now_ns: ?u64, max_probes: usize) Error!usize {
        if (max_probes == 0) return 0;
        const limit = @min(max_probes, self.recovery.pendingCount());
        if (limit > 1) {
            return try self.retransmitPtoProbeBatchesAt(now_ns, limit);
        }
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
            period = std.math.mul(u64, period, 2) catch return quic.rtt.max_pto_ns;
            if (period >= quic.rtt.max_pto_ns) return quic.rtt.max_pto_ns;
        }
        return @min(@max(period, quic.rtt.timer_granularity_ns), quic.rtt.max_pto_ns);
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

    const PreparedPtoProbe = struct {
        candidate: quic.recovery.Candidate,
        packet_number: u64,
        packet_number_len: u8,
        packet_len: usize,
    };

    const PtoProbeBatchResult = struct {
        sent_count: usize,
        send_error: ?net.Socket.SendError = null,
    };

    fn retransmitPtoProbeBatchesAt(self: *Connection, now_ns: ?u64, limit: usize) Error!usize {
        var sent_count: usize = 0;
        while (sent_count < limit) {
            const remaining = limit - sent_count;
            const result = try self.retransmitPtoProbeBatchAt(sent_count, remaining, now_ns);
            sent_count += result.sent_count;
            if (result.send_error) |err| {
                // A sendmmsg-style backend can emit a prefix before the next
                // datagram fails. Those probes are real PTO transmissions even
                // though the caller still needs the socket error.
                if (sent_count != 0) self.incrementPtoCount();
                return err;
            }
            if (result.sent_count == 0) break;
            if (result.sent_count < @min(remaining, max_batch_packets)) break;
        }
        if (sent_count != 0) self.incrementPtoCount();
        return sent_count;
    }

    fn retransmitPtoProbeBatchAt(self: *Connection, first_candidate_index: usize, remaining_limit: usize, sent_time_ns: ?u64) Error!PtoProbeBatchResult {
        const batch_limit = @min(remaining_limit, max_batch_packets);
        var probes: [max_batch_packets]PreparedPtoProbe = undefined;
        var total_payload_len: usize = 0;
        var total_packet_len: usize = 0;
        var count: usize = 0;
        var simulated_pacer = self.pacer;
        var paced_blocked_until_ns: ?u64 = null;
        const now_ns = sent_time_ns orelse self.monotonicNowNs();
        while (count < batch_limit) : (count += 1) {
            const candidate = self.recovery.ptoCandidateAt(first_candidate_index + count) orelse break;
            const packet_number = std.math.add(u64, self.next_packet_number, count) catch return error.InvalidPacketNumber;
            if (packet_number > quic.protection.max_packet_number) return error.InvalidPacketNumber;
            const packet_number_len = quic.protection.packetNumberLenForPayload(packet_number, self.sent.largestAcknowledged(), candidate.payload.len);
            const packet_len = try quic.protection.shortPacketLen(.{
                .destination_connection_id = self.config.peer_connection_id,
                .packet_number = packet_number,
                .packet_number_len = packet_number_len,
                .payload = candidate.payload,
            });
            if (packet_len > self.endpoint.limits.max_datagram_size) return error.DatagramTooLarge;

            if (self.antiAmplificationLimitRemaining()) |credit| {
                const reserved = std.math.add(usize, total_payload_len, candidate.payload.len) catch return error.AntiAmplificationLimited;
                if (reserved > credit) {
                    if (count != 0) break;
                    return error.AntiAmplificationLimited;
                }
            }

            if (simulated_pacer.deadlineAt(
                now_ns,
                packet_len,
                self.congestion.congestion_window,
                self.rtt_stats.smoothedOrInitial(),
            )) |deadline| {
                paced_blocked_until_ns = deadline;
                if (count != 0) break;
                self.pacing_blocked_until_ns = deadline;
                return error.PacingLimited;
            }
            simulated_pacer.onPacketSentAt(
                now_ns,
                packet_len,
                self.congestion.congestion_window,
                self.rtt_stats.smoothedOrInitial(),
            );

            probes[count] = .{
                .candidate = candidate,
                .packet_number = packet_number,
                .packet_number_len = packet_number_len,
                .packet_len = packet_len,
            };
            total_payload_len = std.math.add(usize, total_payload_len, candidate.payload.len) catch return error.InvalidPayloadLength;
            total_packet_len = std.math.add(usize, total_packet_len, packet_len) catch return error.InvalidPayloadLength;
        }
        if (count == 0) return .{ .sent_count = 0 };

        try self.reserveAntiAmplification(total_payload_len);
        errdefer self.releaseAntiAmplification(total_payload_len);

        var tracked_congestion: usize = 0;
        errdefer if (tracked_congestion != 0) self.congestion.discard(tracked_congestion);
        var recorded_recovery_count: usize = 0;
        errdefer {
            var i: usize = 0;
            while (i < recorded_recovery_count) : (i += 1) {
                _ = self.recovery.forgetPacketNumber(probes[i].packet_number);
            }
        }
        var tracked_sent_count: usize = 0;
        errdefer {
            var i: usize = 0;
            while (i < tracked_sent_count) : (i += 1) {
                _ = self.sent.forget(probes[i].packet_number);
            }
        }

        for (probes[0..count]) |probe| {
            self.congestion.onPtoProbeSent(probe.candidate.payload.len);
            tracked_congestion += probe.candidate.payload.len;
            try self.recovery.recordRetransmission(probe.candidate.group_index, probe.packet_number);
            recorded_recovery_count += 1;
            try self.sent.sentAt(probe.packet_number, true, probe.candidate.payload.len, .not_ect, sent_time_ns);
            tracked_sent_count += 1;
        }

        try self.send_packet_buffer.ensureTotalCapacity(self.endpoint.allocator, total_packet_len);
        self.send_packet_buffer.items.len = self.send_packet_buffer.capacity;
        defer self.send_packet_buffer.items.len = 0;

        var datagrams: [max_batch_packets][]const u8 = undefined;
        var packet_offset: usize = 0;
        for (probes[0..count], 0..) |probe, i| {
            try self.prepareAeadForEncryption(
                probe.packet_number,
                sent_time_ns,
            );
            const packet = try quic.protection.sealShortPacketInto(
                self.send_packet_buffer.items[packet_offset..][0..probe.packet_len],
                self.send_key_phase.currentKeys(),
                .{
                    .destination_connection_id = self.config.peer_connection_id,
                    .packet_number = probe.packet_number,
                    .packet_number_len = probe.packet_number_len,
                    .spin_bit = self.nextSpinBit(),
                    .key_phase = self.send_key_phase.currentKeyPhase(),
                    .payload = probe.candidate.payload,
                },
            );
            self.recordPacketEncrypted();
            datagrams[i] = packet;
            std.debug.assert(packet.len == probe.packet_len);
            packet_offset += packet.len;
        }

        const send_result = try self.endpoint.sendManyBytesProgress(self.config.peer, datagrams[0..count]);
        std.debug.assert(send_result.sent_count <= count);

        // All recovery and congestion entries are reserved before the socket
        // call so no allocation can fail after packets are visible on the
        // network. If only a prefix was accepted, retain exactly that prefix
        // and transactionally discard the unsent suffix.
        var sent_payload_len: usize = 0;
        for (probes[0..send_result.sent_count]) |probe| {
            sent_payload_len += probe.candidate.payload.len;
            self.pacer.onPacketSentAt(
                now_ns,
                probe.packet_len,
                self.congestion.congestion_window,
                self.rtt_stats.smoothedOrInitial(),
            );
            self.congestion.onPacketSent(probe.packet_number);
        }
        const unsent_payload_len = total_payload_len - sent_payload_len;
        self.releaseAntiAmplification(unsent_payload_len);
        self.congestion.discard(unsent_payload_len);
        for (probes[send_result.sent_count..count]) |probe| {
            _ = self.recovery.forgetPacketNumber(probe.packet_number);
            _ = self.sent.forget(probe.packet_number);
        }
        self.pacing_blocked_until_ns = paced_blocked_until_ns;
        self.next_packet_number += send_result.sent_count;
        return .{
            .sent_count = send_result.sent_count,
            .send_error = send_result.send_error,
        };
    }

    fn retransmitCandidate(self: *Connection, candidate: quic.recovery.Candidate, mode: RetransmitMode) Error!void {
        try self.retransmitCandidateAt(candidate, mode, self.monotonicNowNs());
    }

    fn retransmitCandidateAt(self: *Connection, candidate: quic.recovery.Candidate, mode: RetransmitMode, sent_time_ns: ?u64) Error!void {
        try self.validateNextPacketNumber();
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
        try self.sendPayloadPacketAt(packet_number, candidate.payload, sent_time_ns, true);
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

    /// Immediately acknowledge a processed packet batch when required.
    ///
    /// HTTP/3's blocking packet pump uses one ACK for an entire GRO batch. ACK,
    /// PADDING, and close-only batches do not elicit another ACK, preventing an
    /// ACK loop while still releasing sender congestion credit for STREAM and
    /// flow-control packets.
    pub fn sendAckForPacketsIfNeeded(
        self: *Connection,
        packets: []const ReceivedPacket,
    ) Error!bool {
        for (packets) |packet| {
            if (!ackEliciting(packet.frames)) continue;
            try self.sendAck(0);
            return true;
        }
        return false;
    }

    pub fn encodedLocalAckDelayNanos(self: Connection, ack_delay_ns: u64) Error!u64 {
        return quic.rtt.encodeAckDelayNanos(ack_delay_ns, self.config.local_ack_delay_exponent) catch |err| switch (err) {
            error.InvalidAckDelayExponent => error.InvalidFrame,
        };
    }

    pub fn resetStream(self: *Connection, stream_id: u64, application_error_code: u64) Error!void {
        try self.validateNextPacketNumber();
        const entry = try self.sendStreamEntry(stream_id);
        try self.sendResetStream(stream_id, application_error_code, entry.highest_sent_end);
    }

    pub fn sendStopSending(self: *Connection, stream_id: u64, application_error_code: u64) Error!void {
        try self.validateNextPacketNumber();
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

    /// Copy the currently assembled receive bytes for diagnostics and
    /// handshake-integrated early-data consumers. The returned slice is owned
    /// by the caller; consuming flow-control credit remains explicit.
    pub fn copyReceivedStream(
        self: Connection,
        allocator: std.mem.Allocator,
        stream_id: u64,
    ) Error!?[]u8 {
        for (self.stream_recv_flows.items) |entry| {
            if (entry.stream_id != stream_id) continue;
            return try allocator.dupe(u8, entry.recv_state.available());
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
        self.pacer.reset();
        try self.queuePathChallenge(challenge);
    }

    pub fn sendPendingPathChallenge(self: *Connection) Error!void {
        try self.sendPendingPathChallengeAt(null, null);
    }

    pub fn sendPendingPathChallengeAt(self: *Connection, now_ns: ?u64, timeout_ns: ?u64) Error!void {
        try self.validateNextPacketNumber();
        const frame = try self.path_validation.nextChallengeFrameAt(now_ns, timeout_ns);
        const frames = [_]quic.Frame{frame};
        try self.send(&frames);
    }

    pub fn sendPendingPathChallengesAt(self: *Connection, now_ns: ?u64, timeout_ns: ?u64) Error!usize {
        try self.validateNextPacketNumber();
        var frames: [8]quic.Frame = undefined;
        const count = try self.path_validation.nextChallengeFramesAt(&frames, now_ns, timeout_ns);
        if (count == 0) return 0;
        try self.send(frames[0..count]);
        return count;
    }

    pub fn pathValidationDeadline(self: Connection) ?u64 {
        return self.path_validation.earliestChallengeDeadline();
    }

    pub fn checkPathValidationTimeouts(self: *Connection, now_ns: u64) Error!usize {
        return try self.path_validation.checkTimeouts(now_ns);
    }

    pub fn sendPendingPathResponse(self: *Connection) Error!void {
        try self.validateNextPacketNumber();
        const frame = try self.path_validation.nextResponseFrame();
        const frames = [_]quic.Frame{frame};
        try self.send(&frames);
    }

    pub fn sendPendingPathResponses(self: *Connection) Error!usize {
        try self.validateNextPacketNumber();
        var frames: [8]quic.Frame = undefined;
        const count = self.path_validation.nextResponseFrames(&frames);
        if (count == 0) return 0;
        try self.send(frames[0..count]);
        return count;
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
        self.congestion.onRttSample(sample.largest_acknowledged, sample.latest_rtt_ns);
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
        try self.validateLocalConnectionIdIssueLimit(0);
        try self.validateNextPacketNumber();
        const frame = try self.local_connection_ids.issue(connection_id, stateless_reset_token);
        const frames = [_]quic.Frame{frame};
        try self.send(&frames);
    }

    pub fn sendNewConnectionIdRetiringPriorTo(
        self: *Connection,
        connection_id: []const u8,
        stateless_reset_token: [16]u8,
        retire_prior_to: u64,
    ) Error!void {
        try self.validateLocalConnectionIdIssueLimit(retire_prior_to);
        try self.validateNextPacketNumber();
        const frame = try self.local_connection_ids.issueWithRetirePriorTo(connection_id, stateless_reset_token, retire_prior_to);
        const frames = [_]quic.Frame{frame};
        try self.send(&frames);
    }

    pub fn sendNewConnectionIdWithDerivedToken(self: *Connection, connection_id: []const u8) Error!void {
        const key = self.config.local_stateless_reset_key orelse return error.InvalidConnectionId;
        try self.validateLocalConnectionIdIssueLimit(0);
        try self.validateNextPacketNumber();
        const frame = try self.local_connection_ids.issueWithStaticKey(connection_id, key);
        const frames = [_]quic.Frame{frame};
        try self.send(&frames);
    }

    pub fn sendNewConnectionIdQuicLb(
        self: *Connection,
        config: quic.quic_lb.Config,
        server_id: []const u8,
        nonce: []const u8,
        first_octet_random_bits: u5,
    ) Error!void {
        try self.sendNewConnectionIdQuicLbAt(
            config,
            server_id,
            nonce,
            first_octet_random_bits,
            0,
            null,
        );
    }

    pub fn sendNewConnectionIdQuicLbAt(
        self: *Connection,
        config: quic.quic_lb.Config,
        server_id: []const u8,
        nonce: []const u8,
        first_octet_random_bits: u5,
        retire_prior_to: u64,
        sent_time_ns: ?u64,
    ) Error!void {
        return self.sendNewConnectionIdQuicLbRetiringPriorTo(
            config,
            server_id,
            nonce,
            first_octet_random_bits,
            retire_prior_to,
            sent_time_ns,
        );
    }

    fn sendNewConnectionIdQuicLbRetiringPriorTo(
        self: *Connection,
        config: quic.quic_lb.Config,
        server_id: []const u8,
        nonce: []const u8,
        first_octet_random_bits: u5,
        retire_prior_to: u64,
        sent_time_ns: ?u64,
    ) Error!void {
        const reset_key = self.config.local_stateless_reset_key orelse
            return error.InvalidConnectionId;
        try self.validateLocalConnectionIdIssueLimit(retire_prior_to);
        try self.validateNextPacketNumber();

        // LocalPool is fixed-size state, so a value snapshot cheaply makes CID
        // issuance transactional with the packet send. A failed UDP write must
        // not consume an active-CID slot for an ID the peer never received.
        const pool_before = self.local_connection_ids;
        errdefer self.local_connection_ids = pool_before;
        const frame = try self.local_connection_ids.issueQuicLbRetirePriorTo(
            config,
            server_id,
            nonce,
            first_octet_random_bits,
            reset_key,
            retire_prior_to,
        );
        const frames = [_]quic.Frame{frame};
        if (sent_time_ns) |timestamp| {
            try self.sendAt(&frames, timestamp);
        } else {
            try self.send(&frames);
        }
    }

    fn validateLocalConnectionIdIssueLimit(self: Connection, retire_prior_to: u64) Error!void {
        // Retire Prior To lets a replacement NEW_CONNECTION_ID atomically ask
        // the peer to drop lower-numbered local CIDs.  Count only IDs that
        // remain active after that instruction, matching RFC 9000's active ID
        // limit semantics and mature stacks such as quicz.
        if (self.local_connection_ids.countAfterRetirePriorTo(retire_prior_to) >= self.config.peer_active_connection_id_limit) {
            return error.ActiveConnectionIdLimit;
        }
    }

    fn validateNextPacketNumber(self: Connection) Error!void {
        // QUIC packet numbers are limited to the varint range even though short
        // headers carry only a truncated encoding.  Check before any helper
        // allocates stream/CID/path-validation state so exhaustion is
        // transactional, matching mature stacks such as quicz.
        if (self.next_packet_number > quic.protection.max_packet_number) return error.InvalidPacketNumber;
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
        self.advanceSendKeyPhase(self.next_packet_number, null);
    }

    pub fn encryptedPacketsWithCurrentKeys(self: Connection) u64 {
        return self.send_key_generation_encrypted_packets;
    }

    pub fn authenticationFailureCount(self: Connection) u64 {
        return self.receive_authentication_failures;
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
        return self.receivePacketAt(self.monotonicNowNs());
    }

    pub fn receivePacketOrDropAfterClose(self: *Connection) Error!?ReceivedPacket {
        return self.receivePacketOrDropAfterCloseAt(self.monotonicNowNs());
    }

    pub fn receivePacketOrDropAfterCloseAt(self: *Connection, now_ns: ?u64) Error!?ReceivedPacket {
        if (self.close_info != null or self.idle_timed_out) return null;
        return try self.receivePacketAt(now_ns);
    }

    pub fn receivePacketAt(self: *Connection, now_ns: ?u64) Error!ReceivedPacket {
        if (self.close_info != null or self.idle_timed_out) return error.ConnectionClosed;
        var datagram = try self.endpoint.receiveBytes();
        defer datagram.deinit(self.endpoint.allocator);
        return try self.processReceivedBytesAt(datagram.from, datagram.bytes, datagram.ecn, now_ns);
    }

    /// Import authenticated 0-RTT frames into the shared application-data
    /// packet-number space after the TLS handshake commits early-data
    /// acceptance. The caller retains ownership of frame payloads.
    pub fn applyEarlyDataFrames(
        self: *Connection,
        packet_number: u64,
        frames: []const quic.Frame,
    ) Error!void {
        for (frames) |frame| {
            try quic.validateFrameForPacketType(frame, .zero_rtt);
        }
        try self.applyReceivedFrames(
            packet_number,
            frames,
            null,
            .not_ect,
        );
    }

    /// Import a successfully transmitted 0-RTT packet into the shared
    /// application-data send state. This preserves packet-number, flow-control,
    /// stream-offset, ACK validation, and loss-recovery continuity when the
    /// connection later installs 1-RTT keys.
    pub fn importSentEarlyData(
        self: *Connection,
        packet_number: u64,
        frames: []const quic.Frame,
    ) Error!void {
        if (packet_number != self.next_packet_number) {
            return error.InvalidPacketNumber;
        }
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(self.endpoint.allocator);
        var stream_bytes: u64 = 0;
        for (frames) |frame| {
            try quic.validateFrameForPacketType(frame, .zero_rtt);
            try frame.write(&payload, self.endpoint.allocator);
            if (frame != .stream) continue;
            try self.validateStreamFrameForSend(frame.stream);
            stream_bytes = std.math.add(
                u64,
                stream_bytes,
                frame.stream.data.len,
            ) catch return error.InvalidFrameLength;
            _ = try self.sendStreamEntry(frame.stream.stream_id);
        }
        if (frames.len == 0) return error.MissingFrame;

        try self.send_flow.reserve(stream_bytes);
        var connection_reserved = true;
        errdefer {
            if (connection_reserved) self.send_flow.used -|= stream_bytes;
        }

        var reserved_streams: std.ArrayList(ReservedStreamCredit) = .empty;
        defer reserved_streams.deinit(self.endpoint.allocator);
        errdefer for (reserved_streams.items) |reserved| {
            const entry = self.findSendStreamEntry(reserved.stream_id) orelse
                continue;
            entry.flow.used -|= reserved.bytes;
        };
        for (frames) |frame| {
            if (frame != .stream or frame.stream.data.len == 0) continue;
            try reserved_streams.append(self.endpoint.allocator, .{
                .stream_id = frame.stream.stream_id,
                .bytes = 0,
            });
            const entry = self.findSendStreamEntry(
                frame.stream.stream_id,
            ) orelse unreachable;
            try entry.flow.reserve(frame.stream.data.len);
            reserved_streams.items[reserved_streams.items.len - 1].bytes =
                frame.stream.data.len;
        }

        const is_ack_eliciting = ackEliciting(frames);
        const is_in_flight = packetInFlight(frames);
        if (is_ack_eliciting) {
            try self.recovery.trackSent(packet_number, payload.items);
        }
        errdefer {
            if (is_ack_eliciting) {
                _ = self.recovery.forgetPacketNumber(packet_number);
            }
        }
        try self.sent.sentInFlightAt(
            packet_number,
            is_ack_eliciting,
            is_in_flight,
            payload.items.len,
            .not_ect,
            null,
        );
        errdefer _ = self.sent.forget(packet_number);
        if (is_in_flight) {
            try self.congestion.reserve(payload.items.len);
        }
        errdefer {
            if (is_in_flight) self.congestion.discard(payload.items.len);
        }

        self.noteSentStreams(frames);
        self.next_packet_number = packet_number + 1;
        connection_reserved = false;
        reserved_streams.clearRetainingCapacity();
    }

    /// Receive and process every 1-RTT packet represented by one kernel
    /// datagram. With UDP_GRO enabled this amortizes recvmsg and allocation
    /// overhead across the whole coalesced segment batch.
    pub fn receivePacketBatch(self: *Connection) Error!ReceivedPacketBatch {
        return self.receivePacketBatchAt(self.monotonicNowNs());
    }

    pub fn receivePacketBatchAt(self: *Connection, now_ns: ?u64) Error!ReceivedPacketBatch {
        if (self.close_info != null or self.idle_timed_out) return error.ConnectionClosed;
        var datagrams = try self.endpoint.receiveBytesBatch();
        defer datagrams.deinit(self.endpoint.allocator);

        const packets = try self.endpoint.allocator.alloc(ReceivedPacket, datagrams.segment_count);
        var completed: usize = 0;
        errdefer {
            for (packets[0..completed]) |*packet| packet.deinit(self.endpoint.allocator);
            self.endpoint.allocator.free(packets);
        }
        for (packets, 0..) |*packet, index| {
            packet.* = try self.processReceivedBytesAt(
                datagrams.from,
                datagrams.datagramAt(index) orelse return error.InvalidPacket,
                datagrams.ecn,
                now_ns,
            );
            completed += 1;
        }
        return .{ .allocator = self.endpoint.allocator, .packets = packets };
    }

    /// Process a kernel/GRO batch and release each decoded packet immediately.
    ///
    /// Event loops that consume connection state rather than retaining packet
    /// diagnostics should prefer this path: it preserves strict wire-order
    /// application while bounding live decrypt/frame allocations to one packet.
    pub fn servicePacketBatch(self: *Connection) Error!usize {
        return self.servicePacketBatchAt(self.monotonicNowNs());
    }

    pub fn servicePacketBatchAt(self: *Connection, now_ns: ?u64) Error!usize {
        if (self.close_info != null or self.idle_timed_out) return error.ConnectionClosed;
        var datagrams = try self.endpoint.receiveBytesBatch();
        defer datagrams.deinit(self.endpoint.allocator);

        var completed: usize = 0;
        while (completed < datagrams.segment_count) : (completed += 1) {
            const bytes = datagrams.datagramAtMutable(completed) orelse return error.InvalidPacket;
            const keys = self.receive_key_phase.keyUpdateKeys();
            const key_phase = quic.protection.peekShortPacketKeyPhase(
                keys.current.hp,
                bytes,
                self.config.local_connection_id.len,
            ) catch |err| {
                if (err == error.AuthenticationFailed) try self.recordAuthenticationFailureAt(now_ns);
                return err;
            };
            if (key_phase == keys.current_key_phase) {
                self.processReceivedBytesInPlaceAt(
                    datagrams.from,
                    bytes,
                    datagrams.ecn,
                    now_ns,
                    keys.current,
                ) catch |err| {
                    if (err == error.AuthenticationFailed) try self.recordAuthenticationFailureAt(now_ns);
                    return err;
                };
                continue;
            }

            // The current-key phase is overwhelmingly common. Keep key-update
            // fallback on the owning path because a failed in-place AEAD trial
            // intentionally destroys its output and cannot safely retry
            // current/next/previous generations against the same ciphertext.
            var packet = try self.processReceivedBytesAt(
                datagrams.from,
                bytes,
                datagrams.ecn,
                now_ns,
            );
            packet.deinit(self.endpoint.allocator);
        }
        return completed;
    }

    fn processReceivedBytesInPlaceAt(
        self: *Connection,
        from: net.IpAddress,
        bytes: []u8,
        ecn: quic.packet_space.EcnCodepoint,
        now_ns: ?u64,
        keys: quic.protection.PacketProtectionKeys,
    ) Error!void {
        _ = from;
        const packet = try quic.protection.openShortPacketInPlace(
            keys,
            bytes,
            self.config.local_connection_id.len,
            self.expected_packet_number,
        );

        const frames = try self.parseServicePacketFramesOrClose(packet.payload, now_ns);
        defer {
            quic.deinitOwnedFrameSlice(self.receive_frame_buffer.items, self.endpoint.allocator);
            self.receive_frame_buffer.clearRetainingCapacity();
        }
        try self.applyReceivedFramesForDestinationOrClose(
            packet.packet_number,
            frames,
            now_ns,
            ecn,
            packet.destination_connection_id,
        );
        self.updateSpinBitAfterReceive(packet.spin_bit);
        self.observePacketReceived(
            now_ns,
            packet.packet_number,
            bytes.len,
            frames,
        );
    }

    fn parseServicePacketFramesOrClose(self: *Connection, payload: []const u8, now_ns: ?u64) Error![]quic.Frame {
        std.debug.assert(self.receive_frame_buffer.items.len == 0);
        errdefer {
            quic.deinitOwnedFrameSlice(self.receive_frame_buffer.items, self.endpoint.allocator);
            self.receive_frame_buffer.clearRetainingCapacity();
        }
        if (payload.len == 0) {
            try self.closeTransportAt(
                @intFromEnum(quic.TransportErrorCode.protocol_violation),
                0,
                "empty payload",
                nsToMs(now_ns),
                null,
            );
            return error.InvalidFrame;
        }

        var pos: usize = 0;
        while (pos < payload.len) {
            if (self.receive_frame_buffer.items.len >= self.config.max_frames_per_packet) return error.MissingFrame;
            const frame_type = quic.rawFrameTypeValue(payload[pos..]);
            var parsed = quic.parseFrameOwned(self.endpoint.allocator, payload[pos..]) catch |err| {
                if (err == error.OutOfMemory) return err;
                const code = quic.frameDecodeTransportErrorCode(err) orelse return err;
                try self.closeTransportAt(
                    @intFromEnum(code),
                    frame_type,
                    "frame encoding",
                    nsToMs(now_ns),
                    null,
                );
                return error.InvalidFrame;
            };
            var appended = false;
            defer if (!appended) parsed.deinitOwned(self.endpoint.allocator);
            try self.receive_frame_buffer.append(self.endpoint.allocator, parsed.frame);
            appended = true;
            pos += parsed.consumed;
        }
        return self.receive_frame_buffer.items;
    }

    fn processReceivedBytesAt(
        self: *Connection,
        from: net.IpAddress,
        bytes: []const u8,
        ecn: quic.packet_space.EcnCodepoint,
        now_ns: ?u64,
    ) Error!ReceivedPacket {
        var packet = self.openReceivedBytesWithFrameClose(
            from,
            bytes,
            self.config.local_connection_id.len,
            now_ns,
        ) catch |err| {
            if (err == error.AuthenticationFailed) try self.recordAuthenticationFailureAt(now_ns);
            return err;
        };
        errdefer packet.deinit(self.endpoint.allocator);
        try self.applyReceivedFramesForDestinationOrClose(packet.packet.packet_number, packet.frames, now_ns, ecn, packet.packet.destination_connection_id);
        self.updateSpinBitAfterReceive(packet.packet.spin_bit);
        if (packet.peer_initiated_key_update) {
            try self.acceptPeerKeyUpdate(packet.packet.key_phase, now_ns);
        }
        self.observePacketReceived(
            now_ns,
            packet.packet.packet_number,
            bytes.len,
            packet.frames,
        );
        return packet;
    }

    fn acceptPeerKeyUpdate(
        self: *Connection,
        peer_key_phase: bool,
        now_ns: ?u64,
    ) Error!void {
        if (!self.receive_key_phase.updateAfterReceiving(peer_key_phase)) return;
        if (self.config.qlog_observer) |observer| {
            observer.keyUpdated(
                self.qlogEventTime(now_ns orelse self.monotonicNowNs()),
                "remote_update",
                peerOneRttKeyType(self.config.local_endpoint),
                self.receive_key_phase.keyUpdateCount(),
            );
        }
        // RFC 9001 §6.2 requires sending keys to reach the corresponding phase
        // before acknowledging a peer's updated-key packet.
        if (self.send_key_phase.currentKeyPhase() != peer_key_phase) {
            if (self.pending_key_update_ack_threshold != null) return error.KeyUpdateError;
            self.advanceSendKeyPhase(self.next_packet_number, now_ns);
        }
    }

    pub fn receiveRoutedDatagram(self: *Connection, routed: quic.runtime.RoutedBytes) Error!ReceivedPacket {
        return self.receiveRoutedDatagramAt(routed, self.monotonicNowNs());
    }

    pub fn receiveRoutedDatagramOrDropAfterClose(self: *Connection, routed: quic.runtime.RoutedBytes) Error!?ReceivedPacket {
        return self.receiveRoutedDatagramOrDropAfterCloseAt(routed, self.monotonicNowNs());
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
        return .{ .packet = try self.receiveRoutedDatagramAt(routed, self.monotonicNowNs()) };
    }

    pub fn receiveRoutedDatagramAt(self: *Connection, routed: quic.runtime.RoutedBytes, now_ns: ?u64) Error!ReceivedPacket {
        if (self.close_info != null or self.idle_timed_out) return error.ConnectionClosed;
        var packet = self.openReceivedBytesWithFrameClose(
            routed.datagram.from,
            routed.datagram.bytes,
            routed.destination_connection_id.len,
            now_ns,
        ) catch |err| {
            if (err == error.AuthenticationFailed) try self.recordAuthenticationFailureAt(now_ns);
            return err;
        };
        errdefer packet.deinit(self.endpoint.allocator);
        try self.applyReceivedFramesForDestinationOrClose(packet.packet.packet_number, packet.frames, now_ns, routed.datagram.ecn, packet.packet.destination_connection_id);
        self.updateSpinBitAfterReceive(packet.packet.spin_bit);
        if (packet.peer_initiated_key_update) {
            try self.acceptPeerKeyUpdate(packet.packet.key_phase, now_ns);
        }
        self.observePacketReceived(
            now_ns,
            packet.packet.packet_number,
            routed.datagram.bytes.len,
            packet.frames,
        );
        return packet;
    }

    pub fn receiveRoutedDatagramWithEcnAt(self: *Connection, routed: quic.runtime.RoutedBytes, now_ns: ?u64, ecn: quic.packet_space.EcnCodepoint) Error!ReceivedPacket {
        if (self.close_info != null or self.idle_timed_out) return error.ConnectionClosed;
        var packet = self.openReceivedBytesWithFrameClose(
            routed.datagram.from,
            routed.datagram.bytes,
            routed.destination_connection_id.len,
            now_ns,
        ) catch |err| {
            if (err == error.AuthenticationFailed) try self.recordAuthenticationFailureAt(now_ns);
            return err;
        };
        errdefer packet.deinit(self.endpoint.allocator);
        try self.applyReceivedFramesForDestinationOrClose(packet.packet.packet_number, packet.frames, now_ns, ecn, packet.packet.destination_connection_id);
        self.updateSpinBitAfterReceive(packet.packet.spin_bit);
        if (packet.peer_initiated_key_update) {
            try self.acceptPeerKeyUpdate(packet.packet.key_phase, now_ns);
        }
        self.observePacketReceived(
            now_ns,
            packet.packet.packet_number,
            routed.datagram.bytes.len,
            packet.frames,
        );
        return packet;
    }

    fn openReceivedBytesWithFrameClose(
        self: *Connection,
        from: net.IpAddress,
        bytes: []const u8,
        destination_connection_id_len: usize,
        now_ns: ?u64,
    ) Error!ReceivedPacket {
        var decoded = try quic.protection.openShortPacketWithKeyUpdate(
            self.endpoint.allocator,
            self.receive_key_phase.keyUpdateKeys(),
            bytes,
            destination_connection_id_len,
            self.expected_packet_number,
        );
        errdefer decoded.deinit(self.endpoint.allocator);

        if (try quic.classifyFramePayloadCloseError(self.endpoint.allocator, decoded.packet.payload, .one_rtt)) |close| {
            try self.closeTransportAt(@intFromEnum(close.code), close.frame_type, close.reason_phrase, nsToMs(now_ns), null);
            return error.InvalidFrame;
        }

        const frames = try parsePacketFramesForType(self.endpoint, decoded.packet.payload, self.config.max_frames_per_packet, .one_rtt);
        errdefer {
            quic.deinitOwnedFrameSlice(frames, self.endpoint.allocator);
            self.endpoint.allocator.free(frames);
        }
        return .{
            .from = from,
            .packet = decoded.packet,
            .frames = frames,
            .peer_initiated_key_update = decoded.peer_initiated_key_update,
        };
    }

    fn applyReceivedFrames(self: *Connection, packet_number: u64, frames: []const quic.Frame, now_ns: ?u64, ecn: quic.packet_space.EcnCodepoint) Error!void {
        try self.applyReceivedFramesForDestination(packet_number, frames, now_ns, ecn, null);
    }

    fn applyReceivedFramesForDestinationOrClose(
        self: *Connection,
        packet_number: u64,
        frames: []const quic.Frame,
        now_ns: ?u64,
        ecn: quic.packet_space.EcnCodepoint,
        packet_destination_connection_id: ?[]const u8,
    ) Error!void {
        self.applyReceivedFramesForDestination(packet_number, frames, now_ns, ecn, packet_destination_connection_id) catch |err| {
            if (self.classifySemanticCloseError(frames, err)) |close| {
                try self.closeTransportAt(@intFromEnum(close.code), close.frame_type, close.reason_phrase, nsToMs(now_ns), null);
            }
            return err;
        };
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
        try self.validateReceivedFramePreconditions(frames, packet_destination_connection_id);
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
                    self.congestion.onAckedWithContext(
                        acked.bytes,
                        acked.largest_sent_time_ns,
                        now_ns,
                        self.rtt_stats.smoothedOrInitial(),
                    );
                    self.congestion.endAck();
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
                    self.observeRecoveryMetrics(now_ns);
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

    fn validateReceivedFramePreconditions(self: *Connection, frames: []const quic.Frame, packet_destination_connection_id: ?[]const u8) Error!void {
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
                .retire_connection_id => |retire| try local_connection_ids.retireExceptPacketDestination(retire.sequence_number, packet_destination_connection_id),
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

    fn classifySemanticCloseError(self: Connection, frames: []const quic.Frame, err: anyerror) ?quic.FramePayloadCloseError {
        return switch (err) {
            error.UnknownPathResponse => for (frames) |frame| {
                if (frame == .path_response) break quic.FramePayloadCloseError{
                    .code = .protocol_violation,
                    .frame_type = @intFromEnum(quic.FrameType.path_response),
                    .reason_phrase = "path response",
                };
            } else null,
            error.InvalidFrame => for (frames) |frame| {
                if (self.config.local_endpoint == .server and frame == .new_token) break semanticClose(.protocol_violation, @intFromEnum(quic.FrameType.new_token), "new token");
                if (self.config.local_endpoint == .server and frame == .handshake_done) break semanticClose(.protocol_violation, @intFromEnum(quic.FrameType.handshake_done), "handshake done");
                if (frame == .datagram) break semanticClose(.protocol_violation, @intFromEnum(quic.FrameType.datagram_len), "datagram");
            } else null,
            error.StreamLimitExceeded => firstFrameClose(frames, .stream_limit_error, "stream limit"),
            error.StreamStateError => firstFrameClose(frames, .stream_state_error, "stream state"),
            error.FlowControlViolation => firstFrameClose(frames, .flow_control_error, "flow control"),
            error.FinalSizeMismatch => firstFrameClose(frames, .final_size_error, "final size"),
            error.ConflictingStreamData => firstFrameClose(frames, .protocol_violation, "stream data"),
            error.InvalidAckFrame => ackFrameClose(frames),
            error.DuplicateConnectionId => connectionIdFrameClose(frames, .protocol_violation, "connection id reuse"),
            error.DuplicateResetToken => connectionIdFrameClose(frames, .protocol_violation, "reset token reuse"),
            error.ActiveConnectionIdLimit => connectionIdFrameClose(frames, .connection_id_limit_error, "connection id limit"),
            error.InvalidConnectionId, error.UnknownConnectionId => retireConnectionIdFrameClose(frames),
            error.AckFrequencyDisabled => ackFrequencyFrameClose(frames),
            else => null,
        };
    }

    fn firstFrameClose(frames: []const quic.Frame, code: quic.TransportErrorCode, reason: []const u8) ?quic.FramePayloadCloseError {
        if (frames.len == 0) return null;
        return semanticClose(code, frameTypeForSemanticClose(frames[frames.len - 1]), reason);
    }

    fn ackFrameClose(frames: []const quic.Frame) ?quic.FramePayloadCloseError {
        for (frames) |frame| {
            if (frame == .ack) return semanticClose(.protocol_violation, @intFromEnum(quic.FrameType.ack), "ack");
        }
        return null;
    }

    fn ackFrequencyFrameClose(frames: []const quic.Frame) ?quic.FramePayloadCloseError {
        for (frames) |frame| {
            if (frame == .ack_frequency) return semanticClose(.protocol_violation, @intFromEnum(quic.FrameType.ack_frequency), "ack frequency");
            if (frame == .immediate_ack) return semanticClose(.protocol_violation, @intFromEnum(quic.FrameType.immediate_ack), "immediate ack");
        }
        return null;
    }

    fn connectionIdFrameClose(frames: []const quic.Frame, code: quic.TransportErrorCode, reason: []const u8) ?quic.FramePayloadCloseError {
        for (frames) |frame| {
            if (frame == .new_connection_id) return semanticClose(code, @intFromEnum(quic.FrameType.new_connection_id), reason);
        }
        return null;
    }

    fn retireConnectionIdFrameClose(frames: []const quic.Frame) ?quic.FramePayloadCloseError {
        for (frames) |frame| {
            if (frame == .retire_connection_id) return semanticClose(.protocol_violation, @intFromEnum(quic.FrameType.retire_connection_id), "retire connection id");
        }
        return null;
    }

    fn semanticClose(code: quic.TransportErrorCode, frame_type: u64, reason: []const u8) quic.FramePayloadCloseError {
        return .{ .code = code, .frame_type = frame_type, .reason_phrase = reason };
    }

    fn frameTypeForSemanticClose(frame: quic.Frame) u64 {
        return switch (frame) {
            .stream => @intFromEnum(quic.FrameType.stream) | 0x02,
            .reset_stream => @intFromEnum(quic.FrameType.reset_stream),
            .stream_data_blocked => @intFromEnum(quic.FrameType.stream_data_blocked),
            .max_stream_data => @intFromEnum(quic.FrameType.max_stream_data),
            .stop_sending => @intFromEnum(quic.FrameType.stop_sending),
            else => 0,
        };
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

    fn receiveMaxStreams(self: *Connection, maximum_streams: u64, direction: StreamDirection) Error!void {
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

    fn receiveStreamsBlocked(self: *Connection, maximum_streams: u64, direction: StreamDirection) Error!void {
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
        if (self.config.max_datagram_queue_items == 0) {
            self.datagrams_dropped_incoming_count +|= 1;
            return;
        }
        const owned = try self.endpoint.allocator.dupe(u8, datagram.data);
        var owns_payload = true;
        errdefer if (owns_payload) self.endpoint.allocator.free(owned);
        const dropped = try self.datagram_recv_queue.pushDroppingOldest(
            self.endpoint.allocator,
            owned,
            self.config.max_datagram_queue_items,
        );
        owns_payload = false;
        if (dropped) |payload| {
            self.endpoint.allocator.free(payload);
            self.datagrams_dropped_incoming_count +|= 1;
        }
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
        try self.validateNextPacketNumber();
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
        try self.sendTrackedFramesEcnAt(frames, .not_ect, self.monotonicNowNs());
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
        self.pacer.reset();
        self.rtt_stats.onPersistentCongestion();
        self.last_persistent_congestion_packet_number = period.end_packet_number;
        return true;
    }

    fn observePacketSent(
        self: *Connection,
        now_ns: u64,
        packet_number: u64,
        packet_length: usize,
        frames: []const quic.Frame,
    ) void {
        const observer = self.config.qlog_observer orelse return;
        observer.packetSent(
            self.qlogEventTime(now_ns),
            packet_number,
            packet_length,
            frames,
            qlogAckDelayExponent(self.config.local_ack_delay_exponent),
        );
    }

    fn observePacketReceived(
        self: *Connection,
        now_ns: ?u64,
        packet_number: u64,
        packet_length: usize,
        frames: []const quic.Frame,
    ) void {
        const observer = self.config.qlog_observer orelse return;
        observer.packetReceived(
            self.qlogEventTime(now_ns orelse self.monotonicNowNs()),
            packet_number,
            packet_length,
            frames,
            qlogAckDelayExponent(self.config.peer_ack_delay_exponent),
        );
    }

    fn observeRecoveryMetrics(self: *Connection, now_ns: ?u64) void {
        const observer = self.config.qlog_observer orelse return;
        observer.metricsUpdated(
            self.qlogEventTime(now_ns orelse self.monotonicNowNs()),
            .{
                .min_rtt_ns = if (self.rtt_stats.has_measurement)
                    self.rtt_stats.min_rtt
                else
                    null,
                .smoothed_rtt_ns = if (self.rtt_stats.has_measurement)
                    self.rtt_stats.smoothed_rtt
                else
                    null,
                .latest_rtt_ns = if (self.rtt_stats.has_measurement)
                    self.rtt_stats.latest_rtt
                else
                    null,
                .rtt_variance_ns = if (self.rtt_stats.has_measurement)
                    self.rtt_stats.rtt_var
                else
                    null,
                .congestion_window = self.congestion.congestion_window,
                .bytes_in_flight = self.congestion.bytes_in_flight,
            },
        );
    }

    fn monotonicNowNs(self: Connection) u64 {
        // `awake` is monotonic and excludes suspend time where the platform can
        // distinguish it. Saturating at the u64 range keeps the existing
        // timestamp API stable even though std.Io uses signed i96 timestamps.
        const timestamp = std.Io.Clock.awake.now(self.endpoint.io).nanoseconds;
        if (timestamp <= 0) return 0;
        return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
    }

    fn qlogEventTime(self: Connection, now_ns: u64) u64 {
        const observer = self.config.qlog_observer orelse return now_ns;
        return switch (observer.trace.options.time_format) {
            .relative => @max(now_ns, observer.trace.options.reference_time_ns),
            .absolute => now_ns,
        };
    }

    fn waitForPacing(self: Connection, now_ns: u64) Error!void {
        const deadline = self.pacing_blocked_until_ns orelse return error.PacingLimited;
        if (deadline <= now_ns) return;
        const delay_ns = deadline - now_ns;
        const signed_delay = std.math.cast(i64, delay_ns) orelse std.math.maxInt(i64);
        try std.Io.sleep(self.endpoint.io, .fromNanoseconds(signed_delay), .awake);
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

    /// Return application-consumed bytes to both QUIC receive windows.
    ///
    /// The connection and stream windows advance as one transaction. If a
    /// generated MAX_DATA/MAX_STREAM_DATA packet cannot be sent, both RecvFlow
    /// snapshots are restored so the caller can retry without losing the
    /// advertisement that unblocks its peer.
    pub fn releaseReceivedCapacity(
        self: *Connection,
        stream_id: u64,
        amount: u64,
    ) Error!void {
        if (amount == 0) return;
        const recv_stream = self.findRecvStreamEntry(stream_id) orelse
            return error.StreamStateError;
        const consume_len = std.math.cast(usize, amount) orelse
            return error.InvalidFrameLength;
        // Preflight before sending an advertisement. Once MAX_* is visible to
        // the peer, consuming the corresponding retained transport bytes must
        // be infallible so local overlap/conflict state cannot diverge from the
        // enlarged window.
        if (consume_len > recv_stream.recv_state.available().len) {
            return error.InvalidStreamRange;
        }
        const previous_connection = self.recv_flow;
        const previous_stream = recv_stream.flow;
        errdefer {
            self.recv_flow = previous_connection;
            recv_stream.flow = previous_stream;
        }

        var frames: [2]quic.Frame = undefined;
        var count: usize = 0;
        if (self.recv_flow.consume(amount) != null) {
            frames[count] = self.recv_flow.maxDataFrame();
            count += 1;
        }
        if (recv_stream.flow.consume(amount) != null) {
            frames[count] = recv_stream.flow.maxStreamDataFrame(stream_id);
            count += 1;
        }
        if (count != 0) try self.send(frames[0..count]);
        try recv_stream.recv_state.consume(consume_len);
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

    fn validateStreamFrameForSend(self: *Connection, stream: quic.StreamFrame) Error!void {
        if (self.findSendStreamEntry(stream.stream_id)) |entry| {
            if (entry.stopped != null or entry.reset_sent != null) return error.StreamStopped;
            return;
        }
        if (!streamHasSendSide(self.config.local_endpoint, stream.stream_id)) return error.StreamStateError;
        if (!streamInitiatedByLocal(self.config.local_endpoint, stream.stream_id)) return;

        const count = streamCountForId(stream.stream_id);
        const direction = streamDirection(stream.stream_id);
        const limit = switch (direction) {
            .bidirectional => self.peer_max_streams_bidi,
            .unidirectional => self.peer_max_streams_uni,
        };
        if (count <= limit) return;
        try self.sendStreamsBlocked(direction);
        return error.StreamLimitExceeded;
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

    fn sendStreamsBlocked(self: *Connection, direction: StreamDirection) Error!void {
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

fn streamDirection(stream_id: u64) StreamDirection {
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

fn allEqual(comptime T: type, values: []const T, expected: T) bool {
    for (values) |value| {
        if (value != expected) return false;
    }
    return true;
}

fn closeExpiryMillis(now_ms: ?u64, pto_ms: ?u64) ?u64 {
    const now = now_ms orelse return null;
    const pto = pto_ms orelse return null;
    const duration = std.math.mul(u64, pto, 3) catch return std.math.maxInt(u64);
    return std.math.add(u64, now, duration) catch std.math.maxInt(u64);
}

fn nsToMs(now_ns: ?u64) ?u64 {
    const ns = now_ns orelse return null;
    return ns / 1_000_000;
}

fn qlogAckDelayExponent(exponent: u64) u6 {
    return @intCast(@min(exponent, quic.rtt.max_ack_delay_exponent));
}

fn oneRttKeyType(
    role: ConnectionConfig.EndpointRole,
) []const u8 {
    return switch (role) {
        .client => "client_1rtt_secret",
        .server => "server_1rtt_secret",
    };
}

fn peerOneRttKeyType(
    role: ConnectionConfig.EndpointRole,
) []const u8 {
    return switch (role) {
        .client => "server_1rtt_secret",
        .server => "client_1rtt_secret",
    };
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

/// Encode, protect, and submit a batch of independent 1-RTT packets.
///
/// The caller supplies scratch storage for both encoded frame payloads and
/// protected datagrams, making the entire path allocation-free. The function
/// validates every frame and computes every required size before writing either
/// buffer or issuing the first UDP send.
pub fn sendFramesBatchInto(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    options: BatchSendOptions,
    payload_storage: []u8,
    packet_storage: []u8,
) Error!usize {
    const result = try sendFramesBatchIntoProgress(
        endpoint,
        to,
        keys,
        options,
        payload_storage,
        packet_storage,
    );
    if (result.send_error) |err| return err;
    std.debug.assert(result.sent_count == options.packets.len);
    return result.sent_bytes;
}

/// Allocation-free batch protection and send with explicit socket progress.
///
/// Unlike `sendFramesBatchInto`, network errors are returned in the result so
/// stateful callers can consume packet numbers for a socket-visible prefix.
/// Validation, sizing, and packet protection still finish before the first
/// datagram is submitted.
pub fn sendFramesBatchIntoProgress(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    options: BatchSendOptions,
    payload_storage: []u8,
    packet_storage: []u8,
) Error!BatchSendResult {
    if (options.packets.len == 0) {
        return .{ .sent_count = 0, .sent_bytes = 0 };
    }
    if (options.packets.len > max_batch_packets) return error.DatagramTooLarge;

    var payload_lengths: [max_batch_packets]usize = undefined;
    var packet_lengths: [max_batch_packets]usize = undefined;
    var total_payload_len: usize = 0;
    var total_packet_len: usize = 0;

    for (options.packets, 0..) |frames, i| {
        if (frames.len == 0) return error.MissingFrame;
        var payload_len: usize = 0;
        for (frames) |frame| {
            try quic.validateFrameForPacketType(frame, .one_rtt);
            payload_len = std.math.add(usize, payload_len, try frame.wireLen()) catch return error.InvalidFrameLength;
        }
        payload_lengths[i] = payload_len;
        total_payload_len = std.math.add(usize, total_payload_len, payload_len) catch return error.InvalidFrameLength;

        const packet_number = std.math.add(u64, options.first_packet_number, i) catch return error.InvalidPacketNumber;
        const packet_len = try quic.protection.shortPacketLen(.{
            .destination_connection_id = options.destination_connection_id,
            .packet_number = packet_number,
            .packet_number_len = options.packet_number_len,
            .payload = payload_storage[0..0],
        });
        packet_lengths[i] = std.math.add(usize, packet_len, payload_len) catch return error.InvalidPayloadLength;
        if (packet_lengths[i] > endpoint.limits.max_datagram_size) return error.DatagramTooLarge;
        total_packet_len = std.math.add(usize, total_packet_len, packet_lengths[i]) catch return error.InvalidPayloadLength;
    }
    if (payload_storage.len < total_payload_len or packet_storage.len < total_packet_len) return error.BufferTooShort;

    var datagrams: [max_batch_packets][]const u8 = undefined;
    var payload_offset: usize = 0;
    var packet_offset: usize = 0;
    for (options.packets, 0..) |frames, i| {
        const payload_len = payload_lengths[i];
        const payload_out = payload_storage[payload_offset..][0..payload_len];
        var fixed = std.heap.FixedBufferAllocator.init(payload_out);
        var encoded = try std.ArrayList(u8).initCapacity(fixed.allocator(), payload_len);
        for (frames) |frame| try frame.write(&encoded, fixed.allocator());
        std.debug.assert(encoded.items.len == payload_len);

        const packet_number = options.first_packet_number + i;
        const packet = try quic.protection.sealShortPacketInto(
            packet_storage[packet_offset..][0..packet_lengths[i]],
            keys,
            .{
                .destination_connection_id = options.destination_connection_id,
                .packet_number = packet_number,
                .packet_number_len = options.packet_number_len,
                .spin_bit = options.spin_bit,
                .key_phase = options.key_phase,
                .payload = encoded.items,
            },
        );
        datagrams[i] = packet;
        payload_offset += payload_len;
        packet_offset += packet.len;
    }

    const send_result = try endpoint.sendManyBytesProgress(
        to,
        datagrams[0..options.packets.len],
    );
    var sent_bytes: usize = 0;
    for (packet_lengths[0..send_result.sent_count]) |packet_len| {
        sent_bytes += packet_len;
    }
    return .{
        .sent_count = send_result.sent_count,
        .sent_bytes = sent_bytes,
        .send_error = send_result.send_error,
    };
}

pub fn sendFramesBatch(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    options: BatchSendOptions,
) Error!void {
    const sizes = try batchStorageSizes(options);
    const storage = try endpoint.allocator.alloc(u8, sizes.payload + sizes.packet);
    defer endpoint.allocator.free(storage);
    _ = try sendFramesBatchInto(
        endpoint,
        to,
        keys,
        options,
        storage[0..sizes.payload],
        storage[sizes.payload..],
    );
}

/// Return the exact reusable scratch required by `sendFramesBatchInto`.
pub fn batchStorageSizes(options: BatchSendOptions) Error!struct { payload: usize, packet: usize } {
    if (options.packets.len > max_batch_packets) return error.DatagramTooLarge;
    var payload_total: usize = 0;
    var packet_total: usize = 0;
    for (options.packets, 0..) |frames, i| {
        if (frames.len == 0) return error.MissingFrame;
        var payload_len: usize = 0;
        for (frames) |frame| {
            try quic.validateFrameForPacketType(frame, .one_rtt);
            payload_len = std.math.add(usize, payload_len, try frame.wireLen()) catch return error.InvalidFrameLength;
        }
        payload_total = std.math.add(usize, payload_total, payload_len) catch return error.InvalidFrameLength;
        const packet_number = std.math.add(u64, options.first_packet_number, i) catch return error.InvalidPacketNumber;
        const overhead = try quic.protection.shortPacketLen(.{
            .destination_connection_id = options.destination_connection_id,
            .packet_number = packet_number,
            .packet_number_len = options.packet_number_len,
            .payload = &.{},
        });
        const packet_len = std.math.add(usize, overhead, payload_len) catch return error.InvalidPayloadLength;
        packet_total = std.math.add(usize, packet_total, packet_len) catch return error.InvalidPayloadLength;
    }
    return .{ .payload = payload_total, .packet = packet_total };
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
            // RFC 9000 §13.2.1: ACK, PADDING, and both CONNECTION_CLOSE
            // variants are non-ack-eliciting.  tquic/quicz rely on the same
            // classification so close packets do not enter recovery or consume
            // congestion credit while the endpoint is already shutting down.
            .ack, .padding, .connection_close, .application_close => {},
            else => return true,
        }
    }
    return false;
}

fn packetInFlight(frames: []const quic.Frame) bool {
    for (frames) |frame| {
        switch (frame) {
            // RFC 9002 counts packets that contain PADDING in bytes-in-flight
            // even though PADDING is not ack-eliciting.  Mature stacks such as
            // tquic model this separately from ack-eliciting recovery so pure
            // padding can still consume and later release congestion credit.
            .ack, .connection_close, .application_close => {},
            .padding => return true,
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

fn addReservedStreamCredit(
    credits: *std.ArrayList(ReservedStreamCredit),
    allocator: std.mem.Allocator,
    stream_id: u64,
    bytes: u64,
) Error!void {
    for (credits.items) |*credit| {
        if (credit.stream_id != stream_id) continue;
        credit.bytes = std.math.add(u64, credit.bytes, bytes) catch
            return error.InvalidFrameLength;
        return;
    }
    try credits.append(allocator, .{
        .stream_id = stream_id,
        .bytes = bytes,
    });
}

fn reservedStreamBytes(
    credits: []const ReservedStreamCredit,
    stream_id: u64,
) u64 {
    for (credits) |credit| {
        if (credit.stream_id == stream_id) return credit.bytes;
    }
    return 0;
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

test "QUIC DATAGRAM receive queue drops oldest without shifting" {
    const allocator = std.testing.allocator;
    var queue: DatagramRecvQueue = .{};
    defer queue.deinit(allocator);

    const one = try allocator.dupe(u8, "one");
    var owns_one = true;
    errdefer if (owns_one) allocator.free(one);
    try std.testing.expectEqual(@as(?[]u8, null), try queue.pushDroppingOldest(allocator, one, 2));
    owns_one = false;

    const two = try allocator.dupe(u8, "two");
    var owns_two = true;
    errdefer if (owns_two) allocator.free(two);
    try std.testing.expectEqual(@as(?[]u8, null), try queue.pushDroppingOldest(allocator, two, 2));
    owns_two = false;

    const three = try allocator.dupe(u8, "three");
    var owns_three = true;
    errdefer if (owns_three) allocator.free(three);
    const dropped = (try queue.pushDroppingOldest(allocator, three, 2)).?;
    owns_three = false;
    defer allocator.free(dropped);
    try std.testing.expectEqualStrings("one", dropped);
    try std.testing.expectEqual(@as(usize, 2), queue.count());

    const first = queue.pop().?;
    defer allocator.free(first);
    try std.testing.expectEqualStrings("two", first);

    const four = try allocator.dupe(u8, "four");
    var owns_four = true;
    errdefer if (owns_four) allocator.free(four);
    try std.testing.expectEqual(@as(?[]u8, null), try queue.pushDroppingOldest(allocator, four, 2));
    owns_four = false;

    const second = queue.pop().?;
    defer allocator.free(second);
    try std.testing.expectEqualStrings("three", second);
    const third = queue.pop().?;
    defer allocator.free(third);
    try std.testing.expectEqualStrings("four", third);
    try std.testing.expect(queue.pop() == null);
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
    const options: BatchSendOptions = .{
        .destination_connection_id = "batch-cid",
        .first_packet_number = 40,
        .packet_number_len = 2,
        .packets = &packets,
    };
    const sizes = try batchStorageSizes(options);
    const payload_storage = try allocator.alloc(u8, sizes.payload);
    defer allocator.free(payload_storage);
    const packet_storage = try allocator.alloc(u8, sizes.packet);
    defer allocator.free(packet_storage);

    const written = try sendFramesBatchInto(
        &sender,
        receiver.address(),
        keys,
        options,
        payload_storage,
        packet_storage,
    );
    try std.testing.expectEqual(sizes.packet, written);

    for (packets, 0..) |expected_frames, i| {
        var received = try receive(&receiver, keys, "batch-cid".len, 40 + i, 8);
        defer received.deinit(allocator);
        try std.testing.expectEqual(@as(u64, @intCast(40 + i)), received.packet.packet_number);
        try std.testing.expectEqual(expected_frames.len, received.frames.len);
        for (expected_frames, received.frames) |expected, actual| {
            try std.testing.expectEqual(@intFromEnum(expected), @intFromEnum(actual));
        }
    }
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
        .sequence_number = 0,
        .ack_eliciting_threshold = 0,
        .request_max_ack_delay = 0,
        .reordering_threshold = 0,
    } }};
    const packets = [_][]const quic.Frame{ &valid, &invalid };
    const options: BatchSendOptions = .{
        .destination_connection_id = "cid",
        .first_packet_number = 0,
        .packets = &packets,
    };
    var payload_storage: [128]u8 = undefined;
    var packet_storage: [256]u8 = undefined;
    @memset(&payload_storage, 0xa5);
    @memset(&packet_storage, 0x5a);
    try std.testing.expectError(
        error.InvalidFrame,
        sendFramesBatchInto(&sender, receiver.address(), keys, options, &payload_storage, &packet_storage),
    );
    try std.testing.expect(allEqual(u8, &payload_storage, 0xa5));
    try std.testing.expect(allEqual(u8, &packet_storage, 0x5a));

    const only_valid = [_][]const quic.Frame{&valid};
    const valid_options: BatchSendOptions = .{
        .destination_connection_id = "cid",
        .first_packet_number = 0,
        .packets = &only_valid,
    };
    const sizes = try batchStorageSizes(valid_options);
    try std.testing.expectError(
        error.BufferTooShort,
        sendFramesBatchInto(
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
    const options: BatchSendOptions = .{
        .destination_connection_id = "cid",
        .first_packet_number = 10,
        .packets = &packets,
    };
    const allocations_before = counting.allocations;
    try sendFramesBatch(&sender, receiver.address(), keys, options);
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
    var partial_vtable = sender.io.vtable.*;
    partial_vtable.netSend = ObservedBatchSend.netSend;
    sender.io = .{
        .userdata = &partial_send,
        .vtable = &partial_vtable,
    };
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
    const options: BatchSendOptions = .{
        .destination_connection_id = "cid",
        .first_packet_number = 20,
        .packets = &packets,
    };
    const sizes = try batchStorageSizes(options);
    const storage = try allocator.alloc(u8, sizes.payload + sizes.packet);
    defer allocator.free(storage);

    const result = try sendFramesBatchIntoProgress(
        &sender,
        receiver.address(),
        keys,
        options,
        storage[0..sizes.payload],
        storage[sizes.payload..],
    );
    try std.testing.expectEqual(@as(usize, 1), result.sent_count);
    try std.testing.expect(result.sent_bytes != 0);
    try std.testing.expectEqual(error.NetworkDown, result.send_error.?);

    var received = try receive(&receiver, keys, "cid".len, 20, 8);
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
    const packet_frames = [_][]const quic.Frame{ &ping, &ping };
    try sendFramesBatch(&client_endpoint, server_endpoint.address(), keys, .{
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

    try sendFramesBatch(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = &server_cid,
        .first_packet_number = 2,
        .packet_number_len = 4,
        .packets = &packet_frames,
    });
    try std.testing.expectEqual(@as(usize, 2), try server.servicePacketBatchAt(20_000_000));
    const second_ack = try server.received.ackFrame(allocator, 0);
    defer allocator.free(second_ack.ranges);
    try std.testing.expectEqual(@as(u64, 3), second_ack.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 3), second_ack.first_ack_range);
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

    try client.send(&[_]quic.Frame{.{ .padding = .{ .len = 16 } }});
    try std.testing.expectEqual(@as(usize, 1), client.sent.packets.items.len);
    try std.testing.expect(!client.sent.packets.items[0].ack_eliciting);
    try std.testing.expect(client.sent.packets.items[0].in_flight);
    try std.testing.expectEqual(@as(usize, 16), client.sent.packets.items[0].bytes);
    try std.testing.expectEqual(@as(usize, 0), client.pendingRecoveryCount());
    try std.testing.expectEqual(@as(?LossDetectionTimerDeadline, null), client.lossDetectionTimerDeadline());
    try std.testing.expectEqual(@as(usize, 16), client.congestion.bytes_in_flight);

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
    try std.testing.expect(server.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.protocol_violation), server.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.stream) | 0x02), server.close_info.?.frame_type);
    try std.testing.expectEqualStrings("stream data", server.close_info.?.reason_phrase);
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
    try std.testing.expect(client.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.protocol_violation), client.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.ack)), client.close_info.?.frame_type);
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
    try std.testing.expect(client.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.stream_limit_error), client.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.stream) | 0x02), client.close_info.?.frame_type);
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
            .{ .max_stream_data = .{ .stream_id = 3, .maximum_stream_data = 64 } },
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
    var client2 = try Connection.init(&client2_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client2_cid,
        .peer_connection_id = &server_cid,
        .local_endpoint = .client,
    });
    defer client2.deinit();

    try sendFrames(&server_endpoint, client2_endpoint.address(), keys, .{
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
    var server3 = try Connection.init(&server3_endpoint, .{
        .peer = client3_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server3_cid,
        .peer_connection_id = &client3_cid,
        .local_endpoint = .server,
    });
    defer server3.deinit();

    try sendFrames(&client3_endpoint, server3_endpoint.address(), keys, .{
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
    try std.testing.expect(server.closing());
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.handshake_done)), server.close_info.?.frame_type);

    var path_server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer path_server_endpoint.deinit();
    const path_server_cid = [_]u8{ 0x51, 0x52, 0x53, 0x54 };
    var path_server = try Connection.init(&path_server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &path_server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer path_server.deinit();

    try sendFrames(&client_endpoint, path_server_endpoint.address(), keys, .{
        .destination_connection_id = &path_server_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{
            .{ .stream = .{ .stream_id = 0, .data = "before-path-error", .fin = false } },
            .{ .path_response = .{ .data = [_]u8{0xaa} ** 8 } },
        },
    });

    try std.testing.expectError(error.UnknownPathResponse, path_server.receivePacket());
    try std.testing.expectEqual(@as(u64, 0), path_server.recv_data_total);
    try std.testing.expectEqual(@as(usize, 0), path_server.stream_recv_flows.items.len);
    try std.testing.expectEqual(@as(usize, 0), path_server.received.ranges.items.len);
    try std.testing.expectEqual(@as(u64, 0), path_server.expected_packet_number);
    try std.testing.expectEqual(@as(usize, 0), path_server.path_validation.outstandingChallengeCount());
    try std.testing.expect(path_server.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.protocol_violation), path_server.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.path_response)), path_server.close_info.?.frame_type);
    try std.testing.expectEqualStrings("path response", path_server.close_info.?.reason_phrase);
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

    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    try sendPayload(&client_endpoint, server_endpoint.address(), client_keys, .{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .payload = &.{0x21},
    });

    try std.testing.expectError(error.InvalidFrame, server.receivePacketAt(1_000_000));
    try std.testing.expect(server.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.frame_encoding_error), server.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, 0x21), server.close_info.?.frame_type);
    try std.testing.expectEqualStrings("frame encoding", server.close_info.?.reason_phrase);

    var close_packet = try receive(&client_endpoint, server_keys, client_cid.len, 0, 8);
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

test "QUIC 1-RTT connection selects and exposes CUBIC congestion control" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0x79} ** quic.protection.secret_len);
    var connection = try Connection.init(&endpoint, .{
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

    var reno = try Connection.init(&endpoint, .{
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

test "QUIC 1-RTT connection reuses protected send storage" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var peer_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer peer_endpoint.deinit();

    var counting = std.testing.FailingAllocator.init(allocator, .{});
    const connection_allocator = counting.allocator();
    var local_endpoint = try quic.runtime.Endpoint.bind(connection_allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer local_endpoint.deinit();

    const keys = quic.protection.deriveAes128Keys([_]u8{0x7a} ** quic.protection.secret_len);
    var connection = try Connection.init(&local_endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
        .max_datagram_size = 4096,
    });
    defer connection.deinit();

    // Pre-size bookkeeping that is intentionally retained for recovery and
    // ACK processing; packet protection itself should then need no allocator.
    try connection.sent.packets.ensureTotalCapacity(connection_allocator, 2);
    counting.fail_index = counting.alloc_index;
    const payload = [_]quic.Frame{.{ .padding = .{ .len = 32 } }};
    try connection.sendAt(&payload, 100);
    try connection.sendAt(&payload, 200);
    try std.testing.expect(!counting.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 2), connection.sent.packets.items.len);
    try std.testing.expectEqual(@as(usize, 0), connection.send_packet_buffer.items.len);
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
    var connection = try Connection.init(&local_endpoint, .{
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
    const packet_len = connection.sent.packets.items[0].bytes + 1 + "peer".len + 1 + quic.protection.aead_tag_len;
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

test "QUIC 1-RTT can disable pacing" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0x7c} ** quic.protection.secret_len);
    var connection = try Connection.init(&endpoint, .{
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
    var connection = try Connection.init(&endpoint, .{
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
    try std.testing.expect(server.localOneRttKeyPhase());
    try std.testing.expectEqual(@as(u64, 1), server.localOneRttKeyUpdateCount());
    try std.testing.expectEqual(@as(?u64, 0), server.pendingOneRttKeyUpdateAckThreshold());
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

test "QUIC 1-RTT automatically updates before the AEAD confidentiality limit" {
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
    const keys = quic.protection.deriveAes128Keys([_]u8{0x69} ** quic.protection.secret_len);
    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .aead_confidentiality_limit = 2,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .aead_confidentiality_limit = 2,
    });
    defer server.deinit();

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try client.send(&ping);
    try client.send(&ping);
    try std.testing.expectEqual(@as(u64, 2), client.encryptedPacketsWithCurrentKeys());
    try std.testing.expect(!client.localOneRttKeyPhase());

    // The next encryption advances first, so generation zero is never used
    // beyond its configured (and RFC-clamped) confidentiality limit.
    try client.send(&ping);
    try std.testing.expect(client.localOneRttKeyPhase());
    try std.testing.expectEqual(@as(u64, 1), client.localOneRttKeyUpdateCount());
    try std.testing.expectEqual(@as(u64, 1), client.encryptedPacketsWithCurrentKeys());
    try std.testing.expectEqual(@as(?u64, 2), client.pendingOneRttKeyUpdateAckThreshold());

    var packet0 = try server.receivePacket();
    defer packet0.deinit(allocator);
    var packet1 = try server.receivePacket();
    defer packet1.deinit(allocator);
    var packet2 = try server.receivePacket();
    defer packet2.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), packet0.packet.packet_number);
    try std.testing.expectEqual(@as(u64, 1), packet1.packet.packet_number);
    try std.testing.expectEqual(@as(u64, 2), packet2.packet.packet_number);
    try std.testing.expect(packet2.peer_initiated_key_update);

    // One more packet fills generation one. Without an ACK for packet 2 the
    // sender cannot safely initiate another update, so the following send
    // terminates locally rather than exceeding the AEAD limit.
    try client.send(&ping);
    try std.testing.expectError(error.AeadLimitReached, client.send(&ping));
    try std.testing.expect(client.closing());
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(quic.TransportErrorCode.aead_limit_reached)),
        client.close_info.?.error_code,
    );
    try std.testing.expectEqual(@as(u64, 4), client.next_packet_number);
}

test "QUIC 1-RTT closes at the AEAD integrity limit" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();
    const local_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const peer_cid = [_]u8{ 0x75, 0x76, 0x77, 0x78 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x79} ** quic.protection.secret_len);
    var connection = try Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &local_cid,
        .peer_connection_id = &peer_cid,
        .local_endpoint = .server,
        .aead_integrity_limit = 2,
    });
    defer connection.deinit();

    const sealed = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = &local_cid,
        .packet_number = 0,
        .packet_number_len = 4,
        .payload = &.{@intFromEnum(quic.FrameType.ping)},
    });
    defer allocator.free(sealed);
    sealed[sealed.len - 1] ^= 0x80; // Preserve header protection; corrupt only the AEAD tag.

    try std.testing.expectError(
        error.AuthenticationFailed,
        connection.processReceivedBytesAt(endpoint.address(), sealed, .not_ect, 1_000_000),
    );
    try std.testing.expectEqual(@as(u64, 1), connection.authenticationFailureCount());
    try std.testing.expect(!connection.closing());

    try std.testing.expectError(
        error.AeadLimitReached,
        connection.processReceivedBytesAt(endpoint.address(), sealed, .not_ect, 2_000_000),
    );
    try std.testing.expectEqual(@as(u64, 2), connection.authenticationFailureCount());
    try std.testing.expect(connection.closing());
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(quic.TransportErrorCode.aead_limit_reached)),
        connection.close_info.?.error_code,
    );
    try std.testing.expectEqual(@as(u64, 1), connection.next_packet_number);
    try std.testing.expectError(error.ConnectionClosed, connection.send(&.{.{ .ping = {} }}));
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
    connection.pacer.onPacketSentAt(100, connection.pacer.maxBurstSize(), connection.congestionWindow(), connection.rtt_stats.smoothedOrInitial());
    try std.testing.expectEqual(@as(usize, 1300), connection.pmtudCurrentSize());
    try std.testing.expectEqual(@as(usize, 0), connection.pacer.budget);

    const challenge = [_]u8{ 0xc0, 1, 2, 3, 4, 5, 6, 7 };
    try connection.beginPeerMigration(migrated_endpoint.address(), challenge);
    try std.testing.expectEqual(migrated_endpoint.address(), connection.config.peer);
    try std.testing.expect(!connection.peerAddressValidated());
    try std.testing.expectEqual(@as(?usize, 0), connection.antiAmplificationLimitRemaining());
    try std.testing.expectEqual(quic.pmtu.min_udp_payload_size, connection.pmtudCurrentSize());
    try std.testing.expect(connection.pmtudShouldProbe());
    try std.testing.expectEqual(connection.pacer.maxBurstSize(), connection.pacer.budget);
    try std.testing.expectEqual(@as(?u64, null), connection.pacer.last_sent_time_ns);
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

test "QUIC 1-RTT connection batches PATH_CHALLENGE and PATH_RESPONSE frames" {
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
    const keys = quic.protection.deriveAes128Keys([_]u8{0xd2} ** quic.protection.secret_len);

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

    try std.testing.expectEqual(@as(usize, 0), try client.sendPendingPathChallengesAt(100, 50));
    try std.testing.expectEqual(@as(usize, 0), try server.sendPendingPathResponses());
    try std.testing.expectError(error.NoPendingPathChallenge, client.sendPendingPathChallengeAt(100, 50));
    try std.testing.expectError(error.NoPendingPathResponse, server.sendPendingPathResponse());

    const first = [_]u8{ 1, 1, 2, 3, 5, 8, 13, 21 };
    const second = [_]u8{ 2, 3, 5, 8, 13, 21, 34, 55 };
    try client.queuePathChallenge(first);
    try client.queuePathChallenge(second);
    try std.testing.expectEqual(@as(usize, 2), try client.sendPendingPathChallengesAt(100, 50));
    try std.testing.expectEqual(@as(usize, 2), client.path_validation.outstandingChallengeCount());

    var challenge_packet = try server.receivePacket();
    defer challenge_packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), challenge_packet.frames.len);
    try std.testing.expectEqualSlices(u8, &first, &challenge_packet.frames[0].path_challenge.data);
    try std.testing.expectEqualSlices(u8, &second, &challenge_packet.frames[1].path_challenge.data);
    try std.testing.expectEqual(@as(usize, 2), server.path_validation.pendingResponseCount());

    try std.testing.expectEqual(@as(usize, 2), try server.sendPendingPathResponses());
    var response_packet = try client.receivePacket();
    defer response_packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), response_packet.frames.len);
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
    try std.testing.expectError(error.ActiveConnectionIdLimit, server.sendNewConnectionId("server-extra-cid", [_]u8{0xab} ** 16));
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

test "QUIC 1-RTT replacement CID can retire prior IDs at peer active limit" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0x72, 0x73, 0x74, 0x75 };
    const server_cid = [_]u8{ 0x76, 0x77, 0x78, 0x79 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xe4} ** quic.protection.secret_len);

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

    try server.sendNewConnectionId("server-first-cid", [_]u8{0xa1} ** 16);
    var first = try client.receivePacket();
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), client.peer_connection_ids.count());

    try std.testing.expectError(error.ActiveConnectionIdLimit, server.sendNewConnectionId("server-extra-cid", [_]u8{0xa2} ** 16));
    try server.sendNewConnectionIdRetiringPriorTo("server-rotated-cid", [_]u8{0xa3} ** 16, 1);
    var replacement = try client.receivePacket();
    defer replacement.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), replacement.frames[0].new_connection_id.sequence_number);
    try std.testing.expectEqual(@as(u64, 1), replacement.frames[0].new_connection_id.retire_prior_to);
    try std.testing.expectEqual(@as(usize, 2), client.peer_connection_ids.count());
    try std.testing.expectEqual(@as(usize, 1), client.pendingRetireConnectionIdCount());

    try std.testing.expect(client.switchToNextPeerConnectionId());
    try std.testing.expectEqualStrings("server-rotated-cid", client.config.peer_connection_id);
    try std.testing.expectEqual(@as(usize, 1), try client.sendPendingRetireConnectionIds());
    try std.testing.expectEqual(@as(usize, 0), client.pendingRetireConnectionIdCount());

    var router = quic.connection_router.Router.init(allocator);
    defer router.deinit();
    try router.register("server-rotated-cid", .{ .connection_index = 0, .sequence_number = 2 });
    var routed = try server_endpoint.receiveRoutedBytes(router);
    defer routed.deinit(allocator);
    var retire = try server.receiveRoutedDatagram(routed);
    defer retire.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), server.local_connection_ids.count());
}

test "QUIC 1-RTT derives local CID stateless reset tokens from config key" {
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
    const reset_key = [_]u8{0x5c} ** quic.stateless_reset.static_key_len;
    const keys = quic.protection.deriveAes128Keys([_]u8{0xe3} ** quic.protection.secret_len);

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
        .local_stateless_reset_key = reset_key,
    });
    defer server.deinit();

    try std.testing.expectEqualSlices(
        u8,
        &quic.stateless_reset.tokenForConnectionId(reset_key, &server_cid),
        &server.local_connection_ids.entries[0].stateless_reset_token,
    );

    try server.sendNewConnectionIdWithDerivedToken("derived-cid");
    var packet = try client.receivePacket();
    defer packet.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &quic.stateless_reset.tokenForConnectionId(reset_key, "derived-cid"),
        &packet.frames[0].new_connection_id.stateless_reset_token,
    );
}

test "QUIC 1-RTT sends QUIC-LB connection IDs with derived reset tokens" {
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
    const reset_key = [_]u8{0x6c} ** quic.stateless_reset.static_key_len;
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe5} ** quic.protection.secret_len,
    );
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
        .local_stateless_reset_key = reset_key,
    });
    defer server.deinit();

    const config = quic.quic_lb.Config{
        .config_rotation = 3,
        .server_id_len = 3,
        .nonce_len = 4,
        .key = .{
            0x8f, 0x95, 0xf0, 0x92, 0x45, 0x76, 0x5f, 0x80,
            0x25, 0x69, 0x34, 0xe5, 0x0c, 0x66, 0x20, 0x7f,
        },
    };
    const server_id = [_]u8{ 0xed, 0x79, 0x3a };
    try server.sendNewConnectionIdQuicLb(
        config,
        &server_id,
        &.{ 0xee, 0x08, 0x0d, 0xbf },
        0,
    );
    var packet = try client.receivePacket();
    defer packet.deinit(allocator);
    const advertised = packet.frames[0].new_connection_id;
    var decoded: [3]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        &server_id,
        try quic.quic_lb.decodeServerId(
            config,
            advertised.connection_id,
            &decoded,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &quic.stateless_reset.tokenForConnectionId(
            reset_key,
            advertised.connection_id,
        ),
        &advertised.stateless_reset_token,
    );
}

test "QUIC 1-RTT QUIC-LB issuance rolls back when sending fails" {
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
        [_]u8{0xe6} ** quic.protection.secret_len,
    );
    const reset_key = [_]u8{0x7c} ** quic.stateless_reset.static_key_len;
    var connection = try Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
        .local_stateless_reset_key = reset_key,
    });
    defer connection.deinit();
    const before = connection.local_connection_ids;
    connection.pacer.budget = 0;
    connection.pacer.last_sent_time_ns = 0;
    connection.rtt_stats.has_measurement = true;
    connection.rtt_stats.smoothed_rtt = 100_000_000;

    try std.testing.expectError(
        error.PacingLimited,
        connection.sendNewConnectionIdQuicLbAt(
            .{
                .config_rotation = 1,
                .server_id_len = 2,
                .nonce_len = 4,
            },
            "id",
            "abcd",
            0,
            0,
            1,
        ),
    );
    try std.testing.expectEqualDeep(before, connection.local_connection_ids);
}

test "QUIC 1-RTT preflights RETIRE_CONNECTION_ID for packet destination CID" {
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
    const keys = quic.protection.deriveAes128Keys([_]u8{0xe2} ** quic.protection.secret_len);

    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();

    _ = try server.local_connection_ids.issue("server-new-cid", [_]u8{0x44} ** 16);
    try std.testing.expectEqual(@as(usize, 2), server.local_connection_ids.count());

    try sendFrames(&client_endpoint, server_endpoint.address(), keys, .{
        .destination_connection_id = "server-new-cid",
        .packet_number = 0,
        .frames = &[_]quic.Frame{
            .{ .stream = .{ .stream_id = 0, .data = "must-not-commit", .fin = false } },
            .{ .retire_connection_id = .{ .sequence_number = 1 } },
        },
    });

    var router = quic.connection_router.Router.init(allocator);
    defer router.deinit();
    try router.register("server-new-cid", .{ .connection_index = 0, .sequence_number = 1 });
    var routed = try server_endpoint.receiveRoutedBytes(router);
    defer routed.deinit(allocator);

    try std.testing.expectError(error.InvalidConnectionId, server.receiveRoutedDatagram(routed));
    try std.testing.expectEqual(@as(usize, 2), server.local_connection_ids.count());
    try std.testing.expectEqual(@as(usize, 0), server.received.ranges.items.len);
    try std.testing.expect(server.findRecvStreamEntry(0) == null);
    try std.testing.expect(server.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.protocol_violation), server.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.retire_connection_id)), server.close_info.?.frame_type);
    try std.testing.expectEqualStrings("retire connection id", server.close_info.?.reason_phrase);
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
    try std.testing.expect(client.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.protocol_violation), client.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.new_connection_id)), client.close_info.?.frame_type);
    try std.testing.expectEqualStrings("reset token reuse", client.close_info.?.reason_phrase);

    var client2_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client2_endpoint.deinit();
    const client2_cid = [_]u8{ 0x89, 0x8a, 0x8b, 0x8c };
    var client2 = try Connection.init(&client2_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client2_cid,
        .peer_connection_id = &server_cid,
        .active_connection_id_limit = 2,
    });
    defer client2.deinit();
    try client2.peer_connection_ids.add(1, "cid-1", [_]u8{0x11} ** 16);

    try sendFrames(&server_endpoint, client2_endpoint.address(), keys, .{
        .destination_connection_id = &client2_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .new_connection_id = .{
            .sequence_number = 2,
            .retire_prior_to = 0,
            .connection_id = "cid-2",
            .stateless_reset_token = [_]u8{0x33} ** 16,
        } }},
    });
    try std.testing.expectError(error.ActiveConnectionIdLimit, client2.receivePacket());
    try std.testing.expectEqual(@as(usize, 2), client2.peer_connection_ids.count());
    try std.testing.expect(client2.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.connection_id_limit_error), client2.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.new_connection_id)), client2.close_info.?.frame_type);
    try std.testing.expectEqualStrings("connection id limit", client2.close_info.?.reason_phrase);
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
    try std.testing.expect(server.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.protocol_violation), server.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.handshake_done)), server.close_info.?.frame_type);
    try std.testing.expectEqualStrings("handshake done", server.close_info.?.reason_phrase);

    var server2_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server2_endpoint.deinit();
    const server2_cid = [_]u8{ 0x65, 0x66, 0x77, 0x89 };
    var server2 = try Connection.init(&server2_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server2_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer server2.deinit();

    try sendFrames(&client_endpoint, server2_endpoint.address(), client_keys, .{
        .destination_connection_id = &server2_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .new_token = .{ .token = "illegal" } }},
    });
    try std.testing.expectError(error.InvalidFrame, server2.receivePacket());
    try std.testing.expectEqual(@as(?[]const u8, null), server2.latestNewToken());
    try std.testing.expect(server2.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.protocol_violation), server2.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.new_token)), server2.close_info.?.frame_type);
    try std.testing.expectEqualStrings("new token", server2.close_info.?.reason_phrase);
}

test "QUIC 1-RTT generic send validates role and extension-gated frames" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer endpoint.deinit();

    const local_cid = [_]u8{ 0x72, 0x6f, 0x6c, 0x65 };
    const peer_cid = [_]u8{ 0x70, 0x65, 0x65, 0x72 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0x72} ** quic.protection.secret_len);

    var client = try Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &local_cid,
        .peer_connection_id = &peer_cid,
        .local_endpoint = .client,
    });
    defer client.deinit();

    try std.testing.expectError(error.MissingFrame, client.send(&.{}));
    try std.testing.expectError(error.InvalidFrame, client.send(&.{.{ .handshake_done = {} }}));
    try std.testing.expectError(error.InvalidFrame, client.send(&.{.{ .new_token = .{ .token = "client-token" } }}));
    try std.testing.expectError(error.DatagramsNotEnabled, client.send(&.{.{ .datagram = .{ .data = "disabled", .length_present = true } }}));
    try std.testing.expectError(error.AckFrequencyDisabled, client.send(&.{.{ .immediate_ack = {} }}));
    try std.testing.expectError(error.AckFrequencyDisabled, client.send(&.{.{ .ack_frequency = .{
        .sequence_number = 0,
        .ack_eliciting_threshold = 2,
        .request_max_ack_delay = 10,
        .reordering_threshold = 2,
    } }}));

    var limited = try Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &local_cid,
        .peer_connection_id = &peer_cid,
        .peer_max_datagram_frame_size = 8,
    });
    defer limited.deinit();
    try std.testing.expectError(error.DatagramTooLarge, limited.send(&.{.{ .datagram = .{ .data = "1234567", .length_present = true } }}));
    try limited.send(&.{.{ .datagram = .{ .data = "1234567", .length_present = false } }});
    var datagram_packet = try endpoint.receiveBytes();
    defer datagram_packet.deinit(allocator);

    var server = try Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &local_cid,
        .peer_connection_id = &peer_cid,
        .local_endpoint = .server,
    });
    defer server.deinit();
    try std.testing.expectError(error.InvalidFrame, server.send(&.{.{ .new_token = .{ .token = "" } }}));
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
    try std.testing.expectEqual(@as(usize, 1), client.sent.packets.items.len);
    try std.testing.expect(!client.sent.packets.items[0].ack_eliciting);
    try std.testing.expectEqual(@as(usize, 0), client.recovery.pendingCount());
    try std.testing.expectEqual(@as(usize, 0), client.congestion.bytes_in_flight);
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
    try std.testing.expectEqual(@as(usize, 1), server2.sent.packets.items.len);
    try std.testing.expect(!server2.sent.packets.items[0].ack_eliciting);
    try std.testing.expectEqual(@as(usize, 0), server2.recovery.pendingCount());
    try std.testing.expectEqual(@as(usize, 0), server2.congestion.bytes_in_flight);
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
    try std.testing.expect(server.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.final_size_error), server.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.reset_stream)), server.close_info.?.frame_type);
    try std.testing.expectEqualStrings("final size", server.close_info.?.reason_phrase);
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
    try std.testing.expectEqual(@as(u64, 1), client.recovery.pending.items[0].packetNumberAt(0).?);
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
    try std.testing.expectEqual(@as(usize, 2), client.recovery.pending.items[0].packetCount());

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

    var observed_send = ObservedBatchSend{ .delegate = client.endpoint.io };
    var observed_vtable = client.endpoint.io.vtable.*;
    observed_vtable.netSend = ObservedBatchSend.netSend;
    client.endpoint.io = .{
        .userdata = &observed_send,
        .vtable = &observed_vtable,
    };
    defer client.endpoint.io = observed_send.delegate;

    const serviced = (try client.serviceLossDetectionTimer(210_000_000)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(LossDetectionTimerKind.pto, serviced.kind);
    try std.testing.expectEqual(@as(usize, 1), observed_send.calls);
    if (client.endpoint.gsoSendEnabled()) {
        try std.testing.expectEqual(@as(usize, 1), observed_send.last_message_count);
        try std.testing.expect(observed_send.last_control_len != 0);
    } else {
        try std.testing.expectEqual(@as(usize, 2), observed_send.last_message_count);
        try std.testing.expectEqual(@as(usize, 0), observed_send.last_control_len);
    }
    try std.testing.expectEqual(@as(u8, 1), client.ptoBackoffCount());
    try std.testing.expectEqual(@as(usize, 2), client.recovery.pending.items[0].packetCount());
    try std.testing.expectEqual(@as(usize, 2), client.recovery.pending.items[1].packetCount());

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

test "QUIC 1-RTT PTO batch sends pacing-limited prefix" {
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
    const keys = quic.protection.deriveAes128Keys([_]u8{0xd9} ** quic.protection.secret_len);

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

    const first_candidate = client.recovery.ptoCandidateAt(0) orelse return error.TestUnexpectedResult;
    const first_probe_packet_number = client.next_packet_number;
    const first_probe_packet_number_len = quic.protection.packetNumberLenForPayload(
        first_probe_packet_number,
        client.sent.largestAcknowledged(),
        first_candidate.payload.len,
    );
    const first_probe_packet_len = try quic.protection.shortPacketLen(.{
        .destination_connection_id = client.config.peer_connection_id,
        .packet_number = first_probe_packet_number,
        .packet_number_len = first_probe_packet_number_len,
        .payload = first_candidate.payload,
    });
    client.pacer.budget = first_probe_packet_len;
    client.pacer.last_sent_time_ns = 0;

    try std.testing.expectEqual(@as(usize, 1), try client.retransmitPtoProbesAt(0, 2));
    try std.testing.expectEqual(@as(u8, 1), client.ptoBackoffCount());
    try std.testing.expect(client.pacing_blocked_until_ns != null);
    try std.testing.expectEqual(@as(usize, 2), client.recovery.pending.items[0].packetCount());
    try std.testing.expectEqual(@as(usize, 1), client.recovery.pending.items[1].packetCount());

    var original0 = try server.receivePacket();
    defer original0.deinit(allocator);
    var original1 = try server.receivePacket();
    defer original1.deinit(allocator);
    var probe0 = try server.receivePacket();
    defer probe0.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), original0.packet.packet_number);
    try std.testing.expectEqual(@as(u64, 1), original1.packet.packet_number);
    try std.testing.expectEqual(@as(u64, 2), probe0.packet.packet_number);
}

test "QUIC 1-RTT stateful batch commits stream flow and recovery" {
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

    const client_cid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4 };
    const server_cid = [_]u8{ 0xb5, 0xb6, 0xb7, 0xb8 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb9} ** quic.protection.secret_len,
    );
    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .enable_pacing = false,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();

    const first = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .data = "first",
    } }};
    const second = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .offset = 5,
        .data = "second",
        .fin = true,
    } }};
    const packets = [_][]const quic.Frame{ &first, &second };
    try client.sendMany(&packets);

    try std.testing.expectEqual(@as(u64, 2), client.next_packet_number);
    try std.testing.expectEqual(@as(u64, 11), client.send_flow.used);
    try std.testing.expectEqual(
        @as(u64, 11),
        client.findSendStreamEntry(0).?.flow.used,
    );
    try std.testing.expectEqual(
        @as(u64, 11),
        client.findSendStreamEntry(0).?.highest_sent_end,
    );
    try std.testing.expectEqual(@as(usize, 2), client.pendingRecoveryCount());
    try std.testing.expectEqual(@as(usize, 2), client.sent.packets.items.len);

    var received0 = try server.receivePacket();
    defer received0.deinit(allocator);
    var received1 = try server.receivePacket();
    defer received1.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), received0.packet.packet_number);
    try std.testing.expectEqualStrings(
        "first",
        received0.frames[0].stream.data,
    );
    try std.testing.expectEqual(@as(u64, 1), received1.packet.packet_number);
    try std.testing.expectEqualStrings(
        "second",
        received1.frames[0].stream.data,
    );
    try std.testing.expect(received1.frames[0].stream.fin);
}

test "QUIC 1-RTT stateful batch splits at AEAD key generation boundary" {
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

    const client_cid = [_]u8{ 0xba, 0xbb, 0xbc, 0xbd };
    const server_cid = [_]u8{ 0xbe, 0xbf, 0xc0, 0xc1 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc2} ** quic.protection.secret_len,
    );
    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .aead_confidentiality_limit = 2,
        .enable_pacing = false,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .aead_confidentiality_limit = 2,
        .enable_pacing = false,
    });
    defer server.deinit();

    const ping = [_]quic.Frame{.{ .ping = {} }};
    const packets = [_][]const quic.Frame{ &ping, &ping, &ping };
    try client.sendMany(&packets);
    try std.testing.expectEqual(@as(u64, 3), client.next_packet_number);
    try std.testing.expectEqual(
        @as(u64, 1),
        client.localOneRttKeyUpdateCount(),
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        client.encryptedPacketsWithCurrentKeys(),
    );
    try std.testing.expectEqual(
        @as(?u64, 2),
        client.pendingOneRttKeyUpdateAckThreshold(),
    );

    var packet0 = try server.receivePacket();
    defer packet0.deinit(allocator);
    var packet1 = try server.receivePacket();
    defer packet1.deinit(allocator);
    var packet2 = try server.receivePacket();
    defer packet2.deinit(allocator);
    try std.testing.expect(!packet0.packet.key_phase);
    try std.testing.expect(!packet1.packet.key_phase);
    try std.testing.expect(packet2.packet.key_phase);
    try std.testing.expect(packet2.peer_initiated_key_update);
}

test "QUIC 1-RTT stateful batch stops at pacing deadline" {
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

    const client_cid = [_]u8{ 0xc3, 0xc4, 0xc5, 0xc6 };
    const server_cid = [_]u8{ 0xc7, 0xc8, 0xc9, 0xca };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xcb} ** quic.protection.secret_len,
    );
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
    const payload_len = try ping[0].wireLen();
    const packet_number_len =
        quic.protection.packetNumberLenForPayload(0, null, payload_len);
    const packet_len = try quic.protection.shortPacketLen(.{
        .destination_connection_id = &server_cid,
        .packet_number = 0,
        .packet_number_len = packet_number_len,
        .payload = &.{0},
    });
    client.pacer.budget = packet_len;
    client.pacer.last_sent_time_ns = 0;

    const packets = [_][]const quic.Frame{ &ping, &ping };
    const result = try client.sendManyProgressAt(&packets, 0);
    try std.testing.expectEqual(@as(usize, 1), result.sent_count);
    try std.testing.expectEqual(@as(usize, 1), result.protected_count);
    try std.testing.expect(result.send_error == null);
    try std.testing.expect(client.pacing_blocked_until_ns != null);
    try std.testing.expectEqual(@as(u64, 1), client.next_packet_number);
    try std.testing.expectEqual(@as(usize, 1), client.pendingRecoveryCount());

    var received = try server.receivePacket();
    defer received.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), received.packet.packet_number);
}

const ObservedBatchSend = struct {
    delegate: std.Io,
    fail_after_prefix: ?usize = null,
    calls: usize = 0,
    last_message_count: usize = 0,
    last_control_len: usize = 0,

    fn netSend(
        userdata: ?*anyopaque,
        socket_handle: net.Socket.Handle,
        messages: []net.OutgoingMessage,
        flags: net.SendFlags,
    ) struct { ?net.Socket.SendError, usize } {
        const self: *ObservedBatchSend = @ptrCast(@alignCast(userdata));
        self.calls += 1;
        self.last_message_count = messages.len;
        self.last_control_len = if (messages.len == 0) 0 else messages[0].control.len;
        const configured_prefix = self.fail_after_prefix orelse {
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        };
        const prefix_len = @min(configured_prefix, messages.len);
        if (prefix_len != 0) {
            const send_error, const sent_count = self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages[0..prefix_len],
                flags,
            );
            if (send_error != null or sent_count != prefix_len) {
                return .{ send_error, sent_count };
            }
        }
        return .{ error.NetworkDown, prefix_len };
    }
};

test "QUIC 1-RTT stateful batch rolls back unsent suffix and skips nonces" {
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

    const client_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4 };
    const server_cid = [_]u8{ 0xc5, 0xc6, 0xc7, 0xc8 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc9} ** quic.protection.secret_len,
    );
    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .enable_pacing = false,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();

    client.endpoint.gso_send_enabled = false;
    var partial_send = ObservedBatchSend{
        .delegate = client.endpoint.io,
        .fail_after_prefix = 1,
    };
    var partial_vtable = client.endpoint.io.vtable.*;
    partial_vtable.netSend = ObservedBatchSend.netSend;
    client.endpoint.io = .{
        .userdata = &partial_send,
        .vtable = &partial_vtable,
    };
    defer client.endpoint.io = partial_send.delegate;

    const first = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .data = "first",
    } }};
    const second = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .offset = 5,
        .data = "second",
    } }};
    const packets = [_][]const quic.Frame{ &first, &second };
    const result = try client.sendManyProgressAt(&packets, 1_000);
    try std.testing.expectEqual(@as(usize, 1), result.sent_count);
    try std.testing.expectEqual(@as(usize, 2), result.protected_count);
    try std.testing.expectEqual(error.NetworkDown, result.send_error.?);
    try std.testing.expectEqual(@as(u64, 2), client.next_packet_number);
    try std.testing.expectEqual(@as(u64, 5), client.send_flow.used);
    try std.testing.expectEqual(
        @as(u64, 5),
        client.findSendStreamEntry(0).?.flow.used,
    );
    try std.testing.expectEqual(
        @as(u64, 5),
        client.findSendStreamEntry(0).?.highest_sent_end,
    );
    try std.testing.expectEqual(@as(usize, 1), client.pendingRecoveryCount());
    try std.testing.expectEqual(@as(usize, 1), client.sent.packets.items.len);
    try std.testing.expectEqual(
        @as(u64, 2),
        client.encryptedPacketsWithCurrentKeys(),
    );

    var received = try server.receivePacket();
    defer received.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), received.packet.packet_number);
    try std.testing.expectEqualStrings(
        "first",
        received.frames[0].stream.data,
    );

    // Retry the unsent application suffix under packet number 2. The receiver
    // accepts the gap at packet 1, while flow/recovery state advances only now.
    client.endpoint.io = partial_send.delegate;
    try client.send(&second);
    try std.testing.expectEqual(@as(u64, 3), client.next_packet_number);
    try std.testing.expectEqual(@as(u64, 11), client.send_flow.used);
    try std.testing.expectEqual(
        @as(u64, 11),
        client.findSendStreamEntry(0).?.highest_sent_end,
    );
    var retried = try server.receivePacket();
    defer retried.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), retried.packet.packet_number);
    try std.testing.expectEqualStrings(
        "second",
        retried.frames[0].stream.data,
    );
}

test "QUIC 1-RTT PTO batch commits a socket-sent prefix before returning error" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer client_endpoint.deinit();

    const client_cid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4 };
    const server_cid = [_]u8{ 0xe5, 0xe6, 0xe7, 0xe8 };
    const keys = quic.protection.deriveAes128Keys([_]u8{0xe9} ** quic.protection.secret_len);

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
    const bytes_in_flight_before = client.bytesInFlight();
    client.endpoint.gso_send_enabled = false;

    // Replace only the client's send function after setup. The wrapper lets
    // the real socket emit the first datagram, then reproduces the partial
    // progress plus error result permitted by sendmmsg-style backends.
    var partial_send = ObservedBatchSend{
        .delegate = client.endpoint.io,
        .fail_after_prefix = 1,
    };
    var partial_vtable = client.endpoint.io.vtable.*;
    partial_vtable.netSend = ObservedBatchSend.netSend;
    client.endpoint.io = .{
        .userdata = &partial_send,
        .vtable = &partial_vtable,
    };
    defer client.endpoint.io = partial_send.delegate;

    try std.testing.expectError(error.NetworkDown, client.retransmitPtoProbesAt(20_000_000, 2));
    try std.testing.expectEqual(@as(usize, 1), partial_send.calls);
    try std.testing.expectEqual(@as(u64, 3), client.next_packet_number);
    try std.testing.expectEqual(@as(u8, 1), client.ptoBackoffCount());
    try std.testing.expectEqual(bytes_in_flight_before + 1, client.bytesInFlight());
    try std.testing.expectEqual(@as(usize, 2), client.recovery.pending.items[0].packetCount());
    try std.testing.expectEqual(@as(usize, 1), client.recovery.pending.items[1].packetCount());

    var original0 = try server.receivePacket();
    defer original0.deinit(allocator);
    var original1 = try server.receivePacket();
    defer original1.deinit(allocator);
    var probe0 = try server.receivePacket();
    defer probe0.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), original0.packet.packet_number);
    try std.testing.expectEqual(@as(u64, 1), original1.packet.packet_number);
    try std.testing.expectEqual(@as(u64, 2), probe0.packet.packet_number);
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
    client.pto_count = 100;
    try std.testing.expectEqual(quic.rtt.max_pto_ns, client.ptoPeriod());

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
    try std.testing.expectEqual(@as(usize, 2), client.recovery.pending.items[0].packetCount());
    try std.testing.expect(!(try client.retransmitTimeThresholdLoss(1_000, 150)));
    try std.testing.expectEqual(@as(usize, 2), client.recovery.pending.items[0].packetCount());
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
    try std.testing.expectEqual(@as(usize, 2), client.recovery.pending.items[0].packetCount());

    try std.testing.expect(try client.retransmitPacketThresholdLoss());
    var second_retransmit = try server.receivePacket();
    defer second_retransmit.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 6), second_retransmit.packet.packet_number);
    try std.testing.expectEqual(@as(usize, 2), client.recovery.pending.items[1].packetCount());
    try std.testing.expect(!(try client.retransmitPacketThresholdLoss()));

    try server.sendAck(0);
    var second_ack = try client.receivePacket();
    defer second_ack.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 6), second_ack.frames[0].ack.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 2), second_ack.frames[0].ack.first_ack_range);
    try std.testing.expectEqual(@as(usize, 2), client.pendingRecoveryCount());
    try std.testing.expectEqual(@as(u64, 2), client.recovery.pending.items[0].packetNumberAt(0).?);
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
    client.pacer.budget = 0;
    client.pacer.last_sent_time_ns = 1_300_000_000;
    try server.sendAck(0);

    var ack = try client.receivePacketAt(1_400_000_000);
    defer ack.deinit(allocator);
    try std.testing.expectEqual(client.pacer.maxBurstSize(), client.pacer.budget);
    try std.testing.expectEqual(@as(?u64, null), client.pacer.last_sent_time_ns);
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

    // The combined helper advances retained overlap-validation storage and
    // emits both connection- and stream-level credit transactionally.
    var combined_server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer combined_server_endpoint.deinit();
    var combined_client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer combined_client_endpoint.deinit();
    const combined_client_cid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
    const combined_server_cid = [_]u8{ 0x35, 0x36, 0x37, 0x38 };
    var combined_client = try Connection.init(&combined_client_endpoint, .{
        .peer = combined_server_endpoint.address(),
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &combined_client_cid,
        .peer_connection_id = &combined_server_cid,
        .initial_send_max_data = 8,
        .initial_send_max_stream_data = 8,
    });
    defer combined_client.deinit();
    var combined_server = try Connection.init(&combined_server_endpoint, .{
        .peer = combined_client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &combined_server_cid,
        .peer_connection_id = &combined_client_cid,
        .initial_receive_max_data = 8,
        .receive_window = 8,
        .initial_receive_max_stream_data = 8,
        .stream_receive_window = 8,
        .local_endpoint = .server,
    });
    defer combined_server.deinit();
    try combined_client.send(&.{.{ .stream = .{
        .stream_id = 0,
        .data = "123456",
    } }});
    var combined_data = try combined_server.receivePacket();
    defer combined_data.deinit(allocator);

    var failed_credit_send = ObservedBatchSend{
        .delegate = combined_server.endpoint.io,
        .fail_after_prefix = 0,
    };
    var failed_credit_vtable = combined_server.endpoint.io.vtable.*;
    failed_credit_vtable.netSend = ObservedBatchSend.netSend;
    combined_server.endpoint.io = .{
        .userdata = &failed_credit_send,
        .vtable = &failed_credit_vtable,
    };
    try std.testing.expectError(
        error.NetworkDown,
        combined_server.releaseReceivedCapacity(0, 6),
    );
    try std.testing.expectEqual(
        @as(u64, 8),
        combined_server.recv_flow.limit,
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        combined_server.recv_flow.consumed,
    );
    try std.testing.expectEqual(
        @as(u64, 8),
        combined_server.findRecvStreamEntry(0).?.flow.limit,
    );
    try std.testing.expectEqual(
        @as(usize, 6),
        combined_server.findRecvStreamEntry(0).?.recv_state.available().len,
    );
    combined_server.endpoint.io = failed_credit_send.delegate;

    try combined_server.releaseReceivedCapacity(0, 6);
    try std.testing.expectEqual(
        @as(usize, 0),
        combined_server.findRecvStreamEntry(0).?.recv_state.available().len,
    );
    var credit = try combined_client.receivePacket();
    defer credit.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), credit.frames.len);
    try std.testing.expectEqual(@as(u64, 14), credit.frames[0].max_data.maximum_data);
    try std.testing.expectEqual(
        @as(u64, 14),
        credit.frames[1].max_stream_data.maximum_stream_data,
    );
    try std.testing.expectEqual(@as(u64, 14), combined_client.send_flow.limit);
    try std.testing.expectEqual(
        @as(u64, 14),
        combined_client.findSendStreamEntry(0).?.flow.limit,
    );

    var violating_server_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer violating_server_endpoint.deinit();
    var violating_client_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer violating_client_endpoint.deinit();
    const violating_client_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const violating_server_cid = [_]u8{ 0x75, 0x76, 0x77, 0x78 };
    var violating_server = try Connection.init(&violating_server_endpoint, .{
        .peer = violating_client_endpoint.address(),
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &violating_server_cid,
        .peer_connection_id = &violating_client_cid,
        .initial_receive_max_stream_data = 3,
        .stream_receive_window = 3,
        .local_endpoint = .server,
    });
    defer violating_server.deinit();

    try sendFrames(&violating_client_endpoint, violating_server_endpoint.address(), client_keys, .{
        .destination_connection_id = &violating_server_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = "abcd", .fin = false } }},
    });
    try std.testing.expectError(error.FlowControlViolation, violating_server.receivePacket());
    try std.testing.expectEqual(@as(u64, 0), violating_server.recv_data_total);
    try std.testing.expectEqual(@as(usize, 0), violating_server.stream_recv_flows.items.len);
    try std.testing.expect(violating_server.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.flow_control_error), violating_server.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.stream) | 0x02), violating_server.close_info.?.frame_type);
    try std.testing.expectEqualStrings("flow control", violating_server.close_info.?.reason_phrase);
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
    try std.testing.expectEqual(@as(u64, 4), server.datagramsReceived());
    try std.testing.expectEqual(@as(u64, 1), server.datagramsDroppedIncoming());
    try std.testing.expectEqual(@as(usize, 2), server.datagramReceiveQueueLen());

    const kept_first = (try server.popDatagram(&out)).?;
    try std.testing.expectEqualStrings("three", kept_first);
    try std.testing.expectError(error.DatagramBufferTooSmall, server.popDatagram(out[0..2]));
    try std.testing.expectEqual(@as(usize, 0), server.datagramReceiveQueueLen());

    try client.send(&.{
        .{ .datagram = .{ .data = "four", .length_present = true } },
        .{ .datagram = .{ .data = "five", .length_present = true } },
    });
    var wrapped = try server.receivePacket();
    defer wrapped.deinit(allocator);
    const wrapped_first = (try server.popDatagram(&out)).?;
    try std.testing.expectEqualStrings("four", wrapped_first);
    const wrapped_second = (try server.popDatagram(&out)).?;
    try std.testing.expectEqualStrings("five", wrapped_second);
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
    try sendFrames(&endpoint, endpoint.address(), keys, .{
        .destination_connection_id = &cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .datagram = .{ .data = "disabled", .length_present = true } }},
    });
    try std.testing.expectError(error.InvalidFrame, no_dgram.receivePacket());
    try std.testing.expect(no_dgram.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.protocol_violation), no_dgram.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.datagram_len)), no_dgram.close_info.?.frame_type);
    try std.testing.expectEqualStrings("datagram", no_dgram.close_info.?.reason_phrase);

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

    var limited_rx_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer limited_rx_endpoint.deinit();
    const limited_rx_cid = [_]u8{ 0xe5, 0xe6, 0xe7, 0xe8 };
    var limited_rx = try Connection.init(&limited_rx_endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &limited_rx_cid,
        .peer_connection_id = &cid,
        .local_max_datagram_frame_size = 8,
        .peer_max_datagram_frame_size = 8,
    });
    defer limited_rx.deinit();
    try sendFrames(&endpoint, limited_rx_endpoint.address(), keys, .{
        .destination_connection_id = &limited_rx_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .datagram = .{ .data = "1234567", .length_present = true } }},
    });
    try std.testing.expectError(error.InvalidFrame, limited_rx.receivePacket());
    try std.testing.expect(limited_rx.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.protocol_violation), limited_rx.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.datagram_len)), limited_rx.close_info.?.frame_type);
    try std.testing.expectEqualStrings("datagram", limited_rx.close_info.?.reason_phrase);
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
    try std.testing.expect(disabled.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.protocol_violation), disabled.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.immediate_ack)), disabled.close_info.?.frame_type);
    try std.testing.expectEqualStrings("immediate ack", disabled.close_info.?.reason_phrase);

    var disabled2_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer disabled2_endpoint.deinit();
    const disabled2_cid = [_]u8{ 0xf9, 0xfa, 0xfb, 0xfc };
    var disabled2 = try Connection.init(&disabled2_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &disabled2_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
    });
    defer disabled2.deinit();
    try sendFrames(&client_endpoint, disabled2_endpoint.address(), keys, .{
        .destination_connection_id = &disabled2_cid,
        .packet_number = 0,
        .frames = &[_]quic.Frame{.{ .ack_frequency = .{
            .sequence_number = 0,
            .ack_eliciting_threshold = 2,
            .request_max_ack_delay = 10,
            .reordering_threshold = 2,
        } }},
    });
    try std.testing.expectError(error.AckFrequencyDisabled, disabled2.receivePacket());
    try std.testing.expect(disabled2.closing());
    try std.testing.expectEqual(@intFromEnum(quic.TransportErrorCode.protocol_violation), disabled2.close_info.?.error_code);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.FrameType.ack_frequency)), disabled2.close_info.?.frame_type);
    try std.testing.expectEqualStrings("ack frequency", disabled2.close_info.?.reason_phrase);
}

test "QUIC 1-RTT qlog observer records packet and recovery events" {
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

    var client_output: std.Io.Writer.Allocating = .init(allocator);
    defer client_output.deinit();
    var client_trace = quic.qlog.Trace.init(&client_output.writer, .{});
    var client_observer = quic.qlog.Observer.init(&client_trace);
    var server_output: std.Io.Writer.Allocating = .init(allocator);
    defer server_output.deinit();
    var server_trace = quic.qlog.Trace.init(&server_output.writer, .{});
    var server_observer = quic.qlog.Observer.init(&server_trace);

    const client_cid = [_]u8{ 1, 2, 3, 4 };
    const server_cid = [_]u8{ 5, 6, 7, 8 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd7} ** quic.protection.secret_len,
    );
    var client = try Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .qlog_observer = &client_observer,
    });
    defer client.deinit();
    var server = try Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .qlog_observer = &server_observer,
    });
    defer server.deinit();

    const ping = [_]quic.Frame{.{ .ping = {} }};
    try client.sendAt(&ping, 1_000_000);
    var received = try server.receivePacketAt(2_000_000);
    defer received.deinit(allocator);
    try std.testing.expect(try server.sendAckForPacketsIfNeeded(&.{received}));
    var ack = try client.receivePacketAt(3_000_000);
    defer ack.deinit(allocator);
    try client.initiateKeyUpdate();

    try std.testing.expect(client.takeQlogError() == null);
    try std.testing.expect(server.takeQlogError() == null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.written(),
        "\"name\":\"quic:packet_sent\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.written(),
        "\"name\":\"quic:packet_received\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.written(),
        "\"name\":\"recovery:metrics_updated\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.written(),
        "\"name\":\"security:key_updated\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        client_output.written(),
        "\"key_type\":\"client_1rtt_secret\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        server_output.written(),
        "\"frame_type\":\"ping\"",
    ) != null);
}

test "QUIC 1-RTT qlog observer reports sticky failures without rolling back send" {
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
    var sender_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender_endpoint.deinit();

    var failing: std.Io.Writer = .failing;
    var trace = quic.qlog.Trace.init(&failing, .{});
    var observer = quic.qlog.Observer.init(&trace);
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe8} ** quic.protection.secret_len,
    );
    var sender = try Connection.init(&sender_endpoint, .{
        .peer = receiver.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
        .qlog_observer = &observer,
    });
    defer sender.deinit();

    try sender.sendAt(&.{.{ .ping = {} }}, 1);
    try std.testing.expectEqual(@as(u64, 1), sender.next_packet_number);
    try std.testing.expect(sender.qlogFailed());
    try std.testing.expectEqualStrings(
        "WriteFailed",
        @errorName(sender.takeQlogError() orelse
            return error.TestUnexpectedResult),
    );
    try std.testing.expect(!sender.qlogFailed());
}
