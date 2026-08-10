const std = @import("std");
const quic = @import("mod.zig");
const fixed_bit = @import("one_rtt/fixed_bit.zig");
const handshake_status = @import("one_rtt/handshake_status.zig");

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
    InvalidPostHandshakeCrypto,
};

pub const SendOptions = struct {
    destination_connection_id: []const u8,
    packet_number: u64,
    packet_number_len: u8 = 4,
    fixed_bit: bool = true,
    spin_bit: bool = false,
    key_phase: bool = false,
    frames: []const quic.Frame,
};

pub const BatchSendOptions = struct {
    destination_connection_id: []const u8,
    first_packet_number: u64,
    packet_number_len: u8 = 4,
    fixed_bit: bool = true,
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
    fixed_bit: bool = true,
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
    max_receive_window: ?u64 = null,
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
    max_stream_receive_window: ?u64 = null,
    max_datagram_size: usize = quic.congestion.default_max_datagram_size,
    /// CUBIC is the high-throughput default; NewReno remains selectable for
    /// compatibility-sensitive deployments.
    congestion_algorithm: quic.congestion.Algorithm = .cubic,
    enable_hystart: bool = true,
    enable_pacing: bool = true,
    pacing_max_burst_packets: usize = quic.pacing.Pacer.default_max_burst_packets,
    max_stored_new_tokens: usize = 4,
    enable_spin_bit: bool = false,
    /// RFC 9287 negotiation is directional: advertise means accepting zero;
    /// peer advertisement permits sending unpredictable QUIC Bit values.
    accept_zero_fixed_bit: bool = false,
    grease_fixed_bit: bool = false,
    active_connection_id_limit: usize = quic.default_active_connection_id_limit,
    local_max_idle_timeout_ms: u64 = 0,
    peer_max_idle_timeout_ms: u64 = 0,
    /// Optional keep-alive PING cadence in milliseconds.
    ///
    /// When enabled, the runtime schedules at most one PING after peer silence
    /// exceeds this interval, capped to half the negotiated idle timeout and
    /// floored at 1.5x the base PTO like quic-zig/tquic-style production
    /// loops. A received packet clears the outstanding keep-alive flag.
    keep_alive_period_ms: u64 = 0,
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
    /// Optional policy cap applied after the negotiated suite's RFC 9001
    /// confidentiality limit. `maxInt(u64)` means “use the suite limit”.
    aead_confidentiality_limit: u64 = std.math.maxInt(u64),
    /// Lifetime count of packets that fail 1-RTT authentication before the
    /// connection is closed with AEAD_LIMIT_REACHED. `maxInt(u64)` means “use
    /// the negotiated suite's limit”.
    aead_integrity_limit: u64 = std.math.maxInt(u64),
    qlog_observer: ?*quic.qlog.Observer = null,
    /// Integrated TLS handshakes set this once their Finished exchange
    /// succeeds. Manually keyed connections leave it false and can call
    /// `markTlsHandshakeComplete` explicitly.
    tls_handshake_complete: bool = false,
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

/// Allocation-free snapshot of the 1-RTT transport state.
///
/// The counters intentionally live on `Connection` instead of being derived
/// from recovery queues: sent/lost packets can leave those queues after ACK
/// processing, while observability APIs need stable lifetime totals similar to
/// quic-zig WebTransport stats and browser `getStats()` surfaces.
pub const ConnectionStats = struct {
    packets_sent: u64,
    packets_received: u64,
    packets_lost: u64,
    /// Protected QUIC packet bytes accepted by the socket.
    bytes_sent: u64,
    /// Protected QUIC packet bytes authenticated and applied by the receiver.
    bytes_received: u64,
    bytes_in_flight: usize,
    congestion_window: usize,
    congestion_available: usize,
    outgoing_streams_created: u64,
    incoming_streams_created: u64,
    datagrams_sent: u64,
    datagrams_received: u64,
    datagrams_dropped_incoming: u64,
    datagram_receive_queue_len: usize,
    smoothed_rtt_ns: ?u64,
    rtt_variance_ns: ?u64,
    min_rtt_ns: ?u64,
    latest_rtt_ns: ?u64,
    pending_recovery_count: usize,
    pto_backoff_count: u8,
    ecn_validation_failed: bool,
    authentication_failures: u64,
    local_key_update_count: u64,
    peer_key_update_count: u64,

    pub fn lossRate(self: ConnectionStats) f64 {
        if (self.packets_sent == 0) return 0.0;
        return @as(f64, @floatFromInt(self.packets_lost)) /
            @as(f64, @floatFromInt(self.packets_sent));
    }
};

pub const SendStreamStats = struct {
    bytes_sent: u64,
    highest_sent_offset: u64,
    send_limit: u64,
    blocked: bool,
    stopped: ?StopSendingInfo,
    reset: ?StreamResetInfo,
};

pub const RecvStreamStats = struct {
    bytes_received: u64,
    bytes_read: u64,
    highest_received_offset: u64,
    available_bytes: usize,
    receive_limit: u64,
    final_size: ?u64,
    reset: ?StreamResetInfo,
    stop_sending_sent: ?StopSendingInfo,
};

const PeerAddressUpdate = union(enum) {
    none,
    same_unvalidated: usize,
    nat_rebinding: net.IpAddress,
    new_path: struct {
        from: net.IpAddress,
        datagram_len: usize,
        path_validation: quic.path_validation.State,
    },

    fn deinit(self: *PeerAddressUpdate) void {
        switch (self.*) {
            .new_path => |*new_path| new_path.path_validation.deinit(),
            else => {},
        }
        self.* = .none;
    }
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

pub const TimerDeadlineKind = enum {
    ack_delay,
    loss_time,
    pto,
    path_validation,
    keep_alive,
    idle_timeout,
    close,
    key_discard,
};

pub const TimerDeadline = struct {
    kind: TimerDeadlineKind,
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
    last_send_stream_index: ?usize = null,
    stream_recv_flows: std.ArrayList(StreamRecvFlowEntry) = .empty,
    last_recv_stream_index: ?usize = null,
    close_info: ?CloseInfo = null,
    send_key_phase: quic.protection.Aes128KeyPhaseState,
    receive_key_phase: quic.protection.Aes128KeyPhaseState,
    pending_key_update_ack_threshold: ?u64 = null,
    send_key_generation_encrypted_packets: u64 = 0,
    receive_authentication_failures: u64 = 0,
    stored_new_tokens: std.ArrayList([]u8) = .empty,
    handshake_status: handshake_status.Status = .in_progress,
    lowest_one_rtt_packet_number: ?u64 = null,
    peer_max_streams_bidi: u64,
    peer_max_streams_uni: u64,
    streams_blocked_bidi_at: ?u64 = null,
    streams_blocked_uni_at: ?u64 = null,
    recv_max_streams_bidi: u64,
    recv_max_streams_uni: u64,
    spin_bit_value: bool = false,
    fixed_bit_generator: fixed_bit.Generator = .{},
    last_activity_ms: ?u64 = null,
    last_peer_activity_ms: ?u64 = null,
    sent_ack_eliciting_since_peer_activity: bool = false,
    idle_timed_out: bool = false,
    keep_alive_ping_sent: bool = false,
    last_persistent_congestion_packet_number: ?u64 = null,
    pto_count: u8 = 0,
    peer_address_validated: bool = true,
    peer_address_bytes_received: usize = 0,
    peer_address_bytes_sent: usize = 0,
    pmtud: quic.pmtu.State = .{},
    packets_sent_count: u64 = 0,
    packets_received_count: u64 = 0,
    packets_lost_count: u64 = 0,
    bytes_sent_count: u64 = 0,
    bytes_received_count: u64 = 0,
    outgoing_streams_created_count: u64 = 0,
    incoming_streams_created_count: u64 = 0,
    datagram_recv_queue: DatagramRecvQueue = .{},
    datagrams_sent_count: u64 = 0,
    datagrams_received_count: u64 = 0,
    datagrams_dropped_incoming_count: u64 = 0,
    ack_frequency_send_next_sequence: u64 = 0,
    ack_frequency_recv_next_sequence: u64 = 0,
    ack_eliciting_threshold: u64 = 1,
    ack_eliciting_since_last_ack: u64 = 0,
    ack_delay_start_ns: ?u64 = null,
    ack_delay_deadline_ns: ?u64 = null,
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
            .recv_flow = try .initWithMaxWindow(
                config.initial_receive_max_data,
                config.receive_window,
                config.max_receive_window orelse config.receive_window,
            ),
            .send_key_phase = .init(config.send_keys, false),
            .receive_key_phase = .init(config.receive_keys, false),
            .peer_max_streams_bidi = config.initial_send_max_streams_bidi,
            .peer_max_streams_uni = config.initial_send_max_streams_uni,
            .recv_max_streams_bidi = config.initial_receive_max_streams_bidi,
            .recv_max_streams_uni = config.initial_receive_max_streams_uni,
        };
        errdefer connection.deinit();
        connection.fixed_bit_generator = try .init(
            endpoint.io,
            config.grease_fixed_bit,
        );
        try connection.send_frame_buffer.ensureTotalCapacity(endpoint.allocator, config.max_datagram_size);
        try connection.send_packet_buffer.ensureTotalCapacity(endpoint.allocator, send_buffer_capacity);
        if (config.local_stateless_reset_key) |key| {
            try connection.local_connection_ids.registerInitialWithStaticKey(config.local_connection_id, key);
        } else {
            try connection.local_connection_ids.registerInitial(config.local_connection_id, [_]u8{0} ** 16);
        }
        try connection.peer_connection_ids.add(0, config.peer_connection_id, [_]u8{0} ** 16);
        try connection.peer_connection_ids.markInUse(0);
        if (config.tls_handshake_complete) {
            connection.handshake_status.onTlsComplete(switch (config.local_endpoint) {
                .client => .client,
                .server => .server,
            });
        }
        connection.observeConnectionStarted(null);
        connection.observeParametersSet(null);
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
        self.fixed_bit_generator.deinit();
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

    /// Route metadata for endpoint-level CID dispatch.
    ///
    /// Shared UDP endpoints inspect the QUIC Bit before packet decryption, so
    /// the negotiated RFC 9287 receive policy has to accompany each registered
    /// connection ID.
    pub fn route(
        self: Connection,
        connection_index: usize,
        sequence_number: u64,
    ) quic.connection_router.Route {
        return .{
            .connection_index = connection_index,
            .sequence_number = sequence_number,
            .peer_address = self.config.peer,
            .active_migration_disabled = self.config.peer_disable_active_migration,
            .accept_zero_fixed_bit = self.config.accept_zero_fixed_bit,
        };
    }

    pub fn send(self: *Connection, frames: []const quic.Frame) Error!void {
        try self.sendWithEcn(frames, .not_ect);
    }

    /// Send TLS post-handshake CRYPTO bytes in the application packet-number
    /// space. Generic `send` intentionally rejects CRYPTO in 1-RTT packets so
    /// applications cannot bypass the monotonic TLS stream-offset invariant.
    pub fn sendPostHandshakeCrypto(
        self: *Connection,
        crypto_offset: *u64,
        data: []const u8,
    ) Error!void {
        if (data.len == 0) return error.InvalidPostHandshakeCrypto;
        const next_offset = std.math.add(
            u64,
            crypto_offset.*,
            data.len,
        ) catch return error.InvalidPostHandshakeCrypto;
        const crypto = quic.Frame{ .crypto = .{
            .offset = crypto_offset.*,
            .data = data,
        } };
        const frames_with_done = [_]quic.Frame{
            crypto,
            .{ .handshake_done = {} },
        };
        const frames = if (self.handshake_status.needsHandshakeDone())
            frames_with_done[0..]
        else
            @as([]const quic.Frame, @as(*const [1]quic.Frame, &crypto));
        try self.sendTrackedFramesEcnAtUnchecked(
            frames,
            .not_ect,
            self.monotonicNowNs(),
        );
        crypto_offset.* = next_offset;
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
        // Route the first application packet through the single-packet path
        // while HANDSHAKE_DONE is unsent. It appends the control frame after
        // the caller's frames, preserving application order, and later calls
        // retain normal GSO/sendmmsg batching.
        if (self.handshake_status.needsHandshakeDone()) {
            try self.sendWithEcnAt(
                packets[0],
                .not_ect,
                sent_time_ns,
            );
            return .{ .sent_count = 1, .protected_count = 1 };
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
            if (packet_len > self.currentSendDatagramSize() or
                packet_len > self.endpoint.limits.max_datagram_size)
            {
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
            var blocked_stream_id: ?u64 = null;
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
                    blocked_stream_id = credit.stream_id;
                    break;
                }
            }
            if (blocked_stream_id) |stream_id| {
                if (count == 0) {
                    try self.sendStreamDataBlocked(stream_id);
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
                _ = try self.recovery.trackSent(packet.packet_number, payload);
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
                    .fixed_bit = self.nextFixedBit(),
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
            self.noteOneRttPacketSent(
                packet.packet_number,
                packet.packet_len,
                now_ns,
                packet.ack_eliciting,
            );
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
        try self.sendWithEcnLoop(frames, ecn);
    }

    fn sendWithEcnLoop(
        self: *Connection,
        frames: []const quic.Frame,
        ecn: quic.packet_space.EcnCodepoint,
    ) Error!void {
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
        if (frames.len != 0 and
            self.handshake_status.needsHandshakeDone() and
            !containsHandshakeDone(frames))
        {
            const combined = try self.endpoint.allocator.alloc(
                quic.Frame,
                frames.len + 1,
            );
            defer self.endpoint.allocator.free(combined);
            @memcpy(combined[0..frames.len], frames);
            // Keep caller frames first so scheduling HANDSHAKE_DONE cannot
            // reorder the application's first 1-RTT frame.
            combined[frames.len] = .{ .handshake_done = {} };
            return self.sendWithEcnAtRaw(
                combined,
                ecn,
                sent_time_ns,
            );
        }
        try self.sendWithEcnAtRaw(frames, ecn, sent_time_ns);
    }

    fn sendWithEcnAtRaw(self: *Connection, frames: []const quic.Frame, ecn: quic.packet_space.EcnCodepoint, sent_time_ns: ?u64) Error!void {
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
                try self.sendStreamDataBlocked(frame.stream.stream_id);
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
        return maxDatagramPayloadForFrameSize(@min(frame_limit, self.currentSendDatagramSize()));
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

    /// Return a stable, allocation-free observability snapshot.
    ///
    /// This complements qlog's event stream for fast control loops and
    /// WebTransport-style APIs that need counters/gauges without JSON encoding
    /// or heap traffic on the packet path.
    pub fn stats(self: Connection) ConnectionStats {
        return .{
            .packets_sent = self.packets_sent_count,
            .packets_received = self.packets_received_count,
            .packets_lost = self.packets_lost_count,
            .bytes_sent = self.bytes_sent_count,
            .bytes_received = self.bytes_received_count,
            .bytes_in_flight = self.congestion.bytes_in_flight,
            .congestion_window = self.congestion.congestion_window,
            .congestion_available = self.congestion.available(),
            .outgoing_streams_created = self.outgoing_streams_created_count,
            .incoming_streams_created = self.incoming_streams_created_count,
            .datagrams_sent = self.datagrams_sent_count,
            .datagrams_received = self.datagrams_received_count,
            .datagrams_dropped_incoming = self.datagrams_dropped_incoming_count,
            .datagram_receive_queue_len = self.datagram_recv_queue.count(),
            .smoothed_rtt_ns = if (self.rtt_stats.has_measurement) self.rtt_stats.smoothed_rtt else null,
            .rtt_variance_ns = if (self.rtt_stats.has_measurement) self.rtt_stats.rtt_var else null,
            .min_rtt_ns = if (self.rtt_stats.has_measurement) self.rtt_stats.min_rtt else null,
            .latest_rtt_ns = if (self.rtt_stats.has_measurement) self.rtt_stats.latest_rtt else null,
            .pending_recovery_count = self.recovery.pendingCount(),
            .pto_backoff_count = self.pto_count,
            .ecn_validation_failed = self.sent.ecnDisabled(),
            .authentication_failures = self.receive_authentication_failures,
            .local_key_update_count = self.send_key_phase.keyUpdateCount(),
            .peer_key_update_count = self.receive_key_phase.keyUpdateCount(),
        };
    }

    pub fn getStats(self: Connection) ConnectionStats {
        return self.stats();
    }

    pub fn sendStreamStats(self: Connection, stream_id: u64) ?SendStreamStats {
        for (self.stream_send_flows.items) |entry| {
            if (entry.stream_id != stream_id) continue;
            return .{
                .bytes_sent = entry.flow.used,
                .highest_sent_offset = entry.highest_sent_end,
                .send_limit = entry.flow.limit,
                .blocked = entry.flow.available() == 0,
                .stopped = entry.stopped,
                .reset = entry.reset_sent,
            };
        }
        return null;
    }

    pub fn getSendStreamStats(self: Connection, stream_id: u64) ?SendStreamStats {
        return self.sendStreamStats(stream_id);
    }

    pub fn recvStreamStats(self: Connection, stream_id: u64) ?RecvStreamStats {
        for (self.stream_recv_flows.items) |entry| {
            if (entry.stream_id != stream_id) continue;
            return .{
                .bytes_received = entry.recv_state.receivedByteCount(),
                .bytes_read = std.math.cast(u64, entry.recv_state.read_offset) orelse
                    std.math.maxInt(u64),
                .highest_received_offset = entry.highest_received_end,
                .available_bytes = entry.recv_state.available().len,
                .receive_limit = entry.flow.limit,
                .final_size = entry.final_size,
                .reset = entry.reset,
                .stop_sending_sent = entry.stop_sending_sent,
            };
        }
        return null;
    }

    pub fn getRecvStreamStats(self: Connection, stream_id: u64) ?RecvStreamStats {
        return self.recvStreamStats(stream_id);
    }

    pub fn keepAliveEnabled(self: Connection) bool {
        return self.config.keep_alive_period_ms != 0;
    }

    /// Effective keep-alive interval in milliseconds.
    ///
    /// The configured period is first capped to half the negotiated idle
    /// timeout when one exists, then raised to at least 1.5x PTO so a keep-alive
    /// PING does not race normal loss recovery on high-latency paths.
    pub fn keepAliveIntervalMillis(self: Connection) ?u64 {
        if (!self.keepAliveEnabled()) return null;
        var interval = self.config.keep_alive_period_ms;
        if (self.effectiveIdleTimeoutMillis()) |idle_timeout| {
            interval = @min(interval, @max(@as(u64, 1), idle_timeout / 2));
        }
        const base_pto_ns = self.rtt_stats.pto(true);
        const floor_ns = std.math.add(
            u64,
            base_pto_ns,
            base_pto_ns / 2,
        ) catch std.math.maxInt(u64);
        return @max(interval, nanosToMillisCeil(floor_ns));
    }

    pub fn keepAliveDeadlineMillis(self: Connection) ?u64 {
        if (self.close_info != null or self.idle_timed_out) return null;
        if (!self.handshakeConfirmed() or self.keep_alive_ping_sent) return null;
        const interval = self.keepAliveIntervalMillis() orelse return null;
        const anchor = self.last_peer_activity_ms orelse
            (self.last_activity_ms orelse return null);
        return std.math.add(u64, anchor, interval) catch std.math.maxInt(u64);
    }

    pub fn keepAlivePingOutstanding(self: Connection) bool {
        return self.keep_alive_ping_sent;
    }

    pub fn sendKeepAlive(self: *Connection) Error!bool {
        return self.sendKeepAliveAt(nanosToMillisFloor(self.monotonicNowNs()));
    }

    pub fn sendKeepAliveAt(self: *Connection, now_ms: u64) Error!bool {
        if (self.close_info != null or self.idle_timed_out) return false;
        if (!self.handshakeConfirmed()) return false;
        const frames = [_]quic.Frame{.{ .ping = {} }};
        try self.sendTrackedFramesEcnAt(&frames, .not_ect, millisToNanos(now_ms));
        self.keep_alive_ping_sent = true;
        return true;
    }

    pub fn serviceKeepAliveAt(self: *Connection, now_ms: u64) Error!bool {
        const deadline = self.keepAliveDeadlineMillis() orelse return false;
        if (now_ms < deadline) return false;
        return try self.sendKeepAliveAt(now_ms);
    }

    /// Earliest connection timer for socket/event-loop integration.
    ///
    /// Mature QUIC loops arm one kernel timer for the next item of transport
    /// work instead of polling loss detection, idle timeout, keep-alive,
    /// path-validation, close, and key-discard timers independently.  This
    /// selector is read-only: callers still dispatch the typed helper matching
    /// `kind` when the deadline becomes due.
    pub fn nextTimerDeadline(self: Connection) ?TimerDeadline {
        var next: ?TimerDeadline = null;
        if (self.ack_delay_deadline_ns) |deadline| {
            considerTimerDeadline(&next, .{
                .kind = .ack_delay,
                .deadline_ns = deadline,
            });
        }
        if (self.lossDetectionTimerDeadline()) |deadline| {
            considerTimerDeadline(&next, .{
                .kind = switch (deadline.kind) {
                    .loss_time => .loss_time,
                    .pto => .pto,
                },
                .deadline_ns = deadline.deadline_ns,
            });
        }
        if (self.pathValidationDeadline()) |deadline| {
            considerTimerDeadline(&next, .{
                .kind = .path_validation,
                .deadline_ns = deadline,
            });
        }
        if (self.keepAliveDeadlineMillis()) |deadline| {
            considerTimerDeadline(&next, .{
                .kind = .keep_alive,
                .deadline_ns = millisToNanos(deadline),
            });
        }
        if (self.idleTimeoutDeadlineMillis()) |deadline| {
            considerTimerDeadline(&next, .{
                .kind = .idle_timeout,
                .deadline_ns = millisToNanos(deadline),
            });
        }
        if (self.closeExpiryDeadlineMillis()) |deadline| {
            considerTimerDeadline(&next, .{
                .kind = .close,
                .deadline_ns = millisToNanos(deadline),
            });
        }
        if (self.oneRttKeyDiscardDeadline()) |deadline| {
            if (deadline >= 0) {
                considerTimerDeadline(&next, .{
                    .kind = .key_discard,
                    .deadline_ns = std.math.cast(u64, deadline) orelse
                        std.math.maxInt(u64),
                });
            } else {
                considerTimerDeadline(&next, .{
                    .kind = .key_discard,
                    .deadline_ns = 0,
                });
            }
        }
        return next;
    }

    pub fn serviceNextTimerAt(self: *Connection, now_ns: u64) Error!?TimerDeadline {
        const deadline = self.nextTimerDeadline() orelse return null;
        if (now_ns < deadline.deadline_ns) return null;

        switch (deadline.kind) {
            .ack_delay => {
                try self.serviceAckDelayTimerAt(now_ns);
            },
            .loss_time, .pto => {
                _ = try self.serviceLossDetectionTimer(now_ns);
            },
            .path_validation => {
                _ = try self.checkPathValidationTimeouts(now_ns);
            },
            .keep_alive => {
                _ = try self.serviceKeepAliveAt(nanosToMillisFloor(now_ns));
            },
            .idle_timeout => {
                _ = self.checkIdleTimeout(nanosToMillisFloor(now_ns));
            },
            .close => {
                _ = self.checkCloseExpired(nanosToMillisFloor(now_ns));
            },
            .key_discard => {
                _ = self.discardExpiredOneRttKeys(
                    std.math.cast(i64, now_ns) orelse std.math.maxInt(i64),
                );
            },
        }
        return deadline;
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
        const frames = [_]quic.Frame{.{ .ack_frequency = .{
            .sequence_number = sequence_number,
            .ack_eliciting_threshold = ack_eliciting_threshold,
            .request_max_ack_delay = request_max_ack_delay,
            .reordering_threshold = reordering_threshold,
        } }};
        try self.send(&frames);
        // ACK_FREQUENCY sequence numbers are part of the peer-visible state
        // machine.  Only advance after the packet is successfully staged/sent;
        // otherwise a transient validation or transport error would create a
        // local gap and make the next retry appear newer than what actually
        // reached the peer.
        self.ack_frequency_send_next_sequence +|= 1;
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
        if (!self.send_flow.shouldSendBlocked()) return;
        const frames = [_]quic.Frame{self.send_flow.dataBlockedFrame()};
        try self.sendTrackedFrames(&frames);
        self.send_flow.markBlockedSent();
    }

    fn sendStreamDataBlocked(self: *Connection, stream_id: u64) Error!void {
        const entry = try self.sendStreamEntry(stream_id);
        if (!entry.flow.shouldSendBlocked()) return;
        const frames = [_]quic.Frame{entry.flow.streamDataBlockedFrame(stream_id)};
        try self.sendTrackedFrames(&frames);
        entry.flow.markBlockedSent();
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
        if (frames.len != 0 and
            self.handshake_status.needsHandshakeDone() and
            !containsHandshakeDone(frames))
        {
            const combined = try self.endpoint.allocator.alloc(
                quic.Frame,
                frames.len + 1,
            );
            defer self.endpoint.allocator.free(combined);
            @memcpy(combined[0..frames.len], frames);
            combined[frames.len] = .{ .handshake_done = {} };
            return self.sendTrackedFramesEcnAtUncheckedRaw(
                combined,
                ecn,
                sent_time_ns,
            );
        }
        try self.sendTrackedFramesEcnAtUncheckedRaw(
            frames,
            ecn,
            sent_time_ns,
        );
    }

    fn sendTrackedFramesEcnAtUncheckedRaw(self: *Connection, frames: []const quic.Frame, ecn: quic.packet_space.EcnCodepoint, sent_time_ns: ?u64) Error!void {
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
        contains_handshake_done: bool,
        largest_acknowledged_sent: ?u64,
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
        if (packet_len > self.currentSendDatagramSize()) return error.DatagramTooLarge;
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
            .contains_handshake_done = containsHandshakeDone(frames),
            .largest_acknowledged_sent = largestAckFrameSent(frames),
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
        // This rollback must live at function scope. Non-HANDSHAKE_DONE sends
        // leave the allocation block before packet protection/socket errors can
        // occur, so a block-local errdefer would leak recovery state.
        errdefer if (tracked_recovery) {
            _ = self.recovery.forgetPacketNumber(packet_number);
        };
        if (prepared.is_ack_eliciting) {
            const recovery_group_id = try self.recovery.trackSent(
                packet_number,
                payload,
            );
            tracked_recovery = true;
            if (self.handshake_status.needsHandshakeDone() and
                prepared.contains_handshake_done)
            {
                // Commit the control-frame state only after every remaining
                // fallible allocation has succeeded. A socket error will then
                // roll the group back through the errdefer below.
                try self.sent.sentInFlightAtWithMetadata(
                    packet_number,
                    prepared.is_ack_eliciting,
                    prepared.is_in_flight,
                    payload.len,
                    ecn,
                    sent_time_ns,
                    null,
                    prepared.largest_acknowledged_sent,
                );
                var tracked_sent = true;
                errdefer if (tracked_sent) {
                    _ = self.sent.forget(packet_number);
                };
                try self.sendPayloadPacketWithPacketNumberLenAt(
                    packet_number,
                    payload,
                    prepared.packet_number_len,
                    ecn,
                    sent_time_ns,
                    prepared.is_ack_eliciting,
                    prepared.is_in_flight,
                );
                self.handshake_status.onHandshakeDoneTracked(
                    recovery_group_id,
                );
                tracked_sent = false;
                tracked_recovery = false;
                self.next_packet_number += 1;
                return;
            }
        }
        try self.sent.sentInFlightAtWithMetadata(packet_number, prepared.is_ack_eliciting, prepared.is_in_flight, payload.len, ecn, sent_time_ns, null, prepared.largest_acknowledged_sent);
        errdefer _ = self.sent.forget(packet_number);
        try self.sendPayloadPacketWithPacketNumberLenAt(
            packet_number,
            payload,
            prepared.packet_number_len,
            ecn,
            sent_time_ns,
            prepared.is_ack_eliciting,
            prepared.is_in_flight,
        );
        tracked_recovery = false;
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

    pub fn currentSendDatagramSize(self: Connection) usize {
        const configured = @min(
            self.config.max_datagram_size,
            self.endpoint.limits.max_datagram_size,
        );
        if (!self.pmtud.enabled) return configured;
        return @min(configured, self.pmtud.currentSize());
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
        _ = try self.recovery.trackSent(packet_number, payload.items);
        errdefer _ = self.recovery.forgetPacketNumber(packet_number);
        try self.sent.sentAtWithPmtu(packet_number, true, payload.items.len, .not_ect, sent_time_ns, probe_size);
        errdefer _ = self.sent.forget(packet_number);
        try self.sendPayloadPacketWithPacketNumberLenAt(
            packet_number,
            payload.items,
            packet_number_len,
            .not_ect,
            sent_time_ns,
            true,
            true,
        );
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
            true,
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
        ack_eliciting: bool,
        pace_packet: bool,
    ) Error!void {
        try self.prepareAeadForEncryption(packet_number, sent_time_ns);
        try self.reserveAntiAmplification(payload.len);
        errdefer self.releaseAntiAmplification(payload.len);
        const packet_options: quic.protection.ShortPacketOptions = .{
            .destination_connection_id = self.config.peer_connection_id,
            .packet_number = packet_number,
            .packet_number_len = packet_number_len,
            .fixed_bit = self.nextFixedBit(),
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
        self.noteOneRttPacketSent(packet_number, packet.len, now_ns, ack_eliciting);
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
            self.send_key_phase.currentKeys().confidentialityLimit(),
        );
    }

    fn aeadIntegrityLimit(self: Connection) u64 {
        return @min(
            self.config.aead_integrity_limit,
            self.receive_key_phase.currentKeys().integrityLimit(),
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
            self.recordPacketsLost(lost.packets);
            self.observeLostPackets(now_ns, "time_threshold");
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
            if (packet_len > self.currentSendDatagramSize() or
                packet_len > self.endpoint.limits.max_datagram_size)
            {
                return error.DatagramTooLarge;
            }

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
                    .fixed_bit = self.nextFixedBit(),
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
            self.noteOneRttPacketSent(
                probe.packet_number,
                probe.packet_len,
                now_ns,
                true,
            );
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
        const packet_number_len = quic.protection.packetNumberLenForPayload(
            packet_number,
            self.sent.largestAcknowledged(),
            candidate.payload.len,
        );
        const packet_len = try quic.protection.shortPacketLen(.{
            .destination_connection_id = self.config.peer_connection_id,
            .packet_number = packet_number,
            .packet_number_len = packet_number_len,
            .payload = candidate.payload,
        });
        if (packet_len > self.currentSendDatagramSize() or
            packet_len > self.endpoint.limits.max_datagram_size)
        {
            return error.DatagramTooLarge;
        }
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
        const handshake_done_group =
            self.handshake_status.recoveryGroupId();
        const marked_sent = self.sent.markAcknowledged(packet_number);
        const removed_recovery = self.recovery.acknowledgePacketNumber(packet_number);
        if (handshake_done_group) |group_id| {
            self.handshake_status.onRecoveryUpdated(
                self.recovery.containsGroupId(group_id),
            );
        }
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
        var stack_ranges: [quic.packet_space.ReceivedPacketTracker.stack_ack_range_capacity]quic.AckRange = undefined;
        var heap_ranges: ?[]quic.AckRange = null;
        defer if (heap_ranges) |ranges| self.endpoint.allocator.free(ranges);
        const ack = try self.ackFrameForSend(ack_delay, &stack_ranges, &heap_ranges);
        const frames = [_]quic.Frame{.{ .ack = ack }};
        try self.send(&frames);
        self.ackDelaySent();
    }

    pub fn sendAckWithEcn(self: *Connection, ack_delay: u64, ecn_counts: quic.EcnCounts) Error!void {
        var stack_ranges: [quic.packet_space.ReceivedPacketTracker.stack_ack_range_capacity]quic.AckRange = undefined;
        var heap_ranges: ?[]quic.AckRange = null;
        defer if (heap_ranges) |ranges| self.endpoint.allocator.free(ranges);
        var ack = try self.ackFrameForSend(ack_delay, &stack_ranges, &heap_ranges);
        ack.ecn_counts = ecn_counts;
        const frames = [_]quic.Frame{.{ .ack = ack }};
        try self.send(&frames);
        self.ackDelaySent();
    }

    fn ackFrameForSend(
        self: Connection,
        ack_delay: u64,
        stack_ranges: *[quic.packet_space.ReceivedPacketTracker.stack_ack_range_capacity]quic.AckRange,
        heap_ranges: *?[]quic.AckRange,
    ) Error!quic.AckFrame {
        const extra_ranges = if (self.received.ranges.items.len == 0)
            0
        else
            self.received.ranges.items.len - 1;
        if (extra_ranges <= stack_ranges.len) {
            return self.received.ackFrameInto(stack_ranges, ack_delay);
        }
        const allocated = try self.endpoint.allocator.alloc(quic.AckRange, extra_ranges);
        heap_ranges.* = allocated;
        return self.received.ackFrameInto(allocated, ack_delay);
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
        var ack_eliciting_count: u64 = 0;
        var largest_packet_number = self.received.largestReceived();
        var reordered = false;
        for (packets) |packet| {
            if (!ackEliciting(packet.frames)) continue;
            ack_eliciting_count +|= 1;
            if (largest_packet_number) |largest| {
                if (packet.packet.packet_number < largest) {
                    const gap = largest - packet.packet.packet_number;
                    if (gap >= self.ack_reordering_threshold) reordered = true;
                } else {
                    largest_packet_number = packet.packet.packet_number;
                }
            } else {
                largest_packet_number = packet.packet.packet_number;
            }
        }
        if (ack_eliciting_count == 0) return false;

        const immediate = self.immediate_ack_requested;
        if (immediate) self.immediate_ack_requested = false;
        errdefer if (immediate) {
            self.immediate_ack_requested = true;
        };

        self.ack_eliciting_since_last_ack +|= ack_eliciting_count;
        errdefer self.ack_eliciting_since_last_ack -|= ack_eliciting_count;

        if (!immediate and
            !reordered and
            self.ack_eliciting_since_last_ack < self.ack_eliciting_threshold)
        {
            self.scheduleAckDelayIfNeeded(packets);
            return false;
        }

        try self.sendAck(0);
        return true;
    }

    fn scheduleAckDelayIfNeeded(self: *Connection, packets: []const ReceivedPacket) void {
        _ = packets;
        if (self.requested_max_ack_delay == 0 or self.ack_delay_deadline_ns != null) return;
        const base = self.monotonicNowNs();
        const delay_ns = std.math.mul(u64, self.requested_max_ack_delay, 1_000) catch std.math.maxInt(u64);
        self.ack_delay_start_ns = base;
        self.ack_delay_deadline_ns = std.math.add(u64, base, delay_ns) catch std.math.maxInt(u64);
    }

    pub fn ackDelayDeadline(self: Connection) ?u64 {
        return self.ack_delay_deadline_ns;
    }

    pub fn serviceAckDelayTimerAt(self: *Connection, now_ns: u64) Error!void {
        const deadline = self.ack_delay_deadline_ns orelse return;
        if (now_ns < deadline) return;
        const start = self.ack_delay_start_ns orelse deadline;
        try self.sendAckForDelayNs(now_ns -| start);
    }

    fn ackDelaySent(self: *Connection) void {
        self.ack_delay_start_ns = null;
        self.ack_delay_deadline_ns = null;
        self.ack_eliciting_since_last_ack = 0;
        self.immediate_ack_requested = false;
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
        var frame_storage: [1]quic.Frame = undefined;
        if (self.path_validation.peekResponseFrames(&frame_storage) == 0) {
            return error.NoPendingPathResponse;
        }
        const frame = frame_storage[0];
        const frames = [_]quic.Frame{frame};
        try self.send(&frames);
        self.path_validation.discardResponses(1);
    }

    pub fn sendPendingPathResponses(self: *Connection) Error!usize {
        try self.validateNextPacketNumber();
        var frames: [8]quic.Frame = undefined;
        const count = self.path_validation.peekResponseFrames(&frames);
        if (count == 0) return 0;
        try self.send(frames[0..count]);
        self.path_validation.discardResponses(count);
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
        self.rtt_stats.updateAt(
            sample.latest_rtt_ns,
            sample.ack_delay_ns,
            self.handshake_status.isConfirmed(),
            now_ns,
        );
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

    pub fn markPeerActivity(self: *Connection, now_ms: u64) void {
        if (self.idle_timed_out) return;
        self.last_activity_ms = now_ms;
        self.last_peer_activity_ms = now_ms;
        self.sent_ack_eliciting_since_peer_activity = false;
        self.keep_alive_ping_sent = false;
    }

    fn markAckElicitingActivity(self: *Connection, now_ms: u64) void {
        if (self.idle_timed_out or self.sent_ack_eliciting_since_peer_activity) return;
        self.last_activity_ms = now_ms;
        self.sent_ack_eliciting_since_peer_activity = true;
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
        if (!self.handshake_status.isComplete()) {
            self.markTlsHandshakeComplete();
        }
        try self.sendPendingHandshakeDone();
    }

    fn sendPendingHandshakeDone(self: *Connection) Error!void {
        if (self.config.local_endpoint != .server) return error.InvalidFrame;
        if (!self.handshake_status.needsHandshakeDone()) return;
        const frames = [_]quic.Frame{.{ .handshake_done = {} }};
        try self.sendWithEcnLoop(&frames, .not_ect);
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
        return self.handshake_status.isConfirmed();
    }

    pub fn handshakeComplete(self: Connection) bool {
        return self.handshake_status.isComplete();
    }

    pub fn handshakeDonePending(self: Connection) bool {
        return self.handshake_status.needsHandshakeDone();
    }

    pub fn handshakeDoneAwaitingAck(self: Connection) bool {
        return self.handshake_status.awaitingHandshakeDoneAck();
    }

    pub fn lowestOneRttPacketNumber(self: Connection) ?u64 {
        return self.lowest_one_rtt_packet_number;
    }

    /// Transition a manually keyed connection to the same state installed by
    /// the integrated TLS handshake. This never writes to the socket.
    pub fn markTlsHandshakeComplete(self: *Connection) void {
        self.handshake_status.onTlsComplete(switch (self.config.local_endpoint) {
            .client => .client,
            .server => .server,
        });
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
        const send_generation = self.send_key_phase.previousKeyGeneration();
        const receive_generation = self.receive_key_phase.previousKeyGeneration();
        var discarded = self.send_key_phase.discardExpiredPrevious(now_nanos);
        if (discarded) {
            self.observeKeyDiscarded(
                now_nanos,
                oneRttKeyType(self.config.local_endpoint),
                send_generation,
            );
        }
        if (self.receive_key_phase.discardExpiredPrevious(now_nanos)) {
            discarded = true;
            self.observeKeyDiscarded(
                now_nanos,
                peerOneRttKeyType(self.config.local_endpoint),
                receive_generation,
            );
        }
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
            _ = try self.recovery.trackSent(packet_number, payload.items);
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
            const key_phase = quic.protection.peekShortPacketKeyPhaseForPolicy(
                keys.current.hp,
                bytes,
                self.config.local_connection_id.len,
                self.config.accept_zero_fixed_bit,
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
        const packet = try quic.protection.openShortPacketInPlaceWithFixedBitPolicy(
            keys,
            bytes,
            self.config.local_connection_id.len,
            self.expected_packet_number,
            self.config.accept_zero_fixed_bit,
        );

        const frames = try self.parseServicePacketFramesOrClose(packet.payload, now_ns);
        defer {
            quic.deinitOwnedFrameSlice(self.receive_frame_buffer.items, self.endpoint.allocator);
            self.receive_frame_buffer.clearRetainingCapacity();
        }
        var peer_address_update = try self.preparePeerAddressUpdate(
            from,
            bytes.len,
            frames,
        );
        defer peer_address_update.deinit();
        try self.applyReceivedFramesForDestinationOrClose(
            packet.packet_number,
            frames,
            now_ns,
            ecn,
            packet.destination_connection_id,
        );
        self.updateSpinBitAfterReceive(packet.spin_bit);
        self.commitPeerAddressUpdate(&peer_address_update);
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
        var peer_address_update = try self.preparePeerAddressUpdate(
            from,
            bytes.len,
            packet.frames,
        );
        defer peer_address_update.deinit();
        try self.applyReceivedFramesForDestinationOrClose(packet.packet.packet_number, packet.frames, now_ns, ecn, packet.packet.destination_connection_id);
        self.updateSpinBitAfterReceive(packet.packet.spin_bit);
        if (packet.peer_initiated_key_update) {
            try self.acceptPeerKeyUpdate(packet.packet.key_phase, now_ns);
        }
        self.commitPeerAddressUpdate(&peer_address_update);
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
        var peer_address_update = try self.preparePeerAddressUpdate(
            routed.datagram.from,
            routed.datagram.bytes.len,
            packet.frames,
        );
        defer peer_address_update.deinit();
        try self.applyReceivedFramesForDestinationOrClose(packet.packet.packet_number, packet.frames, now_ns, routed.datagram.ecn, packet.packet.destination_connection_id);
        self.updateSpinBitAfterReceive(packet.packet.spin_bit);
        if (packet.peer_initiated_key_update) {
            try self.acceptPeerKeyUpdate(packet.packet.key_phase, now_ns);
        }
        self.commitPeerAddressUpdate(&peer_address_update);
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
        var peer_address_update = try self.preparePeerAddressUpdate(
            routed.datagram.from,
            routed.datagram.bytes.len,
            packet.frames,
        );
        defer peer_address_update.deinit();
        try self.applyReceivedFramesForDestinationOrClose(packet.packet.packet_number, packet.frames, now_ns, ecn, packet.packet.destination_connection_id);
        self.updateSpinBitAfterReceive(packet.packet.spin_bit);
        if (packet.peer_initiated_key_update) {
            try self.acceptPeerKeyUpdate(packet.packet.key_phase, now_ns);
        }
        self.commitPeerAddressUpdate(&peer_address_update);
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
        var decoded = try quic.protection.openShortPacketWithKeyUpdateAndFixedBitPolicy(
            self.endpoint.allocator,
            self.receive_key_phase.keyUpdateKeys(),
            bytes,
            destination_connection_id_len,
            self.expected_packet_number,
            self.config.accept_zero_fixed_bit,
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

    fn preparePeerAddressUpdate(
        self: *Connection,
        from: net.IpAddress,
        datagram_len: usize,
        frames: []const quic.Frame,
    ) Error!PeerAddressUpdate {
        if (self.config.peer.eql(&from)) {
            return if (self.peer_address_validated)
                .none
            else
                .{ .same_unvalidated = datagram_len };
        }
        if (!hasNonProbingFrame(frames)) return .none;
        if (self.config.peer_disable_active_migration) {
            return error.ActiveMigrationDisabled;
        }

        const previous = self.config.peer;
        if (peerAddressSameIp(previous, from)) {
            return .{ .nat_rebinding = from };
        }

        var path_validation = try self.path_validation.clone(
            self.endpoint.allocator,
        );
        errdefer path_validation.deinit();

        var challenge: [8]u8 = undefined;
        try std.Io.randomSecure(self.endpoint.io, &challenge);
        try path_validation.queueChallenge(challenge);
        return .{ .new_path = .{
            .from = from,
            .datagram_len = datagram_len,
            .path_validation = path_validation,
        } };
    }

    fn commitPeerAddressUpdate(
        self: *Connection,
        update: *PeerAddressUpdate,
    ) void {
        switch (update.*) {
            .none => {},
            .same_unvalidated => |datagram_len| {
                self.recordPeerAddressBytesReceived(datagram_len);
            },
            .nat_rebinding => |from| {
                self.config.peer = from;
                self.peer_address_validated = true;
                self.peer_address_bytes_received = 0;
                self.peer_address_bytes_sent = 0;
            },
            .new_path => |*new_path| {
                self.config.peer = new_path.from;
                self.peer_address_validated = false;
                self.peer_address_bytes_received = 0;
                self.peer_address_bytes_sent = 0;
                self.recordPeerAddressBytesReceived(new_path.datagram_len);
                self.rtt_stats = .init(std.math.mul(
                    u64,
                    self.config.peer_max_ack_delay_ms,
                    1_000_000,
                ) catch quic.rtt.default_max_ack_delay_ns);
                self.congestion = .initWithOptions(
                    self.config.max_datagram_size,
                    self.config.congestion_algorithm,
                    self.config.enable_hystart,
                );
                self.pacer.reset();
                self.pmtud.resetForPath();
                self.path_validation.deinit();
                self.path_validation = new_path.path_validation;
            },
        }
        update.* = .none;
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
                    const handshake_done_group =
                        self.handshake_status.recoveryGroupId();
                    if (now_ns) |now| _ = try self.updateRttFromAck(frame.ack, now);
                    const acked = self.sent.applyAckDetailed(frame.ack) catch |err| switch (err) {
                        error.InvalidAckFrame => try self.applyAckWithEcnFailure(frame.ack),
                        else => return err,
                    };
                    self.handshake_status.onOneRttAcknowledged(
                        switch (self.config.local_endpoint) {
                            .client => .client,
                            .server => .server,
                        },
                        self.lowest_one_rtt_packet_number,
                        frame.ack.largest_acknowledged,
                    );
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
                        self.recordPacketsLost(lost.packets);
                        self.observeLostPackets(now_ns, "packet_threshold");
                        self.congestion.onLostAt(lost.bytes, lost.largest_sent_time_ns, now_ns);
                        if (lost.largest_pmtu_probe_size) |probe_size| {
                            self.pmtud.onProbeLost(probe_size, self.config.max_datagram_size);
                        }
                        _ = self.applyPersistentCongestionIfDetected();
                    }
                    if (now_ns) |now| {
                        const timed_lost = self.sent.detectTimeThresholdLoss(now, self.rtt_stats.lossDelay(), frame.ack.largest_acknowledged);
                        if (timed_lost.bytes > 0) {
                            self.recordPacketsLost(timed_lost.packets);
                            self.observeLostPackets(now_ns, "time_threshold");
                            self.congestion.onLostAt(timed_lost.bytes, timed_lost.largest_sent_time_ns, now);
                            if (timed_lost.largest_pmtu_probe_size) |probe_size| {
                                self.pmtud.onProbeLost(probe_size, self.config.max_datagram_size);
                            }
                            _ = self.applyPersistentCongestionIfDetected();
                        }
                    }
                    self.observeRecoveryMetrics(now_ns);
                    _ = try self.recovery.applyAck(frame.ack);
                    if (handshake_done_group) |group_id| {
                        self.handshake_status.onRecoveryUpdated(
                            self.recovery.containsGroupId(group_id),
                        );
                    }
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
            const max_buffered = @max(
                flow_limit,
                self.config.max_stream_receive_window orelse
                    self.config.stream_receive_window,
            );
            try recv_streams.append(self.endpoint.allocator, .{
                .stream_id = stream_id,
                .flow_limit = flow_limit,
                .recv_state = quic.stream_state.RecvState.init(
                    self.endpoint.allocator,
                    stream_id,
                    maxBufferedForLimit(max_buffered),
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
            .bidirectional => {
                if (maximum_streams > self.peer_max_streams_bidi) {
                    self.peer_max_streams_bidi = maximum_streams;
                    self.streams_blocked_bidi_at = null;
                }
            },
            .unidirectional => {
                if (maximum_streams > self.peer_max_streams_uni) {
                    self.peer_max_streams_uni = maximum_streams;
                    self.streams_blocked_uni_at = null;
                }
            },
        }
    }

    pub fn nextSpinBit(self: Connection) bool {
        return self.config.enable_spin_bit and self.spin_bit_value;
    }

    fn nextFixedBit(self: *Connection) bool {
        return self.fixed_bit_generator.next();
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
        try self.handshake_status.onHandshakeDoneReceived(switch (self.config.local_endpoint) {
            .client => .client,
            .server => .server,
        });
    }

    fn noteOneRttPacketSent(
        self: *Connection,
        packet_number: u64,
        packet_len: usize,
        now_ns: u64,
        ack_eliciting: bool,
    ) void {
        self.packets_sent_count +|= 1;
        const packet_len_u64 = std.math.cast(u64, packet_len) orelse
            std.math.maxInt(u64);
        self.bytes_sent_count +|= packet_len_u64;
        if (ack_eliciting) self.markAckElicitingActivity(nanosToMillisFloor(now_ns));
        if (self.lowest_one_rtt_packet_number == null or
            packet_number < self.lowest_one_rtt_packet_number.?)
        {
            self.lowest_one_rtt_packet_number = packet_number;
        }
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

    fn recordPacketsLost(self: *Connection, packets: usize) void {
        const packets_u64 = std.math.cast(u64, packets) orelse
            std.math.maxInt(u64);
        self.packets_lost_count +|= packets_u64;
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
                self.observeConnectionClosed(
                    close.now_ms,
                    close.application,
                    close.error_code,
                    close.reason_phrase,
                    close.state,
                );
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
        self.observeConnectionClosed(
            close.now_ms,
            close.application,
            close.error_code,
            close.reason_phrase,
            close.state,
        );
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
        self.packets_received_count +|= 1;
        const packet_length_u64 = std.math.cast(u64, packet_length) orelse
            std.math.maxInt(u64);
        self.bytes_received_count +|= packet_length_u64;
        const event_time = now_ns orelse self.monotonicNowNs();
        self.markPeerActivity(nanosToMillisFloor(event_time));
        const observer = self.config.qlog_observer orelse return;
        observer.packetReceived(
            self.qlogEventTime(event_time),
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

    fn observeLostPackets(self: *Connection, now_ns: ?u64, trigger: []const u8) void {
        const observer = self.config.qlog_observer orelse return;
        const event_time = self.qlogEventTime(now_ns orelse self.monotonicNowNs());
        for (self.sent.packets.items) |*packet| {
            if (!packet.lost or packet.loss_reported) continue;
            observer.packetLost(event_time, packet.packet_number, trigger);
            packet.loss_reported = true;
        }
    }

    fn observeKeyDiscarded(self: *Connection, now_nanos: i64, key_type: []const u8, generation: ?u64) void {
        const observer = self.config.qlog_observer orelse return;
        const now_ns = if (now_nanos <= 0)
            0
        else
            (std.math.cast(u64, now_nanos) orelse std.math.maxInt(u64));
        observer.keyDiscarded(self.qlogEventTime(now_ns), key_type, generation);
    }

    fn observeConnectionStarted(self: *Connection, now_ns: ?u64) void {
        const observer = self.config.qlog_observer orelse return;
        observer.connectionStarted(
            // init() has no caller-provided timestamp. Use the trace reference
            // point rather than wall-clock time so deterministic tests and
            // embedders can still inject smaller packet timestamps later.
            self.qlogEventTime(now_ns orelse 0),
        );
    }

    fn observeParametersSet(self: *Connection, now_ns: ?u64) void {
        const observer = self.config.qlog_observer orelse return;
        const event_time = self.qlogEventTime(now_ns orelse 0);
        observer.parametersSet(event_time, .{
            .owner = .local,
            .max_idle_timeout_ms = self.config.local_max_idle_timeout_ms,
            .max_udp_payload_size = std.math.cast(u64, self.endpoint.limits.max_datagram_size) orelse std.math.maxInt(u64),
            .initial_max_data = self.config.initial_receive_max_data,
            .initial_max_streams_bidi = self.config.initial_receive_max_streams_bidi,
            .initial_max_streams_uni = self.config.initial_receive_max_streams_uni,
            .disable_active_migration = null,
        });
        observer.parametersSet(event_time, .{
            .owner = .remote,
            .max_idle_timeout_ms = self.config.peer_max_idle_timeout_ms,
            .max_udp_payload_size = std.math.cast(u64, self.config.max_datagram_size) orelse std.math.maxInt(u64),
            .initial_max_data = self.config.initial_send_max_data,
            .initial_max_streams_bidi = self.config.initial_send_max_streams_bidi,
            .initial_max_streams_uni = self.config.initial_send_max_streams_uni,
            .disable_active_migration = self.config.peer_disable_active_migration,
        });
    }

    fn observeConnectionClosed(
        self: *Connection,
        now_ms: ?u64,
        application: bool,
        error_code: u64,
        reason_phrase: []const u8,
        state: CloseState,
    ) void {
        const observer = self.config.qlog_observer orelse return;
        const event_time = self.qlogEventTime(if (now_ms) |ms|
            millisToNanos(ms)
        else
            self.monotonicNowNs());
        observer.connectionClosed(
            event_time,
            closeQlogTrigger(state, reason_phrase),
            switch (state) {
                .closing => .local,
                .draining, .closed => .remote,
            },
            if (application) .application else .transport,
            error_code,
            reason_phrase,
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
        self.last_send_stream_index = self.stream_send_flows.items.len - 1;
        if (streamInitiatedByLocal(self.config.local_endpoint, stream_id)) {
            self.outgoing_streams_created_count +|= 1;
        }
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
        const frame: quic.Frame = switch (direction) {
            .bidirectional => blk: {
                if (self.streams_blocked_bidi_at) |blocked_at| {
                    if (blocked_at == self.peer_max_streams_bidi) return;
                }
                break :blk .{ .streams_blocked_bidi = .{ .maximum_streams = self.peer_max_streams_bidi } };
            },
            .unidirectional => blk: {
                if (self.streams_blocked_uni_at) |blocked_at| {
                    if (blocked_at == self.peer_max_streams_uni) return;
                }
                break :blk .{ .streams_blocked_uni = .{ .maximum_streams = self.peer_max_streams_uni } };
            },
        };
        try self.sendTrackedFrames(&[_]quic.Frame{frame});
        switch (direction) {
            .bidirectional => self.streams_blocked_bidi_at = self.peer_max_streams_bidi,
            .unidirectional => self.streams_blocked_uni_at = self.peer_max_streams_uni,
        }
    }

    fn findSendStreamEntry(self: *Connection, stream_id: u64) ?*StreamFlowEntry {
        if (self.last_send_stream_index) |index| {
            if (index < self.stream_send_flows.items.len and
                self.stream_send_flows.items[index].stream_id == stream_id)
            {
                return &self.stream_send_flows.items[index];
            }
        }
        for (self.stream_send_flows.items, 0..) |*entry, index| {
            if (entry.stream_id == stream_id) {
                self.last_send_stream_index = index;
                return entry;
            }
        }
        return null;
    }

    fn recvStreamFlow(self: *Connection, stream_id: u64) Error!*StreamRecvFlowEntry {
        if (self.findRecvStreamEntry(stream_id)) |entry| return entry;
        try self.validateStreamReceiveFrameId(stream_id);
        try self.validatePeerStreamCount(stream_id);
        const initial_limit = self.initialReceiveStreamDataLimit(stream_id);
        const max_buffered = @max(
            initial_limit,
            self.config.max_stream_receive_window orelse
                self.config.stream_receive_window,
        );
        try self.stream_recv_flows.append(self.endpoint.allocator, .{
            .stream_id = stream_id,
            .flow = try .initWithMaxWindow(
                initial_limit,
                self.config.stream_receive_window,
                self.config.max_stream_receive_window orelse self.config.stream_receive_window,
            ),
            .recv_state = quic.stream_state.RecvState.init(
                self.endpoint.allocator,
                stream_id,
                maxBufferedForLimit(max_buffered),
            ),
        });
        self.last_recv_stream_index = self.stream_recv_flows.items.len - 1;
        if (!streamInitiatedByLocal(self.config.local_endpoint, stream_id)) {
            self.incoming_streams_created_count +|= 1;
        }
        return &self.stream_recv_flows.items[self.stream_recv_flows.items.len - 1];
    }

    fn findRecvStreamEntry(self: *Connection, stream_id: u64) ?*StreamRecvFlowEntry {
        if (self.last_recv_stream_index) |index| {
            if (index < self.stream_recv_flows.items.len and
                self.stream_recv_flows.items[index].stream_id == stream_id)
            {
                return &self.stream_recv_flows.items[index];
            }
        }
        for (self.stream_recv_flows.items, 0..) |*entry, index| {
            if (entry.stream_id == stream_id) {
                self.last_recv_stream_index = index;
                return entry;
            }
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

fn peerAddressSameIp(a: net.IpAddress, b: net.IpAddress) bool {
    return switch (a) {
        .ip4 => |a4| switch (b) {
            .ip4 => |b4| std.mem.eql(u8, &a4.bytes, &b4.bytes),
            .ip6 => false,
        },
        .ip6 => |a6| switch (b) {
            .ip4 => false,
            .ip6 => |b6| std.mem.eql(u8, &a6.bytes, &b6.bytes) and
                a6.flow == b6.flow and
                a6.interface.index == b6.interface.index,
        },
    };
}

fn isProbingFrame(frame: quic.Frame) bool {
    return switch (frame) {
        .padding, .new_connection_id, .path_challenge, .path_response => true,
        else => false,
    };
}

fn hasNonProbingFrame(frames: []const quic.Frame) bool {
    for (frames) |frame| {
        if (!isProbingFrame(frame)) return true;
    }
    return false;
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

fn nanosToMillisFloor(ns: u64) u64 {
    return ns / 1_000_000;
}

fn nanosToMillisCeil(ns: u64) u64 {
    return ns / 1_000_000 + @intFromBool((ns % 1_000_000) != 0);
}

fn millisToNanos(ms: u64) u64 {
    return std.math.mul(u64, ms, 1_000_000) catch std.math.maxInt(u64);
}

fn closeQlogTrigger(state: CloseState, reason_phrase: []const u8) []const u8 {
    if (state == .draining and
        std.mem.eql(u8, reason_phrase, "stateless reset"))
    {
        return "stateless_reset";
    }
    return switch (state) {
        .closing => "local_close",
        .draining => "remote_close",
        .closed => "closed",
    };
}

fn considerTimerDeadline(next: *?TimerDeadline, candidate: TimerDeadline) void {
    if (next.* == null or candidate.deadline_ns < next.*.?.deadline_ns) {
        next.* = candidate;
    }
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
        .fixed_bit = options.fixed_bit,
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
                .fixed_bit = options.fixed_bit,
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
        .fixed_bit = options.fixed_bit,
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

fn containsHandshakeDone(frames: []const quic.Frame) bool {
    for (frames) |frame| {
        if (frame == .handshake_done) return true;
    }
    return false;
}

fn largestAckFrameSent(frames: []const quic.Frame) ?u64 {
    var largest: ?u64 = null;
    for (frames) |frame| {
        if (frame == .ack) {
            const acknowledged = frame.ack.largest_acknowledged;
            if (largest == null or acknowledged > largest.?) largest = acknowledged;
        }
    }
    return largest;
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

/// Narrow white-box surface for tests kept in `one_rtt/tests.zig`.
///
/// These adapters expose assertions rather than private entry types, keeping
/// stream bookkeeping and receive-pipeline implementation details unavailable
/// to normal transport callers while allowing the large conformance suite to
/// live outside the production module.
pub const testing = struct {
    pub fn applyReceivedFrames(
        connection: *Connection,
        packet_number: u64,
        frames: []const quic.Frame,
        now_ns: ?u64,
        ecn: quic.packet_space.EcnCodepoint,
    ) Error!void {
        return connection.applyReceivedFrames(
            packet_number,
            frames,
            now_ns,
            ecn,
        );
    }

    pub fn processReceivedBytesAt(
        connection: *Connection,
        from: net.IpAddress,
        bytes: []const u8,
        ecn: quic.packet_space.EcnCodepoint,
        now_ns: u64,
    ) Error!ReceivedPacket {
        return connection.processReceivedBytesAt(
            from,
            bytes,
            ecn,
            now_ns,
        );
    }

    pub fn hasReceiveStream(
        connection: *Connection,
        stream_id: u64,
    ) bool {
        return connection.findRecvStreamEntry(stream_id) != null;
    }

    pub fn sendStreamUsed(
        connection: *Connection,
        stream_id: u64,
    ) ?u64 {
        return if (connection.findSendStreamEntry(stream_id)) |entry|
            entry.flow.used
        else
            null;
    }

    pub fn sendStreamHighestSentEnd(
        connection: *Connection,
        stream_id: u64,
    ) ?u64 {
        return if (connection.findSendStreamEntry(stream_id)) |entry|
            entry.highest_sent_end
        else
            null;
    }

    pub fn sendStreamLimit(
        connection: *Connection,
        stream_id: u64,
    ) ?u64 {
        return if (connection.findSendStreamEntry(stream_id)) |entry|
            entry.flow.limit
        else
            null;
    }

    pub fn receiveStreamLimit(
        connection: *Connection,
        stream_id: u64,
    ) ?u64 {
        return if (connection.findRecvStreamEntry(stream_id)) |entry|
            entry.flow.limit
        else
            null;
    }

    pub fn receiveStreamAvailableLen(
        connection: *Connection,
        stream_id: u64,
    ) ?usize {
        return if (connection.findRecvStreamEntry(stream_id)) |entry|
            entry.recv_state.available().len
        else
            null;
    }

    pub fn validateDatagramFrame(
        connection: Connection,
        datagram: quic.DatagramFrame,
    ) Error!void {
        return connection.validateDatagramFrame(datagram);
    }
};

test {
    _ = @import("one_rtt/tests/mod.zig");
}
