const std = @import("std");
const quic = @import("mod.zig");
const fixed_bit = @import("one_rtt/fixed_bit.zig");
const closed_streams = @import("one_rtt/closed_streams.zig");
const frame_traits = @import("one_rtt/frame_traits.zig");
const datagram_queue = @import("one_rtt/datagram_queue.zig");
const handshake_status = @import("one_rtt/handshake_status.zig");
const pto_jitter = @import("one_rtt/pto_jitter.zig");
const deadline_policy = @import("../internal/deadline.zig");

const net = std.Io.net;

/// ACK_FREQUENCY expresses Requested Max Ack Delay in microseconds, while the
/// QUIC max_ack_delay limit is 2^14 milliseconds (exclusive).
const max_requested_ack_delay_us: u64 = (@as(u64, 1) << 14) * 1000;

fn validateRequestedMaxAckDelay(
    requested_us: u64,
    advertised_min_us: ?u64,
) error{InvalidFrame}!void {
    if (requested_us >= max_requested_ack_delay_us or
        (advertised_min_us != null and requested_us < advertised_min_us.?))
    {
        return error.InvalidFrame;
    }
}

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
    KeyUpdateError,
    InvalidPostHandshakeCrypto,
    InvalidPtoJitter,
    PathValidationLimit,
    InvalidResetToken,
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
    /// Input packets protected before the socket submission. This can exceed
    /// `sent_count` after a partial batch send; callers must never reuse those
    /// packet numbers even though only the prefix was visible on the wire.
    protected_count: usize,
    /// Protected bytes corresponding to `sent_count`.
    sent_bytes: usize,
    /// A sendmmsg-style backend can accept a prefix before failing. Errors
    /// raised by an endpoint interceptor before socket progress are retained
    /// here as well because packet protection has already consumed the whole
    /// batch's nonces.
    send_error: ?quic.runtime.Error = null,
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

/// Borrowed application-facing metadata for one packet that has already been
/// accepted into the connection's transport state.
///
/// The frame payloads point into transient receive storage and are valid only
/// for the duration of a `visitPacket*` callback. Callers that need to retain
/// diagnostics beyond that callback must continue to use `ReceivedPacket`.
pub const ReceivedPacketView = struct {
    from: net.IpAddress,
    packet_number: u64,
    frames: []const quic.Frame,
    peer_initiated_key_update: bool = false,
};

const PendingDatagramObserver = struct {
    context: *anyopaque,
    connection_handle: usize,
    notify: *const fn (*anyopaque, usize) void,
};
pub const PendingDatagramObserverError = error{PendingDatagramObserverBound};

fn callbackErrorSet(comptime callback: anytype) type {
    const callback_type = switch (@typeInfo(@TypeOf(callback))) {
        .@"fn" => @TypeOf(callback),
        .pointer => |pointer| pointer.child,
        else => @compileError("packet visitor must be a function"),
    };
    const return_type = @typeInfo(callback_type).@"fn".return_type orelse
        @compileError("packet visitor must have an explicit return type");
    return switch (@typeInfo(return_type)) {
        .error_union => |error_union| error_union.error_set,
        else => @compileError("packet visitor must return an error union"),
    };
}

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

const ReceivedDatagramBatch = union(enum) {
    owned: quic.runtime.OwnedBytesBatch,
    borrowed: quic.runtime.ReceivedBytesBatchView,

    fn deinit(self: *ReceivedDatagramBatch, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .owned => |*batch| batch.deinit(allocator),
            .borrowed => {},
        }
        self.* = undefined;
    }

    fn view(self: *ReceivedDatagramBatch) quic.runtime.ReceivedBytesBatchView {
        return switch (self.*) {
            .owned => |*batch| .{
                .from = batch.from,
                .storage = batch.storage,
                .segment_size = batch.segment_size,
                .segment_count = batch.segment_count,
                .ecn = batch.ecn,
            },
            .borrowed => |batch| batch,
        };
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

    /// Negotiated version used by version-specific 1-RTT key updates.
    version: quic.Version = .version_1,
    key_update_profile: quic.protection.KeyPhaseState.UpdateProfile = .rfc,
    peer: net.IpAddress,
    receive_keys: quic.protection.PacketProtectionKeys,
    send_keys: quic.protection.PacketProtectionKeys,
    local_connection_id: []const u8,
    peer_connection_id: []const u8,
    local_endpoint: EndpointRole = .client,
    max_ack_ranges: usize = 64,
    max_frames_per_packet: usize = 16,
    /// Maximum unique peer PATH_CHALLENGEs retained while their responses are
    /// blocked. Additional challenges are ignored as permitted by RFC 9000.
    max_pending_path_responses: usize =
        quic.path_validation.default_max_pending_responses,
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
    initial_send_max_streams_bidi: u64 =
        quic.practical_transport_parameters.initial_max_streams_bidi,
    initial_send_max_streams_uni: u64 =
        quic.practical_transport_parameters.initial_max_streams_uni,
    initial_receive_max_streams_bidi: u64 =
        quic.practical_transport_parameters.initial_max_streams_bidi,
    initial_receive_max_streams_uni: u64 =
        quic.practical_transport_parameters.initial_max_streams_uni,
    stream_receive_window: u64 = 64 * 1024,
    max_stream_receive_window: ?u64 = null,
    max_datagram_size: usize = quic.congestion.default_max_datagram_size,
    /// CUBIC is the high-throughput default; NewReno remains selectable for
    /// compatibility-sensitive deployments.
    congestion_algorithm: quic.congestion.Algorithm = .cubic,
    enable_hystart: bool = true,
    enable_pacing: bool = true,
    pacing_max_burst_packets: usize = quic.pacing.Pacer.default_max_burst_packets,
    /// Optional per-connection PTO jitter percentage (0...50). Zero preserves
    /// exact RFC PTO calculations and does not request entropy.
    pto_jitter_percentage: u8 = 0,
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
    /// Number of ack-eliciting application packets that trigger an immediate
    /// ACK. One preserves the low-level historical behavior for callers that
    /// do not drive transport timers; handshake defaults use delayed ACKs.
    local_ack_eliciting_threshold: u64 = 1,
    /// Maximum local ACK delay in microseconds when the packet threshold has
    /// not yet been reached. Zero disables delayed ACKs.
    local_max_ack_delay_us: u64 = 0,
    /// Packet-number gap that forces an immediate ACK; zero disables the
    /// reordering trigger.
    local_ack_reordering_threshold: u64 = quic.packet_space.default_packet_threshold,
    /// Automatic ECN marking policy for ordinary 1-RTT sends.
    ///
    /// Explicit `sendWithEcn*` calls keep their requested codepoint. This
    /// policy only affects convenience send paths such as `send`/`sendAt`.
    automatic_ecn_policy: quic.ecn.Policy = .enabled,
    /// Allow already-buffered contiguous stream data to be drained after a
    /// peer RESET_STREAM, then report the reset exactly once.
    ///
    /// The default preserves netz's historical reset-first application view:
    /// unread bytes remain retained for duplicate/conflict validation but are
    /// no longer returned by application receive APIs once the reset is
    /// observed.
    enable_reset_partial_delivery: bool = false,
    enable_pmtud: bool = false,
    pmtud_max_probe_size: usize = quic.pmtu.max_ipv4_udp_payload_size,
    /// Whether this endpoint advertised disable_active_migration. Servers use
    /// this local policy to silently discard packets from a new client IP.
    local_disable_active_migration: bool = false,
    /// Whether the peer advertised disable_active_migration. This constrains
    /// local path selection; it is not receive-side authorization policy.
    peer_disable_active_migration: bool = false,
    peer_preferred_address: ?quic.PreferredAddress = null,
    local_max_datagram_frame_size: ?usize = null,
    peer_max_datagram_frame_size: ?usize = null,
    max_datagram_queue_items: usize = 16,
    enable_ack_frequency: bool = false,
    /// `min_ack_delay` advertised locally; gates peer ACK_FREQUENCY and
    /// validates its Requested Max Ack Delay (microseconds).
    local_min_ack_delay: ?u64 = null,
    /// Peer's advertised `min_ack_delay`; gates local ACK_FREQUENCY and
    /// validates the delay requested by the caller (microseconds).
    peer_min_ack_delay: ?u64 = null,
    local_stateless_reset_key: ?[quic.stateless_reset.static_key_len]u8 = null,
    /// Authenticated server transport-parameter token for the peer's Initial
    /// connection ID. Only clients can receive this parameter.
    peer_stateless_reset_token: ?[quic.stateless_reset.token_len]u8 = null,
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
    final_size: ?u64 = null,
    stopped: ?StopSendingInfo = null,
    reset_sent: ?StreamResetInfo = null,
    /// The application no longer needs this locally initiated stream. State
    /// is reclaimed once every applicable send/receive half is terminal.
    release_requested: bool = false,
};

const StreamRecvFlowEntry = struct {
    stream_id: u64,
    flow: quic.flow_control.RecvFlow,
    recv_state: quic.stream_state.RecvState,
    highest_received_end: u64 = 0,
    final_size: ?u64 = null,
    reset: ?StreamResetInfo = null,
    /// Absolute application-read boundary captured by the first RESET_STREAM.
    /// Later reordered STREAM frames may still be retained for validation, but
    /// they must never appear after the terminal reset becomes observable.
    reset_delivery_end: ?usize = null,
    reset_reported: bool = false,
    fin_reported: bool = false,
    stop_sending_sent: ?StopSendingInfo = null,
    /// The application has finished with this peer-initiated stream, but its
    /// local send-side terminal frame might still await acknowledgement.
    stream_count_release_requested: bool = false,
    /// Application consumption advanced this stream's receive window, but
    /// the latest MAX_STREAM_DATA value has not reached the socket yet.
    pending_max_stream_data: bool = false,

    fn deinit(self: *StreamRecvFlowEntry) void {
        self.recv_state.deinit();
        self.* = undefined;
    }
};

const RecvStreamPreflightEntry = struct {
    stream_id: u64,
    flow_limit: u64,
    recv_state: quic.stream_state.RecvState.Preflight,
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

pub const PeerStreamReleaseResult = struct {
    /// Number of previously unreleased terminal streams accepted by the call.
    streams_released: usize,
    /// Whether a packet carrying one or more MAX_STREAMS updates was sent.
    update_sent: bool,
};

const ReservedStreamCredit = struct {
    stream_id: u64,
    bytes: u64,
};

const OutboundFrameTraits = frame_traits.Traits;

pub const CloseInfo = struct {
    application: bool = false,
    error_code: u64,
    frame_type: u64 = 0,
    reason_phrase: []u8,
    state: CloseState = .closing,
    started_ms: ?u64 = null,
    expires_ms: ?u64 = null,
    response_deadline_ns: ?u64 = null,
    response_packet_threshold: u8 = 1,
    response_packets: u8 = 0,

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

/// Borrowed details from a peer's authenticated QUIC CONNECTION_CLOSE frame.
///
/// The reason phrase remains owned by `Connection` and is valid until that
/// connection is deinitialized. A stateless reset and a locally generated
/// close deliberately do not produce this value because neither carries peer
/// CONNECTION_CLOSE diagnostics.
pub const PeerCloseInfo = union(enum) {
    transport: Transport,
    application: Application,

    pub const Transport = struct {
        error_code: u64,
        frame_type: u64,
        reason_phrase: []const u8,
    };

    pub const Application = struct {
        error_code: u64,
        reason_phrase: []const u8,
    };
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
    active_send_streams: usize,
    active_receive_streams: usize,
    closed_peer_stream_ranges: usize,
    closed_local_stream_ranges: usize,
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
    failed_path_validations: usize,
    path_challenges_dropped: u64,
    sent_packet_stats: quic.packet_space.SentPacketStats,
    received_packet_stats: quic.packet_space.ReceivedPacketStats,
    recovery_queue_stats: quic.recovery.QueueStats,

    pub fn lossRate(self: ConnectionStats) f64 {
        if (self.packets_sent == 0) return 0.0;
        return @as(f64, @floatFromInt(self.packets_lost)) /
            @as(f64, @floatFromInt(self.packets_sent));
    }
};

pub const SendCredit = struct {
    connection: u64,
    stream: u64,
    congestion: usize,
    max_datagram_size: usize,

    pub fn available(self: SendCredit) usize {
        return @min(
            self.max_datagram_size,
            @min(
                self.congestion,
                @min(
                    std.math.cast(usize, self.connection) orelse
                        std.math.maxInt(usize),
                    std.math.cast(usize, self.stream) orelse
                        std.math.maxInt(usize),
                ),
            ),
        );
    }
};

pub const SendStreamStats = struct {
    bytes_sent: u64,
    highest_sent_offset: u64,
    send_limit: u64,
    send_available: u64,
    blocked: bool,
    stopped: ?StopSendingInfo,
    reset: ?StreamResetInfo,
    final_size: ?u64,
};

pub const RecvStreamStats = struct {
    bytes_received: u64,
    bytes_read: u64,
    highest_received_offset: u64,
    available_bytes: usize,
    receive_limit: u64,
    receive_window_available: u64,
    final_size: ?u64,
    reset: ?StreamResetInfo,
    stop_sending_sent: ?StopSendingInfo,
};

/// One nonblocking receive-side stream event. DATA is copied into the caller's
/// buffer; terminal reset state is returned once per stream.
pub const StreamRead = union(enum) {
    data: struct {
        stream_id: u62,
        bytes: usize,
        fin: bool,
    },
    reset: struct {
        stream_id: u62,
        application_error_code: u64,
        final_size: u64,
    },
};

pub const PeerStreamLifecycle = enum {
    unknown,
    active,
    closed,
};

pub const StreamLifecycle = enum {
    unknown,
    active,
    closed,
};

fn sendStreamStatsFromEntry(entry: *const StreamFlowEntry) SendStreamStats {
    return .{
        .bytes_sent = entry.flow.used,
        .highest_sent_offset = entry.highest_sent_end,
        .send_limit = entry.flow.limit,
        .send_available = entry.flow.available(),
        .blocked = entry.flow.available() == 0,
        .stopped = entry.stopped,
        .reset = entry.reset_sent,
        .final_size = entry.final_size,
    };
}

fn recvStreamStatsFromEntry(entry: *const StreamRecvFlowEntry) RecvStreamStats {
    return .{
        .bytes_received = entry.recv_state.receivedByteCount(),
        .bytes_read = std.math.cast(u64, entry.recv_state.read_offset) orelse
            std.math.maxInt(u64),
        .highest_received_offset = entry.highest_received_end,
        .available_bytes = entry.recv_state.available().len,
        .receive_limit = entry.flow.limit,
        .receive_window_available = entry.flow.limit -| entry.flow.highest_received,
        .final_size = entry.final_size,
        .reset = entry.reset,
        .stop_sending_sent = entry.stop_sending_sent,
    };
}

/// Limit every application read surface to the reset-time frontier. The
/// receive state can retain later reordered bytes to validate QUIC final-size
/// and overlap invariants, but those bytes are transport evidence rather than
/// application data once RESET_STREAM has made the stream terminal.
fn applicationAvailableStreamBytes(
    entry: *const StreamRecvFlowEntry,
    enable_reset_partial_delivery: bool,
) []const u8 {
    const available = entry.recv_state.available();
    if (entry.reset_delivery_end) |delivery_end| {
        if (!enable_reset_partial_delivery or
            entry.reset_reported or
            delivery_end <= entry.recv_state.read_offset)
        {
            return available[0..0];
        }
        return available[0..@min(
            available.len,
            delivery_end - entry.recv_state.read_offset,
        )];
    }
    return available;
}

const PeerAddressUpdate = union(enum) {
    none,
    same_unvalidated: usize,
    probing_candidate: struct {
        from: net.IpAddress,
        datagram_len: usize,
        budget_index: usize,
    },
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

const max_candidate_path_budgets: usize = quic.connection_id.max_pool_size;

const CandidatePathBudget = struct {
    peer: net.IpAddress,
    bytes_received: usize = 0,
    bytes_sent: usize = 0,
    spin_bit_value: bool = false,
    spin_largest_received_packet_number: ?u64 = null,
};

const ValidatedPeerPath = struct {
    peer: net.IpAddress,
    connection_id: [quic.connection_id.max_connection_id_len]u8 =
        .{0} ** quic.connection_id.max_connection_id_len,
    connection_id_len: u8 = 0,
    spin_bit_value: bool = false,
    spin_largest_received_packet_number: ?u64 = null,

    fn init(
        peer: net.IpAddress,
        connection_id: []const u8,
        spin_bit_value: bool,
        spin_largest_received_packet_number: ?u64,
    ) ValidatedPeerPath {
        std.debug.assert(
            connection_id.len <= quic.connection_id.max_connection_id_len,
        );
        var path: ValidatedPeerPath = .{
            .peer = peer,
            .connection_id_len = @intCast(connection_id.len),
            .spin_bit_value = spin_bit_value,
            .spin_largest_received_packet_number = spin_largest_received_packet_number,
        };
        @memcpy(path.connection_id[0..connection_id.len], connection_id);
        return path;
    }

    fn connectionId(self: *const ValidatedPeerPath) []const u8 {
        return self.connection_id[0..self.connection_id_len];
    }
};

fn updateSpinState(
    local_endpoint: ConnectionConfig.EndpointRole,
    value: *bool,
    largest_received_packet_number: *?u64,
    packet_number: u64,
    peer_spin_bit: bool,
) void {
    if (largest_received_packet_number.*) |largest| {
        if (packet_number <= largest) return;
    }
    largest_received_packet_number.* = packet_number;
    value.* = switch (local_endpoint) {
        .client => !peer_spin_bit,
        .server => peer_spin_bit,
    };
}

const DatagramRecvQueue = datagram_queue.Queue;

pub const LossDetectionTimerKind = enum {
    loss_time,
    pto,
};

pub const LossDetectionTimerDeadline = struct {
    kind: LossDetectionTimerKind,
    deadline_ns: u64,
};

pub const TimerDeadlineKind = enum {
    path_response,
    stop_sending_reset,
    streams_blocked_response,
    pacing,
    ack_delay,
    peer_stream_credit,
    receive_credit,
    loss_time,
    pto,
    pmtu_raise,
    path_validation,
    keep_alive,
    idle_timeout,
    close,
    close_response,
    key_discard,
};

pub const TimerDeadline = struct {
    kind: TimerDeadlineKind,
    deadline_ns: u64,
};

pub const anti_amplification_multiplier: usize = 3;
const max_short_packet_overhead: usize = 1 + 20 + 4 + quic.protection.aead_tag_len;
// HTTP/3's default packet builder contributes at most eight frames. Keep the
// automatic HANDSHAKE_DONE augmentation for that common first-flight shape on
// the stack while retaining an exact fallback for lower-level callers.
const handshake_done_frame_stack_capacity: usize = 16;
const pending_ack_frame_stack_capacity: usize = 16;
// Match the default receive parser bound so a peer can consume one update for
// every frame in the coalesced credit packet without special configuration.
const receive_credit_frame_stack_capacity: usize = 16;

fn appendPendingHandshakeDone(
    allocator: std.mem.Allocator,
    stack: *[handshake_done_frame_stack_capacity]quic.Frame,
    frames: []const quic.Frame,
) Error![]quic.Frame {
    const combined_len = std.math.add(usize, frames.len, 1) catch
        return error.InvalidFrameLength;
    const combined = if (combined_len <= stack.len)
        stack[0..combined_len]
    else
        try allocator.alloc(quic.Frame, combined_len);
    @memcpy(combined[0..frames.len], frames);
    combined[frames.len] = .{ .handshake_done = {} };
    return combined;
}

fn appendPendingAck(
    allocator: std.mem.Allocator,
    stack: *[pending_ack_frame_stack_capacity]quic.Frame,
    frames: []const quic.Frame,
    ack: quic.AckFrame,
) Error![]quic.Frame {
    const combined_len = std.math.add(usize, frames.len, 1) catch
        return error.InvalidFrameLength;
    const combined = if (combined_len <= stack.len)
        stack[0..combined_len]
    else
        try allocator.alloc(quic.Frame, combined_len);
    @memcpy(combined[0..frames.len], frames);
    combined[frames.len] = .{ .ack = ack };
    return combined;
}
const timer_blocked_receive_backoff_ns: u64 = std.time.ns_per_ms;
const stream_release_retry_backoff_ns = [_]u64{
    1 * std.time.ns_per_ms,
    2 * std.time.ns_per_ms,
    4 * std.time.ns_per_ms,
    8 * std.time.ns_per_ms,
    16 * std.time.ns_per_ms,
    32 * std.time.ns_per_ms,
    64 * std.time.ns_per_ms,
    128 * std.time.ns_per_ms,
    256 * std.time.ns_per_ms,
    512 * std.time.ns_per_ms,
    1 * std.time.ns_per_s,
};

/// Established 1-RTT receive APIs no longer own Initial or Handshake keys.
/// A long header therefore belongs to an obsolete/rejected packet-number
/// space and is silently discarded before the short-header decoder.
fn isDiscardedLongHeaderPacket(bytes: []const u8) bool {
    return bytes.len != 0 and (bytes[0] & 0x80) != 0;
}

pub const Connection = struct {
    endpoint: *quic.runtime.Endpoint,
    config: ConnectionConfig,
    /// Stable backing for the currently selected peer CID. Peer-pool entries
    /// live inline in `Connection`, so storing a slice into one of them would
    /// become dangling whenever a connection/session is moved by value.
    peer_connection_id_storage: []u8,
    /// One 1-RTT packet may share the UDP datagram that completes the TLS
    /// Handshake packet-number space. The blocking handshake must retain that
    /// suffix until the application runtime is installed; otherwise HTTP/3 can
    /// lose the peer's control stream and first request permanently.
    pending_received_datagram: ?quic.runtime.OwnedBytes = null,
    pending_datagram_observer: ?PendingDatagramObserver = null,
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
    stream_send_index: std.AutoHashMapUnmanaged(u64, usize) = .empty,
    last_send_stream_index: ?usize = null,
    stream_recv_flows: std.ArrayList(StreamRecvFlowEntry) = .empty,
    stream_recv_index: std.AutoHashMapUnmanaged(u64, usize) = .empty,
    closed_peer_bidi_streams: closed_streams.Set = .{},
    closed_peer_uni_streams: closed_streams.Set = .{},
    closed_local_bidi_streams: closed_streams.Set = .{},
    closed_local_uni_streams: closed_streams.Set = .{},
    /// Streams whose received STOP_SENDING still require the mandated
    /// RESET_STREAM response. The stream table is the queue; this count and
    /// deadline only make that work visible to endpoint schedulers.
    pending_stop_sending_resets: usize = 0,
    stop_sending_reset_retry_deadline_ns: ?u64 = null,
    stop_sending_reset_retry_attempts: u8 = 0,
    pending_streams_blocked_bidi_response: bool = false,
    pending_streams_blocked_uni_response: bool = false,
    streams_blocked_response_retry_deadline_ns: ?u64 = null,
    streams_blocked_response_retry_attempts: u8 = 0,
    pending_peer_stream_credit_releases: usize = 0,
    pending_local_stream_releases: usize = 0,
    stream_release_retry_deadline_ns: ?u64 = null,
    stream_release_retry_attempts: u8 = 0,
    pending_max_data: bool = false,
    pending_receive_stream_credits: usize = 0,
    last_receive_credit_stream_id: ?u64 = null,
    receive_credit_retry_deadline_ns: ?u64 = null,
    receive_credit_retry_attempts: u8 = 0,
    last_recv_stream_index: ?usize = null,
    stream_poll_cursor: usize = 0,
    close_info: ?CloseInfo = null,
    peer_close_frame_received: bool = false,
    send_key_phase: quic.protection.Aes128KeyPhaseState,
    receive_key_phase: quic.protection.Aes128KeyPhaseState,
    /// Current-generation packet keys with optional backend AEAD setup kept
    /// alive across packets. The movable key-phase state remains plain data;
    /// these connection-owned contexts are refreshed only on phase changes.
    prepared_send_keys: ?*quic.protection.PreparedPacketProtectionKeys,
    prepared_receive_keys: ?*quic.protection.PreparedPacketProtectionKeys,
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
    next_local_bidi_stream_id: u64,
    next_local_uni_stream_id: u64,
    spin_bit_value: bool = false,
    spin_largest_received_packet_number: ?u64 = null,
    fixed_bit_generator: fixed_bit.Generator = .{},
    last_activity_ms: ?u64 = null,
    last_peer_activity_ms: ?u64 = null,
    sent_ack_eliciting_since_peer_activity: bool = false,
    idle_timed_out: bool = false,
    keep_alive_ping_sent: bool = false,
    last_persistent_congestion_packet_number: ?u64 = null,
    pto_count: u8 = 0,
    pto_jitter_state: pto_jitter.State = .{},
    peer_address_validated: bool = true,
    peer_address_bytes_received: usize = 0,
    peer_address_bytes_sent: usize = 0,
    path_validation_retry_deadline_ns: ?u64 = null,
    path_response_retry_deadline_ns: ?u64 = null,
    path_response_retry_attempts: u8 = 0,
    /// Last path that completed validation. RFC 9000 section 9.3.2 requires
    /// reverting an apparent migration when validation of its address fails.
    last_validated_peer_path: ValidatedPeerPath = undefined,
    /// A client validating the server's preferred_address can still receive
    /// from the original validated tuple until the new path succeeds or fails.
    peer_preferred_address_migration_active: bool = false,
    ecn_path: quic.ecn.PathState = .{},
    /// A cumulative ACK_ECN counter update can include packets from the old
    /// path. Consume one advancing counter report as a fresh baseline before
    /// allowing it to validate the replacement path. This prevents a delayed
    /// old-path mark from masking bleaching on the new path.
    ecn_path_baseline_pending: bool = false,
    pmtud: quic.pmtu.State = .{},
    pmtu_probe_epoch: u32 = 1,
    pmtu_path_epoch: u32 = 1,
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
    /// Authenticated probing-only paths need independent amplification credit
    /// before they become the selected path. Fixed storage prevents an
    /// address-spraying peer from turning path validation into heap growth.
    candidate_path_budgets: [max_candidate_path_budgets]?CandidatePathBudget =
        .{null} ** max_candidate_path_budgets,
    candidate_path_eviction_cursor: usize = 0,
    path_response_targets: std.ArrayList(?net.IpAddress) = .empty,
    path_response_target_head: usize = 0,
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
    /// Reused flow-credit aggregation for stateful packet sends and batches.
    ///
    /// A packet may carry multiple STREAM frames for one stream and later
    /// packets may continue any of them. Keeping both aggregate levels on the
    /// connection makes steady-state HTTP/3 sends allocation-free outside
    /// recovery's required stable payload ownership.
    send_batch_stream_scratch: std.ArrayList(ReservedStreamCredit) = .empty,
    send_batch_packet_stream_scratch: std.ArrayList(ReservedStreamCredit) = .empty,
    /// Reused socket receive storage for synchronous visitor and state-only
    /// service paths. GRO grows this lazily to the largest kernel coalesced
    /// payload; owning diagnostic receives keep independent lifetime storage.
    receive_packet_buffer: std.ArrayList(u8) = .empty,
    receive_ack_range_buffer: std.ArrayList(quic.AckRange) = .empty,
    /// Borrowed frame views used by state-only service and synchronous packet
    /// visitors. They never outlive the current decrypted datagram/GRO segment
    /// and therefore avoid one frame slice allocation per packet on the
    /// event-loop fast path.
    receive_frame_buffer: std.ArrayList(quic.Frame) = .empty,

    pub fn init(endpoint: *quic.runtime.Endpoint, config: ConnectionConfig) Error!Connection {
        if (config.local_endpoint == .server and
            config.peer_stateless_reset_token != null)
        {
            return error.InvalidTransportParameter;
        }
        if (config.peer_connection_id.len >
            quic.connection_id.max_connection_id_len)
        {
            return error.InvalidConnectionId;
        }
        if (config.initial_send_max_streams_bidi > quic.max_stream_count or
            config.initial_send_max_streams_uni > quic.max_stream_count or
            config.initial_receive_max_streams_bidi > quic.max_stream_count or
            config.initial_receive_max_streams_uni > quic.max_stream_count)
        {
            return error.InvalidTransportParameter;
        }
        if (config.local_max_ack_delay_us >= max_requested_ack_delay_us) {
            return error.InvalidTransportParameter;
        }
        const send_buffer_capacity = std.math.add(usize, config.max_datagram_size, max_short_packet_overhead) catch return error.OutOfMemory;
        const peer_connection_id_storage = try endpoint.allocator.alloc(
            u8,
            quic.connection_id.max_connection_id_len,
        );
        var peer_connection_id_storage_owned = true;
        errdefer if (peer_connection_id_storage_owned) {
            endpoint.allocator.free(peer_connection_id_storage);
        };
        @memcpy(
            peer_connection_id_storage[0..config.peer_connection_id.len],
            config.peer_connection_id,
        );
        var stable_config = config;
        stable_config.peer_connection_id =
            peer_connection_id_storage[0..config.peer_connection_id.len];
        var prepared_send_keys = try quic.protection
            .PreparedPacketProtectionKeys.createIfAccelerated(
            endpoint.allocator,
            config.send_keys,
        );
        errdefer if (prepared_send_keys) |prepared| {
            prepared.destroy(endpoint.allocator);
        };
        var prepared_receive_keys = try quic.protection
            .PreparedPacketProtectionKeys.createIfAccelerated(
            endpoint.allocator,
            config.receive_keys,
        );
        errdefer if (prepared_receive_keys) |prepared| {
            prepared.destroy(endpoint.allocator);
        };
        var connection = Connection{
            .endpoint = endpoint,
            .config = stable_config,
            .peer_connection_id_storage = peer_connection_id_storage,
            .received = .init(endpoint.allocator, config.max_ack_ranges),
            .sent = .init(endpoint.allocator),
            .recovery = .init(endpoint.allocator),
            .congestion = .initWithOptions(
                if (config.enable_pmtud) quic.pmtu.min_udp_payload_size else config.max_datagram_size,
                config.congestion_algorithm,
                config.enable_hystart,
            ),
            .pacer = .init(
                config.enable_pacing,
                if (config.enable_pmtud) quic.pmtu.min_udp_payload_size else send_buffer_capacity,
                config.pacing_max_burst_packets,
            ),
            .rtt_stats = .init(std.math.mul(u64, config.peer_max_ack_delay_ms, 1_000_000) catch quic.rtt.default_max_ack_delay_ns),
            .ecn_path = .init(config.automatic_ecn_policy),
            .pmtud = .init(.{ .enabled = config.enable_pmtud, .max_probe_size = config.pmtud_max_probe_size }),
            .path_validation = .initWithMaxPendingResponses(
                endpoint.allocator,
                config.max_pending_path_responses,
            ),
            .send_flow = .init(config.initial_send_max_data),
            .recv_flow = try .initWithMaxWindow(
                config.initial_receive_max_data,
                config.receive_window,
                config.max_receive_window orelse config.receive_window,
            ),
            .send_key_phase = try .initForVersionAndProfile(
                config.version.wireValue(),
                config.send_keys,
                false,
                config.key_update_profile,
            ),
            .receive_key_phase = try .initForVersionAndProfile(
                config.version.wireValue(),
                config.receive_keys,
                false,
                config.key_update_profile,
            ),
            .prepared_send_keys = prepared_send_keys,
            .prepared_receive_keys = prepared_receive_keys,
            .peer_max_streams_bidi = config.initial_send_max_streams_bidi,
            .peer_max_streams_uni = config.initial_send_max_streams_uni,
            .recv_max_streams_bidi = config.initial_receive_max_streams_bidi,
            .recv_max_streams_uni = config.initial_receive_max_streams_uni,
            .next_local_bidi_stream_id = switch (config.local_endpoint) {
                .client => 0,
                .server => 1,
            },
            .next_local_uni_stream_id = switch (config.local_endpoint) {
                .client => 2,
                .server => 3,
            },
            .ack_eliciting_threshold = config.local_ack_eliciting_threshold,
            .requested_max_ack_delay = config.local_max_ack_delay_us,
            .ack_reordering_threshold = config.local_ack_reordering_threshold,
        };
        prepared_send_keys = null;
        prepared_receive_keys = null;
        peer_connection_id_storage_owned = false;
        errdefer connection.deinit();
        connection.fixed_bit_generator = try .init(
            endpoint.io,
            config.grease_fixed_bit,
        );
        connection.pto_jitter_state = try .init(
            endpoint.io,
            config.pto_jitter_percentage,
        );
        try connection.send_frame_buffer.ensureTotalCapacity(endpoint.allocator, config.max_datagram_size);
        try connection.send_packet_buffer.ensureTotalCapacity(endpoint.allocator, send_buffer_capacity);
        try connection.receive_packet_buffer.ensureTotalCapacity(
            endpoint.allocator,
            endpoint.limits.max_datagram_size,
        );
        try connection.receive_ack_range_buffer.ensureTotalCapacity(
            endpoint.allocator,
            config.max_ack_ranges,
        );
        if (config.local_stateless_reset_key) |key| {
            try connection.local_connection_ids.registerInitialWithStaticKey(config.local_connection_id, key);
        } else {
            try connection.local_connection_ids.registerInitial(config.local_connection_id, [_]u8{0} ** 16);
        }
        try connection.peer_connection_ids.addInitial(
            config.peer_connection_id,
        );
        connection.last_validated_peer_path = .init(
            config.peer,
            config.peer_connection_id,
            false,
            null,
        );
        if (config.peer_stateless_reset_token) |token| {
            try connection.peer_connection_ids.setInitialStatelessResetToken(
                token,
            );
        }
        if (config.tls_handshake_complete) {
            connection.handshake_status.onTlsComplete(switch (config.local_endpoint) {
                .client => .client,
                .server => .server,
            });
        }
        connection.applyCurrentPmtuToPath();
        connection.observeConnectionStarted(null);
        connection.observeParametersSet(null);
        return connection;
    }

    pub fn deinit(self: *Connection) void {
        if (self.pending_received_datagram) |*datagram| {
            datagram.deinit(self.endpoint.allocator);
        }
        self.received.deinit();
        self.sent.deinit();
        self.recovery.deinit();
        self.path_validation.deinit();
        if (self.close_info) |*close_info| close_info.deinit(self.endpoint.allocator);
        for (self.stored_new_tokens.items) |token| self.endpoint.allocator.free(token);
        self.stored_new_tokens.deinit(self.endpoint.allocator);
        self.stream_send_flows.deinit(self.endpoint.allocator);
        self.stream_send_index.deinit(self.endpoint.allocator);
        for (self.stream_recv_flows.items) |*entry| entry.deinit();
        self.stream_recv_flows.deinit(self.endpoint.allocator);
        self.stream_recv_index.deinit(self.endpoint.allocator);
        self.closed_peer_bidi_streams.deinit(self.endpoint.allocator);
        self.closed_peer_uni_streams.deinit(self.endpoint.allocator);
        self.closed_local_bidi_streams.deinit(self.endpoint.allocator);
        self.closed_local_uni_streams.deinit(self.endpoint.allocator);
        self.path_response_targets.deinit(self.endpoint.allocator);
        self.datagram_recv_queue.deinit(self.endpoint.allocator);
        self.send_frame_buffer.deinit(self.endpoint.allocator);
        self.send_packet_buffer.deinit(self.endpoint.allocator);
        self.send_batch_stream_scratch.deinit(self.endpoint.allocator);
        self.send_batch_packet_stream_scratch.deinit(
            self.endpoint.allocator,
        );
        self.receive_packet_buffer.deinit(self.endpoint.allocator);
        self.receive_ack_range_buffer.deinit(self.endpoint.allocator);
        self.receive_frame_buffer.deinit(self.endpoint.allocator);
        if (self.prepared_send_keys) |prepared| {
            prepared.destroy(self.endpoint.allocator);
        }
        if (self.prepared_receive_keys) |prepared| {
            prepared.destroy(self.endpoint.allocator);
        }
        self.fixed_bit_generator.deinit();
        self.endpoint.allocator.free(self.peer_connection_id_storage);
        self.* = undefined;
    }

    fn setPeerConnectionId(
        self: *Connection,
        connection_id: []const u8,
    ) void {
        std.debug.assert(connection_id.len <= self.peer_connection_id_storage.len);
        @memmove(
            self.peer_connection_id_storage[0..connection_id.len],
            connection_id,
        );
        self.config.peer_connection_id =
            self.peer_connection_id_storage[0..connection_id.len];
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
            // Retain path metadata for observers and compatibility. The CID
            // router never enforces it before packet authentication.
            .active_migration_disabled = self.config.local_endpoint == .server and
                self.config.local_disable_active_migration,
            .accept_zero_fixed_bit = self.config.accept_zero_fixed_bit,
        };
    }

    /// Snapshot borrowed views of every local CID that currently routes to
    /// this connection. The endpoint owner calls this after CID issuance or a
    /// received RETIRE_CONNECTION_ID to keep its socket-level router exact.
    pub fn localConnectionIdsInto(
        self: *const Connection,
        out: []quic.connection_id.LocalPool.ActiveId,
    ) Error![]quic.connection_id.LocalPool.ActiveId {
        return try self.local_connection_ids.activeIdsInto(out);
    }

    pub fn localConnectionIdRevision(self: *const Connection) u64 {
        return self.local_connection_ids.activeRevision();
    }

    pub fn send(self: *Connection, frames: []const quic.Frame) Error!void {
        try self.sendAutomaticallyWithLoop(frames);
    }

    /// Send one application packet under a caller-owned relative timeout.
    ///
    /// Congestion and flow-control stalls keep processing peer packets and all
    /// transport timers. Received application data remains queued in connection
    /// state, while ACK policy is applied before the send is retried.
    pub fn sendWithTimeout(
        self: *Connection,
        frames: []const quic.Frame,
        timeout: std.Io.Duration,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendWithDeadline(frames, .fromNow(
            self.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// Send one application packet under an absolute awake-clock deadline.
    ///
    /// Unlike `send`, this also waits for congestion and flow-control progress.
    /// It uses the state-only receive path so packets consumed solely to unblock
    /// the write are still acknowledged and their application state is retained.
    pub fn sendWithDeadline(
        self: *Connection,
        frames: []const quic.Frame,
        deadline: std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
        _ = try deadline_policy.usableAwake(self.endpoint.io, deadline);
        while (true) {
            const now_ns = self.monotonicNowNs();
            if (callerDeadlineExpired(deadline, now_ns)) return error.Timeout;
            self.sendAutomaticallyAt(frames, now_ns) catch |err| switch (err) {
                error.FlowControlBlocked, error.CongestionLimited => {
                    self.servicePacketServicingTimersDeadline(deadline) catch |progress_err|
                        switch (progress_err) {
                            error.CongestionLimited => continue,
                            error.PacingLimited => {
                                try self.waitForPacingAvailabilityWithDeadline(
                                    deadline,
                                );
                                continue;
                            },
                            else => |other| return other,
                        };
                    continue;
                },
                error.PacingLimited => {
                    try self.waitForPacingAvailabilityWithDeadline(deadline);
                    continue;
                },
                else => |other| return other,
            };
            return;
        }
    }

    /// Attempt one send using the current awake-clock timestamp without
    /// sleeping or reading the endpoint socket. Event-loop adapters use this
    /// to preserve a single UDP receive owner and retry after their dispatcher
    /// reports transport progress.
    pub fn trySend(self: *Connection, frames: []const quic.Frame) Error!void {
        try self.sendAutomaticallyAt(frames, self.monotonicNowNs());
    }

    fn handleAutomaticEcnUnavailable(
        self: *Connection,
        requested_ecn: quic.packet_space.EcnCodepoint,
    ) bool {
        if (requested_ecn == .not_ect) return false;
        self.ecn_path.onValidationFailure();
        return true;
    }

    fn precheckPlainAckCurrentPathFailure(
        self: Connection,
        ack: quic.AckFrame,
    ) bool {
        if (ack.ecn_counts != null) return false;
        return self.sent.plainAckWouldFailForPathEpoch(
            ack,
            self.pmtu_path_epoch,
        );
    }

    fn sendAutomaticallyWithLoop(
        self: *Connection,
        frames: []const quic.Frame,
    ) Error!void {
        while (true) {
            const now_ns = self.monotonicNowNs();
            self.sendAutomaticallyAt(frames, now_ns) catch |err| switch (err) {
                error.PacingLimited => {
                    try self.waitForPacing(now_ns);
                    continue;
                },
                else => return err,
            };
            return;
        }
    }

    fn sendAutomaticallyAt(
        self: *Connection,
        frames: []const quic.Frame,
        sent_time_ns: ?u64,
    ) Error!void {
        try self.sendWithEcnAtImpl(
            frames,
            self.autoEcnForFrames(frames),
            sent_time_ns,
            true,
        );
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

    /// Submit one stateful batch using the connection's monotonic clock.
    ///
    /// Blocking protocol adapters need explicit prefix progress but should not
    /// pass a null send timestamp: recovery would then have no PTO time base
    /// for the newly sent packets. Deterministic tests can keep using the
    /// timestamped `sendManyProgressAt` variant.
    pub fn sendManyProgress(
        self: *Connection,
        packets: []const []const quic.Frame,
    ) Error!ConnectionBatchSendResult {
        return self.sendManyProgressAt(packets, self.monotonicNowNs());
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
        const now_ns = sent_time_ns orelse self.monotonicNowNs();
        // Route the first application packet through the single-packet path
        // while HANDSHAKE_DONE is unsent. It appends the control frame after
        // the caller's frames, preserving application order, and later calls
        // retain normal GSO/sendmmsg batching.
        if (self.handshake_status.needsHandshakeDone()) {
            try self.sendWithEcnAtImpl(
                packets[0],
                self.autoEcnForFrames(packets[0]),
                now_ns,
                true,
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

        const PacketPreflight = struct {
            payload_len: usize,
            recovery_payload_len: usize,
            ack_eliciting: bool,
            in_flight: bool,
            auto_ecn_eligible: bool,
            stream_bytes: u64,
        };
        var preflight: [max_batch_packets]PacketPreflight = undefined;
        // Stream-limit checks can emit STREAMS_BLOCKED through the ordinary
        // one-packet path, so perform all of them while batch scratch is empty.
        // While walking those frames, cache the packet traits and payload size
        // needed later by pacing, recovery, and packet-number sizing. Stateful
        // batch sends are dominated by many small STREAM packets, so avoiding
        // separate ack-eliciting/in-flight/wire-length passes saves CPU without
        // changing any transport decisions.
        for (packets[0..encryptable], 0..) |frames, i| {
            if (frames.len == 0) return error.MissingFrame;
            var traits: OutboundFrameTraits = .{};
            var payload_len: usize = 0;
            var recovery_payload_len: usize = 0;
            for (frames) |frame| {
                var current_traits: OutboundFrameTraits = .{};
                try self.validateOutboundFrameAndTraits(
                    frame,
                    &current_traits,
                );
                try traits.merge(current_traits);
                if (frame == .stream) {
                    try self.validateStreamFrameForSendAt(
                        frame.stream,
                        now_ns,
                    );
                }
                const frame_len = try frame.wireLen();
                payload_len = std.math.add(
                    usize,
                    payload_len,
                    frame_len,
                ) catch return error.InvalidFrameLength;
                if (current_traits.retransmittable) {
                    recovery_payload_len = std.math.add(
                        usize,
                        recovery_payload_len,
                        frame_len,
                    ) catch return error.InvalidFrameLength;
                }
            }
            preflight[i] = .{
                .payload_len = payload_len,
                .recovery_payload_len = recovery_payload_len,
                .ack_eliciting = traits.ack_eliciting,
                .in_flight = traits.in_flight,
                .auto_ecn_eligible = traits.autoEcnEligible(),
                .stream_bytes = traits.stream_bytes,
            };
        }

        const PreparedPacket = struct {
            frames: []const quic.Frame,
            packet_number: u64,
            packet_number_len: u8,
            payload_len: usize,
            recovery_payload_len: usize,
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
        const smoothed_rtt = self.rtt_stats.smoothedOrInitial();
        var next_pacing_deadline: ?u64 = null;
        var count: usize = 0;
        var total_stream_bytes: u64 = 0;
        var total_in_flight: usize = 0;
        var total_packet_len: usize = 0;
        const largest_acknowledged = self.sent.largestAcknowledged();
        const send_datagram_size = self.currentSendDatagramSize();
        const congestion_available = self.congestion.available();
        const send_flow_available = self.send_flow.available();

        while (count < encryptable) {
            const frames = packets[count];
            const packet_preflight = preflight[count];
            const payload_len = packet_preflight.payload_len;
            const packet_number = self.next_packet_number + count;
            const packet_number_len =
                quic.protection.packetNumberLenForPayload(
                    packet_number,
                    largest_acknowledged,
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
            if (packet_len > send_datagram_size or
                packet_len > self.endpoint.limits.max_datagram_size)
            {
                return error.DatagramTooLarge;
            }

            const in_flight = packet_preflight.in_flight;
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
                if (payload_len > congestion_available -
                    @min(congestion_available, total_in_flight))
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
            if (packet_stream_bytes > send_flow_available -
                @min(send_flow_available, total_stream_bytes))
            {
                if (count == 0) {
                    try self.sendDataBlockedAt(now_ns);
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
                    try self.sendStreamDataBlockedAt(stream_id, now_ns);
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
            prepared[count] = .{
                .frames = frames,
                .packet_number = packet_number,
                .packet_number_len = packet_number_len,
                .payload_len = payload_len,
                .recovery_payload_len = packet_preflight.recovery_payload_len,
                .packet_len = packet_len,
                .ack_eliciting = packet_preflight.ack_eliciting,
                .in_flight = in_flight,
                .stream_bytes = packet_stream_bytes,
            };
            total_stream_bytes += packet_stream_bytes;
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
        // One socket-level traffic-class setting applies to this sendmmsg/GSO
        // submission. Mark the batch only when every packet that will
        // actually be submitted is eligible; later input outside this paced
        // prefix must not suppress ECN for the current batch.
        var batch_auto_ecn_eligible = true;
        for (preflight[0..count]) |packet| {
            batch_auto_ecn_eligible = batch_auto_ecn_eligible and
                packet.auto_ecn_eligible;
        }
        const batch_ecn: quic.packet_space.EcnCodepoint =
            if (batch_auto_ecn_eligible and self.ecn_path.mayMarkEct0())
                .ect0
            else
                .not_ect;

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

        var tracked_recovery_packets: [max_batch_packets]u64 = undefined;
        var tracked_recovery_count: usize = 0;
        errdefer for (tracked_recovery_packets[0..tracked_recovery_count]) |packet_number| {
            _ = self.recovery.forgetPacketNumber(packet_number);
        };
        var tracked_sent_count: usize = 0;
        errdefer for (prepared[0..tracked_sent_count]) |packet| {
            _ = self.sent.forget(packet.packet_number);
        };

        try self.reserveAntiAmplification(total_packet_len);
        var anti_amplification_reserved = true;
        errdefer if (anti_amplification_reserved) {
            self.releaseAntiAmplification(total_packet_len);
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
            const packet_storage = self.send_packet_buffer.items[packet_offset..][0..packet.packet_len];
            const payload_offset = 1 + self.config.peer_connection_id.len + @as(usize, packet.packet_number_len);
            const payload = packet_storage[payload_offset..][0..packet.payload_len];
            const recovery_payload: ?[]const u8 = blk: {
                if (packet.recovery_payload_len != 0) {
                    // Encode once into stable recovery ownership, then copy
                    // those bytes directly through AEAD when the full packet
                    // is retransmittable. RFC 9221 DATAGRAM bytes are omitted
                    // from this stable payload.
                    const tracked = try self.recovery
                        .trackSentUninitialized(
                        packet.packet_number,
                        packet.recovery_payload_len,
                    );
                    tracked_recovery_packets[tracked_recovery_count] =
                        packet.packet_number;
                    tracked_recovery_count += 1;
                    var payload_list = std.ArrayList(u8).initBuffer(
                        tracked.payload,
                    );
                    try writeRetransmittableFramesAssumeCapacity(
                        &payload_list,
                        packet.frames,
                        packet.recovery_payload_len == packet.payload_len,
                    );
                    std.debug.assert(
                        payload_list.items.len ==
                            packet.recovery_payload_len,
                    );
                    break :blk tracked.payload;
                }
                break :blk null;
            };
            if (recovery_payload == null or
                packet.recovery_payload_len != packet.payload_len)
            {
                var payload_list = std.ArrayList(u8).initBuffer(payload);
                for (packet.frames) |frame| {
                    try frame.writeAssumeCapacity(&payload_list);
                }
                std.debug.assert(payload_list.items.len == packet.payload_len);
            }
            try self.sent.sentInFlightAtWithDatagramSizeAndPathEpoch(
                packet.packet_number,
                packet.ack_eliciting,
                packet.in_flight,
                packet.payload_len,
                packet.packet_len,
                batch_ecn,
                sent_time_ns,
                self.pmtu_path_epoch,
            );
            tracked_sent_count += 1;

            const packet_options: quic.protection.ShortPacketOptions = .{
                .destination_connection_id = self.config.peer_connection_id,
                .packet_number = packet.packet_number,
                .packet_number_len = packet.packet_number_len,
                .fixed_bit = self.nextFixedBit(),
                .spin_bit = self.nextSpinBit(),
                .key_phase = self.send_key_phase.currentKeyPhase(),
                .payload = if (recovery_payload != null and
                    packet.recovery_payload_len == packet.payload_len)
                    recovery_payload.?
                else
                    payload,
            };
            const sealed = if (recovery_payload != null and
                packet.recovery_payload_len == packet.payload_len)
                try self.sealCurrentShortPacketInto(
                    packet_storage,
                    packet_options,
                )
            else
                try self.sealCurrentShortPacketInPlace(
                    packet_storage,
                    packet_options,
                );
            self.recordPacketEncrypted();
            protected_count += 1;
            datagrams[i] = sealed;
            packet_offset += sealed.len;
        }

        const send_result = self.endpoint.sendManyBytesProgressWithEcn(
            self.config.peer,
            datagrams[0..count],
            batch_ecn,
        ) catch |err| switch (err) {
            error.EcnUnavailable => if (self.handleAutomaticEcnUnavailable(batch_ecn)) blk: {
                for (prepared[0..count]) |packet| {
                    std.debug.assert(
                        self.sent.rewritePacketEcn(packet.packet_number, .not_ect),
                    );
                }
                break :blk try self.endpoint.sendManyBytesProgressWithEcn(
                    self.config.peer,
                    datagrams[0..count],
                    .not_ect,
                );
            } else return err,
            else => return err,
        };
        std.debug.assert(send_result.sent_count <= count);

        var sent_packet_len: usize = 0;
        var sent_in_flight: usize = 0;
        var sent_stream_bytes: u64 = 0;
        for (prepared[0..send_result.sent_count]) |packet| {
            self.noteOneRttPacketSent(
                packet.packet_number,
                packet.packet_len,
                now_ns,
                packet.ack_eliciting,
            );
            sent_packet_len += packet.packet_len;
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
            total_packet_len - sent_packet_len,
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
        try self.sendAutomaticallyAt(frames, sent_time_ns);
    }

    pub fn sendWithEcnAt(self: *Connection, frames: []const quic.Frame, ecn: quic.packet_space.EcnCodepoint, sent_time_ns: ?u64) Error!void {
        try self.sendWithEcnAtImpl(frames, ecn, sent_time_ns, false);
    }

    fn sendWithEcnAtImpl(
        self: *Connection,
        frames: []const quic.Frame,
        ecn: quic.packet_space.EcnCodepoint,
        sent_time_ns: ?u64,
        automatic_ecn: bool,
    ) Error!void {
        if (frames.len != 0 and
            self.handshake_status.needsHandshakeDone() and
            !frame_traits.containsHandshakeDone(frames))
        {
            var stack: [handshake_done_frame_stack_capacity]quic.Frame =
                undefined;
            const combined = try appendPendingHandshakeDone(
                self.endpoint.allocator,
                &stack,
                frames,
            );
            defer if (combined.ptr != stack[0..].ptr) {
                self.endpoint.allocator.free(combined);
            };
            // Keep caller frames first so scheduling HANDSHAKE_DONE cannot
            // reorder the application's first 1-RTT frame.
            return self.sendWithEcnAtRaw(
                combined,
                ecn,
                sent_time_ns,
                automatic_ecn,
            );
        }
        try self.sendWithEcnAtRaw(frames, ecn, sent_time_ns, automatic_ecn);
    }

    fn sendWithEcnAtRaw(
        self: *Connection,
        frames: []const quic.Frame,
        ecn: quic.packet_space.EcnCodepoint,
        sent_time_ns: ?u64,
        automatic_ecn: bool,
    ) Error!void {
        self.pacing_blocked_until_ns = null;
        if (self.close_info != null or self.idle_timed_out) return error.ConnectionClosed;
        // Preserve the legacy explicit-disable contract without coupling that
        // connection-global compatibility latch to automatic per-path ECN.
        if (!automatic_ecn and ecn != .not_ect and self.sent.ecnDisabled()) {
            return error.EcnDisabled;
        }
        try self.validateNextPacketNumber();
        const validated_traits = try self.validateOutboundFrames(frames);
        const packet_streams = &self.send_batch_packet_stream_scratch;
        std.debug.assert(packet_streams.items.len == 0);
        defer packet_streams.clearRetainingCapacity();
        const stream_bytes = try self.collectOutboundStreamCredits(
            frames,
            packet_streams,
            sent_time_ns,
        );
        const prepared = try self.prepareFramesForSend(
            frames,
            sent_time_ns,
            validated_traits,
        );
        const qlog_now_ns = sent_time_ns orelse self.monotonicNowNs();

        // Pacing preflight above is deliberately mutation-free. Once it
        // succeeds, materialize any new stream entries before flow-control
        // checks so MAX_STREAM_DATA can subsequently refer to a stream whose
        // first attempted write was flow-control blocked.
        for (packet_streams.items) |credit| {
            _ = try self.sendStreamEntry(credit.stream_id);
        }

        if (stream_bytes > self.send_flow.available()) {
            self.send_frame_buffer.items.len = 0;
            packet_streams.clearRetainingCapacity();
            try self.sendDataBlockedAt(sent_time_ns);
            return error.FlowControlBlocked;
        }
        for (packet_streams.items) |credit| {
            const available = if (self.findSendStreamEntry(credit.stream_id)) |entry|
                entry.flow.available()
            else
                self.initialSendStreamDataLimit(credit.stream_id);
            if (credit.bytes > available) {
                self.send_frame_buffer.items.len = 0;
                packet_streams.clearRetainingCapacity();
                try self.sendStreamDataBlockedAt(
                    credit.stream_id,
                    sent_time_ns,
                );
                return error.FlowControlBlocked;
            }
        }

        var reserved_connection: u64 = 0;
        var stack_reserved_streams: [16]ReservedStreamCredit = undefined;
        var reserved_streams: std.ArrayList(ReservedStreamCredit) =
            .initBuffer(&stack_reserved_streams);
        var reserved_streams_allocated = false;
        defer if (reserved_streams_allocated) {
            reserved_streams.deinit(self.endpoint.allocator);
        };
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
        for (packet_streams.items) |credit| {
            if (credit.bytes == 0) continue;
            const entry = (self.findSendStreamEntry(credit.stream_id) orelse unreachable);
            // Record a zero-sized reservation before mutating stream flow so an
            // allocator failure cannot leave `entry.flow.used` inflated.  Once
            // reserve succeeds, update the rollback byte count in place.
            try appendReservedStreamCredit(&reserved_streams, &reserved_streams_allocated, self.endpoint.allocator, .{
                .stream_id = credit.stream_id,
                .bytes = 0,
            });
            const reserved_index = reserved_streams.items.len - 1;
            try entry.flow.reserve(credit.bytes);
            reserved_streams.items[reserved_index].bytes = credit.bytes;
        }
        try self.sendPreparedFramesEcnAtUnchecked(
            prepared,
            ecn,
            sent_time_ns,
            automatic_ecn,
        );
        self.observePacketSent(
            qlog_now_ns,
            self.next_packet_number - 1,
            prepared.packet_len,
            frames,
        );
        self.noteSentStreams(frames);
    }

    fn collectOutboundStreamCredits(
        self: *Connection,
        frames: []const quic.Frame,
        credits: *std.ArrayList(ReservedStreamCredit),
        sent_time_ns: ?u64,
    ) Error!u64 {
        std.debug.assert(credits.items.len == 0);
        errdefer credits.clearRetainingCapacity();

        var stream_bytes: u64 = 0;
        for (frames) |frame| {
            if (frame != .stream) continue;
            try self.validateStreamFrameForSendAt(
                frame.stream,
                sent_time_ns,
            );
            const bytes = std.math.cast(
                u64,
                frame.stream.data.len,
            ) orelse return error.InvalidFrameLength;
            stream_bytes = std.math.add(u64, stream_bytes, bytes) catch
                return error.InvalidFrameLength;
            // Aggregate by stream before consulting flow-control state. HTTP/3
            // writers can split one logical body into several STREAM frames in
            // the same packet; checking each fragment against the same
            // pre-reservation limit would otherwise let the packet exceed the
            // stream's remaining credit.
            try addReservedStreamCredit(
                credits,
                self.endpoint.allocator,
                frame.stream.stream_id,
                bytes,
            );
        }
        return stream_bytes;
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
        const datagram_size = self.currentSendDatagramSize();
        var candidate = maxDatagramPayloadForFrameSize(
            @min(frame_limit, datagram_size),
        ) orelse return null;
        // max_datagram_frame_size limits the DATAGRAM frame itself, whereas
        // the path MTU limits the complete protected QUIC packet. Account for
        // the short header, adaptive packet number, and AEAD tag so callers can
        // rely on this value instead of discovering a smaller bound at send().
        while (true) : (candidate -= 1) {
            const frame_size = datagramFrameWireSizeForLength(
                candidate,
                true,
            ) orelse return null;
            const packet_number_len =
                quic.protection.packetNumberLenForPayload(
                    self.next_packet_number,
                    self.sent.largestAcknowledged(),
                    frame_size,
                );
            const packet_overhead = 1 +
                self.config.peer_connection_id.len +
                @as(usize, packet_number_len) +
                quic.protection.aead_tag_len;
            if (frame_size <= datagram_size -| packet_overhead) {
                return candidate;
            }
            if (candidate == 0) return null;
        }
    }

    pub fn sendDatagram(self: *Connection, data: []const u8) Error!void {
        try self.validateDatagramSend(data);
        const frames = [_]quic.Frame{.{ .datagram = .{
            .data = data,
            .length_present = true,
        } }};
        try self.send(&frames);
        self.datagrams_sent_count +|= 1;
    }

    /// Attempt one unreliable DATAGRAM send without sleeping or receiving.
    /// Event-loop owners can retry after congestion or the exposed pacing
    /// deadline while preserving exactly-once application accounting.
    pub fn trySendDatagram(self: *Connection, data: []const u8) Error!void {
        try self.validateDatagramSend(data);
        const frames = [_]quic.Frame{.{ .datagram = .{
            .data = data,
            .length_present = true,
        } }};
        try self.trySend(&frames);
        self.datagrams_sent_count +|= 1;
    }

    /// Send one unreliable DATAGRAM, waiting for congestion credit for at
    /// most `timeout`. No application send queue is retained: timeout means
    /// this payload was not submitted and may be retried by the caller.
    pub fn sendDatagramWithTimeout(
        self: *Connection,
        data: []const u8,
        timeout: std.Io.Duration,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendDatagramWithDeadline(data, .fromNow(
            self.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// Send one unreliable DATAGRAM under a caller-owned absolute awake-clock
    /// deadline. While congestion-blocked, the connection remains the sole UDP
    /// owner and processes ACKs and transport timers before retrying. Pacing
    /// sleeps are admitted only when their scheduled wake precedes the same
    /// deadline. Received application frames remain queued in connection state.
    pub fn sendDatagramWithDeadline(
        self: *Connection,
        data: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
        while (true) {
            self.trySendDatagramWithDeadline(data, deadline) catch |err| switch (err) {
                error.CongestionLimited => {
                    try self.servicePacketServicingTimersDeadline(deadline);
                    continue;
                },
                else => |other| return other,
            };
            return;
        }
    }

    pub fn sendDatagrams(
        self: *Connection,
        payloads: []const []const u8,
        committed_count: *usize,
    ) Error!void {
        committed_count.* = 0;
        try self.validateDatagrams(payloads);
        while (committed_count.* < payloads.len) {
            var batch_committed: usize = 0;
            self.trySendDatagramsValidated(
                payloads[committed_count.*..],
                &batch_committed,
            ) catch |err| {
                committed_count.* += batch_committed;
                switch (err) {
                    error.CongestionLimited => {
                        try self.servicePacketServicingTimers();
                        continue;
                    },
                    error.PacingLimited => {
                        try self.waitForPacingAvailability();
                        continue;
                    },
                    else => |other| return other,
                }
            };
            if (batch_committed == 0) return error.Unexpected;
            committed_count.* += batch_committed;
        }
    }

    /// Send an ordered batch of unreliable DATAGRAM payloads under one
    /// absolute awake-clock deadline. Every payload is validated before the
    /// first packet is emitted. `committed_count` reports only the prefix
    /// accepted by the socket, even when encryption consumed more packet
    /// numbers during a partial batch submission.
    pub fn sendDatagramsWithTimeout(
        self: *Connection,
        payloads: []const []const u8,
        committed_count: *usize,
        timeout: std.Io.Duration,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
        committed_count.* = 0;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendDatagramsWithDeadline(
            payloads,
            committed_count,
            .fromNow(self.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendDatagramsWithDeadline(
        self: *Connection,
        payloads: []const []const u8,
        committed_count: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
        committed_count.* = 0;
        _ = try deadline_policy.usableAwake(self.endpoint.io, deadline);
        try self.validateDatagrams(payloads);

        while (committed_count.* < payloads.len) {
            _ = try deadline_policy.usableAwake(self.endpoint.io, deadline);
            var batch_committed: usize = 0;
            self.trySendDatagramsValidated(
                payloads[committed_count.*..],
                &batch_committed,
            ) catch |err| {
                committed_count.* += batch_committed;
                switch (err) {
                    error.CongestionLimited => {
                        try self.servicePacketServicingTimersDeadline(deadline);
                        continue;
                    },
                    error.PacingLimited => {
                        try self.waitForPacingAvailabilityWithDeadline(deadline);
                        continue;
                    },
                    else => |other| return other,
                }
            };
            if (batch_committed == 0) return error.Unexpected;
            committed_count.* += batch_committed;
        }
    }

    /// Submit at most one socket batch of unreliable DATAGRAM payloads. The
    /// output count is the socket-visible input prefix, including when the
    /// backend reports an error after accepting some datagrams.
    pub fn trySendDatagrams(
        self: *Connection,
        payloads: []const []const u8,
        committed_count: *usize,
    ) Error!void {
        committed_count.* = 0;
        if (payloads.len == 0) return;
        const batch_len = @min(max_batch_packets, payloads.len);
        try self.validateDatagrams(payloads[0..batch_len]);
        return self.trySendDatagramsValidated(payloads, committed_count);
    }

    pub fn validateDatagrams(
        self: Connection,
        payloads: []const []const u8,
    ) Error!void {
        if (payloads.len != 0) {
            const last_packet_number = std.math.add(
                u64,
                self.next_packet_number,
                payloads.len - 1,
            ) catch return error.InvalidPacketNumber;
            if (last_packet_number > quic.protection.max_packet_number) {
                return error.InvalidPacketNumber;
            }
        }
        for (payloads) |payload| try self.validateDatagramSend(payload);
        // Include each future packet number in size validation before any
        // socket submission. A partial socket send returns immediately; a
        // suffix retry re-enters here with the resulting nonce gap.
        var frames: [1]quic.Frame = undefined;
        for (payloads, 0..) |payload, index| {
            frames[0] = .{ .datagram = .{
                .data = payload,
                .length_present = true,
            } };
            if (try self.packetLenForFramesAtOffset(index, &frames) >
                self.currentSendDatagramSize())
            {
                return error.DatagramTooLarge;
            }
        }
    }

    fn trySendDatagramsValidated(
        self: *Connection,
        payloads: []const []const u8,
        committed_count: *usize,
    ) Error!void {
        committed_count.* = 0;
        if (payloads.len == 0) return;
        const batch_len = @min(max_batch_packets, payloads.len);
        var frame_storage: [max_batch_packets][1]quic.Frame = undefined;
        var packets: [max_batch_packets][]const quic.Frame = undefined;
        for (payloads[0..batch_len], 0..) |payload, index| {
            frame_storage[index][0] = .{ .datagram = .{
                .data = payload,
                .length_present = true,
            } };
            packets[index] = &frame_storage[index];
        }
        const result = try self.sendManyProgress(packets[0..batch_len]);
        committed_count.* = result.sent_count;
        self.datagrams_sent_count +|= result.sent_count;
        if (result.send_error) |err| return err;
    }

    /// Perform one DATAGRAM send attempt while bounding any pacing wait.
    /// Congestion exhaustion is returned to the caller without reading UDP so
    /// protocol adapters can drive their own packet router under the same
    /// deadline.
    pub fn trySendDatagramWithDeadline(
        self: *Connection,
        data: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
        if (deadline.clock != .awake or
            deadline.durationFromNow(self.endpoint.io).raw.nanoseconds <= 0)
        {
            return error.Timeout;
        }
        try self.validateDatagramSend(data);
        const frames = [_]quic.Frame{.{ .datagram = .{
            .data = data,
            .length_present = true,
        } }};
        while (true) {
            const now_ns = self.monotonicNowNs();
            if (callerDeadlineExpired(deadline, now_ns)) {
                return error.Timeout;
            }
            self.sendAutomaticallyAt(&frames, now_ns) catch |err| switch (err) {
                error.PacingLimited => {
                    const pacing_deadline =
                        self.pacing_blocked_until_ns orelse return err;
                    const caller_ns = std.math.cast(
                        u64,
                        deadline.raw.nanoseconds,
                    ) orelse std.math.maxInt(u64);
                    if (pacing_deadline >= caller_ns) return error.Timeout;
                    try self.waitForPacing(now_ns);
                    continue;
                },
                else => |other| return other,
            };
            self.datagrams_sent_count +|= 1;
            return;
        }
    }

    /// Perform exactly one DATAGRAM send attempt under a caller-owned
    /// deadline. Unlike `trySendDatagramWithDeadline`, pacing never sleeps:
    /// it returns `PacingLimited`, or `Timeout` when the earliest retry would
    /// already exhaust the caller's budget.
    pub fn trySendDatagramOnceWithDeadline(
        self: *Connection,
        data: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
        if (deadline.clock != .awake or
            deadline.durationFromNow(self.endpoint.io).raw.nanoseconds <= 0)
        {
            return error.Timeout;
        }
        self.trySendDatagram(data) catch |err| switch (err) {
            error.PacingLimited => {
                const pacing_deadline =
                    self.pacing_blocked_until_ns orelse return err;
                const caller_ns = std.math.cast(
                    u64,
                    deadline.raw.nanoseconds,
                ) orelse std.math.maxInt(u64);
                if (pacing_deadline >= caller_ns) return error.Timeout;
                return err;
            },
            else => |other| return other,
        };
    }

    fn validateDatagramSend(self: Connection, data: []const u8) Error!void {
        const max_payload = self.maxDatagramPayloadSize() orelse return error.DatagramsNotEnabled;
        if (data.len > max_payload) return error.DatagramTooLarge;
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

    /// Remove queued transport copies belonging to one authenticated packet
    /// after an application protocol has routed that packet's frame payloads
    /// directly. Packet identity remains stable across GRO batch visitation.
    pub fn discardDatagramsForPacket(
        self: *Connection,
        packet_number: u64,
    ) usize {
        return self.datagram_recv_queue.discardPacket(
            self.endpoint.allocator,
            packet_number,
        );
    }

    pub fn queuedDatagramsForPacket(
        self: Connection,
        packet_number: u64,
    ) usize {
        return self.datagram_recv_queue.countPacket(packet_number);
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
            .active_send_streams = self.stream_send_flows.items.len,
            .active_receive_streams = self.stream_recv_flows.items.len,
            .closed_peer_stream_ranges = self.closed_peer_bidi_streams.rangeCount() +
                self.closed_peer_uni_streams.rangeCount(),
            .closed_local_stream_ranges = self.closed_local_bidi_streams.rangeCount() +
                self.closed_local_uni_streams.rangeCount(),
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
            .ecn_validation_failed = self.ecn_path.state() == .failed or
                self.sent.ecnDisabled(),
            .authentication_failures = self.receive_authentication_failures,
            .local_key_update_count = self.send_key_phase.keyUpdateCount(),
            .peer_key_update_count = self.receive_key_phase.keyUpdateCount(),
            .failed_path_validations = self.failedPathValidationCount(),
            .path_challenges_dropped = self.path_validation.droppedChallengeCount(),
            .sent_packet_stats = self.sent.stats(),
            .received_packet_stats = self.received.stats(),
            .recovery_queue_stats = self.recovery.stats(),
        };
    }

    pub fn getStats(self: Connection) ConnectionStats {
        return self.stats();
    }

    pub fn sendStreamStats(
        self: *const Connection,
        stream_id: u64,
    ) ?SendStreamStats {
        if (self.stream_send_index.count() == 0) return null;
        const index = self.stream_send_index.get(stream_id) orelse return null;
        if (index >= self.stream_send_flows.items.len) return null;
        const entry = &self.stream_send_flows.items[index];
        if (entry.stream_id != stream_id) return null;
        return sendStreamStatsFromEntry(entry);
    }

    pub fn getSendStreamStats(
        self: *const Connection,
        stream_id: u64,
    ) ?SendStreamStats {
        return self.sendStreamStats(stream_id);
    }

    /// Reserve the next locally initiated stream ID without allocating stream
    /// transport state. State is created lazily by the first STREAM/control
    /// operation, matching QUIC's rule that opening a stream is not visible on
    /// the wire until it is used.
    pub fn openStream(self: *Connection) Error!u64 {
        return self.openLocalStream(.bidirectional);
    }

    /// Attempt to reserve one bidirectional stream without sleeping while a
    /// STREAMS_BLOCKED notification is paced.
    pub fn tryOpenStream(self: *Connection) Error!u64 {
        return self.tryOpenLocalStream(.bidirectional);
    }

    /// Reserve one bidirectional stream when peer credit is already present.
    ///
    /// Unlike `openStreamWithDeadline`, this never reads the endpoint socket
    /// or waits. Unlike `tryOpenStream`, it also emits no STREAMS_BLOCKED
    /// packet. Shared-endpoint dispatchers can therefore poll after routing a
    /// packet or servicing a timer without creating a second socket owner.
    /// `null` leaves the stream-ID cursor unchanged and means the caller must
    /// wait for externally driven MAX_STREAMS progress.
    pub fn pollOpenStream(self: *Connection) Error!?u64 {
        return self.pollOpenLocalStream(.bidirectional);
    }

    /// Peek at the next local stream ID without reserving transport credit.
    /// Protocol adapters with a second shared namespace use this to reject a
    /// cursor mismatch before either irreversible reservation is consumed.
    pub fn nextLocalBidirectionalStreamId(self: *const Connection) u64 {
        return self.next_local_bidi_stream_id;
    }

    pub fn nextLocalUnidirectionalStreamId(self: *const Connection) u64 {
        return self.next_local_uni_stream_id;
    }

    /// Wait for peer bidirectional-stream credit until `timeout` expires.
    ///
    /// The relative timeout is converted once to an absolute awake-clock
    /// deadline, so unrelated packets and transport timer wakeups cannot
    /// extend the caller's bound. A failed wait never advances the stream ID.
    pub fn openStreamWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) (Error || quic.runtime.ReceiveTimeoutError)!u64 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.openStreamWithDeadline(.fromNow(
            self.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// Wait for peer bidirectional-stream credit under an absolute awake
    /// deadline while continuing to receive packets and service QUIC timers.
    pub fn openStreamWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!u64 {
        return self.openLocalStreamWithDeadline(.bidirectional, deadline);
    }

    pub fn openUnidirectionalStream(self: *Connection) Error!u64 {
        return self.openLocalStream(.unidirectional);
    }

    /// Attempt to reserve one unidirectional stream without sleeping while a
    /// STREAMS_BLOCKED notification is paced.
    pub fn tryOpenUnidirectionalStream(self: *Connection) Error!u64 {
        return self.tryOpenLocalStream(.unidirectional);
    }

    /// Socket-free unidirectional counterpart to `pollOpenStream`.
    pub fn pollOpenUnidirectionalStream(self: *Connection) Error!?u64 {
        return self.pollOpenLocalStream(.unidirectional);
    }

    pub fn pollOpenUniStream(self: *Connection) Error!?u64 {
        return self.pollOpenUnidirectionalStream();
    }

    /// Wait for peer unidirectional-stream credit until `timeout` expires.
    pub fn openUnidirectionalStreamWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) (Error || quic.runtime.ReceiveTimeoutError)!u64 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.openUnidirectionalStreamWithDeadline(.fromNow(
            self.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// Wait for peer unidirectional-stream credit under an absolute awake
    /// deadline while continuing to receive packets and service QUIC timers.
    pub fn openUnidirectionalStreamWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!u64 {
        return self.openLocalStreamWithDeadline(.unidirectional, deadline);
    }

    /// Short alias matching common QUIC APIs.
    pub fn openUniStream(self: *Connection) Error!u64 {
        return self.openUnidirectionalStream();
    }

    pub fn openUniStreamWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) (Error || quic.runtime.ReceiveTimeoutError)!u64 {
        return self.openUnidirectionalStreamWithTimeout(timeout);
    }

    pub fn openUniStreamWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!u64 {
        return self.openUnidirectionalStreamWithDeadline(deadline);
    }

    fn openLocalStreamWithDeadline(
        self: *Connection,
        direction: StreamDirection,
        deadline: std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!u64 {
        // Reject another clock domain before STREAMS_BLOCKED or any socket I/O.
        // Every retry then reuses this exact timestamp rather than refreshing
        // a relative timeout after an unrelated packet or transport timer.
        if (deadline.clock != .awake or
            deadline.durationFromNow(self.endpoint.io).raw.nanoseconds <= 0)
        {
            return error.Timeout;
        }
        while (true) {
            if (self.close_info != null or self.idle_timed_out) {
                return error.ConnectionClosed;
            }
            if (!self.localStreamLimitExceeded(direction)) {
                // No other owner may mutate a Connection concurrently, so the
                // immediately following reservation cannot lose this credit.
                return self.reserveLocalStream(direction);
            }
            self.sendStreamsBlockedWithDeadline(
                direction,
                deadline,
            ) catch |err| switch (err) {
                // Only an ACK can restore congestion credit. Keep receiving
                // under the caller's deadline, then retry the notification.
                error.CongestionLimited => {},
                else => |other| return other,
            };
            try self.servicePacketServicingTimersDeadline(deadline);
        }
    }

    fn openLocalStream(
        self: *Connection,
        direction: StreamDirection,
    ) Error!u64 {
        if (self.close_info != null or self.idle_timed_out) {
            return error.ConnectionClosed;
        }
        if (self.localStreamLimitExceeded(direction)) {
            try self.sendStreamsBlocked(direction);
            return error.StreamLimitExceeded;
        }
        return self.reserveLocalStream(direction);
    }

    fn tryOpenLocalStream(
        self: *Connection,
        direction: StreamDirection,
    ) Error!u64 {
        if (self.close_info != null or self.idle_timed_out) {
            return error.ConnectionClosed;
        }
        if (self.localStreamLimitExceeded(direction)) {
            try self.sendStreamsBlockedAt(direction, self.monotonicNowNs());
            return error.StreamLimitExceeded;
        }
        return self.reserveLocalStream(direction);
    }

    fn pollOpenLocalStream(
        self: *Connection,
        direction: StreamDirection,
    ) Error!?u64 {
        if (self.close_info != null or self.idle_timed_out) {
            return error.ConnectionClosed;
        }
        if (self.localStreamLimitExceeded(direction)) return null;
        return try self.reserveLocalStream(direction);
    }

    fn localStreamLimitExceeded(
        self: *const Connection,
        direction: StreamDirection,
    ) bool {
        const stream_id, const limit = switch (direction) {
            .bidirectional => .{
                self.next_local_bidi_stream_id,
                self.peer_max_streams_bidi,
            },
            .unidirectional => .{
                self.next_local_uni_stream_id,
                self.peer_max_streams_uni,
            },
        };
        return streamCountForId(stream_id) > limit;
    }

    fn reserveLocalStream(
        self: *Connection,
        direction: StreamDirection,
    ) Error!u64 {
        const next = switch (direction) {
            .bidirectional => &self.next_local_bidi_stream_id,
            .unidirectional => &self.next_local_uni_stream_id,
        };
        const stream_id = next.*;
        next.* = std.math.add(u64, stream_id, 4) catch
            return error.StreamLimitExceeded;
        self.outgoing_streams_created_count +|= 1;
        return stream_id;
    }

    /// Snapshot the immediately usable application STREAM credit.
    ///
    /// This does not reserve bytes and can race a subsequent send in a
    /// concurrent owner; connection adapters serialize mutation and use it as
    /// a sizing hint before the transport performs authoritative preflight.
    pub fn connectionSendAvailable(self: Connection) u64 {
        return self.send_flow.available();
    }

    /// Snapshot only one stream's immediately usable flow-control credit.
    /// Callers refreshing many streams can combine this with one connection,
    /// congestion, and path-MTU snapshot instead of rebuilding a full
    /// `SendCredit` value for every stream.
    pub fn streamSendAvailable(
        self: *const Connection,
        stream_id: u64,
    ) u64 {
        return if (self.isClosedStream(stream_id))
            0
        else if (self.stream_send_index.count() == 0)
            self.initialSendStreamDataLimit(stream_id)
        else if (self.stream_send_index.get(stream_id)) |index|
            if (index < self.stream_send_flows.items.len and
                self.stream_send_flows.items[index].stream_id == stream_id)
                self.stream_send_flows.items[index].flow.available()
            else
                self.initialSendStreamDataLimit(stream_id)
        else
            self.initialSendStreamDataLimit(stream_id);
    }

    pub fn streamSendCredit(
        self: Connection,
        stream_id: u64,
    ) SendCredit {
        return .{
            .connection = self.connectionSendAvailable(),
            .stream = self.streamSendAvailable(stream_id),
            .congestion = self.congestion.available(),
            .max_datagram_size = self.currentSendDatagramSize(),
        };
    }

    pub fn recvStreamStats(
        self: *const Connection,
        stream_id: u64,
    ) ?RecvStreamStats {
        if (self.stream_recv_index.count() == 0) return null;
        const index = self.stream_recv_index.get(stream_id) orelse return null;
        if (index >= self.stream_recv_flows.items.len) return null;
        const entry = &self.stream_recv_flows.items[index];
        if (entry.stream_id != stream_id) return null;
        return recvStreamStatsFromEntry(entry);
    }

    pub fn getRecvStreamStats(
        self: *const Connection,
        stream_id: u64,
    ) ?RecvStreamStats {
        return self.recvStreamStats(stream_id);
    }

    pub fn keepAliveEnabled(self: *const Connection) bool {
        return self.config.keep_alive_period_ms != 0;
    }

    /// Effective keep-alive interval in milliseconds.
    ///
    /// The configured period is first capped to half the negotiated idle
    /// timeout when one exists, then raised to at least 1.5x PTO so a keep-alive
    /// PING does not race normal loss recovery on high-latency paths.
    pub fn keepAliveIntervalMillis(self: *const Connection) ?u64 {
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

    pub fn keepAliveDeadlineMillis(self: *const Connection) ?u64 {
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
    /// work instead of polling loss detection, deferred stream credit, idle
    /// timeout, keep-alive, path-validation, close, and key-discard timers
    /// independently. This selector is read-only: callers still dispatch the
    /// typed helper matching `kind` when the deadline becomes due.
    pub fn nextTimerDeadline(self: *const Connection) ?TimerDeadline {
        if (self.idle_timed_out) return null;
        if (self.close_info) |close_info| {
            if (close_info.state == .closed) return null;
            var terminal: ?TimerDeadline = null;
            if (close_info.expires_ms) |deadline| {
                considerTimerDeadline(&terminal, .{
                    .kind = .close,
                    .deadline_ns = millisToNanos(deadline),
                });
            }
            if (close_info.state == .closing) {
                if (close_info.response_deadline_ns) |deadline| {
                    considerTimerDeadline(&terminal, .{
                        .kind = .close_response,
                        .deadline_ns = deadline,
                    });
                }
            }
            return terminal;
        }
        var next: ?TimerDeadline = null;
        if (self.path_response_retry_deadline_ns) |deadline| {
            considerTimerDeadline(&next, .{
                .kind = .path_response,
                .deadline_ns = deadline,
            });
        }
        if (self.stop_sending_reset_retry_deadline_ns) |deadline| {
            considerTimerDeadline(&next, .{
                .kind = .stop_sending_reset,
                .deadline_ns = deadline,
            });
        }
        if (self.streams_blocked_response_retry_deadline_ns) |deadline| {
            considerTimerDeadline(&next, .{
                .kind = .streams_blocked_response,
                .deadline_ns = deadline,
            });
        }
        // Internal path-validation work wins ties with the generic pacing
        // notification so one dispatcher turn performs the queued send.
        if (self.path_validation_retry_deadline_ns) |deadline| {
            considerTimerDeadline(&next, .{
                .kind = .path_validation,
                .deadline_ns = deadline,
            });
        }
        if (self.pacing_blocked_until_ns) |deadline| {
            considerTimerDeadline(&next, .{
                .kind = .pacing,
                .deadline_ns = deadline,
            });
        }
        if (self.stream_release_retry_deadline_ns) |deadline| {
            considerTimerDeadline(&next, .{
                .kind = .peer_stream_credit,
                .deadline_ns = deadline,
            });
        }
        if (self.receive_credit_retry_deadline_ns) |deadline| {
            considerTimerDeadline(&next, .{
                .kind = .receive_credit,
                .deadline_ns = deadline,
            });
        }
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
        if (self.pmtuProbeDeadline()) |deadline| {
            considerTimerDeadline(&next, .{
                .kind = .pmtu_raise,
                .deadline_ns = deadline,
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
            .path_response => {
                self.path_response_retry_deadline_ns = null;
                self.sendPendingPathResponseAt(now_ns) catch |err| {
                    self.schedulePathResponseRetry(err, now_ns);
                };
            },
            .stop_sending_reset => {
                self.stop_sending_reset_retry_deadline_ns = null;
                self.flushPendingStopSendingResetAt(now_ns) catch |err| {
                    self.scheduleStopSendingResetRetry(err, now_ns);
                };
            },
            .streams_blocked_response => {
                self.streams_blocked_response_retry_deadline_ns = null;
                self.flushPendingStreamsBlockedResponseAt(now_ns) catch |err| {
                    self.scheduleStreamsBlockedResponseRetry(err, now_ns);
                };
            },
            // Pacing is application-owned pending work rather than a queued
            // transport frame. Clearing the hint emits one endpoint timer
            // event so the application can retry without spinning.
            .pacing => self.pacing_blocked_until_ns = null,
            .ack_delay => {
                try self.serviceAckDelayTimerAt(now_ns);
            },
            .peer_stream_credit => {
                self.stream_release_retry_deadline_ns = null;
                self.flushRequestedStreamReleasesAt(now_ns) catch |err| {
                    self.scheduleStreamReleaseRetry(err, now_ns);
                };
            },
            .receive_credit => {
                self.receive_credit_retry_deadline_ns = null;
                self.flushPendingReceiveCreditAt(now_ns) catch |err| {
                    self.scheduleReceiveCreditRetry(err, now_ns);
                };
            },
            .loss_time, .pto => {
                _ = try self.serviceLossDetectionTimer(now_ns);
            },
            .pmtu_raise => {
                _ = self.servicePmtuTimerAt(now_ns);
            },
            .path_validation => {
                const retry_due = if (self.path_validation_retry_deadline_ns) |retry|
                    now_ns >= retry
                else
                    false;
                const expired = try self.checkPathValidationTimeouts(now_ns);
                // Retrying only by moving an expired challenge back to the
                // pending queue leaves a blocking receive with no next path
                // deadline, so it can sleep forever after a lost
                // PATH_RESPONSE. Emit the retry immediately and arm it for the
                // current PTO; subsequent receive waits remain timer-driven.
                if ((expired != 0 or retry_due) and
                    self.path_validation.pendingChallengeCount() != 0)
                {
                    self.path_validation_retry_deadline_ns = null;
                    _ = self.sendPendingPathChallengesAt(
                        now_ns,
                        self.ptoPeriod(),
                    ) catch |err| switch (err) {
                        // A 1200-byte validation datagram may need more
                        // candidate-path credit. Keep the challenge pending
                        // and let the receive loop wait for another datagram.
                        error.AntiAmplificationLimited,
                        error.CongestionLimited,
                        error.PacingLimited,
                        => {
                            self.notePathValidationSendBlocked(err, now_ns);
                            return deadline;
                        },
                        else => |other| return other,
                    };
                }
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
            .close_response => {
                self.close_info.?.response_deadline_ns = null;
                self.resendClose() catch {
                    self.scheduleCloseResponseAt(now_ns);
                };
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

    /// Exact protected size for a future packet containing `frames`.
    ///
    /// HTTP/3 batch planners use this read-only query before handing borrowed
    /// frame slices to `sendManyProgressAt`. Accounting for the packet-number
    /// offset avoids a fixed-overhead guess when a batch crosses a truncated
    /// packet-number length boundary.
    pub fn packetLenForFramesAtOffset(
        self: Connection,
        packet_offset: usize,
        frames: []const quic.Frame,
    ) Error!usize {
        if (frames.len == 0) return error.MissingFrame;
        const packet_number = std.math.add(
            u64,
            self.next_packet_number,
            packet_offset,
        ) catch return error.InvalidPacketNumber;
        if (packet_number > quic.protection.max_packet_number) {
            return error.InvalidPacketNumber;
        }
        var payload_len: usize = 0;
        for (frames) |frame| {
            payload_len = std.math.add(
                usize,
                payload_len,
                try frame.wireLen(),
            ) catch return error.InvalidFrameLength;
        }
        if (packet_offset == 0 and
            self.handshake_status.needsHandshakeDone())
        {
            payload_len = std.math.add(usize, payload_len, 1) catch
                return error.InvalidFrameLength;
        }
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
        return std.math.add(usize, overhead, payload_len) catch
            return error.InvalidPayloadLength;
    }

    /// Wait until a previously reported pacing deadline becomes writable.
    ///
    /// Blocking protocol adapters call this only after
    /// `sendManyProgressAt` returns `PacingLimited`; event-loop users can keep
    /// integrating `pacingDeadlineAt` into their own scheduler.
    pub fn waitForPacingAvailability(self: *Connection) Error!void {
        try self.waitForPacing(self.monotonicNowNs());
    }

    /// Wait for the currently exposed pacing wake-up without exceeding a
    /// caller-owned absolute awake-clock deadline.
    pub fn waitForPacingAvailabilityWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
        if (deadline.clock != .awake or
            deadline.durationFromNow(self.endpoint.io).raw.nanoseconds <= 0)
        {
            return error.Timeout;
        }
        const now_ns = self.monotonicNowNs();
        const pacing_deadline =
            self.pacing_blocked_until_ns orelse return error.PacingLimited;
        const caller_ns = std.math.cast(
            u64,
            deadline.raw.nanoseconds,
        ) orelse std.math.maxInt(u64);
        if (pacing_deadline >= caller_ns) return error.Timeout;
        try self.waitForPacing(now_ns);
    }

    pub fn sendAckFrequency(self: *Connection, ack_eliciting_threshold: u64, request_max_ack_delay: u64, reordering_threshold: u64) Error!u64 {
        if (!self.ackFrequencySendEnabled()) {
            return error.AckFrequencyDisabled;
        }
        try validateRequestedMaxAckDelay(
            request_max_ack_delay,
            self.config.peer_min_ack_delay,
        );
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
        if (!self.ackFrequencySendEnabled()) {
            return error.AckFrequencyDisabled;
        }
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

    /// Configure this endpoint's local ACK cadence.
    ///
    /// This is the local counterpart to receiving an ACK_FREQUENCY frame. It is
    /// useful for embedded runtimes and benchmarks that know their event-loop
    /// batching policy without negotiating the extension first. `max_ack_delay`
    /// is expressed in microseconds, matching ACK_FREQUENCY.
    pub fn configureAckPolicy(
        self: *Connection,
        ack_eliciting_threshold: u64,
        max_ack_delay: u64,
        reordering_threshold: u64,
    ) void {
        self.ack_eliciting_threshold = ack_eliciting_threshold;
        self.requested_max_ack_delay = max_ack_delay;
        self.ack_reordering_threshold = reordering_threshold;
    }

    pub fn immediateAckRequested(self: Connection) bool {
        return self.immediate_ack_requested;
    }

    fn sendDataBlocked(self: *Connection) Error!void {
        return self.sendDataBlockedAt(null);
    }

    fn sendDataBlockedAt(
        self: *Connection,
        sent_time_ns: ?u64,
    ) Error!void {
        if (!self.send_flow.shouldSendBlocked()) return;
        const frames = [_]quic.Frame{self.send_flow.dataBlockedFrame()};
        if (sent_time_ns) |now_ns|
            try self.sendTrackedFramesEcnAt(&frames, .not_ect, now_ns)
        else
            try self.sendTrackedFrames(&frames);
        self.send_flow.markBlockedSent();
    }

    fn sendStreamDataBlocked(self: *Connection, stream_id: u64) Error!void {
        return self.sendStreamDataBlockedAt(stream_id, null);
    }

    fn sendStreamDataBlockedAt(
        self: *Connection,
        stream_id: u64,
        sent_time_ns: ?u64,
    ) Error!void {
        const entry = try self.sendStreamEntry(stream_id);
        if (!entry.flow.shouldSendBlocked()) return;
        const frames = [_]quic.Frame{entry.flow.streamDataBlockedFrame(stream_id)};
        if (sent_time_ns) |now_ns|
            try self.sendTrackedFramesEcnAt(&frames, .not_ect, now_ns)
        else
            try self.sendTrackedFrames(&frames);
        entry.flow.markBlockedSent();
    }

    fn sendTrackedFrames(self: *Connection, frames: []const quic.Frame) Error!void {
        try self.sendTrackedFramesEcn(frames, .not_ect);
    }

    /// Send internal control frames without allowing pacing sleep to outlive
    /// an application operation's absolute awake-clock deadline. Congestion
    /// remains observable so the caller can pump ACK progress before retrying.
    fn sendTrackedFramesWithDeadline(
        self: *Connection,
        frames: []const quic.Frame,
        deadline: std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
        while (true) {
            const now_ns = self.monotonicNowNs();
            if (callerDeadlineExpired(deadline, now_ns)) return error.Timeout;
            self.sendTrackedFramesEcnAt(
                frames,
                .not_ect,
                now_ns,
            ) catch |err| switch (err) {
                error.PacingLimited => {
                    const pacing_deadline =
                        self.pacing_blocked_until_ns orelse return err;
                    const caller_ns = std.math.cast(
                        u64,
                        deadline.raw.nanoseconds,
                    ) orelse std.math.maxInt(u64);
                    if (pacing_deadline >= caller_ns) return error.Timeout;
                    try self.waitForPacing(now_ns);
                    continue;
                },
                else => |other| return other,
            };
            return;
        }
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
        const validated_traits = try self.validateOutboundFrames(frames);
        try self.sendTrackedFramesEcnAtUncheckedWithTraits(
            frames,
            ecn,
            sent_time_ns,
            validated_traits,
        );
    }

    fn sendTrackedFramesEcnAtUnchecked(self: *Connection, frames: []const quic.Frame, ecn: quic.packet_space.EcnCodepoint, sent_time_ns: ?u64) Error!void {
        return self.sendTrackedFramesEcnAtUncheckedWithTraits(
            frames,
            ecn,
            sent_time_ns,
            null,
        );
    }

    fn sendTrackedFramesEcnAtUncheckedWithTraits(
        self: *Connection,
        frames: []const quic.Frame,
        ecn: quic.packet_space.EcnCodepoint,
        sent_time_ns: ?u64,
        validated_traits: ?frame_traits.Traits,
    ) Error!void {
        try self.validateNextPacketNumber();
        if (frames.len != 0 and
            self.handshake_status.needsHandshakeDone() and
            !frame_traits.containsHandshakeDone(frames))
        {
            var stack: [handshake_done_frame_stack_capacity]quic.Frame =
                undefined;
            const combined = try appendPendingHandshakeDone(
                self.endpoint.allocator,
                &stack,
                frames,
            );
            defer if (combined.ptr != stack[0..].ptr) {
                self.endpoint.allocator.free(combined);
            };
            return self.sendTrackedFramesEcnAtUncheckedRaw(
                combined,
                ecn,
                sent_time_ns,
                null,
            );
        }
        try self.sendTrackedFramesEcnAtUncheckedRaw(
            frames,
            ecn,
            sent_time_ns,
            validated_traits,
        );
    }

    fn sendTrackedFramesEcnAtUncheckedRaw(
        self: *Connection,
        frames: []const quic.Frame,
        ecn: quic.packet_space.EcnCodepoint,
        sent_time_ns: ?u64,
        validated_traits: ?frame_traits.Traits,
    ) Error!void {
        const prepared = try self.prepareFramesForSend(
            frames,
            sent_time_ns,
            validated_traits,
        );
        const qlog_now_ns = sent_time_ns orelse self.monotonicNowNs();
        try self.sendPreparedFramesEcnAtUnchecked(
            prepared,
            ecn,
            sent_time_ns,
            false,
        );
        self.observePacketSent(
            qlog_now_ns,
            self.next_packet_number - 1,
            prepared.packet_len,
            frames,
        );
    }

    const PreparedFrames = struct {
        frames: []const quic.Frame,
        payload_len: usize,
        recovery_payload_len: usize,
        packet_number_len: u8,
        packet_len: usize,
        is_ack_eliciting: bool,
        is_in_flight: bool,
        contains_handshake_done: bool,
        largest_acknowledged_sent: ?u64,
    };

    fn prepareFramesForSend(
        self: *Connection,
        frames: []const quic.Frame,
        sent_time_ns: ?u64,
        validated_traits: ?frame_traits.Traits,
    ) Error!PreparedFrames {
        var payload_len: usize = 0;
        var recovery_payload_len: usize = 0;
        var traits: frame_traits.Traits = validated_traits orelse .{};
        const all_payload_bytes_retransmittable = if (validated_traits) |value|
            value.allPayloadBytesRetransmittable()
        else
            false;
        for (frames) |frame| {
            const frame_len = try frame.wireLen();
            payload_len = std.math.add(
                usize,
                payload_len,
                frame_len,
            ) catch return error.InvalidFrameLength;
            if (!all_payload_bytes_retransmittable) {
                const current = frame_traits.classify(frame);
                if (validated_traits == null) try traits.merge(current);
                if (current.retransmittable) {
                    recovery_payload_len = std.math.add(
                        usize,
                        recovery_payload_len,
                        frame_len,
                    ) catch return error.InvalidFrameLength;
                }
            }
        }
        if (all_payload_bytes_retransmittable) {
            recovery_payload_len = payload_len;
        }
        const packet_number_len = quic.protection.packetNumberLenForPayload(
            self.next_packet_number,
            self.sent.largestAcknowledged(),
            payload_len,
        );
        const packet_len = try quic.protection.shortPacketLenForPayloadLen(
            self.config.peer_connection_id.len,
            self.next_packet_number,
            packet_number_len,
            payload_len,
        );
        if (packet_len > self.currentSendDatagramSize()) return error.DatagramTooLarge;
        if (traits.in_flight) if (sent_time_ns) |now_ns| {
            if (self.pacingDeadlineAt(now_ns, packet_len)) |deadline| {
                self.pacing_blocked_until_ns = deadline;
                return error.PacingLimited;
            }
        };

        return .{
            .frames = frames,
            .payload_len = payload_len,
            .recovery_payload_len = recovery_payload_len,
            .packet_number_len = packet_number_len,
            .packet_len = packet_len,
            .is_ack_eliciting = traits.ack_eliciting,
            .is_in_flight = traits.in_flight,
            .contains_handshake_done = traits.handshake_done,
            .largest_acknowledged_sent = traits.largest_acknowledged,
        };
    }

    fn sendPreparedFramesEcnAtUnchecked(
        self: *Connection,
        prepared: PreparedFrames,
        ecn: quic.packet_space.EcnCodepoint,
        sent_time_ns: ?u64,
        automatic_ecn: bool,
    ) Error!void {
        const packet_number = self.next_packet_number;
        var tracked_congestion = false;
        if (prepared.is_in_flight) {
            try self.congestion.reserve(prepared.payload_len);
            tracked_congestion = true;
        }
        errdefer {
            if (tracked_congestion) {
                self.congestion.discard(prepared.payload_len);
            }
        }
        var tracked_recovery = false;
        // This rollback must live at function scope. Non-HANDSHAKE_DONE sends
        // leave the allocation block before packet protection/socket errors can
        // occur, so a block-local errdefer would leak recovery state.
        errdefer if (tracked_recovery) {
            _ = self.recovery.forgetPacketNumber(packet_number);
        };
        var recovery_payload: ?[]const u8 = null;
        var recovery_group_id: ?u64 = null;
        if (prepared.recovery_payload_len != 0) {
            const tracked = try self.recovery.trackSentUninitialized(
                packet_number,
                prepared.recovery_payload_len,
            );
            tracked_recovery = true;
            var payload_list = std.ArrayList(u8).initBuffer(
                tracked.payload,
            );
            try writeRetransmittableFramesAssumeCapacity(
                &payload_list,
                prepared.frames,
                prepared.recovery_payload_len == prepared.payload_len,
            );
            std.debug.assert(
                payload_list.items.len == prepared.recovery_payload_len,
            );
            recovery_payload = tracked.payload;
            recovery_group_id = tracked.group_id;
        }
        if (recovery_payload == null or
            prepared.recovery_payload_len != prepared.payload_len)
        {
            std.debug.assert(self.send_frame_buffer.items.len == 0);
            errdefer self.send_frame_buffer.items.len = 0;
            try self.send_frame_buffer.ensureUnusedCapacity(
                self.endpoint.allocator,
                prepared.payload_len,
            );
            for (prepared.frames) |frame| {
                try frame.writeAssumeCapacity(&self.send_frame_buffer);
            }
            std.debug.assert(
                self.send_frame_buffer.items.len == prepared.payload_len,
            );
        }
        defer self.send_frame_buffer.items.len = 0;
        const payload = if (recovery_payload != null and
            prepared.recovery_payload_len == prepared.payload_len)
            recovery_payload.?
        else
            self.send_frame_buffer.items;

        try self.sent.sentInFlightAtWithExactDatagramMetadataAndPathEpoch(
            packet_number,
            prepared.is_ack_eliciting,
            prepared.is_in_flight,
            prepared.payload_len,
            try quic.protection.shortPacketLen(.{
                .destination_connection_id = self.config.peer_connection_id,
                .packet_number = packet_number,
                .packet_number_len = prepared.packet_number_len,
                .fixed_bit = true,
                .spin_bit = false,
                .key_phase = self.send_key_phase.currentKeyPhase(),
                .payload = payload,
            }),
            ecn,
            sent_time_ns,
            null,
            self.pmtu_path_epoch,
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
            automatic_ecn,
        );
        if (prepared.contains_handshake_done) {
            self.handshake_status.onHandshakeDoneTracked(
                recovery_group_id orelse unreachable,
            );
        }
        tracked_sent = false;
        tracked_recovery = false;
        self.next_packet_number += 1;
    }

    fn validateOutboundFrames(
        self: Connection,
        frames: []const quic.Frame,
    ) Error!frame_traits.Traits {
        if (frames.len == 0) return error.MissingFrame;
        var combined: frame_traits.Traits = .{};
        for (frames) |frame| {
            var traits: OutboundFrameTraits = .{};
            try self.validateOutboundFrameAndTraits(frame, &traits);
            try combined.merge(traits);
        }
        return combined;
    }

    fn validateOutboundFrameAndTraits(self: Connection, frame: quic.Frame, traits: *OutboundFrameTraits) Error!void {
        try quic.validateFrameForPacketType(frame, .one_rtt);
        try traits.observe(frame);
        switch (frame) {
            .padding, .ack, .connection_close, .application_close => {},
            .new_token => |new_token| {
                // RFC 9000 server-only frames should be blocked before the
                // packet is encoded.  s2n-quic/tquic gate HANDSHAKE_DONE and
                // NEW_TOKEN at transmission time; doing so here keeps generic
                // send() from bypassing the dedicated helpers.
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
            .ack_frequency => |ack_frequency| {
                if (!self.ackFrequencySendEnabled()) {
                    return error.AckFrequencyDisabled;
                }
                try validateRequestedMaxAckDelay(
                    ack_frequency.request_max_ack_delay,
                    self.config.peer_min_ack_delay,
                );
            },
            .immediate_ack => if (!self.ackFrequencySendEnabled()) {
                return error.AckFrequencyDisabled;
            },
            else => {},
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

    fn applyCurrentPmtuToPath(self: *Connection) void {
        const datagram_size = self.currentSendDatagramSize();
        self.congestion.onMtuUpdate(datagram_size);
        self.pacer.onMtuUpdate(datagram_size);
    }

    fn pmtuProbeEpochBump(self: *Connection) void {
        self.pmtu_probe_epoch +%= 1;
        if (self.pmtu_probe_epoch == 0) self.pmtu_probe_epoch = 1;
    }

    fn pmtuPathEpochBump(self: *Connection) void {
        self.pmtu_path_epoch = nextPathEpoch(self.pmtu_path_epoch);
    }

    fn resetRecoveryForPath(
        self: *Connection,
        preserve_rtt: bool,
    ) void {
        self.resetSpinBit();
        self.resetEcnForPath();
        if (!preserve_rtt) {
            self.rtt_stats = .init(std.math.mul(
                u64,
                self.config.peer_max_ack_delay_ms,
                1_000_000,
            ) catch quic.rtt.default_max_ack_delay_ns);
        }
        self.pmtud.resetForPath();
        self.pmtuProbeEpochBump();
        self.pmtuPathEpochBump();
        self.congestion = .initWithOptions(
            self.currentSendDatagramSize(),
            self.config.congestion_algorithm,
            self.config.enable_hystart,
        );
        self.applyCurrentPmtuToPath();
        self.pacer.reset();
        self.pacing_blocked_until_ns = null;
        self.pto_count = 0;
        self.pto_jitter_state.rearm();
        self.last_persistent_congestion_packet_number = null;
    }

    fn reportAckedPmtuEvidence(
        self: *Connection,
        acked: quic.packet_space.SentPacketTracker.AckResult,
    ) void {
        const packet_number = acked.largest_pmtu_acked_packet_number orelse
            return;
        const datagram_size = acked.largest_pmtu_acked_datagram_size orelse
            return;
        self.pmtud.onMtuSizedPacketAcked(packet_number, datagram_size);
    }

    fn autoEcnForFrames(
        self: Connection,
        frames: []const quic.Frame,
    ) quic.packet_space.EcnCodepoint {
        if (!(frame_traits.analyze(frames) catch return .not_ect)
            .autoEcnEligible()) return .not_ect;
        if (!self.ecn_path.mayMarkEct0()) return .not_ect;
        return .ect0;
    }

    fn resetEcnForPath(self: *Connection) void {
        self.ecn_path_baseline_pending =
            self.sent.hasUnacknowledgedEct() or
            self.sent.hasAcknowledgedEctBeyondEcnWatermark();
        self.ecn_path.resetForPath();
    }

    fn reportLostPmtuEvidence(self: *Connection, generation: u32, now_ns: ?u64) void {
        const now = now_ns orelse return;
        if (generation == 0) return;
        var previous_packet_number: ?u64 = null;
        for (self.sent.packets.items) |packet| {
            if (packet.lost_generation != generation) continue;
            // Losses from the retired path must neither count nor bridge a
            // burst on the current path after migration.
            if (packet.pmtu_path_epoch != self.pmtu_path_epoch) continue;
            const new_loss_burst = if (previous_packet_number) |previous|
                previous +| 1 != packet.packet_number
            else
                true;
            previous_packet_number = packet.packet_number;
            const result = self.pmtud.onPacketLost(
                packet.packet_number,
                packet.datagram_size,
                packet.pmtu_probe_size != null,
                new_loss_burst,
                now,
            );
            if (result.mtu_dropped) {
                self.applyCurrentPmtuToPath();
                self.pacer.reset();
            }
        }
    }

    pub fn pmtuProbeDeadline(self: *const Connection) ?u64 {
        return self.pmtud.probeDeadlineNs();
    }

    pub fn servicePmtuTimerAt(self: *Connection, now_ns: u64) bool {
        if (!self.pmtud.serviceRaiseTimer(now_ns, self.config.max_datagram_size)) return false;
        self.applyCurrentPmtuToPath();
        return true;
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

        // `init` reserves at least one path-sized plaintext payload. Reuse it
        // for PMTU probes instead of allocating and zero-filling a temporary
        // ArrayList for every binary-search step. QUIC PING and PADDING are
        // each one-byte frame types, so their encoded payload is canonical.
        std.debug.assert(self.send_frame_buffer.items.len == 0);
        defer self.send_frame_buffer.items.len = 0;
        try self.send_frame_buffer.ensureUnusedCapacity(
            self.endpoint.allocator,
            target_payload_len,
        );
        self.send_frame_buffer.items.len = target_payload_len;
        @memset(self.send_frame_buffer.items, 0);
        self.send_frame_buffer.items[0] = @intFromEnum(quic.FrameType.ping);
        const payload = self.send_frame_buffer.items;

        try self.congestion.reserve(payload.len);
        errdefer self.congestion.discard(payload.len);
        try self.sent.sentInFlightAtWithPmtuAndDatagramSizeAndEpochAndPathEpoch(
            packet_number,
            true,
            true,
            payload.len,
            probe_size,
            .not_ect,
            sent_time_ns,
            probe_size,
            self.pmtu_probe_epoch,
            self.pmtu_path_epoch,
        );
        errdefer _ = self.sent.forget(packet_number);
        // PING/PADDING probes carry no application data that needs recovery.
        // The sent-packet tracker retains their identity for ACK/loss and
        // bytes-in-flight accounting. Never enqueue them in generic recovery:
        // a PTO retransmission would strip probe identity and could not validate
        // the larger path size even if its copy were acknowledged.
        try self.sendPayloadPacketWithPacketNumberLenAt(
            packet_number,
            payload,
            packet_number_len,
            .not_ect,
            sent_time_ns,
            true,
            true,
            false,
        );
        self.next_packet_number += 1;
        self.pmtud.onProbeSentWithIdentity(
            packet_number,
            self.pmtu_probe_epoch,
            probe_size,
        );
        self.applyCurrentPmtuToPath();
        return probe_size;
    }

    pub fn peerAddressValidated(self: Connection) bool {
        return self.peer_address_validated;
    }

    /// Return the currently selected peer UDP path. Authenticated probing-only
    /// packets are answered on their source path without changing this value;
    /// authenticated non-probing traffic commits a NAT rebinding or migration.
    pub fn peerAddress(self: Connection) net.IpAddress {
        return self.config.peer;
    }

    pub fn setPeerAddressValidated(self: *Connection, validated: bool) void {
        self.peer_address_validated = validated;
        if (validated) {
            self.peer_preferred_address_migration_active = false;
            self.peer_address_bytes_received = 0;
            self.peer_address_bytes_sent = 0;
            self.path_validation_retry_deadline_ns = null;
            self.last_validated_peer_path = .init(
                self.config.peer,
                self.config.peer_connection_id,
                self.spin_bit_value,
                self.spin_largest_received_packet_number,
            );
        }
    }

    fn rememberCurrentValidatedPeerPath(self: *Connection) void {
        if (!self.peer_address_validated) return;
        self.last_validated_peer_path = .init(
            self.config.peer,
            self.config.peer_connection_id,
            self.spin_bit_value,
            self.spin_largest_received_packet_number,
        );
    }

    /// Apply role-specific source-address policy before authentication. Clients
    /// accept only their selected server tuple plus the retained validated tuple
    /// during preferred-address migration. Servers that advertised
    /// disable_active_migration discard a new client IP while still allowing a
    /// source-port NAT rebinding. These drops precede packet-number
    /// reconstruction, reset-token comparison, and frame parsing.
    fn shouldDiscardPeerAddressBeforeAuthentication(
        self: *const Connection,
        from: net.IpAddress,
    ) bool {
        if (self.config.local_endpoint == .server) {
            // RFC 9000 section 9 allows an endpoint that advertised
            // disable_active_migration to drop traffic from a new peer IP.
            // A source-port change can be NAT rebinding and remains eligible
            // for authentication and the normal rebinding path below.
            return self.config.local_disable_active_migration and
                !peerAddressSameIp(self.config.peer, from);
        }
        if (self.config.peer.eql(&from)) return false;
        return !self.peer_preferred_address_migration_active or
            !self.last_validated_peer_path.peer.eql(&from);
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
        // RFC 9000 section 8.1 limits only servers before address
        // validation. A client probing a preferred address or initiating
        // migration must be able to send PATH_CHALLENGE before receiving any
        // bytes on that path.
        if (!self.isAntiAmplificationLimited()) return null;
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
        if (!self.isAntiAmplificationLimited()) return;
        self.peer_address_bytes_sent -|= bytes;
    }

    fn isAntiAmplificationLimited(self: Connection) bool {
        return self.config.local_endpoint == .server and
            !self.peer_address_validated;
    }

    fn findCandidatePathBudget(
        self: *const Connection,
        peer: net.IpAddress,
    ) ?usize {
        for (self.candidate_path_budgets, 0..) |entry, index| {
            const budget = entry orelse continue;
            if (budget.peer.eql(&peer)) return index;
        }
        return null;
    }

    fn candidatePathBudgetReferenced(
        self: *const Connection,
        peer: net.IpAddress,
    ) bool {
        for (self.path_response_targets.items[self.path_response_target_head..]) |target| {
            const candidate = target orelse continue;
            if (candidate.eql(&peer)) return true;
        }
        return false;
    }

    fn prepareCandidatePathBudget(
        self: *Connection,
        peer: net.IpAddress,
    ) Error!usize {
        if (self.findCandidatePathBudget(peer)) |index| return index;
        for (self.candidate_path_budgets, 0..) |entry, index| {
            if (entry == null) return index;
        }
        for (0..self.candidate_path_budgets.len) |offset| {
            const index = (self.candidate_path_eviction_cursor + offset) %
                self.candidate_path_budgets.len;
            const existing = self.candidate_path_budgets[index].?;
            if (self.candidatePathBudgetReferenced(existing.peer)) continue;
            self.candidate_path_eviction_cursor =
                (index + 1) % self.candidate_path_budgets.len;
            return index;
        }
        return error.PathValidationLimit;
    }

    fn recordCandidatePathBytesReceived(
        self: *Connection,
        index: usize,
        peer: net.IpAddress,
        bytes: usize,
    ) void {
        if (self.config.local_endpoint != .server) return;
        const slot = &self.candidate_path_budgets[index];
        if (slot.* == null or !slot.*.?.peer.eql(&peer)) {
            slot.* = .{ .peer = peer };
        }
        slot.*.?.bytes_received = std.math.add(
            usize,
            slot.*.?.bytes_received,
            bytes,
        ) catch std.math.maxInt(usize);
    }

    fn takeCandidatePathBudget(
        self: *Connection,
        peer: net.IpAddress,
    ) ?CandidatePathBudget {
        const index = self.findCandidatePathBudget(peer) orelse return null;
        const budget = self.candidate_path_budgets[index].?;
        self.candidate_path_budgets[index] = null;
        return budget;
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
            false,
        );
    }

    fn sealCurrentShortPacketInto(
        self: *const Connection,
        packet: []u8,
        options: quic.protection.ShortPacketOptions,
    ) Error![]u8 {
        if (comptime quic.protection.prepared_packet_protection_enabled) {
            if (self.prepared_send_keys) |prepared| {
                return quic.protection.sealShortPacketIntoPrepared(
                    packet,
                    prepared,
                    options,
                );
            }
        }
        return quic.protection.sealShortPacketInto(
            packet,
            self.send_key_phase.currentKeys(),
            options,
        );
    }

    fn sealCurrentShortPacketInPlace(
        self: *const Connection,
        packet: []u8,
        options: quic.protection.ShortPacketOptions,
    ) Error![]u8 {
        if (comptime quic.protection.prepared_packet_protection_enabled) {
            if (self.prepared_send_keys) |prepared| {
                return quic.protection.sealShortPacketInPlacePrepared(
                    packet,
                    prepared,
                    options,
                );
            }
        }
        return quic.protection.sealShortPacketInPlace(
            packet,
            self.send_key_phase.currentKeys(),
            options,
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
        automatic_ecn: bool,
    ) Error!void {
        const sizing_options: quic.protection.ShortPacketOptions = .{
            .destination_connection_id = self.config.peer_connection_id,
            .packet_number = packet_number,
            .packet_number_len = packet_number_len,
            // Header-bit values do not affect packet length. Keep sizing
            // mutation-free; the fixed-bit generator advances only when the
            // packet has passed pacing preflight and will actually be sealed.
            .fixed_bit = true,
            .spin_bit = false,
            .key_phase = self.send_key_phase.currentKeyPhase(),
            .payload = payload,
        };
        const packet_len = try quic.protection.shortPacketLen(sizing_options);
        const now_ns = sent_time_ns orelse self.monotonicNowNs();
        if (pace_packet) {
            if (self.pacer.deadlineAt(
                now_ns,
                packet_len,
                self.congestion.congestion_window,
                self.rtt_stats.smoothedOrInitial(),
            )) |deadline| {
                self.pacing_blocked_until_ns = deadline;
                return error.PacingLimited;
            }
        }

        // Pacing is a retryable preflight result. Check it before key updates
        // or AEAD sealing so a deferred retransmission cannot consume a nonce
        // and then retry the same packet number. Recovery/congestion callers
        // can safely roll back their metadata without hidden crypto state.
        try self.prepareAeadForEncryption(packet_number, sent_time_ns);
        try self.reserveAntiAmplification(packet_len);
        errdefer self.releaseAntiAmplification(packet_len);
        const packet_options: quic.protection.ShortPacketOptions = .{
            .destination_connection_id = self.config.peer_connection_id,
            .packet_number = packet_number,
            .packet_number_len = packet_number_len,
            .fixed_bit = self.nextFixedBit(),
            .spin_bit = self.nextSpinBit(),
            .key_phase = self.send_key_phase.currentKeyPhase(),
            .payload = payload,
        };
        try self.send_packet_buffer.ensureTotalCapacity(self.endpoint.allocator, packet_len);
        self.send_packet_buffer.items.len = self.send_packet_buffer.capacity;
        defer self.send_packet_buffer.items.len = 0;
        const packet = try self.sealCurrentShortPacketInto(
            self.send_packet_buffer.items,
            packet_options,
        );
        self.recordPacketEncrypted();
        // AEAD sealing consumes the (key phase, packet number) nonce even when
        // the UDP socket subsequently accepts no datagram. Callers roll back
        // recovery, congestion, flow credit, and sent-map state on that error,
        // but the packet number itself must never be reused for new plaintext.
        errdefer self.next_packet_number = packet_number + 1;
        self.endpoint.sendBytesWithEcn(self.config.peer, packet, ecn) catch |err| switch (err) {
            error.EcnUnavailable => if (automatic_ecn and
                self.handleAutomaticEcnUnavailable(ecn))
            blk: {
                std.debug.assert(
                    self.sent.rewritePacketEcn(packet_number, .not_ect),
                );
                break :blk try self.endpoint.sendBytesWithEcn(
                    self.config.peer,
                    packet,
                    .not_ect,
                );
            } else return err,
            else => return err,
        };
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
        if (self.prepared_send_keys) |prepared| {
            prepared.replace(self.send_key_phase.currentKeys());
        }
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

    /// Resolve a failed 1-RTT authentication attempt as either a stateless
    /// reset or an ordinary AEAD integrity failure.
    ///
    /// RFC 9000 section 10.3 permits reset-token comparison only after packet
    /// processing fails. In-place receive paths therefore copy the trailing
    /// candidate before decryption, but call this helper only from an
    /// `AuthenticationFailed` catch. A matching reset does not consume the
    /// peer's AEAD integrity budget and moves directly to draining for three
    /// current application-data PTOs.
    fn handleAuthenticationFailureAt(
        self: *Connection,
        reset_candidate: ?[quic.stateless_reset.token_len]u8,
        now_ns: ?u64,
    ) Error {
        if (reset_candidate) |candidate| {
            if (self.peer_connection_ids.detectStatelessResetToken(candidate) != null) {
                const event_now_ns = now_ns orelse self.monotonicNowNs();
                self.enterStatelessResetDraining(
                    nanosToMillisFloor(event_now_ns),
                    nanosToMillisCeil(self.rtt_stats.pto(true)),
                ) catch |err| return err;
                return error.ConnectionClosed;
            }
        }
        self.recordAuthenticationFailureAt(now_ns) catch |err| return err;
        return error.AuthenticationFailed;
    }

    fn handlePacketProtectionErrorAt(
        self: *Connection,
        protection_error: quic.protection.Error,
        reset_candidate: ?[quic.stateless_reset.token_len]u8,
        now_ns: ?u64,
    ) Error {
        if (protection_error == error.AuthenticationFailed) {
            return self.handleAuthenticationFailureAt(
                reset_candidate,
                now_ns,
            );
        }
        if (protection_error == error.InvalidReservedBits) {
            self.closeTransportAt(
                @intFromEnum(quic.TransportErrorCode.protocol_violation),
                0,
                "reserved bits",
                nsToMs(now_ns),
                null,
            ) catch |err| return err;
        }
        return protection_error;
    }

    fn enterAeadLimitReached(
        self: *Connection,
        reason_phrase: []const u8,
        now_ms: ?u64,
        send_close: bool,
    ) Error!void {
        const code = @intFromEnum(quic.TransportErrorCode.aead_limit_reached);
        if (send_close) {
            // Integrity exhaustion counts failed decryptions and does not
            // consume outgoing confidentiality budget, so RFC 9001 permits a
            // final protected CONNECTION_CLOSE. Socket/allocation failure must
            // not prevent the mandatory local terminal transition.
            self.closeLocally(.{
                .application = false,
                .error_code = code,
                .frame_type = 0,
                .reason_phrase = reason_phrase,
                .now_ms = now_ms,
            }) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => return,
            };
            return;
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
        if (self.recovery.pendingCount() == 0) {
            if (self.sent
                .latestNonProbeAckElicitingInFlightSentTimeForPathEpoch(
                self.pmtu_path_epoch,
            ) == null) {
                return 0;
            }
            try self.sendPtoPingAt(now_ns);
            self.incrementPtoCount();
            return 1;
        }
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

    /// Probe an outstanding flight whose original packet carried no
    /// retransmittable bytes (for example a pure RFC 9221 DATAGRAM). The fresh
    /// PING establishes normal recovery ownership without replaying the
    /// unreliable application payload.
    fn sendPtoPingAt(self: *Connection, sent_time_ns: ?u64) Error!void {
        try self.validateNextPacketNumber();
        const packet_number = self.next_packet_number;
        const payload = [_]u8{@intFromEnum(quic.FrameType.ping)};
        const packet_number_len = quic.protection.packetNumberLenForPayload(
            packet_number,
            self.sent.largestAcknowledged(),
            payload.len,
        );
        const packet_len = try quic.protection.shortPacketLen(.{
            .destination_connection_id = self.config.peer_connection_id,
            .packet_number = packet_number,
            .packet_number_len = packet_number_len,
            .payload = &payload,
        });
        if (packet_len > self.currentSendDatagramSize() or
            packet_len > self.endpoint.limits.max_datagram_size)
        {
            return error.DatagramTooLarge;
        }

        self.congestion.onPtoProbeSent(payload.len);
        errdefer self.congestion.discard(payload.len);
        _ = try self.recovery.trackSent(packet_number, &payload);
        errdefer _ = self.recovery.forgetPacketNumber(packet_number);
        try self.sent.sentAtWithDatagramSizeAndPathEpoch(
            packet_number,
            true,
            payload.len,
            packet_len,
            .not_ect,
            sent_time_ns,
            self.pmtu_path_epoch,
        );
        errdefer _ = self.sent.forget(packet_number);
        try self.sendPayloadPacketAt(
            packet_number,
            &payload,
            sent_time_ns,
            true,
        );
        self.next_packet_number += 1;
    }

    pub fn retransmitPacketThresholdLoss(self: *Connection) Error!bool {
        return self.retransmitSinglePacketThresholdLoss();
    }

    /// Retransmit multiple payload groups already declared lost by ACK-driven
    /// packet-threshold detection.
    ///
    /// `applyReceivedFrames` marks all eligible sent packets lost in one pass,
    /// so event loops should drain more than one recovery candidate before
    /// waiting for PTO. Stopping cleanly when the reduced congestion window is
    /// full or pacing defers the next packet lets a later ACK/timer resume the
    /// same queue without turning ordinary loss recovery into an
    /// application-visible send failure.
    pub fn retransmitPacketThresholdLosses(
        self: *Connection,
        max_retransmissions: usize,
    ) Error!usize {
        var retransmitted: usize = 0;
        while (retransmitted < max_retransmissions) {
            const largest = self.sent.largestAcknowledged() orelse break;
            const candidate = self.recovery.packetThresholdCandidate(
                largest,
                quic.packet_space.default_packet_threshold,
            ) orelse break;
            self.retransmitCandidate(
                candidate,
                .congestion_controlled,
            ) catch |err| switch (err) {
                error.CongestionLimited, error.PacingLimited => break,
                else => return err,
            };
            retransmitted += 1;
        }
        return retransmitted;
    }

    fn retransmitSinglePacketThresholdLoss(
        self: *Connection,
    ) Error!bool {
        const largest = self.sent.largestAcknowledged() orelse return false;
        const candidate = self.recovery.packetThresholdCandidate(largest, quic.packet_space.default_packet_threshold) orelse return false;
        try self.retransmitCandidate(candidate, .congestion_controlled);
        return true;
    }

    pub fn retransmitTimeThresholdLoss(self: *Connection, now_ns: u64, loss_delay_ns: u64) Error!bool {
        const pto_anchor_before =
            self.sent.latestAckElicitingInFlightSentTimeForPathEpoch(
                self.pmtu_path_epoch,
            );
        const largest = self.sent.largestAcknowledged();
        if (largest == null and self.pmtud.active_probe_packet_number == null) {
            return false;
        }
        const lost = self.sent.detectTimeThresholdLossForProbeAndPathEpoch(
            now_ns,
            loss_delay_ns,
            largest,
            self.pmtud.active_probe_packet_number,
            self.pmtud.active_probe_epoch,
            self.pmtu_path_epoch,
        );
        if (lost.bytes > 0 or lost.probe_bytes > 0) {
            const loss_generation = self.sent.currentLossGeneration();
            self.recordPacketsLost(lost.packets);
            self.observeLostPackets(now_ns, "time_threshold");
            self.congestion.onLostAt(
                lost.current_path_bytes,
                lost.current_path_largest_nonprobe_sent_time_ns,
                now_ns,
            );
            self.congestion.discard(lost.current_path_probe_bytes);
            if (lost.active_pmtu_probe_packet_number) |packet_number| {
                self.pmtud.onProbeLostWithIdentity(
                    packet_number,
                    lost.active_pmtu_probe_epoch,
                    lost.active_pmtu_probe_size.?,
                    self.config.max_datagram_size,
                    now_ns,
                );
            }
            self.reportLostPmtuEvidence(loss_generation, now_ns);
            self.applyCurrentPmtuToPath();
            if (lost.current_path_bytes > 0) {
                _ = self.applyPersistentCongestionIfDetected();
            }
        }
        if (self.sent.latestAckElicitingInFlightSentTimeForPathEpoch(
            self.pmtu_path_epoch,
        ) !=
            pto_anchor_before)
        {
            // Loss state is committed before retransmission. Rearm here so a
            // later DatagramTooLarge/pacing/socket error cannot leave the new
            // PTO anchor using the prior epoch. A successful retransmission
            // then advances once more for the newly sent packet's own arm.
            self.pto_jitter_state.rearm();
        }
        var retransmitted = false;
        const scan_count = self.sent.packets.items.len;
        var packet_index: usize = 0;
        while (packet_index < scan_count) : (packet_index += 1) {
            // retransmitCandidate appends a SentPacket and may reallocate the
            // backing list. Copy this record before the mutation rather than
            // retaining a `for` iterator into potentially invalid storage.
            const packet = self.sent.packets.items[packet_index];
            if (!packet.lost) continue;
            const candidate = self.recovery.packetNumberCandidate(packet.packet_number) orelse continue;
            if (candidate.packet_number != packet.packet_number) continue;
            try self.retransmitCandidate(candidate, .congestion_controlled);
            retransmitted = true;
        }
        return retransmitted;
    }

    pub fn timeThresholdLossDeadline(self: *const Connection, loss_delay_ns: u64) ?u64 {
        // Ordinary QUIC loss requires a later ACK. A DPLPMTUD probe has no
        // retransmittable application data, but a lone probe still needs a
        // time-threshold deadline so its search state can be retried.
        const largest = self.sent.largestAcknowledged();
        if (largest == null and self.pmtud.active_probe_packet_number == null) {
            return null;
        }
        return self.sent.timeThresholdLossDeadlineForProbeAndPathEpoch(
            loss_delay_ns,
            largest,
            self.pmtud.active_probe_packet_number,
            self.pmtud.active_probe_epoch,
            self.pmtu_path_epoch,
        );
    }

    pub fn ptoBackoffCount(self: Connection) u8 {
        return self.pto_count;
    }

    /// Whether this connection randomizes its established 1-RTT PTO.
    pub fn ptoJitterEnabled(self: Connection) bool {
        return self.pto_jitter_state.enabled();
    }

    pub fn ptoJitterEpoch(self: Connection) u64 {
        return self.pto_jitter_state.currentEpoch();
    }

    /// Whether this connection preserves the contiguous prefix buffered when
    /// RESET_STREAM arrives for application delivery before its reset event.
    pub fn resetPartialDeliveryEnabled(self: Connection) bool {
        return self.config.enable_reset_partial_delivery;
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

    /// Effective PTO recovery period for the currently armed epoch. Repeated
    /// scheduler reads cannot move an already published deadline.
    pub fn jitteredPtoPeriod(self: *const Connection) u64 {
        return self.pto_jitter_state.period(
            self.rtt_stats.pto(true),
            self.pto_count,
            quic.rtt.timer_granularity_ns,
            quic.rtt.max_pto_ns,
        );
    }

    pub fn ptoDeadline(self: *const Connection) ?u64 {
        if (self.close_info != null or self.idle_timed_out) return null;
        const sent_time = if (self.recovery.pendingCount() != 0)
            self.sent.latestAckElicitingInFlightSentTimeForPathEpoch(
                self.pmtu_path_epoch,
            )
        else
            self.sent.latestNonProbeAckElicitingInFlightSentTimeForPathEpoch(
                self.pmtu_path_epoch,
            );
        const anchor = sent_time orelse {
            // Recovery owns stable payload groups until any copy is ACKed. A
            // packet can be declared lost, removing it from the in-flight PTO
            // base, while its recovery group still needs retransmission. Do not
            // leave such orphaned groups timerless; arm an immediate PTO so the
            // blocking/runtime pump can emit a fresh probe and re-establish a
            // normal in-flight deadline.
            return if (self.recovery.pendingCount() != 0) 0 else null;
        };
        return std.math.add(u64, anchor, self.jitteredPtoPeriod()) catch
            std.math.maxInt(u64);
    }

    pub fn lossDetectionTimerDeadline(self: *const Connection) ?LossDetectionTimerDeadline {
        if (self.close_info != null or self.idle_timed_out) return null;
        const has_recoverable_data = self.recovery.pendingCount() != 0;
        const has_ack_eliciting_in_flight = self.sent
            .latestNonProbeAckElicitingInFlightSentTimeForPathEpoch(
            self.pmtu_path_epoch,
        ) != null;
        const has_active_pmtu_probe = self.pmtud.active_probe_packet_number != null;
        if (!has_recoverable_data and !has_ack_eliciting_in_flight and
            !has_active_pmtu_probe) return null;

        const loss_time = self.timeThresholdLossDeadline(
            self.rtt_stats.lossDelay(),
        );
        // PMTU probes are intentionally absent from generic recovery, so only
        // arm PTO when there is retransmittable data. A lone probe is retired
        // by its time-threshold deadline and then re-armed by PMTU state.
        const pto_time = if (has_recoverable_data or
            has_ack_eliciting_in_flight) self.ptoDeadline() else null;
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
        /// Every sealed probe consumes its AEAD nonce, including a socket-
        /// rejected suffix after a partial batch submission.
        protected_count: usize,
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
                const reserved = std.math.add(usize, total_packet_len, packet_len) catch return error.AntiAmplificationLimited;
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
        if (count == 0) return .{
            .sent_count = 0,
            .protected_count = 0,
        };

        try self.reserveAntiAmplification(total_packet_len);
        errdefer self.releaseAntiAmplification(total_packet_len);

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
            try self.sent.sentAtWithDatagramSizeAndPathEpoch(
                probe.packet_number,
                true,
                probe.candidate.payload.len,
                probe.packet_len,
                .not_ect,
                sent_time_ns,
                self.pmtu_path_epoch,
            );
            tracked_sent_count += 1;
        }

        try self.send_packet_buffer.ensureTotalCapacity(self.endpoint.allocator, total_packet_len);
        self.send_packet_buffer.items.len = self.send_packet_buffer.capacity;
        defer self.send_packet_buffer.items.len = 0;

        var datagrams: [max_batch_packets][]const u8 = undefined;
        var packet_offset: usize = 0;
        var protected_count: usize = 0;
        errdefer if (protected_count != 0) {
            self.next_packet_number += protected_count;
        };
        for (probes[0..count], 0..) |probe, i| {
            try self.prepareAeadForEncryption(
                probe.packet_number,
                sent_time_ns,
            );
            const packet = try self.sealCurrentShortPacketInto(
                self.send_packet_buffer.items[packet_offset..][0..probe.packet_len],
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
            protected_count += 1;
            datagrams[i] = packet;
            std.debug.assert(packet.len == probe.packet_len);
            packet_offset += packet.len;
        }

        const send_result = try self.endpoint.sendManyBytesProgress(self.config.peer, datagrams[0..count]);
        std.debug.assert(send_result.sent_count <= count);

        // All recovery and congestion entries are reserved before the socket
        // call so no allocation can fail after packets are visible on the
        // network. If only a prefix was accepted, retain exactly that prefix
        // and transactionally discard the unsent suffix. Protection has still
        // consumed every nonce, so packet-number progress follows the complete
        // sealed batch rather than only the socket-visible prefix.
        var sent_payload_len: usize = 0;
        var sent_packet_len: usize = 0;
        for (probes[0..send_result.sent_count]) |probe| {
            self.noteOneRttPacketSent(
                probe.packet_number,
                probe.packet_len,
                now_ns,
                true,
            );
            sent_payload_len += probe.candidate.payload.len;
            sent_packet_len += probe.packet_len;
            self.pacer.onPacketSentAt(
                now_ns,
                probe.packet_len,
                self.congestion.congestion_window,
                self.rtt_stats.smoothedOrInitial(),
            );
            self.congestion.onPacketSent(probe.packet_number);
        }
        const unsent_payload_len = total_payload_len - sent_payload_len;
        self.releaseAntiAmplification(total_packet_len - sent_packet_len);
        self.congestion.discard(unsent_payload_len);
        for (probes[send_result.sent_count..count]) |probe| {
            _ = self.recovery.forgetPacketNumber(probe.packet_number);
            _ = self.sent.forget(probe.packet_number);
        }
        self.pacing_blocked_until_ns = paced_blocked_until_ns;
        self.next_packet_number += protected_count;
        protected_count = 0;
        return .{
            .sent_count = send_result.sent_count,
            .protected_count = count,
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
        try self.sent.sentAtWithDatagramSizeAndPathEpoch(
            packet_number,
            true,
            candidate.payload.len,
            packet_len,
            .not_ect,
            sent_time_ns,
            self.pmtu_path_epoch,
        );
        errdefer _ = self.sent.forget(packet_number);
        try self.sendPayloadPacketAt(packet_number, candidate.payload, sent_time_ns, true);
        self.next_packet_number += 1;
    }

    fn incrementPtoCount(self: *Connection) void {
        if (self.pto_count != std.math.maxInt(u8)) self.pto_count += 1;
    }

    pub fn markPacketAcknowledged(self: *Connection, packet_number: u64) bool {
        const pto_anchor_before =
            self.sent.latestAckElicitingInFlightSentTimeForPathEpoch(
                self.pmtu_path_epoch,
            );
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
        if (self.sent.latestAckElicitingInFlightSentTimeForPathEpoch(
            self.pmtu_path_epoch,
        ) !=
            pto_anchor_before)
        {
            self.pto_jitter_state.rearm();
        }
        self.reclaimRequestedLocalStreamsAfterAck();
        return marked_sent or removed_recovery;
    }

    pub fn pendingRecoveryCount(self: Connection) usize {
        return self.recovery.pendingCount();
    }

    /// Whether recovery still protects application/control delivery rather
    /// than only idempotent receive-credit advertisements.
    pub fn pendingDeliveryRecovery(self: Connection) bool {
        return self.recovery.hasPendingDeliveryFrames();
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

    /// Send application frames together with the cumulative ACK currently
    /// pending for received packets.
    ///
    /// Echo/RPC-style protocols naturally produce a response immediately after
    /// reading a request. Combining the ACK with that response avoids an extra
    /// protected UDP datagram and syscall while preserving the ordinary ACK
    /// range, recovery, congestion, and delayed-ACK bookkeeping. If sending
    /// fails, `ackDelaySent` is not called and the ACK remains pending.
    pub fn sendWithPendingAck(
        self: *Connection,
        frames: []const quic.Frame,
        ack_delay: u64,
    ) Error!void {
        if (frames.len == 0) return self.sendAck(ack_delay);
        var stack_ranges: [
            quic.packet_space.ReceivedPacketTracker.stack_ack_range_capacity
        ]quic.AckRange = undefined;
        var heap_ranges: ?[]quic.AckRange = null;
        defer if (heap_ranges) |ranges| self.endpoint.allocator.free(ranges);
        const ack = try self.ackFrameForSend(
            ack_delay,
            &stack_ranges,
            &heap_ranges,
        );
        var stack_frames: [pending_ack_frame_stack_capacity]quic.Frame =
            undefined;
        const combined = try appendPendingAck(
            self.endpoint.allocator,
            &stack_frames,
            frames,
            ack,
        );
        defer if (combined.ptr != stack_frames[0..].ptr) {
            self.endpoint.allocator.free(combined);
        };
        try self.send(combined);
        self.ackDelaySent();
    }

    /// One-attempt counterpart to `sendWithPendingAck` for endpoint-owned
    /// packetizers. Pacing leaves the cumulative ACK pending so the exact
    /// application frames can be retried after the next transport wake-up.
    pub fn trySendWithPendingAck(
        self: *Connection,
        frames: []const quic.Frame,
        ack_delay: u64,
    ) Error!void {
        var stack_ranges: [
            quic.packet_space.ReceivedPacketTracker.stack_ack_range_capacity
        ]quic.AckRange = undefined;
        var heap_ranges: ?[]quic.AckRange = null;
        defer if (heap_ranges) |ranges| self.endpoint.allocator.free(ranges);
        const ack = try self.ackFrameForSend(
            ack_delay,
            &stack_ranges,
            &heap_ranges,
        );
        var stack_frames: [pending_ack_frame_stack_capacity]quic.Frame =
            undefined;
        const combined = try appendPendingAck(
            self.endpoint.allocator,
            &stack_frames,
            frames,
            ack,
        );
        defer if (combined.ptr != stack_frames[0..].ptr) {
            self.endpoint.allocator.free(combined);
        };
        try self.trySend(combined);
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
            if (!frame_traits.ackEliciting(packet.frames)) continue;
            ack_eliciting_count +|= 1;
            if (largest_packet_number) |largest| {
                if (packet.packet.packet_number < largest) {
                    const gap = largest - packet.packet.packet_number;
                    if (self.ack_reordering_threshold != 0 and
                        gap >= self.ack_reordering_threshold)
                    {
                        reordered = true;
                    }
                } else {
                    largest_packet_number = packet.packet.packet_number;
                }
            } else {
                largest_packet_number = packet.packet.packet_number;
            }
        }
        if (ack_eliciting_count == 0) return false;
        return self.sendAckForObservedPacketMetadata(
            ack_eliciting_count,
            reordered,
        );
    }

    /// Apply ACK policy to one borrowed packet view.
    ///
    /// This is the allocation-free counterpart to
    /// `sendAckForPacketsIfNeeded`; it lets synchronous frame visitors retain
    /// the same delayed/immediate ACK behavior without manufacturing an owned
    /// `ReceivedPacket` solely for its packet number and frame slice.
    pub fn sendAckForPacketIfNeeded(
        self: *Connection,
        packet_number: u64,
        frames: []const quic.Frame,
    ) Error!bool {
        if (!frame_traits.ackEliciting(frames)) return false;
        const reordered = if (self.received.largestReceived()) |largest|
            packet_number < largest and
                self.ack_reordering_threshold != 0 and
                largest - packet_number >= self.ack_reordering_threshold
        else
            false;
        return self.sendAckForObservedPacketMetadata(1, reordered);
    }

    fn sendAckForObservedPacketMetadata(
        self: *Connection,
        ack_eliciting_count: u64,
        reordered: bool,
    ) Error!bool {
        std.debug.assert(ack_eliciting_count != 0);

        const immediate_requested = self.immediate_ack_requested;
        if (immediate_requested) self.immediate_ack_requested = false;
        errdefer if (immediate_requested) {
            self.immediate_ack_requested = true;
        };

        self.ack_eliciting_since_last_ack +|= ack_eliciting_count;
        errdefer self.ack_eliciting_since_last_ack -|= ack_eliciting_count;

        if (!immediate_requested and
            self.requested_max_ack_delay != 0 and
            !reordered and
            self.ack_eliciting_since_last_ack < self.ack_eliciting_threshold)
        {
            self.scheduleAckDelayIfNeeded();
            return false;
        }

        try self.sendAck(0);
        return true;
    }

    fn scheduleAckDelayIfNeeded(self: *Connection) void {
        if (self.requested_max_ack_delay == 0 or self.ack_delay_deadline_ns != null) return;
        const base = self.monotonicNowNs();
        const delay_ns = std.math.mul(u64, self.requested_max_ack_delay, 1_000) catch std.math.maxInt(u64);
        self.ack_delay_start_ns = base;
        self.ack_delay_deadline_ns = std.math.add(u64, base, delay_ns) catch std.math.maxInt(u64);
    }

    pub fn ackDelayDeadline(self: Connection) ?u64 {
        return self.ack_delay_deadline_ns;
    }

    /// Immediately emit the cumulative ACK selected by the local delayed-ACK
    /// policy, if one is pending. Protocol shutdown paths use this before
    /// releasing the endpoint so a final peer FIN is not left unacknowledged.
    pub fn flushPendingAck(self: *Connection) Error!bool {
        if (self.ack_eliciting_since_last_ack == 0) return false;
        const now_ns = self.monotonicNowNs();
        const start = self.ack_delay_start_ns orelse now_ns;
        try self.sendAckForDelayNs(now_ns -| start);
        return true;
    }

    /// Flush a pending cumulative ACK before an absolute awake-clock deadline.
    /// Ownership-transfer boundaries use this when the current protocol layer
    /// will stop driving receive timers after returning to its caller.
    pub fn flushPendingAckWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!bool {
        _ = try deadline_policy.usableAwake(self.endpoint.io, deadline);
        if (self.ack_eliciting_since_last_ack == 0) return false;
        while (true) {
            _ = self.tryFlushPendingAck() catch |err| switch (err) {
                error.PacingLimited => {
                    try self.waitForPacingAvailabilityWithDeadline(deadline);
                    continue;
                },
                else => |other| return other,
            };
            return true;
        }
    }

    /// Attempt to flush the delayed cumulative ACK without sleeping for
    /// pacing. On failure the ACK counters and deadline remain intact.
    pub fn tryFlushPendingAck(self: *Connection) Error!bool {
        if (self.ack_eliciting_since_last_ack == 0) return false;
        const now_ns = self.monotonicNowNs();
        const start = self.ack_delay_start_ns orelse now_ns;
        const delay = try self.encodedLocalAckDelayNanos(now_ns -| start);
        try self.trySendWithPendingAck(&.{}, delay);
        return true;
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
        try self.resetStreamAt(stream_id, application_error_code, null);
    }

    /// Abort a send stream while waiting for congestion and pacing progress
    /// for at most `timeout`. A timeout before socket submission leaves the
    /// stream writable so the same reset can be retried safely.
    pub fn resetStreamWithTimeout(
        self: *Connection,
        stream_id: u64,
        application_error_code: u64,
        timeout: std.Io.Duration,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.resetStreamWithDeadline(
            stream_id,
            application_error_code,
            .fromNow(self.endpoint.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Abort a send stream under one caller-owned absolute awake-clock
    /// deadline. While congestion-blocked, ACK/loss/PTO state continues to be
    /// serviced; pacing sleeps never outlive the same deadline.
    pub fn resetStreamWithDeadline(
        self: *Connection,
        stream_id: u64,
        application_error_code: u64,
        deadline: std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
        if (deadline.clock != .awake or
            deadline.durationFromNow(self.endpoint.io).raw.nanoseconds <= 0)
        {
            return error.Timeout;
        }
        while (true) {
            if (deadline.durationFromNow(self.endpoint.io).raw.nanoseconds <= 0) {
                return error.Timeout;
            }
            self.resetStreamAt(
                stream_id,
                application_error_code,
                self.monotonicNowNs(),
            ) catch |err| switch (err) {
                error.CongestionLimited => {
                    self.servicePacketServicingTimersDeadline(deadline) catch |progress_err|
                        switch (progress_err) {
                            error.CongestionLimited => continue,
                            error.PacingLimited => {
                                try self.waitForPacingAvailabilityWithDeadline(
                                    deadline,
                                );
                                continue;
                            },
                            else => |other| return other,
                        };
                    continue;
                },
                error.PacingLimited => {
                    try self.waitForPacingAvailabilityWithDeadline(deadline);
                    continue;
                },
                else => |other| return other,
            };
            return;
        }
    }

    /// Attempt one RESET_STREAM send without sleeping for pacing. The stream
    /// remains writable when the packet cannot be submitted, so an event-loop
    /// owner can retry after its next transport-progress notification.
    pub fn tryResetStream(
        self: *Connection,
        stream_id: u64,
        application_error_code: u64,
    ) Error!void {
        try self.resetStreamAt(
            stream_id,
            application_error_code,
            self.monotonicNowNs(),
        );
    }

    fn resetStreamAt(
        self: *Connection,
        stream_id: u64,
        application_error_code: u64,
        sent_time_ns: ?u64,
    ) Error!void {
        try self.validateNextPacketNumber();
        const entry = try self.sendStreamEntry(stream_id);
        try self.sendResetStreamAt(
            stream_id,
            application_error_code,
            entry.highest_sent_end,
            sent_time_ns,
        );
    }

    pub fn sendStopSending(self: *Connection, stream_id: u64, application_error_code: u64) Error!void {
        try self.sendStopSendingAt(stream_id, application_error_code, null);
    }

    /// Cancel a peer send direction while waiting for congestion and pacing
    /// progress for at most `timeout`. A timeout before socket submission
    /// leaves the receive direction unchanged so the operation is retryable.
    pub fn sendStopSendingWithTimeout(
        self: *Connection,
        stream_id: u64,
        application_error_code: u64,
        timeout: std.Io.Duration,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendStopSendingWithDeadline(
            stream_id,
            application_error_code,
            .fromNow(self.endpoint.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Cancel a peer send direction under one caller-owned absolute awake-clock
    /// deadline. ACK/loss/PTO progress and pacing waits share that deadline.
    pub fn sendStopSendingWithDeadline(
        self: *Connection,
        stream_id: u64,
        application_error_code: u64,
        deadline: std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
        if (deadline.clock != .awake or
            deadline.durationFromNow(self.endpoint.io).raw.nanoseconds <= 0)
        {
            return error.Timeout;
        }
        while (true) {
            if (deadline.durationFromNow(self.endpoint.io).raw.nanoseconds <= 0) {
                return error.Timeout;
            }
            self.sendStopSendingAt(
                stream_id,
                application_error_code,
                self.monotonicNowNs(),
            ) catch |err| switch (err) {
                error.CongestionLimited => {
                    self.servicePacketServicingTimersDeadline(deadline) catch |progress_err|
                        switch (progress_err) {
                            error.CongestionLimited => continue,
                            error.PacingLimited => {
                                try self.waitForPacingAvailabilityWithDeadline(
                                    deadline,
                                );
                                continue;
                            },
                            else => |other| return other,
                        };
                    continue;
                },
                error.PacingLimited => {
                    try self.waitForPacingAvailabilityWithDeadline(deadline);
                    continue;
                },
                else => |other| return other,
            };
            return;
        }
    }

    /// Attempt one STOP_SENDING send without sleeping for pacing. The receive
    /// direction is marked stopped only after the packet reaches the socket.
    pub fn trySendStopSending(
        self: *Connection,
        stream_id: u64,
        application_error_code: u64,
    ) Error!void {
        try self.sendStopSendingAt(
            stream_id,
            application_error_code,
            self.monotonicNowNs(),
        );
    }

    /// Atomically submit any still-needed RESET_STREAM and STOP_SENDING for
    /// one bidirectional stream. State is committed only after the combined
    /// packet reaches the socket.
    pub fn cancelStream(
        self: *Connection,
        stream_id: u64,
        application_error_code: u64,
    ) Error!void {
        try self.cancelStreamAt(
            stream_id,
            application_error_code,
            null,
        );
    }

    /// One-attempt counterpart to `cancelStream`. It never sleeps for pacing,
    /// so an endpoint can retry after its next transport-progress notification.
    pub fn tryCancelStream(
        self: *Connection,
        stream_id: u64,
        application_error_code: u64,
    ) Error!void {
        try self.cancelStreamAt(
            stream_id,
            application_error_code,
            self.monotonicNowNs(),
        );
    }

    fn cancelStreamAt(
        self: *Connection,
        stream_id: u64,
        application_error_code: u64,
        sent_time_ns: ?u64,
    ) Error!void {
        try self.validateNextPacketNumber();
        const send_stream = try self.sendStreamEntry(stream_id);
        const recv_stream = try self.recvStreamFlow(stream_id);
        const reset_info: StreamResetInfo = .{
            .application_error_code = application_error_code,
            .final_size = send_stream.highest_sent_end,
        };
        const needs_reset = send_stream.final_size == null and
            send_stream.reset_sent == null;
        if (send_stream.reset_sent) |existing| {
            if (existing.application_error_code != application_error_code or
                existing.final_size != reset_info.final_size)
            {
                return error.FinalSizeMismatch;
            }
        }
        const needs_stop = if (recv_stream.stop_sending_sent) |existing|
            existing.application_error_code != application_error_code
        else
            true;

        var frames: [2]quic.Frame = undefined;
        var count: usize = 0;
        if (needs_reset) {
            frames[count] = .{ .reset_stream = .{
                .stream_id = stream_id,
                .application_error_code = application_error_code,
                .final_size = reset_info.final_size,
            } };
            count += 1;
        }
        if (needs_stop) {
            frames[count] = .{ .stop_sending = .{
                .stream_id = stream_id,
                .application_error_code = application_error_code,
            } };
            count += 1;
        }
        if (count == 0) return;
        if (sent_time_ns) |now_ns|
            try self.sendTrackedFramesEcnAt(
                frames[0..count],
                .not_ect,
                now_ns,
            )
        else
            try self.sendTrackedFrames(frames[0..count]);
        if (needs_reset) {
            _ = self.recovery.abandonStreamData(stream_id);
            send_stream.reset_sent = reset_info;
        }
        if (needs_stop) {
            recv_stream.stop_sending_sent = .{
                .application_error_code = application_error_code,
            };
        }
    }

    fn sendStopSendingAt(
        self: *Connection,
        stream_id: u64,
        application_error_code: u64,
        sent_time_ns: ?u64,
    ) Error!void {
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
        if (sent_time_ns) |now_ns|
            try self.sendTrackedFramesEcnAt(&frames, .not_ect, now_ns)
        else
            try self.sendTrackedFrames(&frames);
        recv_stream.stop_sending_sent = info;
    }

    pub fn streamResetReceived(self: Connection, stream_id: u64) ?StreamResetInfo {
        if (self.stream_recv_index.count() == 0) return null;
        const index = self.stream_recv_index.get(stream_id) orelse return null;
        if (index >= self.stream_recv_flows.items.len) return null;
        const entry = self.stream_recv_flows.items[index];
        if (entry.stream_id != stream_id) return null;
        return entry.reset;
    }

    /// Borrow the contiguous, not-yet-consumed bytes available on a stream.
    ///
    /// The slice is invalidated by the next operation that can receive or
    /// consume stream data on this connection. This is the allocation-free
    /// application read path; call `releaseReceivedCapacity` after processing
    /// a prefix so the receive buffer can compact and the peer can regain
    /// connection- and stream-level flow-control credit. After RESET_STREAM,
    /// the slice is empty by default or capped to the opt-in reset-time
    /// delivery frontier.
    pub fn availableReceivedStream(
        self: *Connection,
        stream_id: u64,
    ) ?[]const u8 {
        const entry = self.findRecvStreamEntry(stream_id) orelse return null;
        return applicationAvailableStreamBytes(
            entry,
            self.config.enable_reset_partial_delivery,
        );
    }

    /// Borrow contiguous transport bytes even after RESET_STREAM. Protocol
    /// dispatchers use this narrow view only to identify ownership from a
    /// stream prefix; application data APIs continue to honor reset delivery
    /// policy through `availableReceivedStream`.
    pub fn retainedReceivedStream(
        self: *Connection,
        stream_id: u64,
    ) ?[]const u8 {
        const entry = self.findRecvStreamEntry(stream_id) orelse return null;
        return entry.recv_state.available();
    }

    /// Snapshot one receive stream for a protocol parser that is taking over
    /// after consuming a prefix directly from the QUIC buffer. The connection
    /// retains its own copy for flow control and retransmission validation.
    pub fn cloneReceivedStreamState(
        self: *Connection,
        allocator: std.mem.Allocator,
        stream_id: u64,
    ) Error!?quic.stream_state.RecvState {
        const entry = self.findRecvStreamEntry(stream_id) orelse return null;
        return try entry.recv_state.clone(allocator);
    }

    /// Whether FIN has been received contiguously and all stream bytes have
    /// been consumed through `releaseReceivedCapacity`.
    pub fn receivedStreamComplete(
        self: *Connection,
        stream_id: u64,
    ) bool {
        const entry = self.findRecvStreamEntry(stream_id) orelse return false;
        return entry.recv_state.complete();
    }

    /// Return one peer-initiated stream slot after both halves are terminal.
    ///
    /// The receive half is terminal after its FIN has been fully consumed, or
    /// after the application observes a RESET_STREAM and explicitly calls this
    /// method. A bidirectional stream also requires a locally sent FIN or
    /// RESET_STREAM to be acknowledged. Calling before that acknowledgement
    /// records a deferred release that the receive path completes when the ACK
    /// arrives. Closed stream IDs are retained as compressed ranges so late
    /// frames can be ignored without retaining stream buffers and map entries.
    ///
    /// Returns true only when a new MAX_STREAMS frame was sent. Repeated calls
    /// are idempotent.
    pub fn releaseCompletedPeerStream(
        self: *Connection,
        stream_id: u64,
    ) Error!bool {
        const result = try self.releaseCompletedPeerStreamsAt(
            &.{stream_id},
            null,
        );
        return result.update_sent;
    }

    /// Attempt one terminal peer-stream release without sleeping for pacing.
    /// All flow limits and stream state remain unchanged if its MAX_* packet
    /// cannot be submitted.
    pub fn tryReleaseCompletedPeerStream(
        self: *Connection,
        stream_id: u64,
    ) Error!bool {
        const result = try self.releaseCompletedPeerStreamsAt(
            &.{stream_id},
            self.monotonicNowNs(),
        );
        return result.update_sent;
    }

    /// Register an application-level peer-stream retirement request.
    ///
    /// Unlike `releaseCompletedPeerStream`, this accepts a fully received FIN
    /// even when the transport buffer has not been consumed directly. Upper
    /// protocols that copied or parsed the complete message can therefore
    /// relinquish those retained bytes without an extra transport read. The
    /// request is completed after the local half and its reliable data are
    /// acknowledged. Automatic credit-send failures remain pending and retry
    /// from the aggregate connection timer.
    ///
    /// Returns false while the receive half is still incomplete.
    pub fn requestCompletedPeerStreamRelease(
        self: *Connection,
        stream_id: u64,
    ) Error!bool {
        if (streamInitiatedByLocal(self.config.local_endpoint, stream_id)) {
            return error.StreamStateError;
        }
        if (self.isClosedPeerStream(stream_id)) return true;
        const recv_stream = self.findRecvStreamEntry(stream_id) orelse
            return error.StreamStateError;
        if (recv_stream.reset == null and
            !recv_stream.recv_state.receivedComplete())
        {
            return false;
        }
        if (!recv_stream.stream_count_release_requested) {
            recv_stream.stream_count_release_requested = true;
            self.pending_peer_stream_credit_releases += 1;
        }
        const now_ns = self.monotonicNowNs();
        self.flushRequestedStreamReleasesAt(now_ns) catch |err| {
            self.scheduleStreamReleaseRetry(err, now_ns);
        };
        return true;
    }

    /// Register retirement of a locally initiated stream after its upper
    /// protocol has consumed or copied the terminal peer response. No
    /// MAX_STREAMS update is generated because the peer owns that credit.
    /// Reclamation waits for the local FIN/RESET recovery to clear, and for a
    /// bidirectional receive half to reach FIN/RESET. Calling before the peer
    /// half is terminal records the request so a later FIN/RESET completes it.
    ///
    /// Returns true only when the stream was reclaimed immediately; false
    /// means the request is retained until a missing terminal/ACK condition
    /// arrives.
    pub fn requestCompletedLocalStreamRelease(
        self: *Connection,
        stream_id: u64,
    ) Error!bool {
        if (!streamInitiatedByLocal(self.config.local_endpoint, stream_id)) {
            return error.StreamStateError;
        }
        if (self.isClosedLocalStream(stream_id)) return true;
        const send_stream = self.findSendStreamEntry(stream_id) orelse
            return error.StreamStateError;
        if (!send_stream.release_requested) {
            send_stream.release_requested = true;
            self.pending_local_stream_releases += 1;
        }
        const now_ns = self.monotonicNowNs();
        self.flushRequestedStreamReleasesAt(now_ns) catch |err| {
            self.scheduleStreamReleaseRetry(err, now_ns);
        };
        return self.isClosedLocalStream(stream_id);
    }

    /// Return stream-count credit for several terminal peer streams at once.
    ///
    /// At most one MAX_STREAMS frame per direction is emitted, so closing a
    /// concurrent batch costs one packet instead of one packet per stream.
    /// Duplicate IDs are ignored. Validation and packet transmission happen
    /// before local limits or release flags change, preserving retryability on
    /// invalid input, allocation failure, congestion, pacing, or socket error.
    pub fn releaseCompletedPeerStreams(
        self: *Connection,
        stream_ids: []const u64,
    ) Error!PeerStreamReleaseResult {
        return self.releaseCompletedPeerStreamsAt(stream_ids, null);
    }

    fn releaseCompletedPeerStreamsAt(
        self: *Connection,
        stream_ids: []const u64,
        sent_time_ns: ?u64,
    ) Error!PeerStreamReleaseResult {
        var bidi_released: u64 = 0;
        var uni_released: u64 = 0;
        for (stream_ids, 0..) |stream_id, index| {
            if (containsStreamId(stream_ids[0..index], stream_id)) continue;
            if (try self.peerStreamCreditState(stream_id) == .ready) {
                switch (streamDirection(stream_id)) {
                    .bidirectional => bidi_released += 1,
                    .unidirectional => uni_released += 1,
                }
            }
        }
        const released_u64 = std.math.add(
            u64,
            bidi_released,
            uni_released,
        ) catch return error.StreamStateError;
        const released = std.math.cast(usize, released_u64) orelse
            return error.StreamStateError;
        const next_bidi = advanceStreamLimit(
            self.recv_max_streams_bidi,
            bidi_released,
        );
        const next_uni = advanceStreamLimit(
            self.recv_max_streams_uni,
            uni_released,
        );
        var next_recv_flow = self.recv_flow;
        for (stream_ids, 0..) |stream_id, index| {
            if (containsStreamId(stream_ids[0..index], stream_id)) continue;
            if (try self.peerStreamCreditState(stream_id) != .ready) continue;
            const recv_stream = self.findRecvStreamEntry(stream_id).?;
            _ = next_recv_flow.consume(
                recv_stream.flow.highest_received -| recv_stream.flow.consumed,
            );
        }
        try self.prepareClosedPeerStreamInsert(
            std.math.cast(usize, bidi_released) orelse
                return error.OutOfMemory,
            std.math.cast(usize, uni_released) orelse
                return error.OutOfMemory,
        );
        var frames: [3]quic.Frame = undefined;
        var frame_count: usize = 0;
        if (next_recv_flow.limit != self.recv_flow.limit) {
            frames[frame_count] = next_recv_flow.maxDataFrame();
            frame_count += 1;
        }
        if (next_bidi != self.recv_max_streams_bidi) {
            frames[frame_count] = .{ .max_streams_bidi = .{
                .maximum_streams = next_bidi,
            } };
            frame_count += 1;
        }
        if (next_uni != self.recv_max_streams_uni) {
            frames[frame_count] = .{ .max_streams_uni = .{
                .maximum_streams = next_uni,
            } };
            frame_count += 1;
        }
        if (frame_count != 0) {
            if (sent_time_ns) |now_ns|
                try self.sendTrackedFramesEcnAt(
                    frames[0..frame_count],
                    .not_ect,
                    now_ns,
                )
            else
                try self.sendTrackedFrames(frames[0..frame_count]);
        }
        self.recv_flow = next_recv_flow;

        // No connection method may run concurrently with this mutation. The
        // second pass therefore selects exactly the preflighted streams while
        // avoiding temporary heap storage proportional to the batch size.
        for (stream_ids, 0..) |stream_id, index| {
            if (containsStreamId(stream_ids[0..index], stream_id)) continue;
            const state = try self.peerStreamCreditState(stream_id);
            switch (state) {
                .ready => {
                    const recv_stream = self.findRecvStreamEntry(stream_id).?;
                    if (recv_stream.stream_count_release_requested) {
                        self.pending_peer_stream_credit_releases -= 1;
                    }
                    self.reclaimPeerStreamAssumeCapacity(stream_id);
                },
                .waiting_for_local_terminal,
                .waiting_for_send_ack,
                => {
                    const recv_stream = self.findRecvStreamEntry(stream_id).?;
                    if (!recv_stream.stream_count_release_requested) {
                        recv_stream.stream_count_release_requested = true;
                        self.pending_peer_stream_credit_releases += 1;
                    }
                },
                .receive_not_terminal, .released => {},
            }
        }
        self.recv_max_streams_bidi = next_bidi;
        self.recv_max_streams_uni = next_uni;
        if (bidi_released != 0) {
            self.pending_streams_blocked_bidi_response = false;
        }
        if (uni_released != 0) {
            self.pending_streams_blocked_uni_response = false;
        }
        if (!self.pending_streams_blocked_bidi_response and
            !self.pending_streams_blocked_uni_response)
        {
            self.clearStreamsBlockedResponseRetry();
        }
        return .{
            .streams_released = released,
            .update_sent = frame_count != 0,
        };
    }

    const PeerStreamCreditState = enum {
        receive_not_terminal,
        waiting_for_local_terminal,
        waiting_for_send_ack,
        ready,
        released,
    };

    fn peerStreamCreditState(
        self: *Connection,
        stream_id: u64,
    ) Error!PeerStreamCreditState {
        if (streamInitiatedByLocal(self.config.local_endpoint, stream_id)) {
            return error.StreamStateError;
        }
        if (self.isClosedPeerStream(stream_id)) return .released;
        const recv_stream = self.findRecvStreamEntry(stream_id) orelse
            return error.StreamStateError;
        const receive_terminal = recv_stream.reset != null or
            recv_stream.recv_state.complete() or
            (recv_stream.stream_count_release_requested and
                recv_stream.recv_state.receivedComplete());
        if (!receive_terminal) {
            return .receive_not_terminal;
        }
        if (streamDirection(stream_id) == .bidirectional) {
            const send_stream = self.findSendStreamEntry(stream_id) orelse
                return .waiting_for_local_terminal;
            if (send_stream.final_size == null and
                send_stream.reset_sent == null)
            {
                return .waiting_for_local_terminal;
            }
            const pending = self.recovery.hasPendingStreamData(stream_id) or
                (send_stream.reset_sent != null and
                    self.recovery.hasPendingResetStream(stream_id));
            if (pending) {
                return .waiting_for_send_ack;
            }
        }
        return .ready;
    }

    fn isClosedPeerStream(self: *const Connection, stream_id: u64) bool {
        if (streamInitiatedByLocal(self.config.local_endpoint, stream_id)) {
            return false;
        }
        const sequence = stream_id >> 2;
        return switch (streamDirection(stream_id)) {
            .bidirectional => self.closed_peer_bidi_streams.contains(sequence),
            .unidirectional => self.closed_peer_uni_streams.contains(sequence),
        };
    }

    fn isClosedLocalStream(self: *const Connection, stream_id: u64) bool {
        if (!streamInitiatedByLocal(self.config.local_endpoint, stream_id)) {
            return false;
        }
        const sequence = stream_id >> 2;
        return switch (streamDirection(stream_id)) {
            .bidirectional => self.closed_local_bidi_streams.contains(sequence),
            .unidirectional => self.closed_local_uni_streams.contains(sequence),
        };
    }

    fn isClosedStream(self: *const Connection, stream_id: u64) bool {
        return if (streamInitiatedByLocal(self.config.local_endpoint, stream_id))
            self.isClosedLocalStream(stream_id)
        else
            self.isClosedPeerStream(stream_id);
    }

    /// Whether a locally initiated stream has been fully retired and compacted.
    pub fn localStreamClosed(self: Connection, stream_id: u64) bool {
        return self.isClosedLocalStream(stream_id);
    }

    /// Classify any stream without exposing active-table layout.
    pub fn streamLifecycle(
        self: Connection,
        stream_id: u64,
    ) StreamLifecycle {
        if (self.isClosedStream(stream_id)) return .closed;
        if ((self.stream_send_index.count() != 0 and
            self.stream_send_index.contains(stream_id)) or
            (self.stream_recv_index.count() != 0 and
                self.stream_recv_index.contains(stream_id)))
        {
            return .active;
        }
        return .unknown;
    }

    /// Whether a peer-initiated stream has been fully released and compacted.
    /// Late stream-control/data frames for such an ID are ignored by transport.
    pub fn peerStreamClosed(self: Connection, stream_id: u64) bool {
        return self.isClosedPeerStream(stream_id);
    }

    /// Classify stream identity without exposing active-table layout.
    pub fn peerStreamLifecycle(
        self: Connection,
        stream_id: u64,
    ) PeerStreamLifecycle {
        if (streamInitiatedByLocal(self.config.local_endpoint, stream_id)) {
            return .unknown;
        }
        return switch (self.streamLifecycle(stream_id)) {
            .unknown => .unknown,
            .active => .active,
            .closed => .closed,
        };
    }

    fn prepareClosedPeerStreamInsert(
        self: *Connection,
        bidi_count: usize,
        uni_count: usize,
    ) std.mem.Allocator.Error!void {
        try self.closed_peer_bidi_streams.prepareInsert(
            self.endpoint.allocator,
            bidi_count,
        );
        try self.closed_peer_uni_streams.prepareInsert(
            self.endpoint.allocator,
            uni_count,
        );
    }

    fn prepareClosedLocalStreamInsert(
        self: *Connection,
        bidi_count: usize,
        uni_count: usize,
    ) std.mem.Allocator.Error!void {
        try self.closed_local_bidi_streams.prepareInsert(
            self.endpoint.allocator,
            bidi_count,
        );
        try self.closed_local_uni_streams.prepareInsert(
            self.endpoint.allocator,
            uni_count,
        );
    }

    fn localStreamReadyForReclaim(
        self: *Connection,
        stream_id: u64,
    ) bool {
        const send_stream = self.findSendStreamEntry(stream_id) orelse
            return false;
        if (!send_stream.release_requested or
            (send_stream.final_size == null and send_stream.reset_sent == null))
        {
            return false;
        }
        if (self.recovery.hasPendingStreamData(stream_id) or
            (send_stream.reset_sent != null and
                self.recovery.hasPendingResetStream(stream_id)))
        {
            return false;
        }
        if (streamDirection(stream_id) == .unidirectional) return true;
        const recv_stream = self.findRecvStreamEntry(stream_id) orelse
            return false;
        return recv_stream.reset != null or recv_stream.recv_state.receivedComplete();
    }

    fn flushRequestedLocalStreamReleasesAt(
        self: *Connection,
        now_ns: u64,
    ) Error!void {
        if (self.pending_local_stream_releases == 0) return;
        var bidi_ready: usize = 0;
        var uni_ready: usize = 0;
        for (self.stream_send_flows.items) |*send_stream| {
            const stream_id = send_stream.stream_id;
            if (!streamInitiatedByLocal(self.config.local_endpoint, stream_id) or
                !self.localStreamReadyForReclaim(stream_id))
            {
                continue;
            }
            switch (streamDirection(stream_id)) {
                .bidirectional => bidi_ready += 1,
                .unidirectional => uni_ready += 1,
            }
        }
        if (bidi_ready == 0 and uni_ready == 0) return;
        try self.prepareClosedLocalStreamInsert(bidi_ready, uni_ready);

        var next_recv_flow = self.recv_flow;
        for (self.stream_send_flows.items) |*send_stream| {
            const stream_id = send_stream.stream_id;
            if (!streamInitiatedByLocal(self.config.local_endpoint, stream_id) or
                !self.localStreamReadyForReclaim(stream_id))
            {
                continue;
            }
            if (self.findRecvStreamEntry(stream_id)) |recv_stream| {
                _ = next_recv_flow.consume(
                    recv_stream.flow.highest_received -| recv_stream.flow.consumed,
                );
            }
        }
        if (next_recv_flow.limit != self.recv_flow.limit) {
            const frames = [_]quic.Frame{next_recv_flow.maxDataFrame()};
            try self.sendTrackedFramesEcnAt(&frames, .not_ect, now_ns);
        }
        self.recv_flow = next_recv_flow;

        var index: usize = 0;
        while (index < self.stream_send_flows.items.len) {
            const stream_id = self.stream_send_flows.items[index].stream_id;
            if (!streamInitiatedByLocal(self.config.local_endpoint, stream_id) or
                !self.localStreamReadyForReclaim(stream_id))
            {
                index += 1;
                continue;
            }
            self.reclaimLocalStreamAssumeCapacity(stream_id);
            // swapRemove installed an unchecked entry at this index.
        }
    }

    fn reclaimRequestedLocalStreamsAfterAck(self: *Connection) void {
        if (self.pending_local_stream_releases == 0) return;
        const now_ns = self.monotonicNowNs();
        self.flushRequestedLocalStreamReleasesAt(now_ns) catch |err| {
            self.scheduleStreamReleaseRetry(err, now_ns);
        };
    }

    fn reclaimLocalStreamAssumeCapacity(
        self: *Connection,
        stream_id: u64,
    ) void {
        std.debug.assert(streamInitiatedByLocal(
            self.config.local_endpoint,
            stream_id,
        ));
        const sequence = stream_id >> 2;
        switch (streamDirection(stream_id)) {
            .bidirectional => self.closed_local_bidi_streams
                .insertAssumeCapacity(sequence),
            .unidirectional => self.closed_local_uni_streams
                .insertAssumeCapacity(sequence),
        }
        if (self.findRecvStreamEntry(stream_id) != null) {
            self.removeRecvStreamEntry(stream_id);
        }
        _ = self.recovery.abandonClosedStreamFrames(stream_id);
        self.pending_local_stream_releases -= 1;
        self.removeSendStreamEntry(stream_id);
    }

    fn reclaimPeerStreamAssumeCapacity(
        self: *Connection,
        stream_id: u64,
    ) void {
        std.debug.assert(!streamInitiatedByLocal(
            self.config.local_endpoint,
            stream_id,
        ));
        const sequence = stream_id >> 2;
        switch (streamDirection(stream_id)) {
            .bidirectional => self.closed_peer_bidi_streams
                .insertAssumeCapacity(sequence),
            .unidirectional => self.closed_peer_uni_streams
                .insertAssumeCapacity(sequence),
        }
        _ = self.recovery.abandonClosedStreamFrames(stream_id);
        self.removeRecvStreamEntry(stream_id);
        if (streamDirection(stream_id) == .bidirectional) {
            self.removeSendStreamEntry(stream_id);
        }
    }

    fn removeRecvStreamEntry(self: *Connection, stream_id: u64) void {
        const index = self.stream_recv_index.get(stream_id) orelse return;
        const last_index = self.stream_recv_flows.items.len - 1;
        const next_poll_index = if (self.stream_recv_flows.items.len == 0)
            0
        else
            self.stream_poll_cursor % self.stream_recv_flows.items.len;
        var removed = self.stream_recv_flows.swapRemove(index);
        if (removed.pending_max_stream_data) {
            std.debug.assert(self.pending_receive_stream_credits != 0);
            self.pending_receive_stream_credits -= 1;
        }
        _ = self.stream_recv_index.remove(stream_id);
        if (index != last_index) {
            const moved = self.stream_recv_flows.items[index];
            self.stream_recv_index.getPtr(moved.stream_id).?.* = index;
        }
        self.last_recv_stream_index = null;
        if (self.stream_recv_flows.items.len == 0) {
            self.stream_poll_cursor = 0;
        } else if (index != last_index and next_poll_index == last_index) {
            // The stream that was next in round-robin order moved into the
            // removed slot. Follow it so a perpetually readable lower-index
            // stream cannot starve the moved entry.
            self.stream_poll_cursor = index;
        } else if (next_poll_index >= self.stream_recv_flows.items.len) {
            self.stream_poll_cursor = 0;
        } else {
            self.stream_poll_cursor = next_poll_index;
        }
        removed.deinit();
        if (!self.hasPendingReceiveCredit()) {
            self.clearReceiveCreditRetry();
        }
    }

    fn removeSendStreamEntry(self: *Connection, stream_id: u64) void {
        const index = self.stream_send_index.get(stream_id) orelse return;
        const last_index = self.stream_send_flows.items.len - 1;
        const removed = self.stream_send_flows.swapRemove(index);
        if (removed.stopped != null and removed.reset_sent == null) {
            std.debug.assert(self.pending_stop_sending_resets != 0);
            self.pending_stop_sending_resets -= 1;
            if (self.pending_stop_sending_resets == 0) {
                self.clearStopSendingResetRetry();
            }
        }
        _ = self.stream_send_index.remove(stream_id);
        if (index != last_index) {
            const moved = self.stream_send_flows.items[index];
            self.stream_send_index.getPtr(moved.stream_id).?.* = index;
        }
        self.last_send_stream_index = null;
    }

    fn flushRequestedPeerStreamCreditsAt(
        self: *Connection,
        now_ns: u64,
    ) Error!void {
        if (self.pending_peer_stream_credit_releases == 0) return;
        var bidi_released: u64 = 0;
        var uni_released: u64 = 0;
        for (self.stream_recv_flows.items) |*recv_stream| {
            if (!recv_stream.stream_count_release_requested) continue;
            if (try self.peerStreamCreditState(recv_stream.stream_id) !=
                .ready) continue;
            switch (streamDirection(recv_stream.stream_id)) {
                .bidirectional => bidi_released += 1,
                .unidirectional => uni_released += 1,
            }
        }
        if (bidi_released == 0 and uni_released == 0) return;

        const next_bidi = advanceStreamLimit(
            self.recv_max_streams_bidi,
            bidi_released,
        );
        const next_uni = advanceStreamLimit(
            self.recv_max_streams_uni,
            uni_released,
        );
        var next_recv_flow = self.recv_flow;
        for (self.stream_recv_flows.items) |*recv_stream| {
            if (!recv_stream.stream_count_release_requested) continue;
            if (try self.peerStreamCreditState(recv_stream.stream_id) !=
                .ready) continue;
            _ = next_recv_flow.consume(
                recv_stream.flow.highest_received -| recv_stream.flow.consumed,
            );
        }
        try self.prepareClosedPeerStreamInsert(
            std.math.cast(usize, bidi_released) orelse
                return error.OutOfMemory,
            std.math.cast(usize, uni_released) orelse
                return error.OutOfMemory,
        );
        var frames: [3]quic.Frame = undefined;
        var frame_count: usize = 0;
        if (next_recv_flow.limit != self.recv_flow.limit) {
            frames[frame_count] = next_recv_flow.maxDataFrame();
            frame_count += 1;
        }
        if (next_bidi != self.recv_max_streams_bidi) {
            frames[frame_count] = .{ .max_streams_bidi = .{
                .maximum_streams = next_bidi,
            } };
            frame_count += 1;
        }
        if (next_uni != self.recv_max_streams_uni) {
            frames[frame_count] = .{ .max_streams_uni = .{
                .maximum_streams = next_uni,
            } };
            frame_count += 1;
        }
        if (frame_count != 0) try self.sendTrackedFramesEcnAt(
            frames[0..frame_count],
            .not_ect,
            now_ns,
        );
        self.recv_flow = next_recv_flow;

        var index: usize = 0;
        while (index < self.stream_recv_flows.items.len) {
            const recv_stream = &self.stream_recv_flows.items[index];
            if (!recv_stream.stream_count_release_requested) {
                index += 1;
                continue;
            }
            if (try self.peerStreamCreditState(recv_stream.stream_id) !=
                .ready)
            {
                index += 1;
                continue;
            }
            const stream_id = recv_stream.stream_id;
            self.pending_peer_stream_credit_releases -= 1;
            self.reclaimPeerStreamAssumeCapacity(stream_id);
            // swapRemove installed an unchecked entry at this index.
        }
        self.recv_max_streams_bidi = next_bidi;
        self.recv_max_streams_uni = next_uni;
        if (bidi_released != 0) {
            self.pending_streams_blocked_bidi_response = false;
        }
        if (uni_released != 0) {
            self.pending_streams_blocked_uni_response = false;
        }
        if (!self.pending_streams_blocked_bidi_response and
            !self.pending_streams_blocked_uni_response)
        {
            self.clearStreamsBlockedResponseRetry();
        }
    }

    fn flushRequestedStreamReleasesAt(
        self: *Connection,
        now_ns: u64,
    ) Error!void {
        if (self.close_info != null or self.idle_timed_out) {
            self.clearStreamReleaseRetry();
            return;
        }
        try self.flushRequestedPeerStreamCreditsAt(now_ns);
        try self.flushRequestedLocalStreamReleasesAt(now_ns);
        self.clearStreamReleaseRetry();
    }

    fn clearStreamReleaseRetry(self: *Connection) void {
        self.stream_release_retry_deadline_ns = null;
        self.stream_release_retry_attempts = 0;
    }

    fn scheduleStreamReleaseRetry(
        self: *Connection,
        err: Error,
        now_ns: u64,
    ) void {
        if ((self.pending_peer_stream_credit_releases == 0 and
            self.pending_local_stream_releases == 0) or
            self.close_info != null or self.idle_timed_out)
        {
            self.clearStreamReleaseRetry();
            return;
        }
        if (err == error.PacingLimited) {
            if (self.pacing_blocked_until_ns) |deadline| {
                if (deadline > now_ns) {
                    self.stream_release_retry_deadline_ns = deadline;
                    return;
                }
            }
        }
        const index = @min(
            @as(usize, self.stream_release_retry_attempts),
            stream_release_retry_backoff_ns.len - 1,
        );
        self.stream_release_retry_attempts +|= 1;
        self.stream_release_retry_deadline_ns = std.math.add(
            u64,
            now_ns,
            stream_release_retry_backoff_ns[index],
        ) catch std.math.maxInt(u64);
    }

    /// Advance at most one RESET_STREAM owed in response to STOP_SENDING.
    /// The stream table itself owns the pending state, while the timer keeps
    /// endpoint schedulers from depending on another inbound packet.
    fn flushPendingStopSendingResetAt(
        self: *Connection,
        now_ns: u64,
    ) Error!void {
        if (self.pending_stop_sending_resets == 0) {
            self.clearStopSendingResetRetry();
            return;
        }
        for (self.stream_send_flows.items) |*entry| {
            const stopped = entry.stopped orelse continue;
            if (entry.reset_sent != null) continue;
            try self.sendResetStreamAt(
                entry.stream_id,
                stopped.application_error_code,
                entry.highest_sent_end,
                now_ns,
            );
            break;
        }
        if (self.pending_stop_sending_resets == 0) {
            self.clearStopSendingResetRetry();
            return;
        }
        self.stop_sending_reset_retry_attempts = 0;
        self.stop_sending_reset_retry_deadline_ns = std.math.add(
            u64,
            now_ns,
            stream_release_retry_backoff_ns[0],
        ) catch std.math.maxInt(u64);
    }

    fn clearStopSendingResetRetry(self: *Connection) void {
        self.stop_sending_reset_retry_deadline_ns = null;
        self.stop_sending_reset_retry_attempts = 0;
    }

    fn scheduleStopSendingResetRetry(
        self: *Connection,
        err: Error,
        now_ns: u64,
    ) void {
        if (self.pending_stop_sending_resets == 0 or
            self.close_info != null or self.idle_timed_out)
        {
            self.clearStopSendingResetRetry();
            return;
        }
        if (err == error.PacingLimited) {
            if (self.pacing_blocked_until_ns) |deadline| {
                if (deadline > now_ns) {
                    self.stop_sending_reset_retry_deadline_ns = deadline;
                    return;
                }
            }
        }
        const index = @min(
            @as(usize, self.stop_sending_reset_retry_attempts),
            stream_release_retry_backoff_ns.len - 1,
        );
        self.stop_sending_reset_retry_attempts +|= 1;
        self.stop_sending_reset_retry_deadline_ns = std.math.add(
            u64,
            now_ns,
            stream_release_retry_backoff_ns[index],
        ) catch std.math.maxInt(u64);
    }

    fn flushPendingStreamsBlockedResponseAt(
        self: *Connection,
        now_ns: u64,
    ) Error!void {
        if (!self.pending_streams_blocked_bidi_response and
            !self.pending_streams_blocked_uni_response)
        {
            self.clearStreamsBlockedResponseRetry();
            return;
        }
        var frames: [2]quic.Frame = undefined;
        var count: usize = 0;
        if (self.pending_streams_blocked_bidi_response) {
            frames[count] = .{ .max_streams_bidi = .{
                .maximum_streams = self.recv_max_streams_bidi,
            } };
            count += 1;
        }
        if (self.pending_streams_blocked_uni_response) {
            frames[count] = .{ .max_streams_uni = .{
                .maximum_streams = self.recv_max_streams_uni,
            } };
            count += 1;
        }
        try self.sendTrackedFramesEcnAt(
            frames[0..count],
            .not_ect,
            now_ns,
        );
        self.pending_streams_blocked_bidi_response = false;
        self.pending_streams_blocked_uni_response = false;
        self.clearStreamsBlockedResponseRetry();
    }

    fn clearStreamsBlockedResponseRetry(self: *Connection) void {
        self.streams_blocked_response_retry_deadline_ns = null;
        self.streams_blocked_response_retry_attempts = 0;
    }

    fn scheduleStreamsBlockedResponseRetry(
        self: *Connection,
        err: Error,
        now_ns: u64,
    ) void {
        if ((!self.pending_streams_blocked_bidi_response and
            !self.pending_streams_blocked_uni_response) or
            self.close_info != null or self.idle_timed_out)
        {
            self.clearStreamsBlockedResponseRetry();
            return;
        }
        if (err == error.PacingLimited) {
            if (self.pacing_blocked_until_ns) |deadline| {
                if (deadline > now_ns) {
                    self.streams_blocked_response_retry_deadline_ns = deadline;
                    return;
                }
            }
        }
        const index = @min(
            @as(usize, self.streams_blocked_response_retry_attempts),
            stream_release_retry_backoff_ns.len - 1,
        );
        self.streams_blocked_response_retry_attempts +|= 1;
        self.streams_blocked_response_retry_deadline_ns = std.math.add(
            u64,
            now_ns,
            stream_release_retry_backoff_ns[index],
        ) catch std.math.maxInt(u64);
    }

    fn hasPendingReceiveCredit(self: Connection) bool {
        return self.pending_max_data or
            self.pending_receive_stream_credits != 0;
    }

    fn clearReceiveCreditRetry(self: *Connection) void {
        self.receive_credit_retry_deadline_ns = null;
        self.receive_credit_retry_attempts = 0;
    }

    fn scheduleReceiveCreditRetry(
        self: *Connection,
        err: Error,
        now_ns: u64,
    ) void {
        if (!self.hasPendingReceiveCredit() or
            self.close_info != null or self.idle_timed_out)
        {
            self.clearReceiveCreditRetry();
            return;
        }
        if (err == error.PacingLimited) {
            if (self.pacing_blocked_until_ns) |deadline| {
                if (deadline > now_ns) {
                    self.receive_credit_retry_deadline_ns = deadline;
                    return;
                }
            }
        }
        const index = @min(
            @as(usize, self.receive_credit_retry_attempts),
            stream_release_retry_backoff_ns.len - 1,
        );
        self.receive_credit_retry_attempts +|= 1;
        self.receive_credit_retry_deadline_ns = std.math.add(
            u64,
            now_ns,
            stream_release_retry_backoff_ns[index],
        ) catch std.math.maxInt(u64);
    }

    fn flushPendingReceiveCreditAt(
        self: *Connection,
        now_ns: u64,
    ) Error!void {
        if (!self.hasPendingReceiveCredit()) {
            self.clearReceiveCreditRetry();
            return;
        }
        if (self.close_info != null or self.idle_timed_out) {
            self.clearReceiveCreditRetry();
            return;
        }

        var frames: [receive_credit_frame_stack_capacity]quic.Frame = undefined;
        var count: usize = 0;
        const includes_handshake_done =
            self.handshake_status.needsHandshakeDone();
        var payload_len: usize = @intFromBool(includes_handshake_done);
        const includes_max_data = self.pending_max_data;
        if (includes_max_data) {
            frames[count] = self.recv_flow.maxDataFrame();
            payload_len = std.math.add(
                usize,
                payload_len,
                try frames[count].wireLen(),
            ) catch return error.InvalidFrameLength;
            count += 1;
        }
        var selected_stream_ids: [receive_credit_frame_stack_capacity]u64 = undefined;
        var selected_stream_count: usize = 0;
        var scan_after = self.last_receive_credit_stream_id;
        if (self.stream_recv_flows.items.len != 0 and
            self.pending_receive_stream_credits != 0)
        {
            const max_frame_count = frames.len -
                @intFromBool(includes_handshake_done);
            while (count < max_frame_count and
                selected_stream_count < self.pending_receive_stream_credits)
            {
                var next_id: ?u64 = null;
                var wrapped_id: ?u64 = null;
                for (self.stream_recv_flows.items) |*entry| {
                    if (!entry.pending_max_stream_data or
                        containsStreamId(
                            selected_stream_ids[0..selected_stream_count],
                            entry.stream_id,
                        )) continue;
                    if (wrapped_id == null or entry.stream_id < wrapped_id.?) {
                        wrapped_id = entry.stream_id;
                    }
                    if (scan_after) |last| {
                        if (entry.stream_id <= last) continue;
                    }
                    if (next_id == null or entry.stream_id < next_id.?) {
                        next_id = entry.stream_id;
                    }
                }
                const id = next_id orelse wrapped_id orelse break;
                const entry = self.findRecvStreamEntry(id) orelse unreachable;
                const candidate = entry.flow.maxStreamDataFrame(id);
                const next_payload_len = std.math.add(
                    usize,
                    payload_len,
                    try candidate.wireLen(),
                ) catch return error.InvalidFrameLength;
                const packet_number_len =
                    quic.protection.packetNumberLenForPayload(
                        self.next_packet_number,
                        self.sent.largestAcknowledged(),
                        next_payload_len,
                    );
                const packet_len = try quic.protection
                    .shortPacketLenForPayloadLen(
                    self.config.peer_connection_id.len,
                    self.next_packet_number,
                    packet_number_len,
                    next_payload_len,
                );
                if (packet_len > self.currentSendDatagramSize()) {
                    if (selected_stream_count == 0 and !includes_max_data) {
                        return error.DatagramTooLarge;
                    }
                    break;
                }
                frames[count] = candidate;
                count += 1;
                payload_len = next_payload_len;
                selected_stream_ids[selected_stream_count] = id;
                selected_stream_count += 1;
                scan_after = id;
            }
        }
        std.debug.assert(count != 0);
        try self.sendTrackedFramesEcnAt(
            frames[0..count],
            .not_ect,
            now_ns,
        );
        if (includes_max_data) self.pending_max_data = false;
        for (selected_stream_ids[0..selected_stream_count]) |id| {
            const entry = self.findRecvStreamEntry(id) orelse unreachable;
            std.debug.assert(entry.pending_max_stream_data);
            entry.pending_max_stream_data = false;
            std.debug.assert(self.pending_receive_stream_credits != 0);
            self.pending_receive_stream_credits -= 1;
            self.last_receive_credit_stream_id = id;
        }
        if (self.hasPendingReceiveCredit()) {
            self.receive_credit_retry_attempts = 0;
            self.receive_credit_retry_deadline_ns = std.math.add(
                u64,
                now_ns,
                stream_release_retry_backoff_ns[0],
            ) catch std.math.maxInt(u64);
        } else {
            self.clearReceiveCreditRetry();
        }
    }

    /// Copy known receive-stream IDs into caller storage without allocation.
    ///
    /// The returned prefix is a point-in-time view of stream identity only;
    /// use `availableReceivedStream` and `recvStreamStats` for current data and
    /// lifecycle state. Protocol adapters use this to discover streams whose
    /// first packet was consumed while pumping ACK/flow-control progress.
    pub fn receivedStreamIdsInto(
        self: *const Connection,
        out: []u62,
    ) []u62 {
        return self.receivedStreamIdsFromInto(0, out);
    }

    /// Continue `receivedStreamIdsInto` from a physical stream-table offset.
    /// Returning fewer IDs than `out.len` means the current snapshot is fully
    /// scanned. The offset is deliberately opaque and only valid until another
    /// operation can append or reclaim a stream. New pagination code should use
    /// `receivedStreamIdsAfterInto`, whose ID cursor survives table mutation.
    pub fn receivedStreamIdsFromInto(
        self: *const Connection,
        start: usize,
        out: []u62,
    ) []u62 {
        if (start >= self.stream_recv_flows.items.len) return out[0..0];
        const remaining = self.stream_recv_flows.items.len - start;
        const count = @min(out.len, remaining);
        for (
            out[0..count],
            self.stream_recv_flows.items[start..][0..count],
        ) |
            *stream_id,
            entry,
        | {
            stream_id.* = @intCast(entry.stream_id);
        }
        return out[0..count];
    }

    /// Copy the lowest active receive-stream IDs strictly greater than
    /// `after`, in ascending order, without allocating. Unlike the legacy
    /// physical-offset cursor above, this continuation remains valid when a
    /// completed stream is removed with swap-remove between pages.
    pub fn receivedStreamIdsAfterInto(
        self: *const Connection,
        after: ?u62,
        out: []u62,
    ) []u62 {
        if (out.len == 0) return out[0..0];
        var count: usize = 0;
        for (self.stream_recv_flows.items) |entry| {
            const stream_id: u62 = @intCast(entry.stream_id);
            if (after) |previous| if (stream_id <= previous) continue;
            // Receive streams are normally appended in increasing ID order.
            // Reclamation can swap a later entry into the middle, so only the
            // ordered tail may bypass insertion; a full page still scans on
            // for smaller out-of-order IDs that must displace its current tail.
            if (count == 0 or stream_id > out[count - 1]) {
                if (count == out.len) continue;
                out[count] = stream_id;
                count += 1;
                continue;
            }
            var insert_at: usize = 0;
            while (insert_at < count and out[insert_at] < stream_id) {
                insert_at += 1;
            }
            if (insert_at == out.len) continue;
            if (count < out.len) count += 1;
            var move = count - 1;
            while (move > insert_at) : (move -= 1) {
                out[move] = out[move - 1];
            }
            out[insert_at] = stream_id;
        }
        return out[0..count];
    }

    /// Poll one receive stream with round-robin fairness.
    ///
    /// This method never reads the endpoint socket. It copies at most
    /// `out.len` contiguous bytes, returns their flow-control credit before
    /// success, reports FIN with the final data prefix (or one zero-byte
    /// event), and reports RESET_STREAM exactly once. Endpoint dispatchers can
    /// therefore process a packet and drain stream events without introducing
    /// a second UDP owner.
    pub fn pollStream(self: *Connection, out: []u8) Error!?StreamRead {
        if (out.len == 0) return error.BufferTooShort;
        const stream_count = self.stream_recv_flows.items.len;
        if (stream_count == 0) return null;
        const start = self.stream_poll_cursor % stream_count;
        for (0..stream_count) |step| {
            const index = (start + step) % stream_count;
            const entry = &self.stream_recv_flows.items[index];
            if (try self.pollStreamEntry(entry, out)) |event| {
                self.stream_poll_cursor = (index + 1) % stream_count;
                return event;
            }
        }
        return null;
    }

    /// Poll one known stream without allowing a busy sibling to consume the
    /// caller's scheduling turn. Unknown streams and streams with no newly
    /// reportable data or terminal state return null.
    pub fn pollStreamId(
        self: *Connection,
        stream_id: u62,
        out: []u8,
    ) Error!?StreamRead {
        if (out.len == 0) return error.BufferTooShort;
        const entry = self.findRecvStreamEntry(stream_id) orelse return null;
        return self.pollStreamEntry(entry, out);
    }

    pub fn receiveStream(self: *Connection, out: []u8) Error!StreamRead {
        while (true) {
            if (try self.pollStream(out)) |event| return event;
            try self.servicePacketServicingTimers();
        }
    }

    pub fn receiveStreamWithTimeout(
        self: *Connection,
        out: []u8,
        timeout: std.Io.Duration,
    ) (Error || quic.runtime.ReceiveTimeoutError)!StreamRead {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveStreamWithDeadline(
            out,
            .fromNow(
                self.endpoint.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    pub fn receiveStreamWithDeadline(
        self: *Connection,
        out: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!StreamRead {
        _ = try deadline_policy.usableAwake(self.endpoint.io, deadline);
        while (true) {
            if (try self.pollStream(out)) |event| return event;
            try self.servicePacketServicingTimersDeadline(deadline);
        }
    }

    pub fn receiveStreamId(
        self: *Connection,
        stream_id: u62,
        out: []u8,
    ) Error!StreamRead {
        while (true) {
            if (try self.pollStreamId(stream_id, out)) |event| return event;
            try self.servicePacketServicingTimers();
        }
    }

    pub fn receiveStreamIdWithTimeout(
        self: *Connection,
        stream_id: u62,
        out: []u8,
        timeout: std.Io.Duration,
    ) (Error || quic.runtime.ReceiveTimeoutError)!StreamRead {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveStreamIdWithDeadline(
            stream_id,
            out,
            .fromNow(
                self.endpoint.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    pub fn receiveStreamIdWithDeadline(
        self: *Connection,
        stream_id: u62,
        out: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!StreamRead {
        _ = try deadline_policy.usableAwake(self.endpoint.io, deadline);
        while (true) {
            if (try self.pollStreamId(stream_id, out)) |event| return event;
            try self.servicePacketServicingTimersDeadline(deadline);
        }
    }

    fn pollStreamEntry(
        self: *Connection,
        entry: *StreamRecvFlowEntry,
        out: []u8,
    ) Error!?StreamRead {
        const available = applicationAvailableStreamBytes(
            entry,
            self.config.enable_reset_partial_delivery,
        );
        if (entry.reset) |reset| reset: {
            if (self.config.enable_reset_partial_delivery and
                !entry.reset_reported and
                entry.reset_delivery_end.? > entry.recv_state.read_offset)
            {
                break :reset;
            }
            if (entry.reset_reported) return null;
            entry.reset_reported = true;
            return .{ .reset = .{
                .stream_id = @intCast(entry.stream_id),
                .application_error_code = reset.application_error_code,
                .final_size = reset.final_size,
            } };
        }
        if (entry.fin_reported) return null;
        if (available.len != 0) {
            const count = @min(out.len, available.len);
            @memcpy(out[0..count], available[0..count]);
            const fin = entry.reset == null and
                entry.recv_state.final_size != null and
                entry.recv_state.read_offset + count ==
                    entry.recv_state.final_size.?;
            try self.releaseReceivedCapacity(entry.stream_id, count);
            if (fin) entry.fin_reported = true;
            return .{ .data = .{
                .stream_id = @intCast(entry.stream_id),
                .bytes = count,
                .fin = fin,
            } };
        }
        if (entry.recv_state.complete()) {
            entry.fin_reported = true;
            return .{ .data = .{
                .stream_id = @intCast(entry.stream_id),
                .bytes = 0,
                .fin = true,
            } };
        }
        return null;
    }

    /// Copy the currently application-readable receive bytes for diagnostics
    /// and handshake-integrated early-data consumers. Reset partial-delivery
    /// boundaries match `availableReceivedStream`; retained late transport
    /// evidence remains visible only through stream statistics. The returned
    /// slice is owned by the caller; consuming flow-control credit remains
    /// explicit.
    pub fn copyReceivedStream(
        self: Connection,
        allocator: std.mem.Allocator,
        stream_id: u64,
    ) Error!?[]u8 {
        if (self.stream_recv_index.count() == 0) return null;
        const index = self.stream_recv_index.get(stream_id) orelse return null;
        if (index >= self.stream_recv_flows.items.len) return null;
        const entry = self.stream_recv_flows.items[index];
        if (entry.stream_id != stream_id) return null;
        return try allocator.dupe(
            u8,
            applicationAvailableStreamBytes(
                &entry,
                self.config.enable_reset_partial_delivery,
            ),
        );
    }

    pub fn streamStopped(self: Connection, stream_id: u64) ?StopSendingInfo {
        if (self.stream_send_index.count() == 0) return null;
        const index = self.stream_send_index.get(stream_id) orelse return null;
        if (index >= self.stream_send_flows.items.len) return null;
        const entry = self.stream_send_flows.items[index];
        if (entry.stream_id != stream_id) return null;
        return entry.stopped;
    }

    pub fn queuePathChallenge(self: *Connection, data: [8]u8) Error!void {
        _ = try self.path_validation.queueChallengeForPath(
            data,
            self.pmtu_path_epoch,
        );
    }

    pub fn peerActiveMigrationDisabled(self: Connection) bool {
        return self.config.peer_disable_active_migration;
    }

    pub fn localActiveMigrationDisabled(self: Connection) bool {
        return self.config.local_disable_active_migration;
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
        const new_peer = switch (family) {
            .ipv4 => preferredAddressIp4(preferred) orelse return error.InvalidTransportParameter,
            .ipv6 => preferredAddressIp6(preferred) orelse return error.InvalidTransportParameter,
        };
        var peer_connection_ids = self.peer_connection_ids;
        try peer_connection_ids.addWithLimit(1, preferred.connection_id, preferred.stateless_reset_token, self.config.active_connection_id_limit);
        try peer_connection_ids.markInUse(1);
        // RFC 9000 permits a client to use the server's preferred_address even
        // when disable_active_migration was advertised. That parameter only
        // prohibits other client-chosen addresses.
        try self.beginPeerMigrationInternal(new_peer, challenge, false);
        self.peer_preferred_address_migration_active = true;
        self.peer_connection_ids = peer_connection_ids;
        self.setPeerConnectionId(
            self.peer_connection_ids.activeConnectionId(
                preferred.connection_id,
            ).?,
        );
    }

    pub fn beginPeerMigration(self: *Connection, new_peer: net.IpAddress, challenge: [8]u8) Error!void {
        try self.beginPeerMigrationInternal(new_peer, challenge, true);
        self.peer_preferred_address_migration_active = false;
    }

    fn beginPeerMigrationInternal(
        self: *Connection,
        new_peer: net.IpAddress,
        challenge: [8]u8,
        enforce_peer_disable: bool,
    ) Error!void {
        if (enforce_peer_disable and self.config.peer_disable_active_migration) {
            return error.ActiveMigrationDisabled;
        }
        self.rememberCurrentValidatedPeerPath();
        // Queueing the validation challenge can allocate. Perform that
        // fallible work before committing any path state so an allocation
        // failure leaves the old peer, PMTU, congestion, and pacing state
        // intact.
        if (!try self.path_validation.queueChallengeForPath(
            challenge,
            nextPathEpoch(self.pmtu_path_epoch),
        )) return error.DuplicatePathChallenge;
        self.config.peer = new_peer;
        self.peer_address_validated = false;
        self.path_validation_retry_deadline_ns = null;
        const candidate = self.takeCandidatePathBudget(new_peer);
        self.peer_address_bytes_received = if (candidate) |budget|
            budget.bytes_received
        else
            0;
        self.peer_address_bytes_sent = if (candidate) |budget|
            budget.bytes_sent
        else
            0;
        self.resetRecoveryForPath(false);
        if (candidate) |state| {
            self.spin_bit_value = state.spin_bit_value;
            self.spin_largest_received_packet_number =
                state.spin_largest_received_packet_number;
        }
        self.path_validation.abandonPendingChallengesExceptPathEpoch(
            self.pmtu_path_epoch,
        );
    }

    pub fn sendPendingPathChallenge(self: *Connection) Error!void {
        try self.sendPendingPathChallengeAt(null, null);
    }

    pub fn sendPendingPathChallengeAt(self: *Connection, now_ns: ?u64, timeout_ns: ?u64) Error!void {
        try self.validateNextPacketNumber();
        var frames: [1]quic.Frame = undefined;
        if (try self.path_validation.prepareChallengeFrames(&frames) == 0) {
            return error.NoPendingPathChallenge;
        }
        var padded: [2]quic.Frame = undefined;
        const send_frames = try self.padPathValidationFrames(
            &frames,
            &padded,
        );
        const send_result = if (now_ns) |timestamp|
            self.sendAutomaticallyAt(send_frames, timestamp)
        else
            self.send(send_frames);
        send_result catch |err| {
            self.notePathValidationSendBlocked(err, now_ns);
            return err;
        };
        self.path_validation_retry_deadline_ns = null;
        self.path_validation.commitChallengeFrames(
            1,
            now_ns,
            timeout_ns,
            self.pmtu_path_epoch,
        );
    }

    pub fn sendPendingPathChallengesAt(self: *Connection, now_ns: ?u64, timeout_ns: ?u64) Error!usize {
        try self.validateNextPacketNumber();
        var frames: [8]quic.Frame = undefined;
        const count = try self.path_validation.prepareChallengeFrames(&frames);
        if (count == 0) return 0;
        var padded: [9]quic.Frame = undefined;
        const send_frames = try self.padPathValidationFrames(
            frames[0..count],
            &padded,
        );
        const send_result = if (now_ns) |timestamp|
            self.sendAutomaticallyAt(send_frames, timestamp)
        else
            self.send(send_frames);
        send_result catch |err| {
            self.notePathValidationSendBlocked(err, now_ns);
            return err;
        };
        self.path_validation_retry_deadline_ns = null;
        self.path_validation.commitChallengeFrames(
            count,
            now_ns,
            timeout_ns,
            self.pmtu_path_epoch,
        );
        return count;
    }

    pub fn pathValidationDeadline(self: *const Connection) ?u64 {
        return self.path_validation.earliestChallengeDeadline();
    }

    fn notePathValidationSendBlocked(
        self: *Connection,
        err: anyerror,
        now_ns: ?u64,
    ) void {
        if (err != error.AntiAmplificationLimited and
            err != error.CongestionLimited and
            err != error.PacingLimited) return;
        const now = now_ns orelse return;
        if (err == error.PacingLimited) {
            if (self.pacing_blocked_until_ns) |deadline| {
                if (deadline > now) {
                    self.path_validation_retry_deadline_ns = deadline;
                    return;
                }
            }
        }
        self.path_validation_retry_deadline_ns = std.math.add(
            u64,
            now,
            timer_blocked_receive_backoff_ns,
        ) catch std.math.maxInt(u64);
    }

    fn updatePathResponseTimerAfterSend(
        self: *Connection,
        sent_time_ns: ?u64,
    ) void {
        if (self.path_validation.pendingResponseCount() == 0) {
            self.path_response_retry_deadline_ns = null;
            self.path_response_retry_attempts = 0;
            return;
        }
        const now_ns = sent_time_ns orelse self.monotonicNowNs();
        self.path_response_retry_attempts = 0;
        self.path_response_retry_deadline_ns = std.math.add(
            u64,
            now_ns,
            timer_blocked_receive_backoff_ns,
        ) catch std.math.maxInt(u64);
    }

    fn schedulePathResponseRetry(
        self: *Connection,
        err: Error,
        now_ns: u64,
    ) void {
        if (self.path_validation.pendingResponseCount() == 0 or
            self.close_info != null or self.idle_timed_out)
        {
            self.path_response_retry_deadline_ns = null;
            self.path_response_retry_attempts = 0;
            return;
        }
        if (err == error.PacingLimited) {
            if (self.pacing_blocked_until_ns) |deadline| {
                if (deadline > now_ns) {
                    self.path_response_retry_deadline_ns = deadline;
                    return;
                }
            }
        }
        const index = @min(
            @as(usize, self.path_response_retry_attempts),
            stream_release_retry_backoff_ns.len - 1,
        );
        self.path_response_retry_attempts +|= 1;
        self.path_response_retry_deadline_ns = std.math.add(
            u64,
            now_ns,
            stream_release_retry_backoff_ns[index],
        ) catch std.math.maxInt(u64);
    }

    /// Number of path challenges queued or awaiting a response. This exposes
    /// whether a selected path is being validated without leaking the internal
    /// challenge payloads or queue representation.
    pub fn pendingPathValidationCount(self: Connection) usize {
        return self.path_validation.pendingChallengeCount() +
            self.path_validation.outstandingChallengeCount();
    }

    pub fn checkPathValidationTimeouts(self: *Connection, now_ns: u64) Error!usize {
        const result = try self.path_validation.checkTimeoutsForPathEpoch(
            now_ns,
            self.pmtu_path_epoch,
        );
        if (result.failed_current_path and
            !self.peer_address_validated and
            !self.path_validation.hasChallengeForPathEpoch(
                self.pmtu_path_epoch,
            ))
        {
            self.restoreLastValidatedPeerPath();
        }
        return result.expired;
    }

    fn restoreLastValidatedPeerPath(self: *Connection) void {
        const restored = self.last_validated_peer_path;
        self.peer_preferred_address_migration_active = false;
        self.config.peer = restored.peer;
        if (self.peer_connection_ids.selectForPath(
            restored.connectionId(),
        )) |connection_id| {
            self.setPeerConnectionId(connection_id);
        }
        self.peer_address_validated = true;
        self.peer_address_bytes_received = 0;
        self.peer_address_bytes_sent = 0;
        self.path_validation_retry_deadline_ns = null;
        self.resetRecoveryForPath(false);
        self.spin_bit_value = restored.spin_bit_value;
        self.spin_largest_received_packet_number =
            restored.spin_largest_received_packet_number;
        self.path_validation.abandonAllChallenges();
    }

    pub fn failedPathValidationCount(self: Connection) usize {
        return self.path_validation.failedChallengeCount();
    }

    pub fn sendPendingPathResponse(self: *Connection) Error!void {
        try self.sendPendingPathResponseAt(null);
    }

    fn sendPendingPathResponseAt(
        self: *Connection,
        sent_time_ns: ?u64,
    ) Error!void {
        try self.validateNextPacketNumber();
        var frame_storage: [1]quic.Frame = undefined;
        if (self.path_validation.peekResponseFrames(&frame_storage) == 0) {
            return error.NoPendingPathResponse;
        }
        const frame = frame_storage[0];
        const frames = [_]quic.Frame{frame};
        const target = self.peekPathResponseTarget() orelse self.config.peer;
        try self.sendPathValidationToPeerAt(target, &frames, sent_time_ns);
        self.path_validation.discardResponses(1);
        self.discardPathResponseTargets(1);
        self.updatePathResponseTimerAfterSend(sent_time_ns);
    }

    pub fn sendPendingPathResponses(self: *Connection) Error!usize {
        try self.validateNextPacketNumber();
        var frames: [8]quic.Frame = undefined;
        const count = self.path_validation.peekResponseFrames(&frames);
        if (count == 0) return 0;
        if (!self.pathResponseTargetsAllDefault(count)) {
            var sent: usize = 0;
            while (sent < count) : (sent += 1) {
                try self.sendPendingPathResponse();
            }
            return sent;
        }
        var padded: [9]quic.Frame = undefined;
        const send_frames = try self.padPathValidationFrames(
            frames[0..count],
            &padded,
        );
        try self.send(send_frames);
        self.path_validation.discardResponses(count);
        self.discardPathResponseTargets(count);
        self.updatePathResponseTimerAfterSend(null);
        return count;
    }

    fn sendToPeer(
        self: *Connection,
        peer: net.IpAddress,
        frames: []const quic.Frame,
    ) Error!void {
        const previous = self.config.peer;
        self.config.peer = peer;
        defer self.config.peer = previous;
        try self.send(frames);
    }

    fn sendPathValidationToPeer(
        self: *Connection,
        peer: net.IpAddress,
        frames: []const quic.Frame,
    ) Error!void {
        return self.sendPathValidationToPeerAt(peer, frames, null);
    }

    fn sendPathValidationToPeerAt(
        self: *Connection,
        peer: net.IpAddress,
        frames: []const quic.Frame,
        sent_time_ns: ?u64,
    ) Error!void {
        if (peer.eql(&self.config.peer)) {
            var padded: [9]quic.Frame = undefined;
            const send_frames = try self.padPathValidationFrames(
                frames,
                &padded,
            );
            return if (sent_time_ns) |now_ns|
                self.sendAutomaticallyAt(send_frames, now_ns)
            else
                self.send(send_frames);
        }
        if (peer.eql(&self.last_validated_peer_path.peer)) {
            const previous_peer = self.config.peer;
            var previous_peer_connection_id: [
                quic.connection_id.max_connection_id_len
            ]u8 = undefined;
            const previous_peer_connection_id_len =
                self.config.peer_connection_id.len;
            @memcpy(
                previous_peer_connection_id[0..previous_peer_connection_id_len],
                self.config.peer_connection_id,
            );
            const previous_spin_bit_value = self.spin_bit_value;
            const previous_spin_largest_received_packet_number =
                self.spin_largest_received_packet_number;
            const previous_validated = self.peer_address_validated;
            const previous_received = self.peer_address_bytes_received;
            const previous_sent = self.peer_address_bytes_sent;
            self.config.peer = peer;
            if (self.peer_connection_ids.activeConnectionId(
                self.last_validated_peer_path.connectionId(),
            )) |connection_id| {
                self.setPeerConnectionId(connection_id);
            }
            self.peer_address_validated = true;
            self.peer_address_bytes_received = 0;
            self.peer_address_bytes_sent = 0;
            self.spin_bit_value =
                self.last_validated_peer_path.spin_bit_value;
            self.spin_largest_received_packet_number =
                self.last_validated_peer_path
                    .spin_largest_received_packet_number;
            defer {
                self.config.peer = previous_peer;
                self.setPeerConnectionId(
                    previous_peer_connection_id[0..previous_peer_connection_id_len],
                );
                self.spin_bit_value = previous_spin_bit_value;
                self.spin_largest_received_packet_number =
                    previous_spin_largest_received_packet_number;
                self.peer_address_validated = previous_validated;
                self.peer_address_bytes_received = previous_received;
                self.peer_address_bytes_sent = previous_sent;
            }
            var padded: [9]quic.Frame = undefined;
            const send_frames = try self.padPathValidationFrames(
                frames,
                &padded,
            );
            return if (sent_time_ns) |now_ns|
                self.sendAutomaticallyAt(send_frames, now_ns)
            else
                self.send(send_frames);
        }
        if (self.config.local_endpoint != .server) {
            const previous_peer = self.config.peer;
            const previous_spin_bit_value = self.spin_bit_value;
            const previous_spin_largest_received_packet_number =
                self.spin_largest_received_packet_number;
            self.config.peer = peer;
            self.resetSpinBit();
            defer {
                self.config.peer = previous_peer;
                self.spin_bit_value = previous_spin_bit_value;
                self.spin_largest_received_packet_number =
                    previous_spin_largest_received_packet_number;
            }
            var padded: [9]quic.Frame = undefined;
            const send_frames = try self.padPathValidationFrames(
                frames,
                &padded,
            );
            return if (sent_time_ns) |now_ns|
                self.sendAutomaticallyAt(send_frames, now_ns)
            else
                self.send(send_frames);
        }
        const index = self.findCandidatePathBudget(peer) orelse
            return error.AntiAmplificationLimited;
        const previous_peer = self.config.peer;
        const previous_spin_bit_value = self.spin_bit_value;
        const previous_spin_largest_received_packet_number =
            self.spin_largest_received_packet_number;
        const previous_validated = self.peer_address_validated;
        const previous_received = self.peer_address_bytes_received;
        const previous_sent = self.peer_address_bytes_sent;
        self.config.peer = peer;
        self.peer_address_validated = false;
        self.peer_address_bytes_received =
            self.candidate_path_budgets[index].?.bytes_received;
        self.peer_address_bytes_sent =
            self.candidate_path_budgets[index].?.bytes_sent;
        self.spin_bit_value =
            self.candidate_path_budgets[index].?.spin_bit_value;
        self.spin_largest_received_packet_number =
            self.candidate_path_budgets[index].?
                .spin_largest_received_packet_number;
        defer {
            self.candidate_path_budgets[index].?.bytes_received =
                self.peer_address_bytes_received;
            self.candidate_path_budgets[index].?.bytes_sent =
                self.peer_address_bytes_sent;
            self.candidate_path_budgets[index].?.spin_bit_value =
                self.spin_bit_value;
            self.candidate_path_budgets[index].?
                .spin_largest_received_packet_number =
                self.spin_largest_received_packet_number;
            self.config.peer = previous_peer;
            self.spin_bit_value = previous_spin_bit_value;
            self.spin_largest_received_packet_number =
                previous_spin_largest_received_packet_number;
            self.peer_address_validated = previous_validated;
            self.peer_address_bytes_received = previous_received;
            self.peer_address_bytes_sent = previous_sent;
        }
        var padded: [9]quic.Frame = undefined;
        const send_frames = try self.padPathValidationFrames(frames, &padded);
        if (sent_time_ns) |now_ns|
            try self.sendAutomaticallyAt(send_frames, now_ns)
        else
            try self.send(send_frames);
    }

    fn padPathValidationFrames(
        self: *Connection,
        frames: []const quic.Frame,
        storage: []quic.Frame,
    ) Error![]const quic.Frame {
        if (self.currentSendDatagramSize() < quic.pmtu.min_udp_payload_size) {
            return error.DatagramTooLarge;
        }
        if (storage.len < frames.len + 1) return error.BufferTooShort;
        var payload_len: usize = 0;
        for (frames) |frame| {
            payload_len = std.math.add(
                usize,
                payload_len,
                try frame.wireLen(),
            ) catch return error.InvalidFrameLength;
        }
        if (self.handshake_status.needsHandshakeDone() and
            !frame_traits.containsHandshakeDone(frames))
        {
            payload_len = std.math.add(usize, payload_len, 1) catch
                return error.InvalidFrameLength;
        }
        const packet_number_len = quic.protection.packetNumberLen(
            self.next_packet_number,
            self.sent.largestAcknowledged(),
        );
        const overhead = try quic.protection.shortPacketLenForPayloadLen(
            self.config.peer_connection_id.len,
            self.next_packet_number,
            packet_number_len,
            0,
        );
        if (overhead + payload_len >= quic.pmtu.min_udp_payload_size) {
            return frames;
        }
        @memcpy(storage[0..frames.len], frames);
        storage[frames.len] = .{ .padding = .{
            .len = quic.pmtu.min_udp_payload_size - overhead - payload_len,
        } };
        return storage[0 .. frames.len + 1];
    }

    fn peekPathResponseTarget(self: Connection) ?net.IpAddress {
        if (self.pathResponseTargetCount() == 0) return null;
        return self.path_response_targets.items[self.path_response_target_head];
    }

    fn pathResponseTargetsAllDefault(self: Connection, count: usize) bool {
        if (self.pathResponseTargetCount() < count) return false;
        for (self.path_response_targets.items[self.path_response_target_head..][0..count]) |target| {
            if (target) |peer| {
                if (!peer.eql(&self.config.peer)) return false;
            }
        }
        return true;
    }

    fn pathResponseTargetCount(self: Connection) usize {
        return self.path_response_targets.items.len - self.path_response_target_head;
    }

    fn discardPathResponseTargets(self: *Connection, count: usize) void {
        if (count == 0 or self.pathResponseTargetCount() == 0) return;
        if (count >= self.pathResponseTargetCount()) {
            self.path_response_targets.clearRetainingCapacity();
            self.path_response_target_head = 0;
            return;
        }
        self.path_response_target_head += count;
        self.compactPathResponseTargetsIfSparse();
    }

    fn compactPathResponseTargetsIfSparse(self: *Connection) void {
        if (self.path_response_target_head == 0) return;
        if (self.path_response_target_head == self.path_response_targets.items.len or
            self.path_response_target_head >= self.path_response_targets.items.len / 2)
        {
            self.compactPathResponseTargets();
        }
    }

    fn compactPathResponseTargets(self: *Connection) void {
        if (self.path_response_target_head == 0) return;
        const remaining = self.pathResponseTargetCount();
        if (remaining != 0) {
            @memmove(
                self.path_response_targets.items[0..remaining],
                self.path_response_targets.items[self.path_response_target_head..],
            );
        }
        self.path_response_targets.items.len = remaining;
        self.path_response_target_head = 0;
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
        try self.closeLocally(.{
            .application = false,
            .error_code = error_code,
            .frame_type = frame_type,
            .reason_phrase = reason_phrase,
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
        try self.closeLocally(.{
            .application = true,
            .error_code = error_code,
            .reason_phrase = reason_phrase,
            .now_ms = now_ms,
            .pto_ms = pto_ms,
        });
    }

    /// Retire a connection locally without attempting another socket write.
    /// Protocol adapters use this after a multi-packet logical write exposed a
    /// prefix and then exhausted its caller-owned deadline. Retrying would
    /// corrupt stream offsets, while sending CONNECTION_CLOSE here could itself
    /// wait beyond that deadline. Allocation failure still leaves the
    /// connection terminal through the idle-timeout sentinel.
    pub fn failClosedApplication(
        self: *Connection,
        error_code: u64,
        reason_phrase: []const u8,
    ) void {
        if (self.close_info != null or self.idle_timed_out) return;
        self.setCloseInfo(.{
            .application = true,
            .error_code = error_code,
            .reason_phrase = reason_phrase,
            .state = .closing,
        }) catch {
            self.idle_timed_out = true;
            return;
        };
        self.close_info.?.state = .closed;
        self.close_info.?.response_deadline_ns = null;
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

    pub fn closeExpiryDeadlineMillis(self: *const Connection) ?u64 {
        return if (self.close_info) |close_info| close_info.expires_ms else null;
    }

    fn closeResponseDeadline(self: *const Connection) ?u64 {
        const close_info = self.close_info orelse return null;
        if (close_info.state != .closing) return null;
        return close_info.response_deadline_ns;
    }

    /// Return the first peer CONNECTION_CLOSE observed by this connection.
    ///
    /// Local close state is replaced with the peer's diagnostics when the peer
    /// replies while we are closing. This keeps the snapshot unambiguous and
    /// is safe because a draining endpoint can no longer retransmit its local
    /// close frame.
    pub fn peerCloseInfo(self: *const Connection) ?PeerCloseInfo {
        const close_info = self.close_info orelse return null;
        if (!self.peer_close_frame_received) return null;
        if (close_info.application) {
            return .{ .application = .{
                .error_code = close_info.error_code,
                .reason_phrase = close_info.reason_phrase,
            } };
        }
        return .{ .transport = .{
            .error_code = close_info.error_code,
            .frame_type = close_info.frame_type,
            .reason_phrase = close_info.reason_phrase,
        } };
    }

    pub fn checkCloseExpired(self: *Connection, now_ms: u64) bool {
        if (self.close_info) |*close_info| {
            const deadline = close_info.expires_ms orelse return false;
            if (now_ms < deadline) return false;
            close_info.state = .closed;
            close_info.response_deadline_ns = null;
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
        return try self.sent.ackRttSampleForPathEpoch(
            ack,
            now_ns,
            self.config.peer_ack_delay_exponent,
            self.pmtu_path_epoch,
        );
    }

    pub fn updateRttFromAck(self: *Connection, ack: quic.AckFrame, now_ns: u64) Error!bool {
        const sample = try self.ackRttSample(ack, now_ns) orelse return false;
        self.rtt_stats.updateAt(
            sample.latest_rtt_ns,
            sample.ack_delay_ns,
            self.handshake_status.isConfirmed(),
            sample.sent_time_ns,
        );
        self.congestion.onRttSample(sample.largest_acknowledged, sample.latest_rtt_ns);
        return true;
    }

    pub fn persistentCongestionPeriod(self: Connection) ?quic.packet_space.SentPacketTracker.PersistentCongestionPeriod {
        const largest = self.sent.largestAcknowledged() orelse return null;
        const period = self.sent.persistentCongestionPeriodForPathEpoch(
            self.rtt_stats.first_rtt_sample_sent_time_ns,
            largest,
            self.last_persistent_congestion_packet_number,
            self.pmtu_path_epoch,
        ) orelse return null;
        if (period.durationNs() <= self.rtt_stats.persistentCongestionThreshold()) return null;
        return period;
    }

    /// Effective idle timeout in milliseconds after applying RFC 9000 §10.1.
    ///
    /// The transport parameters select the smaller non-zero advertised value,
    /// but that value is only a preference: endpoints MUST raise it to at least
    /// three times the current base PTO. Established application-data PTO
    /// includes the peer's max_ack_delay but excludes exponential backoff,
    /// matching tquic and s2n-quic's negotiated idle-timer calculation.
    pub fn effectiveIdleTimeoutMillis(self: *const Connection) ?u64 {
        const local = self.config.local_max_idle_timeout_ms;
        const peer = self.config.peer_max_idle_timeout_ms;
        if (local == 0 and peer == 0) return null;
        const negotiated = if (local == 0)
            peer
        else if (peer == 0)
            local
        else
            @min(local, peer);
        const minimum_ns = std.math.mul(
            u64,
            self.rtt_stats.pto(true),
            3,
        ) catch std.math.maxInt(u64);
        const minimum_ms = std.math.divCeil(
            u64,
            minimum_ns,
            std.time.ns_per_ms,
        ) catch std.math.maxInt(u64);
        return @max(negotiated, minimum_ms);
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

    pub fn idleTimeoutDeadlineMillis(self: *const Connection) ?u64 {
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
        try self.validateLocalStatelessResetToken(
            connection_id,
            stateless_reset_token,
        );
        try self.validateLocalConnectionIdIssueLimit(0);
        try self.validateNextPacketNumber();
        const pool_before = self.local_connection_ids;
        errdefer self.local_connection_ids = pool_before;
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
        try self.validateLocalStatelessResetToken(
            connection_id,
            stateless_reset_token,
        );
        try self.validateLocalConnectionIdIssueLimit(retire_prior_to);
        try self.validateNextPacketNumber();
        const pool_before = self.local_connection_ids;
        errdefer self.local_connection_ids = pool_before;
        const frame = try self.local_connection_ids.issueWithRetirePriorTo(connection_id, stateless_reset_token, retire_prior_to);
        const frames = [_]quic.Frame{frame};
        try self.send(&frames);
    }

    fn validateLocalStatelessResetToken(
        self: *const Connection,
        connection_id: []const u8,
        token: [quic.stateless_reset.token_len]u8,
    ) Error!void {
        const key = self.config.local_stateless_reset_key orelse return;
        const expected = quic.stateless_reset.tokenForConnectionId(
            key,
            connection_id,
        );
        if (!std.mem.eql(u8, &token, &expected)) {
            return error.InvalidResetToken;
        }
    }

    pub fn sendNewConnectionIdWithDerivedToken(self: *Connection, connection_id: []const u8) Error!void {
        const key = self.config.local_stateless_reset_key orelse return error.InvalidConnectionId;
        try self.validateLocalConnectionIdIssueLimit(0);
        try self.validateNextPacketNumber();
        const pool_before = self.local_connection_ids;
        errdefer self.local_connection_ids = pool_before;
        const frame = try self.local_connection_ids.issueWithStaticKey(connection_id, key);
        const frames = [_]quic.Frame{frame};
        try self.send(&frames);
    }

    pub fn sendNewConnectionIdWithDerivedTokenRetiringPriorTo(
        self: *Connection,
        connection_id: []const u8,
        retire_prior_to: u64,
    ) Error!void {
        const key = self.config.local_stateless_reset_key orelse return error.InvalidConnectionId;
        try self.validateLocalConnectionIdIssueLimit(retire_prior_to);
        try self.validateNextPacketNumber();
        const pool_before = self.local_connection_ids;
        errdefer self.local_connection_ids = pool_before;
        const frame = try self.local_connection_ids
            .issueWithStaticKeyRetirePriorTo(
            connection_id,
            key,
            retire_prior_to,
        );
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
        const effective = self.local_connection_ids
            .effectiveRetirePriorTo(retire_prior_to);
        if (self.local_connection_ids.countAfterRetirePriorTo(effective) >= self.config.peer_active_connection_id_limit) {
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
        self.setPeerConnectionId(entry.slice());
        self.resetSpinValueForConnectionId();
        self.rememberCurrentValidatedPeerPath();
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

    pub fn handshakeConfirmed(self: *const Connection) bool {
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

    pub fn oneRttKeyDiscardDeadline(self: *const Connection) ?i64 {
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

    /// Retain the application-data suffix of a coalesced handshake datagram.
    ///
    /// QUIC short headers carry no packet length, so this slice must be the last
    /// packet in its UDP datagram. It is intentionally consumed through the
    /// normal receive pipeline later, allowing HTTP/3 to observe its STREAM
    /// frames while transport state is updated exactly once.
    pub fn preloadReceivedDatagram(
        self: *Connection,
        from: net.IpAddress,
        bytes: []const u8,
        ecn: quic.packet_space.EcnCodepoint,
    ) Error!void {
        if (bytes.len == 0 or self.pending_received_datagram != null) {
            return error.InvalidPacket;
        }
        self.pending_received_datagram = .{
            .from = from,
            .bytes = try self.endpoint.allocator.dupe(u8, bytes),
            .ecn = ecn,
        };
        if (self.pending_datagram_observer) |observer| {
            observer.notify(observer.context, observer.connection_handle);
        }
    }

    pub fn canBindPendingDatagramObserver(
        self: Connection,
        context: *anyopaque,
        connection_handle: usize,
        notify: *const fn (*anyopaque, usize) void,
    ) bool {
        const observer = self.pending_datagram_observer orelse return true;
        return observer.context == context and
            observer.connection_handle == connection_handle and
            observer.notify == notify;
    }

    pub fn bindPendingDatagramObserver(
        self: *Connection,
        context: *anyopaque,
        connection_handle: usize,
        notify: *const fn (*anyopaque, usize) void,
    ) PendingDatagramObserverError!void {
        if (!self.canBindPendingDatagramObserver(
            context,
            connection_handle,
            notify,
        )) return error.PendingDatagramObserverBound;
        if (self.pending_datagram_observer != null) return;
        self.pending_datagram_observer = .{
            .context = context,
            .connection_handle = connection_handle,
            .notify = notify,
        };
        if (self.pending_received_datagram != null) {
            notify(context, connection_handle);
        }
    }

    pub fn unbindPendingDatagramObserver(
        self: *Connection,
        context: *anyopaque,
        connection_handle: usize,
    ) bool {
        const observer = self.pending_datagram_observer orelse return false;
        if (observer.context != context or
            observer.connection_handle != connection_handle) return false;
        self.pending_datagram_observer = null;
        return true;
    }

    fn takePendingReceivedDatagram(
        self: *Connection,
    ) ?quic.runtime.OwnedBytes {
        const pending = self.pending_received_datagram orelse return null;
        self.pending_received_datagram = null;
        return pending;
    }

    /// Decode one application packet retained behind the peer's Handshake
    /// flight without performing a socket read. Endpoint dispatchers call this
    /// immediately after promoting a completed server handshake.
    pub fn receivePendingPacket(
        self: *Connection,
    ) Error!?ReceivedPacket {
        if (self.pending_received_datagram == null) return null;
        return try self.receivePendingPacketAt(self.monotonicNowNs());
    }

    fn receivePendingPacketAt(
        self: *Connection,
        now_ns: ?u64,
    ) Error!?ReceivedPacket {
        var pending = self.takePendingReceivedDatagram() orelse return null;
        defer pending.deinit(self.endpoint.allocator);
        return try self.processReceivedBytesOrDropPeerAddressAt(
            pending.from,
            pending.bytes,
            pending.ecn,
            now_ns,
        );
    }

    fn receivePendingPacketBatchAt(
        self: *Connection,
        now_ns: ?u64,
    ) Error!?ReceivedPacketBatch {
        var packet = (try self.receivePendingPacketAt(now_ns)) orelse
            return null;
        errdefer packet.deinit(self.endpoint.allocator);
        const packets = try self.endpoint.allocator.alloc(ReceivedPacket, 1);
        packets[0] = packet;
        return .{ .allocator = self.endpoint.allocator, .packets = packets };
    }

    /// Receive one packet while continuing to service QUIC timers.
    ///
    /// Blocking HTTP/3 helpers use this when they are waiting for ACK,
    /// MAX_STREAM_DATA, or response progress.  A plain blocking socket read can
    /// deadlock if the next action is local timer work (ACK-delay expiry, PTO
    /// retransmission, loss detection, keep-alive, or idle timeout) rather than
    /// an already queued datagram.  This helper arms the socket receive with
    /// the next transport deadline, services the timer on timeout, and then
    /// resumes waiting.
    pub fn receivePacketServicingTimers(self: *Connection) Error!ReceivedPacket {
        return self.receivePacketServicingTimersUntil(null) catch |err|
            switch (err) {
                error.Timeout, error.ConcurrencyUnavailable => unreachable,
                else => |other| return @errorCast(other),
            };
    }

    /// Receive one packet while servicing QUIC timers, bounded by an
    /// application deadline that transport timers cannot extend.
    pub fn receivePacketServicingTimersTimeout(
        self: *Connection,
        timeout: std.Io.Timeout,
    ) (Error || quic.runtime.ReceiveTimeoutError)!ReceivedPacket {
        const caller_deadline = callerDeadlineFromTimeout(
            self.endpoint.io,
            timeout,
        );
        return self.receivePacketServicingTimersUntil(
            caller_deadline,
        );
    }

    pub fn receivePacketServicingTimersDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!ReceivedPacket {
        return self.receivePacketServicingTimersUntil(
            try deadline_policy.usableAwake(self.endpoint.io, deadline),
        );
    }

    fn receivePacketServicingTimersUntil(
        self: *Connection,
        caller_deadline: ?std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!ReceivedPacket {
        const now_ns = self.monotonicNowNs();
        if (try self.receivePendingPacketAt(now_ns)) |packet|
            return packet;
        if (callerDeadlineExpired(caller_deadline, now_ns)) {
            return error.Timeout;
        }
        while (true) {
            var datagram = try self.receiveBytesServicingTimersUntil(
                caller_deadline,
            );
            defer datagram.deinit(self.endpoint.allocator);
            // Once 1-RTT keys are installed, retransmitted Initial/Handshake
            // datagrams belong to discarded packet-number spaces. RFC 9001
            // requires silently discarding them; feeding their long header to
            // the short-header decoder incorrectly turns ordinary handshake
            // loss recovery into an application receive failure.
            if (isDiscardedLongHeaderPacket(datagram.bytes)) continue;
            var packet = (try self.processReceivedBytesOrDropPeerAddressAt(
                datagram.from,
                datagram.bytes,
                datagram.ecn,
                self.monotonicNowNs(),
            )) orelse continue;
            errdefer packet.deinit(self.endpoint.allocator);
            _ = try self.retransmitPacketThresholdLosses(max_batch_packets);
            return packet;
        }
    }

    /// Wait for raw packet storage while keeping all connection timers live.
    ///
    /// Both owning receives and borrowed visitors use this single scheduler so
    /// PTO, delayed ACK, pacing, keep-alive, and idle-timeout behavior cannot
    /// drift when an upper-layer protocol changes its packet ownership model.
    fn receiveBytesServicingTimers(
        self: *Connection,
    ) Error!quic.runtime.OwnedBytes {
        return self.receiveBytesServicingTimersUntil(null) catch |err|
            switch (err) {
                error.Timeout, error.ConcurrencyUnavailable => unreachable,
                else => |other| return @errorCast(other),
            };
    }

    fn receiveBytesServicingTimersUntil(
        self: *Connection,
        caller_deadline: ?std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!quic.runtime.OwnedBytes {
        while (true) {
            if (self.close_info != null or self.idle_timed_out) {
                return error.ConnectionClosed;
            }
            const now_ns = self.monotonicNowNs();
            if (callerDeadlineExpired(caller_deadline, now_ns)) {
                return error.Timeout;
            }
            const timer = self.nextTimerDeadline();
            if (timer) |scheduled| if (now_ns >= scheduled.deadline_ns) {
                if (try self.serviceNextTimerForBlockingReceive(
                    now_ns,
                    caller_deadline,
                )) {
                    continue;
                }
                if (try self.receiveBytesAfterBlockedTimer(
                    now_ns,
                    caller_deadline,
                )) |datagram| {
                    return datagram;
                }
                continue;
            };
            const receive_timeout = earliestConnectionReceiveTimeout(
                timer,
                caller_deadline,
            );
            if (receive_timeout == .none) return self.endpoint.receiveBytes();
            return self.endpoint.receiveBytesTimeout(receive_timeout) catch |err| switch (err) {
                error.Timeout => {
                    const timeout_ns = self.monotonicNowNs();
                    if (callerDeadlineExpired(
                        caller_deadline,
                        timeout_ns,
                    )) return error.Timeout;
                    if (!try self.serviceNextTimerForBlockingReceive(
                        timeout_ns,
                        caller_deadline,
                    )) {
                        if (try self.receiveBytesAfterBlockedTimer(
                            timeout_ns,
                            caller_deadline,
                        )) |datagram| {
                            return datagram;
                        }
                    }
                    continue;
                },
                // Some std.Io backends cannot provide a timed network wait.
                // A plain receive still preserves transport correctness; only
                // the unavailable backend's timer wake-up precision is lost.
                error.ConcurrencyUnavailable => if (caller_deadline == null)
                    self.endpoint.receiveBytes()
                else
                    error.ConcurrencyUnavailable,
                else => |other| return @errorCast(other),
            };
        }
    }

    fn serviceNextTimerForBlockingReceive(
        self: *Connection,
        now_ns: u64,
        caller_deadline: ?std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!bool {
        _ = self.serviceNextTimerAt(now_ns) catch |err| switch (err) {
            error.CongestionLimited => return false,
            error.AntiAmplificationLimited => return false,
            error.PacingLimited => {
                if (caller_deadline) |deadline| {
                    try self.waitForPacingAvailabilityWithDeadline(deadline);
                } else {
                    try self.waitForPacing(now_ns);
                }
                return true;
            },
            else => |other| return other,
        };
        return true;
    }

    fn receiveBytesAfterBlockedTimer(
        self: *Connection,
        now_ns: u64,
        caller_deadline: ?std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!?quic.runtime.OwnedBytes {
        const deadline_ns = std.math.add(
            u64,
            now_ns,
            timer_blocked_receive_backoff_ns,
        ) catch std.math.maxInt(u64);
        const timeout = earliestConnectionReceiveTimeout(
            .{ .kind = .loss_time, .deadline_ns = deadline_ns },
            caller_deadline,
        );
        const datagram = self.endpoint.receiveBytesTimeout(timeout) catch |err| switch (err) {
            error.Timeout => {
                if (callerDeadlineExpired(
                    caller_deadline,
                    self.monotonicNowNs(),
                )) return error.Timeout;
                return null;
            },
            error.ConcurrencyUnavailable => {
                if (caller_deadline != null) {
                    return error.ConcurrencyUnavailable;
                }
                return try self.endpoint.receiveBytes();
            },
            else => |other| return @errorCast(other),
        };
        return @as(?quic.runtime.OwnedBytes, datagram);
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
        if (try self.receivePendingPacketAt(now_ns)) |packet| return packet;
        while (true) {
            var datagram = try self.endpoint.receiveBytes();
            defer datagram.deinit(self.endpoint.allocator);
            if (isDiscardedLongHeaderPacket(datagram.bytes)) continue;
            return (try self.processReceivedBytesOrDropPeerAddressAt(
                datagram.from,
                datagram.bytes,
                datagram.ecn,
                now_ns,
            )) orelse continue;
        }
    }

    /// Receive one 1-RTT packet with a caller-supplied socket timeout.
    ///
    /// This is the non-blocking/event-loop counterpart to `receivePacket`.
    /// Callers that drive their own scheduling can poll for ACKs or peer
    /// DATAGRAM/STREAM progress without relying on the timer-servicing
    /// blocking helper. The timeout covers only the UDP receive; authenticated
    /// packets still pass through the normal path validation, packet-number,
    /// recovery, flow-control, and frame-routing pipeline.
    pub fn receivePacketTimeout(
        self: *Connection,
        timeout: std.Io.Timeout,
    ) (Error || quic.runtime.ReceiveTimeoutError)!ReceivedPacket {
        if (self.close_info != null or self.idle_timed_out) {
            return error.ConnectionClosed;
        }
        if (try self.receivePendingPacketAt(self.monotonicNowNs())) |packet|
            return packet;
        const deadline = timeout.toDeadline(self.endpoint.io);
        while (true) {
            var datagram = try self.endpoint.receiveBytesTimeout(deadline);
            defer datagram.deinit(self.endpoint.allocator);
            if (isDiscardedLongHeaderPacket(datagram.bytes)) continue;
            return (try self.processReceivedBytesOrDropPeerAddressAt(
                datagram.from,
                datagram.bytes,
                datagram.ecn,
                self.monotonicNowNs(),
            )) orelse continue;
        }
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
        return self.importSentEarlyDataCopies(packet_number, 1, frames);
    }

    fn earlyDataPacketNumber(
        first_packet_number: u64,
        sent_packet_numbers: ?[]const u64,
        index: usize,
    ) u64 {
        if (sent_packet_numbers) |numbers| return numbers[index];
        return first_packet_number + index;
    }

    /// Import a contiguous set of socket-sent 0-RTT copies. This compatibility
    /// entry point has no protected-but-unsent holes.
    pub fn importSentEarlyDataCopies(
        self: *Connection,
        first_packet_number: u64,
        packet_count: u64,
        frames: []const quic.Frame,
    ) Error!void {
        return self.importSentEarlyDataPacketNumbers(
            first_packet_number,
            packet_count,
            null,
            null,
            frames,
        );
    }

    /// Import socket-sent 0-RTT copies while retiring the complete protected
    /// packet-number interval. The optional number slice must be a strictly
    /// increasing subset of that interval. Null denotes the full interval.
    pub fn importSentEarlyDataPacketNumbers(
        self: *Connection,
        first_packet_number: u64,
        protected_count: u64,
        sent_packet_numbers: ?[]const u64,
        sent_datagram_size: ?usize,
        frames: []const quic.Frame,
    ) Error!void {
        if (protected_count == 0) return error.InvalidPacketNumber;
        const last_packet_number = std.math.add(
            u64,
            first_packet_number,
            protected_count - 1,
        ) catch return error.InvalidPacketNumber;
        if (last_packet_number > quic.protection.max_packet_number or
            first_packet_number != self.next_packet_number)
        {
            return error.InvalidPacketNumber;
        }
        const sent_count = if (sent_packet_numbers) |numbers|
            numbers.len
        else
            std.math.cast(usize, protected_count) orelse
                return error.InvalidPacketNumber;
        if (sent_count == 0 or
            @as(u64, @intCast(sent_count)) > protected_count)
        {
            return error.InvalidPacketNumber;
        }
        if (sent_packet_numbers) |numbers| {
            var previous: ?u64 = null;
            for (numbers) |packet_number| {
                if (packet_number < first_packet_number or
                    packet_number > last_packet_number or
                    (previous != null and packet_number <= previous.?))
                {
                    return error.InvalidPacketNumber;
                }
                previous = packet_number;
            }
        }
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(self.endpoint.allocator);
        var stream_bytes: u64 = 0;
        for (frames) |frame| {
            try quic.validateFrameForPacketType(frame, .zero_rtt);
            try frame.write(&payload, self.endpoint.allocator);
            if (frame != .stream) continue;
            try self.validateStreamFrameForSendAt(frame.stream, null);
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

        const analyzed = try frame_traits.analyze(frames);
        const is_ack_eliciting = analyzed.ack_eliciting;
        var recovery_payload: std.ArrayList(u8) = .empty;
        defer recovery_payload.deinit(self.endpoint.allocator);
        for (frames) |frame| {
            if (frame_traits.classify(frame).retransmittable) {
                try frame.write(&recovery_payload, self.endpoint.allocator);
            }
        }
        if (recovery_payload.items.len == 0 and is_ack_eliciting) {
            // Imported 0-RTT has no retained send timestamp, so it cannot use
            // the ordinary pure-DATAGRAM PTO fallback. Associate a synthetic
            // PING with the original packet number; ACK retires it normally
            // and PTO never replays the unreliable application payload.
            try (quic.Frame{ .ping = {} }).write(
                &recovery_payload,
                self.endpoint.allocator,
            );
        }
        const is_in_flight = analyzed.in_flight;
        if (recovery_payload.items.len != 0) {
            _ = try self.recovery.trackSent(
                earlyDataPacketNumber(
                    first_packet_number,
                    sent_packet_numbers,
                    0,
                ),
                recovery_payload.items,
            );
        }
        var tracked_recovery_packets: usize = @intFromBool(
            recovery_payload.items.len != 0,
        );
        errdefer while (tracked_recovery_packets != 0) {
            tracked_recovery_packets -= 1;
            _ = self.recovery.forgetPacketNumber(
                earlyDataPacketNumber(
                    first_packet_number,
                    sent_packet_numbers,
                    tracked_recovery_packets,
                ),
            );
        };
        if (recovery_payload.items.len != 0) {
            const candidate = self.recovery.packetNumberCandidate(
                earlyDataPacketNumber(
                    first_packet_number,
                    sent_packet_numbers,
                    0,
                ),
            ) orelse unreachable;
            var copy_index: usize = 1;
            while (copy_index < sent_count) : (copy_index += 1) {
                try self.recovery.recordRetransmission(
                    candidate.group_index,
                    earlyDataPacketNumber(
                        first_packet_number,
                        sent_packet_numbers,
                        copy_index,
                    ),
                );
                tracked_recovery_packets += 1;
            }
        }
        var tracked_sent_packets: usize = 0;
        errdefer while (tracked_sent_packets != 0) {
            tracked_sent_packets -= 1;
            _ = self.sent.forget(
                earlyDataPacketNumber(
                    first_packet_number,
                    sent_packet_numbers,
                    tracked_sent_packets,
                ),
            );
        };
        // Exact 0-RTT transmission times are not retained by the synchronous
        // handshake. Anchor every imported copy at handoff time: this is
        // conservative for loss detection and, unlike a null timestamp, keeps
        // unacknowledged sibling copies on a finite recovery timer after any
        // one copy retires the shared payload group.
        const imported_sent_time_ns = self.monotonicNowNs();
        var packet_index: usize = 0;
        while (packet_index < sent_count) : (packet_index += 1) {
            const packet_number = earlyDataPacketNumber(
                first_packet_number,
                sent_packet_numbers,
                packet_index,
            );
            const packet_number_len = quic.protection.packetNumberLenForPayload(
                packet_number,
                self.sent.largestAcknowledged(),
                payload.items.len,
            );
            const packet_len = try quic.protection.shortPacketLen(.{
                .destination_connection_id = self.config.peer_connection_id,
                .packet_number = packet_number,
                .packet_number_len = packet_number_len,
                .fixed_bit = true,
                .spin_bit = false,
                .key_phase = self.send_key_phase.currentKeyPhase(),
                .payload = payload.items,
            });
            const datagram_size = sent_datagram_size orelse packet_len;
            try self.sent.sentInFlightAtWithDatagramSizeAndPathEpoch(
                packet_number,
                is_ack_eliciting,
                is_in_flight,
                payload.items.len,
                datagram_size,
                .not_ect,
                imported_sent_time_ns,
                self.pmtu_path_epoch,
            );
            tracked_sent_packets += 1;
        }
        if (is_in_flight) {
            const in_flight_bytes = std.math.mul(
                usize,
                payload.items.len,
                sent_count,
            ) catch return error.CongestionLimited;
            // These datagrams have already reached the socket during the
            // handshake. Account the complete flight even when PTO copies
            // exceed the newly initialized congestion window.
            self.congestion.onPtoProbeSent(in_flight_bytes);
            errdefer self.congestion.discard(in_flight_bytes);
        }

        self.noteSentStreams(frames);
        self.next_packet_number = last_packet_number + 1;
        connection_reserved = false;
        reserved_streams.clearRetainingCapacity();
        tracked_recovery_packets = 0;
        tracked_sent_packets = 0;
    }

    /// Advance the shared application-data packet-number space past protected
    /// 0-RTT copies that were rejected by the server. Their stream and recovery
    /// state is deliberately not imported, including socket-rejected copies.
    pub fn discardSentEarlyDataCopies(
        self: *Connection,
        first_packet_number: u64,
        packet_count: u64,
    ) Error!void {
        if (packet_count == 0 or
            first_packet_number != self.next_packet_number)
        {
            return error.InvalidPacketNumber;
        }
        const last_packet_number = std.math.add(
            u64,
            first_packet_number,
            packet_count - 1,
        ) catch return error.InvalidPacketNumber;
        if (last_packet_number > quic.protection.max_packet_number) {
            return error.InvalidPacketNumber;
        }
        self.next_packet_number = last_packet_number + 1;
    }

    /// Receive and process every 1-RTT packet represented by one kernel
    /// datagram. With UDP_GRO enabled this amortizes recvmsg and allocation
    /// overhead across the whole coalesced segment batch.
    pub fn receivePacketBatch(self: *Connection) Error!ReceivedPacketBatch {
        return self.receivePacketBatchAt(self.monotonicNowNs());
    }

    pub fn receivePacketBatchAt(self: *Connection, now_ns: ?u64) Error!ReceivedPacketBatch {
        if (self.close_info != null or self.idle_timed_out) return error.ConnectionClosed;
        if (try self.receivePendingPacketBatchAt(now_ns)) |batch| return batch;
        while (true) {
            var datagrams = try self.endpoint.receiveBytesBatch();
            defer datagrams.deinit(self.endpoint.allocator);
            var view: quic.runtime.ReceivedBytesBatchView = .{
                .from = datagrams.from,
                .storage = datagrams.storage,
                .segment_size = datagrams.segment_size,
                .segment_count = datagrams.segment_count,
                .ecn = datagrams.ecn,
            };
            if (try self.processReceivedDatagramBatchAt(
                &view,
                now_ns,
            )) |batch| return batch;
        }
    }

    fn processReceivedDatagramBatchAt(
        self: *Connection,
        datagrams: *quic.runtime.ReceivedBytesBatchView,
        now_ns: ?u64,
    ) Error!?ReceivedPacketBatch {
        if (self.shouldDiscardPeerAddressBeforeAuthentication(datagrams.from)) {
            return null;
        }
        const packets = try self.endpoint.allocator.alloc(ReceivedPacket, datagrams.segment_count);
        var completed: usize = 0;
        errdefer {
            for (packets[0..completed]) |*packet| packet.deinit(self.endpoint.allocator);
            self.endpoint.allocator.free(packets);
        }
        for (0..datagrams.segment_count) |index| {
            const bytes = datagrams.datagramAt(index) orelse
                return error.InvalidPacket;
            if (isDiscardedLongHeaderPacket(bytes)) continue;
            packets[completed] = try self.processReceivedBytesAt(
                datagrams.from,
                bytes,
                datagrams.ecn,
                now_ns,
            );
            completed += 1;
        }
        if (completed == 0) {
            self.endpoint.allocator.free(packets);
            return null;
        }
        const retained = if (completed == packets.len)
            packets
        else
            try self.endpoint.allocator.realloc(packets, completed);
        return .{ .allocator = self.endpoint.allocator, .packets = retained };
    }

    /// Receive one owning GRO batch while continuing to service QUIC timers.
    ///
    /// This is the batch counterpart to `receivePacketServicingTimers`. The
    /// timed socket operation preserves one coalesced kernel datagram instead
    /// of splitting its suffix into the single-packet FIFO, so HTTP/3 can keep
    /// GRO amortization without allowing a blocking read to suppress PTO,
    /// delayed ACK, flow-control, or idle-timeout work.
    pub fn receivePacketBatchServicingTimers(
        self: *Connection,
    ) Error!ReceivedPacketBatch {
        return self.receivePacketBatchServicingTimersUntil(null) catch |err|
            switch (err) {
                error.Timeout, error.ConcurrencyUnavailable => unreachable,
                else => |other| return @errorCast(other),
            };
    }

    pub fn receivePacketBatchServicingTimersTimeout(
        self: *Connection,
        timeout: std.Io.Timeout,
    ) (Error || quic.runtime.ReceiveTimeoutError)!ReceivedPacketBatch {
        return self.receivePacketBatchServicingTimersUntil(
            callerDeadlineFromTimeout(self.endpoint.io, timeout),
        );
    }

    pub fn receivePacketBatchServicingTimersDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!ReceivedPacketBatch {
        return self.receivePacketBatchServicingTimersUntil(
            try deadline_policy.usableAwake(self.endpoint.io, deadline),
        );
    }

    fn receivePacketBatchServicingTimersUntil(
        self: *Connection,
        caller_deadline: ?std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!ReceivedPacketBatch {
        const first_now_ns = self.monotonicNowNs();
        if (try self.receivePendingPacketBatchAt(first_now_ns)) |batch|
            return batch;
        if (callerDeadlineExpired(caller_deadline, first_now_ns)) {
            return error.Timeout;
        }
        while (true) {
            var datagrams = try self.receiveDatagramBatchServicingTimersUntil(
                caller_deadline,
                null,
            );
            defer datagrams.deinit(self.endpoint.allocator);
            var view = datagrams.view();
            var batch = (try self.processReceivedDatagramBatchAt(
                &view,
                self.monotonicNowNs(),
            )) orelse continue;
            errdefer batch.deinit();
            _ = try self.retransmitPacketThresholdLosses(max_batch_packets);
            return batch;
        }
    }

    fn receiveDatagramBatchServicingTimersUntil(
        self: *Connection,
        caller_deadline: ?std.Io.Clock.Timestamp,
        storage: ?[]u8,
    ) (Error || quic.runtime.ReceiveTimeoutError)!ReceivedDatagramBatch {
        while (true) {
            if (self.close_info != null or self.idle_timed_out) {
                return error.ConnectionClosed;
            }
            const timer = self.nextTimerDeadline();
            if (timer == null and caller_deadline == null) {
                return self.receiveDatagramBatch(storage);
            }
            const now_ns = self.monotonicNowNs();
            if (callerDeadlineExpired(caller_deadline, now_ns)) {
                return error.Timeout;
            }
            if (timer) |scheduled| if (now_ns >= scheduled.deadline_ns) {
                if (try self.serviceNextTimerForBlockingReceive(
                    now_ns,
                    caller_deadline,
                )) {
                    continue;
                }
                if (try self.receiveDatagramBatchAfterBlockedTimer(
                    now_ns,
                    caller_deadline,
                    storage,
                )) |batch| {
                    return batch;
                }
                continue;
            };
            return self.receiveDatagramBatchTimeout(
                storage,
                earliestConnectionReceiveTimeout(timer, caller_deadline),
            ) catch |err| switch (err) {
                error.Timeout => {
                    const timeout_ns = self.monotonicNowNs();
                    if (callerDeadlineExpired(
                        caller_deadline,
                        timeout_ns,
                    )) return error.Timeout;
                    if (!try self.serviceNextTimerForBlockingReceive(
                        timeout_ns,
                        caller_deadline,
                    )) {
                        if (try self.receiveDatagramBatchAfterBlockedTimer(
                            timeout_ns,
                            caller_deadline,
                            storage,
                        )) |batch| {
                            return batch;
                        }
                    }
                    continue;
                },
                error.ConcurrencyUnavailable => {
                    if (caller_deadline != null) {
                        return error.ConcurrencyUnavailable;
                    }
                    return self.receiveDatagramBatch(storage);
                },
                else => |other| return @errorCast(other),
            };
        }
    }

    fn receiveDatagramBatchAfterBlockedTimer(
        self: *Connection,
        now_ns: u64,
        caller_deadline: ?std.Io.Clock.Timestamp,
        storage: ?[]u8,
    ) (Error || quic.runtime.ReceiveTimeoutError)!?ReceivedDatagramBatch {
        const deadline_ns = std.math.add(
            u64,
            now_ns,
            timer_blocked_receive_backoff_ns,
        ) catch std.math.maxInt(u64);
        const timeout = earliestConnectionReceiveTimeout(
            .{ .kind = .loss_time, .deadline_ns = deadline_ns },
            caller_deadline,
        );
        const datagrams = self.receiveDatagramBatchTimeout(
            storage,
            timeout,
        ) catch |err| switch (err) {
            error.Timeout => {
                if (callerDeadlineExpired(
                    caller_deadline,
                    self.monotonicNowNs(),
                )) return error.Timeout;
                return null;
            },
            error.ConcurrencyUnavailable => {
                if (caller_deadline != null) {
                    return error.ConcurrencyUnavailable;
                }
                return try self.receiveDatagramBatch(storage);
            },
            else => |other| return @errorCast(other),
        };
        return datagrams;
    }

    fn receiveDatagramBatch(
        self: *Connection,
        storage: ?[]u8,
    ) Error!ReceivedDatagramBatch {
        return if (storage) |out|
            .{ .borrowed = try self.endpoint.receiveBytesBatchInto(out) }
        else
            .{ .owned = try self.endpoint.receiveBytesBatch() };
    }

    fn receiveDatagramBatchTimeout(
        self: *Connection,
        storage: ?[]u8,
        timeout: std.Io.Timeout,
    ) (Error || quic.runtime.ReceiveTimeoutError)!ReceivedDatagramBatch {
        return if (storage) |out|
            .{ .borrowed = try self.endpoint.receiveBytesBatchIntoTimeout(
                out,
                timeout,
            ) }
        else
            .{ .owned = try self.endpoint.receiveBytesBatchTimeout(timeout) };
    }

    /// Process a kernel/GRO batch and release each decoded packet immediately.
    ///
    /// Event loops that consume connection state rather than retaining packet
    /// diagnostics should prefer this path: it preserves strict wire-order
    /// application while bounding live decrypt/frame allocations to one packet.
    pub fn servicePacketBatch(self: *Connection) Error!usize {
        return self.servicePacketBatchAt(self.monotonicNowNs());
    }

    /// Receive and apply one kernel/GRO batch while continuing to service QUIC
    /// timers. The common key phase is decrypted and parsed in receive storage,
    /// and one cumulative ACK decision covers the complete batch.
    pub fn servicePacketBatchServicingTimers(
        self: *Connection,
    ) Error!usize {
        return self.servicePacketBatchServicingTimersUntil(null) catch |err|
            switch (err) {
                error.Timeout, error.ConcurrencyUnavailable => unreachable,
                else => |other| return @errorCast(other),
            };
    }

    pub fn servicePacketBatchServicingTimersTimeout(
        self: *Connection,
        timeout: std.Io.Timeout,
    ) (Error || quic.runtime.ReceiveTimeoutError)!usize {
        return self.servicePacketBatchServicingTimersUntil(
            callerDeadlineFromTimeout(self.endpoint.io, timeout),
        );
    }

    pub fn servicePacketBatchServicingTimersDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!usize {
        return self.servicePacketBatchServicingTimersUntil(
            try deadline_policy.usableAwake(self.endpoint.io, deadline),
        );
    }

    fn servicePacketBatchServicingTimersUntil(
        self: *Connection,
        caller_deadline: ?std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!usize {
        const first_now_ns = self.monotonicNowNs();
        if (self.takePendingReceivedDatagram()) |pending_value| {
            var pending = pending_value;
            defer pending.deinit(self.endpoint.allocator);
            var packet = (try self.processReceivedBytesOrDropPeerAddressAt(
                pending.from,
                pending.bytes,
                pending.ecn,
                first_now_ns,
            )) orelse return 0;
            defer packet.deinit(self.endpoint.allocator);
            _ = try self.retransmitPacketThresholdLosses(max_batch_packets);
            _ = self.sendAckForPacketIfNeeded(
                packet.packet.packet_number,
                packet.frames,
            ) catch {};
            return 1;
        }
        if (callerDeadlineExpired(caller_deadline, first_now_ns)) {
            return error.Timeout;
        }
        const receive_storage = try self.stateOnlyBatchReceiveStorage();
        while (true) {
            var datagrams = try self.receiveDatagramBatchServicingTimersUntil(
                caller_deadline,
                receive_storage,
            );
            defer datagrams.deinit(self.endpoint.allocator);
            var view = datagrams.view();
            var ack: BatchAckObservation = .{
                .largest_packet_number = self.received.largestReceived(),
                .reordering_threshold = self.ack_reordering_threshold,
            };
            const completed = try self.processReceivedDatagramBatchVisitingAt(
                &view,
                self.monotonicNowNs(),
                &ack,
                BatchAckObservation.observe,
            );
            if (completed == 0) continue;
            _ = try self.retransmitPacketThresholdLosses(max_batch_packets);
            if (ack.ack_eliciting_count != 0) {
                _ = self.sendAckForObservedPacketMetadata(
                    ack.ack_eliciting_count,
                    ack.reordered,
                ) catch {};
            }
            return completed;
        }
    }

    /// Receive one ordinary UDP datagram and apply it without returning owned
    /// packet/frame diagnostics.
    ///
    /// Event loops that only consume connection state should prefer this to
    /// `receivePacket`: the current-key phase decrypts in endpoint receive
    /// storage and reuses the connection frame array. Key updates retain the
    /// owning fallback because a failed in-place AEAD trial destroys input.
    pub fn servicePacket(self: *Connection) Error!void {
        return self.servicePacketAt(self.monotonicNowNs());
    }

    pub fn servicePacketAt(
        self: *Connection,
        now_ns: ?u64,
    ) Error!void {
        return self.visitPacketAt(now_ns, {}, discardPacketView);
    }

    /// Receive one packet, apply its transport frames, and synchronously expose
    /// borrowed frames to an application protocol before receive storage is
    /// released.
    ///
    /// The overwhelmingly common current-key path decrypts in place and reuses
    /// `receive_frame_buffer`. Key-phase transitions use the owning decoder so
    /// failed next/previous-key trials can safely retry intact ciphertext.
    pub fn visitPacket(
        self: *Connection,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || callbackErrorSet(visitor))!void {
        return self.visitPacketAt(self.monotonicNowNs(), context, visitor);
    }

    pub fn visitPacketAt(
        self: *Connection,
        now_ns: ?u64,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || callbackErrorSet(visitor))!void {
        if (self.close_info != null or self.idle_timed_out) {
            return error.ConnectionClosed;
        }
        if (self.takePendingReceivedDatagram()) |pending_value| {
            var pending = pending_value;
            defer pending.deinit(self.endpoint.allocator);
            if (!self.shouldDiscardPeerAddressBeforeAuthentication(pending.from)) {
                return self.processReceivedBytesVisitingAt(
                    pending.from,
                    pending.bytes,
                    pending.ecn,
                    now_ns,
                    context,
                    visitor,
                );
            }
        }
        while (true) {
            const datagram = try self.endpoint.receiveBytesInto(
                self.receive_packet_buffer.allocatedSlice(),
            );
            if (isDiscardedLongHeaderPacket(datagram.bytes)) continue;
            if (self.shouldDiscardPeerAddressBeforeAuthentication(datagram.from)) continue;
            return self.processReceivedBytesVisitingAt(
                datagram.from,
                datagram.bytes,
                datagram.ecn,
                now_ns,
                context,
                visitor,
            );
        }
    }

    /// Timer-aware borrowed receive used by blocking HTTP/3 and WebTransport
    /// pumps. ACK-driven retransmission is repaired before the visitor runs,
    /// matching `receivePacketServicingTimers`; the caller remains responsible
    /// for ACK policy because it may need to defer a failed cumulative ACK.
    pub fn visitPacketServicingTimers(
        self: *Connection,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || callbackErrorSet(visitor))!void {
        return self.visitPacketServicingTimersUntil(
            null,
            context,
            visitor,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    /// Borrowed visitor variant bounded by a caller timeout while continuing
    /// to service all earlier transport deadlines.
    pub fn visitPacketServicingTimersTimeout(
        self: *Connection,
        timeout: std.Io.Timeout,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || quic.runtime.ReceiveTimeoutError ||
        callbackErrorSet(visitor))!void {
        const caller_deadline = callerDeadlineFromTimeout(
            self.endpoint.io,
            timeout,
        );
        return self.visitPacketServicingTimersUntil(
            caller_deadline,
            context,
            visitor,
        );
    }

    pub fn visitPacketServicingTimersDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || quic.runtime.ReceiveTimeoutError ||
        callbackErrorSet(visitor))!void {
        return self.visitPacketServicingTimersUntil(
            try deadline_policy.usableAwake(self.endpoint.io, deadline),
            context,
            visitor,
        );
    }

    fn visitPacketServicingTimersUntil(
        self: *Connection,
        caller_deadline: ?std.Io.Clock.Timestamp,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || quic.runtime.ReceiveTimeoutError ||
        callbackErrorSet(visitor))!void {
        const now_ns = self.monotonicNowNs();
        if (self.takePendingReceivedDatagram()) |pending_value| {
            var pending = pending_value;
            defer pending.deinit(self.endpoint.allocator);
            if (!self.shouldDiscardPeerAddressBeforeAuthentication(pending.from)) {
                return self.processReceivedBytesVisitingAt(
                    pending.from,
                    pending.bytes,
                    pending.ecn,
                    now_ns,
                    context,
                    visitor,
                );
            }
        }
        if (callerDeadlineExpired(caller_deadline, now_ns)) {
            return error.Timeout;
        }
        const datagram = try self.receiveBytesIntoServicingTimersUntil(
            caller_deadline,
        );

        const Context = @TypeOf(context);
        const VisitorError = callbackErrorSet(visitor);
        const AdapterContext = struct {
            connection: *Connection,
            context: Context,
        };
        const Adapter = struct {
            fn visit(
                adapter: *AdapterContext,
                packet: ReceivedPacketView,
            ) (Error || VisitorError)!void {
                _ = try adapter.connection.retransmitPacketThresholdLosses(
                    max_batch_packets,
                );
                try visitor(adapter.context, packet);
            }
        };
        var adapter: AdapterContext = .{
            .connection = self,
            .context = context,
        };
        return self.processReceivedBytesVisitingAt(
            datagram.from,
            datagram.bytes,
            datagram.ecn,
            self.monotonicNowNs(),
            &adapter,
            Adapter.visit,
        );
    }

    /// State-only timer-aware receive for stream adapters that consume data
    /// from connection receive state rather than inspecting packet frames.
    pub fn servicePacketServicingTimers(self: *Connection) Error!void {
        return self.visitPacketServicingTimers(self, acknowledgePacketView);
    }

    pub fn servicePacketServicingTimersTimeout(
        self: *Connection,
        timeout: std.Io.Timeout,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
        return self.visitPacketServicingTimersTimeout(
            timeout,
            self,
            acknowledgePacketView,
        );
    }

    pub fn servicePacketServicingTimersDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
        return self.visitPacketServicingTimersDeadline(
            deadline,
            self,
            acknowledgePacketView,
        );
    }

    fn receiveBytesIntoServicingTimers(
        self: *Connection,
    ) Error!quic.runtime.ReceivedBytesView {
        return self.receiveBytesIntoServicingTimersUntil(null) catch |err|
            switch (err) {
                error.Timeout, error.ConcurrencyUnavailable => unreachable,
                else => |other| return @errorCast(other),
            };
    }

    fn receiveBytesIntoServicingTimersUntil(
        self: *Connection,
        caller_deadline: ?std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!quic.runtime.ReceivedBytesView {
        const storage = self.receive_packet_buffer.allocatedSlice();
        while (true) {
            if (self.close_info != null or self.idle_timed_out) {
                return error.ConnectionClosed;
            }
            const now_ns = self.monotonicNowNs();
            if (callerDeadlineExpired(caller_deadline, now_ns)) {
                return error.Timeout;
            }
            const timer = self.nextTimerDeadline();
            if (timer) |scheduled| if (now_ns >= scheduled.deadline_ns) {
                if (try self.serviceNextTimerForBlockingReceive(
                    now_ns,
                    caller_deadline,
                )) {
                    continue;
                }
                if (try self.receiveBytesIntoAfterBlockedTimer(
                    storage,
                    now_ns,
                    caller_deadline,
                )) |datagram| {
                    if (isDiscardedLongHeaderPacket(datagram.bytes)) {
                        continue;
                    }
                    if (self.shouldDiscardPeerAddressBeforeAuthentication(datagram.from)) {
                        continue;
                    }
                    return datagram;
                }
                continue;
            };
            const receive_timeout = earliestConnectionReceiveTimeout(
                timer,
                caller_deadline,
            );
            const datagram = if (receive_timeout == .none)
                try self.endpoint.receiveBytesInto(storage)
            else
                self.endpoint.receiveBytesIntoTimeout(
                    storage,
                    receive_timeout,
                ) catch |err| switch (err) {
                    error.Timeout => {
                        const timeout_ns = self.monotonicNowNs();
                        if (callerDeadlineExpired(
                            caller_deadline,
                            timeout_ns,
                        )) return error.Timeout;
                        if (!try self.serviceNextTimerForBlockingReceive(
                            timeout_ns,
                            caller_deadline,
                        )) {
                            if (try self.receiveBytesIntoAfterBlockedTimer(
                                storage,
                                timeout_ns,
                                caller_deadline,
                            )) |datagram| {
                                if (isDiscardedLongHeaderPacket(datagram.bytes)) {
                                    continue;
                                }
                                if (self.shouldDiscardPeerAddressBeforeAuthentication(datagram.from)) {
                                    continue;
                                }
                                return datagram;
                            }
                        }
                        continue;
                    },
                    error.ConcurrencyUnavailable => {
                        if (caller_deadline != null) {
                            return error.ConcurrencyUnavailable;
                        }
                        const fallback = try self.endpoint.receiveBytesInto(
                            storage,
                        );
                        if (isDiscardedLongHeaderPacket(fallback.bytes) or
                            self.shouldDiscardPeerAddressBeforeAuthentication(
                                fallback.from,
                            ))
                        {
                            continue;
                        }
                        return fallback;
                    },
                    else => |other| return @errorCast(other),
                };
            if (isDiscardedLongHeaderPacket(datagram.bytes)) continue;
            if (self.shouldDiscardPeerAddressBeforeAuthentication(datagram.from)) continue;
            return datagram;
        }
    }

    fn receiveBytesIntoAfterBlockedTimer(
        self: *Connection,
        storage: []u8,
        now_ns: u64,
        caller_deadline: ?std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!?quic.runtime.ReceivedBytesView {
        const deadline_ns = std.math.add(
            u64,
            now_ns,
            timer_blocked_receive_backoff_ns,
        ) catch std.math.maxInt(u64);
        const timeout = earliestConnectionReceiveTimeout(
            .{ .kind = .loss_time, .deadline_ns = deadline_ns },
            caller_deadline,
        );
        const datagram = self.endpoint.receiveBytesIntoTimeout(
            storage,
            timeout,
        ) catch |err| switch (err) {
            error.Timeout => {
                if (callerDeadlineExpired(
                    caller_deadline,
                    self.monotonicNowNs(),
                )) return error.Timeout;
                return null;
            },
            error.ConcurrencyUnavailable => {
                if (caller_deadline != null) {
                    return error.ConcurrencyUnavailable;
                }
                return try self.endpoint.receiveBytesInto(storage);
            },
            else => |other| return @errorCast(other),
        };
        return @as(?quic.runtime.ReceivedBytesView, datagram);
    }

    fn processReceivedBytesVisitingAt(
        self: *Connection,
        from: net.IpAddress,
        bytes: []u8,
        ecn: quic.packet_space.EcnCodepoint,
        now_ns: ?u64,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || callbackErrorSet(visitor))!void {
        return self.processReceivedBytesVisitingWithDestinationIdAt(
            from,
            bytes,
            self.config.local_connection_id.len,
            ecn,
            now_ns,
            context,
            visitor,
        );
    }

    fn processReceivedBytesVisitingWithDestinationIdAt(
        self: *Connection,
        from: net.IpAddress,
        bytes: []u8,
        destination_connection_id_len: usize,
        ecn: quic.packet_space.EcnCodepoint,
        now_ns: ?u64,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || callbackErrorSet(visitor))!void {
        const reset_candidate = quic.stateless_reset.tokenCandidate(bytes);
        const current = self.openCurrentShortPacketInPlaceForKeyPhase(
            self.receive_key_phase.currentKeyPhase(),
            bytes,
            destination_connection_id_len,
            self.expected_packet_number,
            self.config.accept_zero_fixed_bit,
        ) catch |err| {
            return self.handlePacketProtectionErrorAt(
                err,
                reset_candidate,
                now_ns,
            );
        };
        switch (current) {
            .opened => |packet| {
                return self.processOpenedBytesInPlaceVisitingAt(
                    from,
                    bytes,
                    ecn,
                    now_ns,
                    packet,
                    context,
                    visitor,
                );
            },
            .key_phase_mismatch => {},
        }
        var packet = try self.processReceivedBytesWithDestinationIdAt(
            from,
            bytes,
            destination_connection_id_len,
            ecn,
            now_ns,
        );
        defer packet.deinit(self.endpoint.allocator);
        try visitor(context, .{
            .from = packet.from,
            .packet_number = packet.packet.packet_number,
            .frames = packet.frames,
            .peer_initiated_key_update = packet.peer_initiated_key_update,
        });
    }

    fn openCurrentShortPacketInPlaceForKeyPhase(
        self: *const Connection,
        current_key_phase: bool,
        bytes: []u8,
        destination_connection_id_len: usize,
        expected_packet_number: u64,
        allow_zero_fixed_bit: bool,
    ) quic.protection.Error!quic.protection.CurrentKeyOpenResult {
        if (comptime quic.protection.prepared_packet_protection_enabled) {
            if (self.prepared_receive_keys) |prepared| {
                return quic.protection
                    .openShortPacketInPlaceForPreparedKeyPhaseWithFixedBitPolicy(
                    prepared,
                    current_key_phase,
                    bytes,
                    destination_connection_id_len,
                    expected_packet_number,
                    allow_zero_fixed_bit,
                );
            }
        }
        return quic.protection
            .openShortPacketInPlaceForKeyPhaseWithFixedBitPolicy(
            self.receive_key_phase.currentKeys(),
            current_key_phase,
            bytes,
            destination_connection_id_len,
            expected_packet_number,
            allow_zero_fixed_bit,
        );
    }

    pub fn servicePacketBatchAt(self: *Connection, now_ns: ?u64) Error!usize {
        if (self.close_info != null or self.idle_timed_out) return error.ConnectionClosed;
        if (self.takePendingReceivedDatagram()) |pending_value| {
            var pending = pending_value;
            defer pending.deinit(self.endpoint.allocator);
            var packet = (try self.processReceivedBytesOrDropPeerAddressAt(
                pending.from,
                pending.bytes,
                pending.ecn,
                now_ns,
            )) orelse return 0;
            packet.deinit(self.endpoint.allocator);
            return 1;
        }
        var datagrams = try self.endpoint.receiveBytesBatchInto(
            try self.stateOnlyBatchReceiveStorage(),
        );
        return self.processReceivedDatagramBatchVisitingAt(
            &datagrams,
            now_ns,
            {},
            discardPacketView,
        );
    }

    fn stateOnlyBatchReceiveStorage(self: *Connection) Error![]u8 {
        const required = if (self.endpoint.groReceiveEnabled())
            quic.runtime.max_gro_receive_bytes
        else
            self.endpoint.limits.max_datagram_size;
        try self.receive_packet_buffer.ensureTotalCapacity(
            self.endpoint.allocator,
            required,
        );
        return self.receive_packet_buffer.allocatedSlice();
    }

    fn processReceivedDatagramBatchVisitingAt(
        self: *Connection,
        datagrams: *quic.runtime.ReceivedBytesBatchView,
        now_ns: ?u64,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || callbackErrorSet(visitor))!usize {
        if (self.shouldDiscardPeerAddressBeforeAuthentication(datagrams.from)) {
            return 0;
        }

        var completed: usize = 0;
        for (0..datagrams.segment_count) |index| {
            const bytes = datagrams.datagramAtMutable(index) orelse
                return error.InvalidPacket;
            if (isDiscardedLongHeaderPacket(bytes)) continue;
            const reset_candidate = quic.stateless_reset.tokenCandidate(bytes);
            const current = self.openCurrentShortPacketInPlaceForKeyPhase(
                self.receive_key_phase.currentKeyPhase(),
                bytes,
                self.config.local_connection_id.len,
                self.expected_packet_number,
                self.config.accept_zero_fixed_bit,
            ) catch |err| {
                return self.handlePacketProtectionErrorAt(
                    err,
                    reset_candidate,
                    now_ns,
                );
            };
            switch (current) {
                .opened => |packet| {
                    try self.processOpenedBytesInPlaceVisitingAt(
                        datagrams.from,
                        bytes,
                        datagrams.ecn,
                        now_ns,
                        packet,
                        context,
                        visitor,
                    );
                    completed += 1;
                    continue;
                },
                .key_phase_mismatch => {},
            }

            // The current-key phase is overwhelmingly common. Keep key-update
            // fallback on the owning path because a failed in-place AEAD trial
            // intentionally destroys its output and cannot safely retry
            // current/next/previous generations against the same ciphertext.
            {
                var packet = try self.processReceivedBytesAt(
                    datagrams.from,
                    bytes,
                    datagrams.ecn,
                    now_ns,
                );
                defer packet.deinit(self.endpoint.allocator);
                try visitor(context, .{
                    .from = packet.from,
                    .packet_number = packet.packet.packet_number,
                    .frames = packet.frames,
                    .peer_initiated_key_update = packet.peer_initiated_key_update,
                });
            }
            completed += 1;
        }
        return completed;
    }

    fn processOpenedBytesInPlaceAt(
        self: *Connection,
        from: net.IpAddress,
        bytes: []u8,
        ecn: quic.packet_space.EcnCodepoint,
        now_ns: ?u64,
        packet: quic.protection.OpenedShortPacketView,
    ) Error!void {
        return self.processOpenedBytesInPlaceVisitingAt(
            from,
            bytes,
            ecn,
            now_ns,
            packet,
            {},
            discardPacketView,
        );
    }

    fn processOpenedBytesInPlaceVisitingAt(
        self: *Connection,
        from: net.IpAddress,
        bytes: []u8,
        ecn: quic.packet_space.EcnCodepoint,
        now_ns: ?u64,
        packet: quic.protection.OpenedShortPacketView,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || callbackErrorSet(visitor))!void {
        const frames = try self.parseServicePacketFramesOrClose(packet.payload, now_ns);
        defer {
            self.receive_frame_buffer.clearRetainingCapacity();
            self.receive_ack_range_buffer.clearRetainingCapacity();
        }
        var peer_address_update = try self.preparePeerAddressUpdate(
            from,
            bytes.len,
            frames,
        );
        defer peer_address_update.deinit();
        var peer_connection_id_before: [
            quic.connection_id.max_connection_id_len
        ]u8 = undefined;
        const peer_connection_id_before_len =
            self.config.peer_connection_id.len;
        @memcpy(
            peer_connection_id_before[0..peer_connection_id_before_len],
            self.config.peer_connection_id,
        );
        try self.applyReceivedFramesForDestinationOrClose(
            packet.packet_number,
            frames,
            now_ns,
            ecn,
            packet.destination_connection_id,
            from,
            packet.payload,
        );
        const spin_connection_id_changed = !std.mem.eql(
            u8,
            peer_connection_id_before[0..peer_connection_id_before_len],
            self.config.peer_connection_id,
        );
        self.commitPeerAddressUpdate(&peer_address_update);
        if (spin_connection_id_changed) {
            self.resetSpinValueForConnectionId();
            self.rememberCurrentValidatedPeerPath();
            if (!self.config.peer.eql(&from)) {
                self.updateSpinBitAfterReceive(
                    from,
                    packet.packet_number,
                    packet.spin_bit,
                );
            }
        } else {
            self.updateSpinBitAfterReceive(
                from,
                packet.packet_number,
                packet.spin_bit,
            );
        }
        self.observePacketReceived(
            now_ns,
            packet.packet_number,
            bytes.len,
            frames,
        );
        try visitor(context, .{
            .from = from,
            .packet_number = packet.packet_number,
            .frames = frames,
        });
    }

    fn parseServicePacketFramesOrClose(self: *Connection, payload: []const u8, now_ns: ?u64) Error![]quic.Frame {
        std.debug.assert(self.receive_frame_buffer.items.len == 0);
        std.debug.assert(self.receive_ack_range_buffer.items.len == 0);
        errdefer {
            self.receive_frame_buffer.clearRetainingCapacity();
            self.receive_ack_range_buffer.clearRetainingCapacity();
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
            const ack_range_start = self.receive_ack_range_buffer.items.len;
            self.receive_ack_range_buffer.items.len =
                self.receive_ack_range_buffer.capacity;
            const parsed = quic.parseFrameInto(
                payload[pos..],
                self.receive_ack_range_buffer.items[ack_range_start..],
            ) catch |err| {
                self.receive_ack_range_buffer.items.len = ack_range_start;
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
            self.receive_ack_range_buffer.items.len = ack_range_start +
                if (parsed.frame == .ack) parsed.frame.ack.ranges.len else 0;
            try self.receive_frame_buffer.append(self.endpoint.allocator, parsed.frame);
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
        return self.processReceivedBytesWithDestinationIdAt(
            from,
            bytes,
            self.config.local_connection_id.len,
            ecn,
            now_ns,
        );
    }

    fn processReceivedBytesWithDestinationIdAt(
        self: *Connection,
        from: net.IpAddress,
        bytes: []const u8,
        destination_connection_id_len: usize,
        ecn: quic.packet_space.EcnCodepoint,
        now_ns: ?u64,
    ) Error!ReceivedPacket {
        var packet = try self.openReceivedBytesWithFrameClose(
            from,
            bytes,
            destination_connection_id_len,
            now_ns,
        );
        errdefer packet.deinit(self.endpoint.allocator);
        var peer_address_update = try self.preparePeerAddressUpdate(
            from,
            bytes.len,
            packet.frames,
        );
        defer peer_address_update.deinit();
        var peer_connection_id_before: [
            quic.connection_id.max_connection_id_len
        ]u8 = undefined;
        const peer_connection_id_before_len =
            self.config.peer_connection_id.len;
        @memcpy(
            peer_connection_id_before[0..peer_connection_id_before_len],
            self.config.peer_connection_id,
        );
        try self.applyReceivedFramesForDestinationOrClose(
            packet.packet.packet_number,
            packet.frames,
            now_ns,
            ecn,
            packet.packet.destination_connection_id,
            from,
            packet.packet.payload,
        );
        const spin_connection_id_changed = !std.mem.eql(
            u8,
            peer_connection_id_before[0..peer_connection_id_before_len],
            self.config.peer_connection_id,
        );
        if (packet.peer_initiated_key_update) {
            try self.acceptPeerKeyUpdate(packet.packet.key_phase, now_ns);
        }
        self.commitPeerAddressUpdate(&peer_address_update);
        if (spin_connection_id_changed) {
            self.resetSpinValueForConnectionId();
            self.rememberCurrentValidatedPeerPath();
            if (!self.config.peer.eql(&from)) {
                self.updateSpinBitAfterReceive(
                    from,
                    packet.packet.packet_number,
                    packet.packet.spin_bit,
                );
            }
        } else {
            self.updateSpinBitAfterReceive(
                from,
                packet.packet.packet_number,
                packet.packet.spin_bit,
            );
        }
        self.observePacketReceived(
            now_ns,
            packet.packet.packet_number,
            bytes.len,
            packet.frames,
        );
        return packet;
    }

    fn processReceivedBytesOrDropPeerAddressAt(
        self: *Connection,
        from: net.IpAddress,
        bytes: []const u8,
        ecn: quic.packet_space.EcnCodepoint,
        now_ns: ?u64,
    ) Error!?ReceivedPacket {
        if (self.shouldDiscardPeerAddressBeforeAuthentication(from)) return null;
        return try self.processReceivedBytesAt(from, bytes, ecn, now_ns);
    }

    fn acceptPeerKeyUpdate(
        self: *Connection,
        peer_key_phase: bool,
        now_ns: ?u64,
    ) Error!void {
        if (!self.receive_key_phase.updateAfterReceiving(peer_key_phase)) return;
        if (self.prepared_receive_keys) |prepared| {
            prepared.replace(self.receive_key_phase.currentKeys());
        }
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

    /// Process one datagram already routed by Destination Connection ID.
    /// Returns null when role-specific peer-address policy discards it.
    pub fn receiveRoutedDatagram(self: *Connection, routed: quic.runtime.RoutedBytes) Error!?ReceivedPacket {
        return self.receiveRoutedDatagramAt(routed, self.monotonicNowNs());
    }

    pub fn receiveRoutedDatagramOrDropAfterClose(self: *Connection, routed: quic.runtime.RoutedBytes) Error!?ReceivedPacket {
        return self.receiveRoutedDatagramOrDropAfterCloseAt(routed, self.monotonicNowNs());
    }

    /// Process an active connection normally, while retaining CID ownership
    /// through closing/draining without surfacing a fatal receive error. A
    /// current-path datagram observed during closing schedules a rate-limited
    /// CONNECTION_CLOSE response; draining remains strictly silent. Clients
    /// also return null for packets from unknown server tuples, as required by
    /// RFC 9000 section 9.
    pub fn receiveRoutedDatagramOrDropAfterCloseAt(self: *Connection, routed: quic.runtime.RoutedBytes, now_ns: ?u64) Error!?ReceivedPacket {
        if (self.close_info != null or self.idle_timed_out) {
            if (now_ns) |timestamp| {
                if (self.config.peer.eql(&routed.datagram.from)) {
                    self.noteCloseDatagramAt(timestamp);
                }
            }
            return null;
        }
        return try self.receiveRoutedDatagramAt(routed, now_ns);
    }

    pub fn visitRoutedDatagramOrDropAfterCloseAt(
        self: *Connection,
        routed: quic.runtime.RoutedBytesView,
        now_ns: ?u64,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || callbackErrorSet(visitor))!bool {
        if (self.close_info != null or self.idle_timed_out) {
            if (now_ns) |timestamp| {
                if (self.config.peer.eql(&routed.datagram.from)) {
                    self.noteCloseDatagramAt(timestamp);
                }
            }
            return false;
        }
        return self.visitRoutedDatagramAt(
            routed,
            now_ns,
            context,
            visitor,
        );
    }

    pub const RoutedReceiveResult = union(enum) {
        packet: ReceivedPacket,
        stateless_reset: u64,
        dropped_after_close,
        dropped_peer_address,
    };

    pub fn receiveRoutedDatagramOrStatelessReset(self: *Connection, routed: quic.runtime.RoutedBytes, now_ms: ?u64, pto_ms: ?u64) Error!RoutedReceiveResult {
        if (self.close_info != null or self.idle_timed_out) return .dropped_after_close;
        if (self.shouldDiscardPeerAddressBeforeAuthentication(routed.datagram.from)) {
            return .dropped_peer_address;
        }
        if (self.processStatelessResetDatagram(routed.datagram.bytes, now_ms, pto_ms)) |sequence_number| {
            return .{ .stateless_reset = sequence_number };
        }
        return .{ .packet = (try self.receiveRoutedDatagramAt(
            routed,
            self.monotonicNowNs(),
        )).? };
    }

    pub fn receiveRoutedDatagramAt(self: *Connection, routed: quic.runtime.RoutedBytes, now_ns: ?u64) Error!?ReceivedPacket {
        return self.receiveRoutedDatagramWithEcnAt(
            routed,
            now_ns,
            routed.datagram.ecn,
        );
    }

    /// Process one caller-buffer datagram already matched to this connection.
    /// The current-key path decrypts in place and reuses retained frame
    /// storage; key updates retain the safe allocating fallback. `false` means
    /// the authenticated peer-address policy discarded the datagram.
    pub fn visitRoutedDatagramAt(
        self: *Connection,
        routed: quic.runtime.RoutedBytesView,
        now_ns: ?u64,
        context: anytype,
        comptime visitor: anytype,
    ) (Error || callbackErrorSet(visitor))!bool {
        if (self.close_info != null or self.idle_timed_out) {
            return error.ConnectionClosed;
        }
        if (self.shouldDiscardPeerAddressBeforeAuthentication(
            routed.datagram.from,
        )) return false;
        try self.processReceivedBytesVisitingWithDestinationIdAt(
            routed.datagram.from,
            routed.datagram.bytes,
            routed.destination_connection_id.len,
            routed.datagram.ecn,
            now_ns,
            context,
            visitor,
        );
        return true;
    }

    pub fn receiveRoutedDatagramWithEcnAt(self: *Connection, routed: quic.runtime.RoutedBytes, now_ns: ?u64, ecn: quic.packet_space.EcnCodepoint) Error!?ReceivedPacket {
        if (self.close_info != null or self.idle_timed_out) return error.ConnectionClosed;
        if (self.shouldDiscardPeerAddressBeforeAuthentication(routed.datagram.from)) {
            return null;
        }
        var packet = try self.openReceivedBytesWithFrameClose(
            routed.datagram.from,
            routed.datagram.bytes,
            routed.destination_connection_id.len,
            now_ns,
        );
        errdefer packet.deinit(self.endpoint.allocator);
        var peer_address_update = try self.preparePeerAddressUpdate(
            routed.datagram.from,
            routed.datagram.bytes.len,
            packet.frames,
        );
        defer peer_address_update.deinit();
        var peer_connection_id_before: [
            quic.connection_id.max_connection_id_len
        ]u8 = undefined;
        const peer_connection_id_before_len =
            self.config.peer_connection_id.len;
        @memcpy(
            peer_connection_id_before[0..peer_connection_id_before_len],
            self.config.peer_connection_id,
        );
        try self.applyReceivedFramesForDestinationOrClose(
            packet.packet.packet_number,
            packet.frames,
            now_ns,
            ecn,
            packet.packet.destination_connection_id,
            routed.datagram.from,
            packet.packet.payload,
        );
        const spin_connection_id_changed = !std.mem.eql(
            u8,
            peer_connection_id_before[0..peer_connection_id_before_len],
            self.config.peer_connection_id,
        );
        if (packet.peer_initiated_key_update) {
            try self.acceptPeerKeyUpdate(packet.packet.key_phase, now_ns);
        }
        self.commitPeerAddressUpdate(&peer_address_update);
        if (spin_connection_id_changed) {
            self.resetSpinValueForConnectionId();
            self.rememberCurrentValidatedPeerPath();
            if (!self.config.peer.eql(&routed.datagram.from)) {
                self.updateSpinBitAfterReceive(
                    routed.datagram.from,
                    packet.packet.packet_number,
                    packet.packet.spin_bit,
                );
            }
        } else {
            self.updateSpinBitAfterReceive(
                routed.datagram.from,
                packet.packet.packet_number,
                packet.packet.spin_bit,
            );
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
        var decoded = quic.protection.openShortPacketWithKeyUpdateAndFixedBitPolicy(
            self.endpoint.allocator,
            self.receive_key_phase.keyUpdateKeys(),
            bytes,
            destination_connection_id_len,
            self.expected_packet_number,
            self.config.accept_zero_fixed_bit,
        ) catch |err| return self.handlePacketProtectionErrorAt(
            err,
            quic.stateless_reset.tokenCandidate(bytes),
            now_ns,
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
        // The client-side address filter permits the retained validated server
        // tuple while a replacement is being probed. Receiving a delayed or
        // fallback packet there must not reinterpret the server as migrating.
        if (self.config.local_endpoint == .client) {
            std.debug.assert(self.peer_preferred_address_migration_active);
            std.debug.assert(self.last_validated_peer_path.peer.eql(&from));
            return .none;
        }
        if (!hasNonProbingFrame(frames)) return .{
            .probing_candidate = .{
                .from = from,
                .datagram_len = datagram_len,
                .budget_index = if (self.config.local_endpoint == .server)
                    try self.prepareCandidatePathBudget(from)
                else
                    0,
            },
        };
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
        var attempts: usize = 0;
        while (!try path_validation.queueChallengeForPath(
            challenge,
            nextPathEpoch(self.pmtu_path_epoch),
        )) {
            attempts += 1;
            if (attempts == quic.connection_id.max_pool_size) {
                return error.PathValidationLimit;
            }
            try std.Io.randomSecure(self.endpoint.io, &challenge);
        }
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
            .probing_candidate => |candidate| {
                self.recordCandidatePathBytesReceived(
                    candidate.budget_index,
                    candidate.from,
                    candidate.datagram_len,
                );
            },
            .nat_rebinding => |from| {
                const candidate = self.takeCandidatePathBudget(from);
                self.config.peer = from;
                // A port-only NAT rebinding remains the same network path for
                // RTT purposes while every tuple-local recovery signal starts
                // a fresh epoch.
                self.resetRecoveryForPath(true);
                if (candidate) |state| {
                    self.spin_bit_value = state.spin_bit_value;
                    self.spin_largest_received_packet_number =
                        state.spin_largest_received_packet_number;
                }
                self.setPeerAddressValidated(true);
            },
            .new_path => |*new_path| {
                self.rememberCurrentValidatedPeerPath();
                self.config.peer = new_path.from;
                self.peer_address_validated = false;
                const candidate = self.takeCandidatePathBudget(
                    new_path.from,
                );
                self.peer_address_bytes_received = if (candidate) |budget|
                    budget.bytes_received
                else
                    0;
                self.peer_address_bytes_sent = if (candidate) |budget|
                    budget.bytes_sent
                else
                    0;
                self.recordPeerAddressBytesReceived(
                    new_path.datagram_len,
                );
                self.resetRecoveryForPath(false);
                if (candidate) |state| {
                    self.spin_bit_value = state.spin_bit_value;
                    self.spin_largest_received_packet_number =
                        state.spin_largest_received_packet_number;
                }
                self.path_validation.deinit();
                self.path_validation = new_path.path_validation;
                self.path_validation.abandonPendingChallengesExceptPathEpoch(
                    self.pmtu_path_epoch,
                );
            },
        }
        update.* = .none;
    }

    fn applyReceivedFrames(self: *Connection, packet_number: u64, frames: []const quic.Frame, now_ns: ?u64, ecn: quic.packet_space.EcnCodepoint) Error!void {
        var triggering_frame_index: ?usize = null;
        try self.applyReceivedFramesForDestination(
            packet_number,
            frames,
            now_ns,
            ecn,
            null,
            null,
            &triggering_frame_index,
        );
    }

    fn applyReceivedFramesForDestinationOrClose(
        self: *Connection,
        packet_number: u64,
        frames: []const quic.Frame,
        now_ns: ?u64,
        ecn: quic.packet_space.EcnCodepoint,
        packet_destination_connection_id: ?[]const u8,
        path_response_peer: ?net.IpAddress,
        packet_payload: ?[]const u8,
    ) Error!void {
        var triggering_frame_index: ?usize = null;
        self.applyReceivedFramesForDestination(
            packet_number,
            frames,
            now_ns,
            ecn,
            packet_destination_connection_id,
            path_response_peer,
            &triggering_frame_index,
        ) catch |err| {
            const triggering_frame = if (triggering_frame_index) |index|
                frames[index]
            else
                null;
            const raw_frame_type = if (triggering_frame_index) |index|
                if (packet_payload) |payload|
                    rawFrameTypeAtIndex(self.endpoint.allocator, payload, index)
                else
                    null
            else
                null;
            if (self.classifySemanticCloseError(
                triggering_frame,
                raw_frame_type,
                err,
            )) |close| {
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
        path_response_peer: ?net.IpAddress,
        triggering_frame_index: *?usize,
    ) Error!void {
        if (!try self.received.wouldRecordFresh(packet_number)) return error.DuplicatePacket;
        const validated_ack = try self.validateReceivedFramePreconditions(
            frames,
            packet_destination_connection_id,
            triggering_frame_index,
        );
        if (!try self.received.recordWithEcn(packet_number, ecn)) return error.DuplicatePacket;
        if (packet_number >= self.expected_packet_number) {
            self.expected_packet_number = packet_number + 1;
        }
        const path_challenge_count = countPathChallenges(frames);
        const path_response_capacity = self.config.max_pending_path_responses -|
            self.path_validation.pendingResponseCount();
        const path_response_reserve = @min(
            path_challenge_count,
            path_response_capacity,
        );
        if (path_response_reserve != 0) {
            if (self.path_response_target_head != 0 and
                self.path_response_targets.items.len + path_response_reserve >
                    self.path_response_targets.capacity)
            {
                self.compactPathResponseTargets();
            }
            try self.path_response_targets.ensureUnusedCapacity(
                self.endpoint.allocator,
                path_response_reserve,
            );
        }
        var current_path_validated = false;
        for (frames, 0..) |frame, frame_index| {
            triggering_frame_index.* = frame_index;
            switch (frame) {
                .ack => {
                    const pto_anchor_before =
                        self.sent.latestAckElicitingInFlightSentTimeForPathEpoch(
                            self.pmtu_path_epoch,
                        );
                    const pto_base_before = self.rtt_stats.pto(true);
                    // Sample utilization before ACK accounting removes bytes
                    // from flight. Otherwise every ACK would make the sender
                    // look less utilized than it was while transmitting.
                    const congestion_window_utilized =
                        self.congestion.isCongestionWindowUtilized();
                    const handshake_done_group =
                        self.handshake_status.recoveryGroupId();
                    const plain_ack_current_path_failure =
                        self.precheckPlainAckCurrentPathFailure(frame.ack);
                    if (now_ns) |now| _ = try self.updateRttFromAck(frame.ack, now);
                    const acked = self.sent.applyAckDetailedForProbeValidated(
                        frame.ack,
                        self.pmtud.active_probe_packet_number,
                        self.pmtud.active_probe_epoch,
                        self.pmtud.currentSize(),
                        self.pmtu_path_epoch,
                        validated_ack,
                    ) catch |err| switch (err) {
                        error.InvalidAckFrame => try self.applyAckWithEcnFailure(
                            frame.ack,
                            validated_ack,
                        ),
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
                    if (acked.current_path_ack_eliciting_packets > 0) {
                        self.pto_count = 0;
                    }
                    if (acked.active_pmtu_probe_packet_number) |probe_packet_number| {
                        self.pmtud.onProbeAckedWithIdentity(
                            probe_packet_number,
                            acked.active_pmtu_probe_epoch,
                            acked.active_pmtu_probe_size.?,
                            self.config.max_datagram_size,
                            now_ns,
                        );
                        self.applyCurrentPmtuToPath();
                    }
                    const consumed_retired_path_baseline =
                        self.ecn_path_baseline_pending and
                        acked.ecn_counts_updated;
                    if (consumed_retired_path_baseline) {
                        self.ecn_path_baseline_pending = false;
                    }
                    if (frame.ack.ecn_counts != null and
                        (acked.current_path_ect0_packets != 0 or
                            acked.current_path_ect1_packets != 0) and
                        !consumed_retired_path_baseline)
                    {
                        self.ecn_path.onValidatedAck();
                    } else if (plain_ack_current_path_failure) {
                        self.ecn_path.onValidationFailure();
                    }
                    if (frame.ack.ecn_counts == null and
                        (acked.ect0_packets != 0 or
                            acked.ect1_packets != 0))
                    {
                        // A future cumulative ACK_ECN can include these marks
                        // even though this ACK supplied no usable baseline.
                        // Consume the next valid counter update before using
                        // its delta to validate the active path.
                        self.ecn_path_baseline_pending = true;
                    }
                    if (!self.ecn_path_baseline_pending and
                        self.sent.hasAcknowledgedEctBeyondEcnWatermark())
                    {
                        self.ecn_path_baseline_pending = true;
                    }
                    self.reportAckedPmtuEvidence(acked);
                    if (acked.ecn_ce_delta > 0 and
                        !consumed_retired_path_baseline and
                        (acked.current_path_ect0_packets != 0 or
                            acked.current_path_ect1_packets != 0) and
                        acked.current_path_ect0_packets == acked.ect0_packets and
                        acked.current_path_ect1_packets == acked.ect1_packets)
                    {
                        self.congestion.onExplicitCongestion(now_ns);
                    }
                    self.congestion.onAckedWithContextAndUtilization(
                        acked.current_path_bytes,
                        acked.current_path_largest_sent_time_ns,
                        now_ns,
                        self.rtt_stats.smoothedOrInitial(),
                        congestion_window_utilized,
                    );
                    self.congestion.endAck();
                    if (acked.largest_acknowledged_sent) |acknowledged| {
                        self.received.pruneAckedRanges(acknowledged);
                    }
                    const lost = self.sent.detectPacketThresholdLossForProbeAndPathEpoch(
                        frame.ack.largest_acknowledged,
                        quic.packet_space.default_packet_threshold,
                        self.pmtud.active_probe_packet_number,
                        self.pmtud.active_probe_epoch,
                        self.pmtu_path_epoch,
                    );
                    if (lost.bytes > 0 or lost.probe_bytes > 0) {
                        const loss_generation = self.sent.currentLossGeneration();
                        self.recordPacketsLost(lost.packets);
                        self.observeLostPackets(now_ns, "packet_threshold");
                        self.congestion.onLostAt(
                            lost.current_path_bytes,
                            lost.current_path_largest_nonprobe_sent_time_ns,
                            now_ns,
                        );
                        self.congestion.discard(
                            lost.current_path_probe_bytes,
                        );
                        if (lost.active_pmtu_probe_packet_number) |probe_packet_number| {
                            self.pmtud.onProbeLostWithIdentity(
                                probe_packet_number,
                                lost.active_pmtu_probe_epoch,
                                lost.active_pmtu_probe_size.?,
                                self.config.max_datagram_size,
                                now_ns,
                            );
                        }
                        self.reportLostPmtuEvidence(loss_generation, now_ns);
                        self.applyCurrentPmtuToPath();
                        if (lost.current_path_bytes > 0) {
                            _ = self.applyPersistentCongestionIfDetected();
                        }
                    }
                    if (now_ns) |now| {
                        const timed_lost = self.sent.detectTimeThresholdLossForProbeAndPathEpoch(
                            now,
                            self.rtt_stats.lossDelay(),
                            frame.ack.largest_acknowledged,
                            self.pmtud.active_probe_packet_number,
                            self.pmtud.active_probe_epoch,
                            self.pmtu_path_epoch,
                        );
                        if (timed_lost.bytes > 0 or timed_lost.probe_bytes > 0) {
                            const loss_generation = self.sent.currentLossGeneration();
                            self.recordPacketsLost(timed_lost.packets);
                            self.observeLostPackets(now_ns, "time_threshold");
                            self.congestion.onLostAt(
                                timed_lost.current_path_bytes,
                                timed_lost.current_path_largest_nonprobe_sent_time_ns,
                                now,
                            );
                            self.congestion.discard(
                                timed_lost.current_path_probe_bytes,
                            );
                            if (timed_lost.active_pmtu_probe_packet_number) |probe_packet_number| {
                                self.pmtud.onProbeLostWithIdentity(
                                    probe_packet_number,
                                    timed_lost.active_pmtu_probe_epoch,
                                    timed_lost.active_pmtu_probe_size.?,
                                    self.config.max_datagram_size,
                                    now_ns,
                                );
                            }
                            self.reportLostPmtuEvidence(loss_generation, now_ns);
                            self.applyCurrentPmtuToPath();
                            if (timed_lost.current_path_bytes > 0) {
                                _ = self.applyPersistentCongestionIfDetected();
                            }
                        }
                    }
                    self.observeRecoveryMetrics(now_ns);
                    _ = try self.recovery.applyAck(frame.ack);
                    self.reclaimRequestedLocalStreamsAfterAck();
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
                    if ((acked.current_path_ack_eliciting_packets != 0 and
                        (self.sent.latestAckElicitingInFlightSentTimeForPathEpoch(
                            self.pmtu_path_epoch,
                        ) != null or
                            self.recovery.pendingCount() != 0)) or
                        self.sent.latestAckElicitingInFlightSentTimeForPathEpoch(
                            self.pmtu_path_epoch,
                        ) !=
                            pto_anchor_before or
                        self.rtt_stats.pto(true) != pto_base_before)
                    {
                        self.pto_jitter_state.rearm();
                    }
                },
                .max_data => |max_data| self.send_flow.updateLimit(max_data.maximum_data),
                .max_stream_data => |max_stream_data| {
                    if (self.isClosedStream(max_stream_data.stream_id) or
                        self.sendStreamTerminal(max_stream_data.stream_id))
                    {
                        continue;
                    }
                    const flow = try self.sendStreamFlow(max_stream_data.stream_id);
                    flow.updateLimit(max_stream_data.maximum_stream_data);
                },
                .max_streams_bidi => |max_streams| try self.receiveMaxStreams(max_streams.maximum_streams, .bidirectional),
                .max_streams_uni => |max_streams| try self.receiveMaxStreams(max_streams.maximum_streams, .unidirectional),
                .streams_blocked_bidi => |blocked| try self.receiveStreamsBlocked(blocked.maximum_streams, .bidirectional),
                .streams_blocked_uni => |blocked| try self.receiveStreamsBlocked(blocked.maximum_streams, .unidirectional),
                .new_connection_id => |new_connection_id| {
                    var current_peer_connection_id: [quic.connection_id.max_connection_id_len]u8 =
                        undefined;
                    const current_peer_connection_id_len =
                        self.config.peer_connection_id.len;
                    @memcpy(
                        current_peer_connection_id[0..current_peer_connection_id_len],
                        self.config.peer_connection_id,
                    );
                    try self.peer_connection_ids.addWithRetirePriorTo(
                        new_connection_id.sequence_number,
                        new_connection_id.retire_prior_to,
                        new_connection_id.connection_id,
                        new_connection_id.stateless_reset_token,
                        self.config.active_connection_id_limit,
                    );
                    const selected = self.peer_connection_ids.selectForPath(
                        current_peer_connection_id[0..current_peer_connection_id_len],
                    ) orelse return error.UnknownConnectionId;
                    self.setPeerConnectionId(selected);
                    if (!std.mem.eql(
                        u8,
                        current_peer_connection_id[0..current_peer_connection_id_len],
                        self.config.peer_connection_id,
                    )) {
                        self.resetSpinValueForConnectionId();
                    }
                    self.rememberCurrentValidatedPeerPath();
                },
                .retire_connection_id => |retire| try self.local_connection_ids.retireExceptPacketDestination(retire.sequence_number, packet_destination_connection_id),
                .path_challenge => |path_challenge| {
                    if (try self.path_validation.receiveChallenge(path_challenge.data)) {
                        self.path_response_targets.appendAssumeCapacity(
                            path_response_peer,
                        );
                        const response_now = now_ns orelse
                            self.monotonicNowNs();
                        if (self.path_response_retry_deadline_ns == null or
                            response_now < self.path_response_retry_deadline_ns.?)
                        {
                            self.path_response_retry_deadline_ns = response_now;
                        }
                    }
                },
                .path_response => |path_response| {
                    const matched = self.path_validation
                        .takeResponseValidated(path_response.data) orelse
                        return error.UnknownPathResponse;
                    if (matched.path_epoch == self.pmtu_path_epoch) {
                        current_path_validated = true;
                    }
                },
                .reset_stream => |reset| {
                    if (self.isClosedStream(reset.stream_id)) continue;
                    try self.receiveResetStream(reset);
                },
                .stop_sending => |stop| {
                    if (self.isClosedStream(stop.stream_id) or
                        self.sendStreamTerminal(stop.stream_id)) continue;
                    try self.receiveStopSending(stop);
                },
                .new_token => |new_token| try self.receiveNewToken(new_token),
                .handshake_done => try self.receiveHandshakeDone(),
                .datagram => |datagram| try self.receiveDatagramFrame(
                    datagram,
                    packet_number,
                ),
                .ack_frequency => |ack_frequency| try self.receiveAckFrequency(ack_frequency),
                .immediate_ack => self.receiveImmediateAck(),
                .connection_close => |close| try self.setCloseInfo(.{
                    .application = false,
                    .error_code = close.error_code,
                    .frame_type = close.frame_type,
                    .reason_phrase = close.reason_phrase,
                    .peer_close_frame_received = true,
                    .state = .draining,
                    .now_ms = nsToMs(now_ns),
                }),
                .application_close => |close| try self.setCloseInfo(.{
                    .application = true,
                    .error_code = close.error_code,
                    .reason_phrase = close.reason_phrase,
                    .peer_close_frame_received = true,
                    .state = .draining,
                    .now_ms = nsToMs(now_ns),
                }),
                .stream => |stream| {
                    if (self.isClosedStream(stream.stream_id)) continue;
                    var recv_stream = try self.recvStreamFlow(stream.stream_id);
                    const data_len = std.math.cast(u64, stream.data.len) orelse return error.InvalidFrameLength;
                    const stream_end = std.math.add(u64, stream.offset, data_len) catch return error.InvalidFrameLength;
                    const old_highest_received_end = recv_stream.highest_received_end;
                    try self.applyFinalSize(recv_stream, stream_end, stream.fin);
                    try recv_stream.flow.receive(stream_end);
                    _ = try recv_stream.recv_state.insertTracked(stream);

                    // RFC 9000 connection flow control counts the sum of each
                    // stream's largest received offset. A sparse frame therefore
                    // consumes its gap, while retransmissions and lower-offset
                    // gap fills consume no additional connection credit.
                    const offset_increment = receiveOffsetIncrement(
                        old_highest_received_end,
                        stream_end,
                    );
                    if (offset_increment != 0) {
                        const next_total = std.math.add(u64, self.recv_data_total, offset_increment) catch return error.FlowControlViolation;
                        try self.recv_flow.receive(next_total);
                        self.recv_data_total = next_total;
                    }
                    recv_stream.highest_received_end = @max(recv_stream.highest_received_end, stream_end);
                },
                else => {},
            }
        }
        if (current_path_validated) {
            self.setPeerAddressValidated(true);
            // One successful challenge validates the path. Remaining probes
            // for the same selected tuple are redundant and must not retain a
            // timer or later inflate failed-path statistics. Deferring cleanup
            // until the packet is fully applied lets one packet legitimately
            // answer several outstanding challenges.
            self.path_validation.abandonAllChallenges();
        }
        triggering_frame_index.* = null;
        const credit_now_ns = now_ns orelse self.monotonicNowNs();
        self.flushPendingStopSendingResetAt(credit_now_ns) catch |err| {
            self.scheduleStopSendingResetRetry(err, credit_now_ns);
        };
        self.flushPendingStreamsBlockedResponseAt(credit_now_ns) catch |err| {
            self.scheduleStreamsBlockedResponseRetry(err, credit_now_ns);
        };
        self.flushRequestedStreamReleasesAt(credit_now_ns) catch |err| {
            // ACK and stream state above are already committed. Treat this
            // internal credit packet like an event-loop send: preserve the
            // pending release and arm an independent retry instead of making
            // the authenticated packet appear rejected to the caller.
            self.scheduleStreamReleaseRetry(err, credit_now_ns);
        };
        self.flushPendingReceiveCreditAt(credit_now_ns) catch |err| {
            self.scheduleReceiveCreditRetry(err, credit_now_ns);
        };
    }

    fn validateReceivedFramePreconditions(
        self: *Connection,
        frames: []const quic.Frame,
        packet_destination_connection_id: ?[]const u8,
        triggering_frame_index: *?usize,
    ) Error!?quic.packet_space.SentPacketTracker.ValidatedAck {
        if (frames.len == 1 and frames[0] == .ack) {
            triggering_frame_index.* = 0;
            const validated = try self.sent.validateAckForApply(
                frames[0].ack,
                self.pmtu_path_epoch,
            );
            triggering_frame_index.* = null;
            return validated;
        }
        if (frames.len == 1 and frames[0] == .stream) {
            if (self.isClosedStream(frames[0].stream.stream_id)) {
                try self.validateStreamReceiveFrameId(
                    frames[0].stream.stream_id,
                );
                triggering_frame_index.* = null;
                return null;
            }
            triggering_frame_index.* = 0;
            try self.validateSingleStreamFramePrecondition(frames[0].stream);
            triggering_frame_index.* = null;
            return null;
        }
        var recv_data_total = self.recv_data_total;
        var stack_recv_streams: [16]RecvStreamPreflightEntry = undefined;
        var recv_streams: std.ArrayList(RecvStreamPreflightEntry) =
            .initBuffer(&stack_recv_streams);
        var recv_streams_allocated = false;
        var stack_stream_frames: [16]quic.StreamFrame = undefined;
        var stream_frames = quic.stream_state.RecvState.PreflightFrames.init(
            self.endpoint.allocator,
            &stack_stream_frames,
        );
        defer {
            for (recv_streams.items) |*entry| entry.deinit();
            if (recv_streams_allocated) {
                recv_streams.deinit(self.endpoint.allocator);
            }
            stream_frames.deinit();
        }
        var peer_connection_ids = self.peer_connection_ids;
        var local_connection_ids = self.local_connection_ids;
        var stack_path_challenges: [16][8]u8 = undefined;
        var stack_path_responses: [16][8]u8 = undefined;
        const path_challenge_count = countPathChallenges(frames);
        const path_response_count = countPathResponses(frames);
        const path_challenge_slots = @min(
            path_challenge_count,
            self.config.max_pending_path_responses -|
                self.path_validation.pendingResponseCount(),
        );
        const path_challenges = if (path_challenge_slots <=
            stack_path_challenges.len)
            stack_path_challenges[0..path_challenge_slots]
        else
            try self.endpoint.allocator.alloc([8]u8, path_challenge_slots);
        defer if (path_challenges.ptr != stack_path_challenges[0..].ptr) {
            self.endpoint.allocator.free(path_challenges);
        };
        const path_responses = if (path_response_count <=
            stack_path_responses.len)
            stack_path_responses[0..path_response_count]
        else
            try self.endpoint.allocator.alloc([8]u8, path_response_count);
        defer if (path_responses.ptr != stack_path_responses[0..].ptr) {
            self.endpoint.allocator.free(path_responses);
        };
        var path_validation = quic.path_validation.State.ReceivePreflight.init(
            &self.path_validation,
            path_challenges,
            path_responses,
        );

        for (frames, 0..) |frame, frame_index| {
            triggering_frame_index.* = frame_index;
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
                .stream => |stream| {
                    if (self.isClosedStream(stream.stream_id)) {
                        try self.validateStreamReceiveFrameId(stream.stream_id);
                    } else {
                        try self.validateStreamFramePrecondition(stream, &recv_streams, &recv_streams_allocated, &stream_frames, &recv_data_total);
                    }
                },
                .reset_stream => |reset| {
                    if (self.isClosedStream(reset.stream_id)) {
                        try self.validateStreamReceiveFrameId(reset.stream_id);
                    } else {
                        try self.validateResetStreamPrecondition(reset, &recv_streams, &recv_streams_allocated, &stream_frames, &recv_data_total);
                    }
                },
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
                .path_response => |path_response| try path_validation.recordResponse(path_response.data),
                .new_token => |new_token| {
                    if (self.config.local_endpoint == .server) return error.InvalidFrame;
                    if (new_token.token.len == 0) return error.InvalidFrame;
                },
                .handshake_done => {
                    if (self.config.local_endpoint == .server) return error.InvalidFrame;
                },
                .datagram => |datagram| try self.validateDatagramFrame(datagram),
                .ack_frequency => |ack_frequency| try self.validateAckFrequencyForReceive(ack_frequency),
                .immediate_ack => if (!self.ackFrequencyReceiveEnabled()) return error.AckFrequencyDisabled,
                else => {},
            }
        }
        try path_validation.prepare();
        triggering_frame_index.* = null;
        return null;
    }

    /// Preserve packet-level validate-before-mutate semantics for the common
    /// one-STREAM packet without constructing the general multi-frame shadow
    /// state for connection IDs and path validation.
    fn validateSingleStreamFramePrecondition(
        self: *Connection,
        stream: quic.StreamFrame,
    ) Error!void {
        try self.validateStreamReceiveFrameId(stream.stream_id);

        var stack_stream_frames: [1]quic.StreamFrame = undefined;
        var stream_frames = quic.stream_state.RecvState.PreflightFrames.init(
            self.endpoint.allocator,
            &stack_stream_frames,
        );
        defer stream_frames.deinit();

        var recv_stream: RecvStreamPreflightEntry = if (self.findRecvStreamEntry(stream.stream_id)) |existing| .{
            .stream_id = stream.stream_id,
            .flow_limit = existing.flow.limit,
            .recv_state = quic.stream_state.RecvState.Preflight.init(
                &existing.recv_state,
                &stream_frames,
            ),
            .highest_received_end = existing.highest_received_end,
            .final_size = existing.final_size,
        } else blk: {
            try self.validatePeerStreamCount(stream.stream_id);
            const flow_limit = self.initialReceiveStreamDataLimit(
                stream.stream_id,
            );
            const max_buffered = @max(
                flow_limit,
                self.config.max_stream_receive_window orelse
                    self.config.stream_receive_window,
            );
            break :blk .{
                .stream_id = stream.stream_id,
                .flow_limit = flow_limit,
                .recv_state = quic.stream_state.RecvState.Preflight.initEmpty(
                    self.endpoint.allocator,
                    stream.stream_id,
                    maxBufferedForLimit(max_buffered),
                    &stream_frames,
                ),
            };
        };
        defer recv_stream.deinit();

        var recv_data_total = self.recv_data_total;
        try self.validateStreamFrameAgainstPreflight(
            stream,
            &recv_stream,
            &recv_data_total,
        );
    }

    fn classifySemanticCloseError(
        self: Connection,
        triggering_frame: ?quic.Frame,
        raw_frame_type: ?u64,
        err: anyerror,
    ) ?quic.FramePayloadCloseError {
        const frame = triggering_frame orelse return null;
        return switch (err) {
            error.UnknownPathResponse => if (frame == .path_response)
                quic.FramePayloadCloseError{
                    .code = .protocol_violation,
                    .frame_type = @intFromEnum(quic.FrameType.path_response),
                    .reason_phrase = "path response",
                }
            else
                null,
            error.InvalidFrame => blk: {
                if (self.config.local_endpoint == .server and frame == .new_token) break :blk semanticClose(.protocol_violation, @intFromEnum(quic.FrameType.new_token), "new token");
                if (self.config.local_endpoint == .server and frame == .handshake_done) break :blk semanticClose(.protocol_violation, @intFromEnum(quic.FrameType.handshake_done), "handshake done");
                if (frame == .ack_frequency) break :blk ackFrequencyFrameClose(frame);
                if (frame == .datagram) {
                    const frame_type = if (frame.datagram.length_present)
                        quic.FrameType.datagram_len
                    else
                        quic.FrameType.datagram;
                    break :blk semanticClose(
                        .protocol_violation,
                        @intFromEnum(frame_type),
                        "datagram",
                    );
                }
                break :blk null;
            },
            error.StreamLimitExceeded => triggeringFrameClose(frame, raw_frame_type, .stream_limit_error, "stream limit"),
            error.StreamStateError => triggeringFrameClose(frame, raw_frame_type, .stream_state_error, "stream state"),
            error.FlowControlViolation => triggeringFrameClose(frame, raw_frame_type, .flow_control_error, "flow control"),
            error.FinalSizeMismatch => triggeringFrameClose(frame, raw_frame_type, .final_size_error, "final size"),
            error.ConflictingStreamData => triggeringFrameClose(frame, raw_frame_type, .protocol_violation, "stream data"),
            error.InvalidAckFrame => ackFrameClose(frame, raw_frame_type),
            error.DuplicateConnectionId => connectionIdFrameClose(frame, .protocol_violation, "connection id reuse"),
            error.DuplicateResetToken => connectionIdFrameClose(frame, .protocol_violation, "reset token reuse"),
            error.ActiveConnectionIdLimit => connectionIdFrameClose(frame, .connection_id_limit_error, "connection id limit"),
            error.InvalidConnectionId, error.UnknownConnectionId => retireConnectionIdFrameClose(frame),
            error.AckFrequencyDisabled => ackFrequencyFrameClose(frame),
            else => null,
        };
    }

    fn triggeringFrameClose(
        frame: quic.Frame,
        raw_frame_type: ?u64,
        code: quic.TransportErrorCode,
        reason: []const u8,
    ) ?quic.FramePayloadCloseError {
        const frame_type = frameTypeForSemanticClose(
            frame,
            raw_frame_type,
        ) orelse return null;
        return semanticClose(code, frame_type, reason);
    }

    fn ackFrameClose(
        frame: quic.Frame,
        raw_frame_type: ?u64,
    ) ?quic.FramePayloadCloseError {
        if (frame != .ack) return null;
        const fallback = if (frame.ack.ecn_counts == null)
            @intFromEnum(quic.FrameType.ack)
        else
            @intFromEnum(quic.FrameType.ack_ecn);
        const frame_type = if (raw_frame_type) |value|
            if (value == @intFromEnum(quic.FrameType.ack) or
                value == @intFromEnum(quic.FrameType.ack_ecn)) value else fallback
        else
            fallback;
        return semanticClose(.protocol_violation, frame_type, "ack");
    }

    fn ackFrequencyFrameClose(frame: quic.Frame) ?quic.FramePayloadCloseError {
        if (frame == .ack_frequency) return semanticClose(.protocol_violation, @intFromEnum(quic.FrameType.ack_frequency), "ack frequency");
        if (frame == .immediate_ack) return semanticClose(.protocol_violation, @intFromEnum(quic.FrameType.immediate_ack), "immediate ack");
        return null;
    }

    fn connectionIdFrameClose(frame: quic.Frame, code: quic.TransportErrorCode, reason: []const u8) ?quic.FramePayloadCloseError {
        return if (frame == .new_connection_id)
            semanticClose(code, @intFromEnum(quic.FrameType.new_connection_id), reason)
        else
            null;
    }

    fn retireConnectionIdFrameClose(frame: quic.Frame) ?quic.FramePayloadCloseError {
        return if (frame == .retire_connection_id)
            semanticClose(.protocol_violation, @intFromEnum(quic.FrameType.retire_connection_id), "retire connection id")
        else
            null;
    }

    fn semanticClose(code: quic.TransportErrorCode, frame_type: u64, reason: []const u8) quic.FramePayloadCloseError {
        return .{ .code = code, .frame_type = frame_type, .reason_phrase = reason };
    }

    fn frameTypeForSemanticClose(
        frame: quic.Frame,
        raw_frame_type: ?u64,
    ) ?u64 {
        return switch (frame) {
            .stream => if (raw_frame_type) |value|
                if (quic.FrameType.isStream(value)) value else @intFromEnum(quic.FrameType.stream) | 0x02
            else
                @intFromEnum(quic.FrameType.stream) | 0x02,
            .reset_stream => @intFromEnum(quic.FrameType.reset_stream),
            .stream_data_blocked => @intFromEnum(quic.FrameType.stream_data_blocked),
            .max_stream_data => @intFromEnum(quic.FrameType.max_stream_data),
            .stop_sending => @intFromEnum(quic.FrameType.stop_sending),
            else => null,
        };
    }

    fn validateStreamFramePrecondition(
        self: *Connection,
        stream: quic.StreamFrame,
        recv_streams: *std.ArrayList(RecvStreamPreflightEntry),
        recv_streams_allocated: *bool,
        stream_frames: *quic.stream_state.RecvState.PreflightFrames,
        recv_data_total: *u64,
    ) Error!void {
        try self.validateStreamReceiveFrameId(stream.stream_id);
        const recv_stream = try self.preflightRecvStreamEntry(
            recv_streams,
            recv_streams_allocated,
            stream_frames,
            stream.stream_id,
        );
        _ = try self.validateStreamFrameAgainstPreflight(
            stream,
            recv_stream,
            recv_data_total,
        );
    }

    fn validateStreamFrameAgainstPreflight(
        self: *Connection,
        stream: quic.StreamFrame,
        recv_stream: *RecvStreamPreflightEntry,
        recv_data_total: *u64,
    ) Error!void {
        const data_len = std.math.cast(u64, stream.data.len) orelse return error.InvalidFrameLength;
        const stream_end = std.math.add(u64, stream.offset, data_len) catch return error.InvalidFrameLength;

        try preflightApplyFinalSize(recv_stream, stream_end, stream.fin);
        if (stream_end > recv_stream.flow_limit) return error.FlowControlViolation;
        _ = try recv_stream.recv_state.insertTracked(stream);
        try self.preflightRecvCredit(
            receiveOffsetIncrement(
                recv_stream.highest_received_end,
                stream_end,
            ),
            recv_data_total,
        );
        recv_stream.highest_received_end = @max(recv_stream.highest_received_end, stream_end);
    }

    fn validateResetStreamPrecondition(
        self: *Connection,
        reset: quic.ResetStreamFrame,
        recv_streams: *std.ArrayList(RecvStreamPreflightEntry),
        recv_streams_allocated: *bool,
        stream_frames: *quic.stream_state.RecvState.PreflightFrames,
        recv_data_total: *u64,
    ) Error!void {
        try self.validateStreamReceiveFrameId(reset.stream_id);
        const recv_stream = try self.preflightRecvStreamEntry(
            recv_streams,
            recv_streams_allocated,
            stream_frames,
            reset.stream_id,
        );
        try preflightApplyFinalSize(recv_stream, reset.final_size, true);
        if (reset.final_size > recv_stream.flow_limit) return error.FlowControlViolation;
        const received = recv_stream.recv_state.receivedByteCount();
        if (reset.final_size < received) return error.FinalSizeMismatch;
        try self.preflightRecvCredit(
            receiveOffsetIncrement(
                recv_stream.highest_received_end,
                reset.final_size,
            ),
            recv_data_total,
        );
        recv_stream.highest_received_end = @max(recv_stream.highest_received_end, reset.final_size);
    }

    fn preflightRecvStreamEntry(
        self: *Connection,
        recv_streams: *std.ArrayList(RecvStreamPreflightEntry),
        recv_streams_allocated: *bool,
        stream_frames: *quic.stream_state.RecvState.PreflightFrames,
        stream_id: u64,
    ) Error!*RecvStreamPreflightEntry {
        for (recv_streams.items) |*entry| {
            if (entry.stream_id == stream_id) return entry;
        }

        if (self.findRecvStreamEntry(stream_id)) |existing| {
            var recv_state = quic.stream_state.RecvState.Preflight.init(
                &existing.recv_state,
                stream_frames,
            );
            var appended = false;
            errdefer if (!appended) recv_state.deinit();
            try appendRecvStreamPreflight(recv_streams, recv_streams_allocated, self.endpoint.allocator, .{
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
            try appendRecvStreamPreflight(recv_streams, recv_streams_allocated, self.endpoint.allocator, .{
                .stream_id = stream_id,
                .flow_limit = flow_limit,
                .recv_state = quic.stream_state.RecvState.Preflight.initEmpty(
                    self.endpoint.allocator,
                    stream_id,
                    maxBufferedForLimit(max_buffered),
                    stream_frames,
                ),
            });
        }
        return &recv_streams.items[recv_streams.items.len - 1];
    }

    fn preflightRecvCredit(
        self: Connection,
        offset_increment: u64,
        recv_data_total: *u64,
    ) Error!void {
        if (offset_increment == 0) return;
        const next_total = std.math.add(u64, recv_data_total.*, offset_increment) catch return error.FlowControlViolation;
        if (next_total > self.recv_flow.limit) return error.FlowControlViolation;
        recv_data_total.* = next_total;
    }

    fn appendRecvStreamPreflight(
        entries: *std.ArrayList(RecvStreamPreflightEntry),
        allocated: *bool,
        allocator: std.mem.Allocator,
        entry: RecvStreamPreflightEntry,
    ) Error!void {
        if (!allocated.*) {
            if (entries.items.len < entries.capacity) {
                entries.appendAssumeCapacity(entry);
                return;
            }
            // ArrayList.initBuffer cannot grow with an allocator because its
            // stack storage is not allocator-owned. Spill only the rare packet
            // touching more distinct streams than the common fixed capacity.
            var grown = try std.ArrayList(RecvStreamPreflightEntry)
                .initCapacity(allocator, entries.capacity * 2);
            grown.appendSliceAssumeCapacity(entries.items);
            entries.* = grown;
            allocated.* = true;
        }
        try entries.append(allocator, entry);
    }

    fn preflightApplyFinalSize(recv_stream: *RecvStreamPreflightEntry, final_size: u64, final: bool) Error!void {
        try recv_stream.recv_state.applyFinalSize(final_size, final);
        recv_stream.final_size = if (recv_stream.recv_state.final_size) |size|
            std.math.cast(u64, size) orelse return error.InvalidStreamRange
        else
            null;
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
        self.spin_largest_received_packet_number = null;
    }

    fn resetSpinValueForConnectionId(self: *Connection) void {
        self.spin_bit_value = false;
    }

    fn updateSpinBitAfterReceive(
        self: *Connection,
        from: net.IpAddress,
        packet_number: u64,
        peer_spin_bit: bool,
    ) void {
        if (!self.config.enable_spin_bit) return;
        if (self.config.peer.eql(&from)) {
            updateSpinState(
                self.config.local_endpoint,
                &self.spin_bit_value,
                &self.spin_largest_received_packet_number,
                packet_number,
                peer_spin_bit,
            );
            if (self.peer_address_validated and
                self.last_validated_peer_path.peer.eql(&from) and
                std.mem.eql(
                    u8,
                    self.last_validated_peer_path.connectionId(),
                    self.config.peer_connection_id,
                ))
            {
                self.last_validated_peer_path.spin_bit_value =
                    self.spin_bit_value;
                self.last_validated_peer_path
                    .spin_largest_received_packet_number =
                    self.spin_largest_received_packet_number;
            }
            return;
        }
        if (self.last_validated_peer_path.peer.eql(&from)) {
            updateSpinState(
                self.config.local_endpoint,
                &self.last_validated_peer_path.spin_bit_value,
                &self.last_validated_peer_path
                    .spin_largest_received_packet_number,
                packet_number,
                peer_spin_bit,
            );
            return;
        }
        const index = self.findCandidatePathBudget(from) orelse return;
        const candidate = &self.candidate_path_budgets[index].?;
        updateSpinState(
            self.config.local_endpoint,
            &candidate.spin_bit_value,
            &candidate.spin_largest_received_packet_number,
            packet_number,
            peer_spin_bit,
        );
    }

    fn receiveStreamsBlocked(self: *Connection, maximum_streams: u64, direction: StreamDirection) Error!void {
        if (maximum_streams > quic.max_stream_count) return error.InvalidFrame;
        const current_limit = switch (direction) {
            .bidirectional => self.recv_max_streams_bidi,
            .unidirectional => self.recv_max_streams_uni,
        };
        if (maximum_streams < current_limit) {
            switch (direction) {
                .bidirectional => self.pending_streams_blocked_bidi_response = true,
                .unidirectional => self.pending_streams_blocked_uni_response = true,
            }
        }
    }

    fn hasAcknowledgedPacketAtOrAbove(self: Connection, threshold: u64) bool {
        // `SentPacketTracker` maintains the largest acknowledged packet number
        // incrementally while applying ACK ranges.  Use that cached value for
        // the key-update ACK gate instead of rescanning the sent-packet list on
        // every ACK frame, matching the largest-acked bookkeeping used by
        // production recovery implementations.
        return self.sent.hasAcknowledgedAtOrAbove(threshold);
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
        if (ack_eliciting) {
            self.markAckElicitingActivity(nanosToMillisFloor(now_ns));
            // Successful transmission, rather than packet construction,
            // starts a new PTO arm epoch. This also distinguishes packets sent
            // at the same clock timestamp.
            self.pto_jitter_state.rearm();
        }
        if (self.lowest_one_rtt_packet_number == null or
            packet_number < self.lowest_one_rtt_packet_number.?)
        {
            self.lowest_one_rtt_packet_number = packet_number;
        }
    }

    fn receiveDatagramFrame(
        self: *Connection,
        datagram: quic.DatagramFrame,
        packet_number: u64,
    ) Error!void {
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
            packet_number,
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
        try self.validateAckFrequencyForReceive(ack_frequency);
        if (ack_frequency.sequence_number < self.ack_frequency_recv_next_sequence) return;
        self.ack_frequency_recv_next_sequence = ack_frequency.sequence_number +| 1;
        self.ack_eliciting_threshold = ack_frequency.ack_eliciting_threshold;
        self.requested_max_ack_delay = ack_frequency.request_max_ack_delay;
        self.ack_reordering_threshold = ack_frequency.reordering_threshold;
    }

    fn validateAckFrequencyForReceive(
        self: Connection,
        ack_frequency: quic.AckFrequencyFrame,
    ) Error!void {
        if (!self.ackFrequencyReceiveEnabled()) {
            return error.AckFrequencyDisabled;
        }
        // Obsolete frames are ignored in their entirety, including fields
        // that would be invalid in a newer request.
        if (ack_frequency.sequence_number <
            self.ack_frequency_recv_next_sequence) return;
        try validateRequestedMaxAckDelay(
            ack_frequency.request_max_ack_delay,
            self.config.local_min_ack_delay,
        );
    }

    fn ackFrequencySendEnabled(self: Connection) bool {
        if (!self.config.enable_ack_frequency) return false;
        if (self.config.local_min_ack_delay == null and
            self.config.peer_min_ack_delay == null) return true;
        return self.config.peer_min_ack_delay != null;
    }

    fn ackFrequencyReceiveEnabled(self: Connection) bool {
        if (!self.config.enable_ack_frequency) return false;
        if (self.config.local_min_ack_delay == null and
            self.config.peer_min_ack_delay == null) return true;
        return self.config.local_min_ack_delay != null;
    }

    fn receiveImmediateAck(self: *Connection) void {
        self.immediate_ack_requested = true;
    }

    fn receiveResetStream(self: *Connection, reset: quic.ResetStreamFrame) Error!void {
        var recv_stream = try self.recvStreamFlow(reset.stream_id);
        const first_reset = recv_stream.reset == null;
        const old_highest_received_end = recv_stream.highest_received_end;
        try self.applyFinalSize(recv_stream, reset.final_size, true);
        try recv_stream.flow.receive(reset.final_size);

        const received = recv_stream.recv_state.receivedByteCount();
        if (reset.final_size < received) return error.FinalSizeMismatch;
        const offset_increment = receiveOffsetIncrement(
            old_highest_received_end,
            reset.final_size,
        );
        if (offset_increment != 0) {
            const next_total = std.math.add(u64, self.recv_data_total, offset_increment) catch return error.FlowControlViolation;
            try self.recv_flow.receive(next_total);
            self.recv_data_total = next_total;
        }
        recv_stream.highest_received_end = @max(recv_stream.highest_received_end, reset.final_size);

        if (first_reset) {
            // Snapshot the contiguous prefix at the first reset. STREAM frames
            // can be reordered behind RESET_STREAM and remain useful for
            // protocol validation, but partial delivery is specifically for
            // bytes already available when the reset became observable.
            recv_stream.reset_delivery_end = recv_stream.recv_state.read_offset +
                recv_stream.recv_state.available().len;
        }
        recv_stream.reset = .{
            .application_error_code = reset.application_error_code,
            .final_size = reset.final_size,
        };
    }

    fn receiveStopSending(self: *Connection, stop: quic.StopSendingFrame) Error!void {
        try self.validateNextPacketNumber();
        const entry = try self.sendStreamEntry(stop.stream_id);
        if (entry.stopped != null) return;
        entry.stopped = .{ .application_error_code = stop.application_error_code };
        if (entry.reset_sent == null) {
            // RFC 9000 requires RESET_STREAM unless the send side is already
            // terminal. Record the obligation first; packet application must
            // not wait for pacing, and the aggregate timer retries it even if
            // no later packet arrives.
            self.pending_stop_sending_resets += 1;
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

    fn receiveOffsetIncrement(old_highest_received_end: u64, end_offset: u64) u64 {
        return end_offset -| old_highest_received_end;
    }

    fn sendResetStream(self: *Connection, stream_id: u64, application_error_code: u64, final_size: u64) Error!void {
        try self.sendResetStreamAt(
            stream_id,
            application_error_code,
            final_size,
            null,
        );
    }

    fn sendResetStreamAt(
        self: *Connection,
        stream_id: u64,
        application_error_code: u64,
        final_size: u64,
        sent_time_ns: ?u64,
    ) Error!void {
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
        if (sent_time_ns) |now_ns|
            try self.sendTrackedFramesEcnAt(&frames, .not_ect, now_ns)
        else
            try self.sendTrackedFrames(&frames);
        _ = self.recovery.abandonStreamData(stream_id);
        entry.reset_sent = info;
        if (entry.stopped != null) {
            std.debug.assert(self.pending_stop_sending_resets != 0);
            self.pending_stop_sending_resets -= 1;
        }
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
            if (frame.stream.fin) entry.final_size = stream_end;
        }
    }

    fn recordPacketsLost(self: *Connection, packets: usize) void {
        const packets_u64 = std.math.cast(u64, packets) orelse
            std.math.maxInt(u64);
        self.packets_lost_count +|= packets_u64;
    }

    fn closeLocally(self: *Connection, close: struct {
        application: bool,
        error_code: u64,
        frame_type: u64 = 0,
        reason_phrase: []const u8,
        now_ms: ?u64 = null,
        pto_ms: ?u64 = null,
    }) Error!void {
        if (self.close_info != null or self.idle_timed_out) {
            return error.ConnectionClosed;
        }
        const timing = self.closeTiming(close.now_ms, close.pto_ms);

        // Own the diagnostic before attempting irreversible packet emission.
        // After this succeeds, every send outcome must publish the prepared
        // closing state so callers cannot continue using a connection whose
        // peer might already have observed CONNECTION_CLOSE.
        var owned = CloseInfo{
            .application = close.application,
            .error_code = close.error_code,
            .frame_type = close.frame_type,
            .reason_phrase = try self.endpoint.allocator.dupe(
                u8,
                close.reason_phrase,
            ),
            .state = .closing,
            .started_ms = timing.now_ms,
            .expires_ms = closeExpiryMillis(timing.now_ms, timing.pto_ms),
        };
        var owns_reason = true;
        errdefer if (owns_reason) owned.deinit(self.endpoint.allocator);

        const frame: quic.Frame = if (owned.application)
            .{ .application_close = .{
                .error_code = owned.error_code,
                .reason_phrase = owned.reason_phrase,
            } }
        else
            .{ .connection_close = .{
                .error_code = owned.error_code,
                .frame_type = owned.frame_type,
                .reason_phrase = owned.reason_phrase,
            } };
        const send_error: ?Error = blk: {
            self.sendTrackedFrames(&.{frame}) catch |err| break :blk err;
            break :blk null;
        };

        // Packet preparation can itself discover an exhausted AEAD limit and
        // install that more fundamental terminal state. Preserve it rather
        // than overwriting its owned reason phrase or emitting a second qlog
        // close event; the errdefer above releases this unused local request.
        if (self.close_info != null) {
            if (send_error) |err| return err;
            return error.ConnectionClosed;
        }

        self.close_info = owned;
        owns_reason = false;
        self.peer_close_frame_received = false;
        const installed = &self.close_info.?;
        self.observeConnectionClosed(
            installed.started_ms,
            installed.application,
            installed.error_code,
            installed.reason_phrase,
            installed.state,
        );
        if (send_error) |err| return err;
    }

    fn setCloseInfo(self: *Connection, close: struct {
        application: bool,
        error_code: u64,
        frame_type: u64 = 0,
        reason_phrase: []const u8,
        peer_close_frame_received: bool = false,
        state: CloseState,
        now_ms: ?u64 = null,
        pto_ms: ?u64 = null,
    }) Error!void {
        const timing = self.closeTiming(close.now_ms, close.pto_ms);
        if (self.close_info) |*existing| {
            // RFC 9000: receipt of CONNECTION_CLOSE moves the endpoint into
            // draining, where no further packets are sent.  A locally initiated
            // close starts in `closing`; if the peer answers with its own close,
            // do not ignore that transition merely because close_info exists.
            if (close.state == .draining and existing.state == .closing) {
                // Allocate before mutating so OOM leaves the locally initiated
                // closing state intact and retransmittable.
                const peer_reason = if (close.peer_close_frame_received)
                    try self.endpoint.allocator.dupe(u8, close.reason_phrase)
                else
                    null;
                if (peer_reason) |reason_phrase| {
                    self.endpoint.allocator.free(existing.reason_phrase);
                    existing.application = close.application;
                    existing.error_code = close.error_code;
                    existing.frame_type = close.frame_type;
                    existing.reason_phrase = reason_phrase;
                    self.peer_close_frame_received = true;
                }
                existing.state = .draining;
                existing.response_deadline_ns = null;
                existing.response_packets = 0;
                existing.started_ms = timing.now_ms;
                existing.expires_ms = closeExpiryMillis(
                    timing.now_ms,
                    timing.pto_ms,
                );
                self.observeConnectionClosed(
                    timing.now_ms,
                    close.application,
                    close.error_code,
                    close.reason_phrase,
                    close.state,
                );
            }
            return;
        }
        const expires_ms = closeExpiryMillis(timing.now_ms, timing.pto_ms);
        self.close_info = .{
            .application = close.application,
            .error_code = close.error_code,
            .frame_type = close.frame_type,
            .reason_phrase = try self.endpoint.allocator.dupe(u8, close.reason_phrase),
            .state = close.state,
            .started_ms = timing.now_ms,
            .expires_ms = expires_ms,
        };
        self.peer_close_frame_received = close.peer_close_frame_received;
        self.observeConnectionClosed(
            timing.now_ms,
            close.application,
            close.error_code,
            close.reason_phrase,
            close.state,
        );
    }

    fn closeTiming(
        self: Connection,
        now_ms: ?u64,
        pto_ms: ?u64,
    ) struct { now_ms: u64, pto_ms: u64 } {
        return .{
            .now_ms = now_ms orelse
                nanosToMillisCeil(self.monotonicNowNs()),
            // Round upward before multiplying so the millisecond deadline can
            // never expire before RFC 9000's three-PTO minimum.
            .pto_ms = pto_ms orelse
                nanosToMillisCeil(self.rtt_stats.pto(true)),
        };
    }

    fn noteCloseDatagramAt(self: *Connection, now_ns: u64) void {
        const close_info = if (self.close_info) |*value| value else return;
        if (close_info.state != .closing or
            close_info.response_deadline_ns != null)
        {
            return;
        }
        close_info.response_packets +|= 1;
        if (close_info.response_packets <
            close_info.response_packet_threshold)
        {
            return;
        }
        close_info.response_packets = 0;
        close_info.response_packet_threshold *|= 2;
        self.scheduleCloseResponseAt(now_ns);
    }

    fn scheduleCloseResponseAt(self: *Connection, now_ns: u64) void {
        const close_info = if (self.close_info) |*value| value else return;
        if (close_info.state != .closing) return;
        close_info.response_deadline_ns = std.math.add(
            u64,
            now_ns,
            self.rtt_stats.smoothedOrInitial(),
        ) catch std.math.maxInt(u64);
    }

    fn enterStatelessResetDraining(self: *Connection, now_ms: ?u64, pto_ms: ?u64) Error!void {
        const timing = self.closeTiming(now_ms, pto_ms);
        if (self.close_info) |*close_info| {
            close_info.state = .draining;
            close_info.response_deadline_ns = null;
            close_info.response_packets = 0;
            close_info.started_ms = timing.now_ms;
            close_info.expires_ms = closeExpiryMillis(
                timing.now_ms,
                timing.pto_ms,
            );
            return;
        }
        try self.setCloseInfo(.{
            .application = false,
            .error_code = 0,
            .frame_type = 0,
            .reason_phrase = "stateless reset",
            .state = .draining,
            .now_ms = timing.now_ms,
            .pto_ms = timing.pto_ms,
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
            .disable_active_migration = self.config.local_disable_active_migration,
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

    fn monotonicNowNs(self: *const Connection) u64 {
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

    fn applyAckWithEcnFailure(
        self: *Connection,
        ack: quic.AckFrame,
        validated: ?quic.packet_space.SentPacketTracker.ValidatedAck,
    ) Error!quic.packet_space.SentPacketTracker.AckResult {
        var plain_ack = ack;
        plain_ack.ecn_counts = null;
        const plain_ack_current_path_failure =
            self.sent.plainAckWouldFailForPathEpoch(
                plain_ack,
                self.pmtu_path_epoch,
            );
        if (ack.ecn_counts == null or
            !self.sent.validateAckEcnFrameWouldFailForPathEpoch(
                ack,
                self.pmtu_path_epoch,
            ))
        {
            return error.InvalidAckFrame;
        }
        const result = try self.sent.applyAckDetailedForProbeValidated(
            plain_ack,
            self.pmtud.active_probe_packet_number,
            self.pmtud.active_probe_epoch,
            self.pmtud.currentSize(),
            self.pmtu_path_epoch,
            validated,
        );
        if (plain_ack_current_path_failure) {
            self.ecn_path.onValidationFailure();
        }
        if (result.ect0_packets != 0 or result.ect1_packets != 0) {
            self.ecn_path_baseline_pending = true;
        }
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
        return self.releaseReceivedCapacityAt(stream_id, amount, null);
    }

    /// Return application-consumed receive credit without sleeping for
    /// pacing. A failed MAX_DATA/MAX_STREAM_DATA attempt leaves both flow
    /// windows and retained stream bytes unchanged for an event-loop retry.
    pub fn tryReleaseReceivedCapacity(
        self: *Connection,
        stream_id: u64,
        amount: u64,
    ) Error!void {
        return self.releaseReceivedCapacityAt(
            stream_id,
            amount,
            self.monotonicNowNs(),
        );
    }

    /// Commit ownership of received bytes through one absolute stream offset.
    /// Protocol adapters that copy bytes into their own bounded reassembly use
    /// this after parsing succeeds. The receive cursor and both flow windows
    /// advance immediately; MAX_DATA/MAX_STREAM_DATA are sent nonblockingly or
    /// retained for the connection timer to retry.
    pub fn commitReceivedThrough(
        self: *Connection,
        stream_id: u64,
        end_offset: u64,
    ) Error!void {
        const recv_stream = self.findRecvStreamEntry(stream_id) orelse
            return error.StreamStateError;
        const read_offset = std.math.cast(
            u64,
            recv_stream.recv_state.read_offset,
        ) orelse return error.InvalidStreamRange;
        if (end_offset < read_offset) return error.InvalidStreamRange;
        const amount = end_offset - read_offset;
        if (amount == 0) return;
        const consume_len = std.math.cast(usize, amount) orelse
            return error.InvalidFrameLength;
        if (consume_len > recv_stream.recv_state.available().len) {
            return error.InvalidStreamRange;
        }

        if (self.recv_flow.consume(amount) != null) {
            self.pending_max_data = true;
        }
        if (recv_stream.flow.consume(amount) != null and
            !recv_stream.pending_max_stream_data)
        {
            recv_stream.pending_max_stream_data = true;
            self.pending_receive_stream_credits += 1;
        }
        recv_stream.recv_state.consume(consume_len) catch unreachable;

        const now_ns = self.monotonicNowNs();
        self.flushPendingReceiveCreditAt(now_ns) catch |err| {
            self.scheduleReceiveCreditRetry(err, now_ns);
        };
    }

    /// Discard a contiguous receive prefix after the application has sent
    /// STOP_SENDING. Only connection-level credit is replenished: extending
    /// this stream's MAX_STREAM_DATA would invite additional bytes that the
    /// application has explicitly abandoned. A received RESET_STREAM charges
    /// its complete final size to connection flow control even when gaps remain;
    /// settle that stream-level charge here while retaining its reset metadata
    /// for the protocol adapter to report. The return value is the number of
    /// contiguous buffered bytes removed.
    pub fn discardStoppedReceived(
        self: *Connection,
        stream_id: u64,
    ) Error!usize {
        const recv_stream = self.findRecvStreamEntry(stream_id) orelse
            return error.StreamStateError;
        if (recv_stream.stop_sending_sent == null) {
            return error.StreamStateError;
        }
        return self.discardAbandonedReceived(recv_stream);
    }

    /// Release connection-level credit for a receive direction terminated by
    /// RESET_STREAM while preserving the reset metadata for one application
    /// notification. No MAX_STREAM_DATA is generated for a terminal stream.
    pub fn discardResetReceived(
        self: *Connection,
        stream_id: u64,
    ) Error!usize {
        const recv_stream = self.findRecvStreamEntry(stream_id) orelse
            return error.StreamStateError;
        if (recv_stream.reset == null) return error.StreamStateError;
        return self.discardAbandonedReceived(recv_stream);
    }

    fn discardAbandonedReceived(
        self: *Connection,
        recv_stream: *StreamRecvFlowEntry,
    ) Error!usize {
        const discarded = recv_stream.recv_state.available().len;
        const outstanding_credit = recv_stream.flow.highest_received -|
            recv_stream.flow.consumed;
        if (recv_stream.pending_max_stream_data) {
            recv_stream.pending_max_stream_data = false;
            std.debug.assert(self.pending_receive_stream_credits != 0);
            self.pending_receive_stream_credits -= 1;
        }
        if (discarded == 0 and outstanding_credit == 0) {
            if (!self.hasPendingReceiveCredit()) self.clearReceiveCreditRetry();
            return 0;
        }
        if (self.recv_flow.consume(outstanding_credit) != null) {
            self.pending_max_data = true;
        }
        // The stream-level flow counter can advance across reassembly gaps
        // because the caller has explicitly abandoned this receive direction.
        // Keep the actual reassembly cursor contiguous for overlap and
        // final-size validation of reordered packets.
        recv_stream.flow.consumed = recv_stream.flow.highest_received;
        try recv_stream.recv_state.consume(discarded);
        const now_ns = self.monotonicNowNs();
        self.flushPendingReceiveCreditAt(now_ns) catch |err| {
            self.scheduleReceiveCreditRetry(err, now_ns);
        };
        if (!self.hasPendingReceiveCredit()) self.clearReceiveCreditRetry();
        return discarded;
    }

    fn releaseReceivedCapacityAt(
        self: *Connection,
        stream_id: u64,
        amount: u64,
        sent_time_ns: ?u64,
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
        if (count != 0) {
            if (sent_time_ns) |now_ns|
                try self.sendAutomaticallyAt(frames[0..count], now_ns)
            else
                try self.send(frames[0..count]);
        }
        try recv_stream.recv_state.consume(consume_len);
    }

    /// Submit one application packet while atomically returning consumed
    /// receive credit. This is the event-loop counterpart used when an upper
    /// protocol must not expose its packet before the receive cursor commits.
    /// Pacing, congestion, flow-control, and size failures leave both sides
    /// unchanged for retry.
    pub fn trySendAndReleaseReceivedCapacity(
        self: *Connection,
        stream_id: u64,
        amount: u64,
        application_frame: quic.Frame,
    ) Error!void {
        return self.trySendAndReleaseReceivedCapacityAt(
            stream_id,
            amount,
            application_frame,
            self.monotonicNowNs(),
        );
    }

    fn trySendAndReleaseReceivedCapacityAt(
        self: *Connection,
        stream_id: u64,
        amount: u64,
        application_frame: quic.Frame,
        sent_time_ns: u64,
    ) Error!void {
        const recv_stream = self.findRecvStreamEntry(stream_id) orelse
            return error.StreamStateError;
        const consume_len = std.math.cast(usize, amount) orelse
            return error.InvalidFrameLength;
        if (consume_len > recv_stream.recv_state.available().len) {
            return error.InvalidStreamRange;
        }
        var next_connection = self.recv_flow;
        var next_stream = recv_stream.flow;
        var frames: [3]quic.Frame = undefined;
        frames[0] = application_frame;
        var count: usize = 1;
        if (next_connection.consume(amount) != null) {
            frames[count] = next_connection.maxDataFrame();
            count += 1;
        }
        if (next_stream.consume(amount) != null) {
            frames[count] = next_stream.maxStreamDataFrame(stream_id);
            count += 1;
        }
        try self.sendAutomaticallyAt(frames[0..count], sent_time_ns);
        self.recv_flow = next_connection;
        recv_stream.flow = next_stream;
        recv_stream.recv_state.consume(consume_len) catch unreachable;
    }

    fn sendStreamFlow(self: *Connection, stream_id: u64) Error!*quic.flow_control.SendFlow {
        const entry = try self.sendStreamEntry(stream_id);
        return &entry.flow;
    }

    fn sendStreamTerminal(self: *Connection, stream_id: u64) bool {
        const entry = self.findSendStreamEntry(stream_id) orelse return false;
        if (self.recovery.hasPendingStreamData(stream_id)) return false;
        if (entry.reset_sent != null) {
            return !self.recovery.hasPendingResetStream(stream_id);
        }
        return entry.final_size != null;
    }

    fn sendStreamEntry(self: *Connection, stream_id: u64) Error!*StreamFlowEntry {
        if (self.findSendStreamEntry(stream_id)) |entry| return entry;
        if (self.isClosedStream(stream_id)) return error.StreamStateError;
        if (streamInitiatedByLocal(self.config.local_endpoint, stream_id)) {
            try self.validateLocalStreamCount(stream_id);
            // Preserve the historical direct-STREAM API: using a local ID can
            // implicitly reserve it and all lower IDs in that stream-number
            // space. Explicit `openStream` calls already advanced `next`, so
            // they do not increment observability a second time here.
            const next = if (streamDirection(stream_id) == .bidirectional)
                &self.next_local_bidi_stream_id
            else
                &self.next_local_uni_stream_id;
            const requested_count = streamCountForId(stream_id);
            const reserved_count = next.* >> 2;
            if (requested_count > reserved_count) {
                next.* = std.math.add(u64, stream_id, 4) catch
                    return error.StreamLimitExceeded;
                self.outgoing_streams_created_count +|=
                    requested_count - reserved_count;
            }
        }
        const slot = try self.stream_send_index.getOrPut(
            self.endpoint.allocator,
            stream_id,
        );
        std.debug.assert(!slot.found_existing);
        errdefer _ = self.stream_send_index.remove(stream_id);

        try self.stream_send_flows.ensureUnusedCapacity(self.endpoint.allocator, 1);
        const index = self.stream_send_flows.items.len;
        self.stream_send_flows.appendAssumeCapacity(.{
            .stream_id = stream_id,
            .flow = .init(self.initialSendStreamDataLimit(stream_id)),
        });
        slot.value_ptr.* = index;
        self.last_send_stream_index = index;
        return &self.stream_send_flows.items[self.stream_send_flows.items.len - 1];
    }

    fn validateStreamFrameForSendAt(
        self: *Connection,
        stream: quic.StreamFrame,
        sent_time_ns: ?u64,
    ) Error!void {
        if (self.findSendStreamEntry(stream.stream_id)) |entry| {
            if (entry.stopped != null or entry.reset_sent != null) return error.StreamStopped;
            const data_len = std.math.cast(u64, stream.data.len) orelse
                return error.InvalidFrameLength;
            const end = std.math.add(
                u64,
                stream.offset,
                data_len,
            ) catch return error.InvalidFrameLength;
            if (entry.final_size) |final_size| {
                if (end > final_size or
                    (stream.fin and end != final_size))
                {
                    return error.FinalSizeMismatch;
                }
                if (stream.data.len != 0 and
                    end > entry.highest_sent_end)
                {
                    return error.FinalSizeMismatch;
                }
            }
            return;
        }
        if (self.isClosedStream(stream.stream_id)) {
            return error.StreamStateError;
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
        if (sent_time_ns) |now_ns|
            try self.sendStreamsBlockedAt(direction, now_ns)
        else
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
        return self.sendStreamsBlockedAt(direction, null);
    }

    fn sendStreamsBlockedAt(
        self: *Connection,
        direction: StreamDirection,
        sent_time_ns: ?u64,
    ) Error!void {
        const frame = self.streamsBlockedFrame(direction) orelse return;
        if (sent_time_ns) |now_ns|
            try self.sendTrackedFramesEcnAt(
                &[_]quic.Frame{frame},
                .not_ect,
                now_ns,
            )
        else
            try self.sendTrackedFrames(&[_]quic.Frame{frame});
        self.markStreamsBlockedSent(direction);
    }

    fn sendStreamsBlockedWithDeadline(
        self: *Connection,
        direction: StreamDirection,
        deadline: std.Io.Clock.Timestamp,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
        const frame = self.streamsBlockedFrame(direction) orelse return;
        try self.sendTrackedFramesWithDeadline(
            &[_]quic.Frame{frame},
            deadline,
        );
        self.markStreamsBlockedSent(direction);
    }

    fn streamsBlockedFrame(
        self: Connection,
        direction: StreamDirection,
    ) ?quic.Frame {
        const frame: quic.Frame = switch (direction) {
            .bidirectional => blk: {
                if (self.streams_blocked_bidi_at) |blocked_at| {
                    if (blocked_at == self.peer_max_streams_bidi) return null;
                }
                break :blk .{ .streams_blocked_bidi = .{ .maximum_streams = self.peer_max_streams_bidi } };
            },
            .unidirectional => blk: {
                if (self.streams_blocked_uni_at) |blocked_at| {
                    if (blocked_at == self.peer_max_streams_uni) return null;
                }
                break :blk .{ .streams_blocked_uni = .{ .maximum_streams = self.peer_max_streams_uni } };
            },
        };
        return frame;
    }

    fn markStreamsBlockedSent(
        self: *Connection,
        direction: StreamDirection,
    ) void {
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
        if (self.stream_send_index.count() == 0) return null;
        const index = self.stream_send_index.get(stream_id) orelse return null;
        if (index >= self.stream_send_flows.items.len) return null;
        if (self.stream_send_flows.items[index].stream_id != stream_id) return null;
        self.last_send_stream_index = index;
        return &self.stream_send_flows.items[index];
    }

    fn recvStreamFlow(self: *Connection, stream_id: u64) Error!*StreamRecvFlowEntry {
        if (self.findRecvStreamEntry(stream_id)) |entry| return entry;
        if (self.isClosedStream(stream_id)) return error.StreamStateError;
        try self.validateStreamReceiveFrameId(stream_id);
        try self.validatePeerStreamCount(stream_id);
        const initial_limit = self.initialReceiveStreamDataLimit(stream_id);
        const max_buffered = @max(
            initial_limit,
            self.config.max_stream_receive_window orelse
                self.config.stream_receive_window,
        );
        const slot = try self.stream_recv_index.getOrPut(
            self.endpoint.allocator,
            stream_id,
        );
        std.debug.assert(!slot.found_existing);
        errdefer _ = self.stream_recv_index.remove(stream_id);

        try self.stream_recv_flows.ensureUnusedCapacity(self.endpoint.allocator, 1);
        const index = self.stream_recv_flows.items.len;
        self.stream_recv_flows.appendAssumeCapacity(.{
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
        slot.value_ptr.* = index;
        self.last_recv_stream_index = index;
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
        if (self.stream_recv_index.count() == 0) return null;
        const index = self.stream_recv_index.get(stream_id) orelse return null;
        if (index >= self.stream_recv_flows.items.len) return null;
        if (self.stream_recv_flows.items[index].stream_id != stream_id) return null;
        self.last_recv_stream_index = index;
        return &self.stream_recv_flows.items[index];
    }

    fn validateStreamReceiveFrameId(self: *Connection, stream_id: u64) Error!void {
        if (!streamHasReceiveSide(self.config.local_endpoint, stream_id)) return error.StreamStateError;
        if (self.isClosedStream(stream_id)) return;
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
        if (self.isClosedStream(stream_id)) return;
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

    /// Whether `stream_id` belongs to a peer-initiated stream-number space and
    /// falls within the current receive-side MAX_STREAMS limit. This does not
    /// inspect opened/closed state or mutate stream bookkeeping, which lets
    /// upper protocols validate references to idle streams.
    pub fn isPeerInitiatedStreamIdWithinLimit(
        self: Connection,
        stream_id: u64,
    ) bool {
        if (stream_id > quic.varint.max_value) return false;
        if (streamInitiatedByLocal(self.config.local_endpoint, stream_id)) {
            return false;
        }
        const count = streamCountForId(stream_id);
        return if (streamDirection(stream_id) == .bidirectional)
            count <= self.recv_max_streams_bidi
        else
            count <= self.recv_max_streams_uni;
    }

    /// Specialized form for protocols whose identifiers can only refer to a
    /// peer-created bidirectional stream, such as an HTTP/3 request stream.
    pub fn isPeerInitiatedBidirectionalStreamIdWithinLimit(
        self: Connection,
        stream_id: u64,
    ) bool {
        return streamDirection(stream_id) == .bidirectional and
            self.isPeerInitiatedStreamIdWithinLimit(stream_id);
    }

    fn initialSendStreamDataLimit(
        self: *const Connection,
        stream_id: u64,
    ) u64 {
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

fn containsStreamId(stream_ids: []const u64, target: u64) bool {
    for (stream_ids) |stream_id| {
        if (stream_id == target) return true;
    }
    return false;
}

fn advanceStreamLimit(current: u64, released: u64) u64 {
    std.debug.assert(current <= quic.max_stream_count);
    return current + @min(released, quic.max_stream_count - current);
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

fn nextPathEpoch(current: u32) u32 {
    const next = current +% 1;
    return if (next == 0) 1 else next;
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

/// Select the earlier wakeup without losing whether it belongs to transport
/// maintenance or to the application-level operation. Both deadlines use the
/// awake clock, so their raw timestamps are directly comparable.
fn earliestConnectionReceiveTimeout(
    transport: ?TimerDeadline,
    caller: ?std.Io.Clock.Timestamp,
) std.Io.Timeout {
    const transport_deadline: ?std.Io.Clock.Timestamp = if (transport) |value|
        .{
            .clock = .awake,
            .raw = .fromNanoseconds(
                std.math.cast(i96, value.deadline_ns) orelse
                    std.math.maxInt(i96),
            ),
        }
    else
        null;
    if (transport_deadline) |timer| {
        if (caller) |deadline| {
            return .{ .deadline = if (timer.raw.nanoseconds <
                deadline.raw.nanoseconds) timer else deadline };
        }
        return .{ .deadline = timer };
    }
    return if (caller) |deadline| .{ .deadline = deadline } else .none;
}

fn callerDeadlineFromTimeout(
    io: std.Io,
    timeout: std.Io.Timeout,
) ?std.Io.Clock.Timestamp {
    const deadline = timeout.toTimestamp(io);
    if (deadline) |value| {
        if (value.clock == .awake) return value;
        // Compare all receive deadlines in the monotonic awake domain. This
        // samples both clocks once rather than relying on Clock.Timestamp's
        // cross-clock conversion, which is not available on every backend.
        return .fromNow(io, .{
            .clock = .awake,
            .raw = value.durationFromNow(io).raw,
        });
    }
    return null;
}

fn callerDeadlineExpired(
    deadline: ?std.Io.Clock.Timestamp,
    now_ns: u64,
) bool {
    const value = deadline orelse return false;
    const now = std.math.cast(i96, now_ns) orelse std.math.maxInt(i96);
    return now >= value.raw.nanoseconds;
}

fn countPathChallenges(frames: []const quic.Frame) usize {
    var count: usize = 0;
    for (frames) |frame| {
        if (frame == .path_challenge) count += 1;
    }
    return count;
}

fn countPathResponses(frames: []const quic.Frame) usize {
    var count: usize = 0;
    for (frames) |frame| {
        if (frame == .path_response) count += 1;
    }
    return count;
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
    return if (now_ns) |ns| nanosToMillisCeil(ns) else null;
}

fn discardPacketView(_: void, _: ReceivedPacketView) error{}!void {}

fn acknowledgePacketView(
    connection: *Connection,
    packet: ReceivedPacketView,
) Error!void {
    _ = connection.sendAckForPacketIfNeeded(
        packet.packet_number,
        packet.frames,
    ) catch {};
}

const BatchAckObservation = struct {
    largest_packet_number: ?u64,
    reordering_threshold: u64,
    ack_eliciting_count: u64 = 0,
    reordered: bool = false,

    fn observe(
        self: *BatchAckObservation,
        packet: ReceivedPacketView,
    ) error{}!void {
        if (!frame_traits.ackEliciting(packet.frames)) return;
        self.ack_eliciting_count +|= 1;
        if (self.largest_packet_number) |largest| {
            if (packet.packet_number < largest and
                self.reordering_threshold != 0 and
                largest - packet.packet_number >= self.reordering_threshold)
            {
                self.reordered = true;
            } else if (packet.packet_number > largest) {
                self.largest_packet_number = packet.packet_number;
            }
        } else {
            self.largest_packet_number = packet.packet_number;
        }
    }
};

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
    const sizes = try framePacketStorageSizes(options);
    if (sizes.packet > endpoint.limits.max_datagram_size) {
        return error.DatagramTooLarge;
    }
    const packet_storage = try endpoint.allocator.alloc(u8, sizes.packet);
    defer endpoint.allocator.free(packet_storage);
    try sendFramesIntoSized(
        endpoint,
        to,
        keys,
        options,
        sizes,
        packet_storage,
    );
}

pub const FramePacketStorageSizes = struct {
    payload: usize,
    packet: usize,
};

/// Return exact caller storage for one stateless 1-RTT packet. Validation and
/// sizing complete before either output buffer is mutated.
pub fn framePacketStorageSizes(
    options: SendOptions,
) Error!FramePacketStorageSizes {
    if (options.frames.len == 0) return error.MissingFrame;
    var payload_len: usize = 0;
    for (options.frames) |frame| {
        try quic.validateFrameForPacketType(frame, .one_rtt);
        payload_len = std.math.add(
            usize,
            payload_len,
            try frame.wireLen(),
        ) catch return error.InvalidFrameLength;
    }
    return .{
        .payload = payload_len,
        .packet = try quic.protection.shortPacketLenForPayloadLen(
            options.destination_connection_id.len,
            options.packet_number,
            options.packet_number_len,
            payload_len,
        ),
    };
}

/// Encode, protect and submit one stateless 1-RTT packet without allocation.
pub fn sendFramesInto(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    options: SendOptions,
    packet_storage: []u8,
) Error!void {
    const sizes = try framePacketStorageSizes(options);
    return sendFramesIntoSized(
        endpoint,
        to,
        keys,
        options,
        sizes,
        packet_storage,
    );
}

fn sendFramesIntoSized(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    options: SendOptions,
    sizes: FramePacketStorageSizes,
    packet_storage: []u8,
) Error!void {
    if (packet_storage.len < sizes.packet) {
        return error.BufferTooShort;
    }
    if (sizes.packet > endpoint.limits.max_datagram_size) {
        return error.DatagramTooLarge;
    }
    const packet = try sealFramesIntoSized(
        keys,
        options,
        sizes,
        packet_storage,
    );
    try endpoint.sendBytes(to, packet);
}

/// Encode and protect one stateless 1-RTT packet without submitting it.
///
/// Callers that own packet-number state can use the successful return as the
/// exact nonce-consumption boundary, retire the packet number, and only then
/// attempt socket I/O.
pub fn sealFramesInto(
    keys: quic.protection.PacketProtectionKeys,
    options: SendOptions,
    packet_storage: []u8,
) Error![]u8 {
    const sizes = try framePacketStorageSizes(options);
    return sealFramesIntoSized(keys, options, sizes, packet_storage);
}

fn sealFramesIntoSized(
    keys: quic.protection.PacketProtectionKeys,
    options: SendOptions,
    sizes: FramePacketStorageSizes,
    packet_storage: []u8,
) Error![]u8 {
    if (packet_storage.len < sizes.packet) {
        return error.BufferTooShort;
    }

    const payload_offset = 1 + options.destination_connection_id.len +
        @as(usize, options.packet_number_len);
    const payload_out = packet_storage[payload_offset..][0..sizes.payload];
    var fixed = std.heap.FixedBufferAllocator.init(payload_out);
    var encoded = try std.ArrayList(u8).initCapacity(
        fixed.allocator(),
        sizes.payload,
    );
    for (options.frames) |frame| {
        try frame.write(&encoded, fixed.allocator());
    }
    std.debug.assert(encoded.items.len == sizes.payload);
    return quic.protection.sealShortPacketInPlace(
        packet_storage[0..sizes.packet],
        keys,
        .{
            .destination_connection_id = options.destination_connection_id,
            .packet_number = options.packet_number,
            .packet_number_len = options.packet_number_len,
            .fixed_bit = options.fixed_bit,
            .spin_bit = options.spin_bit,
            .key_phase = options.key_phase,
            .payload = encoded.items,
        },
    );
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
/// Unlike `sendFramesBatchInto`, endpoint send errors are returned in the
/// result so stateful callers can consume every protected packet number even
/// when the socket-visible prefix is empty. Validation, sizing, and packet
/// protection still finish before the first datagram is submitted.
pub fn sendFramesBatchIntoProgress(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    options: BatchSendOptions,
    payload_storage: []u8,
    packet_storage: []u8,
) Error!BatchSendResult {
    if (options.packets.len == 0) {
        return .{
            .sent_count = 0,
            .protected_count = 0,
            .sent_bytes = 0,
        };
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

    const send_result = endpoint.sendManyBytesProgress(
        to,
        datagrams[0..options.packets.len],
    ) catch |err| {
        return .{
            .sent_count = 0,
            .protected_count = options.packets.len,
            .sent_bytes = 0,
            .send_error = err,
        };
    };
    var sent_bytes: usize = 0;
    for (packet_lengths[0..send_result.sent_count]) |packet_len| {
        sent_bytes += packet_len;
    }
    return .{
        .sent_count = send_result.sent_count,
        .protected_count = options.packets.len,
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

fn writeRetransmittableFramesAssumeCapacity(
    list: *std.ArrayList(u8),
    frames: []const quic.Frame,
    all_payload_bytes_retransmittable: bool,
) Error!void {
    // Validation already classified the packet. Avoid repeating that branchy
    // pass for the overwhelmingly common all-reliable payload; mixed packets
    // still filter DATAGRAM and the other non-retransmittable frame classes.
    if (all_payload_bytes_retransmittable) {
        for (frames) |frame| try frame.writeAssumeCapacity(list);
        return;
    }
    for (frames) |frame| {
        if (frame_traits.classify(frame).retransmittable) {
            try frame.writeAssumeCapacity(list);
        }
    }
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

fn appendReservedStreamCredit(
    credits: *std.ArrayList(ReservedStreamCredit),
    allocated: *bool,
    allocator: std.mem.Allocator,
    credit: ReservedStreamCredit,
) Error!void {
    if (!allocated.*) {
        if (credits.items.len < credits.capacity) {
            credits.appendAssumeCapacity(credit);
            return;
        }
        // A normal packet touches one stream. Keep rollback metadata on the
        // stack and spill only unusually wide packets without ever asking an
        // allocator to grow caller-owned stack storage.
        var grown = try std.ArrayList(ReservedStreamCredit).initCapacity(
            allocator,
            credits.capacity * 2,
        );
        grown.appendSliceAssumeCapacity(credits.items);
        credits.* = grown;
        allocated.* = true;
    }
    try credits.append(allocator, credit);
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
    return datagramFrameWireSizeForLength(
        datagram.data.len,
        datagram.length_present,
    );
}

fn datagramFrameWireSizeForLength(
    data_len: usize,
    length_present: bool,
) ?usize {
    const type_len = quic.varint.length(if (length_present)
        @intFromEnum(quic.FrameType.datagram_len)
    else
        @intFromEnum(quic.FrameType.datagram)) catch return null;
    var total = std.math.add(usize, type_len, data_len) catch return null;
    if (length_present) {
        const len_len = quic.varint.length(data_len) catch return null;
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

/// Recover the exact wire type of one already parsed frame on the semantic
/// error path. `Frame` intentionally normalizes ACK/ACK_ECN and all eight
/// STREAM encodings, but RFC 9000 CONNECTION_CLOSE requires the triggering
/// frame type as it appeared on the wire.
fn rawFrameTypeAtIndex(
    allocator: std.mem.Allocator,
    payload: []const u8,
    target_index: usize,
) ?u64 {
    var pos: usize = 0;
    var index: usize = 0;
    while (pos < payload.len) : (index += 1) {
        const frame_type = quic.rawFrameTypeValue(payload[pos..]);
        if (index == target_index) return frame_type;
        var parsed = quic.parseFrameOwned(allocator, payload[pos..]) catch
            return null;
        const consumed = parsed.consumed;
        parsed.deinitOwned(allocator);
        if (consumed == 0) return null;
        pos += consumed;
    }
    return null;
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
    pub fn hasPreparedSendPacketProtection(
        connection: *const Connection,
    ) bool {
        return connection.prepared_send_keys != null;
    }

    pub fn hasPreparedReceivePacketProtection(
        connection: *const Connection,
    ) bool {
        return connection.prepared_receive_keys != null;
    }

    pub const LocalCloseInfo = struct {
        application: bool,
        error_code: u64,
        frame_type: u64,
        reason_phrase: []const u8,
    };

    pub fn ecnPathState(connection: *const Connection) quic.ecn.ValidationState {
        return connection.ecn_path.state();
    }

    pub fn currentPathEpoch(connection: *const Connection) u32 {
        return connection.pmtu_path_epoch;
    }

    pub fn spinLargestReceivedPacketNumber(
        connection: *const Connection,
    ) ?u64 {
        return connection.spin_largest_received_packet_number;
    }

    pub fn candidatePathSpinState(
        connection: *const Connection,
        peer: net.IpAddress,
    ) ?struct { value: bool, largest_received_packet_number: ?u64 } {
        const index = connection.findCandidatePathBudget(peer) orelse
            return null;
        const candidate = connection.candidate_path_budgets[index].?;
        return .{
            .value = candidate.spin_bit_value,
            .largest_received_packet_number = candidate.spin_largest_received_packet_number,
        };
    }

    pub fn expectedPacketNumber(connection: *const Connection) u64 {
        return connection.expected_packet_number;
    }

    pub fn ackFrequencyReceiveNextSequence(
        connection: *const Connection,
    ) u64 {
        return connection.ack_frequency_recv_next_sequence;
    }

    pub fn ecnBaselinePending(connection: *const Connection) bool {
        return connection.ecn_path_baseline_pending;
    }

    pub fn candidatePathBudgetCount(
        connection: *const Connection,
    ) usize {
        var count: usize = 0;
        for (connection.candidate_path_budgets) |entry| {
            count += @intFromBool(entry != null);
        }
        return count;
    }

    pub fn pendingPathResponseTargetCount(
        connection: *const Connection,
    ) usize {
        return connection.pathResponseTargetCount();
    }

    pub fn pendingPathResponseCapacity(
        connection: *const Connection,
    ) usize {
        return connection.path_validation.pending_responses.items.capacity;
    }

    pub fn pathResponseTargetCapacity(
        connection: *const Connection,
    ) usize {
        return connection.path_response_targets.capacity;
    }

    pub fn discardPendingPathResponses(
        connection: *Connection,
        count: usize,
    ) void {
        connection.path_validation.discardResponses(count);
        connection.discardPathResponseTargets(count);
        connection.updatePathResponseTimerAfterSend(null);
    }

    pub fn candidatePathBudgetFor(
        connection: *const Connection,
        peer: net.IpAddress,
    ) ?struct { received: usize, sent: usize } {
        const index = connection.findCandidatePathBudget(peer) orelse
            return null;
        const budget = connection.candidate_path_budgets[index].?;
        return .{
            .received = budget.bytes_received,
            .sent = budget.bytes_sent,
        };
    }

    pub fn lastSentPacketEcn(
        connection: *const Connection,
    ) ?quic.packet_space.EcnCodepoint {
        if (connection.sent.packets.items.len == 0) return null;
        return connection.sent.packets.items[
            connection.sent.packets.items.len - 1
        ].ecn;
    }

    pub fn lastSentPacketDatagramSize(
        connection: *const Connection,
    ) ?usize {
        if (connection.sent.packets.items.len == 0) return null;
        return connection.sent.packets.items[
            connection.sent.packets.items.len - 1
        ].datagram_size;
    }

    pub fn localCloseInfo(connection: *const Connection) ?LocalCloseInfo {
        const close_info = connection.close_info orelse return null;
        if (connection.peer_close_frame_received) return null;
        return .{
            .application = close_info.application,
            .error_code = close_info.error_code,
            .frame_type = close_info.frame_type,
            .reason_phrase = close_info.reason_phrase,
        };
    }

    pub fn closeResponseDeadline(connection: *const Connection) ?u64 {
        return connection.closeResponseDeadline();
    }

    pub const handshake_done_test_stack_capacity =
        handshake_done_frame_stack_capacity;

    pub fn appendHandshakeDoneForTest(
        allocator: std.mem.Allocator,
        stack: *[handshake_done_test_stack_capacity]quic.Frame,
        frames: []const quic.Frame,
    ) Error![]quic.Frame {
        return appendPendingHandshakeDone(
            allocator,
            stack,
            frames,
        );
    }

    pub const pending_ack_test_stack_capacity =
        pending_ack_frame_stack_capacity;

    pub fn clampCongestionWindowToBytesInFlight(
        connection: *Connection,
    ) void {
        connection.congestion.congestion_window =
            connection.congestion.bytes_in_flight;
    }

    pub fn acknowledgeAllInFlight(
        connection: *Connection,
    ) void {
        connection.congestion.onAcked(connection.congestion.bytes_in_flight);
    }

    pub fn exhaustPacingAt(
        connection: *Connection,
        now_ns: u64,
    ) void {
        connection.pacer.budget = 0;
        connection.pacer.last_sent_time_ns = now_ns;
    }

    pub fn setPacingBudgetAt(
        connection: *Connection,
        budget: usize,
        now_ns: u64,
    ) void {
        connection.pacer.budget = budget;
        connection.pacer.last_sent_time_ns = now_ns;
        connection.pacing_blocked_until_ns = null;
    }

    pub fn pacingBlockedUntil(
        connection: *const Connection,
    ) ?u64 {
        return connection.pacing_blocked_until_ns;
    }

    pub fn appendPendingAckForTest(
        allocator: std.mem.Allocator,
        stack: *[pending_ack_test_stack_capacity]quic.Frame,
        frames: []const quic.Frame,
        ack: quic.AckFrame,
    ) Error![]quic.Frame {
        return appendPendingAck(allocator, stack, frames, ack);
    }

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

    pub fn processReceivedBytesOrDropPeerAddressAt(
        connection: *Connection,
        from: net.IpAddress,
        bytes: []const u8,
        ecn: quic.packet_space.EcnCodepoint,
        now_ns: u64,
    ) Error!?ReceivedPacket {
        return connection.processReceivedBytesOrDropPeerAddressAt(
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

    pub fn sendStreamFinalSize(
        connection: *Connection,
        stream_id: u64,
    ) ?u64 {
        return if (connection.findSendStreamEntry(stream_id)) |entry|
            entry.final_size
        else
            null;
    }

    pub fn localStreamReleaseRequested(
        connection: *Connection,
        stream_id: u64,
    ) bool {
        return if (connection.findSendStreamEntry(stream_id)) |entry|
            entry.release_requested
        else
            false;
    }

    pub fn peerStreamReleaseRequested(
        connection: *Connection,
        stream_id: u64,
    ) bool {
        return if (connection.findRecvStreamEntry(stream_id)) |entry|
            entry.stream_count_release_requested
        else
            false;
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

    pub fn clampSendStreamLimitToUsed(
        connection: *Connection,
        stream_id: u64,
    ) Error!u64 {
        const entry = try connection.sendStreamEntry(stream_id);
        entry.flow.limit = entry.flow.used;
        entry.flow.blocked_at = null;
        return entry.flow.used;
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

    pub fn receiveDataTotal(connection: *const Connection) u64 {
        return connection.recv_data_total;
    }

    pub fn receiveDataConsumed(connection: *const Connection) u64 {
        return connection.recv_flow.consumed;
    }

    pub fn trySendAndReleaseReceivedCapacityAt(
        connection: *Connection,
        stream_id: u64,
        amount: u64,
        application_frame: quic.Frame,
        sent_time_ns: u64,
    ) Error!void {
        return connection.trySendAndReleaseReceivedCapacityAt(
            stream_id,
            amount,
            application_frame,
            sent_time_ns,
        );
    }

    pub fn validateDatagramFrame(
        connection: Connection,
        datagram: quic.DatagramFrame,
    ) Error!void {
        return connection.validateDatagramFrame(datagram);
    }

    pub fn injectReceivedDatagram(
        connection: *Connection,
        payload: []const u8,
    ) Error!void {
        try connection.receiveDatagramFrame(.{
            .data = payload,
            .length_present = true,
        }, 0);
    }

    pub fn injectReceivedDatagramForPacket(
        connection: *Connection,
        packet_number: u64,
        payload: []const u8,
    ) Error!void {
        try connection.receiveDatagramFrame(.{
            .data = payload,
            .length_present = true,
        }, packet_number);
    }

    pub fn recoveryPayloadForPacket(
        connection: *const Connection,
        packet_number: u64,
    ) ?[]const u8 {
        const candidate = connection.recovery.packetNumberCandidate(
            packet_number,
        ) orelse return null;
        return candidate.payload;
    }
};

comptime {
    const timer_fn = @typeInfo(@TypeOf(Connection.nextTimerDeadline)).@"fn";
    std.debug.assert(timer_fn.params[0].type.? == *const Connection);
    for (.{
        Connection.sendStreamStats,
        Connection.streamSendAvailable,
        Connection.recvStreamStats,
        Connection.receivedStreamIdsAfterInto,
    }) |query| {
        const query_fn = @typeInfo(@TypeOf(query)).@"fn";
        std.debug.assert(query_fn.params[0].type.? == *const Connection);
    }
}

test {
    _ = @import("one_rtt/tests/mod.zig");
}
