const std = @import("std");
pub const cancellation = @import("../internal/cancellation.zig");
const quic = @import("mod.zig");
pub const fixed_bit = @import("one_rtt/fixed_bit.zig");
pub const closed_streams = @import("one_rtt/closed_streams.zig");
pub const reset_prefix = @import("one_rtt/reset_prefix.zig");
pub const close_packet = @import("one_rtt/close_packet.zig");
pub const frame_traits = @import("one_rtt/frame_traits.zig");
const datagram_queue = @import("one_rtt/datagram_queue.zig");
pub const datagram_receive = @import("one_rtt/datagram_receive.zig");
pub const datagram_send = @import("one_rtt/datagram_send.zig");
pub const handshake_status = @import("one_rtt/handshake_status.zig");
pub const key_phase_order = @import("one_rtt/key_phase_order.zig");
pub const pto_jitter = @import("one_rtt/pto_jitter.zig");
pub const prepared_keys = @import("one_rtt/prepared_keys.zig");
pub const connection_scratch = @import("one_rtt/scratch.zig");
pub const stream_cancel = @import("one_rtt/stream_cancel.zig");
pub const owned_receive_race = @import("owned_receive_race.zig");
pub const deadline_policy = @import("../internal/deadline.zig");

/// Direct-mapped stream lookup cache size. Must stay a power of two.
pub const stream_lookup_cache_entries = 64;

const net = std.Io.net;

/// ACK_FREQUENCY expresses Requested Max Ack Delay in microseconds, while the
/// QUIC max_ack_delay limit is 2^14 milliseconds (exclusive).
pub const max_requested_ack_delay_us: u64 = (@as(u64, 1) << 14) * 1000;
pub const max_stream_slice_frames_per_packet: usize = 16;

pub const StreamSliceCursor = struct {
    parts: []const []const u8,
    part_index: usize = 0,
    part_offset: usize = 0,
    committed: usize = 0,

    fn skipEmpty(self: *StreamSliceCursor) void {
        while (self.part_index < self.parts.len and
            self.part_offset == self.parts[self.part_index].len)
        {
            self.part_index += 1;
            self.part_offset = 0;
        }
    }

    pub fn done(self: *StreamSliceCursor) bool {
        self.skipEmpty();
        return self.part_index == self.parts.len;
    }

    pub fn remaining(self: *StreamSliceCursor) []const u8 {
        self.skipEmpty();
        return self.parts[self.part_index][self.part_offset..];
    }

    pub fn advance(self: *StreamSliceCursor, count: usize) void {
        std.debug.assert(count != 0);
        std.debug.assert(count <= self.remaining().len);
        self.part_offset += count;
        self.committed += count;
        self.skipEmpty();
    }
};

pub fn streamSlicesLength(parts: []const []const u8) Error!usize {
    var total: usize = 0;
    for (parts) |part| {
        total = std.math.add(usize, total, part.len) catch
            return error.InvalidFrameLength;
    }
    return total;
}

pub fn framesWireLen(frames: []const quic.Frame) Error!usize {
    var total: usize = 0;
    for (frames) |frame| {
        total = std.math.add(usize, total, try frame.wireLen()) catch
            return error.InvalidFrameLength;
    }
    return total;
}

pub fn streamFrameEnd(stream: quic.StreamFrame) Error!u64 {
    const data_len = std.math.cast(u64, stream.data.len) orelse
        return error.InvalidFrameLength;
    const end = std.math.add(u64, stream.offset, data_len) catch
        return error.InvalidFrameLength;
    if (end > quic.varint.max_value) return error.InvalidFrameLength;
    return end;
}

pub const ValidatedStreamSendRange = struct {
    end: u64,
    stream_id_len: u8,
    offset_len: u8,

    pub fn frameWireLen(
        self: ValidatedStreamSendRange,
        data_len: usize,
    ) Error!usize {
        const data_len_u64 = std.math.cast(u64, data_len) orelse
            return error.InvalidFrameLength;
        var len = std.math.add(
            usize,
            1,
            self.stream_id_len,
        ) catch return error.InvalidFrameLength;
        len = std.math.add(
            usize,
            len,
            self.offset_len,
        ) catch return error.InvalidFrameLength;
        len = std.math.add(
            usize,
            len,
            try quic.varint.length(data_len_u64),
        ) catch return error.InvalidFrameLength;
        return std.math.add(usize, len, data_len) catch
            return error.InvalidFrameLength;
    }
};

pub fn validateRequestedMaxAckDelay(
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
    InvalidReceiveEndpoint,
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

pub const RetransmitMode = enum {
    congestion_controlled,
    pto_probe,
};

pub const StreamDirection = enum {
    bidirectional,
    unidirectional,
};

pub const ReceivedPacket = struct {
    from: net.IpAddress,
    packet: quic.protection.OpenedShortPacket,
    frames: []quic.Frame,
    key_generation: quic.protection.OpenedKeyGeneration = .current,
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

pub const PendingDatagramObserver = struct {
    context: *anyopaque,
    connection_handle: usize,
    notify: *const fn (*anyopaque, usize) void,
};
pub const PendingDatagramObserverError = error{PendingDatagramObserverBound};
pub const PreferredAddressFamily = enum { ipv4, ipv6 };

pub fn callbackErrorSet(comptime callback: anytype) type {
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

pub const ReceivedDatagramBatch = union(enum) {
    owned: quic.runtime.OwnedBytesBatch,
    borrowed: quic.runtime.ReceivedBytesBatchView,

    pub fn deinit(self: *ReceivedDatagramBatch, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .owned => |*batch| batch.deinit(allocator),
            .borrowed => {},
        }
        self.* = undefined;
    }

    pub fn view(self: *ReceivedDatagramBatch) quic.runtime.ReceivedBytesBatchView {
        return switch (self.*) {
            .owned => |*batch| .{
                .from = batch.from,
                .received_on = batch.received_on,
                .storage = batch.storage,
                .segment_size = batch.segment_size,
                .segment_count = batch.segment_count,
                .ecn = batch.ecn,
            },
            .borrowed => |batch| batch,
        };
    }
};

pub const zero_rtt = quic.zero_rtt;
pub const ZeroRttSendOptions = zero_rtt.SendOptions;
pub const ReceivedZeroRttPacket = zero_rtt.Packet;
pub const EarlyDataSender = zero_rtt.EarlyDataSender;
pub const sendZeroRttFrames = zero_rtt.sendFrames;
pub const receiveZeroRtt = zero_rtt.receive;
pub const openZeroRttBytes = zero_rtt.openBytes;

pub const ReliableResetSupport = packed struct(u8) {
    local: bool = false,
    peer: bool = false,
    reserved: u6 = 0,
};

pub const default_max_datagram_queue_bytes: usize = 64 * 1024;

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
    /// Optional hard ceiling for pacing credit, in bytes per second. Null
    /// keeps the congestion-derived rate; zero allows only reset bursts.
    max_pacing_rate_bytes_per_second: ?u64 = null,
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
    /// Directional draft-ietf-quic-reliable-stream-reset negotiation state.
    reliable_reset: ReliableResetSupport = .{},
    /// Maximum application DATAGRAM payloads retained while no direct
    /// receiver is active. Zero keeps only caller-buffer direct delivery.
    max_datagram_queue_items: usize = 16,
    /// Maximum cumulative payload bytes retained by the receive queue.
    /// Metadata and recyclable allocations remain independently bounded by
    /// `max_datagram_queue_items`.
    max_datagram_queue_bytes: usize = default_max_datagram_queue_bytes,
    enable_ack_frequency: bool = false,
    /// `min_ack_delay` advertised locally; gates peer ACK_FREQUENCY and
    /// validates its Requested Max Ack Delay (microseconds).
    local_min_ack_delay: ?u64 = null,
    /// Peer's advertised `min_ack_delay`; gates local ACK_FREQUENCY and
    /// validates the delay requested by the caller (microseconds).
    peer_min_ack_delay: ?u64 = null,
    /// Optional request appended to the first non-empty 1-RTT packet after a
    /// handshake has negotiated ACK_FREQUENCY support. Direct keyed
    /// connections leave this null by default.
    automatic_ack_frequency_request: ?AckFrequencyRequest = null,
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

pub const AckFrequencyRequest = struct {
    /// Wire-level maximum number of ack-eliciting packets the peer may receive
    /// without an ACK. Three therefore requests an ACK on packet four.
    ack_eliciting_threshold: u64 = 3,
    /// Requested Max Ack Delay in microseconds. Null preserves the peer's
    /// transport-parameter value. A larger explicit value is included in PTO
    /// as soon as its request reaches the socket and remains conservative
    /// until that recovery group is acknowledged.
    request_max_ack_delay_us: ?u64 = null,
    reordering_threshold: u64 = quic.packet_space.default_packet_threshold,
};

pub const InFlightAckFrequencyRequest = struct {
    sequence_number: u64,
    recovery_group_id: u64,
    request_max_ack_delay_us: u64,
};

pub const StreamFlowEntry = struct {
    stream_id: u64,
    flow: quic.flow_control.SendFlow,
    highest_sent_end: u64 = 0,
    final_size: ?u64 = null,
    stopped: ?StopSendingInfo = null,
    reset_sent: ?StreamResetInfo = null,
    /// Protocol-owned association bytes. Every local reset, including the
    /// automatic response to STOP_SENDING, keeps this prefix reliable.
    required_reset_prefix: ?reset_prefix.Prefix = null,
    /// The application no longer needs this locally initiated stream. State
    /// is reclaimed once every applicable send/receive half is terminal.
    release_requested: bool = false,
};

pub const StreamRecvFlowEntry = struct {
    stream_id: u64,
    flow: quic.flow_control.RecvFlow,
    recv_state: quic.stream_state.RecvState,
    /// Monotonic receipt time of the first STREAM frame that carried data or
    /// FIN for this receive side. Protocols that buffer an unclaimed stream
    /// can enforce an age bound from wire arrival rather than first discovery.
    first_received_at_ns: ?u64 = null,
    stopped_prefix: reset_prefix.Received = .{},
    highest_received_end: u64 = 0,
    final_size: ?u64 = null,
    reset: ?StreamResetInfo = null,
    /// Absolute application-read boundary captured by the first RESET_STREAM.
    /// Later reordered STREAM frames may still be retained for validation, but
    /// they must never appear after the terminal reset becomes observable.
    reset_delivery_end: ?usize = null,
    reset_reported: bool = false,
    fin_reported: bool = false,
    /// At least one accepted TLS 0-RTT STREAM frame contributed bytes or FIN
    /// to this receive stream. Later 1-RTT continuation does not erase origin.
    received_early_data: bool = false,
    stop_sending_sent: ?StopSendingInfo = null,
    /// The application has finished with this peer-initiated stream, but its
    /// local send-side terminal frame might still await acknowledgement.
    stream_count_release_requested: bool = false,
    /// Application consumption advanced this stream's receive window, but
    /// the latest MAX_STREAM_DATA value has not reached the socket yet.
    pending_max_stream_data: bool = false,

    pub fn deinit(self: *StreamRecvFlowEntry) void {
        self.recv_state.deinit();
        self.* = undefined;
    }
};

pub const AbandonedReceiveResult = struct {
    discarded: usize,
    released_connection_credit: u64,
};

pub const RecvStreamPreflightEntry = struct {
    stream_id: u64,
    flow_limit: u64,
    recv_state: quic.stream_state.RecvState.Preflight,
    highest_received_end: u64 = 0,
    final_size: ?u64 = null,
    reset: ?StreamResetInfo = null,

    pub fn deinit(self: *RecvStreamPreflightEntry) void {
        self.recv_state.deinit();
        self.* = undefined;
    }
};

pub const StreamResetInfo = struct {
    application_error_code: u64,
    final_size: u64,
    /// Bytes from offset zero that remain reliable after RESET_STREAM_AT.
    /// Zero also represents an ordinary RESET_STREAM.
    reliable_size: u64 = 0,
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

pub const ReservedStreamCredit = struct {
    stream_id: u64,
    bytes: u64,
    committed_bytes: u64 = 0,
};

pub const SendStreamPreflightEntry = struct {
    stream_id: u64,
    highest_sent_end: u64,
    final_size: ?u64,
};

pub const OutboundFrameTraits = frame_traits.Traits;

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
    /// Effective pacer rate after applying the congestion-derived rate and
    /// optional configured ceiling. Null means no finite pacing rate exists.
    pacing_rate_bytes_per_second: ?u64,
    max_pacing_rate_bytes_per_second: ?u64,
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
    datagram_receive_queue_bytes: usize,
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
    first_received_at_ns: ?u64,
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

pub fn sendStreamStatsFromEntry(entry: *const StreamFlowEntry) SendStreamStats {
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

pub fn recvStreamStatsFromEntry(entry: *const StreamRecvFlowEntry) RecvStreamStats {
    return .{
        .bytes_received = entry.recv_state.receivedByteCount(),
        .bytes_read = std.math.cast(u64, entry.recv_state.read_offset) orelse
            std.math.maxInt(u64),
        .highest_received_offset = entry.highest_received_end,
        .available_bytes = entry.recv_state.available().len,
        .first_received_at_ns = entry.first_received_at_ns,
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
pub fn applicationAvailableStreamBytes(
    entry: *const StreamRecvFlowEntry,
    enable_reset_partial_delivery: bool,
) []const u8 {
    const available = entry.recv_state.available();
    if (entry.reset_delivery_end) |delivery_end| {
        const reliable_reset = entry.reset != null and
            entry.reset.?.reliable_size != 0;
        if ((!enable_reset_partial_delivery and !reliable_reset) or
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

/// A reset only makes the receive side transport-terminal after every byte in
/// its reliable prefix is contiguous. Application consumption is deliberately
/// separate: callers may still drain the prefix before observing the reset.
pub fn resetReliablePrefixReceived(entry: *const StreamRecvFlowEntry) bool {
    const reset = entry.reset orelse return false;
    const reliable_size = std.math.cast(usize, reset.reliable_size) orelse
        return false;
    return entry.recv_state.read_offset + entry.recv_state.available().len >=
        reliable_size;
}

pub const PeerAddressUpdate = union(enum) {
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

    pub fn deinit(self: *PeerAddressUpdate) void {
        switch (self.*) {
            .new_path => |*new_path| new_path.path_validation.deinit(),
            else => {},
        }
        self.* = .none;
    }
};

pub const max_candidate_path_budgets: usize = quic.connection_id.max_pool_size;

pub const CandidatePathBudget = struct {
    peer: net.IpAddress,
    bytes_received: usize = 0,
    bytes_sent: usize = 0,
    spin_bit_value: bool = false,
    spin_largest_received_packet_number: ?u64 = null,
};

pub const PathResponseTarget = struct {
    peer: ?net.IpAddress = null,
    endpoint: ?*quic.runtime.Endpoint = null,
};

pub const ValidatedPeerPath = struct {
    peer: net.IpAddress,
    endpoint: *quic.runtime.Endpoint,
    connection_id: [quic.connection_id.max_connection_id_len]u8 =
        .{0} ** quic.connection_id.max_connection_id_len,
    connection_id_len: u8 = 0,
    spin_bit_value: bool = false,
    spin_largest_received_packet_number: ?u64 = null,

    pub fn init(
        peer: net.IpAddress,
        endpoint: *quic.runtime.Endpoint,
        connection_id: []const u8,
        spin_bit_value: bool,
        spin_largest_received_packet_number: ?u64,
    ) ValidatedPeerPath {
        std.debug.assert(
            connection_id.len <= quic.connection_id.max_connection_id_len,
        );
        var path: ValidatedPeerPath = .{
            .peer = peer,
            .endpoint = endpoint,
            .connection_id_len = @intCast(connection_id.len),
            .spin_bit_value = spin_bit_value,
            .spin_largest_received_packet_number = spin_largest_received_packet_number,
        };
        @memcpy(path.connection_id[0..connection_id.len], connection_id);
        return path;
    }

    pub fn connectionId(self: *const ValidatedPeerPath) []const u8 {
        return self.connection_id[0..self.connection_id_len];
    }
};

pub fn updateSpinState(
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

pub const DatagramRecvQueue = datagram_queue.Queue;

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
    pmtu_probe,
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
pub const max_short_packet_overhead: usize = 1 + 20 + 4 + quic.protection.aead_tag_len;
// HTTP/3's default packet builder contributes at most eight frames. Keep the
// automatic HANDSHAKE_DONE augmentation for that common first-flight shape on
// the stack while retaining an exact fallback for lower-level callers.
const handshake_done_frame_stack_capacity: usize = 16;
pub const pending_control_frame_stack_capacity: usize = 18;
pub const pending_ack_frame_stack_capacity: usize = 16;
// Match the default receive parser bound so a peer can consume one update for
// every frame in the coalesced credit packet without special configuration.
pub const receive_credit_frame_stack_capacity: usize = 16;

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

const PendingControlFrames = struct {
    frames: []quic.Frame,
};

pub fn appendPendingControlFrames(
    self: *Connection,
    stack: *[pending_control_frame_stack_capacity]quic.Frame,
    frames: []const quic.Frame,
) Error!PendingControlFrames {
    const append_handshake_done = self.handshake_status.needsHandshakeDone() and
        !frame_traits.containsHandshakeDone(frames);
    const append_ack_frequency = self.pending_ack_frequency_request != null and
        !containsAckFrequency(frames);
    const additional = @as(usize, @intFromBool(append_handshake_done)) +
        @intFromBool(append_ack_frequency);
    const combined_len = std.math.add(usize, frames.len, additional) catch
        return error.InvalidFrameLength;
    const combined = if (combined_len <= stack.len)
        stack[0..combined_len]
    else
        try self.endpoint.allocator.alloc(quic.Frame, combined_len);
    @memcpy(combined[0..frames.len], frames);
    var index = frames.len;
    if (append_handshake_done) {
        combined[index] = .{ .handshake_done = {} };
        index += 1;
    }
    if (append_ack_frequency) {
        combined[index] = .{
            .ack_frequency = self.pending_ack_frequency_request.?,
        };
    }
    return .{ .frames = combined };
}

pub fn containsAckFrequency(frames: []const quic.Frame) bool {
    for (frames) |frame| if (frame == .ack_frequency) return true;
    return false;
}

pub fn newestAckFrequencyFrame(
    frames: []const quic.Frame,
) ?quic.AckFrequencyFrame {
    var newest: ?quic.AckFrequencyFrame = null;
    for (frames) |frame| {
        if (frame != .ack_frequency) continue;
        if (newest == null or
            frame.ack_frequency.sequence_number > newest.?.sequence_number)
        {
            newest = frame.ack_frequency;
        }
    }
    return newest;
}

pub fn ackFrameContainsPacketNumber(ack: quic.AckFrame, packet_number: u64) bool {
    if (ack.first_ack_range > ack.largest_acknowledged) return false;
    var range_end = ack.largest_acknowledged;
    var range_start = range_end - ack.first_ack_range;
    if (packet_number >= range_start and packet_number <= range_end) {
        return true;
    }
    for (ack.ranges) |range| {
        const skipped = std.math.add(u64, range.gap, 2) catch return false;
        if (range_start < skipped) return false;
        range_end = range_start - skipped;
        if (range.ack_range_length > range_end) return false;
        range_start = range_end - range.ack_range_length;
        if (packet_number >= range_start and packet_number <= range_end) {
            return true;
        }
    }
    return false;
}

test "QUIC ACK membership handles sparse ranges" {
    const ack = quic.AckFrame{
        .largest_acknowledged = 10,
        .ack_delay = 0,
        .first_ack_range = 2, // 8...10.
        .ranges = &.{
            .{ .gap = 1, .ack_range_length = 1 }, // 4...5.
            .{ .gap = 0, .ack_range_length = 2 }, // 0...2.
        },
    };
    for ([_]u64{ 0, 1, 2, 4, 5, 8, 9, 10 }) |packet_number| {
        try std.testing.expect(ackFrameContainsPacketNumber(
            ack,
            packet_number,
        ));
    }
    for ([_]u64{ 3, 6, 7, 11 }) |packet_number| {
        try std.testing.expect(!ackFrameContainsPacketNumber(
            ack,
            packet_number,
        ));
    }
}

pub fn appendPendingAck(
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
pub const timer_blocked_receive_backoff_ns: u64 = std.time.ns_per_ms;
pub const stream_release_retry_backoff_ns = [_]u64{
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
pub fn isDiscardedLongHeaderPacket(bytes: []const u8) bool {
    return bytes.len != 0 and (bytes[0] & 0x80) != 0;
}

pub const StableConnectionId = u64;

var next_stable_connection_id: std.atomic.Value(StableConnectionId) = .init(1);

pub fn reserveStableConnectionId() StableConnectionId {
    // Wrap would require 2^64 successful connection constructions in one
    // process. Skip zero so it remains available as an invalid/sentinel value.
    while (true) {
        const id = next_stable_connection_id.fetchAdd(1, .monotonic);
        if (id != 0) return id;
    }
}

pub const Connection = @import("one_rtt/connection.zig").Connection;

pub fn streamInitiatedByLocal(local_endpoint: ConnectionConfig.EndpointRole, stream_id: u64) bool {
    const client_initiated = (stream_id & 0x01) == 0;
    return switch (local_endpoint) {
        .client => client_initiated,
        .server => !client_initiated,
    };
}

pub fn streamHasSendSide(local_endpoint: ConnectionConfig.EndpointRole, stream_id: u64) bool {
    return streamDirection(stream_id) == .bidirectional or streamInitiatedByLocal(local_endpoint, stream_id);
}

pub fn streamHasReceiveSide(local_endpoint: ConnectionConfig.EndpointRole, stream_id: u64) bool {
    return streamDirection(stream_id) == .bidirectional or !streamInitiatedByLocal(local_endpoint, stream_id);
}

pub fn streamDirection(stream_id: u64) StreamDirection {
    return if ((stream_id & 0x02) == 0) .bidirectional else .unidirectional;
}

pub fn streamCountForId(stream_id: u64) u64 {
    return (stream_id >> 2) + 1;
}

pub fn containsStreamId(stream_ids: []const u64, target: u64) bool {
    for (stream_ids) |stream_id| {
        if (stream_id == target) return true;
    }
    return false;
}

pub fn advanceStreamLimit(current: u64, released: u64) u64 {
    std.debug.assert(current <= quic.max_stream_count);
    return current + @min(released, quic.max_stream_count - current);
}

pub fn peerAddressSameIp(a: net.IpAddress, b: net.IpAddress) bool {
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

pub fn peerAddressCrossesSystemPortScope(
    a: net.IpAddress,
    b: net.IpAddress,
) bool {
    return peerAddressUsesSystemPort(a) != peerAddressUsesSystemPort(b);
}

fn peerAddressUsesSystemPort(address: net.IpAddress) bool {
    const port = switch (address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
    return port < 1024;
}

pub fn nextPathEpoch(current: u32) u32 {
    const next = current +% 1;
    return if (next == 0) 1 else next;
}

fn isProbingFrame(frame: quic.Frame) bool {
    return switch (frame) {
        .padding, .new_connection_id, .path_challenge, .path_response => true,
        else => false,
    };
}

pub fn hasNonProbingFrame(frames: []const quic.Frame) bool {
    for (frames) |frame| {
        if (!isProbingFrame(frame)) return true;
    }
    return false;
}

/// Select the earlier wakeup without losing whether it belongs to transport
/// maintenance or to the application-level operation. Both deadlines use the
/// awake clock, so their raw timestamps are directly comparable.
pub fn earliestConnectionReceiveTimeout(
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

pub fn callerDeadlineFromTimeout(
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

pub fn callerDeadlineExpired(
    deadline: ?std.Io.Clock.Timestamp,
    now_ns: u64,
) bool {
    const value = deadline orelse return false;
    const now = std.math.cast(i96, now_ns) orelse std.math.maxInt(i96);
    return now >= value.raw.nanoseconds;
}

pub fn countPathChallenges(frames: []const quic.Frame) usize {
    var count: usize = 0;
    for (frames) |frame| {
        if (frame == .path_challenge) count += 1;
    }
    return count;
}

pub fn countPathResponses(frames: []const quic.Frame) usize {
    var count: usize = 0;
    for (frames) |frame| {
        if (frame == .path_response) count += 1;
    }
    return count;
}

pub fn maxBufferedForLimit(limit: u64) usize {
    return std.math.cast(usize, limit) orelse std.math.maxInt(usize);
}

pub fn allZero(comptime T: type, values: []const T) bool {
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

pub fn closeExpiryMillis(now_ms: ?u64, pto_ms: ?u64) ?u64 {
    const now = now_ms orelse return null;
    const pto = pto_ms orelse return null;
    const duration = std.math.mul(u64, pto, 3) catch return std.math.maxInt(u64);
    return std.math.add(u64, now, duration) catch std.math.maxInt(u64);
}

pub fn nsToMs(now_ns: ?u64) ?u64 {
    return if (now_ns) |ns| nanosToMillisCeil(ns) else null;
}

pub fn discardPacketView(_: void, _: ReceivedPacketView) error{}!void {}

pub fn acknowledgePacketView(
    connection: *Connection,
    packet: ReceivedPacketView,
) Error!void {
    _ = connection.sendAckForPacketIfNeeded(
        packet.packet_number,
        packet.frames,
    ) catch {};
}

pub const BatchAckObservation = struct {
    largest_packet_number: ?u64,
    reordering_threshold: u64,
    ack_eliciting_count: u64 = 0,
    reordered: bool = false,

    pub fn observe(
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

pub fn nanosToMillisFloor(ns: u64) u64 {
    return ns / 1_000_000;
}

pub fn nanosToMillisCeil(ns: u64) u64 {
    return ns / 1_000_000 + @intFromBool((ns % 1_000_000) != 0);
}

pub fn millisToNanos(ms: u64) u64 {
    return std.math.mul(u64, ms, 1_000_000) catch std.math.maxInt(u64);
}

pub fn closeQlogTrigger(state: CloseState, reason_phrase: []const u8) []const u8 {
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

pub fn considerTimerDeadline(next: *?TimerDeadline, candidate: TimerDeadline) void {
    if (next.* == null or candidate.deadline_ns < next.*.?.deadline_ns) {
        next.* = candidate;
    }
}

pub fn qlogAckDelayExponent(exponent: u64) u6 {
    return @intCast(@min(exponent, quic.rtt.max_ack_delay_exponent));
}

pub fn oneRttKeyType(
    role: ConnectionConfig.EndpointRole,
) []const u8 {
    return switch (role) {
        .client => "client_1rtt_secret",
        .server => "server_1rtt_secret",
    };
}

pub fn peerOneRttKeyType(
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

pub fn writeRetransmittableFramesAssumeCapacity(
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

pub fn addReservedStreamCredit(
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

pub fn appendReservedStreamCredit(
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

pub fn appendSendStreamPreflightEntry(
    entries: *std.ArrayList(SendStreamPreflightEntry),
    allocated: *bool,
    allocator: std.mem.Allocator,
    entry: SendStreamPreflightEntry,
) Error!void {
    if (!allocated.*) {
        if (entries.items.len < entries.capacity) {
            entries.appendAssumeCapacity(entry);
            return;
        }
        var grown = try std.ArrayList(SendStreamPreflightEntry).initCapacity(
            allocator,
            @max(@as(usize, 1), entries.capacity * 2),
        );
        grown.appendSliceAssumeCapacity(entries.items);
        entries.* = grown;
        allocated.* = true;
    }
    try entries.append(allocator, entry);
}

pub fn reservedStreamBytes(
    credits: []const ReservedStreamCredit,
    stream_id: u64,
) u64 {
    for (credits) |credit| {
        if (credit.stream_id == stream_id) return credit.bytes;
    }
    return 0;
}

pub fn datagramFrameWireSize(datagram: quic.DatagramFrame) ?usize {
    return datagramFrameWireSizeForLength(
        datagram.data.len,
        datagram.length_present,
    );
}

pub fn datagramFrameWireSizeForLength(
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

pub fn maxDatagramPayloadForFrameSize(frame_size: usize) ?usize {
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
pub fn rawFrameTypeAtIndex(
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
        .key_generation = decoded.key_generation,
        .peer_initiated_key_update = decoded.peer_initiated_key_update,
    };
}

pub fn parsePacketFramesForType(
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
    pub fn reportLostPmtuEvidence(
        connection: *Connection,
        generation: u32,
        now_ns: u64,
    ) void {
        connection.reportLostPmtuEvidence(generation, now_ns);
    }

    pub fn prepareLossDeadlineBenchmark(
        connection: *Connection,
        packet_count: usize,
    ) Error!void {
        if (packet_count < 3) return error.InvalidPacketNumber;
        connection.rtt_stats.updateAt(100_000_000, 0, true, 0);
        for (0..packet_count) |packet_number| {
            try connection.sent.sentAtWithDatagramSizeAndPathEpoch(
                @intCast(packet_number),
                true,
                1200,
                1200,
                .not_ect,
                1_000 + packet_number,
                connection.pmtu_path_epoch,
            );
        }
        const ranges = [_]quic.AckRange{.{
            .gap = 0,
            .ack_range_length = @intCast(packet_count - 3),
        }};
        _ = try connection.sent.applyAckDetailed(.{
            .largest_acknowledged = @intCast(packet_count - 1),
            .ack_delay = 0,
            .first_ack_range = 0,
            .ranges = &ranges,
        });
        connection.refreshLossTimeDeadline();
    }

    pub fn cachedLossTimeDeadline(
        connection: *const Connection,
    ) ?u64 {
        return connection.loss_time_deadline_ns;
    }

    pub fn hasPreparedSendPacketProtection(
        connection: *const Connection,
    ) bool {
        return connection.prepared_keys.send() != null;
    }

    pub fn hasPreparedReceivePacketProtection(
        connection: *const Connection,
    ) bool {
        return connection.prepared_keys.receive() != null;
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

    pub fn nextPacketNumber(connection: *const Connection) u64 {
        return connection.next_packet_number;
    }

    pub fn setNextPacketNumber(
        connection: *Connection,
        packet_number: u64,
    ) void {
        connection.next_packet_number = packet_number;
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
        connection.pacer.setLastSentTimeNs(now_ns);
    }

    pub fn setPacingBudgetAt(
        connection: *Connection,
        budget: usize,
        now_ns: u64,
    ) void {
        connection.pacer.budget = budget;
        connection.pacer.setLastSentTimeNs(now_ns);
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
    _ = @import("one_rtt/tests/reset_prefix.zig");
    _ = @import("one_rtt/tests/mod.zig");
}
