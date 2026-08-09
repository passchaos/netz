//! Allocation-free event views for the qlog 0.4 JSON-SEQ encoder.
//!
//! These types intentionally do not own protocol state. A QUIC connection can
//! project its internal packets, recovery metrics, and frames into short-lived
//! views without making the observability layer depend on a particular
//! connection implementation.

pub const VantagePoint = enum {
    client,
    server,
    network,
    unknown,
};

pub const Owner = enum {
    local,
    remote,
};

pub const PacketType = enum {
    initial,
    zero_rtt,
    handshake,
    one_rtt,
    retry,
    version_negotiation,
    stateless_reset,
    unknown,

    pub fn qlogName(self: PacketType) []const u8 {
        return switch (self) {
            .initial => "initial",
            .zero_rtt => "0RTT",
            .handshake => "handshake",
            .one_rtt => "1RTT",
            .retry => "retry",
            .version_negotiation => "version_negotiation",
            .stateless_reset => "stateless_reset",
            .unknown => "unknown",
        };
    }
};

pub const ErrorSpace = enum {
    transport,
    application,
};

pub const StreamType = enum {
    bidirectional,
    unidirectional,
};

/// One encoded ACK range after the first range. These are the wire-level
/// `Gap` and `ACK Range Length` values from RFC 9000 Section 19.3.
pub const AckRange = struct {
    gap: u64,
    ack_range_length: u64,
};

pub const EcnCounts = struct {
    ect0: u64,
    ect1: u64,
    ce: u64,
};

pub const Ack = struct {
    largest_acknowledged: u64,
    /// Decoded ACK delay in milliseconds. The QUIC wire value must first be
    /// expanded with the peer's negotiated `ack_delay_exponent`.
    ack_delay_ms: f64,
    first_ack_range: u64,
    ranges: []const AckRange = &.{},
    ecn_counts: ?EcnCounts = null,
};

pub const Frame = union(enum) {
    padding: struct {
        length: usize,
    },
    ping: void,
    ack: Ack,
    reset_stream: struct {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
    },
    stop_sending: struct {
        stream_id: u64,
        error_code: u64,
    },
    new_token: struct {
        length: usize,
    },
    crypto: struct {
        offset: u64,
        length: usize,
    },
    stream: struct {
        stream_id: u64,
        offset: u64,
        length: usize,
        fin: bool,
    },
    max_data: struct {
        maximum: u64,
    },
    max_stream_data: struct {
        stream_id: u64,
        maximum: u64,
    },
    max_streams: struct {
        stream_type: StreamType,
        maximum: u64,
    },
    data_blocked: struct {
        limit: u64,
    },
    stream_data_blocked: struct {
        stream_id: u64,
        limit: u64,
    },
    streams_blocked: struct {
        stream_type: StreamType,
        limit: u64,
    },
    new_connection_id: struct {
        sequence_number: u64,
        retire_prior_to: u64,
        connection_id_length: usize,
    },
    retire_connection_id: struct {
        sequence_number: u64,
    },
    path_challenge: void,
    path_response: void,
    connection_close: struct {
        error_space: ErrorSpace,
        error_code: u64,
        triggering_frame_type: ?u64 = null,
        reason: []const u8 = "",
    },
    handshake_done: void,
    immediate_ack: void,
    datagram: struct {
        length: usize,
    },
    ack_frequency: struct {
        sequence_number: u64,
        packet_tolerance: u64,
        max_ack_delay: u64,
        reordering_threshold: u64,
    },
};

pub const Packet = struct {
    packet_type: PacketType,
    packet_number: ?u64,
    length: usize,
    frames: []const Frame = &.{},
};

pub const RecoveryMetrics = struct {
    min_rtt_ns: ?u64 = null,
    smoothed_rtt_ns: ?u64 = null,
    latest_rtt_ns: ?u64 = null,
    rtt_variance_ns: ?u64 = null,
    congestion_window: u64,
    bytes_in_flight: u64,
    pacing_rate_bps: ?u64 = null,
};

pub const Event = union(enum) {
    connection_started: struct {
        src_ip: ?[]const u8 = null,
        src_port: ?u16 = null,
        dst_ip: ?[]const u8 = null,
        dst_port: ?u16 = null,
    },
    connection_closed: struct {
        trigger: []const u8,
        owner: ?Owner = null,
        error_space: ErrorSpace,
        error_code: u64,
        reason: []const u8 = "",
    },
    parameters_set: struct {
        owner: Owner,
        max_idle_timeout_ms: ?u64 = null,
        max_udp_payload_size: ?u64 = null,
        initial_max_data: ?u64 = null,
        initial_max_streams_bidi: ?u64 = null,
        initial_max_streams_uni: ?u64 = null,
        disable_active_migration: ?bool = null,
    },
    packet_sent: Packet,
    packet_received: Packet,
    packet_dropped: struct {
        packet_type: ?PacketType = null,
        trigger: []const u8,
        raw_length: ?usize = null,
    },
    metrics_updated: RecoveryMetrics,
    congestion_state_updated: struct {
        old: ?[]const u8 = null,
        new: []const u8,
        trigger: ?[]const u8 = null,
    },
    packet_lost: struct {
        packet_type: PacketType,
        packet_number: u64,
        trigger: []const u8,
    },
    key_updated: struct {
        trigger: []const u8,
        key_type: []const u8,
        generation: ?u64 = null,
    },
    key_discarded: struct {
        key_type: []const u8,
        generation: ?u64 = null,
    },

    pub fn qlogName(self: Event) []const u8 {
        return switch (self) {
            .connection_started => "connectivity:connection_started",
            .connection_closed => "connectivity:connection_closed",
            .parameters_set => "quic:parameters_set",
            .packet_sent => "quic:packet_sent",
            .packet_received => "quic:packet_received",
            .packet_dropped => "quic:packet_dropped",
            .metrics_updated => "recovery:metrics_updated",
            .congestion_state_updated => "recovery:congestion_state_updated",
            .packet_lost => "recovery:packet_lost",
            .key_updated => "security:key_updated",
            .key_discarded => "security:key_retired",
        };
    }
};
