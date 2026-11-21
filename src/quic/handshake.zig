const std = @import("std");
const failure = @import("handshake/failure.zig");
const quic = @import("mod.zig");
const key_exchange = @import("handshake/key_exchange.zig");
const retransmit = @import("handshake/retransmit.zig");
const retry = @import("handshake/retry.zig");
const transport_limits = @import("handshake/transport_limits.zig");
const datagram_reader = @import("handshake/datagram_reader.zig");
const handshake_transcript = @import("handshake/transcript.zig");
const established_promotion = @import("handshake/established_promotion.zig");
const fixed_bit = @import("one_rtt/fixed_bit.zig");
const root_trust = @import("../trust.zig");

const net = std.Io.net;

pub const ClientNistHybridKeyMaterial =
    key_exchange.ClientNistHybridKeyMaterial;
pub const ServerNistHybridKeyMaterial =
    key_exchange.ServerNistHybridKeyMaterial;
pub const ServerRetryPolicy = retry.Policy;

/// Bounded per-encryption-level CRYPTO span for full certificate flights,
/// matching the unified TCP/TLS handshake budget. Storage grows on demand.
pub const default_max_crypto_buffer: usize = 256 * 1024;

pub const Error = quic.runtime.Error || quic.protection.Error || quic.crypto_stream.Error || quic.tls_client_hello.Error || quic.tls.auth.Error || quic.tls.client_auth.Error || quic.one_rtt.Error || quic.zero_rtt.handshake.Error || quic.zero_rtt.replay_filter.Error || quic.resumption.tls_psk.Error || quic.resumption.ticket.handshake.Error || quic.Error || std.Io.RandomSecureError || std.Io.Writer.Error || error{
    DiscardedInitialPacket,
    InvalidHandshakeFlight,
    MissingCryptoFrame,
    MissingAlpn,
    HandshakeTimeout,
    InvalidHandshakeRecovery,
    HandshakeSendFailed,
    HandshakeReceiveFailed,
    PostHandshakeTlsUnavailable,
    NativeTrustStoreUnavailable,
};
pub const AcceptTimeoutError = Error || std.Io.Timeout.Error;

pub const ClientOptions = struct {
    /// Destination Connection ID from the client's first Initial.  It seeds the
    /// first Initial secrets and remains the value expected in the server's
    /// original_destination_connection_id transport parameter after Retry.
    original_destination_connection_id: []const u8,
    local_connection_id: []const u8,
    /// Retry Source Connection ID accepted from a validated Retry packet.  When
    /// set, the retried Initial uses this value as its Destination Connection
    /// ID and key-derivation input while preserving the original DCID above for
    /// transport-parameter validation.
    retry_source_connection_id: []const u8 = &.{},
    version: quic.Version = .version_1,
    /// Versions this client is willing to retry with if the server answers the
    /// first Initial with Version Negotiation.  Preference order is preserved.
    available_versions: []const quic.Version = &.{ .version_1, .version_2 },
    server_name: ?[]const u8 = null,
    alpn_protocols: []const []const u8 = &.{"h3"},
    /// Optional raw override for callers that need full control over the TLS
    /// QUIC transport-parameter extension.  When empty, netz emits
    /// `local_transport_parameters` plus the required connection-id parameter.
    transport_parameters: []const u8 = &.{},
    local_transport_parameters: quic.TransportParameters = quic.practical_transport_parameters,
    address_validation_token: []const u8 = &.{},
    max_crypto_buffer: usize = default_max_crypto_buffer,
    max_crypto_frame_data_len: usize = 1024,
    client_initial_packet_number: u64 = 0,
    client_handshake_packet_number: u64 = 0,
    /// Blocking-handshake PTO/backoff and optional fault-injection policy.
    handshake_recovery: retransmit.Config = .{},
    initial_one_rtt_config: OneRttConfig = .{},
    random: ?[32]u8 = null,
    x25519_secret_key: ?[32]u8 = null,
    p256_secret_key: ?[32]u8 = null,
    p384_secret_key: ?[quic.tls.key_exchange.p384.secret_len]u8 = null,
    x25519_mlkem768_secret_key: ?[
        quic.tls.key_exchange
            .x25519_mlkem768.x25519_secret_len
    ]u8 = null,
    x25519_mlkem768_seed: ?[
        quic.tls.key_exchange
            .x25519_mlkem768.mlkem_seed_len
    ]u8 = null,
    /// Deterministic test/embedding inputs for NIST ECDHE-ML-KEM groups.
    /// Production callers normally leave these null to use secure randomness.
    nist_hybrid_key_material: ClientNistHybridKeyMaterial = .{},
    key_exchange_groups: []const quic.tls_client_hello.NamedGroup =
        &.{
            .x25519_mlkem768,
            .x25519,
            .secp256r1,
            .secp384r1,
        },
    keylog: ?*quic.keylog.Log = null,
    resumption_session: ?*const quic.resumption.Session = null,
    resumption_now_ms: ?u64 = null,
    resumption_server_id: ?[]const u8 = null,
    auto_resumption: ?quic.resumption.ticket.handshake.ClientAutoResume = null,
    early_data: ?quic.zero_rtt.handshake.ClientOffer = null,
    server_auth: ?quic.tls.auth.ClientVerifier = null,
    /// Optional process environment used to honor `SSL_CERT_FILE` and
    /// `SSL_CERT_DIR` when `server_auth` is null. Null keeps the platform
    /// store.
    system_environ: ?std.process.Environ = null,
    /// Optional caller-owned native trust store reused across handshakes. It
    /// takes precedence over `system_environ`; the caller must keep it alive
    /// for the synchronous handshake.
    system_store: ?*const quic.tls.trust.SystemStore = null,
    /// Selects the default root set when `server_auth` and `system_store` are
    /// both null. `.platform` uses the OS verifier; `.bundled` uses the
    /// compiled-in Mozilla roots.
    root_source: root_trust.RootSource = .system,
    client_identity: ?quic.tls.client_auth.ClientIdentity = null,
    /// TLS 1.3 cipher suites offered in preference order.
    cipher_suites: []const quic.tls_client_hello.CipherSuite =
        &quic.tls_client_hello.default_cipher_suites,
    /// RFC 8879 algorithms advertised in compress_certificate. An empty
    /// slice omits the extension.
    certificate_compression_algorithms: []const quic.tls.certificate_compression.Algorithm =
        &quic.tls_client_hello.default_certificate_compression_algorithms,
    /// Reject a compressed Certificate above this uncompressed size before
    /// allocation or inflation.
    max_decompressed_certificate_len: usize = 64 * 1024,
};

pub const ServerPsk = struct {
    identity: []const u8,
    secret: [32]u8,
    secret_value: ?quic.tls.secret.Secret = null,
    age_add: u32,
    issued_at_ms: u64,
    lifetime_seconds: u32,
    now_ms: u64,
    age_tolerance_ms: u32 = 10_000,
    cipher_suite: quic.tls_client_hello.CipherSuite =
        .aes_128_gcm_sha256,
};

pub const ServerEarlyDataPolicy = struct {
    accept: bool = false,
    replay_filter: *quic.zero_rtt.ReplayFilter,
    /// Stable application request identity (for example method+origin+request
    /// nonce), not merely the replayable ticket identity itself.
    replay_key: []const u8 = &.{},
};

const SelectedServerPsk = struct {
    secret: quic.tls.secret.Secret,
    identity_index: u16,
    age_within_tolerance: bool,

    pub fn permitsEarlyData(self: SelectedServerPsk) bool {
        return self.identity_index == 0 and self.age_within_tolerance;
    }
};

pub const ServerOptions = struct {
    /// Endpoint-owned result storage for the final protected close packet.
    /// The worker writes it before submitting a fatal peer-validation close.
    failed_close_out: ?*?@import("handshake/closing.zig").Packet = null,
    failed_close_lifetime_out: ?*u64 = null,
    local_connection_id: []const u8,
    alpn_protocol: []const u8 = "h3",
    /// Optional raw override for the server transport-parameter extension.
    /// When empty, netz emits practical defaults together with server
    /// connection-id parameters derived from the received Initial packet.
    transport_parameters: []const u8 = &.{},
    local_transport_parameters: quic.TransportParameters = quic.practical_transport_parameters,
    address_validation_secrets: []const quic.address_validation_token.Secret = &.{},
    address_validation_peer: []const u8 = &.{},
    address_validation_now_ns: i64 = 0,
    /// Optional process-local replay gate for successfully authenticated Retry
    /// and NEW_TOKEN values. The caller retains ownership and must keep the
    /// filter alive until every accept operation borrowing it has completed.
    address_validation_replay_filter: ?*quic.address_validation_token.SharedReplayFilter = null,
    /// Retry metadata from the first Initial/Retry exchange.  When set, accept()
    /// validates the Initial token as a Retry token bound to ODCID+RSCID and
    /// advertises both `original_destination_connection_id` and
    /// `retry_source_connection_id` transport parameters.
    retry_original_destination_connection_id: []const u8 = &.{},
    retry_source_connection_id: []const u8 = &.{},
    /// When present on a fresh connection, accept() sends one Retry and then
    /// continues the same blocking handshake with the validated retried
    /// Initial. Retry metadata fields above remain available for callers that
    /// already performed Retry outside this adapter.
    retry: ?ServerRetryPolicy = null,
    version: quic.Version = .version_1,
    /// Versions this server advertises in RFC 9368 version_information.  If the
    /// server sends Version Negotiation, keep this aligned with that response so
    /// clients can authenticate that the selected version was not downgraded.
    available_versions: []const quic.Version = &.{ .version_1, .version_2 },
    max_crypto_buffer: usize = default_max_crypto_buffer,
    max_crypto_frame_data_len: usize = 1024,
    server_initial_packet_number: u64 = 0,
    server_handshake_packet_number: u64 = 0,
    /// Blocking-handshake PTO/backoff and optional fault-injection policy.
    handshake_recovery: retransmit.Config = .{},
    initial_one_rtt_config: OneRttConfig = .{},
    random: ?[32]u8 = null,
    x25519_secret_key: ?[32]u8 = null,
    p256_secret_key: ?[32]u8 = null,
    p384_secret_key: ?[quic.tls.key_exchange.p384.secret_len]u8 = null,
    x25519_mlkem768_secret_key: ?[
        quic.tls.key_exchange
            .x25519_mlkem768.x25519_secret_len
    ]u8 = null,
    x25519_mlkem768_encaps_seed: ?[
        quic.tls.key_exchange
            .x25519_mlkem768.encaps_seed_len
    ]u8 = null,
    /// Deterministic test/embedding inputs for NIST ECDHE-ML-KEM groups.
    /// Production callers normally leave these null to use secure randomness.
    nist_hybrid_key_material: ServerNistHybridKeyMaterial = .{},
    key_exchange_groups: []const quic.tls_client_hello.NamedGroup =
        &.{
            .x25519_mlkem768,
            .x25519,
            .secp256r1,
            .secp384r1,
        },
    keylog: ?*quic.keylog.Log = null,
    psk: ?ServerPsk = null,
    auto_resumption: ?quic.resumption.ticket.handshake.ServerAutoResume = null,
    early_data: ?ServerEarlyDataPolicy = null,
    identity: ?quic.tls.auth.ServerIdentity = null,
    client_auth: ?quic.tls.client_auth.ServerPolicy = null,
    /// Server preference is authoritative by default, matching rustls's
    /// provider policy and avoiding accidental client-controlled downgrade.
    cipher_suites: []const quic.tls_client_hello.CipherSuite =
        &quic.tls_client_hello.default_cipher_suites,
    cipher_suite_policy: quic.tls_client_hello.CipherSuiteSelectionPolicy =
        .server_order,
    /// RFC 8879 algorithms the QUIC server may use to compress its
    /// Certificate message on demand. Compression is applied only when the
    /// client offered the algorithm and it reduces the message size.
    certificate_compression_algorithms: []const quic.tls.certificate_compression.Algorithm =
        &quic.tls_client_hello.default_certificate_compression_algorithms,
    /// Optional caller-prepared compressed Certificate messages. A prepared
    /// entry that matches the configured certificate message and the client's
    /// offered algorithm is emitted directly, avoiding per-handshake
    /// compression buffers and CPU. Callers prepare these once at startup and
    /// keep them alive for as long as connections may be accepted. Entries
    /// that do not match are ignored, falling back to on-demand compression.
    prepared_certificate_compression: []const quic.tls.certificate_compression.PreparedView = &.{},
};

pub const OneRttConfig = struct {
    max_ack_ranges: usize = 64,
    max_frames_per_packet: usize = 16,
    /// Maximum unique peer PATH_CHALLENGEs retained until their matching
    /// PATH_RESPONSE packets can be submitted. Excess challenges are ignored.
    max_pending_path_responses: usize =
        quic.path_validation.default_max_pending_responses,
    /// Legacy direct 1-RTT flow-control knobs are retained for source
    /// compatibility, but integrated handshakes now derive the actual send and
    /// receive limits from negotiated transport parameters.  Set
    /// ClientOptions/ServerOptions.local_transport_parameters when controlling
    /// handshake-established flow credit.
    initial_send_max_data: u64 = std.math.maxInt(u62),
    initial_receive_max_data: u64 = std.math.maxInt(u62),
    receive_window: u64 = 64 * 1024,
    max_receive_window: ?u64 = null,
    initial_send_max_stream_data: u64 = std.math.maxInt(u62),
    initial_receive_max_stream_data: u64 = std.math.maxInt(u62),
    stream_receive_window: u64 = 64 * 1024,
    max_stream_receive_window: ?u64 = null,
    /// Maximum application DATAGRAM payloads retained while no direct
    /// receiver is active. Zero keeps only caller-buffer direct delivery.
    max_datagram_queue_items: usize = 16,
    /// Maximum cumulative payload bytes retained by that queue. Direct
    /// caller-buffer delivery remains available when this is zero.
    max_datagram_queue_bytes: usize =
        quic.one_rtt.default_max_datagram_queue_bytes,
    max_datagram_size: usize = quic.congestion.default_max_datagram_size,
    /// Select the 1-RTT key-update derivation for this connection. The default
    /// is RFC 9001/RFC 9369; the compatibility value exists only for pinned
    /// peers known to apply RFC 9001's update label to QUIC v2.
    key_update_profile: quic.protection.KeyPhaseState.UpdateProfile = .rfc,
    congestion_algorithm: quic.congestion.Algorithm = .cubic,
    enable_hystart: bool = true,
    enable_pacing: bool = true,
    pacing_max_burst_packets: usize = quic.pacing.Pacer.default_max_burst_packets,
    /// Optional hard ceiling for pacing credit, in bytes per second. Null
    /// keeps the congestion-derived rate; zero allows only reset bursts.
    max_pacing_rate_bytes_per_second: ?u64 = null,
    /// Randomize established-connection PTOs by up to this percentage. Valid
    /// values are 0...50; zero is deterministic and consumes no entropy.
    pto_jitter_percentage: u8 = 0,
    /// Allow RFC 9000 latency spin-bit generation on the established
    /// connection. Disabled by default for privacy and wire compatibility.
    /// When allowed, the handshake independently suppresses the signal for
    /// one in sixteen connections using its fresh TLS random.
    enable_spin_bit: bool = false,
    /// Automatically test ordinary application traffic with ECT(0).
    ///
    /// This setting is copied into the established 1-RTT connection so a
    /// handshake-created client or server can opt out just like a directly
    /// constructed connection. Explicit `sendWithEcn*` calls remain
    /// independent of this policy.
    automatic_ecn_policy: quic.ecn.Policy = .enabled,
    /// Deliver contiguous bytes received before RESET_STREAM to the
    /// application before surfacing the terminal reset event. Disabled by
    /// default to retain reset-first compatibility.
    enable_reset_partial_delivery: bool = false,
    keep_alive_period_ms: u64 = 0,
    /// Local receive ACK cadence for handshake-established 1-RTT traffic.
    /// The default acknowledges every second ack-eliciting application packet
    /// within 25 ms, matching RFC 9000's recommendation and mature peers.
    local_ack_eliciting_threshold: u64 = 2,
    local_max_ack_delay_us: u64 = 25_000,
    local_ack_reordering_threshold: u64 =
        quic.packet_space.default_packet_threshold,
    /// Optional negotiated ACK_FREQUENCY request. The wire threshold is the
    /// maximum number of ack-eliciting packets the peer may leave unacked.
    /// Null preserves the peer's transport-parameter ACK policy.
    ack_frequency_request: ?quic.one_rtt.AckFrequencyRequest = null,
    /// Stable endpoint secret used to derive reset tokens for every locally
    /// issued connection ID. Servers also bind the Initial Source Connection
    /// ID transport-parameter token to this key during the handshake.
    local_stateless_reset_key: ?[quic.stateless_reset.static_key_len]u8 = null,

    pub fn apply(
        self: OneRttConfig,
        version: quic.Version,
        peer: net.IpAddress,
        receive_keys: quic.protection.PacketProtectionKeys,
        send_keys: quic.protection.PacketProtectionKeys,
        local_connection_id: []const u8,
        peer_connection_id: []const u8,
        local_endpoint: quic.one_rtt.ConnectionConfig.EndpointRole,
        local_transport_parameters: quic.TransportParameters,
        peer_transport_parameters: quic.TransportParameters,
    ) quic.one_rtt.ConnectionConfig {
        return .{
            .version = version,
            .key_update_profile = self.key_update_profile,
            .peer = peer,
            .receive_keys = receive_keys,
            .send_keys = send_keys,
            .local_connection_id = local_connection_id,
            .peer_connection_id = peer_connection_id,
            .local_endpoint = local_endpoint,
            .max_ack_ranges = self.max_ack_ranges,
            .max_frames_per_packet = self.max_frames_per_packet,
            .max_pending_path_responses = self.max_pending_path_responses,
            .max_datagram_queue_items = self.max_datagram_queue_items,
            .max_datagram_queue_bytes = self.max_datagram_queue_bytes,
            .initial_send_max_data = @min(self.initial_send_max_data, peer_transport_parameters.initial_max_data),
            .initial_receive_max_data = @min(self.initial_receive_max_data, local_transport_parameters.initial_max_data),
            .receive_window = self.receive_window,
            .max_receive_window = self.max_receive_window,
            .initial_send_max_stream_data = self.initial_send_max_stream_data,
            .initial_receive_max_stream_data = self.initial_receive_max_stream_data,
            .initial_send_max_stream_data_bidi_local = @min(self.initial_send_max_stream_data, peer_transport_parameters.initial_max_stream_data_bidi_local),
            .initial_send_max_stream_data_bidi_remote = @min(self.initial_send_max_stream_data, peer_transport_parameters.initial_max_stream_data_bidi_remote),
            .initial_send_max_stream_data_uni = @min(self.initial_send_max_stream_data, peer_transport_parameters.initial_max_stream_data_uni),
            .initial_receive_max_stream_data_bidi_local = @min(self.initial_receive_max_stream_data, local_transport_parameters.initial_max_stream_data_bidi_local),
            .initial_receive_max_stream_data_bidi_remote = @min(self.initial_receive_max_stream_data, local_transport_parameters.initial_max_stream_data_bidi_remote),
            .initial_receive_max_stream_data_uni = @min(self.initial_receive_max_stream_data, local_transport_parameters.initial_max_stream_data_uni),
            .initial_send_max_streams_bidi = peer_transport_parameters.initial_max_streams_bidi,
            .initial_send_max_streams_uni = peer_transport_parameters.initial_max_streams_uni,
            .initial_receive_max_streams_bidi = local_transport_parameters.initial_max_streams_bidi,
            .initial_receive_max_streams_uni = local_transport_parameters.initial_max_streams_uni,
            .stream_receive_window = self.stream_receive_window,
            .max_stream_receive_window = self.max_stream_receive_window,
            .max_datagram_size = @min(
                self.max_datagram_size,
                std.math.cast(usize, peer_transport_parameters.max_udp_payload_size) orelse std.math.maxInt(usize),
            ),
            .congestion_algorithm = self.congestion_algorithm,
            .enable_hystart = self.enable_hystart,
            .enable_pacing = self.enable_pacing,
            .pacing_max_burst_packets = self.pacing_max_burst_packets,
            .max_pacing_rate_bytes_per_second = self.max_pacing_rate_bytes_per_second,
            .pto_jitter_percentage = self.pto_jitter_percentage,
            .enable_spin_bit = self.enable_spin_bit,
            .automatic_ecn_policy = self.automatic_ecn_policy,
            .enable_reset_partial_delivery = self.enable_reset_partial_delivery,
            .active_connection_id_limit = std.math.cast(usize, local_transport_parameters.active_connection_id_limit) orelse std.math.maxInt(usize),
            .peer_active_connection_id_limit = std.math.cast(usize, peer_transport_parameters.active_connection_id_limit) orelse std.math.maxInt(usize),
            .local_max_idle_timeout_ms = local_transport_parameters.max_idle_timeout,
            .peer_max_idle_timeout_ms = peer_transport_parameters.max_idle_timeout,
            .keep_alive_period_ms = self.keep_alive_period_ms,
            .local_ack_eliciting_threshold = self.local_ack_eliciting_threshold,
            .local_max_ack_delay_us = @min(
                self.local_max_ack_delay_us,
                std.math.mul(
                    u64,
                    local_transport_parameters.max_ack_delay,
                    1_000,
                ) catch std.math.maxInt(u64),
            ),
            .local_ack_reordering_threshold = self.local_ack_reordering_threshold,
            .local_ack_delay_exponent = local_transport_parameters.ack_delay_exponent,
            .peer_ack_delay_exponent = peer_transport_parameters.ack_delay_exponent,
            .peer_max_ack_delay_ms = peer_transport_parameters.max_ack_delay,
            .local_disable_active_migration = local_transport_parameters.disable_active_migration,
            .peer_disable_active_migration = peer_transport_parameters.disable_active_migration,
            .peer_preferred_address = peer_transport_parameters.preferred_address,
            .local_max_datagram_frame_size = if (local_transport_parameters.max_datagram_frame_size) |size| std.math.cast(usize, size) orelse std.math.maxInt(usize) else null,
            .peer_max_datagram_frame_size = if (peer_transport_parameters.max_datagram_frame_size) |size| std.math.cast(usize, size) orelse std.math.maxInt(usize) else null,
            .reliable_reset = .{
                .local = local_transport_parameters.reset_stream_at,
                .peer = peer_transport_parameters.reset_stream_at,
            },
            .accept_zero_fixed_bit = local_transport_parameters.grease_quic_bit,
            .grease_fixed_bit = peer_transport_parameters.grease_quic_bit,
            .enable_ack_frequency = local_transport_parameters.min_ack_delay != null or peer_transport_parameters.min_ack_delay != null,
            .local_min_ack_delay = local_transport_parameters.min_ack_delay,
            .peer_min_ack_delay = peer_transport_parameters.min_ack_delay,
            .automatic_ack_frequency_request = if (peer_transport_parameters.min_ack_delay != null)
                self.ack_frequency_request
            else
                null,
            .local_stateless_reset_key = self.local_stateless_reset_key,
            .peer_stateless_reset_token = peer_transport_parameters.stateless_reset_token,
            .tls_handshake_complete = true,
        };
    }
};

/// Deeply owned peer certificate chain retained after QUIC/TLS establishment.
/// Certificate bytes are immutable and remain valid until `deinit`.
pub const PeerCertificateChain = struct {
    allocator: std.mem.Allocator,
    certificates: []const []const u8,

    pub fn init(
        allocator: std.mem.Allocator,
        certificates: []const []const u8,
    ) Error!PeerCertificateChain {
        var copies: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (copies.items) |certificate| allocator.free(certificate);
            copies.deinit(allocator);
        }
        try copies.ensureTotalCapacity(allocator, certificates.len);
        for (certificates) |certificate| {
            const copy = try allocator.dupe(u8, certificate);
            copies.appendAssumeCapacity(copy);
        }
        return .{
            .allocator = allocator,
            .certificates = try copies.toOwnedSlice(allocator),
        };
    }

    pub fn deinit(self: *PeerCertificateChain) void {
        for (self.certificates) |certificate| {
            self.allocator.free(certificate);
        }
        self.allocator.free(self.certificates);
        self.* = undefined;
    }
};

pub const EstablishedConnection = struct {
    connection: quic.one_rtt.Connection,
    local_connection_id: []u8,
    peer_connection_id: []u8,
    alpn: []u8,
    /// TLS 1.3 suite authenticated by the handshake and used to derive QUIC
    /// packet protection. Preconfigured sessions derive the same metadata
    /// from their installed packet keys.
    cipher_suite: quic.tls.cipher_suite.Suite,
    /// Whether this handshake authenticated and followed a Retry exchange.
    /// Exposing the fact lets process-level interop gates prove address
    /// validation instead of inferring it from a successful connection.
    retry_processed: bool = false,
    /// RFC 8879 algorithm used by the server's compressed Certificate, or
    /// null when the Certificate message was uncompressed.
    certificate_compression: ?quic.tls.certificate_compression.Algorithm = null,
    resumed: bool = false,
    early_data_status: quic.zero_rtt.handshake.Status = .not_offered,
    /// Application packet numbers consumed by 0-RTT protection and the subset
    /// actually handed to the socket. They can differ after send failure.
    early_data_protected_packet_count: u64 = 0,
    early_data_sent_packet_count: usize = 0,
    /// Absent when 1-RTT state was installed without the TLS transcript secret.
    /// Application data remains fully stateful, but post-handshake tickets are
    /// unavailable unless the external key negotiator supplies this secret.
    resumption_master_secret: ?quic.tls.secret.Secret,
    /// TLS 1.3 exporter master secret bound to the transcript through the
    /// server Finished. Both peers derive the same value. Externally installed
    /// 1-RTT state may omit it when no TLS transcript is available.
    exporter_master_secret: ?quic.tls.secret.Secret,
    peer_certificate_chain: ?PeerCertificateChain,
    peer_transport_parameters: quic.resumption.Snapshot,
    post_handshake_send_crypto_offset: u64 = 0,
    post_handshake_receive_crypto_offset: u64 = 0,

    /// Issue one post-handshake TLS 1.3 ticket and register it in the bounded
    /// server store before sending it in 1-RTT CRYPTO.
    pub fn issueSessionTicket(
        self: *EstablishedConnection,
        io: std.Io,
        config: quic.resumption.ticket.handshake.ServerConfig,
    ) Error!quic.resumption.ticket.handshake.Issued {
        const resumption_master_secret = self.resumption_master_secret orelse
            return error.PostHandshakeTlsUnavailable;
        return quic.resumption.ticket.handshake.issue(
            &self.connection,
            io,
            config,
            resumption_master_secret,
            &self.post_handshake_send_crypto_offset,
        );
    }

    /// Receive one post-handshake NewSessionTicket and atomically insert an
    /// origin+ALPN-bound owned session into the client's cache.
    pub fn receiveAndCacheSessionTicket(
        self: *EstablishedConnection,
        config: quic.resumption.ticket.handshake.ClientConfig,
    ) Error!void {
        const resumption_master_secret = self.resumption_master_secret orelse
            return error.PostHandshakeTlsUnavailable;
        try quic.resumption.ticket.handshake.receiveAndCache(
            &self.connection,
            config,
            resumption_master_secret,
            self.alpn,
            self.peer_transport_parameters,
            &self.post_handshake_receive_crypto_offset,
        );
    }

    pub fn exportKeyingMaterial(
        self: *const EstablishedConnection,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        const exporter_master_secret = self.exporter_master_secret orelse
            return error.PostHandshakeTlsUnavailable;
        try quic.tls.key_schedule.exportKeyingMaterialFor(
            exporter_master_secret,
            label,
            context,
            out,
        );
    }

    pub fn peerCertificates(
        self: *const EstablishedConnection,
    ) ?[]const []const u8 {
        const chain = self.peer_certificate_chain orelse return null;
        return chain.certificates;
    }

    pub fn negotiatedCipherSuite(
        self: EstablishedConnection,
    ) quic.tls.cipher_suite.Suite {
        return self.cipher_suite;
    }

    pub fn negotiatedTranscriptHash(
        self: EstablishedConnection,
    ) quic.tls.secret.Hash {
        return self.cipher_suite.hash();
    }

    pub fn initiateKeyUpdate(self: *EstablishedConnection) Error!void {
        try self.connection.initiateKeyUpdate();
    }

    pub fn localKeyUpdateCount(self: EstablishedConnection) u64 {
        return self.connection.localOneRttKeyUpdateCount();
    }

    pub fn peerKeyUpdateCount(self: EstablishedConnection) u64 {
        return self.connection.peerOneRttKeyUpdateCount();
    }

    pub fn keyUpdateAwaitingAck(self: EstablishedConnection) bool {
        return self.connection.pendingOneRttKeyUpdateAckThreshold() != null;
    }

    pub fn deinit(self: *EstablishedConnection) void {
        const allocator = self.connection.endpoint.allocator;
        self.connection.deinit();
        if (self.resumption_master_secret) |*secret| secret.deinit();
        if (self.exporter_master_secret) |*secret| secret.deinit();
        if (self.peer_certificate_chain) |*chain| chain.deinit();
        allocator.free(self.local_connection_id);
        allocator.free(self.peer_connection_id);
        allocator.free(self.alpn);
        self.* = undefined;
    }
};

/// Inputs for installing externally negotiated 1-RTT keys into the complete
/// stateful QUIC transport.
///
/// This is intentionally distinct from the lightweight packet-protection APIs:
/// the resulting connection owns ACK/loss recovery, congestion, flow control,
/// stream limits, reset/stop state, timers, and key-update accounting. It is
/// suitable for deterministic deployments whose TLS/PSK setup happens outside
/// this module but which still require production QUIC stream semantics.
pub const PreconfiguredConnectionOptions = struct {
    version: quic.Version = .version_1,
    receive_keys: quic.protection.PacketProtectionKeys,
    send_keys: quic.protection.PacketProtectionKeys,
    local_connection_id: []const u8,
    peer_connection_id: []const u8,
    local_transport_parameters: quic.TransportParameters =
        quic.practical_transport_parameters,
    peer_transport_parameters: quic.TransportParameters =
        quic.practical_transport_parameters,
    one_rtt: OneRttConfig = .{},
    alpn_protocol: []const u8 = "h3",
    /// Optional TLS resumption master secret retained by the external
    /// negotiator. Without it, post-handshake NewSessionTicket helpers fail
    /// closed while all QUIC application-data facilities remain available.
    resumption_master_secret: ?quic.tls.secret.Secret = null,
    exporter_master_secret: ?quic.tls.secret.Secret = null,
    /// Authenticated certificate bytes supplied by the external negotiator.
    /// The established connection deep-copies every entry.
    peer_certificates: []const []const u8 = &.{},
};

pub fn establishPreconfigured(
    endpoint: *quic.runtime.Endpoint,
    peer: net.IpAddress,
    local_endpoint: quic.one_rtt.ConnectionConfig.EndpointRole,
    options: PreconfiguredConnectionOptions,
) Error!EstablishedConnection {
    if (options.version == .negotiation or
        quic.isReservedVersionWire(options.version.wireValue()) or
        options.local_connection_id.len == 0 or
        options.receive_keys.suite != options.send_keys.suite)
    {
        return error.InvalidTransportParameter;
    }
    const local_source: quic.TransportParameterSource = switch (local_endpoint) {
        .client => .client,
        .server => .server,
    };
    const peer_source: quic.TransportParameterSource = switch (local_endpoint) {
        .client => .server,
        .server => .client,
    };
    try quic.validateTransportParameters(
        options.local_transport_parameters,
        local_source,
    );
    try quic.validateTransportParameters(
        options.peer_transport_parameters,
        peer_source,
    );
    return establishedConnection(
        endpoint,
        options.version,
        peer,
        options.receive_keys,
        options.send_keys,
        options.local_connection_id,
        options.peer_connection_id,
        options.one_rtt,
        local_endpoint,
        options.local_transport_parameters,
        options.peer_transport_parameters,
        options.alpn_protocol,
        options.send_keys.suite,
        false,
        null,
        false,
        .not_offered,
        options.resumption_master_secret,
        options.exporter_master_secret,
        options.peer_certificates,
        null,
        .none,
    );
}

fn validateConfiguredVersions(version: quic.Version, available_versions: []const quic.Version) Error!void {
    if (version == .negotiation or quic.isReservedVersionWire(version.wireValue())) return error.InvalidVersionNegotiation;
    if (available_versions.len == 0) return error.InvalidVersionNegotiation;
    var contains_chosen = false;
    for (available_versions) |available| {
        if (available == .negotiation) return error.InvalidVersionNegotiation;
        if (available.wireValue() == version.wireValue()) contains_chosen = true;
    }
    if (!contains_chosen) return error.InvalidVersionNegotiation;
}

fn cipherSuiteEnabled(
    configured: []const quic.tls_client_hello.CipherSuite,
    selected: quic.tls_client_hello.CipherSuite,
) bool {
    for (configured) |suite| {
        if (suite == selected) return true;
    }
    return false;
}

pub fn selectServerPsk(
    client_hello_bytes: []const u8,
    cipher_suite: quic.tls_client_hello.CipherSuite,
    configured: ServerPsk,
) Error!?SelectedServerPsk {
    const configured_secret = configured.secret_value orelse
        quic.tls.secret.Secret.fromSha256(configured.secret);
    if (configured_secret.hash != cipher_suite.hash()) return null;
    const offer = try quic.resumption.tls_psk
        .findClientOfferForIdentityForHash(
        client_hello_bytes,
        configured.identity,
        configured_secret.hash,
    ) orelse return null;
    try quic.resumption.tls_psk.verifyClientOfferForSecret(
        client_hello_bytes,
        offer,
        configured.identity,
        configured_secret,
        null,
    );
    return .{
        .secret = configured_secret,
        .identity_index = offer.selected_identity,
        .age_within_tolerance = try quic.resumption.tls_psk
            .ticketAgeWithinTolerance(offer, .{
            .age_add = configured.age_add,
            .issued_at_ms = configured.issued_at_ms,
            .lifetime_seconds = configured.lifetime_seconds,
            .now_ms = configured.now_ms,
            .tolerance_ms = configured.age_tolerance_ms,
        }),
    };
}

pub fn lookupAutomaticServerPsk(
    client_hello_bytes: []const u8,
    cipher_suite: quic.tls_client_hello.CipherSuite,
    automatic: quic.resumption.ticket.handshake.ServerAutoResume,
) Error!?quic.resumption.ticket.store.Lease {
    var offers = (try quic.resumption.tls_psk.parseClientOffers(
        client_hello_bytes,
    )).iterator();
    while (offers.next()) |offered| {
        var lease = (try quic.resumption.ticket.handshake.lookupServer(
            automatic,
            offered.identity,
        )) orelse continue;
        if (lease.secret_value.hash == cipher_suite.hash()) return lease;
        lease.deinit();
    }
    return null;
}

pub fn configuredGreaseQuicBit(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    typed: quic.TransportParameters,
    source: quic.TransportParameterSource,
) Error!bool {
    if (encoded.len == 0) return typed.grease_quic_bit;
    return (try quic.parseTransportParametersTyped(
        allocator,
        encoded,
        source,
    )).grease_quic_bit;
}

fn clientInitialDestinationConnectionId(options: ClientOptions) []const u8 {
    if (options.retry_source_connection_id.len != 0) return options.retry_source_connection_id;
    return options.original_destination_connection_id;
}

fn activeRetrySourceConnectionId(
    options: ClientOptions,
    automatic_retry_source_connection_id: ?[]u8,
) []const u8 {
    if (automatic_retry_source_connection_id) |cid| return cid;
    return options.retry_source_connection_id;
}

fn isVersionNegotiationDatagram(bytes: []const u8) bool {
    if (bytes.len < 5 or (bytes[0] & 0x80) == 0) return false;
    return std.mem.readInt(u32, bytes[1..5], .big) == quic.Version.negotiation.wireValue();
}

fn replaceServerDatagramFromUntil(
    endpoint: *quic.runtime.Endpoint,
    source: quic.runtime.DatagramSource,
    deadline: std.Io.Timeout,
    datagram: *quic.runtime.OwnedBytes,
) Error!void {
    if (timeoutExpired(endpoint.io, deadline)) return error.HandshakeTimeout;
    const next_datagram: quic.runtime.OwnedBytes =
        source.receiveTimeout(deadline) catch |err| switch (err) {
            error.Timeout => return error.HandshakeTimeout,
            error.ConcurrencyUnavailable => return error.HandshakeReceiveFailed,
            else => |other| return @errorCast(other),
        };
    datagram.deinit(endpoint.allocator);
    datagram.* = next_datagram;
}

fn timeoutExpired(io: std.Io, timeout: std.Io.Timeout) bool {
    switch (timeout) {
        .deadline => |deadline| {
            std.debug.assert(deadline.clock == .awake);
            return std.Io.Clock.awake.now(io).nanoseconds >=
                deadline.raw.nanoseconds;
        },
        .none, .duration => return false,
    }
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

pub const HandshakeClosePacketType = failure.PacketType;

pub fn sendHandshakeProtocolViolation(
    endpoint: *quic.runtime.Endpoint,
    peer: net.IpAddress,
    packet_type: HandshakeClosePacketType,
    keys: quic.protection.PacketProtectionKeys,
    version: u32,
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    packet_number: u64,
    reason_phrase: []const u8,
    anti_amplification: ?*retransmit.AntiAmplificationBudget,
) Error!void {
    var state: failure.State = .{
        .endpoint = endpoint,
        .peer = peer,
        .packet_type = packet_type,
        .keys = keys,
        .version = version,
        .destination_connection_id = destination_connection_id,
        .source_connection_id = source_connection_id,
        .next_packet_number = packet_number,
        .client = anti_amplification == null,
        .anti_amplification = anti_amplification,
    };
    try state.send(@intFromEnum(quic.TransportErrorCode.protocol_violation), reason_phrase);
}

fn passiveHandshakeTimeout(
    io: std.Io,
    recovery: retransmit.Config,
) std.Io.Timeout {
    const local = recovery.passiveTimeout().toDeadline(io);
    const caller = recovery.deadline orelse return local;
    return switch (local) {
        .deadline => |value| if (std.Io.Clock.Timestamp.compare(
            caller,
            .lt,
            value,
        )) .{ .deadline = caller } else local,
        .none, .duration => unreachable,
    };
}

pub fn peekExpectedServerInitial(
    bytes: []const u8,
    version: quic.Version,
    expected_destination_connection_id: []const u8,
    allow_zero_fixed_bit: bool,
) Error!?quic.protection.ProtectedLongPacketInfo {
    const info = try quic.protection.peekProtectedLongPacketInfoWithFixedBitPolicy(
        bytes,
        allow_zero_fixed_bit,
    );
    if (info.version != version.wireValue() or
        info.packet_type != .initial or
        !std.mem.eql(
            u8,
            info.destination_connection_id,
            expected_destination_connection_id,
        ))
    {
        return null;
    }
    return info;
}

pub const EarlyDataFlight = struct {
    endpoint: *quic.runtime.Endpoint,
    peer: net.IpAddress,
    initial_keys: quic.protection.PacketProtectionKeys,
    initial_options: quic.initial_exchange.SendInitialFlightOptions,
    zero_rtt_keys: quic.protection.PacketProtectionKeys,
    zero_rtt_options: quic.zero_rtt.SendOptions,
    protected_packet_count: u64 = 0,
    next_initial_packet_number: ?u64 = null,
    sent_packet_numbers: [256]u64 = undefined,
    sent_packet_count: usize = 0,
    sent_packet_len: usize = 0,

    pub fn send(context: *anyopaque, retransmission: u8) anyerror!void {
        const self: *EarlyDataFlight = @ptrCast(@alignCast(context));
        var initial_options = self.initial_options;
        initial_options.initial.packet_number = std.math.add(
            u64,
            self.initial_options.initial.packet_number,
            std.math.mul(
                u64,
                self.initial_options.max_datagrams,
                retransmission,
            ) catch return error.InvalidPacketNumber,
        ) catch return error.InvalidPacketNumber;
        var zero_rtt_options = self.zero_rtt_options;
        zero_rtt_options.packet_number = std.math.add(
            u64,
            self.zero_rtt_options.packet_number,
            self.protected_packet_count,
        ) catch return error.InvalidPacketNumber;
        // Complete 0-RTT validation, allocation and protection before the
        // Initial flight becomes visible. Once this succeeds its application
        // packet number is consumed even if either socket send reports zero.
        var prepared_zero_rtt = try quic.zero_rtt.prepareFrames(
            self.endpoint,
            self.zero_rtt_keys,
            zero_rtt_options,
        );
        defer prepared_zero_rtt.deinit(self.endpoint.allocator);
        self.protected_packet_count = std.math.add(
            u64,
            self.protected_packet_count,
            1,
        ) catch return error.InvalidPacketNumber;
        const initial_progress = try quic.initial_exchange
            .sendInitialCryptoFlightProgress(
            self.endpoint,
            self.peer,
            self.initial_keys,
            initial_options,
        );
        self.next_initial_packet_number = if (initial_progress.last_packet_number < quic.protection.max_packet_number)
            initial_progress.last_packet_number + 1
        else
            null;
        if (initial_progress.sent_count < initial_progress.protected_count) {
            return;
        }
        _ = initial_progress.send_error;
        const zero_rtt_progress = quic.zero_rtt.sendPreparedFramesProgress(
            self.endpoint,
            self.peer,
            prepared_zero_rtt,
        );
        if (zero_rtt_progress.sent_count != 0) {
            std.debug.assert(
                self.sent_packet_count < self.sent_packet_numbers.len,
            );
            self.sent_packet_numbers[self.sent_packet_count] =
                zero_rtt_options.packet_number;
            self.sent_packet_count += 1;
            self.sent_packet_len = zero_rtt_progress.packet_len;
        }
        _ = zero_rtt_progress.send_error;
    }
};

pub fn connect(endpoint: *quic.runtime.Endpoint, peer: net.IpAddress, options: ClientOptions) Error!EstablishedConnection {
    return connectFrom(
        endpoint,
        quic.runtime.DatagramSource.fromEndpoint(endpoint),
        peer,
        options,
    );
}

/// Complete a client handshake before one caller-owned awake-clock deadline.
/// The same timestamp caps Initial PTO, Retry, Version Negotiation, passive
/// fragmented flights, authentication, and Client Finished.
pub fn connectWithDeadline(
    endpoint: *quic.runtime.Endpoint,
    peer: net.IpAddress,
    options: ClientOptions,
    deadline: std.Io.Clock.Timestamp,
) Error!EstablishedConnection {
    return connectFromWithDeadline(
        endpoint,
        .fromEndpoint(endpoint),
        peer,
        options,
        deadline,
    );
}

pub fn connectWithTimeout(
    endpoint: *quic.runtime.Endpoint,
    peer: net.IpAddress,
    options: ClientOptions,
    timeout: std.Io.Duration,
) Error!EstablishedConnection {
    if (timeout.nanoseconds <= 0) return error.HandshakeTimeout;
    return connectWithDeadline(
        endpoint,
        peer,
        options,
        .fromNow(endpoint.io, .{ .raw = timeout, .clock = .awake }),
    );
}

/// Complete a client handshake while receiving through a caller-provided
/// source. A shared socket owner can route this attempt's long-header packets
/// into an inbox instead of allowing several clients to race on the endpoint.
pub fn connectFrom(
    endpoint: *quic.runtime.Endpoint,
    source: quic.runtime.DatagramSource,
    peer: net.IpAddress,
    options: ClientOptions,
) Error!EstablishedConnection {
    var reader = datagram_reader.Reader.init(endpoint.allocator, source);
    defer reader.deinit();
    if (options.resumption_session == null and
        options.early_data == null and
        options.auto_resumption != null)
    {
        const automatic = options.auto_resumption.?;
        var session = (try quic.resumption.ticket.handshake.acquireFirst(
            automatic,
            options.alpn_protocols,
        )) orelse return connectAttempt(
            endpoint,
            &reader,
            peer,
            options,
            false,
            false,
        );
        defer session.deinit();
        var resumed_options = options;
        resumed_options.resumption_session = &session;
        resumed_options.resumption_now_ms = automatic.now_ms;
        resumed_options.resumption_server_id = automatic.server_id;
        return connectAttempt(
            endpoint,
            &reader,
            peer,
            resumed_options,
            false,
            false,
        );
    }
    return connectAttempt(
        endpoint,
        &reader,
        peer,
        options,
        false,
        false,
    );
}

pub fn connectFromWithDeadline(
    endpoint: *quic.runtime.Endpoint,
    source: quic.runtime.DatagramSource,
    peer: net.IpAddress,
    options: ClientOptions,
    deadline: std.Io.Clock.Timestamp,
) Error!EstablishedConnection {
    return connectFrom(
        endpoint,
        source,
        peer,
        try clientOptionsBefore(endpoint.io, options, deadline),
    );
}

pub fn connectFromWithTimeout(
    endpoint: *quic.runtime.Endpoint,
    source: quic.runtime.DatagramSource,
    peer: net.IpAddress,
    options: ClientOptions,
    timeout: std.Io.Duration,
) Error!EstablishedConnection {
    if (timeout.nanoseconds <= 0) return error.HandshakeTimeout;
    return connectFromWithDeadline(
        endpoint,
        source,
        peer,
        options,
        .fromNow(endpoint.io, .{ .raw = timeout, .clock = .awake }),
    );
}

fn clientOptionsBefore(
    io: std.Io,
    options: ClientOptions,
    deadline: std.Io.Clock.Timestamp,
) Error!ClientOptions {
    if (deadline.clock != .awake) return error.InvalidHandshakeRecovery;
    if (deadline.durationFromNow(io).raw.nanoseconds <= 0) {
        return error.HandshakeTimeout;
    }
    var bounded = options;
    if (bounded.handshake_recovery.deadline) |configured| {
        if (configured.clock != .awake) {
            return error.InvalidHandshakeRecovery;
        }
        if (std.Io.Clock.Timestamp.compare(configured, .lt, deadline)) {
            return bounded;
        }
    }
    bounded.handshake_recovery.deadline = deadline;
    return bounded;
}

noinline fn clientFlightLen(
    certificate_len: usize,
    certificate_verify_len: usize,
    finished_len: usize,
) std.mem.Allocator.Error!usize {
    const prefix_len = std.math.add(
        usize,
        certificate_len,
        certificate_verify_len,
    ) catch return error.OutOfMemory;
    return std.math.add(usize, prefix_len, finished_len) catch
        return error.OutOfMemory;
}

fn connectAttempt(
    endpoint: *quic.runtime.Endpoint,
    reader: *datagram_reader.Reader,
    peer: net.IpAddress,
    options: ClientOptions,
    version_negotiation_processed: bool,
    early_data_offered_before_version_negotiation: bool,
) Error!EstablishedConnection {
    const source = reader.datagramSource();
    try validateConfiguredVersions(options.version, options.available_versions);
    const auth_now = std.Io.Timestamp.now(endpoint.io, .real);
    var system_store: ?quic.tls.trust.SystemStore = null;
    defer if (system_store) |*store| store.deinit();
    var platform_verifier: ?quic.tls.platform.Verifier = null;
    defer if (platform_verifier) |*verifier| verifier.deinit();
    const server_auth = options.server_auth orelse blk: {
        if (options.system_store) |store| {
            break :blk quic.tls.auth.ClientVerifier.fromTrustVerifier(
                store.verifier(auth_now.toSeconds()).clientVerifier(),
            );
        }
        if (options.root_source == .platform) {
            platform_verifier = quic.tls.platform.Verifier.init(
                endpoint.allocator,
                .{},
            ) catch |err| switch (@as(anyerror, err)) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.NativeTrustStoreUnavailable,
            };
            break :blk quic.tls.auth.ClientVerifier.fromTrustVerifier(
                platform_verifier.?.clientVerifier(),
            );
        }
        if (options.root_source == .bundled) {
            system_store = root_trust.initBundledStore(
                endpoint.allocator,
                auth_now,
            ) catch |err| switch (@as(anyerror, err)) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.NativeTrustStoreUnavailable,
            };
            break :blk quic.tls.auth.ClientVerifier.fromTrustVerifier(
                system_store.?.verifier(
                    auth_now.toSeconds(),
                ).clientVerifier(),
            );
        }
        if (options.system_environ) |environ| {
            system_store = quic.tls.trust.SystemStore.initWithEnviron(
                endpoint.allocator,
                endpoint.io,
                auth_now,
                environ,
            ) catch |err| switch (@as(anyerror, err)) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.NativeTrustStoreUnavailable,
            };
            break :blk quic.tls.auth.ClientVerifier.fromTrustVerifier(
                system_store.?.verifier(
                    auth_now.toSeconds(),
                ).clientVerifier(),
            );
        }
        break :blk null;
    };
    if (options.retry_source_connection_id.len != 0 and options.address_validation_token.len == 0) {
        return error.InvalidPacket;
    }

    var client_key_shares = try key_exchange.make(
        endpoint.io,
        options.key_exchange_groups,
        .{
            .x25519_secret = options.x25519_secret_key,
            .p256_secret = options.p256_secret_key,
            .p384_secret = options.p384_secret_key,
            .x25519_hybrid_curve_secret = options.x25519_mlkem768_secret_key,
            .x25519_hybrid_mlkem_seed = options.x25519_mlkem768_seed,
            .nist_hybrid = options.nist_hybrid_key_material,
        },
    );
    defer client_key_shares.deinit();
    try options.handshake_recovery.validate();
    const legacy_x25519_public = switch (client_key_shares.shares[0]) {
        .x25519 => |key| key,
        else => [_]u8{0} ** 32,
    };
    const client_random = try random32(endpoint.io, options.random);
    const initial_destination_connection_id = clientInitialDestinationConnectionId(options);
    const initial_secrets = try quic.protection.deriveInitialSecretsForVersion(options.version.wireValue(), initial_destination_connection_id);

    var local_transport_parameters = options.local_transport_parameters;
    var encoded_transport_parameters: std.ArrayList(u8) = .empty;
    defer encoded_transport_parameters.deinit(endpoint.allocator);
    const transport_parameters = try clientTransportParameters(
        endpoint.allocator,
        options,
        endpoint.limits.max_datagram_size,
        &local_transport_parameters,
        &encoded_transport_parameters,
    );

    var client_hello: std.ArrayList(u8) = .empty;
    defer client_hello.deinit(endpoint.allocator);
    try quic.tls_client_hello.writeClientHello(&client_hello, endpoint.allocator, .{
        .random = client_random,
        .x25519_public_key = legacy_x25519_public,
        .key_shares = client_key_shares.slice(),
        .server_name = options.server_name,
        .alpn_protocols = options.alpn_protocols,
        .transport_parameters = transport_parameters,
        .cipher_suites = options.cipher_suites,
        .certificate_compression_algorithms = options.certificate_compression_algorithms,
    });
    const resumption_session = if (options.early_data) |early_data|
        &early_data.lease.session
    else
        options.resumption_session;
    const offer_early_data = options.early_data != null;
    if (offer_early_data and options.retry_source_connection_id.len != 0) {
        // RFC 9001 §4.6: a client MUST NOT send 0-RTT after Retry because the
        // original early-data keys are bound to the pre-Retry ClientHello.
        return error.EarlyDataIncompatibleWithRetry;
    }
    if (options.early_data) |early_data| {
        try early_data.validate();
        if (options.resumption_session) |explicit_session| {
            if (!early_data.lease.session.psk_secret.eql(
                &explicit_session.psk_secret,
            ) or
                !std.mem.eql(
                    u8,
                    early_data.lease.session.ticket,
                    explicit_session.ticket,
                ))
            {
                return error.InvalidEarlyDataLease;
            }
        }
    }
    if (resumption_session) |session| {
        const now_ms = options.resumption_now_ms orelse
            return error.InvalidClientHello;
        if (now_ms < session.issued_at_ms) return error.InvalidClientHello;
        const expected_server_id = options.resumption_server_id orelse
            return error.InvalidClientHello;
        if (!std.mem.eql(u8, session.server_id, expected_server_id)) {
            return error.InvalidClientHello;
        }
        var offered_alpn = false;
        for (options.alpn_protocols) |protocol| {
            if (std.mem.eql(u8, protocol, session.alpn)) {
                offered_alpn = true;
                break;
            }
        }
        if (!offered_alpn) return error.InvalidClientHello;
        const age = now_ms - session.issued_at_ms;
        if (age >= @as(u64, session.lifetime_seconds) * std.time.ms_per_s or
            age > std.math.maxInt(u32))
        {
            return error.ExpiredPsk;
        }
        switch (session.psk_secret.hash) {
            .sha256 => try quic.resumption.tls_psk
                .appendClientOfferWithEarlyData(
                &client_hello,
                endpoint.allocator,
                session.ticket,
                session.obfuscatedTicketAge(now_ms),
                try session.psk_secret.sha256(),
                offer_early_data,
            ),
            .sha384 => try quic.resumption.tls_psk
                .appendClientOfferWithEarlyDataSha384(
                &client_hello,
                endpoint.allocator,
                session.ticket,
                session.obfuscatedTicketAge(now_ms),
                try session.psk_secret.sha384(),
                offer_early_data,
            ),
            .sm3 => return error.InvalidClientHello,
        }
    }

    var retry_token: ?[]u8 = null;
    defer if (retry_token) |token| endpoint.allocator.free(token);
    var retry_source_connection_id: ?[]u8 = null;
    defer if (retry_source_connection_id) |cid|
        endpoint.allocator.free(cid);
    var retry_processed = options.retry_source_connection_id.len != 0;
    var active_destination_connection_id = initial_destination_connection_id;
    var active_token = options.address_validation_token;
    var next_initial_packet_number: ?u64 = null;
    var active_initial_secrets = initial_secrets;
    var active_initial_packet_number = options.client_initial_packet_number;
    var send_early_data = options.early_data != null;
    var protected_early_data_packet_count: u64 = 0;
    var sent_early_data_packet_numbers: [256]u64 = undefined;
    var sent_early_data_packet_count: usize = 0;
    var sent_early_data_packet_len: usize = 0;
    var server_datagram: quic.runtime.OwnedBytes = undefined;
    var accepted_initial_packet_number: ?u64 = null;

    while (true) {
        var response_filter = retry.InitialResponseFilter{
            .allocator = endpoint.allocator,
            .version = options.version,
            .original_destination_connection_id = options.original_destination_connection_id,
            .initial_source_connection_id = options.local_connection_id,
            .initial_keys = active_initial_secrets.server,
            .retry_already_processed = retry_processed,
            .allow_zero_fixed_bit = local_transport_parameters.grease_quic_bit,
        };
        if (send_early_data) {
            const early_data = options.early_data.?;
            const keys =
                try quic.zero_rtt.handshake.clientKeysForSecretAndVersion(
                    options.version.wireValue(),
                    early_data.lease.session.cipher_suite,
                    early_data.lease.session.psk_secret,
                    client_hello.items,
                );
            var send_context = EarlyDataFlight{
                .endpoint = endpoint,
                .peer = peer,
                .initial_keys = active_initial_secrets.client,
                .initial_options = .{
                    .initial = .{
                        .version = options.version.wireValue(),
                        .destination_connection_id = active_destination_connection_id,
                        .source_connection_id = options.local_connection_id,
                        .token = active_token,
                        .packet_number = active_initial_packet_number,
                        .crypto_data = client_hello.items,
                        .max_crypto_frame_data_len = options.max_crypto_frame_data_len,
                        .min_datagram_size = quic.initial_exchange
                            .min_initial_udp_datagram_size,
                    },
                    .max_datagram_size = endpoint.limits.max_datagram_size,
                },
                .zero_rtt_keys = keys.packet,
                .zero_rtt_options = .{
                    .version = options.version.wireValue(),
                    .destination_connection_id = active_destination_connection_id,
                    .source_connection_id = options.local_connection_id,
                    .packet_number = 0,
                    .packet_number_len = early_data.packet_number_len,
                    .frames = early_data.frames,
                },
            };
            server_datagram =
                retransmit.sendAndReceiveMatchingContextFrom(
                    endpoint,
                    source,
                    options.handshake_recovery,
                    &send_context,
                    EarlyDataFlight.send,
                    &response_filter,
                    retry.InitialResponseFilter.accept,
                ) catch |err| {
                    // Packet protection consumes the exclusive lease even if
                    // the socket reports zero progress.
                    if (send_context.protected_packet_count != 0 and
                        early_data.lease.state == .active)
                    {
                        early_data.cache.consumeEarlyData(
                            early_data.lease,
                        ) catch unreachable;
                    }
                    return err;
                };
            next_initial_packet_number = send_context.next_initial_packet_number;
            protected_early_data_packet_count =
                send_context.protected_packet_count;
            sent_early_data_packet_count = send_context.sent_packet_count;
            sent_early_data_packet_len = send_context.sent_packet_len;
            @memcpy(
                sent_early_data_packet_numbers[0..sent_early_data_packet_count],
                send_context.sent_packet_numbers[0..sent_early_data_packet_count],
            );
            if (protected_early_data_packet_count != 0 and
                early_data.lease.state == .active)
            {
                early_data.cache.consumeEarlyData(
                    early_data.lease,
                ) catch unreachable;
            }
        } else {
            var send_context = retransmit.InitialFlight{
                .endpoint = endpoint,
                .peer = peer,
                .keys = active_initial_secrets.client,
                .options = .{
                    .initial = .{
                        .version = options.version.wireValue(),
                        .destination_connection_id = active_destination_connection_id,
                        .source_connection_id = options.local_connection_id,
                        .token = active_token,
                        .packet_number = active_initial_packet_number,
                        .crypto_data = client_hello.items,
                        .max_crypto_frame_data_len = options.max_crypto_frame_data_len,
                        .min_datagram_size = quic.initial_exchange
                            .min_initial_udp_datagram_size,
                    },
                    .max_datagram_size = endpoint.limits.max_datagram_size,
                },
            };
            server_datagram =
                try retransmit.sendAndReceiveMatchingContextFrom(
                    endpoint,
                    source,
                    options.handshake_recovery,
                    &send_context,
                    retransmit.InitialFlight.send,
                    &response_filter,
                    retry.InitialResponseFilter.accept,
                );
            next_initial_packet_number = send_context.next_packet_number;
        }

        accepted_initial_packet_number =
            response_filter.accepted_packet_number;
        _ = quic.retry_flow.validateClientPacket(
            endpoint.allocator,
            .{
                .version = options.version,
                .original_destination_connection_id = options.original_destination_connection_id,
                .initial_source_connection_id = options.local_connection_id,
            },
            server_datagram.bytes,
        ) catch break;
        const processed = quic.retry_flow.processClient(
            endpoint.allocator,
            .{
                .version = options.version,
                .original_destination_connection_id = options.original_destination_connection_id,
                .initial_source_connection_id = options.local_connection_id,
                .retry_already_processed = retry_processed,
            },
            server_datagram.bytes,
            options,
        ) catch |err| switch (err) {
            error.InvalidToken,
            error.TokenExpired,
            error.TokenNotYetValid,
            error.TokenReplay,
            error.RetryAlreadyProcessed,
            error.InitialAlreadyProcessed,
            => return error.InvalidHandshakeFlight,
            else => |other| return @errorCast(other),
        };
        server_datagram.deinit(endpoint.allocator);

        retry_token = processed.token;
        retry_source_connection_id =
            processed.retry_source_connection_id;
        active_destination_connection_id =
            retry_source_connection_id.?;
        active_token = retry_token.?;
        active_initial_secrets = processed.retry_initial_secrets;
        active_initial_packet_number = 0;
        retry_processed = true;
        // RFC 9001 §4.6 forbids replaying 0-RTT after Retry. PSK resumption
        // continues with the exact same ClientHello/binder bytes.
        send_early_data = false;
    }
    var server_datagram_owned = true;
    defer if (server_datagram_owned) {
        server_datagram.deinit(endpoint.allocator);
    };
    if (isVersionNegotiationDatagram(server_datagram.bytes)) {
        var negotiated = (try quic.version_negotiation.processClient(endpoint.allocator, .{
            .chosen_version = options.version,
            .available_versions = options.available_versions,
            .original_destination_connection_id = options.original_destination_connection_id,
            .initial_source_connection_id = options.local_connection_id,
            .initial_sent = true,
            .retry_processed = retry_processed,
            .version_negotiation_processed = version_negotiation_processed,
        }, server_datagram.bytes)) orelse return error.InvalidHandshakeFlight;
        defer negotiated.deinit(endpoint.allocator);
        var next = negotiated.clientOptions(options);
        // 0-RTT keys are version-specific and the lease was consumed once its
        // first packet left the socket. Continue with ordinary PSK resumption
        // rather than replaying early data under the negotiated version.
        next.early_data = null;
        next.resumption_session = resumption_session;
        server_datagram.deinit(endpoint.allocator);
        server_datagram_owned = false;
        return connectAttempt(
            endpoint,
            reader,
            peer,
            next,
            true,
            early_data_offered_before_version_negotiation or offer_early_data,
        );
    }

    const server_initial_deadline = passiveHandshakeTimeout(
        endpoint.io,
        options.handshake_recovery,
    );
    var server_initial_info: quic.protection.ProtectedLongPacketInfo = undefined;
    var server_initial_flight = while (true) {
        server_initial_info = peekExpectedServerInitial(
            server_datagram.bytes,
            options.version,
            options.local_connection_id,
            options.local_transport_parameters.grease_quic_bit,
        ) catch |err| switch (err) {
            error.InvalidInitialPacket,
            error.InvalidPayloadLength,
            error.InvalidHeaderProtectionSample,
            error.BufferTooShort,
            error.UnsupportedVersion,
            => {
                try replaceServerDatagramFromUntil(
                    endpoint,
                    source,
                    server_initial_deadline,
                    &server_datagram,
                );
                continue;
            },
            else => |other| return other,
        } orelse {
            try replaceServerDatagramFromUntil(
                endpoint,
                source,
                server_initial_deadline,
                &server_datagram,
            );
            continue;
        };

        const initial_flight_deadline: ?std.Io.Clock.Timestamp = switch (server_initial_deadline) {
            .none => null,
            .deadline => |deadline| deadline,
            .duration => |duration| .fromNow(endpoint.io, duration),
        };
        break quic.initial_exchange.openInitialCryptoFlightFrom(
            endpoint,
            source,
            server_datagram.from,
            server_datagram.bytes[0..server_initial_info.len],
            active_initial_secrets.server,
            .{
                .expected_packet_number = accepted_initial_packet_number orelse 0,
                .max_crypto_buffer = options.max_crypto_buffer,
                .allow_zero_fixed_bit = local_transport_parameters.grease_quic_bit,
                .discard_invalid_first = true,
                .deadline = initial_flight_deadline,
            },
        ) catch |err| switch (err) {
            error.DiscardedInitialPacket => {
                try replaceServerDatagramFromUntil(
                    endpoint,
                    source,
                    server_initial_deadline,
                    &server_datagram,
                );
                continue;
            },
            else => |other| return other,
        };
    };
    defer server_initial_flight.deinit(endpoint.allocator);
    const server_initial = quic.initial_exchange.ReceivedInitialCrypto{
        .from = server_initial_flight.from,
        .packet = server_initial_flight.first_packet,
        .crypto_data = server_initial_flight.crypto_data,
    };
    var peer_failure: failure.State = .{
        .endpoint = endpoint,
        .peer = server_initial.from,
        .packet_type = .initial,
        .keys = active_initial_secrets.client,
        .version = options.version.wireValue(),
        .destination_connection_id = server_initial.packet.source_connection_id,
        .source_connection_id = options.local_connection_id,
        .next_packet_number = next_initial_packet_number,
        .client = true,
    };
    const parsed_server = try peer_failure.guardTls(quic.tls_client_hello.parseServerHello(
        server_initial.crypto_data,
    ));
    if (!cipherSuiteEnabled(
        options.cipher_suites,
        parsed_server.cipher_suite,
    )) {
        return peer_failure.rejectTls(error.InvalidCipherSuite);
    }
    const offered_psk = resumption_session != null;
    const resumed = if (parsed_server.selected_psk_identity) |identity| blk: {
        if (!offered_psk or identity != 0) return peer_failure.rejectTls(error.InvalidServerHello);
        break :blk true;
    } else false;
    const selected_psk: ?quic.tls.secret.Secret = if (resumed)
        resumption_session.?.psk_secret
    else
        null;
    var offered_selected_group = false;
    for (options.key_exchange_groups) |group| {
        if (group == parsed_server.selected_group) {
            offered_selected_group = true;
            break;
        }
    }
    if (!offered_selected_group) return peer_failure.rejectTls(error.InvalidServerHello);
    var shared = try peer_failure.guardTls(client_key_shares.clientSharedSecret(
        parsed_server.selected_group,
        parsed_server.keyShare(),
    ));
    defer shared.wipe();
    var transcript = handshake_transcript.Flow.init(
        parsed_server.cipher_suite.hash(),
        client_hello.items,
        server_initial.crypto_data,
    );
    const hs_hash = transcript.digest();
    const handshake =
        try quic.tls_client_hello
            .deriveRuntimeHandshakeSecretsFromSliceForVersion(
            options.version.wireValue(),
            parsed_server.cipher_suite,
            shared.bytes(),
            hs_hash,
            selected_psk,
        );
    peer_failure.packet_type = .handshake;
    peer_failure.keys = handshake.client_quic;
    peer_failure.next_packet_number = options.client_handshake_packet_number;
    if (options.keylog) |keylog| {
        try keylog.writeHandshakeSecrets(
            client_random,
            handshake.client_handshake_traffic_secret.bytes(),
            handshake.server_handshake_traffic_secret.bytes(),
        );
    }

    const server_handshake_ecn = server_datagram.ecn;
    var server_handshake_tail =
        server_datagram.bytes[server_initial_info.len..];
    if (server_handshake_tail.len == 0) {
        server_datagram.deinit(endpoint.allocator);
        server_datagram_owned = false;
        server_handshake_tail = &.{};
    }
    var client_handshake_packet_number = options.client_handshake_packet_number;
    var server_handshake = receiveServerHandshakeCrypto(
        endpoint,
        source,
        server_initial.from,
        server_handshake_tail,
        server_handshake_ecn,
        handshake.server_quic,
        handshake.client_quic,
        &client_handshake_packet_number,
        0,
        options.max_crypto_buffer,
        local_transport_parameters.grease_quic_bit,
        !resumed and server_auth != null,
        options.handshake_recovery,
    ) catch |err| {
        if (err == error.InvalidReservedBits) {
            sendHandshakeProtocolViolation(
                endpoint,
                server_initial.from,
                .handshake,
                handshake.client_quic,
                options.version.wireValue(),
                server_initial.packet.source_connection_id,
                options.local_connection_id,
                options.client_handshake_packet_number,
                "reserved bits",
                null,
            ) catch {};
        }
        return err;
    };
    if (server_datagram_owned) {
        server_datagram.deinit(endpoint.allocator);
        server_datagram_owned = false;
    }
    peer_failure.next_packet_number = client_handshake_packet_number;
    defer server_handshake.deinit(endpoint.allocator);
    const server_flight = try peer_failure.guardTls(splitServerFlight(
        server_handshake.crypto_data,
        !resumed and server_auth != null,
    ));
    const encrypted_extensions = try peer_failure.guardTls(quic.tls_client_hello.parseEncryptedExtensions(server_flight.encrypted_extensions));
    try peer_failure.guardTls(ensureOfferedAlpn(options.alpn_protocols, encrypted_extensions.alpn));
    const peer_transport_parameters = try peer_failure.guardTransport(quic.parseTransportParametersTyped(
        endpoint.allocator,
        encrypted_extensions.transport_parameters,
        .server,
    ));
    try peer_failure.guardTransport(validateServerTransportParameters(
        peer_transport_parameters,
        server_initial.packet.source_connection_id,
        options.original_destination_connection_id,
        activeRetrySourceConnectionId(
            options,
            retry_source_connection_id,
        ),
        options.version,
        options.available_versions,
        version_negotiation_processed,
    ));
    const attempt_early_data_status = if (offer_early_data and retry_processed)
        quic.zero_rtt.handshake.Status.rejected
    else
        try quic.zero_rtt.handshake.validateClientAcceptance(
            offer_early_data,
            resumed,
            encrypted_extensions.early_data_accepted,
            if (options.early_data) |early_data|
                early_data.lease.session.transport_parameters
            else
                quic.resumption.Snapshot.fromTransportParameters(.{}),
            peer_transport_parameters,
        );
    const early_data_status = if (early_data_offered_before_version_negotiation and
        attempt_early_data_status == .not_offered)
        quic.zero_rtt.handshake.Status.rejected
    else
        attempt_early_data_status;
    var peer_certificate: ?quic.tls.auth.ParsedCertificate = null;
    defer if (peer_certificate) |*certificate| {
        certificate.deinit(endpoint.allocator);
    };
    // Parsed entries borrow this decompressed message until the established
    // connection makes its own DER copies at the end of the handshake.
    var owned_certificate_bytes: ?[]u8 = null;
    defer if (owned_certificate_bytes) |owned| endpoint.allocator.free(owned);
    var established_certificate_compression: ?quic.tls.certificate_compression.Algorithm = null;
    if (resumed) {
        if (server_flight.certificate != null or
            server_flight.certificate_verify != null)
        {
            return peer_failure.rejectTls(error.InvalidHandshakeFlight);
        }
    } else if (server_auth) |verifier| {
        const raw_certificate_bytes = server_flight.certificate orelse
            return peer_failure.rejectTls(error.InvalidHandshakeFlight);
        const certificate_verify_bytes =
            server_flight.certificate_verify orelse
            return peer_failure.rejectTls(error.InvalidHandshakeFlight);
        // RFC 8879: a type-0x19 message is decompressed for chain parsing,
        // while the transcript continues over the compressed bytes because
        // server_flight.through_certificate keeps the original flight slice.
        const certificate_bytes = if (raw_certificate_bytes[0] ==
            quic.tls.certificate_compression.handshake_type_compressed_certificate)
        blk: {
            const compression_algorithm = blk2: {
                if (raw_certificate_bytes.len < 5) break :blk2 null;
                break :blk2 @as(quic.tls.certificate_compression.Algorithm, @enumFromInt(
                    std.mem.readInt(u16, raw_certificate_bytes[4..6], .big),
                ));
            };
            established_certificate_compression = compression_algorithm;
            const decompressed = quic.tls.certificate_compression.decompressCertificate(
                endpoint.allocator,
                raw_certificate_bytes,
                options.certificate_compression_algorithms,
                options.max_decompressed_certificate_len,
            ) catch return peer_failure.rejectTls(error.InvalidHandshakeFlight);
            owned_certificate_bytes = decompressed;
            break :blk decompressed;
        } else raw_certificate_bytes;
        peer_certificate = try peer_failure.guardTls(quic.tls.auth.parseCertificate(
            endpoint.allocator,
            certificate_bytes,
        ));
        try peer_failure.guardTls(verifier.verifyTrust(
            options.server_name,
            peer_certificate.?.entries,
        ));
        const certificate_verify =
            try peer_failure.guardTls(quic.tls.auth.parseCertificateVerify(
                certificate_verify_bytes,
            ));
        const certificate_transcript_hash = transcript.digestAfter(
            server_flight.through_certificate orelse
                return error.InvalidHandshakeFlight,
        );
        try peer_failure.guardTls(verifier.verifyPeerCertificateVerify(
            peer_certificate.?.entries[0],
            certificate_verify,
            certificate_transcript_hash.bytes(),
            .server,
        ));
    }
    const server_finished = try peer_failure.guardTls(quic.tls_client_hello.parseFinishedForHash(
        server_flight.finished,
        parsed_server.cipher_suite.hash(),
    ));
    transcript.append(server_flight.before_finished);
    const server_finished_hash = transcript.digest();
    try peer_failure.guardTls(quic.tls_client_hello.verifyFinishedForHash(
        handshake.server_handshake_traffic_secret,
        server_finished_hash,
        server_finished,
    ));
    transcript.append(server_flight.finished);
    const application_transcript_hash = transcript.digest();
    const application =
        try quic.tls_client_hello
            .deriveRuntimeApplicationSecretsForVersion(
            options.version.wireValue(),
            parsed_server.cipher_suite,
            handshake.handshake_secret,
            application_transcript_hash,
        );

    var client_certificate: std.ArrayList(u8) = .empty;
    defer client_certificate.deinit(endpoint.allocator);
    var client_certificate_verify: std.ArrayList(u8) = .empty;
    defer client_certificate_verify.deinit(endpoint.allocator);
    if (server_flight.certificate_request) |request_bytes| {
        const request = try peer_failure.guardTls(quic.tls.client_auth.parseRequest(request_bytes));
        const identity = options.client_identity orelse
            return peer_failure.rejectTls(error.ClientCertificateRequired);
        const signer_supported = switch (identity.signer.scheme()) {
            quic.tls.auth.signature_scheme_ed25519 => request.supports_ed25519,
            quic.tls.auth.signature_scheme_ecdsa_secp256r1_sha256 => request.supports_ecdsa_p256_sha256,
            quic.tls.auth.signature_scheme_ecdsa_secp384r1_sha384 => request.supports_ecdsa_p384_sha384,
            else => false,
        };
        if (!signer_supported) return peer_failure.rejectTls(error.UnsupportedSignatureScheme);
        try identity.validate();
        try quic.tls.auth.writeClientCertificateWithContext(
            &client_certificate,
            endpoint.allocator,
            identity.certificate_chain,
            request.request_context,
        );
        const client_certificate_transcript_hash =
            transcript.digestAfter(client_certificate.items);
        try quic.tls.auth.writeCertificateVerifyForRole(
            &client_certificate_verify,
            endpoint.allocator,
            identity.signer,
            client_certificate_transcript_hash.bytes(),
            .client,
        );
    }
    var client_transcript = transcript;
    client_transcript.append(client_certificate.items);
    client_transcript.append(client_certificate_verify.items);
    const client_finished_hash = client_transcript.digest();
    const client_verify = try quic.tls_client_hello
        .computeFinishedVerifyDataForHash(
        handshake.client_handshake_traffic_secret,
        client_finished_hash,
    );
    var client_finished_storage: [
        quic.tls_client_hello
            .max_finished_message_len
    ]u8 = undefined;
    const client_finished = try quic.tls_client_hello.writeFinishedInto(
        &client_finished_storage,
        client_verify,
    );
    client_transcript.append(client_finished);
    const complete_transcript_hash = client_transcript.digest();
    var client_flight_owned: std.ArrayList(u8) = .empty;
    defer client_flight_owned.deinit(endpoint.allocator);
    const client_flight = if (client_certificate.items.len == 0 and
        client_certificate_verify.items.len == 0)
        client_finished
    else flight: {
        const flight_len = try clientFlightLen(
            client_certificate.items.len,
            client_certificate_verify.items.len,
            client_finished.len,
        );
        try client_flight_owned.ensureTotalCapacityPrecise(
            endpoint.allocator,
            flight_len,
        );
        client_flight_owned.appendSliceAssumeCapacity(
            client_certificate.items,
        );
        client_flight_owned.appendSliceAssumeCapacity(
            client_certificate_verify.items,
        );
        client_flight_owned.appendSliceAssumeCapacity(client_finished);
        break :flight client_flight_owned.items;
    };
    var client_handshake_send = retransmit.HandshakeFlight{
        .endpoint = endpoint,
        .peer = server_initial.from,
        .keys = handshake.client_quic,
        .options = .{
            .version = options.version.wireValue(),
            .destination_connection_id = server_initial.packet.source_connection_id,
            .source_connection_id = options.local_connection_id,
            .packet_number = client_handshake_packet_number,
            .fixed_bit = try fixed_bit.randomValue(
                endpoint.io,
                peer_transport_parameters.grease_quic_bit,
            ),
            .crypto_data = client_flight,
            .max_crypto_frame_data_len = options.max_crypto_frame_data_len,
        },
    };
    retransmit.sendWithoutResponse(
        options.handshake_recovery,
        &client_handshake_send,
        retransmit.HandshakeFlight.send,
    ) catch |err| {
        // Protection may have retired a packet-number range before the socket
        // failed. Preserve the first unused number so a close cannot reuse a
        // protected nonce.
        peer_failure.next_packet_number =
            client_handshake_send.next_packet_number;
        return err;
    };
    // A CONNECTION_CLOSE after this point must use a Handshake packet number
    // beyond every protected packet in the client flight.
    peer_failure.next_packet_number = client_handshake_send.next_packet_number;

    if (options.keylog) |keylog| {
        try keylog.writeApplicationSecrets(
            client_random,
            application.client_application_traffic_secret.bytes(),
            application.server_application_traffic_secret.bytes(),
        );
    }
    return establishedConnection(
        endpoint,
        options.version,
        server_initial.from,
        application.server_quic,
        application.client_quic,
        options.local_connection_id,
        server_initial.packet.source_connection_id,
        sampledSpinBitConfig(
            options.initial_one_rtt_config,
            client_random,
        ),
        .client,
        local_transport_parameters,
        peer_transport_parameters,
        encrypted_extensions.alpn,
        parsed_server.cipher_suite,
        retry_processed,
        established_certificate_compression,
        resumed,
        early_data_status,
        try quic.tls.key_schedule.deriveResumptionMasterSecretFor(
            application.master_secret,
            complete_transcript_hash,
        ),
        try quic.tls.key_schedule.deriveExporterMasterSecretFor(
            application.master_secret,
            application_transcript_hash,
        ),
        if (peer_certificate) |certificate| certificate.entries else &.{},
        reader,
        .{ .client = .{
            .coalesced_one_rtt = if (server_handshake.coalesced_one_rtt) |bytes|
                .{
                    .from = server_handshake.from,
                    .bytes = bytes,
                    .ecn = server_handshake.coalesced_one_rtt_ecn,
                }
            else
                null,
            .sent_early_data = if (options.early_data) |early_data|
                .{
                    .protected_packet_count = protected_early_data_packet_count,
                    .sent_packet_numbers = sent_early_data_packet_numbers[0..sent_early_data_packet_count],
                    .sent_datagram_size = sent_early_data_packet_len,
                    .frames = early_data.frames,
                }
            else
                null,
        } },
    );
}

pub fn accept(endpoint: *quic.runtime.Endpoint, options: ServerOptions) Error!EstablishedConnection {
    return acceptInternal(
        endpoint,
        .fromEndpoint(endpoint),
        null,
        options,
    );
}

/// Accept a server connection before one caller-owned awake-clock deadline.
/// The unchanged timestamp covers the first Initial, Retry, fragmented Initial
/// CRYPTO, optional standalone 0-RTT, and every active/passive TLS flight.
pub fn acceptWithDeadline(
    endpoint: *quic.runtime.Endpoint,
    options: ServerOptions,
    deadline: std.Io.Clock.Timestamp,
) AcceptTimeoutError!EstablishedConnection {
    return acceptInternal(
        endpoint,
        .fromEndpoint(endpoint),
        null,
        try serverOptionsBefore(endpoint.io, options, deadline),
    );
}

pub fn acceptWithTimeout(
    endpoint: *quic.runtime.Endpoint,
    options: ServerOptions,
    timeout: std.Io.Duration,
) AcceptTimeoutError!EstablishedConnection {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return acceptWithDeadline(
        endpoint,
        options,
        .fromNow(endpoint.io, .{ .raw = timeout, .clock = .awake }),
    );
}

/// Continue a server handshake from an Initial already received by the sole
/// endpoint dispatcher. Ownership of `initial_datagram` is consumed on every
/// return path. Subsequent handshake packets still use the endpoint receive
/// path; a fully concurrent server supplies those through the pending-handshake
/// inbox layer rather than running this blocking helper in parallel.
pub fn acceptFromInitial(
    endpoint: *quic.runtime.Endpoint,
    initial_datagram: quic.runtime.OwnedBytes,
    options: ServerOptions,
) Error!EstablishedConnection {
    return acceptInternal(
        endpoint,
        .fromEndpoint(endpoint),
        initial_datagram,
        options,
    );
}

pub fn acceptFromInitialWithDeadline(
    endpoint: *quic.runtime.Endpoint,
    initial_datagram: quic.runtime.OwnedBytes,
    options: ServerOptions,
    deadline: std.Io.Clock.Timestamp,
) AcceptTimeoutError!EstablishedConnection {
    var owned = initial_datagram;
    const bounded = serverOptionsBefore(endpoint.io, options, deadline) catch |err|
        {
            owned.deinit(endpoint.allocator);
            return err;
        };
    return acceptInternal(
        endpoint,
        .fromEndpoint(endpoint),
        owned,
        bounded,
    );
}

pub fn acceptFromInitialWithTimeout(
    endpoint: *quic.runtime.Endpoint,
    initial_datagram: quic.runtime.OwnedBytes,
    options: ServerOptions,
    timeout: std.Io.Duration,
) AcceptTimeoutError!EstablishedConnection {
    if (timeout.nanoseconds <= 0) {
        var owned = initial_datagram;
        owned.deinit(endpoint.allocator);
        return error.Timeout;
    }
    return acceptFromInitialWithDeadline(
        endpoint,
        initial_datagram,
        options,
        .fromNow(endpoint.io, .{ .raw = timeout, .clock = .awake }),
    );
}

/// Dispatcher-owned variant that takes the first Initial directly and obtains
/// all later packets from the supplied pending-handshake inbox/source.
pub fn acceptFromInitialSource(
    endpoint: *quic.runtime.Endpoint,
    source: quic.runtime.DatagramSource,
    initial_datagram: quic.runtime.OwnedBytes,
    options: ServerOptions,
) Error!EstablishedConnection {
    return acceptInternal(endpoint, source, initial_datagram, options);
}

pub fn acceptFromInitialSourceWithDeadline(
    endpoint: *quic.runtime.Endpoint,
    source: quic.runtime.DatagramSource,
    initial_datagram: quic.runtime.OwnedBytes,
    options: ServerOptions,
    deadline: std.Io.Clock.Timestamp,
) AcceptTimeoutError!EstablishedConnection {
    var owned = initial_datagram;
    const bounded = serverOptionsBefore(endpoint.io, options, deadline) catch |err|
        {
            owned.deinit(endpoint.allocator);
            return err;
        };
    return acceptInternal(
        endpoint,
        source,
        owned,
        bounded,
    );
}

pub fn acceptFromInitialSourceWithTimeout(
    endpoint: *quic.runtime.Endpoint,
    source: quic.runtime.DatagramSource,
    initial_datagram: quic.runtime.OwnedBytes,
    options: ServerOptions,
    timeout: std.Io.Duration,
) AcceptTimeoutError!EstablishedConnection {
    if (timeout.nanoseconds <= 0) {
        var owned = initial_datagram;
        owned.deinit(endpoint.allocator);
        return error.Timeout;
    }
    return acceptFromInitialSourceWithDeadline(
        endpoint,
        source,
        initial_datagram,
        options,
        .fromNow(endpoint.io, .{ .raw = timeout, .clock = .awake }),
    );
}

fn serverOptionsBefore(
    io: std.Io,
    options: ServerOptions,
    deadline: std.Io.Clock.Timestamp,
) AcceptTimeoutError!ServerOptions {
    if (deadline.clock != .awake or
        deadline.durationFromNow(io).raw.nanoseconds <= 0)
    {
        return error.Timeout;
    }
    var bounded = options;
    if (bounded.handshake_recovery.deadline) |configured| {
        if (configured.clock != .awake) {
            return error.InvalidHandshakeRecovery;
        }
        if (std.Io.Clock.Timestamp.compare(configured, .lt, deadline)) {
            return bounded;
        }
    }
    bounded.handshake_recovery.deadline = deadline;
    return bounded;
}

pub const testing = struct {
    pub fn serverOptionsBeforeForTest(
        io: std.Io,
        options: ServerOptions,
        deadline: std.Io.Clock.Timestamp,
    ) AcceptTimeoutError!ServerOptions {
        return serverOptionsBefore(io, options, deadline);
    }

    pub fn clientOptionsBeforeForTest(
        io: std.Io,
        options: ClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ClientOptions {
        return clientOptionsBefore(io, options, deadline);
    }

    pub fn validateAddressTokenForInitialForTest(
        allocator: std.mem.Allocator,
        token: []const u8,
        original_destination_connection_id: []const u8,
        options: ServerOptions,
    ) Error!void {
        _ = try validateAddressTokenForInitial(
            allocator,
            token,
            original_destination_connection_id,
            options,
        );
    }
};

fn acceptInternal(
    endpoint: *quic.runtime.Endpoint,
    upstream_source: quic.runtime.DatagramSource,
    first_datagram: ?quic.runtime.OwnedBytes,
    options: ServerOptions,
) Error!EstablishedConnection {
    if (options.failed_close_out) |output| output.* = null;
    if (options.failed_close_lifetime_out) |output| output.* = @import("handshake/closing.zig").lifetimeNs(options.handshake_recovery.initial_pto_ms);
    var reader = datagram_reader.Reader.init(
        endpoint.allocator,
        upstream_source,
    );
    defer reader.deinit();
    const source = reader.datagramSource();
    var owned_first = first_datagram;
    defer if (owned_first) |*datagram| datagram.deinit(endpoint.allocator);
    try validateConfiguredVersions(options.version, options.available_versions);
    try options.handshake_recovery.validate();
    if (options.psk) |psk| {
        if (psk.identity.len == 0 or psk.lifetime_seconds == 0) {
            return error.InvalidClientHello;
        }
        const configured_secret = psk.secret_value orelse
            quic.tls.secret.Secret.fromSha256(psk.secret);
        if (configured_secret.hash != psk.cipher_suite.hash()) {
            return error.InvalidClientHello;
        }
    }
    if ((options.retry_original_destination_connection_id.len == 0) != (options.retry_source_connection_id.len == 0)) {
        return error.InvalidPacket;
    }
    if (options.retry != null and
        options.retry_source_connection_id.len != 0)
    {
        return error.InvalidPacket;
    }

    var effective_options = options;
    var owned_retry_original_destination_connection_id: ?[]u8 = null;
    defer if (owned_retry_original_destination_connection_id) |cid|
        endpoint.allocator.free(cid);
    var owned_retry_source_connection_id: ?[]u8 = null;
    defer if (owned_retry_source_connection_id) |cid|
        endpoint.allocator.free(cid);
    var automatic_retry_secrets: [1]quic.address_validation_token.Secret = undefined;
    const accept_zero_fixed_bit = try configuredGreaseQuicBit(
        endpoint.allocator,
        options.transport_parameters,
        options.local_transport_parameters,
        .server,
    );

    var client_initial = if (owned_first) |datagram| blk: {
        const opened = openClientInitialDatagram(
            endpoint,
            source,
            datagram,
            0,
            options.max_crypto_buffer,
            options.retry_source_connection_id,
            options.version,
            accept_zero_fixed_bit,
            options.handshake_recovery.deadline,
        ) catch |err| switch (err) {
            error.DiscardedInitialPacket => {
                var discarded = datagram;
                discarded.deinit(endpoint.allocator);
                owned_first = null;
                break :blk try receiveClientInitial(
                    endpoint,
                    source,
                    0,
                    options.max_crypto_buffer,
                    options.retry_source_connection_id,
                    options.version,
                    options.available_versions,
                    accept_zero_fixed_bit,
                    options.handshake_recovery.deadline,
                );
            },
            else => |other| return other,
        };
        owned_first = null;
        var consumed = datagram;
        consumed.deinit(endpoint.allocator);
        break :blk opened;
    } else try receiveClientInitial(
        endpoint,
        source,
        0,
        options.max_crypto_buffer,
        options.retry_source_connection_id,
        options.version,
        options.available_versions,
        accept_zero_fixed_bit,
        options.handshake_recovery.deadline,
    );
    if (options.retry) |policy| {
        var versioned_policy = policy;
        versioned_policy.version = options.version;
        const odcid = try endpoint.allocator.dupe(
            u8,
            client_initial.packet.destination_connection_id,
        );
        errdefer endpoint.allocator.free(odcid);
        const rscid = if (policy.source_connection_id.len != 0)
            try endpoint.allocator.dupe(
                u8,
                policy.source_connection_id,
            )
        else
            try endpoint.allocator.dupe(
                u8,
                options.local_connection_id,
            );
        errdefer endpoint.allocator.free(rscid);
        var retry_storage: [quic.retry_flow.max_datagram_len]u8 = undefined;
        const prepared = retry.prepareInto(
            &retry_storage,
            endpoint.io,
            versioned_policy,
            rscid,
            odcid,
            client_initial.packet.source_connection_id,
        ) catch |err| switch (err) {
            error.InvalidToken,
            error.TokenExpired,
            error.TokenNotYetValid,
            error.TokenReplay,
            error.RetryAlreadyProcessed,
            error.InitialAlreadyProcessed,
            => return error.InvalidPacket,
            else => |other| return @errorCast(other),
        };
        try endpoint.sendBytes(client_initial.from, prepared.datagram);
        client_initial.deinit(endpoint.allocator);

        // A first-flight 0-RTT packet can already be queued when Retry is
        // transmitted. Ignore non-Initial packets until the client responds
        // with an Initial protected by the Retry SCID-derived keys.
        client_initial = try receiveRetriedClientInitial(
            endpoint,
            source,
            options.max_crypto_buffer,
            rscid,
            options.version,
            accept_zero_fixed_bit,
            options.handshake_recovery.deadline,
        );
        owned_retry_original_destination_connection_id = odcid;
        owned_retry_source_connection_id = rscid;
        effective_options.retry_original_destination_connection_id = odcid;
        effective_options.retry_source_connection_id = rscid;
        automatic_retry_secrets[0] = policy.secret;
        effective_options.address_validation_secrets =
            &automatic_retry_secrets;
        effective_options.address_validation_peer = policy.peer_address;
        effective_options.address_validation_now_ns =
            policy.validation_now_ns orelse policy.issued_ns;
    }
    defer client_initial.deinit(endpoint.allocator);
    const original_destination_connection_id = serverOriginalDestinationConnectionId(
        client_initial.packet.destination_connection_id,
        effective_options,
    );
    const address_validated = try validateAddressTokenForInitial(
        endpoint.allocator,
        client_initial.packet.token,
        original_destination_connection_id,
        effective_options,
    );
    var anti_amplification = retransmit.AntiAmplificationBudget{
        .validated = address_validated,
    };
    anti_amplification.recordReceived(client_initial.bytes_received);

    var peer_failure: failure.State = .{
        .endpoint = endpoint,
        .peer = client_initial.from,
        .packet_type = .initial,
        .keys = client_initial.initial_secrets.server,
        .version = options.version.wireValue(),
        .destination_connection_id = client_initial.packet.source_connection_id,
        .source_connection_id = options.local_connection_id,
        .next_packet_number = options.server_initial_packet_number,
        .anti_amplification = &anti_amplification,
        .closing_out = options.failed_close_out,
        .closing_lifetime_ns = @import("handshake/closing.zig").lifetimeNs(options.handshake_recovery.initial_pto_ms),
    };
    var parsed_client = try peer_failure.guardTls(quic.tls_client_hello.parseClientHello(
        client_initial.crypto_data,
    ));
    defer parsed_client.deinit(endpoint.allocator);
    var automatic_psk_lease: ?quic.resumption.ticket.store.Lease = null;
    defer if (automatic_psk_lease) |*lease| lease.deinit();
    var effective_psk = options.psk;
    const alpn = try peer_failure.guardTls(chooseAlpn(
        options.alpn_protocol,
        parsed_client.alpnProtocols(),
    ));
    const cipher_suite = try peer_failure.guardTls(quic.tls_client_hello.selectCipherSuite(
        parsed_client.cipher_suites,
        options.cipher_suites,
        options.cipher_suite_policy,
    ));
    if (effective_psk == null) {
        if (options.auto_resumption) |automatic| {
            if (parsed_client.psk_offer != null) {
                automatic_psk_lease = try lookupAutomaticServerPsk(
                    client_initial.crypto_data,
                    cipher_suite,
                    automatic,
                );
                if (automatic_psk_lease != null) {
                    const selected = &automatic_psk_lease.?;
                    effective_psk = .{
                        .identity = selected.identity,
                        .secret = selected.secret,
                        .secret_value = selected.secret_value,
                        .age_add = selected.age_add,
                        .issued_at_ms = selected.issued_at_ms,
                        .lifetime_seconds = selected.lifetime_seconds,
                        .now_ms = automatic.now_ms,
                        .age_tolerance_ms = automatic.age_tolerance_ms,
                        .cipher_suite = selected.cipher_suite,
                    };
                }
            }
        }
    }
    if (effective_psk == null) {
        if (options.identity) |identity| {
            const supported = switch (identity.signer.scheme()) {
                quic.tls.auth.signature_scheme_ed25519 => parsed_client.supports_ed25519,
                quic.tls.auth.signature_scheme_ecdsa_secp256r1_sha256 => parsed_client.supports_ecdsa_p256_sha256,
                quic.tls.auth.signature_scheme_ecdsa_secp384r1_sha384 => parsed_client.supports_ecdsa_p384_sha384,
                else => false,
            };
            if (!supported) return peer_failure.rejectTls(error.UnsupportedSignatureScheme);
        }
    }
    const peer_transport_parameters = try peer_failure.guardTransport(quic.parseTransportParametersTyped(
        endpoint.allocator,
        parsed_client.transport_parameters,
        .client,
    ));
    try peer_failure.guardTransport(validateClientTransportParameters(
        peer_transport_parameters,
        client_initial.packet.source_connection_id,
        options.version,
        options.available_versions,
    ));

    const selected_group = try peer_failure.guardTls(quic.tls_client_hello.selectKeyShare(
        parsed_client,
        options.key_exchange_groups,
    ));
    const server_key_exchange = try peer_failure.guardTls(key_exchange.serverRespond(
        endpoint.io,
        selected_group,
        parsed_client.keyShare(selected_group).?,
        .{
            .x25519_secret = options.x25519_secret_key,
            .p256_secret = options.p256_secret_key,
            .p384_secret = options.p384_secret_key,
            .x25519_hybrid_curve_secret = options.x25519_mlkem768_secret_key,
            .x25519_hybrid_encaps_seed = options.x25519_mlkem768_encaps_seed,
            .nist_hybrid = options.nist_hybrid_key_material,
        },
    ));
    const selected_server_share = server_key_exchange.share;
    const legacy_server_public = if (selected_group == .x25519)
        selected_server_share.x25519
    else
        [_]u8{0} ** 32;
    const server_random = try random32(endpoint.io, options.random);
    var shared = server_key_exchange.shared_secret;
    defer shared.wipe();
    var selected_psk: ?quic.tls.secret.Secret = null;
    var selected_psk_identity: ?u16 = null;
    var early_data_accepted = false;
    var early_data_keys: ?quic.zero_rtt.handshake.ClientKeys = null;
    const client_offered_early_data =
        try quic.resumption.tls_psk.clientOfferedEarlyData(
            client_initial.crypto_data,
        );
    if (client_offered_early_data and parsed_client.psk_offer == null) {
        return peer_failure.rejectTls(error.UnexpectedEarlyData);
    }
    if (parsed_client.psk_offer != null) {
        if (effective_psk) |configured_psk| {
            if (try selectServerPsk(
                client_initial.crypto_data,
                cipher_suite,
                configured_psk,
            )) |selection| {
                selected_psk = selection.secret;
                selected_psk_identity = selection.identity_index;
                const early_data_policy = options.early_data;
                if (client_offered_early_data and
                    selection.permitsEarlyData() and
                    effective_options.retry_source_connection_id.len == 0 and
                    early_data_policy != null and
                    early_data_policy.?.accept and
                    configured_psk.cipher_suite == cipher_suite)
                {
                    const replay = early_data_policy.?;
                    const lifetime_ms =
                        @as(u64, configured_psk.lifetime_seconds) *
                        std.time.ms_per_s;
                    const expires_at_ms = std.math.add(
                        u64,
                        configured_psk.issued_at_ms,
                        lifetime_ms,
                    ) catch return error.ExpiredPsk;
                    try replay.replay_filter.checkAndMark(
                        replay.replay_key,
                        configured_psk.now_ms,
                        expires_at_ms,
                    );
                    early_data_keys = try quic.zero_rtt.handshake
                        .clientKeysForSecretAndVersion(
                        options.version.wireValue(),
                        configured_psk.cipher_suite,
                        selection.secret,
                        client_initial.crypto_data,
                    );
                    early_data_accepted = true;
                }
            }
        }
    }
    var pending_early_data: ?quic.zero_rtt.Packet = null;
    defer if (pending_early_data) |*early_data| {
        early_data.deinit(endpoint.allocator);
    };
    if (early_data_accepted) {
        pending_early_data = openClientEarlyData(
            endpoint,
            client_initial.from,
            client_initial.coalesced_tail,
            early_data_keys.?.packet,
            0,
            options.initial_one_rtt_config.max_frames_per_packet,
            client_initial.packet.destination_connection_id,
            client_initial.packet.source_connection_id,
            options.local_transport_parameters.grease_quic_bit,
        ) catch |err| {
            if (err == error.InvalidReservedBits) {
                peer_failure.send(@intFromEnum(quic.TransportErrorCode.protocol_violation), "reserved bits") catch {};
            }
            return err;
        };
        if (pending_early_data == null and
            client_initial.coalesced_tail.len == 0)
        {
            pending_early_data = receiveStandaloneClientEarlyData(
                endpoint,
                source,
                client_initial.from,
                early_data_keys.?.packet,
                0,
                options.initial_one_rtt_config.max_frames_per_packet,
                client_initial.packet.destination_connection_id,
                client_initial.packet.source_connection_id,
                options.local_transport_parameters.grease_quic_bit,
                options.handshake_recovery,
                &anti_amplification,
            ) catch |err| {
                if (err == error.InvalidReservedBits) {
                    peer_failure.send(@intFromEnum(quic.TransportErrorCode.protocol_violation), "reserved bits") catch {};
                }
                return err;
            };
        }
    } else if (client_offered_early_data and
        effective_options.retry_source_connection_id.len != 0)
    {
        // The ClientHello is byte-for-byte identical across Retry and can
        // still carry early_data, but RFC 9001 §4.6 forbids sending another
        // 0-RTT packet. Do not block waiting for a packet that a conforming
        // client must suppress.
        if (client_initial.coalesced_tail.len != 0) {
            return error.InvalidHandshakeFlight;
        }
    } else if (client_offered_early_data) {
        try discardClientEarlyData(
            endpoint,
            source,
            client_initial.from,
            client_initial.coalesced_tail,
            options.version,
            options.local_transport_parameters.grease_quic_bit,
            options.handshake_recovery,
            &anti_amplification,
        );
    } else if (client_initial.coalesced_tail.len != 0) {
        // RFC 9000 requires the first client datagram to be at least 1200
        // bytes. tquic reaches that size with an all-zero suffix outside the
        // Initial packet's encoded Length, while other stacks can coalesce
        // more Initial packets. Preserve the authenticated first packet and
        // tolerate only those two harmless suffix shapes; reject other packet
        // number spaces because accepting undecryptable 0-RTT or Handshake
        // bytes would bypass the state that owns them.
        try validateClientInitialTail(
            client_initial.coalesced_tail,
            options.version,
            accept_zero_fixed_bit,
        );
    }

    var server_hello: std.ArrayList(u8) = .empty;
    defer server_hello.deinit(endpoint.allocator);
    try quic.tls_client_hello.writeServerHello(&server_hello, endpoint.allocator, .{
        .random = server_random,
        .x25519_public_key = legacy_server_public,
        .key_share = selected_server_share,
        .selected_psk_identity = selected_psk_identity,
        .cipher_suite = cipher_suite,
    });
    var transcript = handshake_transcript.Flow.init(
        cipher_suite.hash(),
        client_initial.crypto_data,
        server_hello.items,
    );
    const hs_hash = transcript.digest();
    const handshake = try quic.tls_client_hello
        .deriveRuntimeHandshakeSecretsFromSliceForVersion(
        options.version.wireValue(),
        cipher_suite,
        shared.bytes(),
        hs_hash,
        selected_psk,
    );
    if (options.keylog) |keylog| {
        try keylog.writeHandshakeSecrets(
            parsed_client.random,
            handshake.client_handshake_traffic_secret.bytes(),
            handshake.server_handshake_traffic_secret.bytes(),
        );
    }

    var local_transport_parameters = options.local_transport_parameters;
    var encoded_transport_parameters: std.ArrayList(u8) = .empty;
    defer encoded_transport_parameters.deinit(endpoint.allocator);
    const transport_parameters = try serverTransportParameters(
        endpoint.allocator,
        effective_options,
        endpoint.limits.max_datagram_size,
        original_destination_connection_id,
        effective_options.retry_source_connection_id,
        &local_transport_parameters,
        &encoded_transport_parameters,
    );

    var encrypted_extensions: std.ArrayList(u8) = .empty;
    defer encrypted_extensions.deinit(endpoint.allocator);
    try quic.tls_client_hello.writeEncryptedExtensionsWithEarlyData(
        &encrypted_extensions,
        endpoint.allocator,
        alpn,
        transport_parameters,
        early_data_accepted,
    );
    var server_flight: std.ArrayList(u8) = .empty;
    defer server_flight.deinit(endpoint.allocator);
    try server_flight.appendSlice(endpoint.allocator, encrypted_extensions.items);
    transcript.append(encrypted_extensions.items);
    if (options.client_auth) |client_auth| {
        var certificate_request: std.ArrayList(u8) = .empty;
        defer certificate_request.deinit(endpoint.allocator);
        try quic.tls.client_auth.writeRequest(
            &certificate_request,
            endpoint.allocator,
            &.{},
            client_auth.certificate_authorities,
        );
        try server_flight.appendSlice(
            endpoint.allocator,
            certificate_request.items,
        );
        transcript.append(certificate_request.items);
    }
    if (selected_psk == null and options.identity != null) {
        const identity = options.identity.?;
        try identity.validate();
        var certificate: std.ArrayList(u8) = .empty;
        defer certificate.deinit(endpoint.allocator);
        try quic.tls.auth.writeCertificate(
            &certificate,
            endpoint.allocator,
            identity.certificate_chain,
        );
        // RFC 8879: follow the client's offered algorithm order and emit a
        // CompressedCertificate only when compression saves bytes; the
        // transcript covers the compressed message actually sent.
        const offered = parsed_client.certificateCompressionAlgorithms();
        var compressed_certificate: std.ArrayList(u8) = .empty;
        defer compressed_certificate.deinit(endpoint.allocator);
        var certificate_wire: []const u8 = certificate.items;
        for (offered) |algorithm| {
            if (!algorithm.supported()) continue;
            var enabled = false;
            for (options.certificate_compression_algorithms) |server_algorithm| {
                if (server_algorithm == algorithm) {
                    enabled = true;
                    break;
                }
            }
            if (!enabled) continue;
            var used_prepared = false;
            var prepared_matched = false;
            for (options.prepared_certificate_compression) |prepared| {
                if (prepared.algorithm != algorithm) continue;
                if (!prepared.matchesCertificateMessage(certificate.items)) {
                    continue;
                }
                prepared_matched = true;
                if (!prepared.savesBytes(certificate.items.len)) continue;
                prepared.write(
                    &compressed_certificate,
                    endpoint.allocator,
                ) catch continue;
                certificate_wire = compressed_certificate.items;
                used_prepared = true;
                break;
            }
            if (used_prepared) break;
            // A matching prepared entry is authoritative for this algorithm:
            // callers prepared it once precisely to avoid per-handshake work,
            // and falling back would defeat that reuse.
            if (prepared_matched) continue;
            var prepared = switch (algorithm) {
                .zlib => quic.tls.certificate_compression.Prepared.initZlib(
                    endpoint.allocator,
                    certificate.items,
                    .interactive,
                ) catch continue,
                .brotli => quic.tls.certificate_compression.Prepared.initBrotli(
                    endpoint.allocator,
                    certificate.items,
                    .interactive,
                ) catch continue,
                .zstd => quic.tls.certificate_compression.Prepared.initZstd(
                    endpoint.allocator,
                    certificate.items,
                    .interactive,
                ) catch continue,
                else => continue,
            };
            defer prepared.deinit();
            if (prepared.view().savesBytes(certificate.items.len)) {
                prepared.view().write(
                    &compressed_certificate,
                    endpoint.allocator,
                ) catch continue;
                certificate_wire = compressed_certificate.items;
                break;
            }
        }
        try server_flight.appendSlice(endpoint.allocator, certificate_wire);
        transcript.append(certificate_wire);

        var certificate_verify: std.ArrayList(u8) = .empty;
        defer certificate_verify.deinit(endpoint.allocator);
        const certificate_transcript_hash = transcript.digest();
        try quic.tls.auth.writeCertificateVerify(
            &certificate_verify,
            endpoint.allocator,
            identity.signer,
            certificate_transcript_hash.bytes(),
        );
        try server_flight.appendSlice(
            endpoint.allocator,
            certificate_verify.items,
        );
        transcript.append(certificate_verify.items);
    }
    const server_finished_hash = transcript.digest();
    const server_verify = try quic.tls_client_hello
        .computeFinishedVerifyDataForHash(
        handshake.server_handshake_traffic_secret,
        server_finished_hash,
    );
    const server_finished_offset = server_flight.items.len;
    try quic.tls_client_hello.writeFinishedForHash(
        &server_flight,
        endpoint.allocator,
        server_verify,
    );
    transcript.append(server_flight.items[server_finished_offset..]);
    const application_transcript_hash = transcript.digest();
    var send_context = retransmit.InitialHandshakeFlight{
        .endpoint = endpoint,
        .peer = client_initial.from,
        .initial_keys = client_initial.initial_secrets.server,
        .initial_options = .{
            .initial = .{
                .version = options.version.wireValue(),
                .destination_connection_id = client_initial.packet.source_connection_id,
                .source_connection_id = options.local_connection_id,
                .packet_number = options.server_initial_packet_number,
                .fixed_bit = try fixed_bit.randomValue(
                    endpoint.io,
                    peer_transport_parameters.grease_quic_bit,
                ),
                .crypto_data = server_hello.items,
                .max_crypto_frame_data_len = options.max_crypto_frame_data_len,
                .min_datagram_size = quic.initial_exchange.min_initial_udp_datagram_size,
            },
            .max_datagram_size = endpoint.limits.max_datagram_size,
        },
        .handshake_keys = handshake.server_quic,
        .handshake_options = .{
            .version = options.version.wireValue(),
            .destination_connection_id = client_initial.packet.source_connection_id,
            .source_connection_id = options.local_connection_id,
            .packet_number = options.server_handshake_packet_number,
            .fixed_bit = try fixed_bit.randomValue(
                endpoint.io,
                peer_transport_parameters.grease_quic_bit,
            ),
            .crypto_data = server_flight.items,
            .max_crypto_frame_data_len = options.max_crypto_frame_data_len,
        },
        .anti_amplification = anti_amplification,
    };
    var client_handshake_datagram = try retransmit
        .sendAndReceiveMatchingFromObserved(
        endpoint,
        source,
        options.handshake_recovery,
        &send_context,
        retransmit.InitialHandshakeFlight.send,
        containsHandshakePacket,
        retransmit.InitialHandshakeFlight.observeReceived,
    );
    var client_handshake_datagram_owned = true;
    defer if (client_handshake_datagram_owned) {
        client_handshake_datagram.deinit(endpoint.allocator);
    };
    peer_failure.packet_type = .handshake;
    peer_failure.keys = handshake.server_quic;
    peer_failure.next_packet_number = send_context.next_handshake_packet_number;
    peer_failure.anti_amplification = &send_context.anti_amplification;
    peer_failure.closing_lifetime_ns = options.handshake_recovery.timeoutMillis(send_context.last_retransmission) * 3 * std.time.ns_per_ms;
    if (options.failed_close_lifetime_out) |output| output.* = peer_failure.closing_lifetime_ns;
    var client_handshake = receiveClientHandshakeCryptoFromDatagram(
        endpoint,
        source,
        client_initial.from,
        client_handshake_datagram.from,
        client_handshake_datagram.bytes,
        client_handshake_datagram.ecn,
        handshake.client_quic,
        0,
        options.max_crypto_buffer,
        local_transport_parameters.grease_quic_bit,
        options.client_auth != null,
        options.handshake_recovery,
        &send_context.anti_amplification,
    ) catch |err| {
        if (err == error.InvalidReservedBits) {
            peer_failure.send(@intFromEnum(quic.TransportErrorCode.protocol_violation), "reserved bits") catch {};
        }
        return err;
    };
    client_handshake_datagram.deinit(endpoint.allocator);
    client_handshake_datagram_owned = false;
    defer client_handshake.deinit(endpoint.allocator);
    const client_flight = try peer_failure.guardTls(splitClientFlight(
        client_handshake.crypto_data,
        options.client_auth != null,
    ));
    var peer_certificate: ?quic.tls.auth.ParsedCertificate = null;
    defer if (peer_certificate) |*certificate| {
        certificate.deinit(endpoint.allocator);
    };
    if (options.client_auth) |client_auth| {
        peer_certificate = try peer_failure.guardTls(quic.tls.auth.parseCertificateWithContext(
            endpoint.allocator,
            client_flight.certificate.?,
            &.{},
        ));
        try peer_failure.guardTls(client_auth.verifier.verifyTrust(
            null,
            peer_certificate.?.entries,
        ));
        const certificate_verify =
            try peer_failure.guardTls(quic.tls.auth.parseCertificateVerify(
                client_flight.certificate_verify.?,
            ));
        const client_certificate_transcript_hash =
            transcript.digestAfter(client_flight.certificate.?);
        try peer_failure.guardTls(quic.tls.auth.verifyCertificateVerifyForRole(
            peer_certificate.?.entries[0],
            certificate_verify,
            client_certificate_transcript_hash.bytes(),
            .client,
        ));
    }
    const client_verify = try peer_failure.guardTls(quic.tls_client_hello.parseFinishedForHash(
        client_flight.finished,
        cipher_suite.hash(),
    ));
    transcript.append(client_flight.before_finished);
    const client_finished_hash = transcript.digest();
    try peer_failure.guardTls(quic.tls_client_hello.verifyFinishedForHash(
        handshake.client_handshake_traffic_secret,
        client_finished_hash,
        client_verify,
    ));
    transcript.append(client_flight.finished);
    const complete_transcript_hash = transcript.digest();

    const application = try quic.tls_client_hello
        .deriveRuntimeApplicationSecretsForVersion(
        options.version.wireValue(),
        cipher_suite,
        handshake.handshake_secret,
        application_transcript_hash,
    );
    if (options.keylog) |keylog| {
        try keylog.writeApplicationSecrets(
            parsed_client.random,
            application.client_application_traffic_secret.bytes(),
            application.server_application_traffic_secret.bytes(),
        );
    }
    return establishedConnection(
        endpoint,
        options.version,
        client_initial.from,
        application.client_quic,
        application.server_quic,
        options.local_connection_id,
        client_initial.packet.source_connection_id,
        sampledSpinBitConfig(
            options.initial_one_rtt_config,
            server_random,
        ),
        .server,
        local_transport_parameters,
        peer_transport_parameters,
        alpn,
        cipher_suite,
        effective_options.retry_source_connection_id.len != 0,
        null,
        selected_psk != null,
        if (early_data_accepted) .accepted else if (client_offered_early_data) .rejected else .not_offered,
        try quic.tls.key_schedule.deriveResumptionMasterSecretFor(
            application.master_secret,
            complete_transcript_hash,
        ),
        try quic.tls.key_schedule.deriveExporterMasterSecretFor(
            application.master_secret,
            application_transcript_hash,
        ),
        if (peer_certificate) |certificate| certificate.entries else &.{},
        &reader,
        .{ .server = .{
            .coalesced_one_rtt = if (client_handshake.coalesced_one_rtt) |bytes|
                .{
                    .from = client_handshake.from,
                    .bytes = bytes,
                    .ecn = client_handshake.coalesced_one_rtt_ecn,
                }
            else
                null,
            .received_early_data = if (pending_early_data) |*early_data|
                .{
                    .packet_number = early_data.packet.packet_number,
                    .frames = early_data.frames,
                }
            else
                null,
        } },
    );
}

pub fn containsHandshakePacket(datagram: []const u8) bool {
    var tail = datagram;
    return (nextHandshakePacketFromCoalescedTail(
        &tail,
        true,
    ) catch return false) != null;
}

pub fn openClientHandshakeCryptoFromDatagram(
    endpoint: *quic.runtime.Endpoint,
    from: net.IpAddress,
    datagram: []const u8,
    datagram_ecn: quic.packet_space.EcnCodepoint,
    keys: quic.protection.PacketProtectionKeys,
    expected_packet_number: u64,
    max_crypto_buffer: usize,
    allow_zero_fixed_bit: bool,
    require_client_certificate: bool,
    anti_amplification: ?*retransmit.AntiAmplificationBudget,
) Error!quic.initial_exchange.ReceivedHandshakeCrypto {
    var reassembler = quic.crypto_stream.Reassembler.init(
        endpoint.allocator,
        max_crypto_buffer,
    );
    defer reassembler.deinit();
    var first_packet: ?quic.protection.OpenedHandshakePacket = null;
    errdefer if (first_packet) |*packet| {
        packet.deinit(endpoint.allocator);
    };
    var tail = datagram;
    var next_expected = expected_packet_number;
    while (true) {
        const packet = (nextHandshakePacketFromCoalescedTail(
            &tail,
            allow_zero_fixed_bit,
        ) catch |err| {
            if (isDiscardableLongHeaderParseError(err)) {
                return error.MissingCryptoFrame;
            }
            return err;
        }) orelse break;
        var opened = quic.protection.openHandshakePacketWithFixedBitPolicy(
            endpoint.allocator,
            keys,
            packet,
            next_expected,
            allow_zero_fixed_bit,
        ) catch |err| {
            if (quic.protection.isUnauthenticatedOpenError(err)) continue;
            return err;
        };
        var opened_owned = true;
        errdefer if (opened_owned) opened.deinit(endpoint.allocator);
        next_expected = opened.packet_number + 1;
        quic.initial_exchange.insertCryptoPayload(
            endpoint.allocator,
            &reassembler,
            opened.payload,
            .handshake,
        ) catch |err| switch (err) {
            error.MissingCryptoFrame => {
                // An authenticated ACK/PADDING-only Handshake packet still
                // proves return routability even though it carries no TLS
                // bytes for this reassembler.
                if (anti_amplification) |budget| budget.validate();
                opened.deinit(endpoint.allocator);
                opened_owned = false;
                continue;
            },
            else => |other| return other,
        };
        if (anti_amplification) |budget| budget.validate();
        if (first_packet == null) {
            first_packet = opened;
            opened_owned = false;
        } else {
            opened.deinit(endpoint.allocator);
            opened_owned = false;
        }
        if (splitClientFlight(
            reassembler.available(),
            require_client_certificate,
        )) |_| {
            const crypto_data = try endpoint.allocator.dupe(
                u8,
                reassembler.available(),
            );
            errdefer endpoint.allocator.free(crypto_data);
            const one_rtt_tail = try coalescedOneRttTail(
                datagram,
                allow_zero_fixed_bit,
            );
            const coalesced_one_rtt = if (one_rtt_tail.len == 0)
                null
            else
                try endpoint.allocator.dupe(u8, one_rtt_tail);
            errdefer if (coalesced_one_rtt) |retained| {
                endpoint.allocator.free(retained);
            };
            const result = quic.initial_exchange.ReceivedHandshakeCrypto{
                .from = from,
                .packet = first_packet.?,
                .crypto_data = crypto_data,
                .coalesced_one_rtt = coalesced_one_rtt,
                .coalesced_one_rtt_ecn = datagram_ecn,
            };
            first_packet = null;
            return result;
        } else |err| switch (err) {
            error.InvalidHandshakeFlight => continue,
            else => |other| return other,
        }
    }
    return error.MissingCryptoFrame;
}

pub fn receiveClientHandshakeCryptoFromDatagram(
    endpoint: *quic.runtime.Endpoint,
    source: quic.runtime.DatagramSource,
    expected_from: net.IpAddress,
    first_from: net.IpAddress,
    first_datagram: []const u8,
    first_ecn: quic.packet_space.EcnCodepoint,
    keys: quic.protection.PacketProtectionKeys,
    expected_packet_number: u64,
    max_crypto_buffer: usize,
    allow_zero_fixed_bit: bool,
    require_client_certificate: bool,
    recovery: retransmit.Config,
    anti_amplification: *retransmit.AntiAmplificationBudget,
) Error!quic.initial_exchange.ReceivedHandshakeCrypto {
    // A client Certificate flight can span several MTU-bounded packets. Keep
    // one reassembler across datagrams instead of requiring the complete TLS
    // flight in the first datagram.
    var reassembler = quic.crypto_stream.Reassembler.init(
        endpoint.allocator,
        max_crypto_buffer,
    );
    defer reassembler.deinit();
    var first_packet: ?quic.protection.OpenedHandshakePacket = null;
    errdefer if (first_packet) |*packet| packet.deinit(endpoint.allocator);

    var next_from = first_from;
    var next_bytes = first_datagram;
    var next_ecn = first_ecn;
    var owned_datagram: ?quic.runtime.OwnedBytes = null;
    defer if (owned_datagram) |*datagram| {
        datagram.deinit(endpoint.allocator);
    };
    const deadline = passiveHandshakeTimeout(endpoint.io, recovery);
    var next_expected = expected_packet_number;

    while (true) {
        if (next_from.eql(&expected_from)) {
            var tail = next_bytes;
            while (true) {
                const packet = (nextHandshakePacketFromCoalescedTail(
                    &tail,
                    allow_zero_fixed_bit,
                ) catch |err| {
                    if (isDiscardableLongHeaderParseError(err)) break;
                    return err;
                }) orelse break;
                var opened = quic.protection.openHandshakePacketWithFixedBitPolicy(
                    endpoint.allocator,
                    keys,
                    packet,
                    next_expected,
                    allow_zero_fixed_bit,
                ) catch |err| {
                    if (quic.protection.isUnauthenticatedOpenError(err)) continue;
                    return err;
                };
                var opened_owned = true;
                errdefer if (opened_owned) opened.deinit(endpoint.allocator);
                next_expected = opened.packet_number + 1;
                quic.initial_exchange.insertCryptoPayload(
                    endpoint.allocator,
                    &reassembler,
                    opened.payload,
                    .handshake,
                ) catch |err| switch (err) {
                    error.MissingCryptoFrame => {
                        // An authenticated ACK/PADDING-only Handshake packet
                        // still proves return routability.
                        anti_amplification.validate();
                        opened.deinit(endpoint.allocator);
                        opened_owned = false;
                        continue;
                    },
                    else => |other| return other,
                };
                anti_amplification.validate();
                if (first_packet == null) {
                    first_packet = opened;
                    opened_owned = false;
                } else {
                    opened.deinit(endpoint.allocator);
                    opened_owned = false;
                }
                if (splitClientFlight(
                    reassembler.available(),
                    require_client_certificate,
                )) |_| {
                    const crypto_data = try endpoint.allocator.dupe(
                        u8,
                        reassembler.available(),
                    );
                    errdefer endpoint.allocator.free(crypto_data);
                    const one_rtt_tail = try coalescedOneRttTail(
                        next_bytes,
                        allow_zero_fixed_bit,
                    );
                    const coalesced_one_rtt = if (one_rtt_tail.len == 0)
                        null
                    else
                        try endpoint.allocator.dupe(u8, one_rtt_tail);
                    errdefer if (coalesced_one_rtt) |retained| {
                        endpoint.allocator.free(retained);
                    };
                    const result = quic.initial_exchange.ReceivedHandshakeCrypto{
                        .from = next_from,
                        .packet = first_packet.?,
                        .crypto_data = crypto_data,
                        .coalesced_one_rtt = coalesced_one_rtt,
                        .coalesced_one_rtt_ecn = next_ecn,
                    };
                    first_packet = null;
                    return result;
                } else |err| switch (err) {
                    error.InvalidHandshakeFlight => {},
                    else => |other| return other,
                }
            }
        }
        if (owned_datagram) |*datagram| {
            datagram.deinit(endpoint.allocator);
            owned_datagram = null;
        }
        owned_datagram = source.receiveTimeout(deadline) catch |receive_err|
            switch (receive_err) {
                error.Timeout => return error.HandshakeTimeout,
                error.ConcurrencyUnavailable => return error.HandshakeReceiveFailed,
                else => |other| return @errorCast(other),
            };
        if (owned_datagram.?.from.eql(&expected_from)) {
            anti_amplification.recordReceived(owned_datagram.?.bytes.len);
        }
        next_from = owned_datagram.?.from;
        next_bytes = owned_datagram.?.bytes;
        next_ecn = owned_datagram.?.ecn;
    }
}

fn coalescedOneRttTail(
    bytes: []const u8,
    allow_zero_fixed_bit: bool,
) Error![]const u8 {
    var tail = bytes;
    // Long-header packets carry an explicit length and can be skipped. The
    // first short header consumes the rest of the UDP datagram by definition.
    while (tail.len != 0 and (tail[0] & 0x80) != 0) {
        const info = try quic.protection
            .peekProtectedLongPacketInfoWithFixedBitPolicy(
            tail,
            allow_zero_fixed_bit,
        );
        tail = tail[info.len..];
    }
    return tail;
}

fn serverOriginalDestinationConnectionId(received_destination_connection_id: []const u8, options: ServerOptions) []const u8 {
    if (options.retry_original_destination_connection_id.len != 0) return options.retry_original_destination_connection_id;
    return received_destination_connection_id;
}

fn validateAddressTokenForInitial(
    allocator: std.mem.Allocator,
    token: []const u8,
    original_destination_connection_id: []const u8,
    options: ServerOptions,
) Error!bool {
    if (token.len == 0) {
        if (options.retry_source_connection_id.len != 0) return error.InvalidPacket;
        return false;
    }
    if (options.retry_source_connection_id.len != 0) {
        if (options.retry_original_destination_connection_id.len == 0 or
            options.address_validation_secrets.len == 0 or
            options.address_validation_peer.len == 0) return error.InvalidPacket;
        _ = quic.address_validation_token.validateRetryAnySecret(
            allocator,
            options.address_validation_secrets,
            options.version,
            options.address_validation_now_ns,
            options.address_validation_peer,
            original_destination_connection_id,
            options.retry_source_connection_id,
            token,
        ) catch return error.InvalidPacket;
        try rememberValidatedAddressToken(token, options);
        return true;
    }
    if (options.address_validation_secrets.len == 0 or
        options.address_validation_peer.len == 0)
    {
        // A configured replay gate is an explicit request to validate and
        // consume tokens. Silently accepting one without authentication
        // material would bypass the security policy the caller opted into.
        if (options.address_validation_replay_filter != null) {
            return error.InvalidPacket;
        }
        return false;
    }
    _ = quic.address_validation_token.validateAnySecret(
        options.address_validation_secrets,
        .new_token,
        options.version,
        options.address_validation_now_ns,
        options.address_validation_peer,
        token,
    ) catch return error.InvalidPacket;
    try rememberValidatedAddressToken(token, options);
    return true;
}

fn rememberValidatedAddressToken(
    token: []const u8,
    options: ServerOptions,
) Error!void {
    const replay_filter = options.address_validation_replay_filter orelse return;
    // Authentication, lifetime, address, and (for Retry) exact CID binding
    // have already succeeded. Keep the atomic replay decision immediately
    // before TLS parsing/server flight construction, and retain the existing
    // public InvalidPacket surface for both duplicates and filter failures.
    replay_filter.rememberValidated(token) catch return error.InvalidPacket;
}

const ReceivedClientInitial = struct {
    from: net.IpAddress,
    packet: quic.protection.OpenedInitialPacket,
    crypto_data: []u8,
    initial_secrets: quic.protection.InitialSecrets,
    coalesced_tail: []u8,
    bytes_received: usize,

    fn deinit(self: *ReceivedClientInitial, allocator: std.mem.Allocator) void {
        self.packet.deinit(allocator);
        allocator.free(self.crypto_data);
        allocator.free(self.coalesced_tail);
        self.* = undefined;
    }
};

fn receiveClientInitial(
    endpoint: *quic.runtime.Endpoint,
    source: quic.runtime.DatagramSource,
    expected_packet_number: u64,
    max_crypto_buffer: usize,
    retry_destination_connection_id: []const u8,
    version: quic.Version,
    available_versions: []const quic.Version,
    allow_zero_fixed_bit: bool,
    caller_deadline: ?std.Io.Clock.Timestamp,
) Error!ReceivedClientInitial {
    const supported_wire_versions = try endpoint.allocator.alloc(
        u32,
        available_versions.len,
    );
    defer endpoint.allocator.free(supported_wire_versions);
    for (available_versions, supported_wire_versions) |available, *wire| {
        wire.* = available.wireValue();
    }
    // The ordinary server accept remains unbounded before the first Initial.
    // A caller-owned deadline, however, starts at the public accept entry and
    // must include this wait rather than taking effect only after peer traffic
    // has created retransmission state.
    while (true) {
        var datagram = try receiveFromSourceBefore(source, caller_deadline);
        defer datagram.deinit(endpoint.allocator);
        if (try endpoint.sendVersionNegotiationIfUnsupported(
            datagram.from,
            datagram.bytes,
            supported_wire_versions,
        )) continue;
        return openClientInitialDatagram(
            endpoint,
            source,
            datagram,
            expected_packet_number,
            max_crypto_buffer,
            retry_destination_connection_id,
            version,
            allow_zero_fixed_bit,
            caller_deadline,
        ) catch |err| switch (err) {
            error.DiscardedInitialPacket => continue,
            else => |other| return other,
        };
    }
}

fn openClientInitialDatagram(
    endpoint: *quic.runtime.Endpoint,
    source: quic.runtime.DatagramSource,
    datagram: quic.runtime.OwnedBytes,
    expected_packet_number: u64,
    max_crypto_buffer: usize,
    retry_destination_connection_id: []const u8,
    version: quic.Version,
    allow_zero_fixed_bit: bool,
    caller_deadline: ?std.Io.Clock.Timestamp,
) Error!ReceivedClientInitial {
    if (datagram.bytes.len < quic.initial_exchange.min_initial_udp_datagram_size) {
        return error.DiscardedInitialPacket;
    }

    const header = quic.LongHeader.parseWithFixedBitPolicy(
        datagram.bytes,
        allow_zero_fixed_bit,
    ) catch |err| {
        if (isDiscardableLongHeaderParseError(err)) {
            return error.DiscardedInitialPacket;
        }
        return err;
    };
    if (header.packet_type != .initial) return error.DiscardedInitialPacket;
    if (retry_destination_connection_id.len == 0) {
        // RFC 9000 Section 7.2 requires a first client Initial to use a random
        // Destination Connection ID of at least 8 bytes.  A Retry follow-up is
        // different: its DCID is the server-chosen Retry SCID, which can be
        // shorter, so the accept path below validates exact equality instead.
        if (header.destination_connection_id.len < 8) {
            return error.DiscardedInitialPacket;
        }
    } else if (!std.mem.eql(u8, header.destination_connection_id, retry_destination_connection_id)) {
        return error.DiscardedInitialPacket;
    }

    if (header.version != version.wireValue()) return error.DiscardedInitialPacket;
    const initial_secrets = try quic.protection.deriveInitialSecretsForVersion(version.wireValue(), header.destination_connection_id);
    const initial_info =
        quic.protection.peekProtectedLongPacketInfoWithFixedBitPolicy(
            datagram.bytes,
            allow_zero_fixed_bit,
        ) catch |err| {
            if (isDiscardableLongHeaderParseError(err)) {
                return error.DiscardedInitialPacket;
            }
            return err;
        };
    if (initial_info.packet_type != .initial) {
        return error.DiscardedInitialPacket;
    }
    var flight = try quic.initial_exchange.openInitialCryptoFlightFrom(
        endpoint,
        source,
        datagram.from,
        datagram.bytes[0..initial_info.len],
        initial_secrets.client,
        .{
            .expected_packet_number = expected_packet_number,
            .max_crypto_buffer = max_crypto_buffer,
            .min_datagram_size = quic.initial_exchange.min_initial_udp_datagram_size,
            .first_datagram_size_validated = true,
            .allow_zero_fixed_bit = allow_zero_fixed_bit,
            .deadline = caller_deadline,
            .discard_invalid_first = true,
        },
    );
    errdefer flight.deinit(endpoint.allocator);
    const coalesced_tail = try endpoint.allocator.dupe(
        u8,
        datagram.bytes[initial_info.len..],
    );
    errdefer endpoint.allocator.free(coalesced_tail);
    return .{
        .from = datagram.from,
        .packet = flight.first_packet,
        .crypto_data = flight.crypto_data,
        .initial_secrets = initial_secrets,
        .coalesced_tail = coalesced_tail,
        .bytes_received = std.math.add(
            usize,
            flight.bytes_received,
            datagram.bytes.len - initial_info.len,
        ) catch std.math.maxInt(usize),
    };
}

fn receiveRetriedClientInitial(
    endpoint: *quic.runtime.Endpoint,
    source: quic.runtime.DatagramSource,
    max_crypto_buffer: usize,
    retry_destination_connection_id: []const u8,
    version: quic.Version,
    allow_zero_fixed_bit: bool,
    caller_deadline: ?std.Io.Clock.Timestamp,
) Error!ReceivedClientInitial {
    while (true) {
        var datagram = try receiveFromSourceBefore(source, caller_deadline);
        defer datagram.deinit(endpoint.allocator);
        if (datagram.bytes.len <
            quic.initial_exchange.min_initial_udp_datagram_size)
        {
            // Standalone 0-RTT is allowed to be smaller than 1200 bytes and
            // belongs to the discarded pre-Retry flight.
            continue;
        }
        const info =
            quic.protection.peekProtectedLongPacketInfoWithFixedBitPolicy(
                datagram.bytes,
                allow_zero_fixed_bit,
            ) catch continue;
        if (info.version != version.wireValue() or
            info.packet_type != .initial or
            !std.mem.eql(
                u8,
                info.destination_connection_id,
                retry_destination_connection_id,
            ))
        {
            continue;
        }
        const initial_secrets =
            try quic.protection.deriveInitialSecretsForVersion(
                version.wireValue(),
                retry_destination_connection_id,
            );
        var flight = quic.initial_exchange.openInitialCryptoFlightFrom(
            endpoint,
            source,
            datagram.from,
            datagram.bytes[0..info.len],
            initial_secrets.client,
            .{
                .expected_packet_number = 0,
                .max_crypto_buffer = max_crypto_buffer,
                .min_datagram_size = quic.initial_exchange.min_initial_udp_datagram_size,
                .first_datagram_size_validated = true,
                .allow_zero_fixed_bit = allow_zero_fixed_bit,
                .discard_invalid_first = true,
            },
        ) catch |err| switch (err) {
            error.DiscardedInitialPacket => continue,
            else => |other| return other,
        };
        errdefer flight.deinit(endpoint.allocator);
        const coalesced_tail = try endpoint.allocator.dupe(
            u8,
            datagram.bytes[info.len..],
        );
        errdefer endpoint.allocator.free(coalesced_tail);
        return .{
            .from = datagram.from,
            .packet = flight.first_packet,
            .crypto_data = flight.crypto_data,
            .initial_secrets = initial_secrets,
            .coalesced_tail = coalesced_tail,
            .bytes_received = std.math.add(
                usize,
                flight.bytes_received,
                datagram.bytes.len - info.len,
            ) catch std.math.maxInt(usize),
        };
    }
}

pub fn receiveServerHandshakeCrypto(
    endpoint: *quic.runtime.Endpoint,
    source: quic.runtime.DatagramSource,
    from: net.IpAddress,
    coalesced_tail: []const u8,
    coalesced_ecn: quic.packet_space.EcnCodepoint,
    handshake_keys: quic.protection.PacketProtectionKeys,
    client_handshake_keys: quic.protection.PacketProtectionKeys,
    next_client_packet_number: *u64,
    expected_packet_number: u64,
    max_crypto_buffer: usize,
    allow_zero_fixed_bit: bool,
    require_certificate: bool,
    recovery: retransmit.Config,
) Error!quic.initial_exchange.ReceivedHandshakeCrypto {
    var reassembler = quic.crypto_stream.Reassembler.init(endpoint.allocator, max_crypto_buffer);
    defer reassembler.deinit();
    var first_packet: ?quic.protection.OpenedHandshakePacket = null;
    errdefer if (first_packet) |*packet| packet.deinit(endpoint.allocator);
    var response_from = from;
    var response_ecn = coalesced_ecn;
    var next_expected = expected_packet_number;
    const passive_deadline = passiveHandshakeTimeout(endpoint.io, recovery);
    var pending_tail = coalesced_tail;
    var pending_tail_storage: ?[]u8 = null;
    defer if (pending_tail_storage) |storage| endpoint.allocator.free(storage);

    while (true) {
        const pending_packet = nextHandshakePacketFromCoalescedTail(
            &pending_tail,
            allow_zero_fixed_bit,
        ) catch |err| blk: {
            if (!isDiscardableLongHeaderParseError(err)) return err;
            pending_tail = &.{};
            break :blk null;
        };
        var owned_datagram: ?quic.runtime.OwnedBytes = null;
        defer if (owned_datagram) |*datagram| datagram.deinit(endpoint.allocator);
        const bytes = if (pending_packet) |packet| packet else blk: {
            owned_datagram = source.receiveTimeout(passive_deadline) catch |err|
                switch (err) {
                    error.Timeout => return error.HandshakeTimeout,
                    error.ConcurrencyUnavailable => return error.HandshakeReceiveFailed,
                    else => |other| return @errorCast(other),
                };
            if (!owned_datagram.?.from.eql(&from)) continue;
            response_from = owned_datagram.?.from;
            response_ecn = owned_datagram.?.ecn;
            var datagram_tail: []const u8 = owned_datagram.?.bytes;
            const packet = (nextHandshakePacketFromCoalescedTail(
                &datagram_tail,
                allow_zero_fixed_bit,
            ) catch |err| {
                if (isDiscardableLongHeaderParseError(err)) continue;
                return err;
            }) orelse continue;
            if (datagram_tail.len != 0) {
                if (pending_tail_storage) |storage| {
                    endpoint.allocator.free(storage);
                    pending_tail_storage = null;
                }
                pending_tail_storage = try endpoint.allocator.dupe(
                    u8,
                    datagram_tail,
                );
                pending_tail = pending_tail_storage.?;
            }
            break :blk packet;
        };

        var packet = quic.protection.openHandshakePacketWithFixedBitPolicy(
            endpoint.allocator,
            handshake_keys,
            bytes,
            next_expected,
            allow_zero_fixed_bit,
        ) catch |err| {
            if (quic.protection.isUnauthenticatedOpenError(err)) continue;
            return err;
        };
        errdefer packet.deinit(endpoint.allocator);
        next_expected = packet.packet_number + 1;
        quic.initial_exchange.insertCryptoPayload(
            endpoint.allocator,
            &reassembler,
            packet.payload,
            .handshake,
        ) catch |err| switch (err) {
            // Servers can send Handshake-space ACK/PADDING packets before or
            // between CRYPTO packets.  They advance packet-number state but do
            // not contribute TLS bytes, so keep waiting instead of treating the
            // packet as a malformed handshake flight.
            error.MissingCryptoFrame => {
                packet.deinit(endpoint.allocator);
                continue;
            },
            else => |other| return other,
        };
        if (first_packet == null) {
            first_packet = packet;
            // Some servers gate the rest of the Handshake flight on an ACK
            // for the first CRYPTO packet. Acknowledge it before waiting for
            // the continuation, and reserve the next packet number for the
            // client Finished flight.
            var ack_storage: [64]u8 = undefined;
            var ack_list: std.ArrayList(u8) = .{
                .items = ack_storage[0..0],
                .capacity = ack_storage.len,
            };
            var fixed = std.heap.FixedBufferAllocator.init(&.{});
            try (quic.Frame{ .ack = .{
                .largest_acknowledged = packet.packet_number,
                .ack_delay = 0,
                .first_ack_range = 0,
            } }).write(&ack_list, fixed.allocator());
            var ack_packet_storage: [1280]u8 = undefined;
            const ack_packet = try quic.protection.sealHandshakePacketInto(
                &ack_packet_storage,
                client_handshake_keys,
                .{
                    .version = packet.version,
                    .destination_connection_id = packet.source_connection_id,
                    .source_connection_id = packet.destination_connection_id,
                    .packet_number = next_client_packet_number.*,
                    .payload = ack_list.items,
                },
            );
            next_client_packet_number.* += 1;
            try endpoint.sendBytes(from, ack_packet);
        } else {
            packet.deinit(endpoint.allocator);
        }

        const available = reassembler.available();
        if (splitServerFlight(available, require_certificate)) |_| {
            const crypto_data = try endpoint.allocator.dupe(u8, available);
            errdefer endpoint.allocator.free(crypto_data);
            const one_rtt_tail = try coalescedOneRttTail(
                pending_tail,
                allow_zero_fixed_bit,
            );
            const coalesced_one_rtt = if (one_rtt_tail.len == 0)
                null
            else
                try endpoint.allocator.dupe(u8, one_rtt_tail);
            errdefer if (coalesced_one_rtt) |retained| {
                endpoint.allocator.free(retained);
            };
            const out = quic.initial_exchange.ReceivedHandshakeCrypto{
                .from = response_from,
                .packet = first_packet.?,
                .crypto_data = crypto_data,
                .coalesced_one_rtt = coalesced_one_rtt,
                .coalesced_one_rtt_ecn = response_ecn,
            };
            first_packet = null;
            return out;
        } else |err| switch (err) {
            error.InvalidHandshakeFlight => continue,
            else => |other| return other,
        }
    }
}

pub fn nextHandshakePacketFromCoalescedTail(
    tail: *[]const u8,
    allow_zero_fixed_bit: bool,
) Error!?[]const u8 {
    while (tail.*.len != 0) {
        if ((tail.*[0] & 0x80) == 0) {
            tail.* = &.{};
            return null;
        }
        const info = try quic.protection.peekProtectedLongPacketInfoWithFixedBitPolicy(
            tail.*,
            allow_zero_fixed_bit,
        );
        const packet = tail.*[0..info.len];
        tail.* = tail.*[info.len..];
        if (info.packet_type == .handshake) return packet;
    }
    return null;
}

pub fn openClientEarlyData(
    endpoint: *quic.runtime.Endpoint,
    from: net.IpAddress,
    coalesced_tail: []const u8,
    keys: quic.protection.PacketProtectionKeys,
    expected_packet_number: u64,
    max_frames: usize,
    expected_destination_connection_id: []const u8,
    expected_source_connection_id: []const u8,
    allow_zero_fixed_bit: bool,
) Error!?quic.zero_rtt.Packet {
    if (coalesced_tail.len == 0) return null;
    const info =
        quic.protection.peekProtectedLongPacketInfoWithFixedBitPolicy(
            coalesced_tail,
            allow_zero_fixed_bit,
        ) catch |err| {
            if (isDiscardableLongHeaderParseError(err)) return null;
            return err;
        };
    if (info.packet_type != .zero_rtt or info.len != coalesced_tail.len) {
        return null;
    }
    const opened = quic.protection.openZeroRttPacketWithFixedBitPolicy(
        endpoint.allocator,
        keys,
        coalesced_tail,
        expected_packet_number,
        allow_zero_fixed_bit,
    ) catch |err| {
        if (quic.protection.isUnauthenticatedOpenError(err)) return null;
        return err;
    };
    var packet = try quic.zero_rtt.fromOpenedPacket(
        endpoint,
        from,
        opened,
        max_frames,
    );
    errdefer packet.deinit(endpoint.allocator);
    if (!std.mem.eql(
        u8,
        packet.packet.destination_connection_id,
        expected_destination_connection_id,
    ) or
        !std.mem.eql(
            u8,
            packet.packet.source_connection_id,
            expected_source_connection_id,
        ))
    {
        return error.InvalidInitialPacket;
    }
    return packet;
}

fn receiveStandaloneClientEarlyData(
    endpoint: *quic.runtime.Endpoint,
    source: quic.runtime.DatagramSource,
    expected_from: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    expected_packet_number: u64,
    max_frames: usize,
    expected_destination_connection_id: []const u8,
    expected_source_connection_id: []const u8,
    allow_zero_fixed_bit: bool,
    recovery: retransmit.Config,
    anti_amplification: *retransmit.AntiAmplificationBudget,
) Error!?quic.zero_rtt.Packet {
    const deadline = passiveHandshakeTimeout(endpoint.io, recovery);
    while (true) {
        var datagram = source.receiveTimeout(deadline) catch |err|
            switch (err) {
                error.Timeout => return error.HandshakeTimeout,
                error.ConcurrencyUnavailable => return error.HandshakeReceiveFailed,
                else => |other| return @errorCast(other),
            };
        defer datagram.deinit(endpoint.allocator);
        if (!datagram.from.eql(&expected_from)) continue;
        anti_amplification.recordReceived(datagram.bytes.len);
        if (try openClientEarlyData(
            endpoint,
            datagram.from,
            datagram.bytes,
            keys,
            expected_packet_number,
            max_frames,
            expected_destination_connection_id,
            expected_source_connection_id,
            allow_zero_fixed_bit,
        )) |packet| return packet;
        // PTO sends Initial before its standalone 0-RTT copy. Ignore that
        // retransmitted Initial (and unrelated unauthenticated datagrams) under
        // the same absolute handshake budget, then inspect the next datagram.
    }
}

fn discardClientEarlyData(
    endpoint: *quic.runtime.Endpoint,
    source: quic.runtime.DatagramSource,
    expected_from: net.IpAddress,
    coalesced_tail: []const u8,
    version: quic.Version,
    allow_zero_fixed_bit: bool,
    recovery: retransmit.Config,
    anti_amplification: *retransmit.AntiAmplificationBudget,
) Error!void {
    if (coalesced_tail.len != 0) {
        return validateRejectedEarlyData(coalesced_tail);
    }
    const deadline = passiveHandshakeTimeout(endpoint.io, recovery);
    while (true) {
        var datagram = source.receiveTimeout(deadline) catch |err|
            switch (err) {
                error.Timeout => return error.HandshakeTimeout,
                error.ConcurrencyUnavailable => return error.HandshakeReceiveFailed,
                else => |other| return @errorCast(other),
            };
        defer datagram.deinit(endpoint.allocator);
        if (!datagram.from.eql(&expected_from)) continue;
        anti_amplification.recordReceived(datagram.bytes.len);
        const info = quic.protection
            .peekProtectedLongPacketInfoWithFixedBitPolicy(
            datagram.bytes,
            allow_zero_fixed_bit,
        ) catch return error.InvalidHandshakeFlight;
        if (info.version != version.wireValue() or info.len != datagram.bytes.len) {
            return error.InvalidHandshakeFlight;
        }
        switch (info.packet_type) {
            .zero_rtt => return,
            .initial => continue,
            .handshake, .retry => return error.InvalidHandshakeFlight,
        }
    }
}

fn validateRejectedEarlyData(bytes: []const u8) Error!void {
    const info = try quic.protection.peekProtectedLongPacketInfo(bytes);
    if (info.packet_type != .zero_rtt or info.len != bytes.len) {
        return error.InvalidHandshakeFlight;
    }
    // RFC 9001 permits rejecting 0-RTT while continuing PSK resumption. The
    // authenticated-length packet is deliberately left undecrypted.
}

fn receiveFromSource(
    source: quic.runtime.DatagramSource,
) Error!quic.runtime.OwnedBytes {
    return source.receive() catch |err| switch (err) {
        error.Timeout => unreachable,
        error.ConcurrencyUnavailable => error.HandshakeReceiveFailed,
        else => |other| @errorCast(other),
    };
}

fn receiveFromSourceBefore(
    source: quic.runtime.DatagramSource,
    caller_deadline: ?std.Io.Clock.Timestamp,
) Error!quic.runtime.OwnedBytes {
    const deadline = caller_deadline orelse return receiveFromSource(source);
    return source.receiveTimeout(.{ .deadline = deadline }) catch |err|
        switch (err) {
            error.Timeout => error.HandshakeTimeout,
            error.ConcurrencyUnavailable => error.HandshakeReceiveFailed,
            else => |other| @errorCast(other),
        };
}

pub fn validateClientInitialTail(
    bytes: []const u8,
    version: quic.Version,
    allow_zero_fixed_bit: bool,
) Error!void {
    var tail = bytes;
    while (tail.len != 0) {
        if (std.mem.allEqual(u8, tail, 0)) return;
        const info = try quic.protection
            .peekProtectedLongPacketInfoWithFixedBitPolicy(
            tail,
            allow_zero_fixed_bit,
        );
        if (info.version != version.wireValue() or
            info.packet_type != .initial)
        {
            return error.InvalidHandshakeFlight;
        }
        tail = tail[info.len..];
    }
}

fn establishedConnection(
    endpoint: *quic.runtime.Endpoint,
    version: quic.Version,
    peer: net.IpAddress,
    receive_keys: quic.protection.PacketProtectionKeys,
    send_keys: quic.protection.PacketProtectionKeys,
    local_connection_id: []const u8,
    peer_connection_id: []const u8,
    config: OneRttConfig,
    local_endpoint: quic.one_rtt.ConnectionConfig.EndpointRole,
    local_transport_parameters: quic.TransportParameters,
    peer_transport_parameters: quic.TransportParameters,
    alpn: []const u8,
    cipher_suite: quic.tls.cipher_suite.Suite,
    retry_processed: bool,
    certificate_compression: ?quic.tls.certificate_compression.Algorithm,
    resumed: bool,
    early_data_status: quic.zero_rtt.handshake.Status,
    resumption_master_secret: ?quic.tls.secret.Secret,
    exporter_master_secret: ?quic.tls.secret.Secret,
    peer_certificates: []const []const u8,
    handshake_reader: ?*datagram_reader.Reader,
    post_init: established_promotion.PostInit,
) Error!EstablishedConnection {
    var owned_receive_packet = if (handshake_reader) |reader|
        reader.takeStorage()
    else
        null;
    errdefer if (owned_receive_packet) |storage| {
        endpoint.allocator.free(storage);
    };
    const local_owned = try endpoint.allocator.dupe(u8, local_connection_id);
    errdefer endpoint.allocator.free(local_owned);
    const peer_owned = try endpoint.allocator.dupe(u8, peer_connection_id);
    errdefer endpoint.allocator.free(peer_owned);
    const alpn_owned = try endpoint.allocator.dupe(u8, alpn);
    errdefer endpoint.allocator.free(alpn_owned);
    var peer_certificate_chain: ?PeerCertificateChain =
        if (peer_certificates.len == 0)
            null
        else
            try .init(endpoint.allocator, peer_certificates);
    errdefer if (peer_certificate_chain) |*chain| chain.deinit();
    const transferred_receive_packet = owned_receive_packet;
    owned_receive_packet = null;
    var connection: quic.one_rtt.Connection = undefined;
    try quic.one_rtt.Connection.initWithReceivePacketStorageInto(
        &connection,
        endpoint,
        config.apply(
            version,
            peer,
            receive_keys,
            send_keys,
            local_owned,
            peer_owned,
            local_endpoint,
            local_transport_parameters,
            peer_transport_parameters,
        ),
        transferred_receive_packet,
    );
    errdefer connection.deinit();
    if (local_endpoint == .server) {
        if (local_transport_parameters.preferred_address) |preferred| {
            try connection.registerLocalPreferredAddress(preferred);
        }
    }
    const promotion = try established_promotion.apply(
        &connection,
        local_endpoint,
        early_data_status,
        post_init,
    );
    return .{
        .connection = connection,
        .local_connection_id = local_owned,
        .peer_connection_id = peer_owned,
        .alpn = alpn_owned,
        .cipher_suite = cipher_suite,
        .retry_processed = retry_processed,
        .certificate_compression = certificate_compression,
        .resumed = resumed,
        .early_data_status = early_data_status,
        .early_data_protected_packet_count = promotion.protected_packet_count,
        .early_data_sent_packet_count = promotion.sent_packet_count,
        .resumption_master_secret = resumption_master_secret,
        .exporter_master_secret = exporter_master_secret,
        .peer_certificate_chain = peer_certificate_chain,
        .peer_transport_parameters = .fromTransportParameters(
            peer_transport_parameters,
        ),
    };
}

fn clientTransportParameters(
    allocator: std.mem.Allocator,
    options: ClientOptions,
    receive_capacity: usize,
    local_transport_parameters: *quic.TransportParameters,
    encoded: *std.ArrayList(u8),
) Error![]const u8 {
    if (options.transport_parameters.len != 0) {
        local_transport_parameters.* = try quic.parseTransportParametersTyped(allocator, options.transport_parameters, .client);
        try validateClientTransportParameters(local_transport_parameters.*, options.local_connection_id, options.version, options.available_versions);
        try transport_limits.validateAdvertised(
            local_transport_parameters.max_udp_payload_size,
            receive_capacity,
        );
        return options.transport_parameters;
    }

    transport_limits.limitGenerated(
        local_transport_parameters,
        receive_capacity,
    );
    local_transport_parameters.initial_source_connection_id = options.local_connection_id;
    try validateClientTransportParameters(local_transport_parameters.*, options.local_connection_id, options.version, options.available_versions);
    try quic.encodeTransportParametersForSource(encoded, allocator, local_transport_parameters.*, .client);
    try appendVersionInformationIfAbsent(encoded, allocator, local_transport_parameters.*, options.version, options.available_versions);
    return encoded.items;
}

pub fn serverTransportParameters(
    allocator: std.mem.Allocator,
    options: ServerOptions,
    receive_capacity: usize,
    original_destination_connection_id: []const u8,
    retry_source_connection_id: []const u8,
    local_transport_parameters: *quic.TransportParameters,
    encoded: *std.ArrayList(u8),
) Error![]const u8 {
    if (options.transport_parameters.len != 0) {
        local_transport_parameters.* = try quic.parseTransportParametersTyped(allocator, options.transport_parameters, .server);
        try transport_limits.validateAdvertised(
            local_transport_parameters.max_udp_payload_size,
            receive_capacity,
        );
        try applyServerStatelessResetToken(
            local_transport_parameters,
            options.local_connection_id,
            options.initial_one_rtt_config.local_stateless_reset_key,
            false,
        );
        try validateServerTransportParameters(local_transport_parameters.*, options.local_connection_id, original_destination_connection_id, retry_source_connection_id, options.version, options.available_versions, false);
        return options.transport_parameters;
    }

    transport_limits.limitGenerated(
        local_transport_parameters,
        receive_capacity,
    );
    local_transport_parameters.original_destination_connection_id = original_destination_connection_id;
    local_transport_parameters.initial_source_connection_id = options.local_connection_id;
    if (retry_source_connection_id.len != 0) {
        local_transport_parameters.retry_source_connection_id = retry_source_connection_id;
    }
    try applyServerStatelessResetToken(
        local_transport_parameters,
        options.local_connection_id,
        options.initial_one_rtt_config.local_stateless_reset_key,
        true,
    );
    try validateServerTransportParameters(local_transport_parameters.*, options.local_connection_id, original_destination_connection_id, retry_source_connection_id, options.version, options.available_versions, false);
    try quic.encodeTransportParametersForSource(encoded, allocator, local_transport_parameters.*, .server);
    try appendVersionInformationIfAbsent(encoded, allocator, local_transport_parameters.*, options.version, options.available_versions);
    return encoded.items;
}

fn applyServerStatelessResetToken(
    params: *quic.TransportParameters,
    local_connection_id: []const u8,
    static_key: ?[quic.stateless_reset.static_key_len]u8,
    can_insert: bool,
) Error!void {
    const key = static_key orelse return;
    const expected = quic.stateless_reset.tokenForConnectionId(
        key,
        local_connection_id,
    );
    if (params.stateless_reset_token) |configured| {
        if (!std.mem.eql(u8, &configured, &expected)) {
            return error.InvalidTransportParameter;
        }
    } else if (can_insert) {
        params.stateless_reset_token = expected;
    } else {
        // A raw extension cannot be safely amended without changing the bytes
        // supplied by its caller. Require it to carry the derived token.
        return error.InvalidTransportParameter;
    }
    if (params.preferred_address) |*preferred| {
        const preferred_token = quic.stateless_reset.tokenForConnectionId(
            key,
            preferred.connection_id,
        );
        if (can_insert) {
            preferred.stateless_reset_token = preferred_token;
        } else if (!std.mem.eql(
            u8,
            &preferred.stateless_reset_token,
            &preferred_token,
        )) return error.InvalidTransportParameter;
    }
}

fn appendVersionInformationIfAbsent(
    encoded: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    params: quic.TransportParameters,
    version: quic.Version,
    available_versions: []const quic.Version,
) Error!void {
    if (params.version_information != null) return;
    try quic.encodeVersionInformationFromVersions(encoded, allocator, version, available_versions);
}

fn validateClientTransportParameters(
    params: quic.TransportParameters,
    initial_source_connection_id: []const u8,
    expected_version: quic.Version,
    available_versions: []const quic.Version,
) Error!void {
    try quic.validateTransportParameters(params, .client);
    if (params.initial_source_connection_id == null) return error.InvalidTransportParameter;
    if (!std.mem.eql(u8, params.initial_source_connection_id.?, initial_source_connection_id)) {
        return error.InvalidTransportParameter;
    }
    try validatePeerVersionInformation(params.version_information, expected_version, available_versions, false);
}

pub fn validateServerTransportParameters(
    params: quic.TransportParameters,
    initial_source_connection_id: []const u8,
    original_destination_connection_id: []const u8,
    retry_source_connection_id: []const u8,
    expected_version: quic.Version,
    available_versions: []const quic.Version,
    version_negotiation_processed: bool,
) Error!void {
    try quic.validateTransportParameters(params, .server);
    if (params.initial_source_connection_id == null or params.original_destination_connection_id == null) {
        return error.InvalidTransportParameter;
    }
    if (!std.mem.eql(u8, params.initial_source_connection_id.?, initial_source_connection_id)) {
        return error.InvalidTransportParameter;
    }
    if (!std.mem.eql(u8, params.original_destination_connection_id.?, original_destination_connection_id)) {
        return error.InvalidTransportParameter;
    }
    if (params.preferred_address != null and
        params.initial_source_connection_id.?.len == 0)
    {
        // RFC 9000 section 18.2 forbids a server that selected a zero-length
        // connection ID from providing a preferred address.
        return error.InvalidTransportParameter;
    }
    if (retry_source_connection_id.len == 0) {
        if (params.retry_source_connection_id != null) return error.InvalidTransportParameter;
    } else {
        const advertised = params.retry_source_connection_id orelse return error.InvalidTransportParameter;
        if (!std.mem.eql(u8, advertised, retry_source_connection_id)) return error.InvalidTransportParameter;
    }
    try validatePeerVersionInformation(params.version_information, expected_version, available_versions, version_negotiation_processed);
}

fn validatePeerVersionInformation(
    version_information: ?quic.VersionInformation,
    expected_version: quic.Version,
    available_versions: []const quic.Version,
    version_negotiation_processed: bool,
) Error!void {
    const info = version_information orelse {
        if (version_negotiation_processed and expected_version != .version_1) return error.InvalidTransportParameter;
        return;
    };
    if (info.chosen_version.wireValue() != expected_version.wireValue()) return error.InvalidTransportParameter;
    if (version_negotiation_processed) {
        // RFC 9368 requires an explicitly present server list to be non-empty
        // after the client has acted on Version Negotiation. The special QUIC
        // v1 compatibility rule applies only when the parameter is absent.
        if (info.availableVersionCount() == 0) {
            return error.InvalidTransportParameter;
        }
        for (available_versions) |local| {
            if (local.wireValue() == expected_version.wireValue()) break;
            if (info.containsAvailableVersion(local)) return error.InvalidTransportParameter;
        } else {}
    }
}

const ServerFlight = struct {
    encrypted_extensions: []const u8,
    certificate_request: ?[]const u8 = null,
    certificate: ?[]const u8 = null,
    certificate_verify: ?[]const u8 = null,
    through_certificate: ?[]const u8 = null,
    before_finished: []const u8,
    finished: []const u8,
};

pub fn splitServerFlight(
    bytes: []const u8,
    authenticated_server: bool,
) Error!ServerFlight {
    const ee_len = try handshakeMessageLen(bytes);
    if (ee_len >= bytes.len) return error.InvalidHandshakeFlight;
    var offset = ee_len;
    var certificate_request: ?[]const u8 = null;
    var certificate: ?[]const u8 = null;
    var certificate_verify: ?[]const u8 = null;
    var through_certificate: ?[]const u8 = null;
    if (offset < bytes.len and
        bytes[offset] ==
            quic.tls.client_auth.handshake_type_certificate_request)
    {
        const request_len = try handshakeMessageLen(bytes[offset..]);
        certificate_request = bytes[offset..][0..request_len];
        offset += request_len;
        if (offset >= bytes.len) return error.InvalidHandshakeFlight;
    }
    const has_certificate = offset < bytes.len and
        (bytes[offset] == quic.tls.auth.handshake_type_certificate or
            bytes[offset] == quic.tls.certificate_compression.handshake_type_compressed_certificate);
    if (authenticated_server and !has_certificate) return error.InvalidHandshakeFlight;
    if (has_certificate) {
        const certificate_len = try handshakeMessageLen(bytes[offset..]);
        certificate = bytes[offset..][0..certificate_len];
        offset += certificate_len;
        through_certificate = bytes[0..offset];
        if (offset >= bytes.len) return error.InvalidHandshakeFlight;
        const verify_len = try handshakeMessageLen(bytes[offset..]);
        certificate_verify = bytes[offset..][0..verify_len];
        offset += verify_len;
        if (offset >= bytes.len) return error.InvalidHandshakeFlight;
    }
    const finished_len = try handshakeMessageLen(bytes[offset..]);
    if (offset + finished_len != bytes.len) {
        return error.InvalidHandshakeFlight;
    }
    return .{
        .encrypted_extensions = bytes[0..ee_len],
        .certificate_request = certificate_request,
        .certificate = certificate,
        .certificate_verify = certificate_verify,
        .through_certificate = through_certificate,
        .before_finished = bytes[0..offset],
        .finished = bytes[offset..],
    };
}

const ClientFlight = struct {
    certificate: ?[]const u8 = null,
    certificate_verify: ?[]const u8 = null,
    before_finished: []const u8,
    finished: []const u8,
};

fn splitClientFlight(
    bytes: []const u8,
    authenticated: bool,
) Error!ClientFlight {
    var offset: usize = 0;
    var certificate: ?[]const u8 = null;
    var certificate_verify: ?[]const u8 = null;
    if (authenticated) {
        const certificate_len = try handshakeMessageLen(bytes);
        certificate = bytes[0..certificate_len];
        offset = certificate_len;
        if (offset >= bytes.len) return error.InvalidHandshakeFlight;
        const verify_len = try handshakeMessageLen(bytes[offset..]);
        certificate_verify = bytes[offset..][0..verify_len];
        offset += verify_len;
        if (offset >= bytes.len) return error.InvalidHandshakeFlight;
    }
    const finished_len = try handshakeMessageLen(bytes[offset..]);
    if (offset + finished_len != bytes.len) {
        return error.InvalidHandshakeFlight;
    }
    return .{
        .certificate = certificate,
        .certificate_verify = certificate_verify,
        .before_finished = bytes[0..offset],
        .finished = bytes[offset..],
    };
}

fn hashServerFlightBeforeFinished(
    client_hello: []const u8,
    server_hello: []const u8,
    flight: ServerFlight,
) [32]u8 {
    return hashParts(&.{
        client_hello,
        server_hello,
        flight.before_finished,
    });
}

fn handshakeMessageLen(bytes: []const u8) Error!usize {
    if (bytes.len < 4) return error.InvalidHandshakeFlight;
    const body_len = (@as(usize, bytes[1]) << 16) | (@as(usize, bytes[2]) << 8) | bytes[3];
    const total = 4 + body_len;
    if (total > bytes.len) return error.InvalidHandshakeFlight;
    return total;
}

fn hashParts(parts: []const []const u8) [32]u8 {
    return quic.tls.transcript.hash(parts);
}

fn random32(io: std.Io, provided: ?[32]u8) std.Io.RandomSecureError![32]u8 {
    if (provided) |value| return value;
    var out: [32]u8 = undefined;
    try std.Io.randomSecure(io, &out);
    return out;
}

pub fn sampledSpinBitConfig(
    config: OneRttConfig,
    connection_random: [32]u8,
) OneRttConfig {
    var effective = config;
    effective.enable_spin_bit = config.enable_spin_bit and
        (connection_random[0] & 0x0f) != 0;
    return effective;
}

fn chooseAlpn(server_protocol: []const u8, client_protocols: []const []const u8) Error![]const u8 {
    for (client_protocols) |protocol| {
        if (std.mem.eql(u8, protocol, server_protocol)) return server_protocol;
    }
    return error.MissingAlpn;
}

fn ensureOfferedAlpn(offered: []const []const u8, selected: []const u8) Error!void {
    for (offered) |protocol| {
        if (std.mem.eql(u8, protocol, selected)) return;
    }
    return error.MissingAlpn;
}

pub fn appendTestHandshakeMessage(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    typ: u8,
    body: []const u8,
) !void {
    try list.ensureUnusedCapacity(allocator, 4 + body.len);
    list.appendAssumeCapacity(typ);
    list.appendAssumeCapacity(@truncate(body.len >> 16));
    list.appendAssumeCapacity(@truncate(body.len >> 8));
    list.appendAssumeCapacity(@truncate(body.len));
    try list.appendSlice(allocator, body);
}

test {
    _ = @import("handshake/default_limits_tests.zig");
    _ = @import("handshake/certificate_ownership_tests.zig");
    _ = @import("handshake/failure_tests.zig");
    _ = @import("handshake/tests.zig");
    _ = @import("handshake/key_exchange_tests.zig");
    _ = @import("handshake/prepared_verifier_tests.zig");
}
