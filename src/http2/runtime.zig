const content_digest = @import("../http/digest.zig");
const std = @import("std");
pub const test_socket = @import("../internal/test_socket.zig");
pub const builtin = @import("builtin");
const http2 = @import("mod.zig");
pub const http3 = @import("../http3/mod.zig");
pub const http1 = @import("../http1/mod.zig");
pub const http1_runtime = http1.runtime;
const frame_io = @import("runtime/frame/io.zig");
const frame_wire = @import("runtime/frame/wire.zig");
const flow_window = @import("runtime/flow/window.zig");
const flow_output = @import("runtime/flow/output.zig");
pub const outbound_headers = @import("runtime/headers/connection.zig");
pub const client_authority = @import("runtime/client/authority.zig");
pub const client_duplex_owner = @import("runtime/duplex/client_owner.zig");
const DuplexOwners = @import("runtime/duplex/owners.zig").Owners;
const duplex_wake = @import("runtime/duplex/wake.zig");
pub const ClientDuplexPumpEvent = client_duplex_owner.PumpEvent;
pub const ServerDuplexPumpEvent = union(enum) {
    request: ServerDuplexStream,
    stream: u31,
    progress,
    wake,
};
pub const header_output = @import("runtime/headers/output.zig");
pub const webtransport_settings = @import("runtime/settings/webtransport.zig");
const message_headers = @import("runtime/headers/message.zig");
pub const push = @import("runtime/push.zig");
const priority_runtime = @import("runtime/priority.zig");
const legacy_priority = @import("runtime/priority/legacy.zig");
pub const peer_metadata = @import("runtime/peer_metadata.zig");
pub const response_scheduler = @import(
    "runtime/response_scheduler.zig",
);
pub const concurrent = @import("runtime/concurrent.zig");
pub const bdp = @import("runtime/bdp.zig");
const ping_policy = @import("runtime/ping_enforcement.zig");
pub const data_frame_budget = @import("runtime/data_frame_budget.zig");
const stream_io = @import("../internal/stream_io.zig");
const deadline_policy = @import("../internal/deadline.zig");
const accept_deadline = @import("../internal/accept.zig");
pub const http_date = @import("../internal/http_date.zig");
const tcp_connect = @import("../internal/tcp_connect.zig");
pub const endpoint_host = @import("../internal/endpoint_host.zig");
pub const host_connect = @import("runtime/client/host_connect.zig");
const socket_options = @import("../internal/socket_options.zig");
const content_coding = @import("../http/content_coding.zig");
const uri_redirect = @import("../http1/runtime/redirect.zig");
pub const tls_stream = @import("../tls/mod.zig").stream;
pub const vail = @import("vail");

const net = std.Io.net;
const server_runtime = @import("runtime/server.zig");
const client_runtime = @import("runtime/client.zig");
const messages = @import("runtime/messages.zig");
const connection_runtime = @import("runtime/connection.zig");

pub const ResponseBodySemantics = message_headers.ResponseBodySemantics;
const ResponseHeaderLookup = message_headers.ResponseHeaderLookup;
const HeaderBlockKind = message_headers.HeaderBlockKind;
const RequestHeaderLookup = message_headers.RequestHeaderLookup;
pub const contentLength = message_headers.contentLength;
pub const responseHeaderLookup = message_headers.responseHeaderLookup;
const validateContentLength = message_headers.validateContentLength;
pub const validateExpectedContentLength =
    message_headers.validateExpectedContentLength;
const validateResponseContentLength = message_headers.validateResponseContentLength;
pub const checkedResponseBodyLength = message_headers.checkedResponseBodyLength;
pub const checkedBodyLength = message_headers.checkedBodyLength;
pub const request_batch_cleanup = @import("runtime/request/batch_cleanup.zig");
pub const request_cleanup = @import("runtime/request/cleanup.zig");
pub const complete_request = @import("runtime/request/complete.zig");
const batch_output = @import("runtime/request/batch_output.zig");
pub const complete_upload = @import("runtime/request/upload.zig");
pub const response_cleanup = @import("runtime/response/cleanup.zig");
pub const stream_termination = @import("runtime/stream/termination.zig");
pub const protocol_error_output = @import("runtime/control/protocol_error.zig");
pub const handshake_protocol_error = @import("runtime/connect/protocol_error.zig");
const terminal_tls_output = @import("runtime/control/tls_close.zig");
const bootstrap_output = @import("runtime/connect/bootstrap_output.zig");
pub const response_start = @import("runtime/response/start.zig");
const request_early_response = @import("runtime/request/early_response.zig");
pub const forbidden_response_body = @import("runtime/response/forbidden_body.zig");
pub const response_trailers = @import("runtime/response/trailers.zig");
pub const header_block_limits = @import("runtime/headers/block_limits.zig");
pub const flow_credit = @import("runtime/flow/credit.zig");
pub const flow_capacity = @import("runtime/flow/capacity.zig");
pub const validateDeclaredRequestLength =
    message_headers.validateDeclaredRequestLength;
const requestShouldDefaultContentLength =
    message_headers.requestShouldDefaultContentLength;
pub const stripSuccessfulConnectContentLength =
    message_headers.stripSuccessfulConnectContentLength;
pub const validateHeaderListSize = message_headers.validateHeaderListSize;
/// Validate one decoded header block (names, values, pseudo-header ordering
/// and required request/response fields). Exposed for callers that decode an
/// HPACK block themselves and want the runtime's semantic checks.
pub const validateHeaderBlock = message_headers.validateHeaderBlock;
pub const methodIsHead = message_headers.methodIsHead;
pub const methodIsConnect = message_headers.methodIsConnect;
pub const responseForbidsBody = message_headers.responseForbidsBody;
pub const responseSemanticsFromMethod =
    message_headers.responseSemanticsFromMethod;
pub const responseWriteSuppressesBodySemantics =
    message_headers.responseWriteSuppressesBodySemantics;
pub const validateResponseBodyForStatus =
    message_headers.validateResponseBodyForStatus;
const validateResponseBodyForStatusWithLength =
    message_headers.validateResponseBodyForStatusWithLength;
pub const validateOutgoingResponseBodyForStatus =
    message_headers.validateOutgoingResponseBodyForStatus;
pub const validateOutgoingResponseBodyForStatusWithLength =
    message_headers.validateOutgoingResponseBodyForStatusWithLength;
const validateResponseBodyForRequestSemantics =
    message_headers.validateResponseBodyForRequestSemantics;
pub const validateResponseBodyForRequestSemanticsWithLength =
    message_headers.validateResponseBodyForRequestSemanticsWithLength;
const validateDeclaredResponseLength =
    message_headers.validateDeclaredResponseLength;
pub const validateDeclaredResponseLengthValue =
    message_headers.validateDeclaredResponseLengthValue;
const responseShouldDefaultContentLength =
    message_headers.responseShouldDefaultContentLength;
pub const responseShouldDefaultContentLengthValue =
    message_headers.responseShouldDefaultContentLengthValue;
pub const informationalResponseToSkip = message_headers.informationalResponseToSkip;
pub const statusIsInformational = message_headers.statusIsInformational;
const requestHeaderLookup = message_headers.requestHeaderLookup;
pub const findHeader = message_headers.findHeader;
pub const clientInitiatedStreamId = frame_wire.clientInitiatedStreamId;
pub const encodeFrameHeader = frame_wire.encodeHeader;
pub const encodeWindowUpdateFrame = frame_wire.encodeWindowUpdate;
pub const appendFrameBytes = frame_wire.appendFrame;
const appendHeaderBlockBytes = frame_wire.appendHeaderBlock;
pub const appendPushPromiseBlockBytes = frame_wire.appendPushPromiseBlock;
pub const writeFrameTransport = frame_io.writeTransport;
pub const writeFrameTransportWithDeadline = frame_io.writeTransportWithDeadline;

/// Select automatic small-DATA-frame budgeting in `Limits.data_frame_budget`.
pub const automatic_data_frame_budget: u32 = data_frame_budget.automatic;
pub const PingEnforcementPolicy = ping_policy.Policy;
pub const PingEnforcementStats = ping_policy.Stats;

pub const Error = http2.Error || http1_runtime.Error || tls_stream.Error ||
    uri_redirect.Error || error{
    ConnectionClosed,
    UnexpectedFrame,
    InvalidFrame,
    MissingPseudoHeader,
    InvalidStatus,
    InvalidContentLength,
    InvalidHeader,
    InvalidUri,
    MessageTooLarge,
    FlowControlBlocked,
    FlowControlViolation,
    ExtendedConnectDisabled,
    StreamReset,
    ResponseAvailable,
    ConnectionGoAway,
    TooManyInformationalResponses,
    PushBufferFull,
    PushNotReady,
    UnsupportedScheme,
    PriorityCapacityExceeded,
    InvalidAlpn,
    PostHandshakeTlsUnavailable,
    InvalidServeOptions,
    SocketOptionFailed,
    InvalidTarget,
    InvalidUriTemplate,
    MissingTemplateVariable,
    DuplicateTemplateVariable,
    InvalidTemplateExpansion,
    InvalidScope,
    EncryptionRequired,
    PayloadTooLarge,
    UnexpectedContextId,
    SettingsAckPending,
} || net.IpAddress.ListenError || net.IpAddress.ConnectError || net.HostName.ValidateError || net.HostName.ConnectError || net.Server.AcceptError || net.Stream.Reader.Error || net.Stream.Writer.Error || std.Thread.SpawnError;
pub const ResponseTimeoutError = Error || std.Io.Timeout.Error;
pub const RequestTimeoutError = Error || std.Io.Timeout.Error;

const ReadExactError = net.Stream.Reader.Error || error{ConnectionClosed};

pub const RedirectPolicy = uri_redirect.Policy;

pub const RedirectOptions = struct {
    policy: RedirectPolicy = .{},
    tls: TlsConnectOptions = .{},
};

/// One HTTP/1.1 CONNECT proxy used to establish a TLS HTTP/2 transport.
/// Proxy headers are scoped to CONNECT and are never forwarded to the origin.
pub const HttpConnectProxy = struct {
    uri: []const u8,
    /// Optional CONNECT authority independent from the authenticated origin.
    /// This supports proxy-side routing/service discovery while TLS SNI,
    /// certificate identity, default :authority, and exporter ownership stay
    /// bound to the requested host and port.
    tunnel_authority: ?[]const u8 = null,
    options: http1_runtime.ProxyOptions = .{},
    limits: http1_runtime.Limits = .{},
};

pub const ServeReadConnectionError = enum {
    compression,
    frame_sequence,
    excessive_header_block,
    push_disabled,
};

pub const ServeReadStreamError = struct {
    stream_id: u31,
    code: http2.ErrorCode,
};

pub fn serveRequestStreamErrorCode(err: anyerror) ?http2.ErrorCode {
    return switch (err) {
        error.InvalidHeader,
        error.MissingPseudoHeader,
        error.InvalidContentLength,
        error.ExtendedConnectDisabled,
        => .protocol_error,
        error.MessageTooLarge => .enhance_your_calm,
        else => null,
    };
}

pub fn responseStreamErrorCode(err: anyerror) ?http2.ErrorCode {
    return switch (err) {
        error.InvalidHeader,
        error.MissingPseudoHeader,
        error.InvalidStatus,
        error.InvalidContentLength,
        => .protocol_error,
        error.MessageTooLarge,
        error.TooManyInformationalResponses,
        => .enhance_your_calm,
        else => null,
    };
}

/// A request handler supplies exactly one final response. Preserve the
/// low-level informational-response API, but turn an accidental handler 1xx
/// into a terminal response so the peer cannot wait forever for a final head.
pub fn normalizeHandlerResponse(
    response: *ResponseOptions,
    request_method: []const u8,
    extended_connect: bool,
) bool {
    const invalid_final = statusIsInformational(response.status);
    if (invalid_final) response.* = .{ .status = 500 };
    if (response.request_method == null) response.request_method = request_method;
    response.extended_connect = extended_connect;
    return invalid_final;
}

pub const flag_end_stream: u8 = 0x1;
pub const flag_ack: u8 = 0x1;
pub const flag_end_headers: u8 = 0x4;
pub const default_flow_window = flow_window.default_value;
pub const max_flow_window = flow_window.max_value;
pub const default_max_frame_size: usize = 16 * 1024;
/// Default SETTINGS_MAX_FRAME_SIZE advertised by netz endpoints. A 256-KiB
/// message fits one DATA frame and takes the direct decoder path; small
/// messages and a 10-stream 1-MiB multiplexing control stayed neutral or
/// slightly faster. Peers still start with the RFC 16-KiB default until
/// SETTINGS exchange, and applications can select 16 KiB explicitly.
pub const recommended_large_frame_size: usize = 256 * 1024;
pub const max_max_frame_size: usize = 16_777_215;
const default_max_header_list_size: usize = 16 * 1024;
// Zig 0.16 Threaded networking submits at most eight iovecs. DATA consumes a
// header/payload pair, so four frames make one actual syscall burst. HEADERS
// occupies the first pair and leaves room for three DATA frames.
pub const max_data_frames_per_write: usize = 4;
pub const max_data_frames_with_headers: usize = 3;
pub const graceful_shutdown_ping_payload = [8]u8{
    0x0b, 0x7b, 0xa2, 0xf0, 0x8b, 0x9b, 0xfe, 0x54,
};

pub const DataSliceCursor = struct {
    slices: []const []const u8,
    slice_index: usize = 0,
    slice_offset: usize = 0,

    pub fn appendTo(
        self: *DataSliceCursor,
        output: [][]const u8,
        output_len: *usize,
        len: usize,
    ) void {
        var remaining = len;
        while (remaining != 0) {
            while (self.slice_index < self.slices.len and
                self.slice_offset == self.slices[self.slice_index].len)
            {
                self.slice_index += 1;
                self.slice_offset = 0;
            }
            std.debug.assert(self.slice_index < self.slices.len);
            const slice = self.slices[self.slice_index];
            const count = @min(remaining, slice.len - self.slice_offset);
            std.debug.assert(output_len.* < output.len);
            output[output_len.*] =
                slice[self.slice_offset..][0..count];
            output_len.* += 1;
            self.slice_offset += count;
            remaining -= count;
        }
    }
};

pub fn readSome(
    io: std.Io,
    stream: net.Stream,
    buffer: []u8,
) net.Stream.Reader.Error!usize {
    return stream_io.readSome(io, stream, buffer);
}

pub fn writeAllToStream(
    io: std.Io,
    stream: net.Stream,
    bytes: []const u8,
) net.Stream.Writer.Error!void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = try io.vtable.netWrite(
            io.userdata,
            stream.socket.handle,
            bytes[written..],
            &.{""},
            0,
        );
        if (n == 0) return error.SocketUnconnected;
        written += n;
    }
}

pub const RuntimeTransport = union(enum) {
    tcp: struct { io: std.Io, stream: net.Stream },
    tls_client: *tls_stream.ClientConnection,
    tls_server: *tls_stream.ServerConnection,

    pub fn hasPendingWrite(self: RuntimeTransport) bool {
        return switch (self) {
            .tcp => false,
            .tls_client => |connection| switch (connection.records) {
                inline else => |*records| records.pending_write_len != 0,
            },
            .tls_server => |connection| switch (connection.records) {
                inline else => |*records| records.pending_write_len != 0,
            },
        };
    }

    pub fn read(self: RuntimeTransport, buffer: []u8) Error!usize {
        return switch (self) {
            .tcp => |tcp| readSome(tcp.io, tcp.stream, buffer),
            .tls_client => |connection| connection.read(buffer),
            .tls_server => |connection| connection.read(buffer),
        };
    }

    pub fn readWithDeadline(
        self: RuntimeTransport,
        buffer: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!usize {
        return switch (self) {
            .tcp => |tcp| stream_io.readSomeWithDeadline(
                tcp.io,
                tcp.stream,
                buffer,
                deadline,
            ),
            .tls_client => |connection| connection.readWithDeadline(buffer, deadline),
            .tls_server => |connection| connection.readWithDeadline(buffer, deadline),
        };
    }

    pub fn writeAll(self: RuntimeTransport, bytes: []const u8) Error!void {
        return switch (self) {
            .tcp => |tcp| writeAllToStream(tcp.io, tcp.stream, bytes),
            .tls_client => |connection| connection.writeAll(bytes),
            .tls_server => |connection| connection.writeAll(bytes),
        };
    }

    pub fn writeAllWithDeadline(
        self: RuntimeTransport,
        bytes: []const u8,
        committed: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        return switch (self) {
            .tcp => |tcp| stream_io.writeAllTrackedWithDeadline(
                tcp.io,
                tcp.stream,
                bytes,
                committed,
                deadline,
            ),
            .tls_client => |connection| connection.writeAllWithDeadline(
                bytes,
                committed,
                deadline,
            ),
            .tls_server => |connection| connection.writeAllWithDeadline(
                bytes,
                committed,
                deadline,
            ),
        };
    }

    pub fn writeAllParts(
        self: RuntimeTransport,
        header: []const u8,
        payload: []const u8,
    ) Error!void {
        return switch (self) {
            .tcp => |tcp| stream_io.writeAllParts(
                tcp.io,
                tcp.stream,
                header,
                payload,
            ),
            .tls_client => |connection| connection.writeAllParts(
                header,
                payload,
            ),
            .tls_server => |connection| connection.writeAllParts(
                header,
                payload,
            ),
        };
    }

    pub fn writeAllSlicesWithDeadline(
        self: RuntimeTransport,
        allocator: std.mem.Allocator,
        parts: []const []const u8,
        batch: *std.ArrayList(u8),
        deadline: std.Io.Clock.Timestamp,
        submitted: *bool,
    ) Error!void {
        return @import("runtime/transport/output.zig").writeAllSlicesWithDeadline(
            allocator,
            self,
            parts,
            batch,
            deadline,
            submitted,
        );
    }

    pub fn writeAllSlices(
        self: RuntimeTransport,
        parts: []const []const u8,
    ) Error!void {
        return switch (self) {
            .tcp => |tcp| stream_io.writeAllSlicesWide(
                tcp.io,
                tcp.stream,
                parts,
            ),
            .tls_client => |connection| connection.writeAllSlices(parts),
            .tls_server => |connection| connection.writeAllSlices(parts),
        };
    }

    pub fn close(self: RuntimeTransport) void {
        switch (self) {
            .tcp => |tcp| tcp.stream.close(tcp.io),
            .tls_client => |connection| connection.deinit(),
            .tls_server => |connection| connection.deinit(),
        }
    }

    /// Close a transport whose protocol lifetime is over. TLS gets one finite
    /// terminal close_notify budget instead of the destructor's unbounded
    /// write; zero or expired budgets and failed records close without alert.
    pub fn closeWithTerminalBudget(
        self: RuntimeTransport,
        io: std.Io,
        limits: Limits,
    ) void {
        terminal_tls_output.closeNotify(
            self,
            response_cleanup.cleanupDeadline(.{ .io = io, .limits = limits }, null),
        );
        self.close();
    }

    pub fn updateTrafficKeys(
        self: RuntimeTransport,
        request_peer_update: bool,
    ) Error!void {
        return switch (self) {
            .tls_client => |connection| connection.updateTrafficKeys(
                request_peer_update,
            ),
            .tls_server => |connection| connection.updateTrafficKeys(
                request_peer_update,
            ),
            .tcp => error.PostHandshakeTlsUnavailable,
        };
    }

    pub fn keyUpdateCounts(
        self: *const RuntimeTransport,
    ) ?tls_stream.KeyUpdateCounts {
        return switch (self.*) {
            .tls_client => |connection| connection.keyUpdateCounts(),
            .tls_server => |connection| connection.keyUpdateCounts(),
            .tcp => null,
        };
    }
};

pub fn tcpTransport(io: std.Io, stream: net.Stream) RuntimeTransport {
    return .{ .tcp = .{ .io = io, .stream = stream } };
}

pub fn connectionHandshakeDeadline(
    transport: RuntimeTransport,
    timeout: ?std.Io.Duration,
) Error!?std.Io.Clock.Timestamp {
    const duration = timeout orelse return null;
    if (duration.nanoseconds <= 0) return error.Timeout;
    const io = switch (transport) {
        .tcp => |tcp| tcp.io,
        .tls_client => |connection| connection.io,
        .tls_server => |connection| connection.io,
    };
    return .fromNow(io, .{ .raw = duration, .clock = .awake });
}

pub fn connectionHandshakeDeadlineBefore(
    transport: RuntimeTransport,
    deadline: std.Io.Clock.Timestamp,
    timeout: ?std.Io.Duration,
) Error!std.Io.Clock.Timestamp {
    const io = switch (transport) {
        .tcp => |tcp| tcp.io,
        .tls_client => |connection| connection.io,
        .tls_server => |connection| connection.io,
    };
    return deadline_policy.capTimeout(io, deadline, timeout);
}

pub const Limits = struct {
    /// Source IP/port for newly opened TCP sockets.
    /// Null leaves source selection to the OS. Requires Netz's zio backend.
    local_address: ?std.Io.net.IpAddress = null,
    /// Constrain the socket's network interface independently of source IP.
    /// Names are borrowed; unsupported platforms/backends fail explicitly.
    network_interface: ?tcp_connect.NetworkInterface = null,
    /// Application resolution for named and URI client connections.
    /// Returned peers do not replace TLS identity or HTTP authority.
    address_resolver: ?AddressResolver = null,
    /// Null uses ordered fallback; explicit values propagate to inherited
    /// proxy transport limits unless proxy-specific options override them.
    address_connect_policy: ?AddressConnectPolicy = null,

    /// Local allocation/test ceiling for any inbound or outbound frame payload.
    /// `max_frame_size` below is the HTTP/2 SETTINGS_MAX_FRAME_SIZE value that
    /// can be advertised to peers and must stay within RFC 9113 bounds.
    max_frame_payload: usize = 16 * 1024 * 1024,
    max_body_bytes: usize = 16 * 1024 * 1024,
    /// Best-effort control output after a discarded response, owned
    /// stream cancellation/destruction, terminal early response, protocol
    /// error, or connection teardown. The RPC keeps its original deadline;
    /// cleanup may add at most this separate shared transport budget to the
    /// return path. It bounds both GOAWAY frames and the TLS close_notify
    /// written while discarding a handshake or closing an established
    /// connection. Zero skips writes.
    terminal_cleanup_timeout: std.Io.Duration = .fromMilliseconds(10),
    max_header_fields: usize = 256,
    /// Maximum interim response heads accepted before a final response. This
    /// bounds both HPACK work and observer callbacks from an endless 1xx chain.
    max_informational_responses: usize = 16,
    /// Bounds HEADERS/PUSH_PROMISE continuation chains independently from byte
    /// limits.  Rust h2 derives this from SETTINGS_MAX_HEADER_LIST_SIZE and the
    /// receive frame size to prevent peers from sending endless empty
    /// CONTINUATION frames that never grow the header block.
    max_continuation_frames: ?usize = null,
    /// Local HPACK decoder capacity advertised as SETTINGS_HEADER_TABLE_SIZE.
    /// Values above u32 are rejected because the wire setting is 32-bit.
    header_table_size: usize = http2.Hpack.default_dynamic_table_size,
    /// Local memory ceiling for the HPACK encoder table. The peer's
    /// SETTINGS_HEADER_TABLE_SIZE grants permission up to its value but cannot
    /// raise this independent cap. This setting is not advertised on wire.
    max_encoder_table_size: u32 = http2.Hpack.default_dynamic_table_size,
    initial_window_size: u32 = @intCast(default_flow_window),
    /// Desired receive-side connection window. HTTP/2 starts every connection
    /// at 65,535 bytes, so values above that are established with an initial
    /// connection WINDOW_UPDATE after SETTINGS. This is distinct from
    /// SETTINGS_INITIAL_WINDOW_SIZE, which applies per stream.
    initial_connection_window_size: u32 =
        @intCast(default_flow_window),
    /// Connection-wide budget for DATA framing overhead. The default sentinel
    /// tracks half the receive connection window with a 25,600-byte minimum.
    /// Any other value stays fixed when adaptive receive windows grow.
    data_frame_budget: u32 = automatic_data_frame_budget,
    /// Adapt receive windows from measured DATA throughput and a dedicated
    /// PING RTT sample. Disabled by default so configured fixed-window wire
    /// behavior remains unchanged.
    adaptive_window: bool = false,
    adaptive_window_max: u32 = bdp.default_max_window,
    max_concurrent_streams: ?u32 = null,
    /// Local SETTINGS_MAX_FRAME_SIZE advertised to peers. The 256-KiB default
    /// lets a large single-stream message fit one DATA frame; peers remain on
    /// the RFC 16-KiB initial value until SETTINGS is exchanged.
    max_frame_size: usize = recommended_large_frame_size,
    /// Local decoded header-list limit advertised as
    /// SETTINGS_MAX_HEADER_LIST_SIZE. Values above u32 are rejected because
    /// they cannot be represented without changing the advertised policy.
    max_header_list_size: usize = default_max_header_list_size,
    /// Local cap for PRIORITY_UPDATE records that target request streams not
    /// opened yet. This remains effective even when MAX_CONCURRENT_STREAMS is
    /// not advertised, preventing unbounded state from speculative IDs.
    max_idle_priority_updates: usize = 256,
    /// Maximum distinct RFC 8336 origins retained from the peer for the
    /// lifetime of one connection. Additional advisory entries are ignored.
    max_peer_origins: usize = 256,
    /// Maximum distinct RFC 7838 (stream ID, origin) advertisements retained
    /// from the peer. Existing entries may still be replaced at capacity.
    max_alternative_services: usize = 256,
    /// Maximum application frames retained while an explicit PING round trip
    /// waits for its matching ACK. Each retained frame is independently
    /// bounded by the inbound frame-size limits. Reaching this cap fails the
    /// probe without discarding any frame already removed from the transport.
    max_pending_ping_frames: usize = 256,
    /// Optional server-side rate enforcement for non-ACK PING frames. Generic
    /// HTTP/2 defaults to null; gRPC listeners opt into grpc-core policy.
    ping_enforcement: ?PingEnforcementPolicy = null,
    /// Maximum recently locally-reset stream IDs retained so late DATA,
    /// HEADERS, and duplicate RST_STREAM frames can be discarded without
    /// terminating the connection. Zero disables this tolerance.
    max_reset_stream_history: usize = 64,
    /// Minimum time that a tracked locally-reset stream remains eligible for
    /// late-frame tolerance. Expired entries are reclaimed lazily when the
    /// history needs capacity or a retained ID is queried.
    reset_stream_duration: std.Io.Duration = .fromSeconds(1),
    /// Maximum remotely-reset requests allowed to remain in the pending-accept
    /// queue. Those requests no longer count toward stream concurrency, so a
    /// peer can otherwise churn reset-after-HEADERS requests and retain owned
    /// request allocations until the application reaches them.
    max_pending_accept_reset_streams: usize = 20,
    /// Maximum RST_STREAM frames generated because the peer caused a
    /// stream-local protocol error over the lifetime of one connection. The
    /// count never decreases: reaching the limit turns the next such reset
    /// into GOAWAY(ENHANCE_YOUR_CALM). `null` disables this DoS guard.
    max_local_error_reset_streams: ?usize = 1024,
    /// Absolute budget for DNS resolution plus all TCP connection attempts.
    /// TLS and HTTP/2 handshake timeouts remain independent.
    connect_timeout: ?std.Io.Duration = null,
    /// Optional absolute budget for the HTTP/2 connection preface and initial
    /// SETTINGS exchange after TCP/TLS setup. Interleaved permitted control
    /// frames do not renew this deadline. For h2c Upgrade, the same duration
    /// first bounds the HTTP/1 request/response head and a fresh budget starts
    /// after the 101 response for the HTTP/2 bootstrap exchange.
    handshake_timeout: ?std.Io.Duration = null,
    /// Advertise RFC 8441 SETTINGS_ENABLE_CONNECT_PROTOCOL.  It is disabled by
    /// default because peers may start tunnelling arbitrary bytes on streams
    /// once extended CONNECT is accepted.
    enable_connect_protocol: bool = false,
    /// Capsule-based WebTransport capability and connection-wide initial
    /// quotas. Established Sessions retain their own acknowledged snapshot.
    webtransport: http2.WebTransportSettings = .{},
    /// Explicitly opt in to HTTP/2 server push. The client otherwise sends
    /// SETTINGS_ENABLE_PUSH=0 and rejects PUSH_PROMISE.
    enable_push: bool = false,
    /// Bound retained push notifications and decoded pushed responses even
    /// when MAX_CONCURRENT_STREAMS is left unadvertised.
    max_buffered_pushes: usize = 32,
    /// Connection-wide retained pushed field-section and body byte budget.
    max_buffered_push_bytes: usize = 32 * 1024 * 1024,
    /// Add an IMF-fixdate `date` field to final server responses that do not
    /// already provide one. This matches Hyper's default server behavior.
    auto_date_header: bool = true,
    /// Advertise RFC 9218 SETTINGS_NO_RFC7540_PRIORITIES=1. This allows a
    /// client to use PRIORITY_UPDATE and tells the peer that legacy dependency
    /// signals are intentionally ignored.
    no_rfc7540_priorities: bool = false,
    /// Disable Nagle on HTTP/2 TCP connections. HTTP/2 already provides its
    /// own frame and stream aggregation; retaining Nagle can stall a complete
    /// flow-control burst behind Linux's delayed ACK timer.
    tcp_nodelay: bool = true,
};

/// Scheduling policy for one blocking HTTP/2 keep-alive cycle.
///
/// Unlike an async background driver, `Connection.keepAlive` temporarily owns
/// inbound frame pumping. Call it only when no other reader is active.
pub const KeepAliveOptions = struct {
    /// Send the probe after this much peer receive inactivity.
    interval: std.Io.Duration,
    /// Fail when the matching ACK does not arrive within this budget.
    timeout: std.Io.Duration = .fromSeconds(20),
    /// Permit a probe when no locally or remotely initiated streams are live.
    /// Hyper clients default this to false; Hyper servers effectively use true.
    while_idle: bool = false,
};

pub const KeepAliveResult = enum {
    skipped_idle,
    acknowledged,
};

pub const KeepAlive = struct {
    options: KeepAliveOptions,
    next_payload: u64 = 0,

    pub fn init(options: KeepAliveOptions) Error!KeepAlive {
        if (options.interval.nanoseconds <= 0 or
            options.timeout.nanoseconds <= 0)
        {
            return error.Timeout;
        }
        return .{ .options = options };
    }

    /// Run one cycle and advance the opaque payload only after its ACK. This
    /// gives long-lived drivers deterministic, non-repeating probes without
    /// requiring an allocator or random source.
    pub fn run(self: *KeepAlive, connection: *Connection) Error!KeepAliveResult {
        var payload: [8]u8 = undefined;
        std.mem.writeInt(u64, &payload, self.next_payload, .big);
        const result = try connection.keepAlive(payload, self.options);
        if (result == .acknowledged) self.next_payload +%= 1;
        return result;
    }
};

/// Adopt an accepted TCP socket under one server admission deadline.
/// Ownership transfers on entry, including expired/wrong-clock deadlines and
/// cancellation. Listener managers can start the budget after TCP acceptance
/// and carry it through TLS, HTTP/2 bootstrap and their own owner admission.
pub const acceptOwnedStreamWithDeadline = server_runtime.acceptOwnedStreamWithDeadline;
pub const acceptOwnedStreamWithTimeout = server_runtime.acceptOwnedStreamWithTimeout;
pub const Server = server_runtime.Server;
pub const UnixServer = server_runtime.UnixServer;
pub const adoptPriorKnowledgeStream = server_runtime.adoptPriorKnowledgeStream;
pub const adoptNegotiatedTlsServer = server_runtime.adoptNegotiatedTlsServer;
pub const TlsListenOptions = server_runtime.TlsListenOptions;
pub const TlsServer = server_runtime.TlsServer;
pub const AsyncServeError = server_runtime.AsyncServeError;
pub const ConcurrentServeResult = server_runtime.ConcurrentServeResult;
pub const ConcurrentHandlerServeResult = server_runtime.ConcurrentHandlerServeResult;
pub const ConcurrentHandlerServeError = server_runtime.ConcurrentHandlerServeError;
pub const GoAwayRetryDisposition = server_runtime.GoAwayRetryDisposition;
pub const ServeErrorStage = server_runtime.ServeErrorStage;
pub const ServeErrorPolicy = server_runtime.ServeErrorPolicy;
pub const ServeErrorEvent = server_runtime.ServeErrorEvent;
pub const ServeErrorObserver = server_runtime.ServeErrorObserver;
pub const ServeUntilOptions = server_runtime.ServeUntilOptions;

pub const Client = client_runtime.Client;

pub const StapledOcspPolicy = tls_stream.StapledOcspPolicy;

pub const AddressResolver = http1_runtime.AddressResolver;
pub const AddressConnectPolicy = http1_runtime.AddressConnectPolicy;
pub const HappyEyeballsOptions = http1_runtime.HappyEyeballsOptions;

pub const TlsConnectOptions = struct {
    verify_host: bool = true,
    ca_bundle: ?tls_stream.ClientCaBundle = null,
    /// Optional process environment for vail's native trust store. When set,
    /// `SSL_CERT_FILE` and `SSL_CERT_DIR` take precedence over the platform
    /// roots, matching rustls-native-certs.
    environ: ?std.process.Environ = null,
    /// Optional caller-owned native trust store reused across handshakes.
    system_store: ?*const vail.x509.trust.SystemStore = null,
    /// Selects the default root set when no explicit verifier, CA bundle, or
    /// store is supplied. `.platform` uses the OS verifier; `.bundled` uses
    /// the compiled-in Mozilla roots.
    root_source: tls_stream.RootSource = .system,
    server_verifier: ?vail.tls.auth.ClientVerifier = null,
    /// Built-in verifier policy for RFC 6066 stapled OCSP responses.
    stapled_ocsp: StapledOcspPolicy = .ignore,
    /// Emit status_request. Must remain enabled for `.require` and defaults on
    /// so RFC 7633 Must-Staple certificates work without another option.
    request_ocsp: bool = true,
    client_identity: ?vail.tls.client_auth.ClientIdentity = null,
    cipher_suites: []const vail.tls.cipher_suite.Suite =
        &vail.tls.cipher_suite.default_preference,
    tls12_cipher_suites: []const tls_stream.Tls12CipherSuite =
        tls_stream.default_tls12_cipher_suites,
    protocol_policy: tls_stream.VersionPolicy = .tls12_and_tls13,
    request_tls12_session_ticket: bool = true,
    tls12_ticket_resumption: ?*const tls_stream.Tls12SessionTicket = null,
    request_tls13_session_ticket: bool = true,
    tls13_ticket_resumption: ?*const tls_stream.Tls13SessionTicket = null,
    max_server_handshake_size: usize = 256 * 1024,
    /// Absolute receive budget spanning ServerHello and the encrypted flight.
    tls_handshake_timeout: ?std.Io.Duration = null,
};

pub fn verifiedTlsClientOptions(
    tls_host: []const u8,
    options: TlsConnectOptions,
) tls_stream.ClientVerifiedOptions {
    return .{
        .server_name = tls_host,
        .verify_host = options.verify_host,
        .ca_bundle = options.ca_bundle,
        .system_environ = options.environ,
        .system_store = options.system_store,
        .root_source = options.root_source,
        .server_verifier = options.server_verifier,
        .stapled_ocsp = options.stapled_ocsp,
        .request_ocsp = options.request_ocsp,
        .client_identity = options.client_identity,
        .alpn_protocols = &.{"h2"},
        .cipher_suites = options.cipher_suites,
        .tls12_cipher_suites = options.tls12_cipher_suites,
        .protocol_policy = options.protocol_policy,
        .request_tls12_session_ticket = options.request_tls12_session_ticket,
        .tls12_ticket_resumption = options.tls12_ticket_resumption,
        .request_tls13_session_ticket = options.request_tls13_session_ticket,
        .tls13_ticket_resumption = options.tls13_ticket_resumption,
        .max_server_handshake_size = options.max_server_handshake_size,
        .handshake_timeout = options.tls_handshake_timeout,
    };
}

pub const Role = enum {
    client,
    server,
};

pub const FlowWindow = flow_window.Window;

pub const StreamWindowEntry = struct {
    stream_id: u31,
    window: FlowWindow = .{},
};

pub const LocallyResetStream = struct {
    stream_id: u31,
    reset_at_ns: i96,
};

pub const PromisedRequest = push.PromisedRequest;

pub const AlternativeService = peer_metadata.AlternativeService;

fn FrameSlot(comptime Frame: type) type {
    return struct {
        value: Frame = .{
            .bytes = &.{},
            .frame = undefined,
        },

        pub fn hasValue(self: *const @This()) bool {
            return self.value.bytes.len != 0;
        }

        pub fn getPtr(self: *@This()) ?*Frame {
            return if (self.hasValue()) &self.value else null;
        }

        pub fn put(self: *@This(), value: Frame) void {
            std.debug.assert(!self.hasValue());
            // Production retained frames include the nine-byte wire header.
            // Tests and recovery helpers may use a shorter synthetic backing
            // slice, but a retained frame can never use the empty sentinel.
            std.debug.assert(value.bytes.len != 0);
            self.value = value;
        }

        pub fn take(self: *@This()) ?Frame {
            if (!self.hasValue()) return null;
            const value = self.value;
            self.* = .{};
            return value;
        }

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            var value = self.take() orelse return;
            value.deinit(allocator);
        }
    };
}

pub const OwnedFrameSlot = FrameSlot(OwnedFrame);
pub const RetainedFrameSlot = FrameSlot(RetainedFrame);

pub const ReceivedDataPayload = struct {
    data: []const u8,
    padding_len: u8,
    padding_bytes: u9 = 0,
    budget_charge: u8,
    // Actual adaptive credit granted during this DATA, separate from releases.
    adaptive_connection_increment: u31 = 0,
};

/// Reset evidence for adapters that need a conservative replay decision.
/// Complete request readers set response_started=false only when no response
/// head was observed. Other receive paths preserve the conservative default.
pub const PeerResetInfo = struct {
    reset: http2.ResetStreamPayload,
    response_started: bool,
};

pub const Connection = connection_runtime.Connection;
pub const redirectLocation = connection_runtime.redirectLocation;
pub const redirectH2Headers = connection_runtime.redirectH2Headers;

pub const RequestOptions = messages.RequestOptions;
pub const StreamingRequestOptions = messages.StreamingRequestOptions;
pub const ResponseOptions = messages.ResponseOptions;
pub const StreamingResponseOptions = messages.StreamingResponseOptions;
pub const OwnedRequest = messages.OwnedRequest;
pub const StreamingRequest = messages.StreamingRequest;
pub const StreamingRequestHead = messages.StreamingRequestHead;
pub const OwnedResponse = messages.OwnedResponse;
pub const RedirectedResponse = messages.RedirectedResponse;
pub const StreamingResponse = messages.StreamingResponse;
pub const StreamingResponseHead = messages.StreamingResponseHead;
pub const InformationalObserver = messages.InformationalObserver;
pub const BatchInformationalObserver = messages.BatchInformationalObserver;
pub const BatchOwnedResponseResult = messages.BatchOwnedResponseResult;
pub const BatchOwnedResponseObserver = messages.BatchOwnedResponseObserver;
pub const BatchStreamingResponseResult = messages.BatchStreamingResponseResult;
pub const BatchStreamingResponseObserver = messages.BatchStreamingResponseObserver;
pub const BatchCancellationObserver = messages.BatchCancellationObserver;
pub const StreamResponseSemantics = messages.StreamResponseSemantics;
pub const PendingRequest = messages.PendingRequest;
pub const uriTargetAlloc = messages.uriTargetAlloc;
pub const ignoreStreamingResponseHead = messages.ignoreStreamingResponseHead;
pub const ignoreStreamingRequestHead = messages.ignoreStreamingRequestHead;
pub const countInformationalResponse = messages.countInformationalResponse;
pub const notifyInformationalResponse = messages.notifyInformationalResponse;
pub const streamingRequestFromOwned = messages.streamingRequestFromOwned;

pub const RequestWriter = struct {
    connection: *Connection,
    stream_id: u31,
    expected_length: ?usize,
    head_request: bool,
    /// Traditional CONNECT response semantics: a 2xx response is a tunnel
    /// head rather than an HTTP body. Defaults keep test literals compatible.
    connect_request: bool = false,
    written: usize = 0,
    body_finished: bool = false,
    completed: bool = false,

    /// Cancel a request whose response has not been consumed.
    ///
    /// This remains active after request-body FIN because the peer still owns
    /// the response half. Successful response reads and explicit reset make it
    /// a no-op.
    pub fn deinit(self: *RequestWriter) void {
        if (self.completed) return;
        self.cancel(.cancel) catch {};
    }

    pub fn write(
        self: *RequestWriter,
        data: []const u8,
    ) Error!void {
        return self.writeUntil(data, null);
    }

    pub fn writeWithDeadline(
        self: *RequestWriter,
        data: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.writeUntil(data, deadline);
    }

    pub fn writeWithTimeout(
        self: *RequestWriter,
        data: []const u8,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeWithDeadline(data, .fromNow(self.connection.io, .{
            .raw = timeout,
            .clock = .awake,
        }));
    }

    fn writeUntil(
        self: *RequestWriter,
        data: []const u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        try self.ensureWritable();
        try self.reserveLength(data.len, false);
        var sent: usize = 0;
        self.connection.writeDataTrackedUntil(
            self.stream_id,
            data,
            false,
            &sent,
            deadline,
        ) catch |err| switch (err) {
            error.ResponseAvailable => {
                request_early_response.finish(self, sent, deadline, .{ .transport = Connection.transportForIo });
                return error.ResponseAvailable;
            },
            else => {
                self.written += sent;
                return err;
            },
        };
        self.written += sent;
    }

    pub fn finishData(
        self: *RequestWriter,
        data: []const u8,
    ) Error!void {
        return self.finishDataUntil(data, null);
    }

    pub fn finishDataWithDeadline(
        self: *RequestWriter,
        data: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.finishDataUntil(data, deadline);
    }

    pub fn finishDataWithTimeout(
        self: *RequestWriter,
        data: []const u8,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishDataWithDeadline(data, .fromNow(
            self.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    fn finishDataUntil(
        self: *RequestWriter,
        data: []const u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        try self.ensureWritable();
        try self.reserveLength(data.len, true);
        var sent: usize = 0;
        self.connection.writeDataTrackedUntil(
            self.stream_id,
            data,
            true,
            &sent,
            deadline,
        ) catch |err| switch (err) {
            error.ResponseAvailable => {
                request_early_response.finish(self, sent, deadline, .{ .transport = Connection.transportForIo });
                return error.ResponseAvailable;
            },
            else => {
                self.written += sent;
                return err;
            },
        };
        self.written += sent;
        self.body_finished = true;
    }

    pub fn finish(self: *RequestWriter) Error!void {
        return self.finishData(&.{});
    }

    pub fn finishWithDeadline(
        self: *RequestWriter,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        return self.finishDataWithDeadline(&.{}, deadline);
    }

    pub fn finishWithTimeout(
        self: *RequestWriter,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        return self.finishDataWithTimeout(&.{}, timeout);
    }

    /// Cumulative application body bytes committed by successful DATA
    /// bursts. This advances even when a bounded write later times out, so a
    /// caller can retry only the uncommitted suffix.
    pub fn committedBytes(self: RequestWriter) usize {
        return self.written;
    }

    pub fn finishTrailers(self: *RequestWriter, trailers: []const http2.Hpack.HeaderField) Error!void {
        return self.finishTrailersUntil(trailers, null);
    }

    pub fn finishTrailersWithDeadline(self: *RequestWriter, trailers: []const http2.Hpack.HeaderField, deadline: std.Io.Clock.Timestamp) ResponseTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.finishTrailersUntil(trailers, deadline);
    }

    pub fn finishTrailersWithTimeout(self: *RequestWriter, trailers: []const http2.Hpack.HeaderField, timeout: std.Io.Duration) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishTrailersWithDeadline(trailers, .fromNow(self.connection.io, .{ .raw = timeout, .clock = .awake }));
    }

    fn finishTrailersUntil(self: *RequestWriter, trailers: []const http2.Hpack.HeaderField, deadline: ?std.Io.Clock.Timestamp) Error!void {
        try self.ensureWritable();
        try self.reserveLength(0, true);
        try validateHeaderBlock(trailers, .request_trailers);
        try self.connection.writeHeadersUntil(
            self.stream_id,
            trailers,
            true,
            deadline,
        );
        self.body_finished = true;
    }

    /// Receive the response after the request body has ended.
    pub fn readResponse(
        self: *RequestWriter,
    ) Error!OwnedResponse {
        return self.readResponseWithInformational(null);
    }

    pub fn readResponseWithTimeout(
        self: *RequestWriter,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseUntil(
            null,
            .fromNow(self.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn readResponseWithDeadline(
        self: *RequestWriter,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        return self.readResponseWithInformationalAndDeadline(
            null,
            deadline,
        );
    }

    pub fn readResponseWithInformationalAndDeadline(
        self: *RequestWriter,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.readResponseUntil(informational, deadline);
    }

    pub fn readResponseWithInformationalAndTimeout(
        self: *RequestWriter,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseWithInformationalAndDeadline(
            informational,
            .fromNow(self.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    /// Finish a streaming request while observing ordered interim responses.
    pub fn readResponseWithInformational(
        self: *RequestWriter,
        informational: ?InformationalObserver,
    ) Error!OwnedResponse {
        return self.readResponseUntil(informational, null);
    }

    pub fn readResponseUntil(
        self: *RequestWriter,
        informational: ?InformationalObserver,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        if (self.connection.callback_reader_active) {
            return error.UnexpectedFrame;
        }
        if (!self.body_finished or self.completed) {
            return error.UnexpectedFrame;
        }
        const connection = self.connection;
        const stream_id = self.stream_id;
        const request_method = if (self.head_request) "HEAD" else "POST";
        const response = connection.readResponseUntil(
            stream_id,
            request_method,
            false,
            informational,
            deadline,
        ) catch |err| {
            // readResponseUntil releases the stream on every exit path.
            self.completed = true;
            return err;
        };
        self.completed = true;
        return response;
    }

    pub fn readResponseStreaming(
        self: *RequestWriter,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.readResponseStreamingWithHead(
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn readResponseStreamingWithTimeout(
        self: *RequestWriter,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseStreamingWithHeadAndDeadline(
            .fromNow(self.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn readResponseStreamingWithDeadline(
        self: *RequestWriter,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.readResponseStreamingWithHeadAndDeadline(
            deadline,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn readResponseStreamingWithHeadAndTimeout(
        self: *RequestWriter,
        timeout: std.Io.Duration,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseStreamingWithHeadAndDeadline(
            .fromNow(self.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
            context,
            begin,
            consume,
        );
    }

    pub fn readResponseStreamingWithHeadAndDeadline(
        self: *RequestWriter,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.readResponseStreamingWithInformationalAndHeadAndDeadline(
            null,
            deadline,
            context,
            begin,
            consume,
        );
    }

    pub fn readResponseStreamingWithInformationalAndDeadline(
        self: *RequestWriter,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.readResponseStreamingWithInformationalAndHeadAndDeadline(
            informational,
            deadline,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn readResponseStreamingWithInformationalAndTimeout(
        self: *RequestWriter,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseStreamingWithInformationalAndHeadAndDeadline(
            informational,
            .fromNow(self.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn readResponseStreamingWithInformationalAndHeadAndTimeout(
        self: *RequestWriter,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseStreamingWithInformationalAndHeadAndDeadline(
            informational,
            .fromNow(self.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
            context,
            begin,
            consume,
        );
    }

    /// Finish this request while observing every interim head and the final
    /// head before DATA under a single caller-owned deadline.
    pub fn readResponseStreamingWithInformationalAndHeadAndDeadline(
        self: *RequestWriter,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (self.connection.callback_reader_active) {
            return error.UnexpectedFrame;
        }
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        if (!self.body_finished or self.completed) {
            return error.UnexpectedFrame;
        }
        const connection = self.connection;
        const response = connection.readResponseStreamingWithHeadUntil(
            .{
                .stream_id = self.stream_id,
                .request_method = if (self.head_request) "HEAD" else "POST",
                .extended_connect = false,
            },
            informational,
            deadline,
            context,
            begin,
            consume,
        ) catch |err| {
            self.completed = true;
            return err;
        };
        self.completed = true;
        return response;
    }

    pub fn readResponseStreamingWithInformational(
        self: *RequestWriter,
        informational: ?InformationalObserver,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.readResponseStreamingWithInformationalAndHead(
            informational,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn readResponseStreamingWithHead(
        self: *RequestWriter,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.readResponseStreamingWithInformationalAndHead(
            null,
            context,
            begin,
            consume,
        );
    }

    /// Stream the final response while observing every preceding 1xx head.
    pub fn readResponseStreamingWithInformationalAndHead(
        self: *RequestWriter,
        informational: ?InformationalObserver,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (self.connection.callback_reader_active) {
            return error.UnexpectedFrame;
        }
        if (!self.body_finished or self.completed) {
            return error.UnexpectedFrame;
        }
        const connection = self.connection;
        const pending = Connection.PendingResponse{
            .stream_id = self.stream_id,
            .request_method = if (self.head_request) "HEAD" else "POST",
            .extended_connect = false,
        };
        const response = connection.readResponseStreamingWithHead(
            pending,
            informational,
            context,
            begin,
            consume,
        ) catch |err| {
            // The streaming reader also releases on every exit path.
            self.completed = true;
            return err;
        };
        self.completed = true;
        return response;
    }

    /// Transfer this request's two half-streams to a single step-driven owner.
    /// The original writer becomes inert and must not be used again.
    pub fn beginDuplex(self: *RequestWriter) Error!ClientDuplexStream {
        if (self.completed or
            (self.connection.duplex_reader_active and self.connection.duplex_owners.count() == 0) or
            self.connection.callback_reader_active)
        {
            return error.UnexpectedFrame;
        }
        self.connection.duplex_owners.acquire();
        self.connection.duplex_reader_active = true;
        const duplex = ClientDuplexStream{
            .connection = self.connection,
            .registered = true,
            .stream_id = self.stream_id,
            .expected_request_length = self.expected_length,
            .request_written = self.written,
            .request_finished = self.body_finished,
            .head_request = self.head_request,
            .connect_request = self.connect_request,
        };
        self.completed = true;
        return duplex;
    }

    pub fn reset(
        self: *RequestWriter,
        error_code: http2.ErrorCode,
    ) Error!void {
        try self.ensureWritable();
        return self.cancel(error_code);
    }

    /// Cancel an unconsumed response even after the request body has been
    /// half-closed. The terminal cleanup budget bounds output, and local state
    /// is retired even on failure. Repeated cancellation is a no-op.
    pub fn cancel(
        self: *RequestWriter,
        error_code: http2.ErrorCode,
    ) Error!void {
        if (self.completed) return;
        defer {
            self.body_finished = true;
            self.completed = true;
        }
        return self.connection.terminateOwnedStream(self.stream_id, error_code);
    }

    fn ensureWritable(self: RequestWriter) Error!void {
        if (self.body_finished or self.completed) {
            return error.ConnectionClosed;
        }
        if (!self.connection.outboundStreamIsActive(self.stream_id)) {
            return error.StreamReset;
        }
    }

    fn reserveLength(
        self: RequestWriter,
        additional: usize,
        finishing: bool,
    ) Error!void {
        const total = std.math.add(
            usize,
            self.written,
            additional,
        ) catch return error.MessageTooLarge;
        if (self.expected_length) |expected| {
            if (total > expected or (finishing and total != expected)) {
                return error.InvalidContentLength;
            }
        }
    }
};

pub const DuplexResponseHead = struct {
    headers: []http2.Hpack.HeaderField,
    status: u16,
    body_allowed: bool = true,

    pub fn streamContentDecoder(self: DuplexResponseHead, allocator: std.mem.Allocator, options: content_coding.StreamOptions) content_coding.Error!content_coding.StreamDecoder {
        return (try content_coding.responseDecodingChain(self.headers, self.status, self.body_allowed)).streamDecoder(allocator, options);
    }

    pub fn deinit(self: *DuplexResponseHead, allocator: std.mem.Allocator) void {
        freeHeaders(allocator, self.headers);
        self.* = undefined;
    }
};

pub const DuplexData = struct {
    frame: RetainedFrame,
    data: []const u8,

    pub fn deinit(self: *DuplexData, allocator: std.mem.Allocator) void {
        self.frame.deinit(allocator);
        self.* = undefined;
    }
};

pub const DeferredHeaderBlock = struct {
    payload_key: usize = 0,
    stream_id: u31,
    headers: []http2.Hpack.HeaderField,
    continuation_count: usize,
    decode_error: ?Error = null,
};

pub const DuplexHeaderBlock = struct {
    stream_id: u31,
    end_stream: bool,
    end_headers: bool,
    continuation_count: usize = 0,
    limit_exceeded: bool = false,
    decode_complete: bool = false,
    bytes: std.ArrayList(u8) = .empty,

    pub fn init(
        connection: *Connection,
        first: http2.Frame,
    ) Error!DuplexHeaderBlock {
        const first_headers = try legacy_priority.parseHeaders(connection, first);
        var result = DuplexHeaderBlock{
            .stream_id = first.header.stream_id,
            .end_stream = (first.header.flags & flag_end_stream) != 0,
            .end_headers = (first.header.flags & flag_end_headers) != 0,
        };
        errdefer result.deinit(connection.allocator);
        try result.bytes.appendSlice(
            connection.allocator,
            first_headers.header_block,
        );
        try result.validateSize(connection);
        return result;
    }

    pub fn resumeUntil(
        self: *DuplexHeaderBlock,
        connection: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!?[]http2.Hpack.HeaderField {
        try self.completeUntil(connection, deadline);
        return try self.decode(connection);
    }

    pub fn discardUntil(self: *DuplexHeaderBlock, connection: *Connection, deadline: ?std.Io.Clock.Timestamp) Error![]http2.Hpack.HeaderField {
        try self.completeUntil(connection, deadline);
        connection.hpack_decoder.discardBlock(connection.allocator, self.bytes.items) catch |err| {
            if (connection.hpack_decoder.lastDecodeWasCompressionError()) {
                connection.serve_read_connection_error = .compression;
            }
            return @errorCast(err);
        };
        self.decode_complete = true;
        return &.{};
    }

    fn completeUntil(self: *DuplexHeaderBlock, connection: *Connection, deadline: ?std.Io.Clock.Timestamp) Error!void {
        const header_mode = connection.push_ingress_headers_active;
        connection.push_ingress_headers_active = true;
        defer connection.push_ingress_headers_active = header_mode;
        while (!self.end_headers) {
            var continuation = try connection.readOwnedFrameForDuplexWithDeadline(
                deadline,
            );
            defer continuation.deinit(connection.allocator);
            if (continuation.frame.header.frame_type != .continuation or
                continuation.frame.header.stream_id != self.stream_id)
            {
                connection.serve_read_connection_error = .frame_sequence;
                connection.aggregate_timeout_unusable = true;
                connection.sendProtocolGoAway(connection.lastPeerProcessedStreamId(), .protocol_error, "header-sequence", deadline);
                return error.UnexpectedFrame;
            }
            try self.appendContinuation(connection, continuation.frame);
        }
    }

    pub fn decode(self: *DuplexHeaderBlock, connection: *Connection) Error![]http2.Hpack.HeaderField {
        if (self.limit_exceeded) {
            connection.hpack_decoder.discardBlock(connection.allocator, self.bytes.items) catch |err| {
                if (connection.hpack_decoder.lastDecodeWasCompressionError()) {
                    connection.serve_read_connection_error = .compression;
                    connection.aggregate_timeout_unusable = true;
                }
                return @errorCast(err);
            };
            // A caller may observe the same terminal error again. Do not
            // replay the rejected block's dynamic-table updates on retry.
            self.decode_complete = true;
            self.bytes.clearRetainingCapacity();
            return error.MessageTooLarge;
        }
        const fields = decodeOwnedHeaders(
            connection.allocator,
            self.bytes.items,
            connection.limits,
            &connection.hpack_decoder,
        ) catch |err| {
            // Output limits still consume the complete HPACK block. OOM or a
            // compression failure can stop partway through dynamic updates.
            self.decode_complete = err == error.MessageTooLarge and
                !connection.hpack_decoder.lastDecodeWasCompressionError();
            return err;
        };
        self.decode_complete = true;
        return fields;
    }

    pub fn appendContinuation(self: *DuplexHeaderBlock, connection: *Connection, frame: http2.Frame) Error!void {
        self.continuation_count = std.math.add(usize, self.continuation_count, 1) catch return error.MessageTooLarge;
        self.end_headers = (frame.header.flags & flag_end_headers) != 0;
        const next_len = std.math.add(usize, self.bytes.items.len, frame.payload.len) catch return error.MessageTooLarge;
        self.limit_exceeded = header_block_limits.completeOverflow(
            self.continuation_count,
            connection.maxContinuationFrames(),
            next_len,
            header_block_limits.byteLimit(connection.limits.max_frame_payload, connection.limits.max_header_fields),
            self.end_headers,
        ) catch |err| {
            connection.serve_read_connection_error = .excessive_header_block;
            connection.aggregate_timeout_unusable = true;
            return @errorCast(err);
        };
        try self.bytes.appendSlice(connection.allocator, frame.payload);
    }

    fn validateSize(
        self: DuplexHeaderBlock,
        connection: *const Connection,
    ) Error!void {
        const limit = header_block_limits.byteLimit(connection.limits.max_frame_payload, connection.limits.max_header_fields);
        if (self.bytes.items.len > limit) return error.MessageTooLarge;
    }

    pub fn deinit(self: *DuplexHeaderBlock, allocator: std.mem.Allocator) void {
        self.bytes.deinit(allocator);
        self.* = undefined;
    }
};

pub const DeferredPendingHeaderSlot = struct {
    const Pending = struct {
        header: DuplexHeaderBlock,
        payload_key: usize,
        queued_continuation_count: usize = 0,
        overflow_included: bool = false,
    };

    value: ?*Pending = null,

    pub fn hasValue(self: *const DeferredPendingHeaderSlot) bool {
        return self.value != null;
    }

    pub fn getPtr(self: *DeferredPendingHeaderSlot) ?*Pending {
        return self.value;
    }

    pub fn init(self: *DeferredPendingHeaderSlot, connection: *Connection, first: http2.Frame) Error!void {
        std.debug.assert(self.value == null);
        const pending = try connection.allocator.create(Pending);
        errdefer connection.allocator.destroy(pending);
        pending.* = .{
            .header = try DuplexHeaderBlock.init(connection, first),
            .payload_key = @intFromPtr(first.payload.ptr),
        };
        self.value = pending;
    }

    pub fn deinit(self: *DeferredPendingHeaderSlot, allocator: std.mem.Allocator) void {
        const pending = self.value orelse return;
        pending.header.deinit(allocator);
        allocator.destroy(pending);
        self.value = null;
    }
};

pub const DuplexHeaderBlockSlot = struct {
    value: DuplexHeaderBlock = .{
        .stream_id = 0,
        .end_stream = false,
        .end_headers = false,
    },

    pub fn hasValue(self: *const DuplexHeaderBlockSlot) bool {
        return self.value.stream_id != 0;
    }

    pub fn getPtr(self: *DuplexHeaderBlockSlot) ?*DuplexHeaderBlock {
        return if (self.hasValue()) &self.value else null;
    }

    pub fn put(self: *DuplexHeaderBlockSlot, value: DuplexHeaderBlock) void {
        std.debug.assert(!self.hasValue());
        std.debug.assert(value.stream_id != 0);
        self.value = value;
    }

    pub fn deinit(
        self: *DuplexHeaderBlockSlot,
        allocator: std.mem.Allocator,
    ) void {
        if (!self.hasValue()) return;
        self.value.deinit(allocator);
        self.* = .{};
    }
};

pub const DuplexWriteResult = struct {
    written: usize,
    response_available: bool,
};

pub const DuplexResponseEvent = union(enum) {
    informational: DuplexResponseHead,
    head: DuplexResponseHead,
    data: DuplexData,
    trailers: []http2.Hpack.HeaderField,
    finished,
    reset: http2.ResetStreamPayload,

    pub fn deinit(self: *DuplexResponseEvent, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .informational, .head => |*head| head.deinit(allocator),
            .data => |*data| data.deinit(allocator),
            .trailers => |trailers| freeHeaders(allocator, trailers),
            .finished, .reset => {},
        }
        self.* = undefined;
    }
};

/// One client-owned HTTP/2 stream whose request and response halves progress
/// independently while one connection owner alternates its client handles.
// Duplex stream and tunnel owners live in runtime/duplex/streams.zig.
const duplex_streams = @import("runtime/duplex/streams.zig");

pub const ClientDuplexStream = duplex_streams.ClientDuplexStream;
pub const DuplexRequestEvent = duplex_streams.DuplexRequestEvent;
pub const DuplexRequestDrainResult = duplex_streams.DuplexRequestDrainResult;
pub const ServerDuplexStream = duplex_streams.ServerDuplexStream;
pub const Tunnel = duplex_streams.Tunnel;
pub const TunnelWriter = duplex_streams.TunnelWriter;

pub const Http2ConcurrentEngine = concurrent.Engine(
    Connection,
    ServerDuplexStream,
    StreamingResponseOptions,
);

pub const ResponseWriter = struct {
    connection: *Connection,
    stream_id: u31,
    expected_length: ?usize,
    written: usize = 0,
    finished: bool = false,

    /// Cancel an unfinished response and release its stream.
    ///
    /// Callers should normally `defer writer.deinit()` immediately after
    /// `startResponse`. Successful finish/reset methods make this a no-op.
    pub fn deinit(self: *ResponseWriter) void {
        if (self.finished) return;
        self.connection.terminateOwnedStream(self.stream_id, .cancel) catch {};
        self.finished = true;
    }

    /// Write one DATA chunk while keeping the response open.
    ///
    /// The call blocks only when HTTP/2 send windows are exhausted and pumps
    /// WINDOW_UPDATE/SETTINGS/PING using the connection's existing send path.
    pub fn write(
        self: *ResponseWriter,
        data: []const u8,
    ) Error!void {
        return self.writeUntil(data, null);
    }

    pub fn writeWithTimeout(
        self: *ResponseWriter,
        data: []const u8,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeWithDeadline(data, .fromNow(self.connection.io, .{
            .raw = timeout,
            .clock = .awake,
        }));
    }

    pub fn writeWithDeadline(
        self: *ResponseWriter,
        data: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.writeUntil(data, deadline);
    }

    fn writeUntil(
        self: *ResponseWriter,
        data: []const u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        try self.ensureWritable();
        try self.reserveLength(data.len, false);
        var sent: usize = 0;
        self.connection.writeDataTrackedUntil(
            self.stream_id,
            data,
            false,
            &sent,
            deadline,
        ) catch |err| {
            self.written += sent;
            return err;
        };
        self.written += sent;
    }

    /// Write the final DATA chunk with END_STREAM.
    pub fn finishData(
        self: *ResponseWriter,
        data: []const u8,
    ) Error!void {
        return self.finishDataUntil(data, null);
    }

    pub fn finishDataWithTimeout(
        self: *ResponseWriter,
        data: []const u8,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishDataWithDeadline(data, .fromNow(
            self.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn finishDataWithDeadline(
        self: *ResponseWriter,
        data: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.finishDataUntil(data, deadline);
    }

    fn finishDataUntil(
        self: *ResponseWriter,
        data: []const u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        try self.ensureWritable();
        try self.reserveLength(data.len, true);
        var sent: usize = 0;
        self.connection.writeDataTrackedUntil(
            self.stream_id,
            data,
            true,
            &sent,
            deadline,
        ) catch |err| {
            self.written += sent;
            return err;
        };
        self.written += sent;
        self.finishState();
    }

    /// Finish a response with an empty END_STREAM DATA frame.
    pub fn finish(self: *ResponseWriter) Error!void {
        return self.finishData(&.{});
    }

    pub fn finishWithTimeout(
        self: *ResponseWriter,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        return self.finishDataWithTimeout(&.{}, timeout);
    }

    pub fn finishWithDeadline(
        self: *ResponseWriter,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        return self.finishDataWithDeadline(&.{}, deadline);
    }

    /// Cumulative application body bytes committed by successful DATA
    /// bursts. This advances even when a bounded write later times out, so a
    /// caller can retry only the uncommitted suffix.
    pub fn committedBytes(self: ResponseWriter) usize {
        return self.written;
    }

    /// Finish with response trailers. Trailers carry END_STREAM themselves.
    pub fn finishTrailers(self: *ResponseWriter, trailers: []const http2.Hpack.HeaderField) Error!void {
        return self.finishTrailersUntil(trailers, null);
    }

    pub fn finishTrailersWithDeadline(self: *ResponseWriter, trailers: []const http2.Hpack.HeaderField, deadline: std.Io.Clock.Timestamp) ResponseTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.finishTrailersUntil(trailers, deadline);
    }

    pub fn finishTrailersWithTimeout(self: *ResponseWriter, trailers: []const http2.Hpack.HeaderField, timeout: std.Io.Duration) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishTrailersWithDeadline(trailers, .fromNow(self.connection.io, .{ .raw = timeout, .clock = .awake }));
    }

    fn finishTrailersUntil(self: *ResponseWriter, trailers: []const http2.Hpack.HeaderField, deadline: ?std.Io.Clock.Timestamp) Error!void {
        try self.ensureWritable();
        try self.reserveLength(0, true);
        try validateHeaderBlock(trailers, .response_trailers);
        try self.connection.writeHeadersUntil(
            self.stream_id,
            trailers,
            true,
            deadline,
        );
        self.finishState();
    }

    pub fn reset(
        self: *ResponseWriter,
        error_code: http2.ErrorCode,
    ) Error!void {
        try self.ensureWritable();
        defer self.finished = true;
        return self.connection.terminateOwnedStream(self.stream_id, error_code);
    }

    fn ensureWritable(self: ResponseWriter) Error!void {
        if (self.finished) return error.ConnectionClosed;
        if (!self.connection.outboundStreamIsActive(self.stream_id)) {
            return error.StreamReset;
        }
    }

    fn reserveLength(
        self: ResponseWriter,
        additional: usize,
        finishing: bool,
    ) Error!void {
        const total = std.math.add(
            usize,
            self.written,
            additional,
        ) catch return error.MessageTooLarge;
        if (self.expected_length) |expected| {
            if (total > expected or (finishing and total != expected)) {
                return error.InvalidContentLength;
            }
        }
    }

    fn finishState(self: *ResponseWriter) void {
        self.connection.releasePeerStream(self.stream_id);
        self.finished = true;
    }
};

pub const H2cUpgradeResult = struct {
    connection: Connection,
    upgrade_response: http1_runtime.OwnedResponse,

    pub fn deinit(self: *H2cUpgradeResult, allocator: std.mem.Allocator) void {
        self.upgrade_response.deinit(allocator);
        self.connection.close();
        self.* = undefined;
    }
};

pub const H2cUpgradeRequest = struct {
    connection: Connection,
    request: http1_runtime.OwnedRequest,
    stream_id: u31 = 1,

    pub fn deinit(self: *H2cUpgradeRequest, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
        self.connection.close();
        self.* = undefined;
    }
};

pub const ExtendedConnectRequest = struct {
    stream_id: u31,
    headers: []http2.Hpack.HeaderField,
    method: []const u8,
    path: []const u8,
    scheme: []const u8,
    authority: ?[]const u8,
    protocol: []const u8,
    priority: http2.ExtensiblePriority = .{},

    pub fn deinit(self: *ExtendedConnectRequest, allocator: std.mem.Allocator) void {
        freeHeaders(allocator, self.headers);
        self.* = undefined;
    }
};

pub const ExtendedConnectResponse = struct {
    status: u16,
    headers: []http2.Hpack.HeaderField,
    tunnel: Tunnel,

    pub fn deinit(self: *ExtendedConnectResponse, allocator: std.mem.Allocator) void {
        freeHeaders(allocator, self.headers);
        self.* = undefined;
    }
};

/// Final response to an Extended CONNECT attempt. A successful 2xx response
/// owns a tunnel; a rejected response owns its complete bounded HTTP response
/// metadata/body and has already retired the local HTTP/2 stream.
pub const ExtendedConnectAttempt = struct {
    status: u16,
    headers: []http2.Hpack.HeaderField,
    body: []u8 = &.{},
    trailers: []http2.Hpack.HeaderField = &.{},
    tunnel: ?Tunnel,

    pub fn accepted(self: ExtendedConnectAttempt) bool {
        return self.tunnel != null;
    }

    pub fn responseHeader(
        self: ExtendedConnectAttempt,
        name: []const u8,
    ) ?[]const u8 {
        return findHeader(self.headers, name);
    }

    pub fn deinit(
        self: *ExtendedConnectAttempt,
        allocator: std.mem.Allocator,
    ) void {
        const tunnel = self.tunnel;
        freeHeaders(allocator, self.headers);
        allocator.free(self.body);
        freeHeaders(allocator, self.trailers);
        self.* = undefined;
        if (tunnel) |value| {
            value.connection.abandonExtendedConnect(value.stream_id);
        }
    }

    pub fn requireAccepted(
        self: *ExtendedConnectAttempt,
    ) Error!ExtendedConnectResponse {
        const tunnel = self.tunnel orelse return error.InvalidStatus;
        const response: ExtendedConnectResponse = .{
            .status = self.status,
            .headers = self.headers,
            .tunnel = tunnel,
        };
        std.debug.assert(self.body.len == 0);
        std.debug.assert(self.trailers.len == 0);
        self.* = undefined;
        return response;
    }
};

pub const ConnectUdpSession = http3.connect_udp.CapsuleSession(
    http2.ErrorCode,
    Tunnel,
    TunnelWriteProgress,
);

pub const ConnectIpSession = http3.connect_ip.CapsuleSession(
    http2.ErrorCode,
    Tunnel,
    TunnelWriteProgress,
);

pub const AcceptedConnectUdp = struct {
    target: http3.connect_udp.Target,
    session: ConnectUdpSession,
};

pub const AcceptedConnectIp = struct {
    scope: http3.connect_ip.Scope,
    session: ConnectIpSession,
};

pub const OwnedTunnelData = struct {
    frame: RetainedFrame,
    data: []const u8,
    end_stream: bool,

    pub fn deinit(self: *OwnedTunnelData, allocator: std.mem.Allocator) void {
        self.frame.deinit(allocator);
        self.* = undefined;
    }
};

pub const TunnelWriteProgress = struct {
    /// Exact application-byte prefix committed by complete DATA bursts.
    committed_bytes: usize = 0,
    /// True only when the DATA END_STREAM flag reached the transport.
    fin_committed: bool = false,
};

pub const OwnedGoAway = struct {
    frame: OwnedFrame,
    goaway: http2.GoAwayPayload,

    pub fn deinit(self: *OwnedGoAway, allocator: std.mem.Allocator) void {
        self.frame.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedResetStream = struct {
    frame: OwnedFrame,
    reset: http2.ResetStreamPayload,

    pub fn deinit(self: *OwnedResetStream, allocator: std.mem.Allocator) void {
        self.frame.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedWindowUpdate = struct {
    frame: OwnedFrame,
    window_update: http2.WindowUpdatePayload,

    pub fn deinit(self: *OwnedWindowUpdate, allocator: std.mem.Allocator) void {
        self.frame.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedFrame = frame_io.OwnedFrame;
pub const RetainedFrame = frame_io.RetainedFrame;

pub fn readFrame(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, limits: Limits) Error!OwnedFrame {
    return frame_io.readOwned(
        allocator,
        io,
        stream,
        @min(limits.max_frame_payload, limits.max_frame_size),
    );
}

fn readFrameTransport(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    limits: Limits,
) Error!OwnedFrame {
    return frame_io.readOwnedTransport(
        allocator,
        transport,
        @min(limits.max_frame_payload, limits.max_frame_size),
    );
}

fn readFrameTransportWithDeadline(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    limits: Limits,
    deadline: ?std.Io.Clock.Timestamp,
) Error!OwnedFrame {
    return frame_io.readOwnedTransportWithDeadline(
        allocator,
        transport,
        @min(limits.max_frame_payload, limits.max_frame_size),
        deadline,
    );
}

pub fn writeFrame(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    frame_type: http2.FrameType,
    flags: u8,
    stream_id: u31,
    payload: []const u8,
) Error!void {
    return writeFrameTransport(
        allocator,
        tcpTransport(io, stream),
        frame_type,
        flags,
        stream_id,
        payload,
    );
}

pub fn validateLocalLimits(limits: Limits) Error!void {
    if (limits.webtransport.enabled and !limits.enable_connect_protocol) return error.InvalidSetting;
    // Both values are emitted verbatim in SETTINGS and therefore must fit the
    // protocol's 32-bit setting value. Silently saturating them would make
    // the local decoder policy disagree with the limit advertised on wire.
    if (limits.header_table_size > std.math.maxInt(u32) or
        limits.max_header_list_size > std.math.maxInt(u32))
    {
        return error.InvalidSetting;
    }
    if (limits.initial_window_size > std.math.maxInt(i31)) return error.InvalidSetting;
    if (limits.initial_connection_window_size < default_flow_window or
        limits.initial_connection_window_size > std.math.maxInt(i31))
    {
        return error.InvalidSetting;
    }
    if (limits.adaptive_window and
        (limits.adaptive_window_max < limits.initial_window_size or
            limits.adaptive_window_max <
                limits.initial_connection_window_size or
            limits.adaptive_window_max > std.math.maxInt(i31)))
    {
        return error.InvalidSetting;
    }
    if (limits.max_frame_size < default_max_frame_size or limits.max_frame_size > max_max_frame_size) return error.InvalidSetting;
    if (limits.max_continuation_frames) |limit| if (limit == 0) return error.InvalidSetting;
    if (limits.max_idle_priority_updates == 0) return error.InvalidSetting;
    if (limits.max_pending_ping_frames == 0) return error.InvalidSetting;
    if (limits.ping_enforcement) |policy| try policy.validate();
    if (limits.reset_stream_duration.nanoseconds < 0 or
        limits.terminal_cleanup_timeout.nanoseconds < 0)
    {
        return error.InvalidSetting;
    }
}

pub fn calcMaxContinuationFrames(header_max: usize, frame_max: usize) usize {
    const min_frames_for_list = @max(header_max / frame_max, 1);
    const padding = min_frames_for_list >> 2;
    return @max(min_frames_for_list +| padding, 5);
}

pub fn writeInitialSettings(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, limits: Limits, role: Role) Error!void {
    return writeInitialSettingsTransportMaybeBefore(
        allocator,
        tcpTransport(io, stream),
        limits,
        role,
        null,
    );
}

pub fn writeInitialSettingsTransportMaybeBefore(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    limits: Limits,
    role: Role,
    deadline: ?std.Io.Clock.Timestamp,
) Error!void {
    const settings = try settingsForLimits(limits, role);
    var payload_buf: [max_settings_payload_len]u8 = undefined;
    const payload = try encodeSettingsPayloadInto(&payload_buf, settings.buf[0..settings.count]);
    try bootstrap_output.writeSettings(
        allocator,
        transport,
        payload,
        deadline,
    );
}

pub fn writeInitialConnectionWindowTransportMaybeBefore(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    limits: Limits,
    deadline: ?std.Io.Clock.Timestamp,
) Error!void {
    try bootstrap_output.writeConnectionWindow(
        allocator,
        transport,
        limits.initial_connection_window_size,
        default_flow_window,
        deadline,
    );
}

pub fn decodeOwnedHeaders(
    allocator: std.mem.Allocator,
    block: []const u8,
    limits: Limits,
    decoder: *http2.Hpack.Decoder,
) Error![]http2.Hpack.HeaderField {
    return decoder.decodeBlockOwnedWithLimit(
        allocator,
        block,
        limits.max_header_fields,
        limits.max_header_list_size,
    ) catch |err| switch (err) {
        error.BufferTooShort,
        error.HeaderListTooLarge,
        => return error.MessageTooLarge,
        else => |e| return e,
    };
}

/// Use caller stack storage for ordinary header counts and allocate an exact
/// slice only for unusually large field sets. Pointer identity records
/// ownership without another flag at each short-lived assembly call site.
pub fn stackFirstHeaderFieldBuffer(
    allocator: std.mem.Allocator,
    stack: []http2.Hpack.HeaderField,
    required: usize,
) std.mem.Allocator.Error![]http2.Hpack.HeaderField {
    if (required <= stack.len) return stack[0..required];
    return allocator.alloc(http2.Hpack.HeaderField, required);
}

pub fn freeStackFirstHeaderFieldBuffer(
    allocator: std.mem.Allocator,
    stack: []http2.Hpack.HeaderField,
    fields: []http2.Hpack.HeaderField,
) void {
    if (fields.ptr != stack.ptr) allocator.free(fields);
}

pub fn appendAutomaticDateHeaderValue(
    fields: *std.ArrayList(http2.Hpack.HeaderField),
    date: ?*const [http_date.value_len]u8,
) void {
    const value = date orelse return;
    if (findHeader(fields.items, "date") != null) return;
    fields.appendAssumeCapacity(.{
        .name = "date",
        .value = value,
    });
}

pub fn freeHeaders(allocator: std.mem.Allocator, headers: []http2.Hpack.HeaderField) void {
    if (headers.len != 0) {
        if (headers[0].block_storage != null) {
            http2.Hpack.freeOwnedFields(allocator, headers);
            return;
        }
    }
    for (headers) |header| {
        allocator.free(header.name);
        allocator.free(header.value);
    }
    allocator.free(headers);
}

/// Free a runtime-owned header block produced by the HTTP/2 layer or by
/// `grpc.call.rewriteResponseHeaders`.
pub fn freeHeaderFields(
    allocator: std.mem.Allocator,
    headers: []http2.Hpack.HeaderField,
) void {
    freeHeaders(allocator, headers);
}

pub const testing = struct {
    pub fn enablePeerExtensiblePriorities(
        connection: *Connection,
    ) void {
        connection.peer_no_rfc7540_priorities = true;
    }

    pub fn recvConnectionWindowValue(
        connection: *const Connection,
    ) i64 {
        return connection.recv_connection_window.value;
    }

    pub fn recvStreamWindow(connection: *Connection, stream_id: u31) Error!*FlowWindow {
        return connection.recvStreamWindow(stream_id);
    }

    pub fn receiveDataPayload(connection: *Connection, stream_id: u31, frame: http2.Frame) Error!ReceivedDataPayload {
        return connection.receiveDataPayload(stream_id, frame);
    }

    pub fn releaseReceivedDataCapacity(connection: *Connection, stream_id: u31, data: ReceivedDataPayload, end_stream: bool) Error!void {
        defer connection.releaseDataFrameBudget(data);
        return connection.releaseReceivedDataCapacity(stream_id, data, end_stream);
    }

    pub fn queueAdaptiveWindowTarget(connection: *Connection, target: u32) Error!void {
        return connection.queueAdaptiveWindowTarget(target);
    }

    pub fn setSendConnectionWindow(
        connection: *Connection,
        value: i64,
    ) void {
        connection.send_connection_window.value = value;
    }

    pub fn localErrorResetCount(connection: *const Connection) usize {
        return connection.local_error_reset_streams;
    }

    pub fn findHeader(
        headers: []const http2.Hpack.HeaderField,
        name: []const u8,
    ) ?[]const u8 {
        for (headers) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, name)) {
                return header.value;
            }
        }
        return null;
    }

    pub fn receivePushPromise(
        connection: *Connection,
        frame: http2.Frame,
    ) Error!void {
        return connection.receivePushPromise(frame);
    }

    pub fn receivePriorityUpdate(
        connection: *Connection,
        frame: http2.Frame,
    ) Error!void {
        if (!try connection.handleConnectionFrame(frame)) {
            return error.UnexpectedFrame;
        }
    }

    pub fn reserveNextClientStreamId(
        connection: *Connection,
    ) Error!u31 {
        return connection.reserveNextClientStreamId();
    }

    pub fn sendCompleteRequest(
        connection: *Connection,
        options: RequestOptions,
    ) Error!Connection.PendingResponse {
        return connection.sendCompleteRequest(options);
    }

    pub fn releaseLocalStream(
        connection: *Connection,
        stream_id: u31,
    ) void {
        connection.releaseLocalStream(stream_id);
    }

    pub fn releasePeerStream(
        connection: *Connection,
        stream_id: u31,
    ) void {
        connection.releasePeerStream(stream_id);
    }

    pub fn addActiveLocalStream(
        connection: *Connection,
        stream_id: u31,
    ) Error!void {
        return connection.addActiveLocalStream(stream_id);
    }

    pub fn addActivePeerStream(
        connection: *Connection,
        stream_id: u31,
    ) Error!void {
        return connection.addActivePeerStream(stream_id);
    }

    pub fn sendStreamWindow(
        connection: *Connection,
        stream_id: u31,
    ) Error!*FlowWindow {
        return connection.sendStreamWindow(stream_id);
    }

    pub fn readOwnedFrame(
        connection: *Connection,
    ) Error!OwnedFrame {
        return connection.readOwnedFrame();
    }

    pub fn readOwnedServerDuplexFrameWithDeadline(connection: *Connection, stream_id: u31, deadline: std.Io.Clock.Timestamp) Error!RetainedFrame {
        return connection.readOwnedServerDuplexFrameWithDeadline(stream_id, deadline);
    }

    pub fn copyBorrowedFrame(connection: *Connection, borrowed: frame_io.BorrowedFrame) Error!OwnedFrame {
        return connection.copyBorrowedFrame(borrowed);
    }

    pub fn queuePendingApplicationFrame(
        connection: *Connection,
        frame: OwnedFrame,
    ) Error!void {
        return connection.queuePendingApplicationFrame(frame);
    }

    pub fn recoverPendingApplicationFrameAfterQueueFailure(
        connection: *Connection,
        frame: OwnedFrame,
    ) void {
        connection.recoverPendingApplicationFrameAfterQueueFailure(frame);
    }

    pub fn deinitPendingApplicationFrames(
        connection: *Connection,
    ) void {
        connection.borrowed_pending_frame.deinit(connection.allocator);
        for (connection.pending_application_frames.items[connection.pending_application_frame_head..]) |*frame| frame.deinit(connection.allocator);
        connection.pending_application_frames.deinit(connection.allocator);
        connection.pending_application_frames = .empty;
        connection.pending_application_frame_head = 0;
        connection.pending_application_overflow.deinit(connection.allocator);
    }

    pub fn handleConnectionFrame(
        connection: *Connection,
        frame: http2.Frame,
    ) Error!bool {
        return connection.handleConnectionFrame(frame);
    }

    pub fn hasActivePeerStream(
        connection: *const Connection,
        stream_id: u31,
    ) bool {
        return connection.active_peer_index.count() != 0 and
            connection.active_peer_index.contains(stream_id);
    }

    pub fn hasStreamWindow(
        connection: *const Connection,
        stream_id: u31,
    ) bool {
        return (connection.send_stream_window_index.count() != 0 and
            connection.send_stream_window_index.contains(stream_id)) or
            connection.hasRecvStreamWindow(stream_id);
    }

    pub fn hasResponseSemantics(
        connection: *const Connection,
        stream_id: u31,
    ) bool {
        return connection.response_semantics_index.count() != 0 and
            connection.response_semantics_index.contains(stream_id);
    }

    pub fn hasPeerPriority(
        connection: *const Connection,
        stream_id: u31,
    ) bool {
        return connection.priority_state.get(stream_id) != null or
            connection.priority_state.containsIdleRequest(stream_id);
    }

    pub fn lastPeerClientStreamId(connection: *const Connection) u31 {
        return connection.last_peer_client_stream_id;
    }

    pub fn pendingRequestCount(connection: *const Connection) usize {
        return connection.pendingRequestCount();
    }

    pub fn gracefulPreadmittedCount(
        connection: *const Connection,
    ) usize {
        return connection.graceful_preadmitted_peer_streams.items.len;
    }

    pub fn writeHeaders(
        connection: *Connection,
        stream_id: u31,
        headers: []const http2.Hpack.HeaderField,
        end_stream: bool,
    ) Error!void {
        return connection.writeHeaders(
            stream_id,
            headers,
            end_stream,
        );
    }

    pub fn writeData(
        connection: *Connection,
        stream_id: u31,
        data: []const u8,
        end_stream: bool,
    ) Error!void {
        return connection.writeData(stream_id, data, end_stream);
    }

    pub fn writeRawFrame(
        connection: *Connection,
        frame_type: http2.FrameType,
        flags: u8,
        stream_id: u31,
        payload: []const u8,
    ) Error!void {
        return writeFrameTransport(
            connection.allocator,
            connection.transportForIo(),
            frame_type,
            flags,
            stream_id,
            payload,
        );
    }
};

pub fn requestAuthority(headers: []const http2.Hpack.HeaderField) ?[]const u8 {
    if (findHeader(headers, ":authority")) |authority| return authority;
    return findHeader(headers, "host");
}

pub fn validateH2cUpgradeRequest(request: http1.Request) Error!void {
    if (request.version != .http_1_1) return error.InvalidHeader;
    if (request.method == .CONNECT) return error.InvalidHeader;

    const upgrade = (try optionalHttp1SingletonHeader(request.headers, "upgrade")) orelse return error.InvalidHeader;
    if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, upgrade, " \t"), "h2c")) return error.InvalidHeader;
    if (!headersContainHttpToken(request.headers, "connection", "upgrade")) return error.InvalidHeader;
    if (!headersContainHttpToken(request.headers, "connection", "http2-settings")) return error.InvalidHeader;
}

pub fn decodeHttp2SettingsHeader(allocator: std.mem.Allocator, value: []const u8) Error![]u8 {
    const len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(value) catch return error.InvalidHeader;
    const decoded = try allocator.alloc(u8, len);
    errdefer allocator.free(decoded);
    std.base64.url_safe_no_pad.Decoder.decode(decoded, value) catch return error.InvalidHeader;
    const settings = try http2.parseSettings(allocator, decoded);
    defer allocator.free(settings);
    return decoded;
}

pub fn optionalHttp1SingletonHeader(headers: []const http1.Header, name: []const u8) Error!?[]const u8 {
    var found: ?[]const u8 = null;
    for (headers) |header| {
        if (!header.eqlName(name)) continue;
        if (found != null) return error.InvalidHeader;
        found = header.value;
    }
    return found;
}

pub fn awakeNowNanos(io: std.Io) u64 {
    const now = std.Io.Clock.awake.now(io).nanoseconds;
    if (now <= 0) return 0;
    return std.math.cast(u64, now) orelse std.math.maxInt(u64);
}

pub fn reservedInternalPingPayload(data: [8]u8) bool {
    return std.mem.eql(u8, &data, &graceful_shutdown_ping_payload) or
        bdp.isProbePayload(data);
}

fn headersContainHttpToken(headers: []const http1.Header, name: []const u8, needle: []const u8) bool {
    for (headers) |header| {
        if (header.eqlName(name) and containsHttpToken(header.value, needle)) return true;
    }
    return false;
}

pub const max_settings_payload_len = 15 * 6;

const SettingsForLimits = struct {
    buf: [15]http2.Setting,
    count: usize,
};

pub fn advertisedMaxFrameSize(limits: Limits) usize {
    // Never advertise a frame larger than the local allocation ceiling; a
    // peer would be entitled to send it and the local decoder would reject it
    // with MessageTooLarge. RFC 9113 still requires at least 16 KiB.
    return @max(
        default_max_frame_size,
        @min(limits.max_frame_size, limits.max_frame_payload),
    );
}

pub fn settingsForLimits(limits: Limits, role: Role) Error!SettingsForLimits {
    try validateLocalLimits(limits);
    var settings_buf: [15]http2.Setting = undefined;
    var count: usize = 0;
    settings_buf[count] = .{ .id = .header_table_size, .value = @intCast(limits.header_table_size) };
    count += 1;
    settings_buf[count] = .{ .id = .initial_window_size, .value = limits.initial_window_size };
    count += 1;
    if (limits.max_concurrent_streams) |max_streams| {
        settings_buf[count] = .{ .id = .max_concurrent_streams, .value = max_streams };
        count += 1;
    }
    const advertised_frame_size = advertisedMaxFrameSize(limits);
    if (advertised_frame_size != default_max_frame_size) {
        settings_buf[count] = .{ .id = .max_frame_size, .value = @intCast(advertised_frame_size) };
        count += 1;
    }
    settings_buf[count] = .{ .id = .max_header_list_size, .value = @intCast(limits.max_header_list_size) };
    count += 1;
    if (limits.enable_connect_protocol) {
        settings_buf[count] = .{ .id = .enable_connect_protocol, .value = 1 };
        count += 1;
    }
    if (limits.no_rfc7540_priorities) {
        settings_buf[count] = .{
            .id = .no_rfc7540_priorities,
            .value = 1,
        };
        count += 1;
    }
    if (role == .client) {
        settings_buf[count] = .{
            .id = .enable_push,
            .value = @intFromBool(limits.enable_push),
        };
        count += 1;
    }
    if (limits.webtransport.enabled) {
        var wt_settings: [7]http2.Setting = undefined;
        const values = limits.webtransport.write(&wt_settings);
        @memcpy(settings_buf[count..][0..values.len], values);
        count += values.len;
    }
    return .{ .buf = settings_buf, .count = count };
}

pub fn encodeSettingsPayloadInto(out: *[max_settings_payload_len]u8, settings: []const http2.Setting) Error![]const u8 {
    var pos: usize = 0;
    for (settings) |setting| {
        try http2.validateSetting(setting.id, setting.value);
        std.mem.writeInt(u16, out[pos..][0..2], @intFromEnum(setting.id), .big);
        pos += 2;
        std.mem.writeInt(u32, out[pos..][0..4], setting.value, .big);
        pos += 4;
    }
    return out[0..pos];
}

fn writeSettingsPayloadForLimits(allocator: std.mem.Allocator, payload: *std.ArrayList(u8), limits: Limits, role: Role) Error!void {
    const settings = try settingsForLimits(limits, role);
    try http2.writeSettings(payload, allocator, settings.buf[0..settings.count]);
}

pub fn limitsToHttp1(limits: Limits) http1_runtime.Limits {
    return .{
        .local_address = limits.local_address,
        .network_interface = limits.network_interface,
        .address_resolver = limits.address_resolver,
        .address_connect_policy = limits.address_connect_policy,
        .connect_timeout = limits.connect_timeout,
        .max_head_bytes = limits.max_header_list_size,
        .max_body_bytes = limits.max_body_bytes,
        .request_head_timeout = limits.handshake_timeout,
        .response_head_timeout = limits.handshake_timeout,
    };
}

pub fn containsHttpToken(value: []const u8, needle: []const u8) bool {
    var tokens = std.mem.splitScalar(u8, value, ',');
    while (tokens.next()) |raw| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, raw, " \t"), needle)) return true;
    }
    return false;
}

pub fn readExact(io: std.Io, stream: net.Stream, buffer: []u8) ReadExactError!void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        const n = try readSome(io, stream, buffer[offset..]);
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }
}

fn readExactTransport(
    transport: RuntimeTransport,
    buffer: []u8,
) Error!void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        const n = try transport.read(buffer[offset..]);
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }
}

pub fn readExactTransportWithDeadline(
    transport: RuntimeTransport,
    buffer: []u8,
    deadline: ?std.Io.Clock.Timestamp,
) Error!void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        const n = if (deadline) |absolute|
            try transport.readWithDeadline(buffer[offset..], absolute)
        else
            try transport.read(buffer[offset..]);
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }
}

pub fn writeAll(io: std.Io, stream: net.Stream, bytes: []const u8) net.Stream.Writer.Error!void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = try io.vtable.netWrite(io.userdata, stream.socket.handle, bytes[written..], &.{""}, 0);
        if (n == 0) return error.SocketUnconnected;
        written += n;
    }
}

pub fn expectClientConnectionErrorGoAway(
    frame_type: http2.FrameType,
    stream_id: u31,
    payload: []const u8,
    expected_client_error: anyerror,
    expected_code: http2.ErrorCode,
    expected_debug_data: []const u8,
) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        frame_type: http2.FrameType,
        stream_id: u31,
        payload: []const u8,
        expected_code: http2.ErrorCode,
        expected_debug_data: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var request = try connection.readRequest();
            defer request.deinit(shared.server.allocator);
            try writeFrame(
                shared.server.allocator,
                shared.server.io,
                connection.stream,
                shared.frame_type,
                0,
                shared.stream_id,
                shared.payload,
            );
            var goaway = try connection.readGoAwayWithTimeout(
                .fromSeconds(2),
            );
            defer goaway.deinit(shared.server.allocator);
            try std.testing.expectEqual(
                shared.expected_code,
                goaway.goaway.error_code,
            );
            try std.testing.expectEqual(@as(u31, 0), goaway.goaway.last_stream_id);
            try std.testing.expectEqualStrings(
                shared.expected_debug_data,
                goaway.goaway.debug_data,
            );
        }
    };

    var shared = Shared{
        .server = &server,
        .frame_type = frame_type,
        .stream_id = stream_id,
        .payload = payload,
        .expected_code = expected_code,
        .expected_debug_data = expected_debug_data,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();
    try std.testing.expectError(expected_client_error, client.request(.{
        .path = "/invalid-frame-envelope",
        .authority = "localhost",
    }));
    try std.testing.expect(!client.isReusable());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

pub fn expectServerInitialConnectionErrorGoAway(
    frame_type: http2.FrameType,
    stream_id: u31,
    payload_bytes: []const u8,
    expected_server_error: anyerror,
    expected_code: http2.ErrorCode,
    expected_debug_data: []const u8,
) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .handshake_timeout = .fromSeconds(2) },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        expected_server_error: anyerror,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            if (shared.server.accept()) |connection_value| {
                var connection = connection_value;
                connection.close();
                shared.err = error.TestUnexpectedResult;
            } else |err| {
                if (err != shared.expected_server_error) shared.err = err;
            }
        }
    };

    var shared = Shared{
        .server = &server,
        .expected_server_error = expected_server_error,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeAll(io, stream, http2.connection_preface);
    try writeFrame(
        allocator,
        io,
        stream,
        frame_type,
        0,
        stream_id,
        payload_bytes,
    );

    var goaway = try readFrame(allocator, io, stream, .{});
    defer goaway.deinit(allocator);
    try std.testing.expectEqual(
        http2.FrameType.goaway,
        goaway.frame.header.frame_type,
    );
    const payload = try http2.GoAwayPayload.parse(goaway.frame);
    try std.testing.expectEqual(
        expected_code,
        payload.error_code,
    );
    try std.testing.expectEqualStrings(expected_debug_data, payload.debug_data);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

pub fn queueTestPendingRequest(
    connection: *Connection,
    stream_id: u31,
    path: []const u8,
    queue_allocator: std.mem.Allocator,
) !void {
    const headers = try connection.allocator.alloc(http2.Hpack.HeaderField, 4);
    errdefer connection.allocator.free(headers);
    headers[0] = .{ .name = try connection.allocator.dupe(u8, ":method"), .value = try connection.allocator.dupe(u8, "GET") };
    headers[1] = .{ .name = try connection.allocator.dupe(u8, ":path"), .value = try connection.allocator.dupe(u8, path) };
    headers[2] = .{ .name = try connection.allocator.dupe(u8, ":scheme"), .value = try connection.allocator.dupe(u8, "https") };
    headers[3] = .{ .name = try connection.allocator.dupe(u8, ":authority"), .value = try connection.allocator.dupe(u8, "localhost") };
    errdefer freeHeaders(connection.allocator, headers);

    const body = try connection.allocator.alloc(u8, 0);
    errdefer connection.allocator.free(body);
    var request = try connection.requestFromHeadersAndBody(stream_id, headers, body, &.{});
    errdefer request.deinit(connection.allocator);

    try connection.appendPendingRequest(request, queue_allocator);
    request = undefined;
}

test {
    _ = @import("runtime/tests.zig");
}
