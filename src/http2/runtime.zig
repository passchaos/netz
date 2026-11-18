const content_digest = @import("../http/digest.zig");
const std = @import("std");
const test_socket = @import("../internal/test_socket.zig");
const builtin = @import("builtin");
const http2 = @import("mod.zig");
pub const http3 = @import("../http3/mod.zig");
pub const http1 = @import("../http1/mod.zig");
const http1_runtime = http1.runtime;
const frame_io = @import("runtime/frame/io.zig");
const frame_wire = @import("runtime/frame/wire.zig");
const flow_window = @import("runtime/flow/window.zig");
const flow_output = @import("runtime/flow/output.zig");
const outbound_headers = @import("runtime/headers/connection.zig");
const client_authority = @import("runtime/client/authority.zig");
const client_duplex_owner = @import("runtime/duplex/client_owner.zig");
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
test {
    _ = @import("runtime/concurrent_tests.zig");
    _ = @import("runtime/settings/webtransport_tests.zig");
    _ = @import("runtime/client/authority_tests.zig");
    _ = @import("runtime/client/authority_deadline_tests.zig");
    _ = @import("runtime/client/authority_uri_tests.zig");
    _ = @import("runtime/headers/authority_reuse_tests.zig");
    _ = client_authority;
    _ = endpoint_host;
    _ = host_connect;
    _ = @import("runtime/connect/deadline_tests.zig");
    _ = @import("runtime/connect/output_deadline_tests.zig");
    _ = @import("runtime/connect/owned_accept.zig");
    _ = @import("runtime/connect/protocol_error_tests.zig");
    _ = @import("runtime/connect/tls_protocol_error_tests.zig");
    _ = @import("runtime/control/extension_deadline_tests.zig");
    _ = @import("runtime/control/output_deadline_tests.zig");
    _ = @import("runtime/control/protocol_error_deadline_tests.zig");
    _ = @import("runtime/control/tls_close_tests.zig");
    _ = @import("runtime/push/output_deadline_tests.zig");
    _ = @import("runtime/request/output_deadline_tests.zig");
    _ = @import("runtime/request/complete_deadline_tests.zig");
    _ = @import("runtime/request/cleanup_deadline_tests.zig");
    _ = @import("runtime/request/batch_output_deadline_tests.zig");
    _ = @import("runtime/request/batch_progress_tests.zig");
    _ = @import("runtime/request/batch_tls_deadline_tests.zig");
    _ = @import("runtime/request/complete_early_response_tests.zig");
    _ = @import("runtime/request/upload_tests.zig");
    _ = @import("runtime/response/output_deadline_tests.zig");
    _ = @import("runtime/response/stream_roundtrip_tests.zig");
    _ = @import("runtime/response/goaway_commitment_tests.zig");
    _ = @import("runtime/stream/termination_tests.zig");
    _ = @import("runtime/stream/peer_termination_tests.zig");
    _ = client_duplex_owner;
    _ = @import("runtime/duplex/client_tests.zig");
    _ = @import("runtime/duplex/client_pump_tests.zig");
    _ = @import("runtime/duplex/server_tests.zig");
    _ = @import("runtime/duplex/pump_tests.zig");
    _ = @import("runtime/ping_probe_tests.zig");
    _ = @import("runtime/ping_enforcement_tests.zig");
    _ = @import("runtime/duplex/response_capacity_tests.zig");
    _ = @import("runtime/duplex/batched_credit_tests.zig");
}
const message_headers = @import("runtime/headers/message.zig");
const push = @import("runtime/push.zig");
const priority_runtime = @import("runtime/priority.zig");
const legacy_priority = @import("runtime/priority/legacy.zig");
pub const peer_metadata = @import("runtime/peer_metadata.zig");
pub const response_scheduler = @import(
    "runtime/response_scheduler.zig",
);
pub const concurrent = @import("runtime/concurrent.zig");
pub const bdp = @import("runtime/bdp.zig");
const ping_policy = @import("runtime/ping_enforcement.zig");
const data_frame_budget = @import("runtime/data_frame_budget.zig");
const stream_io = @import("../internal/stream_io.zig");
const deadline_policy = @import("../internal/deadline.zig");
const accept_deadline = @import("../internal/accept.zig");
pub const http_date = @import("../internal/http_date.zig");
const tcp_connect = @import("../internal/tcp_connect.zig");
const endpoint_host = @import("../internal/endpoint_host.zig");
const host_connect = @import("runtime/client/host_connect.zig");
const socket_options = @import("../internal/socket_options.zig");
const content_coding = @import("../http/content_coding.zig");
const uri_redirect = @import("../http1/runtime/redirect.zig");
const tls_stream = @import("../tls/mod.zig").stream;
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
const validateHeaderListSize = message_headers.validateHeaderListSize;
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
const validateResponseBodyForStatus =
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
const appendFrameBytes = frame_wire.appendFrame;
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
const max_max_frame_size: usize = 16_777_215;
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
    var buffers = [_][]u8{buffer};
    return io.vtable.netRead(
        io.userdata,
        stream.socket.handle,
        &buffers,
    );
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

test "HTTP/2 TLS options preserve stapled OCSP policy" {
    const mapped = verifiedTlsClientOptions("example.com", .{
        .stapled_ocsp = .require,
        .request_ocsp = true,
    });
    try std.testing.expectEqual(StapledOcspPolicy.require, mapped.stapled_ocsp);
    try std.testing.expect(mapped.request_ocsp);
    try std.testing.expectEqualStrings("h2", mapped.alpn_protocols[0]);
}

test "HTTP/2 TLS options forward native certificate environment" {
    const mapped = verifiedTlsClientOptions("example.com", .{
        .environ = std.testing.environ,
    });
    try std.testing.expect(mapped.system_environ != null);
}

test "HTTP/2 TLS options forward reusable native trust store" {
    var store = vail.x509.trust.SystemStore.initEmpty(std.testing.allocator);
    defer store.deinit();
    const mapped = verifiedTlsClientOptions("example.com", .{
        .system_store = &store,
    });
    try std.testing.expect(mapped.system_store != null);
}

test "HTTP/2 TLS options forward bundled root selection" {
    const mapped = verifiedTlsClientOptions("example.com", .{
        .root_source = .bundled,
    });
    try std.testing.expectEqual(tls_stream.RootSource.bundled, mapped.root_source);
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
pub const ClientDuplexStream = struct {
    pub const ConnectionCreditPolicy = @import("runtime/duplex/response_capacity.zig").ConnectionCreditPolicy;
    const response_capacity = @import("runtime/duplex/response_capacity.zig").Capacity(.{
        .Error = Error,
        .automatic = Connection.releaseReceivedDataCapacityUntil,
        .update = Connection.sendWindowUpdatesUntil,
        .window = Connection.recvStreamWindow,
        .connectionTarget = Connection.receiveConnectionWindowTarget,
        .streamTarget = Connection.receiveStreamWindowTarget,
    });
    connection: *Connection,
    stream_id: u31,
    expected_request_length: ?usize,
    request_written: usize = 0,
    request_finished: bool = false,
    head_request: bool = false,
    extended_connect: bool = false,
    response_head_seen: bool = false,
    response_finished: bool = false,
    response_finished_reported: bool = false,
    response_body_bytes: usize = 0,
    response_content_length: ?usize = null,
    response_body_forbidden: bool = false,
    informational_count: usize = 0,
    // The high bit denotes automatic credit. Deferred debt is bounded by the
    // HTTP/2 31-bit stream window and fits the remaining bits.
    deferred_response_credit: u32 = 0x80000000,
    pending_header: DuplexHeaderBlockSlot = .{},
    released: bool = false,
    registered: bool = false,

    pub fn deinit(self: *ClientDuplexStream) void {
        if (!self.released) {
            if (self.request_finished and self.response_finished) {
                self.release();
            } else {
                self.reset(.cancel) catch {};
            }
        }
        self.pending_header.deinit(self.connection.allocator);
        self.releaseOwnership();
        self.* = undefined;
    }

    pub fn streamId(self: ClientDuplexStream) u31 {
        return self.stream_id;
    }

    /// Enable before response input begins. The sole connection owner keeps
    /// stream credit until an application consumer acknowledges encoded bytes.
    pub fn deferResponseStreamCredit(self: *ClientDuplexStream) Error!void {
        if (self.response_head_seen or self.response_finished) return error.UnexpectedFrame;
        self.deferred_response_credit = 0;
    }

    pub fn responseStreamCreditDeferred(self: ClientDuplexStream) bool {
        return self.deferred_response_credit != 0x80000000;
    }

    pub fn releaseResponseStreamCreditWithDeadline(self: *ClientDuplexStream, amount: usize, deadline: std.Io.Clock.Timestamp) ResponseTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return response_capacity.release(self, amount, deadline);
    }

    /// Return the amount granted, or zero when the caller should retain its
    /// consumed-byte acknowledgement until half a window accumulates.
    pub fn releaseResponseStreamCreditBatchedWithDeadline(self: *ClientDuplexStream, amount: usize, deadline: std.Io.Clock.Timestamp) ResponseTimeoutError!usize {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return response_capacity.releaseBatched(self, amount, deadline);
    }

    pub fn write(
        self: *ClientDuplexStream,
        data: []const u8,
    ) Error!DuplexWriteResult {
        return self.writeRequestSlicesUntil(&.{data}, false, null);
    }

    pub fn writeWithDeadline(
        self: *ClientDuplexStream,
        data: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!DuplexWriteResult {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.writeRequestSlicesUntil(&.{data}, false, deadline);
    }

    pub fn writeWithTimeout(
        self: *ClientDuplexStream,
        data: []const u8,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!DuplexWriteResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeWithDeadline(data, .fromNow(self.connection.io, .{
            .raw = timeout,
            .clock = .awake,
        }));
    }

    pub fn writeParts(
        self: *ClientDuplexStream,
        first: []const u8,
        second: []const u8,
    ) Error!DuplexWriteResult {
        return self.writeRequestSlices(&.{ first, second }, false);
    }

    pub fn writePartsWithTimeout(
        self: *ClientDuplexStream,
        first: []const u8,
        second: []const u8,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!DuplexWriteResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writePartsWithDeadline(
            first,
            second,
            .fromNow(self.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn writePartsWithDeadline(
        self: *ClientDuplexStream,
        first: []const u8,
        second: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!DuplexWriteResult {
        return self.writeRequestSlicesWithDeadline(
            &.{ first, second },
            false,
            deadline,
        );
    }

    pub fn finishRequest(
        self: *ClientDuplexStream,
    ) Error!DuplexWriteResult {
        return self.finishRequestData(&.{});
    }

    pub fn finishRequestWithDeadline(
        self: *ClientDuplexStream,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!DuplexWriteResult {
        return self.finishRequestDataWithDeadline(&.{}, deadline);
    }

    pub fn finishRequestWithTimeout(
        self: *ClientDuplexStream,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!DuplexWriteResult {
        return self.finishRequestDataWithTimeout(&.{}, timeout);
    }

    pub fn requestFinished(self: ClientDuplexStream) bool {
        return self.request_finished;
    }

    pub fn responseFinished(self: ClientDuplexStream) bool {
        return self.response_finished;
    }

    pub fn reset(
        self: *ClientDuplexStream,
        error_code: http2.ErrorCode,
    ) Error!void {
        if (self.released) return error.ConnectionClosed;
        defer {
            self.request_finished = true;
            self.response_finished = true;
            self.response_finished_reported = true;
            self.released = true;
            self.releaseOwnership();
        }
        if (self.connection.pending_duplex_sibling_header.getPtr()) |pending| {
            if (pending.header.stream_id == self.stream_id) self.connection.aggregate_timeout_unusable = true;
        }
        if (self.pending_header.getPtr()) |pending| {
            // Both incomplete frame input and an interrupted HPACK decode
            // lose state needed to keep the shared decoder synchronized.
            if (!pending.decode_complete) self.connection.aggregate_timeout_unusable = true;
        }
        return self.connection.terminateOwnedStream(self.stream_id, error_code);
    }

    pub fn finishRequestData(
        self: *ClientDuplexStream,
        data: []const u8,
    ) Error!DuplexWriteResult {
        return self.writeRequestSlicesUntil(&.{data}, true, null);
    }

    pub fn finishRequestDataWithDeadline(
        self: *ClientDuplexStream,
        data: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!DuplexWriteResult {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.writeRequestSlicesUntil(&.{data}, true, deadline);
    }

    pub fn finishRequestDataWithTimeout(
        self: *ClientDuplexStream,
        data: []const u8,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!DuplexWriteResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishRequestDataWithDeadline(data, .fromNow(
            self.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn finishRequestParts(
        self: *ClientDuplexStream,
        first: []const u8,
        second: []const u8,
    ) Error!DuplexWriteResult {
        return self.writeRequestSlices(&.{ first, second }, true);
    }

    pub fn finishRequestPartsWithTimeout(
        self: *ClientDuplexStream,
        first: []const u8,
        second: []const u8,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!DuplexWriteResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishRequestPartsWithDeadline(
            first,
            second,
            .fromNow(self.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn finishRequestPartsWithDeadline(
        self: *ClientDuplexStream,
        first: []const u8,
        second: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!DuplexWriteResult {
        return self.writeRequestSlicesWithDeadline(
            &.{ first, second },
            true,
            deadline,
        );
    }

    pub fn finishRequestTrailers(self: *ClientDuplexStream, trailers: []const http2.Hpack.HeaderField) Error!void {
        return self.finishRequestTrailersUntil(trailers, null);
    }

    pub fn finishRequestTrailersWithDeadline(self: *ClientDuplexStream, trailers: []const http2.Hpack.HeaderField, deadline: std.Io.Clock.Timestamp) ResponseTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.finishRequestTrailersUntil(trailers, deadline);
    }

    pub fn finishRequestTrailersWithTimeout(self: *ClientDuplexStream, trailers: []const http2.Hpack.HeaderField, timeout: std.Io.Duration) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishRequestTrailersWithDeadline(trailers, .fromNow(self.connection.io, .{ .raw = timeout, .clock = .awake }));
    }

    fn finishRequestTrailersUntil(self: *ClientDuplexStream, trailers: []const http2.Hpack.HeaderField, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (self.request_finished or self.released) {
            return error.ConnectionClosed;
        }
        if (self.expected_request_length) |expected| {
            if (self.request_written != expected) {
                return error.InvalidContentLength;
            }
        }
        try validateHeaderBlock(trailers, .request_trailers);
        try self.connection.writeHeadersUntil(self.stream_id, trailers, true, deadline);
        self.request_finished = true;
        self.maybeRelease();
    }

    pub fn writeRequestSlices(
        self: *ClientDuplexStream,
        slices: []const []const u8,
        end_stream: bool,
    ) Error!DuplexWriteResult {
        return self.writeRequestSlicesUntil(slices, end_stream, null);
    }

    pub fn writeRequestSlicesWithTimeout(
        self: *ClientDuplexStream,
        slices: []const []const u8,
        end_stream: bool,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!DuplexWriteResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeRequestSlicesWithDeadline(
            slices,
            end_stream,
            .fromNow(self.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn writeRequestSlicesWithDeadline(
        self: *ClientDuplexStream,
        slices: []const []const u8,
        end_stream: bool,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!DuplexWriteResult {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.writeRequestSlicesUntil(slices, end_stream, deadline);
    }

    /// Cumulative request DATA bytes committed by this duplex stream. This
    /// remains authoritative after a bounded write returns `error.Timeout`.
    pub fn requestCommittedBytes(self: ClientDuplexStream) usize {
        return self.request_written;
    }

    fn writeRequestSlicesUntil(
        self: *ClientDuplexStream,
        slices: []const []const u8,
        end_stream: bool,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!DuplexWriteResult {
        if (self.request_finished or self.released) {
            return error.ConnectionClosed;
        }
        if (deadline) |absolute| {
            _ = try deadline_policy.usableAwake(self.connection.io, absolute);
        }
        var additional: usize = 0;
        for (slices) |slice| {
            additional = std.math.add(usize, additional, slice.len) catch
                return error.MessageTooLarge;
        }
        const total = std.math.add(
            usize,
            self.request_written,
            additional,
        ) catch return error.MessageTooLarge;
        if (self.expected_request_length) |expected| {
            if (total > expected or (end_stream and total != expected)) {
                return error.InvalidContentLength;
            }
        }
        if (additional == 0) {
            var sent: usize = 0;
            self.connection.writeDataDuplexTrackedUntil(
                self.stream_id,
                &.{},
                end_stream,
                &sent,
                deadline,
            ) catch |err| switch (err) {
                error.ResponseAvailable => return .{
                    .written = 0,
                    .response_available = true,
                },
                else => return err,
            };
            if (end_stream) self.request_finished = true;
            self.maybeRelease();
            return .{ .written = 0, .response_available = false };
        }
        var written: usize = 0;
        var remaining_non_empty: usize = 0;
        for (slices) |slice| {
            remaining_non_empty += @intFromBool(slice.len != 0);
        }
        for (slices) |slice| {
            if (slice.len == 0) continue;
            remaining_non_empty -= 1;
            var sent: usize = 0;
            self.connection.writeDataDuplexTrackedUntil(
                self.stream_id,
                slice,
                end_stream and remaining_non_empty == 0,
                &sent,
                deadline,
            ) catch |err| switch (err) {
                error.ResponseAvailable => {
                    written += sent;
                    self.request_written += written;
                    return .{
                        .written = written,
                        .response_available = true,
                    };
                },
                else => {
                    self.request_written += written + sent;
                    return err;
                },
            };
            written += sent;
        }
        self.request_written += written;
        if (end_stream) {
            self.request_finished = true;
            self.maybeRelease();
        }
        return .{ .written = written, .response_available = false };
    }

    pub fn readResponseEvent(
        self: *ClientDuplexStream,
    ) Error!DuplexResponseEvent {
        return (try self.readResponseEventUntil(null, false)).?;
    }

    pub fn readResponseEventWithTimeout(
        self: *ClientDuplexStream,
        timeout: std.Io.Duration,
    ) Error!DuplexResponseEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return (try self.readResponseEventUntil(.fromNow(
            self.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ), false)).?;
    }

    pub fn readResponseEventWithDeadline(
        self: *ClientDuplexStream,
        deadline: std.Io.Clock.Timestamp,
    ) Error!DuplexResponseEvent {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return (try self.readResponseEventUntil(deadline, false)).?;
    }

    /// Consume only routed events. This never reads the socket; DATA may
    /// return receive credit through bounded output when a deadline is given.
    pub fn pollResponseEvent(self: *ClientDuplexStream) Error!?DuplexResponseEvent {
        return self.readResponseEventUntil(null, true);
    }

    pub fn pollResponseEventWithDeadline(self: *ClientDuplexStream, deadline: std.Io.Clock.Timestamp) Error!?DuplexResponseEvent {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.readResponseEventUntil(deadline, true);
    }

    pub fn pollResponseEventWithCreditPolicy(self: *ClientDuplexStream, policy: ConnectionCreditPolicy) Error!?DuplexResponseEvent {
        return self.readResponseEventWithCreditUntil(null, true, policy);
    }

    pub fn pollResponseEventWithCreditPolicyAndDeadline(self: *ClientDuplexStream, policy: ConnectionCreditPolicy, deadline: std.Io.Clock.Timestamp) Error!?DuplexResponseEvent {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.readResponseEventWithCreditUntil(deadline, true, policy);
    }

    /// Single-owner coordinator path after the caller has already validated
    /// this awake deadline for its current scheduler turn. Polling remains
    /// socket-free; any resulting flow-control output still receives the same
    /// absolute deadline and performs its ordinary transport checks.
    pub fn pollResponseEventWithCreditPolicyAssumeUsableDeadline(
        self: *ClientDuplexStream,
        policy: ConnectionCreditPolicy,
        deadline: std.Io.Clock.Timestamp,
    ) Error!?DuplexResponseEvent {
        std.debug.assert(deadline.clock == .awake);
        return self.readResponseEventWithCreditUntil(
            deadline,
            true,
            policy,
        );
    }

    fn nextResponseFrame(self: *ClientDuplexStream, deadline: ?std.Io.Clock.Timestamp, buffered: bool) Error!?RetainedFrame {
        if (buffered) return self.connection.pollOwnedClientDuplexFrame(self.stream_id, deadline);
        return try self.connection.readOwnedClientDuplexFrameWithDeadline(self.stream_id, deadline);
    }

    fn readResponseEventUntil(
        self: *ClientDuplexStream,
        deadline: ?std.Io.Clock.Timestamp,
        buffered: bool,
    ) Error!?DuplexResponseEvent {
        return self.readResponseEventWithCreditUntil(deadline, buffered, .immediate);
    }

    fn readResponseEventWithCreditUntil(
        self: *ClientDuplexStream,
        deadline: ?std.Io.Clock.Timestamp,
        buffered: bool,
        policy: ConnectionCreditPolicy,
    ) Error!?DuplexResponseEvent {
        if (self.response_finished_reported) {
            return error.ConnectionClosed;
        }
        if (self.response_finished) {
            self.response_finished_reported = true;
            self.maybeRelease();
            return .finished;
        }
        if (self.connection.aggregate_timeout_unusable) return error.ConnectionClosed;
        while (true) {
            if (self.connection.peer_goaway_last_stream_id) |last| {
                if (self.stream_id > last) {
                    self.connection.releaseLocalStream(self.stream_id);
                    return error.ConnectionGoAway;
                }
            }
            if (self.pending_header.getPtr()) |pending| {
                if (buffered and !pending.end_headers) return null;
                const end_stream = pending.end_stream;
                const headers = (try pending.resumeUntil(
                    self.connection,
                    deadline,
                )).?;
                self.pending_header.deinit(self.connection.allocator);
                return try self.applyResponseHeaders(headers, end_stream);
            }
            const next_frame = self.nextResponseFrame(deadline, buffered);
            var frame = (next_frame catch |err| {
                if (err != error.Timeout) {
                    if (self.connection.pending_duplex_sibling_header.getPtr()) |pending| {
                        if (pending.header.stream_id == self.stream_id) {
                            self.pending_header.put(.{
                                .stream_id = self.stream_id,
                                .end_stream = pending.header.end_stream,
                                .end_headers = pending.header.end_headers,
                                .decode_complete = pending.header.decode_complete,
                            });
                        }
                    }
                }
                return err;
            }) orelse return null;
            var frame_owned = true;
            defer if (frame_owned) frame.deinit(self.connection.allocator);
            if (try self.connection.handleConnectionFrameUntil(frame.frame, deadline)) continue;
            if (frame.frame.header.frame_type == .goaway) {
                const goaway = try http2.GoAwayPayload.parse(frame.frame);
                try self.connection.handleGoAwayForStream(self.stream_id, goaway);
                continue;
            }
            if (frame.frame.header.stream_id != self.stream_id) {
                try self.connection.queueDuplexSiblingFrameUntil(frame);
                frame_owned = false;
                continue;
            }
            switch (frame.frame.header.frame_type) {
                .headers => {
                    const deferred_fields = self.connection.takeDeferredHeaderBlock(frame.frame, true, false) catch |err| {
                        if (err == error.MessageTooLarge) {
                            self.pending_header.put(.{
                                .stream_id = self.stream_id,
                                .end_stream = (frame.frame.header.flags & flag_end_stream) != 0,
                                .end_headers = true,
                                .limit_exceeded = true,
                                .decode_complete = true,
                            });
                        }
                        return err;
                    };
                    if (deferred_fields) |fields| {
                        return try self.applyResponseHeaders(fields, (frame.frame.header.flags & flag_end_stream) != 0);
                    }
                    self.pending_header.put(try DuplexHeaderBlock.init(
                        self.connection,
                        frame.frame,
                    ));
                    const pending = self.pending_header.getPtr().?;
                    const end_stream = pending.end_stream;
                    const headers = (try pending.resumeUntil(
                        self.connection,
                        deadline,
                    )).?;
                    self.pending_header.deinit(self.connection.allocator);
                    return try self.applyResponseHeaders(headers, end_stream);
                },
                .data => {
                    if (!self.response_head_seen) return error.UnexpectedFrame;
                    const payload = try self.connection.receiveDataPayload(
                        self.stream_id,
                        frame.frame,
                    );
                    defer self.connection.releaseDataFrameBudget(payload);
                    const end_stream =
                        (frame.frame.header.flags & flag_end_stream) != 0;
                    self.response_body_bytes = checkedResponseBodyLength(
                        self.response_content_length,
                        self.response_body_bytes,
                        payload.data.len,
                        self.connection.limits.max_body_bytes,
                        !self.response_body_forbidden,
                        end_stream,
                    ) catch |err| {
                        self.connection.releaseConnectionCapacityUntil(
                            frame.frame.payload.len,
                            deadline,
                        ) catch {
                            self.connection.aggregate_timeout_unusable = true;
                            self.connection.terminal_write_failed = true;
                            // The failed write rolled back its window grant.
                            // Retire the consumed bytes locally during unwind.
                            self.connection.recv_connection_window.update(@intCast(frame.frame.payload.len)) catch {};
                        };
                        return @errorCast(err);
                    };
                    if (end_stream) {
                        self.response_finished = true;
                        self.maybeRelease();
                    }
                    if (payload.data.len == 0) {
                        try response_capacity.receiveWithPolicy(
                            self,
                            payload,
                            end_stream,
                            deadline,
                            policy,
                        );
                        if (end_stream) {
                            self.response_finished_reported = true;
                            self.maybeRelease();
                            return .finished;
                        }
                        continue;
                    }
                    try response_capacity.receiveWithPolicy(
                        self,
                        payload,
                        end_stream,
                        deadline,
                        policy,
                    );
                    const data = payload.data;
                    frame_owned = false;
                    return .{ .data = .{ .frame = frame, .data = data } };
                },
                .rst_stream => {
                    const peer_reset = try http2.ResetStreamPayload.parse(
                        frame.frame,
                    );
                    try self.connection.recordResetStream(peer_reset);
                    self.request_finished = true;
                    self.response_finished = true;
                    self.response_finished_reported = true;
                    self.release();
                    return .{ .reset = peer_reset };
                },
                .push_promise => return error.UnexpectedFrame,
                else => return error.UnexpectedFrame,
            }
        }
    }

    fn applyResponseHeaders(
        self: *ClientDuplexStream,
        headers: []http2.Hpack.HeaderField,
        end_stream: bool,
    ) Error!DuplexResponseEvent {
        var headers_owned = true;
        errdefer if (headers_owned) {
            freeHeaders(self.connection.allocator, headers);
        };
        if (!self.response_head_seen) {
            try validateHeaderBlock(headers, .response);
            const lookup = try responseHeaderLookup(headers);
            const status_text = lookup.status orelse
                return error.MissingPseudoHeader;
            const status = std.fmt.parseInt(u16, status_text, 10) catch
                return error.InvalidStatus;
            if (informationalResponseToSkip(status)) {
                if (end_stream or lookup.content_length != null) {
                    return error.InvalidContentLength;
                }
                self.informational_count = std.math.add(
                    usize,
                    self.informational_count,
                    1,
                ) catch return error.TooManyInformationalResponses;
                if (self.informational_count >
                    self.connection.limits.max_informational_responses)
                {
                    return error.TooManyInformationalResponses;
                }
                headers_owned = false;
                return .{ .informational = .{
                    .headers = headers,
                    .status = status,
                } };
            }
            self.response_head_seen = true;
            self.response_content_length = lookup.content_length;
            self.response_body_forbidden = responseForbidsBody(
                status,
                if (self.extended_connect) "CONNECT" else if (self.head_request) "HEAD" else "POST",
                self.extended_connect,
            );
            if (status == 204 and lookup.content_length != null) {
                return error.InvalidContentLength;
            }
            if (!self.response_body_forbidden and
                (lookup.content_length orelse 0) >
                    self.connection.limits.max_body_bytes)
            {
                return error.MessageTooLarge;
            }
            if (end_stream) {
                if (!self.response_body_forbidden) {
                    try validateExpectedContentLength(
                        self.response_content_length,
                        0,
                    );
                }
                self.response_finished = true;
                self.maybeRelease();
            }
            headers_owned = false;
            return .{ .head = .{
                .headers = headers,
                .status = status,
                .body_allowed = !self.response_body_forbidden,
            } };
        }
        if (!end_stream) return error.UnexpectedFrame;
        if (self.response_body_forbidden) return error.InvalidContentLength;
        try validateHeaderBlock(headers, .response_trailers);
        try validateExpectedContentLength(
            self.response_content_length,
            self.response_body_bytes,
        );
        self.response_finished = true;
        self.maybeRelease();
        headers_owned = false;
        return .{ .trailers = headers };
    }

    fn maybeRelease(self: *ClientDuplexStream) void {
        if (self.request_finished and self.response_finished) {
            // The caller may still own a DATA event whose frame allocation is
            // independent, so restoring sibling frames here is safe.
            self.release();
        }
    }

    /// Stop an upload after observing a terminal early response. The default
    /// terminal cleanup budget bounds request-half FIN (or CANCEL when FIN
    /// would violate Content-Length). Local ownership is retired on failure;
    /// the committed response remains available to its caller.
    pub fn closeRequestAfterResponse(self: *ClientDuplexStream) Error!void {
        return self.closeRequestAfterResponseUntil(response_cleanup.cleanupDeadline(self.connection, null));
    }

    pub fn closeRequestAfterResponseWithDeadline(self: *ClientDuplexStream, deadline: std.Io.Clock.Timestamp) ResponseTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.closeRequestAfterResponseUntil(deadline);
    }

    pub fn closeRequestAfterResponseWithTimeout(self: *ClientDuplexStream, timeout: std.Io.Duration) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.closeRequestAfterResponseWithDeadline(.fromNow(self.connection.io, .{ .raw = timeout, .clock = .awake }));
    }

    fn closeRequestAfterResponseUntil(self: *ClientDuplexStream, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (!self.response_finished) return error.UnexpectedFrame;
        if (self.request_finished) return;
        defer {
            self.request_finished = true;
            self.released = true;
            self.releaseOwnership();
        }
        if (self.expected_request_length) |expected| {
            if (self.request_written != expected) {
                return stream_termination.reset(self.connection, self.stream_id, http2.ErrorCode.cancel, deadline, Connection.local_stream_termination_hooks);
            }
        }
        return stream_termination.finish(self.connection, self.stream_id, deadline, Connection.local_stream_termination_hooks);
    }

    fn releaseOwnership(self: *ClientDuplexStream) void {
        if (self.registered) {
            self.connection.releaseClientDuplexOwner(self.stream_id);
            self.registered = false;
        } else {
            self.connection.refreshDuplexReaderActive();
        }
    }

    pub fn release(self: *ClientDuplexStream) void {
        if (self.released) return;
        self.connection.releaseLocalStream(self.stream_id);
        self.releaseOwnership();
        self.released = true;
    }
};

pub const DuplexRequestEvent = union(enum) {
    data: DuplexData,
    trailers: []http2.Hpack.HeaderField,
    finished,
    reset: http2.ResetStreamPayload,

    pub fn deinit(self: *DuplexRequestEvent, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .data => |*data| data.deinit(allocator),
            .trailers => |trailers| freeHeaders(allocator, trailers),
            .finished, .reset => {},
        }
        self.* = undefined;
    }
};

pub const DuplexRequestDrainResult = union(enum) {
    finished,
    reset: http2.ResetStreamPayload,
};

/// Server counterpart to `ClientDuplexStream`. Request metadata is owned by
/// this object while request DATA arrives stepwise and response DATA may be
/// written between receive steps.
pub const ServerDuplexStream = struct {
    connection: *Connection,
    registered: bool = false,
    stream_id: u31,
    headers: []http2.Hpack.HeaderField,
    method: []const u8,
    path: []const u8,
    scheme: []const u8,
    authority: ?[]const u8,
    protocol: ?[]const u8,
    priority: http2.ExtensiblePriority,
    expected_request_length: ?usize,
    /// The peer declared a request body above `Limits.max_body_bytes`. The
    /// stream is still accepted so a streaming handler can answer 413; reading
    /// the body reports `PayloadTooLarge` instead of failing the connection.
    request_body_over_limit: bool = false,
    request_body_bytes: usize = 0,
    request_finished: bool = false,
    request_finished_reported: bool = false,
    response_started: bool = false,
    response_finished: bool = false,
    response_expected_length: ?usize = null,
    response_written: usize = 0,
    pending_header: DuplexHeaderBlockSlot = .{},
    current_body: ?DuplexData = null,
    request_trailers: ?[]http2.Hpack.HeaderField = null,
    released: bool = false,

    pub fn deinit(self: *ServerDuplexStream) void {
        if (!self.released) {
            if (self.request_finished and self.response_finished) {
                self.release();
            } else {
                self.reset(.cancel) catch {};
            }
        }
        self.pending_header.deinit(self.connection.allocator);
        if (self.current_body) |*data| data.deinit(self.connection.allocator);
        if (self.request_trailers) |trailers| freeHeaders(self.connection.allocator, trailers);
        self.releaseOwnership();
        freeHeaders(self.connection.allocator, self.headers);
        self.* = undefined;
    }

    pub fn startResponse(self: *ServerDuplexStream, options: StreamingResponseOptions) Error!void {
        return self.startResponseUntil(options, null);
    }

    /// Send a buffered response head and body as one logical write. The
    /// connection combines the HEADERS block and the first DATA burst when
    /// flow-control credit permits, avoiding a second tiny submission for
    /// the common hello/JSON response.
    pub fn startResponseWithBody(
        self: *ServerDuplexStream,
        options: StreamingResponseOptions,
        data: []const u8,
    ) Error!void {
        if (self.response_started or self.released) {
            return error.UnexpectedFrame;
        }
        try self.connection.writeResponse(self.stream_id, .{
            .status = options.status,
            .headers = options.headers,
            .body = data,
            .request_method = options.request_method,
            .extended_connect = options.extended_connect,
        });
        self.response_started = true;
        self.response_finished = true;
        self.response_written = data.len;
        // `writeResponse` retires the peer stream; finish the duplex owner
        // bookkeeping without releasing the same stream twice.
        self.releaseOwnership();
        self.released = true;
    }

    pub fn startResponseWithDeadline(self: *ServerDuplexStream, options: StreamingResponseOptions, deadline: std.Io.Clock.Timestamp) ResponseTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.startResponseUntil(options, deadline);
    }

    pub fn startResponseWithTimeout(self: *ServerDuplexStream, options: StreamingResponseOptions, timeout: std.Io.Duration) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.startResponseWithDeadline(options, .fromNow(self.connection.io, .{ .raw = timeout, .clock = .awake }));
    }

    fn startResponseUntil(self: *ServerDuplexStream, options: StreamingResponseOptions, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (self.response_started or self.released) {
            return error.UnexpectedFrame;
        }
        var writer = try self.connection.startResponseInternalUntil(
            self.stream_id,
            options,
            false,
            deadline,
        );
        self.response_started = true;
        self.response_finished = writer.finished;
        self.response_expected_length = writer.expected_length;
        self.response_written = writer.written;
        writer.finished = true;
        self.maybeRelease();
    }

    /// Send one response HEADERS block carrying END_STREAM. This is the
    /// trailers-only response shape used by an early gRPC status while the
    /// request half can remain open and be drained separately.
    pub fn finishResponseHeaders(self: *ServerDuplexStream, options: ResponseOptions) Error!void {
        return self.finishResponseHeadersUntil(options, null);
    }

    pub fn finishResponseHeadersWithDeadline(self: *ServerDuplexStream, options: ResponseOptions, deadline: std.Io.Clock.Timestamp) ResponseTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.finishResponseHeadersUntil(options, deadline);
    }

    pub fn finishResponseHeadersWithTimeout(self: *ServerDuplexStream, options: ResponseOptions, timeout: std.Io.Duration) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishResponseHeadersWithDeadline(options, .fromNow(self.connection.io, .{ .raw = timeout, .clock = .awake }));
    }

    fn finishResponseHeadersUntil(self: *ServerDuplexStream, options: ResponseOptions, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (self.response_started or self.released) {
            return error.UnexpectedFrame;
        }
        if (options.body.len != 0 or options.trailers.len != 0) {
            return error.InvalidContentLength;
        }
        var response_options = options;
        response_options.request_method = self.method;
        response_options.extended_connect = self.protocol != null;
        try self.connection.writeResponseInternalUntil(
            self.stream_id,
            response_options,
            false,
            deadline,
        );
        self.response_started = true;
        self.response_finished = true;
        self.maybeRelease();
    }

    pub fn requestFinished(self: ServerDuplexStream) bool {
        return self.request_finished;
    }

    pub fn responseFinished(self: ServerDuplexStream) bool {
        return self.response_finished;
    }

    pub fn reset(
        self: *ServerDuplexStream,
        error_code: http2.ErrorCode,
    ) Error!void {
        if (self.released) return error.ConnectionClosed;
        defer {
            self.request_finished = true;
            self.request_finished_reported = true;
            self.response_finished = true;
            self.released = true;
            self.releaseOwnership();
        }
        if (self.pending_header.getPtr()) |pending| {
            if (!pending.decode_complete) self.connection.aggregate_timeout_unusable = true;
        }
        return self.connection.terminateOwnedStream(self.stream_id, error_code);
    }

    pub fn writeResponse(
        self: *ServerDuplexStream,
        data: []const u8,
    ) Error!DuplexWriteResult {
        return self.writeResponseDataUntil(data, false, null);
    }

    pub fn writeResponseWithTimeout(
        self: *ServerDuplexStream,
        data: []const u8,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!DuplexWriteResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeResponseWithDeadline(data, .fromNow(
            self.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn writeResponseWithDeadline(
        self: *ServerDuplexStream,
        data: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!DuplexWriteResult {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.writeResponseDataUntil(data, false, deadline);
    }

    pub fn writeResponseParts(
        self: *ServerDuplexStream,
        first: []const u8,
        second: []const u8,
    ) Error!DuplexWriteResult {
        return self.writeResponseSlicesUntil(
            &.{ first, second },
            false,
            null,
        );
    }

    pub fn writeResponsePartsWithTimeout(
        self: *ServerDuplexStream,
        first: []const u8,
        second: []const u8,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!DuplexWriteResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeResponsePartsWithDeadline(
            first,
            second,
            .fromNow(self.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn writeResponsePartsWithDeadline(
        self: *ServerDuplexStream,
        first: []const u8,
        second: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!DuplexWriteResult {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.writeResponseSlicesUntil(
            &.{ first, second },
            false,
            deadline,
        );
    }

    pub fn writeResponseSlices(
        self: *ServerDuplexStream,
        slices: []const []const u8,
        end_stream: bool,
    ) Error!DuplexWriteResult {
        return self.writeResponseSlicesUntil(slices, end_stream, null);
    }

    pub fn writeResponseSlicesWithTimeout(
        self: *ServerDuplexStream,
        slices: []const []const u8,
        end_stream: bool,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!DuplexWriteResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeResponseSlicesWithDeadline(
            slices,
            end_stream,
            .fromNow(self.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn writeResponseSlicesWithDeadline(
        self: *ServerDuplexStream,
        slices: []const []const u8,
        end_stream: bool,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!DuplexWriteResult {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.writeResponseSlicesUntil(
            slices,
            end_stream,
            deadline,
        );
    }

    fn writeResponseSlicesUntil(
        self: *ServerDuplexStream,
        slices: []const []const u8,
        end_stream: bool,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!DuplexWriteResult {
        var additional: usize = 0;
        for (slices) |slice| {
            additional = std.math.add(usize, additional, slice.len) catch
                return error.MessageTooLarge;
        }
        const total = std.math.add(
            usize,
            self.response_written,
            additional,
        ) catch return error.MessageTooLarge;
        if (self.response_expected_length) |expected| {
            if (total > expected or (end_stream and total != expected)) {
                return error.InvalidContentLength;
            }
        }
        var written: usize = 0;
        var remaining_non_empty: usize = 0;
        for (slices) |slice| {
            remaining_non_empty += @intFromBool(slice.len != 0);
        }
        for (slices) |slice| {
            if (slice.len == 0) continue;
            remaining_non_empty -= 1;
            const result = try self.writeResponseDataUntil(
                slice,
                end_stream and remaining_non_empty == 0,
                deadline,
            );
            written += result.written;
            if (result.response_available) {
                return .{
                    .written = written,
                    .response_available = true,
                };
            }
        }
        if (written == 0 and end_stream) {
            const result = try self.writeResponseDataUntil(
                &.{},
                true,
                deadline,
            );
            return .{
                .written = 0,
                .response_available = result.response_available,
            };
        }
        return .{ .written = written, .response_available = false };
    }

    /// Write several borrowed DATA slices as one logical burst. The slices
    /// share one DATA frame sequence instead of producing a separate frame
    /// for each slice.
    pub fn writeResponseSlicesBurst(
        self: *ServerDuplexStream,
        slices: []const []const u8,
        end_stream: bool,
    ) Error!DuplexWriteResult {
        if (!self.response_started or self.response_finished or self.released) {
            return error.ConnectionClosed;
        }
        var additional: usize = 0;
        for (slices) |slice| {
            additional = std.math.add(usize, additional, slice.len) catch
                return error.MessageTooLarge;
        }
        const total = std.math.add(
            usize,
            self.response_written,
            additional,
        ) catch return error.MessageTooLarge;
        if (self.response_expected_length) |expected| {
            if (total > expected or (end_stream and total != expected)) {
                return error.InvalidContentLength;
            }
        }
        var sent: usize = 0;
        self.connection.writeDataSlicesPreparedTrackedUntil(
            self.stream_id,
            slices,
            end_stream,
            &sent,
            null,
        ) catch |err| switch (err) {
            error.Timeout => unreachable,
            else => {
                self.response_written += sent;
                return @errorCast(err);
            },
        };
        self.response_written += sent;
        if (end_stream) {
            self.response_finished = true;
            self.maybeRelease();
        }
        return .{ .written = sent, .response_available = false };
    }

    pub fn finishResponse(
        self: *ServerDuplexStream,
    ) Error!DuplexWriteResult {
        return self.finishResponseData(&.{});
    }

    pub fn finishResponseWithTimeout(
        self: *ServerDuplexStream,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!DuplexWriteResult {
        return self.finishResponseDataWithTimeout(&.{}, timeout);
    }

    pub fn finishResponseWithDeadline(
        self: *ServerDuplexStream,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!DuplexWriteResult {
        return self.finishResponseDataWithDeadline(&.{}, deadline);
    }

    pub fn finishResponseData(
        self: *ServerDuplexStream,
        data: []const u8,
    ) Error!DuplexWriteResult {
        return self.writeResponseDataUntil(data, true, null);
    }

    pub fn finishResponseDataWithTimeout(
        self: *ServerDuplexStream,
        data: []const u8,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!DuplexWriteResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishResponseDataWithDeadline(data, .fromNow(
            self.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn finishResponseDataWithDeadline(
        self: *ServerDuplexStream,
        data: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!DuplexWriteResult {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.writeResponseDataUntil(data, true, deadline);
    }

    /// Cumulative response DATA bytes committed by this duplex stream. This
    /// remains authoritative after a bounded write returns `error.Timeout`.
    pub fn responseCommittedBytes(self: ServerDuplexStream) usize {
        return self.response_written;
    }

    pub fn finishResponseTrailers(self: *ServerDuplexStream, trailers: []const http2.Hpack.HeaderField) Error!void {
        return self.finishResponseTrailersUntil(trailers, null);
    }

    pub fn finishResponseTrailersWithDeadline(self: *ServerDuplexStream, trailers: []const http2.Hpack.HeaderField, deadline: std.Io.Clock.Timestamp) ResponseTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.finishResponseTrailersUntil(trailers, deadline);
    }

    pub fn finishResponseTrailersWithTimeout(self: *ServerDuplexStream, trailers: []const http2.Hpack.HeaderField, timeout: std.Io.Duration) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishResponseTrailersWithDeadline(trailers, .fromNow(self.connection.io, .{ .raw = timeout, .clock = .awake }));
    }

    fn finishResponseTrailersUntil(self: *ServerDuplexStream, trailers: []const http2.Hpack.HeaderField, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (!self.response_started or self.response_finished or self.released) {
            return error.ConnectionClosed;
        }
        if (self.response_expected_length) |expected| {
            if (self.response_written != expected) {
                return error.InvalidContentLength;
            }
        }
        try validateHeaderBlock(trailers, .response_trailers);
        try self.connection.writeHeadersUntil(self.stream_id, trailers, true, deadline);
        self.response_finished = true;
        self.maybeRelease();
    }

    fn writeResponseDataUntil(
        self: *ServerDuplexStream,
        data: []const u8,
        end_stream: bool,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!DuplexWriteResult {
        if (!self.response_started or self.response_finished or self.released) {
            return error.ConnectionClosed;
        }
        const total = std.math.add(
            usize,
            self.response_written,
            data.len,
        ) catch return error.MessageTooLarge;
        if (self.response_expected_length) |expected| {
            if (total > expected or (end_stream and total != expected)) {
                return error.InvalidContentLength;
            }
        }
        var sent: usize = 0;
        self.connection.writeDataDuplexTrackedUntil(
            self.stream_id,
            data,
            end_stream,
            &sent,
            deadline,
        ) catch |err| switch (err) {
            error.ResponseAvailable => {
                self.response_written += sent;
                return .{ .written = sent, .response_available = true };
            },
            else => {
                self.response_written += sent;
                return err;
            },
        };
        self.response_written += sent;
        if (end_stream) {
            self.response_finished = true;
            self.maybeRelease();
        }
        return .{ .written = sent, .response_available = false };
    }

    /// Pull the next request-body DATA slice. The returned slice is borrowed
    /// until the following `nextBody` call or `deinit`; trailers are retained
    /// in `requestTrailers`. Returns null after END_STREAM and surfaces a peer
    /// reset as `error.StreamReset`.
    pub fn nextBody(self: *ServerDuplexStream) !?[]const u8 {
        if (self.current_body) |*data| {
            data.deinit(self.connection.allocator);
            self.current_body = null;
        }
        while (true) {
            const event = try self.readRequestEvent();
            switch (event) {
                .data => |value| {
                    self.current_body = value;
                    return self.current_body.?.data;
                },
                .trailers => |trailers| {
                    if (self.request_trailers) |old| freeHeaders(self.connection.allocator, old);
                    self.request_trailers = trailers;
                },
                .finished => return null,
                .reset => return error.StreamReset,
            }
        }
    }

    pub fn requestTrailers(self: ServerDuplexStream) ?[]const http2.Hpack.HeaderField {
        return self.request_trailers;
    }

    /// Content-decoding chain for the encoded DATA returned by `nextBody`.
    pub fn streamContentDecoder(self: ServerDuplexStream, allocator: std.mem.Allocator, options: content_coding.StreamOptions) content_coding.Error!content_coding.StreamDecoder {
        return (try content_coding.parseHeaders(self.headers)).streamDecoder(allocator, options);
    }

    pub fn readRequestEvent(
        self: *ServerDuplexStream,
    ) Error!DuplexRequestEvent {
        return (try self.readRequestEventUntil(null, false)).?;
    }

    pub fn readRequestEventWithTimeout(
        self: *ServerDuplexStream,
        timeout: std.Io.Duration,
    ) Error!DuplexRequestEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return (try self.readRequestEventUntil(.fromNow(
            self.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ), false)).?;
    }

    pub fn readRequestEventWithDeadline(
        self: *ServerDuplexStream,
        deadline: std.Io.Clock.Timestamp,
    ) Error!DuplexRequestEvent {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return (try self.readRequestEventUntil(deadline, false)).?;
    }

    /// Consume only input already routed by the shared server owner.
    pub fn pollRequestEvent(self: *ServerDuplexStream) Error!?DuplexRequestEvent {
        return self.readRequestEventUntil(null, true);
    }

    pub fn pollRequestEventWithDeadline(self: *ServerDuplexStream, deadline: std.Io.Clock.Timestamp) Error!?DuplexRequestEvent {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.readRequestEventUntil(deadline, true);
    }

    /// Discard the remaining request body after the response half has ended.
    /// The caller supplies an independent cleanup deadline; DATA still passes
    /// through normal HTTP/2 validation and flow-control accounting.
    pub fn drainRequestAfterResponseWithDeadline(
        self: *ServerDuplexStream,
        deadline: std.Io.Clock.Timestamp,
    ) Error!DuplexRequestDrainResult {
        if (!self.response_finished) return error.UnexpectedFrame;
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        if (self.request_finished) return .finished;
        while (true) {
            var event = (try self.readRequestEventUntil(deadline, false)).?;
            defer event.deinit(self.connection.allocator);
            switch (event) {
                .data => if (self.request_finished) return .finished,
                .trailers, .finished => return .finished,
                .reset => |reset_value| {
                    return .{ .reset = reset_value };
                },
            }
        }
    }

    /// Wait for the peer to cancel a response that remains open after the
    /// complete request half has already been consumed. This is the server-
    /// streaming counterpart to `readRequestEvent`: connection-control and
    /// sibling-stream frames are preserved while this stream waits for its
    /// terminal RST_STREAM.
    pub fn waitForPeerReset(
        self: *ServerDuplexStream,
    ) Error!http2.ResetStreamPayload {
        return self.waitForPeerResetUntil(null);
    }

    pub fn waitForPeerResetWithTimeout(
        self: *ServerDuplexStream,
        timeout: std.Io.Duration,
    ) Error!http2.ResetStreamPayload {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.waitForPeerResetWithDeadline(.fromNow(
            self.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn waitForPeerResetWithDeadline(
        self: *ServerDuplexStream,
        deadline: std.Io.Clock.Timestamp,
    ) Error!http2.ResetStreamPayload {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.waitForPeerResetUntil(deadline);
    }

    fn waitForPeerResetUntil(
        self: *ServerDuplexStream,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!http2.ResetStreamPayload {
        if (!self.request_finished) return error.UnexpectedFrame;
        if (self.released or self.response_finished) {
            return error.ConnectionClosed;
        }
        while (true) {
            var frame = try self.connection
                .readOwnedServerDuplexFrameWithDeadline(
                self.stream_id,
                deadline,
            );
            var frame_owned = true;
            defer if (frame_owned) frame.deinit(self.connection.allocator);
            if (try self.connection.handleConnectionFrameUntil(frame.frame, deadline)) {
                continue;
            }
            if (frame.frame.header.frame_type == .goaway) continue;
            if (frame.frame.header.stream_id != self.stream_id) {
                try self.connection.queueDuplexSiblingFrameUntil(frame);
                frame_owned = false;
                continue;
            }
            if (frame.frame.header.frame_type != .rst_stream) {
                return error.UnexpectedFrame;
            }
            const peer_reset = try http2.ResetStreamPayload.parse(frame.frame);
            try self.connection.recordResetStream(peer_reset);
            self.request_finished = true;
            self.request_finished_reported = true;
            self.response_finished = true;
            self.release();
            return peer_reset;
        }
    }

    fn readRequestEventUntil(
        self: *ServerDuplexStream,
        deadline: ?std.Io.Clock.Timestamp,
        buffered: bool,
    ) Error!?DuplexRequestEvent {
        if (self.request_finished_reported) {
            return error.ConnectionClosed;
        }
        if (self.request_finished) {
            self.request_finished_reported = true;
            self.maybeRelease();
            return .finished;
        }
        while (true) {
            if (self.pending_header.getPtr()) |pending| {
                if (buffered and !pending.end_headers) return null;
                const trailers = (try pending.resumeUntil(
                    self.connection,
                    deadline,
                )).?;
                self.pending_header.deinit(self.connection.allocator);
                errdefer freeHeaders(self.connection.allocator, trailers);
                try validateHeaderBlock(trailers, .request_trailers);
                try validateExpectedContentLength(
                    self.expected_request_length,
                    self.request_body_bytes,
                );
                self.request_finished = true;
                return .{ .trailers = trailers };
            }
            const next_frame: ?RetainedFrame = if (buffered)
                try self.connection.pollOwnedServerDuplexFrame(self.stream_id)
            else
                try self.connection.readOwnedServerDuplexFrameWithDeadline(
                    self.stream_id,
                    deadline,
                );
            var frame = next_frame orelse return null;
            var frame_owned = true;
            defer if (frame_owned) frame.deinit(self.connection.allocator);
            if (try self.connection.handleConnectionFrameUntil(frame.frame, deadline)) continue;
            if (frame.frame.header.frame_type == .goaway) continue;
            if (frame.frame.header.stream_id != self.stream_id) {
                try self.connection.queueDuplexSiblingFrameUntil(frame);
                frame_owned = false;
                continue;
            }
            switch (frame.frame.header.frame_type) {
                .data => {
                    const payload = try self.connection.receiveDataPayload(
                        self.stream_id,
                        frame.frame,
                    );
                    defer self.connection.releaseDataFrameBudget(payload);
                    const end_stream =
                        (frame.frame.header.flags & flag_end_stream) != 0;
                    self.request_body_bytes = checkedBodyLength(
                        self.expected_request_length,
                        self.request_body_bytes,
                        payload.data.len,
                        self.connection.limits.max_body_bytes,
                        end_stream,
                    ) catch |err| {
                        self.connection.releaseConnectionCapacity(frame.frame.payload.len) catch {};
                        return @errorCast(err);
                    };
                    if (end_stream) {
                        self.request_finished = true;
                        self.maybeRelease();
                    }
                    if (payload.data.len == 0) {
                        try self.connection.releaseReceivedDataCapacityUntil(
                            self.stream_id,
                            payload,
                            end_stream,
                            deadline,
                        );
                        if (end_stream) {
                            self.request_finished_reported = true;
                            self.maybeRelease();
                            return .finished;
                        }
                        continue;
                    }
                    try self.connection.releaseReceivedDataCapacityUntil(
                        self.stream_id,
                        payload,
                        end_stream,
                        deadline,
                    );
                    const data = payload.data;
                    frame_owned = false;
                    return .{ .data = .{ .frame = frame, .data = data } };
                },
                .headers => {
                    if ((frame.frame.header.flags & flag_end_stream) == 0) {
                        return error.UnexpectedFrame;
                    }
                    if (try self.connection.takeDeferredHeaderBlock(
                        frame.frame,
                        true,
                        false,
                    )) |trailers| {
                        errdefer freeHeaders(
                            self.connection.allocator,
                            trailers,
                        );
                        try validateHeaderBlock(
                            trailers,
                            .request_trailers,
                        );
                        try validateExpectedContentLength(
                            self.expected_request_length,
                            self.request_body_bytes,
                        );
                        self.request_finished = true;
                        self.maybeRelease();
                        return .{ .trailers = trailers };
                    }
                    self.pending_header.put(try DuplexHeaderBlock.init(
                        self.connection,
                        frame.frame,
                    ));
                    const pending = self.pending_header.getPtr().?;
                    const trailers = (try pending.resumeUntil(
                        self.connection,
                        deadline,
                    )).?;
                    self.pending_header.deinit(self.connection.allocator);
                    errdefer freeHeaders(self.connection.allocator, trailers);
                    try validateHeaderBlock(trailers, .request_trailers);
                    try validateExpectedContentLength(
                        self.expected_request_length,
                        self.request_body_bytes,
                    );
                    self.request_finished = true;
                    self.maybeRelease();
                    return .{ .trailers = trailers };
                },
                .rst_stream => {
                    const peer_reset = try http2.ResetStreamPayload.parse(
                        frame.frame,
                    );
                    try self.connection.recordResetStream(peer_reset);
                    self.request_finished = true;
                    self.request_finished_reported = true;
                    self.response_finished = true;
                    self.release();
                    return .{ .reset = peer_reset };
                },
                else => return error.UnexpectedFrame,
            }
        }
    }

    fn maybeRelease(self: *ServerDuplexStream) void {
        if (self.request_finished and self.response_finished) {
            self.release();
        }
    }

    pub fn release(self: *ServerDuplexStream) void {
        if (self.released) return;
        self.connection.releasePeerStream(self.stream_id);
        self.releaseOwnership();
        self.released = true;
    }

    fn releaseOwnership(self: *ServerDuplexStream) void {
        if (self.registered) {
            self.connection.releaseServerDuplexOwner(self.stream_id);
            self.registered = false;
        } else {
            self.connection.refreshDuplexReaderActive();
        }
    }
};

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

pub const Tunnel = struct {
    connection: *Connection,
    stream_id: u31,
    /// RFC 9113 counts open and either half-closed state against the
    /// concurrent-stream limit. Atomics preserve Tunnel's documented split
    /// reader/writer use while allowing exactly one side to release state.
    send_finished: std.atomic.Value(bool) = .init(false),
    receive_finished: std.atomic.Value(bool) = .init(false),
    released: std.atomic.Value(bool) = .init(false),

    pub fn write(self: *Tunnel, data: []const u8, end_stream: bool) Error!void {
        var progress: TunnelWriteProgress = .{};
        return self.writeSlicesUntil(
            &.{data},
            end_stream,
            &progress,
            null,
            false,
        ) catch |err| switch (err) {
            error.Timeout => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn writeWithTimeout(
        self: *Tunnel,
        data: []const u8,
        end_stream: bool,
        progress: *TunnelWriteProgress,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeWithDeadline(
            data,
            end_stream,
            progress,
            .fromNow(self.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn writeWithDeadline(
        self: *Tunnel,
        data: []const u8,
        end_stream: bool,
        progress: *TunnelWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.writeSlicesUntil(
            &.{data},
            end_stream,
            progress,
            deadline,
            false,
        );
    }

    /// Write two borrowed slices as one ordered tunnel byte sequence. DATA
    /// frame boundaries and flow-control bursts may cross the slice join; the
    /// caller must retain both slices until this synchronous call returns.
    pub fn writeParts(
        self: *Tunnel,
        first: []const u8,
        second: []const u8,
        end_stream: bool,
    ) Error!void {
        return self.writeSlices(&.{ first, second }, end_stream);
    }

    pub fn writePartsWithTimeout(
        self: *Tunnel,
        first: []const u8,
        second: []const u8,
        end_stream: bool,
        progress: *TunnelWriteProgress,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writePartsWithDeadline(
            first,
            second,
            end_stream,
            progress,
            .fromNow(self.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn writePartsWithDeadline(
        self: *Tunnel,
        first: []const u8,
        second: []const u8,
        end_stream: bool,
        progress: *TunnelWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        return self.writeSlicesWithDeadline(
            &.{ first, second },
            end_stream,
            progress,
            deadline,
        );
    }

    /// Write borrowed slices as one ordered tunnel byte sequence. The HTTP/2
    /// DATA framing layer may split or combine ranges at frame and flow-control
    /// boundaries without copying their contents.
    pub fn writeSlices(
        self: *Tunnel,
        slices: []const []const u8,
        end_stream: bool,
    ) Error!void {
        var progress: TunnelWriteProgress = .{};
        return self.writeSlicesUntil(
            slices,
            end_stream,
            &progress,
            null,
            false,
        ) catch |err| switch (err) {
            error.Timeout => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn writeSlicesWithTimeout(
        self: *Tunnel,
        slices: []const []const u8,
        end_stream: bool,
        progress: *TunnelWriteProgress,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeSlicesWithDeadline(
            slices,
            end_stream,
            progress,
            .fromNow(self.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn writeSlicesWithDeadline(
        self: *Tunnel,
        slices: []const []const u8,
        end_stream: bool,
        progress: *TunnelWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.writeSlicesUntil(
            slices,
            end_stream,
            progress,
            deadline,
            false,
        );
    }

    /// Begin one logical multi-call tunnel write. The initial preflight is
    /// performed once so connection-level reads needed for flow-control credit
    /// cannot turn a later chunk of the same byte sequence into
    /// `ResponseAvailable`. The returned writer borrows this tunnel and must
    /// not overlap another reader or writer on the HTTP/2 connection.
    pub fn beginWriteSequence(self: *Tunnel) Error!TunnelWriter {
        try self.ensureWritable();
        try self.connection.prepareDataWrite(self.stream_id);
        return .{ .tunnel = self };
    }

    pub fn closeWrite(self: *Tunnel) Error!void {
        return self.write(&.{}, true);
    }

    pub fn closeWriteWithTimeout(
        self: *Tunnel,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        var progress: TunnelWriteProgress = .{};
        return self.writeWithTimeout(&.{}, true, &progress, timeout);
    }

    pub fn closeWriteWithDeadline(
        self: *Tunnel,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        var progress: TunnelWriteProgress = .{};
        return self.writeWithDeadline(&.{}, true, &progress, deadline);
    }

    pub fn reset(self: *Tunnel, error_code: http2.ErrorCode) Error!void {
        if (self.released.load(.acquire)) return error.ConnectionClosed;
        defer self.finishReset();
        return self.connection.terminateOwnedStream(self.stream_id, error_code);
    }

    pub fn abort(
        self: *Tunnel,
        deadline: ?std.Io.Clock.Timestamp,
    ) void {
        if (self.released.load(.acquire)) return;
        self.connection.abortExtendedConnect(self.stream_id, deadline);
        self.finishReset();
    }

    pub fn read(self: *Tunnel) Error!OwnedTunnelData {
        return self.readWithDeadlineInternal(null);
    }

    pub fn readWithTimeout(
        self: *Tunnel,
        timeout: std.Io.Duration,
    ) Error!OwnedTunnelData {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readWithDeadlineInternal(.fromNow(
            self.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn readWithDeadline(
        self: *Tunnel,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedTunnelData {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.readWithDeadlineInternal(deadline);
    }

    fn readWithDeadlineInternal(
        self: *Tunnel,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!OwnedTunnelData {
        if (self.receive_finished.load(.acquire)) {
            return error.ConnectionClosed;
        }
        if (self.connection.duplex_reader_active) {
            return error.UnexpectedFrame;
        }
        self.connection.duplex_reader_active = true;
        defer self.connection.duplex_reader_active = false;

        // A previous tunnel read yielded after preserving another stream's
        // frame. Let that stream's ordinary reader make progress before this
        // tunnel consumes more bytes from the shared connection.
        if (self.connection.pendingApplicationFrameCount() != 0 and
            !self.connection.pending_duplex_sibling_header.hasValue())
        {
            return error.ResponseAvailable;
        }
        while (true) {
            var frame = try self.connection
                .readOwnedFrameForDuplexWithDeadline(deadline);
            var frame_owned = true;
            defer if (frame_owned) {
                frame.deinit(self.connection.allocator);
            };
            if (try self.connection.handleConnectionFrameUntil(frame.frame, deadline)) {
                frame.deinit(self.connection.allocator);
                frame_owned = false;
                continue;
            }
            if (frame.frame.header.frame_type == .goaway) {
                const goaway = try http2.GoAwayPayload.parse(frame.frame);
                try self.connection.handleGoAwayForStream(self.stream_id, goaway);
                frame.deinit(self.connection.allocator);
                frame_owned = false;
                continue;
            }
            if (frame.frame.header.stream_id != self.stream_id) {
                try self.connection.queueDuplexSiblingFrameUntil(frame);
                frame_owned = false;
                // Keep consuming an uninterrupted HEADERS/CONTINUATION block
                // so HPACK advances in wire order before handing the sibling
                // stream back to an ordinary request/response reader.
                if (self.connection.pending_duplex_sibling_header.hasValue()) {
                    continue;
                }
                return error.ResponseAvailable;
            }
            switch (frame.frame.header.frame_type) {
                .data => {
                    const payload = try self.connection.receiveDataPayload(self.stream_id, frame.frame);
                    defer self.connection.releaseDataFrameBudget(payload);
                    const end_stream = (frame.frame.header.flags & flag_end_stream) != 0;
                    try self.connection.releaseReceivedDataCapacityUntil(
                        self.stream_id,
                        payload,
                        end_stream,
                        deadline,
                    );
                    if (payload.data.len == 0 and !end_stream) {
                        frame.deinit(self.connection.allocator);
                        frame_owned = false;
                        continue;
                    }
                    if (end_stream) self.finishReceive();
                    frame_owned = false;
                    return .{
                        .frame = frame,
                        .data = payload.data,
                        .end_stream = end_stream,
                    };
                },
                .rst_stream => {
                    const peer_reset = try http2.ResetStreamPayload.parse(
                        frame.frame,
                    );
                    self.connection.recordResetStream(peer_reset) catch |err| {
                        self.finishReset();
                        return err;
                    };
                    self.finishReset();
                    return error.StreamReset;
                },
                .headers => return error.UnexpectedFrame,
                else => {
                    frame.deinit(self.connection.allocator);
                    frame_owned = false;
                    continue;
                },
            }
        }
    }

    fn ensureWritable(self: *Tunnel) Error!void {
        if (self.send_finished.load(.acquire)) return error.ConnectionClosed;
        if (!self.connection.outboundStreamIsActive(self.stream_id)) {
            return error.StreamReset;
        }
    }

    fn writeSlicesUntil(
        self: *Tunnel,
        slices: []const []const u8,
        end_stream: bool,
        progress: *TunnelWriteProgress,
        deadline: ?std.Io.Clock.Timestamp,
        prepared: bool,
    ) ResponseTimeoutError!void {
        progress.* = .{};
        if (deadline) |absolute| {
            _ = try deadline_policy.usableAwake(
                self.connection.io,
                absolute,
            );
        }
        try self.ensureWritable();
        if (!prepared) try self.connection.prepareDataWrite(self.stream_id);
        self.connection.writeDataSlicesPreparedTrackedUntil(
            self.stream_id,
            slices,
            end_stream,
            &progress.committed_bytes,
            deadline,
        ) catch |err| return err;
        progress.fin_committed = end_stream;
        if (end_stream) self.finishSend();
    }

    fn finishSend(self: *Tunnel) void {
        self.send_finished.store(true, .release);
        self.maybeRelease();
    }

    fn finishReceive(self: *Tunnel) void {
        self.receive_finished.store(true, .release);
        self.maybeRelease();
    }

    fn finishReset(self: *Tunnel) void {
        self.send_finished.store(true, .release);
        self.receive_finished.store(true, .release);
        _ = self.released.swap(true, .acq_rel);
    }

    fn maybeRelease(self: *Tunnel) void {
        if (!self.send_finished.load(.acquire) or
            !self.receive_finished.load(.acquire) or
            self.released.swap(true, .acq_rel)) return;
        self.connection.releaseLocalStream(self.stream_id);
        self.connection.releasePeerStream(self.stream_id);
        self.connection.forgetStreamWindows(self.stream_id);
    }
};

pub const TunnelWriter = struct {
    tunnel: *Tunnel,

    pub fn write(
        self: *TunnelWriter,
        data: []const u8,
        end_stream: bool,
    ) Error!void {
        return self.writeSlices(&.{data}, end_stream);
    }

    pub fn writeWithTimeout(
        self: *TunnelWriter,
        data: []const u8,
        end_stream: bool,
        progress: *TunnelWriteProgress,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        return self.writeSlicesWithTimeout(
            &.{data},
            end_stream,
            progress,
            timeout,
        );
    }

    pub fn writeWithDeadline(
        self: *TunnelWriter,
        data: []const u8,
        end_stream: bool,
        progress: *TunnelWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        return self.writeSlicesWithDeadline(
            &.{data},
            end_stream,
            progress,
            deadline,
        );
    }

    pub fn writeParts(
        self: *TunnelWriter,
        first: []const u8,
        second: []const u8,
        end_stream: bool,
    ) Error!void {
        return self.writeSlices(&.{ first, second }, end_stream);
    }

    pub fn writePartsWithTimeout(
        self: *TunnelWriter,
        first: []const u8,
        second: []const u8,
        end_stream: bool,
        progress: *TunnelWriteProgress,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        return self.writeSlicesWithTimeout(
            &.{ first, second },
            end_stream,
            progress,
            timeout,
        );
    }

    pub fn writePartsWithDeadline(
        self: *TunnelWriter,
        first: []const u8,
        second: []const u8,
        end_stream: bool,
        progress: *TunnelWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        return self.writeSlicesWithDeadline(
            &.{ first, second },
            end_stream,
            progress,
            deadline,
        );
    }

    pub fn writeSlices(
        self: *TunnelWriter,
        slices: []const []const u8,
        end_stream: bool,
    ) Error!void {
        var progress: TunnelWriteProgress = .{};
        return self.tunnel.writeSlicesUntil(
            slices,
            end_stream,
            &progress,
            null,
            true,
        ) catch |err| switch (err) {
            error.Timeout => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn writeSlicesWithTimeout(
        self: *TunnelWriter,
        slices: []const []const u8,
        end_stream: bool,
        progress: *TunnelWriteProgress,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeSlicesWithDeadline(
            slices,
            end_stream,
            progress,
            .fromNow(self.tunnel.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn writeSlicesWithDeadline(
        self: *TunnelWriter,
        slices: []const []const u8,
        end_stream: bool,
        progress: *TunnelWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        return self.tunnel.writeSlicesUntil(
            slices,
            end_stream,
            progress,
            deadline,
            true,
        );
    }
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

fn writeFrame(
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

fn writeInitialSettings(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, limits: Limits, role: Role) Error!void {
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

fn readExact(io: std.Io, stream: net.Stream, buffer: []u8) ReadExactError!void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        var buffers = [_][]u8{buffer[offset..]};
        const n = try io.vtable.netRead(
            io.userdata,
            stream.socket.handle,
            &buffers,
        );
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

test "HTTP/2 connection keeps optional state compact" {
    if (@sizeOf(usize) == 8) {
        const connection_size: usize = switch (builtin.mode) {
            .Debug, .ReleaseSafe => 2_080,
            .ReleaseFast, .ReleaseSmall => 2_000,
        };
        try std.testing.expectEqual(connection_size, @sizeOf(Connection));
        try std.testing.expectEqual(@as(usize, 48), @sizeOf(OwnedFrameSlot));
        try std.testing.expectEqual(@as(usize, 56), @sizeOf(RetainedFrameSlot));
        try std.testing.expectEqual(
            @as(usize, 40),
            @sizeOf(DuplexHeaderBlockSlot),
        );
        try std.testing.expectEqual(
            @as(usize, 128),
            @sizeOf(ClientDuplexStream),
        );
        try std.testing.expectEqual(
            // Includes the pull-body `current_body` DATA owner and retained
            // request trailers used by `nextBody`; both are per active stream.
            @as(usize, 304),
            @sizeOf(ServerDuplexStream),
        );
        try std.testing.expectEqual(
            @sizeOf(?*peer_metadata.Origins),
            @sizeOf(@FieldType(Connection, "peer_origins")),
        );
        try std.testing.expectEqual(
            @sizeOf(?*peer_metadata.AlternativeServices),
            @sizeOf(@FieldType(Connection, "alternative_services")),
        );
        try std.testing.expectEqual(
            @sizeOf(?*http2.Hpack.Decoder),
            @sizeOf(@FieldType(Connection, "graceful_preadmit_decoder")),
        );
        try std.testing.expectEqual(
            @sizeOf(?*http2.Hpack.Encoder),
            @sizeOf(@FieldType(Connection, "hpack_encoder_staging")),
        );
        try std.testing.expectEqual(
            @as(usize, 8),
            @sizeOf(@FieldType(Connection, "push_state")),
        );
        try std.testing.expectEqual(
            @as(usize, 8),
            @sizeOf(@FieldType(Connection, "priority_state")),
        );
        try std.testing.expectEqual(
            @as(usize, 8),
            @sizeOf(@FieldType(Connection, "webtransport_settings")),
        );
    }

    const connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    try std.testing.expect(connection.peer_origins == null);
    try std.testing.expect(connection.alternative_services == null);
    try std.testing.expect(connection.graceful_preadmit_decoder == null);
    try std.testing.expect(connection.hpack_encoder_staging == null);
    try std.testing.expect(connection.push_state.state == null);
    try std.testing.expect(connection.priority_state.state == null);
    try std.testing.expect(!connection.borrowed_pending_frame.hasValue());
    try std.testing.expect(!connection.pending_application_overflow.hasValue());
    try std.testing.expect(!connection.duplex_pending_frame.hasValue());
    try std.testing.expect(!connection.pending_duplex_request_head.hasValue());
    try std.testing.expect(!connection.pending_duplex_sibling_header.hasValue());
    try std.testing.expectEqual(@as(usize, 0), connection.peerOrigins().len);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.alternativeServices().len,
    );
}

test "HTTP/2 compact owned frame slot transfers ownership" {
    const allocator = std.testing.allocator;
    var slot = OwnedFrameSlot{};
    slot.deinit(allocator);
    try std.testing.expect(!slot.hasValue());

    const bytes = try allocator.alloc(u8, http2.FrameHeader.encoded_len);
    slot.put(.{ .bytes = bytes, .frame = undefined });
    try std.testing.expect(slot.hasValue());
    var owned = slot.take() orelse return error.TestUnexpectedResult;
    try std.testing.expect(!slot.hasValue());
    owned.deinit(allocator);

    const second = try allocator.alloc(u8, http2.FrameHeader.encoded_len);
    slot.put(.{ .bytes = second, .frame = undefined });
    slot.deinit(allocator);
    try std.testing.expect(!slot.hasValue());
}

test "HTTP/2 compact duplex header slot uses stream zero as empty" {
    var slot = DuplexHeaderBlockSlot{};
    try std.testing.expect(!slot.hasValue());
    slot.put(.{
        .stream_id = 1,
        .end_stream = true,
        .end_headers = true,
    });
    try std.testing.expect(slot.hasValue());
    try std.testing.expectEqual(@as(u31, 1), slot.getPtr().?.stream_id);
    slot.deinit(std.testing.allocator);
    try std.testing.expect(!slot.hasValue());
}

test "HTTP/2 lazy staged HPACK encoder rolls back allocation failure" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.deinitStagedHpackEncoder();
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }

    _ = try connection.hpack_encoder.encodeBlockRetained(allocator, &.{.{
        .name = "x-live",
        .value = "one",
    }});
    const live_entries =
        connection.hpack_encoder.dynamic_table.entries.items.len;

    {
        var failing = std.testing.FailingAllocator.init(allocator, .{
            // The staging object allocation succeeds; copying its non-empty
            // dynamic table then fails and must destroy the detached object.
            .fail_index = 1,
        });
        connection.allocator = failing.allocator();
        defer connection.allocator = allocator;
        try std.testing.expectError(
            error.OutOfMemory,
            connection.prepareStagedHpackEncoder(),
        );
    }

    try std.testing.expect(connection.hpack_encoder_staging == null);
    try std.testing.expectEqual(
        live_entries,
        connection.hpack_encoder.dynamic_table.entries.items.len,
    );
    const staging = try connection.prepareStagedHpackEncoder();
    try std.testing.expectEqual(
        live_entries,
        staging.dynamic_table.entries.items.len,
    );
}

test "HTTP/2 lazy graceful HPACK clone rolls back allocation failure" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .graceful_shutdown_phase = .synchronizing,
    };
    defer {
        connection.clearGracefulPreadmitDecoder();
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }

    const inserted = try connection.hpack_decoder.decodeBlockOwnedWithLimit(
        allocator,
        "\x40\x01x\x01y",
        1,
        64,
    );
    freeHeaders(allocator, inserted);

    var failing = std.testing.FailingAllocator.init(allocator, .{
        // The shadow object allocation succeeds; cloning its non-empty
        // dynamic table then fails and must destroy the detached object.
        .fail_index = 1,
    });
    connection.allocator = failing.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        connection.preadmitGracefulPeerRequest(.{
            .header = .{
                .length = 0,
                .frame_type = .headers,
                .flags = flag_end_headers | flag_end_stream,
                .stream_id = 1,
            },
            .payload = &.{},
        }),
    );
    connection.allocator = allocator;
    try std.testing.expect(connection.graceful_preadmit_decoder == null);
    try std.testing.expect(
        connection.graceful_preadmit_base_processed_stream_id == null,
    );
}

test "HTTP/2 lazy peer metadata creation is transactional" {
    const allocator = std.testing.allocator;

    var origin_failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 1,
    });
    var origin_connection = Connection{
        .io = undefined,
        .allocator = origin_failing.allocator(),
        .stream = undefined,
        .role = .client,
    };
    defer {
        origin_connection.deinitPeerMetadata();
        origin_connection.hpack_decoder.deinit(allocator);
        origin_connection.hpack_encoder.deinit(allocator);
    }
    try std.testing.expectError(
        error.OutOfMemory,
        origin_connection.storePeerOrigin("https://example.com"),
    );
    try std.testing.expect(origin_connection.peer_origins == null);
    origin_connection.allocator = allocator;
    try origin_connection.storePeerOrigin("https://example.com");

    var alternative_failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 1,
    });
    var alternative_connection = Connection{
        .io = undefined,
        .allocator = alternative_failing.allocator(),
        .stream = undefined,
        .role = .client,
    };
    defer {
        alternative_connection.deinitPeerMetadata();
        alternative_connection.hpack_decoder.deinit(allocator);
        alternative_connection.hpack_encoder.deinit(allocator);
    }
    try std.testing.expectError(
        error.OutOfMemory,
        alternative_connection.storeAlternativeService(
            0,
            "https://example.com",
            "h3=\":443\"",
        ),
    );
    try std.testing.expect(alternative_connection.alternative_services == null);
    alternative_connection.allocator = allocator;
    try alternative_connection.storeAlternativeService(
        0,
        "https://example.com",
        "h3=\":443\"",
    );
}

test "HTTP/2 runtime accumulates server ORIGIN entries" {
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
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            connection.sendOrigins(&.{
                "https://example.com",
                "https://cdn.example.com",
            }) catch |err| {
                shared.err = err;
                return;
            };
            // Duplicate entries are legal; clients maintain set semantics.
            connection.sendOrigins(&.{
                "https://cdn.example.com",
                "https://img.example.com",
            }) catch |err| {
                shared.err = err;
                return;
            };
            const ping = connection.readPing() catch |err| {
                shared.err = err;
                return;
            };
            _ = ping;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_peer_origins = 2 },
    );
    defer client.close();
    // Any connection-level read pumps ORIGIN through shared state. Two reads
    // consume the two frames without requiring a synthetic request stream.
    var first = try readFrame(allocator, io, client.stream, client.limits);
    defer first.deinit(allocator);
    try std.testing.expect(try client.handleConnectionFrame(first.frame));
    var second = try readFrame(allocator, io, client.stream, client.limits);
    defer second.deinit(allocator);
    try std.testing.expect(try client.handleConnectionFrame(second.frame));
    try std.testing.expectEqual(@as(usize, 2), client.peerOrigins().len);
    try std.testing.expectEqualStrings(
        "https://cdn.example.com",
        client.peerOrigins()[1],
    );
    try std.testing.expect(client.peerOriginKnown("https://cdn.example.com"));
    try std.testing.expect(!client.peerOriginKnown("https://img.example.com"));
    try std.testing.expectEqual(
        @as(?usize, 1),
        client.peer_origins.?.getIndex("https://cdn.example.com"),
    );
    try std.testing.expect(
        client.peer_origins.?.getIndex("https://img.example.com") == null,
    );
    try std.testing.expect(
        client.peer_origins.?.getIndex("https://missing.example.com") == null,
    );
    _ = try client.ping([_]u8{0x41} ** 8);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 duplicate ORIGIN entry does not allocate" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.deinitPeerMetadata();
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }

    try connection.storePeerOrigin("https://example.com");
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    const saved_allocator = connection.allocator;
    connection.allocator = no_alloc.allocator();
    defer connection.allocator = saved_allocator;
    try connection.storePeerOrigin("https://example.com");
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 1), connection.peerOrigins().len);
}

test "HTTP/2 ORIGIN state enforces connection bound" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .limits = .{ .max_peer_origins = 2 },
    };
    defer {
        connection.deinitPeerMetadata();
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }

    try connection.storePeerOrigin("https://one.example");
    try connection.storePeerOrigin("https://two.example");
    const capacity = connection.peer_origins.?.capacity();
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    const saved_allocator = connection.allocator;
    connection.allocator = no_alloc.allocator();
    defer connection.allocator = saved_allocator;
    try connection.storePeerOrigin("https://one.example");
    try connection.storePeerOrigin("https://three.example");
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 2), connection.peerOrigins().len);
    try std.testing.expectEqual(capacity, connection.peer_origins.?.capacity());
    try std.testing.expect(!connection.peerOriginKnown(
        "https://three.example",
    ));
}

test "HTTP/2 runtime ignores invalid ORIGIN envelope and client origin" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.deinitPeerMetadata();
    }
    const payload = [_]u8{ 0, 1, 'x' };
    // Non-zero stream and incompatible flags are ignored per RFC 8336.
    try std.testing.expect(try connection.handleConnectionFrame(.{
        .header = .{
            .length = payload.len,
            .frame_type = .origin,
            .flags = 0,
            .stream_id = 1,
        },
        .payload = &payload,
    }));
    try std.testing.expect(try connection.handleConnectionFrame(.{
        .header = .{
            .length = payload.len,
            .frame_type = .origin,
            .flags = 1,
            .stream_id = 0,
        },
        .payload = &payload,
    }));
    try std.testing.expectEqual(@as(usize, 0), connection.peerOrigins().len);

    var server_connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        server_connection.deinitPeerMetadata();
    }
    try std.testing.expect(try server_connection.handleConnectionFrame(.{
        .header = .{
            .length = payload.len,
            .frame_type = .origin,
            .flags = 0,
            .stream_id = 0,
        },
        .payload = &payload,
    }));
    try std.testing.expectEqual(
        @as(usize, 0),
        server_connection.peerOrigins().len,
    );
}

test "HTTP/2 runtime receives connection and stream ALTSVC frames" {
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
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            connection.sendAlternativeService(
                0,
                "https://example.com",
                "h3=\":443\"; ma=3600",
            ) catch |err| {
                shared.err = err;
                return;
            };
            connection.sendAlternativeService(
                0,
                "https://example.com",
                "h3=\":8443\"; ma=60",
            ) catch |err| {
                shared.err = err;
                return;
            };
            connection.sendAlternativeService(
                1,
                "",
                "h2=\"alt.example.com:443\"",
            ) catch |err| {
                shared.err = err;
                return;
            };
            connection.sendAlternativeService(
                3,
                "",
                "h2=\"ignored.example.com:443\"",
            ) catch |err| {
                shared.err = err;
                return;
            };
            _ = connection.readPing() catch |err| {
                shared.err = err;
                return;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .max_frame_payload = 4096,
            .max_alternative_services = 2,
        },
    );
    defer client.close();
    inline for (0..4) |_| {
        var frame = try readFrame(
            allocator,
            io,
            client.stream,
            client.limits,
        );
        defer frame.deinit(allocator);
        try std.testing.expect(try client.handleConnectionFrame(frame.frame));
    }
    try std.testing.expectEqual(
        @as(usize, 2),
        client.alternativeServices().len,
    );
    try std.testing.expectEqualStrings(
        "https://example.com",
        client.alternativeServices()[0].origin,
    );
    try std.testing.expectEqualStrings(
        "h3=\":8443\"; ma=60",
        client.alternativeServices()[0].field_value,
    );
    try std.testing.expectEqual(
        @as(u31, 1),
        client.alternativeServices()[1].stream_id,
    );
    try std.testing.expectEqual(
        @as(?usize, 0),
        client.alternative_services.?.getIndex(
            0,
            "https://example.com",
        ),
    );
    try std.testing.expectEqual(
        @as(?usize, 1),
        client.alternative_services.?.getIndex(1, ""),
    );
    try std.testing.expect(
        client.alternative_services.?.getIndex(
            0,
            "https://missing.example.com",
        ) == null,
    );
    try std.testing.expect(
        client.alternative_services.?.getIndex(3, "") == null,
    );
    _ = try client.ping([_]u8{0x42} ** 8);
    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 ALTSVC identical replacement does not allocate" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.deinitPeerMetadata();
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }

    try connection.storeAlternativeService(
        0,
        "https://example.com",
        "h3=\":443\"; ma=3600",
    );
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    const saved_allocator = connection.allocator;
    connection.allocator = no_alloc.allocator();
    defer connection.allocator = saved_allocator;
    try connection.storeAlternativeService(
        0,
        "https://example.com",
        "h3=\":443\"; ma=3600",
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(
        @as(usize, 1),
        connection.alternativeServices().len,
    );
}

test "HTTP/2 ALTSVC state enforces connection bound" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .limits = .{ .max_alternative_services = 2 },
    };
    defer {
        connection.deinitPeerMetadata();
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }

    try connection.storeAlternativeService(
        0,
        "https://one.example",
        "h3=\":443\"; ma=60",
    );
    try connection.storeAlternativeService(
        1,
        "",
        "h2=\"two.example:443\"",
    );
    try connection.storeAlternativeService(
        0,
        "https://one.example",
        "h3=\":8443\"; ma=30",
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        connection.alternativeServices().len,
    );
    try std.testing.expectEqualStrings(
        "h3=\":8443\"; ma=30",
        connection.alternativeServices()[0].field_value,
    );

    const capacity = connection.alternative_services.?.capacity();
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    const saved_allocator = connection.allocator;
    connection.allocator = no_alloc.allocator();
    defer connection.allocator = saved_allocator;
    try connection.storeAlternativeService(
        3,
        "",
        "h3=\"three.example:443\"",
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(
        @as(usize, 2),
        connection.alternativeServices().len,
    );
    try std.testing.expectEqual(
        capacity,
        connection.alternative_services.?.capacity(),
    );
}

test "HTTP/2 zero advertisement bounds retain no peer metadata" {
    const allocator = std.testing.allocator;
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    var connection = Connection{
        .io = undefined,
        .allocator = no_alloc.allocator(),
        .stream = undefined,
        .role = .client,
        .limits = .{
            .max_peer_origins = 0,
            .max_alternative_services = 0,
        },
    };
    defer {
        connection.deinitPeerMetadata();
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }

    try connection.storePeerOrigin("https://ignored.example");
    try connection.storeAlternativeService(
        0,
        "https://ignored.example",
        "h3=\":443\"",
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), connection.peerOrigins().len);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.alternativeServices().len,
    );
}

test "HTTP/2 h2c runtime client and server exchange over TCP" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var client_window = try connection.readWindowUpdate();
            defer client_window.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(u31, 0), client_window.window_update.stream_id);
            try std.testing.expectEqual(@as(u31, 4096), client_window.window_update.increment);

            const ping_data = try connection.readPing();
            try std.testing.expectEqualSlices(u8, &[_]u8{ 8, 6, 7, 5, 3, 0, 9, 9 }, &ping_data);

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("POST", request.method);
            try std.testing.expectEqualStrings("/echo", request.path);
            try std.testing.expectEqualStrings("ping", request.body);

            try connection.writeResponse(request.stream_id, .{
                .status = 200,
                .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
                .body = "pong",
            });
            try connection.sendWindowUpdate(0, 2048);
            try connection.sendWindowUpdate(request.stream_id, 1024);
            try connection.sendGoAway(request.stream_id, .no_error, "done");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    try client.sendWindowUpdate(0, 4096);
    const ping_ack = try client.ping(.{ 8, 6, 7, 5, 3, 0, 9, 9 });
    try std.testing.expectEqualSlices(u8, &[_]u8{ 8, 6, 7, 5, 3, 0, 9, 9 }, &ping_ack);

    var response = try client.request(.{
        .method = "POST",
        .path = "/echo",
        .authority = "127.0.0.1",
        .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
        .body = "ping",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("pong", response.body);
    try std.testing.expectEqualStrings("text/plain", findHeader(response.headers, "content-type").?);
    var window = try client.readWindowUpdate();
    defer window.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 2048), window.window_update.increment);
    try std.testing.expectEqual(@as(i64, default_flow_window + 2048 - "ping".len), client.send_connection_window.value);
    var stream_window = try client.readWindowUpdate();
    defer stream_window.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), stream_window.window_update.stream_id);
    try std.testing.expectEqual(@as(u31, 1024), stream_window.window_update.increment);
    // The response closed stream 1 before this late WINDOW_UPDATE arrived.
    // Return the frame to the explicit observer without recreating the
    // retired stream's window. RFC 9113 permits ignoring this race.
    try std.testing.expectEqual(@as(usize, 0), client.send_stream_window_index.count());
    try std.testing.expectEqual(@as(usize, 0), client.send_stream_windows.items.len);
    var goaway = try client.readGoAway();
    defer goaway.deinit(allocator);
    try std.testing.expectEqual(http2.ErrorCode.no_error, goaway.goaway.error_code);
    try std.testing.expectEqualStrings("done", goaway.goaway.debug_data);
}

test "HTTP/2 server sends 100 Continue before reading an expected body" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/expect", request.path);
            try std.testing.expectEqualStrings("ping", request.body);
            try std.testing.expectEqualStrings(
                "100-continue",
                findHeader(request.headers, "expect").?,
            );
            try connection.writeResponse(request.stream_id, .{
                .status = 200,
                .body = "pong",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    const Observer = struct {
        seen_continue: bool = false,

        fn onResponse(context: *anyopaque, response: StreamingResponseHead) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (response.status == 100) self.seen_continue = true;
        }
    };
    var observer = Observer{};
    var response = try client.requestWithInformational(.{
        .method = "POST",
        .path = "/expect",
        .authority = "127.0.0.1",
        .headers = &.{.{ .name = "expect", .value = "100-continue" }},
        .body = "ping",
    }, .{
        .context = &observer,
        .on_response = Observer.onResponse,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expect(observer.seen_continue);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("pong", response.body);
}

test "HTTP/2 streaming server sends 100 Continue before body callbacks" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            const Sink = struct {
                bytes: usize = 0,

                fn consume(self: *@This(), data: []const u8) !void {
                    self.bytes += data.len;
                }
            };
            var sink = Sink{};
            var request = try connection.readRequestStreaming(
                &sink,
                Sink.consume,
            );
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/expect-streaming", request.path);
            try std.testing.expectEqual(@as(usize, 4), sink.bytes);
            try std.testing.expectEqualStrings(
                "100-continue",
                findHeader(request.headers, "expect").?,
            );
            try connection.writeResponse(request.stream_id, .{
                .status = 200,
                .body = "pong",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var writer = try client.startRequest(.{
        .method = "POST",
        .path = "/expect-streaming",
        .authority = "127.0.0.1",
        .headers = &.{.{ .name = "expect", .value = "100-continue" }},
        .body_length = 4,
    });
    defer writer.deinit();
    try writer.write("ping");
    try writer.finish();

    const Observer = struct {
        seen_continue: bool = false,

        fn onResponse(context: *anyopaque, response: StreamingResponseHead) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (response.status == 100) self.seen_continue = true;
        }
    };
    var observer = Observer{};
    var response = try writer.readResponseWithInformational(.{
        .context = &observer,
        .on_response = Observer.onResponse,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expect(observer.seen_continue);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("pong", response.body);
}

test "HTTP/2 aggregate empty exchange borrows wire frames after warmup" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            {
                var warmup = try connection.readRequest();
                defer warmup.deinit(server_ptr.allocator);
                try std.testing.expectEqualStrings("/measured", warmup.path);
                try connection.writeResponse(warmup.stream_id, .{});
            }

            const second_stream_id = blk: {
                var tracking = std.testing.FailingAllocator.init(
                    allocator,
                    .{},
                );
                const saved_allocator = connection.allocator;
                connection.allocator = tracking.allocator();
                defer connection.allocator = saved_allocator;

                var request = try connection.readRequest();
                defer request.deinit(connection.allocator);
                try std.testing.expectEqualStrings("/measured", request.path);
                try std.testing.expectEqualStrings("", request.body);
                // The owned HPACK fields and strings share one allocation. The
                // complete HEADERS wire frame remains borrowed from the
                // reusable frame-reader buffer.
                try std.testing.expectEqual(
                    @as(usize, 1),
                    tracking.allocations,
                );
                break :blk request.stream_id;
            };
            try connection.writeResponse(second_stream_id, .{});

            {
                var warmup = try connection.readRequest();
                defer warmup.deinit(server_ptr.allocator);
                try std.testing.expectEqualStrings(
                    "small-body",
                    warmup.body,
                );
                try connection.writeResponse(warmup.stream_id, .{});
            }

            const post_stream_id = blk: {
                var tracking = std.testing.FailingAllocator.init(
                    allocator,
                    .{},
                );
                const saved_allocator = connection.allocator;
                connection.allocator = tracking.allocator();
                defer connection.allocator = saved_allocator;

                var request = try connection.readRequest();
                defer request.deinit(connection.allocator);
                try std.testing.expectEqualStrings("POST", request.method);
                try std.testing.expectEqualStrings(
                    "small-body",
                    request.body,
                );
                // Known Content-Length reserves the exact body once. Together
                // with the combined HPACK block, no other allocation remains.
                try std.testing.expectEqual(
                    @as(usize, 2),
                    tracking.allocations,
                );
                break :blk request.stream_id;
            };
            try connection.writeResponse(post_stream_id, .{});

            for (0..2) |_| {
                var request = try connection.readRequest();
                defer request.deinit(server_ptr.allocator);
                try connection.writeResponse(request.stream_id, .{
                    .body = "small-body",
                });
            }

            {
                var body_bytes: usize = 0;
                var tracking = std.testing.FailingAllocator.init(
                    allocator,
                    .{},
                );
                const saved_allocator = connection.allocator;
                connection.allocator = tracking.allocator();
                defer connection.allocator = saved_allocator;

                var request = try connection.readRequestStreaming(
                    &body_bytes,
                    struct {
                        fn consume(
                            count: *usize,
                            data: []const u8,
                        ) !void {
                            count.* += data.len;
                        }
                    }.consume,
                );
                defer request.deinit(connection.allocator);
                try std.testing.expectEqual(@as(usize, 10), body_bytes);
                // Streaming DATA is borrowed and the HEADERS wire frame now
                // remains borrowed too, leaving only the owned HPACK block.
                try std.testing.expectEqual(
                    @as(usize, 1),
                    tracking.allocations,
                );
                try connection.writeResponse(request.stream_id, .{});
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    {
        var warmup = try client.request(.{
            .path = "/measured",
            .authority = "localhost",
        });
        defer warmup.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), warmup.status);
    }

    const pending = try client.sendCompleteRequest(.{
        .path = "/measured",
        .authority = "localhost",
    });
    {
        var tracking = std.testing.FailingAllocator.init(allocator, .{});
        const saved_allocator = client.allocator;
        client.allocator = tracking.allocator();
        defer client.allocator = saved_allocator;

        var response = try client.readResponse(
            pending.stream_id,
            pending.request_method,
            pending.extended_connect,
            null,
        );
        defer response.deinit(client.allocator);
        try std.testing.expectEqual(@as(u16, 200), response.status);
        try std.testing.expectEqualStrings("", response.body);
        // As on the request side, aggregate ownership is one HPACK block.
        try std.testing.expectEqual(@as(usize, 1), tracking.allocations);
    }

    {
        var response = try client.request(.{
            .method = "POST",
            .path = "/measured",
            .authority = "localhost",
            .body = "small-body",
        });
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), response.status);
    }
    {
        var response = try client.request(.{
            .method = "POST",
            .path = "/measured",
            .authority = "localhost",
            .body = "small-body",
        });
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), response.status);
    }

    {
        var warmup = try client.request(.{
            .path = "/measured",
            .authority = "localhost",
        });
        defer warmup.deinit(allocator);
        try std.testing.expectEqualStrings("small-body", warmup.body);
    }
    {
        const response_pending = try client.sendCompleteRequest(.{
            .path = "/measured",
            .authority = "localhost",
        });
        var tracking = std.testing.FailingAllocator.init(allocator, .{});
        const saved_allocator = client.allocator;
        client.allocator = tracking.allocator();
        defer client.allocator = saved_allocator;

        var response = try client.readResponse(
            response_pending.stream_id,
            response_pending.request_method,
            response_pending.extended_connect,
            null,
        );
        defer response.deinit(client.allocator);
        try std.testing.expectEqualStrings("small-body", response.body);
        // The combined HPACK block and exact body buffer are the only owned
        // allocations for a warmed known-length aggregate response.
        try std.testing.expectEqual(@as(usize, 2), tracking.allocations);
    }

    {
        var response = try client.request(.{
            .method = "POST",
            .path = "/measured",
            .authority = "localhost",
            .body = "small-body",
        });
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), response.status);
    }

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 serveConnection handles sequential requests" {
    const allocator = std.testing.allocator;

    var backend = try @import("../runtime.zig").Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        count: usize = 0,
        fn handle(ctx: *@This(), request: OwnedRequest) Error!ResponseOptions {
            ctx.count += 1;
            if (std.mem.eql(u8, request.path, "/one")) return .{ .body = "first" };
            if (std.mem.eql(u8, request.path, "/two")) return .{ .body = "second" };
            return .{ .status = 404, .body = "missing" };
        }
    };

    const Shared = struct {
        server: *Server,
        context: Context = .{},
        served: usize = 0,
        err: ?anyerror = null,
        fn run(shared: *@This()) void {
            shared.served = shared.server.serveConnection(Context, &shared.context, Context.handle, 2) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    var server_task = io.async(Shared.run, .{&shared});
    defer server_task.cancel(io);

    var client = try Client.connectHost(allocator, io, "localhost", server.address().ip4.port, .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var first = try client.request(.{ .path = "/one" });
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("first", first.body);
    var second = try client.request(.{ .path = "/two" });
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("second", second.body);
    var goaway = try client.readGoAway();
    defer goaway.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 3), goaway.goaway.last_stream_id);
    try std.testing.expectEqual(http2.ErrorCode.no_error, goaway.goaway.error_code);
    try std.testing.expectEqualStrings("serve-complete", goaway.goaway.debug_data);

    server_task.await(io);
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.served);
    try std.testing.expectEqual(@as(usize, 2), shared.context.count);
}

test "HTTP/2 serveOne converts handler informational status to final 500" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        calls: usize = 0,

        fn handle(
            self: *@This(),
            request: OwnedRequest,
        ) Error!ResponseOptions {
            self.calls += 1;
            if (std.mem.eql(u8, request.path, "/invalid-final")) {
                return .{ .status = 103 };
            }
            return .{ .status = 204 };
        }
    };
    const Shared = struct {
        server: *Server,
        context: Context = .{},
        first_error: ?anyerror = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            _ = connection.serveOne(
                Context,
                &self.context,
                Context.handle,
            ) catch |err| {
                self.first_error = err;
            };
            _ = try connection.serveOne(
                Context,
                &self.context,
                Context.handle,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    var invalid = try client.request(.{
        .path = "/invalid-final",
        .authority = "localhost",
    });
    defer invalid.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 500), invalid.status);
    try std.testing.expectEqualStrings("", invalid.body);
    var sibling = try client.request(.{
        .path = "/sibling",
        .authority = "localhost",
    });
    defer sibling.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), sibling.status);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(error.InvalidStatus, shared.first_error.?);
    try std.testing.expectEqual(@as(usize, 2), shared.context.calls);
}

test "HTTP/2 concurrent handler batch converts informational status and isolates its error" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        fn handle(
            _: *@This(),
            request: OwnedRequest,
        ) Error!ResponseOptions {
            if (std.mem.eql(u8, request.path, "/invalid-final")) {
                return .{ .status = 103 };
            }
            if (std.mem.eql(u8, request.path, "/sibling")) {
                return .{ .status = 204 };
            }
            return .{ .body = request.path };
        }
    };
    const Shared = struct {
        server: *Server,
        context: Context = .{},
        successes: usize = 0,
        first_error: ?anyerror = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var result = try connection.serveRequestBatchConcurrent(
                Context,
                &self.context,
                Context.handle,
                2,
            );
            defer result.deinit();
            self.successes = result.successCount();
            self.first_error = result.firstError();
            try std.testing.expectEqual(@as(usize, 2), result.errors.len);
            try std.testing.expectEqual(error.InvalidStatus, result.errors[0].?);
            try std.testing.expect(result.errors[1] == null);
            _ = try connection.serveOne(
                Context,
                &self.context,
                Context.handle,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    const invalid_request = try client.sendCompleteRequest(.{
        .path = "/invalid-final",
        .authority = "localhost",
    });
    const sibling_request = try client.sendCompleteRequest(.{
        .path = "/sibling",
        .authority = "localhost",
    });
    {
        var states = [_]Connection.BatchResponseState{
            .{
                .stream_id = invalid_request.stream_id,
                .request_method = invalid_request.request_method,
                .extended_connect = invalid_request.extended_connect,
            },
            .{
                .stream_id = sibling_request.stream_id,
                .request_method = sibling_request.request_method,
                .extended_connect = sibling_request.extended_connect,
            },
        };
        defer for (&states) |*state| {
            client.releaseLocalStream(state.stream_id);
            state.deinit(allocator);
        };
        try client.readResponseBatch(&states, null, null);
        try std.testing.expectEqual(@as(?u16, 500), states[0].status);
        try std.testing.expectEqualStrings("", states[0].body_owned.?);
        try std.testing.expectEqual(@as(?u16, 204), states[1].status);
    }
    var after = try client.request(.{
        .path = "/after",
        .authority = "localhost",
    });
    defer after.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), after.status);
    try std.testing.expectEqualStrings("/after", after.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.successes);
    try std.testing.expectEqual(error.InvalidStatus, shared.first_error.?);
}

test "HTTP/2 concurrent handler batch writes responses in completion order" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        io: std.Io,
        slow_started: std.Io.Event = .unset,
        release_slow: std.Io.Event = .unset,

        fn handle(
            self: *@This(),
            request: OwnedRequest,
        ) Error!ResponseOptions {
            if (std.mem.eql(u8, request.path, "/slow")) {
                self.slow_started.set(self.io);
                try self.release_slow.wait(self.io);
                return .{ .body = request.path };
            }
            try self.slow_started.wait(self.io);
            return .{ .body = request.path };
        }
    };
    const Shared = struct {
        server: *Server,
        context: Context,
        successes: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var result = try connection.serveRequestBatchConcurrent(
                Context,
                &self.context,
                Context.handle,
                2,
            );
            defer result.deinit();
            self.successes = result.successCount();
            if (result.firstError()) |err| return err;
            _ = try connection.serveOne(
                Context,
                &self.context,
                Context.handle,
            );
            try connection.sendGoAway(5, .no_error, "batch-complete");
        }
    };
    var shared = Shared{
        .server = &server,
        .context = .{ .io = io },
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.context.release_slow.set(io);
        thread.join();
    };

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    const slow = try client.sendCompleteRequest(.{
        .path = "/slow",
        .authority = "localhost",
    });
    const fast = try client.sendCompleteRequest(.{
        .path = "/fast",
        .authority = "localhost",
    });
    var fast_response = try client.readResponse(
        fast.stream_id,
        fast.request_method,
        fast.extended_connect,
        null,
    );
    defer fast_response.deinit(allocator);
    try std.testing.expectEqualStrings("/fast", fast_response.body);
    shared.context.release_slow.set(io);
    var slow_response = try client.readResponse(
        slow.stream_id,
        slow.request_method,
        slow.extended_connect,
        null,
    );
    defer slow_response.deinit(allocator);
    try std.testing.expectEqualStrings("/slow", slow_response.body);
    var after = try client.request(.{
        .path = "/after",
        .authority = "localhost",
    });
    defer after.deinit(allocator);
    try std.testing.expectEqualStrings("/after", after.body);
    var goaway = try client.readGoAway();
    defer goaway.deinit(allocator);
    try std.testing.expectEqualStrings("batch-complete", goaway.goaway.debug_data);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.successes);
}

test "HTTP/2 concurrent handler batch isolates handler errors" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        io: std.Io,
        release_failure: std.Io.Event = .unset,

        fn handle(
            self: *@This(),
            request: OwnedRequest,
        ) Error!ResponseOptions {
            if (std.mem.eql(u8, request.path, "/error")) {
                try self.release_failure.wait(self.io);
                return error.InvalidResponse;
            }
            return .{ .body = request.path };
        }
    };
    const Shared = struct {
        server: *Server,
        context: Context,
        successes: usize = 0,
        first_error: ?anyerror = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var result = try connection.serveRequestBatchConcurrent(
                Context,
                &self.context,
                Context.handle,
                2,
            );
            defer result.deinit();
            self.successes = result.successCount();
            self.first_error = result.firstError();
            try std.testing.expectEqual(@as(usize, 2), result.errors.len);
            try std.testing.expectEqual(
                error.InvalidResponse,
                result.errors[0].?,
            );
            try std.testing.expect(result.errors[1] == null);
            _ = try connection.serveOne(
                Context,
                &self.context,
                Context.handle,
            );
        }
    };
    var shared = Shared{
        .server = &server,
        .context = .{ .io = io },
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.context.release_failure.set(io);
        thread.join();
    };

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    const failed = try client.sendCompleteRequest(.{
        .path = "/error",
        .authority = "localhost",
    });
    const fast = try client.sendCompleteRequest(.{
        .path = "/fast",
        .authority = "localhost",
    });
    var fast_response = try client.readResponse(
        fast.stream_id,
        fast.request_method,
        fast.extended_connect,
        null,
    );
    defer fast_response.deinit(allocator);
    try std.testing.expectEqualStrings("/fast", fast_response.body);
    shared.context.release_failure.set(io);
    var reset = try client.readResetStream();
    defer reset.deinit(allocator);
    try std.testing.expectEqual(failed.stream_id, reset.reset.stream_id);
    try std.testing.expectEqual(http2.ErrorCode.internal_error, reset.reset.error_code);
    var after = try client.request(.{
        .path = "/after",
        .authority = "localhost",
    });
    defer after.deinit(allocator);
    try std.testing.expectEqualStrings("/after", after.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.successes);
    try std.testing.expectEqual(error.InvalidResponse, shared.first_error.?);
}

test "HTTP/2 concurrent handler batch accepts an empty server batch" {
    const Context = struct {
        fn handle(
            _: *@This(),
            _: OwnedRequest,
        ) Error!ResponseOptions {
            unreachable;
        }
    };
    var context: Context = .{};
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
    }
    var result = try connection.serveRequestBatchConcurrent(
        Context,
        &context,
        Context.handle,
        0,
    );
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.errors.len);
    try std.testing.expectEqual(@as(usize, 0), result.successCount());
    try std.testing.expect(result.firstError() == null);

    connection.limits.max_concurrent_streams = 1;
    try std.testing.expectError(
        error.InvalidServeOptions,
        connection.serveRequestBatchConcurrent(
            Context,
            &context,
            Context.handle,
            2,
        ),
    );

    connection.limits.max_concurrent_streams = null;
    try connection.addActivePeerStream(1);
    defer connection.releasePeerStream(1);
    try std.testing.expectError(
        error.InvalidServeOptions,
        connection.serveRequestBatchConcurrent(
            Context,
            &context,
            Context.handle,
            1,
        ),
    );
}

test "HTTP/2 client connects by host name" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("http", request.scheme);
            var expected_authority: [32]u8 = undefined;
            const rendered_authority = try std.fmt.bufPrint(&expected_authority, "localhost:{d}", .{server_ptr.address().ip4.port});
            try std.testing.expectEqualStrings(rendered_authority, request.authority.?);
            try connection.writeResponse(request.stream_id, .{ .body = "h2-dns-ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connectHost(allocator, io, "localhost", server.address().ip4.port, .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var response = try client.request(.{
        .method = "GET",
        .path = "/dns",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings("h2-dns-ok", response.body);
}

test "HTTP/2 client sends request to URI" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/h2-uri?x=1", request.path);
            try std.testing.expectEqualStrings("http", request.scheme);
            var expected_authority: [32]u8 = undefined;
            const rendered_authority = try std.fmt.bufPrint(&expected_authority, "localhost:{d}", .{server_ptr.address().ip4.port});
            try std.testing.expectEqualStrings(rendered_authority, request.authority.?);
            try connection.writeResponse(request.stream_id, .{ .body = "h2-uri-ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(allocator, "http://localhost:{d}/h2-uri?x=1", .{server.address().ip4.port});
    defer allocator.free(uri);
    var response = try Client.requestUri(allocator, io, uri, .{}, .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings("h2-uri-ok", response.body);

    try std.testing.expectError(error.UnsupportedScheme, Client.requestUri(allocator, io, "ftp://localhost/", .{}, .{}));
    try std.testing.expectError(error.InvalidUri, Client.requestUri(allocator, io, "http:///missing-host", .{}, .{}));
}

test "HTTP/2 client sends request to bracketed IPv6 URI" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = Server.listen(
        allocator,
        io,
        .{ .ip6 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    ) catch |err| switch (err) {
        error.AddressFamilyUnsupported, error.AddressUnavailable => return error.SkipZigTest,
        else => |e| return e,
    };
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/h2-ipv6?x=1", request.path);
            try std.testing.expectEqualStrings("http", request.scheme);
            var expected_authority: [64]u8 = undefined;
            const rendered_authority = try std.fmt.bufPrint(&expected_authority, "[::1]:{d}", .{server_ptr.address().ip6.port});
            try std.testing.expectEqualStrings(rendered_authority, request.authority.?);
            try connection.writeResponse(request.stream_id, .{ .body = "h2-ipv6-uri-ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(allocator, "http://[::1]:{d}/h2-ipv6?x=1", .{server.address().ip6.port});
    defer allocator.free(uri);
    var response = try Client.requestUri(allocator, io, uri, .{}, .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings("h2-ipv6-uri-ok", response.body);
}

test "HTTP/2 h2c upgrade carries request body and trailers on stream one" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try net.IpAddress.listen(&.{ .ip4 = .loopback(0) }, io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const stream = try shared.listener.accept(shared.io);
            defer stream.close(shared.io);

            var request = try http1_runtime.readRequestFromStream(shared.allocator, shared.io, stream, .{
                .max_head_bytes = 4096,
                .max_body_bytes = 4096,
            }, .{});
            defer request.deinit(shared.allocator);
            try std.testing.expectEqualStrings("/upgrade?x=1", request.request.target);
            try std.testing.expectEqualStrings("h2c", request.request.header("upgrade").?);
            try std.testing.expect(containsHttpToken(request.request.header("connection").?, "http2-settings"));
            try std.testing.expect(request.request.header("http2-settings") != null);
            try std.testing.expectEqualStrings("upgrade-body", request.request.body);
            try std.testing.expectEqual(@as(usize, 1), request.request.trailers.len);
            try std.testing.expectEqualStrings(
                "x-upload-complete",
                request.request.trailers[0].name,
            );
            try std.testing.expectEqualStrings(
                "yes",
                request.request.trailers[0].value,
            );

            try writeAll(shared.io, stream, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n");

            var preface: [http2.connection_preface.len]u8 = undefined;
            try readExact(shared.io, stream, &preface);
            try http2.validateClientPreface(&preface);
            var client_settings = try readFrame(shared.allocator, shared.io, stream, .{ .max_frame_payload = 4096 });
            defer client_settings.deinit(shared.allocator);
            try std.testing.expectEqual(http2.FrameType.settings, client_settings.frame.header.frame_type);

            var server_settings_payload: std.ArrayList(u8) = .empty;
            defer server_settings_payload.deinit(shared.allocator);
            try http2.writeSettings(&server_settings_payload, shared.allocator, &.{.{ .id = .max_frame_size, .value = 16_384 }});
            try writeFrame(shared.allocator, shared.io, stream, .settings, 0, 0, server_settings_payload.items);
            try writeFrame(shared.allocator, shared.io, stream, .settings, flag_ack, 0, &.{});
            var client_ack = try readFrame(shared.allocator, shared.io, stream, .{ .max_frame_payload = 4096 });
            defer client_ack.deinit(shared.allocator);
            try std.testing.expectEqual(http2.FrameType.settings, client_ack.frame.header.frame_type);
            try std.testing.expect((client_ack.frame.header.flags & flag_ack) != 0);

            var response_block: std.ArrayList(u8) = .empty;
            defer response_block.deinit(shared.allocator);
            try http2.Hpack.encodeLiteralBlock(&response_block, shared.allocator, &.{.{ .name = ":status", .value = "200" }});
            try writeFrame(shared.allocator, shared.io, stream, .headers, flag_end_headers, 1, response_block.items);
            try writeFrame(shared.allocator, shared.io, stream, .data, flag_end_stream, 1, "upgraded");
        }
    };

    var shared = Shared{ .allocator = allocator, .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(allocator, "http://localhost:{d}/upgrade?x=1", .{listener.socket.address.ip4.port});
    defer allocator.free(uri);
    var response = try Client.requestUriUpgrade(allocator, io, uri, .{
        .method = "POST",
        .body = "upgrade-body",
        .trailers = &.{.{
            .name = "x-upload-complete",
            .value = "yes",
        }},
    }, .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("upgraded", response.body);
}

test "HTTP/2 server accepts body-bearing h2c upgrade request" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var upgrade = try server_ptr.acceptUpgrade();
            defer upgrade.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(u31, 1), upgrade.stream_id);
            try std.testing.expect(upgrade.request.request.method == .POST);
            try std.testing.expectEqualStrings("/server-upgrade", upgrade.request.request.target);
            try std.testing.expectEqualStrings("request-body", upgrade.request.request.body);
            try std.testing.expectEqual(@as(usize, 1), upgrade.request.request.trailers.len);
            try std.testing.expectEqualStrings(
                "done",
                upgrade.request.request.trailers[0].value,
            );
            try upgrade.connection.writeResponse(upgrade.stream_id, .{ .body = "server-upgraded" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(allocator, "http://localhost:{d}/server-upgrade", .{server.address().ip4.port});
    defer allocator.free(uri);
    var response = try Client.requestUriUpgrade(allocator, io, uri, .{
        .method = "POST",
        .body = "request-body",
        .trailers = &.{.{ .name = "x-upload-complete", .value = "done" }},
    }, .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("server-upgraded", response.body);
}

test "HTTP/2 concurrent handler batch answers PING while a handler waits" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        io: std.Io,
        slow_started: std.Io.Event = .unset,
        release_slow: std.Io.Event = .unset,

        fn handle(
            self: *@This(),
            request: OwnedRequest,
        ) Error!ResponseOptions {
            if (std.mem.eql(u8, request.path, "/slow-ping")) {
                self.slow_started.set(self.io);
                try self.release_slow.wait(self.io);
            } else {
                try self.slow_started.wait(self.io);
            }
            return .{ .body = request.path };
        }
    };
    const Shared = struct {
        server: *Server,
        context: Context,
        successes: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var result = try connection.serveRequestBatchConcurrent(
                Context,
                &self.context,
                Context.handle,
                2,
            );
            defer result.deinit();
            self.successes = result.successCount();
            if (result.firstError()) |err| return err;
            _ = try connection.serveOne(
                Context,
                &self.context,
                Context.handle,
            );
        }
    };
    var shared = Shared{
        .server = &server,
        .context = .{ .io = io },
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.context.release_slow.set(io);
        thread.join();
    };

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    const slow = try client.sendCompleteRequest(.{
        .path = "/slow-ping",
        .authority = "localhost",
    });
    const fast = try client.sendCompleteRequest(.{
        .path = "/fast-ping",
        .authority = "localhost",
    });
    try shared.context.slow_started.wait(io);

    // Put an application HEADERS frame ahead of the PING. The batch owner
    // must retain it for the next serveOne call while still reaching and
    // acknowledging the connection-level frame behind it.
    const after = try client.sendCompleteRequest(.{
        .path = "/after-ping",
        .authority = "localhost",
    });
    const ping_payload = [_]u8{ 3, 1, 4, 1, 5, 9, 2, 6 };
    const ping_ack = try client.pingWithTimeout(
        ping_payload,
        .fromMilliseconds(500),
    );
    try std.testing.expectEqualSlices(u8, &ping_payload, &ping_ack);

    var fast_response = try client.readResponse(
        fast.stream_id,
        fast.request_method,
        fast.extended_connect,
        null,
    );
    defer fast_response.deinit(allocator);
    try std.testing.expectEqualStrings("/fast-ping", fast_response.body);

    shared.context.release_slow.set(io);
    var slow_response = try client.readResponse(
        slow.stream_id,
        slow.request_method,
        slow.extended_connect,
        null,
    );
    defer slow_response.deinit(allocator);
    try std.testing.expectEqualStrings("/slow-ping", slow_response.body);
    var after_response = try client.readResponse(
        after.stream_id,
        after.request_method,
        after.extended_connect,
        null,
    );
    defer after_response.deinit(allocator);
    try std.testing.expectEqualStrings("/after-ping", after_response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.successes);
}

test "HTTP/2 concurrent handler batch does not delay completion behind partial frame" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        io: std.Io,
        handlers_started: std.atomic.Value(usize) = .init(0),
        release_fast: std.Io.Event = .unset,
        release_slow: std.Io.Event = .unset,

        fn handle(
            self: *@This(),
            request: OwnedRequest,
        ) Error!ResponseOptions {
            _ = self.handlers_started.fetchAdd(1, .release);
            if (std.mem.eql(u8, request.path, "/partial-slow")) {
                try self.release_slow.wait(self.io);
            } else {
                try self.release_fast.wait(self.io);
            }
            return .{ .body = request.path };
        }
    };
    const Shared = struct {
        server: *Server,
        context: Context,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var result = try connection.serveRequestBatchConcurrent(
                Context,
                &self.context,
                Context.handle,
                2,
            );
            defer result.deinit();
            try std.testing.expectEqual(@as(usize, 2), result.successCount());
        }
    };
    var shared = Shared{
        .server = &server,
        .context = .{ .io = io },
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.context.release_fast.set(io);
        shared.context.release_slow.set(io);
        thread.join();
    };

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    const slow = try client.sendCompleteRequest(.{
        .path = "/partial-slow",
        .authority = "localhost",
    });
    const fast = try client.sendCompleteRequest(.{
        .path = "/partial-fast",
        .authority = "localhost",
    });
    while (shared.context.handlers_started.load(.acquire) != 2) {
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }

    var ping_header: [http2.FrameHeader.encoded_len]u8 = undefined;
    try encodeFrameHeader(&ping_header, .ping, 0, 0, 8);
    try writeAll(io, client.stream, ping_header[0..1]);
    try std.Io.sleep(io, .fromMilliseconds(20), .awake);
    shared.context.release_fast.set(io);

    var fast_response = try client.readResponseWithTimeout(
        fast.stream_id,
        fast.request_method,
        fast.extended_connect,
        .fromMilliseconds(500),
    );
    defer fast_response.deinit(allocator);
    try std.testing.expectEqualStrings("/partial-fast", fast_response.body);

    const first_ping = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    try writeAll(io, client.stream, ping_header[1..]);
    try writeAll(io, client.stream, &first_ping);
    const second_ping = [_]u8{ 8, 7, 6, 5, 4, 3, 2, 1 };
    const ping_ack = try client.pingWithTimeout(
        second_ping,
        .fromMilliseconds(500),
    );
    try std.testing.expectEqualSlices(u8, &second_ping, &ping_ack);

    shared.context.release_slow.set(io);
    var slow_response = try client.readResponse(
        slow.stream_id,
        slow.request_method,
        slow.extended_connect,
        null,
    );
    defer slow_response.deinit(allocator);
    try std.testing.expectEqualStrings("/partial-slow", slow_response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 readPing ignores ACK frames" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        observed: [8]u8 = undefined,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server, &shared.observed) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server, observed: *[8]u8) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            observed.* = try connection.readPing();
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    try writeFrame(allocator, io, client.stream, .ping, flag_ack, 0, &.{ 1, 1, 1, 1, 1, 1, 1, 1 });
    try writeFrame(allocator, io, client.stream, .ping, 0, 0, &.{ 2, 3, 5, 7, 11, 13, 17, 19 });

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 2, 3, 5, 7, 11, 13, 17, 19 }, &shared.observed);
}

test "HTTP/2 ping helpers handle interleaved control frames" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            try connection.sendWindowUpdate(0, 321);
            try writeFrame(server_ptr.allocator, server_ptr.io, connection.stream, .ping, flag_ack, 0, &.{ 9, 9, 9, 9, 9, 9, 9, 9 });
            const observed = try connection.readPing();
            try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, &observed);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    const ack = try client.ping(.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, &ack);
    try std.testing.expectEqual(@as(i64, default_flow_window + 321), client.send_connection_window.value);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 wait helpers reject unbuffered application frames" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }
    const data_frame = http2.Frame{
        .header = .{ .length = 1, .frame_type = .data, .flags = 0, .stream_id = 1 },
        .payload = "x",
    };
    try std.testing.expect(!try connection.handleConnectionOrGoAwayFrame(data_frame));
}

test "HTTP/2 readWindowUpdate handles interleaved PING" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            const ping_payload = [_]u8{ 4, 8, 15, 16, 23, 42, 0, 1 };
            try writeFrame(server_ptr.allocator, server_ptr.io, connection.stream, .ping, 0, 0, &ping_payload);
            try connection.sendWindowUpdate(0, 777);

            while (true) {
                var frame = try readFrame(server_ptr.allocator, server_ptr.io, connection.stream, server_ptr.limits);
                defer frame.deinit(server_ptr.allocator);
                if (frame.frame.header.frame_type != .ping) continue;
                try std.testing.expect((frame.frame.header.flags & flag_ack) != 0);
                try std.testing.expectEqualSlices(u8, &ping_payload, frame.frame.payload);
                break;
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var update = try client.readWindowUpdate();
    defer update.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 0), update.window_update.stream_id);
    try std.testing.expectEqual(@as(u31, 777), update.window_update.increment);
    try std.testing.expectEqual(@as(i64, default_flow_window + 777), client.send_connection_window.value);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 graceful shutdown sends maximum GOAWAY ping and final boundary" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            connection.last_peer_client_stream_id = 3;
            connection.last_peer_processed_stream_id = 3;
            try connection.gracefulShutdown();
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var first = try client.readGoAway();
    defer first.deinit(allocator);
    try std.testing.expectEqual(std.math.maxInt(u31), first.goaway.last_stream_id);
    try std.testing.expectEqual(http2.ErrorCode.no_error, first.goaway.error_code);

    const shutdown_payload = [_]u8{ 0x0b, 0x7b, 0xa2, 0xf0, 0x8b, 0x9b, 0xfe, 0x54 };
    const observed = try client.readPing();
    try std.testing.expectEqualSlices(u8, &shutdown_payload, &observed);

    var final = try client.readGoAway();
    defer final.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 3), final.goaway.last_stream_id);
    try std.testing.expectEqual(http2.ErrorCode.no_error, final.goaway.error_code);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 graceful shutdown admits request HEADERS before final GOAWAY" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        path: ?[]u8 = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            try connection.gracefulShutdown();
            var request = try connection.readRequest();
            defer request.deinit(self.server.allocator);
            self.path = try self.server.allocator.dupe(u8, request.path);
        }
    };

    var shared = Shared{ .server = &server };
    defer if (shared.path) |path| allocator.free(path);
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{});
    defer client.close();

    var first = try client.readGoAway();
    defer first.deinit(allocator);
    try std.testing.expectEqual(std.math.maxInt(u31), first.goaway.last_stream_id);
    var ping_frame = try client.readOwnedFrame();
    defer ping_frame.deinit(allocator);
    try std.testing.expectEqual(http2.FrameType.ping, ping_frame.frame.header.frame_type);
    const ping_data = (try http2.PingPayload.parse(ping_frame.frame)).data;
    try std.testing.expectEqualSlices(
        u8,
        &graceful_shutdown_ping_payload,
        &ping_data,
    );

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/during-shutdown" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "localhost" },
    });
    try writeFrame(
        allocator,
        io,
        client.stream,
        .headers,
        flag_end_headers | flag_end_stream,
        1,
        block.items,
    );
    try writeFrame(
        allocator,
        io,
        client.stream,
        .ping,
        flag_ack,
        0,
        &graceful_shutdown_ping_payload,
    );

    var final = try client.readGoAway();
    defer final.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), final.goaway.last_stream_id);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings("/during-shutdown", shared.path.?);
}

test "HTTP/2 graceful shutdown refuses overload and retires queued marker" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_concurrent_streams = 1 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        marker_count: usize = 99,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            try connection.gracefulShutdown();
            try std.testing.expectEqual(
                @as(?u31, 1),
                connection.local_goaway_last_stream_id,
            );
            while (connection.graceful_preadmitted_peer_streams.items.len != 0) {
                const frame = (try connection.readBufferedFrame()).frame;
                if (frame.header.frame_type == .headers and
                    connection.gracefulPreadmittedIndex(
                        frame.header.stream_id,
                    ) != null)
                {
                    const headers = try connection.readHeaderBlock(frame);
                    freeHeaders(self.server.allocator, headers);
                    if (connection.gracefulPreadmittedIndex(
                        frame.header.stream_id,
                    )) |index| {
                        _ = connection.graceful_preadmitted_peer_streams
                            .orderedRemove(index);
                    }
                    continue;
                }
                if (try connection.handleConnectionFrame(frame)) continue;
                return error.UnexpectedFrame;
            }
            self.marker_count =
                connection.graceful_preadmitted_peer_streams.items.len;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_concurrent_streams = 1 },
    );
    defer client.close();
    _ = try client.sendCompleteRequest(.{
        .path = "/held",
        .authority = "localhost",
    });

    var initial = try client.readGoAway();
    defer initial.deinit(allocator);
    var ping = try client.readOwnedFrame();
    defer ping.deinit(allocator);
    try std.testing.expectEqual(http2.FrameType.ping, ping.frame.header.frame_type);
    try client.writeHeaders(3, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/refused-during-shutdown" },
        .{ .name = ":scheme", .value = "http" },
    }, true);
    try writeFrame(
        allocator,
        io,
        client.stream,
        .ping,
        flag_ack,
        0,
        ping.frame.payload,
    );
    var reset = try client.readResetStreamWithTimeout(.fromSeconds(2));
    defer reset.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 3), reset.reset.stream_id);
    try std.testing.expectEqual(
        http2.ErrorCode.refused_stream,
        reset.reset.error_code,
    );
    var final = try client.readGoAway();
    defer final.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), final.goaway.last_stream_id);
    try writeFrame(
        allocator,
        io,
        client.stream,
        .ping,
        0,
        0,
        &.{ 7, 6, 5, 4, 3, 2, 1, 0 },
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 0), shared.marker_count);
}

test "HTTP/2 graceful shutdown preadmits dependent HPACK blocks in order" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            try connection.gracefulShutdown();
            var first = try connection.readRequest();
            defer first.deinit(self.server.allocator);
            var second = try connection.readRequest();
            defer second.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/one", first.path);
            try std.testing.expectEqualStrings("/two", second.path);
            try std.testing.expectEqualStrings(
                "shared",
                findHeader(second.headers, "x-dynamic").?,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    var initial = try client.readGoAway();
    defer initial.deinit(allocator);
    var ping_frame = try client.readOwnedFrame();
    defer ping_frame.deinit(allocator);

    var encoder = http2.Hpack.Encoder{};
    defer encoder.deinit(allocator);
    const block_one = try allocator.dupe(u8, try encoder.encodeBlockRetained(
        allocator,
        &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":path", .value = "/one" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = "x-dynamic", .value = "shared" },
        },
    ));
    defer allocator.free(block_one);
    const block_two = try allocator.dupe(u8, try encoder.encodeBlockRetained(
        allocator,
        &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":path", .value = "/two" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = "x-dynamic", .value = "shared" },
        },
    ));
    defer allocator.free(block_two);
    try writeFrame(allocator, io, client.stream, .headers, flag_end_headers | flag_end_stream, 1, block_one);
    try writeFrame(allocator, io, client.stream, .headers, flag_end_headers | flag_end_stream, 3, block_two);
    try writeFrame(allocator, io, client.stream, .ping, flag_ack, 0, &graceful_shutdown_ping_payload);

    var final = try client.readGoAway();
    defer final.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 3), final.goaway.last_stream_id);
    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 graceful shutdown ignores stale PING ACK" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            try connection.gracefulShutdown();
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    var first = try client.readGoAway();
    defer first.deinit(allocator);
    var ping_frame = try client.readOwnedFrame();
    defer ping_frame.deinit(allocator);
    try std.testing.expectEqual(http2.FrameType.ping, ping_frame.frame.header.frame_type);

    const stale = [_]u8{ 1, 3, 3, 7, 0, 0, 0, 1 };
    try writeFrame(allocator, io, client.stream, .ping, flag_ack, 0, &stale);
    try writeFrame(
        allocator,
        io,
        client.stream,
        .ping,
        flag_ack,
        0,
        &graceful_shutdown_ping_payload,
    );
    var final = try client.readGoAway();
    defer final.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 0), final.goaway.last_stream_id);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 graceful shutdown rejects client role before writing" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try std.testing.expectError(error.UnexpectedFrame, connection.gracefulShutdown());
    try std.testing.expectEqual(@as(?u31, null), connection.local_goaway_last_stream_id);
}

test "HTTP/2 graceful shutdown reserves its synchronization PING" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try std.testing.expectError(
        error.InvalidFrame,
        connection.ping(graceful_shutdown_ping_payload),
    );
}

test "HTTP/2 completed graceful shutdown ignores expired wait budgets" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
        .graceful_shutdown_phase = .complete,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try connection.gracefulShutdownWithTimeout(.zero);
    try connection.gracefulShutdownWithDeadline(.{
        .raw = .zero,
        .clock = .real,
    });
}

test "HTTP/2 graceful shutdown write failure is terminal" {
    const FailingWriter = struct {
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            if (self.writes == 1) return @min(header.len, 4);
            return error.NetworkDown;
        }
    };

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var writer: FailingWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = FailingWriter.write;
    const io = std.Io{ .userdata = &writer, .vtable = &vtable };
    var connection = Connection{
        .io = io,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try std.testing.expectError(error.NetworkDown, connection.gracefulShutdown());
    const writes = writer.writes;
    try std.testing.expectError(error.ConnectionClosed, connection.gracefulShutdown());
    try std.testing.expectEqual(writes, writer.writes);
}

test "HTTP/2 graceful shutdown deadline bounds a blocked GOAWAY write" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    if (comptime @import("builtin").os.tag == .windows) return;
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const sender = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    const peer = try listener.accept(io);
    defer peer.close(io);

    const send_buffer: c_int = 4096;
    try std.posix.setsockopt(
        sender.socket.handle,
        std.posix.SOL.SOCKET,
        std.posix.SO.SNDBUF,
        std.mem.asBytes(&send_buffer),
    );
    const filler = [_]u8{0xa5} ** 4096;
    while (true) {
        const rc = std.posix.system.sendto(
            sender.socket.handle,
            filler[0..].ptr,
            filler.len,
            std.posix.MSG.DONTWAIT | std.posix.MSG.NOSIGNAL,
            null,
            0,
        );
        switch (std.posix.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            .AGAIN => break,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }

    var connection = Connection{
        .io = io,
        .allocator = allocator,
        .stream = sender,
        .role = .server,
    };
    defer connection.close();
    try std.testing.expectError(
        error.Timeout,
        connection.gracefulShutdownWithTimeout(.fromMilliseconds(20)),
    );
    try std.testing.expectEqual(.failed, connection.graceful_shutdown_phase);
    try std.testing.expectEqual(
        @as(?u31, null),
        connection.local_goaway_last_stream_id,
    );
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expect(!connection.isReusable());
}

test "HTTP/2 graceful shutdown fails closed when PING ACK write times out" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    if (comptime @import("builtin").os.tag == .windows) return;
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const sender = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    const peer = try listener.accept(io);
    defer peer.close(io);

    const send_buffer: c_int = 4096;
    try std.posix.setsockopt(
        sender.socket.handle,
        std.posix.SOL.SOCKET,
        std.posix.SO.SNDBUF,
        std.mem.asBytes(&send_buffer),
    );
    const filler = [_]u8{0xa5} ** 4096;
    while (true) {
        const rc = std.posix.system.sendto(
            sender.socket.handle,
            filler[0..].ptr,
            filler.len,
            std.posix.MSG.DONTWAIT | std.posix.MSG.NOSIGNAL,
            null,
            0,
        );
        switch (std.posix.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            .AGAIN => break,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }

    var connection = Connection{
        .io = io,
        .allocator = allocator,
        .stream = sender,
        .role = .server,
        .local_goaway_last_stream_id = std.math.maxInt(u31),
        .graceful_shutdown_phase = .synchronizing,
    };
    defer connection.close();
    var ping_storage: [http2.PingPayload.encoded_len]u8 = undefined;
    const peer_ping = http2.PingPayload.writeInto(
        &ping_storage,
        .{ 9, 8, 7, 6, 5, 4, 3, 2 },
        false,
    );
    try connection.frame_reader.buffer.appendSlice(allocator, peer_ping);

    try std.testing.expectError(
        error.Timeout,
        connection.gracefulShutdownWithTimeout(.fromMilliseconds(20)),
    );
    try std.testing.expectEqual(.failed, connection.graceful_shutdown_phase);
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expect(!connection.isReusable());
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.gracefulShutdownWithTimeout(.fromSeconds(1)),
    );
}

test "HTTP/2 graceful shutdown bounds final GOAWAY write" {
    const RecordingWriter = struct {
        bytes: std.ArrayList(u8) = .empty,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            data: []const []const u8,
            splat: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            var total = header.len;
            for (data[0 .. data.len - 1]) |part| total += part.len;
            total += data[data.len - 1].len * splat;
            self.bytes.appendSlice(std.testing.allocator, header) catch {
                return error.SystemResources;
            };
            for (data[0 .. data.len - 1]) |part| {
                self.bytes.appendSlice(std.testing.allocator, part) catch {
                    return error.SystemResources;
                };
            }
            var repeated: usize = 0;
            while (repeated < splat) : (repeated += 1) {
                self.bytes.appendSlice(
                    std.testing.allocator,
                    data[data.len - 1],
                ) catch return error.SystemResources;
            }
            return total;
        }
    };

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var writer: RecordingWriter = .{};
    defer writer.bytes.deinit(std.testing.allocator);
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = RecordingWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
        .local_goaway_last_stream_id = std.math.maxInt(u31),
        .graceful_shutdown_phase = .synchronized,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try std.testing.expectError(
        error.Timeout,
        connection.gracefulShutdownWithDeadline(.{
            .raw = .zero,
            .clock = .real,
        }),
    );
    try std.testing.expect(!connection.gracefulShutdownComplete());
    try std.testing.expectEqual(
        .synchronized,
        connection.graceful_shutdown_phase,
    );
    try std.testing.expectEqual(@as(usize, 0), writer.bytes.items.len);
}

test "HTTP/2 graceful shutdown timeout resumes one outstanding ping" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        io: std.Io,
        first_ping_seen: std.Io.Event = .unset,
        allow_ack: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
                shared.first_ping_seen.set(shared.io);
            };
        }

        fn runFallible(shared: *@This()) !void {
            // The client side drives graceful shutdown in this white-box test;
            // it needs a server-role connection without a second frame reader.
            var connection = try shared.server.accept();
            defer connection.close();
            // The peer SETTINGS ACK is the final handshake frame queued by
            // Client.connect; consume it before observing shutdown frames.
            while (true) {
                var frame = try readFrame(
                    shared.server.allocator,
                    shared.io,
                    connection.stream,
                    shared.server.limits,
                );
                defer frame.deinit(shared.server.allocator);
                if (frame.frame.header.frame_type == .settings and
                    (frame.frame.header.flags & flag_ack) != 0)
                {
                    break;
                }
            }
            var first = try readFrame(
                shared.server.allocator,
                shared.io,
                connection.stream,
                shared.server.limits,
            );
            defer first.deinit(shared.server.allocator);
            try std.testing.expectEqual(http2.FrameType.goaway, first.frame.header.frame_type);
            var ping = try readFrame(
                shared.server.allocator,
                shared.io,
                connection.stream,
                shared.server.limits,
            );
            defer ping.deinit(shared.server.allocator);
            try std.testing.expectEqual(http2.FrameType.ping, ping.frame.header.frame_type);
            try std.testing.expectEqual(@as(u8, 0), ping.frame.header.flags & flag_ack);
            shared.first_ping_seen.set(shared.io);
            try shared.allow_ack.wait(shared.io);
            try writeFrame(
                shared.server.allocator,
                shared.io,
                connection.stream,
                .ping,
                flag_ack,
                0,
                ping.frame.payload,
            );
            var final = try readFrame(
                shared.server.allocator,
                shared.io,
                connection.stream,
                shared.server.limits,
            );
            defer final.deinit(shared.server.allocator);
            try std.testing.expectEqual(http2.FrameType.goaway, final.frame.header.frame_type);
            try std.testing.expectEqual(@as(u31, 0), (try http2.GoAwayPayload.parse(final.frame)).last_stream_id);
        }
    };

    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.allow_ack.set(io);
        thread.join();
    };

    var client = try Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    client.role = .server;
    try std.testing.expectError(
        error.Timeout,
        client.gracefulShutdownWithTimeout(.fromMilliseconds(20)),
    );
    try shared.first_ping_seen.wait(io);
    shared.allow_ack.set(io);
    try client.gracefulShutdownWithTimeout(.fromSeconds(1));

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 graceful shutdown narrows an existing local GOAWAY" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            try connection.sendGoAway(7, .no_error, "draining");
            try connection.gracefulShutdown();
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{});
    defer client.close();

    var first = try client.readGoAway();
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 7), first.goaway.last_stream_id);
    const ping_data = try client.readPing();
    try std.testing.expectEqualSlices(
        u8,
        &graceful_shutdown_ping_payload,
        &ping_data,
    );
    var final = try client.readGoAway();
    defer final.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 0), final.goaway.last_stream_id);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 graceful shutdown ignores streams above final boundary" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            try connection.gracefulShutdown();
            // Stream 1 is above the final zero boundary. Its HEADERS must be
            // decoded and ignored so the following connection PING remains
            // usable rather than surfacing ConnectionGoAway.
            const observed = try connection.readPing();
            try std.testing.expectEqualSlices(
                u8,
                &[_]u8{ 9, 8, 7, 6, 5, 4, 3, 2 },
                &observed,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    var first = try client.readGoAway();
    defer first.deinit(allocator);
    _ = try client.readPing();
    var final = try client.readGoAway();
    defer final.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 0), final.goaway.last_stream_id);

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/too-late" },
        .{ .name = ":scheme", .value = "http" },
    });
    try writeFrame(
        allocator,
        io,
        client.stream,
        .headers,
        flag_end_headers | flag_end_stream,
        1,
        block.items,
    );
    const payload = [_]u8{ 9, 8, 7, 6, 5, 4, 3, 2 };
    try writeFrame(allocator, io, client.stream, .ping, 0, 0, &payload);
    while (true) {
        var frame = try client.readOwnedFrame();
        defer frame.deinit(allocator);
        if (frame.frame.header.frame_type != .ping) continue;
        try std.testing.expect((frame.frame.header.flags & flag_ack) != 0);
        break;
    }

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 owned control readers release unexpected frames exactly once" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            for ([_]u31{ 1, 3, 5 }) |stream_id| {
                try writeFrame(
                    self.server.allocator,
                    self.server.io,
                    connection.stream,
                    .headers,
                    flag_end_headers | flag_end_stream,
                    stream_id,
                    &.{},
                );
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try Client.connect(allocator, io, server.address(), .{});
    defer client.close();

    try std.testing.expectError(error.UnexpectedFrame, client.readResetStream());
    try std.testing.expectError(error.UnexpectedFrame, client.readGoAway());
    try std.testing.expectError(error.UnexpectedFrame, client.readWindowUpdate());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 readWindowUpdate records interleaved GOAWAY" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            try connection.sendGoAway(3, .no_error, "draining");
            try connection.sendWindowUpdate(0, 99);
            _ = try connection.readPing();
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer client.close();

    var update = try client.readWindowUpdate();
    defer update.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 99), update.window_update.increment);
    try std.testing.expectEqual(@as(?u31, 3), client.peer_goaway_last_stream_id);
    _ = try client.ping(.{ 0, 1, 0, 1, 0, 1, 0, 1 });

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 readWindowUpdate enforces local error reset budget" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const limits: Limits = .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
        .max_local_error_reset_streams = 1,
    };
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            const overflow = [_]u8{ 0, 0, 0, 1 };

            try writeFrame(
                self.server.allocator,
                self.server.io,
                connection.stream,
                .window_update,
                0,
                1,
                &overflow,
            );
            var reset = try connection.readResetStreamWithTimeout(
                .fromSeconds(2),
            );
            defer reset.deinit(self.server.allocator);
            try std.testing.expectEqual(@as(u31, 1), reset.reset.stream_id);
            try std.testing.expectEqual(
                http2.ErrorCode.flow_control_error,
                reset.reset.error_code,
            );

            try writeFrame(
                self.server.allocator,
                self.server.io,
                connection.stream,
                .window_update,
                0,
                3,
                &overflow,
            );
            var goaway = try connection.readGoAwayWithTimeout(
                .fromSeconds(2),
            );
            defer goaway.deinit(self.server.allocator);
            try std.testing.expectEqual(@as(u31, 0), goaway.goaway.last_stream_id);
            try std.testing.expectEqual(
                http2.ErrorCode.enhance_your_calm,
                goaway.goaway.error_code,
            );
            try std.testing.expectEqualStrings(
                "too_many_internal_resets",
                goaway.goaway.debug_data,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), limits);
    defer client.close();
    try client.addActiveLocalStream(1);
    try client.addActiveLocalStream(3);
    (try client.sendStreamWindow(1)).value = max_flow_window;
    (try client.sendStreamWindow(3)).value = max_flow_window;

    var first = try client.readWindowUpdateWithTimeout(.fromSeconds(2));
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), first.window_update.stream_id);
    try std.testing.expectEqual(@as(usize, 1), client.local_error_reset_streams);

    try std.testing.expectError(
        error.ConnectionGoAway,
        client.readWindowUpdateWithTimeout(.fromSeconds(2)),
    );
    try std.testing.expect(client.aggregate_timeout_unusable);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 readGoAway handles interleaved PING" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            const ping_payload = [_]u8{ 9, 9, 8, 8, 7, 7, 6, 6 };
            try writeFrame(server_ptr.allocator, server_ptr.io, connection.stream, .ping, 0, 0, &ping_payload);
            try connection.sendGoAway(0, .no_error, "bye");

            while (true) {
                var frame = try readFrame(server_ptr.allocator, server_ptr.io, connection.stream, server_ptr.limits);
                defer frame.deinit(server_ptr.allocator);
                if (frame.frame.header.frame_type != .ping) continue;
                try std.testing.expect((frame.frame.header.flags & flag_ack) != 0);
                try std.testing.expectEqualSlices(u8, &ping_payload, frame.frame.payload);
                break;
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer client.close();

    var goaway = try client.readGoAway();
    defer goaway.deinit(allocator);
    try std.testing.expectEqual(http2.ErrorCode.no_error, goaway.goaway.error_code);
    try std.testing.expectEqualStrings("bye", goaway.goaway.debug_data);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 readResetStream handles interleaved PING" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            const ping_payload = [_]u8{ 1, 4, 1, 4, 2, 1, 3, 5 };
            try writeFrame(server_ptr.allocator, server_ptr.io, connection.stream, .ping, 0, 0, &ping_payload);
            try connection.sendResetStream(request.stream_id, .cancel);

            while (true) {
                var frame = try readFrame(server_ptr.allocator, server_ptr.io, connection.stream, server_ptr.limits);
                defer frame.deinit(server_ptr.allocator);
                if (frame.frame.header.frame_type != .ping) continue;
                try std.testing.expect((frame.frame.header.flags & flag_ack) != 0);
                try std.testing.expectEqualSlices(u8, &ping_payload, frame.frame.payload);
                break;
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer client.close();

    const fields = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/reset-interleaved-ping" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    };
    try client.writeHeaders(1, &fields, true);

    var reset = try client.readResetStream();
    defer reset.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), reset.reset.stream_id);
    try std.testing.expectEqual(http2.ErrorCode.cancel, reset.reset.error_code);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 runtime sends and receives RST_STREAM" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/reset-me", request.path);
            try connection.sendResetStream(request.stream_id, .cancel);

            var reset = try connection.readResetStream();
            defer reset.deinit(server_ptr.allocator);
            try std.testing.expectEqual(request.stream_id, reset.reset.stream_id);
            try std.testing.expectEqual(http2.ErrorCode.no_error, reset.reset.error_code);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    const fields = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/reset-me" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    };
    try client.writeHeaders(1, &fields, true);
    try client.sendResetStream(1, .no_error);

    var inbound_reset = try client.readResetStream();
    defer inbound_reset.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), inbound_reset.reset.stream_id);
    try std.testing.expectEqual(http2.ErrorCode.cancel, inbound_reset.reset.error_code);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 sendResetStream rejects idle streams" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    // Rust h2 deliberately avoids making RST_STREAM the first frame on an idle
    // stream: RFC 9113 only permits HEADERS/PRIORITY there, and a reset before
    // the stream is opened is a connection-level protocol error.  The guard is
    // checked before touching the transport, so this also protects callers from
    // accidentally resetting a stream that has already been fully released.
    try std.testing.expectError(error.InvalidStreamId, connection.sendResetStream(1, .cancel));

    try connection.addActiveLocalStream(1);
    connection.releaseLocalStream(1);
    try std.testing.expectError(error.InvalidStreamId, connection.sendResetStream(1, .cancel));
}

test "HTTP/2 writeData rejects idle streams" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    // DATA frames are only valid after a stream has been opened by HEADERS.
    // Rust h2 tracks pending-open streams so DATA never becomes the first frame
    // on an idle stream; keep the same invariant for the low-level helper.
    try std.testing.expectError(error.InvalidStreamId, connection.writeData(1, "body", true));
    try std.testing.expectEqual(@as(usize, 0), connection.active_local_streams.items.len);
}

test "HTTP/2 writeHeaders rejects wrong-direction idle streams" {
    const fields = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
    };

    var client = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        client.send_stream_windows.deinit(std.testing.allocator);
        client.send_stream_window_index.deinit(std.testing.allocator);
        client.recv_stream_windows.deinit(std.testing.allocator);
        client.recv_stream_window_index.deinit(std.testing.allocator);
        client.active_local_streams.deinit(std.testing.allocator);
        client.active_local_index.deinit(std.testing.allocator);
        client.active_peer_streams.deinit(std.testing.allocator);
        client.active_peer_index.deinit(std.testing.allocator);
        client.hpack_decoder.deinit(std.testing.allocator);
        client.hpack_encoder.deinit(std.testing.allocator);
    }
    try std.testing.expectError(error.InvalidStreamId, client.writeHeaders(2, &fields, true));
    try std.testing.expectEqual(@as(usize, 0), client.active_local_streams.items.len);

    var server = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        server.send_stream_windows.deinit(std.testing.allocator);
        server.send_stream_window_index.deinit(std.testing.allocator);
        server.recv_stream_windows.deinit(std.testing.allocator);
        server.recv_stream_window_index.deinit(std.testing.allocator);
        server.active_local_streams.deinit(std.testing.allocator);
        server.active_local_index.deinit(std.testing.allocator);
        server.active_peer_streams.deinit(std.testing.allocator);
        server.active_peer_index.deinit(std.testing.allocator);
        server.hpack_decoder.deinit(std.testing.allocator);
        server.hpack_encoder.deinit(std.testing.allocator);
    }
    try std.testing.expectError(error.InvalidStreamId, server.writeHeaders(2, &fields, true));
    try std.testing.expectEqual(@as(usize, 0), server.active_local_streams.items.len);
    try std.testing.expectEqual(@as(usize, 0), server.active_peer_streams.items.len);
}

test "HTTP/2 client request fails when response stream is reset" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/reset-response", request.path);
            try connection.sendResetStream(request.stream_id, .cancel);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    try std.testing.expectError(error.StreamReset, client.request(.{
        .method = "GET",
        .path = "/reset-response",
        .authority = "localhost",
    }));

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 client rejects unexpected cross-stream response frames" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/cross-stream", request.path);
            try writeFrame(server_ptr.allocator, server_ptr.io, connection.stream, .data, flag_end_stream, 3, "wrong-stream");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    try std.testing.expectError(error.UnexpectedFrame, client.request(.{
        .method = "GET",
        .path = "/cross-stream",
        .authority = "localhost",
    }));

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 server readRequest fails when request body stream is reset" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        saw_reset: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();

            var request = connection.readRequest() catch |err| {
                if (err == error.StreamReset) {
                    shared.saw_reset = true;
                    return;
                }
                shared.err = err;
                return;
            };
            request.deinit(shared.server.allocator);
            shared.err = error.UnexpectedFrame;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    const headers = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/reset-request" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "content-length", .value = "5" },
    };
    try client.writeHeaders(1, &headers, false);
    try client.writeData(1, "he", false);
    try client.sendResetStream(1, .cancel);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_reset);
}

test "HTTP/2 runtime reads and writes CONTINUATION header blocks" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 24, .max_body_bytes = 4096, .max_frame_size = 16 * 1024 },
    );
    defer server.deinit();

    const long_header_value = "abcdefghijklmnopqrstuvwxyz0123456789";
    const Shared = struct {
        server: *Server,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server, shared.expected) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server, expected: []const u8) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/continuation", request.path);
            try std.testing.expectEqualStrings(expected, findHeader(request.headers, "x-long").?);
            const scratch_capacity = connection.header_block_scratch.capacity;
            const scratch_ptr = connection.header_block_scratch
                .allocatedSlice().ptr;
            try std.testing.expect(scratch_capacity != 0);

            try connection.writeResponse(request.stream_id, .{
                .status = 200,
                .headers = &.{
                    .{ .name = "content-type", .value = "text/plain" },
                    .{ .name = "x-long-response", .value = expected },
                },
                .body = "ok",
            });

            var second = try connection.readRequest();
            defer second.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings(
                "/continuation-two",
                second.path,
            );
            try std.testing.expectEqualStrings(
                expected,
                findHeader(second.headers, "x-long").?,
            );
            try std.testing.expectEqual(
                scratch_capacity,
                connection.header_block_scratch.capacity,
            );
            try std.testing.expectEqual(
                scratch_ptr,
                connection.header_block_scratch.allocatedSlice().ptr,
            );
            try connection.writeResponse(second.stream_id, .{
                .status = 204,
            });
        }
    };

    var shared = Shared{ .server = &server, .expected = long_header_value };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 24,
        .max_body_bytes = 4096,
        .max_frame_size = 16 * 1024,
    });
    defer client.close();

    var response = try client.request(.{
        .method = "GET",
        .path = "/continuation",
        .authority = "localhost",
        .headers = &.{.{ .name = "x-long", .value = long_header_value }},
    });
    defer response.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("ok", response.body);
    try std.testing.expectEqualStrings(long_header_value, findHeader(response.headers, "x-long-response").?);

    var second = try client.request(.{
        .method = "GET",
        .path = "/continuation-two",
        .authority = "localhost",
        .headers = &.{.{ .name = "x-long", .value = long_header_value }},
    });
    defer second.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), second.status);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 single-frame HEADERS bypass continuation scratch" {
    const allocator = std.testing.allocator;
    var encoder = http2.Hpack.Encoder{};
    defer encoder.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try encoder.encodeBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/single" },
        .{ .name = ":scheme", .value = "http" },
    });
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.hpack_decoder.deinit(allocator);
        connection.header_block_scratch.deinit(allocator);
    }
    const headers = try connection.readHeaderBlock(.{
        .header = .{
            .length = @intCast(block.items.len),
            .frame_type = .headers,
            .flags = flag_end_headers | flag_end_stream,
            .stream_id = 1,
        },
        .payload = block.items,
    });
    defer freeHeaders(allocator, headers);
    try std.testing.expectEqualStrings("/single", findHeader(headers, ":path").?);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.header_block_scratch.capacity,
    );
}

test "HTTP/2 runtime bounds CONTINUATION frame chains" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .max_continuation_frames = 2,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            try std.testing.expectError(error.MessageTooLarge, connection.readRequest());
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/continuation-flood" },
        .{ .name = ":scheme", .value = "https" },
    });
    try writeFrame(allocator, io, client.stream, .headers, 0, 1, block.items);
    try writeFrame(allocator, io, client.stream, .continuation, 0, 1, &.{});
    try writeFrame(allocator, io, client.stream, .continuation, 0, 1, &.{});
    try writeFrame(allocator, io, client.stream, .continuation, flag_end_headers, 1, &.{});

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 runtime decodes padded priority HEADERS payloads" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/padded-priority", request.path);
            try std.testing.expectEqualStrings("hello", request.body);

            try connection.writeResponse(request.stream_id, .{ .body = "ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/padded-priority" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "content-length", .value = "5" },
    });

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try payload.append(allocator, 2); // Pad Length.
    try payload.appendSlice(allocator, &.{ 0, 0, 0, 0, 16 }); // PRIORITY: dependency 0, weight 16.
    try payload.appendSlice(allocator, block.items);
    try payload.appendSlice(allocator, &.{ 0, 0 });

    const flags = flag_end_headers | @as(u8, (@as(http2.Flags, .{ .padded = true, .priority = true })).byte());
    try writeFrame(allocator, io, client.stream, .headers, flags, 1, payload.items);
    try client.addActiveLocalStream(1);
    try client.writeData(1, "hello", true);

    var response = try client.readResponse(1, "POST", false, null);
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("ok", response.body);
}

test "HTTP/2 runtime ignores HEADERS priority self dependency" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        saw_expected: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();

            var request = connection.readRequest() catch |err| {
                shared.err = err;
                return;
            };
            defer request.deinit(shared.server.allocator);
            shared.saw_expected = std.mem.eql(
                u8,
                request.path,
                "/self-priority",
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/self-priority" },
        .{ .name = ":scheme", .value = "https" },
    });

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try payload.appendSlice(allocator, &.{ 0, 0, 0, 1, 16 }); // PRIORITY depends on stream 1 itself.
    try payload.appendSlice(allocator, block.items);
    const flags = flag_end_headers | flag_end_stream |
        @as(u8, (@as(http2.Flags, .{ .priority = true })).byte());
    try writeFrame(allocator, io, client.stream, .headers, flags, 1, payload.items);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
}

test "HTTP/2 runtime answers PING while reading request body" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/interleaved-ping", request.path);
            try std.testing.expectEqualStrings("hello", request.body);
            try connection.writeResponse(request.stream_id, .{ .body = "ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    const headers = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/interleaved-ping" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "content-length", .value = "5" },
    };
    try client.writeHeaders(1, &headers, false);
    try client.writeData(1, "he", false);
    const ping_payload = [_]u8{ 1, 3, 3, 7, 0, 0, 0, 1 };
    try writeFrame(allocator, io, client.stream, .ping, 0, 0, &ping_payload);

    var ping_ack = try readFrame(allocator, io, client.stream, client.limits);
    defer ping_ack.deinit(allocator);
    try std.testing.expectEqual(http2.FrameType.ping, ping_ack.frame.header.frame_type);
    try std.testing.expect((ping_ack.frame.header.flags & flag_ack) != 0);
    try std.testing.expectEqualSlices(u8, &ping_payload, ping_ack.frame.payload);

    try client.writeData(1, "llo", true);
    var response = try client.readResponse(1, "POST", false, null);
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("ok", response.body);
}

test "HTTP/2 runtime ignores PRIORITY while reading request body" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/priority-body", request.path);
            try std.testing.expectEqualStrings("hello", request.body);
            try connection.writeResponse(request.stream_id, .{ .body = "ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    const headers = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/priority-body" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "content-length", .value = "5" },
    };
    try client.writeHeaders(1, &headers, false);
    try client.writeData(1, "he", false);

    var priority_bytes: std.ArrayList(u8) = .empty;
    defer priority_bytes.deinit(allocator);
    try http2.PriorityPayload.write(&priority_bytes, allocator, 1, false, 0, 32);
    try writeAll(io, client.stream, priority_bytes.items);
    try client.writeData(1, "llo", true);

    var response = try client.readResponse(1, "POST", false, null);
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("ok", response.body);
}

test "HTTP/2 runtime handles pre-request stream frame ordering" {
    const allocator = std.testing.allocator;

    {
        var threaded = std.Io.Threaded.init(allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        var server = try Server.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        );
        defer server.deinit();

        const Shared = struct {
            server: *Server,
            saw_expected: bool = false,
            err: ?anyerror = null,

            fn run(shared: *@This()) void {
                var connection = shared.server.accept() catch |err| {
                    shared.err = err;
                    return;
                };
                defer connection.close();

                var request = connection.readRequest() catch |err| {
                    if (err == error.UnexpectedFrame) {
                        shared.saw_expected = true;
                        return;
                    }
                    shared.err = err;
                    return;
                };
                request.deinit(shared.server.allocator);
                shared.err = error.UnexpectedFrame;
            }
        };

        var shared = Shared{ .server = &server };
        const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

        var client = try Client.connect(allocator, io, server.address(), .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
        });
        defer client.close();
        try writeFrame(allocator, io, client.stream, .data, flag_end_stream, 1, "body-before-headers");

        thread.join();
        if (shared.err) |err| return err;
        try std.testing.expect(shared.saw_expected);
    }

    {
        var threaded = std.Io.Threaded.init(allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        var server = try Server.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        );
        defer server.deinit();

        const Shared = struct {
            server: *Server,
            err: ?anyerror = null,

            fn run(shared: *@This()) void {
                runFallible(shared.server) catch |err| {
                    shared.err = err;
                };
            }

            fn runFallible(server_ptr: *Server) !void {
                var connection = try server_ptr.accept();
                defer connection.close();

                var request = try connection.readRequest();
                defer request.deinit(server_ptr.allocator);
                try std.testing.expectEqualStrings("/after-priority", request.path);
                try connection.writeResponse(request.stream_id, .{ .body = "ok" });
            }
        };

        var shared = Shared{ .server = &server };
        const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

        var client = try Client.connect(allocator, io, server.address(), .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
        });
        defer client.close();

        var priority: std.ArrayList(u8) = .empty;
        defer priority.deinit(allocator);
        try http2.PriorityPayload.write(&priority, allocator, 1, false, 0, 16);
        try writeAll(io, client.stream, priority.items);

        var response = try client.request(.{
            .method = "GET",
            .path = "/after-priority",
            .authority = "localhost",
        });
        defer response.deinit(allocator);

        thread.join();
        if (shared.err) |err| return err;
        try std.testing.expectEqualStrings("ok", response.body);
    }
}

test "HTTP/2 client answers PING while reading response" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/response-ping", request.path);

            const ping_payload = [_]u8{ 9, 8, 7, 6, 5, 4, 3, 2 };
            try writeFrame(server_ptr.allocator, server_ptr.io, connection.stream, .ping, 0, 0, &ping_payload);
            var ping_ack = try readFrame(server_ptr.allocator, server_ptr.io, connection.stream, server_ptr.limits);
            defer ping_ack.deinit(server_ptr.allocator);
            try std.testing.expectEqual(http2.FrameType.ping, ping_ack.frame.header.frame_type);
            try std.testing.expect((ping_ack.frame.header.flags & flag_ack) != 0);
            try std.testing.expectEqualSlices(u8, &ping_payload, ping_ack.frame.payload);

            try connection.writeResponse(request.stream_id, .{ .body = "after-ping" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var response = try client.request(.{
        .method = "GET",
        .path = "/response-ping",
        .authority = "localhost",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("after-ping", response.body);
}

test "HTTP/2 client skips informational responses before final response" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/interim-h2", request.path);

            try connection.writeInformationalResponse(request.stream_id, 103, &.{.{ .name = "link", .value = "</style.css>; rel=preload" }});
            try connection.writeResponse(request.stream_id, .{ .body = "final" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var response = try client.request(.{
        .method = "GET",
        .path = "/interim-h2",
        .authority = "localhost",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("final", response.body);
}

test "HTTP/2 response writers reject a stream after its final response" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .max_concurrent_streams = 1,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var first = try connection.readRequest();
            defer first.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/first", first.path);
            try connection.writeResponse(first.stream_id, .{ .body = "one" });
            try std.testing.expectEqual(
                @as(usize, 0),
                connection.activePeerStreamCount(),
            );
            try std.testing.expectError(
                error.InvalidStreamId,
                connection.writeResponse(first.stream_id, .{ .body = "duplicate" }),
            );
            try std.testing.expectError(
                error.InvalidStreamId,
                connection.writeInformationalResponse(
                    first.stream_id,
                    103,
                    &.{},
                ),
            );
            try std.testing.expectEqual(
                @as(usize, 0),
                connection.activePeerStreamCount(),
            );

            var second = try connection.readRequest();
            defer second.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/second", second.path);
            try connection.writeResponse(second.stream_id, .{ .body = "two" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var first = try client.request(.{
        .method = "GET",
        .path = "/first",
        .authority = "localhost",
    });
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("one", first.body);

    var second = try client.request(.{
        .method = "GET",
        .path = "/second",
        .authority = "localhost",
    });
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("two", second.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 client observes bounded informational responses in order" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            for (0..4) |index| {
                var request = try connection.readRequest();
                defer request.deinit(server_ptr.allocator);
                try connection.writeInformationalResponse(
                    request.stream_id,
                    103,
                    &.{.{ .name = "link", .value = "</style.css>" }},
                );
                try connection.writeInformationalResponse(
                    request.stream_id,
                    102,
                    &.{.{ .name = "x-progress", .value = "half" }},
                );
                if (index == 3) {
                    try connection.writeInformationalResponse(
                        request.stream_id,
                        103,
                        &.{.{ .name = "link", .value = "</late.css>" }},
                    );
                }
                try connection.writeResponse(request.stream_id, .{
                    .body = "final",
                    .request_method = request.method,
                });
            }
        }
    };

    const Observer = struct {
        statuses: [4]u16 = undefined,
        count: usize = 0,
        valid_headers: bool = true,

        fn observe(context_ptr: *anyopaque, head: StreamingResponseHead) void {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            self.statuses[self.count] = head.status;
            self.valid_headers = self.valid_headers and
                findHeader(head.headers, "date") == null;
            const expected_name = if (head.status == 103)
                "link"
            else
                "x-progress";
            const expected_value = if (head.status == 103)
                "</style.css>"
            else
                "half";
            self.valid_headers = self.valid_headers and
                std.mem.eql(
                    u8,
                    findHeader(head.headers, expected_name) orelse "",
                    expected_value,
                );
            self.count += 1;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
        .max_informational_responses = 2,
    });
    defer client.close();

    var aggregate_observer = Observer{};
    var aggregate = try client.requestWithInformational(.{
        .path = "/informational-aggregate",
        .authority = "localhost",
    }, .{
        .context = &aggregate_observer,
        .on_response = Observer.observe,
    });
    defer aggregate.deinit(allocator);
    try std.testing.expectEqualSlices(
        u16,
        &.{ 103, 102 },
        aggregate_observer.statuses[0..aggregate_observer.count],
    );
    try std.testing.expect(aggregate_observer.valid_headers);
    try std.testing.expectEqualStrings("final", aggregate.body);
    try std.testing.expectEqual(
        @as(usize, http_date.value_len),
        findHeader(aggregate.headers, "date").?.len,
    );

    var streaming_observer = Observer{};
    var body_bytes: usize = 0;
    var streaming = try client.requestStreamingWithInformational(.{
        .path = "/informational-streaming",
        .authority = "localhost",
    }, .{
        .context = &streaming_observer,
        .on_response = Observer.observe,
    }, &body_bytes, struct {
        fn consume(count: *usize, data: []const u8) !void {
            count.* += data.len;
        }
    }.consume);
    defer streaming.deinit(allocator);
    try std.testing.expectEqualSlices(
        u16,
        &.{ 103, 102 },
        streaming_observer.statuses[0..streaming_observer.count],
    );
    try std.testing.expect(streaming_observer.valid_headers);
    try std.testing.expectEqual(@as(usize, 5), body_bytes);

    var writer = try client.startRequest(.{
        .path = "/informational-writer",
        .authority = "localhost",
        .body_length = 0,
    });
    defer writer.deinit();
    try writer.finish();
    var writer_observer = Observer{};
    var writer_response = try writer.readResponseWithInformational(.{
        .context = &writer_observer,
        .on_response = Observer.observe,
    });
    defer writer_response.deinit(allocator);
    try std.testing.expectEqualSlices(
        u16,
        &.{ 103, 102 },
        writer_observer.statuses[0..writer_observer.count],
    );
    try std.testing.expect(writer_observer.valid_headers);
    try std.testing.expectEqualStrings("final", writer_response.body);

    try std.testing.expectError(
        error.TooManyInformationalResponses,
        client.request(.{
            .path = "/informational-over-limit",
            .authority = "localhost",
        }),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 client rejects 101 switching protocols response" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/bad-101-h2", request.path);

            // RFC 9113 has no 101 upgrade path; HTTP/2 peers must use extended
            // CONNECT instead.  Send raw HEADERS so this remains a receive-path
            // regression even if the writer helper rejects 101 in the future.
            try connection.writeHeaders(request.stream_id, &.{
                .{ .name = ":status", .value = "101" },
            }, false);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    try std.testing.expectError(error.InvalidStatus, client.request(.{
        .method = "GET",
        .path = "/bad-101-h2",
        .authority = "localhost",
    }));

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 client resets malformed response stream and reuses connection" {
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
        saw_reset: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var first = try connection.readRequest();
            defer first.deinit(shared.server.allocator);
            try connection.writeHeaders(first.stream_id, &.{
                .{ .name = ":status", .value = "200" },
                .{ .name = "connection", .value = "close" },
            }, true);
            var reset = try connection.readResetStream();
            defer reset.deinit(shared.server.allocator);
            try std.testing.expectEqual(first.stream_id, reset.reset.stream_id);
            try std.testing.expectEqual(http2.ErrorCode.protocol_error, reset.reset.error_code);
            shared.saw_reset = true;

            var second = try connection.readRequest();
            defer second.deinit(shared.server.allocator);
            try std.testing.expectEqualStrings("/good-after-bad-response", second.path);
            try connection.writeResponse(second.stream_id, .{
                .status = 204,
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();

    try std.testing.expectError(error.InvalidHeader, client.request(.{
        .path = "/bad-response",
        .authority = "localhost",
    }));
    var response = try client.request(.{
        .path = "/good-after-bad-response",
        .authority = "localhost",
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), response.status);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_reset);
}

test "HTTP/2 streaming client resets malformed response and reuses connection" {
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
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var first = try connection.readRequest();
            defer first.deinit(shared.server.allocator);
            try connection.writeHeaders(first.stream_id, &.{
                .{ .name = ":status", .value = "204" },
                .{ .name = "content-length", .value = "0" },
            }, true);
            var reset = try connection.readResetStream();
            defer reset.deinit(shared.server.allocator);
            try std.testing.expectEqual(first.stream_id, reset.reset.stream_id);
            try std.testing.expectEqual(http2.ErrorCode.protocol_error, reset.reset.error_code);

            var second = try connection.readRequest();
            defer second.deinit(shared.server.allocator);
            try std.testing.expectEqualStrings("/streaming-sibling", second.path);
            try connection.writeResponse(second.stream_id, .{
                .status = 204,
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();

    try std.testing.expectError(error.InvalidContentLength, client.requestStreaming(
        .{ .path = "/bad-streaming-response", .authority = "localhost" },
        {},
        struct {
            fn consume(_: void, _: []const u8) !void {}
        }.consume,
    ));
    var response = try client.request(.{
        .path = "/streaming-sibling",
        .authority = "localhost",
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), response.status);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 aggregate batch resets malformed member cancels sibling and reuses connection" {
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
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var first = try connection.readRequest();
            defer first.deinit(shared.server.allocator);
            var second = try connection.readRequest();
            defer second.deinit(shared.server.allocator);
            try std.testing.expectEqual(@as(u31, 1), first.stream_id);
            try std.testing.expectEqual(@as(u31, 3), second.stream_id);

            try connection.writeHeaders(first.stream_id, &.{
                .{ .name = ":status", .value = "200" },
                .{ .name = "connection", .value = "close" },
            }, true);
            var first_reset = try connection.readResetStream();
            defer first_reset.deinit(shared.server.allocator);
            var second_reset = try connection.readResetStream();
            defer second_reset.deinit(shared.server.allocator);
            try std.testing.expectEqual(@as(u31, 1), first_reset.reset.stream_id);
            try std.testing.expectEqual(http2.ErrorCode.protocol_error, first_reset.reset.error_code);
            try std.testing.expectEqual(@as(u31, 3), second_reset.reset.stream_id);
            try std.testing.expectEqual(http2.ErrorCode.cancel, second_reset.reset.error_code);

            var third = try connection.readRequest();
            defer third.deinit(shared.server.allocator);
            try std.testing.expectEqual(@as(u31, 5), third.stream_id);
            try connection.writeResponse(third.stream_id, .{ .status = 204 });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();

    var responses: [2]OwnedResponse = undefined;
    try std.testing.expectError(error.InvalidHeader, client.requestBatchInto(
        &.{
            .{ .path = "/bad-batch-response", .authority = "localhost" },
            .{ .path = "/cancelled-batch-sibling", .authority = "localhost" },
        },
        &responses,
    ));
    var third = try client.request(.{
        .path = "/after-batch-error",
        .authority = "localhost",
    });
    defer third.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), third.status);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 streaming batch resets malformed member and cancels sibling" {
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
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var first = try connection.readRequest();
            defer first.deinit(shared.server.allocator);
            var second = try connection.readRequest();
            defer second.deinit(shared.server.allocator);
            try std.testing.expectEqual(@as(u31, 1), first.stream_id);
            try std.testing.expectEqual(@as(u31, 3), second.stream_id);

            try connection.writeHeaders(first.stream_id, &.{
                .{ .name = ":status", .value = "204" },
                .{ .name = "content-length", .value = "0" },
            }, true);
            var first_reset = try connection.readResetStream();
            defer first_reset.deinit(shared.server.allocator);
            var second_reset = try connection.readResetStream();
            defer second_reset.deinit(shared.server.allocator);
            try std.testing.expectEqual(@as(u31, 1), first_reset.reset.stream_id);
            try std.testing.expectEqual(http2.ErrorCode.protocol_error, first_reset.reset.error_code);
            try std.testing.expectEqual(@as(u31, 3), second_reset.reset.stream_id);
            try std.testing.expectEqual(http2.ErrorCode.cancel, second_reset.reset.error_code);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();

    var responses: [2]StreamingResponse = undefined;
    try std.testing.expectError(
        error.InvalidContentLength,
        client.requestBatchStreamingInto(
            &.{
                .{ .path = "/bad-streaming-batch", .authority = "localhost" },
                .{ .path = "/cancel-streaming-sibling", .authority = "localhost" },
            },
            &responses,
            {},
            struct {
                fn consume(_: void, _: usize, _: []const u8) !void {}
            }.consume,
        ),
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 aggregate batch maps malformed HPACK to one GOAWAY" {
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
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var first = try connection.readRequest();
            defer first.deinit(shared.server.allocator);
            var second = try connection.readRequest();
            defer second.deinit(shared.server.allocator);
            try writeFrame(
                shared.server.allocator,
                shared.server.io,
                connection.stream,
                .headers,
                flag_end_headers | flag_end_stream,
                first.stream_id,
                &.{0x80},
            );
            var goaway = try readFrame(
                shared.server.allocator,
                shared.server.io,
                connection.stream,
                connection.limits,
            );
            defer goaway.deinit(shared.server.allocator);
            try std.testing.expectEqual(
                http2.FrameType.goaway,
                goaway.frame.header.frame_type,
            );
            try std.testing.expectEqual(
                http2.ErrorCode.compression_error,
                (try http2.GoAwayPayload.parse(goaway.frame)).error_code,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();

    var responses: [2]OwnedResponse = undefined;
    try std.testing.expectError(error.InvalidEncoding, client.requestBatchInto(
        &.{
            .{ .path = "/bad-batch-hpack", .authority = "localhost" },
            .{ .path = "/hpack-sibling", .authority = "localhost" },
        },
        &responses,
    ));

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 aggregate batch does not reset an already peer-reset member" {
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
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var first = try connection.readRequest();
            defer first.deinit(shared.server.allocator);
            var second = try connection.readRequest();
            defer second.deinit(shared.server.allocator);
            try connection.sendResetStream(first.stream_id, .refused_stream);

            // The peer-originated reset already closed stream 1. Batch cleanup
            // should send exactly one local cancellation for stream 3.
            var sibling_reset = try connection.readResetStream();
            defer sibling_reset.deinit(shared.server.allocator);
            try std.testing.expectEqual(second.stream_id, sibling_reset.reset.stream_id);
            try std.testing.expectEqual(http2.ErrorCode.cancel, sibling_reset.reset.error_code);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();

    var responses: [2]OwnedResponse = undefined;
    try std.testing.expectError(error.StreamReset, client.requestBatchInto(
        &.{
            .{ .path = "/peer-reset", .authority = "localhost" },
            .{ .path = "/cancel-after-peer-reset", .authority = "localhost" },
        },
        &responses,
    ));

    thread.join();
    if (shared.err) |err| return err;
}

fn expectClientConnectionErrorGoAway(
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

test "HTTP/2 client maps SETTINGS on a stream to PROTOCOL_ERROR GOAWAY" {
    try expectClientConnectionErrorGoAway(
        .settings,
        1,
        &.{},
        error.InvalidFrame,
        .protocol_error,
        "frame-envelope",
    );
}

fn expectServerInitialConnectionErrorGoAway(
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

test "HTTP/2 server maps invalid initial SETTINGS envelope to GOAWAY" {
    try expectServerInitialConnectionErrorGoAway(
        .settings,
        1,
        &.{},
        error.InvalidFrame,
        .protocol_error,
        "frame-envelope",
    );
}

test "HTTP/2 server maps invalid initial window setting to FLOW_CONTROL_ERROR" {
    var payload: [6]u8 = undefined;
    std.mem.writeInt(
        u16,
        payload[0..2],
        @intFromEnum(http2.SettingId.initial_window_size),
        .big,
    );
    std.mem.writeInt(u32, payload[2..6], 0x8000_0000, .big);
    try expectServerInitialConnectionErrorGoAway(
        .settings,
        0,
        &payload,
        error.InvalidSetting,
        .flow_control_error,
        "settings-value",
    );
}

test "HTTP/2 client maps invalid peer settings to precise GOAWAY codes" {
    var initial_window: [6]u8 = undefined;
    std.mem.writeInt(
        u16,
        initial_window[0..2],
        @intFromEnum(http2.SettingId.initial_window_size),
        .big,
    );
    std.mem.writeInt(u32, initial_window[2..6], 0x8000_0000, .big);
    try expectClientConnectionErrorGoAway(
        .settings,
        0,
        &initial_window,
        error.InvalidSetting,
        .flow_control_error,
        "settings-value",
    );

    var enable_push: [6]u8 = undefined;
    std.mem.writeInt(
        u16,
        enable_push[0..2],
        @intFromEnum(http2.SettingId.enable_push),
        .big,
    );
    std.mem.writeInt(u32, enable_push[2..6], 1, .big);
    try expectClientConnectionErrorGoAway(
        .settings,
        0,
        &enable_push,
        error.InvalidSetting,
        .protocol_error,
        "settings-value",
    );
}

test "HTTP/2 client maps malformed PING length to FRAME_SIZE_ERROR GOAWAY" {
    try expectClientConnectionErrorGoAway(
        .ping,
        0,
        &.{ 0, 1, 2, 3, 4, 5, 6 },
        error.InvalidFrame,
        .frame_size_error,
        "frame-envelope",
    );
}

test "HTTP/2 client resets zero WINDOW_UPDATE stream and keeps connection" {
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
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var first = try connection.readRequest();
            defer first.deinit(shared.server.allocator);
            try writeFrame(
                shared.server.allocator,
                shared.server.io,
                connection.stream,
                .window_update,
                0,
                first.stream_id,
                &.{ 0, 0, 0, 0 },
            );
            var reset = try connection.readResetStreamWithTimeout(
                .fromSeconds(2),
            );
            defer reset.deinit(shared.server.allocator);
            try std.testing.expectEqual(first.stream_id, reset.reset.stream_id);
            try std.testing.expectEqual(
                http2.ErrorCode.protocol_error,
                reset.reset.error_code,
            );

            var second = try connection.readRequest();
            defer second.deinit(shared.server.allocator);
            try connection.writeResponse(second.stream_id, .{
                .status = 200,
                .body = "reused",
                .request_method = second.method,
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();
    try std.testing.expectError(error.InvalidFrame, client.request(.{
        .path = "/zero-window",
        .authority = "localhost",
    }));
    try std.testing.expect(client.isReusable());

    var response = try client.request(.{
        .path = "/after-zero-window",
        .authority = "localhost",
    });
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("reused", response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 client maps malformed response HPACK to COMPRESSION_ERROR GOAWAY" {
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
        saw_goaway: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
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
                .headers,
                flag_end_headers | flag_end_stream,
                request.stream_id,
                &.{0x80},
            );
            var goaway = try connection.readGoAway();
            defer goaway.deinit(shared.server.allocator);
            try std.testing.expectEqual(
                http2.ErrorCode.compression_error,
                goaway.goaway.error_code,
            );
            shared.saw_goaway = true;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();
    try std.testing.expectError(error.InvalidEncoding, client.request(.{
        .path = "/bad-response-hpack",
        .authority = "localhost",
    }));

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_goaway);
}

test "HTTP/2 client maps cross-stream response CONTINUATION to PROTOCOL_ERROR GOAWAY" {
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
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
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
                .headers,
                0,
                request.stream_id,
                &.{0x88},
            );
            try writeFrame(
                shared.server.allocator,
                shared.server.io,
                connection.stream,
                .continuation,
                flag_end_headers,
                request.stream_id + 2,
                &.{},
            );
            var wire_error = try readFrame(
                shared.server.allocator,
                shared.server.io,
                connection.stream,
                connection.limits,
            );
            defer wire_error.deinit(shared.server.allocator);
            try std.testing.expectEqual(
                http2.FrameType.goaway,
                wire_error.frame.header.frame_type,
            );
            try std.testing.expectEqual(
                http2.ErrorCode.protocol_error,
                (try http2.GoAwayPayload.parse(wire_error.frame)).error_code,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();
    try std.testing.expectError(error.UnexpectedFrame, client.request(.{
        .path = "/bad-response-continuation",
        .authority = "localhost",
    }));

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 informational callback cannot reenter frame reader" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var first = try connection.readRequest();
            defer first.deinit(shared.server.allocator);
            try std.testing.expectEqual(@as(u31, 1), first.stream_id);
            try connection.writeInformationalResponse(
                first.stream_id,
                103,
                &.{.{ .name = "link", .value = "</next>" }},
            );
            var second = try connection.readRequest();
            defer second.deinit(shared.server.allocator);
            try std.testing.expectEqual(@as(u31, 3), second.stream_id);
            try connection.writeResponse(first.stream_id, .{
                .body = "one",
                .request_method = first.method,
            });
            try connection.writeResponse(second.stream_id, .{
                .body = "two",
                .request_method = second.method,
            });
        }
    };

    const Observer = struct {
        connection: *Connection,
        second: ?Connection.PendingResponse = null,
        error_seen: ?anyerror = null,
        reset_error_seen: ?anyerror = null,
        unexpectedly_read: bool = false,

        fn observe(
            raw: *anyopaque,
            head: StreamingResponseHead,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (head.status != 103) @panic("unexpected interim status");
            self.second = self.connection.sendCompleteRequest(.{
                .path = "/second",
                .authority = "localhost",
            }) catch |err| {
                self.error_seen = err;
                return;
            };
            var nested = self.connection.readResponse(
                self.second.?.stream_id,
                self.second.?.request_method,
                self.second.?.extended_connect,
                null,
            ) catch |err| {
                self.error_seen = err;
                self.probeReset();
                return;
            };
            self.unexpectedly_read = true;
            nested.deinit(self.connection.allocator);
            self.probeReset();
        }

        fn probeReset(self: *@This()) void {
            self.connection.sendResetStream(
                self.second.?.stream_id,
                .cancel,
            ) catch |err| {
                self.reset_error_seen = err;
                return;
            };
            self.unexpectedly_read = true;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    const first = try client.sendCompleteRequest(.{
        .path = "/first",
        .authority = "localhost",
    });
    var observer = Observer{ .connection = &client };
    var first_response = try client.readResponse(
        first.stream_id,
        first.request_method,
        first.extended_connect,
        .{ .context = &observer, .on_response = Observer.observe },
    );
    defer first_response.deinit(allocator);
    try std.testing.expect(!observer.unexpectedly_read);
    switch (observer.error_seen orelse return error.TestUnexpectedResult) {
        error.UnexpectedFrame => {},
        else => return error.TestUnexpectedResult,
    }
    switch (observer.reset_error_seen orelse return error.TestUnexpectedResult) {
        error.UnexpectedFrame => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqualStrings("one", first_response.body);

    const second = observer.second orelse return error.TestUnexpectedResult;
    var second_response = try client.readResponse(
        second.stream_id,
        second.request_method,
        second.extended_connect,
        null,
    );
    defer second_response.deinit(allocator);
    try std.testing.expectEqualStrings("two", second_response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 client rejects END_STREAM on informational response" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/bad-interim-h2", request.path);
            try connection.writeHeaders(request.stream_id, &.{
                .{ .name = ":status", .value = "103" },
            }, true);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    try std.testing.expectError(error.UnexpectedFrame, client.request(.{
        .method = "GET",
        .path = "/bad-interim-h2",
        .authority = "localhost",
    }));

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 client rejects content-length on informational response" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/bad-interim-length-h2", request.path);
            // HTTP semantics forbid Content-Length on informational responses.
            // Validate before skipping 1xx HEADERS; otherwise this invalid
            // response could be silently ignored before the final response.
            try connection.writeHeaders(request.stream_id, &.{
                .{ .name = ":status", .value = "103" },
                .{ .name = "content-length", .value = "0" },
            }, false);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    try std.testing.expectError(error.InvalidContentLength, client.request(.{
        .method = "GET",
        .path = "/bad-interim-length-h2",
        .authority = "localhost",
    }));

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 client rejects PUSH_PROMISE after disabling push" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/push-disabled", request.path);

            var promised_block: std.ArrayList(u8) = .empty;
            defer promised_block.deinit(server_ptr.allocator);
            try http2.Hpack.encodeLiteralBlock(&promised_block, server_ptr.allocator, &.{
                .{ .name = ":method", .value = "GET" },
                .{ .name = ":path", .value = "/pushed" },
                .{ .name = ":scheme", .value = "https" },
            });
            var promise: std.ArrayList(u8) = .empty;
            defer promise.deinit(server_ptr.allocator);
            try http2.PushPromisePayload.write(&promise, server_ptr.allocator, request.stream_id, 2, promised_block.items, .{});
            try writeAll(server_ptr.io, connection.stream, promise.items);

            var goaway = try connection.readGoAway();
            defer goaway.deinit(server_ptr.allocator);
            try std.testing.expectEqual(
                http2.ErrorCode.protocol_error,
                goaway.goaway.error_code,
            );
            try std.testing.expectEqualStrings(
                "push-disabled",
                goaway.goaway.debug_data,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    try std.testing.expectError(error.InvalidFrame, client.request(.{
        .method = "GET",
        .path = "/push-disabled",
        .authority = "localhost",
    }));
    try std.testing.expect(!client.isReusable());
    try std.testing.expect(client.push_state.state == null);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 validates PUSH_PROMISE parent and promised stream ids" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    const valid_parent_even_promise = http2.Frame{
        .header = .{ .length = 4, .frame_type = .push_promise, .flags = flag_end_headers, .stream_id = 1 },
        .payload = &.{ 0, 0, 0, 2 },
    };
    try std.testing.expectError(error.InvalidFrame, connection.validatePushPromiseForClientStream(valid_parent_even_promise));

    try connection.addActiveLocalStream(1);
    const promise = try connection.validatePushPromiseForClientStream(valid_parent_even_promise);
    try std.testing.expectEqual(@as(u31, 1), promise.stream_id);
    try std.testing.expectEqual(@as(u31, 2), promise.promised_stream_id);

    const odd_promised_stream = http2.Frame{
        .header = .{ .length = 4, .frame_type = .push_promise, .flags = flag_end_headers, .stream_id = 1 },
        .payload = &.{ 0, 0, 0, 3 },
    };
    try std.testing.expectError(error.InvalidStreamId, connection.validatePushPromiseForClientStream(odd_promised_stream));
}

test "HTTP/2 client fails active request rejected by GOAWAY" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/goaway-reject", request.path);
            try connection.sendGoAway(0, .no_error, "draining");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    try std.testing.expectEqual(
        GoAwayRetryDisposition.no_goaway,
        client.goAwayRetryDisposition(1),
    );

    try std.testing.expectError(error.ConnectionGoAway, client.request(.{
        .method = "GET",
        .path = "/goaway-reject",
        .authority = "localhost",
    }));
    try std.testing.expectEqual(
        @as(?u31, 0),
        client.peerGoAwayLastStreamId(),
    );
    try std.testing.expectEqual(
        GoAwayRetryDisposition.safe_to_retry,
        client.goAwayRetryDisposition(1),
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 client continues active request allowed by GOAWAY" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/goaway-allowed", request.path);
            try connection.sendGoAway(request.stream_id, .no_error, "draining");
            try connection.writeResponse(request.stream_id, .{ .body = "still-ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var response = try client.request(.{
        .method = "GET",
        .path = "/goaway-allowed",
        .authority = "localhost",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("still-ok", response.body);
    try std.testing.expectEqual(
        GoAwayRetryDisposition.may_have_been_processed,
        client.goAwayRetryDisposition(1),
    );
}

test "HTTP/2 client refuses new request after peer GOAWAY" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/first-before-goaway", request.path);
            try connection.sendGoAway(request.stream_id, .no_error, "draining");
            try connection.writeResponse(request.stream_id, .{ .body = "first" });

            // If the client incorrectly opens stream 3 after GOAWAY, this read
            // would eventually observe it.  The test expects the client to
            // reject locally instead, so the server can simply return.
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var first = try client.request(.{
        .method = "GET",
        .path = "/first-before-goaway",
        .authority = "localhost",
    });
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("first", first.body);

    try std.testing.expectError(error.ConnectionGoAway, client.request(.{
        .method = "GET",
        .path = "/second-after-goaway",
        .authority = "localhost",
    }));

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 runtime rejects malformed CONTINUATION sequence" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        saw_expected: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();

            var request = connection.readRequest() catch |err| {
                if (err == error.UnexpectedFrame) {
                    shared.saw_expected = true;
                    return;
                }
                shared.err = err;
                return;
            };
            request.deinit(shared.server.allocator);
            shared.err = error.UnexpectedFrame;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/bad-continuation" },
        .{ .name = ":scheme", .value = "https" },
    });
    const split = block.items.len / 2;
    try writeFrame(allocator, io, client.stream, .headers, 0, 1, block.items[0..split]);
    try writeFrame(allocator, io, client.stream, .continuation, flag_end_headers, 3, block.items[split..]);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
}

test "HTTP/2 serveOne maps malformed HPACK to COMPRESSION_ERROR GOAWAY" {
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

    const Context = struct {
        calls: usize = 0,

        fn handle(ctx: *@This(), _: OwnedRequest) Error!ResponseOptions {
            ctx.calls += 1;
            return .{};
        }
    };
    const Shared = struct {
        server: *Server,
        context: Context = .{},
        saw_expected: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            _ = connection.serveOne(
                Context,
                &shared.context,
                Context.handle,
            ) catch |err| {
                if (err == error.InvalidEncoding) {
                    shared.saw_expected = true;
                    return;
                }
                shared.err = err;
                return;
            };
            shared.err = error.UnexpectedFrame;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();
    // Indexed representation with index zero is invalid HPACK.
    try writeFrame(allocator, io, client.stream, .headers, flag_end_headers | flag_end_stream, 1, &.{0x80});
    var goaway = try client.readGoAway();
    defer goaway.deinit(allocator);
    try std.testing.expectEqual(http2.ErrorCode.compression_error, goaway.goaway.error_code);
    try std.testing.expectEqualStrings("hpack-decode", goaway.goaway.debug_data);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
    try std.testing.expectEqual(@as(usize, 0), shared.context.calls);
}

test "HTTP/2 serveOne maps malformed CONTINUATION to PROTOCOL_ERROR GOAWAY" {
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

    const Context = struct {
        calls: usize = 0,

        fn handle(ctx: *@This(), _: OwnedRequest) Error!ResponseOptions {
            ctx.calls += 1;
            return .{};
        }
    };
    const Shared = struct {
        server: *Server,
        context: Context = .{},
        saw_expected: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            _ = connection.serveOne(
                Context,
                &shared.context,
                Context.handle,
            ) catch |err| {
                if (err == error.UnexpectedFrame) {
                    shared.saw_expected = true;
                    return;
                }
                shared.err = err;
                return;
            };
            shared.err = error.UnexpectedFrame;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/bad-continuation-goaway" },
        .{ .name = ":scheme", .value = "http" },
    });
    const split = block.items.len / 2;
    try writeFrame(allocator, io, client.stream, .headers, flag_end_stream, 1, block.items[0..split]);
    try writeFrame(allocator, io, client.stream, .continuation, flag_end_headers, 3, block.items[split..]);
    var goaway = try client.readGoAway();
    defer goaway.deinit(allocator);
    try std.testing.expectEqual(http2.ErrorCode.protocol_error, goaway.goaway.error_code);
    try std.testing.expectEqualStrings("frame-sequence", goaway.goaway.debug_data);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
    try std.testing.expectEqual(@as(usize, 0), shared.context.calls);
}

test "HTTP/2 serveOne maps unterminated continuation flood to ENHANCE_YOUR_CALM GOAWAY" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_continuation_frames = 1 },
    );
    defer server.deinit();

    const Context = struct {
        calls: usize = 0,
        fn handle(ctx: *@This(), _: OwnedRequest) Error!ResponseOptions {
            ctx.calls += 1;
            return .{};
        }
    };
    const Shared = struct {
        server: *Server,
        context: Context = .{},
        saw_expected: bool = false,
        err: ?anyerror = null,
        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            _ = connection.serveOne(
                Context,
                &shared.context,
                Context.handle,
            ) catch |err| {
                if (err == error.MessageTooLarge) {
                    shared.saw_expected = true;
                    return;
                }
                shared.err = err;
                return;
            };
            shared.err = error.UnexpectedFrame;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();
    try writeFrame(allocator, io, client.stream, .headers, flag_end_stream, 1, &.{0x82});
    try writeFrame(allocator, io, client.stream, .continuation, 0, 1, &.{0x84});
    try writeFrame(allocator, io, client.stream, .continuation, 0, 1, &.{0x86});
    var wire_error = try readFrame(
        allocator,
        io,
        client.stream,
        client.limits,
    );
    defer wire_error.deinit(allocator);
    try std.testing.expectEqual(http2.FrameType.goaway, wire_error.frame.header.frame_type);
    const goaway = try http2.GoAwayPayload.parse(wire_error.frame);
    try std.testing.expectEqual(http2.ErrorCode.enhance_your_calm, goaway.error_code);
    try std.testing.expectEqualStrings("header-block-limit", goaway.debug_data);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
    try std.testing.expectEqual(@as(usize, 0), shared.context.calls);
}

test "HTTP/2 serveConcurrent maps malformed HPACK to COMPRESSION_ERROR GOAWAY" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        calls: usize = 0,

        pub fn handle(ctx: *@This(), _: OwnedRequest) Error!ResponseOptions {
            ctx.calls += 1;
            return .{};
        }
    };
    const Shared = struct {
        server: *Server,
        context: Context = .{},
        result: ?ConcurrentServeResult = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.result = shared.server.serveConcurrent(
                Context,
                &shared.context,
                Context.handle,
                1,
            ) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();
    try writeFrame(allocator, io, client.stream, .headers, flag_end_headers | flag_end_stream, 1, &.{0x80});
    var goaway = try client.readGoAway();
    defer goaway.deinit(allocator);
    try std.testing.expectEqual(http2.ErrorCode.compression_error, goaway.goaway.error_code);

    thread.join();
    if (shared.err) |err| return err;
    var result = shared.result orelse return error.UnexpectedFrame;
    defer result.deinit();
    try std.testing.expectEqual(error.InvalidEncoding, result.firstError().?);
    try std.testing.expectEqual(@as(usize, 0), result.successCount());
    try std.testing.expectEqual(@as(usize, 0), shared.context.calls);
}

test "HTTP/2 runtime rejects server-initiated request stream ids" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        saw_expected: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();

            var request = connection.readRequest() catch |err| {
                if (err == error.InvalidFrame) {
                    shared.saw_expected = true;
                    return;
                }
                shared.err = err;
                return;
            };
            request.deinit(shared.server.allocator);
            shared.err = error.UnexpectedFrame;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/even-stream" },
        .{ .name = ":scheme", .value = "https" },
    });
    try writeFrame(allocator, io, client.stream, .headers, flag_end_headers | flag_end_stream, 2, block.items);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
}

test "HTTP/2 runtime rejects reused or decreasing client stream ids" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        saw_expected: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();

            var first = connection.readRequest() catch |err| {
                shared.err = err;
                return;
            };
            defer first.deinit(shared.server.allocator);
            if (!std.mem.eql(u8, first.path, "/first-high")) {
                shared.err = error.UnexpectedFrame;
                return;
            }

            var second = connection.readRequest() catch |err| {
                if (err == error.InvalidFrame) {
                    shared.saw_expected = true;
                    return;
                }
                shared.err = err;
                return;
            };
            second.deinit(shared.server.allocator);
            shared.err = error.UnexpectedFrame;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    const first_fields = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/first-high" },
        .{ .name = ":scheme", .value = "https" },
    };
    try client.writeHeaders(3, &first_fields, true);

    const second_fields = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/second-low" },
        .{ .name = ":scheme", .value = "https" },
    };
    try client.writeHeaders(1, &second_fields, true);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
}

test "HTTP/2 runtime exchanges request and response trailers" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("POST", request.method);
            try std.testing.expectEqualStrings("/trailers", request.path);
            try std.testing.expectEqualStrings("hello", request.body);
            try std.testing.expectEqual(@as(usize, 1), request.trailers.len);
            try std.testing.expectEqualStrings("request-checksum", request.trailers[0].name);
            try std.testing.expectEqualStrings("ok", request.trailers[0].value);

            try connection.writeResponse(request.stream_id, .{
                .status = 200,
                .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
                .body = "world",
                .trailers = &.{.{ .name = "grpc-status", .value = "0" }},
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var response = try client.request(.{
        .method = "POST",
        .path = "/trailers",
        .authority = "localhost",
        .body = "hello",
        .trailers = &.{.{ .name = "request-checksum", .value = "ok" }},
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("world", response.body);
    try std.testing.expectEqual(@as(usize, 1), response.trailers.len);
    try std.testing.expectEqualStrings("grpc-status", response.trailers[0].name);
    try std.testing.expectEqualStrings("0", response.trailers[0].value);
}

test "HTTP/2 pending request queue reuses consumed slots" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.recv_stream_windows.deinit(allocator);
        connection.recv_stream_window_index.deinit(allocator);
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
        connection.push_state.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.response_semantics.deinit(allocator);
        connection.response_semantics_index.deinit(allocator);
        for (connection.pending_requests.items[connection.pending_request_head..]) |*pending| {
            pending.deinit(allocator);
        }
        connection.pending_requests.deinit(allocator);
        connection.deinitPeerMetadata();
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }

    try connection.pending_requests.ensureTotalCapacityPrecise(allocator, 4);
    try queueTestPendingRequest(&connection, 1, "/one", allocator);
    try queueTestPendingRequest(&connection, 3, "/three", allocator);
    try queueTestPendingRequest(&connection, 5, "/five", allocator);
    try queueTestPendingRequest(&connection, 7, "/seven", allocator);

    var first = connection.popPendingRequest() orelse
        return error.TestUnexpectedResult;
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), first.stream_id);
    try std.testing.expectEqual(@as(usize, 3), connection.pendingRequestCount());
    try std.testing.expectEqual(@as(usize, 1), connection.pending_request_head);

    // The queue is logically non-empty and physically full with one consumed
    // head element. A new interleaved complete request should compact and reuse
    // that slot rather than allocate during a burst of peer request completions.
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try queueTestPendingRequest(&connection, 9, "/nine", no_alloc.allocator());
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 4), connection.pendingRequestCount());
    try std.testing.expectEqual(@as(usize, 0), connection.pending_request_head);

    for ([_]u31{ 3, 5, 7, 9 }) |expected_stream_id| {
        var pending = connection.popPendingRequest() orelse
            return error.TestUnexpectedResult;
        defer pending.deinit(allocator);
        try std.testing.expectEqual(expected_stream_id, pending.stream_id);
    }
    try std.testing.expect(connection.popPendingRequest() == null);
    try std.testing.expectEqual(@as(usize, 0), connection.pending_requests.items.len);
    try std.testing.expectEqual(@as(usize, 0), connection.pending_request_head);
}

test "HTTP/2 pending request queue skips peer-reset tombstones" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{ .max_pending_accept_reset_streams = 2 },
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.recv_stream_windows.deinit(allocator);
        connection.recv_stream_window_index.deinit(allocator);
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
        connection.push_state.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.response_semantics.deinit(allocator);
        connection.response_semantics_index.deinit(allocator);
        for (connection.pending_requests.items[connection.pending_request_head..]) |*pending| {
            pending.deinit(allocator);
        }
        connection.pending_requests.deinit(allocator);
        connection.deinitPeerMetadata();
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }

    try queueTestPendingRequest(&connection, 1, "/one", allocator);
    try queueTestPendingRequest(&connection, 3, "/three", allocator);
    try queueTestPendingRequest(&connection, 5, "/five", allocator);

    try std.testing.expect(!connection.markPendingRequestReset(3));
    try std.testing.expectEqual(@as(usize, 1), connection.pendingAcceptResetStreamCount());
    try std.testing.expectEqual(@as(usize, 3), connection.pendingRequestCount());

    var first = connection.popPendingRequest() orelse
        return error.TestUnexpectedResult;
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), first.stream_id);
    try std.testing.expectEqual(@as(usize, 1), connection.pendingAcceptResetStreamCount());

    var second = connection.popPendingRequest() orelse
        return error.TestUnexpectedResult;
    defer second.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 5), second.stream_id);
    try std.testing.expectEqual(@as(usize, 0), connection.pendingAcceptResetStreamCount());

    try std.testing.expect(connection.popPendingRequest() == null);
    try std.testing.expectEqual(@as(usize, 0), connection.pending_requests.items.len);
    try std.testing.expectEqual(@as(usize, 0), connection.pending_request_head);
}

test "HTTP/2 pending request reset accounting preserves unrelated queue entries" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{ .max_pending_accept_reset_streams = 4 },
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.recv_stream_windows.deinit(allocator);
        connection.recv_stream_window_index.deinit(allocator);
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
        connection.push_state.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.response_semantics.deinit(allocator);
        connection.response_semantics_index.deinit(allocator);
        for (connection.pending_requests.items[connection.pending_request_head..]) |*pending| {
            pending.deinit(allocator);
        }
        connection.pending_requests.deinit(allocator);
        connection.deinitPeerMetadata();
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }

    try queueTestPendingRequest(&connection, 1, "/one", allocator);
    try queueTestPendingRequest(&connection, 3, "/three", allocator);
    try queueTestPendingRequest(&connection, 5, "/five", allocator);

    try std.testing.expect(!connection.markPendingRequestReset(3));
    try std.testing.expectEqual(@as(usize, 1), connection.pendingAcceptResetStreamCount());
    try std.testing.expect(!connection.markPendingRequestReset(3));
    try std.testing.expectEqual(@as(usize, 1), connection.pendingAcceptResetStreamCount());
    try std.testing.expect(!connection.markPendingRequestReset(99));
    try std.testing.expectEqual(@as(usize, 1), connection.pendingAcceptResetStreamCount());

    for ([_]u31{ 1, 5 }) |expected_stream_id| {
        var pending = connection.popPendingRequest() orelse
            return error.TestUnexpectedResult;
        defer pending.deinit(allocator);
        try std.testing.expectEqual(expected_stream_id, pending.stream_id);
    }
    try std.testing.expect(connection.popPendingRequest() == null);
    try std.testing.expectEqual(@as(usize, 0), connection.pendingAcceptResetStreamCount());
}

test "HTTP/2 pending request reset tombstone reuses consumed slot without allocation" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.recv_stream_windows.deinit(allocator);
        connection.recv_stream_window_index.deinit(allocator);
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
        connection.push_state.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.response_semantics.deinit(allocator);
        connection.response_semantics_index.deinit(allocator);
        for (connection.pending_requests.items[connection.pending_request_head..]) |*pending| {
            pending.deinit(allocator);
        }
        connection.pending_requests.deinit(allocator);
        connection.deinitPeerMetadata();
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }

    try connection.pending_requests.ensureTotalCapacityPrecise(allocator, 4);
    try queueTestPendingRequest(&connection, 1, "/one", allocator);
    try queueTestPendingRequest(&connection, 3, "/three", allocator);
    try queueTestPendingRequest(&connection, 5, "/five", allocator);
    try queueTestPendingRequest(&connection, 7, "/seven", allocator);
    try std.testing.expect(!connection.markPendingRequestReset(3));

    var first = connection.popPendingRequest() orelse
        return error.TestUnexpectedResult;
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), first.stream_id);

    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try queueTestPendingRequest(&connection, 9, "/nine", no_alloc.allocator());
    try std.testing.expect(!no_alloc.has_induced_failure);

    for ([_]u31{ 5, 7, 9 }) |expected_stream_id| {
        var pending = connection.popPendingRequest() orelse
            return error.TestUnexpectedResult;
        defer pending.deinit(allocator);
        try std.testing.expectEqual(expected_stream_id, pending.stream_id);
    }
    try std.testing.expect(connection.popPendingRequest() == null);
    try std.testing.expectEqual(@as(usize, 0), connection.pendingAcceptResetStreamCount());
}

fn queueTestPendingRequest(
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

test "HTTP/2 readRequest skips queued sibling reset and preserves unrelated request" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .max_pending_accept_reset_streams = 4,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var first = try connection.readRequestWithDeadline(.fromNow(
                connection.io,
                .{ .raw = .fromSeconds(2), .clock = .awake },
            ));
            defer first.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(u31, 1), first.stream_id);
            try std.testing.expectEqualStrings("/first", first.path);
            try std.testing.expectEqualStrings("first-body", first.body);

            var second = try connection.readRequestWithDeadline(.fromNow(
                connection.io,
                .{ .raw = .fromSeconds(2), .clock = .awake },
            ));
            defer second.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(u31, 5), second.stream_id);
            try std.testing.expectEqualStrings("/third", second.path);
            try std.testing.expectEqualStrings("", second.body);
            try std.testing.expectEqual(@as(usize, 0), connection.pendingAcceptResetStreamCount());
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
        .max_pending_accept_reset_streams = 4,
    });
    defer client.close();

    try client.writeHeaders(1, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/first" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-length", .value = "10" },
    }, false);
    try client.writeHeaders(3, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/second" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    }, true);
    try client.sendResetStream(3, .cancel);
    try client.writeHeaders(5, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/third" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    }, true);
    try client.writeData(1, "first-body", true);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 readRequestStreaming skips queued sibling reset and preserves unrelated request" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .max_pending_accept_reset_streams = 4,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        first_bytes: usize = 0,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            const SharedState = @This();

            var first = try connection.readRequestStreamingWithDeadline(
                .fromNow(connection.io, .{
                    .raw = .fromSeconds(2),
                    .clock = .awake,
                }),
                shared,
                struct {
                    fn consume(shared_ptr: *SharedState, chunk: []const u8) Error!void {
                        shared_ptr.first_bytes += chunk.len;
                    }
                }.consume,
            );
            defer first.deinit(shared.server.allocator);
            try std.testing.expectEqual(@as(u31, 1), first.stream_id);
            try std.testing.expectEqual(@as(usize, 10), shared.first_bytes);

            var second = try connection.readRequestStreamingWithDeadline(
                .fromNow(connection.io, .{
                    .raw = .fromSeconds(2),
                    .clock = .awake,
                }),
                {},
                struct {
                    fn consume(_: void, _: []const u8) Error!void {}
                }.consume,
            );
            defer second.deinit(shared.server.allocator);
            try std.testing.expectEqual(@as(u31, 5), second.stream_id);
            try std.testing.expectEqualStrings("/third-streaming", second.path);
            try std.testing.expectEqual(@as(usize, 0), connection.pendingAcceptResetStreamCount());
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
        .max_pending_accept_reset_streams = 4,
    });
    defer client.close();

    try client.writeHeaders(1, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/first-streaming" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-length", .value = "10" },
    }, false);
    try client.writeHeaders(3, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/second-streaming" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    }, true);
    try client.sendResetStream(3, .cancel);
    try client.writeHeaders(5, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/third-streaming" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    }, true);
    try client.writeData(1, "first-body", true);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 pending accept reset overflow sends ENHANCE_YOUR_CALM GOAWAY" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .max_pending_accept_reset_streams = 1,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            try std.testing.expectError(
                error.ConnectionGoAway,
                connection.readRequestWithDeadline(.fromNow(
                    connection.io,
                    .{ .raw = .fromSeconds(2), .clock = .awake },
                )),
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
        .max_pending_accept_reset_streams = 1,
    });
    defer client.close();

    try client.writeHeaders(1, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/first-overflow" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-length", .value = "10" },
    }, false);
    try client.writeHeaders(3, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/cancel-one" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    }, true);
    try client.sendResetStream(3, .cancel);
    try client.writeHeaders(5, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/cancel-two" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    }, true);
    try client.sendResetStream(5, .cancel);
    try client.writeData(1, "first-body", true);

    var goaway = try client.readGoAwayWithDeadline(.fromNow(
        client.io,
        .{ .raw = .fromSeconds(2), .clock = .awake },
    ));
    defer goaway.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 5), goaway.goaway.last_stream_id);
    try std.testing.expectEqual(
        http2.ErrorCode.enhance_your_calm,
        goaway.goaway.error_code,
    );
    try std.testing.expectEqualStrings(
        "too_many_resets",
        goaway.goaway.debug_data,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 readRequest queues complete interleaved peer request" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var first = try connection.readRequest();
            defer first.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(u31, 1), first.stream_id);
            try std.testing.expectEqualStrings("/first-interleaved", first.path);
            try std.testing.expectEqualStrings("first-body", first.body);

            var second = try connection.readRequest();
            defer second.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(u31, 3), second.stream_id);
            try std.testing.expectEqualStrings("/second-interleaved", second.path);
            try std.testing.expectEqualStrings("", second.body);
            try std.testing.expectEqual(@as(usize, 0), connection.pending_requests.items.len);
            try std.testing.expectEqual(@as(usize, 0), connection.pending_request_head);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    try client.writeHeaders(1, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/first-interleaved" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-length", .value = "10" },
    }, false);
    try client.writeHeaders(3, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/second-interleaved" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    }, true);
    try client.writeData(1, "first-body", true);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 runtime rejects inbound connection-specific headers" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        saw_expected: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();

            var request = connection.readRequest() catch |err| {
                if (err == error.InvalidHeader) {
                    shared.saw_expected = true;
                    return;
                }
                shared.err = err;
                return;
            };
            request.deinit(shared.server.allocator);
            shared.err = error.InvalidHeader;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    const fields = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/bad-header" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "connection", .value = "x-hop" },
        .{ .name = "x-hop", .value = "secret" },
    };
    try client.writeHeaders(1, &fields, true);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
}

test "HTTP/2 serveOne resets malformed request stream and serves sibling" {
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

    const Context = struct {
        calls: usize = 0,

        fn handle(ctx: *@This(), request: OwnedRequest) Error!ResponseOptions {
            ctx.calls += 1;
            if (!std.mem.eql(u8, request.path, "/good-after-reset")) {
                return error.UnexpectedFrame;
            }
            return .{ .status = 204 };
        }
    };
    const Shared = struct {
        server: *Server,
        context: Context = .{},
        saw_bad_header: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            _ = connection.serveOne(
                Context,
                &shared.context,
                Context.handle,
            ) catch |err| {
                if (err == error.InvalidHeader) {
                    shared.saw_bad_header = true;
                } else {
                    shared.err = err;
                    return;
                }
            };
            _ = connection.serveOne(
                Context,
                &shared.context,
                Context.handle,
            ) catch |err| {
                shared.err = err;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();

    var encoder = http2.Hpack.Encoder{};
    defer encoder.deinit(allocator);
    var bad_block: std.ArrayList(u8) = .empty;
    defer bad_block.deinit(allocator);
    try encoder.encodeBlock(&bad_block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/bad" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = "connection", .value = "close" },
    });
    try writeFrame(allocator, io, client.stream, .headers, flag_end_headers | flag_end_stream, 1, bad_block.items);

    var good_block: std.ArrayList(u8) = .empty;
    defer good_block.deinit(allocator);
    try encoder.encodeBlock(&good_block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/good-after-reset" },
        .{ .name = ":scheme", .value = "http" },
    });
    try writeFrame(allocator, io, client.stream, .headers, flag_end_headers | flag_end_stream, 3, good_block.items);

    var reset = try client.readResetStream();
    defer reset.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), reset.reset.stream_id);
    try std.testing.expectEqual(http2.ErrorCode.protocol_error, reset.reset.error_code);
    var response = try client.readResponse(3, "GET", false, null);
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), response.status);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_bad_header);
    try std.testing.expectEqual(@as(usize, 1), shared.context.calls);
}

test "HTTP/2 serveOne resets content-length mismatch after request DATA" {
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

    const Context = struct {
        fn handle(_: *@This(), _: OwnedRequest) Error!ResponseOptions {
            return error.UnexpectedFrame;
        }
    };
    const Shared = struct {
        server: *Server,
        context: Context = .{},
        saw_expected: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            _ = connection.serveOne(
                Context,
                &shared.context,
                Context.handle,
            ) catch |err| {
                if (err == error.InvalidContentLength) {
                    shared.saw_expected = true;
                    return;
                }
                shared.err = err;
                return;
            };
            shared.err = error.UnexpectedFrame;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
    });
    defer client.close();

    try client.writeHeaders(1, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/short" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = "content-length", .value = "5" },
    }, false);
    try client.writeData(1, "four", true);
    var reset = try client.readResetStream();
    defer reset.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), reset.reset.stream_id);
    try std.testing.expectEqual(http2.ErrorCode.protocol_error, reset.reset.error_code);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
}

test "HTTP/2 high-level writers strip outbound connection-specific headers" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/strip-hop-by-hop", request.path);
            try std.testing.expect(findHeader(request.headers, "connection") == null);
            try std.testing.expect(findHeader(request.headers, "x-hop") == null);
            try std.testing.expect(findHeader(request.headers, "keep-alive") == null);
            try std.testing.expect(findHeader(request.headers, "proxy-connection") == null);
            try std.testing.expect(findHeader(request.headers, "transfer-encoding") == null);
            try std.testing.expect(findHeader(request.headers, "upgrade") == null);
            try std.testing.expect(findHeader(request.headers, "te") == null);
            try std.testing.expectEqualStrings("kept", findHeader(request.headers, "x-end-to-end") orelse return error.MissingPseudoHeader);

            try connection.writeResponse(request.stream_id, .{
                .headers = &.{
                    .{ .name = "connection", .value = "x-response-hop" },
                    .{ .name = "x-response-hop", .value = "secret" },
                    .{ .name = "keep-alive", .value = "timeout=5" },
                    .{ .name = "proxy-connection", .value = "keep-alive" },
                    .{ .name = "transfer-encoding", .value = "chunked" },
                    .{ .name = "upgrade", .value = "websocket" },
                    .{ .name = "te", .value = "gzip" },
                    .{ .name = "x-response-end-to-end", .value = "kept" },
                },
                .body = "ok",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var response = try client.request(.{
        .method = "GET",
        .path = "/strip-hop-by-hop",
        .authority = "localhost",
        .headers = &.{
            .{ .name = "connection", .value = "x-hop" },
            .{ .name = "x-hop", .value = "secret" },
            .{ .name = "keep-alive", .value = "timeout=5" },
            .{ .name = "proxy-connection", .value = "keep-alive" },
            .{ .name = "transfer-encoding", .value = "chunked" },
            .{ .name = "upgrade", .value = "websocket" },
            .{ .name = "te", .value = "gzip" },
            .{ .name = "x-end-to-end", .value = "kept" },
        },
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("ok", response.body);
    try std.testing.expect(findHeader(response.headers, "connection") == null);
    try std.testing.expect(findHeader(response.headers, "x-response-hop") == null);
    try std.testing.expect(findHeader(response.headers, "keep-alive") == null);
    try std.testing.expect(findHeader(response.headers, "proxy-connection") == null);
    try std.testing.expect(findHeader(response.headers, "transfer-encoding") == null);
    try std.testing.expect(findHeader(response.headers, "upgrade") == null);
    try std.testing.expect(findHeader(response.headers, "te") == null);
    try std.testing.expectEqualStrings("kept", findHeader(response.headers, "x-response-end-to-end") orelse return error.MissingPseudoHeader);
}

test "HTTP/2 high-level writer strips a late Connection nomination" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var request_headers: [259]http2.Hpack.HeaderField = undefined;
    for (request_headers[0..256]) |*header| {
        header.* = .{ .name = "connection", .value = "x-decoy" };
    }
    request_headers[256] = .{
        .name = "connection",
        .value = "x-late-hop",
    };
    request_headers[257] = .{
        .name = "x-late-hop",
        .value = "must-not-cross-h2",
    };
    request_headers[258] = .{ .name = "x-kept", .value = "yes" };

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_header_fields = 512,
            .max_header_list_size = 64 * 1024,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest();
            defer request.deinit(self.server.allocator);
            try std.testing.expect(findHeader(
                request.headers,
                "connection",
            ) == null);
            try std.testing.expect(findHeader(
                request.headers,
                "x-late-hop",
            ) == null);
            try std.testing.expectEqualStrings(
                "yes",
                findHeader(request.headers, "x-kept") orelse
                    return error.MissingPseudoHeader,
            );

            var response_headers: [259]http2.Hpack.HeaderField = undefined;
            for (response_headers[0..256]) |*header| {
                header.* = .{
                    .name = "connection",
                    .value = "x-response-decoy",
                };
            }
            response_headers[256] = .{
                .name = "connection",
                .value = "x-response-late",
            };
            response_headers[257] = .{
                .name = "x-response-late",
                .value = "must-not-cross-h2",
            };
            response_headers[258] = .{
                .name = "x-response-kept",
                .value = "yes",
            };
            try connection.writeResponse(request.stream_id, .{
                .headers = &response_headers,
            });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_header_fields = 512,
        .max_header_list_size = 64 * 1024,
    });
    defer client.close();
    var response = try client.request(.{
        .method = "GET",
        .path = "/late-nomination",
        .authority = "localhost",
        .headers = &request_headers,
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expect(findHeader(
        response.headers,
        "connection",
    ) == null);
    try std.testing.expect(findHeader(
        response.headers,
        "x-response-late",
    ) == null);
    try std.testing.expectEqualStrings(
        "yes",
        findHeader(response.headers, "x-response-kept") orelse
            return error.MissingPseudoHeader,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 stripConnectionHeaders compacts nominated hop-by-hop fields" {
    const allocator = std.testing.allocator;
    var headers: std.ArrayList(http2.Hpack.HeaderField) = .empty;
    defer headers.deinit(allocator);
    try headers.appendSlice(allocator, &.{
        .{ .name = "x-keep-a", .value = "a" },
        .{ .name = "Connection", .value = "x-hop-a, x-hop-b" },
        .{ .name = "x-hop-a", .value = "remove" },
        .{ .name = "te", .value = "trailers" },
        .{ .name = "x-hop-b", .value = "remove" },
        .{ .name = "Connection", .value = "x-hop-c" },
        .{ .name = "x-hop-c", .value = "remove" },
        .{ .name = "x-keep-b", .value = "b" },
    });

    try outbound_headers.stripConnectionHeaders(
        allocator,
        &headers,
        .request,
    );
    try std.testing.expectEqual(@as(usize, 3), headers.items.len);
    try std.testing.expectEqualStrings("x-keep-a", headers.items[0].name);
    try std.testing.expectEqualStrings("te", headers.items[1].name);
    try std.testing.expectEqualStrings("x-keep-b", headers.items[2].name);
}

test "HTTP/2 high-level request writer preserves TE trailers" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("trailers", findHeader(request.headers, "te") orelse return error.MissingPseudoHeader);
            try connection.writeResponse(request.stream_id, .{ .body = "ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var response = try client.request(.{
        .method = "GET",
        .path = "/te-trailers",
        .authority = "localhost",
        .headers = &.{.{ .name = "te", .value = "trailers" }},
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings("ok", response.body);
}

test "HTTP/2 runtime rejects invalid wire and outbound header names" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        expected_errors: usize = 0,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();

            while (shared.expected_errors < 3) {
                var request = connection.readRequest() catch |err| {
                    if (err == error.InvalidHeader or err == error.MissingPseudoHeader) {
                        shared.expected_errors += 1;
                        continue;
                    }
                    shared.err = err;
                    return;
                };
                request.deinit(shared.server.allocator);
                shared.err = error.InvalidHeader;
                return;
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    const uppercase = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/uppercase" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "Host", .value = "localhost" },
    };
    try client.writeHeaders(1, &uppercase, true);

    const late_pseudo = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/late-pseudo" },
        .{ .name = "accept", .value = "*/*" },
        .{ .name = ":scheme", .value = "https" },
    };
    try client.writeHeaders(3, &late_pseudo, true);

    const duplicate_pseudo = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/duplicate-pseudo" },
        .{ .name = ":scheme", .value = "https" },
    };
    try client.writeHeaders(5, &duplicate_pseudo, true);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 3), shared.expected_errors);

    try std.testing.expectError(error.InvalidHeader, client.request(.{
        .method = "GET",
        .path = "/bad-response-header",
        .authority = "localhost",
        .headers = &.{.{ .name = "Uppercase", .value = "bad" }},
    }));
    try std.testing.expectError(error.InvalidHeader, client.request(.{
        .method = "GET",
        .path = "/bad-request-pseudo",
        .authority = "localhost",
        .headers = &.{.{ .name = ":status", .value = "200" }},
    }));
}

test "HTTP/2 async std.Io server handles concurrent h2c clients" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        pub fn handle(_: *@This(), request: OwnedRequest) Error!ResponseOptions {
            if (!std.mem.eql(u8, request.method, "POST")) return error.UnexpectedFrame;
            if (std.mem.eql(u8, request.path, "/one")) {
                return .{ .status = 200, .body = "h2-one" };
            }
            if (std.mem.eql(u8, request.path, "/two")) {
                return .{ .status = 200, .body = "h2-two" };
            }
            return .{ .status = 404, .body = "missing" };
        }
    };

    const Shared = struct {
        server: *Server,
        context: Context = .{},
        result: ?ConcurrentServeResult = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.result = shared.server.serveConcurrent(Context, &shared.context, Context.handle, 2) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const ClientTask = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        path: []const u8,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(task: *@This()) void {
            runFallible(task) catch |err| {
                task.err = err;
            };
        }

        fn runFallible(task: *@This()) !void {
            var client = try Client.connect(task.allocator, task.io, task.address, .{
                .max_frame_payload = 4096,
                .max_body_bytes = 4096,
            });
            defer client.close();

            var response = try client.request(.{
                .method = "POST",
                .path = task.path,
                .authority = "localhost",
                .body = "hello",
            });
            defer response.deinit(task.allocator);
            try std.testing.expectEqual(@as(u16, 200), response.status);
            try std.testing.expectEqualStrings(task.expected, response.body);
        }
    };

    var clients = [_]ClientTask{
        .{ .allocator = allocator, .io = io, .address = server.address(), .path = "/one", .expected = "h2-one" },
        .{ .allocator = allocator, .io = io, .address = server.address(), .path = "/two", .expected = "h2-two" },
    };
    const client_one = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[0]});
    const client_two = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[1]});

    client_one.join();
    client_two.join();
    server_thread.join();
    defer if (shared.result) |*result| result.deinit();

    if (clients[0].err) |err| return err;
    if (clients[1].err) |err| return err;
    if (shared.err) |err| return err;
    const result = shared.result.?;
    if (result.firstError()) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), result.successCount());
}

test "HTTP/2 serveConcurrent converts handler informational status per connection" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        fn handle(_: *@This(), request: OwnedRequest) Error!ResponseOptions {
            if (std.mem.eql(u8, request.path, "/invalid-final")) {
                return .{ .status = 103 };
            }
            return .{ .status = 204 };
        }
    };
    const Shared = struct {
        server: *Server,
        context: Context = .{},
        result: ?ConcurrentServeResult = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.result = shared.server.serveConcurrent(
                Context,
                &shared.context,
                Context.handle,
                2,
            ) catch |err| {
                shared.err = err;
                return;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const ClientTask = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        path: []const u8,
        expected_status: u16,
        err: ?anyerror = null,

        fn run(task: *@This()) void {
            task.runFallible() catch |err| {
                task.err = err;
            };
        }

        fn runFallible(task: *@This()) !void {
            var client = try Client.connect(task.allocator, task.io, task.address, .{
                .max_frame_payload = 4096,
                .max_body_bytes = 4096,
            });
            defer client.close();
            var response = try client.request(.{
                .path = task.path,
                .authority = "localhost",
            });
            defer response.deinit(task.allocator);
            try std.testing.expectEqual(task.expected_status, response.status);
            try std.testing.expectEqualStrings("", response.body);
        }
    };
    var clients = [_]ClientTask{
        .{
            .allocator = allocator,
            .io = io,
            .address = server.address(),
            .path = "/invalid-final",
            .expected_status = 500,
        },
        .{
            .allocator = allocator,
            .io = io,
            .address = server.address(),
            .path = "/sibling",
            .expected_status = 204,
        },
    };
    const invalid_client = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[0]});
    const sibling_client = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[1]});

    invalid_client.join();
    sibling_client.join();
    server_thread.join();
    defer if (shared.result) |*result| result.deinit();

    if (clients[0].err) |err| return err;
    if (clients[1].err) |err| return err;
    if (shared.err) |err| return err;
    const result = shared.result.?;
    try std.testing.expectEqual(@as(usize, 1), result.successCount());
    try std.testing.expectEqual(error.InvalidStatus, result.firstError().?);
    var invalid_count: usize = 0;
    for (result.errors) |result_error| {
        if (result_error) |err| {
            try std.testing.expectEqual(error.InvalidStatus, err);
            invalid_count += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), invalid_count);
}

test "HTTP/2 runtime validates request content-length" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        saw_expected: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();

            var request = connection.readRequest() catch |err| {
                if (err == error.InvalidContentLength) {
                    shared.saw_expected = true;
                    return;
                }
                shared.err = err;
                return;
            };
            request.deinit(shared.server.allocator);
            shared.err = error.InvalidContentLength;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    const fields = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/bad-length" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-length", .value = "+5" },
    };
    try client.writeHeaders(1, &fields, false);
    try client.writeData(1, "ping", true);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
}

test "HTTP/2 request writer defaults content-length for known body" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/default-request-length", request.path);
            try std.testing.expectEqualStrings("ping", request.body);
            try std.testing.expectEqualStrings("4", findHeader(request.headers, "content-length") orelse return error.MissingPseudoHeader);
            try connection.writeResponse(request.stream_id, .{ .body = "ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var response = try client.request(.{
        .method = "POST",
        .path = "/default-request-length",
        .authority = "localhost",
        .body = "ping",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("ok", response.body);
}

test "HTTP/2 request writer defaults zero content-length for payload methods" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var post = try connection.readRequest();
            defer post.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/default-empty-post-length", post.path);
            try std.testing.expectEqualStrings("", post.body);
            try std.testing.expectEqualStrings("0", findHeader(post.headers, "content-length") orelse return error.MissingPseudoHeader);
            try connection.writeResponse(post.stream_id, .{ .body = "post" });

            var get = try connection.readRequest();
            defer get.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/default-empty-get-length", get.path);
            try std.testing.expectEqualStrings("", get.body);
            try std.testing.expect(findHeader(get.headers, "content-length") == null);
            try connection.writeResponse(get.stream_id, .{ .body = "get" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var post_response = try client.request(.{
        .method = "POST",
        .path = "/default-empty-post-length",
        .authority = "localhost",
    });
    defer post_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), post_response.status);
    try std.testing.expectEqualStrings("post", post_response.body);

    var get_response = try client.request(.{
        .method = "GET",
        .path = "/default-empty-get-length",
        .authority = "localhost",
    });
    defer get_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), get_response.status);
    try std.testing.expectEqualStrings("get", get_response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 runtime validates request content-length before accepting trailers" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        saw_expected: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();

            var request = connection.readRequest() catch |err| {
                if (err == error.InvalidContentLength) {
                    shared.saw_expected = true;
                    return;
                }
                shared.err = err;
                return;
            };
            request.deinit(shared.server.allocator);
            shared.err = error.InvalidContentLength;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    const fields = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/bad-length-trailers" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-length", .value = "5" },
    };
    try client.writeHeaders(1, &fields, false);
    try client.writeData(1, "ping", false);
    try client.writeHeaders(1, &.{.{ .name = "request-checksum", .value = "ok" }}, true);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
}

test "HTTP/2 runtime validates response content-length and method body rules" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();

            var mismatch = connection.readRequest() catch |err| {
                shared.err = err;
                return;
            };
            defer mismatch.deinit(shared.server.allocator);
            connection.writeHeaders(mismatch.stream_id, &.{
                .{ .name = ":status", .value = "200" },
                .{ .name = "content-length", .value = "5" },
            }, false) catch |err| {
                shared.err = err;
                return;
            };
            connection.writeData(mismatch.stream_id, "pong", true) catch |err| {
                shared.err = err;
                return;
            };

            var head = connection.readRequest() catch |err| {
                shared.err = err;
                return;
            };
            defer head.deinit(shared.server.allocator);
            connection.writeResponse(head.stream_id, .{
                .status = 200,
                .headers = &.{.{ .name = "content-length", .value = "5" }},
            }) catch |err| {
                shared.err = err;
                return;
            };

            var no_content = connection.readRequest() catch |err| {
                shared.err = err;
                return;
            };
            defer no_content.deinit(shared.server.allocator);
            connection.writeHeaders(no_content.stream_id, &.{
                .{ .name = ":status", .value = "204" },
                .{ .name = "content-length", .value = "0" },
            }, true) catch |err| {
                shared.err = err;
                return;
            };

            var connect = connection.readRequest() catch |err| {
                shared.err = err;
                return;
            };
            defer connect.deinit(shared.server.allocator);
            connection.writeResponse(connect.stream_id, .{
                .status = 200,
            }) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    try std.testing.expectError(error.InvalidContentLength, client.request(.{
        .method = "GET",
        .path = "/mismatch",
        .authority = "localhost",
    }));

    var head_response = try client.request(.{
        .method = "HEAD",
        .path = "/head",
        .authority = "localhost",
    });
    defer head_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), head_response.status);
    try std.testing.expectEqualStrings("", head_response.body);

    try std.testing.expectError(error.InvalidContentLength, client.request(.{
        .method = "GET",
        .path = "/no-content-cl",
        .authority = "localhost",
    }));

    var connect_response = try client.request(.{
        .method = "CONNECT",
        .path = "example.com:443",
        .authority = "example.com:443",
    });
    defer connect_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), connect_response.status);
    try std.testing.expectEqualStrings("", connect_response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 client consumes framed 205 content and reuses connection" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var first = try connection.readRequest();
            defer first.deinit(server_ptr.allocator);
            // Bypass the high-level sender to model a non-conforming peer.
            // A recipient still follows HTTP/2 framing and consumes DATA up
            // to END_STREAM instead of treating 205 like 204 or 304.
            try connection.writeHeaders(first.stream_id, &.{
                .{ .name = ":status", .value = "205" },
                .{ .name = "content-length", .value = "4" },
            }, false);
            try connection.writeData(first.stream_id, "body", true);
            connection.releasePeerStream(first.stream_id);

            var second = try connection.readRequest();
            defer second.deinit(server_ptr.allocator);
            try connection.writeResponse(second.stream_id, .{
                .body = "after",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var reset = try client.request(.{
        .path = "/reset",
        .authority = "localhost",
    });
    defer reset.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 205), reset.status);
    try std.testing.expectEqualStrings("body", reset.body);

    var after = try client.request(.{
        .path = "/after",
        .authority = "localhost",
    });
    defer after.deinit(allocator);
    try std.testing.expectEqualStrings("after", after.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 response writer defaults content-length for known body" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,
        observed_content_length: ?[]u8 = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(shared.server.allocator);
            try std.testing.expectEqualStrings("/default-response-length", request.path);
            try connection.writeResponse(request.stream_id, .{
                .body = "known-body",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var response = try client.request(.{
        .method = "GET",
        .path = "/default-response-length",
        .authority = "localhost",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("known-body", response.body);
    try std.testing.expectEqualStrings("10", findHeader(response.headers, "content-length") orelse return error.MissingPseudoHeader);
    const date = findHeader(response.headers, "date") orelse
        return error.MissingPseudoHeader;
    try std.testing.expectEqual(@as(usize, http_date.value_len), date.len);
    try std.testing.expectEqualStrings("GMT", date[26..]);
}

test "HTTP/2 server preserves explicit Date and can disable automatic Date" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var first = try connection.readRequest();
            defer first.deinit(self.server.allocator);
            try connection.writeResponse(first.stream_id, .{
                .headers = &.{.{
                    .name = "date",
                    .value = "Sun, 06 Nov 1994 08:49:37 GMT",
                }},
            });
            connection.limits.auto_date_header = false;
            var second = try connection.readRequest();
            defer second.deinit(self.server.allocator);
            try connection.writeResponse(second.stream_id, .{});
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    var explicit = try client.request(.{
        .path = "/explicit-date",
        .authority = "localhost",
    });
    defer explicit.deinit(allocator);
    try std.testing.expectEqualStrings(
        "Sun, 06 Nov 1994 08:49:37 GMT",
        findHeader(explicit.headers, "date").?,
    );
    var disabled = try client.request(.{
        .path = "/disabled-date",
        .authority = "localhost",
    });
    defer disabled.deinit(allocator);
    try std.testing.expect(findHeader(disabled.headers, "date") == null);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 automatic Date appends without allocation after HPACK warmup" {
    const allocator = std.testing.allocator;
    var encoder = http2.Hpack.Encoder{};
    defer encoder.deinit(allocator);
    const date = "Sun, 06 Nov 1994 08:49:37 GMT".*;
    var fields_storage: [2]http2.Hpack.HeaderField = undefined;
    var fields: std.ArrayList(http2.Hpack.HeaderField) =
        .initBuffer(&fields_storage);

    fields.appendAssumeCapacity(.{ .name = ":status", .value = "200" });
    appendAutomaticDateHeaderValue(&fields, &date);
    _ = try encoder.encodeBlockRetained(allocator, fields.items);

    fields.clearRetainingCapacity();
    fields.appendAssumeCapacity(.{ .name = ":status", .value = "200" });
    appendAutomaticDateHeaderValue(&fields, &date);
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    _ = try encoder.encodeBlockRetained(no_alloc.allocator(), fields.items);
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 2), fields.items.len);
    try std.testing.expectEqualStrings("date", fields.items[1].name);
    try std.testing.expectEqualStrings(&date, fields.items[1].value);
}

test "HTTP/2 batch Date preflight reports only missing retained fields" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.response_semantics.deinit(std.testing.allocator);
        connection.response_semantics_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try std.testing.expect(try connection.validateResponseBatchMember(
        1,
        .{},
        true,
    ));
    try std.testing.expect(!(try connection.validateResponseBatchMember(
        1,
        .{ .headers = &.{.{
            .name = "date",
            .value = "Sun, 06 Nov 1994 08:49:37 GMT",
        }} },
        true,
    )));
    // A field nominated by Connection is removed before this decision.
    try std.testing.expect(try connection.validateResponseBatchMember(
        1,
        .{ .headers = &.{
            .{ .name = "connection", .value = "date" },
            .{
                .name = "date",
                .value = "Sun, 06 Nov 1994 08:49:37 GMT",
            },
        } },
        true,
    ));

    connection.limits.auto_date_header = false;
    try std.testing.expect(!(try connection.validateResponseBatchMember(
        1,
        .{},
        true,
    )));
}

test "HTTP/2 client accepts zero Content-Length on successful CONNECT tunnel" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("CONNECT", request.method);

            // Hyper accepts a zero Content-Length from peers on a successful
            // CONNECT response even though the stream switches to tunnel mode
            // after the 2xx HEADERS.  Non-zero lengths remain rejected below.
            try connection.writeHeaders(request.stream_id, &.{
                .{ .name = ":status", .value = "200" },
                .{ .name = "content-length", .value = "0" },
            }, false);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var response = try client.openConnectTunnel(.{
        .method = "CONNECT",
        .authority = "example.com:443",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("0", findHeader(response.headers, "content-length") orelse return error.MissingPseudoHeader);
}

test "HTTP/2 CONNECT tunnel skips valid informational responses" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("CONNECT", request.method);

            try connection.writeExtendedConnectResponse(request.stream_id, 103, &.{
                .{ .name = "link", .value = "</proxy-hint>; rel=preload" },
            }, false);
            try connection.writeExtendedConnectResponse(request.stream_id, 200, &.{}, false);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var response = try client.openConnectTunnel(.{
        .method = "CONNECT",
        .authority = "example.com:443",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 200), response.status);
    const date = findHeader(response.headers, "date") orelse
        return error.MissingPseudoHeader;
    try std.testing.expectEqual(@as(usize, http_date.value_len), date.len);
    try std.testing.expectEqualStrings("GMT", date[26..]);
}

test "HTTP/2 CONNECT informational response omits automatic Date" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .enable_connect_protocol = true,
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readExtendedConnectRequest(
                "websocket",
            );
            defer request.deinit(self.server.allocator);
            try connection.writeExtendedConnectResponse(
                request.stream_id,
                103,
                &.{.{
                    .name = "link",
                    .value = "</proxy-hint>; rel=preload",
                }},
                false,
            );
            try connection.writeExtendedConnectResponse(
                request.stream_id,
                200,
                &.{},
                false,
            );
        }
    };

    const HeadReader = struct {
        fn read(
            connection: *Connection,
            decoder: *http2.Hpack.Decoder,
        ) ![]http2.Hpack.HeaderField {
            while (true) {
                var frame = try connection.readOwnedFrame();
                defer frame.deinit(connection.allocator);
                if (try connection.handleConnectionFrame(frame.frame)) {
                    continue;
                }
                if (frame.frame.header.frame_type != .headers) {
                    return error.UnexpectedFrame;
                }
                if ((frame.frame.header.flags & flag_end_headers) == 0) {
                    return error.UnexpectedFrame;
                }
                const payload = try http2.HeadersPayload.parse(frame.frame);
                return decoder.decodeBlockOwnedWithLimit(
                    connection.allocator,
                    payload.header_block,
                    connection.limits.max_header_fields,
                    connection.limits.max_header_list_size,
                );
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    try std.testing.expect(client.peerExtendedConnectEnabled());
    const stream_id = try client.reserveNextClientStreamId();
    try client.writeHeaders(stream_id, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/chat" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = ":protocol", .value = "websocket" },
    }, false);

    var decoder: http2.Hpack.Decoder = .{};
    defer decoder.deinit(allocator);
    const informational = try HeadReader.read(&client, &decoder);
    defer freeHeaders(allocator, informational);
    try std.testing.expectEqualStrings(
        "103",
        findHeader(informational, ":status").?,
    );
    try std.testing.expect(findHeader(informational, "date") == null);

    const final = try HeadReader.read(&client, &decoder);
    defer freeHeaders(allocator, final);
    try std.testing.expectEqualStrings(
        "200",
        findHeader(final, ":status").?,
    );
    const date = findHeader(final, "date") orelse
        return error.MissingPseudoHeader;
    try std.testing.expectEqual(@as(usize, http_date.value_len), date.len);
    try std.testing.expectEqualStrings("GMT", date[26..]);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 CONNECT tunnel rejects content-length on informational response" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("CONNECT", request.method);

            // Raw HEADERS emulate an invalid peer; the high-level writer rejects
            // this field before it can hit the wire.
            try connection.writeHeaders(request.stream_id, &.{
                .{ .name = ":status", .value = "103" },
                .{ .name = "content-length", .value = "0" },
            }, false);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    try std.testing.expectError(error.InvalidContentLength, client.openConnectTunnel(.{
        .method = "CONNECT",
        .authority = "example.com:443",
    }));

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 runtime accepts multipart traditional CONNECT DATA tunnel" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("CONNECT", request.method);
            try std.testing.expectEqualStrings("example.com:443", request.authority orelse "");

            var tunnel = try connection.acceptConnectTunnel(request, &.{
                .{ .name = "content-length", .value = "0" },
            });
            var inbound = try tunnel.read();
            defer inbound.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("client tunnel bytes", inbound.data);
            try std.testing.expect(!inbound.end_stream);

            try tunnel.writeParts("server tunnel ", "bytes", true);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var response = try client.openConnectTunnel(.{
        .method = "CONNECT",
        .authority = "example.com:443",
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expect(findHeader(response.headers, "content-length") == null);
    try std.testing.expectEqual(
        @as(usize, http_date.value_len),
        findHeader(response.headers, "date").?.len,
    );

    var tunnel = response.tunnel;
    try tunnel.writeParts("client ", "tunnel bytes", false);
    var inbound = try tunnel.read();
    defer inbound.deinit(allocator);
    try std.testing.expectEqualStrings("server tunnel bytes", inbound.data);
    try std.testing.expect(inbound.end_stream);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 tunnel preserves a sibling response for its owner" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();

            var connect_request = try connection.readRequest();
            defer connect_request.deinit(self.server.allocator);
            var tunnel = try connection.acceptConnectTunnel(
                connect_request,
                &.{},
            );

            var sibling_request = try connection.readRequest();
            defer sibling_request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "/sibling",
                sibling_request.path,
            );
            try connection.writeResponse(sibling_request.stream_id, .{
                .body = "sibling response",
                .request_method = sibling_request.method,
            });
            try tunnel.write("tunnel response", true);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    var connect_response = try client.openConnectTunnel(.{
        .method = "CONNECT",
        .authority = "example.com:443",
    });
    defer connect_response.deinit(allocator);
    var sibling = try client.startRequest(.{
        .path = "/sibling",
        .authority = "localhost",
        .body_length = 0,
    });
    defer sibling.deinit();
    try sibling.finish();

    try std.testing.expectError(
        error.ResponseAvailable,
        connect_response.tunnel.readWithDeadline(.fromNow(
            io,
            .{ .raw = .fromSeconds(1), .clock = .awake },
        )),
    );
    var sibling_response = try sibling.readResponse();
    defer sibling_response.deinit(allocator);
    try std.testing.expectEqualStrings(
        "sibling response",
        sibling_response.body,
    );

    var tunnel_data = try connect_response.tunnel.readWithDeadline(.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    ));
    defer tunnel_data.deinit(allocator);
    try std.testing.expectEqualStrings("tunnel response", tunnel_data.data);
    try std.testing.expect(tunnel_data.end_stream);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 tunnel releases concurrency only after both halves close" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .max_concurrent_streams = 1,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            try std.testing.expectEqual(
                @as(?u32, null),
                connection.peerMaxConcurrentStreams(),
            );
            try std.testing.expectEqual(
                @as(?u32, null),
                connection.availableLocalStreamCapacity(),
            );
            try std.testing.expectEqual(
                @as(usize, 0),
                connection.activePeerStreamCount(),
            );

            var first_request = try connection.readRequest();
            defer first_request.deinit(server_ptr.allocator);
            try std.testing.expectEqual(
                @as(usize, 1),
                connection.activePeerStreamCount(),
            );
            var first = try connection.acceptConnectTunnel(
                first_request,
                &.{},
            );
            try first.write("server half close", true);
            try std.testing.expectEqual(
                @as(usize, 1),
                connection.activePeerStreamCount(),
            );
            try std.testing.expectError(
                error.FlowControlViolation,
                connection.reservePeerStream(3),
            );
            try std.testing.expectError(
                error.ConnectionClosed,
                first.write("after end", false),
            );
            var first_end = try first.read();
            defer first_end.deinit(server_ptr.allocator);
            try std.testing.expect(first_end.end_stream);
            try std.testing.expectEqual(
                @as(usize, 0),
                connection.activePeerStreamCount(),
            );
            try std.testing.expect(
                connection.send_stream_window_index.get(first.stream_id) == null,
            );
            try std.testing.expect(
                connection.recv_stream_window_index.get(first.stream_id) == null,
            );

            var second_request = try connection.readRequest();
            defer second_request.deinit(server_ptr.allocator);
            var second = try connection.acceptConnectTunnel(
                second_request,
                &.{},
            );
            var writer = try second.beginWriteSequence();
            try writer.write("server writer close", true);
            try std.testing.expectError(
                error.ConnectionClosed,
                writer.write("after end", false),
            );
            var second_end = try second.read();
            defer second_end.deinit(server_ptr.allocator);
            try std.testing.expect(second_end.end_stream);
            try std.testing.expectEqual(
                @as(usize, 0),
                connection.activePeerStreamCount(),
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    try std.testing.expectEqual(
        @as(?u32, 1),
        client.peerMaxConcurrentStreams(),
    );
    try std.testing.expectEqual(
        @as(?u32, 1),
        client.availableLocalStreamCapacity(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.activeLocalStreamCount(),
    );
    try std.testing.expect(!client.peerExtendedConnectEnabled());

    var first_response = try client.openConnectTunnel(.{
        .method = "CONNECT",
        .authority = "example.com:443",
    });
    defer first_response.deinit(allocator);
    var first = first_response.tunnel;
    var first_data = try first.read();
    defer first_data.deinit(allocator);
    try std.testing.expectEqualStrings("server half close", first_data.data);
    try std.testing.expect(first_data.end_stream);
    try std.testing.expectEqual(
        @as(usize, 1),
        client.activeLocalStreamCount(),
    );
    try std.testing.expectEqual(
        @as(?u32, 0),
        client.availableLocalStreamCapacity(),
    );
    try std.testing.expectError(
        error.FlowControlBlocked,
        client.openConnectTunnel(.{
            .method = "CONNECT",
            .authority = "example.com:443",
        }),
    );
    try first.closeWrite();
    try std.testing.expectError(error.ConnectionClosed, first.closeWrite());
    try std.testing.expectEqual(
        @as(usize, 0),
        client.activeLocalStreamCount(),
    );
    try std.testing.expectEqual(
        @as(?u32, 1),
        client.availableLocalStreamCapacity(),
    );
    try std.testing.expect(
        client.send_stream_window_index.get(first.stream_id) == null,
    );
    try std.testing.expect(
        client.recv_stream_window_index.get(first.stream_id) == null,
    );

    var second_response = try client.openConnectTunnel(.{
        .method = "CONNECT",
        .authority = "example.com:443",
    });
    defer second_response.deinit(allocator);
    var second = second_response.tunnel;
    var writer = try second.beginWriteSequence();
    try writer.write("client writer close", true);
    try std.testing.expectError(
        error.ConnectionClosed,
        writer.write("after end", false),
    );
    var second_data = try second.read();
    defer second_data.deinit(allocator);
    try std.testing.expectEqualStrings(
        "server writer close",
        second_data.data,
    );
    try std.testing.expect(second_data.end_stream);
    try std.testing.expectEqual(
        @as(usize, 0),
        client.activeLocalStreamCount(),
    );
    try std.testing.expectEqual(
        @as(?u32, 1),
        client.availableLocalStreamCapacity(),
    );
    try std.testing.expect(client.isReusable());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 writers reject status-forbidden response bodies" {
    try std.testing.expectError(error.InvalidContentLength, validateResponseBodyForStatus(204, &.{}, "body", &.{}));
    try std.testing.expectError(error.InvalidContentLength, validateResponseBodyForStatus(204, &.{.{ .name = "content-length", .value = "0" }}, "", &.{}));
    try validateResponseBodyForStatus(304, &.{.{ .name = "content-length", .value = "123" }}, "", &.{});
    try std.testing.expectError(error.InvalidContentLength, validateResponseBodyForStatus(304, &.{}, "body", &.{}));
    try std.testing.expectError(error.InvalidContentLength, validateResponseBodyForStatus(103, &.{.{ .name = "content-length", .value = "0" }}, "", &.{}));
    // Receive validation follows stream framing for 205; only outgoing
    // validation enforces the RFC 9110 server requirement.
    try validateResponseBodyForStatus(205, &.{.{ .name = "content-length", .value = "4" }}, "body", &.{});
    try std.testing.expectError(error.InvalidContentLength, validateOutgoingResponseBodyForStatus(205, &.{}, "body", &.{}));
    try std.testing.expectError(error.InvalidContentLength, validateOutgoingResponseBodyForStatus(205, &.{.{ .name = "content-length", .value = "1" }}, "", &.{}));
    try validateOutgoingResponseBodyForStatus(205, &.{.{ .name = "content-length", .value = "0" }}, "", &.{.{ .name = "x-checksum", .value = "ok" }});

    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }
    try connection.reservePeerStream(1);
    try std.testing.expectError(error.InvalidContentLength, connection.writeResponse(1, .{
        .status = 204,
        .body = "body",
    }));
    try std.testing.expectError(error.InvalidContentLength, connection.writeResponse(1, .{
        .status = 205,
        .body = "body",
    }));
    try std.testing.expectError(error.InvalidContentLength, connection.writeResponse(1, .{
        .status = 200,
        .headers = &.{.{ .name = "content-length", .value = "5" }},
        .body = "pong",
    }));
    try std.testing.expectError(error.InvalidContentLength, connection.writeResponse(1, .{
        .status = 200,
        .headers = &.{.{ .name = "content-length", .value = "5" }},
    }));
    try std.testing.expectError(error.InvalidStatus, connection.writeResponse(1, .{
        .status = 103,
    }));
    try std.testing.expectError(error.InvalidStatus, connection.writeInformationalResponse(1, 200, &.{}));
    try std.testing.expectError(error.InvalidContentLength, connection.writeInformationalResponse(1, 103, &.{
        .{ .name = "content-length", .value = "0" },
    }));
    try std.testing.expectError(error.InvalidContentLength, connection.writeExtendedConnectResponse(1, 103, &.{
        .{ .name = "content-length", .value = "0" },
    }, false));
    try std.testing.expectError(error.InvalidContentLength, connection.writeExtendedConnectResponse(1, 200, &.{
        .{ .name = "content-length", .value = "1" },
    }, false));

    var connect_headers: std.ArrayList(http2.Hpack.HeaderField) = .empty;
    defer connect_headers.deinit(std.testing.allocator);
    try connect_headers.appendSlice(std.testing.allocator, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "0" },
        .{ .name = "content-length", .value = "0" },
        .{ .name = "x-ok", .value = "kept" },
    });
    try stripSuccessfulConnectContentLength(&connect_headers);
    try std.testing.expect(findHeader(connect_headers.items, "content-length") == null);
    try std.testing.expectEqualStrings("kept", findHeader(connect_headers.items, "x-ok") orelse return error.MissingPseudoHeader);
}

test "HTTP/2 CONNECT header assembly is stack-first with exact fallback" {
    const allocator = std.testing.allocator;
    var stack: [16]http2.Hpack.HeaderField = undefined;

    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    const common = try stackFirstHeaderFieldBuffer(
        no_alloc.allocator(),
        &stack,
        stack.len,
    );
    defer freeStackFirstHeaderFieldBuffer(
        no_alloc.allocator(),
        &stack,
        common,
    );
    try std.testing.expectEqual(stack[0..].ptr, common.ptr);
    try std.testing.expect(!no_alloc.has_induced_failure);

    try std.testing.expectError(
        error.OutOfMemory,
        stackFirstHeaderFieldBuffer(
            no_alloc.allocator(),
            &stack,
            stack.len + 1,
        ),
    );
    try std.testing.expect(no_alloc.has_induced_failure);

    const overflow = try stackFirstHeaderFieldBuffer(
        allocator,
        &stack,
        stack.len + 1,
    );
    defer freeStackFirstHeaderFieldBuffer(
        allocator,
        &stack,
        overflow,
    );
    try std.testing.expect(overflow.ptr != stack[0..].ptr);
    try std.testing.expectEqual(stack.len + 1, overflow.len);
}

test "HTTP/2 runtime supports RFC 8441 extended CONNECT" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096, .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();

            var request = connection.readRequest() catch |err| {
                shared.err = err;
                return;
            };
            defer request.deinit(shared.server.allocator);
            std.testing.expectEqualStrings("CONNECT", request.method) catch |err| {
                shared.err = err;
                return;
            };
            std.testing.expectEqualStrings("websocket", request.protocol orelse "") catch |err| {
                shared.err = err;
                return;
            };
            std.testing.expectEqualStrings("/chat", request.path) catch |err| {
                shared.err = err;
                return;
            };
            std.testing.expectEqualStrings("http", request.scheme) catch |err| {
                shared.err = err;
                return;
            };
            std.testing.expectEqualStrings("example.com", request.authority orelse "") catch |err| {
                shared.err = err;
                return;
            };
            std.testing.expectEqualStrings("client bytes", request.body) catch |err| {
                shared.err = err;
                return;
            };

            connection.writeResponse(request.stream_id, .{
                .status = 200,
                .body = "server bytes",
            }) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    try std.testing.expect(client.peerExtendedConnectEnabled());

    var response = try client.request(.{
        .method = "CONNECT",
        .path = "/chat",
        .authority = "example.com",
        .protocol = "websocket",
        .body = "client bytes",
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("server bytes", response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 extended CONNECT deadline preserves one response budget" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        io: std.Io,
        request_received: std.Io.Event = .unset,
        send_response: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.request_received.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readExtendedConnectRequest(
                "websocket",
            );
            defer request.deinit(self.server.allocator);
            self.request_received.set(self.io);
            try self.send_response.wait(self.io);
            try connection.rejectExtendedConnect(
                request.stream_id,
                408,
                &.{},
            );
        }
    };

    var shared = Shared{ .server = &server, .io = io };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.send_response.set(io);
        server_thread.join();
    };

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();
    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromMilliseconds(120), .clock = .awake },
    );
    const Result = ResponseTimeoutError!ExtendedConnectResponse;
    const Wake = union(enum) {
        client: Result,
        request: std.Io.Cancelable!void,
    };
    var wake_buffer: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &wake_buffer);
    defer while (select.cancel()) |wake| switch (wake) {
        .client => |result| if (result) |response_value| {
            var response = response_value;
            response.deinit(allocator);
        } else |_| {},
        .request => {},
    };
    select.async(
        .client,
        Connection.openExtendedConnectWithDeadline,
        .{ &client, RequestOptions{
            .method = "CONNECT",
            .path = "/deadline",
            .authority = "localhost",
            .protocol = "websocket",
        }, deadline },
    );
    select.async(
        .request,
        std.Io.Event.wait,
        .{ &shared.request_received, io },
    );
    switch (try select.await()) {
        .client => |result| {
            if (result) |response_value| {
                var response = response_value;
                response.deinit(allocator);
                return error.TestUnexpectedResult;
            } else |err| return err;
        },
        .request => |result| try result,
    }

    const remaining = deadline.durationFromNow(io).raw.nanoseconds;
    if (remaining > 0) {
        try std.Io.sleep(
            io,
            .{ .nanoseconds = remaining + 10 * std.time.ns_per_ms },
            .awake,
        );
    }
    shared.send_response.set(io);
    try std.testing.expectError(
        error.Timeout,
        switch (try select.await()) {
            .client => |result| result,
            .request => return error.TestUnexpectedResult,
        },
    );
    try std.testing.expect(!client.isReusable());

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 extended CONNECT deadline validates before stream mutation" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
        .default_scheme = "http",
        .peer_enable_connect_protocol = true,
    };
    defer {
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.priority_state.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    connection.io = threaded.io();

    try std.testing.expectError(
        error.Timeout,
        connection.openExtendedConnectWithDeadline(
            .{
                .method = "CONNECT",
                .path = "/",
                .authority = "localhost",
                .protocol = "websocket",
            },
            .fromNow(
                connection.io,
                .{ .raw = .fromSeconds(1), .clock = .real },
            ),
        ),
    );
    try std.testing.expectEqual(@as(u31, 1), connection.next_client_stream_id);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.active_local_streams.items.len,
    );
}

test "HTTP/2 extended CONNECT requires peer opt-in" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
        .default_scheme = "http",
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try std.testing.expectError(error.ExtendedConnectDisabled, connection.request(.{
        .method = "CONNECT",
        .path = "/chat",
        .authority = "example.com",
        .protocol = "websocket",
    }));

    const invalid_protocol_method = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/bad" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":protocol", .value = "websocket" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&invalid_protocol_method, .request));

    const lowercase_extended_connect = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "connect" },
        .{ .name = ":path", .value = "/bad" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&lowercase_extended_connect, .request));

    const empty_protocol = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":path", .value = "/bad" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":protocol", .value = "" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&empty_protocol, .request));

    const invalid_protocol_token = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":path", .value = "/bad-protocol" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":protocol", .value = "web socket" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&invalid_protocol_token, .request));

    const missing_extended_authority = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":path", .value = "/chat" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":protocol", .value = "websocket" },
    };
    try std.testing.expectError(error.MissingPseudoHeader, validateHeaderBlock(&missing_extended_authority, .request));

    const extended_host_fallback = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":path", .value = "/chat" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = "host", .value = "example.com" },
    };
    try validateHeaderBlock(&extended_host_fallback, .request);
}

test "HTTP/2 padded DATA charges full frame payload to receive windows" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{ .initial_window_size = 4 },
        .recv_connection_window = .{ .value = 5 },
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    const padded_payload = [_]u8{ 2, 'o', 'k', 0, 0 };
    const padded_frame = http2.Frame{
        .header = .{
            .length = padded_payload.len,
            .frame_type = .data,
            .flags = 0x8, // PADDED
            .stream_id = 1,
        },
        .payload = &padded_payload,
    };

    try std.testing.expectError(error.FlowControlViolation, connection.receiveDataPayload(1, padded_frame));
    try std.testing.expectEqual(@as(i64, 5), connection.recv_connection_window.value);
    try std.testing.expectEqual(@as(i64, 4), (try connection.recvStreamWindow(1)).value);

    try (try connection.recvStreamWindow(1)).update(1);
    const data = try connection.receiveDataPayload(1, padded_frame);
    defer connection.releaseDataFrameBudget(data);
    try std.testing.expectEqualStrings("ok", data.data);
    try std.testing.expectEqual(@as(i64, 0), connection.recv_connection_window.value);
    try std.testing.expectEqual(@as(i64, 0), (try connection.recvStreamWindow(1)).value);
}

test "HTTP/2 empty DATA is legal while stream window is negative" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.recv_stream_windows.deinit(allocator);
        connection.recv_stream_window_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }
    connection.recv_connection_window.value = -7;
    const stream_window = try connection.recvStreamWindow(1);
    stream_window.value = -11;

    const data = try connection.receiveDataPayload(1, .{
        .header = .{
            .length = 0,
            .frame_type = .data,
            .flags = flag_end_stream,
            .stream_id = 1,
        },
        .payload = &.{},
    });
    defer connection.releaseDataFrameBudget(data);
    try std.testing.expectEqual(@as(usize, 0), data.data.len);
    try std.testing.expectEqual(@as(i64, -7), connection.recv_connection_window.value);
    try std.testing.expectEqual(@as(i64, -11), stream_window.value);
}

test "HTTP/2 final DATA returns connection credit without stream update" {
    const allocator = std.testing.allocator;
    const RecordingWriter = struct {
        bytes: [32]u8 = undefined,
        len: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            bytes: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            const count = @min(bytes.len, self.bytes.len - self.len);
            if (count == 0) return error.SocketUnconnected;
            @memcpy(self.bytes[self.len..][0..count], bytes[0..count]);
            self.len += count;
            return count;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: RecordingWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = RecordingWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .recv_connection_window = .{ .value = 20_000 },
        .recv_connection_window_target = 65_535,
        .recv_stream_window_target = 65_535,
        .adaptive_window = bdp.Estimator.init(65_535, 1024 * 1024),
    };
    defer {
        connection.recv_stream_windows.deinit(allocator);
        connection.recv_stream_window_index.deinit(allocator);
    }
    (try connection.recvStreamWindow(1)).value = 20_000;

    try connection.maybeReleaseReceivedCapacity(1, true);

    try std.testing.expectEqual(
        @as(usize, http2.FrameHeader.encoded_len + 4),
        writer.len,
    );
    const frame = try http2.Frame.parse(writer.bytes[0..writer.len]);
    const update = try http2.WindowUpdatePayload.parse(frame);
    try std.testing.expectEqual(@as(u31, 0), update.stream_id);
    try std.testing.expectEqual(@as(u31, 45_535), update.increment);
    try std.testing.expectEqual(
        @as(i64, 20_000),
        (try connection.recvStreamWindow(1)).value,
    );
}

test "HTTP/2 DATA send waits for WINDOW_UPDATE capacity" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            while (true) {
                var headers = try readFrame(server_ptr.allocator, server_ptr.io, connection.stream, server_ptr.limits);
                defer headers.deinit(server_ptr.allocator);
                if (try connection.handleConnectionFrame(headers.frame)) continue;
                try std.testing.expectEqual(http2.FrameType.headers, headers.frame.header.frame_type);
                try std.testing.expectEqual(@as(u31, 1), headers.frame.header.stream_id);
                try std.testing.expect((headers.frame.header.flags & flag_end_stream) == 0);
                // This test deliberately bypasses the high-level request
                // parser, so mirror its stream reservation before using the
                // high-level response writer below.
                try connection.reservePeerStream(1);
                break;
            }

            var first = try readFrame(server_ptr.allocator, server_ptr.io, connection.stream, server_ptr.limits);
            defer first.deinit(server_ptr.allocator);
            try std.testing.expectEqual(http2.FrameType.data, first.frame.header.frame_type);
            const first_data = try http2.DataPayload.parse(first.frame);
            try std.testing.expectEqualStrings("hello", first_data.data);
            try std.testing.expect((first.frame.header.flags & flag_end_stream) == 0);

            // h2/hyper style senders park DATA behind flow control.  Once both
            // connection and stream credit are restored, the blocked request
            // can continue without the application retrying the send.
            try connection.sendWindowUpdate(0, 64);
            try writeFrame(server_ptr.allocator, server_ptr.io, connection.stream, .window_update, 0, 1, &.{ 0, 0, 0, 64 });

            var second = try readFrame(server_ptr.allocator, server_ptr.io, connection.stream, server_ptr.limits);
            defer second.deinit(server_ptr.allocator);
            try std.testing.expectEqual(http2.FrameType.data, second.frame.header.frame_type);
            const second_data = try http2.DataPayload.parse(second.frame);
            try std.testing.expectEqualStrings(" world", second_data.data);
            try std.testing.expect((second.frame.header.flags & flag_end_stream) != 0);

            try connection.writeResponse(1, .{ .status = 200, .body = "ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    client.send_connection_window.value = 5;
    (try client.sendStreamWindow(1)).value = 5;

    var response = try client.request(.{
        .method = "POST",
        .path = "/flow-wait",
        .authority = "localhost",
        .body = "hello world",
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("ok", response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 request writer deadline reports committed flow-control prefix" {
    const allocator = std.testing.allocator;
    const payload = "hello world";

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        allow_credit: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            const deadline = std.Io.Clock.Timestamp.fromNow(
                shared.server.io,
                .{ .raw = .fromSeconds(2), .clock = .awake },
            );

            while (true) {
                var frame = try connection.readOwnedFrameWithDeadline(
                    deadline,
                );
                defer frame.deinit(shared.server.allocator);
                if (try connection.handleConnectionFrame(frame.frame)) {
                    continue;
                }
                try std.testing.expectEqual(
                    http2.FrameType.headers,
                    frame.frame.header.frame_type,
                );
                try std.testing.expectEqual(@as(u31, 1), frame.frame.header.stream_id);
                try std.testing.expect(
                    (frame.frame.header.flags & flag_end_stream) == 0,
                );
                try connection.addActivePeerStream(1);
                break;
            }

            var first = try connection.readOwnedFrameWithDeadline(deadline);
            defer first.deinit(shared.server.allocator);
            try std.testing.expectEqual(
                http2.FrameType.data,
                first.frame.header.frame_type,
            );
            const first_data = try http2.DataPayload.parse(first.frame);
            try std.testing.expectEqualStrings("hello", first_data.data);
            try std.testing.expect(
                (first.frame.header.flags & flag_end_stream) == 0,
            );

            try shared.allow_credit.wait(shared.server.io);
            const increment = [_]u8{ 0, 0, 0, 64 };
            try writeFrame(
                shared.server.allocator,
                shared.server.io,
                connection.stream,
                .window_update,
                0,
                0,
                &increment,
            );
            try writeFrame(
                shared.server.allocator,
                shared.server.io,
                connection.stream,
                .window_update,
                0,
                1,
                &increment,
            );

            var second = try connection.readOwnedFrameWithDeadline(deadline);
            defer second.deinit(shared.server.allocator);
            try std.testing.expectEqual(
                http2.FrameType.data,
                second.frame.header.frame_type,
            );
            const second_data = try http2.DataPayload.parse(second.frame);
            try std.testing.expectEqualStrings(" world", second_data.data);
            try std.testing.expect(
                (second.frame.header.flags & flag_end_stream) != 0,
            );
            try connection.writeResponse(1, .{ .body = "ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.allow_credit.set(io);
        thread.join();
    };

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    var writer = try client.startRequest(.{
        .path = "/deadline-upload",
        .authority = "localhost",
        .body_length = payload.len,
    });
    defer writer.deinit();
    client.send_connection_window.value = 5;
    (try client.sendStreamWindow(1)).value = 5;

    try std.testing.expectError(
        error.Timeout,
        writer.finishDataWithDeadline(payload, .{
            .raw = .zero,
            .clock = .real,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), writer.committedBytes());
    try std.testing.expectEqual(@as(i64, 5), client.send_connection_window.value);
    try std.testing.expectEqual(@as(i64, 5), (try client.sendStreamWindow(1)).value);

    try std.testing.expectError(
        error.Timeout,
        writer.writeWithTimeout(payload, .fromMilliseconds(80)),
    );
    try std.testing.expectEqual(@as(usize, 5), writer.committedBytes());
    try std.testing.expectEqual(@as(i64, 0), client.send_connection_window.value);
    try std.testing.expectEqual(@as(i64, 0), (try client.sendStreamWindow(1)).value);

    shared.allow_credit.set(io);
    try writer.finishData(payload[writer.committedBytes()..]);
    try std.testing.expectEqual(payload.len, writer.committedBytes());

    var response = try writer.readResponse();
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("ok", response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 response writer deadline reports committed flow-control prefix" {
    const allocator = std.testing.allocator;
    const payload = "hello world";

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        timeout_done: std.Io.Event = .unset,
        allow_retry: std.Io.Event = .unset,
        committed_after_timeout: usize = 0,
        connection_window_after_timeout: i64 = -1,
        stream_window_after_timeout: i64 = -1,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
                shared.timeout_done.set(shared.server.io);
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var request = try connection.readRequest();
            defer request.deinit(shared.server.allocator);

            var writer = try connection.startResponse(request.stream_id, .{
                .headers = &.{.{
                    .name = "content-length",
                    .value = "11",
                }},
            });
            defer writer.deinit();
            connection.send_connection_window.value = 5;
            (try connection.sendStreamWindow(request.stream_id)).value = 5;

            try std.testing.expectError(
                error.Timeout,
                writer.finishDataWithDeadline(payload, .{
                    .raw = .zero,
                    .clock = .real,
                }),
            );
            try std.testing.expectEqual(@as(usize, 0), writer.committedBytes());
            try std.testing.expectEqual(
                @as(i64, 5),
                connection.send_connection_window.value,
            );
            try std.testing.expectEqual(
                @as(i64, 5),
                (try connection.sendStreamWindow(request.stream_id)).value,
            );

            try std.testing.expectError(
                error.Timeout,
                writer.finishDataWithTimeout(payload, .fromMilliseconds(80)),
            );
            shared.committed_after_timeout = writer.committedBytes();
            shared.connection_window_after_timeout =
                connection.send_connection_window.value;
            shared.stream_window_after_timeout =
                (try connection.sendStreamWindow(request.stream_id)).value;
            shared.timeout_done.set(shared.server.io);

            try shared.allow_retry.wait(shared.server.io);
            try writer.finishData(payload[writer.committedBytes()..]);
            try std.testing.expectEqual(payload.len, writer.committedBytes());
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.allow_retry.set(io);
        thread.join();
    };

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    const pending = try client.sendCompleteRequest(.{
        .path = "/deadline-response",
        .authority = "localhost",
    });
    defer client.releaseLocalStream(pending.stream_id);
    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromSeconds(2), .clock = .awake },
    );

    while (true) {
        var frame = try client.readOwnedFrameWithDeadline(deadline);
        defer frame.deinit(allocator);
        if (try client.handleConnectionFrame(frame.frame)) continue;
        try std.testing.expectEqual(
            http2.FrameType.headers,
            frame.frame.header.frame_type,
        );
        try std.testing.expectEqual(pending.stream_id, frame.frame.header.stream_id);
        try std.testing.expect((frame.frame.header.flags & flag_end_stream) == 0);
        break;
    }

    var first = try client.readOwnedFrameWithDeadline(deadline);
    defer first.deinit(allocator);
    try std.testing.expectEqual(http2.FrameType.data, first.frame.header.frame_type);
    const first_data = try http2.DataPayload.parse(first.frame);
    try std.testing.expectEqualStrings("hello", first_data.data);
    try std.testing.expect((first.frame.header.flags & flag_end_stream) == 0);

    try shared.timeout_done.wait(io);
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 5), shared.committed_after_timeout);
    try std.testing.expectEqual(@as(i64, 0), shared.connection_window_after_timeout);
    try std.testing.expectEqual(@as(i64, 0), shared.stream_window_after_timeout);

    const increment = [_]u8{ 0, 0, 0, 64 };
    try writeFrame(
        allocator,
        io,
        client.stream,
        .window_update,
        0,
        0,
        &increment,
    );
    try writeFrame(
        allocator,
        io,
        client.stream,
        .window_update,
        0,
        pending.stream_id,
        &increment,
    );
    shared.allow_retry.set(io);

    var second = try client.readOwnedFrameWithDeadline(deadline);
    defer second.deinit(allocator);
    try std.testing.expectEqual(http2.FrameType.data, second.frame.header.frame_type);
    const second_data = try http2.DataPayload.parse(second.frame);
    try std.testing.expectEqualStrings(" world", second_data.data);
    try std.testing.expect((second.frame.header.flags & flag_end_stream) != 0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 local protocol error reset budget closes real connection" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const limits: Limits = .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
        .max_local_error_reset_streams = 1,
    };

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        io: std.Io,
        ready: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.ready.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();

            var first = try connection.readRequest();
            defer first.deinit(self.server.allocator);
            var second = try connection.readRequest();
            defer second.deinit(self.server.allocator);
            try std.testing.expectEqual(@as(u31, 1), first.stream_id);
            try std.testing.expectEqual(@as(u31, 3), second.stream_id);
            (try connection.sendStreamWindow(first.stream_id)).value =
                max_flow_window;
            (try connection.sendStreamWindow(second.stream_id)).value =
                max_flow_window;
            self.ready.set(self.io);

            if (connection.readRequestWithTimeout(.fromSeconds(2))) |request| {
                var unexpected = request;
                unexpected.deinit(self.server.allocator);
                return error.TestUnexpectedResult;
            } else |err| {
                try std.testing.expectEqual(
                    error.ConnectionGoAway,
                    err,
                );
            }
            try std.testing.expectEqual(
                @as(usize, 1),
                connection.local_error_reset_streams,
            );
            try std.testing.expect(connection.aggregate_timeout_unusable);
        }
    };

    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), limits);
    defer client.close();
    _ = try client.sendCompleteRequest(.{
        .path = "/first",
        .authority = "localhost",
    });
    _ = try client.sendCompleteRequest(.{
        .path = "/second",
        .authority = "localhost",
    });
    try shared.ready.wait(io);
    if (shared.err) |err| return err;

    const overflow = [_]u8{ 0, 0, 0, 1 };
    try writeFrame(
        allocator,
        io,
        client.stream,
        .window_update,
        0,
        1,
        &overflow,
    );
    try writeFrame(
        allocator,
        io,
        client.stream,
        .window_update,
        0,
        3,
        &overflow,
    );

    var reset = try client.readResetStreamWithTimeout(.fromSeconds(2));
    defer reset.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), reset.reset.stream_id);
    try std.testing.expectEqual(
        http2.ErrorCode.flow_control_error,
        reset.reset.error_code,
    );

    var goaway = try client.readGoAwayWithTimeout(.fromSeconds(2));
    defer goaway.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 3), goaway.goaway.last_stream_id);
    try std.testing.expectEqual(
        http2.ErrorCode.enhance_your_calm,
        goaway.goaway.error_code,
    );
    try std.testing.expectEqualStrings(
        "too_many_internal_resets",
        goaway.goaway.debug_data,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 response batch reorders out-of-order responses" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var requests: [3]OwnedRequest = undefined;
            var initialized: usize = 0;
            defer for (requests[0..initialized]) |*request| {
                request.deinit(server_ptr.allocator);
            };
            for (&requests) |*request| {
                request.* = try connection.readRequest();
                initialized += 1;
            }

            var stream_ids: [requests.len]u31 = undefined;
            var response_headers: [requests.len]http2.Hpack.HeaderField =
                undefined;
            var responses: [requests.len]ResponseOptions = undefined;
            var index = requests.len;
            while (index != 0) {
                index -= 1;
                const output_index = requests.len - 1 - index;
                stream_ids[output_index] = requests[index].stream_id;
                response_headers[output_index] = .{
                    .name = "x-path",
                    .value = requests[index].path,
                };
                responses[output_index] = .{
                    .headers = response_headers[output_index..][0..1],
                };
            }
            try connection.writeResponseBatch(&stream_ids, &responses);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();

    const requests = [_]RequestOptions{
        .{ .path = "/one", .authority = "localhost" },
        .{ .path = "/two", .authority = "localhost" },
        .{ .path = "/three", .authority = "localhost" },
    };
    var responses: [requests.len]OwnedResponse = undefined;
    try client.requestBatchInto(&requests, &responses);
    defer for (&responses) |*response| response.deinit(allocator);

    try std.testing.expectEqualStrings(
        "/one",
        findHeader(responses[0].headers, "x-path").?,
    );
    try std.testing.expectEqualStrings(
        "/two",
        findHeader(responses[1].headers, "x-path").?,
    );
    try std.testing.expectEqualStrings(
        "/three",
        findHeader(responses[2].headers, "x-path").?,
    );
    for (responses) |response| {
        const date = findHeader(response.headers, "date") orelse
            return error.MissingPseudoHeader;
        try std.testing.expectEqual(@as(usize, http_date.value_len), date.len);
        try std.testing.expectEqualStrings("GMT", date[26..]);
    }
    try std.testing.expectEqual(@as(usize, 0), client.active_local_streams.items.len);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 response batch deadline is not renewed by partial completion" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        reset_stream_id: ?u31 = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var first = try connection.readRequest();
            defer first.deinit(self.server.allocator);
            var second = try connection.readRequest();
            defer second.deinit(self.server.allocator);

            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(150),
                .awake,
            );
            try connection.writeResponse(first.stream_id, .{
                .body = "first",
            });
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(350),
                .awake,
            );
            try connection.writeResponse(second.stream_id, .{
                .body = "late",
            });
            var reset = try connection.readResetStreamWithTimeout(
                .fromSeconds(1),
            );
            defer reset.deinit(self.server.allocator);
            self.reset_stream_id = reset.reset.stream_id;
            try std.testing.expectEqual(
                http2.ErrorCode.cancel,
                reset.reset.error_code,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    const requests = [_]RequestOptions{
        .{ .path = "/first", .authority = "localhost" },
        .{ .path = "/second", .authority = "localhost" },
    };
    var responses: [requests.len]OwnedResponse = undefined;
    try std.testing.expectError(
        error.Timeout,
        client.requestBatchIntoWithTimeout(
            &requests,
            &responses,
            .fromMilliseconds(400),
        ),
    );
    try std.testing.expect(!client.isReusable());
    try std.testing.expectEqual(@as(usize, 0), client.activeLocalStreamCount());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(?u31, 3), shared.reset_stream_id);
}

test "HTTP/2 batch deadlines validate before stream or wire mutation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var connection = Connection{
        .io = threaded.io(),
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .default_scheme = "http",
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.write_batch.deinit(allocator);
        connection.batch_data_headers.deinit(allocator);
        connection.batch_data_parts.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
        connection.deinitStagedHpackEncoder();
    }
    const requests = [_]RequestOptions{.{
        .authority = "localhost",
    }};
    const body_requests = [_]RequestOptions{.{
        .method = "POST",
        .authority = "localhost",
        .body = "body",
    }};
    var responses: [1]OwnedResponse = undefined;
    var streaming_responses: [1]StreamingResponse = undefined;
    const noopConsume = struct {
        fn consume(_: void, _: usize, _: []const u8) !void {}
    }.consume;
    try std.testing.expectError(
        error.Timeout,
        connection.requestBatchIntoWithTimeout(
            &requests,
            &responses,
            .zero,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.requestBodyBatchIntoWithDeadline(
            &body_requests,
            4,
            &responses,
            .fromNow(connection.io, .{
                .raw = .fromSeconds(1),
                .clock = .real,
            }),
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.requestBatchStreamingIntoWithTimeout(
            &requests,
            &streaming_responses,
            .zero,
            {},
            noopConsume,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.requestBatchStreamingWithInformationalIntoWithDeadline(
            &requests,
            &streaming_responses,
            null,
            .fromNow(connection.io, .{
                .raw = .fromSeconds(1),
                .clock = .real,
            }),
            {},
            noopConsume,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.requestBodyBatchStreamingIntoWithTimeout(
            &body_requests,
            4,
            &streaming_responses,
            .zero,
            {},
            noopConsume,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.requestBodyBatchStreamingWithInformationalIntoWithDeadline(
            &body_requests,
            4,
            &streaming_responses,
            null,
            .fromNow(connection.io, .{
                .raw = .fromSeconds(1),
                .clock = .real,
            }),
            {},
            noopConsume,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        connection.requestBodyBatchStreamingWithInformationalIntoWithTimeout(
            &body_requests,
            4,
            &streaming_responses,
            null,
            .zero,
            {},
            noopConsume,
        ),
    );
    try std.testing.expectError(
        error.InvalidFrameSize,
        connection.requestBodyBatchStreamingWithInformationalInto(
            &body_requests,
            0,
            &streaming_responses,
            null,
            {},
            noopConsume,
        ),
    );
    connection.role = .server;
    var inbound_requests: [1]StreamingRequest = undefined;
    try std.testing.expectError(
        error.Timeout,
        connection.readRequestBatchStreamingIntoWithTimeout(
            &inbound_requests,
            .zero,
            {},
            struct {
                fn consume(_: void, _: u31, _: []const u8) !void {}
            }.consume,
        ),
    );
    try std.testing.expectEqual(@as(u31, 1), connection.next_client_stream_id);
    try std.testing.expectEqual(@as(usize, 0), connection.activeLocalStreamCount());
    try std.testing.expectEqual(@as(u31, 0), connection.last_peer_client_stream_id);
    try std.testing.expectEqual(@as(usize, 0), connection.activePeerStreamCount());
    try std.testing.expectEqual(@as(usize, 0), connection.write_batch.items.len);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.hpack_encoder.dynamic_table.entries.items.len,
    );
    try std.testing.expect(!connection.aggregate_timeout_unusable);
}

test "HTTP/2 bodyless request batch partial HEADERS write fails closed" {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            bytes: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            if (self.writes == 1) return @min(bytes.len, 4);
            return error.NetworkDown;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: PartialWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = PartialWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .default_scheme = "http",
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.write_batch.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
        connection.deinitStagedHpackEncoder();
    }

    const requests = [_]RequestOptions{
        .{ .path = "/first", .authority = "localhost" },
        .{ .path = "/second", .authority = "localhost" },
    };
    var responses: [requests.len]OwnedResponse = undefined;
    try std.testing.expectError(
        error.NetworkDown,
        connection.requestBatchInto(&requests, &responses),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
    try std.testing.expectEqual(@as(u31, 5), connection.next_client_stream_id);
    try std.testing.expectEqual(@as(usize, 0), connection.activeLocalStreamCount());
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expect(!connection.isReusable());
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.sendCompleteRequest(.{ .authority = "localhost" }),
    );
}

test "HTTP/2 single request partial HEADERS write fails closed" {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            bytes: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            if (self.writes == 1) return @min(bytes.len, 4);
            return error.NetworkDown;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: PartialWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = PartialWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .default_scheme = "http",
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.write_batch.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
        connection.deinitStagedHpackEncoder();
    }

    try std.testing.expectError(
        error.NetworkDown,
        connection.sendCompleteRequest(.{ .authority = "localhost" }),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
    try std.testing.expectEqual(@as(usize, 0), connection.activeLocalStreamCount());
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expect(!connection.isReusable());
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.sendCompleteRequest(.{ .authority = "localhost" }),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
}

test "HTTP/2 single HEADERS encode failure preserves live HPACK state" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .default_scheme = "http",
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.write_batch.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
        connection.deinitStagedHpackEncoder();
    }

    _ = try connection.hpack_encoder.encodeBlockRetained(allocator, &.{.{
        .name = "x-live",
        .value = "one",
    }});
    const live_entries =
        connection.hpack_encoder.dynamic_table.entries.items.len;
    try connection.addActiveLocalStream(1);
    {
        var failing = std.testing.FailingAllocator.init(
            allocator,
            .{ .fail_index = 0 },
        );
        connection.allocator = failing.allocator();
        defer connection.allocator = allocator;
        try std.testing.expectError(
            error.OutOfMemory,
            connection.writeHeaders(1, &.{.{
                .name = "x-staged",
                .value = "two",
            }}, true),
        );
        try std.testing.expect(failing.has_induced_failure);
    }
    try std.testing.expectEqual(
        live_entries,
        connection.hpack_encoder.dynamic_table.entries.items.len,
    );
    try std.testing.expect(!connection.aggregate_timeout_unusable);
    try std.testing.expect(connection.outboundStreamIsActive(1));
}

test "HTTP/2 PUSH_PROMISE partial write rolls back state and fails closed" {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            bytes: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            if (self.writes == 1) return @min(bytes.len, 4);
            return error.NetworkDown;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: PartialWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = PartialWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
        connection.push_state.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.response_semantics.deinit(allocator);
        connection.response_semantics_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
        connection.deinitStagedHpackEncoder();
    }
    try connection.addActivePeerStream(1);

    const headers = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/pushed" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "x-push-dynamic", .value = "one" },
    };
    try std.testing.expectError(
        error.NetworkDown,
        connection.promisePush(1, &headers),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
    try std.testing.expect(connection.push_state.localStatus(2) == null);
    try std.testing.expect(!connection.response_semantics_index.contains(2));
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.hpack_encoder.dynamic_table.entries.items.len,
    );
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.promisePush(1, &headers),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
}

test "HTTP/2 partial DATA frame write fails connection closed" {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            bytes: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            if (self.writes == 1) return @min(bytes.len, 4);
            return error.NetworkDown;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: PartialWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = PartialWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
    }
    try connection.addActiveLocalStream(1);

    try std.testing.expectError(
        error.NetworkDown,
        connection.writeData(1, "payload", false),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.writeData(1, "retry", false),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
}

test "HTTP/2 partial extension control write fails connection closed" {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            bytes: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            if (self.writes == 1) return @min(bytes.len, 4);
            return error.NetworkDown;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: PartialWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = PartialWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.deinitPeerMetadata();
    }

    try std.testing.expectError(
        error.NetworkDown,
        connection.sendOrigins(&.{"https://example.com"}),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.sendAlternativeService(
            0,
            "https://example.com",
            "h3=\":443\"",
        ),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
}

test "HTTP/2 application batch reset partial write fails closed" {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
        var active: std.atomic.Value(?*@This()) = .init(null);
        writes: std.atomic.Value(usize) = .init(0),

        fn write(
            _: ?*anyopaque,
            _: net.Socket.Handle,
            bytes: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self = active.load(.acquire).?;
            if (self.writes.fetchAdd(1, .monotonic) == 0) return @min(bytes.len, 4);
            return error.NetworkDown;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
    defer listener.deinit(io);
    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    errdefer stream.close(io);
    const peer = try listener.accept(io);
    defer peer.close(io);
    var writer: PartialWriter = .{};
    PartialWriter.active.store(&writer, .release);
    defer PartialWriter.active.store(null, .release);
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = PartialWriter.write;
    var connection = Connection{
        .io = .{ .userdata = threaded.io().userdata, .vtable = &vtable },
        .allocator = allocator,
        .stream = stream,
        .role = .client,
        .limits = .{ .max_reset_stream_history = 0 },
    };
    defer {
        connection.io = io;
        connection.close();
    }

    const states = [_]Connection.BatchResponseState{
        .{
            .stream_id = 1,
            .request_method = "GET",
            .extended_connect = false,
        },
        .{
            .stream_id = 3,
            .request_method = "GET",
            .extended_connect = false,
        },
    };
    try std.testing.expectError(
        error.NetworkDown,
        connection.writeBatchResponseResets(&states),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes.load(.acquire));
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.sendGoAway(0, .no_error, &.{}),
    );
    var responses: [1]OwnedResponse = undefined;
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.requestBatchInto(
            &.{.{ .authority = "localhost" }},
            &responses,
        ),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes.load(.acquire));
}

test "HTTP/2 adaptive window partial write fails closed without local commit" {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            bytes: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            if (self.writes == 1) return @min(bytes.len, 4);
            return error.NetworkDown;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: PartialWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = PartialWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.recv_stream_windows.deinit(allocator);
        connection.recv_stream_window_index.deinit(allocator);
    }

    const target: u32 = 100_000;
    try std.testing.expectError(
        error.NetworkDown,
        connection.sendAdaptiveWindowUpdate(target),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expectEqual(
        @as(u32, @intCast(default_flow_window)),
        connection.recv_connection_window_target,
    );
    try std.testing.expectEqual(
        @as(u32, @intCast(default_flow_window)),
        connection.recv_stream_window_target,
    );
    try std.testing.expect(!connection.awaiting_settings_ack);
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.sendWindowUpdate(0, 1),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
}

test "HTTP/2 internal error GOAWAY bypasses public fail-fast guard" {
    if (comptime builtin.os.tag != .linux) return;
    const allocator = std.testing.allocator;
    const RecordingWriter = struct {
        var active: std.atomic.Value(?*@This()) = .init(null);
        bytes: [128]u8 = undefined,
        len: usize = 0,
        writes: usize = 0,

        fn write(
            _: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self = active.load(.acquire).?;
            self.writes += 1;
            const count = @min(header.len, self.bytes.len - self.len);
            if (count == 0) return error.SocketUnconnected;
            @memcpy(self.bytes[self.len..][0..count], header[0..count]);
            self.len += count;
            return count;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: RecordingWriter = .{};
    RecordingWriter.active.store(&writer, .release);
    defer RecordingWriter.active.store(null, .release);
    const io = threaded.io();
    var fixture = try @import("runtime/testing/blocked_output.zig").BlockedOutput.init(io, .server);
    defer fixture.deinit();
    const connection = &fixture.connection;
    var vtable = io.vtable.*;
    vtable.netWrite = RecordingWriter.write;
    connection.io = .{ .userdata = io.userdata, .vtable = &vtable };
    defer connection.io = io;
    connection.serve_read_connection_error = .frame_sequence;

    connection.sendServeReadError(error.UnexpectedFrame);
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expect(writer.len != 0);
    const frame = try http2.Frame.parse(writer.bytes[0..writer.len]);
    try std.testing.expectEqual(http2.FrameType.goaway, frame.header.frame_type);
    const goaway = try http2.GoAwayPayload.parse(frame);
    try std.testing.expectEqual(http2.ErrorCode.protocol_error, goaway.error_code);
    try std.testing.expectEqualStrings("frame-sequence", goaway.debug_data);

    const writes = writer.writes;
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.sendGoAway(0, .no_error, &.{}),
    );
    try std.testing.expectEqual(writes, writer.writes);
}

test "HTTP/2 streaming request batch partial HEADERS write fails closed" {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            bytes: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            if (self.writes == 1) return @min(bytes.len, 4);
            return error.NetworkDown;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: PartialWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = PartialWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .default_scheme = "http",
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.write_batch.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
        connection.deinitStagedHpackEncoder();
    }

    const requests = [_]RequestOptions{
        .{ .path = "/first", .authority = "localhost" },
        .{ .path = "/second", .authority = "localhost" },
    };
    var responses: [requests.len]StreamingResponse = undefined;
    try std.testing.expectError(
        error.NetworkDown,
        connection.requestBatchStreamingInto(
            &requests,
            &responses,
            {},
            struct {
                fn consume(_: void, _: usize, _: []const u8) !void {}
            }.consume,
        ),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
    try std.testing.expectEqual(@as(u31, 5), connection.next_client_stream_id);
    try std.testing.expectEqual(@as(usize, 0), connection.activeLocalStreamCount());
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expect(!connection.isReusable());
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.sendCompleteRequest(.{ .authority = "localhost" }),
    );
}

test "HTTP/2 body request streaming response batch partial HEADERS fails closed" {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            bytes: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            if (self.writes == 1) return @min(bytes.len, 4);
            return error.NetworkDown;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: PartialWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = PartialWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .default_scheme = "http",
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.write_batch.deinit(allocator);
        connection.batch_data_headers.deinit(allocator);
        connection.batch_data_parts.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
        connection.deinitStagedHpackEncoder();
    }

    const requests = [_]RequestOptions{
        .{ .method = "POST", .authority = "localhost", .body = "one" },
        .{ .method = "POST", .authority = "localhost", .body = "two" },
    };
    var responses: [requests.len]StreamingResponse = undefined;
    try std.testing.expectError(
        error.NetworkDown,
        connection.requestBodyBatchStreamingInto(
            &requests,
            3,
            &responses,
            {},
            struct {
                fn consume(_: void, _: usize, _: []const u8) !void {}
            }.consume,
        ),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
    try std.testing.expectEqual(@as(u31, 5), connection.next_client_stream_id);
    try std.testing.expectEqual(@as(usize, 0), connection.activeLocalStreamCount());
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expect(!connection.isReusable());
}

test "HTTP/2 request body batch partial DATA does not append cleanup resets" {
    const allocator = std.testing.allocator;
    const PartialDataWriter = struct {
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            bytes: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            if (self.writes == 1) return bytes.len;
            if (self.writes == 2) return @min(bytes.len, 4);
            return error.NetworkDown;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: PartialDataWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = PartialDataWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .default_scheme = "http",
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.write_batch.deinit(allocator);
        connection.batch_data_headers.deinit(allocator);
        connection.batch_data_parts.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
        connection.deinitStagedHpackEncoder();
    }

    const requests = [_]RequestOptions{.{
        .method = "POST",
        .authority = "localhost",
        .body = "payload",
    }};
    var responses: [1]OwnedResponse = undefined;
    try std.testing.expectError(
        error.NetworkDown,
        connection.requestBodyBatchInto(
            &requests,
            requests[0].body.len,
            &responses,
        ),
    );
    // HEADERS, one partial DATA prefix, then the failing continuation. The
    // unwind path must not attempt a fourth write for RST_STREAM cleanup.
    try std.testing.expectEqual(@as(usize, 3), writer.writes);
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expectEqual(@as(usize, 0), connection.activeLocalStreamCount());
}

test "HTTP/2 aggregate response batch borrows wire frames after warmup" {
    const allocator = std.testing.allocator;
    const parallel = 3;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            {
                var warmup = try connection.readRequest();
                defer warmup.deinit(server_ptr.allocator);
                try connection.writeResponse(warmup.stream_id, .{});
            }

            const responses = [_]ResponseOptions{.{}} ** parallel;
            for (0..2) |batch_index| {
                var requests: [parallel]OwnedRequest = undefined;
                var initialized: usize = 0;
                defer for (requests[0..initialized]) |*request| {
                    request.deinit(server_ptr.allocator);
                };
                var stream_ids: [parallel]u31 = undefined;
                for (&requests, &stream_ids) |*request, *stream_id| {
                    request.* = try connection.readRequest();
                    initialized += 1;
                    stream_id.* = request.stream_id;
                }
                if (batch_index == 0) {
                    try connection.writeResponseBatch(
                        &stream_ids,
                        &responses,
                    );
                    continue;
                }

                var tracking = std.testing.FailingAllocator.init(
                    allocator,
                    .{},
                );
                const saved_allocator = connection.allocator;
                connection.allocator = tracking.allocator();
                defer connection.allocator = saved_allocator;
                try connection.writeResponseBatch(
                    &stream_ids,
                    &responses,
                );
                try std.testing.expectEqual(
                    @as(usize, 0),
                    tracking.allocations,
                );
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    {
        var warmup = try client.request(.{
            .path = "/batch-borrow",
            .authority = "localhost",
        });
        defer warmup.deinit(allocator);
    }

    const requests = [_]RequestOptions{.{
        .path = "/batch-borrow",
        .authority = "localhost",
    }} ** parallel;
    {
        var responses: [parallel]OwnedResponse = undefined;
        try client.requestBatchInto(&requests, &responses);
        defer for (&responses) |*response| response.deinit(allocator);
    }
    {
        var responses: [parallel]OwnedResponse = undefined;
        var tracking = std.testing.FailingAllocator.init(allocator, .{});
        const saved_allocator = client.allocator;
        client.allocator = tracking.allocator();
        defer client.allocator = saved_allocator;
        try client.requestBatchInto(&requests, &responses);
        defer for (&responses) |*response| {
            response.deinit(client.allocator);
        };
        // Request/response staging and wire-frame reads reuse connection
        // storage. Only one combined HPACK block per response is allocated.
        try std.testing.expectEqual(
            @as(usize, parallel),
            tracking.allocations,
        );
        for (responses) |response| {
            try std.testing.expectEqual(@as(u16, 200), response.status);
            try std.testing.expectEqualStrings("", response.body);
        }
    }

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 request body batch crosses connection flow-control window" {
    const allocator = std.testing.allocator;
    // Each body exceeds the default 65,535-byte stream window and the batch
    // exceeds the connection window, forcing both WINDOW_UPDATE paths.
    const request_body = "batch-body-" ** 8192;
    const parallel = 3;
    const total_body_bytes = request_body.len * parallel;
    const limits: Limits = .{
        .max_body_bytes = request_body.len,
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            var requests: [parallel]StreamingRequest = undefined;
            var initialized = false;
            defer if (initialized) for (&requests) |*request| {
                request.deinit(server_ptr.allocator);
            };
            const Context = struct {
                bytes: usize = 0,
                fn consume(
                    self: *@This(),
                    _: u31,
                    data: []const u8,
                ) !void {
                    self.bytes += data.len;
                }
            };
            var context: Context = .{};
            try connection.readRequestBatchStreamingIntoWithTimeout(
                &requests,
                .fromSeconds(2),
                &context,
                Context.consume,
            );
            initialized = true;
            for (&requests) |*request| {
                try std.testing.expectEqualStrings(
                    "POST",
                    request.method,
                );
                try std.testing.expectEqual(
                    request_body.len,
                    request.body_bytes,
                );
            }
            try std.testing.expectEqual(
                total_body_bytes,
                context.bytes,
            );
            var stream_ids: [parallel]u31 = undefined;
            var response_headers: [parallel]http2.Hpack.HeaderField =
                undefined;
            var responses: [parallel]ResponseOptions = undefined;
            for (&stream_ids, &response_headers, &responses, 0..) |
                *stream_id,
                *response_header,
                *response,
                index,
            | {
                const reverse = parallel - 1 - index;
                stream_id.* = requests[reverse].stream_id;
                response_header.* = .{
                    .name = "x-path",
                    .value = requests[reverse].path,
                };
                response.* = .{
                    .headers = response_headers[index..][0..1],
                };
            }
            try connection.writeResponseBatch(
                &stream_ids,
                &responses,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    const requests = [_]RequestOptions{
        .{
            .method = "POST",
            .path = "/one",
            .authority = "localhost",
            .body = request_body,
        },
        .{
            .method = "POST",
            .path = "/two",
            .authority = "localhost",
            .body = request_body,
        },
        .{
            .method = "POST",
            .path = "/three",
            .authority = "localhost",
            .body = request_body,
        },
    };
    var responses: [parallel]OwnedResponse = undefined;
    try client.requestBodyBatchIntoWithTimeout(
        &requests,
        request_body.len,
        &responses,
        .fromSeconds(2),
    );
    defer for (&responses) |*response| response.deinit(allocator);
    try std.testing.expectEqualStrings(
        "/one",
        findHeader(responses[0].headers, "x-path").?,
    );
    try std.testing.expectEqualStrings(
        "/two",
        findHeader(responses[1].headers, "x-path").?,
    );
    try std.testing.expectEqualStrings(
        "/three",
        findHeader(responses[2].headers, "x-path").?,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 request body batch consumes an early response while another upload waits" {
    const allocator = std.testing.allocator;
    const large_body = "large-upload-" ** 8192;
    const limits: Limits = .{ .max_body_bytes = large_body.len };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        connection: ?*Connection = null,
        early_bytes: usize = 0,
        early_response_sent: bool = false,
        large_bytes: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn consume(
            self: *@This(),
            stream_id: u31,
            data: []const u8,
        ) !void {
            if (stream_id == 1) {
                self.early_bytes += data.len;
                if (self.early_bytes == "small".len) {
                    try self.connection.?.writeResponseInternal(
                        stream_id,
                        .{
                            .body = "early-finished",
                            .request_method = "POST",
                        },
                        false,
                    );
                    self.early_response_sent = true;
                }
                return;
            }
            self.large_bytes += data.len;
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            self.connection = &connection;
            defer self.connection = null;
            var incoming: [2]StreamingRequest = undefined;
            try connection.readRequestBatchStreamingInto(
                &incoming,
                self,
                @This().consume,
            );
            defer for (&incoming) |*request| {
                request.deinit(self.server.allocator);
            };
            try std.testing.expect(self.early_response_sent);
            try std.testing.expectEqualStrings("/early", incoming[0].path);
            try std.testing.expectEqualStrings("/large", incoming[1].path);
            try std.testing.expectEqual(large_body.len, incoming[1].body_bytes);
            connection.releasePeerStream(incoming[0].stream_id);
            try connection.writeResponse(incoming[1].stream_id, .{
                .body = "large-finished",
            });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    const requests = [_]RequestOptions{
        .{
            .method = "POST",
            .path = "/early",
            .authority = "localhost",
            .body = "small",
        },
        .{
            .method = "POST",
            .path = "/large",
            .authority = "localhost",
            .body = large_body,
        },
    };
    var responses: [requests.len]StreamingResponse = undefined;
    const ResponseContext = struct {
        bodies: [requests.len][32]u8 = undefined,
        lengths: [requests.len]usize = .{0} ** requests.len,

        fn consume(
            self: *@This(),
            index: usize,
            data: []const u8,
        ) !void {
            if (self.lengths[index] + data.len > self.bodies[index].len) {
                return error.MessageTooLarge;
            }
            @memcpy(
                self.bodies[index][self.lengths[index]..][0..data.len],
                data,
            );
            self.lengths[index] += data.len;
        }
    };
    var response_context: ResponseContext = .{};
    try client.requestBodyBatchStreamingIntoWithTimeout(
        &requests,
        16 * 1024,
        &responses,
        .fromSeconds(2),
        &response_context,
        ResponseContext.consume,
    );
    defer for (&responses) |*response| response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), responses[0].status);
    try std.testing.expectEqual(@as(u16, 200), responses[1].status);
    try std.testing.expectEqualStrings(
        "early-finished",
        response_context.bodies[0][0..response_context.lengths[0]],
    );
    try std.testing.expectEqualStrings(
        "large-finished",
        response_context.bodies[1][0..response_context.lengths[1]],
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(large_body.len, shared.large_bytes);
}

test "HTTP/2 request body batch deadline covers blocked upload" {
    const allocator = std.testing.allocator;
    const large_body = "deadline-upload-" ** 8192;
    const limits: Limits = .{ .max_body_bytes = large_body.len };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            std.Io.sleep(
                self.server.io,
                .fromMilliseconds(100),
                .awake,
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    const requests = [_]RequestOptions{
        .{
            .method = "POST",
            .path = "/blocked-one",
            .authority = "localhost",
            .body = large_body,
        },
        .{
            .method = "POST",
            .path = "/blocked-two",
            .authority = "localhost",
            .body = large_body,
        },
    };
    var responses: [requests.len]OwnedResponse = undefined;
    try std.testing.expectError(
        error.Timeout,
        client.requestBodyBatchIntoWithTimeout(
            &requests,
            16 * 1024,
            &responses,
            .fromMilliseconds(20),
        ),
    );
    try std.testing.expect(!client.isReusable());
    try std.testing.expectEqual(@as(usize, 0), client.activeLocalStreamCount());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 request body batch streaming ignores duplicate reset and admits later request" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .max_pending_accept_reset_streams = 4,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        stream_one_bytes: usize = 0,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();

            var requests: [2]StreamingRequest = undefined;
            var initialized = false;
            defer if (initialized) for (&requests) |*request| {
                request.deinit(shared.server.allocator);
            };

            const Context = @This();
            try connection.readRequestBatchStreamingInto(
                &requests,
                shared,
                struct {
                    fn consume(
                        context: *Context,
                        stream_id: u31,
                        data: []const u8,
                    ) Error!void {
                        if (stream_id == 1) context.stream_one_bytes += data.len;
                    }
                }.consume,
            );
            initialized = true;

            try std.testing.expectEqual(@as(u31, 1), requests[0].stream_id);
            try std.testing.expectEqualStrings("/first-batch", requests[0].path);
            try std.testing.expectEqual(@as(usize, 10), requests[0].body_bytes);

            try std.testing.expectEqual(@as(u31, 5), requests[1].stream_id);
            try std.testing.expectEqualStrings("/replacement-batch", requests[1].path);
            try std.testing.expectEqual(@as(usize, 0), requests[1].body_bytes);

            try std.testing.expectEqual(@as(usize, 10), shared.stream_one_bytes);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
        .max_pending_accept_reset_streams = 4,
    });
    defer client.close();

    try client.writeHeaders(1, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/first-batch" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-length", .value = "10" },
    }, false);
    try client.writeHeaders(3, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/reset-batch" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    }, true);
    try client.sendResetStream(3, .cancel);
    // The public API deliberately rejects resetting an already closed stream.
    // Inject the duplicate peer frame directly to exercise the receiver's
    // tolerance for a legal retransmission already in flight on the wire.
    var duplicate_reset: [http2.ResetStreamPayload.encoded_len]u8 = undefined;
    const encoded_duplicate = try http2.ResetStreamPayload.writeInto(
        &duplicate_reset,
        3,
        .cancel,
    );
    try client.transportForIo().writeAll(encoded_duplicate);
    try client.writeHeaders(5, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/replacement-batch" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    }, true);
    try client.writeData(1, "first-body", true);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 streaming request consumes body without aggregation" {
    const allocator = std.testing.allocator;
    const body = "streaming-data-" ** 8192;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const limits: Limits = .{
        .max_body_bytes = body.len,
        .initial_window_size = 1024 * 1024,
        .initial_connection_window_size = 1024 * 1024,
    };
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,
        bytes: usize = 0,
        checksum: u64 = 0,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn consume(shared: *@This(), data: []const u8) !void {
            shared.bytes += data.len;
            for (data) |byte| shared.checksum +%= byte;
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            var request = try connection.readRequestStreaming(
                shared,
                consume,
            );
            defer request.deinit(shared.server.allocator);
            try std.testing.expectEqual(body.len, request.body_bytes);
            try connection.writeResponse(request.stream_id, .{});
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    var response = try client.request(.{
        .method = "POST",
        .path = "/stream",
        .authority = "localhost",
        .body = body,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    var expected_checksum: u64 = 0;
    for (body) |byte| expected_checksum +%= byte;
    try std.testing.expectEqual(body.len, shared.bytes);
    try std.testing.expectEqual(expected_checksum, shared.checksum);
}

test "HTTP/2 streaming pending request cleans up callback failure" {
    const allocator = std.testing.allocator;
    const headers = try allocator.alloc(http2.Hpack.HeaderField, 3);
    headers[0] = .{
        .name = try allocator.dupe(u8, ":method"),
        .value = try allocator.dupe(u8, "POST"),
    };
    headers[1] = .{
        .name = try allocator.dupe(u8, ":path"),
        .value = try allocator.dupe(u8, "/fail"),
    };
    headers[2] = .{
        .name = try allocator.dupe(u8, ":scheme"),
        .value = try allocator.dupe(u8, "http"),
    };
    const body = try allocator.dupe(u8, "callback body");

    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        for (connection.pending_requests.items[connection.pending_request_head..]) |*pending| {
            pending.deinit(allocator);
        }
        connection.pending_requests.deinit(allocator);
    }
    try connection.appendPendingRequest(.{
        .stream_id = 1,
        .headers = headers,
        .method = headers[0].value,
        .path = headers[1].value,
        .scheme = headers[2].value,
        .authority = null,
        .body = body,
    }, allocator);

    try std.testing.expectError(
        error.InvalidResponse,
        connection.readRequestStreaming(
            {},
            struct {
                fn consume(_: void, _: []const u8) Error!void {
                    return error.InvalidResponse;
                }
            }.consume,
        ),
    );
    try std.testing.expectEqual(
        connection.pending_requests.items.len,
        connection.pending_request_head,
    );
}

test "HTTP/2 request batch rolls back staged HPACK state" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .default_scheme = "http",
    };
    defer {
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.write_batch.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
        connection.deinitStagedHpackEncoder();
    }

    const requests = [_]RequestOptions{
        .{
            .authority = "localhost",
            .headers = &.{.{
                .name = "x-transactional",
                .value = "first",
            }},
        },
        .{
            .authority = "localhost",
            .headers = &.{.{
                .name = "Uppercase-Invalid",
                .value = "second",
            }},
        },
    };
    var responses: [requests.len]OwnedResponse = undefined;
    try std.testing.expectError(
        error.InvalidHeader,
        connection.requestBatchInto(&requests, &responses),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.hpack_encoder.dynamic_table.entries.items.len,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.active_local_streams.items.len,
    );
}

test "HTTP/2 request body batch rolls back staged HPACK state" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .default_scheme = "http",
        .send_connection_window = .{ .value = 1024 },
        .peer_initial_stream_window = 1024,
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.write_batch.deinit(allocator);
        connection.batch_data_headers.deinit(allocator);
        connection.batch_data_parts.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
        connection.deinitStagedHpackEncoder();
    }

    const requests = [_]RequestOptions{
        .{
            .method = "POST",
            .authority = "localhost",
            .body = "first",
            .headers = &.{.{
                .name = "x-transactional",
                .value = "first",
            }},
        },
        .{
            .method = "POST",
            .authority = "localhost",
            .body = "second",
            .headers = &.{.{
                .name = "Uppercase-Invalid",
                .value = "second",
            }},
        },
    };
    var responses: [requests.len]OwnedResponse = undefined;
    try std.testing.expectError(
        error.InvalidHeader,
        connection.requestBodyBatchInto(
            &requests,
            4,
            &responses,
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.hpack_encoder.dynamic_table.entries.items.len,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.active_local_streams.items.len,
    );
    try std.testing.expectEqual(@as(u31, 1), connection.next_client_stream_id);
    try std.testing.expectEqual(
        @as(i64, 1024),
        connection.send_connection_window.value,
    );
}

test "HTTP/2 response batch validates transactionally" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
        connection.response_semantics.deinit(allocator);
        connection.response_semantics_index.deinit(allocator);
        connection.write_batch.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
        connection.deinitStagedHpackEncoder();
    }
    try connection.addActivePeerStream(1);
    try connection.addActivePeerStream(3);

    try std.testing.expectError(
        error.InvalidContentLength,
        connection.writeResponseBatch(
            &.{ 1, 3 },
            &.{
                .{ .headers = &.{.{
                    .name = "x-transactional",
                    .value = "first",
                }} },
                .{ .body = "not bodyless" },
            },
        ),
    );
    try std.testing.expect(connection.outboundStreamIsActive(1));
    try std.testing.expect(connection.outboundStreamIsActive(3));
    // Full preflight rejects the invalid member before staging any HPACK or
    // wire bytes, which is stronger than merely allowing partial scratch.
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.write_batch.items.len,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.hpack_encoder.dynamic_table.entries.items.len,
    );

    try std.testing.expectError(
        error.InvalidContentLength,
        connection.writeResponseBatch(
            &.{ 1, 3 },
            &.{
                .{},
                .{
                    .status = 205,
                    .headers = &.{.{
                        .name = "content-length",
                        .value = "1",
                    }},
                },
            },
        ),
    );
    try std.testing.expect(connection.outboundStreamIsActive(1));
    try std.testing.expect(connection.outboundStreamIsActive(3));
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.write_batch.items.len,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.hpack_encoder.dynamic_table.entries.items.len,
    );

    try std.testing.expectError(
        error.InvalidStreamId,
        connection.writeResponseBatch(
            &.{ 1, 1 },
            &.{ .{}, .{} },
        ),
    );
    try std.testing.expect(connection.outboundStreamIsActive(1));
    try std.testing.expect(connection.outboundStreamIsActive(3));
}

test "HTTP/2 response batch partial HEADERS write fails closed" {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            bytes: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            if (self.writes == 1) return @min(bytes.len, 4);
            return error.NetworkDown;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: PartialWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = PartialWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{ .auto_date_header = false },
    };
    defer {
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
        connection.response_semantics.deinit(allocator);
        connection.response_semantics_index.deinit(allocator);
        connection.write_batch.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
        connection.deinitStagedHpackEncoder();
    }
    try connection.addActivePeerStream(1);
    try connection.addActivePeerStream(3);

    try std.testing.expectError(
        error.NetworkDown,
        connection.writeResponseBatch(&.{ 1, 3 }, &.{
            .{ .headers = &.{.{ .name = "x-first", .value = "one" }} },
            .{ .headers = &.{.{ .name = "x-second", .value = "two" }} },
        }),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expect(
        connection.hpack_encoder.dynamic_table.entries.items.len != 0,
    );
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.writeResponseBatch(&.{1}, &.{.{}}),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
}

test "HTTP/2 DATA receive releases WINDOW_UPDATE capacity" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 128 * 1024 },
    );
    defer server.deinit();

    const request_body = try allocator.alloc(u8, 40_000);
    defer allocator.free(request_body);
    @memset(request_body, 'q');

    const response_body = try allocator.alloc(u8, 40_000);
    defer allocator.free(response_body);
    @memset(response_body, 'r');

    const Shared = struct {
        server: *Server,
        expected_request: []const u8,
        response_body: []const u8,
        response_window_updates: usize = 0,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(shared.server.allocator);
            try std.testing.expectEqualStrings("/release-capacity", request.path);
            try std.testing.expectEqualSlices(u8, shared.expected_request, request.body);

            try connection.writeResponse(request.stream_id, .{
                .status = 200,
                .body = shared.response_body,
            });

            var conn_update = try connection.readWindowUpdate();
            defer conn_update.deinit(shared.server.allocator);
            try std.testing.expectEqual(@as(u31, 0), conn_update.window_update.stream_id);
            try std.testing.expect(conn_update.window_update.increment > 0);
            shared.response_window_updates += 1;

            var stream_update = try connection.readWindowUpdate();
            defer stream_update.deinit(shared.server.allocator);
            try std.testing.expectEqual(request.stream_id, stream_update.window_update.stream_id);
            try std.testing.expect(stream_update.window_update.increment > 0);
            shared.response_window_updates += 1;
        }
    };

    var shared = Shared{
        .server = &server,
        .expected_request = request_body,
        .response_body = response_body,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 128 * 1024,
    });
    defer client.close();

    var response = try client.request(.{
        .method = "POST",
        .path = "/release-capacity",
        .authority = "localhost",
        .body = request_body,
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualSlices(u8, response_body, response.body);
    try std.testing.expect(client.send_connection_window.value > default_flow_window - @as(i64, @intCast(request_body.len)));

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.response_window_updates);
}

test "HTTP/2 SETTINGS_INITIAL_WINDOW_SIZE updates stream send windows" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    const first = try connection.sendStreamWindow(1);
    try std.testing.expectEqual(@as(?usize, 0), connection.send_stream_window_index.get(1));
    try first.reserve(1024);
    try std.testing.expectEqual(@as(i64, default_flow_window - 1024), first.value);

    const settings = [_]http2.Setting{.{ .id = .initial_window_size, .value = 70_000 }};
    try connection.applySettings(&settings);
    try std.testing.expectEqual(@as(i64, 70_000), connection.peer_initial_stream_window);
    try std.testing.expectEqual(@as(i64, 70_000 - 1024), (try connection.sendStreamWindow(1)).value);
    try std.testing.expectEqual(@as(i64, 70_000), (try connection.sendStreamWindow(3)).value);
    try std.testing.expectEqual(@as(?usize, 1), connection.send_stream_window_index.get(3));

    (try connection.sendStreamWindow(1)).value = max_flow_window;
    try std.testing.expectError(error.FlowControlViolation, connection.applySettings(&.{
        .{ .id = .initial_window_size, .value = std.math.maxInt(i31) },
    }));
    try std.testing.expectEqual(@as(i64, 70_000), connection.peer_initial_stream_window);
    try std.testing.expectEqual(max_flow_window, (try connection.sendStreamWindow(1)).value);

    (try connection.sendStreamWindow(1)).value = 100;
    (try connection.sendStreamWindow(3)).value = max_flow_window;
    try std.testing.expectError(error.FlowControlViolation, connection.applySettings(&.{
        .{ .id = .initial_window_size, .value = std.math.maxInt(i31) },
    }));
    try std.testing.expectEqual(@as(i64, 70_000), connection.peer_initial_stream_window);
    try std.testing.expectEqual(@as(i64, 100), (try connection.sendStreamWindow(1)).value);
    try std.testing.expectEqual(max_flow_window, (try connection.sendStreamWindow(3)).value);
}

test "HTTP/2 adaptive window queues behind initial SETTINGS ACK" {
    const allocator = std.testing.allocator;
    const adaptive_target: u32 = 100_000;
    const sample_bytes: usize = adaptive_target / 2;
    const final_bytes: usize = 1;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 64 * 1024,
            .max_body_bytes = 128 * 1024,
            .adaptive_window = true,
            .adaptive_window_max = 1024 * 1024,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            try std.testing.expect(connection.awaiting_settings_ack);

            var request = try connection.readRequest();
            defer request.deinit(shared.server.allocator);
            try std.testing.expectEqualStrings(
                "/adaptive-window",
                request.path,
            );
            try std.testing.expectEqual(
                sample_bytes + final_bytes,
                request.body.len,
            );

            // The BDP ACK arrived before the initial SETTINGS ACK. Processing
            // the latter emitted exactly one merged adaptive update and began
            // a fresh SETTINGS acknowledgement wait.
            try std.testing.expect(connection.awaiting_settings_ack);
            try std.testing.expectEqual(
                @as(?u32, adaptive_target),
                connection.adaptive_pending_stream_target,
            );
            try std.testing.expectEqual(
                @as(?u32, null),
                connection.adaptive_queued_target,
            );
            try std.testing.expectEqual(
                adaptive_target,
                connection.recv_connection_window_target,
            );
            try std.testing.expectEqual(
                adaptive_target,
                connection.recv_stream_window_target,
            );
            try std.testing.expectEqual(
                @as(u32, adaptive_target / 2),
                connection.dataFrameBudgetMaximum(),
            );
            try std.testing.expect(
                (try connection.recvStreamWindow(1)).value >
                    default_flow_window,
            );
            try std.testing.expectEqual(
                @as(i64, adaptive_target),
                (try connection.recvStreamWindow(3)).value,
            );

            const user_ping = [_]u8{ 6, 2, 6, 4, 3, 3, 8, 3 };
            const observed = try connection.readPing();
            try std.testing.expectEqualSlices(u8, &user_ping, &observed);
            try std.testing.expect(!connection.awaiting_settings_ack);
            try std.testing.expectEqual(
                @as(?u32, null),
                connection.adaptive_pending_stream_target,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeAll(io, stream, http2.connection_preface);
    try writeFrame(allocator, io, stream, .settings, 0, 0, &.{});

    var server_settings = try readFrame(allocator, io, stream, .{});
    defer server_settings.deinit(allocator);
    try std.testing.expectEqual(
        http2.FrameType.settings,
        server_settings.frame.header.frame_type,
    );
    try std.testing.expectEqual(
        @as(u8, 0),
        server_settings.frame.header.flags & flag_ack,
    );
    var server_ack = try readFrame(allocator, io, stream, .{});
    defer server_ack.deinit(allocator);
    try std.testing.expectEqual(
        http2.FrameType.settings,
        server_ack.frame.header.frame_type,
    );
    try std.testing.expect(server_ack.frame.header.flags & flag_ack != 0);

    var request_block: std.ArrayList(u8) = .empty;
    defer request_block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&request_block, allocator, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/adaptive-window" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-length", .value = "50001" },
    });
    try writeFrame(
        allocator,
        io,
        stream,
        .headers,
        flag_end_headers,
        1,
        request_block.items,
    );
    var data: [default_max_frame_size]u8 = undefined;
    @memset(&data, 'd');
    try writeFrame(allocator, io, stream, .data, 0, 1, &data);
    try writeFrame(allocator, io, stream, .data, 0, 1, &data);
    try writeFrame(allocator, io, stream, .data, 0, 1, &data);
    try writeFrame(
        allocator,
        io,
        stream,
        .data,
        0,
        1,
        data[0 .. sample_bytes - 3 * default_max_frame_size],
    );

    var probe_payload: ?[8]u8 = null;
    while (probe_payload == null) {
        var frame = try readFrame(allocator, io, stream, .{});
        defer frame.deinit(allocator);
        if (frame.frame.header.frame_type == .ping) {
            try std.testing.expectEqual(
                @as(u8, 0),
                frame.frame.header.flags & flag_ack,
            );
            probe_payload = (try http2.PingPayload.parse(frame.frame)).data;
            try std.testing.expect(bdp.isProbePayload(probe_payload.?));
        }
    }

    // Deliberately acknowledge the probe before the server's initial
    // SETTINGS. The target must remain queued until that older transaction is
    // acknowledged. The final DATA keeps readRequest alive long enough to
    // process both control frames first.
    try writeFrame(
        allocator,
        io,
        stream,
        .ping,
        flag_ack,
        0,
        &probe_payload.?,
    );
    try writeFrame(allocator, io, stream, .settings, flag_ack, 0, &.{});
    try writeFrame(
        allocator,
        io,
        stream,
        .data,
        flag_end_stream,
        1,
        "!",
    );

    var saw_connection_growth = false;
    var saw_adaptive_settings = false;
    while (!saw_adaptive_settings) {
        var frame = try readFrame(allocator, io, stream, .{});
        defer frame.deinit(allocator);
        switch (frame.frame.header.frame_type) {
            .window_update => {
                const update = try http2.WindowUpdatePayload.parse(
                    frame.frame,
                );
                if (update.stream_id == 0 and
                    update.increment ==
                        adaptive_target - default_flow_window)
                {
                    saw_connection_growth = true;
                }
            },
            .settings => {
                try std.testing.expectEqual(
                    @as(u8, 0),
                    frame.frame.header.flags & flag_ack,
                );
                const settings = try http2.parseSettings(
                    allocator,
                    frame.frame.payload,
                );
                defer allocator.free(settings);
                for (settings) |setting| {
                    if (setting.id == .initial_window_size and
                        setting.value == adaptive_target)
                    {
                        saw_adaptive_settings = true;
                    }
                }
            },
            else => {},
        }
    }
    try std.testing.expect(saw_connection_growth);

    try writeFrame(allocator, io, stream, .settings, flag_ack, 0, &.{});
    // Internal probe-shaped requests are acknowledged as connection control
    // and cannot escape through the public user-PING receive API.
    try writeFrame(
        allocator,
        io,
        stream,
        .ping,
        0,
        0,
        &probe_payload.?,
    );
    const user_ping = [_]u8{ 6, 2, 6, 4, 3, 3, 8, 3 };
    try writeFrame(allocator, io, stream, .ping, 0, 0, &user_ping);
    while (true) {
        var frame = try readFrame(allocator, io, stream, .{});
        defer frame.deinit(allocator);
        if (frame.frame.header.frame_type != .ping or
            frame.frame.header.flags & flag_ack == 0) continue;
        const echoed = (try http2.PingPayload.parse(frame.frame)).data;
        if (bdp.isProbePayload(echoed)) continue;
        try std.testing.expectEqualSlices(u8, &user_ping, &echoed);
        break;
    }

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 adaptive window coalesces pending targets" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
        .awaiting_settings_ack = true,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try connection.queueAdaptiveWindowTarget(100_000);
    try connection.queueAdaptiveWindowTarget(80_000);
    try connection.queueAdaptiveWindowTarget(120_000);
    try std.testing.expectEqual(
        @as(?u32, 120_000),
        connection.adaptive_queued_target,
    );
    try std.testing.expectEqual(
        @as(u32, @intCast(default_flow_window)),
        connection.recv_connection_window_target,
    );
    try std.testing.expectEqual(
        @as(u32, @intCast(default_flow_window)),
        connection.recv_stream_window_target,
    );
}

test "HTTP/2 user PING rejects the adaptive probe namespace" {
    var estimator = bdp.Estimator.init(65_535, bdp.default_max_window);
    const probe = estimator.recordData(1, 0) orelse
        return error.TestUnexpectedResult;
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try std.testing.expectError(error.InvalidFrame, connection.ping(probe));
}

test "HTTP/2 client connect handles interleaved PING before settings" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const stream = try shared.listener.accept(shared.io);
            defer stream.close(shared.io);

            var preface: [http2.connection_preface.len]u8 = undefined;
            try readExact(shared.io, stream, &preface);
            try http2.validateClientPreface(&preface);
            var client_settings = try readFrame(shared.allocator, shared.io, stream, .{ .max_frame_payload = 4096 });
            defer client_settings.deinit(shared.allocator);
            try std.testing.expectEqual(http2.FrameType.settings, client_settings.frame.header.frame_type);

            const ping_payload = [_]u8{ 7, 0, 7, 0, 7, 0, 7, 0 };
            try writeFrame(shared.allocator, shared.io, stream, .ping, 0, 0, &ping_payload);
            try writeInitialSettings(shared.allocator, shared.io, stream, .{ .max_frame_payload = 4096 }, .server);
            try writeFrame(shared.allocator, shared.io, stream, .settings, flag_ack, 0, &.{});

            while (true) {
                var frame = try readFrame(shared.allocator, shared.io, stream, .{ .max_frame_payload = 4096 });
                defer frame.deinit(shared.allocator);
                if (frame.frame.header.frame_type == .settings and (frame.frame.header.flags & flag_ack) != 0) continue;
                try std.testing.expectEqual(http2.FrameType.ping, frame.frame.header.frame_type);
                try std.testing.expect((frame.frame.header.flags & flag_ack) != 0);
                try std.testing.expectEqualSlices(u8, &ping_payload, frame.frame.payload);
                break;
            }
        }
    };

    var shared = Shared{ .allocator = allocator, .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, listener.socket.address, .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer client.close();
    try std.testing.expect(!client.awaiting_settings_ack);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 server clears settings ACK on first control read" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            try std.testing.expect(connection.awaiting_settings_ack);

            const observed = try connection.readPing();
            try std.testing.expectEqualSlices(u8, &[_]u8{ 3, 1, 4, 1, 5, 9, 2, 6 }, &observed);
            try std.testing.expect(!connection.awaiting_settings_ack);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer client.close();
    _ = try client.ping(.{ 3, 1, 4, 1, 5, 9, 2, 6 });

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 client connect clears initial settings ACK wait" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            // The server has not read the client's ACK yet after accept returns.
            std.testing.expect(connection.awaiting_settings_ack) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer client.close();
    try std.testing.expect(!client.awaiting_settings_ack);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 rejects unexpected SETTINGS ACK" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    const ack = http2.Frame{
        .header = .{ .length = 0, .frame_type = .settings, .flags = flag_ack, .stream_id = 0 },
        .payload = &.{},
    };
    try std.testing.expectError(error.InvalidFrame, connection.handleConnectionFrame(ack));
    connection.awaiting_settings_ack = true;
    try std.testing.expect(try connection.handleConnectionFrame(ack));
    try std.testing.expect(!connection.awaiting_settings_ack);
    try std.testing.expectError(error.InvalidFrame, connection.handleConnectionFrame(ack));
}

test "HTTP/2 sendGoAway enforces non-increasing boundaries" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try connection.validateLocalGoAway(7);
    connection.local_goaway_last_stream_id = 7;
    try connection.validateLocalGoAway(5);
    connection.local_goaway_last_stream_id = 5;
    try std.testing.expectError(error.InvalidFrame, connection.validateLocalGoAway(7));
    try std.testing.expectEqual(@as(?u31, 5), connection.local_goaway_last_stream_id);
}

test "HTTP/2 readGoAway records monotonic peer boundary" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.response_semantics.deinit(std.testing.allocator);
        connection.response_semantics_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try connection.rememberResponseSemantics(
        1,
        "HEAD",
        null,
        .{},
    );
    try std.testing.expectEqual(@as(?usize, 0), connection.response_semantics_index.get(1));
    try std.testing.expect((connection.responseSemanticsFor(1, .{})).head);
    connection.forgetResponseSemantics(1);
    try std.testing.expectEqual(@as(usize, 0), connection.response_semantics_index.count());
    try std.testing.expect(!(connection.responseSemanticsFor(1, .{})).head);
    connection.forgetResponseSemantics(1);

    try connection.recordPeerGoAway(.{ .last_stream_id = 7, .error_code = .no_error, .debug_data = &.{} });
    try std.testing.expectEqual(@as(?u31, 7), connection.peer_goaway_last_stream_id);
    try std.testing.expect(!connection.peerGoAwayTooManyPings());
    try connection.recordPeerGoAway(.{ .last_stream_id = 5, .error_code = .enhance_your_calm, .debug_data = "too_many_pings" });
    try std.testing.expectEqual(@as(?u31, 5), connection.peer_goaway_last_stream_id);
    try std.testing.expect(connection.peerGoAwayTooManyPings());
    try connection.recordPeerGoAway(.{ .last_stream_id = 5, .error_code = .no_error, .debug_data = &.{} });
    try std.testing.expect(connection.peerGoAwayTooManyPings());
    try std.testing.expectError(error.InvalidFrame, connection.recordPeerGoAway(.{ .last_stream_id = 7, .error_code = .no_error, .debug_data = &.{} }));
    try std.testing.expectEqual(@as(?u31, 5), connection.peer_goaway_last_stream_id);
}

test "HTTP/2 stream idle classification follows initiator cursors" {
    var server_connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
        .last_peer_client_stream_id = 3,
    };
    defer server_connection.push_state.deinit(std.testing.allocator);

    try std.testing.expect(!server_connection.streamIsIdle(1));
    try std.testing.expect(!server_connection.streamIsIdle(3));
    try std.testing.expect(server_connection.streamIsIdle(5));
    try std.testing.expect(server_connection.streamIsIdle(2));
    const reserved = try server_connection.push_state.reserveLocal(
        std.testing.allocator,
    );
    try std.testing.expectEqual(@as(u31, 2), reserved);
    try std.testing.expect(!server_connection.streamIsIdle(2));
    try std.testing.expect(server_connection.streamIsIdle(4));

    var client_connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
        .next_client_stream_id = 5,
    };
    try std.testing.expect(!client_connection.streamIsIdle(1));
    try std.testing.expect(!client_connection.streamIsIdle(3));
    try std.testing.expect(client_connection.streamIsIdle(5));
    try std.testing.expect(client_connection.streamIsIdle(2));
}

test "HTTP/2 continues after RST_STREAM on a half-closed request" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            var request = try connection.readRequest();
            try std.testing.expectEqual(@as(u31, 1), request.stream_id);
            request.deinit(server_ptr.allocator);

            // readRequest must consume the intervening reset rather than
            // terminating the connection before the next request stream.
            var next_request = try connection.readRequest();
            defer next_request.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(u31, 3), next_request.stream_id);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    const first = try client.sendCompleteRequest(.{
        .path = "/reset",
        .authority = "localhost",
    });
    try client.sendResetStream(first.stream_id, .cancel);
    const second = try client.sendCompleteRequest(.{
        .path = "/after-reset",
        .authority = "localhost",
    });
    try std.testing.expectEqual(@as(u31, 3), second.stream_id);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 client ignores in-flight frames after local reset" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            var first = try connection.readRequest();
            defer first.deinit(server_ptr.allocator);
            var second = try connection.readRequest();
            defer second.deinit(server_ptr.allocator);

            try connection.writeHeaders(first.stream_id, &.{.{
                .name = ":status",
                .value = "200",
            }}, false);
            try writeFrame(
                server_ptr.allocator,
                server_ptr.io,
                connection.stream,
                .data,
                0,
                first.stream_id,
                "late",
            );
            try connection.writeHeaders(first.stream_id, &.{.{
                .name = "x-late-trailer",
                .value = "discarded",
            }}, true);
            try connection.writeResponse(second.stream_id, .{
                .status = 200,
                .body = "ok",
                .request_method = second.method,
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    const first = try client.sendCompleteRequest(.{
        .path = "/cancel",
        .authority = "localhost",
    });
    const second = try client.sendCompleteRequest(.{
        .path = "/sibling",
        .authority = "localhost",
    });
    try client.sendResetStream(first.stream_id, .cancel);

    var response = try client.readResponse(
        second.stream_id,
        second.request_method,
        second.extended_connect,
        null,
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("ok", response.body);
    try std.testing.expectEqual(
        @as(i64, default_flow_window - "ok".len),
        client.recv_connection_window.value,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 client drains buffered sibling after reset peer close" {
    const allocator = std.testing.allocator;

    // Model the exact race deterministically: one transport read has already
    // retained both streams, then the peer closes before the client returns
    // connection credit for DATA that raced with its RST_STREAM.
    var buffered_frames: std.ArrayList(u8) = .empty;
    try appendFrameBytes(
        &buffered_frames,
        allocator,
        .data,
        0,
        1,
        "late",
    );
    try appendFrameBytes(
        &buffered_frames,
        allocator,
        .headers,
        flag_end_headers,
        3,
        &.{0x88}, // HPACK static-table index for `:status: 200`.
    );
    try appendFrameBytes(
        &buffered_frames,
        allocator,
        .data,
        flag_end_stream,
        3,
        "ok",
    );

    const ClosedWriter = struct {
        writes: usize = 0,
        fail_with_network_down: bool = false,

        fn now(
            _: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            return .zero;
        }

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            _: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            if (self.fail_with_network_down) return error.NetworkDown;
            return error.SocketUnconnected;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: ClosedWriter = .{};
    var closed_vtable = threaded.io().vtable.*;
    closed_vtable.now = ClosedWriter.now;
    closed_vtable.netWrite = ClosedWriter.write;
    const closed_io = std.Io{
        .userdata = &writer,
        .vtable = &closed_vtable,
    };

    var connection = Connection{
        .io = closed_io,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .frame_reader = .{ .buffer = buffered_frames },
    };
    defer {
        connection.recv_stream_windows.deinit(allocator);
        connection.recv_stream_window_index.deinit(allocator);
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.frame_reader.deinit(allocator);
    }
    try connection.prepareLocallyResetStreamsAt(1, 0);
    connection.rememberLocallyResetStreamAtAssumeCapacity(1, 0);

    var response = try connection.readResponse(3, "GET", false, null);
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), writer.writes);
    try std.testing.expectEqualStrings("ok", response.body);
    try std.testing.expectEqual(
        @as(i64, default_flow_window - "ok".len),
        connection.recv_connection_window.value,
    );

    connection.recv_connection_window.value -= 7;
    writer.fail_with_network_down = true;
    try std.testing.expectError(
        error.NetworkDown,
        connection.releaseLateResetConnectionCapacity(7),
    );
    // Non-terminal transport failures remain observable and the generic
    // WINDOW_UPDATE transaction must roll its optimistic accounting back.
    try std.testing.expectEqual(
        @as(i64, default_flow_window - "ok".len - 7),
        connection.recv_connection_window.value,
    );
}

test "HTTP/2 ignores unknown extension connection frames" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
    };

    try std.testing.expect(try connection.handleConnectionFrame(.{
        .header = .{
            .length = 3,
            .frame_type = @enumFromInt(0xff),
            .flags = 0xa5,
            .stream_id = 0,
        },
        .payload = "ext",
    }));
    try std.testing.expect(!try connection.handleConnectionFrame(.{
        .header = .{
            .length = 0,
            .frame_type = .data,
            .flags = flag_end_stream,
            .stream_id = 1,
        },
        .payload = &.{},
    }));
}

test "HTTP/2 ignores WINDOW_UPDATE for inactive streams" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
        .next_client_stream_id = 3,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    const inactive_update = http2.Frame{
        .header = .{ .length = 4, .frame_type = .window_update, .flags = 0, .stream_id = 1 },
        .payload = &.{ 0, 0, 0, 10 },
    };
    try std.testing.expect(try connection.handleConnectionFrame(inactive_update));
    try std.testing.expectEqual(@as(usize, 0), connection.send_stream_windows.items.len);

    try connection.addActiveLocalStream(1);
    try std.testing.expect(try connection.handleConnectionFrame(inactive_update));
    try std.testing.expectEqual(@as(usize, 1), connection.send_stream_windows.items.len);
    try std.testing.expectEqual(@as(i64, default_flow_window + 10), (try connection.sendStreamWindow(1)).value);

    const peer_update = http2.Frame{
        .header = .{ .length = 4, .frame_type = .window_update, .flags = 0, .stream_id = 3 },
        .payload = &.{ 0, 0, 0, 7 },
    };
    try connection.addActivePeerStream(3);
    try std.testing.expect(try connection.handleConnectionFrame(peer_update));
    try std.testing.expectEqual(@as(i64, default_flow_window + 7), (try connection.sendStreamWindow(3)).value);
}

test "HTTP/2 stream window helpers reject connection stream id" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try std.testing.expectError(error.InvalidStreamId, connection.sendStreamWindow(0));
    try std.testing.expectError(error.InvalidStreamId, connection.recvStreamWindow(0));
    try std.testing.expectEqual(@as(usize, 0), connection.send_stream_windows.items.len);
    try std.testing.expectEqual(@as(usize, 0), connection.recv_stream_windows.items.len);
}

test "HTTP/2 reset retirement clears both stream windows" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    _ = try connection.sendStreamWindow(1);
    _ = try connection.recvStreamWindow(1);
    connection.forgetStreamWindows(1);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.send_stream_windows.items.len,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.recv_stream_windows.items.len,
    );
    try std.testing.expect(!connection.send_stream_window_index.contains(1));
    try std.testing.expect(!connection.recv_stream_window_index.contains(1));
}

test "HTTP/2 local reset history honors capacity and retention duration" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .limits = .{ .max_reset_stream_history = 2 },
    };
    defer {
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
    }

    const second: i96 = std.time.ns_per_s;
    try connection.prepareLocallyResetStreamsAt(3, 0);
    try std.testing.expect(connection.locally_reset_streams.capacity >= 2);
    connection.rememberLocallyResetStreamAtAssumeCapacity(1, 0);
    connection.rememberLocallyResetStreamAtAssumeCapacity(3, 0);
    try std.testing.expectEqual(
        connection.locallyResetStreamCount(),
        connection.locally_reset_stream_index.count(),
    );
    // Duplicate resets do not consume another slot.
    connection.rememberLocallyResetStreamAtAssumeCapacity(1, second / 2);
    try std.testing.expectEqual(
        @as(usize, 2),
        connection.locallyResetStreamCount(),
    );
    // Capacity pressure cannot evict IDs before their minimum retention time.
    connection.rememberLocallyResetStreamAtAssumeCapacity(5, second / 2);
    try std.testing.expectEqual(
        connection.locallyResetStreamCount(),
        connection.locally_reset_stream_index.count(),
    );
    try std.testing.expect(connection.wasLocallyResetAt(1, second));
    try std.testing.expect(connection.wasLocallyResetAt(3, second));
    try std.testing.expect(!connection.wasLocallyResetAt(5, second));

    // Expiration is strict: exactly one second remains tolerated, while the
    // first later nanosecond reclaims both FIFO entries for new resets.
    connection.rememberLocallyResetStreamAtAssumeCapacity(5, second + 1);
    connection.rememberLocallyResetStreamAtAssumeCapacity(7, second + 1);
    try std.testing.expectEqual(
        connection.locallyResetStreamCount(),
        connection.locally_reset_stream_index.count(),
    );
    try std.testing.expect(!connection.wasLocallyResetAt(1, second + 1));
    try std.testing.expect(!connection.wasLocallyResetAt(3, second + 1));
    try std.testing.expect(connection.wasLocallyResetAt(5, second + 1));
    try std.testing.expect(connection.wasLocallyResetAt(7, second + 1));

    // An expired duplicate is a fresh reset and receives a new retention
    // deadline instead of being discarded by a stale hash hit.
    connection.rememberLocallyResetStreamAtAssumeCapacity(5, 2 * second + 2);
    try std.testing.expect(connection.wasLocallyResetAt(5, 3 * second + 2));
    try std.testing.expect(!connection.wasLocallyResetAt(5, 3 * second + 3));
}

test "HTTP/2 local reset history may be disabled" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .limits = .{ .max_reset_stream_history = 0 },
    };
    defer {
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
    }

    try connection.prepareLocallyResetStreamsAt(1, 0);
    connection.rememberLocallyResetStreamAtAssumeCapacity(1, 0);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.locally_reset_streams.capacity,
    );
    try std.testing.expect(!connection.wasLocallyResetAt(1, 0));
}

test "HTTP/2 configured reset history controls late-frame tolerance" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .limits = .{ .max_reset_stream_history = 1 },
    };
    defer {
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
    }

    try connection.prepareLocallyResetStreamsAt(2, 0);
    connection.rememberLocallyResetStreamAtAssumeCapacity(1, 0);
    connection.rememberLocallyResetStreamAtAssumeCapacity(3, 0);
    const reset_payload = [_]u8{ 0, 0, 0, 8 };
    try std.testing.expect(try connection
        .discardLateFrameForLocallyResetStreamAt(.{
        .header = .{
            .length = reset_payload.len,
            .frame_type = .rst_stream,
            .flags = 0,
            .stream_id = 1,
        },
        .payload = &reset_payload,
    }, 0));
    try std.testing.expect(!try connection
        .discardLateFrameForLocallyResetStreamAt(.{
        .header = .{
            .length = reset_payload.len,
            .frame_type = .rst_stream,
            .flags = 0,
            .stream_id = 3,
        },
        .payload = &reset_payload,
    }, 0));
}

test "HTTP/2 local protocol error reset budget emits terminal GOAWAY" {
    const allocator = std.testing.allocator;
    const RecordingWriter = struct {
        var active: std.atomic.Value(?*@This()) = .init(null);
        bytes: std.ArrayList(u8) = .empty,

        fn write(
            _: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            data: []const []const u8,
            splat: usize,
        ) net.Stream.Writer.Error!usize {
            const self = active.load(.acquire).?;
            var total = header.len;
            self.bytes.appendSlice(allocator, header) catch
                return error.SystemResources;
            for (data[0 .. data.len - 1]) |part| {
                total += part.len;
                self.bytes.appendSlice(allocator, part) catch
                    return error.SystemResources;
            }
            var repeated: usize = 0;
            while (repeated < splat) : (repeated += 1) {
                total += data[data.len - 1].len;
                self.bytes.appendSlice(
                    allocator,
                    data[data.len - 1],
                ) catch return error.SystemResources;
            }
            return total;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: RecordingWriter = .{};
    defer writer.bytes.deinit(allocator);
    RecordingWriter.active.store(&writer, .release);
    defer RecordingWriter.active.store(null, .release);
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = RecordingWriter.write;
    var connection = Connection{
        .io = .{ .userdata = threaded.io().userdata, .vtable = &vtable },
        .allocator = allocator,
        .stream = test_socket.stream(),
        .role = .server,
        .limits = .{ .max_local_error_reset_streams = 1 },
        .last_peer_processed_stream_id = 3,
    };
    defer {
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
    }

    try connection.writeLocalErrorResetStream(
        1,
        .flow_control_error,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        connection.local_error_reset_streams,
    );
    try std.testing.expect(!connection.aggregate_timeout_unusable);

    const reset_frame = try http2.Frame.parse(writer.bytes.items);
    try std.testing.expectEqual(
        http2.FrameType.rst_stream,
        reset_frame.header.frame_type,
    );
    const reset = try http2.ResetStreamPayload.parse(reset_frame);
    try std.testing.expectEqual(@as(u31, 1), reset.stream_id);
    try std.testing.expectEqual(
        http2.ErrorCode.flow_control_error,
        reset.error_code,
    );

    try std.testing.expectError(
        error.ConnectionGoAway,
        connection.writeLocalErrorResetStream(3, .protocol_error),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        connection.local_error_reset_streams,
    );
    try std.testing.expect(connection.aggregate_timeout_unusable);

    const goaway_frame = try http2.Frame.parse(
        writer.bytes.items[reset_frame.consumed()..],
    );
    try std.testing.expectEqual(
        http2.FrameType.goaway,
        goaway_frame.header.frame_type,
    );
    const goaway = try http2.GoAwayPayload.parse(goaway_frame);
    try std.testing.expectEqual(@as(u31, 3), goaway.last_stream_id);
    try std.testing.expectEqual(
        http2.ErrorCode.enhance_your_calm,
        goaway.error_code,
    );
    try std.testing.expectEqualStrings(
        "too_many_internal_resets",
        goaway.debug_data,
    );
    try std.testing.expectEqual(
        writer.bytes.items.len,
        reset_frame.consumed() + goaway_frame.consumed(),
    );
}

test "HTTP/2 excessive padded empty DATA emits terminal GOAWAY" {
    const allocator = std.testing.allocator;
    const RecordingWriter = struct {
        var active: std.atomic.Value(?*@This()) = .init(null);
        bytes: std.ArrayList(u8) = .empty,

        fn write(
            _: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            data: []const []const u8,
            splat: usize,
        ) net.Stream.Writer.Error!usize {
            const self = active.load(.acquire).?;
            var total = header.len;
            self.bytes.appendSlice(allocator, header) catch
                return error.SystemResources;
            for (data[0 .. data.len - 1]) |part| {
                total += part.len;
                self.bytes.appendSlice(allocator, part) catch
                    return error.SystemResources;
            }
            for (0..splat) |_| {
                const part = data[data.len - 1];
                total += part.len;
                self.bytes.appendSlice(allocator, part) catch
                    return error.SystemResources;
            }
            return total;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: RecordingWriter = .{};
    defer writer.bytes.deinit(allocator);
    RecordingWriter.active.store(&writer, .release);
    defer RecordingWriter.active.store(null, .release);
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = RecordingWriter.write;
    var connection = Connection{
        .io = .{ .userdata = threaded.io().userdata, .vtable = &vtable },
        .allocator = allocator,
        .stream = test_socket.stream(),
        .role = .server,
        .last_peer_processed_stream_id = 1,
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.recv_stream_windows.deinit(allocator);
        connection.recv_stream_window_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }
    connection.applyLocalLimits();

    // PADDED with Pad Length 1 and one padding octet has no application
    // payload. Flow control still charges both bytes, while the independent
    // lifetime frame-count guard rejects the 101st non-final empty DATA.
    const padded_empty = [_]u8{ 1, 0 };
    const frame = http2.Frame{
        .header = .{
            .length = padded_empty.len,
            .frame_type = .data,
            .flags = 0x08,
            .stream_id = 1,
        },
        .payload = &padded_empty,
    };
    for (0..data_frame_budget.max_empty_frames) |_| {
        const data = try connection.receiveDataPayload(1, frame);
        defer connection.releaseDataFrameBudget(data);
        try std.testing.expectEqual(@as(usize, 0), data.data.len);
    }
    try std.testing.expectError(
        error.ConnectionGoAway,
        connection.receiveDataPayload(1, frame),
    );
    try std.testing.expect(connection.aggregate_timeout_unusable);

    const goaway_frame = try http2.Frame.parse(writer.bytes.items);
    try std.testing.expectEqual(
        http2.FrameType.goaway,
        goaway_frame.header.frame_type,
    );
    const goaway = try http2.GoAwayPayload.parse(goaway_frame);
    try std.testing.expectEqual(@as(u31, 1), goaway.last_stream_id);
    try std.testing.expectEqual(
        http2.ErrorCode.enhance_your_calm,
        goaway.error_code,
    );
    try std.testing.expectEqualStrings(
        "too_many_data_frames",
        goaway.debug_data,
    );
}

test "HTTP/2 application reset does not consume protocol error budget" {
    const allocator = std.testing.allocator;
    const RecordingWriter = struct {
        bytes: [http2.ResetStreamPayload.encoded_len]u8 = undefined,
        len: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            const count = @min(header.len, self.bytes.len - self.len);
            if (count == 0) return error.SocketUnconnected;
            @memcpy(self.bytes[self.len..][0..count], header[0..count]);
            self.len += count;
            return count;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: RecordingWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = RecordingWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .limits = .{ .max_local_error_reset_streams = 0 },
    };
    defer {
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
    }
    try connection.addActiveLocalStream(1);

    try connection.sendResetStream(1, .cancel);
    try std.testing.expectEqual(@as(usize, 0), connection.local_error_reset_streams);
    try std.testing.expect(!connection.aggregate_timeout_unusable);
    const frame = try http2.Frame.parse(writer.bytes[0..writer.len]);
    const reset = try http2.ResetStreamPayload.parse(frame);
    try std.testing.expectEqual(http2.ErrorCode.cancel, reset.error_code);
}

test "HTTP/2 local protocol error reset budget may be disabled" {
    const allocator = std.testing.allocator;
    const RecordingWriter = struct {
        bytes: [2 * http2.ResetStreamPayload.encoded_len]u8 = undefined,
        len: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            const count = @min(header.len, self.bytes.len - self.len);
            if (count == 0) return error.SocketUnconnected;
            @memcpy(self.bytes[self.len..][0..count], header[0..count]);
            self.len += count;
            return count;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: RecordingWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = RecordingWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{ .max_local_error_reset_streams = null },
    };
    defer {
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
    }

    try connection.writeLocalErrorResetStream(1, .protocol_error);
    try connection.writeLocalErrorResetStream(3, .flow_control_error);
    try std.testing.expectEqual(@as(usize, 2), connection.local_error_reset_streams);
    try std.testing.expect(!connection.aggregate_timeout_unusable);
    try std.testing.expectEqual(@sizeOf(@TypeOf(writer.bytes)), writer.len);
}

test "HTTP/2 failed protocol error reset write is terminal and uncounted" {
    const FailingWriter = struct {
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            if (self.writes == 1) return @min(header.len, 4);
            return error.NetworkDown;
        }
    };

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var writer: FailingWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = FailingWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.locally_reset_streams.deinit(std.testing.allocator);
        connection.locally_reset_stream_index.deinit(std.testing.allocator);
    }

    try std.testing.expectError(
        error.NetworkDown,
        connection.writeLocalErrorResetStream(1, .protocol_error),
    );
    try std.testing.expectEqual(@as(usize, 0), connection.local_error_reset_streams);
    try std.testing.expect(connection.aggregate_timeout_unusable);
}

test "HTTP/2 abandoning peer request releases state after reset write failure" {
    if (comptime builtin.os.tag != .linux) return;
    const allocator = std.testing.allocator;
    const FailingWriter = struct {
        fn write(
            _: ?*anyopaque,
            _: net.Socket.Handle,
            _: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            return error.NetworkDown;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try @import("runtime/testing/blocked_output.zig").BlockedOutput.init(io, .server);
    defer fixture.deinit();
    const connection = &fixture.connection;
    var vtable = io.vtable.*;
    vtable.netWrite = FailingWriter.write;
    connection.io = .{ .userdata = io.userdata, .vtable = &vtable };
    defer connection.io = io;
    connection.limits = .{
        .max_concurrent_streams = 1,
        .max_reset_stream_history = 0,
    };

    try connection.reservePeerStream(1);
    try connection.rememberResponseSemantics(1, "POST", null, .{});
    _ = try connection.sendStreamWindow(1);
    _ = try connection.recvStreamWindow(1);
    try std.testing.expect(connection.outboundStreamIsActive(1));
    try std.testing.expect(connection.hasRecvStreamWindow(1));

    connection.abandonPeerRequest(1, .internal_error);
    try std.testing.expect(!connection.outboundStreamIsActive(1));
    try std.testing.expect(!connection.hasRecvStreamWindow(1));
    try std.testing.expect(!connection.response_semantics_index.contains(1));
    try std.testing.expect(connection.priority_state.get(1) == null);

    // The failed best-effort RST must not strand the sole concurrency slot.
    try connection.reservePeerStream(3);
    try std.testing.expect(connection.outboundStreamIsActive(3));
}

test "HTTP/2 reset history allocation failure precedes wire write" {
    const allocator = std.testing.allocator;
    const RecordingWriter = struct {
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            _: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            return error.SocketUnconnected;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: RecordingWriter = .{};
    var recording_vtable = threaded.io().vtable.*;
    recording_vtable.netWrite = RecordingWriter.write;
    const recording_io = std.Io{
        .userdata = &writer,
        .vtable = &recording_vtable,
    };
    var connection = Connection{
        .io = recording_io,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .limits = .{ .max_reset_stream_history = 1 },
    };
    defer {
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
    }
    try connection.addActiveLocalStream(1);

    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    connection.allocator = failing.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        connection.sendResetStream(1, .cancel),
    );
    connection.allocator = allocator;
    try std.testing.expectEqual(@as(usize, 0), writer.writes);
    try std.testing.expect(connection.outboundStreamIsActive(1));
    try std.testing.expect(!connection.wasLocallyResetAt(1, 0));
}

test "HTTP/2 refusal reserves reset history before consuming headers" {
    const allocator = std.testing.allocator;
    const RecordingWriter = struct {
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            _: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            return error.SocketUnconnected;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: RecordingWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = RecordingWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{
            .max_concurrent_streams = 1,
            .max_reset_stream_history = 1,
        },
    };
    defer {
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
    }
    try connection.active_peer_streams.ensureUnusedCapacity(allocator, 1);
    try connection.active_peer_index.ensureUnusedCapacity(allocator, 1);
    try std.testing.expectEqual(
        Connection.PeerRequestAdmission.admitted,
        try connection.claimPeerRequestStream(1),
    );
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    connection.allocator = failing.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        connection.claimPeerRequestStream(3),
    );
    connection.allocator = allocator;
    try std.testing.expectEqual(@as(usize, 0), writer.writes);
    try std.testing.expectEqual(@as(u31, 1), connection.last_peer_client_stream_id);
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expect(!connection.wasLocallyResetAt(3, 0));
}

test "HTTP/2 refusal write failure makes later request reads terminal" {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            if (self.writes == 1) return @min(header.len, 4);
            return error.NetworkDown;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: PartialWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = PartialWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{ .max_reset_stream_history = 1 },
    };
    defer {
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
    }

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/refused" },
        .{ .name = ":scheme", .value = "https" },
    });
    try std.testing.expectError(
        error.NetworkDown,
        connection.refusePeerRequestStreamUntil(
            3,
            .{
                .header = .{
                    .length = @intCast(block.items.len),
                    .frame_type = .headers,
                    .flags = flag_end_headers,
                    .stream_id = 3,
                },
                .payload = block.items,
            },
            null,
            false,
        ),
    );
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expectError(error.ConnectionClosed, connection.readRequest());
    try std.testing.expect(!connection.wasLocallyResetAt(3, 0));
}

test "HTTP/2 refusal decode failure makes later request reads terminal" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{ .max_reset_stream_history = 1 },
    };
    defer {
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
    }

    try std.testing.expectError(
        error.MessageTooLarge,
        connection.refusePeerRequestStreamUntil(
            3,
            .{
                .header = .{
                    .length = 1,
                    .frame_type = .headers,
                    .flags = flag_end_headers,
                    .stream_id = 3,
                },
                // An indexed integer whose continuation byte is missing.
                .payload = &.{0xff},
            },
            null,
            false,
        ),
    );
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expectError(error.ConnectionClosed, connection.readRequest());
}

test "HTTP/2 sendWindowUpdate rejects idle streams" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    // h2 only releases capacity for streams that exist in the state machine.
    // Sending WINDOW_UPDATE on an idle stream is a protocol error, so the
    // helper refuses before it mutates receive-window bookkeeping or writes.
    try std.testing.expectError(error.InvalidStreamId, connection.sendWindowUpdate(1, 1));
    try std.testing.expectEqual(@as(usize, 0), connection.recv_stream_windows.items.len);
}

test "HTTP/2 local initial window config seeds receive stream windows" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{ .initial_window_size = 1024 },
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try std.testing.expectEqual(@as(i64, 1024), (try connection.recvStreamWindow(1)).value);
    try std.testing.expectEqual(@as(?usize, 0), connection.recv_stream_window_index.get(1));
}

test "HTTP/2 peer max concurrent streams limits locally opened streams" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
        .peer_max_concurrent_streams = 1,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try std.testing.expectEqual(
        @as(?u32, 1),
        connection.peerMaxConcurrentStreams(),
    );
    try std.testing.expectEqual(
        @as(?u32, 1),
        connection.availableLocalStreamCapacity(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.activeLocalStreamCount(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.activePeerStreamCount(),
    );
    try std.testing.expect(!connection.peerExtendedConnectEnabled());

    const first = try connection.reserveNextClientStreamId();
    try std.testing.expectEqual(@as(u31, 1), first);
    try std.testing.expectEqual(@as(usize, 1), connection.active_local_streams.items.len);
    try std.testing.expectEqual(@as(?usize, 0), connection.active_local_index.get(first));
    try std.testing.expectEqual(
        @as(?u32, 0),
        connection.availableLocalStreamCapacity(),
    );
    try std.testing.expectError(error.FlowControlBlocked, connection.reserveNextClientStreamId());
    try std.testing.expectEqual(@as(u31, 3), connection.next_client_stream_id);

    connection.releaseLocalStream(first);
    try std.testing.expectEqual(
        @as(?u32, 1),
        connection.availableLocalStreamCapacity(),
    );
    const second = try connection.reserveNextClientStreamId();
    try std.testing.expectEqual(@as(u31, 3), second);
    try std.testing.expectEqual(@as(usize, 1), connection.active_local_streams.items.len);
    try std.testing.expectEqual(@as(?usize, 0), connection.active_local_index.get(second));
    connection.releaseLocalStream(second);
    try std.testing.expectEqual(@as(usize, 0), connection.active_local_streams.items.len);
    try std.testing.expectEqual(@as(usize, 0), connection.active_local_index.count());
    connection.releaseLocalStream(second);
    try std.testing.expectEqual(@as(usize, 0), connection.active_local_streams.items.len);

    const third = try connection.reserveNextClientStreamId();
    try std.testing.expectEqual(@as(u31, 5), third);
    try std.testing.expectError(error.ConnectionGoAway, connection.handleGoAwayForStream(third, .{
        .last_stream_id = 3,
        .error_code = .no_error,
        .debug_data = &.{},
    }));
    try std.testing.expectEqual(@as(usize, 0), connection.active_local_streams.items.len);
    try std.testing.expectError(error.InvalidFrame, connection.handleGoAwayForStream(1, .{
        .last_stream_id = 5,
        .error_code = .no_error,
        .debug_data = &.{},
    }));
}

test "HTTP/2 available local stream capacity matches priority reservations" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .peer_max_concurrent_streams = 2,
    };
    defer {
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.priority_state.deinit(allocator);
    }

    try std.testing.expectEqual(
        @as(?u32, 2),
        connection.availableLocalStreamCapacity(),
    );
    try connection.priority_state.reserveIdleRequest(
        allocator,
        3,
        connection.activeLocalStreamCount(),
        connection.peerMaxConcurrentStreams(),
        connection.limits.max_idle_priority_updates,
    );
    try std.testing.expectEqual(
        @as(?u32, 1),
        connection.availableLocalStreamCapacity(),
    );
    try connection.priority_state.reserveIdleRequest(
        allocator,
        connection.next_client_stream_id,
        connection.activeLocalStreamCount(),
        connection.peerMaxConcurrentStreams(),
        connection.limits.max_idle_priority_updates,
    );
    // The next request consumes its existing reservation rather than charging
    // the peer limit twice. One later unreserved stream also still fits.
    try std.testing.expectEqual(
        @as(?u32, 1),
        connection.availableLocalStreamCapacity(),
    );
    const first = try connection.reserveNextClientStreamId();
    try std.testing.expectEqual(@as(u31, 1), first);
    try std.testing.expectEqual(
        @as(?u32, 1),
        connection.availableLocalStreamCapacity(),
    );
    const second = try connection.reserveNextClientStreamId();
    try std.testing.expectEqual(@as(u31, 3), second);
    try std.testing.expectEqual(
        @as(?u32, 0),
        connection.availableLocalStreamCapacity(),
    );
}

test "HTTP/2 public peer capabilities track SETTINGS updates" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn writeSettingsUpdate(
            self: *@This(),
            stream: net.Stream,
            settings: []const http2.Setting,
        ) !void {
            var payload: std.ArrayList(u8) = .empty;
            defer payload.deinit(self.allocator);
            try http2.writeSettings(&payload, self.allocator, settings);
            try writeFrame(
                self.allocator,
                self.io,
                stream,
                .settings,
                0,
                0,
                payload.items,
            );
        }

        fn waitForSettingsAckAndPing(
            self: *@This(),
            stream: net.Stream,
            expected_ping: [8]u8,
        ) !void {
            var saw_settings_ack = false;
            var saw_ping = false;
            while (!saw_settings_ack or !saw_ping) {
                var frame = try readFrame(
                    self.allocator,
                    self.io,
                    stream,
                    .{},
                );
                defer frame.deinit(self.allocator);
                switch (frame.frame.header.frame_type) {
                    .settings => {
                        try std.testing.expect(
                            frame.frame.header.flags & flag_ack != 0,
                        );
                        saw_settings_ack = true;
                    },
                    .ping => {
                        try std.testing.expectEqual(
                            @as(u8, 0),
                            frame.frame.header.flags & flag_ack,
                        );
                        const ping = try http2.PingPayload.parse(frame.frame);
                        try std.testing.expectEqualSlices(
                            u8,
                            &expected_ping,
                            &ping.data,
                        );
                        try writeFrame(
                            self.allocator,
                            self.io,
                            stream,
                            .ping,
                            flag_ack,
                            0,
                            &ping.data,
                        );
                        saw_ping = true;
                    },
                    else => return error.UnexpectedFrame,
                }
            }
        }

        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            var preface: [http2.connection_preface.len]u8 = undefined;
            try readExact(self.io, stream, &preface);
            try http2.validateClientPreface(&preface);

            var client_settings = try readFrame(
                self.allocator,
                self.io,
                stream,
                .{},
            );
            defer client_settings.deinit(self.allocator);
            try std.testing.expectEqual(
                http2.FrameType.settings,
                client_settings.frame.header.frame_type,
            );
            try std.testing.expectEqual(
                @as(u8, 0),
                client_settings.frame.header.flags & flag_ack,
            );

            try self.writeSettingsUpdate(stream, &.{
                .{
                    .id = .max_concurrent_streams,
                    .value = 3,
                },
                // RFC 9113 permits a server to make its effective zero value
                // explicit; the client must reject only value 1.
                .{ .id = .enable_push, .value = 0 },
            });
            try writeFrame(
                self.allocator,
                self.io,
                stream,
                .settings,
                flag_ack,
                0,
                &.{},
            );
            var initial_ack = try readFrame(
                self.allocator,
                self.io,
                stream,
                .{},
            );
            defer initial_ack.deinit(self.allocator);
            try std.testing.expectEqual(
                http2.FrameType.settings,
                initial_ack.frame.header.frame_type,
            );
            try std.testing.expect(
                initial_ack.frame.header.flags & flag_ack != 0,
            );

            try self.writeSettingsUpdate(stream, &.{
                .{ .id = .max_concurrent_streams, .value = 1 },
                .{ .id = .enable_connect_protocol, .value = 1 },
            });
            const first_ping = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
            try self.waitForSettingsAckAndPing(stream, first_ping);

            try self.writeSettingsUpdate(stream, &.{.{
                .id = .max_concurrent_streams,
                .value = 4,
            }});
            const second_ping = [_]u8{ 8, 7, 6, 5, 4, 3, 2, 1 };
            try self.waitForSettingsAckAndPing(stream, second_ping);
        }
    };

    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .listener = &listener,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(
        allocator,
        io,
        listener.socket.address,
        .{},
    );
    defer client.close();
    try std.testing.expectEqual(
        @as(?u32, 3),
        client.peerMaxConcurrentStreams(),
    );
    try std.testing.expectEqual(
        @as(?u32, 3),
        client.availableLocalStreamCapacity(),
    );
    try std.testing.expect(!client.peerExtendedConnectEnabled());

    const first_ping = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    try std.testing.expectEqualSlices(u8, &first_ping, &(try client.ping(first_ping)));
    try std.testing.expectEqual(
        @as(?u32, 1),
        client.peerMaxConcurrentStreams(),
    );
    try std.testing.expectEqual(
        @as(?u32, 1),
        client.availableLocalStreamCapacity(),
    );
    try std.testing.expect(client.peerExtendedConnectEnabled());

    const second_ping = [_]u8{ 8, 7, 6, 5, 4, 3, 2, 1 };
    try std.testing.expectEqualSlices(
        u8,
        &second_ping,
        &(try client.ping(second_ping)),
    );
    try std.testing.expectEqual(
        @as(?u32, 4),
        client.peerMaxConcurrentStreams(),
    );
    try std.testing.expectEqual(
        @as(?u32, 4),
        client.availableLocalStreamCapacity(),
    );
    try std.testing.expect(client.peerExtendedConnectEnabled());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 client stream id allocation detects overflow" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
        .next_client_stream_id = std.math.maxInt(u31),
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    // Rust h2's StreamId::next_id returns an overflow error instead of wrapping
    // once the 31-bit stream-id space is exhausted.  Keep the same invariant so
    // long-lived clients cannot wrap to an invalid/previously-used stream id.
    try std.testing.expectError(error.InvalidStreamId, connection.reserveNextClientStreamId());
    try std.testing.expectEqual(@as(u31, std.math.maxInt(u31)), connection.next_client_stream_id);
    try std.testing.expectEqual(@as(usize, 0), connection.active_local_streams.items.len);
}

test "HTTP/2 active stream releases skip empty indexes" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
        connection.push_state.deinit(std.testing.allocator);
        connection.priority_state.deinit(std.testing.allocator);
        connection.response_semantics.deinit(std.testing.allocator);
        connection.response_semantics_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    // Release paths are frequently called from reset/cleanup code for streams
    // that may already be gone.  With empty indexes they should stay as cheap
    // no-ops and avoid probing the hash maps.
    try std.testing.expect(!connection.removeActiveLocalStream(1));
    try std.testing.expect(!connection.removeActivePeerStream(1));
    connection.releaseLocalStream(1);
    connection.releasePeerStream(1);
    try std.testing.expectEqual(@as(usize, 0), connection.active_local_index.count());
    try std.testing.expectEqual(@as(usize, 0), connection.active_peer_index.count());
}

test "HTTP/2 local max concurrent streams limits peer opened streams" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{ .max_concurrent_streams = 1 },
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
        connection.locally_reset_streams.deinit(std.testing.allocator);
        connection.locally_reset_stream_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try connection.reservePeerStream(1);
    try std.testing.expectEqual(@as(usize, 1), connection.active_peer_streams.items.len);
    try std.testing.expectEqual(@as(?usize, 0), connection.active_peer_index.get(1));
    try std.testing.expectError(error.FlowControlViolation, connection.reservePeerStream(3));
    connection.releasePeerStream(1);
    try connection.reservePeerStream(3);
    try std.testing.expectEqual(@as(usize, 1), connection.active_peer_streams.items.len);

    try std.testing.expectError(error.InvalidContentLength, connection.writeResponse(3, .{
        .status = 204,
        .body = "must not send",
    }));
    try std.testing.expectEqual(@as(usize, 1), connection.active_peer_streams.items.len);
    try std.testing.expectError(error.FlowControlViolation, connection.reservePeerStream(5));

    connection.releasePeerStream(3);
    try std.testing.expectEqual(@as(usize, 0), connection.active_peer_streams.items.len);
    try connection.reservePeerStream(5);
    try std.testing.expectError(error.InvalidStatus, connection.rejectExtendedConnect(5, 200, &.{}));
    try std.testing.expectError(
        error.InvalidContentLength,
        connection.rejectExtendedConnectWithBody(
            5,
            304,
            &.{},
            "not allowed",
            &.{},
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), connection.active_peer_streams.items.len);
    connection.releasePeerStream(5);
    try std.testing.expectEqual(@as(usize, 0), connection.active_peer_streams.items.len);
}

test "HTTP/2 refused request advances observed but not processed boundary" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{
            .max_concurrent_streams = 1,
            .max_reset_stream_history = 0,
        },
    };
    defer {
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
        connection.priority_state.deinit(allocator);
    }

    try std.testing.expectEqual(
        Connection.PeerRequestAdmission.admitted,
        try connection.claimPeerRequestStream(1),
    );
    try std.testing.expectEqual(
        Connection.PeerRequestAdmission.refused,
        try connection.claimPeerRequestStream(3),
    );
    try std.testing.expectEqual(@as(u31, 3), connection.last_peer_client_stream_id);
    try std.testing.expectEqual(@as(u31, 1), connection.lastPeerProcessedStreamId());
    connection.releasePeerStream(1);
    try std.testing.expectEqual(
        Connection.PeerRequestAdmission.admitted,
        try connection.claimPeerRequestStream(5),
    );
    try std.testing.expectEqual(@as(u31, 5), connection.lastPeerProcessedStreamId());
}

test "HTTP/2 SETTINGS_MAX_FRAME_SIZE controls outbound DATA splitting" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        data_lengths: [4]usize = [_]usize{0} ** 4,
        data_count: usize = 0,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var stream = try shared.listener.accept(shared.io);
            defer stream.close(shared.io);
            const limits = Limits{ .max_frame_payload = 64 * 1024, .max_body_bytes = 128 * 1024, .max_frame_size = 20_000 };

            var preface_buf: [http2.connection_preface.len]u8 = undefined;
            try readExact(shared.io, stream, &preface_buf);
            try http2.validateClientPreface(&preface_buf);

            var client_settings = try readFrame(shared.allocator, shared.io, stream, limits);
            defer client_settings.deinit(shared.allocator);
            try std.testing.expectEqual(http2.FrameType.settings, client_settings.frame.header.frame_type);
            try std.testing.expectEqual(@as(u8, 0), client_settings.frame.header.flags & flag_ack);

            var settings_payload: std.ArrayList(u8) = .empty;
            defer settings_payload.deinit(shared.allocator);
            try http2.writeSettings(&settings_payload, shared.allocator, &.{
                .{ .id = .max_frame_size, .value = 20_000 },
            });
            try writeFrame(shared.allocator, shared.io, stream, .settings, 0, 0, settings_payload.items);
            try writeFrame(shared.allocator, shared.io, stream, .settings, flag_ack, 0, &.{});

            var client_ack = try readFrame(shared.allocator, shared.io, stream, limits);
            defer client_ack.deinit(shared.allocator);
            try std.testing.expectEqual(http2.FrameType.settings, client_ack.frame.header.frame_type);
            try std.testing.expect((client_ack.frame.header.flags & flag_ack) != 0);

            var request_stream_id: u31 = 0;
            while (true) {
                var frame = try readFrame(shared.allocator, shared.io, stream, limits);
                defer frame.deinit(shared.allocator);
                switch (frame.frame.header.frame_type) {
                    .headers => {
                        request_stream_id = frame.frame.header.stream_id;
                    },
                    .data => {
                        const data = try http2.DataPayload.parse(frame.frame);
                        try std.testing.expect(shared.data_count < shared.data_lengths.len);
                        shared.data_lengths[shared.data_count] = data.data.len;
                        shared.data_count += 1;
                        if ((frame.frame.header.flags & flag_end_stream) != 0) break;
                    },
                    else => {},
                }
            }

            try std.testing.expectEqual(@as(u31, 1), request_stream_id);
            var response_block: std.ArrayList(u8) = .empty;
            defer response_block.deinit(shared.allocator);
            try http2.Hpack.encodeLiteralBlock(&response_block, shared.allocator, &.{
                .{ .name = ":status", .value = "200" },
            });
            try writeFrame(shared.allocator, shared.io, stream, .headers, flag_end_headers | flag_end_stream, request_stream_id, response_block.items);
        }
    };

    var shared = Shared{ .allocator = allocator, .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const body = try allocator.alloc(u8, 45_000);
    defer allocator.free(body);
    @memset(body, 'x');

    var client = try Client.connect(allocator, io, listener.socket.address, .{ .max_frame_payload = 64 * 1024, .max_body_bytes = 128 * 1024 });
    defer client.close();
    var response = try client.request(.{
        .method = "POST",
        .path = "/split-data",
        .authority = "localhost",
        .body = body,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqual(@as(usize, 3), shared.data_count);
    try std.testing.expectEqual(@as(usize, 20_000), shared.data_lengths[0]);
    try std.testing.expectEqual(@as(usize, 20_000), shared.data_lengths[1]);
    try std.testing.expectEqual(@as(usize, 5_000), shared.data_lengths[2]);
}

test "HTTP/2 readFrame enforces inbound SETTINGS_MAX_FRAME_SIZE before payload read" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var stream = try shared.listener.accept(shared.io);
            defer stream.close(shared.io);
            try std.testing.expectError(error.MessageTooLarge, readFrame(shared.allocator, shared.io, stream, .{
                .max_frame_payload = 64 * 1024,
                .max_frame_size = default_max_frame_size,
            }));
        }
    };

    var shared = Shared{ .allocator = allocator, .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer stream.close(io);

    // Send only the header.  A compliant receiver can reject this frame from
    // the advertised size alone and must not allocate or block waiting for the
    // oversized payload bytes.
    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(allocator);
    try (http2.FrameHeader{
        .length = @intCast(default_max_frame_size + 1),
        .frame_type = .data,
        .flags = 0,
        .stream_id = 1,
    }).write(&raw, allocator);
    try writeAll(io, stream, raw.items);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 runtime rejects invalid local SETTINGS limits" {
    if (@sizeOf(usize) > @sizeOf(u32)) {
        const beyond_settings_value = @as(usize, std.math.maxInt(u32)) + 1;
        try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
            .header_table_size = beyond_settings_value,
        }));
        try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
            .max_header_list_size = beyond_settings_value,
        }));
    }
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .initial_window_size = @as(u32, std.math.maxInt(i31)) + 1,
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .initial_connection_window_size = @as(u32, @intCast(default_flow_window)) - 1,
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .initial_connection_window_size = @as(u32, std.math.maxInt(i31)) + 1,
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .max_frame_size = default_max_frame_size - 1,
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .max_frame_size = max_max_frame_size + 1,
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .max_idle_priority_updates = 0,
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .max_pending_ping_frames = 0,
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .reset_stream_duration = .fromNanoseconds(-1),
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .adaptive_window = true,
        .adaptive_window_max = 1024,
    }));
    try std.testing.expectError(error.InvalidSetting, validateLocalLimits(.{
        .adaptive_window = true,
        .adaptive_window_max = @as(u32, std.math.maxInt(i31)) + 1,
    }));
    try validateLocalLimits(.{
        .header_table_size = std.math.maxInt(u32),
        .initial_window_size = std.math.maxInt(i31),
        .initial_connection_window_size = std.math.maxInt(i31),
        .max_frame_size = max_max_frame_size,
        .max_header_list_size = std.math.maxInt(u32),
    });
}

test "HTTP/2 local SETTINGS preserve maximum 32-bit header limits" {
    const settings = try settingsForLimits(.{
        .header_table_size = std.math.maxInt(u32),
        .max_header_list_size = std.math.maxInt(u32),
    }, .server);
    var header_table_size: ?u32 = null;
    var header_list_size: ?u32 = null;
    for (settings.buf[0..settings.count]) |setting| switch (setting.id) {
        .header_table_size => header_table_size = setting.value,
        .max_header_list_size => header_list_size = setting.value,
        else => {},
    };
    try std.testing.expectEqual(
        @as(?u32, std.math.maxInt(u32)),
        header_table_size,
    );
    try std.testing.expectEqual(
        @as(?u32, std.math.maxInt(u32)),
        header_list_size,
    );
}

test "HTTP/2 constructors reject unrepresentable SETTINGS before I/O" {
    if (@sizeOf(usize) <= @sizeOf(u32)) return;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const unreachable_address = net.IpAddress{ .ip4 = .loopback(1) };
    const beyond_settings_value = @as(usize, std.math.maxInt(u32)) + 1;

    try std.testing.expectError(
        error.InvalidSetting,
        Server.listen(allocator, io, unreachable_address, .{
            .header_table_size = beyond_settings_value,
        }),
    );
    try std.testing.expectError(
        error.InvalidSetting,
        Client.connect(allocator, io, unreachable_address, .{
            .max_header_list_size = beyond_settings_value,
        }),
    );
}

test "HTTP/2 runtime validates SETTINGS frame-size and window bounds" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }
    try std.testing.expect(!connection.peerPushEnabled());

    try std.testing.expectError(error.InvalidSetting, connection.applySettings(&.{
        .{ .id = .max_frame_size, .value = default_max_frame_size - 1 },
    }));
    try std.testing.expectError(error.InvalidSetting, connection.applySettings(&.{
        .{ .id = .max_frame_size, .value = max_max_frame_size + 1 },
    }));
    try std.testing.expectError(error.InvalidSetting, connection.applySettings(&.{
        .{ .id = .initial_window_size, .value = @as(u32, std.math.maxInt(i31)) + 1 },
    }));
    try connection.applySettings(&.{
        .{ .id = .enable_push, .value = 0 },
        .{ .id = .no_rfc7540_priorities, .value = 1 },
    });
    try std.testing.expect(!connection.peer_enable_push);
    try std.testing.expect(connection.peer_no_rfc7540_priorities);
    try std.testing.expectError(error.InvalidSetting, connection.applySettings(&.{
        .{ .id = .enable_push, .value = 1 },
    }));
    try std.testing.expect(!connection.peer_enable_push);

    try connection.applySettings(&.{
        .{ .id = .max_frame_size, .value = 32_768 },
        .{ .id = .max_concurrent_streams, .value = 7 },
        .{ .id = .header_table_size, .value = 128 },
    });
    try std.testing.expectEqual(@as(usize, 32_768), connection.peer_max_frame_size);
    try std.testing.expectEqual(
        @as(?u32, 7),
        connection.peerMaxConcurrentStreams(),
    );
    try std.testing.expectEqual(@as(usize, 128), connection.hpack_encoder.dynamic_table.size_limit);
    try std.testing.expect(connection.peer_no_rfc7540_priorities);

    // A peer setting is permission, not an instruction to retain up to 4 GiB
    // of encoder state. The default local ceiling remains 4 KiB.
    try connection.applySettings(&.{.{
        .id = .header_table_size,
        .value = std.math.maxInt(u32),
    }});
    try std.testing.expectEqual(
        http2.Hpack.default_dynamic_table_size,
        connection.hpack_encoder.dynamic_table.size_limit,
    );

    try connection.applySettings(&.{
        .{ .id = .enable_connect_protocol, .value = 0 },
    });
    try std.testing.expect(!connection.peerExtendedConnectEnabled());
    try connection.applySettings(&.{
        .{ .id = .enable_connect_protocol, .value = 1 },
    });
    try std.testing.expect(connection.peerExtendedConnectEnabled());
    try std.testing.expectError(error.InvalidSetting, connection.applySettings(&.{
        .{ .id = .enable_connect_protocol, .value = 0 },
    }));
    try std.testing.expect(connection.peerExtendedConnectEnabled());
    try connection.applySettings(&.{
        .{ .id = .no_rfc7540_priorities, .value = 1 },
    });
    try std.testing.expectError(error.InvalidSetting, connection.applySettings(&.{
        .{ .id = .no_rfc7540_priorities, .value = 0 },
    }));

    var server_connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        server_connection.send_stream_windows.deinit(std.testing.allocator);
        server_connection.recv_stream_windows.deinit(std.testing.allocator);
        server_connection.hpack_decoder.deinit(std.testing.allocator);
        server_connection.hpack_encoder.deinit(std.testing.allocator);
    }
    try server_connection.applySettings(&.{.{ .id = .enable_push, .value = 0 }});
    try std.testing.expect(!server_connection.peer_enable_push);
    try server_connection.applySettings(&.{.{ .id = .enable_push, .value = 1 }});
    try std.testing.expect(server_connection.peer_enable_push);
    try std.testing.expectError(error.InvalidSetting, server_connection.applySettings(&.{
        .{ .id = .enable_push, .value = 2 },
    }));
}

test "HTTP/2 runtime applies independent local HPACK table limits" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{
            .header_table_size = 32,
            .max_encoder_table_size = 128,
        },
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }
    connection.applyLocalLimits();
    try std.testing.expectEqual(@as(usize, 32), connection.hpack_decoder.max_dynamic_table_size);
    try std.testing.expectEqual(
        @as(usize, 128),
        connection.hpack_encoder.dynamic_table.size_limit,
    );
    try connection.applySettings(&.{.{
        .id = .header_table_size,
        .value = 1024,
    }});
    try std.testing.expectEqual(
        @as(usize, 128),
        connection.hpack_encoder.dynamic_table.size_limit,
    );

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(std.testing.allocator);
    try block.appendSlice(std.testing.allocator, &.{ 0x3f, 0x02 }); // Dynamic table size update value 33 > local limit.
    try std.testing.expectError(error.InvalidEncoding, connection.hpack_decoder.decodeBlock(std.testing.allocator, block.items));
}

test "HTTP/2 runtime enforces header list size limits" {
    const allocator = std.testing.allocator;

    const oversized = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "x-large", .value = "0123456789" },
    };
    try std.testing.expectError(error.MessageTooLarge, validateHeaderListSize(&oversized, 172));
    try validateHeaderListSize(&oversized, 173);

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &oversized);
    var decoder = http2.Hpack.Decoder{};
    defer decoder.deinit(allocator);
    try std.testing.expectError(error.MessageTooLarge, decodeOwnedHeaders(allocator, block.items, .{
        .max_header_fields = 16,
        .max_header_list_size = 120,
    }, &decoder));
    var no_alloc_block: std.ArrayList(u8) = .empty;
    defer no_alloc_block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(
        &no_alloc_block,
        allocator,
        &.{.{
            .name = "authorization",
            .value = "compressible-value",
        }},
    );
    var no_alloc_decoder = http2.Hpack.Decoder{};
    defer no_alloc_decoder.deinit(allocator);
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        decodeOwnedHeaders(
            no_alloc.allocator(),
            no_alloc_block.items,
            .{
                .max_header_fields = 16,
                .max_header_list_size = 1,
            },
            &no_alloc_decoder,
        ),
    );
    try std.testing.expect(!no_alloc.has_induced_failure);

    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.recv_stream_windows.deinit(allocator);
        connection.recv_stream_window_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }
    try connection.applySettings(&.{.{ .id = .max_header_list_size, .value = 120 }});
    try std.testing.expectEqual(@as(usize, 120), connection.peer_max_header_list_size);
    try std.testing.expectError(error.MessageTooLarge, connection.writeHeaders(1, &oversized, true));
}

test "HTTP/2 runtime decodes owned headers into one allocation" {
    const allocator = std.testing.allocator;
    const fields = [_]http2.Hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "x-first", .value = "one", .never_index = true },
        .{ .name = "x-second", .value = "two", .never_index = true },
    };
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &fields);
    var decoder = http2.Hpack.Decoder{};
    defer decoder.deinit(allocator);
    const cloned = try decodeOwnedHeaders(
        allocator,
        block.items,
        .{ .max_header_fields = 8 },
        &decoder,
    );
    defer freeHeaders(allocator, cloned);

    try std.testing.expect(cloned[0].block_storage != null);
    try std.testing.expect(cloned[1].block_storage == null);
    try std.testing.expectEqual(
        @intFromPtr(cloned.ptr),
        @intFromPtr(cloned[0].block_storage.?.ptr),
    );
    try std.testing.expectEqualStrings("x-second", cloned[2].name);
    const storage = cloned[0].block_storage.?;
    for (cloned) |field| {
        try std.testing.expect(@intFromPtr(field.name.ptr) >= @intFromPtr(storage.ptr));
        try std.testing.expect(@intFromPtr(field.value.ptr) >= @intFromPtr(storage.ptr));
        try std.testing.expect(
            @intFromPtr(field.value.ptr) + field.value.len <=
                @intFromPtr(storage.ptr) + storage.len,
        );
    }

    var tracking = std.testing.FailingAllocator.init(allocator, .{});
    var tracked_decoder = http2.Hpack.Decoder{};
    defer tracked_decoder.deinit(tracking.allocator());
    const before = tracking.allocations;
    const tracked_headers = try decodeOwnedHeaders(
        tracking.allocator(),
        block.items,
        .{ .max_header_fields = 8 },
        &tracked_decoder,
    );
    defer freeHeaders(tracking.allocator(), tracked_headers);
    // The plan list stays on the stack; the final fields and strings share one
    // aligned allocation for a static/literal application result.
    try std.testing.expectEqual(before + 1, tracking.allocations);
}

test "HTTP/2 runtime advertises configured initial SETTINGS" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        header_table_size: ?u32 = null,
        initial_window_size: ?u32 = null,
        max_concurrent_streams: ?u32 = null,
        max_frame_size: ?u32 = null,
        max_header_list_size: ?u32 = null,
        enable_push: ?u32 = null,
        enable_connect_protocol: ?u32 = null,
        no_rfc7540_priorities: ?u32 = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const stream = try shared.listener.accept(shared.io);
            defer stream.close(shared.io);

            var frame = try readFrame(shared.allocator, shared.io, stream, .{});
            defer frame.deinit(shared.allocator);
            try std.testing.expectEqual(http2.FrameType.settings, frame.frame.header.frame_type);
            const settings = try http2.parseSettings(shared.allocator, frame.frame.payload);
            defer shared.allocator.free(settings);
            for (settings) |setting| switch (setting.id) {
                .header_table_size => shared.header_table_size = setting.value,
                .initial_window_size => shared.initial_window_size = setting.value,
                .max_concurrent_streams => shared.max_concurrent_streams = setting.value,
                .max_frame_size => shared.max_frame_size = setting.value,
                .max_header_list_size => shared.max_header_list_size = setting.value,
                .enable_push => shared.enable_push = setting.value,
                .enable_connect_protocol => shared.enable_connect_protocol = setting.value,
                .no_rfc7540_priorities => shared.no_rfc7540_priorities = setting.value,
                else => {},
            };
        }
    };

    var shared = Shared{ .allocator = allocator, .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeInitialSettings(allocator, io, stream, .{
        .header_table_size = 1024,
        .initial_window_size = 70_000,
        .max_concurrent_streams = 11,
        .max_frame_size = 20_000,
        .max_header_list_size = 4096,
        .enable_connect_protocol = true,
        .no_rfc7540_priorities = true,
    }, .client);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(?u32, 1024), shared.header_table_size);
    try std.testing.expectEqual(@as(?u32, 70_000), shared.initial_window_size);
    try std.testing.expectEqual(@as(?u32, 11), shared.max_concurrent_streams);
    try std.testing.expectEqual(@as(?u32, 20_000), shared.max_frame_size);
    try std.testing.expectEqual(@as(?u32, 4096), shared.max_header_list_size);
    try std.testing.expectEqual(@as(?u32, 0), shared.enable_push);
    try std.testing.expectEqual(@as(?u32, 1), shared.enable_connect_protocol);
    try std.testing.expectEqual(
        @as(?u32, 1),
        shared.no_rfc7540_priorities,
    );
}

test {
    _ = @import("runtime/connect/rejection_tests.zig");
    _ = @import("runtime/frame/retention_tests.zig");
    _ = @import("runtime/headers/limit_reuse_tests.zig");
    _ = @import("runtime/headers/reset_deadline_tests.zig");
    _ = @import("runtime/reset/header_failure_tests.zig");
    _ = @import("runtime/request/batch_error_tests.zig");
    _ = @import("runtime/response/credit_lifecycle_tests.zig");
    _ = @import("runtime/response/credit_failure_tests.zig");
    _ = @import("runtime/response/allocation_failure_tests.zig");
    _ = @import("runtime/response/forbidden_body_tests.zig");
    _ = @import("runtime/response/batch_trailer_sync_tests.zig");
    _ = @import("runtime/response/batch_trailer_failure_tests.zig");
    _ = @import("runtime/response/padding_credit_tests.zig");
    _ = @import("runtime/response/padding_failure_tests.zig");
    _ = @import("runtime/request/padding_credit_tests.zig");
    _ = @import("runtime/flow/tests/padding.zig");
    _ = @import("runtime/push/padding_credit_tests.zig");
    _ = @import("runtime/push/credit_failure_tests.zig");
    _ = @import("runtime/push/credit_refill_tests.zig");
    _ = @import("runtime/push/credit_fault_tests.zig");
    _ = @import("runtime/push/credit_transport_tests.zig");
    _ = @import("runtime/push/late_credit_tests.zig");
    _ = @import("runtime/request/body_length_tests.zig");
    _ = @import("runtime/request/credit_failure_tests.zig");
    _ = @import("runtime/request/allocation_failure_tests.zig");
    _ = @import("runtime/response/body_length_tests.zig");
    _ = @import("runtime/frame/tests/io.zig");
    _ = @import("runtime/frame/tests/wire.zig");
    _ = @import("runtime/flow/tests/window.zig");
    _ = @import("runtime/flow/tests/data.zig");
    _ = @import("runtime/headers/tests/message.zig");
    _ = @import("../http/field_value_tests.zig");
    _ = @import("runtime/headers/value_reuse_tests.zig");
    _ = @import("runtime/tls_tests.zig");
    _ = @import("runtime/push_tests.zig");
    _ = @import("runtime/priority_tests.zig");
    _ = @import("runtime/priority/legacy_tests.zig");
    _ = @import("runtime/priority/dictionary_tests.zig");
    _ = @import("runtime/priority/metadata_tests.zig");
    _ = @import("runtime/priority/legacy_shutdown_tests.zig");
    _ = @import("runtime/streaming_response_tests.zig");
    _ = @import("runtime/response_batch_tests.zig");
    _ = @import("runtime/informational_batch_tests.zig");
    _ = @import("runtime/response_writer_tests.zig");
    _ = @import("runtime/request_writer_tests.zig");
    _ = @import("runtime/ping_timeout_tests.zig");
    _ = @import("runtime/refusal_tests.zig");
    _ = @import("runtime/connect_udp_tests.zig");
    _ = @import("runtime/connect_udp_relay_tests.zig");
    _ = @import("runtime/connect_ip_tests.zig");
    _ = @import("runtime/handshake_timeout_tests.zig");
    _ = @import("runtime/proxy_tests.zig");
    _ = @import("runtime/redirect_tests.zig");
    _ = @import("runtime/server_lifecycle_tests.zig");
    _ = @import("runtime/unix_tests.zig");
}

test {
    _ = @import("runtime/push/receive_tests.zig");
    _ = @import("runtime/push/receive_order_tests.zig");
    _ = @import("runtime/push/receive_lifecycle_tests.zig");
    _ = @import("runtime/push/receive_error_tests.zig");
    _ = @import("runtime/push/receive_store_tests.zig");
}
