const std = @import("std");
const io_interruption = @import("../internal/io_interruption.zig");
const endpoint_host = @import("../internal/endpoint_host.zig");
const builtin = @import("builtin");
const websocket = @import("mod.zig");
pub const common = @import("runtime/common.zig");
pub const http1 = @import("../http1/mod.zig");
pub const http2 = @import("../http2/mod.zig");
pub const http1_runtime = http1.runtime;
const http1_write = @import("../http1/runtime/write.zig");
pub const http1_message_framing =
    @import("../http1/runtime/message/framing.zig");
pub const http2_runtime = http2.runtime;
const http_cookies = @import("../http/cookies/mod.zig");
pub const tls_stream = @import("../tls/mod.zig").stream;
pub const tls_client_identity = @import(
    "runtime/tls_client_identity.zig",
);
pub const compression_scratch =
    @import("runtime/compression_scratch.zig");
const cookie_handshake = @import("runtime/cookies.zig");
pub const message_buffer = @import("runtime/message/buffer.zig");
pub const ReceiveBuffer = message_buffer;
pub const message_state = @import("runtime/message/state.zig");
pub const frame_validation = @import("runtime/message/frame_validation.zig");
pub const receive_failure = @import("runtime/receive_failure.zig");
pub const handshake_headers = @import("runtime/handshake/headers.zig");
const handshake_rejection = @import("runtime/handshake/rejection.zig");
pub const handshake_storage = @import("runtime/handshake/storage.zig");
const handshake_response = @import("runtime/handshake/response.zig");
pub const handshake_request = @import("runtime/handshake/request.zig");
pub const handshake_acceptance = @import("runtime/handshake/acceptance.zig");
const handshake_receive = @import("runtime/handshake/receive.zig");
const origin_policy = @import("runtime/origin_policy.zig");
pub const redirect = @import("runtime/redirect.zig");
const stream_io = @import("../internal/stream_io.zig");
const accept_deadline = @import("../internal/accept.zig");
pub const timed_mutex = @import("../internal/timed_mutex.zig");
pub const deadline_policy = @import("../internal/deadline.zig");
pub const tcp_connect = @import("../internal/tcp_connect.zig");
pub const address_resolver = @import("../internal/address_resolver.zig");
pub const socket_options = @import("../internal/socket_options.zig");
pub const proxy_socks5 = @import("../proxy/socks5.zig");
pub const wire = @import("../internal/wire.zig");
pub const vail = @import("vail");

const net = std.Io.net;

pub const h3 = @import("runtime/h3.zig");
/// Default lower bound for attempting permessage-deflate. Raw DEFLATE framing
/// cannot profitably encode very small messages, and initializing compressor
/// state would dominate their latency. Callers may tune this per endpoint.
pub const default_compression_threshold: usize = 32;
pub const masked_write_scratch_len: usize = 16 * 1024;
const max_batched_payload_slices: usize = 64;
// A 4 KiB application payload occupies 4104 bytes on the masked wire. The old
// 4096-byte read scratch therefore forced two socket reads for this common
// frame size. Keep the burst on the call stack (rather than 16 KiB resident per
// connection) while covering typical WebSocket/TLS records in one read.
pub const transport_read_scratch_len: usize = 16 * 1024;

pub const Error = websocket.Error || http1_runtime.Error || redirect.Error ||
    proxy_socks5.Error ||
    http_cookies.Error ||
    cookie_handshake.Error || http2_runtime.Error || tls_stream.Error || error{
    HeadersTooLarge,
    ConnectionClosed,
    InvalidResponse,
    InvalidOrigin,
    InvalidSubprotocol,
    InvalidUri,
    UnsupportedScheme,
    MessageTooLarge,
    UnexpectedPong,
    WriteInProgress,
    InvalidServeOptions,
    ExporterUnavailable,
    TlsKeyUpdateUnavailable,
    InvalidSocketOption,
    SocketOptionFailed,
    SocketOptionUnsupported,
    CookieHeaderConflict,
    InvalidAddressConnectPolicy,
} || std.Io.RandomSecureError || net.HostName.ValidateError || net.HostName.ConnectError || net.Stream.Reader.Error || net.Stream.Writer.Error;

pub const Limits = common.Limits;
pub const TcpKeepAlive = socket_options.TcpKeepAlive;
pub const Role = common.Role;

pub const IncomingDataKind = frame_validation.DataKind;

pub const MessageFrameReceiveState = struct {
    header: ?websocket.FrameHeader = null,
    payload_start: usize = 0,
    payload_end: usize = 0,
    payload_written: usize = 0,
    message_kind: IncomingDataKind = .none,

    fn reset(self: *MessageFrameReceiveState) void {
        self.* = .{};
    }
};

pub const PendingH2Message = struct {
    const Source = enum { contiguous, slices, fragmented, in_place };

    opcode: websocket.Opcode,
    source: Source = .contiguous,
    original_ptr: usize,
    original_len: usize,
    header: [websocket.max_frame_header_len]u8 = undefined,
    header_len: usize = 0,
    payload_len: usize = 0,
    committed: usize = 0,
    mask_key: ?[4]u8 = null,
    compressed: bool = false,
    fragment_index: usize = 0,
    fragment_start: usize = 0,
    fragmented_payload_total: usize = 0,
    wire_total: usize = 0,

    pub fn matches(
        self: *const PendingH2Message,
        opcode: websocket.Opcode,
        payload: []const u8,
    ) bool {
        return self.source == .contiguous and
            self.opcode == opcode and
            self.original_len == payload.len and
            (payload.len == 0 or
                self.original_ptr == @intFromPtr(payload.ptr));
    }

    pub fn matchesParts(
        self: *const PendingH2Message,
        opcode: websocket.Opcode,
        parts: []const []const u8,
    ) bool {
        return self.source == .slices and
            self.opcode == opcode and
            self.original_len == parts.len and
            (parts.len == 0 or
                self.original_ptr == @intFromPtr(parts.ptr));
    }

    pub fn matchesInPlace(
        self: *const PendingH2Message,
        payload: []const u8,
    ) bool {
        return self.source == .in_place and
            self.opcode == .binary and
            self.original_len == payload.len and
            (payload.len == 0 or
                self.original_ptr == @intFromPtr(payload.ptr));
    }

    pub fn matchesFragments(
        self: *const PendingH2Message,
        opcode: websocket.Opcode,
        fragments: []const []const u8,
    ) bool {
        return self.source == .fragmented and
            self.opcode == opcode and
            self.original_len == fragments.len and
            (fragments.len == 0 or
                self.original_ptr == @intFromPtr(fragments.ptr));
    }

    pub fn totalLen(self: *const PendingH2Message) usize {
        return if (self.source == .fragmented)
            self.wire_total
        else
            self.header_len + self.payload_len;
    }
};

pub const PendingMessage = struct {
    const Source = enum { contiguous, slices, fragmented, in_place };

    opcode: websocket.Opcode,
    source: Source = .contiguous,
    original_ptr: usize,
    original_len: usize,
    header: [websocket.max_frame_header_len]u8 = undefined,
    header_len: usize = 0,
    payload_len: usize = 0,
    committed: usize = 0,
    mask_key: ?[4]u8 = null,
    compressed: bool = false,
    fragment_index: usize = 0,
    fragment_start: usize = 0,
    fragmented_payload_total: usize = 0,
    wire_total: usize = 0,

    pub fn matches(
        self: *const PendingMessage,
        opcode: websocket.Opcode,
        payload: []const u8,
    ) bool {
        return self.source == .contiguous and
            self.opcode == opcode and
            self.original_len == payload.len and
            (payload.len == 0 or
                self.original_ptr == @intFromPtr(payload.ptr));
    }

    pub fn matchesParts(
        self: *const PendingMessage,
        opcode: websocket.Opcode,
        parts: []const []const u8,
    ) bool {
        return self.source == .slices and
            self.opcode == opcode and
            self.original_len == parts.len and
            (parts.len == 0 or
                self.original_ptr == @intFromPtr(parts.ptr));
    }

    pub fn matchesInPlace(
        self: *const PendingMessage,
        payload: []const u8,
    ) bool {
        return self.source == .in_place and
            self.opcode == .binary and
            self.original_len == payload.len and
            (payload.len == 0 or
                self.original_ptr == @intFromPtr(payload.ptr));
    }

    pub fn matchesFragments(
        self: *const PendingMessage,
        opcode: websocket.Opcode,
        fragments: []const []const u8,
    ) bool {
        return self.source == .fragmented and
            self.opcode == opcode and
            self.original_len == fragments.len and
            (fragments.len == 0 or
                self.original_ptr == @intFromPtr(fragments.ptr));
    }

    pub fn totalLen(self: *const PendingMessage) usize {
        return if (self.source == .fragmented)
            self.wire_total
        else
            self.header_len + self.payload_len;
    }
};

pub fn copyMessagePartsAt(
    destination: []u8,
    parts: []const []const u8,
    start_offset: usize,
    mask_key: ?[4]u8,
) websocket.Error!void {
    var skip = start_offset;
    var written: usize = 0;
    for (parts) |part| {
        if (skip >= part.len) {
            skip -= part.len;
            continue;
        }
        const count = @min(
            destination.len - written,
            part.len - skip,
        );
        const source = part[skip..][0..count];
        if (mask_key) |mask| {
            try websocket.applyMaskCopy(
                destination[written..][0..count],
                source,
                mask,
                start_offset + written,
            );
        } else {
            @memcpy(destination[written..][0..count], source);
        }
        written += count;
        skip = 0;
        if (written == destination.len) return;
    }
    std.debug.assert(written == destination.len);
}

pub fn fragmentedWireLen(
    fragments: []const []const u8,
    compressed_len: ?usize,
    masked: bool,
) websocket.Error!usize {
    var total: usize = 0;
    for (fragments, 0..) |fragment, index| {
        const payload_len = if (compressed_len) |len| blk: {
            const range = compressedFragmentRange(
                len,
                fragments.len,
                index,
            );
            break :blk range.end - range.start;
        } else fragment.len;
        var header: [websocket.max_frame_header_len]u8 = undefined;
        const encoded = try websocket.writeFrameHeaderForLengthInto(
            &header,
            if (index == 0) .binary else .continuation,
            payload_len,
            .{ .mask_key = if (masked) [4]u8{ 0, 0, 0, 0 } else null },
        );
        total = std.math.add(usize, total, encoded.len) catch
            return error.PayloadTooLarge;
        total = std.math.add(usize, total, payload_len) catch
            return error.PayloadTooLarge;
    }
    return total;
}

pub const PendingControlFrame = common.PendingControlFrame;
pub const PendingWrite = common.PendingWriteState(PendingMessage);
pub const PendingH2Write = common.PendingWriteState(PendingH2Message);

pub const ClientIdentity = tls_client_identity.ClientIdentity;
pub const ClientCertificateVerifier =
    tls_client_identity.CertificateVerifier;

pub const RuntimeTransport = union(enum) {
    tcp: struct { io: std.Io, stream: net.Stream },
    tls: *http1_runtime.TlsClientConnection,
    tls_vail: *tls_stream.ClientConnection,
    tls_server: *tls_stream.ServerConnection,

    pub fn read(self: RuntimeTransport, buffer: []u8) Error!usize {
        return switch (self) {
            .tcp => |tcp| readSome(tcp.io, tcp.stream, buffer),
            .tls => |conn| conn.read(buffer),
            .tls_vail => |conn| conn.read(buffer),
            .tls_server => |conn| conn.read(buffer),
        };
    }

    /// Read transport bytes without moving an application-owned absolute
    /// deadline. Buffered TLS plaintext is still returned immediately; only a
    /// read that reaches the socket waits against `deadline`.
    pub fn readWithDeadline(
        self: RuntimeTransport,
        buffer: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!usize {
        return switch (self) {
            .tcp => |tcp| readSomeWithDeadline(
                tcp.io,
                tcp.stream,
                buffer,
                deadline,
            ),
            .tls_vail => |conn| conn.readWithDeadline(buffer, deadline),
            .tls_server => |conn| conn.readWithDeadline(buffer, deadline),
            .tls => |conn| conn.readWithDeadline(buffer, deadline),
        };
    }

    pub fn writeAll(self: RuntimeTransport, bytes: []const u8) Error!void {
        return switch (self) {
            .tcp => |tcp| writeAllToStream(tcp.io, tcp.stream, bytes),
            .tls => |conn| conn.writeAll(bytes),
            .tls_vail => |conn| conn.writeAll(bytes),
            .tls_server => |conn| conn.writeAll(bytes),
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
            .tls => |conn| conn.writeAllParts(header, payload),
            .tls_vail => |conn| conn.writeAllParts(header, payload),
            .tls_server => |conn| conn.writeAllParts(header, payload),
        };
    }

    pub fn writeAllSlices(
        self: RuntimeTransport,
        parts: []const []const u8,
    ) Error!void {
        switch (self) {
            .tcp => |tcp| {
                var non_empty: usize = 0;
                for (parts) |part| non_empty += @intFromBool(part.len != 0);
                if (non_empty <= 8) {
                    return stream_io.writeAllSlices(tcp.io, tcp.stream, parts);
                }
                return stream_io.writeAllSlicesWide(tcp.io, tcp.stream, parts);
            },
            .tls => |conn| return conn.writeAllSlices(parts),
            .tls_vail => |conn| return conn.writeAllSlices(parts),
            .tls_server => |conn| return conn.writeAllSlices(parts),
        }
    }

    /// Write one contiguous application prefix under an absolute transport
    /// deadline. TCP reports exact socket progress; TLS implementations report
    /// only complete plaintext records while retaining partial ciphertext for
    /// a safe retry.
    pub fn writeWithDeadline(
        self: RuntimeTransport,
        bytes: []const u8,
        committed: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        committed.* = 0;
        return switch (self) {
            .tcp => |tcp| stream_io.writeAllTrackedWithDeadline(
                tcp.io,
                tcp.stream,
                bytes,
                committed,
                deadline,
            ),
            .tls => |conn| conn.writeAllWithDeadline(
                bytes,
                committed,
                deadline,
            ),
            .tls_vail => |conn| conn.writeAllWithDeadline(
                bytes,
                committed,
                deadline,
            ),
            .tls_server => |conn| conn.writeAllWithDeadline(
                bytes,
                committed,
                deadline,
            ),
        };
    }

    pub fn finishPendingTimedWrite(
        self: RuntimeTransport,
        committed: *usize,
    ) Error!void {
        committed.* = 0;
        return switch (self) {
            .tcp => {},
            .tls => |conn| conn.finishPendingTimedWrite(committed),
            .tls_vail => |conn| conn.finishPendingWrite(committed),
            .tls_server => |conn| conn.finishPendingWrite(committed),
        };
    }

    pub fn close(self: RuntimeTransport) void {
        switch (self) {
            .tcp => |tcp| tcp.stream.close(tcp.io),
            .tls => |conn| conn.deinit(),
            .tls_vail => |conn| conn.deinit(),
            .tls_server => |conn| conn.deinit(),
        }
    }
};

pub const HandshakeWriter = handshake_response.Writer(struct {
    pub const TransportType = RuntimeTransport;
    pub const ErrorType = Error;
    pub const writeWithDeadline = RuntimeTransport.writeWithDeadline;
    pub const writeAllParts = RuntimeTransport.writeAllParts;
});

const HandshakeReader = handshake_receive.Reader(struct {
    pub const TransportType = RuntimeTransport;
    pub const ErrorType = Error;
    pub const read = RuntimeTransport.read;
    pub const readWithDeadline = RuntimeTransport.readWithDeadline;
});

pub fn transportStream(transport: RuntimeTransport) net.Stream {
    return switch (transport) {
        .tcp => |tcp| tcp.stream,
        .tls_server => |connection| connection.stream,
        .tls => |connection| connection.stream,
        .tls_vail => |connection| connection.stream,
    };
}

// WebSocket server owners live in runtime/servers.zig.
const servers = @import("runtime/servers.zig");

pub const Server = servers.Server;
pub const UnixServer = servers.UnixServer;
pub const TlsServer = servers.TlsServer;

pub const TlsListenOptions = struct {
    /// Static identity storage must outlive the listener. A provider may
    /// override it with a separately leased identity for each handshake.
    identity: vail.tls.auth.ServerIdentity,
    identity_provider: ?tls_stream.ServerIdentityProvider = null,
    limits: Limits = .{},
    cipher_suites: []const vail.tls.cipher_suite.Suite =
        &vail.tls.cipher_suite.default_preference,
    tls12_cipher_suites: []const tls_stream.Tls12CipherSuite =
        tls_stream.default_tls12_cipher_suites,
    protocol_policy: tls_stream.VersionPolicy = .tls12_and_tls13,
    tls13_session_tickets: ?tls_stream.Tls13ServerTicketPolicy = null,
    tls12_session_tickets: ?tls_stream.Tls12ServerTicketPolicy = null,
    max_client_hello_size: usize = 64 * 1024,
    max_client_handshake_size: usize = 256 * 1024,
    /// Absolute TLS handshake receive budget. The WebSocket Upgrade-head
    /// deadline starts independently after TLS succeeds.
    tls_handshake_timeout: ?std.Io.Duration = null,
    client_auth: ?vail.tls.client_auth.ServerPolicy = null,
    /// Optional ALPN selection for WSS. WSS runs an HTTP/1.1 Upgrade, so a
    /// configured list may only contain `http/1.1`; an empty list keeps legacy
    /// no-ALPN clients working.
    alpn_protocols: []const []const u8 = &.{},
    tcp_nodelay: bool = true,
};

pub fn receiveUpgradeRequestFromTransport(
    allocator: std.mem.Allocator,
    io: std.Io,
    transport: RuntimeTransport,
    limits: Limits,
    options: AcceptOptions,
    outer_deadline: ?std.Io.Clock.Timestamp,
) Error!PendingUpgrade {
    const deadline = deadline_policy.earlier(
        outer_deadline,
        if (limits.http1_handshake_timeout) |timeout|
            try handshakeDeadline(transport, timeout)
        else
            null,
    );
    var head = try readHttpHeadFromTransport(
        allocator,
        transport,
        limits.max_head_bytes,
        deadline,
    );
    errdefer head.deinit(allocator);

    var request = try http1.parseRequest(
        allocator,
        head.head,
        http1HandshakeRequestParseOptions(limits),
    );
    errdefer request.deinit(allocator);
    // Bytes sent before the 101 response are ambiguous HTTP smuggling/junk,
    // regardless of whether the carrier is TCP or TLS.
    if (head.extra.len != 0) return error.InvalidHandshake;
    websocket.validateClientHandshake(request) catch |err| switch (err) {
        error.UnsupportedVersion => {
            try websocket.validateClientHandshakeForVersionNegotiation(request);
            try origin_policy.validateHttp1(
                request.headers,
                options.allowed_origins,
            );
            if (deadline) |absolute| {
                _ = try deadline_policy.usableAwake(io, absolute);
            }
            try handshake_rejection.writeUnsupportedVersion(
                allocator,
                request.method,
                limits.max_head_bytes,
                HandshakeWriter{ .transport = transport, .deadline = deadline },
                HandshakeWriter.write,
            );
            return err;
        },
        else => return err,
    };
    try origin_policy.validateHttp1(request.headers, options.allowed_origins);

    const key = request.header("sec-websocket-key") orelse
        return error.MissingHeader;
    try validateUpgradeAcceptHeaders(options.extra_headers);
    const selected_protocol = try selectHttp1Subprotocol(
        allocator,
        request.headers,
        options.protocols,
    );
    errdefer if (selected_protocol) |protocol| allocator.free(protocol);
    if (options.require_subprotocol and selected_protocol == null) {
        return error.InvalidSubprotocol;
    }
    const extension_policy: websocket.ExtensionNegotiation.Policy = .{
        .enable_permessage_deflate = options.enable_permessage_deflate,
        .allow_context_takeover = options.allow_context_takeover,
        .context_takeover = options.context_takeover,
        .accept_client_max_window_bits = options.client_max_window_bits,
        .accept_server_max_window_bits = options.server_max_window_bits,
    };
    const selected_extension =
        try websocket.ExtensionNegotiation.acceptClientHeadersWithPolicy(
            allocator,
            request.headers,
            extension_policy,
        );
    errdefer if (selected_extension) |extension| allocator.free(extension);
    const negotiated_extension = if (selected_extension) |extension|
        try websocket.ExtensionNegotiation.validateResponseWithPolicy(
            extension,
            extension_policy,
        )
    else
        websocket.ExtensionNegotiation{};

    return .{
        .io = io,
        .allocator = allocator,
        .transport = transport,
        .limits = limits,
        .options = options,
        .deadline = deadline,
        .request_head = head,
        .request = request,
        .client_key = key,
        .selected_protocol = selected_protocol,
        .selected_extension = selected_extension,
        .negotiated_extension = negotiated_extension,
    };
}

pub const AsyncServeError = Error || std.Io.Cancelable || std.Io.ConcurrentError;

pub const ConcurrentServeResult = struct {
    allocator: std.mem.Allocator,
    errors: []?anyerror,

    pub fn deinit(self: *ConcurrentServeResult) void {
        self.allocator.free(self.errors);
        self.* = undefined;
    }

    pub fn firstError(self: ConcurrentServeResult) ?anyerror {
        for (self.errors) |err| {
            if (err) |value| return value;
        }
        return null;
    }

    pub fn successCount(self: ConcurrentServeResult) usize {
        var count: usize = 0;
        for (self.errors) |err| {
            if (err == null) count += 1;
        }
        return count;
    }
};

pub const ServeErrorStage = enum {
    accept,
    connection,
};

pub const ServeErrorPolicy = enum {
    continue_serving,
    stop,
};

pub const ServeErrorEvent = struct {
    stage: ServeErrorStage,
    err: anyerror,
};

pub const ServeErrorObserver = struct {
    context: *anyopaque,
    /// May be called concurrently by independent connection workers.
    observe: *const fn (context: *anyopaque, event: ServeErrorEvent) void,
};

pub const ServeUntilOptions = struct {
    /// Setting this event cancels blocked accepts and active handler I/O.
    shutdown: *std.Io.Event,
    accept_error_policy: ServeErrorPolicy = .continue_serving,
    connection_error_policy: ServeErrorPolicy = .continue_serving,
    /// Prevent a failed listener from becoming an unbounded retry loop.
    accept_error_backoff: std.Io.Duration = .fromMilliseconds(10),
    error_observer: ?ServeErrorObserver = null,
};

pub fn serveAcceptedConcurrent(
    comptime ServerType: type,
    server: *ServerType,
    io: std.Io,
    allocator: std.mem.Allocator,
    comptime HandlerContext: type,
    context: *HandlerContext,
    comptime handler: *const fn (*HandlerContext, *Connection) Error!void,
    max_connections: usize,
    options: AcceptOptions,
) AsyncServeError!ConcurrentServeResult {
    var group: std.Io.Group = .init;
    const results = try allocator.alloc(?anyerror, max_connections);
    errdefer allocator.free(results);
    // Workers borrow result slots; join them before releasing that storage.
    defer group.cancel(io);
    @memset(results, null);

    for (results) |*result| {
        var connection = try server.accept(options);
        errdefer connection.close();
        const task = ServeTask(HandlerContext){
            .connection = connection,
            .context = context,
            .handler = handler,
            .result = result,
        };
        try group.concurrent(io, ServeTask(HandlerContext).run, .{task});
    }

    try group.await(io);
    return .{ .allocator = allocator, .errors = results };
}

const ServeSupervisorState = struct {
    io: std.Io,
    options: ServeUntilOptions,
    stopping: std.atomic.Value(bool) = .init(false),
    failed: std.Io.Event = .unset,
    error_mutex: std.Io.Mutex = .init,
    first_error: ?anyerror = null,

    fn shouldStop(self: *@This()) bool {
        return self.stopping.load(.acquire) or self.options.shutdown.isSet();
    }

    fn report(self: *@This(), stage: ServeErrorStage, err: anyerror) void {
        if (self.options.error_observer) |observer| {
            observer.observe(observer.context, .{ .stage = stage, .err = err });
        }
        const policy = switch (stage) {
            .accept => self.options.accept_error_policy,
            .connection => self.options.connection_error_policy,
        };
        if (policy != .stop) return;
        self.error_mutex.lockUncancelable(self.io);
        if (self.first_error == null) self.first_error = err;
        self.error_mutex.unlock(self.io);
        self.stopping.store(true, .release);
        self.failed.set(self.io);
    }

    fn firstError(self: *@This()) ?anyerror {
        self.error_mutex.lockUncancelable(self.io);
        defer self.error_mutex.unlock(self.io);
        return self.first_error;
    }
};

pub fn serveAcceptedUntil(
    comptime ServerType: type,
    server: *ServerType,
    io: std.Io,
    comptime HandlerContext: type,
    context: *HandlerContext,
    comptime handler: *const fn (*HandlerContext, *Connection) Error!void,
    max_connections: usize,
    accept_options: AcceptOptions,
    options: ServeUntilOptions,
) anyerror!void {
    if (max_connections == 0 or
        options.accept_error_backoff.nanoseconds < 0)
    {
        return error.InvalidServeOptions;
    }
    var group: std.Io.Group = .init;
    var supervisor = ServeSupervisorState{ .io = io, .options = options };
    var group_finished = false;
    defer if (!group_finished) {
        supervisor.stopping.store(true, .release);
        group.cancel(io);
    };
    for (0..max_connections) |_| {
        try group.concurrent(
            io,
            ServeUntilTask(ServerType, HandlerContext).run,
            .{ServeUntilTask(ServerType, HandlerContext){
                .supervisor = &supervisor,
                .server = server,
                .context = context,
                .handler = handler,
                .accept_options = accept_options,
            }},
        );
    }

    const Wake = union(enum) {
        shutdown: std.Io.Cancelable!void,
        failure: std.Io.Cancelable!void,
    };
    var wake_buffer: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &wake_buffer);
    defer select.cancelDiscard();
    try select.concurrent(.shutdown, waitForServeEvent, .{ options.shutdown, io });
    try select.concurrent(.failure, waitForServeEvent, .{ &supervisor.failed, io });
    switch (try select.await()) {
        .shutdown => |result| try result,
        .failure => |result| try result,
    }

    supervisor.stopping.store(true, .release);
    group.cancel(io);
    group_finished = true;
    select.cancelDiscard();
    if (supervisor.firstError()) |err| return err;
}

fn ServeUntilTask(
    comptime ServerType: type,
    comptime HandlerContext: type,
) type {
    return struct {
        supervisor: *ServeSupervisorState,
        server: *ServerType,
        context: *HandlerContext,
        handler: *const fn (*HandlerContext, *Connection) Error!void,
        accept_options: AcceptOptions,

        fn run(task: @This()) std.Io.Cancelable!void {
            while (!task.supervisor.shouldStop()) {
                var connection = task.server.accept(
                    task.accept_options,
                ) catch |err| {
                    if (err == error.Canceled or
                        task.supervisor.shouldStop())
                    {
                        return error.Canceled;
                    }
                    task.supervisor.report(.accept, err);
                    if (task.supervisor.shouldStop()) return;
                    const backoff =
                        task.supervisor.options.accept_error_backoff;
                    if (backoff.nanoseconds > 0) {
                        std.Io.sleep(
                            task.supervisor.io,
                            backoff,
                            .awake,
                        ) catch |sleep_err| switch (sleep_err) {
                            error.Canceled => return error.Canceled,
                        };
                    }
                    continue;
                };
                defer connection.close();
                task.handler(task.context, &connection) catch |err| {
                    if (err == error.Canceled and
                        task.supervisor.shouldStop()) return;
                    task.supervisor.report(.connection, err);
                };
            }
        }
    };
}

fn waitForServeEvent(
    event: *std.Io.Event,
    io: std.Io,
) std.Io.Cancelable!void {
    try event.wait(io);
}

fn ServeTask(comptime HandlerContext: type) type {
    return struct {
        connection: Connection,
        context: *HandlerContext,
        handler: *const fn (*HandlerContext, *Connection) Error!void,
        result: *?anyerror,

        fn run(task: @This()) std.Io.Cancelable!void {
            var connection = task.connection;
            defer connection.close();
            task.handler(task.context, &connection) catch |err| {
                task.result.* = err;
                return;
            };
            task.result.* = null;
        }
    };
}

pub const AcceptOptions = struct {
    protocols: []const []const u8 = &.{},
    /// Reject the HTTP upgrade unless one of `protocols` was selected.
    ///
    /// Generic WebSocket servers often allow clients to omit a subprotocol,
    /// while protocol bindings such as MQTT require the opening handshake to
    /// select their registered token. Keeping this opt-in avoids weakening the
    /// generic behavior while allowing adapters to fail before sending 101.
    require_subprotocol: bool = false,
    /// When non-empty, require exactly one Origin header whose complete value
    /// byte-for-byte matches an entry. An empty list preserves non-browser and
    /// same-origin-agnostic server use cases by disabling Origin enforcement.
    allowed_origins: []const []const u8 = &.{},
    extra_headers: []const http1.Header = &.{},
    enable_permessage_deflate: bool = false,
    /// Permit RFC 7692 history retention in either negotiated direction.
    /// Disabled by default so existing endpoints retain no-context behavior.
    allow_context_takeover: bool = false,
    /// Explicit client/server direction policy overrides allow_context_takeover.
    context_takeover: ?websocket.ContextTakeover = null,
    /// If offered by the client, select at most this receive-history window.
    client_max_window_bits: ?u8 = null,
    /// Select at most this server send-history window.
    server_max_window_bits: ?u8 = null,
    /// Minimum complete message size considered for outbound compression.
    /// Inbound compressed messages remain accepted after negotiation.
    compression_threshold: usize = default_compression_threshold,
};

/// A validated HTTP/1 WebSocket Upgrade request awaiting application
/// admission. No 101 response has been sent yet.
///
/// This value owns the transport and parsed request. Consume it with `accept`,
/// `acceptWithHeaders`, or `reject`, or call `deinit` to close it. Request
/// metadata remains valid until then, allowing authentication, routing, and
/// load shedding at the HTTP boundary instead of after protocol upgrade. The
/// slices in the original `AcceptOptions` must also remain valid until the
/// pending value is consumed.
pub const PendingUpgrade = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    limits: Limits,
    options: AcceptOptions,
    deadline: ?std.Io.Clock.Timestamp,
    request_head: HttpHead,
    request: http1.Request,
    client_key: []const u8,
    selected_protocol: ?[]u8,
    selected_extension: ?[]u8,
    negotiated_extension: websocket.ExtensionNegotiation,
    response_write_failed: bool = false,

    pub fn deinit(self: *PendingUpgrade) void {
        const allocator = self.allocator;
        const transport = self.transport;
        self.request.deinit(allocator);
        self.request_head.deinit(allocator);
        if (self.selected_protocol) |protocol| allocator.free(protocol);
        if (self.selected_extension) |extension| allocator.free(extension);
        self.* = undefined;
        transport.close();
    }

    pub fn target(self: PendingUpgrade) []const u8 {
        return self.request.target;
    }

    /// Socket address recorded for this Upgrade's transport. Accepted server
    /// connections record the remote peer.
    pub fn peerAddress(self: PendingUpgrade) ?std.Io.net.IpAddress {
        return self.request.from;
    }

    pub fn headers(self: PendingUpgrade) []const http1.Header {
        return self.request.headers;
    }

    pub fn header(
        self: PendingUpgrade,
        name: []const u8,
    ) ?[]const u8 {
        return self.request.header(name);
    }

    /// Return the authenticated client certificate chain for pending WSS
    /// requests. Cleartext and anonymous TLS requests return null.
    pub fn peerCertificates(
        self: *const PendingUpgrade,
    ) ?[]const []const u8 {
        const connection = switch (self.transport) {
            .tls_server => |value| value,
            else => return null,
        };
        return connection.peerCertificates();
    }

    pub fn negotiatedCipherSuite(
        self: *const PendingUpgrade,
    ) ?tls_stream.NegotiatedCipherSuite {
        const connection = switch (self.transport) {
            .tls_server => |value| value,
            else => return null,
        };
        return connection.negotiatedCipherSuite();
    }

    pub fn negotiatedTranscriptHash(
        self: *const PendingUpgrade,
    ) ?tls_stream.TranscriptHash {
        const connection = switch (self.transport) {
            .tls_server => |value| value,
            else => return null,
        };
        return connection.negotiatedTranscriptHash();
    }

    pub fn negotiatedAlpn(self: *const PendingUpgrade) ?[]const u8 {
        const connection = switch (self.transport) {
            .tls_server => |value| value,
            else => return null,
        };
        return connection.negotiatedAlpn();
    }

    pub fn accept(self: *PendingUpgrade) Error!Connection {
        return self.acceptWithHeaders(&.{});
    }

    /// Accept the validated request and add application-selected response
    /// fields to the negotiated subprotocol/extension fields.
    pub fn acceptWithHeaders(
        self: *PendingUpgrade,
        additional_headers: []const http1.Header,
    ) Error!Connection {
        if (self.response_write_failed) return error.ConnectionClosed;
        const allocator = self.allocator;
        const response = try handshake_acceptance.prepare(allocator, .{
            .client_key = self.client_key,
            .protocol = self.selected_protocol,
            .extension = self.selected_extension,
            .configured_headers = self.options.extra_headers,
            .additional_headers = additional_headers,
            .max_head_bytes = self.limits.max_head_bytes,
        });
        defer allocator.free(response);
        if (self.deadline) |deadline| {
            _ = try deadline_policy.usableAwake(self.io, deadline);
        }
        const io = self.io;
        const transport = self.transport;
        try self.writeResponse(response, &.{});

        const selected_protocol = self.selected_protocol;
        const request_head = self.request_head;
        var request = self.request;
        const limits = self.limits;
        const compression_threshold = self.options.compression_threshold;
        const negotiated_extension = self.negotiated_extension;
        if (self.selected_extension) |extension| allocator.free(extension);
        request.deinit(allocator);
        var owned_head = request_head;
        owned_head.deinit(allocator);
        self.* = undefined;

        return .{
            .io = io,
            .allocator = allocator,
            .stream = transportStream(transport),
            .tls_server_conn = switch (transport) {
                .tls_server => |connection| connection,
                else => null,
            },
            .role = .server,
            .limits = common.MessageLimits.from(limits),
            .selected_protocol = selected_protocol,
            .permessage_deflate = negotiated_extension.permessage_deflate,
            .compression_send_context_takeover = negotiated_extension.permessage_deflate and
                !negotiated_extension.server_no_context_takeover,
            .compression_receive_context_takeover = negotiated_extension.permessage_deflate and
                !negotiated_extension.client_no_context_takeover,
            .compression_threshold = compression_threshold,
            .compression_send_max_window_bits = negotiated_extension.server_max_window_bits orelse 15,
            .compression_receive_max_window_bits = negotiated_extension.client_max_window_bits orelse 15,
        };
    }

    /// Send a final HTTP rejection and close the transport. The request never
    /// becomes a WebSocket connection.
    pub fn reject(
        self: *PendingUpgrade,
        status: u16,
        reason: []const u8,
        response_headers: []const http1.Header,
        body: []const u8,
    ) Error!void {
        if (self.response_write_failed) return error.ConnectionClosed;
        const allocator = self.allocator;
        var scratch: http1_write.Scratch = .{};
        defer scratch.deinit(allocator);
        const message = try handshake_rejection.prepare(
            allocator,
            self.request.method,
            status,
            reason,
            response_headers,
            body,
            self.limits.max_head_bytes,
            &scratch,
        );
        if (self.deadline) |deadline| {
            _ = try deadline_policy.usableAwake(self.io, deadline);
        }
        try self.writeResponse(message.header, message.body);
        self.deinit();
    }

    fn writeResponse(self: *PendingUpgrade, response_head: []const u8, body: []const u8) Error!void {
        const writer = HandshakeWriter{ .transport = self.transport, .deadline = self.deadline };
        writer.write(response_head, body) catch |err| {
            // HTTP response bytes have an ambiguous peer-visible prefix.
            // Another 101 or rejection cannot safely follow this failure.
            // Keep metadata/TLS ownership alive for deinit, but wake the peer
            // and block all later response writes immediately.
            self.response_write_failed = true;
            transportStream(self.transport).shutdown(self.io, .both) catch {};
            return err;
        };
    }

    pub fn forbidden(self: *PendingUpgrade) Error!void {
        return self.reject(403, "Forbidden", &.{}, &.{});
    }

    pub fn notFound(self: *PendingUpgrade) Error!void {
        return self.reject(404, "Not Found", &.{}, &.{});
    }

    pub fn tooManyRequests(self: *PendingUpgrade) Error!void {
        return self.reject(429, "Too Many Requests", &.{}, &.{});
    }
};

pub const TlsClientIdentityOptions = tls_client_identity.Options;
pub const StapledOcspPolicy = tls_client_identity.StapledOcspPolicy;
pub const CookieHandshakeOptions = cookie_handshake.Options;
pub const HttpProxyOptions = http1_runtime.ProxyOptions;
pub const Socks5Options = proxy_socks5.Options;
pub const RedirectPolicy = redirect.Policy;
pub const AddressResolver = address_resolver.Resolver;
pub const AddressConnectPolicy = tcp_connect.AddressConnectPolicy;
pub const HappyEyeballsOptions = tcp_connect.HappyEyeballsOptions;

pub const RedirectProxy = struct {
    uri: []const u8,
    options: HttpProxyOptions = .{},
};

pub const Socks5RedirectProxy = struct {
    host: []const u8,
    port: u16 = 1080,
    options: Socks5Options = .{},
};

pub const CookieRedirectOptions = struct {
    jar: *http_cookies.Jar,
    request_context: http_cookies.RequestContext = .{},
    store_context: http_cookies.StoreContext = .{},
    /// Cross-origin is a conservative cross-site approximation unless the
    /// application has a registrable-domain policy proving otherwise.
    cross_origin_is_cross_site: bool = true,
};

pub const RedirectOptions = struct {
    policy: RedirectPolicy = .{},
    tls: http1_runtime.TlsClientOptions = .{},
    proxy: ?RedirectProxy = null,
    socks5_proxy: ?Socks5RedirectProxy = null,
    cookies: ?CookieRedirectOptions = null,
};

/// Result of an HTTP/1 Upgrade attempt before a non-101 response is mapped to
/// the compatibility `InvalidResponse` error. Rejection status, headers,
/// trailers, and body remain owned and inspectable until `deinit`. Successful
/// attempts retain the transport until `requireAccepted` transfers it into a
/// WebSocket connection.
pub const ConnectAttempt = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    transport: ?RuntimeTransport,
    response_bytes: []u8,
    response: http1.Response,
    initial_websocket_bytes: ?[]u8,
    key: [24]u8,
    protocols: []const []const u8,
    require_subprotocol: bool = false,
    enable_permessage_deflate: bool,
    allow_context_takeover: bool,
    /// Explicit client/server direction policy overrides allow_context_takeover.
    context_takeover: ?websocket.ContextTakeover = null,
    client_max_window_bits: ?u8,
    server_max_window_bits: ?u8,
    compression_threshold: usize,
    limits: Limits,

    pub fn accepted(self: ConnectAttempt) bool {
        return self.response.status == 101;
    }

    pub fn status(self: ConnectAttempt) u16 {
        return self.response.status;
    }

    pub fn headers(self: ConnectAttempt) []const http1.Header {
        return self.response.headers;
    }

    pub fn responseHeader(
        self: ConnectAttempt,
        name: []const u8,
    ) ?[]const u8 {
        return self.response.header(name);
    }

    pub fn body(self: ConnectAttempt) []const u8 {
        return self.response.body;
    }

    pub fn trailers(self: ConnectAttempt) []const http1.Header {
        return self.response.trailers;
    }

    pub fn deinit(self: *ConnectAttempt) void {
        const allocator = self.allocator;
        const transport = self.transport;
        self.response.deinit(allocator);
        allocator.free(self.response_bytes);
        if (self.initial_websocket_bytes) |bytes| allocator.free(bytes);
        self.* = undefined;
        if (transport) |owned| owned.close();
    }

    pub fn requireAccepted(self: *ConnectAttempt) Error!Connection {
        if (!self.accepted()) {
            if (handshake_headers.isUnsupportedVersionResponse(
                self.response.status,
                self.response.headers,
            )) return error.UnsupportedVersion;
            return error.InvalidResponse;
        }
        const selected_protocol = try validateServerHandshake(
            self.allocator,
            self.response,
            &self.key,
            self.protocols,
        );
        errdefer if (selected_protocol) |protocol| {
            self.allocator.free(protocol);
        };
        try handshake_headers.enforceSubprotocolRequirement(
            self.require_subprotocol,
            selected_protocol,
        );
        const extension_policy: websocket.ExtensionNegotiation.Policy = .{
            .enable_permessage_deflate = self.enable_permessage_deflate,
            .allow_context_takeover = self.allow_context_takeover,
            .context_takeover = self.context_takeover,
        };
        var extension_offer_storage: [websocket.ExtensionNegotiation.max_offer_value_len]u8 = undefined;
        const extension_offer = try websocket.ExtensionNegotiation
            .offerValueInto(
            &extension_offer_storage,
            extension_policy,
            self.client_max_window_bits,
            self.server_max_window_bits,
        );
        const selected_extension = try websocket.ExtensionNegotiation
            .validateResponseHeadersForOfferWithPolicy(
            self.response.headers,
            extension_offer,
            extension_policy,
        );
        if (selected_extension.permessage_deflate and
            !self.enable_permessage_deflate)
        {
            return error.InvalidExtension;
        }

        const transport = self.transport orelse return error.InvalidResponse;
        const initial_websocket_bytes =
            self.initial_websocket_bytes orelse return error.InvalidResponse;
        const connection = Connection{
            .io = self.io,
            .allocator = self.allocator,
            .stream = transportStream(transport),
            .tls_conn = switch (transport) {
                .tls => |value| value,
                else => null,
            },
            .tls_vail_conn = switch (transport) {
                .tls_vail => |value| value,
                else => null,
            },
            .role = .client,
            .limits = common.MessageLimits.from(self.limits),
            .selected_protocol = selected_protocol,
            .permessage_deflate = selected_extension.permessage_deflate,
            .compression_send_context_takeover = selected_extension.permessage_deflate and
                !selected_extension.client_no_context_takeover,
            .compression_receive_context_takeover = selected_extension.permessage_deflate and
                !selected_extension.server_no_context_takeover,
            .compression_threshold = self.compression_threshold,
            .compression_send_max_window_bits = selected_extension.client_max_window_bits orelse 15,
            .compression_receive_max_window_bits = selected_extension.server_max_window_bits orelse 15,
            .inbuf = .fromOwnedSlice(initial_websocket_bytes),
        };
        const allocator = self.allocator;
        self.response.deinit(allocator);
        allocator.free(self.response_bytes);
        self.* = undefined;
        return connection;
    }
};

/// Final HTTP/1 Upgrade attempt plus the actual URI reached after a bounded
/// redirect chain. `final_uri` is canonical after at least one redirect and
/// otherwise preserves the caller's initial URI. This metadata lets layered
/// protocols apply their own redirect policy to the authenticated peer rather
/// than the authority requested before HTTP redirection.
pub const RedirectConnectAttempt = struct {
    allocator: std.mem.Allocator,
    attempt: ConnectAttempt,
    final_uri: []u8,
    redirect_count: usize,

    pub fn deinit(self: *RedirectConnectAttempt) void {
        const allocator = self.allocator;
        self.attempt.deinit();
        allocator.free(self.final_uri);
        self.* = undefined;
    }

    pub fn requireAccepted(self: *RedirectConnectAttempt) Error!Connection {
        const connection = try self.attempt.requireAccepted();
        const allocator = self.allocator;
        allocator.free(self.final_uri);
        self.* = undefined;
        return connection;
    }

    pub fn takeAttempt(self: *RedirectConnectAttempt) ConnectAttempt {
        const attempt = self.attempt;
        self.allocator.free(self.final_uri);
        self.* = undefined;
        return attempt;
    }
};

pub const Client = @import("runtime/client.zig").Client;

pub fn uriTargetAlloc(allocator: std.mem.Allocator, uri: std.Uri) Error![]u8 {
    const path_value = uriComponentBytes(uri.path);
    const path = if (path_value.len == 0) "/" else path_value;
    if (uri.query) |query| {
        return try std.fmt.allocPrint(allocator, "{s}?{s}", .{ path, uriComponentBytes(query) });
    }
    return try allocator.dupe(u8, path);
}

fn uriComponentBytes(component: std.Uri.Component) []const u8 {
    return switch (component) {
        .raw, .percent_encoded => |value| value,
    };
}

pub fn connectUriEndpointBefore(
    allocator: std.mem.Allocator,
    io: std.Io,
    endpoint: http1_runtime.UriEndpoint,
    options: ConnectOptions,
    deadline: ?std.Io.Clock.Timestamp,
) Error!net.Stream {
    try tcp_connect.validateAddressConnectPolicy(
        options.address_connect_policy,
    );
    const connect_deadline = if (deadline) |absolute|
        try deadline_policy.capTimeout(
            io,
            absolute,
            options.connect_timeout,
        )
    else
        try deadline_policy.fromTimeout(io, options.connect_timeout);
    return tcp_connect.endpointWithOptions(
        allocator,
        io,
        switch (endpoint.target) {
            .ip => |address| address,
            .host => null,
        },
        endpoint.tls_host,
        endpoint.port,
        options.address_resolver,
        options.address_connect_policy,
        connect_deadline,
        .fromOptions(options),
    );
}

pub fn connectNamedEndpointBefore(
    allocator: std.mem.Allocator,
    io: std.Io,
    host: []const u8,
    port: u16,
    options: ConnectOptions,
    deadline: ?std.Io.Clock.Timestamp,
) Error!net.Stream {
    const parsed = try endpoint_host.parse(host, port);
    try tcp_connect.validateAddressConnectPolicy(
        options.address_connect_policy,
    );
    const connect_deadline = if (deadline) |absolute|
        try deadline_policy.capTimeout(
            io,
            absolute,
            options.connect_timeout,
        )
    else
        try deadline_policy.fromTimeout(io, options.connect_timeout);
    return tcp_connect.endpointWithOptions(
        allocator,
        io,
        parsed.literal,
        parsed.host,
        port,
        options.address_resolver,
        options.address_connect_policy,
        connect_deadline,
        .fromOptions(options),
    );
}

pub const ConnectOptions = struct {
    /// Source IP/port for newly opened TCP sockets.
    /// Null leaves source selection to the OS. Requires Netz's zio backend.
    local_address: ?std.Io.net.IpAddress = null,
    /// Constrain the socket's network interface independently of source IP.
    /// Names are borrowed; unsupported platforms/backends fail explicitly.
    network_interface: ?tcp_connect.NetworkInterface = null,

    /// HTTP Host authority for the WebSocket opening handshake. Named connects
    /// default to host:port, with brackets around an IPv6 literal.
    host: []const u8 = "",
    target: []const u8 = "/",
    protocols: []const []const u8 = &.{},
    /// Require the server to select one offered subprotocol. RFC 6455 permits
    /// a null selection by default even when the client sent preferences.
    require_subprotocol: bool = false,
    /// Optional browser Origin value for the opening request.
    origin: ?[]const u8 = null,
    /// Additional opening-handshake fields such as Authorization or Cookie.
    /// Runtime-owned and body-framing headers are rejected so callers cannot
    /// create an ambiguous or body-bearing Upgrade request.
    extra_headers: []const http1.Header = &.{},
    enable_permessage_deflate: bool = false,
    /// Offer RFC 7692 context takeover. The peer may still select
    /// direction-specific no-context parameters.
    allow_context_takeover: bool = false,
    /// Explicit client/server direction policy overrides allow_context_takeover.
    context_takeover: ?websocket.ContextTakeover = null,
    /// Offer a bound for this client's compression history.
    client_max_window_bits: ?u8 = null,
    /// Require the server compressor to use at most this history window.
    server_max_window_bits: ?u8 = null,
    /// Minimum complete message size considered for outbound compression.
    /// Set to zero to attempt every data message or maxInt to receive-only.
    compression_threshold: usize = default_compression_threshold,
    tcp_nodelay: bool = true,
    /// Optional TCP keepalive idle, retry interval, and probe-count policy.
    tcp_keepalive: ?TcpKeepAlive = null,
    /// Linux TCP_USER_TIMEOUT in milliseconds. Null preserves the kernel
    /// default; requesting a value on an unsupported platform fails.
    tcp_user_timeout_ms: ?u32 = null,
    /// Absolute budget for DNS resolution plus all TCP connection attempts.
    /// TLS and HTTP Upgrade retain their separate handshake policies.
    connect_timeout: ?std.Io.Duration = null,
    /// Optional resolver shared by WS/WSS hostname and URI connects plus every
    /// redirect hop. Literal IP targets bypass it. Returned addresses share one
    /// connect deadline while HTTP authority, TLS SNI, and certificate identity
    /// remain bound to the configured host.
    address_resolver: ?AddressResolver = null,
    /// Explicit address-attempt policy. Ordered sequential fallback remains the
    /// default; Happy Eyeballs uses bounded staggered racing.
    address_connect_policy: AddressConnectPolicy = .ordered,
    limits: Limits = .{},
    /// Backward-compatible mTLS shorthand. `vail_tls` takes precedence when
    /// both are supplied.
    tls_identity: ?TlsClientIdentityOptions = null,
    /// Select vail-backed WSS without requiring a client certificate. This
    /// enables peer-chain, ALPN, exporter and KeyUpdate APIs for ordinary WSS.
    /// Cleartext connect helpers reject this field.
    vail_tls: ?TlsClientIdentityOptions = null,
    /// Optional TLS handshake budget used by the standard WSS client. The
    /// vail path uses this value when its nested option leaves one unset.
    tls_handshake_timeout: ?std.Io.Duration = null,
};

pub fn hasClientIdentity(options: ConnectOptions) bool {
    if (options.vail_tls) |tls| {
        if (tls.identity != null) return true;
    }
    if (options.tls_identity) |tls| {
        if (tls.identity != null) return true;
    }
    return false;
}

pub fn clearRedirectTlsTickets(options: *ConnectOptions) void {
    if (options.vail_tls) |configured| {
        var tls = configured;
        tls.tls12_ticket_resumption = null;
        tls.tls13_ticket_resumption = null;
        options.vail_tls = tls;
    }
    if (options.tls_identity) |configured| {
        var tls = configured;
        tls.tls12_ticket_resumption = null;
        tls.tls13_ticket_resumption = null;
        options.tls_identity = tls;
    }
}

pub const OwnedMessage = common.OwnedMessage;
pub const CloseHandshakeEvent = common.CloseHandshakeEvent;
pub const PingEvent = common.PingEvent;
pub const Message = common.Message;
pub const MessageWriteProgress = common.MessageWriteProgress;
pub const MessageIntoReceiveState = common.MessageIntoReceiveState;
pub const PendingAutomaticControl = common.PendingAutomaticControl;
pub const automatic_control = @import("runtime/control/automatic.zig");
pub const control_admission = @import("runtime/control/admission.zig");
pub const receive_cleanup = @import("runtime/receive_failure/cleanup.zig");
pub const ping_control = @import("runtime/control/ping.zig");

pub const Connection = @import("runtime/connection.zig").Connection;

pub const H2Connection = @import("runtime/h2_connection.zig").H2Connection;

pub const H2Client = struct {
    pub fn open(
        allocator: std.mem.Allocator,
        connection: *http2_runtime.Connection,
        options: H2ConnectOptions,
    ) Error!H2Connection {
        var attempt = try openAttemptUntil(
            allocator,
            connection,
            options,
            null,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn openAttempt(
        allocator: std.mem.Allocator,
        connection: *http2_runtime.Connection,
        options: H2ConnectOptions,
    ) Error!H2ConnectAttempt {
        return openAttemptUntil(allocator, connection, options, null);
    }

    /// Complete RFC 8441 negotiation before one absolute awake-clock
    /// deadline. The HTTP/2 connection remains caller-owned on failure.
    pub fn openWithDeadline(
        allocator: std.mem.Allocator,
        connection: *http2_runtime.Connection,
        options: H2ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!H2Connection {
        const absolute = try deadline_policy.usableAwake(
            connection.io,
            deadline,
        );
        var attempt = try openAttemptUntil(
            allocator,
            connection,
            options,
            absolute,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn openAttemptWithDeadline(
        allocator: std.mem.Allocator,
        connection: *http2_runtime.Connection,
        options: H2ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!H2ConnectAttempt {
        const absolute = try deadline_policy.usableAwake(
            connection.io,
            deadline,
        );
        return openAttemptUntil(
            allocator,
            connection,
            options,
            absolute,
        );
    }

    pub fn openWithTimeout(
        allocator: std.mem.Allocator,
        connection: *http2_runtime.Connection,
        options: H2ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!H2Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return openWithDeadline(
            allocator,
            connection,
            options,
            .fromNow(
                connection.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    pub fn openAttemptWithTimeout(
        allocator: std.mem.Allocator,
        connection: *http2_runtime.Connection,
        options: H2ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!H2ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return openAttemptWithDeadline(
            allocator,
            connection,
            options,
            .fromNow(
                connection.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    fn openAttemptUntil(
        allocator: std.mem.Allocator,
        connection: *http2_runtime.Connection,
        options: H2ConnectOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!H2ConnectAttempt {
        var protocol_value_stack: [handshake_headers.protocol_value_stack_capacity]u8 = undefined;
        var protocol_value = try handshake_headers.prepareProtocolValue(
            allocator,
            options.protocols,
            &protocol_value_stack,
        );
        defer protocol_value.deinit(allocator);
        try validateH2ClientExtraHeaders(options.extra_headers);
        const cookie_scope: ?[]u8 = if (options.cookies != null)
            try cookie_handshake.scopeUriAlloc(
                allocator,
                connection.resolveRequestScheme(options.scheme),
                connection.resolveRequestAuthorityFromHeaders(options.authority, options.extra_headers) orelse
                    return error.InvalidUri,
                options.path,
            )
        else
            null;
        defer if (cookie_scope) |uri| allocator.free(uri);
        var prepared_cookie: ?cookie_handshake.Prepared = if (options.cookies) |cookie_options|
            try cookie_handshake.prepare(
                allocator,
                connection.io,
                cookie_options,
                cookie_scope.?,
                options.extra_headers,
            )
        else
            null;
        defer if (prepared_cookie) |*prepared| prepared.deinit();
        const extension_policy: websocket.ExtensionNegotiation.Policy = .{
            .enable_permessage_deflate = options.enable_permessage_deflate,
            .allow_context_takeover = options.allow_context_takeover,
            .context_takeover = options.context_takeover,
        };
        var extension_offer_storage: [websocket.ExtensionNegotiation.max_offer_value_len]u8 = undefined;
        const extension_offer = try websocket.ExtensionNegotiation
            .offerValueInto(
            &extension_offer_storage,
            extension_policy,
            options.client_max_window_bits,
            options.server_max_window_bits,
        );
        const request_count = std.math.add(
            usize,
            1 + @as(usize, @intFromBool(protocol_value.value.len != 0)) +
                @as(usize, @intFromBool(options.origin != null)) +
                @as(usize, @intFromBool(extension_offer != null)) +
                @as(usize, @intFromBool(
                    prepared_cookie != null and
                        prepared_cookie.?.value.len != 0,
                )),
            options.extra_headers.len,
        ) catch return error.HeadersTooLarge;
        var request_stack: [handshake_storage.stack_capacity]http2.Hpack.HeaderField = undefined;
        const request_headers = try handshake_storage.acquire(
            http2.Hpack.HeaderField,
            allocator,
            &request_stack,
            request_count,
        );
        defer handshake_storage.release(
            http2.Hpack.HeaderField,
            allocator,
            &request_stack,
            request_headers,
        );
        var request_index: usize = 0;
        request_headers[request_index] = .{
            .name = "sec-websocket-version",
            .value = "13",
        };
        request_index += 1;
        if (protocol_value.value.len != 0) {
            request_headers[request_index] = .{
                .name = "sec-websocket-protocol",
                .value = protocol_value.value,
            };
            request_index += 1;
        }
        if (options.origin) |origin| {
            request_headers[request_index] = .{
                .name = "origin",
                .value = origin,
            };
            request_index += 1;
        }
        if (extension_offer) |value| {
            request_headers[request_index] = .{
                .name = "sec-websocket-extensions",
                .value = value,
            };
            request_index += 1;
        }
        @memcpy(
            request_headers[request_index..][0..options.extra_headers.len],
            options.extra_headers,
        );
        request_index += options.extra_headers.len;
        if (prepared_cookie) |prepared| if (prepared.value.len != 0) {
            request_headers[request_index] = .{
                .name = "cookie",
                .value = prepared.value,
                .never_index = true,
            };
            request_index += 1;
        };
        std.debug.assert(request_index == request_headers.len);

        const request_options: http2_runtime.RequestOptions = .{
            .method = "CONNECT",
            .path = options.path,
            .scheme = options.scheme,
            .authority = options.authority,
            .protocol = "websocket",
            .headers = request_headers,
        };
        var response = if (deadline) |absolute|
            try connection.openExtendedConnectAttemptWithDeadline(
                request_options,
                absolute,
            )
        else
            try connection.openExtendedConnectAttempt(request_options);
        errdefer response.deinit(allocator);
        if (options.cookies) |cookie_options| {
            try cookie_handshake.store(
                connection.io,
                cookie_options,
                cookie_scope.?,
                response.headers,
            );
        }
        return .{
            .allocator = allocator,
            .response = response,
            .options = options,
        };
    }
};

/// Result of an RFC 8441 attempt before a non-2xx response is mapped to the
/// compatibility `InvalidResponse` error. Rejection metadata stays owned and
/// inspectable until `deinit` or `requireAccepted`.
pub const H2ConnectAttempt = struct {
    allocator: std.mem.Allocator,
    response: http2_runtime.ExtendedConnectAttempt,
    options: H2ConnectOptions,

    pub fn accepted(self: H2ConnectAttempt) bool {
        return self.response.accepted();
    }

    pub fn status(self: H2ConnectAttempt) u16 {
        return self.response.status;
    }

    pub fn responseHeader(
        self: H2ConnectAttempt,
        name: []const u8,
    ) ?[]const u8 {
        return self.response.responseHeader(name);
    }

    pub fn body(self: H2ConnectAttempt) []const u8 {
        return self.response.body;
    }

    pub fn trailers(
        self: H2ConnectAttempt,
    ) []const http2.Hpack.HeaderField {
        return self.response.trailers;
    }

    pub fn deinit(self: *H2ConnectAttempt) void {
        const allocator = self.allocator;
        self.response.deinit(allocator);
        self.* = undefined;
    }

    pub fn requireAccepted(self: *H2ConnectAttempt) Error!H2Connection {
        if (!self.accepted()) {
            if (handshake_headers.isUnsupportedVersionResponse(
                self.response.status,
                self.response.headers,
            )) return error.UnsupportedVersion;
            return error.InvalidStatus;
        }
        const selected_protocol = try validateH2ServerHandshake(
            self.allocator,
            self.response.headers,
            self.options.protocols,
        );
        errdefer if (selected_protocol) |protocol| {
            self.allocator.free(protocol);
        };
        try handshake_headers.enforceSubprotocolRequirement(
            self.options.require_subprotocol,
            selected_protocol,
        );
        const extension_policy: websocket.ExtensionNegotiation.Policy = .{
            .enable_permessage_deflate = self.options.enable_permessage_deflate,
            .allow_context_takeover = self.options.allow_context_takeover,
            .context_takeover = self.options.context_takeover,
        };
        var extension_offer_storage: [websocket.ExtensionNegotiation.max_offer_value_len]u8 = undefined;
        const extension_offer = try websocket.ExtensionNegotiation
            .offerValueInto(
            &extension_offer_storage,
            extension_policy,
            self.options.client_max_window_bits,
            self.options.server_max_window_bits,
        );
        const selected_extension = try websocket.ExtensionNegotiation
            .validateResponseHeadersForOfferWithPolicy(
            self.response.headers,
            extension_offer,
            extension_policy,
        );
        if (selected_extension.permessage_deflate and
            !self.options.enable_permessage_deflate)
        {
            return error.InvalidExtension;
        }
        var response = try self.response.requireAccepted();
        const tunnel = response.tunnel;
        response.deinit(self.allocator);
        const allocator = self.allocator;
        const options = self.options;
        self.* = undefined;
        return H2Connection.init(
            allocator,
            tunnel,
            .client,
            options.limits,
            selected_protocol,
            selected_extension,
            options.compression_threshold,
        );
    }
};

pub const H2Server = struct {
    pub fn accept(
        allocator: std.mem.Allocator,
        connection: *http2_runtime.Connection,
        options: H2AcceptOptions,
    ) Error!H2Connection {
        var pending = try receiveUpgradeRequestUntil(
            allocator,
            connection,
            options,
            null,
        );
        errdefer pending.deinit();
        return pending.accept();
    }

    pub fn acceptWithDeadline(
        allocator: std.mem.Allocator,
        connection: *http2_runtime.Connection,
        options: H2AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!H2Connection {
        const absolute = try deadline_policy.usableAwake(
            connection.io,
            deadline,
        );
        var pending = try receiveUpgradeRequestUntil(
            allocator,
            connection,
            options,
            absolute,
        );
        errdefer pending.deinit();
        return pending.accept();
    }

    pub fn acceptWithTimeout(
        allocator: std.mem.Allocator,
        connection: *http2_runtime.Connection,
        options: H2AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!H2Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return acceptWithDeadline(
            allocator,
            connection,
            options,
            .fromNow(
                connection.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    /// Receive and validate an RFC 8441 request without sending the 200
    /// response. The returned value owns only that HTTP/2 stream; the parent
    /// connection remains caller-owned and may carry independent streams.
    pub fn receiveUpgradeRequest(
        allocator: std.mem.Allocator,
        connection: *http2_runtime.Connection,
        options: H2AcceptOptions,
    ) Error!PendingH2Upgrade {
        return receiveUpgradeRequestUntil(
            allocator,
            connection,
            options,
            null,
        );
    }

    pub fn receiveUpgradeRequestWithDeadline(
        allocator: std.mem.Allocator,
        connection: *http2_runtime.Connection,
        options: H2AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PendingH2Upgrade {
        const absolute = try deadline_policy.usableAwake(
            connection.io,
            deadline,
        );
        return receiveUpgradeRequestUntil(
            allocator,
            connection,
            options,
            absolute,
        );
    }

    pub fn receiveUpgradeRequestWithTimeout(
        allocator: std.mem.Allocator,
        connection: *http2_runtime.Connection,
        options: H2AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!PendingH2Upgrade {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return receiveUpgradeRequestWithDeadline(
            allocator,
            connection,
            options,
            .fromNow(
                connection.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    fn receiveUpgradeRequestUntil(
        allocator: std.mem.Allocator,
        connection: *http2_runtime.Connection,
        options: H2AcceptOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!PendingH2Upgrade {
        var request = if (deadline) |absolute|
            try connection.readExtendedConnectRequestWithDeadline(
                "websocket",
                absolute,
            )
        else
            try connection.readExtendedConnectRequest("websocket");
        var request_owned = true;
        errdefer if (request_owned) {
            const stream_id = request.stream_id;
            request.deinit(allocator);
            if (deadline != null) connection.abortExtendedConnect(stream_id, deadline) else connection.abandonExtendedConnect(stream_id);
        };
        const version = try requiredH2SingletonHeader(
            request.headers,
            "sec-websocket-version",
        );
        websocket.validateClientVersion(version) catch |err| switch (err) {
            error.UnsupportedVersion => {
                try validateH2VersionNegotiationRequest(
                    allocator,
                    request.headers,
                    options.allowed_origins,
                );
                try validateH2ServerExtraHeaders(options.extra_headers);
                if (deadline) |absolute| {
                    _ = try deadline_policy.usableAwake(
                        connection.io,
                        absolute,
                    );
                }
                if (deadline) |absolute| {
                    try connection.rejectExtendedConnectWithDeadline(request.stream_id, 426, &.{.{ .name = "sec-websocket-version", .value = "13" }}, absolute);
                } else try connection.rejectExtendedConnect(
                    request.stream_id,
                    426,
                    &.{.{
                        .name = "sec-websocket-version",
                        .value = "13",
                    }},
                );
                request.deinit(allocator);
                request_owned = false;
                return err;
            },
            else => return err,
        };
        try rejectH2ExtendedConnectLegacyHeaders(request.headers);
        try origin_policy.validateH2(request.headers, options.allowed_origins);

        const selected_protocol = try selectH2Subprotocol(allocator, request.headers, options.protocols);
        errdefer if (selected_protocol) |protocol| allocator.free(protocol);
        if (options.require_subprotocol and selected_protocol == null) {
            return error.InvalidSubprotocol;
        }
        const extension_policy: websocket.ExtensionNegotiation.Policy = .{
            .enable_permessage_deflate = options.enable_permessage_deflate,
            .allow_context_takeover = options.allow_context_takeover,
            .context_takeover = options.context_takeover,
            .accept_client_max_window_bits = options.client_max_window_bits,
            .accept_server_max_window_bits = options.server_max_window_bits,
        };
        const selected_extension = try acceptH2Extensions(
            allocator,
            request.headers,
            extension_policy,
        );
        errdefer if (selected_extension) |extension| allocator.free(extension);
        const negotiated_extension = if (selected_extension) |extension|
            try websocket.ExtensionNegotiation.validateResponseWithPolicy(
                extension,
                extension_policy,
            )
        else
            websocket.ExtensionNegotiation{};

        try validateH2ServerExtraHeaders(options.extra_headers);
        request_owned = false;
        return .{
            .allocator = allocator,
            .connection = connection,
            .options = options,
            .deadline = deadline,
            .request = request,
            .selected_protocol = selected_protocol,
            .selected_extension = selected_extension,
            .negotiated_extension = negotiated_extension,
        };
    }
};

fn validateH2VersionNegotiationRequest(
    allocator: std.mem.Allocator,
    headers: []const http2.Hpack.HeaderField,
    allowed_origins: []const []const u8,
) Error!void {
    try rejectH2ExtendedConnectLegacyHeaders(headers);
    try origin_policy.validateH2(headers, allowed_origins);
    if (try selectH2Subprotocol(allocator, headers, &.{})) |protocol| {
        allocator.free(protocol);
    }
    if (try acceptH2Extensions(allocator, headers, .{})) |extension| {
        allocator.free(extension);
    }
}

/// A validated RFC 8441 request awaiting application admission. No response
/// HEADERS have been sent. The request headers and negotiated values remain
/// owned until this value is accepted, rejected, or deinitialized. Slices in
/// the original `H2AcceptOptions` must remain valid until then.
pub const PendingH2Upgrade = struct {
    allocator: std.mem.Allocator,
    connection: *http2_runtime.Connection,
    options: H2AcceptOptions,
    deadline: ?std.Io.Clock.Timestamp,
    request: http2_runtime.ExtendedConnectRequest,
    selected_protocol: ?[]u8,
    selected_extension: ?[]u8,
    negotiated_extension: websocket.ExtensionNegotiation,

    /// Release the pending stream, using its original budget for cancellation.
    /// A successful reset preserves siblings; a failed or expired reset makes
    /// the caller-owned parent ineligible for further protocol I/O.
    pub fn deinit(self: *PendingH2Upgrade) void {
        const allocator = self.allocator;
        const connection = self.connection;
        const stream_id = self.request.stream_id;
        const deadline = self.deadline;
        self.request.deinit(allocator);
        if (self.selected_protocol) |protocol| allocator.free(protocol);
        if (self.selected_extension) |extension| allocator.free(extension);
        self.* = undefined;
        if (deadline != null) connection.abortExtendedConnect(stream_id, deadline) else connection.abandonExtendedConnect(stream_id);
    }

    pub fn streamId(self: PendingH2Upgrade) u31 {
        return self.request.stream_id;
    }

    /// Remote IP peer of the parent HTTP/2 connection.
    pub fn peerAddress(self: PendingH2Upgrade) ?std.Io.net.IpAddress {
        return self.connection.peerAddress();
    }

    pub fn target(self: PendingH2Upgrade) []const u8 {
        return self.request.path;
    }

    pub fn scheme(self: PendingH2Upgrade) []const u8 {
        return self.request.scheme;
    }

    pub fn authority(self: PendingH2Upgrade) ?[]const u8 {
        return self.request.authority;
    }

    pub fn headers(
        self: PendingH2Upgrade,
    ) []const http2.Hpack.HeaderField {
        return self.request.headers;
    }

    pub fn header(
        self: PendingH2Upgrade,
        name: []const u8,
    ) ?[]const u8 {
        for (self.request.headers) |field| {
            if (std.ascii.eqlIgnoreCase(field.name, name)) return field.value;
        }
        return null;
    }

    /// Authenticated TLS metadata for the HTTP/2 connection carrying this
    /// extended CONNECT. Cleartext h2c returns null.
    pub fn peerCertificates(
        self: *const PendingH2Upgrade,
    ) ?[]const []const u8 {
        return self.connection.peerCertificates();
    }
    pub fn negotiatedAlpn(self: *const PendingH2Upgrade) ?[]const u8 {
        return self.connection.negotiatedAlpn();
    }
    pub fn negotiatedCipherSuite(
        self: *const PendingH2Upgrade,
    ) ?tls_stream.NegotiatedCipherSuite {
        return self.connection.negotiatedCipherSuite();
    }
    pub fn negotiatedTranscriptHash(
        self: *const PendingH2Upgrade,
    ) ?tls_stream.TranscriptHash {
        return self.connection.negotiatedTranscriptHash();
    }

    pub fn accept(self: *PendingH2Upgrade) Error!H2Connection {
        return self.acceptWithHeaders(&.{});
    }

    pub fn acceptWithHeaders(
        self: *PendingH2Upgrade,
        additional_headers: []const http2.Hpack.HeaderField,
    ) Error!H2Connection {
        const allocator = self.allocator;
        try validateH2ServerExtraHeaders(additional_headers);
        const negotiated_count: usize =
            @as(usize, @intFromBool(self.selected_protocol != null)) +
            @as(usize, @intFromBool(self.selected_extension != null));
        const application_count = std.math.add(
            usize,
            self.options.extra_headers.len,
            additional_headers.len,
        ) catch return error.HeadersTooLarge;
        const response_count = std.math.add(
            usize,
            application_count,
            negotiated_count,
        ) catch return error.HeadersTooLarge;
        var response_stack: [handshake_storage.stack_capacity]http2.Hpack.HeaderField =
            undefined;
        const response_headers = try handshake_storage.acquire(
            http2.Hpack.HeaderField,
            allocator,
            &response_stack,
            response_count,
        );
        defer handshake_storage.release(
            http2.Hpack.HeaderField,
            allocator,
            &response_stack,
            response_headers,
        );
        var response_index: usize = 0;
        if (self.selected_protocol) |protocol| {
            response_headers[response_index] = .{
                .name = "sec-websocket-protocol",
                .value = protocol,
            };
            response_index += 1;
        }
        if (self.selected_extension) |extension| {
            response_headers[response_index] = .{
                .name = "sec-websocket-extensions",
                .value = extension,
            };
            response_index += 1;
        }
        @memcpy(
            response_headers[response_index..][0..self.options.extra_headers.len],
            self.options.extra_headers,
        );
        response_index += self.options.extra_headers.len;
        @memcpy(response_headers[response_index..], additional_headers);
        if (self.deadline) |absolute| {
            _ = try deadline_policy.usableAwake(
                self.connection.io,
                absolute,
            );
        }
        const tunnel = if (self.deadline) |absolute|
            try self.connection.acceptExtendedConnectWithDeadline(self.request, response_headers, absolute)
        else
            try self.connection.acceptExtendedConnect(
                self.request,
                response_headers,
            );

        const options = self.options;
        const selected_protocol = self.selected_protocol;
        const negotiated_extension = self.negotiated_extension;
        self.request.deinit(allocator);
        if (self.selected_extension) |extension| allocator.free(extension);
        self.* = undefined;
        return H2Connection.init(
            allocator,
            tunnel,
            .server,
            options.limits,
            selected_protocol,
            negotiated_extension,
            options.compression_threshold,
        );
    }

    /// Send a header-only final non-2xx response on this stream without
    /// closing the parent connection. Use `rejectWithBody` when diagnostics
    /// require DATA or trailers.
    pub fn reject(
        self: *PendingH2Upgrade,
        status: u16,
        response_headers: []const http2.Hpack.HeaderField,
    ) Error!void {
        return self.rejectWithBody(
            status,
            response_headers,
            &.{},
            &.{},
        );
    }

    /// Reject this CONNECT stream with a bounded HTTP/2 response entity. The
    /// parent connection remains usable; body retention on the client is
    /// governed by its HTTP/2 `Limits.max_body_bytes`.
    pub fn rejectWithBody(
        self: *PendingH2Upgrade,
        status: u16,
        response_headers: []const http2.Hpack.HeaderField,
        body: []const u8,
        trailers: []const http2.Hpack.HeaderField,
    ) Error!void {
        if (status < 300 or status > 599) return error.InvalidStatus;
        try validateH2RejectionHeaders(response_headers);
        try validateH2RejectionHeaders(trailers);
        if (self.deadline) |absolute| {
            _ = try deadline_policy.usableAwake(
                self.connection.io,
                absolute,
            );
        }
        if (self.deadline) |absolute| {
            try self.connection.rejectExtendedConnectWithBodyWithDeadline(self.request.stream_id, status, response_headers, body, trailers, absolute);
        } else try self.connection.rejectExtendedConnectWithBody(
            self.request.stream_id,
            status,
            response_headers,
            body,
            trailers,
        );
        const allocator = self.allocator;
        self.request.deinit(allocator);
        if (self.selected_protocol) |protocol| allocator.free(protocol);
        if (self.selected_extension) |extension| allocator.free(extension);
        self.* = undefined;
    }

    pub fn forbidden(self: *PendingH2Upgrade) Error!void {
        return self.reject(403, &.{});
    }

    pub fn notFound(self: *PendingH2Upgrade) Error!void {
        return self.reject(404, &.{});
    }

    pub fn tooManyRequests(self: *PendingH2Upgrade) Error!void {
        return self.reject(429, &.{});
    }
};

/// Narrow test hook for constructing deliberately split WebSocket frames.
/// Production callers should use the validated public message APIs.
pub const testing = if (builtin.is_test) struct {
    pub fn validateHttp1ClientExtraHeaders(
        headers: []const http1.Header,
    ) Error!void {
        return validateHttp1ClientExtraHeadersImpl(headers);
    }

    pub fn validateH2RejectionHeaders(
        headers: []const http2.Hpack.HeaderField,
    ) Error!void {
        return handshake_headers.validateH2RejectionExtra(headers);
    }

    pub fn writeFrame(
        connection: anytype,
        opcode: websocket.Opcode,
        payload: []const u8,
        fin: bool,
    ) Error!void {
        return connection.writeFrameLocked(opcode, payload, fin);
    }

    pub fn pendingH2CloseProgress(
        connection: *const H2Connection,
    ) ?struct { committed: usize, total: usize } {
        const pending = connection.pending_write.closeConst() orelse
            return null;
        return .{ .committed = pending.committed, .total = pending.len };
    }

    pub fn pendingH2PingProgress(
        connection: *const H2Connection,
    ) ?struct { committed: usize, total: usize } {
        const pending = connection.pending_write.pingConst() orelse
            return null;
        return .{ .committed = pending.committed, .total = pending.len };
    }

    pub fn pendingH2AutomaticControlProgress(
        connection: *const H2Connection,
    ) ?control_admission.Progress {
        return control_admission.progressForTest(connection);
    }

    pub fn pendingH2MessageProgress(
        connection: *const H2Connection,
    ) ?MessageWriteProgress {
        const pending = switch (connection.pending_write) {
            .message => |value| value,
            else => return null,
        };
        return .{
            .committed_bytes = pending.committed,
            .total_bytes = pending.totalLen(),
        };
    }

    pub fn pendingMessageProgress(
        connection: *const Connection,
    ) ?MessageWriteProgress {
        const pending = switch (connection.pending_write) {
            .message => |value| value,
            else => return null,
        };
        return .{
            .committed_bytes = pending.committed,
            .total_bytes = pending.totalLen(),
        };
    }

    pub fn pendingPingProgress(
        connection: *const Connection,
    ) ?struct { committed: usize, total: usize } {
        const pending = switch (connection.pending_write) {
            .ping => |value| value,
            else => return null,
        };
        return .{ .committed = pending.committed, .total = pending.len };
    }

    pub fn pendingAutomaticControlProgress(
        connection: *const Connection,
    ) ?control_admission.Progress {
        return control_admission.progressForTest(connection);
    }

    pub fn pendingCloseProgress(
        connection: *const Connection,
    ) ?struct { committed: usize, total: usize } {
        const pending = switch (connection.pending_write) {
            .close => |value| value,
            else => return null,
        };
        return .{ .committed = pending.committed, .total = pending.len };
    }

    pub fn receiveStorageReleased(connection: anytype) bool {
        const tunnel_storage_released =
            if (comptime @hasField(@TypeOf(connection.*), "pending_tunnel_data"))
                connection.pending_tunnel_data == null and
                    connection.pending_tunnel_data_offset == 0
            else
                true;
        return connection.receiveFailed() and
            connection.inbuf.capacity == 0 and
            connection.inbuf.items.len == 0 and
            connection.inbuf_consumed == 0 and
            connection.message_assembler == null and
            !connection.message_into.active() and
            connection.message_frame_receive.header == null and
            connection.compression_receive.payload.capacity == 0 and
            connection.compression_receive.decoded.capacity == 0 and
            connection.compression_receive.context == null and
            tunnel_storage_released;
    }

    pub fn writeAborted(connection: anytype) bool {
        return connection.writeAborted();
    }

    pub fn outboundStorageReleased(connection: anytype) bool {
        const pending_released = if (comptime @hasField(
            @TypeOf(connection.*),
            "pending_write",
        ))
            connection.pending_write.isNone()
        else
            connection.pending_message == null and
                connection.pending_ping == null and
                connection.pending_close == null;
        return pending_released and
            connection.pending_auto_control == null and
            connection.automatic_control_admission == null and
            !connection.application_write_pending.load(.acquire) and
            !connection.automatic_write_pending.load(.acquire) and
            !connection.automatic_control_waiting.load(.acquire) and
            connection.compression_send.payload.capacity == 0 and
            connection.compression_send.encoder == null and
            connection.compression_send.context == null;
    }

    pub fn failReceiveAndFinish(
        connection: anytype,
        code: websocket.CloseCode,
    ) void {
        if (failReceive(connection)) {
            connection.finishReceiveFailure(code, null);
        }
    }

    pub fn beginPendingControl(
        connection: *Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
    ) Error!void {
        return switch (opcode) {
            .ping, .close => connection.beginPendingControlLocked(
                opcode,
                payload,
            ),
            else => error.InvalidFrame,
        };
    }

    pub fn pendingControlBytes(
        connection: *const Connection,
        opcode: websocket.Opcode,
    ) ?[]const u8 {
        return switch (opcode) {
            .ping => if (connection.pending_write.pingConst()) |pending|
                pending.bytes[0..pending.len]
            else
                null,
            .close => if (connection.pending_write.closeConst()) |pending|
                pending.bytes[0..pending.len]
            else
                null,
            else => null,
        };
    }

    pub fn clearPendingControlForTest(
        connection: *Connection,
        opcode: websocket.Opcode,
    ) void {
        switch (opcode) {
            .ping => std.debug.assert(connection.pending_write.isPing()),
            .close => std.debug.assert(connection.pending_write.isClose()),
            else => unreachable,
        }
        connection.pending_write = .none;
        connection.application_write_pending.store(false, .release);
    }

    pub fn writePendingControlPrefix(
        connection: *Connection,
        opcode: websocket.Opcode,
        end: usize,
    ) Error!void {
        const pending = switch (opcode) {
            .ping => connection.pending_write.pingPtr() orelse
                return error.InvalidFrame,
            .close => connection.pending_write.closePtr() orelse
                return error.InvalidFrame,
            else => return error.InvalidFrame,
        };
        if (end < pending.committed or end > pending.len) {
            return error.InvalidFrame;
        }
        try connection.transport().writeAll(
            pending.bytes[pending.committed..end],
        );
        pending.committed = end;
    }

    pub fn beginPendingMessage(
        connection: *Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
    ) Error!void {
        return connection.beginPendingMessageLocked(opcode, payload);
    }

    pub fn markPendingMessageCommitted(
        connection: anytype,
        committed: usize,
    ) void {
        if (comptime @hasField(@TypeOf(connection.*), "pending_write")) {
            const pending = connection.pending_write.messagePtr().?;
            std.debug.assert(committed <= pending.totalLen());
            pending.committed = committed;
        } else {
            std.debug.assert(connection.pending_message != null);
            std.debug.assert(
                committed <= connection.pending_message.?.totalLen(),
            );
            connection.pending_message.?.committed = committed;
        }
    }

    pub fn markPendingControlCommitted(
        connection: anytype,
        opcode: websocket.Opcode,
        committed: usize,
    ) void {
        if (comptime @hasField(@TypeOf(connection.*), "pending_write")) {
            const pending = switch (opcode) {
                .ping => connection.pending_write.pingPtr().?,
                .close => connection.pending_write.closePtr().?,
                else => unreachable,
            };
            std.debug.assert(committed <= pending.len);
            pending.committed = committed;
            return;
        }
        switch (opcode) {
            .ping => {
                std.debug.assert(committed <= connection.pending_ping.?.len);
                connection.pending_ping.?.committed = committed;
            },
            .close => {
                std.debug.assert(committed <= connection.pending_close.?.len);
                connection.pending_close.?.committed = committed;
            },
            else => unreachable,
        }
    }

    pub fn beginPendingH2Message(
        connection: *H2Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
    ) Error!void {
        return connection.beginPendingMessageLocked(opcode, payload);
    }

    pub fn beginPendingH2Control(
        connection: *H2Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
    ) Error!void {
        return switch (opcode) {
            .ping => connection.beginPendingPingLocked(payload),
            .close => connection.beginPendingCloseLocked(payload),
            else => error.InvalidFrame,
        };
    }

    pub fn beginPendingInPlace(
        connection: *Connection,
        payload: []u8,
    ) Error!void {
        return connection.beginPendingInPlaceLocked(payload);
    }

    pub fn copyPendingInPlaceSuffix(
        connection: *Connection,
        payload: []const u8,
        committed: usize,
        out: []u8,
    ) Error![]const u8 {
        const pending = connection.pending_write.messagePtr().?;
        if (!pending.matchesInPlace(payload) or committed > pending.totalLen()) {
            return error.InvalidFrame;
        }
        pending.committed = committed;
        const header_offset = @min(committed, pending.header_len);
        const payload_offset = committed - header_offset;
        var len: usize = 0;
        if (header_offset < pending.header_len) {
            const header = pending.header[header_offset..pending.header_len];
            if (header.len > out.len) return error.BufferTooShort;
            @memcpy(out[0..header.len], header);
            len = header.len;
        }
        const count = @min(out.len - len, payload.len - payload_offset);
        @memcpy(out[len..][0..count], payload[payload_offset..][0..count]);
        return out[0 .. len + count];
    }

    pub fn queueAutomaticControl(
        connection: *Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
    ) Error!void {
        return connection.beginAutomaticControl(
            opcode,
            payload,
            .message,
            null,
        );
    }

    pub fn queueH2AutomaticControl(
        connection: *H2Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
    ) Error!void {
        return connection.beginAutomaticControl(
            opcode,
            payload,
            .message,
            null,
        );
    }

    pub fn initDirectConnection(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        role: Role,
        limits: Limits,
    ) Connection {
        return .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .role = role,
            .limits = common.MessageLimits.from(limits),
        };
    }

    pub fn copyPendingMessageChunk(
        connection: *Connection,
        payload: []const u8,
        committed: usize,
        out: []u8,
    ) Error![]const u8 {
        connection.pending_write.messagePtr().?.committed = committed;
        return connection.fillPendingMessageChunk(payload, out);
    }

    pub fn bufferInitial(connection: *Connection, bytes: []const u8) !void {
        try connection.bufferInitial(bytes);
    }

    pub fn receiveFrameAutoInternal(
        connection: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!websocket.Frame {
        return connection.receiveFrameAutoInternal(deadline, .frame);
    }

    pub fn receiveMessageInternal(
        connection: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!OwnedMessage {
        return connection.receiveMessageInternal(deadline);
    }
} else struct {};

pub const H2ConnectOptions = struct {
    authority: ?[]const u8 = null,
    path: []const u8 = "/",
    /// Optional RFC 8441 `:scheme`.  When omitted, the HTTP/2 runtime uses the
    /// underlying connection's default (`http` for h2c, `https` for future TLS
    /// h2 connections), matching how mature stacks derive `:scheme` from the
    /// selected transport rather than hard-coding secure origins.
    scheme: ?[]const u8 = null,
    protocols: []const []const u8 = &.{},
    /// Require the peer to select one offered subprotocol. The default accepts
    /// RFC 6455's null selection.
    require_subprotocol: bool = false,
    /// Optional browser Origin value sent as a regular RFC 8441 header.
    origin: ?[]const u8 = null,
    extra_headers: []const http2.Hpack.HeaderField = &.{},
    /// Optional single-owner CookieJar adapter. Scope is derived from the
    /// effective `:scheme`, `:authority`, and `:path` sent on this connection.
    cookies: ?CookieHandshakeOptions = null,
    enable_permessage_deflate: bool = false,
    /// Offer RFC 7692 context takeover on this Extended CONNECT stream.
    allow_context_takeover: bool = false,
    /// Explicit client/server direction policy overrides allow_context_takeover.
    context_takeover: ?websocket.ContextTakeover = null,
    /// Offer a bound for this client's compression history.
    client_max_window_bits: ?u8 = null,
    /// Require the server compressor to use at most this history window.
    server_max_window_bits: ?u8 = null,
    /// RFC 8441 outbound compression threshold; receive negotiation is
    /// independent of this value.
    compression_threshold: usize = default_compression_threshold,
    limits: Limits = .{},
};

pub const H2AcceptOptions = struct {
    protocols: []const []const u8 = &.{},
    /// Reject the RFC 8441 handshake unless one of `protocols` was selected.
    require_subprotocol: bool = false,
    /// RFC 8441 counterpart to `AcceptOptions.allowed_origins`.
    allowed_origins: []const []const u8 = &.{},
    extra_headers: []const http2.Hpack.HeaderField = &.{},
    enable_permessage_deflate: bool = false,
    /// Permit RFC 7692 context takeover on this Extended CONNECT stream.
    allow_context_takeover: bool = false,
    /// Explicit client/server direction policy overrides allow_context_takeover.
    context_takeover: ?websocket.ContextTakeover = null,
    /// If offered by the client, select at most this receive-history window.
    client_max_window_bits: ?u8 = null,
    /// Select at most this server send-history window.
    server_max_window_bits: ?u8 = null,
    /// RFC 8441 outbound compression threshold.
    compression_threshold: usize = default_compression_threshold,
    limits: Limits = .{},
};

pub const canSendOpcode = message_state.canSendOpcode;

fn receiveMessageFrameBorrowed(
    connection: anytype,
    deadline: ?std.Io.Clock.Timestamp,
) Error!websocket.BorrowedFrame {
    if (connection.receiveFailed()) return error.ConnectionClosed;
    try connection.ensureNoPendingWrites();
    if (connection.closeSent() and connection.closeReceived()) {
        return error.ConnectionClosed;
    }
    try connection.ensureBufferedWithDeadline(2, deadline);
    var available = message_buffer.unread(
        &connection.inbuf,
        connection.inbuf_consumed,
    );
    const second = available[1];
    var header_len: usize = 2;
    const length_code = second & 0x7f;
    if (length_code == 126) {
        header_len += 2;
    } else if (length_code == 127) {
        header_len += 8;
    }
    if ((second & 0x80) != 0) header_len += 4;
    try connection.ensureBufferedWithDeadline(header_len, deadline);
    available = message_buffer.unread(
        &connection.inbuf,
        connection.inbuf_consumed,
    );
    const header = try websocket.FrameHeader.parse(available);
    const payload_len = std.math.cast(
        usize,
        header.payload_len,
    ) orelse return error.PayloadTooLarge;
    if (payload_len > connection.limits.max_frame_bytes) {
        return error.MessageTooLarge;
    }
    const total_len = std.math.add(
        usize,
        header.header_len,
        payload_len,
    ) catch return error.PayloadTooLarge;
    try ensureIncomingFrameBuffered(connection, header, total_len, deadline);
    available = message_buffer.unread(
        &connection.inbuf,
        connection.inbuf_consumed,
    );
    const options: websocket.ParseFrameOptions = switch (connection.role) {
        .client => .{
            .expect_mask = .unmasked,
            .allow_rsv1 = connection.permessage_deflate,
            .validate_utf8 = false,
        },
        .server => .{
            .expect_mask = .masked,
            .allow_rsv1 = connection.permessage_deflate,
            .validate_utf8 = false,
        },
    };
    return websocket.parseFrameInPlaceWithHeader(
        available[0..total_len],
        header,
        options,
    );
}

pub fn receiveMessageIntoDirectConnection(
    connection: anytype,
    out: []u8,
    deadline: ?std.Io.Clock.Timestamp,
) Error!Message {
    if (connection.receiveFailed()) return error.ConnectionClosed;
    if (comptime @hasField(
        @TypeOf(connection.*),
        "application_write_pending",
    )) {
        if (connection.application_write_pending.load(.acquire)) {
            return error.WriteInProgress;
        }
    }
    // A retained assembler belongs to the allocating receiveMessage API.
    // Reject switching receive modes as a local caller error before installing
    // peer-protocol cleanup, so this does not send Close or poison the stream.
    if (connection.message_assembler != null) return error.InvalidFrame;
    errdefer |err| closeAfterReceiveError(connection, err, deadline);
    if (out.len < connection.limits.max_message_bytes) {
        return error.BufferTooShort;
    }
    try connection.message_into.validateOutput(out);
    errdefer |err| if (!io_interruption.retryable(err) and
        err != error.ResponseAvailable and
        !connection.message_into.canRetryCompletion(err))
    {
        connection.message_into.reset();
        connection.message_frame_receive.reset();
    };
    if (try connection.pendingAutomaticControlOpcodeBefore(.message, deadline)) |opcode| {
        std.debug.assert(
            (try connection.resumeAutomaticControl(deadline)) == null,
        );
        if (opcode == .close) return error.ConnectionClosed;
    }
    try connection.ensureNoPendingWrites();
    if (connection.message_into.complete) return @import("runtime/message/complete_into.zig").finish(connection, out);

    var control_storage: [125]u8 = undefined;
    while (true) {
        const frame = try receiveMessageFrameIntoDirectConnection(
            connection,
            out,
            &control_storage,
            deadline,
        );
        switch (frame.header.opcode) {
            .ping => {
                if (canSendOpcode(
                    .pong,
                    connection.closeSent(),
                    connection.closeReceived(),
                )) {
                    try connection.beginAutomaticControlBefore(
                        .pong,
                        frame.payload,
                        .message,
                        null,
                        deadline,
                        0,
                    );
                    std.debug.assert(
                        (try connection.resumeAutomaticControl(deadline)) == null,
                    );
                }
                continue;
            },
            .pong => continue,
            .close => {
                connection.close_received.store(true, .release);
                if (!connection.closeSent()) {
                    try connection.beginAutomaticControlBefore(
                        .close,
                        frame.payload,
                        .message,
                        null,
                        deadline,
                        0,
                    );
                    std.debug.assert(
                        (try connection.resumeAutomaticControl(deadline)) == null,
                    );
                }
                return error.ConnectionClosed;
            },
            .text, .binary, .continuation => {
                std.debug.assert(connection.message_into.active());
            },
            else => return error.InvalidFrame,
        }
        if (!frame.header.fin) continue;

        connection.message_into.markComplete();
        return @import("runtime/message/complete_into.zig").finish(connection, out);
    }
}

fn receiveMessageFrameIntoDirectConnection(
    connection: anytype,
    out: []u8,
    control_out: *[125]u8,
    deadline: ?std.Io.Clock.Timestamp,
) Error!websocket.BorrowedFrame {
    if (connection.message_frame_receive.header == null) {
        if (connection.closeSent() and connection.closeReceived()) {
            return error.ConnectionClosed;
        }
        try connection.ensureBufferedExactWithDeadline(2, deadline);
        var available = message_buffer.unread(
            &connection.inbuf,
            connection.inbuf_consumed,
        );
        const second = available[1];
        var header_len: usize = 2;
        const length_code = second & 0x7f;
        if (length_code == 126) {
            header_len += 2;
        } else if (length_code == 127) {
            header_len += 8;
        }
        if ((second & 0x80) != 0) header_len += 4;
        try connection.ensureBufferedExactWithDeadline(header_len, deadline);
        available = message_buffer.unread(
            &connection.inbuf,
            connection.inbuf_consumed,
        );
        const header = try websocket.FrameHeader.parse(available);
        const options: websocket.ParseFrameOptions = switch (connection.role) {
            .client => .{
                .expect_mask = .unmasked,
                .allow_rsv1 = connection.permessage_deflate,
                .validate_utf8 = false,
            },
            .server => .{
                .expect_mask = .masked,
                .allow_rsv1 = connection.permessage_deflate,
                .validate_utf8 = false,
            },
        };
        try websocket.validateFrameHeader(header, options);
        const payload_len = std.math.cast(
            usize,
            header.payload_len,
        ) orelse return error.PayloadTooLarge;
        if (payload_len > connection.limits.max_frame_bytes) {
            return error.MessageTooLarge;
        }
        if (header.opcode.isControl()) {
            return receiveFrameIntoConnection(
                connection,
                out,
                control_out,
                deadline,
            );
        }

        const message_kind: IncomingDataKind = switch (header.opcode) {
            .text => blk: {
                if (connection.message_into.active()) {
                    return error.InvalidFrame;
                }
                connection.message_into.begin(out, .text, header.rsv1);
                if (header.rsv1) {
                    try connection.ensureCompressionReceiveScratch();
                } else {
                    connection.message_into.text_utf8.reset();
                }
                break :blk if (header.rsv1) .compressed_text else .text;
            },
            .binary => blk: {
                if (connection.message_into.active()) {
                    return error.InvalidFrame;
                }
                connection.message_into.begin(out, .binary, header.rsv1);
                if (header.rsv1) {
                    try connection.ensureCompressionReceiveScratch();
                }
                break :blk .binary;
            },
            .continuation => blk: {
                if (!connection.message_into.active()) {
                    return error.InvalidFrame;
                }
                break :blk connection.incoming_data_kind;
            },
            else => return error.InvalidFrame,
        };
        const next_written = std.math.add(
            usize,
            connection.message_into.written,
            payload_len,
        ) catch return error.PayloadTooLarge;
        if (next_written > connection.limits.max_message_bytes) {
            return error.PayloadTooLarge;
        }
        connection.discardBuffered(header.header_len);
        connection.message_frame_receive = .{
            .header = header,
            .payload_start = connection.message_into.written,
            .payload_end = next_written,
            .message_kind = message_kind,
        };
    }

    const state = &connection.message_frame_receive;
    const header = state.header.?;
    const payload_len: usize = @intCast(header.payload_len);
    const destination = if (connection.message_into.compressed)
        connection.compression_receive.payload.items[state.payload_start..state.payload_end]
    else
        out[state.payload_start..state.payload_end];
    while (state.payload_written < payload_len) {
        const buffered = message_buffer.unread(
            &connection.inbuf,
            connection.inbuf_consumed,
        );
        const count = @min(
            buffered.len,
            payload_len - state.payload_written,
        );
        if (count != 0) {
            try decodeMessagePayloadChunk(
                &connection.message_into.text_utf8,
                destination[state.payload_written..][0..count],
                buffered[0..count],
                header,
                state.payload_written,
                state.message_kind == .text,
            );
            connection.discardBuffered(count);
            state.payload_written += count;
            continue;
        }
        const read = try connection.readMessagePayloadChunk(
            destination[state.payload_written..],
            deadline,
        );
        if (read == 0) return error.ConnectionClosed;
        if (header.mask_key) |mask| {
            const decoded = destination[state.payload_written..][0..read];
            if (state.message_kind == .text) {
                try connection.message_into.text_utf8.feedMaskedCopy(
                    decoded,
                    decoded,
                    mask,
                    state.payload_written,
                );
            } else {
                websocket.applyMask(decoded, mask, state.payload_written);
            }
        } else if (state.message_kind == .text) {
            try connection.message_into.text_utf8.feed(
                destination[state.payload_written..][0..read],
            );
        }
        state.payload_written += read;
    }
    if (state.message_kind == .text and header.fin) {
        try connection.message_into.text_utf8.finish();
    }
    connection.message_into.written = state.payload_end;
    connection.incoming_data_kind =
        if (header.fin) .none else state.message_kind;
    state.reset();
    return .{
        .header = header,
        .payload = destination,
        .consumed = header.header_len + payload_len,
    };
}

fn decodeMessagePayloadChunk(
    validator: *websocket.Utf8Validator,
    destination: []u8,
    encoded: []const u8,
    header: websocket.FrameHeader,
    payload_offset: usize,
    validate_text: bool,
) Error!void {
    if (header.mask_key) |mask| {
        if (validate_text) {
            return validator.feedMaskedCopy(
                destination,
                encoded,
                mask,
                payload_offset,
            );
        }
        try websocket.applyMaskCopy(
            destination,
            encoded,
            mask,
            payload_offset,
        );
    } else {
        @memcpy(destination, encoded);
    }
    if (validate_text) try validator.feed(destination);
}

fn receiveFrameIntoConnection(
    connection: anytype,
    out: []u8,
    control_out: *[125]u8,
    deadline: ?std.Io.Clock.Timestamp,
) Error!websocket.BorrowedFrame {
    if (connection.closeSent() and connection.closeReceived()) {
        return error.ConnectionClosed;
    }
    try connection.ensureBufferedWithDeadline(2, deadline);
    var available = message_buffer.unread(
        &connection.inbuf,
        connection.inbuf_consumed,
    );
    const second = available[1];
    var header_len: usize = 2;
    const len_code = second & 0x7f;
    if (len_code == 126) {
        header_len += 2;
    } else if (len_code == 127) {
        header_len += 8;
    }
    if ((second & 0x80) != 0) header_len += 4;
    try connection.ensureBufferedWithDeadline(header_len, deadline);
    available = message_buffer.unread(
        &connection.inbuf,
        connection.inbuf_consumed,
    );
    const header = try websocket.FrameHeader.parse(available);
    const payload_len = std.math.cast(
        usize,
        header.payload_len,
    ) orelse return error.PayloadTooLarge;
    if (payload_len > connection.limits.max_frame_bytes) {
        return error.MessageTooLarge;
    }
    const payload_out = if (header.opcode.isControl())
        control_out[0..]
    else
        out;
    if (payload_len > payload_out.len) return error.PayloadTooLarge;
    const total_len = std.math.add(
        usize,
        header.header_len,
        payload_len,
    ) catch return error.PayloadTooLarge;
    try ensureIncomingFrameBuffered(connection, header, total_len, deadline);
    available = message_buffer.unread(
        &connection.inbuf,
        connection.inbuf_consumed,
    );
    const parse_options: websocket.ParseFrameOptions = switch (connection.role) {
        .client => .{
            .expect_mask = .unmasked,
            .allow_rsv1 = connection.permessage_deflate,
            .validate_utf8 = false,
        },
        .server => .{
            .expect_mask = .masked,
            .allow_rsv1 = connection.permessage_deflate,
            .validate_utf8 = false,
        },
    };
    const frame = try websocket.parseFrameIntoWithHeader(
        payload_out,
        available[0..total_len],
        header,
        parse_options,
    );
    connection.discardBuffered(frame.consumed);
    if (connection.closeReceived() and frame.header.opcode != .close) {
        return error.ConnectionClosed;
    }
    return frame;
}

pub fn closeAfterReceiveError(
    connection: anytype,
    err: anyerror,
    deadline: ?std.Io.Clock.Timestamp,
) void {
    if (common.closeCodeForReceiveError(err)) |code| {
        // Nested receive helpers may observe the same failure. Only the first
        // layer sends a Close frame; later errdefers preserve the original
        // error.
        if (!failReceive(connection)) return;
        connection.finishReceiveFailure(code, deadline);
        return;
    }
    if (!receive_failure.isTerminalTransportError(err) or
        connection.close_received.load(.acquire))
    {
        return;
    }
    // A transport end or fatal TLS record error without a WebSocket Close is
    // an abnormal closure.
    // It has no RFC 6455 status code to send, but it must still release partial
    // receive state and prevent application data from being written afterward.
    if (!failReceive(connection)) return;
    connection.finishAbruptReceiveEnd(deadline);
}

pub fn failReceive(connection: anytype) bool {
    if (connection.receive_failed.swap(true, .acq_rel)) return false;
    control_admission.clear(connection);
    if (connection.message_assembler) |*assembler| assembler.deinit();
    connection.message_assembler = null;
    connection.message_into.reset();
    connection.message_frame_receive.reset();
    connection.incoming_data_kind = .none;
    connection.incoming_text_utf8.reset();
    connection.incoming_frame_validated = 0;
    connection.inbuf.clearAndFree(connection.allocator);
    connection.inbuf_consumed = 0;
    if (comptime @hasField(@TypeOf(connection.*), "pending_tunnel_data")) {
        if (connection.pending_tunnel_data) |*data| {
            data.deinit(connection.tunnel.connection.allocator);
        }
        connection.pending_tunnel_data = null;
        connection.pending_tunnel_data_offset = 0;
    }
    connection.compression_receive.deinit(connection.allocator);
    connection.compression_receive = .{};
    return true;
}

/// Read the current frame body while validating uncompressed text bytes as
/// they arrive from the transport. A complete invalid frame need not be
/// buffered before the peer receives Close 1007; this is the fail-fast behavior
/// recommended by RFC 6455 section 8.1 and exercised by Autobahn 6.4.
pub fn ensureIncomingFrameBuffered(
    connection: anytype,
    header: websocket.FrameHeader,
    total_len: usize,
    deadline: ?std.Io.Clock.Timestamp,
) Error!void {
    const parse_options: websocket.ParseFrameOptions = switch (connection.role) {
        .client => .{
            .expect_mask = .unmasked,
            .allow_rsv1 = connection.permessage_deflate,
            .validate_utf8 = false,
        },
        .server => .{
            .expect_mask = .masked,
            .allow_rsv1 = connection.permessage_deflate,
            .validate_utf8 = false,
        },
    };
    // Header errors take precedence over payload validation and are known as
    // soon as the complete header is buffered. The full frame parser repeats
    // this check after the payload arrives as a defensive codec boundary.
    try websocket.validateFrameHeader(header, parse_options);
    const message_kind: IncomingDataKind = switch (header.opcode) {
        .text => blk: {
            if (connection.incoming_data_kind != .none) {
                return error.InvalidFrame;
            }
            // A deadline may expire after validating a prefix of this same
            // frame. Preserve the incremental UTF-8 state in that case; reset
            // only when the frame has not been entered before.
            if (connection.incoming_frame_validated == 0) {
                connection.incoming_text_utf8.reset();
            }
            break :blk if (header.rsv1) .compressed_text else .text;
        },
        .binary => blk: {
            if (connection.incoming_data_kind != .none) {
                return error.InvalidFrame;
            }
            break :blk .binary;
        },
        .continuation => blk: {
            if (connection.incoming_data_kind == .none) {
                return error.InvalidFrame;
            }
            break :blk connection.incoming_data_kind;
        },
        else => .none,
    };
    const validate_text = message_kind == .text;
    var validated = @max(
        header.header_len,
        connection.incoming_frame_validated,
    );
    errdefer preserveIncomingFrameValidation(connection, validated);
    while (message_buffer.unreadLen(
        &connection.inbuf,
        connection.inbuf_consumed,
    ) < total_len) {
        if (validate_text) {
            try validateBufferedTextRange(
                connection,
                header,
                &validated,
                total_len,
            );
        }
        try connection.ensureBufferedWithDeadline(
            @min(
                total_len,
                message_buffer.unreadLen(
                    &connection.inbuf,
                    connection.inbuf_consumed,
                ) + 1,
            ),
            deadline,
        );
    }
    if (validate_text) {
        try validateBufferedTextRange(
            connection,
            header,
            &validated,
            total_len,
        );
        if (header.fin) try connection.incoming_text_utf8.finish();
    }

    if (!header.opcode.isControl()) {
        connection.incoming_data_kind =
            if (header.fin) .none else message_kind;
    }
    connection.incoming_frame_validated = 0;
}

fn preserveIncomingFrameValidation(
    connection: anytype,
    validated: usize,
) void {
    connection.incoming_frame_validated = validated;
}

fn validateBufferedTextRange(
    connection: anytype,
    header: websocket.FrameHeader,
    validated: *usize,
    total_len: usize,
) Error!void {
    const available = message_buffer.unread(
        &connection.inbuf,
        connection.inbuf_consumed,
    );
    const available_end = @min(available.len, total_len);
    if (available_end <= validated.*) return;
    const bytes = available[validated.*..available_end];
    if (header.mask_key) |mask| {
        try connection.incoming_text_utf8.feedMasked(
            bytes,
            mask,
            validated.* - header.header_len,
        );
    } else {
        try connection.incoming_text_utf8.feed(bytes);
    }
    validated.* = available_end;
}

pub fn AllocatingMessageReceiver(comptime TransportConnection: type) type {
    return @import("runtime/message/receive.zig").Controller(struct {
        pub const ConnectionType = TransportConnection;
        pub const ErrorType = Error;
        pub const receiveFailed = ConnectionType.receiveFailed;
        pub const checkWrites = ConnectionType.ensureNoPendingWrites;
        pub const pendingControl = ConnectionType.pendingAutomaticControlOpcodeBefore;
        pub const resumeControl = ConnectionType.resumeAutomaticControl;
        pub const beginControl = ConnectionType.beginAutomaticControlBefore;
        pub const discard = ConnectionType.discardBuffered;
        pub const readFrame = receiveMessageFrameBorrowed;
        pub const afterError = closeAfterReceiveError;
        pub fn onClose(_: *ConnectionType) void {}
    });
}

pub const compressedFragmentRange = message_state.compressedFragmentRange;

const HttpHead = handshake_receive.Head;
pub const readHttpUpgradeResponseBytes = HandshakeReader.readResponseBytes;
pub const readHttpHeadFromTransport = HandshakeReader.readHead;
pub const readHttpHeadFromTransportWithInitial = HandshakeReader.readHeadWithInitial;

pub fn readHttpHead(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, max_head_bytes: usize) Error!HttpHead {
    return readHttpHeadFromTransport(
        allocator,
        .{ .tcp = .{ .io = io, .stream = stream } },
        max_head_bytes,
        null,
    );
}

pub fn http1HandshakeRequestParseOptions(limits: Limits) http1.ParseOptions {
    return .{
        .max_headers = limits.max_request_headers,
    };
}

pub fn http1HandshakeResponseParseOptions(limits: Limits) http1.ParseOptions {
    return .{
        .max_headers = limits.max_response_headers,
    };
}

pub fn handshakeDeadline(
    transport: RuntimeTransport,
    timeout: std.Io.Duration,
) Error!std.Io.Clock.Timestamp {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    const io = switch (transport) {
        .tcp => |tcp| tcp.io,
        .tls => |connection| connection.io,
        .tls_vail => |connection| connection.io,
        .tls_server => |connection| connection.io,
    };
    return .fromNow(io, .{ .raw = timeout, .clock = .awake });
}

pub const validateServerHandshake = handshake_headers.validateHttp1Server;
const requiredSingletonHeader = handshake_headers.requiredHttp1;
const optionalSingletonHeader = handshake_headers.optionalHttp1;
pub const validateH2ServerHandshake = handshake_headers.validateH2Server;
pub const requiredH2SingletonHeader = handshake_headers.requiredH2;
const optionalH2SingletonHeader = handshake_headers.optionalH2;
pub const validateHttp1ClientExtraHeadersImpl =
    handshake_headers.validateHttp1ClientExtra;
const validateUpgradeRejectionHeaders =
    handshake_headers.validateHttp1RejectionExtra;
const validateUpgradeAcceptHeaders =
    handshake_headers.validateHttp1AcceptExtra;
pub const validateH2ClientExtraHeaders = handshake_headers.validateH2ClientExtra;
pub const validateH2ServerExtraHeaders = handshake_headers.validateH2ServerExtra;
const validateH2RejectionHeaders = handshake_headers.validateH2RejectionExtra;
pub const rejectH2ExtendedConnectLegacyHeaders = handshake_headers.rejectH2Legacy;
pub const acceptH2Extensions = handshake_headers.acceptH2Extensions;
pub const selectHttp1Subprotocol = handshake_headers.selectHttp1Subprotocol;
pub const selectH2Subprotocol = handshake_headers.selectH2Subprotocol;

fn readSome(io: std.Io, stream: net.Stream, buffer: []u8) net.Stream.Reader.Error!usize {
    return stream_io.readSome(io, stream, buffer);
}

fn readSomeWithDeadline(
    io: std.Io,
    stream: net.Stream,
    buffer: []u8,
    deadline: std.Io.Clock.Timestamp,
) Error!usize {
    return stream_io.readSomeWithDeadline(io, stream, buffer, deadline);
}

pub fn writeAllToStream(io: std.Io, stream: net.Stream, bytes: []const u8) net.Stream.Writer.Error!void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = try io.vtable.netWrite(io.userdata, stream.socket.handle, bytes[written..], &.{""}, 0);
        if (n == 0) return error.SocketUnconnected;
        written += n;
    }
}

pub fn writeMaskedPayload(
    transport: RuntimeTransport,
    header: []const u8,
    payload: []const u8,
    mask_key: [4]u8,
) Error!void {
    if (payload.len == 0) {
        try transport.writeAll(header);
        return;
    }

    var scratch: [masked_write_scratch_len]u8 = undefined;
    var offset: usize = 0;
    while (offset < payload.len) {
        const count = @min(scratch.len, payload.len - offset);
        try websocket.applyMaskCopy(
            scratch[0..count],
            payload[offset..][0..count],
            mask_key,
            offset,
        );
        if (offset == 0) {
            try transport.writeAllParts(header, scratch[0..count]);
        } else {
            try transport.writeAll(scratch[0..count]);
        }
        offset += count;
    }
}

pub fn writeMaskedPayloadParts(
    transport: RuntimeTransport,
    header: []const u8,
    parts: []const []const u8,
    mask_key: [4]u8,
) Error!void {
    var scratch: [masked_write_scratch_len]u8 = undefined;
    var part_index: usize = 0;
    var part_offset: usize = 0;
    var mask_offset: usize = 0;
    var header_pending = true;

    while (part_index < parts.len) {
        var count: usize = 0;
        while (part_index < parts.len and count < scratch.len) {
            const part = parts[part_index];
            if (part_offset == part.len) {
                part_index += 1;
                part_offset = 0;
                continue;
            }
            const chunk_len = @min(
                scratch.len - count,
                part.len - part_offset,
            );
            try websocket.applyMaskCopy(
                scratch[count..][0..chunk_len],
                part[part_offset..][0..chunk_len],
                mask_key,
                mask_offset,
            );
            count += chunk_len;
            part_offset += chunk_len;
            mask_offset += chunk_len;
        }
        if (count == 0) break;
        if (header_pending) {
            try transport.writeAllParts(header, scratch[0..count]);
            header_pending = false;
        } else {
            try transport.writeAll(scratch[0..count]);
        }
    }
    if (header_pending) try transport.writeAll(header);
}

pub fn writeUnmaskedPayloadSlices(
    transport: RuntimeTransport,
    header: []const u8,
    payload_parts: []const []const u8,
) Error!void {
    // Keep common small vectors in one syscall while supporting an arbitrary
    // caller slice count without allocating a descriptor array.
    var parts: [max_batched_payload_slices + 1][]const u8 = undefined;
    var part_index: usize = 0;
    var header_pending = true;
    while (true) {
        var count: usize = 0;
        if (header_pending) {
            parts[count] = header;
            count += 1;
            header_pending = false;
        }
        while (part_index < payload_parts.len and count < parts.len) {
            const part = payload_parts[part_index];
            part_index += 1;
            if (part.len == 0) continue;
            parts[count] = part;
            count += 1;
        }
        if (count == 0) return;
        try transport.writeAllSlices(parts[0..count]);
        if (part_index == payload_parts.len) return;
    }
}

pub fn writeMaskedTunnelPayloadSlices(
    tunnel: *http2_runtime.Tunnel,
    header: []const u8,
    payload_parts: []const []const u8,
    mask_key: [4]u8,
) Error!void {
    var writer = try tunnel.beginWriteSequence();
    return writeMaskedTunnelPayloadSlicesWithWriter(
        &writer,
        header,
        payload_parts,
        mask_key,
    );
}

pub fn writeUnmaskedTunnelPayloadSlices(
    writer: *http2_runtime.TunnelWriter,
    header: []const u8,
    payload_parts: []const []const u8,
) Error!void {
    var parts: [max_batched_payload_slices + 1][]const u8 = undefined;
    var part_index: usize = 0;
    var header_pending = true;
    while (true) {
        var count: usize = 0;
        if (header_pending) {
            parts[count] = header;
            count += 1;
            header_pending = false;
        }
        while (part_index < payload_parts.len and count < parts.len) {
            const part = payload_parts[part_index];
            part_index += 1;
            if (part.len == 0) continue;
            parts[count] = part;
            count += 1;
        }
        if (count == 0) return;
        try writer.writeSlices(parts[0..count], false);
        if (part_index == payload_parts.len) return;
    }
}

pub fn writeMaskedTunnelPayloadSlicesWithWriter(
    writer: *http2_runtime.TunnelWriter,
    header: []const u8,
    payload_parts: []const []const u8,
    mask_key: [4]u8,
) Error!void {
    var scratch: [masked_write_scratch_len]u8 = undefined;
    var part_index: usize = 0;
    var part_offset: usize = 0;
    var mask_offset: usize = 0;
    var header_pending = true;
    while (part_index < payload_parts.len) {
        var count: usize = 0;
        while (part_index < payload_parts.len and count < scratch.len) {
            const part = payload_parts[part_index];
            if (part_offset == part.len) {
                part_index += 1;
                part_offset = 0;
                continue;
            }
            const chunk_len = @min(
                scratch.len - count,
                part.len - part_offset,
            );
            try websocket.applyMaskCopy(
                scratch[count..][0..chunk_len],
                part[part_offset..][0..chunk_len],
                mask_key,
                mask_offset,
            );
            count += chunk_len;
            part_offset += chunk_len;
            mask_offset += chunk_len;
        }
        if (count == 0) break;
        if (header_pending) {
            try writer.writeParts(header, scratch[0..count], false);
            header_pending = false;
        } else {
            try writer.write(scratch[0..count], false);
        }
    }
    if (header_pending) try writer.write(header, false);
}

test {
    _ = @import("runtime/tests.zig");
}
