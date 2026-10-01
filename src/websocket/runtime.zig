const std = @import("std");
const builtin = @import("builtin");
const websocket = @import("mod.zig");
const common = @import("runtime/common.zig");
const http1 = @import("../http1/mod.zig");
const http2 = @import("../http2/mod.zig");
const http1_runtime = http1.runtime;
const http1_write = @import("../http1/runtime/write.zig");
const http1_message_framing =
    @import("../http1/runtime/message/framing.zig");
const http2_runtime = http2.runtime;
const tls_stream = @import("../tls/mod.zig").stream;
const tls_client_identity = @import(
    "runtime/tls_client_identity.zig",
);
const compression_scratch =
    @import("runtime/compression_scratch.zig");
const message_buffer = @import("runtime/message/buffer.zig");
pub const ReceiveBuffer = message_buffer;
const message_state = @import("runtime/message/state.zig");
const handshake_headers = @import("runtime/handshake/headers.zig");
const handshake_storage = @import("runtime/handshake/storage.zig");
const origin_policy = @import("runtime/origin_policy.zig");
const stream_io = @import("../internal/stream_io.zig");
const accept_deadline = @import("../internal/accept.zig");
const deadline_policy = @import("../internal/deadline.zig");
const tcp_connect = @import("../internal/tcp_connect.zig");
const socket_options = @import("../internal/socket_options.zig");
const wire = @import("../internal/wire.zig");
const vail = @import("vail");

const net = std.Io.net;

pub const h3 = @import("runtime/h3.zig");
/// Default lower bound for attempting permessage-deflate. Raw DEFLATE framing
/// cannot profitably encode very small messages, and initializing compressor
/// state would dominate their latency. Callers may tune this per endpoint.
pub const default_compression_threshold: usize = 32;
const masked_write_scratch_len: usize = 16 * 1024;
const max_batched_payload_slices: usize = 64;
const max_control_frame_len = websocket.max_frame_header_len + 125;
// A 4 KiB application payload occupies 4104 bytes on the masked wire. The old
// 4096-byte read scratch therefore forced two socket reads for this common
// frame size. Keep the burst on the call stack (rather than 16 KiB resident per
// connection) while covering typical WebSocket/TLS records in one read.
const transport_read_scratch_len: usize = 16 * 1024;

pub const Error = websocket.Error || http1_runtime.Error ||
    http2_runtime.Error || tls_stream.Error || error{
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
    SocketOptionFailed,
} || std.Io.RandomSecureError || net.HostName.ValidateError || net.HostName.ConnectError || net.Stream.Reader.Error || net.Stream.Writer.Error;

pub const Limits = common.Limits;
pub const Role = common.Role;

const IncomingDataKind = enum {
    none,
    binary,
    text,
    compressed_text,
};

const MessageFrameReceiveState = struct {
    header: ?websocket.FrameHeader = null,
    payload_start: usize = 0,
    payload_end: usize = 0,
    payload_written: usize = 0,
    message_kind: IncomingDataKind = .none,

    fn reset(self: *MessageFrameReceiveState) void {
        self.* = .{};
    }
};

const PendingH2Close = struct {
    bytes: [max_control_frame_len]u8 = undefined,
    len: usize = 0,
    committed: usize = 0,
    payload: [125]u8 = undefined,
    payload_len: usize = 0,

    fn matches(self: *const PendingH2Close, value: []const u8) bool {
        return std.mem.eql(u8, self.payload[0..self.payload_len], value);
    }
};

const PendingH2Ping = struct {
    bytes: [max_control_frame_len]u8 = undefined,
    len: usize = 0,
    committed: usize = 0,
    payload: [125]u8 = undefined,
    payload_len: usize = 0,

    fn matches(self: *const PendingH2Ping, value: []const u8) bool {
        return std.mem.eql(u8, self.payload[0..self.payload_len], value);
    }
};

const PendingH2Message = struct {
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

    fn matches(
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

    fn matchesParts(
        self: *const PendingH2Message,
        parts: []const []const u8,
    ) bool {
        return self.source == .slices and
            self.opcode == .binary and
            self.original_len == parts.len and
            (parts.len == 0 or
                self.original_ptr == @intFromPtr(parts.ptr));
    }

    fn matchesInPlace(
        self: *const PendingH2Message,
        payload: []const u8,
    ) bool {
        return self.source == .in_place and
            self.opcode == .binary and
            self.original_len == payload.len and
            (payload.len == 0 or
                self.original_ptr == @intFromPtr(payload.ptr));
    }

    fn matchesFragments(
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

    fn totalLen(self: *const PendingH2Message) usize {
        return if (self.source == .fragmented)
            self.wire_total
        else
            self.header_len + self.payload_len;
    }
};

const PendingMessage = struct {
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

    fn matches(
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

    fn matchesParts(
        self: *const PendingMessage,
        parts: []const []const u8,
    ) bool {
        return self.source == .slices and
            self.opcode == .binary and
            self.original_len == parts.len and
            (parts.len == 0 or
                self.original_ptr == @intFromPtr(parts.ptr));
    }

    fn matchesInPlace(
        self: *const PendingMessage,
        payload: []const u8,
    ) bool {
        return self.source == .in_place and
            self.opcode == .binary and
            self.original_len == payload.len and
            (payload.len == 0 or
                self.original_ptr == @intFromPtr(payload.ptr));
    }

    fn matchesFragments(
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

    fn totalLen(self: *const PendingMessage) usize {
        return if (self.source == .fragmented)
            self.wire_total
        else
            self.header_len + self.payload_len;
    }
};

fn copyMessagePartsAt(
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

fn fragmentedWireLen(
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

const PendingControlFrame = struct {
    bytes: [max_control_frame_len]u8 = undefined,
    len: usize = 0,
    committed: usize = 0,
    payload: [125]u8 = undefined,
    payload_len: usize = 0,

    fn matches(self: *const PendingControlFrame, value: []const u8) bool {
        return std.mem.eql(u8, self.payload[0..self.payload_len], value);
    }
};

pub const ClientIdentity = tls_client_identity.ClientIdentity;
pub const ClientCertificateVerifier =
    tls_client_identity.CertificateVerifier;

const RuntimeTransport = union(enum) {
    tcp: struct { io: std.Io, stream: net.Stream },
    tls: *http1_runtime.TlsClientConnection,
    tls_vail: *tls_stream.ClientConnection,
    tls_server: *tls_stream.ServerConnection,

    fn read(self: RuntimeTransport, buffer: []u8) Error!usize {
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
    fn readWithDeadline(
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

    fn writeAll(self: RuntimeTransport, bytes: []const u8) Error!void {
        return switch (self) {
            .tcp => |tcp| writeAllToStream(tcp.io, tcp.stream, bytes),
            .tls => |conn| conn.writeAll(bytes),
            .tls_vail => |conn| conn.writeAll(bytes),
            .tls_server => |conn| conn.writeAll(bytes),
        };
    }

    fn writeAllParts(
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

    fn writeAllSlices(
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
    fn writeWithDeadline(
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

    fn finishPendingTimedWrite(
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

    fn close(self: RuntimeTransport) void {
        switch (self) {
            .tcp => |tcp| tcp.stream.close(tcp.io),
            .tls => |conn| conn.deinit(),
            .tls_vail => |conn| conn.deinit(),
            .tls_server => |conn| conn.deinit(),
        }
    }
};

fn transportStream(transport: RuntimeTransport) net.Stream {
    return switch (transport) {
        .tcp => |tcp| tcp.stream,
        .tls_server => |connection| connection.stream,
        .tls => |connection| connection.stream,
        .tls_vail => |connection| connection.stream,
    };
}

pub const Server = struct {
    http: http1_runtime.Server,
    limits: Limits = .{},

    pub fn listen(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
        return .{
            .http = try .listen(allocator, io, bind_address, .{
                .max_head_bytes = limits.max_head_bytes,
                .max_body_bytes = 0,
            }),
            .limits = limits,
        };
    }

    pub fn deinit(self: *Server) void {
        self.http.deinit();
        self.* = undefined;
    }

    pub fn address(self: Server) net.IpAddress {
        return self.http.address();
    }

    pub fn accept(self: *Server, options: AcceptOptions) Error!Connection {
        var pending = try self.receiveUpgradeRequest(options);
        errdefer pending.deinit();
        return pending.accept();
    }

    /// Apply one caller-owned awake-clock deadline to TCP accept and the
    /// complete HTTP Upgrade.
    pub fn acceptWithDeadline(
        self: *Server,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        var pending = try self.receiveUpgradeRequestWithDeadline(
            options,
            deadline,
        );
        errdefer pending.deinit();
        return pending.accept();
    }

    pub fn acceptWithTimeout(
        self: *Server,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        var pending = try self.receiveUpgradeRequestWithTimeout(
            options,
            timeout,
        );
        errdefer pending.deinit();
        return pending.accept();
    }

    /// Upgrade an already accepted HTTP/1 connection. This lets protocol
    /// adapters consume a trusted preface without duplicating WebSocket
    /// handshake validation.
    pub fn acceptHttpConnection(
        self: *Server,
        http_connection: http1_runtime.Connection,
        options: AcceptOptions,
    ) Error!Connection {
        var pending = try self.receiveHttpUpgradeRequestMaybeBefore(
            http_connection,
            options,
            null,
        );
        errdefer pending.deinit();
        return pending.accept();
    }

    /// Upgrade an accepted HTTP/1 connection before an absolute deadline. The
    /// connection transfers at entry and is closed on every failure path.
    pub fn acceptHttpConnectionWithDeadline(
        self: *Server,
        http_connection: http1_runtime.Connection,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        var pending = try self.receiveHttpUpgradeRequestWithDeadline(
            http_connection,
            options,
            deadline,
        );
        errdefer pending.deinit();
        return pending.accept();
    }

    pub fn acceptHttpConnectionWithTimeout(
        self: *Server,
        http_connection: http1_runtime.Connection,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        // The caller retains the HTTP connection if validation fails before
        // the deadline form receives ownership.
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptHttpConnectionWithDeadline(
            http_connection,
            options,
            .fromNow(self.http.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Receive and validate a WebSocket Upgrade request without sending 101.
    /// The returned value owns the accepted transport until the application
    /// accepts, rejects, or deinitializes it.
    pub fn receiveUpgradeRequest(
        self: *Server,
        options: AcceptOptions,
    ) Error!PendingUpgrade {
        const http_connection = try self.http.accept();
        return self.receiveHttpUpgradeRequest(http_connection, options);
    }

    pub fn receiveUpgradeRequestWithDeadline(
        self: *Server,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PendingUpgrade {
        _ = try deadline_policy.usableAwake(self.http.io, deadline);
        const http_connection = try self.http.acceptWithDeadline(deadline);
        return self.receiveHttpUpgradeRequestMaybeBefore(
            http_connection,
            options,
            deadline,
        );
    }

    pub fn receiveUpgradeRequestWithTimeout(
        self: *Server,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!PendingUpgrade {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveUpgradeRequestWithDeadline(
            options,
            .fromNow(self.http.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Adopt a caller-accepted TCP stream and stop before the 101 decision.
    pub fn receiveStreamUpgradeRequest(
        self: *Server,
        stream: net.Stream,
        options: AcceptOptions,
    ) Error!PendingUpgrade {
        const http_connection = try self.http.acceptStream(stream);
        return self.receiveHttpUpgradeRequest(http_connection, options);
    }

    pub fn receiveStreamUpgradeRequestWithDeadline(
        self: *Server,
        stream: net.Stream,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PendingUpgrade {
        _ = try deadline_policy.usableAwake(self.http.io, deadline);
        const http_connection = try self.http.acceptStream(stream);
        return self.receiveHttpUpgradeRequestMaybeBefore(
            http_connection,
            options,
            deadline,
        );
    }

    pub fn receiveStreamUpgradeRequestWithTimeout(
        self: *Server,
        stream: net.Stream,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!PendingUpgrade {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveStreamUpgradeRequestWithDeadline(
            stream,
            options,
            .fromNow(self.http.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn receiveHttpUpgradeRequest(
        self: *Server,
        http_connection: http1_runtime.Connection,
        options: AcceptOptions,
    ) Error!PendingUpgrade {
        return self.receiveHttpUpgradeRequestMaybeBefore(
            http_connection,
            options,
            null,
        );
    }

    pub fn receiveHttpUpgradeRequestWithDeadline(
        self: *Server,
        http_connection: http1_runtime.Connection,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PendingUpgrade {
        _ = try deadline_policy.usableAwake(self.http.io, deadline);
        return self.receiveHttpUpgradeRequestMaybeBefore(
            http_connection,
            options,
            deadline,
        );
    }

    pub fn receiveHttpUpgradeRequestWithTimeout(
        self: *Server,
        http_connection: http1_runtime.Connection,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!PendingUpgrade {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveHttpUpgradeRequestWithDeadline(
            http_connection,
            options,
            .fromNow(self.http.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn receiveHttpUpgradeRequestMaybeBefore(
        self: *Server,
        http_connection: http1_runtime.Connection,
        options: AcceptOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!PendingUpgrade {
        var http_conn = http_connection;
        errdefer http_conn.close();
        if (self.limits.tcp_nodelay) {
            try socket_options.setTcpNoDelay(http_conn.stream);
        }

        return receiveUpgradeRequestFromTransport(
            self.http.allocator,
            http_conn.io,
            .{ .tcp = .{
                .io = http_conn.io,
                .stream = http_conn.stream,
            } },
            self.limits,
            options,
            deadline,
        );
    }

    pub fn serveConcurrent(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (*HandlerContext, *Connection) Error!void,
        max_connections: usize,
        options: AcceptOptions,
    ) AsyncServeError!ConcurrentServeResult {
        return serveAcceptedConcurrent(
            Server,
            self,
            self.http.io,
            self.http.allocator,
            HandlerContext,
            context,
            handler,
            max_connections,
            options,
        );
    }

    pub fn serveUntil(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (*HandlerContext, *Connection) Error!void,
        max_connections: usize,
        accept_options: AcceptOptions,
        serve_options: ServeUntilOptions,
    ) anyerror!void {
        return serveAcceptedUntil(
            Server,
            self,
            self.http.io,
            HandlerContext,
            context,
            handler,
            max_connections,
            accept_options,
            serve_options,
        );
    }
};

/// Cleartext WebSocket listener over a Unix-domain stream socket.
///
/// This has the same opening-handshake and frame semantics as `Server`; only
/// socket creation differs. The path remains caller-owned and is not removed
/// automatically on shutdown.
pub const UnixServer = struct {
    http: http1_runtime.UnixServer,
    limits: Limits = .{},

    pub fn listen(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        limits: Limits,
    ) Error!UnixServer {
        return .{
            .http = try .listen(allocator, io, address, .{
                .max_head_bytes = limits.max_head_bytes,
                .max_body_bytes = 0,
                // Unix sockets do not implement TCP_NODELAY.
                .tcp_nodelay = false,
            }),
            .limits = limits,
        };
    }

    pub fn deinit(self: *UnixServer) void {
        self.http.deinit();
        self.* = undefined;
    }

    pub fn accept(
        self: *UnixServer,
        options: AcceptOptions,
    ) Error!Connection {
        var pending = try self.receiveUpgradeRequest(options);
        errdefer pending.deinit();
        return pending.accept();
    }

    /// Apply one caller-owned awake-clock deadline to Unix accept and the
    /// complete HTTP Upgrade.
    pub fn acceptWithDeadline(
        self: *UnixServer,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        var pending = try self.receiveUpgradeRequestWithDeadline(
            options,
            deadline,
        );
        errdefer pending.deinit();
        return pending.accept();
    }

    pub fn acceptWithTimeout(
        self: *UnixServer,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        var pending = try self.receiveUpgradeRequestWithTimeout(
            options,
            timeout,
        );
        errdefer pending.deinit();
        return pending.accept();
    }

    /// Receive and validate a Unix-socket Upgrade request without sending 101.
    pub fn receiveUpgradeRequest(
        self: *UnixServer,
        options: AcceptOptions,
    ) Error!PendingUpgrade {
        return self.receiveUpgradeRequestMaybeBefore(options, null);
    }

    pub fn receiveUpgradeRequestWithDeadline(
        self: *UnixServer,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PendingUpgrade {
        _ = try deadline_policy.usableAwake(self.http.io, deadline);
        return self.receiveUpgradeRequestMaybeBefore(options, deadline);
    }

    pub fn receiveUpgradeRequestWithTimeout(
        self: *UnixServer,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!PendingUpgrade {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveUpgradeRequestWithDeadline(
            options,
            .fromNow(self.http.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn receiveHttpUpgradeRequest(
        self: *UnixServer,
        http_connection: http1_runtime.Connection,
        options: AcceptOptions,
    ) Error!PendingUpgrade {
        return self.receiveHttpUpgradeRequestMaybeBefore(
            http_connection,
            options,
            null,
        );
    }

    pub fn receiveHttpUpgradeRequestWithDeadline(
        self: *UnixServer,
        http_connection: http1_runtime.Connection,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PendingUpgrade {
        _ = try deadline_policy.usableAwake(self.http.io, deadline);
        return self.receiveHttpUpgradeRequestMaybeBefore(
            http_connection,
            options,
            deadline,
        );
    }

    pub fn receiveHttpUpgradeRequestWithTimeout(
        self: *UnixServer,
        http_connection: http1_runtime.Connection,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!PendingUpgrade {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveHttpUpgradeRequestWithDeadline(
            http_connection,
            options,
            .fromNow(self.http.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn receiveUpgradeRequestMaybeBefore(
        self: *UnixServer,
        options: AcceptOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!PendingUpgrade {
        const http_connection = if (deadline) |absolute|
            try self.http.acceptWithDeadline(absolute)
        else
            try self.http.accept();
        return self.receiveHttpUpgradeRequestMaybeBefore(
            http_connection,
            options,
            deadline,
        );
    }

    fn receiveHttpUpgradeRequestMaybeBefore(
        self: *UnixServer,
        http_connection: http1_runtime.Connection,
        options: AcceptOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!PendingUpgrade {
        var http_connection_owned = http_connection;
        var http_owned = true;
        errdefer if (http_owned) http_connection_owned.close();
        var limits = self.limits;
        limits.tcp_nodelay = false;
        const pending = try receiveUpgradeRequestFromTransport(
            self.http.allocator,
            self.http.io,
            .{ .tcp = .{
                .io = self.http.io,
                .stream = http_connection_owned.stream,
            } },
            limits,
            options,
            deadline,
        );
        http_owned = false;
        return pending;
    }

    pub fn serveConcurrent(
        self: *UnixServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            *Connection,
        ) Error!void,
        max_connections: usize,
        options: AcceptOptions,
    ) AsyncServeError!ConcurrentServeResult {
        return serveAcceptedConcurrent(
            UnixServer,
            self,
            self.http.io,
            self.http.allocator,
            HandlerContext,
            context,
            handler,
            max_connections,
            options,
        );
    }

    pub fn serveUntil(
        self: *UnixServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (*HandlerContext, *Connection) Error!void,
        max_connections: usize,
        accept_options: AcceptOptions,
        serve_options: ServeUntilOptions,
    ) anyerror!void {
        return serveAcceptedUntil(
            UnixServer,
            self,
            self.http.io,
            HandlerContext,
            context,
            handler,
            max_connections,
            accept_options,
            serve_options,
        );
    }
};

/// TLS 1.3 WebSocket listener.
///
/// TLS termination is performed before the same strict HTTP/1 Upgrade parser
/// used by `Server`, so WSS inherits subprotocol, extension, smuggling and
/// frame-validation behavior rather than maintaining a second handshake path.
pub const TlsServer = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    listener: net.Server,
    limits: Limits,
    tls: tls_stream.ServerOptions,
    tcp_nodelay: bool,

    pub fn listen(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        options: TlsListenOptions,
    ) Error!TlsServer {
        try options.identity.validate();
        return .{
            .allocator = allocator,
            .io = io,
            .listener = try bind_address.listen(
                io,
                .{ .reuse_address = true },
            ),
            .limits = options.limits,
            .tls = .{
                .identity = options.identity,
                .cipher_suites = options.cipher_suites,
                .max_client_hello_size = options.max_client_hello_size,
                .max_client_handshake_size = options.max_client_handshake_size,
                .handshake_timeout = options.tls_handshake_timeout,
                .client_auth = options.client_auth,
                .alpn_protocols = options.alpn_protocols,
            },
            .tcp_nodelay = options.tcp_nodelay,
        };
    }

    pub fn deinit(self: *TlsServer) void {
        self.listener.deinit(self.io);
        self.* = undefined;
    }

    pub fn address(self: TlsServer) net.IpAddress {
        return self.listener.socket.address;
    }

    pub fn accept(
        self: *TlsServer,
        options: AcceptOptions,
    ) Error!Connection {
        var pending = try self.receiveUpgradeRequest(options);
        errdefer pending.deinit();
        return pending.accept();
    }

    /// Carry one caller-owned deadline through TCP accept, TLS, and the HTTP
    /// Upgrade.
    pub fn acceptWithDeadline(
        self: *TlsServer,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        var pending = try self.receiveUpgradeRequestWithDeadline(
            options,
            deadline,
        );
        errdefer pending.deinit();
        return pending.accept();
    }

    pub fn acceptWithTimeout(
        self: *TlsServer,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        var pending = try self.receiveUpgradeRequestWithTimeout(
            options,
            timeout,
        );
        errdefer pending.deinit();
        return pending.accept();
    }

    /// Perform TLS and WebSocket handshakes on an already accepted stream.
    pub fn acceptStream(
        self: *TlsServer,
        stream: net.Stream,
        options: AcceptOptions,
    ) Error!Connection {
        var pending = try self.receiveStreamUpgradeRequestMaybeBefore(
            stream,
            options,
            null,
        );
        errdefer pending.deinit();
        return pending.accept();
    }

    pub fn acceptStreamWithDeadline(
        self: *TlsServer,
        stream: net.Stream,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        var pending = try self.receiveStreamUpgradeRequestWithDeadline(
            stream,
            options,
            deadline,
        );
        errdefer pending.deinit();
        return pending.accept();
    }

    pub fn acceptStreamWithTimeout(
        self: *TlsServer,
        stream: net.Stream,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptStreamWithDeadline(
            stream,
            options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Complete TLS and validate the HTTP Upgrade without sending 101.
    pub fn receiveUpgradeRequest(
        self: *TlsServer,
        options: AcceptOptions,
    ) Error!PendingUpgrade {
        const stream = try self.listener.accept(self.io);
        return self.receiveStreamUpgradeRequest(stream, options);
    }

    pub fn receiveUpgradeRequestWithDeadline(
        self: *TlsServer,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PendingUpgrade {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        const stream = try accept_deadline.withDeadline(
            &self.listener,
            self.io,
            deadline,
        );
        return self.receiveStreamUpgradeRequestMaybeBefore(
            stream,
            options,
            deadline,
        );
    }

    pub fn receiveUpgradeRequestWithTimeout(
        self: *TlsServer,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!PendingUpgrade {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveUpgradeRequestWithDeadline(
            options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn receiveStreamUpgradeRequest(
        self: *TlsServer,
        stream: net.Stream,
        options: AcceptOptions,
    ) Error!PendingUpgrade {
        return self.receiveStreamUpgradeRequestMaybeBefore(
            stream,
            options,
            null,
        );
    }

    pub fn receiveStreamUpgradeRequestWithDeadline(
        self: *TlsServer,
        stream: net.Stream,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PendingUpgrade {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.receiveStreamUpgradeRequestMaybeBefore(
            stream,
            options,
            deadline,
        );
    }

    pub fn receiveStreamUpgradeRequestWithTimeout(
        self: *TlsServer,
        stream: net.Stream,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!PendingUpgrade {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveStreamUpgradeRequestWithDeadline(
            stream,
            options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn receiveStreamUpgradeRequestMaybeBefore(
        self: *TlsServer,
        stream: net.Stream,
        options: AcceptOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!PendingUpgrade {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(self.io);
        if (self.tcp_nodelay) try socket_options.setTcpNoDelay(stream);
        const tls_connection = if (deadline) |absolute|
            try tls_stream.ServerConnection.initWithDeadline(
                self.allocator,
                self.io,
                stream,
                self.tls,
                absolute,
            )
        else
            try tls_stream.ServerConnection.init(
                self.allocator,
                self.io,
                stream,
                self.tls,
            );
        stream_owned = false;
        errdefer tls_connection.deinit();
        return receiveUpgradeRequestFromTransport(
            self.allocator,
            self.io,
            .{ .tls_server = tls_connection },
            self.limits,
            options,
            deadline,
        );
    }

    pub fn serveConcurrent(
        self: *TlsServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            *Connection,
        ) Error!void,
        max_connections: usize,
        options: AcceptOptions,
    ) AsyncServeError!ConcurrentServeResult {
        return serveAcceptedConcurrent(
            TlsServer,
            self,
            self.io,
            self.allocator,
            HandlerContext,
            context,
            handler,
            max_connections,
            options,
        );
    }

    pub fn serveUntil(
        self: *TlsServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (*HandlerContext, *Connection) Error!void,
        max_connections: usize,
        accept_options: AcceptOptions,
        serve_options: ServeUntilOptions,
    ) anyerror!void {
        return serveAcceptedUntil(
            TlsServer,
            self,
            self.io,
            HandlerContext,
            context,
            handler,
            max_connections,
            accept_options,
            serve_options,
        );
    }
};

pub const TlsListenOptions = struct {
    identity: vail.tls.auth.ServerIdentity,
    limits: Limits = .{},
    cipher_suites: []const vail.tls.cipher_suite.Suite =
        &vail.tls.cipher_suite.default_preference,
    max_client_hello_size: usize = 64 * 1024,
    max_client_handshake_size: usize = 256 * 1024,
    /// Absolute TLS handshake receive budget. The WebSocket Upgrade-head
    /// deadline starts independently after TLS succeeds.
    tls_handshake_timeout: ?std.Io.Duration = null,
    client_auth: ?vail.tls.client_auth.ServerPolicy = null,
    /// Optional ALPN selection for WSS. Configured servers require one of
    /// these protocols, matching the vail-backed client policy.
    alpn_protocols: []const []const u8 = &.{},
    tcp_nodelay: bool = true,
};

fn receiveUpgradeRequestFromTransport(
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
    try websocket.validateClientHandshake(request);
    try origin_policy.validateHttp1(request.headers, options.allowed_origins);
    // Bytes sent before the 101 response are ambiguous HTTP smuggling/junk,
    // regardless of whether the carrier is TCP or TLS.
    if (head.extra.len != 0) return error.InvalidHandshake;

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

pub const AsyncServeError = Error || std.Io.Cancelable;

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

fn serveAcceptedConcurrent(
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
        group.async(io, ServeTask(HandlerContext).run, .{task});
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

fn serveAcceptedUntil(
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
    ) ?tls_stream.CipherSuite {
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
        const allocator = self.allocator;
        try validateUpgradeAcceptHeaders(additional_headers);
        const combined_count = std.math.add(
            usize,
            self.options.extra_headers.len,
            additional_headers.len,
        ) catch return error.HeadersTooLarge;
        var response: std.ArrayList(u8) = .empty;
        defer response.deinit(allocator);
        const negotiated_count: usize =
            @as(usize, @intFromBool(self.selected_protocol != null)) +
            @as(usize, @intFromBool(self.selected_extension != null));
        const response_count = std.math.add(
            usize,
            combined_count,
            negotiated_count,
        ) catch return error.HeadersTooLarge;
        var response_stack: [handshake_storage.stack_capacity]http1.Header =
            undefined;
        const response_fields = try handshake_storage.acquire(
            http1.Header,
            allocator,
            &response_stack,
            response_count,
        );
        defer handshake_storage.release(
            http1.Header,
            allocator,
            &response_stack,
            response_fields,
        );
        var response_index: usize = 0;
        if (self.selected_protocol) |protocol| {
            response_fields[response_index] = .{
                .name = "Sec-WebSocket-Protocol",
                .value = protocol,
            };
            response_index += 1;
        }
        if (self.selected_extension) |extension| {
            response_fields[response_index] = .{
                .name = "Sec-WebSocket-Extensions",
                .value = extension,
            };
            response_index += 1;
        }
        @memcpy(
            response_fields[response_index..][0..self.options.extra_headers.len],
            self.options.extra_headers,
        );
        response_index += self.options.extra_headers.len;
        @memcpy(response_fields[response_index..], additional_headers);
        try websocket.writeServerHandshake(
            &response,
            self.allocator,
            self.client_key,
            response_fields,
        );
        if (response.items.len > self.limits.max_head_bytes) {
            return error.HeadersTooLarge;
        }
        if (self.deadline) |deadline| {
            _ = try deadline_policy.usableAwake(self.io, deadline);
        }
        const io = self.io;
        const transport = self.transport;
        try transport.writeAll(response.items);

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
            .limits = limits,
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
        if (status < 300 or status > 599) return error.InvalidStatus;
        const allocator = self.allocator;
        try validateUpgradeRejectionHeaders(response_headers);
        const response_count = std.math.add(
            usize,
            response_headers.len,
            1,
        ) catch return error.HeadersTooLarge;
        var response_stack: [handshake_storage.stack_capacity]http1.Header =
            undefined;
        const response_fields = try handshake_storage.acquire(
            http1.Header,
            allocator,
            &response_stack,
            response_count,
        );
        defer handshake_storage.release(
            http1.Header,
            allocator,
            &response_stack,
            response_fields,
        );
        @memcpy(response_fields[0..response_headers.len], response_headers);
        response_fields[response_headers.len] = .{
            .name = "Connection",
            .value = "close",
        };
        var scratch: http1_write.Scratch = .{};
        defer scratch.deinit(allocator);
        const message = try http1_write.prepareResponse(
            allocator,
            .{
                .status = status,
                .reason = reason,
                .headers = response_fields,
                .body = body,
                .request_method = self.request.method,
            },
            &scratch,
        );
        if (message.header.len > self.limits.max_head_bytes) {
            return error.HeadersTooLarge;
        }
        if (self.deadline) |deadline| {
            _ = try deadline_policy.usableAwake(self.io, deadline);
        }
        try self.transport.writeAllParts(message.header, message.body);
        self.deinit();
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
    enable_permessage_deflate: bool,
    allow_context_takeover: bool,
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
        if (!self.accepted()) return error.InvalidResponse;
        const selected_protocol = try validateServerHandshake(
            self.allocator,
            self.response,
            &self.key,
            self.protocols,
        );
        errdefer if (selected_protocol) |protocol| {
            self.allocator.free(protocol);
        };
        const extension_policy: websocket.ExtensionNegotiation.Policy = .{
            .enable_permessage_deflate = self.enable_permessage_deflate,
            .allow_context_takeover = self.allow_context_takeover,
        };
        const selected_extension = try websocket.ExtensionNegotiation
            .validateResponseForOfferWithPolicy(
            try optionalSingletonHeader(
                self.response.headers,
                "sec-websocket-extensions",
            ),
            websocket.ExtensionNegotiation.offerValue(extension_policy),
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
            .limits = self.limits,
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

pub const Client = struct {
    /// Perform a cleartext WebSocket handshake on an already connected stream.
    /// This is primarily for adapters that must emit a transport preface before
    /// the HTTP Upgrade request. Ownership transfers on success.
    pub fn connectAcceptedStream(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        options: ConnectOptions,
    ) Error!Connection {
        var attempt = try connectAcceptedStreamAttempt(
            allocator,
            io,
            stream,
            options,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectAcceptedStreamAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        options: ConnectOptions,
    ) Error!ConnectAttempt {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        var attempt = try connectStreamAttempt(
            allocator,
            io,
            stream,
            null,
            options,
        );
        stream_owned = false;
        return closeRejectedAttempt(&attempt);
    }

    /// Perform TLS and WebSocket handshakes on a connected stream after an
    /// adapter has emitted a transport preface such as PROXY protocol.
    pub fn connectAcceptedTlsStream(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        server_name: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
    ) Error!Connection {
        var attempt = try connectAcceptedTlsStreamAttempt(
            allocator,
            io,
            stream,
            server_name,
            options,
            tls_options,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectAcceptedTlsStreamAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        server_name: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
    ) Error!ConnectAttempt {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        if (options.vail_tls orelse options.tls_identity) |identity| {
            const tls_conn = try tls_client_identity.init(
                allocator,
                io,
                stream,
                server_name,
                tls_options,
                identity,
            );
            stream_owned = false;
            errdefer tls_conn.deinit();
            var attempt = try connectTransportAttempt(
                allocator,
                io,
                .{ .tls_vail = tls_conn },
                options,
                null,
            );
            return closeRejectedAttempt(&attempt);
        }
        const tls_conn = try http1_runtime.TlsClientConnection.init(
            allocator,
            io,
            stream,
            server_name,
            tls_options,
        );
        stream_owned = false;
        errdefer tls_conn.deinit();
        var attempt = try connectTransportAttempt(
            allocator,
            io,
            .{ .tls = tls_conn },
            options,
            null,
        );
        return closeRejectedAttempt(&attempt);
    }

    pub fn connect(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
    ) Error!Connection {
        var attempt = try connectAttempt(allocator, io, address, options);
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
    ) Error!ConnectAttempt {
        if (options.tls_identity != null or options.vail_tls != null) {
            return error.UnsupportedScheme;
        }
        const stream = try tcp_connect.ip(io, address, options.connect_timeout);
        errdefer stream.close(io);
        var attempt = try connectStreamAttempt(allocator, io, stream, null, options);
        return closeRejectedAttempt(&attempt);
    }

    /// Establish cleartext WebSocket under one caller-owned deadline spanning
    /// TCP setup and the complete HTTP Upgrade response.
    pub fn connectWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        var attempt = try connectAttemptWithDeadline(
            allocator,
            io,
            address,
            options,
            deadline,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        if (options.tls_identity != null or options.vail_tls != null) {
            return error.UnsupportedScheme;
        }
        const stream = try tcp_connect.ipWithDeadline(
            io,
            address,
            try deadline_policy.capTimeout(
                io,
                deadline,
                options.connect_timeout,
            ),
        );
        errdefer stream.close(io);
        var attempt = try connectStreamAttemptBefore(
            allocator,
            io,
            stream,
            null,
            options,
            deadline,
        );
        return closeRejectedAttempt(&attempt);
    }

    pub fn connectWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectWithDeadline(
            allocator,
            io,
            address,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectAttemptWithDeadline(
            allocator,
            io,
            address,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Connect a cleartext WebSocket over a Unix-domain stream socket.
    /// `options.host` remains the HTTP Host authority and must be supplied by
    /// the caller because a filesystem path is not an HTTP authority.
    pub fn connectUnix(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
    ) Error!Connection {
        var attempt = try connectUnixAttempt(allocator, io, address, options);
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectUnixAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
    ) Error!ConnectAttempt {
        if (options.tls_identity != null or options.vail_tls != null) {
            return error.UnsupportedScheme;
        }
        if (options.host.len == 0) return error.InvalidUri;
        const stream = try tcp_connect.unix(io, address, options.connect_timeout);
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        var connect_options = options;
        connect_options.tcp_nodelay = false;
        var attempt = try connectStreamAttempt(
            allocator,
            io,
            stream,
            null,
            connect_options,
        );
        stream_owned = false;
        return closeRejectedAttempt(&attempt);
    }

    pub fn connectUnixWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        var attempt = try connectUnixAttemptWithDeadline(
            allocator,
            io,
            address,
            options,
            deadline,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectUnixAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        if (options.tls_identity != null or options.vail_tls != null) {
            return error.UnsupportedScheme;
        }
        if (options.host.len == 0) return error.InvalidUri;
        const stream = try tcp_connect.unixWithDeadline(
            io,
            address,
            try deadline_policy.capTimeout(
                io,
                deadline,
                options.connect_timeout,
            ),
        );
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        var connect_options = options;
        connect_options.tcp_nodelay = false;
        var attempt = try connectStreamAttemptBefore(
            allocator,
            io,
            stream,
            null,
            connect_options,
            deadline,
        );
        stream_owned = false;
        return closeRejectedAttempt(&attempt);
    }

    pub fn connectUnixWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUnixWithDeadline(
            allocator,
            io,
            address,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectUnixAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.UnixAddress,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUnixAttemptWithDeadline(
            allocator,
            io,
            address,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
    ) Error!Connection {
        var attempt = try connectHostAttempt(
            allocator,
            io,
            host,
            port,
            options,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectHostAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
    ) Error!ConnectAttempt {
        if (options.tls_identity != null or options.vail_tls != null) {
            return error.UnsupportedScheme;
        }
        const host_name = try net.HostName.init(host);
        const stream = try tcp_connect.host(
            io,
            host_name,
            port,
            options.connect_timeout,
        );
        errdefer stream.close(io);
        const default_host = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ host, port });
        defer allocator.free(default_host);
        var connect_options = options;
        if (connect_options.host.len == 0) connect_options.host = default_host;
        var attempt = try connectStreamAttempt(
            allocator,
            io,
            stream,
            null,
            connect_options,
        );
        return closeRejectedAttempt(&attempt);
    }

    pub fn connectHostWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        var attempt = try connectHostAttemptWithDeadline(
            allocator,
            io,
            host,
            port,
            options,
            deadline,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectHostAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        if (options.tls_identity != null or options.vail_tls != null) {
            return error.UnsupportedScheme;
        }
        const host_name = try net.HostName.init(host);
        const stream = try tcp_connect.hostWithDeadline(
            io,
            host_name,
            port,
            try deadline_policy.capTimeout(
                io,
                deadline,
                options.connect_timeout,
            ),
        );
        errdefer stream.close(io);
        const default_host = try std.fmt.allocPrint(
            allocator,
            "{s}:{d}",
            .{ host, port },
        );
        defer allocator.free(default_host);
        var connect_options = options;
        if (connect_options.host.len == 0) connect_options.host = default_host;
        var attempt = try connectStreamAttemptBefore(
            allocator,
            io,
            stream,
            null,
            connect_options,
            deadline,
        );
        return closeRejectedAttempt(&attempt);
    }

    pub fn connectHostWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectHostWithDeadline(
            allocator,
            io,
            host,
            port,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectHostAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectHostAttemptWithDeadline(
            allocator,
            io,
            host,
            port,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectTlsHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
    ) Error!Connection {
        var attempt = try connectTlsHostAttempt(
            allocator,
            io,
            host,
            port,
            options,
            tls_options,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectTlsHostAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
    ) Error!ConnectAttempt {
        const host_name = try net.HostName.init(host);
        const stream = try tcp_connect.host(
            io,
            host_name,
            port,
            options.connect_timeout,
        );
        var attempt = try connectTlsStreamAttempt(
            allocator,
            io,
            stream,
            host,
            port,
            options,
            tls_options,
        );
        return closeRejectedAttempt(&attempt);
    }

    pub fn connectTlsHostWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        var attempt = try connectTlsHostAttemptWithDeadline(
            allocator,
            io,
            host,
            port,
            options,
            tls_options,
            deadline,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectTlsHostAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        const host_name = try net.HostName.init(host);
        const stream = try tcp_connect.hostWithDeadline(
            io,
            host_name,
            port,
            try deadline_policy.capTimeout(
                io,
                deadline,
                options.connect_timeout,
            ),
        );
        var attempt = try connectTlsStreamAttemptBefore(
            allocator,
            io,
            stream,
            host,
            port,
            options,
            tls_options,
            deadline,
        );
        return closeRejectedAttempt(&attempt);
    }

    pub fn connectTlsHostWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectTlsHostWithDeadline(
            allocator,
            io,
            host,
            port,
            options,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectTlsHostAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectTlsHostAttemptWithDeadline(
            allocator,
            io,
            host,
            port,
            options,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Connect to a resolved address while verifying TLS against a separate
    /// hostname. This keeps caller-controlled DNS/service discovery distinct
    /// from SNI and certificate identity. `options.host`, when empty, defaults
    /// to `tls_host:address-port` for the HTTP Upgrade authority.
    pub fn connectTlsAddress(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
    ) Error!Connection {
        var attempt = try connectTlsAddressAttempt(
            allocator,
            io,
            address,
            tls_host,
            options,
            tls_options,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectTlsAddressAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
    ) Error!ConnectAttempt {
        _ = try net.HostName.init(tls_host);
        const stream = try tcp_connect.ip(
            io,
            address,
            options.connect_timeout,
        );
        var attempt = try connectTlsStreamAttempt(
            allocator,
            io,
            stream,
            tls_host,
            address.getPort(),
            options,
            tls_options,
        );
        return closeRejectedAttempt(&attempt);
    }

    pub fn connectTlsAddressWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        var attempt = try connectTlsAddressAttemptWithDeadline(
            allocator,
            io,
            address,
            tls_host,
            options,
            tls_options,
            deadline,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectTlsAddressAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        _ = try net.HostName.init(tls_host);
        const stream = try tcp_connect.ipWithDeadline(
            io,
            address,
            try deadline_policy.capTimeout(
                io,
                deadline,
                options.connect_timeout,
            ),
        );
        var attempt = try connectTlsStreamAttemptBefore(
            allocator,
            io,
            stream,
            tls_host,
            address.getPort(),
            options,
            tls_options,
            deadline,
        );
        return closeRejectedAttempt(&attempt);
    }

    pub fn connectTlsAddressWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectTlsAddressWithDeadline(
            allocator,
            io,
            address,
            tls_host,
            options,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectTlsAddressAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectTlsAddressAttemptWithDeadline(
            allocator,
            io,
            address,
            tls_host,
            options,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn connectTlsStreamAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_host: []const u8,
        port: u16,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
    ) Error!ConnectAttempt {
        return connectTlsStreamAttemptMaybeBefore(
            allocator,
            io,
            stream,
            tls_host,
            port,
            options,
            tls_options,
            null,
        );
    }

    fn connectTlsStreamAttemptBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_host: []const u8,
        port: u16,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        _ = try deadline_policy.usableAwake(io, deadline);
        return connectTlsStreamAttemptMaybeBefore(
            allocator,
            io,
            stream,
            tls_host,
            port,
            options,
            tls_options,
            deadline,
        );
    }

    fn connectTlsStreamAttemptMaybeBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_host: []const u8,
        port: u16,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        const default_host = try std.fmt.allocPrint(
            allocator,
            "{s}:{d}",
            .{ tls_host, port },
        );
        defer allocator.free(default_host);
        var connect_options = options;
        if (connect_options.host.len == 0) connect_options.host = default_host;
        if (connect_options.vail_tls orelse
            connect_options.tls_identity) |identity|
        {
            const tls_conn = if (deadline) |absolute|
                try tls_client_identity.initWithDeadline(
                    allocator,
                    io,
                    stream,
                    tls_host,
                    tls_options,
                    identity,
                    absolute,
                )
            else
                try tls_client_identity.init(
                    allocator,
                    io,
                    stream,
                    tls_host,
                    tls_options,
                    identity,
                );
            stream_owned = false;
            errdefer tls_conn.deinit();
            return connectTransportAttempt(
                allocator,
                io,
                .{ .tls_vail = tls_conn },
                connect_options,
                deadline,
            );
        }
        const tls_conn = if (deadline) |absolute|
            try http1_runtime.TlsClientConnection.initWithDeadline(
                allocator,
                io,
                stream,
                tls_host,
                tls_options,
                absolute,
            )
        else
            try http1_runtime.TlsClientConnection.init(
                allocator,
                io,
                stream,
                tls_host,
                tls_options,
            );
        stream_owned = false;
        errdefer tls_conn.deinit();
        return connectTransportAttempt(
            allocator,
            io,
            .{ .tls = tls_conn },
            connect_options,
            deadline,
        );
    }

    pub fn connectUri(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
    ) Error!Connection {
        return connectUriTls(allocator, io, uri_text, options, .{});
    }

    pub fn connectUriTls(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
    ) Error!Connection {
        return connectUriTlsBefore(
            allocator,
            io,
            uri_text,
            options,
            tls_options,
            null,
        );
    }

    pub fn connectUriAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
    ) Error!ConnectAttempt {
        return connectUriTlsAttempt(allocator, io, uri_text, options, .{});
    }

    pub fn connectUriTlsAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
    ) Error!ConnectAttempt {
        var attempt = try connectUriTlsAttemptBefore(
            allocator,
            io,
            uri_text,
            options,
            tls_options,
            null,
        );
        return closeRejectedAttempt(&attempt);
    }

    pub fn connectUriWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        return connectUriTlsWithDeadline(
            allocator,
            io,
            uri_text,
            options,
            .{},
            deadline,
        );
    }

    pub fn connectUriAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        return connectUriTlsAttemptWithDeadline(
            allocator,
            io,
            uri_text,
            options,
            .{},
            deadline,
        );
    }

    pub fn connectUriWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriWithDeadline(
            allocator,
            io,
            uri_text,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectUriAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriAttemptWithDeadline(
            allocator,
            io,
            uri_text,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectUriTlsWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Connection {
        return connectUriTlsBefore(
            allocator,
            io,
            uri_text,
            options,
            tls_options,
            try deadline_policy.usableAwake(io, deadline),
        );
    }

    pub fn connectUriTlsAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        var attempt = try connectUriTlsAttemptBefore(
            allocator,
            io,
            uri_text,
            options,
            tls_options,
            try deadline_policy.usableAwake(io, deadline),
        );
        return closeRejectedAttempt(&attempt);
    }

    pub fn connectUriTlsWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriTlsWithDeadline(
            allocator,
            io,
            uri_text,
            options,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectUriTlsAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        timeout: std.Io.Duration,
    ) Error!ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriTlsAttemptWithDeadline(
            allocator,
            io,
            uri_text,
            options,
            tls_options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn connectUriTlsBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!Connection {
        var attempt = try connectUriTlsAttemptBefore(
            allocator,
            io,
            uri_text,
            options,
            tls_options,
            deadline,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    fn connectUriTlsAttemptBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        const is_ws = std.ascii.eqlIgnoreCase(uri.scheme, "ws");
        const is_wss = std.ascii.eqlIgnoreCase(uri.scheme, "wss");
        if (!is_ws and !is_wss) return error.UnsupportedScheme;
        if ((options.tls_identity != null or options.vail_tls != null) and
            !is_wss)
        {
            // Client certificates are TLS credentials. Reject rather than
            // silently dropping them when this helper receives a ws:// URI.
            return error.UnsupportedScheme;
        }
        const target = try uriTargetAlloc(allocator, uri);
        defer allocator.free(target);
        var endpoint = try http1_runtime.uriEndpoint(allocator, uri, if (is_wss) 443 else 80);
        defer endpoint.deinit();

        var connect_options = options;
        connect_options.target = target;
        if (connect_options.host.len == 0) connect_options.host = endpoint.authority;

        const stream = if (deadline) |absolute| switch (endpoint.target) {
            .host => |host| try tcp_connect.hostWithDeadline(
                io,
                host,
                endpoint.port,
                try deadline_policy.capTimeout(
                    io,
                    absolute,
                    options.connect_timeout,
                ),
            ),
            .ip => |address| try tcp_connect.ipWithDeadline(
                io,
                address,
                try deadline_policy.capTimeout(
                    io,
                    absolute,
                    options.connect_timeout,
                ),
            ),
        } else switch (endpoint.target) {
            .host => |host| try tcp_connect.host(
                io,
                host,
                endpoint.port,
                options.connect_timeout,
            ),
            .ip => |address| try tcp_connect.ip(
                io,
                address,
                options.connect_timeout,
            ),
        };
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        if (is_wss) {
            if (options.vail_tls orelse options.tls_identity) |identity| {
                const tls_conn = if (deadline) |absolute|
                    try tls_client_identity.initWithDeadline(
                        allocator,
                        io,
                        stream,
                        endpoint.tls_host,
                        tls_options,
                        identity,
                        absolute,
                    )
                else
                    try tls_client_identity.init(
                        allocator,
                        io,
                        stream,
                        endpoint.tls_host,
                        tls_options,
                        identity,
                    );
                stream_owned = false;
                errdefer tls_conn.deinit();
                return connectTransportAttempt(
                    allocator,
                    io,
                    .{ .tls_vail = tls_conn },
                    connect_options,
                    deadline,
                );
            }
            var standard_tls_options = tls_options;
            if (standard_tls_options.handshake_timeout == null) {
                standard_tls_options.handshake_timeout =
                    connect_options.tls_handshake_timeout;
            }
            const tls_conn = if (deadline) |absolute|
                try http1_runtime.TlsClientConnection.initWithDeadline(
                    allocator,
                    io,
                    stream,
                    endpoint.tls_host,
                    standard_tls_options,
                    absolute,
                )
            else
                try http1_runtime.TlsClientConnection.init(
                    allocator,
                    io,
                    stream,
                    endpoint.tls_host,
                    standard_tls_options,
                );
            stream_owned = false;
            errdefer tls_conn.deinit();
            return connectTransportAttempt(
                allocator,
                io,
                .{ .tls = tls_conn },
                connect_options,
                deadline,
            );
        }
        const attempt = try connectTransportAttempt(
            allocator,
            io,
            .{ .tcp = .{ .io = io, .stream = stream } },
            connect_options,
            deadline,
        );
        stream_owned = false;
        return attempt;
    }

    fn connectStreamAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_conn: ?*http1_runtime.TlsClientConnection,
        options: ConnectOptions,
    ) Error!ConnectAttempt {
        return connectStreamAttemptMaybeBefore(
            allocator,
            io,
            stream,
            tls_conn,
            options,
            null,
        );
    }

    fn connectStreamAttemptBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_conn: ?*http1_runtime.TlsClientConnection,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        _ = try deadline_policy.usableAwake(io, deadline);
        return connectStreamAttemptMaybeBefore(
            allocator,
            io,
            stream,
            tls_conn,
            options,
            deadline,
        );
    }

    fn connectStreamAttemptMaybeBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_conn: ?*http1_runtime.TlsClientConnection,
        options: ConnectOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        if (options.tcp_nodelay) {
            try socket_options.setTcpNoDelay(stream);
        }
        const transport: RuntimeTransport = if (tls_conn) |conn| .{ .tls = conn } else .{ .tcp = .{ .io = io, .stream = stream } };
        return connectTransportAttempt(
            allocator,
            io,
            transport,
            options,
            deadline,
        );
    }

    fn closeRejectedAttempt(attempt: *ConnectAttempt) ConnectAttempt {
        if (!attempt.accepted()) {
            attempt.transport.?.close();
            attempt.transport = null;
        }
        return attempt.*;
    }

    fn connectTransportAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        transport: RuntimeTransport,
        options: ConnectOptions,
        outer_deadline: ?std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        var nonce: [16]u8 = undefined;
        try std.Io.randomSecure(io, &nonce);
        var key: [24]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&key, &nonce);

        var protocol_value_stack: [handshake_headers.protocol_value_stack_capacity]u8 = undefined;
        var protocol_value = try handshake_headers.prepareProtocolValue(
            allocator,
            options.protocols,
            &protocol_value_stack,
        );
        defer protocol_value.deinit(allocator);
        try validateHttp1ClientExtraHeadersImpl(options.extra_headers);
        const headers_count = std.math.add(
            usize,
            4 + @as(usize, @intFromBool(protocol_value.value.len != 0)) +
                @as(usize, @intFromBool(options.origin != null)) +
                @as(usize, @intFromBool(options.enable_permessage_deflate)),
            options.extra_headers.len,
        ) catch return error.HeadersTooLarge;
        var headers_stack: [handshake_storage.stack_capacity]http1.Header =
            undefined;
        const headers = try handshake_storage.acquire(
            http1.Header,
            allocator,
            &headers_stack,
            headers_count,
        );
        defer handshake_storage.release(
            http1.Header,
            allocator,
            &headers_stack,
            headers,
        );
        var header_index: usize = 0;
        headers[header_index] = .{ .name = "Upgrade", .value = "websocket" };
        header_index += 1;
        headers[header_index] = .{ .name = "Connection", .value = "Upgrade" };
        header_index += 1;
        headers[header_index] = .{ .name = "Sec-WebSocket-Key", .value = &key };
        header_index += 1;
        headers[header_index] = .{ .name = "Sec-WebSocket-Version", .value = "13" };
        header_index += 1;
        if (protocol_value.value.len != 0) {
            headers[header_index] = .{
                .name = "Sec-WebSocket-Protocol",
                .value = protocol_value.value,
            };
            header_index += 1;
        }
        if (options.origin) |origin| {
            headers[header_index] = .{ .name = "Origin", .value = origin };
            header_index += 1;
        }
        if (websocket.ExtensionNegotiation.offerValue(.{
            .enable_permessage_deflate = options.enable_permessage_deflate,
            .allow_context_takeover = options.allow_context_takeover,
        })) |extension_offer| {
            headers[header_index] = .{
                .name = "Sec-WebSocket-Extensions",
                .value = extension_offer,
            };
            header_index += 1;
        }
        @memcpy(headers[header_index..], options.extra_headers);
        try writeHttpUpgradeRequest(
            allocator,
            transport,
            .{
                .method = .GET,
                .target = options.target,
                .host = options.host,
                .headers = headers,
            },
            options.limits.max_head_bytes,
        );

        const deadline = deadline_policy.earlier(
            outer_deadline,
            if (options.limits.http1_handshake_timeout) |timeout|
                try handshakeDeadline(transport, timeout)
            else
                null,
        );
        var head = try readHttpHeadFromTransport(
            allocator,
            transport,
            options.limits.max_head_bytes,
            deadline,
        );
        var head_owned = true;
        defer if (head_owned) head.deinit(allocator);
        var informational_count: usize = 0;
        while (true) {
            var response_header_stack: [handshake_storage.stack_capacity]http1.Header =
                undefined;
            const response_headers = try handshake_storage.acquire(
                http1.Header,
                allocator,
                &response_header_stack,
                options.limits.max_response_headers,
            );
            defer handshake_storage.release(
                http1.Header,
                allocator,
                &response_header_stack,
                response_headers,
            );
            const response_head = try http1.parseResponseHead(
                head.head,
                response_headers,
                http1HandshakeResponseParseOptions(options.limits),
                .{ .request_method = .GET },
            );
            if (response_head.status < 100 or
                response_head.status >= 200 or
                response_head.status == 101)
            {
                break;
            }
            try http1.validateResponseBodyForStatus(
                response_head.status,
                response_head.headers,
                &.{},
                &.{},
            );
            informational_count += 1;
            if (informational_count >
                options.limits.max_informational_responses)
            {
                return error.TooManyInformationalResponses;
            }
            const next = try readHttpHeadFromTransportWithInitial(
                allocator,
                transport,
                options.limits.max_head_bytes,
                deadline,
                head.extra,
            );
            head.deinit(allocator);
            head = next;
        }
        const response_bytes = try readHttpUpgradeResponseBytes(
            allocator,
            transport,
            &head,
            options.limits,
            outer_deadline,
        );
        if (response_bytes.extra != null) head_owned = false;
        errdefer allocator.free(response_bytes.bytes);
        errdefer if (response_bytes.extra) |extra| allocator.free(extra);
        var response = try http1.parseResponse(
            allocator,
            response_bytes.bytes,
            http1HandshakeResponseParseOptions(options.limits),
        );
        errdefer response.deinit(allocator);
        if (response.status != 101 and
            http1_message_framing.responseHeadUsesCloseDelimitedBody(
                head.head[0 .. head.head.len - 4],
                .GET,
            ))
        {
            response.body = response_bytes.bytes[head.head.len..];
            response.body_framing = .close_delimited;
            response.consumed = response_bytes.bytes.len;
        }
        return .{
            .allocator = allocator,
            .io = io,
            .transport = transport,
            .response_bytes = response_bytes.bytes,
            .response = response,
            .initial_websocket_bytes = response_bytes.extra,
            .key = key,
            .protocols = options.protocols,
            .enable_permessage_deflate = options.enable_permessage_deflate,
            .allow_context_takeover = options.allow_context_takeover,
            .compression_threshold = options.compression_threshold,
            .limits = options.limits,
        };
    }
};

fn uriTargetAlloc(allocator: std.mem.Allocator, uri: std.Uri) Error![]u8 {
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

pub const ConnectOptions = struct {
    /// HTTP Host authority for the WebSocket opening handshake.  `connectHost`
    /// defaults this to its resolved host name when left empty.
    host: []const u8 = "",
    target: []const u8 = "/",
    protocols: []const []const u8 = &.{},
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
    /// Minimum complete message size considered for outbound compression.
    /// Set to zero to attempt every data message or maxInt to receive-only.
    compression_threshold: usize = default_compression_threshold,
    tcp_nodelay: bool = true,
    /// Absolute budget for DNS resolution plus all TCP connection attempts.
    /// TLS and HTTP Upgrade retain their separate handshake policies.
    connect_timeout: ?std.Io.Duration = null,
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

pub const OwnedMessage = common.OwnedMessage;
pub const CloseHandshakeEvent = common.CloseHandshakeEvent;
pub const PingEvent = common.PingEvent;
pub const Message = common.Message;
pub const MessageWriteProgress = common.MessageWriteProgress;
const MessageIntoReceiveState = common.MessageIntoReceiveState;
const PendingAutomaticControl = common.PendingAutomaticControl;

pub const Connection = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    stream: net.Stream,
    tls_conn: ?*http1_runtime.TlsClientConnection = null,
    tls_vail_conn: ?*tls_stream.ClientConnection = null,
    tls_server_conn: ?*tls_stream.ServerConnection = null,
    role: Role,
    limits: Limits = .{},
    inbuf: std.ArrayList(u8) = .empty,
    inbuf_consumed: usize = 0,
    send_mutex: std.Io.Mutex = .init,
    /// Read progress and application writers may observe close state on
    /// different threads, while the send mutex orders complete wire writes.
    close_sent: std.atomic.Value(bool) = .init(false),
    close_received: std.atomic.Value(bool) = .init(false),
    /// A fatal receive failure permanently retires the input half so an
    /// offending or truncated prefix cannot be reparsed. Protocol failures
    /// send Close; abrupt transport ends terminate without fabricating one.
    receive_failed: std.atomic.Value(bool) = .init(false),
    /// A fatal receive raced a retained outbound transaction, so the byte
    /// stream was aborted instead of appending a Close after a partial frame.
    write_aborted: std.atomic.Value(bool) = .init(false),
    /// Lock-free receive-side visibility for resumable application/Ping/Close
    /// transactions. The transaction details remain protected by send_mutex.
    application_write_pending: std.atomic.Value(bool) = .init(false),
    automatic_write_pending: std.atomic.Value(bool) = .init(false),
    incoming_data_kind: IncomingDataKind = .none,
    incoming_text_utf8: websocket.Utf8Validator = .{},
    incoming_frame_validated: usize = 0,
    message_assembler: ?websocket.MessageAssembler = null,
    message_into: MessageIntoReceiveState = .{},
    message_frame_receive: MessageFrameReceiveState = .{},
    selected_protocol: ?[]u8 = null,
    permessage_deflate: bool = false,
    compression_send_context_takeover: bool = false,
    compression_receive_context_takeover: bool = false,
    compression_threshold: usize = default_compression_threshold,
    /// Maximum LZ77 distance for messages emitted by this endpoint. The field
    /// follows the role-specific RFC 7692 direction selected at handshake.
    compression_send_max_window_bits: u8 = 15,
    compression_receive_max_window_bits: u8 = 15,
    compression_send: compression_scratch.SendScratch = .{},
    compression_receive: compression_scratch.Scratch = .{},
    /// One HTTP/1 application frame may outlive a bounded socket write. The
    /// caller retains the original payload; this state retains its mask,
    /// compression output, header, and exact transport cursor.
    pending_message: ?PendingMessage = null,
    pending_ping: ?PendingControlFrame = null,
    pending_close: ?PendingControlFrame = null,
    /// Automatic Pong/Close bytes and, for receiveFrameAuto, the peer frame
    /// that must be delivered after a bounded reply resumes to completion.
    pending_auto_control: ?PendingAutomaticControl = null,

    /// Return the authenticated peer certificate chain. Server-side WSS
    /// returns a verified client chain when mTLS succeeded; vail-backed WSS
    /// clients return the verified server chain. Other transports return null.
    pub fn peerCertificates(
        self: *const Connection,
    ) ?[]const []const u8 {
        if (self.tls_server_conn) |connection| {
            return connection.peerCertificates();
        }
        if (self.tls_vail_conn) |connection| {
            return connection.peerCertificates();
        }
        return null;
    }

    /// Return authenticated TLS 1.3 cipher-suite metadata for vail-backed
    /// WSS. Cleartext and Zig standard-library TLS transports return null.
    pub fn negotiatedCipherSuite(
        self: *const Connection,
    ) ?tls_stream.CipherSuite {
        if (self.tls_server_conn) |connection| {
            return connection.negotiatedCipherSuite();
        }
        if (self.tls_vail_conn) |connection| {
            return connection.negotiatedCipherSuite();
        }
        return null;
    }

    /// Return the negotiated WSS ALPN value for vail-backed transports.
    pub fn negotiatedAlpn(self: *const Connection) ?[]const u8 {
        if (self.tls_server_conn) |connection| {
            return connection.negotiatedAlpn();
        }
        if (self.tls_vail_conn) |connection| {
            return connection.negotiatedAlpn();
        }
        return null;
    }

    /// Return the transcript/HKDF hash implied by the negotiated WSS suite.
    pub fn negotiatedTranscriptHash(
        self: *const Connection,
    ) ?tls_stream.TranscriptHash {
        if (self.tls_server_conn) |connection| {
            return connection.negotiatedTranscriptHash();
        }
        if (self.tls_vail_conn) |connection| {
            return connection.negotiatedTranscriptHash();
        }
        return null;
    }

    /// Start a TLS 1.3 application traffic-key update for vail-backed WSS.
    /// The connection send mutex keeps this control record ordered with every
    /// WebSocket frame writer.
    pub fn updateTrafficKeys(
        self: *Connection,
        request_peer_update: bool,
    ) Error!void {
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);
        if (!self.canSendOpcodeLocked(.binary)) {
            return error.ConnectionClosed;
        }
        if (self.pending_message != null or
            self.pending_ping != null or
            self.pending_close != null or
            self.pending_auto_control != null)
        {
            return error.WriteInProgress;
        }
        if (self.tls_server_conn) |connection| {
            return connection.updateTrafficKeys(request_peer_update);
        }
        if (self.tls_vail_conn) |connection| {
            return connection.updateTrafficKeys(request_peer_update);
        }
        return error.TlsKeyUpdateUnavailable;
    }

    pub fn keyUpdateCounts(
        self: *const Connection,
    ) ?tls_stream.KeyUpdateCounts {
        if (self.tls_server_conn) |connection| {
            return connection.keyUpdateCounts();
        }
        if (self.tls_vail_conn) |connection| {
            return connection.keyUpdateCounts();
        }
        return null;
    }

    /// Export RFC 8446 channel-bound keying material for vail-backed WSS.
    pub fn exportKeyingMaterial(
        self: *const Connection,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        if (self.tls_server_conn) |connection| {
            return connection.exportKeyingMaterial(label, context, out);
        }
        if (self.tls_vail_conn) |connection| {
            return connection.exportKeyingMaterial(label, context, out);
        }
        return error.ExporterUnavailable;
    }

    fn bufferInitial(self: *Connection, bytes: []const u8) Error!void {
        try message_buffer.appendAfterConsumed(
            &self.inbuf,
            &self.inbuf_consumed,
            self.allocator,
            bytes,
        );
    }

    fn transport(self: *Connection) RuntimeTransport {
        if (self.tls_server_conn) |conn| return .{ .tls_server = conn };
        if (self.tls_vail_conn) |conn| return .{ .tls_vail = conn };
        if (self.tls_conn) |conn| return .{ .tls = conn };
        return .{ .tcp = .{ .io = self.io, .stream = self.stream } };
    }

    pub fn close(self: *Connection) void {
        if (self.pending_message) |*pending| {
            std.crypto.secureZero(u8, &pending.header);
            if (pending.mask_key) |*mask| {
                std.crypto.secureZero(u8, mask);
            }
        }
        if (self.pending_ping) |*pending| {
            std.crypto.secureZero(u8, &pending.bytes);
            std.crypto.secureZero(u8, &pending.payload);
        }
        if (self.pending_close) |*pending| {
            std.crypto.secureZero(u8, &pending.bytes);
            std.crypto.secureZero(u8, &pending.payload);
        }
        if (self.pending_auto_control) |*pending| {
            pending.deinit(self.allocator);
        }
        if (self.selected_protocol) |protocol| self.allocator.free(protocol);
        if (self.message_assembler) |*assembler| assembler.deinit();
        self.inbuf.deinit(self.allocator);
        self.compression_send.deinit(self.allocator);
        self.compression_receive.deinit(self.allocator);
        self.transport().close();
        self.* = undefined;
    }

    pub fn sendText(self: *Connection, text: []const u8) Error!void {
        try self.sendMessage(.text, text);
    }

    pub fn sendTextWithTimeout(
        self: *Connection,
        text: []const u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendTextWithDeadline(text, progress, .fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// Send one HTTP/1 WebSocket text frame under an absolute transport
    /// deadline. After partial progress retry with the identical payload slice
    /// until `frame_committed` is true.
    pub fn sendTextWithDeadline(
        self: *Connection,
        text: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(self.io, deadline);
        try common.validateOutgoingMessage(self.limits, .text, text);
        return self.sendMessageWithDeadlineLocked(
            .text,
            text,
            progress,
            deadline,
        );
    }

    pub fn sendBinary(self: *Connection, payload: []const u8) Error!void {
        try self.sendMessage(.binary, payload);
    }

    pub fn sendBinaryWithTimeout(
        self: *Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendBinaryWithDeadline(payload, progress, .fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn sendBinaryWithDeadline(
        self: *Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(self.io, deadline);
        try common.validateOutgoingMessage(
            self.limits,
            .binary,
            payload,
        );
        return self.sendMessageWithDeadlineLocked(
            .binary,
            payload,
            progress,
            deadline,
        );
    }

    /// Compatibility wrapper for the two-slice binary-message form.
    pub fn sendBinaryParts(
        self: *Connection,
        first: []const u8,
        second: []const u8,
    ) Error!void {
        return self.sendBinarySlices(&.{ first, second });
    }

    /// Send borrowed slices as one FIN-terminated binary message.
    ///
    /// The uncompressed server path uses scatter/gather without concatenating
    /// caller data. Clients mask through bounded stack storage while preserving
    /// one continuous four-byte mask phase across every slice. Negotiated
    /// compression consumes the same logical message without a plaintext join.
    pub fn sendBinarySlices(
        self: *Connection,
        parts: []const []const u8,
    ) Error!void {
        if (!canSendOpcode(.binary, self.closeSent(), self.closeReceived())) {
            return error.ConnectionClosed;
        }
        const payload_len = try common.validateOutgoingMessageParts(
            self.limits,
            parts,
        );
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);
        if (self.pending_message != null or
            self.pending_ping != null or
            self.pending_close != null or
            self.pending_auto_control != null)
        {
            return error.WriteInProgress;
        }
        if (!self.canSendOpcodeLocked(.binary)) return error.ConnectionClosed;

        if (self.permessage_deflate and
            payload_len >= self.compression_threshold)
        {
            const compressed = try self.compressMessagePartsLocked(
                parts,
                payload_len,
            );
            if (compressed.len < payload_len) {
                self.writeFrameLockedExtended(
                    .binary,
                    compressed,
                    true,
                    .{ .rsv1 = true },
                ) catch |err| {
                    self.abortAfterUnboundedMessageWriteLocked();
                    return err;
                };
                self.commitCompressionPreviewLocked();
                return;
            }
            self.discardCompressionPreviewLocked();
        }

        var header_storage: [websocket.max_frame_header_len]u8 = undefined;
        if (self.role == .server) {
            const header = try websocket.writeFrameHeaderForLengthInto(
                &header_storage,
                .binary,
                payload_len,
                .{},
            );
            writeUnmaskedPayloadSlices(self.transport(), header, parts) catch |err| {
                self.abortAfterUnboundedMessageWriteLocked();
                return err;
            };
            return;
        }

        var mask_key: [4]u8 = undefined;
        try std.Io.randomSecure(self.io, &mask_key);
        const header = try websocket.writeFrameHeaderForLengthInto(
            &header_storage,
            .binary,
            payload_len,
            .{ .mask_key = mask_key },
        );
        writeMaskedPayloadParts(
            self.transport(),
            header,
            parts,
            mask_key,
        ) catch |err| {
            self.abortAfterUnboundedMessageWriteLocked();
            return err;
        };
    }

    pub fn sendBinarySlicesWithTimeout(
        self: *Connection,
        parts: []const []const u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendBinarySlicesWithDeadline(
            parts,
            progress,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Send borrowed slices as one binary frame under an absolute deadline.
    /// Retry with the same descriptor array and stable payload bytes until
    /// `frame_committed` is true.
    pub fn sendBinarySlicesWithDeadline(
        self: *Connection,
        parts: []const []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(self.io, deadline);
        const payload_len = try common.validateOutgoingMessageParts(
            self.limits,
            parts,
        );
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);
        _ = try deadline_policy.usableAwake(self.io, deadline);
        if (self.pending_ping != null or self.pending_close != null) {
            return error.WriteInProgress;
        }
        if (self.pending_message) |*pending| {
            if (!pending.matchesParts(parts)) {
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.totalLen(),
                };
                return error.WriteInProgress;
            }
        } else {
            if (self.pending_auto_control != null) {
                return error.WriteInProgress;
            }
            if (!self.canSendOpcodeLocked(.binary)) {
                return error.ConnectionClosed;
            }
            try self.beginPendingMessagePartsLocked(parts, payload_len);
        }
        try self.resumePendingMessagePartsLocked(parts, progress, deadline);
    }

    /// Send one binary message by masking the caller buffer in place.
    ///
    /// This opt-in API matches mutable-buffer WebSocket clients such as
    /// websocket.zig. The payload remains masked after return; callers that
    /// need immutable input should continue using `sendBinary`.
    pub fn sendBinaryInPlace(
        self: *Connection,
        payload: []u8,
    ) Error!void {
        if (self.role != .client or self.permessage_deflate) {
            return error.InvalidFrame;
        }
        if (!canSendOpcode(.binary, self.closeSent(), self.closeReceived())) {
            return error.ConnectionClosed;
        }
        try common.validateOutgoingMessage(
            self.limits,
            .binary,
            payload,
        );
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);
        if (self.pending_message != null or
            self.pending_ping != null or
            self.pending_close != null or
            self.pending_auto_control != null)
        {
            return error.WriteInProgress;
        }
        if (!self.canSendOpcodeLocked(.binary)) return error.ConnectionClosed;

        var mask_key: [4]u8 = undefined;
        try std.Io.randomSecure(self.io, &mask_key);
        var header_storage: [websocket.max_frame_header_len]u8 = undefined;
        const header = try websocket.writeFrameHeaderInto(
            &header_storage,
            .binary,
            payload,
            .{ .mask_key = mask_key },
        );
        websocket.applyMask(payload, mask_key, 0);
        self.transport().writeAllParts(header, payload) catch |err| {
            self.abortAfterUnboundedMessageWriteLocked();
            return err;
        };
    }

    pub fn sendBinaryInPlaceWithTimeout(
        self: *Connection,
        payload: []u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendBinaryInPlaceWithDeadline(
            payload,
            progress,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn sendBinaryInPlaceWithDeadline(
        self: *Connection,
        payload: []u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(self.io, deadline);
        if (self.role != .client or self.permessage_deflate) {
            return error.InvalidFrame;
        }
        try common.validateOutgoingMessageLength(self.limits, payload.len);
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);
        _ = try deadline_policy.usableAwake(self.io, deadline);
        if (self.pending_ping != null or self.pending_close != null) {
            return error.WriteInProgress;
        }
        if (self.pending_message) |*pending| {
            if (!pending.matchesInPlace(payload)) {
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.totalLen(),
                };
                return error.WriteInProgress;
            }
        } else {
            if (self.pending_auto_control != null) {
                return error.WriteInProgress;
            }
            if (!self.canSendOpcodeLocked(.binary)) {
                return error.ConnectionClosed;
            }
            try self.beginPendingInPlaceLocked(payload);
        }
        try self.resumePendingInPlaceLocked(payload, progress, deadline);
    }

    fn beginPendingInPlaceLocked(
        self: *Connection,
        payload: []u8,
    ) Error!void {
        var pending = PendingMessage{
            .opcode = .binary,
            .source = .in_place,
            .original_ptr = @intFromPtr(payload.ptr),
            .original_len = payload.len,
            .payload_len = payload.len,
        };
        var key: [4]u8 = undefined;
        try std.Io.randomSecure(self.io, &key);
        pending.mask_key = key;
        const header = try websocket.writeFrameHeaderForLengthInto(
            &pending.header,
            .binary,
            payload.len,
            .{ .mask_key = key },
        );
        pending.header_len = header.len;
        websocket.applyMask(payload, key, 0);
        self.pending_message = pending;
        self.application_write_pending.store(true, .release);
    }

    fn resumePendingInPlaceLocked(
        self: *Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.receiveFailed()) return error.ConnectionClosed;
        const pending = &self.pending_message.?;
        while (pending.committed < pending.totalLen()) {
            const header_offset = @min(pending.committed, pending.header_len);
            const payload_offset = pending.committed - header_offset;
            const bytes = if (header_offset < pending.header_len)
                pending.header[header_offset..pending.header_len]
            else
                payload[payload_offset..];
            var committed: usize = 0;
            self.transport().writeWithDeadline(
                bytes,
                &committed,
                deadline,
            ) catch |err| {
                pending.committed += committed;
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.totalLen(),
                };
                return err;
            };
            pending.committed += committed;
        }
        progress.* = .{
            .committed_bytes = pending.committed,
            .total_bytes = pending.totalLen(),
            .frame_committed = true,
        };
        self.pending_message = null;
        self.application_write_pending.store(false, .release);
    }

    pub fn sendPing(self: *Connection, payload: []const u8) Error!void {
        try self.sendFrame(.ping, payload);
    }

    pub fn sendPingWithTimeout(
        self: *Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendPingWithDeadline(payload, progress, .fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn sendPingWithDeadline(
        self: *Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(self.io, deadline);
        try common.validateOutgoingControlFrame(self.limits, .ping, payload);
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);
        _ = try deadline_policy.usableAwake(self.io, deadline);
        if (self.pending_message != null or self.pending_close != null) {
            return error.WriteInProgress;
        }
        if (self.pending_ping == null) {
            if (self.pending_auto_control != null) {
                return error.WriteInProgress;
            }
            if (!self.canSendOpcodeLocked(.ping)) {
                return error.ConnectionClosed;
            }
            try self.beginPendingControlLocked(
                &self.pending_ping,
                .ping,
                payload,
            );
        }
        const total = self.pending_ping.?.len;
        self.resumePendingControlLocked(
            &self.pending_ping,
            payload,
            deadline,
        ) catch |err| {
            const pending = self.pending_ping.?;
            progress.* = .{
                .committed_bytes = pending.committed,
                .total_bytes = pending.len,
            };
            return err;
        };
        progress.* = .{
            .committed_bytes = total,
            .total_bytes = total,
            .frame_committed = true,
        };
    }

    pub fn sendPong(self: *Connection, payload: []const u8) Error!void {
        try self.sendFrame(.pong, payload);
    }

    pub fn sendPongWithTimeout(
        self: *Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendPongWithDeadline(payload, progress, .fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn sendPongWithDeadline(
        self: *Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(self.io, deadline);
        try common.validateOutgoingControlFrame(self.limits, .pong, payload);
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);
        _ = try deadline_policy.usableAwake(self.io, deadline);
        if (self.pending_ping != null or self.pending_close != null) {
            return error.WriteInProgress;
        }
        if (self.pending_message) |*pending| {
            if (!pending.matches(.pong, payload)) {
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.totalLen(),
                };
                return error.WriteInProgress;
            }
        } else {
            if (self.pending_auto_control != null) {
                return error.WriteInProgress;
            }
            if (!self.canSendOpcodeLocked(.pong)) {
                return error.ConnectionClosed;
            }
            try self.beginPendingPongLocked(payload);
        }
        try self.resumePendingMessageLocked(payload, progress, deadline);
    }

    /// Send Ping once and wait for the matching Pong under one deadline.
    /// Interleaved application frames are returned with ownership so callers
    /// can process them and resume through `continuePingWithDeadline`.
    pub fn pingWithTimeout(
        self: *Connection,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) Error!PingEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const deadline = std.Io.Clock.Timestamp.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        );
        return self.pingWithDeadline(payload, deadline);
    }

    pub fn pingWithDeadline(
        self: *Connection,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PingEvent {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        try common.validateOutgoingControlFrame(
            self.limits,
            .ping,
            payload,
        );
        if (self.automatic_write_pending.load(.acquire) and
            !self.application_write_pending.load(.acquire))
        {
            _ = try self.pendingAutomaticControlOpcode(.ping_wait);
            return self.readPingEvent(payload, deadline);
        }
        {
            self.send_mutex.lockUncancelable(self.io);
            defer self.send_mutex.unlock(self.io);
            _ = try deadline_policy.usableAwake(self.io, deadline);
            if (self.pending_message != null or
                self.pending_close != null)
            {
                return error.WriteInProgress;
            }
            if (self.pending_ping == null) {
                if (self.pending_auto_control != null) {
                    return error.WriteInProgress;
                }
                if (!self.canSendOpcodeLocked(.ping)) {
                    return error.ConnectionClosed;
                }
                try self.beginPendingControlLocked(
                    &self.pending_ping,
                    .ping,
                    payload,
                );
            }
            try self.resumePendingControlLocked(
                &self.pending_ping,
                payload,
                deadline,
            );
        }
        return self.readPingEvent(payload, deadline);
    }

    pub fn continuePingWithDeadline(
        self: *Connection,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PingEvent {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        if (self.automatic_write_pending.load(.acquire) and
            !self.application_write_pending.load(.acquire))
        {
            _ = try self.pendingAutomaticControlOpcode(.ping_wait);
            return self.readPingEvent(payload, deadline);
        }
        {
            self.send_mutex.lockUncancelable(self.io);
            defer self.send_mutex.unlock(self.io);
            try self.resumePendingControlLocked(
                &self.pending_ping,
                payload,
                deadline,
            );
        }
        return self.readPingEvent(payload, deadline);
    }

    /// Resume a Ping after the caller handles an interleaved application
    /// frame, deriving a fresh bounded wait without retransmitting Ping.
    pub fn continuePingWithTimeout(
        self: *Connection,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) Error!PingEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.continuePingWithDeadline(
            payload,
            .fromNow(
                self.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    fn readPingEvent(
        self: *Connection,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PingEvent {
        while (true) {
            var frame = try self.receiveFrameAutoInternal(
                deadline,
                .ping_wait,
            );
            switch (frame.header.opcode) {
                .ping => {
                    frame.deinit(self.allocator);
                    continue;
                },
                .pong => {
                    defer frame.deinit(self.allocator);
                    if (!std.mem.eql(u8, frame.payload, payload)) {
                        return error.UnexpectedPong;
                    }
                    return .{ .pong = {} };
                },
                .close => {
                    defer frame.deinit(self.allocator);
                    return .{ .closed = try websocket.parseClosePayloadOwned(
                        self.allocator,
                        frame.payload,
                    ) };
                },
                .text, .binary, .continuation => {
                    return .{ .application = frame };
                },
                else => {
                    frame.deinit(self.allocator);
                    return error.InvalidFrame;
                },
            }
        }
    }

    pub fn sendClose(self: *Connection, code: websocket.CloseCode, reason: []const u8) Error!void {
        try self.sendCloseFrame(.{ .code = code, .reason = reason });
    }

    pub fn sendCloseWithTimeout(
        self: *Connection,
        code: websocket.CloseCode,
        reason: []const u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        return self.sendCloseFrameWithTimeout(
            .{ .code = code, .reason = reason },
            progress,
            timeout,
        );
    }

    pub fn sendCloseWithDeadline(
        self: *Connection,
        code: websocket.CloseCode,
        reason: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        return self.sendCloseFrameWithDeadline(
            .{ .code = code, .reason = reason },
            progress,
            deadline,
        );
    }

    pub fn sendCloseFrameWithTimeout(
        self: *Connection,
        close_frame: ?websocket.CloseFrame,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendCloseFrameWithDeadline(
            close_frame,
            progress,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn sendCloseFrameWithDeadline(
        self: *Connection,
        close_frame: ?websocket.CloseFrame,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(self.io, deadline);
        var storage: [125]u8 = undefined;
        const payload = try websocket.writeClosePayloadInto(
            &storage,
            close_frame,
        );
        try common.validateOutgoingControlFrame(self.limits, .close, payload);
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);
        _ = try deadline_policy.usableAwake(self.io, deadline);
        if (self.receiveFailed() or self.writeAborted()) {
            return error.ConnectionClosed;
        }
        if (self.pending_message != null or self.pending_ping != null) {
            return error.WriteInProgress;
        }
        if (self.pending_close) |*pending| {
            if (!pending.matches(payload)) return error.WriteInProgress;
        } else {
            if (self.pending_auto_control != null) {
                return error.WriteInProgress;
            }
            if (!self.canSendOpcodeLocked(.close)) {
                return error.ConnectionClosed;
            }
            try self.beginPendingControlLocked(
                &self.pending_close,
                .close,
                payload,
            );
        }
        const total = self.pending_close.?.len;
        self.resumePendingCloseLocked(deadline) catch |err| {
            const pending = self.pending_close orelse {
                progress.* = .{
                    .committed_bytes = total,
                    .total_bytes = total,
                    .frame_committed = true,
                };
                return err;
            };
            progress.* = .{
                .committed_bytes = pending.committed,
                .total_bytes = pending.len,
            };
            return err;
        };
        progress.* = .{
            .committed_bytes = total,
            .total_bytes = total,
            .frame_committed = true,
        };
    }

    pub fn sendCloseFrame(self: *Connection, close_frame: ?websocket.CloseFrame) Error!void {
        var storage: [125]u8 = undefined;
        const payload = try websocket.writeClosePayloadInto(
            &storage,
            close_frame,
        );
        try self.sendFrame(.close, payload);
    }

    pub fn receiveCloseFrame(self: *Connection) Error!?websocket.OwnedCloseFrame {
        var frame = try self.receiveFrame();
        defer frame.deinit(self.allocator);
        if (frame.header.opcode != .close) return error.InvalidFrame;
        return websocket.parseClosePayloadOwned(self.allocator, frame.payload);
    }

    pub fn receiveCloseFrameWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!?websocket.OwnedCloseFrame {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveCloseFrameWithDeadline(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// Receive and parse one peer Close frame under an absolute deadline.
    /// Partial frame bytes remain buffered for a later receive. This strict
    /// typed helper rejects an intervening application or control frame.
    pub fn receiveCloseFrameWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!?websocket.OwnedCloseFrame {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        var frame = try self.receiveFrameWithDeadline(deadline);
        defer frame.deinit(self.allocator);
        if (frame.header.opcode != .close) return error.InvalidFrame;
        return websocket.parseClosePayloadOwned(self.allocator, frame.payload);
    }

    /// Relative-budget counterpart to `receiveFrameWithDeadline`. Partial
    /// frame bytes remain buffered so a later receive can resume exactly.
    pub fn receiveFrameWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!websocket.Frame {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameInternal(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// Receive one frame under a caller-owned absolute deadline. The same
    /// deadline covers partial headers, payload bytes, and TLS records.
    pub fn receiveFrameWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!websocket.Frame {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameInternal(deadline);
    }

    /// Send Close once and wait up to `timeout` for peer-close progress.
    ///
    /// Ping/Pong frames are consumed under one absolute deadline. An in-flight
    /// application frame is returned to the caller, who can process it and
    /// call this method again with a new bounded wait; it is never hidden or
    /// discarded.
    pub fn closeWithTimeout(
        self: *Connection,
        close_frame: ?websocket.CloseFrame,
        timeout: std.Io.Duration,
    ) Error!CloseHandshakeEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const deadline = std.Io.Clock.Timestamp.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        );
        return self.closeWithDeadline(close_frame, deadline);
    }

    /// Send Close once and advance the handshake under an absolute deadline.
    /// Reuse this entry point after `.application` to retain one total budget.
    pub fn closeWithDeadline(
        self: *Connection,
        close_frame: ?websocket.CloseFrame,
        deadline: std.Io.Clock.Timestamp,
    ) Error!CloseHandshakeEvent {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        if (self.receiveFailed() or self.writeAborted()) {
            return error.ConnectionClosed;
        }
        if (self.automatic_write_pending.load(.acquire) and
            !self.application_write_pending.load(.acquire))
        {
            _ = try self.pendingAutomaticControlOpcode(.close_wait);
            return self.readCloseHandshakeEvent(deadline);
        }
        {
            self.send_mutex.lockUncancelable(self.io);
            defer self.send_mutex.unlock(self.io);
            _ = try deadline_policy.usableAwake(self.io, deadline);
            if (self.receiveFailed() or self.writeAborted()) {
                return error.ConnectionClosed;
            }
            if (self.pending_message != null or
                self.pending_ping != null)
            {
                return error.WriteInProgress;
            }
            if (!self.closeSent()) {
                var storage: [125]u8 = undefined;
                const payload = try websocket.writeClosePayloadInto(
                    &storage,
                    close_frame,
                );
                try common.validateOutgoingControlFrame(
                    self.limits,
                    .close,
                    payload,
                );
                if (self.pending_close) |*pending| {
                    if (!pending.matches(payload)) {
                        return error.WriteInProgress;
                    }
                } else {
                    if (self.pending_auto_control != null) {
                        return error.WriteInProgress;
                    }
                    if (!self.canSendOpcodeLocked(.close)) {
                        return error.ConnectionClosed;
                    }
                    try self.beginPendingControlLocked(
                        &self.pending_close,
                        .close,
                        payload,
                    );
                }
            }
            try self.resumePendingCloseLocked(deadline);
        }
        return self.readCloseHandshakeEvent(deadline);
    }

    /// Continue a previously started close handshake under the caller's
    /// original deadline after handling an `.application` event.
    pub fn continueCloseWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!CloseHandshakeEvent {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        if (self.receiveFailed() or self.writeAborted()) {
            return error.ConnectionClosed;
        }
        if (self.automatic_write_pending.load(.acquire) and
            !self.application_write_pending.load(.acquire))
        {
            _ = try self.pendingAutomaticControlOpcode(.close_wait);
            return self.readCloseHandshakeEvent(deadline);
        }
        {
            self.send_mutex.lockUncancelable(self.io);
            defer self.send_mutex.unlock(self.io);
            if (self.receiveFailed() or self.writeAborted()) {
                return error.ConnectionClosed;
            }
            if (self.pending_message != null or
                self.pending_ping != null)
            {
                return error.WriteInProgress;
            }
            if (!self.closeSent() and self.pending_close == null) {
                return error.InvalidFrame;
            }
            try self.resumePendingCloseLocked(deadline);
        }
        return self.readCloseHandshakeEvent(deadline);
    }

    /// Resume an already-started Close handshake under a new relative wait.
    /// This never emits a second Close frame.
    pub fn continueCloseWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!CloseHandshakeEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.continueCloseWithDeadline(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    fn readCloseHandshakeEvent(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!CloseHandshakeEvent {
        while (true) {
            var frame = try self.receiveFrameAutoInternal(
                deadline,
                .close_wait,
            );
            switch (frame.header.opcode) {
                .ping, .pong => {
                    frame.deinit(self.allocator);
                    continue;
                },
                .close => {
                    defer frame.deinit(self.allocator);
                    return .{ .closed = try websocket.parseClosePayloadOwned(
                        self.allocator,
                        frame.payload,
                    ) };
                },
                .text, .binary, .continuation => {
                    return .{ .application = frame };
                },
                else => {
                    frame.deinit(self.allocator);
                    return error.InvalidFrame;
                },
            }
        }
    }

    pub fn sendFrame(self: *Connection, opcode: websocket.Opcode, payload: []const u8) Error!void {
        try common.validateOutgoingControlFrame(
            self.limits,
            opcode,
            payload,
        );
        if (!canSendOpcode(opcode, self.closeSent(), self.closeReceived())) {
            return error.ConnectionClosed;
        }
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);
        try self.sendFrameValidatedLocked(opcode, payload);
    }

    fn sendFrameValidatedLocked(
        self: *Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
    ) Error!void {
        if (self.pending_message != null or
            self.pending_ping != null or
            self.pending_close != null or
            self.pending_auto_control != null)
        {
            return error.WriteInProgress;
        }
        if (!self.canSendOpcodeLocked(opcode)) return error.ConnectionClosed;
        self.writeFrameLocked(opcode, payload, true) catch |err| {
            self.abortAfterUnboundedMessageWriteLocked();
            return err;
        };
        if (opcode == .close) self.close_sent.store(true, .release);
    }

    fn beginPendingControlLocked(
        self: *Connection,
        destination: *?PendingControlFrame,
        opcode: websocket.Opcode,
        payload: []const u8,
    ) Error!void {
        std.debug.assert(destination.* == null);
        var pending: PendingControlFrame = .{};
        @memcpy(pending.payload[0..payload.len], payload);
        pending.payload_len = payload.len;
        var mask_key: ?[4]u8 = null;
        if (self.role == .client) {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.io, &key);
            mask_key = key;
        }
        const encoded = try websocket.writeFrameInto(
            &pending.bytes,
            opcode,
            payload,
            .{ .mask_key = mask_key },
        );
        pending.len = encoded.len;
        destination.* = pending;
        self.application_write_pending.store(true, .release);
    }

    fn resumePendingControlLocked(
        self: *Connection,
        source: *?PendingControlFrame,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.receiveFailed()) return error.ConnectionClosed;
        const pending = if (source.*) |*value| value else return;
        if (!pending.matches(payload)) return error.WriteInProgress;
        var committed: usize = 0;
        self.transport().writeWithDeadline(
            pending.bytes[pending.committed..pending.len],
            &committed,
            deadline,
        ) catch |err| {
            pending.committed += committed;
            return err;
        };
        pending.committed += committed;
        std.debug.assert(pending.committed == pending.len);
        source.* = null;
        self.application_write_pending.store(false, .release);
    }

    fn resumePendingCloseLocked(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.writeAborted()) return error.ConnectionClosed;
        const pending = if (self.pending_close) |*value| value else return;
        var committed: usize = 0;
        self.transport().writeWithDeadline(
            pending.bytes[pending.committed..pending.len],
            &committed,
            deadline,
        ) catch |err| {
            pending.committed += committed;
            return err;
        };
        pending.committed += committed;
        std.debug.assert(pending.committed == pending.len);
        self.pending_close = null;
        self.application_write_pending.store(false, .release);
        self.close_sent.store(true, .release);
    }

    pub fn sendMessage(self: *Connection, opcode: websocket.Opcode, payload: []const u8) Error!void {
        if (opcode != .text and opcode != .binary) return error.InvalidFrame;
        if (!canSendOpcode(opcode, self.closeSent(), self.closeReceived())) {
            return error.ConnectionClosed;
        }
        try common.validateOutgoingMessage(self.limits, opcode, payload);
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);
        if (self.pending_message != null or
            self.pending_ping != null or
            self.pending_close != null or
            self.pending_auto_control != null)
        {
            return error.WriteInProgress;
        }
        if (!self.canSendOpcodeLocked(opcode)) return error.ConnectionClosed;

        if (self.permessage_deflate and
            payload.len >= self.compression_threshold)
        {
            const compressed = try self.compressMessageLocked(payload);
            if (compressed.len < payload.len) {
                self.writeFrameLockedExtended(
                    opcode,
                    compressed,
                    true,
                    .{ .rsv1 = true },
                ) catch |err| {
                    self.abortAfterUnboundedMessageWriteLocked();
                    return err;
                };
                self.commitCompressionPreviewLocked();
                return;
            }
            self.discardCompressionPreviewLocked();
        }
        self.writeFrameLocked(opcode, payload, true) catch |err| {
            self.abortAfterUnboundedMessageWriteLocked();
            return err;
        };
    }

    fn sendMessageWithDeadlineLocked(
        self: *Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);
        _ = try deadline_policy.usableAwake(self.io, deadline);
        if (self.pending_ping != null or self.pending_close != null) {
            return error.WriteInProgress;
        }

        if (self.pending_message) |*pending| {
            if (!pending.matches(opcode, payload)) {
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.totalLen(),
                };
                return error.WriteInProgress;
            }
        } else {
            if (self.pending_auto_control != null) {
                return error.WriteInProgress;
            }
            if (!self.canSendOpcodeLocked(opcode)) {
                return error.ConnectionClosed;
            }
            try self.beginPendingMessageLocked(opcode, payload);
        }
        try self.resumePendingMessageLocked(payload, progress, deadline);
    }

    fn beginPendingMessageLocked(
        self: *Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
    ) Error!void {
        std.debug.assert(self.pending_message == null);
        var pending = PendingMessage{
            .opcode = opcode,
            .original_ptr = @intFromPtr(payload.ptr),
            .original_len = payload.len,
        };
        var encoded_payload = payload;
        errdefer self.discardCompressionPreviewLocked();
        if (self.permessage_deflate and
            payload.len >= self.compression_threshold)
        {
            const compressed = try self.compressMessageLocked(payload);
            if (compressed.len < payload.len) {
                encoded_payload = compressed;
                pending.compressed = true;
            } else {
                self.discardCompressionPreviewLocked();
            }
        }
        if (self.role == .client) {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.io, &key);
            pending.mask_key = key;
        }
        const header = try websocket.writeFrameHeaderForLengthInto(
            &pending.header,
            opcode,
            encoded_payload.len,
            .{
                .mask_key = pending.mask_key,
                .rsv1 = pending.compressed,
            },
        );
        pending.header_len = header.len;
        pending.payload_len = encoded_payload.len;
        self.pending_message = pending;
        self.application_write_pending.store(true, .release);
    }

    fn beginPendingPongLocked(
        self: *Connection,
        payload: []const u8,
    ) Error!void {
        std.debug.assert(self.pending_message == null);
        var pending = PendingMessage{
            .opcode = .pong,
            .original_ptr = @intFromPtr(payload.ptr),
            .original_len = payload.len,
            .payload_len = payload.len,
        };
        if (self.role == .client) {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.io, &key);
            pending.mask_key = key;
        }
        const header = try websocket.writeFrameHeaderForLengthInto(
            &pending.header,
            .pong,
            payload.len,
            .{ .mask_key = pending.mask_key },
        );
        pending.header_len = header.len;
        self.pending_message = pending;
        self.application_write_pending.store(true, .release);
    }

    fn beginPendingMessagePartsLocked(
        self: *Connection,
        parts: []const []const u8,
        payload_len: usize,
    ) Error!void {
        std.debug.assert(self.pending_message == null);
        var pending = PendingMessage{
            .opcode = .binary,
            .source = .slices,
            .original_ptr = @intFromPtr(parts.ptr),
            .original_len = parts.len,
        };
        var encoded_len = payload_len;
        errdefer self.discardCompressionPreviewLocked();
        if (self.permessage_deflate and
            payload_len >= self.compression_threshold)
        {
            const compressed = try self.compressMessagePartsLocked(
                parts,
                payload_len,
            );
            if (compressed.len < payload_len) {
                encoded_len = compressed.len;
                pending.compressed = true;
            } else {
                self.discardCompressionPreviewLocked();
            }
        }
        if (self.role == .client) {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.io, &key);
            pending.mask_key = key;
        }
        const header = try websocket.writeFrameHeaderForLengthInto(
            &pending.header,
            .binary,
            encoded_len,
            .{
                .mask_key = pending.mask_key,
                .rsv1 = pending.compressed,
            },
        );
        pending.header_len = header.len;
        pending.payload_len = encoded_len;
        self.pending_message = pending;
        self.application_write_pending.store(true, .release);
    }

    fn pendingPayload(
        self: *Connection,
        original_payload: []const u8,
    ) []const u8 {
        const pending = &self.pending_message.?;
        return if (pending.compressed)
            self.compression_send.payload.items[0..pending.payload_len]
        else
            original_payload;
    }

    fn fillPendingMessageChunk(
        self: *Connection,
        original_payload: []const u8,
        out: []u8,
    ) Error![]const u8 {
        const pending = &self.pending_message.?;
        const encoded_payload = self.pendingPayload(original_payload);
        const header_offset = @min(
            pending.committed,
            pending.header_len,
        );
        const payload_offset = pending.committed - header_offset;
        var out_len: usize = 0;
        if (header_offset < pending.header_len) {
            const header = pending.header[header_offset..pending.header_len];
            @memcpy(out[0..header.len], header);
            out_len = header.len;
        }
        const count = @min(
            out.len - out_len,
            encoded_payload.len - payload_offset,
        );
        if (pending.mask_key) |mask| {
            try websocket.applyMaskCopy(
                out[out_len..][0..count],
                encoded_payload[payload_offset..][0..count],
                mask,
                payload_offset,
            );
        } else {
            @memcpy(
                out[out_len..][0..count],
                encoded_payload[payload_offset..][0..count],
            );
        }
        out_len += count;
        return out[0..out_len];
    }

    fn resumePendingMessageLocked(
        self: *Connection,
        original_payload: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.receiveFailed()) return error.ConnectionClosed;
        const pending = &self.pending_message.?;
        var scratch: [masked_write_scratch_len]u8 align(64) = undefined;

        while (pending.committed < pending.totalLen()) {
            const wire_bytes = try self.fillPendingMessageChunk(
                original_payload,
                &scratch,
            );

            var transport_committed: usize = 0;
            self.transport().writeWithDeadline(
                wire_bytes,
                &transport_committed,
                deadline,
            ) catch |err| {
                pending.committed += transport_committed;
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.totalLen(),
                };
                return err;
            };
            pending.committed += transport_committed;
        }

        progress.* = .{
            .committed_bytes = pending.committed,
            .total_bytes = pending.totalLen(),
            .frame_committed = true,
        };
        if (pending.compressed) self.commitCompressionPreviewLocked();
        self.pending_message = null;
        self.application_write_pending.store(false, .release);
    }

    fn resumePendingMessagePartsLocked(
        self: *Connection,
        parts: []const []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.receiveFailed()) return error.ConnectionClosed;
        const pending = &self.pending_message.?;
        var scratch: [masked_write_scratch_len + websocket.max_frame_header_len]u8 align(64) = undefined;

        while (pending.committed < pending.totalLen()) {
            const header_offset = @min(
                pending.committed,
                pending.header_len,
            );
            const payload_offset = pending.committed - header_offset;
            var wire_len: usize = 0;
            if (header_offset < pending.header_len) {
                const header = pending.header[header_offset..pending.header_len];
                @memcpy(scratch[0..header.len], header);
                wire_len = header.len;
            }
            const payload_capacity = @min(
                scratch.len - wire_len,
                pending.payload_len - payload_offset,
            );
            if (payload_capacity != 0) {
                const destination = scratch[wire_len..][0..payload_capacity];
                if (pending.compressed) {
                    const source = self.compression_send.payload.items[payload_offset..][0..payload_capacity];
                    if (pending.mask_key) |mask| {
                        try websocket.applyMaskCopy(
                            destination,
                            source,
                            mask,
                            payload_offset,
                        );
                    } else {
                        @memcpy(destination, source);
                    }
                } else {
                    try copyMessagePartsAt(
                        destination,
                        parts,
                        payload_offset,
                        pending.mask_key,
                    );
                }
                wire_len += payload_capacity;
            }

            var transport_committed: usize = 0;
            self.transport().writeWithDeadline(
                scratch[0..wire_len],
                &transport_committed,
                deadline,
            ) catch |err| {
                pending.committed += transport_committed;
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.totalLen(),
                };
                return err;
            };
            pending.committed += transport_committed;
        }

        progress.* = .{
            .committed_bytes = pending.committed,
            .total_bytes = pending.totalLen(),
            .frame_committed = true,
        };
        if (pending.compressed) self.commitCompressionPreviewLocked();
        self.pending_message = null;
        self.application_write_pending.store(false, .release);
    }

    pub fn sendFragmented(self: *Connection, opcode: websocket.Opcode, fragments: []const []const u8) Error!void {
        if (!canSendOpcode(opcode, self.closeSent(), self.closeReceived())) {
            return error.ConnectionClosed;
        }
        const plain_len = try common.validateOutgoingFragments(
            self.limits,
            opcode,
            fragments,
        );

        if (self.permessage_deflate) {
            self.send_mutex.lockUncancelable(self.io);
            defer self.send_mutex.unlock(self.io);
            if (self.pending_message != null or
                self.pending_ping != null or
                self.pending_close != null or
                self.pending_auto_control != null)
            {
                return error.WriteInProgress;
            }
            if (!self.canSendOpcodeLocked(opcode)) return error.ConnectionClosed;
            if (plain_len >= self.compression_threshold) {
                const compressed = try self.compressMessagePartsLocked(
                    fragments,
                    plain_len,
                );
                if (compressed.len < plain_len) {
                    self.writeCompressedFragmentsLocked(
                        opcode,
                        compressed,
                        fragments.len,
                    ) catch |err| {
                        self.abortAfterUnboundedMessageWriteLocked();
                        return err;
                    };
                    self.commitCompressionPreviewLocked();
                    return;
                }
                self.discardCompressionPreviewLocked();
            }
            for (fragments, 0..) |fragment, index| {
                const frame_opcode: websocket.Opcode =
                    if (index == 0) opcode else .continuation;
                self.writeFrameLocked(
                    frame_opcode,
                    fragment,
                    index + 1 == fragments.len,
                ) catch |err| {
                    self.abortAfterUnboundedMessageWriteLocked();
                    return err;
                };
            }
            return;
        }

        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);
        if (self.pending_message != null or
            self.pending_ping != null or
            self.pending_close != null or
            self.pending_auto_control != null)
        {
            return error.WriteInProgress;
        }
        if (!self.canSendOpcodeLocked(opcode)) return error.ConnectionClosed;

        for (fragments, 0..) |fragment, index| {
            const frame_opcode: websocket.Opcode =
                if (index == 0) opcode else .continuation;
            self.writeFrameLocked(
                frame_opcode,
                fragment,
                index + 1 == fragments.len,
            ) catch |err| {
                self.abortAfterUnboundedMessageWriteLocked();
                return err;
            };
        }
    }

    pub fn sendFragmentedWithTimeout(
        self: *Connection,
        opcode: websocket.Opcode,
        fragments: []const []const u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendFragmentedWithDeadline(
            opcode,
            fragments,
            progress,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn sendFragmentedWithDeadline(
        self: *Connection,
        opcode: websocket.Opcode,
        fragments: []const []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(self.io, deadline);
        const plain_len = try common.validateOutgoingFragments(
            self.limits,
            opcode,
            fragments,
        );
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);
        _ = try deadline_policy.usableAwake(self.io, deadline);
        if (self.pending_ping != null or self.pending_close != null) {
            return error.WriteInProgress;
        }
        if (self.pending_message) |*pending| {
            if (!pending.matchesFragments(opcode, fragments)) {
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.totalLen(),
                };
                return error.WriteInProgress;
            }
        } else {
            if (self.pending_auto_control != null) {
                return error.WriteInProgress;
            }
            if (!self.canSendOpcodeLocked(opcode)) {
                return error.ConnectionClosed;
            }
            try self.beginPendingFragmentedLocked(
                opcode,
                fragments,
                plain_len,
            );
        }
        try self.resumePendingFragmentedLocked(
            fragments,
            progress,
            deadline,
        );
    }

    fn beginPendingFragmentedLocked(
        self: *Connection,
        opcode: websocket.Opcode,
        fragments: []const []const u8,
        plain_len: usize,
    ) Error!void {
        std.debug.assert(self.pending_message == null);
        var pending = PendingMessage{
            .opcode = opcode,
            .source = .fragmented,
            .original_ptr = @intFromPtr(fragments.ptr),
            .original_len = fragments.len,
        };
        errdefer self.discardCompressionPreviewLocked();
        if (self.permessage_deflate and
            plain_len >= self.compression_threshold)
        {
            const compressed = try self.compressMessagePartsLocked(
                fragments,
                plain_len,
            );
            pending.compressed = compressed.len < plain_len;
            if (pending.compressed) {
                pending.fragmented_payload_total = compressed.len;
            } else {
                self.discardCompressionPreviewLocked();
            }
        }
        pending.wire_total = try fragmentedWireLen(
            fragments,
            if (pending.compressed) pending.fragmented_payload_total else null,
            self.role == .client,
        );
        self.pending_message = pending;
        self.application_write_pending.store(true, .release);
        errdefer {
            self.pending_message = null;
            self.application_write_pending.store(false, .release);
        }
        try self.preparePendingFragmentLocked(fragments, 0);
    }

    fn preparePendingFragmentLocked(
        self: *Connection,
        fragments: []const []const u8,
        index: usize,
    ) Error!void {
        const pending = &self.pending_message.?;
        std.debug.assert(pending.source == .fragmented);
        const range: message_state.FragmentRange = if (pending.compressed)
            compressedFragmentRange(
                pending.fragmented_payload_total,
                fragments.len,
                index,
            )
        else
            .{ .start = 0, .end = fragments[index].len };
        const mask_key: ?[4]u8 = if (self.role == .client) blk: {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.io, &key);
            break :blk key;
        } else null;
        var header_storage: [websocket.max_frame_header_len]u8 = undefined;
        const header = try websocket.writeFrameHeaderForLengthInto(
            &header_storage,
            if (index == 0) pending.opcode else .continuation,
            range.end - range.start,
            .{
                .fin = index + 1 == fragments.len,
                .mask_key = mask_key,
                .rsv1 = pending.compressed and index == 0,
            },
        );
        @memcpy(pending.header[0..header.len], header);
        pending.fragment_index = index;
        pending.payload_len = range.end - range.start;
        pending.fragment_start = pending.committed;
        pending.mask_key = mask_key;
        pending.header_len = header.len;
    }

    fn resumePendingFragmentedLocked(
        self: *Connection,
        fragments: []const []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.receiveFailed()) return error.ConnectionClosed;
        var scratch: [masked_write_scratch_len]u8 = undefined;
        while (self.pending_message) |*pending| {
            const frame_committed = pending.committed - pending.fragment_start;
            const header_offset = @min(frame_committed, pending.header_len);
            const payload_offset = frame_committed - header_offset;
            var len: usize = 0;
            if (header_offset < pending.header_len) {
                const header = pending.header[header_offset..pending.header_len];
                @memcpy(scratch[0..header.len], header);
                len = header.len;
            }
            const payload = if (pending.compressed) blk: {
                const range = compressedFragmentRange(
                    self.compression_send.payload.items.len,
                    fragments.len,
                    pending.fragment_index,
                );
                break :blk self.compression_send.payload.items[range.start..range.end];
            } else fragments[pending.fragment_index];
            const count = @min(scratch.len - len, payload.len - payload_offset);
            if (pending.mask_key) |mask| {
                try websocket.applyMaskCopy(
                    scratch[len..][0..count],
                    payload[payload_offset..][0..count],
                    mask,
                    payload_offset,
                );
            } else {
                @memcpy(
                    scratch[len..][0..count],
                    payload[payload_offset..][0..count],
                );
            }
            len += count;
            var committed: usize = 0;
            self.transport().writeWithDeadline(
                scratch[0..len],
                &committed,
                deadline,
            ) catch |err| {
                pending.committed += committed;
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.wire_total,
                };
                return err;
            };
            pending.committed += committed;
            if (pending.committed - pending.fragment_start ==
                pending.header_len + pending.payload_len)
            {
                const next_index = pending.fragment_index + 1;
                if (next_index == fragments.len) {
                    progress.* = .{
                        .committed_bytes = pending.committed,
                        .total_bytes = pending.wire_total,
                        .frame_committed = true,
                    };
                    if (pending.compressed) {
                        self.commitCompressionPreviewLocked();
                    }
                    self.pending_message = null;
                    self.application_write_pending.store(false, .release);
                    return;
                }
                try self.preparePendingFragmentLocked(
                    fragments,
                    next_index,
                );
            }
        }
    }

    pub fn receiveFrame(self: *Connection) Error!websocket.Frame {
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameInternal(null);
    }

    fn receiveFrameInternal(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!websocket.Frame {
        if (self.receiveFailed()) return error.ConnectionClosed;
        try self.ensureNoPendingWrites();
        errdefer |err| closeAfterReceiveError(self, err, deadline);
        if (self.closeSent() and self.closeReceived()) return error.ConnectionClosed;
        try self.ensureBufferedWithDeadline(2, deadline);
        var available = message_buffer.unread(
            &self.inbuf,
            self.inbuf_consumed,
        );
        const second = available[1];
        var header_len: usize = 2;
        const len_code = second & 0x7f;
        if (len_code == 126) header_len += 2 else if (len_code == 127) header_len += 8;
        if ((second & 0x80) != 0) header_len += 4;
        try self.ensureBufferedWithDeadline(header_len, deadline);
        available = message_buffer.unread(
            &self.inbuf,
            self.inbuf_consumed,
        );
        const header = try websocket.FrameHeader.parse(available);
        const payload_len = std.math.cast(usize, header.payload_len) orelse return error.PayloadTooLarge;
        if (payload_len > self.limits.max_frame_bytes) return error.MessageTooLarge;
        const total_len = header.header_len + payload_len;
        try ensureIncomingFrameBuffered(self, header, total_len, deadline);
        available = message_buffer.unread(
            &self.inbuf,
            self.inbuf_consumed,
        );

        const parse_options: websocket.ParseFrameOptions = switch (self.role) {
            .client => .{
                .expect_mask = .unmasked,
                .allow_rsv1 = self.permessage_deflate,
                .validate_utf8 = false,
            },
            .server => .{
                .expect_mask = .masked,
                .allow_rsv1 = self.permessage_deflate,
                .validate_utf8 = false,
            },
        };
        var frame = try websocket.parseFrameWithHeader(
            self.allocator,
            available[0..total_len],
            header,
            parse_options,
        );
        errdefer frame.deinit(self.allocator);
        self.discardBuffered(frame.consumed);
        if (self.closeReceived() and frame.header.opcode != .close) {
            return error.ConnectionClosed;
        }
        if (self.compression_receive_context_takeover and
            !frame.header.opcode.isControl())
        {
            self.compression_receive.observeFrame(
                self.allocator,
                frame.header.opcode != .continuation,
                frame.header.rsv1,
                frame.header.opcode == .text,
                frame.header.fin,
                frame.payload,
                self.limits.max_message_bytes,
                self.compression_receive_max_window_bits,
            ) catch |err| switch (err) {
                error.PreviewPending => return error.InvalidFrame,
                error.OutOfMemory => {
                    _ = failReceive(self);
                    return error.OutOfMemory;
                },
                else => |other| return @errorCast(other),
            };
        }
        if (frame.header.opcode == .close) self.close_received.store(true, .release);
        return frame;
    }

    pub fn receiveFrameAuto(self: *Connection) Error!websocket.Frame {
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameAutoInternal(null, .frame);
    }

    pub fn receiveFrameAutoWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!websocket.Frame {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameAutoInternal(
            .fromNow(
                self.io,
                .{ .raw = timeout, .clock = .awake },
            ),
            .frame,
        );
    }

    pub fn receiveFrameAutoWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!websocket.Frame {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameAutoInternal(deadline, .frame);
    }

    fn receiveFrameAutoInternal(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
        delivery: PendingAutomaticControl.Delivery,
    ) Error!websocket.Frame {
        if (try self.pendingAutomaticControlOpcode(delivery)) |_| {
            if (try self.resumeAutomaticControl(deadline)) |frame| {
                return frame;
            }
            return self.receiveFrameAutoInternal(deadline, delivery);
        }
        while (true) {
            var frame = try self.receiveFrameInternal(deadline);
            switch (frame.header.opcode) {
                .ping => {
                    // tungstenite queues automatic Pong replies only while the
                    // connection is still active.  After we have sent Close,
                    // the peer may still deliver in-flight control frames, but
                    // replying with a fresh Pong would write after our close
                    // handshake started.
                    if (!canSendOpcode(
                        .pong,
                        self.closeSent(),
                        self.closeReceived(),
                    )) return frame;
                    self.beginAutomaticControl(
                        .pong,
                        frame.payload,
                        delivery,
                        frame,
                    ) catch |err| {
                        frame.deinit(self.allocator);
                        return err;
                    };
                    return (try self.resumeAutomaticControl(deadline)) orelse
                        unreachable;
                },
                .close => {
                    if (self.closeSent()) return frame;
                    self.beginAutomaticControl(
                        .close,
                        frame.payload,
                        delivery,
                        frame,
                    ) catch |err| {
                        frame.deinit(self.allocator);
                        return err;
                    };
                    return (try self.resumeAutomaticControl(deadline)) orelse
                        unreachable;
                },
                else => return frame,
            }
        }
    }

    pub fn receiveMessage(self: *Connection) Error!OwnedMessage {
        return self.receiveMessageInternal(null);
    }

    /// Receive one complete message within one relative application budget.
    pub fn receiveMessageWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!OwnedMessage {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveMessageInternal(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// Receive one complete message under a caller-owned absolute deadline.
    ///
    /// The deadline is deliberately unchanged across continuation and control
    /// frames. Protocols such as MQTT can therefore enforce one packet-level
    /// inactivity budget without WebSocket Ping/Pong traffic extending it.
    pub fn receiveMessageWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedMessage {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.receiveMessageInternal(deadline);
    }

    fn receiveMessageInternal(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!OwnedMessage {
        if (self.receiveFailed()) return error.ConnectionClosed;
        if (self.message_into.active()) return error.InvalidFrame;
        if (try self.pendingAutomaticControlOpcode(.message)) |opcode| {
            std.debug.assert((try self.resumeAutomaticControl(deadline)) == null);
            if (opcode == .close) return error.ConnectionClosed;
        }
        try self.ensureNoPendingWrites();
        errdefer |err| closeAfterReceiveError(self, err, deadline);
        if (self.message_assembler == null) {
            self.message_assembler = websocket.MessageAssembler.initLimited(
                self.allocator,
                self.limits.max_message_bytes,
            );
        }

        while (true) {
            const frame = try receiveMessageFrameBorrowed(self, deadline);
            switch (frame.header.opcode) {
                .ping => {
                    if (canSendOpcode(
                        .pong,
                        self.closeSent(),
                        self.closeReceived(),
                    )) {
                        try self.beginAutomaticControl(
                            .pong,
                            frame.payload,
                            .message,
                            null,
                        );
                    }
                    self.discardBuffered(frame.consumed);
                    if (self.pending_auto_control != null) {
                        std.debug.assert(
                            (try self.resumeAutomaticControl(deadline)) == null,
                        );
                    }
                    continue;
                },
                .pong => {
                    self.discardBuffered(frame.consumed);
                    continue;
                },
                .close => {
                    self.close_received.store(true, .release);
                    self.message_assembler.?.deinit();
                    self.message_assembler = null;
                    if (!self.closeSent()) {
                        try self.beginAutomaticControl(
                            .close,
                            frame.payload,
                            .message,
                            null,
                        );
                    }
                    self.discardBuffered(frame.consumed);
                    if (self.pending_auto_control != null) {
                        std.debug.assert(
                            (try self.resumeAutomaticControl(deadline)) == null,
                        );
                    }
                    return error.ConnectionClosed;
                },
                else => {
                    const maybe_message = self.message_assembler.?.feedUtf8Validated(
                        frame,
                        self.incoming_text_utf8,
                    ) catch |err| {
                        self.discardBuffered(frame.consumed);
                        self.message_assembler.?.deinit();
                        self.message_assembler = null;
                        return @errorCast(err);
                    };
                    self.discardBuffered(frame.consumed);
                    if (maybe_message) |message| {
                        self.message_assembler.?.deinit();
                        self.message_assembler = null;
                        return finishIncomingMessageForConnection(
                            self,
                            message,
                        );
                    }
                },
            }
        }
    }

    /// Receive one complete message into caller-owned storage.
    ///
    /// `out` must be at least `limits.max_message_bytes`; this lets the method
    /// consume arbitrarily fragmented messages transactionally without finding
    /// a later fragment that no longer fits after earlier frames were removed
    /// from the transport buffer. Control frames retain the same automatic
    /// Pong/Close behavior as `receiveMessage`. Negotiated compressed messages
    /// use reusable connection scratch and inflate directly into `out`.
    pub fn receiveMessageInto(
        self: *Connection,
        out: []u8,
    ) Error!Message {
        return receiveMessageIntoDirectConnection(self, out, null);
    }

    pub fn receiveMessageIntoWithTimeout(
        self: *Connection,
        out: []u8,
        timeout: std.Io.Duration,
    ) Error!Message {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return receiveMessageIntoDirectConnection(
            self,
            out,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Caller-buffer counterpart to `receiveMessageWithDeadline`. The same
    /// absolute deadline spans every fragment, TLS read, and interleaved
    /// control frame while preserving the allocation-avoiding receive path.
    pub fn receiveMessageIntoWithDeadline(
        self: *Connection,
        out: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Message {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return receiveMessageIntoDirectConnection(self, out, deadline);
    }

    fn ensureCompressionReceiveScratch(self: *Connection) Error!void {
        if (self.compression_receive_context_takeover) {
            try self.compression_receive.prepareContext(
                self.allocator,
                self.limits.max_message_bytes,
            );
        } else {
            try self.compression_receive.prepare(
                self.allocator,
                self.limits.max_message_bytes,
            );
        }
    }

    fn compressMessageLocked(
        self: *Connection,
        payload: []const u8,
    ) Error![]const u8 {
        if (self.compression_send_context_takeover) {
            return self.compression_send.preview(
                self.allocator,
                payload,
                self.compression_send_max_window_bits,
            ) catch |err| switch (err) {
                error.PreviewPending => error.WriteInProgress,
                else => |other| @errorCast(other),
            };
        }
        try self.compression_send.prepare(
            self.allocator,
            payload.len,
        );
        return websocket.compressMessageVortIntoWindowWithEncoder(
            &self.compression_send.encoder.?,
            &self.compression_send.payload,
            payload,
            self.compression_send_max_window_bits,
        );
    }

    fn compressMessagePartsLocked(
        self: *Connection,
        parts: []const []const u8,
        payload_len: usize,
    ) Error![]const u8 {
        if (self.compression_send_context_takeover) {
            return self.compression_send.previewFragments(
                self.allocator,
                parts,
                payload_len,
                self.compression_send_max_window_bits,
            ) catch |err| switch (err) {
                error.PreviewPending => error.WriteInProgress,
                else => |other| @errorCast(other),
            };
        }
        try self.compression_send.prepare(
            self.allocator,
            payload_len,
        );
        return websocket.compressMessageFragmentsVortIntoWindowWithEncoder(
            &self.compression_send.encoder.?,
            &self.compression_send.payload,
            parts,
            self.compression_send_max_window_bits,
        );
    }

    fn commitCompressionPreviewLocked(self: *Connection) void {
        if (self.compression_send_context_takeover) {
            self.compression_send.commitPreview() catch unreachable;
        }
    }

    fn discardCompressionPreviewLocked(self: *Connection) void {
        if (self.compression_send_context_takeover) {
            self.compression_send.discardPreview();
        }
    }

    fn abortAfterUnboundedMessageWriteLocked(self: *Connection) void {
        self.discardCompressionPreviewLocked();
        self.write_aborted.store(true, .release);
        transportStream(self.transport()).shutdown(self.io, .both) catch {};
        common.clearPendingOutboundLocked(self);
    }

    fn writeFrameLocked(self: *Connection, opcode: websocket.Opcode, payload: []const u8, fin: bool) Error!void {
        try self.writeFrameLockedExtended(opcode, payload, fin, .{});
    }

    fn writeFrameLockedExtended(
        self: *Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
        fin: bool,
        options: struct { rsv1: bool = false },
    ) Error!void {
        const mask_key = if (self.role == .client) blk: {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.io, &key);
            break :blk key;
        } else null;

        var header_storage: [websocket.max_frame_header_len]u8 = undefined;
        const header = try websocket.writeFrameHeaderInto(
            &header_storage,
            opcode,
            payload,
            .{
                .fin = fin,
                .mask_key = mask_key,
                .rsv1 = options.rsv1,
            },
        );
        if (mask_key) |mask| {
            try writeMaskedPayload(
                self.transport(),
                header,
                payload,
                mask,
            );
        } else {
            try self.transport().writeAllParts(header, payload);
        }
    }

    fn writeCompressedFragmentsLocked(
        self: *Connection,
        opcode: websocket.Opcode,
        compressed_payload: []const u8,
        frame_count: usize,
    ) Error!void {
        if (self.role == .client and
            try self.writeMaskedCompressedFragmentsBatchLocked(
                opcode,
                compressed_payload,
                frame_count,
            ))
        {
            return;
        }
        if (self.role == .server) {
            try self.writeUnmaskedCompressedFragmentsLocked(
                opcode,
                compressed_payload,
                frame_count,
            );
            return;
        }
        for (0..frame_count) |index| {
            const range = compressedFragmentRange(compressed_payload.len, frame_count, index);
            try self.writeFrameLockedExtended(
                if (index == 0) opcode else .continuation,
                compressed_payload[range.start..range.end],
                index + 1 == frame_count,
                .{ .rsv1 = index == 0 },
            );
        }
    }

    fn writeMaskedCompressedFragmentsBatchLocked(
        self: *Connection,
        opcode: websocket.Opcode,
        compressed_payload: []const u8,
        frame_count: usize,
    ) Error!bool {
        const header_bound = std.math.mul(
            usize,
            frame_count,
            websocket.max_frame_header_len,
        ) catch return false;
        const required = std.math.add(
            usize,
            header_bound,
            compressed_payload.len,
        ) catch return false;
        if (required > masked_write_scratch_len) return false;

        // Mask each frame with its own RFC 6455 key, but stage the small
        // compressed message in the same bounded scratch already used by the
        // ordinary client masking path. One transport write then preserves all
        // frame boundaries without sixteen loopback syscalls for a 16-slice
        // application message. Larger messages retain the streaming fallback.
        var encoded: [masked_write_scratch_len]u8 align(64) = undefined;
        const max_mask_key_batch: usize = 16;
        var mask_keys: [max_mask_key_batch][4]u8 = undefined;
        var cursor: usize = 0;
        for (0..frame_count) |index| {
            const range = compressedFragmentRange(
                compressed_payload.len,
                frame_count,
                index,
            );
            const payload = compressed_payload[range.start..range.end];
            const mask_key_index = index % max_mask_key_batch;
            if (mask_key_index == 0) {
                const key_count = @min(
                    max_mask_key_batch,
                    frame_count - index,
                );
                try common.randomMaskKeys(
                    self.io,
                    mask_keys[0..key_count],
                );
            }
            const mask_key = mask_keys[mask_key_index];
            var header_storage: [websocket.max_frame_header_len]u8 = undefined;
            const header = try websocket.writeFrameHeaderInto(
                &header_storage,
                if (index == 0) opcode else .continuation,
                payload,
                .{
                    .fin = index + 1 == frame_count,
                    .mask_key = mask_key,
                    .rsv1 = index == 0,
                },
            );
            @memcpy(encoded[cursor..][0..header.len], header);
            cursor += header.len;
            try websocket.applyMaskCopy(
                encoded[cursor..][0..payload.len],
                payload,
                mask_key,
                0,
            );
            cursor += payload.len;
        }
        try self.transport().writeAll(encoded[0..cursor]);
        return true;
    }

    fn writeUnmaskedCompressedFragmentsLocked(
        self: *Connection,
        opcode: websocket.Opcode,
        compressed_payload: []const u8,
        frame_count: usize,
    ) Error!void {
        // One logical message can contain many intentionally tiny compressed
        // continuation frames. Batch their stack headers and borrowed payload
        // ranges so TCP/std-TLS perform bounded writes/flushes instead of one
        // per frame. Larger frame counts fall back to the ordinary loop below.
        const max_batched_frames: usize = 16;
        if (frame_count > max_batched_frames) {
            for (0..frame_count) |index| {
                const range = compressedFragmentRange(
                    compressed_payload.len,
                    frame_count,
                    index,
                );
                try self.writeFrameLockedExtended(
                    if (index == 0) opcode else .continuation,
                    compressed_payload[range.start..range.end],
                    index + 1 == frame_count,
                    .{ .rsv1 = index == 0 },
                );
            }
            return;
        }

        var headers: [max_batched_frames][websocket.max_frame_header_len]u8 = undefined;
        var parts: [max_batched_frames * 2][]const u8 = undefined;
        for (0..frame_count) |index| {
            const range = compressedFragmentRange(
                compressed_payload.len,
                frame_count,
                index,
            );
            const payload = compressed_payload[range.start..range.end];
            parts[index * 2] = try websocket.writeFrameHeaderInto(
                &headers[index],
                if (index == 0) opcode else .continuation,
                payload,
                .{
                    .fin = index + 1 == frame_count,
                    .rsv1 = index == 0,
                },
            );
            parts[index * 2 + 1] = payload;
        }
        try self.transport().writeAllSlices(parts[0 .. frame_count * 2]);
    }

    fn ensureBuffered(self: *Connection, len: usize) Error!void {
        return self.ensureBufferedWithDeadline(len, null);
    }

    /// Fill exactly the requested prefix without reading payload bytes that a
    /// caller-buffer receive can place directly in its final destination.
    fn ensureBufferedExactWithDeadline(
        self: *Connection,
        len: usize,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        while (message_buffer.unreadLen(
            &self.inbuf,
            self.inbuf_consumed,
        ) < len) {
            const missing = len - message_buffer.unreadLen(
                &self.inbuf,
                self.inbuf_consumed,
            );
            const destination = try message_buffer.reserveAppendAfterConsumed(
                &self.inbuf,
                &self.inbuf_consumed,
                self.allocator,
                missing,
            );
            const count = if (deadline) |absolute|
                try self.transport().readWithDeadline(destination, absolute)
            else
                try self.transport().read(destination);
            if (count == 0) return error.ConnectionClosed;
            message_buffer.commitAppend(&self.inbuf, count);
        }
    }

    fn readMessagePayloadChunk(
        self: *Connection,
        out: []u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!usize {
        if (deadline) |absolute| {
            return self.transport().readWithDeadline(out, absolute);
        }
        return self.transport().read(out);
    }

    fn ensureBufferedWithDeadline(
        self: *Connection,
        len: usize,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        var scratch: [transport_read_scratch_len]u8 = undefined;
        while (message_buffer.unreadLen(
            &self.inbuf,
            self.inbuf_consumed,
        ) < len) {
            const n = if (deadline) |absolute|
                try self.transport().readWithDeadline(&scratch, absolute)
            else
                try self.transport().read(&scratch);
            if (n == 0) return error.ConnectionClosed;
            // One socket read commonly returns one complete WebSocket frame.
            // ArrayList's geometric append growth retained roughly 6.5 KiB for
            // every 4 KiB benchmark connection. Exact growth preserves the
            // same reuse while retaining only bytes the transport delivered.
            try message_buffer.appendAfterConsumed(
                &self.inbuf,
                &self.inbuf_consumed,
                self.allocator,
                scratch[0..n],
            );
        }
    }

    fn discardBuffered(self: *Connection, len: usize) void {
        _ = message_buffer.discardPrefix(
            &self.inbuf,
            &self.inbuf_consumed,
            len,
        );
    }

    /// Call only while holding `send_mutex`. Every writer repeats its close
    /// check here so one queued behind an earlier Close cannot append a frame.
    fn canSendOpcodeLocked(
        self: *const Connection,
        opcode: websocket.Opcode,
    ) bool {
        if (self.writeAborted()) return false;
        if (self.receiveFailed()) return false;
        return canSendOpcode(opcode, self.closeSent(), self.closeReceived());
    }

    fn closeSent(self: *const Connection) bool {
        return self.close_sent.load(.acquire);
    }

    fn closeReceived(self: *const Connection) bool {
        return self.receiveFailed() or self.close_received.load(.acquire);
    }

    fn receiveFailed(self: *const Connection) bool {
        return self.receive_failed.load(.acquire);
    }

    fn writeAborted(self: *const Connection) bool {
        return self.write_aborted.load(.acquire);
    }

    fn ensureNoPendingWrites(self: *Connection) Error!void {
        if (self.application_write_pending.load(.acquire) or
            self.automatic_write_pending.load(.acquire))
        {
            return error.WriteInProgress;
        }
    }

    fn pendingAutomaticControlOpcode(
        self: *Connection,
        delivery: PendingAutomaticControl.Delivery,
    ) Error!?websocket.Opcode {
        if (!self.automatic_write_pending.load(.acquire)) return null;
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);
        const pending = self.pending_auto_control orelse return null;
        if (pending.delivery != delivery) return error.WriteInProgress;
        return pending.opcode;
    }

    fn finishReceiveFailure(
        self: *Connection,
        code: websocket.CloseCode,
        deadline: ?std.Io.Clock.Timestamp,
    ) void {
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);
        if (self.pending_message != null or
            self.pending_ping != null or
            self.pending_close != null or
            self.pending_auto_control != null)
        {
            self.write_aborted.store(true, .release);
            transportStream(self.transport()).shutdown(self.io, .both) catch {};
            common.clearPendingOutboundLocked(self);
            return;
        }
        if (self.closeSent()) return;
        var storage: [125]u8 = undefined;
        const payload = websocket.writeClosePayloadInto(
            &storage,
            .{ .code = code },
        ) catch return;
        if (deadline) |absolute| {
            self.beginPendingControlLocked(
                &self.pending_close,
                .close,
                payload,
            ) catch return;
            self.resumePendingCloseLocked(absolute) catch {
                self.write_aborted.store(true, .release);
                transportStream(self.transport()).shutdown(self.io, .both) catch {};
                common.clearPendingOutboundLocked(self);
            };
            return;
        }
        self.writeFrameLocked(.close, payload, true) catch {
            self.write_aborted.store(true, .release);
            transportStream(self.transport()).shutdown(self.io, .both) catch {};
            return;
        };
        self.close_sent.store(true, .release);
    }

    fn finishAbruptReceiveEnd(
        self: *Connection,
        _: ?std.Io.Clock.Timestamp,
    ) void {
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);
        self.write_aborted.store(true, .release);
        transportStream(self.transport()).shutdown(self.io, .both) catch {};
        common.clearPendingOutboundLocked(self);
    }

    fn beginAutomaticControl(
        self: *Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
        delivery: PendingAutomaticControl.Delivery,
        frame: ?websocket.Frame,
    ) Error!void {
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);
        if (self.pending_auto_control != null) return error.WriteInProgress;

        var pending = PendingAutomaticControl{
            .opcode = opcode,
            .delivery = delivery,
            .fin_committed = true,
            .frame = frame,
        };
        const mask_key = if (self.role == .client) blk: {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.io, &key);
            break :blk key;
        } else null;
        const encoded = try websocket.writeFrameInto(
            &pending.bytes,
            opcode,
            payload,
            .{ .mask_key = mask_key },
        );
        pending.len = encoded.len;
        self.pending_auto_control = pending;
        self.automatic_write_pending.store(true, .release);
    }

    fn resumeAutomaticControl(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!?websocket.Frame {
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);
        const pending = if (self.pending_auto_control) |*value|
            value
        else
            return null;
        if (self.pending_message != null or
            self.pending_ping != null or
            self.pending_close != null)
        {
            return error.WriteInProgress;
        }
        if (!self.canSendOpcodeLocked(pending.opcode)) {
            pending.writes_reply = false;
        }
        if (!pending.complete() and deadline != null) {
            const absolute = deadline.?;
            _ = try deadline_policy.usableAwake(self.io, absolute);
            var committed: usize = 0;
            self.transport().writeWithDeadline(
                pending.bytes[pending.committed..pending.len],
                &committed,
                absolute,
            ) catch |err| {
                pending.committed += committed;
                return err;
            };
            pending.committed += committed;
        } else if (!pending.complete()) {
            var committed: usize = 0;
            self.transport().finishPendingTimedWrite(&committed) catch |err| {
                pending.committed += committed;
                self.abortAfterUnboundedMessageWriteLocked();
                return err;
            };
            pending.committed += committed;
            std.debug.assert(pending.committed <= pending.len);
            self.transport().writeAll(
                pending.bytes[pending.committed..pending.len],
            ) catch |err| {
                self.abortAfterUnboundedMessageWriteLocked();
                return err;
            };
            pending.committed = pending.len;
        }
        std.debug.assert(pending.complete());
        if (pending.opcode == .close) {
            self.close_sent.store(true, .release);
        }
        const frame = pending.frame;
        pending.frame = null;
        std.crypto.secureZero(u8, &pending.bytes);
        self.pending_auto_control = null;
        self.automatic_write_pending.store(false, .release);
        return frame;
    }
};

pub const H2Connection = struct {
    allocator: std.mem.Allocator,
    tunnel: http2_runtime.Tunnel,
    tunnel_owned: bool = false,
    role: Role,
    limits: Limits = .{},
    inbuf: std.ArrayList(u8) = .empty,
    inbuf_consumed: usize = 0,
    send_mutex: std.Io.Mutex = .init,
    /// RFC 8441 keeps the same split receive/write ownership as HTTP/1.
    close_sent: std.atomic.Value(bool) = .init(false),
    close_received: std.atomic.Value(bool) = .init(false),
    /// Terminal protocol errors and abrupt END_STREAM/reset release
    /// receive-only storage immediately.
    receive_failed: std.atomic.Value(bool) = .init(false),
    /// Set when a retained outbound WebSocket frame forces this CONNECT stream
    /// to be reset instead of appending a protocol Close after a partial frame.
    write_aborted: std.atomic.Value(bool) = .init(false),
    application_write_pending: std.atomic.Value(bool) = .init(false),
    automatic_write_pending: std.atomic.Value(bool) = .init(false),
    incoming_data_kind: IncomingDataKind = .none,
    incoming_text_utf8: websocket.Utf8Validator = .{},
    incoming_frame_validated: usize = 0,
    message_assembler: ?websocket.MessageAssembler = null,
    message_into: MessageIntoReceiveState = .{},
    message_frame_receive: MessageFrameReceiveState = .{},
    /// A bounded Close owns its encoded bytes and client mask until the HTTP/2
    /// DATA sequence and END_STREAM are fully committed.
    pending_close: ?PendingH2Close = null,
    /// A bounded Ping retains one encoded frame and client mask until all DATA
    /// bytes commit. Other writes cannot splice bytes into that frame.
    pending_ping: ?PendingH2Ping = null,
    /// Automatic Pong/Close transaction retained independently from an
    /// application-initiated Ping or Close.
    pending_auto_control: ?PendingAutomaticControl = null,
    /// A bounded application message retains only frame/mask/cursor state.
    /// The caller keeps the original payload slice stable through completion.
    pending_message: ?PendingH2Message = null,
    pending_tunnel_data: ?http2_runtime.OwnedTunnelData = null,
    pending_tunnel_data_offset: usize = 0,
    receive_finished: bool = false,
    selected_protocol: ?[]u8 = null,
    permessage_deflate: bool = false,
    compression_send_context_takeover: bool = false,
    compression_receive_context_takeover: bool = false,
    compression_threshold: usize = default_compression_threshold,
    compression_send_max_window_bits: u8 = 15,
    compression_receive_max_window_bits: u8 = 15,
    compression_send: compression_scratch.SendScratch = .{},
    compression_receive: compression_scratch.Scratch = .{},

    fn init(
        allocator: std.mem.Allocator,
        tunnel: http2_runtime.Tunnel,
        role: Role,
        limits: Limits,
        selected_protocol: ?[]u8,
        negotiated_extension: websocket.ExtensionNegotiation,
        compression_threshold: usize,
    ) H2Connection {
        return .{
            .allocator = allocator,
            .tunnel = tunnel,
            .tunnel_owned = true,
            .role = role,
            .limits = limits,
            .selected_protocol = selected_protocol,
            .permessage_deflate = negotiated_extension.permessage_deflate,
            .compression_send_context_takeover = negotiated_extension.permessage_deflate and switch (role) {
                .client => !negotiated_extension.client_no_context_takeover,
                .server => !negotiated_extension.server_no_context_takeover,
            },
            .compression_receive_context_takeover = negotiated_extension.permessage_deflate and switch (role) {
                .client => !negotiated_extension.server_no_context_takeover,
                .server => !negotiated_extension.client_no_context_takeover,
            },
            .compression_threshold = compression_threshold,
            .compression_send_max_window_bits = switch (role) {
                .client => negotiated_extension.client_max_window_bits orelse 15,
                .server => negotiated_extension.server_max_window_bits orelse 15,
            },
            .compression_receive_max_window_bits = switch (role) {
                .client => negotiated_extension.server_max_window_bits orelse 15,
                .server => negotiated_extension.client_max_window_bits orelse 15,
            },
        };
    }

    pub fn close(self: *H2Connection) void {
        if (self.pending_message) |*pending| {
            std.crypto.secureZero(u8, &pending.header);
            if (pending.mask_key) |*mask| {
                std.crypto.secureZero(u8, mask);
            }
        }
        if (self.pending_ping) |*pending| {
            std.crypto.secureZero(u8, &pending.bytes);
            std.crypto.secureZero(u8, &pending.payload);
        }
        if (self.pending_close) |*pending| {
            std.crypto.secureZero(u8, &pending.bytes);
            std.crypto.secureZero(u8, &pending.payload);
        }
        if (self.pending_auto_control) |*pending| {
            pending.deinit(self.allocator);
        }
        if (self.pending_tunnel_data) |*data| {
            data.deinit(self.tunnel.connection.allocator);
        }
        if (self.tunnel_owned) {
            self.tunnel.connection.abandonExtendedConnect(
                self.tunnel.stream_id,
            );
        }
        if (self.selected_protocol) |protocol| self.allocator.free(protocol);
        if (self.message_assembler) |*assembler| assembler.deinit();
        self.inbuf.deinit(self.allocator);
        self.compression_send.deinit(self.allocator);
        self.compression_receive.deinit(self.allocator);
        self.* = undefined;
    }

    /// Return TLS identity and negotiation state for the shared HTTP/2
    /// connection. These are connection-wide values, not per-WebSocket-stream
    /// properties, and remain valid while the parent connection is alive.
    pub fn peerCertificates(
        self: *const H2Connection,
    ) ?[]const []const u8 {
        return self.tunnel.connection.peerCertificates();
    }

    pub fn negotiatedAlpn(self: *const H2Connection) ?[]const u8 {
        return self.tunnel.connection.negotiatedAlpn();
    }

    pub fn negotiatedCipherSuite(
        self: *const H2Connection,
    ) ?tls_stream.CipherSuite {
        return self.tunnel.connection.negotiatedCipherSuite();
    }

    pub fn negotiatedTranscriptHash(
        self: *const H2Connection,
    ) ?tls_stream.TranscriptHash {
        return self.tunnel.connection.negotiatedTranscriptHash();
    }

    pub fn exportKeyingMaterial(
        self: *const H2Connection,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        try self.tunnel.connection.exportKeyingMaterial(
            label,
            context,
            out,
        );
    }

    /// RFC 8441 runs over the parent HTTP/2 connection, so TLS traffic-key
    /// control belongs to that shared transport rather than this logical
    /// WebSocket stream. Cleartext h2c reports the same explicit unavailable
    /// error as the ordinary WebSocket adapter.
    pub fn updateTrafficKeys(
        self: *H2Connection,
        request_peer_update: bool,
    ) Error!void {
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.send_mutex.unlock(self.tunnel.connection.io);
        if (self.pending_message != null or
            self.pending_ping != null or
            self.pending_close != null or
            self.pending_auto_control != null)
        {
            return error.WriteInProgress;
        }
        try self.tunnel.connection.updateTrafficKeys(request_peer_update);
    }

    pub fn keyUpdateCounts(
        self: *const H2Connection,
    ) ?tls_stream.KeyUpdateCounts {
        return self.tunnel.connection.keyUpdateCounts();
    }

    pub fn sendText(self: *H2Connection, text: []const u8) Error!void {
        try self.sendMessage(.text, text);
    }

    pub fn sendTextWithTimeout(
        self: *H2Connection,
        text: []const u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendTextWithDeadline(
            text,
            progress,
            .fromNow(self.tunnel.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    /// Send one text frame under an absolute deadline. After partial progress,
    /// retry with the same payload slice until `frame_committed` is true.
    pub fn sendTextWithDeadline(
        self: *H2Connection,
        text: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        try common.validateOutgoingMessage(self.limits, .text, text);
        return self.sendMessageWithDeadlineLocked(
            .text,
            text,
            progress,
            deadline,
        );
    }

    pub fn sendBinary(self: *H2Connection, payload: []const u8) Error!void {
        try self.sendMessage(.binary, payload);
    }

    pub fn sendBinaryWithTimeout(
        self: *H2Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendBinaryWithDeadline(
            payload,
            progress,
            .fromNow(self.tunnel.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    /// Binary counterpart to `sendTextWithDeadline`; progress counts the
    /// complete RFC 6455 frame and is cumulative across same-slice retries.
    pub fn sendBinaryWithDeadline(
        self: *H2Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        try common.validateOutgoingMessage(
            self.limits,
            .binary,
            payload,
        );
        return self.sendMessageWithDeadlineLocked(
            .binary,
            payload,
            progress,
            deadline,
        );
    }

    /// Mask a mutable RFC 8441 client payload in place and submit its header
    /// and body as one ordered HTTP/2 tunnel sequence. The payload remains
    /// masked after return. Server connections and negotiated compression use
    /// the immutable send APIs instead.
    pub fn sendBinaryInPlace(
        self: *H2Connection,
        payload: []u8,
    ) Error!void {
        if (self.role != .client or self.permessage_deflate) {
            return error.InvalidFrame;
        }
        if (!canSendOpcode(.binary, self.closeSent(), self.closeReceived())) {
            return error.ConnectionClosed;
        }
        try common.validateOutgoingMessage(
            self.limits,
            .binary,
            payload,
        );
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.send_mutex.unlock(self.tunnel.connection.io);
        try self.ensureCanSendOpcodeLocked(.binary);

        var mask_key: [4]u8 = undefined;
        try std.Io.randomSecure(self.tunnel.connection.io, &mask_key);
        var header_storage: [websocket.max_frame_header_len]u8 = undefined;
        const header = try websocket.writeFrameHeaderInto(
            &header_storage,
            .binary,
            payload,
            .{ .mask_key = mask_key },
        );
        websocket.applyMask(payload, mask_key, 0);
        // `Tunnel.writeParts` is synchronous: every DATA write has consumed
        // its borrowed slices before return, so ownership immediately returns
        // to the caller even when flow control split the message.
        self.tunnel.writeParts(header, payload, false) catch |err| {
            self.abortAfterUnboundedMessageWriteLocked();
            return err;
        };
    }

    pub fn sendBinaryInPlaceWithTimeout(
        self: *H2Connection,
        payload: []u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendBinaryInPlaceWithDeadline(
            payload,
            progress,
            .fromNow(self.tunnel.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendBinaryInPlaceWithDeadline(
        self: *H2Connection,
        payload: []u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        if (self.role != .client or self.permessage_deflate) {
            return error.InvalidFrame;
        }
        try common.validateOutgoingMessageLength(self.limits, payload.len);
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.send_mutex.unlock(self.tunnel.connection.io);
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        if (self.pending_ping != null or self.pending_close != null) {
            return error.WriteInProgress;
        }
        if (self.pending_message) |*pending| {
            if (!pending.matchesInPlace(payload)) {
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.totalLen(),
                };
                return error.WriteInProgress;
            }
        } else {
            if (self.pending_auto_control != null) {
                return error.WriteInProgress;
            }
            try self.ensureCanSendOpcodeLocked(.binary);
            try self.beginPendingInPlaceLocked(payload);
        }
        try self.resumePendingInPlaceLocked(payload, progress, deadline);
    }

    fn beginPendingInPlaceLocked(
        self: *H2Connection,
        payload: []u8,
    ) Error!void {
        var pending = PendingH2Message{
            .opcode = .binary,
            .source = .in_place,
            .original_ptr = @intFromPtr(payload.ptr),
            .original_len = payload.len,
            .payload_len = payload.len,
        };
        var key: [4]u8 = undefined;
        try std.Io.randomSecure(self.tunnel.connection.io, &key);
        pending.mask_key = key;
        const header = try websocket.writeFrameHeaderForLengthInto(
            &pending.header,
            .binary,
            payload.len,
            .{ .mask_key = key },
        );
        pending.header_len = header.len;
        websocket.applyMask(payload, key, 0);
        self.pending_message = pending;
        self.application_write_pending.store(true, .release);
    }

    fn resumePendingInPlaceLocked(
        self: *H2Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.receiveFailed()) return error.ConnectionClosed;
        const pending = &self.pending_message.?;
        while (pending.committed < pending.totalLen()) {
            const header_offset = @min(pending.committed, pending.header_len);
            const payload_offset = pending.committed - header_offset;
            const bytes = if (header_offset < pending.header_len)
                pending.header[header_offset..pending.header_len]
            else
                payload[payload_offset..];
            var tunnel_progress: http2_runtime.TunnelWriteProgress = .{};
            self.tunnel.writeWithDeadline(
                bytes,
                false,
                &tunnel_progress,
                deadline,
            ) catch |err| {
                pending.committed += tunnel_progress.committed_bytes;
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.totalLen(),
                };
                return err;
            };
            pending.committed += tunnel_progress.committed_bytes;
        }
        progress.* = .{
            .committed_bytes = pending.committed,
            .total_bytes = pending.totalLen(),
            .frame_committed = true,
        };
        self.pending_message = null;
        self.application_write_pending.store(false, .release);
    }

    /// Compatibility wrapper for the two-slice RFC 8441 form.
    pub fn sendBinaryParts(
        self: *H2Connection,
        first: []const u8,
        second: []const u8,
    ) Error!void {
        return self.sendBinarySlices(&.{ first, second });
    }

    /// Send borrowed slices as one RFC 6455 binary frame over HTTP/2. HTTP/2
    /// DATA flow-control boundaries do not become WebSocket continuations.
    pub fn sendBinarySlices(
        self: *H2Connection,
        parts: []const []const u8,
    ) Error!void {
        if (!canSendOpcode(.binary, self.closeSent(), self.closeReceived())) {
            return error.ConnectionClosed;
        }
        const payload_len = try common.validateOutgoingMessageParts(
            self.limits,
            parts,
        );
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.send_mutex.unlock(self.tunnel.connection.io);
        try self.ensureCanSendOpcodeLocked(.binary);

        if (self.permessage_deflate and
            payload_len >= self.compression_threshold)
        {
            const compressed = try self.compressMessagePartsLocked(
                parts,
                payload_len,
            );
            if (compressed.len < payload_len) {
                self.writeFrameLockedExtended(
                    .binary,
                    compressed,
                    true,
                    .{ .rsv1 = true },
                ) catch |err| {
                    self.abortAfterUnboundedMessageWriteLocked();
                    return err;
                };
                self.commitCompressionPreviewLocked();
                return;
            }
            self.discardCompressionPreviewLocked();
        }

        const mask_key = if (self.role == .client) blk: {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.tunnel.connection.io, &key);
            break :blk key;
        } else null;
        var header_storage: [websocket.max_frame_header_len]u8 = undefined;
        const header = try websocket.writeFrameHeaderForLengthInto(
            &header_storage,
            .binary,
            payload_len,
            .{ .mask_key = mask_key },
        );
        if (mask_key) |mask| {
            writeMaskedTunnelPayloadSlices(
                &self.tunnel,
                header,
                parts,
                mask,
            ) catch |err| {
                self.abortAfterUnboundedMessageWriteLocked();
                return err;
            };
        } else {
            var writer = self.tunnel.beginWriteSequence() catch |err| {
                self.abortAfterUnboundedMessageWriteLocked();
                return err;
            };
            writeUnmaskedTunnelPayloadSlices(
                &writer,
                header,
                parts,
            ) catch |err| {
                self.abortAfterUnboundedMessageWriteLocked();
                return err;
            };
        }
    }

    pub fn sendBinarySlicesWithTimeout(
        self: *H2Connection,
        parts: []const []const u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendBinarySlicesWithDeadline(
            parts,
            progress,
            .fromNow(self.tunnel.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    /// Send borrowed slices as one RFC 6455 binary frame over RFC 8441 under
    /// one absolute deadline. Retry with the same descriptor array until the
    /// complete frame commits.
    pub fn sendBinarySlicesWithDeadline(
        self: *H2Connection,
        parts: []const []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        const payload_len = try common.validateOutgoingMessageParts(
            self.limits,
            parts,
        );
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.send_mutex.unlock(self.tunnel.connection.io);
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        if (self.pending_ping != null or self.pending_close != null) {
            return error.WriteInProgress;
        }
        if (self.pending_message) |*pending| {
            if (!pending.matchesParts(parts)) {
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.totalLen(),
                };
                return error.WriteInProgress;
            }
        } else {
            if (self.pending_auto_control != null) {
                return error.WriteInProgress;
            }
            try self.ensureCanSendOpcodeLocked(.binary);
            try self.beginPendingMessagePartsLocked(parts, payload_len);
        }
        try self.resumePendingMessagePartsLocked(parts, progress, deadline);
    }

    pub fn sendPing(self: *H2Connection, payload: []const u8) Error!void {
        try self.sendFrame(.ping, payload);
    }

    pub fn sendPingWithTimeout(
        self: *H2Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendPingWithDeadline(
            payload,
            progress,
            .fromNow(self.tunnel.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendPingWithDeadline(
        self: *H2Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        try common.validateOutgoingControlFrame(self.limits, .ping, payload);
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.send_mutex.unlock(self.tunnel.connection.io);
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        if (self.pending_message != null or self.pending_close != null) {
            return error.WriteInProgress;
        }
        if (self.pending_ping == null) {
            if (self.pending_auto_control != null) {
                return error.WriteInProgress;
            }
            try self.ensureCanSendOpcodeLocked(.ping);
            try self.beginPendingPingLocked(payload);
        }
        const total = self.pending_ping.?.len;
        self.resumePendingPingLocked(payload, deadline) catch |err| {
            const pending = self.pending_ping.?;
            progress.* = .{
                .committed_bytes = pending.committed,
                .total_bytes = pending.len,
            };
            return err;
        };
        progress.* = .{
            .committed_bytes = total,
            .total_bytes = total,
            .frame_committed = true,
        };
    }

    pub fn sendPong(self: *H2Connection, payload: []const u8) Error!void {
        try self.sendFrame(.pong, payload);
    }

    pub fn sendPongWithTimeout(
        self: *H2Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendPongWithDeadline(
            payload,
            progress,
            .fromNow(self.tunnel.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendPongWithDeadline(
        self: *H2Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        try common.validateOutgoingControlFrame(self.limits, .pong, payload);
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.send_mutex.unlock(self.tunnel.connection.io);
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        if (self.pending_ping != null or self.pending_close != null) {
            return error.WriteInProgress;
        }
        if (self.pending_message) |*pending| {
            if (!pending.matches(.pong, payload)) {
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.totalLen(),
                };
                return error.WriteInProgress;
            }
        } else {
            if (self.pending_auto_control != null) {
                return error.WriteInProgress;
            }
            if (!self.canSendOpcodeLocked(.pong)) {
                return error.ConnectionClosed;
            }
            try self.beginPendingPongLocked(payload);
        }
        try self.resumePendingMessageLocked(payload, progress, deadline);
    }

    /// RFC 8441 counterpart to `Connection.pingWithTimeout`.
    pub fn pingWithTimeout(
        self: *H2Connection,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) Error!PingEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const deadline = std.Io.Clock.Timestamp.fromNow(
            self.tunnel.connection.io,
            .{ .raw = timeout, .clock = .awake },
        );
        return self.pingWithDeadline(payload, deadline);
    }

    pub fn pingWithDeadline(
        self: *H2Connection,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PingEvent {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        try common.validateOutgoingControlFrame(
            self.limits,
            .ping,
            payload,
        );
        if (self.automatic_write_pending.load(.acquire) and
            !self.application_write_pending.load(.acquire))
        {
            _ = try self.pendingAutomaticControlOpcode(.ping_wait);
            return self.readPingEvent(payload, deadline);
        }
        {
            self.send_mutex.lockUncancelable(self.tunnel.connection.io);
            defer self.send_mutex.unlock(self.tunnel.connection.io);
            _ = try deadline_policy.usableAwake(
                self.tunnel.connection.io,
                deadline,
            );
            if (self.pending_message != null or
                self.pending_close != null)
            {
                return error.WriteInProgress;
            }
            if (self.pending_ping == null) {
                if (self.pending_auto_control != null) {
                    return error.WriteInProgress;
                }
                try self.ensureCanSendOpcodeLocked(.ping);
                try self.beginPendingPingLocked(payload);
            }
            try self.resumePendingPingLocked(payload, deadline);
        }
        return self.readPingEvent(payload, deadline);
    }

    pub fn continuePingWithDeadline(
        self: *H2Connection,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PingEvent {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        if (self.automatic_write_pending.load(.acquire) and
            !self.application_write_pending.load(.acquire))
        {
            _ = try self.pendingAutomaticControlOpcode(.ping_wait);
            return self.readPingEvent(payload, deadline);
        }
        {
            self.send_mutex.lockUncancelable(self.tunnel.connection.io);
            defer self.send_mutex.unlock(self.tunnel.connection.io);
            if (self.pending_message != null or
                self.pending_close != null)
            {
                return error.WriteInProgress;
            }
            try self.resumePendingPingLocked(payload, deadline);
        }
        return self.readPingEvent(payload, deadline);
    }

    pub fn continuePingWithTimeout(
        self: *H2Connection,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) Error!PingEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.continuePingWithDeadline(
            payload,
            .fromNow(
                self.tunnel.connection.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    fn readPingEvent(
        self: *H2Connection,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PingEvent {
        while (true) {
            var frame = try self.receiveFrameAutoInternal(
                deadline,
                .ping_wait,
            );
            switch (frame.header.opcode) {
                .ping => {
                    frame.deinit(self.allocator);
                    continue;
                },
                .pong => {
                    defer frame.deinit(self.allocator);
                    if (!std.mem.eql(u8, frame.payload, payload)) {
                        return error.UnexpectedPong;
                    }
                    return .{ .pong = {} };
                },
                .close => {
                    defer frame.deinit(self.allocator);
                    return .{ .closed = try websocket.parseClosePayloadOwned(
                        self.allocator,
                        frame.payload,
                    ) };
                },
                .text, .binary, .continuation => {
                    return .{ .application = frame };
                },
                else => {
                    frame.deinit(self.allocator);
                    return error.InvalidFrame;
                },
            }
        }
    }

    pub fn sendClose(self: *H2Connection, code: websocket.CloseCode, reason: []const u8) Error!void {
        try self.sendCloseFrame(.{ .code = code, .reason = reason });
    }

    pub fn sendCloseWithTimeout(
        self: *H2Connection,
        code: websocket.CloseCode,
        reason: []const u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        return self.sendCloseFrameWithTimeout(
            .{ .code = code, .reason = reason },
            progress,
            timeout,
        );
    }

    pub fn sendCloseWithDeadline(
        self: *H2Connection,
        code: websocket.CloseCode,
        reason: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        return self.sendCloseFrameWithDeadline(
            .{ .code = code, .reason = reason },
            progress,
            deadline,
        );
    }

    pub fn sendCloseFrameWithTimeout(
        self: *H2Connection,
        close_frame: ?websocket.CloseFrame,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendCloseFrameWithDeadline(
            close_frame,
            progress,
            .fromNow(self.tunnel.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendCloseFrameWithDeadline(
        self: *H2Connection,
        close_frame: ?websocket.CloseFrame,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        var storage: [125]u8 = undefined;
        const payload = try websocket.writeClosePayloadInto(
            &storage,
            close_frame,
        );
        try common.validateOutgoingControlFrame(self.limits, .close, payload);
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.send_mutex.unlock(self.tunnel.connection.io);
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        if (self.receiveFailed() or self.writeAborted()) {
            return error.ConnectionClosed;
        }
        if (self.pending_message != null or self.pending_ping != null) {
            return error.WriteInProgress;
        }
        if (self.pending_close) |*pending| {
            if (!pending.matches(payload)) return error.WriteInProgress;
        } else {
            if (self.pending_auto_control != null) {
                return error.WriteInProgress;
            }
            try self.ensureCanSendOpcodeLocked(.close);
            try self.beginPendingCloseLocked(payload);
        }
        const total = self.pending_close.?.len;
        self.resumePendingCloseLocked(deadline) catch |err| {
            const pending = self.pending_close orelse {
                progress.* = .{
                    .committed_bytes = total,
                    .total_bytes = total,
                    .frame_committed = true,
                };
                return err;
            };
            progress.* = .{
                .committed_bytes = pending.committed,
                .total_bytes = pending.len,
            };
            return err;
        };
        progress.* = .{
            .committed_bytes = total,
            .total_bytes = total,
            .frame_committed = true,
        };
    }

    pub fn sendCloseFrame(self: *H2Connection, close_frame: ?websocket.CloseFrame) Error!void {
        var storage: [125]u8 = undefined;
        const payload = try websocket.writeClosePayloadInto(
            &storage,
            close_frame,
        );
        try self.sendFrame(.close, payload);
    }

    pub fn receiveCloseFrame(self: *H2Connection) Error!?websocket.OwnedCloseFrame {
        var frame = try self.receiveFrame();
        defer frame.deinit(self.allocator);
        if (frame.header.opcode != .close) return error.InvalidFrame;
        return websocket.parseClosePayloadOwned(self.allocator, frame.payload);
    }

    pub fn receiveCloseFrameWithTimeout(
        self: *H2Connection,
        timeout: std.Io.Duration,
    ) Error!?websocket.OwnedCloseFrame {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveCloseFrameWithDeadline(.fromNow(
            self.tunnel.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// RFC 8441 counterpart to
    /// `Connection.receiveCloseFrameWithDeadline`.
    pub fn receiveCloseFrameWithDeadline(
        self: *H2Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!?websocket.OwnedCloseFrame {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        var frame = try self.receiveFrameWithDeadline(deadline);
        defer frame.deinit(self.allocator);
        if (frame.header.opcode != .close) return error.InvalidFrame;
        return websocket.parseClosePayloadOwned(self.allocator, frame.payload);
    }

    /// RFC 8441 relative-budget counterpart to
    /// `receiveFrameWithDeadline`.
    pub fn receiveFrameWithTimeout(
        self: *H2Connection,
        timeout: std.Io.Duration,
    ) Error!websocket.Frame {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameInternal(.fromNow(
            self.tunnel.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// RFC 8441 counterpart to `Connection.receiveFrameWithDeadline`.
    pub fn receiveFrameWithDeadline(
        self: *H2Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!websocket.Frame {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameInternal(deadline);
    }

    /// Send Close on the extended CONNECT stream and wait under one absolute
    /// deadline. In-flight application frames are returned rather than lost.
    pub fn closeWithTimeout(
        self: *H2Connection,
        close_frame: ?websocket.CloseFrame,
        timeout: std.Io.Duration,
    ) Error!CloseHandshakeEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const deadline = std.Io.Clock.Timestamp.fromNow(
            self.tunnel.connection.io,
            .{ .raw = timeout, .clock = .awake },
        );
        return self.closeWithDeadline(close_frame, deadline);
    }

    /// RFC 8441 close progress under a caller-owned absolute deadline.
    pub fn closeWithDeadline(
        self: *H2Connection,
        close_frame: ?websocket.CloseFrame,
        deadline: std.Io.Clock.Timestamp,
    ) Error!CloseHandshakeEvent {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        if (self.receiveFailed() or self.writeAborted()) {
            return error.ConnectionClosed;
        }
        if (self.automatic_write_pending.load(.acquire) and
            !self.application_write_pending.load(.acquire))
        {
            _ = try self.pendingAutomaticControlOpcode(.close_wait);
            return self.readCloseHandshakeEvent(deadline);
        }
        {
            self.send_mutex.lockUncancelable(self.tunnel.connection.io);
            defer self.send_mutex.unlock(self.tunnel.connection.io);
            _ = try deadline_policy.usableAwake(
                self.tunnel.connection.io,
                deadline,
            );
            if (self.receiveFailed() or self.writeAborted()) {
                return error.ConnectionClosed;
            }
            if (self.pending_message != null or
                self.pending_ping != null)
            {
                return error.WriteInProgress;
            }
            if (!self.closeSent() or self.pending_close != null) {
                var storage: [125]u8 = undefined;
                const payload = try websocket.writeClosePayloadInto(
                    &storage,
                    close_frame,
                );
                try common.validateOutgoingControlFrame(
                    self.limits,
                    .close,
                    payload,
                );
                if (self.pending_close) |*pending| {
                    if (!pending.matches(payload)) {
                        return error.WriteInProgress;
                    }
                } else {
                    if (self.pending_auto_control != null) {
                        return error.WriteInProgress;
                    }
                    try self.beginPendingCloseLocked(payload);
                }
            }
            try self.resumePendingCloseLocked(deadline);
        }
        return self.readCloseHandshakeEvent(deadline);
    }

    /// RFC 8441 close progress under the original caller-owned deadline.
    pub fn continueCloseWithDeadline(
        self: *H2Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!CloseHandshakeEvent {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        if (self.receiveFailed() or self.writeAborted()) {
            return error.ConnectionClosed;
        }
        if (self.automatic_write_pending.load(.acquire) and
            !self.application_write_pending.load(.acquire))
        {
            _ = try self.pendingAutomaticControlOpcode(.close_wait);
            return self.readCloseHandshakeEvent(deadline);
        }
        {
            self.send_mutex.lockUncancelable(self.tunnel.connection.io);
            defer self.send_mutex.unlock(self.tunnel.connection.io);
            if (self.receiveFailed() or self.writeAborted()) {
                return error.ConnectionClosed;
            }
            if (self.pending_message != null or
                self.pending_ping != null)
            {
                return error.WriteInProgress;
            }
            if (!self.closeSent() and self.pending_close == null) {
                return error.InvalidFrame;
            }
            try self.resumePendingCloseLocked(deadline);
        }
        return self.readCloseHandshakeEvent(deadline);
    }

    pub fn continueCloseWithTimeout(
        self: *H2Connection,
        timeout: std.Io.Duration,
    ) Error!CloseHandshakeEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.continueCloseWithDeadline(.fromNow(
            self.tunnel.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    fn readCloseHandshakeEvent(
        self: *H2Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!CloseHandshakeEvent {
        while (true) {
            var frame = try self.receiveFrameAutoInternal(
                deadline,
                .close_wait,
            );
            switch (frame.header.opcode) {
                .ping, .pong => {
                    frame.deinit(self.allocator);
                    continue;
                },
                .close => {
                    defer frame.deinit(self.allocator);
                    return .{ .closed = try websocket.parseClosePayloadOwned(
                        self.allocator,
                        frame.payload,
                    ) };
                },
                .text, .binary, .continuation => {
                    return .{ .application = frame };
                },
                else => {
                    frame.deinit(self.allocator);
                    return error.InvalidFrame;
                },
            }
        }
    }

    pub fn sendFrame(self: *H2Connection, opcode: websocket.Opcode, payload: []const u8) Error!void {
        try common.validateOutgoingControlFrame(
            self.limits,
            opcode,
            payload,
        );
        if (!canSendOpcode(opcode, self.closeSent(), self.closeReceived())) {
            return error.ConnectionClosed;
        }
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.send_mutex.unlock(self.tunnel.connection.io);
        try self.sendFrameValidatedLocked(opcode, payload);
    }

    fn sendFrameValidatedLocked(
        self: *H2Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
    ) Error!void {
        try self.ensureCanSendOpcodeLocked(opcode);
        self.writeFrameLocked(opcode, payload, true) catch |err| {
            self.abortAfterUnboundedMessageWriteLocked();
            return err;
        };
        if (opcode == .close) self.close_sent.store(true, .release);
    }

    fn beginPendingPingLocked(
        self: *H2Connection,
        payload: []const u8,
    ) Error!void {
        std.debug.assert(self.pending_ping == null);
        var pending: PendingH2Ping = .{};
        @memcpy(pending.payload[0..payload.len], payload);
        pending.payload_len = payload.len;
        var mask_key: ?[4]u8 = null;
        if (self.role == .client) {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.tunnel.connection.io, &key);
            mask_key = key;
        }
        const encoded = try websocket.writeFrameInto(
            &pending.bytes,
            .ping,
            payload,
            .{ .mask_key = mask_key },
        );
        pending.len = encoded.len;
        self.pending_ping = pending;
        self.application_write_pending.store(true, .release);
    }

    fn resumePendingPingLocked(
        self: *H2Connection,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.receiveFailed()) return error.ConnectionClosed;
        const pending = if (self.pending_ping) |*value|
            value
        else
            return;
        if (!pending.matches(payload)) return error.WriteInProgress;
        var progress: http2_runtime.TunnelWriteProgress = .{};
        self.tunnel.writeWithDeadline(
            pending.bytes[pending.committed..pending.len],
            false,
            &progress,
            deadline,
        ) catch |err| {
            pending.committed += progress.committed_bytes;
            return err;
        };
        pending.committed += progress.committed_bytes;
        std.debug.assert(pending.committed == pending.len);
        self.pending_ping = null;
        self.application_write_pending.store(false, .release);
    }

    fn beginPendingCloseLocked(
        self: *H2Connection,
        payload: []const u8,
    ) Error!void {
        std.debug.assert(self.pending_close == null);
        var pending: PendingH2Close = .{};
        @memcpy(pending.payload[0..payload.len], payload);
        pending.payload_len = payload.len;
        var mask_key: ?[4]u8 = null;
        if (self.role == .client) {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.tunnel.connection.io, &key);
            mask_key = key;
        }
        const encoded = try websocket.writeFrameInto(
            &pending.bytes,
            .close,
            payload,
            .{ .mask_key = mask_key },
        );
        pending.len = encoded.len;
        self.pending_close = pending;
        self.application_write_pending.store(true, .release);
    }

    fn resumePendingCloseLocked(
        self: *H2Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.writeAborted()) return error.ConnectionClosed;
        const pending = if (self.pending_close) |*value|
            value
        else
            return;
        var progress: http2_runtime.TunnelWriteProgress = .{};
        self.tunnel.writeWithDeadline(
            pending.bytes[pending.committed..pending.len],
            true,
            &progress,
            deadline,
        ) catch |err| {
            pending.committed += progress.committed_bytes;
            if (progress.fin_committed) {
                self.pending_close = null;
                self.application_write_pending.store(false, .release);
                self.close_sent.store(true, .release);
            }
            return err;
        };
        pending.committed += progress.committed_bytes;
        std.debug.assert(
            pending.committed == pending.len and progress.fin_committed,
        );
        self.pending_close = null;
        self.application_write_pending.store(false, .release);
        self.close_sent.store(true, .release);
    }

    fn sendMessageWithDeadlineLocked(
        self: *H2Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.send_mutex.unlock(self.tunnel.connection.io);
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );

        if (self.pending_message) |*pending| {
            if (!pending.matches(opcode, payload)) {
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.totalLen(),
                };
                return error.WriteInProgress;
            }
        } else {
            if (self.pending_auto_control != null) {
                return error.WriteInProgress;
            }
            try self.ensureCanSendOpcodeLocked(opcode);
            try self.beginPendingMessageLocked(opcode, payload);
        }
        try self.resumePendingMessageLocked(payload, progress, deadline);
    }

    fn beginPendingMessageLocked(
        self: *H2Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
    ) Error!void {
        std.debug.assert(self.pending_message == null);
        var pending = PendingH2Message{
            .opcode = opcode,
            .original_ptr = @intFromPtr(payload.ptr),
            .original_len = payload.len,
        };
        var encoded_payload = payload;
        errdefer self.discardCompressionPreviewLocked();
        if (self.permessage_deflate and
            payload.len >= self.compression_threshold)
        {
            const compressed = try self.compressMessageLocked(payload);
            if (compressed.len < payload.len) {
                encoded_payload = compressed;
                pending.compressed = true;
            } else {
                self.discardCompressionPreviewLocked();
            }
        }
        if (self.role == .client) {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.tunnel.connection.io, &key);
            pending.mask_key = key;
        }
        const header = try websocket.writeFrameHeaderForLengthInto(
            &pending.header,
            opcode,
            encoded_payload.len,
            .{
                .mask_key = pending.mask_key,
                .rsv1 = pending.compressed,
            },
        );
        pending.header_len = header.len;
        pending.payload_len = encoded_payload.len;
        self.pending_message = pending;
        self.application_write_pending.store(true, .release);
    }

    fn beginPendingPongLocked(
        self: *H2Connection,
        payload: []const u8,
    ) Error!void {
        std.debug.assert(self.pending_message == null);
        var pending = PendingH2Message{
            .opcode = .pong,
            .original_ptr = @intFromPtr(payload.ptr),
            .original_len = payload.len,
            .payload_len = payload.len,
        };
        if (self.role == .client) {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.tunnel.connection.io, &key);
            pending.mask_key = key;
        }
        const header = try websocket.writeFrameHeaderForLengthInto(
            &pending.header,
            .pong,
            payload.len,
            .{ .mask_key = pending.mask_key },
        );
        pending.header_len = header.len;
        self.pending_message = pending;
        self.application_write_pending.store(true, .release);
    }

    fn beginPendingMessagePartsLocked(
        self: *H2Connection,
        parts: []const []const u8,
        payload_len: usize,
    ) Error!void {
        std.debug.assert(self.pending_message == null);
        var pending = PendingH2Message{
            .opcode = .binary,
            .source = .slices,
            .original_ptr = @intFromPtr(parts.ptr),
            .original_len = parts.len,
        };
        var encoded_len = payload_len;
        errdefer self.discardCompressionPreviewLocked();
        if (self.permessage_deflate and
            payload_len >= self.compression_threshold)
        {
            const compressed = try self.compressMessagePartsLocked(
                parts,
                payload_len,
            );
            if (compressed.len < payload_len) {
                encoded_len = compressed.len;
                pending.compressed = true;
            } else {
                self.discardCompressionPreviewLocked();
            }
        }
        if (self.role == .client) {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.tunnel.connection.io, &key);
            pending.mask_key = key;
        }
        const header = try websocket.writeFrameHeaderForLengthInto(
            &pending.header,
            .binary,
            encoded_len,
            .{
                .mask_key = pending.mask_key,
                .rsv1 = pending.compressed,
            },
        );
        pending.header_len = header.len;
        pending.payload_len = encoded_len;
        self.pending_message = pending;
        self.application_write_pending.store(true, .release);
    }

    fn resumePendingMessageLocked(
        self: *H2Connection,
        original_payload: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.receiveFailed()) return error.ConnectionClosed;
        const pending = &self.pending_message.?;
        const encoded_payload = if (pending.compressed)
            self.compression_send.payload.items[0..pending.payload_len]
        else
            original_payload;
        var masked: [masked_write_scratch_len]u8 = undefined;

        while (pending.committed < pending.totalLen()) {
            const header_offset = @min(
                pending.committed,
                pending.header_len,
            );
            const payload_offset = pending.committed - header_offset;
            const header = pending.header[header_offset..pending.header_len];
            const remaining_payload = encoded_payload[payload_offset..];
            var parts: [2][]const u8 = undefined;
            var part_count: usize = 0;
            if (header.len != 0) {
                parts[part_count] = header;
                part_count += 1;
            }
            if (remaining_payload.len != 0) {
                if (pending.mask_key) |mask| {
                    const count = @min(masked.len, remaining_payload.len);
                    try websocket.applyMaskCopy(
                        masked[0..count],
                        remaining_payload[0..count],
                        mask,
                        payload_offset,
                    );
                    parts[part_count] = masked[0..count];
                } else {
                    parts[part_count] = remaining_payload;
                }
                part_count += 1;
            }

            var tunnel_progress: http2_runtime.TunnelWriteProgress = .{};
            self.tunnel.writeSlicesWithDeadline(
                parts[0..part_count],
                false,
                &tunnel_progress,
                deadline,
            ) catch |err| {
                pending.committed += tunnel_progress.committed_bytes;
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.totalLen(),
                };
                return err;
            };
            pending.committed += tunnel_progress.committed_bytes;
        }

        progress.* = .{
            .committed_bytes = pending.committed,
            .total_bytes = pending.totalLen(),
            .frame_committed = true,
        };
        if (pending.compressed) self.commitCompressionPreviewLocked();
        self.pending_message = null;
        self.application_write_pending.store(false, .release);
    }

    fn resumePendingMessagePartsLocked(
        self: *H2Connection,
        parts: []const []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.receiveFailed()) return error.ConnectionClosed;
        const pending = &self.pending_message.?;
        var scratch: [masked_write_scratch_len + websocket.max_frame_header_len]u8 align(64) = undefined;

        while (pending.committed < pending.totalLen()) {
            const header_offset = @min(
                pending.committed,
                pending.header_len,
            );
            const payload_offset = pending.committed - header_offset;
            var wire_len: usize = 0;
            if (header_offset < pending.header_len) {
                const header = pending.header[header_offset..pending.header_len];
                @memcpy(scratch[0..header.len], header);
                wire_len = header.len;
            }
            const payload_capacity = @min(
                scratch.len - wire_len,
                pending.payload_len - payload_offset,
            );
            if (payload_capacity != 0) {
                const destination = scratch[wire_len..][0..payload_capacity];
                if (pending.compressed) {
                    const source = self.compression_send.payload.items[payload_offset..][0..payload_capacity];
                    if (pending.mask_key) |mask| {
                        try websocket.applyMaskCopy(
                            destination,
                            source,
                            mask,
                            payload_offset,
                        );
                    } else {
                        @memcpy(destination, source);
                    }
                } else {
                    try copyMessagePartsAt(
                        destination,
                        parts,
                        payload_offset,
                        pending.mask_key,
                    );
                }
                wire_len += payload_capacity;
            }

            var tunnel_progress: http2_runtime.TunnelWriteProgress = .{};
            self.tunnel.writeSlicesWithDeadline(
                &.{scratch[0..wire_len]},
                false,
                &tunnel_progress,
                deadline,
            ) catch |err| {
                pending.committed += tunnel_progress.committed_bytes;
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.totalLen(),
                };
                return err;
            };
            pending.committed += tunnel_progress.committed_bytes;
        }

        progress.* = .{
            .committed_bytes = pending.committed,
            .total_bytes = pending.totalLen(),
            .frame_committed = true,
        };
        if (pending.compressed) self.commitCompressionPreviewLocked();
        self.pending_message = null;
        self.application_write_pending.store(false, .release);
    }

    pub fn sendMessage(self: *H2Connection, opcode: websocket.Opcode, payload: []const u8) Error!void {
        if (opcode != .text and opcode != .binary) return error.InvalidFrame;
        if (!canSendOpcode(opcode, self.closeSent(), self.closeReceived())) {
            return error.ConnectionClosed;
        }
        try common.validateOutgoingMessage(self.limits, opcode, payload);
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.send_mutex.unlock(self.tunnel.connection.io);
        try self.ensureCanSendOpcodeLocked(opcode);

        if (self.permessage_deflate and
            payload.len >= self.compression_threshold)
        {
            const compressed = try self.compressMessageLocked(payload);
            if (compressed.len < payload.len) {
                self.writeFrameLockedExtended(
                    opcode,
                    compressed,
                    true,
                    .{ .rsv1 = true },
                ) catch |err| {
                    self.abortAfterUnboundedMessageWriteLocked();
                    return err;
                };
                self.commitCompressionPreviewLocked();
                return;
            }
            self.discardCompressionPreviewLocked();
        }
        self.writeFrameLocked(opcode, payload, true) catch |err| {
            self.abortAfterUnboundedMessageWriteLocked();
            return err;
        };
    }

    pub fn sendFragmented(self: *H2Connection, opcode: websocket.Opcode, fragments: []const []const u8) Error!void {
        if (!canSendOpcode(opcode, self.closeSent(), self.closeReceived())) {
            return error.ConnectionClosed;
        }
        const plain_len = try common.validateOutgoingFragments(
            self.limits,
            opcode,
            fragments,
        );

        if (self.permessage_deflate) {
            self.send_mutex.lockUncancelable(self.tunnel.connection.io);
            defer self.send_mutex.unlock(self.tunnel.connection.io);
            try self.ensureCanSendOpcodeLocked(opcode);
            if (plain_len >= self.compression_threshold) {
                const compressed = try self.compressMessagePartsLocked(
                    fragments,
                    plain_len,
                );
                if (compressed.len < plain_len) {
                    self.writeCompressedFragmentsLocked(
                        opcode,
                        compressed,
                        fragments.len,
                    ) catch |err| {
                        self.abortAfterUnboundedMessageWriteLocked();
                        return err;
                    };
                    self.commitCompressionPreviewLocked();
                    return;
                }
                self.discardCompressionPreviewLocked();
            }
            self.writeUncompressedFragmentsLocked(
                opcode,
                fragments,
            ) catch |err| {
                self.abortAfterUnboundedMessageWriteLocked();
                return err;
            };
            return;
        }

        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.send_mutex.unlock(self.tunnel.connection.io);
        try self.ensureCanSendOpcodeLocked(opcode);

        self.writeUncompressedFragmentsLocked(opcode, fragments) catch |err| {
            self.abortAfterUnboundedMessageWriteLocked();
            return err;
        };
    }

    pub fn sendFragmentedWithTimeout(
        self: *H2Connection,
        opcode: websocket.Opcode,
        fragments: []const []const u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendFragmentedWithDeadline(
            opcode,
            fragments,
            progress,
            .fromNow(self.tunnel.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendFragmentedWithDeadline(
        self: *H2Connection,
        opcode: websocket.Opcode,
        fragments: []const []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        const plain_len = try common.validateOutgoingFragments(
            self.limits,
            opcode,
            fragments,
        );
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.send_mutex.unlock(self.tunnel.connection.io);
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        if (self.pending_ping != null or self.pending_close != null) {
            return error.WriteInProgress;
        }
        if (self.pending_message) |*pending| {
            if (!pending.matchesFragments(opcode, fragments)) {
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.totalLen(),
                };
                return error.WriteInProgress;
            }
        } else {
            if (self.pending_auto_control != null) {
                return error.WriteInProgress;
            }
            try self.ensureCanSendOpcodeLocked(opcode);
            try self.beginPendingFragmentedLocked(
                opcode,
                fragments,
                plain_len,
            );
        }
        try self.resumePendingFragmentedLocked(
            fragments,
            progress,
            deadline,
        );
    }

    fn beginPendingFragmentedLocked(
        self: *H2Connection,
        opcode: websocket.Opcode,
        fragments: []const []const u8,
        plain_len: usize,
    ) Error!void {
        std.debug.assert(self.pending_message == null);
        var pending = PendingH2Message{
            .opcode = opcode,
            .source = .fragmented,
            .original_ptr = @intFromPtr(fragments.ptr),
            .original_len = fragments.len,
        };
        errdefer self.discardCompressionPreviewLocked();
        if (self.permessage_deflate and
            plain_len >= self.compression_threshold)
        {
            const compressed = try self.compressMessagePartsLocked(
                fragments,
                plain_len,
            );
            pending.compressed = compressed.len < plain_len;
            if (pending.compressed) {
                pending.fragmented_payload_total = compressed.len;
            } else {
                self.discardCompressionPreviewLocked();
            }
        }
        pending.wire_total = try fragmentedWireLen(
            fragments,
            if (pending.compressed) pending.fragmented_payload_total else null,
            self.role == .client,
        );
        self.pending_message = pending;
        self.application_write_pending.store(true, .release);
        errdefer {
            self.pending_message = null;
            self.application_write_pending.store(false, .release);
        }
        try self.preparePendingFragmentLocked(fragments, 0);
    }

    fn preparePendingFragmentLocked(
        self: *H2Connection,
        fragments: []const []const u8,
        index: usize,
    ) Error!void {
        const pending = &self.pending_message.?;
        std.debug.assert(pending.source == .fragmented);
        const range: message_state.FragmentRange = if (pending.compressed)
            compressedFragmentRange(
                pending.fragmented_payload_total,
                fragments.len,
                index,
            )
        else
            .{ .start = 0, .end = fragments[index].len };
        const mask_key: ?[4]u8 = if (self.role == .client) blk: {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.tunnel.connection.io, &key);
            break :blk key;
        } else null;
        var header_storage: [websocket.max_frame_header_len]u8 = undefined;
        const header = try websocket.writeFrameHeaderForLengthInto(
            &header_storage,
            if (index == 0) pending.opcode else .continuation,
            range.end - range.start,
            .{
                .fin = index + 1 == fragments.len,
                .mask_key = mask_key,
                .rsv1 = pending.compressed and index == 0,
            },
        );
        @memcpy(pending.header[0..header.len], header);
        pending.fragment_index = index;
        pending.payload_len = range.end - range.start;
        pending.fragment_start = pending.committed;
        pending.mask_key = mask_key;
        pending.header_len = header.len;
    }

    fn resumePendingFragmentedLocked(
        self: *H2Connection,
        fragments: []const []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.receiveFailed()) return error.ConnectionClosed;
        var scratch: [masked_write_scratch_len]u8 = undefined;
        while (self.pending_message) |*pending| {
            const frame_committed = pending.committed - pending.fragment_start;
            const header_offset = @min(frame_committed, pending.header_len);
            const payload_offset = frame_committed - header_offset;
            var len: usize = 0;
            if (header_offset < pending.header_len) {
                const header = pending.header[header_offset..pending.header_len];
                @memcpy(scratch[0..header.len], header);
                len = header.len;
            }
            const payload = if (pending.compressed) blk: {
                const range = compressedFragmentRange(
                    self.compression_send.payload.items.len,
                    fragments.len,
                    pending.fragment_index,
                );
                break :blk self.compression_send.payload.items[range.start..range.end];
            } else fragments[pending.fragment_index];
            const count = @min(scratch.len - len, payload.len - payload_offset);
            if (pending.mask_key) |mask| {
                try websocket.applyMaskCopy(
                    scratch[len..][0..count],
                    payload[payload_offset..][0..count],
                    mask,
                    payload_offset,
                );
            } else {
                @memcpy(
                    scratch[len..][0..count],
                    payload[payload_offset..][0..count],
                );
            }
            len += count;
            var tunnel_progress: http2_runtime.TunnelWriteProgress = .{};
            self.tunnel.writeWithDeadline(
                scratch[0..len],
                false,
                &tunnel_progress,
                deadline,
            ) catch |err| {
                pending.committed += tunnel_progress.committed_bytes;
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.wire_total,
                };
                return err;
            };
            pending.committed += tunnel_progress.committed_bytes;
            if (pending.committed - pending.fragment_start ==
                pending.header_len + pending.payload_len)
            {
                const next_index = pending.fragment_index + 1;
                if (next_index == fragments.len) {
                    progress.* = .{
                        .committed_bytes = pending.committed,
                        .total_bytes = pending.wire_total,
                        .frame_committed = true,
                    };
                    if (pending.compressed) {
                        self.commitCompressionPreviewLocked();
                    }
                    self.pending_message = null;
                    self.application_write_pending.store(false, .release);
                    return;
                }
                try self.preparePendingFragmentLocked(
                    fragments,
                    next_index,
                );
            }
        }
    }

    pub fn receiveFrame(self: *H2Connection) Error!websocket.Frame {
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameInternal(null);
    }

    fn receiveFrameInternal(
        self: *H2Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!websocket.Frame {
        if (self.receiveFailed()) return error.ConnectionClosed;
        try self.ensureNoPendingWrites();
        errdefer |err| closeAfterReceiveError(self, err, deadline);
        if (self.closeSent() and self.closeReceived()) return error.ConnectionClosed;
        try self.ensureBufferedWithDeadline(2, deadline);
        var available = message_buffer.unread(
            &self.inbuf,
            self.inbuf_consumed,
        );
        const second = available[1];
        var header_len: usize = 2;
        const len_code = second & 0x7f;
        if (len_code == 126) header_len += 2 else if (len_code == 127) header_len += 8;
        if ((second & 0x80) != 0) header_len += 4;
        try self.ensureBufferedWithDeadline(header_len, deadline);
        available = message_buffer.unread(
            &self.inbuf,
            self.inbuf_consumed,
        );
        const header = try websocket.FrameHeader.parse(available);
        const payload_len = std.math.cast(usize, header.payload_len) orelse return error.PayloadTooLarge;
        if (payload_len > self.limits.max_frame_bytes) return error.MessageTooLarge;
        const total_len = header.header_len + payload_len;
        try ensureIncomingFrameBuffered(self, header, total_len, deadline);
        available = message_buffer.unread(
            &self.inbuf,
            self.inbuf_consumed,
        );

        const parse_options: websocket.ParseFrameOptions = switch (self.role) {
            .client => .{
                .expect_mask = .unmasked,
                .allow_rsv1 = self.permessage_deflate,
                .validate_utf8 = false,
            },
            .server => .{
                .expect_mask = .masked,
                .allow_rsv1 = self.permessage_deflate,
                .validate_utf8 = false,
            },
        };
        var frame = try websocket.parseFrameWithHeader(
            self.allocator,
            available[0..total_len],
            header,
            parse_options,
        );
        errdefer frame.deinit(self.allocator);
        self.discardBuffered(frame.consumed);
        if (self.closeReceived() and frame.header.opcode != .close) return error.ConnectionClosed;
        if (self.compression_receive_context_takeover and
            !frame.header.opcode.isControl())
        {
            self.compression_receive.observeFrame(
                self.allocator,
                frame.header.opcode != .continuation,
                frame.header.rsv1,
                frame.header.opcode == .text,
                frame.header.fin,
                frame.payload,
                self.limits.max_message_bytes,
                self.compression_receive_max_window_bits,
            ) catch |err| switch (err) {
                error.PreviewPending => return error.InvalidFrame,
                error.OutOfMemory => {
                    _ = failReceive(self);
                    return error.OutOfMemory;
                },
                else => |other| return @errorCast(other),
            };
        }
        if (frame.header.opcode == .close) self.close_received.store(true, .release);
        return frame;
    }

    pub fn receiveFrameAuto(self: *H2Connection) Error!websocket.Frame {
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameAutoInternal(null, .frame);
    }

    pub fn receiveFrameAutoWithTimeout(
        self: *H2Connection,
        timeout: std.Io.Duration,
    ) Error!websocket.Frame {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameAutoInternal(
            .fromNow(
                self.tunnel.connection.io,
                .{ .raw = timeout, .clock = .awake },
            ),
            .frame,
        );
    }

    pub fn receiveFrameAutoWithDeadline(
        self: *H2Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!websocket.Frame {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameAutoInternal(deadline, .frame);
    }

    fn receiveFrameAutoInternal(
        self: *H2Connection,
        deadline: ?std.Io.Clock.Timestamp,
        delivery: PendingAutomaticControl.Delivery,
    ) Error!websocket.Frame {
        if (try self.pendingAutomaticControlOpcode(delivery)) |_| {
            if (try self.resumeAutomaticControl(deadline)) |frame| {
                return frame;
            }
            return self.receiveFrameAutoInternal(deadline, delivery);
        }
        while (true) {
            var frame = try self.receiveFrameInternal(deadline);
            switch (frame.header.opcode) {
                .ping => {
                    if (!canSendOpcode(
                        .pong,
                        self.closeSent(),
                        self.closeReceived(),
                    )) return frame;
                    self.beginAutomaticControl(
                        .pong,
                        frame.payload,
                        delivery,
                        frame,
                    ) catch |err| {
                        frame.deinit(self.allocator);
                        return err;
                    };
                    return (try self.resumeAutomaticControl(deadline)) orelse
                        unreachable;
                },
                .close => {
                    if (self.closeSent()) return frame;
                    self.beginAutomaticControl(
                        .close,
                        frame.payload,
                        delivery,
                        frame,
                    ) catch |err| {
                        frame.deinit(self.allocator);
                        return err;
                    };
                    return (try self.resumeAutomaticControl(deadline)) orelse
                        unreachable;
                },
                else => return frame,
            }
        }
    }

    pub fn receiveMessage(self: *H2Connection) Error!OwnedMessage {
        return self.receiveMessageInternal(null);
    }

    pub fn receiveMessageWithTimeout(
        self: *H2Connection,
        timeout: std.Io.Duration,
    ) Error!OwnedMessage {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveMessageInternal(.fromNow(
            self.tunnel.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// Receive one RFC 8441 message under a caller-owned absolute deadline.
    /// HTTP/2 connection-control frames and WebSocket control frames share the
    /// same deadline rather than extending upper-layer inactivity budgets.
    pub fn receiveMessageWithDeadline(
        self: *H2Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedMessage {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        return self.receiveMessageInternal(deadline);
    }

    fn receiveMessageInternal(
        self: *H2Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!OwnedMessage {
        if (self.receiveFailed()) return error.ConnectionClosed;
        if (self.message_into.active()) return error.InvalidFrame;
        if (try self.pendingAutomaticControlOpcode(.message)) |opcode| {
            std.debug.assert((try self.resumeAutomaticControl(deadline)) == null);
            if (opcode == .close) return error.ConnectionClosed;
        }
        try self.ensureNoPendingWrites();
        errdefer |err| closeAfterReceiveError(self, err, deadline);
        if (self.message_assembler == null) {
            self.message_assembler = websocket.MessageAssembler.initLimited(
                self.allocator,
                self.limits.max_message_bytes,
            );
        }

        while (true) {
            const frame = try receiveMessageFrameBorrowed(self, deadline);
            switch (frame.header.opcode) {
                .ping => {
                    if (canSendOpcode(
                        .pong,
                        self.closeSent(),
                        self.closeReceived(),
                    )) {
                        try self.beginAutomaticControl(
                            .pong,
                            frame.payload,
                            .message,
                            null,
                        );
                    }
                    self.discardBuffered(frame.consumed);
                    if (self.pending_auto_control != null) {
                        std.debug.assert(
                            (try self.resumeAutomaticControl(deadline)) == null,
                        );
                    }
                    continue;
                },
                .pong => {
                    self.discardBuffered(frame.consumed);
                    continue;
                },
                .close => {
                    self.close_received.store(true, .release);
                    self.message_assembler.?.deinit();
                    self.message_assembler = null;
                    if (!self.closeSent()) {
                        try self.beginAutomaticControl(
                            .close,
                            frame.payload,
                            .message,
                            null,
                        );
                    }
                    self.discardBuffered(frame.consumed);
                    if (self.pending_auto_control != null) {
                        std.debug.assert(
                            (try self.resumeAutomaticControl(deadline)) == null,
                        );
                    }
                    return error.ConnectionClosed;
                },
                else => {
                    const maybe_message = self.message_assembler.?.feedUtf8Validated(
                        frame,
                        self.incoming_text_utf8,
                    ) catch |err| {
                        self.discardBuffered(frame.consumed);
                        self.message_assembler.?.deinit();
                        self.message_assembler = null;
                        return @errorCast(err);
                    };
                    self.discardBuffered(frame.consumed);
                    if (maybe_message) |message| {
                        self.message_assembler.?.deinit();
                        self.message_assembler = null;
                        return finishIncomingMessageForConnection(
                            self,
                            message,
                        );
                    }
                },
            }
        }
    }

    /// Receive one complete message into caller-owned storage.
    ///
    /// HTTP/2 tunnel chunks may split WebSocket frame headers or payloads. This
    /// adapter decodes uncompressed fragments directly into `out`; compressed
    /// input uses only the reusable codec scratch before inflating into `out`.
    pub fn receiveMessageInto(
        self: *H2Connection,
        out: []u8,
    ) Error!Message {
        return receiveMessageIntoDirectConnection(self, out, null);
    }

    pub fn receiveMessageIntoWithTimeout(
        self: *H2Connection,
        out: []u8,
        timeout: std.Io.Duration,
    ) Error!Message {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return receiveMessageIntoDirectConnection(
            self,
            out,
            .fromNow(
                self.tunnel.connection.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    /// RFC 8441 caller-buffer receive under one absolute deadline. HTTP/2
    /// connection-control and WebSocket control frames cannot renew it.
    pub fn receiveMessageIntoWithDeadline(
        self: *H2Connection,
        out: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Message {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        return receiveMessageIntoDirectConnection(self, out, deadline);
    }

    fn ensureCompressionReceiveScratch(self: *H2Connection) Error!void {
        if (self.compression_receive_context_takeover) {
            try self.compression_receive.prepareContext(
                self.allocator,
                self.limits.max_message_bytes,
            );
        } else {
            try self.compression_receive.prepare(
                self.allocator,
                self.limits.max_message_bytes,
            );
        }
    }

    fn compressMessageLocked(
        self: *H2Connection,
        payload: []const u8,
    ) Error![]const u8 {
        if (self.compression_send_context_takeover) {
            return self.compression_send.preview(
                self.allocator,
                payload,
                self.compression_send_max_window_bits,
            ) catch |err| switch (err) {
                error.PreviewPending => error.WriteInProgress,
                else => |other| @errorCast(other),
            };
        }
        try self.compression_send.prepare(
            self.allocator,
            payload.len,
        );
        return websocket.compressMessageVortIntoWindowWithEncoder(
            &self.compression_send.encoder.?,
            &self.compression_send.payload,
            payload,
            self.compression_send_max_window_bits,
        );
    }

    fn compressMessagePartsLocked(
        self: *H2Connection,
        parts: []const []const u8,
        payload_len: usize,
    ) Error![]const u8 {
        if (self.compression_send_context_takeover) {
            return self.compression_send.previewFragments(
                self.allocator,
                parts,
                payload_len,
                self.compression_send_max_window_bits,
            ) catch |err| switch (err) {
                error.PreviewPending => error.WriteInProgress,
                else => |other| @errorCast(other),
            };
        }
        try self.compression_send.prepare(
            self.allocator,
            payload_len,
        );
        return websocket.compressMessageFragmentsVortIntoWindowWithEncoder(
            &self.compression_send.encoder.?,
            &self.compression_send.payload,
            parts,
            self.compression_send_max_window_bits,
        );
    }

    fn commitCompressionPreviewLocked(self: *H2Connection) void {
        if (self.compression_send_context_takeover) {
            self.compression_send.commitPreview() catch unreachable;
        }
    }

    fn discardCompressionPreviewLocked(self: *H2Connection) void {
        if (self.compression_send_context_takeover) {
            self.compression_send.discardPreview();
        }
    }

    fn abortAfterUnboundedMessageWriteLocked(self: *H2Connection) void {
        self.discardCompressionPreviewLocked();
        self.abortTunnelAfterReceiveFailureLocked(null);
    }

    fn writeFrameLocked(self: *H2Connection, opcode: websocket.Opcode, payload: []const u8, fin: bool) Error!void {
        try self.writeFrameLockedExtended(opcode, payload, fin, .{});
    }

    fn writeFrameLockedExtended(
        self: *H2Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
        fin: bool,
        options: struct { rsv1: bool = false },
    ) Error!void {
        const mask_key = if (self.role == .client) blk: {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.tunnel.connection.io, &key);
            break :blk key;
        } else null;
        if (opcode.isControl()) {
            // Control payloads are capped at 125 bytes by RFC 6455, so keep
            // their complete frame on the stack. This also avoids retaining a
            // growable buffer solely for tiny Ping/Pong/Close writes.
            var encoded_storage: [websocket.max_frame_header_len + 125]u8 =
                undefined;
            const frame = try websocket.writeFrameInto(
                &encoded_storage,
                opcode,
                payload,
                .{
                    .fin = fin,
                    .mask_key = mask_key,
                    .rsv1 = options.rsv1,
                },
            );
            try self.tunnel.write(frame, opcode == .close);
            return;
        }
        if (mask_key == null) {
            // RFC 8441 server frames do not require masking. Keep the frame
            // header on the stack and let HTTP/2 frame the header plus borrowed
            // application payload as one ordered tunnel byte sequence.
            var header_storage: [websocket.max_frame_header_len]u8 = undefined;
            const header = try websocket.writeFrameHeaderInto(
                &header_storage,
                opcode,
                payload,
                .{
                    .fin = fin,
                    .rsv1 = options.rsv1,
                },
            );
            try self.tunnel.writeParts(header, payload, false);
            return;
        }
        var header_storage: [websocket.max_frame_header_len]u8 = undefined;
        const header = try websocket.writeFrameHeaderInto(
            &header_storage,
            opcode,
            payload,
            .{
                .fin = fin,
                .mask_key = mask_key,
                .rsv1 = options.rsv1,
            },
        );
        const payload_parts = [_][]const u8{payload};
        try writeMaskedTunnelPayloadSlices(
            &self.tunnel,
            header,
            &payload_parts,
            mask_key.?,
        );
    }

    fn writeCompressedFragmentsLocked(
        self: *H2Connection,
        opcode: websocket.Opcode,
        compressed_payload: []const u8,
        frame_count: usize,
    ) Error!void {
        const max_batched_frames: usize = 16;
        var writer = try self.tunnel.beginWriteSequence();
        var frame_index: usize = 0;
        while (frame_index < frame_count) {
            const batch_count = @min(
                max_batched_frames,
                frame_count - frame_index,
            );
            var headers: [max_batched_frames][websocket.max_frame_header_len]u8 = undefined;
            var parts: [max_batched_frames * 2][]const u8 = undefined;

            if (self.role == .client) {
                // Each RFC 6455 fragment has its own mask key. Batch only when
                // all encoded payload bytes fit bounded stack storage; larger
                // compressed messages stream one frame at a time below.
                var masked: [masked_write_scratch_len]u8 align(64) = undefined;
                var mask_keys: [max_batched_frames][4]u8 = undefined;
                try common.randomMaskKeys(
                    self.tunnel.connection.io,
                    mask_keys[0..batch_count],
                );
                var masked_len: usize = 0;
                var fits = true;
                for (0..batch_count) |batch_index| {
                    const index = frame_index + batch_index;
                    const range = compressedFragmentRange(
                        compressed_payload.len,
                        frame_count,
                        index,
                    );
                    if (range.end - range.start >
                        masked.len - masked_len)
                    {
                        fits = false;
                        break;
                    }
                    const payload = compressed_payload[range.start..range.end];
                    const mask_key = mask_keys[batch_index];
                    parts[batch_index * 2] =
                        try websocket.writeFrameHeaderInto(
                            &headers[batch_index],
                            if (index == 0) opcode else .continuation,
                            payload,
                            .{
                                .fin = index + 1 == frame_count,
                                .mask_key = mask_key,
                                .rsv1 = index == 0,
                            },
                        );
                    try websocket.applyMaskCopy(
                        masked[masked_len..][0..payload.len],
                        payload,
                        mask_key,
                        0,
                    );
                    parts[batch_index * 2 + 1] =
                        masked[masked_len..][0..payload.len];
                    masked_len += payload.len;
                }
                if (fits) {
                    const part_count = std.math.mul(
                        usize,
                        batch_count,
                        2,
                    ) catch return error.PayloadTooLarge;
                    try writer.writeSlices(
                        parts[0..part_count],
                        false,
                    );
                    frame_index += batch_count;
                    continue;
                }

                const range = compressedFragmentRange(
                    compressed_payload.len,
                    frame_count,
                    frame_index,
                );
                const payload = compressed_payload[range.start..range.end];
                var mask_key: [4]u8 = undefined;
                try std.Io.randomSecure(
                    self.tunnel.connection.io,
                    &mask_key,
                );
                const header = try websocket.writeFrameHeaderInto(
                    &headers[0],
                    if (frame_index == 0) opcode else .continuation,
                    payload,
                    .{
                        .fin = frame_index + 1 == frame_count,
                        .mask_key = mask_key,
                        .rsv1 = frame_index == 0,
                    },
                );
                const payload_parts = [_][]const u8{payload};
                try writeMaskedTunnelPayloadSlicesWithWriter(
                    &writer,
                    header,
                    &payload_parts,
                    mask_key,
                );
                frame_index += 1;
                continue;
            }

            for (0..batch_count) |batch_index| {
                const index = frame_index + batch_index;
                const range = compressedFragmentRange(
                    compressed_payload.len,
                    frame_count,
                    index,
                );
                const payload = compressed_payload[range.start..range.end];
                parts[batch_index * 2] = try websocket.writeFrameHeaderInto(
                    &headers[batch_index],
                    if (index == 0) opcode else .continuation,
                    payload,
                    .{
                        .fin = index + 1 == frame_count,
                        .rsv1 = index == 0,
                    },
                );
                parts[batch_index * 2 + 1] = payload;
            }
            const part_count = std.math.mul(
                usize,
                batch_count,
                2,
            ) catch return error.PayloadTooLarge;
            try writer.writeSlices(parts[0..part_count], false);
            frame_index += batch_count;
        }
    }

    fn writeUncompressedFragmentsLocked(
        self: *H2Connection,
        opcode: websocket.Opcode,
        fragments: []const []const u8,
    ) Error!void {
        const max_batched_frames: usize = 16;
        var writer = try self.tunnel.beginWriteSequence();
        var frame_index: usize = 0;
        while (frame_index < fragments.len) {
            const batch_count = @min(
                max_batched_frames,
                fragments.len - frame_index,
            );
            var headers: [max_batched_frames][websocket.max_frame_header_len]u8 = undefined;
            var parts: [max_batched_frames * 2][]const u8 = undefined;

            if (self.role == .client) {
                var masked: [masked_write_scratch_len]u8 align(64) = undefined;
                var mask_keys: [max_batched_frames][4]u8 = undefined;
                try common.randomMaskKeys(
                    self.tunnel.connection.io,
                    mask_keys[0..batch_count],
                );
                var masked_len: usize = 0;
                var fits = true;
                for (0..batch_count) |batch_index| {
                    const index = frame_index + batch_index;
                    const payload = fragments[index];
                    if (payload.len > masked.len - masked_len) {
                        fits = false;
                        break;
                    }
                    const mask_key = mask_keys[batch_index];
                    parts[batch_index * 2] =
                        try websocket.writeFrameHeaderInto(
                            &headers[batch_index],
                            if (index == 0) opcode else .continuation,
                            payload,
                            .{
                                .fin = index + 1 == fragments.len,
                                .mask_key = mask_key,
                            },
                        );
                    try websocket.applyMaskCopy(
                        masked[masked_len..][0..payload.len],
                        payload,
                        mask_key,
                        0,
                    );
                    parts[batch_index * 2 + 1] =
                        masked[masked_len..][0..payload.len];
                    masked_len += payload.len;
                }
                if (fits) {
                    const part_count = std.math.mul(
                        usize,
                        batch_count,
                        2,
                    ) catch return error.PayloadTooLarge;
                    try writer.writeSlices(parts[0..part_count], false);
                    frame_index += batch_count;
                    continue;
                }

                const payload = fragments[frame_index];
                var mask_key: [4]u8 = undefined;
                try std.Io.randomSecure(
                    self.tunnel.connection.io,
                    &mask_key,
                );
                const header = try websocket.writeFrameHeaderInto(
                    &headers[0],
                    if (frame_index == 0) opcode else .continuation,
                    payload,
                    .{
                        .fin = frame_index + 1 == fragments.len,
                        .mask_key = mask_key,
                    },
                );
                const payload_parts = [_][]const u8{payload};
                try writeMaskedTunnelPayloadSlicesWithWriter(
                    &writer,
                    header,
                    &payload_parts,
                    mask_key,
                );
                frame_index += 1;
                continue;
            }

            for (0..batch_count) |batch_index| {
                const index = frame_index + batch_index;
                const payload = fragments[index];
                parts[batch_index * 2] = try websocket.writeFrameHeaderInto(
                    &headers[batch_index],
                    if (index == 0) opcode else .continuation,
                    payload,
                    .{ .fin = index + 1 == fragments.len },
                );
                parts[batch_index * 2 + 1] = payload;
            }
            const part_count = std.math.mul(
                usize,
                batch_count,
                2,
            ) catch return error.PayloadTooLarge;
            try writer.writeSlices(parts[0..part_count], false);
            frame_index += batch_count;
        }
    }

    fn ensureBuffered(self: *H2Connection, len: usize) Error!void {
        return self.ensureBufferedWithDeadline(len, null);
    }

    fn ensureBufferedWithDeadline(
        self: *H2Connection,
        len: usize,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        while (message_buffer.unreadLen(
            &self.inbuf,
            self.inbuf_consumed,
        ) < len) {
            if (self.receive_finished) return error.ConnectionClosed;
            const count = try self.appendTunnelDataChunk(deadline);
            if (count == 0) return error.ConnectionClosed;
        }
    }

    fn ensureBufferedExactWithDeadline(
        self: *H2Connection,
        len: usize,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        while (message_buffer.unreadLen(
            &self.inbuf,
            self.inbuf_consumed,
        ) < len) {
            if (self.receive_finished) return error.ConnectionClosed;
            const missing = len - message_buffer.unreadLen(
                &self.inbuf,
                self.inbuf_consumed,
            );
            const destination = try message_buffer.reserveAppendAfterConsumed(
                &self.inbuf,
                &self.inbuf_consumed,
                self.allocator,
                missing,
            );
            const count = try self.readMessagePayloadChunk(
                destination,
                deadline,
            );
            if (count == 0) return error.ConnectionClosed;
            message_buffer.commitAppend(&self.inbuf, count);
        }
    }

    fn appendTunnelDataChunk(
        self: *H2Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!usize {
        while (true) {
            if (self.pending_tunnel_data) |*pending| {
                const remaining =
                    pending.data[self.pending_tunnel_data_offset..];
                try message_buffer.appendAfterConsumed(
                    &self.inbuf,
                    &self.inbuf_consumed,
                    self.allocator,
                    remaining,
                );
                const count = remaining.len;
                const end_stream = pending.end_stream;
                pending.deinit(self.tunnel.connection.allocator);
                self.pending_tunnel_data = null;
                self.pending_tunnel_data_offset = 0;
                if (end_stream) self.receive_finished = true;
                return count;
            }
            if (self.receive_finished) return 0;
            const data = if (deadline) |absolute|
                try self.tunnel.readWithDeadline(absolute)
            else
                try self.tunnel.read();
            if (data.data.len == 0) {
                const end_stream = data.end_stream;
                var empty = data;
                empty.deinit(self.tunnel.connection.allocator);
                if (end_stream) {
                    self.receive_finished = true;
                    return 0;
                }
                continue;
            }
            self.pending_tunnel_data = data;
        }
    }

    fn readMessagePayloadChunk(
        self: *H2Connection,
        out: []u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!usize {
        std.debug.assert(out.len != 0);
        while (true) {
            if (self.pending_tunnel_data) |*pending| {
                const remaining =
                    pending.data[self.pending_tunnel_data_offset..];
                const count = @min(out.len, remaining.len);
                @memcpy(out[0..count], remaining[0..count]);
                self.pending_tunnel_data_offset += count;
                if (self.pending_tunnel_data_offset == pending.data.len) {
                    const end_stream = pending.end_stream;
                    pending.deinit(self.tunnel.connection.allocator);
                    self.pending_tunnel_data = null;
                    self.pending_tunnel_data_offset = 0;
                    if (end_stream) self.receive_finished = true;
                }
                return count;
            }
            if (self.receive_finished) return 0;
            const data = if (deadline) |absolute|
                try self.tunnel.readWithDeadline(absolute)
            else
                try self.tunnel.read();
            if (data.data.len == 0) {
                const end_stream = data.end_stream;
                var empty = data;
                empty.deinit(self.tunnel.connection.allocator);
                if (end_stream) {
                    self.receive_finished = true;
                    return 0;
                }
                continue;
            }
            self.pending_tunnel_data = data;
        }
    }

    fn discardBuffered(self: *H2Connection, len: usize) void {
        _ = message_buffer.discardPrefix(
            &self.inbuf,
            &self.inbuf_consumed,
            len,
        );
    }

    /// Same post-lock invariant as the TCP/TLS adapter: no RFC 8441 DATA may
    /// be queued after an earlier writer has committed the Close frame.
    fn canSendOpcodeLocked(
        self: *const H2Connection,
        opcode: websocket.Opcode,
    ) bool {
        if (self.writeAborted()) return false;
        if (self.receiveFailed()) return false;
        return canSendOpcode(opcode, self.closeSent(), self.closeReceived());
    }

    fn ensureCanSendOpcodeLocked(
        self: *const H2Connection,
        opcode: websocket.Opcode,
    ) Error!void {
        if (self.pending_message != null) return error.WriteInProgress;
        if (self.pending_ping != null) return error.WriteInProgress;
        if (self.pending_close != null) return error.WriteInProgress;
        if (self.pending_auto_control != null) return error.WriteInProgress;
        if (!self.canSendOpcodeLocked(opcode)) return error.ConnectionClosed;
    }

    fn closeSent(self: *const H2Connection) bool {
        return self.close_sent.load(.acquire);
    }

    fn closeReceived(self: *const H2Connection) bool {
        return self.receiveFailed() or self.close_received.load(.acquire);
    }

    fn receiveFailed(self: *const H2Connection) bool {
        return self.receive_failed.load(.acquire);
    }

    fn writeAborted(self: *const H2Connection) bool {
        return self.write_aborted.load(.acquire);
    }

    fn ensureNoPendingWrites(self: *H2Connection) Error!void {
        if (self.application_write_pending.load(.acquire) or
            self.automatic_write_pending.load(.acquire))
        {
            return error.WriteInProgress;
        }
    }

    fn pendingAutomaticControlOpcode(
        self: *H2Connection,
        delivery: PendingAutomaticControl.Delivery,
    ) Error!?websocket.Opcode {
        if (!self.automatic_write_pending.load(.acquire)) return null;
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.send_mutex.unlock(self.tunnel.connection.io);
        const pending = self.pending_auto_control orelse return null;
        if (pending.delivery != delivery) return error.WriteInProgress;
        return pending.opcode;
    }

    fn abortTunnelAfterReceiveFailureLocked(
        self: *H2Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) void {
        self.write_aborted.store(true, .release);
        self.tunnel.abort(deadline);
        common.clearPendingOutboundLocked(self);
    }

    fn finishReceiveFailure(
        self: *H2Connection,
        code: websocket.CloseCode,
        deadline: ?std.Io.Clock.Timestamp,
    ) void {
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.send_mutex.unlock(self.tunnel.connection.io);
        if (self.pending_message != null or
            self.pending_ping != null or
            self.pending_close != null or
            self.pending_auto_control != null)
        {
            self.abortTunnelAfterReceiveFailureLocked(deadline);
            return;
        }
        if (self.closeSent()) return;
        var storage: [125]u8 = undefined;
        const payload = websocket.writeClosePayloadInto(
            &storage,
            .{ .code = code },
        ) catch return;
        if (deadline) |absolute| {
            self.beginPendingCloseLocked(payload) catch return;
            self.resumePendingCloseLocked(absolute) catch {
                self.abortTunnelAfterReceiveFailureLocked(deadline);
            };
            return;
        }
        self.writeFrameLocked(.close, payload, true) catch {
            self.abortTunnelAfterReceiveFailureLocked(deadline);
            return;
        };
        self.close_sent.store(true, .release);
    }

    fn finishAbruptReceiveEnd(
        self: *H2Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) void {
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.send_mutex.unlock(self.tunnel.connection.io);
        self.abortTunnelAfterReceiveFailureLocked(deadline);
    }

    fn beginAutomaticControl(
        self: *H2Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
        delivery: PendingAutomaticControl.Delivery,
        frame: ?websocket.Frame,
    ) Error!void {
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.send_mutex.unlock(self.tunnel.connection.io);
        if (self.pending_auto_control != null) return error.WriteInProgress;

        var pending = PendingAutomaticControl{
            .opcode = opcode,
            .delivery = delivery,
            .frame = frame,
        };
        const mask_key = if (self.role == .client) blk: {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.tunnel.connection.io, &key);
            break :blk key;
        } else null;
        const encoded = try websocket.writeFrameInto(
            &pending.bytes,
            opcode,
            payload,
            .{ .mask_key = mask_key },
        );
        pending.len = encoded.len;
        self.pending_auto_control = pending;
        self.automatic_write_pending.store(true, .release);
    }

    fn resumeAutomaticControl(
        self: *H2Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!?websocket.Frame {
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.send_mutex.unlock(self.tunnel.connection.io);
        const pending = if (self.pending_auto_control) |*value|
            value
        else
            return null;
        if (self.pending_message != null or
            self.pending_ping != null or
            self.pending_close != null)
        {
            return error.WriteInProgress;
        }
        if (!self.canSendOpcodeLocked(pending.opcode)) {
            pending.writes_reply = false;
        }
        var progress: http2_runtime.TunnelWriteProgress = .{};
        if (!pending.complete() and deadline != null) {
            const absolute = deadline.?;
            _ = try deadline_policy.usableAwake(
                self.tunnel.connection.io,
                absolute,
            );
            self.tunnel.writeWithDeadline(
                pending.bytes[pending.committed..pending.len],
                pending.opcode == .close,
                &progress,
                absolute,
            ) catch |err| {
                pending.committed += progress.committed_bytes;
                pending.fin_committed =
                    pending.fin_committed or progress.fin_committed;
                return err;
            };
        } else if (!pending.complete()) {
            self.tunnel.write(
                pending.bytes[pending.committed..pending.len],
                pending.opcode == .close,
            ) catch |err| {
                self.abortAfterUnboundedMessageWriteLocked();
                return err;
            };
            progress.committed_bytes = pending.len - pending.committed;
            progress.fin_committed = pending.opcode == .close;
        }
        pending.committed += progress.committed_bytes;
        pending.fin_committed = pending.fin_committed or progress.fin_committed;
        std.debug.assert(pending.complete());
        if (pending.opcode == .close) {
            self.close_sent.store(true, .release);
        }
        const frame = pending.frame;
        pending.frame = null;
        std.crypto.secureZero(u8, &pending.bytes);
        self.pending_auto_control = null;
        self.automatic_write_pending.store(false, .release);
        return frame;
    }
};

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
        const request_count = std.math.add(
            usize,
            1 + @as(usize, @intFromBool(protocol_value.value.len != 0)) +
                @as(usize, @intFromBool(options.origin != null)) +
                @as(usize, @intFromBool(options.enable_permessage_deflate)),
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
        if (websocket.ExtensionNegotiation.offerValue(.{
            .enable_permessage_deflate = options.enable_permessage_deflate,
            .allow_context_takeover = options.allow_context_takeover,
        })) |extension_offer| {
            request_headers[request_index] = .{
                .name = "sec-websocket-extensions",
                .value = extension_offer,
            };
            request_index += 1;
        }
        @memcpy(request_headers[request_index..], options.extra_headers);

        const request_options: http2_runtime.RequestOptions = .{
            .method = "CONNECT",
            .path = options.path,
            .scheme = options.scheme,
            .authority = options.authority,
            .protocol = "websocket",
            .headers = request_headers,
        };
        const response = if (deadline) |absolute|
            try connection.openExtendedConnectAttemptWithDeadline(
                request_options,
                absolute,
            )
        else
            try connection.openExtendedConnectAttempt(request_options);
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
        if (!self.accepted()) return error.InvalidStatus;
        const selected_protocol = try validateH2ServerHandshake(
            self.allocator,
            self.response.headers,
            self.options.protocols,
        );
        errdefer if (selected_protocol) |protocol| {
            self.allocator.free(protocol);
        };
        const extension_policy: websocket.ExtensionNegotiation.Policy = .{
            .enable_permessage_deflate = self.options.enable_permessage_deflate,
            .allow_context_takeover = self.options.allow_context_takeover,
        };
        const selected_extension = try websocket.ExtensionNegotiation
            .validateResponseForOfferWithPolicy(
            try optionalH2SingletonHeader(
                self.response.headers,
                "sec-websocket-extensions",
            ),
            websocket.ExtensionNegotiation.offerValue(extension_policy),
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
            connection.abandonExtendedConnect(stream_id);
        };
        const version = try requiredH2SingletonHeader(request.headers, "sec-websocket-version");
        if (!std.mem.eql(u8, version, "13")) return error.InvalidHandshake;
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

    /// Cancel only the pending stream. The shared HTTP/2 connection remains
    /// caller-owned and can continue serving sibling streams.
    pub fn deinit(self: *PendingH2Upgrade) void {
        const allocator = self.allocator;
        const connection = self.connection;
        const stream_id = self.request.stream_id;
        self.request.deinit(allocator);
        if (self.selected_protocol) |protocol| allocator.free(protocol);
        if (self.selected_extension) |extension| allocator.free(extension);
        self.* = undefined;
        connection.abandonExtendedConnect(stream_id);
    }

    pub fn streamId(self: PendingH2Upgrade) u31 {
        return self.request.stream_id;
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
        const tunnel = try self.connection.acceptExtendedConnect(
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
        try self.connection.rejectExtendedConnectWithBody(
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
        const pending = connection.pending_close orelse return null;
        return .{ .committed = pending.committed, .total = pending.len };
    }

    pub fn pendingH2PingProgress(
        connection: *const H2Connection,
    ) ?struct { committed: usize, total: usize } {
        const pending = connection.pending_ping orelse return null;
        return .{ .committed = pending.committed, .total = pending.len };
    }

    pub fn pendingH2AutomaticControlProgress(
        connection: *const H2Connection,
    ) ?struct {
        opcode: websocket.Opcode,
        committed: usize,
        total: usize,
        retains_frame: bool,
    } {
        const pending = connection.pending_auto_control orelse return null;
        return .{
            .opcode = pending.opcode,
            .committed = pending.committed,
            .total = pending.len,
            .retains_frame = pending.frame != null,
        };
    }

    pub fn pendingH2MessageProgress(
        connection: *const H2Connection,
    ) ?MessageWriteProgress {
        const pending = connection.pending_message orelse return null;
        return .{
            .committed_bytes = pending.committed,
            .total_bytes = pending.totalLen(),
        };
    }

    pub fn pendingMessageProgress(
        connection: *const Connection,
    ) ?MessageWriteProgress {
        const pending = connection.pending_message orelse return null;
        return .{
            .committed_bytes = pending.committed,
            .total_bytes = pending.totalLen(),
        };
    }

    pub fn pendingPingProgress(
        connection: *const Connection,
    ) ?struct { committed: usize, total: usize } {
        const pending = connection.pending_ping orelse return null;
        return .{ .committed = pending.committed, .total = pending.len };
    }

    pub fn pendingAutomaticControlProgress(
        connection: *const Connection,
    ) ?struct {
        opcode: websocket.Opcode,
        committed: usize,
        total: usize,
        retains_frame: bool,
    } {
        const pending = connection.pending_auto_control orelse return null;
        return .{
            .opcode = pending.opcode,
            .committed = pending.committed,
            .total = pending.len,
            .retains_frame = pending.frame != null,
        };
    }

    pub fn pendingCloseProgress(
        connection: *const Connection,
    ) ?struct { committed: usize, total: usize } {
        const pending = connection.pending_close orelse return null;
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
            connection.compression_receive.flate_window == null and
            connection.compression_receive.context == null and
            tunnel_storage_released;
    }

    pub fn writeAborted(connection: anytype) bool {
        return connection.writeAborted();
    }

    pub fn outboundStorageReleased(connection: anytype) bool {
        return connection.pending_message == null and
            connection.pending_ping == null and
            connection.pending_close == null and
            connection.pending_auto_control == null and
            !connection.application_write_pending.load(.acquire) and
            !connection.automatic_write_pending.load(.acquire) and
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
            .ping => connection.beginPendingControlLocked(
                &connection.pending_ping,
                opcode,
                payload,
            ),
            .close => connection.beginPendingControlLocked(
                &connection.pending_close,
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
            .ping => if (connection.pending_ping) |*pending|
                pending.bytes[0..pending.len]
            else
                null,
            .close => if (connection.pending_close) |*pending|
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
            .ping => connection.pending_ping = null,
            .close => connection.pending_close = null,
            else => unreachable,
        }
        connection.application_write_pending.store(false, .release);
    }

    pub fn writePendingControlPrefix(
        connection: *Connection,
        opcode: websocket.Opcode,
        end: usize,
    ) Error!void {
        const pending = switch (opcode) {
            .ping => if (connection.pending_ping) |*value| value else return error.InvalidFrame,
            .close => if (connection.pending_close) |*value| value else return error.InvalidFrame,
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
        std.debug.assert(connection.pending_message != null);
        std.debug.assert(
            committed <= connection.pending_message.?.totalLen(),
        );
        connection.pending_message.?.committed = committed;
    }

    pub fn markPendingControlCommitted(
        connection: anytype,
        opcode: websocket.Opcode,
        committed: usize,
    ) void {
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
        const pending = &connection.pending_message.?;
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
            .limits = limits,
        };
    }

    pub fn copyPendingMessageChunk(
        connection: *Connection,
        payload: []const u8,
        committed: usize,
        out: []u8,
    ) Error![]const u8 {
        connection.pending_message.?.committed = committed;
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
    /// Optional browser Origin value sent as a regular RFC 8441 header.
    origin: ?[]const u8 = null,
    extra_headers: []const http2.Hpack.HeaderField = &.{},
    enable_permessage_deflate: bool = false,
    /// Offer RFC 7692 context takeover on this Extended CONNECT stream.
    allow_context_takeover: bool = false,
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
    /// RFC 8441 outbound compression threshold.
    compression_threshold: usize = default_compression_threshold,
    limits: Limits = .{},
};

const canSendOpcode = message_state.canSendOpcode;

fn receiveMessageFrameBorrowed(
    connection: anytype,
    deadline: ?std.Io.Clock.Timestamp,
) Error!websocket.BorrowedFrame {
    if (connection.receiveFailed()) return error.ConnectionClosed;
    if (comptime @hasField(@TypeOf(connection.*), "pending_message")) {
        if (connection.pending_message != null) return error.WriteInProgress;
    }
    if (comptime @hasField(@TypeOf(connection.*), "pending_ping")) {
        if (connection.pending_ping != null) return error.WriteInProgress;
    }
    if (comptime @hasField(@TypeOf(connection.*), "pending_close")) {
        if (connection.pending_close != null) return error.WriteInProgress;
    }
    if (comptime @hasField(
        @TypeOf(connection.*),
        "pending_auto_control",
    )) {
        if (connection.pending_auto_control != null) {
            return error.WriteInProgress;
        }
    }
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

fn receiveMessageIntoDirectConnection(
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
    errdefer |err| if (err != error.Timeout and
        err != error.ResponseAvailable)
    {
        connection.message_into.reset();
        connection.message_frame_receive.reset();
    };
    if (comptime @hasField(
        @TypeOf(connection.*),
        "pending_auto_control",
    )) {
        if (try connection.pendingAutomaticControlOpcode(.message)) |opcode| {
            std.debug.assert(
                (try connection.resumeAutomaticControl(deadline)) == null,
            );
            if (opcode == .close) return error.ConnectionClosed;
        }
    }
    try connection.ensureNoPendingWrites();

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
                    try connection.beginAutomaticControl(
                        .pong,
                        frame.payload,
                        .message,
                        null,
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
                    try connection.beginAutomaticControl(
                        .close,
                        frame.payload,
                        .message,
                        null,
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

        const message_opcode = connection.message_into.opcode orelse
            return error.InvalidFrame;
        const was_compressed = connection.message_into.compressed;
        const payload = if (was_compressed)
            if (connection.compression_receive_context_takeover)
                connection.compression_receive.previewContextInto(
                    connection.allocator,
                    out[0..connection.limits.max_message_bytes],
                    connection.compression_receive.payload.items[0..connection.message_into.written],
                    connection.compression_receive_max_window_bits,
                ) catch |err| switch (err) {
                    error.PreviewPending => return error.InvalidFrame,
                    error.OutOfMemory => {
                        _ = failReceive(connection);
                        return error.OutOfMemory;
                    },
                    else => |other| return @errorCast(other),
                }
            else
                try websocket.decompressMessageInto(
                    out[0..connection.limits.max_message_bytes],
                    connection.compression_receive.payload.items[0..connection.message_into.written],
                    connection.compression_receive.payload.allocatedSlice(),
                    connection.compression_receive.flate_window.?,
                )
        else
            out[0..connection.message_into.written];
        if (connection.message_into.payloadNeedsFinalUtf8Validation() and
            !std.unicode.utf8ValidateSlice(payload))
        {
            if (connection.compression_receive_context_takeover) {
                connection.compression_receive.discardContextPreview();
            }
            return error.InvalidUtf8;
        }
        if (was_compressed and
            connection.compression_receive_context_takeover)
        {
            connection.compression_receive.commitContextPreview();
        }
        connection.message_into.reset();
        return .{
            .opcode = message_opcode,
            .payload = payload,
            .was_compressed = was_compressed,
        };
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

fn closeAfterReceiveError(
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
    if (!isAbruptReceiveEnd(err) or
        connection.close_received.load(.acquire))
    {
        return;
    }
    // EOF/END_STREAM/reset without a WebSocket Close is an abnormal closure.
    // It has no RFC 6455 status code to send, but it must still release partial
    // receive state and prevent application data from being written afterward.
    if (!failReceive(connection)) return;
    connection.finishAbruptReceiveEnd(deadline);
}

fn isAbruptReceiveEnd(err: anyerror) bool {
    return switch (err) {
        error.ConnectionClosed,
        error.StreamReset,
        error.RequestCancelled,
        error.RequestRejected,
        error.ConnectionResetByPeer,
        => true,
        else => false,
    };
}

fn failReceive(connection: anytype) bool {
    if (connection.receive_failed.swap(true, .acq_rel)) return false;
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
fn ensureIncomingFrameBuffered(
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

const finishIncomingMessage = message_state.finishIncomingMessage;

fn finishIncomingMessageForConnection(
    connection: anytype,
    message: websocket.MessageAssembler.Message,
) Error!OwnedMessage {
    if (!message.compressed or
        !connection.compression_receive_context_takeover)
    {
        return finishIncomingMessage(
            connection.allocator,
            message,
            connection.limits.max_message_bytes,
        );
    }
    const compressed_payload = message.payload;
    const payload = connection.compression_receive.previewContextOwned(
        connection.allocator,
        compressed_payload,
        connection.limits.max_message_bytes,
        connection.compression_receive_max_window_bits,
    ) catch |err| {
        connection.allocator.free(compressed_payload);
        return switch (err) {
            error.PreviewPending => error.InvalidFrame,
            error.OutOfMemory => blk: {
                _ = failReceive(connection);
                break :blk error.OutOfMemory;
            },
            else => |other| @errorCast(other),
        };
    };
    connection.allocator.free(compressed_payload);
    errdefer connection.allocator.free(payload);
    if (message.opcode == .text and
        !std.unicode.utf8ValidateSlice(payload))
    {
        connection.compression_receive.discardContextPreview();
        return error.InvalidUtf8;
    }
    connection.compression_receive.commitContextPreview();
    return .{
        .opcode = message.opcode,
        .payload = payload,
        .was_compressed = true,
    };
}

const compressedFragmentRange = message_state.compressedFragmentRange;

const HttpHead = struct {
    head: []u8,
    extra: []u8,

    fn deinit(self: *HttpHead, allocator: std.mem.Allocator) void {
        allocator.free(self.head);
        allocator.free(self.extra);
        self.* = undefined;
    }
};

const HttpUpgradeResponseBytes = struct {
    bytes: []u8,
    /// Bytes following a successful 101 head belong to WebSocket framing.
    /// Rejection responses instead consume their complete HTTP body here.
    extra: ?[]u8,
};

fn readHttpUpgradeResponseBytes(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    head: *HttpHead,
    limits: Limits,
    body_deadline: ?std.Io.Clock.Timestamp,
) Error!HttpUpgradeResponseBytes {
    var header_stack: [handshake_storage.stack_capacity]http1.Header =
        undefined;
    const header_storage = try handshake_storage.acquire(
        http1.Header,
        allocator,
        &header_stack,
        limits.max_response_headers,
    );
    defer handshake_storage.release(
        http1.Header,
        allocator,
        &header_stack,
        header_storage,
    );
    const parsed_head = try http1.parseResponseHead(
        head.head,
        header_storage,
        http1HandshakeResponseParseOptions(limits),
        .{ .request_method = .GET },
    );
    if (parsed_head.status == 101) {
        const result: HttpUpgradeResponseBytes = .{
            .bytes = head.head,
            .extra = head.extra,
        };
        head.* = undefined;
        return result;
    }

    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try bytes.ensureTotalCapacity(
        allocator,
        std.math.add(usize, head.head.len, head.extra.len) catch
            return error.BodyTooLarge,
    );
    bytes.appendSliceAssumeCapacity(head.head);
    bytes.appendSliceAssumeCapacity(head.extra);
    const body_start = head.head.len;

    var scratch: [4096]u8 = undefined;
    if (http1_message_framing.responseHeadUsesCloseDelimitedBody(
        head.head[0 .. head.head.len - 4],
        .GET,
    )) {
        if (bytes.items.len - body_start > limits.max_rejection_body_bytes) {
            return error.BodyTooLarge;
        }
        while (true) {
            const count = if (body_deadline) |absolute|
                try transport.readWithDeadline(&scratch, absolute)
            else
                try transport.read(&scratch);
            if (count == 0) break;
            const body_len = std.math.add(
                usize,
                bytes.items.len - body_start,
                count,
            ) catch return error.BodyTooLarge;
            if (body_len > limits.max_rejection_body_bytes) {
                return error.BodyTooLarge;
            }
            try bytes.appendSlice(allocator, scratch[0..count]);
        }
        return .{ .bytes = try bytes.toOwnedSlice(allocator), .extra = null };
    }

    const target_len = while (true) {
        const len = http1_message_framing.messageTargetLength(
            bytes.items,
            head.head.len - 4,
            limits.max_head_bytes,
            limits.max_rejection_body_bytes,
            .GET,
        ) catch |err| switch (err) {
            error.BufferTooShort => {
                const count = if (body_deadline) |absolute|
                    try transport.readWithDeadline(scratch[0..1], absolute)
                else
                    try transport.read(scratch[0..1]);
                if (count == 0) return error.ConnectionClosed;
                try bytes.appendSlice(allocator, scratch[0..count]);
                continue;
            },
            else => |other| return other,
        };
        break len;
    };
    try bytes.ensureTotalCapacity(allocator, target_len);
    while (bytes.items.len < target_len) {
        const count = if (body_deadline) |absolute|
            try transport.readWithDeadline(
                scratch[0..@min(scratch.len, target_len - bytes.items.len)],
                absolute,
            )
        else
            try transport.read(
                scratch[0..@min(scratch.len, target_len - bytes.items.len)],
            );
        if (count == 0) return error.ConnectionClosed;
        try bytes.appendSlice(allocator, scratch[0..count]);
    }
    // Rejected connections are closed, so any bytes beyond this response are
    // intentionally discarded rather than exposed as ambiguous pipeline data.
    bytes.items.len = target_len;
    return .{ .bytes = try bytes.toOwnedSlice(allocator), .extra = null };
}

fn writeHttpUpgradeRequest(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    options: http1_runtime.RequestOptions,
    max_head_bytes: usize,
) Error!void {
    try http1.validateRequestTargetForMethod(options.method, options.target);
    var has_host = false;
    for (options.headers) |header| {
        if (header.eqlName("host")) has_host = true;
    }
    const header_count = std.math.add(
        usize,
        options.headers.len,
        @intFromBool(!has_host and options.host != null),
    ) catch return error.HeadersTooLarge;
    var header_stack: [handshake_storage.stack_capacity]http1.Header =
        undefined;
    const headers = try handshake_storage.acquire(
        http1.Header,
        allocator,
        &header_stack,
        header_count,
    );
    defer handshake_storage.release(
        http1.Header,
        allocator,
        &header_stack,
        headers,
    );
    @memcpy(headers[0..options.headers.len], options.headers);
    if (!has_host) {
        if (options.host) |host| {
            headers[options.headers.len] = .{ .name = "Host", .value = host };
        }
    }
    try http1.validateHostHeaderBlock(options.version, headers);
    // Preflight the exact bodyless request-head size before allocating the
    // serialization buffer. `extra_headers` is caller-controlled, so checking
    // only after encoding would not make max_head_bytes a memory bound.
    var head_len = std.math.add(
        usize,
        options.method.string().len,
        1,
    ) catch return error.HeadersTooLarge;
    head_len = std.math.add(usize, head_len, options.target.len) catch
        return error.HeadersTooLarge;
    head_len = std.math.add(usize, head_len, 1) catch
        return error.HeadersTooLarge;
    head_len = std.math.add(usize, head_len, options.version.string().len) catch
        return error.HeadersTooLarge;
    head_len = std.math.add(usize, head_len, 2) catch
        return error.HeadersTooLarge;
    for (headers) |header| {
        head_len = std.math.add(usize, head_len, header.name.len) catch
            return error.HeadersTooLarge;
        head_len = std.math.add(usize, head_len, 2) catch
            return error.HeadersTooLarge;
        head_len = std.math.add(usize, head_len, header.value.len) catch
            return error.HeadersTooLarge;
        head_len = std.math.add(usize, head_len, 2) catch
            return error.HeadersTooLarge;
        if (head_len > max_head_bytes) return error.HeadersTooLarge;
    }
    head_len = std.math.add(usize, head_len, 2) catch
        return error.HeadersTooLarge;
    if (head_len > max_head_bytes) return error.HeadersTooLarge;

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try http1.writeRequestChecked(
        &encoded,
        allocator,
        options.method,
        options.target,
        options.version,
        headers,
        options.body,
    );
    // Upgrade requests never carry a body, so the encoded request is exactly
    // the head. Enforce the public head limit before exposing any bytes to the
    // transport; otherwise custom fields could bypass the receive-side bound.
    std.debug.assert(encoded.items.len == head_len);
    try transport.writeAll(encoded.items);
}

fn readHttpHead(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, max_head_bytes: usize) Error!HttpHead {
    return readHttpHeadFromTransport(
        allocator,
        .{ .tcp = .{ .io = io, .stream = stream } },
        max_head_bytes,
        null,
    );
}

fn http1HandshakeRequestParseOptions(limits: Limits) http1.ParseOptions {
    return .{
        .max_headers = limits.max_request_headers,
    };
}

fn http1HandshakeResponseParseOptions(limits: Limits) http1.ParseOptions {
    return .{
        .max_headers = limits.max_response_headers,
    };
}

fn readHttpHeadFromTransport(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    max_head_bytes: usize,
    deadline: ?std.Io.Clock.Timestamp,
) Error!HttpHead {
    return readHttpHeadFromTransportWithInitial(
        allocator,
        transport,
        max_head_bytes,
        deadline,
        &.{},
    );
}

fn readHttpHeadFromTransportWithInitial(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    max_head_bytes: usize,
    deadline: ?std.Io.Clock.Timestamp,
    initial: []const u8,
) Error!HttpHead {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try bytes.appendSlice(allocator, initial);
    var scratch: [4096]u8 = undefined;
    while (true) {
        if (try findHttpHeadEndWithinLimit(bytes.items, max_head_bytes)) |head_end| {
            const split = head_end + 4;
            const head = try allocator.dupe(u8, bytes.items[0..split]);
            errdefer allocator.free(head);
            return .{
                .head = head,
                .extra = try allocator.dupe(u8, bytes.items[split..]),
            };
        }
        const read_buf = scratch[0..@min(scratch.len, max_head_bytes - bytes.items.len)];
        const n = if (deadline) |absolute|
            try transport.readWithDeadline(read_buf, absolute)
        else
            try transport.read(read_buf);
        if (n == 0) return error.ConnectionClosed;
        try bytes.appendSlice(allocator, scratch[0..n]);
    }
}

fn handshakeDeadline(
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

fn findHttpHeadEndWithinLimit(bytes: []const u8, max_head_bytes: usize) Error!?usize {
    if (std.mem.indexOf(u8, bytes, "\r\n\r\n")) |head_end| {
        if (head_end + 4 > max_head_bytes) return error.HeadersTooLarge;
        return head_end;
    }
    if (bytes.len >= max_head_bytes) return error.HeadersTooLarge;
    return null;
}

const validateServerHandshake = handshake_headers.validateHttp1Server;
const requiredSingletonHeader = handshake_headers.requiredHttp1;
const optionalSingletonHeader = handshake_headers.optionalHttp1;
const validateH2ServerHandshake = handshake_headers.validateH2Server;
const requiredH2SingletonHeader = handshake_headers.requiredH2;
const optionalH2SingletonHeader = handshake_headers.optionalH2;
const validateHttp1ClientExtraHeadersImpl =
    handshake_headers.validateHttp1ClientExtra;
const validateUpgradeRejectionHeaders =
    handshake_headers.validateHttp1RejectionExtra;
const validateUpgradeAcceptHeaders =
    handshake_headers.validateHttp1AcceptExtra;
const validateH2ClientExtraHeaders = handshake_headers.validateH2ClientExtra;
const validateH2ServerExtraHeaders = handshake_headers.validateH2ServerExtra;
const validateH2RejectionHeaders = handshake_headers.validateH2RejectionExtra;
const rejectH2ExtendedConnectLegacyHeaders = handshake_headers.rejectH2Legacy;
const acceptH2Extensions = handshake_headers.acceptH2Extensions;
const selectHttp1Subprotocol = handshake_headers.selectHttp1Subprotocol;
const selectH2Subprotocol = handshake_headers.selectH2Subprotocol;

fn readSome(io: std.Io, stream: net.Stream, buffer: []u8) net.Stream.Reader.Error!usize {
    var bufs = [_][]u8{buffer};
    return io.vtable.netRead(io.userdata, stream.socket.handle, &bufs);
}

fn readSomeWithDeadline(
    io: std.Io,
    stream: net.Stream,
    buffer: []u8,
    deadline: std.Io.Clock.Timestamp,
) Error!usize {
    return stream_io.readSomeWithDeadline(io, stream, buffer, deadline);
}

fn writeAllToStream(io: std.Io, stream: net.Stream, bytes: []const u8) net.Stream.Writer.Error!void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = try io.vtable.netWrite(io.userdata, stream.socket.handle, bytes[written..], &.{""}, 0);
        if (n == 0) return error.SocketUnconnected;
        written += n;
    }
}

fn writeMaskedPayload(
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

fn writeMaskedPayloadParts(
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

fn writeUnmaskedPayloadSlices(
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

fn writeMaskedTunnelPayloadSlices(
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

fn writeUnmaskedTunnelPayloadSlices(
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

fn writeMaskedTunnelPayloadSlicesWithWriter(
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

test "WebSocket client handshake accepts split Connection and rejects duplicate critical headers" {
    const allocator = std.testing.allocator;
    const client_key = "dGhlIHNhbXBsZSBub25jZQ==";

    const split_connection =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: keep-alive\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "\r\n";
    var response = try http1.parseResponse(
        allocator,
        split_connection,
        http1HandshakeResponseParseOptions(.{}),
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(?[]u8, null), try validateServerHandshake(allocator, response, client_key, &.{}));
    try std.testing.expectError(error.InvalidSubprotocol, validateServerHandshake(allocator, response, client_key, &.{"chat.v1"}));

    const duplicate_accept =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "\r\n";
    var duplicate_response = try http1.parseResponse(
        allocator,
        duplicate_accept,
        http1HandshakeResponseParseOptions(.{}),
    );
    defer duplicate_response.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateServerHandshake(allocator, duplicate_response, client_key, &.{}));

    const duplicate_extensions =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n" ++
        "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n" ++
        "\r\n";
    var duplicate_extensions_response = try http1.parseResponse(
        allocator,
        duplicate_extensions,
        http1HandshakeResponseParseOptions(.{}),
    );
    defer duplicate_extensions_response.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateServerHandshake(allocator, duplicate_extensions_response, client_key, &.{}));

    const content_length_101 =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n";
    var content_length_response = try http1.parseResponse(
        allocator,
        content_length_101,
        http1HandshakeResponseParseOptions(.{}),
    );
    defer content_length_response.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateServerHandshake(allocator, content_length_response, client_key, &.{}));

    const transfer_encoding_101 =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n";
    var transfer_encoding_response = try http1.parseResponse(
        allocator,
        transfer_encoding_101,
        http1HandshakeResponseParseOptions(.{}),
    );
    defer transfer_encoding_response.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateServerHandshake(allocator, transfer_encoding_response, client_key, &.{}));
}

test "WebSocket server negotiates split subprotocol request headers" {
    const allocator = std.testing.allocator;

    const selected = (try selectHttp1Subprotocol(
        allocator,
        &.{
            .{ .name = "Sec-WebSocket-Protocol", .value = "unknown" },
            .{ .name = "Sec-WebSocket-Protocol", .value = "chat.v2, chat.v1" },
        },
        &.{ "chat.v1", "chat.v2" },
    )).?;
    defer allocator.free(selected);
    try std.testing.expectEqualStrings("chat.v2", selected);

    try std.testing.expectError(error.InvalidSubprotocol, selectHttp1Subprotocol(
        allocator,
        &.{.{ .name = "Sec-WebSocket-Protocol", .value = "chat.v1, bad protocol" }},
        &.{"chat.v1"},
    ));
    try std.testing.expectError(error.InvalidSubprotocol, selectHttp1Subprotocol(
        allocator,
        &.{.{ .name = "Sec-WebSocket-Protocol", .value = "chat.v1" }},
        &.{"bad supported"},
    ));
    try std.testing.expectError(error.InvalidSubprotocol, selectHttp1Subprotocol(
        allocator,
        &.{
            .{ .name = "Sec-WebSocket-Protocol", .value = "chat.v1" },
            .{ .name = "Sec-WebSocket-Protocol", .value = "chat.v2, chat.v1" },
        },
        &.{ "chat.v1", "chat.v2" },
    ));
}

test "WebSocket over HTTP/2 handshake rejects duplicate critical headers" {
    const allocator = std.testing.allocator;

    const duplicate_request_version = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-version", .value = "13" },
        .{ .name = "sec-websocket-version", .value = "13" },
    };
    try std.testing.expectError(error.InvalidHandshake, requiredH2SingletonHeader(&duplicate_request_version, "sec-websocket-version"));

    try std.testing.expectError(error.InvalidHandshake, validateH2ClientExtraHeaders(&.{
        .{ .name = "sec-websocket-version", .value = "13" },
    }));
    try std.testing.expectError(error.InvalidHandshake, validateH2ClientExtraHeaders(&.{
        .{ .name = "sec-websocket-key", .value = "dGhlIHNhbXBsZSBub25jZQ==" },
    }));

    const duplicate_response_protocol = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-protocol", .value = "chat.v1" },
        .{ .name = "sec-websocket-protocol", .value = "chat.v1" },
    };
    try std.testing.expectError(error.InvalidHandshake, validateH2ServerHandshake(std.testing.allocator, &duplicate_response_protocol, &.{"chat.v1"}));
    try std.testing.expectError(error.InvalidHandshake, validateH2ServerExtraHeaders(&.{
        .{ .name = "sec-websocket-protocol", .value = "chat.v1" },
    }));

    const legacy_accept_response = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-accept", .value = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" },
    };
    try std.testing.expectError(error.InvalidHandshake, validateH2ServerHandshake(allocator, &legacy_accept_response, &.{}));

    const legacy_key_request = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-key", .value = "dGhlIHNhbXBsZSBub25jZQ==" },
    };
    try std.testing.expectError(error.InvalidHandshake, rejectH2ExtendedConnectLegacyHeaders(&legacy_key_request));

    const duplicate_extensions = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-extensions", .value = "permessage-deflate; server_no_context_takeover; client_no_context_takeover" },
        .{ .name = "sec-websocket-extensions", .value = "permessage-deflate; server_no_context_takeover; client_no_context_takeover" },
    };
    try std.testing.expectError(error.InvalidHandshake, optionalH2SingletonHeader(&duplicate_extensions, "sec-websocket-extensions"));

    const split_offer = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-extensions", .value = "x-unknown" },
        .{ .name = "sec-websocket-extensions", .value = "permessage-deflate; client_no_context_takeover; server_max_window_bits=15" },
    };
    const accepted = try acceptH2Extensions(allocator, &split_offer, .{
        .enable_permessage_deflate = true,
    });
    defer if (accepted) |value| allocator.free(value);
    try std.testing.expect(accepted != null);

    const split_protocol_offer = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-protocol", .value = "unknown" },
        .{ .name = "sec-websocket-protocol", .value = "chat.v2, chat.v1" },
    };
    const selected = (try selectH2Subprotocol(allocator, &split_protocol_offer, &.{ "chat.v1", "chat.v2" })).?;
    defer allocator.free(selected);
    try std.testing.expectEqualStrings("chat.v2", selected);

    const invalid_split_protocol = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-protocol", .value = "chat.v1" },
        .{ .name = "sec-websocket-protocol", .value = "bad protocol" },
    };
    try std.testing.expectError(error.InvalidSubprotocol, selectH2Subprotocol(allocator, &invalid_split_protocol, &.{"chat.v1"}));
    const duplicate_split_protocol = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-protocol", .value = "chat.v1" },
        .{ .name = "sec-websocket-protocol", .value = "chat.v2, chat.v1" },
    };
    try std.testing.expectError(error.InvalidSubprotocol, selectH2Subprotocol(allocator, &duplicate_split_protocol, &.{ "chat.v1", "chat.v2" }));
    try std.testing.expectError(error.InvalidSubprotocol, validateH2ServerHandshake(allocator, &.{}, &.{"chat.v1"}));
}

test "WebSocket runtime client and server exchange over TCP" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 5,
            .max_message_bytes = 5,
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
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            var frame = try connection.receiveFrame();
            defer frame.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.text, frame.header.opcode);
            try std.testing.expect(frame.header.masked);
            try std.testing.expectEqualStrings("hello", frame.payload);

            try std.testing.expectError(
                error.MessageTooLarge,
                connection.sendText("world!"),
            );
            try connection.sendText("world");

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
            try std.testing.expect(connection.close_received.load(.acquire));
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/chat",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 5,
            .max_message_bytes = 5,
        },
    });
    defer client.close();

    try std.testing.expectError(
        error.MessageTooLarge,
        client.sendText("hello!"),
    );
    try client.sendText("hello");
    var response = try client.receiveFrame();
    defer response.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, response.header.opcode);
    try std.testing.expect(!response.header.masked);
    try std.testing.expectEqualStrings("world", response.payload);

    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket runtime streams large immutable payload without mutation" {
    const allocator = std.testing.allocator;
    const payload_len = masked_write_scratch_len + 257;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 4096,
            .max_frame_bytes = payload_len,
            .max_message_bytes = payload_len,
        },
    );
    defer server.deinit();

    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, index| byte.* = @truncate(index);
    const expected = try allocator.dupe(u8, payload);
    defer allocator.free(expected);

    const Shared = struct {
        server: *Server,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept(.{});
            defer connection.close();
            var message = try connection.receiveMessage();
            defer message.deinit(connection.allocator);
            try std.testing.expectEqual(websocket.Opcode.binary, message.opcode);
            try std.testing.expectEqualSlices(
                u8,
                shared.expected,
                message.payload,
            );
            try connection.sendBinary(message.payload);
            var close = try connection.receiveFrame();
            defer close.deinit(connection.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server, .expected = expected };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/immutable-large",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = payload_len,
            .max_message_bytes = payload_len,
        },
    });
    defer client.close();
    try client.sendBinary(payload);
    try std.testing.expectEqualSlices(u8, expected, payload);
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqualSlices(u8, expected, response.payload);
    try client.sendClose(.normal_closure, "");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket binary slices preserve one frame across length boundaries" {
    const allocator = std.testing.allocator;
    const payload = "0123456789abcdef" ** 4096;
    const lengths = [_]usize{ 0, 125, 126, 65_535, 65_536 };
    const trailing_empty_parts = [_][]const u8{
        "0", "1", "2", "3", "4", "5", "6", "7",
        "8", "9", "a", "b", "c", "d", "e", "",
        "",
    };
    const trailing_empty_payload = "0123456789abcde";
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 4096,
            .max_frame_bytes = payload.len,
            .max_message_bytes = payload.len,
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
            var connection = try server_ptr.accept(.{});
            defer connection.close();
            for (lengths) |len| {
                var frame = try connection.receiveFrame();
                defer frame.deinit(server_ptr.http.allocator);
                try std.testing.expectEqual(websocket.Opcode.binary, frame.header.opcode);
                try std.testing.expect(frame.header.fin);
                try std.testing.expectEqualSlices(u8, payload[0..len], frame.payload);
                const middle = len / 2;
                try connection.sendBinarySlices(if (len == 0)
                    &.{}
                else
                    &.{ payload[0..1], "", payload[1..middle], payload[middle..len] });
            }
            try connection.sendBinarySlices(&trailing_empty_parts);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/binary-parts",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = payload.len,
            .max_message_bytes = payload.len,
        },
    });
    defer client.close();
    for (lengths) |len| {
        const middle = len / 2;
        try client.sendBinarySlices(if (len == 0)
            &.{}
        else
            &.{ payload[0..1], "", payload[1..middle], payload[middle..len] });
        var response = try client.receiveFrame();
        defer response.deinit(allocator);
        try std.testing.expectEqual(websocket.Opcode.binary, response.header.opcode);
        try std.testing.expect(response.header.fin);
        try std.testing.expectEqualSlices(u8, payload[0..len], response.payload);
    }
    var trailing_empty = try client.receiveFrame();
    defer trailing_empty.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.binary, trailing_empty.header.opcode);
    try std.testing.expect(trailing_empty.header.fin);
    try std.testing.expectEqualStrings(
        trailing_empty_payload,
        trailing_empty.payload,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket runtime negotiates subprotocol" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
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
            var connection = try server_ptr.accept(.{ .protocols = &.{ "chat.v2", "superchat" } });
            defer connection.close();
            try std.testing.expectEqualStrings("superchat", connection.selected_protocol.?);

            var frame = try connection.receiveFrame();
            defer frame.deinit(server_ptr.http.allocator);
            try std.testing.expectEqualStrings("hello", frame.payload);
            try connection.sendText("world");

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/subprotocol",
        .protocols = &.{ "video", "superchat" },
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();
    try std.testing.expectEqualStrings("superchat", client.selected_protocol.?);

    try client.sendText("hello");
    var response = try client.receiveFrame();
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("world", response.payload);
    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket client connects by host name" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
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
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            var request = try connection.receiveMessage();
            defer request.deinit(server_ptr.http.allocator);
            try std.testing.expectEqualStrings("hello", request.payload);
            try connection.sendText("dns-world");

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connectHost(allocator, io, "localhost", server.address().ip4.port, .{
        .target = "/dns",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    try client.sendText("hello");
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("dns-world", response.payload);
    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket client connects by ws URI" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
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
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            var request = try connection.receiveMessage();
            defer request.deinit(server_ptr.http.allocator);
            try std.testing.expectEqualStrings("uri-hello", request.payload);
            try connection.sendText("uri-world");

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(allocator, "ws://localhost:{d}/uri?x=1", .{server.address().ip4.port});
    defer allocator.free(uri);
    var client = try Client.connectUri(allocator, io, uri, .{
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    try client.sendText("uri-hello");
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("uri-world", response.payload);
    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectError(error.UnsupportedScheme, Client.connectUri(allocator, io, "ftp://localhost/chat", .{}));
    try std.testing.expectError(error.InvalidUri, Client.connectUri(allocator, io, "ws:///missing-host", .{}));
    try std.testing.expectError(error.InvalidUri, Client.connectUri(allocator, io, "ws://user:pass@localhost/chat", .{}));
}

test "WebSocket client connects by bracketed IPv6 URI" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = Server.listen(
        allocator,
        io,
        .{ .ip6 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
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
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            var request = try connection.receiveMessage();
            defer request.deinit(server_ptr.http.allocator);
            try std.testing.expectEqualStrings("ipv6-uri-hello", request.payload);
            try connection.sendText("ipv6-uri-world");

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(allocator, "ws://[::1]:{d}/ipv6?x=1", .{server.address().ip6.port});
    defer allocator.free(uri);
    var client = try Client.connectUri(allocator, io, uri, .{
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    try client.sendText("ipv6-uri-hello");
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("ipv6-uri-world", response.payload);
    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket runtime negotiates permessage-deflate" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096, .max_message_bytes = 4096 },
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
            var connection = try server_ptr.accept(.{ .enable_permessage_deflate = true });
            defer connection.close();
            try std.testing.expect(connection.permessage_deflate);
            try std.testing.expect(!connection.compression_send_context_takeover);
            try std.testing.expect(!connection.compression_receive_context_takeover);

            var compressed: std.ArrayList(u8) = .empty;
            defer compressed.deinit(server_ptr.http.allocator);
            for (0..3) |index| {
                var frame = try connection.receiveFrame();
                defer frame.deinit(server_ptr.http.allocator);
                try std.testing.expectEqual(
                    if (index == 0) websocket.Opcode.text else .continuation,
                    frame.header.opcode,
                );
                try std.testing.expectEqual(index == 0, frame.header.rsv1);
                try std.testing.expectEqual(index == 2, frame.header.fin);
                try compressed.appendSlice(
                    server_ptr.http.allocator,
                    frame.payload,
                );
            }
            const request = try websocket.decompressMessage(
                server_ptr.http.allocator,
                compressed.items,
                4096,
            );
            defer server_ptr.http.allocator.free(request);
            try std.testing.expectEqualStrings(
                "compressible \xe2\x82\xac compressible compressible",
                request,
            );

            try connection.sendFragmented(.text, &.{ "deflated response ", "deflated response" });

            const ConcurrentSender = struct {
                connection: *Connection,
                io: std.Io,
                start: *std.Io.Event,
                payload: []const u8,
                err: ?anyerror = null,

                fn run(sender: *@This()) void {
                    sender.start.wait(sender.io) catch |err| {
                        sender.err = err;
                        return;
                    };
                    sender.connection.sendText(sender.payload) catch |err| {
                        sender.err = err;
                    };
                }
            };
            const concurrent_a = "h1-concurrent-a-h1-concurrent-a-" ++
                ("a" ** 480);
            const concurrent_b = "h1-concurrent-b-h1-concurrent-b-" ++
                ("b" ** 480);
            var start: std.Io.Event = .unset;
            var senders = [_]ConcurrentSender{
                .{ .connection = &connection, .io = server_ptr.http.io, .start = &start, .payload = concurrent_a },
                .{ .connection = &connection, .io = server_ptr.http.io, .start = &start, .payload = concurrent_b },
            };
            const sender_a = try std.Thread.spawn(.{}, ConcurrentSender.run, .{&senders[0]});
            const sender_b = std.Thread.spawn(.{}, ConcurrentSender.run, .{&senders[1]}) catch |err| {
                start.set(server_ptr.http.io);
                sender_a.join();
                return err;
            };
            start.set(server_ptr.http.io);
            sender_a.join();
            sender_b.join();
            if (senders[0].err) |err| return err;
            if (senders[1].err) |err| return err;

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/deflate",
        .enable_permessage_deflate = true,
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096, .max_message_bytes = 4096 },
    });
    defer client.close();
    try std.testing.expect(client.permessage_deflate);
    try std.testing.expect(!client.compression_send_context_takeover);
    try std.testing.expect(!client.compression_receive_context_takeover);

    // Split one UTF-8 scalar across the application slices. Compression must
    // still produce one DEFLATE message, then preserve the requested three
    // WebSocket frames with RSV1 set only on the first frame.
    try client.sendFragmented(.text, &.{
        "compressible \xe2",
        "\x82",
        "\xac compressible compressible",
    });
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, response.opcode);
    try std.testing.expectEqualStrings("deflated response deflated response", response.payload);
    try std.testing.expect(response.was_compressed);

    const concurrent_a = "h1-concurrent-a-h1-concurrent-a-" ++
        ("a" ** 480);
    const concurrent_b = "h1-concurrent-b-h1-concurrent-b-" ++
        ("b" ** 480);
    var concurrent_first = try client.receiveMessageWithTimeout(
        .fromSeconds(5),
    );
    defer concurrent_first.deinit(allocator);
    var concurrent_second = try client.receiveMessageWithTimeout(
        .fromSeconds(5),
    );
    defer concurrent_second.deinit(allocator);
    try std.testing.expect(concurrent_first.was_compressed);
    try std.testing.expect(concurrent_second.was_compressed);
    const saw_a = std.mem.eql(u8, concurrent_first.payload, concurrent_a) or
        std.mem.eql(u8, concurrent_second.payload, concurrent_a);
    const saw_b = std.mem.eql(u8, concurrent_first.payload, concurrent_b) or
        std.mem.eql(u8, concurrent_second.payload, concurrent_b);
    try std.testing.expect(saw_a);
    try std.testing.expect(saw_b);

    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket HTTP1 context takeover spans runtime API shapes" {
    const allocator = std.testing.allocator;
    const context_payload =
        "abcdefghijklmnopqrstuvwxyz0123456789" ** 8;
    const fallback_payload = [_]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 4096,
            .max_message_bytes = 4096,
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
            var connection = try server_ptr.accept(.{
                .enable_permessage_deflate = true,
                .allow_context_takeover = true,
                .compression_threshold = 0,
            });
            defer connection.close();
            try std.testing.expect(connection.permessage_deflate);
            try std.testing.expect(
                connection.compression_send_context_takeover,
            );
            try std.testing.expect(
                connection.compression_receive_context_takeover,
            );

            // Expansion fallback must discard its preview. If the first
            // plaintext were retained, the identical second payload would
            // become a tiny context-reference frame instead of plain wire.
            for (0..2) |_| {
                var frame = try connection.receiveFrame();
                defer frame.deinit(server_ptr.http.allocator);
                try std.testing.expectEqual(websocket.Opcode.binary, frame.header.opcode);
                try std.testing.expect(!frame.header.rsv1);
                try std.testing.expectEqualSlices(u8, &fallback_payload, frame.payload);
            }

            var first_wire: std.ArrayList(u8) = .empty;
            defer first_wire.deinit(server_ptr.http.allocator);
            for (0..3) |index| {
                var frame = try connection.receiveFrame();
                defer frame.deinit(server_ptr.http.allocator);
                try std.testing.expectEqual(
                    if (index == 0) websocket.Opcode.text else .continuation,
                    frame.header.opcode,
                );
                try std.testing.expectEqual(index == 0, frame.header.rsv1);
                try std.testing.expectEqual(index == 2, frame.header.fin);
                try first_wire.appendSlice(
                    server_ptr.http.allocator,
                    frame.payload,
                );
            }
            const first_plain = try websocket.decompressMessage(
                server_ptr.http.allocator,
                first_wire.items,
                context_payload.len,
            );
            defer server_ptr.http.allocator.free(first_plain);
            try std.testing.expectEqualStrings(context_payload, first_plain);

            var dependent = try connection.receiveFrame();
            defer dependent.deinit(server_ptr.http.allocator);
            try std.testing.expect(dependent.header.rsv1);
            try std.testing.expectError(
                error.InvalidFrame,
                websocket.decompressMessage(
                    server_ptr.http.allocator,
                    dependent.payload,
                    context_payload.len,
                ),
            );

            var progress: MessageWriteProgress = .{};
            try connection.sendFragmentedWithDeadline(
                .text,
                &.{
                    context_payload[0..71],
                    context_payload[71..173],
                    context_payload[173..],
                },
                &progress,
                .fromNow(server_ptr.http.io, .{
                    .raw = .fromSeconds(5),
                    .clock = .awake,
                }),
            );
            try std.testing.expect(progress.frame_committed);
            try connection.sendBinarySlices(&.{
                context_payload[0..97],
                "",
                context_payload[97..],
            });

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/context-takeover",
        .enable_permessage_deflate = true,
        .allow_context_takeover = true,
        .compression_threshold = 0,
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 4096,
            .max_message_bytes = 4096,
        },
    });
    defer client.close();
    try std.testing.expect(client.compression_send_context_takeover);
    try std.testing.expect(client.compression_receive_context_takeover);

    try client.sendBinary(&fallback_payload);
    try client.sendBinary(&fallback_payload);
    var send_progress: MessageWriteProgress = .{};
    try client.sendFragmentedWithDeadline(
        .text,
        &.{
            context_payload[0..83],
            context_payload[83..199],
            context_payload[199..],
        },
        &send_progress,
        .fromNow(io, .{ .raw = .fromSeconds(5), .clock = .awake }),
    );
    try std.testing.expect(send_progress.frame_committed);
    try client.sendBinarySlices(&.{
        context_payload[0..101],
        "",
        context_payload[101..],
    });

    var first_response = try client.receiveMessage();
    defer first_response.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, first_response.opcode);
    try std.testing.expectEqualStrings(context_payload, first_response.payload);
    var caller_storage: [4096]u8 = undefined;
    const second_response = try client.receiveMessageInto(&caller_storage);
    try std.testing.expectEqual(websocket.Opcode.binary, second_response.opcode);
    try std.testing.expectEqualStrings(context_payload, second_response.payload);
    try std.testing.expect(second_response.was_compressed);
    try client.sendClose(.normal_closure, "bye");

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP/2 extended CONNECT exchanges messages" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096, .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *http2_runtime.Server) !void {
            var h2 = try server_ptr.accept();
            defer h2.close();

            var ws = try H2Server.accept(server_ptr.allocator, &h2, .{
                .protocols = &.{"chat.v1"},
                .enable_permessage_deflate = true,
                .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096, .max_message_bytes = 4096 },
            });
            defer ws.close();
            try std.testing.expectEqualStrings("chat.v1", ws.selected_protocol.?);
            try std.testing.expect(ws.permessage_deflate);
            try std.testing.expect(!ws.compression_send_context_takeover);
            try std.testing.expect(!ws.compression_receive_context_takeover);

            var compressed: std.ArrayList(u8) = .empty;
            defer compressed.deinit(server_ptr.allocator);
            for (0..3) |index| {
                var frame = try ws.receiveFrame();
                defer frame.deinit(server_ptr.allocator);
                try std.testing.expectEqual(
                    if (index == 0) websocket.Opcode.text else .continuation,
                    frame.header.opcode,
                );
                try std.testing.expectEqual(index == 0, frame.header.rsv1);
                try std.testing.expectEqual(index == 2, frame.header.fin);
                try compressed.appendSlice(
                    server_ptr.allocator,
                    frame.payload,
                );
            }
            const request = try websocket.decompressMessage(
                server_ptr.allocator,
                compressed.items,
                4096,
            );
            defer server_ptr.allocator.free(request);
            try std.testing.expectEqualStrings(
                "hello \xe2\x82\xac over h2 websocket hello over h2 websocket",
                request,
            );

            try ws.sendFragmented(.text, &.{
                "world over h2 websocket ",
                "world over h2 websocket",
            });

            const ConcurrentSender = struct {
                connection: *H2Connection,
                io: std.Io,
                start: *std.Io.Event,
                payload: []const u8,
                err: ?anyerror = null,

                fn run(sender: *@This()) void {
                    sender.start.wait(sender.io) catch |err| {
                        sender.err = err;
                        return;
                    };
                    sender.connection.sendText(sender.payload) catch |err| {
                        sender.err = err;
                    };
                }
            };
            const concurrent_a = "h2-concurrent-a-h2-concurrent-a-" ++
                ("a" ** 480);
            const concurrent_b = "h2-concurrent-b-h2-concurrent-b-" ++
                ("b" ** 480);
            var start: std.Io.Event = .unset;
            var senders = [_]ConcurrentSender{
                .{
                    .connection = &ws,
                    .io = server_ptr.io,
                    .start = &start,
                    .payload = concurrent_a,
                },
                .{
                    .connection = &ws,
                    .io = server_ptr.io,
                    .start = &start,
                    .payload = concurrent_b,
                },
            };
            const sender_a = try std.Thread.spawn(
                .{},
                ConcurrentSender.run,
                .{&senders[0]},
            );
            const sender_b = std.Thread.spawn(
                .{},
                ConcurrentSender.run,
                .{&senders[1]},
            ) catch |err| {
                start.set(server_ptr.io);
                sender_a.join();
                return err;
            };
            start.set(server_ptr.io);
            sender_a.join();
            sender_b.join();
            if (senders[0].err) |err| return err;
            if (senders[1].err) |err| return err;

            // The h2 WebSocket adapter still runs the normal RFC 6455 close
            // handshake inside DATA frames and maps the final Close write to
            // END_STREAM on the underlying HTTP/2 tunnel.
            try std.testing.expectError(error.ConnectionClosed, ws.receiveMessage());
            try std.testing.expect(ws.close_received.load(.acquire));
            try std.testing.expect(ws.close_sent.load(.acquire));
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var h2_client = try http2_runtime.Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer h2_client.close();

    var ws_client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/chat",
        .protocols = &.{"chat.v1"},
        .enable_permessage_deflate = true,
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096, .max_message_bytes = 4096 },
    });
    defer ws_client.close();
    try std.testing.expectEqualStrings("chat.v1", ws_client.selected_protocol.?);
    try std.testing.expect(ws_client.permessage_deflate);
    try std.testing.expect(!ws_client.compression_send_context_takeover);
    try std.testing.expect(!ws_client.compression_receive_context_takeover);

    try ws_client.sendFragmented(.text, &.{
        "hello \xe2",
        "\x82",
        "\xac over h2 websocket hello over h2 websocket",
    });
    var response_storage: [4096]u8 = undefined;
    const response = try ws_client.receiveMessageIntoWithDeadline(
        &response_storage,
        .fromNow(
            io,
            .{ .raw = .fromSeconds(1), .clock = .awake },
        ),
    );
    try std.testing.expectEqual(websocket.Opcode.text, response.opcode);
    try std.testing.expectEqualStrings(
        "world over h2 websocket world over h2 websocket",
        response.payload,
    );
    const concurrent_a = "h2-concurrent-a-h2-concurrent-a-" ++
        ("a" ** 480);
    const concurrent_b = "h2-concurrent-b-h2-concurrent-b-" ++
        ("b" ** 480);
    var concurrent_first = try ws_client.receiveMessageWithTimeout(
        .fromSeconds(5),
    );
    defer concurrent_first.deinit(allocator);
    var concurrent_second = try ws_client.receiveMessageWithTimeout(
        .fromSeconds(5),
    );
    defer concurrent_second.deinit(allocator);
    try std.testing.expect(concurrent_first.was_compressed);
    try std.testing.expect(concurrent_second.was_compressed);
    const saw_a = std.mem.eql(u8, concurrent_first.payload, concurrent_a) or
        std.mem.eql(u8, concurrent_second.payload, concurrent_a);
    const saw_b = std.mem.eql(u8, concurrent_first.payload, concurrent_b) or
        std.mem.eql(u8, concurrent_second.payload, concurrent_b);
    try std.testing.expect(saw_a);
    try std.testing.expect(saw_b);

    try ws_client.sendClose(.normal_closure, "bye");
    try std.testing.expectError(error.ConnectionClosed, ws_client.receiveMessage());
    try std.testing.expect(ws_client.close_received.load(.acquire));

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket HTTP2 context takeover spans runtime API shapes" {
    const allocator = std.testing.allocator;
    const context_payload =
        "abcdefghijklmnopqrstuvwxyz0123456789" ** 8;
    const fallback_payload = [_]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .enable_connect_protocol = true,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *http2_runtime.Server) !void {
            var h2 = try server_ptr.accept();
            defer h2.close();
            var ws = try H2Server.accept(server_ptr.allocator, &h2, .{
                .enable_permessage_deflate = true,
                .allow_context_takeover = true,
                .compression_threshold = 0,
                .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = 4096,
                    .max_message_bytes = 4096,
                },
            });
            defer ws.close();
            try std.testing.expect(ws.permessage_deflate);
            try std.testing.expect(ws.compression_send_context_takeover);
            try std.testing.expect(ws.compression_receive_context_takeover);

            // Expansion fallback must not enter the compression history.
            for (0..2) |_| {
                var frame = try ws.receiveFrame();
                defer frame.deinit(server_ptr.allocator);
                try std.testing.expectEqual(websocket.Opcode.binary, frame.header.opcode);
                try std.testing.expect(!frame.header.rsv1);
                try std.testing.expectEqualSlices(u8, &fallback_payload, frame.payload);
            }

            var first_wire: std.ArrayList(u8) = .empty;
            defer first_wire.deinit(server_ptr.allocator);
            for (0..3) |index| {
                var frame = try ws.receiveFrame();
                defer frame.deinit(server_ptr.allocator);
                try std.testing.expectEqual(
                    if (index == 0) websocket.Opcode.text else .continuation,
                    frame.header.opcode,
                );
                try std.testing.expectEqual(index == 0, frame.header.rsv1);
                try std.testing.expectEqual(index == 2, frame.header.fin);
                try first_wire.appendSlice(server_ptr.allocator, frame.payload);
            }
            const first_plain = try websocket.decompressMessage(
                server_ptr.allocator,
                first_wire.items,
                context_payload.len,
            );
            defer server_ptr.allocator.free(first_plain);
            try std.testing.expectEqualStrings(context_payload, first_plain);

            var dependent = try ws.receiveFrame();
            defer dependent.deinit(server_ptr.allocator);
            try std.testing.expect(dependent.header.rsv1);
            try std.testing.expectError(
                error.InvalidFrame,
                websocket.decompressMessage(
                    server_ptr.allocator,
                    dependent.payload,
                    context_payload.len,
                ),
            );

            var progress: MessageWriteProgress = .{};
            try ws.sendFragmentedWithDeadline(
                .text,
                &.{
                    context_payload[0..71],
                    context_payload[71..173],
                    context_payload[173..],
                },
                &progress,
                .fromNow(server_ptr.io, .{
                    .raw = .fromSeconds(5),
                    .clock = .awake,
                }),
            );
            try std.testing.expect(progress.frame_committed);
            try ws.sendBinarySlices(&.{
                context_payload[0..97],
                "",
                context_payload[97..],
            });
            try ws.sendText(context_payload);

            var close = try ws.receiveFrame();
            defer close.deinit(server_ptr.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer h2_client.close();
    var client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/context-takeover",
        .enable_permessage_deflate = true,
        .allow_context_takeover = true,
        .compression_threshold = 0,
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 4096,
            .max_message_bytes = 4096,
        },
    });
    defer client.close();
    try std.testing.expect(client.compression_send_context_takeover);
    try std.testing.expect(client.compression_receive_context_takeover);

    try client.sendBinary(&fallback_payload);
    try client.sendBinary(&fallback_payload);
    var send_progress: MessageWriteProgress = .{};
    try client.sendFragmentedWithDeadline(
        .text,
        &.{
            context_payload[0..83],
            context_payload[83..199],
            context_payload[199..],
        },
        &send_progress,
        .fromNow(io, .{ .raw = .fromSeconds(5), .clock = .awake }),
    );
    try std.testing.expect(send_progress.frame_committed);
    try client.sendBinarySlices(&.{
        context_payload[0..101],
        "",
        context_payload[101..],
    });

    var first_response = try client.receiveMessage();
    defer first_response.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, first_response.opcode);
    try std.testing.expectEqualStrings(context_payload, first_response.payload);
    var caller_storage: [4096]u8 = undefined;
    const second_response = try client.receiveMessageInto(&caller_storage);
    try std.testing.expectEqual(websocket.Opcode.binary, second_response.opcode);
    try std.testing.expectEqualStrings(context_payload, second_response.payload);
    try std.testing.expect(second_response.was_compressed);
    var third_response = try client.receiveFrame();
    defer third_response.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, third_response.header.opcode);
    try std.testing.expect(third_response.header.rsv1);
    try std.testing.expect(third_response.header.fin);
    try std.testing.expectError(
        error.InvalidFrame,
        websocket.decompressMessage(
            allocator,
            third_response.payload,
            context_payload.len,
        ),
    );
    try client.sendClose(.normal_closure, "bye");

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP2 close abandons unfinished stream and permits reuse" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .max_concurrent_streams = 1,
            .enable_connect_protocol = true,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();

            var first = try H2Server.accept(
                self.server.allocator,
                &h2,
                .{},
            );
            const first_stream_id = first.tunnel.stream_id;
            first.close();
            var reset = try h2.readResetStreamWithTimeout(
                .fromSeconds(1),
            );
            defer reset.deinit(self.server.allocator);
            try std.testing.expectEqual(first_stream_id, reset.reset.stream_id);
            try std.testing.expectEqual(
                http2.ErrorCode.cancel,
                reset.reset.error_code,
            );

            var second = try H2Server.accept(
                self.server.allocator,
                &h2,
                .{},
            );
            defer second.close();
            var message = try second.receiveMessageWithTimeout(
                .fromSeconds(1),
            );
            defer message.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("second", message.payload);
            try std.testing.expectError(
                error.ConnectionClosed,
                second.receiveMessageWithTimeout(.fromSeconds(1)),
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .enable_connect_protocol = true,
        },
    );
    defer h2_client.close();

    var first = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/abandoned",
    });
    first.close();

    var second = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/reused",
    });
    var second_live = true;
    defer if (second_live) second.close();
    try second.sendText("second");
    try second.sendClose(.normal_closure, "done");
    var close = try second.receiveFrameWithTimeout(.fromSeconds(1));
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
    try std.testing.expectEqualStrings(
        "done",
        (try websocket.parseClosePayload(close.payload)).?.reason,
    );
    second.close();
    second_live = false;

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(h2_client.isReusable());
}

test "WebSocket HTTP2 abrupt END_STREAM aborts only its tunnel" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .max_concurrent_streams = 2,
            .enable_connect_protocol = true,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        first_stream_id: u31 = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            var first = try H2Server.accept(self.server.allocator, &h2, .{});
            defer first.close();
            self.first_stream_id = first.tunnel.stream_id;
            try std.testing.expectError(
                error.ConnectionClosed,
                first.receiveMessageWithTimeout(.fromSeconds(2)),
            );
            try std.testing.expect(testing.receiveStorageReleased(&first));
            try std.testing.expect(testing.writeAborted(&first));
            try std.testing.expect(testing.outboundStorageReleased(&first));
            try std.testing.expectError(
                error.ConnectionClosed,
                first.sendText("late"),
            );

            var sibling = try H2Server.accept(self.server.allocator, &h2, .{});
            defer sibling.close();
            var message = try sibling.receiveMessageWithTimeout(.fromSeconds(2));
            defer message.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("sibling", message.payload);
            try sibling.sendClose(.normal_closure, "done");
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .max_concurrent_streams = 2,
            .enable_connect_protocol = true,
        },
    );
    defer h2_client.close();
    var first = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/abrupt-end",
    });
    defer first.close();
    try testing.writeFrame(&first, .text, "partial", false);
    try first.tunnel.closeWrite();
    var reset = try h2_client.readResetStreamWithTimeout(.fromSeconds(2));
    defer reset.deinit(allocator);
    try std.testing.expectEqual(first.tunnel.stream_id, reset.reset.stream_id);
    try std.testing.expectEqual(http2.ErrorCode.cancel, reset.reset.error_code);

    var sibling = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/sibling",
    });
    defer sibling.close();
    try sibling.sendText("sibling");
    var close = try sibling.receiveFrameWithTimeout(.fromSeconds(2));
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
    try sibling.sendClose(.normal_closure, "done");

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(first.tunnel.stream_id, shared.first_stream_id);
    try std.testing.expect(h2_client.isReusable());
}

test "WebSocket HTTP2 handshake timeout bounds CONNECT response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            var request = try h2.readExtendedConnectRequestWithTimeout(
                "websocket",
                .fromSeconds(1),
            );
            defer request.deinit(self.server.allocator);
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(150),
                .awake,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer h2_client.close();
    try std.testing.expectError(
        error.Timeout,
        H2Client.openWithTimeout(
            allocator,
            &h2_client,
            .{
                .authority = "localhost",
                .path = "/slow-response",
            },
            .fromMilliseconds(30),
        ),
    );
    try std.testing.expect(!h2_client.isReusable());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP2 server handshake resumes after idle timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        io: std.Io,
        timed_out: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.timed_out.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            try std.testing.expectError(
                error.Timeout,
                H2Server.acceptWithTimeout(
                    self.server.allocator,
                    &h2,
                    .{},
                    .fromMilliseconds(30),
                ),
            );
            self.timed_out.set(self.io);

            var ws = try H2Server.acceptWithTimeout(
                self.server.allocator,
                &h2,
                .{},
                .fromSeconds(1),
            );
            defer ws.close();
            try ws.sendText("accepted-after-timeout");
        }
    };

    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer h2_client.close();
    try shared.timed_out.wait(io);
    if (shared.err) |err| return err;
    var ws_client = try H2Client.openWithTimeout(
        allocator,
        &h2_client,
        .{ .authority = "localhost", .path = "/after-timeout" },
        .fromSeconds(1),
    );
    defer ws_client.close();
    var message = try ws_client.receiveMessageWithTimeout(.fromSeconds(1));
    defer message.deinit(allocator);
    try std.testing.expectEqualStrings(
        "accepted-after-timeout",
        message.payload,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP2 timeout APIs reject non-positive budgets" {
    var connection: http2_runtime.Connection = undefined;
    try std.testing.expectError(
        error.Timeout,
        H2Client.openWithTimeout(
            std.testing.allocator,
            &connection,
            .{},
            .zero,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        H2Server.acceptWithTimeout(
            std.testing.allocator,
            &connection,
            .{},
            .zero,
        ),
    );
}

test "WebSocket client rejects unoffered subprotocol" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
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
            var http_conn = try server_ptr.http.accept();
            defer http_conn.close();
            var head = try readHttpHead(server_ptr.http.allocator, http_conn.io, http_conn.stream, server_ptr.limits.max_head_bytes);
            defer head.deinit(server_ptr.http.allocator);
            var request = try http1.parseRequest(
                server_ptr.http.allocator,
                head.head,
                http1HandshakeRequestParseOptions(server_ptr.limits),
            );
            defer request.deinit(server_ptr.http.allocator);
            const key = request.header("sec-websocket-key") orelse return error.MissingHeader;
            var response: std.ArrayList(u8) = .empty;
            defer response.deinit(server_ptr.http.allocator);
            try websocket.writeServerHandshake(&response, server_ptr.http.allocator, key, &.{.{ .name = "Sec-WebSocket-Protocol", .value = "not-offered" }});
            try writeAllToStream(http_conn.io, http_conn.stream, response.items);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    try std.testing.expectError(error.InvalidSubprotocol, Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/bad-subprotocol",
        .protocols = &.{"superchat"},
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    }));

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket client rejects HTTP/1.0 upgrade responses" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
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
            var http_conn = try server_ptr.http.accept();
            defer http_conn.close();
            var head = try readHttpHead(server_ptr.http.allocator, http_conn.io, http_conn.stream, server_ptr.limits.max_head_bytes);
            defer head.deinit(server_ptr.http.allocator);
            var request = try http1.parseRequest(
                server_ptr.http.allocator,
                head.head,
                http1HandshakeRequestParseOptions(server_ptr.limits),
            );
            defer request.deinit(server_ptr.http.allocator);
            const key = request.header("sec-websocket-key") orelse return error.MissingHeader;
            const accept = websocket.acceptKey(key);
            var response: std.ArrayList(u8) = .empty;
            defer response.deinit(server_ptr.http.allocator);
            try response.appendSlice(server_ptr.http.allocator, "HTTP/1.0 101 Switching Protocols\r\n");
            try response.appendSlice(server_ptr.http.allocator, "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ");
            try response.appendSlice(server_ptr.http.allocator, &accept);
            try response.appendSlice(server_ptr.http.allocator, "\r\n\r\n");
            try writeAllToStream(http_conn.io, http_conn.stream, response.items);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    try std.testing.expectError(error.InvalidHandshake, Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/http10-response",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    }));

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket server rejects data sent with HTTP upgrade request" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        saw_expected: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept(.{}) catch |err| {
                if (err == error.InvalidHandshake) {
                    shared.saw_expected = true;
                    return;
                }
                shared.err = err;
                return;
            };
            connection.close();
            shared.err = error.InvalidHandshake;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var request: std.ArrayList(u8) = .empty;
    defer request.deinit(allocator);
    try request.appendSlice(
        allocator,
        "GET /early HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "\r\n",
    );
    try websocket.writeFrame(&request, allocator, .text, "too early", .{ .mask_key = .{ 1, 2, 3, 4 } });
    try writeAllToStream(io, stream, request.items);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.saw_expected);
}

test "WebSocket over HTTP/2 receiveFrameAuto replies to ping" {
    const allocator = std.testing.allocator;

    var backend = try @import("../runtime.zig").Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096, .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,
        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }
        fn runFallible(server_ptr: *http2_runtime.Server) !void {
            var h2 = try server_ptr.accept();
            defer h2.close();
            var ws = try H2Server.accept(server_ptr.allocator, &h2, .{
                .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
            });
            defer ws.close();
            var ping = try ws.receiveFrameAuto();
            defer ping.deinit(server_ptr.allocator);
            try std.testing.expectEqual(websocket.Opcode.ping, ping.header.opcode);
            try std.testing.expectEqualStrings("h2-auto?", ping.payload);
            var close = try ws.receiveFrameAuto();
            defer close.deinit(server_ptr.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    var server_task = io.async(Shared.run, .{&shared});
    defer server_task.cancel(io);

    var h2_client = try http2_runtime.Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer h2_client.close();
    var ws_client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/h2-auto-pong",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer ws_client.close();

    try ws_client.sendPing("h2-auto?");
    var pong = try ws_client.receiveFrame();
    defer pong.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
    try std.testing.expectEqualStrings("h2-auto?", pong.payload);
    try ws_client.sendClose(.normal_closure, "bye");
    var close = try ws_client.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);

    server_task.await(io);
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP/2 control sends do not retain frame scratch" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096, .enable_connect_protocol = true },
    );
    defer server.deinit();
    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,
        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }
        fn runFallible(server_ptr: *http2_runtime.Server) !void {
            var h2 = try server_ptr.accept();
            defer h2.close();
            var ws = try H2Server.accept(server_ptr.allocator, &h2, .{
                .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
            });
            defer ws.close();
            var ping = try ws.receiveFrame();
            defer ping.deinit(server_ptr.allocator);
            try std.testing.expectEqual(websocket.Opcode.ping, ping.header.opcode);
            try ws.sendPong(ping.payload);
            var close = try ws.receiveFrameAuto();
            defer close.deinit(server_ptr.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var h2_client = try http2_runtime.Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer h2_client.close();
    var client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/control-stack",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    try client.sendPing("stack");
    var pong = try client.receiveFrame();
    defer pong.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
    try std.testing.expectEqualStrings("stack", pong.payload);
    try client.sendClose(.normal_closure, "bye");
    var close = try client.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP/2 application frames avoid retained send scratch" {
    const allocator = std.testing.allocator;
    const payload = "borrowed-rfc8441-payload-" ** 700;
    const trailing_empty_parts = [_][]const u8{
        "0", "1", "2", "3", "4", "5", "6", "7",
        "8", "9", "a", "b", "c", "d", "e", "",
        "",
    };
    const trailing_empty_payload = "0123456789abcde";
    const h2_limits: http2_runtime.Limits = .{
        // An 8-KiB stream window makes each sender wait for several peer
        // WINDOW_UPDATE frames. It also places the WebSocket header/payload
        // join inside the first DATA frame, while a message larger than the
        // 16-KiB masking buffer verifies continuity across stack chunks.
        .initial_window_size = 8 * 1024,
        .max_body_bytes = payload.len + websocket.max_frame_header_len,
        .enable_connect_protocol = true,
    };

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        h2_limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *http2_runtime.Server) !void {
            var h2 = try server_ptr.accept();
            defer h2.close();
            var ws = try H2Server.accept(server_ptr.allocator, &h2, .{
                .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = payload.len,
                    .max_message_bytes = payload.len,
                },
            });
            defer ws.close();

            var empty = try ws.receiveFrame();
            defer empty.deinit(server_ptr.allocator);
            try std.testing.expectEqual(websocket.Opcode.binary, empty.header.opcode);
            try std.testing.expect(empty.header.fin);
            try std.testing.expectEqual(@as(usize, 0), empty.payload.len);
            var request = try ws.receiveFrame();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqual(websocket.Opcode.binary, request.header.opcode);
            try std.testing.expect(request.header.fin);
            try std.testing.expectEqualStrings(payload, request.payload);
            try ws.sendBinarySlices(&.{});
            try ws.sendBinarySlices(&.{
                payload[0..7],
                "",
                payload[7..19],
                payload[19..],
            });
            try ws.sendBinarySlices(&trailing_empty_parts);
            var close = try ws.receiveFrameAuto();
            defer close.deinit(server_ptr.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        h2_limits,
    );
    defer h2_client.close();
    var client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/borrowed-frame",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = payload.len,
            .max_message_bytes = payload.len,
        },
    });
    defer client.close();

    try client.sendBinarySlices(&.{});
    try client.sendBinarySlices(&.{
        payload[0..13],
        "",
        payload[13..41],
        payload[41..],
    });
    var empty = try client.receiveFrame();
    defer empty.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.binary, empty.header.opcode);
    try std.testing.expect(empty.header.fin);
    try std.testing.expectEqual(@as(usize, 0), empty.payload.len);
    var message = try client.receiveFrame();
    defer message.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.binary, message.header.opcode);
    try std.testing.expect(message.header.fin);
    try std.testing.expectEqualStrings(payload, message.payload);
    var trailing_empty = try client.receiveFrame();
    defer trailing_empty.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.binary, trailing_empty.header.opcode);
    try std.testing.expect(trailing_empty.header.fin);
    try std.testing.expectEqualStrings(
        trailing_empty_payload,
        trailing_empty.payload,
    );
    try client.sendClose(.normal_closure, "done");
    var close = try client.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP/2 in-place binary send masks and roundtrips" {
    const allocator = std.testing.allocator;
    const original = "mutable-rfc8441-payload";

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_body_bytes = 4096, .enable_connect_protocol = true },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var h2 = try shared.server.accept();
            defer h2.close();
            var ws = try H2Server.accept(shared.server.allocator, &h2, .{
                .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = 4096,
                    .max_message_bytes = 4096,
                },
            });
            defer ws.close();

            var request = try ws.receiveMessage();
            defer request.deinit(shared.server.allocator);
            try std.testing.expectEqual(websocket.Opcode.binary, request.opcode);
            try std.testing.expectEqualStrings(original, request.payload);
            try ws.sendText("in-place-received");
            var close = try ws.receiveFrameAuto();
            defer close.deinit(shared.server.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_body_bytes = 4096 },
    );
    defer h2_client.close();
    var client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/in-place",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 4096,
            .max_message_bytes = 4096,
        },
    });
    defer client.close();

    var payload = original.*;
    try client.sendBinaryInPlace(&payload);
    try std.testing.expect(!std.mem.eql(u8, original, &payload));
    var confirmation = try client.receiveMessageWithTimeout(.fromSeconds(5));
    defer confirmation.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, confirmation.opcode);
    try std.testing.expectEqualStrings("in-place-received", confirmation.payload);
    try client.sendClose(.normal_closure, "done");
    var close = try client.receiveFrameWithTimeout(.fromSeconds(5));
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP/2 compressed binary parts preserve one message" {
    const allocator = std.testing.allocator;
    const first = "h2-compressed-prefix-";
    const second = "compressible-borrowed-payload-" ** 64;
    const expected = first ++ second;

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_body_bytes = expected.len,
            .enable_connect_protocol = true,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *http2_runtime.Server) !void {
            var h2 = try server_ptr.accept();
            defer h2.close();
            var ws = try H2Server.accept(server_ptr.allocator, &h2, .{
                .enable_permessage_deflate = true,
                .compression_threshold = 0,
                .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = expected.len,
                    .max_message_bytes = expected.len,
                },
            });
            defer ws.close();

            var request = try ws.receiveMessage();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqual(websocket.Opcode.binary, request.opcode);
            try std.testing.expectEqualStrings(expected, request.payload);
            try ws.sendBinarySlices(&.{ first, "", second[0..17], second[17..] });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_body_bytes = expected.len },
    );
    defer h2_client.close();
    var client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/compressed-binary-parts",
        .enable_permessage_deflate = true,
        .compression_threshold = 0,
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = expected.len,
            .max_message_bytes = expected.len,
        },
    });
    defer client.close();

    try client.sendBinarySlices(&.{ first, second[0..17], "", second[17..] });
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.binary, response.opcode);
    try std.testing.expectEqualStrings(expected, response.payload);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP/2 compressed fragments reuse bounded send storage" {
    const allocator = std.testing.allocator;
    const payload_len = 64 * 1024;
    var payload: [payload_len]u8 = undefined;
    var random_state: u64 = 0x9e37_79b9_7f4a_7c15;
    for (payload[0 .. payload.len / 2]) |*byte| {
        random_state ^= random_state << 13;
        random_state ^= random_state >> 7;
        random_state ^= random_state << 17;
        byte.* = @truncate(random_state);
    }
    @memcpy(payload[payload.len / 2 ..], payload[0 .. payload.len / 2]);
    const fragments = [_][]const u8{
        payload[0..7000],
        payload[7000..28_000],
        payload[28_000..],
    };

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_body_bytes = payload_len,
            .enable_connect_protocol = true,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const server_ptr = shared.server;
            var h2 = try server_ptr.accept();
            defer h2.close();
            var ws = try H2Server.accept(server_ptr.allocator, &h2, .{
                .enable_permessage_deflate = true,
                .compression_threshold = 0,
                .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = payload_len,
                    .max_message_bytes = payload_len,
                },
            });
            defer ws.close();

            for (0..2) |iteration| {
                var request = try ws.receiveMessage();
                defer request.deinit(server_ptr.allocator);
                try std.testing.expectEqual(
                    websocket.Opcode.binary,
                    request.opcode,
                );
                try std.testing.expectEqualSlices(
                    u8,
                    shared.expected,
                    request.payload,
                );
                const response_fragments = [_][]const u8{
                    request.payload[0..7000],
                    request.payload[7000..28_000],
                    request.payload[28_000..],
                };
                if (iteration == 0) {
                    try ws.sendFragmented(.binary, &response_fragments);
                    try std.testing.expect(
                        ws.compression_send.payload.items.len >
                            masked_write_scratch_len,
                    );
                } else {
                    var failing = std.testing.FailingAllocator.init(
                        server_ptr.allocator,
                        .{},
                    );
                    ws.allocator = failing.allocator();
                    defer ws.allocator = server_ptr.allocator;
                    failing.fail_index = failing.alloc_index;
                    try ws.sendFragmented(.binary, &response_fragments);
                    try std.testing.expect(!failing.has_induced_failure);
                }
            }
        }
    };
    var shared = Shared{ .server = &server, .expected = &payload };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_body_bytes = payload_len },
    );
    defer h2_client.close();
    var client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/compressed-fragments-no-send-buffer",
        .enable_permessage_deflate = true,
        .compression_threshold = 0,
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = payload_len,
            .max_message_bytes = payload_len,
        },
    });
    defer client.close();

    for (0..2) |iteration| {
        if (iteration == 0) {
            try client.sendFragmented(.binary, &fragments);
            try std.testing.expect(
                client.compression_send.payload.items.len >
                    masked_write_scratch_len,
            );
        } else {
            var failing = std.testing.FailingAllocator.init(allocator, .{});
            client.allocator = failing.allocator();
            defer client.allocator = allocator;
            failing.fail_index = failing.alloc_index;
            try client.sendFragmented(.binary, &fragments);
            try std.testing.expect(!failing.has_induced_failure);
        }
        var response = try client.receiveMessage();
        defer response.deinit(allocator);
        try std.testing.expectEqual(websocket.Opcode.binary, response.opcode);
        try std.testing.expectEqualSlices(u8, &payload, response.payload);
    }

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP/2 uncompressed fragments use bounded send storage" {
    const allocator = std.testing.allocator;
    var payload: [40 * 1024]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index *% 131);
    const fragments = [_][]const u8{
        payload[0..9000],
        payload[9000..25_000],
        payload[25_000..],
    };

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_body_bytes = payload.len,
            .enable_connect_protocol = true,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const server_ptr = shared.server;
            var h2 = try server_ptr.accept();
            defer h2.close();
            var ws = try H2Server.accept(server_ptr.allocator, &h2, .{
                .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = shared.expected.len,
                    .max_message_bytes = shared.expected.len,
                },
            });
            defer ws.close();

            var request = try ws.receiveMessage();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualSlices(
                u8,
                shared.expected,
                request.payload,
            );
            try ws.sendFragmented(.binary, &.{
                request.payload[0..9000],
                request.payload[9000..25_000],
                request.payload[25_000..],
            });
        }
    };
    var shared = Shared{ .server = &server, .expected = &payload };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_body_bytes = payload.len },
    );
    defer h2_client.close();
    var client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/uncompressed-fragments-bounded",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = payload.len,
            .max_message_bytes = payload.len,
        },
    });
    defer client.close();

    try client.sendFragmented(.binary, &fragments);
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &payload, response.payload);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP/2 deadline spans control frames" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .enable_connect_protocol = true,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2_runtime.Server,
        timed_out: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var h2 = try shared.server.accept();
            defer h2.close();
            var ws = try H2Server.accept(
                shared.server.allocator,
                &h2,
                .{ .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = 4096,
                    .max_message_bytes = 4096,
                } },
            );
            defer ws.close();
            var storage: [4096]u8 = undefined;
            _ = ws.receiveMessageIntoWithDeadline(
                &storage,
                .fromNow(
                    shared.server.io,
                    .{ .raw = .fromMilliseconds(300), .clock = .awake },
                ),
            ) catch |err| {
                if (err != error.Timeout) return err;
                shared.timed_out = true;
                return;
            };
            return error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer h2_client.close();
    var ws_client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/deadline",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 4096,
            .max_message_bytes = 4096,
        },
    });
    defer ws_client.close();
    for (0..2) |_| {
        try std.Io.sleep(io, .fromMilliseconds(100), .awake);
        try ws_client.sendPing("keep-http2-busy");
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.timed_out);
}

test "WebSocket receiveFrameAuto replies to ping" {
    const allocator = std.testing.allocator;

    var backend = try @import("../runtime.zig").Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
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
            var connection = try server_ptr.accept(.{});
            defer connection.close();
            var ping = try connection.receiveFrameAuto();
            defer ping.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.ping, ping.header.opcode);
            try std.testing.expectEqualStrings("auto?", ping.payload);
            var close = try connection.receiveFrameAuto();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    var server_task = io.async(Shared.run, .{&shared});
    defer server_task.cancel(io);

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/auto-pong",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    try client.sendPing("auto?");
    var pong = try client.receiveFrame();
    defer pong.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
    try std.testing.expectEqualStrings("auto?", pong.payload);
    try client.sendClose(.normal_closure, "bye");
    var close = try client.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);

    server_task.await(io);
    if (shared.err) |err| return err;
}

test "WebSocket pingWithDeadline preserves an interleaved message" {
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
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
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
            var connection = try self.server.accept(.{});
            defer connection.close();
            var ping = try connection.receiveFrame();
            defer ping.deinit(self.server.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.ping, ping.header.opcode);
            try connection.sendText("in flight");
            try connection.sendPong(ping.payload);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/ping-deadline",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();
    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    );
    var application = try client.pingWithDeadline("probe", deadline);
    defer application.deinit(allocator);
    switch (application) {
        .application => |frame| {
            try std.testing.expectEqual(websocket.Opcode.text, frame.header.opcode);
            try std.testing.expectEqualStrings("in flight", frame.payload);
        },
        else => return error.TestUnexpectedResult,
    }
    var pong = try client.continuePingWithTimeout(
        "probe",
        .fromSeconds(1),
    );
    defer pong.deinit(allocator);
    try std.testing.expect(pong == .pong);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket pingWithTimeout rejects mismatched Pong" {
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
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
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
            var connection = try self.server.accept(.{});
            defer connection.close();
            var ping = try connection.receiveFrame();
            defer ping.deinit(self.server.http.allocator);
            try connection.sendPong("wrong");
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/wrong-pong",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();
    try std.testing.expectError(
        error.UnexpectedPong,
        client.pingWithTimeout("probe", .fromSeconds(1)),
    );
    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket pingWithTimeout reports peer Close" {
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
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
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
            var connection = try self.server.accept(.{});
            defer connection.close();
            var ping = try connection.receiveFrame();
            defer ping.deinit(self.server.http.allocator);
            try connection.sendClose(.going_away, "maintenance");
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/ping-close",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();
    var event = try client.pingWithTimeout("probe", .fromSeconds(1));
    defer event.deinit(allocator);
    switch (event) {
        .closed => |maybe_close| {
            const close = maybe_close orelse return error.TestUnexpectedResult;
            try std.testing.expectEqual(websocket.CloseCode.going_away, close.code);
            try std.testing.expectEqualStrings("maintenance", close.reason);
        },
        else => return error.TestUnexpectedResult,
    }
    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket pingWithTimeout enforces one deadline" {
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
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
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
            var connection = try self.server.accept(.{});
            defer connection.close();
            var ping = try connection.receiveFrame();
            defer ping.deinit(self.server.http.allocator);
            try std.Io.sleep(self.server.http.io, .fromMilliseconds(80), .awake);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/ping-timeout",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();
    try std.testing.expectError(
        error.Timeout,
        client.pingWithTimeout("probe", .fromMilliseconds(20)),
    );
    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket over HTTP2 pingWithTimeout validates Pong" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .enable_connect_protocol = true,
        },
    );
    defer server.deinit();
    const Shared = struct {
        server: *http2_runtime.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            var ws = try H2Server.accept(
                self.server.allocator,
                &h2,
                .{ .limits = .{
                    .max_head_bytes = 4096,
                    .max_frame_bytes = 4096,
                    .max_message_bytes = 4096,
                } },
            );
            defer ws.close();
            var ping = try ws.receiveFrame();
            defer ping.deinit(self.server.allocator);
            try std.testing.expectEqual(websocket.Opcode.ping, ping.header.opcode);
            try ws.sendPong(ping.payload);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var h2_client = try http2_runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .enable_connect_protocol = true,
        },
    );
    defer h2_client.close();
    var client = try H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/h2-ping-timeout",
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 4096,
            .max_message_bytes = 4096,
        },
    });
    defer client.close();
    var event = try client.pingWithTimeout("h2-probe", .fromSeconds(1));
    defer event.deinit(allocator);
    try std.testing.expect(event == .pong);
    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket receiveFrameAuto does not pong after sending close" {
    const allocator = std.testing.allocator;

    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .close_sent = .init(true),
    };
    defer connection.inbuf.deinit(allocator);
    try connection.inbuf.appendSlice(allocator, "\x89\x01?");
    var ping = try connection.receiveFrameAuto();
    defer ping.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.ping, ping.header.opcode);
    try std.testing.expectEqualStrings("?", ping.payload);

    var h2 = H2Connection{
        .allocator = allocator,
        .tunnel = undefined,
        .role = .client,
        .close_sent = .init(true),
    };
    defer h2.inbuf.deinit(allocator);
    try h2.inbuf.appendSlice(allocator, "\x89\x01?");
    var h2_ping = try h2.receiveFrameAuto();
    defer h2_ping.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.ping, h2_ping.header.opcode);
    try std.testing.expectEqualStrings("?", h2_ping.payload);
}

test "WebSocket runtime exposes typed close frames" {
    const allocator = std.testing.allocator;

    var backend = try @import("../runtime.zig").Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
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
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            try connection.sendCloseFrame(.{ .code = .going_away, .reason = "restart" });

            var ack = (try connection.receiveCloseFrame()).?;
            defer ack.deinit(connection.allocator);
            try std.testing.expectEqual(websocket.CloseCode.normal_closure, ack.code);
            try std.testing.expectEqualStrings("ack", ack.reason);
        }
    };

    var shared = Shared{ .server = &server };
    var server_task = io.async(Shared.run, .{&shared});
    defer server_task.cancel(io);

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/typed-close",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    var close_frame = (try client.receiveCloseFrame()).?;
    defer close_frame.deinit(allocator);
    try std.testing.expectEqual(websocket.CloseCode.going_away, close_frame.code);
    try std.testing.expectEqualStrings("restart", close_frame.reason);
    try client.sendCloseFrame(.{ .code = .normal_closure, .reason = "ack" });

    server_task.await(io);
    if (shared.err) |err| return err;
}

test "WebSocket receiveMessage assembles fragments and handles control frames" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
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
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            var message = try connection.receiveMessage();
            defer message.deinit(connection.allocator);
            try std.testing.expectEqual(websocket.Opcode.text, message.opcode);
            try std.testing.expectEqualStrings("hello fragmented", message.payload);

            try std.testing.expectError(error.ConnectionClosed, connection.receiveMessage());
            try std.testing.expect(connection.close_received.load(.acquire));
            try std.testing.expect(connection.close_sent.load(.acquire));
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/message",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    try client.sendPing("?");
    const fragments = [_][]const u8{ "hello ", "fragmented" };
    try client.sendFragmented(.text, &fragments);

    var pong = try client.receiveFrame();
    defer pong.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.pong, pong.header.opcode);
    try std.testing.expectEqualStrings("?", pong.payload);

    try client.sendClose(.normal_closure, "bye");
    var close = try client.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket HTTP1 abrupt EOF releases receive state and blocks writes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
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
            var connection = try self.server.accept(.{});
            defer connection.close();
            try std.testing.expectError(
                error.ConnectionClosed,
                connection.receiveMessageWithTimeout(.fromSeconds(1)),
            );
            try std.testing.expect(testing.receiveStorageReleased(&connection));
            try std.testing.expect(testing.writeAborted(&connection));
            try std.testing.expect(testing.outboundStorageReleased(&connection));
            try std.testing.expectError(
                error.ConnectionClosed,
                connection.sendText("late"),
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/abrupt-eof",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();
    try testing.writeFrame(&client, .text, "partial", false);
    try client.stream.shutdown(io, .send);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket receiveMessage enforces aggregate fragmented message limit" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096, .max_message_bytes = 12 },
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
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            try std.testing.expectError(error.PayloadTooLarge, connection.receiveMessage());
            try std.testing.expect(connection.close_sent.load(.acquire));
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/message-limit",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096, .max_message_bytes = 4096 },
    });
    defer client.close();

    const fragments = [_][]const u8{ "12345678", "abcdef" };
    try client.sendFragmented(.text, &fragments);

    var close = try client.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
    try std.testing.expectEqual(
        websocket.CloseCode.message_too_big,
        (try websocket.parseClosePayload(close.payload)).?.code,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket receiveMessage allows in-flight data after initiating close" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
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
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            try connection.sendClose(.normal_closure, "draining");

            // Like tungstenite, initiating the close handshake only closes our
            // write side.  Data already sent by the peer is still readable
            // until its close acknowledgement arrives.
            var message = try connection.receiveMessage();
            defer message.deinit(connection.allocator);
            try std.testing.expectEqual(websocket.Opcode.text, message.opcode);
            try std.testing.expectEqualStrings("already in flight", message.payload);

            try std.testing.expectError(error.ConnectionClosed, connection.receiveMessage());
            try std.testing.expect(connection.close_sent.load(.acquire));
            try std.testing.expect(connection.close_received.load(.acquire));
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/close-after-send",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    try client.sendText("already in flight");

    var close = try client.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
    try client.sendClose(.normal_closure, "ack");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket runtimes validate outgoing text and close frames" {
    const allocator = std.testing.allocator;
    const bad_utf8 = "\xc0\x80";
    const too_large_control = "x" ** 126;

    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
    };
    try std.testing.expectError(error.InvalidUtf8, connection.sendText(bad_utf8));
    try std.testing.expectError(error.InvalidUtf8, connection.sendFragmented(.text, &.{ "\xe2", "(" }));
    try std.testing.expectError(error.InvalidUtf8, connection.sendClose(.normal_closure, bad_utf8));
    try std.testing.expectError(error.InvalidCloseCode, connection.sendClose(.no_status_received, ""));
    try std.testing.expectError(error.InvalidControlFrame, connection.sendPing(too_large_control));
    try std.testing.expectError(error.InvalidFrame, connection.sendFrame(.text, "bypass"));
    try std.testing.expectError(error.InvalidFrame, connection.sendFrame(.continuation, "bypass"));

    var h2 = H2Connection{
        .allocator = allocator,
        .tunnel = undefined,
        .role = .client,
    };
    try std.testing.expectError(error.InvalidUtf8, h2.sendText(bad_utf8));
    try std.testing.expectError(error.InvalidUtf8, h2.sendFragmented(.text, &.{ "\xf0\x9f", "\x28" }));
    try std.testing.expectError(error.InvalidUtf8, h2.sendClose(.normal_closure, bad_utf8));
    try std.testing.expectError(error.InvalidCloseCode, h2.sendClose(.abnormal_closure, ""));
    try std.testing.expectError(error.InvalidControlFrame, h2.sendPong(too_large_control));
    try std.testing.expectError(error.InvalidFrame, h2.sendFrame(.binary, "bypass"));
    try std.testing.expectError(error.InvalidFrame, h2.sendFrame(.continuation, "bypass"));
}

test "WebSocket caller-buffer receive rejects API mixing without failing connection" {
    const allocator = std.testing.allocator;
    var out: [16]u8 = undefined;

    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .limits = .{ .max_message_bytes = out.len },
        .message_assembler = websocket.MessageAssembler.initLimited(
            allocator,
            out.len,
        ),
    };
    defer if (connection.message_assembler) |*assembler| assembler.deinit();
    try std.testing.expectError(
        error.InvalidFrame,
        connection.receiveMessageInto(&out),
    );
    try std.testing.expect(!connection.receiveFailed());
    try std.testing.expect(!connection.closeSent());
    try std.testing.expect(connection.message_assembler != null);

    var h2 = H2Connection{
        .allocator = allocator,
        .tunnel = undefined,
        .role = .client,
        .limits = .{ .max_message_bytes = out.len },
        .message_assembler = websocket.MessageAssembler.initLimited(
            allocator,
            out.len,
        ),
    };
    defer if (h2.message_assembler) |*assembler| assembler.deinit();
    try std.testing.expectError(
        error.InvalidFrame,
        h2.receiveMessageInto(&out),
    );
    try std.testing.expect(!h2.receiveFailed());
    try std.testing.expect(!h2.closeSent());
    try std.testing.expect(h2.message_assembler != null);
}

test "WebSocket HTTP1 and HTTP2 sends enforce configured outbound limits" {
    const limits: Limits = .{
        .max_frame_bytes = 4,
        .max_message_bytes = 6,
    };

    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
        .permessage_deflate = true,
        .limits = limits,
    };
    try std.testing.expectError(
        error.MessageTooLarge,
        connection.sendText("five!"),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        connection.sendBinaryParts("abc", "de"),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        connection.sendBinarySlices(&.{ "a", "", "bc", "de" }),
    );
    connection.permessage_deflate = false;
    var in_place_payload = [_]u8{ 1, 2, 3, 4, 5 };
    try std.testing.expectError(
        error.MessageTooLarge,
        connection.sendBinaryInPlace(&in_place_payload),
    );
    connection.permessage_deflate = true;
    try std.testing.expectError(
        error.MessageTooLarge,
        connection.sendFragmented(.binary, &.{ "abc", "def", "g" }),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        connection.sendPing("five!"),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        connection.sendClose(.normal_closure, "abc"),
    );

    var h2 = H2Connection{
        .allocator = std.testing.allocator,
        .tunnel = undefined,
        .role = .client,
        .permessage_deflate = true,
        .limits = limits,
    };
    try std.testing.expectError(
        error.MessageTooLarge,
        h2.sendBinary("five!"),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        h2.sendBinaryParts("abc", "de"),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        h2.sendBinarySlices(&.{ "a", "", "bc", "de" }),
    );
    h2.permessage_deflate = false;
    try std.testing.expectError(
        error.MessageTooLarge,
        h2.sendBinaryInPlace(&in_place_payload),
    );
    h2.permessage_deflate = true;
    try std.testing.expectError(
        error.MessageTooLarge,
        h2.sendFragmented(.binary, &.{ "abc", "def", "g" }),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        h2.sendPong("five!"),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        h2.sendClose(.normal_closure, "abc"),
    );
}

test "WebSocket runtimes reject duplicate close sends" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .close_sent = .init(true),
    };
    try std.testing.expectError(error.ConnectionClosed, connection.sendFrame(.close, &.{}));
    try std.testing.expectError(error.ConnectionClosed, connection.sendClose(.normal_closure, "again"));

    var h2 = H2Connection{
        .allocator = allocator,
        .tunnel = undefined,
        .role = .client,
        .close_sent = .init(true),
    };
    try std.testing.expectError(error.ConnectionClosed, h2.sendFrame(.close, &.{}));
    try std.testing.expectError(error.ConnectionClosed, h2.sendClose(.normal_closure, "again"));
}

test "WebSocket writers retain close-state guards inside send lock" {
    // Public writers perform cheap argument/state validation before blocking,
    // then use this post-lock guard to close the race with an earlier writer
    // that committed Close while they waited. Exercise both stream adapters
    // without constructing an unrelated transport.
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
        .close_sent = .init(true),
    };
    try std.testing.expect(!connection.canSendOpcodeLocked(.text));

    var h2 = H2Connection{
        .allocator = std.testing.allocator,
        .tunnel = undefined,
        .role = .client,
        .close_sent = .init(true),
    };
    try std.testing.expect(!h2.canSendOpcodeLocked(.text));

    var failed = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
        .receive_failed = .init(true),
    };
    try std.testing.expect(!failed.canSendOpcodeLocked(.text));
    try std.testing.expect(!failed.canSendOpcodeLocked(.close));
    try std.testing.expectError(error.ConnectionClosed, failed.sendText("x"));
    try std.testing.expectError(
        error.ConnectionClosed,
        failed.updateTrafficKeys(false),
    );

    var failed_h2 = H2Connection{
        .allocator = std.testing.allocator,
        .tunnel = undefined,
        .role = .client,
        .receive_failed = .init(true),
    };
    try std.testing.expect(!failed_h2.canSendOpcodeLocked(.text));
    try std.testing.expect(!failed_h2.canSendOpcodeLocked(.close));
    try std.testing.expectError(error.ConnectionClosed, failed_h2.sendText("x"));
}

test "WebSocket HTTP2 pending tunnel data uses parent allocator" {
    var parent_gpa: std.heap.DebugAllocator(.{}) = .init;
    defer std.testing.expect(parent_gpa.deinit() == .ok) catch
        @panic("parent allocator leak");
    var adapter_gpa: std.heap.DebugAllocator(.{}) = .init;
    defer std.testing.expect(adapter_gpa.deinit() == .ok) catch
        @panic("adapter allocator leak");
    const parent_allocator = parent_gpa.allocator();
    const adapter_allocator = adapter_gpa.allocator();

    var parent = http2_runtime.Connection{
        .io = undefined,
        .allocator = parent_allocator,
        .stream = undefined,
        .role = .client,
    };
    const first_bytes = try parent_allocator.dupe(u8, "parent-close");
    var close_connection = H2Connection{
        .allocator = adapter_allocator,
        .tunnel = .{ .connection = &parent, .stream_id = 1 },
        .role = .client,
        .pending_tunnel_data = .{
            .frame = .{
                .bytes = first_bytes,
                .frame = .{
                    .header = .{
                        .length = @intCast(first_bytes.len),
                        .frame_type = .data,
                        .flags = 0,
                        .stream_id = 1,
                    },
                    .payload = first_bytes,
                },
            },
            .data = first_bytes,
            .end_stream = false,
        },
    };
    close_connection.close();

    const second_bytes = try parent_allocator.dupe(u8, "parent-fatal");
    var failed_connection = H2Connection{
        .allocator = adapter_allocator,
        .tunnel = .{ .connection = &parent, .stream_id = 3 },
        .role = .client,
        .pending_tunnel_data = .{
            .frame = .{
                .bytes = second_bytes,
                .frame = .{
                    .header = .{
                        .length = @intCast(second_bytes.len),
                        .frame_type = .data,
                        .flags = 0,
                        .stream_id = 3,
                    },
                    .payload = second_bytes,
                },
            },
            .data = second_bytes,
            .end_stream = false,
        },
    };
    try std.testing.expect(failReceive(&failed_connection));
    try std.testing.expect(testing.receiveStorageReleased(&failed_connection));
    failed_connection.close();
}

test "WebSocket HTTP2 in-place send rejects unsupported modes" {
    var server = H2Connection{
        .allocator = std.testing.allocator,
        .tunnel = undefined,
        .role = .server,
    };
    var payload = [_]u8{1};
    try std.testing.expectError(
        error.InvalidFrame,
        server.sendBinaryInPlace(&payload),
    );

    var compressed = H2Connection{
        .allocator = std.testing.allocator,
        .tunnel = undefined,
        .role = .client,
        .permessage_deflate = true,
    };
    try std.testing.expectError(
        error.InvalidFrame,
        compressed.sendBinaryInPlace(&payload),
    );

    var closed = H2Connection{
        .allocator = std.testing.allocator,
        .tunnel = undefined,
        .role = .client,
        .close_sent = .init(true),
    };
    try std.testing.expectError(
        error.ConnectionClosed,
        closed.sendBinaryInPlace(&payload),
    );

    var too_small = H2Connection{
        .allocator = std.testing.allocator,
        .tunnel = undefined,
        .role = .client,
        .limits = .{ .max_frame_bytes = 0, .max_message_bytes = 0 },
    };
    try std.testing.expectError(
        error.MessageTooLarge,
        too_small.sendBinaryInPlace(&payload),
    );
}

test "WebSocket send state blocks data after receiving close" {
    try std.testing.expect(!canSendOpcode(.text, false, true));
    try std.testing.expect(!canSendOpcode(.binary, false, true));
    try std.testing.expect(!canSendOpcode(.ping, false, true));
    try std.testing.expect(canSendOpcode(.close, false, true));
    try std.testing.expect(!canSendOpcode(.close, true, true));
}

test "WebSocket runtimes reject frames after received close" {
    const allocator = std.testing.allocator;

    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
    };
    defer connection.inbuf.deinit(allocator);
    try connection.inbuf.appendSlice(allocator, "\x88\x00" ++ "\x81\x02hi");
    var close = try connection.receiveFrame();
    defer close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
    try std.testing.expectError(error.ConnectionClosed, connection.receiveFrame());

    var h2 = H2Connection{
        .allocator = allocator,
        .tunnel = undefined,
        .role = .client,
    };
    defer h2.inbuf.deinit(allocator);
    try h2.inbuf.appendSlice(allocator, "\x88\x00" ++ "\x81\x02hi");
    var h2_close = try h2.receiveFrame();
    defer h2_close.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.close, h2_close.header.opcode);
    try std.testing.expectError(error.ConnectionClosed, h2.receiveFrame());
}

test "WebSocket runtimes return closed after close handshake completes" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .close_sent = .init(true),
        .close_received = .init(true),
    };
    try std.testing.expectError(error.ConnectionClosed, connection.receiveFrame());
    try std.testing.expectError(error.ConnectionClosed, connection.receiveMessage());

    var h2 = H2Connection{
        .allocator = allocator,
        .tunnel = undefined,
        .role = .client,
        .close_sent = .init(true),
        .close_received = .init(true),
    };
    try std.testing.expectError(error.ConnectionClosed, h2.receiveFrame());
    try std.testing.expectError(error.ConnectionClosed, h2.receiveMessage());
}

test "WebSocket async std.Io server handles concurrent clients" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        pub fn handle(_: *@This(), connection: *Connection) Error!void {
            var frame = try connection.receiveFrame();
            defer frame.deinit(connection.allocator);
            if (frame.header.opcode != .text) return error.ProtocolFailure;
            if (std.mem.eql(u8, frame.payload, "one")) {
                try connection.sendText("echo-one");
            } else if (std.mem.eql(u8, frame.payload, "two")) {
                try connection.sendText("echo-two");
            } else {
                try connection.sendClose(.unsupported_data, "unexpected");
            }

            var close = try connection.receiveFrame();
            defer close.deinit(connection.allocator);
            if (close.header.opcode != .close) return error.ProtocolFailure;
        }
    };

    const Shared = struct {
        server: *Server,
        context: Context = .{},
        result: ?ConcurrentServeResult = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.result = shared.server.serveConcurrent(Context, &shared.context, Context.handle, 2, .{}) catch |err| {
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
        payload: []const u8,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(task: *@This()) void {
            runFallible(task) catch |err| {
                task.err = err;
            };
        }

        fn runFallible(task: *@This()) !void {
            var client = try Client.connect(task.allocator, task.io, task.address, .{
                .host = "127.0.0.1",
                .target = "/async",
                .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
            });
            defer client.close();

            try client.sendText(task.payload);
            var response = try client.receiveFrame();
            defer response.deinit(task.allocator);
            try std.testing.expectEqual(websocket.Opcode.text, response.header.opcode);
            try std.testing.expectEqualStrings(task.expected, response.payload);
            try client.sendClose(.normal_closure, "bye");
        }
    };

    var clients = [_]ClientTask{
        .{ .allocator = allocator, .io = io, .address = server.address(), .payload = "one", .expected = "echo-one" },
        .{ .allocator = allocator, .io = io, .address = server.address(), .payload = "two", .expected = "echo-two" },
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

test "WebSocket connection serializes concurrent sends" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn sendOne(connection: *Connection, payload: []const u8, err: *?anyerror) void {
            connection.sendText(payload) catch |e| {
                err.* = e;
            };
        }

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept(.{});
            defer connection.close();

            var err_a: ?anyerror = null;
            var err_b: ?anyerror = null;
            const thread_a = try std.Thread.spawn(.{}, sendOne, .{ &connection, "from-a", &err_a });
            const thread_b = try std.Thread.spawn(.{}, sendOne, .{ &connection, "from-b", &err_b });
            thread_a.join();
            thread_b.join();
            if (err_a) |err| return err;
            if (err_b) |err| return err;

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/send-lock",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

    var first = try client.receiveFrame();
    defer first.deinit(allocator);
    var second = try client.receiveFrame();
    defer second.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, first.header.opcode);
    try std.testing.expectEqual(websocket.Opcode.text, second.header.opcode);
    const saw_a = std.mem.eql(u8, first.payload, "from-a") or std.mem.eql(u8, second.payload, "from-a");
    const saw_b = std.mem.eql(u8, first.payload, "from-b") or std.mem.eql(u8, second.payload, "from-b");
    try std.testing.expect(saw_a);
    try std.testing.expect(saw_b);
    try client.sendClose(.normal_closure, "bye");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebSocket HTTP upgrade reader enforces header byte limit at delimiter" {
    const exact = "GET /chat HTTP/1.1\r\nHost: example\r\n\r\n";
    try std.testing.expectEqual(@as(?usize, exact.len - 4), try findHttpHeadEndWithinLimit(exact, exact.len));
    try std.testing.expectError(error.HeadersTooLarge, findHttpHeadEndWithinLimit(exact, exact.len - 1));

    const incomplete = "GET /chat HTTP/1.1\r\nHost: example";
    try std.testing.expectEqual(@as(?usize, null), try findHttpHeadEndWithinLimit(incomplete, incomplete.len + 1));
    try std.testing.expectError(error.HeadersTooLarge, findHttpHeadEndWithinLimit(incomplete, incomplete.len));
}

test {
    _ = h3;
    _ = @import("runtime/message/tests/buffer.zig");
    _ = @import("runtime/message/tests/state.zig");
    _ = @import("runtime/handshake/capacity_tests.zig");
    _ = @import("runtime/handshake/h1_attempt_tests.zig");
    _ = @import("runtime/handshake/h2_admission_tests.zig");
    _ = @import("runtime/h3_tests.zig");
    _ = @import("runtime/h3_recovery_tests.zig");
    _ = @import("runtime/unix_tests.zig");
    _ = @import("runtime/error_close_tests.zig");
    _ = @import("runtime/close_timeout_tests.zig");
    _ = @import("runtime/handshake_timeout_tests.zig");
    _ = @import("runtime/message_io_tests.zig");
    _ = @import("runtime/compression_threshold_tests.zig");
    _ = @import("runtime/wss_tests.zig");
    _ = @import("runtime/server_lifecycle_tests.zig");
    _ = @import("runtime/handshake_header_tests.zig");
}
