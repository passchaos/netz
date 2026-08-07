const std = @import("std");
const websocket = @import("mod.zig");
const http1 = @import("../http1/mod.zig");
const http2 = @import("../http2/mod.zig");
const http1_runtime = http1.runtime;
const http2_runtime = http2.runtime;
const wire = @import("../internal/wire.zig");

const net = std.Io.net;

pub const Error = websocket.Error || http1_runtime.Error || http2_runtime.Error || error{
    HeadersTooLarge,
    ConnectionClosed,
    InvalidResponse,
    InvalidSubprotocol,
    InvalidUri,
    UnsupportedScheme,
    MessageTooLarge,
} || std.Io.RandomSecureError || net.HostName.ValidateError || net.HostName.ConnectError || net.Stream.Reader.Error || net.Stream.Writer.Error;

pub const Limits = struct {
    max_head_bytes: usize = 64 * 1024,
    max_frame_bytes: usize = 16 * 1024 * 1024,
    max_message_bytes: usize = 16 * 1024 * 1024,
};

pub const Role = enum {
    client,
    server,
};

const RuntimeTransport = union(enum) {
    tcp: struct { io: std.Io, stream: net.Stream },
    tls: *http1_runtime.TlsClientConnection,

    fn read(self: RuntimeTransport, buffer: []u8) Error!usize {
        return switch (self) {
            .tcp => |tcp| readSome(tcp.io, tcp.stream, buffer),
            .tls => |conn| conn.read(buffer),
        };
    }

    fn writeAll(self: RuntimeTransport, bytes: []const u8) Error!void {
        return switch (self) {
            .tcp => |tcp| writeAllToStream(tcp.io, tcp.stream, bytes),
            .tls => |conn| conn.writeAll(bytes),
        };
    }
};

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
        var http_conn = try self.http.accept();
        errdefer http_conn.close();

        var head = try readHttpHead(self.http.allocator, http_conn.io, http_conn.stream, self.limits.max_head_bytes);
        defer head.deinit(self.http.allocator);

        var request = try http1.parseRequest(self.http.allocator, head.head, .{});
        defer request.deinit(self.http.allocator);
        try websocket.validateClientHandshake(request);
        // Match tungstenite's server handshake behavior: bytes after the HTTP
        // request are ambiguous before the upgrade response is committed and
        // may be request smuggling/junk.  Clients must wait for 101 before
        // sending WebSocket frames.
        if (head.extra.len != 0) return error.InvalidHandshake;

        const key = request.header("sec-websocket-key") orelse return error.MissingHeader;
        const selected_protocol = try selectHttp1Subprotocol(self.http.allocator, request.headers, options.protocols);
        errdefer if (selected_protocol) |protocol| self.http.allocator.free(protocol);
        const selected_extension = try websocket.ExtensionNegotiation.acceptClientHeaders(
            self.http.allocator,
            request.headers,
            options.enable_permessage_deflate,
        );
        defer if (selected_extension) |extension| self.http.allocator.free(extension);
        var response: std.ArrayList(u8) = .empty;
        defer response.deinit(self.http.allocator);
        var headers: std.ArrayList(http1.Header) = .empty;
        defer headers.deinit(self.http.allocator);
        if (selected_protocol) |protocol| try headers.append(self.http.allocator, .{ .name = "Sec-WebSocket-Protocol", .value = protocol });
        if (selected_extension) |extension| try headers.append(self.http.allocator, .{ .name = "Sec-WebSocket-Extensions", .value = extension });
        try headers.appendSlice(self.http.allocator, options.extra_headers);
        try websocket.writeServerHandshake(&response, self.http.allocator, key, headers.items);
        try writeAllToStream(http_conn.io, http_conn.stream, response.items);

        const connection = Connection{
            .io = http_conn.io,
            .allocator = self.http.allocator,
            .stream = http_conn.stream,
            .role = .server,
            .limits = self.limits,
            .selected_protocol = selected_protocol,
            .permessage_deflate = selected_extension != null,
            .inbuf = .empty,
        };
        return connection;
    }

    pub fn serveConcurrent(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (*HandlerContext, *Connection) Error!void,
        max_connections: usize,
        options: AcceptOptions,
    ) AsyncServeError!ConcurrentServeResult {
        var group: std.Io.Group = .init;
        const results = try self.http.allocator.alloc(?anyerror, max_connections);
        errdefer self.http.allocator.free(results);
        @memset(results, null);

        for (results) |*result| {
            var connection = try self.accept(options);
            errdefer connection.close();
            const task = ServeTask(HandlerContext){
                .connection = connection,
                .context = context,
                .handler = handler,
                .result = result,
            };
            group.async(self.http.io, ServeTask(HandlerContext).run, .{task});
        }

        try group.await(self.http.io);
        return .{ .allocator = self.http.allocator, .errors = results };
    }
};

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
    extra_headers: []const http1.Header = &.{},
    enable_permessage_deflate: bool = false,
};

pub const Client = struct {
    pub fn connect(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
    ) Error!Connection {
        const stream = net.IpAddress.connect(&address, io, .{ .mode = .stream }) catch |err| return err;
        errdefer stream.close(io);
        return connectStream(allocator, io, stream, null, options);
    }

    pub fn connectHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
    ) Error!Connection {
        const host_name = try net.HostName.init(host);
        const stream = try host_name.connect(io, port, .{ .mode = .stream });
        errdefer stream.close(io);
        const default_host = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ host, port });
        defer allocator.free(default_host);
        var connect_options = options;
        if (connect_options.host.len == 0) connect_options.host = default_host;
        return connectStream(allocator, io, stream, null, connect_options);
    }

    pub fn connectTlsHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
        tls_options: http1_runtime.TlsClientOptions,
    ) Error!Connection {
        const host_name = try net.HostName.init(host);
        const stream = try host_name.connect(io, port, .{ .mode = .stream });
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        const tls_conn = try http1_runtime.TlsClientConnection.init(allocator, io, stream, host, tls_options);
        stream_owned = false;
        errdefer tls_conn.deinit();
        const default_host = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ host, port });
        defer allocator.free(default_host);
        var connect_options = options;
        if (connect_options.host.len == 0) connect_options.host = default_host;
        return connectStream(allocator, io, stream, tls_conn, connect_options);
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
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        const is_ws = std.ascii.eqlIgnoreCase(uri.scheme, "ws");
        const is_wss = std.ascii.eqlIgnoreCase(uri.scheme, "wss");
        if (!is_ws and !is_wss) return error.UnsupportedScheme;
        const target = try uriTargetAlloc(allocator, uri);
        defer allocator.free(target);
        var endpoint = try http1_runtime.uriEndpoint(allocator, uri, if (is_wss) 443 else 80);
        defer endpoint.deinit();

        var connect_options = options;
        connect_options.target = target;
        if (connect_options.host.len == 0) connect_options.host = endpoint.authority;

        const stream = try endpoint.connect(io);
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        if (is_wss) {
            const tls_conn = try http1_runtime.TlsClientConnection.init(allocator, io, stream, endpoint.tls_host, tls_options);
            stream_owned = false;
            errdefer tls_conn.deinit();
            return connectStream(allocator, io, stream, tls_conn, connect_options);
        }
        const connection = try connectStream(allocator, io, stream, null, connect_options);
        stream_owned = false;
        return connection;
    }

    fn connectStream(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        tls_conn: ?*http1_runtime.TlsClientConnection,
        options: ConnectOptions,
    ) Error!Connection {
        var nonce: [16]u8 = undefined;
        try std.Io.randomSecure(io, &nonce);
        var key: [24]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&key, &nonce);

        var headers: std.ArrayList(http1.Header) = .empty;
        defer headers.deinit(allocator);
        try headers.appendSlice(allocator, &.{
            .{ .name = "Upgrade", .value = "websocket" },
            .{ .name = "Connection", .value = "Upgrade" },
            .{ .name = "Sec-WebSocket-Key", .value = &key },
            .{ .name = "Sec-WebSocket-Version", .value = "13" },
        });
        var protocol_value: std.ArrayList(u8) = .empty;
        defer protocol_value.deinit(allocator);
        if (options.protocols.len != 0) {
            for (options.protocols, 0..) |protocol, index| {
                if (!websocket.validSubprotocolToken(protocol)) return error.InvalidSubprotocol;
                if (index != 0) try protocol_value.appendSlice(allocator, ", ");
                try protocol_value.appendSlice(allocator, protocol);
            }
            try headers.append(allocator, .{ .name = "Sec-WebSocket-Protocol", .value = protocol_value.items });
        }
        if (options.enable_permessage_deflate) {
            try headers.append(allocator, .{
                .name = "Sec-WebSocket-Extensions",
                .value = "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
            });
        }
        const transport: RuntimeTransport = if (tls_conn) |conn| .{ .tls = conn } else .{ .tcp = .{ .io = io, .stream = stream } };
        try writeHttpUpgradeRequest(allocator, transport, .{
            .method = .GET,
            .target = options.target,
            .host = options.host,
            .headers = headers.items,
        });

        var head = try readHttpHeadFromTransport(allocator, transport, options.limits.max_head_bytes);
        defer head.deinit(allocator);
        var response = try http1.parseResponse(allocator, head.head, .{});
        defer response.deinit(allocator);
        if (response.status != 101) return error.InvalidResponse;
        const selected_protocol = try validateServerHandshake(allocator, response, &key, options.protocols);
        errdefer if (selected_protocol) |protocol| allocator.free(protocol);
        const selected_extension = try websocket.ExtensionNegotiation.validateResponse(try optionalSingletonHeader(response.headers, "sec-websocket-extensions"));
        if (selected_extension.permessage_deflate and !options.enable_permessage_deflate) return error.InvalidExtension;

        var connection = Connection{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .tls_conn = tls_conn,
            .role = .client,
            .limits = options.limits,
            .selected_protocol = selected_protocol,
            .permessage_deflate = selected_extension.permessage_deflate,
            .inbuf = try std.ArrayList(u8).initCapacity(allocator, head.extra.len),
        };
        errdefer connection.inbuf.deinit(connection.allocator);
        try connection.bufferInitial(head.extra);
        return connection;
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
    enable_permessage_deflate: bool = false,
    limits: Limits = .{},
};

pub const OwnedMessage = struct {
    opcode: websocket.Opcode,
    payload: []u8,

    pub fn deinit(self: *OwnedMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        self.* = undefined;
    }
};

pub const Connection = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    stream: net.Stream,
    tls_conn: ?*http1_runtime.TlsClientConnection = null,
    role: Role,
    limits: Limits = .{},
    inbuf: std.ArrayList(u8) = .empty,
    send_mutex: std.Io.Mutex = .init,
    close_sent: bool = false,
    close_received: bool = false,
    selected_protocol: ?[]u8 = null,
    permessage_deflate: bool = false,

    fn bufferInitial(self: *Connection, bytes: []const u8) Error!void {
        try self.inbuf.appendSlice(self.allocator, bytes);
    }

    fn transport(self: *Connection) RuntimeTransport {
        if (self.tls_conn) |conn| return .{ .tls = conn };
        return .{ .tcp = .{ .io = self.io, .stream = self.stream } };
    }

    pub fn close(self: *Connection) void {
        if (self.selected_protocol) |protocol| self.allocator.free(protocol);
        self.inbuf.deinit(self.allocator);
        if (self.tls_conn) |conn| {
            conn.deinit();
        } else {
            self.stream.close(self.io);
        }
        self.* = undefined;
    }

    pub fn sendText(self: *Connection, text: []const u8) Error!void {
        try self.sendMessage(.text, text);
    }

    pub fn sendBinary(self: *Connection, payload: []const u8) Error!void {
        try self.sendMessage(.binary, payload);
    }

    pub fn sendPing(self: *Connection, payload: []const u8) Error!void {
        try self.sendFrame(.ping, payload);
    }

    pub fn sendPong(self: *Connection, payload: []const u8) Error!void {
        try self.sendFrame(.pong, payload);
    }

    pub fn sendClose(self: *Connection, code: websocket.CloseCode, reason: []const u8) Error!void {
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(self.allocator);
        try payload.append(self.allocator, @truncate(@intFromEnum(code) >> 8));
        try payload.append(self.allocator, @truncate(@intFromEnum(code)));
        try payload.appendSlice(self.allocator, reason);
        try websocket.validateClosePayload(payload.items);
        try self.sendFrame(.close, payload.items);
    }

    pub fn sendFrame(self: *Connection, opcode: websocket.Opcode, payload: []const u8) Error!void {
        if (self.close_sent) return error.ConnectionClosed;
        try validateOutgoingFramePayload(opcode, payload);
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);
        try self.writeFrameLocked(opcode, payload, true);
        if (opcode == .close) self.close_sent = true;
    }

    pub fn sendMessage(self: *Connection, opcode: websocket.Opcode, payload: []const u8) Error!void {
        if (opcode != .text and opcode != .binary) return error.InvalidFrame;
        if (self.close_sent) return error.ConnectionClosed;
        try validateOutgoingMessagePayload(opcode, payload);
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);

        if (self.permessage_deflate and payload.len != 0) {
            const compressed = try websocket.compressMessage(self.allocator, payload);
            defer self.allocator.free(compressed);
            try self.writeFrameLockedExtended(opcode, compressed, true, .{ .rsv1 = true });
        } else {
            try self.writeFrameLocked(opcode, payload, true);
        }
    }

    pub fn sendFragmented(self: *Connection, opcode: websocket.Opcode, fragments: []const []const u8) Error!void {
        if (self.close_sent) return error.ConnectionClosed;
        if (opcode != .text and opcode != .binary) return error.InvalidFrame;
        if (fragments.len == 0) return error.InvalidFrame;

        if (self.permessage_deflate) {
            const plain = try joinFragments(self.allocator, fragments);
            defer self.allocator.free(plain);
            if (opcode == .text and !std.unicode.utf8ValidateSlice(plain)) return error.InvalidUtf8;

            const compressed = try websocket.compressMessage(self.allocator, plain);
            defer self.allocator.free(compressed);

            self.send_mutex.lockUncancelable(self.io);
            defer self.send_mutex.unlock(self.io);
            try self.writeCompressedFragmentsLocked(opcode, compressed, fragments.len);
            return;
        }

        if (opcode == .text) try validateOutgoingFragmentedText(self.allocator, fragments);

        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);

        for (fragments, 0..) |fragment, index| {
            const frame_opcode: websocket.Opcode = if (index == 0) opcode else .continuation;
            const fin = index + 1 == fragments.len;
            try self.writeFrameLocked(frame_opcode, fragment, fin);
        }
    }

    pub fn receiveFrame(self: *Connection) Error!websocket.Frame {
        if (self.close_sent and self.close_received) return error.ConnectionClosed;
        try self.ensureBuffered(2);
        const second = self.inbuf.items[1];
        var header_len: usize = 2;
        const len_code = second & 0x7f;
        if (len_code == 126) header_len += 2 else if (len_code == 127) header_len += 8;
        if ((second & 0x80) != 0) header_len += 4;
        try self.ensureBuffered(header_len);

        const header = try websocket.FrameHeader.parse(self.inbuf.items);
        const payload_len = std.math.cast(usize, header.payload_len) orelse return error.PayloadTooLarge;
        if (payload_len > self.limits.max_frame_bytes) return error.MessageTooLarge;
        const total_len = header.header_len + payload_len;
        try self.ensureBuffered(total_len);

        const parse_options: websocket.ParseFrameOptions = switch (self.role) {
            .client => .{ .expect_mask = .unmasked, .allow_rsv1 = self.permessage_deflate },
            .server => .{ .expect_mask = .masked, .allow_rsv1 = self.permessage_deflate },
        };
        var frame = try websocket.parseFrameOptions(self.allocator, self.inbuf.items[0..total_len], parse_options);
        errdefer frame.deinit(self.allocator);
        self.discardBuffered(frame.consumed);
        if (frame.header.opcode == .close) self.close_received = true;
        return frame;
    }

    pub fn receiveMessage(self: *Connection) Error!OwnedMessage {
        var assembler = websocket.MessageAssembler.initLimited(self.allocator, self.limits.max_message_bytes);
        defer assembler.deinit();

        while (true) {
            var frame = try self.receiveFrame();
            defer frame.deinit(self.allocator);
            switch (frame.header.opcode) {
                .ping => {
                    try self.sendPong(frame.payload);
                    continue;
                },
                .pong => continue,
                .close => {
                    self.close_received = true;
                    if (!self.close_sent) {
                        try self.sendFrame(.close, frame.payload);
                    }
                    return error.ConnectionClosed;
                },
                else => {
                    const maybe_message = try assembler.feed(frame);
                    if (maybe_message) |message| {
                        return finishIncomingMessage(self.allocator, message, self.limits.max_message_bytes);
                    }
                },
            }
        }
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
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        const mask_key = if (self.role == .client) blk: {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.io, &key);
            break :blk key;
        } else null;
        try websocket.writeFrameExtended(&encoded, self.allocator, opcode, payload, .{
            .fin = fin,
            .mask_key = mask_key,
            .rsv1 = options.rsv1,
        });
        try self.transport().writeAll(encoded.items);
    }

    fn writeCompressedFragmentsLocked(
        self: *Connection,
        opcode: websocket.Opcode,
        compressed_payload: []const u8,
        frame_count: usize,
    ) Error!void {
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

    fn ensureBuffered(self: *Connection, len: usize) Error!void {
        var scratch: [4096]u8 = undefined;
        while (self.inbuf.items.len < len) {
            const n = try self.transport().read(&scratch);
            if (n == 0) return error.ConnectionClosed;
            try self.inbuf.appendSlice(self.allocator, scratch[0..n]);
        }
    }

    fn discardBuffered(self: *Connection, len: usize) void {
        if (len == self.inbuf.items.len) {
            self.inbuf.clearRetainingCapacity();
            return;
        }
        const remaining = self.inbuf.items[len..];
        @memmove(self.inbuf.items[0..remaining.len], remaining);
        self.inbuf.shrinkRetainingCapacity(remaining.len);
    }
};

pub const H2Connection = struct {
    allocator: std.mem.Allocator,
    tunnel: http2_runtime.Tunnel,
    role: Role,
    limits: Limits = .{},
    inbuf: std.ArrayList(u8) = .empty,
    send_mutex: std.Io.Mutex = .init,
    close_sent: bool = false,
    close_received: bool = false,
    selected_protocol: ?[]u8 = null,
    permessage_deflate: bool = false,

    fn init(
        allocator: std.mem.Allocator,
        tunnel: http2_runtime.Tunnel,
        role: Role,
        limits: Limits,
        selected_protocol: ?[]u8,
        permessage_deflate: bool,
    ) H2Connection {
        return .{
            .allocator = allocator,
            .tunnel = tunnel,
            .role = role,
            .limits = limits,
            .selected_protocol = selected_protocol,
            .permessage_deflate = permessage_deflate,
        };
    }

    pub fn close(self: *H2Connection) void {
        if (self.selected_protocol) |protocol| self.allocator.free(protocol);
        self.inbuf.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn sendText(self: *H2Connection, text: []const u8) Error!void {
        try self.sendMessage(.text, text);
    }

    pub fn sendBinary(self: *H2Connection, payload: []const u8) Error!void {
        try self.sendMessage(.binary, payload);
    }

    pub fn sendPing(self: *H2Connection, payload: []const u8) Error!void {
        try self.sendFrame(.ping, payload);
    }

    pub fn sendPong(self: *H2Connection, payload: []const u8) Error!void {
        try self.sendFrame(.pong, payload);
    }

    pub fn sendClose(self: *H2Connection, code: websocket.CloseCode, reason: []const u8) Error!void {
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(self.allocator);
        try payload.append(self.allocator, @truncate(@intFromEnum(code) >> 8));
        try payload.append(self.allocator, @truncate(@intFromEnum(code)));
        try payload.appendSlice(self.allocator, reason);
        try websocket.validateClosePayload(payload.items);
        try self.sendFrame(.close, payload.items);
    }

    pub fn sendFrame(self: *H2Connection, opcode: websocket.Opcode, payload: []const u8) Error!void {
        if (self.close_sent) return error.ConnectionClosed;
        try validateOutgoingFramePayload(opcode, payload);
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.send_mutex.unlock(self.tunnel.connection.io);
        try self.writeFrameLocked(opcode, payload, true);
        if (opcode == .close) self.close_sent = true;
    }

    pub fn sendMessage(self: *H2Connection, opcode: websocket.Opcode, payload: []const u8) Error!void {
        if (opcode != .text and opcode != .binary) return error.InvalidFrame;
        if (self.close_sent) return error.ConnectionClosed;
        try validateOutgoingMessagePayload(opcode, payload);
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.send_mutex.unlock(self.tunnel.connection.io);

        if (self.permessage_deflate and payload.len != 0) {
            const compressed = try websocket.compressMessage(self.allocator, payload);
            defer self.allocator.free(compressed);
            try self.writeFrameLockedExtended(opcode, compressed, true, .{ .rsv1 = true });
        } else {
            try self.writeFrameLocked(opcode, payload, true);
        }
    }

    pub fn sendFragmented(self: *H2Connection, opcode: websocket.Opcode, fragments: []const []const u8) Error!void {
        if (self.close_sent) return error.ConnectionClosed;
        if (opcode != .text and opcode != .binary) return error.InvalidFrame;
        if (fragments.len == 0) return error.InvalidFrame;

        if (self.permessage_deflate) {
            const plain = try joinFragments(self.allocator, fragments);
            defer self.allocator.free(plain);
            if (opcode == .text and !std.unicode.utf8ValidateSlice(plain)) return error.InvalidUtf8;

            const compressed = try websocket.compressMessage(self.allocator, plain);
            defer self.allocator.free(compressed);

            self.send_mutex.lockUncancelable(self.tunnel.connection.io);
            defer self.send_mutex.unlock(self.tunnel.connection.io);
            try self.writeCompressedFragmentsLocked(opcode, compressed, fragments.len);
            return;
        }

        if (opcode == .text) try validateOutgoingFragmentedText(self.allocator, fragments);

        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.send_mutex.unlock(self.tunnel.connection.io);

        for (fragments, 0..) |fragment, index| {
            const frame_opcode: websocket.Opcode = if (index == 0) opcode else .continuation;
            const fin = index + 1 == fragments.len;
            try self.writeFrameLocked(frame_opcode, fragment, fin);
        }
    }

    pub fn receiveFrame(self: *H2Connection) Error!websocket.Frame {
        if (self.close_sent and self.close_received) return error.ConnectionClosed;
        try self.ensureBuffered(2);
        const second = self.inbuf.items[1];
        var header_len: usize = 2;
        const len_code = second & 0x7f;
        if (len_code == 126) header_len += 2 else if (len_code == 127) header_len += 8;
        if ((second & 0x80) != 0) header_len += 4;
        try self.ensureBuffered(header_len);

        const header = try websocket.FrameHeader.parse(self.inbuf.items);
        const payload_len = std.math.cast(usize, header.payload_len) orelse return error.PayloadTooLarge;
        if (payload_len > self.limits.max_frame_bytes) return error.MessageTooLarge;
        const total_len = header.header_len + payload_len;
        try self.ensureBuffered(total_len);

        const parse_options: websocket.ParseFrameOptions = switch (self.role) {
            .client => .{ .expect_mask = .unmasked, .allow_rsv1 = self.permessage_deflate },
            .server => .{ .expect_mask = .masked, .allow_rsv1 = self.permessage_deflate },
        };
        var frame = try websocket.parseFrameOptions(self.allocator, self.inbuf.items[0..total_len], parse_options);
        errdefer frame.deinit(self.allocator);
        self.discardBuffered(frame.consumed);
        if (frame.header.opcode == .close) self.close_received = true;
        return frame;
    }

    pub fn receiveMessage(self: *H2Connection) Error!OwnedMessage {
        var assembler = websocket.MessageAssembler.initLimited(self.allocator, self.limits.max_message_bytes);
        defer assembler.deinit();

        while (true) {
            var frame = try self.receiveFrame();
            defer frame.deinit(self.allocator);
            switch (frame.header.opcode) {
                .ping => {
                    try self.sendPong(frame.payload);
                    continue;
                },
                .pong => continue,
                .close => {
                    self.close_received = true;
                    if (!self.close_sent) try self.sendFrame(.close, frame.payload);
                    return error.ConnectionClosed;
                },
                else => {
                    const maybe_message = try assembler.feed(frame);
                    if (maybe_message) |message| {
                        return finishIncomingMessage(self.allocator, message, self.limits.max_message_bytes);
                    }
                },
            }
        }
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
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        const mask_key = if (self.role == .client) blk: {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.tunnel.connection.io, &key);
            break :blk key;
        } else null;
        try websocket.writeFrameExtended(&encoded, self.allocator, opcode, payload, .{
            .fin = fin,
            .mask_key = mask_key,
            .rsv1 = options.rsv1,
        });
        // RFC 8441 maps the WebSocket byte stream onto an HTTP/2 stream.  Once
        // a Close frame is sent, this endpoint has no more WebSocket bytes to
        // write, so carry END_STREAM with the DATA frame that contains Close.
        try self.tunnel.write(encoded.items, opcode == .close);
    }

    fn writeCompressedFragmentsLocked(
        self: *H2Connection,
        opcode: websocket.Opcode,
        compressed_payload: []const u8,
        frame_count: usize,
    ) Error!void {
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

    fn ensureBuffered(self: *H2Connection, len: usize) Error!void {
        while (self.inbuf.items.len < len) {
            var data = try self.tunnel.read();
            defer data.deinit(self.allocator);
            if (data.data.len != 0) try self.inbuf.appendSlice(self.allocator, data.data);
            if (data.end_stream) {
                if (self.inbuf.items.len < len) return error.ConnectionClosed;
                break;
            }
        }
    }

    fn discardBuffered(self: *H2Connection, len: usize) void {
        if (len == self.inbuf.items.len) {
            self.inbuf.clearRetainingCapacity();
            return;
        }
        const remaining = self.inbuf.items[len..];
        @memmove(self.inbuf.items[0..remaining.len], remaining);
        self.inbuf.shrinkRetainingCapacity(remaining.len);
    }
};

pub const H2Client = struct {
    pub fn open(
        allocator: std.mem.Allocator,
        connection: *http2_runtime.Connection,
        options: H2ConnectOptions,
    ) Error!H2Connection {
        var request_headers: std.ArrayList(http2.Hpack.HeaderField) = .empty;
        defer request_headers.deinit(allocator);
        try request_headers.append(allocator, .{ .name = "sec-websocket-version", .value = "13" });
        var protocol_value: std.ArrayList(u8) = .empty;
        defer protocol_value.deinit(allocator);
        if (options.protocols.len != 0) {
            for (options.protocols, 0..) |protocol, index| {
                if (!websocket.validSubprotocolToken(protocol)) return error.InvalidSubprotocol;
                if (index != 0) try protocol_value.appendSlice(allocator, ", ");
                try protocol_value.appendSlice(allocator, protocol);
            }
            try request_headers.append(allocator, .{ .name = "sec-websocket-protocol", .value = protocol_value.items });
        }
        if (options.enable_permessage_deflate) {
            try request_headers.append(allocator, .{
                .name = "sec-websocket-extensions",
                .value = "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
            });
        }
        try request_headers.appendSlice(allocator, options.extra_headers);

        var response = try connection.openExtendedConnect(.{
            .method = "CONNECT",
            .path = options.path,
            .scheme = options.scheme,
            .authority = options.authority,
            .protocol = "websocket",
            .headers = request_headers.items,
        });
        errdefer response.deinit(allocator);

        const selected_protocol = try validateH2ServerHandshake(allocator, response.headers, options.protocols);
        errdefer if (selected_protocol) |protocol| allocator.free(protocol);
        const selected_extension = try websocket.ExtensionNegotiation.validateResponse(try optionalH2SingletonHeader(response.headers, "sec-websocket-extensions"));
        if (selected_extension.permessage_deflate and !options.enable_permessage_deflate) return error.InvalidExtension;
        const tunnel = response.tunnel;
        response.tunnel = undefined;
        response.deinit(allocator);

        return H2Connection.init(
            allocator,
            tunnel,
            .client,
            options.limits,
            selected_protocol,
            selected_extension.permessage_deflate,
        );
    }
};

pub const H2Server = struct {
    pub fn accept(
        allocator: std.mem.Allocator,
        connection: *http2_runtime.Connection,
        options: H2AcceptOptions,
    ) Error!H2Connection {
        var request = try connection.readExtendedConnectRequest("websocket");
        errdefer request.deinit(allocator);
        const version = try requiredH2SingletonHeader(request.headers, "sec-websocket-version");
        if (!std.mem.eql(u8, version, "13")) return error.InvalidHandshake;

        const selected_protocol = try selectH2Subprotocol(allocator, request.headers, options.protocols);
        errdefer if (selected_protocol) |protocol| allocator.free(protocol);
        const selected_extension = try acceptH2Extensions(allocator, request.headers, options.enable_permessage_deflate);
        defer if (selected_extension) |extension| allocator.free(extension);

        var response_headers: std.ArrayList(http2.Hpack.HeaderField) = .empty;
        defer response_headers.deinit(allocator);
        if (selected_protocol) |protocol| try response_headers.append(allocator, .{ .name = "sec-websocket-protocol", .value = protocol });
        if (selected_extension) |extension| try response_headers.append(allocator, .{ .name = "sec-websocket-extensions", .value = extension });
        try response_headers.appendSlice(allocator, options.extra_headers);

        const tunnel = try connection.acceptExtendedConnect(request, response_headers.items);
        request.deinit(allocator);
        return H2Connection.init(
            allocator,
            tunnel,
            .server,
            options.limits,
            selected_protocol,
            selected_extension != null,
        );
    }
};

pub const H2ConnectOptions = struct {
    authority: ?[]const u8 = null,
    path: []const u8 = "/",
    /// Optional RFC 8441 `:scheme`.  When omitted, the HTTP/2 runtime uses the
    /// underlying connection's default (`http` for h2c, `https` for future TLS
    /// h2 connections), matching how mature stacks derive `:scheme` from the
    /// selected transport rather than hard-coding secure origins.
    scheme: ?[]const u8 = null,
    protocols: []const []const u8 = &.{},
    extra_headers: []const http2.Hpack.HeaderField = &.{},
    enable_permessage_deflate: bool = false,
    limits: Limits = .{},
};

pub const H2AcceptOptions = struct {
    protocols: []const []const u8 = &.{},
    extra_headers: []const http2.Hpack.HeaderField = &.{},
    enable_permessage_deflate: bool = false,
    limits: Limits = .{},
};

fn validateOutgoingMessagePayload(opcode: websocket.Opcode, payload: []const u8) Error!void {
    if (opcode == .text and !std.unicode.utf8ValidateSlice(payload)) return error.InvalidUtf8;
}

fn validateOutgoingFramePayload(opcode: websocket.Opcode, payload: []const u8) Error!void {
    switch (opcode) {
        // Application data frames must go through sendMessage/sendFragmented so
        // text UTF-8 checks and negotiated permessage-deflate framing cannot be
        // bypassed by the low-level control-frame helper.
        .text, .binary => return error.InvalidFrame,
        .close => try websocket.validateClosePayload(payload),
        .ping, .pong => if (payload.len > 125) return error.InvalidControlFrame,
        .continuation => return error.InvalidFrame,
        _ => return error.InvalidFrame,
    }
}

fn finishIncomingMessage(
    allocator: std.mem.Allocator,
    message: websocket.MessageAssembler.Message,
    max_message_bytes: usize,
) Error!OwnedMessage {
    var payload = message.payload;
    if (message.compressed) {
        errdefer allocator.free(message.payload);
        payload = try websocket.decompressMessage(allocator, message.payload, max_message_bytes);
        allocator.free(message.payload);
    }
    errdefer allocator.free(payload);
    if (message.opcode == .text and !std.unicode.utf8ValidateSlice(payload)) return error.InvalidUtf8;
    return .{ .opcode = message.opcode, .payload = payload };
}

fn validateOutgoingFragmentedText(allocator: std.mem.Allocator, fragments: []const []const u8) Error!void {
    const bytes = try joinFragments(allocator, fragments);
    defer allocator.free(bytes);
    if (!std.unicode.utf8ValidateSlice(bytes)) return error.InvalidUtf8;
}

fn joinFragments(allocator: std.mem.Allocator, fragments: []const []const u8) Error![]u8 {
    var total: usize = 0;
    for (fragments) |fragment| total = std.math.add(usize, total, fragment.len) catch return error.PayloadTooLarge;
    const bytes = try allocator.alloc(u8, total);
    errdefer allocator.free(bytes);
    var offset: usize = 0;
    for (fragments) |fragment| {
        @memcpy(bytes[offset..][0..fragment.len], fragment);
        offset += fragment.len;
    }
    return bytes;
}

const FragmentRange = struct { start: usize, end: usize };

fn compressedFragmentRange(total_len: usize, frame_count: usize, index: usize) FragmentRange {
    std.debug.assert(frame_count != 0);
    std.debug.assert(index < frame_count);
    // permessage-deflate compresses the message as one DEFLATE stream.  RFC 6455
    // fragmentation is then applied to the compressed byte stream, with RSV1 set
    // only on the first frame; boundaries do not have to match caller-provided
    // plaintext fragment boundaries.
    const base = total_len / frame_count;
    const extra = total_len % frame_count;
    const start = index * base + @min(index, extra);
    const len = base + @as(usize, if (index < extra) 1 else 0);
    return .{ .start = start, .end = start + len };
}

const HttpHead = struct {
    head: []u8,
    extra: []u8,

    fn deinit(self: *HttpHead, allocator: std.mem.Allocator) void {
        allocator.free(self.head);
        allocator.free(self.extra);
        self.* = undefined;
    }
};

fn writeHttpUpgradeRequest(allocator: std.mem.Allocator, transport: RuntimeTransport, options: http1_runtime.RequestOptions) Error!void {
    try http1.validateRequestTargetForMethod(options.method, options.target);
    var headers: std.ArrayList(http1.Header) = .empty;
    defer headers.deinit(allocator);
    var has_host = false;
    for (options.headers) |header| {
        if (header.eqlName("host")) has_host = true;
        try headers.append(allocator, header);
    }
    if (!has_host) {
        if (options.host) |host| try headers.append(allocator, .{ .name = "Host", .value = host });
    }
    try http1.validateHostHeaderBlock(options.version, headers.items);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try http1.writeRequestChecked(&encoded, allocator, options.method, options.target, options.version, headers.items, options.body);
    try transport.writeAll(encoded.items);
}

fn readHttpHead(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, max_head_bytes: usize) Error!HttpHead {
    return readHttpHeadFromTransport(allocator, .{ .tcp = .{ .io = io, .stream = stream } }, max_head_bytes);
}

fn readHttpHeadFromTransport(allocator: std.mem.Allocator, transport: RuntimeTransport, max_head_bytes: usize) Error!HttpHead {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
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
        const n = try transport.read(read_buf);
        if (n == 0) return error.ConnectionClosed;
        try bytes.appendSlice(allocator, scratch[0..n]);
    }
}

fn findHttpHeadEndWithinLimit(bytes: []const u8, max_head_bytes: usize) Error!?usize {
    if (std.mem.indexOf(u8, bytes, "\r\n\r\n")) |head_end| {
        if (head_end + 4 > max_head_bytes) return error.HeadersTooLarge;
        return head_end;
    }
    if (bytes.len >= max_head_bytes) return error.HeadersTooLarge;
    return null;
}

fn validateServerHandshake(
    allocator: std.mem.Allocator,
    response: http1.Response,
    client_key: []const u8,
    offered_protocols: []const []const u8,
) Error!?[]u8 {
    if (response.version != .http_1_1) return error.InvalidHandshake;
    const upgrade = try requiredSingletonHeader(response.headers, "upgrade");
    if (!std.ascii.eqlIgnoreCase(upgrade, "websocket")) return error.InvalidHandshake;
    if (!hasHeader(response.headers, "connection")) return error.MissingHeader;
    if (!headersContainToken(response.headers, "connection", "upgrade")) return error.InvalidHandshake;
    if ((try http1.contentLength(response.headers)) != null) return error.InvalidHandshake;
    for (response.headers) |header| {
        if (header.eqlName("transfer-encoding")) return error.InvalidHandshake;
    }
    const accept = try requiredSingletonHeader(response.headers, "sec-websocket-accept");
    const expected = websocket.acceptKey(client_key);
    if (!std.mem.eql(u8, accept, &expected)) return error.InvalidHandshake;
    _ = try websocket.ExtensionNegotiation.validateResponse(try optionalSingletonHeader(response.headers, "sec-websocket-extensions"));
    if (try optionalSingletonHeader(response.headers, "sec-websocket-protocol")) |selected| {
        const protocol = wire.trimOws(selected);
        if (!websocket.validSubprotocolToken(protocol)) return error.InvalidSubprotocol;
        for (offered_protocols) |offered| {
            if (std.mem.eql(u8, protocol, offered)) return try allocator.dupe(u8, protocol);
        }
        return error.InvalidSubprotocol;
    }
    return null;
}

fn requiredSingletonHeader(headers: []const http1.Header, name: []const u8) Error![]const u8 {
    return (try optionalSingletonHeader(headers, name)) orelse error.MissingHeader;
}

fn optionalSingletonHeader(headers: []const http1.Header, name: []const u8) Error!?[]const u8 {
    var found: ?[]const u8 = null;
    for (headers) |header| {
        if (!header.eqlName(name)) continue;
        if (found != null) return error.InvalidHandshake;
        found = header.value;
    }
    return found;
}

fn hasHeader(headers: []const http1.Header, name: []const u8) bool {
    for (headers) |header| {
        if (header.eqlName(name)) return true;
    }
    return false;
}

fn headersContainToken(headers: []const http1.Header, name: []const u8, token: []const u8) bool {
    for (headers) |header| {
        if (header.eqlName(name) and wire.containsToken(header.value, token)) return true;
    }
    return false;
}

fn validateH2ServerHandshake(
    allocator: std.mem.Allocator,
    headers: []const http2.Hpack.HeaderField,
    offered_protocols: []const []const u8,
) Error!?[]u8 {
    if (try optionalH2SingletonHeader(headers, "sec-websocket-protocol")) |selected| {
        const protocol = wire.trimOws(selected);
        if (!websocket.validSubprotocolToken(protocol)) return error.InvalidSubprotocol;
        for (offered_protocols) |offered| {
            if (std.mem.eql(u8, protocol, offered)) return try allocator.dupe(u8, protocol);
        }
        return error.InvalidSubprotocol;
    }
    return null;
}

fn requiredH2SingletonHeader(headers: []const http2.Hpack.HeaderField, name: []const u8) Error![]const u8 {
    return (try optionalH2SingletonHeader(headers, name)) orelse error.MissingHeader;
}

fn optionalH2SingletonHeader(headers: []const http2.Hpack.HeaderField, name: []const u8) Error!?[]const u8 {
    var found: ?[]const u8 = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, name)) continue;
        if (found != null) return error.InvalidHandshake;
        found = header.value;
    }
    return found;
}

fn acceptH2Extensions(
    allocator: std.mem.Allocator,
    headers: []const http2.Hpack.HeaderField,
    enable_permessage_deflate: bool,
) Error!?[]u8 {
    if (!enable_permessage_deflate) return null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "sec-websocket-extensions")) continue;
        if (try websocket.ExtensionNegotiation.accept(allocator, header.value, true)) |accepted| return accepted;
    }
    return null;
}

fn findH2Header(headers: []const http2.Hpack.HeaderField, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

fn selectSubprotocol(allocator: std.mem.Allocator, requested_header: ?[]const u8, supported: []const []const u8) Error!?[]u8 {
    try validateSupportedSubprotocols(supported);
    const raw_requested = requested_header orelse return null;
    var selected: ?[]const u8 = null;
    try considerSubprotocolHeader(raw_requested, supported, &selected);
    if (selected) |protocol| return try allocator.dupe(u8, protocol);
    return null;
}

fn selectHttp1Subprotocol(allocator: std.mem.Allocator, headers: []const http1.Header, supported: []const []const u8) Error!?[]u8 {
    try validateSupportedSubprotocols(supported);
    var selected: ?[]const u8 = null;
    for (headers) |header| {
        if (!header.eqlName("sec-websocket-protocol")) continue;
        // Sec-WebSocket-Protocol has 1#token grammar.  HTTP/1 field lines may
        // arrive split rather than coalesced, so validate all occurrences and
        // choose the first client-preferred protocol we support instead of
        // silently ignoring later field lines.
        try considerSubprotocolHeader(header.value, supported, &selected);
    }
    if (selected) |protocol| return try allocator.dupe(u8, protocol);
    return null;
}

fn selectH2Subprotocol(allocator: std.mem.Allocator, headers: []const http2.Hpack.HeaderField, supported: []const []const u8) Error!?[]u8 {
    try validateSupportedSubprotocols(supported);
    var selected: ?[]const u8 = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "sec-websocket-protocol")) continue;
        try considerSubprotocolHeader(header.value, supported, &selected);
    }
    if (selected) |protocol| return try allocator.dupe(u8, protocol);
    return null;
}

fn validateSupportedSubprotocols(supported: []const []const u8) Error!void {
    for (supported) |protocol| {
        if (!websocket.validSubprotocolToken(protocol)) return error.InvalidSubprotocol;
    }
}

fn considerSubprotocolHeader(raw_requested: []const u8, supported: []const []const u8, selected: *?[]const u8) Error!void {
    var requested = std.mem.splitScalar(u8, raw_requested, ',');
    while (requested.next()) |raw| {
        const candidate = wire.trimOws(raw);
        if (!websocket.validSubprotocolToken(candidate)) return error.InvalidSubprotocol;
        if (selected.* != null) continue;
        for (supported) |protocol| {
            if (std.mem.eql(u8, candidate, protocol)) {
                selected.* = protocol;
                break;
            }
        }
    }
}

fn readSome(io: std.Io, stream: net.Stream, buffer: []u8) net.Stream.Reader.Error!usize {
    var bufs = [_][]u8{buffer};
    return io.vtable.netRead(io.userdata, stream.socket.handle, &bufs);
}

fn writeAllToStream(io: std.Io, stream: net.Stream, bytes: []const u8) net.Stream.Writer.Error!void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = try io.vtable.netWrite(io.userdata, stream.socket.handle, bytes[written..], &.{""}, 0);
        if (n == 0) return error.SocketUnconnected;
        written += n;
    }
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
    var response = try http1.parseResponse(allocator, split_connection, .{});
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(?[]u8, null), try validateServerHandshake(allocator, response, client_key, &.{}));

    const duplicate_accept =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "\r\n";
    var duplicate_response = try http1.parseResponse(allocator, duplicate_accept, .{});
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
    var duplicate_extensions_response = try http1.parseResponse(allocator, duplicate_extensions, .{});
    defer duplicate_extensions_response.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateServerHandshake(allocator, duplicate_extensions_response, client_key, &.{}));

    const content_length_101 =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "Content-Length: 0\r\n" ++
        "\r\n";
    var content_length_response = try http1.parseResponse(allocator, content_length_101, .{});
    defer content_length_response.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateServerHandshake(allocator, content_length_response, client_key, &.{}));

    const transfer_encoding_101 =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n";
    var transfer_encoding_response = try http1.parseResponse(allocator, transfer_encoding_101, .{});
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
}

test "WebSocket over HTTP/2 handshake rejects duplicate critical headers" {
    const allocator = std.testing.allocator;

    const duplicate_request_version = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-version", .value = "13" },
        .{ .name = "sec-websocket-version", .value = "13" },
    };
    try std.testing.expectError(error.InvalidHandshake, requiredH2SingletonHeader(&duplicate_request_version, "sec-websocket-version"));

    const duplicate_response_protocol = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-protocol", .value = "chat.v1" },
        .{ .name = "sec-websocket-protocol", .value = "chat.v1" },
    };
    try std.testing.expectError(error.InvalidHandshake, validateH2ServerHandshake(std.testing.allocator, &duplicate_response_protocol, &.{"chat.v1"}));

    const duplicate_extensions = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-extensions", .value = "permessage-deflate; server_no_context_takeover; client_no_context_takeover" },
        .{ .name = "sec-websocket-extensions", .value = "permessage-deflate; server_no_context_takeover; client_no_context_takeover" },
    };
    try std.testing.expectError(error.InvalidHandshake, optionalH2SingletonHeader(&duplicate_extensions, "sec-websocket-extensions"));

    const split_offer = [_]http2.Hpack.HeaderField{
        .{ .name = "sec-websocket-extensions", .value = "x-unknown" },
        .{ .name = "sec-websocket-extensions", .value = "permessage-deflate; client_no_context_takeover; server_max_window_bits=15" },
    };
    const accepted = try acceptH2Extensions(allocator, &split_offer, true);
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

            var frame = try connection.receiveFrame();
            defer frame.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.text, frame.header.opcode);
            try std.testing.expect(frame.header.masked);
            try std.testing.expectEqualStrings("hello", frame.payload);

            try connection.sendText("world");

            var close = try connection.receiveFrame();
            defer close.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.close, close.header.opcode);
            try std.testing.expect(connection.close_received);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .host = "127.0.0.1",
        .target = "/chat",
        .limits = .{ .max_head_bytes = 4096, .max_frame_bytes = 4096 },
    });
    defer client.close();

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

            var request = try connection.receiveMessage();
            defer request.deinit(server_ptr.http.allocator);
            try std.testing.expectEqual(websocket.Opcode.text, request.opcode);
            try std.testing.expectEqualStrings("compressible compressible compressible", request.payload);

            try connection.sendFragmented(.text, &.{ "deflated response ", "deflated response" });

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

    try client.sendFragmented(.text, &.{ "compressible ", "compressible ", "compressible" });
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, response.opcode);
    try std.testing.expectEqualStrings("deflated response deflated response", response.payload);

    try client.sendClose(.normal_closure, "bye");

    thread.join();
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

            var request = try ws.receiveMessage();
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqual(websocket.Opcode.text, request.opcode);
            try std.testing.expectEqualStrings("hello over h2 websocket", request.payload);

            try ws.sendFragmented(.text, &.{ "world over ", "h2 websocket" });

            // The h2 WebSocket adapter still runs the normal RFC 6455 close
            // handshake inside DATA frames and maps the final Close write to
            // END_STREAM on the underlying HTTP/2 tunnel.
            try std.testing.expectError(error.ConnectionClosed, ws.receiveMessage());
            try std.testing.expect(ws.close_received);
            try std.testing.expect(ws.close_sent);
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

    try ws_client.sendFragmented(.text, &.{ "hello over ", "h2 websocket" });
    var response = try ws_client.receiveMessage();
    defer response.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, response.opcode);
    try std.testing.expectEqualStrings("world over h2 websocket", response.payload);

    try ws_client.sendClose(.normal_closure, "bye");
    try std.testing.expectError(error.ConnectionClosed, ws_client.receiveMessage());
    try std.testing.expect(ws_client.close_received);

    thread.join();
    if (shared.err) |err| return err;
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
            var request = try http1.parseRequest(server_ptr.http.allocator, head.head, .{});
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
            var request = try http1.parseRequest(server_ptr.http.allocator, head.head, .{});
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
            try std.testing.expect(connection.close_received);
            try std.testing.expect(connection.close_sent);
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
            try connection.sendClose(.message_too_big, "too big");
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
            try std.testing.expect(connection.close_sent);
            try std.testing.expect(connection.close_received);
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

test "WebSocket incoming message finalization frees failed payloads" {
    const allocator = std.testing.allocator;

    const bad_deflate = try allocator.dupe(u8, &.{ 0xff, 0xff, 0xff });
    try std.testing.expectError(error.InvalidFrame, finishIncomingMessage(allocator, .{
        .opcode = .text,
        .payload = bad_deflate,
        .compressed = true,
    }, 1024));

    const bad_utf8 = try allocator.dupe(u8, "\xc0\x80");
    try std.testing.expectError(error.InvalidUtf8, finishIncomingMessage(allocator, .{
        .opcode = .text,
        .payload = bad_utf8,
        .compressed = false,
    }, 1024));
}

test "WebSocket runtimes reject duplicate close sends" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .close_sent = true,
    };
    try std.testing.expectError(error.ConnectionClosed, connection.sendFrame(.close, &.{}));
    try std.testing.expectError(error.ConnectionClosed, connection.sendClose(.normal_closure, "again"));

    var h2 = H2Connection{
        .allocator = allocator,
        .tunnel = undefined,
        .role = .client,
        .close_sent = true,
    };
    try std.testing.expectError(error.ConnectionClosed, h2.sendFrame(.close, &.{}));
    try std.testing.expectError(error.ConnectionClosed, h2.sendClose(.normal_closure, "again"));
}

test "WebSocket runtimes return closed after close handshake completes" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .close_sent = true,
        .close_received = true,
    };
    try std.testing.expectError(error.ConnectionClosed, connection.receiveFrame());
    try std.testing.expectError(error.ConnectionClosed, connection.receiveMessage());

    var h2 = H2Connection{
        .allocator = allocator,
        .tunnel = undefined,
        .role = .client,
        .close_sent = true,
        .close_received = true,
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
