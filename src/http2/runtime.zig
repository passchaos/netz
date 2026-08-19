const std = @import("std");
const http2 = @import("mod.zig");
const http1 = @import("../http1/mod.zig");
const http1_runtime = http1.runtime;
const frame_io = @import("runtime/frame_io.zig");
const push = @import("runtime/push.zig");
const priority_runtime = @import("runtime/priority.zig");
const response_scheduler = @import(
    "runtime/response_scheduler.zig",
);
const stream_io = @import("../internal/stream_io.zig");
const socket_options = @import("../internal/socket_options.zig");

const net = std.Io.net;

pub const Error = http2.Error || http1_runtime.Error || error{
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
    UnsupportedScheme,
    PriorityCapacityExceeded,
} || net.IpAddress.ListenError || net.IpAddress.ConnectError || net.HostName.ValidateError || net.HostName.ConnectError || net.Server.AcceptError || net.Stream.Reader.Error || net.Stream.Writer.Error || std.posix.SetSockOptError || std.Thread.SpawnError;

const ReadExactError = net.Stream.Reader.Error || error{ConnectionClosed};

const flag_end_stream: u8 = 0x1;
const flag_ack: u8 = 0x1;
const flag_end_headers: u8 = 0x4;
const default_flow_window: i64 = 65_535;
const max_flow_window: i64 = std.math.maxInt(i31);
const default_max_frame_size: usize = 16 * 1024;
const max_max_frame_size: usize = 16_777_215;
const default_max_header_list_size: usize = 16 * 1024;
// Zig 0.16 Threaded networking submits at most eight iovecs. DATA consumes a
// header/payload pair, so four frames make one actual syscall burst. HEADERS
// occupies the first pair and leaves room for three DATA frames.
const max_data_frames_per_write: usize = 4;
const max_data_frames_with_headers: usize = 3;

pub const Limits = struct {
    /// Local allocation/test ceiling for any inbound or outbound frame payload.
    /// `max_frame_size` below is the HTTP/2 SETTINGS_MAX_FRAME_SIZE value that
    /// can be advertised to peers and must stay within RFC 9113 bounds.
    max_frame_payload: usize = 16 * 1024 * 1024,
    max_body_bytes: usize = 16 * 1024 * 1024,
    max_header_fields: usize = 256,
    /// Bounds HEADERS/PUSH_PROMISE continuation chains independently from byte
    /// limits.  Rust h2 derives this from SETTINGS_MAX_HEADER_LIST_SIZE and the
    /// receive frame size to prevent peers from sending endless empty
    /// CONTINUATION frames that never grow the header block.
    max_continuation_frames: ?usize = null,
    header_table_size: usize = http2.Hpack.default_dynamic_table_size,
    initial_window_size: u32 = @intCast(default_flow_window),
    /// Desired receive-side connection window. HTTP/2 starts every connection
    /// at 65,535 bytes, so values above that are established with an initial
    /// connection WINDOW_UPDATE after SETTINGS. This is distinct from
    /// SETTINGS_INITIAL_WINDOW_SIZE, which applies per stream.
    initial_connection_window_size: u32 =
        @intCast(default_flow_window),
    max_concurrent_streams: ?u32 = null,
    max_frame_size: usize = default_max_frame_size,
    max_header_list_size: usize = default_max_header_list_size,
    /// Local cap for PRIORITY_UPDATE records that target request streams not
    /// opened yet. This remains effective even when MAX_CONCURRENT_STREAMS is
    /// not advertised, preventing unbounded state from speculative IDs.
    max_idle_priority_updates: usize = 256,
    /// Advertise RFC 8441 SETTINGS_ENABLE_CONNECT_PROTOCOL.  It is disabled by
    /// default because peers may start tunnelling arbitrary bytes on streams
    /// once extended CONNECT is accepted.
    enable_connect_protocol: bool = false,
    /// Explicitly opt in to HTTP/2 server push. The client otherwise sends
    /// SETTINGS_ENABLE_PUSH=0 and rejects PUSH_PROMISE.
    enable_push: bool = false,
    /// Advertise RFC 9218 SETTINGS_NO_RFC7540_PRIORITIES=1. This allows a
    /// client to use PRIORITY_UPDATE and tells the peer that legacy dependency
    /// signals are intentionally ignored.
    no_rfc7540_priorities: bool = false,
    /// Disable Nagle on HTTP/2 TCP connections. HTTP/2 already provides its
    /// own frame and stream aggregation; retaining Nagle can stall a complete
    /// flow-control burst behind Linux's delayed ACK timer.
    tcp_nodelay: bool = true,
};

pub const Server = struct {
    io: std.Io,
    listener: net.Server,
    allocator: std.mem.Allocator,
    limits: Limits = .{},

    pub fn listen(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
        try validateLocalLimits(limits);
        return .{
            .io = io,
            .allocator = allocator,
            .listener = try bind_address.listen(io, .{ .reuse_address = true }),
            .limits = limits,
        };
    }

    pub fn deinit(self: *Server) void {
        self.listener.deinit(self.io);
        self.* = undefined;
    }

    pub fn address(self: Server) net.IpAddress {
        return self.listener.socket.address;
    }

    pub fn accept(self: *Server) Error!Connection {
        const stream = try self.listener.accept(self.io);
        errdefer stream.close(self.io);
        if (self.limits.tcp_nodelay) {
            try socket_options.setTcpNoDelay(stream);
        }

        var preface_buf: [http2.connection_preface.len]u8 = undefined;
        try readExact(self.io, stream, &preface_buf);
        try http2.validateClientPreface(&preface_buf);

        var client_settings = try readFrame(self.allocator, self.io, stream, self.limits);
        defer client_settings.deinit(self.allocator);
        if (client_settings.frame.header.frame_type != .settings or (client_settings.frame.header.flags & flag_ack) != 0) {
            return error.UnexpectedFrame;
        }
        const peer_settings = try http2.parseSettings(self.allocator, client_settings.frame.payload);
        defer self.allocator.free(peer_settings);

        try writeInitialSettings(self.allocator, self.io, stream, self.limits, .server);
        try writeInitialConnectionWindow(
            self.allocator,
            self.io,
            stream,
            self.limits,
        );
        try writeFrame(self.allocator, self.io, stream, .settings, flag_ack, 0, &.{});

        var connection = Connection{
            .io = self.io,
            .allocator = self.allocator,
            .stream = stream,
            .role = .server,
            .limits = self.limits,
            .awaiting_settings_ack = true,
        };
        connection.applyLocalLimits();
        try connection.applySettings(peer_settings);
        return connection;
    }

    pub fn acceptUpgrade(self: *Server) Error!H2cUpgradeRequest {
        const stream = try self.listener.accept(self.io);
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(self.io);
        if (self.limits.tcp_nodelay) {
            try socket_options.setTcpNoDelay(stream);
        }

        var request = try http1_runtime.readRequestFromStream(self.allocator, self.io, stream, limitsToHttp1(self.limits), .{});
        errdefer request.deinit(self.allocator);
        try validateH2cUpgradeRequest(request.request);

        const settings_header = (try optionalHttp1SingletonHeader(request.request.headers, "http2-settings")) orelse return error.InvalidHeader;
        const advertised_settings = try decodeHttp2SettingsHeader(self.allocator, settings_header);
        defer self.allocator.free(advertised_settings);

        try http1_runtime.writeResponseToStream(self.allocator, self.io, stream, .{
            .status = 101,
            .reason = "Switching Protocols",
            .headers = &.{
                .{ .name = "Connection", .value = "Upgrade" },
                .{ .name = "Upgrade", .value = "h2c" },
            },
            .request_method = request.request.method,
        });

        var preface_buf: [http2.connection_preface.len]u8 = undefined;
        try readExact(self.io, stream, &preface_buf);
        try http2.validateClientPreface(&preface_buf);

        var client_settings = try readFrame(self.allocator, self.io, stream, self.limits);
        defer client_settings.deinit(self.allocator);
        if (client_settings.frame.header.frame_type != .settings or (client_settings.frame.header.flags & flag_ack) != 0) {
            return error.UnexpectedFrame;
        }
        if (!std.mem.eql(u8, advertised_settings, client_settings.frame.payload)) return error.InvalidFrame;
        const peer_settings = try http2.parseSettings(self.allocator, client_settings.frame.payload);
        defer self.allocator.free(peer_settings);

        try writeInitialSettings(self.allocator, self.io, stream, self.limits, .server);
        try writeInitialConnectionWindow(
            self.allocator,
            self.io,
            stream,
            self.limits,
        );
        try writeFrame(self.allocator, self.io, stream, .settings, flag_ack, 0, &.{});

        // The HTTP/1 Upgrade request already occupies stream 1, so the next
        // frame the server sees after its SETTINGS is normally the client's
        // SETTINGS ACK rather than HEADERS for stream 1.  Consume it here so
        // applications can immediately answer the upgraded request without
        // leaving unread control bytes that would make a short-lived test/server
        // close look like a TCP reset to the client.
        var client_ack = try readFrame(self.allocator, self.io, stream, self.limits);
        defer client_ack.deinit(self.allocator);
        if (client_ack.frame.header.frame_type != .settings or (client_ack.frame.header.flags & flag_ack) == 0) {
            return error.UnexpectedFrame;
        }

        var connection = Connection{
            .io = self.io,
            .allocator = self.allocator,
            .stream = stream,
            .role = .server,
            .limits = self.limits,
            .awaiting_settings_ack = false,
            .last_peer_client_stream_id = 1,
        };
        connection.applyLocalLimits();
        errdefer connection.close();
        try connection.applySettings(peer_settings);
        try connection.reservePeerStream(1);
        errdefer connection.releasePeerStream(1);
        try connection.rememberResponseSemantics(
            1,
            request.request.method.string(),
            null,
            .{},
        );

        stream_owned = false;
        return .{ .connection = connection, .request = request, .stream_id = 1 };
    }

    pub fn serveConnection(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (*HandlerContext, OwnedRequest) Error!ResponseOptions,
        max_requests: usize,
    ) Error!usize {
        var connection = try self.accept();
        defer connection.close();
        return connection.serve(HandlerContext, context, handler, max_requests);
    }

    pub fn serveConcurrent(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (*HandlerContext, OwnedRequest) Error!ResponseOptions,
        max_connections: usize,
    ) AsyncServeError!ConcurrentServeResult {
        var group: std.Io.Group = .init;
        const results = try self.allocator.alloc(?anyerror, max_connections);
        errdefer self.allocator.free(results);
        @memset(results, null);

        for (results) |*result| {
            var connection = try self.accept();
            errdefer connection.close();
            const task = ServeTask(HandlerContext){
                .connection = connection,
                .context = context,
                .handler = handler,
                .result = result,
            };
            group.async(self.io, ServeTask(HandlerContext).run, .{task});
        }

        try group.await(self.io);
        return .{ .allocator = self.allocator, .errors = results };
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
        handler: *const fn (*HandlerContext, OwnedRequest) Error!ResponseOptions,
        result: *?anyerror,

        fn run(task: @This()) std.Io.Cancelable!void {
            var connection = task.connection;
            defer connection.close();

            var request = connection.readRequest() catch |err| {
                task.result.* = err;
                return;
            };
            defer request.deinit(connection.allocator);

            var response = task.handler(task.context, request) catch |err| {
                task.result.* = err;
                return;
            };
            if (response.request_method == null) response.request_method = request.method;
            response.extended_connect = request.protocol != null;
            connection.writeResponse(request.stream_id, response) catch |err| {
                task.result.* = err;
                return;
            };
            task.result.* = null;
        }
    };
}

pub const Client = struct {
    pub fn connect(allocator: std.mem.Allocator, io: std.Io, address: net.IpAddress, limits: Limits) Error!Connection {
        try validateLocalLimits(limits);
        const stream = try address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);
        var connection = try connectStream(allocator, io, stream, limits);
        connection.default_scheme = "http";
        return connection;
    }

    pub fn connectHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        limits: Limits,
    ) Error!Connection {
        try validateLocalLimits(limits);
        const host_name = try net.HostName.init(host);
        const owned_host = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ host, port });
        errdefer allocator.free(owned_host);
        const stream = try host_name.connect(io, port, .{ .mode = .stream });
        errdefer stream.close(io);
        var connection = try connectStream(allocator, io, stream, limits);
        connection.default_authority = owned_host;
        connection.default_scheme = "http";
        return connection;
    }

    /// Perform an RFC 7540 h2c Upgrade request and return the response on
    /// stream 1. `request_options` must include an authority (or Host header)
    /// because the opening request is first sent as HTTP/1.1.
    pub fn connectUpgrade(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        limits: Limits,
        request_options: RequestOptions,
    ) Error!OwnedResponse {
        try validateLocalLimits(limits);
        const stream = try address.connect(io, .{ .mode = .stream });
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        var upgraded = try connectStreamUpgrade(allocator, io, stream, limits, request_options);
        stream_owned = false;
        defer upgraded.deinit(allocator);
        return upgraded.connection.readResponse(1, request_options.method, request_options.protocol != null);
    }

    pub fn requestUriUpgrade(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
    ) Error!OwnedResponse {
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        if (!std.ascii.eqlIgnoreCase(uri.scheme, "http")) return error.UnsupportedScheme;
        const target = try uriTargetAlloc(allocator, uri);
        defer allocator.free(target);
        var endpoint = try http1_runtime.uriEndpoint(allocator, uri, 80);
        defer endpoint.deinit();

        try validateLocalLimits(limits);
        const stream = try endpoint.connect(io);
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        var options = request_options;
        options.path = target;
        if (options.authority == null) options.authority = endpoint.authority;
        if (options.scheme == null) options.scheme = uri.scheme;
        var upgraded = try connectStreamUpgrade(allocator, io, stream, limits, options);
        stream_owned = false;
        defer upgraded.deinit(allocator);
        return upgraded.connection.readResponse(1, options.method, options.protocol != null);
    }

    /// Upgrade an existing cleartext HTTP/1.1 stream to HTTP/2 and return the
    /// established connection plus the consumed 101 response metadata.  The
    /// caller owns both and should call `H2cUpgradeResult.deinit` on error paths
    /// or close/deinit each field manually after taking ownership.
    pub fn connectStreamUpgrade(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
        limits: Limits,
        request_options: RequestOptions,
    ) Error!H2cUpgradeResult {
        try validateLocalLimits(limits);
        if (limits.tcp_nodelay) {
            try socket_options.setTcpNoDelay(stream);
        }
        var connection = Connection{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .role = .client,
            .limits = limits,
            .awaiting_settings_ack = true,
            .next_client_stream_id = 3,
            .default_scheme = "http",
        };
        connection.applyLocalLimits();
        errdefer connection.close();

        const h2c_settings = try settingsForLimits(limits, .client);
        var settings_payload_buf: [max_settings_payload_len]u8 = undefined;
        const settings_payload = try encodeSettingsPayloadInto(&settings_payload_buf, h2c_settings.buf[0..h2c_settings.count]);
        const settings_value = try allocator.alloc(u8, std.base64.url_safe_no_pad.Encoder.calcSize(settings_payload.len));
        defer allocator.free(settings_value);
        _ = std.base64.url_safe_no_pad.Encoder.encode(settings_value, settings_payload);

        var headers: std.ArrayList(http1.Header) = .empty;
        defer headers.deinit(allocator);
        if (request_options.authority) |authority| try headers.append(allocator, .{ .name = "Host", .value = authority });
        var priority_buf: [16]u8 = undefined;
        if (request_options.priority) |value| {
            try headers.append(allocator, .{
                .name = "Priority",
                .value = value.serialize(&priority_buf),
            });
        }
        try headers.appendSlice(allocator, &.{
            .{ .name = "Connection", .value = "Upgrade, HTTP2-Settings" },
            .{ .name = "Upgrade", .value = "h2c" },
            .{ .name = "HTTP2-Settings", .value = settings_value },
        });
        for (request_options.headers) |header| try headers.append(allocator, .{ .name = header.name, .value = header.value });
        try validateHeaderBlock(request_options.trailers, .request_trailers);
        if (request_options.body.len != 0 or request_options.trailers.len != 0) return error.InvalidContentLength;
        const method = http1.Method.parse(request_options.method) catch return error.InvalidHeader;
        try http1_runtime.writeRequestToStream(allocator, io, stream, .{
            .method = method,
            .target = request_options.path,
            .headers = headers.items,
        });

        var upgrade = try http1_runtime.readResponseFromStreamForRequest(allocator, io, stream, limitsToHttp1(limits), .{}, method);
        errdefer upgrade.deinit(allocator);
        if (upgrade.response.status != 101) return error.InvalidResponse;
        const connection_header = upgrade.response.header("connection") orelse return error.InvalidResponse;
        const upgrade_header = upgrade.response.header("upgrade") orelse return error.InvalidResponse;
        if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, upgrade_header, " \t"), "h2c")) return error.InvalidResponse;
        if (!containsHttpToken(connection_header, "upgrade")) return error.InvalidResponse;

        try writeAll(io, stream, http2.connection_preface);
        try writeFrame(allocator, io, stream, .settings, 0, 0, settings_payload);
        var server_settings = try readFrame(allocator, io, stream, limits);
        defer server_settings.deinit(allocator);
        if (server_settings.frame.header.frame_type != .settings or (server_settings.frame.header.flags & flag_ack) != 0) return error.UnexpectedFrame;
        const settings = try http2.parseSettings(allocator, server_settings.frame.payload);
        defer allocator.free(settings);
        try connection.applySettings(settings);
        try writeFrame(allocator, io, stream, .settings, flag_ack, 0, &.{});
        // The Upgrade server waits specifically for this SETTINGS ACK before
        // returning the connection to the application. Send the optional
        // connection WINDOW_UPDATE afterward so it remains the next ordinary
        // control frame consumed by the established runtime.
        try writeInitialConnectionWindow(allocator, io, stream, limits);
        return .{ .connection = connection, .upgrade_response = upgrade };
    }

    fn connectStream(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, limits: Limits) Error!Connection {
        if (limits.tcp_nodelay) {
            try socket_options.setTcpNoDelay(stream);
        }
        try writeAll(io, stream, http2.connection_preface);
        try writeInitialSettings(allocator, io, stream, limits, .client);
        try writeInitialConnectionWindow(allocator, io, stream, limits);

        var saw_server_settings = false;
        var saw_settings_ack = false;
        var connection = Connection{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .role = .client,
            .limits = limits,
            .awaiting_settings_ack = true,
        };
        connection.applyLocalLimits();
        errdefer connection.close();
        while (!saw_server_settings or !saw_settings_ack) {
            var frame = try readFrame(allocator, io, stream, limits);
            defer frame.deinit(allocator);
            if (frame.frame.header.frame_type != .settings) {
                if (try connection.handleConnectionOrGoAwayFrame(frame.frame)) continue;
                return error.UnexpectedFrame;
            }
            if ((frame.frame.header.flags & flag_ack) != 0) {
                saw_settings_ack = true;
                connection.awaiting_settings_ack = false;
            } else {
                saw_server_settings = true;
                const settings = try http2.parseSettings(allocator, frame.frame.payload);
                defer allocator.free(settings);
                try connection.applySettings(settings);
                try writeFrame(allocator, io, stream, .settings, flag_ack, 0, &.{});
            }
        }
        return connection;
    }

    pub fn requestUri(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        request_options: RequestOptions,
        limits: Limits,
    ) Error!OwnedResponse {
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        if (!std.ascii.eqlIgnoreCase(uri.scheme, "http")) return error.UnsupportedScheme;
        const target = try uriTargetAlloc(allocator, uri);
        defer allocator.free(target);
        var endpoint = try http1_runtime.uriEndpoint(allocator, uri, 80);
        defer endpoint.deinit();

        try validateLocalLimits(limits);
        const stream = try endpoint.connect(io);
        var stream_owned = true;
        errdefer if (stream_owned) stream.close(io);
        var connection = try connectStream(allocator, io, stream, limits);
        stream_owned = false;
        defer connection.close();
        connection.default_authority = try allocator.dupe(u8, endpoint.authority);
        connection.default_scheme = uri.scheme;
        var options = request_options;
        options.path = target;
        if (options.scheme == null) options.scheme = uri.scheme;
        return connection.request(options);
    }
};

pub const Role = enum {
    client,
    server,
};

pub const FlowWindow = struct {
    value: i64 = default_flow_window,

    pub fn available(self: FlowWindow) usize {
        if (self.value <= 0) return 0;
        return std.math.cast(usize, self.value) orelse std.math.maxInt(usize);
    }

    pub fn reserve(self: *FlowWindow, amount: usize) Error!void {
        const delta = std.math.cast(i64, amount) orelse return error.MessageTooLarge;
        if (delta > self.value) return error.FlowControlBlocked;
        self.value -= delta;
    }

    pub fn receive(self: *FlowWindow, amount: usize) Error!void {
        const delta = std.math.cast(i64, amount) orelse return error.MessageTooLarge;
        if (delta > self.value) return error.FlowControlViolation;
        self.value -= delta;
    }

    pub fn update(self: *FlowWindow, increment: u31) Error!void {
        const next = std.math.add(i64, self.value, increment) catch return error.FlowControlViolation;
        // RFC 9113 requires a FLOW_CONTROL_ERROR when a WINDOW_UPDATE would
        // make a connection or stream flow-control window exceed 2^31-1.  Do
        // not saturate here: a saturated window lets peers continue after a
        // protocol violation and hides bugs in local capacity accounting.
        if (next > max_flow_window) return error.FlowControlViolation;
        self.value = next;
    }

    pub fn adjust(self: *FlowWindow, delta: i64) Error!void {
        const next = std.math.add(i64, self.value, delta) catch return error.FlowControlViolation;
        if (next > max_flow_window) return error.FlowControlViolation;
        self.value = next;
    }
};

const StreamWindowEntry = struct {
    stream_id: u31,
    window: FlowWindow = .{},
};

pub const PromisedRequest = push.PromisedRequest;

const AltSvcKey = struct {
    stream_id: u31,
    origin: []const u8,
};

const AltSvcKeyContext = struct {
    pub fn hash(_: @This(), key: AltSvcKey) u64 {
        var hasher = std.hash.Wyhash.init(0);
        std.hash.autoHash(&hasher, key.stream_id);
        std.hash.autoHash(&hasher, key.origin.len);
        hasher.update(key.origin);
        return hasher.final();
    }

    pub fn eql(_: @This(), lhs: AltSvcKey, rhs: AltSvcKey) bool {
        return lhs.stream_id == rhs.stream_id and
            std.mem.eql(u8, lhs.origin, rhs.origin);
    }
};

const AltSvcIndex = std.HashMapUnmanaged(
    AltSvcKey,
    usize,
    AltSvcKeyContext,
    std.hash_map.default_max_load_percentage,
);

pub const AlternativeService = struct {
    stream_id: u31,
    origin: []u8,
    field_value: []u8,

    fn deinit(self: *AlternativeService, allocator: std.mem.Allocator) void {
        allocator.free(self.origin);
        allocator.free(self.field_value);
        self.* = undefined;
    }
};

pub const Connection = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    stream: net.Stream,
    role: Role,
    limits: Limits = .{},
    next_client_stream_id: u31 = 1,
    send_connection_window: FlowWindow = .{},
    recv_connection_window: FlowWindow = .{},
    send_stream_windows: std.ArrayList(StreamWindowEntry) = .empty,
    send_stream_window_index: std.AutoHashMapUnmanaged(u31, usize) = .empty,
    recv_stream_windows: std.ArrayList(StreamWindowEntry) = .empty,
    recv_stream_window_index: std.AutoHashMapUnmanaged(u31, usize) = .empty,
    active_local_streams: std.ArrayList(u31) = .empty,
    active_local_index: std.AutoHashMapUnmanaged(u31, usize) = .empty,
    active_peer_streams: std.ArrayList(u31) = .empty,
    active_peer_index: std.AutoHashMapUnmanaged(u31, usize) = .empty,
    push_state: push.State = .{},
    priority_state: priority_runtime.State = .{},
    response_semantics: std.ArrayList(StreamResponseSemantics) = .empty,
    response_semantics_index: std.AutoHashMapUnmanaged(u31, usize) = .empty,
    hpack_decoder: http2.Hpack.Decoder = .{},
    hpack_encoder: http2.Hpack.Encoder = .{},
    write_batch: std.ArrayList(u8) = .empty,
    batch_data_headers: std.ArrayList(
        [http2.FrameHeader.encoded_len]u8,
    ) = .empty,
    batch_data_parts: std.ArrayList([]const u8) = .empty,
    frame_reader: frame_io.Reader = .{},
    /// One application frame encountered while a RequestWriter is blocked on
    /// send credit. Returning to the caller immediately keeps this naturally
    /// bounded while preserving HPACK/wire order for the response reader.
    pending_client_frame: ?OwnedFrame = null,
    peer_initial_stream_window: i64 = default_flow_window,
    peer_max_frame_size: usize = default_max_frame_size,
    peer_max_header_list_size: usize = std.math.maxInt(usize),
    peer_max_concurrent_streams: ?u32 = null,
    peer_enable_connect_protocol: bool = false,
    peer_enable_push: bool = true,
    peer_no_rfc7540_priorities: bool = false,
    peer_priority_setting_seen: bool = false,
    peer_initial_settings_applied: bool = false,
    awaiting_settings_ack: bool = false,
    last_peer_client_stream_id: u31 = 0,
    peer_goaway_last_stream_id: ?u31 = null,
    local_goaway_last_stream_id: ?u31 = null,
    pending_requests: std.ArrayList(OwnedRequest) = .empty,
    pending_request_head: usize = 0,
    peer_origins: std.ArrayList([]u8) = .empty,
    peer_origin_index: std.StringHashMapUnmanaged(usize) = .empty,
    alternative_services: std.ArrayList(AlternativeService) = .empty,
    alternative_service_index: AltSvcIndex = .empty,
    default_authority: ?[]u8 = null,
    /// Borrowed default used when RequestOptions.scheme is omitted.  Cleartext
    /// runtime constructors set this to "http"; a future ALPN/TLS constructor
    /// can set it to "https" without changing request call sites.
    default_scheme: ?[]const u8 = null,

    pub fn close(self: *Connection) void {
        if (self.default_authority) |authority| self.allocator.free(authority);
        self.send_stream_windows.deinit(self.allocator);
        self.send_stream_window_index.deinit(self.allocator);
        self.recv_stream_windows.deinit(self.allocator);
        self.recv_stream_window_index.deinit(self.allocator);
        self.active_local_streams.deinit(self.allocator);
        self.active_local_index.deinit(self.allocator);
        self.active_peer_streams.deinit(self.allocator);
        self.active_peer_index.deinit(self.allocator);
        self.push_state.deinit(self.allocator);
        self.priority_state.deinit(self.allocator);
        self.response_semantics.deinit(self.allocator);
        self.response_semantics_index.deinit(self.allocator);
        for (self.pending_requests.items[self.pending_request_head..]) |*pending| pending.deinit(self.allocator);
        self.pending_requests.deinit(self.allocator);
        for (self.peer_origins.items) |origin| {
            self.allocator.free(origin);
        }
        self.peer_origins.deinit(self.allocator);
        self.peer_origin_index.deinit(self.allocator);
        for (self.alternative_services.items) |*service| {
            service.deinit(self.allocator);
        }
        self.alternative_services.deinit(self.allocator);
        self.alternative_service_index.deinit(self.allocator);
        self.hpack_decoder.deinit(self.allocator);
        self.hpack_encoder.deinit(self.allocator);
        self.write_batch.deinit(self.allocator);
        self.batch_data_headers.deinit(self.allocator);
        self.batch_data_parts.deinit(self.allocator);
        if (self.pending_client_frame) |*frame| {
            frame.deinit(self.allocator);
        }
        self.frame_reader.deinit(self.allocator);
        self.stream.close(self.io);
        self.* = undefined;
    }

    pub fn request(self: *Connection, options: RequestOptions) Error!OwnedResponse {
        const pending = try self.sendCompleteRequest(options);
        return self.readResponse(
            pending.stream_id,
            pending.request_method,
            pending.extended_connect,
        );
    }

    /// Send a request and deliver response DATA without body aggregation.
    ///
    /// Initial headers and trailers in the returned value are owned until
    /// `StreamingResponse.deinit`. Each DATA slice borrows the connection frame
    /// reader and is valid only for the duration of `consume`. The callback
    /// must not retain it. A callback error cancels a still-open stream with
    /// RST_STREAM(CANCEL) before returning the original callback error.
    pub fn requestStreaming(
        self: *Connection,
        options: RequestOptions,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.requestStreamingWithHead(
            options,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    /// Send a request and report final response HEADERS before any DATA.
    ///
    /// Protocol adapters such as gRPC need the selected content/message
    /// encoding before decoding the first body bytes. The head borrows the
    /// eventual `StreamingResponse` allocation and must not be retained.
    pub fn requestStreamingWithHead(
        self: *Connection,
        options: RequestOptions,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        const pending = try self.sendCompleteRequest(options);
        return self.readResponseStreamingWithHead(
            pending,
            context,
            begin,
            consume,
        );
    }

    const PendingResponse = struct {
        stream_id: u31,
        request_method: []const u8,
        extended_connect: bool,
    };

    fn sendCompleteRequest(
        self: *Connection,
        options: RequestOptions,
    ) Error!PendingResponse {
        if (self.role != .client) return error.UnexpectedFrame;
        var request_options = options;
        if (request_options.authority == null) request_options.authority = self.default_authority;
        const scheme = request_options.scheme orelse self.default_scheme orelse "https";

        var fields_stack: [16]http2.Hpack.HeaderField = undefined;
        const fields_capacity = std.math.add(
            usize,
            request_options.headers.len,
            7,
        ) catch return error.MessageTooLarge;
        const fields_buffer = if (fields_capacity <= fields_stack.len)
            fields_stack[0..fields_capacity]
        else
            try self.allocator.alloc(
                http2.Hpack.HeaderField,
                fields_capacity,
            );
        defer if (fields_buffer.ptr != fields_stack[0..].ptr) {
            self.allocator.free(fields_buffer);
        };
        var fields: std.ArrayList(http2.Hpack.HeaderField) =
            .initBuffer(fields_buffer);
        const method_is_connect = methodIsConnect(request_options.method);
        const extended_connect = request_options.protocol != null;
        if (method_is_connect and !extended_connect and (request_options.body.len != 0 or request_options.trailers.len != 0)) {
            return error.InvalidContentLength;
        }
        fields.appendAssumeCapacity(.{
            .name = ":method",
            .value = request_options.method,
        });
        if (!method_is_connect or extended_connect) {
            fields.appendAssumeCapacity(.{
                .name = ":path",
                .value = request_options.path,
            });
            fields.appendAssumeCapacity(.{
                .name = ":scheme",
                .value = scheme,
            });
        }
        if (request_options.protocol) |protocol| {
            if (!self.peer_enable_connect_protocol) return error.ExtendedConnectDisabled;
            fields.appendAssumeCapacity(.{
                .name = ":protocol",
                .value = protocol,
            });
        }
        if (request_options.authority) |authority| {
            fields.appendAssumeCapacity(.{
                .name = ":authority",
                .value = authority,
            });
        }
        var priority_buf: [16]u8 = undefined;
        if (request_options.priority) |value| {
            fields.appendAssumeCapacity(.{
                .name = "priority",
                .value = value.serialize(&priority_buf),
            });
        }
        fields.appendSliceAssumeCapacity(request_options.headers);
        stripConnectionHeaders(&fields, .request);
        var content_length_buf: [32]u8 = undefined;
        if (requestShouldDefaultContentLength(request_options.method, fields.items, request_options.body.len)) {
            const content_length = std.fmt.bufPrint(&content_length_buf, "{}", .{request_options.body.len}) catch unreachable;
            fields.appendAssumeCapacity(.{
                .name = "content-length",
                .value = content_length,
            });
        }
        try validateHeaderBlock(fields.items, .request);
        try validateHeaderBlock(request_options.trailers, .request_trailers);
        try validateDeclaredRequestLength(fields.items, request_options.body.len);

        const stream_id = try self.reserveNextClientStreamId();
        errdefer self.releaseLocalStream(stream_id);
        if (request_options.body.len != 0 and
            request_options.trailers.len == 0)
        {
            try self.writeHeadersThenData(
                stream_id,
                fields.items,
                request_options.body,
                true,
            );
        } else {
            try self.writeHeaders(
                stream_id,
                fields.items,
                request_options.body.len == 0 and
                    request_options.trailers.len == 0,
            );
            if (request_options.body.len != 0) {
                try self.writeData(
                    stream_id,
                    request_options.body,
                    false,
                );
            }
        }
        if (request_options.trailers.len != 0) try self.writeHeaders(stream_id, request_options.trailers, true);
        return .{
            .stream_id = stream_id,
            .request_method = request_options.method,
            .extended_connect = extended_connect,
        };
    }

    /// Start a client request whose DATA is supplied incrementally.
    ///
    /// `body_length` adds Content-Length when the caller did not provide one;
    /// an explicit header must agree. CONNECT uses a dedicated tunnel API and
    /// is rejected here so DATA cannot be confused with tunnel bytes.
    pub fn startRequest(
        self: *Connection,
        options: StreamingRequestOptions,
    ) Error!RequestWriter {
        if (self.role != .client) return error.UnexpectedFrame;
        if (methodIsConnect(options.method)) {
            return error.InvalidContentLength;
        }
        var request_options = options;
        if (request_options.authority == null) {
            request_options.authority = self.default_authority;
        }
        const scheme = request_options.scheme orelse
            self.default_scheme orelse "https";

        var fields_stack: [16]http2.Hpack.HeaderField = undefined;
        const fields_capacity = std.math.add(
            usize,
            request_options.headers.len,
            7,
        ) catch return error.MessageTooLarge;
        const fields_buffer = if (fields_capacity <= fields_stack.len)
            fields_stack[0..fields_capacity]
        else
            try self.allocator.alloc(
                http2.Hpack.HeaderField,
                fields_capacity,
            );
        defer if (fields_buffer.ptr != fields_stack[0..].ptr) {
            self.allocator.free(fields_buffer);
        };
        var fields: std.ArrayList(http2.Hpack.HeaderField) =
            .initBuffer(fields_buffer);
        fields.appendAssumeCapacity(.{
            .name = ":method",
            .value = request_options.method,
        });
        fields.appendAssumeCapacity(.{
            .name = ":path",
            .value = request_options.path,
        });
        fields.appendAssumeCapacity(.{
            .name = ":scheme",
            .value = scheme,
        });
        if (request_options.authority) |authority| {
            fields.appendAssumeCapacity(.{
                .name = ":authority",
                .value = authority,
            });
        }
        var priority_buffer: [16]u8 = undefined;
        if (request_options.priority) |priority| {
            fields.appendAssumeCapacity(.{
                .name = "priority",
                .value = priority.serialize(&priority_buffer),
            });
        }
        fields.appendSliceAssumeCapacity(request_options.headers);
        stripConnectionHeaders(&fields, .request);

        const declared_length = try contentLength(fields.items);
        const expected_length = request_options.body_length orelse
            declared_length;
        if (request_options.body_length) |body_length| {
            if (declared_length) |declared| {
                if (declared != body_length) {
                    return error.InvalidContentLength;
                }
            } else {
                var content_length_buffer: [32]u8 = undefined;
                const value = std.fmt.bufPrint(
                    &content_length_buffer,
                    "{}",
                    .{body_length},
                ) catch unreachable;
                fields.appendAssumeCapacity(.{
                    .name = "content-length",
                    .value = value,
                });
            }
        }
        try validateHeaderBlock(fields.items, .request);

        const stream_id = try self.reserveNextClientStreamId();
        var stream_owned = true;
        errdefer if (stream_owned) self.releaseLocalStream(stream_id);
        try self.writeHeaders(stream_id, fields.items, false);
        stream_owned = false;
        return .{
            .connection = self,
            .stream_id = stream_id,
            .expected_length = expected_length,
            .head_request = methodIsHead(request_options.method),
        };
    }

    /// Send several bodyless requests before waiting for their responses.
    ///
    /// Responses are returned in request order even when peer frames arrive in
    /// a different stream order. Request bodies/trailers are intentionally
    /// rejected for now: a body can exhaust flow-control credit while earlier
    /// responses are already arriving, which requires a fully duplex scheduler
    /// rather than this blocking connection's bounded batch pump.
    ///
    /// On success every `responses` element is initialized and owned by the
    /// caller. Deinitialize each with the connection allocator.
    pub fn requestBatchInto(
        self: *Connection,
        requests: []const RequestOptions,
        responses: []OwnedResponse,
    ) Error!void {
        if (self.role != .client) return error.UnexpectedFrame;
        if (requests.len != responses.len) return error.InvalidResponse;
        if (requests.len == 0) return;
        if (self.active_local_streams.items.len != 0) {
            return error.UnexpectedFrame;
        }
        for (requests) |request_options| {
            if (request_options.body.len != 0 or
                request_options.trailers.len != 0)
            {
                return error.InvalidContentLength;
            }
            // CONNECT transitions the stream into a tunnel whose lifetime
            // cannot be represented by an owned, completed batch response.
            // Use openConnectTunnel/openExtendedConnect for those streams.
            if (methodIsConnect(request_options.method)) {
                return error.InvalidHeader;
            }
        }

        var states_stack: [16]BatchResponseState = undefined;
        const states = if (requests.len <= states_stack.len)
            states_stack[0..requests.len]
        else
            try self.allocator.alloc(BatchResponseState, requests.len);
        defer if (states.ptr != states_stack[0..].ptr) {
            self.allocator.free(states);
        };
        const batch = &self.write_batch;
        batch.clearRetainingCapacity();
        var staged_encoder = try self.hpack_encoder.clone(self.allocator);
        var staged_encoder_owned = true;
        defer if (staged_encoder_owned) {
            staged_encoder.deinit(self.allocator);
        };
        var started: usize = 0;
        errdefer {
            for (states[0..started]) |*state| {
                self.releaseLocalStream(state.stream_id);
                state.deinit(self.allocator);
            }
        }
        for (requests, states) |request_options, *state| {
            const pending = try self.appendBodylessRequestToBatch(
                request_options,
                batch,
                &staged_encoder,
            );
            state.* = .{
                .stream_id = pending.stream_id,
                .request_method = pending.request_method,
                .extended_connect = pending.extended_connect,
            };
            started += 1;
        }
        try writeAll(self.io, self.stream, batch.items);
        self.hpack_encoder.deinit(self.allocator);
        self.hpack_encoder = staged_encoder;
        staged_encoder_owned = false;

        try self.readResponseBatch(states);
        for (states, responses) |*state, *response| {
            response.* = .{
                .headers = state.headers.?,
                .status = state.status.?,
                .body = state.body_owned.?,
                .trailers = state.trailers,
            };
            state.headers = null;
            state.body_owned = null;
            state.trailers = &.{};
            self.releaseLocalStream(state.stream_id);
        }
    }

    /// Send bodyless request heads and stream interleaved response DATA.
    ///
    /// Response metadata is returned in request order, while `consume`
    /// receives that same request index plus each borrowed DATA slice. This is
    /// the no-aggregation counterpart to `requestBatchInto`. If the callback
    /// fails, unfinished streams are cancelled and no output element becomes
    /// caller-owned. A transport write failure may have exposed only a prefix
    /// of the staged request set, so the connection must be closed rather than
    /// reused after such an error.
    pub fn requestBatchStreamingInto(
        self: *Connection,
        requests: []const RequestOptions,
        responses: []StreamingResponse,
        context: anytype,
        comptime consume: anytype,
    ) !void {
        if (self.role != .client) return error.UnexpectedFrame;
        if (requests.len != responses.len) return error.InvalidResponse;
        if (requests.len == 0) return;
        if (self.active_local_streams.items.len != 0) {
            return error.UnexpectedFrame;
        }
        for (requests) |request_options| {
            if (request_options.body.len != 0 or
                request_options.trailers.len != 0)
            {
                return error.InvalidContentLength;
            }
            if (methodIsConnect(request_options.method)) {
                return error.InvalidHeader;
            }
        }

        var states_stack: [16]BatchResponseState = undefined;
        const states = if (requests.len <= states_stack.len)
            states_stack[0..requests.len]
        else
            try self.allocator.alloc(BatchResponseState, requests.len);
        defer if (states.ptr != states_stack[0..].ptr) {
            self.allocator.free(states);
        };

        const batch = &self.write_batch;
        batch.clearRetainingCapacity();
        var staged_encoder = try self.hpack_encoder.clone(self.allocator);
        var staged_encoder_owned = true;
        defer if (staged_encoder_owned) {
            staged_encoder.deinit(self.allocator);
        };
        var started: usize = 0;
        var requests_written = false;
        errdefer {
            for (states[0..started]) |*state| {
                if (requests_written and !state.done) {
                    self.writeResetStreamFrame(
                        state.stream_id,
                        .cancel,
                    ) catch {};
                }
                self.releaseLocalStream(state.stream_id);
                state.deinit(self.allocator);
            }
        }
        for (requests, states) |request_options, *state| {
            const pending = try self.appendBodylessRequestToBatch(
                request_options,
                batch,
                &staged_encoder,
            );
            state.* = .{
                .stream_id = pending.stream_id,
                .request_method = pending.request_method,
                .extended_connect = pending.extended_connect,
            };
            started += 1;
        }
        writeAll(self.io, self.stream, batch.items) catch |err| {
            // Some HEADERS may already be visible. As with body-bearing
            // batches, retain advanced HPACK state and consumed stream IDs so
            // accidental reuse cannot pretend the transaction never started.
            self.hpack_encoder.deinit(self.allocator);
            self.hpack_encoder = staged_encoder;
            staged_encoder_owned = false;
            return err;
        };
        self.hpack_encoder.deinit(self.allocator);
        self.hpack_encoder = staged_encoder;
        staged_encoder_owned = false;
        requests_written = true;

        try self.readResponseBatchStreaming(
            states,
            context,
            consume,
        );
        for (states, responses) |*state, *response| {
            response.* = .{
                .headers = state.headers.?,
                .status = state.status.?,
                .body_bytes = state.body_bytes,
                .trailers = state.trailers,
            };
            state.headers = null;
            state.trailers = &.{};
            self.releaseLocalStream(state.stream_id);
        }
    }

    /// Send a batch whose complete bodies fit current flow-control credit.
    ///
    /// Unlike `requestBatchInto`, this accepts DATA but never pumps incoming
    /// frames while opening the batch. The whole batch is rejected before any
    /// wire write unless every body fits one peer stream window and their sum
    /// fits the current connection window. That bounded contract is sufficient
    /// for max-window parallel workloads and avoids the deadlock ambiguity of
    /// a general blocking full-duplex scheduler. `body_chunk_size` preserves
    /// the caller's application contribution size while HTTP/2 frame splitting
    /// still obeys the negotiated maximum frame size.
    pub fn requestBodyBatchInto(
        self: *Connection,
        requests: []const RequestOptions,
        body_chunk_size: usize,
        responses: []OwnedResponse,
    ) Error!void {
        if (self.role != .client) return error.UnexpectedFrame;
        if (requests.len != responses.len) return error.InvalidResponse;
        if (requests.len == 0) return;
        if (body_chunk_size == 0) return error.InvalidFrameSize;
        if (self.active_local_streams.items.len != 0) {
            return error.UnexpectedFrame;
        }

        var total_body_bytes: usize = 0;
        for (requests) |request_options| {
            if (request_options.trailers.len != 0) {
                return error.InvalidContentLength;
            }
            if (methodIsConnect(request_options.method)) {
                return error.InvalidHeader;
            }
            total_body_bytes = std.math.add(
                usize,
                total_body_bytes,
                request_options.body.len,
            ) catch return error.MessageTooLarge;
            if (request_options.body.len >
                @as(usize, @intCast(@max(
                    self.peer_initial_stream_window,
                    0,
                ))))
            {
                return error.FlowControlBlocked;
            }
        }
        if (total_body_bytes > self.send_connection_window.available()) {
            return error.FlowControlBlocked;
        }

        var states_stack: [16]BatchResponseState = undefined;
        const states = if (requests.len <= states_stack.len)
            states_stack[0..requests.len]
        else
            try self.allocator.alloc(BatchResponseState, requests.len);
        defer if (states.ptr != states_stack[0..].ptr) {
            self.allocator.free(states);
        };
        var credit_reserved_stack: [16]bool = undefined;
        const credit_reserved =
            if (requests.len <= credit_reserved_stack.len)
                credit_reserved_stack[0..requests.len]
            else
                try self.allocator.alloc(bool, requests.len);
        defer if (credit_reserved.ptr != credit_reserved_stack[0..].ptr) {
            self.allocator.free(credit_reserved);
        };
        @memset(credit_reserved, false);

        const batch = &self.write_batch;
        batch.clearRetainingCapacity();
        const original_next_stream_id = self.next_client_stream_id;
        var staged_encoder = try self.hpack_encoder.clone(self.allocator);
        var staged_encoder_owned = true;
        defer if (staged_encoder_owned) {
            staged_encoder.deinit(self.allocator);
        };
        var started: usize = 0;
        errdefer {
            // Before staged HPACK state is committed no HEADERS were written,
            // so local stream IDs roll back with the transaction. Once the
            // write succeeds, IDs remain consumed on later I/O failures.
            if (staged_encoder_owned) {
                self.next_client_stream_id = original_next_stream_id;
            }
            for (states[0..started]) |*state| {
                self.releaseLocalStream(state.stream_id);
                state.deinit(self.allocator);
            }
        }
        for (requests, states) |request_options, *state| {
            const pending = try self.appendRequestHeadToBatch(
                request_options,
                batch,
                &staged_encoder,
            );
            state.* = .{
                .stream_id = pending.stream_id,
                .request_method = pending.request_method,
                .extended_connect = pending.extended_connect,
            };
            started += 1;
        }

        var reserved_connection_bytes: usize = 0;
        errdefer if (reserved_connection_bytes != 0) {
            self.send_connection_window.update(
                @intCast(reserved_connection_bytes),
            ) catch unreachable;
            for (requests, states, credit_reserved) |
                request_options,
                state,
                stream_credit_reserved,
            | {
                if (!stream_credit_reserved) continue;
                (self.sendStreamWindow(state.stream_id) catch continue)
                    .update(@intCast(request_options.body.len)) catch
                    unreachable;
            }
        };
        try self.send_connection_window.reserve(total_body_bytes);
        reserved_connection_bytes = total_body_bytes;
        for (requests, states, credit_reserved) |
            request_options,
            state,
            *stream_credit_reserved,
        | {
            if (request_options.body.len == 0) continue;
            try (try self.sendStreamWindow(state.stream_id)).reserve(
                request_options.body.len,
            );
            stream_credit_reserved.* = true;
        }

        writeAll(self.io, self.stream, batch.items) catch |err| {
            // A transport failure may expose only a prefix of the staged HPACK
            // sequence. It cannot be retried or rolled back; commit encoder
            // state and stream IDs so any accidental reuse fails closed.
            self.hpack_encoder.deinit(self.allocator);
            self.hpack_encoder = staged_encoder;
            staged_encoder_owned = false;
            return err;
        };
        self.hpack_encoder.deinit(self.allocator);
        self.hpack_encoder = staged_encoder;
        staged_encoder_owned = false;
        var body_write_succeeded = false;
        errdefer if (!body_write_succeeded) {
            // A partial DATA submission has consumed an unknown wire prefix.
            // Keep flow-control accounting conservative; this connection must
            // be closed rather than retried.
            reserved_connection_bytes = 0;
        };
        try self.writeRequestBodyBatchData(
            requests,
            states,
            body_chunk_size,
        );
        body_write_succeeded = true;
        reserved_connection_bytes = 0;

        try self.readResponseBatch(states);
        for (states, responses) |*state, *response| {
            response.* = .{
                .headers = state.headers.?,
                .status = state.status.?,
                .body = state.body_owned.?,
                .trailers = state.trailers,
            };
            state.headers = null;
            state.body_owned = null;
            state.trailers = &.{};
            self.releaseLocalStream(state.stream_id);
        }
    }

    fn appendRequestHeadToBatch(
        self: *Connection,
        options: RequestOptions,
        batch: *std.ArrayList(u8),
        encoder: *http2.Hpack.Encoder,
    ) Error!PendingResponse {
        var request_options = options;
        if (request_options.authority == null) {
            request_options.authority = self.default_authority;
        }
        const scheme =
            request_options.scheme orelse self.default_scheme orelse "https";

        var fields_stack: [16]http2.Hpack.HeaderField = undefined;
        const fields_capacity = std.math.add(
            usize,
            request_options.headers.len,
            7,
        ) catch return error.MessageTooLarge;
        const fields_buffer = if (fields_capacity <= fields_stack.len)
            fields_stack[0..fields_capacity]
        else
            try self.allocator.alloc(
                http2.Hpack.HeaderField,
                fields_capacity,
            );
        defer if (fields_buffer.ptr != fields_stack[0..].ptr) {
            self.allocator.free(fields_buffer);
        };
        var fields: std.ArrayList(http2.Hpack.HeaderField) =
            .initBuffer(fields_buffer);
        fields.appendAssumeCapacity(.{
            .name = ":method",
            .value = request_options.method,
        });
        fields.appendAssumeCapacity(.{
            .name = ":path",
            .value = request_options.path,
        });
        fields.appendAssumeCapacity(.{
            .name = ":scheme",
            .value = scheme,
        });
        if (request_options.authority) |authority| {
            fields.appendAssumeCapacity(.{
                .name = ":authority",
                .value = authority,
            });
        }
        var priority_buf: [16]u8 = undefined;
        if (request_options.priority) |value| {
            fields.appendAssumeCapacity(.{
                .name = "priority",
                .value = value.serialize(&priority_buf),
            });
        }
        fields.appendSliceAssumeCapacity(request_options.headers);
        stripConnectionHeaders(&fields, .request);
        var content_length_buf: [32]u8 = undefined;
        if (requestShouldDefaultContentLength(
            request_options.method,
            fields.items,
            request_options.body.len,
        )) {
            const content_length = std.fmt.bufPrint(
                &content_length_buf,
                "{}",
                .{request_options.body.len},
            ) catch unreachable;
            fields.appendAssumeCapacity(.{
                .name = "content-length",
                .value = content_length,
            });
        }
        try validateHeaderBlock(fields.items, .request);
        try validateDeclaredRequestLength(
            fields.items,
            request_options.body.len,
        );
        try validateHeaderListSize(
            fields.items,
            self.peer_max_header_list_size,
        );

        const stream_id = try self.reserveNextClientStreamId();
        errdefer self.releaseLocalStream(stream_id);
        const block = try encoder.encodeBlockRetained(
            self.allocator,
            fields.items,
        );
        try appendHeaderBlockBytes(
            batch,
            self.allocator,
            stream_id,
            block,
            request_options.body.len == 0,
            self.outboundFramePayloadLimit(),
        );
        return .{
            .stream_id = stream_id,
            .request_method = request_options.method,
            .extended_connect = false,
        };
    }

    fn writeRequestBodyBatchData(
        self: *Connection,
        requests: []const RequestOptions,
        states: []const BatchResponseState,
        application_chunk_size: usize,
    ) Error!void {
        var views_stack: [16]BatchDataView = undefined;
        const views = if (requests.len <= views_stack.len)
            views_stack[0..requests.len]
        else
            try self.allocator.alloc(BatchDataView, requests.len);
        defer if (views.ptr != views_stack[0..].ptr) {
            self.allocator.free(views);
        };
        var offsets_stack: [16]usize = undefined;
        const offsets = if (requests.len <= offsets_stack.len)
            offsets_stack[0..requests.len]
        else
            try self.allocator.alloc(usize, requests.len);
        defer if (offsets.ptr != offsets_stack[0..].ptr) {
            self.allocator.free(offsets);
        };
        @memset(offsets, 0);
        for (views, requests, states) |*view, request_options, state| {
            view.* = .{
                .stream_id = state.stream_id,
                .body = request_options.body,
            };
        }
        try self.prepareBodyBatchData(views, application_chunk_size);
        try self.writeBodyBatchData(
            views,
            offsets,
            application_chunk_size,
        );
    }

    const BatchDataView = struct {
        stream_id: u31,
        body: []const u8,
    };

    fn responseBatchSelection(
        self: *const Connection,
        views: []const BatchDataView,
        offsets: []const usize,
        candidates: []response_scheduler.Candidate,
    ) ?response_scheduler.Selection {
        std.debug.assert(views.len == offsets.len);
        std.debug.assert(views.len == candidates.len);
        for (views, offsets, candidates) |view, offset, *candidate| {
            candidate.* = .{
                .stream_id = view.stream_id,
                .remaining = view.body.len - offset,
                .send_capacity = self.sendStreamWindowAvailable(
                    view.stream_id,
                ),
                .priority = self.responsePriority(view.stream_id),
            };
        }
        return response_scheduler.select(candidates);
    }

    fn prepareBodyBatchData(
        self: *Connection,
        views: []const BatchDataView,
        application_chunk_size: usize,
    ) Error!void {
        const frame_limit = self.outboundFramePayloadLimit();
        var max_body_len: usize = 0;
        for (views) |view| max_body_len = @max(max_body_len, view.body.len);
        self.batch_data_headers.clearRetainingCapacity();
        self.batch_data_parts.clearRetainingCapacity();
        if (max_body_len == 0) return;

        // A caller may use an arbitrarily large application contribution to
        // mean "all remaining bytes". Cap scratch sizing at the largest
        // actual body instead of reserving for frames that cannot be emitted.
        const per_round_frames = std.math.divCeil(
            usize,
            @min(application_chunk_size, max_body_len),
            frame_limit,
        ) catch return error.MessageTooLarge;
        const header_capacity = std.math.mul(
            usize,
            views.len,
            per_round_frames,
        ) catch return error.MessageTooLarge;
        try self.batch_data_headers.ensureTotalCapacity(
            self.allocator,
            header_capacity,
        );
        const parts_capacity = std.math.mul(
            usize,
            header_capacity,
            2,
        ) catch return error.MessageTooLarge;
        try self.batch_data_parts.ensureTotalCapacity(
            self.allocator,
            parts_capacity,
        );
    }

    fn writeBodyBatchData(
        self: *Connection,
        views: []const BatchDataView,
        offsets: []usize,
        application_chunk_size: usize,
    ) Error!void {
        // Response batches call `prepareBodyBatchData` before HEADERS are
        // written. The send loop is therefore allocation-free and cannot fail
        // for local memory after committing those responses to the wire.
        std.debug.assert(views.len == offsets.len);
        const frame_limit = self.outboundFramePayloadLimit();

        while (true) {
            self.batch_data_headers.clearRetainingCapacity();
            self.batch_data_parts.clearRetainingCapacity();
            var has_data = false;
            for (views, offsets) |
                view,
                *offset,
            | {
                if (offset.* == view.body.len) continue;
                has_data = true;
                const contribution_len = @min(
                    application_chunk_size,
                    view.body.len - offset.*,
                );
                const contribution_end = offset.* + contribution_len;
                while (offset.* < contribution_end) {
                    const end = @min(
                        contribution_end,
                        offset.* + frame_limit,
                    );
                    const header_index =
                        self.batch_data_headers.items.len;
                    self.batch_data_headers.appendAssumeCapacity(undefined);
                    try encodeFrameHeader(
                        &self.batch_data_headers.items[header_index],
                        .data,
                        if (end == view.body.len)
                            flag_end_stream
                        else
                            0,
                        view.stream_id,
                        end - offset.*,
                    );
                    self.batch_data_parts.appendAssumeCapacity(
                        &self.batch_data_headers.items[header_index],
                    );
                    self.batch_data_parts.appendAssumeCapacity(
                        view.body[offset.*..end],
                    );
                    offset.* = end;
                }
            }
            if (!has_data) return;
            try stream_io.writeAllSlicesWide(
                self.io,
                self.stream,
                self.batch_data_parts.items,
            );
        }
    }

    fn appendBodylessRequestToBatch(
        self: *Connection,
        options: RequestOptions,
        batch: *std.ArrayList(u8),
        encoder: *http2.Hpack.Encoder,
    ) Error!PendingResponse {
        var request_options = options;
        if (request_options.authority == null) {
            request_options.authority = self.default_authority;
        }
        const scheme =
            request_options.scheme orelse self.default_scheme orelse "https";

        var fields_stack: [16]http2.Hpack.HeaderField = undefined;
        const fields_capacity = std.math.add(
            usize,
            request_options.headers.len,
            7,
        ) catch return error.MessageTooLarge;
        const fields_buffer = if (fields_capacity <= fields_stack.len)
            fields_stack[0..fields_capacity]
        else
            try self.allocator.alloc(
                http2.Hpack.HeaderField,
                fields_capacity,
            );
        defer if (fields_buffer.ptr != fields_stack[0..].ptr) {
            self.allocator.free(fields_buffer);
        };
        var fields: std.ArrayList(http2.Hpack.HeaderField) =
            .initBuffer(fields_buffer);

        const method_is_connect = methodIsConnect(request_options.method);
        const extended_connect = request_options.protocol != null;
        fields.appendAssumeCapacity(.{
            .name = ":method",
            .value = request_options.method,
        });
        if (!method_is_connect or extended_connect) {
            fields.appendAssumeCapacity(.{
                .name = ":path",
                .value = request_options.path,
            });
            fields.appendAssumeCapacity(.{
                .name = ":scheme",
                .value = scheme,
            });
        }
        if (request_options.protocol) |protocol| {
            if (!self.peer_enable_connect_protocol) {
                return error.ExtendedConnectDisabled;
            }
            fields.appendAssumeCapacity(.{
                .name = ":protocol",
                .value = protocol,
            });
        }
        if (request_options.authority) |authority| {
            fields.appendAssumeCapacity(.{
                .name = ":authority",
                .value = authority,
            });
        }
        var priority_buf: [16]u8 = undefined;
        if (request_options.priority) |value| {
            fields.appendAssumeCapacity(.{
                .name = "priority",
                .value = value.serialize(&priority_buf),
            });
        }
        fields.appendSliceAssumeCapacity(request_options.headers);
        stripConnectionHeaders(&fields, .request);
        var content_length_buf: [32]u8 = undefined;
        if (requestShouldDefaultContentLength(
            request_options.method,
            fields.items,
            0,
        )) {
            const content_length = std.fmt.bufPrint(
                &content_length_buf,
                "{}",
                .{0},
            ) catch unreachable;
            fields.appendAssumeCapacity(.{
                .name = "content-length",
                .value = content_length,
            });
        }
        try validateHeaderBlock(fields.items, .request);
        try validateDeclaredRequestLength(fields.items, 0);
        try validateHeaderListSize(
            fields.items,
            self.peer_max_header_list_size,
        );

        const stream_id = try self.reserveNextClientStreamId();
        errdefer self.releaseLocalStream(stream_id);
        const block = try encoder.encodeBlockRetained(
            self.allocator,
            fields.items,
        );
        try appendHeaderBlockBytes(
            batch,
            self.allocator,
            stream_id,
            block,
            true,
            self.outboundFramePayloadLimit(),
        );
        return .{
            .stream_id = stream_id,
            .request_method = request_options.method,
            .extended_connect = extended_connect,
        };
    }

    const BatchResponseState = struct {
        stream_id: u31,
        request_method: []const u8,
        extended_connect: bool,
        headers: ?[]http2.Hpack.HeaderField = null,
        status: ?u16 = null,
        content_length: ?usize = null,
        body: std.ArrayList(u8) = .empty,
        body_owned: ?[]u8 = null,
        trailers: []http2.Hpack.HeaderField = &.{},
        forbids_body: bool = false,
        done: bool = false,
        body_bytes: usize = 0,

        fn deinit(
            self: *BatchResponseState,
            allocator: std.mem.Allocator,
        ) void {
            if (self.headers) |headers| freeHeaders(allocator, headers);
            freeHeaders(allocator, self.trailers);
            if (self.body_owned) |body| {
                allocator.free(body);
            } else {
                self.body.deinit(allocator);
            }
            self.* = undefined;
        }
    };

    fn readResponseBatch(
        self: *Connection,
        states: []BatchResponseState,
    ) Error!void {
        var remaining = states.len;
        while (remaining != 0) {
            var frame = try self.readOwnedFrame();
            defer frame.deinit(self.allocator);
            if (try self.handleConnectionFrame(frame.frame)) continue;
            if (frame.frame.header.frame_type == .goaway) {
                const goaway = try http2.GoAwayPayload.parse(frame.frame);
                try self.recordPeerGoAway(goaway);
                for (states) |state| {
                    if (!state.done and state.stream_id > goaway.last_stream_id) {
                        return error.ConnectionGoAway;
                    }
                }
                continue;
            }

            const state = findBatchResponseState(
                states,
                frame.frame.header.stream_id,
            ) orelse return error.UnexpectedFrame;
            if (state.done) return error.UnexpectedFrame;
            switch (frame.frame.header.frame_type) {
                .push_promise => {
                    if (!self.limits.enable_push) {
                        _ = try self.validatePushPromiseForClientStream(
                            frame.frame,
                        );
                        return error.InvalidFrame;
                    }
                    try self.receivePushPromise(frame.frame);
                },
                .headers => {
                    if (state.headers != null) {
                        if (state.forbids_body) {
                            return error.InvalidContentLength;
                        }
                        if ((frame.frame.header.flags & flag_end_stream) == 0) {
                            return error.UnexpectedFrame;
                        }
                        state.trailers = try self.readHeaderBlock(frame.frame);
                        try validateHeaderBlock(
                            state.trailers,
                            .response_trailers,
                        );
                        try validateExpectedContentLength(
                            state.content_length,
                            state.body.items.len,
                        );
                        state.done = true;
                        remaining -= 1;
                        continue;
                    }

                    const headers = try self.readHeaderBlock(frame.frame);
                    var headers_owned_by_state = false;
                    errdefer if (!headers_owned_by_state) {
                        freeHeaders(self.allocator, headers);
                    };
                    try validateHeaderBlock(headers, .response);
                    const lookup = try responseHeaderLookup(headers);
                    const status_text = lookup.status orelse
                        return error.MissingPseudoHeader;
                    const status = std.fmt.parseInt(
                        u16,
                        status_text,
                        10,
                    ) catch return error.InvalidStatus;
                    if (informationalResponseToSkip(status)) {
                        if ((frame.frame.header.flags & flag_end_stream) != 0 or
                            lookup.content_length != null)
                        {
                            return error.InvalidContentLength;
                        }
                        freeHeaders(self.allocator, headers);
                        continue;
                    }

                    state.headers = headers;
                    headers_owned_by_state = true;
                    state.status = status;
                    state.content_length = lookup.content_length;
                    state.forbids_body = responseForbidsBody(
                        status,
                        state.request_method,
                        state.extended_connect,
                    );
                    if (state.forbids_body) {
                        const traditional_connect =
                            methodIsConnect(state.request_method) and
                            !state.extended_connect;
                        if (traditional_connect and
                            (lookup.content_length orelse 0) != 0)
                        {
                            return error.InvalidContentLength;
                        }
                        if ((statusIsInformational(status) or status == 204) and
                            lookup.content_length != null)
                        {
                            return error.InvalidContentLength;
                        }
                    }
                    if ((frame.frame.header.flags & flag_end_stream) != 0) {
                        try validateExpectedContentLength(
                            lookup.content_length,
                            0,
                        );
                        state.done = true;
                        remaining -= 1;
                    }
                },
                .data => {
                    if (state.headers == null) return error.UnexpectedFrame;
                    const data = try self.receiveDataPayload(
                        state.stream_id,
                        frame.frame,
                    );
                    if (state.forbids_body and data.data.len != 0) {
                        return error.InvalidContentLength;
                    }
                    const body_len = std.math.add(
                        usize,
                        state.body.items.len,
                        data.data.len,
                    ) catch return error.MessageTooLarge;
                    if (body_len > self.limits.max_body_bytes) {
                        return error.MessageTooLarge;
                    }
                    try state.body.appendSlice(self.allocator, data.data);
                    try self.maybeReleaseReceivedCapacity(state.stream_id);
                    if ((frame.frame.header.flags & flag_end_stream) != 0) {
                        try validateExpectedContentLength(
                            state.content_length,
                            state.body.items.len,
                        );
                        state.done = true;
                        remaining -= 1;
                    }
                },
                .rst_stream => return error.StreamReset,
                else => return error.UnexpectedFrame,
            }
        }

        // Acquire all body ownership before exposing any output element, so an
        // allocation failure leaves cleanup entirely inside the state array.
        for (states) |*state| {
            state.body_owned = try state.body.toOwnedSlice(self.allocator);
        }
    }

    fn readResponseBatchStreaming(
        self: *Connection,
        states: []BatchResponseState,
        context: anytype,
        comptime consume: anytype,
    ) !void {
        var remaining = states.len;
        while (remaining != 0) {
            const frame = try self.readFrameScratch();
            if (try self.handleConnectionFrame(frame)) continue;
            if (frame.header.frame_type == .goaway) {
                const goaway = try http2.GoAwayPayload.parse(frame);
                try self.recordPeerGoAway(goaway);
                for (states) |state| {
                    if (!state.done and
                        state.stream_id > goaway.last_stream_id)
                    {
                        return error.ConnectionGoAway;
                    }
                }
                continue;
            }

            const state_index = findBatchResponseStateIndex(
                states,
                frame.header.stream_id,
            ) orelse return error.UnexpectedFrame;
            const state = &states[state_index];
            if (state.done) return error.UnexpectedFrame;
            switch (frame.header.frame_type) {
                .push_promise => {
                    if (!self.limits.enable_push) {
                        _ = try self.validatePushPromiseForClientStream(
                            frame,
                        );
                        return error.InvalidFrame;
                    }
                    try self.receivePushPromise(frame);
                },
                .headers => {
                    if (state.headers != null) {
                        if (state.forbids_body or
                            (frame.header.flags & flag_end_stream) == 0)
                        {
                            return error.UnexpectedFrame;
                        }
                        state.trailers = try self.readHeaderBlock(frame);
                        var trailers_owned = true;
                        errdefer if (trailers_owned) {
                            freeHeaders(self.allocator, state.trailers);
                            state.trailers = &.{};
                        };
                        try validateHeaderBlock(
                            state.trailers,
                            .response_trailers,
                        );
                        try validateExpectedContentLength(
                            state.content_length,
                            state.body_bytes,
                        );
                        state.done = true;
                        remaining -= 1;
                        trailers_owned = false;
                        continue;
                    }

                    const headers = try self.readHeaderBlock(frame);
                    var headers_owned_by_state = false;
                    errdefer if (!headers_owned_by_state) {
                        freeHeaders(self.allocator, headers);
                    };
                    try validateHeaderBlock(headers, .response);
                    const lookup = try responseHeaderLookup(headers);
                    const status_text = lookup.status orelse
                        return error.MissingPseudoHeader;
                    const status = std.fmt.parseInt(
                        u16,
                        status_text,
                        10,
                    ) catch return error.InvalidStatus;
                    if (informationalResponseToSkip(status)) {
                        if ((frame.header.flags & flag_end_stream) != 0 or
                            lookup.content_length != null)
                        {
                            return error.InvalidContentLength;
                        }
                        freeHeaders(self.allocator, headers);
                        continue;
                    }

                    state.headers = headers;
                    headers_owned_by_state = true;
                    state.status = status;
                    state.content_length = lookup.content_length;
                    state.forbids_body = responseForbidsBody(
                        status,
                        state.request_method,
                        state.extended_connect,
                    );
                    if ((lookup.content_length orelse 0) >
                        self.limits.max_body_bytes)
                    {
                        return error.MessageTooLarge;
                    }
                    if (state.forbids_body) {
                        const traditional_connect =
                            methodIsConnect(state.request_method) and
                            !state.extended_connect;
                        if (traditional_connect and
                            (lookup.content_length orelse 0) != 0)
                        {
                            return error.InvalidContentLength;
                        }
                        if ((statusIsInformational(status) or status == 204) and
                            lookup.content_length != null)
                        {
                            return error.InvalidContentLength;
                        }
                    }
                    if ((frame.header.flags & flag_end_stream) != 0) {
                        try validateExpectedContentLength(
                            lookup.content_length,
                            0,
                        );
                        state.done = true;
                        remaining -= 1;
                    }
                },
                .data => {
                    if (state.headers == null) return error.UnexpectedFrame;
                    const data = try self.receiveDataPayload(
                        state.stream_id,
                        frame,
                    );
                    if (state.forbids_body and data.data.len != 0) {
                        return error.InvalidContentLength;
                    }
                    state.body_bytes = std.math.add(
                        usize,
                        state.body_bytes,
                        data.data.len,
                    ) catch return error.MessageTooLarge;
                    if (state.body_bytes > self.limits.max_body_bytes) {
                        return error.MessageTooLarge;
                    }
                    if (data.data.len != 0) {
                        consume(
                            context,
                            state_index,
                            data.data,
                        ) catch |err| {
                            // Restore exact charged credit before the outer
                            // cleanup cancels every unfinished stream. Relying
                            // on low-watermark updates here would leak usable
                            // connection credit across callback failures.
                            self.releaseReceivedCapacity(
                                state.stream_id,
                                frame.payload.len,
                            ) catch {};
                            // A final DATA already closed the remote half; do
                            // not emit a redundant reset for that stream while
                            // cancelling the rest of the batch.
                            if ((frame.header.flags &
                                flag_end_stream) != 0)
                            {
                                state.done = true;
                            }
                            return err;
                        };
                    }
                    try self.maybeReleaseReceivedCapacity(state.stream_id);
                    if ((frame.header.flags & flag_end_stream) != 0) {
                        try validateExpectedContentLength(
                            state.content_length,
                            state.body_bytes,
                        );
                        state.done = true;
                        remaining -= 1;
                    }
                },
                .rst_stream => return error.StreamReset,
                else => return error.UnexpectedFrame,
            }
        }
    }

    fn findBatchResponseState(
        states: []BatchResponseState,
        stream_id: u31,
    ) ?*BatchResponseState {
        const index = findBatchResponseStateIndex(
            states,
            stream_id,
        ) orelse return null;
        return &states[index];
    }

    fn findBatchResponseStateIndex(
        states: []const BatchResponseState,
        stream_id: u31,
    ) ?usize {
        if (states.len == 0 or stream_id < states[0].stream_id) return null;
        const delta = stream_id - states[0].stream_id;
        if ((delta & 1) != 0) return null;
        const index: usize = delta / 2;
        if (index >= states.len or states[index].stream_id != stream_id) {
            return null;
        }
        return index;
    }

    pub fn takePromisedRequest(
        self: *Connection,
    ) ?PromisedRequest {
        return self.push_state.take();
    }

    pub fn readPushedResponse(
        self: *Connection,
        promise: PromisedRequest,
    ) Error!OwnedResponse {
        if (self.role != .client) return error.UnexpectedFrame;
        if (!self.push_state.isRemoteReserved(
            promise.promised_stream_id,
        ) or self.push_state.hasPending(promise.promised_stream_id)) {
            return error.InvalidStreamId;
        }
        if (self.limits.max_concurrent_streams) |limit| {
            if (self.active_peer_streams.items.len >= limit) {
                return error.FlowControlViolation;
            }
        }
        try self.addActivePeerStream(promise.promised_stream_id);
        _ = self.push_state.releaseRemote(
            promise.promised_stream_id,
        );
        defer self.releasePeerStream(promise.promised_stream_id);
        return self.readResponseOnPeerStream(
            promise.promised_stream_id,
            findHeader(promise.headers, ":method") orelse "GET",
        );
    }

    /// Refuses a server push that was announced by PUSH_PROMISE.
    ///
    /// The stream ID remains valid after `takePromisedRequest` transfers the
    /// request headers to the caller. Cancellation consumes that owned request,
    /// emits RST_STREAM(CANCEL), and makes later reads or duplicate cancellation
    /// invalid. The caller must not deinitialize or use `promise` afterward.
    pub fn cancelPush(
        self: *Connection,
        promise: *PromisedRequest,
    ) Error!void {
        if (self.role != .client) return error.UnexpectedFrame;
        const promised_stream_id = promise.promised_stream_id;
        if (!self.push_state.isRemoteReserved(promised_stream_id)) {
            return error.InvalidStreamId;
        }
        if (self.push_state.hasPending(promised_stream_id)) {
            return error.InvalidStreamId;
        }
        try self.writeResetStreamFrame(
            promised_stream_id,
            .cancel,
        );
        _ = self.push_state.cancelRemote(
            self.allocator,
            promised_stream_id,
        );
        promise.deinit(self.allocator);
    }

    pub fn peerOrigins(self: Connection) []const []u8 {
        return self.peer_origins.items;
    }

    pub fn alternativeServices(
        self: Connection,
    ) []const AlternativeService {
        return self.alternative_services.items;
    }

    /// Return the most recent RFC 9218 signal for a request or promised push.
    pub fn peerPriority(
        self: Connection,
        stream_id: u31,
    ) ?http2.ExtensiblePriority {
        const update = self.priority_state.get(stream_id) orelse return null;
        return update.priority();
    }

    pub fn peerPriorityFieldValue(
        self: Connection,
        stream_id: u31,
    ) ?[]const u8 {
        const update = self.priority_state.get(stream_id) orelse return null;
        return update.field_value;
    }

    fn effectiveRequestPriority(
        self: Connection,
        stream_id: u31,
        header_value: ?[]const u8,
    ) http2.ExtensiblePriority {
        return self.peerPriority(stream_id) orelse
            http2.ExtensiblePriority.parse(header_value orelse "");
    }

    /// Send an HTTP/2 PRIORITY_UPDATE after the peer opted into RFC 9218.
    ///
    /// RFC 9218 only permits clients to send this frame. The target may be a
    /// request stream that has not opened yet, but a push target must already
    /// have been promised by the server.
    pub fn sendPriorityUpdate(
        self: *Connection,
        stream_id: u31,
        value: http2.ExtensiblePriority,
    ) Error!void {
        var field_value_buf: [16]u8 = undefined;
        return self.sendPriorityUpdateRaw(
            stream_id,
            value.serialize(&field_value_buf),
        );
    }

    /// Raw variant that preserves extension parameters unknown to Netz.
    pub fn sendPriorityUpdateRaw(
        self: *Connection,
        stream_id: u31,
        field_value: []const u8,
    ) Error!void {
        if (self.role != .client) return error.UnexpectedFrame;
        if (!self.peer_no_rfc7540_priorities) {
            return error.UnexpectedFrame;
        }
        if (stream_id == 0) return error.InvalidStreamId;
        if (!clientInitiatedStreamId(stream_id) and
            !self.push_state.isRemoteReserved(stream_id) and
            !self.outboundStreamIsActive(stream_id))
        {
            // Even IDs that have not appeared in PUSH_PROMISE are idle push
            // streams, which RFC 9218 explicitly forbids reprioritizing.
            return error.InvalidStreamId;
        }
        const idle_request = clientInitiatedStreamId(stream_id) and
            stream_id >= self.next_client_stream_id and
            !self.outboundStreamIsActive(stream_id);
        const already_reserved =
            self.priority_state.containsIdleRequest(stream_id);
        if (idle_request) {
            try self.priority_state.reserveIdleRequest(
                self.allocator,
                stream_id,
                self.active_local_streams.items.len,
                self.peer_max_concurrent_streams,
                self.limits.max_idle_priority_updates,
            );
        }
        errdefer if (idle_request and !already_reserved) {
            _ = self.priority_state.activateRequest(stream_id);
        };
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try http2.PriorityUpdatePayload.write(
            &encoded,
            self.allocator,
            stream_id,
            field_value,
        );
        try writeAll(self.io, self.stream, encoded.items);
    }

    /// Read and apply the next peer PRIORITY_UPDATE, skipping ordinary
    /// connection-management frames. Servers can use this when priority
    /// signaling arrives while no request reader is currently pumping frames.
    pub fn readPriorityUpdate(
        self: *Connection,
    ) Error!http2.PriorityUpdatePayload {
        while (true) {
            var frame = try self.readOwnedFrame();
            defer frame.deinit(self.allocator);
            if (frame.frame.header.frame_type == .priority_update) {
                const update =
                    try http2.PriorityUpdatePayload.parse(frame.frame);
                if (!try self.handleConnectionFrame(frame.frame)) {
                    return error.UnexpectedFrame;
                }
                if (self.peerPriorityFieldValue(
                    update.prioritized_stream_id,
                )) |owned| {
                    return .{
                        .prioritized_stream_id = update.prioritized_stream_id,
                        .field_value = owned,
                    };
                }
                continue;
            }
            if (try self.handleConnectionOrGoAwayFrame(frame.frame)) {
                continue;
            }
            return error.UnexpectedFrame;
        }
    }

    pub fn openExtendedConnect(self: *Connection, options: RequestOptions) Error!ExtendedConnectResponse {
        if (self.role != .client) return error.UnexpectedFrame;
        var request_options = options;
        if (request_options.authority == null) request_options.authority = self.default_authority;
        if (!methodIsConnect(request_options.method)) return error.InvalidHeader;
        const protocol = request_options.protocol orelse return error.InvalidHeader;
        if (!self.peer_enable_connect_protocol) return error.ExtendedConnectDisabled;
        if (request_options.body.len != 0 or request_options.trailers.len != 0) return error.InvalidContentLength;
        const scheme = request_options.scheme orelse self.default_scheme orelse "https";

        var fields: std.ArrayList(http2.Hpack.HeaderField) = .empty;
        defer fields.deinit(self.allocator);
        try fields.append(self.allocator, .{ .name = ":method", .value = "CONNECT" });
        try fields.append(self.allocator, .{ .name = ":path", .value = request_options.path });
        try fields.append(self.allocator, .{ .name = ":scheme", .value = scheme });
        try fields.append(self.allocator, .{ .name = ":protocol", .value = protocol });
        if (request_options.authority) |authority| try fields.append(self.allocator, .{ .name = ":authority", .value = authority });
        var priority_buf: [16]u8 = undefined;
        if (request_options.priority) |value| {
            try fields.append(self.allocator, .{
                .name = "priority",
                .value = value.serialize(&priority_buf),
            });
        }
        for (request_options.headers) |header| try fields.append(self.allocator, header);
        stripConnectionHeaders(&fields, .request);
        try validateHeaderBlock(fields.items, .request);

        const stream_id = try self.reserveNextClientStreamId();
        errdefer self.releaseLocalStream(stream_id);
        // Extended CONNECT establishes a bidirectional byte tunnel.  The
        // opening HEADERS therefore deliberately keeps the stream open instead
        // of using END_STREAM like a request with no body would.
        try self.writeHeaders(stream_id, fields.items, false);
        return self.readExtendedConnectResponse(stream_id);
    }

    pub fn openConnectTunnel(self: *Connection, options: RequestOptions) Error!ExtendedConnectResponse {
        if (self.role != .client) return error.UnexpectedFrame;
        var request_options = options;
        if (request_options.authority == null) request_options.authority = self.default_authority;
        if (!methodIsConnect(request_options.method) or request_options.protocol != null) return error.InvalidHeader;
        if (request_options.authority == null) return error.MissingPseudoHeader;
        if (request_options.body.len != 0 or request_options.trailers.len != 0) return error.InvalidContentLength;

        var fields: std.ArrayList(http2.Hpack.HeaderField) = .empty;
        defer fields.deinit(self.allocator);
        try fields.append(self.allocator, .{ .name = ":method", .value = "CONNECT" });
        try fields.append(self.allocator, .{ .name = ":authority", .value = request_options.authority.? });
        var priority_buf: [16]u8 = undefined;
        if (request_options.priority) |value| {
            try fields.append(self.allocator, .{
                .name = "priority",
                .value = value.serialize(&priority_buf),
            });
        }
        for (request_options.headers) |header| try fields.append(self.allocator, header);
        stripConnectionHeaders(&fields, .request);
        try validateHeaderBlock(fields.items, .request);

        const stream_id = try self.reserveNextClientStreamId();
        errdefer self.releaseLocalStream(stream_id);
        // Traditional HTTP/2 CONNECT also establishes a tunnel on the stream.
        // Keep the request side open so DATA frames can flow immediately after
        // the peer accepts with a 2xx response.
        try self.writeHeaders(stream_id, fields.items, false);
        return self.readExtendedConnectResponse(stream_id);
    }

    pub fn readExtendedConnectRequest(self: *Connection, expected_protocol: []const u8) Error!ExtendedConnectRequest {
        if (self.role != .server) return error.UnexpectedFrame;
        if (!self.limits.enable_connect_protocol) return error.ExtendedConnectDisabled;
        while (true) {
            var frame = try self.readOwnedFrame();
            defer frame.deinit(self.allocator);
            if (try self.handleConnectionFrame(frame.frame)) continue;
            switch (frame.frame.header.frame_type) {
                .headers => {
                    const stream_id = frame.frame.header.stream_id;
                    if (!clientInitiatedStreamId(stream_id)) return error.InvalidFrame;
                    if (stream_id <= self.last_peer_client_stream_id) return error.InvalidFrame;
                    try self.reservePeerStream(stream_id);
                    errdefer self.releasePeerStream(stream_id);
                    self.last_peer_client_stream_id = stream_id;
                    if ((frame.frame.header.flags & flag_end_stream) != 0) return error.ConnectionClosed;

                    const headers = try self.readHeaderBlock(frame.frame);
                    errdefer freeHeaders(self.allocator, headers);
                    try validateHeaderBlock(headers, .request);
                    const lookup = try requestHeaderLookup(headers);
                    const method = lookup.method orelse return error.MissingPseudoHeader;
                    const protocol = lookup.protocol orelse return error.InvalidHeader;
                    if (!methodIsConnect(method)) return error.InvalidHeader;
                    if (!std.mem.eql(u8, protocol, expected_protocol)) return error.InvalidHeader;
                    const request_priority =
                        self.effectiveRequestPriority(
                            stream_id,
                            lookup.priority,
                        );
                    try self.rememberResponseSemantics(
                        stream_id,
                        method,
                        protocol,
                        request_priority,
                    );

                    return .{
                        .stream_id = stream_id,
                        .headers = headers,
                        .method = method,
                        .path = lookup.path orelse "",
                        .scheme = lookup.scheme orelse "",
                        .authority = lookup.requestAuthority(),
                        .protocol = protocol,
                        .priority = request_priority,
                    };
                },
                .goaway => continue,
                else => return error.UnexpectedFrame,
            }
        }
    }

    pub fn acceptExtendedConnect(
        self: *Connection,
        connect_request: ExtendedConnectRequest,
        response_headers: []const http2.Hpack.HeaderField,
    ) Error!Tunnel {
        if (self.role != .server) return error.UnexpectedFrame;
        try self.writeExtendedConnectResponse(connect_request.stream_id, 200, response_headers, false);
        return .{ .connection = self, .stream_id = connect_request.stream_id };
    }

    pub fn acceptConnectTunnel(
        self: *Connection,
        connect_request: OwnedRequest,
        response_headers: []const http2.Hpack.HeaderField,
    ) Error!Tunnel {
        if (self.role != .server) return error.UnexpectedFrame;
        if (!methodIsConnect(connect_request.method) or connect_request.protocol != null) return error.InvalidHeader;
        if (connect_request.body.len != 0 or connect_request.trailers.len != 0) return error.InvalidContentLength;
        try self.writeExtendedConnectResponse(connect_request.stream_id, 200, response_headers, false);
        return .{ .connection = self, .stream_id = connect_request.stream_id };
    }

    pub fn rejectExtendedConnect(
        self: *Connection,
        stream_id: u31,
        status: u16,
        response_headers: []const http2.Hpack.HeaderField,
    ) Error!void {
        if (self.role != .server) return error.UnexpectedFrame;
        if (status < 300 or statusIsInformational(status)) return error.InvalidStatus;
        try self.writeExtendedConnectResponse(stream_id, status, response_headers, true);
        self.releasePeerStream(stream_id);
    }

    pub fn readRequest(self: *Connection) Error!OwnedRequest {
        if (self.role != .server) return error.UnexpectedFrame;
        if (self.popPendingRequest()) |pending| return pending;
        while (true) {
            var frame = try self.readOwnedFrame();
            defer frame.deinit(self.allocator);
            if (try self.handleConnectionFrame(frame.frame)) continue;
            switch (frame.frame.header.frame_type) {
                .headers => {
                    const stream_id = frame.frame.header.stream_id;
                    if (!clientInitiatedStreamId(stream_id)) return error.InvalidFrame;
                    if (stream_id <= self.last_peer_client_stream_id) return error.InvalidFrame;
                    try self.reservePeerStream(stream_id);
                    errdefer self.releasePeerStream(stream_id);
                    self.last_peer_client_stream_id = stream_id;
                    const headers = try self.readHeaderBlock(frame.frame);
                    errdefer freeHeaders(self.allocator, headers);
                    try validateHeaderBlock(headers, .request);
                    var trailers: []http2.Hpack.HeaderField = &.{};
                    errdefer freeHeaders(self.allocator, trailers);
                    var body: std.ArrayList(u8) = .empty;
                    errdefer body.deinit(self.allocator);

                    const lookup = try requestHeaderLookup(headers);
                    const method = lookup.method orelse return error.MissingPseudoHeader;
                    const protocol = lookup.protocol;
                    if (protocol != null and !self.limits.enable_connect_protocol) {
                        return error.ExtendedConnectDisabled;
                    }
                    const expected_request_len = lookup.content_length;
                    const is_connect = methodIsConnect(method);
                    const is_extended_connect = is_connect and protocol != null;
                    if (is_connect and !is_extended_connect and (expected_request_len orelse 0) != 0) return error.InvalidContentLength;
                    if (expected_request_len) |body_len| {
                        if (body_len > self.limits.max_body_bytes) {
                            return error.MessageTooLarge;
                        }
                        // The Content-Length has already passed strict header
                        // validation. Reserve the final aggregate once rather
                        // than repeatedly growing while DATA frames arrive.
                        try body.ensureTotalCapacity(
                            self.allocator,
                            body_len,
                        );
                    }

                    if ((!is_connect or is_extended_connect) and (frame.frame.header.flags & flag_end_stream) == 0) {
                        while (true) {
                            var incoming = try self.readRequestBodyFrame(
                                stream_id,
                                &body,
                            );
                            switch (incoming) {
                                .direct_data => |end_stream| {
                                    if (end_stream) break;
                                    continue;
                                },
                                .owned_frame => |*owned| {
                                    defer owned.deinit(self.allocator);
                                    if (try self.handleConnectionFrame(
                                        owned.frame,
                                    )) continue;
                                    if (owned.frame.header.stream_id !=
                                        stream_id)
                                    {
                                        if (try self.queueCompletePeerRequestFrame(
                                            owned.frame,
                                        )) continue;
                                        return error.UnexpectedFrame;
                                    }
                                    switch (owned.frame.header.frame_type) {
                                        .data => {
                                            const data =
                                                try self.receiveDataPayload(
                                                    stream_id,
                                                    owned.frame,
                                                );
                                            const body_len = std.math.add(
                                                usize,
                                                body.items.len,
                                                data.data.len,
                                            ) catch
                                                return error.MessageTooLarge;
                                            if (body_len >
                                                self.limits.max_body_bytes)
                                            {
                                                return error.MessageTooLarge;
                                            }
                                            try body.appendSlice(
                                                self.allocator,
                                                data.data,
                                            );
                                            try self.maybeReleaseReceivedCapacity(
                                                stream_id,
                                            );
                                            if ((owned.frame.header.flags &
                                                flag_end_stream) != 0) break;
                                        },
                                        .headers => {
                                            if ((owned.frame.header.flags &
                                                flag_end_stream) == 0)
                                            {
                                                return error.UnexpectedFrame;
                                            }
                                            trailers =
                                                try self.readHeaderBlock(
                                                    owned.frame,
                                                );
                                            try validateHeaderBlock(
                                                trailers,
                                                .request_trailers,
                                            );
                                            try validateExpectedContentLength(
                                                lookup.content_length,
                                                body.items.len,
                                            );
                                            break;
                                        },
                                        .rst_stream => return error.StreamReset,
                                        else => return error.UnexpectedFrame,
                                    }
                                },
                            }
                        }
                    }

                    try validateExpectedContentLength(lookup.content_length, body.items.len);
                    const request_priority =
                        self.effectiveRequestPriority(
                            stream_id,
                            lookup.priority,
                        );
                    try self.rememberResponseSemantics(
                        stream_id,
                        method,
                        protocol,
                        request_priority,
                    );
                    return .{
                        .stream_id = stream_id,
                        .headers = headers,
                        .method = method,
                        .path = lookup.path orelse "",
                        .scheme = lookup.scheme orelse "",
                        .authority = lookup.requestAuthority(),
                        .protocol = protocol,
                        .body = try body.toOwnedSlice(self.allocator),
                        .trailers = trailers,
                        .priority = request_priority,
                    };
                },
                .goaway => continue,
                else => return error.UnexpectedFrame,
            }
        }
    }

    /// Read a complete request while delivering DATA without aggregation.
    ///
    /// Header and trailer fields in the returned value are owned and remain
    /// valid until `StreamingRequest.deinit`. Each DATA slice is borrowed from
    /// connection scratch and is valid only for the duration of `consume`.
    /// This lets handlers hash, parse, forward, or discard large bodies without
    /// a body-sized allocation. The callback must consume the slice before
    /// returning and must not retain it.
    pub fn readRequestStreaming(
        self: *Connection,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingRequest {
        return self.readRequestStreamingWithHead(
            context,
            ignoreStreamingRequestHead,
            consume,
        );
    }

    /// Read a request while reporting its validated HEADERS before any DATA.
    ///
    /// `begin` and `consume` share `context`. The head and DATA slices are
    /// borrowed for their callback duration; owned headers/trailers are
    /// returned in `StreamingRequest`.
    pub fn readRequestStreamingWithHead(
        self: *Connection,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingRequest {
        if (self.role != .server) return error.UnexpectedFrame;
        if (self.popPendingRequest()) |pending_value| {
            var pending = pending_value;
            var pending_owned = true;
            errdefer if (pending_owned) pending.deinit(self.allocator);
            begin(
                context,
                StreamingRequestHead.fromOwned(pending),
            ) catch |err| {
                self.sendResetStream(
                    pending.stream_id,
                    .cancel,
                ) catch {};
                return err;
            };
            if (pending.body.len != 0) {
                consume(context, pending.body) catch |err| {
                    self.sendResetStream(
                        pending.stream_id,
                        .cancel,
                    ) catch {};
                    return err;
                };
            }
            const result = streamingRequestFromOwned(pending);
            self.allocator.free(pending.body);
            pending_owned = false;
            return result;
        }

        while (true) {
            var first = try self.readOwnedFrame();
            defer first.deinit(self.allocator);
            if (try self.handleConnectionFrame(first.frame)) continue;
            if (first.frame.header.frame_type == .goaway) continue;
            if (first.frame.header.frame_type != .headers) {
                return error.UnexpectedFrame;
            }

            const stream_id = first.frame.header.stream_id;
            if (!clientInitiatedStreamId(stream_id) or
                stream_id <= self.last_peer_client_stream_id)
            {
                return error.InvalidFrame;
            }
            try self.reservePeerStream(stream_id);
            errdefer self.releasePeerStream(stream_id);
            self.last_peer_client_stream_id = stream_id;

            const headers = try self.readHeaderBlock(first.frame);
            var headers_owned = true;
            errdefer if (headers_owned) freeHeaders(self.allocator, headers);
            try validateHeaderBlock(headers, .request);
            const lookup = try requestHeaderLookup(headers);
            const method = lookup.method orelse
                return error.MissingPseudoHeader;
            const protocol = lookup.protocol;
            if (protocol != null and !self.limits.enable_connect_protocol) {
                return error.ExtendedConnectDisabled;
            }
            const is_connect = methodIsConnect(method);
            const is_extended_connect = is_connect and protocol != null;
            if (is_connect and !is_extended_connect and
                (lookup.content_length orelse 0) != 0)
            {
                return error.InvalidContentLength;
            }
            if (lookup.content_length) |body_len| {
                if (body_len > self.limits.max_body_bytes) {
                    return error.MessageTooLarge;
                }
            }
            begin(context, .{
                .stream_id = stream_id,
                .headers = headers,
                .method = method,
                .path = lookup.path orelse "",
                .scheme = lookup.scheme orelse "",
                .authority = lookup.requestAuthority(),
                .protocol = protocol,
            }) catch |err| {
                // The peer's request half may already carry END_STREAM, but
                // this server still owns the response half. Cancel the whole
                // stream so a rejected head cannot leave the client waiting.
                self.writeResetStreamFrame(
                    stream_id,
                    .cancel,
                ) catch {};
                return err;
            };

            var trailers: []http2.Hpack.HeaderField = &.{};
            var trailers_owned = false;
            errdefer if (trailers_owned) {
                freeHeaders(self.allocator, trailers);
            };
            var body_bytes: usize = 0;
            if ((!is_connect or is_extended_connect) and
                (first.frame.header.flags & flag_end_stream) == 0)
            {
                while (true) {
                    const frame = try self.readFrameScratch();
                    if (try self.handleConnectionFrame(frame)) continue;
                    if (frame.header.stream_id != stream_id) {
                        if (try self.queueCompletePeerRequestFrame(frame)) {
                            continue;
                        }
                        return error.UnexpectedFrame;
                    }
                    switch (frame.header.frame_type) {
                        .data => {
                            const data =
                                try self.receiveDataPayload(stream_id, frame);
                            body_bytes = std.math.add(
                                usize,
                                body_bytes,
                                data.data.len,
                            ) catch return error.MessageTooLarge;
                            if (body_bytes > self.limits.max_body_bytes) {
                                return error.MessageTooLarge;
                            }
                            if (data.data.len != 0) {
                                consume(context, data.data) catch |err| {
                                    // Mirror the response-side callback
                                    // contract: once DATA has been consumed
                                    // from the receive window, restore exact
                                    // credit and cancel this stream before
                                    // surfacing the application error.
                                    self.releaseReceivedCapacity(
                                        stream_id,
                                        frame.payload.len,
                                    ) catch {};
                                    // Even final request DATA leaves the
                                    // server response half open; terminate it
                                    // when the application rejects the body.
                                    self.writeResetStreamFrame(
                                        stream_id,
                                        .cancel,
                                    ) catch {};
                                    return err;
                                };
                            }
                            try self.maybeReleaseReceivedCapacity(stream_id);
                            if ((frame.header.flags & flag_end_stream) != 0) {
                                break;
                            }
                        },
                        .headers => {
                            if ((frame.header.flags & flag_end_stream) == 0) {
                                return error.UnexpectedFrame;
                            }
                            trailers = try self.readHeaderBlock(frame);
                            trailers_owned = true;
                            try validateHeaderBlock(
                                trailers,
                                .request_trailers,
                            );
                            break;
                        },
                        .rst_stream => return error.StreamReset,
                        else => return error.UnexpectedFrame,
                    }
                }
            }

            try validateExpectedContentLength(
                lookup.content_length,
                body_bytes,
            );
            const request_priority = self.effectiveRequestPriority(
                stream_id,
                lookup.priority,
            );
            try self.rememberResponseSemantics(
                stream_id,
                method,
                protocol,
                request_priority,
            );
            headers_owned = false;
            trailers_owned = false;
            return .{
                .stream_id = stream_id,
                .headers = headers,
                .method = method,
                .path = lookup.path orelse "",
                .scheme = lookup.scheme orelse "",
                .authority = lookup.requestAuthority(),
                .protocol = protocol,
                .body_bytes = body_bytes,
                .trailers = trailers,
                .priority = request_priority,
            };
        }
    }

    /// Read an exact batch of interleaved request streams without aggregating
    /// DATA bodies.
    ///
    /// Requests are returned in peer HEADERS order. Each callback receives the
    /// stream ID so one application context can keep independent per-stream
    /// parsers/checksums while DATA frames arrive round-robin. Initial headers
    /// and trailers are owned by each `StreamingRequest`; DATA remains borrowed
    /// for the callback duration. Traditional CONNECT is intentionally rejected
    /// because a completed request batch cannot represent tunnel lifetime.
    pub fn readRequestBatchStreamingInto(
        self: *Connection,
        requests: []StreamingRequest,
        context: anytype,
        comptime consume: anytype,
    ) !void {
        if (self.role != .server) return error.UnexpectedFrame;
        if (requests.len == 0) return;

        var expected_stack: [16]?usize = undefined;
        var done_stack: [16]bool = undefined;
        const expected = if (requests.len <= expected_stack.len)
            expected_stack[0..requests.len]
        else
            try self.allocator.alloc(?usize, requests.len);
        defer if (expected.ptr != expected_stack[0..].ptr) {
            self.allocator.free(expected);
        };
        const done = if (requests.len <= done_stack.len)
            done_stack[0..requests.len]
        else
            try self.allocator.alloc(bool, requests.len);
        defer if (done.ptr != done_stack[0..].ptr) {
            self.allocator.free(done);
        };
        @memset(done, false);

        var initialized: usize = 0;
        var completed: usize = 0;
        errdefer {
            for (requests[0..initialized]) |*streaming_request| {
                // Every request still owns an open response half even when its
                // inbound DATA already ended. Cancel the whole batch so a
                // callback/framing failure cannot strand clients waiting for
                // responses that this API will never produce.
                self.writeResetStreamFrame(
                    streaming_request.stream_id,
                    .cancel,
                ) catch {};
                self.releasePeerStream(streaming_request.stream_id);
                streaming_request.deinit(self.allocator);
            }
        }

        while (completed < requests.len) {
            const frame = try self.readFrameScratch();
            if (try self.handleConnectionFrame(frame)) continue;
            if (frame.header.frame_type == .goaway) {
                try self.recordPeerGoAway(
                    try http2.GoAwayPayload.parse(frame),
                );
                return error.ConnectionGoAway;
            }

            switch (frame.header.frame_type) {
                .headers => {
                    if (findStreamingRequestIndex(
                        requests[0..initialized],
                        frame.header.stream_id,
                    )) |index| {
                        if (done[index] or
                            (frame.header.flags & flag_end_stream) == 0)
                        {
                            return error.UnexpectedFrame;
                        }
                        requests[index].trailers =
                            try self.readHeaderBlock(frame);
                        var trailers_owned = true;
                        errdefer if (trailers_owned) {
                            freeHeaders(
                                self.allocator,
                                requests[index].trailers,
                            );
                            requests[index].trailers = &.{};
                        };
                        try validateHeaderBlock(
                            requests[index].trailers,
                            .request_trailers,
                        );
                        try self.finishBatchStreamingRequest(
                            &requests[index],
                            expected[index],
                        );
                        done[index] = true;
                        completed += 1;
                        trailers_owned = false;
                        continue;
                    }

                    if (initialized == requests.len) {
                        return error.UnexpectedFrame;
                    }
                    const stream_id = frame.header.stream_id;
                    if (!clientInitiatedStreamId(stream_id) or
                        stream_id <= self.last_peer_client_stream_id)
                    {
                        return error.InvalidFrame;
                    }
                    try self.reservePeerStream(stream_id);
                    var stream_reserved = true;
                    errdefer if (stream_reserved) {
                        self.releasePeerStream(stream_id);
                    };
                    self.last_peer_client_stream_id = stream_id;

                    const headers = try self.readHeaderBlock(frame);
                    var headers_owned = true;
                    errdefer if (headers_owned) {
                        freeHeaders(self.allocator, headers);
                    };
                    try validateHeaderBlock(headers, .request);
                    const lookup = try requestHeaderLookup(headers);
                    const method = lookup.method orelse
                        return error.MissingPseudoHeader;
                    if (methodIsConnect(method)) return error.InvalidHeader;
                    if (lookup.protocol != null) {
                        return error.InvalidHeader;
                    }
                    if ((lookup.content_length orelse 0) >
                        self.limits.max_body_bytes)
                    {
                        return error.MessageTooLarge;
                    }

                    const index = initialized;
                    const request_priority =
                        self.effectiveRequestPriority(
                            stream_id,
                            lookup.priority,
                        );
                    requests[index] = .{
                        .stream_id = stream_id,
                        .headers = headers,
                        .method = method,
                        .path = lookup.path orelse "",
                        .scheme = lookup.scheme orelse "",
                        .authority = lookup.requestAuthority(),
                        .body_bytes = 0,
                        .priority = request_priority,
                    };
                    expected[index] = lookup.content_length;
                    initialized += 1;
                    headers_owned = false;
                    stream_reserved = false;
                    if ((frame.header.flags & flag_end_stream) != 0) {
                        try self.finishBatchStreamingRequest(
                            &requests[index],
                            expected[index],
                        );
                        done[index] = true;
                        completed += 1;
                    }
                },
                .data => {
                    const index = findStreamingRequestIndex(
                        requests[0..initialized],
                        frame.header.stream_id,
                    ) orelse return error.UnexpectedFrame;
                    if (done[index]) return error.UnexpectedFrame;
                    const data = try self.receiveDataPayload(
                        frame.header.stream_id,
                        frame,
                    );
                    requests[index].body_bytes = std.math.add(
                        usize,
                        requests[index].body_bytes,
                        data.data.len,
                    ) catch return error.MessageTooLarge;
                    if (requests[index].body_bytes >
                        self.limits.max_body_bytes)
                    {
                        return error.MessageTooLarge;
                    }
                    if (data.data.len != 0) {
                        consume(
                            context,
                            frame.header.stream_id,
                            data.data,
                        ) catch |err| {
                            self.releaseReceivedCapacity(
                                frame.header.stream_id,
                                frame.payload.len,
                            ) catch {};
                            return err;
                        };
                    }
                    try self.maybeReleaseReceivedCapacity(
                        frame.header.stream_id,
                    );
                    if ((frame.header.flags & flag_end_stream) != 0) {
                        try self.finishBatchStreamingRequest(
                            &requests[index],
                            expected[index],
                        );
                        done[index] = true;
                        completed += 1;
                    }
                },
                .rst_stream => return error.StreamReset,
                else => return error.UnexpectedFrame,
            }
        }
    }

    fn finishBatchStreamingRequest(
        self: *Connection,
        streaming_request: *StreamingRequest,
        expected_length: ?usize,
    ) Error!void {
        try validateExpectedContentLength(
            expected_length,
            streaming_request.body_bytes,
        );
        try self.rememberResponseSemantics(
            streaming_request.stream_id,
            streaming_request.method,
            streaming_request.protocol,
            streaming_request.priority,
        );
    }

    fn findStreamingRequestIndex(
        requests: []const StreamingRequest,
        stream_id: u31,
    ) ?usize {
        for (requests, 0..) |streaming_request, index| {
            if (streaming_request.stream_id == stream_id) return index;
        }
        return null;
    }

    fn readFrameScratch(self: *Connection) Error!http2.Frame {
        return (try self.readBufferedFrame()).frame;
    }

    fn readBufferedFrame(self: *Connection) Error!frame_io.BorrowedFrame {
        const borrowed = try self.frame_reader.read(
            self.allocator,
            self.io,
            self.stream,
            @min(
                self.limits.max_frame_payload,
                self.limits.max_frame_size,
            ),
        );
        try validateFrameEnvelope(borrowed.frame);
        return borrowed;
    }

    fn readOwnedFrame(self: *Connection) Error!OwnedFrame {
        if (self.pending_client_frame) |frame| {
            self.pending_client_frame = null;
            return frame;
        }
        const borrowed = try self.readBufferedFrame();
        const bytes = try self.allocator.dupe(u8, borrowed.bytes);
        errdefer self.allocator.free(bytes);
        return .{
            .bytes = bytes,
            .frame = try http2.Frame.parse(bytes),
        };
    }

    fn popPendingRequest(self: *Connection) ?OwnedRequest {
        if (self.pending_request_head >= self.pending_requests.items.len) return null;
        const pending = self.pending_requests.items[self.pending_request_head];
        self.pending_request_head += 1;
        self.compactPendingRequestsIfSparse();
        return pending;
    }

    const RequestBodyFrame = union(enum) {
        direct_data: bool,
        owned_frame: OwnedFrame,
    };

    /// Read ordinary, unpadded DATA directly into the aggregate request body.
    ///
    /// The general frame reader must allocate an owning frame because callers
    /// may retain its payload. Request aggregation immediately copies DATA into
    /// the final body, so reading there directly avoids one allocation and one
    /// payload copy per frame. Padded DATA and all control/header frames retain
    /// the fully validated owning fallback.
    fn readRequestBodyFrame(
        self: *Connection,
        stream_id: u31,
        body: *std.ArrayList(u8),
    ) Error!RequestBodyFrame {
        const borrowed = try self.readBufferedFrame();
        const header = borrowed.frame.header;
        const is_direct_data = header.frame_type == .data and
            header.stream_id == stream_id and (header.flags & 0x8) == 0;
        if (!is_direct_data) {
            const bytes = try self.allocator.dupe(u8, borrowed.bytes);
            errdefer self.allocator.free(bytes);
            const frame = try http2.Frame.parse(bytes);
            return .{ .owned_frame = .{
                .bytes = bytes,
                .frame = frame,
            } };
        }

        const old_len = body.items.len;
        const new_len = std.math.add(
            usize,
            old_len,
            borrowed.frame.payload.len,
        ) catch return error.MessageTooLarge;
        if (new_len > self.limits.max_body_bytes) {
            return error.MessageTooLarge;
        }
        try body.appendSlice(self.allocator, borrowed.frame.payload);
        const frame = http2.Frame{
            .header = header,
            .payload = body.items[old_len..new_len],
        };
        _ = try self.receiveDataPayload(stream_id, frame);
        try self.maybeReleaseReceivedCapacity(stream_id);
        return .{
            .direct_data = (header.flags & flag_end_stream) != 0,
        };
    }

    fn queueCompletePeerRequestFrame(self: *Connection, frame: http2.Frame) Error!bool {
        if (frame.header.frame_type != .headers) return false;
        if ((frame.header.flags & flag_end_stream) == 0) return false;
        const stream_id = frame.header.stream_id;
        if (!clientInitiatedStreamId(stream_id)) return error.InvalidFrame;
        if (stream_id <= self.last_peer_client_stream_id) return error.InvalidFrame;
        try self.reservePeerStream(stream_id);
        errdefer self.releasePeerStream(stream_id);
        self.last_peer_client_stream_id = stream_id;

        const headers = try self.readHeaderBlock(frame);
        errdefer freeHeaders(self.allocator, headers);
        try validateHeaderBlock(headers, .request);
        const empty_body = try self.allocator.alloc(u8, 0);
        var body_owned_by_request = false;
        errdefer if (!body_owned_by_request) self.allocator.free(empty_body);
        const queued_request = try self.requestFromHeadersAndBody(stream_id, headers, empty_body, &.{});
        body_owned_by_request = true;
        errdefer {
            var owned = queued_request;
            owned.deinit(self.allocator);
        }
        if (self.pending_request_head != 0 and
            self.pending_requests.items.len == self.pending_requests.capacity)
        {
            self.compactPendingRequests();
        }
        try self.pending_requests.append(self.allocator, queued_request);
        return true;
    }

    fn pendingRequestCount(self: *const Connection) usize {
        return self.pending_requests.items.len - self.pending_request_head;
    }

    fn compactPendingRequestsIfSparse(self: *Connection) void {
        if (self.pending_request_head == 0) return;
        if (self.pending_request_head == self.pending_requests.items.len or
            self.pending_request_head >= self.pending_requests.items.len / 2)
        {
            self.compactPendingRequests();
        }
    }

    fn compactPendingRequests(self: *Connection) void {
        if (self.pending_request_head == 0) return;
        const remaining = self.pendingRequestCount();
        if (remaining != 0) {
            @memmove(
                self.pending_requests.items[0..remaining],
                self.pending_requests.items[self.pending_request_head..],
            );
        }
        self.pending_requests.items.len = remaining;
        self.pending_request_head = 0;
    }

    fn requestFromHeadersAndBody(
        self: *Connection,
        stream_id: u31,
        headers: []http2.Hpack.HeaderField,
        body: []u8,
        trailers: []http2.Hpack.HeaderField,
    ) Error!OwnedRequest {
        const lookup = try requestHeaderLookup(headers);
        const method = lookup.method orelse return error.MissingPseudoHeader;
        const protocol = lookup.protocol;
        if (protocol != null and !self.limits.enable_connect_protocol) return error.ExtendedConnectDisabled;
        const expected_request_len = lookup.content_length;
        const is_connect = methodIsConnect(method);
        const is_extended_connect = is_connect and protocol != null;
        if (is_connect and !is_extended_connect and (expected_request_len orelse 0) != 0) return error.InvalidContentLength;
        try validateExpectedContentLength(lookup.content_length, body.len);
        const request_priority = self.effectiveRequestPriority(
            stream_id,
            lookup.priority,
        );
        try self.rememberResponseSemantics(
            stream_id,
            method,
            protocol,
            request_priority,
        );
        return .{
            .stream_id = stream_id,
            .headers = headers,
            .method = method,
            .path = lookup.path orelse "",
            .scheme = lookup.scheme orelse "",
            .authority = lookup.requestAuthority(),
            .protocol = protocol,
            .body = body,
            .trailers = trailers,
            .priority = request_priority,
        };
    }

    pub fn writeResponse(self: *Connection, stream_id: u31, options: ResponseOptions) Error!void {
        if (self.role != .server) return error.UnexpectedFrame;
        var status_buf: [3]u8 = undefined;
        if (options.status < 100 or options.status > 999) return error.InvalidStatus;
        if (statusIsInformational(options.status)) return error.InvalidStatus;
        const semantics = self.responseSemanticsFor(stream_id, options);
        const suppress_body = responseWriteSuppressesBodySemantics(options.status, semantics);
        const status = std.fmt.bufPrint(&status_buf, "{}", .{options.status}) catch return error.InvalidStatus;

        var fields_stack: [16]http2.Hpack.HeaderField = undefined;
        const fields_capacity = std.math.add(
            usize,
            options.headers.len,
            2,
        ) catch return error.MessageTooLarge;
        const fields_buffer = if (fields_capacity <= fields_stack.len)
            fields_stack[0..fields_capacity]
        else
            try self.allocator.alloc(
                http2.Hpack.HeaderField,
                fields_capacity,
            );
        defer if (fields_buffer.ptr != fields_stack[0..].ptr) {
            self.allocator.free(fields_buffer);
        };
        var fields: std.ArrayList(http2.Hpack.HeaderField) =
            .initBuffer(fields_buffer);
        var content_length_buf: [32]u8 = undefined;
        fields.appendAssumeCapacity(.{
            .name = ":status",
            .value = status,
        });
        fields.appendSliceAssumeCapacity(options.headers);
        stripConnectionHeaders(&fields, .response);
        if (semantics.traditional_connect and options.status >= 200 and options.status < 300) {
            try stripSuccessfulConnectContentLength(&fields);
        }
        const declared_response_length = try contentLength(fields.items);
        try validateResponseBodyForStatusWithLength(options.status, declared_response_length, options.body, options.trailers);
        try validateResponseBodyForRequestSemanticsWithLength(options.status, semantics, declared_response_length, options.body, options.trailers);
        try validateDeclaredResponseLengthValue(options.status, semantics, declared_response_length, options.body.len);
        if (responseShouldDefaultContentLengthValue(options.status, semantics, declared_response_length, options.body.len)) {
            const content_length = std.fmt.bufPrint(&content_length_buf, "{}", .{options.body.len}) catch unreachable;
            fields.appendAssumeCapacity(.{
                .name = "content-length",
                .value = content_length,
            });
        }
        try validateHeaderBlock(fields.items, .response);
        try validateHeaderBlock(options.trailers, .response_trailers);
        if (!suppress_body and
            options.body.len != 0 and
            options.trailers.len == 0)
        {
            try self.writeHeadersThenData(
                stream_id,
                fields.items,
                options.body,
                true,
            );
        } else {
            try self.writeHeaders(
                stream_id,
                fields.items,
                suppress_body or
                    (options.body.len == 0 and options.trailers.len == 0),
            );
        }
        if (!suppress_body) {
            if (options.body.len != 0 and options.trailers.len != 0) {
                try self.writeData(stream_id, options.body, false);
            }
            if (options.trailers.len != 0) try self.writeHeaders(stream_id, options.trailers, true);
        }
        self.releasePeerStream(stream_id);
    }

    /// Start a response whose DATA is supplied incrementally.
    ///
    /// Unlike `writeResponse`, this sends only the final response HEADERS and
    /// returns a stateful writer. The writer enforces the declared
    /// Content-Length across calls, applies HTTP body-forbidden semantics, and
    /// releases the request stream only after DATA FIN, trailers, or reset.
    pub fn startResponse(
        self: *Connection,
        stream_id: u31,
        options: StreamingResponseOptions,
    ) Error!ResponseWriter {
        if (self.role != .server) return error.UnexpectedFrame;
        if (!self.outboundStreamIsActive(stream_id)) {
            return error.InvalidStreamId;
        }
        if (options.status < 100 or options.status > 999 or
            statusIsInformational(options.status))
        {
            return error.InvalidStatus;
        }
        const semantics = self.responseSemanticsFor(stream_id, .{
            .status = options.status,
            .request_method = options.request_method,
            .extended_connect = options.extended_connect,
        });
        const suppress_body =
            responseWriteSuppressesBodySemantics(options.status, semantics);
        var status_buffer: [3]u8 = undefined;
        const status = std.fmt.bufPrint(
            &status_buffer,
            "{}",
            .{options.status},
        ) catch return error.InvalidStatus;

        var fields_stack: [16]http2.Hpack.HeaderField = undefined;
        const fields_capacity = std.math.add(
            usize,
            options.headers.len,
            2,
        ) catch return error.MessageTooLarge;
        const fields_buffer = if (fields_capacity <= fields_stack.len)
            fields_stack[0..fields_capacity]
        else
            try self.allocator.alloc(
                http2.Hpack.HeaderField,
                fields_capacity,
            );
        defer if (fields_buffer.ptr != fields_stack[0..].ptr) {
            self.allocator.free(fields_buffer);
        };
        var fields: std.ArrayList(http2.Hpack.HeaderField) =
            .initBuffer(fields_buffer);
        fields.appendAssumeCapacity(.{
            .name = ":status",
            .value = status,
        });
        fields.appendSliceAssumeCapacity(options.headers);
        stripConnectionHeaders(&fields, .response);
        if (semantics.traditional_connect and
            options.status >= 200 and options.status < 300)
        {
            try stripSuccessfulConnectContentLength(&fields);
        }
        const declared_length = try contentLength(fields.items);
        if ((statusIsInformational(options.status) or
            options.status == 204) and declared_length != null)
        {
            return error.InvalidContentLength;
        }
        if (semantics.traditional_connect and
            options.status >= 200 and options.status < 300 and
            (declared_length orelse 0) != 0)
        {
            return error.InvalidContentLength;
        }
        try validateHeaderBlock(fields.items, .response);

        // HEAD/204/304 and successful traditional CONNECT end at HEADERS.
        // An ordinary zero-length response stays open so the writer may choose
        // either an empty END_STREAM DATA frame or response trailers.
        const ends_at_headers = suppress_body;
        self.writeHeaders(
            stream_id,
            fields.items,
            ends_at_headers,
        ) catch |err| {
            // HPACK state has already advanced once the block is encoded.
            // Callers cannot safely retry `startResponse` on this connection
            // after a transport write failure, so release the stream rather
            // than leaving a half-started writer hidden in connection state.
            self.releasePeerStream(stream_id);
            return err;
        };
        if (ends_at_headers) self.releasePeerStream(stream_id);
        return .{
            .connection = self,
            .stream_id = stream_id,
            .expected_length = declared_length,
            .finished = ends_at_headers,
        };
    }

    /// Validate, HPACK-encode, and submit bodyless responses as one TCP write.
    ///
    /// This is the server counterpart to `requestBatchInto`: the logical HTTP/2
    /// frames remain separate and ordered, while one syscall avoids creating a
    /// train of tiny TCP segments. Every stream must already be active. On
    /// success the streams are released; on validation/encoding failure no
    /// bytes are written and the caller can close or retry the connection.
    pub fn writeResponseBatch(
        self: *Connection,
        stream_ids: []const u31,
        responses: []const ResponseOptions,
    ) Error!void {
        if (self.role != .server) return error.UnexpectedFrame;
        if (stream_ids.len != responses.len) return error.InvalidResponse;
        if (stream_ids.len == 0) return;
        for (stream_ids, 0..) |stream_id, index| {
            if (!self.outboundStreamIsActive(stream_id)) {
                return error.InvalidStreamId;
            }
            for (stream_ids[0..index]) |prior| {
                if (prior == stream_id) return error.InvalidStreamId;
            }
        }

        const batch = &self.write_batch;
        batch.clearRetainingCapacity();
        var staged_encoder = try self.hpack_encoder.clone(self.allocator);
        var staged_encoder_owned = true;
        defer if (staged_encoder_owned) {
            staged_encoder.deinit(self.allocator);
        };
        for (stream_ids, responses) |stream_id, options| {
            if (options.body.len != 0 or options.trailers.len != 0) {
                return error.InvalidContentLength;
            }
            if (options.status < 100 or options.status > 999 or
                statusIsInformational(options.status))
            {
                return error.InvalidStatus;
            }

            var status_buf: [3]u8 = undefined;
            const status = std.fmt.bufPrint(
                &status_buf,
                "{}",
                .{options.status},
            ) catch return error.InvalidStatus;
            const semantics = self.responseSemanticsFor(stream_id, options);

            var fields_stack: [16]http2.Hpack.HeaderField = undefined;
            const fields_capacity = std.math.add(
                usize,
                options.headers.len,
                1,
            ) catch return error.MessageTooLarge;
            const fields_buffer = if (fields_capacity <= fields_stack.len)
                fields_stack[0..fields_capacity]
            else
                try self.allocator.alloc(
                    http2.Hpack.HeaderField,
                    fields_capacity,
                );
            defer if (fields_buffer.ptr != fields_stack[0..].ptr) {
                self.allocator.free(fields_buffer);
            };
            var fields: std.ArrayList(http2.Hpack.HeaderField) =
                .initBuffer(fields_buffer);
            fields.appendAssumeCapacity(.{
                .name = ":status",
                .value = status,
            });
            fields.appendSliceAssumeCapacity(options.headers);
            stripConnectionHeaders(&fields, .response);
            if (semantics.traditional_connect and
                options.status >= 200 and options.status < 300)
            {
                try stripSuccessfulConnectContentLength(&fields);
            }
            const declared_length = try contentLength(fields.items);
            try validateResponseBodyForStatusWithLength(
                options.status,
                declared_length,
                &.{},
                &.{},
            );
            try validateResponseBodyForRequestSemanticsWithLength(
                options.status,
                semantics,
                declared_length,
                &.{},
                &.{},
            );
            try validateDeclaredResponseLengthValue(
                options.status,
                semantics,
                declared_length,
                0,
            );
            try validateHeaderBlock(fields.items, .response);
            try validateHeaderListSize(
                fields.items,
                self.peer_max_header_list_size,
            );

            const block = try staged_encoder.encodeBlockRetained(
                self.allocator,
                fields.items,
            );
            try appendHeaderBlockBytes(
                batch,
                self.allocator,
                stream_id,
                block,
                true,
                self.outboundFramePayloadLimit(),
            );
        }

        try writeAll(self.io, self.stream, batch.items);
        self.hpack_encoder.deinit(self.allocator);
        self.hpack_encoder = staged_encoder;
        staged_encoder_owned = false;
        for (stream_ids) |stream_id| self.releasePeerStream(stream_id);
    }

    /// Send complete response bodies round-robin with flow-control backpressure.
    ///
    /// HEADERS are HPACK-staged transactionally, body slices stay borrowed, and
    /// `body_chunk_size` controls each stream's contribution per round. The
    /// method rejects trailers and body-suppressed response semantics because
    /// those require a different completion lifecycle. DATA consumes only
    /// currently available connection/per-stream credit; when every unfinished
    /// stream is blocked, the connection pumps WINDOW_UPDATE and cancellation
    /// frames before resuming. Validation, encoding, and allocation errors
    /// happen before wire I/O and are retryable. A transport or protocol error
    /// after submission begins may leave a partial response set on the wire;
    /// close the connection instead of retrying that batch.
    pub fn writeResponseBodyBatch(
        self: *Connection,
        stream_ids: []const u31,
        responses: []const ResponseOptions,
        body_chunk_size: usize,
    ) Error!void {
        if (self.role != .server) return error.UnexpectedFrame;
        if (stream_ids.len != responses.len) return error.InvalidResponse;
        if (stream_ids.len == 0) return;
        if (body_chunk_size == 0) return error.InvalidFrameSize;

        for (stream_ids, responses, 0..) |stream_id, options, index| {
            if (!self.outboundStreamIsActive(stream_id)) {
                return error.InvalidStreamId;
            }
            for (stream_ids[0..index]) |prior| {
                if (prior == stream_id) return error.InvalidStreamId;
            }
            if (options.trailers.len != 0) {
                return error.InvalidContentLength;
            }
            const semantics = self.responseSemanticsFor(stream_id, options);
            if (responseWriteSuppressesBodySemantics(
                options.status,
                semantics,
            )) {
                return error.InvalidContentLength;
            }
        }

        var views_stack: [16]BatchDataView = undefined;
        const views = if (responses.len <= views_stack.len)
            views_stack[0..responses.len]
        else
            try self.allocator.alloc(BatchDataView, responses.len);
        defer if (views.ptr != views_stack[0..].ptr) {
            self.allocator.free(views);
        };
        var offsets_stack: [16]usize = undefined;
        const offsets = if (responses.len <= offsets_stack.len)
            offsets_stack[0..responses.len]
        else
            try self.allocator.alloc(usize, responses.len);
        defer if (offsets.ptr != offsets_stack[0..].ptr) {
            self.allocator.free(offsets);
        };
        @memset(offsets, 0);
        var round_reserved_stack: [16]usize = undefined;
        const round_reserved =
            if (responses.len <= round_reserved_stack.len)
                round_reserved_stack[0..responses.len]
            else
                try self.allocator.alloc(usize, responses.len);
        defer if (round_reserved.ptr != round_reserved_stack[0..].ptr) {
            self.allocator.free(round_reserved);
        };
        var candidates_stack: [16]response_scheduler.Candidate =
            undefined;
        const candidates = if (responses.len <= candidates_stack.len)
            candidates_stack[0..responses.len]
        else
            try self.allocator.alloc(
                response_scheduler.Candidate,
                responses.len,
            );
        defer if (candidates.ptr != candidates_stack[0..].ptr) {
            self.allocator.free(candidates);
        };
        for (views, stream_ids, responses) |*view, stream_id, response| {
            view.* = .{ .stream_id = stream_id, .body = response.body };
        }
        try self.prepareBodyBatchData(views, body_chunk_size);

        // Materialize stream windows before HEADERS are visible so DATA
        // scheduling cannot fail with a local allocation after wire commit.
        for (stream_ids) |stream_id| {
            _ = try self.sendStreamWindow(stream_id);
        }

        const batch = &self.write_batch;
        batch.clearRetainingCapacity();
        var staged_encoder = try self.hpack_encoder.clone(self.allocator);
        var staged_encoder_owned = true;
        defer if (staged_encoder_owned) {
            staged_encoder.deinit(self.allocator);
        };
        for (stream_ids, responses) |stream_id, options| {
            try self.appendResponseHeadToBatch(
                stream_id,
                options,
                batch,
                &staged_encoder,
            );
        }

        writeAll(self.io, self.stream, batch.items) catch |err| {
            // A transport failure may expose only a prefix of the staged HPACK
            // sequence. It cannot be retried or rolled back; commit encoder
            // state so accidental connection reuse fails closed.
            self.hpack_encoder.deinit(self.allocator);
            self.hpack_encoder = staged_encoder;
            staged_encoder_owned = false;
            return err;
        };
        self.hpack_encoder.deinit(self.allocator);
        self.hpack_encoder = staged_encoder;
        staged_encoder_owned = false;
        try self.writeResponseBodyBatchData(
            views,
            offsets,
            round_reserved,
            candidates,
            body_chunk_size,
        );
        for (stream_ids) |stream_id| self.releasePeerStream(stream_id);
    }

    fn writeResponseBodyBatchData(
        self: *Connection,
        views: []const BatchDataView,
        offsets: []usize,
        round_reserved: []usize,
        candidates: []response_scheduler.Candidate,
        application_chunk_size: usize,
    ) Error!void {
        std.debug.assert(views.len == offsets.len);
        std.debug.assert(views.len == round_reserved.len);
        std.debug.assert(views.len == candidates.len);
        const frame_limit = self.outboundFramePayloadLimit();
        var remaining_streams = views.len;
        for (views) |view| {
            if (view.body.len == 0) remaining_streams -= 1;
        }
        var next_stream: usize = 0;

        while (remaining_streams != 0) {
            self.batch_data_headers.clearRetainingCapacity();
            self.batch_data_parts.clearRetainingCapacity();
            @memset(round_reserved, 0);
            var made_progress = false;
            var reserved_connection_bytes: usize = 0;
            var wire_write_started = false;
            errdefer if (!wire_write_started) {
                // Before the wide write starts, every reserved byte can be
                // restored exactly. The successful write clears these counts;
                // any transport error thereafter retains conservative credit
                // because the emitted prefix is unknowable.
                self.send_connection_window.update(
                    @intCast(reserved_connection_bytes),
                ) catch unreachable;
                for (views, round_reserved) |rollback_view, bytes| {
                    if (bytes == 0) continue;
                    (self.sendStreamWindow(
                        rollback_view.stream_id,
                    ) catch unreachable).update(
                        @intCast(bytes),
                    ) catch unreachable;
                }
            };
            const pass_start = next_stream;
            const priority_selection =
                if (self.limits.no_rfc7540_priorities)
                    self.responseBatchSelection(
                        views,
                        offsets,
                        candidates,
                    )
                else
                    null;
            var scanned: usize = 0;
            while (scanned < views.len) : (scanned += 1) {
                const index = (pass_start + scanned) % views.len;
                const view = views[index];
                const offset = &offsets[index];
                if (offset.* == view.body.len) continue;
                if (self.send_connection_window.available() == 0) break;
                if (self.limits.no_rfc7540_priorities) {
                    const selection = priority_selection orelse break;
                    if (!selection.includes(candidates, index)) continue;
                }

                const stream_window = try self.sendStreamWindow(
                    view.stream_id,
                );
                const contribution_len = @min(
                    application_chunk_size,
                    view.body.len - offset.*,
                    self.send_connection_window.available(),
                    stream_window.available(),
                );
                if (contribution_len == 0) continue;

                try self.appendResponseBatchContribution(
                    view,
                    offset,
                    contribution_len,
                    frame_limit,
                    stream_window,
                );
                reserved_connection_bytes += contribution_len;
                round_reserved[index] = contribution_len;
                if (offset.* == view.body.len) remaining_streams -= 1;
                made_progress = true;
                if (!self.limits.no_rfc7540_priorities or
                    candidates[index].priority.incremental)
                {
                    // Rotate default and incremental traffic. A small
                    // connection WINDOW_UPDATE therefore cannot repeatedly
                    // feed one stream while equal peers starve.
                    next_stream = (index + 1) % views.len;
                }
            }

            if (made_progress) {
                // A partial wide write consumes an unknown prefix of reserved
                // credit. Keep the conservative reservation and require the
                // caller to close rather than retry this response batch.
                wire_write_started = true;
                try stream_io.writeAllSlicesWide(
                    self.io,
                    self.stream,
                    self.batch_data_parts.items,
                );
                continue;
            }
            try self.waitForResponseBatchCapacity(views, offsets);
        }
    }

    fn appendResponseBatchContribution(
        self: *Connection,
        view: BatchDataView,
        offset: *usize,
        contribution_len: usize,
        frame_limit: usize,
        stream_window: *FlowWindow,
    ) Error!void {
        try self.send_connection_window.reserve(contribution_len);
        errdefer self.send_connection_window.update(
            @intCast(contribution_len),
        ) catch unreachable;
        try stream_window.reserve(contribution_len);
        errdefer stream_window.update(
            @intCast(contribution_len),
        ) catch unreachable;

        const contribution_end = offset.* + contribution_len;
        while (offset.* < contribution_end) {
            const end = @min(
                contribution_end,
                offset.* + frame_limit,
            );
            const header_index = self.batch_data_headers.items.len;
            self.batch_data_headers.appendAssumeCapacity(undefined);
            try encodeFrameHeader(
                &self.batch_data_headers.items[header_index],
                .data,
                if (end == view.body.len) flag_end_stream else 0,
                view.stream_id,
                end - offset.*,
            );
            self.batch_data_parts.appendAssumeCapacity(
                &self.batch_data_headers.items[header_index],
            );
            self.batch_data_parts.appendAssumeCapacity(
                view.body[offset.*..end],
            );
            offset.* = end;
        }
    }

    fn waitForResponseBatchCapacity(
        self: *Connection,
        views: []const BatchDataView,
        offsets: []const usize,
    ) Error!void {
        std.debug.assert(views.len == offsets.len);
        while (!self.responseBatchHasSendCapacity(views, offsets)) {
            // The server-side flow pump consumes every accepted control frame
            // before reading another one, so it can borrow frame-reader storage
            // instead of allocating an OwnedFrame for each WINDOW_UPDATE.
            const frame = try self.readFrameScratch();
            if (try self.handleConnectionFrame(frame)) continue;
            switch (frame.header.frame_type) {
                .goaway => {
                    try self.recordPeerGoAway(
                        try http2.GoAwayPayload.parse(frame),
                    );
                    return error.ConnectionGoAway;
                },
                .rst_stream => {
                    const reset =
                        try http2.ResetStreamPayload.parse(frame);
                    if (findBatchDataViewIndex(
                        views,
                        reset.stream_id,
                    ) != null) {
                        self.recordResetStream(reset);
                        return error.StreamReset;
                    }
                    return error.UnexpectedFrame;
                },
                else => return error.UnexpectedFrame,
            }
        }
    }

    fn responseBatchHasSendCapacity(
        self: *const Connection,
        views: []const BatchDataView,
        offsets: []const usize,
    ) bool {
        if (self.send_connection_window.available() == 0) return false;
        for (views, offsets) |view, offset| {
            if (offset < view.body.len and
                self.sendStreamWindowAvailable(view.stream_id) != 0)
            {
                return true;
            }
        }
        return false;
    }

    fn findBatchDataViewIndex(
        views: []const BatchDataView,
        stream_id: u31,
    ) ?usize {
        for (views, 0..) |view, index| {
            if (view.stream_id == stream_id) return index;
        }
        return null;
    }

    fn appendResponseHeadToBatch(
        self: *Connection,
        stream_id: u31,
        options: ResponseOptions,
        batch: *std.ArrayList(u8),
        encoder: *http2.Hpack.Encoder,
    ) Error!void {
        if (options.status < 100 or options.status > 999 or
            statusIsInformational(options.status))
        {
            return error.InvalidStatus;
        }
        var status_buf: [3]u8 = undefined;
        const status = std.fmt.bufPrint(
            &status_buf,
            "{}",
            .{options.status},
        ) catch return error.InvalidStatus;
        const semantics = self.responseSemanticsFor(stream_id, options);

        var fields_stack: [16]http2.Hpack.HeaderField = undefined;
        const fields_capacity = std.math.add(
            usize,
            options.headers.len,
            2,
        ) catch return error.MessageTooLarge;
        const fields_buffer = if (fields_capacity <= fields_stack.len)
            fields_stack[0..fields_capacity]
        else
            try self.allocator.alloc(
                http2.Hpack.HeaderField,
                fields_capacity,
            );
        defer if (fields_buffer.ptr != fields_stack[0..].ptr) {
            self.allocator.free(fields_buffer);
        };
        var fields: std.ArrayList(http2.Hpack.HeaderField) =
            .initBuffer(fields_buffer);
        fields.appendAssumeCapacity(.{
            .name = ":status",
            .value = status,
        });
        fields.appendSliceAssumeCapacity(options.headers);
        stripConnectionHeaders(&fields, .response);
        const declared_length = try contentLength(fields.items);
        try validateResponseBodyForStatusWithLength(
            options.status,
            declared_length,
            options.body,
            &.{},
        );
        try validateResponseBodyForRequestSemanticsWithLength(
            options.status,
            semantics,
            declared_length,
            options.body,
            &.{},
        );
        try validateDeclaredResponseLengthValue(
            options.status,
            semantics,
            declared_length,
            options.body.len,
        );
        if (responseShouldDefaultContentLengthValue(
            options.status,
            semantics,
            declared_length,
            options.body.len,
        )) {
            var content_length_buf: [32]u8 = undefined;
            const value = std.fmt.bufPrint(
                &content_length_buf,
                "{}",
                .{options.body.len},
            ) catch unreachable;
            fields.appendAssumeCapacity(.{
                .name = "content-length",
                .value = value,
            });
        }
        try validateHeaderBlock(fields.items, .response);
        try validateHeaderListSize(
            fields.items,
            self.peer_max_header_list_size,
        );
        const block = try encoder.encodeBlockRetained(
            self.allocator,
            fields.items,
        );
        try appendHeaderBlockBytes(
            batch,
            self.allocator,
            stream_id,
            block,
            options.body.len == 0,
            self.outboundFramePayloadLimit(),
        );
    }

    pub fn promisePush(
        self: *Connection,
        parent_stream_id: u31,
        request_headers: []const http2.Hpack.HeaderField,
    ) Error!u31 {
        if (self.role != .server or !self.peerPushEnabled()) {
            return error.UnexpectedFrame;
        }
        if (!clientInitiatedStreamId(parent_stream_id) or
            !self.outboundStreamIsActive(parent_stream_id))
        {
            return error.InvalidStreamId;
        }
        try validateHeaderBlock(request_headers, .request);
        const promised_stream_id = try self.push_state.reserveLocal(
            self.allocator,
        );
        errdefer {
            _ = self.push_state.releaseLocal(promised_stream_id);
            self.forgetResponseSemantics(promised_stream_id);
        }
        try self.rememberResponseSemantics(
            promised_stream_id,
            findHeader(request_headers, ":method") orelse "GET",
            findHeader(request_headers, ":protocol"),
            http2.ExtensiblePriority.parse(
                findHeader(request_headers, "priority") orelse "",
            ),
        );
        var block: std.ArrayList(u8) = .empty;
        defer block.deinit(self.allocator);
        try self.hpack_encoder.encodeBlock(
            &block,
            self.allocator,
            request_headers,
        );
        try self.writePushPromiseBlock(
            parent_stream_id,
            promised_stream_id,
            block.items,
        );
        return promised_stream_id;
    }

    pub fn writePushedResponse(
        self: *Connection,
        promised_stream_id: u31,
        response: ResponseOptions,
    ) Error!void {
        if (self.role != .server) return error.UnexpectedFrame;
        const status = self.push_state.localStatus(
            promised_stream_id,
        ) orelse return error.InvalidStreamId;
        if (status == .canceled) {
            _ = self.push_state.releaseLocal(promised_stream_id);
            self.forgetResponseSemantics(promised_stream_id);
            _ = self.priority_state.remove(
                self.allocator,
                promised_stream_id,
            );
            return error.StreamReset;
        }
        var activated = false;
        errdefer if (activated) {
            self.releaseLocalStream(promised_stream_id);
        };
        if (!self.outboundStreamIsActive(promised_stream_id)) {
            if (self.peer_max_concurrent_streams) |limit| {
                if (self.active_local_streams.items.len >= limit) {
                    return error.FlowControlBlocked;
                }
            }
            try self.addActiveLocalStream(promised_stream_id);
            activated = true;
        }
        self.writeResponse(promised_stream_id, response) catch |err| {
            if (self.push_state.localStatus(promised_stream_id) ==
                .canceled)
            {
                _ = self.push_state.releaseLocal(
                    promised_stream_id,
                );
                self.forgetResponseSemantics(promised_stream_id);
            }
            return err;
        };
        self.releaseLocalStream(promised_stream_id);
        _ = self.push_state.releaseLocal(promised_stream_id);
        self.forgetResponseSemantics(promised_stream_id);
    }

    fn peerPushEnabled(self: Connection) bool {
        // Absence of SETTINGS_ENABLE_PUSH means enabled by default for clients.
        // We initialize this true on server connections and update it when
        // client SETTINGS arrive.
        return self.peer_enable_push;
    }

    pub fn serveOne(
        self: *Connection,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (*HandlerContext, OwnedRequest) Error!ResponseOptions,
    ) Error!u31 {
        var owned_request = try self.readRequest();
        const stream_id = owned_request.stream_id;
        defer owned_request.deinit(self.allocator);
        var response = try handler(context, owned_request);
        if (response.request_method == null) response.request_method = owned_request.method;
        response.extended_connect = owned_request.protocol != null;
        try self.writeResponse(stream_id, response);
        return stream_id;
    }

    pub fn serve(
        self: *Connection,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (*HandlerContext, OwnedRequest) Error!ResponseOptions,
        max_requests: usize,
    ) Error!usize {
        var served: usize = 0;
        var last_stream_id: u31 = 0;
        while (served < max_requests) : (served += 1) {
            last_stream_id = try self.serveOne(HandlerContext, context, handler);
        }
        try self.sendGoAway(last_stream_id, .no_error, "serve-complete");
        return served;
    }

    pub fn writeInformationalResponse(self: *Connection, stream_id: u31, status_code: u16, headers: []const http2.Hpack.HeaderField) Error!void {
        if (self.role != .server) return error.UnexpectedFrame;
        if (!statusIsInformational(status_code)) return error.InvalidStatus;
        var status_buf: [3]u8 = undefined;
        const status = std.fmt.bufPrint(&status_buf, "{}", .{status_code}) catch return error.InvalidStatus;
        var fields: std.ArrayList(http2.Hpack.HeaderField) = .empty;
        defer fields.deinit(self.allocator);
        try fields.append(self.allocator, .{ .name = ":status", .value = status });
        for (headers) |header| try fields.append(self.allocator, header);
        stripConnectionHeaders(&fields, .response);
        try validateResponseBodyForStatus(status_code, fields.items, &.{}, &.{});
        try validateHeaderBlock(fields.items, .response);
        // HTTP/2 informational responses never end the stream; the final
        // response HEADERS still owns END_STREAM/body/trailer semantics.  This
        // mirrors h2's send_informational path rather than abusing the final
        // writeResponse helper.
        try self.writeHeaders(stream_id, fields.items, false);
    }

    pub fn ping(self: *Connection, data: [8]u8) Error![8]u8 {
        try writeFrame(self.allocator, self.io, self.stream, .ping, 0, 0, &data);
        while (true) {
            var frame = try self.readOwnedFrame();
            defer frame.deinit(self.allocator);
            if (frame.frame.header.frame_type != .ping) {
                if (try self.handleConnectionOrGoAwayFrame(frame.frame)) continue;
                return error.UnexpectedFrame;
            }
            if ((frame.frame.header.flags & flag_ack) == 0) {
                const ping_payload = try http2.PingPayload.parse(frame.frame);
                try writeFrame(self.allocator, self.io, self.stream, .ping, flag_ack, 0, &ping_payload.data);
                continue;
            }
            const ack_payload = (try http2.PingPayload.parse(frame.frame)).data;
            // Rust h2 keeps outstanding user/shutdown PING payloads and only
            // completes the operation when the ACK echoes that exact opaque
            // value.  Unknown ACKs are legal on the wire, but treating them as
            // completion lets a stale peer ACK satisfy a newer health check.
            if (!std.mem.eql(u8, &ack_payload, &data)) continue;
            return ack_payload;
        }
    }

    pub fn readPing(self: *Connection) Error![8]u8 {
        while (true) {
            var frame = try self.readOwnedFrame();
            defer frame.deinit(self.allocator);
            if (frame.frame.header.frame_type != .ping) {
                if (try self.handleConnectionOrGoAwayFrame(frame.frame)) continue;
                return error.UnexpectedFrame;
            }
            const ping_payload = try http2.PingPayload.parse(frame.frame);
            if ((frame.frame.header.flags & flag_ack) != 0) continue;
            try writeFrame(self.allocator, self.io, self.stream, .ping, flag_ack, 0, &ping_payload.data);
            return ping_payload.data;
        }
    }

    pub fn sendGoAway(self: *Connection, last_stream_id: u31, error_code: http2.ErrorCode, debug_data: []const u8) Error!void {
        try self.validateLocalGoAway(last_stream_id);
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try http2.GoAwayPayload.write(&encoded, self.allocator, last_stream_id, error_code, debug_data);
        try writeAll(self.io, self.stream, encoded.items);
        self.local_goaway_last_stream_id = last_stream_id;
    }

    pub fn sendOrigins(
        self: *Connection,
        origins: []const []const u8,
    ) Error!void {
        if (self.role != .server) return error.UnexpectedFrame;
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try http2.OriginPayload.write(
            &encoded,
            self.allocator,
            origins,
        );
        try writeAll(self.io, self.stream, encoded.items);
    }

    pub fn sendAlternativeService(
        self: *Connection,
        stream_id: u31,
        origin: []const u8,
        field_value: []const u8,
    ) Error!void {
        if (self.role != .server) return error.UnexpectedFrame;
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try http2.AltSvcPayload.write(
            &encoded,
            self.allocator,
            stream_id,
            origin,
            field_value,
        );
        try writeAll(self.io, self.stream, encoded.items);
    }

    fn validateLocalGoAway(self: Connection, last_stream_id: u31) Error!void {
        if (self.local_goaway_last_stream_id) |last| {
            if (last_stream_id > last) return error.InvalidFrame;
        }
    }

    pub fn readGoAway(self: *Connection) Error!OwnedGoAway {
        while (true) {
            var frame = try self.readOwnedFrame();
            errdefer frame.deinit(self.allocator);
            if (frame.frame.header.frame_type != .goaway) {
                if (try self.handleConnectionOrGoAwayFrame(frame.frame)) {
                    frame.deinit(self.allocator);
                    continue;
                }
                frame.deinit(self.allocator);
                return error.UnexpectedFrame;
            }
            const goaway = try http2.GoAwayPayload.parse(frame.frame);
            try self.recordPeerGoAway(goaway);
            return .{ .frame = frame, .goaway = goaway };
        }
    }

    pub fn sendResetStream(self: *Connection, stream_id: u31, error_code: http2.ErrorCode) Error!void {
        if (!self.outboundStreamIsActive(stream_id)) return error.InvalidStreamId;
        try self.writeResetStreamFrame(stream_id, error_code);
        self.releaseLocalStream(stream_id);
        self.releasePeerStream(stream_id);
    }

    pub fn readResetStream(self: *Connection) Error!OwnedResetStream {
        while (true) {
            var frame = try self.readOwnedFrame();
            errdefer frame.deinit(self.allocator);
            if (frame.frame.header.frame_type != .rst_stream) {
                if (try self.handleConnectionOrGoAwayFrame(frame.frame)) {
                    frame.deinit(self.allocator);
                    continue;
                }
                frame.deinit(self.allocator);
                return error.UnexpectedFrame;
            }
            const reset = try http2.ResetStreamPayload.parse(frame.frame);
            self.recordResetStream(reset);
            return .{ .frame = frame, .reset = reset };
        }
    }

    fn writeResetStreamFrame(
        self: *Connection,
        stream_id: u31,
        error_code: http2.ErrorCode,
    ) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try http2.ResetStreamPayload.write(
            &encoded,
            self.allocator,
            stream_id,
            error_code,
        );
        try writeAll(self.io, self.stream, encoded.items);
    }

    fn recordResetStream(
        self: *Connection,
        reset: http2.ResetStreamPayload,
    ) void {
        // A reset is legal on a reserved stream even though that stream is not
        // counted as active. Preserve a server-side cancellation marker until
        // writePushedResponse observes it; client-side reservations can be
        // removed immediately because no pushed response may follow.
        if (self.role == .server and
            self.push_state.cancelLocal(reset.stream_id))
        {
            self.releaseLocalStream(reset.stream_id);
            self.releasePeerStream(reset.stream_id);
            self.forgetResponseSemantics(reset.stream_id);
            _ = self.priority_state.remove(
                self.allocator,
                reset.stream_id,
            );
            return;
        }
        if (self.role == .client) {
            if (self.push_state.cancelRemote(
                self.allocator,
                reset.stream_id,
            )) {
                self.releaseLocalStream(reset.stream_id);
                self.releasePeerStream(reset.stream_id);
                return;
            }
        }
        // A locally completed stream can race with a reset already in flight.
        // Keep accepting that late reset, as the previous runtime did; outbound
        // sendResetStream still rejects streams that were never activated.
        self.releaseLocalStream(reset.stream_id);
        self.releasePeerStream(reset.stream_id);
    }

    pub fn sendWindowUpdate(self: *Connection, stream_id: u31, increment: u31) Error!void {
        if (stream_id == 0) {
            try self.sendWindowUpdates(null, increment, null);
        } else {
            try self.sendWindowUpdates(stream_id, null, increment);
        }
    }

    pub fn releaseReceivedCapacity(self: *Connection, stream_id: u31, amount: usize) Error!void {
        if (amount == 0) return;
        var remaining = amount;
        while (remaining != 0) {
            const increment: u31 = @intCast(@min(remaining, std.math.maxInt(u31)));
            try self.sendWindowUpdates(
                stream_id,
                increment,
                increment,
            );
            remaining -= increment;
        }
    }

    fn sendWindowUpdates(
        self: *Connection,
        stream_id: ?u31,
        connection_increment: ?u31,
        stream_increment: ?u31,
    ) Error!void {
        if (connection_increment == null and stream_increment == null) return;
        if (stream_increment != null) {
            const id = stream_id orelse return error.InvalidStreamId;
            if (!self.outboundStreamIsActive(id) and
                !self.hasRecvStreamWindow(id))
            {
                return error.InvalidStreamId;
            }
        }

        var encoded: [2 * (http2.FrameHeader.encoded_len + 4)]u8 =
            undefined;
        var encoded_len: usize = 0;
        if (connection_increment) |increment| {
            try self.recv_connection_window.update(increment);
            errdefer self.recv_connection_window.adjust(
                -@as(i64, increment),
            ) catch unreachable;
            try encodeWindowUpdateFrame(
                encoded[encoded_len..][0 .. http2.FrameHeader.encoded_len + 4],
                0,
                increment,
            );
            encoded_len += http2.FrameHeader.encoded_len + 4;
        }
        if (stream_increment) |increment| {
            const window = try self.recvStreamWindow(stream_id.?);
            try window.update(increment);
            errdefer window.adjust(-@as(i64, increment)) catch unreachable;
            try encodeWindowUpdateFrame(
                encoded[encoded_len..][0 .. http2.FrameHeader.encoded_len + 4],
                stream_id.?,
                increment,
            );
            encoded_len += http2.FrameHeader.encoded_len + 4;
        }
        try writeAll(self.io, self.stream, encoded[0..encoded_len]);
    }

    fn addActiveLocalStream(self: *Connection, stream_id: u31) Error!void {
        const slot = try self.active_local_index.getOrPut(self.allocator, stream_id);
        if (slot.found_existing) return;
        errdefer _ = self.active_local_index.remove(stream_id);
        try self.active_local_streams.ensureUnusedCapacity(self.allocator, 1);
        const index = self.active_local_streams.items.len;
        self.active_local_streams.appendAssumeCapacity(stream_id);
        slot.value_ptr.* = index;
    }

    fn addActivePeerStream(self: *Connection, stream_id: u31) Error!void {
        const slot = try self.active_peer_index.getOrPut(self.allocator, stream_id);
        if (slot.found_existing) return;
        errdefer _ = self.active_peer_index.remove(stream_id);
        try self.active_peer_streams.ensureUnusedCapacity(self.allocator, 1);
        const index = self.active_peer_streams.items.len;
        self.active_peer_streams.appendAssumeCapacity(stream_id);
        slot.value_ptr.* = index;
    }

    fn removeActiveLocalStream(self: *Connection, stream_id: u31) bool {
        if (self.active_local_index.count() == 0) return false;
        const index = self.active_local_index.get(stream_id) orelse return false;
        const last_index = self.active_local_streams.items.len - 1;
        const removed = self.active_local_streams.swapRemove(index);
        _ = self.active_local_index.remove(removed);
        if (index != last_index) {
            const moved = self.active_local_streams.items[index];
            self.active_local_index.getPtr(moved).?.* = index;
        }
        return true;
    }

    fn removeActivePeerStream(self: *Connection, stream_id: u31) bool {
        if (self.active_peer_index.count() == 0) return false;
        const index = self.active_peer_index.get(stream_id) orelse return false;
        const last_index = self.active_peer_streams.items.len - 1;
        const removed = self.active_peer_streams.swapRemove(index);
        _ = self.active_peer_index.remove(removed);
        if (index != last_index) {
            const moved = self.active_peer_streams.items[index];
            self.active_peer_index.getPtr(moved).?.* = index;
        }
        return true;
    }

    fn reserveNextClientStreamId(self: *Connection) Error!u31 {
        const stream_id = self.next_client_stream_id;
        if (stream_id > std.math.maxInt(u31) - 2) return error.InvalidStreamId;
        if (self.peer_goaway_last_stream_id) |last| {
            if (stream_id > last) return error.ConnectionGoAway;
        }
        if (self.peer_max_concurrent_streams) |max_streams| {
            const was_priority_reserved =
                self.priority_state.containsIdleRequest(stream_id);
            const counted = self.active_local_streams.items.len +
                self.priority_state.idle_requests.items.len -
                @intFromBool(was_priority_reserved);
            if (counted >= max_streams) return error.FlowControlBlocked;
        }
        try self.addActiveLocalStream(stream_id);
        _ = self.priority_state.activateRequest(stream_id);
        self.next_client_stream_id += 2;
        return stream_id;
    }

    fn outboundStreamIsActive(self: Connection, stream_id: u31) bool {
        if (self.active_local_index.count() != 0 and
            self.active_local_index.contains(stream_id)) return true;
        return self.active_peer_index.count() != 0 and
            self.active_peer_index.contains(stream_id);
    }

    fn releaseLocalStream(self: *Connection, stream_id: u31) void {
        if (!self.removeActiveLocalStream(stream_id)) return;
        _ = self.priority_state.remove(
            self.allocator,
            stream_id,
        );
    }

    fn recordPeerGoAway(self: *Connection, goaway: http2.GoAwayPayload) Error!void {
        if (self.peer_goaway_last_stream_id) |last| {
            // RFC 9113 §6.8: endpoints may send more than one GOAWAY, but the
            // last-stream-id value must not increase.  h2 rejects an increasing
            // value as a protocol error because it would resurrect streams that
            // were already declared unprocessed.
            if (goaway.last_stream_id > last) return error.InvalidFrame;
        }
        self.peer_goaway_last_stream_id = goaway.last_stream_id;
    }

    fn handleGoAwayForStream(self: *Connection, stream_id: u31, goaway: http2.GoAwayPayload) Error!void {
        try self.recordPeerGoAway(goaway);
        if (stream_id > goaway.last_stream_id) {
            self.releaseLocalStream(stream_id);
            return error.ConnectionGoAway;
        }
    }

    fn reservePeerStream(self: *Connection, stream_id: u31) Error!void {
        const was_priority_reserved =
            self.priority_state.containsIdleRequest(stream_id);
        if (self.limits.max_concurrent_streams) |max_streams| {
            const counted = self.active_peer_streams.items.len +
                self.priority_state.idle_requests.items.len -
                @intFromBool(was_priority_reserved);
            if (counted >= max_streams) return error.FlowControlViolation;
        }
        try self.addActivePeerStream(stream_id);
        self.priority_state.openRequest(self.allocator, stream_id);
    }

    fn releasePeerStream(self: *Connection, stream_id: u31) void {
        _ = self.removeActivePeerStream(stream_id);
        self.forgetResponseSemantics(stream_id);
        _ = self.priority_state.remove(self.allocator, stream_id);
    }

    fn rememberResponseSemantics(
        self: *Connection,
        stream_id: u31,
        method: []const u8,
        protocol: ?[]const u8,
        priority: http2.ExtensiblePriority,
    ) Error!void {
        const semantics = StreamResponseSemantics{
            .stream_id = stream_id,
            .head = methodIsHead(method),
            .traditional_connect = methodIsConnect(method) and protocol == null,
            .extended_connect = methodIsConnect(method) and protocol != null,
            .priority = priority,
        };
        const slot = try self.response_semantics_index.getOrPut(
            self.allocator,
            stream_id,
        );
        if (slot.found_existing) {
            self.response_semantics.items[slot.value_ptr.*] = semantics;
            return;
        }
        errdefer _ = self.response_semantics_index.remove(stream_id);
        try self.response_semantics.ensureUnusedCapacity(self.allocator, 1);
        const index = self.response_semantics.items.len;
        self.response_semantics.appendAssumeCapacity(semantics);
        slot.value_ptr.* = index;
    }

    fn forgetResponseSemantics(self: *Connection, stream_id: u31) void {
        if (self.response_semantics_index.count() == 0) return;
        const index = self.response_semantics_index.get(stream_id) orelse return;
        const last_index = self.response_semantics.items.len - 1;
        const removed = self.response_semantics.swapRemove(index);
        _ = self.response_semantics_index.remove(removed.stream_id);
        if (index != last_index) {
            const moved = self.response_semantics.items[index];
            self.response_semantics_index.getPtr(moved.stream_id).?.* = index;
        }
    }

    fn responsePriority(self: Connection, stream_id: u31) http2.ExtensiblePriority {
        // PRIORITY_UPDATE has precedence over the request's original Priority
        // field and may arrive after the application accepted the request.
        if (self.peerPriority(stream_id)) |updated| return updated;
        if (self.response_semantics_index.count() == 0) return .{};
        const index = self.response_semantics_index.get(stream_id) orelse
            return .{};
        return self.response_semantics.items[index].priority;
    }

    fn responseSemanticsFor(self: Connection, stream_id: u31, options: ResponseOptions) ResponseBodySemantics {
        if (options.request_method) |method| return responseSemanticsFromMethod(method, options.extended_connect);
        if (self.response_semantics_index.count() == 0) return .{};
        if (self.response_semantics_index.get(stream_id)) |index| {
            const entry = self.response_semantics.items[index];
            return .{
                .head = entry.head,
                .traditional_connect = entry.traditional_connect,
                .extended_connect = entry.extended_connect,
            };
        }
        return .{};
    }

    fn receiveDataPayload(self: *Connection, stream_id: u31, frame: http2.Frame) Error!http2.DataPayload {
        const data = try http2.DataPayload.parse(frame);
        // HTTP/2 flow control charges the whole DATA frame payload, not just
        // the bytes exposed to the application.  PADDED DATA therefore consumes
        // credit for the Pad Length byte and padding octets as well.
        const charged_len = frame.payload.len;
        try self.recv_connection_window.receive(charged_len);
        errdefer self.recv_connection_window.update(@intCast(charged_len)) catch unreachable;
        try (try self.recvStreamWindow(stream_id)).receive(charged_len);
        return data;
    }

    fn maybeReleaseReceivedCapacity(self: *Connection, stream_id: u31) Error!void {
        const connection_target: usize =
            self.limits.initial_connection_window_size;
        const connection_low_watermark = connection_target / 2;
        const conn_available = self.recv_connection_window.available();
        const stream_window = try self.recvStreamWindow(stream_id);
        const stream_target: usize = self.limits.initial_window_size;
        const stream_low_watermark = stream_target / 2;
        const stream_available = stream_window.available();
        const connection_increment: ?u31 =
            if (conn_available <= connection_low_watermark and
            conn_available < connection_target)
                @intCast(connection_target - conn_available)
            else
                null;
        const stream_increment: ?u31 =
            if (stream_available <= stream_low_watermark and
            stream_available < stream_target)
                @intCast(stream_target - stream_available)
            else
                null;
        try self.sendWindowUpdates(
            stream_id,
            connection_increment,
            stream_increment,
        );
    }

    pub fn readWindowUpdate(self: *Connection) Error!OwnedWindowUpdate {
        while (true) {
            var frame = try self.readOwnedFrame();
            errdefer frame.deinit(self.allocator);
            if (frame.frame.header.frame_type != .window_update) {
                if (try self.handleConnectionOrGoAwayFrame(frame.frame)) {
                    frame.deinit(self.allocator);
                    continue;
                }
                frame.deinit(self.allocator);
                return error.UnexpectedFrame;
            }
            const update = try http2.WindowUpdatePayload.parse(frame.frame);
            if (update.stream_id == 0) {
                try self.send_connection_window.update(update.increment);
            } else {
                try (try self.sendStreamWindow(update.stream_id)).update(update.increment);
            }
            return .{ .frame = frame, .window_update = update };
        }
    }

    fn readResponse(self: *Connection, stream_id: u31, request_method: []const u8, extended_connect: bool) Error!OwnedResponse {
        defer self.releaseLocalStream(stream_id);
        var headers: ?[]http2.Hpack.HeaderField = null;
        errdefer if (headers) |h| freeHeaders(self.allocator, h);
        var trailers: []http2.Hpack.HeaderField = &.{};
        errdefer freeHeaders(self.allocator, trailers);
        var body: std.ArrayList(u8) = .empty;
        errdefer body.deinit(self.allocator);
        var response_status: ?u16 = null;
        var response_content_length: ?usize = null;

        while (true) {
            var frame = try self.readOwnedFrame();
            defer frame.deinit(self.allocator);
            if (try self.handleConnectionFrame(frame.frame)) continue;
            if (frame.frame.header.frame_type == .goaway) {
                const goaway = try http2.GoAwayPayload.parse(frame.frame);
                try self.handleGoAwayForStream(stream_id, goaway);
                continue;
            }
            if (frame.frame.header.stream_id != stream_id) return error.UnexpectedFrame;
            switch (frame.frame.header.frame_type) {
                .push_promise => {
                    if (!self.limits.enable_push) {
                        _ = try self.validatePushPromiseForClientStream(
                            frame.frame,
                        );
                        return error.InvalidFrame;
                    }
                    try self.receivePushPromise(frame.frame);
                    continue;
                },
                .headers => {
                    if (headers) |h| {
                        if ((frame.frame.header.flags & flag_end_stream) == 0) return error.UnexpectedFrame;
                        _ = h;
                        try validateExpectedContentLength(response_content_length, body.items.len);
                        trailers = try self.readHeaderBlock(frame.frame);
                        try validateHeaderBlock(trailers, .response_trailers);
                        break;
                    } else {
                        headers = try self.readHeaderBlock(frame.frame);
                        try validateHeaderBlock(headers.?, .response);
                        const lookup = try responseHeaderLookup(headers.?);
                        const status_s = lookup.status orelse return error.MissingPseudoHeader;
                        const status = std.fmt.parseInt(u16, status_s, 10) catch return error.InvalidStatus;
                        response_status = status;
                        response_content_length = lookup.content_length;
                        if (informationalResponseToSkip(status)) {
                            if ((frame.frame.header.flags & flag_end_stream) != 0) return error.UnexpectedFrame;
                            if (lookup.content_length != null) return error.InvalidContentLength;
                            freeHeaders(self.allocator, headers.?);
                            headers = null;
                            response_status = null;
                            response_content_length = null;
                            continue;
                        }
                        if (responseForbidsBody(status, request_method, extended_connect)) {
                            const traditional_connect = methodIsConnect(request_method) and !extended_connect;
                            if (traditional_connect and (lookup.content_length orelse 0) != 0) return error.InvalidContentLength;
                            if ((statusIsInformational(status) or status == 204) and lookup.content_length != null) return error.InvalidContentLength;
                            if (!traditional_connect and (frame.frame.header.flags & flag_end_stream) == 0) {
                                try self.consumeForbiddenResponseBody(stream_id);
                            }
                            break;
                        }
                        if ((frame.frame.header.flags & flag_end_stream) != 0) {
                            try validateExpectedContentLength(lookup.content_length, 0);
                            break;
                        }
                    }
                },
                .data => {
                    if (headers == null) return error.UnexpectedFrame;
                    const data = try self.receiveDataPayload(stream_id, frame.frame);
                    if (body.items.len + data.data.len > self.limits.max_body_bytes) return error.MessageTooLarge;
                    try body.appendSlice(self.allocator, data.data);
                    try self.maybeReleaseReceivedCapacity(stream_id);
                    if ((frame.frame.header.flags & flag_end_stream) != 0) {
                        if (headers != null) try validateExpectedContentLength(response_content_length, body.items.len);
                        break;
                    }
                },
                .rst_stream => return error.StreamReset,
                else => continue,
            }
        }

        const final_headers = headers orelse return error.MissingPseudoHeader;
        const status = response_status orelse return error.MissingPseudoHeader;
        return .{
            .headers = final_headers,
            .status = status,
            .body = try body.toOwnedSlice(self.allocator),
            .trailers = trailers,
        };
    }

    /// Consume one active client response as borrowed DATA events.
    ///
    /// This method is intentionally kept next to the aggregate reader because
    /// both enforce the same informational/status/body/trailer semantics. The
    /// difference is ownership: this path never appends DATA to an ArrayList.
    fn readResponseStreaming(
        self: *Connection,
        pending: PendingResponse,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.readResponseStreamingWithHead(
            pending,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    fn readResponseStreamingWithHead(
        self: *Connection,
        pending: PendingResponse,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        const stream_id = pending.stream_id;
        defer self.releaseLocalStream(stream_id);
        var headers: ?[]http2.Hpack.HeaderField = null;
        errdefer if (headers) |value| {
            freeHeaders(self.allocator, value);
        };
        var trailers: []http2.Hpack.HeaderField = &.{};
        errdefer freeHeaders(self.allocator, trailers);
        var status_value: ?u16 = null;
        var expected_body_len: ?usize = null;
        var body_bytes: usize = 0;

        while (true) {
            var pending_owned: ?OwnedFrame = null;
            defer if (pending_owned) |*owned| {
                owned.deinit(self.allocator);
            };
            const frame = if (self.pending_client_frame != null) blk: {
                pending_owned = try self.readOwnedFrame();
                break :blk pending_owned.?.frame;
            } else try self.readFrameScratch();
            if (try self.handleConnectionFrame(frame)) continue;
            if (frame.header.frame_type == .goaway) {
                const goaway = try http2.GoAwayPayload.parse(frame);
                try self.handleGoAwayForStream(stream_id, goaway);
                continue;
            }
            if (frame.header.stream_id != stream_id) {
                return error.UnexpectedFrame;
            }
            switch (frame.header.frame_type) {
                .push_promise => {
                    if (!self.limits.enable_push) {
                        _ = try self.validatePushPromiseForClientStream(
                            frame,
                        );
                        return error.InvalidFrame;
                    }
                    try self.receivePushPromise(frame);
                },
                .headers => {
                    if (headers != null) {
                        if ((frame.header.flags & flag_end_stream) == 0) {
                            return error.UnexpectedFrame;
                        }
                        trailers = try self.readHeaderBlock(frame);
                        try validateHeaderBlock(
                            trailers,
                            .response_trailers,
                        );
                        try validateExpectedContentLength(
                            expected_body_len,
                            body_bytes,
                        );
                        break;
                    }

                    const decoded = try self.readHeaderBlock(frame);
                    var decoded_owned = true;
                    errdefer if (decoded_owned) {
                        freeHeaders(self.allocator, decoded);
                    };
                    try validateHeaderBlock(decoded, .response);
                    const lookup = try responseHeaderLookup(decoded);
                    const status_text = lookup.status orelse
                        return error.MissingPseudoHeader;
                    const status = std.fmt.parseInt(
                        u16,
                        status_text,
                        10,
                    ) catch return error.InvalidStatus;
                    if (informationalResponseToSkip(status)) {
                        if ((frame.header.flags & flag_end_stream) != 0) {
                            return error.UnexpectedFrame;
                        }
                        if (lookup.content_length != null) {
                            return error.InvalidContentLength;
                        }
                        freeHeaders(self.allocator, decoded);
                        decoded_owned = false;
                        continue;
                    }

                    headers = decoded;
                    decoded_owned = false;
                    status_value = status;
                    expected_body_len = lookup.content_length;
                    begin(context, StreamingResponseHead{
                        .headers = decoded,
                        .status = status,
                    }) catch |err| {
                        if ((frame.header.flags & flag_end_stream) == 0) {
                            self.writeResetStreamFrame(
                                stream_id,
                                .cancel,
                            ) catch {};
                        }
                        return err;
                    };
                    if (responseForbidsBody(
                        status,
                        pending.request_method,
                        pending.extended_connect,
                    )) {
                        const traditional_connect =
                            methodIsConnect(pending.request_method) and
                            !pending.extended_connect;
                        if (traditional_connect and
                            (lookup.content_length orelse 0) != 0)
                        {
                            return error.InvalidContentLength;
                        }
                        if ((statusIsInformational(status) or
                            status == 204) and
                            lookup.content_length != null)
                        {
                            return error.InvalidContentLength;
                        }
                        if (!traditional_connect and
                            (frame.header.flags & flag_end_stream) == 0)
                        {
                            try self.consumeForbiddenResponseBody(stream_id);
                        }
                        break;
                    }
                    if ((expected_body_len orelse 0) >
                        self.limits.max_body_bytes)
                    {
                        return error.MessageTooLarge;
                    }
                    if ((frame.header.flags & flag_end_stream) != 0) {
                        try validateExpectedContentLength(
                            expected_body_len,
                            body_bytes,
                        );
                        break;
                    }
                },
                .data => {
                    if (headers == null) return error.UnexpectedFrame;
                    const data = try self.receiveDataPayload(
                        stream_id,
                        frame,
                    );
                    body_bytes = std.math.add(
                        usize,
                        body_bytes,
                        data.data.len,
                    ) catch return error.MessageTooLarge;
                    if (body_bytes > self.limits.max_body_bytes) {
                        return error.MessageTooLarge;
                    }
                    if (data.data.len != 0) {
                        consume(context, data.data) catch |err| {
                            // DATA already consumed connection credit before
                            // application delivery. Restore its exact charged
                            // payload before canceling; a low-watermark-only
                            // update would let repeated small callback failures
                            // gradually starve unrelated streams.
                            self.releaseReceivedCapacity(
                                stream_id,
                                frame.payload.len,
                            ) catch {};
                            if ((frame.header.flags &
                                flag_end_stream) == 0)
                            {
                                self.writeResetStreamFrame(
                                    stream_id,
                                    .cancel,
                                ) catch {};
                            }
                            return err;
                        };
                    }
                    try self.maybeReleaseReceivedCapacity(stream_id);
                    if ((frame.header.flags & flag_end_stream) != 0) {
                        try validateExpectedContentLength(
                            expected_body_len,
                            body_bytes,
                        );
                        break;
                    }
                },
                .rst_stream => return error.StreamReset,
                else => return error.UnexpectedFrame,
            }
        }

        return .{
            .headers = headers orelse return error.MissingPseudoHeader,
            .status = status_value orelse return error.MissingPseudoHeader,
            .body_bytes = body_bytes,
            .trailers = trailers,
        };
    }

    fn readResponseOnPeerStream(
        self: *Connection,
        stream_id: u31,
        request_method: []const u8,
    ) Error!OwnedResponse {
        var headers: ?[]http2.Hpack.HeaderField = null;
        errdefer if (headers) |value| {
            freeHeaders(self.allocator, value);
        };
        var trailers: []http2.Hpack.HeaderField = &.{};
        errdefer freeHeaders(self.allocator, trailers);
        var body: std.ArrayList(u8) = .empty;
        errdefer body.deinit(self.allocator);
        var response_status: ?u16 = null;
        var response_content_length: ?usize = null;
        while (true) {
            var frame = try self.readOwnedFrame();
            defer frame.deinit(self.allocator);
            if (try self.handleConnectionFrame(frame.frame)) continue;
            if (frame.frame.header.stream_id != stream_id) {
                return error.UnexpectedFrame;
            }
            switch (frame.frame.header.frame_type) {
                .headers => {
                    if (headers != null) {
                        trailers = try self.readHeaderBlock(frame.frame);
                        try validateHeaderBlock(
                            trailers,
                            .response_trailers,
                        );
                        if ((frame.frame.header.flags & flag_end_stream) == 0) {
                            return error.UnexpectedFrame;
                        }
                        break;
                    }
                    headers = try self.readHeaderBlock(frame.frame);
                    try validateHeaderBlock(headers.?, .response);
                    const lookup = try responseHeaderLookup(headers.?);
                    const status_text = lookup.status orelse return error.MissingPseudoHeader;
                    response_status = std.fmt.parseInt(u16, status_text, 10) catch
                        return error.InvalidStatus;
                    response_content_length = lookup.content_length;
                    if ((frame.frame.header.flags & flag_end_stream) != 0) {
                        break;
                    }
                },
                .data => {
                    if (headers == null) return error.UnexpectedFrame;
                    const data = try self.receiveDataPayload(
                        stream_id,
                        frame.frame,
                    );
                    if (body.items.len + data.data.len >
                        self.limits.max_body_bytes)
                    {
                        return error.MessageTooLarge;
                    }
                    try body.appendSlice(self.allocator, data.data);
                    try self.maybeReleaseReceivedCapacity(stream_id);
                    if ((frame.frame.header.flags & flag_end_stream) != 0) {
                        break;
                    }
                },
                .rst_stream => return error.StreamReset,
                else => return error.UnexpectedFrame,
            }
        }
        const final_headers = headers orelse
            return error.MissingPseudoHeader;
        const status = response_status orelse return error.MissingPseudoHeader;
        if (responseForbidsBody(status, request_method, false) and
            body.items.len != 0)
        {
            return error.InvalidContentLength;
        }
        try validateExpectedContentLength(response_content_length, body.items.len);
        return .{
            .headers = final_headers,
            .status = status,
            .body = try body.toOwnedSlice(self.allocator),
            .trailers = trailers,
        };
    }

    fn readExtendedConnectResponse(self: *Connection, stream_id: u31) Error!ExtendedConnectResponse {
        while (true) {
            var frame = try self.readOwnedFrame();
            defer frame.deinit(self.allocator);
            if (try self.handleConnectionFrame(frame.frame)) continue;
            if (frame.frame.header.frame_type == .goaway) {
                const goaway = try http2.GoAwayPayload.parse(frame.frame);
                try self.handleGoAwayForStream(stream_id, goaway);
                continue;
            }
            if (frame.frame.header.stream_id != stream_id) return error.UnexpectedFrame;
            switch (frame.frame.header.frame_type) {
                .headers => {
                    const headers = try self.readHeaderBlock(frame.frame);
                    errdefer freeHeaders(self.allocator, headers);
                    try validateHeaderBlock(headers, .response);
                    const lookup = try responseHeaderLookup(headers);
                    const status_s = lookup.status orelse return error.MissingPseudoHeader;
                    const status = std.fmt.parseInt(u16, status_s, 10) catch return error.InvalidStatus;
                    if (informationalResponseToSkip(status)) {
                        if ((frame.frame.header.flags & flag_end_stream) != 0) return error.UnexpectedFrame;
                        if (lookup.content_length != null) return error.InvalidContentLength;
                        freeHeaders(self.allocator, headers);
                        continue;
                    }
                    if (status < 200 or status > 299) return error.InvalidStatus;
                    if ((lookup.content_length orelse 0) != 0) return error.InvalidContentLength;
                    if ((frame.frame.header.flags & flag_end_stream) != 0) return error.ConnectionClosed;
                    return .{
                        .status = status,
                        .headers = headers,
                        .tunnel = .{ .connection = self, .stream_id = stream_id },
                    };
                },
                .data => return error.UnexpectedFrame,
                .rst_stream => return error.StreamReset,
                else => continue,
            }
        }
    }

    fn validatePushPromiseForClientStream(self: Connection, frame: http2.Frame) Error!http2.PushPromisePayload {
        if (self.role != .client) return error.InvalidFrame;
        const promise = try http2.PushPromisePayload.parse(frame);
        // RFC 9113 keeps server push tied to a client-initiated stream that is
        // still open or half-closed(remote).  Rust h2 treats a promise on an
        // unknown/inactive parent as a connection protocol error instead of
        // silently discarding it; do the same before considering local push
        // policy.
        if (!clientInitiatedStreamId(promise.stream_id) or !self.outboundStreamIsActive(promise.stream_id)) {
            return error.InvalidFrame;
        }
        // Server-pushed streams are server initiated and must be strictly
        // increasing.  The lightweight runtime does not implement a push queue,
        // but validating the promised id catches malformed peers before the
        // normal "push disabled" rejection path.
        if (clientInitiatedStreamId(promise.promised_stream_id)) return error.InvalidStreamId;
        try self.push_state.validatePeerStreamId(
            promise.promised_stream_id,
        );
        return promise;
    }

    fn receivePushPromise(
        self: *Connection,
        frame: http2.Frame,
    ) Error!void {
        const promise = try self.validatePushPromiseForClientStream(frame);
        var block: std.ArrayList(u8) = .empty;
        defer block.deinit(self.allocator);
        try block.appendSlice(self.allocator, promise.header_block);
        var flags = frame.header.flags;
        var continuation_count: usize = 0;
        const max_continuations = self.maxContinuationFrames();
        while ((flags & flag_end_headers) == 0) {
            var continuation = try self.readOwnedFrame();
            defer continuation.deinit(self.allocator);
            if (continuation.frame.header.frame_type != .continuation or
                continuation.frame.header.stream_id != promise.stream_id)
            {
                return error.UnexpectedFrame;
            }
            continuation_count += 1;
            if (continuation_count > max_continuations) {
                return error.MessageTooLarge;
            }
            try block.appendSlice(
                self.allocator,
                continuation.frame.payload,
            );
            flags = continuation.frame.header.flags;
        }
        const headers = try cloneDecodedHeaders(
            self.allocator,
            block.items,
            self.limits,
            &self.hpack_decoder,
        );
        errdefer freeHeaders(self.allocator, headers);
        try validateHeaderBlock(headers, .request);
        try self.push_state.queue(self.allocator, .{
            .parent_stream_id = promise.stream_id,
            .promised_stream_id = promise.promised_stream_id,
            .headers = headers,
        });
    }

    fn consumeForbiddenResponseBody(self: *Connection, stream_id: u31) Error!void {
        while (true) {
            var frame = try self.readOwnedFrame();
            defer frame.deinit(self.allocator);
            if (try self.handleConnectionFrame(frame.frame)) continue;
            if (frame.frame.header.frame_type == .goaway) {
                const goaway = try http2.GoAwayPayload.parse(frame.frame);
                try self.handleGoAwayForStream(stream_id, goaway);
                continue;
            }
            if (frame.frame.header.stream_id != stream_id) return error.UnexpectedFrame;
            switch (frame.frame.header.frame_type) {
                .data => {
                    const data = try self.receiveDataPayload(stream_id, frame.frame);
                    try self.maybeReleaseReceivedCapacity(stream_id);
                    if (data.data.len != 0) return error.InvalidContentLength;
                    if ((frame.frame.header.flags & flag_end_stream) != 0) return;
                },
                .headers => return error.InvalidContentLength,
                .rst_stream => return error.StreamReset,
                else => return error.UnexpectedFrame,
            }
        }
    }

    fn writeHeaders(self: *Connection, stream_id: u31, headers: []const http2.Hpack.HeaderField, end_stream: bool) Error!void {
        try validateHeaderListSize(headers, self.peer_max_header_list_size);
        const activation = try self.ensureStreamTrackedForOutboundHeaders(stream_id);
        errdefer self.undoStreamActivation(activation, stream_id);
        const block = try self.hpack_encoder.encodeBlockRetained(
            self.allocator,
            headers,
        );
        try self.writeHeaderBlock(stream_id, block, end_stream);
    }

    /// Emit HEADERS and the first DATA burst in one stream write when the
    /// header block and current flow-control credit permit it.
    ///
    /// Small request/response bodies are common and two tiny TCP submissions
    /// can trigger Linux's Nagle/delayed-ACK interaction. Larger or blocked
    /// bodies retain the normal framing and WINDOW_UPDATE-driven fallback.
    fn writeHeadersThenData(
        self: *Connection,
        stream_id: u31,
        headers: []const http2.Hpack.HeaderField,
        data: []const u8,
        end_stream: bool,
    ) Error!void {
        std.debug.assert(data.len != 0);
        try validateHeaderListSize(
            headers,
            self.peer_max_header_list_size,
        );
        const activation =
            try self.ensureStreamTrackedForOutboundHeaders(stream_id);
        errdefer self.undoStreamActivation(activation, stream_id);
        const block = try self.hpack_encoder.encodeBlockRetained(
            self.allocator,
            headers,
        );
        const frame_limit = self.outboundFramePayloadLimit();
        const stream_window = try self.sendStreamWindow(stream_id);
        const burst_limit = frame_limit *| max_data_frames_with_headers;
        const first_data_len = @min(
            data.len,
            burst_limit,
            self.send_connection_window.available(),
            stream_window.available(),
        );
        if (block.len > frame_limit or first_data_len == 0) {
            try self.writeHeaderBlock(stream_id, block, false);
            try self.writeData(stream_id, data, end_stream);
            return;
        }

        try self.send_connection_window.reserve(first_data_len);
        errdefer self.send_connection_window.update(
            @intCast(first_data_len),
        ) catch unreachable;
        try stream_window.reserve(first_data_len);
        errdefer stream_window.update(
            @intCast(first_data_len),
        ) catch unreachable;

        var headers_frame: [http2.FrameHeader.encoded_len]u8 = undefined;
        try encodeFrameHeader(
            &headers_frame,
            .headers,
            flag_end_headers,
            stream_id,
            block.len,
        );
        var data_frames: [max_data_frames_per_write][
            http2.FrameHeader.encoded_len
        ]u8 = undefined;
        var parts: [2 + 2 * max_data_frames_per_write][]const u8 =
            undefined;
        parts[0] = &headers_frame;
        parts[1] = block;
        var part_count: usize = 2;
        var offset: usize = 0;
        while (offset < first_data_len) {
            const end = @min(first_data_len, offset + frame_limit);
            const frame_index = (part_count - 2) / 2;
            try encodeFrameHeader(
                &data_frames[frame_index],
                .data,
                if (end_stream and end == data.len)
                    flag_end_stream
                else
                    0,
                stream_id,
                end - offset,
            );
            parts[part_count] = &data_frames[frame_index];
            parts[part_count + 1] = data[offset..end];
            part_count += 2;
            offset = end;
        }
        try stream_io.writeAllSlices(
            self.io,
            self.stream,
            parts[0..part_count],
        );
        if (first_data_len < data.len) {
            try self.writeData(
                stream_id,
                data[first_data_len..],
                end_stream,
            );
        }
    }

    const StreamActivation = enum { none, local, peer };

    fn ensureStreamTrackedForOutboundHeaders(self: *Connection, stream_id: u31) Error!StreamActivation {
        if (stream_id == 0) return error.InvalidStreamId;
        if (self.outboundStreamIsActive(stream_id)) return .none;
        const client_initiated = clientInitiatedStreamId(stream_id);
        if (self.role == .client) {
            if (!client_initiated) return error.InvalidStreamId;
            try self.addActiveLocalStream(stream_id);
            return .local;
        }
        if (!client_initiated) return error.InvalidStreamId;
        try self.addActivePeerStream(stream_id);
        return .peer;
    }

    fn undoStreamActivation(self: *Connection, activation: StreamActivation, stream_id: u31) void {
        switch (activation) {
            .none => {},
            .local => self.releaseLocalStream(stream_id),
            .peer => self.releasePeerStream(stream_id),
        }
    }

    fn writeExtendedConnectResponse(
        self: *Connection,
        stream_id: u31,
        status_code: u16,
        response_headers: []const http2.Hpack.HeaderField,
        end_stream: bool,
    ) Error!void {
        var status_buf: [3]u8 = undefined;
        if (status_code < 100 or status_code > 999) return error.InvalidStatus;
        const status = std.fmt.bufPrint(&status_buf, "{}", .{status_code}) catch return error.InvalidStatus;
        var fields: std.ArrayList(http2.Hpack.HeaderField) = .empty;
        defer fields.deinit(self.allocator);
        try fields.append(self.allocator, .{ .name = ":status", .value = status });
        for (response_headers) |header| try fields.append(self.allocator, header);
        stripConnectionHeaders(&fields, .response);
        try validateResponseBodyForStatus(status_code, fields.items, &.{}, &.{});
        if (status_code >= 200 and status_code < 300) {
            try stripSuccessfulConnectContentLength(&fields);
        }
        try validateHeaderBlock(fields.items, .response);
        try self.writeHeaders(stream_id, fields.items, end_stream);
    }

    fn handleConnectionOrGoAwayFrame(self: *Connection, frame: http2.Frame) Error!bool {
        if (frame.header.frame_type == .goaway) {
            try self.recordPeerGoAway(try http2.GoAwayPayload.parse(frame));
            return true;
        }
        return self.handleConnectionFrame(frame);
    }

    fn handleConnectionFrame(self: *Connection, frame: http2.Frame) Error!bool {
        switch (frame.header.frame_type) {
            .settings => {
                if ((frame.header.flags & flag_ack) != 0) {
                    if (!self.awaiting_settings_ack) return error.InvalidFrame;
                    self.awaiting_settings_ack = false;
                } else {
                    const settings = try http2.parseSettings(self.allocator, frame.payload);
                    defer self.allocator.free(settings);
                    try self.applySettings(settings);
                    try writeFrame(self.allocator, self.io, self.stream, .settings, flag_ack, 0, &.{});
                }
                return true;
            },
            .ping => {
                const ping_payload = try http2.PingPayload.parse(frame);
                if ((frame.header.flags & flag_ack) == 0) {
                    try writeFrame(self.allocator, self.io, self.stream, .ping, flag_ack, 0, &ping_payload.data);
                }
                return true;
            },
            .window_update => {
                const update = try http2.WindowUpdatePayload.parse(frame);
                if (update.stream_id == 0) {
                    try self.send_connection_window.update(update.increment);
                } else if (self.outboundStreamIsActive(update.stream_id)) {
                    try (try self.sendStreamWindow(update.stream_id)).update(update.increment);
                }
                return true;
            },
            .priority => {
                // PRIORITY can be interleaved with DATA/HEADERS and does not
                // alter the message body.  The envelope validator has already
                // checked stream id and payload length; parse it here so
                // malformed priority payloads still fail before being ignored.
                _ = try http2.PriorityPayload.parse(frame);
                if (self.limits.no_rfc7540_priorities) {
                    // Advertising SETTINGS_NO_RFC7540_PRIORITIES=1 commits this
                    // endpoint to ignoring legacy dependency signals.
                    return true;
                }
                return true;
            },
            .priority_update => {
                if (self.role != .server) return error.InvalidFrame;
                if (!self.limits.no_rfc7540_priorities) {
                    // The client is advised to stop these after observing a
                    // missing/zero setting. Unknown extension frames remain
                    // ignorable, so discard rather than allocate state.
                    return true;
                }
                const update = try http2.PriorityUpdatePayload.parse(frame);
                const stream_id = update.prioritized_stream_id;
                if (clientInitiatedStreamId(stream_id)) {
                    if (stream_id > self.last_peer_client_stream_id) {
                        try self.priority_state.reserveIdleRequest(
                            self.allocator,
                            stream_id,
                            self.active_peer_streams.items.len,
                            self.limits.max_concurrent_streams,
                            self.limits.max_idle_priority_updates,
                        );
                    } else if (!self.outboundStreamIsActive(stream_id)) {
                        // Closed request streams can be discarded without
                        // retaining attacker-controlled field values.
                        return true;
                    }
                } else {
                    if (!self.push_state.isLocalReserved(stream_id) and
                        !self.outboundStreamIsActive(stream_id))
                    {
                        if (stream_id <
                            self.push_state.next_local_stream_id)
                        {
                            // A previously promised push is already closed;
                            // RFC 9218 permits discarding this late update.
                            return true;
                        }
                        // An even ID not present in local reservations is an
                        // idle push stream, which RFC 9218 forbids targeting.
                        return error.InvalidFrame;
                    }
                }
                try self.priority_state.store(
                    self.allocator,
                    stream_id,
                    update.field_value,
                );
                return true;
            },
            .rst_stream => {
                const reset = try http2.ResetStreamPayload.parse(frame);
                const reserved_push =
                    (self.role == .server and
                        self.push_state.localStatus(reset.stream_id) != null) or
                    (self.role == .client and
                        self.push_state.isRemoteReserved(reset.stream_id));
                if (!reserved_push) return false;
                self.recordResetStream(reset);
                return true;
            },
            .origin => {
                // ORIGIN is server-to-client only. RFC 8336 requires clients
                // to ignore it when sent on a non-zero stream or with an
                // incompatible reserved flag; envelope validation therefore
                // leaves those cases available for this semantic decision.
                if (self.role != .client or
                    frame.header.stream_id != 0 or
                    (frame.header.flags & 0x0f) != 0)
                {
                    return true;
                }
                var origin = try http2.OriginPayload.parse(
                    self.allocator,
                    frame,
                );
                defer origin.deinit(self.allocator);
                for (origin.origins) |value| {
                    try self.storePeerOrigin(value);
                }
                return true;
            },
            .altsvc => {
                if (self.role != .client or frame.header.flags != 0) {
                    return true;
                }
                const service = try http2.AltSvcPayload.parse(frame);
                try self.storeAlternativeService(
                    frame.header.stream_id,
                    service.origin,
                    service.field_value,
                );
                return true;
            },
            else => return false,
        }
    }

    fn writeHeaderBlock(self: *Connection, stream_id: u31, block: []const u8, end_stream: bool) Error!void {
        const chunk_size = self.outboundFramePayloadLimit();
        const first_len = @min(block.len, chunk_size);
        var offset = first_len;
        try writeFrame(
            self.allocator,
            self.io,
            self.stream,
            .headers,
            (if (offset == block.len) flag_end_headers else 0) | if (end_stream) flag_end_stream else 0,
            stream_id,
            block[0..first_len],
        );
        while (offset < block.len) {
            const end = @min(block.len, offset + chunk_size);
            try writeFrame(
                self.allocator,
                self.io,
                self.stream,
                .continuation,
                if (end == block.len) flag_end_headers else 0,
                stream_id,
                block[offset..end],
            );
            offset = end;
        }
    }

    fn readHeaderBlock(self: *Connection, first: http2.Frame) Error![]http2.Hpack.HeaderField {
        if (first.header.frame_type != .headers) return error.UnexpectedFrame;
        const first_headers = try http2.HeadersPayload.parse(first);
        if (first_headers.priority) |priority| {
            if (priority.stream_dependency == first.header.stream_id) return error.InvalidFrame;
        }
        var block: std.ArrayList(u8) = .empty;
        defer block.deinit(self.allocator);
        try block.appendSlice(self.allocator, first_headers.header_block);
        if (block.items.len > self.limits.max_frame_payload * @as(usize, self.limits.max_header_fields + 1)) return error.MessageTooLarge;

        var flags = first.header.flags;
        var continuation_count: usize = 0;
        const max_continuations = self.maxContinuationFrames();
        while ((flags & flag_end_headers) == 0) {
            var frame = try self.readOwnedFrame();
            defer frame.deinit(self.allocator);
            if (frame.frame.header.frame_type != .continuation or frame.frame.header.stream_id != first.header.stream_id) {
                return error.UnexpectedFrame;
            }
            continuation_count += 1;
            if (continuation_count > max_continuations) return error.MessageTooLarge;
            try block.appendSlice(self.allocator, frame.frame.payload);
            if (block.items.len > self.limits.max_frame_payload * @as(usize, self.limits.max_header_fields + 1)) return error.MessageTooLarge;
            flags = frame.frame.header.flags;
        }
        return cloneDecodedHeaders(
            self.allocator,
            block.items,
            self.limits,
            &self.hpack_decoder,
        );
    }

    fn writePushPromiseBlock(
        self: *Connection,
        parent_stream_id: u31,
        promised_stream_id: u31,
        block: []const u8,
    ) Error!void {
        const chunk_size = self.outboundFramePayloadLimit();
        if (chunk_size <= 4) return error.InvalidFrame;
        const first_len = @min(block.len, chunk_size - 4);
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try http2.PushPromisePayload.write(
            &encoded,
            self.allocator,
            parent_stream_id,
            promised_stream_id,
            block[0..first_len],
            .{ .end_headers = first_len == block.len },
        );
        try writeAll(self.io, self.stream, encoded.items);
        var offset = first_len;
        while (offset < block.len) {
            const end = @min(block.len, offset + chunk_size);
            try writeFrame(
                self.allocator,
                self.io,
                self.stream,
                .continuation,
                if (end == block.len) flag_end_headers else 0,
                parent_stream_id,
                block[offset..end],
            );
            offset = end;
        }
    }

    fn maxContinuationFrames(self: Connection) usize {
        if (self.limits.max_continuation_frames) |limit| return limit;
        return calcMaxContinuationFrames(self.limits.max_header_list_size, self.limits.max_frame_size);
    }

    fn writeData(self: *Connection, stream_id: u31, data: []const u8, end_stream: bool) Error!void {
        var ignored_written: usize = 0;
        return self.writeDataTracked(
            stream_id,
            data,
            end_stream,
            &ignored_written,
        );
    }

    fn writeDataTracked(
        self: *Connection,
        stream_id: u31,
        data: []const u8,
        end_stream: bool,
        written: *usize,
    ) Error!void {
        if (!self.outboundStreamIsActive(stream_id)) return error.InvalidStreamId;
        if (self.role == .client and self.pending_client_frame != null) {
            return error.ResponseAvailable;
        }
        written.* = 0;
        const chunk_size = self.outboundFramePayloadLimit();
        if (data.len == 0) {
            try writeFrame(
                self.allocator,
                self.io,
                self.stream,
                .data,
                if (end_stream) flag_end_stream else 0,
                stream_id,
                &.{},
            );
            return;
        }

        var offset: usize = 0;
        while (offset < data.len) {
            const stream_window = try self.sendStreamWindow(stream_id);
            const available_credit = @min(
                data.len - offset,
                self.send_connection_window.available(),
                stream_window.available(),
            );
            if (available_credit == 0) {
                try self.waitForSendCapacity(stream_id);
                continue;
            }

            const burst_limit = std.math.mul(
                usize,
                chunk_size,
                max_data_frames_per_write,
            ) catch std.math.maxInt(usize);
            const burst_len = @min(available_credit, burst_limit);
            try self.writeDataBurst(
                stream_id,
                data[offset..][0..burst_len],
                end_stream and offset + burst_len == data.len,
                chunk_size,
                stream_window,
            );
            offset += burst_len;
            written.* = offset;
        }
    }

    fn writeDataBurst(
        self: *Connection,
        stream_id: u31,
        payload: []const u8,
        end_stream: bool,
        chunk_size: usize,
        stream_window: *FlowWindow,
    ) Error!void {
        std.debug.assert(payload.len != 0);
        std.debug.assert(payload.len <=
            chunk_size *| max_data_frames_per_write);

        try self.send_connection_window.reserve(payload.len);
        errdefer self.send_connection_window.update(
            @intCast(payload.len),
        ) catch unreachable;
        try stream_window.reserve(payload.len);
        errdefer stream_window.update(
            @intCast(payload.len),
        ) catch unreachable;

        var headers: [max_data_frames_per_write][
            http2.FrameHeader.encoded_len
        ]u8 = undefined;
        var parts: [2 * max_data_frames_per_write][]const u8 = undefined;
        var part_count: usize = 0;
        var offset: usize = 0;
        while (offset < payload.len) {
            const end = @min(payload.len, offset + chunk_size);
            const frame_index = part_count / 2;
            try encodeFrameHeader(
                &headers[frame_index],
                .data,
                if (end_stream and end == payload.len)
                    flag_end_stream
                else
                    0,
                stream_id,
                end - offset,
            );
            parts[part_count] = &headers[frame_index];
            parts[part_count + 1] = payload[offset..end];
            part_count += 2;
            offset = end;
        }
        try stream_io.writeAllSlices(
            self.io,
            self.stream,
            parts[0..part_count],
        );
    }

    fn waitForSendCapacity(self: *Connection, stream_id: u31) Error!void {
        while (self.send_connection_window.available() == 0 or (try self.sendStreamWindow(stream_id)).available() == 0) {
            var frame = try self.readOwnedFrame();
            var frame_owned = true;
            defer if (frame_owned) frame.deinit(self.allocator);
            if (try self.handleConnectionFrame(frame.frame)) {
                if (self.push_state.localStatus(stream_id) ==
                    .canceled)
                {
                    return error.StreamReset;
                }
                continue;
            }
            switch (frame.frame.header.frame_type) {
                .goaway => {
                    const goaway = try http2.GoAwayPayload.parse(frame.frame);
                    try self.handleGoAwayForStream(stream_id, goaway);
                },
                .rst_stream => {
                    const reset = try http2.ResetStreamPayload.parse(frame.frame);
                    if (reset.stream_id == stream_id) {
                        self.recordResetStream(reset);
                        return error.StreamReset;
                    }
                },
                .headers, .data, .push_promise => {
                    if (self.role != .client) {
                        return error.UnexpectedFrame;
                    }
                    if (frame.frame.header.stream_id != stream_id) {
                        return error.UnexpectedFrame;
                    }
                    // Transfer the owning frame to the eventual response
                    // reader. Only one can be pending because this method
                    // returns immediately, so peer input cannot grow an
                    // unbounded side queue while the application is uploading.
                    if (self.pending_client_frame != null) {
                        return error.UnexpectedFrame;
                    }
                    self.pending_client_frame = frame;
                    frame_owned = false;
                    return error.ResponseAvailable;
                },
                else => return error.UnexpectedFrame,
            }
        }
    }

    fn applyInitialWindowSize(self: *Connection, value: u32) Error!void {
        if (value > std.math.maxInt(i31)) return error.InvalidSetting;
        const new_window: i64 = value;
        const delta = new_window - self.peer_initial_stream_window;
        var adjusted: usize = 0;
        errdefer {
            var index: usize = 0;
            while (index < adjusted) : (index += 1) {
                self.send_stream_windows.items[index].window.adjust(-delta) catch unreachable;
            }
        }

        for (self.send_stream_windows.items) |*entry| {
            try entry.window.adjust(delta);
            adjusted += 1;
        }
        self.peer_initial_stream_window = new_window;
    }

    fn applySettings(self: *Connection, settings: []const http2.Setting) Error!void {
        for (settings) |setting| {
            switch (setting.id) {
                .initial_window_size => try self.applyInitialWindowSize(setting.value),
                .max_frame_size => {
                    if (setting.value < default_max_frame_size or setting.value > max_max_frame_size) return error.InvalidSetting;
                    self.peer_max_frame_size = setting.value;
                },
                .max_header_list_size => self.peer_max_header_list_size = setting.value,
                .max_concurrent_streams => self.peer_max_concurrent_streams = setting.value,
                .header_table_size => self.hpack_encoder.setMaxDynamicTableSize(self.allocator, setting.value),
                .no_rfc7540_priorities => {
                    if (setting.value > 1) return error.InvalidSetting;
                    const enabled = setting.value == 1;
                    if (self.peer_initial_settings_applied and
                        !self.peer_priority_setting_seen)
                    {
                        // SETTINGS_NO_RFC7540_PRIORITIES is only valid in the
                        // first peer SETTINGS frame.
                        return error.InvalidSetting;
                    }
                    if (self.peer_priority_setting_seen and
                        self.peer_no_rfc7540_priorities != enabled)
                    {
                        // RFC 9218 requires this value in the initial SETTINGS
                        // and forbids changing it later. Rejecting a change
                        // avoids switching scheduling semantics mid-connection.
                        return error.InvalidSetting;
                    }
                    self.peer_priority_setting_seen = true;
                    self.peer_no_rfc7540_priorities = enabled;
                },
                .enable_push => {
                    if (setting.value > 1) return error.InvalidSetting;
                    // RFC 9113 forbids SETTINGS_ENABLE_PUSH in server SETTINGS.
                    // Clients can send 0 to disable server push; a server-to-client
                    // occurrence is a connection-level protocol error.
                    if (self.role == .client) return error.InvalidSetting;
                    self.peer_enable_push = setting.value == 1;
                },
                .enable_connect_protocol => {
                    if (setting.value > 1) return error.InvalidSetting;
                    // RFC 8441 uses SETTINGS_ENABLE_CONNECT_PROTOCOL as an
                    // irreversible opt-in because :protocol changes request
                    // validation semantics.  A peer may omit the setting or
                    // send 0 before opting in, but once 1 has been observed it
                    // must not downgrade the connection back to 0.
                    if (self.peer_enable_connect_protocol and setting.value == 0) return error.InvalidSetting;
                    self.peer_enable_connect_protocol = setting.value == 1;
                },
                else => {},
            }
        }
        self.peer_initial_settings_applied = true;
    }

    fn storeAlternativeService(
        self: *Connection,
        stream_id: u31,
        origin_value: []const u8,
        field_value: []const u8,
    ) Error!void {
        const key = AltSvcKey{
            .stream_id = stream_id,
            .origin = origin_value,
        };
        if (self.alternative_service_index.count() != 0) {
            if (self.alternative_service_index.get(key)) |index| {
                const service = &self.alternative_services.items[index];
                if (std.mem.eql(u8, service.field_value, field_value)) return;

                const origin = try self.allocator.dupe(u8, origin_value);
                errdefer self.allocator.free(origin);
                const value = try self.allocator.dupe(u8, field_value);
                errdefer self.allocator.free(value);
                const key_ptr = self.alternative_service_index.getKeyPtr(key) orelse
                    unreachable;
                key_ptr.* = .{ .stream_id = stream_id, .origin = origin };
                self.allocator.free(service.origin);
                self.allocator.free(service.field_value);
                service.origin = origin;
                service.field_value = value;
                return;
            }
        }
        const slot = try self.alternative_service_index.getOrPut(
            self.allocator,
            key,
        );
        std.debug.assert(!slot.found_existing);
        errdefer _ = self.alternative_service_index.remove(key);
        const origin = try self.allocator.dupe(u8, origin_value);
        errdefer self.allocator.free(origin);
        const value = try self.allocator.dupe(u8, field_value);
        errdefer self.allocator.free(value);
        const index = self.alternative_services.items.len;
        try self.alternative_services.append(self.allocator, .{
            .stream_id = stream_id,
            .origin = origin,
            .field_value = value,
        });
        slot.key_ptr.* = .{ .stream_id = stream_id, .origin = origin };
        slot.value_ptr.* = index;
    }

    fn peerOriginKnown(self: Connection, origin: []const u8) bool {
        return self.peer_origin_index.count() != 0 and
            self.peer_origin_index.contains(origin);
    }

    fn storePeerOrigin(self: *Connection, origin: []const u8) Error!void {
        if (self.peer_origin_index.count() != 0 and
            self.peer_origin_index.contains(origin)) return;
        const slot = try self.peer_origin_index.getOrPut(
            self.allocator,
            origin,
        );
        std.debug.assert(!slot.found_existing);
        errdefer _ = self.peer_origin_index.remove(origin);
        const owned = try self.allocator.dupe(u8, origin);
        errdefer self.allocator.free(owned);
        const index = self.peer_origins.items.len;
        try self.peer_origins.append(self.allocator, owned);
        self.peer_origin_index.getKeyPtr(origin).?.* = owned;
        slot.value_ptr.* = index;
    }

    fn applyLocalLimits(self: *Connection) void {
        self.hpack_decoder.setMaxDynamicTableSize(self.allocator, self.limits.header_table_size);
        self.recv_connection_window.value =
            self.limits.initial_connection_window_size;
    }

    fn outboundFramePayloadLimit(self: Connection) usize {
        // The peer's SETTINGS_MAX_FRAME_SIZE caps every frame payload we send.
        // `limits.max_frame_payload` remains a local/test ceiling used by this
        // minimal runtime to force small fragments, so use the stricter value.
        return @max(@as(usize, 1), @min(self.peer_max_frame_size, self.limits.max_frame_payload));
    }

    fn sendStreamWindow(self: *Connection, stream_id: u31) Error!*FlowWindow {
        if (stream_id == 0) return error.InvalidStreamId;
        const slot = try self.send_stream_window_index.getOrPut(
            self.allocator,
            stream_id,
        );
        if (slot.found_existing) {
            return &self.send_stream_windows.items[slot.value_ptr.*].window;
        }
        errdefer _ = self.send_stream_window_index.remove(stream_id);
        try self.send_stream_windows.ensureUnusedCapacity(self.allocator, 1);
        const index = self.send_stream_windows.items.len;
        self.send_stream_windows.appendAssumeCapacity(.{
            .stream_id = stream_id,
            .window = .{ .value = self.peer_initial_stream_window },
        });
        slot.value_ptr.* = index;
        return &self.send_stream_windows.items[index].window;
    }

    fn sendStreamWindowAvailable(
        self: *const Connection,
        stream_id: u31,
    ) usize {
        if (self.send_stream_window_index.count() != 0) {
            if (self.send_stream_window_index.get(stream_id)) |index| {
                return self.send_stream_windows.items[index].window.available();
            }
        }
        if (self.peer_initial_stream_window <= 0) return 0;
        return @intCast(self.peer_initial_stream_window);
    }

    fn recvStreamWindow(self: *Connection, stream_id: u31) Error!*FlowWindow {
        if (stream_id == 0) return error.InvalidStreamId;
        const slot = try self.recv_stream_window_index.getOrPut(
            self.allocator,
            stream_id,
        );
        if (slot.found_existing) {
            return &self.recv_stream_windows.items[slot.value_ptr.*].window;
        }
        errdefer _ = self.recv_stream_window_index.remove(stream_id);
        try self.recv_stream_windows.ensureUnusedCapacity(self.allocator, 1);
        const index = self.recv_stream_windows.items.len;
        self.recv_stream_windows.appendAssumeCapacity(.{
            .stream_id = stream_id,
            .window = .{ .value = @intCast(self.limits.initial_window_size) },
        });
        slot.value_ptr.* = index;
        return &self.recv_stream_windows.items[index].window;
    }

    fn hasRecvStreamWindow(self: Connection, stream_id: u31) bool {
        return self.recv_stream_window_index.count() != 0 and
            self.recv_stream_window_index.contains(stream_id);
    }
};

pub const RequestOptions = struct {
    method: []const u8 = "GET",
    path: []const u8 = "/",
    /// Optional request URI scheme for the `:scheme` pseudo-header.  When
    /// omitted, the runtime uses the connection's transport-derived default
    /// (`http` for the h2c helpers in this module, `https` for generic callers).
    scheme: ?[]const u8 = null,
    /// RFC 8441 extended CONNECT `:protocol` pseudo-header.  Sending it
    /// requires the peer to advertise SETTINGS_ENABLE_CONNECT_PROTOCOL = 1.
    protocol: ?[]const u8 = null,
    authority: ?[]const u8 = null,
    /// Optional RFC 9218 end-to-end Priority request field. The runtime emits
    /// it as a normal lowercase header; callers can later reprioritize the
    /// response with `sendPriorityUpdate`.
    priority: ?http2.ExtensiblePriority = null,
    headers: []const http2.Hpack.HeaderField = &.{},
    body: []const u8 = &.{},
    trailers: []const http2.Hpack.HeaderField = &.{},
};

pub const StreamingRequestOptions = struct {
    method: []const u8 = "POST",
    path: []const u8 = "/",
    scheme: ?[]const u8 = null,
    authority: ?[]const u8 = null,
    priority: ?http2.ExtensiblePriority = null,
    headers: []const http2.Hpack.HeaderField = &.{},
    /// Exact request body size. When null, the request is length-unbounded and
    /// ends only through RequestWriter FIN or trailers.
    body_length: ?usize = null,
};

pub const ResponseOptions = struct {
    status: u16 = 200,
    headers: []const http2.Hpack.HeaderField = &.{},
    body: []const u8 = &.{},
    trailers: []const http2.Hpack.HeaderField = &.{},
    /// Optional request method for method-specific response semantics.  HEAD
    /// and successful traditional CONNECT responses do not carry HTTP response
    /// bodies even when representation headers such as Content-Length are
    /// present; server helpers fill this automatically when they own the
    /// request/response loop.
    request_method: ?[]const u8 = null,
    extended_connect: bool = false,
};

pub const StreamingResponseOptions = struct {
    status: u16 = 200,
    headers: []const http2.Hpack.HeaderField = &.{},
    /// Optional request method when the response is not started directly from
    /// a request reader. It controls HEAD and CONNECT body semantics.
    request_method: ?[]const u8 = null,
    extended_connect: bool = false,
};

const StreamResponseSemantics = struct {
    stream_id: u31,
    head: bool = false,
    traditional_connect: bool = false,
    extended_connect: bool = false,
    priority: http2.ExtensiblePriority = .{},
};

const ResponseBodySemantics = struct {
    head: bool = false,
    traditional_connect: bool = false,
    extended_connect: bool = false,
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

pub const OwnedRequest = struct {
    stream_id: u31,
    headers: []http2.Hpack.HeaderField,
    method: []const u8,
    path: []const u8,
    scheme: []const u8,
    authority: ?[]const u8,
    protocol: ?[]const u8 = null,
    body: []u8,
    trailers: []http2.Hpack.HeaderField = &.{},
    priority: http2.ExtensiblePriority = .{},

    pub fn deinit(self: *OwnedRequest, allocator: std.mem.Allocator) void {
        freeHeaders(allocator, self.headers);
        freeHeaders(allocator, self.trailers);
        allocator.free(self.body);
        self.* = undefined;
    }
};

pub const StreamingRequest = struct {
    stream_id: u31,
    headers: []http2.Hpack.HeaderField,
    method: []const u8,
    path: []const u8,
    scheme: []const u8,
    authority: ?[]const u8,
    protocol: ?[]const u8 = null,
    body_bytes: usize,
    trailers: []http2.Hpack.HeaderField = &.{},
    priority: http2.ExtensiblePriority = .{},

    pub fn deinit(
        self: *StreamingRequest,
        allocator: std.mem.Allocator,
    ) void {
        freeHeaders(allocator, self.headers);
        freeHeaders(allocator, self.trailers);
        self.* = undefined;
    }
};

/// Validated request metadata delivered before streaming DATA.
pub const StreamingRequestHead = struct {
    stream_id: u31,
    headers: []const http2.Hpack.HeaderField,
    method: []const u8,
    path: []const u8,
    scheme: []const u8,
    authority: ?[]const u8,
    protocol: ?[]const u8 = null,

    fn fromOwned(request: OwnedRequest) StreamingRequestHead {
        return .{
            .stream_id = request.stream_id,
            .headers = request.headers,
            .method = request.method,
            .path = request.path,
            .scheme = request.scheme,
            .authority = request.authority,
            .protocol = request.protocol,
        };
    }
};

fn streamingRequestFromOwned(request: OwnedRequest) StreamingRequest {
    return .{
        .stream_id = request.stream_id,
        .headers = request.headers,
        .method = request.method,
        .path = request.path,
        .scheme = request.scheme,
        .authority = request.authority,
        .protocol = request.protocol,
        .body_bytes = request.body.len,
        .trailers = request.trailers,
        .priority = request.priority,
    };
}

pub const OwnedResponse = struct {
    headers: []http2.Hpack.HeaderField,
    status: u16,
    body: []u8,
    trailers: []http2.Hpack.HeaderField = &.{},

    pub fn deinit(self: *OwnedResponse, allocator: std.mem.Allocator) void {
        freeHeaders(allocator, self.headers);
        freeHeaders(allocator, self.trailers);
        allocator.free(self.body);
        self.* = undefined;
    }
};

pub const StreamingResponse = struct {
    headers: []http2.Hpack.HeaderField,
    status: u16,
    body_bytes: usize,
    trailers: []http2.Hpack.HeaderField = &.{},

    pub fn deinit(
        self: *StreamingResponse,
        allocator: std.mem.Allocator,
    ) void {
        freeHeaders(allocator, self.headers);
        freeHeaders(allocator, self.trailers);
        self.* = undefined;
    }
};

/// Final (non-informational) response metadata delivered before DATA.
pub const StreamingResponseHead = struct {
    headers: []const http2.Hpack.HeaderField,
    status: u16,
};

fn ignoreStreamingRequestHead(
    context: anytype,
    head: StreamingRequestHead,
) !void {
    _ = context;
    _ = head;
}

fn ignoreStreamingResponseHead(
    context: anytype,
    head: StreamingResponseHead,
) !void {
    _ = context;
    _ = head;
}

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
        self.connection.sendResetStream(
            self.stream_id,
            .cancel,
        ) catch {
            self.connection.releaseLocalStream(self.stream_id);
        };
        self.completed = true;
    }

    pub fn write(
        self: *RequestWriter,
        data: []const u8,
    ) Error!void {
        try self.ensureWritable();
        try self.reserveLength(data.len, false);
        var sent: usize = 0;
        self.connection.writeDataTracked(
            self.stream_id,
            data,
            false,
            &sent,
        ) catch |err| switch (err) {
            error.ResponseAvailable => {
                self.written += sent;
                self.body_finished = true;
                // Stop the request half while preserving the peer's already
                // buffered response frame for readResponse*. Use the raw frame
                // writer because the tracked DATA helper intentionally refuses
                // further request DATA once a response is pending.
                writeFrame(
                    self.connection.allocator,
                    self.connection.io,
                    self.connection.stream,
                    .data,
                    flag_end_stream,
                    self.stream_id,
                    &.{},
                ) catch {};
                return error.ResponseAvailable;
            },
            else => return err,
        };
        self.written += sent;
    }

    pub fn finishData(
        self: *RequestWriter,
        data: []const u8,
    ) Error!void {
        try self.ensureWritable();
        try self.reserveLength(data.len, true);
        var sent: usize = 0;
        self.connection.writeDataTracked(
            self.stream_id,
            data,
            true,
            &sent,
        ) catch |err| switch (err) {
            error.ResponseAvailable => {
                self.written += sent;
                self.body_finished = true;
                writeFrame(
                    self.connection.allocator,
                    self.connection.io,
                    self.connection.stream,
                    .data,
                    flag_end_stream,
                    self.stream_id,
                    &.{},
                ) catch {};
                return error.ResponseAvailable;
            },
            else => return err,
        };
        self.written += sent;
        self.body_finished = true;
    }

    pub fn finish(self: *RequestWriter) Error!void {
        return self.finishData(&.{});
    }

    pub fn finishTrailers(
        self: *RequestWriter,
        trailers: []const http2.Hpack.HeaderField,
    ) Error!void {
        try self.ensureWritable();
        try self.reserveLength(0, true);
        try validateHeaderBlock(trailers, .request_trailers);
        try self.connection.writeHeaders(
            self.stream_id,
            trailers,
            true,
        );
        self.body_finished = true;
    }

    /// Receive the response after the request body has ended.
    pub fn readResponse(
        self: *RequestWriter,
    ) Error!OwnedResponse {
        if (!self.body_finished or self.completed) {
            return error.UnexpectedFrame;
        }
        const connection = self.connection;
        const stream_id = self.stream_id;
        const request_method = if (self.head_request) "HEAD" else "POST";
        const response = connection.readResponse(
            stream_id,
            request_method,
            false,
        ) catch |err| {
            // readResponse releases the stream on every exit path.
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

    pub fn readResponseStreamingWithHead(
        self: *RequestWriter,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
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

    pub fn reset(
        self: *RequestWriter,
        error_code: http2.ErrorCode,
    ) Error!void {
        try self.ensureWritable();
        try self.connection.sendResetStream(self.stream_id, error_code);
        self.body_finished = true;
        self.completed = true;
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
        self.connection.sendResetStream(
            self.stream_id,
            .cancel,
        ) catch {
            // A transport failure may prevent emitting RST_STREAM, but local
            // ownership must still be released so connection teardown does not
            // retain stale response semantics.
            self.connection.releasePeerStream(self.stream_id);
        };
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
        try self.ensureWritable();
        try self.reserveLength(data.len, false);
        try self.connection.writeData(self.stream_id, data, false);
        self.written += data.len;
    }

    /// Write the final DATA chunk with END_STREAM.
    pub fn finishData(
        self: *ResponseWriter,
        data: []const u8,
    ) Error!void {
        try self.ensureWritable();
        try self.reserveLength(data.len, true);
        try self.connection.writeData(self.stream_id, data, true);
        self.written += data.len;
        self.finishState();
    }

    /// Finish a response with an empty END_STREAM DATA frame.
    pub fn finish(self: *ResponseWriter) Error!void {
        return self.finishData(&.{});
    }

    /// Finish with response trailers. Trailers carry END_STREAM themselves.
    pub fn finishTrailers(
        self: *ResponseWriter,
        trailers: []const http2.Hpack.HeaderField,
    ) Error!void {
        try self.ensureWritable();
        try self.reserveLength(0, true);
        try validateHeaderBlock(trailers, .response_trailers);
        try self.connection.writeHeaders(
            self.stream_id,
            trailers,
            true,
        );
        self.finishState();
    }

    pub fn reset(
        self: *ResponseWriter,
        error_code: http2.ErrorCode,
    ) Error!void {
        try self.ensureWritable();
        try self.connection.sendResetStream(
            self.stream_id,
            error_code,
        );
        self.finished = true;
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

pub const OwnedTunnelData = struct {
    frame: OwnedFrame,
    data: []const u8,
    end_stream: bool,

    pub fn deinit(self: *OwnedTunnelData, allocator: std.mem.Allocator) void {
        self.frame.deinit(allocator);
        self.* = undefined;
    }
};

pub const Tunnel = struct {
    connection: *Connection,
    stream_id: u31,

    pub fn write(self: *Tunnel, data: []const u8, end_stream: bool) Error!void {
        try self.connection.writeData(self.stream_id, data, end_stream);
        if (end_stream) {
            self.connection.releaseLocalStream(self.stream_id);
            self.connection.releasePeerStream(self.stream_id);
        }
    }

    pub fn closeWrite(self: *Tunnel) Error!void {
        try self.connection.writeData(self.stream_id, &.{}, true);
    }

    pub fn reset(self: *Tunnel, error_code: http2.ErrorCode) Error!void {
        try self.connection.sendResetStream(self.stream_id, error_code);
    }

    pub fn read(self: *Tunnel) Error!OwnedTunnelData {
        while (true) {
            var frame = try self.connection.readOwnedFrame();
            errdefer frame.deinit(self.connection.allocator);
            if (try self.connection.handleConnectionFrame(frame.frame)) {
                frame.deinit(self.connection.allocator);
                continue;
            }
            if (frame.frame.header.frame_type == .goaway) {
                const goaway = try http2.GoAwayPayload.parse(frame.frame);
                try self.connection.handleGoAwayForStream(self.stream_id, goaway);
                frame.deinit(self.connection.allocator);
                continue;
            }
            if (frame.frame.header.stream_id != self.stream_id) {
                frame.deinit(self.connection.allocator);
                return error.UnexpectedFrame;
            }
            switch (frame.frame.header.frame_type) {
                .data => {
                    const payload = try self.connection.receiveDataPayload(self.stream_id, frame.frame);
                    try self.connection.maybeReleaseReceivedCapacity(self.stream_id);
                    const end_stream = (frame.frame.header.flags & flag_end_stream) != 0;
                    return .{
                        .frame = frame,
                        .data = payload.data,
                        .end_stream = end_stream,
                    };
                },
                .rst_stream => {
                    self.connection.releaseLocalStream(self.stream_id);
                    self.connection.releasePeerStream(self.stream_id);
                    return error.StreamReset;
                },
                .headers => return error.UnexpectedFrame,
                else => {
                    frame.deinit(self.connection.allocator);
                    continue;
                },
            }
        }
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

pub const OwnedFrame = struct {
    bytes: []u8,
    frame: http2.Frame,

    pub fn deinit(self: *OwnedFrame, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

fn readFrame(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, limits: Limits) Error!OwnedFrame {
    var header_buf: [@intCast(http2.FrameHeader.encoded_len)]u8 = undefined;
    try readExact(io, stream, &header_buf);
    const header = try http2.FrameHeader.parse(&header_buf);
    const payload_len: usize = header.length;
    // SETTINGS_MAX_FRAME_SIZE is the receive ceiling we advertise to the peer.
    // Keep the older max_frame_payload guard as a local allocation/test budget,
    // but enforce the stricter of the two before allocating the payload buffer.
    const inbound_payload_limit = @min(limits.max_frame_payload, limits.max_frame_size);
    if (payload_len > inbound_payload_limit) return error.MessageTooLarge;

    const bytes = try allocator.alloc(u8, header_buf.len + payload_len);
    errdefer allocator.free(bytes);
    @memcpy(bytes[0..header_buf.len], &header_buf);
    try readExact(io, stream, bytes[header_buf.len..]);
    const frame = try http2.Frame.parse(bytes);
    try validateFrameEnvelope(frame);
    return .{ .bytes = bytes, .frame = frame };
}

fn validateFrameEnvelope(frame: http2.Frame) Error!void {
    if (frame.payload.len != @as(usize, frame.header.length)) return error.InvalidFrame;

    const stream_id = frame.header.stream_id;
    switch (frame.header.frame_type) {
        .data,
        .headers,
        .continuation,
        => if (stream_id == 0) return error.InvalidFrame,

        .priority => {
            if (stream_id == 0 or frame.payload.len != 5) return error.InvalidFrame;
        },

        .rst_stream => {
            if (stream_id == 0 or frame.payload.len != 4) return error.InvalidFrame;
        },

        .settings => {
            if (stream_id != 0) return error.InvalidFrame;
            if ((frame.header.flags & flag_ack) != 0) {
                if (frame.payload.len != 0) return error.InvalidFrame;
            } else if (frame.payload.len % 6 != 0) return error.InvalidFrame;
        },
        .ping => {
            if (stream_id != 0 or frame.payload.len != 8) return error.InvalidFrame;
        },
        .goaway => {
            if (stream_id != 0 or frame.payload.len < 8) return error.InvalidFrame;
        },
        .priority_update => {
            if (stream_id != 0 or frame.payload.len < 4) {
                return error.InvalidFrame;
            }
        },
        .altsvc, .origin => {},
        .window_update => {
            if (frame.payload.len != 4) return error.InvalidFrame;
            const increment = std.mem.readInt(u32, frame.payload[0..4], .big) & 0x7fff_ffff;
            if (increment == 0) return error.InvalidFrame;
        },
        .push_promise => if (stream_id == 0) return error.InvalidFrame,
        _ => {},
    }
}

fn clientInitiatedStreamId(stream_id: u31) bool {
    return stream_id != 0 and (stream_id & 1) == 1;
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
    _ = allocator;
    var header: [http2.FrameHeader.encoded_len]u8 = undefined;
    try encodeFrameHeader(
        &header,
        frame_type,
        flags,
        stream_id,
        payload.len,
    );
    try stream_io.writeAllParts(io, stream, &header, payload);
}

fn encodeFrameHeader(
    header: *[http2.FrameHeader.encoded_len]u8,
    frame_type: http2.FrameType,
    flags: u8,
    stream_id: u31,
    payload_length: usize,
) Error!void {
    const payload_len = std.math.cast(u24, payload_length) orelse
        return error.InvalidFrameSize;
    header[0] = @truncate(payload_len >> 16);
    header[1] = @truncate(payload_len >> 8);
    header[2] = @truncate(payload_len);
    header[3] = @intFromEnum(frame_type);
    header[4] = flags;
    std.mem.writeInt(u32, header[5..9], @as(u32, stream_id), .big);
}

fn encodeWindowUpdateFrame(
    output: []u8,
    stream_id: u31,
    increment: u31,
) Error!void {
    std.debug.assert(output.len == http2.FrameHeader.encoded_len + 4);
    const header: *[http2.FrameHeader.encoded_len]u8 =
        @ptrCast(output.ptr);
    try encodeFrameHeader(
        header,
        .window_update,
        0,
        stream_id,
        4,
    );
    std.mem.writeInt(
        u32,
        output[http2.FrameHeader.encoded_len..][0..4],
        increment,
        .big,
    );
}

fn appendFrameBytes(
    batch: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    frame_type: http2.FrameType,
    flags: u8,
    stream_id: u31,
    payload: []const u8,
) Error!void {
    const total_len = std.math.add(
        usize,
        http2.FrameHeader.encoded_len,
        payload.len,
    ) catch return error.InvalidFrameSize;
    const start = batch.items.len;
    try batch.ensureUnusedCapacity(allocator, total_len);
    batch.items.len = start + total_len;
    const header = batch.items[start..][0..http2.FrameHeader.encoded_len];
    const header_array: *[http2.FrameHeader.encoded_len]u8 =
        @ptrCast(header.ptr);
    try encodeFrameHeader(
        header_array,
        frame_type,
        flags,
        stream_id,
        payload.len,
    );
    @memcpy(
        batch.items[start + http2.FrameHeader.encoded_len ..][0..payload.len],
        payload,
    );
}

fn appendHeaderBlockBytes(
    batch: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    stream_id: u31,
    block: []const u8,
    end_stream: bool,
    chunk_size: usize,
) Error!void {
    std.debug.assert(chunk_size != 0);
    const first_len = @min(block.len, chunk_size);
    try appendFrameBytes(
        batch,
        allocator,
        .headers,
        (if (first_len == block.len) flag_end_headers else 0) |
            (if (end_stream) flag_end_stream else 0),
        stream_id,
        block[0..first_len],
    );
    var offset = first_len;
    while (offset < block.len) {
        const end = @min(block.len, offset + chunk_size);
        try appendFrameBytes(
            batch,
            allocator,
            .continuation,
            if (end == block.len) flag_end_headers else 0,
            stream_id,
            block[offset..end],
        );
        offset = end;
    }
}

fn validateLocalLimits(limits: Limits) Error!void {
    if (limits.initial_window_size > std.math.maxInt(i31)) return error.InvalidSetting;
    if (limits.initial_connection_window_size < default_flow_window or
        limits.initial_connection_window_size > std.math.maxInt(i31))
    {
        return error.InvalidSetting;
    }
    if (limits.max_frame_size < default_max_frame_size or limits.max_frame_size > max_max_frame_size) return error.InvalidSetting;
    if (limits.max_continuation_frames) |limit| if (limit == 0) return error.InvalidSetting;
    if (limits.max_idle_priority_updates == 0) return error.InvalidSetting;
}

fn calcMaxContinuationFrames(header_max: usize, frame_max: usize) usize {
    const min_frames_for_list = @max(header_max / frame_max, 1);
    const padding = min_frames_for_list >> 2;
    return @max(min_frames_for_list +| padding, 5);
}

fn writeInitialSettings(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, limits: Limits, role: Role) Error!void {
    const settings = try settingsForLimits(limits, role);
    var payload_buf: [max_settings_payload_len]u8 = undefined;
    const payload = try encodeSettingsPayloadInto(&payload_buf, settings.buf[0..settings.count]);
    try writeFrame(allocator, io, stream, .settings, 0, 0, payload);
}

fn writeInitialConnectionWindow(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
) Error!void {
    if (limits.initial_connection_window_size == default_flow_window) return;
    const increment: u31 = @intCast(
        limits.initial_connection_window_size - default_flow_window,
    );
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, increment, .big);
    try writeFrame(
        allocator,
        io,
        stream,
        .window_update,
        0,
        0,
        &payload,
    );
}

fn cloneDecodedHeaders(
    allocator: std.mem.Allocator,
    block: []const u8,
    limits: Limits,
    decoder: *http2.Hpack.Decoder,
) Error![]http2.Hpack.HeaderField {
    var stack_scratch: [32]http2.Hpack.HeaderField = undefined;
    const scratch = if (limits.max_header_fields <= stack_scratch.len)
        stack_scratch[0..limits.max_header_fields]
    else
        try allocator.alloc(http2.Hpack.HeaderField, limits.max_header_fields);
    defer if (limits.max_header_fields > stack_scratch.len) allocator.free(scratch);
    const decoded = decoder.decodeBlockInto(allocator, block, scratch) catch |err| switch (err) {
        error.BufferTooShort => return error.MessageTooLarge,
        else => |e| return e,
    };
    defer http2.Hpack.freeDecodedFieldStorages(allocator, decoded);
    try validateHeaderListSize(decoded, limits.max_header_list_size);
    const cloned = try allocator.alloc(http2.Hpack.HeaderField, decoded.len);
    errdefer allocator.free(cloned);
    if (decoded.len == 0) return cloned;
    var string_bytes: usize = 0;
    for (decoded) |field| {
        string_bytes = std.math.add(
            usize,
            string_bytes,
            field.name.len,
        ) catch return error.MessageTooLarge;
        string_bytes = std.math.add(
            usize,
            string_bytes,
            field.value.len,
        ) catch return error.MessageTooLarge;
    }
    const string_storage = try allocator.alloc(u8, string_bytes);
    errdefer allocator.free(string_storage);
    var string_offset: usize = 0;
    for (decoded, cloned, 0..) |field, *out, index| {
        const name = string_storage[string_offset..][0..field.name.len];
        @memcpy(name, field.name);
        string_offset += name.len;
        const value = string_storage[string_offset..][0..field.value.len];
        @memcpy(value, field.value);
        string_offset += value.len;
        out.* = .{
            .name = name,
            .value = value,
            .never_index = field.never_index,
            .block_storage = if (index == 0) string_storage else null,
        };
    }
    std.debug.assert(string_offset == string_storage.len);
    return cloned;
}

fn freeHeaders(allocator: std.mem.Allocator, headers: []http2.Hpack.HeaderField) void {
    if (headers.len != 0) {
        if (headers[0].block_storage) |storage| {
            allocator.free(storage);
            allocator.free(headers);
            return;
        }
    }
    for (headers) |header| {
        allocator.free(header.name);
        allocator.free(header.value);
    }
    allocator.free(headers);
}

fn contentLength(headers: []const http2.Hpack.HeaderField) Error!?usize {
    var found: ?usize = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "content-length")) continue;
        try parseContentLengthHeaderValue(header.value, &found);
    }
    return found;
}

fn parseContentLengthHeaderValue(value: []const u8, found: *?usize) Error!void {
    var parts = std.mem.splitScalar(u8, value, ',');
    while (parts.next()) |raw_part| {
        const part = std.mem.trim(u8, raw_part, " \t");
        if (part.len == 0) return error.InvalidContentLength;
        for (part) |byte| {
            if (!std.ascii.isDigit(byte)) return error.InvalidContentLength;
        }
        const parsed = std.fmt.parseInt(usize, part, 10) catch return error.InvalidContentLength;
        if (found.*) |existing| {
            if (existing != parsed) return error.InvalidContentLength;
        } else {
            found.* = parsed;
        }
    }
}

const ResponseHeaderLookup = struct {
    status: ?[]const u8 = null,
    content_length: ?usize = null,
};

fn responseHeaderLookup(headers: []const http2.Hpack.HeaderField) Error!ResponseHeaderLookup {
    var lookup: ResponseHeaderLookup = .{};
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, ":status")) {
            if (lookup.status == null) lookup.status = header.value;
            continue;
        }
        if (!std.ascii.eqlIgnoreCase(header.name, "content-length")) continue;
        try parseContentLengthHeaderValue(header.value, &lookup.content_length);
    }
    return lookup;
}

fn validateContentLength(headers: []const http2.Hpack.HeaderField, actual: usize) Error!void {
    try validateExpectedContentLength(try contentLength(headers), actual);
}

fn validateExpectedContentLength(expected: ?usize, actual: usize) Error!void {
    if (expected) |value| {
        if (value != actual) return error.InvalidContentLength;
    }
}

fn validateDeclaredRequestLength(headers: []const http2.Hpack.HeaderField, body_len: usize) Error!void {
    if (try contentLength(headers)) |expected| {
        if (expected != body_len) return error.InvalidContentLength;
    }
}

fn requestShouldDefaultContentLength(method: []const u8, headers: []const http2.Hpack.HeaderField, body_len: usize) bool {
    if (methodIsConnect(method)) return false;
    // Match Hyper's h2 request shaping: exact non-empty bodies always get a
    // length, and bodyless methods with defined payload semantics (for example
    // POST/PUT/PATCH) get an explicit `content-length: 0`.  The explicit zero
    // preserves application intent for methods where an empty payload is
    // materially different from a method that normally carries no payload.
    if (body_len == 0 and !methodHasDefinedPayloadSemantics(method)) return false;
    return (contentLength(headers) catch return false) == null;
}

fn stripConnectionHeaders(headers: *std.ArrayList(http2.Hpack.HeaderField), kind: HeaderBlockKind) void {
    var connection_values: [256][]const u8 = undefined;
    var connection_value_count: usize = 0;
    for (headers.items) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "connection")) continue;
        if (connection_value_count < connection_values.len) {
            connection_values[connection_value_count] = header.value;
            connection_value_count += 1;
        }
    }

    var write_index: usize = 0;
    for (headers.items, 0..) |header, read_index| {
        // Hyper strips outbound HTTP/1 hop-by-hop metadata before handing a
        // header map to h2. Do the same at the convenience writer boundary so
        // callers that forward HTTP/1 headers do not have to pre-filter every
        // field.  This compacts in one pass instead of repeatedly shifting the
        // tail with orderedRemove when forwarded header maps contain many
        // hop-by-hop fields.
        if (stripConnectionHeaderAt(headers.items, read_index, kind, connection_values[0..connection_value_count])) continue;
        headers.items[write_index] = header;
        write_index += 1;
    }
    headers.shrinkRetainingCapacity(write_index);
}

fn stripSuccessfulConnectContentLength(headers: *std.ArrayList(http2.Hpack.HeaderField)) Error!void {
    const declared = try contentLength(headers.items) orelse return;
    if (declared != 0) return error.InvalidContentLength;

    var write_index: usize = 0;
    for (headers.items) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "content-length")) {
            // Hyper allows `content-length: 0` on successful CONNECT responses
            // for peer compatibility, but strips it before sending such a
            // response itself.  The stream is a tunnel after the 2xx HEADERS, so
            // retaining even a zero representation length is misleading metadata.
            continue;
        }
        headers.items[write_index] = header;
        write_index += 1;
    }
    headers.shrinkRetainingCapacity(write_index);
}

fn stripConnectionHeaderAt(headers: []const http2.Hpack.HeaderField, index: usize, kind: HeaderBlockKind, connection_values: []const []const u8) bool {
    const header = headers[index];
    if (std.ascii.eqlIgnoreCase(header.name, "connection")) return true;
    if (connectionSpecificHeaderName(header.name)) return true;
    if (std.ascii.eqlIgnoreCase(header.name, "te") and (kind != .request or !std.ascii.eqlIgnoreCase(std.mem.trim(u8, header.value, " \t"), "trailers"))) return true;

    for (connection_values) |value| {
        var tokens = std.mem.splitScalar(u8, value, ',');
        while (tokens.next()) |raw_token| {
            const token = std.mem.trim(u8, raw_token, " \t");
            if (token.len != 0 and std.ascii.eqlIgnoreCase(header.name, token)) return true;
        }
    }
    return false;
}

fn validateHeaderListSize(headers: []const http2.Hpack.HeaderField, max_size: usize) Error!void {
    var total: usize = 0;
    for (headers) |header| {
        // RFC 9113 measures SETTINGS_MAX_HEADER_LIST_SIZE as the uncompressed
        // field section size: name bytes + value bytes + 32 bytes overhead per
        // field.  Enforcing the same accounting protects both inbound decoded
        // headers and outbound headers constrained by the peer's SETTINGS.
        total = std.math.add(usize, total, header.name.len) catch return error.MessageTooLarge;
        total = std.math.add(usize, total, header.value.len) catch return error.MessageTooLarge;
        total = std.math.add(usize, total, 32) catch return error.MessageTooLarge;
        if (total > max_size) return error.MessageTooLarge;
    }
}

const HeaderBlockKind = enum {
    request,
    response,
    request_trailers,
    response_trailers,
};

fn validateHeaderBlock(headers: []const http2.Hpack.HeaderField, kind: HeaderBlockKind) Error!void {
    var saw_regular = false;
    var seen_method = false;
    var seen_scheme = false;
    var seen_path = false;
    var seen_authority = false;
    var seen_protocol = false;
    var seen_status = false;
    var method_value: ?[]const u8 = null;
    var scheme_value: ?[]const u8 = null;
    var path_value: ?[]const u8 = null;
    var authority_value: ?[]const u8 = null;
    var protocol_value: ?[]const u8 = null;
    var status_value: ?[]const u8 = null;
    var host_value: ?[]const u8 = null;

    for (headers) |header| {
        try validateHeaderName(header.name);
        try validateHeaderValue(header.value);
        const pseudo = std.mem.startsWith(u8, header.name, ":");
        if (pseudo) {
            if (saw_regular) return error.InvalidHeader;
            switch (kind) {
                .request => {
                    try markRequestPseudo(header.name, &seen_method, &seen_scheme, &seen_path, &seen_authority, &seen_protocol);
                    if (std.mem.eql(u8, header.name, ":method")) method_value = header.value;
                    if (std.mem.eql(u8, header.name, ":scheme")) scheme_value = header.value;
                    if (std.mem.eql(u8, header.name, ":path")) path_value = header.value;
                    if (std.mem.eql(u8, header.name, ":authority")) authority_value = header.value;
                    if (std.mem.eql(u8, header.name, ":protocol")) protocol_value = header.value;
                },
                .response => {
                    try markResponsePseudo(header.name, &seen_status);
                    if (std.mem.eql(u8, header.name, ":status")) status_value = header.value;
                },
                .request_trailers, .response_trailers => return error.InvalidHeader,
            }
            continue;
        }
        saw_regular = true;

        if (kind == .request_trailers or kind == .response_trailers) {
            if (forbiddenTrailerFieldName(header.name)) return error.InvalidHeader;
        }
        if (std.ascii.eqlIgnoreCase(header.name, "connection")) {
            // RFC 9113 inherits the HTTP/1.1 Connection token rule: anything
            // nominated by Connection is connection-specific and forbidden in
            // HTTP/2.  Rejecting the field itself is stricter than stripping and
            // prevents peers from smuggling hop-by-hop semantics through a block
            // that another endpoint might forward.
            return error.InvalidHeader;
        }
        if (connectionSpecificHeaderName(header.name)) return error.InvalidHeader;
        if (std.ascii.eqlIgnoreCase(header.name, "te")) {
            switch (kind) {
                .request => if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, header.value, " \t"), "trailers")) return error.InvalidHeader,
                else => return error.InvalidHeader,
            }
        }
        if (std.ascii.eqlIgnoreCase(header.name, "host")) {
            if (host_value != null) return error.InvalidHeader;
            host_value = header.value;
        }
    }

    switch (kind) {
        .request => {
            if (!seen_method) return error.MissingPseudoHeader;
            const method_present = method_value orelse return error.MissingPseudoHeader;
            try validateHttpToken(method_present);
            if (scheme_value) |scheme| try validateUriScheme(scheme);
            if (path_value) |path| try validateUriPath(method_present, path);
            if (authority_value) |authority| try validateRequestAuthority(authority);
            if (host_value) |host| try validateRequestAuthority(host);
            if (authority_value) |authority| {
                if (host_value) |host| {
                    // RFC 9113 allows translating HTTP/1 Host into HTTP/2, but
                    // an HTTP/2 block that carries both names must not describe
                    // two different authorities.  Hyper/h2 builds a single URI
                    // authority; reject disagreement before forwarding can pick
                    // a different origin than application code observes.
                    if (!std.ascii.eqlIgnoreCase(authority, host)) return error.InvalidHeader;
                }
            }
            if (protocol_value) |protocol| {
                try validateHttpToken(protocol);
                const method = method_value orelse return error.MissingPseudoHeader;
                if (!methodIsConnect(method)) return error.InvalidHeader;
                if (!seen_scheme or !seen_path) return error.MissingPseudoHeader;
                if (!seen_authority and host_value == null) return error.MissingPseudoHeader;
            } else if (method_value) |method| {
                if (methodIsConnect(method)) {
                    if (!seen_authority) return error.MissingPseudoHeader;
                    if (seen_scheme or seen_path) return error.InvalidHeader;
                    try validateConnectAuthority(authority_value.?);
                } else if (!seen_scheme or !seen_path) return error.MissingPseudoHeader;
            }
        },
        .response => {
            if (!seen_status) return error.MissingPseudoHeader;
            const status = status_value orelse return error.MissingPseudoHeader;
            if (status.len != 3) return error.InvalidStatus;
            for (status) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidStatus;
            const parsed_status = std.fmt.parseInt(u16, status, 10) catch return error.InvalidStatus;
            if (parsed_status < 100) return error.InvalidStatus;
            if (parsed_status == 101) return error.InvalidStatus;
        },
        .request_trailers, .response_trailers => {},
    }
}

fn validateHeaderName(name: []const u8) Error!void {
    if (name.len == 0) return error.InvalidHeader;
    if (name[0] == ':') {
        if (name.len == 1) return error.InvalidHeader;
        for (name[1..]) |byte| {
            if (byte >= 'A' and byte <= 'Z') return error.InvalidHeader;
            if (!validHeaderNameByte(byte)) return error.InvalidHeader;
        }
        return;
    }
    for (name) |byte| {
        if (byte >= 'A' and byte <= 'Z') return error.InvalidHeader;
        if (!validHeaderNameByte(byte)) return error.InvalidHeader;
    }
}

fn validateHeaderValue(value: []const u8) Error!void {
    for (value) |byte| {
        if ((byte < 0x20 and byte != '\t') or byte == 0x7f) return error.InvalidHeader;
    }
}

fn validateHttpToken(value: []const u8) Error!void {
    if (value.len == 0) return error.InvalidHeader;
    for (value) |byte| {
        if (!isHttpTchar(byte)) return error.InvalidHeader;
    }
}

fn methodIsHead(method: []const u8) bool {
    return std.mem.eql(u8, method, "HEAD");
}

fn methodIsConnect(method: []const u8) bool {
    return std.mem.eql(u8, method, "CONNECT");
}

fn methodHasDefinedPayloadSemantics(method: []const u8) bool {
    return !std.mem.eql(u8, method, "GET") and
        !methodIsHead(method) and
        !std.mem.eql(u8, method, "DELETE") and
        !methodIsConnect(method);
}

fn methodIsOptions(method: []const u8) bool {
    return std.mem.eql(u8, method, "OPTIONS");
}

fn isHttpTchar(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or switch (byte) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

fn validateUriScheme(scheme: []const u8) Error!void {
    if (scheme.len == 0) return error.InvalidHeader;
    if (!std.ascii.isAlphabetic(scheme[0])) return error.InvalidHeader;
    for (scheme[1..]) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or byte == '+' or byte == '-' or byte == '.')) return error.InvalidHeader;
    }
}

fn validateUriPath(method: []const u8, path: []const u8) Error!void {
    if (path.len == 0) return error.InvalidHeader;
    if (std.mem.eql(u8, path, "*")) {
        if (!methodIsOptions(method)) return error.InvalidHeader;
        return;
    }
    if (path[0] != '/') return error.InvalidHeader;
    var saw_fragment = false;
    for (path) |byte| {
        if (byte <= 0x20 or byte == 0x7f) return error.InvalidHeader;
        if (byte == '\\') return error.InvalidHeader;
        if (byte == '#') saw_fragment = true;
    }
    // URI fragments identify client-side secondary resources and are not sent
    // in request-targets.  Reject instead of accepting/truncating so origin
    // servers and intermediaries do not disagree on cache keys.
    if (saw_fragment) return error.InvalidHeader;
}

fn validateRequestAuthority(authority: []const u8) Error!void {
    if (authority.len == 0) return error.InvalidHeader;
    for (authority) |byte| {
        if (byte <= 0x20 or byte == 0x7f or byte == '/' or byte == '\\' or byte == '?' or byte == '#' or byte == '@') return error.InvalidHeader;
    }

    if (authority[0] == '[') {
        const end = std.mem.indexOfScalar(u8, authority, ']') orelse return error.InvalidHeader;
        if (end <= 1) return error.InvalidHeader;
        if (end + 1 < authority.len and authority[end + 1] != ':') return error.InvalidHeader;
        if (end + 1 == authority.len) return;
        try validateAuthorityPort(authority[end + 2 ..]);
        return;
    }

    if (std.mem.indexOfScalar(u8, authority, '[') != null or
        std.mem.indexOfScalar(u8, authority, ']') != null) return error.InvalidHeader;
    const first_colon = std.mem.indexOfScalar(u8, authority, ':');
    if (first_colon) |colon| {
        if (colon == 0) return error.InvalidHeader;
        if (std.mem.indexOfScalar(u8, authority[colon + 1 ..], ':') != null) return error.InvalidHeader;
        try validateAuthorityPort(authority[colon + 1 ..]);
    }
}

fn validateAuthorityPort(port: []const u8) Error!void {
    if (port.len == 0) return error.InvalidHeader;
    for (port) |byte| {
        if (!std.ascii.isDigit(byte)) return error.InvalidHeader;
    }
    const parsed_port = std.fmt.parseInt(u32, port, 10) catch return error.InvalidHeader;
    if (parsed_port > std.math.maxInt(u16)) return error.InvalidHeader;
}

fn validHeaderNameByte(byte: u8) bool {
    return std.ascii.isLower(byte) or std.ascii.isDigit(byte) or switch (byte) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

fn markRequestPseudo(
    name: []const u8,
    seen_method: *bool,
    seen_scheme: *bool,
    seen_path: *bool,
    seen_authority: *bool,
    seen_protocol: *bool,
) Error!void {
    if (std.mem.eql(u8, name, ":method")) return markOnce(seen_method);
    if (std.mem.eql(u8, name, ":scheme")) return markOnce(seen_scheme);
    if (std.mem.eql(u8, name, ":path")) return markOnce(seen_path);
    if (std.mem.eql(u8, name, ":authority")) return markOnce(seen_authority);
    if (std.mem.eql(u8, name, ":protocol")) return markOnce(seen_protocol);
    return error.InvalidHeader;
}

fn markResponsePseudo(name: []const u8, seen_status: *bool) Error!void {
    if (std.mem.eql(u8, name, ":status")) return markOnce(seen_status);
    return error.InvalidHeader;
}

fn markOnce(seen: *bool) Error!void {
    if (seen.*) return error.InvalidHeader;
    seen.* = true;
}

fn validateConnectAuthority(authority: []const u8) Error!void {
    try validateRequestAuthority(authority);
    const port: []const u8 = if (authority[0] == '[') blk: {
        const end = std.mem.indexOfScalar(u8, authority, ']') orelse return error.InvalidHeader;
        if (end <= 1 or end + 2 > authority.len or authority[end + 1] != ':') return error.InvalidHeader;
        break :blk authority[end + 2 ..];
    } else blk: {
        const colon = std.mem.lastIndexOfScalar(u8, authority, ':') orelse return error.InvalidHeader;
        if (colon == 0 or colon + 1 >= authority.len) return error.InvalidHeader;
        if (std.mem.indexOfScalar(u8, authority[0..colon], ':') != null) return error.InvalidHeader;
        break :blk authority[colon + 1 ..];
    };
    try validateAuthorityPort(port);
}

fn connectionSpecificHeaderName(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "keep-alive") or
        std.ascii.eqlIgnoreCase(name, "proxy-connection") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "upgrade");
}

fn forbiddenTrailerFieldName(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "authorization") or
        std.ascii.eqlIgnoreCase(name, "cache-control") or
        std.ascii.eqlIgnoreCase(name, "content-encoding") or
        std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "content-range") or
        std.ascii.eqlIgnoreCase(name, "content-type") or
        std.ascii.eqlIgnoreCase(name, "host") or
        std.ascii.eqlIgnoreCase(name, "max-forwards") or
        std.ascii.eqlIgnoreCase(name, "set-cookie") or
        std.ascii.eqlIgnoreCase(name, "trailer") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "te");
}

fn responseForbidsBody(status: u16, request_method: []const u8, extended_connect: bool) bool {
    if ((status >= 100 and status < 200) or status == 204 or status == 304) return true;
    if (methodIsHead(request_method)) return true;
    if (!extended_connect and methodIsConnect(request_method) and status >= 200 and status < 300) return true;
    return false;
}

fn responseSemanticsFromMethod(method: []const u8, extended_connect: bool) ResponseBodySemantics {
    return .{
        .head = methodIsHead(method),
        .traditional_connect = methodIsConnect(method) and !extended_connect,
        .extended_connect = methodIsConnect(method) and extended_connect,
    };
}

fn responseWriteSuppressesBodySemantics(status: u16, semantics: ResponseBodySemantics) bool {
    if ((status >= 100 and status < 200) or status == 204 or status == 304) return true;
    if (semantics.head) return true;
    if (semantics.traditional_connect and status >= 200 and status < 300) return true;
    return false;
}

fn validateResponseBodyForStatus(
    status: u16,
    headers: []const http2.Hpack.HeaderField,
    body: []const u8,
    trailers: []const http2.Hpack.HeaderField,
) Error!void {
    try validateResponseBodyForStatusWithLength(
        status,
        try contentLength(headers),
        body,
        trailers,
    );
}

fn validateResponseBodyForStatusWithLength(
    status: u16,
    declared_content_length: ?usize,
    body: []const u8,
    trailers: []const http2.Hpack.HeaderField,
) Error!void {
    if (!((status >= 100 and status < 200) or status == 204 or status == 304)) return;
    if (body.len != 0 or trailers.len != 0) return error.InvalidContentLength;
    // As in HTTP/1, 304 may describe the selected representation length, but
    // 1xx and 204 responses terminate at the HEADERS block and must not carry a
    // Content-Length that could be mistaken for DATA on this stream.
    if (status != 304 and declared_content_length != null) return error.InvalidContentLength;
}

fn validateResponseBodyForRequestSemantics(
    status: u16,
    semantics: ResponseBodySemantics,
    headers: []const http2.Hpack.HeaderField,
    body: []const u8,
    trailers: []const http2.Hpack.HeaderField,
) Error!void {
    try validateResponseBodyForRequestSemanticsWithLength(
        status,
        semantics,
        try contentLength(headers),
        body,
        trailers,
    );
}

fn validateResponseBodyForRequestSemanticsWithLength(
    status: u16,
    semantics: ResponseBodySemantics,
    declared_content_length: ?usize,
    body: []const u8,
    trailers: []const http2.Hpack.HeaderField,
) Error!void {
    if (semantics.head) {
        if (trailers.len != 0) return error.InvalidContentLength;
        if (declared_content_length) |len| {
            if (body.len != 0 and len != body.len) return error.InvalidContentLength;
        }
        return;
    }
    if (semantics.traditional_connect and status >= 200 and status < 300) {
        // Successful traditional CONNECT switches the stream into tunnel mode:
        // HTTP response DATA/trailers would be interpreted as tunnel bytes by
        // the peer. Reject them at the server writer boundary rather than
        // silently framing an ambiguous response.
        if (body.len != 0 or trailers.len != 0) return error.InvalidContentLength;
        if ((declared_content_length orelse 0) != 0) return error.InvalidContentLength;
    }
}

fn validateDeclaredResponseLength(
    status: u16,
    semantics: ResponseBodySemantics,
    headers: []const http2.Hpack.HeaderField,
    body_len: usize,
) Error!void {
    try validateDeclaredResponseLengthValue(
        status,
        semantics,
        try contentLength(headers),
        body_len,
    );
}

fn validateDeclaredResponseLengthValue(
    status: u16,
    semantics: ResponseBodySemantics,
    declared_content_length: ?usize,
    body_len: usize,
) Error!void {
    if ((status >= 100 and status < 200) or status == 204) return;
    if (semantics.traditional_connect and status >= 200 and status < 300) return;
    if (declared_content_length) |len| {
        // 304 and HEAD responses may describe the selected representation, so
        // only require equality when an actual DATA body is sent.  For normal
        // responses, writing a declared length that differs from DATA bytes
        // leaves peers waiting or causes them to reject the stream.
        if (body_len != 0 and len != body_len) return error.InvalidContentLength;
        if (body_len == 0 and status != 304 and !semantics.head and len != 0) return error.InvalidContentLength;
    }
}

fn responseShouldDefaultContentLength(
    status: u16,
    semantics: ResponseBodySemantics,
    headers: []const http2.Hpack.HeaderField,
    body_len: usize,
) bool {
    return responseShouldDefaultContentLengthValue(
        status,
        semantics,
        contentLength(headers) catch return false,
        body_len,
    );
}

fn responseShouldDefaultContentLengthValue(
    status: u16,
    semantics: ResponseBodySemantics,
    declared_content_length: ?usize,
    body_len: usize,
) bool {
    if (body_len == 0) return false;
    if (responseWriteSuppressesBodySemantics(status, semantics)) return false;
    return declared_content_length == null;
}

fn informationalResponseToSkip(status: u16) bool {
    return statusIsInformational(status) and status != 101;
}

fn statusIsInformational(status: u16) bool {
    return status >= 100 and status < 200;
}

const RequestHeaderLookup = struct {
    method: ?[]const u8 = null,
    path: ?[]const u8 = null,
    scheme: ?[]const u8 = null,
    authority: ?[]const u8 = null,
    host: ?[]const u8 = null,
    protocol: ?[]const u8 = null,
    priority: ?[]const u8 = null,
    content_length: ?usize = null,

    fn requestAuthority(self: RequestHeaderLookup) ?[]const u8 {
        return self.authority orelse self.host;
    }
};

fn requestHeaderLookup(headers: []const http2.Hpack.HeaderField) Error!RequestHeaderLookup {
    var lookup: RequestHeaderLookup = .{};
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, ":method")) {
            if (lookup.method == null) lookup.method = header.value;
        } else if (std.ascii.eqlIgnoreCase(header.name, ":path")) {
            if (lookup.path == null) lookup.path = header.value;
        } else if (std.ascii.eqlIgnoreCase(header.name, ":scheme")) {
            if (lookup.scheme == null) lookup.scheme = header.value;
        } else if (std.ascii.eqlIgnoreCase(header.name, ":authority")) {
            if (lookup.authority == null) lookup.authority = header.value;
        } else if (std.ascii.eqlIgnoreCase(header.name, "host")) {
            if (lookup.host == null) lookup.host = header.value;
        } else if (std.ascii.eqlIgnoreCase(header.name, ":protocol")) {
            if (lookup.protocol == null) lookup.protocol = header.value;
        } else if (std.ascii.eqlIgnoreCase(header.name, "priority")) {
            if (lookup.priority == null) lookup.priority = header.value;
        } else if (std.ascii.eqlIgnoreCase(header.name, "content-length")) {
            try parseContentLengthHeaderValue(header.value, &lookup.content_length);
        }
    }
    return lookup;
}

fn findHeader(headers: []const http2.Hpack.HeaderField, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

pub const testing = struct {
    pub fn setSendConnectionWindow(
        connection: *Connection,
        value: i64,
    ) void {
        connection.send_connection_window.value = value;
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

    pub fn releaseLocalStream(
        connection: *Connection,
        stream_id: u31,
    ) void {
        connection.releaseLocalStream(stream_id);
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

    pub fn handleConnectionFrame(
        connection: *Connection,
        frame: http2.Frame,
    ) Error!bool {
        return connection.handleConnectionFrame(frame);
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
};

fn requestAuthority(headers: []const http2.Hpack.HeaderField) ?[]const u8 {
    if (findHeader(headers, ":authority")) |authority| return authority;
    return findHeader(headers, "host");
}

fn validateH2cUpgradeRequest(request: http1.Request) Error!void {
    if (request.version != .http_1_1) return error.InvalidHeader;
    if (request.method == .CONNECT) return error.InvalidHeader;
    if (request.body.len != 0 or request.trailers.len != 0) return error.InvalidContentLength;

    const upgrade = (try optionalHttp1SingletonHeader(request.headers, "upgrade")) orelse return error.InvalidHeader;
    if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, upgrade, " \t"), "h2c")) return error.InvalidHeader;
    if (!headersContainHttpToken(request.headers, "connection", "upgrade")) return error.InvalidHeader;
    if (!headersContainHttpToken(request.headers, "connection", "http2-settings")) return error.InvalidHeader;
}

fn decodeHttp2SettingsHeader(allocator: std.mem.Allocator, value: []const u8) Error![]u8 {
    const len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(value) catch return error.InvalidHeader;
    const decoded = try allocator.alloc(u8, len);
    errdefer allocator.free(decoded);
    std.base64.url_safe_no_pad.Decoder.decode(decoded, value) catch return error.InvalidHeader;
    const settings = try http2.parseSettings(allocator, decoded);
    defer allocator.free(settings);
    return decoded;
}

fn optionalHttp1SingletonHeader(headers: []const http1.Header, name: []const u8) Error!?[]const u8 {
    var found: ?[]const u8 = null;
    for (headers) |header| {
        if (!header.eqlName(name)) continue;
        if (found != null) return error.InvalidHeader;
        found = header.value;
    }
    return found;
}

fn headersContainHttpToken(headers: []const http1.Header, name: []const u8, needle: []const u8) bool {
    for (headers) |header| {
        if (header.eqlName(name) and containsHttpToken(header.value, needle)) return true;
    }
    return false;
}

const max_settings_payload_len = 8 * 6;

const SettingsForLimits = struct {
    buf: [8]http2.Setting,
    count: usize,
};

fn settingsForLimits(limits: Limits, role: Role) Error!SettingsForLimits {
    try validateLocalLimits(limits);
    var settings_buf: [8]http2.Setting = undefined;
    var count: usize = 0;
    settings_buf[count] = .{ .id = .header_table_size, .value = @intCast(@min(limits.header_table_size, std.math.maxInt(u32))) };
    count += 1;
    settings_buf[count] = .{ .id = .initial_window_size, .value = limits.initial_window_size };
    count += 1;
    if (limits.max_concurrent_streams) |max_streams| {
        settings_buf[count] = .{ .id = .max_concurrent_streams, .value = max_streams };
        count += 1;
    }
    if (limits.max_frame_size != default_max_frame_size) {
        settings_buf[count] = .{ .id = .max_frame_size, .value = @intCast(limits.max_frame_size) };
        count += 1;
    }
    settings_buf[count] = .{ .id = .max_header_list_size, .value = @intCast(@min(limits.max_header_list_size, std.math.maxInt(u32))) };
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
    return .{ .buf = settings_buf, .count = count };
}

fn encodeSettingsPayloadInto(out: *[max_settings_payload_len]u8, settings: []const http2.Setting) Error![]const u8 {
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

fn limitsToHttp1(limits: Limits) http1_runtime.Limits {
    return .{
        .max_head_bytes = limits.max_header_list_size,
        .max_body_bytes = limits.max_body_bytes,
    };
}

fn containsHttpToken(value: []const u8, needle: []const u8) bool {
    var tokens = std.mem.splitScalar(u8, value, ',');
    while (tokens.next()) |raw| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, raw, " \t"), needle)) return true;
    }
    return false;
}

fn readExact(io: std.Io, stream: net.Stream, buffer: []u8) ReadExactError!void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        var bufs = [_][]u8{buffer[offset..]};
        const n = try io.vtable.netRead(io.userdata, stream.socket.handle, &bufs);
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }
}

fn writeAll(io: std.Io, stream: net.Stream, bytes: []const u8) net.Stream.Writer.Error!void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = try io.vtable.netWrite(io.userdata, stream.socket.handle, bytes[written..], &.{""}, 0);
        if (n == 0) return error.SocketUnconnected;
        written += n;
    }
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
        .{ .max_frame_payload = 4096 },
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
    try std.testing.expectEqual(@as(usize, 3), client.peerOrigins().len);
    try std.testing.expectEqualStrings(
        "https://img.example.com",
        client.peerOrigins()[2],
    );
    try std.testing.expect(client.peerOriginKnown("https://cdn.example.com"));
    try std.testing.expect(client.peerOriginKnown("https://img.example.com"));
    try std.testing.expectEqual(@as(?usize, 1), client.peer_origin_index.get("https://cdn.example.com"));
    try std.testing.expectEqual(@as(?usize, 2), client.peer_origin_index.get("https://img.example.com"));
    try std.testing.expect(client.peer_origin_index.get("https://missing.example.com") == null);
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
        for (connection.peer_origins.items) |origin| allocator.free(origin);
        connection.peer_origins.deinit(allocator);
        connection.peer_origin_index.deinit(allocator);
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
    try std.testing.expectEqual(@as(usize, 1), connection.peer_origins.items.len);
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
        for (connection.peer_origins.items) |origin| allocator.free(origin);
        connection.peer_origins.deinit(allocator);
        connection.peer_origin_index.deinit(allocator);
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
        server_connection.peer_origins.deinit(allocator);
        server_connection.peer_origin_index.deinit(allocator);
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
        .{ .max_frame_payload = 4096 },
    );
    defer client.close();
    inline for (0..3) |_| {
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
        client.alternative_service_index.get(.{
            .stream_id = 0,
            .origin = "https://example.com",
        }),
    );
    try std.testing.expectEqual(
        @as(?usize, 1),
        client.alternative_service_index.get(.{
            .stream_id = 1,
            .origin = "",
        }),
    );
    try std.testing.expect(client.alternative_service_index.get(.{
        .stream_id = 0,
        .origin = "https://missing.example.com",
    }) == null);
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
        for (connection.alternative_services.items) |*service| {
            service.deinit(allocator);
        }
        connection.alternative_services.deinit(allocator);
        connection.alternative_service_index.deinit(allocator);
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
    try std.testing.expectEqual(@as(usize, 1), connection.alternative_services.items.len);
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
    try std.testing.expectEqual(@as(i64, default_flow_window + 1024 - "ping".len), (try client.sendStreamWindow(1)).value);
    var goaway = try client.readGoAway();
    defer goaway.deinit(allocator);
    try std.testing.expectEqual(http2.ErrorCode.no_error, goaway.goaway.error_code);
    try std.testing.expectEqualStrings("done", goaway.goaway.debug_data);
}

test "HTTP/2 serveConnection handles sequential requests" {
    const allocator = std.testing.allocator;

    var backend = try @import("../runtime.zig").Backend.initAuto(allocator, .evented_then_threaded);
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
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

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

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.served);
    try std.testing.expectEqual(@as(usize, 2), shared.context.count);
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

    try std.testing.expectError(error.UnsupportedScheme, Client.requestUri(allocator, io, "https://localhost/", .{}, .{}));
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

test "HTTP/2 h2c upgrade request receives stream one response" {
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
                .max_body_bytes = 0,
            }, .{});
            defer request.deinit(shared.allocator);
            try std.testing.expectEqualStrings("/upgrade?x=1", request.request.target);
            try std.testing.expectEqualStrings("h2c", request.request.header("upgrade").?);
            try std.testing.expect(containsHttpToken(request.request.header("connection").?, "http2-settings"));
            try std.testing.expect(request.request.header("http2-settings") != null);

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
    var response = try Client.requestUriUpgrade(allocator, io, uri, .{}, .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("upgraded", response.body);
}

test "HTTP/2 server accepts h2c upgrade request" {
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
            try std.testing.expectEqual(http1.Method.GET, upgrade.request.request.method);
            try std.testing.expectEqualStrings("/server-upgrade", upgrade.request.request.target);
            try upgrade.connection.writeResponse(upgrade.stream_id, .{ .body = "server-upgraded" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(allocator, "http://localhost:{d}/server-upgrade", .{server.address().ip4.port});
    defer allocator.free(uri);
    var response = try Client.requestUriUpgrade(allocator, io, uri, .{}, .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("server-upgraded", response.body);
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
        .{ .max_frame_payload = 24, .max_body_bytes = 4096 },
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

            try connection.writeResponse(request.stream_id, .{
                .status = 200,
                .headers = &.{
                    .{ .name = "content-type", .value = "text/plain" },
                    .{ .name = "x-long-response", .value = expected },
                },
                .body = "ok",
            });
        }
    };

    var shared = Shared{ .server = &server, .expected = long_header_value };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 24,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var response = try client.request(.{
        .method = "GET",
        .path = "/continuation",
        .authority = "localhost",
        .headers = &.{.{ .name = "x-long", .value = long_header_value }},
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("ok", response.body);
    try std.testing.expectEqualStrings(long_header_value, findHeader(response.headers, "x-long-response").?);
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

    var response = try client.readResponse(1, "POST", false);
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("ok", response.body);
}

test "HTTP/2 runtime rejects HEADERS priority self dependency" {
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
                if (err == error.InvalidFrame or err == error.InvalidStreamId) {
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
        .{ .name = ":path", .value = "/self-priority" },
        .{ .name = ":scheme", .value = "https" },
    });

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try payload.appendSlice(allocator, &.{ 0, 0, 0, 1, 16 }); // PRIORITY depends on stream 1 itself.
    try payload.appendSlice(allocator, block.items);
    const flags = flag_end_headers | @as(u8, (@as(http2.Flags, .{ .priority = true })).byte());
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
    var response = try client.readResponse(1, "POST", false);
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

    var response = try client.readResponse(1, "POST", false);
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

    try std.testing.expectError(error.ConnectionGoAway, client.request(.{
        .method = "GET",
        .path = "/goaway-reject",
        .authority = "localhost",
    }));

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
        connection.peer_origins.deinit(allocator);
        connection.peer_origin_index.deinit(allocator);
        connection.alternative_services.deinit(allocator);
        connection.alternative_service_index.deinit(allocator);
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

    if (connection.pending_request_head != 0 and
        connection.pending_requests.items.len == connection.pending_requests.capacity)
    {
        connection.compactPendingRequests();
    }
    try connection.pending_requests.append(queue_allocator, request);
    request = undefined;
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

    stripConnectionHeaders(&headers, .request);
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

test "HTTP/2 header validation rejects connection-specific headers" {
    const bad_te_request = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/bad-te" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "te", .value = "gzip" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&bad_te_request, .request));

    const bad_transfer_encoding_request = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/bad-transfer-encoding" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "transfer-encoding", .value = "chunked" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&bad_transfer_encoding_request, .request));

    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&.{
        .{ .name = "te", .value = "trailers" },
    }, .request_trailers));
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&.{
        .{ .name = "content-length", .value = "5" },
    }, .request_trailers));
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "te", .value = "trailers" },
    }, .response));
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "connection", .value = "x-hop" },
    }, .response));
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/bad-value" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "x-bad", .value = "ok\r\ninjected: yes" },
    }, .request));

    try std.testing.expectError(error.InvalidContentLength, validateDeclaredRequestLength(&.{
        .{ .name = "content-length", .value = "5" },
    }, "pong".len));
}

test "HTTP/2 runtime validates pseudo headers and lowercase names" {
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

    const connect_missing_authority = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
    };
    try std.testing.expectError(error.MissingPseudoHeader, validateHeaderBlock(&connect_missing_authority, .request));

    const connect_with_path_scheme = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.com:443" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&connect_with_path_scheme, .request));

    const connect_ipv6 = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "[2001:db8::1]:443" },
    };
    try validateHeaderBlock(&connect_ipv6, .request);

    const connect_no_port = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&connect_no_port, .request));

    const connect_bad_port = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.com:65536" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&connect_bad_port, .request));

    const lowercase_connect_authority_only = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "connect" },
        .{ .name = ":authority", .value = "example.com:443" },
    };
    try std.testing.expectError(error.MissingPseudoHeader, validateHeaderBlock(&lowercase_connect_authority_only, .request));

    const lowercase_connect_origin_form = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "connect" },
        .{ .name = ":path", .value = "/ordinary-extension-method" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try validateHeaderBlock(&lowercase_connect_origin_form, .request);

    const lowercase_options_asterisk = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "options" },
        .{ .name = ":path", .value = "*" },
        .{ .name = ":scheme", .value = "https" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&lowercase_options_asterisk, .request));

    const empty_method = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&empty_method, .request));

    const invalid_method_token = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET /" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&invalid_method_token, .request));

    const empty_path = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "" },
        .{ .name = ":scheme", .value = "https" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&empty_path, .request));

    const response_lookup_headers = [_]http2.Hpack.HeaderField{
        .{ .name = ":status", .value = "204" },
        .{ .name = "content-length", .value = "0, 0" },
    };
    const response_lookup = try responseHeaderLookup(&response_lookup_headers);
    try std.testing.expectEqualStrings("204", response_lookup.status.?);
    try std.testing.expectEqual(@as(?usize, 0), response_lookup.content_length);

    const bad_status = [_]http2.Hpack.HeaderField{
        .{ .name = ":status", .value = "20x" },
    };
    try std.testing.expectError(error.InvalidStatus, validateHeaderBlock(&bad_status, .response));

    const low_status = [_]http2.Hpack.HeaderField{
        .{ .name = ":status", .value = "099" },
    };
    try std.testing.expectError(error.InvalidStatus, validateHeaderBlock(&low_status, .response));

    const switching_protocols = [_]http2.Hpack.HeaderField{
        .{ .name = ":status", .value = "101" },
    };
    try std.testing.expectError(error.InvalidStatus, validateHeaderBlock(&switching_protocols, .response));

    const connection_header = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/connection" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "connection", .value = "keep-alive" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&connection_header, .request));

    const embedded_colon_name = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/embedded-colon" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "bad:name", .value = "value" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&embedded_colon_name, .request));

    const malformed_pseudo_name = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/malformed-pseudo" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":bad:name", .value = "value" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&malformed_pseudo_name, .request));

    const host_only = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/host-only" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "host", .value = "example.com" },
    };
    try validateHeaderBlock(&host_only, .request);
    try std.testing.expectEqualStrings("example.com", requestAuthority(&host_only).?);
    const host_lookup = try requestHeaderLookup(&host_only);
    try std.testing.expectEqualStrings("GET", host_lookup.method.?);
    try std.testing.expectEqualStrings("/host-only", host_lookup.path.?);
    try std.testing.expectEqualStrings("https", host_lookup.scheme.?);
    try std.testing.expectEqualStrings("example.com", host_lookup.requestAuthority().?);

    const lookup_with_length = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/lookup" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "content-length", .value = "5, 5" },
        .{ .name = "priority", .value = "u=1" },
    };
    const parsed_lookup = try requestHeaderLookup(&lookup_with_length);
    try std.testing.expectEqual(@as(?usize, 5), parsed_lookup.content_length);
    try std.testing.expectEqualStrings("u=1", parsed_lookup.priority.?);

    const matching_authorities = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/matching-authorities" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "EXAMPLE.com:443" },
        .{ .name = "host", .value = "example.COM:443" },
    };
    try validateHeaderBlock(&matching_authorities, .request);

    const mismatched_authorities = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/mismatched-authorities" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "origin.example" },
        .{ .name = "host", .value = "proxy.example" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&mismatched_authorities, .request));

    const invalid_scheme = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/invalid-scheme" },
        .{ .name = ":scheme", .value = "https://" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&invalid_scheme, .request));

    const invalid_path = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "relative" },
        .{ .name = ":scheme", .value = "https" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&invalid_path, .request));

    const query_only_path = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "?q=1" },
        .{ .name = ":scheme", .value = "https" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&query_only_path, .request));

    const origin_form_with_query = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/?q=1" },
        .{ .name = ":scheme", .value = "https" },
    };
    try validateHeaderBlock(&origin_form_with_query, .request);

    const fragment_path = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/resource#fragment" },
        .{ .name = ":scheme", .value = "https" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&fragment_path, .request));

    const invalid_authority = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/invalid-authority" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "user@example.com" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&invalid_authority, .request));

    const invalid_authority_port = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/invalid-authority-port" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com:65536" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&invalid_authority_port, .request));

    const bad_response_value = [_]http2.Hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "x-bad", .value = "bad\x7fvalue" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&bad_response_value, .response));

    const invalid_request_trailer = [_]http2.Hpack.HeaderField{
        .{ .name = "content-type", .value = "text/plain" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&invalid_request_trailer, .request_trailers));

    const invalid_response_trailer = [_]http2.Hpack.HeaderField{
        .{ .name = "set-cookie", .value = "a=b" },
    };
    try std.testing.expectError(error.InvalidHeader, validateHeaderBlock(&invalid_response_trailer, .response_trailers));

    try std.testing.expect(responseForbidsBody(200, "HEAD", false));
    try std.testing.expect(!responseForbidsBody(200, "head", false));
    try std.testing.expect(responseForbidsBody(200, "CONNECT", false));
    try std.testing.expect(!responseForbidsBody(200, "connect", false));
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

test "HTTP/2 runtime accepts traditional CONNECT DATA tunnel" {
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

            try tunnel.write("server tunnel bytes", false);
            try tunnel.closeWrite();
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

    var tunnel = response.tunnel;
    try tunnel.write("client tunnel bytes", false);
    var inbound = try tunnel.read();
    defer inbound.deinit(allocator);
    try std.testing.expectEqualStrings("server tunnel bytes", inbound.data);

    var fin = try tunnel.read();
    defer fin.deinit(allocator);
    try std.testing.expectEqualStrings("", fin.data);
    try std.testing.expect(fin.end_stream);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 writers reject status-forbidden response bodies" {
    try std.testing.expectError(error.InvalidContentLength, validateResponseBodyForStatus(204, &.{}, "body", &.{}));
    try std.testing.expectError(error.InvalidContentLength, validateResponseBodyForStatus(204, &.{.{ .name = "content-length", .value = "0" }}, "", &.{}));
    try validateResponseBodyForStatus(304, &.{.{ .name = "content-length", .value = "123" }}, "", &.{});
    try std.testing.expectError(error.InvalidContentLength, validateResponseBodyForStatus(304, &.{}, "body", &.{}));
    try std.testing.expectError(error.InvalidContentLength, validateResponseBodyForStatus(103, &.{.{ .name = "content-length", .value = "0" }}, "", &.{}));

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
    try std.testing.expectError(error.InvalidContentLength, connection.writeResponse(1, .{
        .status = 204,
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
    try std.testing.expect(client.peer_enable_connect_protocol);

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

test "HTTP/2 flow window blocks and updates" {
    var window = FlowWindow{ .value = 4 };
    try std.testing.expectEqual(@as(usize, 4), window.available());
    try window.reserve(4);
    try std.testing.expectEqual(@as(i64, 0), window.value);
    try std.testing.expectEqual(@as(usize, 0), window.available());
    try std.testing.expectError(error.FlowControlBlocked, window.reserve(1));
    try window.update(8);
    try window.reserve(3);
    try std.testing.expectEqual(@as(i64, 5), window.value);
    window.value = max_flow_window;
    try std.testing.expectError(error.FlowControlViolation, window.update(1));
    try std.testing.expectEqual(max_flow_window, window.value);

    var recv = FlowWindow{ .value = 2 };
    try std.testing.expectError(error.FlowControlViolation, recv.receive(3));
    try recv.receive(2);
    try std.testing.expectEqual(@as(i64, 0), recv.value);
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
    try std.testing.expectEqualStrings("ok", data.data);
    try std.testing.expectEqual(@as(i64, 0), connection.recv_connection_window.value);
    try std.testing.expectEqual(@as(i64, 0), (try connection.recvStreamWindow(1)).value);
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

test "HTTP/2 request batch reorders out-of-order responses" {
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
    try std.testing.expectEqual(@as(usize, 0), client.active_local_streams.items.len);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 request body batch sends bounded parallel bodies" {
    const allocator = std.testing.allocator;
    const request_body = "batch-body-" ** 1024;
    const parallel = 3;
    const total_body_bytes = request_body.len * parallel;
    const limits: Limits = .{
        .max_body_bytes = request_body.len,
        .initial_window_size = @max(
            total_body_bytes,
            @as(usize, @intCast(default_flow_window)),
        ),
        .initial_connection_window_size = @max(
            total_body_bytes,
            @as(usize, @intCast(default_flow_window)),
        ),
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
            try connection.readRequestBatchStreamingInto(
                &requests,
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
    try client.requestBodyBatchInto(
        &requests,
        request_body.len,
        &responses,
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

test "HTTP/2 request body batch rejects insufficient credit before write" {
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
        connection.batch_data_headers.deinit(allocator);
        connection.batch_data_parts.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }
    connection.send_connection_window.value = 7;
    connection.peer_initial_stream_window = 4;
    const requests = [_]RequestOptions{
        .{
            .method = "POST",
            .authority = "localhost",
            .body = "1234",
        },
        .{
            .method = "POST",
            .authority = "localhost",
            .body = "5678",
        },
    };
    var responses: [requests.len]OwnedResponse = undefined;
    try std.testing.expectError(
        error.FlowControlBlocked,
        connection.requestBodyBatchInto(&requests, 4, &responses),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.write_batch.items.len,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.active_local_streams.items.len,
    );
    try std.testing.expectEqual(@as(i64, 7), connection.send_connection_window.value);
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

test "HTTP/2 buffered frame reader preserves coalesced suffix" {
    const allocator = std.testing.allocator;
    var raw: std.ArrayList(u8) = .empty;
    try (http2.Frame{
        .header = .{
            .length = 0,
            .frame_type = .ping,
            .flags = flag_ack,
            .stream_id = 0,
        },
        .payload = "12345678",
    }).write(&raw, allocator);
    try (http2.Frame{
        .header = .{
            .length = 0,
            .frame_type = .headers,
            .flags = flag_end_headers | flag_end_stream,
            .stream_id = 1,
        },
        .payload = &.{0x82},
    }).write(&raw, allocator);

    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .frame_reader = .{ .buffer = raw },
    };
    defer connection.frame_reader.deinit(allocator);

    const first = try connection.readBufferedFrame();
    try std.testing.expectEqual(http2.FrameType.ping, first.frame.header.frame_type);
    try std.testing.expectEqualStrings("12345678", first.frame.payload);
    const second = try connection.readBufferedFrame();
    try std.testing.expectEqual(http2.FrameType.headers, second.frame.header.frame_type);
    try std.testing.expectEqual(@as(u31, 1), second.frame.header.stream_id);
    try std.testing.expectEqualSlices(u8, &.{0x82}, second.frame.payload);
    try std.testing.expectEqual(
        connection.frame_reader.buffer.items.len,
        connection.frame_reader.start,
    );
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
    defer connection.pending_requests.deinit(allocator);
    try connection.pending_requests.append(allocator, .{
        .stream_id = 1,
        .headers = headers,
        .method = headers[0].value,
        .path = headers[1].value,
        .scheme = headers[2].value,
        .authority = null,
        .body = body,
    });

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
    try std.testing.expect(connection.write_batch.items.len != 0);
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
    try connection.recordPeerGoAway(.{ .last_stream_id = 5, .error_code = .no_error, .debug_data = &.{} });
    try std.testing.expectEqual(@as(?u31, 5), connection.peer_goaway_last_stream_id);
    try std.testing.expectError(error.InvalidFrame, connection.recordPeerGoAway(.{ .last_stream_id = 7, .error_code = .no_error, .debug_data = &.{} }));
    try std.testing.expectEqual(@as(?u31, 5), connection.peer_goaway_last_stream_id);
}

test "HTTP/2 ignores WINDOW_UPDATE for inactive streams" {
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

    const first = try connection.reserveNextClientStreamId();
    try std.testing.expectEqual(@as(u31, 1), first);
    try std.testing.expectEqual(@as(usize, 1), connection.active_local_streams.items.len);
    try std.testing.expectEqual(@as(?usize, 0), connection.active_local_index.get(first));
    try std.testing.expectError(error.FlowControlBlocked, connection.reserveNextClientStreamId());
    try std.testing.expectEqual(@as(u31, 3), connection.next_client_stream_id);

    connection.releaseLocalStream(first);
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
    try std.testing.expectEqual(@as(usize, 1), connection.active_peer_streams.items.len);
    connection.releasePeerStream(5);
    try std.testing.expectEqual(@as(usize, 0), connection.active_peer_streams.items.len);
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
    try validateLocalLimits(.{
        .initial_window_size = std.math.maxInt(i31),
        .initial_connection_window_size = std.math.maxInt(i31),
        .max_frame_size = max_max_frame_size,
    });
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

    try std.testing.expectError(error.InvalidSetting, connection.applySettings(&.{
        .{ .id = .max_frame_size, .value = default_max_frame_size - 1 },
    }));
    try std.testing.expectError(error.InvalidSetting, connection.applySettings(&.{
        .{ .id = .max_frame_size, .value = max_max_frame_size + 1 },
    }));
    try std.testing.expectError(error.InvalidSetting, connection.applySettings(&.{
        .{ .id = .initial_window_size, .value = @as(u32, std.math.maxInt(i31)) + 1 },
    }));
    try std.testing.expectError(error.InvalidSetting, connection.applySettings(&.{
        .{ .id = .enable_push, .value = 0 },
    }));

    try connection.applySettings(&.{
        .{ .id = .max_frame_size, .value = 32_768 },
        .{ .id = .max_concurrent_streams, .value = 7 },
        .{ .id = .header_table_size, .value = 128 },
        .{ .id = .no_rfc7540_priorities, .value = 1 },
    });
    try std.testing.expectEqual(@as(usize, 32_768), connection.peer_max_frame_size);
    try std.testing.expectEqual(@as(?u32, 7), connection.peer_max_concurrent_streams);
    try std.testing.expectEqual(@as(usize, 128), connection.hpack_encoder.dynamic_table.size_limit);
    try std.testing.expect(connection.peer_no_rfc7540_priorities);

    try connection.applySettings(&.{
        .{ .id = .enable_connect_protocol, .value = 0 },
    });
    try std.testing.expect(!connection.peer_enable_connect_protocol);
    try connection.applySettings(&.{
        .{ .id = .enable_connect_protocol, .value = 1 },
    });
    try std.testing.expect(connection.peer_enable_connect_protocol);
    try std.testing.expectError(error.InvalidSetting, connection.applySettings(&.{
        .{ .id = .enable_connect_protocol, .value = 0 },
    }));
    try std.testing.expect(connection.peer_enable_connect_protocol);
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
    try std.testing.expectError(error.InvalidSetting, server_connection.applySettings(&.{
        .{ .id = .enable_push, .value = 2 },
    }));
}

test "HTTP/2 runtime applies local HPACK decoder table limit" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{ .header_table_size = 32 },
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

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(std.testing.allocator);
    try block.appendSlice(std.testing.allocator, &.{ 0x3f, 0x02 }); // Dynamic table size update value 33 > local limit.
    try std.testing.expectError(error.InvalidEncoding, connection.hpack_decoder.decodeBlock(std.testing.allocator, block.items));
}

test "HTTP/2 runtime validates frame envelope rules" {
    try validateFrameEnvelope(.{
        .header = .{ .length = 0, .frame_type = .data, .flags = flag_end_stream, .stream_id = 1 },
        .payload = &.{},
    });
    try validateFrameEnvelope(.{
        .header = .{ .length = 0, .frame_type = .settings, .flags = flag_ack, .stream_id = 0 },
        .payload = &.{},
    });
    try validateFrameEnvelope(.{
        .header = .{ .length = 6, .frame_type = .settings, .flags = 0, .stream_id = 0 },
        .payload = &.{ 0, 1, 0, 0, 0, 0 },
    });
    try validateFrameEnvelope(.{
        .header = .{ .length = 4, .frame_type = .rst_stream, .flags = 0, .stream_id = 1 },
        .payload = &.{ 0, 0, 0, 8 },
    });

    try std.testing.expectError(error.InvalidFrame, validateFrameEnvelope(.{
        .header = .{ .length = 1, .frame_type = .data, .flags = 0, .stream_id = 1 },
        .payload = &.{},
    }));
    try std.testing.expectError(error.InvalidFrame, validateFrameEnvelope(.{
        .header = .{ .length = 0, .frame_type = .data, .flags = 0, .stream_id = 0 },
        .payload = &.{},
    }));
    try std.testing.expectError(error.InvalidFrame, validateFrameEnvelope(.{
        .header = .{ .length = 1, .frame_type = .settings, .flags = flag_ack, .stream_id = 0 },
        .payload = &.{0},
    }));
    try std.testing.expectError(error.InvalidFrame, validateFrameEnvelope(.{
        .header = .{ .length = 5, .frame_type = .settings, .flags = 0, .stream_id = 0 },
        .payload = &.{ 0, 1, 0, 0, 0 },
    }));
    try std.testing.expectError(error.InvalidFrame, validateFrameEnvelope(.{
        .header = .{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 1 },
        .payload = &.{},
    }));
    try std.testing.expectError(error.InvalidFrame, validateFrameEnvelope(.{
        .header = .{ .length = 3, .frame_type = .rst_stream, .flags = 0, .stream_id = 1 },
        .payload = &.{ 0, 0, 0 },
    }));
    try std.testing.expectError(error.InvalidFrame, validateFrameEnvelope(.{
        .header = .{ .length = 7, .frame_type = .ping, .flags = 0, .stream_id = 0 },
        .payload = &.{ 0, 1, 2, 3, 4, 5, 6 },
    }));
    try std.testing.expectError(error.InvalidFrame, validateFrameEnvelope(.{
        .header = .{ .length = 8, .frame_type = .ping, .flags = 0, .stream_id = 1 },
        .payload = &.{ 0, 1, 2, 3, 4, 5, 6, 7 },
    }));
    try std.testing.expectError(error.InvalidFrame, validateFrameEnvelope(.{
        .header = .{ .length = 4, .frame_type = .window_update, .flags = 0, .stream_id = 1 },
        .payload = &.{ 0, 0, 0, 0 },
    }));
    try std.testing.expectError(error.InvalidFrame, validateFrameEnvelope(.{
        .header = .{ .length = 4, .frame_type = .priority, .flags = 0, .stream_id = 1 },
        .payload = &.{ 0, 0, 0, 0 },
    }));
    try std.testing.expectError(error.InvalidFrame, validateFrameEnvelope(.{
        .header = .{ .length = 8, .frame_type = .goaway, .flags = 0, .stream_id = 1 },
        .payload = &.{ 0, 0, 0, 0, 0, 0, 0, 0 },
    }));
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
    try std.testing.expectError(error.MessageTooLarge, cloneDecodedHeaders(allocator, block.items, .{
        .max_header_fields = 16,
        .max_header_list_size = 120,
    }, &decoder));

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

test "HTTP/2 runtime clones decoded headers into one string allocation" {
    const allocator = std.testing.allocator;
    const fields = [_]http2.Hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "x-first", .value = "one" },
        .{ .name = "x-second", .value = "two" },
    };
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &fields);
    var decoder = http2.Hpack.Decoder{};
    defer decoder.deinit(allocator);
    const cloned = try cloneDecodedHeaders(
        allocator,
        block.items,
        .{ .max_header_fields = 8 },
        &decoder,
    );
    defer freeHeaders(allocator, cloned);

    try std.testing.expect(cloned[0].block_storage != null);
    try std.testing.expect(cloned[1].block_storage == null);
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
    _ = @import("runtime/push_tests.zig");
    _ = @import("runtime/priority_tests.zig");
    _ = @import("runtime/streaming_response_tests.zig");
    _ = @import("runtime/response_batch_tests.zig");
    _ = @import("runtime/response_writer_tests.zig");
    _ = @import("runtime/request_writer_tests.zig");
}
