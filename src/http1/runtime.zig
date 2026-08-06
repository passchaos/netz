const std = @import("std");
const http1 = @import("mod.zig");
const wire = @import("../internal/wire.zig");

const net = std.Io.net;

pub const Error = http1.Error || error{
    HeadersTooLarge,
    BodyTooLarge,
    ConnectionClosed,
    InvalidResponse,
} || net.IpAddress.ListenError || net.IpAddress.ConnectError || net.HostName.ValidateError || net.HostName.ConnectError || net.Server.AcceptError || net.Stream.Reader.Error || net.Stream.Writer.Error || std.Thread.SpawnError;

pub const Limits = struct {
    max_head_bytes: usize = 64 * 1024,
    max_body_bytes: usize = 16 * 1024 * 1024,
};

pub const Server = struct {
    io: std.Io,
    listener: net.Server,
    allocator: std.mem.Allocator,
    limits: Limits = .{},

    pub fn listen(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
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
        return .{
            .io = self.io,
            .allocator = self.allocator,
            .stream = try self.listener.accept(self.io),
            .limits = self.limits,
        };
    }

    pub fn serveOne(self: *Server, context: anytype, comptime handler: anytype) Error!void {
        var connection = try self.accept();
        defer connection.close();
        var request = try connection.readRequest(.{});
        defer request.deinit(self.allocator);
        var response = try handler(context, request.request);
        if (response.request_method == null) response.request_method = request.request.method;
        try connection.writeResponse(response);
    }

    pub fn serveConcurrent(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (*HandlerContext, http1.Request) Error!ResponseOptions,
        max_connections: usize,
    ) AsyncServeError!ConcurrentServeResult {
        var group: std.Io.Group = .init;
        const results = try self.allocator.alloc(?anyerror, max_connections);
        errdefer self.allocator.free(results);
        @memset(results, null);

        for (results, 0..) |*result, index| {
            var connection = try self.accept();
            errdefer connection.close();

            const task = ServeTask(HandlerContext){
                .connection = connection,
                .context = context,
                .handler = handler,
                .result = result,
            };
            // `std.Io.Group.async` copies the task context into the selected
            // std.Io backend.  The connection stream ownership transfers to the
            // task; each task closes its own stream after writing a response.
            group.async(self.io, ServeTask(HandlerContext).run, .{task});
            _ = index;
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
        handler: *const fn (*HandlerContext, http1.Request) Error!ResponseOptions,
        result: *?anyerror,

        fn run(task: @This()) std.Io.Cancelable!void {
            var connection = task.connection;
            defer connection.close();

            var request = connection.readRequest(.{}) catch |err| {
                task.result.* = err;
                return;
            };
            defer request.deinit(connection.allocator);

            var response = task.handler(task.context, request.request) catch |err| {
                task.result.* = err;
                return;
            };
            if (response.request_method == null) response.request_method = request.request.method;
            connection.writeResponse(response) catch |err| {
                task.result.* = err;
                return;
            };
            task.result.* = null;
        }
    };
}

pub const Client = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    stream: net.Stream,
    limits: Limits = .{},
    inbuf: std.ArrayList(u8) = .empty,
    default_host: ?[]u8 = null,

    pub fn connect(allocator: std.mem.Allocator, io: std.Io, address: net.IpAddress, limits: Limits) Error!Client {
        return .{
            .io = io,
            .allocator = allocator,
            .stream = try address.connect(io, .{ .mode = .stream }),
            .limits = limits,
        };
    }

    pub fn connectHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        limits: Limits,
    ) Error!Client {
        const host_name = try net.HostName.init(host);
        const owned_host = try allocator.dupe(u8, host);
        errdefer allocator.free(owned_host);
        return .{
            .io = io,
            .allocator = allocator,
            .stream = try host_name.connect(io, port, .{ .mode = .stream }),
            .limits = limits,
            .default_host = owned_host,
        };
    }

    pub fn close(self: *Client) void {
        if (self.default_host) |host| self.allocator.free(host);
        self.inbuf.deinit(self.allocator);
        self.stream.close(self.io);
        self.* = undefined;
    }

    pub fn request(self: *Client, request_options: RequestOptions) Error!OwnedResponse {
        var options = request_options;
        if (options.host == null) options.host = self.default_host;
        try writeRequestToStream(self.allocator, self.io, self.stream, options);
        return readResponseFromStreamBufferedForRequest(self.allocator, self.io, self.stream, self.limits, .{}, &self.inbuf, request_options.method);
    }

    pub fn openConnectTunnel(self: *Client, target: []const u8, headers: []const http1.Header) Error!Tunnel {
        try http1.validateConnectTarget(target);
        try writeRequestToStream(self.allocator, self.io, self.stream, .{
            .method = .CONNECT,
            .target = target,
            .host = target,
            .headers = headers,
        });
        var response = try readResponseFromStreamBufferedForRequest(self.allocator, self.io, self.stream, self.limits, .{}, &self.inbuf, .CONNECT);
        errdefer response.deinit(self.allocator);
        if (response.response.status < 200 or response.response.status >= 300) return error.InvalidResponse;
        if (response.response.body.len != 0 or response.response.trailers.len != 0) return error.InvalidResponse;
        response.deinit(self.allocator);
        return .{
            .io = self.io,
            .allocator = self.allocator,
            .stream = self.stream,
            .inbuf = &self.inbuf,
        };
    }
};

pub const Connection = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    stream: net.Stream,
    limits: Limits = .{},
    inbuf: std.ArrayList(u8) = .empty,

    pub fn close(self: *Connection) void {
        self.inbuf.deinit(self.allocator);
        self.stream.close(self.io);
        self.* = undefined;
    }

    pub fn readRequest(self: *Connection, options: http1.ParseOptions) Error!OwnedRequest {
        return readRequestFromStreamBuffered(self.allocator, self.io, self.stream, self.limits, options, &self.inbuf);
    }

    pub fn writeResponse(self: *Connection, response: ResponseOptions) Error!void {
        try writeResponseToStream(self.allocator, self.io, self.stream, response);
    }

    pub fn acceptConnectTunnel(self: *Connection, request: http1.Request, response_headers: []const http1.Header) Error!Tunnel {
        if (request.method != .CONNECT or request.body.len != 0 or request.trailers.len != 0) return error.InvalidResponse;
        try http1.validateConnectTarget(request.target);
        try writeResponseToStream(self.allocator, self.io, self.stream, .{
            .status = 200,
            .reason = "Connection Established",
            .headers = response_headers,
            .request_method = .CONNECT,
        });
        return .{
            .io = self.io,
            .allocator = self.allocator,
            .stream = self.stream,
            .inbuf = &self.inbuf,
        };
    }
};

pub const Tunnel = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    stream: net.Stream,
    inbuf: *std.ArrayList(u8),

    pub fn write(self: *Tunnel, bytes: []const u8) Error!void {
        try writeAll(self.io, self.stream, bytes);
    }

    pub fn read(self: *Tunnel, buffer: []u8) Error!usize {
        if (self.inbuf.items.len != 0) {
            const n = @min(buffer.len, self.inbuf.items.len);
            @memcpy(buffer[0..n], self.inbuf.items[0..n]);
            discardPrefix(self.inbuf, n);
            return n;
        }
        return readSome(self.io, self.stream, buffer);
    }
};

pub const OwnedRequest = struct {
    bytes: []u8,
    request: http1.Request,

    pub fn deinit(self: *OwnedRequest, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const OwnedResponse = struct {
    bytes: []u8,
    response: http1.Response,

    pub fn deinit(self: *OwnedResponse, allocator: std.mem.Allocator) void {
        self.response.deinit(allocator);
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const RequestOptions = struct {
    method: http1.Method = .GET,
    target: []const u8 = "/",
    version: http1.Version = .http_1_1,
    /// Optional authority used to synthesize Host when the caller did not
    /// provide one explicitly.  HTTP/1.1 requires Host on origin-form requests;
    /// keeping it in RequestOptions lets the client runtime behave like mature
    /// stacks without forcing every call site to hand-build a header field.
    host: ?[]const u8 = null,
    headers: []const http1.Header = &.{},
    body: []const u8 = &.{},
    trailers: []const http1.Header = &.{},
};

pub const ResponseOptions = struct {
    version: http1.Version = .http_1_1,
    status: u16 = 200,
    reason: []const u8 = "OK",
    headers: []const http1.Header = &.{},
    body: []const u8 = &.{},
    trailers: []const http1.Header = &.{},
    /// Optional method of the request this response answers.  HEAD and
    /// successful CONNECT have method-specific body framing rules that cannot
    /// be inferred from status/headers alone.
    request_method: ?http1.Method = null,
};

pub fn readRequestFromStream(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
) Error!OwnedRequest {
    const bytes = try readRequestMessageBytes(allocator, io, stream, limits);
    errdefer allocator.free(bytes);
    var request = try http1.parseRequest(allocator, bytes, options);
    errdefer request.deinit(allocator);
    try http1.validateRequestHost(request);
    return .{ .bytes = bytes, .request = request };
}

pub fn readRequestFromStreamBuffered(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
) Error!OwnedRequest {
    const bytes = try readRequestMessageBytesBuffered(allocator, io, stream, limits, inbuf);
    errdefer allocator.free(bytes);
    var request = try http1.parseRequest(allocator, bytes, options);
    errdefer request.deinit(allocator);
    try http1.validateRequestHost(request);
    return .{ .bytes = bytes, .request = request };
}

pub fn readResponseFromStream(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
) Error!OwnedResponse {
    while (true) {
        const bytes = try readMessageBytes(allocator, io, stream, limits);
        errdefer allocator.free(bytes);
        var response = try parseResponseForRuntime(allocator, bytes, options, null);
        errdefer response.deinit(allocator);
        applyCloseDelimitedResponseBody(&response, bytes, null);
        if (informationalResponseToSkip(response.status)) {
            response.deinit(allocator);
            allocator.free(bytes);
            continue;
        }
        return .{ .bytes = bytes, .response = response };
    }
}

pub fn readResponseFromStreamForRequest(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    request_method: http1.Method,
) Error!OwnedResponse {
    while (true) {
        const bytes = try readMessageBytesForResponse(allocator, io, stream, limits, request_method);
        errdefer allocator.free(bytes);
        var response = try parseResponseForRuntime(allocator, bytes, options, request_method);
        errdefer response.deinit(allocator);
        applyCloseDelimitedResponseBody(&response, bytes, request_method);
        if (informationalResponseToSkip(response.status)) {
            response.deinit(allocator);
            allocator.free(bytes);
            continue;
        }
        return .{ .bytes = bytes, .response = response };
    }
}

pub fn readResponseFromStreamBuffered(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
) Error!OwnedResponse {
    while (true) {
        const bytes = try readMessageBytesBuffered(allocator, io, stream, limits, inbuf);
        errdefer allocator.free(bytes);
        var response = try parseResponseForRuntime(allocator, bytes, options, null);
        errdefer response.deinit(allocator);
        applyCloseDelimitedResponseBody(&response, bytes, null);
        if (informationalResponseToSkip(response.status)) {
            response.deinit(allocator);
            allocator.free(bytes);
            continue;
        }
        return .{ .bytes = bytes, .response = response };
    }
}

pub fn readResponseFromStreamBufferedForRequest(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
    request_method: http1.Method,
) Error!OwnedResponse {
    while (true) {
        const bytes = try readMessageBytesBufferedForResponse(allocator, io, stream, limits, inbuf, request_method);
        errdefer allocator.free(bytes);
        var response = try parseResponseForRuntime(allocator, bytes, options, request_method);
        errdefer response.deinit(allocator);
        applyCloseDelimitedResponseBody(&response, bytes, request_method);
        if (informationalResponseToSkip(response.status)) {
            response.deinit(allocator);
            allocator.free(bytes);
            continue;
        }
        return .{ .bytes = bytes, .response = response };
    }
}

fn parseResponseForRuntime(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    options: http1.ParseOptions,
    request_method: ?http1.Method,
) Error!http1.Response {
    if (request_method) |method| {
        return http1.parseResponseForRequest(allocator, bytes, options, method) catch |err| switch (err) {
            error.InvalidTransferEncoding => try parseNonChunkedTransferResponse(allocator, bytes, options, method),
            else => |e| return e,
        };
    }
    return http1.parseResponse(allocator, bytes, options) catch |err| switch (err) {
        error.InvalidTransferEncoding => try parseNonChunkedTransferResponse(allocator, bytes, options, null),
        else => |e| return e,
    };
}

fn parseNonChunkedTransferResponse(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    options: http1.ParseOptions,
    request_method: ?http1.Method,
) Error!http1.Response {
    const head_end = std.mem.indexOf(u8, bytes, "\r\n\r\n") orelse return error.BufferTooShort;
    const head = bytes[0..head_end];
    if (responseHeadForbidsBody(head, request_method)) return error.InvalidTransferEncoding;
    if ((try transferEncodingState(head)) != .non_chunked) return error.InvalidTransferEncoding;

    var sanitized: std.ArrayList(u8) = .empty;
    errdefer sanitized.deinit(allocator);
    try appendHeadWithoutHeaders(&sanitized, allocator, head, &.{ "transfer-encoding", "content-length" });
    try sanitized.appendSlice(allocator, "\r\n\r\n");
    const sanitized_storage = try sanitized.toOwnedSlice(allocator);
    errdefer allocator.free(sanitized_storage);

    var response = if (request_method) |method|
        try http1.parseResponseForRequest(allocator, sanitized_storage, options, method)
    else
        try http1.parseResponse(allocator, sanitized_storage, options);
    errdefer response.deinit(allocator);
    try attachRuntimeHeaderStorage(allocator, &response, sanitized_storage);
    try appendOriginalHeaderLines(allocator, &response, head, "transfer-encoding");

    const body_start = head_end + 4;
    response.body = bytes[body_start..];
    response.body_framing = .close_delimited;
    response.consumed = bytes.len;
    return response;
}

fn attachRuntimeHeaderStorage(allocator: std.mem.Allocator, response: *http1.Response, storage: []u8) Error!void {
    const old = response.header_value_storage;
    const combined = try allocator.alloc([]u8, old.len + 1);
    @memcpy(combined[0..old.len], old);
    combined[old.len] = storage;
    allocator.free(old);
    response.header_value_storage = combined;
}

fn appendOriginalHeaderLines(
    allocator: std.mem.Allocator,
    response: *http1.Response,
    head: []const u8,
    name: []const u8,
) Error!void {
    var count: usize = 0;
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(line[0..colon], name)) count += 1;
    }
    if (count == 0) return;

    const old = response.headers;
    const combined = try allocator.alloc(http1.Header, old.len + count);
    @memcpy(combined[0..old.len], old);

    var out_index = old.len;
    lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], name)) continue;
        const value = wire.trimOws(line[colon + 1 ..]);
        try http1.validateHeader(.{ .name = line[0..colon], .value = value });
        combined[out_index] = .{ .name = line[0..colon], .value = value };
        out_index += 1;
    }
    allocator.free(old);
    response.headers = combined;
}

fn appendHeadWithoutHeaders(list: *std.ArrayList(u8), allocator: std.mem.Allocator, head: []const u8, names: []const []const u8) Error!void {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    const status_line = lines.next() orelse return error.InvalidResponse;
    try list.appendSlice(allocator, status_line);
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse {
            try list.appendSlice(allocator, "\r\n");
            try list.appendSlice(allocator, line);
            continue;
        };
        if (headerNameInList(line[0..colon], names)) continue;
        try list.appendSlice(allocator, "\r\n");
        try list.appendSlice(allocator, line);
    }
}

fn headerNameInList(name: []const u8, names: []const []const u8) bool {
    for (names) |candidate| {
        if (std.ascii.eqlIgnoreCase(name, candidate)) return true;
    }
    return false;
}

fn applyCloseDelimitedResponseBody(response: *http1.Response, bytes: []const u8, request_method: ?http1.Method) void {
    const head_end = std.mem.indexOf(u8, bytes, "\r\n\r\n") orelse return;
    if (!responseHeadUsesCloseDelimitedBody(bytes[0..head_end], request_method)) return;
    const body_start = head_end + 4;
    if (bytes.len < body_start) return;
    response.body = bytes[body_start..];
    response.body_framing = .close_delimited;
    response.consumed = bytes.len;
}

pub fn writeRequestToStream(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, options: RequestOptions) Error!void {
    try http1.validateRequestTargetForMethod(options.method, options.target);
    var request_headers: std.ArrayList(http1.Header) = .empty;
    defer request_headers.deinit(allocator);
    try appendRequestHeadersWithHost(&request_headers, allocator, options.headers, options.host);
    try http1.validateHostHeaderBlock(options.version, request_headers.items);
    if (options.method == .CONNECT and (options.body.len != 0 or options.trailers.len != 0)) return error.InvalidContentLength;
    const use_chunked = try chunkedWriteFraming(options.version, request_headers.items, options.trailers);
    try validateDeclaredRequestBodyLength(request_headers.items, options.body.len, use_chunked);
    var headers: std.ArrayList(http1.Header) = .empty;
    defer headers.deinit(allocator);
    var len_buf: [32]u8 = undefined;
    var trailer_value: std.ArrayList(u8) = .empty;
    defer trailer_value.deinit(allocator);
    try appendDefaultedHeaders(
        &headers,
        allocator,
        request_headers.items,
        options.body.len,
        options.trailers,
        use_chunked,
        shouldDefaultRequestContentLength(options.method, options.body.len, options.trailers),
        &len_buf,
        &trailer_value,
    );

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try encoded.appendSlice(allocator, options.method.string());
    try encoded.append(allocator, ' ');
    try encoded.appendSlice(allocator, options.target);
    try encoded.append(allocator, ' ');
    try encoded.appendSlice(allocator, options.version.string());
    try encoded.appendSlice(allocator, "\r\n");
    try writeHeaderLines(&encoded, allocator, headers.items);
    try encoded.appendSlice(allocator, "\r\n");
    if (use_chunked) {
        const chunks = [_][]const u8{options.body};
        try encodeChunkedForRuntime(&encoded, allocator, &chunks, options.trailers);
    } else {
        try encoded.appendSlice(allocator, options.body);
    }
    try writeAll(io, stream, encoded.items);
}

fn appendRequestHeadersWithHost(
    list: *std.ArrayList(http1.Header),
    allocator: std.mem.Allocator,
    headers: []const http1.Header,
    host: ?[]const u8,
) Error!void {
    var has_host = false;
    for (headers) |header| {
        if (header.eqlName("host")) has_host = true;
        try list.append(allocator, header);
    }
    if (!has_host) {
        if (host) |value| try list.append(allocator, .{ .name = "Host", .value = value });
    }
}

pub fn writeResponseToStream(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, options: ResponseOptions) Error!void {
    try http1.validateStatusCode(options.status);
    try http1.validateReasonPhrase(options.reason);
    try http1.validateResponseBodyForStatus(options.status, options.headers, options.body, options.trailers);
    const use_chunked = try chunkedWriteFraming(options.version, options.headers, options.trailers);
    try validateDeclaredResponseBodyLength(
        options.status,
        options.request_method,
        options.headers,
        options.body.len,
        options.trailers.len,
        use_chunked,
    );
    const suppress_body = responseWriteSuppressesBody(options.status, options.request_method);
    var headers: std.ArrayList(http1.Header) = .empty;
    defer headers.deinit(allocator);
    var len_buf: [32]u8 = undefined;
    var trailer_value: std.ArrayList(u8) = .empty;
    defer trailer_value.deinit(allocator);
    try appendDefaultedHeaders(
        &headers,
        allocator,
        options.headers,
        options.body.len,
        options.trailers,
        use_chunked,
        !http1.statusCodeForbidsBody(options.status),
        &len_buf,
        &trailer_value,
    );

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try encoded.appendSlice(allocator, options.version.string());
    try encoded.append(allocator, ' ');
    try appendDecimalForRuntime(&encoded, allocator, options.status);
    if (options.reason.len != 0) {
        try encoded.append(allocator, ' ');
        try encoded.appendSlice(allocator, options.reason);
    }
    try encoded.appendSlice(allocator, "\r\n");
    try writeHeaderLines(&encoded, allocator, headers.items);
    try encoded.appendSlice(allocator, "\r\n");
    if (suppress_body) {
        // HEAD/304/CONNECT response bodies are interpreted out-of-band by HTTP
        // semantics.  Preserve descriptive headers, but do not put even a
        // zero-size chunk on the wire.
    } else if (use_chunked) {
        const chunks = [_][]const u8{options.body};
        try encodeChunkedForRuntime(&encoded, allocator, &chunks, options.trailers);
    } else {
        try encoded.appendSlice(allocator, options.body);
    }
    try writeAll(io, stream, encoded.items);
}

fn appendDefaultedHeaders(
    list: *std.ArrayList(http1.Header),
    allocator: std.mem.Allocator,
    headers: []const http1.Header,
    body_len: usize,
    trailers: []const http1.Header,
    use_chunked: bool,
    add_default_content_length: bool,
    len_buf: *[32]u8,
    trailer_value: *std.ArrayList(u8),
) Error!void {
    var has_content_length = false;
    var has_transfer_encoding = false;
    var has_trailer = false;
    for (headers) |header| {
        if (header.eqlName("content-length")) has_content_length = true;
        if (header.eqlName("transfer-encoding")) has_transfer_encoding = true;
        if (header.eqlName("trailer")) has_trailer = true;
        if (use_chunked and header.eqlName("content-length")) continue;
        try list.append(allocator, header);
    }
    if (use_chunked) {
        if (!has_transfer_encoding) try list.append(allocator, .{ .name = "Transfer-Encoding", .value = "chunked" });
        if (trailers.len != 0 and !has_trailer) {
            try renderTrailerHeaderValue(trailer_value, allocator, trailers);
            try list.append(allocator, .{ .name = "Trailer", .value = trailer_value.items });
        }
    } else if (add_default_content_length and !has_content_length) {
        const rendered = std.fmt.bufPrint(len_buf, "{}", .{body_len}) catch unreachable;
        try list.append(allocator, .{ .name = "Content-Length", .value = rendered });
    }
}

fn shouldDefaultRequestContentLength(method: http1.Method, body_len: usize, trailers: []const http1.Header) bool {
    if (body_len != 0 or trailers.len != 0) return true;
    return switch (method) {
        .GET, .HEAD, .CONNECT => false,
        else => true,
    };
}

fn validateDeclaredRequestBodyLength(headers: []const http1.Header, body_len: usize, use_chunked: bool) Error!void {
    if (use_chunked) return;
    const declared = try http1.contentLength(headers);
    if (declared) |len| {
        // Once a caller supplies Content-Length the runtime encoder must ensure
        // the wire body matches it exactly.  Sending a shorter/longer body leaves
        // the peer desynchronized and can corrupt the next pipelined message.
        if (len != body_len) return error.InvalidContentLength;
    }
}

fn validateDeclaredResponseBodyLength(
    status: u16,
    request_method: ?http1.Method,
    headers: []const http1.Header,
    body_len: usize,
    trailers_len: usize,
    use_chunked: bool,
) Error!void {
    if (request_method) |method| {
        if (method == .CONNECT and status >= 200 and status < 300) {
            if (use_chunked) return error.InvalidTransferEncoding;
            // RFC 9110/9112: a 2xx CONNECT response switches to tunnel mode
            // immediately after the header section.  Content-Length/TE would be
            // interpreted differently by different intermediaries, so forbid it
            // even when the declared length is zero.
            if (body_len != 0 or (try http1.contentLength(headers)) != null) return error.InvalidContentLength;
            return;
        }
        if (method == .HEAD) {
            if (trailers_len != 0) return error.InvalidTrailer;
            if (try http1.contentLength(headers)) |len| {
                if (body_len != 0 and len != body_len) return error.InvalidContentLength;
            }
            return;
        }
    }
    if (use_chunked) return;
    if (status == 304) return;
    const declared = try http1.contentLength(headers);
    if (declared) |len| {
        if (len != body_len) return error.InvalidContentLength;
    }
}

fn responseWriteSuppressesBody(status: u16, request_method: ?http1.Method) bool {
    if (http1.statusCodeForbidsBody(status)) return true;
    if (request_method) |method| {
        if (method == .HEAD) return true;
        if (method == .CONNECT and status >= 200 and status < 300) return true;
    }
    return false;
}

fn chunkedWriteFraming(version: http1.Version, headers: []const http1.Header, trailers: []const http1.Header) Error!bool {
    var has_transfer_encoding = false;
    for (headers) |header| {
        if (header.eqlName("transfer-encoding")) {
            has_transfer_encoding = true;
            break;
        }
    }

    if (has_transfer_encoding) {
        // Once callers opt into transfer coding, the runtime must emit bytes
        // that match the declared framing.  This HTTP/1 layer only knows how to
        // encode chunked bodies, so reject unsupported stacked codings instead
        // of silently sending a raw body under misleading headers.
        if ((try http1.bodyFraming(headers)) != .chunked) return error.InvalidTransferEncoding;
        if (version == .http_1_0) return error.InvalidVersion;
        return true;
    }

    if (trailers.len == 0) return false;
    if (version == .http_1_0) return error.InvalidVersion;
    return true;
}

fn renderTrailerHeaderValue(value: *std.ArrayList(u8), allocator: std.mem.Allocator, trailers: []const http1.Header) Error!void {
    value.clearRetainingCapacity();
    for (trailers, 0..) |trailer, index| {
        var duplicate = false;
        for (trailers[0..index]) |prior| {
            if (trailer.eqlName(prior.name)) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) continue;
        if (value.items.len != 0) try value.appendSlice(allocator, ", ");
        try value.appendSlice(allocator, trailer.name);
    }
}

fn appendDecimalForRuntime(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: anytype) Error!void {
    var tmp: [32]u8 = undefined;
    const rendered = std.fmt.bufPrint(&tmp, "{}", .{value}) catch return error.InvalidResponse;
    try list.appendSlice(allocator, rendered);
}

fn writeHeaderLines(list: *std.ArrayList(u8), allocator: std.mem.Allocator, headers: []const http1.Header) Error!void {
    for (headers) |header| {
        try http1.validateHeader(header);
        try list.appendSlice(allocator, header.name);
        try list.appendSlice(allocator, ": ");
        try list.appendSlice(allocator, header.value);
        try list.appendSlice(allocator, "\r\n");
    }
}

fn writeMergedHeaderLines(list: *std.ArrayList(u8), allocator: std.mem.Allocator, headers: []const http1.Header) Error!void {
    var written = try std.ArrayList(bool).initCapacity(allocator, headers.len);
    defer written.deinit(allocator);
    try written.appendNTimes(allocator, false, headers.len);

    for (headers, 0..) |header, index| {
        if (written.items[index]) continue;
        try http1.validateHeader(header);
        try list.appendSlice(allocator, header.name);
        try list.appendSlice(allocator, ": ");
        try list.appendSlice(allocator, header.value);
        written.items[index] = true;

        var next = index + 1;
        while (next < headers.len) : (next += 1) {
            if (written.items[next]) continue;
            const duplicate = headers[next];
            if (!header.eqlName(duplicate.name)) continue;
            try http1.validateHeader(duplicate);
            // Match Hyper's repeated-trailer behavior: preserve the first field
            // name casing and append repeated values into the same field line so
            // recipients see one logical trailer field.
            try list.appendSlice(allocator, ", ");
            try list.appendSlice(allocator, duplicate.value);
            written.items[next] = true;
        }
        try list.appendSlice(allocator, "\r\n");
    }
}

fn encodeChunkedForRuntime(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    chunks: []const []const u8,
    trailers: []const http1.Header,
) Error!void {
    try http1.validateTrailers(trailers);
    for (chunks) |chunk| {
        // A zero-length chunk is the chunked terminator on the wire.  Treat
        // empty payload slices as "no DATA" and emit exactly one terminating
        // chunk after all non-empty payload slices so empty bodies can still
        // carry trailers.
        if (chunk.len == 0) continue;
        var tmp: [32]u8 = undefined;
        const rendered = std.fmt.bufPrint(&tmp, "{x}\r\n", .{chunk.len}) catch return error.InvalidResponse;
        try list.appendSlice(allocator, rendered);
        try list.appendSlice(allocator, chunk);
        try list.appendSlice(allocator, "\r\n");
    }
    try list.appendSlice(allocator, "0\r\n");
    try writeMergedHeaderLines(list, allocator, trailers);
    try list.appendSlice(allocator, "\r\n");
}

fn readMessageBytes(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, limits: Limits) Error![]u8 {
    return readMessageBytesWithContext(allocator, io, stream, limits, null, false, true);
}

fn readMessageBytesForResponse(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, limits: Limits, request_method: http1.Method) Error![]u8 {
    return readMessageBytesWithContext(allocator, io, stream, limits, request_method, false, true);
}

fn readRequestMessageBytes(allocator: std.mem.Allocator, io: std.Io, stream: net.Stream, limits: Limits) Error![]u8 {
    return readMessageBytesWithContext(allocator, io, stream, limits, null, true, false);
}

fn readMessageBytesWithContext(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    request_method: ?http1.Method,
    auto_continue: bool,
    close_delimited_when_unknown: bool,
) Error![]u8 {
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);

    var scratch: [4096]u8 = undefined;
    var head_end: ?usize = try findHttpHeadEndWithinLimit(bytes.items, limits.max_head_bytes);
    while (head_end == null) {
        // The non-buffered helpers have nowhere to keep bytes that belong to
        // the next pipelined message.  Read the head one byte at a time until
        // CRLFCRLF so this API remains safe even without an explicit inbuf.
        const read_buf = scratch[0..1];
        const n = try readSome(io, stream, read_buf);
        if (n == 0) return error.ConnectionClosed;
        try bytes.appendSlice(allocator, scratch[0..n]);
        head_end = try findHttpHeadEndWithinLimit(bytes.items, limits.max_head_bytes);
    }
    try maybeWriteContinue(io, stream, bytes.items[0..head_end.?], bytes.items.len - (head_end.? + 4), auto_continue);

    if (close_delimited_when_unknown and responseHeadUsesCloseDelimitedBody(bytes.items[0..head_end.?], request_method)) {
        const body_start = head_end.? + 4;
        while (true) {
            const n = try readSome(io, stream, &scratch);
            if (n == 0) break;
            try bytes.appendSlice(allocator, scratch[0..n]);
            if (bytes.items.len - body_start > limits.max_body_bytes) return error.BodyTooLarge;
        }
        return bytes.toOwnedSlice(allocator);
    }

    const target_len = while (true) {
        const len = messageTargetLength(bytes.items, head_end.?, limits.max_body_bytes, request_method) catch |err| switch (err) {
            error.BufferTooShort => {
                if (bytes.items.len >= head_end.? + 4 + limits.max_body_bytes) return error.BodyTooLarge;
                // Unknown-length bodies such as chunked framing cannot safely
                // batch-read without an inbuf: the next read might cross the
                // terminating chunk into a pipelined message.  Read one byte
                // at a time until the body parser can compute the target.
                const read_buf = scratch[0..1];
                const n = try readSome(io, stream, read_buf);
                if (n == 0) return error.ConnectionClosed;
                try bytes.appendSlice(allocator, scratch[0..n]);
                if (bytes.items.len > head_end.? + 4 + limits.max_body_bytes) return error.BodyTooLarge;
                continue;
            },
            else => |e| return e,
        };
        break len;
    };
    while (bytes.items.len < target_len) {
        const read_buf = scratch[0..@min(scratch.len, target_len - bytes.items.len)];
        const n = try readSome(io, stream, read_buf);
        if (n == 0) return error.ConnectionClosed;
        try bytes.appendSlice(allocator, scratch[0..n]);
        if (bytes.items.len > head_end.? + 4 + limits.max_body_bytes) return error.BodyTooLarge;
    }
    return bytes.toOwnedSlice(allocator);
}

fn readMessageBytesBuffered(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    inbuf: *std.ArrayList(u8),
) Error![]u8 {
    return readMessageBytesBufferedWithContext(allocator, io, stream, limits, inbuf, null, false, true);
}

fn readMessageBytesBufferedForResponse(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    inbuf: *std.ArrayList(u8),
    request_method: http1.Method,
) Error![]u8 {
    return readMessageBytesBufferedWithContext(allocator, io, stream, limits, inbuf, request_method, false, true);
}

fn readRequestMessageBytesBuffered(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    inbuf: *std.ArrayList(u8),
) Error![]u8 {
    return readMessageBytesBufferedWithContext(allocator, io, stream, limits, inbuf, null, true, false);
}

fn readMessageBytesBufferedWithContext(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    limits: Limits,
    inbuf: *std.ArrayList(u8),
    request_method: ?http1.Method,
    auto_continue: bool,
    close_delimited_when_unknown: bool,
) Error![]u8 {
    var scratch: [4096]u8 = undefined;
    var head_end: ?usize = try findHttpHeadEndWithinLimit(inbuf.items, limits.max_head_bytes);
    while (head_end == null) {
        const read_buf = scratch[0..@min(scratch.len, limits.max_head_bytes - inbuf.items.len)];
        const n = try readSome(io, stream, read_buf);
        if (n == 0) return error.ConnectionClosed;
        try inbuf.appendSlice(allocator, scratch[0..n]);
        head_end = try findHttpHeadEndWithinLimit(inbuf.items, limits.max_head_bytes);
    }
    try maybeWriteContinue(io, stream, inbuf.items[0..head_end.?], inbuf.items.len - (head_end.? + 4), auto_continue);

    if (close_delimited_when_unknown and responseHeadUsesCloseDelimitedBody(inbuf.items[0..head_end.?], request_method)) {
        const body_start = head_end.? + 4;
        while (true) {
            const n = try readSome(io, stream, &scratch);
            if (n == 0) break;
            try inbuf.appendSlice(allocator, scratch[0..n]);
            if (inbuf.items.len - body_start > limits.max_body_bytes) return error.BodyTooLarge;
        }
        const bytes = try inbuf.toOwnedSlice(allocator);
        inbuf.* = .empty;
        return bytes;
    }

    const target_len = while (true) {
        const len = messageTargetLength(inbuf.items, head_end.?, limits.max_body_bytes, request_method) catch |err| switch (err) {
            error.BufferTooShort => {
                const n = try readSome(io, stream, &scratch);
                if (n == 0) return error.ConnectionClosed;
                try inbuf.appendSlice(allocator, scratch[0..n]);
                if (inbuf.items.len > head_end.? + 4 + limits.max_body_bytes) return error.BodyTooLarge;
                continue;
            },
            else => |e| return e,
        };
        break len;
    };

    while (inbuf.items.len < target_len) {
        const n = try readSome(io, stream, &scratch);
        if (n == 0) return error.ConnectionClosed;
        try inbuf.appendSlice(allocator, scratch[0..n]);
        if (inbuf.items.len > head_end.? + 4 + limits.max_body_bytes) return error.BodyTooLarge;
    }

    const bytes = try allocator.dupe(u8, inbuf.items[0..target_len]);
    discardPrefix(inbuf, target_len);
    return bytes;
}

fn maybeWriteContinue(io: std.Io, stream: net.Stream, head: []const u8, already_buffered_body_bytes: usize, auto_continue: bool) Error!void {
    _ = already_buffered_body_bytes;
    if (!auto_continue) return;
    if (!requestShouldSendContinue(head)) return;
    try writeAll(io, stream, "HTTP/1.1 100 Continue\r\n\r\n");
}

fn discardPrefix(list: *std.ArrayList(u8), len: usize) void {
    if (len >= list.items.len) {
        list.clearRetainingCapacity();
        return;
    }
    const remaining = list.items[len..];
    @memmove(list.items[0..remaining.len], remaining);
    list.shrinkRetainingCapacity(remaining.len);
}

fn messageTargetLength(bytes: []const u8, head_end: usize, max_body_bytes: usize, request_method: ?http1.Method) Error!usize {
    const body_start = head_end + 4;
    const head = bytes[0..head_end];
    if (responseHeadForbidsBody(head, request_method)) return body_start;
    switch (try transferEncodingState(head)) {
        .none => {},
        .chunked => return body_start + try chunkedWireLength(bytes[body_start..], max_body_bytes),
        .non_chunked => {
            if (request_method == null) return error.InvalidTransferEncoding;
            return body_start;
        },
    }
    if (try contentLengthFromHead(head)) |len| {
        if (len > max_body_bytes) return error.BodyTooLarge;
        return body_start + len;
    }
    return body_start;
}

fn findHttpHeadEndWithinLimit(bytes: []const u8, max_head_bytes: usize) Error!?usize {
    if (std.mem.indexOf(u8, bytes, "\r\n\r\n")) |head_end| {
        if (head_end + 4 > max_head_bytes) return error.HeadersTooLarge;
        return head_end;
    }
    if (bytes.len >= max_head_bytes) return error.HeadersTooLarge;
    return null;
}

const TransferEncodingState = enum { none, chunked, non_chunked };

fn transferEncodingState(head: []const u8) Error!TransferEncodingState {
    var saw_transfer_encoding = false;
    var saw_chunked = false;
    var saw_non_chunked = false;
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], "transfer-encoding")) continue;
        saw_transfer_encoding = true;
        var tokens = std.mem.splitScalar(u8, line[colon + 1 ..], ',');
        while (tokens.next()) |raw| {
            const token = wire.trimOws(raw);
            if (token.len == 0) return error.InvalidTransferEncoding;
            if (std.ascii.eqlIgnoreCase(token, "chunked")) {
                if (saw_chunked) return error.InvalidTransferEncoding;
                saw_chunked = true;
            } else {
                saw_non_chunked = true;
            }
        }
    }
    if (!saw_transfer_encoding) return .none;
    if (saw_non_chunked) return .non_chunked;
    if (!saw_chunked) return error.InvalidTransferEncoding;
    return .chunked;
}

fn contentLengthFromHead(head: []const u8) Error!?usize {
    var found: ?usize = null;
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], "content-length")) continue;
        var parts = std.mem.splitScalar(u8, line[colon + 1 ..], ',');
        while (parts.next()) |raw_part| {
            const part = wire.trimOws(raw_part);
            if (part.len == 0) return error.InvalidContentLength;
            for (part) |byte| {
                if (!std.ascii.isDigit(byte)) return error.InvalidContentLength;
            }
            const parsed = std.fmt.parseInt(usize, part, 10) catch |err| switch (err) {
                error.InvalidCharacter => return error.InvalidContentLength,
                error.Overflow => return error.ContentLengthOverflow,
            };
            if (found) |existing| {
                if (existing != parsed) return error.ConflictingContentLength;
            } else {
                found = parsed;
            }
        }
    }
    return found;
}

fn responseHeadUsesCloseDelimitedBody(head: []const u8, request_method: ?http1.Method) bool {
    if (responseHeadForbidsBody(head, request_method)) return false;
    const te = transferEncodingState(head) catch return false;
    if (te == .chunked) return false;
    if (te == .non_chunked) return true;
    if (findHeaderValue(head, "content-length") != null) return false;
    return true;
}

fn responseHeadForbidsBody(head: []const u8, request_method: ?http1.Method) bool {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    const status_line = lines.next() orelse return false;
    var parts = std.mem.splitScalar(u8, status_line, ' ');
    _ = parts.next() orelse return false;
    const status_s = parts.next() orelse return false;
    if (status_s.len != 3) return false;
    const status = std.fmt.parseInt(u16, status_s, 10) catch return false;
    if ((status >= 100 and status < 200) or status == 204 or status == 304) return true;
    if (request_method == null) return false;
    return switch (request_method.?) {
        .HEAD => true,
        .CONNECT => status >= 200 and status < 300,
        else => false,
    };
}

fn informationalResponseToSkip(status: u16) bool {
    // RFC 9110 allows one or more interim 1xx responses before the final
    // response.  101 is deliberately not skipped because it transfers the
    // connection to the upgraded protocol.
    return status >= 100 and status < 200 and status != 101;
}

fn requestShouldSendContinue(head: []const u8) bool {
    if (!requestHeadIsHttp11(head)) return false;
    if (!requestExpectIsOnlyContinue(head)) return false;
    if (!requestHeadHasValidHost(head)) return false;
    return requestHeadHasBody(head);
}

fn requestExpectIsOnlyContinue(head: []const u8) bool {
    var found = false;
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], "expect")) continue;
        if (found) return false;
        found = true;
        // Hyper only recognizes an exact 100-continue expectation.  Be equally
        // conservative: comma-separated or unknown expectations require the
        // application to decide, not this auto-continue fast path.
        if (!std.ascii.eqlIgnoreCase(wire.trimOws(line[colon + 1 ..]), "100-continue")) return false;
    }
    return found;
}

fn requestHeadHasValidHost(head: []const u8) bool {
    var found = false;
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], "host")) continue;
        if (found) return false;
        found = true;
        http1.validateHostValue(line[colon + 1 ..]) catch return false;
    }
    return found;
}

fn requestHeadIsHttp11(head: []const u8) bool {
    const first_line_end = std.mem.indexOf(u8, head, "\r\n") orelse head.len;
    return std.mem.endsWith(u8, head[0..first_line_end], " HTTP/1.1");
}

fn requestHeadHasBody(head: []const u8) bool {
    if ((transferEncodingState(head) catch .none) == .chunked) return true;
    if (contentLengthFromHead(head) catch null) |len| return len > 0;
    return false;
}

fn chunkedWireLength(body: []const u8, max_body_bytes: usize) Error!usize {
    var pos: usize = 0;
    var decoded_total: usize = 0;
    var extension_bytes: usize = 0;
    while (true) {
        const line_end = std.mem.indexOf(u8, body[pos..], "\r\n") orelse return error.BufferTooShort;
        const line = body[pos .. pos + line_end];
        pos += line_end + 2;
        const semi = std.mem.indexOfScalar(u8, line, ';') orelse line.len;
        if (semi != line.len) {
            extension_bytes = std.math.add(usize, extension_bytes, line.len - semi) catch return error.ChunkExtensionTooLarge;
            if (extension_bytes > http1.max_chunk_extension_bytes) return error.ChunkExtensionTooLarge;
        }
        const size = try http1.parseChunkSize(line[0..semi]);
        decoded_total = std.math.add(usize, decoded_total, size) catch return error.BodyTooLarge;
        if (decoded_total > max_body_bytes) return error.BodyTooLarge;
        if (size == 0) {
            const trailer_end = std.mem.indexOf(u8, body[pos..], "\r\n") orelse return error.BufferTooShort;
            if (trailer_end == 0) return pos + 2;
            const full_end = std.mem.indexOf(u8, body[pos..], "\r\n\r\n") orelse return error.BufferTooShort;
            return pos + full_end + 4;
        }
        if (body.len < pos + size + 2) return error.BufferTooShort;
        pos += size;
        if (!std.mem.eql(u8, body[pos .. pos + 2], "\r\n")) return error.InvalidChunk;
        pos += 2;
    }
}

fn findHeaderValue(head: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(line[0..colon], name)) return wire.trimOws(line[colon + 1 ..]);
    }
    return null;
}

fn readSome(io: std.Io, stream: net.Stream, buffer: []u8) net.Stream.Reader.Error!usize {
    var bufs = [_][]u8{buffer};
    return io.vtable.netRead(io.userdata, stream.socket.handle, &bufs);
}

fn readExactForTest(io: std.Io, stream: net.Stream, buffer: []u8) Error!void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        const n = try readSome(io, stream, buffer[offset..]);
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

test "HTTP/1 runtime client and server exchange over TCP" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
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

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqual(http1.Method.POST, request.request.method);
            try std.testing.expectEqualStrings("/echo", request.request.target);
            try std.testing.expectEqualStrings("127.0.0.1", request.request.header("host").?);
            try std.testing.expectEqualStrings("ping", request.request.body);

            try connection.writeResponse(.{
                .status = 201,
                .reason = "Created",
                .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
                .body = "pong",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    var response = try client.request(.{
        .method = .POST,
        .target = "/echo",
        .host = "127.0.0.1",
        .body = "ping",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 201), response.response.status);
    try std.testing.expectEqualStrings("pong", response.response.body);
    try std.testing.expectEqualStrings("text/plain", response.response.header("content-type").?);
}

test "HTTP/1 runtime opens CONNECT tunnel" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
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

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqual(http1.Method.CONNECT, request.request.method);
            try std.testing.expectEqualStrings("example.com:443", request.request.target);
            try std.testing.expectEqualStrings("example.com:443", request.request.header("host").?);

            var tunnel = try connection.acceptConnectTunnel(request.request, &.{});
            var buf: [64]u8 = undefined;
            const n = try tunnel.read(&buf);
            try std.testing.expectEqualStrings("client tunnel bytes", buf[0..n]);
            try tunnel.write("server tunnel bytes");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var tunnel = try client.openConnectTunnel("example.com:443", &.{});
    try tunnel.write("client tunnel bytes");
    var buf: [64]u8 = undefined;
    const n = try tunnel.read(&buf);
    try std.testing.expectEqualStrings("server tunnel bytes", buf[0..n]);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectError(error.MalformedStartLine, client.openConnectTunnel("/not-authority", &.{}));
}

test "HTTP/1 client connects by host name" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
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

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("localhost", request.request.header("host").?);
            try connection.writeResponse(.{ .body = "dns-ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connectHost(allocator, io, "localhost", server.address().ip4.port, .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var response = try client.request(.{});
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings("dns-ok", response.response.body);
}

test "HTTP/1 server sends 100 Continue before reading expected body" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
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

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqual(http1.Method.POST, request.request.method);
            try std.testing.expectEqualStrings("/expect", request.request.target);
            try std.testing.expectEqualStrings("ping", request.request.body);

            try connection.writeResponse(.{
                .status = 200,
                .reason = "OK",
                .body = "accepted",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();

    // Send only the head first.  A Hyper-compatible HTTP/1 server must emit
    // 100 Continue after seeing a valid HTTP/1.1 request with a body so the
    // client can safely stream a large payload without deadlocking.
    try writeAll(io, client.stream, "POST /expect HTTP/1.1\r\n" ++
        "Host: 127.0.0.1\r\n" ++
        "Expect: 100-Continue\r\n" ++
        "Content-Length: 4\r\n" ++
        "\r\n");
    var interim: [25]u8 = undefined;
    try readExactForTest(io, client.stream, &interim);
    try std.testing.expectEqualStrings("HTTP/1.1 100 Continue\r\n\r\n", &interim);

    try writeAll(io, client.stream, "ping");
    var response = try readResponseFromStreamBufferedForRequest(allocator, io, client.stream, client.limits, .{}, &client.inbuf, .POST);
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("accepted", response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 server suppresses 100 Continue for invalid request head" {
    const bad_host = "POST /expect HTTP/1.1\r\n" ++
        "Host: http://example.com\r\n" ++
        "Expect: 100-continue\r\n" ++
        "Content-Length: 4\r\n" ++
        "\r\n";
    try std.testing.expect(!requestShouldSendContinue(bad_host));

    const duplicate_host = "POST /expect HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Host: other.example\r\n" ++
        "Expect: 100-continue\r\n" ++
        "Content-Length: 4\r\n" ++
        "\r\n";
    try std.testing.expect(!requestShouldSendContinue(duplicate_host));

    const mixed_expect = "POST /expect HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Expect: 100-continue, custom\r\n" ++
        "Content-Length: 4\r\n" ++
        "\r\n";
    try std.testing.expect(!requestShouldSendContinue(mixed_expect));
}

test "HTTP/1 server sends 100 Continue even when body was pre-read" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
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

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("ping", request.request.body);
            try connection.writeResponse(.{ .body = "accepted" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();

    try writeAll(io, client.stream, "POST /expect HTTP/1.1\r\n" ++
        "Host: 127.0.0.1\r\n" ++
        "Expect: 100-continue\r\n" ++
        "Content-Length: 4\r\n" ++
        "\r\n" ++
        "ping");
    var interim: [25]u8 = undefined;
    try readExactForTest(io, client.stream, &interim);
    try std.testing.expectEqualStrings("HTTP/1.1 100 Continue\r\n\r\n", &interim);

    var response = try readResponseFromStreamBufferedForRequest(allocator, io, client.stream, client.limits, .{}, &client.inbuf, .POST);
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("accepted", response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 client skips interim responses before final response" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
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

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/interim", request.request.target);

            try writeAll(server_ptr.io, connection.stream, "HTTP/1.1 100 Continue\r\n\r\n" ++
                "HTTP/1.1 102 Processing\r\n\r\n" ++
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfinal");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    var response = try client.request(.{
        .method = .GET,
        .target = "/interim",
        .headers = &.{.{ .name = "Host", .value = "127.0.0.1" }},
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("final", response.response.body);
}

test "HTTP/1 async std.Io server handles concurrent clients" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Context = struct {
        pub fn handle(_: *@This(), request: http1.Request) Error!ResponseOptions {
            if (request.method != .POST) return error.InvalidMethod;
            if (std.mem.eql(u8, request.target, "/one")) {
                return .{ .status = 200, .body = "handled-one" };
            }
            if (std.mem.eql(u8, request.target, "/two")) {
                return .{ .status = 200, .body = "handled-two" };
            }
            return .{ .status = 404, .reason = "Not Found", .body = "missing" };
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
        target: []const u8,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(task: *@This()) void {
            runFallible(task) catch |err| {
                task.err = err;
            };
        }

        fn runFallible(task: *@This()) !void {
            var client = try Client.connect(task.allocator, task.io, task.address, .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
            defer client.close();
            var response = try client.request(.{
                .method = .POST,
                .target = task.target,
                .headers = &.{.{ .name = "Host", .value = "127.0.0.1" }},
                .body = "hello",
            });
            defer response.deinit(task.allocator);
            try std.testing.expectEqual(@as(u16, 200), response.response.status);
            try std.testing.expectEqualStrings(task.expected, response.response.body);
        }
    };

    var clients = [_]ClientTask{
        .{ .allocator = allocator, .io = io, .address = server.address(), .target = "/one", .expected = "handled-one" },
        .{ .allocator = allocator, .io = io, .address = server.address(), .target = "/two", .expected = "handled-two" },
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

test "HTTP/1 runtime reuses persistent connection and preserves pipelined bytes" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
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

            var first = try connection.readRequest(.{});
            defer first.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/one", first.request.target);
            try connection.writeResponse(.{
                .status = 200,
                .headers = &.{.{ .name = "Connection", .value = "keep-alive" }},
                .body = "first",
            });

            var second = try connection.readRequest(.{});
            defer second.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/two", second.request.target);
            try connection.writeResponse(.{
                .status = 200,
                .headers = &.{.{ .name = "Connection", .value = "close" }},
                .body = "second",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    const keep_alive = [_]http1.Header{.{ .name = "Connection", .value = "keep-alive" }};
    try writeRequestToStream(allocator, io, client.stream, .{
        .method = .GET,
        .target = "/one",
        .headers = &.{ keep_alive[0], .{ .name = "Host", .value = "localhost" } },
    });
    try writeRequestToStream(allocator, io, client.stream, .{
        .method = .GET,
        .target = "/two",
        .headers = &.{ keep_alive[0], .{ .name = "Host", .value = "localhost" } },
    });

    var first_response = try readResponseFromStreamBuffered(allocator, io, client.stream, client.limits, .{}, &client.inbuf);
    defer first_response.deinit(allocator);
    try std.testing.expectEqualStrings("first", first_response.response.body);
    try std.testing.expect(first_response.response.keepAlive());

    var second_response = try readResponseFromStreamBuffered(allocator, io, client.stream, client.limits, .{}, &client.inbuf);
    defer second_response.deinit(allocator);
    try std.testing.expectEqualStrings("second", second_response.response.body);
    try std.testing.expect(!second_response.response.keepAlive());

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 client reuses default HTTP/1.1 persistent connection" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
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

            var first = try connection.readRequest(.{});
            defer first.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/default-one", first.request.target);
            try std.testing.expect(first.request.keepAlive());
            try connection.writeResponse(.{ .status = 200, .body = "first" });

            var second = try connection.readRequest(.{});
            defer second.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/default-two", second.request.target);
            try std.testing.expect(second.request.keepAlive());
            try connection.writeResponse(.{ .status = 200, .body = "second" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();

    var first = try client.request(.{
        .target = "/default-one",
        .headers = &.{.{ .name = "Host", .value = "localhost" }},
    });
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("first", first.response.body);
    try std.testing.expect(first.response.keepAlive());

    var second = try client.request(.{
        .target = "/default-two",
        .headers = &.{.{ .name = "Host", .value = "localhost" }},
    });
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("second", second.response.body);
    try std.testing.expect(second.response.keepAlive());

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 client keeps pipelined response after HEAD response headers" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
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

            var first = try connection.readRequest(.{});
            defer first.deinit(server_ptr.allocator);
            try std.testing.expectEqual(http1.Method.HEAD, first.request.method);

            var second = try connection.readRequest(.{});
            defer second.deinit(server_ptr.allocator);
            try std.testing.expectEqual(http1.Method.GET, second.request.method);

            // A HEAD response can advertise the Content-Length a GET would have
            // returned, but no body bytes follow.  Send the next response
            // immediately to prove the client does not consume it as a HEAD
            // body.
            const raw =
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\n" ++
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong";
            try writeAll(server_ptr.io, connection.stream, raw);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    const keep_alive = [_]http1.Header{.{ .name = "Connection", .value = "keep-alive" }};
    try writeRequestToStream(allocator, io, client.stream, .{
        .method = .HEAD,
        .target = "/head",
        .headers = &.{ keep_alive[0], .{ .name = "Host", .value = "localhost" } },
    });
    try writeRequestToStream(allocator, io, client.stream, .{
        .method = .GET,
        .target = "/next",
        .headers = &.{ keep_alive[0], .{ .name = "Host", .value = "localhost" } },
    });

    var head_response = try readResponseFromStreamBufferedForRequest(allocator, io, client.stream, client.limits, .{}, &client.inbuf, .HEAD);
    defer head_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), head_response.response.status);
    try std.testing.expectEqual(http1.BodyFraming.none, head_response.response.body_framing);
    try std.testing.expectEqualStrings("", head_response.response.body);

    var get_response = try readResponseFromStreamBufferedForRequest(allocator, io, client.stream, client.limits, .{}, &client.inbuf, .GET);
    defer get_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), get_response.response.status);
    try std.testing.expectEqualStrings("pong", get_response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 runtime writes request trailers with chunked framing" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
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

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);

            try std.testing.expectEqual(http1.Method.POST, request.request.method);
            try std.testing.expectEqual(http1.BodyFraming.chunked, request.request.body_framing);
            try std.testing.expectEqualStrings("upload", request.request.body);
            try std.testing.expectEqualStrings("chunked", request.request.header("transfer-encoding").?);
            try std.testing.expectEqualStrings("Digest, X-Upload-Complete", request.request.header("trailer").?);
            try std.testing.expectEqual(@as(usize, 2), request.request.trailers.len);
            try std.testing.expectEqualStrings("Digest", request.request.trailers[0].name);
            try std.testing.expectEqualStrings("sha-256=demo, sha-256=second", request.request.trailers[0].value);
            try std.testing.expectEqualStrings("X-Upload-Complete", request.request.trailers[1].name);
            try std.testing.expectEqualStrings("yes", request.request.trailers[1].value);

            try connection.writeResponse(.{ .body = "ok" });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    var response = try client.request(.{
        .method = .POST,
        .target = "/upload",
        .headers = &.{.{ .name = "Host", .value = "127.0.0.1" }},
        .body = "upload",
        .trailers = &.{
            .{ .name = "Digest", .value = "sha-256=demo" },
            .{ .name = "digest", .value = "sha-256=second" },
            .{ .name = "X-Upload-Complete", .value = "yes" },
        },
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("ok", response.response.body);
}

test "HTTP/1 runtime writes response trailers with chunked framing" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
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

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/download", request.request.target);
            try std.testing.expectEqualStrings("trailers", request.request.header("te").?);

            try connection.writeResponse(.{
                .status = 200,
                .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
                .body = "download",
                .trailers = &.{
                    .{ .name = "Digest", .value = "sha-256=response" },
                    .{ .name = "digest", .value = "sha-256=second" },
                },
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    var response = try client.request(.{
        .method = .GET,
        .target = "/download",
        .headers = &.{
            .{ .name = "Host", .value = "127.0.0.1" },
            .{ .name = "TE", .value = "trailers" },
        },
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqual(http1.BodyFraming.chunked, response.response.body_framing);
    try std.testing.expectEqualStrings("download", response.response.body);
    try std.testing.expectEqualStrings("chunked", response.response.header("transfer-encoding").?);
    try std.testing.expectEqualStrings("Digest", response.response.header("trailer").?);
    try std.testing.expectEqual(@as(usize, 1), response.response.trailers.len);
    try std.testing.expectEqualStrings("Digest", response.response.trailers[0].name);
    try std.testing.expectEqualStrings("sha-256=response, sha-256=second", response.response.trailers[0].value);
}

test "HTTP/1 runtime honors explicit transfer-encoding chunked writes" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
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

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqual(http1.BodyFraming.chunked, request.request.body_framing);
            try std.testing.expectEqualStrings("streamed", request.request.body);
            try std.testing.expectEqual(@as(?[]const u8, null), request.request.header("content-length"));
            try std.testing.expectEqual(@as(?[]const u8, null), request.request.header("trailer"));

            try connection.writeResponse(.{
                .headers = &.{.{ .name = "Transfer-Encoding", .value = "chunked" }},
                .body = "accepted",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    var response = try client.request(.{
        .method = .POST,
        .target = "/explicit-chunked",
        .headers = &.{
            .{ .name = "Host", .value = "127.0.0.1" },
            .{ .name = "Transfer-Encoding", .value = "chunked" },
            .{ .name = "Content-Length", .value = "999" },
        },
        .body = "streamed",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(http1.BodyFraming.chunked, response.response.body_framing);
    try std.testing.expectEqualStrings("accepted", response.response.body);
    try std.testing.expectEqual(@as(?[]const u8, null), response.response.header("content-length"));
    try std.testing.expectEqual(@as(usize, 0), response.response.trailers.len);
}

test "HTTP/1 client reads close-delimited response body" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
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

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/close-delimited", request.request.target);

            // No Content-Length or Transfer-Encoding: the response body is
            // delimited by closing the connection, which remains common for
            // simple HTTP/1.0-style origin/proxy responses.
            try writeAll(server_ptr.io, connection.stream, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nclose-delimited-body");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    var response = try client.request(.{
        .method = .GET,
        .target = "/close-delimited",
        .headers = &.{.{ .name = "Host", .value = "127.0.0.1" }},
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqual(http1.BodyFraming.close_delimited, response.response.body_framing);
    try std.testing.expectEqualStrings("close-delimited-body", response.response.body);
}

test "HTTP/1 client treats non-chunked response transfer coding as close-delimited" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
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

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/te-close-delimited", request.request.target);

            // Hyper treats a response with a non-chunked transfer coding as
            // close-delimited.  Requests remain strict because accepting
            // unsupported request transfer codings is a smuggling risk.
            try writeAll(server_ptr.io, connection.stream, "HTTP/1.1 200 OK\r\nTransfer-Encoding: yolo\r\nContent-Length: 999\r\nConnection: close\r\n\r\nclose-delimited-body");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    var response = try client.request(.{
        .method = .GET,
        .target = "/te-close-delimited",
        .headers = &.{.{ .name = "Host", .value = "127.0.0.1" }},
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqual(http1.BodyFraming.close_delimited, response.response.body_framing);
    try std.testing.expectEqualStrings("yolo", response.response.header("transfer-encoding").?);
    try std.testing.expect(response.response.header("content-length") == null);
    try std.testing.expectEqualStrings("close-delimited-body", response.response.body);
}

test "HTTP/1 status-forbidden body preserves pipelined response without request context" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
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

            var first = try connection.readRequest(.{});
            defer first.deinit(server_ptr.allocator);
            var second = try connection.readRequest(.{});
            defer second.deinit(server_ptr.allocator);

            try writeAll(server_ptr.io, connection.stream, "HTTP/1.1 204 No Content\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\n" ++
                "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_head_bytes = 4096, .max_body_bytes = 4096 });
    defer client.close();
    const keep_alive = [_]http1.Header{.{ .name = "Connection", .value = "keep-alive" }};
    try writeRequestToStream(allocator, io, client.stream, .{ .target = "/no-content", .headers = &.{ keep_alive[0], .{ .name = "Host", .value = "localhost" } } });
    try writeRequestToStream(allocator, io, client.stream, .{ .target = "/next", .headers = &.{ keep_alive[0], .{ .name = "Host", .value = "localhost" } } });

    var first_response = try readResponseFromStreamBuffered(allocator, io, client.stream, client.limits, .{}, &client.inbuf);
    defer first_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), first_response.response.status);
    try std.testing.expectEqualStrings("", first_response.response.body);

    var second_response = try readResponseFromStreamBuffered(allocator, io, client.stream, client.limits, .{}, &client.inbuf);
    defer second_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), second_response.response.status);
    try std.testing.expectEqualStrings("pong", second_response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 runtime does not default Content-Length for status-forbidden responses" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
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
            var request = connection.readRequest(.{}) catch |err| {
                shared.err = err;
                return;
            };
            defer request.deinit(shared.server.allocator);
            connection.writeResponse(.{ .status = 204, .reason = "No Content" }) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();
    var response = try client.request(.{
        .target = "/no-content",
        .headers = &.{.{ .name = "Host", .value = "127.0.0.1" }},
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 204), response.response.status);
    try std.testing.expect(response.response.header("content-length") == null);
    try std.testing.expectEqualStrings("", response.response.body);
}

test "HTTP/1 runtime does not default Connection close on writes" {
    const allocator = std.testing.allocator;

    var len_buf: [32]u8 = undefined;
    var trailer_value: std.ArrayList(u8) = .empty;
    defer trailer_value.deinit(allocator);
    var headers: std.ArrayList(http1.Header) = .empty;
    defer headers.deinit(allocator);

    try appendDefaultedHeaders(&headers, allocator, &.{}, 0, &.{}, false, true, &len_buf, &trailer_value);
    try std.testing.expect(wire.findHeader(headers.items, "connection") == null);
    try std.testing.expectEqualStrings("0", wire.findHeader(headers.items, "content-length").?);

    headers.clearRetainingCapacity();
    try appendDefaultedHeaders(
        &headers,
        allocator,
        &.{.{ .name = "Connection", .value = "close" }},
        0,
        &.{},
        false,
        true,
        &len_buf,
        &trailer_value,
    );
    try std.testing.expectEqualStrings("close", wire.findHeader(headers.items, "connection").?);
}

test "HTTP/1 request writers default Content-Length by method" {
    try std.testing.expect(!shouldDefaultRequestContentLength(.GET, 0, &.{}));
    try std.testing.expect(!shouldDefaultRequestContentLength(.HEAD, 0, &.{}));
    try std.testing.expect(!shouldDefaultRequestContentLength(.CONNECT, 0, &.{}));
    try std.testing.expect(shouldDefaultRequestContentLength(.POST, 0, &.{}));
    try std.testing.expect(shouldDefaultRequestContentLength(.GET, 1, &.{}));
    try std.testing.expect(shouldDefaultRequestContentLength(.GET, 0, &.{.{ .name = "x-trailer", .value = "ok" }}));
}

test "HTTP/1 request writer omits zero Content-Length for bodyless safe methods" {
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

            var first = try readRequestFromStream(shared.allocator, shared.io, stream, .{
                .max_head_bytes = 4096,
                .max_body_bytes = 4096,
            }, .{});
            defer first.deinit(shared.allocator);
            try std.testing.expectEqual(http1.Method.GET, first.request.method);
            try std.testing.expect(first.request.header("content-length") == null);

            var second = try readRequestFromStream(shared.allocator, shared.io, stream, .{
                .max_head_bytes = 4096,
                .max_body_bytes = 4096,
            }, .{});
            defer second.deinit(shared.allocator);
            try std.testing.expectEqual(http1.Method.POST, second.request.method);
            try std.testing.expectEqualStrings("0", second.request.header("content-length").?);
        }
    };

    var shared = Shared{ .allocator = allocator, .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeRequestToStream(allocator, io, stream, .{
        .method = .GET,
        .target = "/safe",
        .headers = &.{.{ .name = "Host", .value = "example" }},
    });
    try writeRequestToStream(allocator, io, stream, .{
        .method = .POST,
        .target = "/entity",
        .headers = &.{.{ .name = "Host", .value = "example" }},
    });

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 runtime validates outbound request and response framing before writing" {
    const allocator = std.testing.allocator;
    const io: std.Io = undefined;
    const stream: net.Stream = undefined;

    try std.testing.expectError(error.InvalidHost, writeRequestToStream(allocator, io, stream, .{
        .method = .GET,
        .target = "/missing-host",
    }));
    try std.testing.expectError(error.InvalidContentLength, writeRequestToStream(allocator, io, stream, .{
        .method = .POST,
        .target = "/bad-length",
        .headers = &.{
            .{ .name = "Host", .value = "example" },
            .{ .name = "Content-Length", .value = "5" },
        },
        .body = "ping",
    }));
    try std.testing.expectError(error.InvalidContentLength, writeRequestToStream(allocator, io, stream, .{
        .method = .CONNECT,
        .target = "example.com:443",
        .headers = &.{.{ .name = "Host", .value = "example.com:443" }},
        .body = "not allowed",
    }));
    try std.testing.expectError(error.InvalidContentLength, writeResponseToStream(allocator, io, stream, .{
        .status = 200,
        .headers = &.{.{ .name = "Content-Length", .value = "5" }},
        .body = "pong",
    }));
    try std.testing.expectError(error.InvalidContentLength, writeResponseToStream(allocator, io, stream, .{
        .status = 200,
        .headers = &.{.{ .name = "Content-Length", .value = "0" }},
        .request_method = .CONNECT,
    }));
}

test "HTTP/1 runtime target length rejects ambiguous head framing" {
    const conflicting = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!";
    const conflicting_head_end = std.mem.indexOf(u8, conflicting, "\r\n\r\n").?;
    try std.testing.expectError(error.ConflictingContentLength, messageTargetLength(conflicting, conflicting_head_end, 1024, null));

    const coalesced = "HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\n\r\nhello";
    const coalesced_head_end = std.mem.indexOf(u8, coalesced, "\r\n\r\n").?;
    try std.testing.expectEqual(coalesced.len, try messageTargetLength(coalesced, coalesced_head_end, 1024, null));

    const signed_length = "HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\nhello";
    const signed_length_head_end = std.mem.indexOf(u8, signed_length, "\r\n\r\n").?;
    try std.testing.expectError(error.InvalidContentLength, messageTargetLength(signed_length, signed_length_head_end, 1024, null));

    const unsupported_te = "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    const unsupported_te_head_end = std.mem.indexOf(u8, unsupported_te, "\r\n\r\n").?;
    try std.testing.expectError(error.InvalidTransferEncoding, messageTargetLength(unsupported_te, unsupported_te_head_end, 1024, null));

    const signed_chunk = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n+5\r\nhello\r\n0\r\n\r\n";
    const signed_chunk_head_end = std.mem.indexOf(u8, signed_chunk, "\r\n\r\n").?;
    try std.testing.expectError(error.InvalidChunk, messageTargetLength(signed_chunk, signed_chunk_head_end, 1024, null));
}

test "HTTP/1 runtime enforces header byte limit at delimiter" {
    const exact = "GET / HTTP/1.1\r\nHost: example\r\n\r\n";
    try std.testing.expectEqual(@as(?usize, exact.len - 4), try findHttpHeadEndWithinLimit(exact, exact.len));
    try std.testing.expectError(error.HeadersTooLarge, findHttpHeadEndWithinLimit(exact, exact.len - 1));

    const incomplete = "GET / HTTP/1.1\r\nHost: example";
    try std.testing.expectEqual(@as(?usize, null), try findHttpHeadEndWithinLimit(incomplete, incomplete.len + 1));
    try std.testing.expectError(error.HeadersTooLarge, findHttpHeadEndWithinLimit(incomplete, incomplete.len));
}

test "HTTP/1 non-buffered request reader preserves pipelined bytes on socket" {
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

            var first = try readRequestFromStream(shared.allocator, shared.io, stream, .{
                .max_head_bytes = 4096,
                .max_body_bytes = 4096,
            }, .{});
            defer first.deinit(shared.allocator);
            try std.testing.expectEqualStrings("/first", first.request.target);
            try std.testing.expectEqualStrings("hello", first.request.body);

            var second = try readRequestFromStream(shared.allocator, shared.io, stream, .{
                .max_head_bytes = 4096,
                .max_body_bytes = 4096,
            }, .{});
            defer second.deinit(shared.allocator);
            try std.testing.expectEqualStrings("/second", second.request.target);
            try std.testing.expectEqualStrings("world", second.request.body);
        }
    };

    var shared = Shared{ .allocator = allocator, .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeAll(io, stream, "POST /first HTTP/1.1\r\nHost: example\r\nContent-Length: 5\r\n\r\nhello" ++
        "POST /second HTTP/1.1\r\nHost: example\r\nContent-Length: 5\r\n\r\nworld");

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 non-buffered chunked reader preserves pipelined bytes on socket" {
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

            var first = try readRequestFromStream(shared.allocator, shared.io, stream, .{
                .max_head_bytes = 4096,
                .max_body_bytes = 4096,
            }, .{});
            defer first.deinit(shared.allocator);
            try std.testing.expectEqualStrings("/chunked", first.request.target);
            try std.testing.expectEqual(http1.BodyFraming.chunked, first.request.body_framing);
            try std.testing.expectEqualStrings("hello", first.request.body);

            var second = try readRequestFromStream(shared.allocator, shared.io, stream, .{
                .max_head_bytes = 4096,
                .max_body_bytes = 4096,
            }, .{});
            defer second.deinit(shared.allocator);
            try std.testing.expectEqualStrings("/second", second.request.target);
            try std.testing.expectEqualStrings("world", second.request.body);
        }
    };

    var shared = Shared{ .allocator = allocator, .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeAll(io, stream, "POST /chunked HTTP/1.1\r\nHost: example\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nDigest: ok\r\n\r\n" ++
        "POST /second HTTP/1.1\r\nHost: example\r\nContent-Length: 5\r\n\r\nworld");

    thread.join();
    if (shared.err) |err| return err;
}
