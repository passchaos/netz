//! Client/server gRPC message streams over HTTP/2 DATA callbacks.
//!
//! The HTTP/2 runtime owns connection flow control and stream cancellation.
//! This layer validates gRPC metadata before DATA, reassembles arbitrary
//! five-byte-prefix/payload splits, applies compression independently per
//! message, and validates terminal grpc-status trailers. This file keeps the
//! sequential API; `duplex.zig` layers a single-owner step driver over the same
//! metadata builders and codec policy.

const std = @import("std");
const http2 = @import("../../http2/mod.zig");
const response_metadata = @import("../response_metadata.zig");
const details_mod = @import("../status_details.zig");
const call = @import("../call.zig");
const compression = @import("../compression.zig");
const metadata = @import("../metadata.zig");
const wire = @import("../wire.zig");
const codec = @import("codec.zig");
const web = @import("../web.zig");

pub const Error = call.Error || codec.Error || web.Error || error{
    MissingGrpcStatus,
};

pub const RequestOptions = struct {
    path: []const u8,
    authority: ?[]const u8 = null,
    scheme: ?[]const u8 = null,
    compression: compression.Algorithm = .identity,
    compression_level: u4 = 6,
    accepted_encodings: compression.AlgorithmSet =
        compression.AlgorithmSet.supported,
    timeout: ?wire.Timeout = null,
    /// Explicit channel readiness policy. Null permits service-config policy.
    wait_for_ready: ?bool = null,
    metadata: []const http2.Hpack.HeaderField = &.{},
    binary_metadata: []const metadata.BinaryMetadata = &.{},
    /// Compatibility ceiling used for both directions unless a directional
    /// limit below is stricter.
    max_message_size: usize = 16 * 1024 * 1024,
    max_request_message_size: ?usize = null,
    max_response_message_size: ?usize = null,

    pub fn requestMessageLimit(self: RequestOptions) usize {
        return @min(
            self.max_message_size,
            self.max_request_message_size orelse self.max_message_size,
        );
    }

    pub fn responseMessageLimit(self: RequestOptions) usize {
        return @min(
            self.max_message_size,
            self.max_response_message_size orelse self.max_message_size,
        );
    }
};

pub const ClientWriter = struct {
    allocator: std.mem.Allocator,
    transport: http2.runtime.RequestWriter,
    encoder: codec.Encoder,
    accepted_encodings: compression.AlgorithmSet,
    max_message_size: usize,
    deadline: ?std.Io.Clock.Timestamp = null,

    pub fn deinit(self: *ClientWriter) void {
        self.transport.deinit();
        self.* = undefined;
    }

    pub fn writeMessage(
        self: *ClientWriter,
        payload: []const u8,
    ) Error!void {
        return self.writeMessageWithOptions(payload, .{});
    }

    pub fn writeMessageWithOptions(
        self: *ClientWriter,
        payload: []const u8,
        options: codec.MessageOptions,
    ) Error!void {
        if (self.deadline) |deadline| {
            self.encoder.writeMessageWithOptionsAndDeadline(
                &self.transport,
                payload,
                options,
                deadline,
            ) catch |err| {
                if (err == error.Timeout) self.cancelAfterDeadline();
                return err;
            };
        } else {
            try self.encoder.writeMessageWithOptions(
                &self.transport,
                payload,
                options,
            );
        }
    }

    /// Write one message, or consume a response that ended the upload early.
    ///
    /// A non-null result means the HTTP/2 writer encountered response HEADERS
    /// while waiting for flow-control credit. The transport has already
    /// half-closed the request direction and retained that frame, so callers
    /// can inspect typed gRPC status instead of losing it behind
    /// `ResponseAvailable`. Normal progress returns null.
    pub fn writeMessageOrReadResponse(
        self: *ClientWriter,
        payload: []const u8,
        context: anytype,
        comptime consume: anytype,
    ) !?Response {
        return self.writeMessageWithOptionsOrReadResponse(
            payload,
            .{},
            context,
            consume,
        );
    }

    pub fn writeMessageWithOptionsOrReadResponse(
        self: *ClientWriter,
        payload: []const u8,
        options: codec.MessageOptions,
        context: anytype,
        comptime consume: anytype,
    ) !?Response {
        self.writeMessageWithOptions(payload, options) catch |err| switch (err) {
            error.ResponseAvailable => {
                return try self.readResponse(context, consume);
            },
            error.StreamReset => return try self.takeResetResponse(),
            else => return err,
        };
        return null;
    }

    pub fn finish(self: *ClientWriter) Error!void {
        if (self.deadline) |deadline| {
            self.transport.finishWithDeadline(deadline) catch |err| {
                if (err == error.Timeout) self.cancelAfterDeadline();
                return err;
            };
        } else {
            try self.transport.finish();
        }
    }

    /// Cancel both halves with HTTP/2 CANCEL. This is idempotent once the
    /// transport has reached a terminal state.
    pub fn cancel(self: *ClientWriter) Error!void {
        try self.transport.cancel(.cancel);
    }

    /// Finish the request side and consume all response messages.
    pub fn finishAndRead(
        self: *ClientWriter,
        context: anytype,
        comptime consume: anytype,
    ) !Response {
        self.finish() catch |err| switch (err) {
            error.StreamReset => return try self.takeResetResponse(),
            else => return err,
        };
        return self.readResponse(context, consume);
    }

    /// Consume the response after request DATA has already been finished.
    pub fn readResponse(
        self: *ClientWriter,
        context: anytype,
        comptime consume: anytype,
    ) !Response {
        var bridge = ClientResponseBridge(@TypeOf(context), consume).init(
            self.allocator,
            self.max_message_size,
            self.accepted_encodings,
            context,
        );
        defer bridge.deinit();
        var response = (if (self.deadline) |deadline|
            self.transport.readResponseStreamingWithHeadAndDeadline(
                deadline,
                &bridge,
                @TypeOf(bridge).begin,
                @TypeOf(bridge).consumeData,
            )
        else
            self.transport.readResponseStreamingWithHead(
                &bridge,
                @TypeOf(bridge).begin,
                @TypeOf(bridge).consumeData,
            )) catch |err| {
            self.transport.completed = true;
            switch (err) {
                error.StreamReset => return try self.takeResetResponse(),
                else => return err,
            }
        };
        errdefer response.deinit(self.allocator);
        bridge.finish() catch |err| {
            // The HTTP/2 reader has already released the transport stream at
            // END_STREAM, so only the gRPC framing error remains to surface.
            // No reset can be sent after this point.
            return err;
        };
        const result = try parseResponseTerminal(
            self.allocator,
            response.status,
            response.headers,
            response.trailers,
            bridge.encoding,
        );
        return .{
            .allocator = self.allocator,
            .transport = response,
            .reset = null,
            .status = result.status,
            .status_message = result.status_message,
            .status_details = result.status_details,
            .encoding = result.encoding,
        };
    }

    fn cancelAfterDeadline(self: *ClientWriter) void {
        self.transport.cancel(.cancel) catch {};
    }

    fn takeResetResponse(self: *ClientWriter) Error!Response {
        const reset = self.transport.connection.takeLastPeerReset() orelse
            return error.StreamReset;
        // RST_STREAM fully closes both halves. Suppress RequestWriter.deinit's
        // fallback cancellation now that the peer's terminal state is owned
        // by the typed gRPC response.
        self.transport.completed = true;
        return resetResponse(self.allocator, reset);
    }
};

pub fn startClient(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    options: RequestOptions,
) Error!ClientWriter {
    const deadline: ?std.Io.Clock.Timestamp = if (options.timeout) |timeout|
        std.Io.Clock.Timestamp.fromNow(connection.io, .{
            .raw = timeout.duration(),
            .clock = .awake,
        })
    else
        null;
    return startClientUnderDeadline(
        connection,
        allocator,
        options,
        deadline,
    );
}

/// Start a stream under a deadline captured before channel readiness.
pub fn startClientUnderDeadline(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    options: RequestOptions,
    deadline: ?std.Io.Clock.Timestamp,
) Error!ClientWriter {
    return startClientWithDeadlines(connection, allocator, options, deadline, deadline);
}

fn startClientWithDeadlines(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    options: RequestOptions,
    rpc_deadline: ?std.Io.Clock.Timestamp,
    io_deadline: ?std.Io.Clock.Timestamp,
) Error!ClientWriter {
    _ = try call.parseRequestMetadata(
        "POST",
        options.path,
        &.{
            .{ .name = "content-type", .value = "application/grpc+proto" },
            .{ .name = "te", .value = "trailers" },
        },
    );
    try call.validateCustomMetadata(options.metadata);
    try call.validateCustomBinaryMetadata(options.binary_metadata);
    var binary = try metadata.encodeFieldsAlloc(
        allocator,
        options.binary_metadata,
    );
    defer binary.deinit();

    var header_storage: [16]http2.Hpack.HeaderField = undefined;
    const header_count = std.math.add(
        usize,
        options.metadata.len,
        std.math.add(
            usize,
            binary.fields.len,
            5,
        ) catch return error.MessageTooLarge,
    ) catch return error.MessageTooLarge;
    const buffer = if (header_count <= header_storage.len)
        header_storage[0..header_count]
    else
        try allocator.alloc(http2.Hpack.HeaderField, header_count);
    defer if (buffer.ptr != header_storage[0..].ptr) allocator.free(buffer);
    var headers: std.ArrayList(http2.Hpack.HeaderField) =
        .initBuffer(buffer);
    headers.appendAssumeCapacity(.{
        .name = "content-type",
        .value = "application/grpc+proto",
    });
    headers.appendAssumeCapacity(.{
        .name = "te",
        .value = "trailers",
    });
    var timeout_buffer: [9]u8 = undefined;
    if (rpc_deadline) |absolute| {
        const remaining = absolute.durationFromNow(connection.io).raw;
        if (remaining.nanoseconds <= 0) return error.Timeout;
        headers.appendAssumeCapacity(.{
            .name = "grpc-timeout",
            .value = try (try wire.Timeout.fromDuration(remaining))
                .formatInto(&timeout_buffer),
        });
    }
    if (options.compression != .identity) {
        headers.appendAssumeCapacity(.{
            .name = "grpc-encoding",
            .value = options.compression.name(),
        });
    }
    var accept_encoding_buffer: [32]u8 = undefined;
    headers.appendAssumeCapacity(.{
        .name = "grpc-accept-encoding",
        .value = try compression.formatAcceptEncodingInto(
            &accept_encoding_buffer,
            options.accepted_encodings,
        ),
    });
    headers.appendSliceAssumeCapacity(options.metadata);
    headers.appendSliceAssumeCapacity(binary.fields);

    return .{
        .allocator = allocator,
        .transport = if (io_deadline) |absolute|
            try connection.startRequestWithDeadline(.{
                .method = "POST",
                .path = options.path,
                .scheme = options.scheme,
                .authority = options.authority,
                .headers = headers.items,
            }, absolute)
        else
            try connection.startRequest(.{
                .method = "POST",
                .path = options.path,
                .scheme = options.scheme,
                .authority = options.authority,
                .headers = headers.items,
            }),
        .encoder = .{
            .allocator = allocator,
            .algorithm = options.compression,
            .compression_level = options.compression_level,
            .max_message_size = options.requestMessageLimit(),
        },
        .accepted_encodings = options.accepted_encodings,
        .max_message_size = options.responseMessageLimit(),
        .deadline = rpc_deadline,
    };
}

/// Start the HTTP/2 request and transfer it to the step-driven duplex owner.
/// Kept here so sequential and duplex calls cannot drift in their gRPC header
/// construction or compression negotiation.
pub const ClientDuplexTransport = struct {
    transport: http2.runtime.ClientDuplexStream,
    deadline: ?std.Io.Clock.Timestamp,
};

pub fn startClientDuplexTransport(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    options: RequestOptions,
) Error!ClientDuplexTransport {
    var writer = try startClient(connection, allocator, options);
    return beginClientDuplexTransport(&writer);
}

pub fn startClientDuplexTransportUnderDeadline(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    options: RequestOptions,
    deadline: ?std.Io.Clock.Timestamp,
) Error!ClientDuplexTransport {
    var writer = try startClientUnderDeadline(
        connection,
        allocator,
        options,
        deadline,
    );
    return beginClientDuplexTransport(&writer);
}

/// Bound request setup without advertising a lifetime for a long-lived RPC.
pub fn startClientDuplexTransportWithIoDeadline(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    options: RequestOptions,
    deadline: std.Io.Clock.Timestamp,
) Error!ClientDuplexTransport {
    if (deadline.clock != .awake or
        deadline.durationFromNow(connection.io).raw.nanoseconds <= 0)
    {
        return error.Timeout;
    }
    var writer = try startClientWithDeadlines(
        connection,
        allocator,
        options,
        null,
        deadline,
    );
    return beginClientDuplexTransport(&writer);
}

fn beginClientDuplexTransport(
    writer: *ClientWriter,
) Error!ClientDuplexTransport {
    errdefer writer.deinit();
    const transport = try writer.transport.beginDuplex();
    const deadline = writer.deadline;
    // beginDuplex has transferred both HTTP/2 halves and made the writer
    // inert. Marking this local value undefined documents that it must not run
    // its cancellation deinitializer after the transfer.
    writer.* = undefined;
    return .{ .transport = transport, .deadline = deadline };
}

fn resetResponse(
    allocator: std.mem.Allocator,
    reset: http2.ResetStreamPayload,
) Error!Response {
    return .{
        .allocator = allocator,
        .transport = null,
        .reset = reset,
        .status = call.statusFromHttp2Error(reset.error_code),
        .status_message = try call.resetStatusMessageAlloc(
            allocator,
            reset.error_code,
        ),
        .encoding = null,
    };
}

pub const Response = struct {
    allocator: std.mem.Allocator,
    /// Null when the peer reset the stream before a complete HTTP response.
    transport: ?http2.runtime.StreamingResponse,
    reset: ?http2.ResetStreamPayload = null,
    status: wire.Status,
    status_message: []u8,
    status_details: ?details_mod.Owned = null,
    encoding: ?[]const u8,

    pub fn deinit(self: *Response) void {
        self.allocator.free(self.status_message);
        if (self.status_details) |*details| details.deinit();
        if (self.transport) |*transport| {
            transport.deinit(self.allocator);
        }
        self.* = undefined;
    }
};

pub const Request = struct {
    allocator: std.mem.Allocator,
    transport: http2.runtime.StreamingRequest,
    path: []const u8,
    service: []const u8,
    method: []const u8,
    timeout: ?wire.Timeout,
    encoding: ?[]const u8,
    accepted_encodings: compression.AlgorithmSet,
    message_count: usize,

    pub fn deinit(self: *Request) void {
        self.transport.deinit(self.allocator);
        self.* = undefined;
    }
};

pub fn readRequest(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    max_message_size: usize,
    context: anytype,
    comptime consume: anytype,
) !Request {
    var bridge = ServerRequestBridge(@TypeOf(context), consume).init(
        allocator,
        max_message_size,
        context,
        false,
    );
    defer bridge.deinit();
    const request = try connection.readRequestStreamingWithHead(
        &bridge,
        @TypeOf(bridge).begin,
        @TypeOf(bridge).consumeData,
    );
    return finishRequest(connection, allocator, &bridge, request);
}

/// One gRPC-Web server-streaming request plus the negotiated text or binary
/// wire its response must use.
pub const WebRequest = struct {
    request: Request,
    content_type: web.ContentType,

    pub fn deinit(self: *WebRequest) void {
        self.request.deinit();
        self.* = undefined;
    }
};

pub fn readWebRequest(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    max_message_size: usize,
    context: anytype,
    comptime consume: anytype,
) !WebRequest {
    var bridge = ServerRequestBridge(@TypeOf(context), consume).init(
        allocator,
        max_message_size,
        context,
        true,
    );
    defer bridge.deinit();
    const request = try connection.readRequestStreamingWithHead(
        &bridge,
        @TypeOf(bridge).begin,
        @TypeOf(bridge).consumeData,
    );
    const finished = try finishRequest(connection, allocator, &bridge, request);
    return .{
        .request = finished,
        .content_type = bridge.response_content_type orelse
            return error.InvalidWebContentType,
    };
}

pub fn readWebRequestWithTimeout(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    max_message_size: usize,
    timeout: std.Io.Duration,
    context: anytype,
    comptime consume: anytype,
) !WebRequest {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return readWebRequestWithDeadline(
        connection,
        allocator,
        max_message_size,
        .fromNow(connection.io, .{ .raw = timeout, .clock = .awake }),
        context,
        consume,
    );
}

pub fn readWebRequestWithDeadline(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    max_message_size: usize,
    deadline: std.Io.Clock.Timestamp,
    context: anytype,
    comptime consume: anytype,
) !WebRequest {
    var bridge = ServerRequestBridge(@TypeOf(context), consume).init(
        allocator,
        max_message_size,
        context,
        true,
    );
    defer bridge.deinit();
    const request = try connection.readRequestStreamingWithHeadAndDeadline(
        deadline,
        &bridge,
        @TypeOf(bridge).begin,
        @TypeOf(bridge).consumeData,
    );
    const finished = try finishRequest(connection, allocator, &bridge, request);
    return .{
        .request = finished,
        .content_type = bridge.response_content_type orelse
            return error.InvalidWebContentType,
    };
}

fn finishRequest(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    bridge: anytype,
    request_value: http2.runtime.StreamingRequest,
) !Request {
    var request = request_value;
    errdefer request.deinit(allocator);
    bridge.finish() catch |err| {
        // HTTP/2 END_STREAM with a partial gRPC prefix/payload is a stream
        // protocol failure. Match gRPC Core's message assembler behavior by
        // terminating this stream rather than leaving it available for a
        // response after surfacing the framing error.
        connection.abandonPeerRequest(
            request.stream_id,
            .internal_error,
        );
        return err;
    };
    const parsed = bridge.metadata orelse return error.InvalidGrpcRequest;
    // gRPC-Web server streaming carries exactly one request message; the
    // client-streaming half of bidi is not part of the protocol.
    if (bridge.web and bridge.message_count != 1) {
        connection.abandonPeerRequest(
            request.stream_id,
            .internal_error,
        );
        return error.InvalidMessageCount;
    }
    return .{
        .allocator = allocator,
        .transport = request,
        .path = request.path,
        .service = parsed.service,
        .method = parsed.method,
        .timeout = parsed.timeout,
        .encoding = parsed.encoding,
        .accepted_encodings = parsed.accepted_encodings,
        .message_count = bridge.message_count,
    };
}

pub fn readRequestWithTimeout(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    max_message_size: usize,
    timeout: std.Io.Duration,
    context: anytype,
    comptime consume: anytype,
) !Request {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return readRequestWithDeadline(
        connection,
        allocator,
        max_message_size,
        .fromNow(connection.io, .{ .raw = timeout, .clock = .awake }),
        context,
        consume,
    );
}

pub fn readRequestWithDeadline(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    max_message_size: usize,
    deadline: std.Io.Clock.Timestamp,
    context: anytype,
    comptime consume: anytype,
) !Request {
    var bridge = ServerRequestBridge(@TypeOf(context), consume).init(
        allocator,
        max_message_size,
        context,
        false,
    );
    defer bridge.deinit();
    const request = try connection.readRequestStreamingWithHeadAndDeadline(
        deadline,
        &bridge,
        @TypeOf(bridge).begin,
        @TypeOf(bridge).consumeData,
    );
    return finishRequest(connection, allocator, &bridge, request);
}

pub const TerminalOptions = web.TerminalOptions;

pub const ResponseOptions = struct {
    compression: compression.Algorithm = .identity,
    compression_level: u4 = 6,
    request_accepted_encodings: compression.AlgorithmSet = .{},
    accepted_encodings: compression.AlgorithmSet =
        compression.AlgorithmSet.supported,
    initial_metadata: []const http2.Hpack.HeaderField = &.{},
    initial_binary_metadata: []const metadata.BinaryMetadata = &.{},
    max_message_size: usize = 16 * 1024 * 1024,
};

pub const ServerWriter = struct {
    allocator: std.mem.Allocator,
    transport: http2.runtime.ResponseWriter,
    encoder: codec.Encoder,

    pub fn deinit(self: *ServerWriter) void {
        self.transport.deinit();
        self.* = undefined;
    }

    pub fn writeMessage(
        self: *ServerWriter,
        payload: []const u8,
    ) Error!void {
        return self.writeMessageWithOptions(payload, .{});
    }

    pub fn writeMessageWithOptions(
        self: *ServerWriter,
        payload: []const u8,
        options: codec.MessageOptions,
    ) Error!void {
        try self.encoder.writeMessageWithOptions(
            &self.transport,
            payload,
            options,
        );
    }

    pub fn finish(
        self: *ServerWriter,
        status: wire.Status,
        status_message: ?[]const u8,
        trailing_metadata: []const http2.Hpack.HeaderField,
        trailing_binary_metadata: []const metadata.BinaryMetadata,
    ) Error!void {
        return self.finishWithOptions(.{ .status = status, .status_message = status_message, .trailing_metadata = trailing_metadata, .trailing_binary_metadata = trailing_binary_metadata });
    }

    pub fn finishWithOptions(self: *ServerWriter, options: TerminalOptions) Error!void {
        var fields = try terminalFields(self.allocator, options);
        defer fields.deinit();
        try self.transport.finishTrailers(fields.fields);
    }

    pub fn finishOk(self: *ServerWriter) Error!void {
        try self.finish(.ok, null, &.{}, &.{});
    }
};

pub fn startResponse(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    stream_id: u31,
    options: ResponseOptions,
) Error!ServerWriter {
    try call.validateCustomMetadata(options.initial_metadata);
    try call.validateCustomBinaryMetadata(options.initial_binary_metadata);
    var binary = try metadata.encodeFieldsAlloc(
        allocator,
        options.initial_binary_metadata,
    );
    defer binary.deinit();
    const algorithm = responseAlgorithm(options);

    var storage: [16]http2.Hpack.HeaderField = undefined;
    const buffer = try responseHeaderBuffer(
        allocator,
        &storage,
        options,
        binary.fields.len,
    );
    defer if (buffer.ptr != storage[0..].ptr) allocator.free(buffer);
    var headers: std.ArrayList(http2.Hpack.HeaderField) = .initBuffer(buffer);
    var accept_buffer: [32]u8 = undefined;
    try appendResponseHeaders(
        &headers,
        &accept_buffer,
        options,
        algorithm,
        binary.fields,
    );

    return .{
        .allocator = allocator,
        .transport = try connection.startResponse(stream_id, .{
            .status = 200,
            .headers = headers.items,
        }),
        .encoder = .{
            .allocator = allocator,
            .algorithm = algorithm,
            .compression_level = options.compression_level,
            .max_message_size = options.max_message_size,
        },
    };
}

pub fn startDuplexResponse(
    transport: *http2.runtime.ServerDuplexStream,
    allocator: std.mem.Allocator,
    options: ResponseOptions,
) Error!void {
    try call.validateCustomMetadata(options.initial_metadata);
    try call.validateCustomBinaryMetadata(options.initial_binary_metadata);
    var binary = try metadata.encodeFieldsAlloc(
        allocator,
        options.initial_binary_metadata,
    );
    defer binary.deinit();
    const algorithm = responseAlgorithm(options);

    var storage: [16]http2.Hpack.HeaderField = undefined;
    const buffer = try responseHeaderBuffer(
        allocator,
        &storage,
        options,
        binary.fields.len,
    );
    defer if (buffer.ptr != storage[0..].ptr) allocator.free(buffer);
    var headers: std.ArrayList(http2.Hpack.HeaderField) = .initBuffer(buffer);
    var accept_buffer: [32]u8 = undefined;
    try appendResponseHeaders(
        &headers,
        &accept_buffer,
        options,
        algorithm,
        binary.fields,
    );
    try transport.startResponse(.{ .status = 200, .headers = headers.items });
}

fn responseAlgorithm(options: ResponseOptions) compression.Algorithm {
    return if (options.request_accepted_encodings.contains(options.compression))
        options.compression
    else
        .identity;
}

fn responseHeaderBuffer(
    allocator: std.mem.Allocator,
    stack: []http2.Hpack.HeaderField,
    options: ResponseOptions,
    binary_count: usize,
) Error![]http2.Hpack.HeaderField {
    const count = std.math.add(
        usize,
        std.math.add(usize, options.initial_metadata.len, binary_count) catch
            return error.MessageTooLarge,
        3,
    ) catch return error.MessageTooLarge;
    return if (count <= stack.len) stack[0..count] else allocator.alloc(http2.Hpack.HeaderField, count);
}

fn appendResponseHeaders(
    headers: *std.ArrayList(http2.Hpack.HeaderField),
    accept_buffer: *[32]u8,
    options: ResponseOptions,
    algorithm: compression.Algorithm,
    binary_fields: []const http2.Hpack.HeaderField,
) Error!void {
    headers.appendAssumeCapacity(.{
        .name = "content-type",
        .value = "application/grpc+proto",
    });
    if (algorithm != .identity) {
        headers.appendAssumeCapacity(.{
            .name = "grpc-encoding",
            .value = algorithm.name(),
        });
    }
    headers.appendAssumeCapacity(.{
        .name = "grpc-accept-encoding",
        .value = try compression.formatAcceptEncodingInto(
            accept_buffer,
            options.accepted_encodings,
        ),
    });
    headers.appendSliceAssumeCapacity(options.initial_metadata);
    headers.appendSliceAssumeCapacity(binary_fields);
}

const terminalFields = @import("terminal.zig").build;

pub fn finishDuplexTrailers(
    transport: *http2.runtime.ServerDuplexStream,
    allocator: std.mem.Allocator,
    status: wire.Status,
    status_message: ?[]const u8,
    trailing_metadata: []const http2.Hpack.HeaderField,
    trailing_binary_metadata: []const metadata.BinaryMetadata,
) Error!void {
    return finishDuplexTrailersWithOptions(transport, allocator, .{ .status = status, .status_message = status_message, .trailing_metadata = trailing_metadata, .trailing_binary_metadata = trailing_binary_metadata });
}

pub fn finishDuplexTrailersWithOptions(transport: *http2.runtime.ServerDuplexStream, allocator: std.mem.Allocator, options: TerminalOptions) Error!void {
    var fields = try terminalFields(allocator, options);
    defer fields.deinit();
    try transport.finishResponseTrailers(fields.fields);
}

pub fn finishDuplexHeadersOnly(
    transport: *http2.runtime.ServerDuplexStream,
    allocator: std.mem.Allocator,
    status: wire.Status,
    status_message: ?[]const u8,
    trailing_metadata: []const http2.Hpack.HeaderField,
    trailing_binary_metadata: []const metadata.BinaryMetadata,
) Error!void {
    return finishDuplexHeadersOnlyWithOptions(transport, allocator, .{ .status = status, .status_message = status_message, .trailing_metadata = trailing_metadata, .trailing_binary_metadata = trailing_binary_metadata });
}

pub fn finishDuplexHeadersOnlyWithOptions(transport: *http2.runtime.ServerDuplexStream, allocator: std.mem.Allocator, options: TerminalOptions) Error!void {
    var terminal = try terminalFields(allocator, options);
    defer terminal.deinit();
    const count = std.math.add(usize, terminal.fields.len, 1) catch
        return error.MessageTooLarge;
    const headers = try allocator.alloc(http2.Hpack.HeaderField, count);
    defer allocator.free(headers);
    headers[0] = .{
        .name = "content-type",
        .value = "application/grpc+proto",
    };
    @memcpy(headers[1..], terminal.fields);
    try transport.finishResponseHeaders(.{
        .status = 200,
        .headers = headers,
    });
}

fn ClientResponseBridge(
    comptime Context: type,
    comptime deliver: anytype,
) type {
    return struct {
        allocator: std.mem.Allocator,
        max_message_size: usize,
        accepted_encodings: compression.AlgorithmSet,
        context: Context,
        decoder: ?codec.Decoder = null,
        encoding: ?[]const u8 = null,
        head_seen: bool = false,
        parse_body: bool = false,

        fn init(
            allocator: std.mem.Allocator,
            max_message_size: usize,
            accepted_encodings: compression.AlgorithmSet,
            context: Context,
        ) @This() {
            return .{
                .allocator = allocator,
                .max_message_size = max_message_size,
                .accepted_encodings = accepted_encodings,
                .context = context,
            };
        }

        fn deinit(self: *@This()) void {
            if (self.decoder) |*decoder| decoder.deinit();
        }

        fn begin(
            self: *@This(),
            head: http2.runtime.StreamingResponseHead,
        ) Error!void {
            self.head_seen = true;
            self.parse_body = response_metadata.parseBody(head.status, head.headers, &.{});
            if (!self.parse_body) return;
            self.encoding = call.headerValue(
                head.headers,
                "grpc-encoding",
            );
            self.decoder = try codec.Decoder.init(
                self.allocator,
                self.max_message_size,
                self.encoding,
                self.accepted_encodings,
            );
        }

        fn consumeData(self: *@This(), data: []const u8) !void {
            if (!self.parse_body) return;
            const decoder = if (self.decoder) |*value|
                value
            else
                return error.InvalidStreamState;
            try decoder.feed(data, self.context, deliver);
        }

        fn finish(self: *@This()) Error!void {
            if (!self.head_seen) return error.InvalidStreamState;
            if (!self.parse_body) return;
            const decoder = if (self.decoder) |*value|
                value
            else
                return error.InvalidStreamState;
            try decoder.finish();
        }
    };
}

fn ServerRequestBridge(
    comptime Context: type,
    comptime deliver: anytype,
) type {
    return struct {
        allocator: std.mem.Allocator,
        max_message_size: usize,
        context: Context,
        web: bool,
        metadata: ?call.RequestMetadata = null,
        response_content_type: ?web.ContentType = null,
        decoder: ?codec.Decoder = null,
        message_count: usize = 0,
        text_decoder: ?web.TextDecoder = null,

        fn init(
            allocator: std.mem.Allocator,
            max_message_size: usize,
            context: Context,
            web_flavor: bool,
        ) @This() {
            return .{
                .allocator = allocator,
                .max_message_size = max_message_size,
                .context = context,
                .web = web_flavor,
            };
        }

        fn deinit(self: *@This()) void {
            if (self.decoder) |*decoder| decoder.deinit();
        }

        fn begin(
            self: *@This(),
            head: http2.runtime.StreamingRequestHead,
        ) Error!void {
            if (self.web) {
                const raw = call.headerValue(
                    head.headers,
                    "content-type",
                ) orelse return error.InvalidContentType;
                const negotiated = try web.parseContentType(raw);
                self.response_content_type = try web.negotiateResponseContentType(negotiated, head.headers);
                if (negotiated.text) {
                    self.text_decoder = .{};
                }
                const parsed = try call.parseWebRequestMetadata(
                    head.method,
                    head.path,
                    head.headers,
                );
                self.metadata = parsed;
                self.decoder = try codec.Decoder.init(
                    self.allocator,
                    self.max_message_size,
                    parsed.encoding,
                    compression.AlgorithmSet.supported,
                );
                return;
            }
            const parsed = try call.parseRequestMetadata(
                head.method,
                head.path,
                head.headers,
            );
            self.metadata = parsed;
            self.decoder = try codec.Decoder.init(
                self.allocator,
                self.max_message_size,
                parsed.encoding,
                compression.AlgorithmSet.supported,
            );
        }

        fn consumeData(self: *@This(), data: []const u8) !void {
            if (self.text_decoder) |*text_decoder| return text_decoder.feed(data, self, consumeDecoded);
            return self.consumeDecoded(data);
        }

        fn consumeDecoded(self: *@This(), data: []const u8) !void {
            const decoder = if (self.decoder) |*value|
                value
            else
                return error.InvalidStreamState;
            try decoder.feed(data, self, deliverMessage);
        }

        fn deliverMessage(
            self: *@This(),
            message: codec.DecodedMessage,
        ) !void {
            if (self.web and self.message_count != 0) return error.InvalidMessageCount;
            try deliver(self.context, message);
            self.message_count += 1;
        }

        fn finish(self: *@This()) !void {
            const decoder = if (self.decoder) |*value|
                value
            else
                return error.InvalidStreamState;
            if (self.text_decoder) |*text_decoder| try text_decoder.finish(self, consumeDecoded);
            try decoder.finish();
        }
    };
}

pub const ParsedResponseTerminal = struct {
    status: wire.Status,
    status_message: []u8,
    status_details: ?details_mod.Owned = null,
    encoding: ?[]const u8,
};

pub fn parseResponseTerminal(
    allocator: std.mem.Allocator,
    http_status: u16,
    headers: []const http2.Hpack.HeaderField,
    trailers: []const http2.Hpack.HeaderField,
    encoding: ?[]const u8,
) Error!ParsedResponseTerminal {
    const terminal = try response_metadata.parseTerminal(allocator, http_status, headers, trailers);
    return .{
        .status = terminal.status,
        .status_message = terminal.status_message,
        .status_details = terminal.status_details,
        .encoding = encoding,
    };
}
