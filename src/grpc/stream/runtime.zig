//! Client/server gRPC message streams over HTTP/2 DATA callbacks.
//!
//! The HTTP/2 runtime owns connection flow control and stream cancellation.
//! This layer validates gRPC metadata before DATA, reassembles arbitrary
//! five-byte-prefix/payload splits, applies compression independently per
//! message, and validates terminal grpc-status trailers. The current blocking
//! transport completes the request half before consuming response messages;
//! it supports client-streaming and server-streaming sequences, not interleaved
//! full-duplex bidi scheduling.

const std = @import("std");
const http2 = @import("../../http2/mod.zig");
const call = @import("../call.zig");
const compression = @import("../compression.zig");
const metadata = @import("../metadata.zig");
const wire = @import("../wire.zig");
const codec = @import("codec.zig");

pub const Error = call.Error || codec.Error || error{
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
    metadata: []const http2.Hpack.HeaderField = &.{},
    binary_metadata: []const metadata.BinaryMetadata = &.{},
    max_message_size: usize = 16 * 1024 * 1024,
};

pub const ClientWriter = struct {
    allocator: std.mem.Allocator,
    transport: http2.runtime.RequestWriter,
    encoder: codec.Encoder,
    accepted_encodings: compression.AlgorithmSet,
    max_message_size: usize,

    pub fn deinit(self: *ClientWriter) void {
        self.transport.deinit();
        self.* = undefined;
    }

    pub fn writeMessage(
        self: *ClientWriter,
        payload: []const u8,
    ) Error!void {
        try self.encoder.writeMessage(&self.transport, payload);
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
        self.writeMessage(payload) catch |err| switch (err) {
            error.ResponseAvailable => {
                return try self.readResponse(context, consume);
            },
            else => return err,
        };
        return null;
    }

    pub fn finish(self: *ClientWriter) Error!void {
        try self.transport.finish();
    }

    /// Finish the request side and consume all response messages.
    pub fn finishAndRead(
        self: *ClientWriter,
        context: anytype,
        comptime consume: anytype,
    ) !Response {
        try self.finish();
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
        var response = self.transport.readResponseStreamingWithHead(
            &bridge,
            @TypeOf(bridge).begin,
            @TypeOf(bridge).consumeData,
        ) catch |err| {
            self.transport.completed = true;
            return err;
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
            .status = result.status,
            .status_message = result.status_message,
            .encoding = result.encoding,
        };
    }
};

pub fn startClient(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    options: RequestOptions,
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
    if (options.timeout) |timeout| {
        headers.appendAssumeCapacity(.{
            .name = "grpc-timeout",
            .value = try timeout.formatInto(&timeout_buffer),
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
        .transport = try connection.startRequest(.{
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
            .max_message_size = options.max_message_size,
        },
        .accepted_encodings = options.accepted_encodings,
        .max_message_size = options.max_message_size,
    };
}

pub const Response = struct {
    allocator: std.mem.Allocator,
    transport: http2.runtime.StreamingResponse,
    status: wire.Status,
    status_message: []u8,
    encoding: ?[]const u8,

    pub fn deinit(self: *Response) void {
        self.allocator.free(self.status_message);
        self.transport.deinit(self.allocator);
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
    );
    defer bridge.deinit();
    var request = try connection.readRequestStreamingWithHead(
        &bridge,
        @TypeOf(bridge).begin,
        @TypeOf(bridge).consumeData,
    );
    errdefer request.deinit(allocator);
    bridge.finish() catch |err| {
        // HTTP/2 END_STREAM with a partial gRPC prefix/payload is a stream
        // protocol failure. Match gRPC Core's message assembler behavior by
        // terminating this stream rather than leaving it available for a
        // response after surfacing the framing error.
        connection.sendResetStream(
            request.stream_id,
            .internal_error,
        ) catch {};
        return err;
    };
    const parsed = bridge.metadata orelse return error.InvalidGrpcRequest;
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
        try self.encoder.writeMessage(&self.transport, payload);
    }

    pub fn finish(
        self: *ServerWriter,
        status: wire.Status,
        status_message: ?[]const u8,
        trailing_metadata: []const http2.Hpack.HeaderField,
        trailing_binary_metadata: []const metadata.BinaryMetadata,
    ) Error!void {
        try call.validateCustomMetadata(trailing_metadata);
        try call.validateCustomBinaryMetadata(trailing_binary_metadata);
        var binary = try metadata.encodeFieldsAlloc(
            self.allocator,
            trailing_binary_metadata,
        );
        defer binary.deinit();
        var status_buffer: [2]u8 = undefined;
        const status_value = std.fmt.bufPrint(
            &status_buffer,
            "{d}",
            .{@intFromEnum(status)},
        ) catch unreachable;
        const encoded_message = if (status_message) |message|
            try wire.encodeStatusMessageAlloc(self.allocator, message)
        else
            try self.allocator.alloc(u8, 0);
        defer self.allocator.free(encoded_message);

        var storage: [16]http2.Hpack.HeaderField = undefined;
        const count = std.math.add(
            usize,
            std.math.add(
                usize,
                trailing_metadata.len,
                binary.fields.len,
            ) catch return error.MessageTooLarge,
            1 + @intFromBool(status_message != null),
        ) catch return error.MessageTooLarge;
        const buffer = if (count <= storage.len)
            storage[0..count]
        else
            try self.allocator.alloc(http2.Hpack.HeaderField, count);
        defer if (buffer.ptr != storage[0..].ptr) {
            self.allocator.free(buffer);
        };
        var trailers: std.ArrayList(http2.Hpack.HeaderField) =
            .initBuffer(buffer);
        trailers.appendAssumeCapacity(.{
            .name = "grpc-status",
            .value = status_value,
        });
        if (status_message != null) {
            trailers.appendAssumeCapacity(.{
                .name = "grpc-message",
                .value = encoded_message,
            });
        }
        trailers.appendSliceAssumeCapacity(trailing_metadata);
        trailers.appendSliceAssumeCapacity(binary.fields);
        try self.transport.finishTrailers(trailers.items);
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
    const algorithm = if (options.request_accepted_encodings.contains(
        options.compression,
    ))
        options.compression
    else
        .identity;

    var storage: [16]http2.Hpack.HeaderField = undefined;
    const count = std.math.add(
        usize,
        std.math.add(
            usize,
            options.initial_metadata.len,
            binary.fields.len,
        ) catch return error.MessageTooLarge,
        3,
    ) catch return error.MessageTooLarge;
    const buffer = if (count <= storage.len)
        storage[0..count]
    else
        try allocator.alloc(http2.Hpack.HeaderField, count);
    defer if (buffer.ptr != storage[0..].ptr) allocator.free(buffer);
    var headers: std.ArrayList(http2.Hpack.HeaderField) =
        .initBuffer(buffer);
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
    var accept_buffer: [32]u8 = undefined;
    headers.appendAssumeCapacity(.{
        .name = "grpc-accept-encoding",
        .value = try compression.formatAcceptEncodingInto(
            &accept_buffer,
            options.accepted_encodings,
        ),
    });
    headers.appendSliceAssumeCapacity(options.initial_metadata);
    headers.appendSliceAssumeCapacity(binary.fields);

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
            const content_type = call.headerValue(
                head.headers,
                "content-type",
            );
            const status_raw = call.headerValue(
                head.headers,
                "grpc-status",
            );
            const grpc_content_type = content_type != null and
                wire.isContentType(content_type.?);
            self.parse_body =
                grpc_content_type and
                (head.status == 200 or status_raw != null);
            if ((head.status == 200 or status_raw != null) and
                !grpc_content_type)
            {
                return error.InvalidContentType;
            }
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
        metadata: ?call.RequestMetadata = null,
        decoder: ?codec.Decoder = null,
        message_count: usize = 0,

        fn init(
            allocator: std.mem.Allocator,
            max_message_size: usize,
            context: Context,
        ) @This() {
            return .{
                .allocator = allocator,
                .max_message_size = max_message_size,
                .context = context,
            };
        }

        fn deinit(self: *@This()) void {
            if (self.decoder) |*decoder| decoder.deinit();
        }

        fn begin(
            self: *@This(),
            head: http2.runtime.StreamingRequestHead,
        ) Error!void {
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
            try deliver(self.context, message);
            self.message_count += 1;
        }

        fn finish(self: *@This()) Error!void {
            const decoder = if (self.decoder) |*value|
                value
            else
                return error.InvalidStreamState;
            try decoder.finish();
        }
    };
}

const ParsedResponseTerminal = struct {
    status: wire.Status,
    status_message: []u8,
    encoding: ?[]const u8,
};

fn parseResponseTerminal(
    allocator: std.mem.Allocator,
    http_status: u16,
    headers: []const http2.Hpack.HeaderField,
    trailers: []const http2.Hpack.HeaderField,
    encoding: ?[]const u8,
) Error!ParsedResponseTerminal {
    const status_raw = call.headerValue(
        trailers,
        "grpc-status",
    ) orelse call.headerValue(headers, "grpc-status");
    const status = if (status_raw) |raw|
        wire.Status.parse(raw) catch .unknown
    else
        call.statusFromHttp(http_status);
    if (status_raw == null and http_status == 200) {
        return error.MissingGrpcStatus;
    }
    const message_raw = call.headerValue(
        trailers,
        "grpc-message",
    ) orelse call.headerValue(headers, "grpc-message");
    return .{
        .status = status,
        .status_message = if (message_raw) |message|
            try wire.decodeStatusMessageAlloc(allocator, message)
        else if (status_raw == null)
            try std.fmt.allocPrint(
                allocator,
                "HTTP status {d} without grpc-status",
                .{http_status},
            )
        else
            try allocator.alloc(u8, 0),
        .encoding = encoding,
    };
}
