//! gRPC-Web translation (https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md).
//!
//! Browsers cannot emit the `te: trailers` header or read HTTP/2 response
//! trailers. gRPC-Web keeps the same length-prefixed request messages but
//! returns terminal status as an in-body frame with the high marker bit
//! (`0x80`) instead of an HTTP trailer block. The `-text` variants carry the
//! entity as independently padded base64 chunks. This module is transport neutral;
//! `runtime.ServerConnection` maps it onto the production HTTP/2 connection.

const std = @import("std");
const http2_mod = @import("../http2/mod.zig");
const call = @import("call.zig");
const wire = @import("wire.zig");
const compression_mod = @import("compression.zig");
const metadata_mod = @import("metadata.zig");
const codec = @import("stream/codec.zig");
const content_type_mod = @import("web/content_type.zig");
const text = @import("web/text.zig");
const response_headers = @import("web/response_headers.zig");
pub const cors = @import("web/cors/mod.zig");
pub const http1 = @import("web/http1/mod.zig");
pub const http2 = @import("web/http2/mod.zig");

test {
    _ = response_headers;
    _ = cors;
    _ = http1;
    _ = http2;
    _ = @import("web/tests.zig");
    _ = @import("web/streaming_tests.zig");
}

pub const Error = call.Error || codec.Error || content_type_mod.Error || text.Error || cors.Error;

pub const Format = content_type_mod.Format;
pub const ContentType = content_type_mod.ContentType;
pub const parseContentType = content_type_mod.parseContentType;
pub const negotiateResponseContentType = content_type_mod.negotiateResponseContentType;

pub const TextDecoder = text.Decoder;
pub const base64DecodeAlloc = text.decodeAlloc;

fn base64EncodeAlloc(
    allocator: std.mem.Allocator,
    input: []const u8,
) std.mem.Allocator.Error![]u8 {
    const encoder = std.base64.standard.Encoder;
    const out = try allocator.alloc(u8, encoder.calcSize(input.len));
    const encoded = encoder.encode(out, input);
    return out[0..encoded.len];
}

/// Parse one unary gRPC-Web request entity. The returned request owns its
/// decoded application message; base64-decoded text intermediates never
/// escape this function.
pub fn parseUnaryRequest(
    allocator: std.mem.Allocator,
    method: []const u8,
    path: []const u8,
    headers: []const http2_mod.Hpack.HeaderField,
    body: []const u8,
    content_type: ContentType,
    max_message_size: usize,
) Error!call.UnaryRequest {
    var owned_wire: ?[]u8 = null;
    defer if (owned_wire) |wire_bytes| allocator.free(wire_bytes);
    const framed = if (content_type.text) blk: {
        const decoded = try base64DecodeAlloc(allocator, body);
        owned_wire = decoded;
        break :blk decoded;
    } else body;

    var request = try call.parseWebUnaryRequest(
        allocator,
        method,
        path,
        headers,
        framed,
        max_message_size,
    );
    errdefer request.deinit();
    if (content_type.text and request.owned_message == null) {
        // The application message borrows the base64-decoded entity; copy it
        // into request-owned storage before that intermediate is freed.
        const owned = try allocator.dupe(u8, request.message.payload);
        request.message.payload = owned;
        request.owned_message = owned;
    }
    return request;
}

/// Build the gRPC-Web response entity: one data frame for the response
/// message followed by one `0x80` trailers frame. Custom metadata and the
/// percent-encoded status message use the same validation as native gRPC.
pub fn buildResponseBody(
    allocator: std.mem.Allocator,
    options: call.UnaryResponseOptions,
) Error![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    var encoded_message: ?compression_mod.EncodedPayload = null;
    defer if (encoded_message) |*encoded| encoded.deinit(allocator);
    const response_algorithm: compression_mod.Algorithm =
        if (options.message != null and
        options.request_accepted_encodings.contains(options.compression))
            options.compression
        else
            .identity;
    if (options.message) |message| {
        encoded_message = try compression_mod.compressAlloc(
            allocator,
            response_algorithm,
            message,
            options.compression_level,
        );
        try wire.writeMessage(
            &body,
            allocator,
            encoded_message.?.bytes,
            encoded_message.?.compressed,
        );
    }

    const trailer_block = try buildTrailerBlock(allocator, .{
        .status = options.status,
        .status_message = options.status_message,
        .retry_pushback_ms = options.retry_pushback_ms,
        .trailing_metadata = options.trailing_metadata,
        .trailing_binary_metadata = options.trailing_binary_metadata,
    });
    defer allocator.free(trailer_block);

    if (trailer_block.len > std.math.maxInt(u32)) {
        return error.MessageTooLarge;
    }
    var frame_header: [5]u8 = undefined;
    frame_header[0] = 0x80;
    std.mem.writeInt(
        u32,
        frame_header[1..5],
        @intCast(trailer_block.len),
        .big,
    );
    try body.appendSlice(allocator, &frame_header);
    try body.appendSlice(allocator, trailer_block);
    return body.toOwnedSlice(allocator);
}

/// Terminal gRPC-Web metadata serialized as one `0x80` frame.
pub const TerminalOptions = response_headers.TerminalOptions;

/// Build the `Name: Value\r\n` trailer block for a terminal gRPC-Web frame.
/// The returned bytes are allocator-owned and omit the five-byte prefix.
pub fn buildTrailerBlock(
    allocator: std.mem.Allocator,
    options: TerminalOptions,
) Error![]u8 {
    try call.validateCustomMetadata(options.trailing_metadata);
    try call.validateCustomBinaryMetadata(options.trailing_binary_metadata);
    // These fields travel in DATA, bypassing HTTP/2's header validation. The
    // gRPC-Web trailers block requires lowercase gRPC metadata names and
    // printable ASCII values, including rejection of CR/LF injection.
    for (options.trailing_metadata) |field| {
        for (field.name) |byte| {
            if (!((byte >= 'a' and byte <= 'z') or
                (byte >= '0' and byte <= '9') or
                byte == '_' or byte == '.' or byte == '-'))
            {
                return error.InvalidMetadata;
            }
        }
        for (field.value) |byte| {
            if (byte < 0x20 or byte > 0x7e) return error.InvalidMetadata;
        }
    }
    var trailer_block: std.ArrayList(u8) = .empty;
    errdefer trailer_block.deinit(allocator);
    var status_buffer: [2]u8 = undefined;
    const status_value = std.fmt.bufPrint(
        &status_buffer,
        "{d}",
        .{@intFromEnum(options.status)},
    ) catch unreachable;
    try trailer_block.print(
        allocator,
        "grpc-status:{s}\r\n",
        .{status_value},
    );
    if (options.status_message) |message| {
        const encoded = try wire.encodeStatusMessageAlloc(allocator, message);
        defer allocator.free(encoded);
        try trailer_block.print(
            allocator,
            "grpc-message:{s}\r\n",
            .{encoded},
        );
    }
    if (options.retry_pushback_ms) |milliseconds| {
        var pushback_buffer: [21]u8 = undefined;
        const pushback = std.fmt.bufPrint(
            &pushback_buffer,
            "{d}",
            .{milliseconds},
        ) catch unreachable;
        try trailer_block.print(
            allocator,
            "grpc-retry-pushback-ms:{s}\r\n",
            .{pushback},
        );
    }
    for (options.trailing_metadata) |field| {
        try trailer_block.print(
            allocator,
            "{s}:{s}\r\n",
            .{ field.name, field.value },
        );
    }
    var trailing_binary = try metadata_mod.encodeFieldsAlloc(
        allocator,
        options.trailing_binary_metadata,
    );
    defer trailing_binary.deinit();
    for (trailing_binary.fields) |field| {
        try trailer_block.print(
            allocator,
            "{s}:{s}\r\n",
            .{ field.name, field.value },
        );
    }
    return trailer_block.toOwnedSlice(allocator);
}

/// Write one unary gRPC-Web response on an HTTP/2 connection. Trailers are
/// delivered in the body (or, for trailers-only responses, in headers), so
/// the stream never uses an HTTP trailer block.
pub fn writeUnaryResponse(
    connection: *http2_mod.runtime.Connection,
    allocator: std.mem.Allocator,
    stream_id: u31,
    options: call.UnaryResponseOptions,
    content_type: ContentType,
) Error!void {
    try call.validateCustomMetadata(options.initial_metadata);
    try call.validateCustomMetadata(options.trailing_metadata);
    try call.validateCustomBinaryMetadata(options.initial_binary_metadata);
    try call.validateCustomBinaryMetadata(options.trailing_binary_metadata);
    if (options.status == .ok and options.message == null) {
        return error.InvalidMessageCount;
    }
    if (options.trailers_only and options.message != null) {
        return error.InvalidMessageCount;
    }

    const response_algorithm: compression_mod.Algorithm =
        if (options.message != null and
        options.request_accepted_encodings.contains(options.compression))
            options.compression
        else
            .identity;

    var headers: response_headers.Block = .{};
    try headers.prepare(allocator, .{
        .content_type = content_type,
        .compression = response_algorithm,
        .accepted_encodings = options.accepted_encodings,
        .initial_metadata = options.initial_metadata,
        .initial_binary_metadata = options.initial_binary_metadata,
        .terminal = if (options.trailers_only) .{
            .status = options.status,
            .status_message = options.status_message,
            .retry_pushback_ms = options.retry_pushback_ms,
            .trailing_metadata = options.trailing_metadata,
            .trailing_binary_metadata = options.trailing_binary_metadata,
        } else null,
    });
    defer headers.deinit(allocator);
    if (options.trailers_only) return connection.writeResponse(stream_id, .{ .headers = headers.fields.items });

    const framed_body = try buildResponseBody(allocator, options);
    defer allocator.free(framed_body);
    const entity = if (content_type.text)
        try base64EncodeAlloc(allocator, framed_body)
    else
        framed_body;
    defer if (content_type.text) allocator.free(entity);
    return connection.writeResponse(stream_id, .{
        .headers = headers.fields.items,
        .body = entity,
    });
}

// ---------------------------------------------------------------------------
// Server streaming
// ---------------------------------------------------------------------------

pub const StreamResponseOptions = struct {
    compression: compression_mod.Algorithm = .identity,
    compression_level: u4 = 6,
    request_accepted_encodings: compression_mod.AlgorithmSet = .{},
    accepted_encodings: compression_mod.AlgorithmSet =
        compression_mod.AlgorithmSet.supported,
    initial_metadata: []const http2_mod.Hpack.HeaderField = &.{},
    initial_binary_metadata: []const metadata_mod.BinaryMetadata = &.{},
    max_message_size: usize = 16 * 1024 * 1024,
};

const Base64Sink = text.EncoderSink(http2_mod.runtime.ResponseWriter);

/// Streaming gRPC-Web response: zero or more data frames followed by one
/// `0x80` trailers frame, all carried in HTTP/2 DATA with END_STREAM.
pub const ServerStreamWriter = struct {
    allocator: std.mem.Allocator,
    transport: http2_mod.runtime.ResponseWriter,
    encoder: codec.Encoder,
    content_type: ContentType,
    base64_sink: Base64Sink = .{},
    finished: bool = false,

    pub fn deinit(self: *ServerStreamWriter) void {
        if (!self.finished) self.transport.deinit();
    }

    pub fn writeMessage(self: *ServerStreamWriter, payload: []const u8) Error!void {
        return self.writeMessageWithOptions(payload, .{});
    }

    pub fn writeMessageWithOptions(
        self: *ServerStreamWriter,
        payload: []const u8,
        options: codec.MessageOptions,
    ) Error!void {
        if (self.finished) return error.InvalidStreamState;
        if (self.content_type.text) {
            self.base64_sink.inner = &self.transport;
            try self.encoder.writeMessageWithOptions(
                &self.base64_sink,
                payload,
                options,
            );
            return self.base64_sink.flushPadding();
        }
        return self.encoder.writeMessageWithOptions(
            &self.transport,
            payload,
            options,
        );
    }

    /// Append the terminal trailers frame and end the HTTP/2 stream without
    /// an HTTP trailer block.
    pub fn finish(
        self: *ServerStreamWriter,
        status: wire.Status,
        status_message: ?[]const u8,
        trailing_metadata: []const http2_mod.Hpack.HeaderField,
        trailing_binary_metadata: []const metadata_mod.BinaryMetadata,
    ) Error!void {
        return self.finishWithOptions(.{
            .status = status,
            .status_message = status_message,
            .trailing_metadata = trailing_metadata,
            .trailing_binary_metadata = trailing_binary_metadata,
        });
    }

    pub fn finishWithOptions(self: *ServerStreamWriter, options: TerminalOptions) Error!void {
        if (self.finished) return error.InvalidStreamState;
        const block = try buildTrailerBlock(self.allocator, options);
        defer self.allocator.free(block);
        if (block.len > std.math.maxInt(u32)) return error.MessageTooLarge;
        var frame_header: [5]u8 = undefined;
        frame_header[0] = 0x80;
        std.mem.writeInt(
            u32,
            frame_header[1..5],
            @intCast(block.len),
            .big,
        );
        if (self.content_type.text) {
            self.base64_sink.inner = &self.transport;
            try self.base64_sink.write(&frame_header);
            try self.base64_sink.write(block);
            try self.base64_sink.flushPadding();
        } else {
            try self.transport.write(&frame_header);
            try self.transport.write(block);
        }
        try self.transport.finishData(&.{});
        self.finished = true;
    }

    pub fn finishOk(self: *ServerStreamWriter) Error!void {
        return self.finish(.ok, null, &.{}, &.{});
    }
};

/// Start a gRPC-Web server-streaming response with the negotiated wire.
pub fn startServerStream(
    connection: *http2_mod.runtime.Connection,
    allocator: std.mem.Allocator,
    stream_id: u31,
    options: StreamResponseOptions,
    content_type: ContentType,
) Error!ServerStreamWriter {
    try call.validateCustomMetadata(options.initial_metadata);
    try call.validateCustomBinaryMetadata(options.initial_binary_metadata);
    const response_algorithm: compression_mod.Algorithm =
        if (options.request_accepted_encodings.contains(options.compression))
            options.compression
        else
            .identity;

    var headers: response_headers.Block = .{};
    try headers.prepare(allocator, .{
        .content_type = content_type,
        .compression = response_algorithm,
        .accepted_encodings = options.accepted_encodings,
        .initial_metadata = options.initial_metadata,
        .initial_binary_metadata = options.initial_binary_metadata,
    });
    defer headers.deinit(allocator);

    const transport = try connection.startResponse(stream_id, .{
        .status = 200,
        .headers = headers.fields.items,
    });
    return .{
        .allocator = allocator,
        .transport = transport,
        .encoder = .{
            .allocator = allocator,
            .algorithm = response_algorithm,
            .compression_level = options.compression_level,
            .max_message_size = options.max_message_size,
        },
        .content_type = content_type,
    };
}
