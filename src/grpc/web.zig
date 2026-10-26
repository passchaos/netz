//! gRPC-Web translation (https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md).
//!
//! Browsers cannot emit the `te: trailers` header or read HTTP/2 response
//! trailers. gRPC-Web keeps the same length-prefixed request messages but
//! returns terminal status as an in-body frame with the high marker bit
//! (`0x80`) instead of an HTTP trailer block. The `-text` variants carry the
//! whole entity as standard padded base64. This module is transport neutral;
//! `runtime.ServerConnection` maps it onto the production HTTP/2 connection.

const std = @import("std");
const http2 = @import("../http2/mod.zig");
const call = @import("call.zig");
const wire = @import("wire.zig");
const compression_mod = @import("compression.zig");
const metadata_mod = @import("metadata.zig");
const codec = @import("stream/codec.zig");

pub const Error = call.Error || codec.Error || error{
    InvalidTextEncoding,
    InvalidWebContentType,
};

/// gRPC-Web payload codec: protobuf is opaque bytes here, matching gRPC.
pub const Format = enum {
    proto,
    json,

    fn suffix(self: Format) []const u8 {
        return switch (self) {
            .proto => "+proto",
            .json => "+json",
        };
    }
};

/// Whether the entity uses the base64 text wire (`application/grpc-web-text`).
pub const ContentType = struct {
    format: Format,
    text: bool,

    /// Canonical response media type. gRPC-Web clients accept any type that
    /// begins with `application/grpc-web`; proto binary keeps the unsuffixed
    /// form Envoy returns for an unsuffixed request.
    pub fn canonical(self: ContentType) []const u8 {
        if (self.text) {
            return switch (self.format) {
                .proto => "application/grpc-web-text",
                .json => "application/grpc-web-text+json",
            };
        }
        return switch (self.format) {
            .proto => "application/grpc-web",
            .json => "application/grpc-web+json",
        };
    }
};

const media = "application/grpc-web";
const text_media = "application/grpc-web-text";

/// Classify a gRPC-Web request content type. Unknown parameters after a
/// semicolon are ignored, matching the HTTP content-type grammar. Plain
/// `application/grpc` is rejected so the gRPC and gRPC-Web paths cannot be
/// confused by shared server dispatch.
pub fn parseContentType(raw: []const u8) Error!ContentType {
    var value = std.mem.trim(u8, raw, " \t");
    if (std.mem.indexOfScalar(u8, value, ';')) |semicolon| {
        value = std.mem.trim(u8, value[0..semicolon], " \t");
    }
    if (value.len < media.len or
        !std.ascii.eqlIgnoreCase(value[0..media.len], media))
    {
        return error.InvalidWebContentType;
    }
    const rest = value[media.len..];
    if (rest.len == 0) {
        return .{ .format = .proto, .text = false };
    }
    if (std.ascii.eqlIgnoreCase(rest, "+proto")) {
        return .{ .format = .proto, .text = false };
    }
    if (std.ascii.eqlIgnoreCase(rest, "+json")) {
        return .{ .format = .json, .text = false };
    }
    // The text forms replace the separator with "-text".
    if (rest.len < "-text".len or
        !std.ascii.eqlIgnoreCase(rest[0.."-text".len], "-text"))
    {
        return error.InvalidWebContentType;
    }
    const text_rest = rest["-text".len..];
    if (text_rest.len == 0) {
        return .{ .format = .proto, .text = true };
    }
    if (std.ascii.eqlIgnoreCase(text_rest, "+proto")) {
        return .{ .format = .proto, .text = true };
    }
    if (std.ascii.eqlIgnoreCase(text_rest, "+json")) {
        return .{ .format = .json, .text = true };
    }
    return error.InvalidWebContentType;
}

pub fn base64DecodeAlloc(
    allocator: std.mem.Allocator,
    input: []const u8,
) Error![]u8 {
    const trimmed = std.mem.trim(u8, input, " \t\r\n");
    var padded: []const u8 = trimmed;
    var pad_storage: ?[]u8 = null;
    defer if (pad_storage) |storage| allocator.free(storage);
    if (trimmed.len % 4 != 0) {
        const padded_len = std.mem.alignForward(usize, trimmed.len, 4);
        const storage = try allocator.alloc(u8, padded_len);
        @memcpy(storage[0..trimmed.len], trimmed);
        @memset(storage[trimmed.len..], '=');
        pad_storage = storage;
        padded = storage;
    }
    const decoder = std.base64.standard.Decoder;
    const decoded_len = decoder.calcSizeForSlice(padded) catch
        return error.InvalidTextEncoding;
    const decoded = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(decoded);
    decoder.decode(decoded, padded) catch
        return error.InvalidTextEncoding;
    return decoded;
}

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
    headers: []const http2.Hpack.HeaderField,
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
pub const TerminalOptions = struct {
    status: wire.Status,
    status_message: ?[]const u8 = null,
    retry_pushback_ms: ?i64 = null,
    trailing_metadata: []const http2.Hpack.HeaderField = &.{},
    trailing_binary_metadata: []const metadata_mod.BinaryMetadata = &.{},
};

/// Build the `Name: Value\r\n` trailer block for a terminal gRPC-Web frame.
/// The returned bytes are allocator-owned and omit the five-byte prefix.
pub fn buildTrailerBlock(
    allocator: std.mem.Allocator,
    options: TerminalOptions,
) Error![]u8 {
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
    connection: *http2.runtime.Connection,
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

    var initial_binary = try metadata_mod.encodeFieldsAlloc(
        allocator,
        options.initial_binary_metadata,
    );
    defer initial_binary.deinit();
    var trailing_binary = try metadata_mod.encodeFieldsAlloc(
        allocator,
        options.trailing_binary_metadata,
    );
    defer trailing_binary.deinit();

    var status_buffer: [2]u8 = undefined;
    const status_value = std.fmt.bufPrint(
        &status_buffer,
        "{d}",
        .{@intFromEnum(options.status)},
    ) catch unreachable;
    const encoded_status_message = if (options.status_message) |message|
        try wire.encodeStatusMessageAlloc(allocator, message)
    else
        try allocator.alloc(u8, 0);
    defer allocator.free(encoded_status_message);

    const trailing_count = std.math.add(
        usize,
        std.math.add(
            usize,
            options.trailing_metadata.len,
            trailing_binary.fields.len,
        ) catch return error.MessageTooLarge,
        @as(usize, 1) +
            @as(usize, @intFromBool(options.status_message != null)) +
            @as(usize, @intFromBool(options.retry_pushback_ms != null)),
    ) catch return error.MessageTooLarge;
    var header_storage: [32]http2.Hpack.HeaderField = undefined;
    const initial_count = std.math.add(
        usize,
        std.math.add(
            usize,
            std.math.add(
                usize,
                3,
                @as(usize, @intFromBool(response_algorithm != .identity)),
            ) catch return error.MessageTooLarge,
            options.initial_metadata.len,
        ) catch return error.MessageTooLarge,
        initial_binary.fields.len +
            @as(usize, @intFromBool(options.trailers_only)) * trailing_count,
    ) catch return error.MessageTooLarge;
    const initial_buffer = if (initial_count <= header_storage.len)
        header_storage[0..initial_count]
    else
        try allocator.alloc(http2.Hpack.HeaderField, initial_count);
    defer if (initial_buffer.ptr != header_storage[0..].ptr) {
        allocator.free(initial_buffer);
    };
    var initial: std.ArrayList(http2.Hpack.HeaderField) =
        .initBuffer(initial_buffer);
    initial.appendAssumeCapacity(.{
        .name = "content-type",
        .value = content_type.canonical(),
    });
    if (response_algorithm != .identity) {
        initial.appendAssumeCapacity(.{
            .name = "grpc-encoding",
            .value = response_algorithm.name(),
        });
    }
    var accept_encoding_buffer: [32]u8 = undefined;
    initial.appendAssumeCapacity(.{
        .name = "grpc-accept-encoding",
        .value = try compression_mod.formatAcceptEncodingInto(
            &accept_encoding_buffer,
            options.accepted_encodings,
        ),
    });
    initial.appendSliceAssumeCapacity(options.initial_metadata);
    initial.appendSliceAssumeCapacity(initial_binary.fields);

    if (options.trailers_only) {
        initial.appendAssumeCapacity(.{
            .name = "grpc-status",
            .value = status_value,
        });
        if (options.status_message != null) {
            initial.appendAssumeCapacity(.{
                .name = "grpc-message",
                .value = encoded_status_message,
            });
        }
        if (options.retry_pushback_ms) |milliseconds| {
            var pushback_buffer: [21]u8 = undefined;
            initial.appendAssumeCapacity(.{
                .name = "grpc-retry-pushback-ms",
                .value = std.fmt.bufPrint(
                    &pushback_buffer,
                    "{d}",
                    .{milliseconds},
                ) catch unreachable,
            });
        }
        initial.appendSliceAssumeCapacity(options.trailing_metadata);
        initial.appendSliceAssumeCapacity(trailing_binary.fields);
        return connection.writeResponse(stream_id, .{
            .headers = initial.items,
        });
    }

    const framed_body = try buildResponseBody(allocator, options);
    defer allocator.free(framed_body);
    const entity = if (content_type.text)
        try base64EncodeAlloc(allocator, framed_body)
    else
        framed_body;
    defer if (content_type.text) allocator.free(entity);
    return connection.writeResponse(stream_id, .{
        .headers = initial.items,
        .body = entity,
    });
}

test "gRPC-Web classifies the four binary and text media types" {
    const cases = [_]struct {
        raw: []const u8,
        format: Format,
        text: bool,
    }{
        .{ .raw = "application/grpc-web", .format = .proto, .text = false },
        .{ .raw = "application/grpc-web+proto", .format = .proto, .text = false },
        .{ .raw = "application/grpc-web+json", .format = .json, .text = false },
        .{ .raw = "application/grpc-web-text", .format = .proto, .text = true },
        .{ .raw = "application/grpc-web-text+proto", .format = .proto, .text = true },
        .{ .raw = "application/grpc-web-text+json", .format = .json, .text = true },
    };
    for (cases) |case| {
        const parsed = try parseContentType(case.raw);
        try std.testing.expectEqual(case.format, parsed.format);
        try std.testing.expectEqual(case.text, parsed.text);
    }
    // Parameters and surrounding OWS follow the HTTP content-type grammar.
    const parametrized = try parseContentType("application/grpc-web; charset=utf-8");
    try std.testing.expectEqual(Format.proto, parametrized.format);
    try std.testing.expect(!parametrized.text);

    try std.testing.expectError(
        error.InvalidWebContentType,
        parseContentType("application/grpc"),
    );
    try std.testing.expectError(
        error.InvalidWebContentType,
        parseContentType("application/json"),
    );
    try std.testing.expectError(
        error.InvalidWebContentType,
        parseContentType("application/grpc-web-x"),
    );
}

test "gRPC-Web canonical response types round trip" {
    const binary = try parseContentType("application/grpc-web+proto");
    try std.testing.expectEqualStrings(
        "application/grpc-web",
        binary.canonical(),
    );
    const json = try parseContentType("application/grpc-web+json");
    try std.testing.expectEqualStrings(
        "application/grpc-web+json",
        json.canonical(),
    );
    const text = try parseContentType("application/grpc-web-text");
    try std.testing.expectEqualStrings(
        "application/grpc-web-text",
        text.canonical(),
    );
    const text_json = try parseContentType("application/grpc-web-text+json");
    try std.testing.expectEqualStrings(
        "application/grpc-web-text+json",
        text_json.canonical(),
    );
}

test "gRPC-Web binary request decodes one framed message" {
    const allocator = std.testing.allocator;
    var entity: [10]u8 = undefined;
    entity[0] = 0;
    std.mem.writeInt(u32, entity[1..5], 5, .big);
    @memcpy(entity[5..10], "hello");
    const headers = [_]http2.Hpack.HeaderField{};
    var request = try parseUnaryRequest(
        allocator,
        "POST",
        "/demo.Echo/Unary",
        &headers,
        &entity,
        .{ .format = .proto, .text = false },
        1024,
    );
    defer request.deinit();
    try std.testing.expectEqualStrings("hello", request.message.payload);
    try std.testing.expect(request.owned_message == null);
}

test "gRPC-Web text request base64 decodes and owns its message" {
    const allocator = std.testing.allocator;
    var framed: [10]u8 = undefined;
    framed[0] = 0;
    std.mem.writeInt(u32, framed[1..5], 5, .big);
    @memcpy(framed[5..10], "hello");
    const encoded = try base64EncodeAlloc(allocator, &framed);
    defer allocator.free(encoded);

    const headers = [_]http2.Hpack.HeaderField{};
    var request = try parseUnaryRequest(
        allocator,
        "POST",
        "/demo.Echo/Unary",
        &headers,
        encoded,
        .{ .format = .proto, .text = true },
        1024,
    );
    defer request.deinit();
    try std.testing.expectEqualStrings("hello", request.message.payload);
    try std.testing.expect(request.owned_message != null);

    try std.testing.expectError(
        error.InvalidTextEncoding,
        parseUnaryRequest(
            allocator,
            "POST",
            "/demo.Echo/Unary",
            &headers,
            "%%%%",
            .{ .format = .proto, .text = true },
            1024,
        ),
    );
}

test "gRPC-Web rejects missing or duplicated request messages" {
    const allocator = std.testing.allocator;
    const headers = [_]http2.Hpack.HeaderField{};
    try std.testing.expectError(
        error.InvalidMessageCount,
        parseUnaryRequest(
            allocator,
            "POST",
            "/demo.Echo/Unary",
            &headers,
            "",
            .{ .format = .proto, .text = false },
            1024,
        ),
    );
    var two: [20]u8 = undefined;
    for (0..2) |index| {
        two[index * 10] = 0;
        std.mem.writeInt(u32, two[index * 10 + 1 ..][0..4], 5, .big);
        @memcpy(two[index * 10 + 5 ..][0..5], "hello");
    }
    try std.testing.expectError(
        error.InvalidMessageCount,
        parseUnaryRequest(
            allocator,
            "POST",
            "/demo.Echo/Unary",
            &headers,
            &two,
            .{ .format = .proto, .text = false },
            1024,
        ),
    );
    try std.testing.expectError(
        error.InvalidGrpcRequest,
        parseUnaryRequest(
            allocator,
            "GET",
            "/demo.Echo/Unary",
            &headers,
            two[0..10],
            .{ .format = .proto, .text = false },
            1024,
        ),
    );
}

test "gRPC-Web response body ends with one trailers frame" {
    const allocator = std.testing.allocator;
    const body = try buildResponseBody(allocator, .{
        .status = .ok,
        .message = "pong",
    });
    defer allocator.free(body);

    // One data frame for the four-byte message.
    try std.testing.expect(body[0] == 0);
    try std.testing.expectEqual(
        @as(u32, 4),
        std.mem.readInt(u32, body[1..5], .big),
    );
    try std.testing.expectEqualStrings("pong", body[5..9]);
    // The terminal frame carries the 0x80 marker and status trailer.
    const trailer_offset = 9;
    try std.testing.expectEqual(@as(u8, 0x80), body[trailer_offset]);
    const trailer_len = std.mem.readInt(
        u32,
        body[trailer_offset + 1 ..][0..4],
        .big,
    );
    try std.testing.expectEqual(
        body.len - trailer_offset - 5,
        trailer_len,
    );
    const trailer_block = body[trailer_offset + 5 ..];
    try std.testing.expect(trailer_block.len > 0);
    try std.testing.expect(std.mem.startsWith(u8, trailer_block, "grpc-status:0\r\n"));
    try std.testing.expect(trailer_block[trailer_block.len - 2 ..][0] == '\r' and
        trailer_block[trailer_block.len - 1] == '\n');
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
    initial_metadata: []const http2.Hpack.HeaderField = &.{},
    initial_binary_metadata: []const metadata_mod.BinaryMetadata = &.{},
    max_message_size: usize = 16 * 1024 * 1024,
};

/// Allocation-free streaming standard-base64 filter for `grpc-web-text`.
/// Three input bytes become four output characters; up to two final bytes
/// stay buffered until `flushPadding` writes the padded terminal group.
const Base64Sink = struct {
    inner: ?*http2.runtime.ResponseWriter = null,
    pending: [3]u8 = undefined,
    pending_len: u2 = 0,

    const encoder = std.base64.standard.Encoder;
    /// Input chunk size (a multiple of three); 768 input bytes become 1024.
    const chunk_input = 768;
    const chunk_output: usize = chunk_input / 3 * 4;

    pub fn write(self: *Base64Sink, bytes: []const u8) Error!void {
        const inner = self.inner orelse return error.InvalidStreamState;
        var input = bytes;
        if (self.pending_len != 0) {
            const take = @min(
                @as(usize, 3) - self.pending_len,
                input.len,
            );
            @memcpy(
                self.pending[self.pending_len..][0..take],
                input[0..take],
            );
            self.pending_len += @intCast(take);
            input = input[take..];
            if (self.pending_len == 3) {
                var group: [4]u8 = undefined;
                _ = encoder.encode(&group, &self.pending);
                try inner.write(&group);
                self.pending_len = 0;
            }
        }
        var encoded: [chunk_output]u8 = undefined;
        while (input.len >= chunk_input) {
            _ = encoder.encode(
                &encoded,
                input[0..chunk_input],
            );
            try inner.write(&encoded);
            input = input[chunk_input..];
        }
        // Fewer than one chunk remains, but it can still contain complete
        // triplets; only the final 1-2 bytes stay buffered for padding.
        const complete = (input.len / 3) * 3;
        if (complete != 0) {
            const out_len = encoder.calcSize(complete);
            _ = encoder.encode(encoded[0..out_len], input[0..complete]);
            try inner.write(encoded[0..out_len]);
            input = input[complete..];
        }
        if (input.len != 0) {
            std.debug.assert(input.len < 3);
            @memcpy(self.pending[0..input.len], input);
            self.pending_len = @intCast(input.len);
        }
    }

    fn flushPadding(self: *Base64Sink) Error!void {
        const inner = self.inner orelse return error.InvalidStreamState;
        if (self.pending_len == 0) return;
        var group: [4]u8 = undefined;
        _ = encoder.encode(
            &group,
            self.pending[0..self.pending_len],
        );
        try inner.write(&group);
        self.pending_len = 0;
    }
};

/// Streaming gRPC-Web response: zero or more data frames followed by one
/// `0x80` trailers frame, all carried in HTTP/2 DATA with END_STREAM.
pub const ServerStreamWriter = struct {
    allocator: std.mem.Allocator,
    transport: http2.runtime.ResponseWriter,
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
            return self.encoder.writeMessageWithOptions(
                &self.base64_sink,
                payload,
                options,
            );
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
        trailing_metadata: []const http2.Hpack.HeaderField,
        trailing_binary_metadata: []const metadata_mod.BinaryMetadata,
    ) Error!void {
        if (self.finished) return error.InvalidStreamState;
        const block = try buildTrailerBlock(self.allocator, .{
            .status = status,
            .status_message = status_message,
            .trailing_metadata = trailing_metadata,
            .trailing_binary_metadata = trailing_binary_metadata,
        });
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
    connection: *http2.runtime.Connection,
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

    var initial_binary = try metadata_mod.encodeFieldsAlloc(
        allocator,
        options.initial_binary_metadata,
    );
    defer initial_binary.deinit();

    const initial_count = 3 +
        @as(usize, @intFromBool(response_algorithm != .identity)) +
        options.initial_metadata.len +
        initial_binary.fields.len;
    var header_storage: [32]http2.Hpack.HeaderField = undefined;
    const initial_buffer = if (initial_count <= header_storage.len)
        header_storage[0..initial_count]
    else
        try allocator.alloc(http2.Hpack.HeaderField, initial_count);
    defer if (initial_buffer.ptr != header_storage[0..].ptr) {
        allocator.free(initial_buffer);
    };
    var initial: std.ArrayList(http2.Hpack.HeaderField) =
        .initBuffer(initial_buffer);
    initial.appendAssumeCapacity(.{
        .name = "content-type",
        .value = content_type.canonical(),
    });
    if (response_algorithm != .identity) {
        initial.appendAssumeCapacity(.{
            .name = "grpc-encoding",
            .value = response_algorithm.name(),
        });
    }
    var accept_encoding_buffer: [32]u8 = undefined;
    initial.appendAssumeCapacity(.{
        .name = "grpc-accept-encoding",
        .value = try compression_mod.formatAcceptEncodingInto(
            &accept_encoding_buffer,
            options.accepted_encodings,
        ),
    });
    initial.appendSliceAssumeCapacity(options.initial_metadata);
    initial.appendSliceAssumeCapacity(initial_binary.fields);

    const transport = try connection.startResponse(stream_id, .{
        .status = 200,
        .headers = initial.items,
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
