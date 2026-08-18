//! gRPC unary call semantics over the netz HTTP/2 runtime.

const std = @import("std");
const http2 = @import("../http2/mod.zig");
const compression_mod = @import("compression.zig");
const metadata_mod = @import("metadata.zig");
const wire = @import("wire.zig");

pub const Error = wire.Error || metadata_mod.Error ||
    compression_mod.Error ||
    http2.runtime.Error || error{
    CompressionNotNegotiated,
    InvalidContentType,
    InvalidGrpcRequest,
    InvalidMetadata,
    InvalidMessageCount,
};

const Status = wire.Status;
const Message = wire.Message;
const MessageIterator = wire.MessageIterator;
const Timeout = wire.Timeout;
const Algorithm = compression_mod.Algorithm;
const AlgorithmSet = compression_mod.AlgorithmSet;
const writeMessage = wire.writeMessage;
const encodeStatusMessageAlloc = wire.encodeStatusMessageAlloc;
const decodeStatusMessageAlloc = wire.decodeStatusMessageAlloc;
const isContentType = wire.isContentType;

pub const UnaryRequest = struct {
    allocator: std.mem.Allocator,
    stream_id: u31,
    path: []const u8,
    service: []const u8,
    method: []const u8,
    /// The application payload after any per-message decompression.
    message: Message,
    was_compressed: bool,
    timeout: ?Timeout,
    encoding: ?[]const u8,
    accepted_encodings: AlgorithmSet,
    headers: []const http2.Hpack.HeaderField,
    owned_message: ?[]u8,

    pub fn deinit(self: *UnaryRequest) void {
        if (self.owned_message) |owned| self.allocator.free(owned);
        self.* = undefined;
    }
};

/// Validated gRPC request metadata shared by unary and streaming calls.
///
/// Every slice borrows the HTTP/2 request headers/head that was supplied to
/// `parseRequestMetadata`.
pub const RequestMetadata = struct {
    path: []const u8,
    service: []const u8,
    method: []const u8,
    timeout: ?Timeout,
    encoding: ?[]const u8,
    accepted_encodings: AlgorithmSet,
};

pub fn parseRequestMetadata(
    method: []const u8,
    path_value: []const u8,
    headers: []const http2.Hpack.HeaderField,
) Error!RequestMetadata {
    if (!std.mem.eql(u8, method, "POST")) {
        return error.InvalidGrpcRequest;
    }
    const content_type = findHeader(
        headers,
        "content-type",
    ) orelse return error.InvalidContentType;
    if (!isContentType(content_type)) return error.InvalidContentType;
    const te = findHeader(headers, "te") orelse
        return error.InvalidGrpcRequest;
    if (!std.ascii.eqlIgnoreCase(
        std.mem.trim(u8, te, " \t"),
        "trailers",
    )) {
        return error.InvalidGrpcRequest;
    }
    const path = try splitMethodPath(path_value);
    return .{
        .path = path_value,
        .service = path.service,
        .method = path.method,
        .timeout = if (findHeader(headers, "grpc-timeout")) |raw|
            try Timeout.parse(raw)
        else
            null,
        .encoding = findHeader(headers, "grpc-encoding"),
        .accepted_encodings = compression_mod.parseAcceptEncoding(
            findHeader(headers, "grpc-accept-encoding"),
        ),
    };
}

pub fn parseUnaryRequest(
    allocator: std.mem.Allocator,
    request: *const http2.runtime.OwnedRequest,
    max_message_size: usize,
) Error!UnaryRequest {
    const metadata = try parseRequestMetadata(
        request.method,
        request.path,
        request.headers,
    );
    var iterator = MessageIterator.init(
        request.body,
        max_message_size,
    );
    const message = (try iterator.next()) orelse
        return error.InvalidMessageCount;
    if (try iterator.next() != null) {
        return error.InvalidMessageCount;
    }
    try validateMessageEncoding(message, metadata.encoding);
    var decoded = try decodeReceivedMessage(
        allocator,
        message,
        metadata.encoding,
        AlgorithmSet.supported,
        max_message_size,
    );
    errdefer decoded.deinit(allocator);
    return .{
        .allocator = allocator,
        .stream_id = request.stream_id,
        .path = metadata.path,
        .service = metadata.service,
        .method = metadata.method,
        .message = .{
            .compressed = false,
            .payload = decoded.bytes,
        },
        .was_compressed = message.compressed,
        .timeout = metadata.timeout,
        .encoding = metadata.encoding,
        .accepted_encodings = metadata.accepted_encodings,
        .headers = request.headers,
        .owned_message = decoded.owned,
    };
}

pub const UnaryCallOptions = struct {
    path: []const u8,
    authority: ?[]const u8 = null,
    scheme: ?[]const u8 = null,
    message: []const u8,
    /// Requested per-message encoding. Compression is skipped when it cannot
    /// make this particular message smaller.
    compression: Algorithm = .identity,
    compression_level: u4 = 6,
    /// Decoders advertised to the server for response messages.
    accepted_encodings: AlgorithmSet = .supported,
    timeout: ?Timeout = null,
    /// ASCII application metadata already suitable for HTTP/2.
    metadata: []const http2.Hpack.HeaderField = &.{},
    /// Raw application bytes encoded as unpadded Base64 `-bin` fields.
    binary_metadata: []const metadata_mod.BinaryMetadata = &.{},
    max_message_size: usize = 16 * 1024 * 1024,
};

pub const UnaryResponse = struct {
    allocator: std.mem.Allocator,
    transport: http2.runtime.OwnedResponse,
    status: Status,
    status_message: []u8,
    message: ?Message,
    was_compressed: bool,
    encoding: ?[]const u8,
    owned_message: ?[]u8,

    pub fn deinit(self: *UnaryResponse) void {
        if (self.owned_message) |owned| self.allocator.free(owned);
        self.allocator.free(self.status_message);
        self.transport.deinit(self.allocator);
        self.* = undefined;
    }
};

pub fn unaryCall(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    options: UnaryCallOptions,
) Error!UnaryResponse {
    if (options.message.len > options.max_message_size) {
        return error.GrpcMessageTooLarge;
    }
    var encoded = try compression_mod.compressAlloc(
        allocator,
        options.compression,
        options.message,
        options.compression_level,
    );
    defer encoded.deinit(allocator);
    _ = try splitMethodPath(options.path);
    try validateCustomMetadata(options.metadata);
    try validateCustomBinaryMetadata(options.binary_metadata);
    var binary_metadata = try metadata_mod.encodeFieldsAlloc(
        allocator,
        options.binary_metadata,
    );
    defer binary_metadata.deinit();

    var framed: std.ArrayList(u8) = .empty;
    defer framed.deinit(allocator);
    try writeMessage(
        &framed,
        allocator,
        encoded.bytes,
        encoded.compressed,
    );

    var header_storage: [16]http2.Hpack.HeaderField = undefined;
    const header_count = std.math.add(
        usize,
        options.metadata.len,
        std.math.add(
            usize,
            binary_metadata.fields.len,
            5,
        ) catch return error.MessageTooLarge,
    ) catch return error.MessageTooLarge;
    const buffer = if (header_count <= header_storage.len)
        header_storage[0..header_count]
    else
        try allocator.alloc(http2.Hpack.HeaderField, header_count);
    defer if (buffer.ptr != header_storage[0..].ptr) {
        allocator.free(buffer);
    };
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
        .value = try compression_mod.formatAcceptEncodingInto(
            &accept_encoding_buffer,
            options.accepted_encodings,
        ),
    });
    headers.appendSliceAssumeCapacity(options.metadata);
    headers.appendSliceAssumeCapacity(binary_metadata.fields);

    const response = try connection.request(.{
        .method = "POST",
        .path = options.path,
        .scheme = options.scheme,
        .authority = options.authority,
        .headers = headers.items,
        .body = framed.items,
    });
    return parseUnaryResponse(
        allocator,
        response,
        options.max_message_size,
        options.accepted_encodings,
    );
}

pub const UnaryResponseOptions = struct {
    status: Status = .ok,
    message: ?[]const u8 = null,
    /// Requested response encoding. The message remains uncompressed unless
    /// the request advertised support for this algorithm.
    compression: Algorithm = .identity,
    compression_level: u4 = 6,
    request_accepted_encodings: AlgorithmSet = .{},
    /// Decoders advertised by this server for future request messages.
    accepted_encodings: AlgorithmSet = .supported,
    status_message: ?[]const u8 = null,
    initial_metadata: []const http2.Hpack.HeaderField = &.{},
    trailing_metadata: []const http2.Hpack.HeaderField = &.{},
    /// Raw initial metadata encoded into HTTP/2 response headers.
    initial_binary_metadata: []const metadata_mod.BinaryMetadata = &.{},
    /// Raw trailing metadata encoded into gRPC response trailers.
    trailing_binary_metadata: []const metadata_mod.BinaryMetadata = &.{},
    trailers_only: bool = false,
};

pub fn writeUnaryResponse(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    stream_id: u31,
    options: UnaryResponseOptions,
) Error!void {
    try validateCustomMetadata(options.initial_metadata);
    try validateCustomMetadata(options.trailing_metadata);
    try validateCustomBinaryMetadata(
        options.initial_binary_metadata,
    );
    try validateCustomBinaryMetadata(
        options.trailing_binary_metadata,
    );
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
    if (options.status == .ok and options.message == null) {
        return error.InvalidMessageCount;
    }
    if (options.trailers_only and options.message != null) {
        return error.InvalidMessageCount;
    }

    var framed: std.ArrayList(u8) = .empty;
    defer framed.deinit(allocator);
    var encoded_message: ?compression_mod.EncodedPayload = null;
    defer if (encoded_message) |*encoded| encoded.deinit(allocator);
    const response_algorithm: Algorithm =
        if (options.message != null and
        options.request_accepted_encodings.contains(
            options.compression,
        ))
            options.compression
        else
            .identity;
    if (options.message) |message| {
        // A server must not use a response encoding absent from the client's
        // last grpc-accept-encoding advertisement. Falling back to identity
        // is required even when the application requested compression.
        encoded_message = try compression_mod.compressAlloc(
            allocator,
            response_algorithm,
            message,
            options.compression_level,
        );
        try writeMessage(
            &framed,
            allocator,
            encoded_message.?.bytes,
            encoded_message.?.compressed,
        );
    }
    var status_buffer: [2]u8 = undefined;
    const status_value = std.fmt.bufPrint(
        &status_buffer,
        "{d}",
        .{@intFromEnum(options.status)},
    ) catch unreachable;
    const encoded_status_message = if (options.status_message) |message|
        try encodeStatusMessageAlloc(allocator, message)
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
            @intFromBool(options.status_message != null),
    ) catch return error.MessageTooLarge;
    var initial_storage: [16]http2.Hpack.HeaderField = undefined;
    const initial_base = std.math.add(
        usize,
        2,
        @intFromBool(response_algorithm != .identity),
    ) catch return error.MessageTooLarge;
    const initial_extra = std.math.add(
        usize,
        initial_base,
        if (options.trailers_only) trailing_count else 0,
    ) catch return error.MessageTooLarge;
    const initial_count = std.math.add(
        usize,
        std.math.add(
            usize,
            options.initial_metadata.len,
            initial_binary.fields.len,
        ) catch return error.MessageTooLarge,
        initial_extra,
    ) catch return error.MessageTooLarge;
    const initial_buffer = if (initial_count <= initial_storage.len)
        initial_storage[0..initial_count]
    else
        try allocator.alloc(http2.Hpack.HeaderField, initial_count);
    defer if (initial_buffer.ptr != initial_storage[0..].ptr) {
        allocator.free(initial_buffer);
    };
    var initial: std.ArrayList(http2.Hpack.HeaderField) =
        .initBuffer(initial_buffer);
    initial.appendAssumeCapacity(.{
        .name = "content-type",
        .value = "application/grpc+proto",
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

    var trailing_storage: [16]http2.Hpack.HeaderField = undefined;
    const trailing_buffer = if (trailing_count <= trailing_storage.len)
        trailing_storage[0..trailing_count]
    else
        try allocator.alloc(http2.Hpack.HeaderField, trailing_count);
    defer if (trailing_buffer.ptr != trailing_storage[0..].ptr) {
        allocator.free(trailing_buffer);
    };
    var trailing: std.ArrayList(http2.Hpack.HeaderField) =
        .initBuffer(trailing_buffer);
    trailing.appendAssumeCapacity(.{
        .name = "grpc-status",
        .value = status_value,
    });
    if (options.status_message != null) {
        trailing.appendAssumeCapacity(.{
            .name = "grpc-message",
            .value = encoded_status_message,
        });
    }
    trailing.appendSliceAssumeCapacity(options.trailing_metadata);
    trailing.appendSliceAssumeCapacity(trailing_binary.fields);

    if (options.trailers_only) {
        initial.appendSliceAssumeCapacity(trailing.items);
        return connection.writeResponse(stream_id, .{
            .headers = initial.items,
        });
    }
    return connection.writeResponse(stream_id, .{
        .headers = initial.items,
        .body = framed.items,
        .trailers = trailing.items,
    });
}

fn parseUnaryResponse(
    allocator: std.mem.Allocator,
    transport: http2.runtime.OwnedResponse,
    max_message_size: usize,
    accepted_encodings: AlgorithmSet,
) Error!UnaryResponse {
    var owned = transport;
    errdefer owned.deinit(allocator);
    const status_raw = findHeader(
        owned.trailers,
        "grpc-status",
    ) orelse findHeader(owned.headers, "grpc-status");
    const status = if (status_raw) |raw|
        Status.parse(raw) catch .unknown
    else
        statusFromHttp(owned.status);
    const status_message_raw = findHeader(
        owned.trailers,
        "grpc-message",
    ) orelse findHeader(owned.headers, "grpc-message");
    const status_message = if (status_message_raw) |raw|
        try decodeStatusMessageAlloc(allocator, raw)
    else if (status_raw == null)
        try std.fmt.allocPrint(
            allocator,
            "HTTP status {d} without grpc-status",
            .{owned.status},
        )
    else
        try allocator.alloc(u8, 0);
    errdefer allocator.free(status_message);

    const content_type = findHeader(
        owned.headers,
        "content-type",
    );
    const grpc_content_type = content_type != null and
        isContentType(content_type.?);
    if ((owned.status == 200 or status_raw != null) and
        !grpc_content_type)
    {
        return error.InvalidContentType;
    }

    const encoding = findHeader(owned.headers, "grpc-encoding");
    var message: ?Message = null;
    var owned_message: ?[]u8 = null;
    errdefer if (owned_message) |payload| allocator.free(payload);
    var was_compressed = false;
    const parse_grpc_body =
        grpc_content_type and
        (status_raw != null or owned.status == 200);
    if (parse_grpc_body and owned.body.len != 0) {
        var iterator = MessageIterator.init(
            owned.body,
            max_message_size,
        );
        message = (try iterator.next()) orelse unreachable;
        if (try iterator.next() != null) {
            return error.InvalidMessageCount;
        }
        try validateMessageEncoding(message.?, encoding);
        var decoded = try decodeReceivedMessage(
            allocator,
            message.?,
            encoding,
            accepted_encodings,
            max_message_size,
        );
        errdefer decoded.deinit(allocator);
        was_compressed = message.?.compressed;
        owned_message = decoded.owned;
        // From this point UnaryResponse owns the decoded allocation. Clear
        // the temporary guard so a later status-validation error cannot free
        // the same payload through two errdefers.
        decoded.owned = null;
        message = .{
            .compressed = false,
            .payload = decoded.bytes,
        };
    }
    if (status == .ok and message == null) {
        return error.InvalidMessageCount;
    }
    return .{
        .allocator = allocator,
        .transport = owned,
        .status = status,
        .status_message = status_message,
        .message = message,
        .was_compressed = was_compressed,
        .encoding = encoding,
        .owned_message = owned_message,
    };
}

fn decodeReceivedMessage(
    allocator: std.mem.Allocator,
    message: Message,
    encoding: ?[]const u8,
    accepted_encodings: AlgorithmSet,
    max_message_size: usize,
) Error!compression_mod.DecodedPayload {
    if (!message.compressed) {
        return .{ .bytes = message.payload };
    }
    const raw_encoding = encoding orelse
        return error.CompressionNotNegotiated;
    const algorithm = Algorithm.parse(raw_encoding) orelse
        return error.UnsupportedCompression;
    if (algorithm == .identity) return error.CompressionNotNegotiated;
    if (!accepted_encodings.contains(algorithm)) {
        return error.UnsupportedCompression;
    }
    return compression_mod.decompressAlloc(
        allocator,
        algorithm,
        message.payload,
        max_message_size,
    );
}

fn splitMethodPath(
    path: []const u8,
) Error!struct {
    service: []const u8,
    method: []const u8,
} {
    if (path.len < 4 or path[0] != '/') {
        return error.InvalidGrpcRequest;
    }
    const separator = std.mem.indexOfScalar(
        u8,
        path[1..],
        '/',
    ) orelse return error.InvalidGrpcRequest;
    const absolute = separator + 1;
    if (absolute == 1 or absolute + 1 >= path.len or
        std.mem.indexOfScalar(u8, path[absolute + 1 ..], '/') != null)
    {
        return error.InvalidGrpcRequest;
    }
    return .{
        .service = path[1..absolute],
        .method = path[absolute + 1 ..],
    };
}

fn findHeader(
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

pub fn validateMessageEncoding(
    message: Message,
    encoding: ?[]const u8,
) Error!void {
    const value = encoding orelse {
        if (message.compressed) return error.CompressionNotNegotiated;
        return;
    };
    const algorithm = Algorithm.parse(value) orelse
        return error.UnsupportedCompression;
    if (message.compressed and algorithm == .identity) {
        return error.CompressionNotNegotiated;
    }
}

pub fn headerValue(
    headers: []const http2.Hpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    return findHeader(headers, name);
}

pub fn statusFromHttp(status: u16) Status {
    return switch (status) {
        400 => .internal,
        401 => .unauthenticated,
        403 => .permission_denied,
        404 => .unimplemented,
        429, 502, 503, 504 => .unavailable,
        else => .unknown,
    };
}

pub fn validateCustomMetadata(
    metadata: []const http2.Hpack.HeaderField,
) Error!void {
    for (metadata) |field| {
        if (field.name.len == 0 or field.name[0] == ':' or
            metadata_mod.isBinaryName(field.name) or
            std.ascii.eqlIgnoreCase(field.name, "content-type") or
            std.ascii.eqlIgnoreCase(field.name, "te") or
            std.ascii.startsWithIgnoreCase(field.name, "grpc-"))
        {
            return error.InvalidMetadata;
        }
    }
}

pub fn validateCustomBinaryMetadata(
    metadata: []const metadata_mod.BinaryMetadata,
) Error!void {
    for (metadata) |field| {
        try metadata_mod.validateBinaryName(field.name);
        if (std.ascii.startsWithIgnoreCase(field.name, "grpc-")) {
            return error.InvalidMetadata;
        }
    }
}
