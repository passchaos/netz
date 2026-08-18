//! gRPC unary call semantics over the netz HTTP/2 runtime.

const std = @import("std");
const http2 = @import("../http2/mod.zig");
const wire = @import("wire.zig");

pub const Error = wire.Error || http2.runtime.Error || error{
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
const writeMessage = wire.writeMessage;
const encodeStatusMessageAlloc = wire.encodeStatusMessageAlloc;
const decodeStatusMessageAlloc = wire.decodeStatusMessageAlloc;
const isContentType = wire.isContentType;

pub const UnaryRequest = struct {
    stream_id: u31,
    path: []const u8,
    service: []const u8,
    method: []const u8,
    message: Message,
    timeout: ?Timeout,
    encoding: ?[]const u8,
    headers: []const http2.Hpack.HeaderField,
};

pub fn parseUnaryRequest(
    request: *const http2.runtime.OwnedRequest,
    max_message_size: usize,
) Error!UnaryRequest {
    if (!std.mem.eql(u8, request.method, "POST")) {
        return error.InvalidGrpcRequest;
    }
    const content_type = findHeader(
        request.headers,
        "content-type",
    ) orelse return error.InvalidContentType;
    if (!isContentType(content_type)) return error.InvalidContentType;
    const te = findHeader(request.headers, "te") orelse
        return error.InvalidGrpcRequest;
    if (!std.ascii.eqlIgnoreCase(
        std.mem.trim(u8, te, " \t"),
        "trailers",
    )) {
        return error.InvalidGrpcRequest;
    }
    const path = try splitMethodPath(request.path);
    const timeout = if (findHeader(request.headers, "grpc-timeout")) |raw|
        try Timeout.parse(raw)
    else
        null;
    const encoding = findHeader(request.headers, "grpc-encoding");
    var iterator = MessageIterator.init(
        request.body,
        max_message_size,
    );
    const message = (try iterator.next()) orelse
        return error.InvalidMessageCount;
    if (try iterator.next() != null) {
        return error.InvalidMessageCount;
    }
    try validateMessageEncoding(message, encoding);
    return .{
        .stream_id = request.stream_id,
        .path = request.path,
        .service = path.service,
        .method = path.method,
        .message = message,
        .timeout = timeout,
        .encoding = encoding,
        .headers = request.headers,
    };
}

pub const UnaryCallOptions = struct {
    path: []const u8,
    authority: ?[]const u8 = null,
    scheme: ?[]const u8 = null,
    message: []const u8,
    compressed: bool = false,
    encoding: ?[]const u8 = null,
    timeout: ?Timeout = null,
    metadata: []const http2.Hpack.HeaderField = &.{},
    max_message_size: usize = 16 * 1024 * 1024,
};

pub const UnaryResponse = struct {
    allocator: std.mem.Allocator,
    transport: http2.runtime.OwnedResponse,
    status: Status,
    status_message: []u8,
    message: ?Message,
    encoding: ?[]const u8,

    pub fn deinit(self: *UnaryResponse) void {
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
    try validateMessageEncoding(
        .{
            .compressed = options.compressed,
            .payload = options.message,
        },
        options.encoding,
    );
    _ = try splitMethodPath(options.path);
    try validateCustomMetadata(options.metadata);

    var framed: std.ArrayList(u8) = .empty;
    defer framed.deinit(allocator);
    try writeMessage(
        &framed,
        allocator,
        options.message,
        options.compressed,
    );

    var header_storage: [16]http2.Hpack.HeaderField = undefined;
    const header_count = std.math.add(
        usize,
        options.metadata.len,
        4,
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
    if (options.encoding) |encoding| {
        headers.appendAssumeCapacity(.{
            .name = "grpc-encoding",
            .value = encoding,
        });
    }
    headers.appendSliceAssumeCapacity(options.metadata);

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
    );
}

pub const UnaryResponseOptions = struct {
    status: Status = .ok,
    message: ?[]const u8 = null,
    compressed: bool = false,
    encoding: ?[]const u8 = null,
    status_message: ?[]const u8 = null,
    initial_metadata: []const http2.Hpack.HeaderField = &.{},
    trailing_metadata: []const http2.Hpack.HeaderField = &.{},
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
    if (options.status == .ok and options.message == null) {
        return error.InvalidMessageCount;
    }
    if (options.trailers_only and options.message != null) {
        return error.InvalidMessageCount;
    }
    if (options.message) |message| {
        try validateMessageEncoding(
            .{
                .compressed = options.compressed,
                .payload = message,
            },
            options.encoding,
        );
    }

    var framed: std.ArrayList(u8) = .empty;
    defer framed.deinit(allocator);
    if (options.message) |message| {
        try writeMessage(
            &framed,
            allocator,
            message,
            options.compressed,
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
        options.trailing_metadata.len,
        @as(usize, 1) +
            @intFromBool(options.status_message != null),
    ) catch return error.MessageTooLarge;
    var initial_storage: [16]http2.Hpack.HeaderField = undefined;
    const initial_base = std.math.add(
        usize,
        1,
        @intFromBool(options.encoding != null),
    ) catch return error.MessageTooLarge;
    const initial_extra = std.math.add(
        usize,
        initial_base,
        if (options.trailers_only) trailing_count else 0,
    ) catch return error.MessageTooLarge;
    const initial_count = std.math.add(
        usize,
        options.initial_metadata.len,
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
    if (options.encoding) |encoding| {
        initial.appendAssumeCapacity(.{
            .name = "grpc-encoding",
            .value = encoding,
        });
    }
    initial.appendSliceAssumeCapacity(options.initial_metadata);

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
        .encoding = encoding,
    };
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
    if (!message.compressed) return;
    const value = encoding orelse
        return error.CompressionNotNegotiated;
    if (std.ascii.eqlIgnoreCase(value, "identity")) {
        return error.CompressionNotNegotiated;
    }
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
            std.ascii.eqlIgnoreCase(field.name, "content-type") or
            std.ascii.eqlIgnoreCase(field.name, "te") or
            std.ascii.startsWithIgnoreCase(field.name, "grpc-"))
        {
            return error.InvalidMetadata;
        }
    }
}
