const std = @import("std");
const http = @import("../../../http1/mod.zig");
const h2 = @import("../../../http2/mod.zig");
const web = @import("../../web.zig");
const call = @import("../../call.zig");
const codec = @import("../../stream/codec.zig");
const text = @import("../text.zig");
const response_headers = @import("../response_headers.zig");
const adapter = @import("mod.zig");
const server_request = @import("../server_request.zig");

pub fn writeUnary(request: *adapter.Request, options: call.UnaryResponseOptions) adapter.Error!void {
    if (request.responded) return error.InvalidStreamState;
    try call.validateCustomMetadata(options.initial_metadata);
    try call.validateCustomMetadata(options.trailing_metadata);
    try call.validateCustomBinaryMetadata(options.initial_binary_metadata);
    try call.validateCustomBinaryMetadata(options.trailing_binary_metadata);
    try validateCorsMetadata(request, options.initial_metadata);
    if (options.trailers_only) try validateCorsMetadata(request, options.trailing_metadata);
    if (options.status == .ok and options.message == null or options.trailers_only and options.message != null) return error.InvalidMessageCount;
    if (options.message) |message| if (message.len > request.max_message_size) return error.GrpcMessageTooLarge;
    var adapted = options;
    adapted.request_accepted_encodings = request.request.accepted_encodings;
    const algorithm = if (adapted.message != null and adapted.request_accepted_encodings.contains(options.compression)) options.compression else .identity;
    var initial: response_headers.Block = .{};
    try initial.prepare(request.connection.allocator, .{
        .content_type = request.content_type,
        .compression = algorithm,
        .accepted_encodings = options.accepted_encodings,
        .initial_metadata = options.initial_metadata,
        .initial_binary_metadata = options.initial_binary_metadata,
        .terminal = if (options.trailers_only) .{
            .status = options.status,
            .status_message = options.status_message,
            .status_details = options.status_details,
            .retry_pushback_ms = options.retry_pushback_ms,
            .trailing_metadata = options.trailing_metadata,
            .trailing_binary_metadata = options.trailing_binary_metadata,
        } else null,
    });
    defer initial.deinit(request.connection.allocator);
    var body: ?[]u8 = null;
    defer if (body) |bytes| request.connection.allocator.free(bytes);
    if (!options.trailers_only) {
        body = try web.buildResponseBody(request.connection.allocator, adapted);
        if (request.content_type.text) {
            const encoded = try encode(request.connection.allocator, body.?);
            request.connection.allocator.free(body.?);
            body = encoded;
        }
    }
    var headers = try Fields.init(request.connection.allocator, initial.fields.items, extras(request), !request.transport.request.keepAlive());
    defer headers.deinit();
    try request.connection.writeResponse(.{ .headers = headers.items, .body = body orelse &.{}, .request_method = .POST });
    request.responded = true;
    if (!request.transport.request.keepAlive()) request.connection.writer_state.phase = .unusable;
}

pub fn startServerStream(request: *adapter.Request, options: web.StreamResponseOptions) adapter.Error!ServerStreamWriter {
    if (request.responded) return error.InvalidStreamState;
    try validateCorsMetadata(request, options.initial_metadata);
    const algorithm = if (request.request.accepted_encodings.contains(options.compression)) options.compression else .identity;
    var initial: response_headers.Block = .{};
    try initial.prepare(request.connection.allocator, .{
        .content_type = request.content_type,
        .compression = algorithm,
        .accepted_encodings = options.accepted_encodings,
        .initial_metadata = options.initial_metadata,
        .initial_binary_metadata = options.initial_binary_metadata,
    });
    defer initial.deinit(request.connection.allocator);
    var headers = try Fields.init(request.connection.allocator, initial.fields.items, extras(request), !request.transport.request.keepAlive());
    defer headers.deinit();
    const transport = try request.connection.startResponse(.{ .headers = headers.items, .request_method = .POST });
    request.responded = true;
    return .{
        .allocator = request.connection.allocator,
        .transport = transport,
        .content_type = request.content_type,
        .encoder = .{ .allocator = request.connection.allocator, .algorithm = algorithm, .compression_level = options.compression_level, .max_message_size = @min(options.max_message_size, request.max_message_size) },
    };
}

pub const ServerStreamWriter = struct {
    allocator: std.mem.Allocator,
    transport: http.runtime.ResponseWriter,
    content_type: web.ContentType,
    encoder: codec.Encoder,
    sink: text.EncoderSink(http.runtime.ResponseWriter) = .{},
    finished: bool = false,
    pub fn deinit(self: *ServerStreamWriter) void {
        if (!self.finished) self.transport.deinit();
    }
    pub fn writeMessage(self: *ServerStreamWriter, payload: []const u8) adapter.Error!void {
        return self.writeMessageWithOptions(payload, .{});
    }
    pub fn writeMessageWithOptions(self: *ServerStreamWriter, payload: []const u8, options: codec.MessageOptions) adapter.Error!void {
        if (self.finished) return error.InvalidStreamState;
        if (self.content_type.text) {
            self.sink.inner = &self.transport;
            try self.encoder.writeMessageWithOptions(&self.sink, payload, options);
            return self.sink.flushPadding();
        }
        return self.encoder.writeMessageWithOptions(&self.transport, payload, options);
    }
    pub fn finish(self: *ServerStreamWriter, options: web.TerminalOptions) adapter.Error!void {
        if (self.finished) return error.InvalidStreamState;
        const block = try web.buildTrailerBlock(self.allocator, options);
        defer self.allocator.free(block);
        if (block.len > std.math.maxInt(u32)) return error.MessageTooLarge;
        var prefix: [5]u8 = undefined;
        prefix[0] = 0x80;
        std.mem.writeInt(u32, prefix[1..5], @intCast(block.len), .big);
        if (self.content_type.text) {
            self.sink.inner = &self.transport;
            try self.sink.write(&prefix);
            try self.sink.write(block);
            try self.sink.flushPadding();
        } else {
            try self.transport.write(&prefix);
            try self.transport.write(block);
        }
        try self.transport.finish();
        self.finished = true;
    }
    pub fn finishOk(self: *ServerStreamWriter) adapter.Error!void {
        return self.finish(.{ .status = .ok });
    }
};

pub fn handled(connection: *http.runtime.Connection, request: *const http.Request, status: u16, extra: []const h2.Hpack.HeaderField) adapter.Error!void {
    const initial: []const h2.Hpack.HeaderField = if (status == 405) &.{.{ .name = "allow", .value = "POST, OPTIONS" }} else &.{};
    var fields = try Fields.init(connection.allocator, initial, extra, !request.keepAlive());
    defer fields.deinit();
    try connection.writeResponse(.{ .status = status, .reason = switch (status) {
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        else => "Error",
    }, .headers = fields.items, .request_method = request.method });
    if (!request.keepAlive()) connection.writer_state.phase = .unusable;
}

fn extras(request: *const adapter.Request) []const h2.Hpack.HeaderField {
    return if (request.cors_headers) |headers| headers.fields else &.{};
}

fn validateCorsMetadata(request: *const adapter.Request, fields: []const h2.Hpack.HeaderField) adapter.Error!void {
    return server_request.validateCorsMetadata(request.cors_headers != null, fields);
}

fn encode(allocator: std.mem.Allocator, bytes: []const u8) std.mem.Allocator.Error![]u8 {
    const encoder = std.base64.standard.Encoder;
    const output = try allocator.alloc(u8, encoder.calcSize(bytes.len));
    _ = encoder.encode(output, bytes);
    return output;
}

const Fields = struct {
    allocator: std.mem.Allocator,
    items: []http.Header,
    fn init(allocator: std.mem.Allocator, initial: []const h2.Hpack.HeaderField, extra: []const h2.Hpack.HeaderField, close: bool) std.mem.Allocator.Error!Fields {
        const count = std.math.add(usize, initial.len, extra.len + 1 + @as(usize, @intFromBool(close))) catch return error.OutOfMemory;
        const items = try allocator.alloc(http.Header, count);
        var index: usize = 0;
        for (initial) |field| {
            items[index] = .{ .name = field.name, .value = field.value };
            index += 1;
        }
        for (extra) |field| {
            items[index] = .{ .name = field.name, .value = field.value };
            index += 1;
        }
        items[index] = .{ .name = "vary", .value = "Accept" };
        index += 1;
        if (close) items[index] = .{ .name = "connection", .value = "close" };
        return .{ .allocator = allocator, .items = items };
    }
    fn deinit(self: *Fields) void {
        self.allocator.free(self.items);
        self.* = undefined;
    }
};
