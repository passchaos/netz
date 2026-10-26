const std = @import("std");
const http = @import("../../../http2/mod.zig");
const web = @import("../../web.zig");
const call = @import("../../call.zig");
const codec = @import("../../stream/codec.zig");
const server_request = @import("../server_request.zig");
const adapter = @import("mod.zig");

pub fn writeUnary(request: *adapter.Request, options: call.UnaryResponseOptions) adapter.Error!void {
    if (request.responded) return error.InvalidStreamState;
    try call.validateCustomMetadata(options.initial_metadata);
    try call.validateCustomMetadata(options.trailing_metadata);
    try call.validateCustomBinaryMetadata(options.initial_binary_metadata);
    try call.validateCustomBinaryMetadata(options.trailing_binary_metadata);
    if (options.message) |message| if (message.len > request.max_message_size) return error.GrpcMessageTooLarge;
    try server_request.validateCorsMetadata(request.cors_headers != null, options.initial_metadata);
    if (options.trailers_only) try server_request.validateCorsMetadata(request.cors_headers != null, options.trailing_metadata);
    var adapted = options;
    adapted.request_accepted_encodings = request.request.accepted_encodings;
    var headers = try Fields.init(request.connection.allocator, options.initial_metadata, extras(request));
    defer headers.deinit();
    adapted.initial_metadata = headers.fields;
    try web.writeUnaryResponse(request.connection, request.connection.allocator, request.transport.stream_id, adapted, request.content_type);
    request.responded = true;
}

pub fn startServerStream(request: *adapter.Request, options: web.StreamResponseOptions) adapter.Error!ServerStreamWriter {
    if (request.responded) return error.InvalidStreamState;
    try call.validateCustomMetadata(options.initial_metadata);
    try call.validateCustomBinaryMetadata(options.initial_binary_metadata);
    try server_request.validateCorsMetadata(request.cors_headers != null, options.initial_metadata);
    var headers = try Fields.init(request.connection.allocator, options.initial_metadata, extras(request));
    defer headers.deinit();
    var adapted = options;
    adapted.initial_metadata = headers.fields;
    adapted.request_accepted_encodings = request.request.accepted_encodings;
    adapted.max_message_size = @min(request.max_message_size, options.max_message_size);
    const writer = try web.startServerStream(request.connection, request.connection.allocator, request.transport.stream_id, adapted, request.content_type);
    request.responded = true;
    return .{ .inner = writer };
}

pub const ServerStreamWriter = struct {
    inner: web.ServerStreamWriter,
    pub fn deinit(self: *ServerStreamWriter) void {
        self.inner.deinit();
    }
    pub fn writeMessage(self: *ServerStreamWriter, bytes: []const u8) adapter.Error!void {
        return self.inner.writeMessage(bytes);
    }
    pub fn writeMessageWithOptions(self: *ServerStreamWriter, bytes: []const u8, options: codec.MessageOptions) adapter.Error!void {
        return self.inner.writeMessageWithOptions(bytes, options);
    }
    pub fn finish(self: *ServerStreamWriter, options: web.TerminalOptions) adapter.Error!void {
        return self.inner.finishWithOptions(options);
    }
    pub fn finishOk(self: *ServerStreamWriter) adapter.Error!void {
        return self.inner.finishOk();
    }
};

pub fn handled(connection: *http.runtime.Connection, stream_id: u31, status: u16, extra: []const http.Hpack.HeaderField) adapter.Error!void {
    const initial: []const http.Hpack.HeaderField = if (status == 405) &.{.{ .name = "allow", .value = "POST, OPTIONS" }} else &.{};
    var headers = try Fields.init(connection.allocator, initial, extra);
    defer headers.deinit();
    try connection.writeResponse(stream_id, .{ .status = status, .headers = headers.fields });
}

fn extras(request: *const adapter.Request) []const http.Hpack.HeaderField {
    return if (request.cors_headers) |headers| headers.fields else &.{};
}

const Fields = struct {
    allocator: std.mem.Allocator,
    fields: []http.Hpack.HeaderField,
    fn init(allocator: std.mem.Allocator, initial: []const http.Hpack.HeaderField, extra: []const http.Hpack.HeaderField) std.mem.Allocator.Error!Fields {
        const count = std.math.add(usize, initial.len, std.math.add(usize, extra.len, 1) catch return error.OutOfMemory) catch return error.OutOfMemory;
        const fields = try allocator.alloc(http.Hpack.HeaderField, count);
        @memcpy(fields[0..initial.len], initial);
        @memcpy(fields[initial.len..][0..extra.len], extra);
        fields[count - 1] = .{ .name = "vary", .value = "Accept" };
        return .{ .allocator = allocator, .fields = fields };
    }
    fn deinit(self: *Fields) void {
        self.allocator.free(self.fields);
        self.* = undefined;
    }
};
