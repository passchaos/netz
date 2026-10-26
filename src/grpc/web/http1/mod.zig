//! gRPC-Web unary requests and server streams on HTTP/1.1 connections.
const std = @import("std");
const http = @import("../../../http1/mod.zig");
const h2 = @import("../../../http2/mod.zig");
const web = @import("../../web.zig");
const call = @import("../../call.zig");
const cors = @import("../cors/mod.zig");
const response = @import("response.zig");
const server_request = @import("../server_request.zig");

pub const Error = web.Error || http.runtime.Error || cors.Error;
pub const Options = server_request.Options;

pub const Request = struct {
    /// Borrowed; keep the connection alive through response completion and
    /// request deinitialization. Message and canonical-header storage is owned.
    connection: *http.runtime.Connection,
    transport: http.runtime.OwnedRequest,
    request: call.UnaryRequest,
    content_type: web.ContentType,
    cors_headers: ?cors.Headers,
    mapped_headers: HeaderMap,
    max_message_size: usize,
    responded: bool = false,

    /// A dropped request cannot be reassigned to a later HTTP/1 response.
    pub fn deinit(self: *Request) void {
        if (!self.responded) self.connection.writer_state.phase = .unusable;
        const allocator = self.connection.allocator;
        self.request.deinit();
        if (self.cors_headers) |*headers| headers.deinit();
        self.mapped_headers.deinit(allocator);
        self.transport.deinit(allocator);
        self.* = undefined;
    }

    pub fn writeUnary(self: *Request, options: call.UnaryResponseOptions) Error!void {
        return response.writeUnary(self, options);
    }

    pub fn startServerStream(self: *Request, options: web.StreamResponseOptions) Error!response.ServerStreamWriter {
        return response.startServerStream(self, options);
    }
};

pub const ReadResult = union(enum) {
    request: Request,
    /// An OPTIONS preflight or rejected request already received a response.
    handled: struct { status: u16 },
};

/// Consume one bounded HTTP request. CORS and protocol rejections are replied
/// to before exposing a request to the application; the connection stays
/// reusable when request framing and persistence allow it.
pub fn readRequest(connection: *http.runtime.Connection, options: Options) Error!ReadResult {
    if (options.cors_policy) |policy| try policy.validate();
    var transport = try connection.readRequest(.{});
    var owned_transport = true;
    defer if (owned_transport) transport.deinit(connection.allocator);
    errdefer connection.writer_state.phase = .unusable;
    if (transport.request.version != .http_1_1) return error.InvalidVersion;
    var headers = try HeaderMap.init(connection.allocator, transport.request.headers);
    var owned_headers = true;
    defer if (owned_headers) headers.deinit(connection.allocator);
    var cors_headers: ?cors.Headers = null;
    var owned_cors = true;
    defer if (owned_cors) {
        if (cors_headers) |*fields| fields.deinit();
    };
    const classified = try server_request.classify(options, transport.request.method.string(), headers.fields);
    if (options.cors_policy) |policy| cors_headers = try cors.Headers.init(connection.allocator, policy, classified.cors_decision.?);
    const extra = if (cors_headers) |fields| fields.fields else &.{};
    if (classified.status) |status| {
        try response.handled(connection, &transport.request, status, extra);
        return .{ .handled = .{ .status = status } };
    }
    var request = web.parseUnaryRequest(connection.allocator, "POST", transport.request.target, headers.fields, transport.request.body, classified.input_type.?, options.max_message_size) catch |err| {
        if (err == error.OutOfMemory) return err;
        const status: u16 = if (err == error.GrpcMessageTooLarge) 413 else 400;
        try response.handled(connection, &transport.request, status, extra);
        return .{ .handled = .{ .status = status } };
    };
    errdefer request.deinit();
    owned_transport = false;
    owned_headers = false;
    owned_cors = false;
    return .{ .request = .{
        .connection = connection,
        .transport = transport,
        .request = request,
        .content_type = classified.output_type.?,
        .cors_headers = cors_headers,
        .mapped_headers = headers,
        .max_message_size = options.max_message_size,
    } };
}

const HeaderMap = struct {
    fields: []h2.Hpack.HeaderField,
    names: []u8,
    fn init(allocator: std.mem.Allocator, input: []const http.Header) std.mem.Allocator.Error!HeaderMap {
        var names_len: usize = 0;
        for (input) |field| names_len = std.math.add(usize, names_len, field.name.len) catch return error.OutOfMemory;
        const fields = try allocator.alloc(h2.Hpack.HeaderField, input.len);
        errdefer allocator.free(fields);
        const names = try allocator.alloc(u8, names_len);
        var offset: usize = 0;
        for (input, fields) |field, *mapped| {
            for (field.name, names[offset..][0..field.name.len]) |byte, *lower| lower.* = std.ascii.toLower(byte);
            mapped.* = .{ .name = names[offset..][0..field.name.len], .value = field.value };
            offset += field.name.len;
        }
        return .{ .fields = fields, .names = names };
    }
    fn deinit(self: *HeaderMap, allocator: std.mem.Allocator) void {
        allocator.free(self.fields);
        allocator.free(self.names);
        self.* = undefined;
    }
};

pub const ServerStreamWriter = response.ServerStreamWriter;
test {
    _ = @import("tests.zig");
}
