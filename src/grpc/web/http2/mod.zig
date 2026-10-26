//! gRPC-Web request dispatch and CORS on persistent HTTP/2 connections.
const std = @import("std");
const http = @import("../../../http2/mod.zig");
const call = @import("../../call.zig");
const web = @import("../../web.zig");
const cors = @import("../cors/mod.zig");
const server_request = @import("../server_request.zig");
const response = @import("response.zig");

pub const Options = server_request.Options;
pub const Error = web.Error || cors.Error;
pub const ReadResult = union(enum) {
    request: Request,
    handled: struct { stream_id: u31, status: u16 },
};

pub const Request = struct {
    /// Borrowed until response completion and request deinitialization.
    connection: *http.runtime.Connection,
    transport: http.runtime.OwnedRequest,
    request: call.UnaryRequest,
    content_type: web.ContentType,
    cors_headers: ?cors.Headers,
    max_message_size: usize,
    responded: bool = false,

    pub fn deinit(self: *Request) void {
        if (!self.responded) self.connection.abandonPeerRequest(self.transport.stream_id, .cancel);
        const allocator = self.connection.allocator;
        self.request.deinit();
        if (self.cors_headers) |*headers| headers.deinit();
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

pub fn readRequest(connection: *http.runtime.Connection, options: Options) Error!ReadResult {
    return readBefore(connection, options, null);
}

pub fn readRequestWithTimeout(connection: *http.runtime.Connection, options: Options, timeout: std.Io.Duration) Error!ReadResult {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    if (options.cors_policy) |policy| try policy.validate();
    return readBefore(connection, options, .fromNow(connection.io, .{ .raw = timeout, .clock = .awake }));
}

pub fn readRequestWithDeadline(connection: *http.runtime.Connection, options: Options, deadline: std.Io.Clock.Timestamp) Error!ReadResult {
    if (options.cors_policy) |policy| try policy.validate();
    return readBefore(connection, options, try @import("../../../internal/deadline.zig").usableAwake(connection.io, deadline));
}

fn readBefore(connection: *http.runtime.Connection, options: Options, deadline: ?std.Io.Clock.Timestamp) Error!ReadResult {
    if (options.cors_policy) |policy| try policy.validate();
    var transport = if (deadline) |before| try connection.readRequestWithDeadline(before) else try connection.readRequest();
    var transport_owned = true;
    defer if (transport_owned) transport.deinit(connection.allocator);
    errdefer connection.abandonPeerRequest(transport.stream_id, .internal_error);
    const classified = try server_request.classify(options, transport.method, transport.headers);
    var cors_headers: ?cors.Headers = null;
    var cors_owned = true;
    defer if (cors_owned) {
        if (cors_headers) |*headers| headers.deinit();
    };
    if (options.cors_policy) |policy| cors_headers = try cors.Headers.init(connection.allocator, policy, classified.cors_decision.?);
    const extra = if (cors_headers) |headers| headers.fields else &.{};
    if (classified.status) |status| {
        try response.handled(connection, transport.stream_id, status, extra);
        return .{ .handled = .{ .stream_id = transport.stream_id, .status = status } };
    }
    var request = web.parseUnaryRequest(connection.allocator, transport.method, transport.path, transport.headers, transport.body, classified.input_type.?, options.max_message_size) catch |err| {
        if (err == error.OutOfMemory) return err;
        const status: u16 = if (err == error.GrpcMessageTooLarge) 413 else 400;
        try response.handled(connection, transport.stream_id, status, extra);
        return .{ .handled = .{ .stream_id = transport.stream_id, .status = status } };
    };
    request.stream_id = transport.stream_id;
    transport_owned = false;
    cors_owned = false;
    return .{ .request = .{
        .connection = connection,
        .transport = transport,
        .request = request,
        .content_type = classified.output_type.?,
        .cors_headers = cors_headers,
        .max_message_size = options.max_message_size,
    } };
}

pub const ServerStreamWriter = response.ServerStreamWriter;
test {
    _ = @import("tests.zig");
}
