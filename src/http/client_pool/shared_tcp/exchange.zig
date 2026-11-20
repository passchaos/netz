//! One aggregate response over a step-driven client duplex stream.
const std = @import("std");
const client = @import("../../client.zig");
const mapping = @import("../../client/header_mapping.zig");
const http2 = @import("../../../http2/mod.zig");
const runtime = @import("../../../http2/runtime.zig");
const BodyReader = @import("body_reader.zig").Reader;

pub const Exchange = struct {
    stream: runtime.ClientDuplexStream,
    request: client.RequestOptions,
    reader: ?*BodyReader = null,
    written: usize = 0,
    headers: []http2.Hpack.HeaderField = &.{},
    trailers: []http2.Hpack.HeaderField = &.{},
    status: u16 = 0,
    body_allowed: bool = true,
    trailers_only: bool = false,
    body: std.ArrayList(u8) = .empty,

    pub fn init(connection: *runtime.Connection, target: []const u8, request: client.RequestOptions, until: std.Io.Clock.Timestamp, wake: *std.Io.Event, quantum: usize) !Exchange {
        // The shared aggregate path owns only the CONNECT response head. A
        // request body or trailers would be tunnel bytes the caller cannot
        // consume through this API.
        if (std.mem.eql(u8, request.method, "CONNECT") and
            (request.bodySource() == .reader or request.bodySource().contentLength().? != 0 or request.trailers.len != 0))
        {
            return error.InvalidContentLength;
        }
        var stack: [mapping.max_stack_headers]http2.Hpack.HeaderField = undefined;
        var headers = try mapping.mapHttp2(connection.allocator, request.headers, &stack);
        defer headers.deinit(connection.allocator);
        // Validate trailers before committing request HEADERS.
        var trailer_stack: [mapping.max_stack_trailers]http2.Hpack.HeaderField = undefined;
        var trailers = try mapping.mapHttp2(connection.allocator, request.trailers, &trailer_stack);
        defer trailers.deinit(connection.allocator);
        try @import("../../../http2/runtime/headers/message.zig").validateHeaderBlock(trailers.items, .request_trailers);
        const reader = switch (request.bodySource()) {
            .slice => null,
            .reader => |body| try BodyReader.create(connection.allocator, connection.io, body.reader, wake, quantum),
        };
        errdefer if (reader) |source| source.deinit();
        var writer = try connection.startRequestWithDeadline(.{
            .method = request.method,
            .path = target,
            .headers = headers.items,
            .body_length = request.bodySource().contentLength(),
        }, until);
        errdefer writer.deinit();
        var stream = try writer.beginDuplex();
        errdefer stream.deinit();
        if (reader) |source| try source.start();
        return .{ .stream = stream, .request = request, .reader = reader };
    }

    pub fn deinit(self: *Exchange, allocator: std.mem.Allocator) void {
        if (self.reader) |reader| reader.deinit();
        self.stream.deinit();
        // Decoded HPACK fields may share one packed allocation. The runtime's
        // destructor handles both packed blocks and separately owned fields.
        runtime.freeHeaderFields(allocator, self.headers);
        runtime.freeHeaderFields(allocator, self.trailers);
        self.body.deinit(allocator);
        self.* = undefined;
    }

    pub fn write(self: *Exchange, quantum: usize, until: std.Io.Clock.Timestamp) !bool {
        if (self.stream.requestFinished()) return false;
        const remaining = if (self.reader) |reader| switch (reader.available()) {
            .pending => return false,
            .data => |bytes| bytes,
            .eof => return self.finishBody(until),
            .failure => return error.RequestBodyReadFailed,
        } else self.request.bodySource().slice[self.written..];
        const bytes = remaining[0..@min(remaining.len, quantum)];
        const result = if (self.reader == null and self.request.trailers.len == 0 and bytes.len == remaining.len)
            try self.stream.finishRequestDataWithDeadline(bytes, until)
        else
            try self.stream.writeWithDeadline(bytes, until);
        self.written += result.written;
        if (self.reader) |reader| reader.consume(result.written);
        if (self.reader == null and self.written == self.request.bodySource().slice.len and self.request.trailers.len != 0) {
            return self.finishBody(until);
        }
        return result.written != 0 or result.response_available or self.stream.requestFinished();
    }

    fn finishBody(self: *Exchange, until: std.Io.Clock.Timestamp) !bool {
        if (self.request.trailers.len != 0) {
            var stack: [mapping.max_stack_trailers]http2.Hpack.HeaderField = undefined;
            var trailers = try mapping.mapHttp2(self.stream.connection.allocator, self.request.trailers, &stack);
            defer trailers.deinit(self.stream.connection.allocator);
            try self.stream.finishRequestTrailersWithDeadline(trailers.items, until);
            return true;
        }
        const result = try self.stream.finishRequestDataWithDeadline(&.{}, until);
        return result.written != 0 or result.response_available or self.stream.requestFinished();
    }

    pub fn poll(self: *Exchange, until: std.Io.Clock.Timestamp) !?runtime.OwnedResponse {
        const allocator = self.stream.connection.allocator;
        while (try self.stream.pollResponseEventWithDeadline(until)) |received| {
            var event = received;
            defer event.deinit(allocator);
            switch (event) {
                .informational => {},
                .head => |head| {
                    self.headers = head.headers;
                    event.head.headers = &.{};
                    self.status = head.status;
                    self.body_allowed = head.body_allowed;
                    self.trailers_only = self.stream.responseFinished();
                },
                .data => |data| try self.body.appendSlice(allocator, data.data),
                .trailers => |trailers| {
                    self.trailers = trailers;
                    event.trailers = &.{};
                },
                .reset => return error.StreamReset,
                .finished => {
                    // An early final response must stop an unfinished upload.
                    if (!self.stream.requestFinished()) try self.stream.reset(.cancel);
                    const body = try self.body.toOwnedSlice(allocator);
                    const response = runtime.OwnedResponse{ .headers = self.headers, .trailers = self.trailers, .status = self.status, .body = body, .body_allowed = self.body_allowed, .trailers_only = self.trailers_only };
                    self.headers = &.{};
                    self.trailers = &.{};
                    return response;
                },
            }
        }
        return null;
    }
};
