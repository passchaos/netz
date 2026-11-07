//! One aggregate response over a step-driven client duplex stream.
const std = @import("std");
const client = @import("../../client.zig");
const mapping = @import("../../client/header_mapping.zig");
const http2 = @import("../../../http2/mod.zig");
const runtime = @import("../../../http2/runtime.zig");

pub const Exchange = struct {
    stream: runtime.ClientDuplexStream,
    request: client.RequestOptions,
    written: usize = 0,
    headers: []http2.Hpack.HeaderField = &.{},
    trailers: []http2.Hpack.HeaderField = &.{},
    status: u16 = 0,
    body_allowed: bool = true,
    trailers_only: bool = false,
    body: std.ArrayList(u8) = .empty,

    pub fn init(connection: *runtime.Connection, target: []const u8, request: client.RequestOptions, until: std.Io.Clock.Timestamp) !Exchange {
        var stack: [mapping.max_stack_headers]http2.Hpack.HeaderField = undefined;
        var headers = try mapping.mapHttp2(connection.allocator, request.headers, &stack);
        defer headers.deinit(connection.allocator);
        // Validate trailers before committing request HEADERS.
        var trailer_stack: [mapping.max_stack_trailers]http2.Hpack.HeaderField = undefined;
        var trailers = try mapping.mapHttp2(connection.allocator, request.trailers, &trailer_stack);
        defer trailers.deinit(connection.allocator);
        try @import("../../../http2/runtime/headers/message.zig").validateHeaderBlock(trailers.items, .request_trailers);
        var writer = try connection.startRequestWithDeadline(.{
            .method = request.method,
            .path = target,
            .headers = headers.items,
            .body_length = request.body.len,
        }, until);
        errdefer writer.deinit();
        return .{ .stream = try writer.beginDuplex(), .request = request };
    }

    pub fn deinit(self: *Exchange, allocator: std.mem.Allocator) void {
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
        const remaining = self.request.body[self.written..];
        const bytes = remaining[0..@min(remaining.len, quantum)];
        const result = if (self.request.trailers.len == 0 and bytes.len == remaining.len)
            try self.stream.finishRequestDataWithDeadline(bytes, until)
        else
            try self.stream.writeWithDeadline(bytes, until);
        self.written += result.written;
        if (self.written == self.request.body.len and self.request.trailers.len != 0) {
            var stack: [mapping.max_stack_trailers]http2.Hpack.HeaderField = undefined;
            var trailers = try mapping.mapHttp2(self.stream.connection.allocator, self.request.trailers, &stack);
            defer trailers.deinit(self.stream.connection.allocator);
            try self.stream.finishRequestTrailersWithDeadline(trailers.items, until);
            return true;
        }
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
