//! Unified streaming request/response handles for HTTP/1, HTTP/2, and HTTP/3.
//!
//! Request bodies are written incrementally by the caller. Response bodies are
//! delivered through callbacks because the protocol runtimes own the read loop
//! and cannot be paused from a pull reader without buffering the whole body.

const std = @import("std");
const http1 = @import("../../http1/mod.zig");
const http2 = @import("../../http2/mod.zig");
const http3 = @import("../../http3/mod.zig");
const http1_runtime = @import("../../http1/runtime.zig");
const http2_runtime = @import("../../http2/runtime.zig");
const http3_runtime = @import("../../http3/runtime.zig");
const types = @import("../client/types.zig");

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const ResponseHead = struct {
    protocol: types.Protocol,
    status: u16,
    headers: []const Header,
};

pub const ResponseSink = struct {
    context: *anyopaque,
    begin: *const fn (context: *anyopaque, head: ResponseHead) anyerror!void,
    data: *const fn (context: *anyopaque, bytes: []const u8) anyerror!void,
    end: *const fn (context: *anyopaque, trailers: []const Header) anyerror!void,
};

pub const Handle = struct {
    allocator: std.mem.Allocator,
    protocol: types.Protocol,
    state: State,
    h1_continue_pending: bool = false,
    h1_buffered_response: ?http1_runtime.OwnedResponse = null,
    h3_pending_event: ?http3_runtime.StreamingEvent = null,
    response_available: bool = false,
    body_finished: bool = false,
    response_head: ?ResponseHead = null,
    response_headers: []Header = &.{},
    response_header_storage: []u8 = &.{},

    const State = union(enum) {
        http1: http1_runtime.RequestWriter,
        http2: http2_runtime.RequestWriter,
        http3: Http3,
    };

    pub const Http3 = struct {
        client: *http3_runtime.HandshakeClient,
        stream_id: u62,
    };

    pub fn initHttp1(
        allocator: std.mem.Allocator,
        writer: http1_runtime.RequestWriter,
    ) Handle {
        return .{
            .allocator = allocator,
            .protocol = .http1,
            .state = .{ .http1 = writer },
            .h1_continue_pending = writer.expects_continue,
        };
    }

    pub fn initHttp2(
        allocator: std.mem.Allocator,
        writer: http2_runtime.RequestWriter,
    ) Handle {
        return .{
            .allocator = allocator,
            .protocol = .http2,
            .state = .{ .http2 = writer },
        };
    }

    /// Wrap a stream opened through `HandshakeClient.startRequest`.
    pub fn initHttp3(
        allocator: std.mem.Allocator,
        client: *http3_runtime.HandshakeClient,
        stream_id: u62,
    ) Handle {
        return .{
            .allocator = allocator,
            .protocol = .http3,
            .state = .{ .http3 = .{
                .client = client,
                .stream_id = stream_id,
            } },
        };
    }

    pub fn deinit(self: *Handle) void {
        switch (self.state) {
            .http1 => |*writer| writer.deinit(),
            .http2 => |*writer| writer.deinit(),
            .http3 => {},
        }
        if (self.h1_buffered_response) |*response| {
            response.deinit(self.allocator);
        }
        if (self.h3_pending_event) |*event| {
            event.deinit(self.allocator);
        }
        if (self.response_headers.len != 0) {
            self.allocator.free(self.response_headers);
        }
        if (self.response_header_storage.len != 0) {
            self.allocator.free(self.response_header_storage);
        }
        self.* = undefined;
    }

    pub fn writeBody(self: *Handle, bytes: []const u8) !void {
        switch (self.state) {
            .http1 => |*writer| {
                if (self.h1_continue_pending) {
                    self.h1_continue_pending = false;
                    switch (try writer.waitForContinue()) {
                        .proceed => {},
                        .final_response => |response| {
                            self.h1_buffered_response = response;
                            self.response_available = true;
                            return error.ResponseAvailable;
                        },
                    }
                }
                try writer.write(bytes);
            },
            .http2 => |*writer| {
                writer.write(bytes) catch |err| switch (err) {
                    error.ResponseAvailable => {
                        self.response_available = true;
                        self.body_finished = true;
                        return error.ResponseAvailable;
                    },
                    else => return err,
                };
            },
            .http3 => |*h3| {
                h3.client.sendRequestBodyPaced(
                    h3.stream_id,
                    bytes,
                    false,
                ) catch |err| switch (err) {
                    error.RequestCancelled, error.RequestRejected => {
                        if (try self.stashHttp3Head(h3)) {
                            self.response_available = true;
                            return error.ResponseAvailable;
                        }
                        return err;
                    },
                    else => return err,
                };
            },
        }
    }

    pub fn finishBody(self: *Handle) !void {
        switch (self.state) {
            .http1 => |*writer| {
                try writer.finish();
            },
            .http2 => |*writer| {
                writer.finish() catch |err| switch (err) {
                    error.ResponseAvailable => {
                        self.response_available = true;
                        self.body_finished = true;
                        return;
                    },
                    else => return err,
                };
            },
            .http3 => |*h3| {
                h3.client.sendRequestBodyPaced(
                    h3.stream_id,
                    &.{},
                    true,
                ) catch |err| switch (err) {
                    error.RequestCancelled, error.RequestRejected => {
                        if (try self.stashHttp3Head(h3)) {
                            self.response_available = true;
                            self.body_finished = true;
                            return;
                        }
                        return err;
                    },
                    else => return err,
                };
            },
        }
        self.body_finished = true;
    }

    pub fn finishTrailers(self: *Handle, trailers: []const Header) !void {
        switch (self.state) {
            .http1 => |*writer| {
                const mapped = try mapHeaders1(self.allocator, trailers);
                defer self.allocator.free(mapped);
                try writer.finishTrailers(mapped);
            },
            .http2 => |*writer| {
                const mapped = try mapHeaders2(self.allocator, trailers);
                defer self.allocator.free(mapped);
                writer.finishTrailers(mapped) catch |err| switch (err) {
                    error.ResponseAvailable => {
                        self.response_available = true;
                        self.body_finished = true;
                        return;
                    },
                    else => return err,
                };
            },
            .http3 => |*h3| {
                const mapped = try mapHeaders3(self.allocator, trailers);
                defer self.allocator.free(mapped);
                h3.client.finishRequestTrailersPaced(
                    h3.stream_id,
                    mapped,
                ) catch |err| switch (err) {
                    error.RequestCancelled, error.RequestRejected => {
                        if (try self.stashHttp3Head(h3)) {
                            self.response_available = true;
                            self.body_finished = true;
                            return;
                        }
                        return err;
                    },
                    else => return err,
                };
            },
        }
        self.body_finished = true;
    }

    /// Stream the final response into `sink`. `head.headers` and trailer
    /// slices are valid only for the duration of the corresponding callback.
    pub fn readResponse(self: *Handle, sink: ResponseSink) !ResponseHead {
        if (self.h1_buffered_response) |response| {
            return self.emitBufferedResponse(response, sink);
        }
        var context = ResponseContext{ .handle = self, .sink = sink };
        switch (self.state) {
            .http1 => |*writer| {
                var response = try writer.readResponseStreamingWithHead(
                    &context,
                    beginHttp1,
                    consumeResponse,
                );
                defer response.deinit(self.allocator);
                const trailers = try mapHeaders1(
                    self.allocator,
                    response.trailers,
                );
                defer self.allocator.free(trailers);
                try sink.end(sink.context, trailers);
            },
            .http2 => |*writer| {
                var response = try writer.readResponseStreamingWithHead(
                    &context,
                    beginHttp2,
                    consumeResponse,
                );
                defer response.deinit(self.allocator);
                const trailers = try mapHeaders2(
                    self.allocator,
                    response.trailers,
                );
                defer self.allocator.free(trailers);
                try sink.end(sink.context, trailers);
            },
            .http3 => |*h3| {
                return self.readResponseHttp3(h3, sink);
            },
        }
        return self.response_head orelse error.MissingResponseHead;
    }

    fn emitBufferedResponse(
        self: *Handle,
        response: http1_runtime.OwnedResponse,
        sink: ResponseSink,
    ) !ResponseHead {        const headers = try copyHeaders1(
            self.allocator,
            &self.response_headers,
            &self.response_header_storage,
            response.response.headers,
        );
        const head = ResponseHead{
            .protocol = .http1,
            .status = response.response.status,
            .headers = headers,
        };
        self.response_head = head;
        try sink.begin(sink.context, head);
        if (response.response.body.len != 0) {
            try sink.data(sink.context, response.response.body);
        }
        const trailers = try mapHeaders1(
            self.allocator,
            response.response.trailers,
        );
        defer self.allocator.free(trailers);
        try sink.end(sink.context, trailers);
        return head;
    }

    /// Move an already buffered final response head out of the H3 event
    /// queue. Used when a request-body write observes an early rejection and
    /// the caller should read the response instead of sending more body.
    fn stashHttp3Head(self: *Handle, h3: *const Http3) !bool {
        if (self.h3_pending_event != null) return true;
        while (try h3.client.pollResponseEvent(h3.stream_id)) |event| {
            switch (event) {
                .head => |head| switch (head) {
                    .request => return error.InvalidResponse,
                    .response => |response| {
                        if (response.status >= 200) {
                            self.h3_pending_event = event;
                            return true;
                        }
                        var informational = event;
                        informational.deinit(self.allocator);
                    },
                },
                .data_available, .trailers, .finished, .push_promise => {
                    var ignored = event;
                    ignored.deinit(self.allocator);
                },
            }
        }
        return false;
    }

    fn readResponseHttp3(
        self: *Handle,
        h3: *const Http3,
        sink: ResponseSink,
    ) !ResponseHead {
        var trailers: ?http3.DecodedTrailers = null;
        defer if (trailers) |*value| value.deinit(self.allocator);

        var pending = self.h3_pending_event;
        self.h3_pending_event = null;
        defer if (pending) |*event| event.deinit(self.allocator);
        var use_pending = pending != null;

        while (true) {
            var event = if (use_pending) blk: {
                use_pending = false;
                const value = pending.?;
                pending = null;
                break :blk value;
            } else (try h3.client.receiveResponseEvent(h3.stream_id)) orelse
                continue;
            defer event.deinit(self.allocator);
            switch (event) {
                .head => |head| switch (head) {
                    .request => return error.InvalidResponse,
                    .response => |response| {
                        if (response.status < 200) continue;
                        try self.beginHttp3Response(response, sink);
                    },
                },
                .data_available => {
                    var buffer: [16 * 1024]u8 = undefined;
                    const count = try h3.client.readResponseData(
                        h3.stream_id,
                        &buffer,
                    );
                    if (count != 0) {
                        try sink.data(sink.context, buffer[0..count]);
                    }
                },
                .trailers => |value| {
                    if (trailers != null) return error.InvalidResponse;
                    trailers = value;
                    event = .finished;
                },
                .finished => {
                    const mapped = try mapHeaders3(
                        self.allocator,
                        if (trailers) |value| value.fields else &.{},
                    );
                    defer self.allocator.free(mapped);
                    try sink.end(sink.context, mapped);
                    return self.response_head orelse
                        error.MissingResponseHead;
                },
                .push_promise => {},
            }
        }
    }

    fn beginHttp3Response(
        self: *Handle,
        response: http3.DecodedResponseHead,
        sink: ResponseSink,
    ) !void {
        const mapped = try mapHeaders3(self.allocator, response.headers);
        defer self.allocator.free(mapped);
        try self.beginResponse(.http3, response.status, mapped);
        try sink.begin(sink.context, self.response_head.?);
    }

    fn beginResponse(
        self: *Handle,
        protocol: types.Protocol,
        status: u16,
        headers: []const Header,
    ) !void {
        const owned = try copyHeadersGeneric(
            self.allocator,
            &self.response_headers,
            &self.response_header_storage,
            headers,
        );
        const head = ResponseHead{
            .protocol = protocol,
            .status = status,
            .headers = owned,
        };
        self.response_head = head;
        // The context is filled by the caller's begin adapter.
    }

    const ResponseContext = struct {
        handle: *Handle,
        sink: ResponseSink,
    };

    fn beginHttp1(
        context: *ResponseContext,
        head: http1_runtime.StreamingResponseHead,
    ) !void {
        const mapped = try mapHeaders1(
            context.handle.allocator,
            head.headers,
        );
        defer context.handle.allocator.free(mapped);
        try context.handle.beginResponse(.http1, head.status, mapped);
        try context.sink.begin(
            context.sink.context,
            context.handle.response_head.?,
        );
    }

    fn beginHttp2(
        context: *ResponseContext,
        head: http2_runtime.StreamingResponseHead,
    ) !void {
        const mapped = try mapHeaders2(
            context.handle.allocator,
            head.headers,
        );
        defer context.handle.allocator.free(mapped);
        try context.handle.beginResponse(.http2, head.status, mapped);
        try context.sink.begin(
            context.sink.context,
            context.handle.response_head.?,
        );
    }

    fn consumeResponse(
        context: *ResponseContext,
        bytes: []const u8,
    ) !void {
        try context.sink.data(context.sink.context, bytes);
    }
};

/// Open a streaming HTTP/3 request on an exclusive `HandshakeClient`.
///
/// The client must not be bound to a pool dispatcher; H3 pool requests stay
/// buffered until the dispatcher grows a streaming command channel.
pub fn startHttp3(
    allocator: std.mem.Allocator,
    client: *http3_runtime.HandshakeClient,
    request: http3.Request,
    body_length: ?usize,
) !Handle {
    const stream_id = try client.startRequest(request, body_length);
    return Handle.initHttp3(allocator, client, stream_id);
}

fn mapHeaders1(
    allocator: std.mem.Allocator,
    headers: []const http1.Header,
) ![]Header {
    const result = try allocator.alloc(Header, headers.len);
    for (headers, result) |source, *target| {
        target.* = .{ .name = source.name, .value = source.value };
    }
    return result;
}

fn mapHeaders2(
    allocator: std.mem.Allocator,
    headers: []const http2.Hpack.HeaderField,
) ![]Header {
    const result = try allocator.alloc(Header, headers.len);
    for (headers, result) |source, *target| {
        target.* = .{ .name = source.name, .value = source.value };
    }
    return result;
}

fn mapHeaders3(
    allocator: std.mem.Allocator,
    headers: []const http3.Qpack.HeaderField,
) ![]Header {
    const result = try allocator.alloc(Header, headers.len);
    for (headers, result) |source, *target| {
        target.* = .{ .name = source.name, .value = source.value };
    }
    return result;
}

fn copyHeaders1(
    allocator: std.mem.Allocator,
    headers_out: *[]Header,
    storage_out: *[]u8,
    headers: []const http1.Header,
) ![]Header {
    return copyHeaderPairs(allocator, headers_out, storage_out, headers);
}

fn copyHeadersGeneric(
    allocator: std.mem.Allocator,
    headers_out: *[]Header,
    storage_out: *[]u8,
    headers: []const Header,
) ![]Header {
    return copyHeaderPairs(allocator, headers_out, storage_out, headers);
}

fn copyHeaderPairs(
    allocator: std.mem.Allocator,
    headers_out: *[]Header,
    storage_out: *[]u8,
    headers: anytype,
) ![]Header {
    var total: usize = 0;
    for (headers) |header| {
        total = try std.math.add(usize, total, header.name.len);
        total = try std.math.add(usize, total, header.value.len);
    }
    if (headers_out.*.len != 0) allocator.free(headers_out.*);
    if (storage_out.*.len != 0) allocator.free(storage_out.*);
    headers_out.* = &.{};
    storage_out.* = &.{};

    const storage = try allocator.alloc(u8, total);
    errdefer allocator.free(storage);
    const result = try allocator.alloc(Header, headers.len);
    errdefer allocator.free(result);
    var offset: usize = 0;
    for (headers, result) |source, *target| {
        const name = storage[offset..][0..source.name.len];
        @memcpy(name, source.name);
        offset += source.name.len;
        const value = storage[offset..][0..source.value.len];
        @memcpy(value, source.value);
        offset += source.value.len;
        target.* = .{ .name = name, .value = value };
    }
    headers_out.* = result;
    storage_out.* = storage;
    return result;
}
