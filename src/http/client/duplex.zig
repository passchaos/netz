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
const upload = @import("upload.zig");
const reader_upload = @import("reader_upload.zig");
const Fifo = @import("../../internal/fifo.zig").Fifo;

pub const Header = types.Header;
pub const UploadProgress = upload.Progress;

pub const ResponseHead = @import("response_sink.zig").ResponseHead;
pub const ResponseSink = @import("response_sink.zig").ResponseSink;

pub const Handle = struct {
    allocator: std.mem.Allocator,
    protocol: types.Protocol,
    state: State,
    reader_upload: reader_upload.Pump = .{},
    h1_continue_pending: bool = false,
    h1_buffered_response: ?http1_runtime.OwnedResponse = null,
    h3_pending_event: ?http3_runtime.StreamingEvent = null,
    h3_pending_interims: Fifo(http3_runtime.StreamingEvent) = .{},
    h3_response_metadata: ?struct { body_allowed: bool, consumed: usize, qpack_section_acknowledgments: usize } = null,
    response_available: bool = false,
    body_finished: bool = false,
    response_complete: bool = false,
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
            .body_finished = client.outbound_bodies.find(stream_id) == null,
            .state = .{ .http3 = .{
                .client = client,
                .stream_id = stream_id,
            } },
        };
    }

    pub fn deinit(self: *Handle) void {
        self.reader_upload.deinit(self.allocator);
        switch (self.state) {
            .http1 => |*writer| writer.deinit(),
            .http2 => |*writer| writer.deinit(),
            .http3 => |*h3| {
                // Abandoning a live H3 request must release its stream
                // lifecycle; the connection itself stays reusable.
                if (!self.response_complete) {
                    h3.client.tryCancelRequest(
                        h3.stream_id,
                        http3.ApplicationErrorCode.request_cancelled,
                    ) catch {};
                }
            },
        }
        if (self.h1_buffered_response) |*response| {
            response.deinit(self.allocator);
        }
        if (self.h3_pending_event) |*event| {
            event.deinit(self.allocator);
        }
        for (self.h3_pending_interims.slice()) |queued| {
            var event = queued;
            event.deinit(self.allocator);
        }
        self.h3_pending_interims.deinit(self.allocator);
        if (self.response_headers.len != 0) {
            self.allocator.free(self.response_headers);
        }
        if (self.response_header_storage.len != 0) {
            self.allocator.free(self.response_header_storage);
        }
        self.* = undefined;
    }

    pub const writeBody = upload.writeBody;
    pub const writeBodyWithDeadline = upload.writeBodyWithDeadline;
    pub const writeBodyWithTimeout = upload.writeBodyWithTimeout;
    pub const writeBodyFromReader = upload.writeBodyFromReader;
    pub const writeBodyFromReaderWithDeadline = upload.writeBodyFromReaderWithDeadline;
    pub const writeBodyFromReaderWithTimeout = upload.writeBodyFromReaderWithTimeout;
    pub const finishBody = upload.finishBody;
    pub const finishBodyWithDeadline = upload.finishBodyWithDeadline;
    pub const finishBodyWithTimeout = upload.finishBodyWithTimeout;
    pub const finishTrailers = upload.finishTrailers;
    pub const finishTrailersWithDeadline = upload.finishTrailersWithDeadline;
    pub const finishTrailersWithTimeout = upload.finishTrailersWithTimeout;

    /// Stream the final response into `sink`. Final head fields remain valid
    /// until handle deinit; data, interim and trailer views are callback-scoped.
    pub fn readResponse(self: *Handle, sink: ResponseSink) !ResponseHead {
        return self.readResponseBefore(sink, null);
    }

    /// Stream the final response under one absolute awake-clock deadline.
    pub fn readResponseWithDeadline(
        self: *Handle,
        sink: ResponseSink,
        deadline: std.Io.Clock.Timestamp,
    ) !ResponseHead {
        return self.readResponseBefore(sink, deadline);
    }

    pub fn readResponseWithTimeout(self: *Handle, sink: ResponseSink, timeout: std.Io.Duration) !ResponseHead {
        return self.readResponseWithDeadline(sink, (try @import("../../internal/deadline.zig").fromTimeout(upload.io(self), timeout)).?);
    }

    fn readResponseBefore(
        self: *Handle,
        sink: ResponseSink,
        deadline: ?std.Io.Clock.Timestamp,
    ) !ResponseHead {
        if (self.response_complete) return self.response_head orelse error.MissingResponseHead;
        if (self.h1_buffered_response) |response| {
            return self.emitBufferedResponse(response, sink);
        }
        var context = ResponseContext{ .handle = self, .sink = sink };
        switch (self.state) {
            .http1 => |*writer| {
                const observer: ?http1_runtime.InformationalObserver =
                    if (sink.informational != null) .{
                        .context = &context,
                        .on_response = observeInformationalHttp1,
                    } else null;
                var response = if (deadline) |absolute|
                    try writer.readResponseStreamingWithInformationalAndHeadAndDeadline(
                        observer,
                        absolute,
                        &context,
                        beginHttp1,
                        consumeResponse,
                    )
                else
                    try writer.readResponseStreamingWithInformationalAndHead(
                        observer,
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
                const observer: ?http2_runtime.InformationalObserver =
                    if (sink.informational != null) .{
                        .context = &context,
                        .on_response = observeInformationalHttp2,
                    } else null;
                var response = if (deadline) |absolute|
                    try writer.readResponseStreamingWithInformationalAndHeadAndDeadline(
                        observer,
                        absolute,
                        &context,
                        beginHttp2,
                        consumeResponse,
                    )
                else
                    try writer.readResponseStreamingWithInformationalAndHead(
                        observer,
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
                return self.readResponseHttp3(h3, sink, deadline);
            },
        }
        self.response_complete = true;
        return self.response_head orelse error.MissingResponseHead;
    }

    fn emitBufferedResponse(
        self: *Handle,
        response: http1_runtime.OwnedResponse,
        sink: ResponseSink,
    ) !ResponseHead {
        const headers = try copyHeaders1(
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
        self.response_complete = true;
        return head;
    }

    fn readResponseHttp3(
        self: *Handle,
        h3: *const Http3,
        sink: ResponseSink,
        deadline: ?std.Io.Clock.Timestamp,
    ) !ResponseHead {
        var trailers: ?http3.DecodedTrailers = null;
        defer if (trailers) |*value| value.deinit(self.allocator);

        var pending = self.h3_pending_event;
        self.h3_pending_event = null;
        defer if (pending) |*event| event.deinit(self.allocator);
        var use_pending = pending != null;

        while (true) {
            var event = if (self.h3_pending_interims.popFront()) |interim|
                interim
            else if (use_pending) blk: {
                use_pending = false;
                const value = pending.?;
                pending = null;
                break :blk value;
            } else blk: {
                const received = if (deadline) |absolute|
                    try h3.client.receiveResponseEventWithDeadline(
                        h3.stream_id,
                        absolute,
                    )
                else
                    try h3.client.receiveResponseEvent(h3.stream_id);
                break :blk received orelse continue;
            };
            defer event.deinit(self.allocator);
            switch (event) {
                .head => |head| switch (head) {
                    .request => return error.InvalidResponse,
                    .response => |response| {
                        if (response.status < 200) {
                            if (sink.informational) |callback| {
                                const mapped = try mapHeaders3(
                                    self.allocator,
                                    response.headers,
                                );
                                defer self.allocator.free(mapped);
                                callback(sink.context, .{
                                    .protocol = .http3,
                                    .status = response.status,
                                    .headers = mapped,
                                });
                            }
                            continue;
                        }
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
                    self.response_complete = true;
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
        self.h3_response_metadata = .{ .body_allowed = response.body_allowed, .consumed = response.consumed, .qpack_section_acknowledgments = response.qpack_section_acknowledgments };
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

    fn observeInformationalHttp1(
        context: *anyopaque,
        head: http1_runtime.InformationalResponseHead,
    ) void {
        const self: *ResponseContext = @ptrCast(@alignCast(context));
        const callback = self.sink.informational orelse return;
        const mapped = mapHeaders1(
            self.handle.allocator,
            head.headers,
        ) catch return;
        defer self.handle.allocator.free(mapped);
        callback(self.sink.context, .{
            .protocol = .http1,
            .status = head.status,
            .headers = mapped,
        });
    }

    fn observeInformationalHttp2(
        context: *anyopaque,
        head: http2_runtime.StreamingResponseHead,
    ) void {
        const self: *ResponseContext = @ptrCast(@alignCast(context));
        const callback = self.sink.informational orelse return;
        const mapped = mapHeaders2(
            self.handle.allocator,
            head.headers,
        ) catch return;
        defer self.handle.allocator.free(mapped);
        callback(self.sink.context, .{
            .protocol = .http2,
            .status = head.status,
            .headers = mapped,
        });
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
/// The client must not be bound to a pool dispatcher. Pooled streams use
/// `Pool.startRequest` and retain their dispatcher-owned command channel.
pub fn startHttp3(
    allocator: std.mem.Allocator,
    client: *http3_runtime.HandshakeClient,
    request: http3.Request,
    body_length: ?usize,
) !Handle {
    const stream_id = try client.startRequest(request, body_length);
    return Handle.initHttp3(allocator, client, stream_id);
}

pub fn startHttp3WithDeadline(allocator: std.mem.Allocator, client: *http3_runtime.HandshakeClient, request: http3.Request, body_length: ?usize, deadline: std.Io.Clock.Timestamp) !Handle {
    const stream_id = try client.startRequestWithDeadline(request, body_length, deadline);
    return Handle.initHttp3(allocator, client, stream_id);
}

pub fn startHttp3WithTimeout(allocator: std.mem.Allocator, client: *http3_runtime.HandshakeClient, request: http3.Request, body_length: ?usize, timeout: std.Io.Duration) !Handle {
    const stream_id = try client.startRequestWithTimeout(request, body_length, timeout);
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
        target.* = .{ .name = source.name, .value = source.value, .never_indexed = source.never_index };
    }
    return result;
}

fn mapHeaders3(
    allocator: std.mem.Allocator,
    headers: []const http3.Qpack.HeaderField,
) ![]Header {
    const result = try allocator.alloc(Header, headers.len);
    for (headers, result) |source, *target| {
        target.* = .{ .name = source.name, .value = source.value, .never_indexed = source.never_indexed };
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
        target.* = .{ .name = name, .value = value, .never_indexed = if (comptime @hasField(@TypeOf(source), "never_indexed")) source.never_indexed else false };
    }
    headers_out.* = result;
    storage_out.* = storage;
    return result;
}
