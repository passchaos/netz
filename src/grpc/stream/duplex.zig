//! Step-driven, single-owner gRPC streams over HTTP/2.
//!
//! A duplex value is the only code allowed to read frames from its HTTP/2
//! connection while it is alive.  Message callbacks therefore run inline with
//! `read*Event`; their payload is borrowed only for that callback.  This avoids
//! a background reader, cross-thread queues, and accidental use of DATA storage
//! after the owning HTTP/2 event has been released.

const std = @import("std");
const http2 = @import("../../http2/mod.zig");
const call = @import("../call.zig");
const compression = @import("../compression.zig");
const metadata = @import("../metadata.zig");
const wire = @import("../wire.zig");
const codec = @import("codec.zig");
const sequential = @import("runtime.zig");

pub const Error = sequential.Error;
pub const RequestOptions = sequential.RequestOptions;
pub const ResponseOptions = sequential.ResponseOptions;

/// A write stopped only at a precisely reported wire-byte boundary.
///
/// On `peer_event`, the duplex object retains the unsent suffix.  The caller
/// must drive the peer event(s), then call `resumeMessage`; it must not submit
/// the logical message again because a prefix of it may already be on the wire.
pub const WriteResult = enum { complete, peer_event };

pub const MessageProgress = struct {
    count: usize,
    end_stream: bool,
};

/// Initial response metadata borrowed from `ClientDuplex`.
///
/// It remains valid until the terminal event is taken or the duplex is
/// deinitialized. Reading DATA events does not invalidate it; the terminal
/// event takes ownership of the same metadata.
pub const ResponseHead = struct {
    status: u16,
    headers: []const http2.Hpack.HeaderField,
    encoding: ?[]const u8,
};

/// Owned terminal response.  A reset is represented in the same value as a
/// trailers status, so applications cannot accidentally discard its typed gRPC
/// mapping while handling the HTTP/2 reason separately.
pub const Response = struct {
    allocator: std.mem.Allocator,
    head: ?http2.runtime.DuplexResponseHead = null,
    trailers: ?[]http2.Hpack.HeaderField = null,
    reset: ?http2.ResetStreamPayload = null,
    status: wire.Status,
    status_message: []u8,
    encoding: ?[]const u8 = null,

    pub fn deinit(self: *Response) void {
        self.allocator.free(self.status_message);
        if (self.head) |*head| head.deinit(self.allocator);
        if (self.trailers) |trailers| {
            http2.Hpack.freeOwnedFields(self.allocator, trailers);
        }
        self.* = undefined;
    }
};

pub const ClientEvent = union(enum) {
    /// Owned informational HTTP metadata.  Call `deinit` after inspection.
    informational: http2.runtime.DuplexResponseHead,
    /// Borrowed initial gRPC metadata.  See `ResponseHead` for its lifetime.
    initial_metadata: ResponseHead,
    /// Number of complete messages delivered by this transport step.
    messages: MessageProgress,
    /// Owned terminal status, delivered exactly once.
    terminal: Response,

    pub fn deinit(self: *ClientEvent, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .informational => |*head| head.deinit(allocator),
            .terminal => |*response| response.deinit(),
            .initial_metadata, .messages => {},
        }
        self.* = undefined;
    }
};

const PendingMessage = struct {
    bytes: []u8,
    offset: usize = 0,

    fn deinit(self: *PendingMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const ClientDuplex = struct {
    allocator: std.mem.Allocator,
    transport: http2.runtime.ClientDuplexStream,
    encoder: codec.Encoder,
    accepted_encodings: compression.AlgorithmSet,
    max_message_size: usize,
    decoder: ?codec.Decoder = null,
    response_head: ?http2.runtime.DuplexResponseHead = null,
    response_encoding: ?[]const u8 = null,
    parse_response_body: bool = false,
    pending_message: ?PendingMessage = null,
    pending_terminal: ?Response = null,
    terminal_delivered: bool = false,

    pub fn deinit(self: *ClientDuplex) void {
        if (self.decoder) |*decoder| decoder.deinit();
        if (self.response_head) |*head| head.deinit(self.allocator);
        if (self.pending_message) |*pending| pending.deinit(self.allocator);
        if (self.pending_terminal) |*response| response.deinit();
        self.transport.deinit();
        self.* = undefined;
    }

    pub fn streamId(self: ClientDuplex) u31 {
        return self.transport.streamId();
    }

    pub fn requestFinished(self: ClientDuplex) bool {
        return self.transport.requestFinished();
    }

    /// Encode and begin one message.  At most one partially written message is
    /// retained, keeping retries unambiguous and byte-exact.
    pub fn writeMessage(
        self: *ClientDuplex,
        payload: []const u8,
    ) Error!WriteResult {
        if (self.pending_message != null) return error.InvalidStreamState;
        if (self.terminal_delivered or self.pending_terminal != null or
            self.transport.responseFinished())
        {
            return error.ConnectionClosed;
        }
        self.pending_message = .{
            .bytes = try encodeMessageAlloc(self.allocator, self.encoder, payload),
        };
        return self.resumeMessage();
    }

    /// Continue the exact unsent suffix after a response event interrupted a
    /// flow-control-blocked write.
    pub fn resumeMessage(self: *ClientDuplex) Error!WriteResult {
        if (self.terminal_delivered or self.pending_terminal != null or
            self.transport.responseFinished())
        {
            return error.ConnectionClosed;
        }
        const pending = if (self.pending_message) |*value| value else return error.InvalidStreamState;
        const result = self.transport.write(pending.bytes[pending.offset..]) catch |err| {
            if (err == error.StreamReset) return .peer_event;
            return err;
        };
        pending.offset += result.written;
        if (pending.offset == pending.bytes.len) {
            pending.deinit(self.allocator);
            self.pending_message = null;
            return .complete;
        }
        if (!result.response_available) return error.InvalidStreamState;
        return .peer_event;
    }

    pub fn finishRequest(self: *ClientDuplex) Error!WriteResult {
        if (self.pending_message != null) return error.InvalidStreamState;
        if (self.terminal_delivered or self.pending_terminal != null or
            self.transport.responseFinished())
        {
            return error.ConnectionClosed;
        }
        const result = self.transport.finishRequest() catch |err| {
            if (err == error.StreamReset) return .peer_event;
            return err;
        };
        return if (result.response_available) .peer_event else .complete;
    }

    pub fn reset(self: *ClientDuplex, code: http2.ErrorCode) Error!void {
        try self.transport.reset(code);
    }

    pub fn readResponseEvent(
        self: *ClientDuplex,
        context: anytype,
        comptime consume: anytype,
    ) !ClientEvent {
        return self.readResponseEventUntil(null, context, consume);
    }

    pub fn readResponseEventWithTimeout(
        self: *ClientDuplex,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !ClientEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseEventUntil(.fromNow(
            self.transport.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ), context, consume);
    }

    pub fn readResponseEventWithDeadline(
        self: *ClientDuplex,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !ClientEvent {
        return self.readResponseEventUntil(deadline, context, consume);
    }

    fn readResponseEventUntil(
        self: *ClientDuplex,
        deadline: ?std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !ClientEvent {
        if (self.pending_terminal) |response| {
            self.pending_terminal = null;
            self.terminal_delivered = true;
            return .{ .terminal = response };
        }
        if (self.terminal_delivered) return error.ConnectionClosed;

        var event = try readClientTransportEvent(&self.transport, deadline);
        switch (event) {
            .informational => |head| {
                event = undefined;
                return .{ .informational = head };
            },
            .head => |head| {
                event = undefined;
                try self.beginResponse(head);
                if (!self.transport.responseFinished()) {
                    const stored = self.response_head.?;
                    return .{ .initial_metadata = .{
                        .status = stored.status,
                        .headers = stored.headers,
                        .encoding = self.response_encoding,
                    } };
                }
                try self.finishResponseDecoder();
                try self.consumeTransportFinished(deadline);
                const response = try self.takeTerminal(null);
                self.closeRequestAfterTerminal() catch {};
                self.terminal_delivered = true;
                return .{ .terminal = response };
            },
            .data => |*data| {
                var delivered: usize = 0;
                const Counter = MessageCounter(@TypeOf(context), consume);
                var counter = Counter{
                    .context = context,
                    .count = &delivered,
                };
                if (self.parse_response_body) {
                    const decoder = if (self.decoder) |*value| value else return error.InvalidStreamState;
                    decoder.feed(data.data, &counter, Counter.deliver) catch |err| {
                        event.deinit(self.allocator);
                        self.transport.reset(.internal_error) catch {};
                        return err;
                    };
                }
                event.deinit(self.allocator);
                const ended = self.transport.responseFinished();
                if (ended) {
                    try self.finishResponseDecoder();
                    try self.consumeTransportFinished(deadline);
                    const response = try self.takeTerminal(null);
                    self.closeRequestAfterTerminal() catch {};
                    if (delivered == 0) {
                        self.terminal_delivered = true;
                        return .{ .terminal = response };
                    }
                    self.pending_terminal = response;
                }
                return .{ .messages = .{
                    .count = delivered,
                    .end_stream = ended,
                } };
            },
            .trailers => |trailers| {
                event = undefined;
                var trailers_owned = true;
                errdefer if (trailers_owned) {
                    http2.Hpack.freeOwnedFields(self.allocator, trailers);
                };
                try self.finishResponseDecoder();
                try self.consumeTransportFinished(deadline);
                const response = try self.takeTerminal(trailers);
                trailers_owned = false;
                self.closeRequestAfterTerminal() catch {};
                self.terminal_delivered = true;
                return .{ .terminal = response };
            },
            .finished => return error.InvalidStreamState,
            .reset => |reset_value| {
                event = undefined;
                self.discardPendingMessage();
                self.terminal_delivered = true;
                return .{ .terminal = try self.takeResetTerminal(reset_value) };
            },
        }
    }

    fn beginResponse(
        self: *ClientDuplex,
        head: http2.runtime.DuplexResponseHead,
    ) Error!void {
        if (self.response_head != null) return error.InvalidStreamState;
        errdefer {
            var owned = head;
            owned.deinit(self.allocator);
        }
        const content_type = call.headerValue(head.headers, "content-type");
        const status_raw = call.headerValue(head.headers, "grpc-status");
        const grpc_content_type = content_type != null and
            wire.isContentType(content_type.?);
        self.parse_response_body = grpc_content_type and
            (head.status == 200 or status_raw != null);
        if ((head.status == 200 or status_raw != null) and !grpc_content_type) {
            return error.InvalidContentType;
        }
        self.response_encoding = call.headerValue(head.headers, "grpc-encoding");
        if (self.parse_response_body) {
            self.decoder = try codec.Decoder.init(
                self.allocator,
                self.max_message_size,
                self.response_encoding,
                self.accepted_encodings,
            );
        }
        self.response_head = head;
    }

    fn finishResponseDecoder(self: *ClientDuplex) Error!void {
        if (!self.parse_response_body) return;
        const decoder = if (self.decoder) |*value| value else return error.InvalidStreamState;
        decoder.finish() catch |err| {
            self.transport.reset(.internal_error) catch {};
            return err;
        };
    }

    fn closeRequestAfterTerminal(self: *ClientDuplex) Error!void {
        self.discardPendingMessage();
        if (!self.transport.requestFinished()) {
            try self.transport.closeRequestAfterResponse();
        }
    }

    fn consumeTransportFinished(
        self: *ClientDuplex,
        deadline: ?std.Io.Clock.Timestamp,
    ) !void {
        var event = try readClientTransportEvent(&self.transport, deadline);
        defer event.deinit(self.allocator);
        if (event != .finished) return error.InvalidStreamState;
    }

    fn takeTerminal(
        self: *ClientDuplex,
        trailers: ?[]http2.Hpack.HeaderField,
    ) Error!Response {
        const head = self.response_head orelse return error.InvalidStreamState;
        const parsed = sequential.parseResponseTerminal(
            self.allocator,
            head.status,
            head.headers,
            trailers orelse &.{},
            self.response_encoding,
        ) catch |err| {
            if (trailers) |fields| http2.Hpack.freeOwnedFields(self.allocator, fields);
            return err;
        };
        self.response_head = null;
        return .{
            .allocator = self.allocator,
            .head = head,
            .trailers = trailers,
            .status = parsed.status,
            .status_message = parsed.status_message,
            .encoding = parsed.encoding,
        };
    }

    fn takeResetTerminal(
        self: *ClientDuplex,
        reset_value: http2.ResetStreamPayload,
    ) Error!Response {
        const head = self.response_head;
        const status_message = try call.resetStatusMessageAlloc(
            self.allocator,
            reset_value.error_code,
        );
        self.response_head = null;
        return .{
            .allocator = self.allocator,
            .head = head,
            .reset = reset_value,
            .status = call.statusFromHttp2Error(reset_value.error_code),
            .status_message = status_message,
            .encoding = self.response_encoding,
        };
    }

    fn discardPendingMessage(self: *ClientDuplex) void {
        if (self.pending_message) |*pending| pending.deinit(self.allocator);
        self.pending_message = null;
    }
};

pub fn startDuplex(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    options: RequestOptions,
) Error!ClientDuplex {
    return .{
        .allocator = allocator,
        .transport = try sequential.startClientDuplexTransport(
            connection,
            allocator,
            options,
        ),
        .encoder = .{
            .allocator = allocator,
            .algorithm = options.compression,
            .compression_level = options.compression_level,
            .max_message_size = options.max_message_size,
        },
        .accepted_encodings = options.accepted_encodings,
        .max_message_size = options.max_message_size,
    };
}

pub const RequestTerminal = struct {
    allocator: std.mem.Allocator,
    trailers: ?[]http2.Hpack.HeaderField = null,
    message_count: usize,

    pub fn deinit(self: *RequestTerminal) void {
        if (self.trailers) |trailers| {
            http2.Hpack.freeOwnedFields(self.allocator, trailers);
        }
        self.* = undefined;
    }
};

pub const ServerEvent = union(enum) {
    messages: MessageProgress,
    finished: RequestTerminal,
    reset: http2.ResetStreamPayload,

    pub fn deinit(self: *ServerEvent) void {
        switch (self.*) {
            .finished => |*terminal| terminal.deinit(),
            .messages, .reset => {},
        }
        self.* = undefined;
    }
};

pub const ServerDuplex = struct {
    allocator: std.mem.Allocator,
    transport: http2.runtime.ServerDuplexStream,
    decoder: codec.Decoder,
    response_encoder: ?codec.Encoder = null,
    pending_message: ?PendingMessage = null,
    pending_terminal: ?RequestTerminal = null,
    terminal_delivered: bool = false,
    path: []const u8,
    service: []const u8,
    method: []const u8,
    timeout: ?wire.Timeout,
    encoding: ?[]const u8,
    accepted_encodings: compression.AlgorithmSet,
    message_count: usize = 0,

    pub fn deinit(self: *ServerDuplex) void {
        self.decoder.deinit();
        if (self.pending_message) |*pending| pending.deinit(self.allocator);
        if (self.pending_terminal) |*terminal| terminal.deinit();
        self.transport.deinit();
        self.* = undefined;
    }

    pub fn streamId(self: ServerDuplex) u31 {
        return self.transport.stream_id;
    }

    pub fn requestFinished(self: ServerDuplex) bool {
        return self.transport.requestFinished();
    }

    pub fn responseFinished(self: ServerDuplex) bool {
        return self.transport.responseFinished();
    }

    pub fn readRequestEvent(
        self: *ServerDuplex,
        context: anytype,
        comptime consume: anytype,
    ) !ServerEvent {
        return self.readRequestEventUntil(null, context, consume);
    }

    pub fn readRequestEventWithTimeout(
        self: *ServerDuplex,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !ServerEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readRequestEventUntil(.fromNow(
            self.transport.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ), context, consume);
    }

    pub fn readRequestEventWithDeadline(
        self: *ServerDuplex,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !ServerEvent {
        return self.readRequestEventUntil(deadline, context, consume);
    }

    fn readRequestEventUntil(
        self: *ServerDuplex,
        deadline: ?std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !ServerEvent {
        if (self.pending_terminal) |terminal| {
            self.pending_terminal = null;
            self.terminal_delivered = true;
            return .{ .finished = terminal };
        }
        if (self.terminal_delivered) return error.ConnectionClosed;

        var event = try readServerTransportEvent(&self.transport, deadline);
        switch (event) {
            .data => |*data| {
                var delivered: usize = 0;
                const Counter = MessageCounter(@TypeOf(context), consume);
                var counter = Counter{
                    .context = context,
                    .count = &delivered,
                };
                self.decoder.feed(data.data, &counter, Counter.deliver) catch |err| {
                    event.deinit(self.allocator);
                    self.transport.reset(.internal_error) catch {};
                    return err;
                };
                event.deinit(self.allocator);
                self.message_count = std.math.add(
                    usize,
                    self.message_count,
                    delivered,
                ) catch return error.MessageTooLarge;
                const ended = self.transport.requestFinished();
                if (ended) {
                    try self.finishRequestDecoder();
                    try self.consumeRequestFinished(deadline);
                    const terminal = RequestTerminal{
                        .allocator = self.allocator,
                        .message_count = self.message_count,
                    };
                    if (delivered == 0) {
                        self.terminal_delivered = true;
                        return .{ .finished = terminal };
                    }
                    self.pending_terminal = terminal;
                }
                return .{ .messages = .{
                    .count = delivered,
                    .end_stream = ended,
                } };
            },
            .trailers => |trailers| {
                event = undefined;
                var trailers_owned = true;
                errdefer if (trailers_owned) {
                    http2.Hpack.freeOwnedFields(self.allocator, trailers);
                };
                try self.finishRequestDecoder();
                try self.consumeRequestFinished(deadline);
                self.terminal_delivered = true;
                trailers_owned = false;
                return .{ .finished = .{
                    .allocator = self.allocator,
                    .trailers = trailers,
                    .message_count = self.message_count,
                } };
            },
            .finished => {
                event = undefined;
                try self.finishRequestDecoder();
                self.terminal_delivered = true;
                return .{ .finished = .{
                    .allocator = self.allocator,
                    .message_count = self.message_count,
                } };
            },
            .reset => |reset_value| {
                event = undefined;
                self.discardPendingMessage();
                self.terminal_delivered = true;
                return .{ .reset = reset_value };
            },
        }
    }

    pub fn startResponse(
        self: *ServerDuplex,
        options: ResponseOptions,
    ) Error!void {
        if (self.response_encoder != null) return error.InvalidStreamState;
        try sequential.startDuplexResponse(
            &self.transport,
            self.allocator,
            options,
        );
        const algorithm = negotiatedResponseAlgorithm(options);
        self.response_encoder = .{
            .allocator = self.allocator,
            .algorithm = algorithm,
            .compression_level = options.compression_level,
            .max_message_size = options.max_message_size,
        };
    }

    pub fn writeMessage(
        self: *ServerDuplex,
        payload: []const u8,
    ) Error!WriteResult {
        if (self.pending_message != null) return error.InvalidStreamState;
        if (self.transport.responseFinished()) return error.ConnectionClosed;
        const encoder = self.response_encoder orelse
            return error.InvalidStreamState;
        self.pending_message = .{
            .bytes = try encodeMessageAlloc(self.allocator, encoder, payload),
        };
        return self.resumeMessage();
    }

    pub fn resumeMessage(self: *ServerDuplex) Error!WriteResult {
        if (self.transport.responseFinished()) return error.ConnectionClosed;
        const pending = if (self.pending_message) |*value| value else return error.InvalidStreamState;
        const result = self.transport.writeResponse(
            pending.bytes[pending.offset..],
        ) catch |err| {
            if (err == error.StreamReset) return .peer_event;
            return err;
        };
        pending.offset += result.written;
        if (pending.offset == pending.bytes.len) {
            pending.deinit(self.allocator);
            self.pending_message = null;
            return .complete;
        }
        if (!result.response_available) return error.InvalidStreamState;
        return .peer_event;
    }

    /// Finish with gRPC status.  Before `startResponse` this emits a true
    /// trailers-only HEADERS block; afterwards it emits trailing HEADERS.
    pub fn finish(
        self: *ServerDuplex,
        status: wire.Status,
        status_message: ?[]const u8,
        trailing_metadata: []const http2.Hpack.HeaderField,
        trailing_binary_metadata: []const metadata.BinaryMetadata,
    ) Error!void {
        if (self.pending_message != null) return error.InvalidStreamState;
        if (self.response_encoder == null) {
            try sequential.finishDuplexHeadersOnly(
                &self.transport,
                self.allocator,
                status,
                status_message,
                trailing_metadata,
                trailing_binary_metadata,
            );
        } else {
            try sequential.finishDuplexTrailers(
                &self.transport,
                self.allocator,
                status,
                status_message,
                trailing_metadata,
                trailing_binary_metadata,
            );
        }
    }

    pub fn finishOk(self: *ServerDuplex) Error!void {
        return self.finish(.ok, null, &.{}, &.{});
    }

    pub fn reset(self: *ServerDuplex, code: http2.ErrorCode) Error!void {
        try self.transport.reset(code);
    }

    fn finishRequestDecoder(self: *ServerDuplex) Error!void {
        self.decoder.finish() catch |err| {
            self.transport.reset(.internal_error) catch {};
            return err;
        };
    }

    fn consumeRequestFinished(
        self: *ServerDuplex,
        deadline: ?std.Io.Clock.Timestamp,
    ) !void {
        var event = try readServerTransportEvent(&self.transport, deadline);
        defer event.deinit(self.allocator);
        if (event != .finished) return error.InvalidStreamState;
    }

    fn discardPendingMessage(self: *ServerDuplex) void {
        if (self.pending_message) |*pending| pending.deinit(self.allocator);
        self.pending_message = null;
    }
};

pub fn acceptDuplex(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    max_message_size: usize,
) Error!ServerDuplex {
    return acceptDuplexTransport(
        try connection.acceptDuplexRequest(),
        allocator,
        max_message_size,
    );
}

pub fn acceptDuplexWithTimeout(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    max_message_size: usize,
    timeout: std.Io.Duration,
) !ServerDuplex {
    return acceptDuplexTransport(
        try connection.acceptDuplexRequestWithTimeout(timeout),
        allocator,
        max_message_size,
    );
}

pub fn acceptDuplexWithDeadline(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    max_message_size: usize,
    deadline: std.Io.Clock.Timestamp,
) !ServerDuplex {
    return acceptDuplexTransport(
        try connection.acceptDuplexRequestWithDeadline(deadline),
        allocator,
        max_message_size,
    );
}

fn acceptDuplexTransport(
    transport_value: http2.runtime.ServerDuplexStream,
    allocator: std.mem.Allocator,
    max_message_size: usize,
) Error!ServerDuplex {
    var transport = transport_value;
    errdefer transport.deinit();
    const parsed = try call.parseRequestMetadata(
        transport.method,
        transport.path,
        transport.headers,
    );
    return .{
        .allocator = allocator,
        .transport = transport,
        .decoder = try codec.Decoder.init(
            allocator,
            max_message_size,
            parsed.encoding,
            compression.AlgorithmSet.supported,
        ),
        .path = parsed.path,
        .service = parsed.service,
        .method = parsed.method,
        .timeout = parsed.timeout,
        .encoding = parsed.encoding,
        .accepted_encodings = parsed.accepted_encodings,
    };
}

fn MessageCounter(comptime Context: type, comptime consume: anytype) type {
    return struct {
        context: Context,
        count: *usize,

        fn deliver(self: *@This(), message: codec.DecodedMessage) !void {
            try consume(self.context, message);
            self.count.* += 1;
        }
    };
}

fn encodeMessageAlloc(
    allocator: std.mem.Allocator,
    encoder: codec.Encoder,
    payload: []const u8,
) Error![]u8 {
    var encoded: std.ArrayList(u8) = .empty;
    errdefer encoded.deinit(allocator);
    try encoder.appendMessage(&encoded, payload);
    return encoded.toOwnedSlice(allocator);
}

fn readClientTransportEvent(
    transport: *http2.runtime.ClientDuplexStream,
    deadline: ?std.Io.Clock.Timestamp,
) !http2.runtime.DuplexResponseEvent {
    return if (deadline) |value|
        transport.readResponseEventWithDeadline(value)
    else
        transport.readResponseEvent();
}

fn readServerTransportEvent(
    transport: *http2.runtime.ServerDuplexStream,
    deadline: ?std.Io.Clock.Timestamp,
) !http2.runtime.DuplexRequestEvent {
    return if (deadline) |value|
        transport.readRequestEventWithDeadline(value)
    else
        transport.readRequestEvent();
}

fn negotiatedResponseAlgorithm(
    options: ResponseOptions,
) compression.Algorithm {
    return if (options.request_accepted_encodings.contains(options.compression))
        options.compression
    else
        .identity;
}
