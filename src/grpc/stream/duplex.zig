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

const ReceiveState = enum {
    active,
    terminal_pending,
    terminal_delivered,
    failed,
};

fn ownResponseHead(
    allocator: std.mem.Allocator,
    status: u16,
    headers: []const http2.Hpack.HeaderField,
) !http2.runtime.DuplexResponseHead {
    return .{
        .status = status,
        .headers = try cloneHeaders(allocator, headers),
    };
}

fn cloneHeaders(
    allocator: std.mem.Allocator,
    headers: []const http2.Hpack.HeaderField,
) ![]http2.Hpack.HeaderField {
    var total_bytes: usize = 0;
    for (headers) |header| {
        total_bytes = std.math.add(
            usize,
            total_bytes,
            std.math.add(usize, header.name.len, header.value.len) catch
                return error.MessageTooLarge,
        ) catch return error.MessageTooLarge;
    }
    const fields = try allocator.alloc(http2.Hpack.HeaderField, headers.len);
    errdefer allocator.free(fields);
    const storage = try allocator.alloc(u8, total_bytes);
    errdefer allocator.free(storage);
    var cursor: usize = 0;
    for (headers, 0..) |header, index| {
        const name = storage[cursor..][0..header.name.len];
        @memcpy(name, header.name);
        cursor += header.name.len;
        const value = storage[cursor..][0..header.value.len];
        @memcpy(value, header.value);
        cursor += header.value.len;
        fields[index] = .{
            .name = name,
            .value = value,
            .never_index = header.never_index,
            .block_storage = if (index == 0) storage else null,
        };
    }
    if (headers.len == 0) allocator.free(storage);
    return fields;
}

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
    receive_state: ReceiveState = .active,

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
        try self.ensureWritable();
        if (self.pending_message != null) return error.InvalidStreamState;
        self.pending_message = .{
            .bytes = try encodeMessageAlloc(self.allocator, self.encoder, payload),
        };
        return self.resumeMessage();
    }

    /// Continue the exact unsent suffix after a response event interrupted a
    /// flow-control-blocked write.
    pub fn resumeMessage(self: *ClientDuplex) Error!WriteResult {
        try self.ensureWritable();
        const pending = if (self.pending_message) |*value| value else return error.InvalidStreamState;
        const result = self.transport.write(pending.bytes[pending.offset..]) catch |err| {
            // Only a successful `response_available` result has a precise,
            // resumable byte count. Any transport error can have unknown wire
            // progress, so retrying would risk duplicating message bytes.
            self.fail(.internal_error);
            return err;
        };
        if (result.written > pending.bytes.len - pending.offset) {
            self.fail(.internal_error);
            return error.InvalidStreamState;
        }
        pending.offset = std.math.add(usize, pending.offset, result.written) catch {
            self.fail(.internal_error);
            return error.InvalidStreamState;
        };
        if (pending.offset == pending.bytes.len) {
            pending.deinit(self.allocator);
            self.pending_message = null;
            return .complete;
        }
        if (!result.response_available) {
            self.fail(.internal_error);
            return error.InvalidStreamState;
        }
        return .peer_event;
    }

    pub fn finishRequest(self: *ClientDuplex) Error!WriteResult {
        try self.ensureWritable();
        if (self.pending_message != null) return error.InvalidStreamState;
        const result = self.transport.finishRequest() catch |err| {
            self.fail(.internal_error);
            return err;
        };
        return if (result.response_available) .peer_event else .complete;
    }

    pub fn reset(self: *ClientDuplex, code: http2.ErrorCode) Error!void {
        if (self.receive_state == .failed or
            self.receive_state == .terminal_delivered)
        {
            return error.ConnectionClosed;
        }
        self.discardReceiveState();
        self.receive_state = .failed;
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
        return self.readResponseEventWithDeadline(
            .fromNow(self.transport.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
            context,
            consume,
        );
    }

    pub fn readResponseEventWithDeadline(
        self: *ClientDuplex,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !ClientEvent {
        if (self.pending_terminal) |response| {
            self.pending_terminal = null;
            self.receive_state = .terminal_delivered;
            return .{ .terminal = response };
        }
        if (self.receive_state != .active) return error.ConnectionClosed;
        const event = self.transport.readResponseEventWithDeadline(
            deadline,
        ) catch |err| {
            if (err != error.Timeout) self.fail(.internal_error);
            return err;
        };
        return self.readResponseEventTransport(
            event,
            deadline,
            context,
            consume,
        );
    }

    fn readResponseEventUntil(
        self: *ClientDuplex,
        deadline: ?std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !ClientEvent {
        if (self.pending_terminal) |response| {
            self.pending_terminal = null;
            self.receive_state = .terminal_delivered;
            return .{ .terminal = response };
        }
        if (self.receive_state != .active) return error.ConnectionClosed;
        const event = readClientTransportEvent(
            &self.transport,
            deadline,
        ) catch |err| {
            if (err != error.Timeout) self.fail(.internal_error);
            return err;
        };
        return self.readResponseEventTransport(
            event,
            deadline,
            context,
            consume,
        );
    }

    fn readResponseEventTransport(
        self: *ClientDuplex,
        transport_event: http2.runtime.DuplexResponseEvent,
        deadline: ?std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !ClientEvent {
        if (self.pending_terminal != null or self.receive_state != .active) {
            var unused = transport_event;
            unused.deinit(self.allocator);
            return error.ConnectionClosed;
        }
        var event = transport_event;
        switch (event) {
            .informational => |head| {
                event = undefined;
                return .{ .informational = head };
            },
            .head => |head| {
                event = undefined;
                self.beginResponse(head) catch |err| {
                    self.fail(.internal_error);
                    return err;
                };
                if (!self.transport.responseFinished()) {
                    const stored = self.response_head.?;
                    return .{ .initial_metadata = .{
                        .status = stored.status,
                        .headers = stored.headers,
                        .encoding = self.response_encoding,
                    } };
                }
                self.finishResponseDecoder() catch |err| {
                    self.fail(.internal_error);
                    return err;
                };
                self.consumeTransportFinished(deadline) catch |err| {
                    self.fail(.internal_error);
                    return err;
                };
                const response = self.takeTerminal(null) catch |err| {
                    self.fail(.internal_error);
                    return err;
                };
                self.closeRequestAfterTerminal() catch {};
                self.receive_state = .terminal_delivered;
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
                    const decoder = if (self.decoder) |*value| value else {
                        event.deinit(self.allocator);
                        self.fail(.internal_error);
                        return error.InvalidStreamState;
                    };
                    decoder.feed(data.data, &counter, Counter.deliver) catch |err| {
                        event.deinit(self.allocator);
                        self.fail(.internal_error);
                        return err;
                    };
                }
                event.deinit(self.allocator);
                const ended = self.transport.responseFinished();
                if (ended) {
                    self.finishResponseDecoder() catch |err| {
                        self.fail(.internal_error);
                        return err;
                    };
                    self.consumeTransportFinished(deadline) catch |err| {
                        self.fail(.internal_error);
                        return err;
                    };
                    const response = self.takeTerminal(null) catch |err| {
                        self.fail(.internal_error);
                        return err;
                    };
                    self.closeRequestAfterTerminal() catch {};
                    if (delivered == 0) {
                        self.receive_state = .terminal_delivered;
                        return .{ .terminal = response };
                    }
                    self.pending_terminal = response;
                    self.receive_state = .terminal_pending;
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
                self.finishResponseDecoder() catch |err| {
                    self.fail(.internal_error);
                    return err;
                };
                self.consumeTransportFinished(deadline) catch |err| {
                    self.fail(.internal_error);
                    return err;
                };
                const response = self.takeTerminal(trailers) catch |err| {
                    self.fail(.internal_error);
                    return err;
                };
                trailers_owned = false;
                self.closeRequestAfterTerminal() catch {};
                self.receive_state = .terminal_delivered;
                return .{ .terminal = response };
            },
            .finished => {
                event = undefined;
                self.finishResponseDecoder() catch |err| {
                    self.fail(.internal_error);
                    return err;
                };
                const response = self.takeTerminal(null) catch |err| {
                    self.fail(.internal_error);
                    return err;
                };
                self.closeRequestAfterTerminal() catch {};
                self.receive_state = .terminal_delivered;
                return .{ .terminal = response };
            },
            .reset => |reset_value| {
                event = undefined;
                self.discardPendingMessage();
                const response = self.takeResetTerminal(reset_value) catch |err| {
                    self.fail(.internal_error);
                    return err;
                };
                self.receive_state = .terminal_delivered;
                return .{ .terminal = response };
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
        try decoder.finish();
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
        const parsed = try sequential.parseResponseTerminal(
            self.allocator,
            head.status,
            head.headers,
            trailers orelse &.{},
            self.response_encoding,
        );
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

    fn ensureWritable(self: ClientDuplex) Error!void {
        if (self.receive_state != .active or self.transport.responseFinished()) {
            return error.ConnectionClosed;
        }
    }

    /// Make every post-error operation deterministic. Reset is attempted once;
    /// local state is discarded even when the transport is already unusable.
    fn fail(self: *ClientDuplex, code: http2.ErrorCode) void {
        if (self.receive_state == .failed) return;
        self.discardReceiveState();
        self.receive_state = .failed;
        self.transport.reset(code) catch {};
    }

    fn discardReceiveState(self: *ClientDuplex) void {
        self.discardPendingMessage();
        if (self.pending_terminal) |*response| response.deinit();
        self.pending_terminal = null;
        if (self.response_head) |*head| head.deinit(self.allocator);
        self.response_head = null;
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
    receive_state: ReceiveState = .active,
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
        return self.readRequestEventWithDeadline(
            .fromNow(self.transport.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
            context,
            consume,
        );
    }

    pub fn readRequestEventWithDeadline(
        self: *ServerDuplex,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !ServerEvent {
        if (self.pending_terminal) |terminal| {
            self.pending_terminal = null;
            self.receive_state = .terminal_delivered;
            return .{ .finished = terminal };
        }
        if (self.receive_state != .active) return error.ConnectionClosed;
        const event = self.transport.readRequestEventWithDeadline(
            deadline,
        ) catch |err| {
            if (err != error.Timeout) self.fail(.internal_error);
            return err;
        };
        return self.readRequestEventTransport(
            event,
            deadline,
            context,
            consume,
        );
    }

    fn readRequestEventUntil(
        self: *ServerDuplex,
        deadline: ?std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !ServerEvent {
        if (self.pending_terminal) |terminal| {
            self.pending_terminal = null;
            self.receive_state = .terminal_delivered;
            return .{ .finished = terminal };
        }
        if (self.receive_state != .active) return error.ConnectionClosed;
        const event = readServerTransportEvent(
            &self.transport,
            deadline,
        ) catch |err| {
            if (err != error.Timeout) self.fail(.internal_error);
            return err;
        };
        return self.readRequestEventTransport(
            event,
            deadline,
            context,
            consume,
        );
    }

    fn readRequestEventTransport(
        self: *ServerDuplex,
        transport_event: http2.runtime.DuplexRequestEvent,
        deadline: ?std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !ServerEvent {
        if (self.pending_terminal != null or self.receive_state != .active) {
            var unused = transport_event;
            unused.deinit(self.allocator);
            return error.ConnectionClosed;
        }
        var event = transport_event;
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
                    self.fail(.internal_error);
                    return err;
                };
                event.deinit(self.allocator);
                self.message_count = std.math.add(
                    usize,
                    self.message_count,
                    delivered,
                ) catch {
                    self.fail(.internal_error);
                    return error.MessageTooLarge;
                };
                const ended = self.transport.requestFinished();
                if (ended) {
                    self.finishRequestDecoder() catch |err| {
                        self.fail(.internal_error);
                        return err;
                    };
                    self.consumeRequestFinished(deadline) catch |err| {
                        self.fail(.internal_error);
                        return err;
                    };
                    const terminal = RequestTerminal{
                        .allocator = self.allocator,
                        .message_count = self.message_count,
                    };
                    if (delivered == 0) {
                        self.receive_state = .terminal_delivered;
                        return .{ .finished = terminal };
                    }
                    self.pending_terminal = terminal;
                    self.receive_state = .terminal_pending;
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
                self.finishRequestDecoder() catch |err| {
                    self.fail(.internal_error);
                    return err;
                };
                self.consumeRequestFinished(deadline) catch |err| {
                    self.fail(.internal_error);
                    return err;
                };
                self.receive_state = .terminal_delivered;
                trailers_owned = false;
                return .{ .finished = .{
                    .allocator = self.allocator,
                    .trailers = trailers,
                    .message_count = self.message_count,
                } };
            },
            .finished => {
                event = undefined;
                self.finishRequestDecoder() catch |err| {
                    self.fail(.internal_error);
                    return err;
                };
                self.receive_state = .terminal_delivered;
                return .{ .finished = .{
                    .allocator = self.allocator,
                    .message_count = self.message_count,
                } };
            },
            .reset => |reset_value| {
                event = undefined;
                self.discardPendingMessage();
                self.receive_state = .terminal_delivered;
                return .{ .reset = reset_value };
            },
        }
    }

    pub fn startResponse(
        self: *ServerDuplex,
        options: ResponseOptions,
    ) Error!void {
        try self.ensureResponseWritable();
        if (self.response_encoder != null) return error.InvalidStreamState;
        sequential.startDuplexResponse(
            &self.transport,
            self.allocator,
            options,
        ) catch |err| {
            self.fail(.internal_error);
            return err;
        };
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
        try self.ensureResponseWritable();
        if (self.pending_message != null) return error.InvalidStreamState;
        const encoder = self.response_encoder orelse
            return error.InvalidStreamState;
        self.pending_message = .{
            .bytes = try encodeMessageAlloc(self.allocator, encoder, payload),
        };
        return self.resumeMessage();
    }

    pub fn resumeMessage(self: *ServerDuplex) Error!WriteResult {
        try self.ensureResponseWritable();
        const pending = if (self.pending_message) |*value| value else return error.InvalidStreamState;
        const result = self.transport.writeResponse(
            pending.bytes[pending.offset..],
        ) catch |err| {
            self.fail(.internal_error);
            return err;
        };
        if (result.written > pending.bytes.len - pending.offset) {
            self.fail(.internal_error);
            return error.InvalidStreamState;
        }
        pending.offset = std.math.add(usize, pending.offset, result.written) catch {
            self.fail(.internal_error);
            return error.InvalidStreamState;
        };
        if (pending.offset == pending.bytes.len) {
            pending.deinit(self.allocator);
            self.pending_message = null;
            return .complete;
        }
        if (!result.response_available) {
            self.fail(.internal_error);
            return error.InvalidStreamState;
        }
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
        try self.ensureResponseWritable();
        if (self.pending_message != null) return error.InvalidStreamState;
        if (self.response_encoder == null) {
            sequential.finishDuplexHeadersOnly(
                &self.transport,
                self.allocator,
                status,
                status_message,
                trailing_metadata,
                trailing_binary_metadata,
            ) catch |err| {
                self.fail(.internal_error);
                return err;
            };
        } else {
            sequential.finishDuplexTrailers(
                &self.transport,
                self.allocator,
                status,
                status_message,
                trailing_metadata,
                trailing_binary_metadata,
            ) catch |err| {
                self.fail(.internal_error);
                return err;
            };
        }
    }

    pub fn finishOk(self: *ServerDuplex) Error!void {
        return self.finish(.ok, null, &.{}, &.{});
    }

    pub fn reset(self: *ServerDuplex, code: http2.ErrorCode) Error!void {
        try self.ensureResponseWritable();
        self.discardReceiveState();
        self.receive_state = .failed;
        try self.transport.reset(code);
    }

    /// Wait for cancellation after the request half reached END_STREAM while
    /// the server-streaming response remains open. Only this duplex owner may
    /// read connection frames during the wait.
    pub fn waitForPeerReset(
        self: *ServerDuplex,
    ) Error!http2.ResetStreamPayload {
        return self.transport.waitForPeerReset();
    }

    pub fn waitForPeerResetWithTimeout(
        self: *ServerDuplex,
        timeout: std.Io.Duration,
    ) Error!http2.ResetStreamPayload {
        return self.transport.waitForPeerResetWithTimeout(timeout);
    }

    pub fn waitForPeerResetWithDeadline(
        self: *ServerDuplex,
        deadline: std.Io.Clock.Timestamp,
    ) Error!http2.ResetStreamPayload {
        return self.transport.waitForPeerResetWithDeadline(deadline);
    }

    fn finishRequestDecoder(self: *ServerDuplex) Error!void {
        try self.decoder.finish();
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

    fn ensureResponseWritable(self: ServerDuplex) Error!void {
        if (self.receive_state == .failed or self.transport.responseFinished()) {
            return error.ConnectionClosed;
        }
    }

    fn fail(self: *ServerDuplex, code: http2.ErrorCode) void {
        if (self.receive_state == .failed) return;
        self.discardReceiveState();
        self.receive_state = .failed;
        self.transport.reset(code) catch {};
    }

    fn discardReceiveState(self: *ServerDuplex) void {
        self.discardPendingMessage();
        if (self.pending_terminal) |*terminal| terminal.deinit();
        self.pending_terminal = null;
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

test "duplex terminal allocation failure releases all owned metadata" {
    const allocator = std.testing.allocator;
    const headers = [_]http2.Hpack.HeaderField{
        .{
            .name = "content-type",
            .value = "application/grpc+proto",
        },
        .{ .name = "grpc-encoding", .value = "identity" },
    };
    const trailers = [_]http2.Hpack.HeaderField{
        .{ .name = "grpc-status", .value = "7" },
        .{ .name = "grpc-message", .value = "denied%20message" },
    };

    // Sweep allocation failure through both owned header copies and terminal
    // status-message decoding. Every unsuccessful construction must release
    // exactly the allocations it acquired before failing.
    for (0..6) |fail_index| {
        var failing = std.testing.FailingAllocator.init(allocator, .{
            .fail_index = fail_index,
        });
        const failing_allocator = failing.allocator();
        var head = ownResponseHead(failing_allocator, 200, &headers) catch |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            try std.testing.expectEqual(
                failing.allocated_bytes,
                failing.freed_bytes,
            );
            continue;
        };
        const trailers_copy = cloneHeaders(failing_allocator, &trailers) catch |err| {
            head.deinit(failing_allocator);
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            try std.testing.expectEqual(
                failing.allocated_bytes,
                failing.freed_bytes,
            );
            continue;
        };
        const parsed = sequential.parseResponseTerminal(
            failing_allocator,
            head.status,
            head.headers,
            trailers_copy,
            "identity",
        ) catch |err| {
            http2.Hpack.freeOwnedFields(failing_allocator, trailers_copy);
            head.deinit(failing_allocator);
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            try std.testing.expectEqual(
                failing.allocated_bytes,
                failing.freed_bytes,
            );
            continue;
        };
        failing_allocator.free(parsed.status_message);
        http2.Hpack.freeOwnedFields(failing_allocator, trailers_copy);
        head.deinit(failing_allocator);
        try std.testing.expectEqual(
            failing.allocated_bytes,
            failing.freed_bytes,
        );
    }
}
