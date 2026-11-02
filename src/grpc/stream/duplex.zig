//! Step-driven, single-owner gRPC streams over HTTP/2.
//!
//! One connection owner serially drives its duplex values. Client and server
//! streams can coexist on one HTTP/2 connection; their events and compression
//! state remain independent. Message callbacks run inline with `read*Event`
//! and borrow payload only for that callback.

const std = @import("std");
const response_metadata = @import("../response_metadata.zig");
const details_mod = @import("../status_details.zig");
const http2 = @import("../../http2/mod.zig");
const auth = @import("../auth.zig");
const call = @import("../call.zig");
const compression = @import("../compression.zig");
const metadata = @import("../metadata.zig");
const wire = @import("../wire.zig");
const codec = @import("codec.zig");
const completion = @import("completion.zig");
const client_receive = @import("duplex/client_receive.zig");
const outbound_ownership = @import("duplex/outbound_ownership.zig");
const sequential = @import("runtime.zig");

pub const OwnedMessage = outbound_ownership.OwnedMessage;

pub const Error = sequential.Error;
pub const RequestOptions = sequential.RequestOptions;
pub const ResponseOptions = sequential.ResponseOptions;

/// A write stopped only at a precisely reported wire-byte boundary.
///
/// On `peer_event`, the duplex object retains the unsent suffix.  The caller
/// must drive the peer event(s), then call `resumeMessage`; it must not submit
/// the logical message again because a prefix of it may already be on the wire.
pub const WriteResult = enum { complete, peer_event };
pub const PollWriteResult = enum { complete, blocked };

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
    status_details: ?details_mod.Owned = null,
    encoding: ?[]const u8 = null,

    pub fn deinit(self: *Response) void {
        self.allocator.free(self.status_message);
        if (self.status_details) |*details| details.deinit();
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

/// Internal adapter event for an application-owned message decoder. Metadata
/// and terminal status are validated here; DATA remains encoded gRPC bytes.
pub const RawClientEvent = union(enum) {
    informational: http2.runtime.DuplexResponseHead,
    initial_metadata: ResponseHead,
    data: http2.runtime.DuplexData,
    progress,
    terminal: Response,
    pub fn deinit(self: *RawClientEvent, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .informational => |*head| head.deinit(allocator),
            .data => |*data| data.deinit(allocator),
            .terminal => |*response| response.deinit(),
            .initial_metadata, .progress => {},
        }
        self.* = undefined;
    }
};

const ReceiveMode = enum { unselected, decoded, raw };

const PendingMessage = struct {
    bytes: []u8,
    offset: usize = 0,
    end_stream: bool = false,

    fn deinit(self: *PendingMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

/// Large server responses first try one borrowed prefix-plus-payload DATA
/// burst. The framed fallback and its owned pending message remain for small
/// messages.
const borrowed_server_message_threshold: usize = 64 * 1024;

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
    pending_data: ?client_receive.PendingData = null,
    pending_terminal: ?Response = null,
    receive_state: ReceiveState = .active,
    receive_mode: ReceiveMode = .unselected,
    deadline: ?std.Io.Clock.Timestamp = null,
    completion_observer: ?*completion.Observer = null,

    pub fn deinit(self: *ClientDuplex) void {
        self.finishCompletion(false);
        if (self.decoder) |*decoder| decoder.deinit();
        if (self.response_head) |*head| head.deinit(self.allocator);
        if (self.pending_message) |*pending| pending.deinit(self.allocator);
        if (self.pending_data) |*pending| pending.data.deinit(self.allocator);
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
        return self.writeMessageWithOptions(payload, .{});
    }

    pub fn writeMessageWithOptions(
        self: *ClientDuplex,
        payload: []const u8,
        options: codec.MessageOptions,
    ) Error!WriteResult {
        try self.stageMessage(payload, options);
        return self.resumeMessage();
    }

    pub fn allocMessage(
        self: *ClientDuplex,
        payload_len: usize,
    ) Error!OwnedMessage {
        try self.ensureWritable();
        if (self.pending_message != null) return error.InvalidStreamState;
        if (payload_len > self.encoder.max_message_size) {
            return error.GrpcMessageTooLarge;
        }
        return OwnedMessage.init(self.allocator, payload_len);
    }

    /// Consume `message` on success or error. A deferred `message.deinit()` is
    /// safe because successful transfer clears its optional storage.
    pub fn writeOwnedMessage(
        self: *ClientDuplex,
        message: *OwnedMessage,
    ) Error!WriteResult {
        return self.writeOwnedMessageWithOptions(message, .{});
    }

    pub fn writeOwnedMessageWithOptions(
        self: *ClientDuplex,
        message: *OwnedMessage,
        options: codec.MessageOptions,
    ) Error!WriteResult {
        try self.stageOwnedMessageWithEndStream(message, options, false);
        return self.resumeMessage();
    }

    /// Encode one final request message and set END_STREAM on its last wire
    /// byte. If peer activity interrupts a flow-control wait, `resumeMessage`
    /// retains both the exact suffix and the final-message intent.
    pub fn writeFinalMessage(
        self: *ClientDuplex,
        payload: []const u8,
    ) Error!WriteResult {
        return self.writeFinalMessageWithOptions(payload, .{});
    }

    pub fn writeFinalMessageWithOptions(
        self: *ClientDuplex,
        payload: []const u8,
        options: codec.MessageOptions,
    ) Error!WriteResult {
        try self.stageFinalMessage(payload, options);
        return self.resumeMessage();
    }

    pub fn writeFinalOwnedMessage(
        self: *ClientDuplex,
        message: *OwnedMessage,
    ) Error!WriteResult {
        return self.writeFinalOwnedMessageWithOptions(message, .{});
    }

    pub fn writeFinalOwnedMessageWithOptions(
        self: *ClientDuplex,
        message: *OwnedMessage,
        options: codec.MessageOptions,
    ) Error!WriteResult {
        try self.stageOwnedMessageWithEndStream(message, options, true);
        return self.resumeMessage();
    }

    /// Retain a final message without writing or reading transport input.
    pub fn stageFinalMessage(self: *ClientDuplex, payload: []const u8, options: codec.MessageOptions) Error!void {
        try self.stageMessageWithEndStream(payload, options, true);
    }

    /// Retain an ordinary message for a background owner without socket IO.
    pub fn stageMessage(self: *ClientDuplex, payload: []const u8, options: codec.MessageOptions) Error!void {
        try self.stageMessageWithEndStream(payload, options, false);
    }

    /// Retain a prefix-reserved allocation made by `self.allocator` for a
    /// background owner. On a `true` result, ownership transfers to this
    /// stream. A `false` result means compression produced a separate
    /// allocation and the caller still owns `storage`. On error ownership
    /// always remains with the caller.
    pub fn stageOwnedMessageStorage(
        self: *ClientDuplex,
        storage: []u8,
        options: codec.MessageOptions,
        end_stream: bool,
    ) Error!bool {
        try self.ensureWritable();
        if (self.pending_message != null) return error.InvalidStreamState;
        const encoded = try outbound_ownership.encode(
            self.allocator,
            self.encoder,
            storage,
            options,
        );
        self.pending_message = .{
            .bytes = encoded.bytes,
            .end_stream = end_stream,
        };
        return encoded.input_transferred;
    }

    fn stageOwnedMessageWithEndStream(
        self: *ClientDuplex,
        message: *OwnedMessage,
        options: codec.MessageOptions,
        end_stream: bool,
    ) Error!void {
        defer message.deinit();
        try self.ensureWritable();
        if (self.pending_message != null) return error.InvalidStreamState;
        self.pending_message = .{
            .bytes = try outbound_ownership.encodeMessage(
                self.allocator,
                self.encoder,
                message,
                options,
            ),
            .end_stream = end_stream,
        };
    }

    fn stageMessageWithEndStream(self: *ClientDuplex, payload: []const u8, options: codec.MessageOptions, end_stream: bool) Error!void {
        try self.ensureWritable();
        if (self.pending_message != null) return error.InvalidStreamState;
        self.pending_message = .{
            .bytes = try encodeMessageAlloc(
                self.allocator,
                self.encoder,
                payload,
                options,
            ),
            .end_stream = end_stream,
        };
    }

    /// Commit at most the currently available credit and caller's byte budget.
    /// No socket input is read; a blocked suffix stays byte-exact for the owner.
    pub fn pollResumeMessageWithDeadline(self: *ClientDuplex, deadline: std.Io.Clock.Timestamp, max_bytes: usize) Error!PollWriteResult {
        try self.ensureWritable();
        if (max_bytes == 0) return error.InvalidStreamState;
        if (deadline.clock != .awake) return error.Timeout;
        const effective = earlierDeadline(self.deadline, deadline);
        if (effective.clock != .awake or effective.durationFromNow(self.transport.connection.io).raw.nanoseconds <= 0) {
            if (self.deadline) |rpc| if (rpc.durationFromNow(self.transport.connection.io).raw.nanoseconds <= 0) self.fail(.cancel);
            return error.Timeout;
        }
        const pending = if (self.pending_message) |*value| value else return .complete;
        const remaining = pending.bytes.len - pending.offset;
        const amount = @min(remaining, max_bytes, self.transport.connection.availableClientSendCapacity(self.streamId()));
        if (amount == 0 and remaining != 0) return .blocked;
        const final = pending.end_stream and amount == remaining;
        const result = (if (final)
            self.transport.finishRequestDataWithDeadline(pending.bytes[pending.offset..][0..amount], effective)
        else
            self.transport.writeWithDeadline(pending.bytes[pending.offset..][0..amount], effective)) catch |err| {
            self.fail(if (err == error.Timeout) .cancel else .internal_error);
            return err;
        };
        pending.offset += result.written;
        if (pending.offset == pending.bytes.len) {
            pending.deinit(self.allocator);
            self.pending_message = null;
            return .complete;
        }
        return .blocked;
    }

    /// Continue the exact unsent suffix after a response event interrupted a
    /// flow-control-blocked write.
    pub fn resumeMessage(self: *ClientDuplex) Error!WriteResult {
        try self.ensureWritable();
        const pending = if (self.pending_message) |*value| value else return error.InvalidStreamState;
        const result = (if (self.deadline) |deadline|
            if (pending.end_stream)
                self.transport.finishRequestDataWithDeadline(
                    pending.bytes[pending.offset..],
                    deadline,
                )
            else
                self.transport.writeWithDeadline(
                    pending.bytes[pending.offset..],
                    deadline,
                )
        else if (pending.end_stream)
            self.transport.finishRequestData(pending.bytes[pending.offset..])
        else
            self.transport.write(pending.bytes[pending.offset..])) catch |err| {
            // Only a successful `response_available` result has a precise,
            // resumable byte count. Any transport error can have unknown wire
            // progress, so retrying would risk duplicating message bytes.
            self.fail(if (err == error.Timeout) .cancel else .internal_error);
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
        return self.finishRequestUntil(self.deadline);
    }

    /// Bound a background owner's empty request FIN under its operation budget.
    pub fn finishRequestWithDeadline(self: *ClientDuplex, deadline: std.Io.Clock.Timestamp) Error!WriteResult {
        if (deadline.clock != .awake) return error.Timeout;
        const effective = earlierDeadline(self.deadline, deadline);
        if (effective.durationFromNow(self.transport.connection.io).raw.nanoseconds <= 0) {
            if (self.deadline) |rpc| if (rpc.durationFromNow(self.transport.connection.io).raw.nanoseconds <= 0) self.fail(.cancel);
            return error.Timeout;
        }
        return self.finishRequestUntil(effective);
    }

    fn finishRequestUntil(self: *ClientDuplex, deadline: ?std.Io.Clock.Timestamp) Error!WriteResult {
        try self.ensureWritable();
        if (self.pending_message != null) return error.InvalidStreamState;
        const result = (if (deadline) |until|
            self.transport.finishRequestWithDeadline(until)
        else
            self.transport.finishRequest()) catch |err| {
            self.fail(if (err == error.Timeout) .cancel else .internal_error);
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
        self.finishCompletion(false);
        try self.transport.reset(code);
    }

    pub fn cancel(self: *ClientDuplex) Error!void {
        return self.reset(.cancel);
    }

    pub fn readResponseEvent(
        self: *ClientDuplex,
        context: anytype,
        comptime consume: anytype,
    ) !ClientEvent {
        return self.readResponseEventWithRpcDeadline(
            self.deadline,
            self.deadline != null,
            context,
            consume,
        );
    }

    pub fn readResponseEventWithTimeout(
        self: *ClientDuplex,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !ClientEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const requested = std.Io.Clock.Timestamp.fromNow(
            self.transport.connection.io,
            .{
                .raw = timeout,
                .clock = .awake,
            },
        );
        return self.readResponseEventWithDeadline(
            requested,
            context,
            consume,
        );
    }

    /// A local read cancellation or executor admission failure retains the
    /// stream and decoder while HTTP/2 remains usable. The operation returns
    /// its original error; a later read resumes that state. Consumer callback
    /// errors and explicit RPC/stream cancellation retain terminal behavior.
    pub fn readResponseEventWithDeadline(
        self: *ClientDuplex,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !ClientEvent {
        if (deadline.clock != .awake) return error.Timeout;
        const effective = earlierDeadline(self.deadline, deadline);
        const rpc_limited = if (self.deadline) |rpc_deadline|
            !std.Io.Clock.Timestamp.compare(deadline, .lt, rpc_deadline)
        else
            false;
        return self.readResponseEventWithRpcDeadline(
            effective,
            rpc_limited,
            context,
            consume,
        );
    }

    /// Consume only events routed by the shared HTTP/2 pump. No socket input
    /// is read. DATA credit and terminal cleanup retain their finite budgets.
    pub fn pollResponseEvent(
        self: *ClientDuplex,
        context: anytype,
        comptime consume: anytype,
    ) !?ClientEvent {
        return self.pollResponseEventUntil(self.deadline, self.deadline != null, context, consume);
    }

    pub fn pollResponseEventWithDeadline(
        self: *ClientDuplex,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !?ClientEvent {
        if (deadline.clock != .awake) return error.Timeout;
        const effective = earlierDeadline(self.deadline, deadline);
        const rpc_limited = if (self.deadline) |rpc|
            !std.Io.Clock.Timestamp.compare(deadline, .lt, rpc)
        else
            false;
        return self.pollResponseEventUntil(effective, rpc_limited, context, consume);
    }

    const receive_hooks = .{
        .Event = ClientEvent,
        .raw = false,
        .begin = beginResponse,
        .finishDecoder = finishResponseDecoder,
        .finished = consumeTransportFinished,
        .terminal = takeTerminal,
        .resetTerminal = takeResetTerminal,
        .closeRequest = closeRequestAfterTerminal,
        .discardPending = discardPendingMessage,
        .fail = fail,
        .readTransport = readClientTransportEvent,
        .Counter = MessageCounter,
    };
    const raw_receive_hooks = .{
        .Event = RawClientEvent,
        .raw = true,
        .begin = beginResponse,
        .finishDecoder = finishResponseDecoder,
        .finished = consumeTransportFinished,
        .terminal = takeTerminal,
        .resetTerminal = takeResetTerminal,
        .closeRequest = closeRequestAfterTerminal,
        .discardPending = discardPendingMessage,
        .fail = fail,
    };

    fn selectReceiveMode(self: *ClientDuplex, mode: ReceiveMode) Error!void {
        if (self.receive_mode == .unselected) self.receive_mode = mode;
        if (self.receive_mode != mode) return error.InvalidStreamState;
    }

    fn pollResponseEventUntil(self: *ClientDuplex, deadline: ?std.Io.Clock.Timestamp, cancel_on_timeout: bool, context: anytype, comptime consume: anytype) !?ClientEvent {
        try self.selectReceiveMode(.decoded);
        return client_receive.poll(self, deadline, cancel_on_timeout, std.math.maxInt(usize), context, consume, receive_hooks);
    }
    fn readResponseEventWithRpcDeadline(self: *ClientDuplex, deadline: ?std.Io.Clock.Timestamp, cancel_on_timeout: bool, context: anytype, comptime consume: anytype) !ClientEvent {
        try self.selectReceiveMode(.decoded);
        return client_receive.read(self, deadline, cancel_on_timeout, context, consume, receive_hooks);
    }

    /// Bound callback delivery without reading the socket. A partial DATA
    /// frame stays owned until subsequent polls consume its exact suffix.
    pub fn pollResponseEventLimited(self: *ClientDuplex, max_messages: usize, context: anytype, comptime consume: anytype) !?ClientEvent {
        try self.selectReceiveMode(.decoded);
        return client_receive.poll(self, self.deadline, self.deadline != null, max_messages, context, consume, receive_hooks);
    }
    pub fn pollResponseEventLimitedWithDeadline(self: *ClientDuplex, max_messages: usize, deadline: std.Io.Clock.Timestamp, context: anytype, comptime consume: anytype) !?ClientEvent {
        try self.selectReceiveMode(.decoded);
        if (deadline.clock != .awake) return error.Timeout;
        const effective = earlierDeadline(self.deadline, deadline);
        const rpc_limited = if (self.deadline) |rpc| !std.Io.Clock.Timestamp.compare(deadline, .lt, rpc) else false;
        return client_receive.poll(self, effective, rpc_limited, max_messages, context, consume, receive_hooks);
    }

    /// Route encoded DATA to a consumer-owned decoder. Use one receive mode
    /// for the entire RPC; raw and decoded event reads cannot be mixed.
    pub fn pollRawResponseEventWithDeadline(self: *ClientDuplex, deadline: std.Io.Clock.Timestamp) Error!?RawClientEvent {
        return self.pollRawResponseEventWithCredit(
            deadline,
            .immediate,
            false,
        );
    }

    /// Keep connection credit available with low-watermark refills while the
    /// application owns stream-credit acknowledgements.
    pub fn pollRawResponseEventBatchedWithDeadline(self: *ClientDuplex, deadline: std.Io.Clock.Timestamp) Error!?RawClientEvent {
        return self.pollRawResponseEventWithCredit(
            deadline,
            .low_watermark,
            false,
        );
    }

    /// Endpoint-owner counterpart whose scheduler turn already classified the
    /// RPC/write deadlines against its scan-cached awake timestamp.
    pub fn pollRawResponseEventBatchedWithValidatedDeadline(self: *ClientDuplex, deadline: std.Io.Clock.Timestamp) Error!?RawClientEvent {
        return self.pollRawResponseEventWithCredit(
            deadline,
            .low_watermark,
            true,
        );
    }

    fn pollRawResponseEventWithCredit(self: *ClientDuplex, deadline: std.Io.Clock.Timestamp, policy: http2.runtime.ClientDuplexStream.ConnectionCreditPolicy, comptime deadline_validated: bool) Error!?RawClientEvent {
        try self.selectReceiveMode(.raw);
        if (deadline.clock != .awake) return error.Timeout;
        const effective = earlierDeadline(self.deadline, deadline);
        const rpc_limited = if (self.deadline) |rpc| !std.Io.Clock.Timestamp.compare(deadline, .lt, rpc) else false;
        return if (deadline_validated)
            client_receive.pollWithConnectionCreditValidatedDeadline(
                self,
                effective,
                rpc_limited,
                1,
                {},
                unusedMessage,
                raw_receive_hooks,
                policy,
            )
        else
            client_receive.pollWithConnectionCredit(
                self,
                effective,
                rpc_limited,
                1,
                {},
                unusedMessage,
                raw_receive_hooks,
                policy,
            );
    }

    fn unusedMessage(_: void, _: codec.DecodedMessage) Error!void {
        unreachable;
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
        self.parse_response_body = response_metadata.parseBody(head.status, head.headers, &.{});
        self.response_encoding = if (self.parse_response_body) call.headerValue(head.headers, "grpc-encoding") else null;
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
        if (self.receive_mode == .raw) return;
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
        self.finishCompletion(parsed.status == .ok);
        return .{
            .allocator = self.allocator,
            .head = head,
            .trailers = trailers,
            .status = parsed.status,
            .status_message = parsed.status_message,
            .status_details = parsed.status_details,
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
        self.finishCompletion(false);
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
        self.finishCompletion(false);
        self.transport.reset(code) catch {};
    }

    fn discardReceiveState(self: *ClientDuplex) void {
        if (self.pending_data) |*pending| pending.data.deinit(self.allocator);
        self.pending_data = null;
        self.discardPendingMessage();
        if (self.pending_terminal) |*response| response.deinit();
        self.pending_terminal = null;
        if (self.response_head) |*head| head.deinit(self.allocator);
        self.response_head = null;
    }

    pub fn setCompletionObserver(
        self: *ClientDuplex,
        observer: *completion.Observer,
    ) void {
        std.debug.assert(self.completion_observer == null);
        self.completion_observer = observer;
    }

    fn finishCompletion(self: *ClientDuplex, success: bool) void {
        const observer = self.completion_observer orelse return;
        self.completion_observer = null;
        observer.finish(success);
    }
};

pub fn startDuplex(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    options: RequestOptions,
) Error!ClientDuplex {
    return clientFromTransport(allocator, options, try sequential.startClientDuplexTransport(
        connection,
        allocator,
        options,
    ));
}

pub fn startDuplexUnderDeadline(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    options: RequestOptions,
    deadline: ?std.Io.Clock.Timestamp,
) Error!ClientDuplex {
    return clientFromTransport(allocator, options, try sequential.startClientDuplexTransportUnderDeadline(
        connection,
        allocator,
        options,
        deadline,
    ));
}

/// Bound only HEADERS output; no grpc-timeout or persistent RPC deadline is
/// introduced. Subsequent writes and reads use their own operation budgets.
pub fn startDuplexWithIoDeadline(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    options: RequestOptions,
    deadline: std.Io.Clock.Timestamp,
) Error!ClientDuplex {
    return clientFromTransport(allocator, options, try sequential.startClientDuplexTransportWithIoDeadline(
        connection,
        allocator,
        options,
        deadline,
    ));
}

pub fn startDuplexWithDeadlines(connection: *http2.runtime.Connection, allocator: std.mem.Allocator, options: RequestOptions, rpc_deadline: ?std.Io.Clock.Timestamp, output_deadline: std.Io.Clock.Timestamp) Error!ClientDuplex {
    return clientFromTransport(allocator, options, try sequential.startClientDuplexTransportWithDeadlines(connection, allocator, options, rpc_deadline, output_deadline));
}

/// Start one retry attempt without advertising its shorter local timer as the
/// RPC's grpc-timeout budget.
pub fn startDuplexWithRetryDeadlines(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    options: RequestOptions,
    rpc_deadline: ?std.Io.Clock.Timestamp,
    attempt_deadline: ?std.Io.Clock.Timestamp,
    output_deadline: std.Io.Clock.Timestamp,
) Error!ClientDuplex {
    return clientFromTransport(
        allocator,
        options,
        try sequential.startClientDuplexTransportWithRetryDeadlines(
            connection,
            allocator,
            options,
            rpc_deadline,
            attempt_deadline,
            output_deadline,
        ),
    );
}

fn clientFromTransport(
    allocator: std.mem.Allocator,
    options: RequestOptions,
    started: sequential.ClientDuplexTransport,
) ClientDuplex {
    return .{
        .allocator = allocator,
        .transport = started.transport,
        .encoder = .{
            .allocator = allocator,
            .algorithm = options.compression,
            .compression_level = options.compression_level,
            .max_message_size = options.requestMessageLimit(),
        },
        .accepted_encodings = options.accepted_encodings,
        .max_message_size = options.responseMessageLimit(),
        .deadline = started.deadline,
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

pub const RequestDrainResult = http2.runtime.DuplexRequestDrainResult;

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
    deadline: ?std.Io.Clock.Timestamp = null,
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

    /// Borrow the validated request metadata for this RPC. The slice remains
    /// valid until the duplex stream is deinitialized.
    pub fn requestHeaders(
        self: ServerDuplex,
    ) []const http2.Hpack.HeaderField {
        return self.transport.headers;
    }

    pub fn requestFinished(self: ServerDuplex) bool {
        return self.transport.requestFinished();
    }

    pub fn responseFinished(self: ServerDuplex) bool {
        return self.transport.responseFinished();
    }

    /// Require one Bearer credential before reading request DATA. A failed
    /// check completes only the response half with UNAUTHENTICATED; call
    /// `drainRequestAfterResponseWithDeadline` to retire the upload safely.
    pub fn requireBearer(
        self: *ServerDuplex,
        expected_token: []const u8,
        status_message: ?[]const u8,
    ) Error!bool {
        if (auth.bearerTokenMatches(
            self.requestHeaders(),
            expected_token,
        )) return true;
        try self.finish(.unauthenticated, status_message, &.{}, &.{});
        return false;
    }

    pub fn checkDeadline(self: ServerDuplex) Error!void {
        if (self.deadlineExpired()) return error.Timeout;
    }

    pub fn deadlineExpired(self: ServerDuplex) bool {
        const deadline = self.deadline orelse return false;
        return deadline.durationFromNow(
            self.transport.connection.io,
        ).raw.nanoseconds <= 0;
    }

    pub fn readRequestEvent(
        self: *ServerDuplex,
        context: anytype,
        comptime consume: anytype,
    ) !ServerEvent {
        return self.readRequestEventUntil(self.deadline, context, consume);
    }

    pub fn readRequestEventWithTimeout(
        self: *ServerDuplex,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !ServerEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const requested = std.Io.Clock.Timestamp.fromNow(
            self.transport.connection.io,
            .{
                .raw = timeout,
                .clock = .awake,
            },
        );
        return self.readRequestEventWithDeadline(
            requested,
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
        if (deadline.clock != .awake) return error.Timeout;
        const effective = earlierDeadline(self.deadline, deadline);
        if (self.pending_terminal) |terminal| {
            self.pending_terminal = null;
            self.receive_state = .terminal_delivered;
            return .{ .finished = terminal };
        }
        if (self.receive_state != .active) return error.ConnectionClosed;
        const event = self.transport.readRequestEventWithDeadline(
            effective,
        ) catch |err| {
            if (err != error.Timeout) self.fail(.internal_error);
            return err;
        };
        return self.readRequestEventTransport(
            event,
            effective,
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
        return self.writeMessageWithOptions(payload, .{});
    }

    pub fn writeMessageWithOptions(
        self: *ServerDuplex,
        payload: []const u8,
        options: codec.MessageOptions,
    ) Error!WriteResult {
        try self.ensureResponseWritable();
        if (self.pending_message != null) return error.InvalidStreamState;
        const encoder = self.response_encoder orelse
            return error.InvalidStreamState;
        if (payload.len > encoder.max_message_size) {
            return error.GrpcMessageTooLarge;
        }
        if (payload.len >= borrowed_server_message_threshold) {
            return self.writeBorrowedMessage(payload, options, encoder);
        }
        self.pending_message = .{
            .bytes = try encodeMessageAlloc(
                self.allocator,
                encoder,
                payload,
                options,
            ),
        };
        return self.resumeMessage();
    }

    fn writeBorrowedMessage(
        self: *ServerDuplex,
        payload: []const u8,
        options: codec.MessageOptions,
        encoder: codec.Encoder,
    ) Error!WriteResult {
        const algorithm: compression.Algorithm =
            if (options.disable_compression) .identity else encoder.algorithm;
        var encoded = try compression.compressAlloc(
            self.allocator,
            algorithm,
            payload,
            encoder.compression_level,
        );
        defer encoded.deinit(self.allocator);
        _ = try wire.encodedMessageLen(encoded.bytes.len);

        var prefix: [5]u8 = undefined;
        _ = try wire.writeMessageInto(&prefix, &.{}, encoded.compressed);
        std.mem.writeInt(
            u32,
            prefix[1..5],
            @intCast(encoded.bytes.len),
            .big,
        );
        const total = std.math.add(
            usize,
            prefix.len,
            encoded.bytes.len,
        ) catch {
            self.fail(.internal_error);
            return error.MessageTooLarge;
        };
        const slices = [_][]const u8{ &prefix, encoded.bytes };
        const result = self.transport.writeResponseSlicesBurst(
            &slices,
            false,
        ) catch |err| {
            self.fail(.internal_error);
            return err;
        };
        if (result.written != total) {
            self.fail(.internal_error);
            return error.InvalidStreamState;
        }
        return .complete;
    }

    /// Allocate response payload storage with the gRPC prefix already
    /// reserved. `startResponse` must have selected the response encoder.
    pub fn allocMessage(
        self: *ServerDuplex,
        payload_len: usize,
    ) Error!OwnedMessage {
        try self.ensureResponseWritable();
        if (self.pending_message != null) return error.InvalidStreamState;
        const encoder = self.response_encoder orelse
            return error.InvalidStreamState;
        if (payload_len > encoder.max_message_size) {
            return error.GrpcMessageTooLarge;
        }
        return OwnedMessage.init(self.allocator, payload_len);
    }

    /// Consume `message` on success or error. A deferred `message.deinit()` is
    /// safe because successful transfer clears its optional storage.
    pub fn writeOwnedMessage(
        self: *ServerDuplex,
        message: *OwnedMessage,
    ) Error!WriteResult {
        return self.writeOwnedMessageWithOptions(message, .{});
    }

    pub fn writeOwnedMessageWithOptions(
        self: *ServerDuplex,
        message: *OwnedMessage,
        options: codec.MessageOptions,
    ) Error!WriteResult {
        defer message.deinit();
        try self.ensureResponseWritable();
        if (self.pending_message != null) return error.InvalidStreamState;
        const encoder = self.response_encoder orelse
            return error.InvalidStreamState;
        self.pending_message = .{
            .bytes = try outbound_ownership.encodeMessage(
                self.allocator,
                encoder,
                message,
                options,
            ),
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
        return self.finishWithOptions(.{ .status = status, .status_message = status_message, .trailing_metadata = trailing_metadata, .trailing_binary_metadata = trailing_binary_metadata });
    }

    pub fn finishWithOptions(self: *ServerDuplex, options: sequential.TerminalOptions) Error!void {
        // Local metadata errors occur before output and preserve the writer.
        if (options.status_details) |bytes| _ = try details_mod.validate(options.status, bytes);
        try call.validateCustomMetadata(options.trailing_metadata);
        try call.validateCustomBinaryMetadata(options.trailing_binary_metadata);
        try self.ensureResponseWritable();
        if (self.pending_message != null) return error.InvalidStreamState;
        if (self.response_encoder == null) {
            sequential.finishDuplexHeadersOnlyWithOptions(
                &self.transport,
                self.allocator,
                options,
            ) catch |err| {
                self.fail(.internal_error);
                return err;
            };
        } else {
            sequential.finishDuplexTrailersWithOptions(
                &self.transport,
                self.allocator,
                options,
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

    /// Drain the request half after an early terminal response. The cleanup
    /// deadline is intentionally independent of the RPC's `grpc-timeout`,
    /// which has normally expired before a deadline status is sent. The
    /// serial connection owner routes sibling and connection-control frames
    /// while this duplex drains.
    pub fn drainRequestAfterResponseWithDeadline(
        self: *ServerDuplex,
        cleanup_deadline: std.Io.Clock.Timestamp,
    ) !RequestDrainResult {
        if (!self.transport.responseFinished()) {
            return error.InvalidStreamState;
        }
        if (cleanup_deadline.clock != .awake) return error.Timeout;
        self.discardReceiveState();
        const result = try self.transport
            .drainRequestAfterResponseWithDeadline(cleanup_deadline);
        self.receive_state = .terminal_delivered;
        return result;
    }

    /// Wait for cancellation after the request half reached END_STREAM while
    /// the server-streaming response remains open. Only this duplex owner may
    /// read connection frames during the wait.
    pub fn waitForPeerReset(
        self: *ServerDuplex,
    ) Error!http2.ResetStreamPayload {
        return self.finishPeerResetWait(
            self.transport.waitForPeerReset() catch |err| {
                if (err != error.Canceled) self.fail(.internal_error);
                return err;
            },
        );
    }

    pub fn waitForPeerResetWithTimeout(
        self: *ServerDuplex,
        timeout: std.Io.Duration,
    ) Error!http2.ResetStreamPayload {
        const peer_reset = self.transport.waitForPeerResetWithTimeout(
            timeout,
        ) catch |err| {
            if (err != error.Timeout and err != error.Canceled) {
                self.fail(.internal_error);
            }
            return err;
        };
        return self.finishPeerResetWait(peer_reset);
    }

    pub fn waitForPeerResetWithDeadline(
        self: *ServerDuplex,
        deadline: std.Io.Clock.Timestamp,
    ) Error!http2.ResetStreamPayload {
        const peer_reset = self.transport.waitForPeerResetWithDeadline(
            deadline,
        ) catch |err| {
            if (err != error.Timeout and err != error.Canceled) {
                self.fail(.internal_error);
            }
            return err;
        };
        return self.finishPeerResetWait(peer_reset);
    }

    fn finishPeerResetWait(
        self: *ServerDuplex,
        peer_reset: http2.ResetStreamPayload,
    ) http2.ResetStreamPayload {
        self.discardReceiveState();
        self.receive_state = .terminal_delivered;
        return peer_reset;
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
    const deadline: ?std.Io.Clock.Timestamp = if (parsed.timeout) |timeout|
        std.Io.Clock.Timestamp.fromNow(transport.connection.io, .{
            .raw = timeout.duration(),
            .clock = .awake,
        })
    else
        null;
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
        .deadline = deadline,
        .encoding = parsed.encoding,
        .accepted_encodings = parsed.accepted_encodings,
    };
}

fn MessageCounter(comptime Context: type, comptime consume: anytype) type {
    return struct {
        context: Context,
        count: *usize,

        pub fn deliver(self: *@This(), message: codec.DecodedMessage) !void {
            try consume(self.context, message);
            self.count.* += 1;
        }
    };
}

fn encodeMessageAlloc(
    allocator: std.mem.Allocator,
    encoder: codec.Encoder,
    payload: []const u8,
    options: codec.MessageOptions,
) Error![]u8 {
    var encoded: std.ArrayList(u8) = .empty;
    errdefer encoded.deinit(allocator);
    try encoder.appendMessageWithOptions(&encoded, payload, options);
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

fn earlierDeadline(
    rpc: ?std.Io.Clock.Timestamp,
    requested: std.Io.Clock.Timestamp,
) std.Io.Clock.Timestamp {
    const rpc_deadline = rpc orelse return requested;
    return if (std.Io.Clock.Timestamp.compare(
        rpc_deadline,
        .lt,
        requested,
    )) rpc_deadline else requested;
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

test "gRPC duplex terminal allocation failure releases all owned metadata" {
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
        .{ .name = "grpc-status-details-bin", .value = "CAc" },
    };

    // Sweep allocation failure through both owned header copies and terminal
    // status-message decoding. Every unsuccessful construction must release
    // exactly the allocations it acquired before failing.
    for (0..16) |fail_index| {
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
        if (parsed.status_details) |value| {
            var details = value;
            details.deinit();
        }
        http2.Hpack.freeOwnedFields(failing_allocator, trailers_copy);
        head.deinit(failing_allocator);
        try std.testing.expectEqual(
            failing.allocated_bytes,
            failing.freed_bytes,
        );
    }
}
