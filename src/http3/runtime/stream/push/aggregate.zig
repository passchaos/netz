//! Ownership and resumable aggregation for one HTTP/3 pushed response.

const std = @import("std");
const http3 = @import("../../../mod.zig");
const runtime_error = @import("../../error.zig");
const push_state = @import("state.zig");

const Error = runtime_error.Error;

/// Reports a callback-scoped pushed informational response with every identity
/// needed to correlate it to both the PUSH_PROMISE and its QUIC stream.
pub const InformationalObserver = struct {
    context: *anyopaque,
    on_response: *const fn (
        context: *anyopaque,
        push_id: u64,
        request_stream_id: u62,
        stream_id: u62,
        response: http3.InformationalResponseHead,
    ) void,
};

pub const Response = struct {
    push_id: u64,
    request_stream_id: u62,
    stream_id: u62,
    response: http3.DecodedResponse,

    pub fn deinit(self: *Response, allocator: std.mem.Allocator) void {
        self.response.deinit(allocator);
        self.* = undefined;
    }
};

/// Resumable ownership for an aggregate push receive. Unlike ordinary
/// responses, push bodies are consumed through the incremental reader, so
/// decoded heads and copied DATA must outlive a caller timeout.
pub const State = struct {
    head: ?http3.DecodedResponseHead = null,
    trailers: ?http3.DecodedTrailers = null,
    body: std.ArrayList(u8) = .empty,
    push_id: ?u64 = null,
    request_stream_id: u62 = 0,
    stream_id: u62 = 0,
    finished: bool = false,

    pub fn active(self: State) bool {
        return self.push_id != null;
    }

    pub fn deinit(self: *State, allocator: std.mem.Allocator) void {
        if (self.head) |*head| head.deinit(allocator);
        if (self.trailers) |*trailers| trailers.deinit(allocator);
        self.body.deinit(allocator);
        self.* = .{};
    }

    pub fn takeResponse(
        self: *State,
        allocator: std.mem.Allocator,
    ) Error!Response {
        if (!self.finished) return error.UnexpectedStream;
        const head = self.head orelse return error.ExpectedHeadersFrame;
        const body_storage: ?[]u8 = if (self.body.items.len == 0) storage: {
            self.body.deinit(allocator);
            break :storage null;
        } else try self.body.toOwnedSlice(allocator);
        const trailer_fields: []http3.Qpack.HeaderField =
            if (self.trailers) |trailers|
                trailers.fields
            else
                @constCast(&.{});
        const acknowledgments =
            head.qpack_section_acknowledgments +
            if (self.trailers) |trailers|
                trailers.qpack_section_acknowledgments
            else
                0;
        const result: Response = .{
            .push_id = self.push_id.?,
            .request_stream_id = self.request_stream_id,
            .stream_id = self.stream_id,
            .response = .{
                .status = head.status,
                .body_allowed = head.body_allowed,
                .headers = head.headers,
                .trailers = trailer_fields,
                .body = if (body_storage) |storage| storage else &.{},
                .body_storage = body_storage,
                .consumed = 0,
                .qpack_section_acknowledgments = acknowledgments,
            },
        };
        // Every allocation has moved into `result`; resetting avoids running
        // either decoded-field deinitializer on transferred ownership.
        self.* = .{};
        return result;
    }
};

/// Drive one resumable pushed-response aggregation with transport-specific
/// event and body readers supplied at comptime. Handshake-backed and
/// preconfigured-key clients share this state machine while retaining their
/// own packet pumps and receive-window feedback paths.
pub fn receive(
    context: anytype,
    state: *State,
    allocator: std.mem.Allocator,
    informational: ?InformationalObserver,
    deadline: ?std.Io.Clock.Timestamp,
    comptime next_event: anytype,
    comptime read_data: anytype,
    comptime stream_pending: anytype,
) runtime_error.ReceiveTimeoutError!Response {
    if (state.finished) return state.takeResponse(allocator);
    while (true) {
        var event: push_state.PushEvent = try next_event(
            context,
            state.push_id,
            deadline,
        );
        defer event.deinit(allocator);
        if (state.push_id) |expected| {
            if (event.push_id != expected) return error.UnexpectedStream;
        } else {
            state.push_id = event.push_id;
            state.request_stream_id = event.request_stream_id;
            state.stream_id = event.stream_id;
        }
        // Moving an owned head or trailers value out of `event` requires
        // replacing its tag before the deferred deinitializer runs. Keep the
        // transport's actual end-of-stream signal separate from that ownership
        // sentinel so a header-only prefix cannot complete the aggregate early.
        const stream_finished = event.value == .finished;
        switch (event.value) {
            .head => |value| {
                if (value != .response) return error.UnexpectedFrame;
                if (value.response.status < 200) {
                    if (informational) |observer| {
                        observer.on_response(
                            observer.context,
                            event.push_id,
                            event.request_stream_id,
                            event.stream_id,
                            .{
                                .status = value.response.status,
                                .headers = value.response.headers,
                            },
                        );
                    }
                    continue;
                }
                if (state.head != null) return error.UnexpectedFrame;
                state.head = value.response;
                event.value = .finished;
            },
            .data_available => {
                var chunk: [4096]u8 = undefined;
                while (stream_pending(context, event.push_id)) {
                    const count = try read_data(
                        context,
                        event.push_id,
                        &chunk,
                    );
                    if (count == 0) break;
                    try state.body.appendSlice(
                        allocator,
                        chunk[0..count],
                    );
                }
            },
            .trailers => |value| {
                if (state.trailers != null) return error.UnexpectedFrame;
                state.trailers = value;
                event.value = .finished;
            },
            .finished => {},
            .push_promise => return error.UnexpectedFrame,
        }
        if (!stream_finished or
            stream_pending(context, event.push_id))
        {
            continue;
        }
        state.finished = true;
        return state.takeResponse(allocator);
    }
}
