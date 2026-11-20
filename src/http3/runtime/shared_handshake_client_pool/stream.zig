//! Incremental duplex transactions over a shared-pool lease.
//!
//! `Transaction` (request.zig) buffers a complete response body for the
//! dispatcher. This variant exposes the same lease/event primitives to a caller
//! that wants to write the request body and consume the response incrementally.
//! The caller owns the event loop: pump `Pool.receive*`, route every event
//! through `processEvent`, and retry writes that reported backpressure.

const std = @import("std");
const http3 = @import("../../mod.zig");
const request = @import("request.zig");

pub fn Transaction(
    comptime Runtime: type,
    comptime Pool: type,
    comptime OperationError: type,
) type {
    return struct {
        pool: *Pool,
        lease: *Pool.Lease,
        stream_id: u62,
        request_origin: http3.Origin,
        response_head: ?http3.DecodedResponseHead = null,
        response_trailers: ?http3.DecodedTrailers = null,
        response_finished: bool = false,
        active: bool = true,

        const Self = @This();

        /// Callback-scoped response view. Head and trailer fields are borrowed
        /// from the event for the duration of the callback.
        pub const Sink = struct {
            context: *anyopaque,
            begin: *const fn (
                context: *anyopaque,
                head: http3.DecodedResponseHead,
            ) anyerror!void,
            data: *const fn (
                context: *anyopaque,
                bytes: []const u8,
            ) anyerror!void,
            end: *const fn (
                context: *anyopaque,
                trailers: []const http3.Qpack.HeaderField,
            ) anyerror!void,
            informational: ?*const fn (*anyopaque, http3.DecodedResponseHead) void = null,
        };

        /// Open the request head on `lease`. Backpressure errors
        /// (`PacingLimited`, `CongestionLimited`, `FlowControlBlocked`,
        /// `StreamLimitExceeded`, `AntiAmplificationLimited`) leave the stream
        /// unopened; pump events and retry `init`.
        pub fn init(
            pool: *Pool,
            lease: *Pool.Lease,
            request_value: http3.Request,
            body_length: ?usize,
        ) OperationError!Self {
            if (!lease.active) return error.InvalidLease;
            const origin = lease.requestOrigin();
            if (!http3.sameOrigin(lease.connectionOrigin(), origin)) {
                // Cross-origin coalescing needs the certificate-identity check
                // in `Transaction.initState`; streaming callers can acquire a
                // dedicated lease instead.
                return error.InvalidOrigin;
            }
            if (lease.client().peerOriginExcluded(origin)) {
                return error.InvalidOrigin;
            }
            const stream_id = lease.tryStartRequest(
                request_value,
                body_length,
            ) catch |err| switch (err) {
                error.PacingLimited,
                error.CongestionLimited,
                error.FlowControlBlocked,
                error.StreamLimitExceeded,
                error.AntiAmplificationLimited,
                => return @errorCast(err),
                else => return @errorCast(err),
            };
            return .{
                .pool = pool,
                .lease = lease,
                .stream_id = stream_id,
                .request_origin = origin,
            };
        }

        pub fn deinit(self: *Self) void {
            if (!self.active) return;
            if (!self.response_finished and self.lease.active) {
                self.lease.tryCancelRequest(
                    self.stream_id,
                    http3.ApplicationErrorCode.request_cancelled,
                ) catch {};
            }
            if (self.response_head) |*head| head.deinit(self.pool.allocator);
            if (self.response_trailers) |*trailers| {
                trailers.deinit(self.pool.allocator);
            }
            self.active = false;
        }

        pub fn connectionHandle(self: *const Self) ?Pool.Handle {
            if (!self.active or !self.lease.active) return null;
            return self.lease.connectionHandle();
        }

        pub fn requestStreamId(self: *const Self) ?u62 {
            if (!self.active) return null;
            return self.stream_id;
        }

        /// Submit one request DATA contribution. `fin` closes the request
        /// stream. Backpressure errors mean "pump events, then retry the same
        /// contribution"; no offset is committed.
        pub fn writeBody(
            self: *Self,
            data: []const u8,
            fin: bool,
        ) OperationError!void {
            if (!self.active or !self.lease.active) {
                return error.InvalidLease;
            }
            self.lease.trySendRequestBody(
                self.stream_id,
                data,
                fin,
            ) catch |err| return @errorCast(err);
        }

        /// Submit request trailers and close the request stream.
        pub fn writeTrailers(
            self: *Self,
            trailers: []const http3.Qpack.HeaderField,
        ) OperationError!void {
            if (!self.active or !self.lease.active) {
                return error.InvalidLease;
            }
            self.lease.tryFinishRequestTrailers(
                self.stream_id,
                trailers,
            ) catch |err| return @errorCast(err);
        }

        /// Route one pool event. Events for other connections or streams are
        /// left untouched so sibling transactions can consume them.
        pub fn processEvent(
            self: *Self,
            event: *Pool.Event,
            sink: Sink,
        ) anyerror!void {
            if (!self.active or !self.lease.active) {
                return error.InvalidLease;
            }
            const handle = self.lease.connectionHandle();
            switch (event.*) {
                .response => |*response_event| {
                    if (response_event.connection_handle != handle or
                        request.responseStreamId(
                            response_event.response,
                        ) != self.stream_id)
                    {
                        return;
                    }
                    var response = response_event.response;
                    event.* = .consumed;
                    try self.processResponse(&response, sink);
                },
                .closed => |closed| {
                    if (closed.connection_handle == handle) {
                        return error.ConnectionClosed;
                    }
                },
                .progress, .push, .timer, .consumed, .unrouted => {},
            }
        }

        /// Pump pool events until the response stream finishes and return the
        /// owned head, which stays valid until `deinit`.
        pub fn readResponse(
            self: *Self,
            sink: Sink,
            deadline: ?std.Io.Clock.Timestamp,
        ) anyerror!*const http3.DecodedResponseHead {
            while (!self.response_finished) {
                var event = if (deadline) |absolute|
                    try self.pool.receiveWithDeadline(absolute)
                else
                    try self.pool.receive();
                defer event.deinit(self.pool.allocator);
                try self.processEvent(&event, sink);
            }
            return &self.response_head.?;
        }

        fn processResponse(
            self: *Self,
            response: *Runtime.StreamingResponseEvent,
            sink: Sink,
        ) anyerror!void {
            switch (response.*) {
                .reset => |reset| {
                    return if (reset.application_error_code ==
                        http3.ApplicationErrorCode.request_rejected)
                        error.RequestRejected
                    else
                        error.RequestCancelled;
                },
                .message => |*message| switch (message.value) {
                    .head => |head_value| {
                        var head = head_value;
                        if (head != .response) {
                            head.deinit(self.pool.allocator);
                            return;
                        }
                        var decoded = head.response;
                        if (decoded.status < 200) {
                            defer decoded.deinit(self.pool.allocator);
                            if (sink.informational) |observe| observe(sink.context, decoded);
                            return;
                        }
                        if (self.response_head != null or
                            self.response_finished)
                        {
                            decoded.deinit(self.pool.allocator);
                            return error.UnexpectedStream;
                        }
                        self.response_head = decoded;
                        try sink.begin(sink.context, decoded);
                    },
                    .data_available => {
                        var buffer: [16 * 1024]u8 = undefined;
                        const count = try self.pool.readResponseDataOnce(
                            self.lease.connectionHandle(),
                            self.stream_id,
                            &buffer,
                        ) orelse 0;
                        if (count != 0) {
                            try sink.data(sink.context, buffer[0..count]);
                        }
                    },
                    .trailers => |trailers_value| {
                        var trailers = trailers_value;
                        if (self.response_trailers != null) {
                            trailers.deinit(self.pool.allocator);
                            return error.InvalidHeader;
                        }
                        self.response_trailers = trailers;
                    },
                    .finished => {
                        if (self.response_head == null or
                            self.response_finished)
                        {
                            return error.UnexpectedStream;
                        }
                        const fields = if (self.response_trailers) |trailers|
                            trailers.fields
                        else
                            &.{};
                        try sink.end(sink.context, fields);
                        self.response_finished = true;
                    },
                    .push_promise => |promise_value| {
                        var promise = promise_value;
                        promise.deinit(self.pool.allocator);
                    },
                },
            }
        }
    };
}
