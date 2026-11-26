const std = @import("std");
const concurrent = @import("../concurrent.zig");
const content_coding = @import("../../../http/content_coding.zig");
const deadline_policy = @import("../../../internal/deadline.zig");
const http2 = @import("../../mod.zig");
const response_cleanup = @import("../response/cleanup.zig");
const response_trailers = @import("../response/trailers.zig");
const stream_termination = @import("../stream/termination.zig");

const runtime = @import("../../runtime.zig");
const Connection = runtime.Connection;
const DuplexData = runtime.DuplexData;
const DuplexHeaderBlock = runtime.DuplexHeaderBlock;
const DuplexHeaderBlockSlot = runtime.DuplexHeaderBlockSlot;
const DuplexResponseEvent = runtime.DuplexResponseEvent;
const DuplexWriteResult = runtime.DuplexWriteResult;
const Error = runtime.Error;
const Limits = runtime.Limits;
const OwnedTunnelData = runtime.OwnedTunnelData;
const ResponseOptions = runtime.ResponseOptions;
const ResponseTimeoutError = runtime.ResponseTimeoutError;
const RetainedFrame = runtime.RetainedFrame;
const Server = runtime.Server;
const StreamingResponseOptions = runtime.StreamingResponseOptions;
const TunnelWriteProgress = runtime.TunnelWriteProgress;
const checkedBodyLength = runtime.checkedBodyLength;
const checkedResponseBodyLength = runtime.checkedResponseBodyLength;
const flag_end_stream = runtime.flag_end_stream;
const freeHeaders = runtime.freeHeaders;
const informationalResponseToSkip = runtime.informationalResponseToSkip;
const responseForbidsBody = runtime.responseForbidsBody;
const responseHeaderLookup = runtime.responseHeaderLookup;
const validateExpectedContentLength = runtime.validateExpectedContentLength;
const validateHeaderBlock = runtime.validateHeaderBlock;

pub const ClientDuplexStream = struct {
    pub const ConnectionCreditPolicy = @import("response_capacity.zig").ConnectionCreditPolicy;
    const response_capacity = @import("response_capacity.zig").Capacity(.{
        .Error = Error,
        .automatic = Connection.releaseReceivedDataCapacityUntil,
        .update = Connection.sendWindowUpdatesUntil,
        .window = Connection.recvStreamWindow,
        .connectionTarget = Connection.receiveConnectionWindowTarget,
        .streamTarget = Connection.receiveStreamWindowTarget,
    });
    connection: *Connection,
    stream_id: u31,
    expected_request_length: ?usize,
    request_written: usize = 0,
    request_finished: bool = false,
    head_request: bool = false,
    connect_request: bool = false,
    extended_connect: bool = false,
    response_head_seen: bool = false,
    response_finished: bool = false,
    response_finished_reported: bool = false,
    response_body_bytes: usize = 0,
    response_content_length: ?usize = null,
    response_body_forbidden: bool = false,
    informational_count: usize = 0,
    // The high bit denotes automatic credit. Deferred debt is bounded by the
    // HTTP/2 31-bit stream window and fits the remaining bits.
    deferred_response_credit: u32 = 0x80000000,
    pending_header: DuplexHeaderBlockSlot = .{},
    released: bool = false,
    registered: bool = false,

    pub fn deinit(self: *ClientDuplexStream) void {
        if (!self.released) {
            if (self.request_finished and self.response_finished) {
                self.release();
            } else {
                self.reset(.cancel) catch {};
            }
        }
        self.pending_header.deinit(self.connection.allocator);
        self.releaseOwnership();
        self.* = undefined;
    }

    pub fn streamId(self: ClientDuplexStream) u31 {
        return self.stream_id;
    }

    /// Enable before response input begins. The sole connection owner keeps
    /// stream credit until an application consumer acknowledges encoded bytes.
    pub fn deferResponseStreamCredit(self: *ClientDuplexStream) Error!void {
        if (self.response_head_seen or self.response_finished) return error.UnexpectedFrame;
        self.deferred_response_credit = 0;
    }

    pub fn responseStreamCreditDeferred(self: ClientDuplexStream) bool {
        return self.deferred_response_credit != 0x80000000;
    }

    pub fn releaseResponseStreamCreditWithDeadline(self: *ClientDuplexStream, amount: usize, deadline: std.Io.Clock.Timestamp) ResponseTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return response_capacity.release(self, amount, deadline);
    }

    /// Return the amount granted, or zero when the caller should retain its
    /// consumed-byte acknowledgement until half a window accumulates.
    pub fn releaseResponseStreamCreditBatchedWithDeadline(self: *ClientDuplexStream, amount: usize, deadline: std.Io.Clock.Timestamp) ResponseTimeoutError!usize {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return response_capacity.releaseBatched(self, amount, deadline);
    }

    pub fn write(
        self: *ClientDuplexStream,
        data: []const u8,
    ) Error!DuplexWriteResult {
        return self.writeRequestSlicesUntil(&.{data}, false, null);
    }

    pub fn writeWithDeadline(
        self: *ClientDuplexStream,
        data: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!DuplexWriteResult {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.writeRequestSlicesUntil(&.{data}, false, deadline);
    }

    pub fn writeWithTimeout(
        self: *ClientDuplexStream,
        data: []const u8,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!DuplexWriteResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeWithDeadline(data, .fromNow(self.connection.io, .{
            .raw = timeout,
            .clock = .awake,
        }));
    }

    pub fn writeParts(
        self: *ClientDuplexStream,
        first: []const u8,
        second: []const u8,
    ) Error!DuplexWriteResult {
        return self.writeRequestSlices(&.{ first, second }, false);
    }

    pub fn writePartsWithTimeout(
        self: *ClientDuplexStream,
        first: []const u8,
        second: []const u8,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!DuplexWriteResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writePartsWithDeadline(
            first,
            second,
            .fromNow(self.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn writePartsWithDeadline(
        self: *ClientDuplexStream,
        first: []const u8,
        second: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!DuplexWriteResult {
        return self.writeRequestSlicesWithDeadline(
            &.{ first, second },
            false,
            deadline,
        );
    }

    pub fn finishRequest(
        self: *ClientDuplexStream,
    ) Error!DuplexWriteResult {
        return self.finishRequestData(&.{});
    }

    pub fn finishRequestWithDeadline(
        self: *ClientDuplexStream,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!DuplexWriteResult {
        return self.finishRequestDataWithDeadline(&.{}, deadline);
    }

    pub fn finishRequestWithTimeout(
        self: *ClientDuplexStream,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!DuplexWriteResult {
        return self.finishRequestDataWithTimeout(&.{}, timeout);
    }

    pub fn requestFinished(self: ClientDuplexStream) bool {
        return self.request_finished;
    }

    pub fn responseFinished(self: ClientDuplexStream) bool {
        return self.response_finished;
    }

    pub fn reset(
        self: *ClientDuplexStream,
        error_code: http2.ErrorCode,
    ) Error!void {
        if (self.released) return error.ConnectionClosed;
        defer {
            self.request_finished = true;
            self.response_finished = true;
            self.response_finished_reported = true;
            self.released = true;
            self.releaseOwnership();
        }
        if (self.connection.pending_duplex_sibling_header.getPtr()) |pending| {
            if (pending.header.stream_id == self.stream_id) self.connection.aggregate_timeout_unusable = true;
        }
        if (self.pending_header.getPtr()) |pending| {
            // Both incomplete frame input and an interrupted HPACK decode
            // lose state needed to keep the shared decoder synchronized.
            if (!pending.decode_complete) self.connection.aggregate_timeout_unusable = true;
        }
        return self.connection.terminateOwnedStream(self.stream_id, error_code);
    }

    pub fn finishRequestData(
        self: *ClientDuplexStream,
        data: []const u8,
    ) Error!DuplexWriteResult {
        return self.writeRequestSlicesUntil(&.{data}, true, null);
    }

    pub fn finishRequestDataWithDeadline(
        self: *ClientDuplexStream,
        data: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!DuplexWriteResult {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.writeRequestSlicesUntil(&.{data}, true, deadline);
    }

    pub fn finishRequestDataWithTimeout(
        self: *ClientDuplexStream,
        data: []const u8,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!DuplexWriteResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishRequestDataWithDeadline(data, .fromNow(
            self.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn finishRequestParts(
        self: *ClientDuplexStream,
        first: []const u8,
        second: []const u8,
    ) Error!DuplexWriteResult {
        return self.writeRequestSlices(&.{ first, second }, true);
    }

    pub fn finishRequestPartsWithTimeout(
        self: *ClientDuplexStream,
        first: []const u8,
        second: []const u8,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!DuplexWriteResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishRequestPartsWithDeadline(
            first,
            second,
            .fromNow(self.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn finishRequestPartsWithDeadline(
        self: *ClientDuplexStream,
        first: []const u8,
        second: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!DuplexWriteResult {
        return self.writeRequestSlicesWithDeadline(
            &.{ first, second },
            true,
            deadline,
        );
    }

    pub fn finishRequestTrailers(self: *ClientDuplexStream, trailers: []const http2.Hpack.HeaderField) Error!void {
        return self.finishRequestTrailersUntil(trailers, null);
    }

    pub fn finishRequestTrailersWithDeadline(self: *ClientDuplexStream, trailers: []const http2.Hpack.HeaderField, deadline: std.Io.Clock.Timestamp) ResponseTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.finishRequestTrailersUntil(trailers, deadline);
    }

    pub fn finishRequestTrailersWithTimeout(self: *ClientDuplexStream, trailers: []const http2.Hpack.HeaderField, timeout: std.Io.Duration) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishRequestTrailersWithDeadline(trailers, .fromNow(self.connection.io, .{ .raw = timeout, .clock = .awake }));
    }

    fn finishRequestTrailersUntil(self: *ClientDuplexStream, trailers: []const http2.Hpack.HeaderField, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (self.request_finished or self.released) {
            return error.ConnectionClosed;
        }
        if (self.expected_request_length) |expected| {
            if (self.request_written != expected) {
                return error.InvalidContentLength;
            }
        }
        try validateHeaderBlock(trailers, .request_trailers);
        try self.connection.writeHeadersUntil(self.stream_id, trailers, true, deadline);
        self.request_finished = true;
        self.maybeRelease();
    }

    pub fn writeRequestSlices(
        self: *ClientDuplexStream,
        slices: []const []const u8,
        end_stream: bool,
    ) Error!DuplexWriteResult {
        return self.writeRequestSlicesUntil(slices, end_stream, null);
    }

    pub fn writeRequestSlicesWithTimeout(
        self: *ClientDuplexStream,
        slices: []const []const u8,
        end_stream: bool,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!DuplexWriteResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeRequestSlicesWithDeadline(
            slices,
            end_stream,
            .fromNow(self.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn writeRequestSlicesWithDeadline(
        self: *ClientDuplexStream,
        slices: []const []const u8,
        end_stream: bool,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!DuplexWriteResult {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.writeRequestSlicesUntil(slices, end_stream, deadline);
    }

    /// Cumulative request DATA bytes committed by this duplex stream. This
    /// remains authoritative after a bounded write returns `error.Timeout`.
    pub fn requestCommittedBytes(self: ClientDuplexStream) usize {
        return self.request_written;
    }

    fn writeRequestSlicesUntil(
        self: *ClientDuplexStream,
        slices: []const []const u8,
        end_stream: bool,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!DuplexWriteResult {
        if (self.request_finished or self.released) {
            return error.ConnectionClosed;
        }
        if (deadline) |absolute| {
            _ = try deadline_policy.usableAwake(self.connection.io, absolute);
        }
        var additional: usize = 0;
        for (slices) |slice| {
            additional = std.math.add(usize, additional, slice.len) catch
                return error.MessageTooLarge;
        }
        const total = std.math.add(
            usize,
            self.request_written,
            additional,
        ) catch return error.MessageTooLarge;
        if (self.expected_request_length) |expected| {
            if (total > expected or (end_stream and total != expected)) {
                return error.InvalidContentLength;
            }
        }
        if (additional == 0) {
            var sent: usize = 0;
            self.connection.writeDataDuplexTrackedUntil(
                self.stream_id,
                &.{},
                end_stream,
                &sent,
                deadline,
            ) catch |err| switch (err) {
                error.ResponseAvailable => return .{
                    .written = 0,
                    .response_available = true,
                },
                else => return err,
            };
            if (end_stream) self.request_finished = true;
            self.maybeRelease();
            return .{ .written = 0, .response_available = false };
        }
        var written: usize = 0;
        var remaining_non_empty: usize = 0;
        for (slices) |slice| {
            remaining_non_empty += @intFromBool(slice.len != 0);
        }
        for (slices) |slice| {
            if (slice.len == 0) continue;
            remaining_non_empty -= 1;
            var sent: usize = 0;
            self.connection.writeDataDuplexTrackedUntil(
                self.stream_id,
                slice,
                end_stream and remaining_non_empty == 0,
                &sent,
                deadline,
            ) catch |err| switch (err) {
                error.ResponseAvailable => {
                    written += sent;
                    self.request_written += written;
                    return .{
                        .written = written,
                        .response_available = true,
                    };
                },
                else => {
                    self.request_written += written + sent;
                    return err;
                },
            };
            written += sent;
        }
        self.request_written += written;
        if (end_stream) {
            self.request_finished = true;
            self.maybeRelease();
        }
        return .{ .written = written, .response_available = false };
    }

    pub fn readResponseEvent(
        self: *ClientDuplexStream,
    ) Error!DuplexResponseEvent {
        return (try self.readResponseEventUntil(null, false)).?;
    }

    pub fn readResponseEventWithTimeout(
        self: *ClientDuplexStream,
        timeout: std.Io.Duration,
    ) Error!DuplexResponseEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return (try self.readResponseEventUntil(.fromNow(
            self.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ), false)).?;
    }

    pub fn readResponseEventWithDeadline(
        self: *ClientDuplexStream,
        deadline: std.Io.Clock.Timestamp,
    ) Error!DuplexResponseEvent {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return (try self.readResponseEventUntil(deadline, false)).?;
    }

    /// Consume only routed events. This never reads the socket; DATA may
    /// return receive credit through bounded output when a deadline is given.
    pub fn pollResponseEvent(self: *ClientDuplexStream) Error!?DuplexResponseEvent {
        return self.readResponseEventUntil(null, true);
    }

    pub fn pollResponseEventWithDeadline(self: *ClientDuplexStream, deadline: std.Io.Clock.Timestamp) Error!?DuplexResponseEvent {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.readResponseEventUntil(deadline, true);
    }

    pub fn pollResponseEventWithCreditPolicy(self: *ClientDuplexStream, policy: ConnectionCreditPolicy) Error!?DuplexResponseEvent {
        return self.readResponseEventWithCreditUntil(null, true, policy);
    }

    pub fn pollResponseEventWithCreditPolicyAndDeadline(self: *ClientDuplexStream, policy: ConnectionCreditPolicy, deadline: std.Io.Clock.Timestamp) Error!?DuplexResponseEvent {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.readResponseEventWithCreditUntil(deadline, true, policy);
    }

    /// Single-owner coordinator path after the caller has already validated
    /// this awake deadline for its current scheduler turn. Polling remains
    /// socket-free; any resulting flow-control output still receives the same
    /// absolute deadline and performs its ordinary transport checks.
    pub fn pollResponseEventWithCreditPolicyAssumeUsableDeadline(
        self: *ClientDuplexStream,
        policy: ConnectionCreditPolicy,
        deadline: std.Io.Clock.Timestamp,
    ) Error!?DuplexResponseEvent {
        std.debug.assert(deadline.clock == .awake);
        return self.readResponseEventWithCreditUntil(
            deadline,
            true,
            policy,
        );
    }

    fn nextResponseFrame(self: *ClientDuplexStream, deadline: ?std.Io.Clock.Timestamp, buffered: bool) Error!?RetainedFrame {
        if (buffered) return self.connection.pollOwnedClientDuplexFrame(self.stream_id, deadline);
        return try self.connection.readOwnedClientDuplexFrameWithDeadline(self.stream_id, deadline);
    }

    fn readResponseEventUntil(
        self: *ClientDuplexStream,
        deadline: ?std.Io.Clock.Timestamp,
        buffered: bool,
    ) Error!?DuplexResponseEvent {
        return self.readResponseEventWithCreditUntil(deadline, buffered, .immediate);
    }

    fn readResponseEventWithCreditUntil(
        self: *ClientDuplexStream,
        deadline: ?std.Io.Clock.Timestamp,
        buffered: bool,
        policy: ConnectionCreditPolicy,
    ) Error!?DuplexResponseEvent {
        if (self.response_finished_reported) {
            return error.ConnectionClosed;
        }
        if (self.response_finished) {
            self.response_finished_reported = true;
            self.maybeRelease();
            return .finished;
        }
        if (self.connection.aggregate_timeout_unusable) return error.ConnectionClosed;
        while (true) {
            if (self.connection.peer_goaway_last_stream_id) |last| {
                if (self.stream_id > last) {
                    self.connection.releaseLocalStream(self.stream_id);
                    return error.ConnectionGoAway;
                }
            }
            if (self.pending_header.getPtr()) |pending| {
                if (buffered and !pending.end_headers) return null;
                const end_stream = pending.end_stream;
                const headers = (try pending.resumeUntil(
                    self.connection,
                    deadline,
                )).?;
                self.pending_header.deinit(self.connection.allocator);
                return try self.applyResponseHeaders(headers, end_stream);
            }
            const next_frame = self.nextResponseFrame(deadline, buffered);
            var frame = (next_frame catch |err| {
                if (err != error.Timeout) {
                    if (self.connection.pending_duplex_sibling_header.getPtr()) |pending| {
                        if (pending.header.stream_id == self.stream_id) {
                            self.pending_header.put(.{
                                .stream_id = self.stream_id,
                                .end_stream = pending.header.end_stream,
                                .end_headers = pending.header.end_headers,
                                .decode_complete = pending.header.decode_complete,
                            });
                        }
                    }
                }
                return err;
            }) orelse return null;
            var frame_owned = true;
            defer if (frame_owned) frame.deinit(self.connection.allocator);
            if (try self.connection.handleConnectionFrameUntil(frame.frame, deadline)) continue;
            if (frame.frame.header.frame_type == .goaway) {
                const goaway = try http2.GoAwayPayload.parse(frame.frame);
                try self.connection.handleGoAwayForStream(self.stream_id, goaway);
                continue;
            }
            if (frame.frame.header.stream_id != self.stream_id) {
                try self.connection.queueDuplexSiblingFrameUntil(frame);
                frame_owned = false;
                continue;
            }
            switch (frame.frame.header.frame_type) {
                .headers => {
                    const deferred_fields = self.connection.takeDeferredHeaderBlock(frame.frame, true, false) catch |err| {
                        if (err == error.MessageTooLarge) {
                            self.pending_header.put(.{
                                .stream_id = self.stream_id,
                                .end_stream = (frame.frame.header.flags & flag_end_stream) != 0,
                                .end_headers = true,
                                .limit_exceeded = true,
                                .decode_complete = true,
                            });
                        }
                        return err;
                    };
                    if (deferred_fields) |fields| {
                        return try self.applyResponseHeaders(fields, (frame.frame.header.flags & flag_end_stream) != 0);
                    }
                    self.pending_header.put(try DuplexHeaderBlock.init(
                        self.connection,
                        frame.frame,
                    ));
                    const pending = self.pending_header.getPtr().?;
                    const end_stream = pending.end_stream;
                    const headers = (try pending.resumeUntil(
                        self.connection,
                        deadline,
                    )).?;
                    self.pending_header.deinit(self.connection.allocator);
                    return try self.applyResponseHeaders(headers, end_stream);
                },
                .data => {
                    if (!self.response_head_seen) return error.UnexpectedFrame;
                    const payload = try self.connection.receiveDataPayload(
                        self.stream_id,
                        frame.frame,
                    );
                    defer self.connection.releaseDataFrameBudget(payload);
                    const end_stream =
                        (frame.frame.header.flags & flag_end_stream) != 0;
                    self.response_body_bytes = checkedResponseBodyLength(
                        self.response_content_length,
                        self.response_body_bytes,
                        payload.data.len,
                        self.connection.limits.max_body_bytes,
                        !self.response_body_forbidden,
                        end_stream,
                    ) catch |err| {
                        self.connection.releaseConnectionCapacityUntil(
                            frame.frame.payload.len,
                            deadline,
                        ) catch {
                            self.connection.aggregate_timeout_unusable = true;
                            self.connection.terminal_write_failed = true;
                            // The failed write rolled back its window grant.
                            // Retire the consumed bytes locally during unwind.
                            self.connection.recv_connection_window.update(@intCast(frame.frame.payload.len)) catch {};
                        };
                        return @errorCast(err);
                    };
                    if (end_stream) {
                        self.response_finished = true;
                        self.maybeRelease();
                    }
                    if (payload.data.len == 0) {
                        try response_capacity.receiveWithPolicy(
                            self,
                            payload,
                            end_stream,
                            deadline,
                            policy,
                        );
                        if (end_stream) {
                            self.response_finished_reported = true;
                            self.maybeRelease();
                            return .finished;
                        }
                        continue;
                    }
                    try response_capacity.receiveWithPolicy(
                        self,
                        payload,
                        end_stream,
                        deadline,
                        policy,
                    );
                    const data = payload.data;
                    frame_owned = false;
                    return .{ .data = .{ .frame = frame, .data = data } };
                },
                .rst_stream => {
                    const peer_reset = try http2.ResetStreamPayload.parse(
                        frame.frame,
                    );
                    try self.connection.recordResetStream(peer_reset);
                    self.request_finished = true;
                    self.response_finished = true;
                    self.response_finished_reported = true;
                    self.release();
                    return .{ .reset = peer_reset };
                },
                .push_promise => return error.UnexpectedFrame,
                else => return error.UnexpectedFrame,
            }
        }
    }

    fn applyResponseHeaders(
        self: *ClientDuplexStream,
        headers: []http2.Hpack.HeaderField,
        end_stream: bool,
    ) Error!DuplexResponseEvent {
        var headers_owned = true;
        errdefer if (headers_owned) {
            freeHeaders(self.connection.allocator, headers);
        };
        if (!self.response_head_seen) {
            try validateHeaderBlock(headers, .response);
            const lookup = try responseHeaderLookup(headers);
            const status_text = lookup.status orelse
                return error.MissingPseudoHeader;
            const status = std.fmt.parseInt(u16, status_text, 10) catch
                return error.InvalidStatus;
            if (informationalResponseToSkip(status)) {
                if (end_stream or lookup.content_length != null) {
                    return error.InvalidContentLength;
                }
                self.informational_count = std.math.add(
                    usize,
                    self.informational_count,
                    1,
                ) catch return error.TooManyInformationalResponses;
                if (self.informational_count >
                    self.connection.limits.max_informational_responses)
                {
                    return error.TooManyInformationalResponses;
                }
                headers_owned = false;
                return .{ .informational = .{
                    .headers = headers,
                    .status = status,
                } };
            }
            self.response_head_seen = true;
            self.response_content_length = lookup.content_length;
            self.response_body_forbidden = responseForbidsBody(
                status,
                if (self.extended_connect)
                    "CONNECT"
                else if (self.connect_request)
                    "CONNECT"
                else if (self.head_request)
                    "HEAD"
                else
                    "POST",
                self.extended_connect,
            );
            if (status == 204 and lookup.content_length != null) {
                return error.InvalidContentLength;
            }
            if (!self.response_body_forbidden and
                (lookup.content_length orelse 0) >
                    self.connection.limits.max_body_bytes)
            {
                return error.MessageTooLarge;
            }
            const traditional_connect =
                self.connect_request and !self.extended_connect;
            if (end_stream or
                (traditional_connect and status >= 200 and status < 300))
            {
                if (!self.response_body_forbidden) {
                    try validateExpectedContentLength(
                        self.response_content_length,
                        0,
                    );
                }
                self.response_finished = true;
                self.maybeRelease();
            }
            headers_owned = false;
            return .{ .head = .{
                .headers = headers,
                .status = status,
                .body_allowed = !self.response_body_forbidden,
            } };
        }
        if (!end_stream) return error.UnexpectedFrame;
        if (self.response_body_forbidden) return error.InvalidContentLength;
        try validateHeaderBlock(headers, .response_trailers);
        try validateExpectedContentLength(
            self.response_content_length,
            self.response_body_bytes,
        );
        self.response_finished = true;
        self.maybeRelease();
        headers_owned = false;
        return .{ .trailers = headers };
    }

    fn maybeRelease(self: *ClientDuplexStream) void {
        if (self.request_finished and self.response_finished) {
            // The caller may still own a DATA event whose frame allocation is
            // independent, so restoring sibling frames here is safe.
            self.release();
        }
    }

    /// Stop an upload after observing a terminal early response. The default
    /// terminal cleanup budget bounds request-half FIN (or CANCEL when FIN
    /// would violate Content-Length). Local ownership is retired on failure;
    /// the committed response remains available to its caller.
    pub fn closeRequestAfterResponse(self: *ClientDuplexStream) Error!void {
        return self.closeRequestAfterResponseUntil(response_cleanup.cleanupDeadline(self.connection, null));
    }

    pub fn closeRequestAfterResponseWithDeadline(self: *ClientDuplexStream, deadline: std.Io.Clock.Timestamp) ResponseTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.closeRequestAfterResponseUntil(deadline);
    }

    pub fn closeRequestAfterResponseWithTimeout(self: *ClientDuplexStream, timeout: std.Io.Duration) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.closeRequestAfterResponseWithDeadline(.fromNow(self.connection.io, .{ .raw = timeout, .clock = .awake }));
    }

    fn closeRequestAfterResponseUntil(self: *ClientDuplexStream, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (!self.response_finished) return error.UnexpectedFrame;
        if (self.request_finished) return;
        defer {
            self.request_finished = true;
            self.released = true;
            self.releaseOwnership();
        }
        if (self.expected_request_length) |expected| {
            if (self.request_written != expected) {
                return stream_termination.reset(self.connection, self.stream_id, http2.ErrorCode.cancel, deadline, Connection.local_stream_termination_hooks);
            }
        }
        return stream_termination.finish(self.connection, self.stream_id, deadline, Connection.local_stream_termination_hooks);
    }

    fn releaseOwnership(self: *ClientDuplexStream) void {
        if (self.registered) {
            self.connection.releaseClientDuplexOwner(self.stream_id);
            self.registered = false;
        } else {
            self.connection.refreshDuplexReaderActive();
        }
    }

    pub fn release(self: *ClientDuplexStream) void {
        if (self.released) return;
        self.connection.releaseLocalStream(self.stream_id);
        self.releaseOwnership();
        self.released = true;
    }
};

pub const DuplexRequestEvent = union(enum) {
    data: DuplexData,
    trailers: []http2.Hpack.HeaderField,
    finished,
    reset: http2.ResetStreamPayload,

    pub fn deinit(self: *DuplexRequestEvent, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .data => |*data| data.deinit(allocator),
            .trailers => |trailers| freeHeaders(allocator, trailers),
            .finished, .reset => {},
        }
        self.* = undefined;
    }
};

pub const DuplexRequestDrainResult = union(enum) {
    finished,
    reset: http2.ResetStreamPayload,
};

/// Server counterpart to `ClientDuplexStream`. Request metadata is owned by
/// this object while request DATA arrives stepwise and response DATA may be
/// written between receive steps.
pub const ServerDuplexStream = struct {
    connection: *Connection,
    registered: bool = false,
    stream_id: u31,
    headers: []http2.Hpack.HeaderField,
    method: []const u8,
    path: []const u8,
    scheme: []const u8,
    authority: ?[]const u8,
    protocol: ?[]const u8,
    priority: http2.ExtensiblePriority,
    expected_request_length: ?usize,
    /// The peer declared a request body above `Limits.max_body_bytes`. The
    /// stream is still accepted so a streaming handler can answer 413; reading
    /// the body reports `PayloadTooLarge` instead of failing the connection.
    request_body_over_limit: bool = false,
    request_body_bytes: usize = 0,
    request_finished: bool = false,
    request_finished_reported: bool = false,
    response_started: bool = false,
    response_finished: bool = false,
    response_expected_length: ?usize = null,
    response_written: usize = 0,
    pending_header: DuplexHeaderBlockSlot = .{},
    current_body: ?DuplexData = null,
    request_trailers: ?[]http2.Hpack.HeaderField = null,
    released: bool = false,

    pub fn deinit(self: *ServerDuplexStream) void {
        if (!self.released) {
            if (self.request_finished and self.response_finished) {
                self.release();
            } else {
                self.reset(.cancel) catch {};
            }
        }
        self.pending_header.deinit(self.connection.allocator);
        if (self.current_body) |*data| data.deinit(self.connection.allocator);
        if (self.request_trailers) |trailers| freeHeaders(self.connection.allocator, trailers);
        self.releaseOwnership();
        freeHeaders(self.connection.allocator, self.headers);
        self.* = undefined;
    }

    pub fn startResponse(self: *ServerDuplexStream, options: StreamingResponseOptions) Error!void {
        return self.startResponseUntil(options, null);
    }

    pub fn writeInformationalResponse(self: *ServerDuplexStream, status: u16, headers: []const http2.Hpack.HeaderField) Error!void {
        if (self.response_started or self.released) return error.UnexpectedFrame;
        try self.connection.writeInformationalResponse(self.stream_id, status, headers);
    }

    pub fn writeInformationalResponseWithDeadline(self: *ServerDuplexStream, status: u16, headers: []const http2.Hpack.HeaderField, deadline: std.Io.Clock.Timestamp) ResponseTimeoutError!void {
        if (self.response_started or self.released) return error.UnexpectedFrame;
        try self.connection.writeInformationalResponseWithDeadline(self.stream_id, status, headers, deadline);
    }

    /// Send a buffered response head and body as one logical write. The
    /// connection combines the HEADERS block and the first DATA burst when
    /// flow-control credit permits, avoiding a second tiny submission for
    /// the common hello/JSON response.
    pub fn startResponseWithBody(
        self: *ServerDuplexStream,
        options: StreamingResponseOptions,
        data: []const u8,
    ) Error!void {
        return self.startResponseWithBodyUntil(options, data, null);
    }

    /// HEADERS and DATA retain one caller-owned awake-clock deadline.
    pub fn startResponseWithBodyWithDeadline(self: *ServerDuplexStream, options: StreamingResponseOptions, data: []const u8, deadline: std.Io.Clock.Timestamp) ResponseTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.startResponseWithBodyUntil(options, data, deadline);
    }

    pub fn startResponseWithBodyWithTimeout(self: *ServerDuplexStream, options: StreamingResponseOptions, data: []const u8, timeout: std.Io.Duration) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.startResponseWithBodyWithDeadline(options, data, .fromNow(self.connection.io, .{ .raw = timeout, .clock = .awake }));
    }

    fn startResponseWithBodyUntil(self: *ServerDuplexStream, options: StreamingResponseOptions, data: []const u8, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (self.response_started or self.released) {
            return error.UnexpectedFrame;
        }
        try self.connection.writeResponseInternalUntil(self.stream_id, .{
            .status = options.status,
            .headers = options.headers,
            .body = data,
            .request_method = options.request_method,
            .extended_connect = options.extended_connect,
        }, true, deadline);
        self.response_started = true;
        self.response_finished = true;
        self.response_written = data.len;
        // `writeResponse` retires the peer stream; finish the duplex owner
        // bookkeeping without releasing the same stream twice.
        self.releaseOwnership();
        self.released = true;
    }

    pub fn startResponseWithDeadline(self: *ServerDuplexStream, options: StreamingResponseOptions, deadline: std.Io.Clock.Timestamp) ResponseTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.startResponseUntil(options, deadline);
    }

    pub fn startResponseWithTimeout(self: *ServerDuplexStream, options: StreamingResponseOptions, timeout: std.Io.Duration) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.startResponseWithDeadline(options, .fromNow(self.connection.io, .{ .raw = timeout, .clock = .awake }));
    }

    fn startResponseUntil(self: *ServerDuplexStream, options: StreamingResponseOptions, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (self.response_started or self.released) {
            return error.UnexpectedFrame;
        }
        var writer = try self.connection.startResponseInternalUntil(
            self.stream_id,
            options,
            false,
            deadline,
        );
        self.response_started = true;
        self.response_finished = writer.finished;
        self.response_expected_length = writer.expected_length;
        self.response_written = writer.written;
        writer.finished = true;
        self.maybeRelease();
    }

    /// Send one response HEADERS block carrying END_STREAM. This is the
    /// trailers-only response shape used by an early gRPC status while the
    /// request half can remain open and be drained separately.
    pub fn finishResponseHeaders(self: *ServerDuplexStream, options: ResponseOptions) Error!void {
        return self.finishResponseHeadersUntil(options, null);
    }

    pub fn finishResponseHeadersWithDeadline(self: *ServerDuplexStream, options: ResponseOptions, deadline: std.Io.Clock.Timestamp) ResponseTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.finishResponseHeadersUntil(options, deadline);
    }

    pub fn finishResponseHeadersWithTimeout(self: *ServerDuplexStream, options: ResponseOptions, timeout: std.Io.Duration) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishResponseHeadersWithDeadline(options, .fromNow(self.connection.io, .{ .raw = timeout, .clock = .awake }));
    }

    fn finishResponseHeadersUntil(self: *ServerDuplexStream, options: ResponseOptions, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (self.response_started or self.released) {
            return error.UnexpectedFrame;
        }
        if (options.body.len != 0 or options.trailers.len != 0) {
            return error.InvalidContentLength;
        }
        var response_options = options;
        response_options.request_method = self.method;
        response_options.extended_connect = self.protocol != null;
        try self.connection.writeResponseInternalUntil(
            self.stream_id,
            response_options,
            false,
            deadline,
        );
        self.response_started = true;
        self.response_finished = true;
        self.maybeRelease();
    }

    pub fn requestFinished(self: ServerDuplexStream) bool {
        return self.request_finished;
    }

    pub fn responseFinished(self: ServerDuplexStream) bool {
        return self.response_finished;
    }

    pub fn reset(
        self: *ServerDuplexStream,
        error_code: http2.ErrorCode,
    ) Error!void {
        return self.resetUntil(error_code, null);
    }

    pub fn resetWithDeadline(self: *ServerDuplexStream, error_code: http2.ErrorCode, deadline: std.Io.Clock.Timestamp) ResponseTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.resetUntil(error_code, deadline);
    }

    pub fn resetWithTimeout(self: *ServerDuplexStream, error_code: http2.ErrorCode, timeout: std.Io.Duration) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.resetWithDeadline(error_code, .fromNow(self.connection.io, .{ .raw = timeout, .clock = .awake }));
    }

    fn resetUntil(self: *ServerDuplexStream, error_code: http2.ErrorCode, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (self.released) return error.ConnectionClosed;
        defer {
            self.request_finished = true;
            self.request_finished_reported = true;
            self.response_finished = true;
            self.released = true;
            self.releaseOwnership();
        }
        if (self.pending_header.getPtr()) |pending| {
            if (!pending.decode_complete) self.connection.aggregate_timeout_unusable = true;
        }
        return if (deadline) |until|
            self.connection.terminateOwnedStreamWithDeadline(self.stream_id, error_code, until)
        else
            self.connection.terminateOwnedStream(self.stream_id, error_code);
    }

    pub fn writeResponse(
        self: *ServerDuplexStream,
        data: []const u8,
    ) Error!DuplexWriteResult {
        return self.writeResponseDataUntil(data, false, null);
    }

    pub fn writeResponseWithTimeout(
        self: *ServerDuplexStream,
        data: []const u8,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!DuplexWriteResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeResponseWithDeadline(data, .fromNow(
            self.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn writeResponseWithDeadline(
        self: *ServerDuplexStream,
        data: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!DuplexWriteResult {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.writeResponseDataUntil(data, false, deadline);
    }

    pub fn writeResponseParts(
        self: *ServerDuplexStream,
        first: []const u8,
        second: []const u8,
    ) Error!DuplexWriteResult {
        return self.writeResponseSlicesUntil(
            &.{ first, second },
            false,
            null,
        );
    }

    pub fn writeResponsePartsWithTimeout(
        self: *ServerDuplexStream,
        first: []const u8,
        second: []const u8,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!DuplexWriteResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeResponsePartsWithDeadline(
            first,
            second,
            .fromNow(self.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn writeResponsePartsWithDeadline(
        self: *ServerDuplexStream,
        first: []const u8,
        second: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!DuplexWriteResult {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.writeResponseSlicesUntil(
            &.{ first, second },
            false,
            deadline,
        );
    }

    pub fn writeResponseSlices(
        self: *ServerDuplexStream,
        slices: []const []const u8,
        end_stream: bool,
    ) Error!DuplexWriteResult {
        return self.writeResponseSlicesUntil(slices, end_stream, null);
    }

    pub fn writeResponseSlicesWithTimeout(
        self: *ServerDuplexStream,
        slices: []const []const u8,
        end_stream: bool,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!DuplexWriteResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeResponseSlicesWithDeadline(
            slices,
            end_stream,
            .fromNow(self.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn writeResponseSlicesWithDeadline(
        self: *ServerDuplexStream,
        slices: []const []const u8,
        end_stream: bool,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!DuplexWriteResult {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.writeResponseSlicesUntil(
            slices,
            end_stream,
            deadline,
        );
    }

    fn writeResponseSlicesUntil(
        self: *ServerDuplexStream,
        slices: []const []const u8,
        end_stream: bool,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!DuplexWriteResult {
        var additional: usize = 0;
        for (slices) |slice| {
            additional = std.math.add(usize, additional, slice.len) catch
                return error.MessageTooLarge;
        }
        const total = std.math.add(
            usize,
            self.response_written,
            additional,
        ) catch return error.MessageTooLarge;
        if (self.response_expected_length) |expected| {
            if (total > expected or (end_stream and total != expected)) {
                return error.InvalidContentLength;
            }
        }
        var written: usize = 0;
        var remaining_non_empty: usize = 0;
        for (slices) |slice| {
            remaining_non_empty += @intFromBool(slice.len != 0);
        }
        for (slices) |slice| {
            if (slice.len == 0) continue;
            remaining_non_empty -= 1;
            const result = try self.writeResponseDataUntil(
                slice,
                end_stream and remaining_non_empty == 0,
                deadline,
            );
            written += result.written;
            if (result.response_available) {
                return .{
                    .written = written,
                    .response_available = true,
                };
            }
        }
        if (written == 0 and end_stream) {
            const result = try self.writeResponseDataUntil(
                &.{},
                true,
                deadline,
            );
            return .{
                .written = 0,
                .response_available = result.response_available,
            };
        }
        return .{ .written = written, .response_available = false };
    }

    /// Write several borrowed DATA slices as one logical burst. The slices
    /// share one DATA frame sequence instead of producing a separate frame
    /// for each slice.
    pub fn writeResponseSlicesBurst(
        self: *ServerDuplexStream,
        slices: []const []const u8,
        end_stream: bool,
    ) Error!DuplexWriteResult {
        if (!self.response_started or self.response_finished or self.released) {
            return error.ConnectionClosed;
        }
        var additional: usize = 0;
        for (slices) |slice| {
            additional = std.math.add(usize, additional, slice.len) catch
                return error.MessageTooLarge;
        }
        const total = std.math.add(
            usize,
            self.response_written,
            additional,
        ) catch return error.MessageTooLarge;
        if (self.response_expected_length) |expected| {
            if (total > expected or (end_stream and total != expected)) {
                return error.InvalidContentLength;
            }
        }
        var sent: usize = 0;
        self.connection.writeDataSlicesPreparedTrackedUntil(
            self.stream_id,
            slices,
            end_stream,
            &sent,
            null,
        ) catch |err| switch (err) {
            error.Timeout => unreachable,
            else => {
                self.response_written += sent;
                return @errorCast(err);
            },
        };
        self.response_written += sent;
        if (end_stream) {
            self.response_finished = true;
            self.maybeRelease();
        }
        return .{ .written = sent, .response_available = false };
    }

    pub fn finishResponse(
        self: *ServerDuplexStream,
    ) Error!DuplexWriteResult {
        return self.finishResponseData(&.{});
    }

    pub fn finishResponseWithTimeout(
        self: *ServerDuplexStream,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!DuplexWriteResult {
        return self.finishResponseDataWithTimeout(&.{}, timeout);
    }

    pub fn finishResponseWithDeadline(
        self: *ServerDuplexStream,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!DuplexWriteResult {
        return self.finishResponseDataWithDeadline(&.{}, deadline);
    }

    pub fn finishResponseData(
        self: *ServerDuplexStream,
        data: []const u8,
    ) Error!DuplexWriteResult {
        return self.writeResponseDataUntil(data, true, null);
    }

    pub fn finishResponseDataWithTimeout(
        self: *ServerDuplexStream,
        data: []const u8,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!DuplexWriteResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishResponseDataWithDeadline(data, .fromNow(
            self.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn finishResponseDataWithDeadline(
        self: *ServerDuplexStream,
        data: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!DuplexWriteResult {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.writeResponseDataUntil(data, true, deadline);
    }

    /// Cumulative response DATA bytes committed by this duplex stream. This
    /// remains authoritative after a bounded write returns `error.Timeout`.
    pub fn responseCommittedBytes(self: ServerDuplexStream) usize {
        return self.response_written;
    }

    pub fn finishResponseTrailers(self: *ServerDuplexStream, trailers: []const http2.Hpack.HeaderField) Error!void {
        return self.finishResponseTrailersUntil(trailers, null);
    }

    pub fn finishResponseTrailersWithDeadline(self: *ServerDuplexStream, trailers: []const http2.Hpack.HeaderField, deadline: std.Io.Clock.Timestamp) ResponseTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.finishResponseTrailersUntil(trailers, deadline);
    }

    pub fn finishResponseTrailersWithTimeout(self: *ServerDuplexStream, trailers: []const http2.Hpack.HeaderField, timeout: std.Io.Duration) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishResponseTrailersWithDeadline(trailers, .fromNow(self.connection.io, .{ .raw = timeout, .clock = .awake }));
    }

    fn finishResponseTrailersUntil(self: *ServerDuplexStream, trailers: []const http2.Hpack.HeaderField, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (!self.response_started or self.response_finished or self.released) {
            return error.ConnectionClosed;
        }
        if (self.response_expected_length) |expected| {
            if (self.response_written != expected) {
                return error.InvalidContentLength;
            }
        }
        try validateHeaderBlock(trailers, .response_trailers);
        try self.connection.writeHeadersUntil(self.stream_id, trailers, true, deadline);
        self.response_finished = true;
        self.maybeRelease();
    }

    fn writeResponseDataUntil(
        self: *ServerDuplexStream,
        data: []const u8,
        end_stream: bool,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!DuplexWriteResult {
        if (!self.response_started or self.response_finished or self.released) {
            return error.ConnectionClosed;
        }
        const total = std.math.add(
            usize,
            self.response_written,
            data.len,
        ) catch return error.MessageTooLarge;
        if (self.response_expected_length) |expected| {
            if (total > expected or (end_stream and total != expected)) {
                return error.InvalidContentLength;
            }
        }
        var sent: usize = 0;
        self.connection.writeDataDuplexTrackedUntil(
            self.stream_id,
            data,
            end_stream,
            &sent,
            deadline,
        ) catch |err| switch (err) {
            error.ResponseAvailable => {
                self.response_written += sent;
                return .{ .written = sent, .response_available = true };
            },
            else => {
                self.response_written += sent;
                return err;
            },
        };
        self.response_written += sent;
        if (end_stream) {
            self.response_finished = true;
            self.maybeRelease();
        }
        return .{ .written = sent, .response_available = false };
    }

    /// Pull the next request-body DATA slice. The returned slice is borrowed
    /// until the following `nextBody` call or `deinit`; trailers are retained
    /// in `requestTrailers`. Returns null after END_STREAM and surfaces a peer
    /// reset as `error.StreamReset`.
    pub fn nextBody(self: *ServerDuplexStream) !?[]const u8 {
        if (self.current_body) |*data| {
            data.deinit(self.connection.allocator);
            self.current_body = null;
        }
        while (true) {
            const event = try self.readRequestEvent();
            switch (event) {
                .data => |value| {
                    self.current_body = value;
                    return self.current_body.?.data;
                },
                .trailers => |trailers| {
                    if (self.request_trailers) |old| freeHeaders(self.connection.allocator, old);
                    self.request_trailers = trailers;
                },
                .finished => return null,
                .reset => return error.StreamReset,
            }
        }
    }

    pub fn requestTrailers(self: ServerDuplexStream) ?[]const http2.Hpack.HeaderField {
        return self.request_trailers;
    }

    /// Content-decoding chain for the encoded DATA returned by `nextBody`.
    pub fn streamContentDecoder(self: ServerDuplexStream, allocator: std.mem.Allocator, options: content_coding.StreamOptions) content_coding.Error!content_coding.StreamDecoder {
        return (try content_coding.parseHeaders(self.headers)).streamDecoder(allocator, options);
    }

    pub fn readRequestEvent(
        self: *ServerDuplexStream,
    ) Error!DuplexRequestEvent {
        return (try self.readRequestEventUntil(null, false)).?;
    }

    pub fn readRequestEventWithTimeout(
        self: *ServerDuplexStream,
        timeout: std.Io.Duration,
    ) Error!DuplexRequestEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return (try self.readRequestEventUntil(.fromNow(
            self.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ), false)).?;
    }

    pub fn readRequestEventWithDeadline(
        self: *ServerDuplexStream,
        deadline: std.Io.Clock.Timestamp,
    ) Error!DuplexRequestEvent {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return (try self.readRequestEventUntil(deadline, false)).?;
    }

    /// Consume only input already routed by the shared server owner.
    pub fn pollRequestEvent(self: *ServerDuplexStream) Error!?DuplexRequestEvent {
        return self.readRequestEventUntil(null, true);
    }

    pub fn pollRequestEventWithDeadline(self: *ServerDuplexStream, deadline: std.Io.Clock.Timestamp) Error!?DuplexRequestEvent {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.readRequestEventUntil(deadline, true);
    }

    /// Discard the remaining request body after the response half has ended.
    /// The caller supplies an independent cleanup deadline; DATA still passes
    /// through normal HTTP/2 validation and flow-control accounting.
    pub fn drainRequestAfterResponseWithDeadline(
        self: *ServerDuplexStream,
        deadline: std.Io.Clock.Timestamp,
    ) Error!DuplexRequestDrainResult {
        if (!self.response_finished) return error.UnexpectedFrame;
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        if (self.request_finished) return .finished;
        while (true) {
            var event = (try self.readRequestEventUntil(deadline, false)).?;
            defer event.deinit(self.connection.allocator);
            switch (event) {
                .data => if (self.request_finished) return .finished,
                .trailers, .finished => return .finished,
                .reset => |reset_value| {
                    return .{ .reset = reset_value };
                },
            }
        }
    }

    /// Wait for the peer to cancel a response that remains open after the
    /// complete request half has already been consumed. This is the server-
    /// streaming counterpart to `readRequestEvent`: connection-control and
    /// sibling-stream frames are preserved while this stream waits for its
    /// terminal RST_STREAM.
    pub fn waitForPeerReset(
        self: *ServerDuplexStream,
    ) Error!http2.ResetStreamPayload {
        return self.waitForPeerResetUntil(null);
    }

    pub fn waitForPeerResetWithTimeout(
        self: *ServerDuplexStream,
        timeout: std.Io.Duration,
    ) Error!http2.ResetStreamPayload {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.waitForPeerResetWithDeadline(.fromNow(
            self.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn waitForPeerResetWithDeadline(
        self: *ServerDuplexStream,
        deadline: std.Io.Clock.Timestamp,
    ) Error!http2.ResetStreamPayload {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.waitForPeerResetUntil(deadline);
    }

    fn waitForPeerResetUntil(
        self: *ServerDuplexStream,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!http2.ResetStreamPayload {
        if (!self.request_finished) return error.UnexpectedFrame;
        if (self.released or self.response_finished) {
            return error.ConnectionClosed;
        }
        while (true) {
            var frame = try self.connection
                .readOwnedServerDuplexFrameWithDeadline(
                self.stream_id,
                deadline,
            );
            var frame_owned = true;
            defer if (frame_owned) frame.deinit(self.connection.allocator);
            if (try self.connection.handleConnectionFrameUntil(frame.frame, deadline)) {
                continue;
            }
            if (frame.frame.header.frame_type == .goaway) continue;
            if (frame.frame.header.stream_id != self.stream_id) {
                try self.connection.queueDuplexSiblingFrameUntil(frame);
                frame_owned = false;
                continue;
            }
            if (frame.frame.header.frame_type != .rst_stream) {
                return error.UnexpectedFrame;
            }
            const peer_reset = try http2.ResetStreamPayload.parse(frame.frame);
            try self.connection.recordResetStream(peer_reset);
            self.request_finished = true;
            self.request_finished_reported = true;
            self.response_finished = true;
            self.release();
            return peer_reset;
        }
    }

    fn readRequestEventUntil(
        self: *ServerDuplexStream,
        deadline: ?std.Io.Clock.Timestamp,
        buffered: bool,
    ) Error!?DuplexRequestEvent {
        if (self.request_finished_reported) {
            return error.ConnectionClosed;
        }
        if (self.request_finished) {
            self.request_finished_reported = true;
            self.maybeRelease();
            return .finished;
        }
        while (true) {
            if (self.pending_header.getPtr()) |pending| {
                if (buffered and !pending.end_headers) return null;
                const trailers = (try pending.resumeUntil(
                    self.connection,
                    deadline,
                )).?;
                self.pending_header.deinit(self.connection.allocator);
                errdefer freeHeaders(self.connection.allocator, trailers);
                try validateHeaderBlock(trailers, .request_trailers);
                try validateExpectedContentLength(
                    self.expected_request_length,
                    self.request_body_bytes,
                );
                self.request_finished = true;
                return .{ .trailers = trailers };
            }
            const next_frame: ?RetainedFrame = if (buffered)
                try self.connection.pollOwnedServerDuplexFrame(self.stream_id)
            else
                try self.connection.readOwnedServerDuplexFrameWithDeadline(
                    self.stream_id,
                    deadline,
                );
            var frame = next_frame orelse return null;
            var frame_owned = true;
            defer if (frame_owned) frame.deinit(self.connection.allocator);
            if (try self.connection.handleConnectionFrameUntil(frame.frame, deadline)) continue;
            if (frame.frame.header.frame_type == .goaway) continue;
            if (frame.frame.header.stream_id != self.stream_id) {
                try self.connection.queueDuplexSiblingFrameUntil(frame);
                frame_owned = false;
                continue;
            }
            switch (frame.frame.header.frame_type) {
                .data => {
                    const payload = try self.connection.receiveDataPayload(
                        self.stream_id,
                        frame.frame,
                    );
                    defer self.connection.releaseDataFrameBudget(payload);
                    const end_stream =
                        (frame.frame.header.flags & flag_end_stream) != 0;
                    self.request_body_bytes = checkedBodyLength(
                        self.expected_request_length,
                        self.request_body_bytes,
                        payload.data.len,
                        self.connection.limits.max_body_bytes,
                        end_stream,
                    ) catch |err| {
                        self.connection.releaseConnectionCapacity(frame.frame.payload.len) catch {};
                        return @errorCast(err);
                    };
                    if (end_stream) {
                        self.request_finished = true;
                        self.maybeRelease();
                    }
                    if (payload.data.len == 0) {
                        try self.connection.releaseReceivedDataCapacityUntil(
                            self.stream_id,
                            payload,
                            end_stream,
                            deadline,
                        );
                        if (end_stream) {
                            self.request_finished_reported = true;
                            self.maybeRelease();
                            return .finished;
                        }
                        continue;
                    }
                    try self.connection.releaseReceivedDataCapacityUntil(
                        self.stream_id,
                        payload,
                        end_stream,
                        deadline,
                    );
                    const data = payload.data;
                    frame_owned = false;
                    return .{ .data = .{ .frame = frame, .data = data } };
                },
                .headers => {
                    if ((frame.frame.header.flags & flag_end_stream) == 0) {
                        return error.UnexpectedFrame;
                    }
                    if (try self.connection.takeDeferredHeaderBlock(
                        frame.frame,
                        true,
                        false,
                    )) |trailers| {
                        errdefer freeHeaders(
                            self.connection.allocator,
                            trailers,
                        );
                        try validateHeaderBlock(
                            trailers,
                            .request_trailers,
                        );
                        try validateExpectedContentLength(
                            self.expected_request_length,
                            self.request_body_bytes,
                        );
                        self.request_finished = true;
                        self.maybeRelease();
                        return .{ .trailers = trailers };
                    }
                    self.pending_header.put(try DuplexHeaderBlock.init(
                        self.connection,
                        frame.frame,
                    ));
                    const pending = self.pending_header.getPtr().?;
                    const trailers = (try pending.resumeUntil(
                        self.connection,
                        deadline,
                    )).?;
                    self.pending_header.deinit(self.connection.allocator);
                    errdefer freeHeaders(self.connection.allocator, trailers);
                    try validateHeaderBlock(trailers, .request_trailers);
                    try validateExpectedContentLength(
                        self.expected_request_length,
                        self.request_body_bytes,
                    );
                    self.request_finished = true;
                    self.maybeRelease();
                    return .{ .trailers = trailers };
                },
                .rst_stream => {
                    const peer_reset = try http2.ResetStreamPayload.parse(
                        frame.frame,
                    );
                    try self.connection.recordResetStream(peer_reset);
                    self.request_finished = true;
                    self.request_finished_reported = true;
                    self.response_finished = true;
                    self.release();
                    return .{ .reset = peer_reset };
                },
                else => return error.UnexpectedFrame,
            }
        }
    }

    fn maybeRelease(self: *ServerDuplexStream) void {
        if (self.request_finished and self.response_finished) {
            self.release();
        }
    }

    pub fn release(self: *ServerDuplexStream) void {
        if (self.released) return;
        self.connection.releasePeerStream(self.stream_id);
        self.releaseOwnership();
        self.released = true;
    }

    fn releaseOwnership(self: *ServerDuplexStream) void {
        if (self.registered) {
            self.connection.releaseServerDuplexOwner(self.stream_id);
            self.registered = false;
        } else {
            self.connection.refreshDuplexReaderActive();
        }
    }
};

pub const Tunnel = struct {
    connection: *Connection,
    stream_id: u31,
    /// RFC 9113 counts open and either half-closed state against the
    /// concurrent-stream limit. Atomics preserve Tunnel's documented split
    /// reader/writer use while allowing exactly one side to release state.
    send_finished: std.atomic.Value(bool) = .init(false),
    receive_finished: std.atomic.Value(bool) = .init(false),
    released: std.atomic.Value(bool) = .init(false),

    pub fn write(self: *Tunnel, data: []const u8, end_stream: bool) Error!void {
        var progress: TunnelWriteProgress = .{};
        return self.writeSlicesUntil(
            &.{data},
            end_stream,
            &progress,
            null,
            false,
        ) catch |err| switch (err) {
            error.Timeout => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn writeWithTimeout(
        self: *Tunnel,
        data: []const u8,
        end_stream: bool,
        progress: *TunnelWriteProgress,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeWithDeadline(
            data,
            end_stream,
            progress,
            .fromNow(self.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn writeWithDeadline(
        self: *Tunnel,
        data: []const u8,
        end_stream: bool,
        progress: *TunnelWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.writeSlicesUntil(
            &.{data},
            end_stream,
            progress,
            deadline,
            false,
        );
    }

    /// Write two borrowed slices as one ordered tunnel byte sequence. DATA
    /// frame boundaries and flow-control bursts may cross the slice join; the
    /// caller must retain both slices until this synchronous call returns.
    pub fn writeParts(
        self: *Tunnel,
        first: []const u8,
        second: []const u8,
        end_stream: bool,
    ) Error!void {
        return self.writeSlices(&.{ first, second }, end_stream);
    }

    pub fn writePartsWithTimeout(
        self: *Tunnel,
        first: []const u8,
        second: []const u8,
        end_stream: bool,
        progress: *TunnelWriteProgress,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writePartsWithDeadline(
            first,
            second,
            end_stream,
            progress,
            .fromNow(self.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn writePartsWithDeadline(
        self: *Tunnel,
        first: []const u8,
        second: []const u8,
        end_stream: bool,
        progress: *TunnelWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        return self.writeSlicesWithDeadline(
            &.{ first, second },
            end_stream,
            progress,
            deadline,
        );
    }

    /// Write borrowed slices as one ordered tunnel byte sequence. The HTTP/2
    /// DATA framing layer may split or combine ranges at frame and flow-control
    /// boundaries without copying their contents.
    pub fn writeSlices(
        self: *Tunnel,
        slices: []const []const u8,
        end_stream: bool,
    ) Error!void {
        var progress: TunnelWriteProgress = .{};
        return self.writeSlicesUntil(
            slices,
            end_stream,
            &progress,
            null,
            false,
        ) catch |err| switch (err) {
            error.Timeout => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn writeSlicesWithTimeout(
        self: *Tunnel,
        slices: []const []const u8,
        end_stream: bool,
        progress: *TunnelWriteProgress,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeSlicesWithDeadline(
            slices,
            end_stream,
            progress,
            .fromNow(self.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn writeSlicesWithDeadline(
        self: *Tunnel,
        slices: []const []const u8,
        end_stream: bool,
        progress: *TunnelWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.writeSlicesUntil(
            slices,
            end_stream,
            progress,
            deadline,
            false,
        );
    }

    /// Begin one logical multi-call tunnel write. The initial preflight is
    /// performed once so connection-level reads needed for flow-control credit
    /// cannot turn a later chunk of the same byte sequence into
    /// `ResponseAvailable`. The returned writer borrows this tunnel and must
    /// not overlap another reader or writer on the HTTP/2 connection.
    pub fn beginWriteSequence(self: *Tunnel) Error!TunnelWriter {
        try self.ensureWritable();
        try self.connection.prepareDataWrite(self.stream_id);
        return .{ .tunnel = self };
    }

    pub fn closeWrite(self: *Tunnel) Error!void {
        return self.write(&.{}, true);
    }

    pub fn closeWriteWithTimeout(
        self: *Tunnel,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        var progress: TunnelWriteProgress = .{};
        return self.writeWithTimeout(&.{}, true, &progress, timeout);
    }

    pub fn closeWriteWithDeadline(
        self: *Tunnel,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        var progress: TunnelWriteProgress = .{};
        return self.writeWithDeadline(&.{}, true, &progress, deadline);
    }

    pub fn reset(self: *Tunnel, error_code: http2.ErrorCode) Error!void {
        if (self.released.load(.acquire)) return error.ConnectionClosed;
        defer self.finishReset();
        return self.connection.terminateOwnedStream(self.stream_id, error_code);
    }

    pub fn abort(
        self: *Tunnel,
        deadline: ?std.Io.Clock.Timestamp,
    ) void {
        if (self.released.load(.acquire)) return;
        self.connection.abortExtendedConnect(self.stream_id, deadline);
        self.finishReset();
    }

    pub fn read(self: *Tunnel) Error!OwnedTunnelData {
        return self.readWithDeadlineInternal(null);
    }

    pub fn readWithTimeout(
        self: *Tunnel,
        timeout: std.Io.Duration,
    ) Error!OwnedTunnelData {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readWithDeadlineInternal(.fromNow(
            self.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn readWithDeadline(
        self: *Tunnel,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedTunnelData {
        _ = try deadline_policy.usableAwake(self.connection.io, deadline);
        return self.readWithDeadlineInternal(deadline);
    }

    fn readWithDeadlineInternal(
        self: *Tunnel,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!OwnedTunnelData {
        if (self.receive_finished.load(.acquire)) {
            return error.ConnectionClosed;
        }
        if (self.connection.duplex_reader_active) {
            return error.UnexpectedFrame;
        }
        self.connection.duplex_reader_active = true;
        defer self.connection.duplex_reader_active = false;

        // A previous tunnel read yielded after preserving another stream's
        // frame. Let that stream's ordinary reader make progress before this
        // tunnel consumes more bytes from the shared connection.
        if (self.connection.pendingApplicationFrameCount() != 0 and
            !self.connection.pending_duplex_sibling_header.hasValue())
        {
            return error.ResponseAvailable;
        }
        while (true) {
            var frame = try self.connection
                .readOwnedFrameForDuplexWithDeadline(deadline);
            var frame_owned = true;
            defer if (frame_owned) {
                frame.deinit(self.connection.allocator);
            };
            if (try self.connection.handleConnectionFrameUntil(frame.frame, deadline)) {
                frame.deinit(self.connection.allocator);
                frame_owned = false;
                continue;
            }
            if (frame.frame.header.frame_type == .goaway) {
                const goaway = try http2.GoAwayPayload.parse(frame.frame);
                try self.connection.handleGoAwayForStream(self.stream_id, goaway);
                frame.deinit(self.connection.allocator);
                frame_owned = false;
                continue;
            }
            if (frame.frame.header.stream_id != self.stream_id) {
                try self.connection.queueDuplexSiblingFrameUntil(frame);
                frame_owned = false;
                // Keep consuming an uninterrupted HEADERS/CONTINUATION block
                // so HPACK advances in wire order before handing the sibling
                // stream back to an ordinary request/response reader.
                if (self.connection.pending_duplex_sibling_header.hasValue()) {
                    continue;
                }
                return error.ResponseAvailable;
            }
            switch (frame.frame.header.frame_type) {
                .data => {
                    const payload = try self.connection.receiveDataPayload(self.stream_id, frame.frame);
                    defer self.connection.releaseDataFrameBudget(payload);
                    const end_stream = (frame.frame.header.flags & flag_end_stream) != 0;
                    try self.connection.releaseReceivedDataCapacityUntil(
                        self.stream_id,
                        payload,
                        end_stream,
                        deadline,
                    );
                    if (payload.data.len == 0 and !end_stream) {
                        frame.deinit(self.connection.allocator);
                        frame_owned = false;
                        continue;
                    }
                    if (end_stream) self.finishReceive();
                    frame_owned = false;
                    return .{
                        .frame = frame,
                        .data = payload.data,
                        .end_stream = end_stream,
                    };
                },
                .rst_stream => {
                    const peer_reset = try http2.ResetStreamPayload.parse(
                        frame.frame,
                    );
                    self.connection.recordResetStream(peer_reset) catch |err| {
                        self.finishReset();
                        return err;
                    };
                    self.finishReset();
                    return error.StreamReset;
                },
                .headers => return error.UnexpectedFrame,
                else => {
                    frame.deinit(self.connection.allocator);
                    frame_owned = false;
                    continue;
                },
            }
        }
    }

    fn ensureWritable(self: *Tunnel) Error!void {
        if (self.send_finished.load(.acquire)) return error.ConnectionClosed;
        if (!self.connection.outboundStreamIsActive(self.stream_id)) {
            return error.StreamReset;
        }
    }

    fn writeSlicesUntil(
        self: *Tunnel,
        slices: []const []const u8,
        end_stream: bool,
        progress: *TunnelWriteProgress,
        deadline: ?std.Io.Clock.Timestamp,
        prepared: bool,
    ) ResponseTimeoutError!void {
        progress.* = .{};
        if (deadline) |absolute| {
            _ = try deadline_policy.usableAwake(
                self.connection.io,
                absolute,
            );
        }
        try self.ensureWritable();
        if (!prepared) try self.connection.prepareDataWrite(self.stream_id);
        self.connection.writeDataSlicesPreparedTrackedUntil(
            self.stream_id,
            slices,
            end_stream,
            &progress.committed_bytes,
            deadline,
        ) catch |err| return err;
        progress.fin_committed = end_stream;
        if (end_stream) self.finishSend();
    }

    fn finishSend(self: *Tunnel) void {
        self.send_finished.store(true, .release);
        self.maybeRelease();
    }

    fn finishReceive(self: *Tunnel) void {
        self.receive_finished.store(true, .release);
        self.maybeRelease();
    }

    fn finishReset(self: *Tunnel) void {
        self.send_finished.store(true, .release);
        self.receive_finished.store(true, .release);
        _ = self.released.swap(true, .acq_rel);
    }

    fn maybeRelease(self: *Tunnel) void {
        if (!self.send_finished.load(.acquire) or
            !self.receive_finished.load(.acquire) or
            self.released.swap(true, .acq_rel)) return;
        self.connection.releaseLocalStream(self.stream_id);
        self.connection.releasePeerStream(self.stream_id);
        self.connection.forgetStreamWindows(self.stream_id);
    }
};

pub const TunnelWriter = struct {
    tunnel: *Tunnel,

    pub fn write(
        self: *TunnelWriter,
        data: []const u8,
        end_stream: bool,
    ) Error!void {
        return self.writeSlices(&.{data}, end_stream);
    }

    pub fn writeWithTimeout(
        self: *TunnelWriter,
        data: []const u8,
        end_stream: bool,
        progress: *TunnelWriteProgress,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        return self.writeSlicesWithTimeout(
            &.{data},
            end_stream,
            progress,
            timeout,
        );
    }

    pub fn writeWithDeadline(
        self: *TunnelWriter,
        data: []const u8,
        end_stream: bool,
        progress: *TunnelWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        return self.writeSlicesWithDeadline(
            &.{data},
            end_stream,
            progress,
            deadline,
        );
    }

    pub fn writeParts(
        self: *TunnelWriter,
        first: []const u8,
        second: []const u8,
        end_stream: bool,
    ) Error!void {
        return self.writeSlices(&.{ first, second }, end_stream);
    }

    pub fn writePartsWithTimeout(
        self: *TunnelWriter,
        first: []const u8,
        second: []const u8,
        end_stream: bool,
        progress: *TunnelWriteProgress,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        return self.writeSlicesWithTimeout(
            &.{ first, second },
            end_stream,
            progress,
            timeout,
        );
    }

    pub fn writePartsWithDeadline(
        self: *TunnelWriter,
        first: []const u8,
        second: []const u8,
        end_stream: bool,
        progress: *TunnelWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        return self.writeSlicesWithDeadline(
            &.{ first, second },
            end_stream,
            progress,
            deadline,
        );
    }

    pub fn writeSlices(
        self: *TunnelWriter,
        slices: []const []const u8,
        end_stream: bool,
    ) Error!void {
        var progress: TunnelWriteProgress = .{};
        return self.tunnel.writeSlicesUntil(
            slices,
            end_stream,
            &progress,
            null,
            true,
        ) catch |err| switch (err) {
            error.Timeout => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn writeSlicesWithTimeout(
        self: *TunnelWriter,
        slices: []const []const u8,
        end_stream: bool,
        progress: *TunnelWriteProgress,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeSlicesWithDeadline(
            slices,
            end_stream,
            progress,
            .fromNow(self.tunnel.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn writeSlicesWithDeadline(
        self: *TunnelWriter,
        slices: []const []const u8,
        end_stream: bool,
        progress: *TunnelWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        return self.tunnel.writeSlicesUntil(
            slices,
            end_stream,
            progress,
            deadline,
            true,
        );
    }
};
