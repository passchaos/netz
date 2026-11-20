//! One HTTP/1 streaming request exchange, including response consumption.
const std = @import("std");
const http1 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const sequence = @import("message/response_sequence.zig");
const deadline_policy = runtime.deadline_policy;
const informationalResponseToSkip = runtime.message_framing.informationalResponseToSkip;
const Error = runtime.Error;
const InformationalObserver = runtime.InformationalObserver;
const StreamingBodyWriter = runtime.StreamingBodyWriter;
const Client = runtime.Client;
const OwnedResponse = runtime.OwnedResponse;
const StreamingResponse = runtime.StreamingResponse;
const ignoreStreamingResponseHead = runtime.ignoreStreamingResponseHead;
const responseIsReusable = runtime.responseIsReusable;
const streamingResponseIsReusable = runtime.streamingResponseIsReusable;
const readResponseFromTransportBufferedForRequestObserved = runtime.readResponseFromTransportBufferedForRequestObserved;
const validateAndCountInformationalResponse = sequence.validateAndCountInformationalResponse;
const notifyInformationalResponse = sequence.notifyInformationalResponse;
const readOneResponseFromTransportBufferedForRequest = sequence.readOneResponseFromTransportBufferedForRequest;

pub const RequestWriter = struct {
    client: *Client,
    method: http1.Method,
    /// True only when the serialized HTTP/1.1 request has a body and its sole
    /// Expect value is 100-continue. This value is immutable across writer
    /// copies; the one-shot observation state lives in shared connection state.
    expects_continue: bool,
    body: StreamingBodyWriter,

    pub fn deinit(self: *RequestWriter) void {
        self.body.deinit();
    }

    pub fn write(
        self: *RequestWriter,
        data: []const u8,
    ) Error!void {
        try self.body.write(data);
    }

    pub fn writeChunks(
        self: *RequestWriter,
        chunks: []const []const u8,
    ) Error!void {
        try self.body.writeChunks(chunks);
    }

    pub fn writeWithDeadline(self: *RequestWriter, data: []const u8, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.body.writeWithDeadline(data, deadline);
    }

    pub fn writeWithTimeout(self: *RequestWriter, data: []const u8, timeout: std.Io.Duration) Error!void {
        return self.body.writeWithTimeout(data, timeout);
    }

    pub fn writeChunksWithDeadline(self: *RequestWriter, chunks: []const []const u8, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.body.writeChunksWithDeadline(chunks, deadline);
    }

    pub fn writeChunksWithTimeout(self: *RequestWriter, chunks: []const []const u8, timeout: std.Io.Duration) Error!void {
        return self.body.writeChunksWithTimeout(chunks, timeout);
    }

    pub fn finishTrailersWithDeadline(self: *RequestWriter, trailers: []const http1.Header, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.body.finishTrailersWithDeadline(trailers, deadline);
    }

    pub fn finishTrailersWithTimeout(self: *RequestWriter, trailers: []const http1.Header, timeout: std.Io.Duration) Error!void {
        return self.body.finishTrailersWithTimeout(trailers, timeout);
    }

    pub fn finishWithDeadline(self: *RequestWriter, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.body.finishWithDeadline(deadline);
    }

    pub fn finishWithTimeout(self: *RequestWriter, timeout: std.Io.Duration) Error!void {
        return self.body.finishWithTimeout(timeout);
    }

    pub fn committedBytes(self: RequestWriter) usize {
        return self.body.committedBytes();
    }

    pub fn finish(self: *RequestWriter) Error!void {
        try self.body.finish();
    }

    pub fn finishTrailers(
        self: *RequestWriter,
        trailers: []const http1.Header,
    ) Error!void {
        try self.body.finishTrailers(trailers);
    }

    /// Wait for `100 Continue` before transmitting an expected request body.
    ///
    /// Other informational responses are consumed while waiting. A final
    /// response is returned to the caller and makes the HTTP/1 connection
    /// unusable: without sending the declared request body, the connection
    /// cannot safely begin another exchange even if the peer advertises
    /// keep-alive. The returned final response is owned by the caller.
    pub fn waitForContinue(
        self: *RequestWriter,
    ) Error!ExpectContinueResult {
        return self.waitForContinueWithInformational(null);
    }

    pub fn waitForContinueWithDeadline(self: *RequestWriter, deadline: std.Io.Clock.Timestamp) Error!ExpectContinueResult {
        return self.waitForContinueWithInformationalAndDeadline(null, deadline);
    }

    pub fn waitForContinueWithTimeout(self: *RequestWriter, timeout: std.Io.Duration) Error!ExpectContinueResult {
        return self.waitForContinueWithDeadline((try deadline_policy.fromTimeout(self.client.io, timeout)).?);
    }

    pub fn waitForContinueWithInformationalAndDeadline(self: *RequestWriter, informational: ?InformationalObserver, deadline: std.Io.Clock.Timestamp) Error!ExpectContinueResult {
        _ = try deadline_policy.usableAwake(self.client.io, deadline);
        const previous = self.client.response_deadline;
        self.client.response_deadline = deadline_policy.earlier(previous, deadline);
        defer self.client.response_deadline = previous;
        return self.waitForContinueWithInformational(informational);
    }

    pub fn waitForContinueWithInformationalAndTimeout(self: *RequestWriter, informational: ?InformationalObserver, timeout: std.Io.Duration) Error!ExpectContinueResult {
        return self.waitForContinueWithInformationalAndDeadline(informational, (try deadline_policy.fromTimeout(self.client.io, timeout)).?);
    }

    /// Wait for 100 Continue while observing every preceding informational
    /// head, including the 100 response which releases the request body.
    pub fn waitForContinueWithInformational(
        self: *RequestWriter,
        informational: ?InformationalObserver,
    ) Error!ExpectContinueResult {
        try self.body.ensureExchangeActive();
        if (!self.expects_continue or
            self.body.state.expect_continue_received or
            self.body.isBodyFinished() or
            self.body.state.phase != .writing or self.body.state.written != 0)
        {
            return error.InvalidWriterState;
        }

        self.client.beginResponseHeadSequence();
        defer self.client.endResponseHeadSequence();
        while (true) {
            const response_head_deadline =
                try self.client.ensureResponseHeadDeadline();
            var response = readOneResponseFromTransportBufferedForRequest(
                self.client.allocator,
                self.client.transport(),
                self.client.limits,
                .{},
                &self.client.inbuf,
                self.method,
                response_head_deadline,
                self.client.response_deadline,
            ) catch |err| {
                self.body.fail();
                return err;
            };
            if (informationalResponseToSkip(response.response.status)) {
                validateAndCountInformationalResponse(
                    response.response,
                    self.client.limits,
                    &self.body.state.informational_responses_seen,
                ) catch |err| {
                    response.deinit(self.client.allocator);
                    self.body.fail();
                    return err;
                };
                notifyInformationalResponse(
                    informational,
                    response.response,
                );
            }
            if (response.response.status == 100) {
                response.deinit(self.client.allocator);
                self.body.state.expect_continue_received = true;
                return .proceed;
            }
            if (informationalResponseToSkip(response.response.status)) {
                response.deinit(self.client.allocator);
                continue;
            }

            // The peer rejected or otherwise answered the request before its
            // body. Transfer response ownership while retiring this writer.
            self.body.release(false);
            return .{ .final_response = response };
        }
    }

    /// Read the response and release the connection exchange slot exactly once.
    pub fn readResponse(self: *RequestWriter) Error!OwnedResponse {
        return self.readResponseWithInformational(null);
    }

    pub fn readResponseWithParseOptions(
        self: *RequestWriter,
        parse_options: http1.ParseOptions,
    ) Error!OwnedResponse {
        return self.readResponseWithParseOptionsAndInformational(
            parse_options,
            null,
        );
    }

    pub fn readResponseWithTimeout(
        self: *RequestWriter,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseWithDeadline(.fromNow(
            self.client.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn readResponseWithDeadline(
        self: *RequestWriter,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        return self.readResponseWithInformationalAndDeadline(
            null,
            deadline,
        );
    }

    pub fn readResponseWithParseOptionsAndTimeout(
        self: *RequestWriter,
        parse_options: http1.ParseOptions,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseWithParseOptionsAndDeadline(
            parse_options,
            .fromNow(self.client.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn readResponseWithParseOptionsAndDeadline(
        self: *RequestWriter,
        parse_options: http1.ParseOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        _ = try deadline_policy.usableAwake(self.client.io, deadline);
        std.debug.assert(self.client.response_deadline == null);
        self.client.response_deadline = deadline;
        defer self.client.response_deadline = null;
        return self.readResponseWithParseOptionsAndInformational(
            parse_options,
            null,
        );
    }

    pub fn readResponseWithParseOptionsAndInformationalAndTimeout(
        self: *RequestWriter,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseWithParseOptionsAndInformationalAndDeadline(
            parse_options,
            informational,
            .fromNow(self.client.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn readResponseWithParseOptionsAndInformationalAndDeadline(
        self: *RequestWriter,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        _ = try deadline_policy.usableAwake(self.client.io, deadline);
        std.debug.assert(self.client.response_deadline == null);
        self.client.response_deadline = deadline;
        defer self.client.response_deadline = null;
        return self.readResponseWithParseOptionsAndInformational(
            parse_options,
            informational,
        );
    }

    pub fn readResponseWithInformationalAndDeadline(
        self: *RequestWriter,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        _ = try deadline_policy.usableAwake(self.client.io, deadline);
        std.debug.assert(self.client.response_deadline == null);
        self.client.response_deadline = deadline;
        defer self.client.response_deadline = null;
        return self.readResponseWithInformational(informational);
    }

    pub fn readResponseWithInformationalAndTimeout(
        self: *RequestWriter,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
    ) Error!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseWithInformationalAndDeadline(
            informational,
            .fromNow(self.client.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    /// Read the final response while synchronously observing preceding 1xx
    /// heads. This is the streaming-request counterpart to
    /// `Client.requestWithInformational`.
    pub fn readResponseWithInformational(
        self: *RequestWriter,
        informational: ?InformationalObserver,
    ) Error!OwnedResponse {
        return self.readResponseWithParseOptionsAndInformational(
            .{},
            informational,
        );
    }

    pub fn readResponseWithParseOptionsAndInformational(
        self: *RequestWriter,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
    ) Error!OwnedResponse {
        try self.body.ensureExchangeActive();
        if (!self.body.isBodyFinished()) return error.InvalidWriterState;

        const response = readResponseFromTransportBufferedForRequestObserved(
            self.client.allocator,
            self.client.transport(),
            self.client.limits,
            parse_options,
            &self.client.inbuf,
            self.method,
            informational,
            &self.body.state.informational_responses_seen,
            self.client.response_deadline,
        ) catch |err| {
            self.body.fail();
            return err;
        };
        self.body.release(responseIsReusable(response.response, self.method));
        return response;
    }

    pub fn readResponseStreaming(
        self: *RequestWriter,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.readResponseStreamingWithHead(
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn readResponseStreamingWithTimeout(
        self: *RequestWriter,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseStreamingWithDeadline(
            .fromNow(self.client.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
            context,
            consume,
        );
    }

    pub fn readResponseStreamingWithDeadline(
        self: *RequestWriter,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.readResponseStreamingWithInformationalAndDeadline(
            null,
            deadline,
            context,
            consume,
        );
    }

    pub fn readResponseStreamingWithInformationalAndDeadline(
        self: *RequestWriter,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        _ = try deadline_policy.usableAwake(self.client.io, deadline);
        std.debug.assert(self.client.response_deadline == null);
        self.client.response_deadline = deadline;
        defer self.client.response_deadline = null;
        return self.readResponseStreamingWithInformational(
            informational,
            context,
            consume,
        );
    }

    pub fn readResponseStreamingWithInformationalAndTimeout(
        self: *RequestWriter,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseStreamingWithInformationalAndDeadline(
            informational,
            .fromNow(self.client.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
            context,
            consume,
        );
    }

    pub fn readResponseStreamingWithParseOptions(
        self: *RequestWriter,
        parse_options: http1.ParseOptions,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.readResponseStreamingWithOptionsAndHead(
            parse_options,
            null,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn readResponseStreamingWithParseOptionsAndInformational(
        self: *RequestWriter,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.readResponseStreamingWithOptionsAndHead(
            parse_options,
            informational,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn readResponseStreamingWithParseOptionsAndTimeout(
        self: *RequestWriter,
        parse_options: http1.ParseOptions,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseStreamingWithParseOptionsAndDeadline(
            parse_options,
            .fromNow(self.client.io, .{ .raw = timeout, .clock = .awake }),
            context,
            consume,
        );
    }

    pub fn readResponseStreamingWithParseOptionsAndDeadline(
        self: *RequestWriter,
        parse_options: http1.ParseOptions,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        _ = try deadline_policy.usableAwake(self.client.io, deadline);
        std.debug.assert(self.client.response_deadline == null);
        self.client.response_deadline = deadline;
        defer self.client.response_deadline = null;
        return self.readResponseStreamingWithOptionsAndHead(
            parse_options,
            null,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn readResponseStreamingWithParseOptionsAndInformationalAndTimeout(
        self: *RequestWriter,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseStreamingWithParseOptionsAndInformationalAndDeadline(
            parse_options,
            informational,
            .fromNow(self.client.io, .{ .raw = timeout, .clock = .awake }),
            context,
            consume,
        );
    }

    pub fn readResponseStreamingWithParseOptionsAndInformationalAndDeadline(
        self: *RequestWriter,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        _ = try deadline_policy.usableAwake(self.client.io, deadline);
        std.debug.assert(self.client.response_deadline == null);
        self.client.response_deadline = deadline;
        defer self.client.response_deadline = null;
        return self.readResponseStreamingWithOptionsAndHead(
            parse_options,
            informational,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    /// Stream the final response body while observing preceding 1xx heads.
    pub fn readResponseStreamingWithInformational(
        self: *RequestWriter,
        informational: ?InformationalObserver,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.readResponseStreamingWithInformationalAndHead(
            informational,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn readResponseStreamingWithHead(
        self: *RequestWriter,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.readResponseStreamingWithInformationalAndHead(
            null,
            context,
            begin,
            consume,
        );
    }

    pub fn readResponseStreamingWithInformationalAndHead(
        self: *RequestWriter,
        informational: ?InformationalObserver,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.readResponseStreamingWithOptionsAndHead(
            .{},
            informational,
            context,
            begin,
            consume,
        );
    }

    /// Finish the request and stream the final response under one absolute
    /// deadline while observing every interim head and the final head.
    pub fn readResponseStreamingWithInformationalAndHeadAndDeadline(
        self: *RequestWriter,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        _ = try deadline_policy.usableAwake(self.client.io, deadline);
        std.debug.assert(self.client.response_deadline == null);
        self.client.response_deadline = deadline;
        defer self.client.response_deadline = null;
        return self.readResponseStreamingWithInformationalAndHead(
            informational,
            context,
            begin,
            consume,
        );
    }

    pub fn readResponseStreamingWithInformationalAndHeadAndTimeout(
        self: *RequestWriter,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseStreamingWithInformationalAndHeadAndDeadline(
            informational,
            .fromNow(self.client.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
            context,
            begin,
            consume,
        );
    }

    pub fn readResponseStreamingWithOptionsAndHead(
        self: *RequestWriter,
        parse_options: http1.ParseOptions,
        informational: ?InformationalObserver,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        try self.body.ensureExchangeActive();
        if (!self.body.isBodyFinished()) {
            return error.InvalidWriterState;
        }
        const response = self.client.readStreamingResponse(
            self.method,
            parse_options,
            informational,
            &self.body.state.informational_responses_seen,
            context,
            begin,
            consume,
        ) catch |err| {
            self.body.fail();
            return err;
        };
        self.body.release(streamingResponseIsReusable(
            response,
            self.method,
        ));
        return response;
    }
};

pub const ExpectContinueResult = union(enum) {
    proceed,
    final_response: OwnedResponse,
};
