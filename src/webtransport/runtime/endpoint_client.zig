//! Authenticated WebTransport Session multiplexing over one HTTP/3 connection.
//!
//! The connection remains the sole UDP reader and owns HTTP/3/QPACK state.
//! Each accepted Session owns only its response metadata, associated-stream
//! registry, and Capsule control state, so hash-map growth never moves QUIC.

const std = @import("std");
const webtransport = @import("../mod.zig");
const http3 = @import("../../http3/mod.zig");
const quic = @import("../../quic/mod.zig");
const deadline_policy = @import("../../internal/deadline.zig");
const round_robin = @import("../../internal/round_robin.zig");
const connect_headers = @import("connect/headers.zig");
const session_control = @import("session_control.zig");
const handshake_stream = @import("stream.zig");
const incremental_stream = @import("stream_incremental.zig");
const stream_association = @import("stream_association.zig");

const net = std.Io.net;

pub const Error = webtransport.Error || http3.runtime.Error ||
    quic.runtime.ReceiveTimeoutError || session_control.Error || error{
    InvalidConnect,
    InvalidSessionState,
    MessageTooLarge,
    SessionRejected,
    SessionLimitExceeded,
};
pub const TimeoutError = Error || quic.runtime.ReceiveTimeoutError;

pub const Options = struct {
    limits: http3.runtime.Limits = .{},
    h3: http3.runtime.HandshakeClientOptions,
    /// Local memory/admission bound independent of the server SETTINGS value.
    max_sessions: usize = 16,
};

pub const SessionOptions = struct {
    authority: []const u8,
    path: []const u8 = "/",
    origin: []const u8 = "/",
    headers: []const http3.Qpack.HeaderField = &.{},
    max_streams: usize = 128,
    max_rejection_body_bytes: usize = 1024 * 1024,
};

pub const Rejection = struct {
    response: http3.DecodedResponseHead,
    body: []u8,
    trailers: []http3.Qpack.HeaderField,

    pub fn status(self: Rejection) u16 {
        return self.response.status;
    }

    pub fn header(self: Rejection, name: []const u8) ?[]const u8 {
        return findHeader(self.response.headers, name);
    }

    pub fn deinit(self: *Rejection, allocator: std.mem.Allocator) void {
        self.response.deinit(allocator);
        allocator.free(self.body);
        http3.Qpack.freeDecodedFields(allocator, self.trailers);
        self.* = undefined;
    }
};

pub const OpenResult = union(enum) {
    accepted: *Session,
    rejected: Rejection,

    pub fn deinit(self: *OpenResult, client: *Client) void {
        switch (self.*) {
            .accepted => {},
            .rejected => |*value| value.deinit(client.allocator),
        }
        self.* = undefined;
    }
};

pub const Event = union(enum) {
    stream: incremental_stream.Read,
    datagram: http3.runtime.OwnedConnectDatagram,
    session: session_control.Event,

    pub fn deinit(self: *Event, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .datagram => |*value| value.deinit(allocator),
            .stream, .session => {},
        }
        self.* = undefined;
    }
};

pub const AnyEvent = struct {
    session_id: webtransport.SessionId,
    event: Event,

    pub fn deinit(self: *AnyEvent, allocator: std.mem.Allocator) void {
        self.event.deinit(allocator);
        self.* = undefined;
    }
};

pub const Session = struct {
    session_id: webtransport.SessionId,
    response: http3.DecodedResponseHead,
    streams: webtransport.StreamRegistry,
    control: session_control.Control,
    close_response_pending: bool = false,

    pub fn id(self: Session) webtransport.SessionId {
        return self.session_id;
    }

    pub fn responseHeader(self: Session, name: []const u8) ?[]const u8 {
        return findHeader(self.response.headers, name);
    }

    pub fn stableId(
        self: *Session,
        client: *Client,
    ) Error!quic.one_rtt.StableConnectionId {
        try self.validateOwner(client);
        return client.stableId();
    }

    fn deinit(self: *Session, client: *Client) void {
        client.h3.closeConnectDatagramAssociation(
            self.session_id.value,
        ) catch {};
        self.response.deinit(client.allocator);
        self.control.deinit();
        self.streams.deinit();
        self.* = undefined;
    }

    fn validateOwner(self: *Session, client: *Client) Error!void {
        if (client.sessions.get(self.session_id.value) != self) {
            return error.InvalidSessionState;
        }
    }

    pub fn sendDatagram(
        self: *Session,
        client: *Client,
        payload: []const u8,
    ) Error!void {
        try self.validateOwner(client);
        try self.control.ensureOpen();
        try client.h3.sendConnectDatagram(self.session_id.value, payload);
    }

    pub fn sendDatagramWithTimeout(
        self: *Session,
        client: *Client,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) TimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendDatagramWithDeadline(
            client,
            payload,
            .fromNow(client.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendDatagramWithDeadline(
        self: *Session,
        client: *Client,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) TimeoutError!void {
        try self.validateOwner(client);
        try self.control.ensureOpen();
        try client.h3.sendConnectDatagramWithDeadline(
            self.session_id.value,
            payload,
            deadline,
        );
    }

    pub fn maxDatagramPayloadSize(
        self: *Session,
        client: *Client,
    ) ?usize {
        self.validateOwner(client) catch return null;
        return client.h3.maxConnectDatagramPayloadSize(
            self.session_id.value,
        );
    }

    pub fn openBidirectionalStream(
        self: *Session,
        client: *Client,
    ) Error!u62 {
        return self.openStream(client, .bidirectional);
    }

    pub fn openUnidirectionalStream(
        self: *Session,
        client: *Client,
    ) Error!u62 {
        return self.openStream(client, .unidirectional);
    }

    fn openStream(
        self: *Session,
        client: *Client,
        direction: webtransport.StreamDirection,
    ) Error!u62 {
        try self.validateOwner(client);
        try self.control.ensureOpen();
        const connection = &client.h3.established.connection;
        const stream_id: u62 = @intCast(switch (direction) {
            .bidirectional => connection.nextLocalBidirectionalStreamId(),
            .unidirectional => connection.nextLocalUnidirectionalStreamId(),
        });
        try self.streams.prepareLocalId(stream_id, direction);
        const opened: u64 = switch (direction) {
            .bidirectional => try client.h3.openClientBidirectionalStream(),
            .unidirectional => try connection.openUnidirectionalStream(),
        };
        std.debug.assert(opened == stream_id);
        _ = try self.streams.registerLocal(stream_id, direction);
        return stream_id;
    }

    pub fn sendStream(
        self: *Session,
        client: *Client,
        stream_id: u62,
        payload: []const u8,
        fin: bool,
    ) Error!void {
        try self.validateOwner(client);
        try self.control.ensureOpen();
        try handshake_stream.send(
            &client.h3.established.connection,
            &self.streams,
            self.session_id,
            stream_id,
            payload,
            fin,
        );
    }

    pub fn sendStreamWithTimeout(
        self: *Session,
        client: *Client,
        stream_id: u62,
        payload: []const u8,
        fin: bool,
        committed: *usize,
        timeout: std.Io.Duration,
    ) TimeoutError!void {
        committed.* = 0;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendStreamWithDeadline(
            client,
            stream_id,
            payload,
            fin,
            committed,
            .fromNow(client.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendStreamWithDeadline(
        self: *Session,
        client: *Client,
        stream_id: u62,
        payload: []const u8,
        fin: bool,
        committed: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) TimeoutError!void {
        committed.* = 0;
        try self.validateOwner(client);
        try self.control.ensureOpen();
        try handshake_stream.sendWithDeadline(
            &client.h3.established.connection,
            &self.streams,
            self.session_id,
            stream_id,
            payload,
            fin,
            committed,
            deadline,
        );
    }

    pub fn resetStream(
        self: *Session,
        client: *Client,
        stream_id: u62,
        code: u32,
    ) Error!void {
        try self.validateOwner(client);
        try incremental_stream.reset(
            &client.h3.established.connection,
            &self.streams,
            stream_id,
            code,
        );
    }

    pub fn stopStream(
        self: *Session,
        client: *Client,
        stream_id: u62,
        code: u32,
    ) Error!void {
        try self.validateOwner(client);
        try incremental_stream.stop(
            &client.h3.established.connection,
            &self.streams,
            stream_id,
            code,
        );
    }

    pub fn close(
        self: *Session,
        client: *Client,
        code: u32,
        reason: []const u8,
    ) Error!void {
        try self.validateOwner(client);
        if (self.control.local_close_sent or
            self.control.local_close_failed) return;
        var storage: [4 + session_control.max_close_reason + 16]u8 = undefined;
        const encoded = try session_control.writeCloseInto(
            &storage,
            code,
            reason,
        );
        try self.control.beginLocalClose();
        client.h3.sendRequestBodyPaced(
            self.session_id.value,
            encoded,
            true,
        ) catch |err| {
            self.control.recordLocalCloseFailure(code);
            return err;
        };
        try self.control.recordLocalClose(code);
    }
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    h3: http3.runtime.HandshakeClient,
    max_sessions: usize,
    sessions: std.AutoHashMapUnmanaged(u62, *Session) = .empty,
    last_ready_session_id: ?u62 = null,

    pub fn connect(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: Options,
    ) Error!Client {
        if (options.max_sessions == 0) return error.InvalidSessionState;
        const h3_options = resolvedH3Options(options.h3);
        return .{
            .allocator = allocator,
            .h3 = try http3.runtime.HandshakeClient.connect(
                allocator,
                io,
                local_address,
                server,
                options.limits,
                h3_options,
            ),
            .max_sessions = options.max_sessions,
        };
    }

    pub fn connectWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: Options,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Client {
        if (options.max_sessions == 0) return error.InvalidSessionState;
        return .{
            .allocator = allocator,
            .h3 = try http3.runtime.HandshakeClient.connectWithDeadline(
                allocator,
                io,
                local_address,
                server,
                options.limits,
                resolvedH3Options(options.h3),
                deadline,
            ),
            .max_sessions = options.max_sessions,
        };
    }

    pub fn connectWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: Options,
        timeout: std.Io.Duration,
    ) Error!Client {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectWithDeadline(
            allocator,
            io,
            local_address,
            server,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn deinit(self: *Client) void {
        var iterator = self.sessions.valueIterator();
        while (iterator.next()) |entry| {
            entry.*.deinit(self);
            self.allocator.destroy(entry.*);
        }
        self.sessions.deinit(self.allocator);
        self.h3.deinit();
        self.* = undefined;
    }

    pub fn session(
        self: *Client,
        session_id: webtransport.SessionId,
    ) ?*Session {
        return self.sessions.get(session_id.value);
    }

    pub fn sessionCount(self: *const Client) usize {
        return self.sessions.count();
    }

    pub fn address(self: Client) net.IpAddress {
        return self.h3.address();
    }

    pub fn remoteAddress(self: Client) net.IpAddress {
        return self.h3.established.connection.peerAddress();
    }

    pub fn stableId(self: *const Client) quic.one_rtt.StableConnectionId {
        return self.h3.established.connection.stableId();
    }

    pub fn remoteAddressValidated(self: Client) bool {
        return self.h3.established.connection.peerAddressValidated();
    }

    pub fn rttNanos(self: Client) ?u64 {
        return self.h3.established.connection.stats().smoothed_rtt_ns;
    }

    pub fn stats(self: Client) quic.one_rtt.ConnectionStats {
        return self.h3.established.connection.stats();
    }

    pub fn exportKeyingMaterial(
        self: *const Client,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        try self.h3.exportKeyingMaterial(label, context, out);
    }

    pub fn peerCertificates(self: *const Client) ?[]const []const u8 {
        return self.h3.peerCertificates();
    }

    pub fn negotiatedAlpn(self: Client) []const u8 {
        return self.h3.negotiatedAlpn();
    }

    pub fn initiateKeyUpdate(self: *Client) Error!void {
        try self.h3.initiateKeyUpdate();
    }

    pub fn closeConnection(
        self: *Client,
        application_error_code: u62,
        reason: []const u8,
    ) Error!void {
        try self.h3.closeConnection(application_error_code, reason);
    }

    pub fn openSession(
        self: *Client,
        options: SessionOptions,
    ) Error!*Session {
        var result = try self.openSessionAttempt(options);
        return self.requireAcceptedResult(&result);
    }

    pub fn openSessionWithDeadline(
        self: *Client,
        options: SessionOptions,
        deadline: std.Io.Clock.Timestamp,
    ) TimeoutError!*Session {
        var result = try self.openSessionAttemptWithDeadline(
            options,
            deadline,
        );
        return self.requireAcceptedResult(&result);
    }

    pub fn openSessionWithTimeout(
        self: *Client,
        options: SessionOptions,
        timeout: std.Io.Duration,
    ) TimeoutError!*Session {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.openSessionWithDeadline(
            options,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    fn requireAcceptedResult(
        self: *Client,
        result: *OpenResult,
    ) Error!*Session {
        return switch (result.*) {
            .accepted => |session_value| session_value,
            .rejected => |*rejection| {
                rejection.deinit(self.allocator);
                return error.SessionRejected;
            },
        };
    }

    pub fn openSessionAttempt(
        self: *Client,
        options: SessionOptions,
    ) Error!OpenResult {
        return self.openSessionAttemptBefore(options, null);
    }

    pub fn openSessionAttemptWithDeadline(
        self: *Client,
        options: SessionOptions,
        deadline: std.Io.Clock.Timestamp,
    ) TimeoutError!OpenResult {
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        return self.openSessionAttemptBefore(options, deadline);
    }

    pub fn openSessionAttemptWithTimeout(
        self: *Client,
        options: SessionOptions,
        timeout: std.Io.Duration,
    ) TimeoutError!OpenResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.openSessionAttemptWithDeadline(
            options,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    fn openSessionAttemptBefore(
        self: *Client,
        options: SessionOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) TimeoutError!OpenResult {
        try validateSessionOptions(options);
        const peer = if (self.h3.control.settings.received)
            self.h3.control.settings.peer
        else if (deadline) |absolute|
            try self.h3.receivePeerSettingsWithDeadline(absolute)
        else
            try self.h3.receivePeerSettings();
        try webtransport.ensureDatagramsNegotiated(
            self.h3.options.local_settings,
            peer,
        );
        if (self.sessions.count() >= sessionCapacity(
            self.max_sessions,
            peer.webtransport_max_sessions,
        )) {
            return error.SessionLimitExceeded;
        }

        var header_stack: [connect_headers.stack_capacity]http3.Qpack.HeaderField =
            undefined;
        var headers = try connect_headers.prepareRequest(
            self.allocator,
            options.origin,
            options.headers,
            &header_stack,
        );
        defer headers.deinit(self.allocator);
        try self.sessions.ensureUnusedCapacity(self.allocator, 1);
        const request = http3.Request{
            .method = "CONNECT",
            .path = options.path,
            .scheme = "https",
            .authority = options.authority,
            .headers = headers.fields,
        };
        const stream_id = if (deadline) |absolute|
            try self.h3.startRequestWithDeadline(request, null, absolute)
        else
            try self.h3.startRequest(request, null);
        errdefer self.h3.cancelRequest(
            stream_id,
            http3.ApplicationErrorCode.request_cancelled,
        ) catch {};
        const session_id = webtransport.SessionId.init(stream_id);
        var streams = try handshake_stream.initRegistry(
            self.allocator,
            session_id,
            .client,
            self.h3.options.local_settings,
            peer,
            options.max_streams,
            null,
            null,
        );
        errdefer streams.deinit();
        var control = try session_control.Control.init(
            self.allocator,
            session_id,
        );
        errdefer control.deinit();
        const session_value = try self.allocator.create(Session);
        errdefer self.allocator.destroy(session_value);

        var response = try self.receiveFinalResponse(stream_id, deadline);
        if (response.status < 200 or response.status >= 300) {
            const rejection = try self.receiveRejection(
                stream_id,
                response,
                options.max_rejection_body_bytes,
                deadline,
            );
            streams.deinit();
            control.deinit();
            self.allocator.destroy(session_value);
            return .{ .rejected = rejection };
        }
        errdefer response.deinit(self.allocator);
        try validateSuccessfulResponse(response);
        if (deadline) |absolute| {
            _ = try deadline_policy.usableAwake(
                self.h3.established.connection.endpoint.io,
                absolute,
            );
        }
        try self.h3.detachResponseStream(stream_id);
        session_value.* = .{
            .session_id = session_id,
            .response = response,
            .streams = streams,
            .control = control,
        };
        self.sessions.putAssumeCapacityNoClobber(stream_id, session_value);
        return .{ .accepted = session_value };
    }

    fn receiveFinalResponse(
        self: *Client,
        stream_id: u62,
        deadline: ?std.Io.Clock.Timestamp,
    ) TimeoutError!http3.DecodedResponseHead {
        while (true) {
            var event = (if (deadline) |absolute|
                try self.h3.receiveResponseEventWithDeadline(
                    stream_id,
                    absolute,
                )
            else
                try self.h3.receiveResponseEvent(stream_id)) orelse continue;
            defer event.deinit(self.allocator);
            switch (event) {
                .head => |*head| {
                    if (head.* != .response) return error.InvalidConnect;
                    if (head.response.status < 200) continue;
                    const response = head.response;
                    event = .finished;
                    return response;
                },
                else => return error.InvalidConnect,
            }
        }
    }

    fn receiveRejection(
        self: *Client,
        stream_id: u62,
        response: http3.DecodedResponseHead,
        max_body_bytes: usize,
        deadline: ?std.Io.Clock.Timestamp,
    ) TimeoutError!Rejection {
        errdefer {
            var owned = response;
            owned.deinit(self.allocator);
        }
        if ((response.content_length orelse 0) > max_body_bytes) {
            return error.MessageTooLarge;
        }
        var body: std.ArrayList(u8) = .empty;
        errdefer body.deinit(self.allocator);
        if (response.content_length) |expected| {
            try body.ensureTotalCapacityPrecise(self.allocator, expected);
        }
        var trailers: []http3.Qpack.HeaderField = &.{};
        errdefer http3.Qpack.freeDecodedFields(self.allocator, trailers);
        var scratch: [16 * 1024]u8 = undefined;
        while (true) {
            var event = (if (deadline) |absolute|
                try self.h3.receiveResponseEventWithDeadline(
                    stream_id,
                    absolute,
                )
            else
                try self.h3.receiveResponseEvent(stream_id)) orelse continue;
            defer event.deinit(self.allocator);
            switch (event) {
                .data_available => {
                    const remaining = max_body_bytes -| body.items.len;
                    const count = try self.h3.readResponseData(
                        stream_id,
                        scratch[0..@min(scratch.len, remaining +| 1)],
                    );
                    if (count > remaining) return error.MessageTooLarge;
                    try body.appendSlice(self.allocator, scratch[0..count]);
                },
                .trailers => |value| {
                    if (trailers.len != 0) return error.InvalidConnect;
                    trailers = value.fields;
                    event = .finished;
                },
                .finished => break,
                .push_promise => continue,
                .head => return error.InvalidConnect,
            }
        }
        const owned_body = if (response.content_length != null)
            body.toOwnedSliceAssert()
        else
            try body.toOwnedSlice(self.allocator);
        return .{
            .response = response,
            .body = owned_body,
            .trailers = trailers,
        };
    }

    pub fn removeSession(
        self: *Client,
        session_id: webtransport.SessionId,
    ) Error!bool {
        const current = self.sessions.get(session_id.value) orelse return false;
        if (current.close_response_pending) {
            try self.h3.sendRequestBodyPaced(
                session_id.value,
                &.{},
                true,
            );
            current.close_response_pending = false;
            current.control.local_close_sent = true;
        }
        try session_control.terminateStreams(
            &self.h3.established.connection,
            &current.streams,
        );
        const removed = self.sessions.fetchRemove(session_id.value).?.value;
        removed.deinit(self);
        self.allocator.destroy(removed);
        if (self.last_ready_session_id == session_id.value) {
            self.last_ready_session_id = null;
        }
        return true;
    }

    pub fn poll(
        self: *Client,
        session_id: webtransport.SessionId,
        stream_buffer: []u8,
    ) Error!?Event {
        if (stream_buffer.len == 0) return error.BufferTooShort;
        const session_value = self.session(session_id) orelse
            return error.InvalidSessionState;
        return self.pollSession(session_value, stream_buffer);
    }

    fn pollSession(
        self: *Client,
        session_value: *Session,
        stream_buffer: []u8,
    ) Error!?Event {
        const session_id = session_value.session_id;
        if (session_value.close_response_pending) {
            self.h3.trySendRequestBody(
                session_id.value,
                &.{},
                true,
            ) catch |err| switch (err) {
                error.PacingLimited,
                error.CongestionLimited,
                error.FlowControlBlocked,
                => return null,
                error.RequestCancelled, error.RequestRejected => {},
                else => return err,
            };
            session_value.close_response_pending = false;
            session_value.control.local_close_sent = true;
        }
        if (!session_value.control.terminal_reported) {
            const control_event = session_value.control.pollOnce(
                &self.h3.established.connection,
            ) catch |err| switch (err) {
                error.PacingLimited,
                error.CongestionLimited,
                error.FlowControlBlocked,
                => return null,
                error.InvalidCapsule => {
                    self.h3.established.connection.tryResetStream(
                        session_id.value,
                        http3.ApplicationErrorCode.message_error,
                    ) catch |reset_err| switch (reset_err) {
                        error.PacingLimited,
                        error.CongestionLimited,
                        error.FlowControlBlocked,
                        => return null,
                        else => return reset_err,
                    };
                    return err;
                },
                else => {
                    try http3.runtime.closeConnectionForProtocolError(
                        &self.h3.established.connection,
                        err,
                    );
                    return err;
                },
            };
            if (control_event) |event| {
                if (event == .closed and
                    !session_value.control.local_close_sent)
                {
                    session_value.close_response_pending = true;
                }
                return .{ .session = event };
            }
        }
        if (try incremental_stream.pollOnceShared(
            &self.h3.established.connection,
            &session_value.streams,
            session_id,
            stream_buffer,
            self.sessionLookup(),
        )) |event| return .{ .stream = event };
        if (try self.h3.pollConnectDatagram(session_id.value)) |datagram| {
            return .{ .datagram = datagram };
        }
        return null;
    }

    /// Return one already-buffered event from any active Session. The stable
    /// Session-ID cursor survives hash-map rehashes and advances only when a
    /// producer yields an event, preventing one continuously ready Session
    /// from starving its siblings.
    pub fn pollAny(
        self: *Client,
        stream_buffer: []u8,
    ) Error!?AnyEvent {
        if (stream_buffer.len == 0) return error.BufferTooShort;
        return round_robin.poll(
            u62,
            @TypeOf(self.sessions),
            AnyEvent,
            &self.sessions,
            &self.last_ready_session_id,
            .{ .client = self, .stream_buffer = stream_buffer },
            struct {
                fn run(
                    context: anytype,
                    session_id: u62,
                    session_ptr: **Session,
                ) Error!?AnyEvent {
                    const event = (try context.client.pollSession(
                        session_ptr.*,
                        context.stream_buffer,
                    )) orelse return null;
                    return .{
                        .session_id = .init(session_id),
                        .event = event,
                    };
                }
            }.run,
        );
    }

    pub fn receiveWithDeadline(
        self: *Client,
        session_id: webtransport.SessionId,
        stream_buffer: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) TimeoutError!Event {
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        while (true) {
            if (try self.poll(session_id, stream_buffer)) |event| return event;
            try self.h3.receiveDetachedResponseProgressWithDeadline(
                session_id.value,
                deadline,
            );
        }
    }

    pub fn receiveWithTimeout(
        self: *Client,
        session_id: webtransport.SessionId,
        stream_buffer: []u8,
        timeout: std.Io.Duration,
    ) TimeoutError!Event {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveWithDeadline(
            session_id,
            stream_buffer,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn receiveAnyWithDeadline(
        self: *Client,
        stream_buffer: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) TimeoutError!AnyEvent {
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        while (true) {
            if (try self.pollAny(stream_buffer)) |event| return event;
            const session_id = self.firstSessionId() orelse
                return error.InvalidSessionState;
            try self.h3.receiveDetachedResponseProgressWithDeadline(
                session_id,
                deadline,
            );
        }
    }

    pub fn receiveAnyWithTimeout(
        self: *Client,
        stream_buffer: []u8,
        timeout: std.Io.Duration,
    ) TimeoutError!AnyEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveAnyWithDeadline(
            stream_buffer,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    fn firstSessionId(self: *const Client) ?u62 {
        var iterator = self.sessions.keyIterator();
        return if (iterator.next()) |key| key.* else null;
    }

    pub const testing = struct {
        const ReadyProbe = struct {
            ready: []const u62,

            fn poll(
                self: *const ReadyProbe,
                session_id: u62,
                _: **Session,
            ) Error!?u62 {
                if (std.mem.indexOfScalar(
                    u62,
                    self.ready,
                    session_id,
                ) == null) return null;
                return session_id;
            }
        };

        pub fn pollReadySessionId(
            client: *Client,
            ready: []const u62,
        ) Error!?u62 {
            var probe = ReadyProbe{ .ready = ready };
            return round_robin.poll(
                u62,
                @TypeOf(client.sessions),
                u62,
                &client.sessions,
                &client.last_ready_session_id,
                &probe,
                ReadyProbe.poll,
            );
        }
    };

    fn sessionLookup(self: *const Client) stream_association.SessionLookup {
        return .{
            .context = self,
            .scope = 0,
            .containsFn = containsSession,
        };
    }

    fn containsSession(
        context: *const anyopaque,
        _: u64,
        session_id: u62,
    ) bool {
        const self: *const Client = @ptrCast(@alignCast(context));
        return self.sessions.contains(session_id);
    }
};

fn validateSessionOptions(options: SessionOptions) Error!void {
    if (options.authority.len == 0 or options.path.len == 0 or
        options.max_streams == 0)
    {
        return error.InvalidConnect;
    }
    try connect_headers.validate(options.headers, .request);
}

fn resolvedH3Options(
    options: http3.runtime.HandshakeClientOptions,
) http3.runtime.HandshakeClientOptions {
    var resolved = options;
    resolved.session.local_settings = webtransport.defaultSettings(
        resolved.session.local_settings,
    );
    return resolved;
}

test "WebTransport endpoint option normalization preserves resolver" {
    const Resolver = struct {
        fn resolve(
            _: *anyopaque,
            _: std.mem.Allocator,
            _: std.Io,
            _: []const u8,
            _: u16,
            _: ?std.Io.Clock.Timestamp,
        ) http3.runtime.AddressResolver.ResolveError![]net.IpAddress {
            return error.UnknownHostName;
        }
    };
    var context: u8 = 0;
    const resolved = resolvedH3Options(.{
        .handshake = .{
            .original_destination_connection_id = "origin",
            .local_connection_id = "local",
        },
        .address_resolver = .{
            .context = &context,
            .resolve = Resolver.resolve,
        },
    });
    try std.testing.expectEqual(
        @intFromPtr(&context),
        @intFromPtr(resolved.address_resolver.?.context),
    );
    try std.testing.expect(
        resolved.session.local_settings.enable_connect_protocol,
    );
}

fn sessionCapacity(local: usize, peer: u64) usize {
    const peer_capacity = std.math.cast(usize, peer) orelse
        std.math.maxInt(usize);
    return @min(local, peer_capacity);
}

test "WebTransport endpoint client uses local and peer Session minimum" {
    try std.testing.expectEqual(@as(usize, 2), sessionCapacity(2, 3));
    try std.testing.expectEqual(@as(usize, 2), sessionCapacity(3, 2));
    try std.testing.expectEqual(
        @as(usize, 4),
        sessionCapacity(4, quic.varint.max_value),
    );
}

fn validateSuccessfulResponse(
    response: http3.DecodedResponseHead,
) Error!void {
    if (response.status < 200 or response.status >= 300) {
        return error.SessionRejected;
    }
    try connect_headers.validateOptionalCapsule(response.headers);
}

fn findHeader(
    headers: []const http3.Qpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}
