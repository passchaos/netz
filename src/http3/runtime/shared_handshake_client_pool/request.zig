//! One event-driven HTTP/3 request borrowing a shared-endpoint pool lease.
//!
//! Multiple transactions may borrow the same lease when one external driver
//! serializes all calls. Request URI/options remain producer-owned until the
//! send phase reaches `.response`; decoded response storage is owned here.

const std = @import("std");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const route_key = @import("../handshake_client_pool/shared/route.zig");

const request_body_chunk_bytes: usize = 512;

pub const OwnedResponse = struct {
    allocator: std.mem.Allocator,
    stream_bytes: []u8,
    response: http3.DecodedResponse,

    pub fn deinit(self: *OwnedResponse) void {
        self.response.deinit(self.allocator);
        self.allocator.free(self.stream_bytes);
        self.* = undefined;
    }
};

pub fn Transaction(
    comptime Runtime: type,
    comptime Pool: type,
    comptime OperationError: type,
) type {
    return struct {
        pool: *Pool,
        lease: *Pool.Lease,
        uri: []const u8,
        route: route_key.Key,
        request: Runtime.UriRequestOptions,
        stream_id: ?u62 = null,
        send_phase: SendPhase = .head,
        body_offset: usize = 0,
        response_head: ?http3.DecodedResponseHead = null,
        response_trailers: ?http3.DecodedTrailers = null,
        response_body: std.ArrayList(u8) = .empty,
        active: bool = true,

        const Self = @This();

        const SendPhase = enum {
            head,
            body,
            trailers,
            response,
        };

        pub fn init(
            pool: *Pool,
            lease: *Pool.Lease,
            uri: []const u8,
            request: Runtime.UriRequestOptions,
        ) OperationError!Self {
            var self = try initState(pool, lease, uri, request);
            errdefer self.deinit();
            try self.progress();
            return self;
        }

        /// Attach response processing to the request stream already committed
        /// by an accepted 0-RTT handshake. No request bytes are sent here.
        pub fn initAcceptedEarly(
            pool: *Pool,
            lease: *Pool.Lease,
            uri: []const u8,
            request: Runtime.UriRequestOptions,
        ) OperationError!Self {
            const stream_id = lease.early_stream_id orelse
                return error.UnexpectedEarlyData;
            if (lease.early_disposition == null or
                lease.early_disposition.? != .accepted)
            {
                return error.UnexpectedEarlyData;
            }
            var self = try initState(pool, lease, uri, request);
            self.stream_id = stream_id;
            self.send_phase = .response;
            return self;
        }

        fn initState(
            pool: *Pool,
            lease: *Pool.Lease,
            uri: []const u8,
            request: Runtime.UriRequestOptions,
        ) OperationError!Self {
            if (!lease.active) return error.InvalidLease;
            const route = try route_key.Key.init(uri, null, null);
            const requested_origin = route.origin();
            const connection_origin = lease.connectionOrigin();
            if (lease.client().peerOriginExcluded(requested_origin)) {
                return error.InvalidOrigin;
            }
            if (!http3.sameOrigin(connection_origin, requested_origin)) {
                if (lease.client().peerOriginSetAllows(
                    connection_origin,
                    requested_origin,
                ) != true) return error.InvalidOrigin;
                const certificates = lease.client().peerCertificates() orelse
                    return error.InvalidOrigin;
                if (certificates.len == 0) return error.InvalidOrigin;
                quic.tls.trust.verifyServerCertificateIdentity(
                    certificates[0],
                    requested_origin.host,
                ) catch return error.InvalidOrigin;
            }
            const self = Self{
                .pool = pool,
                .lease = lease,
                .uri = uri,
                .route = route,
                .request = request,
            };
            return self;
        }

        pub fn deinit(self: *Self) void {
            if (!self.active) return;
            if (self.stream_id) |stream_id| {
                if (self.lease.active) {
                    self.lease.tryCancelRequest(
                        stream_id,
                        http3.ApplicationErrorCode.request_cancelled,
                    ) catch {};
                }
            }
            self.clearResponse();
            self.response_body.deinit(self.pool.allocator);
            self.active = false;
        }

        pub fn connectionHandle(self: Self) ?usize {
            if (!self.active or !self.lease.active) return null;
            return self.lease.connectionHandle();
        }

        pub fn requestStreamId(self: Self) ?u62 {
            return self.stream_id;
        }

        pub fn sendingComplete(self: Self) bool {
            return self.send_phase == .response;
        }

        /// Retry any request head/body/trailer work previously blocked by
        /// transport flow control, congestion, pacing, or stream limits.
        pub fn progress(self: *Self) OperationError!void {
            if (!self.active or !self.lease.active) return error.InvalidLease;
            while (self.send_phase != .response) {
                switch (self.send_phase) {
                    .head => {
                        const parsed = std.Uri.parse(self.uri) catch
                            return error.InvalidUri;
                        var endpoint = try Runtime.uriEndpoint(
                            self.pool.allocator,
                            parsed,
                        );
                        defer endpoint.deinit();
                        const path = try Runtime.uriRequestTargetAlloc(
                            self.pool.allocator,
                            parsed,
                        );
                        defer self.pool.allocator.free(path);
                        const request: http3.Request = .{
                            .method = self.request.method,
                            .path = path,
                            .scheme = "https",
                            .authority = endpoint.authority,
                            .headers = self.request.headers,
                        };
                        if (self.request.body.len == 0 and
                            self.request.trailers.len == 0)
                        {
                            self.stream_id = self.lease.sendRequest(
                                request,
                            ) catch |err| {
                                if (sendBackpressure(err)) return;
                                return @errorCast(err);
                            };
                            self.send_phase = .response;
                            continue;
                        }
                        self.stream_id = self.lease.tryStartRequest(
                            request,
                            if (self.request.body.len == 0)
                                null
                            else
                                self.request.body.len,
                        ) catch |err| {
                            if (sendBackpressure(err)) return;
                            return @errorCast(err);
                        };
                        self.send_phase = if (self.request.body.len == 0)
                            .trailers
                        else
                            .body;
                    },
                    .body => {
                        const end = @min(
                            self.request.body.len,
                            self.body_offset + request_body_chunk_bytes,
                        );
                        const finished = end == self.request.body.len;
                        self.lease.trySendRequestBody(
                            self.stream_id.?,
                            self.request.body[self.body_offset..end],
                            finished and self.request.trailers.len == 0,
                        ) catch |err| {
                            if (sendBackpressure(err)) return;
                            return @errorCast(err);
                        };
                        self.body_offset = end;
                        if (finished) {
                            self.send_phase = if (self.request.trailers.len == 0)
                                .response
                            else
                                .trailers;
                        }
                    },
                    .trailers => {
                        self.lease.tryFinishRequestTrailers(
                            self.stream_id.?,
                            self.request.trailers,
                        ) catch |err| {
                            if (sendBackpressure(err)) return;
                            return @errorCast(err);
                        };
                        self.send_phase = .response;
                    },
                    .response => unreachable,
                }
            }
        }

        /// Consume a response event for this stream. Progress/timer events are
        /// intentionally left unchanged so sibling transactions borrowing the
        /// same lease may also retry their pending sends.
        pub fn processEvent(
            self: *Self,
            event: *Pool.Event,
        ) OperationError!?OwnedResponse {
            if (!self.active or !self.lease.active) return error.InvalidLease;
            const handle = self.lease.connectionHandle();
            switch (event.*) {
                .response => |response_event| {
                    if (response_event.connection_handle != handle or
                        self.stream_id == null or
                        responseStreamId(response_event.response) !=
                            self.stream_id.?)
                    {
                        return null;
                    }
                    var response = response_event.response;
                    event.* = .consumed;
                    return self.processResponseEvent(&response);
                },
                .progress => |progress_handle| {
                    if (progress_handle == handle) try self.progress();
                    return null;
                },
                .timer => |timer| {
                    if (timer.connection_handle == handle) try self.progress();
                    return null;
                },
                .closed => |closed| {
                    if (closed.connection_handle == handle) {
                        return error.ConnectionClosed;
                    }
                    return null;
                },
                .push, .consumed, .unrouted => return null,
            }
        }

        fn processResponseEvent(
            self: *Self,
            response: *Runtime.StreamingResponseEvent,
        ) OperationError!?OwnedResponse {
            switch (response.*) {
                .reset => |reset| {
                    return if (reset.application_error_code ==
                        http3.ApplicationErrorCode.request_rejected)
                        error.RequestRejected
                    else
                        error.RequestCancelled;
                },
                .message => |message| switch (message.value) {
                    .head => |head_value| {
                        var head = head_value;
                        if (head != .response) {
                            head.deinit(self.pool.allocator);
                            return null;
                        }
                        var decoded = head.response;
                        if (decoded.status < 200) {
                            decoded.deinit(self.pool.allocator);
                            return null;
                        }
                        if (self.send_phase != .response or
                            self.response_head != null)
                        {
                            decoded.deinit(self.pool.allocator);
                            return error.UnexpectedStream;
                        }
                        self.response_head = decoded;
                        return null;
                    },
                    .push_promise => |promise_value| {
                        var promise = promise_value;
                        promise.deinit(self.pool.allocator);
                        return null;
                    },
                    .data_available => {
                        try self.readAvailableBody();
                        return null;
                    },
                    .trailers => |trailers_value| {
                        var trailers = trailers_value;
                        if (self.response_trailers != null) {
                            trailers.deinit(self.pool.allocator);
                            return error.InvalidHeader;
                        }
                        self.response_trailers = trailers;
                        return null;
                    },
                    .finished => return try self.finishResponse(),
                },
            }
        }

        fn readAvailableBody(self: *Self) OperationError!void {
            const stream_id = self.stream_id orelse
                return error.UnexpectedStream;
            var storage: [4096]u8 = undefined;
            const read = (try self.pool.readResponseDataOnce(
                self.lease.connectionHandle(),
                stream_id,
                &storage,
            )) orelse return;
            if (read == 0) return;
            const max_body = self.lease.client().options.max_stream_buffer;
            if (read > max_body or
                self.response_body.items.len > max_body - read)
            {
                return error.ExcessiveLoad;
            }
            try self.response_body.appendSlice(
                self.pool.allocator,
                storage[0..read],
            );
        }

        fn finishResponse(self: *Self) OperationError!OwnedResponse {
            const head = self.response_head orelse return error.MissingStatus;
            if (head.status == 421) {
                try self.lease.client().removePeerOriginAfterMisdirected(
                    self.route.origin(),
                );
                try self.lease.refresh();
            }
            const stream_bytes = try self.pool.allocator.alloc(u8, 0);
            errdefer self.pool.allocator.free(stream_bytes);
            const body = try self.response_body.toOwnedSlice(
                self.pool.allocator,
            );
            errdefer self.pool.allocator.free(body);
            const trailers = if (self.response_trailers) |value|
                value.fields
            else
                try self.pool.allocator.alloc(http3.Qpack.HeaderField, 0);
            errdefer if (self.response_trailers == null) {
                self.pool.allocator.free(trailers);
            };
            const trailer_acknowledgments = if (self.response_trailers) |value|
                value.qpack_section_acknowledgments
            else
                0;
            self.response_head = null;
            self.response_trailers = null;
            self.response_body = .empty;
            self.active = false;
            return .{
                .allocator = self.pool.allocator,
                .stream_bytes = stream_bytes,
                .response = .{
                    .status = head.status,
                    .body_allowed = head.body_allowed,
                    .headers = head.headers,
                    .trailers = trailers,
                    .body = body,
                    .body_storage = body,
                    .consumed = 0,
                    .qpack_section_acknowledgments = head.qpack_section_acknowledgments +
                        trailer_acknowledgments,
                },
            };
        }

        fn clearResponse(self: *Self) void {
            if (self.response_head) |*head| {
                head.deinit(self.pool.allocator);
            }
            if (self.response_trailers) |*trailers| {
                trailers.deinit(self.pool.allocator);
            }
            self.response_head = null;
            self.response_trailers = null;
            self.response_body.clearRetainingCapacity();
        }
    };
}

pub fn responseStreamId(response: anytype) u62 {
    return switch (response) {
        .message => |message| message.stream_id,
        .reset => |reset| reset.stream_id,
    };
}

fn sendBackpressure(err: anyerror) bool {
    return switch (err) {
        error.PacingLimited,
        error.CongestionLimited,
        error.FlowControlBlocked,
        error.StreamLimitExceeded,
        error.AntiAmplificationLimited,
        => true,
        else => false,
    };
}
