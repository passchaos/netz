//! Event-driven redirect transaction for the shared-endpoint HTTP/3 pool.
//!
//! The pool remains the sole UDP receive owner. A transaction consumes only
//! response/progress/timer events for its current lease and stream; every
//! unrelated event remains untouched for the caller's normal dispatcher loop.

const std = @import("std");
const http3 = @import("../../mod.zig");
const uri_redirect = @import("../../../http1/runtime/redirect.zig");
const owning_pool = @import("../handshake_client_pool.zig");

const request_body_chunk_bytes: usize = 512;

pub const OwnedResponse = struct {
    allocator: std.mem.Allocator,
    response: http3.DecodedResponse,

    pub fn deinit(self: *OwnedResponse) void {
        self.response.deinit(self.allocator);
        self.* = undefined;
    }
};

/// Final decoded response from a shared-pool redirect transaction.
///
/// Unlike the blocking owning client, the event-driven pool never retains one
/// contiguous raw HTTP/3 stream image. Decoded QPACK fields and the aggregate
/// body own their exact storage directly.
pub const RedirectedResponse = struct {
    allocator: std.mem.Allocator,
    response: OwnedResponse,
    final_uri: []u8,
    redirect_count: usize,

    pub fn deinit(self: *RedirectedResponse) void {
        const allocator = self.allocator;
        self.response.deinit();
        allocator.free(self.final_uri);
        self.* = undefined;
    }

    pub fn takeResponse(self: *RedirectedResponse) OwnedResponse {
        const response = self.response;
        self.allocator.free(self.final_uri);
        self.* = undefined;
        return response;
    }
};

pub fn Transaction(
    comptime Runtime: type,
    comptime Pool: type,
    comptime Adapter: type,
    comptime OperationError: type,
) type {
    return struct {
        pool: *Pool,
        chain: uri_redirect.Chain,
        current_uri: []u8,
        request: Runtime.UriRequestOptions,
        redirect_options: Runtime.RedirectOptions,
        deadline: ?std.Io.Clock.Timestamp,
        owned_headers: ?[]http3.Qpack.HeaderField = null,
        crossed_origin: bool = false,
        lease: ?Pool.Lease = null,
        stream_id: ?u62 = null,
        send_phase: SendPhase = .head,
        body_offset: usize = 0,
        response_head: ?http3.DecodedResponseHead = null,
        response_trailers: ?http3.DecodedTrailers = null,
        response_body: std.ArrayList(u8) = .empty,
        follow_redirect: bool = false,
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
            uri_text: []const u8,
            request: Runtime.UriRequestOptions,
            redirect_options: Runtime.RedirectOptions,
            deadline: ?std.Io.Clock.Timestamp,
        ) OperationError!Self {
            var chain = uri_redirect.Chain.init(
                pool.allocator,
                redirect_options.policy,
            );
            var chain_owned = true;
            errdefer if (chain_owned) chain.deinit();
            try chain.recordInitial(uri_text);
            const current_uri = try pool.allocator.dupe(u8, uri_text);
            var current_uri_owned = true;
            errdefer if (current_uri_owned) {
                pool.allocator.free(current_uri);
            };
            var self = Self{
                .pool = pool,
                .chain = chain,
                .current_uri = current_uri,
                .request = request,
                .redirect_options = redirect_options,
                .deadline = deadline,
            };
            chain_owned = false;
            current_uri_owned = false;
            errdefer self.deinit();
            self.lease = try Adapter.acquire(
                pool,
                current_uri,
                deadline,
                null,
            );
            try self.progressSend();
            return self;
        }

        /// Destroy an incomplete transaction. Its active lease is discarded,
        /// because a partially submitted request cannot safely return to idle.
        /// A completed transaction is consumed and `deinit` becomes a no-op.
        pub fn deinit(self: *Self) void {
            if (!self.active) return;
            if (self.lease) |*lease| lease.discard();
            self.lease = null;
            if (self.response_head) |*head| {
                head.deinit(self.pool.allocator);
            }
            if (self.response_trailers) |*trailers| {
                trailers.deinit(self.pool.allocator);
            }
            self.response_body.deinit(self.pool.allocator);
            if (self.owned_headers) |headers| {
                self.pool.allocator.free(headers);
            }
            self.pool.allocator.free(self.current_uri);
            self.chain.deinit();
            self.active = false;
        }

        pub fn connectionHandle(self: Self) ?usize {
            const lease = self.lease orelse return null;
            return lease.connectionHandle();
        }

        pub fn requestStreamId(self: Self) ?u62 {
            return self.stream_id;
        }

        /// Consume one pool event when it belongs to this transaction.
        /// Matching events are replaced with `.consumed`; unrelated events are
        /// unchanged and remain caller-owned. A non-null result consumes the
        /// transaction and owns the final response URI and message.
        pub fn processEvent(
            self: *Self,
            event: *Pool.Event,
        ) OperationError!?RedirectedResponse {
            if (!self.active) return error.InvalidLease;
            if (self.deadline) |absolute| {
                if (absolute.durationFromNow(self.pool.io).raw.nanoseconds <= 0) {
                    return error.Timeout;
                }
            }
            const handle = self.connectionHandle() orelse
                return error.InvalidLease;
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
                    if (try self.processResponseEvent(&response)) |result| {
                        return result;
                    }
                    return null;
                },
                .progress => |progress_handle| {
                    if (progress_handle != handle) return null;
                    event.* = .consumed;
                    try self.progressSend();
                    return null;
                },
                .timer => |timer| {
                    if (timer.connection_handle != handle) return null;
                    event.* = .consumed;
                    try self.progressSend();
                    return null;
                },
                .closed => |closed| {
                    if (closed.connection_handle != handle) return null;
                    event.* = .consumed;
                    return error.ConnectionClosed;
                },
                .push, .consumed, .unrouted => return null,
            }
        }

        fn processResponseEvent(
            self: *Self,
            response: *Runtime.StreamingResponseEvent,
        ) OperationError!?RedirectedResponse {
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
                            return error.InvalidStatus;
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
                        self.follow_redirect =
                            uri_redirect.isRedirectStatus(decoded.status) and
                            (try redirectLocation(decoded.headers)) != null;
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
                        if (self.follow_redirect) {
                            trailers.deinit(self.pool.allocator);
                        } else if (self.response_trailers != null) {
                            trailers.deinit(self.pool.allocator);
                            return error.InvalidHeader;
                        } else {
                            self.response_trailers = trailers;
                        }
                        return null;
                    },
                    .finished => return self.finishResponse(),
                },
            }
        }

        fn readAvailableBody(self: *Self) OperationError!void {
            const lease = if (self.lease) |*value| value else return error.InvalidLease;
            const stream_id = self.stream_id orelse
                return error.UnexpectedStream;
            var storage: [4096]u8 = undefined;
            const read = (try self.pool.readResponseDataOnce(
                lease.connectionHandle(),
                stream_id,
                &storage,
            )) orelse return;
            if (read == 0 or self.follow_redirect) return;
            const max_body = lease.client().options.max_stream_buffer;
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

        fn finishResponse(
            self: *Self,
        ) OperationError!?RedirectedResponse {
            const head = self.response_head orelse return error.MissingStatus;
            if (!self.follow_redirect) return try self.finishFinalResponse();
            const location = (try redirectLocation(head.headers)) orelse
                return try self.finishFinalResponse();
            var next = try self.chain.follow(
                self.current_uri,
                location,
                head.status,
            );
            var next_owned = true;
            defer if (next_owned) next.deinit();
            const next_uri = std.Uri.parse(next.uri) catch
                return error.InvalidUri;
            if (!std.ascii.eqlIgnoreCase(next_uri.scheme, "https")) {
                return error.InsecureRedirect;
            }
            const policy = self.redirect_options.policy;
            if (next.cross_origin) {
                try uri_redirect.enforceClientIdentityPolicy(
                    policy,
                    true,
                    self.pool.options.client.handshake.client_identity != null,
                );
                self.crossed_origin = true;
            }
            const action = uri_redirect.methodActionBytes(
                policy,
                head.status,
                self.request.method,
            );
            const remove_credentials = next.cross_origin and
                !policy.forward_cross_origin_credentials;
            self.request.headers = try redirectHeaders(
                self.pool.allocator,
                self.request.headers,
                remove_credentials,
                action == .rewrite_get,
                &self.owned_headers,
            );
            if (action == .rewrite_get) {
                self.request.method = "GET";
                self.request.body = &.{};
                self.request.trailers = &.{};
            } else if (remove_credentials) {
                self.request.trailers = &.{};
            }

            self.clearResponse();
            if (self.lease) |*lease| lease.release();
            self.lease = null;
            self.pool.allocator.free(self.current_uri);
            self.current_uri = next.uri;
            next_owned = false;
            self.stream_id = null;
            self.send_phase = .head;
            self.body_offset = 0;
            const redirect_context: ?owning_pool.RedirectConnectContext =
                if (self.crossed_origin) .{
                    .cross_origin = true,
                    .forward_client_identity = policy.allow_cross_origin_client_identity,
                } else null;
            self.lease = try Adapter.acquire(
                self.pool,
                self.current_uri,
                self.deadline,
                redirect_context,
            );
            try self.progressSend();
            return null;
        }

        fn finishFinalResponse(
            self: *Self,
        ) OperationError!RedirectedResponse {
            const final_uri = try uri_redirect.canonicalize(
                self.pool.allocator,
                self.current_uri,
            );
            errdefer self.pool.allocator.free(final_uri);
            const body = try self.pool.allocator.dupe(
                u8,
                self.response_body.items,
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
            const head = self.response_head.?;
            self.response_head = null;
            self.response_trailers = null;
            const response: OwnedResponse = .{
                .allocator = self.pool.allocator,
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
            if (self.lease) |*lease| lease.release();
            self.lease = null;
            const redirect_count = self.chain.redirects;
            self.finishTransaction();
            return .{
                .allocator = self.pool.allocator,
                .response = response,
                .final_uri = final_uri,
                .redirect_count = redirect_count,
            };
        }

        fn progressSend(self: *Self) OperationError!void {
            while (self.send_phase != .response) {
                const lease = if (self.lease) |*value| value else return error.InvalidLease;
                switch (self.send_phase) {
                    .head => {
                        const uri = std.Uri.parse(self.current_uri) catch
                            return error.InvalidUri;
                        var endpoint = try Runtime.uriEndpoint(
                            self.pool.allocator,
                            uri,
                        );
                        defer endpoint.deinit();
                        const path = try Runtime.uriRequestTargetAlloc(
                            self.pool.allocator,
                            uri,
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
                            self.stream_id = lease.sendRequest(request) catch |err| {
                                if (sendBackpressure(err)) return;
                                return @errorCast(err);
                            };
                            self.send_phase = .response;
                            continue;
                        }
                        self.stream_id = lease.tryStartRequest(
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
                        lease.trySendRequestBody(
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
                        lease.tryFinishRequestTrailers(
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
            self.follow_redirect = false;
        }

        fn finishTransaction(self: *Self) void {
            self.response_body.deinit(self.pool.allocator);
            if (self.owned_headers) |headers| {
                self.pool.allocator.free(headers);
            }
            self.owned_headers = null;
            self.pool.allocator.free(self.current_uri);
            self.chain.deinit();
            self.active = false;
        }
    };
}

fn responseStreamId(response: anytype) u62 {
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

fn redirectLocation(
    headers: []const http3.Qpack.HeaderField,
) uri_redirect.Error!?[]const u8 {
    var found: ?[]const u8 = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "location")) continue;
        if (found != null or header.value.len == 0) {
            return error.InvalidRedirect;
        }
        found = header.value;
    }
    return found;
}

fn redirectHeaders(
    allocator: std.mem.Allocator,
    source: []const http3.Qpack.HeaderField,
    remove_credentials: bool,
    remove_body: bool,
    owned: *?[]http3.Qpack.HeaderField,
) std.mem.Allocator.Error![]const http3.Qpack.HeaderField {
    var retained_count: usize = 0;
    for (source) |header| {
        if (!dropRedirectHeader(
            header.name,
            remove_credentials,
            remove_body,
        )) retained_count += 1;
    }
    if (retained_count == source.len) return source;
    if (retained_count == 0) {
        if (owned.*) |old| allocator.free(old);
        owned.* = null;
        return &.{};
    }
    const headers = try allocator.alloc(
        http3.Qpack.HeaderField,
        retained_count,
    );
    var index: usize = 0;
    for (source) |header| {
        if (dropRedirectHeader(
            header.name,
            remove_credentials,
            remove_body,
        )) continue;
        headers[index] = header;
        index += 1;
    }
    if (owned.*) |old| allocator.free(old);
    owned.* = headers;
    return headers;
}

fn dropRedirectHeader(
    name: []const u8,
    remove_credentials: bool,
    remove_body: bool,
) bool {
    if (std.ascii.eqlIgnoreCase(name, "host")) return true;
    if (remove_credentials and uri_redirect.isCrossOriginCredential(name)) {
        return true;
    }
    if (remove_credentials and std.ascii.eqlIgnoreCase(name, "trailer")) {
        return true;
    }
    return remove_body and uri_redirect.isBodyHeader(name);
}
