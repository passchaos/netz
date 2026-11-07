//! Complete request, stale-retry, and redirect operations for the negotiated
//! HTTP pool. Connection admission and ownership remain in the parent pool.

const std = @import("std");
const client = @import("../client.zig");
const redirect = @import("../client/redirect.zig");
const header_mapping = @import("../client/header_mapping.zig");
const deadline_policy = @import("../../internal/deadline.zig");
const http_method = @import("../../internal/http_method.zig");
const http1_runtime = @import("../../http1/runtime.zig");
const uri_redirect = @import("../../http1/runtime/redirect.zig");
const http3 = @import("../../http3/mod.zig");
const alt_svc_cache = @import("../alt_svc_cache.zig");

pub fn requestUri(
    pool: anytype,
    uri_text: []const u8,
    request: client.RequestOptions,
) !client.OwnedResponse {
    return requestUriBefore(pool, uri_text, request, null, false, false);
}

pub fn requestUriWithTimeout(
    pool: anytype,
    uri_text: []const u8,
    request: client.RequestOptions,
    timeout: std.Io.Duration,
) !client.OwnedResponse {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return requestUriWithDeadline(
        pool,
        uri_text,
        request,
        .fromNow(pool.io, .{ .raw = timeout, .clock = .awake }),
    );
}

pub fn requestUriWithDeadline(
    pool: anytype,
    uri_text: []const u8,
    request: client.RequestOptions,
    deadline: std.Io.Clock.Timestamp,
) !client.OwnedResponse {
    return requestUriBefore(
        pool,
        uri_text,
        request,
        try deadline_policy.usableAwake(pool.io, deadline),
        false,
        false,
    );
}

pub fn requestUriBefore(
    pool: anytype,
    uri_text: []const u8,
    request: client.RequestOptions,
    deadline: ?std.Io.Clock.Timestamp,
    crossed_origin: bool,
    forward_client_identity: bool,
) @typeInfo(@TypeOf(pool)).pointer.child.RequestOperationError!client.OwnedResponse {
    if (pool.http3 != null) {
        var guard = try @import("../../internal/mutex_guard.zig").Guard.initBefore(&pool.mutex, pool.io, deadline);
        defer guard.unlock();
        if (pool.closed) return error.PoolClosed;
    }
    const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
    const target = try uriTargetAlloc(pool.allocator, uri);
    defer pool.allocator.free(target);
    var origin_endpoint: ?http1_runtime.UriEndpoint = null;
    defer if (origin_endpoint) |*endpoint| endpoint.deinit();
    var h3_origin: ?http3.Origin = null;
    if (pool.http3 != null and
        std.ascii.eqlIgnoreCase(uri.scheme, "https"))
    {
        origin_endpoint = try http1_runtime.uriEndpoint(
            pool.allocator,
            uri,
            443,
        );
        h3_origin = .{
            .scheme = "https",
            .host = origin_endpoint.?.tls_host,
            .port = origin_endpoint.?.port,
        };
    }
    if (pool.options.client.http_proxy == null) {
        if (pool.http3) |h3_state| h3_attempt: {
            const origin = h3_origin orelse break :h3_attempt;
            var alternative = h3_state.cache.lookup(origin) catch
                break :h3_attempt;
            if (alternative == null) break :h3_attempt;
            defer alternative.?.deinit();
            if (requestHttp3(
                pool,
                h3_state,
                origin,
                uri_text,
                &alternative.?,
                request,
                deadline,
                crossed_origin,
                forward_client_identity,
            )) |owned| {
                _ = h3_state.cache.recordSuccess(origin);
                var result = owned;
                observeAltSvc(h3_state, origin, &result);
                return result;
            } else |err| {
                if (h3FailureAffectsAlternative(err)) {
                    _ = h3_state.cache.recordFailure(origin);
                }
                if (!h3FallbackAllowed(h3_state, request.method, err)) {
                    return err;
                }
            }
        }
    }
    var retry_stale = true;
    while (true) {
        const shared = pool.tcp_requests.request(pool, uri_text, target, request, deadline, crossed_origin) catch |err| return @errorCast(err);
        const fallback = switch (shared) {
            .response => |owned| {
                var result = owned;
                if (pool.http3) |h3_state| if (h3_origin) |origin| observeAltSvc(h3_state, origin, &result);
                return result;
            },
            .failure => |failure| {
                if (retry_stale and failure.was_reused and http_method.isIdempotent(request.method) and
                    retryableStaleConnectionError(failure.err))
                {
                    retry_stale = false;
                    continue;
                }
                return @errorCast(failure.err);
            },
            .fallback => |lease| lease,
        };
        var lease = fallback orelse if (deadline) |absolute|
            try pool.acquireUriWithDeadlineAndOriginIsolation(
                uri_text,
                absolute,
                crossed_origin,
            )
        else
            try pool.acquireUriWithOriginIsolation(
                uri_text,
                crossed_origin,
            );
        defer if (lease.active) lease.discard();
        const connection = lease.connection();
        const request_target = if (connection.isForwardProxy()) uri_text else target;
        const response = if (deadline) |absolute|
            connection.requestWithDeadline(request_target, request, absolute)
        else
            connection.request(request_target, request);
        const owned_response = response catch |err| {
            const was_reused = lease.was_reused;
            lease.discard();
            if (retry_stale and was_reused and
                http_method.isIdempotent(request.method) and
                retryableStaleConnectionError(err))
            {
                retry_stale = false;
                continue;
            }
            return err;
        };
        var result = owned_response;
        errdefer result.deinit();
        lease.release();
        if (pool.http3) |h3_state| {
            if (h3_origin) |origin| observeAltSvc(
                h3_state,
                origin,
                &result,
            );
        }
        return result;
    }
}

fn requestHttp3(
    pool: anytype,
    state: anytype,
    origin: http3.Origin,
    uri_text: []const u8,
    alternative: *const alt_svc_cache.Alternative,
    request: client.RequestOptions,
    deadline: ?std.Io.Clock.Timestamp,
    crossed_origin: bool,
    forward_client_identity: bool,
) !client.OwnedResponse {
    const PoolType = @typeInfo(@TypeOf(pool)).pointer.child;
    var header_stack: [header_mapping.max_stack_headers]http3.Qpack.HeaderField =
        undefined;
    var trailer_stack: [header_mapping.max_stack_trailers]http3.Qpack.HeaderField =
        undefined;
    var headers = try header_mapping.mapHttp3(
        pool.allocator,
        request.headers,
        &header_stack,
    );
    defer headers.deinit(pool.allocator);
    var trailers = try header_mapping.mapHttp3(
        pool.allocator,
        request.trailers,
        &trailer_stack,
    );
    defer trailers.deinit(pool.allocator);
    const response = try state.request(
        origin,
        uri_text,
        alternative,
        .{
            .method = request.method,
            .headers = headers.items,
            .body = request.body,
            .trailers = trailers.items,
        },
        request.allow_early_data,
        deadline,
        crossed_origin,
        forward_client_identity,
        PoolType.Internal.tcpIdleReclaimer(pool),
    );
    return .{
        .allocator = pool.allocator,
        .value = .{ .http3 = response.response },
        .early_data = if (response.early_data) |metadata| .{
            .disposition = metadata.disposition,
            .retry_reason = metadata.retry_reason,
        } else null,
    };
}

fn observeAltSvc(
    state: anytype,
    origin: http3.Origin,
    response: *const client.OwnedResponse,
) void {
    if (response.status() == 421) {
        _ = state.cache.remove(origin);
        return;
    }
    switch (response.value) {
        .http1 => |value| _ = state.cache.updateFromHeaders(
            origin,
            value.response.headers,
        ) catch {},
        .http2 => |value| _ = state.cache.updateFromHeaders(
            origin,
            value.headers,
        ) catch {},
        .http3 => |value| _ = state.cache.updateFromHeaders(
            origin,
            value.response.headers,
        ) catch {},
    }
}

fn h3FallbackAllowed(
    state: anytype,
    method: []const u8,
    err: anyerror,
) bool {
    switch (err) {
        error.Timeout,
        error.Canceled,
        error.ConcurrencyUnavailable,
        error.OutOfMemory,
        error.InvalidHeader,
        error.InvalidUri,
        => return false,
        else => {},
    }
    return switch (state.options.fallback) {
        .never => false,
        .idempotent_methods => http_method.isIdempotent(method),
    };
}

fn h3FailureAffectsAlternative(err: anyerror) bool {
    return switch (err) {
        error.Timeout,
        error.Canceled,
        error.ConcurrencyUnavailable,
        error.OutOfMemory,
        error.InvalidHeader,
        error.InvalidUri,
        => false,
        else => true,
    };
}

pub fn requestUriFollowingRedirects(
    pool: anytype,
    uri_text: []const u8,
    request: client.RequestOptions,
    redirect_options: client.RedirectOptions,
) !client.OwnedResponse {
    var result = try requestUriFollowingRedirectsDetailedBefore(
        pool,
        uri_text,
        request,
        redirect_options,
        null,
    );
    return result.takeResponse();
}

pub fn requestUriFollowingRedirectsDetailed(
    pool: anytype,
    uri_text: []const u8,
    request: client.RequestOptions,
    redirect_options: client.RedirectOptions,
) !client.RedirectedResponse {
    return requestUriFollowingRedirectsDetailedBefore(
        pool,
        uri_text,
        request,
        redirect_options,
        null,
    );
}

pub fn requestUriFollowingRedirectsWithTimeout(
    pool: anytype,
    uri_text: []const u8,
    request: client.RequestOptions,
    redirect_options: client.RedirectOptions,
    timeout: std.Io.Duration,
) !client.OwnedResponse {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return requestUriFollowingRedirectsWithDeadline(
        pool,
        uri_text,
        request,
        redirect_options,
        .fromNow(pool.io, .{ .raw = timeout, .clock = .awake }),
    );
}

pub fn requestUriFollowingRedirectsWithDeadline(
    pool: anytype,
    uri_text: []const u8,
    request: client.RequestOptions,
    redirect_options: client.RedirectOptions,
    deadline: std.Io.Clock.Timestamp,
) !client.OwnedResponse {
    var result = try requestUriFollowingRedirectsDetailedBefore(
        pool,
        uri_text,
        request,
        redirect_options,
        try deadline_policy.usableAwake(pool.io, deadline),
    );
    return result.takeResponse();
}

pub fn requestUriFollowingRedirectsDetailedWithTimeout(
    pool: anytype,
    uri_text: []const u8,
    request: client.RequestOptions,
    redirect_options: client.RedirectOptions,
    timeout: std.Io.Duration,
) !client.RedirectedResponse {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return requestUriFollowingRedirectsDetailedWithDeadline(
        pool,
        uri_text,
        request,
        redirect_options,
        .fromNow(pool.io, .{ .raw = timeout, .clock = .awake }),
    );
}

pub fn requestUriFollowingRedirectsDetailedWithDeadline(
    pool: anytype,
    uri_text: []const u8,
    request: client.RequestOptions,
    redirect_options: client.RedirectOptions,
    deadline: std.Io.Clock.Timestamp,
) !client.RedirectedResponse {
    return requestUriFollowingRedirectsDetailedBefore(
        pool,
        uri_text,
        request,
        redirect_options,
        try deadline_policy.usableAwake(pool.io, deadline),
    );
}

fn requestUriFollowingRedirectsDetailedBefore(
    pool: anytype,
    uri_text: []const u8,
    request: client.RequestOptions,
    redirect_options: client.RedirectOptions,
    deadline: ?std.Io.Clock.Timestamp,
) !client.RedirectedResponse {
    const PoolType = @typeInfo(@TypeOf(pool)).pointer.child;
    return redirect.followDetailed(
        PoolType.RequestOperationError,
        pool,
        uri_text,
        request,
        redirect_options,
        deadline,
        RedirectAdapter(PoolType),
    );
}

fn RedirectAdapter(comptime PoolType: type) type {
    return struct {
        pub fn request(
            pool: *PoolType,
            uri_text: []const u8,
            request_options: client.RequestOptions,
            deadline: ?std.Io.Clock.Timestamp,
            crossed_origin: bool,
            policy: uri_redirect.Policy,
        ) PoolType.RequestOperationError!client.OwnedResponse {
            return requestUriBefore(
                pool,
                uri_text,
                request_options,
                deadline,
                crossed_origin,
                policy.allow_cross_origin_client_identity,
            );
        }

        pub fn clientIdentityConfigured(pool: *const PoolType) bool {
            if (pool.options.client.tls.client_identity != null) return true;
            return if (pool.options.http3) |options|
                options.handshake.handshake.client_identity != null
            else
                false;
        }
    };
}

fn uriTargetAlloc(
    allocator: std.mem.Allocator,
    uri: std.Uri,
) ![]u8 {
    const path = switch (uri.path) {
        .raw, .percent_encoded => |value| value,
    };
    const effective_path = if (path.len == 0) "/" else path;
    if (uri.query) |query| {
        const bytes = switch (query) {
            .raw, .percent_encoded => |value| value,
        };
        return std.fmt.allocPrint(
            allocator,
            "{s}?{s}",
            .{ effective_path, bytes },
        );
    }
    return allocator.dupe(u8, effective_path);
}

fn retryableStaleConnectionError(err: anyerror) bool {
    return switch (err) {
        error.ConnectionAborted,
        error.ConnectionClosed,
        error.ConnectionResetByPeer,
        error.EndOfStream,
        error.ReadFailed,
        error.SocketUnconnected,
        error.WriteFailed,
        => true,
        else => false,
    };
}
