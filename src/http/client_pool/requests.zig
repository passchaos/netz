//! Complete request, stale-retry, and redirect operations for the negotiated
//! HTTP pool. Connection admission and ownership remain in the parent pool.

const std = @import("std");
const client = @import("../client.zig");
const redirect = @import("../client/redirect.zig");
const deadline_policy = @import("../../internal/deadline.zig");
const http_method = @import("../../internal/http_method.zig");
const uri_redirect = @import("../../http1/runtime/redirect.zig");

pub fn requestUri(
    pool: anytype,
    uri_text: []const u8,
    request: client.RequestOptions,
) !client.OwnedResponse {
    return requestUriBefore(pool, uri_text, request, null) catch |err| switch (err) {
        error.Timeout,
        error.Canceled,
        error.ConcurrencyUnavailable,
        => unreachable,
        else => |other| return other,
    };
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
    );
}

fn requestUriBefore(
    pool: anytype,
    uri_text: []const u8,
    request: client.RequestOptions,
    deadline: ?std.Io.Clock.Timestamp,
) !client.OwnedResponse {
    const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
    const target = try uriTargetAlloc(pool.allocator, uri);
    defer pool.allocator.free(target);
    var retry_stale = true;
    while (true) {
        var lease = if (deadline) |absolute|
            try pool.acquireUriWithDeadline(uri_text, absolute)
        else
            try pool.acquireUri(uri_text);
        defer if (lease.active) lease.discard();
        const response = if (deadline) |absolute|
            lease.connection().requestWithDeadline(target, request, absolute)
        else
            lease.connection().request(target, request);
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
        return result;
    }
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
            _ = crossed_origin;
            _ = policy;
            return requestUriBefore(
                pool,
                uri_text,
                request_options,
                deadline,
            );
        }

        pub fn clientIdentityConfigured(pool: *const PoolType) bool {
            return pool.options.client.tls.client_identity != null;
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
