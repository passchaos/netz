//! Same-origin URI batches for the exclusive HTTP/2 connection pool.
//!
//! This is the synchronous execution core for a future cloneable-sender
//! driver: one lease submits all request HEADERS before reading. Bodyless
//! batches use the transactional HEADERS path; body-bearing batches use the
//! runtime's full-duplex round-robin upload/response pump.

const std = @import("std");
const deadline_policy = @import("../../internal/deadline.zig");
const http_method = @import("../../internal/http_method.zig");
const http1_runtime = @import("../../http1/runtime.zig");
const runtime = @import("../runtime.zig");

pub const UriRequest = struct {
    uri: []const u8,
    request: runtime.RequestOptions = .{},
};

const stack_request_count: usize = 16;
const stack_target_bytes: usize = 1024;

pub fn requestUriBatch(
    pool: anytype,
    requests: []const UriRequest,
    responses: []runtime.OwnedResponse,
) !void {
    return requestUriBatchBefore(pool, requests, responses, null) catch |err| switch (err) {
        error.Timeout, error.Canceled => unreachable,
        else => |other| return other,
    };
}

pub fn requestUriBatchWithTimeout(
    pool: anytype,
    requests: []const UriRequest,
    responses: []runtime.OwnedResponse,
    timeout: std.Io.Duration,
) !void {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return requestUriBatchWithDeadline(
        pool,
        requests,
        responses,
        .fromNow(pool.io, .{ .raw = timeout, .clock = .awake }),
    );
}

pub fn requestUriBatchWithDeadline(
    pool: anytype,
    requests: []const UriRequest,
    responses: []runtime.OwnedResponse,
    deadline: std.Io.Clock.Timestamp,
) !void {
    return requestUriBatchBefore(
        pool,
        requests,
        responses,
        try deadline_policy.usableAwake(pool.io, deadline),
    );
}

fn requestUriBatchBefore(
    pool: anytype,
    requests: []const UriRequest,
    responses: []runtime.OwnedResponse,
    deadline: ?std.Io.Clock.Timestamp,
) !void {
    if (requests.len != responses.len) return error.InvalidResponse;
    if (requests.len == 0) return;
    var has_body = false;
    for (requests) |item| {
        if (item.request.trailers.len != 0) {
            return error.InvalidContentLength;
        }
        has_body = has_body or item.request.body.len != 0;
    }

    const first_uri = std.Uri.parse(requests[0].uri) catch
        return error.InvalidUri;
    const first_secure = try secureForScheme(first_uri.scheme);
    var first_endpoint = try http1_runtime.uriEndpoint(
        pool.allocator,
        first_uri,
        if (first_secure) 443 else 80,
    );
    defer first_endpoint.deinit();

    var total_target_bytes: usize = 0;
    for (requests, 0..) |item, index| {
        const uri = std.Uri.parse(item.uri) catch return error.InvalidUri;
        const secure = try secureForScheme(uri.scheme);
        if (index != 0) {
            var endpoint = try http1_runtime.uriEndpoint(
                pool.allocator,
                uri,
                if (secure) 443 else 80,
            );
            defer endpoint.deinit();
            if (secure != first_secure or
                endpoint.port != first_endpoint.port or
                !std.ascii.eqlIgnoreCase(
                    endpoint.tls_host,
                    first_endpoint.tls_host,
                ))
            {
                return error.MixedBatchOrigins;
            }
        }
        total_target_bytes = std.math.add(
            usize,
            total_target_bytes,
            try targetLength(uri),
        ) catch return error.MessageTooLarge;
    }

    var request_stack: [stack_request_count]runtime.RequestOptions = undefined;
    const native_requests = if (requests.len <= request_stack.len)
        request_stack[0..requests.len]
    else
        try pool.allocator.alloc(runtime.RequestOptions, requests.len);
    defer if (native_requests.ptr != request_stack[0..].ptr) {
        pool.allocator.free(native_requests);
    };
    var target_stack: [stack_target_bytes]u8 = undefined;
    const target_storage = if (total_target_bytes <= target_stack.len)
        target_stack[0..total_target_bytes]
    else
        try pool.allocator.alloc(u8, total_target_bytes);
    defer if (target_storage.ptr != target_stack[0..].ptr) {
        pool.allocator.free(target_storage);
    };
    var target_offset: usize = 0;
    for (requests, native_requests) |item, *native| {
        const uri = std.Uri.parse(item.uri) catch unreachable;
        const len = try targetLength(uri);
        const target = target_storage[target_offset..][0..len];
        writeTarget(target, uri);
        target_offset += len;
        native.* = item.request;
        native.path = target;
        native.scheme = null;
        native.authority = null;
    }

    const retry_stale = allIdempotent(requests);
    var may_retry = retry_stale;
    while (true) {
        var lease = if (deadline) |absolute|
            try pool.acquireUriWithDeadline(requests[0].uri, absolute)
        else
            try pool.acquireUri(requests[0].uri);
        defer if (lease.active) lease.discard();
        const result = if (has_body)
            if (deadline) |absolute|
                lease.connection().requestBodyBatchIntoWithDeadline(
                    native_requests,
                    pool.options.batch_body_chunk_size,
                    responses,
                    absolute,
                )
            else
                lease.connection().requestBodyBatchInto(
                    native_requests,
                    pool.options.batch_body_chunk_size,
                    responses,
                )
        else if (deadline) |absolute|
            lease.connection().requestBatchIntoWithDeadline(
                native_requests,
                responses,
                absolute,
            )
        else
            lease.connection().requestBatchInto(
                native_requests,
                responses,
            );
        result catch |err| {
            const reused = lease.was_reused;
            lease.discard();
            if (may_retry and reused and retryableStaleConnectionError(err)) {
                may_retry = false;
                continue;
            }
            return err;
        };
        lease.release();
        return;
    }
}

fn secureForScheme(scheme: []const u8) !bool {
    if (std.ascii.eqlIgnoreCase(scheme, "https")) return true;
    if (std.ascii.eqlIgnoreCase(scheme, "http")) return false;
    return error.UnsupportedScheme;
}

fn targetLength(uri: std.Uri) !usize {
    const path = componentBytes(uri.path);
    const path_len = if (path.len == 0) 1 else path.len;
    if (uri.query) |query| {
        const prefix_len = std.math.add(usize, path_len, 1) catch
            return error.MessageTooLarge;
        return std.math.add(
            usize,
            prefix_len,
            componentBytes(query).len,
        ) catch return error.MessageTooLarge;
    }
    return path_len;
}

fn writeTarget(out: []u8, uri: std.Uri) void {
    const path = componentBytes(uri.path);
    const effective_path = if (path.len == 0) "/" else path;
    @memcpy(out[0..effective_path.len], effective_path);
    if (uri.query) |query| {
        out[effective_path.len] = '?';
        const bytes = componentBytes(query);
        @memcpy(out[effective_path.len + 1 ..], bytes);
    }
}

fn componentBytes(component: std.Uri.Component) []const u8 {
    return switch (component) {
        .raw, .percent_encoded => |value| value,
    };
}

fn allIdempotent(requests: []const UriRequest) bool {
    for (requests) |item| {
        if (!http_method.isIdempotent(item.request.method)) return false;
    }
    return true;
}

fn retryableStaleConnectionError(err: anyerror) bool {
    return switch (err) {
        error.ConnectionAborted,
        error.ConnectionClosed,
        error.ConnectionResetByPeer,
        error.EndOfStream,
        error.SocketUnconnected,
        => true,
        else => false,
    };
}
