//! Same-origin URI batches for the exclusive HTTP/2 connection pool.
//!
//! This is the synchronous execution core for the cloneable-sender driver:
//! one lease submits all request HEADERS before reading. Bodyless
//! batches use the transactional HEADERS path; body-bearing batches use the
//! runtime's full-duplex round-robin upload/response pump, with terminal
//! request trailers committed through a distinct HPACK transaction.

const std = @import("std");
const deadline_policy = @import("../../internal/deadline.zig");
const http_method = @import("../../internal/http_method.zig");
const http1_runtime = @import("../../http1/runtime.zig");
const runtime = @import("../runtime.zig");
const header_message = @import("../runtime/headers/message.zig");

pub const UriRequest = struct {
    uri: []const u8,
    request: runtime.RequestOptions = .{},
};

const stack_request_count: usize = 16;
const stack_target_bytes: usize = 1024;

const PreparedUriBatch = struct {
    native_requests: []runtime.RequestOptions,
    target_storage: []u8,
    has_body_or_trailers: bool,
    requests_allocated: bool,
    targets_allocated: bool,

    fn deinit(self: *PreparedUriBatch, pool: anytype) void {
        if (self.requests_allocated) {
            pool.allocator.free(self.native_requests);
        }
        if (self.targets_allocated) {
            pool.allocator.free(self.target_storage);
        }
        self.* = undefined;
    }
};

fn prepareUriBatch(
    pool: anytype,
    requests: []const UriRequest,
    request_stack: *[stack_request_count]runtime.RequestOptions,
    target_stack: *[stack_target_bytes]u8,
) !PreparedUriBatch {
    var has_body_or_trailers = false;
    for (requests) |item| {
        try header_message.validateHeaderBlock(
            item.request.trailers,
            .request_trailers,
        );
        has_body_or_trailers = has_body_or_trailers or
            item.request.body.len != 0 or
            item.request.trailers.len != 0;
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

    const requests_allocated = requests.len > request_stack.len;
    const native_requests = if (requests_allocated)
        try pool.allocator.alloc(runtime.RequestOptions, requests.len)
    else
        request_stack[0..requests.len];
    errdefer if (requests_allocated) pool.allocator.free(native_requests);
    const targets_allocated = total_target_bytes > target_stack.len;
    const target_storage = if (targets_allocated)
        try pool.allocator.alloc(u8, total_target_bytes)
    else
        target_stack[0..total_target_bytes];
    errdefer if (targets_allocated) pool.allocator.free(target_storage);

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
    return .{
        .native_requests = native_requests,
        .target_storage = target_storage,
        .has_body_or_trailers = has_body_or_trailers,
        .requests_allocated = requests_allocated,
        .targets_allocated = targets_allocated,
    };
}

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

/// Pool-backed request batch with independent request deadlines. Capacity
/// admission is retried after expiring only the earliest members; once a
/// connection is leased, the full-duplex runtime delivers every terminal
/// result through `observer` using the original URI-batch index.
pub fn requestUriBatchWithPerStreamDeadlines(
    pool: anytype,
    requests: []const UriRequest,
    deadlines: []const ?std.Io.Clock.Timestamp,
    observer: runtime.BatchOwnedResponseObserver,
) !void {
    return requestUriBatchWithPerStreamDeadlinesMode(
        false,
        pool,
        requests,
        deadlines,
        observer,
    );
}

/// Callback-streaming counterpart to
/// `requestUriBatchWithPerStreamDeadlines`. URI admission and original-index
/// mapping are identical, but response DATA is never aggregated.
pub fn requestUriBatchStreamingWithPerStreamDeadlines(
    pool: anytype,
    requests: []const UriRequest,
    deadlines: []const ?std.Io.Clock.Timestamp,
    observer: runtime.BatchStreamingResponseObserver,
) !void {
    return requestUriBatchWithPerStreamDeadlinesMode(
        true,
        pool,
        requests,
        deadlines,
        observer,
    );
}

fn requestUriBatchWithPerStreamDeadlinesMode(
    comptime streaming: bool,
    pool: anytype,
    requests: []const UriRequest,
    deadlines: []const ?std.Io.Clock.Timestamp,
    observer: anytype,
) !void {
    if (requests.len != deadlines.len) return error.InvalidResponse;
    if (requests.len == 0) return;
    for (deadlines) |deadline| {
        if (deadline) |absolute| {
            if (absolute.clock != .awake) return error.Timeout;
        }
    }

    var request_stack: [stack_request_count]runtime.RequestOptions = undefined;
    var target_stack: [stack_target_bytes]u8 = undefined;
    var prepared = try prepareUriBatch(
        pool,
        requests,
        &request_stack,
        &target_stack,
    );
    defer prepared.deinit(pool);

    var active_stack: [stack_request_count]bool = undefined;
    const active = if (requests.len <= active_stack.len)
        active_stack[0..requests.len]
    else
        try pool.allocator.alloc(bool, requests.len);
    defer if (active.ptr != active_stack[0..].ptr) {
        pool.allocator.free(active);
    };
    @memset(active, true);

    var compact_requests_stack: [stack_request_count]runtime.RequestOptions =
        undefined;
    const compact_requests = if (requests.len <= compact_requests_stack.len)
        compact_requests_stack[0..requests.len]
    else
        try pool.allocator.alloc(runtime.RequestOptions, requests.len);
    defer if (compact_requests.ptr != compact_requests_stack[0..].ptr) {
        pool.allocator.free(compact_requests);
    };
    var compact_deadlines_stack: [stack_request_count]?std.Io.Clock.Timestamp =
        undefined;
    const compact_deadlines = if (requests.len <= compact_deadlines_stack.len)
        compact_deadlines_stack[0..requests.len]
    else
        try pool.allocator.alloc(?std.Io.Clock.Timestamp, requests.len);
    defer if (compact_deadlines.ptr != compact_deadlines_stack[0..].ptr) {
        pool.allocator.free(compact_deadlines);
    };
    var original_indices_stack: [stack_request_count]usize = undefined;
    const original_indices = if (requests.len <= original_indices_stack.len)
        original_indices_stack[0..requests.len]
    else
        try pool.allocator.alloc(usize, requests.len);
    defer if (original_indices.ptr != original_indices_stack[0..].ptr) {
        pool.allocator.free(original_indices);
    };

    while (true) {
        var active_count: usize = 0;
        var first_active: ?usize = null;
        var earliest: ?std.Io.Clock.Timestamp = null;
        for (active, deadlines, 0..) |*is_active, deadline, index| {
            if (!is_active.*) continue;
            if (deadline) |absolute| {
                if (absolute.durationFromNow(pool.io).raw.nanoseconds <= 0) {
                    is_active.* = false;
                    observer.on_result(
                        observer.context,
                        index,
                        .{ .err = error.Timeout },
                    );
                    continue;
                }
            }
            first_active = first_active orelse index;
            earliest = deadline_policy.earlier(earliest, deadline);
            active_count += 1;
        }
        if (active_count == 0) return;

        var lease = if (earliest) |absolute|
            pool.acquireUriWithDeadline(
                requests[first_active.?].uri,
                absolute,
            ) catch |err| switch (err) {
                error.Timeout => continue,
                else => |other| return other,
            }
        else
            try pool.acquireUri(requests[first_active.?].uri);
        defer if (lease.active) lease.discard();

        var compact_count: usize = 0;
        for (active, deadlines, 0..) |*is_active, deadline, index| {
            if (!is_active.*) continue;
            if (deadline) |absolute| {
                if (absolute.durationFromNow(pool.io).raw.nanoseconds <= 0) {
                    is_active.* = false;
                    observer.on_result(
                        observer.context,
                        index,
                        .{ .err = error.Timeout },
                    );
                    continue;
                }
            }
            compact_requests[compact_count] =
                prepared.native_requests[index];
            compact_deadlines[compact_count] = deadline;
            original_indices[compact_count] = index;
            compact_count += 1;
        }
        if (compact_count == 0) {
            lease.release();
            return;
        }

        const Mapping = if (streaming) struct {
            observer: runtime.BatchStreamingResponseObserver,
            original_indices: []const usize,

            fn head(
                raw_context: *anyopaque,
                compact_index: usize,
                response: runtime.StreamingResponseHead,
            ) anyerror!void {
                const self: *@This() = @ptrCast(@alignCast(raw_context));
                if (self.observer.on_head) |on_head| {
                    try on_head(
                        self.observer.context,
                        self.original_indices[compact_index],
                        response,
                    );
                }
            }

            fn data(
                raw_context: *anyopaque,
                compact_index: usize,
                bytes: []const u8,
            ) anyerror!void {
                const self: *@This() = @ptrCast(@alignCast(raw_context));
                try self.observer.on_data(
                    self.observer.context,
                    self.original_indices[compact_index],
                    bytes,
                );
            }

            fn observe(
                raw_context: *anyopaque,
                compact_index: usize,
                result: runtime.BatchStreamingResponseResult,
            ) void {
                const self: *@This() = @ptrCast(@alignCast(raw_context));
                self.observer.on_result(
                    self.observer.context,
                    self.original_indices[compact_index],
                    result,
                );
            }
        } else struct {
            observer: runtime.BatchOwnedResponseObserver,
            original_indices: []const usize,

            fn observe(
                raw_context: *anyopaque,
                compact_index: usize,
                result: runtime.BatchOwnedResponseResult,
            ) void {
                const self: *@This() = @ptrCast(@alignCast(raw_context));
                self.observer.on_result(
                    self.observer.context,
                    self.original_indices[compact_index],
                    result,
                );
            }
        };
        var mapping: Mapping = .{
            .observer = observer,
            .original_indices = original_indices[0..compact_count],
        };
        const result = if (streaming)
            if (prepared.has_body_or_trailers)
                lease.connection()
                    .requestBodyBatchStreamingWithPerStreamDeadlines(
                    compact_requests[0..compact_count],
                    pool.options.batch_body_chunk_size,
                    compact_deadlines[0..compact_count],
                    .{
                        .context = &mapping,
                        .on_head = Mapping.head,
                        .on_data = Mapping.data,
                        .on_result = Mapping.observe,
                    },
                )
            else
                lease.connection().requestBatchStreamingWithPerStreamDeadlines(
                    compact_requests[0..compact_count],
                    compact_deadlines[0..compact_count],
                    .{
                        .context = &mapping,
                        .on_head = Mapping.head,
                        .on_data = Mapping.data,
                        .on_result = Mapping.observe,
                    },
                )
        else if (prepared.has_body_or_trailers)
            lease.connection().requestBodyBatchWithPerStreamDeadlines(
                compact_requests[0..compact_count],
                pool.options.batch_body_chunk_size,
                compact_deadlines[0..compact_count],
                .{ .context = &mapping, .on_result = Mapping.observe },
            )
        else
            lease.connection().requestBatchWithPerStreamDeadlines(
                compact_requests[0..compact_count],
                compact_deadlines[0..compact_count],
                .{ .context = &mapping, .on_result = Mapping.observe },
            );
        result catch |err| {
            lease.discard();
            return err;
        };
        lease.release();
        return;
    }
}

fn requestUriBatchBefore(
    pool: anytype,
    requests: []const UriRequest,
    responses: []runtime.OwnedResponse,
    deadline: ?std.Io.Clock.Timestamp,
) !void {
    if (requests.len != responses.len) return error.InvalidResponse;
    if (requests.len == 0) return;
    var request_stack: [stack_request_count]runtime.RequestOptions = undefined;
    var target_stack: [stack_target_bytes]u8 = undefined;
    var prepared = try prepareUriBatch(
        pool,
        requests,
        &request_stack,
        &target_stack,
    );
    defer prepared.deinit(pool);
    const native_requests = prepared.native_requests;

    const retry_stale = allIdempotent(requests);
    var may_retry = retry_stale;
    while (true) {
        var lease = if (deadline) |absolute|
            try pool.acquireUriWithDeadline(requests[0].uri, absolute)
        else
            try pool.acquireUri(requests[0].uri);
        defer if (lease.active) lease.discard();
        const result = if (prepared.has_body_or_trailers)
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
