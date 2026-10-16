//! Same-origin URI batch adapter for the exclusive authenticated H3 pool.
//!
//! This module owns URI preparation, pool admission, original-index mapping,
//! Alt-Svc routing, SETTINGS observation, and 421 authority updates. The
//! connection runtime remains the sole request/response lifecycle owner.

const std = @import("std");
const http3 = @import("../../mod.zig");

const stack_request_count: usize = 16;

pub fn UriRequest(comptime Runtime: type) type {
    return struct {
        uri: []const u8,
        request: Runtime.UriRequestOptions = .{},
    };
}

pub fn request(
    comptime Runtime: type,
    pool: anytype,
    requests: []const UriRequest(Runtime),
    deadlines: []const ?std.Io.Clock.Timestamp,
    observer: Runtime.BatchOwnedHandshakeResponseObserver,
    cancellation: ?Runtime.BatchHandshakeCancellationObserver,
    alt_svc: ?http3.AltSvcTarget,
) !void {
    if (requests.len != deadlines.len) return error.InvalidSetting;
    if (requests.len == 0) return;

    const allocator = pool.allocator;
    const first_uri = std.Uri.parse(requests[0].uri) catch
        return error.InvalidUri;
    var first_endpoint = try Runtime.uriEndpoint(allocator, first_uri);
    defer first_endpoint.deinit();
    const first_origin = try http3.requestOrigin(
        first_uri.scheme,
        first_endpoint.authority,
    );

    var stack_native: [stack_request_count]http3.Request = undefined;
    var stack_paths: [stack_request_count][]u8 = undefined;
    const native = if (requests.len <= stack_native.len)
        stack_native[0..requests.len]
    else
        try allocator.alloc(http3.Request, requests.len);
    defer if (requests.len > stack_native.len) allocator.free(native);
    const paths = if (requests.len <= stack_paths.len)
        stack_paths[0..requests.len]
    else
        try allocator.alloc([]u8, requests.len);
    defer if (requests.len > stack_paths.len) allocator.free(paths);
    var prepared_paths: usize = 0;
    defer for (paths[0..prepared_paths]) |path| allocator.free(path);

    for (requests, native, paths) |item, *out, *path| {
        const uri = std.Uri.parse(item.uri) catch return error.InvalidUri;
        var endpoint = try Runtime.uriEndpoint(allocator, uri);
        defer endpoint.deinit();
        const origin = try http3.requestOrigin(uri.scheme, endpoint.authority);
        if (!http3.sameOrigin(first_origin, origin)) {
            return error.InvalidUri;
        }
        path.* = try Runtime.uriRequestTargetAlloc(allocator, uri);
        prepared_paths += 1;
        out.* = .{
            .method = item.request.method,
            .path = path.*,
            .scheme = "https",
            .authority = first_endpoint.authority,
            .headers = item.request.headers,
            .body = item.request.body,
            .trailers = item.request.trailers,
        };
    }

    var stack_active: [stack_request_count]bool = undefined;
    const active = if (requests.len <= stack_active.len)
        stack_active[0..requests.len]
    else
        try allocator.alloc(bool, requests.len);
    defer if (requests.len > stack_active.len) allocator.free(active);
    @memset(active, true);

    while (true) {
        var active_count: usize = 0;
        var earliest: ?std.Io.Clock.Timestamp = null;
        for (active, deadlines, 0..) |*is_active, deadline, index| {
            if (!is_active.*) continue;
            if (cancellation) |cancel| {
                if (cancel.take_canceled(cancel.context, index)) {
                    is_active.* = false;
                    observer.on_result(
                        observer.context,
                        index,
                        .{ .err = error.Canceled },
                    );
                    continue;
                }
            }
            if (deadline) |absolute| {
                if (absolute.clock != .awake or
                    absolute.durationFromNow(pool.io).raw.nanoseconds <= 0)
                {
                    is_active.* = false;
                    observer.on_result(
                        observer.context,
                        index,
                        .{ .err = error.Timeout },
                    );
                    continue;
                }
                earliest = if (earliest) |current|
                    if (std.Io.Clock.Timestamp.compare(
                        absolute,
                        .lt,
                        current,
                    )) absolute else current
                else
                    absolute;
            }
            active_count += 1;
        }
        if (cancellation) |cancel| cancel.acknowledge(cancel.context);
        if (active_count == 0) return;

        const lease = if (alt_svc) |target|
            if (earliest) |absolute|
                pool.acquireUriAltSvcWithDeadline(
                    requests[0].uri,
                    target,
                    absolute,
                )
            else
                pool.acquireUriAltSvc(requests[0].uri, target)
        else if (earliest) |absolute|
            pool.acquireUriWithDeadline(requests[0].uri, absolute)
        else
            pool.acquireUri(requests[0].uri);
        var acquired = lease catch |err| switch (err) {
            error.Timeout => continue,
            else => {
                for (active, 0..) |*is_active, index| {
                    if (!is_active.*) continue;
                    is_active.* = false;
                    observer.on_result(
                        observer.context,
                        index,
                        .{ .err = err },
                    );
                }
                return err;
            },
        };
        defer if (acquired.active) acquired.discard();

        var compact_stack: [stack_request_count]http3.Request = undefined;
        var deadline_stack: [stack_request_count]?std.Io.Clock.Timestamp = undefined;
        var index_stack: [stack_request_count]usize = undefined;
        const compact = if (active_count <= compact_stack.len)
            compact_stack[0..active_count]
        else
            try allocator.alloc(http3.Request, active_count);
        defer if (active_count > compact_stack.len) allocator.free(compact);
        const compact_deadlines = if (active_count <= deadline_stack.len)
            deadline_stack[0..active_count]
        else
            try allocator.alloc(?std.Io.Clock.Timestamp, active_count);
        defer if (active_count > deadline_stack.len) allocator.free(compact_deadlines);
        const original_indices = if (active_count <= index_stack.len)
            index_stack[0..active_count]
        else
            try allocator.alloc(usize, active_count);
        defer if (active_count > index_stack.len) allocator.free(original_indices);
        var compact_count: usize = 0;
        for (active, native, deadlines, 0..) |is_active, item, deadline, index| {
            if (!is_active) continue;
            compact[compact_count] = item;
            compact_deadlines[compact_count] = deadline;
            original_indices[compact_count] = index;
            compact_count += 1;
        }

        const Lease = @TypeOf(acquired);
        const Mapping = struct {
            lease: *Lease,
            observer: Runtime.BatchOwnedHandshakeResponseObserver,
            original_indices: []const usize,
            authority_error: ?anyerror = null,

            fn observe(
                raw: *anyopaque,
                compact_index: usize,
                result: Runtime.BatchOwnedHandshakeResponseResult,
            ) void {
                const self: *@This() = @ptrCast(@alignCast(raw));
                const original_index = self.original_indices[compact_index];
                switch (result) {
                    .response => |response_value| {
                        var response = response_value;
                        if (response.response.status == 421) {
                            self.lease.client()
                                .removePeerOriginAfterMisdirected(
                                self.lease.requestOrigin(),
                            ) catch |err| {
                                self.authority_error = err;
                                response.deinit(self.lease.pool.allocator);
                                self.observer.on_result(
                                    self.observer.context,
                                    original_index,
                                    .{ .err = err },
                                );
                                return;
                            };
                        }
                        self.observer.on_result(
                            self.observer.context,
                            original_index,
                            .{ .response = response },
                        );
                    },
                    .err => |err| self.observer.on_result(
                        self.observer.context,
                        original_index,
                        .{ .err = err },
                    ),
                }
            }
        };
        var mapping = Mapping{
            .lease = &acquired,
            .observer = observer,
            .original_indices = original_indices,
        };

        const CancellationMapping = struct {
            source: Runtime.BatchHandshakeCancellationObserver,
            original_indices: []const usize,

            fn take(raw: *anyopaque, compact_index: usize) bool {
                const self: *@This() = @ptrCast(@alignCast(raw));
                return self.source.take_canceled(
                    self.source.context,
                    self.original_indices[compact_index],
                );
            }

            fn acknowledge(raw: *anyopaque) void {
                const self: *@This() = @ptrCast(@alignCast(raw));
                self.source.acknowledge(self.source.context);
            }
        };
        var cancellation_mapping: CancellationMapping = undefined;
        const mapped_cancellation: ?Runtime.BatchHandshakeCancellationObserver =
            if (cancellation) |source| blk: {
                cancellation_mapping = .{
                    .source = source,
                    .original_indices = original_indices,
                };
                break :blk .{
                    .event = source.event,
                    .context = &cancellation_mapping,
                    .take_canceled = CancellationMapping.take,
                    .acknowledge = CancellationMapping.acknowledge,
                };
            } else null;

        const run_result = if (mapped_cancellation) |cancel|
            acquired.client()
                .requestBatchWithPerStreamDeadlinesAndCancellation(
                compact,
                compact_deadlines,
                .{ .context = &mapping, .on_result = Mapping.observe },
                cancel,
            )
        else
            acquired.client().requestBatchWithPerStreamDeadlines(
                compact,
                compact_deadlines,
                .{ .context = &mapping, .on_result = Mapping.observe },
            );
        run_result catch |err| {
            acquired.discard();
            return err;
        };
        if (mapping.authority_error != null) {
            acquired.discard();
            return mapping.authority_error.?;
        }
        if (pool.options.peer_settings_observer) |settings_observer| {
            if (acquired.client().peerSettings()) |settings| {
                settings_observer.observe(
                    settings_observer.context,
                    acquired.requestOrigin(),
                    settings,
                );
            }
        }
        acquired.release();
        return;
    }
}
