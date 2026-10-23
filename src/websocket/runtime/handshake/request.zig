//! Validate and serialize a bodyless HTTP/1 Upgrade request before exposing
//! bytes, then send it through the caller's common handshake writer.

const std = @import("std");
const http1 = @import("../../../http1/mod.zig");
const http1_runtime = @import("../../../http1/runtime.zig");
const storage = @import("storage.zig");

pub fn write(
    allocator: std.mem.Allocator,
    options: http1_runtime.RequestOptions,
    max_head_bytes: usize,
    context: anytype,
    comptime write_parts: anytype,
) !void {
    try http1.validateRequestTargetForMethod(options.method, options.target);
    var has_host = false;
    for (options.headers) |header| {
        if (header.eqlName("host")) has_host = true;
    }
    const header_count = std.math.add(
        usize,
        options.headers.len,
        @intFromBool(!has_host and options.host != null),
    ) catch return error.HeadersTooLarge;
    var header_stack: [storage.stack_capacity]http1.Header =
        undefined;
    const headers = try storage.acquire(
        http1.Header,
        allocator,
        &header_stack,
        header_count,
    );
    defer storage.release(
        http1.Header,
        allocator,
        &header_stack,
        headers,
    );
    @memcpy(headers[0..options.headers.len], options.headers);
    if (!has_host) {
        if (options.host) |host| {
            headers[options.headers.len] = .{ .name = "Host", .value = host };
        }
    }
    try http1.validateHostHeaderBlock(options.version, headers);
    // Preflight the exact bodyless request-head size before allocating the
    // serialization buffer. `extra_headers` is caller-controlled, so checking
    // only after encoding would not make max_head_bytes a memory bound.
    var head_len = std.math.add(
        usize,
        options.method.string().len,
        1,
    ) catch return error.HeadersTooLarge;
    head_len = std.math.add(usize, head_len, options.target.len) catch
        return error.HeadersTooLarge;
    head_len = std.math.add(usize, head_len, 1) catch
        return error.HeadersTooLarge;
    head_len = std.math.add(usize, head_len, options.version.string().len) catch
        return error.HeadersTooLarge;
    head_len = std.math.add(usize, head_len, 2) catch
        return error.HeadersTooLarge;
    for (headers) |header| {
        head_len = std.math.add(usize, head_len, header.name.len) catch
            return error.HeadersTooLarge;
        head_len = std.math.add(usize, head_len, 2) catch
            return error.HeadersTooLarge;
        head_len = std.math.add(usize, head_len, header.value.len) catch
            return error.HeadersTooLarge;
        head_len = std.math.add(usize, head_len, 2) catch
            return error.HeadersTooLarge;
        if (head_len > max_head_bytes) return error.HeadersTooLarge;
    }
    head_len = std.math.add(usize, head_len, 2) catch
        return error.HeadersTooLarge;
    if (head_len > max_head_bytes) return error.HeadersTooLarge;

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try http1.writeRequestChecked(
        &encoded,
        allocator,
        options.method,
        options.target,
        options.version,
        headers,
        options.body,
    );
    // Upgrade requests never carry a body, so the encoded request is exactly
    // the head. Enforce the public head limit before exposing any bytes to the
    // transport; otherwise custom fields could bypass the receive-side bound.
    std.debug.assert(encoded.items.len == head_len);
    try write_parts(context, encoded.items, &.{});
}
