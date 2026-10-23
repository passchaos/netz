//! Prepare a bounded 101 response before mutating transport or pending state.

const std = @import("std");
const http1 = @import("../../../http1/mod.zig");
const server = @import("../../handshake/server.zig");
const headers = @import("headers.zig");
const storage = @import("storage.zig");

pub const Options = struct {
    client_key: []const u8,
    protocol: ?[]const u8 = null,
    extension: ?[]const u8 = null,
    configured_headers: []const http1.Header = &.{},
    additional_headers: []const http1.Header = &.{},
    max_head_bytes: usize,
};

pub fn prepare(allocator: std.mem.Allocator, options: Options) ![]u8 {
    try headers.validateHttp1AcceptExtra(options.configured_headers);
    try headers.validateHttp1AcceptExtra(options.additional_headers);
    var negotiated: [2]http1.Header = undefined;
    var count: usize = 0;
    if (options.protocol) |value| {
        negotiated[count] = .{ .name = "Sec-WebSocket-Protocol", .value = value };
        count += 1;
    }
    if (options.extension) |value| {
        negotiated[count] = .{ .name = "Sec-WebSocket-Extensions", .value = value };
        count += 1;
    }
    const groups = [_][]const http1.Header{
        negotiated[0..count], options.configured_headers, options.additional_headers,
    };
    const len = server.encodedLen(options.client_key, &groups) catch |err| switch (err) {
        error.PayloadTooLarge => return error.HeadersTooLarge,
        else => return err,
    };
    if (len > options.max_head_bytes) return error.HeadersTooLarge;
    // Every field contributes at least its name plus ': ' and CRLF to the
    // checked wire budget. Descriptor storage is acquired only after it fits.
    for (groups[1..]) |group| count = std.math.add(usize, count, group.len) catch return error.HeadersTooLarge;
    var stack: [storage.stack_capacity]http1.Header = undefined;
    const fields = try storage.acquire(http1.Header, allocator, &stack, count);
    defer storage.release(http1.Header, allocator, &stack, fields);
    var offset: usize = 0;
    for (groups) |group| {
        @memcpy(fields[offset..][0..group.len], group);
        offset += group.len;
    }
    var encoded: std.ArrayList(u8) = .empty;
    errdefer encoded.deinit(allocator);
    try encoded.ensureTotalCapacityPrecise(allocator, len);
    try server.write(&encoded, allocator, options.client_key, fields);
    std.debug.assert(encoded.items.len == len);
    return encoded.toOwnedSlice(allocator);
}

test "WebSocket acceptance exact head limit includes mandatory fields and delimiter" {
    const expected =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" ++
        "Sec-WebSocket-Protocol: chat.v1\r\nX-Test: ok\r\n\r\n";
    var options = Options{
        .client_key = "dGhlIHNhbXBsZSBub25jZQ==",
        .protocol = "chat.v1",
        .additional_headers = &.{.{ .name = "X-Test", .value = "ok" }},
        .max_head_bytes = expected.len - 1,
    };
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.HeadersTooLarge, prepare(failing.allocator(), options));
    try std.testing.expect(!failing.has_induced_failure);
    options.max_head_bytes = expected.len;
    const bytes = try prepare(std.testing.allocator, options);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings(expected, bytes);
}
