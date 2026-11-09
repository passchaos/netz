//! EOF-delimited responses retain body input before growing storage.
const std = @import("std");
const runtime = @import("../../runtime.zig");
const allocator = std.testing.allocator;
const Shape = enum { eof, transfer };
const payload = [_]u8{'r'} ** 8192;

test "HTTP1 buffered EOF allocation retries preserve exact body" {
    for (std.enums.values(Shape)) |shape| {
        var succeeded = false;
        for (0..24) |fail_index| {
            if (try exercise(shape, fail_index)) {
                succeeded = true;
                break;
            }
        }
        try std.testing.expect(succeeded);
    }
}

fn exercise(shape: Shape, fail_index: usize) !bool {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
    defer listener.deinit(io);
    const socket = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer socket.close(io);
    const peer = try listener.accept(io);
    defer peer.close(io);
    const prefix: []const u8 = switch (shape) {
        .eof => "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n",
        .transfer => "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nContent-Length: 1\r\n\r\n",
    };
    var input = std.ArrayList(u8).fromOwnedSlice(try allocator.dupe(u8, prefix));
    defer input.deinit(allocator);
    var writer = peer.writer(io, &.{});
    try writer.interface.writeAll(&payload);
    try peer.shutdown(io, .send);
    const body_len = payload.len;
    const options = @import("../../mod.zig").ParseOptions{};
    const limits = runtime.Limits{ .max_body_bytes = body_len };
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index, .resize_fail_index = 0 });
    const result = runtime.readResponseFromStreamBufferedForRequestWithTimeout(failing.allocator(), io, socket, limits, options, &input, .GET, .fromSeconds(1));
    var response = if (failing.has_induced_failure) blk: {
        try std.testing.expectError(error.OutOfMemory, result);
        break :blk try runtime.readResponseFromStreamBufferedForRequestWithTimeout(allocator, io, socket, limits, options, &input, .GET, .fromSeconds(1));
    } else try result;
    defer response.deinit(allocator);
    try std.testing.expectEqual(body_len, response.response.body.len);
    try std.testing.expectEqualStrings(&payload, response.response.body);
    try std.testing.expect(!response.response.keepAlive());
    try std.testing.expectEqual(@as(usize, 0), input.items.len);
    return !failing.has_induced_failure;
}
