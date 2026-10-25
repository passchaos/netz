const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");
const window = @import("../flow/window.zig");
const allocator = std.testing.allocator;
const probe: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };

const Failure = enum { reset, content_length, trailers, quota, cancel, cancel_complete };

test "HTTP/2 failed pushes return prior DATA credit and preserve completed sibling" {
    for (std.enums.values(Failure)) |failure| try exercise(failure, false);
}

test "HTTP/2 push cleanup excludes DATA credit already returned by parent refill" {
    for (std.enums.values(Failure)) |failure| try exercise(failure, true);
}

fn appendPromise(connection: *runtime.Connection, id: u31) !void {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    var encoded: [4]u8 = undefined;
    std.mem.writeInt(u32, &encoded, id, .big);
    try bytes.appendSlice(allocator, &encoded);
    try http2.Hpack.encodeLiteralBlock(&bytes, allocator, &.{
        .{ .name = ":method", .value = "GET" }, .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/push" }, .{ .name = ":authority", .value = "localhost" },
    });
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .push_promise, 4, 1, bytes.items);
}

fn exercise(failure: Failure, parent_refill: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    const peer = try listener.accept(io);
    defer peer.close(io);
    var connection = runtime.Connection{ .io = io, .allocator = allocator, .stream = stream, .role = .client, .limits = .{ .enable_push = true, .max_buffered_push_bytes = if (failure == .quota) 256 else 1024 * 1024 } };
    defer connection.close();
    try appendPromise(&connection, 2);
    try appendPromise(&connection, 4);
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 4, 2, if (failure == .content_length or failure == .trailers) "\x88\x0f\x0d\x01\x33" else "\x88");
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, if (failure == .cancel_complete) 9 else 8, 2, "\x02ab\x00\x00");
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 4, 4, "\x88");
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 1, 4, "xyz");
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, if (parent_refill) 4 else 5, 1, "\x88");
    if (parent_refill) {
        const body = "a" ** 8192;
        for (0..4) |index| try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, if (index == 3) 1 else 0, 1, body);
    }
    var parent = try connection.requestWithTimeout(.{ .authority = "localhost" }, .fromSeconds(1));
    defer parent.deinit(allocator);
    try std.testing.expectEqual(window.default_value - @as(i64, if (parent_refill) 0 else 5), connection.recv_connection_window.value);
    var failed = connection.takePromisedRequest() orelse return error.MissingPromise;
    var failed_owned = true;
    defer if (failed_owned) failed.deinit(allocator);
    var sibling = connection.takePromisedRequest() orelse return error.MissingPromise;
    defer sibling.deinit(allocator);
    if (failure == .cancel or failure == .cancel_complete) {
        try connection.cancelPush(&failed);
        failed_owned = false;
    } else {
        switch (failure) {
            .reset => try wire.appendFrame(&connection.frame_reader.buffer, allocator, .rst_stream, 0, 2, &.{ 0, 0, 0, 8 }),
            .content_length => try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 9, 2, "\x00cd"),
            .trailers => try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 5, 2, "\x40\x01x\x01y"),
            .quota => try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 0, 2, "a" ** 512),
            else => unreachable,
        }
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .ping, 1, 0, &probe);
        _ = try connection.pingWithTimeout(probe, .fromSeconds(1));
        try std.testing.expectError(switch (failure) {
            .reset => error.StreamReset,
            .quota => error.PushBufferFull,
            else => error.InvalidContentLength,
        }, connection.readPushedResponseWithTimeout(failed, .fromSeconds(1)));
    }
    try std.testing.expect(!connection.aggregate_timeout_unusable);
    const expected = window.default_value - @as(i64, if (parent_refill) 0 else 3);
    if (expected != connection.recv_connection_window.value) {
        std.debug.print("push {s} parent_refill={any} left window {d} instead of {d}\n", .{ @tagName(failure), parent_refill, connection.recv_connection_window.value, expected });
        return error.PushCreditNotReleased;
    }
    var healthy = try connection.readPushedResponseWithTimeout(sibling, .fromSeconds(1));
    defer healthy.deinit(allocator);
    try std.testing.expectEqualStrings("xyz", healthy.body);
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 5, 3, if (failure == .trailers) "\x88\xbe" else "\x88");
    var next = try connection.requestWithTimeout(.{ .authority = "localhost" }, .fromSeconds(1));
    defer next.deinit(allocator);
    if (failure == .trailers) try std.testing.expectEqualStrings("y", runtime.testing.findHeader(next.headers, "x").?);
}
