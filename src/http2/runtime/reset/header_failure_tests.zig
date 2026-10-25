//! Ignored field sections still own connection-wide HPACK progress.
const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");

const allocator = std.testing.allocator;
const probe: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 };

const Fixture = struct {
    connection: runtime.Connection,
    peer: std.Io.net.Stream,

    fn init(io: std.Io, limits: runtime.Limits) !Fixture {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);
        const peer = try listener.accept(io);
        return .{ .connection = .{ .io = io, .allocator = allocator, .stream = stream, .role = .client, .limits = limits }, .peer = peer };
    }

    fn deinit(self: *@This()) void {
        self.peer.close(self.connection.io);
        self.connection.close();
    }
};

test "HTTP/2 late reset HEADERS allocation failure forbids connection reuse" {
    try failClosed(true);
}

test "HTTP/2 late reset HEADERS sequence failure forbids connection reuse" {
    try failClosed(false);
}

fn failClosed(allocation_failure: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io(), .{});
    defer fixture.deinit();
    const connection = &fixture.connection;
    const id = try runtime.testing.reserveNextClientStreamId(connection);
    try connection.sendResetStream(id, .cancel);
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, if (allocation_failure) 0x4 else 0, id, if (allocation_failure) "\x40\x01x\x01y" else &.{0x88});
    if (!allocation_failure) {
        // A PING cannot occur until this HEADERS section ends.
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .ping, 0, 0, &probe);
    }
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .ping, 1, 0, &probe);
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    if (allocation_failure) connection.allocator = failing.allocator();
    const result = connection.pingWithTimeout(probe, .fromSeconds(1));
    connection.allocator = allocator;
    if (allocation_failure) {
        try std.testing.expectError(error.OutOfMemory, result);
        try std.testing.expect(failing.has_induced_failure);
    } else {
        try std.testing.expectError(error.UnexpectedFrame, result);
    }
    try std.testing.expect(!connection.isReusable());
    try std.testing.expectError(error.ConnectionClosed, connection.pingWithTimeout(probe, .fromSeconds(1)));
}

test "HTTP/2 late reset HEADERS exceeding output limits preserve dynamic-table synchronization" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io(), .{ .max_header_fields = 2, .max_header_list_size = 128 });
    defer fixture.deinit();
    const connection = &fixture.connection;
    const id = try runtime.testing.reserveNextClientStreamId(connection);
    try connection.sendResetStream(id, .cancel);
    // These ignored status fields exceed both output limits. The final literal
    // must nevertheless enter the dynamic table for a later stream's index 62.
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 0x4, id, "\x88" ** 64 ++ "\x40\x01x\x01y");
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .ping, 1, 0, &probe);
    _ = try connection.pingWithTimeout(probe, .fromSeconds(1));
    try std.testing.expect(connection.isReusable());
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 0x5, 3, "\x88\xbe");
    var response = try connection.requestWithTimeout(.{ .path = "/healthy", .authority = "localhost" }, .fromSeconds(1));
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("y", runtime.testing.findHeader(response.headers, "x").?);
}

test "HTTP/2 late reset HEADERS validates without allocating discarded field output" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io(), .{ .max_header_fields = 1, .max_header_list_size = 1 });
    defer fixture.deinit();
    const connection = &fixture.connection;
    const id = try runtime.testing.reserveNextClientStreamId(connection);
    try connection.sendResetStream(id, .cancel);
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 0x4, id, "\x88" ** 64);
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .ping, 1, 0, &probe);
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    connection.allocator = failing.allocator();
    defer connection.allocator = allocator;
    _ = try connection.pingWithTimeout(probe, .fromSeconds(1));
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expect(connection.isReusable());
}

test "HTTP/2 late reset HEADERS retains compression and unfinished assembly errors" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |assembly_limit| {
        var fixture = try Fixture.init(threaded.io(), .{ .max_header_fields = 1, .max_header_list_size = 1, .max_continuation_frames = 1 });
        defer fixture.deinit();
        const connection = &fixture.connection;
        const id = try runtime.testing.reserveNextClientStreamId(connection);
        try connection.sendResetStream(id, .cancel);
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, if (assembly_limit) 0 else 0x4, id, if (assembly_limit) &.{0x88} else "\x88" ** 64 ++ "\x80");
        if (assembly_limit) {
            for (0..2) |_| try wire.appendFrame(&connection.frame_reader.buffer, allocator, .continuation, 0, id, &.{0x88});
        }
        try std.testing.expectError(if (assembly_limit) error.MessageTooLarge else error.InvalidEncoding, connection.pingWithTimeout(probe, .fromSeconds(1)));
        if (!assembly_limit) try std.testing.expect(connection.hpack_decoder.lastDecodeWasCompressionError());
        try std.testing.expect(!connection.isReusable());
    }
}

fn queueFrame(connection: *runtime.Connection, kind: http2.FrameType, flags: u8, id: u31, bytes: []const u8) !void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try wire.appendFrame(&encoded, allocator, kind, flags, id, bytes);
    const owned = try encoded.toOwnedSlice(allocator);
    errdefer allocator.free(owned);
    try runtime.testing.queuePendingApplicationFrame(connection, .{ .bytes = owned, .frame = try http2.Frame.parse(owned) });
}

test "HTTP/2 late reset HEADERS retires deferred input without duplicate HPACK changes" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |already_decoded| {
        var fixture = try Fixture.init(threaded.io(), .{ .enable_push = true });
        defer fixture.deinit();
        const connection = &fixture.connection;
        const id = try runtime.testing.reserveNextClientStreamId(connection);
        try queueFrame(connection, .headers, 0, id, "\x88\x40\x01x\x01y");
        if (already_decoded) {
            try queueFrame(connection, .continuation, 0x4, id, "\x40\x01z\x01w");
        } else {
            try wire.appendFrame(&connection.frame_reader.buffer, allocator, .continuation, 0x4, id, "\x40\x01z\x01w");
        }
        try connection.sendResetStream(id, .cancel);
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 0x5, 3, "\x88\xbe\xbf");
        var response = try connection.requestWithTimeout(.{ .path = "/healthy", .authority = "localhost" }, .fromSeconds(1));
        defer response.deinit(allocator);
        try std.testing.expectEqualStrings("w", runtime.testing.findHeader(response.headers, "z").?);
        try std.testing.expectEqualStrings("y", runtime.testing.findHeader(response.headers, "x").?);
        try std.testing.expectEqual(@as(usize, 68), connection.hpack_decoder.dynamic_table.used);
        // Push-enabled connections deliberately stay outside exclusive pools;
        // the connection itself and its HPACK state must remain usable.
        try std.testing.expect(!connection.aggregate_timeout_unusable);
    }
}

test "HTTP/2 late reset HEADERS terminal assembly overflow is discarded completely" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io(), .{ .max_header_fields = 1, .max_header_list_size = 1, .max_continuation_frames = 1 });
    defer fixture.deinit();
    const connection = &fixture.connection;
    const id = try runtime.testing.reserveNextClientStreamId(connection);
    try connection.sendResetStream(id, .cancel);
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .headers, 0, id, &.{0x88});
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .continuation, 0, id, &.{0x88});
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .continuation, 0x4, id, "\x40\x01x\x01y");
    try wire.appendFrame(&connection.frame_reader.buffer, allocator, .ping, 1, 0, &probe);
    _ = try connection.pingWithTimeout(probe, .fromSeconds(1));
    try std.testing.expectEqual(@as(usize, 34), connection.hpack_decoder.dynamic_table.used);
    try std.testing.expect(connection.isReusable());
}
