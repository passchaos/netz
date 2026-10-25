const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");
const frame_io = @import("../frame/io.zig");
const window = @import("../flow/window.zig");

const allocator = std.testing.allocator;
const Mode = enum { aggregate, streaming };
const Shape = enum { empty, declared, growing, padded, fragmented, trailers, informational, dynamic, forbidden };

test {
    _ = @import("connect_allocation_tests.zig");
    _ = @import("cleanup_failure_tests.zig");
    _ = @import("trailer_sync_tests.zig");
}

const Fixture = struct {
    connection: runtime.Connection,
    peer: std.Io.net.Stream,

    fn init(io: std.Io) !Fixture {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);
        const peer = try listener.accept(io);
        errdefer peer.close(io);
        var connection = runtime.Connection{ .io = io, .allocator = allocator, .stream = stream, .role = .client };
        try runtime.testing.addActiveLocalStream(&connection, 1);
        return .{ .connection = connection, .peer = peer };
    }

    fn deinit(self: *@This()) void {
        self.connection.allocator = allocator;
        self.peer.close(self.connection.io);
        self.connection.close();
    }
};

fn consume(_: void, _: []const u8) !void {}

test "HTTP/2 response allocation failure retires discarded aggregate state" {
    for (std.enums.values(Shape)) |shape| {
        try exhaust(.aggregate, shape, false, false);
        try exhaust(.aggregate, shape, true, false);
    }
}

test "HTTP/2 response allocation failure retires discarded streaming state" {
    for (std.enums.values(Shape)) |shape| {
        try exhaust(.streaming, shape, false, false);
        try exhaust(.streaming, shape, true, false);
    }
}

test "HTTP/2 response allocation failure keeps TCP cancellation and credit consistent" {
    for (std.enums.values(Mode)) |mode| {
        for (std.enums.values(Shape)) |shape| try exhaust(mode, shape, true, true);
    }
}

fn exhaust(mode: Mode, shape: Shape, bounded: bool, from_socket: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for (0..100) |fail_index| {
        var fixture = try Fixture.init(threaded.io());
        defer fixture.deinit();
        const connection = &fixture.connection;
        try appendResponse(connection, 1, shape);
        try appendResponse(connection, 3, .empty);
        if (from_socket) {
            const bytes = try connection.frame_reader.buffer.toOwnedSlice(allocator);
            defer allocator.free(bytes);
            var writer = fixture.peer.writer(connection.io, &.{});
            try writer.interface.writeAll(bytes);
            try fixture.peer.shutdown(connection.io, .send);
            try connection.frame_reader.buffer.ensureTotalCapacityPrecise(allocator, 64 * 1024);
        }
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index, .resize_fail_index = 0 });
        connection.allocator = failing.allocator();
        const outcome = read(connection, mode, bounded, shape == .forbidden);
        connection.allocator = allocator;
        if (outcome) |_| {
            try std.testing.expect(!failing.has_induced_failure);
            return;
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            if (!connection.aggregate_timeout_unusable) {
                std.debug.print("discarded {s}/{s} response at allocation {d} remains reusable\n", .{ @tagName(mode), @tagName(shape), fail_index });
                return error.DiscardedResponseRemainsReusable;
            }
            try std.testing.expectEqual(@as(usize, 0), connection.active_local_streams.items.len);
            try std.testing.expectEqual(@as(usize, 0), connection.recv_stream_windows.items.len);
            try std.testing.expectEqual(window.default_value, connection.recv_connection_window.value);
            try std.testing.expect(!connection.isReusable());
            const cursor = connection.frame_reader.start;
            try std.testing.expectError(error.ConnectionClosed, connection.readResponseWithTimeout(3, "POST", false, .fromSeconds(1)));
            try std.testing.expectError(error.ConnectionClosed, connection.readResponseStreamingWithTimeout(3, "POST", false, .fromSeconds(1), {}, consume));
            try std.testing.expectEqual(cursor, connection.frame_reader.start);
            try expectCancellation(&fixture);
        }
    }
    return error.FailureSequenceDidNotFinish;
}

fn read(connection: *runtime.Connection, mode: Mode, bounded: bool, head: bool) !void {
    var request = runtime.RequestWriter{ .connection = connection, .stream_id = 1, .expected_length = 0, .head_request = head, .body_finished = true };
    switch (mode) {
        .aggregate => {
            var response = if (bounded) try request.readResponseWithTimeout(.fromSeconds(1)) else try request.readResponse();
            defer response.deinit(connection.allocator);
        },
        .streaming => {
            var response = if (bounded) try request.readResponseStreamingWithTimeout(.fromSeconds(1), {}, consume) else try request.readResponseStreaming({}, consume);
            defer response.deinit(connection.allocator);
        },
    }
}

fn appendResponse(connection: *runtime.Connection, id: u31, shape: Shape) !void {
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    const bytes = &connection.frame_reader.buffer;
    if (shape == .informational) {
        try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{
            .{ .name = ":status", .value = "103" },
            .{ .name = "link", .value = "</style.css>; rel=preload" },
        });
        try wire.appendFrame(bytes, allocator, .headers, 4, id, block.items);
        block.clearRetainingCapacity();
    }
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{.{ .name = ":status", .value = "200" }});
    if (shape == .declared) try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{.{ .name = "content-length", .value = "257" }});
    if (shape == .dynamic) try block.appendSlice(allocator, "\x40\x01x\x01y");
    if (shape == .fragmented) {
        const split = block.items.len / 2;
        try wire.appendFrame(bytes, allocator, .headers, 0, id, block.items[0..split]);
        try wire.appendFrame(bytes, allocator, .continuation, 4, id, block.items[split..]);
    } else {
        try wire.appendFrame(bytes, allocator, .headers, if (shape == .empty or shape == .dynamic) 5 else 4, id, block.items);
    }
    if (shape == .empty or shape == .dynamic) return;
    if (shape == .forbidden) {
        try wire.appendFrame(bytes, allocator, .data, 1, id, "");
        return;
    }
    const body = "a" ** 257;
    try wire.appendFrame(bytes, allocator, .data, if (shape == .padded) 0x08 else 0, id, if (shape == .padded) "\x02ab\x00\x00" else body[0..2]);
    try wire.appendFrame(bytes, allocator, .data, if (shape == .trailers) 0 else 1, id, body[2..]);
    if (shape == .trailers) {
        block.clearRetainingCapacity();
        try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{.{ .name = "x-done", .value = "yes" }});
        try wire.appendFrame(bytes, allocator, .headers, 5, id, block.items);
    }
}

fn expectCancellation(fixture: *Fixture) !void {
    const connection = &fixture.connection;
    try connection.stream.shutdown(connection.io, .send);
    var reader: frame_io.Reader = .{};
    defer reader.deinit(allocator);
    var resets: usize = 0;
    var refunded: usize = 0;
    while (true) {
        const incoming = reader.read(allocator, connection.io, fixture.peer, 16_384) catch |err| switch (err) {
            error.ConnectionClosed => break,
            else => return err,
        };
        switch (incoming.frame.header.frame_type) {
            .rst_stream => {
                const reset = try http2.ResetStreamPayload.parse(incoming.frame);
                try std.testing.expectEqual(@as(u31, 1), reset.stream_id);
                try std.testing.expectEqual(http2.ErrorCode.cancel, reset.error_code);
                resets += 1;
            },
            .window_update => {
                const update = try http2.WindowUpdatePayload.parse(incoming.frame);
                if (update.stream_id == 0) refunded += update.increment else {
                    try std.testing.expectEqual(@as(u31, 1), update.stream_id);
                    try std.testing.expect(update.increment <= 3);
                }
            },
            else => return error.UnexpectedCleanupFrame,
        }
    }
    try std.testing.expectEqual(@as(usize, 1), resets);
    try std.testing.expect(refunded <= 260);
}

test "HTTP/2 response reads reject a connection retired by timeout" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io());
    defer fixture.deinit();
    const connection = &fixture.connection;
    try std.testing.expectError(error.Timeout, connection.readResponseWithTimeout(1, "POST", false, .fromMilliseconds(1)));
    try appendResponse(connection, 3, .empty);
    const cursor = connection.frame_reader.start;
    try std.testing.expectError(error.ConnectionClosed, connection.readResponseWithTimeout(3, "POST", false, .fromSeconds(1)));
    try std.testing.expectError(error.ConnectionClosed, connection.readResponseStreamingWithTimeout(3, "POST", false, .fromSeconds(1), {}, consume));
    try std.testing.expectEqual(cursor, connection.frame_reader.start);
}
