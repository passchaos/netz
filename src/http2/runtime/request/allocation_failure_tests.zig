const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");
const window = @import("../flow/window.zig");
const frame_io = @import("../frame/io.zig");

const allocator = std.testing.allocator;
const Mode = enum { aggregate, streaming, batch };
const Shape = enum { empty, declared, growing, padded, fragmented, trailers, sibling };

const Fixture = struct {
    connection: runtime.Connection,
    peer: std.Io.net.Stream,

    fn init(io: std.Io) !Fixture {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);
        const peer = try listener.accept(io);
        return .{ .connection = .{ .io = io, .allocator = allocator, .stream = stream, .role = .server }, .peer = peer };
    }

    fn deinit(self: *@This()) void {
        self.connection.allocator = allocator;
        self.peer.close(self.connection.io);
        self.connection.close();
    }
};

test "HTTP/2 request allocation failure retires discarded aggregate state" {
    for (std.enums.values(Shape)) |shape| {
        try exhaust(.aggregate, shape, false, false);
        try exhaust(.aggregate, shape, true, false);
    }
}

test "HTTP/2 request allocation failure retires discarded streaming state" {
    for (std.enums.values(Shape)) |shape| {
        try exhaust(.streaming, shape, false, false);
        try exhaust(.streaming, shape, true, false);
    }
}

test "HTTP/2 request allocation failure retires discarded batch state" {
    for (std.enums.values(Shape)) |shape| {
        if (shape == .sibling) continue;
        try exhaust(.batch, shape, false, false);
        try exhaust(.batch, shape, true, false);
    }
}

test "HTTP/2 request allocation failure keeps real TCP cancellation and credit consistent" {
    for (std.enums.values(Mode)) |mode| {
        for (std.enums.values(Shape)) |shape| {
            if (mode == .batch and shape == .sibling) continue;
            try exhaust(mode, shape, true, true);
        }
    }
}

fn consume(_: void, _: []const u8) !void {}
fn consumeBatch(_: void, _: u31, _: []const u8) !void {}

fn exhaust(mode: Mode, shape: Shape, bounded: bool, from_socket: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for (0..100) |fail_index| {
        var fixture = try Fixture.init(threaded.io());
        defer fixture.deinit();
        const connection = &fixture.connection;
        try appendRequest(connection, 1, shape);
        if (mode == .batch) try appendRequest(connection, 3, .empty);
        // Later wire input must never be surfaced after this operation loses
        // the only owner of a consumed head, body, or HPACK section.
        try appendRequest(connection, 5, .empty);
        if (from_socket) {
            try sendBuffered(&fixture);
            // Fault message ownership after transport storage is available.
            try connection.frame_reader.buffer.ensureTotalCapacityPrecise(allocator, 64 * 1024);
        }
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index, .resize_fail_index = 0 });
        connection.allocator = failing.allocator();
        const outcome = read(connection, mode, bounded);
        connection.allocator = allocator;
        if (outcome) |_| {
            try std.testing.expect(!failing.has_induced_failure);
            return;
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(failing.has_induced_failure);
            if (!connection.aggregate_timeout_unusable) {
                std.debug.print("discarded {s}/{s} request at allocation {d} remains reusable\n", .{ @tagName(mode), @tagName(shape), fail_index });
                return error.DiscardedRequestRemainsReusable;
            }
            try std.testing.expectEqual(@as(usize, 0), connection.active_peer_streams.items.len);
            try std.testing.expectEqual(@as(usize, 0), connection.recv_stream_windows.items.len);
            try std.testing.expectEqual(@as(usize, 0), connection.response_semantics.items.len);
            try std.testing.expectEqual(@as(usize, 0), connection.pending_requests.items.len);
            try std.testing.expectEqual(window.default_value, connection.recv_connection_window.value);
            const cursor = connection.frame_reader.start;
            try std.testing.expectError(error.ConnectionClosed, connection.readRequest());
            try std.testing.expectError(error.ConnectionClosed, connection.readRequestStreaming({}, consume));
            var requests: [2]runtime.StreamingRequest = undefined;
            try std.testing.expectError(error.ConnectionClosed, connection.readRequestBatchStreamingInto(&requests, {}, consumeBatch));
            try std.testing.expectEqual(cursor, connection.frame_reader.start);
            try expectCancellation(&fixture);
        }
    }
    return error.FailureSequenceDidNotFinish;
}

fn sendBuffered(fixture: *Fixture) !void {
    const connection = &fixture.connection;
    const bytes = try connection.frame_reader.buffer.toOwnedSlice(allocator);
    defer allocator.free(bytes);
    var writer = fixture.peer.writer(connection.io, &.{});
    try writer.interface.writeAll(bytes);
    try fixture.peer.shutdown(connection.io, .send);
}

fn expectCancellation(fixture: *Fixture) !void {
    const connection = &fixture.connection;
    try connection.stream.shutdown(connection.io, .send);
    var reader: frame_io.Reader = .{};
    defer reader.deinit(allocator);
    var reset_ids: [2]bool = .{ false, false };
    var refunded: usize = 0;
    while (true) {
        const incoming = reader.read(allocator, connection.io, fixture.peer, 16_384) catch |err| switch (err) {
            error.ConnectionClosed => break,
            else => return err,
        };
        switch (incoming.frame.header.frame_type) {
            .rst_stream => {
                const reset = try http2.ResetStreamPayload.parse(incoming.frame);
                try std.testing.expectEqual(http2.ErrorCode.cancel, reset.error_code);
                try std.testing.expect(reset.stream_id == 1 or reset.stream_id == 3);
                const index: usize = if (reset.stream_id == 1) 0 else 1;
                try std.testing.expect(!reset_ids[index]);
                reset_ids[index] = true;
            },
            .window_update => {
                const update = try http2.WindowUpdatePayload.parse(incoming.frame);
                try std.testing.expectEqual(@as(u31, 0), update.stream_id);
                refunded += update.increment;
            },
            else => return error.UnexpectedCleanupFrame,
        }
    }
    if (connection.last_peer_client_stream_id >= 1) try std.testing.expect(reset_ids[0]);
    if (connection.last_peer_client_stream_id >= 3) try std.testing.expect(reset_ids[1]);
    try std.testing.expect(refunded <= 260);
}

fn read(connection: *runtime.Connection, mode: Mode, bounded: bool) !void {
    switch (mode) {
        .aggregate => {
            var request = if (bounded) try connection.readRequestWithTimeout(.fromSeconds(1)) else try connection.readRequest();
            defer request.deinit(connection.allocator);
        },
        .streaming => {
            var request = if (bounded) try connection.readRequestStreamingWithTimeout(.fromSeconds(1), {}, consume) else try connection.readRequestStreaming({}, consume);
            defer request.deinit(connection.allocator);
        },
        .batch => {
            var requests: [2]runtime.StreamingRequest = undefined;
            if (bounded) try connection.readRequestBatchStreamingIntoWithTimeout(&requests, .fromSeconds(1), {}, consumeBatch) else try connection.readRequestBatchStreamingInto(&requests, {}, consumeBatch);
            defer for (&requests) |*request| request.deinit(connection.allocator);
        },
    }
}

fn appendRequest(connection: *runtime.Connection, id: u31, shape: Shape) !void {
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = ":path", .value = "/allocation" },
    });
    if (shape == .declared) try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{.{ .name = "content-length", .value = "257" }});
    const bytes = &connection.frame_reader.buffer;
    if (shape == .fragmented) {
        const split = block.items.len / 2;
        try wire.appendFrame(bytes, allocator, .headers, 0, id, block.items[0..split]);
        try wire.appendFrame(bytes, allocator, .continuation, 4, id, block.items[split..]);
    } else {
        try wire.appendFrame(bytes, allocator, .headers, if (shape == .empty) 5 else 4, id, block.items);
    }
    if (shape == .empty) return;
    const body = "a" ** 257;
    if (shape == .padded) {
        try wire.appendFrame(bytes, allocator, .data, 0x08, id, "\x02ab\x00\x00");
    } else {
        try wire.appendFrame(bytes, allocator, .data, 0, id, body[0..2]);
    }
    if (shape == .sibling) try appendRequest(connection, 3, .empty);
    try wire.appendFrame(bytes, allocator, .data, if (shape == .trailers) 0 else 1, id, body[2..]);
    if (shape == .trailers) {
        block.clearRetainingCapacity();
        try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{.{ .name = "x-complete", .value = "yes" }});
        try wire.appendFrame(bytes, allocator, .headers, 5, id, block.items);
    }
}

test "HTTP/2 request allocation failure before admission preserves real TCP input" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for (std.enums.values(Mode)) |mode| {
        var fixture = try Fixture.init(threaded.io());
        defer fixture.deinit();
        const connection = &fixture.connection;
        try appendRequest(connection, 1, .empty);
        if (mode == .batch) try appendRequest(connection, 3, .empty);
        try sendBuffered(&fixture);
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        connection.allocator = failing.allocator();
        try std.testing.expectError(error.OutOfMemory, read(connection, mode, true));
        connection.allocator = allocator;
        try std.testing.expect(!connection.aggregate_timeout_unusable);
        try std.testing.expectEqual(@as(u31, 0), connection.last_peer_client_stream_id);
        try read(connection, mode, true);
    }
}

test "HTTP/2 request allocation failure from application callbacks remains stream local" {
    const Reject = struct {
        fn begin(_: void, _: runtime.StreamingRequestHead) !void {
            return error.OutOfMemory;
        }
        fn body(_: void, _: []const u8) !void {
            return error.OutOfMemory;
        }
        fn batch(_: void, _: u31, _: []const u8) !void {
            return error.OutOfMemory;
        }
    };
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    for (0..3) |callback| {
        var fixture = try Fixture.init(threaded.io());
        defer fixture.deinit();
        const connection = &fixture.connection;
        try appendRequest(connection, 1, .padded);
        try appendRequest(connection, 5, .empty);
        if (callback == 0) {
            try std.testing.expectError(error.OutOfMemory, connection.readRequestStreamingWithHead({}, Reject.begin, consume));
        } else if (callback == 1) {
            try std.testing.expectError(error.OutOfMemory, connection.readRequestStreaming({}, Reject.body));
        } else {
            var requests: [2]runtime.StreamingRequest = undefined;
            try std.testing.expectError(error.OutOfMemory, connection.readRequestBatchStreamingInto(&requests, {}, Reject.batch));
        }
        try std.testing.expect(!connection.aggregate_timeout_unusable);
        try std.testing.expectEqual(window.default_value, connection.recv_connection_window.value);
        var healthy = try connection.readRequestWithTimeout(.fromSeconds(1));
        defer healthy.deinit(allocator);
        try std.testing.expectEqual(@as(u31, 5), healthy.stream_id);
        try std.testing.expectEqual(window.default_value, connection.recv_connection_window.value);
    }
}

test "HTTP/2 request allocation failure stops cancellation after a partial reset write" {
    try partialCleanupWrite(false);
    try partialCleanupWrite(true);
}

fn partialCleanupWrite(with_data: bool) !void {
    const Writer = struct {
        calls: usize = 0,
        fn write(context: ?*anyopaque, _: std.Io.net.Socket.Handle, header: []const u8, _: []const []const u8, _: usize) std.Io.net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            if (self.calls == 1) return @min(header.len, 4);
            return error.NetworkDown;
        }
    };
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var vtable = io.vtable.*;
    vtable.netWrite = Writer.write;
    var tested_sibling = false;
    for (0..100) |fail_index| {
        var fixture = try Fixture.init(io);
        defer fixture.deinit();
        const connection = &fixture.connection;
        try appendRequest(connection, 1, .empty);
        connection.frame_reader.buffer.items[4] = 4; // Keep request 1 open.
        if (with_data) try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 0, 1, "ab");
        try appendRequest(connection, 3, .empty);
        try appendRequest(connection, 5, .empty);
        try wire.appendFrame(&connection.frame_reader.buffer, allocator, .data, 1, 1, "");
        var writer: Writer = .{};
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
        connection.io = .{ .userdata = &writer, .vtable = &vtable };
        connection.allocator = failing.allocator();
        const outcome = read(connection, .aggregate, false);
        connection.io = io;
        connection.allocator = allocator;
        if (outcome) |_| break else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(writer.calls <= 2);
            if (writer.calls != 0) {
                try std.testing.expectEqual(@as(usize, 2), writer.calls);
                try std.testing.expect(connection.terminal_write_failed);
                if (connection.last_peer_client_stream_id >= 3) tested_sibling = true;
            }
            try std.testing.expectEqual(@as(usize, 0), connection.active_peer_streams.items.len);
            try std.testing.expectEqual(@as(usize, 0), connection.pending_requests.items.len);
        }
    }
    try std.testing.expect(tested_sibling);
}
