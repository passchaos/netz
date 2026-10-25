//! An accepted 100 Continue belongs to the pending request across local OOM.
const std = @import("std");
const runtime = @import("../../runtime.zig");
const allocator = std.testing.allocator;
const interim = "HTTP/1.1 100 Continue\r\n\r\n";
const http1 = @import("../../mod.zig");
const Shape = enum { fixed, chunked, folded };
const Retry = enum { aggregate, streaming, batch };

const Observer = struct {
    base: std.Io,
    writes: usize = 0,
    cancel_read: bool = false,
    pub var active: *@This() = undefined;
    fn netWrite(_: ?*anyopaque, handle: std.Io.net.Socket.Handle, header: []const u8, parts: []const []const u8, splat: usize) std.Io.net.Stream.Writer.Error!usize {
        const self = active;
        const count = try self.base.vtable.netWrite(self.base.userdata, handle, header, parts, splat);
        self.writes += 1;
        return count;
    }

    fn netRead(_: ?*anyopaque, handle: std.Io.net.Socket.Handle, out: [][]u8) std.Io.net.Stream.Reader.Error!usize {
        const self = active;
        if (self.cancel_read) {
            self.cancel_read = false;
            return error.Canceled;
        }
        return self.base.vtable.netRead(self.base.userdata, handle, out);
    }
};

fn bytes(shape: Shape) []const u8 {
    return switch (shape) {
        .fixed => "POST /retry HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\nbody",
        .chunked => "POST /retry HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n4\r\nbody\r\n0\r\nX-Final: done\r\n\r\n",
        .folded => "POST /retry HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4,\r\n 4\r\nExpect: 100-continue\r\n\r\nbody",
    };
}

test "HTTP1 automatic Continue is emitted once across request decode allocation retries" {
    for (std.enums.values(Shape)) |shape| {
        var succeeded = false;
        for (0..32) |fail_index| {
            if (try exercise(shape, fail_index, .aggregate)) {
                succeeded = true;
                break;
            }
        }
        try std.testing.expect(succeeded);
    }
}

test "HTTP1 Continue retry transfers to streaming and borrowed batch readers" {
    for ([_]Retry{ .streaming, .batch }) |retry| _ = try exercise(.fixed, 0, retry);
}

fn exercise(shape: Shape, fail_index: usize, retry: Retry) !bool {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(base, .{});
    defer listener.deinit(base);
    const peer = try listener.socket.address.connect(base, .{ .mode = .stream });
    defer peer.close(base);
    const socket = try listener.accept(base);
    var observer = Observer{ .base = base };
    Observer.active = &observer;
    var vtable = base.vtable.*;
    vtable.netWrite = Observer.netWrite;
    var connection = runtime.Connection{ .allocator = allocator, .io = .{ .userdata = base.userdata, .vtable = &vtable }, .stream = socket };
    defer connection.close();
    try connection.inbuf.appendSlice(allocator, bytes(shape));
    try connection.inbuf.appendSlice(allocator, bytes(.fixed));
    const options: http1.ParseOptions = .{ .allow_obs_fold = shape == .folded };
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index, .resize_fail_index = 0 });
    const result = blk: {
        connection.allocator = failing.allocator();
        defer connection.allocator = allocator;
        break :blk connection.readRequest(options);
    };
    if (failing.has_induced_failure) {
        try std.testing.expectError(error.OutOfMemory, result);
        const writes_before = observer.writes;
        var repeated = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0, .resize_fail_index = 0 });
        {
            connection.allocator = repeated.allocator();
            defer connection.allocator = allocator;
            try std.testing.expectError(error.OutOfMemory, connection.readRequest(options));
        }
        try std.testing.expectEqual(writes_before, observer.writes);
        switch (retry) {
            .aggregate => {
                var request = try connection.readRequestWithTimeout(options, .fromSeconds(1));
                defer request.deinit(allocator);
                try std.testing.expectEqualStrings("body", request.request.body);
                if (shape == .chunked) try std.testing.expectEqualStrings("done", request.request.trailers[0].value);
            },
            .streaming => {
                const Sink = struct {
                    len: usize = 0,
                    storage: [4]u8 = undefined,
                    fn consume(self: *@This(), input: []const u8) !void {
                        @memcpy(self.storage[self.len..][0..input.len], input);
                        self.len += input.len;
                    }
                };
                var sink: Sink = .{};
                var request = try connection.readRequestStreaming(&sink, Sink.consume);
                defer request.deinit(allocator);
                try std.testing.expectEqualStrings("body", sink.storage[0..sink.len]);
            },
            .batch => {
                var heads: [1]http1.RequestHead = undefined;
                var headers: [8]http1.Header = undefined;
                var bodies: [1][]const u8 = undefined;
                const consumed = try connection.readRequestBatchInto(&heads, &headers, &bodies, .{ .max_headers = 8 });
                try std.testing.expectEqualStrings("body", bodies[0]);
                try connection.consumeRequestBatch(0);
                try std.testing.expect(connection.request_continue.sent);
                try connection.consumeRequestBatch(consumed);
            },
        }
    } else {
        var request = try result;
        request.deinit(allocator);
    }
    try std.testing.expectEqual(@as(usize, 1), observer.writes);
    var response: [interim.len]u8 = undefined;
    var reader = peer.reader(base, &.{});
    try reader.interface.readSliceAll(&response);
    try std.testing.expectEqualStrings(interim, &response);
    var next = try connection.readRequestWithTimeout(.{}, .fromSeconds(1));
    defer next.deinit(allocator);
    try std.testing.expectEqualStrings("body", next.request.body);
    try std.testing.expectEqual(@as(usize, 2), observer.writes);
    try reader.interface.readSliceAll(&response);
    try std.testing.expectEqualStrings(interim, &response);
    try std.testing.expect(!connection.request_continue.sent);
    return !failing.has_induced_failure;
}

test "HTTP1 automatic Continue survives a canceled body read and resets on semantic consumption" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(base, .{});
    defer listener.deinit(base);
    const peer = try listener.socket.address.connect(base, .{ .mode = .stream });
    defer peer.close(base);
    const socket = try listener.accept(base);
    var observer = Observer{ .base = base, .cancel_read = true };
    Observer.active = &observer;
    var vtable = base.vtable.*;
    vtable.netWrite = Observer.netWrite;
    vtable.netRead = Observer.netRead;
    var connection = runtime.Connection{ .allocator = allocator, .io = .{ .userdata = base.userdata, .vtable = &vtable }, .stream = socket };
    defer connection.close();
    try connection.inbuf.appendSlice(allocator, bytes(.fixed)[0 .. bytes(.fixed).len - 2]);
    try std.testing.expectError(error.Canceled, connection.readRequest(.{}));
    try std.testing.expect(connection.request_continue.sent);
    try std.testing.expect(connection.writer_state.phase == .idle);
    var writer = peer.writer(base, &.{});
    try writer.interface.writeAll("dy");
    var request = try connection.readRequest(.{});
    defer request.deinit(allocator);
    try std.testing.expectEqualStrings("body", request.request.body);
    try std.testing.expectEqual(@as(usize, 1), observer.writes);
    try std.testing.expect(!connection.request_continue.sent);
    // A complete malformed trailer is consumed by the owning parser. Its
    // Continue state must not suppress the next request's response.
    try connection.inbuf.appendSlice(allocator, "POST /bad HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n0\r\nContent-Length: 4\r\n\r\n");
    try connection.inbuf.appendSlice(allocator, bytes(.fixed));
    try std.testing.expectError(error.InvalidTrailer, connection.readRequest(.{}));
    try std.testing.expect(!connection.request_continue.sent);
    var next = try connection.readRequest(.{});
    defer next.deinit(allocator);
    try std.testing.expectEqualStrings("body", next.request.body);
    try std.testing.expectEqual(@as(usize, 3), observer.writes);
}
