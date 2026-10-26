//! Zero-progress expiry retains a later-deadline stream and exact DATA suffix.
const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../../runtime.zig");
const http2 = @import("../../mod.zig");
const frame_io = @import("../frame/io.zig");
const wire = @import("../frame/wire.zig");
const BlockedOutput = @import("../testing/blocked_output.zig").BlockedOutput;
const allocator = std.testing.allocator;

const DelayedWrite = struct {
    var active: std.atomic.Value(?*DelayedWrite) = .init(null);
    io: std.Io,
    at: usize,
    calls: std.atomic.Value(usize) = .init(0),
    fn write(userdata: ?*anyopaque, handle: std.Io.net.Socket.Handle, header: []const u8, data: []const []const u8, splat: usize) std.Io.net.Stream.Writer.Error!usize {
        const self = active.load(.acquire).?;
        if (self.calls.fetchAdd(1, .monotonic) == self.at) try std.Io.sleep(self.io, .fromSeconds(1), .awake);
        return self.io.vtable.netWrite(userdata, handle, header, data, splat);
    }
};
const Observer = struct {
    errors: [2]?anyerror = .{ null, null },
    response: ?runtime.OwnedResponse = null,
    fn result(context: *anyopaque, index: usize, value: runtime.BatchOwnedResponseResult) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        switch (value) {
            .err => |err| self.errors[index] = err,
            .response => |response| {
                self.response = response;
            },
        }
    }
};

fn exercise(data: bool) !void {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try BlockedOutput.init(io, .client);
    defer fixture.deinit();
    const Peer = struct {
        stream: std.Io.net.Stream,
        io: std.Io,
        data: bool,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }
        fn serve(self: *@This()) !void {
            var heads: usize = 0;
            var canceled = false;
            while (true) {
                var frame = try frame_io.readOwned(allocator, self.io, self.stream, 16_384);
                defer frame.deinit(allocator);
                switch (frame.frame.header.frame_type) {
                    .headers => {
                        heads += 1;
                        try std.testing.expectEqual(@as(u31, if (self.data and heads == 1) 1 else 3), frame.frame.header.stream_id);
                        if (!self.data) break;
                    },
                    .rst_stream => {
                        const reset = try http2.ResetStreamPayload.parse(frame.frame);
                        try std.testing.expectEqual(@as(u31, 1), reset.stream_id);
                        try std.testing.expectEqual(http2.ErrorCode.cancel, reset.error_code);
                        canceled = true;
                    },
                    .data => {
                        try std.testing.expect(self.data and canceled);
                        try std.testing.expectEqual(@as(u31, 3), frame.frame.header.stream_id);
                        try std.testing.expectEqualStrings("alive", frame.frame.payload);
                        try std.testing.expect((frame.frame.header.flags & 1) != 0);
                        break;
                    },
                    else => return error.UnexpectedFrame,
                }
            }
            try std.testing.expectEqual(@as(usize, if (self.data) 2 else 1), heads);
            var response: std.ArrayList(u8) = .empty;
            defer response.deinit(allocator);
            try wire.appendFrame(&response, allocator, .headers, 4, 3, &.{0x88});
            try wire.appendFrame(&response, allocator, .data, 1, 3, "ok");
            var writer = self.stream.writer(self.io, &.{});
            try writer.interface.writeAll(response.items);
        }
    };
    var peer: Peer = .{ .stream = fixture.peer, .io = io, .data = data };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) {
        fixture.connection.stream.shutdown(io, .send) catch {};
        thread.join();
    };
    var delayed: DelayedWrite = .{ .io = io, .at = if (data) 1 else 0 };
    DelayedWrite.active.store(&delayed, .release);
    defer DelayedWrite.active.store(null, .release);
    var vtable = io.vtable.*;
    vtable.netWrite = DelayedWrite.write;
    fixture.connection.io = .{ .userdata = io.userdata, .vtable = &vtable };
    defer fixture.connection.io = io;
    const requests = [_]runtime.RequestOptions{
        .{ .method = "POST", .path = "/expired", .authority = "localhost", .body = if (data) "expired" else &.{} },
        .{ .method = "POST", .path = "/alive", .authority = "localhost", .body = if (data) "alive" else &.{} },
    };
    const deadlines = [_]?std.Io.Clock.Timestamp{
        .fromNow(io, .{ .raw = .fromMilliseconds(30), .clock = .awake }),
        .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
    };
    var observer: Observer = .{};
    defer if (observer.response) |*response| response.deinit(allocator);
    const output: runtime.BatchOwnedResponseObserver = .{ .context = &observer, .on_result = Observer.result };
    if (data) try fixture.connection.requestBodyBatchWithPerStreamDeadlines(&requests, 16_384, &deadlines, output) else try fixture.connection.requestBatchWithPerStreamDeadlines(&requests, &deadlines, output);
    try std.testing.expectEqual(@as(?anyerror, error.Timeout), observer.errors[0]);
    try std.testing.expect(observer.errors[1] == null);
    try std.testing.expectEqualStrings("ok", observer.response.?.body);
    try std.testing.expect(!fixture.connection.aggregate_timeout_unusable);
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.activeLocalStreamCount());
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

test "HTTP/2 batch zero-progress HEADERS expiry preserves a later stream" {
    try exercise(false);
}
test "HTTP/2 batch zero-progress DATA expiry rewinds offsets and preserves a later stream" {
    try exercise(true);
}

test "HTTP/2 batch zero-progress shared expiry rolls back unused stream IDs" {
    if (comptime builtin.os.tag != .linux) return;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try BlockedOutput.init(io, .client);
    defer fixture.deinit();
    var delayed: DelayedWrite = .{ .io = io, .at = 0 };
    DelayedWrite.active.store(&delayed, .release);
    defer DelayedWrite.active.store(null, .release);
    var vtable = io.vtable.*;
    vtable.netWrite = DelayedWrite.write;
    fixture.connection.io = .{ .userdata = io.userdata, .vtable = &vtable };
    defer fixture.connection.io = io;
    const requests = [_]runtime.RequestOptions{ .{ .path = "/one", .authority = "localhost" }, .{ .path = "/two", .authority = "localhost" } };
    var responses: [2]runtime.OwnedResponse = undefined;
    try std.testing.expectError(error.Timeout, fixture.connection.requestBatchIntoWithTimeout(&requests, &responses, .fromMilliseconds(30)));
    try std.testing.expectEqual(@as(u31, 1), fixture.connection.next_client_stream_id);
    try std.testing.expect(!fixture.connection.aggregate_timeout_unusable);
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.activeLocalStreamCount());
    try std.testing.expectEqual(@as(usize, 0), fixture.connection.hpack_encoder.dynamic_table.used);
    try fixture.connection.stream.shutdown(io, .send);
    try std.testing.expectError(error.ConnectionClosed, frame_io.readOwned(allocator, io, fixture.peer, 16_384));
}
