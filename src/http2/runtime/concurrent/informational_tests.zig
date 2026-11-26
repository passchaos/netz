const std = @import("std");
const runtime = @import("../../runtime.zig");
const allocator = std.testing.allocator;

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}

test "HTTP/2 concurrent informational responses compose with bodies and trailers" {
    try informational(false);
}

test "HTTP/2 concurrent inline expired commands preserve response state" {
    try informational(true);
}

fn informational(inline_bodyless: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    var shutdown: std.Io.Event = .unset;
    const Context = struct { io: std.Io, shutdown: *std.Io.Event, inline_bodyless: bool };
    var context = Context{ .io = io, .shutdown = &shutdown, .inline_bodyless = inline_bodyless };
    const Handler = struct {
        fn run(ctx: *Context, stream: *runtime.Connection.ConcurrentStream) !void {
            try std.testing.expectError(error.Timeout, stream.writeInformationalResponseWithDeadline(102, &.{}, .{ .raw = .zero, .clock = .awake }));
            try std.testing.expectError(error.Timeout, stream.writeInformationalResponseWithTimeout(102, &.{}, .zero));
            try std.testing.expectError(error.Timeout, stream.startResponseWithTimeout(.{ .status = 200 }, .zero));
            try std.testing.expectError(error.Timeout, stream.startResponseWithBodyWithTimeout(.{ .status = 200 }, "x", false, .zero));
            try std.testing.expectError(error.Timeout, stream.startResponseWithBodyWithDeadline(.{ .status = 200 }, "x", false, .{ .raw = .zero, .clock = .awake }));
            try std.testing.expectError(error.Timeout, stream.writeDataWithTimeout("x", false, .zero));
            const expired: std.Io.Clock.Timestamp = .{ .raw = .zero, .clock = .awake };
            try std.testing.expectError(error.Timeout, stream.startResponseWithDeadline(.{ .status = 200 }, expired));
            try std.testing.expectError(error.Timeout, stream.writeDataWithDeadline("x", false, expired));
            try std.testing.expectError(error.Timeout, stream.finishWithTrailersWithDeadline(&.{}, expired));
            try std.testing.expectError(error.Timeout, stream.resetWithDeadline(.cancel, expired));
            const foreign = std.Io.Clock.Timestamp.fromNow(ctx.io, .{ .clock = .real, .raw = .fromSeconds(5) });
            try std.testing.expectError(error.Timeout, stream.startResponseWithBodyWithDeadline(.{ .status = 200 }, "x", false, foreign));

            try stream.writeInformationalResponse(100, &.{});
            try stream.writeInformationalResponseWithDeadline(103, &.{.{ .name = "link", .value = "</style.css>" }}, deadline(ctx.io));
            try stream.startResponse(.{ .status = 200 });
            try std.testing.expectError(error.UnexpectedFrame, stream.writeInformationalResponse(103, &.{}));
            try stream.writeData("alpha", false);
            try stream.writeData("beta", false);
            try std.testing.expectError(
                error.Timeout,
                stream.resetWithTimeout(.cancel, .zero),
            );
            try std.testing.expectError(
                error.Timeout,
                stream.finishWithTrailersWithTimeout(&.{}, .zero),
            );
            try stream.finishWithTrailersWithTimeout(
                &.{.{ .name = "x-finished", .value = "done" }},
                .fromSeconds(1),
            );
        }
    };
    const Worker = struct {
        fn run(listener: *runtime.Server, ctx: *Context) !void {
            var connection = try listener.acceptWithDeadline(deadline(ctx.io));
            defer connection.close();
            const summary = try connection.serveConcurrentStreams(Context, ctx, Handler.run, .{ .max_streams = 2, .shutdown = ctx.shutdown, .inline_bodyless = ctx.inline_bodyless });
            try std.testing.expectEqual(@as(usize, 2), summary.completed);
            try std.testing.expectEqual(@as(usize, 0), summary.failed);
        }
    };
    var serving = try io.concurrent(Worker.run, .{ &server, &context });
    defer _ = serving.cancel(io) catch {};
    var client = try runtime.Client.connectWithTimeout(allocator, io, server.address(), .{}, .fromSeconds(5));
    defer client.close();
    const Observer = struct {
        statuses: [2]u16 = undefined,
        count: usize = 0,
        fn observe(context_ptr: *anyopaque, head: runtime.StreamingResponseHead) void {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            if (self.count < self.statuses.len) self.statuses[self.count] = head.status;
            self.count += 1;
        }
    };
    for (0..2) |_| {
        var observer = Observer{};
        var response = try client.requestWithInformationalAndDeadline(.{ .method = "GET", .path = "/stream" }, .{ .context = &observer, .on_response = Observer.observe }, deadline(io));
        defer response.deinit(allocator);
        try std.testing.expectEqualStrings("alphabeta", response.body);
        try std.testing.expectEqual(@as(usize, 2), observer.count);
        try std.testing.expectEqual(@as(u16, 100), observer.statuses[0]);
        try std.testing.expectEqual(@as(u16, 103), observer.statuses[1]);
        try std.testing.expectEqualStrings("done", response.trailers[0].value);
    }
    shutdown.set(io);
    try serving.await(io);
}
