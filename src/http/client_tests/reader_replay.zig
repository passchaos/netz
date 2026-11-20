//! Replaying a body requires reproducing every byte, not only an idempotent
//! method. Single-pass Readers must retain the first attempt's error.
const std = @import("std");
const http = @import("../mod.zig");
const runtime = @import("../../http1/runtime.zig");
const allocator = std.testing.allocator;
const payload = "replay-body";

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}

const Reset = struct {
    calls: usize = 0,
    fail: bool = false,

    fn rewind(context: ?*anyopaque, reader: *std.Io.Reader) std.Io.Reader.Error!void {
        const self: *Reset = @ptrCast(@alignCast(context.?));
        self.calls += 1;
        if (self.fail) return error.ReadFailed;
        reader.* = .fixed(payload);
    }
};

fn exercise(comptime mode: enum { single_pass, replayable, failed_reset, source_failure, slice }) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Worker = struct {
        fn run(listener: *runtime.Server) !void {
            {
                var connection = try listener.acceptWithTimeout(.fromSeconds(5));
                defer connection.close();
                var warm = try connection.readRequestWithDeadline(.{}, deadline(listener.io));
                defer warm.deinit(allocator);
                try connection.writeResponse(.{ .status = 204, .request_method = warm.request.method });
                if (mode == .source_failure) {
                    try std.testing.expectError(error.ConnectionClosed, connection.readRequestWithDeadline(.{}, deadline(listener.io)));
                } else {
                    var upload = try connection.readRequestWithDeadline(.{}, deadline(listener.io));
                    defer upload.deinit(allocator);
                    try std.testing.expectEqualStrings(payload, upload.request.body);
                }
                // The upload consumed the Reader, but its final response is
                // lost. A stale pooled retry must reconstruct the full body.
            }
            if (mode == .single_pass or mode == .failed_reset or mode == .source_failure) {
                try std.testing.expectError(error.Timeout, listener.acceptWithTimeout(.fromMilliseconds(100)));
                return;
            }
            var connection = try listener.acceptWithTimeout(.fromSeconds(5));
            defer connection.close();
            var upload = try connection.readRequestWithDeadline(.{}, deadline(listener.io));
            defer upload.deinit(allocator);
            try std.testing.expectEqualStrings(payload, upload.request.body);
            try connection.writeResponse(.{ .body = "replayed", .request_method = upload.request.method });
        }
    };
    var serving = try io.concurrent(Worker.run, .{&server});
    defer _ = serving.cancel(io) catch {};
    var pool = try http.Pool.init(allocator, io, .{});
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/upload", .{server.address().getPort()});
    defer allocator.free(uri);
    var warm = try pool.requestUriWithDeadline(uri, .{}, deadline(io));
    defer warm.deinit();
    var reader = if (mode == .source_failure) std.Io.Reader.failing else std.Io.Reader.fixed(payload);
    var reset = Reset{ .fail = mode == .failed_reset };
    const request: http.RequestOptions = .{
        .method = "PUT",
        .body = "wrong-fallback",
        .body_source = if (mode == .slice) .{ .slice = payload } else .{ .reader = .{
            .reader = &reader,
            .length = payload.len,
            .replay = if (mode == .single_pass) null else .{ .context = &reset, .rewind = Reset.rewind },
        } },
    };
    const result = pool.requestUriWithDeadline(uri, request, deadline(io));
    if (mode == .single_pass) {
        try std.testing.expectError(error.ConnectionClosed, result);
        try std.testing.expectEqual(@as(usize, 0), reset.calls);
    } else if (mode == .source_failure) {
        try std.testing.expectError(error.RequestBodyReadFailed, result);
        try std.testing.expectEqual(@as(usize, 0), reset.calls);
    } else if (mode == .failed_reset) {
        try std.testing.expectError(error.ReadFailed, result);
        try std.testing.expectEqual(@as(usize, 1), reset.calls);
    } else {
        var response = try result;
        defer response.deinit();
        try std.testing.expectEqualStrings("replayed", response.body());
        try std.testing.expectEqual(@as(usize, if (mode == .slice) 0 else 1), reset.calls);
    }
    try serving.await(io);
}

test "unified HTTP consumed single-pass Reader is not retried" {
    try exercise(.single_pass);
}

test "unified HTTP replayable Reader rewinds before a stale retry" {
    try exercise(.replayable);
}

test "unified HTTP failed Reader rewind preserves its error without redial" {
    try exercise(.failed_reset);
}

test "unified HTTP Reader failure never triggers a stale retry" {
    try exercise(.source_failure);
}

test "unified HTTP body source slice still replays every byte" {
    try exercise(.slice);
}

test "unified HTTP replayable Reader supports preserving redirects" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Worker = struct {
        fn run(listener: *runtime.Server) !void {
            for (0..2) |index| {
                var connection = try listener.acceptWithTimeout(.fromSeconds(5));
                defer connection.close();
                var request = try connection.readRequestWithDeadline(.{}, deadline(listener.io));
                defer request.deinit(allocator);
                try std.testing.expectEqualStrings(payload, request.request.body);
                try std.testing.expectEqualStrings(if (index == 0) "/first" else "/second", request.request.target);
                try connection.writeResponse(.{
                    .status = if (index == 0) 307 else 200,
                    .headers = if (index == 0) &.{.{ .name = "Location", .value = "/second" }} else &.{},
                    .body = if (index == 0) "" else "redirected",
                    .request_method = request.request.method,
                });
            }
        }
    };
    var serving = try io.concurrent(Worker.run, .{&server});
    defer _ = serving.cancel(io) catch {};
    var client = try http.Client.init(allocator, io, .{});
    defer client.deinit();
    const uri = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/first", .{server.address().getPort()});
    defer allocator.free(uri);
    var reader = std.Io.Reader.fixed(payload);
    var reset = Reset{};
    var response = try client.requestUriFollowingRedirectsWithDeadline(uri, .{
        .method = "PUT",
        .body_source = .{ .reader = .{ .reader = &reader, .length = payload.len, .replay = .{ .context = &reset, .rewind = Reset.rewind } } },
    }, .{}, deadline(io));
    defer response.deinit();
    try std.testing.expectEqualStrings("redirected", response.body());
    try std.testing.expectEqual(@as(usize, 1), reset.calls);
    try serving.await(io);
}
