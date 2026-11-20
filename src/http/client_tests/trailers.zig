//! Exercise the unified H1 trailer overflow path over a persistent connection.
const std = @import("std");
const http = @import("../mod.zig");
const runtime = @import("../../http1/runtime.zig");
const allocator = std.testing.allocator;
const counts = [_]usize{ 16, 17, 40 };

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}

test "unified HTTP H1 reader and duplex trailers exceed stack capacity" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Worker = struct {
        fn run(listener: *runtime.Server) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(5));
            defer connection.close();
            for (counts) |count| {
                for (0..2) |_| {
                    var request = try connection.readRequestWithDeadline(.{}, deadline(listener.io));
                    defer request.deinit(allocator);
                    try std.testing.expectEqualStrings("upload", request.request.body);
                    try std.testing.expectEqual(count, request.request.trailers.len);
                    for (request.request.trailers, 0..) |trailer, index| {
                        var name: [32]u8 = undefined;
                        try std.testing.expectEqualStrings(try std.fmt.bufPrint(&name, "x-upload-{d}", .{index}), trailer.name);
                        try std.testing.expectEqualStrings("done", trailer.value);
                    }
                    try connection.writeResponse(.{ .status = 204, .request_method = request.request.method });
                }
            }
        }
    };
    var serving = try io.concurrent(Worker.run, .{&server});
    defer _ = serving.cancel(io) catch {};
    var client = try http.Client.init(allocator, io, .{});
    defer client.deinit();
    const uri = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/upload", .{server.address().getPort()});
    defer allocator.free(uri);
    var connection = try client.connectUri(uri);
    defer connection.close();
    var storage: [40][32]u8 = undefined;
    var trailers: [40]http.Header = undefined;
    for (&trailers, &storage, 0..) |*trailer, *name, index| {
        trailer.* = .{ .name = try std.fmt.bufPrint(name, "x-upload-{d}", .{index}), .value = "done" };
    }
    for (counts) |count| {
        var reader = std.Io.Reader.fixed("upload");
        var response = try connection.requestWithDeadline("/upload", .{
            .method = "POST",
            .body_source = .{ .reader = .{ .reader = &reader, .length = 6 } },
            .trailers = trailers[0..count],
        }, deadline(io));
        defer response.deinit();
        try std.testing.expectEqual(@as(u16, 204), response.status());
        var handle = try connection.startRequest("/upload", .{
            .method = "POST",
            .body_length = .unknown,
            .trailers = trailers[0..count],
        });
        defer handle.deinit();
        try handle.writeBody("upload");
        // The exact same public Header slice declares and finishes trailers.
        try handle.finishTrailers(trailers[0..count]);
        const Sink = struct {
            fn begin(_: *anyopaque, head: http.ResponseHead) !void {
                try std.testing.expectEqual(@as(u16, 204), head.status);
            }
            fn data(_: *anyopaque, bytes: []const u8) !void {
                try std.testing.expectEqual(@as(usize, 0), bytes.len);
            }
            fn end(_: *anyopaque, fields: []const http.Header) !void {
                try std.testing.expectEqual(@as(usize, 0), fields.len);
            }
        };
        var context: u8 = 0;
        _ = try handle.readResponse(.{ .context = &context, .begin = Sink.begin, .data = Sink.data, .end = Sink.end });
    }
    try serving.await(io);
}
