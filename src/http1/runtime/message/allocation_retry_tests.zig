//! Buffered HTTP requests retain every wire byte across local allocation failure.
const std = @import("std");
const runtime = @import("../../runtime.zig");
const allocator = std.testing.allocator;
const http1 = @import("../../mod.zig");
const Shape = enum { empty, fixed, chunked, folded };
const Api = enum { connection, direct, direct_plain };
const next_request = "GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n";

fn requestBytes(shape: Shape) []const u8 {
    return switch (shape) {
        .empty => "GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n",
        .fixed => "POST /first HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nbody",
        .chunked => "POST /first HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nTrailer: X-Final\r\n\r\n2;part=one\r\nbo\r\n2\r\ndy\r\n0\r\nX-Final: done\r\n\r\n",
        .folded => "POST /first HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4,\r\n 4\r\nX-Trace: first\r\n second\r\n\r\nbody",
    };
}

test "HTTP1 buffered request allocation failure preserves input for exact retry" {
    for (std.enums.values(Shape)) |shape| {
        for (std.enums.values(Api)) |api| {
            for ([_]bool{ false, true }) |buffered| {
                var succeeded = false;
                for (0..32) |fail_index| {
                    if (try exercise(shape, api, buffered, fail_index)) {
                        succeeded = true;
                        break;
                    }
                }
                try std.testing.expect(succeeded);
            }
        }
    }
}

fn read(connection: *runtime.Connection, api: Api, options: http1.ParseOptions) !runtime.OwnedRequest {
    return switch (api) {
        .connection => connection.readRequestWithTimeout(options, .fromSeconds(1)),
        .direct => runtime.readRequestFromStreamBufferedWithTimeout(connection.allocator, connection.io, connection.stream, .{}, options, &connection.inbuf, .fromSeconds(1)),
        .direct_plain => runtime.readRequestFromStreamBuffered(connection.allocator, connection.io, connection.stream, .{}, options, &connection.inbuf),
    };
}

fn exercise(shape: Shape, api: Api, buffered: bool, fail_index: usize) !bool {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const peer = try server.address().connect(io, .{ .mode = .stream });
    defer peer.close(io);
    var connection = try server.accept();
    defer connection.close();
    var writer = peer.writer(io, &.{});
    if (buffered) try connection.inbuf.appendSlice(allocator, requestBytes(shape)) else try writer.interface.writeAll(requestBytes(shape));
    try writer.interface.writeAll(next_request);
    const options: http1.ParseOptions = .{ .allow_obs_fold = shape == .folded };
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index, .resize_fail_index = 0 });
    const result = blk: {
        connection.allocator = failing.allocator();
        defer connection.allocator = allocator;
        break :blk read(&connection, api, options);
    };
    if (failing.has_induced_failure) {
        try std.testing.expectError(error.OutOfMemory, result);
        var repeated = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0, .resize_fail_index = 0 });
        {
            connection.allocator = repeated.allocator();
            defer connection.allocator = allocator;
            try std.testing.expectError(error.OutOfMemory, read(&connection, api, options));
        }
        var request = try read(&connection, api, options);
        defer request.deinit(allocator);
        try std.testing.expectEqualStrings("/first", request.request.target);
        try std.testing.expectEqualStrings(if (shape == .empty) "" else "body", request.request.body);
        if (shape == .chunked) try std.testing.expectEqualStrings("done", request.request.trailers[0].value);
        if (shape == .folded) try std.testing.expectEqualStrings("first second", request.request.header("x-trace").?);
    } else {
        var request = try result;
        request.deinit(allocator);
    }
    var next = try read(&connection, api, .{});
    defer next.deinit(allocator);
    try std.testing.expectEqualStrings("/second", next.request.target);
    return !failing.has_induced_failure;
}

test "HTTP1 buffered response decode OOM restores the message ahead of its pipeline suffix" {
    for ([_]bool{ false, true }) |bounded| {
        var succeeded = false;
        for (0..24) |fail_index| {
            var threaded = std.Io.Threaded.init(allocator, .{});
            defer threaded.deinit();
            const io = threaded.io();
            var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
            defer listener.deinit(io);
            const socket = try listener.socket.address.connect(io, .{ .mode = .stream });
            defer socket.close(io);
            const peer = try listener.accept(io);
            defer peer.close(io);
            var writer = peer.writer(io, &.{});
            try writer.interface.writeAll("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Final\r\n\r\n4\r\nbody\r\n0\r\nX-Final: done\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nnext");
            var input: std.ArrayList(u8) = .empty;
            defer input.deinit(allocator);
            var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index, .resize_fail_index = 0 });
            const result = if (bounded)
                runtime.readResponseFromStreamBufferedForRequestWithTimeout(failing.allocator(), io, socket, .{}, .{}, &input, .GET, .fromSeconds(1))
            else
                runtime.readResponseFromStreamBufferedObserved(failing.allocator(), io, socket, .{}, .{}, &input, null);
            if (failing.has_induced_failure) {
                try std.testing.expectError(error.OutOfMemory, result);
                var response = try runtime.readResponseFromStreamBufferedForRequestWithTimeout(allocator, io, socket, .{}, .{}, &input, .GET, .fromSeconds(1));
                defer response.deinit(allocator);
                try std.testing.expectEqualStrings("body", response.response.body);
                try std.testing.expectEqualStrings("done", response.response.trailers[0].value);
            } else {
                var response = try result;
                response.deinit(allocator);
                succeeded = true;
            }
            var next = try runtime.readResponseFromStreamBufferedForRequestWithTimeout(allocator, io, socket, .{}, .{}, &input, .GET, .fromSeconds(1));
            defer next.deinit(allocator);
            try std.testing.expectEqualStrings("next", next.response.body);
            if (succeeded) break;
        }
        try std.testing.expect(succeeded);
    }
}
