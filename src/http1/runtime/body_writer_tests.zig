const std = @import("std");
const http1 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const net = std.Io.net;

const limits: runtime.Limits = .{
    .max_head_bytes = 4096,
    .max_body_bytes = 4096,
};

test "HTTP/1 fixed-length request writer streams and reuses connection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *runtime.Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var first = try connection.readRequest(.{});
            defer first.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/fixed", first.request.target);
            try std.testing.expectEqualStrings("hello world", first.request.body);
            try connection.writeResponse(.{ .body = "first" });

            var second = try connection.readRequest(.{});
            defer second.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("/second", second.request.target);
            try connection.writeResponse(.{
                .headers = &.{.{
                    .name = "Connection",
                    .value = "close",
                }},
                .body = "second",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();

    var writer = try client.startRequest(.{
        .method = .POST,
        .target = "/fixed",
        .host = "localhost",
        .body_length = 11,
    });
    defer writer.deinit();
    var stale_copy = writer;
    try std.testing.expectError(
        error.ConnectionBusy,
        client.request(.{
            .target = "/must-wait",
            .host = "localhost",
        }),
    );
    try writer.write("hello");
    try std.testing.expectError(
        error.InvalidContentLength,
        stale_copy.write("1234567"),
    );
    try writer.write(" ");
    try writer.write("world");
    try writer.finish();
    try std.testing.expectError(
        error.InvalidWriterState,
        stale_copy.write("late"),
    );
    // Request-body completion does not free the HTTP/1 exchange slot. The
    // matching response must be consumed before another request can start.
    try std.testing.expectError(
        error.ConnectionBusy,
        client.request(.{
            .target = "/still-waiting",
            .host = "localhost",
        }),
    );
    var first_response = try writer.readResponse();
    defer first_response.deinit(allocator);
    try std.testing.expectEqualStrings(
        "first",
        first_response.response.body,
    );

    var second_response = try client.request(.{
        .target = "/second",
        .host = "localhost",
    });
    defer second_response.deinit(allocator);
    try std.testing.expectEqualStrings(
        "second",
        second_response.response.body,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 chunked request writer streams announced trailers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *runtime.Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqual(
                http1.BodyFraming.chunked,
                request.request.body_framing,
            );
            try std.testing.expectEqualStrings(
                "streamed upload",
                request.request.body,
            );
            try std.testing.expectEqualStrings(
                "Digest, X-Complete",
                request.request.header("trailer").?,
            );
            try std.testing.expectEqual(@as(usize, 2), request.request.trailers.len);
            try std.testing.expectEqualStrings(
                "sha-256=first, sha-256=second",
                request.request.trailers[0].value,
            );
            try connection.writeResponse(.{
                .headers = &.{.{
                    .name = "Connection",
                    .value = "close",
                }},
                .body = "ok",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    var writer = try client.startRequest(.{
        .method = .POST,
        .target = "/chunked",
        .host = "localhost",
        .trailer_names = &.{ "Digest", "X-Complete", "digest" },
    });
    defer writer.deinit();
    try writer.write("");
    try writer.write("streamed ");
    try writer.write("upload");
    try writer.finishTrailers(&.{
        .{ .name = "Digest", .value = "sha-256=first" },
        .{ .name = "digest", .value = "sha-256=second" },
        .{ .name = "X-Complete", .value = "yes" },
    });
    var response = try writer.readResponse();
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("ok", response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 body writer batches borrowed chunk boundaries" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *runtime.Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings(
                "onetwothree",
                request.request.body,
            );
            try connection.writeResponse(.{
                .headers = &.{.{
                    .name = "Connection",
                    .value = "close",
                }},
                .body = "ok",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    var writer = try client.startRequest(.{
        .method = .POST,
        .target = "/batch",
        .host = "localhost",
    });
    defer writer.deinit();
    try writer.writeChunks(&.{ "one", "", "two", "three" });
    try writer.finish();
    var response = try writer.readResponse();
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("ok", response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 chunked response writer streams announced trailers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *runtime.Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);

            var writer = try connection.startResponse(.{
                .request_method = request.request.method,
                .trailer_names = &.{"Digest"},
            });
            defer writer.deinit();
            try writer.write("");
            try writer.write("streamed ");
            try writer.write("response");
            try writer.finishTrailers(&.{
                .{ .name = "Digest", .value = "sha-256=first" },
                .{ .name = "digest", .value = "sha-256=second" },
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    var response = try client.request(.{
        .target = "/streamed-response",
        .host = "localhost",
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(http1.BodyFraming.chunked, response.response.body_framing);
    try std.testing.expectEqualStrings("streamed response", response.response.body);
    try std.testing.expectEqualStrings(
        "sha-256=first, sha-256=second",
        response.response.trailers[0].value,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 body writer length errors are transactional" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const stream = try shared.listener.accept(shared.io);
            defer stream.close(shared.io);
            var request = try runtime.readRequestFromStream(
                shared.allocator,
                shared.io,
                stream,
                limits,
                .{},
            );
            defer request.deinit(shared.allocator);
            try std.testing.expectEqualStrings("12345", request.request.body);
            try runtime.writeResponseToStream(
                shared.allocator,
                shared.io,
                stream,
                .{
                    .headers = &.{.{
                        .name = "Connection",
                        .value = "close",
                    }},
                    .body = "ok",
                },
            );
        }
    };

    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .listener = &listener,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(
        allocator,
        io,
        listener.socket.address,
        limits,
    );
    defer client.close();
    var writer = try client.startRequest(.{
        .method = .POST,
        .target = "/length",
        .host = "localhost",
        .body_length = 5,
    });
    defer writer.deinit();
    try writer.write("123");
    try std.testing.expectError(
        error.InvalidContentLength,
        writer.write("456"),
    );
    try std.testing.expectError(
        error.InvalidContentLength,
        writer.finish(),
    );
    try writer.write("45");
    try writer.finish();
    var response = try writer.readResponse();
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("ok", response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 response writer suppresses forbidden bodies" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *runtime.Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var first = try connection.readRequest(.{});
            defer first.deinit(server_ptr.allocator);
            var no_content = try connection.startResponse(.{
                .status = 204,
                .reason = "No Content",
                .request_method = first.request.method,
            });
            defer no_content.deinit();
            try std.testing.expectError(
                error.InvalidWriterState,
                no_content.write("forbidden"),
            );

            var second = try connection.readRequest(.{});
            defer second.deinit(server_ptr.allocator);
            try connection.writeResponse(.{
                .headers = &.{.{
                    .name = "Connection",
                    .value = "close",
                }},
                .body = "after",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        limits,
    );
    defer client.close();
    var first_response = try client.request(.{
        .target = "/no-content",
        .host = "localhost",
    });
    defer first_response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), first_response.response.status);
    var second_response = try client.request(.{
        .target = "/after",
        .host = "localhost",
    });
    defer second_response.deinit(allocator);
    try std.testing.expectEqualStrings("after", second_response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 abandoned request writer makes connection unusable" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        io: std.Io,
        listener: *net.Server,

        fn run(shared: *@This()) void {
            const stream = shared.listener.accept(shared.io) catch return;
            defer stream.close(shared.io);
            var buffer: [256]u8 = undefined;
            var buffers = [_][]u8{&buffer};
            _ = shared.io.vtable.netRead(
                shared.io.userdata,
                stream.socket.handle,
                &buffers,
            ) catch return;
        }
    };

    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(
        allocator,
        io,
        listener.socket.address,
        limits,
    );
    var writer = try client.startRequest(.{
        .method = .POST,
        .target = "/abandoned",
        .host = "localhost",
        .body_length = 10,
    });
    try writer.write("partial");
    writer.deinit();
    try std.testing.expectError(
        error.ConnectionUnusable,
        client.request(.{
            .target = "/must-not-reuse",
            .host = "localhost",
        }),
    );
    client.close();
    thread.join();
}
