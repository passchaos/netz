const std = @import("std");
const runtime = @import("../runtime.zig");

test "HTTP/2 Unix listener accept deadline expires without a client" {
    if (comptime @import("builtin").os.tag == .windows) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_storage: [std.fs.max_path_bytes]u8 = undefined;
    const directory_len = try tmp.dir.realPath(io, &path_storage);
    const suffix = try std.fmt.bufPrint(
        path_storage[directory_len..],
        "/http2-accept-timeout.sock",
        .{},
    );
    const full_path = path_storage[0 .. directory_len + suffix.len];
    const address = try std.Io.net.UnixAddress.init(full_path);
    var server = try runtime.UnixServer.listen(
        allocator,
        io,
        address,
        .{},
    );
    defer {
        server.deinit();
        std.Io.Dir.deleteFileAbsolute(io, full_path) catch {};
    }

    try std.testing.expectError(
        error.Timeout,
        server.acceptWithTimeout(.fromMilliseconds(20)),
    );
}

test "HTTP/2 client and server exchange over a Unix socket" {
    if (comptime @import("builtin").os.tag == .windows) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_storage: [std.fs.max_path_bytes]u8 = undefined;
    const directory_len = try tmp.dir.realPath(io, &path_storage);
    const suffix = try std.fmt.bufPrint(
        path_storage[directory_len..],
        "/http2.sock",
        .{},
    );
    const full_path = path_storage[0 .. directory_len + suffix.len];
    const address = try std.Io.net.UnixAddress.init(full_path);
    const limits: runtime.Limits = .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    };
    var server = try runtime.UnixServer.listen(
        allocator,
        io,
        address,
        limits,
    );
    defer {
        server.deinit();
        std.Io.Dir.deleteFileAbsolute(io, full_path) catch {};
    }

    const Shared = struct {
        server: *runtime.UnixServer,
        err: ?anyerror = null,

        const Context = struct {
            fn handle(
                _: *@This(),
                request: runtime.OwnedRequest,
            ) runtime.Error!runtime.ResponseOptions {
                if (!std.mem.eql(u8, request.method, "POST") or
                    !std.mem.eql(u8, request.path, "/unix") or
                    !std.mem.eql(u8, request.authority.?, "local.service") or
                    !std.mem.eql(u8, request.body, "request"))
                {
                    return error.UnexpectedFrame;
                }
                if (request.from != null) return error.UnexpectedFrame;
                return .{ .status = 201, .body = "unix-http2" };
            }
        };

        fn run(self: *@This()) void {
            var handler_context: Context = .{};
            _ = self.server.serveConnection(
                Context,
                &handler_context,
                Context.handle,
                1,
            ) catch |err| {
                self.err = err;
                return;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connectUnix(
        allocator,
        io,
        address,
        "local.service",
        limits,
    );
    defer client.close();
    try std.testing.expect(client.peerAddress() == null);
    var response = try client.request(.{
        .method = "POST",
        .path = "/unix",
        .body = "request",
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 201), response.status);
    try std.testing.expectEqualStrings("unix-http2", response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 Unix server caller timeout bounds bootstrap" {
    if (comptime @import("builtin").os.tag == .windows) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_storage: [std.fs.max_path_bytes]u8 = undefined;
    const directory_len = try tmp.dir.realPath(io, &path_storage);
    const suffix = try std.fmt.bufPrint(
        path_storage[directory_len..],
        "/http2-timeout.sock",
        .{},
    );
    const full_path = path_storage[0 .. directory_len + suffix.len];
    const address = try std.Io.net.UnixAddress.init(full_path);
    var server = try runtime.UnixServer.listen(
        allocator,
        io,
        address,
        .{ .handshake_timeout = .fromSeconds(1) },
    );
    defer {
        server.deinit();
        std.Io.Dir.deleteFileAbsolute(io, full_path) catch {};
    }

    const Shared = struct {
        server: *runtime.UnixServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.acceptWithTimeout(
                .fromMilliseconds(30),
            ) catch |err| {
                self.err = err;
                return;
            };
            connection.close();
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const client = try address.connect(io);
    defer client.close(io);

    thread.join();
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}
