const std = @import("std");
const runtime = @import("../runtime.zig");

test "HTTP/1 client and server exchange over a Unix socket" {
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
        "/http.sock",
        .{},
    );
    const full_path = path_storage[0 .. directory_len + suffix.len];
    const address = try std.Io.net.UnixAddress.init(full_path);
    var server = try runtime.UnixServer.listen(allocator, io, address, .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer {
        server.deinit();
        std.Io.Dir.deleteFileAbsolute(io, full_path) catch {};
    }

    const Shared = struct {
        server: *runtime.UnixServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            var request = connection.readRequest(.{}) catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit(connection.allocator);
            if (!std.mem.eql(u8, request.request.target, "/health") or
                !std.mem.eql(
                    u8,
                    request.request.header("host") orelse "",
                    "local.service",
                ))
            {
                self.err = error.UnexpectedRequest;
                return;
            }
            connection.writeResponse(.{
                .status = 200,
                .body = "unix-http-ok",
                .request_method = request.request.method,
            }) catch |err| {
                self.err = err;
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
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    var response = try client.request(.{
        .method = .GET,
        .target = "/health",
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings(
        "unix-http-ok",
        response.response.body,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
