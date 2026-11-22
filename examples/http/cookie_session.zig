//! Cookie persistence across requests with `netz.http.CookieSession`.
//!
//! Mirrors the `reqwest` cookie-store example and `curl -c/-b`: the server
//! sets one session cookie, and the next pooled request automatically carries
//! it without an explicit `Cookie` header.

const std = @import("std");
const netz = @import("netz");

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var server = try netz.http1.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const ServerTask = struct {
        server: *netz.http1.runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            // The pool reuses this connection for both requests.
            var connection = try self.server.accept();
            defer connection.close();
            for (0..2) |_| {
                var request = try connection.readRequest(.{});
                defer request.deinit(self.server.allocator);
                if (std.mem.eql(u8, request.request.target, "/login")) {
                    try connection.writeResponse(.{
                        .headers = &.{
                            .{
                                .name = "set-cookie",
                                .value = "session=abc123; Path=/; HttpOnly",
                            },
                            .{ .name = "content-type", .value = "text/plain" },
                        },
                        .body = "logged in",
                        .request_method = request.request.method,
                    });
                    continue;
                }
                const cookie = request.request.header("cookie") orelse "(none)";
                var storage: [256]u8 = undefined;
                const body = try std.fmt.bufPrint(
                    &storage,
                    "server saw cookie: {s}",
                    .{cookie},
                );
                try connection.writeResponse(.{
                    .headers = &.{.{
                        .name = "content-type",
                        .value = "text/plain",
                    }},
                    .body = body,
                    .request_method = request.request.method,
                });
            }
        }
    };

    var task = ServerTask{ .server = &server };
    var server_task = io.async(ServerTask.run, .{&task});
    defer server_task.cancel(io);

    const login_uri = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}/login",
        .{server.address().ip4.port},
    );
    defer allocator.free(login_uri);
    const me_uri = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}/me",
        .{server.address().ip4.port},
    );
    defer allocator.free(me_uri);

    var session = try netz.http.CookieSession.init(allocator, io, .{
        .client = .{ .protocol_policy = .http1_only },
    }, .{});
    defer session.deinit();

    var login = try session.requestUriWithTimeout(
        login_uri,
        .{ .method = "GET" },
        .{},
        .fromSeconds(5),
    );
    defer login.deinit();
    std.debug.print("login {d}: {s}\n", .{
        login.status(),
        login.body(),
    });

    var me = try session.requestUriWithTimeout(
        me_uri,
        .{ .method = "GET" },
        .{},
        .fromSeconds(5),
    );
    defer me.deinit();
    std.debug.print("me {d}: {s}\n", .{
        me.status(),
        me.body(),
    });

    server_task.await(io);
    if (task.err) |err| return err;
}
