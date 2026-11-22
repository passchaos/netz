//! Follow HTTP redirects with the unified client.
//!
//! Mirrors `curl -L` / the `reqwest` redirect example: the server answers
//! `/old` with a relative 302, and the client resolves it, follows the chain
//! under one deadline, and reports the final URI and hop count.

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
            // Each redirect hop uses a fresh one-shot connection.
            for (0..2) |_| {
                var connection = try self.server.accept();
                defer connection.close();
                var request = try connection.readRequest(.{});
                defer request.deinit(self.server.allocator);
                if (std.mem.eql(u8, request.request.target, "/old")) {
                    try connection.writeResponse(.{
                        .status = 302,
                        .headers = &.{.{
                            .name = "location",
                            .value = "/new",
                        }},
                        .body = "",
                        .request_method = request.request.method,
                    });
                    continue;
                }
                try connection.writeResponse(.{
                    .headers = &.{.{
                        .name = "content-type",
                        .value = "text/plain",
                    }},
                    .body = "arrived after redirect",
                    .request_method = request.request.method,
                });
            }
        }
    };

    var task = ServerTask{ .server = &server };
    var server_task = io.async(ServerTask.run, .{&task});
    defer server_task.cancel(io);

    const uri = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}/old",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);

    var client = try netz.http.Client.init(allocator, io, .{
        .protocol_policy = .http1_only,
    });
    defer client.deinit();
    var redirected = try client.requestUriFollowingRedirectsDetailed(
        uri,
        .{ .method = "GET" },
        .{},
    );
    defer redirected.deinit();
    std.debug.print("redirects={d} final={s} status={d}: {s}\n", .{
        redirected.redirect_count,
        redirected.final_uri,
        redirected.response.status(),
        redirected.response.body(),
    });

    server_task.await(io);
    if (task.err) |err| return err;
}
