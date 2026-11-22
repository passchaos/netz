//! Use the unified HTTP client and pool against a local HTTP/1.1 server.
//!
//! `netz.http.Client` selects HTTP/1.1, HTTP/2, or HTTP/3 from one protocol
//! policy and owns a one-shot connection per request. `netz.http.Pool` keeps
//! negotiated connections for reuse. This example stays on cleartext HTTP/1
//! so it runs without external services; `prefer_http3`/`http3_only` use the
//! same request API for HTTPS origins (see `run-http3-fetch`).

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
            // The one-shot client opens one connection and closes it after
            // the response.
            var one_shot = try self.server.accept();
            try self.serve(&one_shot);
            one_shot.close();

            // The pool keeps its first connection and reuses it for the
            // second request, so one accept serves both.
            var pooled = try self.server.accept();
            try self.serve(&pooled);
            try self.serve(&pooled);
            pooled.close();
        }

        fn serve(self: *@This(), connection: anytype) !void {
            var request = try connection.readRequest(.{});
            defer request.deinit(self.server.allocator);
            try connection.writeResponse(.{
                .headers = &.{.{
                    .name = "content-type",
                    .value = "text/plain",
                }},
                .body = "hello from the unified HTTP client",
                .request_method = request.request.method,
            });
        }
    };

    var task = ServerTask{ .server = &server };
    var server_task = io.async(ServerTask.run, .{&task});
    defer server_task.cancel(io);

    const uri = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}/hello",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);

    // One-shot request with one relative deadline covering connect, request,
    // and response. `.http1_only` is explicit because the local server is
    // cleartext; the default `.prefer_http2` would still negotiate H1 here.
    var client = try netz.http.Client.init(allocator, io, .{
        .protocol_policy = .http1_only,
    });
    defer client.deinit();
    var response = try client.requestUriWithTimeout(uri, .{
        .method = "GET",
        .headers = &.{.{ .name = "accept", .value = "text/plain" }},
    }, .fromSeconds(5));
    defer response.deinit();
    std.debug.print("one-shot {t} {d}: {s}\n", .{
        response.protocol(),
        response.status(),
        response.body(),
    });

    // The pool applies the same protocol policy and reuses the negotiated
    // connection. Its own limits bound idle and total sockets.
    var pool = try netz.http.Pool.init(allocator, io, .{
        .client = .{ .protocol_policy = .http1_only },
        .max_connections = 4,
        .max_idle_connections = 2,
        .max_idle_per_origin = 2,
    });
    defer pool.deinit();
    for (0..2) |index| {
        var pooled = try pool.requestUri(uri, .{ .method = "GET" });
        defer pooled.deinit();
        std.debug.print("pooled {d} {t} {d}: {s}\n", .{
            index,
            pooled.protocol(),
            pooled.status(),
            pooled.body(),
        });
    }

    server_task.await(io);
    if (task.err) |err| return err;
}
