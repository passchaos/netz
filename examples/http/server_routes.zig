//! A small routed HTTP/1.1 server with a graceful shutdown route.
//!
//! Mirrors hyper's routing/service examples: one persistent connection serves
//! several routes, an unknown path returns 404, and `/quit` finishes the last
//! response before the server closes the connection.

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
            var connection = try self.server.accept();
            defer connection.close();
            while (true) {
                var request = connection.readRequest(.{}) catch |err| switch (err) {
                    error.ConnectionClosed => return,
                    else => return err,
                };
                defer request.deinit(self.server.allocator);
                const target = request.request.target;
                const path = if (std.mem.indexOfScalar(u8, target, '?')) |index|
                    target[0..index]
                else
                    target;

                if (std.mem.eql(u8, path, "/quit")) {
                    try self.respond(&connection, request.request, 200, "bye");
                    return;
                }
                if (std.mem.eql(u8, path, "/")) {
                    try self.respond(&connection, request.request, 200, "home");
                } else if (std.mem.eql(u8, path, "/health")) {
                    try self.respond(&connection, request.request, 200, "ok");
                } else if (std.mem.eql(u8, path, "/hello")) {
                    const query = if (std.mem.indexOfScalar(
                        u8,
                        target,
                        '?',
                    )) |index| target[index + 1 ..] else "";
                    var decoded = try netz.http.form.decodeAlloc(
                        self.server.allocator,
                        query,
                        .{},
                    );
                    defer decoded.deinit();
                    var name: []const u8 = "world";
                    for (decoded.pairs) |pair| {
                        if (std.mem.eql(u8, pair.name, "name")) name = pair.value;
                    }
                    var storage: [128]u8 = undefined;
                    const body = try std.fmt.bufPrint(
                        &storage,
                        "hello {s}",
                        .{name},
                    );
                    try self.respond(&connection, request.request, 200, body);
                } else if (std.mem.eql(u8, path, "/whoami")) {
                    var storage: [64]u8 = undefined;
                    const body = if (request.request.from) |from|
                        try std.fmt.bufPrint(
                            &storage,
                            "peer-port={d}",
                            .{from.getPort()},
                        )
                    else
                        "peer=unknown";
                    try self.respond(&connection, request.request, 200, body);
                } else if (std.mem.eql(u8, path, "/echo")) {
                    try self.respond(
                        &connection,
                        request.request,
                        200,
                        request.request.body,
                    );
                } else {
                    try self.respond(
                        &connection,
                        request.request,
                        404,
                        "not found",
                    );
                }
            }
        }

        fn respond(
            self: *@This(),
            connection: *netz.http1.runtime.Connection,
            request: netz.http1.Request,
            status: u16,
            body: []const u8,
        ) !void {
            _ = self;
            try connection.writeResponse(.{
                .status = status,
                .headers = &.{.{
                    .name = "content-type",
                    .value = "text/plain",
                }},
                .body = body,
                .request_method = request.method,
            });
        }
    };

    var task = ServerTask{ .server = &server };
    var server_task = io.async(ServerTask.run, .{&task});
    defer server_task.cancel(io);

    const base_uri = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}",
        .{server.address().ip4.port},
    );
    defer allocator.free(base_uri);

    // One pooled connection drives every route; `/quit` ends the server loop.
    var pool = try netz.http.Pool.init(allocator, io, .{
        .client = .{ .protocol_policy = .http1_only },
        .max_connections = 2,
        .max_idle_connections = 1,
        .max_idle_per_origin = 1,
    });
    defer pool.deinit();

    const requests = [_]struct {
        target: []const u8,
        method: []const u8,
        body: []const u8 = "",
    }{
        .{ .target = "/", .method = "GET" },
        .{ .target = "/health", .method = "GET" },
        .{ .target = "/hello?name=netz", .method = "GET" },
        .{ .target = "/echo", .method = "POST", .body = "echo body" },
        .{ .target = "/whoami", .method = "GET" },
        .{ .target = "/missing", .method = "GET" },
        .{ .target = "/quit", .method = "GET" },
    };
    for (requests) |item| {
        const uri = try std.fmt.allocPrint(
            allocator,
            "{s}{s}",
            .{ base_uri, item.target },
        );
        defer allocator.free(uri);
        var response = try pool.requestUriWithTimeout(
            uri,
            .{ .method = item.method, .body = item.body },
            .fromSeconds(5),
        );
        defer response.deinit();
        std.debug.print("{s} {s} -> {d}: {s}\n", .{
            item.method,
            item.target,
            response.status(),
            response.body(),
        });
    }

    server_task.await(io);
    if (task.err) |err| return err;
}
