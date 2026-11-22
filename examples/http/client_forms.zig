//! Query strings, URL-encoded forms, and HEAD requests with the unified client.
//!
//! Mirrors the common `reqwest` form example and `curl -d` / `curl -I`:
//! build a query with `netz.http.form`, POST one `application/x-www-form-
//! urlencoded` body, and inspect headers with a HEAD request.

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
            // The one-shot unified client opens one connection per request.
            for (0..3) |_| {
                var connection = try self.server.accept();
                defer connection.close();
                var request = try connection.readRequest(.{});
                defer request.deinit(self.server.allocator);

                if (std.mem.eql(u8, request.request.target, "/submit")) {
                    try self.serveSubmit(&connection, request.request);
                } else {
                    try self.serveSearch(&connection, request.request);
                }
            }
        }

        fn serveSearch(
            self: *@This(),
            connection: *netz.http1.runtime.Connection,
            request: netz.http1.Request,
        ) !void {
            const query = if (std.mem.indexOfScalar(
                u8,
                request.target,
                '?',
            )) |index| request.target[index + 1 ..] else "";
            var decoded = try netz.http.form.decodeAlloc(
                self.server.allocator,
                query,
                .{},
            );
            defer decoded.deinit();
            const first = if (decoded.pairs.len == 0)
                "(none)"
            else
                decoded.pairs[0].name;
            const first_value = if (decoded.pairs.len == 0)
                ""
            else
                decoded.pairs[0].value;
            var storage: [256]u8 = undefined;
            const body = try std.fmt.bufPrint(
                &storage,
                "search pairs={d} first={s}={s}",
                .{ decoded.pairs.len, first, first_value },
            );
            try connection.writeResponse(.{
                .headers = &.{.{
                    .name = "content-type",
                    .value = "text/plain",
                }},
                .body = body,
                .request_method = request.method,
            });
        }

        fn serveSubmit(
            self: *@This(),
            connection: *netz.http1.runtime.Connection,
            request: netz.http1.Request,
        ) !void {
            var decoded = try netz.http.form.decodeAlloc(
                self.server.allocator,
                request.body,
                .{},
            );
            defer decoded.deinit();
            var name: []const u8 = "(missing)";
            for (decoded.pairs) |pair| {
                if (std.mem.eql(u8, pair.name, "name")) name = pair.value;
            }
            var storage: [256]u8 = undefined;
            const body = try std.fmt.bufPrint(
                &storage,
                "submitted name={s} fields={d}",
                .{ name, decoded.pairs.len },
            );
            try connection.writeResponse(.{
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

    // Build the query string with the same bounded encoder used by servers.
    const query = try netz.http.form.encodeAlloc(allocator, &.{
        .{ .name = "q", .value = "netz http" },
        .{ .name = "limit", .value = "10" },
    });
    defer allocator.free(query);
    const search_uri = try std.fmt.allocPrint(
        allocator,
        "{s}/search?{s}",
        .{ base_uri, query },
    );
    defer allocator.free(search_uri);
    const submit_uri = try std.fmt.allocPrint(
        allocator,
        "{s}/submit",
        .{base_uri},
    );
    defer allocator.free(submit_uri);

    var client = try netz.http.Client.init(allocator, io, .{
        .protocol_policy = .http1_only,
    });
    defer client.deinit();

    var search = try client.requestUriWithTimeout(
        search_uri,
        .{ .method = "GET" },
        .fromSeconds(5),
    );
    defer search.deinit();
    std.debug.print("GET {d}: {s}\n", .{
        search.status(),
        search.body(),
    });

    const form_body = try netz.http.form.encodeAlloc(allocator, &.{
        .{ .name = "name", .value = "netz user" },
        .{ .name = "note", .value = "hello world" },
    });
    defer allocator.free(form_body);
    var submitted = try client.requestUriWithTimeout(
        submit_uri,
        .{
            .method = "POST",
            .headers = &.{.{
                .name = "content-type",
                .value = "application/x-www-form-urlencoded",
            }},
            .body = form_body,
        },
        .fromSeconds(5),
    );
    defer submitted.deinit();
    std.debug.print("POST {d}: {s}\n", .{
        submitted.status(),
        submitted.body(),
    });

    // HEAD returns the same status and headers with an empty body.
    var head = try client.requestUriWithTimeout(
        search_uri,
        .{ .method = "HEAD" },
        .fromSeconds(5),
    );
    defer head.deinit();
    std.debug.print("HEAD {d}: body={d} content-length={?s}\n", .{
        head.status(),
        head.body().len,
        head.header("content-length"),
    });

    server_task.await(io);
    if (task.err) |err| return err;
}
