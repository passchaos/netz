//! Bearer and Basic Authorization headers with the unified client.
//!
//! Mirrors `curl -H 'Authorization: Bearer ...'`, `curl -u user:pass`, and the
//! common reqwest auth pattern: a local server rejects an unauthenticated
//! request with 401 plus `WWW-Authenticate`, then accepts a bearer token and
//! Basic credentials on the same origin.

const std = @import("std");
const netz = @import("netz");

const bearer_token = "netz-demo-token";
const basic_user = "alice";
const basic_password = "s3cret";

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

    var basic_storage: [128]u8 = undefined;
    const basic_credentials = try std.fmt.bufPrint(
        &basic_storage,
        "{s}:{s}",
        .{ basic_user, basic_password },
    );
    var encoded_storage: [256]u8 = undefined;
    const encoded_basic = std.base64.standard.Encoder.encode(
        &encoded_storage,
        basic_credentials,
    );

    const ServerTask = struct {
        server: *netz.http1.runtime.Server,
        encoded_basic: []const u8,
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

                const authorization = request.request.header("authorization");
                if (authorization == null) {
                    try connection.writeResponse(.{
                        .status = 401,
                        .reason = "Unauthorized",
                        .headers = &.{.{
                            .name = "www-authenticate",
                            .value = "Basic realm=\"netz-example\"",
                        }},
                        .body = "missing authorization\n",
                        .request_method = request.request.method,
                    });
                    continue;
                }
                const value = authorization.?;
                if (std.mem.startsWith(u8, value, "Bearer ")) {
                    const token = value["Bearer ".len..];
                    if (std.mem.eql(u8, token, bearer_token)) {
                        try connection.writeResponse(.{
                            .body = "bearer accepted\n",
                            .request_method = request.request.method,
                        });
                    } else {
                        try connection.writeResponse(.{
                            .status = 403,
                            .reason = "Forbidden",
                            .body = "invalid bearer token\n",
                            .request_method = request.request.method,
                        });
                    }
                } else if (std.mem.startsWith(u8, value, "Basic ")) {
                    const credentials = value["Basic ".len..];
                    if (std.mem.eql(u8, credentials, self.encoded_basic)) {
                        var body_storage: [128]u8 = undefined;
                        const body = try std.fmt.bufPrint(
                            &body_storage,
                            "basic accepted for {s}\n",
                            .{basic_user},
                        );
                        try connection.writeResponse(.{
                            .body = body,
                            .request_method = request.request.method,
                        });
                    } else {
                        try connection.writeResponse(.{
                            .status = 403,
                            .reason = "Forbidden",
                            .body = "invalid basic credentials\n",
                            .request_method = request.request.method,
                        });
                    }
                } else {
                    try connection.writeResponse(.{
                        .status = 400,
                        .reason = "Bad Request",
                        .body = "unsupported authorization scheme\n",
                        .request_method = request.request.method,
                    });
                }
            }
        }
    };

    var task = ServerTask{
        .server = &server,
        .encoded_basic = encoded_basic,
    };
    var server_task = io.async(ServerTask.run, .{&task});
    defer server_task.cancel(io);

    const account_uri = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}/account",
        .{server.address().ip4.port},
    );
    defer allocator.free(account_uri);

    var client = try netz.http.Client.init(allocator, io, .{
        .protocol_policy = .http1_only,
    });
    defer client.deinit();

    var anonymous = try client.requestUriWithTimeout(
        account_uri,
        .{ .method = "GET" },
        .fromSeconds(5),
    );
    defer anonymous.deinit();
    std.debug.print("GET anonymous {d}: {s}", .{
        anonymous.status(),
        anonymous.body(),
    });
    std.debug.print(
        "  challenge={?s}\n",
        .{anonymous.header("www-authenticate")},
    );

    const bearer_header = try std.fmt.allocPrint(
        allocator,
        "Bearer {s}",
        .{bearer_token},
    );
    defer allocator.free(bearer_header);
    var bearer = try client.requestUriWithTimeout(
        account_uri,
        .{
            .method = "GET",
            .headers = &.{.{ .name = "authorization", .value = bearer_header }},
        },
        .fromSeconds(5),
    );
    defer bearer.deinit();
    std.debug.print("GET bearer {d}: {s}", .{
        bearer.status(),
        bearer.body(),
    });

    const basic_header = try std.fmt.allocPrint(
        allocator,
        "Basic {s}",
        .{encoded_basic},
    );
    defer allocator.free(basic_header);
    var basic = try client.requestUriWithTimeout(
        account_uri,
        .{
            .method = "GET",
            .headers = &.{.{ .name = "authorization", .value = basic_header }},
        },
        .fromSeconds(5),
    );
    defer basic.deinit();
    std.debug.print("GET basic {d}: {s}", .{
        basic.status(),
        basic.body(),
    });

    server_task.await(io);
    if (task.err) |err| return err;
}
