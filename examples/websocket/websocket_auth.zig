//! WebSocket opening-handshake authentication.
//!
//! Mirrors a tungstenite/reqwest server that rejects an unauthenticated
//! Upgrade with 401 plus `WWW-Authenticate`, then accepts a client that sends
//! `Authorization` through `ConnectOptions.extra_headers`. The server inspects
//! the pending request before any 101 is written.

const std = @import("std");
const netz = @import("netz");

const bearer_token = "netz-ws-token";

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var server = try netz.websocket.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_frame_bytes = 4096, .max_message_bytes = 4096 },
    );
    defer server.deinit();

    const ServerTask = struct {
        server: *netz.websocket.runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            // First attempt: no Authorization field.
            {
                var pending = try self.server.receiveUpgradeRequest(.{});
                var pending_owned = true;
                defer if (pending_owned) pending.deinit();
                try pending.reject(
                    401,
                    "Unauthorized",
                    &.{.{
                        .name = "www-authenticate",
                        .value = "Bearer realm=\"netz-example\"",
                    }},
                    "missing bearer token\n",
                );
                pending_owned = false;
                std.debug.print("server rejected unauthenticated Upgrade\n", .{});
            }

            // Second attempt: validate the bearer token before accepting.
            var pending = try self.server.receiveUpgradeRequest(.{});
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            const authorization = pending.header("authorization") orelse
                return error.InvalidAuthorization;
            const expected = "Bearer " ++ bearer_token;
            if (!std.mem.eql(u8, authorization, expected)) {
                try pending.reject(403, "Forbidden", &.{}, "invalid bearer token\n");
                pending_owned = false;
                return error.InvalidAuthorization;
            }
            var connection = try pending.accept();
            pending_owned = false;
            defer connection.close();

            var message = try connection.receiveMessage();
            defer message.deinit(self.server.http.allocator);
            try connection.sendTextSlices(&.{ "authenticated ", message.payload });
            var close = try connection.receiveFrame();
            defer close.deinit(self.server.http.allocator);
            if (close.header.opcode != .close) return error.InvalidFrame;
        }
    };

    var task = ServerTask{ .server = &server };
    var server_task = io.async(ServerTask.run, .{&task});
    defer server_task.cancel(io);

    const uri = try std.fmt.allocPrint(
        allocator,
        "ws://127.0.0.1:{d}/chat",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);

    // Attempt 1: no Authorization. The server response stays inspectable.
    var rejected = try netz.websocket.runtime.Client.connectUriAttempt(
        allocator,
        io,
        uri,
        .{},
    );
    defer rejected.deinit();
    std.debug.print("client got status {d} challenge={?s}\n", .{
        rejected.status(),
        rejected.responseHeader("www-authenticate"),
    });
    try std.testing.expect(!rejected.accepted());

    // Attempt 2: send the bearer token in the opening handshake.
    var attempt = try netz.websocket.runtime.Client.connectUriAttempt(
        allocator,
        io,
        uri,
        .{
            .extra_headers = &.{.{
                .name = "authorization",
                .value = "Bearer " ++ bearer_token,
            }},
        },
    );
    var attempt_owned = true;
    defer if (attempt_owned) attempt.deinit();
    var client = try attempt.requireAccepted();
    attempt_owned = false;
    defer client.close();

    try client.sendText("hello authenticated websocket");
    var response = try client.receiveMessage();
    defer response.deinit(allocator);
    std.debug.print("client received: {s}\n", .{response.payload});
    try client.sendClose(.normal_closure, "bye");

    server_task.await(io);
    if (task.err) |err| return err;
}
