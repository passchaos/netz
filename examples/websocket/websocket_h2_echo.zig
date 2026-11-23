//! WebSocket over HTTP/2 (RFC 8441) on the cleartext h2c runtime.
//!
//! Mirrors how browsers reuse one HTTP/2 connection for WebSocket streams: the
//! extended CONNECT carries `:protocol = websocket`, and every WebSocket is an
//! independent stream instead of a TCP Upgrade. The same code works over TLS
//! by using `http2.runtime.TlsServer`/`TlsClient` instead of the h2c helpers.

const std = @import("std");
const netz = @import("netz");

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var server = try netz.http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .enable_connect_protocol = true,
            .max_body_bytes = 4096,
        },
    );
    defer server.deinit();

    const ServerTask = struct {
        server: *netz.http2.runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var parent = try self.server.accept();
            defer parent.close();
            var connection = try netz.websocket.runtime.H2Server.accept(
                self.server.allocator,
                &parent,
                .{ .protocols = &.{"echo.v1"} },
            );
            defer connection.close();
            var message = try connection.receiveMessage();
            defer message.deinit(self.server.allocator);
            std.debug.print(
                "RFC 8441 server received: {s}\n",
                .{message.payload},
            );
            try connection.sendText(message.payload);
        }
    };

    var task = ServerTask{ .server = &server };
    var server_task = io.async(ServerTask.run, .{&task});
    defer server_task.cancel(io);

    var parent = try netz.http2.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .enable_connect_protocol = true,
            .max_body_bytes = 4096,
        },
    );
    defer parent.close();
    var connection = try netz.websocket.runtime.H2Client.open(
        allocator,
        &parent,
        .{
            .authority = "localhost",
            .path = "/echo",
            .protocols = &.{"echo.v1"},
        },
    );
    defer connection.close();
    try connection.sendText("hello over RFC 8441");
    var reply = try connection.receiveMessage();
    defer reply.deinit(allocator);
    std.debug.print("RFC 8441 client received: {s}\n", .{reply.payload});

    server_task.await(io);
    if (task.err) |err| return err;
}
