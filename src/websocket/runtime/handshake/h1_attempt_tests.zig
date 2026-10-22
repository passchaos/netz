const std = @import("std");
const http1_runtime = @import("../../../http1/runtime.zig");
const runtime = @import("../../runtime.zig");
const websocket = @import("../../mod.zig");

const net = std.Io.net;

fn writeAll(io: std.Io, stream: net.Stream, bytes: []const u8) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        const count = try io.vtable.netWrite(
            io.userdata,
            stream.socket.handle,
            bytes[written..],
            &.{""},
            0,
        );
        if (count == 0) return error.SocketUnconnected;
        written += count;
    }
}

fn serveResponse(
    allocator: std.mem.Allocator,
    io: std.Io,
    listener: *net.Server,
    response: []const u8,
) !void {
    const stream = try listener.accept(io);
    defer stream.close(io);
    var request = try http1_runtime.readRequestFromStreamWithTimeout(
        allocator,
        io,
        stream,
        .{ .max_head_bytes = 4096, .max_body_bytes = 0 },
        .{ .max_headers = 32 },
        .fromSeconds(3),
    );
    defer request.deinit(allocator);
    try writeAll(io, stream, response);
}

test "WebSocket HTTP1 connect attempt preserves rejection metadata and body" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const response =
        "HTTP/1.1 401 Unauthorized\r\n" ++
        "Content-Length: 12\r\n" ++
        "X-Auth-Reason: expired\r\n" ++
        "Connection: close\r\n\r\n" ++
        "unauthorized";
    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        response: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            serveResponse(
                self.allocator,
                self.io,
                self.listener,
                self.response,
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .listener = &listener,
        .response = response,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const uri = try std.fmt.allocPrint(
        allocator,
        "ws://127.0.0.1:{d}/auth",
        .{listener.socket.address.getPort()},
    );
    defer allocator.free(uri);
    var attempt = try runtime.Client.connectUriAttemptWithTimeout(
        allocator,
        io,
        uri,
        .{ .limits = .{ .max_head_bytes = 4096 } },
        .fromSeconds(3),
    );
    defer attempt.deinit();
    try std.testing.expect(!attempt.accepted());
    try std.testing.expectEqual(@as(u16, 401), attempt.status());
    try std.testing.expectEqualStrings(
        "expired",
        attempt.responseHeader("x-auth-reason").?,
    );
    try std.testing.expectEqualStrings("unauthorized", attempt.body());
    try std.testing.expectError(error.InvalidResponse, attempt.requireAccepted());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP1 client maps advertised unsupported version" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const response =
        "HTTP/1.1 426 Upgrade Required\r\n" ++
        "Sec-WebSocket-Version: 8, 12\r\n" ++
        "Sec-WebSocket-Version: 14\r\n" ++
        "Content-Length: 11\r\n" ++
        "Connection: close\r\n\r\n" ++
        "unsupported";
    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        response: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            serveResponse(
                self.allocator,
                self.io,
                self.listener,
                self.response,
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .listener = &listener,
        .response = response,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var attempt = try runtime.Client.connectAttemptWithTimeout(
        allocator,
        io,
        listener.socket.address,
        .{ .host = "localhost", .limits = .{ .max_head_bytes = 4096 } },
        .fromSeconds(3),
    );
    defer attempt.deinit();
    try std.testing.expectEqual(@as(u16, 426), attempt.status());
    try std.testing.expectEqualStrings("8, 12", attempt.responseHeader(
        "sec-websocket-version",
    ).?);
    try std.testing.expectEqualStrings("unsupported", attempt.body());
    try std.testing.expectError(
        error.UnsupportedVersion,
        attempt.requireAccepted(),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP1 connect attempt skips bounded informational responses" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const response =
        "HTTP/1.1 103 Early Hints\r\nLink: </auth>\r\n\r\n" ++
        "HTTP/1.1 401 Unauthorized\r\nContent-Length: 6\r\n" ++
        "Connection: close\r\n\r\ndenied";
    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        response: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            serveResponse(
                self.allocator,
                self.io,
                self.listener,
                self.response,
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .listener = &listener,
        .response = response,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var attempt = try runtime.Client.connectAttemptWithTimeout(
        allocator,
        io,
        listener.socket.address,
        .{ .host = "localhost", .limits = .{ .max_head_bytes = 4096 } },
        .fromSeconds(3),
    );
    defer attempt.deinit();
    try std.testing.expectEqual(@as(u16, 401), attempt.status());
    try std.testing.expectEqualStrings("denied", attempt.body());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP1 connect attempt rejects excessive informational responses" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            serveResponse(
                self.allocator,
                self.io,
                self.listener,
                "HTTP/1.1 103 Early Hints\r\n\r\n" ++
                    "HTTP/1.1 102 Processing\r\n\r\n" ++
                    "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .listener = &listener,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    try std.testing.expectError(
        error.TooManyInformationalResponses,
        runtime.Client.connectAttemptWithTimeout(
            allocator,
            io,
            listener.socket.address,
            .{
                .host = "localhost",
                .limits = .{
                    .max_head_bytes = 4096,
                    .max_informational_responses = 1,
                },
            },
            .fromSeconds(3),
        ),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP1 connect attempt decodes chunked rejection trailers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const response =
        "HTTP/1.1 429 Too Many Requests\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "Connection: close\r\n\r\n" ++
        "4\r\nslow\r\n" ++
        "0\r\nRetry-After: 5\r\n\r\n";
    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        response: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            serveResponse(
                self.allocator,
                self.io,
                self.listener,
                self.response,
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .listener = &listener,
        .response = response,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var attempt = try runtime.Client.connectAttemptWithTimeout(
        allocator,
        io,
        listener.socket.address,
        .{ .host = "localhost", .limits = .{ .max_head_bytes = 4096 } },
        .fromSeconds(3),
    );
    defer attempt.deinit();
    try std.testing.expectEqual(@as(u16, 429), attempt.status());
    try std.testing.expectEqualStrings("slow", attempt.body());
    try std.testing.expectEqual(@as(usize, 1), attempt.trailers().len);
    try std.testing.expect(attempt.trailers()[0].eqlName("retry-after"));
    try std.testing.expectEqualStrings("5", attempt.trailers()[0].value);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP1 legacy connect still maps rejection to InvalidResponse" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            serveResponse(
                self.allocator,
                self.io,
                self.listener,
                "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n" ++
                    "Connection: close\r\n\r\n",
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .listener = &listener,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    try std.testing.expectError(error.InvalidResponse, runtime.Client.connectWithTimeout(
        allocator,
        io,
        listener.socket.address,
        .{ .host = "localhost", .limits = .{ .max_head_bytes = 4096 } },
        .fromSeconds(3),
    ));

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP1 connect attempt bounds rejection body" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            serveResponse(
                self.allocator,
                self.io,
                self.listener,
                "HTTP/1.1 403 Forbidden\r\nContent-Length: 5\r\n" ++
                    "Connection: close\r\n\r\ndenied",
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .listener = &listener,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    try std.testing.expectError(error.BodyTooLarge, runtime.Client.connectAttempt(
        allocator,
        io,
        listener.socket.address,
        .{
            .host = "localhost",
            .limits = .{
                .max_head_bytes = 4096,
                .max_rejection_body_bytes = 4,
            },
        },
    ));

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP1 connect attempt preserves close-delimited rejection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            serveResponse(
                self.allocator,
                self.io,
                self.listener,
                "HTTP/1.1 503 Service Unavailable\r\n" ++
                    "Connection: close\r\n\r\ntry later",
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .listener = &listener,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var attempt = try runtime.Client.connectAttemptWithTimeout(
        allocator,
        io,
        listener.socket.address,
        .{ .host = "localhost", .limits = .{ .max_head_bytes = 4096 } },
        .fromSeconds(3),
    );
    defer attempt.deinit();
    try std.testing.expectEqual(@as(u16, 503), attempt.status());
    try std.testing.expectEqualStrings("try later", attempt.body());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP1 accepted attempt skips informational and preserves coalesced frame bytes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            const stream = self.listener.accept(self.io) catch |err| {
                self.err = err;
                return;
            };
            defer stream.close(self.io);
            var request = http1_runtime.readRequestFromStreamWithTimeout(
                self.allocator,
                self.io,
                stream,
                .{ .max_head_bytes = 4096, .max_body_bytes = 0 },
                .{ .max_headers = 32 },
                .fromSeconds(3),
            ) catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit(self.allocator);
            const key = request.request.header("sec-websocket-key") orelse {
                self.err = error.MissingHeader;
                return;
            };
            const accept = websocket.acceptKey(key);
            var response: std.ArrayList(u8) = .empty;
            defer response.deinit(self.allocator);
            response.appendSlice(
                self.allocator,
                "HTTP/1.1 103 Early Hints\r\nLink: </socket>\r\n\r\n" ++
                    "HTTP/1.1 101 Switching Protocols\r\n" ++
                    "Upgrade: websocket\r\n" ++
                    "Connection: Upgrade\r\nSec-WebSocket-Accept: ",
            ) catch |err| {
                self.err = err;
                return;
            };
            response.appendSlice(self.allocator, &accept) catch |err| {
                self.err = err;
                return;
            };
            response.appendSlice(self.allocator, "\r\n\r\n\x81\x02ok") catch |err| {
                self.err = err;
                return;
            };
            writeAll(self.io, stream, response.items) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .listener = &listener,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var attempt = try runtime.Client.connectAttemptWithTimeout(
        allocator,
        io,
        listener.socket.address,
        .{ .host = "localhost", .limits = .{ .max_head_bytes = 4096 } },
        .fromSeconds(3),
    );
    var attempt_owned = true;
    defer if (attempt_owned) attempt.deinit();
    try std.testing.expect(attempt.accepted());
    var connection = try attempt.requireAccepted();
    attempt_owned = false;
    defer connection.close();
    var frame = try connection.receiveFrame();
    defer frame.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, frame.header.opcode);
    try std.testing.expectEqualStrings("ok", frame.payload);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket HTTP1 client rejects unoffered compression window" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            const stream = self.listener.accept(self.io) catch |err| {
                self.err = err;
                return;
            };
            defer stream.close(self.io);
            var request = http1_runtime.readRequestFromStreamWithTimeout(
                self.allocator,
                self.io,
                stream,
                .{ .max_head_bytes = 4096, .max_body_bytes = 0 },
                .{ .max_headers = 32 },
                .fromSeconds(3),
            ) catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit(self.allocator);
            const key = request.request.header("sec-websocket-key") orelse {
                self.err = error.MissingHeader;
                return;
            };
            const accept = websocket.acceptKey(key);
            var response: std.ArrayList(u8) = .empty;
            defer response.deinit(self.allocator);
            response.appendSlice(
                self.allocator,
                "HTTP/1.1 101 Switching Protocols\r\n" ++
                    "Upgrade: websocket\r\n" ++
                    "Connection: Upgrade\r\n" ++
                    "Sec-WebSocket-Accept: ",
            ) catch |err| {
                self.err = err;
                return;
            };
            response.appendSlice(self.allocator, &accept) catch |err| {
                self.err = err;
                return;
            };
            response.appendSlice(
                self.allocator,
                "\r\nSec-WebSocket-Extensions: permessage-deflate; " ++
                    "server_no_context_takeover; " ++
                    "client_no_context_takeover; " ++
                    "client_max_window_bits=15\r\n\r\n",
            ) catch |err| {
                self.err = err;
                return;
            };
            writeAll(self.io, stream, response.items) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .listener = &listener,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var attempt = try runtime.Client.connectAttemptWithTimeout(
        allocator,
        io,
        listener.socket.address,
        .{
            .host = "localhost",
            .enable_permessage_deflate = true,
            .limits = .{ .max_head_bytes = 4096 },
        },
        .fromSeconds(3),
    );
    defer attempt.deinit();
    try std.testing.expect(attempt.accepted());
    try std.testing.expectError(
        error.InvalidExtension,
        attempt.requireAccepted(),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
