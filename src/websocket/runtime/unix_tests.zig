const std = @import("std");
const runtime = @import("../runtime.zig");
const websocket = @import("../mod.zig");

test "WebSocket Unix sockets reject TCP-only socket policy" {
    if (comptime @import("builtin").os.tag == .windows) {
        return error.SkipZigTest;
    }
    const address = try std.Io.net.UnixAddress.init(
        "/tmp/netz-websocket-tcp-user-timeout-unsupported.sock",
    );
    try std.testing.expectError(
        error.SocketOptionUnsupported,
        runtime.UnixServer.listen(
            std.testing.allocator,
            std.testing.io,
            address,
            .{ .tcp_user_timeout_ms = 1 },
        ),
    );
    try std.testing.expectError(
        error.SocketOptionUnsupported,
        runtime.UnixServer.listen(
            std.testing.allocator,
            std.testing.io,
            address,
            .{ .tcp_keepalive = .{
                .idle_seconds = 1,
                .interval_seconds = 1,
                .probe_count = 1,
            } },
        ),
    );
    try std.testing.expectError(
        error.SocketOptionUnsupported,
        runtime.Client.connectUnixAttempt(
            std.testing.allocator,
            std.testing.io,
            address,
            .{
                .host = "localhost",
                .tcp_user_timeout_ms = 1,
            },
        ),
    );
    try std.testing.expectError(
        error.SocketOptionUnsupported,
        runtime.Client.connectUnixAttempt(
            std.testing.allocator,
            std.testing.io,
            address,
            .{
                .host = "localhost",
                .tcp_keepalive = .{
                    .idle_seconds = 1,
                    .interval_seconds = 1,
                    .probe_count = 1,
                },
            },
        ),
    );
}

test "WebSocket client and server exchange over a Unix socket" {
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
    const socket_path = try std.fmt.bufPrint(
        path_storage[directory_len..],
        "/websocket.sock",
        .{},
    );
    const full_path = path_storage[0 .. directory_len + socket_path.len];
    const address = try std.Io.net.UnixAddress.init(full_path);
    var server = try runtime.UnixServer.listen(allocator, io, address, .{
        .max_head_bytes = 4096,
        .max_frame_bytes = 4096,
        .max_message_bytes = 4096,
    });
    defer {
        server.deinit();
        std.Io.Dir.deleteFileAbsolute(io, full_path) catch {};
    }

    const Shared = struct {
        server: *runtime.UnixServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var pending = self.server.receiveUpgradeRequest(.{
                .protocols = &.{"unix.test"},
                .require_subprotocol = true,
                .enable_permessage_deflate = true,
            }) catch |err| {
                self.err = err;
                return;
            };
            if (pending.peerAddress() != null) {
                self.err = error.UnexpectedMessage;
                pending.deinit();
                return;
            }
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            if (!std.mem.eql(u8, pending.target(), "/unix") or
                !std.mem.eql(
                    u8,
                    pending.header("authorization") orelse "",
                    "Bearer unix-admission",
                ))
            {
                self.err = error.InvalidHandshake;
                return;
            }
            var connection = pending.accept() catch |err| {
                self.err = err;
                return;
            };
            pending_owned = false;
            defer connection.close();
            if (connection.peerAddress() != null) {
                self.err = error.UnexpectedMessage;
                return;
            }
            var message = connection.receiveMessage() catch |err| {
                self.err = err;
                return;
            };
            defer message.deinit(connection.allocator);
            if (message.opcode != .text or
                !std.mem.eql(u8, message.payload, "hello over unix"))
            {
                self.err = error.UnexpectedMessage;
                return;
            }
            connection.sendText("unix websocket reply") catch |err| {
                self.err = err;
                return;
            };
            var close = connection.receiveFrame() catch |err| {
                self.err = err;
                return;
            };
            defer close.deinit(connection.allocator);
            if (close.header.opcode != websocket.Opcode.close) {
                self.err = error.UnexpectedMessage;
            }
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
        .{
            .host = "localhost",
            .target = "/unix",
            .protocols = &.{"unix.test"},
            .extra_headers = &.{.{
                .name = "Authorization",
                .value = "Bearer unix-admission",
            }},
            .enable_permessage_deflate = true,
            .limits = .{
                .max_head_bytes = 4096,
                .max_frame_bytes = 4096,
                .max_message_bytes = 4096,
            },
        },
    );
    defer client.close();
    try std.testing.expect(client.peerAddress() == null);
    try std.testing.expectEqualStrings(
        "unix.test",
        client.selected_protocol.?,
    );
    try std.testing.expect(client.permessage_deflate);
    try client.sendText("hello over unix");
    var reply = try client.receiveMessage();
    defer reply.deinit(allocator);
    try std.testing.expectEqual(websocket.Opcode.text, reply.opcode);
    try std.testing.expectEqualStrings(
        "unix websocket reply",
        reply.payload,
    );
    try client.sendClose(.normal_closure, "done");

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebSocket Unix server caller timeout bounds HTTP upgrade" {
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
    const socket_path = try std.fmt.bufPrint(
        path_storage[directory_len..],
        "/websocket-timeout.sock",
        .{},
    );
    const full_path = path_storage[0 .. directory_len + socket_path.len];
    const address = try std.Io.net.UnixAddress.init(full_path);
    var server = try runtime.UnixServer.listen(allocator, io, address, .{
        .http1_handshake_timeout = .fromSeconds(1),
    });
    defer {
        server.deinit();
        std.Io.Dir.deleteFileAbsolute(io, full_path) catch {};
    }

    const Shared = struct {
        server: *runtime.UnixServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.acceptWithTimeout(
                .{},
                .fromMilliseconds(30),
            ) catch |err| {
                self.err = err;
                return;
            };
            connection.close();
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const client = try address.connect(io);
    defer client.close(io);

    thread.join();
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "WebSocket Unix listener accept deadline expires without a client" {
    if (comptime @import("builtin").os.tag == .windows) {
        return error.SkipZigTest;
    }
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // TmpDir lives under this cwd-relative path. Keep the Unix address
    // bounded even when the checkout itself exceeds sun_path's capacity.
    var path_storage: [std.Io.net.UnixAddress.max_len]u8 = undefined;
    const full_path = try std.fmt.bufPrint(
        &path_storage,
        ".zig-cache/tmp/{s}/websocket-accept-deadline.sock",
        .{tmp.sub_path},
    );
    const address = try std.Io.net.UnixAddress.init(full_path);
    var server = try runtime.UnixServer.listen(allocator, io, address, .{});
    defer {
        server.deinit();
        tmp.dir.deleteFile(io, "websocket-accept-deadline.sock") catch {};
    }

    try std.testing.expectError(
        error.Timeout,
        server.receiveUpgradeRequestWithTimeout(
            .{},
            .fromMilliseconds(20),
        ),
    );
}
