const std = @import("std");
const runtime = @import("../runtime.zig");

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

fn readExact(io: std.Io, stream: net.Stream, bytes: []u8) !void {
    var read: usize = 0;
    while (read < bytes.len) {
        var buffers = [_][]u8{bytes[read..]};
        const count = try io.vtable.netRead(
            io.userdata,
            stream.socket.handle,
            &buffers,
        );
        if (count == 0) return error.ConnectionClosed;
        read += count;
    }
}

test "HTTP/1 request head timeout starts before the first byte" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .request_head_timeout = .fromMilliseconds(75) },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            _ = connection.readRequest(.{}) catch |err| {
                self.err = err;
                return;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try server.address().connect(io, .{ .mode = .stream });
    defer client.close(io);

    thread.join();
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "HTTP/1 request head timeout is absolute across trickled bytes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .request_head_timeout = .fromMilliseconds(150) },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        read_started: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            self.read_started.set(self.server.io);
            _ = connection.readRequest(.{}) catch |err| {
                self.err = err;
                return;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try server.address().connect(io, .{ .mode = .stream });
    defer client.close(io);
    try shared.read_started.wait(io);
    try writeAll(io, client, "GET / HTTP/1.1\r\n");
    try std.Io.sleep(io, .fromMilliseconds(80), .awake);
    try writeAll(io, client, "Host: localhost\r\n");
    try std.Io.sleep(io, .fromMilliseconds(80), .awake);
    // The server should already have expired the original deadline. Ignore a
    // peer-close write error; if an implementation incorrectly renewed the
    // deadline, this terminator would complete the request and fail below.
    writeAll(io, client, "\r\n") catch |err| switch (err) {
        error.SocketUnconnected, error.ConnectionResetByPeer => {},
        else => return err,
    };

    thread.join();
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "HTTP/1 explicit request deadline resumes a partial head" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        prefix_received: std.Io.Event = .unset,
        timed_out: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.prefix_received.set(self.server.io);
                self.timed_out.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            self.prefix_received.set(self.server.io);
            try std.testing.expectError(
                error.Timeout,
                connection.readRequestWithTimeout(
                    .{},
                    .fromMilliseconds(20),
                ),
            );
            try std.testing.expect(connection.writer_state.phase == .idle);
            self.timed_out.set(self.server.io);

            var request = try connection.readRequestWithDeadline(
                .{},
                .fromNow(
                    self.server.io,
                    .{ .raw = .fromSeconds(1), .clock = .awake },
                ),
            );
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "/resumed",
                request.request.target,
            );
            try std.testing.expectEqualStrings(
                "localhost",
                request.request.header("host").?,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try server.address().connect(io, .{ .mode = .stream });
    defer client.close(io);
    try writeAll(io, client, "GET /resumed HTTP/1.1\r\nHost:");
    try shared.prefix_received.wait(io);
    try shared.timed_out.wait(io);
    try writeAll(io, client, " localhost\r\n\r\n");

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 request head timeout resets for each persistent request" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .request_head_timeout = .fromMilliseconds(150) },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        first_read: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            var first = connection.readRequest(.{}) catch |err| {
                self.err = err;
                return;
            };
            defer first.deinit(allocator);
            if (!std.mem.eql(u8, first.request.target, "/first")) {
                self.err = error.TestUnexpectedResult;
                return;
            }
            self.first_read.set(self.server.io);
            var second = connection.readRequest(.{}) catch |err| {
                self.err = err;
                return;
            };
            defer second.deinit(allocator);
            if (!std.mem.eql(u8, second.request.target, "/second")) {
                self.err = error.TestUnexpectedResult;
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try server.address().connect(io, .{ .mode = .stream });
    defer client.close(io);
    try writeAll(io, client, "GET /first HTTP/1.1\r\n");
    try std.Io.sleep(io, .fromMilliseconds(80), .awake);
    try writeAll(io, client, "Host: localhost\r\n\r\n");
    try shared.first_read.waitTimeout(
        io,
        .{ .duration = .{
            .raw = .fromSeconds(2),
            .clock = .awake,
        } },
    );
    try std.Io.sleep(io, .fromMilliseconds(80), .awake);
    try writeAll(
        io,
        client,
        "GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 request head timeout excludes a slow body" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .request_head_timeout = .fromMilliseconds(100) },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            var request = connection.readRequest(.{}) catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit(allocator);
            if (!std.mem.eql(u8, request.request.body, "body")) {
                self.err = error.TestUnexpectedResult;
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try server.address().connect(io, .{ .mode = .stream });
    defer client.close(io);
    try writeAll(
        io,
        client,
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n",
    );
    var interim: [25]u8 = undefined;
    try readExact(io, client, &interim);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 100 Continue\r\n\r\n",
        &interim,
    );
    try std.Io.sleep(io, .fromMilliseconds(150), .awake);
    try writeAll(io, client, "body");

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 pipelined batch gives each unbuffered head a fresh deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .request_head_timeout = .fromMilliseconds(150) },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            var heads: [2]@import("../mod.zig").RequestHead = undefined;
            var headers: [8]@import("../mod.zig").Header = undefined;
            var bodies: [2][]const u8 = undefined;
            const consumed = connection.readRequestBatchInto(
                &heads,
                &headers,
                &bodies,
                .{ .max_headers = 4 },
            ) catch |err| {
                self.err = err;
                return;
            };
            if (consumed == 0 or
                !std.mem.eql(u8, heads[0].target, "/first") or
                !std.mem.eql(u8, heads[1].target, "/second"))
            {
                self.err = error.TestUnexpectedResult;
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try server.address().connect(io, .{ .mode = .stream });
    defer client.close(io);
    try writeAll(
        io,
        client,
        "GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    try std.Io.sleep(io, .fromMilliseconds(80), .awake);
    try writeAll(
        io,
        client,
        "GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/1 streaming request head timeout covers TLS records" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const tls_testing = @import("../../tls/testing.zig");
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .limits = .{
                .request_head_timeout = .fromMilliseconds(100),
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            _ = connection.readRequestStreaming({}, struct {
                fn consume(_: void, _: []const u8) !void {}
            }.consume) catch |err| {
                self.err = err;
                return;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try runtime.Client.connectTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{},
        .{ .verify_host = false },
    );
    defer client.close();
    try client.tls_conn.?.writeAll("GET / HTTP/1.1\r\n");

    thread.join();
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "HTTP/1 TLS listener bounds an idle transport handshake" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const tls_testing = @import("../../tls/testing.zig");
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .tls_handshake_timeout = .fromMilliseconds(75),
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            connection.close();
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const client = try server.address().connect(io, .{ .mode = .stream });
    defer client.close(io);
    thread.join();
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "HTTP/1 TLS server caller timeout bounds transport handshake" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const tls_testing = @import("../../tls/testing.zig");
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .tls_handshake_timeout = .fromSeconds(1),
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.acceptWithTimeout(
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
    const client = try server.address().connect(io, .{ .mode = .stream });
    defer client.close(io);

    thread.join();
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "HTTP/1 io_uring rejects an unsupported request head timeout" {
    if (comptime @import("builtin").os.tag != .linux) {
        return error.SkipZigTest;
    }
    var connection = runtime.LinuxIoUringConnection{
        .allocator = std.testing.allocator,
        .stream = undefined,
        .limits = .{ .request_head_timeout = .fromMilliseconds(1) },
    };
    defer {
        connection.inbuf.deinit(std.testing.allocator);
        connection.write_scratch.deinit(std.testing.allocator);
    }
    try std.testing.expectError(
        error.TimedReadUnsupported,
        connection.readRequest(.{}),
    );
}
