const std = @import("std");
const forwarded_io = @import("../../internal/testing/forwarded_io.zig");
const native_protocol_io = @import("../../internal/testing/native_protocol_io.zig");
const pool_mod = @import("../client_pool.zig");
const runtime = @import("../runtime.zig");
const tls_stream = @import("../../tls/mod.zig").stream;

fn localCaBundle(
    allocator: std.mem.Allocator,
    io: std.Io,
) !struct { std.crypto.Certificate.Bundle, std.Io.RwLock } {
    const tls_testing = @import("../../tls/testing.zig");
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    var pem_storage: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&pem_storage);
    try writer.writeAll("-----BEGIN CERTIFICATE-----\n");
    const encoded_len = std.base64.standard.Encoder.calcSize(
        certificate_der.len,
    );
    const encoded = try writer.writableSliceGreedy(encoded_len);
    _ = std.base64.standard.Encoder.encode(
        encoded[0..encoded_len],
        &certificate_der,
    );
    writer.advance(encoded_len);
    try writer.writeAll("\n-----END CERTIFICATE-----\n");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "ca.pem",
        .data = writer.buffered(),
    });
    var bundle: std.crypto.Certificate.Bundle = .empty;
    errdefer bundle.deinit(allocator);
    try bundle.addCertsFromFilePath(
        allocator,
        io,
        std.Io.Timestamp.now(io, .real),
        tmp.dir,
        "ca.pem",
    );
    return .{ bundle, .init };
}

fn uriFor(
    allocator: std.mem.Allocator,
    address: std.Io.net.IpAddress,
    path: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}{s}",
        .{ address.ip4.port, path },
    );
}

fn writeRawAll(
    io: std.Io,
    stream: std.Io.net.Stream,
    bytes: []const u8,
) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const parts = [_][]const u8{""};
        const written = try io.vtable.netWrite(
            io.userdata,
            stream.socket.handle,
            bytes[offset..],
            &parts,
            0,
        );
        if (written == 0) return error.SocketUnconnected;
        offset += written;
    }
}

test "HTTP/1 client pool reuses one persistent connection" {
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
        release: std.Io.Event = .unset,
        accepts: usize = 0,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            self.accepts += 1;
            defer connection.close();
            for (0..2) |index| {
                var request = try connection.readRequest(.{});
                defer request.deinit(self.server.allocator);
                try std.testing.expectEqualStrings(
                    if (index == 0) "/first" else "/second?x=1",
                    request.request.target,
                );
                try connection.writeResponse(.{
                    .body = if (index == 0) "one" else "two",
                    .request_method = request.request.method,
                });
            }
            try self.release.wait(self.server.io);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.release.set(io);
        thread.join();
    };
    var pool = try pool_mod.Pool.init(allocator, io, .{});
    defer pool.deinit();
    const first_uri = try uriFor(allocator, server.address(), "/first");
    defer allocator.free(first_uri);
    const second_uri = try uriFor(
        allocator,
        server.address(),
        "/second?x=1",
    );
    defer allocator.free(second_uri);
    var lease = try pool.acquireUri(first_uri);
    var first = try lease.client().request(.{ .target = "/first" });
    try std.testing.expectEqual(
        runtime.IdleSocketState.clean,
        runtime.probeIdleSocket(lease.client().stream),
    );
    lease.release();
    defer first.deinit(allocator);
    var second = try pool.requestUri(second_uri, .{});
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("one", first.response.body);
    try std.testing.expectEqualStrings("two", second.response.body);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());

    shared.release.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.accepts);
}

test "HTTP/1 client pool discards unsolicited read-ahead response" {
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
        accepts: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            {
                var connection = try self.server.accept();
                self.accepts += 1;
                defer connection.close();
                var request = try connection.readRequest(.{});
                defer request.deinit(self.server.allocator);
                try std.testing.expectEqualStrings(
                    "/first",
                    request.request.target,
                );
                try connection.writeResponses(&.{
                    .{ .body = "one", .request_method = request.request.method },
                    .{ .body = "ghost", .request_method = request.request.method },
                });
            }
            {
                var connection = try self.server.acceptWithTimeout(
                    .fromSeconds(2),
                );
                self.accepts += 1;
                defer connection.close();
                var request = try connection.readRequest(.{});
                defer request.deinit(self.server.allocator);
                try std.testing.expectEqualStrings(
                    "/second",
                    request.request.target,
                );
                try connection.writeResponse(.{
                    .body = "two",
                    .request_method = request.request.method,
                });
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_authority = 1,
    });
    defer pool.deinit();
    const first_uri = try uriFor(allocator, server.address(), "/first");
    defer allocator.free(first_uri);
    const second_uri = try uriFor(allocator, server.address(), "/second");
    defer allocator.free(second_uri);

    var first = try pool.requestUriWithTimeout(
        first_uri,
        .{},
        .fromSeconds(2),
    );
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("one", first.response.body);
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());

    var second = try pool.requestUriWithTimeout(
        second_uri,
        .{},
        .fromSeconds(2),
    );
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("two", second.response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.accepts);
}

test "HTTP/1 client pool discards kernel-queued unsolicited response" {
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
        first_consumed: std.Io.Event = .unset,
        ghost_written: std.Io.Event = .unset,
        accepts: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.ghost_written.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            {
                var connection = try self.server.accept();
                self.accepts += 1;
                defer connection.close();
                var request = try connection.readRequest(.{});
                defer request.deinit(self.server.allocator);
                try connection.writeResponse(.{
                    .body = "one",
                    .request_method = request.request.method,
                });
                try self.first_consumed.wait(self.server.io);
                try writeRawAll(
                    self.server.io,
                    connection.stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nghost",
                );
                self.ghost_written.set(self.server.io);
            }
            {
                var connection = try self.server.acceptWithTimeout(
                    .fromSeconds(2),
                );
                self.accepts += 1;
                defer connection.close();
                var request = try connection.readRequest(.{});
                defer request.deinit(self.server.allocator);
                try connection.writeResponse(.{
                    .body = "two",
                    .request_method = request.request.method,
                });
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.first_consumed.set(io);
        thread.join();
    };

    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_authority = 1,
    });
    defer pool.deinit();
    const first_uri = try uriFor(allocator, server.address(), "/first");
    defer allocator.free(first_uri);
    const second_uri = try uriFor(allocator, server.address(), "/second");
    defer allocator.free(second_uri);

    var lease = try pool.acquireUri(first_uri);
    var first = try lease.client().request(.{ .target = "/first" });
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("one", first.response.body);
    try std.testing.expectEqual(@as(usize, 0), lease.client().inbuf.items.len);
    shared.first_consumed.set(io);
    try shared.ghost_written.wait(io);
    var attempts: usize = 0;
    while (lease.client().isReusableForPool() and attempts < 100) : (attempts += 1) {
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expect(!lease.client().isReusableForPool());
    lease.release();
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());

    var second = try pool.requestUriWithTimeout(
        second_uri,
        .{},
        .fromSeconds(2),
    );
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("two", second.response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.accepts);
}

test "HTTP/1 client pool rechecks an idle socket before checkout" {
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
        lease_released: std.Io.Event = .unset,
        ghost_written: std.Io.Event = .unset,
        accepts: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.ghost_written.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            {
                var connection = try self.server.accept();
                self.accepts += 1;
                defer connection.close();
                var request = try connection.readRequest(.{});
                defer request.deinit(self.server.allocator);
                try connection.writeResponse(.{ .body = "one" });
                try self.lease_released.wait(self.server.io);
                try writeRawAll(
                    self.server.io,
                    connection.stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nghost",
                );
                self.ghost_written.set(self.server.io);
            }
            {
                var connection = try self.server.acceptWithTimeout(
                    .fromSeconds(2),
                );
                self.accepts += 1;
                defer connection.close();
                var request = try connection.readRequest(.{});
                defer request.deinit(self.server.allocator);
                try std.testing.expectEqualStrings(
                    "/second",
                    request.request.target,
                );
                try connection.writeResponse(.{ .body = "two" });
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.lease_released.set(io);
        thread.join();
    };

    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_authority = 1,
    });
    defer pool.deinit();
    const first_uri = try uriFor(allocator, server.address(), "/first");
    defer allocator.free(first_uri);
    const second_uri = try uriFor(allocator, server.address(), "/second");
    defer allocator.free(second_uri);

    var first = try pool.requestUri(first_uri, .{});
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("one", first.response.body);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    shared.lease_released.set(io);
    try shared.ghost_written.wait(io);

    var second = try pool.requestUriWithTimeout(
        second_uri,
        .{},
        .fromSeconds(2),
    );
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("two", second.response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.accepts);
}

test "HTTP/1 client pool discards kernel-queued EOF" {
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
        first_consumed: std.Io.Event = .unset,
        eof_sent: std.Io.Event = .unset,
        accepts: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.eof_sent.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            {
                var connection = try self.server.accept();
                self.accepts += 1;
                defer connection.close();
                var request = try connection.readRequest(.{});
                defer request.deinit(self.server.allocator);
                try connection.writeResponse(.{
                    .body = "one",
                    .request_method = request.request.method,
                });
                try self.first_consumed.wait(self.server.io);
                try connection.stream.shutdown(self.server.io, .send);
                self.eof_sent.set(self.server.io);
            }
            {
                var connection = try self.server.acceptWithTimeout(
                    .fromSeconds(2),
                );
                self.accepts += 1;
                defer connection.close();
                var request = try connection.readRequest(.{});
                defer request.deinit(self.server.allocator);
                try connection.writeResponse(.{
                    .body = "two",
                    .request_method = request.request.method,
                });
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.first_consumed.set(io);
        thread.join();
    };

    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_authority = 1,
    });
    defer pool.deinit();
    const first_uri = try uriFor(allocator, server.address(), "/first");
    defer allocator.free(first_uri);
    const second_uri = try uriFor(allocator, server.address(), "/second");
    defer allocator.free(second_uri);

    var lease = try pool.acquireUri(first_uri);
    var first = try lease.client().request(.{ .target = "/first" });
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("one", first.response.body);
    shared.first_consumed.set(io);
    try shared.eof_sent.wait(io);
    var attempts: usize = 0;
    while (lease.client().isReusableForPool() and attempts < 100) : (attempts += 1) {
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expect(!lease.client().isReusableForPool());
    lease.release();
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());

    var second = try pool.requestUriWithTimeout(
        second_uri,
        .{},
        .fromSeconds(2),
    );
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("two", second.response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.accepts);
}

test "HTTP/1 client pool discards a CONNECT handoff" {
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
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqual(
                @import("../mod.zig").Method.CONNECT,
                request.request.method,
            );
            var tunnel = try connection.acceptConnectTunnel(
                request.request,
                &.{},
            );
            var buffer: [16]u8 = undefined;
            const count = try tunnel.read(&buffer);
            try std.testing.expectEqualStrings("pool tunnel", buffer[0..count]);
            try tunnel.write("pool reply");
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_authority = 1,
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, server.address(), "/connect");
    defer allocator.free(uri);
    var lease = try pool.acquireUri(uri);
    var tunnel = try lease.client().openConnectTunnel(
        "example.com:443",
        &.{},
    );
    try tunnel.write("pool tunnel");
    var buffer: [16]u8 = undefined;
    const count = try tunnel.read(&buffer);
    try std.testing.expectEqualStrings("pool reply", buffer[0..count]);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    lease.release();
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
}

test "HTTP/1 client pool discards an aggregate partial-write failure" {
    try native_protocol_io.runStream(pooledPartialWriteFailure);
}

fn pooledPartialWriteFailure(io: std.Io) !void {
    const allocator = std.testing.allocator;
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        received: [4]u8 = undefined,
        received_len: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            while (self.received_len < self.received.len) {
                var buffers = [_][]u8{self.received[self.received_len..]};
                const count = try self.server.io.vtable.netRead(
                    self.server.io.userdata,
                    connection.stream.socket.handle,
                    &buffers,
                );
                if (count == 0) break;
                self.received_len += count;
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_authority = 1,
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, server.address(), "/partial");
    defer allocator.free(uri);
    var lease = try pool.acquireUri(uri);

    const FailingWriter = struct {
        delegate: std.Io,
        calls: usize = 0,

        fn write(
            context: ?*anyopaque,
            handle: std.Io.net.Socket.Handle,
            header: []const u8,
            _: []const []const u8,
            _: usize,
        ) std.Io.net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            if (self.calls != 1) return error.NetworkDown;
            return self.delegate.vtable.netWrite(
                self.delegate.userdata,
                handle,
                header[0..@min(header.len, 4)],
                &.{""},
                0,
            );
        }
    };
    {
        var failing = FailingWriter{ .delegate = io };
        lease.client().io = forwarded_io.observer(&failing, .{ .netWrite = FailingWriter.write });
        defer lease.client().io = io;
        try std.testing.expectError(
            error.NetworkDown,
            lease.client().request(.{
                .method = .POST,
                .target = "/partial",
                .body = "body",
            }),
        );
        try std.testing.expect(!lease.client().isReusable());
    }
    lease.release();
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 4), shared.received_len);
    try std.testing.expectEqualStrings("POST", &shared.received);
}

test "HTTP/1 client pool normalizes explicit default port keys" {
    const allocator = std.testing.allocator;
    // Parsing both spellings exercises the key path without requiring the
    // privileged default port to be bindable in a test environment.
    const implicit = try std.Uri.parse("http://example.com/");
    var implicit_endpoint = try runtime.uriEndpoint(allocator, implicit, 80);
    defer implicit_endpoint.deinit();
    const explicit = try std.Uri.parse("http://EXAMPLE.COM:80/");
    var explicit_endpoint = try runtime.uriEndpoint(allocator, explicit, 80);
    defer explicit_endpoint.deinit();
    try std.testing.expectEqual(implicit_endpoint.port, explicit_endpoint.port);
    try std.testing.expect(std.ascii.eqlIgnoreCase(
        implicit_endpoint.tls_host,
        explicit_endpoint.tls_host,
    ));
}

test "HTTP/1 client connect timeout is available through direct and pool APIs" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(1) };

    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connect(allocator, io, address, .{
            .connect_timeout = .zero,
        }),
    );
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .limits = .{ .connect_timeout = .zero },
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, address, "/connect-timeout");
    defer allocator.free(uri);
    try std.testing.expectError(error.Timeout, pool.acquireUri(uri));
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
}

test "HTTP/1 client pool retries a stale idempotent connection" {
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
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var first = try self.server.accept();
            var request = try first.readRequest(.{});
            request.deinit(self.server.allocator);
            try first.writeResponse(.{ .body = "first" });
            first.close();

            var second = try self.server.accept();
            defer second.close();
            request = try second.readRequest(.{});
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/retry", request.request.target);
            try std.testing.expect(request.request.method == .QUERY);
            try second.writeResponse(.{ .body = "retried" });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{});
    defer pool.deinit();
    const first_uri = try uriFor(allocator, server.address(), "/seed");
    defer allocator.free(first_uri);
    const retry_uri = try uriFor(allocator, server.address(), "/retry");
    defer allocator.free(retry_uri);
    var first = try pool.requestUri(first_uri, .{});
    first.deinit(allocator);
    var retried = try pool.requestUri(retry_uri, .{ .method = .QUERY });
    defer retried.deinit(allocator);
    try std.testing.expectEqualStrings("retried", retried.response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 client pool discards close in any Connection response field" {
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
        release: std.Io.Event = .unset,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(self.server.allocator);
            try connection.writeResponse(.{
                // The first field alone advertises persistence. A later close
                // token must still make the parsed response and pool slot
                // non-reusable.
                .headers = &.{
                    .{ .name = "Connection", .value = "keep-alive" },
                    .{ .name = "connection", .value = "close" },
                },
                .body = "done",
            });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{});
    defer pool.deinit();
    const uri = try uriFor(allocator, server.address(), "/close");
    defer allocator.free(uri);
    var response = try pool.requestUri(uri, .{});
    defer response.deinit(allocator);
    try std.testing.expect(!response.response.keepAlive());
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 client pool retires TE plus CL response connection" {
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
        accepts: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.server.accept();
            defer first.close();
            self.accepts += 1;
            var first_request = try first.readRequest(.{});
            defer first_request.deinit(self.server.allocator);
            try writeRawAll(
                self.server.io,
                first.stream,
                "HTTP/1.1 200 OK\r\n" ++
                    "Content-Length: invalid\r\n" ++
                    "Transfer-Encoding: chunked\r\n\r\n" ++
                    "3\r\none\r\n0\r\n\r\n",
            );

            // Keep the ambiguous-response socket open. A client that derives
            // reuse only from the sanitized headers will send its next request
            // there and leave this fresh accept waiting until timeout.
            var second = try self.server.acceptWithTimeout(
                .fromSeconds(2),
            );
            defer second.close();
            self.accepts += 1;
            var second_request = try second.readRequest(.{});
            defer second_request.deinit(self.server.allocator);
            try second.writeResponse(.{
                .body = "two",
                .request_method = second_request.request.method,
            });
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var pool = try pool_mod.Pool.init(allocator, io, .{});
    defer pool.deinit();
    const first_uri = try uriFor(allocator, server.address(), "/ambiguous");
    defer allocator.free(first_uri);
    const second_uri = try uriFor(allocator, server.address(), "/fresh");
    defer allocator.free(second_uri);
    var first = try pool.requestUriWithTimeout(
        first_uri,
        .{},
        .fromSeconds(3),
    );
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("one", first.response.body);
    try std.testing.expect(first.response.header("content-length") == null);
    try std.testing.expect(first.response.must_close);
    try std.testing.expect(!first.response.keepAlive());
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());

    var second = try pool.requestUriWithTimeout(
        second_uri,
        .{},
        .fromSeconds(3),
    );
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("two", second.response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.accepts);
}

test "HTTP/1 client pool reuses verified TLS connection" {
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
        .{ .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
        } },
    );
    defer server.deinit();
    const Shared = struct {
        server: *runtime.TlsServer,
        release: std.Io.Event = .unset,
        accepts: usize = 0,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            self.accepts += 1;
            defer connection.close();
            for (0..2) |_| {
                var request = try connection.readRequest(.{});
                defer request.deinit(allocator);
                try connection.writeResponse(.{ .body = "secure" });
            }
            try self.release.wait(self.server.io);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.release.set(io);
        thread.join();
    };
    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .tls = .{ .ca_bundle = .{
            .bundle = &ca_bundle,
            .lock = &ca_lock,
        } },
    });
    defer pool.deinit();
    const first_uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/first",
        .{server.address().ip4.port},
    );
    defer allocator.free(first_uri);
    const second_uri = try std.fmt.allocPrint(
        allocator,
        "https://LOCALHOST:{d}/second",
        .{server.address().ip4.port},
    );
    defer allocator.free(second_uri);
    var first = try pool.requestUri(first_uri, .{});
    defer first.deinit(allocator);
    var second = try pool.requestUri(second_uri, .{});
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("secure", first.response.body);
    try std.testing.expectEqualStrings("secure", second.response.body);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());

    shared.release.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.accepts);
}

fn testTlsTicketResumptionAfterRetirement(
    comptime protocol_policy: tls_stream.VersionPolicy,
) !void {
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
    const public_key = key_pair.public_key.toUncompressedSec1();
    var keyring = try tls_stream.Tls13TicketKeyring.init(.{
        .id = 29,
        .secret = [_]u8{0x29} ** tls_stream.tls13_ticket_key_len,
    });
    defer keyring.deinit();
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
            .protocol_policy = protocol_policy,
            .alpn_protocols = &.{"http/1.1"},
            .tls12_session_tickets = if (protocol_policy == .tls12_only) .{
                .keyring = &keyring,
                .server_id = "127.0.0.1",
                .lifetime_seconds = 3600,
            } else null,
            .tls13_session_tickets = if (protocol_policy == .tls13_only) .{
                .keyring = &keyring,
                .server_id = "127.0.0.1",
                .lifetime_seconds = 3600,
            } else null,
        },
    );
    defer server.deinit();
    const Shared = struct {
        server: *runtime.TlsServer,
        resumed: [2]bool = .{ false, false },
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for (0..2) |index| {
                var connection = try self.server.accept();
                defer connection.close();
                self.resumed[index] = connection.wasTlsSessionResumed() orelse
                    return error.MissingTlsMetadata;
                var request = try connection.readRequest(.{});
                defer request.deinit(allocator);
                try connection.writeResponse(.{
                    .body = if (index == 0) "first" else "second",
                    .request_method = request.request.method,
                });
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_idle_connections = 0,
        .max_idle_per_authority = 0,
        .vail_tls = .{
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .alpn_protocols = &.{"http/1.1"},
            .protocol_policy = protocol_policy,
        },
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://127.0.0.1:{d}/ticket",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var first = try pool.requestUri(uri, .{});
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("first", first.response.body);
    var second = try pool.requestUri(uri, .{});
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("second", second.response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqualSlices(bool, &.{ false, true }, &shared.resumed);
}

test "HTTP/1 client pool resumes TLS 1.2 ticket after retirement" {
    try testTlsTicketResumptionAfterRetirement(.tls12_only);
}

test "HTTP/1 client pool resumes TLS 1.3 ticket after retirement" {
    try testTlsTicketResumptionAfterRetirement(.tls13_only);
}

test "HTTP/1 client pool discards TLS-buffered unsolicited response" {
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
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
            .limits = .{ .auto_date_header = false },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        accepts: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            {
                var connection = try self.server.accept();
                self.accepts += 1;
                defer connection.close();
                var request = try connection.readRequest(.{});
                defer request.deinit(self.server.allocator);
                try std.testing.expectEqualStrings(
                    "/first",
                    request.request.target,
                );
                // The first response is exactly one 4096-byte HTTP read. The
                // following response therefore remains in the TLS plaintext
                // buffer even though Client.inbuf is empty. writeResponses
                // coalesces both messages into one TLS application record.
                const first_body = [_]u8{'a'} ** 4055;
                try connection.writeResponses(&.{
                    .{ .body = &first_body, .request_method = request.request.method },
                    .{ .body = "ghost", .request_method = request.request.method },
                });
            }
            {
                var connection = try self.server.acceptWithTimeout(
                    .fromSeconds(2),
                );
                self.accepts += 1;
                defer connection.close();
                var request = try connection.readRequest(.{});
                defer request.deinit(self.server.allocator);
                try std.testing.expectEqualStrings(
                    "/second",
                    request.request.target,
                );
                try connection.writeResponse(.{
                    .body = "two",
                    .request_method = request.request.method,
                });
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_authority = 1,
        .tls = .{ .ca_bundle = .{
            .bundle = &ca_bundle,
            .lock = &ca_lock,
        } },
    });
    defer pool.deinit();
    const first_uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/first",
        .{server.address().ip4.port},
    );
    defer allocator.free(first_uri);
    const second_uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/second",
        .{server.address().ip4.port},
    );
    defer allocator.free(second_uri);

    var first = try pool.requestUriWithTimeout(
        first_uri,
        .{},
        .fromSeconds(2),
    );
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 4055), first.response.body.len);
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());

    var second = try pool.requestUriWithTimeout(
        second_uri,
        .{},
        .fromSeconds(2),
    );
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("two", second.response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.accepts);
}

test "HTTP/1 client pool serves concurrent leases per authority" {
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
    const request_count = 4;
    const Shared = struct {
        server: *runtime.Server,
        release: *std.Io.Event,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var group: std.Io.Group = .init;
            defer group.cancel(self.server.io);
            var errors: [request_count]?anyerror = @splat(null);
            for (&errors) |*result| {
                const accepted = try self.server.accept();
                try group.concurrent(self.server.io, struct {
                    fn serve(
                        connection_value: runtime.Connection,
                        result_ptr: *?anyerror,
                        allocator_value: std.mem.Allocator,
                        self_release: *std.Io.Event,
                        io_value: std.Io,
                    ) std.Io.Cancelable!void {
                        var connection = connection_value;
                        defer connection.close();
                        var request = connection.readRequest(.{}) catch |err| {
                            result_ptr.* = err;
                            return;
                        };
                        defer request.deinit(allocator_value);
                        connection.writeResponse(.{ .body = "parallel" }) catch |err| {
                            result_ptr.* = err;
                        };
                        self_release.wait(io_value) catch |err| {
                            result_ptr.* = err;
                        };
                    }
                }.serve, .{
                    accepted,
                    result,
                    self.server.allocator,
                    self.release,
                    self.server.io,
                });
            }
            try group.await(self.server.io);
            for (errors) |err| if (err) |value| return value;
        }
    };
    const Requester = struct {
        pool: *pool_mod.Pool,
        uri: []const u8,
        acquired_count: *std.atomic.Value(usize),
        all_acquired: *std.Io.Event,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            var lease = self.pool.acquireUri(self.uri) catch |err| {
                self.err = err;
                // Avoid stranding peers at the barrier if setup itself fails;
                // their result still cannot make the test pass.
                self.all_acquired.set(self.pool.io);
                return;
            };
            defer if (lease.active) lease.discard();
            if (self.acquired_count.fetchAdd(1, .acq_rel) + 1 == request_count) {
                self.all_acquired.set(self.pool.io);
            }
            self.all_acquired.wait(self.pool.io) catch |err| {
                self.err = err;
                return;
            };
            var response = lease.client().request(.{
                .target = "/parallel",
            }) catch |err| {
                self.err = err;
                return;
            };
            defer response.deinit(self.pool.allocator);
            if (!std.mem.eql(u8, response.response.body, "parallel")) {
                self.err = error.InvalidResponse;
                return;
            }
            lease.release();
        }
    };
    var release: std.Io.Event = .unset;
    var shared = Shared{ .server = &server, .release = &release };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        release.set(io);
        server_thread.join();
    };
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = request_count,
        .max_idle_connections = request_count,
        .max_idle_per_authority = request_count,
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, server.address(), "/parallel");
    defer allocator.free(uri);
    var acquired_count: std.atomic.Value(usize) = .init(0);
    var all_acquired: std.Io.Event = .unset;
    var requests: [request_count]Requester = undefined;
    var threads: [request_count]std.Thread = undefined;
    for (&requests, 0..) |*request, index| {
        request.* = .{
            .pool = &pool,
            .uri = uri,
            .acquired_count = &acquired_count,
            .all_acquired = &all_acquired,
        };
        threads[index] = try std.Thread.spawn(.{}, Requester.run, .{request});
    }
    for (&threads) |*thread| thread.join();
    for (requests) |request| if (request.err) |err| return err;
    try std.testing.expectEqual(request_count, pool.idleCount());
    try std.testing.expectEqual(
        request_count,
        try pool.idleCountForUri(uri),
    );

    release.set(io);
    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 client pool caps checked-out connections" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
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
        accepted: std.Io.Event = .unset,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                self.accepted.set(self.server.io);
                return;
            };
            defer connection.close();
            self.accepted.set(self.server.io);
            self.release.wait(self.server.io) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.release.set(io);
        thread.join();
    };

    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_authority = 1,
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, server.address(), "/limited");
    defer allocator.free(uri);
    var first = try pool.acquireUri(uri);
    try shared.accepted.wait(io);
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectError(
        error.ConnectionLimitReached,
        pool.acquireUri(uri),
    );

    first.release();
    first.release();
    first.discard();
    try std.testing.expect(!first.active);
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    var reused = try pool.acquireUri(uri);
    try std.testing.expect(reused.was_reused);
    reused.discard();
    reused.discard();
    reused.release();
    try std.testing.expect(!reused.active);
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());

    shared.release.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 client pool releases failed connection reservation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    const address = server.address();
    server.deinit();

    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_authority = 1,
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, address, "/unreachable");
    defer allocator.free(uri);
    try std.testing.expectError(error.ConnectionRefused, pool.acquireUri(uri));
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectError(error.ConnectionRefused, pool.acquireUri(uri));
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
}

test "HTTP/1 client pool waits for an idle lease within one deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
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
        accepted: std.Io.Event = .unset,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                self.accepted.set(self.server.io);
                return;
            };
            defer connection.close();
            self.accepted.set(self.server.io);
            self.release.wait(self.server.io) catch |err| {
                self.err = err;
            };
        }
    };
    const Waiter = struct {
        pool: *pool_mod.Pool,
        uri: []const u8,
        acquired: bool = false,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var lease = self.pool.acquireUriWithTimeout(
                self.uri,
                .fromSeconds(1),
            ) catch |err| {
                self.err = err;
                return;
            };
            self.acquired = lease.was_reused;
            lease.discard();
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var server_joined = false;
    defer if (!server_joined) {
        shared.release.set(io);
        server_thread.join();
    };
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_authority = 1,
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, server.address(), "/wait");
    defer allocator.free(uri);
    var first = try pool.acquireUri(uri);
    try shared.accepted.wait(io);
    if (shared.err) |err| return err;

    var waiter = Waiter{ .pool = &pool, .uri = uri };
    const waiter_thread = try std.Thread.spawn(.{}, Waiter.run, .{&waiter});
    try std.Io.sleep(io, .fromMilliseconds(10), .awake);
    first.release();
    waiter_thread.join();
    if (waiter.err) |err| return err;
    try std.testing.expect(waiter.acquired);
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());

    shared.release.set(io);
    server_thread.join();
    server_joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 client pool admits capacity waiters in FIFO order" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Shared = struct {
        server: *runtime.Server,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            for (0..3) |_| {
                var connection = self.server.accept() catch |err| {
                    self.err = err;
                    return;
                };
                connection.close();
            }
        }
    };
    const Waiter = struct {
        pool: *pool_mod.Pool,
        uri: []const u8,
        acquired: std.Io.Event = .unset,
        release: std.Io.Event = .unset,
        order: *std.atomic.Value(u32),
        position: u32 = 0,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            var lease = self.pool.acquireUriWithTimeout(
                self.uri,
                .fromSeconds(2),
            ) catch |err| {
                self.err = err;
                self.acquired.set(self.pool.io);
                return;
            };
            self.position = self.order.fetchAdd(1, .monotonic) + 1;
            self.acquired.set(self.pool.io);
            self.release.wait(self.pool.io) catch |err| {
                self.err = err;
            };
            lease.discard();
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var server_joined = false;
    defer if (!server_joined) server_thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 0,
        .max_idle_per_authority = 0,
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, server.address(), "/fifo");
    defer allocator.free(uri);
    var held = try pool.acquireUri(uri);

    var order: std.atomic.Value(u32) = .init(0);
    var first = Waiter{ .pool = &pool, .uri = uri, .order = &order };
    var second = Waiter{ .pool = &pool, .uri = uri, .order = &order };
    const first_thread = try std.Thread.spawn(.{}, Waiter.run, .{&first});
    var first_joined = false;
    defer if (!first_joined) {
        first.release.set(io);
        first_thread.join();
    };
    while (pool.waitingCount() != 1) {
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    const second_thread = try std.Thread.spawn(.{}, Waiter.run, .{&second});
    var second_joined = false;
    defer if (!second_joined) {
        second.release.set(io);
        second_thread.join();
    };
    while (pool.waitingCount() != 2) {
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }

    held.discard();
    try first.acquired.wait(io);
    if (first.err) |err| return err;
    try std.testing.expectEqual(@as(u32, 1), first.position);
    try std.testing.expect(!second.acquired.isSet());
    first.release.set(io);
    first_thread.join();
    first_joined = true;
    try second.acquired.wait(io);
    if (second.err) |err| return err;
    try std.testing.expectEqual(@as(u32, 2), second.position);
    second.release.set(io);
    second_thread.join();
    second_joined = true;
    try std.testing.expectEqual(@as(usize, 0), pool.waitingCount());
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());

    server_thread.join();
    server_joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 client pool acquisition timeout preserves capacity" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
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
        accepted: std.Io.Event = .unset,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                self.accepted.set(self.server.io);
                return;
            };
            defer connection.close();
            self.accepted.set(self.server.io);
            self.release.wait(self.server.io) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.release.set(io);
        server_thread.join();
    };
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_authority = 1,
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, server.address(), "/timeout");
    defer allocator.free(uri);
    var lease = try pool.acquireUri(uri);
    try shared.accepted.wait(io);
    if (shared.err) |err| return err;
    try std.testing.expectError(
        error.Timeout,
        pool.acquireUriWithTimeout(uri, .fromMilliseconds(5)),
    );
    try std.testing.expectError(
        error.Timeout,
        pool.acquireUriWithDeadline(
            uri,
            .fromNow(io, .{
                .clock = .awake,
                .raw = .fromMilliseconds(5),
            }),
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    lease.discard();
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    shared.release.set(io);
    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 pool request deadline spans capacity wait and response" {
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
        first_accepted: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.first_accepted.set(self.server.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.server.accept();
            defer first.close();
            self.first_accepted.set(self.server.io);
            var second = try self.server.accept();
            defer second.close();
            var request = try second.readRequest(.{});
            defer request.deinit(self.server.allocator);
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(150),
                .awake,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 0,
        .max_idle_per_authority = 0,
        .limits = .{ .connect_timeout = .fromSeconds(1) },
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, server.address(), "/deadline");
    defer allocator.free(uri);
    var held = try pool.acquireUri(uri);
    try shared.first_accepted.wait(io);
    if (shared.err) |err| return err;

    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromMilliseconds(60),
        .clock = .awake,
    });
    const Releaser = struct {
        io: std.Io,
        lease: *pool_mod.Lease,
        fn run(self: *@This()) void {
            std.Io.sleep(self.io, .fromMilliseconds(25), .awake) catch {};
            self.lease.discard();
        }
    };
    var releaser = Releaser{ .io = io, .lease = &held };
    const release_thread = try std.Thread.spawn(.{}, Releaser.run, .{&releaser});
    var release_joined = false;
    defer if (!release_joined) release_thread.join();
    try std.testing.expectError(
        error.Timeout,
        pool.requestUriWithDeadline(uri, .{}, deadline),
    );
    release_thread.join();
    release_joined = true;
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 pool request timeout rejects a non-positive budget" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pool = try pool_mod.Pool.init(
        std.testing.allocator,
        threaded.io(),
        .{},
    );
    defer pool.deinit();
    try std.testing.expectError(
        error.Timeout,
        pool.requestUriWithTimeout(
            "http://localhost/",
            .{},
            .zero,
        ),
    );
}

test "HTTP/1 pool deadline rejects a non-awake clock before URI parsing" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var pool = try pool_mod.Pool.init(std.testing.allocator, io, .{});
    defer pool.deinit();
    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .real },
    );

    try std.testing.expectError(
        error.Timeout,
        pool.acquireUriWithDeadline("not a URI", deadline),
    );
    try std.testing.expectError(
        error.Timeout,
        pool.requestUriWithDeadline("not a URI", .{}, deadline),
    );
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
}

test "HTTP/1 client pool close wakes blocked acquisition" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    const ServerTask = struct {
        server: *runtime.Server,
        accepted: std.Io.Event = .unset,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                self.accepted.set(self.server.io);
                return;
            };
            defer connection.close();
            self.accepted.set(self.server.io);
            self.release.wait(self.server.io) catch |err| {
                self.err = err;
            };
        }
    };
    const Waiter = struct {
        pool: *pool_mod.Pool,
        uri: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var lease = self.pool.acquireUriWithTimeout(
                self.uri,
                .fromSeconds(1),
            ) catch |err| {
                self.err = err;
                return;
            };
            lease.discard();
        }
    };

    var server_task = ServerTask{ .server = &server };
    const server_thread = try std.Thread.spawn(
        .{},
        ServerTask.run,
        .{&server_task},
    );
    var server_joined = false;
    defer if (!server_joined) {
        server_task.release.set(io);
        server_thread.join();
    };
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_authority = 1,
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, server.address(), "/closed");
    defer allocator.free(uri);
    var lease = try pool.acquireUri(uri);
    try server_task.accepted.wait(io);
    if (server_task.err) |err| return err;

    var waiter = Waiter{ .pool = &pool, .uri = uri };
    const waiter_thread = try std.Thread.spawn(.{}, Waiter.run, .{&waiter});
    try std.Io.sleep(io, .fromMilliseconds(10), .awake);
    pool.close();
    waiter_thread.join();
    try std.testing.expectEqual(error.PoolClosed, waiter.err.?);
    lease.discard();
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());

    server_task.release.set(io);
    server_thread.join();
    server_joined = true;
    if (server_task.err) |err| return err;
}

test "HTTP/1 client pool enforces per-authority idle limit" {
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
    const request_count = 3;
    const Shared = struct {
        server: *runtime.Server,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var group: std.Io.Group = .init;
            defer group.cancel(self.server.io);
            var errors: [request_count]?anyerror = @splat(null);
            for (&errors) |*result| {
                const accepted = try self.server.accept();
                try group.concurrent(self.server.io, struct {
                    fn serve(
                        connection_value: runtime.Connection,
                        result_ptr: *?anyerror,
                        allocator_value: std.mem.Allocator,
                        release: *std.Io.Event,
                        io_value: std.Io,
                    ) std.Io.Cancelable!void {
                        var connection = connection_value;
                        defer connection.close();
                        var request = connection.readRequest(.{}) catch |err| {
                            result_ptr.* = err;
                            return;
                        };
                        defer request.deinit(allocator_value);
                        connection.writeResponse(.{ .body = "bounded" }) catch |err| {
                            result_ptr.* = err;
                        };
                        release.wait(io_value) catch |err| {
                            result_ptr.* = err;
                        };
                    }
                }.serve, .{
                    accepted,
                    result,
                    self.server.allocator,
                    &self.release,
                    self.server.io,
                });
            }
            try group.await(self.server.io);
            for (errors) |err| if (err) |value| return value;
        }
    };
    const Requester = struct {
        pool: *pool_mod.Pool,
        uri: []const u8,
        acquired_count: *std.atomic.Value(usize),
        all_acquired: *std.Io.Event,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            var lease = self.pool.acquireUriWithTimeout(
                self.uri,
                .fromSeconds(5),
            ) catch |err| {
                self.err = err;
                self.all_acquired.set(self.pool.io);
                return;
            };
            defer if (lease.active) lease.discard();
            if (self.acquired_count.fetchAdd(1, .acq_rel) + 1 == request_count) {
                self.all_acquired.set(self.pool.io);
            }
            self.all_acquired.waitTimeout(self.pool.io, .{ .duration = .{
                .raw = .fromSeconds(5),
                .clock = .awake,
            } }) catch |err| {
                self.err = err;
                return;
            };
            var response = lease.client().requestWithTimeout(
                .{ .target = "/bounded" },
                .fromSeconds(5),
            ) catch |err| {
                self.err = err;
                return;
            };
            response.deinit(self.pool.allocator);
            lease.release();
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.release.set(io);
        const listener_stream: std.Io.net.Stream = .{
            .socket = server.listener.socket,
        };
        listener_stream.shutdown(io, .both) catch {};
        server_thread.join();
    };
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_idle_connections = request_count,
        .max_idle_per_authority = 1,
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, server.address(), "/bounded");
    defer allocator.free(uri);
    var acquired_count: std.atomic.Value(usize) = .init(0);
    var all_acquired: std.Io.Event = .unset;
    var requests: [request_count]Requester = undefined;
    var threads: [request_count]std.Thread = undefined;
    for (&requests, 0..) |*request, index| {
        request.* = .{
            .pool = &pool,
            .uri = uri,
            .acquired_count = &acquired_count,
            .all_acquired = &all_acquired,
        };
        threads[index] = try std.Thread.spawn(.{}, Requester.run, .{request});
    }
    for (&threads) |*thread| thread.join();
    for (requests) |request| if (request.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(
        @as(usize, 1),
        try pool.idleCountForUri(uri),
    );

    shared.release.set(io);
    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 client pool zero idle capacity disables reuse" {
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
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            for (0..2) |_| {
                var connection = try self.server.accept();
                defer connection.close();
                var request = try connection.readRequest(.{});
                defer request.deinit(self.server.allocator);
                try connection.writeResponse(.{ .body = "fresh" });
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_idle_connections = 0,
        .max_idle_per_authority = 0,
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, server.address(), "/fresh");
    defer allocator.free(uri);
    for (0..2) |_| {
        var response = try pool.requestUri(uri, .{});
        response.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 client pool expires idle connections" {
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
        release: std.Io.Event = .unset,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(self.server.allocator);
            try connection.writeResponse(.{ .body = "idle" });
            try self.release.wait(self.server.io);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.release.set(io);
        thread.join();
    };
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .idle_timeout = .fromMilliseconds(20),
    });
    defer pool.deinit();
    const uri = try uriFor(allocator, server.address(), "/idle");
    defer allocator.free(uri);
    var response = try pool.requestUri(uri, .{});
    response.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.Io.sleep(io, .fromMilliseconds(30), .awake);
    try std.testing.expectEqual(@as(usize, 1), pool.pruneExpired());
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());

    shared.release.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 client pool replaces an idle authority at total capacity" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var first_server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer first_server.deinit();
    var second_server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer second_server.deinit();
    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(self.server.allocator);
            try connection.writeResponse(.{ .body = "ok" });
            // Give the pool time to evict and close the older idle socket.
            var byte: [1]u8 = undefined;
            const tcp = connection.stream;
            var bufs = [_][]u8{&byte};
            const count = try self.server.io.vtable.netRead(
                self.server.io.userdata,
                tcp.socket.handle,
                &bufs,
            );
            try std.testing.expectEqual(@as(usize, 0), count);
        }
    };
    const Once = struct {
        server: *runtime.Server,
        release: *std.Io.Event,
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
            defer request.deinit(self.server.allocator);
            connection.writeResponse(.{ .body = "ok" }) catch |err| {
                self.err = err;
            };
            self.release.wait(self.server.io) catch |err| {
                self.err = err;
            };
        }
    };
    var first_shared = Shared{ .server = &first_server };
    var second_release: std.Io.Event = .unset;
    var second_shared = Once{
        .server = &second_server,
        .release = &second_release,
    };
    const first_thread = try std.Thread.spawn(.{}, Shared.run, .{&first_shared});
    const second_thread = try std.Thread.spawn(.{}, Once.run, .{&second_shared});
    var first_joined = false;
    var second_joined = false;
    defer if (!first_joined) first_thread.join();
    defer if (!second_joined) {
        second_release.set(io);
        second_thread.join();
    };
    var pool = try pool_mod.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_authority = 1,
        .idle_timeout = null,
    });
    defer pool.deinit();
    const first_uri = try uriFor(allocator, first_server.address(), "/one");
    defer allocator.free(first_uri);
    const second_uri = try uriFor(allocator, second_server.address(), "/two");
    defer allocator.free(second_uri);
    var first = try pool.requestUri(first_uri, .{});
    first.deinit(allocator);
    var second = try pool.requestUri(second_uri, .{});
    second.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(
        @as(usize, 0),
        try pool.idleCountForUri(first_uri),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        try pool.idleCountForUri(second_uri),
    );

    second_release.set(io);
    first_thread.join();
    first_joined = true;
    second_thread.join();
    second_joined = true;
    if (first_shared.err) |err| return err;
    if (second_shared.err) |err| return err;
}
