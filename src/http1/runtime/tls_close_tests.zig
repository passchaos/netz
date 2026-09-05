const std = @import("std");
const http1 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const tls_stream = @import("../../tls/mod.zig").stream;
const tls_testing = @import("../../tls/testing.zig");

const net = std.Io.net;
const KeyPair = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair;

fn serverOptions(
    certificate_chain: []const []const u8,
    key_pair: KeyPair,
) tls_stream.ServerOptions {
    return .{
        .identity = .{
            .certificate_chain = certificate_chain,
            .signer = .{ .ecdsa_p256_sha256 = .{
                .key_pair = key_pair,
            } },
        },
    };
}

fn clientOptions(public_key: [65]u8) tls_stream.ClientOptions {
    return .{
        .server_name = "localhost",
        .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        },
    };
}

fn readRequestHead(connection: *tls_stream.ServerConnection) !void {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    var scratch: [256]u8 = undefined;
    while (std.mem.indexOf(u8, bytes.items, "\r\n\r\n") == null) {
        const count = try connection.read(&scratch);
        if (count == 0) return error.ConnectionClosed;
        try bytes.appendSlice(std.testing.allocator, scratch[0..count]);
        if (bytes.items.len > 4096) return error.HeadersTooLarge;
    }
}

test "HTTP/1 TLS serve retires after authenticated client close notify" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const certificate_chain = [_][]const u8{&certificate_der};
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = serverOptions(&certificate_chain, key_pair).identity },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        served: usize = 0,
        handled: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            self.served = try connection.serve(self, handle, 4);
        }

        fn handle(
            self: *@This(),
            request: http1.Request,
        ) runtime.Error!runtime.ResponseOptions {
            self.handled += 1;
            if (!std.mem.eql(u8, request.target, "/clean-close")) {
                return error.InvalidResponse;
            }
            return .{ .body = "complete" };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    const stream = try server.address().connect(io, .{ .mode = .stream });
    var stream_owned = true;
    defer if (stream_owned) stream.close(io);
    const client = try tls_stream.ClientConnection.init(
        allocator,
        io,
        stream,
        clientOptions(public_key),
    );
    stream_owned = false;
    defer client.deinit();
    try client.writeAll(
        "GET /clean-close HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    try client.sendCloseNotify();

    var response: std.ArrayList(u8) = .empty;
    defer response.deinit(allocator);
    var scratch: [512]u8 = undefined;
    while (true) {
        const count = try client.read(&scratch);
        if (count == 0) break;
        try response.appendSlice(allocator, scratch[0..count]);
    }
    try std.testing.expect(
        std.mem.indexOf(u8, response.items, "\r\n\r\ncomplete") != null,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), shared.served);
    try std.testing.expectEqual(@as(usize, 1), shared.handled);
}

fn expectTlsServeRejectsTruncatedRequest(request: []const u8) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const certificate_chain = [_][]const u8{&certificate_der};
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = serverOptions(&certificate_chain, key_pair).identity },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        handled: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            _ = connection.serve(self, handle, 4) catch |err| {
                self.err = err;
                return;
            };
        }

        fn handle(
            self: *@This(),
            _: http1.Request,
        ) runtime.Error!runtime.ResponseOptions {
            self.handled += 1;
            return .{};
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    const stream = try server.address().connect(io, .{ .mode = .stream });
    var stream_owned = true;
    defer if (stream_owned) stream.close(io);
    const client = try tls_stream.ClientConnection.init(
        allocator,
        io,
        stream,
        clientOptions(public_key),
    );
    stream_owned = false;
    defer client.deinit();
    try client.writeAll(request);
    try client.sendCloseNotify();
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), try client.read(&byte));

    thread.join();
    joined = true;
    try std.testing.expectEqual(@as(usize, 0), shared.handled);
    try std.testing.expectEqual(error.ConnectionClosed, shared.err.?);
}

test "HTTP/1 TLS serve rejects request truncation before close notify" {
    const cases = [_]struct { name: []const u8, request: []const u8 }{
        .{
            .name = "head",
            .request = "GET /partial HTTP/1.1\r\nHost: local",
        },
        .{
            .name = "fixed body",
            .request = "POST /fixed HTTP/1.1\r\n" ++
                "Host: localhost\r\nContent-Length: 5\r\n\r\nabc",
        },
        .{
            .name = "chunked body",
            .request = "POST /chunked HTTP/1.1\r\n" ++
                "Host: localhost\r\nTransfer-Encoding: chunked\r\n\r\n" ++
                "3\r\nabc\r\n",
        },
    };
    for (cases) |case| {
        errdefer std.log.err(
            "TLS request truncation case failed: {s}",
            .{case.name},
        );
        try expectTlsServeRejectsTruncatedRequest(case.request);
    }
}

test "HTTP/1 TLS serve permits raw EOF only at an empty request boundary" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const certificate_chain = [_][]const u8{&certificate_der};
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = serverOptions(&certificate_chain, key_pair).identity },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        served: usize = 1,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            self.served = connection.serve(self, handle, 4) catch |err| {
                self.err = err;
                return;
            };
        }

        fn handle(
            _: *@This(),
            _: http1.Request,
        ) runtime.Error!runtime.ResponseOptions {
            return error.InvalidResponse;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    const stream = try server.address().connect(io, .{ .mode = .stream });
    var stream_owned = true;
    defer if (stream_owned) stream.close(io);
    const client = try tls_stream.ClientConnection.init(
        allocator,
        io,
        stream,
        clientOptions(public_key),
    );
    stream_owned = false;
    defer client.deinit();
    try stream.shutdown(io, .send);

    var byte: [1]u8 = undefined;
    // The server may retire an idle HTTP connection and still sends its own
    // close_notify. TLS half-close state must not suppress that reply.
    try std.testing.expectEqual(@as(usize, 0), try client.read(&byte));
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 0), shared.served);
}

test "HTTP/1 TLS serve never hides a truncated TLS record at an empty boundary" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const certificate_chain = [_][]const u8{&certificate_der};
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = serverOptions(&certificate_chain, key_pair).identity },
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
            _ = connection.serve(self, handle, 4) catch |err| {
                self.err = err;
                return;
            };
        }

        fn handle(
            _: *@This(),
            _: http1.Request,
        ) runtime.Error!runtime.ResponseOptions {
            return error.InvalidResponse;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    const stream = try server.address().connect(io, .{ .mode = .stream });
    var stream_owned = true;
    defer if (stream_owned) stream.close(io);
    const client = try tls_stream.ClientConnection.init(
        allocator,
        io,
        stream,
        clientOptions(public_key),
    );
    stream_owned = false;
    defer client.deinit();

    // Begin a TLSCiphertext header and then close before its remaining header
    // and authenticated payload. No HTTP plaintext has reached the server.
    const written = try io.vtable.netWrite(
        io.userdata,
        stream.socket.handle,
        &.{0x17},
        &.{""},
        0,
    );
    try std.testing.expectEqual(@as(usize, 1), written);
    try stream.shutdown(io, .send);

    var byte: [1]u8 = undefined;
    try std.testing.expectError(error.UnexpectedEof, client.read(&byte));
    thread.join();
    joined = true;
    try std.testing.expectEqual(error.TruncatedRecord, shared.err.?);
}

test "HTTP/1 close-delimited HTTPS body requires close notify" {
    const Case = struct {
        clean: bool,
        expected_error: ?anyerror,
    };
    const cases = [_]Case{
        .{ .clean = true, .expected_error = null },
        .{ .clean = false, .expected_error = error.UnexpectedEof },
    };
    for (cases) |case| {
        const allocator = std.testing.allocator;
        var threaded = std.Io.Threaded.init(allocator, .{
            .async_limit = .unlimited,
        });
        defer threaded.deinit();
        const io = threaded.io();
        var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
        try std.base64.standard.Decoder.decode(
            &certificate_der,
            tls_testing.certificate_base64,
        );
        const key_pair = try tls_testing.serverKeyPair();
        const public_key = key_pair.public_key.toUncompressedSec1();
        var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
            io,
            .{ .reuse_address = true },
        );
        defer listener.deinit(io);

        const Shared = struct {
            listener: *net.Server,
            io: std.Io,
            certificate: []const u8,
            key_pair: KeyPair,
            clean: bool,
            err: ?anyerror = null,

            fn run(self: *@This()) void {
                self.runFallible() catch |err| {
                    self.err = err;
                };
            }

            fn runFallible(self: *@This()) !void {
                const stream = try self.listener.accept(self.io);
                var stream_owned = true;
                defer if (stream_owned) stream.close(self.io);
                const certificate_chain = [_][]const u8{self.certificate};
                const connection = try tls_stream.ServerConnection.init(
                    std.testing.allocator,
                    self.io,
                    stream,
                    serverOptions(&certificate_chain, self.key_pair),
                );
                stream_owned = false;
                defer connection.deinit();
                try readRequestHead(connection);
                try connection.writeAll(
                    "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\ncomplete",
                );
                if (self.clean) {
                    try connection.sendCloseNotify();
                } else {
                    try stream.shutdown(self.io, .send);
                }
            }
        };

        var shared = Shared{
            .listener = &listener,
            .io = io,
            .certificate = &certificate_der,
            .key_pair = key_pair,
            .clean = case.clean,
        };
        const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
        var joined = false;
        defer if (!joined) thread.join();
        var client = try runtime.Client.connectVailTlsHost(
            allocator,
            io,
            "localhost",
            listener.socket.address.ip4.port,
            .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
            .{ .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            } },
        );
        defer client.close();
        const result = client.request(.{ .target = "/body" });
        if (case.expected_error) |expected| {
            try std.testing.expectError(expected, result);
        } else {
            var response = try result;
            defer response.deinit(allocator);
            try std.testing.expectEqualStrings(
                "complete",
                response.response.body,
            );
        }

        thread.join();
        joined = true;
        if (shared.err) |err| return err;
    }
}
