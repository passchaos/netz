const std = @import("std");
const http1 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const tls_testing = @import("../../tls/testing.zig");

const Api = enum {
    accept_stream,
    serve_one,
    serve_connection,
};

test "HTTP/1 TLS listener accept deadline expires without a client" {
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
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{
                .key_pair = key_pair,
            } },
        } },
    );
    defer server.deinit();

    try std.testing.expectError(
        error.Timeout,
        server.acceptWithTimeout(.fromMilliseconds(20)),
    );
}

fn exerciseTlsServerApi(api: Api) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{
                .key_pair = key_pair,
            } },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        api: Api,
        handled: usize = 0,
        served: usize = 0,
        err: ?anyerror = null,

        fn handle(
            self: *@This(),
            request: http1.Request,
        ) runtime.Error!runtime.ResponseOptions {
            const expected = if (self.handled == 0) "/one" else "/two";
            if (!std.mem.eql(u8, request.target, expected)) {
                return error.InvalidResponse;
            }
            self.handled += 1;
            return .{ .body = if (self.handled == 1) "first" else "second" };
        }

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            switch (self.api) {
                .accept_stream => {
                    const stream = try self.server.listener.accept(
                        self.server.io,
                    );
                    var connection = try self.server.acceptStream(stream);
                    defer connection.close();
                    self.served = try connection.serve(
                        self,
                        @This().handle,
                        1,
                    );
                },
                .serve_one => {
                    try self.server.serveOne(self, @This().handle);
                    self.served = 1;
                },
                .serve_connection => {
                    self.served = try self.server.serveConnection(
                        self,
                        @This().handle,
                        2,
                    );
                },
            }
        }
    };

    var shared = Shared{ .server = &server, .api = api };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connectVailTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{},
        .{ .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        } },
    );
    defer client.close();

    var first = try client.request(.{ .target = "/one" });
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("first", first.response.body);
    if (api == .serve_connection) {
        var second = try client.request(.{ .target = "/two" });
        defer second.deinit(allocator);
        try std.testing.expectEqualStrings("second", second.response.body);
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    const expected: usize = if (api == .serve_connection) 2 else 1;
    try std.testing.expectEqual(expected, shared.served);
    try std.testing.expectEqual(expected, shared.handled);
}

test "HTTP/1 TLS server adopts an accepted stream" {
    try exerciseTlsServerApi(.accept_stream);
}

test "HTTP/1 TLS server serves one request" {
    try exerciseTlsServerApi(.serve_one);
}

test "HTTP/1 TLS server serves a persistent connection" {
    try exerciseTlsServerApi(.serve_connection);
}

const alpn_server = @import("../../tls/alpn_server.zig");

const AlpnTestServer = struct {
    server: *alpn_server.Server,
    expected_body: []const u8 = "alpn-http1",
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.runFallible() catch |err| {
            self.err = err;
        };
    }

    fn runFallible(self: *@This()) !void {
        const accepted = try self.server.acceptWithTimeout(.fromSeconds(5));
        var connection = try runtime.adoptNegotiatedTlsServer(
            std.testing.allocator,
            self.server.io,
            accepted.stream,
            accepted.tls,
            .{},
        );
        defer connection.close();
        try std.testing.expectEqualStrings(
            "http/1.1",
            connection.negotiatedAlpn().?,
        );
        try std.testing.expect(connection.peerAddress().getPort() != 0);

        var request = try connection.readRequest(.{});
        defer request.deinit(std.testing.allocator);
        try std.testing.expect(request.request.from != null);
        try std.testing.expect(request.request.from.?.getPort() != 0);
        try connection.writeResponse(.{
            .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
            .body = self.expected_body,
            .request_method = request.request.method,
        });
    }
};

fn listenAlpnTestServer(
    allocator: std.mem.Allocator,
    io: std.Io,
    key_pair: anytype,
    certificate_chain: []const []const u8,
) !alpn_server.Server {
    return alpn_server.Server.listen(allocator, io, .{
        .address = .{ .ip4 = .loopback(0) },
        .tls = .{
            .identity = .{
                .certificate_chain = certificate_chain,
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair.* } },
            },
            .alpn_protocols = &.{ "h2", "http/1.1" },
        },
    });
}

test "HTTP/1 adopts an ALPN-negotiated TLS server connection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
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

    var server = try listenAlpnTestServer(
        allocator,
        io,
        &key_pair,
        &certificate_chain,
    );
    defer server.deinit();

    var shared = AlpnTestServer{ .server = &server };
    const thread = try std.Thread.spawn(.{}, AlpnTestServer.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connectVailTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{},
        .{
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .alpn_protocols = &.{"http/1.1"},
        },
    );
    defer client.close();

    var response = try client.request(.{ .target = "/alpn" });
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("alpn-http1", response.response.body);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/1 ALPN adoption fails closed for a negotiated h2 connection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
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

    var server = try listenAlpnTestServer(
        allocator,
        io,
        &key_pair,
        &certificate_chain,
    );
    defer server.deinit();

    const Reject = struct {
        server: *alpn_server.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const accepted = try self.server.acceptWithTimeout(.fromSeconds(5));
            var connection = runtime.adoptNegotiatedTlsServer(
                std.testing.allocator,
                self.server.io,
                accepted.stream,
                accepted.tls,
                .{},
            ) catch |err| {
                self.err = err;
                return;
            };
            connection.close();
            self.err = error.ExpectedInvalidAlpn;
        }
    };

    var shared = Reject{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Reject.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    // The handshake itself succeeds; the client rejects the negotiated `h2`
    // protocol for an HTTP/1 client, while the server adoption rejects it for
    // an HTTP/1 server. Both sides fail closed without serving any request.
    try std.testing.expectError(
        error.InvalidAlpn,
        runtime.Client.connectVailTlsHost(
            allocator,
            io,
            "localhost",
            server.address().ip4.port,
            .{},
            .{
                .server_verifier = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                },
                .alpn_protocols = &.{"h2"},
            },
        ),
    );

    thread.join();
    joined = true;
    const observed = shared.err orelse return error.ExpectedInvalidAlpn;
    try std.testing.expectEqual(error.InvalidAlpn, observed);
}

test "HTTP/1 TLS listener rejects non-HTTP/1.1 ALPN offers" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const certificate_chain = [_][]const u8{&certificate_der};

    try std.testing.expectError(
        error.InvalidAlpn,
        runtime.TlsServer.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{
                .identity = .{
                    .certificate_chain = &certificate_chain,
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
                .alpn_protocols = &.{ "h2", "http/1.1" },
            },
        ),
    );

    // The HTTP/1.1-only list is the valid configuration.
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &certificate_chain,
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .alpn_protocols = &.{"http/1.1"},
        },
    );
    server.deinit();
}

test "HTTP/1 client without ALPN is rejected by an ALPN dispatcher" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
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

    var server = try listenAlpnTestServer(
        allocator,
        io,
        &key_pair,
        &certificate_chain,
    );
    defer server.deinit();

    const Acceptor = struct {
        server: *alpn_server.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            const accepted = self.server.acceptWithTimeout(
                .fromSeconds(5),
            ) catch |err| {
                self.err = err;
                return;
            };
            accepted.tls.deinit();
        }
    };

    var acceptor = Acceptor{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Acceptor.run, .{&acceptor});
    var joined = false;
    defer if (!joined) thread.join();

    // The default client list is empty, so the dispatcher has no shared
    // protocol and rejects the handshake.
    if (runtime.Client.connectVailTlsHost(
        allocator,
        io,
        "localhost",
        server.address().ip4.port,
        .{},
        .{ .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        } },
    )) |client_value| {
        var client = client_value;
        client.close();
        return error.ExpectedAlpnRejection;
    } else |_| {}

    thread.join();
    joined = true;
    try std.testing.expect(acceptor.err != null);
}
