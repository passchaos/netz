const std = @import("std");
const runtime = @import("../runtime.zig");
const tls_stream = @import("../../tls/mod.zig").stream;
const tls_testing = @import("../../tls/testing.zig");

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
test "WebSocket server handshake timeout is absolute across trickled bytes" {
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
        .{ .http1_handshake_timeout = .fromMilliseconds(150) },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        read_started: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.read_started.set(self.server.http.io);
            var connection = self.server.accept(.{}) catch |err| {
                self.err = err;
                return;
            };
            connection.close();
            self.err = error.TestUnexpectedResult;
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
    writeAll(io, client, "\r\n") catch |err| switch (err) {
        error.SocketUnconnected, error.ConnectionResetByPeer => {},
        else => return err,
    };

    thread.join();
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "WebSocket server caller timeout bounds the HTTP upgrade" {
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
        .{ .http1_handshake_timeout = .fromSeconds(1) },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.acceptWithTimeout(
                .{},
                .fromMilliseconds(50),
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
    try writeAll(
        io,
        client,
        "GET / HTTP/1.1\r\nHost: localhost\r\n",
    );

    thread.join();
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "WebSocket accepted HTTP connection timeout bounds Upgrade" {
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
        .{ .http1_handshake_timeout = .fromSeconds(1) },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            const http_connection = self.server.http.accept() catch |err| {
                self.err = err;
                return;
            };
            var connection = self.server.acceptHttpConnectionWithTimeout(
                http_connection,
                .{},
                .fromMilliseconds(40),
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
    try writeAll(io, client, "GET / HTTP/1.1\r\nHost: localhost\r\n");

    thread.join();
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "WebSocket client bounds an idle HTTP upgrade response" {
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
        io: std.Io,
        listener: *net.Server,

        fn run(self: *@This()) void {
            const stream = self.listener.accept(self.io) catch return;
            defer stream.close(self.io);
            std.Io.sleep(self.io, .fromMilliseconds(250), .awake) catch {};
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connect(
            allocator,
            io,
            listener.socket.address,
            .{
                .host = "localhost",
                .limits = .{
                    .http1_handshake_timeout = .fromMilliseconds(75),
                },
            },
        ),
    );
    thread.join();
}
test "WebSocket client connect timeout is independent from upgrade timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    // A ready listener proves enabling the connect budget does not consume or
    // replace the separate HTTP Upgrade response budget. The peer accepts the
    // TCP connection, then deliberately remains silent through that budget.
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        fn run(self: *@This()) void {
            const stream = self.listener.accept(self.io) catch return;
            defer stream.close(self.io);
            std.Io.sleep(self.io, .fromMilliseconds(250), .awake) catch {};
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connect(
            allocator,
            io,
            listener.socket.address,
            .{
                .host = "localhost",
                .connect_timeout = .fromSeconds(1),
                .limits = .{
                    .http1_handshake_timeout = .fromMilliseconds(20),
                },
            },
        ),
    );
    thread.join();
}

test "WebSocket caller deadline spans TCP setup and HTTP upgrade" {
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
        io: std.Io,
        listener: *net.Server,

        fn run(self: *@This()) void {
            const stream = self.listener.accept(self.io) catch return;
            defer stream.close(self.io);
            std.Io.sleep(self.io, .fromMilliseconds(150), .awake) catch {};
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connectWithDeadline(
            allocator,
            io,
            listener.socket.address,
            .{
                .host = "localhost",
                .connect_timeout = .fromSeconds(1),
                .limits = .{
                    .http1_handshake_timeout = .fromSeconds(1),
                },
            },
            .fromNow(io, .{
                .raw = .fromMilliseconds(20),
                .clock = .awake,
            }),
        ),
    );
    thread.join();
    joined = true;
}

test "WebSocket caller deadline retains shorter connect timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connectWithDeadline(
            allocator,
            io,
            .{ .ip4 = .loopback(1) },
            .{
                .host = "localhost",
                .connect_timeout = .zero,
            },
            .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
        ),
    );
}

test "WebSocket caller timeout rejects a non-positive budget" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connectWithTimeout(
            std.testing.allocator,
            threaded.io(),
            .{ .ip4 = .loopback(1) },
            .{ .host = "localhost" },
            .zero,
        ),
    );
}

test "WebSocket client rejects non-positive connect timeout before dialing" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connect(
            allocator,
            io,
            .{ .ip4 = .loopback(1) },
            .{
                .host = "localhost",
                .connect_timeout = .zero,
            },
        ),
    );
}

test "WSS server bounds the decrypted HTTP upgrade request" {
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
                .http1_handshake_timeout = .fromMilliseconds(75),
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept(.{}) catch |err| {
                self.err = err;
                return;
            };
            connection.close();
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const stream = try server.address().connect(io, .{ .mode = .stream });
    var stream_owned = true;
    defer if (stream_owned) stream.close(io);
    const client = try tls_stream.ClientConnection.init(
        allocator,
        io,
        stream,
        .{
            .server_name = "localhost",
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
        },
    );
    stream_owned = false;
    defer client.deinit();
    try client.writeAll("GET / HTTP/1.1\r\n");

    thread.join();
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "WSS listener bounds an idle TLS handshake" {
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
            var connection = self.server.accept(.{}) catch |err| {
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

test "WSS server caller timeout bounds TLS and HTTP upgrade" {
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
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .tls_handshake_timeout = .fromSeconds(1),
            .limits = .{
                .http1_handshake_timeout = .fromSeconds(1),
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.acceptWithTimeout(
                .{},
                .fromMilliseconds(50),
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
    var joined = false;
    defer if (!joined) thread.join();
    const stream = try server.address().connect(io, .{ .mode = .stream });
    var stream_owned = true;
    defer if (stream_owned) stream.close(io);
    const client = try tls_stream.ClientConnection.init(
        allocator,
        io,
        stream,
        .{
            .server_name = "localhost",
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = key_pair.public_key.toUncompressedSec1(),
            },
        },
    );
    stream_owned = false;
    defer client.deinit();
    // Leave the HTTP Upgrade incomplete after TLS has consumed part of the
    // same caller-owned budget. The HTTP phase must not receive a fresh one.
    try std.Io.sleep(io, .fromMilliseconds(25), .awake);
    client.writeAll("GET / HTTP/1.1\r\nHost: localhost\r\n") catch |err| switch (err) {
        // The server may consume the shared TLS + HTTP deadline and close the
        // connection before this deliberately late, incomplete Upgrade write.
        error.SocketUnconnected, error.ConnectionResetByPeer => {},
        else => return err,
    };

    thread.join();
    joined = true;
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "WSS accepted stream timeout bounds TLS handshake" {
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
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .tls_handshake_timeout = .fromSeconds(1),
            .limits = .{
                .http1_handshake_timeout = .fromSeconds(1),
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            const stream = self.server.listener.accept(self.server.io) catch |err|
                {
                    self.err = err;
                    return;
                };
            var connection = self.server.acceptStreamWithTimeout(
                stream,
                .{},
                .fromMilliseconds(40),
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

test "WSS vail client bounds an idle TLS handshake" {
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
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();

    const Shared = struct {
        io: std.Io,
        listener: *net.Server,

        fn run(self: *@This()) void {
            const stream = self.listener.accept(self.io) catch return;
            defer stream.close(self.io);
            std.Io.sleep(
                self.io,
                .fromMilliseconds(250),
                .awake,
            ) catch {};
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connectTlsHost(
            allocator,
            io,
            "127.0.0.1",
            listener.socket.address.ip4.port,
            .{ .tls_identity = .{
                .identity = .{
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
                .server_verifier = .{},
                .handshake_timeout = .fromMilliseconds(75),
            } },
            .{},
        ),
    );
    thread.join();
    joined = true;
}

test "WSS standard client bounds an idle TLS handshake" {
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
        io: std.Io,
        listener: *net.Server,
        fn run(self: *@This()) void {
            const stream = self.listener.accept(self.io) catch return;
            defer stream.close(self.io);
            std.Io.sleep(self.io, .fromMilliseconds(250), .awake) catch {};
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connectTlsHost(
            allocator,
            io,
            "127.0.0.1",
            listener.socket.address.ip4.port,
            .{},
            .{
                .verify_host = false,
                .handshake_timeout = .fromMilliseconds(20),
            },
        ),
    );
    thread.join();
}

test "WSS caller deadline bounds TLS handshake" {
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
        io: std.Io,
        listener: *net.Server,
        fn run(self: *@This()) void {
            const stream = self.listener.accept(self.io) catch return;
            defer stream.close(self.io);
            std.Io.sleep(self.io, .fromMilliseconds(150), .awake) catch {};
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connectTlsAddressWithDeadline(
            allocator,
            io,
            listener.socket.address,
            "localhost",
            .{
                .connect_timeout = .fromSeconds(1),
                .tls_handshake_timeout = .fromSeconds(1),
                .limits = .{
                    .http1_handshake_timeout = .fromSeconds(1),
                },
            },
            .{ .verify_host = false },
            .fromNow(io, .{
                .raw = .fromMilliseconds(20),
                .clock = .awake,
            }),
        ),
    );
    thread.join();
    joined = true;
}

test "WSS connect options forward TLS timeout to standard client" {
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
        io: std.Io,
        listener: *net.Server,
        fn run(self: *@This()) void {
            const stream = self.listener.accept(self.io) catch return;
            defer stream.close(self.io);
            std.Io.sleep(self.io, .fromMilliseconds(250), .awake) catch {};
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const uri = try std.fmt.allocPrint(
        allocator,
        "wss://127.0.0.1:{d}/timeout",
        .{listener.socket.address.ip4.port},
    );
    defer allocator.free(uri);
    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connectUriTls(
            allocator,
            io,
            uri,
            .{ .tls_handshake_timeout = .fromMilliseconds(20) },
            .{ .verify_host = false },
        ),
    );
    thread.join();
}
