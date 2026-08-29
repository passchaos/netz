const std = @import("std");
const vail = @import("vail");
const client = @import("client_connection.zig");
const server = @import("server_connection.zig");
const tls_testing = @import("../testing.zig");

const net = std.Io.net;

const Identity = struct {
    certificate: [tls_testing.certificate_der_len]u8,
    key_pair: std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair,

    fn init() !Identity {
        var certificate: [tls_testing.certificate_der_len]u8 = undefined;
        try std.base64.standard.Decoder.decode(
            &certificate,
            tls_testing.certificate_base64,
        );
        return .{
            .certificate = certificate,
            .key_pair = try tls_testing.serverKeyPair(),
        };
    }

    fn options(
        self: *const Identity,
        timeout: std.Io.Duration,
    ) server.Options {
        return .{
            .identity = .{
                .certificate_chain = &.{&self.certificate},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = self.key_pair,
                } },
            },
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .handshake_timeout = timeout,
        };
    }
};

fn connect(io: std.Io, listener: *net.Server) !net.Stream {
    return listener.socket.address.connect(io, .{ .mode = .stream });
}

fn closeAfterDelay(
    io: std.Io,
    stream: net.Stream,
    delay: std.Io.Duration,
) void {
    std.Io.sleep(io, delay, .awake) catch {};
    stream.close(io);
}

fn writeAll(io: std.Io, stream: net.Stream, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const count = try io.vtable.netWrite(
            io.userdata,
            stream.socket.handle,
            bytes[offset..],
            &.{""},
            0,
        );
        if (count == 0) return error.SocketUnconnected;
        offset += count;
    }
}

fn writeClientHello(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
) !void {
    var secret = [_]u8{0x42} ** vail.tls.key_exchange.secret_len;
    defer std.crypto.secureZero(u8, &secret);
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
    const public_key = try vail.tls.key_exchange.publicKey(secret);
    var message: std.ArrayList(u8) = .empty;
    defer message.deinit(allocator);
    try vail.tls.client_hello.write(&message, allocator, .{
        .random = [_]u8{0x11} ** 32,
        .session_id = &([_]u8{0x22} ** 32),
        .server_name = "localhost",
        .x25519_public_key = public_key,
        .cipher_suites = &.{.aes_128_gcm_sha256},
    });
    var header = [_]u8{
        vail.tls.record.content_type_handshake,
        0x03,
        0x01,
        0,
        0,
    };
    std.mem.writeInt(u16, header[3..5], @intCast(message.items.len), .big);
    try writeAll(io, stream, &header);
    try writeAll(io, stream, message.items);
}

test "TLS server handshake times out while waiting for ClientHello" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var identity = try Identity.init();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        identity: *const Identity,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            const stream = self.listener.accept(self.io) catch |err| {
                self.err = err;
                return;
            };
            defer stream.close(self.io);
            const certificate_chain = [_][]const u8{
                &self.identity.certificate,
            };
            var options = self.identity.options(.fromMilliseconds(75));
            options.identity.certificate_chain = &certificate_chain;
            const result = server.Connection.init(
                allocator,
                self.io,
                stream,
                options,
            );
            if (result) |connection| {
                connection.deinit();
                self.err = error.TestUnexpectedResult;
            } else |err| self.err = err;
        }
    };
    var shared = Shared{
        .io = io,
        .listener = &listener,
        .identity = &identity,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const peer = try connect(io, &listener);
    defer peer.close(io);
    thread.join();
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "TLS client handshake times out while waiting for ServerHello" {
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
            closeAfterDelay(
                self.io,
                stream,
                .fromMilliseconds(250),
            );
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var stream = try connect(io, &listener);
    defer stream.close(io);
    var joined = false;
    defer if (!joined) thread.join();
    try std.testing.expectError(
        error.Timeout,
        client.Connection.init(allocator, io, stream, .{
            .server_name = "localhost",
            // This verifier cannot be reached while the peer remains silent.
            .server_verifier = .{},
            .handshake_timeout = .fromMilliseconds(75),
        }),
    );
    thread.join();
    joined = true;
}

test "TLS client absolute deadline bounds the complete handshake" {
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
            closeAfterDelay(self.io, stream, .fromMilliseconds(250));
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    const stream = try connect(io, &listener);
    defer stream.close(io);

    try std.testing.expectError(
        error.Timeout,
        client.Connection.initWithDeadline(
            allocator,
            io,
            stream,
            .{
                .server_name = "localhost",
                .server_verifier = .{},
                .handshake_timeout = .fromSeconds(1),
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

test "TLS server absolute deadline bounds the complete handshake" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var identity = try Identity.init();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        identity: *const Identity,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            const stream = self.listener.accept(self.io) catch |err| {
                self.err = err;
                return;
            };
            defer stream.close(self.io);
            const certificate_chain = [_][]const u8{
                &self.identity.certificate,
            };
            var options = self.identity.options(.fromSeconds(1));
            // `Identity.options` is a convenience for immediate calls. Keep
            // this backing slice in the worker frame because the deadline
            // path adds another synchronous helper layer before validation.
            options.identity.certificate_chain = &certificate_chain;
            const connection = server.Connection.initWithDeadline(
                allocator,
                self.io,
                stream,
                options,
                .fromNow(self.io, .{
                    .raw = .fromMilliseconds(20),
                    .clock = .awake,
                }),
            ) catch |err| {
                self.err = err;
                return;
            };
            connection.deinit();
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{
        .io = io,
        .listener = &listener,
        .identity = &identity,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const peer = try connect(io, &listener);
    defer peer.close(io);

    thread.join();
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "TLS client absolute deadline retains shorter handshake timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const peer = try connect(io, &listener);
    defer peer.close(io);
    const stream = try listener.accept(io);
    defer stream.close(io);

    try std.testing.expectError(
        error.Timeout,
        client.Connection.initWithDeadline(
            allocator,
            io,
            stream,
            .{
                .server_name = "localhost",
                .server_verifier = .{},
                .handshake_timeout = .zero,
            },
            .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
        ),
    );
}

test "TLS handshake rejects non-positive timeout before network IO" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var identity = try Identity.init();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const server_peer = try connect(io, &listener);
    defer server_peer.close(io);
    const server_stream = try listener.accept(io);
    defer server_stream.close(io);
    try std.testing.expectError(
        error.Timeout,
        server.Connection.init(
            allocator,
            io,
            server_stream,
            identity.options(.zero),
        ),
    );

    const client_stream = try connect(io, &listener);
    defer client_stream.close(io);
    const client_peer = try listener.accept(io);
    defer client_peer.close(io);
    try std.testing.expectError(
        error.Timeout,
        client.Connection.init(allocator, io, client_stream, .{
            .server_name = "localhost",
            .server_verifier = .{},
            .handshake_timeout = .fromNanoseconds(-1),
        }),
    );
}

test "TLS handshake succeeds within one shared deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var identity = try Identity.init();
    const public_key = identity.key_pair.public_key.toUncompressedSec1();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        identity: *const Identity,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            var stream_owned = true;
            errdefer if (stream_owned) stream.close(self.io);
            const certificate_chain = [_][]const u8{
                &self.identity.certificate,
            };
            var options = self.identity.options(.fromSeconds(2));
            options.identity.certificate_chain = &certificate_chain;
            const connection = try server.Connection.init(
                allocator,
                self.io,
                stream,
                options,
            );
            stream_owned = false;
            defer connection.deinit();
            var request: [4]u8 = undefined;
            var offset: usize = 0;
            while (offset < request.len) {
                const count = try connection.read(request[offset..]);
                if (count == 0) return error.ConnectionClosed;
                offset += count;
            }
            try std.testing.expectEqualStrings("ping", &request);
            try connection.writeAll("pong");
        }
    };
    var shared = Shared{
        .io = io,
        .listener = &listener,
        .identity = &identity,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const stream = try connect(io, &listener);
    var stream_owned = true;
    defer if (stream_owned) stream.close(io);
    const connection = try client.Connection.init(allocator, io, stream, .{
        .server_name = "localhost",
        .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        },
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .handshake_timeout = .fromSeconds(2),
    });
    stream_owned = false;
    defer connection.deinit();
    try connection.writeAll("ping");
    var response: [4]u8 = undefined;
    var offset: usize = 0;
    while (offset < response.len) {
        const count = try connection.read(response[offset..]);
        if (count == 0) return error.ConnectionClosed;
        offset += count;
    }
    try std.testing.expectEqualStrings("pong", &response);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "TLS server deadline is not renewed after ClientHello" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var identity = try Identity.init();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        identity: *const Identity,
        started: std.Io.Event = .unset,
        err: ?anyerror = null,
        elapsed: std.Io.Duration = .zero,

        fn run(self: *@This()) void {
            const stream = self.listener.accept(self.io) catch |err| {
                self.err = err;
                return;
            };
            defer stream.close(self.io);
            const started = std.Io.Timestamp.now(self.io, .awake);
            self.started.set(self.io);
            const certificate_chain = [_][]const u8{
                &self.identity.certificate,
            };
            var options = self.identity.options(.fromMilliseconds(200));
            options.identity.certificate_chain = &certificate_chain;
            const result = server.Connection.init(
                allocator,
                self.io,
                stream,
                options,
            );
            self.elapsed = started.durationTo(
                std.Io.Timestamp.now(self.io, .awake),
            );
            if (result) |connection| {
                connection.deinit();
                self.err = error.TestUnexpectedResult;
            } else |err| self.err = err;
        }
    };
    var shared = Shared{
        .io = io,
        .listener = &listener,
        .identity = &identity,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const stream = try connect(io, &listener);
    defer stream.close(io);
    var joined = false;
    defer if (!joined) thread.join();
    // Deliver a valid ClientHello late in the budget, then withhold Finished.
    // A per-flight timeout would wait another 200 ms after this write.
    try shared.started.wait(io);
    try std.Io.sleep(io, .fromMilliseconds(120), .awake);
    try writeClientHello(allocator, io, stream);
    thread.join();
    joined = true;
    try std.testing.expectEqual(error.Timeout, shared.err.?);
    try std.testing.expect(shared.elapsed.toMilliseconds() < 270);
}
