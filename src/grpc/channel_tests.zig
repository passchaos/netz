const std = @import("std");
const grpc = @import("mod.zig");
const channel = @import("channel.zig");
const http2 = @import("../http2/mod.zig");
const tls = @import("../tls/mod.zig");

const allocator = std.testing.allocator;

const ScriptedConnector = struct {
    address: std.Io.net.IpAddress,
    limits: http2.runtime.Limits = .{},
    failures_remaining: usize = 0,
    attempts: usize = 0,
    attempted: std.Io.Event = .unset,

    fn target(self: *@This()) channel.Target {
        return .{ .custom = .{
            .context = self,
            .connect_fn = connect,
            .retryable_fn = retryable,
        } };
    }

    fn connect(
        context_ptr: ?*anyopaque,
        alloc: std.mem.Allocator,
        io: std.Io,
        deadline: std.Io.Clock.Timestamp,
    ) http2.runtime.Error!http2.runtime.Connection {
        const self: *@This() = @ptrCast(@alignCast(context_ptr.?));
        self.attempts += 1;
        self.attempted.set(io);
        if (self.failures_remaining != 0) {
            self.failures_remaining -= 1;
            return error.ConnectionRefused;
        }
        return http2.runtime.Client.connectWithDeadline(
            alloc,
            io,
            self.address,
            self.limits,
            deadline,
        );
    }

    fn retryable(_: ?*anyopaque, err: anyerror) bool {
        return err == error.ConnectionRefused;
    }
};

const AlwaysUnavailable = struct {
    attempts: usize = 0,
    attempted: std.Io.Event = .unset,

    fn target(self: *@This()) channel.Target {
        return .{ .custom = .{
            .context = self,
            .connect_fn = connect,
            .retryable_fn = retryable,
        } };
    }

    fn connect(
        context_ptr: ?*anyopaque,
        _: std.mem.Allocator,
        io: std.Io,
        _: std.Io.Clock.Timestamp,
    ) http2.runtime.Error!http2.runtime.Connection {
        const self: *@This() = @ptrCast(@alignCast(context_ptr.?));
        self.attempts += 1;
        self.attempted.set(io);
        return error.ConnectionRefused;
    }

    fn retryable(_: ?*anyopaque, err: anyerror) bool {
        return err == error.ConnectionRefused;
    }
};

const UnaryPeer = struct {
    server: *http2.runtime.Server,
    close_first: bool = false,
    response_count: usize = 1,
    reply: []const u8 = "reply",
    requests: usize = 0,
    observed_timeout_ns: i96 = 0,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.serve() catch |err| {
            self.err = err;
        };
    }

    fn serve(self: *@This()) !void {
        if (self.close_first) {
            var first = try self.server.acceptWithTimeout(.fromSeconds(2));
            try self.serveRequest(&first, false);
            first.close();
            var second = try self.server.acceptWithTimeout(.fromSeconds(2));
            defer second.close();
            try self.serveRequest(&second, true);
            return;
        }
        var connection = try self.server.acceptWithTimeout(.fromSeconds(2));
        defer connection.close();
        for (0..self.response_count) |_| {
            try self.serveRequest(&connection, true);
        }
    }

    fn serveRequest(
        self: *@This(),
        connection: *http2.runtime.Connection,
        respond: bool,
    ) !void {
        var request = try connection.readRequestWithTimeout(.fromSeconds(2));
        defer request.deinit(self.server.allocator);
        var parsed = try grpc.parseUnaryRequest(
            self.server.allocator,
            &request,
            1024,
        );
        defer parsed.deinit();
        self.requests += 1;
        if (grpc.call.headerValue(request.headers, "grpc-timeout")) |raw| {
            self.observed_timeout_ns =
                (try grpc.Timeout.parse(raw)).duration().nanoseconds;
        }
        if (!respond) return;
        try grpc.writeUnaryResponse(
            connection,
            self.server.allocator,
            request.stream_id,
            .{ .message = self.reply },
        );
    }
};

const TlsUnaryPeer = struct {
    server: *http2.runtime.TlsServer,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.serve() catch |err| {
            self.err = err;
        };
    }

    fn serve(self: *@This()) !void {
        var connection = try self.server.acceptWithTimeout(.fromSeconds(2));
        defer connection.close();
        var request = try connection.readRequestWithTimeout(.fromSeconds(2));
        defer request.deinit(self.server.allocator);
        var parsed = try grpc.parseUnaryRequest(
            self.server.allocator,
            &request,
            1024,
        );
        defer parsed.deinit();
        try grpc.writeUnaryResponse(
            &connection,
            self.server.allocator,
            request.stream_id,
            .{ .message = "secure" },
        );
    }
};

fn testBackoff() channel.BackoffPolicy {
    return .{
        .initial_backoff = .fromMilliseconds(2),
        .multiplier = 1,
        .jitter = 0,
        .max_backoff = .fromMilliseconds(2),
        .min_connect_timeout = .fromSeconds(1),
    };
}

test "gRPC wait-for-ready channel reconnects within one RPC deadline" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    var peer = UnaryPeer{ .server = &server };
    const thread = try std.Thread.spawn(.{}, UnaryPeer.run, .{&peer});
    defer thread.join();

    var connector = ScriptedConnector{
        .address = server.address(),
        .failures_remaining = 2,
    };
    var client = try channel.Channel.init(
        allocator,
        io,
        connector.target(),
        .{ .backoff = testBackoff() },
    );
    defer client.deinit();
    var response = try client.unary(.{
        .path = "/fixture.Ready/Unary",
        .message = "request",
        .timeout = .{ .value = 1, .unit = .second },
        .wait_for_ready = true,
    });
    defer response.deinit();
    try std.testing.expectEqualStrings("reply", response.message.?.payload);
    try std.testing.expectEqual(@as(usize, 3), connector.attempts);
    try std.testing.expect(peer.observed_timeout_ns > 0);
    try std.testing.expect(peer.observed_timeout_ns < std.time.ns_per_s);
    if (peer.err) |err| return err;
}

test "gRPC wait-for-ready channel connects through TLS ALPN" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate,
        tls.testing.certificate_base64,
    );
    const key = try tls.testing.serverKeyPair();
    var server = try http2.runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } },
            },
            .protocol_policy = .tls13_only,
            .limits = .{ .handshake_timeout = .fromSeconds(1) },
        },
    );
    defer server.deinit();
    var peer = TlsUnaryPeer{ .server = &server };
    const thread = try std.Thread.spawn(.{}, TlsUnaryPeer.run, .{&peer});
    defer thread.join();

    var client = try channel.Channel.init(
        allocator,
        io,
        .{ .tls_address = .{
            .address = server.address(),
            .tls_host = "localhost",
            .authority = "localhost",
            .limits = .{ .handshake_timeout = .fromSeconds(1) },
            .tls = .{
                .server_verifier = .{
                    .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1(),
                },
                .protocol_policy = .tls13_only,
            },
        } },
        .{ .backoff = testBackoff() },
    );
    defer client.deinit();
    try std.testing.expectEqual(
        @as(usize, 1),
        try client.warmWithTimeout(.fromSeconds(1)),
    );
    try std.testing.expectEqualStrings("h2", client.negotiatedAlpn().?);
    try std.testing.expectEqual(
        @as(usize, 1),
        client.peerCertificates().?.len,
    );
    var response = try client.unary(.{
        .path = "/fixture.Ready/Unary",
        .message = "request",
        .timeout = .{ .value = 1, .unit = .second },
        .wait_for_ready = true,
    });
    defer response.deinit();
    try std.testing.expectEqualStrings("secure", response.message.?.payload);
    if (peer.err) |err| return err;
}

test "gRPC channel service config waits unless the call overrides fail-fast" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var unavailable: AlwaysUnavailable = .{};
    var client = try channel.Channel.init(
        allocator,
        io,
        unavailable.target(),
        .{ .backoff = testBackoff() },
    );
    defer client.deinit();
    var config = try grpc.ServiceConfig.parse(allocator,
        \\{"methodConfig":[{"name":[{}],"waitForReady":true}]}
    );
    defer config.deinit();

    try std.testing.expectError(error.ConnectionRefused, client.unaryWithServiceConfig(.{
        .path = "/fixture.Ready/Unary",
        .message = "request",
        .timeout = .{ .value = 100, .unit = .millisecond },
        .wait_for_ready = false,
    }, &config));
    try std.testing.expectEqual(@as(usize, 1), unavailable.attempts);

    try std.testing.expectError(error.Timeout, client.unaryWithServiceConfig(.{
        .path = "/fixture.Ready/Unary",
        .message = "request",
        .timeout = .{ .value = 12, .unit = .millisecond },
    }, &config));
    try std.testing.expect(unavailable.attempts > 1);
}

test "gRPC channel applies fail-fast readiness to streaming call starts" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var unavailable: AlwaysUnavailable = .{};
    var client = try channel.Channel.init(
        allocator,
        io,
        unavailable.target(),
        .{ .backoff = testBackoff() },
    );
    defer client.deinit();
    var config = try grpc.ServiceConfig.parse(allocator,
        \\{"methodConfig":[{"name":[{}],"waitForReady":true}]}
    );
    defer config.deinit();
    try std.testing.expectError(error.ConnectionRefused, client.startStreamingWithServiceConfig(.{
        .path = "/fixture.Ready/Stream",
        .timeout = .{ .value = 1, .unit = .second },
        .wait_for_ready = false,
    }, &config));
    try std.testing.expectError(error.ConnectionRefused, client.startDuplexWithServiceConfig(.{
        .path = "/fixture.Ready/Duplex",
        .timeout = .{ .value = 1, .unit = .second },
        .wait_for_ready = false,
    }, &config));
    try std.testing.expectEqual(@as(usize, 2), unavailable.attempts);
}

test "gRPC channel cancellation interrupts unbounded wait-for-ready backoff" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var unavailable: AlwaysUnavailable = .{};
    var client = try channel.Channel.init(
        allocator,
        io,
        unavailable.target(),
        .{ .backoff = .{
            .initial_backoff = .fromSeconds(1),
            .multiplier = 1,
            .jitter = 0,
            .max_backoff = .fromSeconds(1),
            .min_connect_timeout = .fromMilliseconds(10),
        } },
    );
    defer client.deinit();
    const Shared = struct {
        client: *channel.Channel,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            _ = self.client.unary(.{
                .path = "/fixture.Ready/Unary",
                .message = "request",
                .wait_for_ready = true,
            }) catch |err| {
                self.err = err;
                return;
            };
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .client = &client };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    try unavailable.attempted.wait(io);
    client.cancelWaits();
    thread.join();
    try std.testing.expectEqual(error.Canceled, shared.err.?);
}

test "gRPC channel preserves scheduled backoff across deadline calls" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var unavailable: AlwaysUnavailable = .{};
    var client = try channel.Channel.init(
        allocator,
        io,
        unavailable.target(),
        .{ .backoff = .{
            .initial_backoff = .fromMilliseconds(100),
            .multiplier = 1,
            .jitter = 0,
            .max_backoff = .fromMilliseconds(100),
            .min_connect_timeout = .fromMilliseconds(10),
        } },
    );
    defer client.deinit();
    try std.testing.expectError(error.Timeout, client.unary(.{
        .path = "/fixture.Ready/Unary",
        .message = "request",
        .timeout = .{ .value = 5, .unit = .millisecond },
        .wait_for_ready = true,
    }));
    try std.testing.expectEqual(@as(usize, 1), unavailable.attempts);
    try std.testing.expectError(error.Timeout, client.unary(.{
        .path = "/fixture.Ready/Unary",
        .message = "request",
        .timeout = .{ .value = 5, .unit = .millisecond },
        .wait_for_ready = true,
    }));
    try std.testing.expectEqual(@as(usize, 1), unavailable.attempts);
    client.resetConnectionBackoff();
    try std.testing.expectError(error.ConnectionRefused, client.unary(.{
        .path = "/fixture.Ready/Unary",
        .message = "request",
        .wait_for_ready = false,
    }));
    try std.testing.expectEqual(@as(usize, 2), unavailable.attempts);
}

test "gRPC channel rejects HTTP2 push and invalid backoff policy" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    try std.testing.expectError(error.InvalidChannelOptions, channel.Channel.init(
        allocator,
        io,
        .{ .cleartext_ip = .{
            .address = .{ .ip4 = .loopback(1) },
            .limits = .{ .enable_push = true },
        } },
        .{},
    ));
    var unavailable: AlwaysUnavailable = .{};
    try std.testing.expectError(error.InvalidChannelOptions, channel.Channel.init(
        allocator,
        io,
        unavailable.target(),
        .{ .backoff = .{ .initial_backoff = .zero } },
    ));

    var defaults = try grpc.ServiceConfig.parse(allocator, "{}");
    defer defaults.deinit();
    const endpoints = [_]channel.Endpoint{.{ .custom = .{
        .context = &unavailable,
        .connect_fn = AlwaysUnavailable.connect,
        .retryable_fn = AlwaysUnavailable.retryable,
    } }};
    var selected = try channel.Channel.initWithServiceConfig(
        allocator,
        io,
        .{ .resolved = .{
            .endpoints = &endpoints,
            .policy = .round_robin,
        } },
        .{},
        &defaults,
    );
    defer selected.deinit();
    try std.testing.expectEqual(
        channel.SelectionPolicy.round_robin,
        selected.selectionPolicy(),
    );
}

test "gRPC resolved channel initialization is allocation transactional" {
    const Harness = struct {
        fn run(alloc: std.mem.Allocator) !void {
            var unavailable: AlwaysUnavailable = .{};
            const endpoints = [_]channel.Endpoint{
                .{ .custom = .{
                    .context = &unavailable,
                    .connect_fn = AlwaysUnavailable.connect,
                    .retryable_fn = AlwaysUnavailable.retryable,
                } },
                .{ .custom = .{
                    .context = &unavailable,
                    .connect_fn = AlwaysUnavailable.connect,
                    .retryable_fn = AlwaysUnavailable.retryable,
                } },
            };
            var client = try channel.Channel.init(
                alloc,
                undefined,
                .{ .resolved = .{ .endpoints = &endpoints } },
                .{},
            );
            client.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, Harness.run, .{});
}

test "gRPC wait-for-ready does not replay an RPC after transport commitment" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    var peer = UnaryPeer{ .server = &server, .close_first = true };
    const thread = try std.Thread.spawn(.{}, UnaryPeer.run, .{&peer});
    defer thread.join();
    var connector = ScriptedConnector{ .address = server.address() };
    var client = try channel.Channel.init(
        allocator,
        io,
        connector.target(),
        .{ .backoff = testBackoff() },
    );
    defer client.deinit();

    const first = client.unary(.{
        .path = "/fixture.Ready/Unary",
        .message = "request",
        .timeout = .{ .value = 1, .unit = .second },
        .wait_for_ready = true,
    });
    if (first) |response_value| {
        var response = response_value;
        response.deinit();
        return error.TestExpectedError;
    } else |_| {}
    try std.testing.expectEqual(@as(usize, 1), connector.attempts);

    var second = try client.unary(.{
        .path = "/fixture.Ready/Unary",
        .message = "request",
        .timeout = .{ .value = 1, .unit = .second },
        .wait_for_ready = true,
    });
    defer second.deinit();
    try std.testing.expectEqualStrings("reply", second.message.?.payload);
    try std.testing.expectEqual(@as(usize, 2), connector.attempts);
    if (peer.err) |err| return err;
}

test "gRPC resolved channel round robins ready endpoint connections" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server_a = try http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server_a.deinit();
    var server_b = try http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server_b.deinit();
    var peer_a = UnaryPeer{
        .server = &server_a,
        .response_count = 2,
        .reply = "a",
    };
    var peer_b = UnaryPeer{
        .server = &server_b,
        .response_count = 2,
        .reply = "b",
    };
    const thread_a = try std.Thread.spawn(.{}, UnaryPeer.run, .{&peer_a});
    defer thread_a.join();
    const thread_b = try std.Thread.spawn(.{}, UnaryPeer.run, .{&peer_b});
    defer thread_b.join();
    const endpoints = [_]channel.Endpoint{
        .{ .cleartext_ip = .{ .address = server_a.address() } },
        .{ .cleartext_ip = .{ .address = server_b.address() } },
    };
    var config = try grpc.ServiceConfig.parse(allocator,
        \\{"loadBalancingConfig":[{"round_robin":{}}]}
    );
    defer config.deinit();
    var client = try channel.Channel.initWithServiceConfig(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &endpoints } },
        .{ .backoff = testBackoff() },
        &config,
    );
    defer client.deinit();
    try std.testing.expectEqual(
        channel.SelectionPolicy.round_robin,
        client.selectionPolicy(),
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        try client.warmWithTimeout(.fromSeconds(1)),
    );
    for ([_][]const u8{ "a", "b", "a", "b" }) |expected| {
        var response = try client.unary(.{
            .path = "/fixture.Balance/Unary",
            .message = "request",
            .timeout = .{ .value = 1, .unit = .second },
            .wait_for_ready = true,
        });
        defer response.deinit();
        try std.testing.expectEqualStrings(expected, response.message.?.payload);
    }
    if (peer_a.err) |err| return err;
    if (peer_b.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), peer_a.requests);
    try std.testing.expectEqual(@as(usize, 2), peer_b.requests);
}

test "gRPC resolved pick-first sticks to the first reachable endpoint" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    var reservation = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) })
        .listen(io, .{ .reuse_address = true });
    const unavailable = reservation.socket.address;
    reservation.deinit(io);
    var peer = UnaryPeer{
        .server = &server,
        .response_count = 2,
        .reply = "selected",
    };
    const thread = try std.Thread.spawn(.{}, UnaryPeer.run, .{&peer});
    defer thread.join();
    const endpoints = [_]channel.Endpoint{
        .{ .cleartext_ip = .{ .address = unavailable } },
        .{ .cleartext_ip = .{ .address = server.address() } },
    };
    var client = try channel.Channel.init(
        allocator,
        io,
        .{ .resolved = .{ .endpoints = &endpoints } },
        .{ .backoff = testBackoff() },
    );
    defer client.deinit();
    for (0..2) |_| {
        var response = try client.unary(.{
            .path = "/fixture.Balance/Unary",
            .message = "request",
            .timeout = .{ .value = 1, .unit = .second },
        });
        defer response.deinit();
        try std.testing.expectEqualStrings(
            "selected",
            response.message.?.payload,
        );
    }
    if (peer.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), peer.requests);
}

test "gRPC resolved endpoint backoff does not block a healthy sibling" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    var peer = UnaryPeer{ .server = &server, .response_count = 2 };
    const thread = try std.Thread.spawn(.{}, UnaryPeer.run, .{&peer});
    defer thread.join();
    var unavailable: AlwaysUnavailable = .{};
    const endpoints = [_]channel.Endpoint{
        .{ .custom = .{
            .context = &unavailable,
            .connect_fn = AlwaysUnavailable.connect,
            .retryable_fn = AlwaysUnavailable.retryable,
        } },
        .{ .cleartext_ip = .{ .address = server.address() } },
    };
    var client = try channel.Channel.init(
        allocator,
        io,
        .{ .resolved = .{
            .endpoints = &endpoints,
            .policy = .round_robin,
        } },
        .{ .backoff = .{
            .initial_backoff = .fromSeconds(1),
            .multiplier = 1,
            .jitter = 0,
            .max_backoff = .fromSeconds(1),
            .min_connect_timeout = .fromMilliseconds(10),
        } },
    );
    defer client.deinit();
    for (0..2) |_| {
        var response = try client.unary(.{
            .path = "/fixture.Balance/Unary",
            .message = "request",
            .timeout = .{ .value = 1, .unit = .second },
        });
        defer response.deinit();
    }
    try std.testing.expectEqual(@as(usize, 1), unavailable.attempts);
    if (peer.err) |err| return err;
}
