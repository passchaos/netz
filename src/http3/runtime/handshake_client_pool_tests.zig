const std = @import("std");
const http3 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const connection_budget = @import("../../internal/connection_budget.zig");
const tls_testing = @import("../../tls/testing.zig");

test "HTTP/3 pool waits on a shared connection budget under one deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var budget = try connection_budget.Budget.create(allocator, io, 1);
    defer budget.deinit();
    try budget.tryReserve(null);

    var connector = runtime.HandshakeClientPoolDefaultConnector{ .options = .{
        .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
        },
    } };
    var pool = try runtime.HandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .loopback(0) },
        .max_connections = 2,
        .shared_connection_budget = budget,
        .connector = connector.connector(),
    });
    defer pool.deinit();

    try std.testing.expectError(
        error.Timeout,
        pool.acquireUriWithTimeout(
            "https://127.0.0.1:443/shared-budget",
            .fromMilliseconds(10),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.waitingCount());
    try std.testing.expectEqual(@as(usize, 0), budget.waitingCount());
    try std.testing.expectEqual(@as(usize, 1), budget.connectionCount());
    budget.release(1);
}

test "HTTP/3 unbounded request reclaims a shared connection slot" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var budget = try connection_budget.Budget.create(allocator, io, 1);
    defer budget.deinit();
    try budget.tryReserve(null);

    const Context = struct {
        budget: *connection_budget.Budget,
        connect_calls: usize = 0,
        reclaim_calls: usize = 0,

        fn connect(
            _: *anyopaque,
            _: std.mem.Allocator,
            _: std.Io,
            _: std.Io.net.IpAddress,
            _: std.Uri,
            _: runtime.Limits,
        ) runtime.Error!runtime.HandshakeClient {
            return error.Unexpected;
        }

        fn connectAlt(
            context: *anyopaque,
            _: std.mem.Allocator,
            _: std.Io,
            _: std.Io.net.IpAddress,
            _: std.Uri,
            _: http3.AltSvcTarget,
            _: runtime.Limits,
        ) runtime.Error!runtime.HandshakeClient {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.connect_calls += 1;
            return error.ConnectionRefused;
        }

        fn reclaim(context: *anyopaque) bool {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.reclaim_calls += 1;
            self.budget.release(1);
            return true;
        }
    };
    var context = Context{ .budget = budget };
    var pool = try runtime.HandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .loopback(0) },
        .max_connections = 2,
        .shared_connection_budget = budget,
        .connector = .{
            .context = &context,
            .client_identity_configured = false,
            .connect = Context.connect,
            .connect_alt_svc = Context.connectAlt,
        },
    });
    defer pool.deinit();

    try std.testing.expectError(
        error.ConnectionRefused,
        pool.requestUriAltSvcReclaiming(
            "https://origin.example/path",
            .{
                .alpn = "h3",
                .connect_host = "127.0.0.1",
                .origin_host = "origin.example",
                .port = 443,
            },
            .{},
            null,
            null,
            .{
                .context = &context,
                .reclaim = Context.reclaim,
            },
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), context.reclaim_calls);
    try std.testing.expectEqual(@as(usize, 1), context.connect_calls);
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), budget.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), budget.waitingCount());
}

test "HTTP/3 URI connect timeout validates and preserves one deadline" {
    const quic = @import("../../quic/mod.zig");
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const base: @FieldType(
        quic.handshake.ClientOptions,
        "handshake_recovery",
    ) = .{
        .initial_pto_ms = 100,
        .max_pto_ms = 400,
        .max_retries = 3,
    };

    try std.testing.expectError(
        error.HandshakeTimeout,
        runtime.testing.handshakeRecoveryBeforeForTest(
            io,
            .fromNow(io, .{ .raw = .zero, .clock = .awake }),
            base,
        ),
    );
    const deadline: std.Io.Clock.Timestamp = .fromNow(io, .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    });
    const bounded = try runtime.testing.handshakeRecoveryBeforeForTest(
        io,
        deadline,
        base,
    );
    try std.testing.expectEqual(deadline, bounded.deadline.?);
    try std.testing.expectEqual(base.initial_pto_ms, bounded.initial_pto_ms);
    try std.testing.expectEqual(base.max_pto_ms, bounded.max_pto_ms);
    try std.testing.expectEqual(base.max_retries, bounded.max_retries);
}

test "HTTP/3 direct and URI deadline APIs reject expired deadlines" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const expired: std.Io.Clock.Timestamp = .fromNow(io, .{
        .raw = .zero,
        .clock = .awake,
    });
    const options: runtime.HandshakeClientOptions = .{ .handshake = .{
        .original_destination_connection_id = "deadline-origin",
        .local_connection_id = "deadline-client",
    } };
    try std.testing.expectError(
        error.HandshakeTimeout,
        runtime.HandshakeClient.connectWithDeadline(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .ip4 = .loopback(443) },
            .{},
            options,
            expired,
        ),
    );
    try std.testing.expectError(
        error.HandshakeTimeout,
        runtime.HandshakeClient.connectUriWithDeadline(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            try std.Uri.parse("https://localhost/"),
            .{},
            options,
            expired,
        ),
    );
    try std.testing.expectError(
        error.HandshakeTimeout,
        runtime.HandshakeClient.connectWithTimeout(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .ip4 = .loopback(443) },
            .{},
            options,
            .zero,
        ),
    );
    try std.testing.expectError(
        error.HandshakeTimeout,
        runtime.HandshakeClient.connectUriWithTimeout(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            try std.Uri.parse("https://localhost/"),
            .{},
            options,
            .zero,
        ),
    );
}

test "HTTP/3 request timeout rejects a non-positive budget" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const options: runtime.HandshakeClientOptions = .{ .handshake = .{
        .original_destination_connection_id = "timeout-origin",
        .local_connection_id = "timeout-client",
    } };
    try std.testing.expectError(
        error.Timeout,
        runtime.HandshakeClient.requestUriWithTimeout(
            allocator,
            threaded.io(),
            .{ .ip4 = .loopback(0) },
            try std.Uri.parse("https://localhost/"),
            .{},
            .{},
            options,
            .zero,
        ),
    );
}

test "HTTP/3 pool releases a timed-out URI handshake reservation" {
    const quic = @import("../../quic/mod.zig");
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    // Keep a real UDP destination open but deliberately never service it.
    // This avoids an immediate ICMP refusal and exercises the deadline in the
    // actual Initial retransmission loop used by the default pool connector.
    var silent = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer silent.deinit();
    var connector = runtime.HandshakeClientPoolDefaultConnector{ .options = .{
        .connect_timeout = .fromMilliseconds(20),
        .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .handshake_recovery = .{
                .initial_pto_ms = 1_000,
                .max_pto_ms = 4_000,
                .max_retries = 3,
            },
        },
    } };
    var pool = try runtime.HandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .max_connections = 1,
        .connector = connector.connector(),
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://127.0.0.1:{d}/timeout",
        .{silent.address().ip4.port},
    );
    defer allocator.free(uri);

    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectError(
        error.HandshakeTimeout,
        pool.acquireUri(uri),
    );
    const elapsed = started.durationTo(std.Io.Clock.awake.now(io));
    try std.testing.expect(elapsed.nanoseconds < 500 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.leasedCount());
    try std.testing.expectEqual(@as(usize, 0), pool.waitingCount());
}

test "HTTP/3 pool acquire deadline bounds a custom connector" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const SlowConnector = struct {
        fn connect(
            _: *anyopaque,
            _: std.mem.Allocator,
            io_value: std.Io,
            _: std.Io.net.IpAddress,
            _: std.Uri,
            _: runtime.Limits,
        ) runtime.Error!runtime.HandshakeClient {
            std.Io.sleep(
                io_value,
                .fromMilliseconds(150),
                .awake,
            ) catch |err| return err;
            return error.ConnectionRefused;
        }
    };
    var context: u8 = 0;
    var pool = try runtime.HandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .loopback(0) },
        .max_connections = 1,
        .connector = .{
            .context = &context,
            .client_identity_configured = false,
            .connect = SlowConnector.connect,
        },
    });
    defer pool.deinit();

    try std.testing.expectError(
        error.Timeout,
        pool.acquireUriWithDeadline(
            "https://localhost/slow",
            .fromNow(io, .{
                .raw = .fromMilliseconds(20),
                .clock = .awake,
            }),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.leasedCount());
}

test "HTTP/3 pool request timeout rejects a non-positive budget" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var context: u8 = 0;
    const connector: runtime.HandshakeClientPoolConnector = .{
        .context = &context,
        .client_identity_configured = false,
        .connect = struct {
            fn connect(
                _: *anyopaque,
                _: std.mem.Allocator,
                _: std.Io,
                _: std.Io.net.IpAddress,
                _: std.Uri,
                _: runtime.Limits,
            ) runtime.Error!runtime.HandshakeClient {
                return error.InvalidUri;
            }
        }.connect,
    };
    var pool = try runtime.HandshakeClientPool.init(
        allocator,
        threaded.io(),
        .{
            .local_address = .{ .ip4 = .loopback(0) },
            .connector = connector,
        },
    );
    defer pool.deinit();
    try std.testing.expectError(
        error.Timeout,
        pool.requestUriWithTimeout(
            "https://localhost/",
            .{},
            .zero,
        ),
    );
}

test "HTTP/3 pool refuses Alt-Svc without an explicit route connector" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var context: u8 = 0;
    var pool = try runtime.HandshakeClientPool.init(
        allocator,
        threaded.io(),
        .{
            .local_address = .{ .ip4 = .loopback(0) },
            .max_connections = 1,
            .connector = .{
                .context = &context,
                .client_identity_configured = false,
                .connect = struct {
                    fn connect(
                        _: *anyopaque,
                        _: std.mem.Allocator,
                        _: std.Io,
                        _: std.Io.net.IpAddress,
                        _: std.Uri,
                        _: runtime.Limits,
                    ) runtime.Error!runtime.HandshakeClient {
                        return error.Unexpected;
                    }
                }.connect,
            },
        },
    );
    defer pool.deinit();
    try std.testing.expectError(
        error.InvalidHeader,
        pool.acquireUriAltSvc(
            "https://localhost/",
            .{
                .alpn = "h3",
                .connect_host = "127.0.0.1",
                .origin_host = "localhost",
                .port = 443,
            },
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.leasedCount());
}

test "HTTP/3 pool requires redirect-aware Alt-Svc isolation hook" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const Context = struct {
        ordinary_alt_called: bool = false,
        redirect_alt_called: bool = false,

        fn connect(
            _: *anyopaque,
            _: std.mem.Allocator,
            _: std.Io,
            _: std.Io.net.IpAddress,
            _: std.Uri,
            _: runtime.Limits,
        ) runtime.Error!runtime.HandshakeClient {
            return error.Unexpected;
        }

        fn connectAlt(
            context_ptr: *anyopaque,
            _: std.mem.Allocator,
            _: std.Io,
            _: std.Io.net.IpAddress,
            _: std.Uri,
            _: http3.AltSvcTarget,
            _: runtime.Limits,
        ) runtime.Error!runtime.HandshakeClient {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            self.ordinary_alt_called = true;
            return error.Unexpected;
        }

        fn connectAltRedirect(
            context_ptr: *anyopaque,
            _: std.mem.Allocator,
            _: std.Io,
            _: std.Io.net.IpAddress,
            _: std.Uri,
            _: http3.AltSvcTarget,
            _: runtime.Limits,
            redirect: runtime.HandshakeClientPoolRedirectConnectContext,
        ) runtime.Error!runtime.HandshakeClient {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            if (!redirect.cross_origin or redirect.forward_client_identity) {
                return error.Unexpected;
            }
            self.redirect_alt_called = true;
            return error.ConnectionRefused;
        }
    };
    var context: Context = .{};
    var pool = try runtime.HandshakeClientPool.init(
        allocator,
        threaded.io(),
        .{
            .local_address = .{ .ip4 = .loopback(0) },
            .max_connections = 1,
            .connector = .{
                .context = &context,
                .client_identity_configured = false,
                .connect = Context.connect,
                .connect_alt_svc = Context.connectAlt,
                .connect_alt_svc_redirect = Context.connectAltRedirect,
            },
        },
    );
    defer pool.deinit();
    try std.testing.expectError(
        error.Timeout,
        pool.requestUriAltSvcForRedirectWithTimeout(
            "https://localhost/redirected",
            .{
                .alpn = "h3",
                .connect_host = "127.0.0.1",
                .origin_host = "localhost",
                .port = 443,
            },
            .{},
            .{
                .cross_origin = true,
                .forward_client_identity = false,
            },
            .fromNanoseconds(0),
        ),
    );
    try std.testing.expect(!context.redirect_alt_called);
    try std.testing.expectError(
        error.ConnectionRefused,
        pool.requestUriAltSvcForRedirect(
            "https://localhost/redirected",
            .{
                .alpn = "h3",
                .connect_host = "127.0.0.1",
                .origin_host = "localhost",
                .port = 443,
            },
            .{},
            .{
                .cross_origin = true,
                .forward_client_identity = false,
            },
        ),
    );
    try std.testing.expect(!context.ordinary_alt_called);
    try std.testing.expect(context.redirect_alt_called);
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
}

test "HTTP/3 pool preserves origin over Alt-Svc routing and reuses QUIC" {
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
    const limits: runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    const server_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78 };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        } },
    );
    defer server.deinit();

    const Worker = struct {
        server: *runtime.HandshakeServer,
        accepts: usize = 0,
        requests: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            self.accepts += 1;
            defer session.deinit();
            for (0..2) |index| {
                var request = try session.receiveRequest();
                defer request.deinit(self.server.allocator);
                try std.testing.expect(std.ascii.eqlIgnoreCase(
                    "origin.example:9443",
                    request.request.authority.?,
                ));
                try std.testing.expectEqualStrings(
                    if (index == 0) "/one" else "/two",
                    request.request.path,
                );
                try session.sendResponse(request.stream_id, .{
                    .status = 200,
                    .request_method = request.request.method,
                    .body = if (index == 0) "one" else "two",
                });
                self.requests += 1;
            }
        }
    };
    var worker = Worker{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();

    var connector = runtime.HandshakeClientPoolDefaultConnector{ .options = .{
        .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
        },
    } };
    var pool = try runtime.HandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .limits = limits,
        .idle = .{
            .max_idle_per_origin = 1,
            .max_idle_total = 1,
        },
        .max_connections = 1,
        .connector = connector.connector(),
    });
    defer pool.deinit();
    const target: http3.AltSvcTarget = .{
        .alpn = "h3",
        .connect_host = "127.0.0.1",
        .origin_host = "origin.example",
        .port = server.address().ip4.port,
    };
    var first = try pool.requestUriAltSvcWithTimeout(
        "https://origin.example:9443/one",
        target,
        .{},
        .fromSeconds(5),
    );
    defer first.deinit(allocator);
    var second = try pool.requestUriAltSvcWithTimeout(
        "https://ORIGIN.EXAMPLE:9443/two",
        target,
        .{},
        .fromSeconds(5),
    );
    defer second.deinit(allocator);

    thread.join();
    joined = true;
    if (worker.err) |err| return err;
    try std.testing.expectEqualStrings("one", first.response.body);
    try std.testing.expectEqualStrings("two", second.response.body);
    try std.testing.expectEqual(@as(usize, 1), worker.accepts);
    try std.testing.expectEqual(@as(usize, 2), worker.requests);
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(u64, 1), pool.stats().total_reused);
}

test "HTTP/3 pool coalesces only certificate-authorized ORIGIN entries and honors 421" {
    const quic = @import("../../quic/mod.zig");
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
    const limits: runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    const server_cid = [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        } },
    );
    defer server.deinit();

    const origin_b = "https://localhost:9444";
    const origin_without_certificate = "https://other.example:9445";
    const Worker = struct {
        server: *runtime.HandshakeServer,
        advertised_origins: []const []const u8,
        accepts: usize = 0,
        requests: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn receive(
            self: *@This(),
            session: *runtime.HandshakeServerSession,
            expected_authority: []const u8,
            expected_path: []const u8,
        ) !runtime.OwnedHandshakeRequest {
            var request = try session.receiveRequestWithTimeout(
                .fromSeconds(5),
            );
            errdefer request.deinit(self.server.allocator);
            try std.testing.expect(std.ascii.eqlIgnoreCase(
                expected_authority,
                request.request.authority.?,
            ));
            try std.testing.expectEqualStrings(
                expected_path,
                request.request.path,
            );
            try std.testing.expect(!request.was_early_data);
            self.requests += 1;
            return request;
        }

        fn reply(
            _: *@This(),
            session: *runtime.HandshakeServerSession,
            request: runtime.OwnedHandshakeRequest,
            status: u16,
            body: []const u8,
        ) !void {
            try session.sendResponse(request.stream_id, .{
                .status = status,
                .request_method = request.request.method,
                .body = body,
            });
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.server.acceptWithTimeout(.fromSeconds(10));
            self.accepts += 1;
            defer first.deinit();
            try std.testing.expectEqual(
                quic.zero_rtt.handshake.Status.not_offered,
                first.established.early_data_status,
            );

            var initial = try self.receive(
                &first,
                "localhost:9443",
                "/initial",
            );
            defer initial.deinit(self.server.allocator);
            try first.sendOrigins(self.advertised_origins);
            try self.reply(&first, initial, 200, "initial");

            var coalesced = try self.receive(
                &first,
                "localhost:9444",
                "/coalesced",
            );
            defer coalesced.deinit(self.server.allocator);
            try self.reply(&first, coalesced, 421, "misdirected");

            var original_again = try self.receive(
                &first,
                "localhost:9443",
                "/original-again",
            );
            defer original_again.deinit(self.server.allocator);
            try self.reply(&first, original_again, 200, "original-again");

            var second = try self.server.acceptWithTimeout(.fromSeconds(10));
            self.accepts += 1;
            defer second.deinit();
            var certificate_miss = try self.receive(
                &second,
                "other.example:9445",
                "/certificate-miss",
            );
            defer certificate_miss.deinit(self.server.allocator);
            try self.reply(&second, certificate_miss, 200, "new-for-certificate");

            var third = try self.server.acceptWithTimeout(.fromSeconds(10));
            self.accepts += 1;
            defer third.deinit();
            var excluded = try self.receive(
                &third,
                "localhost:9444",
                "/after-421",
            );
            defer excluded.deinit(self.server.allocator);
            try self.reply(&third, excluded, 200, "new-after-421");
        }
    };
    const advertised = [_][]const u8{
        origin_b,
        origin_without_certificate,
    };
    var worker = Worker{
        .server = &server,
        .advertised_origins = &advertised,
    };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();

    var connector = runtime.HandshakeClientPoolDefaultConnector{
        .options = .{
            .handshake = .{
                .original_destination_connection_id = &.{},
                .local_connection_id = &.{},
                // The pin authenticates possession but deliberately does not make
                // every hostname valid. Coalescing separately checks the leaf SAN.
                .server_auth = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                },
            },
        },
    };
    var pool = try runtime.HandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .limits = limits,
        .idle = .{
            .max_idle_per_origin = 1,
            .max_idle_total = 1,
        },
        .max_connections = 1,
        .connector = connector.connector(),
    });
    defer pool.deinit();

    const target_a: http3.AltSvcTarget = .{
        .alpn = "h3",
        .connect_host = "127.0.0.1",
        .origin_host = "localhost",
        .port = server.address().ip4.port,
    };
    const target_b = target_a;
    const target_certificate_miss: http3.AltSvcTarget = .{
        .alpn = "h3",
        .connect_host = "127.0.0.1",
        .origin_host = "other.example",
        .port = server.address().ip4.port,
    };
    const NoReclaim = struct {
        fn reclaim(_: *anyopaque) bool {
            return false;
        }
    };
    var no_reclaim_context: u8 = 0;

    var initial = try pool.requestUriAltSvcWithTimeout(
        "https://localhost:9443/initial",
        target_a,
        .{},
        .fromSeconds(5),
    );
    defer initial.deinit(allocator);
    var coalesced = try pool.requestUriAltSvcEarlyReclaiming(
        "https://localhost:9444/coalesced",
        target_b,
        .{},
        .{},
        .{},
        .{},
        .fromNow(io, .{
            .raw = .fromSeconds(5),
            .clock = .awake,
        }),
        .{
            .context = &no_reclaim_context,
            .reclaim = NoReclaim.reclaim,
        },
    );
    defer coalesced.response.deinit(allocator);
    // Even though the caller supplied a complete early-request configuration,
    // cross-origin idle reuse remains an ordinary 1-RTT request and does not
    // construct or report a 0-RTT attempt.
    try std.testing.expect(coalesced.early_data == null);
    var original_again = try pool.requestUriAltSvcWithTimeout(
        "https://LOCALHOST:9443/original-again",
        target_a,
        .{},
        .fromSeconds(5),
    );
    defer original_again.deinit(allocator);
    var certificate_miss = try pool.requestUriAltSvcWithTimeout(
        "https://other.example:9445/certificate-miss",
        target_certificate_miss,
        .{},
        .fromSeconds(5),
    );
    defer certificate_miss.deinit(allocator);
    var after_421 = try pool.requestUriAltSvcWithTimeout(
        "https://localhost:9444/after-421",
        target_b,
        .{},
        .fromSeconds(5),
    );
    defer after_421.deinit(allocator);

    thread.join();
    joined = true;
    if (worker.err) |err| return err;
    try std.testing.expectEqualStrings("initial", initial.response.body);
    try std.testing.expectEqualStrings(
        "misdirected",
        coalesced.response.response.body,
    );
    try std.testing.expectEqual(
        @as(u16, 421),
        coalesced.response.response.status,
    );
    try std.testing.expectEqualStrings(
        "original-again",
        original_again.response.body,
    );
    try std.testing.expectEqualStrings(
        "new-for-certificate",
        certificate_miss.response.body,
    );
    try std.testing.expectEqualStrings("new-after-421", after_421.response.body);
    try std.testing.expectEqual(@as(usize, 3), worker.accepts);
    try std.testing.expectEqual(@as(usize, 5), worker.requests);
    try std.testing.expectEqual(@as(u64, 2), pool.stats().total_reused);
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
}

test "HTTP/3 handshake client pool replaces idle capacity across origins" {
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
    const limits: runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };

    const server_a_cid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const server_b_cid = [_]u8{ 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7 };
    var server_a = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_a_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        } },
    );
    defer server_a.deinit();
    var server_b = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_b_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        } },
    );
    defer server_b.deinit();

    const ServerWorker = struct {
        server: *runtime.HandshakeServer,
        expected_paths: []const []const u8,
        response_bodies: []const []const u8,
        requests: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var session = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer session.deinit();
            for (self.expected_paths, self.response_bodies) |expected_path, body| {
                var request = session.receiveRequest() catch |err| {
                    self.err = err;
                    return;
                };
                defer request.deinit(self.server.allocator);
                if (!std.mem.eql(u8, expected_path, request.request.path)) {
                    self.err = error.InvalidUri;
                    return;
                }
                session.sendResponse(request.stream_id, .{
                    .status = 200,
                    .request_method = request.request.method,
                    .body = body,
                }) catch |err| {
                    self.err = err;
                    return;
                };
                self.requests += 1;
            }
        }
    };
    var worker_a = ServerWorker{
        .server = &server_a,
        .expected_paths = &.{"/origin-a"},
        .response_bodies = &.{"a"},
    };
    var worker_b = ServerWorker{
        .server = &server_b,
        .expected_paths = &.{ "/origin-b/one", "/origin-b/two" },
        .response_bodies = &.{ "b-one", "b-two" },
    };
    const thread_a = try std.Thread.spawn(.{}, ServerWorker.run, .{&worker_a});
    var joined_a = false;
    defer if (!joined_a) thread_a.join();
    const thread_b = try std.Thread.spawn(.{}, ServerWorker.run, .{&worker_b});
    var joined_b = false;
    defer if (!joined_b) thread_b.join();

    const CountingConnector = struct {
        inner: runtime.HandshakeClientPoolDefaultConnector,
        connects: usize = 0,

        fn connect(
            context: *anyopaque,
            allocator_value: std.mem.Allocator,
            io_value: std.Io,
            local_address: std.Io.net.IpAddress,
            uri: std.Uri,
            client_limits: runtime.Limits,
        ) runtime.Error!runtime.HandshakeClient {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.connects += 1;
            return self.inner.connector().connect(
                &self.inner,
                allocator_value,
                io_value,
                local_address,
                uri,
                client_limits,
            );
        }
    };
    var connector = CountingConnector{ .inner = .{ .options = .{
        .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
        },
    } } };
    var pool = try runtime.HandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .limits = limits,
        .idle = .{
            .max_idle_per_origin = 1,
            .max_idle_total = 1,
        },
        .max_connections = 1,
        .connector = .{
            .context = &connector,
            .client_identity_configured = false,
            .connect = CountingConnector.connect,
        },
    });
    defer pool.deinit();

    const uri_a = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/origin-a",
        .{server_a.address().ip4.port},
    );
    defer allocator.free(uri_a);
    const uri_b_one = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/origin-b/one",
        .{server_b.address().ip4.port},
    );
    defer allocator.free(uri_b_one);
    const uri_b_two = try std.fmt.allocPrint(
        allocator,
        "https://LOCALHOST:{d}/origin-b/two",
        .{server_b.address().ip4.port},
    );
    defer allocator.free(uri_b_two);

    var response_a = try pool.requestUri(uri_a, .{});
    defer response_a.deinit(allocator);
    // The only connection slot is idle for origin A here. Acquiring origin B
    // must retire A before dialing B rather than rejecting the request or
    // temporarily exceeding the configured total.
    var response_b_one = try pool.requestUri(uri_b_one, .{});
    defer response_b_one.deinit(allocator);
    var response_b_two = try pool.requestUri(uri_b_two, .{});
    defer response_b_two.deinit(allocator);

    thread_a.join();
    joined_a = true;
    thread_b.join();
    joined_b = true;
    if (worker_a.err) |err| return err;
    if (worker_b.err) |err| return err;

    try std.testing.expectEqualStrings("a", response_a.response.body);
    try std.testing.expectEqualStrings("b-one", response_b_one.response.body);
    try std.testing.expectEqualStrings("b-two", response_b_two.response.body);
    try std.testing.expectEqual(@as(usize, 1), worker_a.requests);
    try std.testing.expectEqual(@as(usize, 2), worker_b.requests);
    try std.testing.expectEqual(@as(usize, 2), connector.connects);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 0), pool.leasedCount());
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(u64, 1), pool.stats().total_reused);
}

test "HTTP/3 handshake client pool admits capacity waiters in FIFO order" {
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
    const server_cid = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7 };
    const limits: runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            for (0..3) |_| {
                var session = self.server.accept() catch |err| {
                    self.err = err;
                    return;
                };
                // The waiter deliberately discards each newly admitted client
                // immediately. Complete each server-side close before
                // accepting the next QUIC handshake on the same UDP socket.
                session.deinit();
            }
        }
    };
    const Waiter = struct {
        pool: *runtime.HandshakeClientPool,
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
    var connector = runtime.HandshakeClientPoolDefaultConnector{ .options = .{
        .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
        },
    } };
    var pool = try runtime.HandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .limits = limits,
        .idle = .{
            .max_idle_per_origin = 0,
            .max_idle_total = 0,
        },
        .max_connections = 1,
        .connector = connector.connector(),
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/fifo",
        .{server.address().ip4.port},
    );
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
