const std = @import("std");
const runtime = @import("../runtime.zig");
const tls_testing = @import("../../tls/testing.zig");

test "HTTP/3 shared pool routes two origins through one endpoint" {
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

    var server_a = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = "shared-pool-server-a",
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
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
            .local_connection_id = "shared-pool-server-b",
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
        } },
    );
    defer server_b.deinit();

    const ServerWorker = struct {
        server: *runtime.HandshakeServer,
        expected_path: []const u8,
        expected_body: []const u8 = &.{},
        body: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var session = self.server.acceptWithTimeout(
                .fromSeconds(5),
            ) catch |err| {
                self.err = err;
                return;
            };
            defer session.deinit();
            var request = session.receiveRequest() catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit(self.server.allocator);
            if (!std.mem.eql(u8, request.request.path, self.expected_path)) {
                self.err = error.TestUnexpectedResult;
                return;
            }
            if (!std.mem.eql(u8, request.request.body, self.expected_body)) {
                self.err = error.TestUnexpectedResult;
                return;
            }
            if (self.expected_body.len != 0 and
                (request.request.trailers.len != 1 or
                    !std.mem.eql(
                        u8,
                        request.request.trailers[0].name,
                        "x-upload",
                    ) or
                    !std.mem.eql(
                        u8,
                        request.request.trailers[0].value,
                        "complete",
                    )))
            {
                self.err = error.TestUnexpectedResult;
                return;
            }
            session.sendResponse(request.stream_id, .{
                .status = 200,
                .body = self.body,
            }) catch |err| {
                self.err = err;
            };
        }
    };
    var worker_a = ServerWorker{
        .server = &server_a,
        .expected_path = "/a",
        .expected_body = "upload-a",
        .body = "origin-a",
    };
    var worker_b = ServerWorker{
        .server = &server_b,
        .expected_path = "/b",
        .body = "origin-b",
    };
    const thread_a = try std.Thread.spawn(.{}, ServerWorker.run, .{&worker_a});
    var joined_a = false;
    defer if (!joined_a) thread_a.join();
    const thread_b = try std.Thread.spawn(.{}, ServerWorker.run, .{&worker_b});
    var joined_b = false;
    defer if (!joined_b) thread_b.join();

    var pool = try runtime.SharedHandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .limits = limits,
        .max_connections = 2,
        .client = .{ .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .handshake_recovery = .{
                .initial_pto_ms = 20,
                .max_pto_ms = 40,
                .max_duration_ms = 2_000,
            },
            .initial_one_rtt_config = .{
                .max_datagram_size = 1200,
                .enable_pacing = false,
            },
        }, .connect_timeout = .fromSeconds(3) },
    });
    defer pool.deinit();
    const uri_a = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/a",
        .{server_a.address().ip4.port},
    );
    defer allocator.free(uri_a);
    const uri_b = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/b",
        .{server_b.address().ip4.port},
    );
    defer allocator.free(uri_b);

    var lease_a = try pool.acquireUri(uri_a);
    var lease_a_active = true;
    defer if (lease_a_active) lease_a.discard();
    var lease_b = try pool.acquireUri(uri_b);
    var lease_b_active = true;
    defer if (lease_b_active) lease_b.discard();
    try std.testing.expectEqual(pool.address(), lease_a.client().address());
    try std.testing.expectEqual(pool.address(), lease_b.client().address());
    try std.testing.expect(!lease_a.client().owns_endpoint);
    try std.testing.expect(!lease_b.client().owns_endpoint);
    try std.testing.expect(lease_a.client().dispatcherBound());
    try std.testing.expect(lease_b.client().dispatcherBound());
    try std.testing.expectError(
        error.InvalidDispatcherState,
        lease_a.client().receiveProgress(),
    );
    try std.testing.expectError(
        error.InvalidDispatcherState,
        lease_a.client().request(.{
            .method = "GET",
            .path = "/blocking",
        }),
    );
    try std.testing.expectEqual(@as(usize, 2), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 2), pool.routeCount());
    try std.testing.expectEqual(@as(usize, 0), pool.pendingHandshakeCount());

    const stream_a = try lease_a.tryStartRequest(.{
        .method = "POST",
        .path = "/a",
        .authority = "localhost",
    }, "upload-a".len);
    try lease_a.trySendRequestBodyParts(
        stream_a,
        &.{ "up", "load", "-", "a" },
        false,
    );
    try lease_a.tryFinishRequestTrailers(stream_a, &.{.{
        .name = "x-upload",
        .value = "complete",
    }});
    const stream_b = try lease_b.sendRequest(.{
        .method = "GET",
        .path = "/b",
        .authority = "localhost",
    });
    try std.testing.expectEqual(@as(u62, 0), stream_a);
    try std.testing.expectEqual(@as(u62, 0), stream_b);

    var body_a: ["origin-a".len]u8 = undefined;
    var body_b: ["origin-b".len]u8 = undefined;
    var body_a_len: usize = 0;
    var body_b_len: usize = 0;
    var finished_a = false;
    var finished_b = false;
    while (!finished_a or !finished_b) {
        var event = try pool.receiveWithTimeout(.fromSeconds(2));
        defer event.deinit(allocator);
        switch (event) {
            .response => |*response| {
                const lease = if (response.connection_handle ==
                    lease_a.connectionHandle())
                    &lease_a
                else if (response.connection_handle ==
                    lease_b.connectionHandle())
                    &lease_b
                else
                    return error.TestUnexpectedResult;
                const output = if (lease == &lease_a)
                    body_a[body_a_len..]
                else
                    body_b[body_b_len..];
                const message = switch (response.response) {
                    .message => |*value| value,
                    .reset => return error.TestUnexpectedResult,
                };
                switch (message.value) {
                    .head => |head| {
                        if (head != .response) {
                            return error.TestUnexpectedResult;
                        }
                        try std.testing.expectEqual(
                            @as(u16, 200),
                            head.response.status,
                        );
                    },
                    .data_available => {
                        const read = (try pool.readResponseDataOnce(
                            response.connection_handle,
                            message.stream_id,
                            output,
                        )) orelse 0;
                        if (lease == &lease_a)
                            body_a_len += read
                        else
                            body_b_len += read;
                    },
                    .finished => {
                        if (lease == &lease_a)
                            finished_a = true
                        else
                            finished_b = true;
                    },
                    .push_promise, .trailers => return error.TestUnexpectedResult,
                }
            },
            .progress, .timer, .consumed => {},
            .push, .closed, .unrouted => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expectEqualStrings("origin-a", body_a[0..body_a_len]);
    try std.testing.expectEqualStrings("origin-b", body_b[0..body_b_len]);

    const handle_a = lease_a.connectionHandle();
    lease_a.release();
    lease_a_active = false;
    lease_b.release();
    lease_b_active = false;
    var reused = try pool.acquireUri(uri_a);
    defer reused.discard();
    try std.testing.expect(reused.was_reused);
    try std.testing.expectEqual(handle_a, reused.connectionHandle());
    try std.testing.expectEqual(@as(u64, 1), pool.stats().total_reused);

    thread_a.join();
    joined_a = true;
    thread_b.join();
    joined_b = true;
    if (worker_a.err) |err| return err;
    if (worker_b.err) |err| return err;
}

test "HTTP/3 shared pool releases failed handshake capacity" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var silent = try @import("../../quic/mod.zig").runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer silent.deinit();
    var pool = try runtime.SharedHandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .max_connections = 1,
        .client = .{
            .connect_timeout = .fromMilliseconds(20),
            .handshake = .{
                .original_destination_connection_id = &.{},
                .local_connection_id = &.{},
                .handshake_recovery = .{
                    .initial_pto_ms = 100,
                    .max_pto_ms = 100,
                    .max_retries = 1,
                },
            },
        },
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://127.0.0.1:{d}/timeout",
        .{silent.address().ip4.port},
    );
    defer allocator.free(uri);

    try std.testing.expectError(error.HandshakeTimeout, pool.acquireUri(uri));
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.routeCount());
    try std.testing.expectEqual(@as(usize, 0), pool.pendingHandshakeCount());
    try std.testing.expectEqual(@as(usize, 0), pool.leasedCount());
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
}

test "HTTP/3 shared pool batches two streaming uploads" {
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
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = "shared-batch-server",
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
        } },
    );
    defer server.deinit();

    const Worker = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var session = self.server.acceptWithTimeout(
                .fromSeconds(5),
            ) catch |err| {
                self.err = err;
                return;
            };
            defer session.deinit();
            var saw_first = false;
            var saw_second = false;
            for (0..2) |_| {
                var request = session.receiveRequestWithTimeout(
                    .fromSeconds(2),
                ) catch |err| {
                    self.err = err;
                    return;
                };
                defer request.deinit(self.server.allocator);
                if (std.mem.eql(u8, request.request.path, "/first")) {
                    if (!std.mem.eql(u8, request.request.body, "one")) {
                        self.err = error.TestUnexpectedResult;
                        return;
                    }
                    saw_first = true;
                } else if (std.mem.eql(
                    u8,
                    request.request.path,
                    "/second",
                )) {
                    if (!std.mem.eql(u8, request.request.body, "two")) {
                        self.err = error.TestUnexpectedResult;
                        return;
                    }
                    saw_second = true;
                } else {
                    self.err = error.TestUnexpectedResult;
                    return;
                }
            }
            if (!saw_first or !saw_second) {
                self.err = error.TestUnexpectedResult;
            }
        }
    };
    var worker = Worker{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();

    var pool = try runtime.SharedHandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .max_connections = 1,
        .limits = limits,
        .client = .{ .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .initial_one_rtt_config = .{
                .max_datagram_size = 1200,
                .enable_pacing = false,
            },
        }, .connect_timeout = .fromSeconds(3) },
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/batch",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var lease = try pool.acquireUri(uri);
    var lease_active = true;
    defer if (lease_active) lease.discard();

    const first = try lease.tryStartRequest(.{
        .method = "POST",
        .path = "/first",
        .authority = "localhost",
    }, 3);
    const second = try lease.tryStartRequest(.{
        .method = "POST",
        .path = "/second",
        .authority = "localhost",
    }, 3);
    const progress = try lease.trySendRequestBodyBatch(&.{
        .{ .stream_id = first, .data = "one", .fin = true },
        .{ .stream_id = second, .data = "two", .fin = true },
    });
    try std.testing.expectEqual(@as(usize, 2), progress.sent_count);
    try std.testing.expect(progress.send_error == null);

    thread.join();
    joined = true;
    if (worker.err) |err| return err;
    lease.discard();
    lease_active = false;
}

test "HTTP/3 shared pool enforces leased capacity" {
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
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{ .max_datagram_size = 4096 } },
        .{ .handshake = .{
            .local_connection_id = "shared-cap-server",
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
        } },
    );
    defer server.deinit();

    const Worker = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var session = self.server.acceptWithTimeout(
                .fromSeconds(3),
            ) catch |err| {
                self.err = err;
                return;
            };
            defer session.deinit();
            var request = session.receiveRequestWithTimeout(
                .fromSeconds(2),
            ) catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit(self.server.allocator);
        }
    };
    var worker = Worker{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();

    var pool = try runtime.SharedHandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .max_connections = 1,
        .limits = .{ .quic = .{ .max_datagram_size = 4096 } },
        .client = .{ .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
        } },
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/capacity",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);

    var lease = try pool.acquireUri(uri);
    var lease_active = true;
    defer if (lease_active) lease.discard();
    const stream_id = try lease.sendRequest(.{
        .method = "GET",
        .path = "/capacity",
        .authority = "localhost",
    });
    try lease.tryCancelRequest(
        stream_id,
        @import("../mod.zig").ApplicationErrorCode.request_cancelled,
    );
    try std.testing.expectError(error.ConnectionLimitReached, pool.acquireUri(
        "https://127.0.0.1:443/other",
    ));
    lease.discard();
    lease_active = false;
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.routeCount());

    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}
