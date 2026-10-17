const std = @import("std");
const http3 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const tls_testing = @import("../../tls/testing.zig");

const limits: runtime.Limits = .{ .quic = .{
    .max_datagram_size = 4096,
    .max_frames_per_datagram = 8,
} };

fn findHeader(
    headers: []const http3.Qpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

fn driveRedirect(
    pool: *runtime.SharedHandshakeClientPool,
    transaction: *runtime.SharedHandshakeClientPool.RedirectTransaction,
    deadline: std.Io.Clock.Timestamp,
) !runtime.SharedHandshakeClientPool.RedirectedResponse {
    while (true) {
        var event = try pool.receiveWithDeadline(deadline);
        defer event.deinit(pool.allocator);
        if (try transaction.processEvent(&event)) |result| return result;
        if (event != .consumed) return error.TestUnexpectedResult;
    }
}

test "HTTP/3 shared pool transaction reuses one redirect connection" {
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
    const server_cid = [_]u8{ 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88 };
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
    const payload = "shared-pool-payload-" ** 80;

    const Shared = struct {
        server: *runtime.HandshakeServer,
        payload: []const u8,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.acceptWithTimeout(.fromSeconds(5));
            defer session.deinit();
            var first = try session.receiveRequestWithTimeout(.fromSeconds(5));
            defer first.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("POST", first.request.method);
            try std.testing.expectEqualStrings("/start", first.request.path);
            try std.testing.expectEqualStrings(self.payload, first.request.body);
            try std.testing.expectEqual(@as(usize, 1), first.request.trailers.len);
            try session.sendResponse(first.stream_id, .{
                .status = 303,
                .headers = &.{.{ .name = "location", .value = "/final" }},
                .body = "discard-this-redirect-body",
                .request_method = first.request.method,
            });

            var second = try session.receiveRequestWithTimeout(.fromSeconds(5));
            defer second.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("GET", second.request.method);
            try std.testing.expectEqualStrings("/final", second.request.path);
            try std.testing.expectEqual(@as(usize, 0), second.request.body.len);
            try std.testing.expectEqual(@as(usize, 0), second.request.trailers.len);
            try std.testing.expectEqualStrings(
                "Bearer retained",
                findHeader(second.request.headers, "authorization").?,
            );
            try std.testing.expect(
                findHeader(second.request.headers, "content-type") == null,
            );
            try session.sendResponse(second.stream_id, .{
                .status = 200,
                .body = "shared-final",
                .request_method = second.request.method,
            });
            try self.release.wait(self.server.quic_server.endpoint.io);
        }
    };
    var shared = Shared{ .server = &server, .payload = payload };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.release.set(io);
        server_thread.join();
    };

    var pool = try runtime.SharedHandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .limits = limits,
        .max_connections = 1,
        .client = .{
            .connect_timeout = .fromSeconds(3),
            .address_connect_policy = .{ .happy_eyeballs = .{
                .attempt_delay = .fromMilliseconds(20),
                .max_in_flight = 2,
            } },
            .handshake = .{
                .original_destination_connection_id = &.{},
                .local_connection_id = &.{},
                .server_auth = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                },
                .initial_one_rtt_config = .{
                    .max_datagram_size = 4096,
                    .enable_pacing = false,
                },
            },
        },
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/start",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var transaction = try pool.beginUriFollowingRedirectsWithTimeout(
        uri,
        .{
            .method = "POST",
            .headers = &.{
                .{ .name = "authorization", .value = "Bearer retained" },
                .{ .name = "content-type", .value = "text/plain" },
            },
            .body = payload,
            .trailers = &.{.{ .name = "x-upload", .value = "complete" }},
        },
        .{},
        .fromSeconds(5),
    );
    var transaction_active = true;
    defer if (transaction_active) transaction.deinit();

    const current_handle = transaction.connectionHandle().?;
    var unrelated = runtime.SharedHandshakeClientPool.Event{
        .progress = current_handle + 1,
    };
    try std.testing.expect((try transaction.processEvent(&unrelated)) == null);
    try std.testing.expect(unrelated == .progress);
    try std.testing.expectEqual(current_handle + 1, unrelated.progress);
    var unrelated_response = runtime.SharedHandshakeClientPool.Event{
        .response = .{
            .connection_handle = current_handle + 1,
            .response = .{ .reset = .{
                .stream_id = 96,
                .application_error_code = 17,
            } },
        },
    };
    defer unrelated_response.deinit(allocator);
    try std.testing.expect(
        (try transaction.processEvent(&unrelated_response)) == null,
    );
    try std.testing.expect(unrelated_response == .response);
    try std.testing.expectEqual(
        current_handle + 1,
        unrelated_response.response.connection_handle,
    );

    var result = try driveRedirect(
        &pool,
        &transaction,
        .fromNow(io, .{ .raw = .fromSeconds(5), .clock = .awake }),
    );
    transaction_active = false;
    defer result.deinit();
    try std.testing.expectEqualStrings("shared-final", result.response.response.body);
    try std.testing.expectEqual(@as(usize, 1), result.redirect_count);
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.routeCount());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 0), pool.leasedCount());

    shared.release.set(io);
    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 shared pool transaction isolates cross-origin replay" {
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
    var redirector = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = "shrd-red",
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        } },
    );
    defer redirector.deinit();
    var target = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = "shrd-tgt",
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        } },
    );
    defer target.deinit();
    const target_uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/final",
        .{target.address().ip4.port},
    );
    defer allocator.free(target_uri);
    const payload = "cross-origin-body-" ** 70;

    const Worker = struct {
        server: *runtime.HandshakeServer,
        target_uri: ?[]const u8,
        payload: []const u8,
        release: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.acceptWithTimeout(.fromSeconds(5));
            defer session.deinit();
            var request = try session.receiveRequestWithTimeout(.fromSeconds(5));
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("POST", request.request.method);
            try std.testing.expectEqualStrings(self.payload, request.request.body);
            if (self.target_uri) |location| {
                try std.testing.expectEqualStrings(
                    "Bearer first-origin",
                    findHeader(request.request.headers, "authorization").?,
                );
                try session.sendResponse(request.stream_id, .{
                    .status = 307,
                    .headers = &.{.{ .name = "location", .value = location }},
                    .body = "discard-cross-origin",
                    .request_method = request.request.method,
                });
            } else {
                try std.testing.expect(
                    findHeader(request.request.headers, "authorization") == null,
                );
                try std.testing.expectEqualStrings(
                    "application/json",
                    findHeader(request.request.headers, "accept").?,
                );
                try std.testing.expectEqual(@as(usize, 0), request.request.trailers.len);
                try session.sendResponse(request.stream_id, .{
                    .status = 200,
                    .body = "shared-cross-origin-final",
                    .request_method = request.request.method,
                });
            }
            try self.release.wait(self.server.quic_server.endpoint.io);
        }
    };
    var release: std.Io.Event = .unset;
    var redirect_worker = Worker{
        .server = &redirector,
        .target_uri = target_uri,
        .payload = payload,
        .release = &release,
    };
    var target_worker = Worker{
        .server = &target,
        .target_uri = null,
        .payload = payload,
        .release = &release,
    };
    const redirect_thread = try std.Thread.spawn(.{}, Worker.run, .{&redirect_worker});
    var redirect_joined = false;
    defer if (!redirect_joined) {
        release.set(io);
        redirect_thread.join();
    };
    const target_thread = try std.Thread.spawn(.{}, Worker.run, .{&target_worker});
    var target_joined = false;
    defer if (!target_joined) {
        release.set(io);
        target_thread.join();
    };

    var pool = try runtime.SharedHandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .limits = limits,
        .max_connections = 2,
        .client = .{
            .connect_timeout = .fromSeconds(3),
            .address_connect_policy = .{ .happy_eyeballs = .{
                .attempt_delay = .fromMilliseconds(20),
                .max_in_flight = 2,
            } },
            .handshake = .{
                .original_destination_connection_id = &.{},
                .local_connection_id = &.{},
                .server_auth = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                },
                .initial_one_rtt_config = .{
                    .max_datagram_size = 4096,
                    .enable_pacing = false,
                },
            },
        },
    });
    defer pool.deinit();
    const initial_uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/start",
        .{redirector.address().ip4.port},
    );
    defer allocator.free(initial_uri);
    var transaction = try pool.beginUriFollowingRedirectsWithTimeout(
        initial_uri,
        .{
            .method = "POST",
            .headers = &.{
                .{ .name = "authorization", .value = "Bearer first-origin" },
                .{ .name = "accept", .value = "application/json" },
            },
            .body = payload,
            .trailers = &.{.{ .name = "x-upload", .value = "complete" }},
        },
        .{},
        .fromSeconds(5),
    );
    var transaction_active = true;
    defer if (transaction_active) transaction.deinit();
    var result = try driveRedirect(
        &pool,
        &transaction,
        .fromNow(io, .{ .raw = .fromSeconds(5), .clock = .awake }),
    );
    transaction_active = false;
    defer result.deinit();
    try std.testing.expectEqualStrings(
        "shared-cross-origin-final",
        result.response.response.body,
    );
    try std.testing.expectEqual(@as(usize, 1), result.redirect_count);
    try std.testing.expectEqual(@as(usize, 2), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 2), pool.routeCount());
    try std.testing.expectEqual(@as(usize, 2), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 0), pool.leasedCount());

    release.set(io);
    redirect_thread.join();
    redirect_joined = true;
    target_thread.join();
    target_joined = true;
    if (redirect_worker.err) |err| return err;
    if (target_worker.err) |err| return err;
}

test "HTTP/3 shared pool transaction blocks cross-origin client identity" {
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
        limits,
        .{ .handshake = .{
            .local_connection_id = "shrd-id",
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.HandshakeServer,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.acceptWithTimeout(.fromSeconds(5));
            defer session.deinit();
            var request = try session.receiveRequestWithTimeout(.fromSeconds(5));
            defer request.deinit(self.server.allocator);
            try session.sendResponse(request.stream_id, .{
                .status = 307,
                .headers = &.{.{
                    .name = "location",
                    .value = "https://localhost:1/identity-boundary",
                }},
                .request_method = request.request.method,
            });
            try self.release.wait(self.server.quic_server.endpoint.io);
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.release.set(io);
        server_thread.join();
    };

    var pool = try runtime.SharedHandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .limits = limits,
        .max_connections = 2,
        .client = .{
            .connect_timeout = .fromSeconds(3),
            .handshake = .{
                .original_destination_connection_id = &.{},
                .local_connection_id = &.{},
                .server_auth = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                },
                .client_identity = .{
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
                .initial_one_rtt_config = .{
                    .max_datagram_size = 4096,
                    .enable_pacing = false,
                },
            },
        },
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/start",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var transaction = try pool.beginUriFollowingRedirectsWithTimeout(
        uri,
        .{},
        .{},
        .fromSeconds(5),
    );
    defer transaction.deinit();
    try std.testing.expectError(
        error.CrossOriginIdentityRestricted,
        driveRedirect(
            &pool,
            &transaction,
            .fromNow(io, .{ .raw = .fromSeconds(5), .clock = .awake }),
        ),
    );

    shared.release.set(io);
    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 shared pool redirect rejects zero timeout before I/O" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var pool = try runtime.SharedHandshakeClientPool.init(
        allocator,
        threaded.io(),
        .{
            .local_address = .{ .ip4 = .loopback(0) },
            .client = .{ .handshake = .{
                .original_destination_connection_id = &.{},
                .local_connection_id = &.{},
            } },
        },
    );
    defer pool.deinit();
    try std.testing.expectError(
        error.Timeout,
        pool.beginUriFollowingRedirectsWithTimeout(
            "https://localhost/",
            .{},
            .{},
            .zero,
        ),
    );
}
