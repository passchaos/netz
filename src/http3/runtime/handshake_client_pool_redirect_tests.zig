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

test "HTTP/3 pool follows same-origin redirect on one connection" {
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
    const server_cid = [_]u8{ 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };
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
        release: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            var first = try session.receiveRequest();
            defer first.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("POST", first.request.method);
            try std.testing.expectEqualStrings("/start", first.request.path);
            try std.testing.expectEqualStrings("payload", first.request.body);
            try std.testing.expectEqualStrings(
                "Bearer same-origin",
                findHeader(first.request.headers, "authorization").?,
            );
            try session.sendResponse(first.stream_id, .{
                .status = 303,
                .headers = &.{.{ .name = "location", .value = "/final" }},
                .request_method = first.request.method,
            });

            var second = try session.receiveRequest();
            defer second.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("GET", second.request.method);
            try std.testing.expectEqualStrings("/final", second.request.path);
            try std.testing.expectEqual(@as(usize, 0), second.request.body.len);
            try std.testing.expectEqual(@as(usize, 0), second.request.trailers.len);
            try std.testing.expectEqualStrings(
                "Bearer same-origin",
                findHeader(second.request.headers, "authorization").?,
            );
            try std.testing.expect(
                findHeader(second.request.headers, "content-type") == null,
            );
            try session.sendResponse(second.stream_id, .{
                .status = 200,
                .body = "pooled-final",
                .request_method = second.request.method,
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
        .max_connections = 1,
        .connector = connector.connector(),
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/start",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var result = try pool.requestUriFollowingRedirectsDetailedWithTimeout(
        uri,
        .{
            .method = "POST",
            .headers = &.{
                .{ .name = "authorization", .value = "Bearer same-origin" },
                .{ .name = "content-type", .value = "text/plain" },
            },
            .body = "payload",
            .trailers = &.{.{ .name = "x-upload", .value = "complete" }},
        },
        .{},
        .fromSeconds(3),
    );
    defer result.deinit();
    try std.testing.expectEqualStrings("pooled-final", result.response.response.body);
    try std.testing.expectEqual(@as(usize, 1), result.redirect_count);
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 0), pool.leasedCount());

    shared.release.set(io);
    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 pool redirects across origins with isolated credentials" {
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
    const redirect_cid = [_]u8{ 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58 };
    const target_cid = [_]u8{ 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68 };
    var redirector = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &redirect_cid,
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
            .local_connection_id = &target_cid,
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

    const Worker = struct {
        server: *runtime.HandshakeServer,
        target_uri: ?[]const u8,
        release: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit();
            var request = try session.receiveRequest();
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("POST", request.request.method);
            try std.testing.expectEqualStrings("payload", request.request.body);
            if (self.target_uri) |location| {
                try std.testing.expectEqualStrings(
                    "Bearer first-origin",
                    findHeader(request.request.headers, "authorization").?,
                );
                try session.sendResponse(request.stream_id, .{
                    .status = 307,
                    .headers = &.{.{ .name = "location", .value = location }},
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
                    .body = "cross-origin-final",
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
        .release = &release,
    };
    var target_worker = Worker{
        .server = &target,
        .target_uri = null,
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
        .max_connections = 2,
        .connector = connector.connector(),
    });
    defer pool.deinit();
    const initial_uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/start",
        .{redirector.address().ip4.port},
    );
    defer allocator.free(initial_uri);
    var result = try pool.requestUriFollowingRedirectsDetailedWithTimeout(
        initial_uri,
        .{
            .method = "POST",
            .headers = &.{
                .{ .name = "authorization", .value = "Bearer first-origin" },
                .{ .name = "accept", .value = "application/json" },
            },
            .body = "payload",
            .trailers = &.{.{ .name = "x-upload", .value = "complete" }},
        },
        .{},
        .fromSeconds(3),
    );
    defer result.deinit();
    try std.testing.expectEqualStrings(
        "cross-origin-final",
        result.response.response.body,
    );
    try std.testing.expectEqual(@as(usize, 1), result.redirect_count);
    try std.testing.expectEqual(@as(usize, 2), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 2), pool.idleCount());

    release.set(io);
    redirect_thread.join();
    redirect_joined = true;
    target_thread.join();
    target_joined = true;
    if (redirect_worker.err) |err| return err;
    if (target_worker.err) |err| return err;
}

test "HTTP/3 pool blocks configured client identity across origins" {
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
            var session = try self.server.accept();
            defer session.deinit();
            var request = try session.receiveRequest();
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

    var connector_context =
        runtime.HandshakeClientPoolDefaultConnector{ .options = .{
            .handshake = .{
                .original_destination_connection_id = &.{},
                .local_connection_id = &.{},
                .server_auth = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                },
            },
        } };
    var connector = connector_context.connector();
    // A custom connector must declare this whenever it can present an
    // identity. The test does not need an actual client certificate because
    // the pool rejects the authority boundary before the second dial.
    connector.client_identity_configured = true;
    var pool = try runtime.HandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .limits = limits,
        .max_connections = 2,
        .connector = connector,
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/start",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    try std.testing.expectError(
        error.CrossOriginIdentityRestricted,
        pool.requestUriFollowingRedirectsWithTimeout(
            uri,
            .{},
            .{},
            .fromSeconds(3),
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());

    shared.release.set(io);
    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 pool redirect rejects zero timeout before I/O" {
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
        pool.requestUriFollowingRedirectsWithTimeout(
            "https://localhost/",
            .{},
            .{},
            .zero,
        ),
    );
}
