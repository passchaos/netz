const std = @import("std");
const runtime = @import("../runtime.zig");
const quic = @import("../../quic/mod.zig");
const tls_testing = @import("../../tls/testing.zig");

test "HTTP/3 shared synchronous acquire races both endpoint families" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var silent_v6 = quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip6 = .loopback(0) },
        .{},
    ) catch |err| switch (err) {
        error.AddressFamilyUnsupported,
        error.AddressUnavailable,
        => return error.SkipZigTest,
        else => |other| return other,
    };
    defer silent_v6.deinit();

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
            .local_connection_id = "shared-sync-server",
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
        } },
    );
    defer server.deinit();

    const ServerWorker = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var session = self.server.acceptWithTimeout(
                .fromSeconds(5),
            ) catch |err| {
                self.err = err;
                return;
            };
            session.deinit();
        }
    };
    var worker = ServerWorker{ .server = &server };
    const thread = try std.Thread.spawn(.{}, ServerWorker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();

    const Resolver = struct {
        silent: std.Io.net.IpAddress,
        live: std.Io.net.IpAddress,

        fn resolve(
            context: *anyopaque,
            resolve_allocator: std.mem.Allocator,
            _: std.Io,
            host: []const u8,
            _: u16,
            _: ?std.Io.Clock.Timestamp,
        ) runtime.SharedHandshakeClientPoolAddressResolver.ResolveError![]std.Io.net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (!std.mem.eql(u8, host, "sync.shared.test")) {
                return error.UnknownHostName;
            }
            const addresses = try resolve_allocator.alloc(
                std.Io.net.IpAddress,
                2,
            );
            addresses[0] = self.silent;
            addresses[1] = self.live;
            return addresses;
        }
    };
    var resolver = Resolver{
        .silent = silent_v6.address(),
        .live = server.address(),
    };
    var pool = try runtime.SharedHandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip6 = .loopback(0) },
        .migration_local_address = .{ .ip4 = .loopback(0) },
        .limits = limits,
        .max_connections = 1,
        .client = .{
            .handshake = .{
                .original_destination_connection_id = &.{},
                .local_connection_id = &.{},
                .server_auth = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                },
            },
            .connect_timeout = .fromSeconds(3),
            .address_attempt_timeout = .fromSeconds(2),
            .address_connect_policy = .{ .happy_eyeballs = .{
                .attempt_delay = .fromMilliseconds(20),
                .max_in_flight = 2,
            } },
            .address_resolver = .{
                .context = &resolver,
                .resolve = Resolver.resolve,
            },
        },
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://sync.shared.test:{d}/",
        .{server.address().getPort()},
    );
    defer allocator.free(uri);

    const started = std.Io.Clock.awake.now(io);
    var lease = try pool.acquireUri(uri);
    defer lease.release();
    try std.testing.expect(
        started.durationTo(std.Io.Clock.awake.now(io)).nanoseconds <
            std.time.ns_per_s,
    );
    try std.testing.expectEqual(
        pool.migrationAddress().?,
        lease.client().address(),
    );
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.pendingHandshakeCount());

    var first_initial = try silent_v6.receiveBytesWithTimeout(
        .fromMilliseconds(200),
    );
    defer first_initial.deinit(allocator);
    try std.testing.expect(first_initial.bytes.len >= 1200);

    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}

test "HTTP/3 shared Happy Eyeballs deadline cancels every route" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var silent_v6 = quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip6 = .loopback(0) },
        .{},
    ) catch |err| switch (err) {
        error.AddressFamilyUnsupported,
        error.AddressUnavailable,
        => return error.SkipZigTest,
        else => |other| return other,
    };
    defer silent_v6.deinit();
    var silent_v4 = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer silent_v4.deinit();

    const Resolver = struct {
        first: std.Io.net.IpAddress,
        second: std.Io.net.IpAddress,

        fn resolve(
            context: *anyopaque,
            resolve_allocator: std.mem.Allocator,
            _: std.Io,
            _: []const u8,
            _: u16,
            _: ?std.Io.Clock.Timestamp,
        ) runtime.SharedHandshakeClientPoolAddressResolver.ResolveError![]std.Io.net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            const addresses = try resolve_allocator.alloc(
                std.Io.net.IpAddress,
                2,
            );
            addresses[0] = self.first;
            addresses[1] = self.second;
            return addresses;
        }
    };
    var resolver = Resolver{
        .first = silent_v6.address(),
        .second = silent_v4.address(),
    };
    var pool = try runtime.SharedHandshakeClientPool.init(allocator, io, .{
        .local_address = .{ .ip6 = .loopback(0) },
        .migration_local_address = .{ .ip4 = .loopback(0) },
        .max_connections = 1,
        .client = .{
            .handshake = .{
                .original_destination_connection_id = &.{},
                .local_connection_id = &.{},
            },
            .connect_timeout = .fromMilliseconds(100),
            .address_attempt_timeout = .fromSeconds(2),
            .address_connect_policy = .{ .happy_eyeballs = .{
                .attempt_delay = .fromMilliseconds(10),
                .max_in_flight = 2,
            } },
            .address_resolver = .{
                .context = &resolver,
                .resolve = Resolver.resolve,
            },
        },
    });
    defer pool.deinit();

    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectError(
        error.HandshakeTimeout,
        pool.acquireUri("https://deadline.shared.test/"),
    );
    try std.testing.expect(
        started.durationTo(std.Io.Clock.awake.now(io)).nanoseconds <
            500 * std.time.ns_per_ms,
    );
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.pendingHandshakeCount());
    try std.testing.expectEqual(@as(usize, 0), pool.routeCount());

    var first = try silent_v6.receiveBytesWithTimeout(
        .fromMilliseconds(100),
    );
    defer first.deinit(allocator);
    var second = try silent_v4.receiveBytesWithTimeout(
        .fromMilliseconds(100),
    );
    defer second.deinit(allocator);
    try std.testing.expect(first.bytes.len >= 1200);
    try std.testing.expect(second.bytes.len >= 1200);
}
