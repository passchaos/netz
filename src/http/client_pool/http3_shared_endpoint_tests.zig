const std = @import("std");
const http = @import("../mod.zig");
const http1_runtime = @import("../../http1/runtime.zig");
const http2_runtime = @import("../../http2/runtime.zig");
const http3_runtime = @import("../../http3/runtime.zig");
const tls_testing = @import("../../tls/testing.zig");

test "unified HTTP pool shares one UDP endpoint across H3 origins" {
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
    const identity: @FieldType(http1_runtime.TlsListenOptions, "identity") = .{
        .certificate_chain = &.{&certificate_der},
        .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
    };
    var tcp_a = try http2_runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = identity },
    );
    defer tcp_a.deinit();
    var tcp_b = try http2_runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = identity },
    );
    defer tcp_b.deinit();

    const limits: http3_runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    const cid_a = [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };
    const cid_b = [_]u8{ 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0 };
    var h3_a = try http3_runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &cid_a,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        } },
    );
    defer h3_a.deinit();
    var h3_b = try http3_runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &cid_b,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        } },
    );
    defer h3_b.deinit();
    const alt_a = try std.fmt.allocPrint(
        allocator,
        "h3=\":{d}\"; ma=60",
        .{h3_a.address().ip4.port},
    );
    defer allocator.free(alt_a);
    const alt_b = try std.fmt.allocPrint(
        allocator,
        "h3=\":{d}\"; ma=60",
        .{h3_b.address().ip4.port},
    );
    defer allocator.free(alt_b);

    const TcpWorker = struct {
        server: *http2_runtime.TlsServer,
        alt_svc: []const u8,
        expected_path: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(10));
            defer connection.close();
            var request = try connection.readRequestWithTimeout(.fromSeconds(5));
            defer request.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(self.expected_path, request.path);
            try connection.writeResponse(request.stream_id, .{
                .headers = &.{.{ .name = "alt-svc", .value = self.alt_svc }},
                .body = self.expected_path,
                .request_method = request.method,
            });
        }
    };
    var slow_received: std.Io.Event = .unset;
    var release_slow: std.Io.Event = .unset;
    const H3Worker = struct {
        server: *http3_runtime.HandshakeServer,
        path: []const u8,
        body: []const u8,
        received: ?*std.Io.Event = null,
        release: ?*std.Io.Event = null,
        accepts: usize = 0,
        client_address: ?std.Io.net.IpAddress = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.acceptWithTimeout(.fromSeconds(10));
            self.accepts += 1;
            defer session.deinit();
            var request = try session.receiveRequestWithTimeout(.fromSeconds(5));
            defer request.deinit(self.server.allocator);
            self.client_address = request.from;
            try std.testing.expectEqualStrings(self.path, request.request.path);
            if (self.received) |event| {
                event.set(self.server.quic_server.endpoint.io);
            }
            if (self.release) |event| {
                try event.waitTimeout(
                    self.server.quic_server.endpoint.io,
                    .{ .duration = .{
                        .clock = .awake,
                        .raw = .fromSeconds(5),
                    } },
                );
            }
            try session.sendResponse(request.stream_id, .{
                .status = 200,
                .request_method = request.request.method,
                .body = self.body,
            });
        }
    };
    var tcp_worker_a = TcpWorker{
        .server = &tcp_a,
        .alt_svc = alt_a,
        .expected_path = "/discover-a",
    };
    var tcp_worker_b = TcpWorker{
        .server = &tcp_b,
        .alt_svc = alt_b,
        .expected_path = "/discover-b",
    };
    var h3_worker_a = H3Worker{
        .server = &h3_a,
        .path = "/slow",
        .body = "slow",
        .received = &slow_received,
        .release = &release_slow,
    };
    var h3_worker_b = H3Worker{
        .server = &h3_b,
        .path = "/fast",
        .body = "fast",
    };
    const tcp_thread_a = try std.Thread.spawn(.{}, TcpWorker.run, .{&tcp_worker_a});
    var tcp_joined_a = false;
    defer if (!tcp_joined_a) tcp_thread_a.join();
    const tcp_thread_b = try std.Thread.spawn(.{}, TcpWorker.run, .{&tcp_worker_b});
    var tcp_joined_b = false;
    defer if (!tcp_joined_b) tcp_thread_b.join();
    const h3_thread_a = try std.Thread.spawn(.{}, H3Worker.run, .{&h3_worker_a});
    var h3_joined_a = false;
    defer if (!h3_joined_a) h3_thread_a.join();
    const h3_thread_b = try std.Thread.spawn(.{}, H3Worker.run, .{&h3_worker_b});
    var h3_joined_b = false;
    defer if (!h3_joined_b) h3_thread_b.join();

    const Resolver = struct {
        addresses: [4]std.Io.net.IpAddress,
        calls: std.atomic.Value(u8) = .init(0),

        fn resolve(
            context: *anyopaque,
            resolve_allocator: std.mem.Allocator,
            _: std.Io,
            host: []const u8,
            port: u16,
            deadline: ?std.Io.Clock.Timestamp,
        ) http.AddressResolver.ResolveError![]std.Io.net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (!std.mem.eql(u8, host, "localhost") or deadline == null) {
                return error.UnknownHostName;
            }
            for (self.addresses) |address| {
                if (address.getPort() != port) continue;
                const result = try resolve_allocator.alloc(
                    std.Io.net.IpAddress,
                    1,
                );
                result[0] = address;
                _ = self.calls.fetchAdd(1, .acq_rel);
                return result;
            }
            return error.UnknownHostName;
        }
    };
    var resolver = Resolver{ .addresses = .{
        tcp_a.address(),
        tcp_b.address(),
        h3_a.address(),
        h3_b.address(),
    } };

    var pool = try http.Pool.init(allocator, io, .{
        .client = .{
            .address_resolver = .{
                .context = &resolver,
                .resolve = Resolver.resolve,
            },
            .tls = .{ .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            } },
        },
        .http3 = .{
            .limits = limits,
            .handshake = .{ .handshake = .{
                .original_destination_connection_id = &.{},
                .local_connection_id = &.{},
                .server_auth = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                },
            } },
            .idle = .{
                .max_idle_per_origin = 1,
                .max_idle_total = 2,
            },
            .max_connections = 2,
            .fallback = .never,
        },
    });
    defer pool.deinit();
    const base_a = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}",
        .{tcp_a.address().ip4.port},
    );
    defer allocator.free(base_a);
    const base_b = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}",
        .{tcp_b.address().ip4.port},
    );
    defer allocator.free(base_b);
    const discover_a = try std.fmt.allocPrint(
        allocator,
        "{s}/discover-a",
        .{base_a},
    );
    defer allocator.free(discover_a);
    const discover_b = try std.fmt.allocPrint(
        allocator,
        "{s}/discover-b",
        .{base_b},
    );
    defer allocator.free(discover_b);
    var response = try pool.requestUriWithTimeout(
        discover_a,
        .{},
        .fromSeconds(5),
    );
    response.deinit();
    response = try pool.requestUriWithTimeout(
        discover_b,
        .{},
        .fromSeconds(5),
    );
    response.deinit();

    const slow_uri = try std.fmt.allocPrint(allocator, "{s}/slow", .{base_a});
    defer allocator.free(slow_uri);
    const fast_uri = try std.fmt.allocPrint(allocator, "{s}/fast", .{base_b});
    defer allocator.free(fast_uri);
    const Producer = struct {
        fn run(
            client_pool: *http.Pool,
            uri: []const u8,
            body: []const u8,
        ) !void {
            var value = try client_pool.requestUriWithTimeout(
                uri,
                .{},
                .fromSeconds(5),
            );
            defer value.deinit();
            try std.testing.expectEqual(http.Protocol.http3, value.protocol());
            try std.testing.expectEqualStrings(body, value.body());
        }
    };
    var slow = try std.Io.concurrent(
        io,
        Producer.run,
        .{ &pool, slow_uri, "slow" },
    );
    var slow_active = true;
    defer if (slow_active) {
        release_slow.set(io);
        slow.cancel(io) catch {};
    };
    try slow_received.waitTimeout(io, .{ .duration = .{
        .clock = .awake,
        .raw = .fromSeconds(2),
    } });
    var fast = try std.Io.concurrent(
        io,
        Producer.run,
        .{ &pool, fast_uri, "fast" },
    );
    try fast.await(io);
    release_slow.set(io);
    try slow.await(io);
    slow_active = false;

    tcp_thread_a.join();
    tcp_joined_a = true;
    tcp_thread_b.join();
    tcp_joined_b = true;
    h3_thread_a.join();
    h3_joined_a = true;
    h3_thread_b.join();
    h3_joined_b = true;
    if (tcp_worker_a.err) |err| return err;
    if (tcp_worker_b.err) |err| return err;
    if (h3_worker_a.err) |err| return err;
    if (h3_worker_b.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), h3_worker_a.accepts);
    try std.testing.expectEqual(@as(usize, 1), h3_worker_b.accepts);
    try std.testing.expectEqual(
        h3_worker_a.client_address,
        h3_worker_b.client_address,
    );
    try std.testing.expectEqual(@as(usize, 2), pool.http3ConnectionCount());
    try std.testing.expectEqual(@as(usize, 2), pool.http3IdleCount());
    try std.testing.expectEqual(@as(usize, 4), pool.totalConnectionCount());
    try std.testing.expectEqual(@as(u8, 4), resolver.calls.load(.acquire));
}
