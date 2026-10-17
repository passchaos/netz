const std = @import("std");
const runtime = @import("../../runtime.zig");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const tls_testing = @import("../../../tls/testing.zig");

test "HTTP3 owning Happy Eyeballs races dual-family URI handshakes" {
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
            .local_connection_id = "happy-server",
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
                .fromSeconds(10),
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
        calls: std.atomic.Value(u8) = .init(0),

        fn resolve(
            context: *anyopaque,
            resolve_allocator: std.mem.Allocator,
            _: std.Io,
            host: []const u8,
            _: u16,
            _: ?std.Io.Clock.Timestamp,
        ) runtime.AddressResolver.ResolveError![]std.Io.net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (!std.mem.eql(u8, host, "dual-stack.h3.test")) {
                return error.UnknownHostName;
            }
            const addresses = try resolve_allocator.alloc(
                std.Io.net.IpAddress,
                2,
            );
            addresses[0] = self.silent;
            addresses[1] = self.live;
            _ = self.calls.fetchAdd(1, .acq_rel);
            return addresses;
        }
    };
    var resolver = Resolver{
        .silent = silent_v6.address(),
        .live = server.address(),
    };
    const uri_text = try std.fmt.allocPrint(
        allocator,
        "https://dual-stack.h3.test:{d}/",
        .{server.address().getPort()},
    );
    defer allocator.free(uri_text);
    const uri = try std.Uri.parse(uri_text);

    const started = std.Io.Clock.awake.now(io);
    var client = try runtime.HandshakeClient.connectUriWithTimeout(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        uri,
        limits,
        .{
            .handshake = .{
                .original_destination_connection_id = "happy-original",
                .local_connection_id = "happy-client",
                .server_auth = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                },
            },
            .address_attempt_timeout = .fromSeconds(5),
            .address_connect_policy = .{ .happy_eyeballs = .{
                .attempt_delay = .fromMilliseconds(20),
                .max_in_flight = 2,
            } },
            .alternate_local_address = .{ .ip6 = .loopback(0) },
            .address_resolver = .{
                .context = &resolver,
                .resolve = Resolver.resolve,
            },
        },
        .fromSeconds(10),
    );
    defer client.deinit();
    const elapsed = started.durationTo(std.Io.Clock.awake.now(io));
    try std.testing.expect(elapsed.nanoseconds < 4 * std.time.ns_per_s);
    try std.testing.expectEqual(@as(u8, 1), resolver.calls.load(.acquire));
    try std.testing.expect(std.meta.activeTag(client.address()) == .ip4);
    try std.testing.expect(client.established.connection.peerAddress().eql(
        &resolver.live,
    ));

    var raced_initial = try silent_v6.receiveBytesWithTimeout(
        .fromMilliseconds(200),
    );
    defer raced_initial.deinit(allocator);
    try std.testing.expect(raced_initial.bytes.len >= 1200);

    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}

test "HTTP3 Happy Eyeballs validates policy and alternate bind family" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const uri = try std.Uri.parse("https://127.0.0.1:9/");
    const base: runtime.HandshakeClientOptions = .{ .handshake = .{
        .original_destination_connection_id = "invalid-original",
        .local_connection_id = "invalid-local",
    } };

    var invalid_delay = base;
    invalid_delay.address_connect_policy = .{ .happy_eyeballs = .{
        .attempt_delay = .zero,
    } };
    try std.testing.expectError(
        error.InvalidAddressConnectPolicy,
        runtime.HandshakeClient.connectUri(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            uri,
            .{},
            invalid_delay,
        ),
    );

    var same_family = base;
    same_family.alternate_local_address = .{ .ip4 = .loopback(0) };
    try std.testing.expectError(
        error.InvalidAddressConnectPolicy,
        runtime.HandshakeClient.connectUri(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            uri,
            .{},
            same_family,
        ),
    );
}

test "HTTP3 Happy Eyeballs total deadline cancels every handshake" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var silent_a = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer silent_a.deinit();
    var silent_b = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer silent_b.deinit();

    const Resolver = struct {
        first: std.Io.net.IpAddress,
        second: std.Io.net.IpAddress,

        fn resolve(
            context: *anyopaque,
            resolve_allocator: std.mem.Allocator,
            _: std.Io,
            host: []const u8,
            _: u16,
            _: ?std.Io.Clock.Timestamp,
        ) runtime.AddressResolver.ResolveError![]std.Io.net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (!std.mem.eql(u8, host, "deadline.happy.test")) {
                return error.UnknownHostName;
            }
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
        .first = silent_a.address(),
        .second = silent_b.address(),
    };
    const uri = try std.Uri.parse("https://deadline.happy.test/");
    const started = std.Io.Clock.awake.now(io);
    try std.testing.expectError(
        error.HandshakeTimeout,
        runtime.HandshakeClient.connectUriWithTimeout(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            uri,
            .{},
            .{
                .handshake = .{
                    .original_destination_connection_id = "deadline-original",
                    .local_connection_id = "deadline-client",
                },
                .address_attempt_timeout = .fromSeconds(5),
                .address_connect_policy = .{ .happy_eyeballs = .{
                    .attempt_delay = .fromMilliseconds(10),
                    .max_in_flight = 2,
                } },
                .address_resolver = .{
                    .context = &resolver,
                    .resolve = Resolver.resolve,
                },
            },
            .fromMilliseconds(100),
        ),
    );
    const elapsed = started.durationTo(std.Io.Clock.awake.now(io));
    try std.testing.expect(elapsed.nanoseconds < 500 * std.time.ns_per_ms);

    var first_initial = try silent_a.receiveBytesWithTimeout(
        .fromMilliseconds(100),
    );
    defer first_initial.deinit(allocator);
    var second_initial = try silent_b.receiveBytesWithTimeout(
        .fromMilliseconds(100),
    );
    defer second_initial.deinit(allocator);
    try std.testing.expect(first_initial.bytes.len >= 1200);
    try std.testing.expect(second_initial.bytes.len >= 1200);
}

test "HTTP3 Happy Eyeballs offers zero RTT only on the first attempt" {
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

    const ticket = "happy-eyeballs-early-ticket";
    const psk = [_]u8{0x61} ** 32;
    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(.{
        .server_id = "origin.happy.test:443",
        .alpn = "h3",
        .ticket = ticket,
        .psk = psk,
        .issued_at_ms = 1_000,
        .lifetime_seconds = 3_600,
        .age_add = 17,
        .max_early_data_size = quic.resumption.cache.quic_early_data_size,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    });
    var lease = (try cache.beginEarlyData(
        "origin.happy.test:443",
        "h3",
        1_500,
    )).?;
    defer lease.deinit();
    var early_request = try runtime.PreparedEarlyRequest.init(
        allocator,
        .{
            .method = "GET",
            .path = "/raced-early",
            .authority = "origin.happy.test",
        },
        .{},
        .{},
    );
    defer early_request.deinit();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var replay_filter = try quic.zero_rtt.ReplayFilter.init(
        allocator,
        io,
        8,
    );
    defer replay_filter.deinit();
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
            .local_connection_id = "happy-early-server",
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .psk = .{
                .identity = ticket,
                .secret = psk,
                .age_add = 17,
                .issued_at_ms = 1_000,
                .lifetime_seconds = 3_600,
                .now_ms = 1_500,
            },
            .early_data = .{
                .accept = true,
                .replay_filter = &replay_filter,
                .replay_key = "happy-eyeballs-first-only",
            },
        } },
    );
    defer server.deinit();

    const ServerWorker = struct {
        server: *runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.acceptWithTimeout(.fromSeconds(10));
            defer session.deinit();
            try std.testing.expectEqual(
                quic.zero_rtt.handshake.Status.not_offered,
                session.established.early_data_status,
            );
            var request = try session.receiveRequestWithTimeout(
                .fromSeconds(5),
            );
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expect(!request.was_early_data);
            try std.testing.expectEqualStrings(
                "/raced-early",
                request.request.path,
            );
            try session.sendResponse(request.stream_id, .{ .status = 204 });
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
        ) runtime.AddressResolver.ResolveError![]std.Io.net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (!std.mem.eql(u8, host, "route.happy.test")) {
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
    const uri = try std.Uri.parse("https://origin.happy.test/");
    const target: http3.AltSvcTarget = .{
        .alpn = "h3",
        .connect_host = "route.happy.test",
        .port = server.address().getPort(),
        .origin_host = "origin.happy.test",
    };

    const connected = try runtime.HandshakeClient
        .connectUriAltSvcWithEarlyRequestWithDeadline(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        uri,
        target,
        limits,
        .{
            .handshake = .{
                .original_destination_connection_id = "happy-early-original",
                .local_connection_id = "happy-early-client",
                .server_auth = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                },
                .resumption_now_ms = 1_500,
                .resumption_server_id = "origin.happy.test:443",
            },
            .address_attempt_timeout = .fromSeconds(5),
            .address_connect_policy = .{ .happy_eyeballs = .{
                .attempt_delay = .fromMilliseconds(20),
                .max_in_flight = 2,
            } },
            .alternate_local_address = .{ .ip6 = .loopback(0) },
            .address_resolver = .{
                .context = &resolver,
                .resolve = Resolver.resolve,
            },
        },
        &early_request,
        &cache,
        &lease,
        .fromNow(io, .{ .raw = .fromSeconds(10), .clock = .awake }),
    );
    var client = connected.client;
    defer client.deinit();
    try std.testing.expectEqual(
        runtime.EarlyRequestDisposition.rejected,
        connected.disposition,
    );

    var response = try client.requestWithTimeout(.{
        .method = "GET",
        .path = "/raced-early",
        .authority = "origin.happy.test",
    }, .fromSeconds(5));
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), response.response.status);

    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}
