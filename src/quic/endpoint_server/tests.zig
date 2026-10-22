const std = @import("std");
const quic = @import("../mod.zig");
const endpoint_server = @import("../endpoint_server.zig");
const tls_testing = @import("../../tls/testing.zig");

test "QUIC endpoint server rejects invalid admission limits" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();

    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
        }, .{ .max_pending_handshakes = 0 }),
    );
    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
        }, .{ .inbox_capacity = 0 }),
    );
    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
        }, .{ .handshake_poll_interval = .zero }),
    );
    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
        }, .{
            .stateless_reset_min_interval = .fromNanoseconds(-1),
        }),
    );

    const reset_key = [_]u8{0x51} **
        quic.stateless_reset.static_key_len;
    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
            .transport_parameters = &.{0},
        }, .{ .stateless_reset_key = reset_key }),
    );
    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
        }, .{ .preferred_address = endpoint.address() }),
    );
    var other_address = endpoint.address();
    other_address.setPort(other_address.getPort() +| 1);
    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
        }, .{
            .stateless_reset_key = reset_key,
            .preferred_address = other_address,
        }),
    );
    var secondary = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer secondary.deinit();
    var mismatched_secondary_address = secondary.address();
    mismatched_secondary_address.setPort(
        mismatched_secondary_address.getPort() +| 1,
    );
    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
        }, .{
            .stateless_reset_key = reset_key,
            .preferred_address = mismatched_secondary_address,
            .preferred_endpoint = &secondary,
        }),
    );
    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
        }, .{
            .stateless_reset_key = reset_key,
            .preferred_endpoint = &endpoint,
        }),
    );
    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
        }, .{
            .stateless_reset_key = reset_key,
            .preferred_additional_address = endpoint.address(),
        }),
    );
    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
        }, .{
            .stateless_reset_key = reset_key,
            .preferred_endpoint = &secondary,
            .preferred_additional_address = endpoint.address(),
        }),
    );
    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
        }, .{
            .stateless_reset_key = reset_key,
            .preferred_address = secondary.address(),
            .preferred_endpoint = &secondary,
            .preferred_additional_address = endpoint.address(),
        }),
    );
    var other_threaded = std.Io.Threaded.init(allocator, .{});
    defer other_threaded.deinit();
    var other_io_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        other_threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer other_io_endpoint.deinit();
    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
        }, .{
            .stateless_reset_key = reset_key,
            .preferred_endpoint = &other_io_endpoint,
        }),
    );
    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
            .local_transport_parameters = .{
                .preferred_address = .{
                    .ipv4_address = .{ 127, 0, 0, 1 },
                    .ipv4_port = 4433,
                    .connection_id = "preferred-cid",
                },
            },
        }, .{ .stateless_reset_key = reset_key }),
    );

    var raw_preferred_parameters: std.ArrayList(u8) = .empty;
    defer raw_preferred_parameters.deinit(allocator);
    try quic.encodeTransportParametersForSource(
        &raw_preferred_parameters,
        allocator,
        .{
            .preferred_address = .{
                .ipv4_address = .{ 127, 0, 0, 1 },
                .ipv4_port = 4433,
                .connection_id = "raw-preferred-cid",
            },
        },
        .server,
    );
    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
            .transport_parameters = raw_preferred_parameters.items,
        }, .{}),
    );
    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
            .local_transport_parameters = .{
                .stateless_reset_token = [_]u8{0x52} **
                    quic.stateless_reset.token_len,
            },
        }, .{ .stateless_reset_key = reset_key }),
    );
    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
            .initial_one_rtt_config = .{
                .local_stateless_reset_key = reset_key,
            },
        }, .{}),
    );
    try std.testing.expectError(
        error.InvalidOptions,
        endpoint_server.Server.init(allocator, &endpoint, .{
            .local_connection_id = &.{},
            .initial_one_rtt_config = .{
                .local_stateless_reset_key = [_]u8{0x53} **
                    quic.stateless_reset.static_key_len,
            },
        }, .{ .stateless_reset_key = reset_key }),
    );
}

test "QUIC endpoint server owns address token replay history by default" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();

    const secret: quic.address_validation_token.Secret =
        [_]u8{0x61} ** quic.address_validation_token.secret_len;
    const token = try quic.address_validation_token.encode(
        allocator,
        secret,
        .{
            .kind = .new_token,
            .issued_ns = 1,
            .lifetime_ns = 100,
            .peer_address = "peer",
            .nonce = [_]u8{0x62} **
                quic.address_validation_token.nonce_len,
        },
    );
    defer allocator.free(token);

    {
        var server = try endpoint_server.Server.init(
            allocator,
            &endpoint,
            .{
                .local_connection_id = &.{},
                .address_validation_secrets = &.{secret},
            },
            .{ .address_validation_replay_capacity = 2 },
        );
        defer server.deinit();
        try std.testing.expect(
            server.ownsAddressValidationReplayFilter(),
        );
        const replay_filter = server.handshake_options
            .address_validation_replay_filter.?;
        try std.testing.expect(
            replay_filter == server.worker_context.options
                .address_validation_replay_filter.?,
        );
        try replay_filter.rememberValidated(token);
        try std.testing.expectError(
            error.TokenReplay,
            replay_filter.rememberValidated(token),
        );
        try std.testing.expectEqual(
            @as(usize, 1),
            server.addressValidationReplayEntryCount(),
        );
    }

    {
        var disabled = try endpoint_server.Server.init(
            allocator,
            &endpoint,
            .{
                .local_connection_id = &.{},
                .address_validation_secrets = &.{secret},
            },
            .{ .address_validation_replay_capacity = 0 },
        );
        defer disabled.deinit();
        try std.testing.expect(
            !disabled.ownsAddressValidationReplayFilter(),
        );
        try std.testing.expect(
            disabled.handshake_options
                .address_validation_replay_filter == null,
        );
    }

    {
        var retry_server = try endpoint_server.Server.init(
            allocator,
            &endpoint,
            .{
                .local_connection_id = &.{},
                .retry = .{
                    .secret = secret,
                    .peer_address = "peer",
                    .issued_ns = 1,
                    .lifetime_ns = 100,
                },
            },
            .{ .address_validation_replay_capacity = 2 },
        );
        defer retry_server.deinit();
        try std.testing.expect(
            retry_server.ownsAddressValidationReplayFilter(),
        );
    }

    var caller_filter = try quic.address_validation_token
        .SharedReplayFilter.init(allocator, io, 2);
    defer caller_filter.deinit();
    var borrowed = try endpoint_server.Server.init(
        allocator,
        &endpoint,
        .{
            .local_connection_id = &.{},
            .address_validation_secrets = &.{secret},
            .address_validation_replay_filter = &caller_filter,
        },
        .{ .address_validation_replay_capacity = 2 },
    );
    defer borrowed.deinit();
    try std.testing.expect(!borrowed.ownsAddressValidationReplayFilter());
    try std.testing.expect(
        borrowed.handshake_options.address_validation_replay_filter.? ==
            &caller_filter,
    );
}

test "QUIC endpoint server keeps automatic stateless reset opt in" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer.deinit();
    var server = try endpoint_server.Server.init(allocator, &endpoint, .{
        .local_connection_id = &.{},
    }, .{});
    defer server.deinit();

    const trigger = [_]u8{0x40} **
        (quic.endpoint_dispatcher.default_server_connection_id_len + 19);
    try peer.sendBytes(server.address(), &trigger);
    var event = (try server.receiveOnce(
        &.{quic.Version.version_1.wireValue()},
        .{ .raw = .fromSeconds(1), .clock = .awake },
    )) orelse return error.TestUnexpectedResult;
    defer event.deinit(allocator);
    try std.testing.expect(event == .unrouted);
    try std.testing.expectEqual(
        quic.endpoint_dispatcher.UnroutedKind.unknown_short_header,
        event.unrouted.unrouted.kind,
    );
    try std.testing.expectError(
        error.Timeout,
        peer.receiveBytesWithTimeout(.fromMilliseconds(1)),
    );
}

test "QUIC endpoint server sends and rate limits automatic stateless resets" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer.deinit();
    var other_peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer other_peer.deinit();
    const reset_key = [_]u8{0x61} **
        quic.stateless_reset.static_key_len;
    var server = try endpoint_server.Server.init(allocator, &endpoint, .{
        .local_connection_id = &.{},
    }, .{
        .stateless_reset_key = reset_key,
        .stateless_reset_min_interval = .fromSeconds(1),
    });
    defer server.deinit();

    const cid_len = quic.endpoint_dispatcher.default_server_connection_id_len;
    var trigger = [_]u8{0xa5} ** (cid_len + 19);
    trigger[0] = 0x40;
    const cid = trigger[1 .. 1 + cid_len];
    const versions = [_]u32{quic.Version.version_1.wireValue()};

    try peer.sendBytes(server.address(), &trigger);
    try std.testing.expectEqual(
        @as(?endpoint_server.Event, null),
        try server.receiveOnce(
            &versions,
            .{ .raw = .fromSeconds(1), .clock = .awake },
        ),
    );
    var reset = try peer.receiveBytesWithTimeout(.fromSeconds(1));
    defer reset.deinit(allocator);
    try std.testing.expect(reset.bytes.len < trigger.len);
    try std.testing.expect(quic.stateless_reset.matches(
        reset.bytes,
        quic.stateless_reset.tokenForConnectionId(reset_key, cid),
    ));

    try other_peer.sendBytes(server.address(), &trigger);
    try std.testing.expectEqual(
        @as(?endpoint_server.Event, null),
        try server.receiveOnce(
            &versions,
            .{ .raw = .fromSeconds(1), .clock = .awake },
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        other_peer.receiveBytesWithTimeout(.fromMilliseconds(1)),
    );

    server.last_stateless_reset_ns = null;
    const too_short = [_]u8{0x40} ** (cid_len + 18);
    try peer.sendBytes(server.address(), &too_short);
    try std.testing.expectEqual(
        @as(?endpoint_server.Event, null),
        try server.receiveOnce(
            &versions,
            .{ .raw = .fromSeconds(1), .clock = .awake },
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        peer.receiveBytesWithTimeout(.fromMilliseconds(1)),
    );

    var fixed_bit_clear = trigger;
    fixed_bit_clear[0] = 0;
    try peer.sendBytes(server.address(), &fixed_bit_clear);
    try std.testing.expectEqual(
        @as(?endpoint_server.Event, null),
        try server.receiveOnce(
            &versions,
            .{ .raw = .fromSeconds(1), .clock = .awake },
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        peer.receiveBytesWithTimeout(.fromMilliseconds(1)),
    );

    const unknown_long = [_]u8{ 0xc0, 0, 0, 0, 1 };
    try peer.sendBytes(server.address(), &unknown_long);
    var long_event = (try server.receiveOnce(
        &versions,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    )) orelse return error.TestUnexpectedResult;
    defer long_event.deinit(allocator);
    try std.testing.expect(long_event == .unrouted);
    try std.testing.expectEqual(
        quic.endpoint_dispatcher.UnroutedKind.malformed_long_header,
        long_event.unrouted.unrouted.kind,
    );
    try std.testing.expectError(
        error.Timeout,
        peer.receiveBytesWithTimeout(.fromMilliseconds(1)),
    );
}

test "QUIC endpoint server resets unknown packets in visitor and batch receives" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer.deinit();
    const reset_key = [_]u8{0x71} **
        quic.stateless_reset.static_key_len;
    var server = try endpoint_server.Server.init(allocator, &endpoint, .{
        .local_connection_id = &.{},
    }, .{
        .stateless_reset_key = reset_key,
        .stateless_reset_min_interval = .zero,
    });
    defer server.deinit();

    const cid_len = quic.endpoint_dispatcher.default_server_connection_id_len;
    var trigger = [_]u8{0xb5} ** (cid_len + 19);
    trigger[0] = 0x40;
    const expected = quic.stateless_reset.tokenForConnectionId(
        reset_key,
        trigger[1 .. 1 + cid_len],
    );
    const versions = [_]u32{quic.Version.version_1.wireValue()};
    const Visitor = struct {
        fn visit(
            _: void,
            _: quic.endpoint_dispatcher.RoutedPacketView,
        ) error{}!void {}
    };

    try peer.sendBytes(server.address(), &trigger);
    var storage: [4096]u8 = undefined;
    try std.testing.expectEqual(
        @as(?endpoint_server.VisitEvent, null),
        try server.receiveVisitingOnce(
            &versions,
            &storage,
            .fromMilliseconds(2),
            {},
            Visitor.visit,
        ),
    );
    var visitor_reset = try peer.receiveBytesWithTimeout(.fromSeconds(1));
    defer visitor_reset.deinit(allocator);
    try std.testing.expect(quic.stateless_reset.matches(
        visitor_reset.bytes,
        expected,
    ));

    try peer.sendBytes(server.address(), &trigger);
    var events: [1]endpoint_server.VisitEvent = undefined;
    try std.testing.expectError(
        error.Timeout,
        server.receiveManyVisitingWithDeadline(
            &versions,
            &storage,
            &events,
            .fromNow(io, .{
                .raw = .fromMilliseconds(2),
                .clock = .awake,
            }),
            {},
            Visitor.visit,
        ),
    );
    var batch_reset = try peer.receiveBytesWithTimeout(.fromSeconds(1));
    defer batch_reset.deinit(allocator);
    try std.testing.expect(quic.stateless_reset.matches(
        batch_reset.bytes,
        expected,
    ));
}

test "QUIC endpoint server idle batch receive preserves caller deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    var server = try endpoint_server.Server.init(
        allocator,
        &endpoint,
        .{ .local_connection_id = &.{} },
        .{ .max_pending_handshakes = 1 },
    );
    defer server.deinit();
    try std.testing.expectEqual(
        @as(usize, 0),
        try server.replenishConnectionIds(999),
    );
    const versions = [_]u32{quic.Version.version_1.wireValue()};
    var storage: [4096]u8 = undefined;
    var events: [1]endpoint_server.VisitEvent = undefined;
    const Visitor = struct {
        fn visit(
            _: void,
            _: quic.endpoint_dispatcher.RoutedPacketView,
        ) error{}!void {}
    };
    try std.testing.expectError(
        error.Timeout,
        server.receiveManyVisitingWithDeadline(
            &versions,
            &storage,
            &events,
            .fromNow(threaded.io(), .{
                .raw = .fromMilliseconds(1),
                .clock = .awake,
            }),
            {},
            Visitor.visit,
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        server.receiveManyVisitingTimeout(
            &versions,
            &storage,
            &events,
            .{ .duration = .{ .raw = .zero, .clock = .awake } },
            {},
            Visitor.visit,
        ),
    );
}

test "QUIC endpoint server routes two authenticated connections on one socket" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    const server_key = try tls_testing.serverKeyPair();
    const server_public = server_key.public_key.toUncompressedSec1();
    const stateless_reset_key = [_]u8{0x91} **
        quic.stateless_reset.static_key_len;
    var server = try endpoint_server.Server.init(
        allocator,
        &server_endpoint,
        .{
            .local_connection_id = &.{},
            .alpn_protocol = "netz-shared-endpoint-test",
            .random = [_]u8{0x31} ** 32,
            .x25519_secret_key = [_]u8{0x32} ** 32,
            .key_exchange_groups = &.{.x25519},
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .identity = .{
                .certificate_chain = &.{&server_public},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = server_key,
                } },
            },
            .initial_one_rtt_config = .{ .enable_pacing = false },
            .handshake_recovery = .{
                .initial_pto_ms = 20,
                .max_pto_ms = 40,
                .max_duration_ms = 10_000,
            },
        },
        .{
            .max_pending_handshakes = 2,
            .max_connections = 2,
            .inbox_capacity = 16,
            .handshake_timeout_ms = 10_000,
            .stateless_reset_key = stateless_reset_key,
            .preferred_address = server_endpoint.address(),
        },
    );
    defer server.deinit();

    const Client = struct {
        const Stage = enum {
            handshake,
            request,
            response,
            first_rotation,
            replacement_cid,
            second_rotation,
            complete,
        };

        allocator: std.mem.Allocator,
        io: std.Io,
        peer: std.Io.net.IpAddress,
        public_key: [65]u8,
        stateless_reset_key: [quic.stateless_reset.static_key_len]u8,
        index: u8,
        preferred_connection_id: [
            quic.endpoint_dispatcher.default_server_connection_id_len
        ]u8 = undefined,
        preferred_reset_token: [quic.stateless_reset.token_len]u8 = undefined,
        err: ?anyerror = null,
        stage: Stage = .handshake,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                std.debug.print(
                    "shared endpoint client={d} stage={s} error={s}\n",
                    .{ self.index, @tagName(self.stage), @errorName(err) },
                );
            };
        }

        fn runFallible(self: *@This()) !void {
            var endpoint = try quic.runtime.Endpoint.bind(
                self.allocator,
                self.io,
                .{ .ip4 = .loopback(0) },
                .{ .max_datagram_size = 4096 },
            );
            defer endpoint.deinit();
            var original_dcid = [_]u8{0x40} ** 8;
            var client_cid = [_]u8{0x50} ** 8;
            original_dcid[0] +%= self.index;
            client_cid[0] +%= self.index;
            var random = [_]u8{0x60} ** 32;
            random[0] +%= self.index;
            var secret = [_]u8{0x70} ** 32;
            secret[0] +%= self.index;
            const version: quic.Version = if (self.index == 0)
                .version_1
            else
                .version_2;
            var established = try quic.handshake.connectWithTimeout(
                &endpoint,
                self.peer,
                .{
                    .version = version,
                    .available_versions = &.{version},
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .server_name = "localhost",
                    .alpn_protocols = &.{"netz-shared-endpoint-test"},
                    .server_auth = .{
                        .pinned_ecdsa_p256_public_key = self.public_key,
                    },
                    .random = random,
                    .x25519_secret_key = secret,
                    .key_exchange_groups = &.{.x25519},
                    .cipher_suites = &.{.aes_128_gcm_sha256},
                    .local_transport_parameters = .{
                        .initial_max_data = 64 * 1024,
                        .initial_max_stream_data_bidi_local = 64 * 1024,
                        .initial_max_stream_data_bidi_remote = 64 * 1024,
                        .initial_max_stream_data_uni = 64 * 1024,
                        .initial_max_streams_bidi = 1,
                        .initial_max_streams_uni = 1,
                        .active_connection_id_limit = 4,
                    },
                    .initial_one_rtt_config = .{ .enable_pacing = false },
                    .handshake_recovery = .{
                        .initial_pto_ms = 20,
                        .max_pto_ms = 40,
                        .max_duration_ms = 10_000,
                    },
                },
                .fromSeconds(10),
            );
            defer established.deinit();
            self.stage = .request;
            const expected_reset_token =
                quic.stateless_reset.tokenForConnectionId(
                    self.stateless_reset_key,
                    established.peer_connection_id,
                );
            try std.testing.expectEqual(
                @as(?[quic.stateless_reset.token_len]u8, expected_reset_token),
                established.connection.config.peer_stateless_reset_token,
            );
            const preferred = established.connection.peerPreferredAddress() orelse
                return error.TestUnexpectedResult;
            try std.testing.expectEqual(
                self.preferred_connection_id.len,
                preferred.connection_id.len,
            );
            @memcpy(&self.preferred_connection_id, preferred.connection_id);
            self.preferred_reset_token = preferred.stateless_reset_token;
            try std.testing.expectEqualSlices(
                u8,
                &quic.stateless_reset.tokenForConnectionId(
                    self.stateless_reset_key,
                    preferred.connection_id,
                ),
                &self.preferred_reset_token,
            );
            const payload = [_]u8{ 'c', 'l', 'i', 'e', 'n', 't', '-', self.index };
            try established.connection.send(&.{.{ .stream = .{
                .stream_id = 0,
                .data = &payload,
                .fin = true,
            } }});
            self.stage = .response;
            var response: [payload.len]u8 = undefined;
            const received = try established.connection
                .receiveStreamIdWithTimeout(
                0,
                &response,
                .fromSeconds(10),
            );
            const data = switch (received) {
                .reset => return error.TestUnexpectedResult,
                .data => |value| value,
            };
            try std.testing.expect(data.fin);
            try std.testing.expectEqual(payload.len, data.bytes);
            try std.testing.expectEqualSlices(u8, &payload, &response);
            self.stage = .first_rotation;
            try std.testing.expect(
                try established.connection.switchToNextPeerConnectionId(),
            );
            const rotated_cid = established.connection.config
                .peer_connection_id;
            var reset_datagram = [_]u8{0x40} **
                quic.stateless_reset.min_datagram_len;
            const rotated_token = quic.stateless_reset.tokenForConnectionId(
                self.stateless_reset_key,
                rotated_cid,
            );
            @memcpy(
                reset_datagram[reset_datagram.len - rotated_token.len ..],
                &rotated_token,
            );
            const rotated_sequence = established.connection
                .detectStatelessReset(&reset_datagram) orelse
                return error.TestUnexpectedResult;
            try std.testing.expect(rotated_sequence != 0);
            try std.testing.expectEqual(
                @as(usize, 1),
                try established.connection.sendPendingRetireConnectionIds(),
            );
            self.stage = .replacement_cid;
            const cid_deadline = std.Io.Clock.Timestamp.fromNow(self.io, .{
                .raw = .fromSeconds(10),
                .clock = .awake,
            });
            while (true) {
                var packet = try established.connection
                    .receivePacketServicingTimersDeadline(cid_deadline);
                defer packet.deinit(self.allocator);
                var found = false;
                for (packet.frames) |frame| {
                    if (frame != .new_connection_id or
                        frame.new_connection_id.sequence_number != 4) continue;
                    try std.testing.expectEqualSlices(
                        u8,
                        &quic.stateless_reset.tokenForConnectionId(
                            self.stateless_reset_key,
                            frame.new_connection_id.connection_id,
                        ),
                        &frame.new_connection_id.stateless_reset_token,
                    );
                    found = true;
                }
                _ = try established.connection.sendAckForPacketIfNeeded(
                    packet.packet.packet_number,
                    packet.frames,
                );
                if (found) break;
            }
            self.stage = .second_rotation;
            try std.testing.expect(
                try established.connection.switchToNextPeerConnectionId(),
            );
            self.stage = .complete;
        }
    };

    var clients = [_]Client{
        .{ .allocator = allocator, .io = io, .peer = server.address(), .public_key = server_public, .stateless_reset_key = stateless_reset_key, .index = 0 },
        .{ .allocator = allocator, .io = io, .peer = server.address(), .public_key = server_public, .stateless_reset_key = stateless_reset_key, .index = 1 },
    };
    var threads: [clients.len]std.Thread = undefined;
    var started: usize = 0;
    defer for (threads[0..started]) |thread| thread.join();
    for (&clients, &threads) |*client, *thread| {
        thread.* = try std.Thread.spawn(.{}, Client.run, .{client});
        started += 1;
    }

    const versions = [_]u32{
        quic.Version.version_1.wireValue(),
        quic.Version.version_2.wireValue(),
    };
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(15),
        .clock = .awake,
    });
    var replies: usize = 0;
    var receive_storage: [4 * 4096]u8 = undefined;
    var receive_events: [4]endpoint_server.VisitEvent = undefined;
    const Visitor = struct {
        fn visit(
            _: void,
            packet: quic.endpoint_dispatcher.RoutedPacketView,
        ) !void {
            try std.testing.expect(packet.packet.frames.len != 0);
        }
    };
    while (replies < clients.len) {
        const event_count = server.receiveManyVisitingWithDeadline(
            &versions,
            &receive_storage,
            &receive_events,
            deadline,
            {},
            Visitor.visit,
        ) catch |err| {
            std.debug.print(
                "shared endpoint server stage=replies count={d} error={s}\n",
                .{ replies, @errorName(err) },
            );
            return err;
        };
        for (receive_events[0..event_count]) |*event| {
            defer event.deinit(allocator);
            switch (event.*) {
                .connected => |handle| {
                    const established = server.connection(handle) orelse
                        return error.TestUnexpectedResult;
                    try std.testing.expectEqual(
                        @as(?[quic.stateless_reset.static_key_len]u8, stateless_reset_key),
                        established.connection.config
                            .local_stateless_reset_key,
                    );
                    try std.testing.expectEqual(
                        @as(?u64, 1),
                        try server.pollOpenStream(handle),
                    );
                    try std.testing.expectEqual(
                        @as(?u64, 3),
                        try server.pollOpenUnidirectionalStream(handle),
                    );
                    try std.testing.expectEqual(
                        established.connection.streamSendCredit(3),
                        try server.streamSendCredit(handle, 3),
                    );
                },
                .timer => {},
                .handshake_failed => |failure| return failure.err,
                .unrouted => return error.TestUnexpectedResult,
                .packet => |packet| {
                    var request: [8]u8 = undefined;
                    const received = (try server.pollStreamId(
                        packet.connection_handle,
                        0,
                        &request,
                    )) orelse continue;
                    const data = switch (received) {
                        .reset => return error.TestUnexpectedResult,
                        .data => |value| value,
                    };
                    if (!data.fin or data.bytes != request.len or
                        !std.mem.eql(u8, request[0..7], "client-") or
                        request[7] > 1)
                    {
                        return error.TestUnexpectedResult;
                    }
                    try server.trySend(
                        packet.connection_handle,
                        &.{.{ .stream = .{
                            .stream_id = 0,
                            .data = &request,
                            .fin = true,
                        } }},
                    );
                    replies += 1;
                },
            }
        }
    }
    var retirements: usize = 0;
    while (retirements < clients.len) {
        var event = server.receiveWithDeadline(&versions, deadline) catch |err| {
            std.debug.print(
                "shared endpoint server stage=retirements count={d} error={s}\n",
                .{ retirements, @errorName(err) },
            );
            return err;
        };
        defer event.deinit(allocator);
        switch (event) {
            .packet => |*packet| {
                for (packet.packet.frames) |frame| {
                    retirements += @intFromBool(
                        frame == .retire_connection_id and
                            frame.retire_connection_id.sequence_number == 0,
                    );
                }
                _ = try server.acknowledgePacketIfNeeded(packet);
            },
            .timer => {},
            .handshake_failed => |failure| return failure.err,
            .connected, .unrouted => return error.TestUnexpectedResult,
        }
    }

    for (threads) |thread| thread.join();
    started = 0;
    for (clients) |client| if (client.err) |err| return err;
    try std.testing.expect(!std.mem.eql(
        u8,
        &clients[0].preferred_connection_id,
        &clients[1].preferred_connection_id,
    ));
    try std.testing.expect(!std.mem.eql(
        u8,
        &clients[0].preferred_reset_token,
        &clients[1].preferred_reset_token,
    ));
    try std.testing.expectEqual(@as(usize, 2), server.connectionCount());
    try std.testing.expectEqual(clients.len * 4, server.dispatcher.routeCount());
}

test "QUIC endpoint server routes preferred address CID and path validation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    const server_key = try tls_testing.serverKeyPair();
    const server_public = server_key.public_key.toUncompressedSec1();
    const reset_key = [_]u8{0x92} **
        quic.stateless_reset.static_key_len;
    var server = try endpoint_server.Server.init(
        allocator,
        &server_endpoint,
        .{
            .local_connection_id = &.{},
            .alpn_protocol = "netz-preferred-address-test",
            .random = [_]u8{0x33} ** 32,
            .x25519_secret_key = [_]u8{0x34} ** 32,
            .key_exchange_groups = &.{.x25519},
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .identity = .{
                .certificate_chain = &.{&server_public},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = server_key,
                } },
            },
            .initial_one_rtt_config = .{ .enable_pacing = false },
            .handshake_recovery = .{
                .initial_pto_ms = 20,
                .max_pto_ms = 40,
                .max_duration_ms = 2_000,
            },
        },
        .{
            .max_pending_handshakes = 1,
            .max_connections = 1,
            .inbox_capacity = 16,
            .handshake_timeout_ms = 2_000,
            .stateless_reset_key = reset_key,
            .automatic_connection_id_replenishment = false,
            .preferred_address = server_endpoint.address(),
        },
    );
    defer server.deinit();

    const challenge = [_]u8{ 0x93, 1, 2, 3, 4, 5, 6, 7 };
    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        server_address: std.Io.net.IpAddress,
        public_key: [65]u8,
        reset_key: [quic.stateless_reset.static_key_len]u8,
        challenge: [8]u8,
        done: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
            self.done.set(self.io);
        }

        fn runFallible(self: *@This()) !void {
            var endpoint = try quic.runtime.Endpoint.bind(
                self.allocator,
                self.io,
                .{ .ip4 = .loopback(0) },
                .{ .max_datagram_size = 4096 },
            );
            defer endpoint.deinit();
            var established = try quic.handshake.connectWithTimeout(
                &endpoint,
                self.server_address,
                .{
                    .original_destination_connection_id = "preferred-odcid",
                    .local_connection_id = "preferred-client",
                    .server_name = "localhost",
                    .alpn_protocols = &.{"netz-preferred-address-test"},
                    .server_auth = .{
                        .pinned_ecdsa_p256_public_key = self.public_key,
                    },
                    .random = [_]u8{0x35} ** 32,
                    .x25519_secret_key = [_]u8{0x36} ** 32,
                    .key_exchange_groups = &.{.x25519},
                    .cipher_suites = &.{.aes_128_gcm_sha256},
                    .local_transport_parameters = .{
                        .active_connection_id_limit = 2,
                    },
                    .initial_one_rtt_config = .{ .enable_pacing = false },
                    .handshake_recovery = .{
                        .initial_pto_ms = 20,
                        .max_pto_ms = 40,
                        .max_duration_ms = 2_000,
                    },
                },
                .fromSeconds(2),
            );
            defer established.deinit();
            const preferred = established.connection.peerPreferredAddress() orelse
                return error.TestUnexpectedResult;
            try std.testing.expectEqual(
                self.server_address,
                quic.one_rtt.Connection.preferredAddressIp4(preferred).?,
            );
            try std.testing.expectEqualSlices(
                u8,
                &quic.stateless_reset.tokenForConnectionId(
                    self.reset_key,
                    preferred.connection_id,
                ),
                &preferred.stateless_reset_token,
            );
            try established.connection.beginPeerPreferredAddressMigration(
                self.challenge,
                .ipv4,
            );
            try established.connection.sendPendingPathChallenge();

            const deadline = std.Io.Clock.Timestamp.fromNow(self.io, .{
                .raw = .fromSeconds(2),
                .clock = .awake,
            });
            var saw_response = false;
            while (!established.connection.peerAddressValidated()) {
                var packet = try established.connection
                    .receivePacketServicingTimersDeadline(deadline);
                defer packet.deinit(self.allocator);
                for (packet.frames) |frame| {
                    if (frame == .path_response and
                        std.mem.eql(
                            u8,
                            &frame.path_response.data,
                            &self.challenge,
                        ))
                    {
                        saw_response = true;
                    }
                }
                _ = try established.connection.sendAckForPacketIfNeeded(
                    packet.packet.packet_number,
                    packet.frames,
                );
            }
            try std.testing.expect(saw_response);
        }
    };

    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .server_address = server.address(),
        .public_key = server_public,
        .reset_key = reset_key,
        .challenge = challenge,
    };
    const client_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) client_thread.join();

    const versions = [_]u32{quic.Version.version_1.wireValue()};
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(3),
        .clock = .awake,
    });
    var handle: ?quic.endpoint_dispatcher.ConnectionHandle = null;
    var saw_preferred_challenge = false;
    while (!saw_preferred_challenge) {
        var event = try server.receiveWithDeadline(&versions, deadline);
        defer event.deinit(allocator);
        switch (event) {
            .connected => |connected| {
                handle = connected;
                const established = server.connection(connected) orelse
                    return error.TestUnexpectedResult;
                try std.testing.expectEqual(
                    @as(usize, 2),
                    established.connection.localConnectionIdCount(),
                );
                try std.testing.expectEqual(
                    @as(usize, 2),
                    server.dispatcher.routeCount(),
                );
            },
            .packet => |*packet| {
                if (packet.connection_id_sequence != 1) {
                    _ = try server.acknowledgePacketIfNeeded(packet);
                    continue;
                }
                for (packet.packet.frames) |frame| {
                    saw_preferred_challenge =
                        saw_preferred_challenge or
                        (frame == .path_challenge and
                            std.mem.eql(
                                u8,
                                &frame.path_challenge.data,
                                &challenge,
                            ));
                }
                _ = try server.acknowledgePacketIfNeeded(packet);
                const established = server.connection(
                    packet.connection_handle,
                ) orelse return error.TestUnexpectedResult;
                _ = try established.connection.sendPendingPathResponses();
                try server.refreshConnectionTimer(
                    packet.connection_handle,
                );
            },
            .timer => {},
            .handshake_failed => |failure| return failure.err,
            .unrouted => return error.TestUnexpectedResult,
        }
    }
    try std.testing.expect(handle != null);
    client_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "QUIC endpoint server migrates to a distinct preferred endpoint" {
    try testDistinctPreferredEndpoint(.ipv4, false);
}

test "QUIC endpoint server migrates to a distinct IPv6 preferred endpoint" {
    try testDistinctPreferredEndpoint(.ipv6, false);
}

test "QUIC endpoint server validates dual-stack preferred IPv4 path" {
    try testDistinctPreferredEndpoint(.ipv4, true);
}

test "QUIC endpoint server validates dual-stack preferred IPv6 path" {
    try testDistinctPreferredEndpoint(.ipv6, true);
}

test "QUIC endpoint server advertises dual-stack preferred address" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var primary = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer primary.deinit();
    var secondary = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip6 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer secondary.deinit();
    const cid = "dual-stack-cid";
    const token = [_]u8{0x94} ** quic.stateless_reset.token_len;
    const advertised = try endpoint_server.testing.preferredAddressForOptions(
        &primary,
        .{
            .stateless_reset_key = [_]u8{0x93} **
                quic.stateless_reset.static_key_len,
            .preferred_endpoint = &secondary,
            .preferred_additional_address = primary.address(),
        },
        cid,
        token,
    );
    try std.testing.expectEqual(primary.address().ip4.bytes, advertised.ipv4_address);
    try std.testing.expectEqual(primary.address().ip4.port, advertised.ipv4_port);
    try std.testing.expectEqual(secondary.address().ip6.bytes, advertised.ipv6_address);
    try std.testing.expectEqual(secondary.address().ip6.port, advertised.ipv6_port);
    try std.testing.expectEqualStrings(cid, advertised.connection_id);
    try std.testing.expectEqual(token, advertised.stateless_reset_token);

    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(allocator);
    try quic.encodeTransportParametersForSource(
        &wire,
        allocator,
        .{ .preferred_address = advertised },
        .server,
    );
    const parsed = try quic.parseTransportParametersTyped(
        allocator,
        wire.items,
        .server,
    );
    try std.testing.expectEqualDeep(advertised, parsed.preferred_address.?);
}

fn testDistinctPreferredEndpoint(
    comptime family: quic.one_rtt.PreferredAddressFamily,
    comptime dual_stack: bool,
) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const primary_bind: std.Io.net.IpAddress = switch (family) {
        .ipv4 => .{ .ip4 = .loopback(0) },
        .ipv6 => .{ .ip6 = .loopback(0) },
    };
    const preferred_bind: std.Io.net.IpAddress = switch (family) {
        .ipv4 => if (dual_stack)
            .{ .ip6 = .loopback(0) }
        else
            .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 0 } },
        .ipv6 => if (dual_stack)
            .{ .ip4 = .loopback(0) }
        else
            .{ .ip6 = .loopback(0) },
    };

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        primary_bind,
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var preferred_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        preferred_bind,
        .{ .max_datagram_size = 4096 },
    );
    defer preferred_endpoint.deinit();
    const server_key = try tls_testing.serverKeyPair();
    const server_public = server_key.public_key.toUncompressedSec1();
    const reset_key = [_]u8{0x94} **
        quic.stateless_reset.static_key_len;
    var server = try endpoint_server.Server.init(
        allocator,
        &server_endpoint,
        .{
            .local_connection_id = &.{},
            .alpn_protocol = "netz-distinct-preferred-test",
            .random = [_]u8{0x95} ** 32,
            .x25519_secret_key = [_]u8{0x96} ** 32,
            .key_exchange_groups = &.{.x25519},
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .identity = .{
                .certificate_chain = &.{&server_public},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = server_key,
                } },
            },
            .initial_one_rtt_config = .{ .enable_pacing = false },
            .handshake_recovery = .{
                .initial_pto_ms = 20,
                .max_pto_ms = 40,
                .max_duration_ms = 2_000,
            },
        },
        .{
            .max_pending_handshakes = 1,
            .max_connections = 1,
            .inbox_capacity = 16,
            .handshake_timeout_ms = 2_000,
            .stateless_reset_key = reset_key,
            .automatic_connection_id_replenishment = false,
            .preferred_endpoint = &preferred_endpoint,
            .preferred_additional_address = if (dual_stack)
                server_endpoint.address()
            else
                null,
        },
    );
    defer server.deinit();

    const challenge = [_]u8{ 0x97, 1, 2, 3, 4, 5, 6, 7 };
    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        original_address: std.Io.net.IpAddress,
        preferred_address: std.Io.net.IpAddress,
        alternate_address: ?std.Io.net.IpAddress,
        public_key: [65]u8,
        reset_key: [quic.stateless_reset.static_key_len]u8,
        challenge: [8]u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var endpoint = try quic.runtime.Endpoint.bind(
                self.allocator,
                self.io,
                switch (family) {
                    .ipv4 => .{ .ip4 = .loopback(0) },
                    .ipv6 => .{ .ip6 = .loopback(0) },
                },
                .{ .max_datagram_size = 4096 },
            );
            defer endpoint.deinit();
            var established = try quic.handshake.connectWithTimeout(
                &endpoint,
                self.original_address,
                .{
                    .original_destination_connection_id = "distinct-odcid",
                    .local_connection_id = "distinct-client",
                    .server_name = "localhost",
                    .alpn_protocols = &.{"netz-distinct-preferred-test"},
                    .server_auth = .{
                        .pinned_ecdsa_p256_public_key = self.public_key,
                    },
                    .random = [_]u8{0x98} ** 32,
                    .x25519_secret_key = [_]u8{0x99} ** 32,
                    .key_exchange_groups = &.{.x25519},
                    .cipher_suites = &.{.aes_128_gcm_sha256},
                    .local_transport_parameters = .{
                        .active_connection_id_limit = 2,
                    },
                    .initial_one_rtt_config = .{ .enable_pacing = false },
                    .handshake_recovery = .{
                        .initial_pto_ms = 20,
                        .max_pto_ms = 40,
                        .max_duration_ms = 2_000,
                    },
                },
                .fromSeconds(2),
            );
            defer established.deinit();
            const preferred = established.connection.peerPreferredAddress() orelse
                return error.TestUnexpectedResult;
            try std.testing.expectEqual(
                self.preferred_address,
                switch (family) {
                    .ipv4 => quic.one_rtt.Connection
                        .preferredAddressIp4(preferred).?,
                    .ipv6 => quic.one_rtt.Connection
                        .preferredAddressIp6(preferred).?,
                },
            );
            if (self.alternate_address) |alternate| {
                try std.testing.expectEqual(
                    alternate,
                    switch (family) {
                        .ipv4 => quic.one_rtt.Connection
                            .preferredAddressIp6(preferred).?,
                        .ipv6 => quic.one_rtt.Connection
                            .preferredAddressIp4(preferred).?,
                    },
                );
            }
            try established.connection.beginPeerPreferredAddressMigration(
                self.challenge,
                family,
            );
            try established.connection.sendPendingPathChallenge();

            const migration_deadline = std.Io.Clock.Timestamp.fromNow(self.io, .{
                .raw = .fromSeconds(2),
                .clock = .awake,
            });
            while (!established.connection.peerAddressValidated()) {
                var packet = try established.connection
                    .receivePacketServicingTimersDeadline(migration_deadline);
                defer packet.deinit(self.allocator);
                for (packet.frames) |frame| {
                    if (frame == .path_response) {
                        try std.testing.expectEqual(
                            self.preferred_address,
                            packet.from,
                        );
                    }
                }
                _ = try established.connection.sendAckForPacketIfNeeded(
                    packet.packet.packet_number,
                    packet.frames,
                );
            }
            try std.testing.expectEqual(
                self.preferred_address,
                established.connection.peerAddress(),
            );
            try established.connection.send(&.{.{ .ping = {} }});
            try established.connection.send(&.{.{ .stream = .{
                .stream_id = 0,
                .data = "zero-copy",
                .fin = true,
            } }});
            const response_deadline = std.Io.Clock.Timestamp.fromNow(self.io, .{
                .raw = .fromSeconds(2),
                .clock = .awake,
            });
            var saw_ping = false;
            while (!saw_ping) {
                var response = try established.connection
                    .receivePacketServicingTimersDeadline(response_deadline);
                defer response.deinit(self.allocator);
                try std.testing.expectEqual(
                    self.preferred_address,
                    response.from,
                );
                for (response.frames) |frame| {
                    saw_ping = saw_ping or frame == .ping;
                }
                _ = try established.connection.sendAckForPacketIfNeeded(
                    response.packet.packet_number,
                    response.frames,
                );
            }

            var unknown_cid = [_]u8{0xa1} **
                quic.endpoint_dispatcher.default_server_connection_id_len;
            unknown_cid[0] = 0xa2;
            var reset_trigger = [_]u8{0xa3} ** 64;
            reset_trigger[0] = 0x40;
            @memcpy(reset_trigger[1..][0..unknown_cid.len], &unknown_cid);
            try endpoint.sendBytes(self.preferred_address, &reset_trigger);
            const expected_token = quic.stateless_reset.tokenForConnectionId(
                self.reset_key,
                &unknown_cid,
            );
            const reset_deadline = std.Io.Clock.Timestamp.fromNow(self.io, .{
                .raw = .fromSeconds(2),
                .clock = .awake,
            });
            while (true) {
                var reset = try endpoint.receiveBytesWithDeadline(
                    reset_deadline,
                );
                defer reset.deinit(self.allocator);
                try std.testing.expectEqual(
                    self.preferred_address,
                    reset.from,
                );
                if (quic.stateless_reset.matches(
                    reset.bytes,
                    expected_token,
                )) break;
            }
            try established.connection.send(&.{.{ .ping = {} }});
        }
    };

    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .original_address = server.address(),
        .preferred_address = if (dual_stack)
            server_endpoint.address()
        else
            preferred_endpoint.address(),
        .alternate_address = if (dual_stack)
            preferred_endpoint.address()
        else
            null,
        .public_key = server_public,
        .reset_key = reset_key,
        .challenge = challenge,
    };
    const client_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) client_thread.join();

    const versions = [_]u32{quic.Version.version_1.wireValue()};
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(5),
        .clock = .awake,
    });
    var handle: ?quic.endpoint_dispatcher.ConnectionHandle = null;
    var saw_preferred_ping = false;
    while (!saw_preferred_ping) {
        var event = try server.receiveWithDeadline(&versions, deadline);
        defer event.deinit(allocator);
        switch (event) {
            .connected => |connected| handle = connected,
            .packet => |*packet| {
                if (packet.connection_id_sequence != 1) {
                    _ = try server.acknowledgePacketIfNeeded(packet);
                    continue;
                }
                const established = server.connection(
                    packet.connection_handle,
                ) orelse return error.TestUnexpectedResult;
                for (packet.packet.frames) |frame| {
                    if (frame == .path_challenge and
                        std.mem.eql(
                            u8,
                            &frame.path_challenge.data,
                            &challenge,
                        ))
                    {
                        _ = try established.connection
                            .sendPendingPathResponses();
                    }
                    if (frame == .ping) {
                        saw_preferred_ping = true;
                        try server.trySend(
                            packet.connection_handle,
                            &.{.{ .ping = {} }},
                        );
                    }
                }
                _ = try server.acknowledgePacketIfNeeded(packet);
            },
            .timer => {},
            .handshake_failed => |failure| return failure.err,
            .unrouted => return error.TestUnexpectedResult,
        }
    }
    const established = server.connection(handle orelse
        return error.TestUnexpectedResult) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(
        if (dual_stack) server_endpoint.address() else preferred_endpoint.address(),
        established.connection.sendEndpoint().address(),
    );
    const VisitContext = struct {
        ping_count: usize = 0,
        saw_stream: bool = false,
        storage: []const u8,
        preferred_storage: []const u8,
    };
    const Visitor = struct {
        fn visit(
            visit_context: *VisitContext,
            packet: quic.endpoint_dispatcher.RoutedPacketView,
        ) !void {
            try std.testing.expectEqual(@as(u64, 1), packet.connection_id_sequence);
            for (packet.packet.frames) |frame| {
                visit_context.ping_count += @intFromBool(frame == .ping);
                if (frame == .stream) {
                    try std.testing.expectEqualStrings(
                        "zero-copy",
                        frame.stream.data,
                    );
                    const data_start = @intFromPtr(frame.stream.data.ptr);
                    const storage_start = @intFromPtr(
                        visit_context.storage.ptr,
                    );
                    const preferred_start = @intFromPtr(
                        visit_context.preferred_storage.ptr,
                    );
                    const in_primary = data_start >= storage_start and
                        data_start + frame.stream.data.len <=
                            storage_start + visit_context.storage.len;
                    const in_preferred = data_start >= preferred_start and
                        data_start + frame.stream.data.len <=
                            preferred_start +
                                visit_context.preferred_storage.len;
                    try std.testing.expect(in_primary or in_preferred);
                    visit_context.saw_stream = true;
                }
            }
        }
    };
    var visitor_storage: [2 * 4096]u8 = undefined;
    var visit_context = VisitContext{
        .storage = &visitor_storage,
        .preferred_storage = server.preferred_receive_storage,
    };
    var visitor_events: [2]endpoint_server.VisitEvent = undefined;
    const visitor_deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    });
    while (!visit_context.saw_stream or visit_context.ping_count == 0) {
        const count = try server.receiveManyVisitingWithDeadline(
            &versions,
            &visitor_storage,
            &visitor_events,
            visitor_deadline,
            &visit_context,
            Visitor.visit,
        );
        try std.testing.expect(count != 0);
        for (visitor_events[0..count]) |*event| {
            defer event.deinit(allocator);
            switch (event.*) {
                .packet, .timer => {},
                .handshake_failed => |failure| return failure.err,
                .connected, .unrouted => return error.TestUnexpectedResult,
            }
        }
    }
    try std.testing.expect(visit_context.saw_stream);
    try std.testing.expect(visit_context.ping_count >= 1);
    try std.testing.expect(server.multi_endpoint_view_count >= 2);
    try std.testing.expect(server.multi_endpoint_owning_count >= 1);
    client_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "QUIC multi-endpoint visitor preserves transport state after callback error" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var primary = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer primary.deinit();
    var preferred = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer preferred.deinit();
    var peer = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb1} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&primary, .{
        .peer = peer.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "server-local",
        .peer_connection_id = "peer-local",
        .local_endpoint = .server,
    });
    defer connection.deinit();
    try connection.registerLocalPreferredEndpoint(&preferred);
    var server = try endpoint_server.Server.init(
        allocator,
        &primary,
        .{ .local_connection_id = &.{} },
        .{
            .stateless_reset_key = [_]u8{0xb2} **
                quic.stateless_reset.static_key_len,
            .preferred_endpoint = &preferred,
        },
    );
    defer server.deinit();
    const handle: quic.endpoint_dispatcher.ConnectionHandle = 41;
    try server.dispatcher.registerConnection(handle, &connection);
    errdefer _ = server.dispatcher.unregisterConnection(handle) catch false;

    try quic.one_rtt.sendFrames(
        &peer,
        preferred.address(),
        keys,
        .{
            .destination_connection_id = "server-local",
            .packet_number = 0,
            .frames = &.{.{ .ping = {} }},
        },
    );
    const Visitor = struct {
        fn visit(
            _: void,
            _: quic.endpoint_dispatcher.RoutedPacketView,
        ) error{Rejected}!void {
            return error.Rejected;
        }
    };
    var storage: [4096]u8 = undefined;
    try std.testing.expectError(
        error.Rejected,
        server.receiveVisitingWithDeadline(
            &.{quic.Version.version_1.wireValue()},
            &storage,
            .fromNow(io, .{
                .clock = .awake,
                .raw = .fromSeconds(1),
            }),
            {},
            Visitor.visit,
        ),
    );
    try std.testing.expectEqual(@as(u64, 1), connection.stats().packets_received);
    try std.testing.expectEqual(&preferred, connection.sendEndpoint());
    try server.dispatcher.refreshConnectionTimer(handle);
    try std.testing.expect(try server.dispatcher.unregisterConnection(handle));
}

test "QUIC endpoint server resets a client after connection state loss" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    const server_key = try tls_testing.serverKeyPair();
    const server_public = server_key.public_key.toUncompressedSec1();
    const reset_key = [_]u8{0xa7} **
        quic.stateless_reset.static_key_len;
    var server = try endpoint_server.Server.init(
        allocator,
        &server_endpoint,
        .{
            .local_connection_id = &.{},
            .alpn_protocol = "netz-reset-after-state-loss",
            .random = [_]u8{0xa8} ** 32,
            .x25519_secret_key = [_]u8{0xa9} ** 32,
            .key_exchange_groups = &.{.x25519},
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .identity = .{
                .certificate_chain = &.{&server_public},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = server_key,
                } },
            },
            .initial_one_rtt_config = .{ .enable_pacing = false },
            .handshake_recovery = .{
                .initial_pto_ms = 20,
                .max_pto_ms = 40,
                .max_duration_ms = 2_000,
            },
        },
        .{
            .max_pending_handshakes = 1,
            .max_connections = 1,
            .handshake_timeout_ms = 2_000,
            .stateless_reset_key = reset_key,
            .automatic_connection_id_replenishment = false,
        },
    );
    defer server.deinit();

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        server_address: std.Io.net.IpAddress,
        public_key: [65]u8,
        reset_key: [quic.stateless_reset.static_key_len]u8,
        connected: std.Io.Event = .unset,
        state_removed: std.Io.Event = .unset,
        done: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.connected.set(self.io);
            };
            self.done.set(self.io);
        }

        fn runFallible(self: *@This()) !void {
            var endpoint = try quic.runtime.Endpoint.bind(
                self.allocator,
                self.io,
                .{ .ip4 = .loopback(0) },
                .{ .max_datagram_size = 4096 },
            );
            defer endpoint.deinit();
            var established = try quic.handshake.connectWithTimeout(
                &endpoint,
                self.server_address,
                .{
                    .original_destination_connection_id = "reset-old",
                    .local_connection_id = "reset-client",
                    .server_name = "localhost",
                    .alpn_protocols = &.{"netz-reset-after-state-loss"},
                    .server_auth = .{
                        .pinned_ecdsa_p256_public_key = self.public_key,
                    },
                    .random = [_]u8{0xaa} ** 32,
                    .x25519_secret_key = [_]u8{0xab} ** 32,
                    .key_exchange_groups = &.{.x25519},
                    .cipher_suites = &.{.aes_128_gcm_sha256},
                    .initial_one_rtt_config = .{ .enable_pacing = false },
                    .handshake_recovery = .{
                        .initial_pto_ms = 20,
                        .max_pto_ms = 40,
                        .max_duration_ms = 2_000,
                    },
                },
                .fromSeconds(2),
            );
            defer established.deinit();
            const expected = quic.stateless_reset.tokenForConnectionId(
                self.reset_key,
                established.peer_connection_id,
            );
            try std.testing.expectEqual(
                @as(?[quic.stateless_reset.token_len]u8, expected),
                established.connection.config.peer_stateless_reset_token,
            );
            self.connected.set(self.io);
            try self.state_removed.wait(self.io);

            try established.connection.sendWithTimeout(
                &.{.{ .ping = {} }},
                .fromSeconds(1),
            );
            const deadline = std.Io.Clock.Timestamp.fromNow(self.io, .{
                .raw = .fromSeconds(2),
                .clock = .awake,
            });
            while (true) {
                var packet = established.connection
                    .receivePacketServicingTimersDeadline(deadline) catch |err|
                    switch (err) {
                        error.ConnectionClosed => break,
                        else => return err,
                    };
                defer packet.deinit(self.allocator);
                _ = try established.connection.sendAckForPacketIfNeeded(
                    packet.packet.packet_number,
                    packet.frames,
                );
            }
            try std.testing.expect(established.connection.draining());
            try std.testing.expect(
                established.connection.closeExpiryDeadlineMillis() != null,
            );
            try std.testing.expectEqual(
                @as(u64, 0),
                established.connection.authenticationFailureCount(),
            );
        }
    };

    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .server_address = server.address(),
        .public_key = server_public,
        .reset_key = reset_key,
    };
    const client_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.state_removed.set(io);
        client_thread.join();
    };

    const versions = [_]u32{quic.Version.version_1.wireValue()};
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(3),
        .clock = .awake,
    });
    var handle: ?quic.endpoint_dispatcher.ConnectionHandle = null;
    while (handle == null) {
        var event = try server.receiveWithDeadline(&versions, deadline);
        defer event.deinit(allocator);
        switch (event) {
            .connected => |connected| handle = connected,
            .timer, .packet => {},
            .handshake_failed => |failure| return failure.err,
            .unrouted => return error.TestUnexpectedResult,
        }
    }
    try shared.connected.wait(io);
    if (shared.err) |err| {
        client_thread.join();
        joined = true;
        return err;
    }
    try std.testing.expectEqual(@as(usize, 1), server.connectionCount());
    try std.testing.expectEqual(@as(usize, 1), server.dispatcher.routeCount());
    try std.testing.expect(try server.removeConnection(handle.?));
    try std.testing.expectEqual(@as(usize, 0), server.connectionCount());
    try std.testing.expectEqual(@as(usize, 0), server.dispatcher.routeCount());
    shared.state_removed.set(io);

    while (!shared.done.isSet()) {
        if (deadline.durationFromNow(io).raw.nanoseconds <= 0) {
            return error.Timeout;
        }
        if (try server.receiveOnce(
            &versions,
            .{ .raw = .fromMilliseconds(20), .clock = .awake },
        )) |event_value| {
            var event = event_value;
            defer event.deinit(allocator);
            return error.TestUnexpectedResult;
        }
    }
    client_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}
