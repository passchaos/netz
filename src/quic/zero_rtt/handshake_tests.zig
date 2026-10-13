const std = @import("std");
const quic = @import("../mod.zig");

const handshake = quic.handshake;

test "QUIC integrated handshake accepts authenticated 0-RTT stream data" {
    try runEarlyData(.aes_128_gcm_sha256, false, false, 1500, .accepted);
}

test "QUIC integrated handshake accepts ChaCha20 0-RTT and 1-RTT data" {
    try runEarlyData(.chacha20_poly1305_sha256, false, false, 1500, .accepted);
}

test "QUIC integrated handshake accepts AES-256 SHA-384 0-RTT and 1-RTT" {
    try runEarlyData(.aes_256_gcm_sha384, false, false, 1500, .accepted);
}

test "QUIC integrated handshake preserves retransmitted 0-RTT packet numbers" {
    try runEarlyData(.aes_128_gcm_sha256, true, false, 1500, .accepted);
}

test "QUIC integrated handshake retires socket-rejected 0-RTT packet number" {
    try runEarlyData(.aes_128_gcm_sha256, false, true, 1500, .accepted);
}

test "QUIC ticket age skew rejects 0-RTT but resumes with PSK" {
    try runEarlyData(.aes_128_gcm_sha256, false, false, 20_000, .rejected);
}

test "QUIC Version Negotiation reports prior 0-RTT offer as rejected" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();
    const ticket = "vn-early-ticket";
    const psk = [_]u8{0xda} ** 32;
    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(earlyTicket(
        ticket,
        .fromSha256(psk),
        .aes_128_gcm_sha256,
    ));
    var lease = (try cache.beginEarlyData(
        "localhost:443",
        "h3",
        1500,
    )).?;
    defer lease.deinit();

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        err: ?anyerror = null,
        resumed: bool = false,
        status: quic.zero_rtt.handshake.Status = .not_offered,
        first_one_rtt_packet_number: ?u64 = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var first_initial = try self.endpoint.receiveBytes();
            defer first_initial.deinit(self.endpoint.allocator);
            const first_header = try quic.LongHeader.parse(first_initial.bytes);
            try std.testing.expectEqual(
                quic.Version.version_1.wireValue(),
                first_header.version,
            );
            try std.testing.expectEqual(
                quic.PacketType.initial,
                first_header.packet_type,
            );

            var first_early = try self.endpoint.receiveBytes();
            defer first_early.deinit(self.endpoint.allocator);
            const early_info = try quic.protection
                .peekProtectedLongPacketInfo(first_early.bytes);
            try std.testing.expectEqual(
                quic.Version.version_1.wireValue(),
                early_info.version,
            );
            try std.testing.expectEqual(
                quic.protection.ProtectedLongPacketType.zero_rtt,
                early_info.packet_type,
            );

            var vn: std.ArrayList(u8) = .empty;
            defer vn.deinit(self.endpoint.allocator);
            try quic.writeVersionNegotiationPacket(
                &vn,
                self.endpoint.allocator,
                .{
                    .destination_connection_id = first_header.source_connection_id,
                    .source_connection_id = first_header.destination_connection_id,
                    .versions = &.{quic.Version.version_2.wireValue()},
                },
            );
            try self.endpoint.sendBytes(first_initial.from, vn.items);

            var established = try handshake.accept(self.endpoint, .{
                .version = .version_2,
                .available_versions = &.{.version_2},
                .local_connection_id = "server",
                .random = [_]u8{0xdb} ** 32,
                .x25519_secret_key = [_]u8{0xdc} ** 32,
                .key_exchange_groups = &.{.x25519},
                .psk = .{
                    .identity = ticket,
                    .secret = psk,
                    .age_add = 17,
                    .issued_at_ms = 1000,
                    .lifetime_seconds = 3600,
                    .now_ms = 1500,
                },
            });
            defer established.deinit();
            self.resumed = established.resumed;
            self.status = established.early_data_status;
            var packet = try established.connection.receivePacket();
            defer packet.deinit(self.endpoint.allocator);
            self.first_one_rtt_packet_number = packet.packet.packet_number;
        }
    };
    var shared = Shared{ .endpoint = &server_endpoint };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const early_frames = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = "old-version-early",
        .fin = true,
    } }};
    var established = try handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .version = .version_1,
            .available_versions = &.{ .version_2, .version_1 },
            .original_destination_connection_id = "vnearly1",
            .local_connection_id = "client",
            .random = [_]u8{0xdd} ** 32,
            .x25519_secret_key = [_]u8{0xde} ** 32,
            .key_exchange_groups = &.{.x25519},
            .resumption_now_ms = 1500,
            .resumption_server_id = "localhost:443",
            .early_data = .{
                .cache = &cache,
                .lease = &lease,
                .frames = &early_frames,
            },
        },
    );
    defer established.deinit();
    try std.testing.expect(established.resumed);
    try std.testing.expectEqual(
        quic.zero_rtt.handshake.Status.rejected,
        established.early_data_status,
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        established.early_data_protected_packet_count,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        established.early_data_sent_packet_count,
    );
    try std.testing.expectEqual(@as(u64, 0), established.connection.next_packet_number);
    try established.connection.send(&.{.{ .ping = {} }});

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.resumed);
    try std.testing.expectEqual(
        quic.zero_rtt.handshake.Status.not_offered,
        shared.status,
    );
    try std.testing.expectEqual(@as(?u64, 0), shared.first_one_rtt_packet_number);
    try std.testing.expectEqual(.consumed, lease.state);
}

fn runEarlyData(
    cipher_suite: quic.tls_client_hello.CipherSuite,
    drop_first_server_flight: bool,
    reject_first_client_zero_rtt: bool,
    server_now_ms: u64,
    expected_status: quic.zero_rtt.handshake.Status,
) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();
    const RejectFirstZeroRtt = struct {
        delegate: std.Io,
        enabled: bool,
        rejected: bool = false,

        fn netSend(
            userdata: ?*anyopaque,
            socket_handle: std.Io.net.Socket.Handle,
            messages: []std.Io.net.OutgoingMessage,
            flags: std.Io.net.SendFlags,
        ) struct { ?std.Io.net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(userdata));
            if (self.enabled and !self.rejected and messages.len == 1) {
                const bytes = messages[0].data_ptr[0..messages[0].data_len];
                if (bytes.len >= 5 and
                    std.mem.readInt(u32, bytes[1..5], .big) ==
                        quic.Version.version_1.wireValue() and
                    (bytes[0] & 0x30) == 0x10)
                {
                    self.rejected = true;
                    return .{ error.NetworkDown, 0 };
                }
            }
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        }
    };
    var reject = RejectFirstZeroRtt{
        .delegate = client_endpoint.io,
        .enabled = reject_first_client_zero_rtt,
    };
    var rejecting_vtable = client_endpoint.io.vtable.*;
    rejecting_vtable.netSend = RejectFirstZeroRtt.netSend;
    client_endpoint.io = .{
        .userdata = &reject,
        .vtable = &rejecting_vtable,
    };
    defer client_endpoint.io = reject.delegate;

    const ticket = "early-ticket";
    const psk = pskForSuite(cipher_suite);
    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(earlyTicket(ticket, psk, cipher_suite));
    var lease = (try cache.beginEarlyData("localhost:443", "h3", 1500)).?;
    defer lease.deinit();
    var replay_filter = try quic.zero_rtt.ReplayFilter.init(
        allocator,
        io,
        8,
    );
    defer replay_filter.deinit();

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        replay_filter: *quic.zero_rtt.ReplayFilter,
        ticket: []const u8,
        psk: [32]u8,
        psk_secret: quic.tls.secret.Secret,
        cipher_suite: quic.tls_client_hello.CipherSuite,
        now_ms: u64,
        drop_first_server_flight: bool,
        err: ?anyerror = null,
        resumed: bool = false,
        early_data_status: quic.zero_rtt.handshake.Status = .not_offered,
        early_data: ?[]u8 = null,

        fn dropFirst(attempt: u8) bool {
            return attempt == 0;
        }

        fn run(shared: *@This()) void {
            var established = handshake.accept(shared.endpoint, .{
                .local_connection_id = "server",
                .random = [_]u8{0xb2} ** 32,
                .x25519_secret_key = [_]u8{0xb3} ** 32,
                .psk = .{
                    .identity = shared.ticket,
                    .secret = shared.psk,
                    .secret_value = shared.psk_secret,
                    .age_add = 17,
                    .issued_at_ms = 1000,
                    .lifetime_seconds = 3600,
                    .now_ms = shared.now_ms,
                    .cipher_suite = shared.cipher_suite,
                },
                .early_data = .{
                    .accept = true,
                    .replay_filter = shared.replay_filter,
                    .replay_key = "request-1",
                },
                .handshake_recovery = .{
                    .initial_pto_ms = 20,
                    .max_pto_ms = 20,
                    .max_retries = 3,
                    .should_drop = if (shared.drop_first_server_flight)
                        dropFirst
                    else
                        null,
                },
                .cipher_suites = &.{shared.cipher_suite},
            }) catch |err| {
                shared.err = err;
                return;
            };
            defer established.deinit();
            shared.resumed = established.resumed;
            shared.early_data_status = established.early_data_status;
            shared.early_data = established.connection.copyReceivedStream(
                shared.endpoint.allocator,
                0,
            ) catch |err| {
                shared.err = err;
                return;
            };
        }
    };
    var shared = Shared{
        .endpoint = &server_endpoint,
        .replay_filter = &replay_filter,
        .ticket = ticket,
        .psk = if (psk.hash == .sha256)
            psk.sha256() catch unreachable
        else
            [_]u8{0} ** 32,
        .psk_secret = psk,
        .cipher_suite = cipher_suite,
        .now_ms = server_now_ms,
        .drop_first_server_flight = drop_first_server_flight,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const frames = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = "early request",
        .fin = true,
    } }};
    var established = try handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = "12345678",
            .local_connection_id = "client",
            .random = [_]u8{0xb4} ** 32,
            .x25519_secret_key = [_]u8{0xb5} ** 32,
            .key_exchange_groups = &.{
                .x25519_mlkem768,
                .x25519,
            },
            .cipher_suites = &.{cipher_suite},
            .resumption_now_ms = 1500,
            .resumption_server_id = "localhost:443",
            .early_data = .{
                .cache = &cache,
                .lease = &lease,
                .frames = &frames,
            },
            .handshake_recovery = .{
                .initial_pto_ms = 5,
                .max_pto_ms = 10,
                .max_retries = 5,
            },
        },
    );
    defer established.deinit();
    thread.join();
    defer if (shared.early_data) |bytes| allocator.free(bytes);
    if (shared.err) |err| return err;

    try std.testing.expect(established.resumed);
    try std.testing.expectEqual(
        cipher_suite,
        established.connection.config.send_keys.suite,
    );
    try std.testing.expectEqual(
        expected_status,
        established.early_data_status,
    );
    try std.testing.expect(shared.resumed);
    try std.testing.expectEqual(
        expected_status,
        shared.early_data_status,
    );
    try std.testing.expectEqual(
        @as(usize, if (expected_status == .accepted) 1 else 0),
        replay_filter.count(),
    );
    if (expected_status == .accepted) {
        try std.testing.expectEqualStrings(
            "early request",
            shared.early_data orelse return error.TestUnexpectedResult,
        );
    } else {
        try std.testing.expect(shared.early_data == null);
    }
    try std.testing.expectEqual(.consumed, lease.state);
    const protected_early_data_packets =
        established.early_data_protected_packet_count;
    const sent_early_data_packets =
        established.early_data_sent_packet_count;
    try std.testing.expectEqual(
        protected_early_data_packets,
        established.connection.next_packet_number,
    );
    try std.testing.expect(sent_early_data_packets >= 1);
    if (drop_first_server_flight)
        try std.testing.expect(protected_early_data_packets > 1);
    if (reject_first_client_zero_rtt) {
        try std.testing.expect(reject.rejected);
        try std.testing.expectEqual(@as(u64, 2), protected_early_data_packets);
        try std.testing.expectEqual(@as(usize, 1), sent_early_data_packets);
        try std.testing.expect(
            quic.one_rtt.testing.recoveryPayloadForPacket(
                &established.connection,
                0,
            ) == null,
        );
        try std.testing.expect(
            quic.one_rtt.testing.recoveryPayloadForPacket(
                &established.connection,
                1,
            ) != null,
        );
    }
    if (expected_status == .accepted) {
        try std.testing.expectEqual(
            sent_early_data_packets,
            established.connection.stats().sent_packet_stats.tracked_packets,
        );
        try std.testing.expectEqual(
            sent_early_data_packets,
            established.connection.stats().recovery_queue_stats.packet_number_copies,
        );
    } else {
        try std.testing.expectEqual(
            @as(usize, 0),
            established.connection.stats().sent_packet_stats.tracked_packets,
        );
        try std.testing.expectEqual(
            @as(usize, 0),
            established.connection.pendingRecoveryCount(),
        );
        try std.testing.expect(established.connection.sendStreamStats(0) == null);
    }
    // X25519MLKEM768 makes ClientHello exceed one 1200-byte Initial. Reaching
    // this assertion proves the server consumed the following standalone
    // 0-RTT datagram after cross-datagram Initial CRYPTO reassembly.
    try established.connection.send(&.{.{ .ping = {} }});
    var one_rtt = try sharedEndpointReceive(
        &server_endpoint,
        established.connection.config.send_keys,
        protected_early_data_packets,
    );
    try std.testing.expectEqual(
        protected_early_data_packets,
        one_rtt.packet.packet_number,
    );
    one_rtt.deinit(allocator);
}

test "QUIC integrated handshake rejects 0-RTT but resumes with PSK" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();
    const RejectFirstZeroRtt = struct {
        delegate: std.Io,
        rejected: bool = false,

        fn netSend(
            userdata: ?*anyopaque,
            socket_handle: std.Io.net.Socket.Handle,
            messages: []std.Io.net.OutgoingMessage,
            flags: std.Io.net.SendFlags,
        ) struct { ?std.Io.net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(userdata));
            if (!self.rejected and messages.len == 1) {
                const bytes = messages[0].data_ptr[0..messages[0].data_len];
                if (bytes.len >= 5 and
                    std.mem.readInt(u32, bytes[1..5], .big) ==
                        quic.Version.version_1.wireValue() and
                    (bytes[0] & 0x30) == 0x10)
                {
                    self.rejected = true;
                    return .{ error.NetworkDown, 0 };
                }
            }
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        }
    };
    var reject = RejectFirstZeroRtt{ .delegate = client_endpoint.io };
    var rejecting_vtable = client_endpoint.io.vtable.*;
    rejecting_vtable.netSend = RejectFirstZeroRtt.netSend;
    client_endpoint.io = .{
        .userdata = &reject,
        .vtable = &rejecting_vtable,
    };
    defer client_endpoint.io = reject.delegate;

    const ticket = "rejected-ticket";
    const psk = [_]u8{0xc1} ** 32;
    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(earlyTicket(
        ticket,
        .fromSha256(psk),
        .aes_128_gcm_sha256,
    ));
    var lease = (try cache.beginEarlyData("localhost:443", "h3", 1500)).?;
    defer lease.deinit();
    var replay_filter = try quic.zero_rtt.ReplayFilter.init(
        allocator,
        io,
        8,
    );
    defer replay_filter.deinit();

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        replay_filter: *quic.zero_rtt.ReplayFilter,
        ticket: []const u8,
        psk: [32]u8,
        err: ?anyerror = null,
        resumed: bool = false,
        status: quic.zero_rtt.handshake.Status = .not_offered,

        fn run(shared: *@This()) void {
            var established = handshake.accept(shared.endpoint, .{
                .local_connection_id = "server",
                .random = [_]u8{0xc2} ** 32,
                .x25519_secret_key = [_]u8{0xc3} ** 32,
                .psk = .{
                    .identity = shared.ticket,
                    .secret = shared.psk,
                    .age_add = 17,
                    .issued_at_ms = 1000,
                    .lifetime_seconds = 3600,
                    .now_ms = 1500,
                },
                // The ticket was issued under AES. Selecting ChaCha remains
                // valid for PSK-DHE resumption because both suites use
                // SHA-256, but RFC 8446 requires rejecting 0-RTT when the
                // selected AEAD differs from the ticket's suite.
                .cipher_suites = &.{.chacha20_poly1305_sha256},
                .early_data = .{
                    .accept = true,
                    .replay_filter = shared.replay_filter,
                    .replay_key = "suite-mismatch",
                },
            }) catch |err| {
                shared.err = err;
                return;
            };
            shared.resumed = established.resumed;
            shared.status = established.early_data_status;
            established.deinit();
        }
    };
    var shared = Shared{
        .endpoint = &server_endpoint,
        .replay_filter = &replay_filter,
        .ticket = ticket,
        .psk = psk,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const frames = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = "discard me",
    } }};
    var established = try handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = "87654321",
            .local_connection_id = "client",
            .random = [_]u8{0xc4} ** 32,
            .x25519_secret_key = [_]u8{0xc5} ** 32,
            .resumption_now_ms = 1500,
            .resumption_server_id = "localhost:443",
            .early_data = .{
                .cache = &cache,
                .lease = &lease,
                .frames = &frames,
            },
            .handshake_recovery = .{
                .initial_pto_ms = 5,
                .max_pto_ms = 10,
                .max_retries = 5,
            },
        },
    );
    defer established.deinit();
    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expect(established.resumed);
    try std.testing.expectEqual(
        quic.tls_client_hello.CipherSuite.chacha20_poly1305_sha256,
        established.connection.config.send_keys.suite,
    );
    try std.testing.expectEqual(
        quic.zero_rtt.handshake.Status.rejected,
        established.early_data_status,
    );
    try std.testing.expect(shared.resumed);
    try std.testing.expectEqual(
        quic.zero_rtt.handshake.Status.rejected,
        shared.status,
    );
    try std.testing.expectEqual(.consumed, lease.state);
    try std.testing.expect(reject.rejected);
    try std.testing.expectEqual(
        @as(u64, 2),
        established.early_data_protected_packet_count,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        established.early_data_sent_packet_count,
    );
    try std.testing.expectEqual(@as(u64, 2), established.connection.next_packet_number);
    try std.testing.expectEqual(
        @as(usize, 0),
        established.connection.stats().sent_packet_stats.tracked_packets,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        established.connection.pendingRecoveryCount(),
    );
    try std.testing.expect(established.connection.sendStreamStats(0) == null);
}

test "QUIC integrated server replay gate rejects a repeated early-data key" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();

    const ticket = "replayed-ticket";
    const psk = [_]u8{0xd1} ** 32;
    var cache = try quic.resumption.Cache.init(allocator, 1);
    defer cache.deinit();
    try cache.store(earlyTicket(
        ticket,
        .fromSha256(psk),
        .aes_128_gcm_sha256,
    ));
    var lease = (try cache.beginEarlyData("localhost:443", "h3", 1500)).?;
    defer lease.deinit();
    var replay_filter = try quic.zero_rtt.ReplayFilter.init(
        allocator,
        io,
        8,
    );
    defer replay_filter.deinit();
    try replay_filter.checkAndMark(
        "duplicate-request",
        1400,
        3_601_000,
    );

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        replay_filter: *quic.zero_rtt.ReplayFilter,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var established = handshake.accept(shared.endpoint, .{
                .local_connection_id = "server",
                .random = [_]u8{0xd2} ** 32,
                .x25519_secret_key = [_]u8{0xd3} ** 32,
                .psk = .{
                    .identity = ticket,
                    .secret = psk,
                    .age_add = 17,
                    .issued_at_ms = 1000,
                    .lifetime_seconds = 3600,
                    .now_ms = 1500,
                },
                .early_data = .{
                    .accept = true,
                    .replay_filter = shared.replay_filter,
                    .replay_key = "duplicate-request",
                },
            }) catch |err| {
                shared.err = err;
                return;
            };
            established.deinit();
        }
    };
    var shared = Shared{
        .endpoint = &server_endpoint,
        .replay_filter = &replay_filter,
    };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const Client = struct {
        endpoint: *quic.runtime.Endpoint,
        peer: std.Io.net.IpAddress,
        cache: *quic.resumption.Cache,
        lease: *quic.resumption.EarlyDataLease,
        err: ?anyerror = null,

        fn run(client: *@This()) void {
            const frames = [_]quic.Frame{.{ .stream = .{
                .stream_id = 0,
                .data = "replayed",
            } }};
            var established = handshake.connect(
                client.endpoint,
                client.peer,
                .{
                    .original_destination_connection_id = "replay01",
                    .local_connection_id = "client",
                    .random = [_]u8{0xd4} ** 32,
                    .x25519_secret_key = [_]u8{0xd5} ** 32,
                    .resumption_now_ms = 1500,
                    .resumption_server_id = "localhost:443",
                    .early_data = .{
                        .cache = client.cache,
                        .lease = client.lease,
                        .frames = &frames,
                    },
                },
            ) catch |err| {
                client.err = err;
                return;
            };
            established.deinit();
        }
    };
    var client = Client{
        .endpoint = &client_endpoint,
        .peer = server_endpoint.address(),
        .cache = &cache,
        .lease = &lease,
    };
    const client_thread = try std.Thread.spawn(.{}, Client.run, .{&client});
    server_thread.join();
    try std.testing.expectEqualStrings(
        "ReplayedEarlyData",
        @errorName(shared.err orelse return error.TestUnexpectedResult),
    );
    try server_endpoint.sendBytes(client_endpoint.address(), "invalid");
    client_thread.join();
    try std.testing.expect(client.err != null);
    try std.testing.expectEqual(.consumed, lease.state);
}

fn earlyTicket(
    ticket: []const u8,
    psk: quic.tls.secret.Secret,
    cipher_suite: quic.tls_client_hello.CipherSuite,
) quic.resumption.Ticket {
    return .{
        .server_id = "localhost:443",
        .alpn = "h3",
        .ticket = ticket,
        .psk = if (psk.hash == .sha256)
            psk.sha256() catch unreachable
        else
            [_]u8{0} ** 32,
        .psk_secret = psk,
        .issued_at_ms = 1000,
        .lifetime_seconds = 3600,
        .age_add = 17,
        .cipher_suite = cipher_suite,
        .max_early_data_size = quic.resumption.cache.quic_early_data_size,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    };
}

fn pskForSuite(
    suite: quic.tls_client_hello.CipherSuite,
) quic.tls.secret.Secret {
    return switch (suite.hash()) {
        .sha256 => .fromSha256([_]u8{0xb1} ** 32),
        .sha384 => .fromSha384([_]u8{0xb1} ** 48),
        .sm3 => unreachable,
    };
}

fn sharedEndpointReceive(
    endpoint: *quic.runtime.Endpoint,
    keys: quic.protection.PacketProtectionKeys,
    expected_packet_number: u64,
) !quic.one_rtt.ReceivedPacket {
    return quic.one_rtt.receive(
        endpoint,
        keys,
        "server".len,
        expected_packet_number,
        8,
    );
}
