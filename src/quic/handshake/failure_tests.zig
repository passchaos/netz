const std = @import("std");
const quic = @import("../mod.zig");
const handshake = @import("../handshake.zig");

fn rejection(comptime version: quic.Version, comptime mode: enum { alpn, cipher, key_share, malformed }) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    var client = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer client.deinit();
    const dcid = "tls-failure-origin";
    const scid = "tls-failure-client";
    const server_cid = "tls-failure-server";
    const keys = try quic.protection.deriveInitialSecretsForVersion(version.wireValue(), dcid);
    var parameters: std.ArrayList(u8) = .empty;
    defer parameters.deinit(allocator);
    var local = quic.practical_transport_parameters;
    local.initial_source_connection_id = scid;
    try quic.encodeTransportParametersForSource(&parameters, allocator, local, .client);
    var hello: std.ArrayList(u8) = .empty;
    defer hello.deinit(allocator);
    if (mode == .malformed) {
        try hello.appendSlice(allocator, &.{ 0x01, 0x00, 0x00, 0x00 });
    } else {
        try quic.tls_client_hello.writeClientHello(&hello, allocator, .{
            .random = [_]u8{0x62} ** 32,
            .x25519_public_key = try @import("../tls/key_exchange.zig").x25519PublicKey([_]u8{0x63} ** 32),
            .alpn_protocols = if (mode == .alpn) &.{"unsupported"} else &.{"h3"},
            .cipher_suites = if (mode == .cipher) &.{.aes_256_gcm_sha384} else &.{.aes_128_gcm_sha256},
            .transport_parameters = parameters.items,
        });
    }
    _ = try quic.initial_exchange.sendInitialCryptoFlight(&client, server.address(), keys.client, .{
        .initial = .{
            .version = version.wireValue(),
            .destination_connection_id = dcid,
            .source_connection_id = scid,
            .packet_number = 0,
            .crypto_data = hello.items,
            .max_crypto_frame_data_len = 256,
            .min_datagram_size = 1200,
        },
        .max_datagram_size = 1280,
    });
    const expected = switch (mode) {
        .alpn => error.MissingAlpn,
        .cipher => error.NoSharedCipherSuite,
        .key_share => error.MissingKeyShare,
        .malformed => error.BufferTooShort,
    };
    try std.testing.expectError(expected, handshake.acceptWithTimeout(&server, .{
        .local_connection_id = server_cid,
        .version = version,
        .available_versions = &.{version},
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .key_exchange_groups = if (mode == .key_share) &.{.secp256r1} else &.{.x25519},
    }, .fromMilliseconds(100)));
    var datagram = try client.receiveBytesWithTimeout(.fromMilliseconds(100));
    defer datagram.deinit(allocator);
    var opened = try quic.protection.openInitialPacket(allocator, keys.server, datagram.bytes, 0);
    defer opened.deinit(allocator);
    const parsed = try quic.parseFrame(opened.payload);
    try std.testing.expect(parsed.frame == .connection_close);
    const code: u64 = switch (mode) {
        .alpn => 0x178,
        .cipher, .key_share => 0x128,
        .malformed => 0x132,
    };
    try std.testing.expectEqual(code, parsed.frame.connection_close.error_code);
}

test "QUIC TLS rejection emits exact Initial close codes" {
    inline for (.{ quic.Version.version_1, quic.Version.version_2 }) |version| {
        inline for (.{ .alpn, .cipher, .key_share, .malformed }) |mode| try rejection(version, mode);
    }
}

test "QUIC TLS rejection reaches the client before its handshake deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    var client = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer client.deinit();
    const Worker = struct {
        endpoint: *quic.runtime.Endpoint,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            if (handshake.acceptWithTimeout(self.endpoint, .{
                .local_connection_id = "reject-server",
            }, .fromSeconds(2))) |value| {
                var unexpected = value;
                unexpected.deinit();
                self.err = error.TestUnexpectedResult;
            } else |err| {
                if (err != error.MissingAlpn) self.err = err;
            }
        }
    };
    var worker = Worker{ .endpoint = &server };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();
    try std.testing.expectError(error.ConnectionClosed, handshake.connectWithTimeout(&client, server.address(), .{
        .original_destination_connection_id = "reject-origin",
        .local_connection_id = "reject-client",
        .alpn_protocols = &.{"unsupported"},
    }, .fromSeconds(1)));
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
}

test "QUIC TLS rejection close emitter preserves its wire error" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(std.testing.allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{});
    defer endpoint.deinit();
    const keys = quic.protection.deriveInitialSecrets("reject-origin");
    var state: @import("failure.zig").State = .{
        .endpoint = &endpoint,
        .peer = endpoint.address(),
        .packet_type = .initial,
        .keys = keys.server,
        .version = quic.Version.version_1.wireValue(),
        .destination_connection_id = "reject-client",
        .source_connection_id = "reject-server",
        .next_packet_number = 0,
    };
    try state.send(0x178, "MissingAlpn");
    var bytes = try endpoint.receiveBytesWithTimeout(.fromMilliseconds(100));
    defer bytes.deinit(std.testing.allocator);
    var packet = try quic.protection.openInitialPacket(std.testing.allocator, keys.server, bytes.bytes, 0);
    defer packet.deinit(std.testing.allocator);
    const parsed = try quic.parseFrame(packet.payload);
    try std.testing.expectEqual(@as(u64, 0x178), parsed.frame.connection_close.error_code);
}

test "QUIC TLS rejection uses Initial or Handshake keys on the client" {
    const server_fixture = @import("test_server.zig");
    inline for (.{ quic.Version.version_1, quic.Version.version_2 }) |version| {
        inline for ([_]server_fixture.Mode{ .alpn, .finished, .cipher, .parameters, .close }) |mode| {
            var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
            defer threaded.deinit();
            var server = try quic.runtime.Endpoint.bind(std.testing.allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{});
            defer server.deinit();
            var client = try quic.runtime.Endpoint.bind(std.testing.allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{});
            defer client.deinit();
            var worker = server_fixture.Server{ .endpoint = &server, .mode = mode, .version = version };
            const thread = try std.Thread.spawn(.{}, server_fixture.Server.run, .{&worker});
            var joined = false;
            defer if (!joined) thread.join();
            const expected = switch (mode) {
                .alpn => error.MissingAlpn,
                .finished => error.BadFinished,
                .cipher => error.InvalidCipherSuite,
                .parameters => error.InvalidTransportParameter,
                .close => error.ConnectionClosed,
            };
            try std.testing.expectError(expected, handshake.connectWithTimeout(&client, server.address(), .{
                .original_destination_connection_id = "peer-origin",
                .local_connection_id = "peer-client",
                .version = version,
                .available_versions = &.{version},
                .key_exchange_groups = &.{.x25519},
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .random = [_]u8{0x71} ** 32,
                .x25519_secret_key = [_]u8{0x72} ** 32,
            }, .fromSeconds(2)));
            thread.join();
            joined = true;
            if (worker.err) |err| return err;
        }
    }
}

test "QUIC TLS rejection stops Initial and Handshake CRYPTO extraction" {
    inline for (.{ quic.FramePacketType.initial, quic.FramePacketType.handshake }) |packet_type| {
        inline for (.{ false, true }) |crypto_first| {
            var bytes: std.ArrayList(u8) = .empty;
            defer bytes.deinit(std.testing.allocator);
            if (crypto_first) try (quic.Frame{ .crypto = .{ .offset = 0, .data = "hello" } }).write(&bytes, std.testing.allocator);
            try (quic.Frame{ .connection_close = .{ .error_code = 0x178, .frame_type = 0, .reason_phrase = "closed" } }).write(&bytes, std.testing.allocator);
            if (!crypto_first) try (quic.Frame{ .crypto = .{ .offset = 0, .data = "hello" } }).write(&bytes, std.testing.allocator);
            var reassembler = quic.crypto_stream.Reassembler.init(std.testing.allocator, 128);
            defer reassembler.deinit();
            try std.testing.expectError(error.ConnectionClosed, quic.initial_exchange.insertCryptoPayload(std.testing.allocator, &reassembler, bytes.items, packet_type));
        }
    }
}

test "QUIC TLS rejection verifies client Finished before closing with a fresh packet number" {
    inline for (.{ quic.Version.version_1, quic.Version.version_2 }) |version| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var server = try quic.runtime.Endpoint.bind(std.testing.allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{});
        defer server.deinit();
        var client = try quic.runtime.Endpoint.bind(std.testing.allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{});
        defer client.deinit();
        const Worker = struct {
            endpoint: *quic.runtime.Endpoint,
            version: quic.Version,
            err: ?anyerror = null,
            fn run(self: *@This()) void {
                if (handshake.acceptWithTimeout(self.endpoint, .{ .version = self.version, .available_versions = &.{self.version}, .local_connection_id = "finish-server", .key_exchange_groups = &.{.x25519} }, .fromSeconds(2))) |value| {
                    var unexpected = value;
                    unexpected.deinit();
                    self.err = error.TestUnexpectedResult;
                } else |err| if (err != error.BadFinished) {
                    self.err = err;
                }
            }
        };
        var worker = Worker{ .endpoint = &server, .version = version };
        const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
        var joined = false;
        defer if (!joined) thread.join();
        const keys = try quic.protection.deriveInitialSecretsForVersion(version.wireValue(), "finish-origin");
        var parameters: std.ArrayList(u8) = .empty;
        defer parameters.deinit(std.testing.allocator);
        var local = quic.practical_transport_parameters;
        local.initial_source_connection_id = "finish-client";
        try quic.encodeTransportParametersForSource(&parameters, std.testing.allocator, local, .client);
        var hello: std.ArrayList(u8) = .empty;
        defer hello.deinit(std.testing.allocator);
        const secret = [_]u8{0x69} ** 32;
        try quic.tls_client_hello.writeClientHello(&hello, std.testing.allocator, .{
            .random = [_]u8{0x68} ** 32,
            .x25519_public_key = try @import("../tls/key_exchange.zig").x25519PublicKey(secret),
            .transport_parameters = parameters.items,
            .cipher_suites = &.{.aes_128_gcm_sha256},
        });
        _ = try quic.initial_exchange.sendInitialCryptoFlight(&client, server.address(), keys.client, .{ .initial = .{ .version = version.wireValue(), .destination_connection_id = "finish-origin", .source_connection_id = "finish-client", .packet_number = 0, .crypto_data = hello.items, .min_datagram_size = 1200 }, .max_datagram_size = 1280 });
        var initial = try quic.initial_exchange.receiveInitialCryptoFlight(&client, keys.server, .{ .expected_packet_number = 0, .max_crypto_buffer = 4096, .deadline = .fromNow(threaded.io(), .{ .raw = .fromSeconds(2), .clock = .awake }) });
        defer initial.deinit(std.testing.allocator);
        const parsed = try quic.tls_client_hello.parseServerHello(initial.crypto_data);
        const shared = try @import("../tls/key_exchange.zig").x25519SharedSecret(secret, parsed.x25519_public_key);
        const digest = quic.tls.transcript.hashFor(.sha256, &.{ hello.items, initial.crypto_data });
        const secrets = try quic.tls_client_hello.deriveRuntimeHandshakeSecretsForVersion(version.wireValue(), .aes_128_gcm_sha256, shared, digest, null);
        var flight = try quic.initial_exchange.receiveHandshakeCrypto(&client, secrets.server_quic, 0, 4096);
        defer flight.deinit(std.testing.allocator);
        var finished: std.ArrayList(u8) = .empty;
        defer finished.deinit(std.testing.allocator);
        try quic.tls_client_hello.writeFinished(&finished, std.testing.allocator, [_]u8{0} ** 32);
        try quic.initial_exchange.sendHandshakeCrypto(&client, server.address(), secrets.client_quic, .{ .version = version.wireValue(), .destination_connection_id = "finish-server", .source_connection_id = "finish-client", .packet_number = 0, .crypto_data = finished.items });
        var bytes = try client.receiveBytesWithTimeout(.fromSeconds(2));
        defer bytes.deinit(std.testing.allocator);
        var opened = try quic.protection.openHandshakePacket(std.testing.allocator, secrets.server_quic, bytes.bytes, 1);
        defer opened.deinit(std.testing.allocator);
        try std.testing.expectEqual(@as(u64, 1), opened.packet_number);
        try std.testing.expectEqual(@as(u64, 0x133), (try quic.parseFrame(opened.payload)).frame.connection_close.error_code);
        thread.join();
        joined = true;
        if (worker.err) |err| return err;
    }
}

test "QUIC TLS rejection guards preserve local errors and close ownership" {
    const target = @import("failure.zig");
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(std.testing.allocator, threaded.io(), .{ .ip4 = .loopback(0) }, .{});
    defer endpoint.deinit();
    var budget: @import("retransmit.zig").AntiAmplificationBudget = .{};
    budget.recordReceived(1200);
    var state: target.State = .{ .endpoint = &endpoint, .peer = endpoint.address(), .packet_type = .initial, .keys = quic.protection.deriveInitialSecrets("local-origin").server, .version = quic.Version.version_1.wireValue(), .destination_connection_id = "local-client", .source_connection_id = "local-server", .next_packet_number = 7, .anti_amplification = &budget };
    try std.testing.expectError(error.OutOfMemory, state.guardTls(@as(error{OutOfMemory}!void, error.OutOfMemory)));
    try std.testing.expectEqual(@as(?u64, 7), state.next_packet_number);
    try std.testing.expectEqual(@as(usize, 0), budget.bytes_sent);
    try std.testing.expectError(error.Timeout, endpoint.receiveBytesWithTimeout(.fromMilliseconds(5)));
    const FailedSend = struct {
        fn send(_: ?*anyopaque, _: std.Io.net.Socket.Handle, _: []std.Io.net.OutgoingMessage, _: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
            return .{ error.SystemResources, 0 };
        }
    };
    const original = endpoint.io;
    var vtable = original.vtable.*;
    vtable.netSend = FailedSend.send;
    endpoint.io = .{ .userdata = original.userdata, .vtable = &vtable };
    defer endpoint.io = original;
    try std.testing.expectError(error.MissingAlpn, state.guardTls(@as(error{MissingAlpn}!void, error.MissingAlpn)));
    try std.testing.expect(state.next_packet_number == null);
    try std.testing.expectEqual(@as(usize, 0), budget.bytes_sent);
    try std.testing.expectError(error.MissingAlpn, state.guardTls(@as(error{MissingAlpn}!void, error.MissingAlpn)));
    try std.testing.expectEqual(@as(usize, 0), budget.bytes_sent);
}
