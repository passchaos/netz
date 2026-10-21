const std = @import("std");
const mqtt = @import("mod.zig");
const runtime = @import("runtime.zig");
const mqtt_tls = @import("tls_runtime.zig");
const reconnect = @import("reconnect.zig");
const http1_runtime = @import("../http1/mod.zig").runtime;
const tls_stream = @import("../tls/mod.zig").stream;
const tls_test = @import("testing/tls13_server.zig");

const max_packet_size: usize = 4096;
const tls_server_max_packet_size: usize = 32 * 1024;
const large_payload_bytes: usize = 20 * 1024;
const CertificateBundle = std.crypto.Certificate.Bundle;

test "MQTT TLS caller-connected stream closes on expired deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client = try listener.socket.address.connect(io, .{ .mode = .stream });
    const peer = try listener.accept(io);
    defer peer.close(io);

    try std.testing.expectError(
        error.Timeout,
        mqtt_tls.Client.connectStreamAttemptWithDeadline(
            allocator,
            io,
            client,
            "broker.internal",
            .{ .mqtt = .{ .client_id = "owned-tls-stream" } },
            .{ .raw = .zero, .clock = .awake },
        ),
    );
    var byte: [1]u8 = undefined;
    var buffers = [_][]u8{&byte};
    try std.testing.expectEqual(
        @as(usize, 0),
        try io.vtable.netRead(
            io.userdata,
            peer.socket.handle,
            &buffers,
        ),
    );
}

fn writeStreamAll(
    io: std.Io,
    stream: std.Io.net.Stream,
    bytes: []const u8,
) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const remainder = try io.vtable.netWrite(
            io.userdata,
            stream.socket.handle,
            bytes[offset..],
            &.{""},
            0,
        );
        if (remainder == 0) return error.ConnectionClosed;
        offset += remainder;
    }
}

test "MQTT TLS negotiates configured ALPN without client authentication" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_test.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_test.certificate_base64,
    );
    const key_pair = try tls_test.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var server = try mqtt_tls.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .alpn_protocols = &.{ "mqtt", "x-amzn-mqtt-ca" },
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer server.deinit();
    const Shared = struct {
        server: *mqtt_tls.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *mqtt_tls.Server) !void {
            var accepted = try server_ptr.accept(.{ .protocol = .v5 });
            defer accepted.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings(
                "mqtt",
                accepted.connection.negotiatedAlpn().?,
            );
            try std.testing.expect(
                accepted.connection.peerCertificates() == null,
            );
            try std.testing.expectEqual(
                tls_stream.NegotiatedCipherSuite.aes_128_gcm_sha256,
                accepted.connection.negotiatedCipherSuite().?,
            );
            try std.testing.expectEqual(
                tls_stream.TranscriptHash.sha256,
                accepted.connection.negotiatedTranscriptHash().?,
            );
            try std.testing.expectEqualStrings(
                "mqtt-alpn",
                accepted.connect.connect.client_id,
            );
            try accepted.connection.updateTrafficKeys(true);
            try accepted.connection.readPingReq();
            try accepted.connection.writePingResp();
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(server_ptr.allocator);
            const updates = accepted.connection.keyUpdateCounts().?;
            try std.testing.expectEqual(@as(u64, 1), updates.sent);
            try std.testing.expectEqual(@as(u64, 1), updates.received);
            try std.testing.expect(!updates.awaiting_peer_response);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try mqtt_tls.Client.connectAddress(
        allocator,
        io,
        server.address(),
        "localhost",
        .{
            .mqtt = .{
                .protocol = .v5,
                .client_id = "mqtt-alpn",
            },
            // An ALPN-only client must use the vail path even though it has no
            // certificate identity of its own. The pin keeps the test fully
            // local and proves ordinary server authentication still applies.
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .alpn_protocols = &.{ "mqtt", "x-amzn-mqtt-ca" },
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer client.close();
    const server_chain = client.peerCertificates() orelse
        return error.MissingPeerCertificate;
    try std.testing.expectEqual(@as(usize, 1), server_chain.len);
    try std.testing.expectEqualSlices(
        u8,
        &certificate_der,
        server_chain[0],
    );
    // The transport must own its selection rather than borrowing either
    // caller's short-lived ALPN list.
    try std.testing.expect(
        client.negotiatedAlpn().?.ptr != "mqtt".ptr,
    );
    try std.testing.expectEqualStrings(
        "mqtt",
        client.negotiatedAlpn().?,
    );
    try std.testing.expectEqual(
        tls_stream.NegotiatedCipherSuite.aes_128_gcm_sha256,
        client.negotiatedCipherSuite().?,
    );
    try std.testing.expectEqual(
        tls_stream.TranscriptHash.sha256,
        client.negotiatedTranscriptHash().?,
    );
    try client.ping();
    const updates = client.keyUpdateCounts().?;
    try std.testing.expectEqual(@as(u64, 1), updates.sent);
    try std.testing.expectEqual(@as(u64, 1), updates.received);
    try std.testing.expect(!updates.awaiting_peer_response);
    try client.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT TLS 1.2 RFC 5077 ticket survives direct and reconnect lifecycles" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_test.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_test.certificate_base64,
    );
    const key_pair = try tls_test.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var keyring = try tls_stream.Tls12TicketKeyring.init(.{
        .id = 12,
        .secret = [_]u8{0x5c} ** tls_stream.tls12_ticket_key_len,
    });
    defer keyring.deinit();
    var server = try mqtt_tls.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .alpn_protocols = &.{"mqtt"},
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .tls12_cipher_suites = &.{
                .ecdhe_ecdsa_aes_128_gcm_sha256,
            },
            .protocol_policy = .tls12_only,
            .tls12_session_tickets = .{
                .keyring = &keyring,
                .server_id = "localhost",
                .lifetime_seconds = 3600,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_tls.Server,
        resumed: [6]bool = .{ false, false, false, false, false, false },
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            for (0..6) |index| {
                var accepted = shared.server.accept(.{ .protocol = .v5 }) catch |err| {
                    shared.err = err;
                    return;
                };
                defer accepted.deinit(shared.server.allocator);
                if (accepted.connection.negotiatedTlsProtocol() != .tls12) {
                    shared.err = error.InvalidProtocolVersion;
                    return;
                }
                shared.resumed[index] = accepted.connection.wasTlsSessionResumed() orelse {
                    shared.err = error.MissingTlsMetadata;
                    return;
                };
                accepted.connection.readPingReq() catch |err| {
                    shared.err = err;
                    return;
                };
                accepted.connection.writePingResp() catch |err| {
                    shared.err = err;
                    return;
                };
                var disconnect = accepted.connection.readDisconnect() catch |err| {
                    shared.err = err;
                    return;
                };
                disconnect.deinit(shared.server.allocator);
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ticket: ?tls_stream.Tls12SessionTicket = null;
    defer if (ticket) |*cached| cached.deinit();
    for (0..2) |index| {
        var client = try mqtt_tls.Client.connectAddress(
            allocator,
            io,
            server.address(),
            "localhost",
            .{
                .mqtt = .{
                    .protocol = .v5,
                    .client_id = "mqtt-tls12",
                },
                .server_verifier = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                },
                .alpn_protocols = &.{"mqtt"},
                .cipher_suites = &.{.aes_128_gcm_sha256},
                .tls12_cipher_suites = &.{
                    .ecdhe_ecdsa_aes_128_gcm_sha256,
                },
                .protocol_policy = .tls12_only,
                .tls12_ticket_resumption = if (index == 0) null else &ticket.?,
            },
        );
        defer client.close();
        try std.testing.expectEqual(
            tls_stream.Protocol.tls12,
            client.negotiatedTlsProtocol().?,
        );
        try std.testing.expectEqual(index != 0, client.wasTlsSessionResumed().?);
        try std.testing.expectEqual(
            tls_stream.NegotiatedCipherSuite.ecdhe_ecdsa_aes_128_gcm_sha256,
            client.negotiatedCipherSuite().?,
        );
        try std.testing.expectError(
            error.TlsKeyUpdateUnavailable,
            client.updateTrafficKeys(false),
        );
        try client.ping();
        if (client.takeTls12SessionTicket()) |renewed| {
            if (ticket) |*cached| cached.deinit();
            ticket = renewed;
        }
        if (index == 0) try std.testing.expect(ticket != null);
        try client.disconnect(0);
    }

    var connector = mqtt_tls.ReconnectConnector{
        .address = server.address(),
        .tls_host = "localhost",
        .options = .{
            .mqtt = .{ .client_id = "connector-placeholder" },
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .alpn_protocols = &.{"mqtt"},
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .tls12_cipher_suites = &.{
                .ecdhe_ecdsa_aes_128_gcm_sha256,
            },
            .protocol_policy = .tls12_only,
        },
    };
    var shutdown: std.Io.Event = .unset;
    var reconnecting = try reconnect.Client.initConnector(
        allocator,
        io,
        connector.connector(),
        .{
            .protocol = .v5,
            .client_id = "mqtt-tls12-reconnect",
        },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(1),
        },
        &shutdown,
    );
    defer reconnecting.deinit();
    for (0..4) |index| {
        if (index == 2) {
            const storage = reconnecting.tls12_session_ticket.?.ticket_storage;
            storage[storage.len - 1] ^= 1;
        } else if (index == 3) {
            reconnecting.tls12_session_ticket.?.session.created_at_seconds = 0;
        }
        _ = try reconnecting.connect();
        try std.testing.expectEqual(
            index == 1,
            reconnecting.connection().?.wasTlsSessionResumed().?,
        );
        try reconnecting.connection().?.ping();
        try reconnecting.disconnect(0);
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, true, false, true, false, false },
        &shared.resumed,
    );
}

test "MQTT reconnect client renews and validates TLS 1.3 tickets" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_test.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_test.certificate_base64,
    );
    const key_pair = try tls_test.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var keyring = try tls_stream.Tls13TicketKeyring.init(.{
        .id = 13,
        .secret = [_]u8{0x6d} ** tls_stream.tls13_ticket_key_len,
    });
    defer keyring.deinit();
    var server = try mqtt_tls.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .alpn_protocols = &.{"mqtt"},
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .protocol_policy = .tls13_only,
            .tls13_session_tickets = .{
                .keyring = &keyring,
                .server_id = "localhost",
                .lifetime_seconds = 3600,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_tls.Server,
        resumed: [5]bool = .{ false, false, false, false, false },
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for (0..self.resumed.len) |index| {
                var accepted = try self.server.accept(.{
                    .protocol = .v5,
                    .session_present = index != 0,
                });
                defer accepted.deinit(self.server.allocator);
                if (accepted.connection.negotiatedTlsProtocol() != .tls13) {
                    return error.InvalidProtocolVersion;
                }
                self.resumed[index] =
                    accepted.connection.wasTlsSessionResumed() orelse
                    return error.MissingTlsMetadata;
                try accepted.connection.readPingReq();
                try accepted.connection.writePingResp();
                var disconnect = try accepted.connection.readDisconnect();
                disconnect.deinit(self.server.allocator);
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var connector = mqtt_tls.ReconnectConnector{
        .address = server.address(),
        .tls_host = "localhost",
        .options = .{
            .mqtt = .{ .client_id = "connector-placeholder" },
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .alpn_protocols = &.{"mqtt"},
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .protocol_policy = .tls13_only,
        },
    };
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.initConnector(
        allocator,
        io,
        connector.connector(),
        .{
            .protocol = .v5,
            .client_id = "mqtt-tls13-reconnect",
            .clean_start = false,
        },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(1),
        },
        &shutdown,
    );
    defer client.deinit();

    var client_resumed: [5]bool = undefined;
    for (0..client_resumed.len) |index| {
        if (index == 2) {
            const identity = client.tls13_session_ticket.?.identity;
            identity[identity.len - 1] ^= 1;
        } else if (index == 4) {
            client.tls13_session_ticket.?.received_at_ms = 0;
        }
        _ = if (index % 2 == 0)
            try client.connect()
        else
            try client.connectWithTimeout(.fromSeconds(10));
        client_resumed[index] =
            client.connection().?.wasTlsSessionResumed().?;
        try client.connection().?.ping();
        try client.disconnect(0);
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    const expected = [_]bool{ false, true, false, true, false };
    try std.testing.expectEqualSlices(bool, &expected, &client_resumed);
    try std.testing.expectEqualSlices(bool, &expected, &shared.resumed);
}

test "MQTT TLS explicitly selects vail with ordinary CA verification" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_test.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_test.certificate_base64,
    );
    const key_pair = try tls_test.serverKeyPair();
    var server = try mqtt_tls.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
        } },
    );
    defer server.deinit();
    const Shared = struct {
        server: *mqtt_tls.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var accepted = self.server.accept(.{ .protocol = .v5 }) catch |err| {
                self.err = err;
                return;
            };
            defer accepted.deinit(self.server.allocator);
            var disconnect = accepted.connection.readDisconnect() catch |err| {
                self.err = err;
                return;
            };
            disconnect.deinit(self.server.allocator);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    var client = try mqtt_tls.Client.connectAddress(
        allocator,
        io,
        server.address(),
        "localhost",
        .{
            .mqtt = .{ .protocol = .v5, .client_id = "forced-vail" },
            .tls = .{ .ca_bundle = .{
                .bundle = &ca_bundle,
                .lock = &ca_lock,
            } },
            .use_vail = true,
        },
    );
    defer client.close();
    try std.testing.expect(client.negotiatedCipherSuite() != null);
    try std.testing.expect(client.negotiatedTranscriptHash() != null);
    try client.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT native TLS shutdown wakes a blocked packet reader" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_test.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_test.certificate_base64,
    );
    const key_pair = try tls_test.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var server = try mqtt_tls.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
        } },
    );
    defer server.deinit();

    const ServerState = struct {
        server: *mqtt_tls.Server,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var accepted = self.server.accept(.{ .protocol = .v5 }) catch |err| {
                self.err = err;
                return;
            };
            defer accepted.deinit(self.server.allocator);
            self.release.waitUncancelable(self.server.io);
        }
    };
    var server_state = ServerState{ .server = &server };
    const server_thread = try std.Thread.spawn(
        .{},
        ServerState.run,
        .{&server_state},
    );
    var server_joined = false;
    defer if (!server_joined) {
        server_state.release.set(io);
        server_thread.join();
    };

    var client = try mqtt_tls.Client.connectAddress(
        allocator,
        io,
        server.address(),
        "localhost",
        .{
            .mqtt = .{
                .protocol = .v5,
                .client_id = "tls-shutdown-reader",
            },
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
        },
    );
    defer client.close();

    const ReaderState = struct {
        connection: *runtime.Connection,
        result: ?anyerror = null,

        fn run(self: *@This()) void {
            var event = self.connection.readClientPacketEvent() catch |err| {
                self.result = err;
                return;
            };
            event.deinit(self.connection.allocator);
            self.result = error.TestUnexpectedResult;
        }
    };
    var reader = ReaderState{ .connection = &client };
    const reader_thread = try std.Thread.spawn(.{}, ReaderState.run, .{&reader});
    try std.Io.sleep(io, .fromMilliseconds(10), .awake);
    try client.shutdown();
    reader_thread.join();
    try std.testing.expectEqual(error.ConnectionClosed, reader.result.?);

    server_state.release.set(io);
    server_thread.join();
    server_joined = true;
    if (server_state.err) |err| return err;
}

test "MQTT TLS server completes verified MQTT 5 QoS 1" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_test.certificate_der_len]u8 =
        undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_test.certificate_base64,
    );
    const key_pair = try tls_test.serverKeyPair();
    var server = try mqtt_tls.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{
                    .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    },
                },
            },
            .limits = .{
                .max_packet_size = tls_server_max_packet_size,
            },
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer server.deinit();
    const Shared = struct {
        server: *mqtt_tls.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *mqtt_tls.Server) !void {
            var accepted = try server_ptr.accept(.{ .protocol = .v5 });
            defer accepted.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings(
                "mqtt-tls-server",
                accepted.connect.connect.client_id,
            );

            var publish = try accepted.connection.readPublish();
            defer publish.deinit(server_ptr.allocator);
            try std.testing.expectEqual(
                mqtt.QoS.at_least_once,
                publish.publish.qos,
            );
            try std.testing.expectEqualStrings(
                "server/tls/qos1",
                publish.publish.topic,
            );
            try std.testing.expectEqualStrings(
                "encrypted-to-broker",
                publish.publish.payload,
            );
            try accepted.connection.writePubAck(
                publish.publish.packet_id.?,
                0,
            );

            var large_publish = try accepted.connection.readPublish();
            defer large_publish.deinit(server_ptr.allocator);
            try std.testing.expectEqual(
                mqtt.QoS.at_least_once,
                large_publish.publish.qos,
            );
            try std.testing.expectEqualStrings(
                "server/tls/large-client-write",
                large_publish.publish.topic,
            );
            try expectLargePayload(large_publish.publish.payload);
            try accepted.connection.writePubAck(
                large_publish.publish.packet_id.?,
                0,
            );

            var response_payload: [large_payload_bytes]u8 = undefined;
            fillLargePayload(&response_payload);
            try accepted.connection.publish(
                "server/tls/large-server-write",
                &response_payload,
                .{},
            );

            var disconnect =
                try accepted.connection.readDisconnect();
            defer disconnect.deinit(server_ptr.allocator);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    var client = try mqtt_tls.Client.connectAddress(
        allocator,
        io,
        server.address(),
        "localhost",
        .{
            .mqtt = .{
                .protocol = .v5,
                .client_id = "mqtt-tls-server",
                .limits = .{
                    .max_packet_size = tls_server_max_packet_size,
                },
            },
            .tls = .{
                .ca_bundle = .{
                    .bundle = &ca_bundle,
                    .lock = &ca_lock,
                },
            },
        },
    );
    defer client.close();
    try client.publish(
        "server/tls/qos1",
        "encrypted-to-broker",
        .{ .qos = .at_least_once },
    );
    var large_payload: [large_payload_bytes]u8 = undefined;
    fillLargePayload(&large_payload);
    try client.publish(
        "server/tls/large-client-write",
        &large_payload,
        .{ .qos = .at_least_once },
    );
    var server_publish = try client.readPublish();
    defer server_publish.deinit(allocator);
    try std.testing.expectEqualStrings(
        "server/tls/large-server-write",
        server_publish.publish.topic,
    );
    try expectLargePayload(server_publish.publish.payload);
    try client.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT reconnect client reuses native TLS connector" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_test.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_test.certificate_base64,
    );
    const key_pair = try tls_test.serverKeyPair();
    var server = try mqtt_tls.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_tls.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.server.accept(.{ .protocol = .v5 });
            first.deinit(self.server.allocator);
            var second = try self.server.accept(.{
                .protocol = .v5,
                .session_present = true,
            });
            defer second.deinit(self.server.allocator);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    var connector = mqtt_tls.ReconnectConnector{
        .address = server.address(),
        .tls_host = "localhost",
        .options = .{
            .mqtt = .{ .client_id = "connector-placeholder" },
            .tls = .{ .ca_bundle = .{
                .bundle = &ca_bundle,
                .lock = &ca_lock,
            } },
        },
    };
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.initConnector(
        allocator,
        io,
        connector.connector(),
        .{
            .protocol = .v5,
            .client_id = "reconnect-tls",
            .clean_start = false,
        },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(8),
        },
        &shutdown,
    );
    defer client.deinit();
    var first = (try client.pollWithTimeout(.fromSeconds(10))) orelse
        return error.TestExpectedConnectEvent;
    defer first.deinit(allocator);
    try std.testing.expect(first == .connected);
    var second = (try client.pollWithTimeout(.fromSeconds(10))) orelse
        return error.TestExpectedReconnectEvent;
    defer second.deinit(allocator);
    try std.testing.expect(second == .connected);
    try std.testing.expect(second.connected.session_present);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT reconnect client reuses TLS hostname and URI connectors" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_test.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_test.certificate_base64,
    );
    const key_pair = try tls_test.serverKeyPair();
    var server = try mqtt_tls.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_tls.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for ([_][]const u8{ "tls-host", "tls-uri" }) |client_id| {
                var accepted = try self.server.accept(.{ .protocol = .v5 });
                try std.testing.expectEqualStrings(
                    client_id,
                    accepted.connect.connect.client_id,
                );
                var disconnect = try accepted.connection.readDisconnect();
                disconnect.deinit(self.server.allocator);
                accepted.deinit(self.server.allocator);
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    const Resolver = struct {
        address: std.Io.net.IpAddress,
        calls: std.atomic.Value(u8) = .init(0),

        fn resolve(
            context: *anyopaque,
            resolve_allocator: std.mem.Allocator,
            _: std.Io,
            host: []const u8,
            port: u16,
            deadline: ?std.Io.Clock.Timestamp,
        ) runtime.AddressResolver.ResolveError![]std.Io.net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (!std.mem.eql(u8, host, "localhost") or
                port != self.address.getPort() or deadline == null)
            {
                return error.UnknownHostName;
            }
            const addresses = try resolve_allocator.alloc(
                std.Io.net.IpAddress,
                1,
            );
            addresses[0] = self.address;
            _ = self.calls.fetchAdd(1, .acq_rel);
            return addresses;
        }
    };
    var resolver = Resolver{ .address = server.address() };
    const tls_options: mqtt_tls.ConnectOptions = .{
        .mqtt = .{
            .client_id = "connector-placeholder",
            .network_connect_timeout = .fromSeconds(3),
            .address_resolver = .{
                .context = &resolver,
                .resolve = Resolver.resolve,
            },
        },
        .tls = .{ .ca_bundle = .{
            .bundle = &ca_bundle,
            .lock = &ca_lock,
        } },
    };

    var host_connector = mqtt_tls.HostReconnectConnector{
        .host = "localhost",
        .port = server.address().ip4.port,
        .options = tls_options,
    };
    var host_shutdown: std.Io.Event = .unset;
    var host_client = try reconnect.Client.initConnector(
        allocator,
        io,
        host_connector.connector(),
        .{ .protocol = .v5, .client_id = "tls-host" },
        .{},
        &host_shutdown,
    );
    defer host_client.deinit();
    _ = try host_client.connect();
    try host_client.disconnect(0);

    const uri = try std.fmt.allocPrint(
        allocator,
        "mqtts://localhost:{d}",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var uri_connector = mqtt_tls.UriReconnectConnector{
        .uri = uri,
        .options = tls_options,
    };
    var uri_shutdown: std.Io.Event = .unset;
    var uri_client = try reconnect.Client.initConnector(
        allocator,
        io,
        uri_connector.connector(),
        .{ .protocol = .v5, .client_id = "tls-uri" },
        .{},
        &uri_shutdown,
    );
    defer uri_client.deinit();
    _ = try uri_client.connect();
    try uri_client.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u8, 2), resolver.calls.load(.acquire));
}

test "MQTT TLS URI reconnect connector preserves validation and network timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var invalid = mqtt_tls.UriReconnectConnector{
        .uri = "mqtt://localhost",
        .options = .{
            .mqtt = .{ .client_id = "connector-placeholder" },
        },
    };
    try std.testing.expectError(
        error.UnsupportedScheme,
        invalid.connector().connectAttempt(allocator, io, .{
            .client_id = "tls-invalid-uri",
        }),
    );

    var timeout = mqtt_tls.UriReconnectConnector{
        .uri = "mqtts://localhost:8883",
        .options = .{ .mqtt = .{
            .client_id = "placeholder",
            .network_connect_timeout = .zero,
        } },
    };
    try std.testing.expectError(
        error.Timeout,
        timeout.connector().connectAttempt(allocator, io, .{
            .client_id = "tls-uri-timeout",
            .network_connect_timeout = .fromSeconds(1),
        }),
    );
}

test "MQTT TLS server consumes PROXY v2 before TLS" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_test.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_test.certificate_base64,
    );
    const key_pair = try tls_test.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var server = try mqtt_tls.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .limits = .{
                .proxy_protocol = .v2,
                .proxy_header_timeout = .fromSeconds(1),
            },
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_tls.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var accepted = shared.server.accept(.{ .protocol = .v5 }) catch |err| {
                shared.err = err;
                return;
            };
            defer accepted.deinit(shared.server.allocator);
            const metadata = accepted.connection.proxyMetadata() orelse {
                shared.err = error.MissingProxyMetadata;
                return;
            };
            const source = accepted.connection.remoteAddress();
            if (metadata.version != .v2 or source != .ip4 or
                source.ip4.port != 6275 or
                !std.mem.eql(u8, &source.ip4.bytes, &.{ 192, 0, 2, 5 }))
            {
                shared.err = error.InvalidProxyMetadata;
                return;
            }
            var disconnect = accepted.connection.readDisconnect() catch |err| {
                shared.err = err;
                return;
            };
            disconnect.deinit(shared.server.allocator);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const stream = try server.address().connect(io, .{ .mode = .stream });
    var stream_owned = true;
    defer if (stream_owned) stream.close(io);
    try writeStreamAll(io, stream, &(mqtt.proxy_protocol.v2_signature ++
        [_]u8{ 0x21, 0x11, 0x00, 0x0c } ++
        [_]u8{
            192, 0, 2, 5, 127, 0, 0, 1, 0x18, 0x83, 0x07, 0x5b,
        }));
    const tls_connection = try @import("../tls/mod.zig").stream
        .ClientConnection.initVerified(allocator, io, stream, .{
        .server_name = "localhost",
        .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        },
        .cipher_suites = &.{.aes_128_gcm_sha256},
    });
    stream_owned = false;
    var connection = runtime.Connection.initVailTls(allocator, tls_connection, .{
        .protocol = .v5,
        .client_id = "proxy-before-tls",
    });
    var attempt = try connection.establishClient(.{
        .protocol = .v5,
        .client_id = "proxy-before-tls",
    });
    try std.testing.expect(attempt.accepted());
    var accepted = try attempt.requireAccepted();
    defer accepted.deinit(allocator);
    try accepted.connection.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT TLS server bounds the post-handshake CONNECT packet" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_test.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_test.certificate_base64,
    );
    const key_pair = try tls_test.serverKeyPair();
    var server = try mqtt_tls.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .limits = .{ .max_packet_size = max_packet_size },
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_tls.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var accepted = self.server.accept(.{
                .connect_timeout = .fromMilliseconds(75),
            }) catch |err| {
                self.err = err;
                return;
            };
            accepted.deinit(self.server.allocator);
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    const stream = try server.address().connect(io, .{ .mode = .stream });
    var stream_owned = true;
    defer if (stream_owned) stream.close(io);
    const tls_connection = try http1_runtime.TlsClientConnection.init(
        allocator,
        io,
        stream,
        "localhost",
        .{ .ca_bundle = .{
            .bundle = &ca_bundle,
            .lock = &ca_lock,
        } },
    );
    stream_owned = false;
    defer tls_connection.deinit();

    thread.join();
    joined = true;
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "MQTT TLS server caller timeout spans TLS and CONNECT" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_test.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_test.certificate_base64,
    );
    const key_pair = try tls_test.serverKeyPair();
    var server = try mqtt_tls.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .limits = .{ .max_packet_size = max_packet_size },
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .tls_handshake_timeout = .fromSeconds(1),
        },
    );
    defer server.deinit();
    try std.testing.expectError(
        error.Timeout,
        server.acceptWithTimeout(
            .{ .connect_timeout = .fromSeconds(1) },
            .fromMilliseconds(20),
        ),
    );

    const Shared = struct {
        server: *mqtt_tls.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var accepted = self.server.acceptWithTimeout(
                .{ .connect_timeout = .fromSeconds(1) },
                .fromMilliseconds(500),
            ) catch |err| {
                self.err = err;
                return;
            };
            accepted.deinit(self.server.allocator);
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    const stream = try server.address().connect(io, .{ .mode = .stream });
    var stream_owned = true;
    defer if (stream_owned) stream.close(io);
    const tls_connection = try http1_runtime.TlsClientConnection.init(
        allocator,
        io,
        stream,
        "localhost",
        .{ .ca_bundle = .{
            .bundle = &ca_bundle,
            .lock = &ca_lock,
        } },
    );
    stream_owned = false;
    defer tls_connection.deinit();
    // Completing the client handshake proves the shared budget reaches the
    // MQTT CONNECT phase. Keep the peer silent until that budget expires.

    thread.join();
    joined = true;
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "MQTT TLS server enforces Keep Alive inactivity" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_test.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_test.certificate_base64,
    );
    const key_pair = try tls_test.serverKeyPair();
    var server = try mqtt_tls.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{
                .key_pair = key_pair,
            } },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_tls.Server,
        timed_out: bool = false,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var accepted = try shared.server.accept(.{ .protocol = .v5 });
            defer accepted.deinit(shared.server.allocator);
            _ = accepted.connection.readBrokerEventWithKeepAlive() catch |err| {
                if (err != error.Timeout) return err;
                shared.timed_out = true;
                return;
            };
            return error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    var client = try mqtt_tls.Client.connectAddress(
        allocator,
        io,
        server.address(),
        "localhost",
        .{
            .mqtt = .{
                .protocol = .v5,
                .client_id = "mqtt-tls-keep-alive",
                .keep_alive_seconds = 1,
            },
            .tls = .{ .ca_bundle = .{
                .bundle = &ca_bundle,
                .lock = &ca_lock,
            } },
        },
    );
    defer client.close();

    const started = std.Io.Clock.awake.now(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.timed_out);
    const elapsed = started.durationTo(std.Io.Clock.awake.now(io));
    try std.testing.expect(
        elapsed.nanoseconds >= 1400 * std.time.ns_per_ms,
    );
    try std.testing.expect(elapsed.nanoseconds < 4 * std.time.ns_per_s);
}

test "MQTT standard TLS client enforces local packet deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_test.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_test.certificate_base64,
    );
    const key_pair = try tls_test.serverKeyPair();
    var server = try mqtt_tls.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .identity = .{
            .certificate_chain = &.{&certificate_der},
            .signer = .{ .ecdsa_p256_sha256 = .{
                .key_pair = key_pair,
            } },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_tls.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var accepted = try shared.server.accept(.{ .protocol = .v5 });
            defer accepted.deinit(shared.server.allocator);
            try std.Io.sleep(
                shared.server.io,
                .fromMilliseconds(400),
                .awake,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    var client = try mqtt_tls.Client.connectAddress(
        allocator,
        io,
        server.address(),
        "localhost",
        .{
            .mqtt = .{
                .protocol = .v5,
                .client_id = "mqtt-std-tls-deadline",
            },
            .tls = .{ .ca_bundle = .{
                .bundle = &ca_bundle,
                .lock = &ca_lock,
            } },
        },
    );
    defer client.close();

    try std.testing.expectError(
        error.Timeout,
        client.transport.readPacketWithInactivityTimeout(
            allocator,
            max_packet_size,
            .{ .raw = .fromMilliseconds(100), .clock = .awake },
        ),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT native TLS client identity completes required mTLS" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_test.certificate_der_len]u8 =
        undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_test.certificate_base64,
    );
    const key_pair = try tls_test.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var server = try mqtt_tls.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .client_auth = .{
                .verifier = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                },
            },
            .limits = .{ .max_packet_size = max_packet_size },
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_tls.Server,
        certificate: *const [tls_test.certificate_der_len]u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var accepted = try shared.server.accept(.{
                .protocol = .v5,
            });
            defer accepted.deinit(shared.server.allocator);
            try std.testing.expectEqualStrings(
                "native-mtls-client",
                accepted.connect.connect.client_id,
            );
            const chain = accepted.connection.peerCertificates() orelse
                return error.MissingPeerCertificate;
            try std.testing.expectEqual(@as(usize, 1), chain.len);
            try std.testing.expectEqualSlices(
                u8,
                shared.certificate,
                chain[0],
            );
            var publish = try accepted.connection.readPublish();
            defer publish.deinit(shared.server.allocator);
            try std.testing.expectEqualStrings(
                "native/mtls",
                publish.publish.topic,
            );
            try accepted.connection.writePubAck(
                publish.publish.packet_id.?,
                0,
            );
        }
    };
    var shared = Shared{
        .server = &server,
        .certificate = &certificate_der,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try mqtt_tls.Client.connectAddress(
        allocator,
        io,
        server.address(),
        "localhost",
        .{
            .mqtt = .{
                .protocol = .v5,
                .client_id = "native-mtls-client",
                .limits = .{ .max_packet_size = max_packet_size },
            },
            .client_identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer client.close();
    try client.publish(
        "native/mtls",
        "authenticated",
        .{ .qos = .at_least_once },
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT native TLS client identity verifies CA and hostname" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_test.certificate_der_len]u8 =
        undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_test.certificate_base64,
    );
    const key_pair = try tls_test.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var server = try mqtt_tls.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .client_auth = .{
                .verifier = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                },
            },
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_tls.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var accepted = shared.server.accept(.{
                .protocol = .v5,
            }) catch |err| {
                shared.err = err;
                return;
            };
            accepted.deinit(shared.server.allocator);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    var client = try mqtt_tls.Client.connectAddress(
        allocator,
        io,
        server.address(),
        "localhost",
        .{
            .mqtt = .{
                .protocol = .v5,
                .client_id = "native-mtls-ca",
            },
            .tls = .{ .ca_bundle = .{
                .bundle = &ca_bundle,
                .lock = &ca_lock,
            } },
            .client_identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    client.close();

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT native TLS client identity rejects wrong server pin" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_test.certificate_der_len]u8 =
        undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_test.certificate_base64,
    );
    const key_pair = try tls_test.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var wrong_key = public_key;
    wrong_key[1] ^= 1;
    var server = try mqtt_tls.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .client_auth = .{
                .verifier = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                },
            },
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_tls.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            _ = shared.server.accept(.{ .protocol = .v5 }) catch |err| {
                shared.err = err;
                return;
            };
            shared.err = error.ExpectedClientFailure;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    try std.testing.expectError(
        error.CertificateUntrusted,
        mqtt_tls.Client.connectAddress(
            allocator,
            io,
            server.address(),
            "localhost",
            .{
                .mqtt = .{
                    .protocol = .v5,
                    .client_id = "native-mtls-wrong-pin",
                },
                .client_identity = .{
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
                .server_verifier = .{
                    .pinned_ecdsa_p256_public_key = wrong_key,
                },
                .cipher_suites = &.{.aes_128_gcm_sha256},
            },
        ),
    );
    thread.join();
    joined = true;
    try std.testing.expect(shared.err != null);
}

fn fillLargePayload(payload: []u8) void {
    for (payload, 0..) |*byte, index| {
        byte.* = @truncate(index *% 29 +% 7);
    }
}

fn expectLargePayload(payload: []const u8) !void {
    try std.testing.expectEqual(large_payload_bytes, payload.len);
    for (payload, 0..) |byte, index| {
        try std.testing.expectEqual(
            @as(u8, @truncate(index *% 29 +% 7)),
            byte,
        );
    }
}

test "MQTT TLS client verifies local CA and completes MQTT 5 QoS 1" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try tls_test.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
    );
    defer server.deinit();

    const Shared = struct {
        server: *tls_test.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *tls_test.Server) !void {
            var connection = try server_ptr.accept();
            defer connection.deinit();
            var input: [max_packet_size]u8 = undefined;
            var output: std.ArrayList(u8) = .empty;
            defer output.deinit(server_ptr.allocator);

            const connect_bytes = try connection.readApplication(&input);
            var connect = try mqtt.Connect.parse(
                server_ptr.allocator,
                connect_bytes,
            );
            defer connect.deinit(server_ptr.allocator);
            try std.testing.expectEqual(
                mqtt.ProtocolVersion.v5,
                connect.protocol,
            );
            try std.testing.expectEqualStrings(
                "mqtt-tls-v5",
                connect.client_id,
            );
            try mqtt.ConnAck.write(
                &output,
                server_ptr.allocator,
                .v5,
                false,
                0,
                &.{},
            );
            try connection.writeApplication(output.items);

            const publish_bytes = try connection.readApplication(&input);
            var publish = try mqtt.Publish.parse(
                server_ptr.allocator,
                .v5,
                publish_bytes,
            );
            defer publish.deinit(server_ptr.allocator);
            try std.testing.expectEqual(
                mqtt.QoS.at_least_once,
                publish.qos,
            );
            try std.testing.expectEqualStrings(
                "tls/qos1",
                publish.topic,
            );
            try std.testing.expectEqualStrings(
                "encrypted",
                publish.payload,
            );
            output.clearRetainingCapacity();
            try mqtt.AckPacket.write(
                &output,
                server_ptr.allocator,
                .v5,
                .puback,
                publish.packet_id.?,
                0,
                &.{},
            );
            try connection.writeApplication(output.items);

            const disconnect_bytes = try connection.readApplication(&input);
            var disconnect = try mqtt.Disconnect.parse(
                server_ptr.allocator,
                .v5,
                disconnect_bytes,
            );
            defer disconnect.deinit(server_ptr.allocator);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    var client = try mqtt_tls.Client.connectAddress(
        allocator,
        io,
        server.address(),
        "localhost",
        .{
            .mqtt = .{
                .protocol = .v5,
                .client_id = "mqtt-tls-v5",
                .limits = .{ .max_packet_size = max_packet_size },
            },
            .tls = .{
                .ca_bundle = .{
                    .bundle = &ca_bundle,
                    .lock = &ca_lock,
                },
            },
        },
    );
    defer client.close();
    try client.publish(
        "tls/qos1",
        "encrypted",
        .{ .qos = .at_least_once },
    );
    try client.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT TLS client bounds the post-handshake CONNACK packet" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try tls_test.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
    );
    defer server.deinit();
    const Shared = struct {
        server: *tls_test.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.deinit();
            var input: [max_packet_size]u8 = undefined;
            _ = try connection.readApplication(&input);
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(150),
                .awake,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var ca_bundle, var ca_lock = try localCaBundle(allocator, io);
    defer ca_bundle.deinit(allocator);
    try std.testing.expectError(
        error.Timeout,
        mqtt_tls.Client.connectAddress(
            allocator,
            io,
            server.address(),
            "localhost",
            .{
                .mqtt = .{
                    .client_id = "silent-tls-server",
                    .connect_timeout = .fromMilliseconds(75),
                },
                .tls = .{ .ca_bundle = .{
                    .bundle = &ca_bundle,
                    .lock = &ca_lock,
                } },
            },
        ),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT TLS caller deadline spans TLS setup and CONNACK" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try tls_test.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
    );
    defer server.deinit();
    const Shared = struct {
        server: *tls_test.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.deinit();
            var input: [max_packet_size]u8 = undefined;
            _ = try connection.readApplication(&input);
            try std.Io.sleep(
                self.server.io,
                .fromMilliseconds(750),
                .awake,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    try std.testing.expectError(
        error.Timeout,
        mqtt_tls.Client.connectAddressAttemptWithDeadline(
            allocator,
            io,
            server.address(),
            "localhost",
            .{
                .mqtt = .{
                    .client_id = "total-tls-connect-deadline",
                    .network_connect_timeout = .fromSeconds(1),
                    .connect_timeout = .fromSeconds(1),
                },
                .tls = .{
                    .verify_host = false,
                    .handshake_timeout = .fromSeconds(1),
                },
            },
            .fromNow(io, .{
                // Leave ample room for a loaded local TLS handshake while
                // still expiring well before the peer supplies a CONNACK.
                .raw = .fromMilliseconds(500),
                .clock = .awake,
            }),
        ),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT TLS caller deadline retains shorter network phase timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    try std.testing.expectError(
        error.Timeout,
        mqtt_tls.Client.connectAddressAttemptWithDeadline(
            allocator,
            io,
            .{ .ip4 = .loopback(1) },
            "localhost",
            .{ .mqtt = .{
                .client_id = "tls-phase-timeout",
                .network_connect_timeout = .zero,
            } },
            .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
        ),
    );
}

test "MQTT TLS caller timeout rejects a non-positive budget" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(
        error.Timeout,
        mqtt_tls.Client.connectAddressWithTimeout(
            std.testing.allocator,
            threaded.io(),
            .{ .ip4 = .loopback(1) },
            "localhost",
            .{ .mqtt = .{ .client_id = "tls-total-timeout" } },
            .zero,
        ),
    );
}

test "MQTT TLS client supports mqtts URI and MQTT 3.1.1" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try tls_test.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
    );
    defer server.deinit();

    const Shared = struct {
        server: *tls_test.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *tls_test.Server) !void {
            var connection = try server_ptr.accept();
            defer connection.deinit();
            var input: [max_packet_size]u8 = undefined;
            var output: std.ArrayList(u8) = .empty;
            defer output.deinit(server_ptr.allocator);

            const connect_bytes = try connection.readApplication(&input);
            var connect = try mqtt.Connect.parse(
                server_ptr.allocator,
                connect_bytes,
            );
            defer connect.deinit(server_ptr.allocator);
            try std.testing.expectEqual(
                mqtt.ProtocolVersion.v3_1_1,
                connect.protocol,
            );
            try mqtt.ConnAck.write(
                &output,
                server_ptr.allocator,
                .v3_1_1,
                false,
                0,
                &.{},
            );
            try connection.writeApplication(output.items);

            const publish_bytes = try connection.readApplication(&input);
            var publish = try mqtt.Publish.parse(
                server_ptr.allocator,
                .v3_1_1,
                publish_bytes,
            );
            defer publish.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings(
                "tls/v3",
                publish.topic,
            );
            try std.testing.expectEqualStrings(
                "payload",
                publish.payload,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const uri = try std.fmt.allocPrint(
        allocator,
        "mqtts://localhost:{d}",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var client = try mqtt_tls.Client.connectUri(
        allocator,
        io,
        uri,
        .{
            .mqtt = .{
                .protocol = .v3_1_1,
                .client_id = "mqtt-tls-v3",
                .limits = .{ .max_packet_size = max_packet_size },
            },
            // URI parsing and encrypted transport are covered here; the
            // previous test separately proves explicit CA/hostname validation.
            .tls = .{ .verify_host = false },
        },
    );
    defer client.close();
    try client.publish("tls/v3", "payload", .{});

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT TLS URI rejects cleartext schemes before connecting" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(
        error.UnsupportedScheme,
        mqtt_tls.Client.connectUri(
            allocator,
            threaded.io(),
            "mqtt://localhost",
            .{ .mqtt = .{ .client_id = "wrong-scheme" } },
        ),
    );
}

test "MQTT TLS listener bounds an idle transport handshake" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [tls_test.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_test.certificate_base64,
    );
    const key_pair = try tls_test.serverKeyPair();
    var server = try mqtt_tls.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .tls_handshake_timeout = .fromMilliseconds(75),
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *mqtt_tls.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var accepted = self.server.accept(.{}) catch |err| {
                self.err = err;
                return;
            };
            accepted.deinit(self.server.allocator);
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const client = try server.address().connect(io, .{ .mode = .stream });
    defer client.close(io);
    thread.join();
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "MQTT vail TLS client bounds an idle server handshake" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const key_pair = try tls_test.serverKeyPair();
    var certificate_der: [tls_test.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_test.certificate_base64,
    );

    const Shared = struct {
        io: std.Io,
        listener: *std.Io.net.Server,

        fn run(self: *@This()) void {
            const stream = self.listener.accept(self.io) catch return;
            defer stream.close(self.io);
            std.Io.sleep(
                self.io,
                .fromMilliseconds(250),
                .awake,
            ) catch {};
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    try std.testing.expectError(
        error.Timeout,
        mqtt_tls.Client.connectAddress(
            allocator,
            io,
            listener.socket.address,
            "localhost",
            .{
                .mqtt = .{ .client_id = "tls-timeout" },
                // Supplying an identity deliberately selects the vail path.
                .client_identity = .{
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
                .server_verifier = .{},
                .tls_handshake_timeout = .fromMilliseconds(75),
            },
        ),
    );
    thread.join();
    joined = true;
}

test "MQTT standard TLS client bounds an idle server handshake" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const Shared = struct {
        io: std.Io,
        listener: *std.Io.net.Server,
        fn run(self: *@This()) void {
            const stream = self.listener.accept(self.io) catch return;
            defer stream.close(self.io);
            std.Io.sleep(self.io, .fromMilliseconds(250), .awake) catch {};
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    try std.testing.expectError(
        error.Timeout,
        mqtt_tls.Client.connectAddress(
            allocator,
            io,
            listener.socket.address,
            "localhost",
            .{
                .mqtt = .{ .client_id = "tls-std-timeout" },
                .tls = .{ .verify_host = false },
                .tls_handshake_timeout = .fromMilliseconds(20),
            },
        ),
    );
    thread.join();
}

test "MQTT TLS reconnect connector preserves network timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var connector = mqtt_tls.ReconnectConnector{
        .address = .{ .ip4 = .loopback(1) },
        .tls_host = "localhost",
        .options = .{ .mqtt = .{
            .client_id = "placeholder",
            .network_connect_timeout = .zero,
        } },
    };
    try std.testing.expectError(
        error.Timeout,
        connector.connector().connectAttempt(allocator, io, .{
            .client_id = "reconnect-timeout",
            .network_connect_timeout = .fromSeconds(1),
        }),
    );
}

fn localCaBundle(
    allocator: std.mem.Allocator,
    io: std.Io,
) !struct { CertificateBundle, std.Io.RwLock } {
    var certificate_der: [tls_test.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_test.certificate_base64,
    );
    var pem_storage: [512]u8 = undefined;
    var writer = std.Io.Writer.fixed(&pem_storage);
    try writer.writeAll("-----BEGIN CERTIFICATE-----\n");
    const encoded_len = std.base64.standard.Encoder.calcSize(
        certificate_der.len,
    );
    const encoded = try writer.writableSliceGreedy(encoded_len);
    _ = std.base64.standard.Encoder.encode(
        encoded[0..encoded_len],
        &certificate_der,
    );
    writer.advance(encoded_len);
    try writer.writeAll("\n-----END CERTIFICATE-----\n");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "ca.pem",
        .data = writer.buffered(),
    });
    var bundle: CertificateBundle = .empty;
    errdefer bundle.deinit(allocator);
    try bundle.addCertsFromFilePath(
        allocator,
        io,
        std.Io.Timestamp.now(io, .real),
        tmp.dir,
        "ca.pem",
    );
    return .{ bundle, .init };
}
