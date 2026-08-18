const std = @import("std");
const mqtt = @import("mod.zig");
const runtime = @import("runtime.zig");
const mqtt_tls = @import("tls_runtime.zig");
const tls_test = @import("testing/tls13_server.zig");

const max_packet_size: usize = 4096;
const tls_server_max_packet_size: usize = 32 * 1024;
const large_payload_bytes: usize = 20 * 1024;
const CertificateBundle = std.crypto.Certificate.Bundle;

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
