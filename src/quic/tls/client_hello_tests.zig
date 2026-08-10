const std = @import("std");
const quic = @import("../mod.zig");
const target = @import("../tls_client_hello.zig");

const handshake_type_client_hello_for_test: u8 = 0x01;
const handshake_type_server_hello_for_test: u8 = 0x02;
const handshake_type_encrypted_extensions_for_test: u8 = 0x08;
const ext_alpn_for_test: u16 = 0x0010;
const ext_supported_versions_for_test: u16 = 0x002b;
const ext_quic_transport_parameters_for_test: u16 = 0x0039;

fn appendIntForTest(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    comptime T: type,
    value: T,
) !void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .big);
    try list.appendSlice(allocator, &bytes);
}

fn appendU16LenForTest(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    len: usize,
    err: target.Error,
) target.Error!void {
    if (len > std.math.maxInt(u16)) return err;
    try appendIntForTest(list, allocator, u16, @intCast(len));
}

test "QUIC TLS ClientHello encodes and parses QUIC extensions" {
    const allocator = std.testing.allocator;
    const random = [_]u8{0x11} ** 32;
    const key = [_]u8{0x22} ** 32;
    var tp: std.ArrayList(u8) = .empty;
    defer tp.deinit(allocator);
    try quic.encodeTransportParameter(&tp, allocator, @intFromEnum(quic.TransportParameterId.initial_max_data), &.{ 0x40, 0x64 });

    var hello: std.ArrayList(u8) = .empty;
    defer hello.deinit(allocator);
    try target.writeClientHello(&hello, allocator, .{
        .random = random,
        .x25519_public_key = key,
        .server_name = "example.com",
        .alpn_protocols = &.{ "h3", "h3-29" },
        .transport_parameters = tp.items,
    });

    var parsed = try target.parseClientHello(allocator, hello.items);
    defer parsed.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &random, &parsed.random);
    try std.testing.expectEqualStrings("example.com", parsed.server_name.?);
    try std.testing.expectEqualStrings("h3", parsed.alpn_protocols[0]);
    try std.testing.expectEqualStrings("h3-29", parsed.alpn_protocols[1]);
    try std.testing.expectEqualSlices(u8, &key, parsed.x25519_public_key);
    try std.testing.expect(parsed.supports_ed25519);
    try std.testing.expect(parsed.supports_ecdsa_p256_sha256);
    try std.testing.expect(parsed.supports_ecdsa_p384_sha384);
    try std.testing.expect(parsed.supports_rsa_pss_rsae_sha256);
    try std.testing.expect(parsed.supports_rsa_pss_rsae_sha384);
    try std.testing.expect(parsed.supports_rsa_pss_rsae_sha512);
    try std.testing.expect(parsed.supports_rsa_pss_pss_sha256);
    try std.testing.expect(parsed.supports_rsa_pss_pss_sha384);
    try std.testing.expect(parsed.supports_rsa_pss_pss_sha512);

    const params = try quic.parseTransportParameters(allocator, parsed.transport_parameters);
    defer allocator.free(params);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.TransportParameterId.initial_max_data)), params[0].id);

    var duplicate_transport_parameters = try hello.clone(allocator);
    defer duplicate_transport_parameters.deinit(allocator);
    try appendClientHelloExtensionForTest(&duplicate_transport_parameters, allocator, ext_quic_transport_parameters_for_test, &.{});
    try std.testing.expectError(error.InvalidClientHello, target.parseClientHello(allocator, duplicate_transport_parameters.items));

    const offsets = try clientHelloOffsetsForTest(hello.items);
    var aes256_first = try hello.clone(allocator);
    defer aes256_first.deinit(allocator);
    std.mem.writeInt(
        u16,
        aes256_first.items[offsets.cipher_suites_start..][0..2],
        0x1302,
        .big,
    );
    var aes256_parsed = try target.parseClientHello(
        allocator,
        aes256_first.items,
    );
    defer aes256_parsed.deinit(allocator);
    try std.testing.expectEqual(
        target.CipherSuite.aes_256_gcm_sha384,
        try target.selectCipherSuite(
            aes256_parsed.cipher_suites,
            &target.default_cipher_suites,
            .server_order,
        ),
    );

    var no_shared_cipher = try hello.clone(allocator);
    defer no_shared_cipher.deinit(allocator);
    std.mem.writeInt(
        u16,
        no_shared_cipher.items[offsets.cipher_suites_start..][0..2],
        0x1304,
        .big,
    );
    std.mem.writeInt(
        u16,
        no_shared_cipher.items[offsets.cipher_suites_start + 2 ..][0..2],
        0x00ff,
        .big,
    );
    std.mem.writeInt(
        u16,
        no_shared_cipher.items[offsets.cipher_suites_start + 4 ..][0..2],
        0x1305,
        .big,
    );
    var no_shared_parsed = try target.parseClientHello(
        allocator,
        no_shared_cipher.items,
    );
    defer no_shared_parsed.deinit(allocator);
    try std.testing.expectError(
        error.NoSharedCipherSuite,
        target.selectCipherSuite(
            no_shared_parsed.cipher_suites,
            &target.default_cipher_suites,
            .server_order,
        ),
    );

    var non_null_compression = try hello.clone(allocator);
    defer non_null_compression.deinit(allocator);
    non_null_compression.items[offsets.compression_start] = 1;
    try std.testing.expectError(error.InvalidClientHello, target.parseClientHello(allocator, non_null_compression.items));

    // Real TLS 1.3 clients commonly send a version preference vector instead of
    // the one-element vector produced by this minimal writer. QUIC still requires
    // TLS 1.3 to be offered, but the parser must not reject otherwise valid
    // multi-version ClientHellos before negotiation can happen.
    const multi_version_payload = [_]u8{ 4, 0x03, 0x03, 0x03, 0x04 };
    var multi_version_hello = try hello.clone(allocator);
    defer multi_version_hello.deinit(allocator);
    try replaceClientHelloExtensionForTest(&multi_version_hello, allocator, ext_supported_versions_for_test, &multi_version_payload);
    var multi_version_parsed = try target.parseClientHello(allocator, multi_version_hello.items);
    defer multi_version_parsed.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &key, multi_version_parsed.x25519_public_key);

    const malformed_supported_versions = [_][]const u8{
        &.{},
        &.{0},
        &.{ 1, 0x03 },
        &.{ 3, 0x03, 0x03, 0x04 },
        &.{ 2, 0x03, 0x03 },
        &.{ 4, 0x03, 0x04 },
    };
    for (malformed_supported_versions) |payload| {
        var malformed_version_hello = try hello.clone(allocator);
        defer malformed_version_hello.deinit(allocator);
        try replaceClientHelloExtensionForTest(&malformed_version_hello, allocator, ext_supported_versions_for_test, payload);
        try std.testing.expectError(error.InvalidClientHello, target.parseClientHello(allocator, malformed_version_hello.items));
    }

    const huge_transport_parameters = try allocator.alloc(u8, @as(usize, std.math.maxInt(u16)) + 1);
    defer allocator.free(huge_transport_parameters);
    try std.testing.expectError(error.InvalidClientHello, target.writeClientHello(&hello, allocator, .{
        .random = random,
        .x25519_public_key = key,
        .transport_parameters = huge_transport_parameters,
    }));

    const huge_sni = try allocator.alloc(u8, @as(usize, std.math.maxInt(u16)) - 1);
    defer allocator.free(huge_sni);
    @memset(huge_sni, 'a');
    try std.testing.expectError(error.InvalidClientHello, target.writeClientHello(&hello, allocator, .{
        .random = random,
        .x25519_public_key = key,
        .server_name = huge_sni,
    }));

    const long_proto = try allocator.alloc(u8, 255);
    defer allocator.free(long_proto);
    @memset(long_proto, 'h');
    const too_many_protocols = try allocator.alloc([]const u8, 257);
    defer allocator.free(too_many_protocols);
    for (too_many_protocols) |*protocol| protocol.* = long_proto;
    try std.testing.expectError(error.InvalidClientHello, target.writeClientHello(&hello, allocator, .{
        .random = random,
        .x25519_public_key = key,
        .alpn_protocols = too_many_protocols,
    }));
}

fn appendClientHelloExtensionForTest(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    typ: u16,
    payload: []const u8,
) target.Error!void {
    if (list.items.len < 4 or list.items[0] != handshake_type_client_hello_for_test) return error.InvalidClientHello;
    const body_len = (@as(usize, list.items[1]) << 16) | (@as(usize, list.items[2]) << 8) | list.items[3];
    if (body_len + 4 != list.items.len) return error.InvalidClientHello;

    var pos: usize = 4;
    pos += 2 + 32; // legacy_version + random
    if (pos >= list.items.len) return error.InvalidClientHello;
    const session_id_len = list.items[pos];
    pos += 1 + @as(usize, session_id_len);
    if (pos + 2 > list.items.len) return error.InvalidClientHello;
    const cipher_suites_len = std.mem.readInt(u16, list.items[pos..][0..2], .big);
    pos += 2 + @as(usize, cipher_suites_len);
    if (pos >= list.items.len) return error.InvalidClientHello;
    const compression_len = list.items[pos];
    pos += 1 + @as(usize, compression_len);
    if (pos + 2 > list.items.len) return error.InvalidClientHello;

    const extensions_len_pos = pos;
    const extensions_len = std.mem.readInt(u16, list.items[extensions_len_pos..][0..2], .big);
    if (extensions_len_pos + 2 + @as(usize, extensions_len) != list.items.len) return error.InvalidClientHello;
    const added_len = std.math.add(usize, 4, payload.len) catch return error.InvalidClientHello;
    const next_extensions_len = std.math.add(usize, extensions_len, added_len) catch return error.InvalidClientHello;
    const next_body_len = std.math.add(usize, body_len, added_len) catch return error.InvalidClientHello;
    if (next_extensions_len > std.math.maxInt(u16) or next_body_len > std.math.maxInt(u24)) return error.InvalidClientHello;

    try appendIntForTest(list, allocator, u16, typ);
    try appendU16LenForTest(list, allocator, payload.len, error.InvalidClientHello);
    try list.appendSlice(allocator, payload);
    std.mem.writeInt(u16, list.items[extensions_len_pos..][0..2], @intCast(next_extensions_len), .big);
    list.items[1] = @truncate(next_body_len >> 16);
    list.items[2] = @truncate(next_body_len >> 8);
    list.items[3] = @truncate(next_body_len);
}

fn replaceClientHelloExtensionForTest(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    typ: u16,
    replacement_payload: []const u8,
) target.Error!void {
    if (list.items.len < 4 or list.items[0] != handshake_type_client_hello_for_test) return error.InvalidClientHello;
    const body_len = (@as(usize, list.items[1]) << 16) | (@as(usize, list.items[2]) << 8) | list.items[3];
    if (body_len + 4 != list.items.len) return error.InvalidClientHello;

    var pos: usize = 4 + 2 + 32;
    if (pos >= list.items.len) return error.InvalidClientHello;
    const session_id_len = list.items[pos];
    pos += 1 + @as(usize, session_id_len);
    if (pos + 2 > list.items.len) return error.InvalidClientHello;
    const cipher_suites_len = std.mem.readInt(u16, list.items[pos..][0..2], .big);
    pos += 2 + @as(usize, cipher_suites_len);
    if (pos >= list.items.len) return error.InvalidClientHello;
    const compression_len = list.items[pos];
    pos += 1 + @as(usize, compression_len);
    if (pos + 2 > list.items.len) return error.InvalidClientHello;

    const extensions_len_pos = pos;
    const extensions_len = std.mem.readInt(u16, list.items[extensions_len_pos..][0..2], .big);
    var ext_pos = extensions_len_pos + 2;
    const ext_end = ext_pos + @as(usize, extensions_len);
    if (ext_end != list.items.len) return error.InvalidClientHello;
    while (ext_pos < ext_end) {
        if (ext_pos + 4 > ext_end) return error.InvalidClientHello;
        const ext_type = std.mem.readInt(u16, list.items[ext_pos..][0..2], .big);
        const old_len = std.mem.readInt(u16, list.items[ext_pos + 2 ..][0..2], .big);
        const old_payload_start = ext_pos + 4;
        const old_payload_end = old_payload_start + @as(usize, old_len);
        if (old_payload_end > ext_end) return error.InvalidClientHello;
        if (ext_type == typ) {
            const old_total = 4 + @as(usize, old_len);
            const new_total = std.math.add(usize, 4, replacement_payload.len) catch return error.InvalidClientHello;
            const next_extensions_len = if (new_total >= old_total)
                std.math.add(usize, extensions_len, new_total - old_total) catch return error.InvalidClientHello
            else
                extensions_len - (old_total - new_total);
            const next_body_len = if (new_total >= old_total)
                std.math.add(usize, body_len, new_total - old_total) catch return error.InvalidClientHello
            else
                body_len - (old_total - new_total);
            if (next_extensions_len > std.math.maxInt(u16) or next_body_len > std.math.maxInt(u24)) return error.InvalidClientHello;

            const tail = try allocator.dupe(u8, list.items[old_payload_end..]);
            defer allocator.free(tail);
            try list.resize(allocator, old_payload_start + replacement_payload.len + tail.len);
            try appendU16LenToSlice(list.items[ext_pos + 2 ..][0..2], replacement_payload.len);
            @memcpy(list.items[old_payload_start..][0..replacement_payload.len], replacement_payload);
            @memcpy(list.items[old_payload_start + replacement_payload.len ..], tail);
            std.mem.writeInt(u16, list.items[extensions_len_pos..][0..2], @intCast(next_extensions_len), .big);
            list.items[1] = @truncate(next_body_len >> 16);
            list.items[2] = @truncate(next_body_len >> 8);
            list.items[3] = @truncate(next_body_len);
            return;
        }
        ext_pos = old_payload_end;
    }
    return error.InvalidClientHello;
}

fn appendU16LenToSlice(out: *[2]u8, len: usize) target.Error!void {
    if (len > std.math.maxInt(u16)) return error.InvalidClientHello;
    std.mem.writeInt(u16, out, @intCast(len), .big);
}

const ClientHelloOffsetsForTest = struct {
    cipher_suites_start: usize,
    compression_start: usize,
};

fn clientHelloOffsetsForTest(bytes: []const u8) target.Error!ClientHelloOffsetsForTest {
    if (bytes.len < 4 or bytes[0] != handshake_type_client_hello_for_test) return error.InvalidClientHello;
    const body_len = (@as(usize, bytes[1]) << 16) | (@as(usize, bytes[2]) << 8) | bytes[3];
    if (body_len + 4 != bytes.len) return error.InvalidClientHello;

    var pos: usize = 4 + 2 + 32;
    if (pos >= bytes.len) return error.InvalidClientHello;
    const session_id_len = bytes[pos];
    pos += 1 + @as(usize, session_id_len);
    if (pos + 2 > bytes.len) return error.InvalidClientHello;
    const cipher_suites_len = std.mem.readInt(u16, bytes[pos..][0..2], .big);
    const cipher_suites_start = pos + 2;
    pos += 2 + @as(usize, cipher_suites_len);
    if (pos >= bytes.len) return error.InvalidClientHello;
    const compression_len = bytes[pos];
    const compression_start = pos + 1;
    if (compression_start + @as(usize, compression_len) > bytes.len) return error.InvalidClientHello;
    return .{ .cipher_suites_start = cipher_suites_start, .compression_start = compression_start };
}

fn appendServerHelloExtensionForTest(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    typ: u16,
    payload: []const u8,
) target.Error!void {
    if (list.items.len < 4 or list.items[0] != handshake_type_server_hello_for_test) return error.InvalidServerHello;
    const body_len = (@as(usize, list.items[1]) << 16) | (@as(usize, list.items[2]) << 8) | list.items[3];
    if (body_len + 4 != list.items.len) return error.InvalidServerHello;

    var pos: usize = 4 + 2 + 32;
    if (pos >= list.items.len) return error.InvalidServerHello;
    const session_id_len = list.items[pos];
    pos += 1 + @as(usize, session_id_len) + 2 + 1; // session id + cipher suite + compression
    if (pos + 2 > list.items.len) return error.InvalidServerHello;
    try appendHandshakeExtensionForTest(list, allocator, pos, typ, payload, error.InvalidServerHello);
}

fn appendEncryptedExtensionsExtensionForTest(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    typ: u16,
    payload: []const u8,
) target.Error!void {
    if (list.items.len < 6 or list.items[0] != handshake_type_encrypted_extensions_for_test) return error.InvalidEncryptedExtensions;
    const body_len = (@as(usize, list.items[1]) << 16) | (@as(usize, list.items[2]) << 8) | list.items[3];
    if (body_len + 4 != list.items.len) return error.InvalidEncryptedExtensions;
    try appendHandshakeExtensionForTest(list, allocator, 4, typ, payload, error.InvalidEncryptedExtensions);
}

fn appendHandshakeExtensionForTest(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    extensions_len_pos: usize,
    typ: u16,
    payload: []const u8,
    err: target.Error,
) target.Error!void {
    if (extensions_len_pos + 2 > list.items.len) return err;
    const body_len = (@as(usize, list.items[1]) << 16) | (@as(usize, list.items[2]) << 8) | list.items[3];
    const extensions_len = std.mem.readInt(u16, list.items[extensions_len_pos..][0..2], .big);
    if (extensions_len_pos + 2 + @as(usize, extensions_len) != list.items.len) return err;
    const added_len = std.math.add(usize, 4, payload.len) catch return err;
    const next_extensions_len = std.math.add(usize, extensions_len, added_len) catch return err;
    const next_body_len = std.math.add(usize, body_len, added_len) catch return err;
    if (next_extensions_len > std.math.maxInt(u16) or next_body_len > std.math.maxInt(u24)) return err;

    try appendIntForTest(list, allocator, u16, typ);
    try appendU16LenForTest(list, allocator, payload.len, err);
    try list.appendSlice(allocator, payload);
    std.mem.writeInt(u16, list.items[extensions_len_pos..][0..2], @intCast(next_extensions_len), .big);
    list.items[1] = @truncate(next_body_len >> 16);
    list.items[2] = @truncate(next_body_len >> 8);
    list.items[3] = @truncate(next_body_len);
}

test "QUIC TLS ClientHello travels over Initial CRYPTO exchange" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try quic.runtime.Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server.deinit();
    var client = try quic.runtime.Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{ .max_datagram_size = 4096 });
    defer client.deinit();

    const original_dcid = [_]u8{ 8, 7, 6, 5, 4, 3, 2, 1 };
    const client_scid = [_]u8{ 1, 1, 1, 1 };
    const secrets = quic.protection.deriveInitialSecrets(&original_dcid);
    var hello: std.ArrayList(u8) = .empty;
    defer hello.deinit(allocator);
    try target.writeClientHello(&hello, allocator, .{
        .random = [_]u8{0x33} ** 32,
        .x25519_public_key = [_]u8{0x44} ** 32,
        .server_name = "localhost",
        .transport_parameters = &.{},
    });

    try quic.initial_exchange.sendInitialCrypto(&client.endpoint, server.address(), secrets.client, .{
        .destination_connection_id = &original_dcid,
        .source_connection_id = &client_scid,
        .packet_number = 0,
        .crypto_data = hello.items,
        .max_crypto_frame_data_len = 64,
    });

    var received = try quic.initial_exchange.receiveInitialCrypto(&server.endpoint, secrets.client, 0, 4096);
    defer received.deinit(allocator);
    var parsed = try target.parseClientHello(allocator, received.crypto_data);
    defer parsed.deinit(allocator);
    try std.testing.expectEqualStrings("localhost", parsed.server_name.?);
    try std.testing.expectEqualStrings("h3", parsed.alpn_protocols[0]);
}

test "QUIC TLS ServerHello and handshake secrets derive on both sides" {
    const allocator = std.testing.allocator;
    const client_secret = [_]u8{0x11} ** 32;
    const server_secret = [_]u8{0x22} ** 32;
    const client_public = try target.x25519PublicKey(client_secret);
    const server_public = try target.x25519PublicKey(server_secret);

    var encoded_client_hello: std.ArrayList(u8) = .empty;
    defer encoded_client_hello.deinit(allocator);
    try target.writeClientHello(&encoded_client_hello, allocator, .{
        .random = [_]u8{0x33} ** 32,
        .x25519_public_key = client_public,
        .server_name = "localhost",
        .transport_parameters = &.{},
    });

    var parsed_client = try target.parseClientHello(allocator, encoded_client_hello.items);
    defer parsed_client.deinit(allocator);
    const server_shared = try target.x25519SharedSecret(server_secret, parsed_client.x25519_public_key);

    var server_hello: std.ArrayList(u8) = .empty;
    defer server_hello.deinit(allocator);
    try target.writeServerHello(&server_hello, allocator, .{
        .random = [_]u8{0x44} ** 32,
        .x25519_public_key = server_public,
    });
    const parsed_server = try target.parseServerHello(server_hello.items);
    const client_shared = try target.x25519SharedSecret(client_secret, parsed_server.x25519_public_key);
    try std.testing.expectEqualSlices(u8, &client_shared, &server_shared);

    var duplicate_server_supported_versions = try server_hello.clone(allocator);
    defer duplicate_server_supported_versions.deinit(allocator);
    try appendServerHelloExtensionForTest(&duplicate_server_supported_versions, allocator, ext_supported_versions_for_test, &.{ 0x03, 0x04 });
    try std.testing.expectError(error.InvalidServerHello, target.parseServerHello(duplicate_server_supported_versions.items));

    const th = target.transcriptHash(encoded_client_hello.items, server_hello.items);
    const client_keys = target.deriveHandshakeSecrets(client_shared, th);
    const server_keys = target.deriveHandshakeSecrets(server_shared, th);
    try std.testing.expectEqualSlices(u8, &client_keys.handshake_secret, &server_keys.handshake_secret);
    try std.testing.expectEqualSlices(u8, &client_keys.client_quic.key, &server_keys.client_quic.key);
    try std.testing.expectEqualSlices(u8, &client_keys.server_quic.key, &server_keys.server_quic.key);
    try std.testing.expect(!std.mem.eql(u8, &client_keys.client_quic.key, &client_keys.server_quic.key));
}

test "QUIC TLS ClientHello offers X25519 and P-256 and server selects P-256" {
    const allocator = std.testing.allocator;
    const x25519_secret = [_]u8{0x41} ** 32;
    const x25519_public = try target.x25519PublicKey(x25519_secret);
    const client_p256_secret = [_]u8{0} ** 31 ++ [_]u8{1};
    const server_p256_secret = [_]u8{0} ** 31 ++ [_]u8{2};
    const client_p256_public =
        try quic.tls.key_exchange.p256.publicKey(
            client_p256_secret,
        );
    const server_p256_public =
        try quic.tls.key_exchange.p256.publicKey(
            server_p256_secret,
        );
    const shares = [_]target.KeyShare{
        .{ .x25519 = x25519_public },
        .{ .secp256r1 = client_p256_public },
    };

    var client_hello: std.ArrayList(u8) = .empty;
    defer client_hello.deinit(allocator);
    try target.writeClientHello(&client_hello, allocator, .{
        .random = [_]u8{0x42} ** 32,
        .x25519_public_key = x25519_public,
        .key_shares = &shares,
        .transport_parameters = &.{},
    });
    var parsed_client = try target.parseClientHello(
        allocator,
        client_hello.items,
    );
    defer parsed_client.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &x25519_public,
        parsed_client.keyShare(.x25519).?,
    );
    try std.testing.expectEqualSlices(
        u8,
        &client_p256_public,
        parsed_client.keyShare(.secp256r1).?,
    );

    var server_hello: std.ArrayList(u8) = .empty;
    defer server_hello.deinit(allocator);
    try target.writeServerHello(&server_hello, allocator, .{
        .random = [_]u8{0x43} ** 32,
        .x25519_public_key = [_]u8{0} ** 32,
        .key_share = .{ .secp256r1 = server_p256_public },
    });
    const parsed_server = try target.parseServerHello(
        server_hello.items,
    );
    try std.testing.expectEqual(
        target.NamedGroup.secp256r1,
        parsed_server.selected_group,
    );
    try std.testing.expectEqualSlices(
        u8,
        &server_p256_public,
        parsed_server.keyShare(),
    );
    const client_shared = try quic.tls.key_exchange.p256.sharedSecret(
        client_p256_secret,
        parsed_server.keyShare(),
    );
    const server_shared = try quic.tls.key_exchange.p256.sharedSecret(
        server_p256_secret,
        parsed_client.keyShare(.secp256r1).?,
    );
    try std.testing.expectEqualSlices(
        u8,
        &client_shared,
        &server_shared,
    );
    try std.testing.expectEqual(
        target.NamedGroup.secp256r1,
        try target.selectKeyShare(
            parsed_client,
            &.{.secp256r1},
        ),
    );
    try std.testing.expectError(
        error.MissingKeyShare,
        target.selectKeyShare(
            parsed_client,
            &.{},
        ),
    );
}

test "QUIC TLS QUIC keys use version-specific packet-protection labels" {
    const shared = [_]u8{0x33} ** 32;
    const transcript = [_]u8{0x44} ** 32;
    const v1 = try target.deriveHandshakeSecretsForVersion(quic.Version.version_1.wireValue(), shared, transcript);
    const v2 = try target.deriveHandshakeSecretsForVersion(quic.Version.version_2.wireValue(), shared, transcript);

    try std.testing.expectEqualSlices(u8, &v1.handshake_secret, &v2.handshake_secret);
    try std.testing.expectEqualSlices(u8, &v1.client_handshake_traffic_secret, &v2.client_handshake_traffic_secret);
    try std.testing.expect(!std.mem.eql(u8, &v1.client_quic.key, &v2.client_quic.key));

    const app_v1 = try target.deriveApplicationSecretsForVersion(quic.Version.version_1.wireValue(), v1.handshake_secret, transcript);
    const app_v2 = try target.deriveApplicationSecretsForVersion(quic.Version.version_2.wireValue(), v1.handshake_secret, transcript);
    try std.testing.expectEqualSlices(u8, &app_v1.master_secret, &app_v2.master_secret);
    try std.testing.expect(!std.mem.eql(u8, &app_v1.client_quic.key, &app_v2.client_quic.key));
}

test "QUIC TLS versioned packet-protection derivation rejects unsupported versions" {
    const unsupported_version: u32 = 0xface_b00c;
    const shared = [_]u8{0x35} ** 32;
    const transcript = [_]u8{0x36} ** 32;
    const handshake_secret = [_]u8{0x37} ** quic.protection.secret_len;

    try std.testing.expectError(error.UnsupportedVersion, target.deriveHandshakeSecretsForVersion(unsupported_version, shared, transcript));
    try std.testing.expectError(error.UnsupportedVersion, target.deriveApplicationSecretsForVersion(unsupported_version, handshake_secret, transcript));
}

test "QUIC TLS runtime SHA-384 secrets derive AES-256 packet keys and Finished" {
    const shared = [_]u8{0x39} ** 32;
    const handshake_hash = quic.tls.transcript.hashFor(
        .sha384,
        &.{ "client hello", "server hello" },
    );
    const handshake = try target.deriveRuntimeHandshakeSecretsForVersion(
        quic.Version.version_1.wireValue(),
        .aes_256_gcm_sha384,
        shared,
        handshake_hash,
        null,
    );
    try std.testing.expectEqual(
        quic.tls.secret.Hash.sha384,
        handshake.handshake_secret.hash,
    );
    try std.testing.expectEqual(
        target.CipherSuite.aes_256_gcm_sha384,
        handshake.client_quic.suite,
    );

    const application_hash = quic.tls.transcript.hashFor(
        .sha384,
        &.{ "client hello", "server flight" },
    );
    const application =
        try target.deriveRuntimeApplicationSecretsForVersion(
            quic.Version.version_1.wireValue(),
            .aes_256_gcm_sha384,
            handshake.handshake_secret,
            application_hash,
        );
    const finished = try target.computeFinishedVerifyDataForHash(
        application.client_application_traffic_secret,
        application_hash,
    );
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try target.writeFinishedForHash(
        &encoded,
        std.testing.allocator,
        finished,
    );
    const parsed = try target.parseFinishedForHash(
        encoded.items,
        .sha384,
    );
    try target.verifyFinishedForHash(
        application.client_application_traffic_secret,
        application_hash,
        parsed,
    );
}

test "QUIC TLS ClientHello and ServerHello exchange over protected Initial packets" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try quic.runtime.Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server.deinit();
    var client = try quic.runtime.Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{ .max_datagram_size = 4096 });
    defer client.deinit();

    const original_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03, 0x04 };
    const client_scid = [_]u8{ 0x10, 0x11, 0x12, 0x13 };
    const server_scid = [_]u8{ 0x20, 0x21, 0x22, 0x23 };
    const initial_secrets = quic.protection.deriveInitialSecrets(&original_dcid);

    const client_secret = [_]u8{0x45} ** 32;
    const server_secret = [_]u8{0x46} ** 32;
    const client_public = try target.x25519PublicKey(client_secret);
    const server_public = try target.x25519PublicKey(server_secret);

    var encoded_client_hello: std.ArrayList(u8) = .empty;
    defer encoded_client_hello.deinit(allocator);
    try target.writeClientHello(&encoded_client_hello, allocator, .{
        .random = [_]u8{0x47} ** 32,
        .x25519_public_key = client_public,
        .server_name = "localhost",
        .alpn_protocols = &.{"h3"},
        .transport_parameters = &.{},
    });

    try quic.initial_exchange.sendInitialCrypto(&client.endpoint, server.address(), initial_secrets.client, .{
        .destination_connection_id = &original_dcid,
        .source_connection_id = &client_scid,
        .packet_number = 0,
        .crypto_data = encoded_client_hello.items,
        .max_crypto_frame_data_len = 64,
    });

    var server_received = try quic.initial_exchange.receiveInitialCrypto(&server.endpoint, initial_secrets.client, 0, 4096);
    defer server_received.deinit(allocator);
    var parsed_client = try target.parseClientHello(allocator, server_received.crypto_data);
    defer parsed_client.deinit(allocator);
    const server_shared = try target.x25519SharedSecret(server_secret, parsed_client.x25519_public_key);

    var server_hello: std.ArrayList(u8) = .empty;
    defer server_hello.deinit(allocator);
    try target.writeServerHello(&server_hello, allocator, .{
        .random = [_]u8{0x48} ** 32,
        .x25519_public_key = server_public,
    });
    const server_transcript = target.transcriptHash(encoded_client_hello.items, server_hello.items);
    const server_handshake = target.deriveHandshakeSecrets(server_shared, server_transcript);

    try quic.initial_exchange.sendInitialCrypto(&server.endpoint, server_received.from, initial_secrets.server, .{
        .destination_connection_id = &client_scid,
        .source_connection_id = &server_scid,
        .packet_number = 0,
        .crypto_data = server_hello.items,
        .max_crypto_frame_data_len = 64,
    });

    var client_received = try quic.initial_exchange.receiveInitialCrypto(&client.endpoint, initial_secrets.server, 0, 4096);
    defer client_received.deinit(allocator);
    const parsed_server = try target.parseServerHello(client_received.crypto_data);
    const client_shared = try target.x25519SharedSecret(client_secret, parsed_server.x25519_public_key);
    const client_transcript = target.transcriptHash(encoded_client_hello.items, client_received.crypto_data);
    const client_handshake = target.deriveHandshakeSecrets(client_shared, client_transcript);

    try std.testing.expectEqualSlices(u8, &server_shared, &client_shared);
    try std.testing.expectEqualSlices(u8, &server_handshake.client_quic.key, &client_handshake.client_quic.key);
    try std.testing.expectEqualSlices(u8, &server_handshake.server_quic.key, &client_handshake.server_quic.key);
}

test "QUIC TLS EncryptedExtensions and Finished verify data" {
    const allocator = std.testing.allocator;
    var tp: std.ArrayList(u8) = .empty;
    defer tp.deinit(allocator);
    try quic.encodeTransportParameter(&tp, allocator, @intFromEnum(quic.TransportParameterId.initial_max_data), &.{ 0x40, 0x64 });

    var ee: std.ArrayList(u8) = .empty;
    defer ee.deinit(allocator);
    try target.writeEncryptedExtensions(&ee, allocator, "h3", tp.items);
    const parsed_ee = try target.parseEncryptedExtensions(ee.items);
    try std.testing.expectEqualStrings("h3", parsed_ee.alpn);
    const params = try quic.parseTransportParameters(allocator, parsed_ee.transport_parameters);
    defer allocator.free(params);
    try std.testing.expectEqual(@as(u64, @intFromEnum(quic.TransportParameterId.initial_max_data)), params[0].id);

    var duplicate_ee_alpn = try ee.clone(allocator);
    defer duplicate_ee_alpn.deinit(allocator);
    try appendEncryptedExtensionsExtensionForTest(&duplicate_ee_alpn, allocator, ext_alpn_for_test, &.{ 0x00, 0x03, 0x02, 'h', '3' });
    try std.testing.expectError(error.InvalidEncryptedExtensions, target.parseEncryptedExtensions(duplicate_ee_alpn.items));

    const base_key = [_]u8{0x5a} ** 32;
    var transcript_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(ee.items, &transcript_hash, .{});
    const verify_data = target.computeFinishedVerifyData(base_key, transcript_hash);

    var finished: std.ArrayList(u8) = .empty;
    defer finished.deinit(allocator);
    try target.writeFinished(&finished, allocator, verify_data);
    const parsed_finished = try target.parseFinished(finished.items);
    try target.verifyFinished(base_key, transcript_hash, parsed_finished);

    var wrong_hash = transcript_hash;
    wrong_hash[0] ^= 0xff;
    try std.testing.expectError(error.BadFinished, target.verifyFinished(base_key, wrong_hash, parsed_finished));
}

test "QUIC TLS server handshake flight travels over Handshake packet" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try quic.runtime.Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer server.deinit();
    var client = try quic.runtime.Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{ .max_datagram_size = 4096 });
    defer client.deinit();

    const original_dcid = [_]u8{ 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87 };
    const client_scid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3 };
    const server_scid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3 };
    const initial_secrets = quic.protection.deriveInitialSecrets(&original_dcid);

    const client_secret = [_]u8{0x51} ** 32;
    const server_secret = [_]u8{0x52} ** 32;
    const client_public = try target.x25519PublicKey(client_secret);
    const server_public = try target.x25519PublicKey(server_secret);

    var encoded_client_hello: std.ArrayList(u8) = .empty;
    defer encoded_client_hello.deinit(allocator);
    try target.writeClientHello(&encoded_client_hello, allocator, .{
        .random = [_]u8{0x53} ** 32,
        .x25519_public_key = client_public,
        .server_name = "localhost",
        .transport_parameters = &.{},
    });
    try quic.initial_exchange.sendInitialCrypto(&client.endpoint, server.address(), initial_secrets.client, .{
        .destination_connection_id = &original_dcid,
        .source_connection_id = &client_scid,
        .packet_number = 0,
        .crypto_data = encoded_client_hello.items,
        .max_crypto_frame_data_len = 64,
    });

    var server_received = try quic.initial_exchange.receiveInitialCrypto(&server.endpoint, initial_secrets.client, 0, 4096);
    defer server_received.deinit(allocator);
    var parsed_client = try target.parseClientHello(allocator, server_received.crypto_data);
    defer parsed_client.deinit(allocator);
    const server_shared = try target.x25519SharedSecret(server_secret, parsed_client.x25519_public_key);

    var server_hello: std.ArrayList(u8) = .empty;
    defer server_hello.deinit(allocator);
    try target.writeServerHello(&server_hello, allocator, .{
        .random = [_]u8{0x54} ** 32,
        .x25519_public_key = server_public,
    });
    const hs_hash = target.transcriptHash(encoded_client_hello.items, server_hello.items);
    const server_keys = target.deriveHandshakeSecrets(server_shared, hs_hash);

    var ee: std.ArrayList(u8) = .empty;
    defer ee.deinit(allocator);
    try target.writeEncryptedExtensions(&ee, allocator, "h3", &.{});
    var transcript = std.crypto.hash.sha2.Sha256.init(.{});
    transcript.update(encoded_client_hello.items);
    transcript.update(server_hello.items);
    transcript.update(ee.items);
    var server_finished_hash: [32]u8 = undefined;
    transcript.final(&server_finished_hash);
    const verify_data = target.computeFinishedVerifyData(server_keys.server_handshake_traffic_secret, server_finished_hash);

    var finished: std.ArrayList(u8) = .empty;
    defer finished.deinit(allocator);
    try target.writeFinished(&finished, allocator, verify_data);

    var server_flight: std.ArrayList(u8) = .empty;
    defer server_flight.deinit(allocator);
    try server_flight.appendSlice(allocator, ee.items);
    try server_flight.appendSlice(allocator, finished.items);
    try quic.initial_exchange.sendHandshakeCrypto(&server.endpoint, server_received.from, server_keys.server_quic, .{
        .destination_connection_id = &client_scid,
        .source_connection_id = &server_scid,
        .packet_number = 0,
        .crypto_data = server_flight.items,
        .max_crypto_frame_data_len = 64,
    });

    var client_received = try quic.initial_exchange.receiveHandshakeCrypto(&client.endpoint, server_keys.server_quic, 0, 4096);
    defer client_received.deinit(allocator);
    const ee_len = handshakeMessageLen(client_received.crypto_data);
    const parsed_ee = try target.parseEncryptedExtensions(client_received.crypto_data[0..ee_len]);
    try std.testing.expectEqualStrings("h3", parsed_ee.alpn);
    const parsed_finished = try target.parseFinished(client_received.crypto_data[ee_len..]);

    const parsed_server = try target.parseServerHello(server_hello.items);
    const client_shared = try target.x25519SharedSecret(client_secret, parsed_server.x25519_public_key);
    const client_keys = target.deriveHandshakeSecrets(client_shared, hs_hash);
    try target.verifyFinished(client_keys.server_handshake_traffic_secret, server_finished_hash, parsed_finished);

    var through_server_finished = std.crypto.hash.sha2.Sha256.init(.{});
    through_server_finished.update(encoded_client_hello.items);
    through_server_finished.update(server_hello.items);
    through_server_finished.update(ee.items);
    through_server_finished.update(finished.items);
    var client_finished_hash: [32]u8 = undefined;
    through_server_finished.final(&client_finished_hash);
    const client_verify = target.computeFinishedVerifyData(client_keys.client_handshake_traffic_secret, client_finished_hash);

    var client_finished: std.ArrayList(u8) = .empty;
    defer client_finished.deinit(allocator);
    try target.writeFinished(&client_finished, allocator, client_verify);
    try quic.initial_exchange.sendHandshakeCrypto(&client.endpoint, server.address(), client_keys.client_quic, .{
        .destination_connection_id = &server_scid,
        .source_connection_id = &client_scid,
        .packet_number = 0,
        .crypto_data = client_finished.items,
        .max_crypto_frame_data_len = 64,
    });

    var server_client_finished = try quic.initial_exchange.receiveHandshakeCrypto(&server.endpoint, server_keys.client_quic, 0, 4096);
    defer server_client_finished.deinit(allocator);
    const parsed_client_finished = try target.parseFinished(server_client_finished.crypto_data);
    try target.verifyFinished(server_keys.client_handshake_traffic_secret, client_finished_hash, parsed_client_finished);

    var full_transcript = std.crypto.hash.sha2.Sha256.init(.{});
    full_transcript.update(encoded_client_hello.items);
    full_transcript.update(server_hello.items);
    full_transcript.update(ee.items);
    full_transcript.update(finished.items);
    full_transcript.update(client_finished.items);
    var app_hash: [32]u8 = undefined;
    full_transcript.final(&app_hash);
    const client_app = target.deriveApplicationSecrets(client_keys.handshake_secret, app_hash);
    const server_app = target.deriveApplicationSecrets(server_keys.handshake_secret, app_hash);
    try std.testing.expectEqualSlices(u8, &client_app.client_quic.key, &server_app.client_quic.key);
    try std.testing.expectEqualSlices(u8, &client_app.server_quic.key, &server_app.server_quic.key);
    try std.testing.expect(!std.mem.eql(u8, &client_app.client_quic.key, &client_app.server_quic.key));
}

fn handshakeMessageLen(bytes: []const u8) usize {
    return 4 + ((@as(usize, bytes[1]) << 16) | (@as(usize, bytes[2]) << 8) | bytes[3]);
}
