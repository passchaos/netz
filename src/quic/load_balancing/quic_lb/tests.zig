const std = @import("std");
const quic_lb = @import("mod.zig");

const vector_key = [16]u8{
    0x8f, 0x95, 0xf0, 0x92, 0x45, 0x76, 0x5f, 0x80,
    0x25, 0x69, 0x34, 0xe5, 0x0c, 0x66, 0x20, 0x7f,
};

test "QUIC-LB draft-21 unencrypted vectors" {
    try expectVector(
        .{
            .config_rotation = 0,
            .server_id_len = 3,
            .nonce_len = 4,
        },
        &.{ 0xc4, 0x60, 0x5e },
        &.{ 0x45, 0x04, 0xcc, 0x4f },
        "07c4605e4504cc4f",
    );
    try expectVector(
        .{
            .config_rotation = 1,
            .server_id_len = 5,
            .nonce_len = 5,
        },
        &.{ 0x35, 0x0d, 0x28, 0xb4, 0x20 },
        &.{ 0x34, 0x87, 0xd9, 0x70, 0x0b },
        "2a350d28b4203487d9700b",
    );
}

test "QUIC-LB draft-21 encrypted vectors" {
    try expectVector(
        .{
            .config_rotation = 0,
            .server_id_len = 3,
            .nonce_len = 4,
            .key = vector_key,
        },
        &.{ 0xed, 0x79, 0x3a },
        &.{ 0xee, 0x08, 0x0d, 0xbf },
        "0720b1d07b359d3c",
    );
    try expectVector(
        .{
            .config_rotation = 1,
            .server_id_len = 10,
            .nonce_len = 5,
            .key = vector_key,
        },
        &.{ 0xed, 0x79, 0x3a, 0x51, 0xd4, 0x9b, 0x8f, 0x5f, 0xab, 0x65 },
        &.{ 0xee, 0x08, 0x0d, 0xbf, 0x48 },
        "2fcc381bc74cb4fbad2823a3d1f8fed2",
    );
    // Appendix B prints this row with first octet 0x12. That contradicts its
    // own cr_bits=3 and 18-byte routing block: Section 3 requires
    // (3 << 5) | 18 == 0x72. The remaining encrypted bytes match the vector.
    try expectVector(
        .{
            .config_rotation = 2,
            .server_id_len = 8,
            .nonce_len = 8,
            .key = vector_key,
        },
        &.{ 0xed, 0x79, 0x3a, 0x51, 0xd4, 0x9b, 0x8f, 0x5f },
        &.{ 0xee, 0x08, 0x0d, 0xbf, 0x48, 0xc0, 0xd1, 0xe5 },
        "504dd2d05a7b0de9b2b9907afb5ecf8cc3",
    );
    // Server ID exceeds nonce length, so load-balancer decoding requires the
    // fourth Feistel pass rather than stopping after the left half.
    try expectVector(
        .{
            .config_rotation = 3,
            .server_id_len = 9,
            .nonce_len = 9,
            .key = vector_key,
        },
        &.{ 0xed, 0x79, 0x3a, 0x51, 0xd4, 0x9b, 0x8f, 0x5f, 0xab },
        &.{ 0xee, 0x08, 0x0d, 0xbf, 0x48, 0xc0, 0xd1, 0xe5, 0x5d },
        "725779c9cc86beb3a3a4a3ca96fce4bfe0cdbc",
    );
}

test "QUIC-LB draft-21 odd-length encryption example" {
    const key = [16]u8{
        0xfd, 0xf7, 0x26, 0xa9, 0x89, 0x3e, 0xc0, 0x5c,
        0x06, 0x32, 0xd3, 0x95, 0x66, 0x80, 0xba, 0xf0,
    };
    try expectVector(
        .{
            .config_rotation = 0,
            .server_id_len = 3,
            .nonce_len = 4,
            .key = key,
        },
        &.{ 0x31, 0x44, 0x1a },
        &.{ 0x9c, 0x69, 0xc2, 0x75 },
        "0767947d29be054a",
    );
}

test "QUIC-LB validates configuration and buffers before mutation" {
    try std.testing.expectEqualStrings(
        "draft-ietf-quic-load-balancers-21",
        quic_lb.specification,
    );
    const valid = quic_lb.Config{
        .config_rotation = 0,
        .server_id_len = 1,
        .nonce_len = 4,
    };
    try std.testing.expectError(
        error.ReservedConfigRotation,
        (quic_lb.Config{
            .config_rotation = 7,
            .server_id_len = 1,
            .nonce_len = 4,
        }).validate(),
    );
    try std.testing.expectError(
        error.InvalidServerIdLength,
        (quic_lb.Config{
            .config_rotation = 0,
            .server_id_len = 0,
            .nonce_len = 4,
        }).validate(),
    );
    try std.testing.expectError(
        error.InvalidNonceLength,
        (quic_lb.Config{
            .config_rotation = 0,
            .server_id_len = 1,
            .nonce_len = 3,
        }).validate(),
    );
    try std.testing.expectError(
        error.ConnectionIdTooLong,
        (quic_lb.Config{
            .config_rotation = 0,
            .server_id_len = 15,
            .nonce_len = 5,
        }).validate(),
    );

    var out = [_]u8{0xa5} ** 20;
    try std.testing.expectError(
        error.InvalidServerIdLength,
        quic_lb.encode(valid, "xx", "1234", 0, &out),
    );
    try std.testing.expectEqualSlices(u8, &([_]u8{0xa5} ** 20), &out);
    try std.testing.expectError(
        error.InvalidNonceLength,
        quic_lb.encode(valid, "x", "123", 0, &out),
    );
    try std.testing.expectEqualSlices(u8, &([_]u8{0xa5} ** 20), &out);
    try std.testing.expectError(
        error.BufferTooShort,
        quic_lb.encode(valid, "x", "1234", 0, out[0..5]),
    );
    try std.testing.expectEqualSlices(u8, &([_]u8{0xa5} ** 20), &out);
}

test "QUIC-LB validates rotation and encoded length while decoding" {
    const config = quic_lb.Config{
        .config_rotation = 2,
        .server_id_len = 2,
        .nonce_len = 4,
    };
    var cid_storage: [20]u8 = undefined;
    const cid = try quic_lb.encode(config, "id", "abcd", 0, &cid_storage);
    var server_id: [2]u8 = undefined;
    try std.testing.expectEqualStrings(
        "id",
        try quic_lb.decodeServerId(config, cid, &server_id),
    );

    var wrong_rotation = cid_storage;
    wrong_rotation[0] ^= 0x20;
    try std.testing.expectError(
        error.ConfigRotationMismatch,
        quic_lb.decodeServerId(config, wrong_rotation[0..cid.len], &server_id),
    );

    var wrong_length = cid_storage;
    wrong_length[0] = (wrong_length[0] & 0xe0) | 1;
    try std.testing.expectError(
        error.InvalidConnectionIdLength,
        quic_lb.decodeServerId(config, wrong_length[0..cid.len], &server_id),
    );
    try std.testing.expectError(
        error.BufferTooShort,
        quic_lb.decodeServerId(config, cid[0 .. cid.len - 1], &server_id),
    );
}

test "QUIC-LB supports every permitted routing-block length" {
    const key = [_]u8{0x5a} ** 16;
    var cid_storage: [quic_lb.max_connection_id_len]u8 = undefined;
    var server_id_storage: [quic_lb.max_server_id_len]u8 = undefined;
    var nonce_storage: [quic_lb.max_routing_block_len]u8 = undefined;
    var decoded: [quic_lb.max_server_id_len]u8 = undefined;

    for (5..quic_lb.max_routing_block_len + 1) |routing_len| {
        // Exercise both sides of the three-pass decoder optimization boundary:
        // short SIDs fit in the left half; long SIDs require the fourth pass.
        const sid_len = if (routing_len == 5)
            1
        else
            routing_len - quic_lb.min_nonce_len;
        const nonce_len = routing_len - sid_len;
        for (server_id_storage[0..sid_len], 0..) |*byte, index| {
            byte.* = @intCast(0x20 + index);
        }
        for (nonce_storage[0..nonce_len], 0..) |*byte, index| {
            byte.* = @intCast(0x80 + index);
        }
        const config = quic_lb.Config{
            .config_rotation = @intCast(routing_len % 7),
            .server_id_len = @intCast(sid_len),
            .nonce_len = @intCast(nonce_len),
            .key = key,
        };
        const cid = try quic_lb.encode(
            config,
            server_id_storage[0..sid_len],
            nonce_storage[0..nonce_len],
            0,
            &cid_storage,
        );
        try std.testing.expectEqual(routing_len + 1, cid.len);
        try std.testing.expectEqualSlices(
            u8,
            server_id_storage[0..sid_len],
            try quic_lb.decodeServerId(config, cid, &decoded),
        );
    }
}

test "QUIC-LB random low bits are preserved without length encoding" {
    const config = quic_lb.Config{
        .config_rotation = 5,
        .server_id_len = 2,
        .nonce_len = 4,
        .key = vector_key,
        .self_encoded_length = false,
    };
    var cid_storage: [20]u8 = undefined;
    const cid = try quic_lb.encode(config, "id", "abcd", 0x1b, &cid_storage);
    try std.testing.expectEqual(@as(u8, 0xbb), cid[0]);
    try std.testing.expectEqual(@as(u3, 5), quic_lb.extractConfigRotation(cid[0]));
    var server_id: [2]u8 = undefined;
    try std.testing.expectEqualStrings(
        "id",
        try quic_lb.decodeServerId(config, cid, &server_id),
    );
}

test "QUIC-LB appends server-use bytes outside the encrypted routing block" {
    const config = quic_lb.Config{
        .config_rotation = 4,
        .server_id_len = 3,
        .nonce_len = 4,
        .key = vector_key,
    };
    var cid_storage: [quic_lb.max_connection_id_len]u8 = undefined;
    const cid = try quic_lb.encodeWithServerUse(
        config,
        "sid",
        "abcd",
        "use",
        0,
        &cid_storage,
    );
    try std.testing.expectEqual(@as(usize, 11), cid.len);
    try std.testing.expectEqual(@as(usize, 11), quic_lb.encodedConnectionIdLen(cid[0]));
    try std.testing.expectEqualStrings("use", cid[cid.len - 3 ..]);
    var server_id: [3]u8 = undefined;
    try std.testing.expectEqualStrings(
        "sid",
        try quic_lb.decodeServerId(config, cid, &server_id),
    );

    try std.testing.expectError(
        error.ConnectionIdTooLong,
        quic_lb.encodeWithServerUse(
            config,
            "sid",
            "abcd",
            &([_]u8{0} ** 13),
            0,
            &cid_storage,
        ),
    );
}

fn expectVector(
    config: quic_lb.Config,
    server_id: []const u8,
    nonce: []const u8,
    expected_hex: []const u8,
) !void {
    var expected: [quic_lb.max_connection_id_len]u8 = undefined;
    const expected_bytes = try std.fmt.hexToBytes(&expected, expected_hex);
    var cid_storage: [quic_lb.max_connection_id_len]u8 = undefined;
    const cid = try quic_lb.encode(config, server_id, nonce, 0, &cid_storage);
    try std.testing.expectEqualSlices(u8, expected_bytes, cid);
    try std.testing.expectEqual(config.config_rotation, quic_lb.extractConfigRotation(cid[0]));
    try std.testing.expectEqual(cid.len, quic_lb.encodedConnectionIdLen(cid[0]));

    var decoded: [quic_lb.max_server_id_len]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        server_id,
        try quic_lb.decodeServerId(config, cid, &decoded),
    );
}
