const std = @import("std");
const websocket_root = @import("mod.zig");

const deflate = @import("../internal/deflate.zig");
const http1 = @import("../http1/mod.zig");

const CloseCode = websocket_root.CloseCode;
const ExtensionNegotiation = websocket_root.ExtensionNegotiation;
const Frame = websocket_root.Frame;
const FrameHeader = websocket_root.FrameHeader;
const MessageAssembler = websocket_root.MessageAssembler;
const Opcode = websocket_root.Opcode;
const Utf8Validator = websocket_root.Utf8Validator;
const acceptKey = websocket_root.acceptKey;
const applyMask = websocket_root.applyMask;
const applyMaskCopy = websocket_root.applyMaskCopy;
const compressMessage = websocket_root.compressMessage;
const compressMessageVortIntoWindow = websocket_root.compressMessageVortIntoWindow;
const decompressMessage = websocket_root.decompressMessage;
const max_frame_header_len = websocket_root.max_frame_header_len;
const max_frame_payload_len = websocket_root.max_frame_payload_len;
const parseClosePayload = websocket_root.parseClosePayload;
const parseClosePayloadOwned = websocket_root.parseClosePayloadOwned;
const parseFrameInPlaceWithHeader = websocket_root.parseFrameInPlaceWithHeader;
const parseFrameInto = websocket_root.parseFrameInto;
const parseFrameIntoWithHeader = websocket_root.parseFrameIntoWithHeader;
const parseFrameOptions = websocket_root.parseFrameOptions;
const parseFrameWithHeader = websocket_root.parseFrameWithHeader;
const validateClientHandshake = websocket_root.validateClientHandshake;
const validateClientHandshakeForVersionNegotiation = websocket_root.validateClientHandshakeForVersionNegotiation;
const validateClosePayload = websocket_root.validateClosePayload;
const writeClosePayload = websocket_root.writeClosePayload;
const writeClosePayloadInto = websocket_root.writeClosePayloadInto;
const writeFrame = websocket_root.writeFrame;
const writeFrameExtended = websocket_root.writeFrameExtended;
const writeFrameHeaderForLengthInto = websocket_root.writeFrameHeaderForLengthInto;
const writeFrameHeaderInto = websocket_root.writeFrameHeaderInto;
const writeFrameInto = websocket_root.writeFrameInto;

test "WebSocket incremental UTF-8 validator rejects decisive bytes" {
    var validator: Utf8Validator = .{};
    try validator.feed("valid \xe2");
    try validator.feed("\x82");
    try validator.feed("\xac text");
    try validator.finish();

    validator.reset();
    try validator.feedByte(0xf4);
    try std.testing.expectError(error.InvalidUtf8, validator.feedByte(0x90));

    validator.reset();
    try validator.feedByte(0xed);
    try std.testing.expectError(error.InvalidUtf8, validator.feedByte(0xa0));

    validator.reset();
    try validator.feedByte(0xe0);
    try std.testing.expectError(error.InvalidUtf8, validator.feedByte(0x9f));

    validator.reset();
    try validator.feedByte(0xf0);
    try std.testing.expectError(error.InvalidUtf8, validator.finish());
}

test "WebSocket incremental UTF-8 validator skips ASCII blocks safely" {
    var validator: Utf8Validator = .{};
    const ascii = "abcdefghijklmnopqrstuvwxyz0123456789" ** 8;
    try validator.feed(ascii);
    try validator.finish();

    validator.reset();
    try validator.feed(ascii ++ "\xe2");
    try validator.feed("\x82");
    try validator.feed("\xac" ++ ascii);
    try validator.finish();

    validator.reset();
    const invalid = ascii ++ "\xff" ++ ascii;
    try std.testing.expectError(error.InvalidUtf8, validator.feed(invalid));

    var storage = [_]u8{'x'} ** 96;
    for (0..64) |offset| {
        @memset(&storage, 'x');
        @memcpy(storage[offset..][0..3], "\xe2\x98\x83");
        validator.reset();
        try validator.feed(&storage);
        try validator.finish();

        storage[offset] = 0xff;
        validator.reset();
        try std.testing.expectError(
            error.InvalidUtf8,
            validator.feed(&storage),
        );
    }
}

test "WebSocket incremental UTF-8 validator handles masked offsets" {
    const key = [4]u8{ 0x12, 0x34, 0x56, 0x78 };
    var storage = [_]u8{'a'} ** 96;
    @memcpy(storage[31..34], "\xe2\x98\x83");
    const plain = storage;
    for (0..4) |mask_offset| {
        storage = plain;
        applyMask(&storage, key, mask_offset);
        var validator: Utf8Validator = .{};
        try validator.feedMasked(&storage, key, mask_offset);
        try validator.finish();

        storage = plain;
        storage[63] = 0xff;
        applyMask(&storage, key, mask_offset);
        validator.reset();
        try std.testing.expectError(
            error.InvalidUtf8,
            validator.feedMasked(&storage, key, mask_offset),
        );
    }

    var split = [_]u8{ 0xe2, 0x98, 0x83 };
    applyMask(&split, key, 3);
    var validator: Utf8Validator = .{};
    try validator.feedMasked(split[0..1], key, 3);
    try validator.feedMasked(split[1..2], key, 4);
    try validator.feedMasked(split[2..3], key, 5);
    try validator.finish();
}

test "WebSocket masked UTF-8 copy validates in one pass" {
    const key = [4]u8{ 0x12, 0x34, 0x56, 0x78 };
    const plain = ("vector-ascii-" ** 8) ++ "snowman: \xe2\x98\x83";
    for (0..4) |mask_offset| {
        var encoded = plain.*;
        applyMask(&encoded, key, mask_offset);
        var output: [plain.len]u8 = undefined;
        var validator: Utf8Validator = .{};
        try validator.feedMaskedCopy(
            &output,
            &encoded,
            key,
            mask_offset,
        );
        try validator.finish();
        try std.testing.expectEqualStrings(plain, &output);

        validator.reset();
        try validator.feedMaskedCopy(
            &encoded,
            &encoded,
            key,
            mask_offset,
        );
        try validator.finish();
        try std.testing.expectEqualStrings(plain, &encoded);
    }

    var invalid = [_]u8{ 0xf4, 0x90 };
    applyMask(&invalid, key, 3);
    var output: [invalid.len]u8 = undefined;
    var validator: Utf8Validator = .{};
    try std.testing.expectError(
        error.InvalidUtf8,
        validator.feedMaskedCopy(&output, &invalid, key, 3),
    );

    var split = [_]u8{ 0xe2, 0x98, 0x83 };
    applyMask(&split, key, 3);
    var decoded: [split.len]u8 = undefined;
    validator.reset();
    try validator.feedMaskedCopy(decoded[0..1], split[0..1], key, 3);
    try validator.feedMaskedCopy(decoded[1..2], split[1..2], key, 4);
    try validator.feedMaskedCopy(decoded[2..3], split[2..3], key, 5);
    try validator.finish();
    try std.testing.expectEqualStrings("\xe2\x98\x83", &decoded);
}

test "WebSocket accept key matches RFC example" {
    const key = acceptKey("dGhlIHNhbXBsZSBub25jZQ==");
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &key);
}

test "WebSocket frame masked roundtrip" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeFrame(&encoded, allocator, .text, "Hello", .{ .mask_key = .{ 1, 2, 3, 4 } });
    var frame = try parseFrameOptions(allocator, encoded.items, .{ .expect_mask = .masked });
    defer frame.deinit(allocator);
    try std.testing.expectEqual(Opcode.text, frame.header.opcode);
    try std.testing.expectEqualStrings("Hello", frame.payload);

    var payload = [_]u8{
        0,  1,  2,  3,  4,  5,  6,  7,
        8,  9,  10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31,
        32, 33, 34,
    };
    var expected = payload;
    const mask_key = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const offset = 3;
    for (&expected, 0..) |*byte, i| byte.* ^= mask_key[(offset + i) & 3];
    applyMask(&payload, mask_key, offset);
    try std.testing.expectEqualSlices(u8, &expected, &payload);
}

test "WebSocket frame decodes masked payload into caller storage" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeFrame(
        &encoded,
        allocator,
        .binary,
        "caller-owned",
        .{ .mask_key = .{ 1, 2, 3, 4 } },
    );

    var storage: [32]u8 = undefined;
    const frame = try parseFrameInto(
        &storage,
        encoded.items,
        .{ .expect_mask = .masked },
    );
    try std.testing.expectEqual(Opcode.binary, frame.header.opcode);
    try std.testing.expectEqualStrings("caller-owned", frame.payload);
    try std.testing.expectEqual(encoded.items.len, frame.consumed);
    try std.testing.expectError(
        error.BufferTooShort,
        parseFrameInto(
            storage[0..4],
            encoded.items,
            .{ .expect_mask = .masked },
        ),
    );

    var predecoded_storage: [32]u8 = undefined;
    const header = try FrameHeader.parse(encoded.items);
    const predecoded = try parseFrameIntoWithHeader(
        &predecoded_storage,
        encoded.items,
        header,
        .{ .expect_mask = .masked },
    );
    try std.testing.expectEqual(
        frame.header.header_len,
        predecoded.header.header_len,
    );
    try std.testing.expectEqual(
        frame.header.payload_len,
        predecoded.header.payload_len,
    );
    try std.testing.expectEqual(frame.header.opcode, predecoded.header.opcode);
    try std.testing.expectEqual(frame.header.masked, predecoded.header.masked);
    try std.testing.expectEqualStrings(frame.payload, predecoded.payload);
    try std.testing.expectEqual(frame.consumed, predecoded.consumed);

    const in_place = try allocator.dupe(u8, encoded.items);
    defer allocator.free(in_place);
    const decoded_in_place = try parseFrameInPlaceWithHeader(
        in_place,
        header,
        .{ .expect_mask = .masked },
    );
    try std.testing.expectEqualStrings(
        frame.payload,
        decoded_in_place.payload,
    );
    try std.testing.expectEqual(
        frame.consumed,
        decoded_in_place.consumed,
    );

    try std.testing.expectError(
        error.MaskedServerFrame,
        parseFrameIntoWithHeader(
            &predecoded_storage,
            encoded.items,
            header,
            .{ .expect_mask = .unmasked },
        ),
    );
}

test "WebSocket predecoded frame rejects total length overflow" {
    const header = FrameHeader{
        .fin = true,
        .opcode = .binary,
        .masked = false,
        .payload_len = @intCast(std.math.maxInt(usize)),
        .mask_key = null,
        .header_len = max_frame_header_len,
    };
    try std.testing.expectError(error.PayloadTooLarge, header.wireLen());
    try std.testing.expectError(
        error.PayloadTooLarge,
        parseFrameWithHeader(std.testing.allocator, &.{}, header, .{}),
    );

    var output: [0]u8 = .{};
    try std.testing.expectError(
        error.PayloadTooLarge,
        parseFrameIntoWithHeader(&output, &.{}, header, .{}),
    );
    try std.testing.expectError(
        error.PayloadTooLarge,
        parseFrameInPlaceWithHeader(&output, header, .{}),
    );
}

test "WebSocket caller-buffer frame encoding matches allocating writer" {
    const allocator = std.testing.allocator;
    const payload_lengths = [_]usize{
        0,
        1,
        125,
        126,
        std.math.maxInt(u16),
        @as(usize, std.math.maxInt(u16)) + 1,
    };

    for (payload_lengths) |payload_len| {
        const payload = try allocator.alloc(u8, payload_len);
        defer allocator.free(payload);
        for (payload, 0..) |*byte, index| byte.* = @truncate(index);

        for ([_]?[4]u8{ null, .{ 0x12, 0x34, 0x56, 0x78 } }) |mask_key| {
            var allocating: std.ArrayList(u8) = .empty;
            defer allocating.deinit(allocator);
            try writeFrameExtended(
                &allocating,
                allocator,
                .binary,
                payload,
                .{ .mask_key = mask_key },
            );

            const storage = try allocator.alloc(
                u8,
                payload_len + max_frame_header_len,
            );
            defer allocator.free(storage);
            const encoded = try writeFrameInto(
                storage,
                .binary,
                payload,
                .{ .mask_key = mask_key },
            );
            try std.testing.expectEqualSlices(
                u8,
                allocating.items,
                encoded,
            );

            const header = try FrameHeader.parse(encoded);
            try std.testing.expectEqual(
                @as(u64, @intCast(payload_len)),
                header.payload_len,
            );
            try std.testing.expectEqual(mask_key != null, header.masked);
        }
    }
}

test "WebSocket predecoded header parsers match ordinary parsers" {
    const allocator = std.testing.allocator;
    const payload_lengths = [_]usize{ 0, 1, 125, 126, 257 };
    for (payload_lengths) |payload_len| {
        const payload = try allocator.alloc(u8, payload_len);
        defer allocator.free(payload);
        for (payload, 0..) |*byte, index| byte.* = @truncate(index * 29);
        for ([_]?[4]u8{ null, .{ 9, 8, 7, 6 } }) |mask_key| {
            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(allocator);
            try writeFrame(
                &encoded,
                allocator,
                .binary,
                payload,
                .{ .mask_key = mask_key },
            );
            const header = try FrameHeader.parse(encoded.items);

            var ordinary = try parseFrameOptions(
                allocator,
                encoded.items,
                .{},
            );
            defer ordinary.deinit(allocator);
            var predecoded = try parseFrameWithHeader(
                allocator,
                encoded.items,
                header,
                .{},
            );
            defer predecoded.deinit(allocator);
            try std.testing.expectEqual(ordinary.consumed, predecoded.consumed);
            try std.testing.expectEqualSlices(
                u8,
                ordinary.payload,
                predecoded.payload,
            );

            const output = try allocator.alloc(u8, payload_len);
            defer allocator.free(output);
            const borrowed = try parseFrameIntoWithHeader(
                output,
                encoded.items,
                header,
                .{},
            );
            try std.testing.expectEqualSlices(u8, payload, borrowed.payload);

            const mutable_encoded = try allocator.dupe(u8, encoded.items);
            defer allocator.free(mutable_encoded);
            const in_place = try parseFrameInPlaceWithHeader(
                mutable_encoded,
                header,
                .{},
            );
            try std.testing.expectEqual(ordinary.consumed, in_place.consumed);
            try std.testing.expectEqualSlices(u8, payload, in_place.payload);
        }
    }
}

test "WebSocket length-only frame header matches payload-based encoder" {
    const payload_lengths = [_]usize{
        0,
        1,
        125,
        126,
        std.math.maxInt(u16),
        @as(usize, std.math.maxInt(u16)) + 1,
    };
    for (payload_lengths) |payload_len| {
        const payload = try std.testing.allocator.alloc(u8, payload_len);
        defer std.testing.allocator.free(payload);
        for ([_]?[4]u8{ null, .{ 1, 2, 3, 4 } }) |mask_key| {
            var expected_storage: [max_frame_header_len]u8 = undefined;
            const expected = try writeFrameHeaderInto(
                &expected_storage,
                .binary,
                payload,
                .{ .mask_key = mask_key },
            );
            var actual_storage: [max_frame_header_len]u8 = undefined;
            const actual = try writeFrameHeaderForLengthInto(
                &actual_storage,
                .binary,
                payload_len,
                .{ .mask_key = mask_key },
            );
            try std.testing.expectEqualSlices(u8, expected, actual);
        }
    }
    var storage: [max_frame_header_len]u8 = undefined;
    if (comptime @bitSizeOf(usize) >= 64) {
        const largest = try writeFrameHeaderForLengthInto(
            &storage,
            .binary,
            @intCast(max_frame_payload_len),
            .{},
        );
        const parsed = try FrameHeader.parse(largest);
        try std.testing.expectEqual(max_frame_payload_len, parsed.payload_len);
        @memset(&storage, 0xa5);
        try std.testing.expectError(
            error.PayloadTooLarge,
            writeFrameHeaderForLengthInto(
                &storage,
                .binary,
                @as(usize, @intCast(max_frame_payload_len)) + 1,
                .{},
            ),
        );
        try std.testing.expectEqualSlices(
            u8,
            &([_]u8{0xa5} ** max_frame_header_len),
            &storage,
        );
    }
    try std.testing.expectError(
        error.InvalidControlFrame,
        writeFrameHeaderForLengthInto(
            &storage,
            .ping,
            126,
            .{},
        ),
    );
}

test "WebSocket fixed frame encoder rejects short output transactionally" {
    var storage = [_]u8{0xa5} ** max_frame_header_len;
    try std.testing.expectError(
        error.BufferTooShort,
        writeFrameInto(
            &storage,
            .binary,
            "payload does not fit",
            .{ .mask_key = .{ 1, 2, 3, 4 } },
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{0xa5} ** max_frame_header_len),
        &storage,
    );
}

test "WebSocket mask copy preserves input and supports stream offsets" {
    const payload = "0123456789abcdef";
    var masked: [payload.len]u8 = undefined;
    const key = [4]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    const offset = 3;
    try applyMaskCopy(&masked, payload, key, offset);
    for (masked, 0..) |byte, index| {
        try std.testing.expectEqual(
            payload[index] ^ key[(offset + index) & 3],
            byte,
        );
    }
    try std.testing.expectEqualStrings("0123456789abcdef", payload);

    var short: [payload.len - 1]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooShort,
        applyMaskCopy(&short, payload, key, offset),
    );
}

test "WebSocket handshake validation" {
    const allocator = std.testing.allocator;
    const raw = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    var req = try http1.parseRequest(allocator, raw, .{});
    defer req.deinit(allocator);
    try validateClientHandshake(req);

    const unsupported_version =
        "GET /chat HTTP/1.1\r\nHost: example.com\r\n" ++
        "Upgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
        "Sec-WebSocket-Version: 12\r\n\r\n";
    var unsupported_req = try http1.parseRequest(
        allocator,
        unsupported_version,
        .{},
    );
    defer unsupported_req.deinit(allocator);
    try std.testing.expectError(
        error.UnsupportedVersion,
        validateClientHandshake(unsupported_req),
    );
    try validateClientHandshakeForVersionNegotiation(unsupported_req);

    const unsupported_with_bad_key =
        "GET /chat HTTP/1.1\r\nHost: example.com\r\n" ++
        "Upgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: not-base64\r\n" ++
        "Sec-WebSocket-Version: 12\r\n\r\n";
    var bad_key_req = try http1.parseRequest(
        allocator,
        unsupported_with_bad_key,
        .{},
    );
    defer bad_key_req.deinit(allocator);
    try std.testing.expectError(
        error.UnsupportedVersion,
        validateClientHandshake(bad_key_req),
    );
    try std.testing.expectError(
        error.InvalidHandshake,
        validateClientHandshakeForVersionNegotiation(bad_key_req),
    );

    const malformed_headers = try allocator.dupe(
        http1.Header,
        unsupported_req.headers,
    );
    defer allocator.free(malformed_headers);
    var malformed_req = unsupported_req;
    malformed_req.headers = malformed_headers;
    var version_header: ?*http1.Header = null;
    for (malformed_headers) |*header| {
        if (header.eqlName("sec-websocket-version")) {
            version_header = header;
            break;
        }
    }
    const version = version_header orelse return error.TestUnexpectedResult;
    for ([_][]const u8{ "", "012", "12, 13", "300" }) |malformed| {
        version.value = malformed;
        try std.testing.expectError(
            error.InvalidHandshake,
            validateClientHandshake(malformed_req),
        );
        try std.testing.expectError(
            error.InvalidHandshake,
            validateClientHandshakeForVersionNegotiation(malformed_req),
        );
    }

    var constructed_missing_host = req;
    constructed_missing_host.headers = req.headers[1..];
    try std.testing.expectError(
        error.MissingHeader,
        validateClientHandshake(constructed_missing_host),
    );

    const split_connection = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: keep-alive\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    var split_req = try http1.parseRequest(allocator, split_connection, .{});
    defer split_req.deinit(allocator);
    try validateClientHandshake(split_req);

    const listed_upgrade = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: h2c/1, WebSocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    var listed_upgrade_req = try http1.parseRequest(
        allocator,
        listed_upgrade,
        .{},
    );
    defer listed_upgrade_req.deinit(allocator);
    try validateClientHandshake(listed_upgrade_req);

    const split_upgrade = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: h2c/1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    var split_upgrade_req = try http1.parseRequest(
        allocator,
        split_upgrade,
        .{},
    );
    defer split_upgrade_req.deinit(allocator);
    try validateClientHandshake(split_upgrade_req);

    const invalid_upgrade = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: h2c/bad/version, websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    var invalid_upgrade_req = try http1.parseRequest(
        allocator,
        invalid_upgrade,
        .{},
    );
    defer invalid_upgrade_req.deinit(allocator);
    try std.testing.expectError(
        error.InvalidHandshake,
        validateClientHandshake(invalid_upgrade_req),
    );

    const http10 = "GET /chat HTTP/1.0\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    try std.testing.expectError(
        error.InvalidVersion,
        http1.parseRequest(allocator, http10, .{}),
    );

    const duplicate_key = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    var duplicate_key_req = try http1.parseRequest(allocator, duplicate_key, .{});
    defer duplicate_key_req.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateClientHandshake(duplicate_key_req));

    const missing_host = "GET /chat HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    try std.testing.expectError(
        error.InvalidHost,
        http1.parseRequest(allocator, missing_host, .{}),
    );

    const empty_host = "GET /chat HTTP/1.1\r\nHost: \t \r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    try std.testing.expectError(
        error.InvalidHost,
        http1.parseRequest(allocator, empty_host, .{}),
    );

    const invalid_host = "GET /chat HTTP/1.1\r\nHost: http://example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    try std.testing.expectError(
        error.InvalidHost,
        http1.parseRequest(allocator, invalid_host, .{}),
    );

    const unbracketed_ipv6_host = "GET /chat HTTP/1.1\r\nHost: 2001:db8::1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    try std.testing.expectError(
        error.InvalidHost,
        http1.parseRequest(allocator, unbracketed_ipv6_host, .{}),
    );

    const duplicate_host = "GET /chat HTTP/1.1\r\nHost: example.com\r\nHost: other.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    try std.testing.expectError(
        error.InvalidHost,
        http1.parseRequest(allocator, duplicate_host, .{}),
    );

    const valid_protocols = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat.v1, super-chat\r\n\r\n";
    var valid_protocols_req = try http1.parseRequest(allocator, valid_protocols, .{});
    defer valid_protocols_req.deinit(allocator);
    try validateClientHandshake(valid_protocols_req);

    const invalid_protocol = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat.v1, bad protocol\r\n\r\n";
    var invalid_protocol_req = try http1.parseRequest(allocator, invalid_protocol, .{});
    defer invalid_protocol_req.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateClientHandshake(invalid_protocol_req));

    const empty_protocol_members = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: , chat.v1,,\r\n\r\n";
    var empty_protocol_members_req = try http1.parseRequest(
        allocator,
        empty_protocol_members,
        .{},
    );
    defer empty_protocol_members_req.deinit(allocator);
    try validateClientHandshake(empty_protocol_members_req);

    const only_empty_protocols = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: , ,\r\n\r\n";
    var only_empty_protocols_req = try http1.parseRequest(
        allocator,
        only_empty_protocols,
        .{},
    );
    defer only_empty_protocols_req.deinit(allocator);
    try std.testing.expectError(
        error.InvalidHandshake,
        validateClientHandshake(only_empty_protocols_req),
    );

    const duplicate_protocol = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat.v1, chat.v1\r\n\r\n";
    var duplicate_protocol_req = try http1.parseRequest(allocator, duplicate_protocol, .{});
    defer duplicate_protocol_req.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateClientHandshake(duplicate_protocol_req));

    const split_duplicate_protocol = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: chat.v1\r\nSec-WebSocket-Protocol: chat.v2, chat.v1\r\n\r\n";
    var split_duplicate_protocol_req = try http1.parseRequest(allocator, split_duplicate_protocol, .{});
    defer split_duplicate_protocol_req.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateClientHandshake(split_duplicate_protocol_req));

    const valid_extensions = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: x-example; mode=\"safe\", permessage-deflate\r\n\r\n";
    var valid_extensions_req = try http1.parseRequest(
        allocator,
        valid_extensions,
        .{},
    );
    defer valid_extensions_req.deinit(allocator);
    try validateClientHandshake(valid_extensions_req);

    const declined_extension = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate; unknown=1\r\n\r\n";
    var declined_extension_req = try http1.parseRequest(
        allocator,
        declined_extension,
        .{},
    );
    defer declined_extension_req.deinit(allocator);
    try validateClientHandshake(declined_extension_req);

    const malformed_trailing_extension = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate\r\nSec-WebSocket-Extensions: broken extension\r\n\r\n";
    var malformed_trailing_extension_req = try http1.parseRequest(
        allocator,
        malformed_trailing_extension,
        .{},
    );
    defer malformed_trailing_extension_req.deinit(allocator);
    try std.testing.expectError(
        error.InvalidExtension,
        validateClientHandshake(malformed_trailing_extension_req),
    );

    const request_body = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nContent-Length: 4\r\n\r\nbody";
    var request_body_req = try http1.parseRequest(allocator, request_body, .{});
    defer request_body_req.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateClientHandshake(request_body_req));

    const chunked_request = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    var chunked_request_req = try http1.parseRequest(allocator, chunked_request, .{});
    defer chunked_request_req.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateClientHandshake(chunked_request_req));
}

test "WebSocket strict frame validation" {
    const allocator = std.testing.allocator;
    const unmasked_text = "\x81\x02hi";
    try std.testing.expectError(error.UnmaskedClientFrame, parseFrameOptions(allocator, unmasked_text, .{ .expect_mask = .masked }));

    const masked_server_ping = "\x89\x80\x01\x02\x03\x04";
    try std.testing.expectError(error.MaskedServerFrame, parseFrameOptions(allocator, masked_server_ping, .{ .expect_mask = .unmasked }));

    const non_minimal = "\x81\x7e\x00\x02hi";
    try std.testing.expectError(error.NonMinimalLength, parseFrameOptions(allocator, non_minimal, .{}));

    const rsv = "\xc1\x02hi";
    try std.testing.expectError(error.UnexpectedRsv, parseFrameOptions(allocator, rsv, .{}));

    const rsv_ping = "\xc9\x00";
    try std.testing.expectError(error.UnexpectedRsv, parseFrameOptions(allocator, rsv_ping, .{ .allow_rsv1 = true }));

    const rsv_continuation = "\xc0\x00";
    try std.testing.expectError(error.UnexpectedRsv, parseFrameOptions(allocator, rsv_continuation, .{ .allow_rsv1 = true }));

    const bad_utf8 = "\x81\x02\xc0\x80";
    try std.testing.expectError(error.InvalidUtf8, parseFrameOptions(allocator, bad_utf8, .{}));

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try std.testing.expectError(error.InvalidOpcode, writeFrame(&encoded, allocator, @enumFromInt(0x3), "", .{}));
    try std.testing.expectError(error.InvalidControlFrame, writeFrameExtended(&encoded, allocator, .ping, "", .{ .fin = false }));
    try std.testing.expectError(error.UnexpectedRsv, writeFrameExtended(&encoded, allocator, .ping, "", .{ .rsv1 = true }));
    try std.testing.expectError(error.UnexpectedRsv, writeFrameExtended(&encoded, allocator, .continuation, "", .{ .rsv1 = true }));
    var bad_close = [_]u8{ 0x03, 0xed };
    try std.testing.expectError(error.InvalidCloseCode, writeFrame(&encoded, allocator, .close, &bad_close, .{}));
    var invalid_text = [_]u8{ 0xc0, 0x80 };
    try std.testing.expectError(error.InvalidUtf8, writeFrame(&encoded, allocator, .text, &invalid_text, .{}));
}

test "WebSocket close payload validation" {
    const allocator = std.testing.allocator;
    var good_payload = [_]u8{ 0x03, 0xe8, 'b', 'y', 'e' };
    try validateClosePayload(&good_payload);
    const parsed = (try parseClosePayload(&good_payload)).?;
    try std.testing.expectEqual(CloseCode.normal_closure, parsed.code);
    try std.testing.expectEqualStrings("bye", parsed.reason);

    var owned = (try parseClosePayloadOwned(allocator, &good_payload)).?;
    defer owned.deinit(allocator);
    try std.testing.expectEqual(CloseCode.normal_closure, owned.code);
    try std.testing.expectEqualStrings("bye", owned.reason);

    try std.testing.expect((try parseClosePayload(&.{})) == null);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeClosePayload(&encoded, allocator, .{ .code = .going_away, .reason = "restart" });
    try std.testing.expectEqualSlices(u8, &.{ 0x03, 0xe9, 'r', 'e', 's', 't', 'a', 'r', 't' }, encoded.items);
    var fixed_storage: [125]u8 = undefined;
    const fixed_payload = try writeClosePayloadInto(
        &fixed_storage,
        .{ .code = .going_away, .reason = "restart" },
    );
    try std.testing.expectEqualSlices(u8, encoded.items, fixed_payload);
    const encoded_parsed = (try parseClosePayload(encoded.items)).?;
    try std.testing.expectEqual(CloseCode.going_away, encoded_parsed.code);
    try std.testing.expectEqualStrings("restart", encoded_parsed.reason);

    encoded.clearRetainingCapacity();
    try writeClosePayload(&encoded, allocator, null);
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);
    try std.testing.expectEqual(
        @as(usize, 0),
        (try writeClosePayloadInto(&fixed_storage, null)).len,
    );

    var bad_reserved = [_]u8{ 0x03, 0xed };
    try std.testing.expectError(error.InvalidCloseCode, validateClosePayload(&bad_reserved));
    try std.testing.expectError(error.InvalidCloseCode, writeClosePayload(&encoded, allocator, .{ .code = .no_status_received }));

    var bad_utf8 = [_]u8{ 0x03, 0xe8, 0xc0, 0x80 };
    try std.testing.expectError(error.InvalidUtf8, validateClosePayload(&bad_utf8));
    try std.testing.expectError(error.InvalidUtf8, writeClosePayload(&encoded, allocator, .{ .code = .normal_closure, .reason = "\xc0\x80" }));

    try std.testing.expectError(error.InvalidControlFrame, writeClosePayload(&encoded, allocator, .{ .code = .normal_closure, .reason = "x" ** 124 }));
}

test "WebSocket permessage-deflate helpers negotiate and roundtrip" {
    const allocator = std.testing.allocator;

    const accepted = try ExtensionNegotiation.accept(
        allocator,
        "permessage-deflate; client_no_context_takeover; server_max_window_bits=\"15\"",
        true,
    );
    defer if (accepted) |value| allocator.free(value);
    try std.testing.expect(accepted != null);
    try std.testing.expect(std.mem.indexOf(u8, accepted.?, "permessage-deflate") != null);
    const response = try ExtensionNegotiation.validateResponse(accepted.?);
    try std.testing.expect(response.permessage_deflate);
    try std.testing.expect(response.client_no_context_takeover);
    try std.testing.expect(response.server_no_context_takeover);

    const bounded = try ExtensionNegotiation.acceptWithPolicy(
        allocator,
        "permessage-deflate; client_max_window_bits=12; server_max_window_bits=11",
        .{
            .enable_permessage_deflate = true,
            .allow_context_takeover = true,
            .accept_client_max_window_bits = 9,
            .accept_server_max_window_bits = 10,
        },
    );
    defer if (bounded) |value| allocator.free(value);
    try std.testing.expectEqualStrings(
        "permessage-deflate; client_max_window_bits=9; server_max_window_bits=10",
        bounded.?,
    );
    const selected_window_response = try ExtensionNegotiation
        .validateResponseWithPolicy(bounded.?, .{
        .enable_permessage_deflate = true,
        .allow_context_takeover = true,
    });
    try std.testing.expectEqual(
        @as(?u8, 9),
        selected_window_response.client_max_window_bits,
    );
    try std.testing.expectEqual(
        @as(?u8, 10),
        selected_window_response.server_max_window_bits,
    );

    const peer_bounded = try ExtensionNegotiation.acceptWithPolicy(
        allocator,
        "permessage-deflate; client_max_window_bits=8; server_max_window_bits=9",
        .{
            .enable_permessage_deflate = true,
            .accept_client_max_window_bits = 12,
            .accept_server_max_window_bits = 12,
        },
    );
    defer if (peer_bounded) |value| allocator.free(value);
    try std.testing.expect(std.mem.indexOf(
        u8,
        peer_bounded.?,
        "client_max_window_bits=8; server_max_window_bits=9",
    ) != null);
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.acceptWithPolicy(
            allocator,
            "permessage-deflate",
            .{
                .enable_permessage_deflate = true,
                .accept_client_max_window_bits = 7,
            },
        ),
    );

    var offer_storage: [ExtensionNegotiation.max_offer_value_len]u8 = undefined;
    const bounded_offer = try ExtensionNegotiation.offerValueInto(
        &offer_storage,
        .{
            .enable_permessage_deflate = true,
            .allow_context_takeover = true,
        },
        9,
        10,
    );
    try std.testing.expectEqualStrings(
        "permessage-deflate; client_max_window_bits=9; server_max_window_bits=10",
        bounded_offer.?,
    );
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.offerValueInto(
            &offer_storage,
            .{ .enable_permessage_deflate = true },
            16,
            null,
        ),
    );

    const split_headers = [_]http1.Header{
        .{ .name = "Sec-WebSocket-Extensions", .value = "x-unknown" },
        .{ .name = "Sec-WebSocket-Extensions", .value = "permessage-deflate; client_no_context_takeover; server_max_window_bits=15" },
    };
    const accepted_split = try ExtensionNegotiation.acceptClientHeaders(allocator, &split_headers, true);
    defer if (accepted_split) |value| allocator.free(value);
    try std.testing.expect(accepted_split != null);
    try std.testing.expect(std.mem.startsWith(u8, accepted_split.?, "permessage-deflate"));

    const small_window = try ExtensionNegotiation.accept(
        allocator,
        "permessage-deflate; server_max_window_bits=12",
        true,
    );
    defer if (small_window) |value| allocator.free(value);
    try std.testing.expectEqualStrings(
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover; server_max_window_bits=12",
        small_window.?,
    );
    try std.testing.expectError(error.InvalidExtension, ExtensionNegotiation.validateResponse("permessage-deflate"));
    const quoted_window_response = try ExtensionNegotiation.validateResponse(
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover; client_max_window_bits=\"15\"",
    );
    try std.testing.expectEqual(@as(?u8, 15), quoted_window_response.client_max_window_bits);
    const small_window_response = try ExtensionNegotiation.validateResponse(
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover; client_max_window_bits=\"12\"",
    );
    try std.testing.expectEqual(@as(?u8, 12), small_window_response.client_max_window_bits);
    const split_response_headers = [_]http1.Header{
        .{ .name = "Sec-WebSocket-Extensions", .value = "" },
        .{
            .name = "Sec-WebSocket-Extensions",
            .value = "permessage-deflate",
        },
    };
    const split_response = try ExtensionNegotiation
        .validateResponseHeadersForOfferWithPolicy(
        &split_response_headers,
        "permessage-deflate",
        .{
            .enable_permessage_deflate = true,
            .allow_context_takeover = true,
        },
    );
    try std.testing.expect(split_response.permessage_deflate);

    const duplicate_response_headers = [_]http1.Header{
        .{
            .name = "Sec-WebSocket-Extensions",
            .value = "permessage-deflate",
        },
        .{
            .name = "Sec-WebSocket-Extensions",
            .value = ", permessage-deflate",
        },
    };
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.validateResponseHeadersForOfferWithPolicy(
            &duplicate_response_headers,
            "permessage-deflate",
            .{
                .enable_permessage_deflate = true,
                .allow_context_takeover = true,
            },
        ),
    );

    const unknown_response_headers = [_]http1.Header{
        .{
            .name = "Sec-WebSocket-Extensions",
            .value = "permessage-deflate",
        },
        .{ .name = "Sec-WebSocket-Extensions", .value = "x-unknown" },
    };
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.validateResponseHeadersForOfferWithPolicy(
            &unknown_response_headers,
            "permessage-deflate",
            .{
                .enable_permessage_deflate = true,
                .allow_context_takeover = true,
            },
        ),
    );
    var invalid_window_output: std.ArrayList(u8) = .empty;
    defer invalid_window_output.deinit(allocator);
    try std.testing.expectError(
        error.InvalidExtension,
        compressMessageVortIntoWindow(
            &invalid_window_output,
            allocator,
            "invalid compression window",
            7,
        ),
    );
    const escaped_window_response = try ExtensionNegotiation.validateResponse(
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover; client_max_window_bits=\"1\\5\"",
    );
    try std.testing.expectEqual(
        @as(?u8, 15),
        escaped_window_response.client_max_window_bits,
    );
    try std.testing.expectError(error.InvalidExtension, ExtensionNegotiation.validateResponse(
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover; client_max_window_bits=\"1\\ 5\"",
    ));
    try std.testing.expectError(error.InvalidExtension, ExtensionNegotiation.validateResponse(
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover, x-unknown",
    ));
    try std.testing.expectError(error.InvalidExtension, ExtensionNegotiation.validateResponse(
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover, permessage-deflate; server_no_context_takeover; client_no_context_takeover",
    ));
    const unknown_parameter = try ExtensionNegotiation.parseOffer(
        "permessage-deflate; server_no_context_takeover; x-unknown=1",
    );
    try std.testing.expect(!unknown_parameter.permessage_deflate);
    const declined_accept = try ExtensionNegotiation.accept(
        allocator,
        "permessage-deflate; x-unknown=1",
        true,
    );
    try std.testing.expect(declined_accept == null);
    const duplicate_parameter = try ExtensionNegotiation.parseOffer(
        "permessage-deflate; client_no_context_takeover; client_no_context_takeover",
    );
    try std.testing.expect(!duplicate_parameter.permessage_deflate);
    const duplicate_window = try ExtensionNegotiation.parseOffer(
        "permessage-deflate; server_max_window_bits=15; server_max_window_bits=15",
    );
    try std.testing.expect(!duplicate_window.permessage_deflate);
    const later_valid_offer = try ExtensionNegotiation.parseOffer(
        "permessage-deflate; x-unknown=1, " ++
            "permessage-deflate; server_max_window_bits=12",
    );
    try std.testing.expect(later_valid_offer.permessage_deflate);
    try std.testing.expectEqual(
        @as(?u8, 12),
        later_valid_offer.server_max_window_bits,
    );
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.parseOffer(
            "permessage-deflate, broken extension",
        ),
    );
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.parseOffer(
            "x-example; mode=\"not a token\"",
        ),
    );
    const empty_members = try ExtensionNegotiation.parseOffer(
        ", permessage-deflate,,",
    );
    try std.testing.expect(empty_members.permessage_deflate);
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.parseOffer(", ,"),
    );

    const valid_unknown_then_known = try ExtensionNegotiation.parseOffer(
        "x-example; mode=\"safe\", permessage-deflate; server_max_window_bits=12",
    );
    try std.testing.expect(valid_unknown_then_known.permessage_deflate);
    try std.testing.expectEqual(
        @as(?u8, 12),
        valid_unknown_then_known.server_max_window_bits,
    );
    const escaped_window_offer = try ExtensionNegotiation.parseOffer(
        "permessage-deflate; server_max_window_bits=\"\\1\\2\"",
    );
    try std.testing.expectEqual(
        @as(?u8, 12),
        escaped_window_offer.server_max_window_bits,
    );

    const complete_headers = [_]http1.Header{
        .{
            .name = "Sec-WebSocket-Extensions",
            .value = "",
        },
        .{
            .name = "Sec-WebSocket-Extensions",
            .value = "permessage-deflate",
        },
        .{
            .name = "Sec-WebSocket-Extensions",
            .value = "x-example; mode=\"safe\"",
        },
    };
    const complete_accept = try ExtensionNegotiation
        .acceptClientHeadersWithPolicy(
        allocator,
        &complete_headers,
        .{ .enable_permessage_deflate = true },
    );
    defer if (complete_accept) |value| allocator.free(value);
    try std.testing.expect(complete_accept != null);

    const empty_headers = [_]http1.Header{
        .{ .name = "Sec-WebSocket-Extensions", .value = "" },
        .{ .name = "Sec-WebSocket-Extensions", .value = ", ," },
    };
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.acceptClientHeadersWithPolicy(
            allocator,
            &empty_headers,
            .{ .enable_permessage_deflate = false },
        ),
    );

    const malformed_later_headers = [_]http1.Header{
        .{
            .name = "Sec-WebSocket-Extensions",
            .value = "permessage-deflate",
        },
        .{
            .name = "Sec-WebSocket-Extensions",
            .value = "x-example; mode=\"not a token\"",
        },
    };
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.acceptClientHeadersWithPolicy(
            allocator,
            &malformed_later_headers,
            .{ .enable_permessage_deflate = true },
        ),
    );
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.acceptWithPolicy(
            allocator,
            "permessage-deflate, broken extension",
            .{ .enable_permessage_deflate = false },
        ),
    );

    try std.testing.expect(ExtensionNegotiation.offerValue(.{}) == null);
    try std.testing.expectEqualStrings(
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
        ExtensionNegotiation.offerValue(.{
            .enable_permessage_deflate = true,
        }).?,
    );
    try std.testing.expectEqualStrings(
        "permessage-deflate",
        ExtensionNegotiation.offerValue(.{
            .enable_permessage_deflate = true,
            .allow_context_takeover = true,
        }).?,
    );
    const takeover_accept = try ExtensionNegotiation.acceptWithPolicy(
        allocator,
        "permessage-deflate",
        .{
            .enable_permessage_deflate = true,
            .allow_context_takeover = true,
        },
    );
    defer if (takeover_accept) |value| allocator.free(value);
    try std.testing.expectEqualStrings(
        "permessage-deflate",
        takeover_accept.?,
    );
    const takeover_response = try ExtensionNegotiation
        .validateResponseWithPolicy(
        takeover_accept,
        .{
            .enable_permessage_deflate = true,
            .allow_context_takeover = true,
        },
    );
    try std.testing.expect(takeover_response.permessage_deflate);
    try std.testing.expect(!takeover_response.client_no_context_takeover);
    try std.testing.expect(!takeover_response.server_no_context_takeover);
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.validateResponseWithPolicy(
            "permessage-deflate",
            .{ .enable_permessage_deflate = false },
        ),
    );

    const permissive_policy: ExtensionNegotiation.Policy = .{
        .enable_permessage_deflate = true,
        .allow_context_takeover = true,
    };
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.validateResponseWithPolicy(
            "permessage-deflate; x-unknown=1",
            permissive_policy,
        ),
    );
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.validateResponseForOfferWithPolicy(
            "permessage-deflate; client_max_window_bits=15",
            "permessage-deflate",
            permissive_policy,
        ),
    );
    const implicit_client_window = try ExtensionNegotiation
        .validateResponseForOfferWithPolicy(
        "permessage-deflate; client_max_window_bits=8",
        "permessage-deflate; client_max_window_bits",
        permissive_policy,
    );
    try std.testing.expectEqual(
        @as(?u8, 8),
        implicit_client_window.client_max_window_bits,
    );
    const maximum_implicit_client_window = try ExtensionNegotiation
        .validateResponseForOfferWithPolicy(
        "permessage-deflate; client_max_window_bits=15",
        "permessage-deflate; client_max_window_bits",
        permissive_policy,
    );
    try std.testing.expectEqual(
        @as(?u8, 15),
        maximum_implicit_client_window.client_max_window_bits,
    );
    const client_window_hint_is_not_a_limit = try ExtensionNegotiation
        .validateResponseForOfferWithPolicy(
        "permessage-deflate; client_max_window_bits=13",
        "permessage-deflate; client_max_window_bits=12",
        permissive_policy,
    );
    try std.testing.expectEqual(
        @as(?u8, 13),
        client_window_hint_is_not_a_limit.client_max_window_bits,
    );
    for ([_]u8{ 11, 12 }) |bits| {
        var response_buffer: [64]u8 = undefined;
        const bounded_response = try std.fmt.bufPrint(
            &response_buffer,
            "permessage-deflate; client_max_window_bits={d}",
            .{bits},
        );
        const bounded_client_window = try ExtensionNegotiation
            .validateResponseForOfferWithPolicy(
            bounded_response,
            "permessage-deflate; client_max_window_bits=12",
            permissive_policy,
        );
        try std.testing.expectEqual(
            @as(?u8, bits),
            bounded_client_window.client_max_window_bits,
        );
    }
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.validateResponseForOfferWithPolicy(
            "permessage-deflate; client_max_window_bits",
            "permessage-deflate; client_max_window_bits",
            permissive_policy,
        ),
    );
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.validateResponseForOfferWithPolicy(
            "permessage-deflate; server_max_window_bits",
            "permessage-deflate",
            permissive_policy,
        ),
    );
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.validateResponseForOfferWithPolicy(
            "permessage-deflate; client_max_window_bits=08",
            "permessage-deflate; client_max_window_bits",
            permissive_policy,
        ),
    );
    const invalid_window_offer = try ExtensionNegotiation.parseOffer(
        "permessage-deflate; server_max_window_bits=012",
    );
    try std.testing.expect(!invalid_window_offer.permessage_deflate);
    const unsolicited_server_window = try ExtensionNegotiation
        .validateResponseForOfferWithPolicy(
        "permessage-deflate; server_max_window_bits=12",
        "permessage-deflate",
        permissive_policy,
    );
    try std.testing.expectEqual(
        @as(?u8, 12),
        unsolicited_server_window.server_max_window_bits,
    );
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.validateResponseForOfferWithPolicy(
            "permessage-deflate; server_max_window_bits=13",
            "permessage-deflate; server_max_window_bits=12",
            permissive_policy,
        ),
    );
    const bounded_server_window = try ExtensionNegotiation
        .validateResponseForOfferWithPolicy(
        "permessage-deflate; server_max_window_bits=12",
        "permessage-deflate; server_max_window_bits=12",
        permissive_policy,
    );
    try std.testing.expectEqual(
        @as(?u8, 12),
        bounded_server_window.server_max_window_bits,
    );
    const matching_offer = try ExtensionNegotiation
        .validateResponseForOfferWithPolicy(
        "permessage-deflate; client_max_window_bits=12; server_max_window_bits=11",
        "permessage-deflate, " ++
            "permessage-deflate; client_max_window_bits=12; server_max_window_bits=11",
        permissive_policy,
    );
    try std.testing.expectEqual(
        @as(?u8, 12),
        matching_offer.client_max_window_bits,
    );
    try std.testing.expectError(
        error.InvalidExtension,
        ExtensionNegotiation.validateResponseForOfferWithPolicy(
            "permessage-deflate; client_max_window_bits=13; server_max_window_bits=12",
            "permessage-deflate, " ++
                "permessage-deflate; client_max_window_bits=13; server_max_window_bits=11",
            permissive_policy,
        ),
    );

    const payload = "compress me compress me compress me compress me";
    const compressed = try compressMessage(allocator, payload);
    defer allocator.free(compressed);
    try std.testing.expect(compressed.len < payload.len);
    try std.testing.expect(!std.mem.endsWith(u8, compressed, "\x00\x00\xff\xff"));
    const decoded = try decompressMessage(allocator, compressed, 1024);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(payload, decoded);

    // Two identical pseudo-random halves have no useful local repetition, so
    // a 512-byte window cannot refer back to the first half while a 32-KiB
    // window can. This guards the negotiated bound in the actual encoder, not
    // merely the extension response text.
    var distant_repeat: [2048]u8 = undefined;
    var state: u32 = 0x9e37_79b9;
    for (distant_repeat[0..1024]) |*byte| {
        state = state *% 1_664_525 +% 1_013_904_223;
        byte.* = @truncate(state >> 24);
    }
    @memcpy(distant_repeat[1024..], distant_repeat[0..1024]);
    var small_window_encoded: std.ArrayList(u8) = .empty;
    defer small_window_encoded.deinit(allocator);
    _ = try compressMessageVortIntoWindow(
        &small_window_encoded,
        allocator,
        &distant_repeat,
        9,
    );
    var full_window_encoded: std.ArrayList(u8) = .empty;
    defer full_window_encoded.deinit(allocator);
    _ = try compressMessageVortIntoWindow(
        &full_window_encoded,
        allocator,
        &distant_repeat,
        15,
    );
    try std.testing.expect(
        small_window_encoded.items.len > full_window_encoded.items.len + 512,
    );
    const small_window_decoded = try decompressMessage(
        allocator,
        small_window_encoded.items,
        distant_repeat.len,
    );
    defer allocator.free(small_window_decoded);
    try std.testing.expectEqualSlices(
        u8,
        &distant_repeat,
        small_window_decoded,
    );

    const repeated_payload = "fragmented compressed message fragmented compressed message";
    const repeated_compressed = try compressMessage(allocator, repeated_payload);
    defer allocator.free(repeated_compressed);
    const repeated_decoded = try decompressMessage(allocator, repeated_compressed, 1024);
    defer allocator.free(repeated_decoded);
    try std.testing.expectEqualStrings(repeated_payload, repeated_decoded);

    var assembler = MessageAssembler.initLimited(allocator, 1024);
    defer assembler.deinit();
    const split = repeated_compressed.len / 2;
    const compressed_first = Frame{
        .header = .{
            .fin = false,
            .rsv1 = true,
            .opcode = .text,
            .masked = false,
            .payload_len = split,
            .mask_key = null,
            .header_len = 2,
        },
        .payload = repeated_compressed[0..split],
        .consumed = 2 + split,
    };
    try std.testing.expectEqual(@as(?MessageAssembler.Message, null), try assembler.feed(compressed_first));
    const compressed_tail = Frame{
        .header = .{
            .fin = true,
            .opcode = .continuation,
            .masked = false,
            .payload_len = repeated_compressed.len - split,
            .mask_key = null,
            .header_len = 2,
        },
        .payload = repeated_compressed[split..],
        .consumed = 2 + repeated_compressed.len - split,
    };
    const compressed_message = (try assembler.feed(compressed_tail)).?;
    defer allocator.free(compressed_message.payload);
    try std.testing.expect(compressed_message.compressed);
    const fragmented_decoded = try decompressMessage(allocator, compressed_message.payload, 1024);
    defer allocator.free(fragmented_decoded);
    try std.testing.expectEqualStrings(repeated_payload, fragmented_decoded);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeFrameExtended(&encoded, allocator, .text, compressed, .{ .rsv1 = true });
    var frame = try parseFrameOptions(allocator, encoded.items, .{ .allow_rsv1 = true, .validate_utf8 = false });
    defer frame.deinit(allocator);
    try std.testing.expect(frame.header.rsv1);
    try std.testing.expectError(error.PayloadTooLarge, decompressMessage(allocator, frame.payload, 4));
}

test "WebSocket message assembler enforces aggregate payload limit" {
    const allocator = std.testing.allocator;
    var assembler = MessageAssembler.initLimited(allocator, 8);
    defer assembler.deinit();

    var first_payload = [_]u8{ 'h', 'e', 'l', 'l', 'o' };
    const first = Frame{
        .header = .{
            .fin = false,
            .opcode = .text,
            .masked = false,
            .payload_len = first_payload.len,
            .mask_key = null,
            .header_len = 2,
        },
        .payload = &first_payload,
        .consumed = 2 + first_payload.len,
    };
    try std.testing.expectEqual(@as(?MessageAssembler.Message, null), try assembler.feed(first));

    var second_payload = [_]u8{ 'w', 'o', 'r', 'l', 'd' };
    const second = Frame{
        .header = .{
            .fin = true,
            .opcode = .continuation,
            .masked = false,
            .payload_len = second_payload.len,
            .mask_key = null,
            .header_len = 2,
        },
        .payload = &second_payload,
        .consumed = 2 + second_payload.len,
    };
    try std.testing.expectError(error.PayloadTooLarge, assembler.feed(second));
}

test "WebSocket message assembler owns a complete frame with one exact allocation" {
    const payload = "single-frame-owned-payload";
    var tracking = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    const allocator = tracking.allocator();
    var assembler = MessageAssembler.initLimited(allocator, payload.len);
    defer assembler.deinit();
    const frame = Frame{
        .header = .{
            .fin = true,
            .opcode = .binary,
            .masked = false,
            .payload_len = payload.len,
            .mask_key = null,
            .header_len = 2,
        },
        .payload = @constCast(payload),
        .consumed = 2 + payload.len,
    };

    const message = (try assembler.feed(frame)).?;
    defer allocator.free(message.payload);
    try std.testing.expectEqualStrings(payload, message.payload);
    try std.testing.expectEqual(@as(usize, 1), tracking.allocations);
    try std.testing.expectEqual(@as(usize, 0), tracking.resize_index);
    try std.testing.expectEqual(payload.len, tracking.allocated_bytes);
}

test "WebSocket message assembler validates completed text fragments" {
    const allocator = std.testing.allocator;
    var assembler = MessageAssembler.init(allocator);
    defer assembler.deinit();

    var first_payload = [_]u8{0xf0};
    const first = Frame{
        .header = .{
            .fin = false,
            .opcode = .text,
            .masked = false,
            .payload_len = first_payload.len,
            .mask_key = null,
            .header_len = 2,
        },
        .payload = &first_payload,
        .consumed = 2 + first_payload.len,
    };
    try std.testing.expectEqual(@as(?MessageAssembler.Message, null), try assembler.feed(first));

    var invalid_tail = [_]u8{ 0x28, 0x8c, 0x28 };
    const second = Frame{
        .header = .{
            .fin = true,
            .opcode = .continuation,
            .masked = false,
            .payload_len = invalid_tail.len,
            .mask_key = null,
            .header_len = 2,
        },
        .payload = &invalid_tail,
        .consumed = 2 + invalid_tail.len,
    };
    try std.testing.expectError(error.InvalidUtf8, assembler.feed(second));

    assembler.deinit();
    assembler = MessageAssembler.init(allocator);
    var compressed_first_payload = [_]u8{0xf0};
    const compressed_first = Frame{
        .header = .{
            .fin = false,
            .rsv1 = true,
            .opcode = .text,
            .masked = false,
            .payload_len = compressed_first_payload.len,
            .mask_key = null,
            .header_len = 2,
        },
        .payload = &compressed_first_payload,
        .consumed = 2 + compressed_first_payload.len,
    };
    try std.testing.expectEqual(@as(?MessageAssembler.Message, null), try assembler.feed(compressed_first));

    const compressed_message = (try assembler.feed(second)).?;
    defer allocator.free(compressed_message.payload);
    try std.testing.expect(compressed_message.compressed);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xf0, 0x28, 0x8c, 0x28 }, compressed_message.payload);
}

test "WebSocket handshake rejects malformed nonce" {
    const allocator = std.testing.allocator;
    const raw = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: not-base64\r\nSec-WebSocket-Version: 13\r\n\r\n";
    var req = try http1.parseRequest(allocator, raw, .{});
    defer req.deinit(allocator);
    try std.testing.expectError(error.InvalidHandshake, validateClientHandshake(req));
}
