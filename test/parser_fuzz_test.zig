//! Bounded cross-protocol parser fuzz targets.
//!
//! Ordinary tests replay the structured seed corpus. Run the fuzz-parsers
//! build step with --fuzz=N for coverage-guided mutation. Every generated
//! parser input is capped at 64 KiB.

const std = @import("std");
const netz = @import("netz");

const max_input_bytes = 64 * 1024;

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

const http_get_seed = smithSliceSeed(
    "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
);
const http_chunked_seed = smithSliceSeed(
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "4\r\ntest\r\n0\r\nX-End: yes\r\n\r\n",
);
const http_ambiguous_seed = smithSliceSeed(
    "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n" ++
        "Content-Length: 2\r\n\r\nx",
);

test "fuzz bounded cross-protocol parsers" {
    try std.testing.fuzz({}, fuzzAllParsers, .{ .corpus = &.{
        &http_get_seed,
        &http_chunked_seed,
        &http_ambiguous_seed,
        &websocket_text_seed,
        &websocket_close_seed,
        &websocket_extended_seed,
        &webtransport_close_seed,
        &webtransport_datagram_seed,
        &webtransport_bidi_seed,
        &webtransport_uni_seed,
        &mqtt_connect_seed,
        &mqtt_publish_seed,
        &mqtt_subscribe_seed,
        &mqtt_bad_length_seed,
    } });
}

test "bounded deterministic parser mutation smoke" {
    const seeds = [_][]const u8{
        http_get_seed[4..],
        http_chunked_seed[4..],
        http_ambiguous_seed[4..],
        websocket_text_seed[4..],
        websocket_close_seed[4..],
        websocket_extended_seed[4..],
        webtransport_close_seed[4..],
        webtransport_datagram_seed[4..],
        webtransport_bidi_seed[4..],
        webtransport_uni_seed[4..],
        mqtt_connect_seed[4..],
        mqtt_publish_seed[4..],
        mqtt_subscribe_seed[4..],
        mqtt_bad_length_seed[4..],
    };
    var buffer: [max_input_bytes]u8 = undefined;
    for (seeds) |seed| {
        try exerciseAll(seed);
        for (0..seed.len + 1) |length| try exerciseAll(seed[0..length]);
        for (seed, 0..) |_, index| {
            @memcpy(buffer[0..seed.len], seed);
            buffer[index] ^= 0xff;
            try exerciseAll(buffer[0..seed.len]);
        }
        @memcpy(buffer[0..seed.len], seed);
        const appended = @min(seed.len + 4, buffer.len);
        @memset(buffer[seed.len..appended], 0xff);
        try exerciseAll(buffer[0..appended]);
    }

    var prng = std.Random.DefaultPrng.init(0x6e65747a5f66757a);
    const random = prng.random();
    for (0..256) |_| {
        const length = random.uintLessThan(usize, 4097);
        random.bytes(buffer[0..length]);
        try exerciseAll(buffer[0..length]);
    }
}

fn fuzzAllParsers(_: void, smith: *std.testing.Smith) !void {
    var storage: [max_input_bytes]u8 = undefined;
    const bytes = storage[0..smith.slice(&storage)];
    try exerciseAll(bytes);
}

fn exerciseAll(bytes: []const u8) !void {
    try exerciseHttp(bytes);
    try exerciseWebSocket(bytes);
    try exerciseWebTransport(bytes);
    try exerciseMqtt(bytes);
}

fn exerciseHttp(bytes: []const u8) !void {
    const allocator = std.testing.allocator;
    const options = netz.http1.ParseOptions{
        .max_headers = 128,
        .max_request_target_bytes = 8 * 1024,
    };
    var headers: [128]netz.http1.Header = undefined;
    if (netz.http1.parseRequestHead(bytes, &headers, options)) |head| {
        try std.testing.expect(head.head_len <= bytes.len);
        try std.testing.expect(head.headers.len <= headers.len);
    } else |_| {}
    if (netz.http1.parseResponseHead(bytes, &headers, options, .{})) |head| {
        try std.testing.expect(head.head_len <= bytes.len);
        try std.testing.expect(head.headers.len <= headers.len);
    } else |_| {}
    if (netz.http1.parseRequest(allocator, bytes, options)) |value| {
        var request = value;
        defer request.deinit(allocator);
        try std.testing.expect(request.consumed <= bytes.len);
        try std.testing.expect(request.headers.len <= options.max_headers);
    } else |_| {}
    if (netz.http1.parseResponse(allocator, bytes, options)) |value| {
        var response = value;
        defer response.deinit(allocator);
        try std.testing.expect(response.consumed <= bytes.len);
        try std.testing.expect(response.headers.len <= options.max_headers);
    } else |_| {}
    if (netz.http1.decodeChunked(allocator, bytes, options)) |value| {
        var decoded = value;
        defer decoded.deinit(allocator);
        try std.testing.expect(decoded.consumed <= bytes.len);
        try std.testing.expect(decoded.body.len <= bytes.len);
    } else |_| {}
}

const websocket_text_seed = smithSliceSeed(&.{
    0x81,    0x85,    1,       2,       3,       4,
    'h' ^ 1, 'e' ^ 2, 'l' ^ 3, 'l' ^ 4, 'o' ^ 1,
});
const websocket_close_seed = smithSliceSeed(&.{ 0x88, 0x02, 0x03, 0xe8 });
const websocket_extended_seed = smithSliceSeed(&.{
    0x82, 0x7e, 0x00, 0x7e,
});

fn exerciseWebSocket(bytes: []const u8) !void {
    const allocator = std.testing.allocator;
    if (netz.websocket.FrameHeader.parse(bytes)) |header| {
        try std.testing.expect(header.header_len <= bytes.len);
    } else |_| {}
    if (netz.websocket.parseFrameOptions(allocator, bytes, .{})) |value| {
        var frame = value;
        defer frame.deinit(allocator);
        try std.testing.expect(frame.consumed <= bytes.len);
        try std.testing.expectEqual(frame.header.payload_len, frame.payload.len);
    } else |_| {}
    if (netz.websocket.parseClosePayloadOwned(allocator, bytes)) |maybe| {
        if (maybe) |value| {
            var close = value;
            defer close.deinit(allocator);
            try std.testing.expect(std.unicode.utf8ValidateSlice(close.reason));
        }
    } else |_| {}
    _ = netz.websocket.ExtensionNegotiation.parseOffer(bytes) catch {};
    if (netz.websocket.ExtensionNegotiation.accept(
        allocator,
        bytes,
        true,
    )) |maybe| {
        if (maybe) |accepted| allocator.free(accepted);
    } else |_| {}
}

const webtransport_close_seed = smithSliceSeed(&.{
    0x68, 0x43, 0x06, 0, 0, 0, 1, 'o', 'k',
});
const webtransport_datagram_seed = smithSliceSeed(&.{ 0x00, 'd', 'a', 't', 'a' });
const webtransport_bidi_seed = smithSliceSeed(&.{ 0x40, 0x41, 0x00 });
const webtransport_uni_seed = smithSliceSeed(&.{ 0x54, 0x00 });

fn exerciseWebTransport(bytes: []const u8) !void {
    if (netz.webtransport.Capsule.parse(bytes)) |parsed| {
        try std.testing.expect(parsed.consumed <= bytes.len);
        switch (parsed.capsule) {
            .close_session => |close| try std.testing.expect(
                std.unicode.utf8ValidateSlice(close.reason),
            ),
            else => {},
        }
    } else |_| {}
    if (netz.webtransport.Datagram.parse(bytes)) |datagram| {
        try std.testing.expect(datagram.payload.len <= bytes.len);
        try std.testing.expect(datagram.session_id.isClientInitiatedBidirectional());
    } else |_| {}
    if (netz.webtransport.BidirectionalStreamHeader.parse(bytes)) |header| {
        try std.testing.expect(header.consumed <= bytes.len);
        try std.testing.expect(header.session_id.isClientInitiatedBidirectional());
    } else |_| {}
    if (netz.webtransport.UnidirectionalStreamHeader.parse(bytes)) |header| {
        try std.testing.expect(header.consumed <= bytes.len);
        if (header.session_id) |session_id| {
            try std.testing.expect(session_id.isClientInitiatedBidirectional());
        }
    } else |_| {}
}

const mqtt_connect_seed = smithSliceSeed(
    "\x10\x0e\x00\x04MQTT\x05\x02\x00\x3c\x00\x00\x01a",
);
const mqtt_publish_seed = smithSliceSeed(
    "\x32\x0b\x00\x05topic\x00\x01\x00x",
);
const mqtt_subscribe_seed = smithSliceSeed(
    "\x82\x09\x00\x01\x00\x00\x03a/+\x01",
);
const mqtt_bad_length_seed = smithSliceSeed(&.{ 0x30, 0x80, 0x00 });

fn exerciseMqtt(bytes: []const u8) !void {
    const mqtt = netz.mqtt;
    if (mqtt.FixedHeader.parse(bytes)) |fixed| {
        try std.testing.expect(fixed.header_len <= bytes.len);
        try std.testing.expect(fixed.remaining_len <= 268_435_455);
    } else |_| {}
    if (mqtt.Connect.parse(std.testing.allocator, bytes)) |value| {
        var packet = value;
        defer packet.deinit(std.testing.allocator);
        try std.testing.expect(packet.client_id.len <= std.math.maxInt(u16));
    } else |_| {}
    inline for (.{ mqtt.ProtocolVersion.v3_1_1, .v5 }) |protocol| {
        inline for (.{
            mqtt.ConnAck,
            mqtt.Publish,
            mqtt.AckPacket,
            mqtt.Subscribe,
            mqtt.SubAck,
            mqtt.Unsubscribe,
            mqtt.UnsubAck,
            mqtt.Disconnect,
            mqtt.Auth,
        }) |Packet| {
            if (Packet.parse(std.testing.allocator, protocol, bytes)) |value| {
                var packet = value;
                defer packet.deinit(std.testing.allocator);
            } else |_| {}
        }
    }
}
