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
const http2_settings_seed = smithSliceSeed(&.{
    0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x04, 0x00, 0x00, 0xff, 0xff,
});
const http2_headers_seed = smithSliceSeed(&.{
    0x00, 0x00, 0x02, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01,
    0x82, 0x84,
});
const hpack_seed = smithSliceSeed(&.{ 0x82, 0x84, 0x87 });
const http3_settings_seed = smithSliceSeed(&.{
    0x00, 0x04, 0x02, 0x01, 0x00,
});
const http3_headers_seed = smithSliceSeed(&.{
    0x01, 0x03, 0x00, 0x00, 0xd1,
});
const qpack_encoder_seed = smithSliceSeed(&.{
    0x3f, 0xbd, 0x01, 0xc0, 0x03, 'n', 'e', 't',
});
const qpack_decoder_seed = smithSliceSeed(&.{ 0x81, 0x41, 0x01 });
const cookie_seed = smithSliceSeed(
    "sid=abc; Path=/docs; Secure; HttpOnly; SameSite=Lax; Max-Age=60",
);
const cookie_snapshot_seed = smithSliceSeed("netz-http-cookie-jar\x00");
const cookie_netscape_seed = smithSliceSeed(
    "# Netscape HTTP Cookie File\n" ++
        "example.test\tFALSE\t/\tFALSE\t0\tsid\tabc\n",
);

test "fuzz bounded cross-protocol parsers" {
    try std.testing.fuzz({}, fuzzAllParsers, .{ .corpus = &.{
        &http_get_seed,
        &http_chunked_seed,
        &http_ambiguous_seed,
        &http2_settings_seed,
        &http2_headers_seed,
        &hpack_seed,
        &http3_settings_seed,
        &http3_headers_seed,
        &qpack_encoder_seed,
        &qpack_decoder_seed,
        &cookie_seed,
        &cookie_snapshot_seed,
        &cookie_netscape_seed,
        &websocket_text_seed,
        &websocket_close_seed,
        &websocket_extended_seed,
        &webtransport_close_seed,
        &webtransport_datagram_seed,
        &webtransport_bidi_seed,
        &webtransport_uni_seed,
        &webtransport_max_data_seed,
        &webtransport_max_bidi_seed,
        &webtransport_max_uni_seed,
        &webtransport_data_blocked_seed,
        &webtransport_bidi_blocked_seed,
        &webtransport_uni_blocked_seed,
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
        http2_settings_seed[4..],
        http2_headers_seed[4..],
        hpack_seed[4..],
        http3_settings_seed[4..],
        http3_headers_seed[4..],
        qpack_encoder_seed[4..],
        qpack_decoder_seed[4..],
        cookie_seed[4..],
        cookie_snapshot_seed[4..],
        cookie_netscape_seed[4..],
        websocket_text_seed[4..],
        websocket_close_seed[4..],
        websocket_extended_seed[4..],
        webtransport_close_seed[4..],
        webtransport_datagram_seed[4..],
        webtransport_bidi_seed[4..],
        webtransport_uni_seed[4..],
        webtransport_max_data_seed[4..],
        webtransport_max_bidi_seed[4..],
        webtransport_max_uni_seed[4..],
        webtransport_data_blocked_seed[4..],
        webtransport_bidi_blocked_seed[4..],
        webtransport_uni_blocked_seed[4..],
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
    try exerciseHttp1(bytes);
    try exerciseHttp2(bytes);
    try exerciseHttp3(bytes);
    try exerciseCookies(bytes);
}

fn exerciseCookies(bytes: []const u8) !void {
    var jar = try netz.http.CookieJar.init(std.testing.allocator, .{
        .max_cookies = 2,
        .max_cookies_per_domain = 2,
    });
    defer jar.deinit();
    _ = try jar.storeSetCookie(
        "https://example.test/docs/item",
        bytes,
        1_700_000_000,
    );
    _ = jar.restoreSnapshot(bytes, 1_700_000_000) catch {};
    _ = jar.restoreNetscapeLossy(bytes, 1_700_000_000, .{
        .acknowledge_metadata_loss = true,
        .include_session = true,
    }) catch {};
    try std.testing.expect(jar.count() <= 1);
    var out: [netz.http.CookieMaximumBytes]u8 = undefined;
    const value = try jar.cookieHeaderValueInto(
        "https://example.test/docs/next",
        1_700_000_001,
        .{},
        &out,
    );
    try std.testing.expect(value.len <= out.len);
}

fn exerciseHttp1(bytes: []const u8) !void {
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

fn exerciseHttp2(bytes: []const u8) !void {
    const allocator = std.testing.allocator;
    _ = netz.http2.validateClientPreface(bytes) catch {};
    if (netz.http2.FrameHeader.parse(bytes)) |header| {
        try std.testing.expectEqual(netz.http2.FrameHeader.encoded_len, 9);
        try std.testing.expect(header.length <= std.math.maxInt(u24));
    } else |_| {}
    if (netz.http2.Frame.parse(bytes)) |frame| {
        try std.testing.expect(frame.consumed() <= bytes.len);
        try std.testing.expectEqual(@as(usize, frame.header.length), frame.payload.len);
        _ = netz.http2.DataPayload.parse(frame) catch {};
        _ = netz.http2.ResetStreamPayload.parse(frame) catch {};
        _ = netz.http2.PriorityPayload.parse(frame) catch {};
        _ = netz.http2.HeadersPayload.parse(frame) catch {};
        _ = netz.http2.PushPromisePayload.parse(frame) catch {};
        _ = netz.http2.PingPayload.parse(frame) catch {};
        _ = netz.http2.GoAwayPayload.parse(frame) catch {};
        _ = netz.http2.WindowUpdatePayload.parse(frame) catch {};
        _ = netz.http2.PriorityUpdatePayload.parse(frame) catch {};
        if (netz.http2.OriginPayload.parse(allocator, frame)) |value| {
            var origins = value;
            defer origins.deinit(allocator);
        } else |_| {}
    } else |_| {}
    if (netz.http2.parseSettings(allocator, bytes)) |settings| {
        defer allocator.free(settings);
        try std.testing.expectEqual(@as(usize, 0), bytes.len % 6);
        try std.testing.expectEqual(bytes.len / 6, settings.len);
    } else |_| {}

    var decoder = netz.http2.Hpack.Decoder{};
    defer decoder.deinit(allocator);
    if (decoder.decodeBlockOwnedWithLimit(
        allocator,
        bytes,
        128,
        max_input_bytes,
    )) |fields| {
        defer netz.http2.Hpack.freeOwnedFields(allocator, fields);
        try std.testing.expect(fields.len <= 128);
    } else |_| {}
    if (netz.http2.Hpack.decodeHuffman(allocator, bytes)) |decoded| {
        defer allocator.free(decoded);
        try std.testing.expect(decoded.len <= bytes.len * 2);
    } else |_| {}
}

fn exerciseHttp3(bytes: []const u8) !void {
    const allocator = std.testing.allocator;
    if (netz.http3.Frame.parseHeader(bytes)) |header| {
        try std.testing.expect(header.header_length <= bytes.len);
        _ = header.totalLength() catch {};
    } else |_| {}
    if (netz.http3.Frame.parse(bytes)) |frame| {
        try std.testing.expect(frame.consumed <= bytes.len);
        try std.testing.expect(frame.payload.len <= bytes.len);
        switch (frame.frame_type) {
            netz.http3.FrameType.goaway => _ = netz.http3.parseGoAwayPayload(frame.payload) catch {},
            netz.http3.FrameType.cancel_push => _ = netz.http3.parseCancelPushPayload(frame.payload) catch {},
            netz.http3.FrameType.max_push_id => _ = netz.http3.parseMaxPushIdPayload(frame.payload) catch {},
            netz.http3.FrameType.push_promise => _ = netz.http3.parsePushPromisePayload(frame.payload) catch {},
            netz.http3.FrameType.priority_update_request,
            netz.http3.FrameType.priority_update_push,
            => _ = netz.http3.parsePriorityUpdatePayload(frame.payload) catch {},
            netz.http3.FrameType.origin => {
                if (netz.http3.OriginPayload.parse(
                    allocator,
                    frame.payload,
                )) |value| {
                    var origins = value;
                    defer origins.deinit(allocator);
                } else |_| {}
            },
            else => {},
        }
    } else |_| {}
    if (netz.http3.parseSettings(allocator, bytes)) |settings| {
        defer allocator.free(settings);
        try std.testing.expect(settings.len <= bytes.len);
    } else |_| {}
    if (netz.http3.ControlStream.parse(allocator, bytes)) |value| {
        var stream = value;
        defer stream.deinit(allocator);
        for (stream.frames) |frame| {
            try std.testing.expect(frame.consumed <= bytes.len);
        }
    } else |_| {}
    if (netz.http3.decodeRequest(allocator, bytes)) |value| {
        var request = value;
        defer request.deinit(allocator);
        try std.testing.expect(request.consumed <= bytes.len);
    } else |_| {}
    if (netz.http3.decodeResponse(allocator, bytes)) |value| {
        var response = value;
        defer response.deinit(allocator);
        try std.testing.expect(response.consumed <= bytes.len);
    } else |_| {}
    try exerciseQpack(bytes);
}

fn exerciseQpack(bytes: []const u8) !void {
    const allocator = std.testing.allocator;
    const qpack = netz.http3.Qpack;
    if (qpack.decodeEncoderInstruction(allocator, bytes)) |value| {
        var instruction = value;
        defer instruction.deinit(allocator);
        try std.testing.expect(instruction.consumed <= bytes.len);
    } else |_| {}
    if (qpack.decodeDecoderInstruction(bytes)) |instruction| {
        try std.testing.expect(instruction.consumed <= bytes.len);
    } else |_| {}
    if (qpack.decodeLiteralBlockOwnedWithLimit(
        allocator,
        bytes,
        max_input_bytes,
    )) |fields| {
        defer qpack.freeDecodedFields(allocator, fields);
        try std.testing.expect(fields.len <= bytes.len);
    } else |_| {}

    var table = qpack.DynamicTable.init(allocator, 4096);
    defer table.deinit();
    try table.setCapacity(4096);
    _ = qpack.applyEncoderInstructions(&table, allocator, bytes) catch {};
    if (qpack.decodeDynamicBlockOwnedWithLimit(
        allocator,
        bytes,
        table,
        max_input_bytes,
    )) |decoded| {
        defer qpack.freeDecodedFields(allocator, decoded.fields);
        try std.testing.expect(decoded.fields.len <= bytes.len);
        try std.testing.expect(decoded.required_insert_count <= table.insert_count);
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
const webtransport_max_data_seed = smithSliceSeed(&.{ 0x99, 0x0b, 0x4d, 0x3d, 1, 42 });
const webtransport_max_bidi_seed = smithSliceSeed(&.{ 0x99, 0x0b, 0x4d, 0x3f, 1, 42 });
const webtransport_max_uni_seed = smithSliceSeed(&.{ 0x99, 0x0b, 0x4d, 0x40, 1, 42 });
const webtransport_data_blocked_seed = smithSliceSeed(&.{ 0x99, 0x0b, 0x4d, 0x41, 1, 0 });
const webtransport_bidi_blocked_seed = smithSliceSeed(&.{ 0x99, 0x0b, 0x4d, 0x43, 1, 0 });
const webtransport_uni_blocked_seed = smithSliceSeed(&.{ 0x99, 0x0b, 0x4d, 0x44, 1, 0 });

fn exerciseWebTransport(bytes: []const u8) !void {
    if (netz.webtransport.Capsule.parse(bytes)) |parsed| {
        try std.testing.expect(parsed.consumed <= bytes.len);
        switch (parsed.capsule) {
            .close_session => |close| try std.testing.expect(
                std.unicode.utf8ValidateSlice(close.reason),
            ),
            else => {},
        }
        if (parsed.capsule.flowType() != null) {
            var encoded: [32]u8 = undefined;
            const roundtrip = try parsed.capsule.writeInto(&encoded);
            try std.testing.expectEqualDeep(parsed.capsule, (try netz.webtransport.Capsule.parse(roundtrip)).capsule);
            const settings = netz.http3.Settings{
                .webtransport_initial_max_data = 8,
                .webtransport_initial_max_streams_bidi = 1,
                .webtransport_initial_max_streams_uni = 1,
            };
            var state = try netz.webtransport.flow_control.State.init(settings, settings);
            const snapshot = state;
            if (state.receiveCapsule(parsed.capsule)) |_| {} else |_| {
                try std.testing.expectEqualDeep(snapshot, state);
            }
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
