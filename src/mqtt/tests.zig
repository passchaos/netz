const std = @import("std");
const mqtt_root = @import("mod.zig");
const bridge = @import("bridge.zig");
const testing = @import("testing/mod.zig");
const wire = @import("../internal/wire.zig");

const AckPacket = mqtt_root.AckPacket;
const Auth = mqtt_root.Auth;
const ConnAck = mqtt_root.ConnAck;
const Connect = mqtt_root.Connect;
const ConnectPacketOptions = mqtt_root.ConnectPacketOptions;
const Disconnect = mqtt_root.Disconnect;
const FixedHeader = mqtt_root.FixedHeader;
const PacketType = mqtt_root.PacketType;
const Property = mqtt_root.Property;
const PropertyId = mqtt_root.PropertyId;
const ProtocolVersion = mqtt_root.ProtocolVersion;
const Publish = mqtt_root.Publish;
const PublishWriteOptions = mqtt_root.PublishWriteOptions;
const QoS = mqtt_root.QoS;
const SubAck = mqtt_root.SubAck;
const Subscribe = mqtt_root.Subscribe;
const Subscription = mqtt_root.Subscription;
const UnsubAck = mqtt_root.UnsubAck;
const Unsubscribe = mqtt_root.Unsubscribe;
const assignedClientIdentifier = mqtt_root.assignedClientIdentifier;
const connectProtocolLevel = mqtt_root.connectProtocolLevel;
const decodeRemainingLength = mqtt_root.decodeRemainingLength;
const encodeRemainingLength = mqtt_root.encodeRemainingLength;
const maximumPacketSize = mqtt_root.maximumPacketSize;
const packetTypeFromFirstByte = mqtt_root.packetTypeFromFirstByte;
const parseProperties = mqtt_root.parseProperties;
const ping_packet_len = mqtt_root.ping_packet_len;
const readUtf8 = mqtt_root.readUtf8;
const receiveMaximum = mqtt_root.receiveMaximum;
const remainingLengthEncodedLen = mqtt_root.remainingLengthEncodedLen;
const requestProblemInformation = mqtt_root.requestProblemInformation;
const requestResponseInformation = mqtt_root.requestResponseInformation;
const serverReference = mqtt_root.serverReference;
const topicAlias = mqtt_root.topicAlias;
const topicMatchesFilter = mqtt_root.topicMatchesFilter;
const validTopicFilter = mqtt_root.validTopicFilter;
const validTopicName = mqtt_root.validTopicName;
const validateAuthReasonForSender = mqtt_root.validateAuthReasonForSender;
const validateDisconnectReasonForSender = mqtt_root.validateDisconnectReasonForSender;
const validatePacketFlags = mqtt_root.validatePacketFlags;
const validatePacketTypeForSender = mqtt_root.validatePacketTypeForSender;
const validatePing = mqtt_root.validatePing;
const validateStrictUtf8Properties = mqtt_root.validateStrictUtf8Properties;
const validateStrictUtf8String = mqtt_root.validateStrictUtf8String;
const validateTopicFilter = mqtt_root.validateTopicFilter;
const validateTopicName = mqtt_root.validateTopicName;
const validateUtf8String = mqtt_root.validateUtf8String;
const writeBinary = mqtt_root.writeBinary;
const writeConnectPacket = mqtt_root.writeConnectPacket;
const writePing = mqtt_root.writePing;
const writePingInto = mqtt_root.writePingInto;
const writeProperties = mqtt_root.writeProperties;
const writePublish = mqtt_root.writePublish;
const writePublishPrefix = mqtt_root.writePublishPrefix;
const writeUtf8 = mqtt_root.writeUtf8;

test "MQTT fixed header distinguishes reserved packet type zero" {
    try std.testing.expectError(
        error.ReservedPacketType,
        FixedHeader.parse(&.{ 0x00, 0x00 }),
    );
    try std.testing.expectError(
        error.ReservedPacketType,
        FixedHeader.parse(&.{ 0x0f, 0x00 }),
    );
    inline for (std.meta.fields(PacketType)) |field| {
        const first = @as(u8, @intCast(field.value)) << 4;
        try std.testing.expectEqual(
            @as(PacketType, @enumFromInt(field.value)),
            try packetTypeFromFirstByte(first),
        );
    }
}

test "MQTT fixed header write is transactional" {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try encoded.ensureTotalCapacityPrecise(std.testing.allocator, 1);
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        (FixedHeader{
            .packet_type = .publish,
            .flags = 0,
            .remaining_len = 0,
            .header_len = 0,
        }).write(&encoded, failing.allocator()),
    );
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);

    try encoded.appendBounded(0xa5);
    try std.testing.expectError(
        error.RemainingLengthTooLarge,
        (FixedHeader{
            .packet_type = .publish,
            .flags = 0,
            .remaining_len = 268_435_456,
            .header_len = 0,
        }).write(&encoded, std.testing.allocator),
    );
    try std.testing.expectEqualSlices(u8, &.{0xa5}, encoded.items);

    var exact_storage: [5]u8 = undefined;
    var exact = std.ArrayList(u8).initBuffer(&exact_storage);
    var no_alloc = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try (FixedHeader{
        .packet_type = .publish,
        .flags = 0,
        .remaining_len = 268_435_455,
        .header_len = 0,
    }).write(&exact, no_alloc.allocator());
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x30, 0xff, 0xff, 0xff, 0x7f },
        exact.items,
    );
}

test "MQTT primitive encoders are transactional on allocation failure" {
    var remaining: std.ArrayList(u8) = .empty;
    defer remaining.deinit(std.testing.allocator);
    try remaining.ensureTotalCapacityPrecise(std.testing.allocator, 1);
    try std.testing.expectEqual(@as(usize, 1), remaining.capacity);
    var failing_remaining = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        encodeRemainingLength(
            &remaining,
            failing_remaining.allocator(),
            128,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), remaining.items.len);

    var utf8: std.ArrayList(u8) = .empty;
    defer utf8.deinit(std.testing.allocator);
    try utf8.ensureTotalCapacityPrecise(std.testing.allocator, 2);
    try std.testing.expectEqual(@as(usize, 2), utf8.capacity);
    var failing_utf8 = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        writeUtf8(&utf8, failing_utf8.allocator(), "x"),
    );
    try std.testing.expectEqual(@as(usize, 0), utf8.items.len);

    var binary: std.ArrayList(u8) = .empty;
    defer binary.deinit(std.testing.allocator);
    try binary.ensureTotalCapacityPrecise(std.testing.allocator, 2);
    try std.testing.expectEqual(@as(usize, 2), binary.capacity);
    var failing_binary = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        writeBinary(&binary, failing_binary.allocator(), "x"),
    );
    try std.testing.expectEqual(@as(usize, 0), binary.items.len);
}

test "MQTT PUBLISH codec rejects DUP at QoS zero transactionally" {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try encoded.appendSlice(std.testing.allocator, "prefix");

    try std.testing.expectError(
        error.InvalidFlags,
        writePublish(
            &encoded,
            std.testing.allocator,
            .v5,
            "invalid/dup",
            "payload",
            .{ .qos = .at_most_once, .dup = true },
        ),
    );
    try std.testing.expectEqualStrings("prefix", encoded.items);
    try std.testing.expectError(
        error.InvalidFlags,
        Publish.parse(
            std.testing.allocator,
            .v5,
            &.{ 0x38, 0x04, 0x00, 0x01, 'a', 0x00 },
        ),
    );
}

test "MQTT PUBLISH prefix matches complete packet encoding" {
    const allocator = std.testing.allocator;
    const cases = [_]struct {
        protocol: ProtocolVersion,
        topic: []const u8,
        payload: []const u8,
        options: PublishWriteOptions,
    }{
        .{
            .protocol = .v3_1_1,
            .topic = "sensors/temperature",
            .payload = "small",
            .options = .{},
        },
        .{
            .protocol = .v5,
            .topic = "sensors/temperature",
            .payload = &([_]u8{0xa5} ** 256),
            .options = .{
                .qos = .at_least_once,
                .retain = true,
                .dup = true,
                .packet_id = 42,
                .properties = &.{
                    .{ .two_byte = .{
                        .id = .topic_alias,
                        .value = 2,
                    } },
                    .{ .utf8_pair = .{
                        .id = .user_property,
                        .key = "source",
                        .value = "prefix-test",
                    } },
                },
            },
        },
    };
    for (cases) |case| {
        var complete: std.ArrayList(u8) = .empty;
        defer complete.deinit(allocator);
        try writePublish(
            &complete,
            allocator,
            case.protocol,
            case.topic,
            case.payload,
            case.options,
        );
        var prefix: std.ArrayList(u8) = .empty;
        defer prefix.deinit(allocator);
        const lengths = try writePublishPrefix(
            &prefix,
            allocator,
            case.protocol,
            case.topic,
            case.payload,
            case.options,
        );
        try std.testing.expectEqual(prefix.items.len, lengths.prefix);
        try std.testing.expectEqual(complete.items.len, lengths.total);
        try std.testing.expectEqualSlices(
            u8,
            complete.items[0..prefix.items.len],
            prefix.items,
        );
        try std.testing.expectEqualSlices(
            u8,
            case.payload,
            complete.items[prefix.items.len..],
        );
    }
}

test "MQTT remaining length roundtrip" {
    const allocator = std.testing.allocator;
    const values = [_]usize{ 0, 127, 128, 16_384, 268_435_455 };
    for (values) |value| {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try encodeRemainingLength(&encoded, allocator, value);
        const decoded = try decodeRemainingLength(encoded.items);
        try std.testing.expectEqual(value, decoded.value);
        try std.testing.expectEqual(remainingLengthEncodedLen(value), decoded.len);
    }
    try std.testing.expectError(error.MalformedRemainingLength, decodeRemainingLength(&.{ 0x80, 0x00 }));
    try std.testing.expectError(error.MalformedRemainingLength, decodeRemainingLength(&.{ 0xff, 0x00 }));
}

test "MQTT PUBLISH direct encoding is allocation-free with exact capacity" {
    const allocator = std.testing.allocator;
    const properties = [_]Property{
        .{ .byte = .{ .id = .payload_format_indicator, .value = 1 } },
        .{ .four_byte = .{ .id = .message_expiry_interval, .value = 30 } },
        .{ .varint = .{ .id = .subscription_identifier, .value = 321 } },
        .{ .binary = .{ .id = .correlation_data, .value = "id" } },
        .{ .utf8 = .{ .id = .content_type, .value = "text/plain" } },
        .{ .utf8_pair = .{ .id = .user_property, .key = "k", .value = "v" } },
    };
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writePublish(
        &encoded,
        allocator,
        .v5,
        "direct/topic",
        "payload",
        .{
            .qos = .at_least_once,
            .retain = true,
            .packet_id = 7,
            .properties = &properties,
        },
    );
    const expected = try allocator.dupe(u8, encoded.items);
    defer allocator.free(expected);
    encoded.clearRetainingCapacity();

    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try writePublish(
        &encoded,
        no_alloc.allocator(),
        .v5,
        "direct/topic",
        "payload",
        .{
            .qos = .at_least_once,
            .retain = true,
            .packet_id = 7,
            .properties = &properties,
        },
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, expected, encoded.items);
    var parsed = try Publish.parse(allocator, .v5, encoded.items);
    defer parsed.deinit(allocator);
    try std.testing.expectEqualStrings("direct/topic", parsed.topic);
    try std.testing.expectEqualStrings("payload", parsed.payload);
    try std.testing.expectEqual(@as(?u16, 7), parsed.packet_id);
    try std.testing.expectEqual(properties.len, parsed.properties.len);

    const preserved_len = encoded.items.len;
    try std.testing.expectError(
        error.InvalidUtf8,
        writePublish(
            &encoded,
            allocator,
            .v5,
            "direct/topic",
            "payload",
            .{ .properties = &.{.{ .utf8 = .{
                .id = .content_type,
                .value = "bad\x00value",
            } }} },
        ),
    );
    try std.testing.expectEqual(preserved_len, encoded.items.len);
}

test "MQTT property writer reuses exact output capacity" {
    const allocator = std.testing.allocator;
    const properties = [_]Property{
        .{ .byte = .{ .id = .payload_format_indicator, .value = 1 } },
        .{ .two_byte = .{ .id = .topic_alias, .value = 7 } },
        .{ .four_byte = .{ .id = .message_expiry_interval, .value = 9 } },
        .{ .varint = .{ .id = .subscription_identifier, .value = 300 } },
        .{ .binary = .{ .id = .correlation_data, .value = "bytes" } },
        .{ .utf8 = .{ .id = .content_type, .value = "text/plain" } },
        .{ .utf8_pair = .{ .id = .user_property, .key = "key", .value = "value" } },
    };
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeProperties(&encoded, allocator, &properties);
    const expected = try allocator.dupe(u8, encoded.items);
    defer allocator.free(expected);
    encoded.clearRetainingCapacity();

    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try writeProperties(&encoded, no_alloc.allocator(), &properties);
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, expected, encoded.items);
    var cursor = wire.Cursor.init(encoded.items);
    const decoded = try parseProperties(allocator, &cursor);
    defer allocator.free(decoded);
    try std.testing.expectEqual(properties.len, decoded.len);
    try std.testing.expect(cursor.eof());

    const preserved_len = encoded.items.len;
    try std.testing.expectError(
        error.InvalidProperty,
        writeProperties(&encoded, allocator, &.{
            .{ .two_byte = .{ .id = .topic_alias, .value = 1 } },
            .{ .two_byte = .{ .id = .topic_alias, .value = 2 } },
        }),
    );
    try std.testing.expectEqual(preserved_len, encoded.items.len);
}

test "MQTT CONNECT direct encoding reuses exact output capacity" {
    const allocator = std.testing.allocator;
    const connect_properties = [_]Property{
        .{ .two_byte = .{ .id = .receive_maximum, .value = 10 } },
        .{ .utf8_pair = .{ .id = .user_property, .key = "client", .value = "netz" } },
    };
    const will_properties = [_]Property{
        .{ .four_byte = .{ .id = .will_delay_interval, .value = 5 } },
        .{ .utf8 = .{ .id = .content_type, .value = "text/plain" } },
    };
    const options = ConnectPacketOptions{
        .client_id = "direct-client",
        .clean_start = false,
        .keep_alive_seconds = 45,
        .properties = &connect_properties,
        .will = .{
            .topic = "status/direct-client",
            .payload = "offline",
            .qos = .at_least_once,
            .retain = true,
            .properties = @constCast(&will_properties),
        },
        .username = "user",
        .password = "password",
    };
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeConnectPacket(&encoded, allocator, .v5, options);
    const expected = try allocator.dupe(u8, encoded.items);
    defer allocator.free(expected);
    encoded.clearRetainingCapacity();
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try writeConnectPacket(&encoded, no_alloc.allocator(), .v5, options);
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, expected, encoded.items);
    var parsed = try Connect.parse(allocator, encoded.items);
    defer parsed.deinit(allocator);
    try std.testing.expectEqualStrings("direct-client", parsed.client_id);
    try std.testing.expectEqualStrings("offline", parsed.will.?.payload);
    try std.testing.expectEqualStrings("user", parsed.username.?);
    try std.testing.expectEqualStrings("password", parsed.password.?);
}

test "MQTT CONNACK and publish acknowledgments reuse output capacity" {
    const allocator = std.testing.allocator;
    const properties = [_]Property{
        .{ .utf8 = .{ .id = .reason_string, .value = "accepted" } },
        .{ .utf8_pair = .{ .id = .user_property, .key = "k", .value = "v" } },
    };
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    try ConnAck.write(&output, allocator, .v5, true, 0, &properties);
    const connack = try allocator.dupe(u8, output.items);
    defer allocator.free(connack);
    output.clearRetainingCapacity();
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try ConnAck.write(
        &output,
        no_alloc.allocator(),
        .v5,
        true,
        0,
        &properties,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, connack, output.items);

    output.clearRetainingCapacity();
    try AckPacket.write(
        &output,
        allocator,
        .v5,
        .puback,
        7,
        0x10,
        &properties,
    );
    const ack = try allocator.dupe(u8, output.items);
    defer allocator.free(ack);
    output.clearRetainingCapacity();
    no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try AckPacket.write(
        &output,
        no_alloc.allocator(),
        .v5,
        .puback,
        7,
        0x10,
        &properties,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, ack, output.items);
    var parsed = try AckPacket.parse(allocator, .v5, output.items);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 7), parsed.packet_id);
    try std.testing.expectEqual(@as(u8, 0x10), parsed.reason_code);

    const fixed = try FixedHeader.parse(output.items);
    var payload_parsed = try AckPacket.parsePayload(
        allocator,
        .v5,
        fixed.packet_type,
        fixed.flags,
        output.items[fixed.header_len..],
    );
    defer payload_parsed.deinit(allocator);
    try std.testing.expectEqual(parsed.packet_type, payload_parsed.packet_type);
    try std.testing.expectEqual(parsed.packet_id, payload_parsed.packet_id);
    try std.testing.expectEqual(parsed.reason_code, payload_parsed.reason_code);
}

test "MQTT subscription control writers reuse output capacity" {
    const allocator = std.testing.allocator;
    const properties = [_]Property{
        .{ .varint = .{ .id = .subscription_identifier, .value = 19 } },
        .{ .utf8_pair = .{ .id = .user_property, .key = "source", .value = "test" } },
    };
    const subscriptions = [_]Subscription{
        .{ .topic_filter = "sensors/+", .qos = .at_least_once },
        .{ .topic_filter = "alerts/#", .qos = .exactly_once, .no_local = true },
    };
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    try Subscribe.write(&output, allocator, .v5, 9, &properties, &subscriptions);
    const subscribe = try allocator.dupe(u8, output.items);
    defer allocator.free(subscribe);
    output.clearRetainingCapacity();
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try Subscribe.write(
        &output,
        no_alloc.allocator(),
        .v5,
        9,
        &properties,
        &subscriptions,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, subscribe, output.items);

    output.clearRetainingCapacity();
    const filters = [_][]const u8{ "sensors/+", "alerts/#" };
    try Unsubscribe.write(&output, allocator, .v5, 10, &.{}, &filters);
    const unsubscribe = try allocator.dupe(u8, output.items);
    defer allocator.free(unsubscribe);
    output.clearRetainingCapacity();
    no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try Unsubscribe.write(
        &output,
        no_alloc.allocator(),
        .v5,
        10,
        &.{},
        &filters,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, unsubscribe, output.items);
}

test "MQTT Assigned Client Identifier lookup" {
    const properties = [_]Property{
        .{ .utf8 = .{
            .id = .assigned_client_identifier,
            .value = "auto-client",
        } },
    };
    try std.testing.expectEqualStrings(
        "auto-client",
        assignedClientIdentifier(&properties).?,
    );
    try std.testing.expect(assignedClientIdentifier(&.{}) == null);
}

test "MQTT UTF-8 strings reject forbidden code points but allow discouraged controls" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    try validateUtf8String("");
    try validateUtf8String("plain/ascii/topic");
    try std.testing.expectError(error.InvalidUtf8, writeUtf8(&out, std.testing.allocator, "bad\x00topic"));
    try std.testing.expectError(
        error.InvalidUtf8,
        validateUtf8String("valid\xc2\xa2\x00tail"),
    );

    var encoded: [4]u8 = undefined;
    var codepoint: u21 = 0xfdd0;
    while (codepoint <= 0xfdef) : (codepoint += 1) {
        const len = try std.unicode.utf8Encode(codepoint, &encoded);
        try std.testing.expectError(
            error.InvalidUtf8,
            validateUtf8String(encoded[0..len]),
        );
    }
    for (0..17) |plane| {
        const plane_base: u21 = @intCast(plane * 0x10000);
        for ([_]u21{ plane_base + 0xfffe, plane_base + 0xffff }) |noncharacter| {
            const len = try std.unicode.utf8Encode(noncharacter, &encoded);
            try std.testing.expectError(
                error.InvalidUtf8,
                validateUtf8String(encoded[0..len]),
            );
        }
    }
    for ([_]u21{ 0xfdcf, 0xfdf0, 0xfffd, 0x10000, 0x1fffd, 0x10fffd }) |allowed| {
        const len = try std.unicode.utf8Encode(allowed, &encoded);
        try validateUtf8String(encoded[0..len]);
    }
    try std.testing.expectError(
        error.InvalidUtf8,
        writeUtf8(&out, std.testing.allocator, "bad\xef\xbf\xbetopic"),
    );

    var raw = [_]u8{ 0, 5, 'h', 'e', 0, 'l', 'o' };
    var cursor = wire.Cursor.init(&raw);
    try std.testing.expectError(error.InvalidUtf8, readUtf8(&cursor));

    var noncharacter = [_]u8{ 0, 3, 0xef, 0xbf, 0xbe };
    cursor = wire.Cursor.init(&noncharacter);
    try std.testing.expectError(error.InvalidUtf8, readUtf8(&cursor));

    try writeUtf8(&out, std.testing.allocator, "ok\x1ftopic");
    try std.testing.expectEqualStrings("ok\x1ftopic", out.items[2..]);
    out.clearRetainingCapacity();

    var del = [_]u8{ 0, 3, 'b', 0x7f, 'd' };
    cursor = wire.Cursor.init(&del);
    try std.testing.expectEqualStrings("b\x7fd", try readUtf8(&cursor));
}

test "MQTT strict UTF-8 policy rejects discouraged controls" {
    for ([_][]const u8{
        "bad\x01value",
        "bad\x1fvalue",
        "bad\x7fvalue",
        "bad\xc2\x9fvalue",
    }) |value| {
        try std.testing.expectError(
            error.InvalidUtf8,
            validateStrictUtf8String(value),
        );
    }
    try validateStrictUtf8String("plain/ascii/value");
    try std.testing.expectError(
        error.InvalidUtf8,
        validateStrictUtf8String("valid\xc2\xa2\x1ftail"),
    );
    try validateStrictUtf8String("valid\xf0\xaa\x9b\x94value");

    try validateStrictUtf8Properties(&.{
        .{ .utf8 = .{
            .id = .reason_string,
            .value = "valid reason",
        } },
        .{ .utf8_pair = .{
            .id = .user_property,
            .key = "trace",
            .value = "valid value",
        } },
        .{ .binary = .{
            .id = .correlation_data,
            .value = "opaque\x00\xff",
        } },
    });
    try std.testing.expectError(
        error.InvalidUtf8,
        validateStrictUtf8Properties(&.{.{ .utf8 = .{
            .id = .reason_string,
            .value = "bad\x7freason",
        } }}),
    );
    try std.testing.expectError(
        error.InvalidUtf8,
        validateStrictUtf8Properties(&.{.{ .utf8_pair = .{
            .id = .user_property,
            .key = "bad\xef\xb7\x90key",
            .value = "value",
        } }}),
    );
    try std.testing.expectError(
        error.InvalidUtf8,
        validateStrictUtf8Properties(&.{.{ .utf8_pair = .{
            .id = .user_property,
            .key = "key",
            .value = "bad\xc2\x9fvalue",
        } }}),
    );
}

test "MQTT ASCII validation preserves base and strict policies" {
    var value: [1]u8 = undefined;
    for (0..128) |raw| {
        value[0] = @intCast(raw);
        if (raw == 0) {
            try std.testing.expectError(
                error.InvalidUtf8,
                validateUtf8String(&value),
            );
        } else {
            try validateUtf8String(&value);
        }

        if (raw <= 0x1f or raw == 0x7f) {
            try std.testing.expectError(
                error.InvalidUtf8,
                validateStrictUtf8String(&value),
            );
        } else {
            try validateStrictUtf8String(&value);
        }
    }
}

test "MQTT ping packets reject trailing bytes" {
    var ping: std.ArrayList(u8) = .empty;
    defer ping.deinit(std.testing.allocator);
    try writePing(&ping, std.testing.allocator, false);
    try validatePing(ping.items, false);
    var direct: [ping_packet_len]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        ping.items,
        writePingInto(&direct, false),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xd0, 0x00 },
        writePingInto(&direct, true),
    );
    try ping.append(std.testing.allocator, 0);
    try std.testing.expectError(error.InvalidPacketType, validatePing(ping.items, false));
}

test "MQTT Control Packet types enforce sender direction" {
    const client_only = [_]PacketType{
        .connect,
        .subscribe,
        .unsubscribe,
        .pingreq,
    };
    const server_only = [_]PacketType{
        .connack,
        .suback,
        .unsuback,
        .pingresp,
    };
    const bidirectional = [_]PacketType{
        .publish,
        .puback,
        .pubrec,
        .pubrel,
        .pubcomp,
        .disconnect,
        .auth,
    };

    for (client_only) |packet_type| {
        try validatePacketTypeForSender(packet_type, .client);
        try std.testing.expectError(
            error.InvalidPacketDirection,
            validatePacketTypeForSender(packet_type, .server),
        );
    }
    for (server_only) |packet_type| {
        try validatePacketTypeForSender(packet_type, .server);
        try std.testing.expectError(
            error.InvalidPacketDirection,
            validatePacketTypeForSender(packet_type, .client),
        );
    }
    for (bidirectional) |packet_type| {
        try validatePacketTypeForSender(packet_type, .client);
        try validatePacketTypeForSender(packet_type, .server);
    }
}

test "MQTT fixed-header flags are classified as malformed" {
    const ordinary = [_]PacketType{
        .connect,
        .connack,
        .puback,
        .pubrec,
        .pubcomp,
        .suback,
        .unsuback,
        .pingreq,
        .pingresp,
        .disconnect,
        .auth,
    };
    for (ordinary) |packet_type| {
        try validatePacketFlags(.v5, .{
            .packet_type = packet_type,
            .flags = packet_type.defaultFlags(),
            .remaining_len = 0,
            .header_len = 2,
        });
        try std.testing.expectError(
            error.InvalidFlags,
            validatePacketFlags(.v5, .{
                .packet_type = packet_type,
                .flags = 0x01,
                .remaining_len = 0,
                .header_len = 2,
            }),
        );
    }

    for ([_]PacketType{ .pubrel, .subscribe, .unsubscribe }) |packet_type| {
        try validatePacketFlags(.v5, .{
            .packet_type = packet_type,
            .flags = 0x02,
            .remaining_len = 0,
            .header_len = 2,
        });
    }
    try std.testing.expectError(
        error.InvalidFlags,
        validatePacketFlags(.v3_1_1, .{
            .packet_type = .pubrel,
            .flags = 0x0a,
            .remaining_len = 0,
            .header_len = 2,
        }),
    );
    try std.testing.expectError(
        error.InvalidFlags,
        validatePacketFlags(.v5, .{
            .packet_type = .pubrel,
            .flags = 0x0a,
            .remaining_len = 0,
            .header_len = 2,
        }),
    );

    try validatePacketFlags(.v5, .{
        .packet_type = .publish,
        .flags = 0x0c,
        .remaining_len = 0,
        .header_len = 2,
    });
    try std.testing.expectError(
        error.InvalidFlags,
        validatePacketFlags(.v5, .{
            .packet_type = .publish,
            .flags = 0x08,
            .remaining_len = 0,
            .header_len = 2,
        }),
    );
    try std.testing.expectError(
        error.InvalidQoS,
        validatePacketFlags(.v5, .{
            .packet_type = .publish,
            .flags = 0x06,
            .remaining_len = 0,
            .header_len = 2,
        }),
    );
}

test "MQTT 3.1.1 private bridge CONNECT roundtrip is version scoped" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try writeConnectPacket(&encoded, allocator, .v3_1_1, .{
        .client_id = "private-bridge",
        .bridge_mode = true,
        .clean_start = false,
    });
    const level_index = (try FixedHeader.parse(encoded.items)).header_len +
        2 + "MQTT".len;
    try std.testing.expectEqual(@as(u8, 0x84), encoded.items[level_index]);
    var parsed = try Connect.parse(allocator, encoded.items);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(ProtocolVersion.v3_1_1, parsed.protocol);
    try std.testing.expect(parsed.bridge_mode);

    encoded.items[level_index] = 0x85;
    try std.testing.expectError(
        error.InvalidProtocolLevel,
        Connect.parse(allocator, encoded.items),
    );

    encoded.clearRetainingCapacity();
    try std.testing.expectError(
        error.InvalidProtocolLevel,
        writeConnectPacket(&encoded, allocator, .v5, .{
            .client_id = "invalid-private-v5",
            .bridge_mode = true,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);
}

test "MQTT 3.1 CONNECT uses MQIsdp and legacy validation" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeConnectPacket(&encoded, allocator, .v3_1, .{
        .client_id = "p",
        .clean_start = true,
        .keep_alive_seconds = 10,
    });
    try std.testing.expectEqualSlices(u8, &.{
        0x10, 0x0f,
        0x00, 0x06,
        'M',  'Q',
        'I',  's',
        'd',  'p',
        0x03, 0x02,
        0x00, 0x0a,
        0x00, 0x01,
        'p',
    }, encoded.items);
    var parsed = try Connect.parse(allocator, encoded.items);
    try std.testing.expectEqual(ProtocolVersion.v3_1, parsed.protocol);
    try std.testing.expect(parsed.clean_start);
    parsed.deinit(allocator);

    // MQTT 3.1 predates the MQTT 3.1.1 requirement that CONNECT's fixed
    // header flags and Connect Flags bit zero are reserved-zero.
    encoded.items[0] = 0x14;
    encoded.items[11] |= 0x01;
    parsed = try Connect.parse(allocator, encoded.items);
    parsed.deinit(allocator);

    encoded.items[10] = ProtocolVersion.v3_1_1.byte();
    try std.testing.expectError(
        error.InvalidProtocolLevel,
        Connect.parse(allocator, encoded.items),
    );

    encoded.clearRetainingCapacity();
    try std.testing.expectError(
        error.InvalidClientId,
        writeConnectPacket(&encoded, allocator, .v3_1, .{
            .client_id = "",
            .clean_start = true,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);

    const maximum_ascii_id = "abcdefghijklmnopqrstuvw";
    try writeConnectPacket(&encoded, allocator, .v3_1, .{
        .client_id = maximum_ascii_id,
    });
    parsed = try Connect.parse(allocator, encoded.items);
    try std.testing.expectEqualStrings(maximum_ascii_id, parsed.client_id);
    parsed.deinit(allocator);

    encoded.clearRetainingCapacity();
    try std.testing.expectError(
        error.InvalidClientId,
        writeConnectPacket(&encoded, allocator, .v3_1, .{
            .client_id = "abcdefghijklmnopqrstuvwx",
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);

    const maximum_multibyte_id = [_]u8{ 0xc3, 0xa9 } ** 23;
    try writeConnectPacket(&encoded, allocator, .v3_1, .{
        .client_id = &maximum_multibyte_id,
    });
    parsed = try Connect.parse(allocator, encoded.items);
    try std.testing.expectEqualSlices(
        u8,
        &maximum_multibyte_id,
        parsed.client_id,
    );
    parsed.deinit(allocator);

    const overlong_multibyte_id = [_]u8{ 0xc3, 0xa9 } ** 24;
    encoded.clearRetainingCapacity();
    try std.testing.expectError(
        error.InvalidClientId,
        writeConnectPacket(&encoded, allocator, .v3_1, .{
            .client_id = &overlong_multibyte_id,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);

    try writeConnectPacket(&encoded, allocator, .v3_1, .{
        .client_id = "legacy-bridge",
        .bridge_mode = true,
        .clean_start = false,
    });
    const level_index = (try FixedHeader.parse(encoded.items)).header_len +
        2 + "MQIsdp".len;
    try std.testing.expectEqual(@as(u8, 0x83), encoded.items[level_index]);
    parsed = try Connect.parse(allocator, encoded.items);
    defer parsed.deinit(allocator);
    try std.testing.expect(parsed.bridge_mode);

    var connack_bytes: std.ArrayList(u8) = .empty;
    defer connack_bytes.deinit(allocator);
    try ConnAck.write(&connack_bytes, allocator, .v3_1, false, 0, &.{});
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x20, 0x02, 0x00, 0x00 },
        connack_bytes.items,
    );
    var connack = try ConnAck.parse(allocator, .v3_1, connack_bytes.items);
    defer connack.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), connack.reason_code);
}

test "MQTT connect and publish parse" {
    const allocator = std.testing.allocator;
    var connect_bytes: std.ArrayList(u8) = .empty;
    defer connect_bytes.deinit(allocator);
    var will_props = [_]Property{.{ .four_byte = .{ .id = .will_delay_interval, .value = 5 } }};
    try writeConnectPacket(&connect_bytes, allocator, .v5, .{
        .client_id = "client-1",
        .clean_start = true,
        .keep_alive_seconds = 30,
        .properties = &.{.{ .two_byte = .{ .id = .receive_maximum, .value = 10 } }},
        .will = .{
            .topic = "status/client-1",
            .payload = "offline",
            .qos = .at_least_once,
            .properties = &will_props,
        },
        .username = "rumq",
        .password = "mq",
    });
    var connect = try Connect.parse(allocator, connect_bytes.items);
    defer connect.deinit(allocator);
    try std.testing.expectEqual(ProtocolVersion.v5, connect.protocol);
    try std.testing.expect(!connect.bridge_mode);
    try std.testing.expect(connect.clean_start);
    try std.testing.expectEqualStrings("client-1", connect.client_id);
    try std.testing.expectEqual(@as(usize, 1), connect.properties.len);
    try std.testing.expectEqual(@as(u16, 10), connect.properties[0].two_byte.value);
    try std.testing.expectEqual(@as(?u16, 10), receiveMaximum(connect.properties));
    try std.testing.expectEqual(@as(?u32, null), maximumPacketSize(connect.properties));
    try std.testing.expectEqual(@as(?u16, null), topicAlias(connect.properties));
    try std.testing.expectEqualStrings("status/client-1", connect.will.?.topic);
    try std.testing.expectEqualStrings("offline", connect.will.?.payload);
    try std.testing.expectEqual(QoS.at_least_once, connect.will.?.qos);
    try std.testing.expectEqual(@as(u32, 5), connect.will.?.properties[0].four_byte.value);
    try std.testing.expectEqualStrings("rumq", connect.username.?);
    try std.testing.expectEqualStrings("mq", connect.password.?);

    connect_bytes.clearRetainingCapacity();
    try writeConnectPacket(&connect_bytes, allocator, .v5, .{
        .client_id = "",
        .clean_start = true,
    });
    connect.deinit(allocator);
    connect = try Connect.parse(allocator, connect_bytes.items);
    try std.testing.expectEqualStrings("", connect.client_id);
    try std.testing.expect(connect.clean_start);

    const protocol_level_index = (try FixedHeader.parse(
        connect_bytes.items,
    )).header_len + 2 + "MQTT".len;
    try std.testing.expectEqual(
        ProtocolVersion.v5.byte(),
        try connectProtocolLevel(connect_bytes.items),
    );
    connect_bytes.items[protocol_level_index] = 6;
    try std.testing.expectEqual(
        @as(u8, 6),
        try connectProtocolLevel(connect_bytes.items),
    );
    try std.testing.expectError(
        error.InvalidProtocolLevel,
        Connect.parse(allocator, connect_bytes.items),
    );
    connect_bytes.items[protocol_level_index - 1] = 'X';
    try std.testing.expectError(
        error.InvalidProtocolName,
        connectProtocolLevel(connect_bytes.items),
    );
    connect_bytes.items[protocol_level_index - 1] = 'T';
    connect_bytes.items[protocol_level_index] = ProtocolVersion.v5.byte();
    connect_bytes.clearRetainingCapacity();
    try writeConnectPacket(&connect_bytes, allocator, .v5, .{
        .client_id = "",
        .clean_start = false,
    });
    connect.deinit(allocator);
    connect = try Connect.parse(allocator, connect_bytes.items);
    try std.testing.expectEqualStrings("", connect.client_id);
    try std.testing.expect(!connect.clean_start);
    try std.testing.expectError(error.InvalidClientId, writeConnectPacket(&connect_bytes, allocator, .v3_1_1, .{
        .client_id = "",
        .clean_start = false,
    }));

    var persistent_empty_id: std.ArrayList(u8) = .empty;
    defer persistent_empty_id.deinit(allocator);
    var persistent_variable: std.ArrayList(u8) = .empty;
    defer persistent_variable.deinit(allocator);
    try writeUtf8(&persistent_variable, allocator, "MQTT");
    try persistent_variable.append(allocator, ProtocolVersion.v3_1_1.byte());
    try persistent_variable.append(allocator, 0x00); // Clean Start false with an empty Client ID.
    try wire.appendInt(&persistent_variable, allocator, u16, 30, .big);
    try writeUtf8(&persistent_variable, allocator, "");
    try (FixedHeader{
        .packet_type = .connect,
        .flags = 0,
        .remaining_len = persistent_variable.items.len,
        .header_len = 0,
    }).write(&persistent_empty_id, allocator);
    try persistent_empty_id.appendSlice(allocator, persistent_variable.items);
    try std.testing.expectError(error.InvalidClientId, Connect.parse(allocator, persistent_empty_id.items));

    var bad_will_props = [_]Property{.{ .byte = .{ .id = .payload_format_indicator, .value = 1 } }};
    try std.testing.expectError(error.InvalidUtf8, writeConnectPacket(&connect_bytes, allocator, .v5, .{
        .client_id = "client-2",
        .will = .{ .topic = "status/client-2", .payload = "\xff", .properties = &bad_will_props },
    }));

    var publish_bytes: std.ArrayList(u8) = .empty;
    defer publish_bytes.deinit(allocator);
    try writePublish(&publish_bytes, allocator, .v5, "sensors/temp", "21.5", .{ .qos = .at_least_once, .packet_id = 7, .properties = &.{.{ .two_byte = .{ .id = .topic_alias, .value = 2 } }} });
    var publish = try Publish.parse(allocator, .v5, publish_bytes.items);
    const publish_fixed = try FixedHeader.parse(publish_bytes.items);
    var payload_publish = try Publish.parsePayload(
        allocator,
        .v5,
        publish_fixed.flags,
        publish_bytes.items[publish_fixed.header_len..],
    );
    defer payload_publish.deinit(allocator);
    try std.testing.expectEqual(publish.qos, payload_publish.qos);
    try std.testing.expectEqual(publish.packet_id, payload_publish.packet_id);
    try std.testing.expectEqualStrings(publish.topic, payload_publish.topic);
    try std.testing.expectEqualStrings(publish.payload, payload_publish.payload);
    var trailing_publish = try publish_bytes.clone(allocator);
    defer trailing_publish.deinit(allocator);
    try trailing_publish.append(allocator, 0);
    try std.testing.expectError(error.InvalidPacketType, Publish.parse(allocator, .v5, trailing_publish.items));

    defer publish.deinit(allocator);
    try std.testing.expectEqual(QoS.at_least_once, publish.qos);
    try std.testing.expectEqual(@as(u16, 7), publish.packet_id.?);
    try std.testing.expectEqualStrings("21.5", publish.payload);
    try std.testing.expectEqual(@as(?u16, 2), topicAlias(publish.properties));
    try std.testing.expectError(
        error.InvalidFlags,
        Publish.parsePayload(
            allocator,
            .v5,
            0x08,
            publish_bytes.items[publish_fixed.header_len..],
        ),
    );

    var wildcard_publish = try publish_bytes.clone(allocator);
    defer wildcard_publish.deinit(allocator);
    const wildcard_fixed = try FixedHeader.parse(wildcard_publish.items);
    wildcard_publish.items[wildcard_fixed.header_len + 2] = '+';
    try std.testing.expectError(
        error.InvalidTopic,
        Publish.parse(allocator, .v5, wildcard_publish.items),
    );

    var invalid_topic_publish = try publish_bytes.clone(allocator);
    defer invalid_topic_publish.deinit(allocator);
    const invalid_topic_fixed = try FixedHeader.parse(
        invalid_topic_publish.items,
    );
    invalid_topic_publish.items[invalid_topic_fixed.header_len + 2] = 0xff;
    try std.testing.expectError(
        error.InvalidUtf8,
        Publish.parse(allocator, .v5, invalid_topic_publish.items),
    );
    try std.testing.expectError(error.InvalidPacketIdentifier, writePublish(&publish_bytes, allocator, .v5, "sensors/temp", "bad", .{ .qos = .at_least_once }));
    try std.testing.expectError(error.InvalidPacketIdentifier, writePublish(&publish_bytes, allocator, .v5, "sensors/temp", "bad", .{ .qos = .at_least_once, .packet_id = 0 }));
    try std.testing.expectError(error.InvalidPacketIdentifier, writePublish(&publish_bytes, allocator, .v5, "sensors/temp", "bad", .{ .packet_id = 7 }));

    try std.testing.expectError(error.InvalidUtf8, writePublish(&publish_bytes, allocator, .v5, "sensors/temp", "\xff", .{
        .properties = &.{.{ .byte = .{ .id = .payload_format_indicator, .value = 1 } }},
    }));

    var invalid_payload = std.ArrayList(u8).empty;
    defer invalid_payload.deinit(allocator);
    try writePublish(&invalid_payload, allocator, .v5, "sensors/temp", "ok", .{
        .properties = &.{.{ .byte = .{ .id = .payload_format_indicator, .value = 1 } }},
    });
    invalid_payload.items[invalid_payload.items.len - 2] = 0xff;
    invalid_payload.items[invalid_payload.items.len - 1] = 0xff;
    try std.testing.expectError(error.InvalidUtf8, Publish.parse(allocator, .v5, invalid_payload.items));

    var alias_only_bytes: std.ArrayList(u8) = .empty;
    defer alias_only_bytes.deinit(allocator);
    try writePublish(&alias_only_bytes, allocator, .v5, "", "alias payload", .{ .properties = &.{.{ .two_byte = .{ .id = .topic_alias, .value = 2 } }} });
    var alias_only = try Publish.parse(allocator, .v5, alias_only_bytes.items);
    defer alias_only.deinit(allocator);
    try std.testing.expectEqualStrings("", alias_only.topic);
    try std.testing.expectEqual(@as(?u16, 2), topicAlias(alias_only.properties));

    var invalid_publish: std.ArrayList(u8) = .empty;
    defer invalid_publish.deinit(allocator);
    var invalid_variable: std.ArrayList(u8) = .empty;
    defer invalid_variable.deinit(allocator);
    try writeUtf8(&invalid_variable, allocator, "sensors/temp");
    try wire.appendInt(&invalid_variable, allocator, u16, 0, .big);
    try writeProperties(&invalid_variable, allocator, &.{});
    try invalid_variable.appendSlice(allocator, "bad");
    try (FixedHeader{
        .packet_type = .publish,
        .flags = @as(u4, @intFromEnum(QoS.at_least_once)) << 1,
        .remaining_len = invalid_variable.items.len,
        .header_len = 0,
    }).write(&invalid_publish, allocator);
    try invalid_publish.appendSlice(allocator, invalid_variable.items);
    try std.testing.expectError(error.InvalidPacketIdentifier, Publish.parse(allocator, .v5, invalid_publish.items));
}

test "MQTT v5 property values are validated" {
    const allocator = std.testing.allocator;

    var invalid_write: std.ArrayList(u8) = .empty;
    defer invalid_write.deinit(allocator);
    try std.testing.expectError(error.InvalidProperty, writeProperties(&invalid_write, allocator, &.{
        .{ .two_byte = .{ .id = .receive_maximum, .value = 0 } },
    }));
    // Public callers construct Property unions directly, so reject mismatched
    // union tags instead of serializing a semantically wrong property id with a
    // different wire width.  rumqtt models each packet's properties as typed
    // fields; this check preserves that safety for netz's compact union API.
    try std.testing.expectError(error.InvalidProperty, writeProperties(&invalid_write, allocator, &.{
        .{ .two_byte = .{ .id = .payload_format_indicator, .value = 1 } },
    }));

    const Cases = struct {
        fn expectInvalid(bytes: []const u8) !void {
            var cursor = wire.Cursor.init(bytes);
            try std.testing.expectError(error.InvalidProperty, parseProperties(std.testing.allocator, &cursor));
        }
    };
    const InvalidIdentifierCases = struct {
        fn expectInvalid(bytes: []const u8) !void {
            var cursor = wire.Cursor.init(bytes);
            try std.testing.expectError(
                error.InvalidPropertyIdentifier,
                parseProperties(std.testing.allocator, &cursor),
            );
        }
    };

    try InvalidIdentifierCases.expectInvalid(&.{ 0x02, 0x00, 0x01 });
    var noncanonical_identifier = wire.Cursor.init(
        &.{ 0x03, 0x80, 0x00, 0x01 },
    );
    try std.testing.expectError(
        error.MalformedRemainingLength,
        parseProperties(allocator, &noncanonical_identifier),
    );
    try InvalidIdentifierCases.expectInvalid(&.{ 0x02, 0x7f, 0x01 });

    var invalid_receive_maximum: std.ArrayList(u8) = .empty;
    defer invalid_receive_maximum.deinit(allocator);
    try encodeRemainingLength(&invalid_receive_maximum, allocator, 3);
    try invalid_receive_maximum.appendSlice(allocator, &.{ @intFromEnum(PropertyId.receive_maximum), 0, 0 });
    try Cases.expectInvalid(invalid_receive_maximum.items);

    var invalid_max_packet: std.ArrayList(u8) = .empty;
    defer invalid_max_packet.deinit(allocator);
    try encodeRemainingLength(&invalid_max_packet, allocator, 5);
    try invalid_max_packet.append(allocator, @intFromEnum(PropertyId.maximum_packet_size));
    try wire.appendInt(&invalid_max_packet, allocator, u32, 0, .big);
    try Cases.expectInvalid(invalid_max_packet.items);

    var invalid_response_topic: std.ArrayList(u8) = .empty;
    defer invalid_response_topic.deinit(allocator);
    try encodeRemainingLength(&invalid_response_topic, allocator, 12);
    try invalid_response_topic.append(allocator, @intFromEnum(PropertyId.response_topic));
    try wire.appendInt(&invalid_response_topic, allocator, u16, 9, .big);
    try invalid_response_topic.appendSlice(allocator, "reply/+/x");
    try Cases.expectInvalid(invalid_response_topic.items);

    var invalid_topic_alias: std.ArrayList(u8) = .empty;
    defer invalid_topic_alias.deinit(allocator);
    try encodeRemainingLength(&invalid_topic_alias, allocator, 3);
    try invalid_topic_alias.appendSlice(allocator, &.{ @intFromEnum(PropertyId.topic_alias), 0, 0 });
    try Cases.expectInvalid(invalid_topic_alias.items);

    var invalid_retain_available: std.ArrayList(u8) = .empty;
    defer invalid_retain_available.deinit(allocator);
    try encodeRemainingLength(&invalid_retain_available, allocator, 2);
    try invalid_retain_available.appendSlice(allocator, &.{ @intFromEnum(PropertyId.retain_available), 2 });
    try Cases.expectInvalid(invalid_retain_available.items);

    var invalid_max_qos: std.ArrayList(u8) = .empty;
    defer invalid_max_qos.deinit(allocator);
    try encodeRemainingLength(&invalid_max_qos, allocator, 2);
    try invalid_max_qos.appendSlice(allocator, &.{ @intFromEnum(PropertyId.maximum_qos), 2 });
    try Cases.expectInvalid(invalid_max_qos.items);

    var duplicate_receive_maximum: std.ArrayList(u8) = .empty;
    defer duplicate_receive_maximum.deinit(allocator);
    try encodeRemainingLength(&duplicate_receive_maximum, allocator, 6);
    try duplicate_receive_maximum.appendSlice(allocator, &.{ @intFromEnum(PropertyId.receive_maximum), 0, 1 });
    try duplicate_receive_maximum.appendSlice(allocator, &.{ @intFromEnum(PropertyId.receive_maximum), 0, 2 });
    try Cases.expectInvalid(duplicate_receive_maximum.items);

    var duplicate_write: std.ArrayList(u8) = .empty;
    defer duplicate_write.deinit(allocator);
    try std.testing.expectError(error.InvalidProperty, writeProperties(&duplicate_write, allocator, &.{
        .{ .four_byte = .{ .id = .maximum_packet_size, .value = 1024 } },
        .{ .four_byte = .{ .id = .maximum_packet_size, .value = 2048 } },
    }));

    try writeProperties(&duplicate_write, allocator, &.{
        .{ .utf8_pair = .{ .id = .user_property, .key = "a", .value = "1" } },
        .{ .utf8_pair = .{ .id = .user_property, .key = "b", .value = "2" } },
    });
}

test "MQTT v5 packet-specific properties are validated" {
    const allocator = std.testing.allocator;

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try std.testing.expectError(error.InvalidProperty, writeConnectPacket(&encoded, allocator, .v5, .{
        .client_id = "client",
        .properties = &.{.{ .two_byte = .{ .id = .topic_alias, .value = 1 } }},
    }));
    var invalid_will_props = [_]Property{.{ .two_byte = .{ .id = .receive_maximum, .value = 1 } }};
    try std.testing.expectError(error.InvalidProperty, writeConnectPacket(&encoded, allocator, .v5, .{
        .client_id = "client",
        .will = .{
            .topic = "status/client",
            .payload = "offline",
            .properties = &invalid_will_props,
        },
    }));
    try std.testing.expectError(error.InvalidProperty, ConnAck.write(&encoded, allocator, .v5, false, 0, &.{
        .{ .two_byte = .{ .id = .topic_alias, .value = 1 } },
    }));
    try std.testing.expectError(error.InvalidProperty, ConnAck.write(&encoded, allocator, .v5, false, 0, &.{
        .{ .utf8 = .{ .id = .assigned_client_identifier, .value = "" } },
    }));
    try std.testing.expectError(
        error.InvalidProperty,
        ConnAck.parse(
            allocator,
            .v5,
            &.{ 0x20, 0x06, 0x00, 0x00, 0x03, 0x12, 0x00, 0x00 },
        ),
    );
    try std.testing.expectError(error.InvalidProperty, writePublish(&encoded, allocator, .v5, "topic", "payload", .{
        .properties = &.{.{ .two_byte = .{ .id = .receive_maximum, .value = 1 } }},
    }));
    try std.testing.expectError(error.InvalidProperty, Subscribe.write(&encoded, allocator, .v5, 1, &.{
        .{ .utf8 = .{ .id = .reason_string, .value = "not allowed" } },
    }, &.{.{ .topic_filter = "topic" }}));
    try std.testing.expectError(error.InvalidProperty, Subscribe.write(&encoded, allocator, .v5, 1, &.{
        .{ .varint = .{ .id = .subscription_identifier, .value = 1 } },
        .{ .varint = .{ .id = .subscription_identifier, .value = 2 } },
    }, &.{.{ .topic_filter = "topic" }}));
    try std.testing.expectError(error.InvalidProperty, writeConnectPacket(&encoded, allocator, .v3_1_1, .{
        .client_id = "client",
        .properties = &.{.{ .utf8_pair = .{ .id = .user_property, .key = "k", .value = "v" } }},
    }));
    var v3_will_props = [_]Property{.{ .utf8_pair = .{ .id = .user_property, .key = "will-k", .value = "will-v" } }};
    try std.testing.expectError(error.InvalidProperty, writeConnectPacket(&encoded, allocator, .v3_1_1, .{
        .client_id = "client",
        .will = .{
            .topic = "status/client",
            .payload = "offline",
            .properties = &v3_will_props,
        },
    }));
    try std.testing.expectError(error.InvalidProperty, ConnAck.write(&encoded, allocator, .v3_1_1, false, 0, &.{
        .{ .utf8_pair = .{ .id = .user_property, .key = "k", .value = "v" } },
    }));
    try std.testing.expectError(error.InvalidProperty, writePublish(&encoded, allocator, .v3_1_1, "topic", "payload", .{
        .properties = &.{.{ .utf8_pair = .{ .id = .user_property, .key = "k", .value = "v" } }},
    }));
    try std.testing.expectError(error.InvalidProperty, Subscribe.write(&encoded, allocator, .v3_1_1, 1, &.{
        .{ .utf8_pair = .{ .id = .user_property, .key = "k", .value = "v" } },
    }, &.{.{ .topic_filter = "topic" }}));
    try std.testing.expectError(error.InvalidProperty, Unsubscribe.write(&encoded, allocator, .v5, 1, &.{
        .{ .varint = .{ .id = .subscription_identifier, .value = 1 } },
    }, &.{"topic"}));
    try std.testing.expectError(error.InvalidProperty, SubAck.write(&encoded, allocator, .v5, 1, &.{
        .{ .two_byte = .{ .id = .receive_maximum, .value = 1 } },
    }, &.{0}));
    try std.testing.expectError(error.InvalidProperty, Disconnect.write(&encoded, allocator, .v5, 0, &.{
        .{ .two_byte = .{ .id = .topic_alias, .value = 1 } },
    }));
    try std.testing.expectError(error.InvalidProperty, AckPacket.write(&encoded, allocator, .v5, .puback, 1, 0, &.{
        .{ .varint = .{ .id = .subscription_identifier, .value = 1 } },
    }));
    try std.testing.expectError(error.InvalidProperty, writeConnectPacket(&encoded, allocator, .v5, .{
        .client_id = "client",
        .properties = &.{.{ .binary = .{ .id = .authentication_data, .value = "opaque" } }},
    }));
    try std.testing.expectError(error.InvalidProperty, ConnAck.write(&encoded, allocator, .v5, false, 0, &.{
        .{ .binary = .{ .id = .authentication_data, .value = "opaque" } },
    }));
    try std.testing.expectError(error.InvalidProperty, Auth.write(&encoded, allocator, .v5, 0x18, &.{
        .{ .binary = .{ .id = .authentication_data, .value = "opaque" } },
    }));
    try Auth.write(&encoded, allocator, .v5, 0x18, &.{
        .{ .utf8 = .{ .id = .authentication_method, .value = "SCRAM-SHA-256" } },
        .{ .binary = .{ .id = .authentication_data, .value = "opaque" } },
    });

    var invalid_connect: std.ArrayList(u8) = .empty;
    defer invalid_connect.deinit(allocator);
    var connect_variable: std.ArrayList(u8) = .empty;
    defer connect_variable.deinit(allocator);
    try writeUtf8(&connect_variable, allocator, "MQTT");
    try connect_variable.append(allocator, ProtocolVersion.v5.byte());
    try connect_variable.append(allocator, 0x02);
    try wire.appendInt(&connect_variable, allocator, u16, 30, .big);
    // Topic Alias is a PUBLISH-only property in rumqtt/MQTT v5 and must not be
    // accepted in CONNECT even though it is well-formed generically.
    try writeProperties(&connect_variable, allocator, &.{.{ .two_byte = .{ .id = .topic_alias, .value = 1 } }});
    try writeUtf8(&connect_variable, allocator, "client");
    try (FixedHeader{
        .packet_type = .connect,
        .flags = 0,
        .remaining_len = connect_variable.items.len,
        .header_len = 0,
    }).write(&invalid_connect, allocator);
    try invalid_connect.appendSlice(allocator, connect_variable.items);
    try std.testing.expectError(
        error.MalformedPropertyContext,
        Connect.parse(allocator, invalid_connect.items),
    );

    var invalid_suback: std.ArrayList(u8) = .empty;
    defer invalid_suback.deinit(allocator);
    var suback_variable: std.ArrayList(u8) = .empty;
    defer suback_variable.deinit(allocator);
    try wire.appendInt(&suback_variable, allocator, u16, 1, .big);
    try writeProperties(&suback_variable, allocator, &.{.{ .two_byte = .{ .id = .receive_maximum, .value = 1 } }});
    try suback_variable.append(allocator, 0x00);
    try (FixedHeader{
        .packet_type = .suback,
        .flags = 0,
        .remaining_len = suback_variable.items.len,
        .header_len = 0,
    }).write(&invalid_suback, allocator);
    try invalid_suback.appendSlice(allocator, suback_variable.items);
    try std.testing.expectError(
        error.MalformedPropertyContext,
        SubAck.parse(allocator, .v5, invalid_suback.items),
    );

    var duplicate_subscribe: std.ArrayList(u8) = .empty;
    defer duplicate_subscribe.deinit(allocator);
    var subscribe_variable: std.ArrayList(u8) = .empty;
    defer subscribe_variable.deinit(allocator);
    try wire.appendInt(&subscribe_variable, allocator, u16, 1, .big);
    try writeProperties(&subscribe_variable, allocator, &.{
        .{ .varint = .{ .id = .subscription_identifier, .value = 1 } },
        .{ .varint = .{ .id = .subscription_identifier, .value = 2 } },
    });
    try writeUtf8(&subscribe_variable, allocator, "topic");
    try subscribe_variable.append(allocator, 0);
    try (FixedHeader{
        .packet_type = .subscribe,
        .flags = PacketType.subscribe.defaultFlags(),
        .remaining_len = subscribe_variable.items.len,
        .header_len = 0,
    }).write(&duplicate_subscribe, allocator);
    try duplicate_subscribe.appendSlice(allocator, subscribe_variable.items);
    try std.testing.expectError(error.InvalidProperty, Subscribe.parse(allocator, .v5, duplicate_subscribe.items));

    encoded.clearRetainingCapacity();
    try writePublish(&encoded, allocator, .v5, "topic", "payload", .{
        .properties = &.{
            .{ .varint = .{ .id = .subscription_identifier, .value = 1 } },
            .{ .varint = .{ .id = .subscription_identifier, .value = 2 } },
        },
    });
    var publish = try Publish.parse(allocator, .v5, encoded.items);
    defer publish.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), publish.properties.len);

    encoded.clearRetainingCapacity();
    try Subscribe.write(&encoded, allocator, .v5, 1, &.{
        .{ .varint = .{ .id = .subscription_identifier, .value = 1 } },
        .{ .utf8_pair = .{ .id = .user_property, .key = "k", .value = "v" } },
    }, &.{.{ .topic_filter = "topic" }});
}

test "MQTT CONNECT validates flags and will topic" {
    const allocator = std.testing.allocator;
    var invalid_flags: std.ArrayList(u8) = .empty;
    defer invalid_flags.deinit(allocator);
    try (FixedHeader{ .packet_type = .connect, .flags = 0, .remaining_len = 12, .header_len = 0 }).write(&invalid_flags, allocator);
    try writeUtf8(&invalid_flags, allocator, "MQTT");
    try invalid_flags.append(allocator, ProtocolVersion.v3_1_1.byte());
    try invalid_flags.append(allocator, 0x20); // will retain without will flag
    try wire.appendInt(&invalid_flags, allocator, u16, 30, .big);
    try writeUtf8(&invalid_flags, allocator, "");
    try std.testing.expectError(error.InvalidFlags, Connect.parse(allocator, invalid_flags.items));

    var password_without_username_v3: std.ArrayList(u8) = .empty;
    defer password_without_username_v3.deinit(allocator);
    var password_v3_variable: std.ArrayList(u8) = .empty;
    defer password_v3_variable.deinit(allocator);
    try writeUtf8(&password_v3_variable, allocator, "MQTT");
    try password_v3_variable.append(allocator, ProtocolVersion.v3_1_1.byte());
    try password_v3_variable.append(allocator, 0x42); // Password + Clean Session, but no User Name.
    try wire.appendInt(&password_v3_variable, allocator, u16, 30, .big);
    try writeUtf8(&password_v3_variable, allocator, "client");
    try writeBinary(&password_v3_variable, allocator, "password");
    try (FixedHeader{
        .packet_type = .connect,
        .flags = 0,
        .remaining_len = password_v3_variable.items.len,
        .header_len = 0,
    }).write(&password_without_username_v3, allocator);
    try password_without_username_v3.appendSlice(allocator, password_v3_variable.items);
    try std.testing.expectError(error.InvalidFlags, Connect.parse(allocator, password_without_username_v3.items));
    try std.testing.expectError(error.InvalidFlags, writeConnectPacket(&password_without_username_v3, allocator, .v3_1_1, .{
        .client_id = "client",
        .password = "password",
    }));

    // MQTT 5 keeps the Username and Password payload flags independent for
    // enhanced-authentication deployments, so the v3.1.1 guard above must not
    // reject the same flag combination for protocol level 5.
    var password_without_username_v5: std.ArrayList(u8) = .empty;
    defer password_without_username_v5.deinit(allocator);
    try writeConnectPacket(&password_without_username_v5, allocator, .v5, .{
        .client_id = "client-5",
        .password = "password",
    });
    var parsed_password_only_v5 = try Connect.parse(allocator, password_without_username_v5.items);
    defer parsed_password_only_v5.deinit(allocator);
    try std.testing.expectEqual(ProtocolVersion.v5, parsed_password_only_v5.protocol);
    try std.testing.expect(parsed_password_only_v5.username == null);
    try std.testing.expectEqualStrings("password", parsed_password_only_v5.password.?);

    var invalid_will: std.ArrayList(u8) = .empty;
    defer invalid_will.deinit(allocator);
    try std.testing.expectError(error.InvalidTopic, writeConnectPacket(&invalid_will, allocator, .v5, .{
        .client_id = "client-2",
        .will = .{ .topic = "bad/+/topic", .payload = "offline" },
    }));
}

test "MQTT CONNECT releases Will Delay properties after invalid empty topic" {
    // Exact CONNECT shape from Mosquitto issue 573191. Parsing allocates the
    // Will property list before validating its empty Topic Name, so the error
    // path must release that list as well as the outer CONNECT properties.
    // std.testing.allocator turns either ownership leak into a test failure.
    const packet = [_]u8{
        0x10, 0x2a, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54,
        0x05, 0x06, 0x00, 0x3c, 0x03, 0x21, 0x00, 0x14,
        0x00, 0x10, 0x77, 0x69, 0x6c, 0x6c, 0x2d, 0x35,
        0x37, 0x33, 0x31, 0x39, 0x31, 0x2d, 0x74, 0x65,
        0x73, 0x74, 0x05, 0x18, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x00,
    };
    try std.testing.expectError(
        error.InvalidTopic,
        Connect.parse(std.testing.allocator, &packet),
    );
}

test "MQTT topic validation and filter matching" {
    try std.testing.expect(validTopicName("sensors/temp"));
    try std.testing.expect(!validTopicName(""));
    try std.testing.expect(!validTopicName("wrong/#/path"));
    try std.testing.expect(!validTopicName("w/r/o/n/g+"));
    try std.testing.expect(!validTopicName("bad\x00topic"));
    try std.testing.expect(!validTopicName(&[_]u8{ 0xff, 0xfe }));

    try std.testing.expect(validTopicFilter("correct/filter/#"));
    try std.testing.expect(validTopicFilter("cor/+/rect/+"));
    try std.testing.expect(!validTopicFilter(""));
    try std.testing.expect(!validTopicFilter("wrong/#/filter"));
    try std.testing.expect(!validTopicFilter("wrong/wr#ng/filter"));
    try std.testing.expect(!validTopicFilter("wr/+o+/ng"));
    try std.testing.expect(!validTopicFilter("bad\x00/filter"));
    try std.testing.expect(!validTopicFilter(&[_]u8{ 'b', 'a', 'd', '/', 0xff }));
    try std.testing.expect(validTopicFilter("$share/group/sensors/+/temp"));
    try std.testing.expect(validTopicFilter("$share/group/#"));
    try std.testing.expect(!validTopicFilter("$share/group"));
    try std.testing.expect(!validTopicFilter("$share//sensors/temp"));
    try std.testing.expect(!validTopicFilter("$share/bad\x00group/sensors/temp"));
    try std.testing.expect(!validTopicFilter("$share/gr+oup/sensors/temp"));
    try std.testing.expect(!validTopicFilter("$share/group/bad/#/filter"));

    try std.testing.expect(topicMatchesFilter("a/b/c", "a/b/c"));
    try std.testing.expect(topicMatchesFilter("a/b/c/d/e", "a/+/c/+/e"));
    try std.testing.expect(topicMatchesFilter("a/b/c/d/e/f", "a/b/c/#"));
    try std.testing.expect(!topicMatchesFilter("a/b", "a/b/+"));
    try std.testing.expect(!topicMatchesFilter("$system/metrics", "+/+"));
    try std.testing.expect(topicMatchesFilter("$system/metrics", "$system/+"));
    try std.testing.expect(topicMatchesFilter("sensors/temp", "$share/workers/sensors/+"));
    try std.testing.expect(!topicMatchesFilter("$system/metrics", "$share/workers/+"));
    try std.testing.expect(topicMatchesFilter("$system/metrics", "$share/workers/$system/+"));
    try std.testing.expect(!topicMatchesFilter("sensors/temp", "$share//sensors/+"));

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try std.testing.expectError(error.InvalidTopic, writePublish(&encoded, std.testing.allocator, .v5, "bad/#", "payload", .{}));
    try std.testing.expectError(error.InvalidSubscription, Subscribe.write(&encoded, std.testing.allocator, .v5, 1, &.{}, &[_]Subscription{.{ .topic_filter = "bad/#/filter" }}));
    try std.testing.expectError(error.InvalidSubscription, Subscribe.write(&encoded, std.testing.allocator, .v5, 1, &.{}, &[_]Subscription{.{ .topic_filter = "$share/group" }}));
}

test "MQTT topic validation enforces the UTF-8 wire length transactionally" {
    const allocator = std.testing.allocator;
    const oversized = try allocator.alloc(u8, std.math.maxInt(u16) + 1);
    defer allocator.free(oversized);
    @memset(oversized, 'a');
    const maximum = oversized[0..std.math.maxInt(u16)];

    try std.testing.expect(validTopicName(maximum));
    try std.testing.expect(validTopicFilter(maximum));
    try std.testing.expectError(error.InvalidTopic, validateTopicName(oversized));
    try std.testing.expectError(
        error.InvalidSubscription,
        validateTopicFilter(oversized),
    );

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try encoded.appendSlice(allocator, "existing output");
    try std.testing.expectError(
        error.InvalidTopic,
        writePublish(&encoded, allocator, .v5, oversized, "payload", .{}),
    );
    try std.testing.expectEqualStrings("existing output", encoded.items);
    try std.testing.expectError(
        error.InvalidSubscription,
        Subscribe.write(
            &encoded,
            allocator,
            .v5,
            1,
            &.{},
            &.{.{ .topic_filter = oversized }},
        ),
    );
    try std.testing.expectEqualStrings("existing output", encoded.items);
}

test "MQTT connack ack and ping controls" {
    const allocator = std.testing.allocator;

    var connack_bytes: std.ArrayList(u8) = .empty;
    defer connack_bytes.deinit(allocator);
    try ConnAck.write(&connack_bytes, allocator, .v5, true, 0, &.{});
    var connack = try ConnAck.parse(allocator, .v5, connack_bytes.items);
    defer connack.deinit(allocator);
    try std.testing.expect(connack.session_present);
    try std.testing.expectEqual(@as(u8, 0), connack.reason_code);
    try std.testing.expectError(error.InvalidFlags, ConnAck.write(&connack_bytes, allocator, .v5, true, 0x80, &.{}));
    try std.testing.expectError(error.InvalidReasonCode, ConnAck.write(&connack_bytes, allocator, .v5, false, 0x8b, &.{}));
    connack_bytes.clearRetainingCapacity();
    try ConnAck.write(&connack_bytes, allocator, .v3_1_1, false, 0x05, &.{});
    connack.deinit(allocator);
    connack = try ConnAck.parse(allocator, .v3_1_1, connack_bytes.items);
    try std.testing.expectEqual(@as(u8, 0x05), connack.reason_code);
    try std.testing.expectError(error.InvalidReasonCode, ConnAck.write(&connack_bytes, allocator, .v3_1_1, false, 0x80, &.{}));

    var direct_connack: [ConnAck.no_properties_max_len]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x20, 0x03, 0x01, 0x00, 0x00 },
        try ConnAck.writeNoPropertiesInto(
            &direct_connack,
            .v5,
            true,
            0,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x20, 0x03, 0x00, 0x80, 0x00 },
        try ConnAck.writeNoPropertiesInto(
            &direct_connack,
            .v5,
            false,
            0x80,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x20, 0x02, 0x00, 0x05 },
        try ConnAck.writeNoPropertiesInto(
            &direct_connack,
            .v3_1_1,
            false,
            0x05,
        ),
    );
    try std.testing.expectError(
        error.InvalidFlags,
        ConnAck.writeNoPropertiesInto(
            &direct_connack,
            .v5,
            true,
            0x80,
        ),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        ConnAck.writeNoPropertiesInto(
            &direct_connack,
            .v3_1_1,
            false,
            0x80,
        ),
    );

    var invalid_connack: std.ArrayList(u8) = .empty;
    defer invalid_connack.deinit(allocator);
    try (FixedHeader{
        .packet_type = .connack,
        .flags = 0,
        .remaining_len = 3,
        .header_len = 0,
    }).write(&invalid_connack, allocator);
    try invalid_connack.appendSlice(allocator, &.{ 0x00, 0x8b, 0x00 });
    try std.testing.expectError(error.InvalidReasonCode, ConnAck.parse(allocator, .v5, invalid_connack.items));

    invalid_connack.clearRetainingCapacity();
    try (FixedHeader{
        .packet_type = .connack,
        .flags = 0,
        .remaining_len = 3,
        .header_len = 0,
    }).write(&invalid_connack, allocator);
    try invalid_connack.appendSlice(allocator, &.{ 0x01, 0x80, 0x00 });
    try std.testing.expectError(error.InvalidFlags, ConnAck.parse(allocator, .v5, invalid_connack.items));

    var puback_bytes: std.ArrayList(u8) = .empty;
    defer puback_bytes.deinit(allocator);
    try AckPacket.write(&puback_bytes, allocator, .v5, .puback, 42, 0x10, &.{});
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x40, 0x03, 0x00, 0x2a, 0x10 }, puback_bytes.items);
    var direct_ack: [AckPacket.no_properties_max_len]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        puback_bytes.items,
        try AckPacket.writeNoPropertiesInto(
            &direct_ack,
            .v5,
            .puback,
            42,
            0x10,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x40, 0x02, 0x00, 0x2a },
        try AckPacket.writeNoPropertiesInto(
            &direct_ack,
            .v5,
            .puback,
            42,
            0,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x62, 0x02, 0x12, 0x34 },
        try AckPacket.writeNoPropertiesInto(
            &direct_ack,
            .v3_1_1,
            .pubrel,
            0x1234,
            0,
        ),
    );
    try std.testing.expectError(
        error.InvalidPacketIdentifier,
        AckPacket.writeNoPropertiesInto(
            &direct_ack,
            .v5,
            .puback,
            0,
            0,
        ),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        AckPacket.writeNoPropertiesInto(
            &direct_ack,
            .v3_1_1,
            .puback,
            42,
            0x80,
        ),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        AckPacket.writeNoPropertiesInto(
            &direct_ack,
            .v5,
            .pubrel,
            42,
            0x10,
        ),
    );
    try std.testing.expectError(
        error.InvalidPacketType,
        AckPacket.writeNoPropertiesInto(
            &direct_ack,
            .v5,
            .suback,
            42,
            0,
        ),
    );
    var puback = try AckPacket.parse(allocator, .v5, puback_bytes.items);
    defer puback.deinit(allocator);
    try std.testing.expectEqual(PacketType.puback, puback.packet_type);
    try std.testing.expectEqual(@as(u16, 42), puback.packet_id);
    try std.testing.expectEqual(@as(u8, 0x10), puback.reason_code);
    try std.testing.expect(puback.accepted());

    puback_bytes.clearRetainingCapacity();
    try AckPacket.write(&puback_bytes, allocator, .v5, .puback, 43, 0x80, &.{
        .{ .utf8 = .{ .id = .reason_string, .value = "quota" } },
        .{ .utf8_pair = .{ .id = .user_property, .key = "trace", .value = "puback-negative" } },
    });
    puback.deinit(allocator);
    puback = try AckPacket.parse(allocator, .v5, puback_bytes.items);
    try std.testing.expectEqual(@as(u8, 0x80), puback.reason_code);
    try std.testing.expect(!puback.accepted());
    try std.testing.expectEqualStrings("quota", puback.properties[0].utf8.value);

    try std.testing.expectError(error.InvalidReasonCode, AckPacket.write(&puback_bytes, allocator, .v5, .pubrel, 44, 0x10, &.{}));
    try std.testing.expectError(error.InvalidProperty, AckPacket.write(&puback_bytes, allocator, .v5, .puback, 44, 0, &.{
        .{ .two_byte = .{ .id = .topic_alias, .value = 1 } },
    }));
    try std.testing.expectError(error.InvalidReasonCode, AckPacket.write(&puback_bytes, allocator, .v3_1_1, .puback, 44, 0x80, &.{}));
    try std.testing.expectError(error.InvalidPacketType, AckPacket.write(&puback_bytes, allocator, .v5, .unsuback, 44, 0, &.{}));
    puback_bytes.clearRetainingCapacity();
    try UnsubAck.write(&puback_bytes, allocator, .v5, 44, &.{}, &.{0x00});
    try std.testing.expectError(error.InvalidPacketType, AckPacket.parse(allocator, .v5, puback_bytes.items));

    try std.testing.expectError(
        error.InvalidFlags,
        AckPacket.parse(allocator, .v3_1_1, &.{ 0x6a, 0x02, 0x00, 0x2a }),
    );
    try std.testing.expectError(
        error.InvalidFlags,
        AckPacket.parse(allocator, .v5, &.{ 0x6a, 0x02, 0x00, 0x2a }),
    );
    var ping: std.ArrayList(u8) = .empty;
    defer ping.deinit(allocator);
    try writePing(&ping, allocator, false);
    try validatePing(ping.items, false);
}

test "MQTT subscribe and suback controls" {
    const allocator = std.testing.allocator;
    const subs = [_]Subscription{
        .{ .topic_filter = "sensors/+", .qos = .at_least_once },
        .{ .topic_filter = "alerts/#", .qos = .at_most_once, .retain_as_published = true },
    };

    var subscribe_bytes: std.ArrayList(u8) = .empty;
    defer subscribe_bytes.deinit(allocator);
    try Subscribe.write(&subscribe_bytes, allocator, .v5, 9, &.{}, &subs);
    var subscribe = try Subscribe.parse(allocator, .v5, subscribe_bytes.items);
    defer subscribe.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 9), subscribe.packet_id);
    try std.testing.expectEqual(@as(usize, 2), subscribe.subscriptions.len);
    try std.testing.expectEqualStrings("sensors/+", subscribe.subscriptions[0].topic_filter);
    try std.testing.expectEqual(QoS.at_least_once, subscribe.subscriptions[0].qos);

    subscribe_bytes.clearRetainingCapacity();
    try Subscribe.write(&subscribe_bytes, allocator, .v3_1_1, 10, &.{}, &.{.{ .topic_filter = "v3/ok", .qos = .at_least_once }});
    subscribe.deinit(allocator);
    subscribe = try Subscribe.parse(allocator, .v3_1_1, subscribe_bytes.items);
    try std.testing.expectEqual(@as(u16, 10), subscribe.packet_id);
    try std.testing.expectEqual(QoS.at_least_once, subscribe.subscriptions[0].qos);
    try std.testing.expect(!subscribe.subscriptions[0].no_local);
    try std.testing.expect(!subscribe.subscriptions[0].retain_as_published);
    try std.testing.expectEqual(@as(u2, 0), subscribe.subscriptions[0].retain_handling);

    try std.testing.expectError(error.InvalidSubscription, Subscribe.write(&subscribe_bytes, allocator, .v3_1_1, 11, &.{}, &.{.{
        .topic_filter = "v3/no-local",
        .qos = .at_most_once,
        .no_local = true,
    }}));
    try std.testing.expectError(error.InvalidSubscription, Subscribe.write(&subscribe_bytes, allocator, .v3_1_1, 12, &.{}, &.{.{
        .topic_filter = "v3/retain-handling",
        .retain_handling = 1,
    }}));
    try std.testing.expectError(error.InvalidSubscription, Subscribe.write(&subscribe_bytes, allocator, .v5, 13, &.{}, &.{.{
        .topic_filter = "$share/workers/sensors/+",
        .no_local = true,
    }}));

    var invalid_v3_options: std.ArrayList(u8) = .empty;
    defer invalid_v3_options.deinit(allocator);
    var invalid_v3_variable: std.ArrayList(u8) = .empty;
    defer invalid_v3_variable.deinit(allocator);
    try wire.appendInt(&invalid_v3_variable, allocator, u16, 13, .big);
    try writeUtf8(&invalid_v3_variable, allocator, "v3/bad-options");
    try invalid_v3_variable.append(allocator, 0x04); // MQTT 5 No Local bit is reserved in 3.1.1.
    try (FixedHeader{
        .packet_type = .subscribe,
        .flags = PacketType.subscribe.defaultFlags(),
        .remaining_len = invalid_v3_variable.items.len,
        .header_len = 0,
    }).write(&invalid_v3_options, allocator);
    try invalid_v3_options.appendSlice(allocator, invalid_v3_variable.items);
    try std.testing.expectError(error.MalformedSubscriptionOptions, Subscribe.parse(allocator, .v3_1_1, invalid_v3_options.items));

    for ([_]u8{ 0x40, 0x80, 0xf0 }) |options| {
        const malformed = [_]u8{
            0x82, 0x07, 0x00, 0x0f, 0x00, 0x00, 0x01, 'p', options,
        };
        try std.testing.expectError(
            error.MalformedSubscriptionOptions,
            Subscribe.parse(allocator, .v5, &malformed),
        );
    }
    try std.testing.expectError(
        error.InvalidSubscription,
        Subscribe.parse(
            allocator,
            .v5,
            &.{ 0x82, 0x07, 0x00, 0x0f, 0x00, 0x00, 0x01, 'p', 0x30 },
        ),
    );

    // A complete UTF-8 Topic Filter still needs its Subscription Options
    // byte. Read the whole subscription tuple before applying semantic Topic
    // Filter checks so structural truncation remains a Malformed Packet.
    try std.testing.expectError(
        error.BufferTooShort,
        Subscribe.parse(
            allocator,
            .v5,
            &.{ 0x82, 0x06, 0x00, 0x0f, 0x00, 0x00, 0x01, 'p' },
        ),
    );

    var invalid_shared_no_local: std.ArrayList(u8) = .empty;
    defer invalid_shared_no_local.deinit(allocator);
    var invalid_shared_variable: std.ArrayList(u8) = .empty;
    defer invalid_shared_variable.deinit(allocator);
    try wire.appendInt(&invalid_shared_variable, allocator, u16, 14, .big);
    try writeProperties(&invalid_shared_variable, allocator, &.{});
    try writeUtf8(&invalid_shared_variable, allocator, "$share/workers/sensors/+");
    try invalid_shared_variable.append(allocator, 0x04);
    try (FixedHeader{
        .packet_type = .subscribe,
        .flags = PacketType.subscribe.defaultFlags(),
        .remaining_len = invalid_shared_variable.items.len,
        .header_len = 0,
    }).write(&invalid_shared_no_local, allocator);
    try invalid_shared_no_local.appendSlice(allocator, invalid_shared_variable.items);
    try std.testing.expectError(error.InvalidSubscription, Subscribe.parse(allocator, .v5, invalid_shared_no_local.items));

    var suback_bytes: std.ArrayList(u8) = .empty;
    defer suback_bytes.deinit(allocator);
    const reasons = [_]u8{ 0x01, 0x00 };
    try SubAck.write(&suback_bytes, allocator, .v5, 9, &.{}, &reasons);
    var suback = try SubAck.parse(allocator, .v5, suback_bytes.items);
    defer suback.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 9), suback.packet_id);
    try std.testing.expectEqualSlices(u8, &reasons, suback.reason_codes);
    var direct_suback: [256]u8 = undefined;
    const direct_v5 = try SubAck.writeNoPropertiesInto(
        &direct_suback,
        .v5,
        9,
        &reasons,
    );
    try std.testing.expectEqualSlices(u8, suback_bytes.items, direct_v5);
    try std.testing.expectEqual(
        direct_v5.len,
        try SubAck.noPropertiesWireLen(.v5, 9, &reasons),
    );

    suback_bytes.clearRetainingCapacity();
    try SubAck.write(&suback_bytes, allocator, .v3_1_1, 9, &.{}, &.{0x80});
    suback.deinit(allocator);
    suback = try SubAck.parse(allocator, .v3_1_1, suback_bytes.items);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x80}, suback.reason_codes);
    try std.testing.expectEqualSlices(
        u8,
        suback_bytes.items,
        try SubAck.writeNoPropertiesInto(
            &direct_suback,
            .v3_1_1,
            9,
            &.{0x80},
        ),
    );
    try std.testing.expectError(error.InvalidReasonCode, SubAck.write(&suback_bytes, allocator, .v3_1_1, 9, &.{}, &.{0x83}));
    try std.testing.expectError(
        error.BufferTooShort,
        SubAck.writeNoPropertiesInto(
            direct_suback[0 .. direct_v5.len - 1],
            .v5,
            9,
            &reasons,
        ),
    );
    try std.testing.expectError(
        error.InvalidPacketIdentifier,
        SubAck.noPropertiesWireLen(.v5, 0, &reasons),
    );
    var untouched_suback: [8]u8 = @splat(0xa5);
    try std.testing.expectError(
        error.InvalidReasonCode,
        SubAck.writeNoPropertiesInto(
            &untouched_suback,
            .v5,
            1,
            &.{0x03},
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{0xa5} ** untouched_suback.len),
        &untouched_suback,
    );
    var many_reasons: [126]u8 = @splat(0);
    const direct_large = try SubAck.writeNoPropertiesInto(
        &direct_suback,
        .v5,
        0x1234,
        &many_reasons,
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x90, 0x81, 0x01, 0x12, 0x34, 0x00 },
        direct_large[0..6],
    );
    try std.testing.expectEqual(@as(usize, 132), direct_large.len);

    var invalid_suback: std.ArrayList(u8) = .empty;
    defer invalid_suback.deinit(allocator);
    try (FixedHeader{
        .packet_type = .suback,
        .flags = 0,
        .remaining_len = 3,
        .header_len = 0,
    }).write(&invalid_suback, allocator);
    try invalid_suback.appendSlice(allocator, &.{ 0x00, 0x09, 0x83 });
    try std.testing.expectError(error.InvalidReasonCode, SubAck.parse(allocator, .v3_1_1, invalid_suback.items));
}

test "MQTT unsubscribe and unsuback controls" {
    const allocator = std.testing.allocator;
    const filters = [_][]const u8{ "sensors/+", "alerts/#" };

    var unsubscribe_bytes: std.ArrayList(u8) = .empty;
    defer unsubscribe_bytes.deinit(allocator);
    try Unsubscribe.write(&unsubscribe_bytes, allocator, .v5, 11, &.{}, &filters);
    var unsubscribe = try Unsubscribe.parse(allocator, .v5, unsubscribe_bytes.items);
    defer unsubscribe.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 11), unsubscribe.packet_id);
    try std.testing.expectEqual(@as(usize, 2), unsubscribe.topic_filters.len);

    try std.testing.expectEqualStrings("sensors/+", unsubscribe.topic_filters[0]);
    try std.testing.expectEqualStrings("alerts/#", unsubscribe.topic_filters[1]);

    unsubscribe_bytes.clearRetainingCapacity();
    try Unsubscribe.write(&unsubscribe_bytes, allocator, .v3_1_1, 12, &.{}, &filters);
    unsubscribe.deinit(allocator);
    unsubscribe = try Unsubscribe.parse(allocator, .v3_1_1, unsubscribe_bytes.items);
    try std.testing.expectEqual(@as(u16, 12), unsubscribe.packet_id);
    try std.testing.expectEqual(@as(usize, 2), unsubscribe.topic_filters.len);

    var unsuback_bytes: std.ArrayList(u8) = .empty;
    defer unsuback_bytes.deinit(allocator);
    const reasons = [_]u8{ 0x00, 0x11 };
    try UnsubAck.write(&unsuback_bytes, allocator, .v5, 11, &.{}, &reasons);
    var unsuback = try UnsubAck.parse(allocator, .v5, unsuback_bytes.items);
    defer unsuback.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 11), unsuback.packet_id);
    try std.testing.expectEqualSlices(u8, &reasons, unsuback.reason_codes);
    var direct_unsuback: [256]u8 = undefined;
    const direct_v5 = try UnsubAck.writeNoPropertiesInto(
        &direct_unsuback,
        .v5,
        11,
        &reasons,
    );
    try std.testing.expectEqualSlices(u8, unsuback_bytes.items, direct_v5);
    try std.testing.expectEqual(
        direct_v5.len,
        try UnsubAck.noPropertiesWireLen(.v5, 11, &reasons),
    );

    unsuback_bytes.clearRetainingCapacity();
    try UnsubAck.write(&unsuback_bytes, allocator, .v3_1_1, 12, &.{}, &.{});
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xb0, 0x02, 0x00, 0x0c }, unsuback_bytes.items);
    unsuback.deinit(allocator);
    unsuback = try UnsubAck.parse(allocator, .v3_1_1, unsuback_bytes.items);
    try std.testing.expectEqual(@as(u16, 12), unsuback.packet_id);
    try std.testing.expectEqualSlices(u8, &[_]u8{0x00}, unsuback.reason_codes);

    unsuback_bytes.clearRetainingCapacity();
    try UnsubAck.write(&unsuback_bytes, allocator, .v3_1_1, 13, &.{}, &.{0x00});
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xb0, 0x02, 0x00, 0x0d }, unsuback_bytes.items);
    try std.testing.expectEqualSlices(
        u8,
        unsuback_bytes.items,
        try UnsubAck.writeNoPropertiesInto(
            &direct_unsuback,
            .v3_1_1,
            13,
            &.{0x00},
        ),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        UnsubAck.noPropertiesWireLen(.v5, 1, &.{}),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        UnsubAck.writeNoPropertiesInto(
            &direct_unsuback,
            .v3_1_1,
            1,
            &.{0x11},
        ),
    );
    var untouched_unsuback: [8]u8 = @splat(0x5a);
    try std.testing.expectError(
        error.InvalidReasonCode,
        UnsubAck.writeNoPropertiesInto(
            &untouched_unsuback,
            .v5,
            1,
            &.{0x42},
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{0x5a} ** untouched_unsuback.len),
        &untouched_unsuback,
    );

    var invalid: std.ArrayList(u8) = .empty;
    defer invalid.deinit(allocator);
    try std.testing.expectError(error.InvalidSubscription, Unsubscribe.write(&invalid, allocator, .v5, 1, &.{}, &[_][]const u8{}));
    try std.testing.expectError(error.InvalidSubscription, Unsubscribe.write(&invalid, allocator, .v5, 1, &.{}, &[_][]const u8{"bad/#/filter"}));
    try std.testing.expectError(error.InvalidReasonCode, UnsubAck.write(&invalid, allocator, .v5, 1, &.{}, &[_]u8{0x42}));
    try std.testing.expectError(error.InvalidProperty, Unsubscribe.write(&invalid, allocator, .v3_1_1, 1, &.{
        .{ .utf8_pair = .{ .id = .user_property, .key = "k", .value = "v" } },
    }, &filters));
    try std.testing.expectError(error.InvalidProperty, UnsubAck.write(&invalid, allocator, .v3_1_1, 1, &.{
        .{ .utf8 = .{ .id = .reason_string, .value = "v3 has no properties" } },
    }, &[_]u8{0x00}));
    try std.testing.expectError(error.InvalidReasonCode, UnsubAck.write(&invalid, allocator, .v3_1_1, 1, &.{}, &[_]u8{ 0x00, 0x00 }));
    try std.testing.expectError(error.InvalidReasonCode, UnsubAck.write(&invalid, allocator, .v3_1_1, 1, &.{}, &[_]u8{0x11}));
}

test "MQTT disconnect control" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try Disconnect.write(&encoded, allocator, .v5, 0x00, &.{});
    var disconnect = try Disconnect.parse(allocator, .v5, encoded.items);
    defer disconnect.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0), disconnect.reason_code);
    encoded.clearRetainingCapacity();
    try Disconnect.write(&encoded, allocator, .v5, 0x8d, &.{});
    disconnect.deinit(allocator);
    disconnect = try Disconnect.parse(allocator, .v5, encoded.items);
    try std.testing.expectEqual(@as(u8, 0x8d), disconnect.reason_code);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xe0, 0x01, 0x8d }, encoded.items);
    encoded.clearRetainingCapacity();
    try encoded.appendSlice(allocator, &.{ 0xe0, 0x01, 0x8d });
    disconnect.deinit(allocator);
    disconnect = try Disconnect.parse(allocator, .v5, encoded.items);
    try std.testing.expectEqual(@as(u8, 0x8d), disconnect.reason_code);
    try std.testing.expectEqual(@as(usize, 0), disconnect.properties.len);
    try std.testing.expectError(error.InvalidReasonCode, Disconnect.write(&encoded, allocator, .v5, 0x05, &.{}));
    try std.testing.expectError(error.InvalidReasonCode, Disconnect.write(&encoded, allocator, .v3_1_1, 0x8d, &.{}));
    try std.testing.expectError(error.InvalidProperty, Disconnect.write(&encoded, allocator, .v3_1_1, 0, &.{
        .{ .utf8 = .{ .id = .reason_string, .value = "v3 has no properties" } },
    }));

    var direct: [Disconnect.no_properties_max_len]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xe0, 0x00 },
        try Disconnect.writeNoPropertiesInto(&direct, .v5, 0),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xe0, 0x01, 0x8d },
        try Disconnect.writeNoPropertiesInto(&direct, .v5, 0x8d),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xe0, 0x00 },
        try Disconnect.writeNoPropertiesInto(&direct, .v3_1_1, 0),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        Disconnect.writeNoPropertiesInto(&direct, .v3_1_1, 0x8d),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        Disconnect.writeNoPropertiesInto(&direct, .v5, 0x05),
    );

    var invalid: std.ArrayList(u8) = .empty;
    defer invalid.deinit(allocator);
    try (FixedHeader{
        .packet_type = .disconnect,
        .flags = 0,
        .remaining_len = 2,
        .header_len = 0,
    }).write(&invalid, allocator);
    try invalid.appendSlice(allocator, &.{ 0x05, 0x00 });
    try std.testing.expectError(error.InvalidReasonCode, Disconnect.parse(allocator, .v5, invalid.items));

    const server_reference = [_]Property{.{ .utf8 = .{
        .id = .server_reference,
        .value = "mqtt://other.example:1883",
    } }};
    encoded.clearRetainingCapacity();
    try Disconnect.write(
        &encoded,
        allocator,
        .v5,
        0x9c,
        &server_reference,
    );
    disconnect.deinit(allocator);
    disconnect = try Disconnect.parse(allocator, .v5, encoded.items);
    try std.testing.expectEqualStrings(
        "mqtt://other.example:1883",
        serverReference(disconnect.properties).?,
    );
}

test "MQTT DISCONNECT reason codes enforce sender direction" {
    const both = [_]u8{
        0x00, 0x80, 0x81, 0x82, 0x83, 0x90, 0x93,
        0x94, 0x95, 0x96, 0x97, 0x98, 0x99,
    };
    for (both) |code| {
        try validateDisconnectReasonForSender(code, .client);
        try validateDisconnectReasonForSender(code, .server);
    }

    try validateDisconnectReasonForSender(0x04, .client);
    try std.testing.expectError(
        error.InvalidReasonCode,
        validateDisconnectReasonForSender(0x04, .server),
    );

    const server_only = [_]u8{
        0x87, 0x89, 0x8b, 0x8d, 0x8e, 0x8f, 0x9a, 0x9b,
        0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2,
    };
    for (server_only) |code| {
        try validateDisconnectReasonForSender(code, .server);
        try std.testing.expectError(
            error.InvalidReasonCode,
            validateDisconnectReasonForSender(code, .client),
        );
    }
}

test "MQTT v5 AUTH control" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try Auth.write(&encoded, allocator, .v5, 0x18, &.{
        .{ .utf8 = .{ .id = .authentication_method, .value = "SCRAM-SHA-256" } },
        .{ .binary = .{ .id = .authentication_data, .value = "client-first" } },
        .{ .utf8_pair = .{ .id = .user_property, .key = "trace", .value = "auth-1" } },
    });
    var auth = try Auth.parse(allocator, .v5, encoded.items);
    defer auth.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x18), auth.reason_code);
    try std.testing.expectEqual(@as(usize, 3), auth.properties.len);
    try std.testing.expectEqual(PropertyId.authentication_method, auth.properties[0].utf8.id);
    try std.testing.expectEqualStrings("SCRAM-SHA-256", auth.properties[0].utf8.value);
    try std.testing.expectEqualStrings("client-first", auth.properties[1].binary.value);

    encoded.clearRetainingCapacity();
    try Auth.write(&encoded, allocator, .v5, 0x00, &.{});
    auth.deinit(allocator);
    auth = try Auth.parse(allocator, .v5, encoded.items);
    try std.testing.expectEqual(@as(u8, 0), auth.reason_code);
    try std.testing.expectEqual(@as(usize, 0), auth.properties.len);

    var direct: [Auth.no_properties_max_len]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xf0, 0x00 },
        try Auth.writeNoPropertiesInto(&direct, .v5, 0),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xf0, 0x02, 0x18, 0x00 },
        try Auth.writeNoPropertiesInto(&direct, .v5, 0x18),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xf0, 0x02, 0x19, 0x00 },
        try Auth.writeNoPropertiesInto(&direct, .v5, 0x19),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        Auth.writeNoPropertiesInto(&direct, .v5, 0x01),
    );
    try std.testing.expectError(
        error.InvalidPacketType,
        Auth.writeNoPropertiesInto(&direct, .v3_1_1, 0),
    );

    // MQTT 5 AUTH packets either omit the variable header entirely (remaining
    // length 0, implicit Success/no properties) or include both a reason code
    // and the following property-length varint.  A lone reason byte would make
    // the packet ambiguous for streaming parsers, so keep it rejected like
    // mature MQTT stacks such as rumqtt do.
    try std.testing.expectError(error.BufferTooShort, Auth.parse(allocator, .v5, &.{ 0xf0, 0x01, 0x18 }));

    try std.testing.expectError(error.InvalidReasonCode, Auth.write(&encoded, allocator, .v5, 0x01, &.{}));
    try std.testing.expectError(error.InvalidPacketType, Auth.write(&encoded, allocator, .v3_1_1, 0x00, &.{}));
    try std.testing.expectError(error.InvalidProperty, Auth.write(&encoded, allocator, .v5, 0x18, &.{
        .{ .two_byte = .{ .id = .receive_maximum, .value = 10 } },
    }));
}

test "MQTT AUTH reason codes enforce sender direction" {
    try validateAuthReasonForSender(0x00, .server);
    try std.testing.expectError(
        error.InvalidReasonCode,
        validateAuthReasonForSender(0x00, .client),
    );
    try validateAuthReasonForSender(0x18, .client);
    try validateAuthReasonForSender(0x18, .server);
    try validateAuthReasonForSender(0x19, .client);
    try std.testing.expectError(
        error.InvalidReasonCode,
        validateAuthReasonForSender(0x19, .server),
    );
}

test "MQTT DISCONNECT and AUTH writers reuse output capacity" {
    const allocator = std.testing.allocator;
    const disconnect_properties = [_]Property{
        .{ .utf8 = .{ .id = .reason_string, .value = "moving" } },
        .{ .utf8 = .{ .id = .server_reference, .value = "other.example" } },
    };
    const auth_properties = [_]Property{
        .{ .utf8 = .{ .id = .authentication_method, .value = "SCRAM-SHA-256" } },
        .{ .binary = .{ .id = .authentication_data, .value = "server-final" } },
    };
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);

    try Disconnect.write(
        &output,
        allocator,
        .v5,
        0x9c,
        &disconnect_properties,
    );
    const disconnect = try allocator.dupe(u8, output.items);
    defer allocator.free(disconnect);
    output.clearRetainingCapacity();
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try Disconnect.write(
        &output,
        no_alloc.allocator(),
        .v5,
        0x9c,
        &disconnect_properties,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, disconnect, output.items);
    var parsed_disconnect = try Disconnect.parse(allocator, .v5, output.items);
    defer parsed_disconnect.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x9c), parsed_disconnect.reason_code);

    output.clearRetainingCapacity();
    try Auth.write(&output, allocator, .v5, 0x18, &auth_properties);
    const auth = try allocator.dupe(u8, output.items);
    defer allocator.free(auth);
    output.clearRetainingCapacity();
    no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try Auth.write(
        &output,
        no_alloc.allocator(),
        .v5,
        0x18,
        &auth_properties,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, auth, output.items);
    var parsed_auth = try Auth.parse(allocator, .v5, output.items);
    defer parsed_auth.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x18), parsed_auth.reason_code);
    try std.testing.expectEqual(@as(usize, 2), parsed_auth.properties.len);
}

test "MQTT CONNECT information preference helpers use protocol defaults" {
    try std.testing.expectEqual(
        @as(?bool, null),
        requestProblemInformation(&.{}),
    );
    try std.testing.expectEqual(
        @as(?bool, null),
        requestResponseInformation(&.{}),
    );
    try std.testing.expectEqual(
        @as(?bool, false),
        requestProblemInformation(&.{.{ .byte = .{
            .id = .request_problem_information,
            .value = 0,
        } }}),
    );
    try std.testing.expectEqual(
        @as(?bool, true),
        requestResponseInformation(&.{.{ .byte = .{
            .id = .request_response_information,
            .value = 1,
        } }}),
    );
}
