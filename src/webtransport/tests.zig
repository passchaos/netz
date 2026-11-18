const std = @import("std");
const webtransport_root = @import("mod.zig");

const http3 = @import("../http3/mod.zig");
const quic = @import("../quic/mod.zig");
const stream = @import("stream.zig");
const wire = @import("../internal/wire.zig");

const ApplicationErrorCode = webtransport_root.ApplicationErrorCode;
const BidirectionalStreamHeader = webtransport_root.BidirectionalStreamHeader;
const Capsule = webtransport_root.Capsule;
const CapsuleType = webtransport_root.CapsuleType;
const Datagram = webtransport_root.Datagram;
const SessionId = webtransport_root.SessionId;
const SessionState = webtransport_root.SessionState;
const StreamLifecycle = webtransport_root.StreamLifecycle;
const StreamRegistry = webtransport_root.StreamRegistry;
const UnidirectionalStreamHeader = webtransport_root.UnidirectionalStreamHeader;
const Version = webtransport_root.Version;
const applicationErrorCodeToHttp3 = webtransport_root.applicationErrorCodeToHttp3;
const connectHeaders = webtransport_root.connectHeaders;
const defaultSettings = webtransport_root.defaultSettings;
const enabled = webtransport_root.enabled;
const ensureDatagramsNegotiated = webtransport_root.ensureDatagramsNegotiated;
const ensureNegotiated = webtransport_root.ensureNegotiated;
const http3ToApplicationErrorCode = webtransport_root.http3ToApplicationErrorCode;
const maxDatagramPayloadSize = webtransport_root.maxDatagramPayloadSize;
const maxQuarterStreamId = webtransport_root.maxQuarterStreamId;
const max_close_reason = webtransport_root.max_close_reason;
const negotiatedVersion = webtransport_root.negotiatedVersion;
const settingsWithSessionCapacity = webtransport_root.settingsWithSessionCapacity;

test "WebTransport capsule and stream headers" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (Capsule{ .close_session = .{ .code = 42, .reason = "done" } }).write(&encoded, allocator);
    const parsed = try Capsule.parse(encoded.items);
    try std.testing.expectEqual(@as(u32, 42), parsed.capsule.close_session.code);
    try std.testing.expectEqualStrings("done", parsed.capsule.close_session.reason);

    encoded.clearRetainingCapacity();
    try std.testing.expectError(error.InvalidCapsule, (Capsule{ .close_session = .{ .code = 1, .reason = "\xff" } }).write(&encoded, allocator));
    try quic.varint.encode(&encoded, allocator, CapsuleType.close_webtransport_session);
    try quic.varint.encode(&encoded, allocator, 5);
    try wire.appendInt(&encoded, allocator, u32, 1, .big);
    try encoded.append(allocator, 0xff);
    try std.testing.expectError(error.InvalidCapsule, Capsule.parse(encoded.items));

    var stream_bytes: std.ArrayList(u8) = .empty;
    defer stream_bytes.deinit(allocator);
    try UnidirectionalStreamHeader.writeWebTransport(
        &stream_bytes,
        allocator,
        SessionId.init(0),
    );
    const header = try UnidirectionalStreamHeader.parse(stream_bytes.items);
    try std.testing.expectEqual(http3.StreamType.webtransport_unidirectional, header.stream_type);
    try std.testing.expect(header.session_id.?.isClientInitiatedBidirectional());

    var bidi_storage: [16]u8 = undefined;
    const bidi = try BidirectionalStreamHeader.writeInto(
        &bidi_storage,
        .init(256),
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x40, 0x41, 0x41, 0x00 },
        bidi,
    );
    const bidi_header = try BidirectionalStreamHeader.parse(bidi);
    try std.testing.expectEqual(@as(u62, 256), bidi_header.session_id.value);
    try std.testing.expectEqual(bidi.len, bidi_header.consumed);
    try std.testing.expectError(
        error.InvalidStreamType,
        BidirectionalStreamHeader.parse(&.{0}),
    );

    stream_bytes.clearRetainingCapacity();
    try std.testing.expectError(
        error.InvalidSessionId,
        UnidirectionalStreamHeader.writeWebTransport(
            &stream_bytes,
            allocator,
            SessionId.init(1),
        ),
    );
    try quic.varint.encode(
        &stream_bytes,
        allocator,
        @intFromEnum(http3.StreamType.webtransport_unidirectional),
    );
    try quic.varint.encode(&stream_bytes, allocator, 1);
    try std.testing.expectError(
        error.InvalidSessionId,
        UnidirectionalStreamHeader.parse(stream_bytes.items),
    );

    const headers = connectHeaders("example.com", "/wt", "https://example.com");
    try std.testing.expectEqual(@as(usize, 6), headers.len);
    try std.testing.expectEqualStrings("capsule-protocol", headers[5].name);
    try std.testing.expect(try http3.capsule.protocolEnabled(&headers));
}

test "WebTransport close capsule enforces the reason byte limit" {
    const allocator = std.testing.allocator;
    const maximum_reason = [_]u8{'x'} ** max_close_reason;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (Capsule{ .close_session = .{
        .code = 42,
        .reason = &maximum_reason,
    } }).write(&encoded, allocator);
    const parsed = try Capsule.parse(encoded.items);
    try std.testing.expectEqual(@as(u32, 42), parsed.capsule.close_session.code);
    try std.testing.expectEqualSlices(
        u8,
        &maximum_reason,
        parsed.capsule.close_session.reason,
    );

    const oversized_reason = [_]u8{'y'} ** (max_close_reason + 1);
    var rejected: std.ArrayList(u8) = .empty;
    defer rejected.deinit(allocator);
    try rejected.appendSlice(allocator, "prefix");
    try std.testing.expectError(
        error.InvalidCapsule,
        (Capsule{ .close_session = .{
            .code = 43,
            .reason = &oversized_reason,
        } }).write(&rejected, allocator),
    );
    try std.testing.expectEqualStrings("prefix", rejected.items);

    var oversized_value: [4 + max_close_reason + 1]u8 = undefined;
    std.mem.writeInt(u32, oversized_value[0..4], 44, .big);
    @memset(oversized_value[4..], 'z');
    var malformed: std.ArrayList(u8) = .empty;
    defer malformed.deinit(allocator);
    try http3.capsule.write(
        &malformed,
        allocator,
        CapsuleType.close_webtransport_session,
        &oversized_value,
    );
    try std.testing.expectError(
        error.InvalidCapsule,
        Capsule.parse(malformed.items),
    );
}

test "WebTransport list encoders are transactional on allocation failure" {
    const allocator = std.testing.allocator;

    var capsule_bytes: std.ArrayList(u8) = .empty;
    defer capsule_bytes.deinit(allocator);
    try capsule_bytes.ensureTotalCapacityPrecise(allocator, 2);
    var capsule_failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        (Capsule{ .datagram = "x" }).write(
            &capsule_bytes,
            capsule_failing.allocator(),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), capsule_bytes.items.len);

    var unidirectional_bytes: std.ArrayList(u8) = .empty;
    defer unidirectional_bytes.deinit(allocator);
    try unidirectional_bytes.ensureTotalCapacityPrecise(allocator, 2);
    var unidirectional_failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        UnidirectionalStreamHeader.writeWebTransport(
            &unidirectional_bytes,
            unidirectional_failing.allocator(),
            .init(0),
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        unidirectional_bytes.items.len,
    );

    var datagram_bytes: std.ArrayList(u8) = .empty;
    defer datagram_bytes.deinit(allocator);
    try datagram_bytes.ensureTotalCapacityPrecise(allocator, 1);
    var datagram_failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        (Datagram{ .session_id = .init(0), .payload = "x" }).write(
            &datagram_bytes,
            datagram_failing.allocator(),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), datagram_bytes.items.len);
}

test "DRAIN_WEBTRANSPORT_SESSION capsule requires an empty payload" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try (Capsule{ .drain_session = {} }).write(&encoded, allocator);
    const parsed = try Capsule.parse(encoded.items);
    try std.testing.expect(parsed.capsule == .drain_session);
    try std.testing.expectEqual(encoded.items.len, parsed.consumed);

    encoded.clearRetainingCapacity();
    try quic.varint.encode(&encoded, allocator, CapsuleType.drain_webtransport_session);
    try quic.varint.encode(&encoded, allocator, 1);
    try encoded.append(allocator, 0);
    try std.testing.expectError(error.InvalidCapsule, Capsule.parse(encoded.items));
}

test "WebTransport stream registry enforces IDs limits and lifecycle" {
    const allocator = std.testing.allocator;
    var client = try StreamRegistry.init(
        allocator,
        .init(0),
        .client,
        .{
            .max_local_bidi = 2,
            .max_local_uni = 1,
            .max_peer_bidi = 1,
            .max_peer_uni = 1,
        },
    );
    defer client.deinit();

    const first = try client.openLocal(.bidirectional);
    try std.testing.expectEqual(@as(u62, 4), first.stream_id);
    try std.testing.expect(first.locally_initiated);
    const second = try client.openLocal(.bidirectional);
    try std.testing.expectEqual(@as(u62, 8), second.stream_id);
    try std.testing.expectError(
        error.StreamLimitExceeded,
        client.openLocal(.bidirectional),
    );
    const uni = try client.openLocal(.unidirectional);
    try std.testing.expectEqual(@as(u62, 14), uni.stream_id);
    try std.testing.expectError(
        error.StreamLimitExceeded,
        client.openLocal(.unidirectional),
    );

    const peer = try client.registerPeer(1, .bidirectional);
    try std.testing.expect(!peer.locally_initiated);
    try std.testing.expectError(
        error.DuplicateStream,
        client.registerPeer(1, .bidirectional),
    );
    try std.testing.expectError(
        error.InvalidStreamType,
        client.registerPeer(5, .unidirectional),
    );

    try client.recordSent(4, 5, true);
    try std.testing.expectEqual(
        StreamLifecycle.fin_sent,
        client.get(4).?.lifecycle(),
    );
    try client.recordReceived(4, 7, true);
    try std.testing.expectEqual(
        StreamLifecycle.closed,
        client.get(4).?.lifecycle(),
    );
    try std.testing.expectEqual(@as(u64, 5), client.get(4).?.bytes_sent);
    try std.testing.expectEqual(@as(u64, 7), client.get(4).?.bytes_received);
    try std.testing.expectError(
        error.InvalidStreamState,
        client.recordSent(4, 1, false),
    );

    try client.markReset(8, applicationErrorCodeToHttp3(42));
    try std.testing.expectEqual(
        StreamLifecycle.reset,
        client.get(8).?.lifecycle(),
    );
    try std.testing.expectEqual(
        @as(?u32, 42),
        client.get(8).?.receive_reset.?.application_code,
    );
    try client.markStopped(
        4,
        ApplicationErrorCode.buffered_stream_rejected,
    );
    try std.testing.expectEqual(
        ApplicationErrorCode.buffered_stream_rejected,
        client.get(4).?.stopped.?.http3_code,
    );
    try std.testing.expectEqual(
        @as(?u32, null),
        client.get(4).?.stopped.?.application_code,
    );
    try std.testing.expectError(
        error.UnknownStream,
        client.recordReceived(100, 1, false),
    );
}

test "WebTransport application error mapping skips reserved HTTP/3 codes" {
    const values = [_]u32{
        0,
        1,
        29,
        30,
        31,
        42,
        std.math.maxInt(u32),
    };
    for (values) |value| {
        const mapped = applicationErrorCodeToHttp3(value);
        try std.testing.expect(
            (mapped - 0x21) % 0x1f != 0,
        );
        try std.testing.expectEqual(
            @as(?u32, value),
            http3ToApplicationErrorCode(mapped),
        );
    }
    try std.testing.expectEqual(
        @as(?u32, null),
        http3ToApplicationErrorCode(
            ApplicationErrorCode.buffered_stream_rejected,
        ),
    );
    try std.testing.expectEqual(
        @as(?u32, null),
        http3ToApplicationErrorCode(
            ApplicationErrorCode.mapped_base + 0x21 -
                (ApplicationErrorCode.mapped_base % 0x1f),
        ),
    );
    try std.testing.expectEqual(
        @as(?u32, null),
        http3ToApplicationErrorCode(quic.varint.max_value),
    );
}

test "WebTransport datagram maps quarter stream id" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (Datagram{ .session_id = .init(8), .payload = "dgram" }).write(&encoded, allocator);
    const parsed = try Datagram.parse(encoded.items);
    try std.testing.expectEqual(@as(u62, 8), parsed.session_id.value);
    try std.testing.expectEqualStrings("dgram", parsed.payload);

    encoded.clearRetainingCapacity();
    try std.testing.expectError(error.InvalidSessionId, (Datagram{ .session_id = .init(1), .payload = "bad" }).write(&encoded, allocator));
    try quic.varint.encode(&encoded, allocator, maxQuarterStreamId() + 1);
    try encoded.appendSlice(allocator, "overflow");
    try std.testing.expectError(error.InvalidSessionId, Datagram.parse(encoded.items));
}

test "WebTransport session state tracks lifecycle and datagram counters" {
    var state = SessionState{};
    try std.testing.expect(!state.established);
    try std.testing.expectError(error.InvalidSessionId, state.establish(.init(1))); // server-initiated, invalid for CONNECT sessions.

    try state.establish(.init(0));
    try std.testing.expect(state.established);
    try state.recordDatagramSent(.init(0));
    try state.recordDatagramReceived(.init(0));
    try std.testing.expectEqual(@as(u64, 1), state.datagrams_sent);
    try std.testing.expectEqual(@as(u64, 1), state.datagrams_received);
    try std.testing.expectError(error.InvalidSessionId, state.recordDatagramReceived(.init(4)));

    state.drain();
    try std.testing.expect(state.draining);
    state.close(42);
    try std.testing.expect(state.closed);
    try std.testing.expectEqual(@as(?u32, 42), state.close_code);
    try std.testing.expectError(error.InvalidSessionId, state.recordDatagramSent(.init(0)));
}

test "WebTransport settings negotiation and datagram budget" {
    const local = defaultSettings(.{});
    const clamped = defaultSettings(.{
        .webtransport_max_sessions = 4,
    });
    try std.testing.expectEqual(
        @as(u64, 1),
        clamped.webtransport_max_sessions,
    );
    const multiplexed = try settingsWithSessionCapacity(.{}, 8);
    try std.testing.expectEqual(
        @as(u64, 8),
        multiplexed.webtransport_max_sessions,
    );
    try std.testing.expectError(
        error.InvalidSessionState,
        settingsWithSessionCapacity(.{}, 0),
    );
    try std.testing.expectError(
        error.InvalidSessionState,
        settingsWithSessionCapacity(
            .{},
            @as(u64, quic.varint.max_value) + 1,
        ),
    );
    const peer = http3.Settings{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .webtransport_max_sessions = 4,
    };
    try ensureDatagramsNegotiated(local, peer);
    try std.testing.expect(enabled(peer));
    var chrome_peer = peer;
    chrome_peer.enable_connect_protocol = false;
    try ensureDatagramsNegotiated(local, chrome_peer);
    try std.testing.expectError(
        error.WebTransportNotNegotiated,
        ensureDatagramsNegotiated(.{}, chrome_peer),
    );
    try std.testing.expectEqual(@as(?usize, 1199), maxDatagramPayloadSize(1200, .init(0)));
    try std.testing.expectEqual(@as(?usize, 1198), maxDatagramPayloadSize(1200, .init(256)));
    try std.testing.expectError(error.DatagramsNotNegotiated, ensureDatagramsNegotiated(local, .{
        .enable_connect_protocol = true,
        .webtransport_max_sessions = 1,
    }));
}

test "WebTransport negotiation selects only the highest common wire family" {
    const compatible = defaultSettings(.{});
    var modern = compatible;
    modern.webtransport_versions = .{ .draft16 = true };
    var legacy = compatible;
    legacy.webtransport_versions = .{ .legacy = true };
    try std.testing.expectEqual(Version.draft16, try negotiatedVersion(compatible, compatible));
    try std.testing.expectEqual(Version.draft16, try negotiatedVersion(modern, compatible));
    try std.testing.expectEqual(Version.legacy, try negotiatedVersion(compatible, legacy));
    try std.testing.expectError(error.WebTransportNotNegotiated, ensureNegotiated(modern, legacy));
    try std.testing.expectError(error.WebTransportNotNegotiated, ensureNegotiated(legacy, modern));
    const peer = http3.Settings.fromList(&.{.{
        .id = @intFromEnum(http3.SettingId.webtransport_max_sessions),
        .value = 1,
    }});
    try std.testing.expectEqual(Version.legacy, try negotiatedVersion(compatible, peer));
    try std.testing.expectError(error.WebTransportNotNegotiated, negotiatedVersion(modern, peer));
    var disabled = compatible;
    disabled.webtransport_versions = .{};
    try std.testing.expect(!enabled(disabled));
    try std.testing.expectError(error.WebTransportNotNegotiated, negotiatedVersion(disabled, compatible));
}
