const std = @import("std");
const wire = @import("../internal/wire.zig");
const webtransport_error = @import("../internal/webtransport_error.zig");
const quic = @import("../quic/mod.zig");
const http3 = @import("../http3/mod.zig");

pub const runtime = @import("runtime.zig");
pub const Version = http3.WebTransportVersion;
pub const application_protocol = @import("application_protocol.zig");

pub const Error = wire.Error || error{
    BufferTooShort,
    InvalidSessionId,
    InvalidSessionState,
    InvalidCapsule,
    InvalidStreamType,
    InvalidStreamState,
    DuplicateStream,
    UnknownStream,
    StreamLimitExceeded,
    WebTransportNotNegotiated,
    DatagramsNotNegotiated,
    ReliableResetNotNegotiated,
    IntegerOverflow,
    FlowControlBlocked,
    FlowControlViolation,
} || application_protocol.Error || std.mem.Allocator.Error;

pub const CapsuleType = @import("capsule.zig").CapsuleType;
/// Maximum UTF-8 reason length in CLOSE_WEBTRANSPORT_SESSION.
pub const max_close_reason = @import("capsule.zig").max_close_reason;
pub const flow_control = @import("flow_control.zig");

pub const ApplicationErrorCode = webtransport_error.ApplicationErrorCode;

/// WebTransport maps its 32-bit application stream errors into an HTTP/3
/// varint range while skipping every reserved HTTP/3 error code of the form
/// `0x1f * N + 0x21`.
pub fn applicationErrorCodeToHttp3(application_code: u32) u64 {
    return webtransport_error.applicationToHttp3(application_code);
}

/// Recover a WebTransport application stream error from its HTTP/3 code.
///
/// Protocol-defined errors such as SESSION_GONE and arbitrary HTTP/3 errors
/// intentionally return null; callers can still inspect `StreamError.http3_code`.
pub fn http3ToApplicationErrorCode(http3_code: u64) ?u32 {
    return webtransport_error.http3ToApplication(http3_code);
}

pub const StreamError = struct {
    /// Raw HTTP/3 application error carried by RESET_STREAM/STOP_SENDING.
    http3_code: u64,
    /// Present only when `http3_code` belongs to WebTransport's mapped range.
    application_code: ?u32,

    pub fn fromHttp3(http3_code: u64) StreamError {
        return .{
            .http3_code = http3_code,
            .application_code = http3ToApplicationErrorCode(http3_code),
        };
    }
};

pub const stream = @import("stream.zig");
pub const FrameType = stream.FrameType;
pub const BidirectionalStreamHeader = stream.BidirectionalStreamHeader;
pub const EndpointRole = stream.EndpointRole;
pub const StreamDirection = stream.StreamDirection;
pub const StreamLifecycle = stream.StreamLifecycle;
pub const ReceiveMode = stream.ReceiveMode;
pub const StreamState = stream.StreamState;
pub const StreamRegistry = stream.StreamRegistry;

pub const Setting = struct {
    pub const enable_webtransport: http3.Setting = .{ .id = @intFromEnum(http3.SettingId.webtransport_max_sessions), .value = 1 };
    pub const enable_datagram: http3.Setting = .{ .id = @intFromEnum(http3.SettingId.h3_datagram), .value = 1 };
    pub const enable_connect_protocol: http3.Setting = .{ .id = @intFromEnum(http3.SettingId.enable_connect_protocol), .value = 1 };
};

pub const default_initial_max_data: u64 = 64 * 1024;
pub const default_initial_max_streams_uni: u64 = 16;
pub const default_initial_max_streams_bidi: u64 = 16;

pub const SessionId = struct {
    value: u62,

    pub fn init(value: u62) SessionId {
        return .{ .value = value };
    }

    pub fn isClientInitiatedBidirectional(self: SessionId) bool {
        const stream_id = quic.StreamId.init(self.value);
        return stream_id.initiator() == .client and
            stream_id.direction() == .bidirectional;
    }

    pub fn quarterStreamId(self: SessionId) u60 {
        return @truncate(self.value >> 2);
    }
};

fn validateSessionId(session_id: SessionId) Error!void {
    if (!session_id.isClientInitiatedBidirectional()) return error.InvalidSessionId;
}

fn sessionIdFromWire(value: u64) Error!SessionId {
    const id: u62 = std.math.cast(u62, value) orelse return error.InvalidSessionId;
    const session_id = SessionId.init(id);
    try validateSessionId(session_id);
    return session_id;
}

pub const SessionState = struct {
    session_id: ?SessionId = null,
    established: bool = false,
    draining: bool = false,
    closed: bool = false,
    close_code: ?u32 = null,
    datagrams_sent: u64 = 0,
    datagrams_received: u64 = 0,

    pub fn establish(self: *SessionState, session_id: SessionId) Error!void {
        try validateSessionId(session_id);
        self.session_id = session_id;
        self.established = true;
        self.draining = false;
        self.closed = false;
        self.close_code = null;
    }

    pub fn recordDatagramSent(self: *SessionState, session_id: SessionId) Error!void {
        try self.ensureOpen(session_id);
        self.datagrams_sent += 1;
    }

    pub fn recordDatagramReceived(self: *SessionState, session_id: SessionId) Error!void {
        try self.ensureOpen(session_id);
        self.datagrams_received += 1;
    }

    pub fn drain(self: *SessionState) void {
        if (self.established and !self.closed) self.draining = true;
    }

    pub fn close(self: *SessionState, code: u32) void {
        self.closed = true;
        self.established = false;
        self.draining = false;
        self.close_code = code;
    }

    pub fn ensureOpen(self: SessionState, session_id: SessionId) Error!void {
        if (!self.established or self.closed) return error.InvalidSessionId;
        const current = self.session_id orelse return error.InvalidSessionId;
        if (current.value != session_id.value) return error.InvalidSessionId;
    }
};

pub const Capsule = @import("capsule.zig").Capsule;

pub const UnidirectionalStreamHeader = struct {
    stream_type: http3.StreamType,
    session_id: ?SessionId,
    consumed: usize,

    pub fn parse(bytes: []const u8) Error!UnidirectionalStreamHeader {
        var cursor = wire.Cursor.init(bytes);
        const stream_type: http3.StreamType = @enumFromInt(try quic.varint.decode(&cursor));
        const session_id = if (stream_type == .webtransport_unidirectional) try sessionIdFromWire(try quic.varint.decode(&cursor)) else null;
        return .{ .stream_type = stream_type, .session_id = session_id, .consumed = cursor.pos };
    }

    pub fn writeWebTransport(list: *std.ArrayList(u8), allocator: std.mem.Allocator, session_id: SessionId) !void {
        try validateSessionId(session_id);
        const stream_type: u64 = @intFromEnum(
            http3.StreamType.webtransport_unidirectional,
        );
        const type_len = try quic.varint.length(stream_type);
        const session_len = try quic.varint.length(session_id.value);
        try list.ensureUnusedCapacity(allocator, type_len + session_len);
        quic.varint.encodeWithLenAssumeCapacity(list, stream_type, type_len);
        quic.varint.encodeWithLenAssumeCapacity(
            list,
            session_id.value,
            session_len,
        );
    }
};

pub const Datagram = struct {
    session_id: SessionId,
    payload: []const u8,

    pub fn parse(bytes: []const u8) Error!Datagram {
        var cursor = wire.Cursor.init(bytes);
        const quarter_stream_id = try quic.varint.decode(&cursor);
        if (quarter_stream_id > maxQuarterStreamId()) return error.InvalidSessionId;
        return .{ .session_id = SessionId.init(@intCast(quarter_stream_id << 2)), .payload = bytes[cursor.pos..] };
    }

    pub fn write(self: Datagram, list: *std.ArrayList(u8), allocator: std.mem.Allocator) !void {
        try validateSessionId(self.session_id);
        const quarter_stream_id = self.session_id.quarterStreamId();
        const prefix_len = try quic.varint.length(quarter_stream_id);
        const total_len = std.math.add(usize, prefix_len, self.payload.len) catch
            return error.IntegerOverflow;
        try list.ensureUnusedCapacity(allocator, total_len);
        quic.varint.encodeWithLenAssumeCapacity(
            list,
            quarter_stream_id,
            prefix_len,
        );
        list.appendSliceAssumeCapacity(self.payload);
    }
};

fn maxQuarterStreamId() u64 {
    return @as(u64, std.math.maxInt(u62)) >> 2;
}

pub fn enabled(settings: http3.Settings) bool {
    return settings.webTransportVersions().any();
}

pub fn datagramsEnabled(settings: http3.Settings) bool {
    return settings.h3_datagram;
}

pub fn defaultSettings(settings: http3.Settings) http3.Settings {
    return settingsWithSessionCapacity(settings, 1) catch unreachable;
}

/// Apply WebTransport capability settings while advertising the exact number
/// of concurrent Sessions this endpoint can independently route on one HTTP/3
/// connection. `max_sessions` must be a non-zero QUIC varint.
pub fn settingsWithSessionCapacity(
    settings: http3.Settings,
    max_sessions: u64,
) Error!http3.Settings {
    if (max_sessions == 0 or max_sessions > quic.varint.max_value) {
        return error.InvalidSessionState;
    }
    var out = settings;
    out.enable_connect_protocol = true;
    out.h3_datagram = true;
    out.enable_webtransport = true;
    out.webtransport_max_sessions = max_sessions;
    if (out.webtransport_initial_max_data == 0) out.webtransport_initial_max_data = default_initial_max_data;
    if (out.webtransport_initial_max_streams_uni == 0) out.webtransport_initial_max_streams_uni = default_initial_max_streams_uni;
    if (out.webtransport_initial_max_streams_bidi == 0) out.webtransport_initial_max_streams_bidi = default_initial_max_streams_bidi;
    return out;
}

pub fn ensureNegotiated(local: http3.Settings, peer: http3.Settings) Error!void {
    // RFC 9220's ENABLE_CONNECT_PROTOCOL setting is an HTTP/3 capability that
    // servers advertise to clients. A WebTransport client proves its use of
    // Extended CONNECT with the validated :protocol pseudo-header; Chromium
    // therefore does not echo the setting in its client SETTINGS frame.
    if (!local.enable_connect_protocol) return error.WebTransportNotNegotiated;
    _ = try negotiatedVersion(local, peer);
}

/// Select the highest wire family both SETTINGS advertisements actually
/// support. A legacy peer cannot satisfy a draft-16-only local policy.
pub fn negotiatedVersion(local: http3.Settings, peer: http3.Settings) Error!Version {
    return local.webTransportVersions().highestCommon(peer.webTransportVersions()) orelse
        error.WebTransportNotNegotiated;
}

pub fn ensureDatagramsNegotiated(local: http3.Settings, peer: http3.Settings) Error!void {
    try ensureNegotiated(local, peer);
    if (!datagramsEnabled(local) or !datagramsEnabled(peer)) return error.DatagramsNotNegotiated;
}

pub fn maxDatagramPayloadSize(quic_payload_size: ?usize, session_id: SessionId) ?usize {
    const payload_size = quic_payload_size orelse return null;
    const quarter_stream_id_len = quic.varint.length(session_id.quarterStreamId()) catch return null;
    if (quarter_stream_id_len >= payload_size) return null;
    return payload_size - quarter_stream_id_len;
}

pub fn connectHeaders(authority: []const u8, path: []const u8, origin: []const u8) [6]http3.Qpack.HeaderField {
    return connectHeadersForVersion(authority, path, origin, .legacy);
}

pub fn connectHeadersForVersion(authority: []const u8, path: []const u8, origin: []const u8, version: Version) [6]http3.Qpack.HeaderField {
    return .{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = version.protocol() },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = authority },
        .{ .name = ":path", .value = if (path.len == 0) origin else path },
        http3.capsule.protocol_header,
    };
}

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

test {
    _ = runtime;
    _ = flow_control;
    _ = application_protocol;
    _ = @import("runtime/negotiation_tests.zig");
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
