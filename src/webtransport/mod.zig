const std = @import("std");
const wire = @import("../internal/wire.zig");
const quic = @import("../quic/mod.zig");
const http3 = @import("../http3/mod.zig");

pub const runtime = @import("runtime.zig");

pub const Error = wire.Error || error{
    BufferTooShort,
    InvalidSessionId,
    InvalidCapsule,
    InvalidStreamType,
    InvalidStreamState,
    DuplicateStream,
    UnknownStream,
    StreamLimitExceeded,
    WebTransportNotNegotiated,
    DatagramsNotNegotiated,
    IntegerOverflow,
} || std.mem.Allocator.Error;

pub const CapsuleType = struct {
    pub const datagram: u64 = 0x00;
    pub const close_webtransport_session: u64 = 0x2843;
    pub const drain_webtransport_session: u64 = 0x78ae;
};

pub const ApplicationErrorCode = struct {
    pub const session_gone: u64 = 0x170d7b68;
    pub const buffered_stream_rejected: u64 = 0x3994bd84;
    pub const mapped_base: u64 = 0x52e4a40fa8db;
};

/// WebTransport maps its 32-bit application stream errors into an HTTP/3
/// varint range while skipping every reserved HTTP/3 error code of the form
/// `0x1f * N + 0x21`.
pub fn applicationErrorCodeToHttp3(application_code: u32) u64 {
    const code: u64 = application_code;
    return ApplicationErrorCode.mapped_base + code + code / 0x1e;
}

/// Recover a WebTransport application stream error from its HTTP/3 code.
///
/// Protocol-defined errors such as SESSION_GONE and arbitrary HTTP/3 errors
/// intentionally return null; callers can still inspect `StreamError.http3_code`.
pub fn http3ToApplicationErrorCode(http3_code: u64) ?u32 {
    if (http3_code < ApplicationErrorCode.mapped_base) return null;
    const difference = http3_code - ApplicationErrorCode.mapped_base;
    const max_code: u64 = std.math.maxInt(u32);
    const mapped_end = ApplicationErrorCode.mapped_base +
        max_code + max_code / 0x1e;
    if (http3_code > mapped_end) return null;
    if ((http3_code - 0x21) % 0x1f == 0) return null;
    const candidate = difference - difference / 0x1f;
    const application_code = std.math.cast(u32, candidate) orelse return null;
    if (applicationErrorCodeToHttp3(application_code) != http3_code) {
        return null;
    }
    return application_code;
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

pub const Capsule = union(enum) {
    datagram: []const u8,
    close_session: CloseSession,
    drain_session: void,
    unknown: struct { capsule_type: u64, payload: []const u8 },

    pub const CloseSession = struct {
        code: u32,
        reason: []const u8,
    };

    pub fn parse(bytes: []const u8) Error!struct { capsule: Capsule, consumed: usize } {
        var cursor = wire.Cursor.init(bytes);
        const capsule_type = try quic.varint.decode(&cursor);
        const len = try quic.varint.decode(&cursor);
        const payload_len = std.math.cast(usize, len) orelse return error.IntegerOverflow;
        const payload = try cursor.readSlice(payload_len);
        const capsule: Capsule = switch (capsule_type) {
            CapsuleType.datagram => .{ .datagram = payload },
            CapsuleType.close_webtransport_session => blk: {
                if (payload.len < 4) return error.InvalidCapsule;
                const code = std.mem.readInt(u32, payload[0..4], .big);
                if (!std.unicode.utf8ValidateSlice(payload[4..])) return error.InvalidCapsule;
                break :blk .{ .close_session = .{ .code = code, .reason = payload[4..] } };
            },
            CapsuleType.drain_webtransport_session => .{ .drain_session = {} },
            else => .{ .unknown = .{ .capsule_type = capsule_type, .payload = payload } },
        };
        return .{ .capsule = capsule, .consumed = cursor.pos };
    }

    pub fn write(self: Capsule, list: *std.ArrayList(u8), allocator: std.mem.Allocator) !void {
        switch (self) {
            .datagram => |payload| {
                try quic.varint.encode(list, allocator, CapsuleType.datagram);
                try quic.varint.encode(list, allocator, payload.len);
                try list.appendSlice(allocator, payload);
            },
            .close_session => |close| {
                if (!std.unicode.utf8ValidateSlice(close.reason)) return error.InvalidCapsule;
                try quic.varint.encode(list, allocator, CapsuleType.close_webtransport_session);
                try quic.varint.encode(list, allocator, 4 + close.reason.len);
                try wire.appendInt(list, allocator, u32, close.code, .big);
                try list.appendSlice(allocator, close.reason);
            },
            .drain_session => {
                try quic.varint.encode(list, allocator, CapsuleType.drain_webtransport_session);
                try quic.varint.encode(list, allocator, 0);
            },
            .unknown => |unknown| {
                try quic.varint.encode(list, allocator, unknown.capsule_type);
                try quic.varint.encode(list, allocator, unknown.payload.len);
                try list.appendSlice(allocator, unknown.payload);
            },
        }
    }
};

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
        try quic.varint.encode(list, allocator, @intFromEnum(http3.StreamType.webtransport_unidirectional));
        try quic.varint.encode(list, allocator, session_id.value);
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
        try quic.varint.encode(list, allocator, self.session_id.quarterStreamId());
        try list.appendSlice(allocator, self.payload);
    }
};

fn maxQuarterStreamId() u64 {
    return @as(u64, std.math.maxInt(u62)) >> 2;
}

pub fn enabled(settings: http3.Settings) bool {
    return settings.enable_webtransport or settings.webtransport_max_sessions != 0;
}

pub fn datagramsEnabled(settings: http3.Settings) bool {
    return settings.h3_datagram;
}

pub fn defaultSettings(settings: http3.Settings) http3.Settings {
    var out = settings;
    out.enable_connect_protocol = true;
    out.h3_datagram = true;
    out.enable_webtransport = true;
    if (out.webtransport_max_sessions == 0) out.webtransport_max_sessions = 1;
    if (out.webtransport_initial_max_data == 0) out.webtransport_initial_max_data = default_initial_max_data;
    if (out.webtransport_initial_max_streams_uni == 0) out.webtransport_initial_max_streams_uni = default_initial_max_streams_uni;
    if (out.webtransport_initial_max_streams_bidi == 0) out.webtransport_initial_max_streams_bidi = default_initial_max_streams_bidi;
    return out;
}

pub fn ensureNegotiated(local: http3.Settings, peer: http3.Settings) Error!void {
    if (!local.enable_connect_protocol or !peer.enable_connect_protocol) return error.WebTransportNotNegotiated;
    if (!enabled(local) or !enabled(peer)) return error.WebTransportNotNegotiated;
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
    return .{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "webtransport" },
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
    const peer = http3.Settings{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .webtransport_max_sessions = 4,
    };
    try ensureDatagramsNegotiated(local, peer);
    try std.testing.expect(enabled(peer));
    try std.testing.expectEqual(@as(?usize, 1199), maxDatagramPayloadSize(1200, .init(0)));
    try std.testing.expectEqual(@as(?usize, 1198), maxDatagramPayloadSize(1200, .init(256)));
    try std.testing.expectError(error.DatagramsNotNegotiated, ensureDatagramsNegotiated(local, .{
        .enable_connect_protocol = true,
        .webtransport_max_sessions = 1,
    }));
}

test {
    _ = runtime;
}
