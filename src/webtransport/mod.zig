const std = @import("std");
pub const h2 = @import("h2/mod.zig");
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
    SessionFlowControlRequired,
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

pub fn maxQuarterStreamId() u64 {
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

/// Preserve every requested initial quota, including zero, while applying
/// WebTransport capabilities. Null retains the ordinary defaulting policy.
pub const settingsWithInitialFlowLimits = @import("settings/flow.zig").apply;

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
    const local_versions = local.webTransportVersions();
    const peer_versions = peer.webTransportVersions();
    if (!peer_versions.any()) {
        if (local_versions.legacy) return .legacy;
        return error.WebTransportNotNegotiated;
    }
    return local_versions.highestCommon(peer_versions) orelse
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

test {
    _ = h2;
    _ = runtime;
    _ = @import("settings/flow_tests.zig");
    _ = flow_control;
    _ = application_protocol;
    _ = @import("runtime/negotiation_tests.zig");
}

test {
    _ = @import("tests.zig");
}
