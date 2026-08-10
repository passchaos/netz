const std = @import("std");
const wire = @import("../internal/wire.zig");
const priority_field = @import("../internal/priority.zig");
const quic = @import("../quic/mod.zig");

pub const runtime = @import("runtime.zig");
pub const capsule = @import("capsule.zig");

pub const Error = wire.Error || error{
    BufferTooShort,
    InvalidFrame,
    InvalidSetting,
    InvalidStreamType,
    MissingSettings,
    DuplicateSettings,
    GoAwayIdIncreased,
    MaxPushIdReduced,
    PushIdExceeded,
    DuplicatePushId,
    ExpectedHeadersFrame,
    UnexpectedFrame,
    MissingMethod,
    MissingPath,
    MissingStatus,
    InvalidStatus,
    InvalidHeader,
    InvalidPriorityUpdate,
    StreamCreationError,
    RequestCancelled,
    RequestIncomplete,
    InvalidContentLength,
    IntegerOverflow,
    ExcessiveLoad,
    ExtendedConnectDisabled,
    QpackDynamicTableUnsupported,
    QpackEncoderStreamError,
    QpackDecoderStreamError,
    QpackDecompressionFailed,
    QpackBlocked,
} || std.mem.Allocator.Error;

pub const max_settings_payload_size: usize = 256;

pub const ApplicationErrorCode = struct {
    pub const request_rejected: u64 = 0x10b;
    pub const request_cancelled: u64 = 0x10c;
    pub const request_incomplete: u64 = 0x10d;
};

pub const AltSvcEndpoint = struct {
    /// ALPN identifier, for example "h3" or "h3-29".
    alpn: []const u8,
    /// Authority value from the quoted alternative service, usually ":443" or
    /// "host:443".  The slice is borrowed from the input field value.
    authority: []const u8,
    port: ?u16 = null,
    max_age: ?u64 = null,
};

pub const AltSvcTarget = struct {
    alpn: []const u8,
    /// Host text suitable for DNS/IP connection code.  A leading ":" Alt-Svc
    /// authority inherits the origin host; bracketed IPv6 literals are
    /// normalized by dropping their brackets.
    connect_host: []const u8,
    port: u16,
    /// Origin host used for request authority / certificate policy.  Like
    /// `connect_host`, bracketed IPv6 input is normalized without brackets.
    origin_host: []const u8,
    max_age: ?u64 = null,
};

pub const Origin = struct {
    scheme: []const u8,
    /// Host text normalized for origin comparison.  Bracketed IPv6
    /// authorities are stored without their brackets, matching Alt-Svc targets
    /// and DNS/IP dial helpers.
    host: []const u8,
    port: u16,
};

/// Build an RFC 6454-style origin key from HTTP/3 pseudo-header inputs.
///
/// This helper is intentionally certificate-agnostic: callers that coalesce
/// HTTP/3 requests across origins still need to enforce their TLS certificate
/// and server-authority policy, while this parser supplies the normalized
/// scheme/host/port key used by those decisions.
pub fn requestOrigin(scheme: []const u8, authority: []const u8) Error!Origin {
    try validateUriScheme(scheme);
    try validateRequestAuthority(authority);
    const default_port = defaultPortForScheme(scheme) orelse return error.InvalidHeader;
    return .{
        .scheme = scheme,
        .host = try altSvcAuthorityHost(authority),
        .port = altSvcPort(authority) orelse default_port,
    };
}

pub fn sameOrigin(a: Origin, b: Origin) bool {
    return std.ascii.eqlIgnoreCase(a.scheme, b.scheme) and
        std.ascii.eqlIgnoreCase(a.host, b.host) and
        a.port == b.port;
}

/// Parse the first HTTP/3 alternative from any header list containing Alt-Svc.
pub fn firstHttp3AltSvcHeader(headers: anytype) Error!?AltSvcEndpoint {
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "alt-svc")) continue;
        if (try firstHttp3AltSvc(header.value)) |endpoint| return endpoint;
    }
    return null;
}

/// Parse and resolve the first HTTP/3 Alt-Svc endpoint into connection inputs.
///
/// Real deployments often advertise `h3=":443"`, meaning "same host, different
/// protocol/port".  This helper applies that origin-relative rule and returns
/// the concrete host and port a QUIC client should dial.
pub fn firstHttp3AltSvcTarget(
    origin_host: []const u8,
    headers: anytype,
    default_port: u16,
) Error!?AltSvcTarget {
    const endpoint = (try firstHttp3AltSvcHeader(headers)) orelse return null;
    return try altSvcTarget(origin_host, endpoint, default_port);
}

pub fn altSvcTarget(
    origin_host: []const u8,
    endpoint: AltSvcEndpoint,
    default_port: u16,
) Error!AltSvcTarget {
    const origin = try normalizeAltSvcHost(origin_host);
    const connect_host = if (endpoint.authority[0] == ':')
        origin
    else
        try altSvcAuthorityHost(endpoint.authority);
    const port = endpoint.port orelse default_port;
    if (port == 0) return error.InvalidHeader;
    return .{
        .alpn = endpoint.alpn,
        .connect_host = connect_host,
        .port = port,
        .origin_host = origin,
        .max_age = endpoint.max_age,
    };
}

/// Parse the first HTTP/3 alternative from an Alt-Svc field value.
///
/// This is intentionally allocation-free so clients can cheaply inspect HTTP/1
/// or HTTP/2 response headers before deciding whether to race or upgrade to
/// HTTP/3. It accepts the common wire form used by real sites such as
/// `h3=":443"; ma=2592000,h3-29=":443"; ma=2592000`.
pub fn firstHttp3AltSvc(field_value: []const u8) Error!?AltSvcEndpoint {
    var offset: usize = 0;
    while (offset < field_value.len) {
        const next = std.mem.indexOfScalarPos(u8, field_value, offset, ',') orelse field_value.len;
        const item = std.mem.trim(u8, field_value[offset..next], " \t");
        offset = if (next == field_value.len) next else next + 1;
        if (item.len == 0) continue;
        if (std.ascii.eqlIgnoreCase(item, "clear")) return null;

        const eq = std.mem.indexOfScalar(u8, item, '=') orelse return error.InvalidHeader;
        const alpn = std.mem.trim(u8, item[0..eq], " \t");
        if (!isHttp3Alpn(alpn)) continue;

        var rest = std.mem.trim(u8, item[eq + 1 ..], " \t");
        if (rest.len < 2 or rest[0] != '"') return error.InvalidHeader;
        const quote_end = std.mem.indexOfScalarPos(u8, rest, 1, '"') orelse return error.InvalidHeader;
        const authority = rest[1..quote_end];
        if (authority.len == 0) return error.InvalidHeader;
        validateAltSvcAuthority(authority) catch return error.InvalidHeader;

        var max_age: ?u64 = null;
        rest = rest[quote_end + 1 ..];
        while (std.mem.trim(u8, rest, " \t").len != 0) {
            rest = std.mem.trim(u8, rest, " \t");
            if (rest[0] != ';') return error.InvalidHeader;
            rest = std.mem.trim(u8, rest[1..], " \t");
            const param_end = std.mem.indexOfScalar(u8, rest, ';') orelse rest.len;
            const param = std.mem.trim(u8, rest[0..param_end], " \t");
            rest = rest[param_end..];
            if (param.len == 0) continue;
            const param_eq = std.mem.indexOfScalar(u8, param, '=') orelse continue;
            const name = std.mem.trim(u8, param[0..param_eq], " \t");
            const value = std.mem.trim(u8, param[param_eq + 1 ..], " \t");
            if (std.ascii.eqlIgnoreCase(name, "ma")) {
                max_age = std.fmt.parseInt(u64, value, 10) catch return error.InvalidHeader;
            }
        }

        return .{
            .alpn = alpn,
            .authority = authority,
            .port = altSvcPort(authority),
            .max_age = max_age,
        };
    }
    return null;
}

fn isHttp3Alpn(alpn: []const u8) bool {
    if (std.mem.eql(u8, alpn, "h3")) return true;
    if (!std.mem.startsWith(u8, alpn, "h3-")) return false;
    if (alpn.len == 3) return false;
    for (alpn[3..]) |byte| {
        if (!std.ascii.isDigit(byte)) return false;
    }
    return true;
}

fn validateAltSvcAuthority(authority: []const u8) Error!void {
    for (authority) |byte| {
        // Alt-Svc uses quoted-string syntax, but the alternative authority is
        // still authority-like. Reject separators/control bytes that would make
        // the value ambiguous for callers before they race a QUIC connection.
        if (byte <= 0x20 or byte >= 0x7f or byte == '"' or byte == ',' or byte == ';' or byte == '/') {
            return error.InvalidHeader;
        }
    }
    if (authority[0] == ':') {
        _ = parseAltSvcPort(authority[1..]) orelse return error.InvalidHeader;
        return;
    }
    if (authority[0] == '[') {
        const end = std.mem.indexOfScalar(u8, authority, ']') orelse return error.InvalidHeader;
        if (end <= 1) return error.InvalidHeader;
        if (end + 1 == authority.len) return;
        if (authority[end + 1] != ':') return error.InvalidHeader;
        _ = parseAltSvcPort(authority[end + 2 ..]) orelse return error.InvalidHeader;
        return;
    }
    if (std.mem.indexOfScalar(u8, authority, '[') != null or
        std.mem.indexOfScalar(u8, authority, ']') != null)
    {
        return error.InvalidHeader;
    }
    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon| {
        if (colon == 0 or colon + 1 >= authority.len) return error.InvalidHeader;
        if (std.mem.indexOfScalar(u8, authority[0..colon], ':') != null) return error.InvalidHeader;
        _ = parseAltSvcPort(authority[colon + 1 ..]) orelse return error.InvalidHeader;
    }
}

fn altSvcPort(authority: []const u8) ?u16 {
    if (authority.len == 0) return null;
    if (authority[0] == ':') return parseAltSvcPort(authority[1..]);
    if (authority[0] == '[') {
        const end = std.mem.indexOfScalar(u8, authority, ']') orelse return null;
        if (end + 1 >= authority.len or authority[end + 1] != ':') return null;
        return parseAltSvcPort(authority[end + 2 ..]);
    }
    const colon = std.mem.lastIndexOfScalar(u8, authority, ':') orelse return null;
    if (std.mem.indexOfScalar(u8, authority[0..colon], ':') != null) return null;
    return parseAltSvcPort(authority[colon + 1 ..]);
}

fn parseAltSvcPort(bytes: []const u8) ?u16 {
    if (bytes.len == 0) return null;
    return std.fmt.parseInt(u16, bytes, 10) catch null;
}

fn defaultPortForScheme(scheme: []const u8) ?u16 {
    if (std.ascii.eqlIgnoreCase(scheme, "https")) return 443;
    if (std.ascii.eqlIgnoreCase(scheme, "http")) return 80;
    return null;
}

fn normalizeAltSvcHost(host: []const u8) Error![]const u8 {
    if (host.len == 0) return error.InvalidHeader;
    for (host) |byte| {
        if (byte <= 0x20 or byte >= 0x7f or
            byte == '"' or byte == ',' or byte == ';' or byte == '/')
        {
            return error.InvalidHeader;
        }
    }
    if (host[0] == '[') {
        if (host.len <= 2 or host[host.len - 1] != ']') {
            return error.InvalidHeader;
        }
        return host[1 .. host.len - 1];
    }
    if (std.mem.indexOfScalar(u8, host, '[') != null or
        std.mem.indexOfScalar(u8, host, ']') != null)
    {
        return error.InvalidHeader;
    }
    return host;
}

fn altSvcAuthorityHost(authority: []const u8) Error![]const u8 {
    if (authority.len == 0 or authority[0] == ':') return error.InvalidHeader;
    if (authority[0] == '[') {
        const end = std.mem.indexOfScalar(u8, authority, ']') orelse
            return error.InvalidHeader;
        if (end <= 1) return error.InvalidHeader;
        return authority[1..end];
    }
    const colon = std.mem.lastIndexOfScalar(u8, authority, ':') orelse
        return authority;
    return authority[0..colon];
}

pub const FrameType = struct {
    pub const data: u64 = 0x00;
    pub const headers: u64 = 0x01;
    pub const cancel_push: u64 = 0x03;
    pub const settings: u64 = 0x04;
    pub const push_promise: u64 = 0x05;
    pub const goaway: u64 = 0x07;
    pub const max_push_id: u64 = 0x0d;
    pub const priority_update_request: u64 = 0x0f0700;
    pub const priority_update_push: u64 = 0x0f0701;
    pub const webtransport_stream: u64 = 0x41;
};

pub const StreamType = enum(u64) {
    control = 0x00,
    push = 0x01,
    qpack_encoder = 0x02,
    qpack_decoder = 0x03,
    webtransport_unidirectional = 0x54,
    _,
};

pub const Frame = struct {
    pub const Header = struct {
        frame_type: u64,
        payload_length: usize,
        header_length: usize,

        pub fn totalLength(self: Header) Error!usize {
            return std.math.add(
                usize,
                self.header_length,
                self.payload_length,
            ) catch error.IntegerOverflow;
        }
    };

    frame_type: u64,
    payload: []const u8,
    consumed: usize,

    /// Parse only type and payload length.
    ///
    /// This succeeds as soon as both varints are available, even when the
    /// payload is split across later QUIC STREAM frames.
    pub fn parseHeader(bytes: []const u8) Error!Header {
        var cursor = wire.Cursor.init(bytes);
        const frame_type = try quic.varint.decode(&cursor);
        try validateFrameType(frame_type);
        const encoded_length = try quic.varint.decode(&cursor);
        const payload_length = std.math.cast(
            usize,
            encoded_length,
        ) orelse return error.IntegerOverflow;
        const header: Header = .{
            .frame_type = frame_type,
            .payload_length = payload_length,
            .header_length = cursor.pos,
        };
        _ = try header.totalLength();
        return header;
    }

    pub fn parse(bytes: []const u8) Error!Frame {
        const header = try parseHeader(bytes);
        const total_length = try header.totalLength();
        if (bytes.len < total_length) return error.BufferTooShort;
        return .{
            .frame_type = header.frame_type,
            .payload = bytes[header.header_length..total_length],
            .consumed = total_length,
        };
    }

    pub fn write(self: Frame, list: *std.ArrayList(u8), allocator: std.mem.Allocator) !void {
        try validateFrameType(self.frame_type);
        try validateFramePayloadShape(self.frame_type, self.payload);
        try quic.varint.encode(list, allocator, self.frame_type);
        try quic.varint.encode(list, allocator, self.payload.len);
        try list.appendSlice(allocator, self.payload);
    }
};

fn validateFrameType(frame_type: u64) Error!void {
    switch (frame_type) {
        // RFC 9114 §7.2.8 reserves the HTTP/2 frame type code points that have
        // no HTTP/3 semantics.  tquic and quic-zig reject them as
        // H3_FRAME_UNEXPECTED rather than treating them as ignorable extension
        // frames; do the same at the frame parser boundary so every stream
        // context gets consistent behavior.
        0x02, 0x06, 0x08, 0x09 => return error.UnexpectedFrame,
        else => {},
    }
}

fn validateFramePayloadShape(frame_type: u64, payload: []const u8) Error!void {
    switch (frame_type) {
        FrameType.goaway,
        FrameType.cancel_push,
        FrameType.max_push_id,
        => _ = try parseSingleVarintPayload(payload),
        FrameType.push_promise => _ = try parsePushPromisePayload(payload),
        FrameType.priority_update_request,
        FrameType.priority_update_push,
        => _ = try parsePriorityUpdatePayload(payload),
        else => {},
    }
}

pub const SettingId = enum(u64) {
    qpack_max_table_capacity = 0x01,
    max_field_section_size = 0x06,
    qpack_blocked_streams = 0x07,
    enable_connect_protocol = 0x08,
    h3_datagram = 0x33,
    /// Legacy WebTransport enable/max-session identifier seen in older
    /// WebTransport drafts and retained by earlier netz releases.  Peers in
    /// the wild disagree on whether this identifier is a boolean enable bit or
    /// a session count, so Settings.fromList accepts either non-zero form.
    webtransport_max_sessions = 0x2b603742,
    enable_webtransport = 0x2c7cf000,
    webtransport_max_sessions_draft = 0xc671706a,
    webtransport_max_sessions_v13 = 0x14e9cd29,
    webtransport_initial_max_data = 0x2b61,
    webtransport_initial_max_streams_uni = 0x2b64,
    webtransport_initial_max_streams_bidi = 0x2b65,
    _,
};

pub const Setting = struct {
    id: u64,
    value: u64,
};

pub const Settings = struct {
    /// Hard implementation cap; each runtime additionally bounds this by its
    /// configured concurrent request-stream retention limit.
    pub const max_supported_qpack_blocked_streams: u64 = 128;

    qpack_max_table_capacity: u64 = 0,
    /// RFC 9114 inherits the HTTP semantics that an omitted
    /// SETTINGS_MAX_FIELD_SECTION_SIZE means "no advertised limit".  Mature
    /// stacks such as tquic represent this as None/unbounded; use maxInt here
    /// so callers can still compare against a concrete value.
    max_field_section_size: u64 = std.math.maxInt(u64),
    qpack_blocked_streams: u64 = 0,
    enable_connect_protocol: bool = false,
    h3_datagram: bool = false,
    enable_webtransport: bool = false,
    webtransport_max_sessions: u64 = 0,
    webtransport_initial_max_data: u64 = 0,
    webtransport_initial_max_streams_uni: u64 = 0,
    webtransport_initial_max_streams_bidi: u64 = 0,

    pub fn fromList(settings: []const Setting) Settings {
        var out: Settings = .{};
        for (settings) |setting| {
            switch (setting.id) {
                @intFromEnum(SettingId.qpack_max_table_capacity) => out.qpack_max_table_capacity = setting.value,
                @intFromEnum(SettingId.max_field_section_size) => out.max_field_section_size = setting.value,
                @intFromEnum(SettingId.qpack_blocked_streams) => out.qpack_blocked_streams = setting.value,
                @intFromEnum(SettingId.enable_connect_protocol) => out.enable_connect_protocol = setting.value != 0,
                @intFromEnum(SettingId.h3_datagram) => out.h3_datagram = setting.value != 0,
                @intFromEnum(SettingId.enable_webtransport) => out.enable_webtransport = setting.value != 0,
                @intFromEnum(SettingId.webtransport_max_sessions) => {
                    if (setting.value != 0) out.enable_webtransport = true;
                    // Older drafts used this identifier inconsistently: some
                    // peers send it as a boolean enable bit, while older netz
                    // used it as the session count.  Preserve a real count
                    // received under newer identifiers if this legacy bit
                    // arrives later in the SETTINGS payload.
                    if (setting.value > 1 or out.webtransport_max_sessions == 0) {
                        out.webtransport_max_sessions = setting.value;
                    }
                },
                @intFromEnum(SettingId.webtransport_max_sessions_draft),
                @intFromEnum(SettingId.webtransport_max_sessions_v13),
                => {
                    out.webtransport_max_sessions = setting.value;
                    if (setting.value != 0) out.enable_webtransport = true;
                },
                @intFromEnum(SettingId.webtransport_initial_max_data) => out.webtransport_initial_max_data = setting.value,
                @intFromEnum(SettingId.webtransport_initial_max_streams_uni) => out.webtransport_initial_max_streams_uni = setting.value,
                @intFromEnum(SettingId.webtransport_initial_max_streams_bidi) => out.webtransport_initial_max_streams_bidi = setting.value,
                else => {}, // RFC 9114 requires unknown settings to be ignored.
            }
        }
        return out;
    }

    pub fn writePayload(self: Settings, list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
        try self.validateLocal();
        if (self.qpack_max_table_capacity != 0) try writeSetting(list, allocator, .qpack_max_table_capacity, self.qpack_max_table_capacity);
        if (self.max_field_section_size != std.math.maxInt(u64)) try writeSetting(list, allocator, .max_field_section_size, self.max_field_section_size);
        if (self.qpack_blocked_streams != 0) try writeSetting(list, allocator, .qpack_blocked_streams, self.qpack_blocked_streams);
        if (self.enable_connect_protocol) try writeSetting(list, allocator, .enable_connect_protocol, 1);
        if (self.h3_datagram) try writeSetting(list, allocator, .h3_datagram, 1);
        const webtransport_enabled = self.enable_webtransport or self.webtransport_max_sessions != 0;
        if (webtransport_enabled) {
            // Emit both legacy enable identifiers.  The historical netz name
            // for 0x2b603742 is kept for source compatibility, but writing a
            // boolean value here avoids peers that validate it as an enable bit
            // rejecting counts greater than one.  The concrete max-session
            // count is emitted below under the newer identifiers.
            try writeSetting(list, allocator, .webtransport_max_sessions, 1);
            try writeSetting(list, allocator, .enable_webtransport, 1);
        }
        if (self.webtransport_max_sessions != 0) {
            try writeSetting(list, allocator, .webtransport_max_sessions_draft, self.webtransport_max_sessions);
            try writeSetting(list, allocator, .webtransport_max_sessions_v13, self.webtransport_max_sessions);
        }
        if (self.webtransport_initial_max_data != 0) try writeSetting(list, allocator, .webtransport_initial_max_data, self.webtransport_initial_max_data);
        if (self.webtransport_initial_max_streams_uni != 0) try writeSetting(list, allocator, .webtransport_initial_max_streams_uni, self.webtransport_initial_max_streams_uni);
        if (self.webtransport_initial_max_streams_bidi != 0) try writeSetting(list, allocator, .webtransport_initial_max_streams_bidi, self.webtransport_initial_max_streams_bidi);
    }

    pub fn validateLocal(self: Settings) Error!void {
        if (self.qpack_blocked_streams > max_supported_qpack_blocked_streams) {
            return error.QpackDynamicTableUnsupported;
        }
        if (std.math.cast(usize, self.qpack_max_table_capacity) == null) {
            return error.InvalidSetting;
        }
    }
};

fn writeSetting(list: *std.ArrayList(u8), allocator: std.mem.Allocator, id: SettingId, value: u64) Error!void {
    try quic.varint.encode(list, allocator, @intFromEnum(id));
    try quic.varint.encode(list, allocator, value);
}

pub const SettingsState = struct {
    local: Settings = .{},
    peer: Settings = .{},
    sent: bool = false,
    received: bool = false,

    pub fn markSent(self: *SettingsState, settings: Settings) void {
        self.local = settings;
        self.sent = true;
    }

    pub fn markReceived(self: *SettingsState, settings: Settings) void {
        self.peer = settings;
        self.received = true;
    }

    pub fn ready(self: SettingsState) bool {
        return self.sent and self.received;
    }
};

pub const ControlState = struct {
    pub const StoredPriorityUpdate = struct {
        frame_type: u64,
        payload: PriorityUpdatePayload,

        pub fn priority(self: StoredPriorityUpdate) Priority {
            return self.payload.priority();
        }

        fn deinit(
            self: *StoredPriorityUpdate,
            allocator: std.mem.Allocator,
        ) void {
            allocator.free(self.payload.field_value);
            self.* = undefined;
        }
    };

    settings: SettingsState = .{},
    peer_goaway_id: ?u64 = null,
    local_goaway_id: ?u64 = null,
    peer_max_push_id: ?u64 = null,
    local_max_push_id: ?u64 = null,
    /// Most recent peer CANCEL_PUSH identifier, retained for compatibility.
    peer_cancelled_push_id: ?u64 = null,
    /// Every distinct peer-cancelled push ID in receive order.
    peer_cancelled_push_ids: std.ArrayList(u64) = .empty,
    push_cancellation_generation: u64 = 0,
    peer_control_stream_id: ?u64 = null,
    latest_priority_update: ?PriorityUpdatePayload = null,
    latest_priority_update_type: ?u64 = null,
    priority_updates: std.ArrayList(StoredPriorityUpdate) = .empty,
    priority_update_generation: u64 = 0,
    peer_qpack_encoder_stream_id: ?u64 = null,
    peer_qpack_decoder_stream_id: ?u64 = null,

    pub fn deinit(self: *ControlState, allocator: std.mem.Allocator) void {
        for (self.priority_updates.items) |*update| {
            update.deinit(allocator);
        }
        self.priority_updates.deinit(allocator);
        self.peer_cancelled_push_ids.deinit(allocator);
        self.* = undefined;
    }

    pub fn clone(
        self: ControlState,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!ControlState {
        var copy = self;
        copy.latest_priority_update = null;
        copy.priority_updates = .empty;
        copy.peer_cancelled_push_ids = .empty;
        errdefer copy.deinit(allocator);
        try copy.peer_cancelled_push_ids.appendSlice(
            allocator,
            self.peer_cancelled_push_ids.items,
        );
        try copy.priority_updates.ensureTotalCapacity(
            allocator,
            self.priority_updates.items.len,
        );
        for (self.priority_updates.items) |update| {
            const owned = try allocator.dupe(
                u8,
                update.payload.field_value,
            );
            copy.priority_updates.appendAssumeCapacity(.{
                .frame_type = update.frame_type,
                .payload = .{
                    .prioritized_element_id = update.payload.prioritized_element_id,
                    .field_value = owned,
                },
            });
        }
        if (copy.priority_updates.items.len != 0) {
            copy.latest_priority_update =
                copy.priority_updates.items[
                    copy.priority_updates.items.len - 1
                ].payload;
        }
        return copy;
    }

    pub fn writeSettingsStream(self: *ControlState, list: *std.ArrayList(u8), allocator: std.mem.Allocator, settings: Settings) Error!void {
        try writeControlStreamPrefix(list, allocator);
        try writeSettingsFrame(list, allocator, settings);
        self.settings.markSent(settings);
    }

    pub fn writeGoAway(self: *ControlState, list: *std.ArrayList(u8), allocator: std.mem.Allocator, stream_id: u64) Error!void {
        if (self.local_goaway_id) |previous| {
            if (stream_id > previous) return error.GoAwayIdIncreased;
        }

        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(allocator);
        try quic.varint.encode(&payload, allocator, stream_id);
        try (Frame{ .frame_type = FrameType.goaway, .payload = payload.items, .consumed = 0 }).write(list, allocator);
        self.local_goaway_id = stream_id;
    }

    pub fn writeMaxPushId(self: *ControlState, list: *std.ArrayList(u8), allocator: std.mem.Allocator, push_id: u64) Error!void {
        if (self.local_max_push_id) |previous| {
            if (push_id < previous) return error.MaxPushIdReduced;
        }
        try writeMaxPushIdFrame(list, allocator, push_id);
        self.local_max_push_id = push_id;
    }

    pub fn applyControlStreamBytes(self: *ControlState, allocator: std.mem.Allocator, bytes: []const u8) Error!void {
        var cursor = wire.Cursor.init(bytes);
        const stream_type: StreamType = @enumFromInt(try quic.varint.decode(&cursor));
        if (stream_type != .control) return error.InvalidStreamType;
        try self.registerControlStream(0);
        try self.applyControlPayload(allocator, bytes[cursor.pos..]);
    }

    pub fn applyControlPayload(self: *ControlState, allocator: std.mem.Allocator, payload: []const u8) Error!void {
        var cursor = wire.Cursor.init(payload);
        while (!cursor.eof()) {
            const frame = try Frame.parse(payload[cursor.pos..]);
            cursor.pos += frame.consumed;
            try self.applyFrame(allocator, frame);
        }
    }

    pub fn registerControlStream(self: *ControlState, stream_id: u64) Error!void {
        if (self.peer_control_stream_id) |existing| {
            if (existing != stream_id) return error.StreamCreationError;
            return;
        }
        self.peer_control_stream_id = stream_id;
    }

    pub fn registerQpackStream(self: *ControlState, stream_type: StreamType, stream_id: u64) Error!void {
        switch (stream_type) {
            .qpack_encoder => {
                if (self.peer_qpack_encoder_stream_id != null) return error.StreamCreationError;
                self.peer_qpack_encoder_stream_id = stream_id;
            },
            .qpack_decoder => {
                if (self.peer_qpack_decoder_stream_id != null) return error.StreamCreationError;
                self.peer_qpack_decoder_stream_id = stream_id;
            },
            else => return error.InvalidStreamType,
        }
    }

    pub fn applyFrame(self: *ControlState, allocator: std.mem.Allocator, frame: Frame) Error!void {
        if (!self.settings.received and frame.frame_type != FrameType.settings) return error.MissingSettings;

        switch (frame.frame_type) {
            FrameType.settings => {
                if (self.settings.received) return error.DuplicateSettings;
                const raw = try parseSettings(allocator, frame.payload);
                defer allocator.free(raw);
                self.settings.markReceived(Settings.fromList(raw));
            },
            FrameType.goaway => {
                const id = try parseGoAwayPayload(frame.payload);
                if (self.peer_goaway_id) |previous| {
                    if (id > previous) return error.GoAwayIdIncreased;
                }
                self.peer_goaway_id = id;
            },
            FrameType.max_push_id => {
                const push_id = try parseSingleVarintPayload(frame.payload);
                if (self.peer_max_push_id) |previous| {
                    if (push_id < previous) return error.MaxPushIdReduced;
                }
                self.peer_max_push_id = push_id;
            },
            FrameType.cancel_push => {
                const push_id = try parseSingleVarintPayload(frame.payload);
                try self.storePushCancellation(allocator, push_id);
            },
            FrameType.priority_update_request => {
                const priority_update = try parsePriorityUpdatePayload(frame.payload);
                try validateRequestStreamId(priority_update.prioritized_element_id);
                try self.storePriorityUpdate(
                    allocator,
                    frame.frame_type,
                    priority_update,
                );
            },
            FrameType.priority_update_push => {
                try self.storePriorityUpdate(
                    allocator,
                    frame.frame_type,
                    try parsePriorityUpdatePayload(frame.payload),
                );
            },
            FrameType.data, FrameType.headers, FrameType.push_promise => return error.UnexpectedFrame,
            else => {}, // Unknown extension frames on the control stream are ignored.
        }
    }

    pub fn acceptsRequestStream(self: ControlState, stream_id: u64) bool {
        const goaway_id = self.peer_goaway_id orelse return true;
        return stream_id < goaway_id;
    }

    pub fn acceptsLocalRequestStream(self: ControlState, stream_id: u64) bool {
        const goaway_id = self.local_goaway_id orelse return true;
        return stream_id < goaway_id;
    }

    pub fn requestPriorityUpdate(
        self: ControlState,
        stream_id: u64,
    ) ?PriorityUpdatePayload {
        return self.priorityUpdate(
            FrameType.priority_update_request,
            stream_id,
        );
    }

    pub fn pushPriorityUpdate(
        self: ControlState,
        push_id: u64,
    ) ?PriorityUpdatePayload {
        return self.priorityUpdate(
            FrameType.priority_update_push,
            push_id,
        );
    }

    pub fn priorityUpdate(
        self: ControlState,
        frame_type: u64,
        prioritized_element_id: u64,
    ) ?PriorityUpdatePayload {
        for (self.priority_updates.items) |update| {
            if (update.frame_type == frame_type and
                update.payload.prioritized_element_id ==
                    prioritized_element_id)
            {
                return update.payload;
            }
        }
        return null;
    }

    pub fn pushCancelled(self: ControlState, push_id: u64) bool {
        for (self.peer_cancelled_push_ids.items) |cancelled| {
            if (cancelled == push_id) return true;
        }
        return false;
    }

    fn storePushCancellation(
        self: *ControlState,
        allocator: std.mem.Allocator,
        push_id: u64,
    ) Error!void {
        if (self.pushCancelled(push_id)) {
            self.peer_cancelled_push_id = push_id;
            return;
        }
        const next_generation = std.math.add(
            u64,
            self.push_cancellation_generation,
            1,
        ) catch return error.InvalidFrame;
        try self.peer_cancelled_push_ids.append(allocator, push_id);
        self.peer_cancelled_push_id = push_id;
        self.push_cancellation_generation = next_generation;
    }

    fn storePriorityUpdate(
        self: *ControlState,
        allocator: std.mem.Allocator,
        frame_type: u64,
        update: PriorityUpdatePayload,
    ) Error!void {
        const next_generation = std.math.add(
            u64,
            self.priority_update_generation,
            1,
        ) catch return error.InvalidPriorityUpdate;
        const owned = try allocator.dupe(u8, update.field_value);
        errdefer allocator.free(owned);

        var existing_index: ?usize = null;
        for (self.priority_updates.items, 0..) |stored, index| {
            if (stored.frame_type == frame_type and
                stored.payload.prioritized_element_id ==
                    update.prioritized_element_id)
            {
                existing_index = index;
                break;
            }
        }
        if (existing_index == null) {
            try self.priority_updates.ensureUnusedCapacity(allocator, 1);
        }
        if (existing_index) |index| {
            var replaced = self.priority_updates.orderedRemove(index);
            replaced.deinit(allocator);
        }
        self.priority_updates.appendAssumeCapacity(.{
            .frame_type = frame_type,
            .payload = .{
                .prioritized_element_id = update.prioritized_element_id,
                .field_value = owned,
            },
        });
        self.latest_priority_update_type = frame_type;
        self.latest_priority_update = .{
            .prioritized_element_id = update.prioritized_element_id,
            .field_value = owned,
        };
        self.priority_update_generation = next_generation;
    }
};

pub const PushPromisePayload = struct {
    push_id: u64,
    field_section: []const u8,
};

pub const DecodedPushPromise = struct {
    push_id: u64,
    request: DecodedRequestHead,

    pub fn deinit(
        self: *DecodedPushPromise,
        allocator: std.mem.Allocator,
    ) void {
        self.request.deinit(allocator);
        self.* = undefined;
    }
};

pub const Priority = priority_field.Priority;

pub const PriorityUpdatePayload = struct {
    prioritized_element_id: u64,
    field_value: []const u8,

    pub fn priority(self: PriorityUpdatePayload) Priority {
        return Priority.parse(self.field_value);
    }
};

pub fn writeControlStreamPrefix(list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
    try quic.varint.encode(list, allocator, @intFromEnum(StreamType.control));
}

pub fn writeQpackEncoderStreamPrefix(list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
    try quic.varint.encode(list, allocator, @intFromEnum(StreamType.qpack_encoder));
}

pub fn writeQpackDecoderStreamPrefix(list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
    try quic.varint.encode(list, allocator, @intFromEnum(StreamType.qpack_decoder));
}

pub fn writeSettingsFrame(list: *std.ArrayList(u8), allocator: std.mem.Allocator, settings: Settings) Error!void {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try settings.writePayload(&payload, allocator);
    try (Frame{ .frame_type = FrameType.settings, .payload = payload.items, .consumed = 0 }).write(list, allocator);
}

pub fn parseGoAwayPayload(payload: []const u8) Error!u64 {
    return parseSingleVarintPayload(payload);
}

pub fn writeCancelPushFrame(list: *std.ArrayList(u8), allocator: std.mem.Allocator, push_id: u64) Error!void {
    try writeSingleVarintFrame(list, allocator, FrameType.cancel_push, push_id);
}

pub fn parseCancelPushPayload(payload: []const u8) Error!u64 {
    return parseSingleVarintPayload(payload);
}

pub fn writeMaxPushIdFrame(list: *std.ArrayList(u8), allocator: std.mem.Allocator, push_id: u64) Error!void {
    try writeSingleVarintFrame(list, allocator, FrameType.max_push_id, push_id);
}

pub fn parseMaxPushIdPayload(payload: []const u8) Error!u64 {
    return parseSingleVarintPayload(payload);
}

pub fn writePushPromiseFrame(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    push_id: u64,
    field_section: []const u8,
) Error!void {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try quic.varint.encode(&payload, allocator, push_id);
    try payload.appendSlice(allocator, field_section);
    try (Frame{ .frame_type = FrameType.push_promise, .payload = payload.items, .consumed = 0 }).write(list, allocator);
}

pub fn writePushPromiseDynamic(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    push_id: u64,
    promised_request: Request,
    peer_settings: Settings,
    request_stream_id: u64,
    encoder: anytype,
) Error!void {
    if (promised_request.body.len != 0 or
        promised_request.trailers.len != 0)
    {
        return error.InvalidContentLength;
    }
    var fields_buf: [64]Qpack.HeaderField = undefined;
    const fields = try promised_request.headerFields(&fields_buf);
    try validateHeaderBlock(fields, .request);
    try validateFieldSectionSize(
        fields,
        peer_settings.max_field_section_size,
    );
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try encoder.encodeFieldSection(
        &block,
        request_stream_id,
        fields,
    );
    try writePushPromiseFrame(list, allocator, push_id, block.items);
    try queueIndexableFields(encoder, fields);
}

pub fn parsePushPromisePayload(payload: []const u8) Error!PushPromisePayload {
    var cursor = wire.Cursor.init(payload);
    const push_id = quic.varint.decode(&cursor) catch return error.InvalidFrame;
    return .{ .push_id = push_id, .field_section = payload[cursor.pos..] };
}

/// Decode and own the promised request field section.
pub fn decodePushPromiseWithDynamicTable(
    allocator: std.mem.Allocator,
    payload: []const u8,
    settings: Settings,
    table: Qpack.DynamicTable,
) Error!DecodedPushPromise {
    const promise = try parsePushPromisePayload(payload);
    var request = try decodeRequestHeadFieldSectionWithDynamicTable(
        allocator,
        promise.field_section,
        settings,
        table,
    );
    errdefer request.deinit(allocator);
    request.consumed = payload.len;
    return .{ .push_id = promise.push_id, .request = request };
}

pub fn writePriorityUpdateFrame(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    request_stream_id: u64,
    priority: Priority,
) Error!void {
    try validateRequestStreamId(request_stream_id);
    var field_value_buf: [16]u8 = undefined;
    const field_value = priority.serialize(&field_value_buf);
    try writePriorityUpdateFrameRaw(list, allocator, FrameType.priority_update_request, request_stream_id, field_value);
}

pub fn writePushPriorityUpdateFrame(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    push_id: u64,
    priority: Priority,
) Error!void {
    var field_value_buf: [16]u8 = undefined;
    const field_value = priority.serialize(&field_value_buf);
    try writePriorityUpdateFrameRaw(
        list,
        allocator,
        FrameType.priority_update_push,
        push_id,
        field_value,
    );
}

pub fn writePriorityUpdateFrameRaw(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    frame_type: u64,
    prioritized_element_id: u64,
    field_value: []const u8,
) Error!void {
    if (frame_type != FrameType.priority_update_request and frame_type != FrameType.priority_update_push) return error.InvalidPriorityUpdate;
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try quic.varint.encode(&payload, allocator, prioritized_element_id);
    try payload.appendSlice(allocator, field_value);
    try (Frame{ .frame_type = frame_type, .payload = payload.items, .consumed = 0 }).write(list, allocator);
}

pub fn parsePriorityUpdatePayload(payload: []const u8) Error!PriorityUpdatePayload {
    var cursor = wire.Cursor.init(payload);
    const id = quic.varint.decode(&cursor) catch return error.InvalidFrame;
    return .{ .prioritized_element_id = id, .field_value = payload[cursor.pos..] };
}

fn validateRequestStreamId(stream_id: u64) Error!void {
    if ((stream_id & 0x3) != 0) return error.UnexpectedFrame;
}

pub fn validatePushPromise(control: ControlState, push_id: u64) Error!void {
    const max_push_id = control.local_max_push_id orelse return error.PushIdExceeded;
    if (push_id > max_push_id) return error.PushIdExceeded;
}

pub fn validateResponsePushPromises(control: ControlState, bytes: []const u8) Error!void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const frame = try Frame.parse(bytes[offset..]);
        if (frame.frame_type == FrameType.push_promise) {
            const promise = try parsePushPromisePayload(frame.payload);
            try validatePushPromise(control, promise.push_id);
        }
        offset += frame.consumed;
    }
}

fn writeSingleVarintFrame(list: *std.ArrayList(u8), allocator: std.mem.Allocator, frame_type: u64, value: u64) Error!void {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try quic.varint.encode(&payload, allocator, value);
    try (Frame{ .frame_type = frame_type, .payload = payload.items, .consumed = 0 }).write(list, allocator);
}

fn parseSingleVarintPayload(payload: []const u8) Error!u64 {
    var cursor = wire.Cursor.init(payload);
    const value = quic.varint.decode(&cursor) catch return error.InvalidFrame;
    if (!cursor.eof()) return error.InvalidFrame;
    return value;
}

pub fn parseSettings(allocator: std.mem.Allocator, payload: []const u8) Error![]Setting {
    if (payload.len > max_settings_payload_size) return error.InvalidSetting;
    var cursor = wire.Cursor.init(payload);
    var settings: std.ArrayList(Setting) = .empty;
    errdefer settings.deinit(allocator);
    while (!cursor.eof()) {
        const id = quic.varint.decode(&cursor) catch return error.InvalidSetting;
        const value = quic.varint.decode(&cursor) catch return error.InvalidSetting;
        try validateSetting(id, value, settings.items);
        try settings.append(allocator, .{ .id = id, .value = value });
    }
    return settings.toOwnedSlice(allocator);
}

fn validateSetting(id: u64, value: u64, seen: []const Setting) Error!void {
    for (seen) |setting| {
        if (setting.id == id) return error.InvalidSetting;
    }

    switch (id) {
        // RFC 9114 reserves HTTP/2 SETTINGS identifiers that have no HTTP/3
        // meaning.  Reference stacks such as tquic and quic-zig reject these as
        // H3_SETTINGS_ERROR instead of silently ignoring them.
        0x00, 0x02, 0x03, 0x04, 0x05 => return error.InvalidSetting,
        @intFromEnum(SettingId.enable_connect_protocol),
        @intFromEnum(SettingId.h3_datagram),
        @intFromEnum(SettingId.enable_webtransport),
        => if (value > 1) return error.InvalidSetting,
        else => {},
    }
}

pub fn writeSettings(list: *std.ArrayList(u8), allocator: std.mem.Allocator, settings: []const Setting) Error!void {
    for (settings, 0..) |setting, index| {
        try validateSetting(setting.id, setting.value, settings[0..index]);
        try quic.varint.encode(list, allocator, setting.id);
        try quic.varint.encode(list, allocator, setting.value);
    }
}

pub const ControlStream = struct {
    stream_type: StreamType,
    frames: []Frame,

    pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) Error!ControlStream {
        var cursor = wire.Cursor.init(bytes);
        const stream_type: StreamType = @enumFromInt(try quic.varint.decode(&cursor));
        if (stream_type != .control) return error.InvalidStreamType;
        var frames: std.ArrayList(Frame) = .empty;
        errdefer frames.deinit(allocator);
        while (!cursor.eof()) {
            const frame = try Frame.parse(bytes[cursor.pos..]);
            cursor.pos += frame.consumed;
            try frames.append(allocator, frame);
        }
        return .{ .stream_type = stream_type, .frames = try frames.toOwnedSlice(allocator) };
    }

    pub fn deinit(self: *ControlStream, allocator: std.mem.Allocator) void {
        allocator.free(self.frames);
        self.* = undefined;
    }
};

pub const Qpack = @import("qpack/mod.zig");

pub const Request = struct {
    method: []const u8,
    path: []const u8,
    scheme: []const u8 = "https",
    authority: ?[]const u8 = null,
    headers: []const Qpack.HeaderField = &.{},
    body: []const u8 = &.{},
    trailers: []const Qpack.HeaderField = &.{},

    pub fn headerFields(self: Request, out: []Qpack.HeaderField) Error![]Qpack.HeaderField {
        var count: usize = 0;
        const extended_connect = std.mem.eql(u8, self.method, "CONNECT") and requestHasProtocolPseudo(self.headers);
        try appendHeaderField(out, &count, .{ .name = ":method", .value = self.method });
        if (!std.mem.eql(u8, self.method, "CONNECT") or extended_connect) {
            try appendHeaderField(out, &count, .{ .name = ":path", .value = self.path });
            try appendHeaderField(out, &count, .{ .name = ":scheme", .value = self.scheme });
        }
        if (self.authority) |authority| try appendHeaderField(out, &count, .{ .name = ":authority", .value = authority });
        for (self.headers) |header| try appendHeaderField(out, &count, header);
        return out[0..count];
    }

    pub fn write(self: Request, list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
        try self.writeWithSettings(list, allocator, .{});
    }

    pub fn writeWithSettings(self: Request, list: *std.ArrayList(u8), allocator: std.mem.Allocator, peer_settings: Settings) Error!void {
        var fields_buf: [64]Qpack.HeaderField = undefined;
        var fields = try self.headerFields(&fields_buf);
        var content_length_buf: [32]u8 = undefined;
        if (requestShouldDefaultContentLength(self.method, fields, self.body.len)) {
            var field_count = fields.len;
            const content_length = std.fmt.bufPrint(&content_length_buf, "{}", .{self.body.len}) catch unreachable;
            try appendHeaderField(&fields_buf, &field_count, .{ .name = "content-length", .value = content_length });
            fields = fields_buf[0..field_count];
        }
        try validateHeaderBlock(fields, .request);
        try validateHeaderBlock(self.trailers, .trailers);
        try validateFieldSectionSize(fields, peer_settings.max_field_section_size);
        try validateFieldSectionSize(self.trailers, peer_settings.max_field_section_size);
        try validateRequestBodyForMethod(fields, self.body, self.trailers);
        try validateContentLength(fields, self.body.len);
        try writeHeadersAndData(list, allocator, fields, self.body, self.trailers);
    }

    pub fn writeDynamic(
        self: Request,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        peer_settings: Settings,
        stream_id: u64,
        encoder: anytype,
    ) Error!void {
        var fields_buf: [64]Qpack.HeaderField = undefined;
        var fields = try self.headerFields(&fields_buf);
        var content_length_buf: [32]u8 = undefined;
        if (requestShouldDefaultContentLength(self.method, fields, self.body.len)) {
            var field_count = fields.len;
            const content_length = std.fmt.bufPrint(
                &content_length_buf,
                "{}",
                .{self.body.len},
            ) catch unreachable;
            try appendHeaderField(&fields_buf, &field_count, .{
                .name = "content-length",
                .value = content_length,
            });
            fields = fields_buf[0..field_count];
        }
        try validateHeaderBlock(fields, .request);
        try validateHeaderBlock(self.trailers, .trailers);
        try validateFieldSectionSize(fields, peer_settings.max_field_section_size);
        try validateFieldSectionSize(self.trailers, peer_settings.max_field_section_size);
        try validateRequestBodyForMethod(fields, self.body, self.trailers);
        try validateContentLength(fields, self.body.len);
        try writeHeadersAndDataDynamic(
            list,
            allocator,
            fields,
            self.body,
            self.trailers,
            stream_id,
            encoder,
        );
        try queueIndexableFields(encoder, fields);
        try queueIndexableFields(encoder, self.trailers);
    }

    /// Encode only the initial HEADERS section for an incrementally-sent body.
    ///
    /// `body_length` adds (or verifies) Content-Length. Null permits an
    /// unknown-length body delimited by stream FIN. The returned value is the
    /// effective length to enforce while streaming; plain CONNECT returns zero
    /// because RFC 9114 forbids request DATA on that form.
    pub fn writeStreamingHeadDynamic(
        self: Request,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        peer_settings: Settings,
        stream_id: u64,
        body_length: ?usize,
        encoder: anytype,
    ) Error!struct { expected_length: ?usize, body_allowed: bool } {
        if (self.body.len != 0 or self.trailers.len != 0) {
            return error.InvalidContentLength;
        }
        var fields_buf: [64]Qpack.HeaderField = undefined;
        var fields = try self.headerFields(&fields_buf);
        var content_length_buf: [32]u8 = undefined;
        const plain_connect = std.mem.eql(u8, self.method, "CONNECT") and
            !requestHasProtocolPseudo(self.headers);
        if (plain_connect) {
            if (body_length) |length| {
                if (length != 0) return error.InvalidContentLength;
            }
            try validateHeaderBlock(fields, .request);
            try validateFieldSectionSize(
                fields,
                peer_settings.max_field_section_size,
            );
            try validateRequestBodyForMethod(fields, &.{}, &.{});
            try writeHeadersFrameDynamic(
                list,
                allocator,
                fields,
                stream_id,
                encoder,
            );
            try queueIndexableFields(encoder, fields);
            return .{ .expected_length = 0, .body_allowed = false };
        }
        const effective_length = try applyStreamingContentLength(
            &fields_buf,
            &fields,
            body_length,
            &content_length_buf,
        );
        try validateHeaderBlock(fields, .request);
        try validateFieldSectionSize(
            fields,
            peer_settings.max_field_section_size,
        );
        try validateRequestBodyForMethod(fields, &.{}, &.{});
        try writeHeadersFrameDynamic(
            list,
            allocator,
            fields,
            stream_id,
            encoder,
        );
        try queueIndexableFields(encoder, fields);
        return .{
            .expected_length = effective_length,
            .body_allowed = true,
        };
    }
};

fn requestHasProtocolPseudo(headers: []const Qpack.HeaderField) bool {
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, ":protocol")) return true;
    }
    return false;
}

fn requestShouldDefaultContentLength(method: []const u8, headers: []const Qpack.HeaderField, body_len: usize) bool {
    if (std.mem.eql(u8, method, "CONNECT")) return false;
    // Align the HTTP/3 convenience writer with Hyper's h2 shaping and our
    // HTTP/2 runtime: known non-empty bodies get an explicit length, and empty
    // bodies on methods with defined payload semantics (POST/PUT/PATCH/etc.)
    // get `content-length: 0` so intermediaries and applications do not have
    // to infer intent from the absence of DATA frames.
    if (body_len == 0 and !methodHasDefinedPayloadSemantics(method)) return false;
    return (contentLength(headers) catch return false) == null;
}

fn methodHasDefinedPayloadSemantics(method: []const u8) bool {
    return !std.mem.eql(u8, method, "GET") and
        !std.mem.eql(u8, method, "HEAD") and
        !std.mem.eql(u8, method, "DELETE") and
        !std.mem.eql(u8, method, "CONNECT");
}

fn findHeader(headers: []const Qpack.HeaderField, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

pub const Response = struct {
    status: u16,
    headers: []const Qpack.HeaderField = &.{},
    body: []const u8 = &.{},
    trailers: []const Qpack.HeaderField = &.{},

    pub fn successful(self: Response) bool {
        return self.status >= 200 and self.status < 300;
    }

    pub fn headerFields(self: Response, out: []Qpack.HeaderField, status_buf: *[3]u8) Error![]Qpack.HeaderField {
        var count: usize = 0;
        if (self.status < 100 or self.status > 999) return error.InvalidStatus;
        if (self.status < 200) return error.InvalidStatus;
        const status = std.fmt.bufPrint(status_buf, "{d}", .{self.status}) catch return error.InvalidStatus;
        try appendHeaderField(out, &count, .{ .name = ":status", .value = status });
        for (self.headers) |header| try appendHeaderField(out, &count, header);
        return out[0..count];
    }

    pub fn write(self: Response, list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
        try self.writeWithSettings(list, allocator, .{});
    }

    pub fn writeWithSettings(self: Response, list: *std.ArrayList(u8), allocator: std.mem.Allocator, peer_settings: Settings) Error!void {
        var fields_buf: [64]Qpack.HeaderField = undefined;
        var status_buf: [3]u8 = undefined;
        var fields = try self.headerFields(&fields_buf, &status_buf);
        var content_length_buf: [32]u8 = undefined;
        if (responseShouldDefaultContentLength(self.status, fields, self.body.len)) {
            var field_count = fields.len;
            const content_length = std.fmt.bufPrint(&content_length_buf, "{}", .{self.body.len}) catch unreachable;
            try appendHeaderField(&fields_buf, &field_count, .{ .name = "content-length", .value = content_length });
            fields = fields_buf[0..field_count];
        }
        try validateHeaderBlock(fields, .response);
        try validateHeaderBlock(self.trailers, .trailers);
        try validateFieldSectionSize(fields, peer_settings.max_field_section_size);
        try validateFieldSectionSize(self.trailers, peer_settings.max_field_section_size);
        try validateResponseBodyForStatus(self.status, fields, self.body, self.trailers);
        try validateContentLengthForStatus(self.status, fields, self.body.len);
        try writeHeadersAndData(list, allocator, fields, self.body, self.trailers);
    }

    pub fn writeDynamic(
        self: Response,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        peer_settings: Settings,
        stream_id: u64,
        encoder: anytype,
    ) Error!void {
        var fields_buf: [64]Qpack.HeaderField = undefined;
        var status_buf: [3]u8 = undefined;
        var fields = try self.headerFields(&fields_buf, &status_buf);
        var content_length_buf: [32]u8 = undefined;
        if (responseShouldDefaultContentLength(self.status, fields, self.body.len)) {
            var field_count = fields.len;
            const content_length = std.fmt.bufPrint(
                &content_length_buf,
                "{}",
                .{self.body.len},
            ) catch unreachable;
            try appendHeaderField(&fields_buf, &field_count, .{
                .name = "content-length",
                .value = content_length,
            });
            fields = fields_buf[0..field_count];
        }
        try validateHeaderBlock(fields, .response);
        try validateHeaderBlock(self.trailers, .trailers);
        try validateFieldSectionSize(fields, peer_settings.max_field_section_size);
        try validateFieldSectionSize(self.trailers, peer_settings.max_field_section_size);
        try validateResponseBodyForStatus(self.status, fields, self.body, self.trailers);
        try validateContentLengthForStatus(self.status, fields, self.body.len);
        try writeHeadersAndDataDynamic(
            list,
            allocator,
            fields,
            self.body,
            self.trailers,
            stream_id,
            encoder,
        );
        try queueIndexableFields(encoder, fields);
        try queueIndexableFields(encoder, self.trailers);
    }

    /// Encode only final response HEADERS for incremental DATA transmission.
    pub fn writeStreamingHeadDynamic(
        self: Response,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        peer_settings: Settings,
        stream_id: u64,
        body_length: ?usize,
        encoder: anytype,
    ) Error!struct { expected_length: ?usize, body_allowed: bool } {
        if (self.body.len != 0 or self.trailers.len != 0) {
            return error.InvalidContentLength;
        }
        var fields_buf: [64]Qpack.HeaderField = undefined;
        var status_buf: [3]u8 = undefined;
        var fields = try self.headerFields(&fields_buf, &status_buf);
        const body_forbidden = self.status == 204 or self.status == 304;
        if (body_forbidden) {
            if (self.status == 204 and findHeader(
                self.headers,
                "content-length",
            ) != null) {
                return error.InvalidContentLength;
            }
            if (body_length) |length| {
                if (length != 0) return error.InvalidContentLength;
            }
            try validateHeaderBlock(fields, .response);
            try validateFieldSectionSize(
                fields,
                peer_settings.max_field_section_size,
            );
            try validateResponseBodyForStatus(
                self.status,
                fields,
                &.{},
                &.{},
            );
            try writeHeadersFrameDynamic(
                list,
                allocator,
                fields,
                stream_id,
                encoder,
            );
            try queueIndexableFields(encoder, fields);
            return .{ .expected_length = 0, .body_allowed = false };
        }
        var content_length_buf: [32]u8 = undefined;
        const effective_length = try applyStreamingContentLength(
            &fields_buf,
            &fields,
            body_length,
            &content_length_buf,
        );
        try validateHeaderBlock(fields, .response);
        try validateFieldSectionSize(
            fields,
            peer_settings.max_field_section_size,
        );
        try validateResponseBodyForStatus(self.status, fields, &.{}, &.{});
        try writeHeadersFrameDynamic(
            list,
            allocator,
            fields,
            stream_id,
            encoder,
        );
        try queueIndexableFields(encoder, fields);
        return .{
            .expected_length = effective_length,
            .body_allowed = true,
        };
    }
};

fn applyStreamingContentLength(
    fields_buf: *[64]Qpack.HeaderField,
    fields: *[]Qpack.HeaderField,
    requested: ?usize,
    content_length_buf: *[32]u8,
) Error!?usize {
    const declared = try contentLength(fields.*);
    const expected = requested orelse return declared;
    if (declared) |value| {
        if (value != expected) return error.InvalidContentLength;
        return expected;
    }
    const rendered = std.fmt.bufPrint(
        content_length_buf,
        "{}",
        .{expected},
    ) catch unreachable;
    var field_count = fields.*.len;
    try appendHeaderField(fields_buf, &field_count, .{
        .name = "content-length",
        .value = rendered,
    });
    fields.* = fields_buf[0..field_count];
    return expected;
}

fn responseShouldDefaultContentLength(status: u16, headers: []const Qpack.HeaderField, body_len: usize) bool {
    if (body_len == 0) return false;
    if ((status >= 100 and status < 200) or status == 204 or status == 304) return false;
    return (contentLength(headers) catch return false) == null;
}

pub const InformationalResponse = struct {
    status: u16,
    headers: []const Qpack.HeaderField = &.{},

    pub fn headerFields(self: InformationalResponse, out: []Qpack.HeaderField, status_buf: *[3]u8) Error![]Qpack.HeaderField {
        if (self.status < 100 or self.status >= 200) return error.InvalidStatus;
        var count: usize = 0;
        const status = std.fmt.bufPrint(status_buf, "{d}", .{self.status}) catch return error.InvalidStatus;
        try appendHeaderField(out, &count, .{ .name = ":status", .value = status });
        for (self.headers) |header| try appendHeaderField(out, &count, header);
        return out[0..count];
    }

    pub fn write(self: InformationalResponse, list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
        try self.writeWithSettings(list, allocator, .{});
    }

    pub fn writeWithSettings(self: InformationalResponse, list: *std.ArrayList(u8), allocator: std.mem.Allocator, peer_settings: Settings) Error!void {
        var fields_buf: [64]Qpack.HeaderField = undefined;
        var status_buf: [3]u8 = undefined;
        const fields = try self.headerFields(&fields_buf, &status_buf);
        try validateHeaderBlock(fields, .response);
        try validateFieldSectionSize(fields, peer_settings.max_field_section_size);
        try validateResponseBodyForStatus(self.status, fields, &.{}, &.{});
        try writeHeadersFrame(list, allocator, fields);
    }

    pub fn writeDynamic(
        self: InformationalResponse,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        peer_settings: Settings,
        stream_id: u64,
        encoder: anytype,
    ) Error!void {
        var fields_buf: [64]Qpack.HeaderField = undefined;
        var status_buf: [3]u8 = undefined;
        const fields = try self.headerFields(&fields_buf, &status_buf);
        try validateHeaderBlock(fields, .response);
        try validateFieldSectionSize(fields, peer_settings.max_field_section_size);
        try validateResponseBodyForStatus(self.status, fields, &.{}, &.{});
        try writeHeadersFrameDynamic(
            list,
            allocator,
            fields,
            stream_id,
            encoder,
        );
        try queueIndexableFields(encoder, fields);
    }
};

pub fn writeResponseSequence(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    informational: []const InformationalResponse,
    response: Response,
) Error!void {
    try writeResponseSequenceWithSettings(list, allocator, informational, response, .{});
}

pub fn writeResponseSequenceWithSettings(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    informational: []const InformationalResponse,
    response: Response,
    peer_settings: Settings,
) Error!void {
    for (informational) |info| try info.writeWithSettings(list, allocator, peer_settings);
    try response.writeWithSettings(list, allocator, peer_settings);
}

pub fn writeResponseSequenceDynamic(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    informational: []const InformationalResponse,
    response: Response,
    peer_settings: Settings,
    stream_id: u64,
    encoder: anytype,
) Error!void {
    for (informational) |info| {
        try info.writeDynamic(
            list,
            allocator,
            peer_settings,
            stream_id,
            encoder,
        );
    }
    try response.writeDynamic(
        list,
        allocator,
        peer_settings,
        stream_id,
        encoder,
    );
}

pub const DecodedRequest = struct {
    method: []const u8,
    path: []const u8,
    scheme: []const u8,
    authority: ?[]const u8,
    headers: []Qpack.HeaderField,
    trailers: []Qpack.HeaderField = &.{},
    body: []const u8,
    body_storage: ?[]u8 = null,
    consumed: usize,
    qpack_section_acknowledgments: usize = 0,

    /// Release arrays and body storage owned by `decodeRequest`. Header field
    /// names/values still borrow from the encoded stream bytes; callers must
    /// keep those bytes alive while reading `headers` or `trailers`.
    pub fn deinit(self: *DecodedRequest, allocator: std.mem.Allocator) void {
        Qpack.freeDecodedFields(allocator, self.headers);
        Qpack.freeDecodedFields(allocator, self.trailers);
        if (self.body_storage) |body| allocator.free(body);
        self.* = undefined;
    }
};

pub const DecodedResponse = struct {
    status: u16,
    headers: []Qpack.HeaderField,
    trailers: []Qpack.HeaderField = &.{},
    body: []const u8,
    body_storage: ?[]u8 = null,
    consumed: usize,
    qpack_section_acknowledgments: usize = 0,

    pub fn successful(self: DecodedResponse) bool {
        return self.status >= 200 and self.status < 300;
    }

    /// Release arrays and body storage owned by `decodeResponse`. Header field
    /// names/values still borrow from the encoded stream bytes; callers must
    /// keep those bytes alive while reading `headers` or `trailers`.
    pub fn deinit(self: *DecodedResponse, allocator: std.mem.Allocator) void {
        Qpack.freeDecodedFields(allocator, self.headers);
        Qpack.freeDecodedFields(allocator, self.trailers);
        if (self.body_storage) |body| allocator.free(body);
        self.* = undefined;
    }
};

pub const DecodedRequestHead = struct {
    method: []const u8,
    path: []const u8,
    scheme: []const u8,
    authority: ?[]const u8,
    headers: []Qpack.HeaderField,
    content_length: ?usize,
    body_allowed: bool,
    consumed: usize,
    qpack_section_acknowledgments: usize,

    pub fn deinit(
        self: *DecodedRequestHead,
        allocator: std.mem.Allocator,
    ) void {
        Qpack.freeDecodedFields(allocator, self.headers);
        self.* = undefined;
    }
};

pub const DecodedResponseHead = struct {
    status: u16,
    headers: []Qpack.HeaderField,
    content_length: ?usize,
    body_allowed: bool,
    consumed: usize,
    qpack_section_acknowledgments: usize,

    pub fn deinit(
        self: *DecodedResponseHead,
        allocator: std.mem.Allocator,
    ) void {
        Qpack.freeDecodedFields(allocator, self.headers);
        self.* = undefined;
    }
};

pub const DecodedTrailers = struct {
    fields: []Qpack.HeaderField,
    qpack_section_acknowledgments: usize,

    pub fn deinit(
        self: *DecodedTrailers,
        allocator: std.mem.Allocator,
    ) void {
        Qpack.freeDecodedFields(allocator, self.fields);
        self.* = undefined;
    }
};

pub fn decodeTrailersWithDynamicTable(
    allocator: std.mem.Allocator,
    payload: []const u8,
    settings: Settings,
    table: Qpack.DynamicTable,
) Error!DecodedTrailers {
    const field_decoder = FieldSectionDecoder{ .dynamic = table };
    const decoded = try field_decoder.decode(allocator, payload);
    errdefer Qpack.freeDecodedFields(allocator, decoded.fields);
    try validateHeaderBlock(decoded.fields, .trailers);
    try validateFieldSectionSize(
        decoded.fields,
        settings.max_field_section_size,
    );
    const owned = try ownHeaderFields(allocator, decoded.fields);
    Qpack.freeDecodedFields(allocator, decoded.fields);
    return .{
        .fields = owned,
        .qpack_section_acknowledgments = @intFromBool(decoded.requires_acknowledgment),
    };
}

pub fn decodeRequestHeadWithDynamicTable(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    settings: Settings,
    table: Qpack.DynamicTable,
) Error!DecodedRequestHead {
    const frame = try firstHeadersFrame(bytes, .request);
    var head = try decodeRequestHeadFieldSectionWithDynamicTable(
        allocator,
        frame.value.payload,
        settings,
        table,
    );
    head.consumed = frame.consumed;
    return head;
}

pub fn decodeRequestHeadFieldSectionWithDynamicTable(
    allocator: std.mem.Allocator,
    field_section: []const u8,
    settings: Settings,
    table: Qpack.DynamicTable,
) Error!DecodedRequestHead {
    const field_decoder = FieldSectionDecoder{ .dynamic = table };
    const decoded = try field_decoder.decode(allocator, field_section);
    errdefer Qpack.freeDecodedFields(allocator, decoded.fields);
    try validateHeaderBlock(decoded.fields, .request);
    try validateFieldSectionSize(
        decoded.fields,
        settings.max_field_section_size,
    );

    var method: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var scheme: ?[]const u8 = null;
    var authority: ?[]const u8 = null;
    for (decoded.fields) |header| {
        if (std.mem.eql(u8, header.name, ":method")) {
            method = header.value;
        } else if (std.mem.eql(u8, header.name, ":path")) {
            path = header.value;
        } else if (std.mem.eql(u8, header.name, ":scheme")) {
            scheme = header.value;
        } else if (std.mem.eql(u8, header.name, ":authority")) {
            authority = header.value;
        } else if (std.ascii.eqlIgnoreCase(header.name, "host") and
            authority == null)
        {
            authority = header.value;
        }
    }
    const method_value = method orelse return error.MissingMethod;
    const has_protocol = requestHasProtocolPseudo(decoded.fields);
    if (has_protocol and !settings.enable_connect_protocol) {
        return error.ExtendedConnectDisabled;
    }
    const plain_connect = std.mem.eql(u8, method_value, "CONNECT") and
        !has_protocol;
    const declared_length = try contentLength(decoded.fields);
    if (plain_connect and declared_length != null) {
        return error.InvalidContentLength;
    }
    // validateHeaderBlock above guarantees these pseudo fields. Resolve all
    // fallible semantic choices before transferring field ownership so no
    // error path can double-free the decoder output.
    _ = path orelse if (plain_connect) "" else return error.MissingPath;
    _ = scheme orelse if (plain_connect) "" else return error.InvalidHeader;
    const owned_fields = try ownHeaderFields(allocator, decoded.fields);
    Qpack.freeDecodedFields(allocator, decoded.fields);
    return .{
        .method = ownedFieldValue(owned_fields, ":method").?,
        .path = ownedFieldValue(owned_fields, ":path") orelse
            if (plain_connect) "" else return error.MissingPath,
        .scheme = ownedFieldValue(owned_fields, ":scheme") orelse
            if (plain_connect) "" else return error.InvalidHeader,
        .authority = ownedFieldValue(owned_fields, ":authority") orelse
            ownedFieldValueCaseInsensitive(owned_fields, "host"),
        .headers = owned_fields,
        .content_length = declared_length,
        .body_allowed = !plain_connect,
        .consumed = 0,
        .qpack_section_acknowledgments = @intFromBool(decoded.requires_acknowledgment),
    };
}

pub fn decodeResponseHeadWithDynamicTable(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    settings: Settings,
    table: Qpack.DynamicTable,
) Error!DecodedResponseHead {
    var offset: usize = 0;
    var acknowledgments: usize = 0;
    while (true) {
        const frame = try firstHeadersFrame(bytes[offset..], .response);
        var head = try decodeResponseHeadFieldSectionWithDynamicTable(
            allocator,
            frame.value.payload,
            settings,
            table,
        );
        acknowledgments += head.qpack_section_acknowledgments;
        offset += frame.consumed;
        if (head.status < 200) {
            head.deinit(allocator);
            if (offset >= bytes.len) return error.BufferTooShort;
            continue;
        }
        head.consumed = offset;
        head.qpack_section_acknowledgments = acknowledgments;
        return head;
    }
}

pub fn decodeResponseHeadFieldSectionWithDynamicTable(
    allocator: std.mem.Allocator,
    field_section: []const u8,
    settings: Settings,
    table: Qpack.DynamicTable,
) Error!DecodedResponseHead {
    const field_decoder = FieldSectionDecoder{ .dynamic = table };
    const decoded = try field_decoder.decode(allocator, field_section);
    errdefer Qpack.freeDecodedFields(allocator, decoded.fields);
    try validateHeaderBlock(decoded.fields, .response);
    try validateFieldSectionSize(
        decoded.fields,
        settings.max_field_section_size,
    );
    const status = try responseStatus(decoded.fields);
    const declared_length = try contentLength(decoded.fields);
    if (status == 204 and declared_length != null) {
        return error.InvalidContentLength;
    }
    const owned_fields = try ownHeaderFields(allocator, decoded.fields);
    Qpack.freeDecodedFields(allocator, decoded.fields);
    return .{
        .status = status,
        .headers = owned_fields,
        .content_length = declared_length,
        .body_allowed = status != 204 and status != 304,
        .consumed = 0,
        .qpack_section_acknowledgments = @intFromBool(decoded.requires_acknowledgment),
    };
}

const FirstHeaders = struct {
    value: Frame,
    consumed: usize,
};

fn firstHeadersFrame(
    bytes: []const u8,
    kind: MessageStreamKind,
) Error!FirstHeaders {
    var offset: usize = 0;
    while (true) {
        const frame = try Frame.parse(bytes[offset..]);
        offset += frame.consumed;
        if (frame.frame_type == FrameType.headers) {
            return .{ .value = frame, .consumed = offset };
        }
        if (frame.frame_type == FrameType.push_promise) {
            if (kind == .request) return error.ExpectedHeadersFrame;
            _ = try parsePushPromisePayload(frame.payload);
        } else if (frame.frame_type == FrameType.data or
            requestStreamForbiddenFrame(frame.frame_type))
        {
            return error.ExpectedHeadersFrame;
        }
        if (offset >= bytes.len) return error.BufferTooShort;
    }
}

fn ownHeaderFields(
    allocator: std.mem.Allocator,
    fields: []const Qpack.HeaderField,
) std.mem.Allocator.Error![]Qpack.HeaderField {
    const owned = try allocator.alloc(Qpack.HeaderField, fields.len);
    var initialized: usize = 0;
    errdefer {
        for (owned[0..initialized]) |field| {
            if (field.name_storage) |storage| allocator.free(storage);
            if (field.value_storage) |storage| allocator.free(storage);
        }
        allocator.free(owned);
    }
    for (fields, owned) |field, *destination| {
        const name = try allocator.dupe(u8, field.name);
        errdefer allocator.free(name);
        const value = try allocator.dupe(u8, field.value);
        destination.* = .{
            .name = name,
            .value = value,
            .never_indexed = field.never_indexed,
            .name_storage = name,
            .value_storage = value,
        };
        initialized += 1;
    }
    return owned;
}

fn ownedFieldValue(
    fields: []const Qpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, name)) return field.value;
    }
    return null;
}

fn ownedFieldValueCaseInsensitive(
    fields: []const Qpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (fields) |field| {
        if (std.ascii.eqlIgnoreCase(field.name, name)) return field.value;
    }
    return null;
}

pub fn decodeRequest(allocator: std.mem.Allocator, bytes: []const u8) Error!DecodedRequest {
    // `decodeRequest` is the codec-level entry point and intentionally does
    // not assume a SETTINGS exchange has happened. Negotiated runtime paths
    // call `decodeRequestWithSettings`, which enforces advertised features such
    // as RFC 9220 extended CONNECT.
    return decodeRequestWithOptions(allocator, bytes, .{}, false, .literal);
}

pub fn decodeRequestWithSettings(allocator: std.mem.Allocator, bytes: []const u8, settings: Settings) Error!DecodedRequest {
    return decodeRequestWithOptions(allocator, bytes, settings, true, .literal);
}

pub fn decodeRequestWithDynamicTable(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    settings: Settings,
    table: Qpack.DynamicTable,
) Error!DecodedRequest {
    return decodeRequestWithOptions(allocator, bytes, settings, true, .{ .dynamic = table });
}

fn decodeRequestWithOptions(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    settings: Settings,
    enforce_extended_connect_setting: bool,
    field_decoder: FieldSectionDecoder,
) Error!DecodedRequest {
    var message = try decodeMessage(
        allocator,
        bytes,
        .request,
        settings.max_field_section_size,
        field_decoder,
    );
    errdefer message.deinit(allocator);

    try validateHeaderBlock(message.headers, .request);
    try validateHeaderBlock(message.trailers, .trailers);
    try validateRequestBodyForMethod(message.headers, message.body, message.trailers);
    try validateContentLength(message.headers, message.body.len);

    var method: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var scheme: ?[]const u8 = null;
    var authority: ?[]const u8 = null;
    for (message.headers) |header| {
        if (std.mem.eql(u8, header.name, ":method")) {
            method = header.value;
        } else if (std.mem.eql(u8, header.name, ":path")) {
            path = header.value;
        } else if (std.mem.eql(u8, header.name, ":scheme")) {
            scheme = header.value;
        } else if (std.mem.eql(u8, header.name, ":authority")) {
            authority = header.value;
        } else if (std.ascii.eqlIgnoreCase(header.name, "host") and authority == null) {
            authority = header.value;
        }
    }
    const method_value = method orelse return error.MissingMethod;
    const has_protocol = requestHasProtocolPseudo(message.headers);
    if (enforce_extended_connect_setting and has_protocol and !settings.enable_connect_protocol) {
        return error.ExtendedConnectDisabled;
    }
    const plain_connect = std.mem.eql(u8, method_value, "CONNECT") and !has_protocol;

    return .{
        .method = method_value,
        .path = path orelse if (plain_connect) "" else return error.MissingPath,
        .scheme = scheme orelse if (plain_connect) "" else return error.InvalidHeader,
        .authority = authority,
        .headers = message.headers,
        .trailers = message.trailers,
        .body = message.body,
        .body_storage = message.body_storage,
        .consumed = message.consumed,
        .qpack_section_acknowledgments = message.qpack_section_acknowledgments,
    };
}

pub fn decodeResponse(allocator: std.mem.Allocator, bytes: []const u8) Error!DecodedResponse {
    return decodeResponseWithSettings(allocator, bytes, .{});
}

pub fn decodeResponseWithSettings(allocator: std.mem.Allocator, bytes: []const u8, settings: Settings) Error!DecodedResponse {
    return decodeResponseWithFieldDecoder(allocator, bytes, settings, .literal);
}

pub fn decodeResponseWithDynamicTable(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    settings: Settings,
    table: Qpack.DynamicTable,
) Error!DecodedResponse {
    return decodeResponseWithFieldDecoder(
        allocator,
        bytes,
        settings,
        .{ .dynamic = table },
    );
}

fn decodeResponseWithFieldDecoder(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    settings: Settings,
    field_decoder: FieldSectionDecoder,
) Error!DecodedResponse {
    var message = try decodeResponseMessage(
        allocator,
        bytes,
        settings.max_field_section_size,
        field_decoder,
    );
    errdefer message.deinit(allocator);

    try validateHeaderBlock(message.headers, .response);
    try validateHeaderBlock(message.trailers, .trailers);

    const final_status = try responseStatus(message.headers);
    try validateResponseBodyForStatus(final_status, message.headers, message.body, message.trailers);
    try validateContentLengthForStatus(final_status, message.headers, message.body.len);

    return .{
        .status = final_status,
        .headers = message.headers,
        .trailers = message.trailers,
        .body = message.body,
        .body_storage = message.body_storage,
        .consumed = message.consumed,
        .qpack_section_acknowledgments = message.qpack_section_acknowledgments,
    };
}

const DecodedMessage = struct {
    headers: []Qpack.HeaderField,
    trailers: []Qpack.HeaderField = &.{},
    body: []const u8,
    body_storage: ?[]u8 = null,
    consumed: usize,
    qpack_section_acknowledgments: usize = 0,

    fn deinit(self: *DecodedMessage, allocator: std.mem.Allocator) void {
        Qpack.freeDecodedFields(allocator, self.headers);
        Qpack.freeDecodedFields(allocator, self.trailers);
        if (self.body_storage) |body| allocator.free(body);
        self.* = undefined;
    }
};

const MessageStreamKind = enum {
    request,
    response,
};

const DecodedFieldSection = struct {
    fields: []Qpack.HeaderField,
    requires_acknowledgment: bool = false,
};

const FieldSectionDecoder = union(enum) {
    literal,
    dynamic: Qpack.DynamicTable,

    fn decode(
        self: FieldSectionDecoder,
        allocator: std.mem.Allocator,
        payload: []const u8,
    ) Error!DecodedFieldSection {
        return switch (self) {
            .literal => .{ .fields = try Qpack.decodeLiteralBlock(allocator, payload) },
            .dynamic => |table| blk: {
                const decoded = try Qpack.decodeDynamicBlock(allocator, payload, table);
                break :blk .{
                    .fields = decoded.fields,
                    .requires_acknowledgment = decoded.required_insert_count != 0,
                };
            },
        };
    }
};

fn writeHeadersFrame(list: *std.ArrayList(u8), allocator: std.mem.Allocator, fields: []const Qpack.HeaderField) Error!void {
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try Qpack.encodeLiteralBlock(&block, allocator, fields);
    try (Frame{ .frame_type = FrameType.headers, .payload = block.items, .consumed = 0 }).write(list, allocator);
}

fn writeHeadersFrameDynamic(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    fields: []const Qpack.HeaderField,
    stream_id: u64,
    encoder: anytype,
) Error!void {
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try encoder.encodeFieldSection(&block, stream_id, fields);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(list, allocator);
}

pub fn writeTrailersDynamic(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    trailers: []const Qpack.HeaderField,
    peer_settings: Settings,
    stream_id: u64,
    encoder: anytype,
) Error!void {
    if (trailers.len == 0) return error.InvalidHeader;
    try validateHeaderBlock(trailers, .trailers);
    try validateFieldSectionSize(
        trailers,
        peer_settings.max_field_section_size,
    );
    try writeHeadersFrameDynamic(
        list,
        allocator,
        trailers,
        stream_id,
        encoder,
    );
    try queueIndexableFields(encoder, trailers);
}

fn writeHeadersAndData(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    fields: []const Qpack.HeaderField,
    body: []const u8,
    trailers: []const Qpack.HeaderField,
) Error!void {
    try writeHeadersFrame(list, allocator, fields);
    if (body.len > 0) {
        try (Frame{ .frame_type = FrameType.data, .payload = body, .consumed = 0 }).write(list, allocator);
    }
    if (trailers.len > 0) {
        try writeHeadersFrame(list, allocator, trailers);
    }
}

fn writeHeadersAndDataDynamic(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    fields: []const Qpack.HeaderField,
    body: []const u8,
    trailers: []const Qpack.HeaderField,
    stream_id: u64,
    encoder: anytype,
) Error!void {
    try writeHeadersFrameDynamic(list, allocator, fields, stream_id, encoder);
    if (body.len > 0) {
        try (Frame{
            .frame_type = FrameType.data,
            .payload = body,
            .consumed = 0,
        }).write(list, allocator);
    }
    if (trailers.len > 0) {
        try writeHeadersFrameDynamic(
            list,
            allocator,
            trailers,
            stream_id,
            encoder,
        );
    }
}

fn queueIndexableFields(encoder: anytype, fields: []const Qpack.HeaderField) !void {
    for (fields) |field| {
        if (!qpackShouldIndex(field)) continue;
        if (encoder.table.findExact(field.name, field.value) != null) continue;
        _ = try encoder.insertField(field.name, field.value);
    }
}

fn qpackShouldIndex(field: Qpack.HeaderField) bool {
    if (field.never_indexed) return false;
    if (field.name.len + field.value.len < 8) return false;
    if (std.mem.eql(u8, field.name, "authorization") or
        std.mem.eql(u8, field.name, "proxy-authorization") or
        std.mem.eql(u8, field.name, "cookie") or
        std.mem.eql(u8, field.name, "set-cookie"))
    {
        return false;
    }
    return true;
}

fn requestStreamForbiddenFrame(frame_type: u64) bool {
    return switch (frame_type) {
        FrameType.cancel_push,
        FrameType.settings,
        FrameType.goaway,
        FrameType.max_push_id,
        FrameType.priority_update_request,
        FrameType.priority_update_push,
        => true,
        else => false,
    };
}

fn responseStatus(headers: []const Qpack.HeaderField) Error!u16 {
    for (headers) |header| {
        if (!std.mem.eql(u8, header.name, ":status")) continue;
        if (header.value.len != 3) return error.InvalidStatus;
        for (header.value) |byte| {
            if (!std.ascii.isDigit(byte)) return error.InvalidStatus;
        }
        const status = std.fmt.parseInt(u16, header.value, 10) catch return error.InvalidStatus;
        if (status < 100 or status > 999) return error.InvalidStatus;
        return status;
    }
    return error.MissingStatus;
}

fn decodeResponseMessage(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    max_field_section_size: u64,
    field_decoder: FieldSectionDecoder,
) Error!DecodedMessage {
    var offset: usize = 0;
    var informational_acknowledgments: usize = 0;
    while (true) {
        const frame = try Frame.parse(bytes[offset..]);
        if (frame.frame_type != FrameType.headers) {
            if (frame.frame_type == FrameType.data or requestStreamForbiddenFrame(frame.frame_type)) return error.ExpectedHeadersFrame;
            if (frame.frame_type == FrameType.push_promise) _ = try parsePushPromisePayload(frame.payload);
            offset += frame.consumed;
            if (offset >= bytes.len) return error.MissingStatus;
            continue;
        }
        const decoded = try field_decoder.decode(allocator, frame.payload);
        var decoded_owned = true;
        defer if (decoded_owned) Qpack.freeDecodedFields(allocator, decoded.fields);
        try validateHeaderBlock(decoded.fields, .response);
        try validateFieldSectionSize(decoded.fields, max_field_section_size);
        const status = try responseStatus(decoded.fields);
        if (status < 200) {
            informational_acknowledgments += @intFromBool(decoded.requires_acknowledgment);
            Qpack.freeDecodedFields(allocator, decoded.fields);
            decoded_owned = false;
            offset += frame.consumed;
            if (offset >= bytes.len) return error.MissingStatus;
            continue;
        }
        decoded_owned = false;
        var message = try decodeMessageAfterHeaders(
            allocator,
            bytes,
            .response,
            max_field_section_size,
            field_decoder,
            decoded,
            offset + frame.consumed,
        );
        message.qpack_section_acknowledgments += informational_acknowledgments;
        return message;
    }
}

fn decodeMessage(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    kind: MessageStreamKind,
    max_field_section_size: u64,
    field_decoder: FieldSectionDecoder,
) Error!DecodedMessage {
    var offset: usize = 0;
    const headers_frame = while (true) {
        const frame = try Frame.parse(bytes[offset..]);
        if (frame.frame_type == FrameType.headers) break frame;
        if (frame.frame_type == FrameType.push_promise) {
            if (kind == .request) return error.ExpectedHeadersFrame;
            _ = try parsePushPromisePayload(frame.payload);
            offset += frame.consumed;
            if (offset >= bytes.len) return error.ExpectedHeadersFrame;
            continue;
        }
        if (frame.frame_type == FrameType.data or requestStreamForbiddenFrame(frame.frame_type)) return error.ExpectedHeadersFrame;
        // RFC 9114 allows unknown extension frames on request streams.  Like
        // tquic's request-stream state machine, ignore them before the first
        // HEADERS rather than treating every non-HEADERS frame as fatal.
        offset += frame.consumed;
        if (offset >= bytes.len) return error.ExpectedHeadersFrame;
    };
    const decoded_headers = try field_decoder.decode(allocator, headers_frame.payload);
    var headers_owned = true;
    errdefer if (headers_owned) Qpack.freeDecodedFields(allocator, decoded_headers.fields);
    try validateFieldSectionSize(decoded_headers.fields, max_field_section_size);
    headers_owned = false;
    return decodeMessageAfterHeaders(
        allocator,
        bytes,
        kind,
        max_field_section_size,
        field_decoder,
        decoded_headers,
        offset + headers_frame.consumed,
    );
}

fn decodeMessageAfterHeaders(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    kind: MessageStreamKind,
    max_field_section_size: u64,
    field_decoder: FieldSectionDecoder,
    decoded_headers: DecodedFieldSection,
    initial_consumed: usize,
) Error!DecodedMessage {
    errdefer Qpack.freeDecodedFields(allocator, decoded_headers.fields);
    var consumed = initial_consumed;
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);
    var trailers: []Qpack.HeaderField = &.{};
    errdefer Qpack.freeDecodedFields(allocator, trailers);
    var saw_trailers = false;
    var qpack_section_acknowledgments: usize =
        @intFromBool(decoded_headers.requires_acknowledgment);
    while (consumed < bytes.len) {
        const frame = try Frame.parse(bytes[consumed..]);
        consumed += frame.consumed;
        switch (frame.frame_type) {
            FrameType.data => {
                if (saw_trailers) return error.UnexpectedFrame;
                try body.appendSlice(allocator, frame.payload);
            },
            FrameType.headers => {
                if (saw_trailers) return error.UnexpectedFrame;
                const decoded_trailers = try field_decoder.decode(allocator, frame.payload);
                errdefer Qpack.freeDecodedFields(allocator, decoded_trailers.fields);
                try validateFieldSectionSize(decoded_trailers.fields, max_field_section_size);
                trailers = decoded_trailers.fields;
                qpack_section_acknowledgments +=
                    @intFromBool(decoded_trailers.requires_acknowledgment);
                saw_trailers = true;
            },
            FrameType.push_promise => {
                if (kind == .request or saw_trailers) return error.UnexpectedFrame;
                _ = try parsePushPromisePayload(frame.payload);
            },
            else => if (requestStreamForbiddenFrame(frame.frame_type)) return error.UnexpectedFrame,
        }
    }

    const body_storage: ?[]u8 = if (body.items.len == 0) storage: {
        body.deinit(allocator);
        break :storage null;
    } else try body.toOwnedSlice(allocator);

    return .{
        .headers = decoded_headers.fields,
        .trailers = trailers,
        .body = if (body_storage) |storage| storage else &.{},
        .body_storage = body_storage,
        .consumed = consumed,
        .qpack_section_acknowledgments = qpack_section_acknowledgments,
    };
}

fn appendHeaderField(out: []Qpack.HeaderField, count: *usize, field: Qpack.HeaderField) Error!void {
    if (count.* >= out.len) return error.InvalidFrame;
    out[count.*] = field;
    count.* += 1;
}

fn validateFieldSectionSize(headers: []const Qpack.HeaderField, max_field_section_size: u64) Error!void {
    var size: u64 = 0;
    for (headers) |header| {
        size = std.math.add(u64, size, header.name.len) catch return error.ExcessiveLoad;
        size = std.math.add(u64, size, header.value.len) catch return error.ExcessiveLoad;
        // RFC 9114 §4.2.2 carries over the HTTP/2/QPACK accounting rule: the
        // field section size is the uncompressed name/value bytes plus 32 bytes
        // per field.  Enforce the advertised limit after decoding so compressed
        // representations cannot bypass SETTINGS_MAX_FIELD_SECTION_SIZE.
        size = std.math.add(u64, size, 32) catch return error.ExcessiveLoad;
        if (size > max_field_section_size) return error.ExcessiveLoad;
    }
}

fn contentLength(headers: []const Qpack.HeaderField) Error!?usize {
    var found: ?usize = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "content-length")) continue;
        var parts = std.mem.splitScalar(u8, header.value, ',');
        while (parts.next()) |raw_part| {
            const part = std.mem.trim(u8, raw_part, " \t");
            if (part.len == 0) return error.InvalidContentLength;
            for (part) |byte| {
                if (!std.ascii.isDigit(byte)) return error.InvalidContentLength;
            }
            const parsed = std.fmt.parseInt(usize, part, 10) catch return error.InvalidContentLength;
            if (found) |existing| {
                if (existing != parsed) return error.InvalidContentLength;
            } else {
                found = parsed;
            }
        }
    }
    return found;
}

fn validateRequestBodyForMethod(headers: []const Qpack.HeaderField, body: []const u8, trailers: []const Qpack.HeaderField) Error!void {
    var method: ?[]const u8 = null;
    var has_protocol = false;
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, ":method")) method = header.value;
        if (std.mem.eql(u8, header.name, ":protocol")) has_protocol = true;
    }
    if (method) |value| {
        if (std.mem.eql(u8, value, "CONNECT") and !has_protocol) {
            if (body.len != 0 or trailers.len != 0) return error.InvalidContentLength;
            if ((try contentLength(headers)) != null) return error.InvalidContentLength;
        }
    }
}

fn validateContentLength(headers: []const Qpack.HeaderField, actual: usize) Error!void {
    if (try contentLength(headers)) |expected| {
        if (expected != actual) return error.InvalidContentLength;
    }
}

fn validateContentLengthForStatus(status: u16, headers: []const Qpack.HeaderField, actual: usize) Error!void {
    if (try contentLength(headers)) |expected| {
        if (status == 304 and actual == 0) return;
        if (expected != actual) return error.InvalidContentLength;
    }
}

fn validateResponseBodyForStatus(
    status: u16,
    headers: []const Qpack.HeaderField,
    body: []const u8,
    trailers: []const Qpack.HeaderField,
) Error!void {
    if (!((status >= 100 and status < 200) or status == 204 or status == 304)) return;
    if (body.len != 0 or trailers.len != 0) return error.InvalidContentLength;
    const declared_content_length = try contentLength(headers);
    if (status != 304 and declared_content_length != null) return error.InvalidContentLength;
}

const HeaderBlockKind = enum {
    request,
    response,
    trailers,
};

fn validateHeaderBlock(headers: []const Qpack.HeaderField, kind: HeaderBlockKind) Error!void {
    var saw_regular = false;
    var seen_method = false;
    var seen_scheme = false;
    var seen_path = false;
    var seen_authority = false;
    var seen_protocol = false;
    var seen_status = false;
    var method_value: ?[]const u8 = null;
    var scheme_value: ?[]const u8 = null;
    var path_value: ?[]const u8 = null;
    var authority_value: ?[]const u8 = null;
    var protocol_value: ?[]const u8 = null;
    var host_value: ?[]const u8 = null;

    for (headers) |header| {
        try validateHeaderName(header.name);
        try validateHeaderValue(header.value);
        const pseudo = std.mem.startsWith(u8, header.name, ":");
        if (pseudo) {
            if (saw_regular) return error.InvalidHeader;
            switch (kind) {
                .request => {
                    try markRequestPseudo(header.name, &seen_method, &seen_scheme, &seen_path, &seen_authority, &seen_protocol);
                    if (std.mem.eql(u8, header.name, ":method")) method_value = header.value;
                    if (std.mem.eql(u8, header.name, ":scheme")) scheme_value = header.value;
                    if (std.mem.eql(u8, header.name, ":path")) path_value = header.value;
                    if (std.mem.eql(u8, header.name, ":authority")) authority_value = header.value;
                    if (std.mem.eql(u8, header.name, ":protocol")) protocol_value = header.value;
                },
                .response => {
                    try markResponsePseudo(header.name, &seen_status);
                    if (std.mem.eql(u8, header.name, ":status")) {
                        if (header.value.len != 3) return error.InvalidStatus;
                        for (header.value) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidStatus;
                        const parsed_status = std.fmt.parseInt(u16, header.value, 10) catch return error.InvalidStatus;
                        if (parsed_status < 100) return error.InvalidStatus;
                        if (parsed_status == 101) return error.InvalidStatus;
                    }
                },
                .trailers => return error.InvalidHeader,
            }
            continue;
        }
        saw_regular = true;

        if (kind == .trailers and forbiddenTrailerFieldName(header.name)) return error.InvalidHeader;
        if (std.mem.eql(u8, header.name, "host")) {
            if (host_value != null) return error.InvalidHeader;
            host_value = header.value;
        }
        if (connectionSpecificHeaderName(header.name)) return error.InvalidHeader;
        if (std.ascii.eqlIgnoreCase(header.name, "te")) {
            switch (kind) {
                .request => if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, header.value, " \t"), "trailers")) return error.InvalidHeader,
                .response, .trailers => return error.InvalidHeader,
            }
        }
    }

    switch (kind) {
        .request => {
            const method = method_value orelse return error.MissingMethod;
            try validateHttpToken(method);
            const is_connect = std.mem.eql(u8, method, "CONNECT");
            if (is_connect and !seen_protocol) {
                // RFC 9114 preserves the HTTP CONNECT authority-form special
                // case: traditional CONNECT carries :method and :authority, but
                // omits :scheme and :path. Extended CONNECT (:protocol present)
                // falls through to the regular request-target requirements.
                if (!seen_authority or seen_scheme or seen_path) return error.InvalidHeader;
                try validateConnectAuthority(authority_value orelse return error.InvalidHeader);
                return;
            }
            if (seen_protocol) {
                try validateHttpToken(protocol_value orelse return error.InvalidHeader);
                if (!is_connect) return error.InvalidHeader;
            }
            const scheme = scheme_value orelse return error.InvalidHeader;
            try validateUriScheme(scheme);
            const path = path_value orelse return error.MissingPath;
            try validateUriPath(method, path);
            if (authority_value) |authority| try validateRequestAuthority(authority);
            if (host_value) |host| try validateRequestAuthority(host);
            if (authority_value) |authority| {
                if (host_value) |host| {
                    if (!std.ascii.eqlIgnoreCase(authority, host)) return error.InvalidHeader;
                }
            }
            if ((std.mem.eql(u8, scheme, "http") or std.mem.eql(u8, scheme, "https")) and
                ((authority_value == null or authority_value.?.len == 0) and host_value == null))
            {
                return error.InvalidHeader;
            }
        },
        .response => if (!seen_status) return error.MissingStatus,
        .trailers => {},
    }
}

fn validateHttpToken(value: []const u8) Error!void {
    if (value.len == 0) return error.InvalidHeader;
    for (value) |byte| {
        if (!isHttpTchar(byte)) return error.InvalidHeader;
    }
}

fn isHttpTchar(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or switch (byte) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

fn validateUriScheme(scheme: []const u8) Error!void {
    if (scheme.len == 0) return error.InvalidHeader;
    if (!std.ascii.isAlphabetic(scheme[0])) return error.InvalidHeader;
    for (scheme[1..]) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or byte == '+' or byte == '-' or byte == '.')) return error.InvalidHeader;
    }
}

fn validateUriPath(method: []const u8, path: []const u8) Error!void {
    if (path.len == 0) return error.InvalidHeader;
    if (std.mem.eql(u8, path, "*")) {
        if (!std.mem.eql(u8, method, "OPTIONS")) return error.InvalidHeader;
        return;
    }
    if (path[0] != '/') return error.InvalidHeader;
    var saw_fragment = false;
    for (path) |byte| {
        if (byte <= 0x20 or byte == 0x7f or byte == '\\') return error.InvalidHeader;
        if (byte == '#') saw_fragment = true;
    }
    if (saw_fragment) return error.InvalidHeader;
}

fn validateRequestAuthority(authority: []const u8) Error!void {
    if (authority.len == 0) return error.InvalidHeader;
    for (authority) |byte| {
        if (byte <= 0x20 or byte == 0x7f or byte == '/' or byte == '\\' or byte == '?' or byte == '#' or byte == '@') return error.InvalidHeader;
    }
    if (authority[0] == '[') {
        const end = std.mem.indexOfScalar(u8, authority, ']') orelse return error.InvalidHeader;
        if (end <= 1) return error.InvalidHeader;
        if (end + 1 < authority.len and authority[end + 1] != ':') return error.InvalidHeader;
        if (end + 1 == authority.len) return;
        try validateAuthorityPort(authority[end + 2 ..]);
        return;
    }
    if (std.mem.indexOfScalar(u8, authority, '[') != null or std.mem.indexOfScalar(u8, authority, ']') != null) return error.InvalidHeader;
    if (std.mem.indexOfScalar(u8, authority, ':')) |colon| {
        if (colon == 0) return error.InvalidHeader;
        if (std.mem.indexOfScalar(u8, authority[colon + 1 ..], ':') != null) return error.InvalidHeader;
        try validateAuthorityPort(authority[colon + 1 ..]);
    }
}

fn validateConnectAuthority(authority: []const u8) Error!void {
    try validateRequestAuthority(authority);
    const port: []const u8 = if (authority[0] == '[') blk: {
        const end = std.mem.indexOfScalar(u8, authority, ']') orelse return error.InvalidHeader;
        if (end <= 1 or end + 2 > authority.len or authority[end + 1] != ':') return error.InvalidHeader;
        break :blk authority[end + 2 ..];
    } else blk: {
        const colon = std.mem.lastIndexOfScalar(u8, authority, ':') orelse return error.InvalidHeader;
        if (colon == 0 or colon + 1 >= authority.len) return error.InvalidHeader;
        if (std.mem.indexOfScalar(u8, authority[0..colon], ':') != null) return error.InvalidHeader;
        break :blk authority[colon + 1 ..];
    };
    try validateAuthorityPort(port);
}

fn validateAuthorityPort(port: []const u8) Error!void {
    if (port.len == 0) return error.InvalidHeader;
    for (port) |byte| {
        if (!std.ascii.isDigit(byte)) return error.InvalidHeader;
    }
    const parsed_port = std.fmt.parseInt(u32, port, 10) catch return error.InvalidHeader;
    if (parsed_port > std.math.maxInt(u16)) return error.InvalidHeader;
}

fn validateHeaderName(name: []const u8) Error!void {
    if (name.len == 0) return error.InvalidHeader;
    if (name[0] == ':') {
        if (name.len == 1) return error.InvalidHeader;
        for (name[1..]) |byte| {
            if (!validHeaderNameByte(byte)) return error.InvalidHeader;
        }
        return;
    }
    for (name) |byte| {
        if (!validHeaderNameByte(byte)) return error.InvalidHeader;
    }
}

fn validateHeaderValue(value: []const u8) Error!void {
    for (value) |byte| {
        if ((byte < 0x20 and byte != '\t') or byte == 0x7f) return error.InvalidHeader;
    }
}

fn validHeaderNameByte(byte: u8) bool {
    if (byte >= 'A' and byte <= 'Z') return false;
    return std.ascii.isLower(byte) or std.ascii.isDigit(byte) or switch (byte) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

fn markRequestPseudo(
    name: []const u8,
    seen_method: *bool,
    seen_scheme: *bool,
    seen_path: *bool,
    seen_authority: *bool,
    seen_protocol: *bool,
) Error!void {
    if (std.mem.eql(u8, name, ":method")) return markOnce(seen_method);
    if (std.mem.eql(u8, name, ":scheme")) return markOnce(seen_scheme);
    if (std.mem.eql(u8, name, ":path")) return markOnce(seen_path);
    if (std.mem.eql(u8, name, ":authority")) return markOnce(seen_authority);
    if (std.mem.eql(u8, name, ":protocol")) return markOnce(seen_protocol);
    return error.InvalidHeader;
}

fn markResponsePseudo(name: []const u8, seen_status: *bool) Error!void {
    if (std.mem.eql(u8, name, ":status")) return markOnce(seen_status);
    return error.InvalidHeader;
}

fn markOnce(seen: *bool) Error!void {
    if (seen.*) return error.InvalidHeader;
    seen.* = true;
}

fn forbiddenTrailerFieldName(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "authorization") or
        std.ascii.eqlIgnoreCase(name, "cache-control") or
        std.ascii.eqlIgnoreCase(name, "content-encoding") or
        std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "content-range") or
        std.ascii.eqlIgnoreCase(name, "content-type") or
        std.ascii.eqlIgnoreCase(name, "host") or
        std.ascii.eqlIgnoreCase(name, "max-forwards") or
        std.ascii.eqlIgnoreCase(name, "set-cookie") or
        std.ascii.eqlIgnoreCase(name, "trailer") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "te");
}

fn connectionSpecificHeaderName(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "connection") or
        std.ascii.eqlIgnoreCase(name, "keep-alive") or
        std.ascii.eqlIgnoreCase(name, "proxy-connection") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "upgrade") or
        std.ascii.eqlIgnoreCase(name, "http2-settings");
}

pub const Datagram = struct {
    quarter_stream_id: u64,
    payload: []const u8,

    pub fn parse(bytes: []const u8) Error!Datagram {
        var cursor = wire.Cursor.init(bytes);
        const quarter_stream_id = try quic.varint.decode(&cursor);
        return .{ .quarter_stream_id = quarter_stream_id, .payload = bytes[cursor.pos..] };
    }

    pub fn write(self: Datagram, list: *std.ArrayList(u8), allocator: std.mem.Allocator) !void {
        try quic.varint.encode(list, allocator, self.quarter_stream_id);
        try list.appendSlice(allocator, self.payload);
    }
};

test "HTTP/3 parses Alt-Svc HTTP/3 advertisements" {
    const robotics = try firstHttp3AltSvc("h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("h3", robotics.alpn);
    try std.testing.expectEqualStrings(":443", robotics.authority);
    try std.testing.expectEqual(@as(?u16, 443), robotics.port);
    try std.testing.expectEqual(@as(?u64, 2_592_000), robotics.max_age);

    const draft = try firstHttp3AltSvc(" h2=\":443\"; ma=60, h3-29=\"alt.example:8443\"; ma=120 ") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("h3-29", draft.alpn);
    try std.testing.expectEqualStrings("alt.example:8443", draft.authority);
    try std.testing.expectEqual(@as(?u16, 8443), draft.port);
    try std.testing.expectEqual(@as(?u64, 120), draft.max_age);

    const ipv6 = try firstHttp3AltSvc("h3=\"[2001:db8::1]:443\"") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("[2001:db8::1]:443", ipv6.authority);
    try std.testing.expectEqual(@as(?u16, 443), ipv6.port);

    try std.testing.expect((try firstHttp3AltSvc("clear")) == null);
    try std.testing.expect((try firstHttp3AltSvc("h2=\":443\"")) == null);

    const headers = [_]Qpack.HeaderField{
        .{ .name = "server", .value = "example" },
        .{ .name = "Alt-Svc", .value = "h2=\":443\", h3=\":8443\"; ma=30" },
    };
    const from_headers = try firstHttp3AltSvcHeader(&headers) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("h3", from_headers.alpn);
    try std.testing.expectEqual(@as(?u16, 8443), from_headers.port);

    const robotics_target = try altSvcTarget("robotics.bytedance.com", robotics, 443);
    try std.testing.expectEqualStrings("robotics.bytedance.com", robotics_target.connect_host);
    try std.testing.expectEqualStrings("robotics.bytedance.com", robotics_target.origin_host);
    try std.testing.expectEqual(@as(u16, 443), robotics_target.port);

    const header_target = try firstHttp3AltSvcTarget("example.com", &headers, 443) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("example.com", header_target.origin_host);
    try std.testing.expectEqualStrings("example.com", header_target.connect_host);
    try std.testing.expectEqual(@as(u16, 8443), header_target.port);

    const ipv6_target = try altSvcTarget("[2001:db8::2]", ipv6, 443);
    try std.testing.expectEqualStrings("2001:db8::2", ipv6_target.origin_host);
    try std.testing.expectEqualStrings("2001:db8::1", ipv6_target.connect_host);
    try std.testing.expectEqual(@as(u16, 443), ipv6_target.port);

    try std.testing.expectError(error.InvalidHeader, altSvcTarget("bad/host", robotics, 443));
    try std.testing.expectError(error.InvalidHeader, firstHttp3AltSvc("h3=\"\""));
    try std.testing.expectError(error.InvalidHeader, firstHttp3AltSvc("h3=\":bad\""));
    try std.testing.expectError(error.InvalidHeader, firstHttp3AltSvc("h3=\"example.com/evil\""));
    try std.testing.expectError(error.InvalidHeader, firstHttp3AltSvc("h3=\":443\"; ma=bad"));
}

test "HTTP/3 normalizes request origins for reuse policy" {
    const https_default = try requestOrigin("https", "Example.COM");
    try std.testing.expectEqualStrings("https", https_default.scheme);
    try std.testing.expectEqualStrings("Example.COM", https_default.host);
    try std.testing.expectEqual(@as(u16, 443), https_default.port);

    const explicit_https = try requestOrigin("https", "example.com:443");
    try std.testing.expect(sameOrigin(https_default, explicit_https));

    const different_port = try requestOrigin("https", "example.com:8443");
    try std.testing.expect(!sameOrigin(https_default, different_port));

    const ipv6 = try requestOrigin("https", "[2001:db8::1]:443");
    try std.testing.expectEqualStrings("2001:db8::1", ipv6.host);
    try std.testing.expectEqual(@as(u16, 443), ipv6.port);

    const http_default = try requestOrigin("http", "example.com");
    try std.testing.expectEqual(@as(u16, 80), http_default.port);
    try std.testing.expect(!sameOrigin(https_default, http_default));

    try std.testing.expectError(error.InvalidHeader, requestOrigin("ftp", "example.com"));
    try std.testing.expectError(error.InvalidHeader, requestOrigin("https", "user@example.com"));
    try std.testing.expectError(error.InvalidHeader, requestOrigin("https", "example.com:bad"));
}

test "HTTP/3 frame settings and qpack literal block" {
    const allocator = std.testing.allocator;
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    const settings = [_]Setting{
        .{ .id = @intFromEnum(SettingId.h3_datagram), .value = 1 },
        .{ .id = @intFromEnum(SettingId.webtransport_max_sessions), .value = 16 },
    };
    try writeSettings(&payload, allocator, &settings);

    var encoded_frame: std.ArrayList(u8) = .empty;
    defer encoded_frame.deinit(allocator);
    try (Frame{ .frame_type = FrameType.settings, .payload = payload.items, .consumed = 0 }).write(&encoded_frame, allocator);
    const frame = try Frame.parse(encoded_frame.items);
    const parsed_settings = try parseSettings(allocator, frame.payload);
    defer allocator.free(parsed_settings);
    try std.testing.expectEqual(@as(u64, 1), parsed_settings[0].value);
    try std.testing.expectError(error.UnexpectedFrame, (Frame{
        .frame_type = 0x02, // HTTP/2 PRIORITY is reserved in HTTP/3.
        .payload = &.{},
        .consumed = 0,
    }).write(&encoded_frame, allocator));

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    const fields = [_]Qpack.HeaderField{ .{ .name = ":method", .value = "GET" }, .{ .name = ":path", .value = "/" } };
    try Qpack.encodeLiteralBlock(&block, allocator, &fields);
    try std.testing.expectEqual(@as(u8, 0xd1), block.items[2]); // static index 17, :method GET
    try std.testing.expectEqual(@as(u8, 0xc1), block.items[3]); // static index 1, :path /
    const decoded = try Qpack.decodeLiteralBlock(allocator, block.items);
    defer Qpack.freeDecodedFields(allocator, decoded);
    try std.testing.expectEqualStrings(":method", decoded[0].name);
    try std.testing.expectEqualStrings("GET", decoded[0].value);
}

test "HTTP/3 frame header parses before payload arrives" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try quic.varint.encode(&encoded, allocator, FrameType.data);
    try quic.varint.encode(&encoded, allocator, 1_000_000);

    const header = try Frame.parseHeader(encoded.items);
    try std.testing.expectEqual(FrameType.data, header.frame_type);
    try std.testing.expectEqual(@as(usize, 1_000_000), header.payload_length);
    try std.testing.expectEqual(encoded.items.len, header.header_length);
    try std.testing.expectEqual(
        encoded.items.len + 1_000_000,
        try header.totalLength(),
    );
    try std.testing.expectError(
        error.BufferTooShort,
        Frame.parse(encoded.items),
    );

    for (0..encoded.items.len) |len| {
        try std.testing.expectError(
            error.BufferTooShort,
            Frame.parseHeader(encoded.items[0..len]),
        );
    }
}

test "HTTP/3 rejects reserved HTTP/2 frame types" {
    const allocator = std.testing.allocator;
    const reserved_frame_types = [_]u64{ 0x02, 0x06, 0x08, 0x09 };
    for (reserved_frame_types) |frame_type| {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try std.testing.expectError(error.UnexpectedFrame, (Frame{ .frame_type = frame_type, .payload = "", .consumed = 0 }).write(&encoded, allocator));
        try quic.varint.encode(&encoded, allocator, frame_type);
        try quic.varint.encode(&encoded, allocator, 0);
        try std.testing.expectError(error.UnexpectedFrame, Frame.parse(encoded.items));
    }
}

test {
    _ = @import("qpack/tests.zig");
}

test "HTTP/3 priority field and PRIORITY_UPDATE frame" {
    const allocator = std.testing.allocator;
    const parsed = Priority.parse("u=1, foo=bar, i=?1");
    try std.testing.expectEqual(@as(u3, 1), parsed.urgency);
    try std.testing.expect(parsed.incremental);
    var field_buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("u=1, i", parsed.serialize(&field_buf));
    try std.testing.expectEqual(@as(u3, 3), Priority.parse("u=9, i=?0").urgency);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writePriorityUpdateFrame(&encoded, allocator, 8, parsed);
    const frame = try Frame.parse(encoded.items);
    try std.testing.expectEqual(FrameType.priority_update_request, frame.frame_type);
    const payload = try parsePriorityUpdatePayload(frame.payload);
    try std.testing.expectEqual(@as(u64, 8), payload.prioritized_element_id);
    try std.testing.expectEqual(@as(u3, 1), payload.priority().urgency);
    try std.testing.expect(payload.priority().incremental);

    var control = ControlState{};
    defer control.deinit(allocator);
    var settings_payload: std.ArrayList(u8) = .empty;
    defer settings_payload.deinit(allocator);
    try writeControlStreamPrefix(&settings_payload, allocator);
    try writeSettingsFrame(&settings_payload, allocator, .{});
    try control.applyControlStreamBytes(allocator, settings_payload.items);
    try control.applyFrame(allocator, frame);
    try std.testing.expectEqual(@as(u64, 8), control.latest_priority_update.?.prioritized_element_id);
    try std.testing.expectEqual(
        @as(u3, 1),
        control.requestPriorityUpdate(8).?.priority().urgency,
    );

    var second_request: std.ArrayList(u8) = .empty;
    defer second_request.deinit(allocator);
    try writePriorityUpdateFrame(
        &second_request,
        allocator,
        12,
        .{ .urgency = 5 },
    );
    try control.applyFrame(
        allocator,
        try Frame.parse(second_request.items),
    );
    try std.testing.expectEqual(
        @as(u3, 1),
        control.requestPriorityUpdate(8).?.priority().urgency,
    );
    try std.testing.expectEqual(
        @as(u3, 5),
        control.requestPriorityUpdate(12).?.priority().urgency,
    );

    var push_priority: std.ArrayList(u8) = .empty;
    defer push_priority.deinit(allocator);
    try writePushPriorityUpdateFrame(
        &push_priority,
        allocator,
        3,
        .{ .urgency = 2, .incremental = true },
    );
    try control.applyFrame(
        allocator,
        try Frame.parse(push_priority.items),
    );
    try std.testing.expectEqual(
        @as(u3, 2),
        control.pushPriorityUpdate(3).?.priority().urgency,
    );
    try std.testing.expect(
        control.pushPriorityUpdate(3).?.priority().incremental,
    );

    try std.testing.expectError(error.UnexpectedFrame, writePriorityUpdateFrame(&encoded, allocator, 1, parsed));
    var invalid_priority: std.ArrayList(u8) = .empty;
    defer invalid_priority.deinit(allocator);
    try writePriorityUpdateFrameRaw(&invalid_priority, allocator, FrameType.priority_update_request, 1, "u=1");
    const invalid_frame = try Frame.parse(invalid_priority.items);
    try std.testing.expectError(error.UnexpectedFrame, control.applyFrame(allocator, invalid_frame));
}

fn checkPriorityUpdateStateAllocationFailure(
    allocator: std.mem.Allocator,
) !void {
    var control = ControlState{ .settings = .{ .received = true } };
    defer control.deinit(allocator);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writePriorityUpdateFrame(
        &encoded,
        allocator,
        0,
        .{ .urgency = 1 },
    );
    try control.applyFrame(allocator, try Frame.parse(encoded.items));
    encoded.clearRetainingCapacity();
    try writePriorityUpdateFrame(
        &encoded,
        allocator,
        4,
        .{ .urgency = 5, .incremental = true },
    );
    try control.applyFrame(allocator, try Frame.parse(encoded.items));
    encoded.clearRetainingCapacity();
    try writePriorityUpdateFrame(
        &encoded,
        allocator,
        0,
        .{ .urgency = 2 },
    );
    try control.applyFrame(allocator, try Frame.parse(encoded.items));
    try std.testing.expectEqual(
        @as(u3, 2),
        control.requestPriorityUpdate(0).?.priority().urgency,
    );
    try std.testing.expectEqual(
        @as(u3, 5),
        control.requestPriorityUpdate(4).?.priority().urgency,
    );
}

test "HTTP/3 per-element priority state is allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkPriorityUpdateStateAllocationFailure,
        .{},
    );
}

test "HTTP/3 control stream rejects request frames" {
    const allocator = std.testing.allocator;
    var control = ControlState{};
    defer control.deinit(allocator);
    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(allocator);
    try writeControlStreamPrefix(&stream, allocator);
    try writeSettingsFrame(&stream, allocator, .{});
    try (Frame{ .frame_type = FrameType.data, .payload = "forbidden", .consumed = 0 }).write(&stream, allocator);
    try std.testing.expectError(error.UnexpectedFrame, control.applyControlStreamBytes(allocator, stream.items));

    var initialized = ControlState{ .settings = .{ .received = true } };
    try std.testing.expectError(error.UnexpectedFrame, initialized.applyFrame(allocator, .{
        .frame_type = FrameType.headers,
        .payload = &.{},
        .consumed = 0,
    }));
    try std.testing.expectError(error.UnexpectedFrame, initialized.applyFrame(allocator, .{
        .frame_type = FrameType.push_promise,
        .payload = &.{},
        .consumed = 0,
    }));
}

test "HTTP/3 typed settings state tracks negotiation" {
    const allocator = std.testing.allocator;
    const defaults = Settings{};
    try std.testing.expectEqual(std.math.maxInt(u64), defaults.max_field_section_size);
    var default_payload: std.ArrayList(u8) = .empty;
    defer default_payload.deinit(allocator);
    try defaults.writePayload(&default_payload, allocator);
    try std.testing.expectEqual(@as(usize, 0), default_payload.items.len);
    try (Settings{
        .qpack_max_table_capacity = 1,
    }).writePayload(&default_payload, allocator);
    default_payload.clearRetainingCapacity();
    try (Settings{
        .qpack_blocked_streams = 128,
    }).writePayload(&default_payload, allocator);
    try std.testing.expect(default_payload.items.len != 0);
    default_payload.clearRetainingCapacity();
    try std.testing.expectError(error.QpackDynamicTableUnsupported, (Settings{
        .qpack_blocked_streams = 129,
    }).writePayload(&default_payload, allocator));

    const local = Settings{
        .max_field_section_size = 32 * 1024,
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .webtransport_max_sessions = 16,
    };

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try local.writePayload(&payload, allocator);
    const raw = try parseSettings(allocator, payload.items);
    defer allocator.free(raw);
    const decoded = Settings.fromList(raw);

    try std.testing.expectEqual(@as(u64, 32 * 1024), decoded.max_field_section_size);
    try std.testing.expect(decoded.enable_connect_protocol);
    try std.testing.expect(decoded.h3_datagram);
    try std.testing.expectEqual(@as(u64, 16), decoded.webtransport_max_sessions);

    var state = SettingsState{};
    try std.testing.expect(!state.ready());
    state.markSent(local);
    try std.testing.expect(!state.ready());
    state.markReceived(decoded);
    try std.testing.expect(state.ready());
    try std.testing.expect(state.peer.h3_datagram);
}

test "HTTP/3 control stream enforces SETTINGS first and GOAWAY monotonicity" {
    const allocator = std.testing.allocator;

    var local_control = ControlState{};
    var stream_bytes: std.ArrayList(u8) = .empty;
    defer stream_bytes.deinit(allocator);
    try local_control.writeSettingsStream(&stream_bytes, allocator, .{
        .h3_datagram = true,
        .webtransport_max_sessions = 2,
    });
    try local_control.writeGoAway(&stream_bytes, allocator, 12);
    try std.testing.expectError(error.GoAwayIdIncreased, local_control.writeGoAway(&stream_bytes, allocator, 16));

    var peer_control = ControlState{};
    try peer_control.applyControlStreamBytes(allocator, stream_bytes.items);
    try std.testing.expectEqual(@as(?u64, 0), peer_control.peer_control_stream_id);
    try peer_control.registerControlStream(0);
    try std.testing.expectError(error.StreamCreationError, peer_control.registerControlStream(4));
    try std.testing.expect(peer_control.settings.received);
    try std.testing.expect(peer_control.settings.peer.h3_datagram);
    try std.testing.expectEqual(@as(u64, 2), peer_control.settings.peer.webtransport_max_sessions);
    try std.testing.expectEqual(@as(?u64, 12), peer_control.peer_goaway_id);
    try std.testing.expect(peer_control.acceptsRequestStream(8));
    try std.testing.expect(!peer_control.acceptsRequestStream(12));

    var invalid: std.ArrayList(u8) = .empty;
    defer invalid.deinit(allocator);
    try writeControlStreamPrefix(&invalid, allocator);
    var goaway_payload: std.ArrayList(u8) = .empty;
    defer goaway_payload.deinit(allocator);
    try quic.varint.encode(&goaway_payload, allocator, 0);
    try (Frame{ .frame_type = FrameType.goaway, .payload = goaway_payload.items, .consumed = 0 }).write(&invalid, allocator);
    var missing_settings = ControlState{};
    try std.testing.expectError(error.MissingSettings, missing_settings.applyControlStreamBytes(allocator, invalid.items));

    var bad_settings: std.ArrayList(u8) = .empty;
    defer bad_settings.deinit(allocator);
    try quic.varint.encode(&bad_settings, allocator, 0x04);
    try quic.varint.encode(&bad_settings, allocator, 1);
    try std.testing.expectError(error.InvalidSetting, parseSettings(allocator, bad_settings.items));

    bad_settings.clearRetainingCapacity();
    try quic.varint.encode(&bad_settings, allocator, @intFromEnum(SettingId.h3_datagram));
    try quic.varint.encode(&bad_settings, allocator, 2);
    try std.testing.expectError(error.InvalidSetting, parseSettings(allocator, bad_settings.items));

    try std.testing.expectError(error.InvalidSetting, writeSettings(&bad_settings, allocator, &[_]Setting{
        .{ .id = @intFromEnum(SettingId.h3_datagram), .value = 1 },
        .{ .id = @intFromEnum(SettingId.h3_datagram), .value = 1 },
    }));
    try std.testing.expectError(error.InvalidSetting, writeSettings(&bad_settings, allocator, &[_]Setting{.{ .id = 0x04, .value = 0 }}));

    var excessive_settings: std.ArrayList(u8) = .empty;
    defer excessive_settings.deinit(allocator);
    try excessive_settings.appendNTimes(allocator, 0, max_settings_payload_size + 1);
    try std.testing.expectError(error.InvalidSetting, parseSettings(allocator, excessive_settings.items));

    var duplicate_settings = ControlState{};
    var duplicate: std.ArrayList(u8) = .empty;
    defer duplicate.deinit(allocator);
    try duplicate_settings.writeSettingsStream(&duplicate, allocator, .{});
    try writeSettingsFrame(&duplicate, allocator, .{});
    try std.testing.expectError(error.DuplicateSettings, duplicate_settings.applyControlStreamBytes(allocator, duplicate.items));
}

test "HTTP/3 push control frames and state" {
    const allocator = std.testing.allocator;

    var cancel: std.ArrayList(u8) = .empty;
    defer cancel.deinit(allocator);
    try writeCancelPushFrame(&cancel, allocator, 7);
    const cancel_frame = try Frame.parse(cancel.items);
    try std.testing.expectEqual(FrameType.cancel_push, cancel_frame.frame_type);
    try std.testing.expectEqual(@as(u64, 7), try parseCancelPushPayload(cancel_frame.payload));

    var max_push: std.ArrayList(u8) = .empty;
    defer max_push.deinit(allocator);
    var control = ControlState{};
    defer control.deinit(allocator);
    try control.writeMaxPushId(&max_push, allocator, 4);
    try std.testing.expectEqual(@as(?u64, 4), control.local_max_push_id);
    try control.writeMaxPushId(&max_push, allocator, 8);
    try std.testing.expectEqual(@as(?u64, 8), control.local_max_push_id);
    try std.testing.expectError(error.MaxPushIdReduced, control.writeMaxPushId(&max_push, allocator, 2));

    var peer_control = ControlState{ .settings = .{ .received = true } };
    defer peer_control.deinit(allocator);
    const first = try Frame.parse(max_push.items);
    try peer_control.applyFrame(allocator, first);
    try std.testing.expectEqual(@as(?u64, 4), peer_control.peer_max_push_id);
    const second = try Frame.parse(max_push.items[first.consumed..]);
    try peer_control.applyFrame(allocator, second);
    try std.testing.expectEqual(@as(?u64, 8), peer_control.peer_max_push_id);

    var reduced: std.ArrayList(u8) = .empty;
    defer reduced.deinit(allocator);
    try writeMaxPushIdFrame(&reduced, allocator, 1);
    const reduced_frame = try Frame.parse(reduced.items);
    try std.testing.expectError(error.MaxPushIdReduced, peer_control.applyFrame(allocator, reduced_frame));

    try peer_control.applyFrame(allocator, cancel_frame);
    try std.testing.expectEqual(
        @as(?u64, 7),
        peer_control.peer_cancelled_push_id,
    );
    var second_cancel: std.ArrayList(u8) = .empty;
    defer second_cancel.deinit(allocator);
    try writeCancelPushFrame(&second_cancel, allocator, 3);
    try peer_control.applyFrame(
        allocator,
        try Frame.parse(second_cancel.items),
    );
    // Duplicate cancellation is idempotent; distinct IDs remain queryable.
    try peer_control.applyFrame(allocator, cancel_frame);
    try std.testing.expect(peer_control.pushCancelled(7));
    try std.testing.expect(peer_control.pushCancelled(3));
    try std.testing.expectEqual(
        @as(usize, 2),
        peer_control.peer_cancelled_push_ids.items.len,
    );
}

test "HTTP/3 PUSH_PROMISE frame payload and limit validation" {
    const allocator = std.testing.allocator;
    var field_section: std.ArrayList(u8) = .empty;
    defer field_section.deinit(allocator);
    try Qpack.encodeLiteralBlock(&field_section, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/pushed.css" },
        .{ .name = ":authority", .value = "example.test" },
    });

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writePushPromiseFrame(&encoded, allocator, 3, field_section.items);
    const frame = try Frame.parse(encoded.items);
    try std.testing.expectEqual(FrameType.push_promise, frame.frame_type);
    const promise = try parsePushPromisePayload(frame.payload);
    try std.testing.expectEqual(@as(u64, 3), promise.push_id);
    const decoded = try Qpack.decodeLiteralBlock(allocator, promise.field_section);
    defer Qpack.freeDecodedFields(allocator, decoded);
    try std.testing.expectEqualStrings("/pushed.css", decoded[2].value);

    try validatePushPromise(.{ .local_max_push_id = 3 }, promise.push_id);
    try std.testing.expectError(error.PushIdExceeded, validatePushPromise(.{}, promise.push_id));
    try std.testing.expectError(error.PushIdExceeded, validatePushPromise(.{ .local_max_push_id = 2 }, promise.push_id));

    var dynamic_table = Qpack.DynamicTable.init(allocator, 0);
    defer dynamic_table.deinit();
    var decoded_promise = try decodePushPromiseWithDynamicTable(
        allocator,
        frame.payload,
        .{},
        dynamic_table,
    );
    defer decoded_promise.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 3), decoded_promise.push_id);
    try std.testing.expectEqualStrings(
        "/pushed.css",
        decoded_promise.request.path,
    );

    var response_with_push: std.ArrayList(u8) = .empty;
    defer response_with_push.deinit(allocator);
    try writePushPromiseFrame(&response_with_push, allocator, 3, field_section.items);
    var response_headers: std.ArrayList(u8) = .empty;
    defer response_headers.deinit(allocator);
    try Qpack.encodeLiteralBlock(&response_headers, allocator, &.{.{ .name = ":status", .value = "200" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = response_headers.items, .consumed = 0 }).write(&response_with_push, allocator);
    try validateResponsePushPromises(.{ .local_max_push_id = 3 }, response_with_push.items);
    try std.testing.expectError(error.PushIdExceeded, validateResponsePushPromises(.{}, response_with_push.items));
    try std.testing.expectError(error.PushIdExceeded, validateResponsePushPromises(.{ .local_max_push_id = 2 }, response_with_push.items));
}

test "HTTP/3 enforces SETTINGS_MAX_FIELD_SECTION_SIZE" {
    const allocator = std.testing.allocator;

    var request_bytes: std.ArrayList(u8) = .empty;
    defer request_bytes.deinit(allocator);
    try (Request{
        .method = "GET",
        .path = "/limited",
        .authority = "example.com",
    }).write(&request_bytes, allocator);
    var decoded_request = try decodeRequest(allocator, request_bytes.items);
    decoded_request.deinit(allocator);
    try std.testing.expectError(error.ExcessiveLoad, decodeRequestWithSettings(allocator, request_bytes.items, .{
        .max_field_section_size = 1,
    }));
    var rejected_request_write: std.ArrayList(u8) = .empty;
    defer rejected_request_write.deinit(allocator);
    try std.testing.expectError(error.ExcessiveLoad, (Request{
        .method = "GET",
        .path = "/limited",
        .authority = "example.com",
    }).writeWithSettings(&rejected_request_write, allocator, .{
        .max_field_section_size = 1,
    }));

    var response_bytes: std.ArrayList(u8) = .empty;
    defer response_bytes.deinit(allocator);
    try (Response{
        .status = 200,
        .trailers = &.{.{ .name = "grpc-status", .value = "0" }},
    }).write(&response_bytes, allocator);
    var decoded_response = try decodeResponseWithSettings(allocator, response_bytes.items, .{
        .max_field_section_size = 44,
    });
    decoded_response.deinit(allocator);
    try std.testing.expectError(error.ExcessiveLoad, decodeResponseWithSettings(allocator, response_bytes.items, .{
        .max_field_section_size = 43,
    }));

    var rejected_response_write: std.ArrayList(u8) = .empty;
    defer rejected_response_write.deinit(allocator);
    try std.testing.expectError(error.ExcessiveLoad, writeResponseSequenceWithSettings(&rejected_response_write, allocator, &.{.{
        .status = 103,
    }}, .{
        .status = 200,
    }, .{
        .max_field_section_size = 41,
    }));
}

fn checkPushCancellationStateAllocationFailure(
    allocator: std.mem.Allocator,
) !void {
    var control = ControlState{ .settings = .{ .received = true } };
    defer control.deinit(allocator);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writeCancelPushFrame(&encoded, allocator, 1);
    try control.applyFrame(allocator, try Frame.parse(encoded.items));
    encoded.clearRetainingCapacity();
    try writeCancelPushFrame(&encoded, allocator, 3);
    try control.applyFrame(allocator, try Frame.parse(encoded.items));
    try control.applyFrame(allocator, try Frame.parse(encoded.items));
    try std.testing.expect(control.pushCancelled(1));
    try std.testing.expect(control.pushCancelled(3));
    try std.testing.expectEqual(
        @as(usize, 2),
        control.peer_cancelled_push_ids.items.len,
    );
}

test "HTTP/3 per-ID push cancellation is allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkPushCancellationStateAllocationFailure,
        .{},
    );
}

test "HTTP/3 rejects malformed structured frame payloads" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.InvalidFrame, parseGoAwayPayload(&.{}));
    try std.testing.expectError(error.InvalidFrame, parseCancelPushPayload(&.{}));
    try std.testing.expectError(error.InvalidFrame, parseMaxPushIdPayload(&.{}));
    try std.testing.expectError(error.InvalidFrame, parsePushPromisePayload(&.{}));
    try std.testing.expectError(error.InvalidFrame, parsePriorityUpdatePayload(&.{}));

    const truncated_two_byte_varint = [_]u8{0x40};
    try std.testing.expectError(error.InvalidFrame, parseGoAwayPayload(&truncated_two_byte_varint));
    try std.testing.expectError(error.InvalidFrame, parsePushPromisePayload(&truncated_two_byte_varint));
    try std.testing.expectError(error.InvalidFrame, parsePriorityUpdatePayload(&truncated_two_byte_varint));

    var malformed_frame_write: std.ArrayList(u8) = .empty;
    defer malformed_frame_write.deinit(allocator);
    try std.testing.expectError(error.InvalidFrame, (Frame{ .frame_type = FrameType.goaway, .payload = &.{}, .consumed = 0 }).write(&malformed_frame_write, allocator));

    var malformed_response: std.ArrayList(u8) = .empty;
    defer malformed_response.deinit(allocator);
    try quic.varint.encode(&malformed_response, allocator, FrameType.push_promise);
    try quic.varint.encode(&malformed_response, allocator, 0);
    var header_block: std.ArrayList(u8) = .empty;
    defer header_block.deinit(allocator);
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "200" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&malformed_response, allocator);
    try std.testing.expectError(error.InvalidFrame, decodeResponse(allocator, malformed_response.items));

    var malformed_settings: std.ArrayList(u8) = .empty;
    defer malformed_settings.deinit(allocator);
    try quic.varint.encode(&malformed_settings, allocator, @intFromEnum(SettingId.h3_datagram));
    try std.testing.expectError(error.InvalidSetting, parseSettings(allocator, malformed_settings.items));
}

test "HTTP/3 datagram" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (Datagram{ .quarter_stream_id = 4, .payload = "capsule" }).write(&encoded, allocator);
    const parsed = try Datagram.parse(encoded.items);
    try std.testing.expectEqual(@as(u64, 4), parsed.quarter_stream_id);
    try std.testing.expectEqualStrings("capsule", parsed.payload);
}

test "HTTP/3 request encode decode" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try (Request{
        .method = "POST",
        .path = "/submit",
        .authority = "example.com",
        .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
        .body = "hello",
    }).write(&encoded, allocator);

    var decoded = try decodeRequest(allocator, encoded.items);
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings("POST", decoded.method);
    try std.testing.expectEqualStrings("/submit", decoded.path);
    try std.testing.expectEqualStrings("example.com", decoded.authority.?);
    try std.testing.expectEqualStrings("hello", decoded.body);
    try std.testing.expectEqualStrings("5", findHeader(decoded.headers, "content-length") orelse return error.MissingHeader);

    encoded.clearRetainingCapacity();
    try (Request{
        .method = "POST",
        .path = "/empty",
        .authority = "example.com",
    }).write(&encoded, allocator);
    var empty_post = try decodeRequest(allocator, encoded.items);
    defer empty_post.deinit(allocator);
    try std.testing.expectEqualStrings("0", findHeader(empty_post.headers, "content-length") orelse return error.MissingHeader);

    encoded.clearRetainingCapacity();
    try (Request{
        .method = "GET",
        .path = "/no-length",
        .authority = "example.com",
    }).write(&encoded, allocator);
    var get = try decodeRequest(allocator, encoded.items);
    defer get.deinit(allocator);
    try std.testing.expect(findHeader(get.headers, "content-length") == null);
}

test "HTTP/3 dynamic QPACK request decode preserves message semantics and acknowledgment count" {
    const allocator = std.testing.allocator;
    var table = Qpack.DynamicTable.init(allocator, 512);
    defer table.deinit();
    try table.setCapacity(512);
    _ = try table.insert("x-request-id", "request-20260809");
    _ = try table.insert("x-trailer", "complete");

    const headers = [_]Qpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/dynamic" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "content-length", .value = "4" },
        .{ .name = "x-request-id", .value = "request-20260809" },
    };
    const trailers = [_]Qpack.HeaderField{
        .{ .name = "x-trailer", .value = "complete" },
    };
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try Qpack.encodeDynamicBlock(&block, allocator, &headers, table);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&encoded, allocator);
    try (Frame{
        .frame_type = FrameType.data,
        .payload = "body",
        .consumed = 0,
    }).write(&encoded, allocator);
    block.clearRetainingCapacity();
    try Qpack.encodeDynamicBlock(&block, allocator, &trailers, table);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&encoded, allocator);

    var decoded = try decodeRequestWithDynamicTable(
        allocator,
        encoded.items,
        .{},
        table,
    );
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings("POST", decoded.method);
    try std.testing.expectEqualStrings("/dynamic", decoded.path);
    try std.testing.expectEqualStrings("https", decoded.scheme);
    try std.testing.expectEqualStrings("example.com", decoded.authority.?);
    try std.testing.expectEqualStrings("body", decoded.body);
    try std.testing.expectEqual(@as(usize, 1), decoded.trailers.len);
    try std.testing.expectEqualStrings("complete", decoded.trailers[0].value);
    try std.testing.expectEqual(@as(usize, 2), decoded.qpack_section_acknowledgments);
}

test "HTTP/3 dynamic QPACK response counts informational and final acknowledgments" {
    const allocator = std.testing.allocator;
    var table = Qpack.DynamicTable.init(allocator, 512);
    defer table.deinit();
    try table.setCapacity(512);
    _ = try table.insert("x-release", "netz-2026");

    const informational = [_]Qpack.HeaderField{
        .{ .name = ":status", .value = "103" },
        .{ .name = "x-release", .value = "netz-2026" },
    };
    const final = [_]Qpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "2" },
        .{ .name = "x-release", .value = "netz-2026" },
    };
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try Qpack.encodeDynamicBlock(&block, allocator, &informational, table);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&encoded, allocator);
    block.clearRetainingCapacity();
    try Qpack.encodeDynamicBlock(&block, allocator, &final, table);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&encoded, allocator);
    try (Frame{
        .frame_type = FrameType.data,
        .payload = "ok",
        .consumed = 0,
    }).write(&encoded, allocator);

    var decoded = try decodeResponseWithDynamicTable(
        allocator,
        encoded.items,
        .{},
        table,
    );
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), decoded.status);
    try std.testing.expectEqualStrings("ok", decoded.body);
    try std.testing.expectEqual(@as(usize, 2), decoded.qpack_section_acknowledgments);
}

test "HTTP/3 dynamic heads decode before DATA and own fields" {
    const allocator = std.testing.allocator;
    var table = Qpack.DynamicTable.init(allocator, 512);
    defer table.deinit();
    try table.setCapacity(512);
    _ = try table.insert("x-owned", "dynamic-value");

    var request_bytes: std.ArrayList(u8) = .empty;
    defer request_bytes.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/stream-head" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = "content-length", .value = "1000000" },
        .{ .name = "x-owned", .value = "dynamic-value" },
    }, table);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&request_bytes, allocator);
    const request_head_bytes = request_bytes.items.len;
    try quic.varint.encode(&request_bytes, allocator, FrameType.data);
    try quic.varint.encode(&request_bytes, allocator, 1_000_000);

    var request_head = try decodeRequestHeadWithDynamicTable(
        allocator,
        request_bytes.items,
        .{},
        table,
    );
    defer request_head.deinit(allocator);
    try std.testing.expectEqualStrings("POST", request_head.method);
    try std.testing.expectEqualStrings("/stream-head", request_head.path);
    try std.testing.expectEqual(
        @as(?usize, 1_000_000),
        request_head.content_length,
    );
    try std.testing.expectEqual(request_head_bytes, request_head.consumed);
    try std.testing.expectEqual(
        @as(usize, 1),
        request_head.qpack_section_acknowledgments,
    );
    @memset(block.items, 0);
    try std.testing.expectEqualStrings(
        "dynamic-value",
        ownedFieldValue(request_head.headers, "x-owned").?,
    );

    var response_bytes: std.ArrayList(u8) = .empty;
    defer response_bytes.deinit(allocator);
    block.clearRetainingCapacity();
    try Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":status", .value = "103" },
        .{ .name = "x-owned", .value = "dynamic-value" },
    }, table);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&response_bytes, allocator);
    block.clearRetainingCapacity();
    try Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "8" },
        .{ .name = "x-owned", .value = "dynamic-value" },
    }, table);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&response_bytes, allocator);
    const response_head_bytes = response_bytes.items.len;

    var response_head = try decodeResponseHeadWithDynamicTable(
        allocator,
        response_bytes.items,
        .{},
        table,
    );
    defer response_head.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response_head.status);
    try std.testing.expectEqual(@as(?usize, 8), response_head.content_length);
    try std.testing.expectEqual(response_head_bytes, response_head.consumed);
    try std.testing.expectEqual(
        @as(usize, 2),
        response_head.qpack_section_acknowledgments,
    );
}

fn checkDynamicQpackHeadAllocationFailure(
    allocator: std.mem.Allocator,
) !void {
    var table = Qpack.DynamicTable.init(allocator, 512);
    defer table.deinit();
    try table.setCapacity(512);
    _ = try table.insert("x-owned", "dynamic-value");
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/oom-head" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = "x-owned", .value = "dynamic-value" },
    }, table);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&encoded, allocator);
    var head = try decodeRequestHeadWithDynamicTable(
        allocator,
        encoded.items,
        .{},
        table,
    );
    head.deinit(allocator);
}

test "HTTP/3 dynamic head decoding is transactional under allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkDynamicQpackHeadAllocationFailure,
        .{},
    );
}

fn checkDynamicQpackMessageAllocationFailure(allocator: std.mem.Allocator) !void {
    var table = Qpack.DynamicTable.init(allocator, 512);
    defer table.deinit();
    try table.setCapacity(512);
    _ = try table.insert("x-transaction", "owned-dynamic-value");

    const headers = [_]Qpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/oom" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "content-length", .value = "4" },
        .{ .name = "x-transaction", .value = "owned-dynamic-value" },
    };
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try Qpack.encodeDynamicBlock(&block, allocator, &headers, table);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&encoded, allocator);
    try (Frame{
        .frame_type = FrameType.data,
        .payload = "body",
        .consumed = 0,
    }).write(&encoded, allocator);
    block.clearRetainingCapacity();
    try Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = "x-transaction", .value = "owned-dynamic-value" },
    }, table);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&encoded, allocator);

    var decoded = try decodeRequestWithDynamicTable(
        allocator,
        encoded.items,
        .{},
        table,
    );
    decoded.deinit(allocator);
}

test "HTTP/3 dynamic QPACK message decode is transactional under allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkDynamicQpackMessageAllocationFailure,
        .{},
    );
}

test "HTTP/3 message aggregates DATA frames and trailing HEADERS" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    var header_block: std.ArrayList(u8) = .empty;
    defer header_block.deinit(allocator);
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/multi" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "content-length", .value = "11" },
    });
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&encoded, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "hello ", .consumed = 0 }).write(&encoded, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "world", .consumed = 0 }).write(&encoded, allocator);

    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{
        .{ .name = "grpc-status", .value = "0" },
    });
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&encoded, allocator);

    var decoded = try decodeRequest(allocator, encoded.items);
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings("POST", decoded.method);
    try std.testing.expectEqualStrings("hello world", decoded.body);
    try std.testing.expectEqual(@as(usize, 1), decoded.trailers.len);
    try std.testing.expectEqualStrings("grpc-status", decoded.trailers[0].name);
    try std.testing.expectEqual(@as(usize, encoded.items.len), decoded.consumed);
}

test "HTTP/3 message rejects bad frame order and content length" {
    const allocator = std.testing.allocator;

    var data_first: std.ArrayList(u8) = .empty;
    defer data_first.deinit(allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "oops", .consumed = 0 }).write(&data_first, allocator);
    try std.testing.expectError(error.ExpectedHeadersFrame, decodeRequest(allocator, data_first.items));

    var signed_length_request: std.ArrayList(u8) = .empty;
    defer signed_length_request.deinit(allocator);
    var signed_block: std.ArrayList(u8) = .empty;
    defer signed_block.deinit(allocator);
    try Qpack.encodeLiteralBlock(&signed_block, allocator, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/signed-length" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "content-length", .value = "+4" },
    });
    try (Frame{ .frame_type = FrameType.headers, .payload = signed_block.items, .consumed = 0 }).write(&signed_length_request, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "1234", .consumed = 0 }).write(&signed_length_request, allocator);
    try std.testing.expectError(error.InvalidContentLength, decodeRequest(allocator, signed_length_request.items));

    var connect_with_length = std.ArrayList(u8).empty;
    defer connect_with_length.deinit(allocator);
    signed_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&signed_block, allocator, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "proxy.example.com:443" },
        .{ .name = "content-length", .value = "0" },
    });
    try (Frame{ .frame_type = FrameType.headers, .payload = signed_block.items, .consumed = 0 }).write(&connect_with_length, allocator);
    try std.testing.expectError(error.InvalidContentLength, decodeRequest(allocator, connect_with_length.items));

    var invalid_length: std.ArrayList(u8) = .empty;
    defer invalid_length.deinit(allocator);
    var header_block: std.ArrayList(u8) = .empty;
    defer header_block.deinit(allocator);
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/bad-length" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "content-length", .value = "5" },
    });
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&invalid_length, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "1234", .consumed = 0 }).write(&invalid_length, allocator);
    try std.testing.expectError(error.InvalidContentLength, decodeRequest(allocator, invalid_length.items));

    var low_status: std.ArrayList(u8) = .empty;
    defer low_status.deinit(allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "099" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&low_status, allocator);
    try std.testing.expectError(error.InvalidStatus, decodeResponse(allocator, low_status.items));

    var malformed_status: std.ArrayList(u8) = .empty;
    defer malformed_status.deinit(allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "0200" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&malformed_status, allocator);
    try std.testing.expectError(error.InvalidStatus, decodeResponse(allocator, malformed_status.items));

    malformed_status.clearRetainingCapacity();
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "20x" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&malformed_status, allocator);
    try std.testing.expectError(error.InvalidStatus, decodeResponse(allocator, malformed_status.items));

    malformed_status.clearRetainingCapacity();
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "101" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&malformed_status, allocator);
    // HTTP/3 has no HTTP/1.1 Upgrade/Switching Protocols path.  Reject 101 at
    // the header-validation boundary instead of silently treating it as a
    // skippable informational response.
    try std.testing.expectError(error.InvalidStatus, decodeResponse(allocator, malformed_status.items));

    var informational_response: std.ArrayList(u8) = .empty;
    defer informational_response.deinit(allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "103" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&informational_response, allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "200" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&informational_response, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "final", .consumed = 0 }).write(&informational_response, allocator);
    var informational_decoded = try decodeResponse(allocator, informational_response.items);
    defer informational_decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), informational_decoded.status);
    try std.testing.expectEqualStrings("final", informational_decoded.body);

    var extension_prefaced_response: std.ArrayList(u8) = .empty;
    defer extension_prefaced_response.deinit(allocator);
    try (Frame{ .frame_type = 0x21, .payload = "extension", .consumed = 0 }).write(&extension_prefaced_response, allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "200" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&extension_prefaced_response, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "response-ext", .consumed = 0 }).write(&extension_prefaced_response, allocator);
    var extension_decoded = try decodeResponse(allocator, extension_prefaced_response.items);
    defer extension_decoded.deinit(allocator);
    try std.testing.expectEqualStrings("response-ext", extension_decoded.body);

    var pushed_response: std.ArrayList(u8) = .empty;
    defer pushed_response.deinit(allocator);
    try writePushPromiseFrame(&pushed_response, allocator, 0, "promised-headers");
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "200" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&pushed_response, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "pushed-ok", .consumed = 0 }).write(&pushed_response, allocator);
    var pushed_decoded = try decodeResponse(allocator, pushed_response.items);
    defer pushed_decoded.deinit(allocator);
    try std.testing.expectEqualStrings("pushed-ok", pushed_decoded.body);

    var client_push_promise: std.ArrayList(u8) = .empty;
    defer client_push_promise.deinit(allocator);
    try writePushPromiseFrame(&client_push_promise, allocator, 0, "illegal-client-push");
    try std.testing.expectError(error.ExpectedHeadersFrame, decodeRequest(allocator, client_push_promise.items));

    var informational_only = std.ArrayList(u8).empty;
    defer informational_only.deinit(allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "103" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&informational_only, allocator);
    try std.testing.expectError(error.MissingStatus, decodeResponse(allocator, informational_only.items));

    var written_sequence: std.ArrayList(u8) = .empty;
    defer written_sequence.deinit(allocator);
    try writeResponseSequence(&written_sequence, allocator, &.{.{
        .status = 103,
        .headers = &.{.{ .name = "link", .value = "</style.css>; rel=preload" }},
    }}, .{ .status = 200, .body = "sequence-final" });
    var sequence_decoded = try decodeResponse(allocator, written_sequence.items);
    defer sequence_decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), sequence_decoded.status);
    try std.testing.expectEqualStrings("sequence-final", sequence_decoded.body);
    try std.testing.expectError(error.InvalidStatus, (InformationalResponse{ .status = 200 }).write(&written_sequence, allocator));
    try std.testing.expectError(error.InvalidContentLength, (InformationalResponse{
        .status = 103,
        .headers = &.{.{ .name = "content-length", .value = "1" }},
    }).write(&written_sequence, allocator));

    var signed_length_response: std.ArrayList(u8) = .empty;
    defer signed_length_response.deinit(allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "+4" },
    });
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&signed_length_response, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "1234", .consumed = 0 }).write(&signed_length_response, allocator);
    try std.testing.expectError(error.InvalidContentLength, decodeResponse(allocator, signed_length_response.items));

    var no_content_body: std.ArrayList(u8) = .empty;
    defer no_content_body.deinit(allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "204" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&no_content_body, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "body", .consumed = 0 }).write(&no_content_body, allocator);
    try std.testing.expectError(error.InvalidContentLength, decodeResponse(allocator, no_content_body.items));

    var not_modified_length: std.ArrayList(u8) = .empty;
    defer not_modified_length.deinit(allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{
        .{ .name = ":status", .value = "304" },
        .{ .name = "content-length", .value = "123" },
    });
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&not_modified_length, allocator);
    var not_modified = try decodeResponse(allocator, not_modified_length.items);
    defer not_modified.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 304), not_modified.status);

    var bad_order: std.ArrayList(u8) = .empty;
    defer bad_order.deinit(allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{
        .{ .name = ":status", .value = "200" },
    });
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&bad_order, allocator);
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&bad_order, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "late", .consumed = 0 }).write(&bad_order, allocator);
    try std.testing.expectError(error.UnexpectedFrame, decodeResponse(allocator, bad_order.items));

    var forbidden: std.ArrayList(u8) = .empty;
    defer forbidden.deinit(allocator);
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&forbidden, allocator);
    try (Frame{ .frame_type = FrameType.settings, .payload = &.{}, .consumed = 0 }).write(&forbidden, allocator);
    try std.testing.expectError(error.UnexpectedFrame, decodeResponse(allocator, forbidden.items));
}

test "HTTP/3 validates pseudo headers and connection-specific fields" {
    const allocator = std.testing.allocator;

    const Helper = struct {
        fn writeRequestBlock(list: *std.ArrayList(u8), gpa: std.mem.Allocator, fields: []const Qpack.HeaderField) !void {
            var block: std.ArrayList(u8) = .empty;
            defer block.deinit(gpa);
            try Qpack.encodeLiteralBlock(&block, gpa, fields);
            try (Frame{ .frame_type = FrameType.headers, .payload = block.items, .consumed = 0 }).write(list, gpa);
        }

        fn writeRequestWithTrailers(
            list: *std.ArrayList(u8),
            gpa: std.mem.Allocator,
            fields: []const Qpack.HeaderField,
            trailers: []const Qpack.HeaderField,
        ) !void {
            try writeRequestBlock(list, gpa, fields);
            var block: std.ArrayList(u8) = .empty;
            defer block.deinit(gpa);
            try Qpack.encodeLiteralBlock(&block, gpa, trailers);
            try (Frame{ .frame_type = FrameType.headers, .payload = block.items, .consumed = 0 }).write(list, gpa);
        }
    };

    const valid_request = [_]Qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    };

    var uppercase: std.ArrayList(u8) = .empty;
    defer uppercase.deinit(allocator);
    try Helper.writeRequestBlock(&uppercase, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "Content-Type", .value = "text/plain" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, uppercase.items));

    var duplicate_pseudo: std.ArrayList(u8) = .empty;
    defer duplicate_pseudo.deinit(allocator);
    try Helper.writeRequestBlock(&duplicate_pseudo, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, duplicate_pseudo.items));

    var connection_specific: std.ArrayList(u8) = .empty;
    defer connection_specific.deinit(allocator);
    try Helper.writeRequestBlock(&connection_specific, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "transfer-encoding", .value = "chunked" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, connection_specific.items));

    var bad_te: std.ArrayList(u8) = .empty;
    defer bad_te.deinit(allocator);
    try Helper.writeRequestBlock(&bad_te, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "te", .value = "gzip" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, bad_te.items));

    var good_te: std.ArrayList(u8) = .empty;
    defer good_te.deinit(allocator);
    try Helper.writeRequestBlock(&good_te, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "te", .value = "trailers" },
    });
    var decoded = try decodeRequest(allocator, good_te.items);
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings("GET", decoded.method);

    var missing_authority = std.ArrayList(u8).empty;
    defer missing_authority.deinit(allocator);
    try Helper.writeRequestBlock(&missing_authority, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, missing_authority.items));

    var host_authority = std.ArrayList(u8).empty;
    defer host_authority.deinit(allocator);
    try Helper.writeRequestBlock(&host_authority, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "host", .value = "example.com" },
    });
    var host_decoded = try decodeRequest(allocator, host_authority.items);
    defer host_decoded.deinit(allocator);
    try std.testing.expectEqualStrings("GET", host_decoded.method);
    try std.testing.expectEqualStrings("example.com", host_decoded.authority.?);

    var mismatched_authority = std.ArrayList(u8).empty;
    defer mismatched_authority.deinit(allocator);
    try Helper.writeRequestBlock(&mismatched_authority, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "origin.example" },
        .{ .name = "host", .value = "proxy.example" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, mismatched_authority.items));

    var invalid_path = std.ArrayList(u8).empty;
    defer invalid_path.deinit(allocator);
    try Helper.writeRequestBlock(&invalid_path, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "relative" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, invalid_path.items));

    var query_only_path = std.ArrayList(u8).empty;
    defer query_only_path.deinit(allocator);
    try Helper.writeRequestBlock(&query_only_path, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "?only=query" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, query_only_path.items));

    var options_asterisk = std.ArrayList(u8).empty;
    defer options_asterisk.deinit(allocator);
    try Helper.writeRequestBlock(&options_asterisk, allocator, &.{
        .{ .name = ":method", .value = "OPTIONS" },
        .{ .name = ":path", .value = "*" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    });
    var options_decoded = try decodeRequest(allocator, options_asterisk.items);
    defer options_decoded.deinit(allocator);
    try std.testing.expectEqualStrings("OPTIONS", options_decoded.method);
    try std.testing.expectEqualStrings("*", options_decoded.path);

    var lowercase_options_asterisk = std.ArrayList(u8).empty;
    defer lowercase_options_asterisk.deinit(allocator);
    try Helper.writeRequestBlock(&lowercase_options_asterisk, allocator, &.{
        .{ .name = ":method", .value = "options" },
        .{ .name = ":path", .value = "*" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, lowercase_options_asterisk.items));

    var invalid_authority = std.ArrayList(u8).empty;
    defer invalid_authority.deinit(allocator);
    try Helper.writeRequestBlock(&invalid_authority, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "user@example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, invalid_authority.items));

    var invalid_method_token = std.ArrayList(u8).empty;
    defer invalid_method_token.deinit(allocator);
    try Helper.writeRequestBlock(&invalid_method_token, allocator, &.{
        .{ .name = ":method", .value = "GET /" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, invalid_method_token.items));

    var empty_path = std.ArrayList(u8).empty;
    defer empty_path.deinit(allocator);
    try Helper.writeRequestBlock(&empty_path, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, empty_path.items));

    var plain_connect = std.ArrayList(u8).empty;
    defer plain_connect.deinit(allocator);
    try (Request{
        .method = "CONNECT",
        .path = "/must-be-omitted",
        .authority = "proxy.example.com:443",
    }).write(&plain_connect, allocator);
    var connect_decoded = try decodeRequest(allocator, plain_connect.items);
    defer connect_decoded.deinit(allocator);
    try std.testing.expectEqualStrings("CONNECT", connect_decoded.method);
    try std.testing.expectEqualStrings("", connect_decoded.path);
    try std.testing.expectEqualStrings("", connect_decoded.scheme);

    try std.testing.expectError(error.InvalidContentLength, (Request{
        .method = "CONNECT",
        .path = "/must-be-omitted",
        .authority = "proxy.example.com:443",
        .headers = &.{.{ .name = "content-length", .value = "0" }},
    }).write(&plain_connect, allocator));

    try std.testing.expectError(error.InvalidContentLength, (Request{
        .method = "CONNECT",
        .path = "/must-be-omitted",
        .authority = "proxy.example.com:443",
        .body = "tunnel bytes",
    }).write(&plain_connect, allocator));

    var lowercase_connect = std.ArrayList(u8).empty;
    defer lowercase_connect.deinit(allocator);
    try (Request{
        .method = "connect",
        .path = "/ordinary-extension-method",
        .scheme = "https",
        .authority = "example.com",
        .headers = &.{.{ .name = "content-length", .value = "4" }},
        .body = "body",
    }).write(&lowercase_connect, allocator);
    var lowercase_decoded = try decodeRequest(allocator, lowercase_connect.items);
    defer lowercase_decoded.deinit(allocator);
    try std.testing.expectEqualStrings("connect", lowercase_decoded.method);
    try std.testing.expectEqualStrings("body", lowercase_decoded.body);

    var extended_connect_missing_target = std.ArrayList(u8).empty;
    defer extended_connect_missing_target.deinit(allocator);
    try Helper.writeRequestBlock(&extended_connect_missing_target, allocator, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "webtransport" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, extended_connect_missing_target.items));

    var extended_connect = std.ArrayList(u8).empty;
    defer extended_connect.deinit(allocator);
    try (Request{
        .method = "CONNECT",
        .path = "/wt",
        .scheme = "https",
        .authority = "example.com",
        .headers = &.{.{ .name = ":protocol", .value = "webtransport" }},
    }).write(&extended_connect, allocator);
    try std.testing.expectError(error.ExtendedConnectDisabled, decodeRequestWithSettings(allocator, extended_connect.items, .{}));
    var extended_decoded = try decodeRequestWithSettings(allocator, extended_connect.items, .{ .enable_connect_protocol = true });
    defer extended_decoded.deinit(allocator);
    try std.testing.expectEqualStrings("CONNECT", extended_decoded.method);
    try std.testing.expectEqualStrings("webtransport", findHeader(extended_decoded.headers, ":protocol").?);

    var invalid_protocol_token = std.ArrayList(u8).empty;
    defer invalid_protocol_token.deinit(allocator);
    try Helper.writeRequestBlock(&invalid_protocol_token, allocator, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "web transport" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, invalid_protocol_token.items));

    var bad_protocol_method = std.ArrayList(u8).empty;
    defer bad_protocol_method.deinit(allocator);
    try Helper.writeRequestBlock(&bad_protocol_method, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":protocol", .value = "webtransport" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, bad_protocol_method.items));

    var bad_value = std.ArrayList(u8).empty;
    defer bad_value.deinit(allocator);
    try Helper.writeRequestBlock(&bad_value, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "x-bad", .value = "ok\r\ninjected: yes" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, bad_value.items));

    var pseudo_trailer: std.ArrayList(u8) = .empty;
    try std.testing.expectError(error.InvalidContentLength, (Request{
        .method = "POST",
        .path = "/upload",
        .authority = "example.com",
        .headers = &.{.{ .name = "content-length", .value = "5" }},
        .body = "body",
    }).write(&pseudo_trailer, allocator));

    try std.testing.expectError(error.InvalidHeader, (Request{
        .method = "POST",
        .path = "/upload",
        .authority = "example.com",
        .body = "body",
        .trailers = &.{.{ .name = "content-length", .value = "4" }},
    }).write(&pseudo_trailer, allocator));

    try std.testing.expectError(error.InvalidHeader, (Response{
        .status = 200,
        .body = "ok",
        .trailers = &.{.{ .name = "set-cookie", .value = "a=b" }},
    }).write(&pseudo_trailer, allocator));

    defer pseudo_trailer.deinit(allocator);
    try Helper.writeRequestWithTrailers(&pseudo_trailer, allocator, &valid_request, &.{
        .{ .name = ":status", .value = "200" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, pseudo_trailer.items));

    try std.testing.expectError(error.InvalidHeader, (Request{
        .method = "GET",
        .path = "/",
        .headers = &.{.{ .name = "Connection", .value = "close" }},
    }).write(&pseudo_trailer, allocator));
}

test "HTTP/3 response encode decode" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try (Response{
        .status = 201,
        .headers = &.{.{ .name = "server", .value = "netz" }},
        .body = "created",
    }).write(&encoded, allocator);
    var default_length = try decodeResponse(allocator, encoded.items);
    defer default_length.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 201), default_length.status);
    try std.testing.expectEqualStrings("created", default_length.body);
    try std.testing.expectEqualStrings("7", findHeader(default_length.headers, "content-length") orelse return error.MissingHeader);

    encoded.clearRetainingCapacity();
    const response = Response{
        .status = 201,
        .headers = &.{
            .{ .name = "server", .value = "netz" },
            .{ .name = "content-length", .value = "7" },
        },
        .body = "created",
        .trailers = &.{.{ .name = "checksum", .value = "ok" }},
    };
    try std.testing.expect(response.successful());
    try response.write(&encoded, allocator);

    var decoded = try decodeResponse(allocator, encoded.items);
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 201), decoded.status);
    try std.testing.expect(decoded.successful());
    try std.testing.expectEqualStrings("created", decoded.body);
    try std.testing.expectEqual(@as(usize, 1), decoded.trailers.len);
    try std.testing.expectEqualStrings("checksum", decoded.trailers[0].name);
    try std.testing.expectError(error.InvalidContentLength, (Response{
        .status = 200,
        .headers = &.{.{ .name = "content-length", .value = "5" }},
        .body = "ok",
    }).write(&encoded, allocator));
    try std.testing.expectError(error.InvalidContentLength, (Response{
        .status = 204,
        .body = "body",
    }).write(&encoded, allocator));
    try std.testing.expectError(error.InvalidStatus, (Response{
        .status = 103,
    }).write(&encoded, allocator));
    try std.testing.expectError(error.InvalidStatus, (Response{
        .status = 103,
        .headers = &.{.{ .name = "content-length", .value = "0" }},
    }).write(&encoded, allocator));
    try (Response{
        .status = 304,
        .headers = &.{.{ .name = "content-length", .value = "123" }},
    }).write(&encoded, allocator);
}

test {
    _ = runtime;
}
