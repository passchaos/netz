const std = @import("std");
const wire = @import("../internal/wire.zig");
const priority_field = @import("../internal/priority.zig");
const exact_range_set = @import("../internal/exact_range_set.zig");
const http_method = @import("../internal/http_method.zig");
const quic = @import("../quic/mod.zig");
const header_fields = @import("codec/header_storage.zig");

pub const runtime = @import("runtime.zig");
pub const capsule = @import("capsule.zig");
pub const origin_pool = @import("origin_pool.zig");

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
    TooManyInformationalResponses,
    InvalidHeader,
    InvalidOrigin,
    InvalidPriorityUpdate,
    IdError,
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
pub const default_max_informational_responses: usize = 16;
/// RFC 8336 leaves the Origin Set unbounded. Apply a deterministic connection
/// state cap so an authenticated server cannot grow client memory indefinitely.
pub const max_peer_origins: usize = 256;
/// Bound total retained RFC 9218 request and push state independently of each
/// control-frame size so a peer cannot grow connection memory with unique IDs.
pub const default_max_priority_updates: usize = 256;
/// Bound partial control-frame retention, including fragmented ORIGIN frames.
pub const max_control_stream_buffer_size: usize = 64 * 1024;

pub const ApplicationErrorCode = struct {
    /// RFC 9297 malformed HTTP Datagram association/context identifier.
    pub const datagram_error: u64 = 0x33;
    pub const no_error: u64 = 0x100;
    pub const general_protocol_error: u64 = 0x101;
    pub const internal_error: u64 = 0x102;
    pub const stream_creation_error: u64 = 0x103;
    pub const closed_critical_stream: u64 = 0x104;
    pub const frame_unexpected: u64 = 0x105;
    pub const frame_error: u64 = 0x106;
    pub const excessive_load: u64 = 0x107;
    pub const id_error: u64 = 0x108;
    pub const settings_error: u64 = 0x109;
    pub const missing_settings: u64 = 0x10a;
    pub const request_rejected: u64 = 0x10b;
    pub const request_cancelled: u64 = 0x10c;
    pub const request_incomplete: u64 = 0x10d;
    pub const message_error: u64 = 0x10e;
    pub const connect_error: u64 = 0x10f;
    pub const version_fallback: u64 = 0x110;
    pub const qpack_decompression_failed: u64 = 0x200;
    pub const qpack_encoder_stream_error: u64 = 0x201;
    pub const qpack_decoder_stream_error: u64 = 0x202;
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

pub const OriginKey = struct {
    allocator: std.mem.Allocator,
    scheme: []u8,
    host: []u8,
    port: u16,

    pub fn deinit(self: *OriginKey) void {
        self.allocator.free(self.scheme);
        self.allocator.free(self.host);
        self.* = undefined;
    }

    pub fn origin(self: OriginKey) Origin {
        return .{
            .scheme = self.scheme,
            .host = self.host,
            .port = self.port,
        };
    }
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

/// Allocate a stable lowercase origin key for connection pools.
///
/// `requestOrigin` intentionally borrows slices from decoded request headers or
/// caller URI storage.  Pooling/reuse code often needs the normalized key to
/// outlive that decode buffer, so this helper owns lowercase scheme/host bytes
/// while keeping IPv6 literals bracket-free just like `Origin`.
pub fn requestOriginKey(
    allocator: std.mem.Allocator,
    scheme: []const u8,
    authority: []const u8,
) Error!OriginKey {
    const parsed = try requestOrigin(scheme, authority);
    return try originKeyFromOrigin(allocator, parsed);
}

/// Parse and own one RFC 6454 ASCII serialization carried by RFC 9412.
///
/// ORIGIN entries must be origins, not general URIs: userinfo, path, query and
/// fragment components are forbidden, and an explicit port is normalized to
/// the same canonical key as the scheme's default port.
pub fn requestOriginKeyFromSerialized(
    allocator: std.mem.Allocator,
    serialized: []const u8,
) Error!OriginKey {
    return originKeyFromOrigin(
        allocator,
        try originFromSerialized(serialized),
    );
}

/// Parse one RFC 6454 ASCII serialization without taking ownership.
pub fn originFromSerialized(serialized: []const u8) Error!Origin {
    const uri = std.Uri.parse(serialized) catch return error.InvalidOrigin;
    if (uri.user != null or uri.password != null or
        !uri.path.isEmpty() or uri.query != null or uri.fragment != null)
    {
        return error.InvalidOrigin;
    }
    const host_component = uri.host orelse return error.InvalidOrigin;
    const host = switch (host_component) {
        .raw, .percent_encoded => |value| value,
    };
    if (host.len == 0) return error.InvalidOrigin;
    const normalized_host = normalizeAltSvcHost(host) catch
        return error.InvalidOrigin;
    const default_port = defaultPortForScheme(uri.scheme) orelse
        return error.InvalidOrigin;
    return .{
        .scheme = uri.scheme,
        .host = normalized_host,
        .port = uri.port orelse default_port,
    };
}

/// Allocate a stable lowercase key from an already parsed origin.
///
/// This avoids re-rendering `scheme://authority` just to call
/// `requestOriginKey` when a caller has already validated and normalized the
/// origin for reuse/coalescing decisions.
pub fn originKeyFromOrigin(
    allocator: std.mem.Allocator,
    origin: Origin,
) Error!OriginKey {
    const owned_scheme = try asciiLowerAlloc(allocator, origin.scheme);
    errdefer allocator.free(owned_scheme);
    const owned_host = try asciiLowerAlloc(allocator, origin.host);
    errdefer allocator.free(owned_host);
    return .{
        .allocator = allocator,
        .scheme = owned_scheme,
        .host = owned_host,
        .port = origin.port,
    };
}

fn cloneOriginKey(
    allocator: std.mem.Allocator,
    origin: OriginKey,
) std.mem.Allocator.Error!OriginKey {
    const scheme = try allocator.dupe(u8, origin.scheme);
    errdefer allocator.free(scheme);
    const host = try allocator.dupe(u8, origin.host);
    return .{
        .allocator = allocator,
        .scheme = scheme,
        .host = host,
        .port = origin.port,
    };
}

fn cloneOrigin(
    allocator: std.mem.Allocator,
    origin: Origin,
) std.mem.Allocator.Error!OriginKey {
    const scheme = try allocator.dupe(u8, origin.scheme);
    errdefer allocator.free(scheme);
    const host = try allocator.dupe(u8, origin.host);
    return .{
        .allocator = allocator,
        .scheme = scheme,
        .host = host,
        .port = origin.port,
    };
}

pub fn sameOrigin(a: Origin, b: Origin) bool {
    return std.ascii.eqlIgnoreCase(a.scheme, b.scheme) and
        std.ascii.eqlIgnoreCase(a.host, b.host) and
        a.port == b.port;
}

fn originListContains(origins: []const OriginKey, origin: Origin) bool {
    for (origins) |candidate| {
        if (sameOrigin(candidate.origin(), origin)) return true;
    }
    return false;
}

pub const ReuseDecision = enum {
    /// Same scheme/host/port: RFC 9114 allows reuse without cross-origin
    /// coalescing policy beyond the already-established connection state.
    same_origin,
    /// Scheme and port match but host differs.  A caller may still coalesce
    /// HTTP/3 requests here, but only after proving the TLS certificate and
    /// server authority cover the requested host.
    requires_authority_validation,
    /// Scheme or port differs, so this connection is not a conservative reuse
    /// candidate.
    different_scheme_or_port,
};

pub fn connectionReuseDecision(existing: Origin, request: Origin) ReuseDecision {
    if (sameOrigin(existing, request)) return .same_origin;
    if (std.ascii.eqlIgnoreCase(existing.scheme, request.scheme) and
        existing.port == request.port)
    {
        return .requires_authority_validation;
    }
    return .different_scheme_or_port;
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

pub fn isHttp3Alpn(alpn: []const u8) bool {
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

fn asciiLowerAlloc(allocator: std.mem.Allocator, value: []const u8) std.mem.Allocator.Error![]u8 {
    const owned = try allocator.dupe(u8, value);
    for (owned) |*byte| byte.* = std.ascii.toLower(byte.*);
    return owned;
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
    /// RFC 9412 connection-authority advertisement.
    pub const origin: u64 = 0x0c;
    pub const max_push_id: u64 = 0x0d;
    pub const priority_update_request: u64 = 0x0f0700;
    pub const priority_update_push: u64 = 0x0f0701;
    pub const webtransport_stream: u64 = 0x41;
};

/// RFC 9412 ORIGIN payload. Entry slices borrow `payload`; only the descriptor
/// array is owned. Individual malformed origins are deliberately retained here
/// because RFC 8336 requires clients to ignore those entries while processing
/// the remaining frame.
pub const OriginPayload = struct {
    origins: []const []const u8,

    pub fn parse(
        allocator: std.mem.Allocator,
        payload: []const u8,
    ) Error!OriginPayload {
        if (payload.len == 0) {
            return .{ .origins = @constCast(&[_][]const u8{}) };
        }
        var cursor = wire.Cursor.init(payload);
        var count: usize = 0;
        while (!cursor.eof()) {
            const len = try cursor.readInt(u16, .big);
            _ = try cursor.readSlice(len);
            count += 1;
        }
        const origins = try allocator.alloc([]const u8, count);
        errdefer allocator.free(origins);
        cursor = wire.Cursor.init(payload);
        for (origins) |*origin| {
            const len = try cursor.readInt(u16, .big);
            origin.* = try cursor.readSlice(len);
        }
        return .{ .origins = origins };
    }

    pub fn deinit(
        self: *OriginPayload,
        allocator: std.mem.Allocator,
    ) void {
        allocator.free(self.origins);
        self.* = undefined;
    }

    pub fn write(
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        origins: []const []const u8,
    ) Error!void {
        const original_len = list.items.len;
        errdefer list.items.len = original_len;
        var payload_len: usize = 0;
        if (origins.len > max_peer_origins) return error.ExcessiveLoad;
        for (origins) |origin| {
            if (origin.len == 0 or origin.len > std.math.maxInt(u16)) {
                return error.InvalidOrigin;
            }
            _ = try originFromSerialized(origin);
            payload_len = std.math.add(
                usize,
                payload_len,
                2 + origin.len,
            ) catch return error.IntegerOverflow;
        }
        const total_len = std.math.add(
            usize,
            try frameHeaderWireLen(FrameType.origin, payload_len),
            payload_len,
        ) catch return error.IntegerOverflow;
        try list.ensureUnusedCapacity(allocator, total_len);
        try writeFrameHeader(list, allocator, FrameType.origin, payload_len);
        for (origins) |origin| {
            const start = list.items.len;
            list.items.len += 2 + origin.len;
            std.mem.writeInt(
                u16,
                list.items[start..][0..2],
                @intCast(origin.len),
                .big,
            );
            @memcpy(list.items[start + 2 ..][0..origin.len], origin);
        }
    }
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
        const payload_len_u64 = std.math.cast(u64, self.payload.len) orelse
            return error.IntegerOverflow;
        const frame_type_len = try quic.varint.length(self.frame_type);
        const payload_len_len = try quic.varint.length(payload_len_u64);
        try list.ensureUnusedCapacity(allocator, try frameWireLen(
            self.frame_type,
            self.payload.len,
        ));
        quic.varint.encodeWithLenAssumeCapacity(
            list,
            self.frame_type,
            frame_type_len,
        );
        quic.varint.encodeWithLenAssumeCapacity(
            list,
            payload_len_u64,
            payload_len_len,
        );
        list.appendSliceAssumeCapacity(self.payload);
    }
};

fn frameHeaderWireLen(frame_type: u64, payload_len: usize) Error!usize {
    const type_len = try quic.varint.length(frame_type);
    const payload_len_u64 = std.math.cast(u64, payload_len) orelse return error.IntegerOverflow;
    return std.math.add(usize, type_len, try quic.varint.length(payload_len_u64)) catch error.IntegerOverflow;
}

fn frameWireLen(frame_type: u64, payload_len: usize) Error!usize {
    return std.math.add(
        usize,
        try frameHeaderWireLen(frame_type, payload_len),
        payload_len,
    ) catch error.IntegerOverflow;
}

fn appendVarintAssumeCapacity(list: *std.ArrayList(u8), value: u64) Error!void {
    try quic.varint.encodeAssumeCapacity(list, value);
}

fn writeFrameHeader(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    frame_type: u64,
    payload_len: usize,
) Error!void {
    if (frame_type <= 63 and payload_len <= 63) {
        try list.ensureUnusedCapacity(allocator, 2);
        list.appendAssumeCapacity(@intCast(frame_type));
        list.appendAssumeCapacity(@intCast(payload_len));
        return;
    }
    const payload_len_u64 = std.math.cast(u64, payload_len) orelse
        return error.IntegerOverflow;
    const type_len = try quic.varint.length(frame_type);
    const payload_varint_len = try quic.varint.length(payload_len_u64);
    try list.ensureUnusedCapacity(
        allocator,
        @as(usize, type_len) + payload_varint_len,
    );
    quic.varint.encodeWithLenAssumeCapacity(list, frame_type, type_len);
    quic.varint.encodeWithLenAssumeCapacity(
        list,
        payload_len_u64,
        payload_varint_len,
    );
}

fn validateFrameType(frame_type: u64) Error!void {
    switch (frame_type) {
        // RFC 9114 §7.2.8 reserves the HTTP/2 frame type code points that have
        // no HTTP/3 semantics.  tquic and quic-zig reject them as
        // H3_FRAME_UNEXPECTED rather than treating them as ignorable extension
        // frames; do the same at the frame parser boundary so every stream
        // context gets consistent behavior.
        0x02, 0x06, 0x08, 0x09 => return error.UnexpectedFrame,
        // RFC 9297's WEBTRANSPORT_STREAM is a special bidirectional-stream
        // prefix followed by a Session ID, not an ordinary HTTP/3 frame with
        // a payload-length field. WebTransport routing parses it before the
        // generic frame codec; every generic frame context must reject it.
        FrameType.webtransport_stream => return error.UnexpectedFrame,
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
        const len = try self.payloadLen();
        try list.ensureUnusedCapacity(allocator, len);
        try self.writePayloadAssumeCapacity(list);
    }

    fn writePayloadAssumeCapacity(self: Settings, list: *std.ArrayList(u8)) Error!void {
        if (self.qpack_max_table_capacity != 0) try writeSetting(list, .qpack_max_table_capacity, self.qpack_max_table_capacity);
        if (self.max_field_section_size != std.math.maxInt(u64)) try writeSetting(list, .max_field_section_size, self.max_field_section_size);
        if (self.qpack_blocked_streams != 0) try writeSetting(list, .qpack_blocked_streams, self.qpack_blocked_streams);
        if (self.enable_connect_protocol) try writeSetting(list, .enable_connect_protocol, 1);
        if (self.h3_datagram) try writeSetting(list, .h3_datagram, 1);
        const webtransport_enabled = self.enable_webtransport or self.webtransport_max_sessions != 0;
        if (webtransport_enabled) {
            // Emit both legacy enable identifiers.  The historical netz name
            // for 0x2b603742 is kept for source compatibility, but writing a
            // boolean value here avoids peers that validate it as an enable bit
            // rejecting counts greater than one.  The concrete max-session
            // count is emitted below under the newer identifiers.
            try writeSetting(list, .webtransport_max_sessions, 1);
            try writeSetting(list, .enable_webtransport, 1);
        }
        if (self.webtransport_max_sessions != 0) {
            try writeSetting(list, .webtransport_max_sessions_draft, self.webtransport_max_sessions);
            try writeSetting(list, .webtransport_max_sessions_v13, self.webtransport_max_sessions);
        }
        if (self.webtransport_initial_max_data != 0) try writeSetting(list, .webtransport_initial_max_data, self.webtransport_initial_max_data);
        if (self.webtransport_initial_max_streams_uni != 0) try writeSetting(list, .webtransport_initial_max_streams_uni, self.webtransport_initial_max_streams_uni);
        if (self.webtransport_initial_max_streams_bidi != 0) try writeSetting(list, .webtransport_initial_max_streams_bidi, self.webtransport_initial_max_streams_bidi);
    }

    pub fn payloadLen(self: Settings) Error!usize {
        try self.validateLocal();
        var len: usize = 0;
        if (self.qpack_max_table_capacity != 0) len = try addSettingLen(len, .qpack_max_table_capacity, self.qpack_max_table_capacity);
        if (self.max_field_section_size != std.math.maxInt(u64)) len = try addSettingLen(len, .max_field_section_size, self.max_field_section_size);
        if (self.qpack_blocked_streams != 0) len = try addSettingLen(len, .qpack_blocked_streams, self.qpack_blocked_streams);
        if (self.enable_connect_protocol) len = try addSettingLen(len, .enable_connect_protocol, 1);
        if (self.h3_datagram) len = try addSettingLen(len, .h3_datagram, 1);
        const webtransport_enabled = self.enable_webtransport or self.webtransport_max_sessions != 0;
        if (webtransport_enabled) {
            len = try addSettingLen(len, .webtransport_max_sessions, 1);
            len = try addSettingLen(len, .enable_webtransport, 1);
        }
        if (self.webtransport_max_sessions != 0) {
            len = try addSettingLen(len, .webtransport_max_sessions_draft, self.webtransport_max_sessions);
            len = try addSettingLen(len, .webtransport_max_sessions_v13, self.webtransport_max_sessions);
        }
        if (self.webtransport_initial_max_data != 0) len = try addSettingLen(len, .webtransport_initial_max_data, self.webtransport_initial_max_data);
        if (self.webtransport_initial_max_streams_uni != 0) len = try addSettingLen(len, .webtransport_initial_max_streams_uni, self.webtransport_initial_max_streams_uni);
        if (self.webtransport_initial_max_streams_bidi != 0) len = try addSettingLen(len, .webtransport_initial_max_streams_bidi, self.webtransport_initial_max_streams_bidi);
        return len;
    }

    pub fn validateLocal(self: Settings) Error!void {
        if (self.qpack_blocked_streams > max_supported_qpack_blocked_streams) {
            return error.QpackDynamicTableUnsupported;
        }
        if (self.qpack_max_table_capacity > quic.varint.max_value or
            (self.max_field_section_size != std.math.maxInt(u64) and
                self.max_field_section_size > quic.varint.max_value) or
            self.webtransport_max_sessions > quic.varint.max_value or
            self.webtransport_initial_max_data > quic.varint.max_value or
            self.webtransport_initial_max_streams_uni > quic.varint.max_value or
            self.webtransport_initial_max_streams_bidi > quic.varint.max_value)
        {
            return error.InvalidSetting;
        }
        if (std.math.cast(usize, self.qpack_max_table_capacity) == null) {
            return error.InvalidSetting;
        }
    }

    /// Validate the server SETTINGS that govern an accepted 0-RTT request.
    /// A server may increase remembered limits, but accepting early data and
    /// then reducing a capability the client was permitted to use would make
    /// already-sent HTTP/3 bytes invalid.
    pub fn validateAfterEarlyDataAccepted(
        remembered: Settings,
        current: Settings,
    ) Error!void {
        if (current.qpack_max_table_capacity <
            remembered.qpack_max_table_capacity or
            current.max_field_section_size <
                remembered.max_field_section_size or
            current.qpack_blocked_streams < remembered.qpack_blocked_streams or
            (remembered.enable_connect_protocol and
                !current.enable_connect_protocol) or
            (remembered.h3_datagram and !current.h3_datagram) or
            (remembered.enable_webtransport and
                !current.enable_webtransport) or
            current.webtransport_max_sessions <
                remembered.webtransport_max_sessions or
            current.webtransport_initial_max_data <
                remembered.webtransport_initial_max_data or
            current.webtransport_initial_max_streams_uni <
                remembered.webtransport_initial_max_streams_uni or
            current.webtransport_initial_max_streams_bidi <
                remembered.webtransport_initial_max_streams_bidi)
        {
            return error.InvalidSetting;
        }
    }
};

fn addFrameLen(a: usize, b: usize) Error!usize {
    return std.math.add(usize, a, b) catch error.IntegerOverflow;
}

fn settingLen(id: SettingId, value: u64) Error!usize {
    const id_len = try quic.varint.length(@intFromEnum(id));
    return addFrameLen(id_len, try quic.varint.length(value));
}

fn addSettingLen(current: usize, id: SettingId, value: u64) Error!usize {
    return addFrameLen(current, try settingLen(id, value));
}

fn writeSetting(list: *std.ArrayList(u8), id: SettingId, value: u64) Error!void {
    try appendVarintAssumeCapacity(list, @intFromEnum(id));
    try appendVarintAssumeCapacity(list, value);
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
    pub const Options = struct {
        /// Shared cap across request- and push-element priority entries.
        max_priority_updates: usize = default_max_priority_updates,
    };

    const PriorityUpdateKey = struct {
        frame_type: u64,
        prioritized_element_id: u64,
    };

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

    /// Optional semantic validation performed for each complete control frame
    /// immediately before it mutates connection state. Runtime layers use this
    /// hook for checks that depend on transport limits or application-owned
    /// push metadata, neither of which belongs in the wire codec.
    pub const FrameDisposition = enum { apply, ignore };

    pub const FrameValidator = struct {
        context: *const anyopaque,
        validate: *const fn (
            context: *const anyopaque,
            state: ControlState,
            frame: Frame,
        ) Error!FrameDisposition,

        fn validateFrame(
            self: FrameValidator,
            state: ControlState,
            frame: Frame,
        ) Error!FrameDisposition {
            return self.validate(self.context, state, frame);
        }
    };

    settings: SettingsState = .{},
    /// Server settings remembered by a client that sent 0-RTT. Consumed by
    /// the first peer SETTINGS frame before any dependent response is routed.
    early_data_peer_settings: ?Settings = null,
    peer_goaway_id: ?u64 = null,
    local_goaway_id: ?u64 = null,
    /// Server-advertised RFC 9412 Origin Set additions, in first-seen order.
    /// The first successfully processed ORIGIN frame initializes the set even
    /// when it is empty; the client must then stop using implicit coalescing.
    peer_origins: std.ArrayList(OriginKey) = .empty,
    /// Origins removed after a 421 response, including the implicit initial
    /// origin which is not otherwise stored in `peer_origins`.
    peer_origin_exclusions: std.ArrayList(OriginKey) = .empty,
    peer_origin_set_initialized: bool = false,
    peer_origin_generation: u64 = 0,
    local_origin_set_sent: bool = false,
    peer_max_push_id: ?u64 = null,
    local_max_push_id: ?u64 = null,
    /// Counts successfully applied client-only frames even when a duplicate
    /// leaves their value state unchanged. Runtime role checks compare this
    /// generation after buffered parsing, including split control frames.
    peer_client_only_frame_generation: u64 = 0,
    /// Exact lifetime cancellation history. Sequential IDs use only the
    /// embedded prefix; sparse IDs are retained as merged ranges.
    peer_cancelled_push_ids: exact_range_set.Set = .{},
    push_cancellation_generation: u64 = 0,
    peer_control_stream_id: ?u64 = null,
    /// Absolute QUIC stream offset through which peer control bytes have been
    /// applied to this HTTP/3 control state. QUIC may retransmit STREAM ranges
    /// under new packet numbers; without this cursor, a duplicate offset-zero
    /// control frame would re-apply SETTINGS and incorrectly surface as
    /// H3_SETTINGS_ERROR.
    peer_control_stream_consumed_offset: usize = 0,
    /// Incomplete control-frame bytes retained across QUIC STREAM boundaries.
    peer_control_stream_buffer: std.ArrayList(u8) = .empty,
    latest_priority_update: ?PriorityUpdatePayload = null,
    latest_priority_update_type: ?u64 = null,
    priority_updates: std.ArrayList(StoredPriorityUpdate) = .empty,
    priority_update_index: std.AutoHashMapUnmanaged(PriorityUpdateKey, usize) = .empty,
    priority_update_generation: u64 = 0,
    max_priority_updates: usize = default_max_priority_updates,
    /// Coarse retirement watermarks keep late updates from turning completed
    /// elements back into retained state. Advancing a watermark may also drop
    /// priority hints for lower idle request IDs or older promised push IDs;
    /// RFC 9218 explicitly permits ignoring priority signals, and this bounded
    /// policy is preferable to lifetime tombstone growth.
    retired_request_priority_through: ?u64 = null,
    retired_push_priority_through: ?u64 = null,
    peer_qpack_encoder_stream_id: ?u64 = null,
    peer_qpack_decoder_stream_id: ?u64 = null,
    peer_qpack_encoder_stream_consumed_offset: usize = 0,
    peer_qpack_decoder_stream_consumed_offset: usize = 0,

    pub fn init(options: Options) Error!ControlState {
        if (options.max_priority_updates == 0) return error.InvalidSetting;
        return .{ .max_priority_updates = options.max_priority_updates };
    }

    pub fn deinit(self: *ControlState, allocator: std.mem.Allocator) void {
        for (self.peer_origins.items) |*origin| origin.deinit();
        self.peer_origins.deinit(allocator);
        for (self.peer_origin_exclusions.items) |*origin| origin.deinit();
        self.peer_origin_exclusions.deinit(allocator);
        self.peer_control_stream_buffer.deinit(allocator);
        for (self.priority_updates.items) |*update| {
            update.deinit(allocator);
        }
        self.priority_updates.deinit(allocator);
        self.priority_update_index.deinit(allocator);
        self.peer_cancelled_push_ids.deinit(allocator);
        self.* = undefined;
    }

    pub fn clone(
        self: ControlState,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!ControlState {
        return self.cloneWithControlBufferLen(
            allocator,
            self.peer_control_stream_buffer.items.len,
        );
    }

    fn cloneWithControlBufferLen(
        self: ControlState,
        allocator: std.mem.Allocator,
        control_buffer_len: usize,
    ) std.mem.Allocator.Error!ControlState {
        std.debug.assert(
            control_buffer_len <= self.peer_control_stream_buffer.items.len,
        );
        var copy = self;
        copy.latest_priority_update = null;
        copy.peer_origins = .empty;
        copy.peer_origin_exclusions = .empty;
        copy.peer_control_stream_buffer = .empty;
        copy.priority_updates = .empty;
        copy.priority_update_index = .empty;
        copy.peer_cancelled_push_ids = .{};
        errdefer copy.deinit(allocator);
        try copy.peer_origins.ensureTotalCapacity(
            allocator,
            self.peer_origins.items.len,
        );
        for (self.peer_origins.items) |origin| {
            const owned = try cloneOriginKey(allocator, origin);
            copy.peer_origins.appendAssumeCapacity(owned);
        }
        try copy.peer_origin_exclusions.ensureTotalCapacity(
            allocator,
            self.peer_origin_exclusions.items.len,
        );
        for (self.peer_origin_exclusions.items) |origin| {
            const owned = try cloneOriginKey(allocator, origin);
            copy.peer_origin_exclusions.appendAssumeCapacity(owned);
        }
        try copy.peer_control_stream_buffer.appendSlice(
            allocator,
            self.peer_control_stream_buffer.items[0..control_buffer_len],
        );
        copy.peer_cancelled_push_ids =
            try self.peer_cancelled_push_ids.clone(allocator);
        try copy.priority_updates.ensureTotalCapacity(
            allocator,
            self.priority_updates.items.len,
        );
        try copy.priority_update_index.ensureUnusedCapacity(
            allocator,
            std.math.cast(u32, self.priority_updates.items.len) orelse
                return error.OutOfMemory,
        );
        var latest_index: ?usize = null;
        for (self.priority_updates.items) |update| {
            const owned = try allocator.dupe(
                u8,
                update.payload.field_value,
            );
            const index = copy.priority_updates.items.len;
            const copied = StoredPriorityUpdate{
                .frame_type = update.frame_type,
                .payload = .{
                    .prioritized_element_id = update.payload.prioritized_element_id,
                    .field_value = owned,
                },
            };
            copy.priority_updates.appendAssumeCapacity(copied);
            copy.priority_update_index.putAssumeCapacity(
                priorityUpdateKey(copied.frame_type, copied.payload.prioritized_element_id),
                index,
            );
            if (self.latest_priority_update) |latest| {
                if (self.latest_priority_update_type == update.frame_type and
                    latest.prioritized_element_id ==
                        update.payload.prioritized_element_id)
                {
                    latest_index = index;
                }
            }
        }
        if (latest_index) |index| {
            // Replacement and swap-removal deliberately do not keep the
            // backing array in generation order. Rebind the compatibility
            // view while cloning rather than assuming the array tail is the
            // most recently processed update. Tracking the index here also
            // avoids a hash lookup that would use borrowed state as a key.
            copy.latest_priority_update = copy.priority_updates.items[index].payload;
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
        var storage: [max_single_varint_frame_len]u8 = undefined;
        const bytes = try writeSingleVarintFrameInto(
            &storage,
            FrameType.goaway,
            stream_id,
        );
        try list.ensureUnusedCapacity(allocator, bytes.len);
        list.appendSliceAssumeCapacity(bytes);
        self.local_goaway_id = stream_id;
    }

    /// Encodes GOAWAY into caller storage and commits the monotonic local ID
    /// only after validation and encoding have succeeded.
    pub fn writeGoAwayInto(
        self: *ControlState,
        storage: *[max_single_varint_frame_len]u8,
        stream_id: u64,
    ) Error![]const u8 {
        if (self.local_goaway_id) |previous| {
            if (stream_id > previous) return error.GoAwayIdIncreased;
        }

        const bytes = try writeSingleVarintFrameInto(storage, FrameType.goaway, stream_id);
        self.local_goaway_id = stream_id;
        return bytes;
    }

    pub fn writeMaxPushId(self: *ControlState, list: *std.ArrayList(u8), allocator: std.mem.Allocator, push_id: u64) Error!void {
        if (self.local_max_push_id) |previous| {
            if (push_id < previous) return error.MaxPushIdReduced;
        }
        var storage: [max_single_varint_frame_len]u8 = undefined;
        const bytes = try writeMaxPushIdFrameInto(&storage, push_id);
        try list.ensureUnusedCapacity(allocator, bytes.len);
        list.appendSliceAssumeCapacity(bytes);
        self.local_max_push_id = push_id;
    }

    /// Encodes MAX_PUSH_ID into caller storage and updates state only after a
    /// valid frame has been produced.
    pub fn writeMaxPushIdInto(
        self: *ControlState,
        storage: *[max_single_varint_frame_len]u8,
        push_id: u64,
    ) Error![]const u8 {
        if (self.local_max_push_id) |previous| {
            if (push_id < previous) return error.MaxPushIdReduced;
        }
        const bytes = try writeMaxPushIdFrameInto(storage, push_id);
        self.local_max_push_id = push_id;
        return bytes;
    }

    /// Append one RFC 9412 ORIGIN frame and commit the local advertisement
    /// marker only after all validation and allocation succeeds. Servers may
    /// call this repeatedly to add origins; an empty first frame deliberately
    /// restricts clients to the connection's initial origin.
    pub fn writeOrigins(
        self: *ControlState,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        origins: []const []const u8,
    ) Error!void {
        try OriginPayload.write(list, allocator, origins);
        self.local_origin_set_sent = true;
    }

    pub fn hasSentOriginSet(self: ControlState) bool {
        return self.local_origin_set_sent;
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

    /// Append contiguous control-stream bytes and apply every complete frame.
    /// A split type, length, or payload remains buffered for the next STREAM
    /// fragment. The fixed cap prevents unknown or oversized extension frames
    /// from turning a critical stream into unbounded connection memory.
    pub fn appendControlPayload(
        self: *ControlState,
        allocator: std.mem.Allocator,
        payload: []const u8,
    ) Error!void {
        return self.appendControlPayloadValidated(
            allocator,
            payload,
            null,
        );
    }

    pub fn appendControlPayloadValidated(
        self: *ControlState,
        allocator: std.mem.Allocator,
        payload: []const u8,
        validator: ?FrameValidator,
    ) Error!void {
        if (payload.len > max_control_stream_buffer_size -|
            self.peer_control_stream_buffer.items.len)
        {
            return error.ExcessiveLoad;
        }
        const previous_buffer_len = self.peer_control_stream_buffer.items.len;
        try self.peer_control_stream_buffer.appendSlice(allocator, payload);
        // Delay the deep snapshot until a complete frame can actually mutate
        // state. Incomplete input and ignorable extension frames only touch
        // the bounded byte buffer.
        var previous: ?ControlState = null;
        defer if (previous) |*value| value.deinit(allocator);
        errdefer {
            if (previous) |value| {
                self.deinit(allocator);
                self.* = value;
                previous = null;
            } else {
                self.peer_control_stream_buffer.items.len =
                    previous_buffer_len;
            }
        }
        var consumed: usize = 0;
        while (consumed < self.peer_control_stream_buffer.items.len) {
            const remaining = self.peer_control_stream_buffer.items[consumed..];
            const header = Frame.parseHeader(remaining) catch |err| switch (err) {
                error.BufferTooShort => break,
                else => return err,
            };
            if (header.payload_length > max_control_stream_buffer_size) {
                return error.ExcessiveLoad;
            }
            const total = try header.totalLength();
            if (remaining.len < total) break;
            const frame = Frame{
                .frame_type = header.frame_type,
                .payload = remaining[header.header_length..total],
                .consumed = total,
            };
            // A semantic validator may choose to ignore an obsolete advisory
            // frame, but it must not bypass the control stream's mandatory
            // SETTINGS-first ordering.
            if (!self.settings.received and
                frame.frame_type != FrameType.settings)
            {
                return error.MissingSettings;
            }
            if (validator) |value| {
                if (try value.validateFrame(self.*, frame) == .ignore) {
                    consumed += total;
                    continue;
                }
            }
            if (self.settings.received and
                !controlFrameMayMutateOrError(frame.frame_type))
            {
                consumed += total;
                continue;
            }
            if (previous == null) {
                previous = try self.cloneWithControlBufferLen(
                    allocator,
                    previous_buffer_len,
                );
            }
            try self.applyFrame(allocator, frame);
            consumed += total;
        }
        if (consumed == 0) return;
        const retained = self.peer_control_stream_buffer.items.len - consumed;
        if (retained != 0) {
            std.mem.copyForwards(
                u8,
                self.peer_control_stream_buffer.items[0..retained],
                self.peer_control_stream_buffer.items[consumed..],
            );
        }
        self.peer_control_stream_buffer.items.len = retained;
    }

    fn controlFrameMayMutateOrError(frame_type: u64) bool {
        return switch (frame_type) {
            FrameType.settings,
            FrameType.goaway,
            FrameType.max_push_id,
            FrameType.cancel_push,
            FrameType.origin,
            FrameType.priority_update_request,
            FrameType.priority_update_push,
            FrameType.data,
            FrameType.headers,
            FrameType.push_promise,
            FrameType.webtransport_stream,
            => true,
            else => false,
        };
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
                const received = Settings.fromList(raw);
                if (self.early_data_peer_settings) |remembered| {
                    try remembered.validateAfterEarlyDataAccepted(received);
                }
                self.settings.markReceived(received);
                self.early_data_peer_settings = null;
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
                self.peer_client_only_frame_generation = std.math.add(
                    u64,
                    self.peer_client_only_frame_generation,
                    1,
                ) catch return error.InvalidFrame;
                self.peer_max_push_id = push_id;
            },
            FrameType.cancel_push => {
                const push_id = try parseSingleVarintPayload(frame.payload);
                try self.storePushCancellation(allocator, push_id);
                self.peer_client_only_frame_generation = std.math.add(
                    u64,
                    self.peer_client_only_frame_generation,
                    1,
                ) catch return error.InvalidFrame;
            },
            FrameType.origin => try self.applyOriginFrame(
                allocator,
                frame.payload,
            ),
            FrameType.priority_update_request => {
                const priority_update = try parsePriorityUpdatePayload(frame.payload);
                validateRequestStreamId(
                    priority_update.prioritized_element_id,
                ) catch return error.IdError;
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
            FrameType.data,
            FrameType.headers,
            FrameType.push_promise,
            FrameType.webtransport_stream,
            => return error.UnexpectedFrame,
            else => {}, // Unknown extension frames on the control stream are ignored.
        }
    }

    pub fn acceptsRequestStream(self: ControlState, stream_id: u64) bool {
        const goaway_id = self.peer_goaway_id orelse return true;
        return stream_id < goaway_id;
    }

    pub fn peerOrigins(self: ControlState) []const OriginKey {
        return self.peer_origins.items;
    }

    pub fn peerOriginSetInitialized(self: ControlState) bool {
        return self.peer_origin_set_initialized;
    }

    pub fn peerOriginKnown(self: ControlState, origin: Origin) bool {
        return originListContains(self.peer_origins.items, origin);
    }

    /// Return null until the first ORIGIN frame initializes authority policy.
    /// Once initialized, the RFC 8336 Origin Set always includes the initial
    /// connection origin plus every valid advertised addition. Certificate
    /// verification remains a separate mandatory caller check.
    pub fn peerOriginSetAllows(
        self: ControlState,
        initial_origin: Origin,
        requested_origin: Origin,
    ) ?bool {
        if (!self.peer_origin_set_initialized) return null;
        if (originListContains(
            self.peer_origin_exclusions.items,
            requested_origin,
        )) return false;
        return sameOrigin(initial_origin, requested_origin) or
            self.peerOriginKnown(requested_origin);
    }

    fn applyOriginFrame(
        self: *ControlState,
        allocator: std.mem.Allocator,
        payload: []const u8,
    ) Error!void {
        const next_generation = std.math.add(
            u64,
            self.peer_origin_generation,
            1,
        ) catch return error.InvalidFrame;
        var parsed = try OriginPayload.parse(allocator, payload);
        defer parsed.deinit(allocator);
        var additions: std.ArrayList(OriginKey) = .empty;
        defer {
            for (additions.items) |*origin| origin.deinit();
            additions.deinit(allocator);
        }
        for (parsed.origins) |origin| {
            var key = requestOriginKeyFromSerialized(
                allocator,
                origin,
            ) catch |err| switch (err) {
                error.InvalidOrigin => continue,
                else => return err,
            };
            var duplicate = self.peerOriginKnown(key.origin());
            if (!duplicate) for (additions.items) |candidate| {
                if (sameOrigin(candidate.origin(), key.origin())) {
                    duplicate = true;
                    break;
                }
            };
            if (duplicate) {
                key.deinit();
                continue;
            }
            if (self.peer_origins.items.len + additions.items.len >=
                max_peer_origins)
            {
                key.deinit();
                return error.ExcessiveLoad;
            }
            additions.append(allocator, key) catch |err| {
                key.deinit();
                return err;
            };
        }
        try self.peer_origins.ensureUnusedCapacity(
            allocator,
            additions.items.len,
        );
        self.peer_origins.appendSliceAssumeCapacity(additions.items);
        additions.items.len = 0;
        // A later ORIGIN frame can re-add an origin removed by a 421 response.
        var excluded_index: usize = 0;
        while (excluded_index < self.peer_origin_exclusions.items.len) {
            if (!self.peerOriginKnown(
                self.peer_origin_exclusions.items[excluded_index].origin(),
            )) {
                excluded_index += 1;
                continue;
            }
            var removed = self.peer_origin_exclusions.orderedRemove(
                excluded_index,
            );
            removed.deinit();
        }
        self.peer_origin_set_initialized = true;
        self.peer_origin_generation = next_generation;
    }

    /// RFC 8336 removes an origin after a 421 response. The initial origin is
    /// supplied by the connection owner because this codec state does not own
    /// SNI or peer-address metadata. Removal is idempotent and preserves order.
    pub fn removePeerOrigin(
        self: *ControlState,
        allocator: std.mem.Allocator,
        origin: Origin,
    ) Error!void {
        if (!originListContains(self.peer_origin_exclusions.items, origin)) {
            if (self.peer_origin_exclusions.items.len >= max_peer_origins) {
                return error.ExcessiveLoad;
            }
            var owned = try cloneOrigin(allocator, origin);
            errdefer owned.deinit();
            try self.peer_origin_exclusions.append(allocator, owned);
        }
        for (self.peer_origins.items, 0..) |candidate, index| {
            if (!sameOrigin(candidate.origin(), origin)) continue;
            var removed = self.peer_origins.orderedRemove(index);
            removed.deinit();
            return;
        }
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
        if (self.priority_update_index.count() == 0) return null;
        const key = priorityUpdateKey(frame_type, prioritized_element_id);
        const index = self.priority_update_index.get(key) orelse return null;
        if (index >= self.priority_updates.items.len) return null;
        const update = self.priority_updates.items[index];
        if (update.frame_type != frame_type or
            update.payload.prioritized_element_id != prioritized_element_id)
        {
            return null;
        }
        return update.payload;
    }

    /// Forget request priority after the corresponding request becomes
    /// terminal. Removal is idempotent and repairs the swap-moved index entry.
    pub fn removeRequestPriority(
        self: *ControlState,
        allocator: std.mem.Allocator,
        stream_id: u64,
    ) void {
        self.removePriorityUpdate(
            allocator,
            FrameType.priority_update_request,
            stream_id,
        );
    }

    /// Forget push priority once the promised push is cancelled or its stream
    /// is complete. Keeping both element namespaces recyclable makes the bound
    /// a memory limit rather than a lifetime quota on long-lived connections.
    pub fn removePushPriority(
        self: *ControlState,
        allocator: std.mem.Allocator,
        push_id: u64,
    ) void {
        self.removePriorityUpdate(
            allocator,
            FrameType.priority_update_push,
            push_id,
        );
    }

    /// Mark a request priority namespace prefix as terminal and discard all
    /// retained hints in that prefix. Future late updates are discarded by
    /// `discardRetiredPriorityUpdates` after runtime validation.
    pub fn retireRequestPriority(
        self: *ControlState,
        allocator: std.mem.Allocator,
        stream_id: u64,
    ) void {
        self.retired_request_priority_through = if (self.retired_request_priority_through) |previous| @max(previous, stream_id) else stream_id;
        self.removePriorityPrefix(
            allocator,
            FrameType.priority_update_request,
            self.retired_request_priority_through.?,
        );
    }

    /// Mark a push priority namespace prefix as terminal. Push scheduling hints
    /// below the watermark may be discarded because priorities are advisory.
    pub fn retirePushPriority(
        self: *ControlState,
        allocator: std.mem.Allocator,
        push_id: u64,
    ) void {
        self.retired_push_priority_through = if (self.retired_push_priority_through) |previous| @max(previous, push_id) else push_id;
        self.removePriorityPrefix(
            allocator,
            FrameType.priority_update_push,
            self.retired_push_priority_through.?,
        );
    }

    /// Expose retained entries read-only so a runtime can validate or apply
    /// every update decoded from a batched control-stream fragment. Callers
    /// must not retain the slice across another mutating control operation.
    pub fn priorityUpdates(self: ControlState) []const StoredPriorityUpdate {
        return self.priority_updates.items;
    }

    /// Reclaim hints for element-ID prefixes the runtime has declared
    /// terminal. Calling this after each control-stream fragment also discards
    /// late updates without retaining an unbounded set of closed IDs.
    pub fn discardRetiredPriorityUpdates(
        self: *ControlState,
        allocator: std.mem.Allocator,
    ) void {
        if (self.retired_request_priority_through) |through| {
            self.removePriorityPrefix(
                allocator,
                FrameType.priority_update_request,
                through,
            );
        }
        if (self.retired_push_priority_through) |through| {
            self.removePriorityPrefix(
                allocator,
                FrameType.priority_update_push,
                through,
            );
        }
    }

    pub fn pushCancelled(self: ControlState, push_id: u64) bool {
        return self.peer_cancelled_push_ids.contains(push_id);
    }

    pub fn cancelledPushRangeCount(self: ControlState) usize {
        return self.peer_cancelled_push_ids.rangeCount();
    }

    fn storePushCancellation(
        self: *ControlState,
        allocator: std.mem.Allocator,
        push_id: u64,
    ) Error!void {
        if (self.peer_cancelled_push_ids.contains(push_id)) {
            return;
        }
        const next_generation = std.math.add(
            u64,
            self.push_cancellation_generation,
            1,
        ) catch return error.InvalidFrame;
        try self.peer_cancelled_push_ids.prepareInsertValue(
            allocator,
            push_id,
        );
        self.peer_cancelled_push_ids.insertAssumeCapacity(push_id);
        self.push_cancellation_generation = next_generation;
        self.retirePushPriority(allocator, push_id);
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
        const key = priorityUpdateKey(
            frame_type,
            update.prioritized_element_id,
        );
        if (self.priority_update_index.count() != 0) {
            if (self.priority_update_index.get(key)) |index| {
                const stored = &self.priority_updates.items[index];
                if (std.mem.eql(u8, stored.payload.field_value, update.field_value)) {
                    self.latest_priority_update_type = frame_type;
                    self.latest_priority_update = stored.payload;
                    self.priority_update_generation = next_generation;
                    return;
                }
                const owned = try allocator.dupe(u8, update.field_value);
                errdefer allocator.free(owned);
                allocator.free(stored.payload.field_value);
                stored.payload.field_value = owned;
                self.latest_priority_update_type = frame_type;
                self.latest_priority_update = .{
                    .prioritized_element_id = update.prioritized_element_id,
                    .field_value = owned,
                };
                self.priority_update_generation = next_generation;
                return;
            }
        }
        if (self.priority_updates.items.len >= self.max_priority_updates) {
            return error.ExcessiveLoad;
        }
        const slot = try self.priority_update_index.getOrPut(allocator, key);
        std.debug.assert(!slot.found_existing);
        errdefer _ = self.priority_update_index.remove(key);

        const owned = try allocator.dupe(u8, update.field_value);
        errdefer allocator.free(owned);
        try self.priority_updates.ensureUnusedCapacity(allocator, 1);
        const insert_index = self.priority_updates.items.len;
        self.priority_updates.appendAssumeCapacity(.{
            .frame_type = frame_type,
            .payload = .{
                .prioritized_element_id = update.prioritized_element_id,
                .field_value = owned,
            },
        });
        slot.value_ptr.* = insert_index;
        self.latest_priority_update_type = frame_type;
        self.latest_priority_update = .{
            .prioritized_element_id = update.prioritized_element_id,
            .field_value = owned,
        };
        self.priority_update_generation = next_generation;
    }

    fn removePriorityUpdate(
        self: *ControlState,
        allocator: std.mem.Allocator,
        frame_type: u64,
        prioritized_element_id: u64,
    ) void {
        const key = priorityUpdateKey(frame_type, prioritized_element_id);
        const index = self.priority_update_index.get(key) orelse return;
        const removed_was_latest = self.latest_priority_update_type == frame_type and
            self.latest_priority_update != null and
            self.latest_priority_update.?.prioritized_element_id ==
                prioritized_element_id;
        _ = self.priority_update_index.remove(key);
        var removed = self.priority_updates.swapRemove(index);
        removed.deinit(allocator);
        if (index < self.priority_updates.items.len) {
            const moved = self.priority_updates.items[index];
            const moved_key = priorityUpdateKey(
                moved.frame_type,
                moved.payload.prioritized_element_id,
            );
            self.priority_update_index.getPtr(moved_key).?.* = index;
        }
        if (removed_was_latest) {
            self.latest_priority_update = null;
            self.latest_priority_update_type = null;
        }
    }

    fn removePriorityPrefix(
        self: *ControlState,
        allocator: std.mem.Allocator,
        frame_type: u64,
        through: u64,
    ) void {
        var index: usize = 0;
        while (index < self.priority_updates.items.len) {
            const update = self.priority_updates.items[index];
            if (update.frame_type != frame_type or
                update.payload.prioritized_element_id > through)
            {
                index += 1;
                continue;
            }
            self.removePriorityUpdate(
                allocator,
                update.frame_type,
                update.payload.prioritized_element_id,
            );
            // swapRemove moved an unchecked entry into `index`.
        }
    }

    fn priorityUpdateKey(
        frame_type: u64,
        prioritized_element_id: u64,
    ) PriorityUpdateKey {
        return .{
            .frame_type = frame_type,
            .prioritized_element_id = prioritized_element_id,
        };
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

/// The largest supported single-varint HTTP/3 control frame: one-byte frame
/// type, one-byte encoded payload length, and an eight-byte value.
pub const max_single_varint_frame_len: usize = 1 + 1 + 8;

/// Canonical PRIORITY_UPDATE values emitted by `Priority.serialize` are at
/// most `"u=7, i"` (6 bytes). The extension frame type needs four bytes,
/// its payload length one, and the prioritized element ID at most eight.
pub const max_priority_update_frame_len: usize = 4 + 1 + 8 + 6;

pub const PriorityUpdatePayload = struct {
    prioritized_element_id: u64,
    field_value: []const u8,

    pub fn priority(self: PriorityUpdatePayload) Priority {
        return Priority.parse(self.field_value);
    }
};

pub fn writeControlStreamPrefix(list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
    try writeStreamPrefix(list, allocator, .control);
}

pub fn writeQpackEncoderStreamPrefix(list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
    try writeStreamPrefix(list, allocator, .qpack_encoder);
}

pub fn writeQpackDecoderStreamPrefix(list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
    try writeStreamPrefix(list, allocator, .qpack_decoder);
}

fn writeStreamPrefix(list: *std.ArrayList(u8), allocator: std.mem.Allocator, stream_type: StreamType) Error!void {
    try list.ensureUnusedCapacity(allocator, 1);
    list.appendAssumeCapacity(@intCast(@intFromEnum(stream_type)));
}

pub fn writeSettingsFrame(list: *std.ArrayList(u8), allocator: std.mem.Allocator, settings: Settings) Error!void {
    const original_len = list.items.len;
    errdefer list.items.len = original_len;
    const payload_len = try settings.payloadLen();
    try list.ensureUnusedCapacity(
        allocator,
        try frameWireLen(FrameType.settings, payload_len),
    );
    try writeFrameHeader(list, allocator, FrameType.settings, payload_len);
    try settings.writePayloadAssumeCapacity(list);
}

pub fn parseGoAwayPayload(payload: []const u8) Error!u64 {
    return parseSingleVarintPayload(payload);
}

pub fn writeCancelPushFrame(list: *std.ArrayList(u8), allocator: std.mem.Allocator, push_id: u64) Error!void {
    try writeSingleVarintFrame(list, allocator, FrameType.cancel_push, push_id);
}

/// Encodes a complete CANCEL_PUSH frame into caller-owned fixed storage.
pub fn writeCancelPushFrameInto(
    storage: *[max_single_varint_frame_len]u8,
    push_id: u64,
) Error![]const u8 {
    return writeSingleVarintFrameInto(storage, FrameType.cancel_push, push_id);
}

pub fn parseCancelPushPayload(payload: []const u8) Error!u64 {
    return parseSingleVarintPayload(payload);
}

pub fn writeMaxPushIdFrame(list: *std.ArrayList(u8), allocator: std.mem.Allocator, push_id: u64) Error!void {
    try writeSingleVarintFrame(list, allocator, FrameType.max_push_id, push_id);
}

/// Encodes a complete MAX_PUSH_ID frame into caller-owned fixed storage.
pub fn writeMaxPushIdFrameInto(
    storage: *[max_single_varint_frame_len]u8,
    push_id: u64,
) Error![]const u8 {
    return writeSingleVarintFrameInto(storage, FrameType.max_push_id, push_id);
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
    const push_id_len = try quic.varint.length(push_id);
    const payload_len = std.math.add(usize, push_id_len, field_section.len) catch return error.IntegerOverflow;
    try writeVarintPayloadFrame(
        list,
        allocator,
        FrameType.push_promise,
        push_id,
        payload_len,
        field_section,
    );
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
    var fields_stack: [header_fields.stack_capacity]Qpack.HeaderField = undefined;
    const fields_buf = try header_fields.acquire(
        allocator,
        &fields_stack,
        try requestHeaderFieldCapacity(promised_request, 0),
    );
    defer header_fields.release(allocator, &fields_stack, fields_buf);
    const fields = try promised_request.headerFields(fields_buf);
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
    return decodePushPromiseWithFieldDecoder(
        allocator,
        payload,
        settings,
        .{ .dynamic = table },
    );
}

fn decodePushPromiseWithFieldDecoder(
    allocator: std.mem.Allocator,
    payload: []const u8,
    settings: Settings,
    field_decoder: FieldSectionDecoder,
) Error!DecodedPushPromise {
    const promise = try parsePushPromisePayload(payload);
    var request = try decodeRequestHeadFieldSection(
        allocator,
        promise.field_section,
        settings,
        field_decoder,
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

/// Encodes a canonical request PRIORITY_UPDATE without allocating.
pub fn writePriorityUpdateFrameInto(
    storage: *[max_priority_update_frame_len]u8,
    request_stream_id: u64,
    priority: Priority,
) Error![]const u8 {
    try validateRequestStreamId(request_stream_id);
    return writePriorityUpdateFrameRawInto(
        storage,
        FrameType.priority_update_request,
        request_stream_id,
        priority,
    );
}

/// Encodes a canonical push PRIORITY_UPDATE without allocating.
pub fn writePushPriorityUpdateFrameInto(
    storage: *[max_priority_update_frame_len]u8,
    push_id: u64,
    priority: Priority,
) Error![]const u8 {
    return writePriorityUpdateFrameRawInto(
        storage,
        FrameType.priority_update_push,
        push_id,
        priority,
    );
}

fn writePriorityUpdateFrameRawInto(
    storage: *[max_priority_update_frame_len]u8,
    frame_type: u64,
    prioritized_element_id: u64,
    priority: Priority,
) Error![]const u8 {
    var field_value_storage: [6]u8 = undefined;
    const field_value = priority.serialize(&field_value_storage);
    return writeVarintPayloadFrameInto(
        storage,
        frame_type,
        prioritized_element_id,
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
    const id_len = try quic.varint.length(prioritized_element_id);
    const payload_len = std.math.add(usize, id_len, field_value.len) catch return error.IntegerOverflow;
    try writeVarintPayloadFrame(
        list,
        allocator,
        frame_type,
        prioritized_element_id,
        payload_len,
        field_value,
    );
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
    var storage: [max_single_varint_frame_len]u8 = undefined;
    const bytes = try writeSingleVarintFrameInto(&storage, frame_type, value);
    try list.ensureUnusedCapacity(allocator, bytes.len);
    list.appendSliceAssumeCapacity(bytes);
}

fn writeSingleVarintFrameInto(
    storage: *[max_single_varint_frame_len]u8,
    frame_type: u64,
    value: u64,
) Error![]const u8 {
    try validateFrameType(frame_type);
    const payload_len = try quic.varint.length(value);
    var offset: usize = 0;
    offset += (try quic.varint.encodeInto(storage[offset..], frame_type)).len;
    offset += (try quic.varint.encodeInto(storage[offset..], payload_len)).len;
    offset += (try quic.varint.encodeInto(storage[offset..], value)).len;
    return storage[0..offset];
}

fn writeVarintPayloadFrameInto(
    storage: []u8,
    frame_type: u64,
    value: u64,
    tail: []const u8,
) Error![]const u8 {
    try validateFrameType(frame_type);
    const value_len = try quic.varint.length(value);
    const payload_len = std.math.add(usize, value_len, tail.len) catch
        return error.IntegerOverflow;
    const payload_len_u64 = std.math.cast(u64, payload_len) orelse
        return error.IntegerOverflow;
    const frame_type_len = try quic.varint.length(frame_type);
    const payload_len_len = try quic.varint.length(payload_len_u64);
    const total_len = std.math.add(
        usize,
        @as(usize, frame_type_len) + payload_len_len,
        payload_len,
    ) catch return error.IntegerOverflow;
    if (storage.len < total_len) return error.BufferTooShort;

    var offset: usize = 0;
    offset += (try quic.varint.encodeInto(storage[offset..], frame_type)).len;
    offset += (try quic.varint.encodeInto(storage[offset..], payload_len_u64)).len;
    offset += (try quic.varint.encodeInto(storage[offset..], value)).len;
    @memcpy(storage[offset..][0..tail.len], tail);
    return storage[0..total_len];
}

fn writeVarintPayloadFrame(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    frame_type: u64,
    value: u64,
    payload_len: usize,
    tail: []const u8,
) Error!void {
    try validateFrameType(frame_type);
    const payload_len_u64 = std.math.cast(u64, payload_len) orelse
        return error.IntegerOverflow;
    const frame_type_len = try quic.varint.length(frame_type);
    const payload_len_len = try quic.varint.length(payload_len_u64);
    const value_len = try quic.varint.length(value);
    std.debug.assert(@as(usize, value_len) + tail.len == payload_len);
    try list.ensureUnusedCapacity(
        allocator,
        @as(usize, frame_type_len) + payload_len_len + payload_len,
    );
    quic.varint.encodeWithLenAssumeCapacity(list, frame_type, frame_type_len);
    quic.varint.encodeWithLenAssumeCapacity(list, payload_len_u64, payload_len_len);
    quic.varint.encodeWithLenAssumeCapacity(list, value, value_len);
    list.appendSliceAssumeCapacity(tail);
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
    var count: usize = 0;
    while (!cursor.eof()) {
        _ = quic.varint.decode(&cursor) catch return error.InvalidSetting;
        _ = quic.varint.decode(&cursor) catch return error.InvalidSetting;
        count += 1;
    }

    const settings = try allocator.alloc(Setting, count);
    errdefer allocator.free(settings);
    cursor = wire.Cursor.init(payload);
    for (settings, 0..) |*setting, index| {
        const id = quic.varint.decode(&cursor) catch return error.InvalidSetting;
        const value = quic.varint.decode(&cursor) catch return error.InvalidSetting;
        try validateSetting(id, value, settings[0..index]);
        setting.* = .{ .id = id, .value = value };
    }
    return settings;
}

fn validateSetting(id: u64, value: u64, seen: []const Setting) Error!void {
    for (seen) |setting| {
        if (setting.id == id) return error.InvalidSetting;
    }

    switch (id) {
        // RFC 9114 reserves HTTP/2 SETTINGS identifiers that have no HTTP/3
        // meaning.  Reference stacks such as tquic and quic-zig reject these as
        // H3_SETTINGS_ERROR instead of silently ignoring them.
        0x02, 0x03, 0x04, 0x05 => return error.InvalidSetting,
        @intFromEnum(SettingId.enable_connect_protocol),
        @intFromEnum(SettingId.h3_datagram),
        @intFromEnum(SettingId.enable_webtransport),
        => if (value > 1) return error.InvalidSetting,
        else => {},
    }
}

pub fn writeSettings(list: *std.ArrayList(u8), allocator: std.mem.Allocator, settings: []const Setting) Error!void {
    var payload_len: usize = 0;
    for (settings, 0..) |setting, index| {
        try validateSetting(setting.id, setting.value, settings[0..index]);
        payload_len = std.math.add(
            usize,
            payload_len,
            try quic.varint.length(setting.id),
        ) catch return error.IntegerOverflow;
        payload_len = std.math.add(
            usize,
            payload_len,
            try quic.varint.length(setting.value),
        ) catch return error.IntegerOverflow;
    }

    try list.ensureUnusedCapacity(allocator, payload_len);
    for (settings) |setting| {
        quic.varint.encodeWithLenAssumeCapacity(
            list,
            setting.id,
            try quic.varint.length(setting.id),
        );
        quic.varint.encodeWithLenAssumeCapacity(
            list,
            setting.value,
            try quic.varint.length(setting.value),
        );
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

fn requestHeaderFieldCapacity(request: Request, extra: usize) Error!usize {
    const extended_connect = std.mem.eql(u8, request.method, "CONNECT") and
        requestHasProtocolPseudo(request.headers);
    var pseudo_count: usize = 1;
    if (!std.mem.eql(u8, request.method, "CONNECT") or extended_connect) {
        pseudo_count += 2;
    }
    pseudo_count += @intFromBool(request.authority != null);
    return header_fields.capacity(
        try header_fields.capacity(request.headers.len, pseudo_count),
        extra,
    );
}

fn responseHeaderFieldCapacity(response: Response, extra: usize) Error!usize {
    return header_fields.capacity(
        try header_fields.capacity(response.headers.len, 1),
        extra,
    );
}

fn informationalHeaderFieldCapacity(
    response: InformationalResponse,
) Error!usize {
    return header_fields.capacity(response.headers.len, 1);
}

pub const Request = struct {
    pub const Context = enum {
        direct,
        proxy,
    };

    method: []const u8,
    path: []const u8,
    scheme: []const u8 = "https",
    authority: ?[]const u8 = null,
    headers: []const Qpack.HeaderField = &.{},
    body: []const u8 = &.{},
    trailers: []const Qpack.HeaderField = &.{},

    /// Validate request metadata and body semantics before encoding. HTTP/3
    /// uses the same pseudo-header request target for direct and proxy hops;
    /// the context is explicit so callers can share policy without importing
    /// HTTP/1 request-target rules.
    pub fn validateForContext(
        self: Request,
        context: Context,
    ) Error!void {
        switch (context) {
            .direct, .proxy => {},
        }
        try validateHttpToken(self.method);

        var saw_regular = false;
        var seen_protocol = false;
        var host_value: ?[]const u8 = null;
        var declared_content_length: ?usize = null;
        for (self.headers) |header| {
            try validateHeaderName(header.name);
            try validateHeaderValue(header.value);
            if (std.mem.startsWith(u8, header.name, ":")) {
                if (saw_regular or
                    !std.mem.eql(u8, header.name, ":protocol") or
                    seen_protocol)
                {
                    return error.InvalidHeader;
                }
                seen_protocol = true;
                try validateHttpToken(header.value);
                continue;
            }
            saw_regular = true;
            if (std.mem.eql(u8, header.name, "host")) {
                if (host_value != null) return error.InvalidHeader;
                host_value = header.value;
            }
            if (std.mem.eql(u8, header.name, "priority")) {
                _ = priority_field.Priority.parseStrict(header.value) catch
                    return error.InvalidHeader;
            }
            if (connectionSpecificHeaderName(header.name)) {
                return error.InvalidHeader;
            }
            if (std.ascii.eqlIgnoreCase(header.name, "te") and
                !std.ascii.eqlIgnoreCase(
                    std.mem.trim(u8, header.value, " \t"),
                    "trailers",
                ))
            {
                return error.InvalidHeader;
            }
            if (std.ascii.eqlIgnoreCase(header.name, "content-length")) {
                try parseContentLengthHeaderValue(
                    header.value,
                    &declared_content_length,
                );
            }
        }
        try validateHeaderBlock(self.trailers, .trailers);

        const is_connect = std.mem.eql(u8, self.method, "CONNECT");
        if (is_connect and !seen_protocol) {
            const authority = self.authority orelse return error.InvalidHeader;
            try validateConnectAuthority(authority);
        } else {
            if (seen_protocol and !is_connect) return error.InvalidHeader;
            try validateUriScheme(self.scheme);
            try validateUriPath(self.method, self.path);
            if (self.authority) |authority| {
                try validateRequestAuthority(authority);
            }
            if (host_value) |host| try validateRequestAuthority(host);
            if (self.authority) |authority| {
                if (host_value) |host| {
                    if (!std.ascii.eqlIgnoreCase(authority, host)) {
                        return error.InvalidHeader;
                    }
                }
            }
            if ((std.mem.eql(u8, self.scheme, "http") or
                std.mem.eql(u8, self.scheme, "https")) and
                ((self.authority == null or self.authority.?.len == 0) and
                    host_value == null))
            {
                return error.InvalidHeader;
            }
        }
        try validateRequestBodyForMethodValue(
            self.method,
            seen_protocol,
            declared_content_length,
            self.body,
            self.trailers,
        );
        try validateContentLengthValue(
            declared_content_length,
            self.body.len,
        );
    }

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
        var fields_stack: [header_fields.stack_capacity]Qpack.HeaderField = undefined;
        const fields_buf = try header_fields.acquire(
            allocator,
            &fields_stack,
            try requestHeaderFieldCapacity(self, 1),
        );
        defer header_fields.release(allocator, &fields_stack, fields_buf);
        var fields = try self.headerFields(fields_buf);
        const extended_connect = std.mem.eql(u8, self.method, "CONNECT") and
            requestHasProtocolPseudo(self.headers);
        var content_length_buf: [32]u8 = undefined;
        var declared_content_length = try contentLength(fields);
        if (requestShouldDefaultContentLengthValue(
            self.method,
            declared_content_length,
            self.body.len,
        )) {
            var field_count = fields.len;
            const content_length = std.fmt.bufPrint(&content_length_buf, "{}", .{self.body.len}) catch unreachable;
            try appendHeaderField(fields_buf, &field_count, .{ .name = "content-length", .value = content_length });
            fields = fields_buf[0..field_count];
            declared_content_length = self.body.len;
        }
        try validateHeaderBlock(fields, .request);
        try validateHeaderBlock(self.trailers, .trailers);
        try validateFieldSectionSize(fields, peer_settings.max_field_section_size);
        try validateFieldSectionSize(self.trailers, peer_settings.max_field_section_size);
        try validateRequestBodyForMethodValue(
            self.method,
            extended_connect,
            declared_content_length,
            self.body,
            self.trailers,
        );
        try validateContentLengthValue(declared_content_length, self.body.len);
        try writeHeadersAndData(list, allocator, fields, self.body, self.trailers);
    }

    /// Encode only the initial request HEADERS using literal/static QPACK.
    /// This is the allocation-staged counterpart used by event-loop runtimes
    /// that must submit the resulting stream prefix in one nonblocking send.
    pub fn writeStreamingHead(
        self: Request,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        peer_settings: Settings,
        body_length: ?usize,
    ) Error!struct { expected_length: ?usize, body_allowed: bool } {
        if (self.body.len != 0 or self.trailers.len != 0) {
            return error.InvalidContentLength;
        }
        var fields_stack: [header_fields.stack_capacity]Qpack.HeaderField =
            undefined;
        const fields_buf = try header_fields.acquire(
            allocator,
            &fields_stack,
            try requestHeaderFieldCapacity(self, 1),
        );
        defer header_fields.release(allocator, &fields_stack, fields_buf);
        var fields = try self.headerFields(fields_buf);
        var content_length_buf: [32]u8 = undefined;
        const extended_connect = std.mem.eql(u8, self.method, "CONNECT") and
            requestHasProtocolPseudo(self.headers);
        const plain_connect = std.mem.eql(u8, self.method, "CONNECT") and
            !extended_connect;
        if (plain_connect) {
            if (body_length) |length| {
                if (length != 0) return error.InvalidContentLength;
            }
            const declared_content_length = try contentLength(fields);
            try validateHeaderBlock(fields, .request);
            try validateFieldSectionSize(
                fields,
                peer_settings.max_field_section_size,
            );
            try validateRequestBodyForMethodValue(
                self.method,
                extended_connect,
                declared_content_length,
                &.{},
                &.{},
            );
            try writeHeadersFrame(list, allocator, fields);
            return .{ .expected_length = 0, .body_allowed = false };
        }
        const effective_length = try applyStreamingContentLength(
            fields_buf,
            &fields,
            body_length,
            &content_length_buf,
        );
        try validateHeaderBlock(fields, .request);
        try validateFieldSectionSize(
            fields,
            peer_settings.max_field_section_size,
        );
        try validateRequestBodyForMethodValue(
            self.method,
            extended_connect,
            effective_length,
            &.{},
            &.{},
        );
        try writeHeadersFrame(list, allocator, fields);
        return .{
            .expected_length = effective_length,
            .body_allowed = true,
        };
    }

    pub fn writeDynamic(
        self: Request,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        peer_settings: Settings,
        stream_id: u64,
        encoder: anytype,
    ) Error!void {
        var fields_stack: [header_fields.stack_capacity]Qpack.HeaderField = undefined;
        const fields_buf = try header_fields.acquire(
            allocator,
            &fields_stack,
            try requestHeaderFieldCapacity(self, 1),
        );
        defer header_fields.release(allocator, &fields_stack, fields_buf);
        var fields = try self.headerFields(fields_buf);
        const extended_connect = std.mem.eql(u8, self.method, "CONNECT") and
            requestHasProtocolPseudo(self.headers);
        var content_length_buf: [32]u8 = undefined;
        var declared_content_length = try contentLength(fields);
        if (requestShouldDefaultContentLengthValue(
            self.method,
            declared_content_length,
            self.body.len,
        )) {
            var field_count = fields.len;
            const content_length = std.fmt.bufPrint(
                &content_length_buf,
                "{}",
                .{self.body.len},
            ) catch unreachable;
            try appendHeaderField(fields_buf, &field_count, .{
                .name = "content-length",
                .value = content_length,
            });
            fields = fields_buf[0..field_count];
            declared_content_length = self.body.len;
        }
        try validateHeaderBlock(fields, .request);
        try validateHeaderBlock(self.trailers, .trailers);
        try validateFieldSectionSize(fields, peer_settings.max_field_section_size);
        try validateFieldSectionSize(self.trailers, peer_settings.max_field_section_size);
        try validateRequestBodyForMethodValue(
            self.method,
            extended_connect,
            declared_content_length,
            self.body,
            self.trailers,
        );
        try validateContentLengthValue(declared_content_length, self.body.len);
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
        var fields_stack: [header_fields.stack_capacity]Qpack.HeaderField = undefined;
        const fields_buf = try header_fields.acquire(
            allocator,
            &fields_stack,
            try requestHeaderFieldCapacity(self, 1),
        );
        defer header_fields.release(allocator, &fields_stack, fields_buf);
        var fields = try self.headerFields(fields_buf);
        var content_length_buf: [32]u8 = undefined;
        const extended_connect = std.mem.eql(u8, self.method, "CONNECT") and
            requestHasProtocolPseudo(self.headers);
        const plain_connect = std.mem.eql(u8, self.method, "CONNECT") and
            !extended_connect;
        if (plain_connect) {
            if (body_length) |length| {
                if (length != 0) return error.InvalidContentLength;
            }
            const declared_content_length = try contentLength(fields);
            try validateHeaderBlock(fields, .request);
            try validateFieldSectionSize(
                fields,
                peer_settings.max_field_section_size,
            );
            try validateRequestBodyForMethodValue(
                self.method,
                extended_connect,
                declared_content_length,
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
        const effective_length = try applyStreamingContentLength(
            fields_buf,
            &fields,
            body_length,
            &content_length_buf,
        );
        try validateHeaderBlock(fields, .request);
        try validateFieldSectionSize(
            fields,
            peer_settings.max_field_section_size,
        );
        try validateRequestBodyForMethodValue(
            self.method,
            extended_connect,
            effective_length,
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

fn requestShouldDefaultContentLengthValue(method: []const u8, declared_content_length: ?usize, body_len: usize) bool {
    if (std.mem.eql(u8, method, "CONNECT")) return false;
    // Align the HTTP/3 convenience writer with Hyper's h2 shaping and our
    // HTTP/2 runtime: known non-empty bodies get an explicit length, and empty
    // bodies on methods with defined payload semantics (POST/PUT/PATCH/etc.)
    // get `content-length: 0` so intermediaries and applications do not have
    // to infer intent from the absence of DATA frames.
    if (body_len == 0 and !methodHasDefinedPayloadSemantics(method)) return false;
    return declared_content_length == null;
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
    /// Optional originating request method for method-specific response
    /// semantics. Server convenience loops populate this automatically. HEAD
    /// responses advertise the representation length without DATA, while a
    /// successful traditional CONNECT cannot carry HTTP message body bytes.
    request_method: ?[]const u8 = null,
    /// True for SETTINGS-negotiated extended CONNECT. Traditional CONNECT
    /// enters tunnel mode at a successful final response; extended CONNECT
    /// retains HTTP DATA semantics for the selected protocol.
    extended_connect: bool = false,

    pub fn successful(self: Response) bool {
        return self.status >= 200 and self.status < 300;
    }

    pub fn suppressesBody(self: Response) bool {
        return responseSuppressesBody(self.status, responseSemantics(self));
    }

    /// Validate status- and request-method-specific body rules without writing
    /// bytes. Runtime streaming helpers use this before separating HEADERS,
    /// DATA, and trailers into independent transport operations.
    pub fn validateBodySemantics(self: Response) Error!void {
        const declared_content_length = try contentLength(self.headers);
        try validateOutgoingResponseBodyForStatusWithLength(
            self.status,
            declared_content_length,
            self.body,
            self.trailers,
        );
        try validateResponseBodyForRequestSemanticsWithLength(
            self.status,
            responseSemantics(self),
            declared_content_length,
            self.body,
            self.trailers,
        );
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
        var fields_stack: [header_fields.stack_capacity]Qpack.HeaderField = undefined;
        const fields_buf = try header_fields.acquire(
            allocator,
            &fields_stack,
            try responseHeaderFieldCapacity(self, 1),
        );
        defer header_fields.release(allocator, &fields_stack, fields_buf);
        var status_buf: [3]u8 = undefined;
        var fields = try self.headerFields(fields_buf, &status_buf);
        var content_length_buf: [32]u8 = undefined;
        const semantics = responseSemantics(self);
        try stripSuccessfulConnectContentLength(&fields, self.status, semantics);
        var declared_content_length = try contentLength(fields);
        if (responseShouldDefaultContentLengthValue(
            self.status,
            semantics,
            declared_content_length,
            self.body.len,
        )) {
            var field_count = fields.len;
            const content_length = std.fmt.bufPrint(&content_length_buf, "{}", .{self.body.len}) catch unreachable;
            try appendHeaderField(fields_buf, &field_count, .{ .name = "content-length", .value = content_length });
            fields = fields_buf[0..field_count];
            declared_content_length = self.body.len;
        }
        try validateHeaderBlock(fields, .response);
        try validateHeaderBlock(self.trailers, .trailers);
        try validateFieldSectionSize(fields, peer_settings.max_field_section_size);
        try validateFieldSectionSize(self.trailers, peer_settings.max_field_section_size);
        try validateOutgoingResponseBodyForStatusWithLength(
            self.status,
            declared_content_length,
            self.body,
            self.trailers,
        );
        try validateResponseBodyForRequestSemanticsWithLength(
            self.status,
            semantics,
            declared_content_length,
            self.body,
            self.trailers,
        );
        try validateContentLengthForRequestSemantics(
            self.status,
            semantics,
            declared_content_length,
            self.body.len,
        );
        try writeHeadersAndData(
            list,
            allocator,
            fields,
            if (responseSuppressesBody(self.status, semantics)) &.{} else self.body,
            if (responseSuppressesBody(self.status, semantics)) &.{} else self.trailers,
        );
    }

    pub fn writeDynamic(
        self: Response,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        peer_settings: Settings,
        stream_id: u64,
        encoder: anytype,
    ) Error!void {
        var fields_stack: [header_fields.stack_capacity]Qpack.HeaderField = undefined;
        const fields_buf = try header_fields.acquire(
            allocator,
            &fields_stack,
            try responseHeaderFieldCapacity(self, 1),
        );
        defer header_fields.release(allocator, &fields_stack, fields_buf);
        var status_buf: [3]u8 = undefined;
        var fields = try self.headerFields(fields_buf, &status_buf);
        var content_length_buf: [32]u8 = undefined;
        const semantics = responseSemantics(self);
        try stripSuccessfulConnectContentLength(&fields, self.status, semantics);
        var declared_content_length = try contentLength(fields);
        if (responseShouldDefaultContentLengthValue(
            self.status,
            semantics,
            declared_content_length,
            self.body.len,
        )) {
            var field_count = fields.len;
            const content_length = std.fmt.bufPrint(
                &content_length_buf,
                "{}",
                .{self.body.len},
            ) catch unreachable;
            try appendHeaderField(fields_buf, &field_count, .{
                .name = "content-length",
                .value = content_length,
            });
            fields = fields_buf[0..field_count];
            declared_content_length = self.body.len;
        }
        try validateHeaderBlock(fields, .response);
        try validateHeaderBlock(self.trailers, .trailers);
        try validateFieldSectionSize(fields, peer_settings.max_field_section_size);
        try validateFieldSectionSize(self.trailers, peer_settings.max_field_section_size);
        try validateOutgoingResponseBodyForStatusWithLength(
            self.status,
            declared_content_length,
            self.body,
            self.trailers,
        );
        try validateResponseBodyForRequestSemanticsWithLength(
            self.status,
            semantics,
            declared_content_length,
            self.body,
            self.trailers,
        );
        try validateContentLengthForRequestSemantics(
            self.status,
            semantics,
            declared_content_length,
            self.body.len,
        );
        try writeHeadersAndDataDynamic(
            list,
            allocator,
            fields,
            if (responseSuppressesBody(self.status, semantics)) &.{} else self.body,
            if (responseSuppressesBody(self.status, semantics)) &.{} else self.trailers,
            stream_id,
            encoder,
        );
        try queueIndexableFields(encoder, fields);
        try queueIndexableFields(encoder, self.trailers);
    }

    /// Encode only final response HEADERS with literal/static QPACK for an
    /// event-loop-owned incremental response.
    pub fn writeStreamingHead(
        self: Response,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        peer_settings: Settings,
        body_length: ?usize,
    ) Error!struct { expected_length: ?usize, body_allowed: bool } {
        if (self.body.len != 0 or self.trailers.len != 0) {
            return error.InvalidContentLength;
        }
        var fields_stack: [header_fields.stack_capacity]Qpack.HeaderField =
            undefined;
        const fields_buf = try header_fields.acquire(
            allocator,
            &fields_stack,
            try responseHeaderFieldCapacity(self, 1),
        );
        defer header_fields.release(allocator, &fields_stack, fields_buf);
        var status_buf: [3]u8 = undefined;
        var fields = try self.headerFields(fields_buf, &status_buf);
        const semantics = responseSemantics(self);
        const body_forbidden = responseSuppressesBody(
            self.status,
            semantics,
        );
        if (body_forbidden) {
            if (!semantics.head) {
                if (body_length) |length| {
                    if (length != 0) return error.InvalidContentLength;
                }
            }
            try stripSuccessfulConnectContentLength(
                &fields,
                self.status,
                semantics,
            );
            var content_length_buf: [32]u8 = undefined;
            const declared_content_length = if ((semantics.head or
                self.status == 304) and body_length != null)
                try applyStreamingContentLength(
                    fields_buf,
                    &fields,
                    body_length,
                    &content_length_buf,
                )
            else
                try contentLength(fields);
            try validateResponseBodyForRequestSemanticsWithLength(
                self.status,
                semantics,
                declared_content_length,
                &.{},
                &.{},
            );
            try validateContentLengthForRequestSemantics(
                self.status,
                semantics,
                declared_content_length,
                body_length orelse 0,
            );
            try validateHeaderBlock(fields, .response);
            try validateFieldSectionSize(
                fields,
                peer_settings.max_field_section_size,
            );
            try validateResponseBodyForStatusWithLength(
                self.status,
                declared_content_length,
                &.{},
                &.{},
            );
            try writeHeadersFrame(list, allocator, fields);
            return .{ .expected_length = 0, .body_allowed = false };
        }
        var content_length_buf: [32]u8 = undefined;
        const effective_length = try applyStreamingResponseContentLength(
            self.status,
            fields_buf,
            &fields,
            body_length,
            &content_length_buf,
        );
        try validateHeaderBlock(fields, .response);
        try validateFieldSectionSize(
            fields,
            peer_settings.max_field_section_size,
        );
        try validateOutgoingResponseBodyForStatusWithLength(
            self.status,
            effective_length,
            &.{},
            &.{},
        );
        try writeHeadersFrame(list, allocator, fields);
        return .{
            .expected_length = effective_length,
            .body_allowed = true,
        };
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
        var fields_stack: [header_fields.stack_capacity]Qpack.HeaderField = undefined;
        const fields_buf = try header_fields.acquire(
            allocator,
            &fields_stack,
            try responseHeaderFieldCapacity(self, 1),
        );
        defer header_fields.release(allocator, &fields_stack, fields_buf);
        var status_buf: [3]u8 = undefined;
        var fields = try self.headerFields(fields_buf, &status_buf);
        const semantics = responseSemantics(self);
        const body_forbidden = responseSuppressesBody(
            self.status,
            semantics,
        );
        if (body_forbidden) {
            if (!semantics.head) {
                if (body_length) |length| {
                    if (length != 0) return error.InvalidContentLength;
                }
            }
            try stripSuccessfulConnectContentLength(
                &fields,
                self.status,
                semantics,
            );
            var content_length_buf: [32]u8 = undefined;
            const declared_content_length = if ((semantics.head or
                self.status == 304) and body_length != null)
                try applyStreamingContentLength(
                    fields_buf,
                    &fields,
                    body_length,
                    &content_length_buf,
                )
            else
                try contentLength(fields);
            try validateResponseBodyForRequestSemanticsWithLength(
                self.status,
                semantics,
                declared_content_length,
                &.{},
                &.{},
            );
            try validateContentLengthForRequestSemantics(
                self.status,
                semantics,
                declared_content_length,
                body_length orelse 0,
            );
            try validateHeaderBlock(fields, .response);
            try validateFieldSectionSize(
                fields,
                peer_settings.max_field_section_size,
            );
            try validateResponseBodyForStatusWithLength(
                self.status,
                declared_content_length,
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
        const effective_length = try applyStreamingResponseContentLength(
            self.status,
            fields_buf,
            &fields,
            body_length,
            &content_length_buf,
        );
        try validateHeaderBlock(fields, .response);
        try validateFieldSectionSize(
            fields,
            peer_settings.max_field_section_size,
        );
        try validateOutgoingResponseBodyForStatusWithLength(
            self.status,
            effective_length,
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
        return .{
            .expected_length = effective_length,
            .body_allowed = true,
        };
    }
};

fn applyStreamingResponseContentLength(
    status: u16,
    fields_buf: []Qpack.HeaderField,
    fields: *[]Qpack.HeaderField,
    requested: ?usize,
    content_length_buf: *[32]u8,
) Error!?usize {
    if (status != 205) {
        return applyStreamingContentLength(
            fields_buf,
            fields,
            requested,
            content_length_buf,
        );
    }
    const declared = try contentLength(fields.*);
    if ((requested orelse 0) != 0 or (declared orelse 0) != 0) {
        return error.InvalidContentLength;
    }
    return 0;
}

fn applyStreamingContentLength(
    fields_buf: []Qpack.HeaderField,
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

pub const ResponseSemantics = struct {
    head: bool = false,
    traditional_connect: bool = false,
};

fn responseSemantics(response: Response) ResponseSemantics {
    return responseSemanticsForRequest(
        response.request_method,
        response.extended_connect,
    );
}

pub fn responseSemanticsForRequest(
    method: ?[]const u8,
    extended_connect: bool,
) ResponseSemantics {
    const value = method orelse return .{};
    return .{
        .head = std.mem.eql(u8, value, "HEAD"),
        .traditional_connect = std.mem.eql(u8, value, "CONNECT") and
            !extended_connect,
    };
}

fn responseSuppressesBody(
    status: u16,
    semantics: ResponseSemantics,
) bool {
    if ((status >= 100 and status < 200) or status == 204 or status == 304) {
        return true;
    }
    if (semantics.head) return true;
    return semantics.traditional_connect and status >= 200 and status < 300;
}

fn stripSuccessfulConnectContentLength(
    fields: *[]Qpack.HeaderField,
    status: u16,
    semantics: ResponseSemantics,
) Error!void {
    if (!semantics.traditional_connect or status < 200 or status >= 300) {
        return;
    }
    const declared = try contentLength(fields.*) orelse return;
    if (declared != 0) return error.InvalidContentLength;

    var write_index: usize = 0;
    for (fields.*) |field| {
        if (std.ascii.eqlIgnoreCase(field.name, "content-length")) continue;
        fields.*[write_index] = field;
        write_index += 1;
    }
    fields.* = fields.*[0..write_index];
}

fn validateResponseBodyForRequestSemanticsWithLength(
    status: u16,
    semantics: ResponseSemantics,
    declared_content_length: ?usize,
    body: []const u8,
    trailers: []const Qpack.HeaderField,
) Error!void {
    if (semantics.head) {
        if (trailers.len != 0) return error.InvalidContentLength;
        if (declared_content_length) |length| {
            if (body.len != 0 and body.len != length) {
                return error.InvalidContentLength;
            }
        }
        return;
    }
    if (semantics.traditional_connect and status >= 200 and status < 300) {
        if (body.len != 0 or trailers.len != 0 or
            (declared_content_length orelse 0) != 0)
        {
            return error.InvalidContentLength;
        }
    }
}

fn validateContentLengthForRequestSemantics(
    status: u16,
    semantics: ResponseSemantics,
    declared_content_length: ?usize,
    body_len: usize,
) Error!void {
    if (semantics.head) return;
    if (semantics.traditional_connect and status >= 200 and status < 300) {
        return;
    }
    try validateContentLengthForStatusValue(
        status,
        declared_content_length,
        body_len,
    );
}

fn responseShouldDefaultContentLengthValue(
    status: u16,
    semantics: ResponseSemantics,
    declared_content_length: ?usize,
    body_len: usize,
) bool {
    if (body_len == 0) return false;
    if (responseSuppressesBody(status, semantics)) return false;
    return declared_content_length == null;
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
        var fields_stack: [header_fields.stack_capacity]Qpack.HeaderField = undefined;
        const fields_buf = try header_fields.acquire(
            allocator,
            &fields_stack,
            try informationalHeaderFieldCapacity(self),
        );
        defer header_fields.release(allocator, &fields_stack, fields_buf);
        var status_buf: [3]u8 = undefined;
        const fields = try self.headerFields(fields_buf, &status_buf);
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
        var fields_stack: [header_fields.stack_capacity]Qpack.HeaderField = undefined;
        const fields_buf = try header_fields.acquire(
            allocator,
            &fields_stack,
            try informationalHeaderFieldCapacity(self),
        );
        defer header_fields.release(allocator, &fields_stack, fields_buf);
        var status_buf: [3]u8 = undefined;
        const fields = try self.headerFields(fields_buf, &status_buf);
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

/// Borrowed metadata for one response HEADERS section preceding the final
/// response. Header storage is valid only for the observer callback.
pub const InformationalResponseHead = struct {
    status: u16,
    headers: []const Qpack.HeaderField,
};

pub const InformationalObserver = struct {
    context: *anyopaque,
    on_response: *const fn (
        context: *anyopaque,
        response: InformationalResponseHead,
    ) void,
};

/// Local safeguards and callbacks used while decoding a complete response.
/// The informational limit applies even when no observer is installed so a
/// legacy aggregate read cannot be kept busy by an unbounded 1xx chain.
pub const ResponseDecodeOptions = struct {
    max_informational_responses: usize =
        default_max_informational_responses,
    informational: ?InformationalObserver = null,
    /// Optional originating method for HEAD and successful traditional
    /// CONNECT response validation. Generic decoders leave this null when the
    /// request context is unavailable; runtime clients always provide it.
    request_method: ?[]const u8 = null,
    extended_connect: bool = false,
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
    const decoded = try field_decoder.decode(
        allocator,
        payload,
        settings.max_field_section_size,
    );
    errdefer Qpack.freeDecodedFields(allocator, decoded.fields);
    try validateHeaderBlock(decoded.fields, .trailers);
    try validateFieldSectionSize(
        decoded.fields,
        settings.max_field_section_size,
    );
    return .{
        .fields = decoded.fields,
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
    return decodeRequestHeadFieldSection(
        allocator,
        field_section,
        settings,
        .{ .dynamic = table },
    );
}

fn decodeRequestHeadFieldSection(
    allocator: std.mem.Allocator,
    field_section: []const u8,
    settings: Settings,
    field_decoder: FieldSectionDecoder,
) Error!DecodedRequestHead {
    const decoded = try field_decoder.decode(
        allocator,
        field_section,
        settings.max_field_section_size,
    );
    errdefer Qpack.freeDecodedFields(allocator, decoded.fields);
    const lookup = try validateRequestHeaderBlock(decoded.fields);
    try validateFieldSectionSize(
        decoded.fields,
        settings.max_field_section_size,
    );
    if (lookup.content_length_invalid) return error.InvalidContentLength;

    const method_value = lookup.method(decoded.fields) orelse return error.MissingMethod;
    const has_protocol = lookup.hasProtocol();
    if (has_protocol and !settings.enable_connect_protocol) {
        return error.ExtendedConnectDisabled;
    }
    const plain_connect = std.mem.eql(u8, method_value, "CONNECT") and
        !has_protocol;
    const declared_length = lookup.content_length;
    if (plain_connect and declared_length != null) {
        return error.InvalidContentLength;
    }
    _ = lookup.path(decoded.fields) orelse
        if (plain_connect) "" else return error.MissingPath;
    _ = lookup.scheme(decoded.fields) orelse
        if (plain_connect) "" else return error.InvalidHeader;
    return .{
        .method = lookup.method(decoded.fields).?,
        .path = lookup.path(decoded.fields) orelse
            if (plain_connect) "" else return error.MissingPath,
        .scheme = lookup.scheme(decoded.fields) orelse
            if (plain_connect) "" else return error.InvalidHeader,
        .authority = lookup.requestAuthority(decoded.fields),
        .headers = decoded.fields,
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
    return decodeResponseHeadWithDynamicTableAndOptions(
        allocator,
        bytes,
        settings,
        table,
        .{},
    );
}

/// Decode through the final response head while synchronously reporting each
/// preceding 1xx section. Observer header slices are callback-scoped.
pub fn decodeResponseHeadWithDynamicTableAndOptions(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    settings: Settings,
    table: Qpack.DynamicTable,
    options: ResponseDecodeOptions,
) Error!DecodedResponseHead {
    // Count successful decodes, not attempts. A QPACK-blocked section can be
    // retried after encoder instructions arrive and must not spend the bound
    // until it has actually produced one informational response.
    var offset: usize = 0;
    var acknowledgments: usize = 0;
    var informational_count: usize = 0;
    while (true) {
        const frame = try firstResponseHeadersFrame(
            allocator,
            bytes[offset..],
            settings,
            .{ .dynamic = table },
        );
        acknowledgments += frame.qpack_section_acknowledgments;
        var head = try decodeResponseHeadFieldSectionWithDynamicTable(
            allocator,
            frame.value.payload,
            settings,
            table,
        );
        var head_owned = true;
        defer if (head_owned) head.deinit(allocator);
        acknowledgments += head.qpack_section_acknowledgments;
        offset += frame.consumed;
        if (head.status < 200) {
            try notifyInformationalResponse(
                options.informational,
                .{ .status = head.status, .headers = head.headers },
                &informational_count,
                options.max_informational_responses,
            );
            if (offset >= bytes.len) return error.BufferTooShort;
            continue;
        }
        const semantics = responseSemanticsForRequest(
            options.request_method,
            options.extended_connect,
        );
        try validateDecodedResponseHeadSemantics(
            head.status,
            head.content_length,
            semantics,
        );
        head.body_allowed = !responseSuppressesBody(
            head.status,
            semantics,
        );
        head.consumed = offset;
        head.qpack_section_acknowledgments = acknowledgments;
        head_owned = false;
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
    const decoded = try field_decoder.decode(
        allocator,
        field_section,
        settings.max_field_section_size,
    );
    errdefer Qpack.freeDecodedFields(allocator, decoded.fields);
    const lookup = try validateResponseHeaderBlock(decoded.fields);
    try validateFieldSectionSize(
        decoded.fields,
        settings.max_field_section_size,
    );
    if (lookup.content_length_invalid) return error.InvalidContentLength;
    const status = lookup.status orelse return error.MissingStatus;
    const declared_length = lookup.content_length;
    try validateResponseBodyForStatusWithLength(
        status,
        declared_length,
        &.{},
        &.{},
    );
    return .{
        .status = status,
        .headers = decoded.fields,
        .content_length = declared_length,
        .body_allowed = status != 204 and status != 304,
        .consumed = 0,
        .qpack_section_acknowledgments = @intFromBool(decoded.requires_acknowledgment),
    };
}

/// Apply originating-request semantics to an already decoded final response
/// head. Streaming runtimes use this after QPACK decoding because the generic
/// field-section decoder intentionally has no request-stream context.
pub fn applyResponseHeadRequestSemantics(
    head: *DecodedResponseHead,
    method: ?[]const u8,
    extended_connect: bool,
) Error!void {
    const semantics = responseSemanticsForRequest(method, extended_connect);
    try validateDecodedResponseHeadSemantics(
        head.status,
        head.content_length,
        semantics,
    );
    head.body_allowed = !responseSuppressesBody(head.status, semantics);
}

const FirstHeaders = struct {
    value: Frame,
    consumed: usize,
};

const FirstResponseHeaders = struct {
    value: Frame,
    consumed: usize,
    qpack_section_acknowledgments: usize,
};

fn firstResponseHeadersFrame(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    settings: Settings,
    field_decoder: FieldSectionDecoder,
) Error!FirstResponseHeaders {
    var offset: usize = 0;
    var acknowledgments: usize = 0;
    while (true) {
        const frame = try Frame.parse(bytes[offset..]);
        offset += frame.consumed;
        if (frame.frame_type == FrameType.headers) {
            return .{
                .value = frame,
                .consumed = offset,
                .qpack_section_acknowledgments = acknowledgments,
            };
        }
        if (frame.frame_type == FrameType.push_promise) {
            var promise = try decodePushPromiseWithFieldDecoder(
                allocator,
                frame.payload,
                settings,
                field_decoder,
            );
            acknowledgments +=
                promise.request.qpack_section_acknowledgments;
            promise.deinit(allocator);
        } else if (frame.frame_type == FrameType.data or
            messageStreamForbiddenFrame(frame.frame_type))
        {
            return error.ExpectedHeadersFrame;
        }
        if (offset >= bytes.len) return error.BufferTooShort;
    }
}

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
            messageStreamForbiddenFrame(frame.frame_type))
        {
            return error.ExpectedHeadersFrame;
        }
        if (offset >= bytes.len) return error.BufferTooShort;
    }
}

fn ownHeaderFields(
    allocator: std.mem.Allocator,
    fields: []Qpack.HeaderField,
) std.mem.Allocator.Error![]Qpack.HeaderField {
    for (fields) |*field| {
        // Dynamic references are already decoded into this representation.
        // All other combinations are normalized here so every final field has
        // one allocation rather than separate name and value allocations.
        if (fieldStoredContiguously(field.*)) continue;
        const storage_len = std.math.add(
            usize,
            field.name.len,
            field.value.len,
        ) catch return error.OutOfMemory;
        const storage = try allocator.alloc(u8, storage_len);
        @memcpy(storage[0..field.name.len], field.name);
        @memcpy(storage[field.name.len..], field.value);
        if (field.name_storage) |old| allocator.free(old);
        if (field.value_storage) |old| allocator.free(old);
        const name_len = field.name.len;
        const never_indexed = field.never_indexed;
        field.* = .{
            .name = storage[0..name_len],
            .value = storage[name_len..],
            .never_indexed = never_indexed,
            .name_storage = storage,
        };
    }
    return fields;
}

fn fieldStoredContiguously(field: Qpack.HeaderField) bool {
    // This is the canonical one-allocation representation used here and by
    // QPACK dynamic references. Other decoder-owned combinations are safely
    // copied before their old independent storage is released.
    const owner = field.name_storage orelse return false;
    if (field.value_storage != null) return false;
    const owner_start = @intFromPtr(owner.ptr);
    const name_start = @intFromPtr(field.name.ptr);
    const value_start = @intFromPtr(field.value.ptr);
    return name_start == owner_start and
        field.name.len <= owner.len and
        value_start == owner_start + field.name.len and
        field.value.len == owner.len - field.name.len;
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
        settings,
        field_decoder,
    );
    errdefer message.deinit(allocator);

    try validateHeaderBlock(message.trailers, .trailers);
    const lookup = message.request_lookup orelse
        try requestHeaderLookup(message.headers);
    const method_value = lookup.method(message.headers) orelse
        return error.MissingMethod;
    const has_protocol = lookup.hasProtocol();
    if (enforce_extended_connect_setting and has_protocol and !settings.enable_connect_protocol) {
        return error.ExtendedConnectDisabled;
    }
    const plain_connect = std.mem.eql(u8, method_value, "CONNECT") and !has_protocol;
    try validateRequestBodyForMethodValue(
        method_value,
        has_protocol,
        lookup.content_length,
        message.body,
        message.trailers,
    );
    try validateContentLengthValue(lookup.content_length, message.body.len);

    return .{
        .method = method_value,
        .path = lookup.path(message.headers) orelse
            if (plain_connect) "" else return error.MissingPath,
        .scheme = lookup.scheme(message.headers) orelse
            if (plain_connect) "" else return error.InvalidHeader,
        .authority = lookup.requestAuthority(message.headers),
        .headers = message.headers,
        .trailers = message.trailers,
        .body = message.body,
        .body_storage = message.body_storage,
        .consumed = message.consumed,
        .qpack_section_acknowledgments = message.qpack_section_acknowledgments,
    };
}

pub fn decodeResponse(allocator: std.mem.Allocator, bytes: []const u8) Error!DecodedResponse {
    return decodeResponseWithOptions(allocator, bytes, .{});
}

/// Decode a complete response and synchronously report ordered interim heads.
pub fn decodeResponseWithOptions(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    options: ResponseDecodeOptions,
) Error!DecodedResponse {
    return decodeResponseWithSettingsAndOptions(
        allocator,
        bytes,
        .{},
        options,
    );
}

pub fn decodeResponseWithSettings(allocator: std.mem.Allocator, bytes: []const u8, settings: Settings) Error!DecodedResponse {
    return decodeResponseWithSettingsAndOptions(
        allocator,
        bytes,
        settings,
        .{},
    );
}

/// Settings-aware complete response decoder with bounded 1xx observation.
pub fn decodeResponseWithSettingsAndOptions(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    settings: Settings,
    options: ResponseDecodeOptions,
) Error!DecodedResponse {
    return decodeResponseWithFieldDecoder(
        allocator,
        bytes,
        settings,
        .literal,
        options,
    );
}

pub fn decodeResponseWithDynamicTable(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    settings: Settings,
    table: Qpack.DynamicTable,
) Error!DecodedResponse {
    return decodeResponseWithDynamicTableAndOptions(
        allocator,
        bytes,
        settings,
        table,
        .{},
    );
}

/// Stateful-QPACK response decoder with bounded ordered 1xx observation.
pub fn decodeResponseWithDynamicTableAndOptions(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    settings: Settings,
    table: Qpack.DynamicTable,
    options: ResponseDecodeOptions,
) Error!DecodedResponse {
    return decodeResponseWithFieldDecoder(
        allocator,
        bytes,
        settings,
        .{ .dynamic = table },
        options,
    );
}

fn decodeResponseWithFieldDecoder(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    settings: Settings,
    field_decoder: FieldSectionDecoder,
    options: ResponseDecodeOptions,
) Error!DecodedResponse {
    var message = try decodeResponseMessage(
        allocator,
        bytes,
        settings,
        field_decoder,
        options,
    );
    errdefer message.deinit(allocator);

    try validateHeaderBlock(message.trailers, .trailers);

    const lookup = message.response_lookup orelse
        try responseHeaderLookup(message.headers);
    const final_status = lookup.status orelse return error.MissingStatus;
    const semantics = responseSemanticsForRequest(
        options.request_method,
        options.extended_connect,
    );
    try validateResponseBodyForStatusWithLength(
        final_status,
        lookup.content_length,
        message.body,
        message.trailers,
    );
    try validateDecodedResponseRequestSemantics(
        final_status,
        semantics,
        lookup.content_length,
        message.body,
        message.trailers,
    );
    try validateContentLengthForRequestSemantics(
        final_status,
        semantics,
        lookup.content_length,
        message.body.len,
    );

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

fn validateDecodedResponseHeadSemantics(
    status: u16,
    content_length: ?usize,
    semantics: ResponseSemantics,
) Error!void {
    if (semantics.traditional_connect and status >= 200 and status < 300 and
        (content_length orelse 0) != 0)
    {
        return error.InvalidContentLength;
    }
}

fn validateDecodedResponseRequestSemantics(
    status: u16,
    semantics: ResponseSemantics,
    declared_content_length: ?usize,
    body: []const u8,
    trailers: []const Qpack.HeaderField,
) Error!void {
    if (semantics.head) {
        if (body.len != 0 or trailers.len != 0) {
            return error.InvalidContentLength;
        }
        return;
    }
    if (semantics.traditional_connect and status >= 200 and status < 300) {
        if (body.len != 0 or trailers.len != 0 or
            (declared_content_length orelse 0) != 0)
        {
            return error.InvalidContentLength;
        }
    }
}

const DecodedMessage = struct {
    headers: []Qpack.HeaderField,
    trailers: []Qpack.HeaderField = &.{},
    body: []const u8,
    body_storage: ?[]u8 = null,
    request_lookup: ?RequestHeaderLookup = null,
    response_lookup: ?ResponseHeaderLookup = null,
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
        max_field_section_size: u64,
    ) Error!DecodedFieldSection {
        return switch (self) {
            .literal => .{ .fields = try Qpack.decodeLiteralBlockOwnedWithLimit(
                allocator,
                payload,
                max_field_section_size,
            ) },
            .dynamic => |table| blk: {
                const decoded = try Qpack.decodeDynamicBlockOwnedWithLimit(
                    allocator,
                    payload,
                    table,
                    max_field_section_size,
                );
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
    const original_len = list.items.len;
    errdefer list.shrinkRetainingCapacity(original_len);
    // QPACK exposes an append-oriented encoder. Reserve the maximum two-varint
    // HTTP/3 frame header before encoding the block, then close the gap once
    // its exact size is known. This keeps one reusable allocation and avoids a
    // second temporary ArrayList for every dynamic HEADERS section.
    const max_header_len: usize = 16;
    try list.ensureUnusedCapacity(allocator, max_header_len);
    const payload_start = original_len + max_header_len;
    list.items.len = payload_start;
    try encoder.encodeFieldSection(list, stream_id, fields);
    const payload_len = list.items.len - payload_start;
    var header_storage: [max_header_len]u8 = undefined;
    var header = std.ArrayList(u8).initBuffer(&header_storage);
    var fixed = std.heap.FixedBufferAllocator.init(&header_storage);
    try writeFrameHeader(
        &header,
        fixed.allocator(),
        FrameType.headers,
        payload_len,
    );
    std.debug.assert(header.items.len <= max_header_len);
    const gap = max_header_len - header.items.len;
    std.mem.copyForwards(
        u8,
        list.items[original_len + header.items.len .. original_len + header.items.len + payload_len],
        list.items[payload_start..],
    );
    @memcpy(
        list.items[original_len..][0..header.items.len],
        header.items,
    );
    list.items.len -= gap;
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

pub fn writeTrailers(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    trailers: []const Qpack.HeaderField,
    peer_settings: Settings,
) Error!void {
    if (trailers.len == 0) return error.InvalidHeader;
    try validateHeaderBlock(trailers, .trailers);
    try validateFieldSectionSize(
        trailers,
        peer_settings.max_field_section_size,
    );
    try writeHeadersFrame(list, allocator, trailers);
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

/// Return whether a frame type is defined for another HTTP/3 stream context
/// and therefore cannot be ignored as an unknown extension on a request,
/// response, or push stream.
pub fn messageStreamForbiddenFrame(frame_type: u64) bool {
    return switch (frame_type) {
        FrameType.cancel_push,
        FrameType.settings,
        FrameType.goaway,
        FrameType.origin,
        FrameType.max_push_id,
        FrameType.priority_update_request,
        FrameType.priority_update_push,
        FrameType.webtransport_stream,
        0x02,
        0x06,
        0x08,
        0x09,
        => true,
        else => false,
    };
}

fn responseStatus(headers: []const Qpack.HeaderField) Error!u16 {
    for (headers) |header| {
        if (!std.mem.eql(u8, header.name, ":status")) continue;
        return parseStatusValue(header.value);
    }
    return error.MissingStatus;
}

fn parseStatusValue(value: []const u8) Error!u16 {
    if (value.len != 3) return error.InvalidStatus;
    for (value) |byte| {
        if (!std.ascii.isDigit(byte)) return error.InvalidStatus;
    }
    const status = std.fmt.parseInt(u16, value, 10) catch return error.InvalidStatus;
    if (status < 100 or status > 999) return error.InvalidStatus;
    return status;
}

fn decodeResponseMessage(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    settings: Settings,
    field_decoder: FieldSectionDecoder,
    options: ResponseDecodeOptions,
) Error!DecodedMessage {
    // Aggregate decoding owns each field list only until this loop advances.
    // Invoke the observer before freeing an interim section, and retain only
    // the cumulative QPACK acknowledgment count needed by the final response.
    var offset: usize = 0;
    var preceding_acknowledgments: usize = 0;
    var informational_count: usize = 0;
    while (true) {
        const frame = try Frame.parse(bytes[offset..]);
        if (frame.frame_type != FrameType.headers) {
            if (frame.frame_type == FrameType.data or messageStreamForbiddenFrame(frame.frame_type)) return error.ExpectedHeadersFrame;
            if (frame.frame_type == FrameType.push_promise) {
                var promise = try decodePushPromiseWithFieldDecoder(
                    allocator,
                    frame.payload,
                    settings,
                    field_decoder,
                );
                preceding_acknowledgments +=
                    promise.request.qpack_section_acknowledgments;
                promise.deinit(allocator);
            }
            offset += frame.consumed;
            if (offset >= bytes.len) return error.MissingStatus;
            continue;
        }
        const decoded = try field_decoder.decode(
            allocator,
            frame.payload,
            settings.max_field_section_size,
        );
        var decoded_owned = true;
        defer if (decoded_owned) Qpack.freeDecodedFields(allocator, decoded.fields);
        const lookup = try validateResponseHeaderBlock(decoded.fields);
        try validateFieldSectionSize(
            decoded.fields,
            settings.max_field_section_size,
        );
        if (lookup.content_length_invalid) return error.InvalidContentLength;
        const status = lookup.status orelse return error.MissingStatus;
        if (status < 200) {
            try validateResponseBodyForStatusWithLength(
                status,
                lookup.content_length,
                &.{},
                &.{},
            );
            try notifyInformationalResponse(
                options.informational,
                .{ .status = status, .headers = decoded.fields },
                &informational_count,
                options.max_informational_responses,
            );
            preceding_acknowledgments +=
                @intFromBool(decoded.requires_acknowledgment);
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
            settings,
            field_decoder,
            decoded,
            offset + frame.consumed,
            lookup.content_length,
        );
        message.response_lookup = lookup;
        message.qpack_section_acknowledgments += preceding_acknowledgments;
        return message;
    }
}

fn notifyInformationalResponse(
    observer: ?InformationalObserver,
    response: InformationalResponseHead,
    count: *usize,
    limit: usize,
) Error!void {
    count.* = std.math.add(usize, count.*, 1) catch
        return error.TooManyInformationalResponses;
    if (count.* > limit) return error.TooManyInformationalResponses;
    if (observer) |value| {
        value.on_response(value.context, response);
    }
}

fn decodeMessage(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    kind: MessageStreamKind,
    settings: Settings,
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
        if (frame.frame_type == FrameType.data or messageStreamForbiddenFrame(frame.frame_type)) return error.ExpectedHeadersFrame;
        // RFC 9114 allows unknown extension frames on request streams.  Like
        // tquic's request-stream state machine, ignore them before the first
        // HEADERS rather than treating every non-HEADERS frame as fatal.
        offset += frame.consumed;
        if (offset >= bytes.len) return error.ExpectedHeadersFrame;
    };
    const decoded_headers = try field_decoder.decode(
        allocator,
        headers_frame.payload,
        settings.max_field_section_size,
    );
    var headers_owned = true;
    errdefer if (headers_owned) Qpack.freeDecodedFields(allocator, decoded_headers.fields);
    try validateFieldSectionSize(
        decoded_headers.fields,
        settings.max_field_section_size,
    );
    const request_lookup = if (kind == .request)
        try validateRequestHeaderBlock(decoded_headers.fields)
    else blk: {
        const lookup = try validateResponseHeaderBlock(decoded_headers.fields);
        if (lookup.content_length_invalid) return error.InvalidContentLength;
        break :blk null;
    };
    if (request_lookup) |lookup| {
        if (lookup.content_length_invalid) return error.InvalidContentLength;
    }
    headers_owned = false;
    var message = try decodeMessageAfterHeaders(
        allocator,
        bytes,
        kind,
        settings,
        field_decoder,
        decoded_headers,
        offset + headers_frame.consumed,
        if (request_lookup) |lookup| lookup.content_length else null,
    );
    message.request_lookup = request_lookup;
    return message;
}

fn decodeMessageAfterHeaders(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    kind: MessageStreamKind,
    settings: Settings,
    field_decoder: FieldSectionDecoder,
    decoded_headers: DecodedFieldSection,
    initial_consumed: usize,
    declared_content_length: ?usize,
) Error!DecodedMessage {
    errdefer Qpack.freeDecodedFields(allocator, decoded_headers.fields);
    var consumed = initial_consumed;
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);
    if (declared_content_length) |expected_body_len| {
        // A malicious peer can declare a huge Content-Length and then send no
        // DATA.  Cap eager reservation to bytes already present on this
        // complete message buffer; appends below still grow if the actual DATA
        // frames justify it.
        const remaining_bytes = bytes.len - initial_consumed;
        const reservation = @min(expected_body_len, remaining_bytes);
        if (reservation != 0) {
            try body.ensureTotalCapacity(allocator, reservation);
        }
    }
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
                const decoded_trailers = try field_decoder.decode(
                    allocator,
                    frame.payload,
                    settings.max_field_section_size,
                );
                errdefer Qpack.freeDecodedFields(allocator, decoded_trailers.fields);
                try validateFieldSectionSize(
                    decoded_trailers.fields,
                    settings.max_field_section_size,
                );
                trailers = decoded_trailers.fields;
                qpack_section_acknowledgments +=
                    @intFromBool(decoded_trailers.requires_acknowledgment);
                saw_trailers = true;
            },
            FrameType.push_promise => {
                if (kind == .request or saw_trailers) return error.UnexpectedFrame;
                var promise = try decodePushPromiseWithFieldDecoder(
                    allocator,
                    frame.payload,
                    settings,
                    field_decoder,
                );
                qpack_section_acknowledgments +=
                    promise.request.qpack_section_acknowledgments;
                promise.deinit(allocator);
            },
            else => if (messageStreamForbiddenFrame(frame.frame_type)) return error.UnexpectedFrame,
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
        try parseContentLengthHeaderValue(header.value, &found);
    }
    return found;
}

fn parseContentLengthHeaderValue(value: []const u8, found: *?usize) Error!void {
    var parts = std.mem.splitScalar(u8, value, ',');
    while (parts.next()) |raw_part| {
        const part = std.mem.trim(u8, raw_part, " \t");
        if (part.len == 0) return error.InvalidContentLength;
        for (part) |byte| {
            if (!std.ascii.isDigit(byte)) return error.InvalidContentLength;
        }
        const parsed = std.fmt.parseInt(usize, part, 10) catch return error.InvalidContentLength;
        if (found.*) |existing| {
            if (existing != parsed) return error.InvalidContentLength;
        } else {
            found.* = parsed;
        }
    }
}

const RequestHeaderLookup = struct {
    method_index: ?usize = null,
    path_index: ?usize = null,
    scheme_index: ?usize = null,
    authority_index: ?usize = null,
    host_index: ?usize = null,
    has_protocol_pseudo: bool = false,
    content_length: ?usize = null,
    content_length_invalid: bool = false,

    fn method(self: RequestHeaderLookup, headers: []const Qpack.HeaderField) ?[]const u8 {
        const index = self.method_index orelse return null;
        return headers[index].value;
    }

    fn path(self: RequestHeaderLookup, headers: []const Qpack.HeaderField) ?[]const u8 {
        const index = self.path_index orelse return null;
        return headers[index].value;
    }

    fn scheme(self: RequestHeaderLookup, headers: []const Qpack.HeaderField) ?[]const u8 {
        const index = self.scheme_index orelse return null;
        return headers[index].value;
    }

    fn requestAuthority(self: RequestHeaderLookup, headers: []const Qpack.HeaderField) ?[]const u8 {
        const index = self.authority_index orelse self.host_index orelse return null;
        return headers[index].value;
    }

    fn hasProtocol(self: RequestHeaderLookup) bool {
        return self.has_protocol_pseudo;
    }
};

fn requestHeaderLookup(headers: []const Qpack.HeaderField) Error!RequestHeaderLookup {
    var lookup: RequestHeaderLookup = .{};
    for (headers, 0..) |header, index| {
        if (std.mem.eql(u8, header.name, ":method")) {
            if (lookup.method_index == null) lookup.method_index = index;
        } else if (std.mem.eql(u8, header.name, ":path")) {
            if (lookup.path_index == null) lookup.path_index = index;
        } else if (std.mem.eql(u8, header.name, ":scheme")) {
            if (lookup.scheme_index == null) lookup.scheme_index = index;
        } else if (std.mem.eql(u8, header.name, ":authority")) {
            if (lookup.authority_index == null) lookup.authority_index = index;
        } else if (std.mem.eql(u8, header.name, ":protocol")) {
            lookup.has_protocol_pseudo = true;
        } else if (std.ascii.eqlIgnoreCase(header.name, "host")) {
            if (lookup.host_index == null) lookup.host_index = index;
        } else if (std.ascii.eqlIgnoreCase(header.name, "content-length")) {
            try parseContentLengthHeaderValue(header.value, &lookup.content_length);
        }
    }
    return lookup;
}

const ResponseHeaderLookup = struct {
    status: ?u16 = null,
    content_length: ?usize = null,
    content_length_invalid: bool = false,
};

fn responseHeaderLookup(headers: []const Qpack.HeaderField) Error!ResponseHeaderLookup {
    var lookup: ResponseHeaderLookup = .{};
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, ":status")) {
            if (lookup.status == null) lookup.status = try parseStatusValue(header.value);
        } else if (std.ascii.eqlIgnoreCase(header.name, "content-length")) {
            try parseContentLengthHeaderValue(header.value, &lookup.content_length);
        }
    }
    return lookup;
}

fn validateRequestBodyForMethod(headers: []const Qpack.HeaderField, body: []const u8, trailers: []const Qpack.HeaderField) Error!void {
    var method: ?[]const u8 = null;
    var has_protocol = false;
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, ":method")) method = header.value;
        if (std.mem.eql(u8, header.name, ":protocol")) has_protocol = true;
    }
    if (method) |value| {
        try validateRequestBodyForMethodValue(
            value,
            has_protocol,
            try contentLength(headers),
            body,
            trailers,
        );
    }
}

fn validateRequestBodyForMethodValue(
    method: []const u8,
    extended_connect: bool,
    declared_content_length: ?usize,
    body: []const u8,
    trailers: []const Qpack.HeaderField,
) Error!void {
    if (std.mem.eql(u8, method, "CONNECT") and !extended_connect) {
        if (body.len != 0 or trailers.len != 0) return error.InvalidContentLength;
        if (declared_content_length != null) return error.InvalidContentLength;
    }
}

fn validateContentLength(headers: []const Qpack.HeaderField, actual: usize) Error!void {
    try validateContentLengthValue(try contentLength(headers), actual);
}

fn validateContentLengthValue(expected: ?usize, actual: usize) Error!void {
    if (expected) |value| {
        if (value != actual) return error.InvalidContentLength;
    }
}

fn validateContentLengthForStatus(status: u16, headers: []const Qpack.HeaderField, actual: usize) Error!void {
    try validateContentLengthForStatusValue(status, try contentLength(headers), actual);
}

fn validateContentLengthForStatusValue(status: u16, expected: ?usize, actual: usize) Error!void {
    if (expected) |value| {
        if (status == 304 and actual == 0) return;
        if (value != actual) return error.InvalidContentLength;
    }
}

fn validateResponseBodyForStatus(
    status: u16,
    headers: []const Qpack.HeaderField,
    body: []const u8,
    trailers: []const Qpack.HeaderField,
) Error!void {
    try validateResponseBodyForStatusWithLength(
        status,
        try contentLength(headers),
        body,
        trailers,
    );
}

fn validateOutgoingResponseBodyForStatusWithLength(
    status: u16,
    declared_content_length: ?usize,
    body: []const u8,
    trailers: []const Qpack.HeaderField,
) Error!void {
    try validateResponseBodyForStatusWithLength(
        status,
        declared_content_length,
        body,
        trailers,
    );
    // RFC 9110 Section 15.3.6: 205 has ordinary HTTP/3 stream framing but a
    // server MUST NOT generate response content. Trailer fields are not
    // content and remain permitted after a zero-length DATA sequence.
    if (status != 205) return;
    if (body.len != 0 or (declared_content_length orelse 0) != 0) {
        return error.InvalidContentLength;
    }
}

fn validateResponseBodyForStatusWithLength(
    status: u16,
    declared_content_length: ?usize,
    body: []const u8,
    trailers: []const Qpack.HeaderField,
) Error!void {
    if (!((status >= 100 and status < 200) or status == 204 or status == 304)) return;
    if (body.len != 0 or trailers.len != 0) return error.InvalidContentLength;
    if (status != 304 and declared_content_length != null) return error.InvalidContentLength;
}

const HeaderBlockKind = enum {
    request,
    response,
    trailers,
};

fn validateHeaderBlock(headers: []const Qpack.HeaderField, kind: HeaderBlockKind) Error!void {
    _ = try validateHeaderBlockImpl(false, headers, kind);
}

const HeaderBlockValidation = struct {
    request: RequestHeaderLookup = .{},
    response: ResponseHeaderLookup = .{},
};

fn validateRequestHeaderBlock(
    headers: []const Qpack.HeaderField,
) Error!RequestHeaderLookup {
    return (try validateHeaderBlockImpl(true, headers, .request)).request;
}

fn validateResponseHeaderBlock(
    headers: []const Qpack.HeaderField,
) Error!ResponseHeaderLookup {
    return (try validateHeaderBlockImpl(true, headers, .response)).response;
}

fn validateHeaderBlockImpl(
    comptime collect_lookup: bool,
    headers: []const Qpack.HeaderField,
    kind: HeaderBlockKind,
) Error!HeaderBlockValidation {
    var lookup: HeaderBlockValidation = .{};
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

    for (headers, 0..) |header, index| {
        try validateHeaderName(header.name);
        try validateHeaderValue(header.value);
        const pseudo = std.mem.startsWith(u8, header.name, ":");
        if (pseudo) {
            if (saw_regular) return error.InvalidHeader;
            switch (kind) {
                .request => {
                    switch (try markRequestPseudo(
                        header.name,
                        &seen_method,
                        &seen_scheme,
                        &seen_path,
                        &seen_authority,
                        &seen_protocol,
                    )) {
                        .method => {
                            method_value = header.value;
                            if (comptime collect_lookup) lookup.request.method_index = index;
                        },
                        .scheme => {
                            scheme_value = header.value;
                            if (comptime collect_lookup) lookup.request.scheme_index = index;
                        },
                        .path => {
                            path_value = header.value;
                            if (comptime collect_lookup) lookup.request.path_index = index;
                        },
                        .authority => {
                            authority_value = header.value;
                            if (comptime collect_lookup) lookup.request.authority_index = index;
                        },
                        .protocol => {
                            protocol_value = header.value;
                            if (comptime collect_lookup) lookup.request.has_protocol_pseudo = true;
                        },
                    }
                },
                .response => {
                    try markResponsePseudo(header.name, &seen_status);
                    if (header.value.len != 3) return error.InvalidStatus;
                    for (header.value) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidStatus;
                    const parsed_status = std.fmt.parseInt(u16, header.value, 10) catch return error.InvalidStatus;
                    if (parsed_status < 100) return error.InvalidStatus;
                    if (parsed_status == 101) return error.InvalidStatus;
                    if (comptime collect_lookup) {
                        lookup.response.status = parsed_status;
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
            if (comptime collect_lookup) lookup.request.host_index = index;
        }
        if (comptime collect_lookup) {
            if (std.ascii.eqlIgnoreCase(header.name, "content-length")) {
                switch (kind) {
                    .request => parseContentLengthHeaderValue(
                        header.value,
                        &lookup.request.content_length,
                    ) catch {
                        lookup.request.content_length_invalid = true;
                    },
                    .response => parseContentLengthHeaderValue(
                        header.value,
                        &lookup.response.content_length,
                    ) catch {
                        lookup.response.content_length_invalid = true;
                    },
                    .trailers => unreachable,
                }
            }
        }
        if (std.mem.eql(u8, header.name, "priority")) {
            _ = priority_field.Priority.parseStrict(header.value) catch {
                return error.InvalidHeader;
            };
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
            } else {
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
            }
        },
        .response => if (!seen_status) return error.MissingStatus,
        .trailers => {},
    }
    return lookup;
}

fn validateHttpToken(value: []const u8) Error!void {
    if (!http_method.isToken(value)) return error.InvalidHeader;
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

const RequestPseudo = enum { method, scheme, path, authority, protocol };

fn markRequestPseudo(
    name: []const u8,
    seen_method: *bool,
    seen_scheme: *bool,
    seen_path: *bool,
    seen_authority: *bool,
    seen_protocol: *bool,
) Error!RequestPseudo {
    if (std.mem.eql(u8, name, ":method")) {
        try markOnce(seen_method);
        return .method;
    }
    if (std.mem.eql(u8, name, ":scheme")) {
        try markOnce(seen_scheme);
        return .scheme;
    }
    if (std.mem.eql(u8, name, ":path")) {
        try markOnce(seen_path);
        return .path;
    }
    if (std.mem.eql(u8, name, ":authority")) {
        try markOnce(seen_authority);
        return .authority;
    }
    if (std.mem.eql(u8, name, ":protocol")) {
        try markOnce(seen_protocol);
        return .protocol;
    }
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
    pub const max_quarter_stream_id: u64 =
        @as(u64, std.math.maxInt(u62)) >> 2;

    quarter_stream_id: u64,
    payload: []const u8,

    pub fn parse(bytes: []const u8) Error!Datagram {
        var cursor = wire.Cursor.init(bytes);
        const quarter_stream_id = try quic.varint.decode(&cursor);
        if (quarter_stream_id > max_quarter_stream_id) {
            return error.InvalidFrame;
        }
        return .{ .quarter_stream_id = quarter_stream_id, .payload = bytes[cursor.pos..] };
    }

    pub fn write(self: Datagram, list: *std.ArrayList(u8), allocator: std.mem.Allocator) !void {
        if (self.quarter_stream_id > max_quarter_stream_id) {
            return error.InvalidFrame;
        }
        const id_len = try quic.varint.length(self.quarter_stream_id);
        const total_len = std.math.add(usize, id_len, self.payload.len) catch
            return error.IntegerOverflow;
        try list.ensureUnusedCapacity(allocator, total_len);
        try appendVarintAssumeCapacity(list, self.quarter_stream_id);
        list.appendSliceAssumeCapacity(self.payload);
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
    try std.testing.expectEqual(
        ReuseDecision.same_origin,
        connectionReuseDecision(https_default, explicit_https),
    );

    const different_port = try requestOrigin("https", "example.com:8443");
    try std.testing.expect(!sameOrigin(https_default, different_port));
    try std.testing.expectEqual(
        ReuseDecision.different_scheme_or_port,
        connectionReuseDecision(https_default, different_port),
    );

    const sibling_origin = try requestOrigin("https", "api.example.com");
    try std.testing.expectEqual(
        ReuseDecision.requires_authority_validation,
        connectionReuseDecision(https_default, sibling_origin),
    );

    const ipv6 = try requestOrigin("https", "[2001:db8::1]:443");
    try std.testing.expectEqualStrings("2001:db8::1", ipv6.host);
    try std.testing.expectEqual(@as(u16, 443), ipv6.port);

    const http_default = try requestOrigin("http", "example.com");
    try std.testing.expectEqual(@as(u16, 80), http_default.port);
    try std.testing.expect(!sameOrigin(https_default, http_default));
    try std.testing.expect(sameOrigin(
        try requestOrigin("https", "[2001:db8::1]:8443"),
        try originFromSerialized("https://[2001:db8::1]:8443"),
    ));

    try std.testing.expectError(error.InvalidHeader, requestOrigin("ftp", "example.com"));
    try std.testing.expectError(error.InvalidHeader, requestOrigin("https", "user@example.com"));
    try std.testing.expectError(error.InvalidHeader, requestOrigin("https", "example.com:bad"));
}

test "HTTP/3 RFC 9412 ORIGIN frames accumulate canonical origins" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    const advertised = [_][]const u8{
        "https://Example.COM",
        "https://cdn.example.com:8443",
        "https://example.com:443",
    };
    try OriginPayload.write(&encoded, allocator, &advertised);
    const frame = try Frame.parse(encoded.items);
    try std.testing.expectEqual(FrameType.origin, frame.frame_type);
    var parsed = try OriginPayload.parse(allocator, frame.payload);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), parsed.origins.len);
    const expected_single = "\x0c\x15\x00\x13https://example.com";
    var single: std.ArrayList(u8) = .empty;
    defer single.deinit(allocator);
    try OriginPayload.write(
        &single,
        allocator,
        &.{"https://example.com"},
    );
    try std.testing.expectEqualSlices(u8, expected_single, single.items);
    const fixed = try Frame.parse(expected_single);
    var fixed_payload = try OriginPayload.parse(allocator, fixed.payload);
    defer fixed_payload.deinit(allocator);
    try std.testing.expectEqualStrings(
        "https://example.com",
        fixed_payload.origins[0],
    );

    var control = ControlState{};
    defer control.deinit(allocator);
    control.settings.received = true;
    try control.applyFrame(allocator, frame);
    try std.testing.expect(control.peerOriginSetInitialized());
    // The explicit default port canonicalizes to the first origin rather than
    // consuming another bounded Origin Set entry.
    try std.testing.expectEqual(@as(usize, 2), control.peerOrigins().len);
    try std.testing.expect(control.peerOriginKnown(
        try requestOrigin("https", "example.com"),
    ));
    try std.testing.expect(control.peerOriginKnown(
        try requestOrigin("https", "CDN.EXAMPLE.COM:8443"),
    ));
    try std.testing.expectEqual(
        true,
        control.peerOriginSetAllows(
            try requestOrigin("https", "initial.example"),
            try requestOrigin("https", "cdn.example.com:8443"),
        ).?,
    );
    try std.testing.expectEqual(
        false,
        control.peerOriginSetAllows(
            try requestOrigin("https", "initial.example"),
            try requestOrigin("https", "missing.example"),
        ).?,
    );
    try control.removePeerOrigin(
        allocator,
        try requestOrigin("https", "cdn.example.com:8443"),
    );
    try std.testing.expect(!control.peerOriginKnown(
        try requestOrigin("https", "cdn.example.com:8443"),
    ));
    try std.testing.expectEqual(@as(usize, 1), control.peerOrigins().len);
    try control.removePeerOrigin(
        allocator,
        try requestOrigin("https", "initial.example"),
    );
    try std.testing.expectEqual(
        false,
        control.peerOriginSetAllows(
            try requestOrigin("https", "initial.example"),
            try requestOrigin("https", "initial.example"),
        ).?,
    );
    var readded: std.ArrayList(u8) = .empty;
    defer readded.deinit(allocator);
    try OriginPayload.write(
        &readded,
        allocator,
        &.{"https://initial.example"},
    );
    try control.applyFrame(allocator, try Frame.parse(readded.items));
    try std.testing.expectEqual(
        true,
        control.peerOriginSetAllows(
            try requestOrigin("https", "initial.example"),
            try requestOrigin("https", "initial.example"),
        ).?,
    );
    var uninitialized = ControlState{};
    defer uninitialized.deinit(allocator);
    try std.testing.expect(uninitialized.peerOriginSetAllows(
        try requestOrigin("https", "initial.example"),
        try requestOrigin("https", "missing.example"),
    ) == null);

    var empty: std.ArrayList(u8) = .empty;
    defer empty.deinit(allocator);
    try OriginPayload.write(&empty, allocator, &.{});
    var empty_control = ControlState{};
    defer empty_control.deinit(allocator);
    empty_control.settings.received = true;
    try empty_control.applyFrame(allocator, try Frame.parse(empty.items));
    try std.testing.expect(empty_control.peerOriginSetInitialized());
    try std.testing.expectEqual(@as(usize, 0), empty_control.peerOrigins().len);
    try std.testing.expectEqual(
        true,
        empty_control.peerOriginSetAllows(
            try requestOrigin("https", "initial.example"),
            try requestOrigin("https", "initial.example:443"),
        ).?,
    );
    try std.testing.expectEqual(
        false,
        empty_control.peerOriginSetAllows(
            try requestOrigin("https", "initial.example"),
            try requestOrigin("https", "other.example"),
        ).?,
    );
}

test "HTTP/3 ORIGIN ignores invalid origins and rejects malformed framing" {
    const allocator = std.testing.allocator;
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try wire.appendInt(&payload, allocator, u16, 0, .big);
    try wire.appendInt(&payload, allocator, u16, 13, .big);
    try payload.appendSlice(allocator, "not-an-origin");
    try wire.appendInt(&payload, allocator, u16, 21, .big);
    try payload.appendSlice(allocator, "https://valid.example");

    var control = ControlState{};
    defer control.deinit(allocator);
    control.settings.received = true;
    try control.applyFrame(allocator, .{
        .frame_type = FrameType.origin,
        .payload = payload.items,
        .consumed = 0,
    });
    try std.testing.expect(control.peerOriginSetInitialized());
    try std.testing.expectEqual(@as(usize, 1), control.peerOrigins().len);
    try std.testing.expect(control.peerOriginKnown(
        try requestOrigin("https", "valid.example"),
    ));

    var malformed = [_]u8{ 0, 5, 'h', 't' };
    try std.testing.expectError(
        error.BufferTooShort,
        OriginPayload.parse(allocator, &malformed),
    );
    try std.testing.expectError(
        error.InvalidOrigin,
        OriginPayload.write(&payload, allocator, &.{"https://example.com/path"}),
    );
}

test "HTTP/3 ORIGIN state update is transactional on allocation failure" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try OriginPayload.write(
        &encoded,
        allocator,
        &.{"https://new.example"},
    );
    const frame = try Frame.parse(encoded.items);

    var control = ControlState{};
    defer control.deinit(allocator);
    control.settings.received = true;
    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        control.applyFrame(fail_first.allocator(), frame),
    );
    try std.testing.expect(!control.peerOriginSetInitialized());
    try std.testing.expectEqual(@as(usize, 0), control.peerOrigins().len);
}

test "HTTP/3 control stream buffers a split ORIGIN frame" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try OriginPayload.write(
        &encoded,
        allocator,
        &.{"https://split.example"},
    );

    for (1..encoded.items.len) |split| {
        var control = ControlState{};
        defer control.deinit(allocator);
        control.settings.received = true;
        try control.appendControlPayload(
            allocator,
            encoded.items[0..split],
        );
        try std.testing.expect(!control.peerOriginSetInitialized());
        try control.appendControlPayload(
            allocator,
            encoded.items[split..],
        );
        try std.testing.expect(control.peerOriginSetInitialized());
        try std.testing.expect(control.peerOriginKnown(
            try requestOrigin("https", "split.example"),
        ));
        try std.testing.expectEqual(
            @as(usize, 0),
            control.peer_control_stream_buffer.items.len,
        );
    }
}

test "HTTP/3 incomplete control frame avoids state snapshot allocation" {
    const allocator = std.testing.allocator;
    var control = ControlState{ .settings = .{ .received = true } };
    defer control.deinit(allocator);

    var priority: std.ArrayList(u8) = .empty;
    defer priority.deinit(allocator);
    try writePriorityUpdateFrame(
        &priority,
        allocator,
        0,
        .{ .urgency = 2 },
    );
    try control.applyFrame(allocator, try Frame.parse(priority.items));
    try control.peer_control_stream_buffer.ensureTotalCapacity(allocator, 8);

    // Unknown extension frame type 0x21, two-byte payload, one payload byte
    // still missing. Existing priority state ensures the old eager snapshot
    // path would have needed an allocation before noticing incompleteness.
    const partial = [_]u8{ 0x21, 0x02, 0xaa };
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try control.appendControlPayload(no_alloc.allocator(), &partial);
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(
        u8,
        &partial,
        control.peer_control_stream_buffer.items,
    );
    try std.testing.expectEqual(
        @as(u3, 2),
        control.requestPriorityUpdate(0).?.priority().urgency,
    );

    try control.appendControlPayload(allocator, &.{0xbb});
    try std.testing.expectEqual(
        @as(usize, 0),
        control.peer_control_stream_buffer.items.len,
    );
    try std.testing.expectEqual(
        @as(u3, 2),
        control.requestPriorityUpdate(0).?.priority().urgency,
    );

    const complete_extension = [_]u8{ 0x21, 0x01, 0xcc };
    try control.appendControlPayload(
        no_alloc.allocator(),
        &complete_extension,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(
        @as(usize, 0),
        control.peer_control_stream_buffer.items.len,
    );
}

test "HTTP/3 ORIGIN state enforces its connection memory bound" {
    const allocator = std.testing.allocator;
    var control = ControlState{};
    defer control.deinit(allocator);
    control.settings.received = true;

    var serialized: [max_peer_origins][32]u8 = undefined;
    var origins: [max_peer_origins][]const u8 = undefined;
    for (&serialized, &origins, 0..) |*storage, *origin, index| {
        origin.* = try std.fmt.bufPrint(
            storage,
            "https://o{d}.example",
            .{index},
        );
    }
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try OriginPayload.write(&encoded, allocator, &origins);
    try control.applyFrame(allocator, try Frame.parse(encoded.items));
    try std.testing.expectEqual(
        max_peer_origins,
        control.peerOrigins().len,
    );

    encoded.clearRetainingCapacity();
    try OriginPayload.write(
        &encoded,
        allocator,
        &.{"https://overflow.example"},
    );
    try std.testing.expectError(
        error.ExcessiveLoad,
        control.applyFrame(allocator, try Frame.parse(encoded.items)),
    );
    try std.testing.expectEqual(
        max_peer_origins,
        control.peerOrigins().len,
    );
}

test "HTTP/3 owns canonical origin keys for connection pools" {
    const allocator = std.testing.allocator;

    var key = try requestOriginKey(allocator, "HTTPS", "Example.COM:443");
    defer key.deinit();
    try std.testing.expectEqualStrings("https", key.scheme);
    try std.testing.expectEqualStrings("example.com", key.host);
    try std.testing.expectEqual(@as(u16, 443), key.port);

    var from_origin = try originKeyFromOrigin(allocator, try requestOrigin("HTTPS", "Example.COM"));
    defer from_origin.deinit();
    try std.testing.expect(sameOrigin(key.origin(), from_origin.origin()));

    var sibling = try requestOriginKey(allocator, "https", "api.example.com");
    defer sibling.deinit();
    try std.testing.expectEqual(
        ReuseDecision.requires_authority_validation,
        connectionReuseDecision(key.origin(), sibling.origin()),
    );

    var ipv6 = try requestOriginKey(allocator, "HTTPS", "[2001:DB8::1]:443");
    defer ipv6.deinit();
    try std.testing.expectEqualStrings("2001:db8::1", ipv6.host);
    try std.testing.expect(sameOrigin(
        ipv6.origin(),
        try requestOrigin("https", "[2001:db8::1]"),
    ));
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
    try std.testing.expectEqual(@as(u8, FrameType.settings), encoded_frame.items[0]);
    try std.testing.expectEqual(@as(u8, @intCast(payload.items.len)), encoded_frame.items[1]);
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

test "HTTP/3 settings identifier zero is an ignorable extension" {
    const allocator = std.testing.allocator;

    const parsed = try parseSettings(allocator, &.{ 0x00, 0x2a });
    defer allocator.free(parsed);
    try std.testing.expectEqualSlices(Setting, &.{.{ .id = 0x00, .value = 0x2a }}, parsed);

    // Identifier zero has no defined HTTP/3 meaning, so the typed settings
    // view must ignore it just like any other unknown extension identifier.
    try std.testing.expectEqual(Settings{}, Settings.fromList(parsed));

    for ([_]u8{ 0x02, 0x03, 0x04, 0x05 }) |reserved_id| {
        try std.testing.expectError(
            error.InvalidSetting,
            parseSettings(allocator, &.{ reserved_id, 0x00 }),
        );
    }
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

test "HTTP/3 unidirectional stream prefixes write fixed bytes" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try writeControlStreamPrefix(&encoded, allocator);
    try writeQpackEncoderStreamPrefix(&encoded, allocator);
    try writeQpackDecoderStreamPrefix(&encoded, allocator);

    try std.testing.expectEqualSlices(u8, &.{
        @intFromEnum(StreamType.control),
        @intFromEnum(StreamType.qpack_encoder),
        @intFromEnum(StreamType.qpack_decoder),
    }, encoded.items);
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

test "HTTP/3 generic frame codec rejects WebTransport stream prefix" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try quic.varint.encode(
        &encoded,
        allocator,
        FrameType.webtransport_stream,
    );
    try quic.varint.encode(&encoded, allocator, 17);
    try std.testing.expectError(
        error.UnexpectedFrame,
        Frame.parseHeader(encoded.items),
    );
    try std.testing.expectError(
        error.UnexpectedFrame,
        (Frame{
            .frame_type = FrameType.webtransport_stream,
            .payload = &.{},
            .consumed = 0,
        }).write(&encoded, allocator),
    );
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
    try std.testing.expect(control.requestPriorityUpdate(8) == null);
    try std.testing.expect(control.pushPriorityUpdate(3) == null);
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
    var replacement_request: std.ArrayList(u8) = .empty;
    defer replacement_request.deinit(allocator);
    try writePriorityUpdateFrame(
        &replacement_request,
        allocator,
        8,
        .{ .urgency = 0 },
    );
    try control.applyFrame(
        allocator,
        try Frame.parse(replacement_request.items),
    );
    try std.testing.expectEqual(
        @as(u3, 0),
        control.requestPriorityUpdate(8).?.priority().urgency,
    );
    try std.testing.expectEqual(
        @as(u3, 5),
        control.requestPriorityUpdate(12).?.priority().urgency,
    );
    try std.testing.expectEqual(@as(usize, 2), control.priority_updates.items.len);
    try std.testing.expectEqual(
        @as(?usize, 0),
        control.priority_update_index.get(.{
            .frame_type = FrameType.priority_update_request,
            .prioritized_element_id = 8,
        }),
    );
    try std.testing.expectEqual(
        @as(?usize, 1),
        control.priority_update_index.get(.{
            .frame_type = FrameType.priority_update_request,
            .prioritized_element_id = 12,
        }),
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
    var cloned = try control.clone(allocator);
    defer cloned.deinit(allocator);
    try std.testing.expectEqual(
        @as(u3, 0),
        cloned.requestPriorityUpdate(8).?.priority().urgency,
    );
    try std.testing.expectEqual(
        @as(u3, 5),
        cloned.requestPriorityUpdate(12).?.priority().urgency,
    );
    try std.testing.expectEqual(
        @as(u3, 2),
        cloned.pushPriorityUpdate(3).?.priority().urgency,
    );

    try std.testing.expectError(error.UnexpectedFrame, writePriorityUpdateFrame(&encoded, allocator, 1, parsed));
    var invalid_priority: std.ArrayList(u8) = .empty;
    defer invalid_priority.deinit(allocator);
    try writePriorityUpdateFrameRaw(&invalid_priority, allocator, FrameType.priority_update_request, 1, "u=1");
    const invalid_frame = try Frame.parse(invalid_priority.items);
    try std.testing.expectError(error.IdError, control.applyFrame(allocator, invalid_frame));

    var no_alloc_priority: std.ArrayList(u8) = .empty;
    defer no_alloc_priority.deinit(allocator);
    try no_alloc_priority.ensureTotalCapacity(allocator, 32);
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try writePriorityUpdateFrameRaw(
        &no_alloc_priority,
        no_alloc.allocator(),
        FrameType.priority_update_request,
        16,
        "u=2",
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    const no_alloc_frame = try Frame.parse(no_alloc_priority.items);
    const no_alloc_payload = try parsePriorityUpdatePayload(no_alloc_frame.payload);
    try std.testing.expectEqual(@as(u64, 16), no_alloc_payload.prioritized_element_id);
    try std.testing.expectEqualStrings("u=2", no_alloc_payload.field_value);

    var direct_storage: [max_priority_update_frame_len]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        no_alloc_priority.items,
        try writePriorityUpdateFrameInto(
            &direct_storage,
            16,
            .{ .urgency = 2 },
        ),
    );
    var push_list: std.ArrayList(u8) = .empty;
    defer push_list.deinit(allocator);
    try writePushPriorityUpdateFrame(
        &push_list,
        allocator,
        quic.varint.max_value,
        .{ .urgency = 7, .incremental = true },
    );
    try std.testing.expectEqual(
        max_priority_update_frame_len,
        push_list.items.len,
    );
    try std.testing.expectEqualSlices(
        u8,
        push_list.items,
        try writePushPriorityUpdateFrameInto(
            &direct_storage,
            quic.varint.max_value,
            .{ .urgency = 7, .incremental = true },
        ),
    );
    try std.testing.expectError(
        error.UnexpectedFrame,
        writePriorityUpdateFrameInto(&direct_storage, 1, .{}),
    );
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

test "HTTP/3 identical priority update replacement does not allocate" {
    const allocator = std.testing.allocator;
    var control = ControlState{ .settings = .{ .received = true } };
    defer control.deinit(allocator);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writePriorityUpdateFrame(
        &encoded,
        allocator,
        0,
        .{ .urgency = 1, .incremental = true },
    );
    const frame = try Frame.parse(encoded.items);
    try control.applyFrame(allocator, frame);
    const generation = control.priority_update_generation;

    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try control.applyFrame(no_alloc.allocator(), frame);
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(
        generation + 1,
        control.priority_update_generation,
    );
    try std.testing.expectEqual(
        @as(u3, 1),
        control.requestPriorityUpdate(0).?.priority().urgency,
    );
    try std.testing.expect(
        control.requestPriorityUpdate(0).?.priority().incremental,
    );
}

test "HTTP/3 priority state is bounded and request removal repairs indexes" {
    const allocator = std.testing.allocator;
    var control = try ControlState.init(.{ .max_priority_updates = 2 });
    defer control.deinit(allocator);
    control.settings.received = true;

    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try writePriorityUpdateFrame(&first, allocator, 0, .{ .urgency = 1 });
    try control.applyFrame(allocator, try Frame.parse(first.items));
    var second: std.ArrayList(u8) = .empty;
    defer second.deinit(allocator);
    try writePriorityUpdateFrame(&second, allocator, 4, .{ .urgency = 2 });
    try control.applyFrame(allocator, try Frame.parse(second.items));

    first.clearRetainingCapacity();
    try writePriorityUpdateFrame(&first, allocator, 0, .{ .urgency = 5 });
    try control.applyFrame(allocator, try Frame.parse(first.items));
    try std.testing.expectEqual(
        @as(u3, 5),
        control.requestPriorityUpdate(0).?.priority().urgency,
    );
    var cloned = try control.clone(allocator);
    defer cloned.deinit(allocator);
    try std.testing.expectEqual(
        @as(u64, 0),
        cloned.latest_priority_update.?.prioritized_element_id,
    );
    try std.testing.expectEqual(
        @as(u3, 5),
        cloned.latest_priority_update.?.priority().urgency,
    );

    var overflow: std.ArrayList(u8) = .empty;
    defer overflow.deinit(allocator);
    try writePriorityUpdateFrame(&overflow, allocator, 8, .{});
    try std.testing.expectError(
        error.ExcessiveLoad,
        control.applyFrame(allocator, try Frame.parse(overflow.items)),
    );
    try std.testing.expect(control.requestPriorityUpdate(8) == null);

    control.removeRequestPriority(allocator, 0);
    try std.testing.expect(control.requestPriorityUpdate(0) == null);
    try std.testing.expectEqual(
        @as(u3, 2),
        control.requestPriorityUpdate(4).?.priority().urgency,
    );
    try control.applyFrame(allocator, try Frame.parse(overflow.items));
    try std.testing.expect(control.requestPriorityUpdate(8) != null);
    control.removeRequestPriority(allocator, 99);

    control.removeRequestPriority(allocator, 4);
    var push: std.ArrayList(u8) = .empty;
    defer push.deinit(allocator);
    try writePushPriorityUpdateFrame(&push, allocator, 3, .{ .urgency = 6 });
    try control.applyFrame(allocator, try Frame.parse(push.items));
    try std.testing.expect(control.pushPriorityUpdate(3) != null);
    control.removePushPriority(allocator, 3);
    try std.testing.expect(control.pushPriorityUpdate(3) == null);

    control.retireRequestPriority(allocator, 8);
    try control.applyFrame(allocator, try Frame.parse(overflow.items));
    control.discardRetiredPriorityUpdates(allocator);
    try std.testing.expect(control.requestPriorityUpdate(8) == null);
    try std.testing.expectEqual(@as(usize, 0), control.priorityUpdates().len);

    try control.applyFrame(allocator, try Frame.parse(push.items));
    control.retirePushPriority(allocator, 3);
    try control.applyFrame(allocator, try Frame.parse(push.items));
    control.discardRetiredPriorityUpdates(allocator);
    try std.testing.expect(control.pushPriorityUpdate(3) == null);
    try std.testing.expectEqual(@as(usize, 0), control.priorityUpdates().len);
}

test "HTTP/3 priority state rejects a zero bound" {
    try std.testing.expectError(
        error.InvalidSetting,
        ControlState.init(.{ .max_priority_updates = 0 }),
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
    try std.testing.expectError(error.UnexpectedFrame, initialized.applyFrame(allocator, .{
        .frame_type = FrameType.webtransport_stream,
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
    const beyond_varint = @as(u64, quic.varint.max_value) + 1;
    inline for (.{
        Settings{ .qpack_max_table_capacity = beyond_varint },
        Settings{ .max_field_section_size = beyond_varint },
        Settings{ .webtransport_max_sessions = beyond_varint },
        Settings{ .webtransport_initial_max_data = beyond_varint },
        Settings{ .webtransport_initial_max_streams_uni = beyond_varint },
        Settings{ .webtransport_initial_max_streams_bidi = beyond_varint },
    }) |invalid| {
        try std.testing.expectError(
            error.InvalidSetting,
            invalid.writePayload(&default_payload, allocator),
        );
        try std.testing.expectEqual(@as(usize, 0), default_payload.items.len);
    }
    const maximum_qpack_capacity = @min(
        @as(u64, quic.varint.max_value),
        std.math.maxInt(usize),
    );
    const maximum = Settings{
        .qpack_max_table_capacity = maximum_qpack_capacity,
        .max_field_section_size = quic.varint.max_value,
        .webtransport_max_sessions = quic.varint.max_value,
        .webtransport_initial_max_data = quic.varint.max_value,
        .webtransport_initial_max_streams_uni = quic.varint.max_value,
        .webtransport_initial_max_streams_bidi = quic.varint.max_value,
    };
    default_payload.clearRetainingCapacity();
    try maximum.writePayload(&default_payload, allocator);
    const maximum_raw = try parseSettings(allocator, default_payload.items);
    defer allocator.free(maximum_raw);
    const maximum_decoded = Settings.fromList(maximum_raw);
    try std.testing.expectEqual(
        maximum.qpack_max_table_capacity,
        maximum_decoded.qpack_max_table_capacity,
    );
    try std.testing.expectEqual(
        maximum.max_field_section_size,
        maximum_decoded.max_field_section_size,
    );
    try std.testing.expectEqual(
        maximum.webtransport_max_sessions,
        maximum_decoded.webtransport_max_sessions,
    );
    try std.testing.expectEqual(
        maximum.webtransport_initial_max_data,
        maximum_decoded.webtransport_initial_max_data,
    );
    try std.testing.expectEqual(
        maximum.webtransport_initial_max_streams_uni,
        maximum_decoded.webtransport_initial_max_streams_uni,
    );
    try std.testing.expectEqual(
        maximum.webtransport_initial_max_streams_bidi,
        maximum_decoded.webtransport_initial_max_streams_bidi,
    );

    const local = Settings{
        .max_field_section_size = 32 * 1024,
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .webtransport_max_sessions = 16,
    };

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try local.writePayload(&payload, allocator);
    try std.testing.expectEqual(payload.items.len, try local.payloadLen());
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

    var direct_frame: std.ArrayList(u8) = .empty;
    defer direct_frame.deinit(allocator);
    try direct_frame.ensureTotalCapacity(allocator, payload.items.len + 2);
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try writeSettingsFrame(&direct_frame, no_alloc.allocator(), local);
    try std.testing.expect(!no_alloc.has_induced_failure);
    const parsed_frame = try Frame.parse(direct_frame.items);
    try std.testing.expectEqual(FrameType.settings, parsed_frame.frame_type);
    try std.testing.expectEqualSlices(u8, payload.items, parsed_frame.payload);
}

test "HTTP/3 SETTINGS frame write is transactional and exactly reserved" {
    const allocator = std.testing.allocator;
    const settings = Settings{ .qpack_max_table_capacity = 64 };

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try encoded.ensureTotalCapacityPrecise(allocator, 2);
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        writeSettingsFrame(&encoded, failing.allocator(), settings),
    );
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);

    var exact_storage: [5]u8 = undefined;
    var exact = std.ArrayList(u8).initBuffer(&exact_storage);
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try writeSettingsFrame(&exact, no_alloc.allocator(), settings);
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x04, 0x03, 0x01, 0x40, 0x40 },
        exact.items,
    );
}

test "HTTP/3 accepted early data rejects reduced remembered settings" {
    const remembered = Settings{
        .qpack_max_table_capacity = 256,
        .max_field_section_size = 4096,
        .qpack_blocked_streams = 2,
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .enable_webtransport = true,
        .webtransport_max_sessions = 4,
        .webtransport_initial_max_data = 1024,
        .webtransport_initial_max_streams_uni = 2,
        .webtransport_initial_max_streams_bidi = 3,
    };
    try remembered.validateAfterEarlyDataAccepted(remembered);
    var increased = remembered;
    increased.qpack_max_table_capacity += 1;
    increased.max_field_section_size += 1;
    increased.qpack_blocked_streams += 1;
    increased.webtransport_max_sessions += 1;
    increased.webtransport_initial_max_data += 1;
    increased.webtransport_initial_max_streams_uni += 1;
    increased.webtransport_initial_max_streams_bidi += 1;
    try remembered.validateAfterEarlyDataAccepted(increased);

    inline for (.{
        "qpack capacity",
        "field section size",
        "blocked streams",
        "extended connect",
        "datagrams",
        "webtransport",
        "webtransport sessions",
        "webtransport data",
        "webtransport uni streams",
        "webtransport bidi streams",
    }, 0..) |_, index| {
        var reduced = remembered;
        switch (index) {
            0 => reduced.qpack_max_table_capacity -= 1,
            1 => reduced.max_field_section_size -= 1,
            2 => reduced.qpack_blocked_streams -= 1,
            3 => reduced.enable_connect_protocol = false,
            4 => reduced.h3_datagram = false,
            5 => reduced.enable_webtransport = false,
            6 => reduced.webtransport_max_sessions -= 1,
            7 => reduced.webtransport_initial_max_data -= 1,
            8 => reduced.webtransport_initial_max_streams_uni -= 1,
            9 => reduced.webtransport_initial_max_streams_bidi -= 1,
            else => unreachable,
        }
        try std.testing.expectError(
            error.InvalidSetting,
            remembered.validateAfterEarlyDataAccepted(reduced),
        );
    }

    const allocator = std.testing.allocator;
    var control = ControlState{
        .early_data_peer_settings = remembered,
    };
    defer control.deinit(allocator);
    var reduced_frame: std.ArrayList(u8) = .empty;
    defer reduced_frame.deinit(allocator);
    var reduced = remembered;
    reduced.max_field_section_size -= 1;
    try writeSettingsFrame(&reduced_frame, allocator, reduced);
    try std.testing.expectError(
        error.InvalidSetting,
        control.applyFrame(allocator, try Frame.parse(reduced_frame.items)),
    );
    try std.testing.expect(!control.settings.received);
    try std.testing.expect(control.early_data_peer_settings != null);

    var accepted_frame: std.ArrayList(u8) = .empty;
    defer accepted_frame.deinit(allocator);
    try writeSettingsFrame(&accepted_frame, allocator, increased);
    try control.applyFrame(
        allocator,
        try Frame.parse(accepted_frame.items),
    );
    try std.testing.expect(control.settings.received);
    try std.testing.expect(control.early_data_peer_settings == null);
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
        peer_control.cancelledPushRangeCount(),
    );
}

test "HTTP/3 single-varint control frames avoid temporary payload allocation" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try encoded.ensureTotalCapacity(allocator, 16);

    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try writeCancelPushFrame(&encoded, no_alloc.allocator(), 7);
    try writeMaxPushIdFrame(&encoded, no_alloc.allocator(), 4);

    var control = ControlState{};
    try control.writeGoAway(&encoded, no_alloc.allocator(), 12);

    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, &.{
        FrameType.cancel_push, 1, 7,
        FrameType.max_push_id, 1, 4,
        FrameType.goaway,      1, 12,
    }, encoded.items);

    var storage: [max_single_varint_frame_len]u8 = undefined;
    var direct_control = ControlState{};
    try std.testing.expectEqualSlices(
        u8,
        encoded.items[0..3],
        try writeCancelPushFrameInto(&storage, 7),
    );
    try std.testing.expectEqualSlices(
        u8,
        encoded.items[3..6],
        try direct_control.writeMaxPushIdInto(&storage, 4),
    );
    try std.testing.expectEqualSlices(
        u8,
        encoded.items[6..9],
        try direct_control.writeGoAwayInto(&storage, 12),
    );
    try std.testing.expectError(
        error.GoAwayIdIncreased,
        direct_control.writeGoAwayInto(&storage, 16),
    );
    try std.testing.expectError(
        error.MaxPushIdReduced,
        direct_control.writeMaxPushIdInto(&storage, 2),
    );
    const max_value_frame = try writeCancelPushFrameInto(
        &storage,
        quic.varint.max_value,
    );
    try std.testing.expectEqual(max_single_varint_frame_len, max_value_frame.len);
    try std.testing.expectEqual(
        quic.varint.max_value,
        try parseCancelPushPayload((try Frame.parse(max_value_frame)).payload),
    );
    try std.testing.expectError(
        error.VarIntTooLarge,
        writeCancelPushFrameInto(
            &storage,
            @as(u64, quic.varint.max_value) + 1,
        ),
    );

    var failed_control = ControlState{};
    var failed: std.ArrayList(u8) = .empty;
    defer failed.deinit(allocator);
    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        failed_control.writeGoAway(
            &failed,
            fail_first.allocator(),
            4,
        ),
    );
    try std.testing.expectEqual(@as(?u64, null), failed_control.local_goaway_id);
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

    var no_alloc_encoded: std.ArrayList(u8) = .empty;
    defer no_alloc_encoded.deinit(allocator);
    try no_alloc_encoded.ensureTotalCapacity(allocator, 64);
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try writePushPromiseFrame(&no_alloc_encoded, no_alloc.allocator(), 3, field_section.items);
    try std.testing.expect(!no_alloc.has_induced_failure);
    const no_alloc_frame = try Frame.parse(no_alloc_encoded.items);
    try std.testing.expectEqual(FrameType.push_promise, no_alloc_frame.frame_type);
    try std.testing.expectEqual(@as(u64, 3), (try parsePushPromisePayload(no_alloc_frame.payload)).push_id);
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
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.ExcessiveLoad,
        decodeRequestWithSettings(
            no_alloc.allocator(),
            request_bytes.items,
            .{ .max_field_section_size = 1 },
        ),
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
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
        control.cancelledPushRangeCount(),
    );
    var cloned = try control.clone(allocator);
    defer cloned.deinit(allocator);
    try std.testing.expect(cloned.pushCancelled(1));
    try std.testing.expect(cloned.pushCancelled(3));
}

test "HTTP/3 per-ID push cancellation is allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkPushCancellationStateAllocationFailure,
        .{},
    );
}

test "HTTP/3 sequential push cancellation history remains allocation-free" {
    const allocator = std.testing.allocator;
    var control = ControlState{ .settings = .{ .received = true } };
    defer control.deinit(allocator);
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );

    for (0..64) |push_id| {
        const payload = [_]u8{@intCast(push_id)};
        try control.applyFrame(no_alloc.allocator(), .{
            .frame_type = FrameType.cancel_push,
            .payload = &payload,
            .consumed = 0,
        });
    }
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 1), control.cancelledPushRangeCount());
    try std.testing.expectEqual(@as(u64, 64), control.push_cancellation_generation);
    for (0..64) |push_id| try std.testing.expect(
        control.pushCancelled(push_id),
    );

    const generation = control.push_cancellation_generation;
    try control.applyFrame(no_alloc.allocator(), .{
        .frame_type = FrameType.cancel_push,
        .payload = &.{31},
        .consumed = 0,
    });
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(generation, control.push_cancellation_generation);

    var cloned = try control.clone(no_alloc.allocator());
    defer cloned.deinit(allocator);
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 1), cloned.cancelledPushRangeCount());
    try std.testing.expect(cloned.pushCancelled(0));
    try std.testing.expect(cloned.pushCancelled(63));
    try std.testing.expect(!cloned.pushCancelled(64));
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
    try std.testing.expectEqual(@as(u8, 4), encoded.items[0]);
    const parsed = try Datagram.parse(encoded.items);
    try std.testing.expectEqual(@as(u64, 4), parsed.quarter_stream_id);
    try std.testing.expectEqualStrings("capsule", parsed.payload);
}

test "HTTP/3 datagram bounds the Quarter Stream ID" {
    const allocator = std.testing.allocator;
    const maximum = Datagram.max_quarter_stream_id;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (Datagram{
        .quarter_stream_id = maximum,
        .payload = &.{},
    }).write(&encoded, allocator);
    try std.testing.expectEqual(
        maximum,
        (try Datagram.parse(encoded.items)).quarter_stream_id,
    );

    encoded.clearRetainingCapacity();
    try quic.varint.encode(&encoded, allocator, maximum + 1);
    try std.testing.expectError(error.InvalidFrame, Datagram.parse(encoded.items));
    try std.testing.expectError(error.InvalidFrame, (Datagram{
        .quarter_stream_id = maximum + 1,
        .payload = &.{},
    }).write(&encoded, allocator));
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

test "HTTP/3 request context accepts OPTIONS asterisk only" {
    const options_asterisk = Request{
        .method = "OPTIONS",
        .path = "*",
        .authority = "example.com",
    };
    try options_asterisk.validateForContext(.direct);
    try options_asterisk.validateForContext(.proxy);

    try std.testing.expectError(
        error.InvalidHeader,
        (Request{
            .method = "GET",
            .path = "*",
            .authority = "example.com",
        }).validateForContext(.direct),
    );
    try std.testing.expectError(
        error.InvalidHeader,
        (Request{
            .method = "options",
            .path = "*",
            .authority = "example.com",
        }).validateForContext(.proxy),
    );
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

test "HTTP/3 aggregate response decodes push promises and counts their acknowledgments" {
    const allocator = std.testing.allocator;
    var table = Qpack.DynamicTable.init(allocator, 512);
    defer table.deinit();
    try table.setCapacity(512);
    _ = try table.insert("x-push-kind", "dynamic-asset");

    var promise_block: std.ArrayList(u8) = .empty;
    defer promise_block.deinit(allocator);
    try Qpack.encodeDynamicBlock(&promise_block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/asset.css" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = "x-push-kind", .value = "dynamic-asset" },
    }, table);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writePushPromiseFrame(
        &encoded,
        allocator,
        3,
        promise_block.items,
    );
    try (Response{ .status = 204 }).write(&encoded, allocator);

    var decoded = try decodeResponseWithDynamicTable(
        allocator,
        encoded.items,
        .{},
        table,
    );
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), decoded.status);
    try std.testing.expectEqual(
        @as(usize, 1),
        decoded.qpack_section_acknowledgments,
    );
    var decoded_head = try decodeResponseHeadWithDynamicTable(
        allocator,
        encoded.items,
        .{},
        table,
    );
    defer decoded_head.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), decoded_head.status);
    try std.testing.expectEqual(encoded.items.len, decoded_head.consumed);
    try std.testing.expectEqual(
        @as(usize, 1),
        decoded_head.qpack_section_acknowledgments,
    );

    var malformed: std.ArrayList(u8) = .empty;
    defer malformed.deinit(allocator);
    // The prefix is complete and declares no dynamic dependency; the literal
    // field line itself is truncated. This ensures aggregate decoding, not
    // the dependency prepass, detects the malformed promise.
    try writePushPromiseFrame(
        &malformed,
        allocator,
        3,
        &.{ 0x00, 0x00, 0x20 },
    );
    try (Response{ .status = 204 }).write(&malformed, allocator);
    try std.testing.expectError(
        error.QpackDecompressionFailed,
        decodeResponseWithDynamicTable(
            allocator,
            malformed.items,
            .{},
            table,
        ),
    );
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
    const request_storage = request_head.headers[0].block_storage orelse
        return error.TestUnexpectedResult;
    for (request_head.headers) |field| {
        try std.testing.expect(field.name_storage == null);
        try std.testing.expect(field.value_storage == null);
        try std.testing.expectEqual(
            field.name.ptr + field.name.len,
            field.value.ptr,
        );
        try std.testing.expect(
            @intFromPtr(field.value.ptr) + field.value.len <=
                @intFromPtr(request_storage.ptr) + request_storage.len,
        );
    }

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

test "HTTP/3 owned header fields use one allocation per materialized field" {
    const allocator = std.testing.allocator;
    var tracking = std.testing.FailingAllocator.init(allocator, .{});
    const tracked = tracking.allocator();
    const fields = try tracked.alloc(Qpack.HeaderField, 3);
    var transferred = false;
    defer if (!transferred) tracked.free(fields);

    fields[0] = .{ .name = ":status", .value = "200" };
    const dynamic_storage = try tracked.dupe(u8, "x-dynamicvalue");
    fields[1] = .{
        .name = dynamic_storage[0..9],
        .value = dynamic_storage[9..],
        .name_storage = dynamic_storage,
    };
    const decoded_value = try tracked.dupe(u8, "decoded-value");
    fields[2] = .{
        .name = "content-type",
        .value = decoded_value,
        .value_storage = decoded_value,
    };

    const before = tracking.allocations;
    const owned = try ownHeaderFields(tracked, fields);
    transferred = true;
    defer Qpack.freeDecodedFields(tracked, owned);

    try std.testing.expectEqual(fields.ptr, owned.ptr);
    // The already-contiguous dynamic field transfers without allocation. The
    // fully borrowed and partially owned fields each need exactly one new
    // backing block, rather than one allocation per string.
    try std.testing.expectEqual(before + 2, tracking.allocations);
    for (owned) |field| {
        const storage = field.name_storage orelse
            return error.TestUnexpectedResult;
        try std.testing.expect(field.value_storage == null);
        try std.testing.expectEqual(storage.ptr, field.name.ptr);
        try std.testing.expectEqual(
            storage.ptr + field.name.len,
            field.value.ptr,
        );
        try std.testing.expectEqual(
            storage.len,
            field.name.len + field.value.len,
        );
    }
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

    var invalid_order_and_length: std.ArrayList(u8) = .empty;
    defer invalid_order_and_length.deinit(allocator);
    signed_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&signed_block, allocator, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = "content-length", .value = "+4" },
        .{ .name = ":path", .value = "/late-pseudo" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = signed_block.items,
        .consumed = 0,
    }).write(&invalid_order_and_length, allocator);
    try std.testing.expectError(
        error.InvalidHeader,
        decodeRequest(allocator, invalid_order_and_length.items),
    );

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
    var promised_headers: std.ArrayList(u8) = .empty;
    defer promised_headers.deinit(allocator);
    try Qpack.encodeLiteralBlock(&promised_headers, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/promised" },
        .{ .name = ":authority", .value = "example.test" },
    });
    try writePushPromiseFrame(
        &pushed_response,
        allocator,
        0,
        promised_headers.items,
    );
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

    inline for ([_]u64{
        FrameType.settings,
        FrameType.origin,
        FrameType.webtransport_stream,
    }) |frame_type| {
        var forbidden: std.ArrayList(u8) = .empty;
        defer forbidden.deinit(allocator);
        try (Frame{
            .frame_type = FrameType.headers,
            .payload = header_block.items,
            .consumed = 0,
        }).write(&forbidden, allocator);
        if (frame_type == FrameType.webtransport_stream) {
            try quic.varint.encode(&forbidden, allocator, frame_type);
            try quic.varint.encode(&forbidden, allocator, 0);
        } else {
            try (Frame{
                .frame_type = frame_type,
                .payload = &.{},
                .consumed = 0,
            }).write(&forbidden, allocator);
        }
        try std.testing.expectError(
            error.UnexpectedFrame,
            decodeResponse(allocator, forbidden.items),
        );
    }
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

    var bad_priority: std.ArrayList(u8) = .empty;
    defer bad_priority.deinit(allocator);
    try Helper.writeRequestBlock(&bad_priority, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "priority", .value = "u=1," },
    });
    try std.testing.expectError(
        error.InvalidHeader,
        decodeRequest(allocator, bad_priority.items),
    );

    var good_priority: std.ArrayList(u8) = .empty;
    defer good_priority.deinit(allocator);
    try Helper.writeRequestBlock(&good_priority, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "priority", .value = "u=1, i" },
    });
    var priority_decoded = try decodeRequest(
        allocator,
        good_priority.items,
    );
    priority_decoded.deinit(allocator);

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
    try std.testing.expectError(error.InvalidContentLength, (Response{
        .status = 205,
        .body = "body",
    }).write(&encoded, allocator));
    try std.testing.expectError(error.InvalidContentLength, (Response{
        .status = 205,
        .headers = &.{.{ .name = "content-length", .value = "1" }},
    }).write(&encoded, allocator));
    try validateResponseBodyForStatusWithLength(
        205,
        4,
        "body",
        &.{},
    );
    var peer_reset_bytes: std.ArrayList(u8) = .empty;
    defer peer_reset_bytes.deinit(allocator);
    var peer_reset_fields: std.ArrayList(u8) = .empty;
    defer peer_reset_fields.deinit(allocator);
    try Qpack.encodeLiteralBlock(&peer_reset_fields, allocator, &.{
        .{ .name = ":status", .value = "205" },
        .{ .name = "content-length", .value = "4" },
    });
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = peer_reset_fields.items,
        .consumed = 0,
    }).write(&peer_reset_bytes, allocator);
    try (Frame{
        .frame_type = FrameType.data,
        .payload = "body",
        .consumed = 0,
    }).write(&peer_reset_bytes, allocator);
    var peer_reset = try decodeResponse(allocator, peer_reset_bytes.items);
    defer peer_reset.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 205), peer_reset.status);
    try std.testing.expectEqualStrings("body", peer_reset.body);
    encoded.clearRetainingCapacity();
    try (Response{
        .status = 205,
        .headers = &.{.{ .name = "content-length", .value = "0" }},
        .trailers = &.{.{ .name = "x-reset-complete", .value = "yes" }},
    }).write(&encoded, allocator);
    var reset = try decodeResponse(allocator, encoded.items);
    defer reset.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 205), reset.status);
    try std.testing.expectEqualStrings("", reset.body);
    try std.testing.expectEqual(@as(usize, 1), reset.trailers.len);
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

test "HTTP/3 response honors HEAD and CONNECT request semantics" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try (Response{
        .status = 200,
        .headers = &.{.{ .name = "content-length", .value = "14" }},
        .body = "representation",
        .request_method = "HEAD",
    }).write(&encoded, allocator);
    var head = try decodeResponseWithOptions(
        allocator,
        encoded.items,
        .{ .request_method = "HEAD" },
    );
    defer head.deinit(allocator);
    try std.testing.expectEqualStrings("", head.body);
    try std.testing.expectEqualStrings(
        "14",
        findHeader(head.headers, "content-length") orelse
            return error.MissingHeader,
    );

    var illegal_head: std.ArrayList(u8) = .empty;
    defer illegal_head.deinit(allocator);
    try (Response{
        .status = 200,
        .body = "illegal",
    }).write(&illegal_head, allocator);
    try std.testing.expectError(
        error.InvalidContentLength,
        decodeResponseWithOptions(allocator, illegal_head.items, .{
            .request_method = "HEAD",
        }),
    );

    encoded.clearRetainingCapacity();
    try (Response{
        .status = 200,
        .headers = &.{.{ .name = "content-length", .value = "0" }},
        .request_method = "CONNECT",
    }).write(&encoded, allocator);
    var connect = try decodeResponseWithOptions(
        allocator,
        encoded.items,
        .{ .request_method = "CONNECT" },
    );
    defer connect.deinit(allocator);
    try std.testing.expect(findHeader(connect.headers, "content-length") == null);

    try std.testing.expectError(error.InvalidContentLength, (Response{
        .status = 200,
        .body = "not-http-body",
        .request_method = "CONNECT",
    }).write(&encoded, allocator));

    encoded.clearRetainingCapacity();
    try (Response{
        .status = 200,
        .body = "extended-data",
        .request_method = "CONNECT",
        .extended_connect = true,
    }).write(&encoded, allocator);
    var extended = try decodeResponseWithOptions(
        allocator,
        encoded.items,
        .{
            .request_method = "CONNECT",
            .extended_connect = true,
        },
    );
    defer extended.deinit(allocator);
    try std.testing.expectEqualStrings("extended-data", extended.body);
}

test {
    _ = runtime;
    _ = origin_pool;
    _ = @import("codec/header_capacity_tests.zig");
    _ = @import("informational_tests.zig");
}
