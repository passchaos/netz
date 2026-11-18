const content_digest = @import("../http/digest.zig");
const std = @import("std");
const authority_semantics = @import("../http/authority/mod.zig");

test {
    _ = @import("origin_normalization_tests.zig");
}
pub const wire = @import("../internal/wire.zig");
const priority_field = @import("../internal/priority.zig");
pub const exact_range_set = @import("../internal/exact_range_set.zig");
const http_method = @import("../internal/http_method.zig");
const content_coding = @import("../http/content_coding.zig");
const early_data = @import("../http/early_data.zig");
pub const quic = @import("../quic/mod.zig");
const header_fields = @import("codec/header_storage.zig");

pub const runtime = @import("runtime.zig");
pub const socks5_runtime = @import("socks5_runtime.zig");
pub const capsule = @import("capsule.zig");
pub const connect_udp = @import("connect_udp.zig").Protocol(@This());
pub const connect_ip = @import("connect_ip.zig").Protocol(@This());
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
/// Bound each retained RFC 9218 PRIORITY_UPDATE payload. This matches quiche's
/// control-frame limit and prevents the entry-count cap from multiplying the
/// complete 64-KiB control-stream buffering allowance.
pub const default_max_priority_update_payload_size: usize = 256;
/// Backwards-compatible name for the default per-connection receive policy.
pub const max_priority_update_payload_size: usize =
    default_max_priority_update_payload_size;
/// Bound partial control-frame retention, including fragmented ORIGIN frames.
pub const max_control_stream_buffer_size: usize = 64 * 1024;
pub const max_control_frame_header_size: usize = 16;

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
    const parsed_authority = authority_semantics.parse(authority) catch return error.InvalidHeader;
    const default_port = defaultPortForScheme(scheme) orelse return error.InvalidHeader;
    return .{
        .scheme = scheme,
        .host = if (parsed_authority.kind == .future) authority[0 .. parsed_authority.host.len + 2] else parsed_authority.host,
        .port = parsed_authority.port orelse default_port,
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
    if (serialized.len < uri.scheme.len + 3 or !std.mem.eql(u8, serialized[uri.scheme.len..][0..3], "://")) return error.InvalidOrigin;
    const raw_authority = serialized[uri.scheme.len + 3 ..];
    const parsed_authority = authority_semantics.parse(raw_authority) catch return error.InvalidOrigin;
    const default_port = defaultPortForScheme(uri.scheme) orelse return error.InvalidOrigin;
    return .{
        .scheme = uri.scheme,
        .host = if (parsed_authority.kind == .future) raw_authority[0 .. parsed_authority.host.len + 2] else parsed_authority.host,
        .port = parsed_authority.port orelse default_port,
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
    try validateUriScheme(origin.scheme);
    const owned_host = authority_semantics.canonicalHostAlloc(allocator, origin.host) catch |err| switch (err) {
        error.InvalidAuthority => return error.InvalidHeader,
        error.OutOfMemory => return error.OutOfMemory,
    };
    errdefer allocator.free(owned_host);
    const owned_scheme = try asciiLowerAlloc(allocator, origin.scheme);
    errdefer allocator.free(owned_scheme);

    return .{
        .allocator = allocator,
        .scheme = owned_scheme,
        .host = owned_host,
        .port = origin.port,
    };
}

pub fn cloneOriginKey(
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

pub fn cloneOrigin(allocator: std.mem.Allocator, origin: Origin) Error!OriginKey {
    return originKeyFromOrigin(allocator, origin);
}

pub fn sameOrigin(a: Origin, b: Origin) bool {
    return std.ascii.eqlIgnoreCase(a.scheme, b.scheme) and
        authority_semantics.hostEquivalent(a.host, b.host) and
        a.port == b.port;
}

pub fn originListContains(origins: []const OriginKey, origin: Origin) bool {
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

pub const SettingId = @import("settings.zig").SettingId;
pub const Setting = @import("settings.zig").Setting;
pub const Settings = @import("settings.zig").Settings;
pub const SettingsState = @import("settings.zig").SettingsState;
pub const WebTransportVersion = @import("settings.zig").WebTransportVersion;
pub const WebTransportVersions = @import("settings.zig").WebTransportVersions;

fn addFrameLen(a: usize, b: usize) Error!usize {
    return std.math.add(usize, a, b) catch error.IntegerOverflow;
}

pub const ControlState = @import("control.zig").ControlState;

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

pub fn validateRequestStreamId(stream_id: u64) Error!void {
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

pub fn writeSingleVarintFrameInto(
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

pub fn parseSingleVarintPayload(payload: []const u8) Error!u64 {
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
        try early_data.validateOutboundRequestHeaders(self.headers);

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
            if (host_value) |host| {
                try validateRequestAuthority(host);
                if (!authority_semantics.equivalent("", authority, host)) return error.InvalidHeader;
            }
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
                    if (!authority_semantics.equivalent(self.scheme, authority, host)) {
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

    pub fn mightHaveBeenEarly(self: Request) bool {
        return early_data.requestMightHaveBeenEarly(self.headers);
    }

    pub fn earlyDataForwardingAction(
        self: Request,
        current_hop_was_early_data: bool,
    ) early_data.ForwardingAction {
        return early_data.forwardingAction(
            self.headers,
            current_hop_was_early_data,
        );
    }

    pub fn headerFields(self: Request, out: []Qpack.HeaderField) Error![]Qpack.HeaderField {
        try early_data.validateOutboundRequestHeaders(self.headers);
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
        return self.writeCompleteDynamic(list, allocator, peer_settings, stream_id, encoder, true);
    }

    /// Validate the complete body and trailers before encoding its initial
    /// HEADERS. Runtimes can then send borrowed DATA under flow control without
    /// retaining a second encoded copy of the complete request.
    pub fn writeCompleteHeadDynamic(
        self: Request,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        peer_settings: Settings,
        stream_id: u64,
        encoder: anytype,
    ) Error!void {
        return self.writeCompleteDynamic(list, allocator, peer_settings, stream_id, encoder, false);
    }

    fn writeCompleteDynamic(
        self: Request,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        peer_settings: Settings,
        stream_id: u64,
        encoder: anytype,
        include_body: bool,
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
        if (include_body) {
            try writeHeadersAndDataDynamic(
                list,
                allocator,
                fields,
                self.body,
                self.trailers,
                stream_id,
                encoder,
            );
        } else {
            try writeHeadersFrameDynamic(list, allocator, fields, stream_id, encoder);
        }
        try queueIndexableFields(encoder, fields);
        if (include_body) try queueIndexableFields(encoder, self.trailers);
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

pub fn findHeader(headers: []const Qpack.HeaderField, name: []const u8) ?[]const u8 {
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
        return self.writeCompleteDynamic(list, allocator, peer_settings, stream_id, encoder, true);
    }

    /// Validate the complete response and encode only its final HEADERS.
    /// Complete runtimes then send borrowed DATA with transport flow control.
    pub fn writeCompleteHeadDynamic(
        self: Response,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        peer_settings: Settings,
        stream_id: u64,
        encoder: anytype,
    ) Error!void {
        return self.writeCompleteDynamic(list, allocator, peer_settings, stream_id, encoder, false);
    }

    fn writeCompleteDynamic(
        self: Response,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        peer_settings: Settings,
        stream_id: u64,
        encoder: anytype,
        include_body: bool,
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
        if (include_body) {
            try writeHeadersAndDataDynamic(
                list,
                allocator,
                fields,
                if (responseSuppressesBody(self.status, semantics)) &.{} else self.body,
                if (responseSuppressesBody(self.status, semantics)) &.{} else self.trailers,
                stream_id,
                encoder,
            );
        } else {
            try writeHeadersFrameDynamic(list, allocator, fields, stream_id, encoder);
        }
        try queueIndexableFields(encoder, fields);
        if (include_body) try queueIndexableFields(encoder, self.trailers);
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

    pub fn mightHaveBeenEarly(self: DecodedRequest) bool {
        return early_data.requestMightHaveBeenEarly(self.headers);
    }

    /// Release arrays and body storage owned by `decodeRequest`. Header field
    /// names/values still borrow from the encoded stream bytes; callers must
    /// keep those bytes alive while reading `headers` or `trailers`.
    pub fn deinit(self: *DecodedRequest, allocator: std.mem.Allocator) void {
        Qpack.freeDecodedFields(allocator, self.headers);
        Qpack.freeDecodedFields(allocator, self.trailers);
        if (self.body_storage) |body| allocator.free(body);
        self.* = undefined;
    }

    pub fn contentEncoding(
        self: DecodedRequest,
    ) content_coding.Error!content_coding.Chain {
        return content_coding.parseHeaders(self.headers);
    }

    /// Decode Content-Encoding layers without mutating QPACK-owned metadata
    /// or the encoded request body.
    pub fn decodeContentAlloc(
        self: DecodedRequest,
        allocator: std.mem.Allocator,
        max_output_len: usize,
    ) content_coding.Error!content_coding.DecodedBody {
        return content_coding.decodeHeadersAlloc(
            allocator,
            self.headers,
            self.body,
            max_output_len,
        );
    }

    pub fn decodeContentInto(
        self: DecodedRequest,
        out: []u8,
        scratch: []u8,
    ) content_coding.Error![]u8 {
        return (try self.contentEncoding()).decodeInto(
            self.body,
            out,
            scratch,
        );
    }
};

pub const DecodedResponse = struct {
    status: u16,
    headers: []Qpack.HeaderField,
    trailers: []Qpack.HeaderField = &.{},
    body: []const u8,
    body_storage: ?[]u8 = null,
    /// False when originating-request semantics suppress representation data.
    body_allowed: bool = true,
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

    /// Validate actual message content, including content-coded bytes, against
    /// every enabled Content-Digest in headers and trailers.
    pub fn verifyContentDigest(self: DecodedResponse, policy: content_digest.Policy) content_digest.Error!content_digest.Result {
        return content_digest.verifyContent(self.body, self.headers, self.trailers, policy);
    }

    pub fn contentEncoding(
        self: DecodedResponse,
    ) content_coding.Error!content_coding.Chain {
        return content_coding.parseHeaders(self.headers);
    }

    /// Decode Content-Encoding layers without mutating QPACK-owned metadata
    /// or the encoded response body.
    pub fn decodeContentAlloc(
        self: DecodedResponse,
        allocator: std.mem.Allocator,
        max_output_len: usize,
    ) content_coding.Error!content_coding.DecodedBody {
        return (try content_coding.responseDecodingChain(self.headers, self.status, self.body_allowed)).decodeAlloc(
            allocator,
            self.body,
            max_output_len,
        );
    }

    pub fn decodeContentInto(
        self: DecodedResponse,
        out: []u8,
        scratch: []u8,
    ) content_coding.Error![]u8 {
        return (try content_coding.responseDecodingChain(self.headers, self.status, self.body_allowed)).decodeInto(
            self.body,
            out,
            scratch,
        );
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
    /// True when the request stream ended with the head, so the handler can
    /// run without waiting for body events.
    request_finished: bool = false,
    consumed: usize,
    qpack_section_acknowledgments: usize,

    pub fn mightHaveBeenEarly(self: DecodedRequestHead) bool {
        return early_data.requestMightHaveBeenEarly(self.headers);
    }

    pub fn streamContentDecoder(
        self: DecodedRequestHead,
        allocator: std.mem.Allocator,
        options: content_coding.StreamOptions,
    ) content_coding.Error!content_coding.StreamDecoder {
        return (try content_coding.parseHeaders(self.headers)).streamDecoder(
            allocator,
            options,
        );
    }

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

    pub fn streamContentDecoder(
        self: DecodedResponseHead,
        allocator: std.mem.Allocator,
        options: content_coding.StreamOptions,
    ) content_coding.Error!content_coding.StreamDecoder {
        return (try content_coding.responseDecodingChain(self.headers, self.status, self.body_allowed)).streamDecoder(
            allocator,
            options,
        );
    }

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

pub fn ownHeaderFields(
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

pub fn ownedFieldValue(
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
        .body_allowed = !responseSuppressesBody(final_status, semantics),
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
                // RFC 9114 section 4.1 allows PUSH_PROMISE before, after, or
                // interleaved with response-message frames. It remains
                // forbidden on request and push streams.
                if (kind == .request) return error.UnexpectedFrame;
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

pub fn validateResponseBodyForStatusWithLength(
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
        if (kind == .response and early_data.isHeaderName(header.name)) {
            return error.InvalidHeader;
        }
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
                const authority = authority_value orelse return error.InvalidHeader;
                try validateConnectAuthority(authority);
                if (host_value) |host| {
                    try validateRequestAuthority(host);
                    if (!authority_semantics.equivalent("", authority, host)) return error.InvalidHeader;
                }
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
                        if (!authority_semantics.equivalent(scheme, authority, host)) return error.InvalidHeader;
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
    _ = authority_semantics.parse(authority) catch return error.InvalidHeader;
}

fn validateConnectAuthority(authority: []const u8) Error!void {
    authority_semantics.validateConnect(authority) catch return error.InvalidHeader;
}

const validateHeaderName = @import("../http/field_name.zig").validate;

const validateHeaderValue = @import("../http/field_value.zig").validate;

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
    return early_data.isHeaderName(name) or
        std.ascii.eqlIgnoreCase(name, "authorization") or
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

test {
    _ = @import("qpack/tests.zig");
    _ = @import("priority_dictionary_tests.zig");
    _ = @import("priority_metadata_tests.zig");
}

pub fn checkPriorityUpdateStateAllocationFailure(
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

pub fn checkPushCancellationStateAllocationFailure(
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

pub fn checkDynamicQpackHeadAllocationFailure(
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

pub fn checkDynamicQpackMessageAllocationFailure(allocator: std.mem.Allocator) !void {
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

test {
    _ = runtime;
    _ = origin_pool;
    _ = @import("connect_ip_tests.zig");
    _ = @import("codec/header_capacity_tests.zig");
    _ = @import("control_frame_limits_tests.zig");
    _ = @import("informational_tests.zig");
}

test {
    _ = @import("settings.zig");
}

test {
    _ = @import("tests.zig");
}
