const std = @import("std");
const authority_semantics = @import("../../../http/authority/mod.zig");
const http2 = @import("../../mod.zig");
const connection_headers = @import("connection.zig");
const http_method = @import("../../../internal/http_method.zig");
const early_data = @import("../../../http/early_data.zig");

pub const Error = http2.Error || error{
    MissingPseudoHeader,
    InvalidStatus,
    InvalidContentLength,
    InvalidHeader,
    MessageTooLarge,
};

pub const ResponseBodySemantics = struct {
    head: bool = false,
    traditional_connect: bool = false,
    extended_connect: bool = false,
};
pub fn contentLength(headers: []const http2.Hpack.HeaderField) Error!?usize {
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

pub const ResponseHeaderLookup = struct {
    status: ?[]const u8 = null,
    content_length: ?usize = null,
};

pub fn responseHeaderLookup(headers: []const http2.Hpack.HeaderField) Error!ResponseHeaderLookup {
    var lookup: ResponseHeaderLookup = .{};
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, ":status")) {
            if (lookup.status == null) lookup.status = header.value;
            continue;
        }
        if (!std.ascii.eqlIgnoreCase(header.name, "content-length")) continue;
        try parseContentLengthHeaderValue(header.value, &lookup.content_length);
    }
    return lookup;
}

pub fn validateContentLength(headers: []const http2.Hpack.HeaderField, actual: usize) Error!void {
    try validateExpectedContentLength(try contentLength(headers), actual);
}

pub fn validateExpectedContentLength(expected: ?usize, actual: usize) Error!void {
    if (expected) |value| {
        if (value != actual) return error.InvalidContentLength;
    }
}

/// HEAD and 304 may advertise a representation length without transferring
/// its content. Check their actual empty body independently of that metadata.
pub fn validateResponseContentLength(expected: ?usize, actual: usize, body_allowed: bool) Error!void {
    if (!body_allowed) {
        if (actual != 0) return error.InvalidContentLength;
        return;
    }
    try validateExpectedContentLength(expected, actual);
}

/// Validate DATA before retaining or exposing it. A declared length is an
/// upper bound throughout the response and must match exactly at END_STREAM
/// (RFC 9113 section 8.1.1). Count content only, excluding DATA padding.
pub fn checkedResponseBodyLength(
    expected: ?usize,
    current: usize,
    additional: usize,
    max_body_bytes: usize,
    body_allowed: bool,
    end_stream: bool,
) error{ InvalidContentLength, MessageTooLarge }!usize {
    if (!body_allowed and (current != 0 or additional != 0)) return error.InvalidContentLength;
    return checkedBodyLength(if (body_allowed) expected else null, current, additional, max_body_bytes, end_stream);
}

/// Shared request/response content accounting. Validate a DATA frame before
/// storage or application delivery, excluding its padding from content length.
pub fn checkedBodyLength(
    expected: ?usize,
    current: usize,
    additional: usize,
    max_body_bytes: usize,
    end_stream: bool,
) error{ InvalidContentLength, MessageTooLarge }!usize {
    const next = std.math.add(usize, current, additional) catch return error.MessageTooLarge;
    if (next > max_body_bytes) return error.MessageTooLarge;
    if (expected) |length| {
        if (next > length or (end_stream and next != length)) return error.InvalidContentLength;
    }
    return next;
}

pub fn validateDeclaredRequestLength(headers: []const http2.Hpack.HeaderField, body_len: usize) Error!void {
    if (try contentLength(headers)) |expected| {
        if (expected != body_len) return error.InvalidContentLength;
    }
}

pub fn requestShouldDefaultContentLength(method: []const u8, headers: []const http2.Hpack.HeaderField, body_len: usize) bool {
    if (methodIsConnect(method)) return false;
    // Match Hyper's h2 request shaping: exact non-empty bodies always get a
    // length, and bodyless methods with defined payload semantics (for example
    // POST/PUT/PATCH) get an explicit `content-length: 0`.  The explicit zero
    // preserves application intent for methods where an empty payload is
    // materially different from a method that normally carries no payload.
    if (body_len == 0 and !methodHasDefinedPayloadSemantics(method)) return false;
    return (contentLength(headers) catch return false) == null;
}

pub fn stripSuccessfulConnectContentLength(headers: *std.ArrayList(http2.Hpack.HeaderField)) Error!void {
    const declared = try contentLength(headers.items) orelse return;
    if (declared != 0) return error.InvalidContentLength;

    var write_index: usize = 0;
    for (headers.items) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "content-length")) {
            // Hyper allows `content-length: 0` on successful CONNECT responses
            // for peer compatibility, but strips it before sending such a
            // response itself.  The stream is a tunnel after the 2xx HEADERS, so
            // retaining even a zero representation length is misleading metadata.
            continue;
        }
        headers.items[write_index] = header;
        write_index += 1;
    }
    headers.shrinkRetainingCapacity(write_index);
}

pub fn validateHeaderListSize(headers: []const http2.Hpack.HeaderField, max_size: usize) Error!void {
    var total: usize = 0;
    for (headers) |header| {
        // RFC 9113 measures SETTINGS_MAX_HEADER_LIST_SIZE as the uncompressed
        // field section size: name bytes + value bytes + 32 bytes overhead per
        // field.  Enforcing the same accounting protects both inbound decoded
        // headers and outbound headers constrained by the peer's SETTINGS.
        total = std.math.add(usize, total, header.name.len) catch return error.MessageTooLarge;
        total = std.math.add(usize, total, header.value.len) catch return error.MessageTooLarge;
        total = std.math.add(usize, total, 32) catch return error.MessageTooLarge;
        if (total > max_size) return error.MessageTooLarge;
    }
}

pub const HeaderBlockKind = enum {
    request,
    response,
    request_trailers,
    response_trailers,
};

pub fn validateHeaderBlock(headers: []const http2.Hpack.HeaderField, kind: HeaderBlockKind) Error!void {
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
    var status_value: ?[]const u8 = null;
    var host_value: ?[]const u8 = null;

    for (headers) |header| {
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
                        .method => method_value = header.value,
                        .scheme => scheme_value = header.value,
                        .path => path_value = header.value,
                        .authority => authority_value = header.value,
                        .protocol => protocol_value = header.value,
                    }
                },
                .response => {
                    try markResponsePseudo(header.name, &seen_status);
                    status_value = header.value;
                },
                .request_trailers, .response_trailers => return error.InvalidHeader,
            }
            continue;
        }
        saw_regular = true;

        // Most field names match no special rule. One length switch replaces
        // the chained case-insensitive comparisons on the hot path.
        switch (header.name.len) {
            2 => if (std.ascii.eqlIgnoreCase(header.name, "te")) {
                switch (kind) {
                    .request => if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, header.value, " \t"), "trailers")) return error.InvalidHeader,
                    else => return error.InvalidHeader,
                }
            },
            4 => if (std.ascii.eqlIgnoreCase(header.name, "host")) {
                if (host_value != null) return error.InvalidHeader;
                host_value = header.value;
            },
            7 => if (std.ascii.eqlIgnoreCase(header.name, "upgrade")) return error.InvalidHeader,
            10 => switch (header.name[0] | 0x20) {
                'c' => if (std.ascii.eqlIgnoreCase(header.name, "connection")) return error.InvalidHeader,
                'e' => if (kind != .request and early_data.isHeaderName(header.name)) return error.InvalidHeader,
                'k' => if (std.ascii.eqlIgnoreCase(header.name, "keep-alive")) return error.InvalidHeader,
                else => {},
            },
            16 => if (std.ascii.eqlIgnoreCase(header.name, "proxy-connection")) return error.InvalidHeader,
            17 => if (std.ascii.eqlIgnoreCase(header.name, "transfer-encoding")) return error.InvalidHeader,
            else => {},
        }

        if (kind == .request_trailers or kind == .response_trailers) {
            if (forbiddenTrailerFieldName(header.name)) return error.InvalidHeader;
        }
    }

    switch (kind) {
        .request => {
            if (!seen_method) return error.MissingPseudoHeader;
            const method_present = method_value orelse return error.MissingPseudoHeader;
            try validateHttpToken(method_present);
            if (scheme_value) |scheme| try validateUriScheme(scheme);
            if (path_value) |path| try validateUriPath(method_present, path);
            if (authority_value) |authority| try validateRequestAuthority(authority);
            if (host_value) |host| try validateRequestAuthority(host);
            if (authority_value) |authority| {
                if (host_value) |host| {
                    // RFC 9113 allows translating HTTP/1 Host into HTTP/2, but
                    // an HTTP/2 block that carries both names must not describe
                    // two different authorities.  Hyper/h2 builds a single URI
                    // authority; reject disagreement before forwarding can pick
                    // a different origin than application code observes.
                    if (!authority_semantics.equivalent(scheme_value orelse "", authority, host)) return error.InvalidHeader;
                }
            }
            if (protocol_value) |protocol| {
                try validateHttpToken(protocol);
                const method = method_value orelse return error.MissingPseudoHeader;
                if (!methodIsConnect(method)) return error.InvalidHeader;
                if (!seen_scheme or !seen_path) return error.MissingPseudoHeader;
                if (!seen_authority and host_value == null) return error.MissingPseudoHeader;
            } else if (method_value) |method| {
                if (methodIsConnect(method)) {
                    if (!seen_authority) return error.MissingPseudoHeader;
                    if (seen_scheme or seen_path) return error.InvalidHeader;
                    try validateConnectAuthority(authority_value.?);
                } else if (!seen_scheme or !seen_path) return error.MissingPseudoHeader;
            }
        },
        .response => {
            if (!seen_status) return error.MissingPseudoHeader;
            const status = status_value orelse return error.MissingPseudoHeader;
            if (status.len != 3) return error.InvalidStatus;
            for (status) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidStatus;
            const parsed_status = std.fmt.parseInt(u16, status, 10) catch return error.InvalidStatus;
            if (parsed_status < 100) return error.InvalidStatus;
            if (parsed_status == 101) return error.InvalidStatus;
        },
        .request_trailers, .response_trailers => {},
    }
}

const validateHeaderName = @import("../../../http/field_name.zig").validate;

const validateHeaderValue = @import("../../../http/field_value.zig").validate;

fn validateHttpToken(value: []const u8) Error!void {
    if (!http_method.isToken(value)) return error.InvalidHeader;
}

pub fn methodIsHead(method: []const u8) bool {
    return std.mem.eql(u8, method, "HEAD");
}

pub fn methodIsConnect(method: []const u8) bool {
    return std.mem.eql(u8, method, "CONNECT");
}

fn methodHasDefinedPayloadSemantics(method: []const u8) bool {
    return !std.mem.eql(u8, method, "GET") and
        !methodIsHead(method) and
        !std.mem.eql(u8, method, "DELETE") and
        !methodIsConnect(method);
}

fn methodIsOptions(method: []const u8) bool {
    return std.mem.eql(u8, method, "OPTIONS");
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
        if (!methodIsOptions(method)) return error.InvalidHeader;
        return;
    }
    if (path[0] != '/') return error.InvalidHeader;
    var saw_fragment = false;
    for (path) |byte| {
        if (byte <= 0x20 or byte == 0x7f) return error.InvalidHeader;
        if (byte == '\\') return error.InvalidHeader;
        if (byte == '#') saw_fragment = true;
    }
    // URI fragments identify client-side secondary resources and are not sent
    // in request-targets.  Reject instead of accepting/truncating so origin
    // servers and intermediaries do not disagree on cache keys.
    if (saw_fragment) return error.InvalidHeader;
}

fn validateRequestAuthority(authority: []const u8) Error!void {
    _ = authority_semantics.parse(authority) catch return error.InvalidHeader;
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
    // Pseudo-header names are fixed; one length switch replaces the chained
    // comparisons for every request block.
    switch (name.len) {
        5 => if (std.mem.eql(u8, name, ":path")) {
            try markOnce(seen_path);
            return .path;
        },
        7 => {
            if (std.mem.eql(u8, name, ":method")) {
                try markOnce(seen_method);
                return .method;
            }
            if (std.mem.eql(u8, name, ":scheme")) {
                try markOnce(seen_scheme);
                return .scheme;
            }
        },
        9 => if (std.mem.eql(u8, name, ":protocol")) {
            try markOnce(seen_protocol);
            return .protocol;
        },
        10 => if (std.mem.eql(u8, name, ":authority")) {
            try markOnce(seen_authority);
            return .authority;
        },
        else => {},
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

fn validateConnectAuthority(authority: []const u8) Error!void {
    authority_semantics.validateConnect(authority) catch return error.InvalidHeader;
}

const connectionSpecificHeaderName =
    connection_headers.connectionSpecificHeaderName;

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

pub fn responseForbidsBody(status: u16, request_method: []const u8, extended_connect: bool) bool {
    if ((status >= 100 and status < 200) or status == 204 or status == 304) return true;
    if (methodIsHead(request_method)) return true;
    if (!extended_connect and methodIsConnect(request_method) and status >= 200 and status < 300) return true;
    return false;
}

pub fn responseSemanticsFromMethod(method: []const u8, extended_connect: bool) ResponseBodySemantics {
    return .{
        .head = methodIsHead(method),
        .traditional_connect = methodIsConnect(method) and !extended_connect,
        .extended_connect = methodIsConnect(method) and extended_connect,
    };
}

pub fn responseWriteSuppressesBodySemantics(status: u16, semantics: ResponseBodySemantics) bool {
    if ((status >= 100 and status < 200) or status == 204 or status == 304) return true;
    if (semantics.head) return true;
    if (semantics.traditional_connect and status >= 200 and status < 300) return true;
    return false;
}

pub fn validateResponseBodyForStatus(
    status: u16,
    headers: []const http2.Hpack.HeaderField,
    body: []const u8,
    trailers: []const http2.Hpack.HeaderField,
) Error!void {
    try validateResponseBodyForStatusWithLength(
        status,
        try contentLength(headers),
        body,
        trailers,
    );
}

pub fn validateResponseBodyForStatusWithLength(
    status: u16,
    declared_content_length: ?usize,
    body: []const u8,
    trailers: []const http2.Hpack.HeaderField,
) Error!void {
    if (!((status >= 100 and status < 200) or status == 204 or status == 304)) return;
    if (body.len != 0 or trailers.len != 0) return error.InvalidContentLength;
    // As in HTTP/1, 304 may describe the selected representation length, but
    // 1xx and 204 responses terminate at the HEADERS block and must not carry a
    // Content-Length that could be mistaken for DATA on this stream.
    if (status != 304 and declared_content_length != null) return error.InvalidContentLength;
}

pub fn validateOutgoingResponseBodyForStatus(
    status: u16,
    headers: []const http2.Hpack.HeaderField,
    body: []const u8,
    trailers: []const http2.Hpack.HeaderField,
) Error!void {
    try validateOutgoingResponseBodyForStatusWithLength(
        status,
        try contentLength(headers),
        body,
        trailers,
    );
}

pub fn validateOutgoingResponseBodyForStatusWithLength(
    status: u16,
    declared_content_length: ?usize,
    body: []const u8,
    trailers: []const http2.Hpack.HeaderField,
) Error!void {
    try validateResponseBodyForStatusWithLength(
        status,
        declared_content_length,
        body,
        trailers,
    );
    // RFC 9110 Section 15.3.6 forbids response content for 205. Keep this
    // separate from `responseForbidsBody`: HTTP/2 still uses END_STREAM to
    // delimit the response and may carry a trailer section after zero DATA.
    if (status != 205) return;
    if (body.len != 0) return error.InvalidContentLength;
    if (declared_content_length) |length| {
        if (length != 0) return error.InvalidContentLength;
    }
}

pub fn validateResponseBodyForRequestSemantics(
    status: u16,
    semantics: ResponseBodySemantics,
    headers: []const http2.Hpack.HeaderField,
    body: []const u8,
    trailers: []const http2.Hpack.HeaderField,
) Error!void {
    try validateResponseBodyForRequestSemanticsWithLength(
        status,
        semantics,
        try contentLength(headers),
        body,
        trailers,
    );
}

pub fn validateResponseBodyForRequestSemanticsWithLength(
    status: u16,
    semantics: ResponseBodySemantics,
    declared_content_length: ?usize,
    body: []const u8,
    trailers: []const http2.Hpack.HeaderField,
) Error!void {
    if (semantics.head) {
        if (trailers.len != 0) return error.InvalidContentLength;
        if (declared_content_length) |len| {
            if (body.len != 0 and len != body.len) return error.InvalidContentLength;
        }
        return;
    }
    if (semantics.traditional_connect and status >= 200 and status < 300) {
        // Successful traditional CONNECT switches the stream into tunnel mode:
        // HTTP response DATA/trailers would be interpreted as tunnel bytes by
        // the peer. Reject them at the server writer boundary rather than
        // silently framing an ambiguous response.
        if (body.len != 0 or trailers.len != 0) return error.InvalidContentLength;
        if ((declared_content_length orelse 0) != 0) return error.InvalidContentLength;
    }
}

pub fn validateDeclaredResponseLength(
    status: u16,
    semantics: ResponseBodySemantics,
    headers: []const http2.Hpack.HeaderField,
    body_len: usize,
) Error!void {
    try validateDeclaredResponseLengthValue(
        status,
        semantics,
        try contentLength(headers),
        body_len,
    );
}

pub fn validateDeclaredResponseLengthValue(
    status: u16,
    semantics: ResponseBodySemantics,
    declared_content_length: ?usize,
    body_len: usize,
) Error!void {
    if ((status >= 100 and status < 200) or status == 204) return;
    if (semantics.traditional_connect and status >= 200 and status < 300) return;
    if (declared_content_length) |len| {
        // 304 and HEAD responses may describe the selected representation, so
        // only require equality when an actual DATA body is sent.  For normal
        // responses, writing a declared length that differs from DATA bytes
        // leaves peers waiting or causes them to reject the stream.
        if (body_len != 0 and len != body_len) return error.InvalidContentLength;
        if (body_len == 0 and status != 304 and !semantics.head and len != 0) return error.InvalidContentLength;
    }
}

pub fn responseShouldDefaultContentLength(
    status: u16,
    semantics: ResponseBodySemantics,
    headers: []const http2.Hpack.HeaderField,
    body_len: usize,
) bool {
    return responseShouldDefaultContentLengthValue(
        status,
        semantics,
        contentLength(headers) catch return false,
        body_len,
    );
}

pub fn responseShouldDefaultContentLengthValue(
    status: u16,
    semantics: ResponseBodySemantics,
    declared_content_length: ?usize,
    body_len: usize,
) bool {
    if (body_len == 0) return false;
    if (responseWriteSuppressesBodySemantics(status, semantics)) return false;
    return declared_content_length == null;
}

pub fn informationalResponseToSkip(status: u16) bool {
    return statusIsInformational(status) and status != 101;
}

pub fn statusIsInformational(status: u16) bool {
    return status >= 100 and status < 200;
}

pub const RequestHeaderLookup = struct {
    method: ?[]const u8 = null,
    path: ?[]const u8 = null,
    scheme: ?[]const u8 = null,
    authority: ?[]const u8 = null,
    host: ?[]const u8 = null,
    protocol: ?[]const u8 = null,
    priority: http2.ExtensiblePriority = .{},
    content_length: ?usize = null,
    /// True when an `expect` field requests `100-continue`. The server sends
    /// the interim head before reading request DATA.
    expects_continue: bool = false,

    pub fn requestAuthority(self: RequestHeaderLookup) ?[]const u8 {
        return self.authority orelse self.host;
    }
};

pub fn requestHeaderLookup(headers: []const http2.Hpack.HeaderField) Error!RequestHeaderLookup {
    var lookup: RequestHeaderLookup = .{};
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, ":method")) {
            if (lookup.method == null) lookup.method = header.value;
        } else if (std.ascii.eqlIgnoreCase(header.name, ":path")) {
            if (lookup.path == null) lookup.path = header.value;
        } else if (std.ascii.eqlIgnoreCase(header.name, ":scheme")) {
            if (lookup.scheme == null) lookup.scheme = header.value;
        } else if (std.ascii.eqlIgnoreCase(header.name, ":authority")) {
            if (lookup.authority == null) lookup.authority = header.value;
        } else if (std.ascii.eqlIgnoreCase(header.name, "host")) {
            if (lookup.host == null) lookup.host = header.value;
        } else if (std.ascii.eqlIgnoreCase(header.name, ":protocol")) {
            if (lookup.protocol == null) lookup.protocol = header.value;
        } else if (std.ascii.eqlIgnoreCase(header.name, "content-length")) {
            try parseContentLengthHeaderValue(header.value, &lookup.content_length);
        } else if (std.ascii.eqlIgnoreCase(header.name, "expect")) {
            if (expectHeaderRequestsContinue(header.value)) {
                lookup.expects_continue = true;
            }
        }
    }
    lookup.priority = http2.ExtensiblePriority.parseFields(headers);
    return lookup;
}

/// Parse the RFC 9110 `Expect` field as a comma-separated case-insensitive
/// list. Unknown expectations are ignored; only `100-continue` changes server
/// behavior.
pub fn expectHeaderRequestsContinue(value: []const u8) bool {
    var rest = value;
    while (rest.len != 0) {
        const comma = std.mem.indexOfScalar(u8, rest, ',') orelse rest.len;
        const token = std.mem.trim(u8, rest[0..comma], " \t");
        if (std.ascii.eqlIgnoreCase(token, "100-continue")) return true;
        rest = if (comma == rest.len) "" else rest[comma + 1 ..];
    }
    return false;
}

pub fn findHeader(headers: []const http2.Hpack.HeaderField, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}
