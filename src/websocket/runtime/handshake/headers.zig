const std = @import("std");
const websocket = @import("../../mod.zig");
const http1 = @import("../../../http1/mod.zig");
const http2 = @import("../../../http2/mod.zig");
const wire = @import("../../../internal/wire.zig");
const storage = @import("storage.zig");

pub const protocol_value_stack_capacity: usize = 128;
pub const protocol_token_stack_capacity: usize = 16;

pub const PreparedProtocolValue = struct {
    value: []const u8,
    allocated: ?[]u8 = null,

    pub fn deinit(
        self: *PreparedProtocolValue,
        allocator: std.mem.Allocator,
    ) void {
        if (self.allocated) |bytes| allocator.free(bytes);
        self.* = undefined;
    }
};

/// Validate and join the client-preferred subprotocol list as `1#token`.
/// Common short offers borrow caller-owned stack storage; only larger values
/// allocate, and sizing completes before either destination is mutated.
pub fn prepareProtocolValue(
    allocator: std.mem.Allocator,
    protocols: []const []const u8,
    stack: []u8,
) !PreparedProtocolValue {
    try validateOfferedProtocols(protocols);
    var len: usize = 0;
    for (protocols, 0..) |protocol, index| {
        len = std.math.add(usize, len, protocol.len) catch
            return error.PayloadTooLarge;
        if (index != 0) {
            len = std.math.add(usize, len, 2) catch
                return error.PayloadTooLarge;
        }
    }
    const value = if (len <= stack.len) stack[0..len] else try allocator.alloc(u8, len);
    var offset: usize = 0;
    for (protocols, 0..) |protocol, index| {
        if (index != 0) {
            @memcpy(value[offset..][0..2], ", ");
            offset += 2;
        }
        @memcpy(value[offset..][0..protocol.len], protocol);
        offset += protocol.len;
    }
    return .{
        .value = value,
        .allocated = if (value.ptr == stack.ptr) null else value,
    };
}

/// Validate an HTTP/1.1 101 response and own the selected subprotocol.
pub fn validateHttp1Server(
    allocator: std.mem.Allocator,
    response: http1.Response,
    client_key: []const u8,
    offered_protocols: []const []const u8,
) !?[]u8 {
    try validateOfferedProtocols(offered_protocols);
    if (response.version != .http_1_1 or response.status != 101) {
        return error.InvalidHandshake;
    }
    try websocket.validateHttp1UpgradeHeaders(response.headers);
    if ((try http1.contentLength(response.headers)) != null) {
        return error.InvalidHandshake;
    }
    for (response.headers) |header| {
        if (header.eqlName("transfer-encoding") or
            header.eqlName("trailer"))
        {
            return error.InvalidHandshake;
        }
    }
    const accept = try requiredHttp1(
        response.headers,
        "sec-websocket-accept",
    );
    const expected = websocket.acceptKey(client_key);
    if (!std.mem.eql(u8, accept, &expected)) return error.InvalidHandshake;
    _ = try websocket.ExtensionNegotiation.validateResponseWithPolicy(
        try optionalHttp1(
            response.headers,
            "sec-websocket-extensions",
        ),
        .{
            .enable_permessage_deflate = true,
            .allow_context_takeover = true,
        },
    );
    if (try optionalHttp1(
        response.headers,
        "sec-websocket-protocol",
    )) |selected| {
        const protocol = wire.trimOws(selected);
        if (!websocket.validSubprotocolToken(protocol)) {
            return error.InvalidSubprotocol;
        }
        for (offered_protocols) |offered| {
            if (std.mem.eql(u8, protocol, offered)) {
                return try allocator.dupe(u8, protocol);
            }
        }
        return error.InvalidSubprotocol;
    }
    if (offered_protocols.len != 0) return error.InvalidSubprotocol;
    return null;
}

pub fn requiredHttp1(
    headers: []const http1.Header,
    name: []const u8,
) ![]const u8 {
    return (try optionalHttp1(headers, name)) orelse error.MissingHeader;
}

pub fn optionalHttp1(
    headers: []const http1.Header,
    name: []const u8,
) !?[]const u8 {
    var found: ?[]const u8 = null;
    for (headers) |header| {
        if (!header.eqlName(name)) continue;
        if (found != null) return error.InvalidHandshake;
        found = header.value;
    }
    return found;
}

pub fn validateH2Server(
    allocator: std.mem.Allocator,
    headers: []const http2.Hpack.HeaderField,
    offered_protocols: []const []const u8,
) !?[]u8 {
    try validateOfferedProtocols(offered_protocols);
    try rejectH2Legacy(headers);
    if (try optionalH2(headers, "sec-websocket-version")) |_| {
        return error.InvalidHandshake;
    }
    if (try optionalH2(headers, "sec-websocket-protocol")) |selected| {
        const protocol = wire.trimOws(selected);
        if (!websocket.validSubprotocolToken(protocol)) {
            return error.InvalidSubprotocol;
        }
        for (offered_protocols) |offered| {
            if (std.mem.eql(u8, protocol, offered)) {
                return try allocator.dupe(u8, protocol);
            }
        }
        return error.InvalidSubprotocol;
    }
    if (offered_protocols.len != 0) return error.InvalidSubprotocol;
    return null;
}

pub fn requiredH2(
    headers: []const http2.Hpack.HeaderField,
    name: []const u8,
) ![]const u8 {
    return (try optionalH2(headers, name)) orelse error.MissingHeader;
}

pub fn optionalH2(
    headers: []const http2.Hpack.HeaderField,
    name: []const u8,
) !?[]const u8 {
    var found: ?[]const u8 = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, name)) continue;
        if (found != null) return error.InvalidHandshake;
        found = header.value;
    }
    return found;
}

pub fn validateHttp1ClientExtra(
    headers: []const http1.Header,
) !void {
    for (headers) |header| {
        try http1.validateHeader(header);
        if (http1ClientOwned(header.name) or http1Framing(header.name)) {
            return error.InvalidHandshake;
        }
    }
}

pub fn validateHttp1RejectionExtra(
    headers: []const http1.Header,
) !void {
    for (headers) |header| {
        try http1.validateHeader(header);
        if (header.eqlName("connection") or
            header.eqlName("content-length") or
            header.eqlName("transfer-encoding") or
            header.eqlName("trailer") or
            header.eqlName("upgrade") or
            header.eqlName("sec-websocket-accept") or
            header.eqlName("sec-websocket-protocol") or
            header.eqlName("sec-websocket-extensions") or
            http1Framing(header.name))
        {
            return error.InvalidHandshake;
        }
    }
}

pub fn validateHttp1AcceptExtra(
    headers: []const http1.Header,
) !void {
    for (headers) |header| {
        try http1.validateHeader(header);
        if (header.eqlName("upgrade") or
            header.eqlName("connection") or
            header.eqlName("sec-websocket-accept") or
            header.eqlName("sec-websocket-protocol") or
            header.eqlName("sec-websocket-extensions") or
            http1Framing(header.name))
        {
            return error.InvalidHandshake;
        }
    }
}

pub fn validateH2ClientExtra(
    headers: []const http2.Hpack.HeaderField,
) !void {
    for (headers) |header| {
        if (h2ClientOwned(header.name) or h2Legacy(header.name)) {
            return error.InvalidHandshake;
        }
    }
}

pub fn validateH2ServerExtra(
    headers: []const http2.Hpack.HeaderField,
) !void {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(
            header.name,
            "sec-websocket-protocol",
        ) or std.ascii.eqlIgnoreCase(
            header.name,
            "sec-websocket-extensions",
        ) or std.ascii.eqlIgnoreCase(
            header.name,
            "sec-websocket-version",
        ) or h2Legacy(header.name)) return error.InvalidHandshake;
    }
}

/// Rejected RFC 8441 requests use ordinary HTTP/2 response semantics. Keep
/// WebSocket negotiation and body framing under the adapter's control so the
/// declared length always matches the DATA emitted by `rejectWithBody`.
pub fn validateH2RejectionExtra(
    headers: []const http2.Hpack.HeaderField,
) !void {
    try validateH2ServerExtra(headers);
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "content-length")) {
            return error.InvalidHandshake;
        }
    }
}

pub fn rejectH2Legacy(
    headers: []const http2.Hpack.HeaderField,
) !void {
    for (headers) |header| {
        if (h2Legacy(header.name)) return error.InvalidHandshake;
    }
}

pub fn acceptH2Extensions(
    allocator: std.mem.Allocator,
    headers: []const http2.Hpack.HeaderField,
    policy: websocket.ExtensionNegotiation.Policy,
) !?[]u8 {
    return websocket.ExtensionNegotiation.acceptClientHeadersWithPolicy(
        allocator,
        headers,
        policy,
    );
}

pub fn selectHttp1Subprotocol(
    allocator: std.mem.Allocator,
    headers: []const http1.Header,
    supported: []const []const u8,
) !?[]u8 {
    return selectSubprotocol(allocator, headers, supported);
}

pub fn selectH2Subprotocol(
    allocator: std.mem.Allocator,
    headers: []const http2.Hpack.HeaderField,
    supported: []const []const u8,
) !?[]u8 {
    return selectSubprotocol(allocator, headers, supported);
}

/// Select the first client-preferred token supported by the server while
/// rejecting duplicates across split field lines. HTTP/1, HTTP/2, and HTTP/3
/// header field types all expose `name` and `value`, so one implementation
/// keeps their grammar and allocation policy identical.
pub fn selectSubprotocol(
    allocator: std.mem.Allocator,
    headers: anytype,
    supported: []const []const u8,
) !?[]u8 {
    try validateSupportedSubprotocols(supported);
    var saw_header = false;
    var token_count: usize = 0;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(
            header.name,
            "sec-websocket-protocol",
        )) continue;
        saw_header = true;
        var requested = std.mem.splitScalar(u8, header.value, ',');
        while (requested.next()) |raw| {
            const candidate = wire.trimOws(raw);
            if (candidate.len == 0) continue;
            if (!websocket.validSubprotocolToken(candidate)) {
                return error.InvalidSubprotocol;
            }
            token_count = std.math.add(usize, token_count, 1) catch
                return error.PayloadTooLarge;
        }
    }
    if (saw_header and token_count == 0) return error.InvalidSubprotocol;
    var token_stack: [protocol_token_stack_capacity][]const u8 = undefined;
    const seen = try storage.acquire(
        []const u8,
        allocator,
        &token_stack,
        token_count,
    );
    defer storage.release([]const u8, allocator, &token_stack, seen);
    var selected: ?[]const u8 = null;
    var seen_count: usize = 0;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(
            header.name,
            "sec-websocket-protocol",
        )) continue;
        var requested = std.mem.splitScalar(u8, header.value, ',');
        while (requested.next()) |raw| {
            const candidate = wire.trimOws(raw);
            if (candidate.len == 0) continue;
            if (!websocket.validSubprotocolToken(candidate)) {
                return error.InvalidSubprotocol;
            }
            for (seen[0..seen_count]) |previous| {
                if (std.mem.eql(u8, previous, candidate)) {
                    return error.InvalidSubprotocol;
                }
            }
            seen[seen_count] = candidate;
            seen_count += 1;
            if (selected != null) continue;
            for (supported) |protocol| {
                if (std.mem.eql(u8, candidate, protocol)) {
                    selected = protocol;
                    break;
                }
            }
        }
    }
    if (selected) |protocol| return try allocator.dupe(u8, protocol);
    return null;
}

fn http1ClientOwned(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "host") or
        std.ascii.eqlIgnoreCase(name, "upgrade") or
        std.ascii.eqlIgnoreCase(name, "connection") or
        std.ascii.eqlIgnoreCase(name, "sec-websocket-key") or
        std.ascii.eqlIgnoreCase(name, "sec-websocket-accept") or
        std.ascii.eqlIgnoreCase(name, "sec-websocket-version") or
        std.ascii.eqlIgnoreCase(name, "sec-websocket-protocol") or
        std.ascii.eqlIgnoreCase(name, "sec-websocket-extensions") or
        std.ascii.eqlIgnoreCase(name, "origin");
}

fn http1Framing(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "trailer");
}

fn h2ClientOwned(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "sec-websocket-version") or
        std.ascii.eqlIgnoreCase(name, "sec-websocket-protocol") or
        std.ascii.eqlIgnoreCase(name, "sec-websocket-extensions");
}

fn h2Legacy(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "sec-websocket-key") or
        std.ascii.eqlIgnoreCase(name, "sec-websocket-accept");
}

fn validateSupportedSubprotocols(supported: []const []const u8) !void {
    for (supported) |protocol| {
        if (!websocket.validSubprotocolToken(protocol)) {
            return error.InvalidSubprotocol;
        }
    }
}

/// RFC 6455 requires every subprotocol in a client's preference list to be
/// unique. Subprotocol identifiers are case-sensitive, so differently cased
/// tokens remain distinct.
pub fn validateOfferedProtocols(protocols: []const []const u8) !void {
    for (protocols, 0..) |protocol, index| {
        if (!websocket.validSubprotocolToken(protocol)) {
            return error.InvalidSubprotocol;
        }
        for (protocols[0..index]) |previous| {
            if (std.mem.eql(u8, previous, protocol)) {
                return error.InvalidSubprotocol;
            }
        }
    }
}

test "WebSocket subprotocol offer is stack-first and exact on overflow" {
    const allocator = std.testing.allocator;
    var stack: [protocol_value_stack_capacity]u8 = undefined;
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    var common = try prepareProtocolValue(
        failing.allocator(),
        &.{ "chat.v1", "chat.v2" },
        &stack,
    );
    defer common.deinit(failing.allocator());
    try std.testing.expectEqualStrings("chat.v1, chat.v2", common.value);
    try std.testing.expect(common.allocated == null);
    try std.testing.expect(!failing.has_induced_failure);

    var duplicate_stack = [_]u8{0xa5} ** protocol_value_stack_capacity;
    try std.testing.expectError(
        error.InvalidSubprotocol,
        prepareProtocolValue(
            failing.allocator(),
            &.{ "chat.v1", "chat.v1" },
            &duplicate_stack,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{0xa5} ** protocol_value_stack_capacity),
        &duplicate_stack,
    );
    try std.testing.expect(!failing.has_induced_failure);

    var case_stack: [protocol_value_stack_capacity]u8 = undefined;
    var case_distinct = try prepareProtocolValue(
        allocator,
        &.{ "chat.v1", "Chat.v1" },
        &case_stack,
    );
    defer case_distinct.deinit(allocator);
    try std.testing.expectEqualStrings(
        "chat.v1, Chat.v1",
        case_distinct.value,
    );

    const long = "x" ** (protocol_value_stack_capacity + 1);
    try std.testing.expectError(
        error.OutOfMemory,
        prepareProtocolValue(
            failing.allocator(),
            &.{long},
            &stack,
        ),
    );

    const h1_headers = [_]http1.Header{.{
        .name = "Sec-WebSocket-Protocol",
        .value = ", chat.v2,, chat.v1,",
    }};
    const selected = try selectSubprotocol(
        allocator,
        &h1_headers,
        &.{ "chat.v1", "chat.v2" },
    );
    defer if (selected) |value| allocator.free(value);
    try std.testing.expectEqualStrings("chat.v2", selected.?);

    const empty_protocols = [_]http1.Header{.{
        .name = "Sec-WebSocket-Protocol",
        .value = ", ,",
    }};
    try std.testing.expectError(
        error.InvalidSubprotocol,
        selectSubprotocol(allocator, &empty_protocols, &.{"chat.v1"}),
    );

    const sixteen_tokens = [_]http1.Header{.{
        .name = "Sec-WebSocket-Protocol",
        .value = "a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p",
    }};
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    const no_match = try selectSubprotocol(
        no_alloc.allocator(),
        &sixteen_tokens,
        &.{},
    );
    try std.testing.expect(no_match == null);
    try std.testing.expect(!no_alloc.has_induced_failure);

    var many_tokens: [protocol_token_stack_capacity * 2 + 1]u8 = undefined;
    for (&many_tokens, 0..) |*byte, index| {
        byte.* = if ((index & 1) == 0) 'x' else ',';
    }
    const overflow_headers = [_]http1.Header{.{
        .name = "Sec-WebSocket-Protocol",
        .value = &many_tokens,
    }};
    var overflow_failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        selectSubprotocol(
            overflow_failing.allocator(),
            &overflow_headers,
            &.{},
        ),
    );
}
