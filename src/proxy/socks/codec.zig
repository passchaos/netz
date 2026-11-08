//! Bounded SOCKS4/4a and SOCKS5 server-side wire codecs.
//!
//! Every parser consumes caller-owned bytes and never allocates. Incomplete
//! input is reported separately from malformed input so streaming servers can
//! continue reading without turning a hostile peer into unbounded work.

const std = @import("std");

const net = std.Io.net;

pub const Error = error{
    Incomplete,
    Malformed,
    UnsupportedVersion,
    UnsupportedCommand,
    UnsupportedAddressType,
    UnsupportedAuthentication,
    NoAcceptableAuthentication,
    InvalidPort,
    InvalidHostName,
    NameTooLong,
    BufferTooSmall,
    TooManyMethods,
};

pub const Version = enum(u8) {
    v4 = 4,
    v5 = 5,
    _,
};

pub const Method = enum(u8) {
    none = 0x00,
    username_password = 0x02,
    no_acceptable = 0xff,
    _,
};

pub const Command = enum(u8) {
    connect = 0x01,
    bind = 0x02,
    udp_associate = 0x03,
    _,

    pub fn fromByte(value: u8) Error!Command {
        return switch (value) {
            0x01 => .connect,
            0x02 => .bind,
            0x03 => .udp_associate,
            else => error.UnsupportedCommand,
        };
    }
};

pub const Socks4Command = enum(u8) {
    connect = 0x01,
    bind = 0x02,
    _,

    pub fn fromByte(value: u8) Error!Socks4Command {
        return switch (value) {
            0x01 => .connect,
            0x02 => .bind,
            else => error.UnsupportedCommand,
        };
    }
};

/// RFC 1928 reply codes.
pub const Reply = enum(u8) {
    succeeded = 0x00,
    general_failure = 0x01,
    connection_not_allowed = 0x02,
    network_unreachable = 0x03,
    host_unreachable = 0x04,
    connection_refused = 0x05,
    ttl_expired = 0x06,
    command_not_supported = 0x07,
    address_type_not_supported = 0x08,
    _,
};

/// SOCKS4 reply codes from the original SOCKS4 specification.
pub const Socks4Reply = enum(u8) {
    granted = 90,
    rejected = 91,
    identd_unavailable = 92,
    identd_mismatch = 93,
};

pub const Domain = struct {
    host: []const u8,
    port: u16,
};

pub const Address = union(enum) {
    ip: net.IpAddress,
    domain: Domain,

    pub fn getPort(self: Address) u16 {
        return switch (self) {
            .ip => |ip| ip.getPort(),
            .domain => |domain| domain.port,
        };
    }

    pub fn eql(self: Address, other: Address) bool {
        return switch (self) {
            .ip => |ip| switch (other) {
                .ip => |other_ip| ip.eql(&other_ip),
                .domain => false,
            },
            .domain => |domain| switch (other) {
                .ip => false,
                .domain => |other_domain| domain.port ==
                    other_domain.port and
                    std.ascii.eqlIgnoreCase(domain.host, other_domain.host),
            },
        };
    }
};

pub const max_socks4_user_id_len: usize = 255;
pub const max_socks4_request_len: usize = 8 + max_socks4_user_id_len + 1 +
    net.HostName.max_len + 1;
pub const max_socks5_greeting_len: usize = 2 + 255;
pub const max_socks5_request_len: usize = 4 + 1 + 255 + 2;

pub const Greeting = struct {
    methods: []const u8,
};

pub fn parseSocks5Greeting(bytes: []const u8) Error!Greeting {
    if (bytes.len < 1) return error.Incomplete;
    if (bytes[0] != @intFromEnum(Version.v5)) {
        return error.UnsupportedVersion;
    }
    if (bytes.len < 2) return error.Incomplete;
    const method_count = bytes[1];
    if (method_count == 0) return error.Malformed;
    const end = 2 + @as(usize, method_count);
    if (bytes.len < end) return error.Incomplete;
    return .{ .methods = bytes[2..end] };
}

pub const Socks5Request = struct {
    command: Command,
    address: Address,
};

pub const ParsedSocks5Request = struct {
    request: Socks5Request,
    consumed: usize,
};

pub fn parseSocks5Request(bytes: []const u8) Error!ParsedSocks5Request {
    if (bytes.len < 4) return error.Incomplete;
    if (bytes[0] != @intFromEnum(Version.v5)) {
        return error.UnsupportedVersion;
    }
    if (bytes[2] != 0) return error.Malformed;
    const command = try Command.fromByte(bytes[1]);
    const decoded = try decodeSocks5Address(bytes, 3);
    return .{
        .request = .{
            .command = command,
            .address = decoded.address,
        },
        .consumed = decoded.end,
    };
}

pub const DecodedAddress = struct {
    address: Address,
    end: usize,
};

/// Decode the ATYP-prefixed address at `offset`. `end` points just past the
/// two-byte port and can be used as the consumed length.
pub fn decodeSocks5Address(
    bytes: []const u8,
    offset: usize,
) Error!DecodedAddress {
    if (offset >= bytes.len) return error.Incomplete;
    const address_type = bytes[offset];
    return switch (address_type) {
        0x01 => blk: {
            if (bytes.len - offset < 1 + 4 + 2) return error.Incomplete;
            const ip_bytes = bytes[offset + 1 ..][0..4].*;
            const port = std.mem.readInt(
                u16,
                bytes[offset + 5 ..][0..2],
                .big,
            );
            break :blk .{
                .address = .{ .ip = .{ .ip4 = .{
                    .bytes = ip_bytes,
                    .port = port,
                } } },
                .end = offset + 1 + 4 + 2,
            };
        },
        0x04 => blk: {
            if (bytes.len - offset < 1 + 16 + 2) return error.Incomplete;
            const ip_bytes = bytes[offset + 1 ..][0..16].*;
            const port = std.mem.readInt(
                u16,
                bytes[offset + 17 ..][0..2],
                .big,
            );
            break :blk .{
                .address = .{ .ip = .{ .ip6 = .{
                    .bytes = ip_bytes,
                    .port = port,
                    .flow = 0,
                    .interface = .none,
                } } },
                .end = offset + 1 + 16 + 2,
            };
        },
        0x03 => blk: {
            if (bytes.len - offset < 2) return error.Incomplete;
            const host_len = bytes[offset + 1];
            if (host_len == 0) return error.InvalidHostName;
            const end = offset + 2 + @as(usize, host_len) + 2;
            if (bytes.len < end) return error.Incomplete;
            const host = bytes[offset + 2 ..][0..host_len];
            try validateHost(host);
            const port = std.mem.readInt(
                u16,
                bytes[end - 2 ..][0..2],
                .big,
            );
            break :blk .{
                .address = .{ .domain = .{
                    .host = host,
                    .port = port,
                } },
                .end = end,
            };
        },
        else => error.UnsupportedAddressType,
    };
}

/// Encode an ATYP-prefixed address including its two-byte port.
pub fn encodeSocks5Address(
    output: []u8,
    address: Address,
) Error!usize {
    switch (address) {
        .ip => |ip| switch (ip) {
            .ip4 => |value| {
                if (output.len < 1 + 4 + 2) return error.BufferTooSmall;
                output[0] = 0x01;
                @memcpy(output[1..][0..4], &value.bytes);
                std.mem.writeInt(u16, output[5..][0..2], value.port, .big);
                return 7;
            },
            .ip6 => |value| {
                if (output.len < 1 + 16 + 2) return error.BufferTooSmall;
                output[0] = 0x04;
                @memcpy(output[1..][0..16], &value.bytes);
                std.mem.writeInt(u16, output[17..][0..2], value.port, .big);
                return 19;
            },
        },
        .domain => |domain| {
            try validateHost(domain.host);
            const total = 1 + 1 + domain.host.len + 2;
            if (output.len < total) return error.BufferTooSmall;
            output[0] = 0x03;
            output[1] = @intCast(domain.host.len);
            @memcpy(output[2..][0..domain.host.len], domain.host);
            std.mem.writeInt(
                u16,
                output[2 + domain.host.len ..][0..2],
                domain.port,
                .big,
            );
            return total;
        },
    }
}

pub fn encodeSocks5Reply(
    output: []u8,
    reply: Reply,
    address: Address,
) Error!usize {
    if (output.len < 4) return error.BufferTooSmall;
    output[0] = @intFromEnum(Version.v5);
    output[1] = @intFromEnum(reply);
    output[2] = 0;
    const address_len = try encodeSocks5Address(output[3..], address);
    return 3 + address_len;
}

pub fn encodeSocks5Method(
    output: []u8,
    method: Method,
) Error!void {
    if (output.len < 2) return error.BufferTooSmall;
    output[0] = @intFromEnum(Version.v5);
    output[1] = @intFromEnum(method);
}

pub const Socks4Header = struct {
    command: Socks4Command,
    port: u16,
    /// Header address. For SOCKS4a this is the marker address (0.0.0.x).
    ip: net.IpAddress,
    is_4a: bool,
};

pub fn parseSocks4Header(bytes: [8]u8) Error!Socks4Header {
    if (bytes[0] != @intFromEnum(Version.v4)) {
        return error.UnsupportedVersion;
    }
    const command = try Socks4Command.fromByte(bytes[1]);
    const port = std.mem.readInt(u16, bytes[2..4], .big);
    const ip_bytes = bytes[4..8].*;
    const is_4a = ip_bytes[0] == 0 and ip_bytes[1] == 0 and
        ip_bytes[2] == 0 and ip_bytes[3] != 0;
    return .{
        .command = command,
        .port = port,
        .ip = .{ .ip4 = .{ .bytes = ip_bytes, .port = port } },
        .is_4a = is_4a,
    };
}

pub const Socks4Request = struct {
    command: Socks4Command,
    address: Address,
    user_id: []const u8,
    is_4a: bool,
};

pub fn buildSocks4Request(
    header: Socks4Header,
    user_id: []const u8,
    domain: ?[]const u8,
) Error!Socks4Request {
    if (user_id.len > max_socks4_user_id_len) return error.NameTooLong;
    const address: Address = if (header.is_4a) blk: {
        const host = domain orelse return error.InvalidHostName;
        try validateHost(host);
        break :blk .{ .domain = .{
            .host = host,
            .port = header.port,
        } };
    } else .{ .ip = header.ip };
    return .{
        .command = header.command,
        .address = address,
        .user_id = user_id,
        .is_4a = header.is_4a,
    };
}

pub const ParsedSocks4Request = struct {
    request: Socks4Request,
    consumed: usize,
};

pub fn parseSocks4Request(bytes: []const u8) Error!ParsedSocks4Request {
    if (bytes.len < 8) return error.Incomplete;
    const header = try parseSocks4Header(bytes[0..8].*);
    const user_end = findNul(bytes, 8) orelse return error.Incomplete;
    const user_id = bytes[8..user_end];
    if (user_id.len > max_socks4_user_id_len) return error.NameTooLong;
    if (!header.is_4a) {
        return .{
            .request = try buildSocks4Request(header, user_id, null),
            .consumed = user_end + 1,
        };
    }
    const domain_start = user_end + 1;
    const domain_end = findNul(bytes, domain_start) orelse
        return error.Incomplete;
    const domain = bytes[domain_start..domain_end];
    return .{
        .request = try buildSocks4Request(header, user_id, domain),
        .consumed = domain_end + 1,
    };
}

pub fn encodeSocks4Reply(
    output: *[8]u8,
    reply: Socks4Reply,
    address: Address,
) void {
    output[0] = 0;
    output[1] = @intFromEnum(reply);
    std.mem.writeInt(u16, output[2..4], address.getPort(), .big);
    switch (address) {
        .ip => |ip| switch (ip) {
            .ip4 => |value| @memcpy(output[4..8], &value.bytes),
            // SOCKS4 has no IPv6 representation; use the unspecified address.
            .ip6 => @memset(output[4..8], 0),
        },
        // SOCKS4 replies carry a binary IPv4 address, never a hostname.
        .domain => @memset(output[4..8], 0),
    }
}

fn findNul(bytes: []const u8, start: usize) ?usize {
    var index = start;
    while (index < bytes.len) : (index += 1) {
        if (bytes[index] == 0) return index;
    }
    return null;
}

fn validateHost(host: []const u8) Error!void {
    if (host.len == 0 or host.len > net.HostName.max_len) {
        return error.InvalidHostName;
    }
    _ = net.HostName.init(host) catch return error.InvalidHostName;
}

test "SOCKS5 greeting parsing is bounded" {
    try std.testing.expectError(
        error.Incomplete,
        parseSocks5Greeting(&.{5}),
    );
    try std.testing.expectError(
        error.UnsupportedVersion,
        parseSocks5Greeting(&.{4}),
    );
    try std.testing.expectError(
        error.Malformed,
        parseSocks5Greeting(&.{ 5, 0 }),
    );
    try std.testing.expectError(
        error.Incomplete,
        parseSocks5Greeting(&.{ 5, 2, 0 }),
    );
    const greeting = try parseSocks5Greeting(&.{ 5, 2, 0, 2 });
    try std.testing.expectEqualSlices(u8, &.{ 0, 2 }, greeting.methods);
}

test "SOCKS5 request parsing accepts every address family" {
    const cases = [_]struct {
        bytes: []const u8,
        command: Command,
        port: u16,
    }{
        .{
            .bytes = &.{ 5, 1, 0, 1, 192, 0, 2, 1, 0, 80 },
            .command = .connect,
            .port = 80,
        },
        .{
            .bytes = &.{
                5,    2,    0,    4,
                0x20, 0x01, 0x0d, 0xb8,
                0,    0,    0,    0,
                0,    0,    0,    0,
                0,    0,    0,    1,
                1,    187,
            },
            .command = .bind,
            .port = 443,
        },
        .{
            .bytes = &.{ 5, 3, 0, 3, 14, 'o', 'r', 'i', 'g', 'i', 'n', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 53 },
            .command = .udp_associate,
            .port = 53,
        },
    };
    for (cases) |case| {
        const parsed = try parseSocks5Request(case.bytes);
        try std.testing.expectEqual(case.command, parsed.request.command);
        try std.testing.expectEqual(case.port, parsed.request.address.getPort());
        try std.testing.expectEqual(case.bytes.len, parsed.consumed);
    }
}

test "SOCKS5 request parsing rejects malformed and truncated input" {
    try std.testing.expectError(
        error.Incomplete,
        parseSocks5Request(&.{ 5, 1 }),
    );
    try std.testing.expectError(
        error.UnsupportedVersion,
        parseSocks5Request(&.{ 4, 1, 0, 1, 127, 0, 0, 1, 0, 80 }),
    );
    try std.testing.expectError(
        error.Malformed,
        parseSocks5Request(&.{ 5, 1, 1, 1, 127, 0, 0, 1, 0, 80 }),
    );
    try std.testing.expectError(
        error.UnsupportedCommand,
        parseSocks5Request(&.{ 5, 9, 0, 1, 127, 0, 0, 1, 0, 80 }),
    );
    try std.testing.expectError(
        error.UnsupportedAddressType,
        parseSocks5Request(&.{ 5, 1, 0, 9, 127, 0, 0, 1, 0, 80 }),
    );
    try std.testing.expectError(
        error.InvalidHostName,
        parseSocks5Request(&.{ 5, 1, 0, 3, 0, 0, 80 }),
    );
    try std.testing.expectError(
        error.Incomplete,
        parseSocks5Request(&.{ 5, 1, 0, 3, 5, 'a' }),
    );
}

test "SOCKS4 and SOCKS4a requests are bounded and distinguishable" {
    const plain = try parseSocks4Request(&.{
        4,   1,   0,   80,
        127, 0,   0,   1,
        'u', 's', 'e', 'r',
        0,
    });
    try std.testing.expect(!plain.request.is_4a);
    try std.testing.expectEqualStrings("user", plain.request.user_id);
    try std.testing.expectEqual(@as(u16, 80), plain.request.address.getPort());
    switch (plain.request.address) {
        .ip => |ip| try std.testing.expectEqualSlices(
            u8,
            &.{ 127, 0, 0, 1 },
            &ip.ip4.bytes,
        ),
        .domain => return error.TestExpectedEqual,
    }

    const a = try parseSocks4Request(&.{
        4,   2,   0x01, 0xbb,
        0,   0,   0,    1,
        'u', 0,   'o',  'r',
        'i', 'g', 'i',  'n',
        '.', 'e', 'x',  'a',
        'm', 'p', 'l',  'e',
        0,
    });
    try std.testing.expect(a.request.is_4a);
    switch (a.request.address) {
        .domain => |domain| try std.testing.expectEqualStrings(
            "origin.example",
            domain.host,
        ),
        .ip => return error.TestExpectedEqual,
    }

    try std.testing.expectError(
        error.Incomplete,
        parseSocks4Request(&.{ 4, 1, 0, 80, 127, 0, 0, 1 }),
    );
    try std.testing.expectError(
        error.Incomplete,
        parseSocks4Request(&.{
            4,   1, 0x01, 0xbb,
            0,   0, 0,    1,
            'u', 0, 'o',  'r',
        }),
    );
}

test "SOCKS reply encoders round trip address families" {
    const addresses = [_]Address{
        .{ .ip = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 80 } } },
        .{ .ip = .{ .ip6 = .{
            .bytes = .{
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                0,    0,    0,    0,    0, 0, 0, 1,
            },
            .port = 443,
            .flow = 0,
            .interface = .none,
        } } },
        .{ .domain = .{ .host = "origin.example", .port = 8080 } },
    };
    for (addresses) |address| {
        var storage: [64]u8 = undefined;
        const len = try encodeSocks5Reply(
            &storage,
            .succeeded,
            address,
        );
        const decoded = try decodeSocks5Address(storage[3..len], 0);
        try std.testing.expect(decoded.address.eql(address));
        try std.testing.expectEqual(len - 3, decoded.end);
    }

    var socks4_reply: [8]u8 = undefined;
    encodeSocks4Reply(
        &socks4_reply,
        .granted,
        .{ .ip = .{ .ip4 = .{
            .bytes = .{ 127, 0, 0, 1 },
            .port = 1080,
        } } },
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0, 90, 0x04, 0x38, 127, 0, 0, 1 },
        &socks4_reply,
    );
}

test "truncated valid requests never panic or succeed early" {
    const valid = [_][]const u8{
        &.{ 5, 1, 0, 1, 192, 0, 2, 1, 0, 80 },
        &.{ 5, 3, 0, 3, 14, 'o', 'r', 'i', 'g', 'i', 'n', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 53 },
        &.{ 4, 1, 0, 80, 127, 0, 0, 1, 'u', 0 },
    };
    for (valid) |request| {
        var end: usize = 1;
        while (end < request.len) : (end += 1) {
            _ = parseSocks5Request(request[0..end]) catch {};
            _ = parseSocks4Request(request[0..end]) catch {};
        }
    }
}
