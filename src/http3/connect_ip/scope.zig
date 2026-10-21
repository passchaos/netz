//! RFC 9484 request scope and default MASQUE path codec.

const std = @import("std");
const capsules = @import("capsules.zig");
const packets = @import("packet.zig");

const net = std.Io.net;

pub const Error = error{
    BufferTooShort,
    IntegerOverflow,
    InvalidScope,
};

pub const PacketError = Error || packets.Error;

/// Result of applying a CONNECT-IP request scope to one tunneled packet.
/// Indeterminate results keep DNS and fragment-reassembly ownership explicit
/// instead of silently widening the request scope.
pub const PacketDecision = enum {
    allowed,
    denied,
    requires_dns_resolution,
    requires_reassembly,
};

pub const default_path_prefix = "/.well-known/masque/ip/";

/// CONNECT-IP request scope. `target = "*"` and `ip_protocol = null` request
/// wildcard routing. A non-wildcard target is a reg-name or canonical IP
/// address, optionally followed by `/prefix-length`.
pub const Scope = struct {
    target: []const u8 = "*",
    ip_protocol: ?u8 = null,

    pub fn validate(self: Scope) error{InvalidScope}!void {
        try validateTarget(self.target);
    }

    /// Apply this scope to one complete IPv4/IPv6 packet. A reg-name target
    /// returns `requires_dns_resolution`; callers with an authoritative result
    /// use `packetDecisionWithResolvedTargets` instead.
    pub fn packetDecision(
        self: Scope,
        packet: []const u8,
    ) PacketError!PacketDecision {
        return self.packetDecisionView(try packets.parse(packet), null);
    }

    /// Apply this scope using the caller's current DNS result for a reg-name
    /// target. An empty address set authoritatively denies every destination.
    pub fn packetDecisionWithResolvedTargets(
        self: Scope,
        packet: []const u8,
        resolved_targets: []const capsules.IpAddress,
    ) PacketError!PacketDecision {
        return self.packetDecisionView(
            try packets.parse(packet),
            resolved_targets,
        );
    }

    fn packetDecisionView(
        self: Scope,
        packet: packets.View,
        resolved_targets: ?[]const capsules.IpAddress,
    ) PacketError!PacketDecision {
        try self.validate();
        const target = targetDecision(
            self.target,
            packet.destination,
            resolved_targets,
        );
        const protocol = protocolDecision(
            self.ip_protocol,
            packet.version,
            packet.ip_protocol,
        );
        if (target == .denied or protocol == .denied) return .denied;
        if (target == .requires_dns_resolution) {
            return .requires_dns_resolution;
        }
        if (protocol == .requires_reassembly) return .requires_reassembly;
        return .allowed;
    }
};

fn targetDecision(
    target: []const u8,
    destination: capsules.IpAddress,
    resolved_targets: ?[]const capsules.IpAddress,
) PacketDecision {
    if (std.mem.eql(u8, target, "*")) return .allowed;
    const slash = std.mem.indexOfScalar(u8, target, '/');
    const address_text = if (slash) |index| target[0..index] else target;
    if (std.mem.indexOfScalar(u8, address_text, ':') != null) {
        const address = net.Ip6Address.parse(address_text, 0) catch
            return .requires_dns_resolution;
        if (destination.version() != 6) return .denied;
        const prefix = if (slash) |index|
            std.fmt.parseUnsigned(u8, target[index + 1 ..], 10) catch
                return .denied
        else
            128;
        return if (prefixContains(&address.bytes, &destination.ipv6, prefix))
            .allowed
        else
            .denied;
    }
    if (net.Ip4Address.parse(address_text, 0)) |address| {
        if (destination.version() != 4) return .denied;
        const prefix = if (slash) |index|
            std.fmt.parseUnsigned(u8, target[index + 1 ..], 10) catch
                return .denied
        else
            32;
        return if (prefixContains(&address.bytes, &destination.ipv4, prefix))
            .allowed
        else
            .denied;
    } else |_| {}
    const resolved = resolved_targets orelse return .requires_dns_resolution;
    for (resolved) |address| {
        if (ipAddressEqual(address, destination)) return .allowed;
    }
    return .denied;
}

fn protocolDecision(
    required: ?u8,
    version: packets.Version,
    actual: ?u8,
) PacketDecision {
    const expected = required orelse return .allowed;
    const protocol = actual orelse return .requires_reassembly;
    if (protocol == expected or
        (version == .ipv4 and protocol == 1) or
        (version == .ipv6 and protocol == 58))
    {
        return .allowed;
    }
    return .denied;
}

fn ipAddressEqual(a: capsules.IpAddress, b: capsules.IpAddress) bool {
    if (a.version() != b.version()) return false;
    return std.mem.eql(u8, a.bytes(), b.bytes());
}

fn prefixContains(
    expected: []const u8,
    actual: []const u8,
    prefix_length: u8,
) bool {
    const full_bytes = prefix_length / 8;
    if (!std.mem.eql(u8, expected[0..full_bytes], actual[0..full_bytes])) {
        return false;
    }
    const partial_bits = prefix_length % 8;
    if (partial_bits == 0) return true;
    const shift: u3 = @intCast(8 - partial_bits);
    const mask: u8 = @as(u8, 0xff) << shift;
    return (expected[full_bytes] & mask) == (actual[full_bytes] & mask);
}

pub fn defaultPathLen(scope: Scope) Error!usize {
    try scope.validate();
    const target_len = encodedTargetLen(scope.target) catch
        return error.IntegerOverflow;
    const protocol_len: usize = if (scope.ip_protocol) |protocol|
        decimalLen(protocol)
    else
        1;
    return std.math.add(
        usize,
        default_path_prefix.len + 2 + protocol_len,
        target_len,
    ) catch return error.IntegerOverflow;
}

pub fn writeDefaultPath(out: []u8, scope: Scope) Error![]u8 {
    const needed = try defaultPathLen(scope);
    if (out.len < needed) return error.BufferTooShort;
    @memcpy(out[0..default_path_prefix.len], default_path_prefix);
    var offset = default_path_prefix.len;
    offset += writeEncodedTarget(out[offset..], scope.target);
    out[offset] = '/';
    offset += 1;
    if (scope.ip_protocol) |protocol| {
        const text = std.fmt.bufPrint(out[offset..], "{d}", .{protocol}) catch
            return error.BufferTooShort;
        offset += text.len;
    } else {
        out[offset] = '*';
        offset += 1;
    }
    out[offset] = '/';
    offset += 1;
    std.debug.assert(offset == needed);
    return out[0..offset];
}

/// Parse RFC 9484's default path. `Scope.target` borrows `target_out`.
pub fn parseDefaultPath(
    path: []const u8,
    target_out: []u8,
) Error!Scope {
    if (!std.mem.startsWith(u8, path, default_path_prefix) or
        path.len <= default_path_prefix.len + 2 or
        path[path.len - 1] != '/')
    {
        return error.InvalidScope;
    }
    const value = path[default_path_prefix.len .. path.len - 1];
    const separator = std.mem.indexOfScalar(u8, value, '/') orelse
        return error.InvalidScope;
    if (separator == 0 or separator + 1 >= value.len or
        std.mem.indexOfScalar(u8, value[separator + 1 ..], '/') != null)
    {
        return error.InvalidScope;
    }
    const target = try decodeTarget(value[0..separator], target_out);
    var protocol_storage: [3]u8 = undefined;
    const protocol_text = decodeTarget(
        value[separator + 1 ..],
        &protocol_storage,
    ) catch |err| switch (err) {
        error.BufferTooShort => return error.InvalidScope,
        else => |other| return other,
    };
    const protocol = if (std.mem.eql(u8, protocol_text, "*"))
        null
    else protocol: {
        for (protocol_text) |byte| {
            if (!std.ascii.isDigit(byte)) return error.InvalidScope;
        }
        break :protocol std.fmt.parseUnsigned(
            u8,
            protocol_text,
            10,
        ) catch return error.InvalidScope;
    };
    const scope = Scope{ .target = target, .ip_protocol = protocol };
    try scope.validate();
    return scope;
}

fn validateTarget(target: []const u8) error{InvalidScope}!void {
    if (target.len == 0 or std.mem.indexOfScalar(u8, target, '%') != null) {
        return error.InvalidScope;
    }
    if (std.mem.eql(u8, target, "*")) return;

    const slash = std.mem.indexOfScalar(u8, target, '/');
    const address_text = if (slash) |index| target[0..index] else target;
    if (slash) |index| {
        if (index == 0 or index + 1 >= target.len or
            std.mem.indexOfScalar(u8, target[index + 1 ..], '/') != null)
        {
            return error.InvalidScope;
        }
        const prefix_text = target[index + 1 ..];
        for (prefix_text) |byte| {
            if (!std.ascii.isDigit(byte)) return error.InvalidScope;
        }
        if (std.mem.indexOfScalar(u8, address_text, ':') != null) {
            const prefix = std.fmt.parseUnsigned(u8, prefix_text, 10) catch
                return error.InvalidScope;
            if (prefix > 128) return error.InvalidScope;
            const address = net.Ip6Address.parse(address_text, 0) catch
                return error.InvalidScope;
            if (!hostBitsZero(&address.bytes, prefix)) {
                return error.InvalidScope;
            }
            return;
        }
        const prefix = std.fmt.parseUnsigned(u8, prefix_text, 10) catch
            return error.InvalidScope;
        if (prefix > 32) return error.InvalidScope;
        const address = net.Ip4Address.parse(address_text, 0) catch
            return error.InvalidScope;
        if (!hostBitsZero(&address.bytes, prefix)) {
            return error.InvalidScope;
        }
        return;
    }

    if (std.mem.indexOfScalar(u8, address_text, ':') != null) {
        _ = net.Ip6Address.parse(address_text, 0) catch
            return error.InvalidScope;
        return;
    }
    if (net.Ip4Address.parse(address_text, 0)) |_| {
        return;
    } else |_| {}
    for (address_text) |byte| {
        if (!isRegNameByte(byte)) return error.InvalidScope;
    }
}

fn hostBitsZero(bytes: []const u8, prefix_length: u8) bool {
    const full_bytes = prefix_length / 8;
    const partial_bits = prefix_length % 8;
    var index: usize = full_bytes;
    if (partial_bits != 0) {
        const host_mask: u8 = (@as(u8, 1) << @intCast(8 - partial_bits)) - 1;
        if ((bytes[index] & host_mask) != 0) return false;
        index += 1;
    }
    for (bytes[index..]) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

fn decodeTarget(encoded: []const u8, out: []u8) Error![]const u8 {
    var out_len: usize = 0;
    var index: usize = 0;
    while (index < encoded.len) {
        const decoded = if (encoded[index] == '%') decoded: {
            if (index + 2 >= encoded.len) return error.InvalidScope;
            const high = hexValue(encoded[index + 1]) orelse
                return error.InvalidScope;
            const low = hexValue(encoded[index + 2]) orelse
                return error.InvalidScope;
            index += 3;
            break :decoded (high << 4) | low;
        } else decoded: {
            const byte = encoded[index];
            if (!isUnreserved(byte) and byte != '*') {
                return error.InvalidScope;
            }
            index += 1;
            break :decoded byte;
        };
        if (out_len >= out.len) return error.BufferTooShort;
        out[out_len] = decoded;
        out_len += 1;
    }
    return out[0..out_len];
}

fn encodedTargetLen(target: []const u8) error{IntegerOverflow}!usize {
    if (std.mem.eql(u8, target, "*")) return 1;
    var result: usize = 0;
    for (target) |byte| {
        result = std.math.add(
            usize,
            result,
            if (isUnreserved(byte)) 1 else 3,
        ) catch return error.IntegerOverflow;
    }
    return result;
}

fn writeEncodedTarget(out: []u8, target: []const u8) usize {
    if (std.mem.eql(u8, target, "*")) {
        out[0] = '*';
        return 1;
    }
    const hex = "0123456789ABCDEF";
    var offset: usize = 0;
    for (target) |byte| {
        if (isUnreserved(byte)) {
            out[offset] = byte;
            offset += 1;
        } else {
            out[offset] = '%';
            out[offset + 1] = hex[byte >> 4];
            out[offset + 2] = hex[byte & 0x0f];
            offset += 3;
        }
    }
    return offset;
}

fn isUnreserved(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or
        byte == '-' or byte == '.' or byte == '_' or byte == '~';
}

fn isRegNameByte(byte: u8) bool {
    if (isUnreserved(byte)) return true;
    return switch (byte) {
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => true,
        else => false,
    };
}

fn hexValue(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

fn decimalLen(value: u8) usize {
    if (value >= 100) return 3;
    if (value >= 10) return 2;
    return 1;
}

test "CONNECT-IP scope applies prefix protocol and ICMP policy to packets" {
    const scope = Scope{
        .target = "203.0.113.0/24",
        .ip_protocol = 6,
    };
    var packet = [_]u8{
        0x45, 0, 0, 20, 0,   1, 0,   0,  64, 6, 0, 0,
        192,  0, 2, 21, 203, 0, 113, 42,
    };
    try std.testing.expectEqual(
        PacketDecision.allowed,
        try scope.packetDecision(&packet),
    );
    packet[9] = 17;
    try std.testing.expectEqual(
        PacketDecision.denied,
        try scope.packetDecision(&packet),
    );
    packet[9] = 1;
    try std.testing.expectEqual(
        PacketDecision.allowed,
        try scope.packetDecision(&packet),
    );
    packet[16..20].* = .{ 198, 51, 100, 42 };
    try std.testing.expectEqual(
        PacketDecision.denied,
        try scope.packetDecision(&packet),
    );
}

test "CONNECT-IP reg-name scope requires or consumes DNS results" {
    const scope = Scope{ .target = "service.example" };
    const packet = [_]u8{
        0x45, 0, 0, 20, 0,   1, 0,   0,  64, 17, 0, 0,
        192,  0, 2, 21, 203, 0, 113, 42,
    };
    try std.testing.expectEqual(
        PacketDecision.requires_dns_resolution,
        try scope.packetDecision(&packet),
    );
    try std.testing.expectEqual(
        PacketDecision.allowed,
        try scope.packetDecisionWithResolvedTargets(&packet, &.{
            .{ .ipv4 = .{ 203, 0, 113, 42 } },
        }),
    );
    try std.testing.expectEqual(
        PacketDecision.denied,
        try scope.packetDecisionWithResolvedTargets(&packet, &.{
            .{ .ipv4 = .{ 203, 0, 113, 43 } },
        }),
    );
}

test "CONNECT-IP scoped protocol keeps unresolved fragments indeterminate" {
    var fragment = [_]u8{0} ** 48;
    fragment[0] = 0x60;
    fragment[5] = 8;
    fragment[6] = 44;
    fragment[7] = 64;
    fragment[24..40].* = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++
        [_]u8{0} ** 11 ++ [_]u8{2};
    fragment[40] = 60;
    fragment[43] = 8;
    const scoped = Scope{
        .target = "2001:db8::/64",
        .ip_protocol = 17,
    };
    try std.testing.expectEqual(
        PacketDecision.requires_reassembly,
        try scoped.packetDecision(&fragment),
    );
    const wildcard_protocol = Scope{ .target = "2001:db8::/64" };
    try std.testing.expectEqual(
        PacketDecision.allowed,
        try wildcard_protocol.packetDecision(&fragment),
    );
}
