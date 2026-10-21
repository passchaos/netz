//! Allocation-free IPv4/IPv6 packet inspection for RFC 9484 CONNECT-IP.
//!
//! Policy checks need the source, destination, and outermost non-extension
//! protocol carried by the tunneled packet. IPv6 therefore walks the extension
//! chain defined by RFC 8200 instead of treating the base header's Next Header
//! field as the application protocol. A non-initial fragment whose fragmentable
//! part starts with another extension header reports an unresolved protocol;
//! only a protocol-wildcard route can safely admit it without reassembly state.

const std = @import("std");
const capsules = @import("capsules.zig");

pub const Error = error{
    InvalidPacket,
    HopLimitExceeded,
};

pub const Version = enum(u8) {
    ipv4 = 4,
    ipv6 = 6,
};

pub const View = struct {
    version: Version,
    source: capsules.IpAddress,
    destination: capsules.IpAddress,
    /// Outermost non-extension protocol. Null means a non-initial IPv6
    /// fragment prevented stateless traversal of a later extension header.
    ip_protocol: ?u8,
    /// Offset of the first byte after every header inspected by this parser.
    header_length: usize,
    hop_limit: u8,
    fragmented: bool,
};

pub fn parse(packet: []const u8) Error!View {
    if (packet.len == 0) return error.InvalidPacket;
    return switch (packet[0] >> 4) {
        4 => parseIpv4(packet),
        6 => parseIpv6(packet),
        else => error.InvalidPacket,
    };
}

/// Decrement IPv4 TTL or IPv6 Hop Limit before forwarding. IPv4's header
/// checksum is recomputed over the complete options-bearing header.
pub fn decrementHopLimit(packet: []u8) Error!void {
    const view = try parse(packet);
    if (view.hop_limit <= 1) return error.HopLimitExceeded;
    switch (view.version) {
        .ipv4 => {
            packet[8] -= 1;
            packet[10..12].* = .{ 0, 0 };
            std.mem.writeInt(
                u16,
                packet[10..12],
                ipv4HeaderChecksumAssumeValid(packet[0..view.header_length]),
                .big,
            );
        },
        .ipv6 => packet[7] -= 1,
    }
}

pub fn ipv4HeaderChecksumValid(packet: []const u8) Error!bool {
    const view = try parse(packet);
    if (view.version != .ipv4) return error.InvalidPacket;
    return ipv4HeaderChecksumAssumeValid(packet[0..view.header_length]) == 0;
}

pub fn ipv4HeaderChecksum(header: []const u8) Error!u16 {
    if (header.len < 20 or header.len > 60 or header.len % 4 != 0 or
        header[0] >> 4 != 4 or @as(usize, header[0] & 0x0f) * 4 != header.len)
    {
        return error.InvalidPacket;
    }
    return ipv4HeaderChecksumAssumeValid(header);
}

fn parseIpv4(packet: []const u8) Error!View {
    if (packet.len < 20) return error.InvalidPacket;
    const words = packet[0] & 0x0f;
    if (words < 5) return error.InvalidPacket;
    const header_length = @as(usize, words) * 4;
    const total_length = std.mem.readInt(u16, packet[2..4], .big);
    if (header_length > packet.len or total_length != packet.len or
        total_length < header_length)
    {
        return error.InvalidPacket;
    }
    const flags_and_offset = std.mem.readInt(u16, packet[6..8], .big);
    if ((flags_and_offset & 0x8000) != 0) return error.InvalidPacket;
    return .{
        .version = .ipv4,
        .source = .{ .ipv4 = packet[12..16].* },
        .destination = .{ .ipv4 = packet[16..20].* },
        .ip_protocol = packet[9],
        .header_length = header_length,
        .hop_limit = packet[8],
        .fragmented = (flags_and_offset & 0x3fff) != 0,
    };
}

fn parseIpv6(packet: []const u8) Error!View {
    if (packet.len < 40) return error.InvalidPacket;
    const payload_length = std.mem.readInt(u16, packet[4..6], .big);
    const total_length = @as(usize, payload_length) + 40;
    // Payload Length zero is the ordinary empty-payload form only. CONNECT-IP
    // deliberately caps packets below RFC 2675 jumbogram sizes.
    if (total_length != packet.len) return error.InvalidPacket;

    var next_header = packet[6];
    var offset: usize = 40;
    var saw_hop_by_hop = false;
    var saw_fragment = false;
    var fragmented = false;
    var resolved_protocol: ?u8 = next_header;
    while (extensionKind(next_header)) |kind| {
        switch (kind) {
            .hop_by_hop, .routing, .destination_options => {
                if (kind == .hop_by_hop) {
                    if (saw_hop_by_hop or offset != 40) {
                        return error.InvalidPacket;
                    }
                    saw_hop_by_hop = true;
                }
                if (offset + 2 > packet.len) return error.InvalidPacket;
                const length = (@as(usize, packet[offset + 1]) + 1) * 8;
                if (offset + length > packet.len) return error.InvalidPacket;
                next_header = packet[offset];
                offset += length;
            },
            .fragment => {
                if (saw_fragment or offset + 8 > packet.len or
                    packet[offset + 1] != 0)
                {
                    return error.InvalidPacket;
                }
                saw_fragment = true;
                fragmented = true;
                const fragment = std.mem.readInt(
                    u16,
                    packet[offset + 2 ..][0..2],
                    .big,
                );
                if ((fragment & 0x0006) != 0) return error.InvalidPacket;
                next_header = packet[offset];
                offset += 8;
                if ((fragment >> 3) & 0x1fff != 0) {
                    resolved_protocol = if (extensionKind(next_header) == null)
                        next_header
                    else
                        null;
                    break;
                }
            },
            .authentication => {
                if (offset + 2 > packet.len) return error.InvalidPacket;
                const length = (@as(usize, packet[offset + 1]) + 2) * 4;
                if (length < 12 or offset + length > packet.len) {
                    return error.InvalidPacket;
                }
                next_header = packet[offset];
                offset += length;
            },
            .encapsulating_security_payload => {
                // ESP's trailer (and therefore its Next Header field) is
                // encrypted. Stateless policy can only admit it through a
                // protocol-wildcard route.
                if (offset + 8 > packet.len) return error.InvalidPacket;
                resolved_protocol = null;
                break;
            },
        }
        resolved_protocol = next_header;
    }
    return .{
        .version = .ipv6,
        .source = .{ .ipv6 = packet[8..24].* },
        .destination = .{ .ipv6 = packet[24..40].* },
        .ip_protocol = resolved_protocol,
        .header_length = offset,
        .hop_limit = packet[7],
        .fragmented = fragmented,
    };
}

const ExtensionKind = enum {
    hop_by_hop,
    routing,
    fragment,
    authentication,
    encapsulating_security_payload,
    destination_options,
};

fn extensionKind(protocol: u8) ?ExtensionKind {
    return switch (protocol) {
        0 => .hop_by_hop,
        43 => .routing,
        44 => .fragment,
        50 => .encapsulating_security_payload,
        51 => .authentication,
        60 => .destination_options,
        else => null,
    };
}

fn ipv4HeaderChecksumAssumeValid(header: []const u8) u16 {
    var sum: u32 = 0;
    var offset: usize = 0;
    while (offset < header.len) : (offset += 2) {
        sum += std.mem.readInt(u16, header[offset..][0..2], .big);
    }
    while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
    return @truncate(~sum);
}

test "CONNECT-IP parses strict IPv4 packets and updates TTL checksum" {
    var packet = [_]u8{
        0x45, 0, 0, 20, 0,   1, 0,   0,  64, 6, 0, 0,
        192,  0, 2, 21, 203, 0, 113, 42,
    };
    std.mem.writeInt(u16, packet[10..12], try ipv4HeaderChecksum(&packet), .big);
    const view = try parse(&packet);
    try std.testing.expectEqual(Version.ipv4, view.version);
    try std.testing.expectEqual(@as(?u8, 6), view.ip_protocol);
    try std.testing.expectEqual(@as(u8, 64), view.hop_limit);
    try std.testing.expect(!view.fragmented);
    try std.testing.expectEqualSlices(u8, &.{ 192, 0, 2, 21 }, view.source.bytes());
    try std.testing.expectEqualSlices(u8, &.{ 203, 0, 113, 42 }, view.destination.bytes());
    try std.testing.expect(try ipv4HeaderChecksumValid(&packet));

    try decrementHopLimit(&packet);
    try std.testing.expectEqual(@as(u8, 63), packet[8]);
    try std.testing.expect(try ipv4HeaderChecksumValid(&packet));
    packet[8] = 1;
    try std.testing.expectError(error.HopLimitExceeded, decrementHopLimit(&packet));
}

test "CONNECT-IP rejects malformed IPv4 length and header fields" {
    const valid = [_]u8{
        0x45, 0, 0, 20, 0,   1,  0,   0, 64, 17, 0, 0,
        192,  0, 2, 1,  198, 51, 100, 1,
    };
    try std.testing.expectError(error.InvalidPacket, parse(valid[0..19]));
    var bad = valid;
    bad[0] = 0x44;
    try std.testing.expectError(error.InvalidPacket, parse(&bad));
    bad = valid;
    bad[3] = 19;
    try std.testing.expectError(error.InvalidPacket, parse(&bad));
    bad = valid;
    bad[6] = 0x80;
    try std.testing.expectError(error.InvalidPacket, parse(&bad));
}

test "CONNECT-IP walks IPv6 options to the outer protocol" {
    var packet = [_]u8{0} ** 84;
    packet[0] = 0x60;
    packet[5] = 44;
    packet[6] = 0;
    packet[7] = 32;
    packet[8..24].* = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 11 ++ [_]u8{1};
    packet[24..40].* = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 11 ++ [_]u8{2};
    packet[40] = 43;
    packet[41] = 0;
    packet[48] = 60;
    packet[49] = 0;
    packet[56] = 51;
    packet[57] = 0;
    packet[64] = 17;
    packet[65] = 1;
    const view = try parse(&packet);
    try std.testing.expectEqual(Version.ipv6, view.version);
    try std.testing.expectEqual(@as(?u8, 17), view.ip_protocol);
    try std.testing.expectEqual(@as(usize, 76), view.header_length);
    try std.testing.expectEqual(@as(u8, 32), view.hop_limit);
    try std.testing.expect(!view.fragmented);

    try decrementHopLimit(&packet);
    try std.testing.expectEqual(@as(u8, 31), packet[7]);
}

test "CONNECT-IP reports unresolved non-initial IPv6 extension fragments" {
    var packet = [_]u8{0} ** 48;
    packet[0] = 0x60;
    packet[5] = 8;
    packet[6] = 44;
    packet[7] = 64;
    packet[40] = 60;
    packet[42] = 0;
    packet[43] = 8;
    const view = try parse(&packet);
    try std.testing.expect(view.fragmented);
    try std.testing.expectEqual(@as(?u8, null), view.ip_protocol);
    try std.testing.expectEqual(@as(usize, 48), view.header_length);
}

test "CONNECT-IP leaves encrypted ESP upper protocol unresolved" {
    var packet = [_]u8{0} ** 48;
    packet[0] = 0x60;
    packet[5] = 8;
    packet[6] = 50;
    packet[7] = 64;
    const view = try parse(&packet);
    try std.testing.expectEqual(@as(?u8, null), view.ip_protocol);
    try std.testing.expectEqual(@as(usize, 40), view.header_length);
}

test "CONNECT-IP rejects truncated IPv6 extensions and jumbograms" {
    var packet = [_]u8{0} ** 48;
    packet[0] = 0x60;
    packet[5] = 8;
    packet[6] = 60;
    packet[40] = 17;
    packet[41] = 1;
    try std.testing.expectError(error.InvalidPacket, parse(&packet));

    packet[4] = 0;
    packet[5] = 0;
    try std.testing.expectError(error.InvalidPacket, parse(&packet));
}
