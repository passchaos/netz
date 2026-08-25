//! Strict, bounded HAProxy PROXY protocol v1/v2 decoding for trusted MQTT
//! listeners. The header is consumed before MQTT framing, and all returned
//! metadata owns its variable-length storage.

const std = @import("std");
const stream_io = @import("../internal/stream_io.zig");

const net = std.Io.net;

pub const v1_max_header_bytes: usize = 108;
pub const v2_fixed_header_bytes: usize = 16;
pub const v2_max_payload_bytes: usize = 500;
pub const v2_signature = [_]u8{
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51,
    0x55, 0x49, 0x54, 0x0a,
};

pub const Error = std.mem.Allocator.Error ||
    net.Stream.Reader.Error || stream_io.TimedReadError || error{
    ConnectionClosed,
    InvalidHeader,
    HeaderTooLarge,
    ChecksumMismatch,
};

pub const Version = enum { v1, v2 };

pub const Command = enum { local, proxy };

pub const Transport = enum { stream, datagram };

pub const Endpoints = struct {
    source: net.IpAddress,
    destination: net.IpAddress,
    transport: Transport,
};

pub const TlsInfo = struct {
    client_ssl: bool,
    client_certificate_connection: bool,
    client_certificate_session: bool,
    verified: bool,
    version: ?[]u8 = null,
    common_name: ?[]u8 = null,
    cipher: ?[]u8 = null,
    signature_algorithm: ?[]u8 = null,
    key_algorithm: ?[]u8 = null,

    pub fn deinit(self: *TlsInfo, allocator: std.mem.Allocator) void {
        if (self.version) |value| allocator.free(value);
        if (self.common_name) |value| allocator.free(value);
        if (self.cipher) |value| allocator.free(value);
        if (self.signature_algorithm) |value| allocator.free(value);
        if (self.key_algorithm) |value| allocator.free(value);
        self.* = undefined;
    }
};

pub const Metadata = struct {
    allocator: std.mem.Allocator,
    version: Version,
    command: Command,
    endpoints: ?Endpoints = null,
    source_unix: ?[]u8 = null,
    destination_unix: ?[]u8 = null,
    alpn: ?[]u8 = null,
    authority: ?[]u8 = null,
    unique_id: ?[]u8 = null,
    network_namespace: ?[]u8 = null,
    tls: ?TlsInfo = null,

    pub fn deinit(self: *Metadata) void {
        if (self.source_unix) |value| self.allocator.free(value);
        if (self.destination_unix) |value| self.allocator.free(value);
        if (self.alpn) |value| self.allocator.free(value);
        if (self.authority) |value| self.allocator.free(value);
        if (self.unique_id) |value| self.allocator.free(value);
        if (self.network_namespace) |value| self.allocator.free(value);
        if (self.tls) |*value| value.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn sourceAddress(self: Metadata) ?net.IpAddress {
        return if (self.endpoints) |endpoints| endpoints.source else null;
    }

    pub fn destinationAddress(self: Metadata) ?net.IpAddress {
        return if (self.endpoints) |endpoints| endpoints.destination else null;
    }
};

pub fn read(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    version: Version,
) Error!Metadata {
    return readWithDeadline(allocator, io, stream, version, null);
}

/// Consume one complete header before an optional absolute deadline. A single
/// deadline spans all fragmented reads, so a trusted-proxy listener cannot be
/// held indefinitely by a byte-at-a-time preface.
pub fn readWithDeadline(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    version: Version,
    deadline: ?std.Io.Clock.Timestamp,
) Error!Metadata {
    return switch (version) {
        .v1 => readV1(allocator, io, stream, deadline),
        .v2 => readV2(allocator, io, stream, deadline),
    };
}

pub fn parseV1(
    allocator: std.mem.Allocator,
    header: []const u8,
) Error!Metadata {
    if (header.len > v1_max_header_bytes) return error.HeaderTooLarge;
    if (header.len < 2 or
        !std.mem.eql(u8, header[header.len - 2 ..], "\r\n"))
    {
        return error.InvalidHeader;
    }
    const line = header[0 .. header.len - 2];
    var fields = std.mem.splitScalar(u8, line, ' ');
    if (!std.mem.eql(u8, fields.next() orelse return error.InvalidHeader, "PROXY")) {
        return error.InvalidHeader;
    }
    const family = fields.next() orelse return error.InvalidHeader;
    if (std.mem.eql(u8, family, "UNKNOWN")) {
        // HAProxy v1 permits arbitrary data after UNKNOWN. It is intentionally
        // ignored because the transport endpoints remain authoritative.
        return .{
            .allocator = allocator,
            .version = .v1,
            .command = .local,
        };
    }
    if (!std.mem.eql(u8, family, "TCP4") and
        !std.mem.eql(u8, family, "TCP6"))
    {
        return error.InvalidHeader;
    }
    const source_text = fields.next() orelse return error.InvalidHeader;
    const destination_text = fields.next() orelse return error.InvalidHeader;
    const source_port = try parsePort(fields.next() orelse
        return error.InvalidHeader);
    const destination_port = try parsePort(fields.next() orelse
        return error.InvalidHeader);
    if (fields.next() != null) return error.InvalidHeader;

    const source = if (family[3] == '4')
        net.IpAddress.parseIp4(source_text, source_port) catch
            return error.InvalidHeader
    else
        net.IpAddress.parseIp6(source_text, source_port) catch
            return error.InvalidHeader;
    const destination = if (family[3] == '4')
        net.IpAddress.parseIp4(destination_text, destination_port) catch
            return error.InvalidHeader
    else
        net.IpAddress.parseIp6(destination_text, destination_port) catch
            return error.InvalidHeader;
    return .{
        .allocator = allocator,
        .version = .v1,
        .command = .proxy,
        .endpoints = .{
            .source = source,
            .destination = destination,
            .transport = .stream,
        },
    };
}

pub fn parseV2(
    allocator: std.mem.Allocator,
    header: []const u8,
) Error!Metadata {
    if (header.len < v2_fixed_header_bytes or
        !std.mem.eql(u8, header[0..v2_signature.len], &v2_signature))
    {
        return error.InvalidHeader;
    }
    const payload_len = readU16(header[14..16]);
    if (payload_len > v2_max_payload_bytes) return error.HeaderTooLarge;
    if (header.len != v2_fixed_header_bytes + payload_len) {
        return error.InvalidHeader;
    }
    const version_command = header[12];
    if (version_command >> 4 != 2) return error.InvalidHeader;
    const command: Command = switch (version_command & 0x0f) {
        0 => .local,
        1 => .proxy,
        else => return error.InvalidHeader,
    };
    const family = header[13] >> 4;
    const protocol = header[13] & 0x0f;
    if (command == .local) {
        // LOCAL transports are deliberately opaque: address and TLV bytes
        // describe the proxy itself and must not become client identity.
        return .{
            .allocator = allocator,
            .version = .v2,
            .command = .local,
        };
    }
    const transport: Transport = switch (protocol) {
        1 => .stream,
        2 => .datagram,
        else => return error.InvalidHeader,
    };
    // A PROXY header precedes a connection-oriented MQTT byte stream. Accepting
    // DGRAM here would attach datagram provenance to TCP application bytes.
    if (transport != .stream) return error.InvalidHeader;

    var metadata = Metadata{
        .allocator = allocator,
        .version = .v2,
        .command = .proxy,
    };
    errdefer metadata.deinit();
    const payload = header[v2_fixed_header_bytes..];
    const offset: usize = switch (family) {
        1 => blk: {
            if (payload.len < 12) return error.InvalidHeader;
            metadata.endpoints = .{
                .source = .{ .ip4 = .{
                    .bytes = payload[0..4].*,
                    .port = readU16(payload[8..10]),
                } },
                .destination = .{ .ip4 = .{
                    .bytes = payload[4..8].*,
                    .port = readU16(payload[10..12]),
                } },
                .transport = transport,
            };
            break :blk 12;
        },
        2 => blk: {
            if (payload.len < 36) return error.InvalidHeader;
            metadata.endpoints = .{
                .source = .{ .ip6 = .{
                    .bytes = payload[0..16].*,
                    .port = readU16(payload[32..34]),
                } },
                .destination = .{ .ip6 = .{
                    .bytes = payload[16..32].*,
                    .port = readU16(payload[34..36]),
                } },
                .transport = transport,
            };
            break :blk 36;
        },
        3 => blk: {
            if (payload.len < 216 or transport != .stream) {
                return error.InvalidHeader;
            }
            metadata.source_unix = try duplicateUnixName(
                allocator,
                payload[0..108],
            );
            metadata.destination_unix = try duplicateUnixName(
                allocator,
                payload[108..216],
            );
            break :blk 216;
        },
        else => return error.InvalidHeader,
    };
    try parseTlvs(&metadata, header, payload, offset);
    return metadata;
}

fn readV1(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    deadline: ?std.Io.Clock.Timestamp,
) Error!Metadata {
    var header: [v1_max_header_bytes]u8 = undefined;
    var len: usize = 0;
    while (len < header.len) {
        try readExact(io, stream, header[len .. len + 1], deadline);
        len += 1;
        if (len >= 2 and std.mem.eql(u8, header[len - 2 .. len], "\r\n")) {
            return parseV1(allocator, header[0..len]);
        }
    }
    return error.HeaderTooLarge;
}

fn readV2(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    deadline: ?std.Io.Clock.Timestamp,
) Error!Metadata {
    var fixed: [v2_fixed_header_bytes]u8 = undefined;
    try readExact(io, stream, &fixed, deadline);
    if (!std.mem.eql(u8, fixed[0..v2_signature.len], &v2_signature)) {
        return error.InvalidHeader;
    }
    const payload_len = readU16(fixed[14..16]);
    if (payload_len > v2_max_payload_bytes) return error.HeaderTooLarge;
    var header: [v2_fixed_header_bytes + v2_max_payload_bytes]u8 = undefined;
    @memcpy(header[0..fixed.len], &fixed);
    try readExact(
        io,
        stream,
        header[fixed.len .. fixed.len + payload_len],
        deadline,
    );
    return parseV2(allocator, header[0 .. fixed.len + payload_len]);
}

fn parseTlvs(
    metadata: *Metadata,
    complete_header: []const u8,
    payload: []const u8,
    start: usize,
) Error!void {
    var offset = start;
    var crc_offset: ?usize = null;
    var expected_crc: u32 = 0;
    while (offset < payload.len) {
        if (payload.len - offset < 3) return error.InvalidHeader;
        const typ = payload[offset];
        const len = readU16(payload[offset + 1 .. offset + 3]);
        offset += 3;
        if (len > payload.len - offset) return error.InvalidHeader;
        const value = payload[offset .. offset + len];
        switch (typ) {
            0x01 => try replaceOwned(&metadata.alpn, metadata.allocator, value),
            0x02 => try replaceOwned(&metadata.authority, metadata.allocator, value),
            0x03 => {
                if (len != 4 or crc_offset != null) return error.InvalidHeader;
                crc_offset = v2_fixed_header_bytes + offset;
                expected_crc = readU32(value);
            },
            0x05 => try replaceOwned(&metadata.unique_id, metadata.allocator, value),
            0x20 => try parseSslTlv(metadata, value),
            0x30 => try replaceOwned(
                &metadata.network_namespace,
                metadata.allocator,
                value,
            ),
            else => {},
        }
        offset += len;
    }
    if (crc_offset) |index| {
        var crc = std.hash.crc.Crc32Iscsi.init();
        crc.update(complete_header[0..index]);
        crc.update(&.{ 0, 0, 0, 0 });
        crc.update(complete_header[index + 4 ..]);
        if (crc.final() != expected_crc) return error.ChecksumMismatch;
    }
}

fn parseSslTlv(metadata: *Metadata, value: []const u8) Error!void {
    if (value.len < 5 or metadata.tls != null) return error.InvalidHeader;
    var tls = TlsInfo{
        .client_ssl = value[0] & 0x01 != 0,
        .client_certificate_connection = value[0] & 0x02 != 0,
        .client_certificate_session = value[0] & 0x04 != 0,
        .verified = readU32(value[1..5]) == 0,
    };
    errdefer tls.deinit(metadata.allocator);
    var offset: usize = 5;
    while (offset < value.len) {
        if (value.len - offset < 3) return error.InvalidHeader;
        const typ = value[offset];
        const len = readU16(value[offset + 1 .. offset + 3]);
        offset += 3;
        if (len > value.len - offset) return error.InvalidHeader;
        const item = value[offset .. offset + len];
        switch (typ) {
            0x21 => try replaceOwned(&tls.version, metadata.allocator, item),
            0x22 => try replaceOwned(
                &tls.common_name,
                metadata.allocator,
                item,
            ),
            0x23 => try replaceOwned(&tls.cipher, metadata.allocator, item),
            0x24 => try replaceOwned(
                &tls.signature_algorithm,
                metadata.allocator,
                item,
            ),
            0x25 => try replaceOwned(
                &tls.key_algorithm,
                metadata.allocator,
                item,
            ),
            else => {},
        }
        offset += len;
    }
    metadata.tls = tls;
}

fn replaceOwned(
    slot: *?[]u8,
    allocator: std.mem.Allocator,
    value: []const u8,
) std.mem.Allocator.Error!void {
    const owned = try allocator.dupe(u8, value);
    if (slot.*) |old| allocator.free(old);
    slot.* = owned;
}

fn duplicateUnixName(
    allocator: std.mem.Allocator,
    field: []const u8,
) std.mem.Allocator.Error![]u8 {
    const end = std.mem.indexOfScalar(u8, field, 0) orelse field.len;
    return allocator.dupe(u8, field[0..end]);
}

fn parsePort(text: []const u8) Error!u16 {
    if (text.len == 0) return error.InvalidHeader;
    const port = std.fmt.parseInt(u16, text, 10) catch
        return error.InvalidHeader;
    if (port == 0) return error.InvalidHeader;
    return port;
}

fn readExact(
    io: std.Io,
    stream: net.Stream,
    out: []u8,
    deadline: ?std.Io.Clock.Timestamp,
) Error!void {
    var offset: usize = 0;
    while (offset < out.len) {
        const count = if (deadline) |absolute|
            try stream_io.readSomeWithDeadline(
                io,
                stream,
                out[offset..],
                absolute,
            )
        else blk: {
            var bufs = [_][]u8{out[offset..]};
            break :blk try io.vtable.netRead(
                io.userdata,
                stream.socket.handle,
                &bufs,
            );
        };
        if (count == 0) return error.ConnectionClosed;
        offset += count;
    }
}

fn readU16(bytes: []const u8) u16 {
    std.debug.assert(bytes.len >= 2);
    return (@as(u16, bytes[0]) << 8) | bytes[1];
}

fn readU32(bytes: []const u8) u32 {
    std.debug.assert(bytes.len >= 4);
    return (@as(u32, bytes[0]) << 24) |
        (@as(u32, bytes[1]) << 16) |
        (@as(u32, bytes[2]) << 8) |
        bytes[3];
}

test "PROXY v1 parses TCP endpoints and UNKNOWN" {
    var tcp4 = try parseV1(
        std.testing.allocator,
        "PROXY TCP4 192.0.2.5 127.0.0.1 6275 1883\r\n",
    );
    defer tcp4.deinit();
    try std.testing.expectEqual(Command.proxy, tcp4.command);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 192, 0, 2, 5 },
        &tcp4.endpoints.?.source.ip4.bytes,
    );
    try std.testing.expectEqual(@as(u16, 6275), tcp4.endpoints.?.source.ip4.port);

    var unknown = try parseV1(
        std.testing.allocator,
        "PROXY UNKNOWN ignored fields\r\n",
    );
    defer unknown.deinit();
    try std.testing.expectEqual(Command.local, unknown.command);
    try std.testing.expect(unknown.endpoints == null);
}

test "PROXY v1 rejects malformed and oversized headers" {
    try std.testing.expectError(
        error.InvalidHeader,
        parseV1(std.testing.allocator, "PROXY TCP3 1 2 3 4\r\n"),
    );
    try std.testing.expectError(
        error.InvalidHeader,
        parseV1(std.testing.allocator, "PROXY TCP4 192.0.2.5 127.0.0.1 0 1883\r\n"),
    );
    var too_long: [v1_max_header_bytes + 1]u8 = @splat('x');
    too_long[too_long.len - 2] = '\r';
    too_long[too_long.len - 1] = '\n';
    try std.testing.expectError(
        error.HeaderTooLarge,
        parseV1(std.testing.allocator, &too_long),
    );
}

test "PROXY v2 parses IPv4 endpoints and SSL metadata" {
    var header: std.ArrayList(u8) = .empty;
    defer header.deinit(std.testing.allocator);
    try header.appendSlice(std.testing.allocator, &v2_signature);
    try header.appendSlice(std.testing.allocator, &.{ 0x21, 0x11, 0, 0 });
    try header.appendSlice(std.testing.allocator, &.{
        192, 0, 2, 5, 127, 0, 0, 1, 0x18, 0x83, 0x07, 0x5b,
    });
    const ssl_value = [_]u8{
        0x07, 0,   0,   0,   0,
        0x21, 0,   7,   'T', 'L',
        'S',  'v', '1', '.', '3',
        0x22, 0,   6,   'c', 'l',
        'i',  'e', 'n', 't',
    };
    try header.appendSlice(std.testing.allocator, &.{
        0x01, 0, 4,             'm', 'q', 't', 't',
        0x20, 0, ssl_value.len,
    });
    try header.appendSlice(std.testing.allocator, &ssl_value);
    const payload_len: u16 = @intCast(header.items.len - v2_fixed_header_bytes);
    std.mem.writeInt(u16, header.items[14..16], payload_len, .big);

    var metadata = try parseV2(std.testing.allocator, header.items);
    defer metadata.deinit();
    try std.testing.expectEqualStrings("mqtt", metadata.alpn.?);
    try std.testing.expectEqualStrings("TLSv1.3", metadata.tls.?.version.?);
    try std.testing.expectEqualStrings("client", metadata.tls.?.common_name.?);
    try std.testing.expect(metadata.tls.?.verified);
    try std.testing.expectEqual(@as(u16, 6275), metadata.sourceAddress().?.ip4.port);
}

test "PROXY v2 LOCAL ignores opaque payload" {
    const header = v2_signature ++ [_]u8{ 0x20, 0x00, 0x00, 0x03 } ++
        [_]u8{ 1, 2, 3 };
    var metadata = try parseV2(std.testing.allocator, &header);
    defer metadata.deinit();
    try std.testing.expectEqual(Command.local, metadata.command);
    try std.testing.expect(metadata.sourceAddress() == null);
}

test "PROXY v2 parses IPv6 and Unix stream endpoints" {
    const ipv6 = v2_signature ++ [_]u8{ 0x21, 0x21, 0x00, 0x24 } ++
        [_]u8{
            0x20, 0x01, 0x0d, 0xb8, 0x05, 0x06, 0x07, 0x08,
            0x09, 0,    0,    0,    0,    0,    0,    1,
            0,    0,    0,    0,    0,    0,    0,    0,
            0,    0,    0,    0,    0,    0,    0,    1,
            0x18, 0x83, 0x07, 0x5b,
        };
    var ipv6_metadata = try parseV2(std.testing.allocator, &ipv6);
    defer ipv6_metadata.deinit();
    try std.testing.expectEqual(
        @as(u16, 6275),
        ipv6_metadata.sourceAddress().?.ip6.port,
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x20, 0x01, 0x0d, 0xb8 },
        ipv6_metadata.sourceAddress().?.ip6.bytes[0..4],
    );

    var unix = v2_signature ++ [_]u8{ 0x21, 0x31, 0x00, 0xd8 } ++
        [_]u8{0} ** 216;
    @memcpy(unix[16..21], "/src/");
    @memcpy(unix[124..129], "/dst/");
    var unix_metadata = try parseV2(std.testing.allocator, &unix);
    defer unix_metadata.deinit();
    try std.testing.expectEqualStrings("/src/", unix_metadata.source_unix.?);
    try std.testing.expectEqualStrings("/dst/", unix_metadata.destination_unix.?);
}

test "PROXY v2 validates declared size and CRC32C" {
    const invalid_size = v2_signature ++ [_]u8{ 0x21, 0x11, 0x00, 0x0b } ++
        [_]u8{0} ** 12;
    try std.testing.expectError(
        error.InvalidHeader,
        parseV2(std.testing.allocator, &invalid_size),
    );
    const datagram = v2_signature ++ [_]u8{ 0x21, 0x12, 0x00, 0x0c } ++
        [_]u8{0} ** 12;
    try std.testing.expectError(
        error.InvalidHeader,
        parseV2(std.testing.allocator, &datagram),
    );

    var header = v2_signature ++ [_]u8{ 0x21, 0x11, 0x00, 0x13 } ++
        [_]u8{0} ** 12 ++ [_]u8{ 0x03, 0x00, 0x04, 0, 0, 0, 0 };
    const crc_offset = header.len - 4;
    const checksum = std.hash.crc.Crc32Iscsi.hash(&header);
    std.mem.writeInt(u32, header[crc_offset..], checksum, .big);
    var metadata = try parseV2(std.testing.allocator, &header);
    metadata.deinit();
    header[crc_offset] ^= 1;
    try std.testing.expectError(
        error.ChecksumMismatch,
        parseV2(std.testing.allocator, &header),
    );
}
