//! VMess legacy request/response header codec with security NONE bodies.
//!
//! This implements the legacy (non-AEAD) VMess header path documented by
//! v2fly: HMAC-MD5 timestamp authentication, AES-128-CFB header protection,
//! FNV-1a checksum, and plaintext bodies. Modern VMess AEAD headers and
//! encrypted body modes are separate layers.

const std = @import("std");

const net = std.Io.net;
const codec = @import("../socks/codec.zig");
const crypto = @import("crypto.zig");

pub const version: u8 = 1;
pub const security_legacy: u8 = 1;
pub const security_none: u8 = 5;
pub const security_aes128_gcm: u8 = 3;
pub const security_chacha20_poly1305: u8 = 4;
pub const option_chunk_stream: u8 = 0x01;

pub const Error = error{
    AuthenticationFailed,
    UnsupportedSecurity,
    InvalidHeader,
    TruncatedHeader,
    InvalidAddress,
    InvalidHostName,
    InvalidChecksum,
    BufferTooSmall,
    UnsupportedCommand,
};

pub const Command = enum(u8) {
    tcp = 1,
    udp = 2,
};

pub const ClientSession = struct {
    body_key: [16]u8,
    body_iv: [16]u8,
    response_header: u8,
    security: u8 = security_none,
    option: u8 = 0,
};

pub const ServerSession = struct {
    body_key: [16]u8,
    body_iv: [16]u8,
    response_header: u8,
    security: u8 = security_none,
    option: u8 = 0,
};

pub const Request = struct {
    command: Command,
    address: codec.Address,
};

/// Build the plaintext VMess request header (without auth or encryption).
pub fn buildPlainHeader(
    allocator: std.mem.Allocator,
    request: Request,
    padding_len: u8,
    response_header: u8,
    body_key: [16]u8,
    body_iv: [16]u8,
    security: u8,
    option: u8,
) ![]u8 {
    if (padding_len > 15) return error.InvalidHeader;

    var plain: std.ArrayList(u8) = .empty;
    errdefer plain.deinit(allocator);
    try plain.append(allocator, version);
    try plain.appendSlice(allocator, &body_iv);
    try plain.appendSlice(allocator, &body_key);
    try plain.append(allocator, response_header);
    try plain.append(allocator, option);
    try plain.append(allocator, (padding_len << 4) | security);
    try plain.append(allocator, 0);
    try plain.append(allocator, @intFromEnum(request.command));
    try plain.append(allocator, @intCast(request.address.getPort() >> 8));
    try plain.append(allocator, @intCast(request.address.getPort() & 0xff));
    try encodeAddress(allocator, &plain, request.address);
    for (0..padding_len) |_| {
        try plain.append(allocator, 0x5a);
    }
    const checksum = crypto.fnv1a32(plain.items);
    try plain.append(allocator, @intCast(checksum >> 24));
    try plain.append(allocator, @intCast((checksum >> 16) & 0xff));
    try plain.append(allocator, @intCast((checksum >> 8) & 0xff));
    try plain.append(allocator, @intCast(checksum & 0xff));
    return plain.toOwnedSlice(allocator);
}

/// Encode the complete legacy client header (auth + encrypted request header).
/// The caller writes payload bytes after this header without encryption.
pub fn encodeRequestHeader(
    allocator: std.mem.Allocator,
    uuid: [16]u8,
    timestamp: i64,
    request: Request,
    padding_len: u8,
    response_header: u8,
    body_key: [16]u8,
    body_iv: [16]u8,
    security: u8,
    option: u8,
) ![]u8 {
    const plain = try buildPlainHeader(
        allocator,
        request,
        padding_len,
        response_header,
        body_key,
        body_iv,
        security,
        option,
    );
    defer allocator.free(plain);

    var key: [16]u8 = undefined;
    crypto.cmdKey(uuid, &key);
    var encryptor = crypto.Cfb.initEncrypt(key, crypto.timestampIv(timestamp));
    encryptor.process(plain, plain);

    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    try output.appendSlice(allocator, &crypto.timestampAuth(uuid, timestamp));
    try output.appendSlice(allocator, plain);
    return output.toOwnedSlice(allocator);
}

pub const DecodedRequest = struct {
    request: Request,
    session: ServerSession,
};

/// Parse a complete plaintext VMess request header, including padding and the
/// FNV-1a checksum.
pub fn parsePlainHeader(
    bytes: []const u8,
    host_storage: []u8,
) !DecodedRequest {
    if (bytes.len < 38) return error.TruncatedHeader;
    if (bytes[0] != version) return error.InvalidHeader;
    const session: ServerSession = .{
        .body_iv = bytes[1..17].*,
        .body_key = bytes[17..33].*,
        .response_header = bytes[33],
        .security = bytes[35] & 0x0f,
        .option = bytes[34],
    };
    const option = bytes[34];
    const security = bytes[35] & 0x0f;
    if (security != security_legacy and security != security_none and
        security != security_aes128_gcm and
        security != security_chacha20_poly1305)
    {
        return error.UnsupportedSecurity;
    }
    if (security == security_none and
        option & option_chunk_stream != 0)
    {
        return error.UnsupportedSecurity;
    }
    const padding_len: usize = bytes[35] >> 4;
    if (padding_len > 15) return error.InvalidHeader;
    if (bytes[36] != 0) return error.InvalidHeader;
    const command: Command = switch (bytes[37]) {
        1 => .tcp,
        2 => .udp,
        else => return error.UnsupportedCommand,
    };

    var offset: usize = 38;
    if (bytes.len < offset + 2 + 1) return error.TruncatedHeader;
    const port = std.mem.readInt(u16, bytes[offset..][0..2], .big);
    offset += 2;
    const address_type = bytes[offset];
    offset += 1;

    var address: codec.Address = undefined;
    switch (address_type) {
        1 => {
            if (bytes.len < offset + 4) return error.TruncatedHeader;
            address = .{ .ip = .{ .ip4 = .{
                .bytes = bytes[offset..][0..4].*,
                .port = port,
            } } };
            offset += 4;
        },
        3 => {
            if (bytes.len < offset + 16) return error.TruncatedHeader;
            address = .{ .ip = .{ .ip6 = .{
                .bytes = bytes[offset..][0..16].*,
                .port = port,
                .flow = 0,
                .interface = .none,
            } } };
            offset += 16;
        },
        2 => {
            if (bytes.len < offset + 1) return error.TruncatedHeader;
            const host_len = bytes[offset];
            offset += 1;
            if (host_len == 0) return error.InvalidAddress;
            if (bytes.len < offset + host_len) return error.TruncatedHeader;
            const host = bytes[offset..][0..host_len];
            _ = net.HostName.init(host) catch return error.InvalidHostName;
            if (host_len > host_storage.len) return error.BufferTooSmall;
            @memcpy(host_storage[0..host_len], host);
            address = .{ .domain = .{
                .host = host_storage[0..host_len],
                .port = port,
            } };
            offset += host_len;
        },
        else => return error.InvalidAddress,
    }

    if (bytes.len < offset + padding_len + 4) return error.TruncatedHeader;
    offset += padding_len;
    const expected = std.mem.readInt(u32, bytes[offset..][0..4], .big);
    if (crypto.fnv1a32(bytes[0..offset]) != expected) {
        return error.InvalidChecksum;
    }

    return .{
        .request = .{ .command = command, .address = address },
        .session = session,
    };
}

/// Decode a streaming legacy request header after the caller has read the
/// 16-byte authentication prefix.
pub fn decodeLegacyHeaderAfterAuth(
    connection: anytype,
    uuid: [16]u8,
    now_seconds: i64,
    window_seconds: u32,
    host_storage: []u8,
    auth: [16]u8,
) !DecodedRequest {
    var matched_timestamp: ?i64 = null;
    const window: i64 = @intCast(window_seconds);
    var delta: i64 = -window;
    while (delta <= window) : (delta += 1) {
        const timestamp = now_seconds + delta;
        const expected = crypto.timestampAuth(uuid, timestamp);
        if (timingSafeEql(&auth, &expected)) matched_timestamp = timestamp;
    }
    const timestamp = matched_timestamp orelse
        return error.AuthenticationFailed;

    var key: [16]u8 = undefined;
    crypto.cmdKey(uuid, &key);
    var decryptor = crypto.Cfb.initDecrypt(key, crypto.timestampIv(timestamp));

    var header: [512]u8 = undefined;
    var used: usize = 0;
    try readDecrypted(connection, &decryptor, header[used..][0..38]);
    used += 38;

    const padding_len: usize = header[35] >> 4;
    if (padding_len > 15) return error.InvalidHeader;
    try readDecrypted(connection, &decryptor, header[used..][0..2]);
    used += 2;
    try readDecrypted(connection, &decryptor, header[used..][0..1]);
    const address_type = header[used];
    used += 1;
    const address_len: usize = switch (address_type) {
        1 => 4,
        3 => 16,
        2 => blk: {
            try readDecrypted(connection, &decryptor, header[used..][0..1]);
            const host_len = header[used];
            used += 1;
            if (host_len == 0) return error.InvalidAddress;
            break :blk host_len;
        },
        else => return error.InvalidAddress,
    };
    try readDecrypted(connection, &decryptor, header[used..][0..address_len]);
    used += address_len;
    if (padding_len > 0) {
        try readDecrypted(
            connection,
            &decryptor,
            header[used..][0..padding_len],
        );
        used += padding_len;
    }
    var checksum_bytes: [4]u8 = undefined;
    try readDecrypted(connection, &decryptor, &checksum_bytes);
    @memcpy(header[used..][0..4], &checksum_bytes);
    used += 4;
    return parsePlainHeader(header[0..used], host_storage);
}

/// Decode a streaming request header from a TLS-like connection. Only the
/// exact header bytes are read; payload bytes remain unread.
pub fn decodeRequestHeader(
    connection: anytype,
    uuid: [16]u8,
    now_seconds: i64,
    window_seconds: u32,
    host_storage: []u8,
) !DecodedRequest {
    var auth: [16]u8 = undefined;
    try readExact(connection, &auth);
    return decodeLegacyHeaderAfterAuth(
        connection,
        uuid,
        now_seconds,
        window_seconds,
        host_storage,
        auth,
    );
}

/// Encode and write the VMess response header. The response body is plaintext.
pub fn encodeResponseHeader(
    session: ServerSession,
    connection: anytype,
) !void {
    var key: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(&session.body_key, &key, .{});
    var iv: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(&session.body_iv, &iv, .{});

    var plain = [4]u8{
        session.response_header,
        0,
        0,
        0,
    };
    var encryptor = crypto.Cfb.initEncrypt(key, iv);
    var wire: [4]u8 = undefined;
    encryptor.process(&wire, &plain);
    try writeAll(connection, &wire);
}

/// Decode the response header on the client side.
pub fn decodeResponseHeader(
    session: ClientSession,
    connection: anytype,
) !void {
    var key: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(&session.body_key, &key, .{});
    var iv: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(&session.body_iv, &iv, .{});

    var wire: [4]u8 = undefined;
    try readExact(connection, &wire);
    var plain: [4]u8 = undefined;
    var decryptor = crypto.Cfb.initDecrypt(key, iv);
    decryptor.process(&plain, &wire);
    if (plain[0] != session.response_header) return error.InvalidHeader;
    if (plain[2] != 0) return error.InvalidHeader;
    if (plain[3] != 0) {
        var command_bytes: [255]u8 = undefined;
        try readExact(connection, command_bytes[0..plain[3]]);
    }
}

fn encodeAddress(
    allocator: std.mem.Allocator,
    output: *std.ArrayList(u8),
    address: codec.Address,
) !void {
    switch (address) {
        .ip => |ip| switch (ip) {
            .ip4 => |value| {
                try output.append(allocator, 1);
                try output.appendSlice(allocator, &value.bytes);
            },
            .ip6 => |value| {
                try output.append(allocator, 3);
                try output.appendSlice(allocator, &value.bytes);
            },
        },
        .domain => |domain| {
            _ = net.HostName.init(domain.host) catch
                return error.InvalidHostName;
            try output.append(allocator, 2);
            try output.append(allocator, @intCast(domain.host.len));
            try output.appendSlice(allocator, domain.host);
        },
    }
}

fn readDecrypted(
    connection: anytype,
    decryptor: *crypto.Cfb,
    output: []u8,
) !void {
    var offset: usize = 0;
    while (offset < output.len) {
        const count = try connection.read(output[offset..]);
        if (count == 0) return error.TruncatedHeader;
        decryptor.process(output[offset..][0..count], output[offset..][0..count]);
        offset += count;
    }
}

fn readExact(connection: anytype, output: []u8) !void {
    var offset: usize = 0;
    while (offset < output.len) {
        const count = try connection.read(output[offset..]);
        if (count == 0) return error.TruncatedHeader;
        offset += count;
    }
}

fn writeAll(connection: anytype, bytes: []const u8) !void {
    try connection.writeAll(bytes);
}

fn timingSafeEql(a: *const [16]u8, b: *const [16]u8) bool {
    var difference: u8 = 0;
    for (a, b) |lhs, rhs| difference |= lhs ^ rhs;
    return difference == 0;
}

test "VMess request header round trips through an in-memory stream" {
    const allocator = std.testing.allocator;
    const uuid: [16]u8 = .{
        0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53,
        0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11,
    };
    const timestamp: i64 = 1700000000;
    const target = codec.Address{ .ip = .{ .ip4 = .{
        .bytes = .{ 192, 0, 2, 1 },
        .port = 443,
    } } };
    const body_key = [_]u8{0x11} ** 16;
    const body_iv = [_]u8{0x22} ** 16;
    const wire = try encodeRequestHeader(
        allocator,
        uuid,
        timestamp,
        .{ .command = .tcp, .address = target },
        0,
        0x77,
        body_key,
        body_iv,
        security_none,
        0,
    );
    defer allocator.free(wire);

    var connection = MemoryConnection{ .bytes = wire };
    var host_storage: [255]u8 = undefined;
    const decoded = try decodeRequestHeader(
        &connection,
        uuid,
        timestamp,
        0,
        &host_storage,
    );
    try std.testing.expectEqual(Command.tcp, decoded.request.command);
    try std.testing.expect(decoded.request.address.eql(target));
    try std.testing.expectEqual(@as(u8, 0x77), decoded.session.response_header);
    try std.testing.expectEqualSlices(u8, &body_key, &decoded.session.body_key);
    try std.testing.expectEqualSlices(u8, &body_iv, &decoded.session.body_iv);
}

test "VMess rejects a corrupted authentication value" {
    const allocator = std.testing.allocator;
    const uuid = [_]u8{0x01} ** 16;
    const wire = try encodeRequestHeader(
        allocator,
        uuid,
        1700000000,
        .{ .command = .tcp, .address = .{ .ip = .{ .ip4 = .{
            .bytes = .{ 127, 0, 0, 1 },
            .port = 80,
        } } } },
        0,
        1,
        [_]u8{0} ** 16,
        [_]u8{0} ** 16,
        security_none,
        0,
    );
    defer allocator.free(wire);
    wire[0] ^= 1;
    var connection = MemoryConnection{ .bytes = wire };
    var host_storage: [255]u8 = undefined;
    try std.testing.expectError(
        error.AuthenticationFailed,
        decodeRequestHeader(&connection, uuid, 1700000000, 0, &host_storage),
    );
}

const MemoryConnection = struct {
    bytes: []const u8,
    offset: usize = 0,
    written: [64]u8 = undefined,
    written_len: usize = 0,

    fn read(self: *@This(), output: []u8) !usize {
        const available = self.bytes.len - self.offset;
        const take = @min(available, output.len);
        @memcpy(output[0..take], self.bytes[self.offset..][0..take]);
        self.offset += take;
        return take;
    }

    fn writeAll(self: *@This(), bytes: []const u8) !void {
        @memcpy(self.written[self.written_len..][0..bytes.len], bytes);
        self.written_len += bytes.len;
    }
};
