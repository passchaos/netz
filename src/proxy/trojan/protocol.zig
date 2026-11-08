//! Trojan password proof and command constants.

const std = @import("std");

const codec = @import("../socks/codec.zig");

pub const password_hex_len: usize = 56;
pub const max_password_line_len: usize = 128;

pub const PasswordMode = enum { hashed, raw };

pub const Command = enum(u8) {
    connect = 0x01,
    udp_associate = 0x03,
};

pub const ProtocolError = error{
    InvalidPasswordLine,
    UnsupportedCommand,
};

/// Compute `hex(SHA-224(password))` used by the Trojan request line.
pub fn passwordHex(password: []const u8, output: *[password_hex_len]u8) void {
    var digest: [28]u8 = undefined;
    std.crypto.hash.sha2.Sha224.hash(password, &digest, .{});
    const encoded = std.fmt.bytesToHex(digest, .lower);
    output.* = encoded;
}

pub fn verifyPasswordLine(
    password: []const u8,
    mode: PasswordMode,
    line: []const u8,
) bool {
    return switch (mode) {
        .raw => timingSafeEql(line, password),
        .hashed => blk: {
            var expected: [password_hex_len]u8 = undefined;
            passwordHex(password, &expected);
            break :blk timingSafeEql(line, &expected);
        },
    };
}

/// Build one Trojan UDP packet: address, 16-bit payload length, payload.
pub fn buildUdpPacket(
    allocator: std.mem.Allocator,
    address: codec.Address,
    payload: []const u8,
) ![]u8 {
    if (payload.len > std.math.maxInt(u16)) return error.InvalidPacket;
    var address_storage: [1 + 1 + 255 + 2]u8 = undefined;
    const address_len = try codec.encodeSocks5Address(
        &address_storage,
        address,
    );
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    try output.appendSlice(allocator, address_storage[0..address_len]);
    try output.append(allocator, @intCast(payload.len >> 8));
    try output.append(allocator, @intCast(payload.len & 0xff));
    try output.appendSlice(allocator, payload);
    return output.toOwnedSlice(allocator);
}

pub fn commandFromByte(value: u8) ProtocolError!Command {
    return switch (value) {
        0x01 => .connect,
        0x03 => .udp_associate,
        else => error.UnsupportedCommand,
    };
}

fn timingSafeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var difference: u8 = 0;
    for (a, b) |lhs, rhs| difference |= lhs ^ rhs;
    return difference == 0;
}

test "Trojan password hashes match SHA-224 reference vectors" {
    var output: [password_hex_len]u8 = undefined;
    passwordHex("password", &output);
    try std.testing.expectEqualStrings(
        "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01",
        &output,
    );
    passwordHex("trojan-secret", &output);
    try std.testing.expectEqualStrings(
        "7303ad4bbf936a4e63dd6af3216c0043de0e5679dd23227326837dbc",
        &output,
    );
}

test "Trojan password verification rejects wrong lengths and values" {
    try std.testing.expect(verifyPasswordLine("password", .hashed, "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"));
    try std.testing.expect(!verifyPasswordLine("password", .hashed, "00000000000000000000000000000000000000000000000000000000"));
    try std.testing.expect(!verifyPasswordLine("password", .hashed, "short"));
    try std.testing.expect(verifyPasswordLine("password", .raw, "password"));
    try std.testing.expect(!verifyPasswordLine("password", .raw, "passwore"));
}

test "Trojan commands are bounded to CONNECT and UDP ASSOCIATE" {
    try std.testing.expectEqual(Command.connect, try commandFromByte(0x01));
    try std.testing.expectEqual(Command.udp_associate, try commandFromByte(0x03));
    try std.testing.expectError(error.UnsupportedCommand, commandFromByte(0x02));
    try std.testing.expectError(error.UnsupportedCommand, commandFromByte(0xff));
}
