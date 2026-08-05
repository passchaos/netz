const std = @import("std");

pub const token_len: usize = 16;
pub const min_datagram_len: usize = token_len + 5;

pub const Error = error{
    InvalidLength,
    InvalidHeaderForm,
} || std.mem.Allocator.Error;

pub fn tokenCandidate(datagram: []const u8) ?[token_len]u8 {
    if (datagram.len < min_datagram_len) return null;
    var token: [token_len]u8 = undefined;
    @memcpy(&token, datagram[datagram.len - token_len ..]);
    return token;
}

pub fn matches(datagram: []const u8, expected_token: [token_len]u8) bool {
    const candidate = tokenCandidate(datagram) orelse return false;
    return std.crypto.timing_safe.eql([token_len]u8, candidate, expected_token);
}

pub fn validPrefix(prefix: []const u8) bool {
    return prefix.len != 0 and (prefix[0] & 0xc0) == 0x40;
}

pub fn encode(list: *std.ArrayList(u8), allocator: std.mem.Allocator, unpredictable_prefix: []const u8, token: [token_len]u8) Error!void {
    if (unpredictable_prefix.len < min_datagram_len - token_len) return error.InvalidLength;
    if (!validPrefix(unpredictable_prefix)) return error.InvalidHeaderForm;
    try list.appendSlice(allocator, unpredictable_prefix);
    try list.appendSlice(allocator, &token);
}

test "QUIC stateless reset encodes and matches trailing token" {
    const allocator = std.testing.allocator;
    const token = [_]u8{0xa5} ** token_len;
    var datagram: std.ArrayList(u8) = .empty;
    defer datagram.deinit(allocator);
    try encode(&datagram, allocator, &.{ 0x40, 1, 2, 3, 4 }, token);

    try std.testing.expect(datagram.items.len == min_datagram_len);
    try std.testing.expect(matches(datagram.items, token));
    try std.testing.expect(!matches(datagram.items, [_]u8{0x5a} ** token_len));
    try std.testing.expectEqual(token, tokenCandidate(datagram.items).?);
}

test "QUIC stateless reset validates minimum size and short header prefix" {
    const allocator = std.testing.allocator;
    var datagram: std.ArrayList(u8) = .empty;
    defer datagram.deinit(allocator);
    try std.testing.expectError(error.InvalidLength, encode(&datagram, allocator, &.{ 0x40, 1 }, [_]u8{0} ** token_len));
    try std.testing.expectError(error.InvalidHeaderForm, encode(&datagram, allocator, &.{ 0xc0, 1, 2, 3, 4 }, [_]u8{0} ** token_len));
    try std.testing.expect(tokenCandidate(&.{ 0x40, 1, 2 }) == null);
}
