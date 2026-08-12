const std = @import("std");
const vail = @import("vail");

pub const token_len: usize = 16;
pub const static_key_len: usize = 16;
pub const min_datagram_len: usize = token_len + 5;

pub const Error = error{
    InvalidLength,
    InvalidHeaderForm,
} || std.Io.RandomSecureError || std.mem.Allocator.Error;

pub fn tokenForConnectionId(static_key: [static_key_len]u8, connection_id: []const u8) [token_len]u8 {
    const mac = vail.crypto.mac.authenticate(
        &static_key,
        "netz/quic/stateless-reset/v1",
        &.{connection_id},
    );
    return mac[0..token_len].*;
}

pub fn tokenCandidate(datagram: []const u8) ?[token_len]u8 {
    if (datagram.len < min_datagram_len) return null;
    var token: [token_len]u8 = undefined;
    @memcpy(&token, datagram[datagram.len - token_len ..]);
    return token;
}

pub fn matches(datagram: []const u8, expected_token: [token_len]u8) bool {
    if (datagram.len < min_datagram_len) return false;
    return matchesTokenSlice(
        datagram[datagram.len - token_len ..],
        expected_token,
    );
}

pub fn matchesToken(
    candidate: [token_len]u8,
    expected_token: [token_len]u8,
) bool {
    return vail.crypto.mac.verifyTruncated(
        token_len,
        candidate,
        expected_token,
    );
}

pub fn matchesTokenSlice(
    candidate: []const u8,
    expected_token: [token_len]u8,
) bool {
    if (candidate.len != token_len) return false;
    return vail.crypto.mac.verifyTruncated(
        token_len,
        candidate[0..token_len].*,
        expected_token,
    );
}

pub fn validPrefix(prefix: []const u8) bool {
    return prefix.len != 0 and (prefix[0] & 0xc0) == 0x40;
}

pub fn encode(list: *std.ArrayList(u8), allocator: std.mem.Allocator, unpredictable_prefix: []const u8, token: [token_len]u8) Error!void {
    if (unpredictable_prefix.len < min_datagram_len - token_len) return error.InvalidLength;
    if (!validPrefix(unpredictable_prefix)) return error.InvalidHeaderForm;
    try list.ensureUnusedCapacity(allocator, unpredictable_prefix.len + token_len);
    list.appendSliceAssumeCapacity(unpredictable_prefix);
    list.appendSliceAssumeCapacity(&token);
}

pub fn encodeForConnectionId(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    io: std.Io,
    packet_len: usize,
    static_key: [static_key_len]u8,
    connection_id: []const u8,
) Error!void {
    if (packet_len < min_datagram_len) return error.InvalidLength;
    const prefix_len = packet_len - token_len;
    const start = list.items.len;
    try list.resize(allocator, start + packet_len);
    errdefer list.shrinkRetainingCapacity(start);

    const prefix = list.items[start..][0..prefix_len];
    try std.Io.randomSecure(io, prefix);
    prefix[0] = (prefix[0] & 0x3f) | 0x40;
    const token = tokenForConnectionId(static_key, connection_id);
    @memcpy(list.items[start + prefix_len ..][0..token_len], &token);
}

test "QUIC stateless reset token derives from static key and connection ID" {
    const key = [_]u8{0x42} ** static_key_len;
    const cid = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const other_cid = [_]u8{ 0x01, 0x02, 0x03, 0x05 };

    const token = tokenForConnectionId(key, &cid);
    try std.testing.expectEqual(token, tokenForConnectionId(key, &cid));
    try std.testing.expect(!std.mem.eql(u8, &token, &tokenForConnectionId(key, &other_cid)));
}

test "QUIC stateless reset encodes and matches trailing token" {
    const allocator = std.testing.allocator;
    const token = [_]u8{0xa5} ** token_len;
    var datagram: std.ArrayList(u8) = .empty;
    defer datagram.deinit(allocator);
    try encode(&datagram, allocator, &.{ 0x40, 1, 2, 3, 4 }, token);

    try std.testing.expect(datagram.items.len == min_datagram_len);
    try std.testing.expect(matches(datagram.items, token));
    try std.testing.expect(matchesToken(tokenCandidate(datagram.items).?, token));
    try std.testing.expect(matchesTokenSlice(datagram.items[datagram.items.len - token_len ..], token));
    try std.testing.expect(!matches(datagram.items, [_]u8{0x5a} ** token_len));
    try std.testing.expect(!matchesTokenSlice(datagram.items[datagram.items.len - token_len + 1 ..], token));
    try std.testing.expectEqual(token, tokenCandidate(datagram.items).?);
}

test "QUIC stateless reset encodes random packet from static key and CID" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const key = [_]u8{0x31} ** static_key_len;
    const cid = [_]u8{ 0x41, 0x42, 0x43, 0x44 };
    const token = tokenForConnectionId(key, &cid);
    var datagram: std.ArrayList(u8) = .empty;
    defer datagram.deinit(allocator);

    try encodeForConnectionId(&datagram, allocator, io, 64, key, &cid);
    try std.testing.expectEqual(@as(usize, 64), datagram.items.len);
    try std.testing.expect(validPrefix(datagram.items));
    try std.testing.expect(matches(datagram.items, token));
    try std.testing.expectError(error.InvalidLength, encodeForConnectionId(&datagram, allocator, io, min_datagram_len - 1, key, &cid));
}

test "QUIC stateless reset validates minimum size and short header prefix" {
    const allocator = std.testing.allocator;
    var datagram: std.ArrayList(u8) = .empty;
    defer datagram.deinit(allocator);
    try std.testing.expectError(error.InvalidLength, encode(&datagram, allocator, &.{ 0x40, 1 }, [_]u8{0} ** token_len));
    try std.testing.expectError(error.InvalidHeaderForm, encode(&datagram, allocator, &.{ 0xc0, 1, 2, 3, 4 }, [_]u8{0} ** token_len));
    try std.testing.expect(tokenCandidate(&.{ 0x40, 1, 2 }) == null);
}
