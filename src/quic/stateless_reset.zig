const std = @import("std");
const vail = @import("vail");

pub const token_len: usize = 16;
pub const static_key_len: usize = 16;
pub const min_datagram_len: usize = token_len + 5;
/// Bound endpoint-generated resets to the minimum QUIC Initial datagram size.
/// A reset only needs to be unpredictable and smaller than its trigger; a
/// larger response would consume stack and network capacity without adding
/// protocol value.
pub const max_response_len: usize = 1200;

pub const Error = error{
    BufferTooShort,
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
    const packet_len = try encodedLen(unpredictable_prefix);
    const start = list.items.len;
    try list.ensureUnusedCapacity(allocator, packet_len);
    list.items.len += packet_len;
    _ = encodeInto(list.items[start..][0..packet_len], unpredictable_prefix, token) catch unreachable;
}

pub fn encodedLen(unpredictable_prefix: []const u8) Error!usize {
    if (unpredictable_prefix.len < min_datagram_len - token_len) {
        return error.InvalidLength;
    }
    if (!validPrefix(unpredictable_prefix)) return error.InvalidHeaderForm;
    return std.math.add(usize, unpredictable_prefix.len, token_len) catch
        error.InvalidLength;
}

/// Encode a stateless reset into caller-owned storage. Validation and sizing
/// finish before any output is changed, allowing callers to reuse the buffer
/// after a rejected prefix or short destination.
pub fn encodeInto(
    storage: []u8,
    unpredictable_prefix: []const u8,
    token: [token_len]u8,
) Error![]const u8 {
    const packet_len = try encodedLen(unpredictable_prefix);
    if (storage.len < packet_len) return error.BufferTooShort;
    @memcpy(storage[0..unpredictable_prefix.len], unpredictable_prefix);
    @memcpy(storage[unpredictable_prefix.len..][0..token_len], &token);
    return storage[0..packet_len];
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
    const start = list.items.len;
    try list.resize(allocator, start + packet_len);
    errdefer list.shrinkRetainingCapacity(start);
    _ = try encodeForConnectionIdInto(
        list.items[start..][0..packet_len],
        io,
        packet_len,
        static_key,
        connection_id,
    );
}

/// Generate a complete reset directly in caller-owned storage. The output is
/// randomized in place and the derived token overwrites its final 16 bytes.
pub fn encodeForConnectionIdInto(
    storage: []u8,
    io: std.Io,
    packet_len: usize,
    static_key: [static_key_len]u8,
    connection_id: []const u8,
) Error![]const u8 {
    if (packet_len < min_datagram_len) return error.InvalidLength;
    if (storage.len < packet_len) return error.BufferTooShort;
    const prefix_len = packet_len - token_len;
    const output = storage[0..packet_len];
    const prefix = output[0..prefix_len];
    try std.Io.randomSecure(io, prefix);
    prefix[0] = (prefix[0] & 0x3f) | 0x40;
    const token = tokenForConnectionId(static_key, connection_id);
    @memcpy(output[prefix_len..][0..token_len], &token);
    return output;
}

/// Choose a bounded reset size for an unknown-CID short-header datagram.
/// Returning null means a response would be invalid or could form a reset loop.
pub fn responseLen(triggering_datagram: []const u8, endpoint_max: usize) ?usize {
    if (!validPrefix(triggering_datagram)) return null;
    if (triggering_datagram.len <= min_datagram_len) return null;
    const len = @min(
        triggering_datagram.len - 1,
        endpoint_max,
        max_response_len,
    );
    if (len < min_datagram_len) return null;
    return len;
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

    var direct_storage: [min_datagram_len]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        datagram.items,
        try encodeInto(
            &direct_storage,
            &.{ 0x40, 1, 2, 3, 4 },
            token,
        ),
    );
    var short_storage: [min_datagram_len - 1]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooShort,
        encodeInto(
            &short_storage,
            &.{ 0x40, 1, 2, 3, 4 },
            token,
        ),
    );
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

    var direct: [64]u8 = undefined;
    const direct_packet = try encodeForConnectionIdInto(
        &direct,
        io,
        direct.len,
        key,
        &cid,
    );
    try std.testing.expectEqual(direct.len, direct_packet.len);
    try std.testing.expect(validPrefix(direct_packet));
    try std.testing.expect(matches(direct_packet, token));
    try std.testing.expect(!std.mem.eql(u8, datagram.items, direct_packet));

    var short_storage: [min_datagram_len - 1]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooShort,
        encodeForConnectionIdInto(
            &short_storage,
            io,
            min_datagram_len,
            key,
            &cid,
        ),
    );
    try std.testing.expectError(error.InvalidLength, encodeForConnectionId(&datagram, allocator, io, min_datagram_len - 1, key, &cid));
}

test "QUIC stateless reset validates minimum size and short header prefix" {
    const allocator = std.testing.allocator;
    var datagram: std.ArrayList(u8) = .empty;
    defer datagram.deinit(allocator);
    try std.testing.expectError(error.InvalidLength, encode(&datagram, allocator, &.{ 0x40, 1 }, [_]u8{0} ** token_len));
    try std.testing.expectError(error.InvalidHeaderForm, encode(&datagram, allocator, &.{ 0xc0, 1, 2, 3, 4 }, [_]u8{0} ** token_len));
    try std.testing.expect(tokenCandidate(&.{ 0x40, 1, 2 }) == null);

    const trigger = [_]u8{0x40} ** 64;
    try std.testing.expectEqual(@as(?usize, 63), responseLen(&trigger, 1500));
    try std.testing.expectEqual(@as(?usize, 32), responseLen(&trigger, 32));
    try std.testing.expectEqual(
        @as(?usize, max_response_len),
        responseLen(&([_]u8{0x40} ** 1500), 1500),
    );
    try std.testing.expectEqual(
        @as(?usize, null),
        responseLen(&([_]u8{0x40} ** min_datagram_len), 1500),
    );
    try std.testing.expectEqual(
        @as(?usize, null),
        responseLen(&trigger, min_datagram_len - 1),
    );
    var long_header_trigger = trigger;
    long_header_trigger[0] = 0xc0;
    try std.testing.expectEqual(
        @as(?usize, null),
        responseLen(&long_header_trigger, 1500),
    );
}
