//! RFC 9297 HTTP Capsule Protocol TLV codec.
//!
//! Capsules are carried in HTTP/3 DATA frame payloads after a successful
//! Extended CONNECT negotiation.  The codec is intentionally independent from
//! the higher-level WebTransport capsule union so MASQUE/proxy users can parse,
//! skip, or forward unknown capsule types without allocating.

const std = @import("std");
const wire = @import("../internal/wire.zig");
const structured_field = @import("../internal/structured_field.zig");
const quic = @import("../quic/mod.zig");
const qpack = @import("qpack/mod.zig");

pub const Error = wire.Error || error{
    IntegerOverflow,
    InvalidFrame,
    InvalidHeader,
} || std.mem.Allocator.Error;

pub const CapsuleType = struct {
    pub const datagram: u64 = 0x00;
};

pub const header_name = "capsule-protocol";
pub const header_value_true = "?1";

pub const protocol_header: qpack.HeaderField = .{
    .name = header_name,
    .value = header_value_true,
};

pub fn protocolEnabled(headers: []const qpack.HeaderField) Error!bool {
    var found = false;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, header_name)) continue;
        if (found) return error.InvalidHeader;
        found = true;
        const enabled = structured_field.parseBooleanItem(header.value) catch
            return error.InvalidHeader;
        if (!enabled) return error.InvalidHeader;
    }
    return found;
}

pub fn appendProtocolHeader(
    out: []qpack.HeaderField,
    count: *usize,
) Error!void {
    if (count.* >= out.len) return error.InvalidFrame;
    out[count.*] = protocol_header;
    count.* += 1;
}

pub const Capsule = struct {
    capsule_type: u64,
    /// Borrowed view into the encoded capsule value.
    value: []const u8,

    pub fn isDatagram(self: Capsule) bool {
        return self.capsule_type == CapsuleType.datagram;
    }
};

pub const Parsed = struct {
    capsule: Capsule,
    consumed: usize,
};

/// Reserved capsule type pattern from RFC 9297 §4.7.
///
/// Receivers still need to be able to skip unknown/reserved capsule values; the
/// helper lets send paths or extension negotiators reject the greased values
/// when they are about to advertise or emit a concrete capsule type.
pub fn isReservedCapsuleType(capsule_type: u64) bool {
    return capsule_type >= 0x17 and (capsule_type - 0x17) % 0x29 == 0;
}

pub fn parse(bytes: []const u8) Error!Parsed {
    var cursor = wire.Cursor.init(bytes);
    const capsule_type = try quic.varint.decode(&cursor);
    const value_len = try quic.varint.decode(&cursor);
    const payload_len = std.math.cast(usize, value_len) orelse return error.IntegerOverflow;
    const value = try cursor.readSlice(payload_len);
    return .{
        .capsule = .{ .capsule_type = capsule_type, .value = value },
        .consumed = cursor.pos,
    };
}

pub fn encodedLen(capsule_type: u64, value_len: usize) Error!usize {
    const value_len_u64 = std.math.cast(u64, value_len) orelse return error.IntegerOverflow;
    const type_len = try quic.varint.length(capsule_type);
    const length_len = try quic.varint.length(value_len_u64);
    return std.math.add(
        usize,
        std.math.add(usize, type_len, length_len) catch return error.IntegerOverflow,
        value_len,
    ) catch return error.IntegerOverflow;
}

pub fn write(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    capsule_type: u64,
    value: []const u8,
) Error!void {
    const value_len = std.math.cast(u64, value.len) orelse return error.IntegerOverflow;
    if (capsule_type <= 63 and value_len <= 63) {
        try list.appendSlice(allocator, &.{ @intCast(capsule_type), @intCast(value_len) });
    } else {
        try quic.varint.encode(list, allocator, capsule_type);
        try quic.varint.encode(list, allocator, value_len);
    }
    try list.appendSlice(allocator, value);
}

/// Encode into caller-provided storage, avoiding the allocation required by the
/// ArrayList writer.  This is useful on hot CONNECT-stream paths where capsule
/// values are already buffered by the application.
pub fn writeInto(
    out: []u8,
    capsule_type: u64,
    value: []const u8,
) Error![]u8 {
    const total_len = try encodedLen(capsule_type, value.len);
    if (out.len < total_len) return error.BufferTooShort;

    var offset: usize = 0;
    const type_bytes = try quic.varint.encodeInto(out[offset..], capsule_type);
    offset += type_bytes.len;
    const value_len = std.math.cast(u64, value.len) orelse return error.IntegerOverflow;
    const length_bytes = try quic.varint.encodeInto(out[offset..], value_len);
    offset += length_bytes.len;
    std.mem.copyForwards(u8, out[offset..][0..value.len], value);
    offset += value.len;
    return out[0..offset];
}

pub fn writeDatagram(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    value: []const u8,
) Error!void {
    try write(list, allocator, CapsuleType.datagram, value);
}

pub fn writeDatagramInto(out: []u8, value: []const u8) Error![]u8 {
    return writeInto(out, CapsuleType.datagram, value);
}

/// Sequential parser for a CONNECT stream data buffer.
///
/// `next` returns `null` instead of consuming bytes when the remaining suffix
/// is incomplete.  Callers can keep `remainingSlice()` and append more DATA
/// bytes before retrying, while malformed complete prefixes still surface as
/// errors.
pub const Iterator = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn init(data: []const u8) Iterator {
        return .{ .data = data };
    }

    pub fn next(self: *Iterator) Error!?Capsule {
        if (self.pos >= self.data.len) return null;
        const parsed = parse(self.data[self.pos..]) catch |err| switch (err) {
            error.BufferTooShort => return null,
            else => return err,
        };
        self.pos += parsed.consumed;
        return parsed.capsule;
    }

    pub fn remaining(self: Iterator) usize {
        return self.data.len - self.pos;
    }

    pub fn remainingSlice(self: Iterator) []const u8 {
        return self.data[self.pos..];
    }
};

test "HTTP/3 capsule writes and parses generic DATAGRAM capsules" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try writeDatagram(&encoded, allocator, "hello capsule");
    try std.testing.expectEqualSlices(u8, &.{ CapsuleType.datagram, "hello capsule".len }, encoded.items[0..2]);
    const parsed = try parse(encoded.items);
    try std.testing.expectEqual(CapsuleType.datagram, parsed.capsule.capsule_type);
    try std.testing.expect(parsed.capsule.isDatagram());
    try std.testing.expectEqualStrings("hello capsule", parsed.capsule.value);
    try std.testing.expectEqual(encoded.items.len, parsed.consumed);

    encoded.clearRetainingCapacity();
    try write(&encoded, allocator, 0x1234, "");
    const empty = try parse(encoded.items);
    try std.testing.expectEqual(@as(u64, 0x1234), empty.capsule.capsule_type);
    try std.testing.expectEqual(@as(usize, 0), empty.capsule.value.len);
}

test "HTTP/3 capsule validates Capsule-Protocol header" {
    const enabled_headers = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = "Capsule-Protocol", .value = "?1; mode=webtransport" },
    };
    try std.testing.expect(try protocolEnabled(&enabled_headers));

    const absent_headers = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
    };
    try std.testing.expect(!(try protocolEnabled(&absent_headers)));

    const false_headers = [_]qpack.HeaderField{
        .{ .name = "capsule-protocol", .value = "?0" },
    };
    try std.testing.expectError(error.InvalidHeader, protocolEnabled(&false_headers));

    const duplicate_headers = [_]qpack.HeaderField{
        protocol_header,
        .{ .name = "Capsule-Protocol", .value = "?1" },
    };
    try std.testing.expectError(error.InvalidHeader, protocolEnabled(&duplicate_headers));

    var out: [2]qpack.HeaderField = undefined;
    var count: usize = 0;
    try appendProtocolHeader(&out, &count);
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqualStrings(header_name, out[0].name);
    try std.testing.expectEqualStrings(header_value_true, out[0].value);
}

test "HTTP/3 capsule supports caller-buffer encoding" {
    var out: [32]u8 = undefined;
    const written = try writeDatagramInto(&out, "abc");
    try std.testing.expectEqual(@as(usize, 5), written.len);
    const parsed = try parse(written);
    try std.testing.expectEqual(CapsuleType.datagram, parsed.capsule.capsule_type);
    try std.testing.expectEqualStrings("abc", parsed.capsule.value);

    var too_small: [4]u8 = undefined;
    try std.testing.expectError(error.BufferTooShort, writeDatagramInto(&too_small, "abc"));
}

test "HTTP/3 capsule iterator stops before incomplete suffix" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try writeDatagram(&encoded, allocator, "first");
    try write(&encoded, allocator, 0xff, "second");
    try encoded.append(allocator, 0x00); // Incomplete trailing capsule type.

    var iter = Iterator.init(encoded.items);
    const first = (try iter.next()).?;
    try std.testing.expectEqual(CapsuleType.datagram, first.capsule_type);
    try std.testing.expectEqualStrings("first", first.value);
    const second = (try iter.next()).?;
    try std.testing.expectEqual(@as(u64, 0xff), second.capsule_type);
    try std.testing.expectEqualStrings("second", second.value);
    try std.testing.expect((try iter.next()) == null);
    try std.testing.expectEqual(@as(usize, 1), iter.remaining());
    try std.testing.expectEqualSlices(u8, &.{0x00}, iter.remainingSlice());
}

test "HTTP/3 capsule rejects truncated values and detects reserved pattern" {
    try std.testing.expectError(error.BufferTooShort, parse(&.{}));
    try std.testing.expectError(error.BufferTooShort, parse(&.{0x00}));

    var truncated = [_]u8{ 0x00, 0x05, 'a', 'b' };
    try std.testing.expectError(error.BufferTooShort, parse(&truncated));

    try std.testing.expect(isReservedCapsuleType(0x17));
    try std.testing.expect(isReservedCapsuleType(0x40));
    try std.testing.expect(isReservedCapsuleType(0x69));
    try std.testing.expect(!isReservedCapsuleType(CapsuleType.datagram));
    try std.testing.expect(!isReservedCapsuleType(0x18));
}

test "HTTP/3 capsule handles large values" {
    var payload: [8000]u8 = undefined;
    @memset(&payload, 0xab);

    var encoded: [8010]u8 = undefined;
    const written = try writeDatagramInto(&encoded, &payload);
    const parsed = try parse(written);
    try std.testing.expectEqual(CapsuleType.datagram, parsed.capsule.capsule_type);
    try std.testing.expectEqual(@as(usize, 8000), parsed.capsule.value.len);
    try std.testing.expectEqual(@as(u8, 0xab), parsed.capsule.value[0]);
    try std.testing.expectEqual(@as(u8, 0xab), parsed.capsule.value[7999]);
}
