//! WebTransport Capsule Protocol wire encoding and decoding.

const std = @import("std");
const wire = @import("../internal/wire.zig");
const quic = @import("../quic/mod.zig");
const Error = @import("mod.zig").Error;

pub const CapsuleType = struct {
    pub const datagram: u64 = 0x00;
    pub const close_webtransport_session: u64 = 0x2843;
    pub const drain_webtransport_session: u64 = 0x78ae;
    pub const max_data: u64 = 0x190b4d3d;
    pub const max_streams_bidi: u64 = 0x190b4d3f;
    pub const max_streams_uni: u64 = 0x190b4d40;
    pub const data_blocked: u64 = 0x190b4d41;
    pub const streams_blocked_bidi: u64 = 0x190b4d43;
    pub const streams_blocked_uni: u64 = 0x190b4d44;
};

pub const max_close_reason: usize = 1024;

pub const Capsule = union(enum) {
    datagram: []const u8,
    close_session: CloseSession,
    drain_session: void,
    max_data: u64,
    max_streams_bidi: u64,
    max_streams_uni: u64,
    data_blocked: u64,
    streams_blocked_bidi: u64,
    streams_blocked_uni: u64,
    unknown: struct { capsule_type: u64, payload: []const u8 },

    pub const CloseSession = struct {
        code: u32,
        reason: []const u8,
    };

    const WireLayout = struct {
        capsule_type: u64,
        value_len: usize,
        type_len: u8,
        length_len: u8,
        total_len: usize,
    };

    fn wireLayout(self: Capsule) Error!WireLayout {
        const capsule_type: u64, const value_len: usize = switch (self) {
            .datagram => |payload| .{ CapsuleType.datagram, payload.len },
            .close_session => |close| blk: {
                if (close.reason.len > max_close_reason or
                    !std.unicode.utf8ValidateSlice(close.reason))
                {
                    return error.InvalidCapsule;
                }
                break :blk .{
                    CapsuleType.close_webtransport_session,
                    std.math.add(usize, 4, close.reason.len) catch
                        return error.IntegerOverflow,
                };
            },
            .drain_session => .{ CapsuleType.drain_webtransport_session, 0 },
            .max_data,
            .max_streams_bidi,
            .max_streams_uni,
            .data_blocked,
            .streams_blocked_bidi,
            .streams_blocked_uni,
            => |value| .{ self.flowType().?, try quic.varint.length(value) },
            .unknown => |unknown| .{
                unknown.capsule_type,
                unknown.payload.len,
            },
        };
        const value_len_u64 = std.math.cast(u64, value_len) orelse
            return error.IntegerOverflow;
        const type_len = try quic.varint.length(capsule_type);
        const length_len = try quic.varint.length(value_len_u64);
        const prefix_len = std.math.add(
            usize,
            type_len,
            length_len,
        ) catch return error.IntegerOverflow;
        return .{
            .capsule_type = capsule_type,
            .value_len = value_len,
            .type_len = type_len,
            .length_len = length_len,
            .total_len = std.math.add(usize, prefix_len, value_len) catch
                return error.IntegerOverflow,
        };
    }

    pub fn parse(bytes: []const u8) Error!struct { capsule: Capsule, consumed: usize } {
        var cursor = wire.Cursor.init(bytes);
        const capsule_type = try quic.varint.decode(&cursor);
        const len = try quic.varint.decode(&cursor);
        const payload_len = std.math.cast(usize, len) orelse return error.IntegerOverflow;
        const payload = try cursor.readSlice(payload_len);
        const capsule: Capsule = switch (capsule_type) {
            CapsuleType.datagram => .{ .datagram = payload },
            CapsuleType.close_webtransport_session => blk: {
                if (payload.len < 4 or
                    payload.len > 4 + max_close_reason)
                {
                    return error.InvalidCapsule;
                }
                const code = std.mem.readInt(u32, payload[0..4], .big);
                if (!std.unicode.utf8ValidateSlice(payload[4..])) return error.InvalidCapsule;
                break :blk .{ .close_session = .{ .code = code, .reason = payload[4..] } };
            },
            CapsuleType.drain_webtransport_session => blk: {
                if (payload.len != 0) return error.InvalidCapsule;
                break :blk .{ .drain_session = {} };
            },
            CapsuleType.max_data => .{ .max_data = try parseFlowValue(payload) },
            CapsuleType.max_streams_bidi => .{ .max_streams_bidi = try parseFlowValue(payload) },
            CapsuleType.max_streams_uni => .{ .max_streams_uni = try parseFlowValue(payload) },
            CapsuleType.data_blocked => .{ .data_blocked = try parseFlowValue(payload) },
            CapsuleType.streams_blocked_bidi => .{ .streams_blocked_bidi = try parseFlowValue(payload) },
            CapsuleType.streams_blocked_uni => .{ .streams_blocked_uni = try parseFlowValue(payload) },
            else => .{ .unknown = .{ .capsule_type = capsule_type, .payload = payload } },
        };
        return .{ .capsule = capsule, .consumed = cursor.pos };
    }

    pub fn write(self: Capsule, list: *std.ArrayList(u8), allocator: std.mem.Allocator) !void {
        const layout = try self.wireLayout();
        try list.ensureUnusedCapacity(allocator, layout.total_len);
        quic.varint.encodeWithLenAssumeCapacity(
            list,
            layout.capsule_type,
            layout.type_len,
        );
        quic.varint.encodeWithLenAssumeCapacity(
            list,
            layout.value_len,
            layout.length_len,
        );
        switch (self) {
            .datagram => |payload| {
                list.appendSliceAssumeCapacity(payload);
            },
            .close_session => |close| {
                const code_start = list.items.len;
                list.items.len += 4;
                std.mem.writeInt(
                    u32,
                    list.items[code_start..][0..4],
                    close.code,
                    .big,
                );
                list.appendSliceAssumeCapacity(close.reason);
            },
            .drain_session => {},
            .max_data,
            .max_streams_bidi,
            .max_streams_uni,
            .data_blocked,
            .streams_blocked_bidi,
            .streams_blocked_uni,
            => |value| quic.varint.encodeWithLenAssumeCapacity(list, value, @intCast(layout.value_len)),
            .unknown => |unknown| {
                list.appendSliceAssumeCapacity(unknown.payload);
            },
        }
    }

    pub fn encodedLen(self: Capsule) Error!usize {
        return (try self.wireLayout()).total_len;
    }

    /// Validate the whole capsule before writing any caller-owned byte.
    pub fn writeInto(self: Capsule, output: []u8) Error![]u8 {
        const layout = try self.wireLayout();
        if (output.len < layout.total_len) return error.BufferTooShort;
        const encoded_type = try quic.varint.encodeInto(output, layout.capsule_type);
        const encoded_length = try quic.varint.encodeInto(output[encoded_type.len..], layout.value_len);
        const prefix_len = encoded_type.len + encoded_length.len;
        const payload = output[prefix_len..layout.total_len];
        switch (self) {
            .datagram => |bytes| @memcpy(payload, bytes),
            .unknown => |value| @memcpy(payload, value.payload),
            .close_session => |close| {
                std.mem.writeInt(u32, payload[0..4], close.code, .big);
                @memcpy(payload[4..], close.reason);
            },
            .drain_session => {},
            .max_data,
            .max_streams_bidi,
            .max_streams_uni,
            .data_blocked,
            .streams_blocked_bidi,
            .streams_blocked_uni,
            => |value| _ = try quic.varint.encodeInto(payload, value),
        }
        return output[0..layout.total_len];
    }

    pub fn flowType(self: Capsule) ?u64 {
        return switch (self) {
            .max_data => CapsuleType.max_data,
            .max_streams_bidi => CapsuleType.max_streams_bidi,
            .max_streams_uni => CapsuleType.max_streams_uni,
            .data_blocked => CapsuleType.data_blocked,
            .streams_blocked_bidi => CapsuleType.streams_blocked_bidi,
            .streams_blocked_uni => CapsuleType.streams_blocked_uni,
            else => null,
        };
    }
};

fn parseFlowValue(payload: []const u8) Error!u64 {
    var cursor = wire.Cursor.init(payload);
    const value = quic.varint.decode(&cursor) catch return error.InvalidCapsule;
    if (cursor.pos != payload.len) return error.InvalidCapsule;
    return value;
}

test {
    _ = @import("capsule/tests.zig");
}
