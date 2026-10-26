//! Bounded schema-free protobuf reader shared by transport metadata codecs.
const std = @import("std");
pub const Error = error{ InvalidFieldNumber, InvalidUtf8, MalformedMessage, TruncatedMessage, VarintOverflow };

pub const Field = struct { number: u32, wire_type: u3 };

pub const Reader = struct {
    bytes: []const u8,
    cursor: usize = 0,

    pub fn next(self: *Reader) Error!?Field {
        if (self.cursor == self.bytes.len) return null;
        const key = try self.varint();
        const number = key >> 3;
        if (number == 0 or number > 0x1fffffff) {
            return error.InvalidFieldNumber;
        }
        return .{ .number = @intCast(number), .wire_type = @intCast(key & 7) };
    }

    pub fn varint(self: *Reader) Error!u64 {
        var value: u64 = 0;
        var shift: u6 = 0;
        for (0..10) |index| {
            if (self.cursor == self.bytes.len) return error.TruncatedMessage;
            const byte = self.bytes[self.cursor];
            self.cursor += 1;
            if (index == 9 and byte > 1) return error.VarintOverflow;
            value |= @as(u64, byte & 0x7f) << shift;
            if (byte & 0x80 == 0) return value;
            if (index != 9) shift += 7;
        }
        return error.VarintOverflow;
    }

    pub fn bytesValue(self: *Reader) Error![]const u8 {
        const raw_len = try self.varint();
        if (raw_len > std.math.maxInt(usize)) return error.TruncatedMessage;
        const len: usize = @intCast(raw_len);
        if (len > self.bytes.len - self.cursor) return error.TruncatedMessage;
        const value = self.bytes[self.cursor..][0..len];
        self.cursor += len;
        return value;
    }

    pub fn string(self: *Reader) Error![]const u8 {
        const value = try self.bytesValue();
        if (!std.unicode.utf8ValidateSlice(value)) return error.InvalidUtf8;
        return value;
    }

    pub fn skip(self: *Reader, field: Field) Error!void {
        return self.skipValue(field.number, field.wire_type, 0);
    }

    fn skipValue(
        self: *Reader,
        field_number: u32,
        wire_type: u3,
        depth: u8,
    ) Error!void {
        switch (wire_type) {
            0 => _ = try self.varint(),
            1 => try self.skipBytes(8),
            2 => _ = try self.bytesValue(),
            3 => {
                if (depth == 100) return error.MalformedMessage;
                while (try self.next()) |nested| {
                    if (nested.wire_type == 4) {
                        if (nested.number != field_number) {
                            return error.MalformedMessage;
                        }
                        return;
                    }
                    try self.skipValue(
                        nested.number,
                        nested.wire_type,
                        depth + 1,
                    );
                }
                return error.TruncatedMessage;
            },
            4, 6, 7 => return error.MalformedMessage,
            5 => try self.skipBytes(4),
        }
    }

    fn skipBytes(self: *Reader, len: usize) Error!void {
        if (len > self.bytes.len - self.cursor) {
            return error.TruncatedMessage;
        }
        self.cursor += len;
    }
};
