//! gRPC binary metadata wire encoding.
//!
//! HTTP/2 transports carry `-bin` values as standard Base64. Senders omit
//! padding; receivers accept padded or unpadded values and split comma-joined
//! fields into distinct application metadata values.

const std = @import("std");
const http2 = @import("../http2/mod.zig");

pub const Error = std.mem.Allocator.Error || error{
    BufferTooSmall,
    InvalidBinaryMetadata,
    InvalidMetadata,
    MetadataTooLarge,
};

pub const BinaryMetadata = struct {
    name: []const u8,
    /// Raw application bytes. `encodeFieldsAlloc` performs Base64 encoding.
    value: []const u8,
};

pub fn isBinaryName(name: []const u8) bool {
    return name.len >= 4 and
        std.mem.endsWith(u8, name, "-bin");
}

pub fn validateBinaryName(name: []const u8) Error!void {
    if (!isBinaryName(name)) return error.InvalidMetadata;
    for (name) |byte| {
        if ((byte >= '0' and byte <= '9') or
            (byte >= 'a' and byte <= 'z') or
            byte == '_' or byte == '-' or byte == '.')
        {
            continue;
        }
        return error.InvalidMetadata;
    }
}

pub const EncodedFields = struct {
    allocator: std.mem.Allocator,
    fields: []http2.Hpack.HeaderField,
    values: []u8,

    pub fn deinit(self: *EncodedFields) void {
        self.allocator.free(self.values);
        self.allocator.free(self.fields);
        self.* = undefined;
    }
};

/// Encode raw binary metadata into HTTP/2 header fields.
///
/// Header names continue borrowing the input entries. Field values borrow the
/// returned `values` allocation and remain valid until `deinit`.
pub fn encodeFieldsAlloc(
    allocator: std.mem.Allocator,
    metadata: []const BinaryMetadata,
) Error!EncodedFields {
    var values_len: usize = 0;
    for (metadata) |entry| {
        try validateBinaryName(entry.name);
        values_len = std.math.add(
            usize,
            values_len,
            std.base64.standard_no_pad.Encoder.calcSize(
                entry.value.len,
            ),
        ) catch return error.MetadataTooLarge;
    }
    const fields = try allocator.alloc(
        http2.Hpack.HeaderField,
        metadata.len,
    );
    errdefer allocator.free(fields);
    const values = try allocator.alloc(u8, values_len);
    errdefer allocator.free(values);

    var cursor: usize = 0;
    for (metadata, 0..) |entry, index| {
        const encoded_len =
            std.base64.standard_no_pad.Encoder.calcSize(
                entry.value.len,
            );
        const encoded = std.base64.standard_no_pad.Encoder.encode(
            values[cursor..][0..encoded_len],
            entry.value,
        );
        fields[index] = .{
            .name = entry.name,
            .value = encoded,
            // Binary metadata is frequently unique and may contain sensitive
            // opaque data; match gRPC Core's conservative non-indexing path.
            .never_index = true,
        };
        cursor += encoded_len;
    }
    std.debug.assert(cursor == values.len);
    return .{
        .allocator = allocator,
        .fields = fields,
        .values = values,
    };
}

pub fn decodedUpperBound(raw: []const u8) Error!usize {
    if (raw.len == 0) return 0;
    var total: usize = 0;
    var parts = std.mem.splitScalar(u8, raw, ',');
    while (parts.next()) |part_raw| {
        const part = std.mem.trim(u8, part_raw, " \t");
        const decoded_len = decodedSegmentLen(part) catch
            return error.InvalidBinaryMetadata;
        total = std.math.add(usize, total, decoded_len) catch
            return error.MetadataTooLarge;
    }
    return total;
}

pub fn decodedFieldsUpperBound(
    fields: []const http2.Hpack.HeaderField,
    name: []const u8,
) Error!usize {
    try validateBinaryName(name);
    var total: usize = 0;
    for (fields) |field| {
        if (!std.mem.eql(u8, field.name, name)) continue;
        total = std.math.add(
            usize,
            total,
            try decodedUpperBound(field.value),
        ) catch return error.MetadataTooLarge;
    }
    return total;
}

pub const DecodedValue = struct {
    /// Borrowed from the iterator's caller-provided scratch buffer.
    value: []const u8,
};

pub const ValueIterator = struct {
    fields: []const http2.Hpack.HeaderField,
    name: []const u8,
    scratch: []u8,
    field_index: usize = 0,
    raw: ?[]const u8 = null,
    raw_offset: usize = 0,
    scratch_offset: usize = 0,

    pub fn init(
        fields: []const http2.Hpack.HeaderField,
        name: []const u8,
        scratch: []u8,
    ) Error!ValueIterator {
        try validateBinaryName(name);
        return .{
            .fields = fields,
            .name = name,
            .scratch = scratch,
        };
    }

    pub fn next(self: *ValueIterator) Error!?DecodedValue {
        while (true) {
            if (self.raw == null) {
                while (self.field_index < self.fields.len) {
                    const field = self.fields[self.field_index];
                    self.field_index += 1;
                    if (!std.mem.eql(u8, field.name, self.name)) continue;
                    self.raw = field.value;
                    self.raw_offset = 0;
                    break;
                }
                if (self.raw == null) return null;
            }

            const raw = self.raw.?;
            if (raw.len == 0 and self.raw_offset == 0) {
                self.raw = null;
                return .{
                    .value = self.scratch[self.scratch_offset..self.scratch_offset],
                };
            }
            const remaining = raw[self.raw_offset..];
            const comma = std.mem.indexOfScalar(u8, remaining, ',');
            const raw_part = if (comma) |index|
                remaining[0..index]
            else
                remaining;
            const part = std.mem.trim(u8, raw_part, " \t");

            const decoded_len = decodedSegmentLen(part) catch
                return error.InvalidBinaryMetadata;
            if (decoded_len >
                self.scratch.len - self.scratch_offset)
            {
                // Do not consume the value. The caller may replace `scratch`
                // with a larger buffer and retry this same iterator position.
                return error.BufferTooSmall;
            }
            const output = self.scratch[self.scratch_offset..][0..decoded_len];
            decodeSegment(output, part) catch
                return error.InvalidBinaryMetadata;
            self.raw_offset += raw_part.len +
                @intFromBool(comma != null);
            if (comma == null) self.raw = null;
            self.scratch_offset += decoded_len;
            return .{ .value = output };
        }
    }
};

fn decodedSegmentLen(segment: []const u8) std.base64.Error!usize {
    if (std.mem.endsWith(u8, segment, "=")) {
        return std.base64.standard.Decoder.calcSizeForSlice(
            segment,
        );
    }
    return std.base64.standard_no_pad.Decoder.calcSizeForSlice(
        segment,
    );
}

fn decodeSegment(
    out: []u8,
    segment: []const u8,
) std.base64.Error!void {
    if (std.mem.endsWith(u8, segment, "=")) {
        return std.base64.standard.Decoder.decode(out, segment);
    }
    return std.base64.standard_no_pad.Decoder.decode(out, segment);
}
