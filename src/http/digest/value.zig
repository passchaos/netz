//! Fixed-storage digest values and transactional Structured Field emission.
const std = @import("std");
const types = @import("types.zig");

pub const max_value_bytes = 154;

pub const Set = struct {
    sha256: ?[32]u8 = null,
    sha512: ?[64]u8 = null,

    pub fn encodedLen(self: Set) usize {
        var length: usize = 0;
        if (self.sha256 != null) length += 54;
        if (self.sha512 != null) length += 98;
        if (self.sha256 != null and self.sha512 != null) length += 2;
        return length;
    }

    /// No output byte changes when capacity is insufficient. An empty Set
    /// serializes the valid empty Dictionary.
    pub fn writeInto(self: Set, output: []u8) types.Error![]u8 {
        const length = self.encodedLen();
        if (output.len < length) return error.BufferTooShort;
        var offset: usize = 0;
        if (self.sha256) |bytes| write(output, &offset, "sha-256", &bytes);
        if (self.sha512) |bytes| write(output, &offset, "sha-512", &bytes);
        std.debug.assert(offset == length);
        return output[0..length];
    }
};

fn write(output: []u8, offset: *usize, name: []const u8, bytes: []const u8) void {
    if (offset.* != 0) {
        @memcpy(output[offset.*..][0..2], ", ");
        offset.* += 2;
    }
    @memcpy(output[offset.*..][0..name.len], name);
    offset.* += name.len;
    @memcpy(output[offset.*..][0..2], "=:");
    offset.* += 2;
    const encoded_len = std.base64.standard.Encoder.calcSize(bytes.len);
    _ = std.base64.standard.Encoder.encode(output[offset.*..][0..encoded_len], bytes);
    offset.* += encoded_len;
    output[offset.*] = ':';
    offset.* += 1;
}
