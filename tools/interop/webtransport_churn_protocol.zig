const std = @import("std");

pub const max_streams: usize = 256;
pub const result_magic = "NZWTRES2";
pub const reset_mask_bits: usize = max_streams;
pub const reset_mask_bytes: usize = reset_mask_bits / 8;
pub const ResetMask = std.meta.Int(.unsigned, reset_mask_bits);
pub const result_len: usize = 32 + reset_mask_bytes + 8;
const splitmix_increment: u64 = 0x9e37_79b9_7f4a_7c15;

/// Select a stable, non-periodic reset set while guaranteeing that every
/// valid churn shape contains both a reset and a normally finished stream.
pub fn shouldReset(seed: u64, stream_count: usize, stream_index: usize) bool {
    std.debug.assert(stream_count >= 2 and stream_count <= max_streams);
    std.debug.assert(stream_index < stream_count);
    if (stream_index == 0) return true;
    if (stream_index == 1) return false;

    var value = seed +% splitmix_increment *% (@as(u64, stream_index) +% 1);
    value = (value ^ (value >> 30)) *% 0xbf58_476d_1ce4_e5b9;
    value = (value ^ (value >> 27)) *% 0x94d0_49bb_1331_11eb;
    value ^= value >> 31;
    return value & 1 != 0;
}

pub const Result = struct {
    streams: u16 = 0,
    fins: u16 = 0,
    resets: u16 = 0,
    received_bytes: u64 = 0,
    checksum: u64 = 0,
    reset_mask: ResetMask = 0,
    reset_code_sum: u64 = 0,

    pub fn markReset(self: *Result, stream_index: usize) void {
        std.debug.assert(stream_index < reset_mask_bits);
        self.reset_mask |= @as(ResetMask, 1) << @intCast(stream_index);
    }

    pub fn encode(self: Result) [result_len]u8 {
        var bytes = [_]u8{0} ** result_len;
        @memcpy(bytes[0..8], result_magic);
        std.mem.writeInt(u16, bytes[8..10], self.streams, .big);
        std.mem.writeInt(u16, bytes[10..12], self.fins, .big);
        std.mem.writeInt(u16, bytes[12..14], self.resets, .big);
        std.mem.writeInt(u64, bytes[16..24], self.received_bytes, .big);
        std.mem.writeInt(u64, bytes[24..32], self.checksum, .big);
        std.mem.writeInt(ResetMask, bytes[32..64], self.reset_mask, .big);
        std.mem.writeInt(u64, bytes[64..72], self.reset_code_sum, .big);
        return bytes;
    }

    pub fn decode(bytes: *const [result_len]u8) !Result {
        if (!std.mem.eql(u8, bytes[0..8], result_magic) or
            bytes[14] != 0 or bytes[15] != 0)
        {
            return error.InvalidChurnResult;
        }
        return .{
            .streams = std.mem.readInt(u16, bytes[8..10], .big),
            .fins = std.mem.readInt(u16, bytes[10..12], .big),
            .resets = std.mem.readInt(u16, bytes[12..14], .big),
            .received_bytes = std.mem.readInt(u64, bytes[16..24], .big),
            .checksum = std.mem.readInt(u64, bytes[24..32], .big),
            .reset_mask = std.mem.readInt(ResetMask, bytes[32..64], .big),
            .reset_code_sum = std.mem.readInt(u64, bytes[64..72], .big),
        };
    }
};

test "WebTransport churn result encodes all 256 reset bits" {
    var result: Result = .{
        .streams = 256,
        .fins = 128,
        .resets = 128,
        .received_bytes = 2_129_920,
        .checksum = 271_564_800,
        .reset_code_sum = 2_113_536,
    };
    for (0..max_streams) |index| {
        if (index % 2 == 1) result.markReset(index);
    }
    const encoded = result.encode();
    try std.testing.expectEqual(result, try Result.decode(&encoded));
    try std.testing.expectEqual(
        @as(ResetMask, 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa),
        result.reset_mask,
    );
}

test "WebTransport churn reset selection is stable across mask words" {
    const seed: u64 = 0x0123_4567_89ab_cdef;
    var mask: ResetMask = 0;
    var resets: usize = 0;
    for (0..max_streams) |index| {
        if (!shouldReset(seed, max_streams, index)) continue;
        mask |= @as(ResetMask, 1) << @intCast(index);
        resets += 1;
    }
    try std.testing.expectEqual(@as(usize, 134), resets);
    try std.testing.expectEqual(
        @as(ResetMask, 0x20717754f9d11ba55f3754fe3fba318753ac3c582f1d6af9817734c8ac80f7c1),
        mask,
    );
    try std.testing.expect(shouldReset(seed, 2, 0));
    try std.testing.expect(!shouldReset(seed, 2, 1));
    try std.testing.expect(shouldReset(2, max_streams, max_streams - 1));
}
