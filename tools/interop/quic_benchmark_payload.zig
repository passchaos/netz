const std = @import("std");

const period: usize = 256;
const cycle_checksum: u64 = 255 * period / 2;

const Pattern = struct {
    bytes: [period]u8,
    prefix_checksums: [period + 1]u16,
};

const patterns: [period]Pattern = blk: {
    @setEvalBranchQuota(300_000);
    var result: [period]Pattern = undefined;
    for (&result, 0..) |*pattern, bias| {
        pattern.prefix_checksums[0] = 0;
        for (&pattern.bytes, 0..) |*value, offset| {
            value.* = @truncate(offset * 131 + bias);
            pattern.prefix_checksums[offset + 1] =
                pattern.prefix_checksums[offset] + value.*;
        }
    }
    break :blk result;
};

pub fn byte(round: u32, stream_index: usize, offset: usize) u8 {
    const pattern = select(round, stream_index);
    return pattern.bytes[offset % period];
}

pub fn fill(payload: []u8, round: u32, stream_index: usize) u64 {
    if (payload.len == 0) return 0;
    const pattern = select(round, stream_index);
    const initial: usize = @min(payload.len, period);
    @memcpy(payload[0..initial], pattern.bytes[0..initial]);
    var initialized: usize = initial;
    while (initialized < payload.len) {
        const count: usize = @min(period, payload.len - initialized);
        @memcpy(
            payload[initialized..][0..count],
            pattern.bytes[0..count],
        );
        initialized += count;
    }
    return checksum(round, stream_index, 0, payload.len);
}

pub fn verify(
    bytes: []const u8,
    round: u32,
    stream_index: usize,
    offset: usize,
) !u64 {
    const pattern = select(round, stream_index);
    var consumed: usize = 0;
    var pattern_offset = offset % period;
    while (consumed < bytes.len) {
        const count = @min(
            bytes.len - consumed,
            period - pattern_offset,
        );
        if (!std.mem.eql(
            u8,
            bytes[consumed..][0..count],
            pattern.bytes[pattern_offset..][0..count],
        )) {
            return error.InvalidBenchmarkPayload;
        }
        consumed += count;
        pattern_offset = 0;
    }
    return checksum(round, stream_index, offset, bytes.len);
}

fn select(round: u32, stream_index: usize) *const Pattern {
    const bias: u8 = @truncate(
        @as(usize, round) *% 29 +% stream_index *% 17,
    );
    return &patterns[bias];
}

fn checksum(
    round: u32,
    stream_index: usize,
    offset: usize,
    len: usize,
) u64 {
    const pattern = select(round, stream_index);
    const full_cycles = len / period;
    var result = @as(u64, @intCast(full_cycles)) *% cycle_checksum;
    const tail = len % period;
    const start = offset % period;
    const first = @min(tail, period - start);
    result +%= pattern.prefix_checksums[start + first] -
        pattern.prefix_checksums[start];
    if (first != tail) {
        result +%= pattern.prefix_checksums[tail - first];
    }
    return result;
}

test "QUIC benchmark payload tables match bytewise generation and verification" {
    const lengths = [_]usize{ 0, 1, 17, 255, 256, 257, 1023, 1024, 1025 };
    const rounds = [_]u32{ 0, 1, 255, 256, std.math.maxInt(u32) };
    const streams = [_]usize{ 0, 1, 2, 3 };
    var storage: [1537]u8 = undefined;

    for (rounds) |round| {
        for (streams) |stream_index| {
            for (lengths) |len| {
                const actual_checksum = fill(
                    storage[0..len],
                    round,
                    stream_index,
                );
                var expected_checksum: u64 = 0;
                for (storage[0..len], 0..) |value, offset| {
                    const expected: u8 = @truncate(
                        offset *% 131 +% stream_index *% 17 +%
                            @as(usize, round) *% 29,
                    );
                    try std.testing.expectEqual(expected, value);
                    expected_checksum +%= expected;
                }
                try std.testing.expectEqual(
                    expected_checksum,
                    actual_checksum,
                );
            }

            _ = fill(&storage, round, stream_index);
            for ([_]usize{ 0, 1, 255, 256, 257 }) |offset| {
                for (lengths) |len| {
                    if (offset + len > storage.len) continue;
                    const bytes = storage[offset .. offset + len];
                    var expected_checksum: u64 = 0;
                    for (bytes) |value| expected_checksum +%= value;
                    try std.testing.expectEqual(
                        expected_checksum,
                        try verify(bytes, round, stream_index, offset),
                    );
                    if (len == 0) continue;
                    const corrupt_index = offset + len / 2;
                    storage[corrupt_index] ^= 1;
                    try std.testing.expectError(
                        error.InvalidBenchmarkPayload,
                        verify(
                            storage[offset .. offset + len],
                            round,
                            stream_index,
                            offset,
                        ),
                    );
                    storage[corrupt_index] ^= 1;
                }
            }
        }
    }

    const large = try std.testing.allocator.alloc(u8, 1024 * 1024);
    defer std.testing.allocator.free(large);
    const actual_checksum = fill(large, 257, 3);
    try std.testing.expectEqual(
        actual_checksum,
        try verify(large, 257, 3, 0),
    );
    large[65_535] ^= 1;
    try std.testing.expectError(
        error.InvalidBenchmarkPayload,
        verify(large, 257, 3, 0),
    );
}
