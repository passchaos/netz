//! Bounded RFC 7692 compression fuzzing.
//!
//! Each input is treated both as hostile compressed wire data and as plaintext
//! for independent std.flate and Vort round trips. Input, decompressed output,
//! fragment count, and negotiated window size are all explicitly bounded.

const std = @import("std");
const netz = @import("netz");

const max_input_bytes = 16 * 1024;
const max_decompressed_bytes = 64 * 1024;
const restored_tail_bytes = 9;

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

const empty_seed = smithSliceSeed("");
const text_seed = smithSliceSeed(
    "permessage-deflate permessage-deflate permessage-deflate",
);
const binary_seed = smithSliceSeed(&.{
    0x00, 0xff, 0x00, 0xff, 0x01, 0xfe, 0x02, 0xfd,
    0x03, 0xfc, 0x04, 0xfb, 0x05, 0xfa, 0x06, 0xf9,
});
// Python zlib level 9, wbits=-15, Z_SYNC_FLUSH, with 00 00 ff ff removed.
const external_deflate_seed = smithSliceSeed(&.{
    0x4a, 0xad, 0x28, 0x49, 0x2d, 0xca, 0x4b, 0xcc,
    0x51, 0x48, 0xa9, 0xcc, 0x4b, 0xcc, 0xcd, 0x4c,
    0x56, 0x48, 0x49, 0x4d, 0xcb, 0x49, 0x2c, 0x49,
    0x55, 0x28, 0x48, 0xac, 0xcc, 0xc9, 0x4f, 0x4c,
    0x51, 0x48, 0x1d, 0x55, 0x30, 0x92, 0x14, 0x00,
    0x00,
});
const malformed_deflate_seed = smithSliceSeed(&.{
    0xff, 0xff, 0x00, 0x00, 0x7f, 0x80, 0x01, 0xfe,
});
// Reduced from a coverage-guided crash in Zig 0.16's buffered inflater path.
const short_dynamic_deflate_seed = smithSliceSeed(&.{
    0x04, 0xfb, 0x05, 0xfa, 0x00, 0xff, 0x00, 0xff, 0x01,
    0xfe, 0x02, 0xfd, 0x03, 0xfc, 0x04, 0xfb, 0x05, 0xfa,
});

test "fuzz bounded WebSocket compression" {
    try std.testing.fuzz({}, fuzzCompression, .{ .corpus = &.{
        &empty_seed,
        &text_seed,
        &binary_seed,
        &external_deflate_seed,
        &malformed_deflate_seed,
        &short_dynamic_deflate_seed,
    } });
}

test "bounded deterministic WebSocket compression mutation smoke" {
    const seeds = [_][]const u8{
        empty_seed[4..],
        text_seed[4..],
        binary_seed[4..],
        external_deflate_seed[4..],
        malformed_deflate_seed[4..],
        short_dynamic_deflate_seed[4..],
    };
    var buffer: [max_input_bytes]u8 = undefined;
    for (seeds) |seed| {
        try exerciseCompression(seed);
        for (0..seed.len + 1) |length| {
            try exerciseCompressedInput(seed[0..length]);
        }
        for (seed, 0..) |_, index| {
            @memcpy(buffer[0..seed.len], seed);
            buffer[index] ^= 0xff;
            try exerciseCompressedInput(buffer[0..seed.len]);
        }
    }

    var prng = std.Random.DefaultPrng.init(0x77735f6465666c74);
    const random = prng.random();
    for (0..64) |_| {
        const length = random.uintLessThan(usize, 2049);
        random.bytes(buffer[0..length]);
        try exerciseCompression(buffer[0..length]);
    }
}

fn fuzzCompression(_: void, smith: *std.testing.Smith) !void {
    var storage: [max_input_bytes]u8 = undefined;
    const bytes = storage[0..smith.slice(&storage)];
    try exerciseCompression(bytes);
}

fn exerciseCompression(bytes: []const u8) !void {
    try exerciseCompressedInput(bytes);
    try roundTripStandard(bytes);
    try roundTripVort(bytes, 8 + @as(u8, @truncate(bytes.len % 8)));
    try roundTripVortFragments(bytes, 8 + @as(u8, @truncate(bytes.len % 8)));
}

fn exerciseCompressedInput(bytes: []const u8) !void {
    const allocator = std.testing.allocator;
    var output: [max_decompressed_bytes]u8 = undefined;
    var scratch: [max_input_bytes + restored_tail_bytes]u8 = undefined;
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    if (netz.websocket.decompressMessageInto(
        &output,
        bytes,
        &scratch,
        &window,
    )) |decoded| {
        try std.testing.expect(decoded.len <= output.len);
    } else |_| {}

    if (netz.websocket.decompressMessage(
        allocator,
        bytes,
        max_decompressed_bytes,
    )) |decoded| {
        defer allocator.free(decoded);
        try std.testing.expect(decoded.len <= max_decompressed_bytes);
    } else |_| {}
}

fn roundTripStandard(payload: []const u8) !void {
    const allocator = std.testing.allocator;
    const compressed = try netz.websocket.compressMessage(
        allocator,
        payload,
    );
    defer allocator.free(compressed);
    const decoded = try netz.websocket.decompressMessage(
        allocator,
        compressed,
        payload.len,
    );
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, payload, decoded);
}

fn roundTripVort(payload: []const u8, window_bits: u8) !void {
    const allocator = std.testing.allocator;
    var compressed: std.ArrayList(u8) = .empty;
    defer compressed.deinit(allocator);
    const wire = try netz.websocket.compressMessageVortIntoWindow(
        &compressed,
        allocator,
        payload,
        window_bits,
    );
    const decoded = try netz.websocket.decompressMessage(
        allocator,
        wire,
        payload.len,
    );
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, payload, decoded);
}

fn roundTripVortFragments(payload: []const u8, window_bits: u8) !void {
    const allocator = std.testing.allocator;
    const first = payload.len / 3;
    const second = first + (payload.len - first) / 2;
    const fragments = [_][]const u8{
        payload[0..first],
        payload[first..second],
        payload[second..],
    };
    var compressed: std.ArrayList(u8) = .empty;
    defer compressed.deinit(allocator);
    const wire = try netz.websocket.compressMessageFragmentsVortIntoWindow(
        &compressed,
        allocator,
        &fragments,
        window_bits,
    );
    const decoded = try netz.websocket.decompressMessage(
        allocator,
        wire,
        payload.len,
    );
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, payload, decoded);
}
