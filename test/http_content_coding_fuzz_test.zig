//! Bounded fuzz coverage for shared HTTP Content-Encoding parsing and decode.

const std = @import("std");
const netz = @import("netz");

const max_input_bytes: usize = 4096;
const max_output_bytes: usize = 8192;

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

const empty_seed = smithSliceSeed("");
const token_seed = smithSliceSeed("gzip, deflate, br, zstd");
const gzip_seed = smithSliceSeed(&.{
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x03, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07,
    0x00, 0x86, 0xa6, 0x10, 0x36, 0x05, 0x00, 0x00,
    0x00,
});

test "fuzz bounded HTTP content coding" {
    try std.testing.fuzz({}, fuzzContentCoding, .{ .corpus = &.{
        &empty_seed,
        &token_seed,
        &gzip_seed,
    } });
}

test "bounded deterministic HTTP content coding mutation smoke" {
    const seeds = [_][]const u8{
        empty_seed[4..],
        token_seed[4..],
        gzip_seed[4..],
    };
    var mutated: [max_input_bytes]u8 = undefined;
    for (seeds) |seed| {
        try exercise(seed);
        for (0..seed.len + 1) |length| try exercise(seed[0..length]);
        for (seed, 0..) |_, index| {
            @memcpy(mutated[0..seed.len], seed);
            mutated[index] ^= 0xff;
            try exercise(mutated[0..seed.len]);
        }
    }

    var prng = std.Random.DefaultPrng.init(0x687474705f636f64);
    const random = prng.random();
    for (0..64) |_| {
        const length = random.uintLessThan(usize, max_input_bytes + 1);
        random.bytes(mutated[0..length]);
        try exercise(mutated[0..length]);
    }
}

fn fuzzContentCoding(_: void, smith: *std.testing.Smith) !void {
    var storage: [max_input_bytes]u8 = undefined;
    try exercise(storage[0..smith.slice(&storage)]);
}

fn exercise(bytes: []const u8) !void {
    _ = netz.http.content_coding.parse(bytes) catch {};

    var output: [max_output_bytes]u8 = undefined;
    var scratch: [max_output_bytes]u8 = undefined;
    inline for ([_]netz.http.ContentCoding{
        .gzip,
        .deflate,
        .br,
        .zstd,
    }) |coding| {
        var chain: netz.http.ContentCodingChain = .{};
        chain.storage[0] = coding;
        chain.len = 1;
        if (chain.decodeInto(bytes, &output, &scratch)) |decoded| {
            try std.testing.expect(decoded.len <= output.len);
        } else |_| {}
        try exerciseStream(coding, bytes);
    }
}

fn exerciseStream(
    coding: netz.http.ContentCoding,
    bytes: []const u8,
) !void {
    var decoder = try netz.http.content_coding.StreamDecoder.init(
        std.testing.allocator,
        coding,
        .{
            .max_encoded_bytes = bytes.len,
            .max_decoded_bytes = max_output_bytes,
        },
    );
    defer decoder.deinit();
    var output: [31]u8 = undefined;
    var input_offset: usize = 0;
    var turns: usize = 0;
    while (input_offset < bytes.len) {
        const result = decoder.step(
            bytes[input_offset..],
            &output,
        ) catch return;
        try std.testing.expect(result.input_read <= bytes.len - input_offset);
        try std.testing.expect(result.output_written <= output.len);
        input_offset += result.input_read;
        turns += 1;
        try std.testing.expect(turns <= bytes.len + max_output_bytes + 1);
        if (result.status == .done) continue;
        try std.testing.expect(
            result.input_read != 0 or result.output_written != 0,
        );
    }
    while (!decoder.finished()) {
        const result = decoder.finish(&output) catch return;
        try std.testing.expectEqual(@as(usize, 0), result.input_read);
        try std.testing.expect(result.output_written <= output.len);
        turns += 1;
        try std.testing.expect(turns <= bytes.len + max_output_bytes + 2);
        if (result.status == .done) break;
        try std.testing.expectEqual(
            netz.http.content_coding.StreamStatus.need_output,
            result.status,
        );
        try std.testing.expect(result.output_written != 0);
    }
    try std.testing.expect(
        decoder.totalOutputWritten() <= max_output_bytes,
    );
}
