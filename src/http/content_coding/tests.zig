const std = @import("std");
const vort = @import("vort");
const content_coding = @import("../content_coding.zig");

const Coding = content_coding.Coding;
const Chain = content_coding.Chain;
const StreamDecoder = content_coding.StreamDecoder;
const StreamStatus = content_coding.StreamStatus;

test "HTTP content coding parses repeated and stacked fields" {
    const Header = struct { name: []const u8, value: []const u8 };
    const chain = try content_coding.parseHeaders(&[_]Header{
        .{ .name = "Content-Encoding", .value = "deflate, gzip" },
        .{ .name = "content-encoding", .value = "BR, zstd" },
    });
    try std.testing.expectEqualSlices(
        Coding,
        &.{ .deflate, .gzip, .br, .zstd },
        chain.items(),
    );
    try std.testing.expect(chain.encoded());
    try std.testing.expectEqualStrings("gzip", Coding.gzip.name());
    try std.testing.expectEqual(
        Coding.gzip,
        (try content_coding.parse("x-gzip")).items()[0],
    );
    const identity = try content_coding.parse(null);
    try std.testing.expect(!identity.encoded());
    var borrowed = try identity.decodeAlloc(
        std.testing.allocator,
        "plain",
        5,
    );
    defer borrowed.deinit(std.testing.allocator);
    try std.testing.expect(borrowed.owned == null);
    try std.testing.expectEqualStrings("plain", borrowed.bytes);
    try std.testing.expectError(
        error.InvalidContentEncoding,
        content_coding.parse("gzip,,br"),
    );
    try std.testing.expectError(
        error.InvalidContentEncoding,
        content_coding.parse("gzip;level=1"),
    );
    try std.testing.expectError(
        error.UnsupportedContentEncoding,
        content_coding.parse("compress"),
    );
    try std.testing.expectError(
        error.TooManyContentEncodings,
        content_coding.parse(
            "gzip,gzip,gzip,gzip,gzip,gzip,gzip,gzip,gzip",
        ),
    );
}

test "HTTP content coding decodes Vort gzip deflate Brotli and Zstandard" {
    const allocator = std.testing.allocator;
    const payload = "bounded HTTP content decoding " ** 32;

    const zlib = try vort.encodeZlibStoredAlloc(allocator, payload);
    defer allocator.free(zlib);
    try expectDecoded(allocator, .deflate, zlib, payload);

    const gzip = try vort.encodeGzipStoredAlloc(allocator, payload);
    defer allocator.free(gzip);
    try expectDecoded(allocator, .gzip, gzip, payload);

    const brotli = try vort.brEncodeStoredStreamAlloc(allocator, payload);
    defer allocator.free(brotli);
    try expectDecoded(allocator, .br, brotli, payload);

    const zstd = try vort.zstdEncodeNativeFrameAlloc(allocator, payload);
    defer allocator.free(zstd);
    try expectDecoded(allocator, .zstd, zstd, payload);
}

test "HTTP content coding reverses stacked encodings into caller buffers" {
    const allocator = std.testing.allocator;
    const payload = "stacked HTTP representation " ** 16;
    const zlib = try vort.encodeZlibStoredAlloc(allocator, payload);
    defer allocator.free(zlib);
    const gzip = try vort.encodeGzipStoredAlloc(allocator, zlib);
    defer allocator.free(gzip);

    const chain = try content_coding.parse("deflate, gzip");
    var output: [2048]u8 = undefined;
    var scratch: [2048]u8 = undefined;
    const decoded = try chain.decodeInto(gzip, &output, &scratch);
    try std.testing.expectEqualStrings(payload, decoded);

    var owned = try chain.decodeAlloc(allocator, gzip, output.len);
    defer owned.deinit(allocator);
    try std.testing.expectEqualStrings(payload, owned.bytes);
    try std.testing.expect(owned.owned != null);

    try std.testing.expectError(
        error.DecodedBodyTooLarge,
        chain.decodeInto(gzip, output[0 .. payload.len - 1], &scratch),
    );
    try std.testing.expectError(
        error.DecodedBodyTooLarge,
        chain.decodeInto(gzip, &output, scratch[0 .. zlib.len - 1]),
    );
    try std.testing.expectError(
        error.AliasedBuffers,
        chain.decodeInto(gzip, &output, &output),
    );
}

test "HTTP content coding streams every supported encoding with backpressure" {
    const allocator = std.testing.allocator;
    const payload = "progressive HTTP content decoding " ** 32;

    const zlib = try vort.encodeZlibStoredAlloc(allocator, payload);
    defer allocator.free(zlib);
    try expectStreamDecoded(allocator, .deflate, zlib, payload);

    const gzip = try vort.encodeGzipStoredAlloc(allocator, payload);
    defer allocator.free(gzip);
    try expectStreamDecoded(allocator, .gzip, gzip, payload);

    const brotli = try vort.brEncodeStoredStreamAlloc(allocator, payload);
    defer allocator.free(brotli);
    try expectStreamDecoded(allocator, .br, brotli, payload);

    const zstd = try vort.zstdEncodeNativeFrameAlloc(allocator, payload);
    defer allocator.free(zstd);
    try expectStreamDecoded(allocator, .zstd, zstd, payload);
}

test "HTTP content coding streaming preserves EOF and limit errors" {
    const allocator = std.testing.allocator;
    const payload = "stream limits " ** 32;
    const gzip = try vort.encodeGzipStoredAlloc(allocator, payload);
    defer allocator.free(gzip);

    var truncated = try StreamDecoder.init(allocator, .gzip, .{
        .max_encoded_bytes = gzip.len,
        .max_decoded_bytes = payload.len,
    });
    defer truncated.deinit();
    var output: [64]u8 = undefined;
    var input_offset: usize = 0;
    while (input_offset < gzip.len - 1) {
        const result = try truncated.step(
            gzip[input_offset .. gzip.len - 1],
            &output,
        );
        input_offset += result.input_read;
        try std.testing.expect(
            result.input_read != 0 or result.output_written != 0,
        );
    }
    var saw_truncated = false;
    while (!truncated.finished()) {
        if (truncated.finish(&output)) |result| {
            if (result.status == .done) break;
            try std.testing.expect(result.output_written != 0);
        } else |err| {
            try std.testing.expectEqual(error.InvalidContentEncoding, err);
            saw_truncated = true;
            break;
        }
    }
    try std.testing.expect(saw_truncated);
    try std.testing.expectError(
        error.InvalidDecoderState,
        truncated.step(&.{}, &output),
    );

    var encoded_limited = try StreamDecoder.init(allocator, .gzip, .{
        .max_encoded_bytes = gzip.len - 1,
        .max_decoded_bytes = payload.len,
    });
    defer encoded_limited.deinit();
    try std.testing.expectError(
        error.EncodedBodyTooLarge,
        encoded_limited.step(gzip, &output),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        encoded_limited.totalInputRead(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        encoded_limited.totalOutputWritten(),
    );

    var decoded_limited = try StreamDecoder.init(allocator, .gzip, .{
        .max_encoded_bytes = gzip.len,
        .max_decoded_bytes = payload.len - 1,
    });
    defer decoded_limited.deinit();
    var saw_decoded_limit = false;
    input_offset = 0;
    while (input_offset < gzip.len) {
        if (decoded_limited.step(gzip[input_offset..], &output)) |result| {
            input_offset += result.input_read;
            try std.testing.expect(
                result.input_read != 0 or result.output_written != 0,
            );
        } else |err| {
            try std.testing.expectEqual(error.DecodedBodyTooLarge, err);
            saw_decoded_limit = true;
            break;
        }
    }
    while (!saw_decoded_limit and !decoded_limited.finished()) {
        if (decoded_limited.finish(&output)) |result| {
            if (result.status == .done) break;
            try std.testing.expect(result.output_written != 0);
        } else |err| {
            try std.testing.expectEqual(error.DecodedBodyTooLarge, err);
            saw_decoded_limit = true;
        }
    }
    try std.testing.expect(saw_decoded_limit);
}

test "HTTP content coding streams stacked Vort codecs with tiny queues" {
    const allocator = std.testing.allocator;
    const payload = "stacked progressive content decoding " ** 24;
    const zlib = try vort.encodeZlibStoredAlloc(allocator, payload);
    defer allocator.free(zlib);
    const gzip = try vort.encodeGzipStoredAlloc(allocator, zlib);
    defer allocator.free(gzip);
    const brotli = try vort.brEncodeStoredStreamAlloc(allocator, gzip);
    defer allocator.free(brotli);
    const zstd = try vort.zstdEncodeNativeFrameAlloc(allocator, brotli);
    defer allocator.free(zstd);
    const max_layer_bytes = @max(
        payload.len,
        @max(zlib.len, @max(gzip.len, brotli.len)),
    );
    const chain = try content_coding.parse("deflate, gzip, br, zstd");

    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var decoder = try chain.streamDecoder(failing.allocator(), .{
        .max_encoded_bytes = zstd.len,
        .max_decoded_bytes = max_layer_bytes,
        .intermediate_buffer_bytes = 3,
    });
    defer decoder.deinit();

    const first = try decodeStreamFragmented(allocator, &decoder, zstd);
    defer allocator.free(first);
    try std.testing.expectEqualStrings(payload, first);
    decoder.reset();
    failing.fail_index = failing.alloc_index;
    const second = try decodeStreamFragmented(allocator, &decoder, zstd);
    defer allocator.free(second);
    try std.testing.expectEqualStrings(payload, second);
    try std.testing.expectEqual(zstd.len, decoder.totalInputRead());
    try std.testing.expectEqual(payload.len, decoder.totalOutputWritten());
    try std.testing.expect(!failing.has_induced_failure);
}

test "HTTP stacked streaming initialization rolls back every allocation" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        initStackedStreamDecoder,
        .{},
    );
}

test "HTTP stacked streaming keeps the public nesting cap" {
    const codings = [_]Coding{.gzip} ** (content_coding.max_codings + 1);
    try std.testing.expectError(
        error.TooManyContentEncodings,
        StreamDecoder.initChain(std.testing.allocator, &codings, .{
            .max_encoded_bytes = 1024,
            .max_decoded_bytes = 2048,
        }),
    );
}

test "HTTP stacked streaming bounds intermediates and validates inner EOF" {
    const allocator = std.testing.allocator;
    const payload = "inner stream";
    const zlib = try vort.encodeZlibStoredAlloc(allocator, payload);
    defer allocator.free(zlib);
    const gzip = try vort.encodeGzipStoredAlloc(allocator, zlib);
    defer allocator.free(gzip);
    const chain = try content_coding.parse("deflate, gzip");

    var limited = try chain.streamDecoder(allocator, .{
        .max_encoded_bytes = gzip.len,
        .max_decoded_bytes = payload.len,
        .intermediate_buffer_bytes = 2,
    });
    defer limited.deinit();
    var output: [payload.len]u8 = undefined;
    try std.testing.expectError(
        error.DecodedBodyTooLarge,
        decodeStreamInto(&limited, gzip, &output),
    );

    const truncated_gzip = try vort.encodeGzipStoredAlloc(
        allocator,
        zlib[0 .. zlib.len - 1],
    );
    defer allocator.free(truncated_gzip);
    var truncated = try chain.streamDecoder(allocator, .{
        .max_encoded_bytes = truncated_gzip.len,
        .max_decoded_bytes = zlib.len,
        .intermediate_buffer_bytes = 2,
    });
    defer truncated.deinit();
    try std.testing.expectError(
        error.InvalidContentEncoding,
        decodeStreamInto(&truncated, truncated_gzip, &output),
    );

    const trailed_zlib = try std.mem.concat(
        allocator,
        u8,
        &.{ zlib, "trailing-inner-bytes" },
    );
    defer allocator.free(trailed_zlib);
    const trailed_gzip = try vort.encodeGzipStoredAlloc(
        allocator,
        trailed_zlib,
    );
    defer allocator.free(trailed_gzip);
    var trailed = try chain.streamDecoder(allocator, .{
        .max_encoded_bytes = trailed_gzip.len,
        .max_decoded_bytes = trailed_zlib.len,
        .intermediate_buffer_bytes = 2,
    });
    defer trailed.deinit();
    try std.testing.expectError(
        error.InvalidContentEncoding,
        decodeStreamInto(&trailed, trailed_gzip, &output),
    );
}

test "HTTP identity streaming reports exact resumable progress" {
    const allocator = std.testing.allocator;
    var decoder = try StreamDecoder.init(allocator, .identity, .{
        .max_encoded_bytes = 5,
        .max_decoded_bytes = 5,
    });
    defer decoder.deinit();
    var first: [2]u8 = undefined;
    const first_result = try decoder.step("hello", &first);
    try std.testing.expectEqual(StreamStatus.need_output, first_result.status);
    try std.testing.expectEqual(@as(usize, 2), first_result.input_read);
    try std.testing.expectEqualStrings("he", &first);
    var second: [3]u8 = undefined;
    const second_result = try decoder.step("llo", &second);
    try std.testing.expectEqual(StreamStatus.need_input, second_result.status);
    try std.testing.expectEqualStrings("llo", &second);
    const finished = try decoder.finish(&.{});
    try std.testing.expectEqual(StreamStatus.done, finished.status);
    try std.testing.expectEqual(@as(usize, 5), decoder.totalInputRead());
    try std.testing.expectEqual(@as(usize, 5), decoder.totalOutputWritten());
}

test "HTTP content coding streaming rejects trailing bytes and resets" {
    const allocator = std.testing.allocator;
    const payload = "trailing";
    const encoded = try vort.encodeZlibStoredAlloc(allocator, payload);
    defer allocator.free(encoded);
    const trailed = try std.mem.concat(allocator, u8, &.{ encoded, "x" });
    defer allocator.free(trailed);

    var decoder = try StreamDecoder.init(allocator, .deflate, .{
        .max_encoded_bytes = trailed.len,
        .max_decoded_bytes = payload.len,
    });
    defer decoder.deinit();
    var output: [payload.len + 1]u8 = undefined;
    if (decoder.step(trailed, &output)) |result| {
        try std.testing.expectEqual(StreamStatus.done, result.status);
        try std.testing.expect(result.input_read < trailed.len);
        try std.testing.expectError(
            error.InvalidContentEncoding,
            decoder.step(trailed[result.input_read..], &output),
        );
    } else |err| {
        try std.testing.expectEqual(error.InvalidContentEncoding, err);
    }

    decoder.reset();
    const result = try decoder.step(encoded, &output);
    try std.testing.expectEqual(encoded.len, result.input_read);
    try std.testing.expectEqualStrings(
        payload,
        output[0..result.output_written],
    );
    try std.testing.expect((try decoder.finish(&.{})).status == .done);
}

test "HTTP gzip streaming allocates only its reusable decoder state" {
    const allocator = std.testing.allocator;
    const payload = "allocation-free streaming decode " ** 16;
    const encoded = try vort.encodeGzipStoredAlloc(allocator, payload);
    defer allocator.free(encoded);

    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var decoder = try StreamDecoder.init(failing.allocator(), .gzip, .{
        .max_encoded_bytes = encoded.len,
        .max_decoded_bytes = payload.len,
    });
    defer decoder.deinit();
    failing.fail_index = failing.alloc_index;

    var output: [payload.len + 1]u8 = undefined;
    for (0..2) |_| {
        decoder.reset();
        const decoded = try decodeStreamInto(&decoder, encoded, &output);
        try std.testing.expectEqualStrings(payload, decoded);
    }
    try std.testing.expect(!failing.has_induced_failure);
}

fn expectDecoded(
    allocator: std.mem.Allocator,
    coding: Coding,
    encoded: []const u8,
    expected: []const u8,
) !void {
    var chain: Chain = .{};
    chain.storage[0] = coding;
    chain.len = 1;
    var decoded = try chain.decodeAlloc(
        allocator,
        encoded,
        expected.len,
    );
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings(expected, decoded.bytes);

    var output: [2048]u8 = undefined;
    const into = try chain.decodeInto(encoded, &output, &.{});
    try std.testing.expectEqualStrings(expected, into);
    try std.testing.expectError(
        error.DecodedBodyTooLarge,
        chain.decodeAlloc(allocator, encoded, expected.len - 1),
    );
}

fn expectStreamDecoded(
    allocator: std.mem.Allocator,
    coding: Coding,
    encoded: []const u8,
    expected: []const u8,
) !void {
    var decoder = try StreamDecoder.init(allocator, coding, .{
        .max_encoded_bytes = encoded.len,
        .max_decoded_bytes = expected.len,
    });
    defer decoder.deinit();
    var decoded: std.ArrayList(u8) = .empty;
    defer decoded.deinit(allocator);
    var output: [7]u8 = undefined;
    var input_offset: usize = 0;
    var turn: usize = 0;
    while (input_offset < encoded.len) {
        const end = @min(encoded.len, input_offset + 1 + turn % 5);
        while (input_offset < end) {
            const result = try decoder.step(
                encoded[input_offset..end],
                &output,
            );
            try decoded.appendSlice(
                allocator,
                output[0..result.output_written],
            );
            input_offset += result.input_read;
            if (result.status == .done) {
                try std.testing.expectEqual(encoded.len, input_offset);
                break;
            }
            try std.testing.expect(
                result.input_read != 0 or result.output_written != 0,
            );
            if (result.status == .need_input) {
                try std.testing.expectEqual(end, input_offset);
            }
        }
        turn += 1;
    }
    while (!decoder.finished()) {
        const result = try decoder.finish(&output);
        try decoded.appendSlice(
            allocator,
            output[0..result.output_written],
        );
        if (result.status == .done) break;
        try std.testing.expectEqual(StreamStatus.need_output, result.status);
        try std.testing.expect(result.output_written != 0);
    }
    try std.testing.expectEqual(encoded.len, decoder.totalInputRead());
    try std.testing.expectEqual(expected.len, decoder.totalOutputWritten());
    try std.testing.expectEqualStrings(expected, decoded.items);
}

fn decodeStreamInto(
    decoder: *StreamDecoder,
    input: []const u8,
    output: []u8,
) ![]u8 {
    var input_offset: usize = 0;
    var output_offset: usize = 0;
    while (input_offset < input.len) {
        const result = try decoder.step(
            input[input_offset..],
            output[output_offset..],
        );
        input_offset += result.input_read;
        output_offset += result.output_written;
        if (result.status == .done) break;
        if (result.input_read == 0 and result.output_written == 0) {
            return error.TestUnexpectedResult;
        }
    }
    while (!decoder.finished()) {
        const result = try decoder.finish(output[output_offset..]);
        output_offset += result.output_written;
        if (result.status == .done) break;
        if (result.output_written == 0) return error.TestUnexpectedResult;
    }
    return output[0..output_offset];
}

fn decodeStreamFragmented(
    allocator: std.mem.Allocator,
    decoder: *StreamDecoder,
    input: []const u8,
) ![]u8 {
    var decoded: std.ArrayList(u8) = .empty;
    errdefer decoded.deinit(allocator);
    var output: [5]u8 = undefined;
    var input_offset: usize = 0;
    var turn: usize = 0;
    while (input_offset < input.len) {
        const end = @min(input.len, input_offset + 1 + turn % 7);
        while (input_offset < end) {
            const result = try decoder.step(
                input[input_offset..end],
                &output,
            );
            try decoded.appendSlice(
                allocator,
                output[0..result.output_written],
            );
            input_offset += result.input_read;
            if (result.status == .done) {
                if (input_offset != input.len) return error.TestUnexpectedResult;
                break;
            }
            if (result.input_read == 0 and result.output_written == 0) {
                return error.TestUnexpectedResult;
            }
        }
        turn += 1;
    }
    while (!decoder.finished()) {
        const result = try decoder.finish(&output);
        try decoded.appendSlice(
            allocator,
            output[0..result.output_written],
        );
        if (result.status == .done) break;
        if (result.output_written == 0) return error.TestUnexpectedResult;
    }
    return decoded.toOwnedSlice(allocator);
}

fn initStackedStreamDecoder(allocator: std.mem.Allocator) !void {
    const chain = try content_coding.parse("deflate, gzip");
    var decoder = try chain.streamDecoder(allocator, .{
        .max_encoded_bytes = 1024,
        .max_decoded_bytes = 2048,
        .intermediate_buffer_bytes = 7,
    });
    defer decoder.deinit();
}
