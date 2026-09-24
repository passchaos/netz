//! Stateful RFC 7692 compression contexts.
//!
//! These codecs retain only the negotiated LZ77 history. Callers explicitly
//! reset a direction at message boundaries when `*_no_context_takeover` is
//! negotiated. Failed decoding never commits partial history.

const std = @import("std");
const vort = @import("../internal/vort.zig");

pub const Error = error{
    InvalidExtension,
    InvalidFrame,
    PayloadTooLarge,
    WriteFailed,
} || std.mem.Allocator.Error;

const base_options: vort.CompressionOptions = .{
    .parser = .hash,
    .lz77_options = .{
        .window_len = 16 * 1024,
        .max_chain = 4,
        .nice_len = 32,
    },
};

fn compressionOptions(max_window_bits: u8) Error!vort.CompressionOptions {
    if (max_window_bits < 8 or max_window_bits > 15) {
        return error.InvalidExtension;
    }
    var options = base_options;
    const negotiated_window = @as(usize, 1) << @intCast(max_window_bits);
    options.lz77_options.window_len = @min(
        options.lz77_options.window_len,
        negotiated_window,
    );
    return options;
}

fn mapCompressionError(err: anyerror) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.WriteFailed,
    };
}

fn removeTail(output: *std.ArrayList(u8)) Error![]const u8 {
    const tail = "\x00\x00\xff\xff";
    if (!std.mem.endsWith(u8, output.items, tail)) {
        return error.WriteFailed;
    }
    output.items.len -= tail.len;
    return output.items;
}

/// Stateful RFC 7692 compressor for negotiated context takeover.
///
/// A successful compression call commits the plaintext to future history. The
/// caller must therefore use the returned bytes as a compressed RSV1 message;
/// implementations that may fall back to uncompressed wire data must make that
/// decision before calling or retain a separate preview/rollback policy.
pub const CompressionContext = struct {
    encoder: vort.RawFixedSyncFlushEncoder,
    max_window_bits: u8,

    pub fn init(
        allocator: std.mem.Allocator,
        max_window_bits: u8,
    ) Error!CompressionContext {
        _ = try compressionOptions(max_window_bits);
        return .{
            .encoder = .init(allocator),
            .max_window_bits = max_window_bits,
        };
    }

    pub fn deinit(self: *CompressionContext) void {
        self.encoder.deinit();
        self.* = undefined;
    }

    pub fn resetContext(self: *CompressionContext) void {
        self.encoder.resetContext();
    }

    pub fn compressInto(
        self: *CompressionContext,
        output: *std.ArrayList(u8),
        payload: []const u8,
    ) Error![]const u8 {
        output.clearRetainingCapacity();
        _ = self.encoder.encodeAppendContext(
            output,
            payload,
            try compressionOptions(self.max_window_bits),
        ) catch |err| return mapCompressionError(err);
        return removeTail(output);
    }

    pub fn compressFragmentsInto(
        self: *CompressionContext,
        output: *std.ArrayList(u8),
        fragments: []const []const u8,
    ) Error![]const u8 {
        output.clearRetainingCapacity();
        _ = self.encoder.encodeChunksAppendContext(
            output,
            fragments,
            try compressionOptions(self.max_window_bits),
        ) catch |err| return mapCompressionError(err);
        return removeTail(output);
    }
};

/// Stateful RFC 7692 inflater for negotiated context takeover.
pub const DecompressionContext = struct {
    allocator: std.mem.Allocator,
    max_window_bits: u8,
    history: std.ArrayList(u8) = .empty,
    input: std.ArrayList(u8) = .empty,
    window: ?[]u8 = null,

    pub fn init(
        allocator: std.mem.Allocator,
        max_window_bits: u8,
    ) Error!DecompressionContext {
        _ = try compressionOptions(max_window_bits);
        return .{
            .allocator = allocator,
            .max_window_bits = max_window_bits,
        };
    }

    pub fn deinit(self: *DecompressionContext) void {
        self.history.deinit(self.allocator);
        self.input.deinit(self.allocator);
        if (self.window) |window| self.allocator.free(window);
        self.* = undefined;
    }

    pub fn resetContext(self: *DecompressionContext) void {
        self.history.clearRetainingCapacity();
    }

    pub fn decompressInto(
        self: *DecompressionContext,
        output: *std.ArrayList(u8),
        compressed_payload: []const u8,
        max_message_bytes: usize,
    ) Error![]const u8 {
        const tail = [_]u8{
            0x00, 0x00, 0xff, 0xff,
            0x01, 0x00, 0x00, 0xff,
            0xff,
        };
        self.input.clearRetainingCapacity();
        try self.input.ensureTotalCapacity(
            self.allocator,
            compressed_payload.len +| tail.len,
        );
        self.input.appendSliceAssumeCapacity(compressed_payload);
        self.input.appendSliceAssumeCapacity(&tail);
        if (self.window == null) {
            self.window = try self.allocator.alloc(
                u8,
                std.compress.flate.max_window_len,
            );
        }
        const window = self.window.?;
        const history_len = self.history.items.len;
        @memcpy(window[0..history_len], self.history.items);

        var input_reader = std.Io.Reader.fixed(self.input.items);
        var decompressor = std.compress.flate.Decompress.init(
            &input_reader,
            .raw,
            window,
        );
        decompressor.reader.seek = history_len;
        decompressor.reader.end = history_len;

        output.clearRetainingCapacity();
        try output.ensureTotalCapacity(
            self.allocator,
            max_message_bytes,
        );
        var writer: std.Io.Writer = .fixed(
            output.allocatedSlice()[0..max_message_bytes],
        );
        _ = decompressor.reader.streamRemaining(&writer) catch |err| {
            return switch (err) {
                error.WriteFailed => error.PayloadTooLarge,
                error.ReadFailed => error.InvalidFrame,
            };
        };
        output.items.len = writer.end;
        try self.rememberContext(output.items);
        return output.items;
    }

    fn rememberContext(
        self: *DecompressionContext,
        payload: []const u8,
    ) std.mem.Allocator.Error!void {
        const window_len = @as(usize, 1) <<
            @intCast(self.max_window_bits);
        const keep_payload = @min(payload.len, window_len);
        const keep_history = @min(
            self.history.items.len,
            window_len - keep_payload,
        );
        try self.history.ensureTotalCapacity(
            self.allocator,
            keep_history + keep_payload,
        );
        if (keep_history != 0) {
            const old_len = self.history.items.len;
            @memmove(
                self.history.items[0..keep_history],
                self.history.items[old_len - keep_history ..],
            );
        }
        self.history.items.len = keep_history + keep_payload;
        @memcpy(
            self.history.items[keep_history..],
            payload[payload.len - keep_payload ..],
        );
    }
};

test "context takeover round trips and resets transactionally" {
    const allocator = std.testing.allocator;
    const first = "abcdefghijklmnopqrstuvwxyz0123456789";
    const second = first;
    var compressor = try CompressionContext.init(allocator, 15);
    defer compressor.deinit();
    var decompressor = try DecompressionContext.init(allocator, 15);
    defer decompressor.deinit();
    var compressed: std.ArrayList(u8) = .empty;
    defer compressed.deinit(allocator);
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);

    const first_wire = try compressor.compressInto(&compressed, first);
    const first_copy = try allocator.dupe(u8, first_wire);
    defer allocator.free(first_copy);
    try std.testing.expectEqualStrings(
        first,
        try decompressor.decompressInto(&output, first_copy, first.len),
    );

    const second_wire = try compressor.compressInto(&compressed, second);
    try std.testing.expect(second_wire.len < first_copy.len);
    const second_copy = try allocator.dupe(u8, second_wire);
    defer allocator.free(second_copy);
    try std.testing.expectEqualStrings(
        second,
        try decompressor.decompressInto(&output, second_copy, second.len),
    );

    var continuous: std.ArrayList(u8) = .empty;
    defer continuous.deinit(allocator);
    try continuous.appendSlice(allocator, first_copy);
    try continuous.appendSlice(allocator, "\x00\x00\xff\xff");
    try continuous.appendSlice(allocator, second_copy);
    try continuous.appendSlice(
        allocator,
        "\x00\x00\xff\xff\x01\x00\x00\xff\xff",
    );
    var continuous_reader = std.Io.Reader.fixed(continuous.items);
    var continuous_window: [std.compress.flate.max_window_len]u8 = undefined;
    var continuous_decoder = std.compress.flate.Decompress.init(
        &continuous_reader,
        .raw,
        &continuous_window,
    );
    var continuous_output: [first.len + second.len]u8 = undefined;
    var continuous_writer: std.Io.Writer = .fixed(&continuous_output);
    _ = try continuous_decoder.reader.streamRemaining(&continuous_writer);
    try std.testing.expectEqualStrings(
        first ++ second,
        continuous_writer.buffered(),
    );

    try std.testing.expectError(
        error.PayloadTooLarge,
        decompressor.decompressInto(&output, second_copy, second.len - 1),
    );
    // The failed decode above must not append another message to history.
    const third_wire = try compressor.compressInto(&compressed, second);
    try std.testing.expectEqualStrings(
        second,
        try decompressor.decompressInto(&output, third_wire, second.len),
    );

    compressor.resetContext();
    decompressor.resetContext();
    const reset_wire = try compressor.compressInto(&compressed, second);
    try std.testing.expectEqualSlices(u8, first_copy, reset_wire);
    try std.testing.expectEqualStrings(
        second,
        try decompressor.decompressInto(&output, reset_wire, second.len),
    );
}

test "context takeover decodes external zlib sequence" {
    const allocator = std.testing.allocator;
    const payload = "abcdefghijklmnopqrstuvwxyz0123456789";
    const first_wire = [_]u8{
        0x4a, 0x4c, 0x4a, 0x4e, 0x49, 0x4d, 0x4b, 0xcf,
        0xc8, 0xcc, 0xca, 0xce, 0xc9, 0xcd, 0xcb, 0x2f,
        0x28, 0x2c, 0x2a, 0x2e, 0x29, 0x2d, 0x2b, 0xaf,
        0xa8, 0xac, 0x32, 0x30, 0x34, 0x32, 0x36, 0x31,
        0x35, 0x33, 0xb7, 0xb0, 0x04, 0x00,
    };
    const second_wire = [_]u8{ 0x4a, 0x24, 0x42, 0x0d, 0x00 };
    var decompressor = try DecompressionContext.init(allocator, 15);
    defer decompressor.deinit();
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    try std.testing.expectEqualStrings(
        payload,
        try decompressor.decompressInto(&output, &first_wire, payload.len),
    );
    try std.testing.expectEqualStrings(
        payload,
        try decompressor.decompressInto(&output, &second_wire, payload.len),
    );

    decompressor.resetContext();
    try std.testing.expectError(
        error.InvalidFrame,
        decompressor.decompressInto(&output, &second_wire, payload.len),
    );
}
