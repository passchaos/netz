//! Focused DEFLATE compatibility surface used by netz.
//!
//! The raw encoder writes one non-final fixed-Huffman block followed by the
//! RFC 7692 sync-flush marker. Its hash-chain workspace is retained across
//! independent messages, keeping the WebSocket hot path allocation-free after
//! warmup without pulling an unrelated compression repository into the package.

const std = @import("std");

pub const ParserMode = enum { hash };

pub const GreedyOptions = struct {
    window_len: usize = 32 * 1024,
    max_chain: usize = 4,
    nice_len: usize = 32,
};

pub const CompressionOptions = struct {
    parser: ParserMode = .hash,
    lz77_options: GreedyOptions = .{},
};

const no_position = std.math.maxInt(u32);
const hash_bits: usize = 12;
const hash_size: usize = 1 << hash_bits;
const min_match: usize = 3;
const max_match: usize = 258;

const Input = struct {
    chunks: []const []const u8,
    total: usize,
    offsets: []const usize,
    contiguous: ?[]const u8,

    fn init(
        allocator: std.mem.Allocator,
        offsets: *std.ArrayList(usize),
        chunks: []const []const u8,
    ) !Input {
        try offsets.resize(allocator, chunks.len + 1);
        var total: usize = 0;
        var only_non_empty: ?[]const u8 = null;
        var non_empty_count: usize = 0;
        for (chunks, 0..) |chunk, index| {
            offsets.items[index] = total;
            total = std.math.add(usize, total, chunk.len) catch
                return error.IntegerOverflow;
            if (chunk.len != 0) {
                non_empty_count += 1;
                only_non_empty = chunk;
            }
        }
        offsets.items[chunks.len] = total;
        return .{
            .chunks = chunks,
            .total = total,
            .offsets = offsets.items,
            .contiguous = if (non_empty_count == 1) only_non_empty else null,
        };
    }

    inline fn byteAt(self: Input, index: usize) u8 {
        if (self.contiguous) |bytes| return bytes[index];
        const chunk_index = self.chunkIndex(index);
        return self.chunks[chunk_index][index - self.offsets[chunk_index]];
    }

    fn chunkIndex(self: Input, absolute: usize) usize {
        var low: usize = 0;
        var high = self.chunks.len;
        while (low < high) {
            const middle = low + (high - low) / 2;
            if (self.offsets[middle + 1] <= absolute) {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        return low;
    }

    const Cursor = struct {
        chunks: []const []const u8,
        chunk_index: usize,
        offset: usize,

        fn init(input: Input, absolute: usize) Cursor {
            const index = input.chunkIndex(absolute);
            return .{
                .chunks = input.chunks,
                .chunk_index = index,
                .offset = absolute - input.offsets[index],
            };
        }

        inline fn next(self: *Cursor) u8 {
            while (self.offset == self.chunks[self.chunk_index].len) {
                self.chunk_index += 1;
                self.offset = 0;
            }
            const byte = self.chunks[self.chunk_index][self.offset];
            self.offset += 1;
            return byte;
        }
    };
};

const Bits = struct {
    out: *std.ArrayList(u8),
    scratch: u64 = 0,
    count: u6 = 0,

    inline fn write(self: *Bits, value: u64, count: u6) void {
        self.scratch |= value << self.count;
        self.count += count;
        while (self.count >= 8) {
            self.out.appendAssumeCapacity(@truncate(self.scratch));
            self.scratch >>= 8;
            self.count -= 8;
        }
    }

    fn byteAlign(self: *Bits) void {
        if (self.count == 0) return;
        self.out.appendAssumeCapacity(@truncate(self.scratch));
        self.scratch = 0;
        self.count = 0;
    }
};

pub const RawFixedSyncFlushEncoder = struct {
    allocator: std.mem.Allocator,
    heads: std.ArrayList(u32) = .empty,
    epochs: std.ArrayList(u32) = .empty,
    previous: std.ArrayList(u32) = .empty,
    chunk_offsets: std.ArrayList(usize) = .empty,
    epoch: u32 = 0,

    pub fn init(allocator: std.mem.Allocator) RawFixedSyncFlushEncoder {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *RawFixedSyncFlushEncoder) void {
        self.heads.deinit(self.allocator);
        self.epochs.deinit(self.allocator);
        self.previous.deinit(self.allocator);
        self.chunk_offsets.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn encodeAppend(
        self: *RawFixedSyncFlushEncoder,
        out: *std.ArrayList(u8),
        input: []const u8,
        options: CompressionOptions,
    ) !usize {
        return self.encodeChunksAppend(out, &.{input}, options);
    }

    pub fn encodeChunksAppend(
        self: *RawFixedSyncFlushEncoder,
        out: *std.ArrayList(u8),
        chunks: []const []const u8,
        options: CompressionOptions,
    ) !usize {
        _ = options.parser;
        const input = try Input.init(
            self.allocator,
            &self.chunk_offsets,
            chunks,
        );
        const window_len = options.lz77_options.window_len;
        if (window_len < 256 or window_len > 32 * 1024 or
            options.lz77_options.max_chain == 0 or
            options.lz77_options.nice_len < min_match)
        {
            return error.InvalidBlockPlan;
        }
        try self.ensureWorkspace(
            input.total,
            options.lz77_options.window_len,
        );
        self.beginMessage();
        const start = out.items.len;
        errdefer out.items.len = start;
        try out.ensureUnusedCapacity(
            self.allocator,
            input.total +| (input.total + 7) / 8 +| 8,
        );
        var bits = Bits{ .out = out };
        bits.write(0b010, 3); // BFINAL=0, BTYPE=fixed Huffman.

        var pos: usize = 0;
        while (pos < input.total) {
            const match = self.findAndInsert(input, pos, options);
            if (match.len < min_match) {
                writeLiteral(&bits, input.byteAt(pos));
                pos += 1;
                continue;
            }
            writeLength(&bits, match.len);
            writeDistance(&bits, match.distance);
            const end = pos + match.len;
            // The current anchor already represents long repetitions. Seed
            // only the tail so the next search can cross this match without
            // hashing every skipped byte.
            var insert_pos = if (end > pos + 4) end - 4 else pos + 1;
            while (insert_pos < end) : (insert_pos += 1) {
                self.insert(input, insert_pos);
            }
            pos = end;
        }
        writeFixedSymbol(&bits, 256);
        bits.write(0, 3); // Empty non-final stored block.
        bits.byteAlign();
        out.appendSliceAssumeCapacity(&.{ 0, 0, 0xff, 0xff });
        return out.items.len - start;
    }

    fn ensureWorkspace(
        self: *RawFixedSyncFlushEncoder,
        input_len: usize,
        window_len: usize,
    ) !void {
        if (input_len > std.math.maxInt(u32)) return error.IntegerOverflow;
        if (self.heads.items.len != hash_size) {
            try self.heads.resize(self.allocator, hash_size);
            errdefer self.heads.clearAndFree(self.allocator);
            try self.epochs.resize(self.allocator, hash_size);
            @memset(self.epochs.items, 0);
        }
        try self.previous.resize(
            self.allocator,
            @min(input_len, window_len),
        );
    }

    fn beginMessage(self: *RawFixedSyncFlushEncoder) void {
        self.epoch +%= 1;
        if (self.epoch == 0) {
            @memset(self.epochs.items, 0);
            self.epoch = 1;
        }
    }

    const Match = struct { len: usize = 0, distance: usize = 0 };

    fn findAndInsert(
        self: *RawFixedSyncFlushEncoder,
        input: Input,
        pos: usize,
        options: CompressionOptions,
    ) Match {
        if (pos + min_match > input.total) return .{};
        const bucket = inputHash(input, pos);
        var candidate = if (self.epochs.items[bucket] == self.epoch)
            self.heads.items[bucket]
        else
            no_position;

        var best: Match = .{};
        var checked: usize = 0;
        const maximum = @min(max_match, input.total - pos);
        while (candidate != no_position and
            checked < options.lz77_options.max_chain)
        {
            const previous_pos: usize = candidate;
            if (previous_pos >= pos) break;
            const distance = pos - previous_pos;
            if (distance > options.lz77_options.window_len) break;
            var len: usize = 0;
            if (input.contiguous) |bytes| {
                while (len < maximum and
                    bytes[previous_pos + len] == bytes[pos + len])
                {
                    len += 1;
                }
            } else {
                var previous_cursor = Input.Cursor.init(input, previous_pos);
                var current_cursor = Input.Cursor.init(input, pos);
                while (len < maximum and
                    previous_cursor.next() == current_cursor.next())
                {
                    len += 1;
                }
            }
            if (len >= min_match and len > best.len) {
                best = .{ .len = len, .distance = distance };
                if (len >= options.lz77_options.nice_len or len == maximum) {
                    break;
                }
            }
            candidate = self.previous.items[
                previous_pos % self.previous.items.len
            ];
            checked += 1;
        }
        self.previous.items[pos % self.previous.items.len] =
            if (self.epochs.items[bucket] == self.epoch)
                self.heads.items[bucket]
            else
                no_position;
        self.heads.items[bucket] = @intCast(pos);
        self.epochs.items[bucket] = self.epoch;
        return best;
    }

    fn insert(
        self: *RawFixedSyncFlushEncoder,
        input: Input,
        pos: usize,
    ) void {
        if (pos + min_match > input.total) return;
        const bucket = inputHash(input, pos);
        self.previous.items[pos % self.previous.items.len] =
            if (self.epochs.items[bucket] == self.epoch)
                self.heads.items[bucket]
            else
                no_position;
        self.heads.items[bucket] = @intCast(pos);
        self.epochs.items[bucket] = self.epoch;
    }
};

pub fn encodeRawFixedSyncFlushAppend(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    input: []const u8,
    options: CompressionOptions,
) !usize {
    var encoder = RawFixedSyncFlushEncoder.init(allocator);
    defer encoder.deinit();
    return encoder.encodeAppend(out, input, options);
}

pub fn encodeRawFixedSyncFlushChunksAppend(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    chunks: []const []const u8,
    options: CompressionOptions,
) !usize {
    var encoder = RawFixedSyncFlushEncoder.init(allocator);
    defer encoder.deinit();
    return encoder.encodeChunksAppend(out, chunks, options);
}

pub fn encodeZlibLevelAlloc(
    allocator: std.mem.Allocator,
    input: []const u8,
    level: u4,
) ![]u8 {
    return encodeWrappedAlloc(allocator, input, .zlib, level);
}

pub fn encodeGzipLevelAlloc(
    allocator: std.mem.Allocator,
    input: []const u8,
    level: u4,
) ![]u8 {
    return encodeWrappedAlloc(allocator, input, .gzip, level);
}

pub fn decodeZlibAllocLimited(
    allocator: std.mem.Allocator,
    input: []const u8,
    max_output_len: usize,
) ![]u8 {
    return decodeWrappedAllocLimited(allocator, input, .zlib, max_output_len);
}

pub fn decodeGzipAppendLimited(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    input: []const u8,
    max_output_len: usize,
) !usize {
    const start = out.items.len;
    const decoded = try decodeWrappedAllocLimited(
        allocator,
        input,
        .gzip,
        max_output_len,
    );
    defer allocator.free(decoded);
    errdefer out.items.len = start;
    try out.appendSlice(allocator, decoded);
    return decoded.len;
}

fn encodeWrappedAlloc(
    allocator: std.mem.Allocator,
    input: []const u8,
    container: std.compress.flate.Container,
    level: u4,
) ![]u8 {
    if (level > 9) return error.InvalidBlockPlan;
    if (level == 0) {
        return encodeStoredWrappedAlloc(allocator, input, container);
    }
    const options = compressionOptions(level) orelse
        return error.InvalidBlockPlan;
    const window = try allocator.alloc(
        u8,
        std.compress.flate.max_window_len,
    );
    defer allocator.free(window);
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    try output.ensureTotalCapacity(input.len +| container.size() +| 64);
    var compressor = try std.compress.flate.Compress.init(
        &output.writer,
        window,
        container,
        options,
    );
    try compressor.writer.writeAll(input);
    try compressor.finish();
    return output.toOwnedSlice();
}

fn encodeStoredWrappedAlloc(
    allocator: std.mem.Allocator,
    input: []const u8,
    container: std.compress.flate.Container,
) ![]u8 {
    const deflate_len = try storedDeflateLen(input.len);
    const required = std.math.add(
        usize,
        container.size(),
        deflate_len,
    ) catch return error.IntegerOverflow;
    const out = try allocator.alloc(u8, required);
    errdefer allocator.free(out);
    var offset: usize = 0;
    const header = container.header();
    @memcpy(out[offset..][0..header.len], header);
    offset += header.len;
    offset += try writeStoredDeflate(out[offset..], input);
    switch (container) {
        .raw => {},
        .zlib => {
            std.mem.writeInt(
                u32,
                out[offset..][0..4],
                std.hash.Adler32.hash(input),
                .big,
            );
            offset += 4;
        },
        .gzip => {
            std.mem.writeInt(
                u32,
                out[offset..][0..4],
                std.hash.crc.Crc32.hash(input),
                .little,
            );
            std.mem.writeInt(
                u32,
                out[offset + 4 ..][0..4],
                @truncate(input.len),
                .little,
            );
            offset += 8;
        },
    }
    std.debug.assert(offset == out.len);
    return out;
}

fn decodeWrappedAllocLimited(
    allocator: std.mem.Allocator,
    input: []const u8,
    container: std.compress.flate.Container,
    max_output_len: usize,
) ![]u8 {
    var input_reader: std.Io.Reader = .fixed(input);
    const window = try allocator.alloc(
        u8,
        std.compress.flate.max_window_len,
    );
    defer allocator.free(window);
    var decompressor = std.compress.flate.Decompress.init(
        &input_reader,
        container,
        window,
    );
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    while (decompressor.reader.peekGreedy(1)) |bytes| {
        if (bytes.len > max_output_len -| output.writer.end) {
            return error.OutputLimitExceeded;
        }
        try output.writer.writeAll(bytes);
        decompressor.reader.toss(bytes.len);
    } else |err| switch (err) {
        error.EndOfStream => {},
        error.ReadFailed => return error.InvalidCompressedData,
    }
    if (decompressor.err != null) return error.InvalidCompressedData;
    if (input_reader.seek != input_reader.end) return error.TrailingBytes;
    const decoded = output.written();
    switch (container) {
        .raw => {},
        .zlib => {
            if (input.len < 4 or
                std.mem.readInt(u32, input[input.len - 4 ..][0..4], .big) !=
                    std.hash.Adler32.hash(decoded))
            {
                return error.InvalidCompressedData;
            }
        },
        .gzip => {
            if (input.len < 8 or
                std.mem.readInt(u32, input[input.len - 8 ..][0..4], .little) !=
                    std.hash.crc.Crc32.hash(decoded) or
                std.mem.readInt(u32, input[input.len - 4 ..][0..4], .little) !=
                    @as(u32, @truncate(decoded.len)))
            {
                return error.InvalidCompressedData;
            }
        },
    }
    return output.toOwnedSlice();
}

fn compressionOptions(level: u4) ?std.compress.flate.Compress.Options {
    return switch (level) {
        0, 1 => .level_1,
        2 => .level_2,
        3 => .level_3,
        4 => .level_4,
        5 => .level_5,
        6 => .level_6,
        7 => .level_7,
        8 => .level_8,
        9 => .level_9,
        else => null,
    };
}

fn inputHash(input: Input, pos: usize) usize {
    if (input.contiguous) |bytes| {
        const value = (@as(u32, bytes[pos]) << 16) |
            (@as(u32, bytes[pos + 1]) << 8) |
            bytes[pos + 2];
        return ((value *% 2654435761) >> (32 - hash_bits)) &
            (hash_size - 1);
    }
    var cursor = Input.Cursor.init(input, pos);
    const value = (@as(u32, cursor.next()) << 16) |
        (@as(u32, cursor.next()) << 8) |
        cursor.next();
    return ((value *% 2654435761) >> (32 - hash_bits)) &
        (hash_size - 1);
}

fn reverseBits(value: u16, count: u5) u16 {
    return @bitReverse(value) >> @intCast(16 - count);
}

fn writeFixedSymbol(bits: *Bits, symbol: u16) void {
    if (symbol <= 143) {
        bits.write(reverseBits(symbol + 0x30, 8), 8);
    } else if (symbol <= 255) {
        bits.write(reverseBits(symbol - 144 + 0x190, 9), 9);
    } else if (symbol <= 279) {
        bits.write(reverseBits(symbol - 256, 7), 7);
    } else {
        bits.write(reverseBits(symbol - 280 + 0xc0, 8), 8);
    }
}

const length_bases = [_]u16{
    3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23,  27,
    31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
};
const length_extra = [_]u4{
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
    2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
};

fn writeLength(bits: *Bits, length: usize) void {
    var index: usize = 0;
    while (index + 1 < length_bases.len and
        length >= length_bases[index + 1]) : (index += 1)
    {}
    writeFixedSymbol(bits, @intCast(257 + index));
    const extra = length_extra[index];
    if (extra != 0) {
        bits.write(length - length_bases[index], extra);
    }
}

const distance_bases = [_]u16{
    1,   2,   3,   4,   5,   7,    9,    13,   17,   25,   33,   49,   65,    97,    129,
    193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
};
const distance_extra = [_]u4{
    0, 0, 0, 0, 1, 1, 2, 2,  3,  3,  4,  4,  5,  5,  6,
    6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
};

fn writeDistance(bits: *Bits, distance: usize) void {
    var index: usize = 0;
    while (index + 1 < distance_bases.len and
        distance >= distance_bases[index + 1]) : (index += 1)
    {}
    bits.write(reverseBits(@intCast(index), 5), 5);
    const extra = distance_extra[index];
    if (extra != 0) {
        bits.write(distance - distance_bases[index], extra);
    }
}

fn writeLiteral(bits: *Bits, byte: u8) void {
    writeFixedSymbol(bits, byte);
}

const stored_header_overhead: usize = 5;

fn storedDeflateLen(input_len: usize) !usize {
    const blocks = @max(
        @as(usize, 1),
        (input_len + std.math.maxInt(u16) - 1) /
            std.math.maxInt(u16),
    );
    return std.math.add(
        usize,
        input_len,
        std.math.mul(usize, blocks, stored_header_overhead) catch
            return error.IntegerOverflow,
    ) catch return error.IntegerOverflow;
}

fn writeStoredDeflate(
    out: []u8,
    input: []const u8,
) !usize {
    var output_offset: usize = 0;
    var input_offset: usize = 0;
    while (input_offset < input.len or
        (input.len == 0 and input_offset == 0))
    {
        const count = @min(
            input.len - input_offset,
            std.math.maxInt(u16),
        );
        const len: u16 = @intCast(count);
        out[output_offset] =
            @intFromBool(input_offset + count == input.len);
        std.mem.writeInt(
            u16,
            out[output_offset + 1 ..][0..2],
            len,
            .little,
        );
        std.mem.writeInt(
            u16,
            out[output_offset + 3 ..][0..2],
            ~len,
            .little,
        );
        @memcpy(
            out[output_offset + stored_header_overhead ..][0..count],
            input[input_offset..][0..count],
        );
        output_offset += stored_header_overhead + count;
        input_offset += count;
        if (input.len == 0) break;
    }
    return output_offset;
}

test "focused raw sync flush round trips all byte values and split input" {
    const allocator = std.testing.allocator;
    var payload: [1024]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index);
    const chunks = [_][]const u8{
        payload[0..1],
        payload[1..257],
        payload[257..700],
        payload[700..],
    };
    var encoder = RawFixedSyncFlushEncoder.init(allocator);
    defer encoder.deinit();
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    _ = try encoder.encodeChunksAppend(&encoded, &chunks, .{});
    try encoded.appendSlice(allocator, &.{
        0x01, 0x00, 0x00, 0xff, 0xff,
    });
    var input: std.Io.Reader = .fixed(encoded.items);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var decoder = std.compress.flate.Decompress.init(
        &input,
        .raw,
        &window,
    );
    var output: [payload.len]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&output);
    try std.testing.expectEqual(
        payload.len,
        try decoder.reader.streamRemaining(&writer),
    );
    try std.testing.expectEqualSlices(u8, &payload, writer.buffered());
}

test "focused wrapped decoder rejects corruption and trailing bytes" {
    const allocator = std.testing.allocator;
    const payload = "wrapped payload " ** 32;
    for ([_]std.compress.flate.Container{ .zlib, .gzip }) |container| {
        const encoded = try encodeWrappedAlloc(
            allocator,
            payload,
            container,
            6,
        );
        defer allocator.free(encoded);
        const decoded = try decodeWrappedAllocLimited(
            allocator,
            encoded,
            container,
            payload.len,
        );
        defer allocator.free(decoded);
        try std.testing.expectEqualStrings(payload, decoded);
        try std.testing.expectError(
            error.OutputLimitExceeded,
            decodeWrappedAllocLimited(
                allocator,
                encoded,
                container,
                payload.len - 1,
            ),
        );
        const trailed = try std.mem.concat(allocator, u8, &.{ encoded, "x" });
        defer allocator.free(trailed);
        try std.testing.expectError(
            error.TrailingBytes,
            decodeWrappedAllocLimited(
                allocator,
                trailed,
                container,
                payload.len,
            ),
        );
        const corrupted = try allocator.dupe(u8, encoded);
        defer allocator.free(corrupted);
        corrupted[corrupted.len - 1] ^= 1;
        try std.testing.expectError(
            error.InvalidCompressedData,
            decodeWrappedAllocLimited(
                allocator,
                corrupted,
                container,
                payload.len,
            ),
        );
    }
}
