//! Canonical Huffman coding shared by HTTP/2 HPACK and HTTP/3 QPACK.

const std = @import("std");
const hpack_huffman = @import("hpack_huffman_table.zig");

/// Encode an RFC 9204/HPACK canonical Huffman string.
pub fn encodeHuffman(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    return encodeHuffmanExact(allocator, value, try encodedLen(value));
}

pub fn encodeHuffmanWithLen(allocator: std.mem.Allocator, value: []const u8, encoded_len: usize) ![]u8 {
    // This entry point is public through HPACK, so reject a stale caller-
    // supplied length rather than letting the unchecked writer overrun or
    // leave part of its allocation uninitialized in release builds.
    if (encoded_len != try encodedLen(value)) return error.InvalidEncoding;
    return encodeHuffmanExact(allocator, value, encoded_len);
}

fn encodeHuffmanExact(allocator: std.mem.Allocator, value: []const u8, encoded_len: usize) ![]u8 {
    const out = try allocator.alloc(u8, encoded_len);
    errdefer allocator.free(out);
    encodeHuffmanInto(out, value);
    return out;
}

pub fn appendHuffmanAssumeCapacity(
    list: *std.ArrayList(u8),
    value: []const u8,
    encoded_len: usize,
) void {
    std.debug.assert(list.capacity - list.items.len >= encoded_len);
    const start_len = list.items.len;
    list.items.len = start_len + encoded_len;
    encodeHuffmanInto(list.items[start_len..], value);
}

fn encodeHuffmanInto(out: []u8, value: []const u8) void {
    var out_index: usize = 0;

    var bits: u64 = 0;
    var bits_left: u6 = 40;
    for (value) |byte| {
        const entry = hpack_huffman.encode_table[byte];
        bits |= @as(u64, entry.code) << @intCast(bits_left - entry.bits);
        bits_left -= entry.bits;

        while (bits_left <= 32) {
            std.debug.assert(out_index < out.len);
            out[out_index] = @truncate(bits >> 32);
            out_index += 1;
            bits <<= 8;
            bits_left += 8;
        }
    }

    if (bits_left != 40) {
        // HPACK defines this canonical code in RFC 7541 §5.2. QPACK reuses it
        // through RFC 9204 §4.1.2, including EOS-prefix final-octet padding.
        bits |= (@as(u64, 1) << bits_left) - 1;
        std.debug.assert(out_index < out.len);
        out[out_index] = @truncate(bits >> 32);
        out_index += 1;
    }
    std.debug.assert(out_index == out.len);
}

pub fn encodedLen(value: []const u8) !usize {
    var bit_len: usize = 0;
    for (value) |byte| {
        bit_len = std.math.add(usize, bit_len, hpack_huffman.encode_table[byte].bits) catch return error.IntegerOverflow;
    }
    return std.math.divCeil(usize, bit_len, 8) catch unreachable;
}

/// Worst-case encoded bytes: every symbol consumes at least five bits.
pub fn maxEncodedLen(value_len: usize) usize {
    const bit_len = std.math.mul(usize, value_len, 8) catch
        return std.math.maxInt(usize);
    return bit_len / 5 + @intFromBool(bit_len % 5 != 0);
}

/// Encode into a buffer sized to `maxEncodedLen(value.len)` and return the
/// exact encoded length. This lets callers obtain the length and the bytes in
/// one pass instead of running `encodedLen` first.
pub fn encodeHuffmanIntoBounded(out: []u8, value: []const u8) !usize {
    var out_index: usize = 0;
    var bits: u64 = 0;
    var bits_left: u6 = 40;
    for (value) |byte| {
        const entry = hpack_huffman.encode_table[byte];
        bits |= @as(u64, entry.code) << @intCast(bits_left - entry.bits);
        bits_left -= entry.bits;

        while (bits_left <= 32) {
            if (out_index >= out.len) return error.BufferTooShort;
            out[out_index] = @truncate(bits >> 32);
            out_index += 1;
            bits <<= 8;
            bits_left += 8;
        }
    }

    if (bits_left != 40) {
        bits |= (@as(u64, 1) << bits_left) - 1;
        if (out_index >= out.len) return error.BufferTooShort;
        out[out_index] = @truncate(bits >> 32);
        out_index += 1;
    }
    return out_index;
}

/// Decode an RFC 9204/HPACK canonical Huffman string.
pub fn decodeHuffman(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
    if (encoded.len == 0) return @constCast(&[_]u8{});
    const decoded_len = try decodedLen(encoded);
    return decodeHuffmanWithLen(allocator, encoded, decoded_len);
}

pub fn decodeHuffmanWithLen(
    allocator: std.mem.Allocator,
    encoded: []const u8,
    decoded_len: usize,
) ![]u8 {
    if (encoded.len == 0) {
        if (decoded_len != 0) return error.InvalidEncoding;
        return @constCast(&[_]u8{});
    }
    const out = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(out);
    try decodeHuffmanInto(out, encoded);
    return out;
}

/// Decode into exactly sized caller storage. The bounds checks keep this safe
/// for public callers while allowing QPACK to scan a Huffman string, enforce
/// its uncompressed field budget, and then decode without another allocation.
pub fn decodeHuffmanInto(out: []u8, encoded: []const u8) !void {
    const written = decodeInternal(true, out, encoded) catch |err| switch (err) {
        error.BufferTooShort => return error.InvalidEncoding,
        else => return err,
    };
    if (written != out.len) return error.InvalidEncoding;
}

/// Decode into caller storage that may be larger than the decoded string.
/// Returns the number of bytes written. `error.BufferTooShort` reports that
/// the storage was too small, so a caller can retry with `decodedLen` instead
/// of running a separate length pass before every decode.
pub fn decodeHuffmanIntoBounded(out: []u8, encoded: []const u8) !usize {
    return decodeInternal(true, out, encoded);
}

pub fn decodedLen(encoded: []const u8) !usize {
    return decodeInternal(false, &.{}, encoded);
}

/// Decode through a 12-bit root table and fall back to the trie only for
/// longer codes. HPACK's shortest code is five bits, so at most two symbols
/// can complete inside one 12-bit window.
fn decodeInternal(
    comptime write_output: bool,
    out: []u8,
    encoded: []const u8,
) !usize {
    var out_index: usize = 0;
    var buffer: u64 = 0;
    var bit_count: u8 = 0;
    var input_index: usize = 0;
    var node: u16 = huffman_root_node;
    var pending_bits: usize = 0;

    while (true) {
        while (bit_count < huffman_root_table_bits and
            input_index < encoded.len)
        {
            buffer = (buffer << 8) | encoded[input_index];
            bit_count += 8;
            input_index += 1;
        }
        if (bit_count < huffman_root_table_bits) break;

        const shift: u6 = @intCast(bit_count - huffman_root_table_bits);
        const index: u12 = @truncate(buffer >> shift);
        const entry = huffman_root_table[index];
        if (entry.count != 0) {
            for (entry.symbols[0..@intCast(entry.count)]) |symbol| {
                if (write_output) {
                    if (out_index >= out.len) return error.BufferTooShort;
                    out[out_index] = symbol;
                }
                out_index += 1;
            }
            consumeBits(&buffer, &bit_count, entry.bits);
            node = huffman_root_node;
            pending_bits = 0;
            continue;
        }
        if (entry.node == huffman_invalid_node) return error.InvalidEncoding;

        // Codes longer than the root-table window fall back to the trie. The
        // table entry already validated the first 12 bits as a live prefix.
        consumeBits(&buffer, &bit_count, huffman_root_table_bits);
        pending_bits += huffman_root_table_bits;
        node = entry.node;
        while (true) {
            if (bit_count == 0) {
                if (input_index == encoded.len) break;
                buffer = (buffer << 8) | encoded[input_index];
                bit_count += 8;
                input_index += 1;
            }
            const bit: u1 = @truncate(buffer >> @intCast(bit_count - 1));
            bit_count -= 1;
            buffer &= (@as(u64, 1) << @intCast(bit_count)) - 1;
            pending_bits += 1;
            const next = huffman_decode_trie[node].child[bit] orelse
                return error.InvalidEncoding;
            node = next;
            if (huffman_decode_trie[node].symbol) |symbol| {
                if (symbol == hpack_huffman.eos_symbol) {
                    return error.InvalidEncoding;
                }
                if (write_output) {
                    if (out_index >= out.len) return error.BufferTooShort;
                    out[out_index] = @intCast(symbol);
                }
                out_index += 1;
                node = huffman_root_node;
                pending_bits = 0;
                break;
            }
            if (pending_bits > huffman_max_code_bits) {
                return error.InvalidEncoding;
            }
        }
    }

    // Drain the remaining buffered bits through the trie.
    while (bit_count != 0) {
        const bit: u1 = @truncate(buffer >> @intCast(bit_count - 1));
        bit_count -= 1;
        buffer &= (@as(u64, 1) << @intCast(bit_count)) - 1;
        pending_bits += 1;
        const next = huffman_decode_trie[node].child[bit] orelse
            return error.InvalidEncoding;
        node = next;
        if (huffman_decode_trie[node].symbol) |symbol| {
            if (symbol == hpack_huffman.eos_symbol) {
                return error.InvalidEncoding;
            }
            if (write_output) {
                if (out_index >= out.len) return error.BufferTooShort;
                out[out_index] = @intCast(symbol);
            }
            out_index += 1;
            node = huffman_root_node;
            pending_bits = 0;
        }
    }

    if (pending_bits != 0) {
        // The only legal incomplete suffix is EOS-prefix padding of at most
        // seven one bits. Both compression formats share this exact rule.
        if (pending_bits > 7) return error.InvalidEncoding;
        const mask = (@as(u8, 1) << @as(u3, @intCast(pending_bits))) - 1;
        if (encoded[encoded.len - 1] & mask != mask) {
            return error.InvalidEncoding;
        }
    }

    return out_index;
}

fn consumeBits(buffer: *u64, bit_count: *u8, count: u8) void {
    bit_count.* -= count;
    buffer.* &= (@as(u64, 1) << @intCast(bit_count.*)) - 1;
}

const huffman_root_node: u16 = 0;
const huffman_max_code_bits: u6 = 30;

const HuffmanDecodeNode = struct {
    child: [2]?u16 = .{ null, null },
    symbol: ?u16 = null,
};

const huffman_decode_trie = buildHuffmanDecodeTrie();

fn buildHuffmanDecodeTrie() [huffman_decode_node_count]HuffmanDecodeNode {
    @setEvalBranchQuota(200_000);
    var nodes = [_]HuffmanDecodeNode{.{}} ** huffman_decode_node_count;
    var used: u16 = 1;

    for (hpack_huffman.encode_table, 0..) |entry, symbol| {
        var node: u16 = huffman_root_node;
        var bit_index: u6 = 0;
        while (bit_index < entry.bits) : (bit_index += 1) {
            const shift: u5 = @intCast(entry.bits - 1 - bit_index);
            const bit: u1 = @truncate((entry.code >> shift) & 1);
            if (nodes[node].child[bit] == null) {
                nodes[node].child[bit] = used;
                used += 1;
            }
            node = nodes[node].child[bit].?;
        }
        nodes[node].symbol = @intCast(symbol);
    }

    return nodes;
}

const huffman_decode_node_count = blk: {
    var count: usize = 1;
    for (hpack_huffman.encode_table) |entry| count += entry.bits;
    break :blk count;
};

const huffman_root_table_bits: u8 = 12;
const huffman_invalid_node: u16 = std.math.maxInt(u16);

const RootTableEntry = struct {
    symbols: [2]u8 = .{ 0, 0 },
    count: u8 = 0,
    bits: u8 = huffman_root_table_bits,
    node: u16 = huffman_invalid_node,
};

const huffman_root_table = buildRootTable();

fn buildRootTable() [4096]RootTableEntry {
    @setEvalBranchQuota(2_000_000);
    var table: [4096]RootTableEntry = undefined;
    for (0..4096) |prefix| {
        var entry: RootTableEntry = .{};
        var node: u16 = huffman_root_node;
        var consumed: u8 = 0;
        var last_symbol_end: u8 = 0;
        var bit_index: u8 = 0;
        var valid = true;
        while (bit_index < 12) : (bit_index += 1) {
            const shift: u6 = @intCast(11 - bit_index);
            const bit: u1 = @truncate((prefix >> shift) & 1);
            const next = huffman_decode_trie[node].child[bit] orelse {
                valid = false;
                break;
            };
            node = next;
            consumed += 1;
            if (huffman_decode_trie[node].symbol) |symbol| {
                if (symbol == hpack_huffman.eos_symbol) {
                    valid = false;
                    break;
                }
                if (entry.count == entry.symbols.len) {
                    // Three symbols cannot fit in 12 bits (5 + 5 + 5 > 12);
                    // keep the guard so a table change cannot truncate.
                    valid = false;
                    break;
                }
                entry.symbols[@intCast(entry.count)] = @intCast(symbol);
                entry.count += 1;
                last_symbol_end = consumed;
                node = huffman_root_node;
            }
        }
        if (!valid) {
            table[prefix] = .{};
            continue;
        }
        if (entry.count == 0) {
            // No symbol completed; `node` is the live trie prefix after 12 bits.
            entry.bits = huffman_root_table_bits;
            entry.node = node;
        } else {
            // Consume through the last completed symbol. Any remaining bits in
            // the window belong to the next code and stay buffered.
            entry.bits = last_symbol_end;
            entry.node = huffman_root_node;
        }
        table[prefix] = entry;
    }
    return table;
}

test "Huffman roundtrip covers every byte and random strings" {
    const alloc = std.testing.allocator;
    for (0..256) |b| {
        const input = [_]u8{@intCast(b)};
        const encoded = try encodeHuffman(alloc, &input);
        defer alloc.free(encoded);
        try std.testing.expectEqual(@as(usize, 1), try decodedLen(encoded));
        const decoded = try decodeHuffman(alloc, encoded);
        defer alloc.free(decoded);
        try std.testing.expectEqualSlices(u8, &input, decoded);
        var exact: [1]u8 = undefined;
        try decodeHuffmanInto(&exact, encoded);
        try std.testing.expectEqual(input[0], exact[0]);
    }

    for (0..256) |a| {
        for (0..256) |b| {
            const input = [_]u8{ @intCast(a), @intCast(b) };
            var encoded_buf: [8]u8 = undefined;
            const encoded_len = try encodedLen(&input);
            encodeHuffmanInto(encoded_buf[0..encoded_len], &input);
            try std.testing.expectEqual(
                @as(usize, 2),
                try decodedLen(encoded_buf[0..encoded_len]),
            );
            var exact: [2]u8 = undefined;
            try decodeHuffmanInto(&exact, encoded_buf[0..encoded_len]);
            try std.testing.expectEqualSlices(u8, &input, &exact);
        }
    }

    var prng = std.Random.DefaultPrng.init(0x12345678);
    const random = prng.random();
    for (0..512) |_| {
        var buf: [64]u8 = undefined;
        const len = random.intRangeAtMost(usize, 0, buf.len);
        random.bytes(buf[0..len]);
        const encoded = try encodeHuffman(alloc, buf[0..len]);
        defer alloc.free(encoded);
        try std.testing.expectEqual(len, try decodedLen(encoded));
        const decoded = try decodeHuffman(alloc, encoded);
        defer alloc.free(decoded);
        try std.testing.expectEqualSlices(u8, buf[0..len], decoded);
    }
}

test "Huffman rejects EOS and non-one padding" {
    const alloc = std.testing.allocator;
    // EOS is 30 one bits; four 0xff bytes contain it directly.
    const eos = [_]u8{ 0xff, 0xff, 0xff, 0xff };
    try std.testing.expectError(
        error.InvalidEncoding,
        decodedLen(&eos),
    );
    try std.testing.expectError(
        error.InvalidEncoding,
        decodeHuffman(alloc, &eos),
    );
    var out: [1]u8 = undefined;
    try std.testing.expectError(
        error.InvalidEncoding,
        decodeHuffmanInto(&out, &eos),
    );

    // '0' is the five-bit code 00000; the remaining three zero bits are not
    // legal EOS-prefix padding.
    const zero_padding = [_]u8{0x00};
    try std.testing.expectError(
        error.InvalidEncoding,
        decodedLen(&zero_padding),
    );
    try std.testing.expectError(
        error.InvalidEncoding,
        decodeHuffman(alloc, &zero_padding),
    );
}

test "bounded decode reports the written length and overflow" {
    const alloc = std.testing.allocator;
    const value = "bounded huffman decode";
    const encoded = try encodeHuffman(alloc, value);
    defer alloc.free(encoded);

    var large: [64]u8 = undefined;
    const written = try decodeHuffmanIntoBounded(&large, encoded);
    try std.testing.expectEqual(value.len, written);
    try std.testing.expectEqualSlices(u8, value, large[0..written]);

    var exact: [value.len]u8 = undefined;
    try std.testing.expectEqual(
        @as(usize, value.len),
        try decodeHuffmanIntoBounded(&exact, encoded),
    );
    try std.testing.expectEqualSlices(u8, value, &exact);

    var small: [value.len - 1]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooShort,
        decodeHuffmanIntoBounded(&small, encoded),
    );
    // The exact-size public API keeps its historical error contract.
    try std.testing.expectError(
        error.InvalidEncoding,
        decodeHuffmanInto(&small, encoded),
    );

    const eos = [_]u8{ 0xff, 0xff, 0xff, 0xff };
    try std.testing.expectError(
        error.InvalidEncoding,
        decodeHuffmanIntoBounded(&large, &eos),
    );
}

test "table decoder matches the bit-by-bit reference on random input" {
    const alloc = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x5eed5eed);
    const random = prng.random();
    for (0..20_000) |_| {
        var buf: [48]u8 = undefined;
        const len = random.intRangeAtMost(usize, 0, buf.len);
        random.bytes(buf[0..len]);
        const encoded = buf[0..len];

        const new_len = decodedLen(encoded);
        const ref_len = referenceDecodedLen(encoded);
        if (new_len) |value| {
            const reference_value = ref_len catch
                return error.TestUnexpectedResult;
            try std.testing.expectEqual(reference_value, value);
            const decoded = try alloc.alloc(u8, value);
            defer alloc.free(decoded);
            try decodeHuffmanInto(decoded, encoded);
            const reference = try alloc.alloc(u8, value);
            defer alloc.free(reference);
            try referenceDecodeInto(reference, encoded);
            try std.testing.expectEqualSlices(u8, reference, decoded);
        } else |new_error| {
            if (ref_len) |_| return error.TestUnexpectedResult else |reference_error| {
                try std.testing.expectEqual(new_error, reference_error);
            }
            var output: [128]u8 = undefined;
            try std.testing.expectError(
                new_error,
                decodeHuffmanInto(&output, encoded),
            );
        }
    }
}

/// The original bit-by-bit walker retained as an independent oracle for the
/// table-driven decoder. Test-only; production uses `decodeInternal`.
fn referenceDecodeInto(out: []u8, encoded: []const u8) !void {
    var out_index: usize = 0;
    var node: u16 = huffman_root_node;
    var pending_code: u32 = 0;
    var pending_bits: u6 = 0;
    for (encoded) |byte| {
        var bit_index: u4 = 0;
        while (bit_index < 8) : (bit_index += 1) {
            const bit: u1 = @truncate((byte >> @intCast(7 - bit_index)) & 1);
            pending_code = (pending_code << 1) | bit;
            pending_bits += 1;
            if (pending_bits > huffman_max_code_bits) {
                return error.InvalidEncoding;
            }
            const next = huffman_decode_trie[node].child[bit] orelse
                return error.InvalidEncoding;
            node = next;
            if (huffman_decode_trie[node].symbol) |symbol| {
                if (symbol == hpack_huffman.eos_symbol) {
                    return error.InvalidEncoding;
                }
                if (out_index >= out.len) return error.InvalidEncoding;
                out[out_index] = @intCast(symbol);
                out_index += 1;
                node = huffman_root_node;
                pending_code = 0;
                pending_bits = 0;
            }
        }
    }
    if (pending_bits != 0) {
        if (pending_bits > 7) return error.InvalidEncoding;
        const padding = (@as(u32, 1) << @as(u5, @intCast(pending_bits))) - 1;
        if (pending_code != padding) return error.InvalidEncoding;
    }
    if (out_index != out.len) return error.InvalidEncoding;
}

fn referenceDecodedLen(encoded: []const u8) !usize {
    if (encoded.len == 0) return 0;
    var len: usize = 0;
    var node: u16 = huffman_root_node;
    var pending_code: u32 = 0;
    var pending_bits: u6 = 0;
    for (encoded) |byte| {
        var bit_index: u4 = 0;
        while (bit_index < 8) : (bit_index += 1) {
            const bit: u1 = @truncate((byte >> @intCast(7 - bit_index)) & 1);
            pending_code = (pending_code << 1) | bit;
            pending_bits += 1;
            if (pending_bits > huffman_max_code_bits) {
                return error.InvalidEncoding;
            }
            const next = huffman_decode_trie[node].child[bit] orelse
                return error.InvalidEncoding;
            node = next;
            if (huffman_decode_trie[node].symbol) |symbol| {
                if (symbol == hpack_huffman.eos_symbol) {
                    return error.InvalidEncoding;
                }
                len = std.math.add(usize, len, 1) catch
                    return error.IntegerOverflow;
                node = huffman_root_node;
                pending_code = 0;
                pending_bits = 0;
            }
        }
    }
    if (pending_bits != 0) {
        if (pending_bits > 7) return error.InvalidEncoding;
        const padding = (@as(u32, 1) << @as(u5, @intCast(pending_bits))) - 1;
        if (pending_code != padding) return error.InvalidEncoding;
    }
    return len;
}
