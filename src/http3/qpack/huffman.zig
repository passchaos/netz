//! Canonical Huffman coding shared by HPACK and QPACK.

const std = @import("std");
const hpack_huffman = @import("../../http2/hpack_huffman.zig");

/// Encode an RFC 9204/HPACK canonical Huffman string.
pub fn encodeHuffman(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    return encodeHuffmanWithLen(allocator, value, try encodedLen(value));
}

pub fn encodeHuffmanWithLen(allocator: std.mem.Allocator, value: []const u8, encoded_len: usize) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.ensureTotalCapacity(allocator, encoded_len);

    var bits: u64 = 0;
    var bits_left: u6 = 40;
    for (value) |byte| {
        const entry = hpack_huffman.encode_table[byte];
        bits |= @as(u64, entry.code) << @intCast(bits_left - entry.bits);
        bits_left -= entry.bits;

        while (bits_left <= 32) {
            try out.append(allocator, @truncate(bits >> 32));
            bits <<= 8;
            bits_left += 8;
        }
    }

    if (bits_left != 40) {
        // QPACK reuses HPACK's canonical Huffman code (RFC 9204 §4.1.2),
        // including EOS-prefix padding of the final octet.
        bits |= (@as(u64, 1) << bits_left) - 1;
        try out.append(allocator, @truncate(bits >> 32));
    }
    std.debug.assert(out.items.len == encoded_len);
    return out.toOwnedSlice(allocator);
}

pub fn encodedLen(value: []const u8) !usize {
    var bit_len: usize = 0;
    for (value) |byte| {
        bit_len = std.math.add(usize, bit_len, hpack_huffman.encode_table[byte].bits) catch return error.IntegerOverflow;
    }
    return std.math.divCeil(usize, bit_len, 8) catch unreachable;
}

/// Decode an RFC 9204/HPACK canonical Huffman string.
pub fn decodeHuffman(allocator: std.mem.Allocator, encoded: []const u8) ![]u8 {
    if (encoded.len == 0) return @constCast(&[_]u8{});
    const decoded_len = try decodedLen(encoded);
    const out = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(out);
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
            if (pending_bits > huffman_max_code_bits) return error.InvalidEncoding;

            const next = huffman_decode_trie[node].child[bit] orelse return error.InvalidEncoding;
            node = next;
            if (huffman_decode_trie[node].symbol) |symbol| {
                if (symbol == hpack_huffman.eos_symbol) return error.InvalidEncoding;
                out[out_index] = @intCast(symbol);
                out_index += 1;
                node = huffman_root_node;
                pending_code = 0;
                pending_bits = 0;
            }
        }
    }

    if (pending_bits != 0) {
        // The only legal incomplete suffix is EOS-prefix padding of at
        // most seven one bits.  QPACK inherits this exact Huffman coding
        // from HPACK (RFC 9204 §4.1.2).
        if (pending_bits > 7) return error.InvalidEncoding;
        const padding = (@as(u32, 1) << @as(u5, @intCast(pending_bits))) - 1;
        if (pending_code != padding) return error.InvalidEncoding;
    }

    std.debug.assert(out_index == out.len);
    return out;
}

pub fn decodedLen(encoded: []const u8) !usize {
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
            if (pending_bits > huffman_max_code_bits) return error.InvalidEncoding;

            const next = huffman_decode_trie[node].child[bit] orelse return error.InvalidEncoding;
            node = next;
            if (huffman_decode_trie[node].symbol) |symbol| {
                if (symbol == hpack_huffman.eos_symbol) return error.InvalidEncoding;
                len = std.math.add(usize, len, 1) catch return error.IntegerOverflow;
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
