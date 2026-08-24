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
        // The only legal incomplete suffix is EOS-prefix padding of at most
        // seven one bits. Both compression formats share this exact rule.
        if (pending_bits > 7) return error.InvalidEncoding;
        const padding = (@as(u32, 1) << @as(u5, @intCast(pending_bits))) - 1;
        if (pending_code != padding) return error.InvalidEncoding;
    }

    if (out_index != out.len) return error.InvalidEncoding;
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
