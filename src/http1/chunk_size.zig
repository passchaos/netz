//! Shared chunk-size syntax and bounded per-message metadata accounting.
const std = @import("std");
const http1 = @import("mod.zig");
const extension = @import("chunk_extension.zig");

pub const Error = http1.Error || error{ChunkSizeOverheadTooLarge};

pub const State = struct {
    extension_bytes: usize = 0,
    overhead_bytes: usize = 0,

    /// Commit credit only after a complete size line validates. Canonical
    /// hexadecimal digits belong to required framing; leading zeroes,
    /// whitespace and extensions share the extra allowance.
    pub fn feed(self: *State, line: []const u8) Error!usize {
        if (line.len >= http1.max_chunk_size_line_bytes) return error.ChunkExtensionTooLarge;
        const semi = std.mem.indexOfScalar(u8, line, ';') orelse line.len;
        const extra = if (semi == line.len) 0 else line.len - semi;
        const extensions = std.math.add(usize, self.extension_bytes, extra) catch return error.ChunkExtensionTooLarge;
        if (extensions > http1.max_chunk_extension_bytes) return error.ChunkExtensionTooLarge;
        if (extra != 0) try extension.validate(line[semi + 1 ..]);
        const size = try http1.parseChunkSize(try sizePart(line[0..semi]));
        const overhead = std.math.add(usize, self.overhead_bytes, line.len - hexDigitLen(size)) catch return error.ChunkSizeOverheadTooLarge;
        if (overhead > http1.max_chunk_size_line_bytes) return error.ChunkSizeOverheadTooLarge;
        self.extension_bytes = extensions;
        self.overhead_bytes = overhead;
        return size;
    }
};

pub fn hexDigitLen(value: usize) usize {
    var digits: usize = 1;
    var remaining = value;
    while (remaining >= 16) : (remaining >>= 4) digits += 1;
    return digits;
}

/// The bound excludes CRLF. A final CR may already be buffered while its LF
/// is still in flight, and does not consume a size-line byte of allowance.
pub fn validateIncomplete(bytes: []const u8) error{ChunkExtensionTooLarge}!void {
    const line_len = bytes.len - @intFromBool(std.mem.endsWith(u8, bytes, "\r"));
    if (line_len >= http1.max_chunk_size_line_bytes) return error.ChunkExtensionTooLarge;
}

pub fn sizePart(raw_size: []const u8) error{InvalidChunk}![]const u8 {
    if (raw_size.len == 0) return error.InvalidChunk;
    var end: usize = 0;
    while (end < raw_size.len and std.ascii.isHex(raw_size[end])) : (end += 1) {}
    if (end == 0) return error.InvalidChunk;
    for (raw_size[end..]) |byte| {
        if (byte != ' ' and byte != '\t') return error.InvalidChunk;
    }
    return raw_size[0..end];
}
