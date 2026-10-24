const std = @import("std");
const http1 = @import("../../mod.zig");
const wire = @import("../../../internal/wire.zig");
const chunk_extension = @import("../../chunk_extension.zig");

pub const Error = http1.Error || error{
    HeadersTooLarge,
    BodyTooLarge,
};

pub const TransferEncodingState = enum {
    none,
    chunked,
    non_chunked,
};

/// Return the exact wire boundary of one aggregate HTTP/1 message once it is
/// available. Body limits apply to decoded chunk payload, while head/trailer
/// limits apply to their own wire sections.
pub fn messageTargetLength(
    bytes: []const u8,
    head_end: usize,
    max_head_bytes: usize,
    max_body_bytes: usize,
    request_method: ?http1.Method,
) Error!usize {
    const body_start = std.math.add(usize, head_end, 4) catch
        return error.HeadersTooLarge;
    if (body_start > bytes.len) return error.BufferTooShort;
    const head = bytes[0..head_end];
    if (responseHeadForbidsBody(head, request_method)) return body_start;
    switch (try transferEncodingState(head)) {
        .none => {},
        .chunked => {
            const layout = try chunkedBodyLayout(
                bytes[body_start..],
                max_head_bytes,
                max_body_bytes,
            );
            return std.math.add(usize, body_start, layout.wire_len) catch
                return error.BodyTooLarge;
        },
        .non_chunked => {
            if (request_method == null) {
                return error.InvalidTransferEncoding;
            }
            return body_start;
        },
    }
    if (try contentLengthFromHead(head)) |len| {
        if (len > max_body_bytes) return error.BodyTooLarge;
        return std.math.add(usize, body_start, len) catch
            return error.ContentLengthOverflow;
    }
    return body_start;
}

pub fn findHeadEndWithinLimit(
    bytes: []const u8,
    max_head_bytes: usize,
) Error!?usize {
    if (std.mem.indexOf(u8, bytes, "\r\n\r\n")) |head_end| {
        const wire_len = std.math.add(usize, head_end, 4) catch
            return error.HeadersTooLarge;
        if (wire_len > max_head_bytes) return error.HeadersTooLarge;
        return head_end;
    }
    if (bytes.len >= max_head_bytes) return error.HeadersTooLarge;
    return null;
}

pub fn transferEncodingState(head: []const u8) Error!TransferEncodingState {
    var state: @import("../../transfer_encoding.zig").State = .{};
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], "transfer-encoding")) continue;
        try state.feed(line[colon + 1 ..]);
    }
    if (!state.present) return .none;
    return if (state.final_is_chunked) .chunked else .non_chunked;
}

pub fn contentLengthFromHead(head: []const u8) Error!?usize {
    var found: ?usize = null;
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(
            line[0..colon],
            "content-length",
        )) continue;
        var parts = std.mem.splitScalar(u8, line[colon + 1 ..], ',');
        while (parts.next()) |raw_part| {
            const part = wire.trimOws(raw_part);
            if (part.len == 0) return error.InvalidContentLength;
            for (part) |byte| {
                if (!std.ascii.isDigit(byte)) {
                    return error.InvalidContentLength;
                }
            }
            const parsed = std.fmt.parseInt(usize, part, 10) catch |err|
                switch (err) {
                    error.InvalidCharacter => return error.InvalidContentLength,
                    error.Overflow => return error.ContentLengthOverflow,
                };
            if (found) |existing| {
                if (existing != parsed) {
                    return error.ConflictingContentLength;
                }
            } else {
                found = parsed;
            }
        }
    }
    return found;
}

pub fn responseHeadUsesCloseDelimitedBody(
    head: []const u8,
    request_method: ?http1.Method,
) bool {
    if (responseHeadForbidsBody(head, request_method)) return false;
    const transfer_encoding = transferEncodingState(head) catch return false;
    if (transfer_encoding == .chunked) return false;
    if (transfer_encoding == .non_chunked) return true;
    return findHeaderValue(head, "content-length") == null;
}

pub fn responseHeadForbidsBody(
    head: []const u8,
    request_method: ?http1.Method,
) bool {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    const status_line = lines.next() orelse return false;
    var parts = std.mem.splitScalar(u8, status_line, ' ');
    _ = parts.next() orelse return false;
    const status_s = parts.next() orelse return false;
    if (status_s.len != 3) return false;
    const status = std.fmt.parseInt(u16, status_s, 10) catch return false;
    if ((status >= 100 and status < 200) or status == 204 or status == 304) {
        return true;
    }
    if (request_method == null) return false;
    return switch (request_method.?) {
        .HEAD => true,
        .CONNECT => status >= 200 and status < 300,
        else => false,
    };
}

pub fn informationalResponseToSkip(status: u16) bool {
    return status >= 100 and status < 200 and status != 101;
}

pub fn requestShouldSendContinue(head: []const u8) bool {
    if (!requestHeadIsHttp11(head)) return false;
    if (!requestExpectIsOnlyContinue(head)) return false;
    if (!requestHeadHasValidHost(head)) return false;
    return requestHeadHasBody(head);
}

fn requestExpectIsOnlyContinue(head: []const u8) bool {
    var found = false;
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], "expect")) continue;
        if (found) return false;
        found = true;
        if (!std.ascii.eqlIgnoreCase(
            wire.trimOws(line[colon + 1 ..]),
            "100-continue",
        )) return false;
    }
    return found;
}

fn requestHeadHasValidHost(head: []const u8) bool {
    var found = false;
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], "host")) continue;
        if (found) return false;
        found = true;
        http1.validateHostValue(line[colon + 1 ..]) catch return false;
    }
    return found;
}

fn requestHeadIsHttp11(head: []const u8) bool {
    const first_line_end = std.mem.indexOf(u8, head, "\r\n") orelse
        head.len;
    return std.mem.endsWith(
        u8,
        head[0..first_line_end],
        " HTTP/1.1",
    );
}

fn requestHeadHasBody(head: []const u8) bool {
    if ((transferEncodingState(head) catch .none) == .chunked) return true;
    if (contentLengthFromHead(head) catch null) |len| return len > 0;
    return false;
}

pub const ChunkedBodyLayout = struct {
    wire_len: usize,
    decoded_len: usize,
    trailer_start: usize,
    trailer_fields_len: usize,
};

/// Maximum aggregate wire bytes retained for a chunk-coded body. A peer may
/// encode every payload byte as a one-byte chunk (six wire bytes including
/// framing); one shared line allowance covers extensions, leading zeroes, and
/// LWS, while trailers retain their independent head-sized budget.
pub fn maxChunkedWireBytes(
    max_head_bytes: usize,
    max_body_bytes: usize,
) usize {
    const chunk_bytes = std.math.mul(usize, max_body_bytes, 6) catch
        return std.math.maxInt(usize);
    const with_line_allowance = std.math.add(
        usize,
        chunk_bytes,
        http1.max_chunk_size_line_bytes + 3,
    ) catch return std.math.maxInt(usize);
    return std.math.add(usize, with_line_allowance, max_head_bytes) catch
        std.math.maxInt(usize);
}

/// Validate one chunk-coded body and report the wire and decoded boundaries.
/// Trailer field syntax is deliberately left to the message parser because
/// its compatibility policy is supplied separately from framing limits.
pub fn chunkedBodyLayout(
    body: []const u8,
    max_head_bytes: usize,
    max_body_bytes: usize,
) Error!ChunkedBodyLayout {
    const max_wire_bytes = maxChunkedWireBytes(
        max_head_bytes,
        max_body_bytes,
    );
    var pos: usize = 0;
    var decoded_total: usize = 0;
    var extension_bytes: usize = 0;
    var line_overhead_bytes: usize = 0;
    while (true) {
        const remaining = body[pos..];
        const line_end = std.mem.indexOf(u8, remaining, "\r\n") orelse {
            if (remaining.len >= http1.max_chunk_size_line_bytes) {
                return error.ChunkExtensionTooLarge;
            }
            return error.BufferTooShort;
        };
        if (line_end >= http1.max_chunk_size_line_bytes) {
            return error.ChunkExtensionTooLarge;
        }
        const line = remaining[0..line_end];
        const line_wire_len = std.math.add(usize, line_end, 2) catch
            return error.ChunkSizeOverflow;
        const next_pos = std.math.add(usize, pos, line_wire_len) catch
            return error.ChunkSizeOverflow;
        if (next_pos > max_wire_bytes) return error.BodyTooLarge;
        const semi = std.mem.indexOfScalar(u8, line, ';') orelse line.len;
        if (semi != line.len) {
            extension_bytes = std.math.add(
                usize,
                extension_bytes,
                line.len - semi,
            ) catch return error.ChunkExtensionTooLarge;
            if (extension_bytes > http1.max_chunk_extension_bytes) {
                return error.ChunkExtensionTooLarge;
            }
            try chunk_extension.validate(line[semi + 1 ..]);
        }
        const size = try http1.parseChunkSize(try chunkSizePart(line[0..semi]));
        line_overhead_bytes = std.math.add(
            usize,
            line_overhead_bytes,
            line.len - 1,
        ) catch return error.BodyTooLarge;
        if (line_overhead_bytes > http1.max_chunk_size_line_bytes) {
            return error.BodyTooLarge;
        }
        decoded_total = std.math.add(usize, decoded_total, size) catch
            return error.BodyTooLarge;
        if (decoded_total > max_body_bytes) return error.BodyTooLarge;
        pos = next_pos;
        if (size == 0) {
            const trailer = try chunkedTrailerLayout(
                body[pos..],
                max_head_bytes,
            );
            const wire_len = std.math.add(usize, pos, trailer.wire_len) catch
                return error.HeadersTooLarge;
            if (wire_len > max_wire_bytes) return error.BodyTooLarge;
            return .{
                .wire_len = wire_len,
                .decoded_len = decoded_total,
                .trailer_start = pos,
                .trailer_fields_len = trailer.fields_len,
            };
        }
        const data_end = std.math.add(usize, pos, size) catch
            return error.ChunkSizeOverflow;
        const required_end = std.math.add(usize, data_end, 2) catch
            return error.ChunkSizeOverflow;
        if (required_end > max_wire_bytes) return error.BodyTooLarge;
        if (body.len < required_end) return error.BufferTooShort;
        if (!std.mem.eql(u8, body[data_end..required_end], "\r\n")) {
            return error.InvalidChunk;
        }
        pos = required_end;
    }
}

/// Copy the payload bytes from a previously validated chunk-coded body. The
/// destination must start at or before the source so unread chunk metadata is
/// never overwritten; this is the shape used by HTTP/1 pipeline compaction.
pub fn copyChunkedPayloadForwards(
    body: []const u8,
    destination: []u8,
) void {
    std.debug.assert(destination.len == 0 or
        @intFromPtr(destination.ptr) <= @intFromPtr(body.ptr));
    var pos: usize = 0;
    var out_pos: usize = 0;
    while (true) {
        const line_end = std.mem.indexOf(u8, body[pos..], "\r\n") orelse
            unreachable;
        const line = body[pos .. pos + line_end];
        pos += line_end + 2;
        const semi = std.mem.indexOfScalar(u8, line, ';') orelse line.len;
        const size = http1.parseChunkSize(
            chunkSizePart(line[0..semi]) catch unreachable,
        ) catch unreachable;
        if (size == 0) {
            std.debug.assert(out_pos == destination.len);
            return;
        }
        const data_end = pos + size;
        @memmove(destination[out_pos..][0..size], body[pos..data_end]);
        out_pos += size;
        pos = data_end + 2;
    }
}

fn chunkSizePart(raw_size: []const u8) Error![]const u8 {
    if (raw_size.len == 0) return error.InvalidChunk;
    var end: usize = 0;
    while (end < raw_size.len and std.ascii.isHex(raw_size[end])) : (end += 1) {}
    if (end == 0) return error.InvalidChunk;
    for (raw_size[end..]) |byte| {
        if (byte != ' ' and byte != '\t') return error.InvalidChunk;
    }
    return raw_size[0..end];
}

const ChunkedTrailerLayout = struct {
    wire_len: usize,
    fields_len: usize,
};

fn chunkedTrailerLayout(
    trailers: []const u8,
    max_head_bytes: usize,
) Error!ChunkedTrailerLayout {
    if (std.mem.startsWith(u8, trailers, "\r\n")) {
        if (2 > max_head_bytes) return error.HeadersTooLarge;
        return .{ .wire_len = 2, .fields_len = 0 };
    }
    if (std.mem.indexOf(u8, trailers, "\r\n\r\n")) |end| {
        const len = std.math.add(usize, end, 4) catch
            return error.HeadersTooLarge;
        if (len > max_head_bytes) return error.HeadersTooLarge;
        return .{ .wire_len = len, .fields_len = end };
    }
    if (trailers.len >= max_head_bytes) return error.HeadersTooLarge;
    return error.BufferTooShort;
}

pub fn findHeaderValue(head: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(line[0..colon], name)) {
            return wire.trimOws(line[colon + 1 ..]);
        }
    }
    return null;
}
