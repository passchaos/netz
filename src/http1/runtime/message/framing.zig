const std = @import("std");
const http1 = @import("../../mod.zig");
const wire = @import("../../../internal/wire.zig");

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
            const wire_len = try chunkedWireLength(
                bytes[body_start..],
                max_head_bytes,
                max_body_bytes,
            );
            return std.math.add(usize, body_start, wire_len) catch
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
    var saw_transfer_encoding = false;
    var saw_chunked = false;
    var saw_non_chunked = false;
    var final_is_chunked = false;
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(
            line[0..colon],
            "transfer-encoding",
        )) continue;
        saw_transfer_encoding = true;
        var tokens = std.mem.splitScalar(u8, line[colon + 1 ..], ',');
        while (tokens.next()) |raw| {
            const token = wire.trimOws(raw);
            if (token.len == 0) return error.InvalidTransferEncoding;
            const is_chunked = std.ascii.eqlIgnoreCase(token, "chunked");
            if (is_chunked) {
                if (saw_chunked) return error.InvalidTransferEncoding;
                saw_chunked = true;
            } else {
                saw_non_chunked = true;
            }
            final_is_chunked = is_chunked;
        }
    }
    if (!saw_transfer_encoding) return .none;
    if (saw_chunked and final_is_chunked) return .chunked;
    if (saw_non_chunked or saw_chunked) return .non_chunked;
    return error.InvalidTransferEncoding;
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

fn chunkedWireLength(
    body: []const u8,
    max_head_bytes: usize,
    max_body_bytes: usize,
) Error!usize {
    var pos: usize = 0;
    var decoded_total: usize = 0;
    var extension_bytes: usize = 0;
    while (true) {
        const remaining = body[pos..];
        const line_end = std.mem.indexOf(u8, remaining, "\r\n") orelse {
            if (remaining.len >= http1.max_chunk_extension_bytes + 32) {
                return error.ChunkExtensionTooLarge;
            }
            return error.BufferTooShort;
        };
        const line = remaining[0..line_end];
        const line_wire_len = std.math.add(usize, line_end, 2) catch
            return error.ChunkSizeOverflow;
        const next_pos = std.math.add(usize, pos, line_wire_len) catch
            return error.ChunkSizeOverflow;
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
            try validateChunkExtension(line[semi + 1 ..]);
        }
        const size = try http1.parseChunkSize(try chunkSizePart(line[0..semi]));
        decoded_total = std.math.add(usize, decoded_total, size) catch
            return error.BodyTooLarge;
        if (decoded_total > max_body_bytes) return error.BodyTooLarge;
        pos = next_pos;
        if (size == 0) {
            const trailer_len = try chunkedTrailerWireLength(
                body[pos..],
                max_head_bytes,
            );
            return std.math.add(usize, pos, trailer_len) catch
                return error.HeadersTooLarge;
        }
        const data_end = std.math.add(usize, pos, size) catch
            return error.ChunkSizeOverflow;
        const required_end = std.math.add(usize, data_end, 2) catch
            return error.ChunkSizeOverflow;
        if (body.len < required_end) return error.BufferTooShort;
        if (!std.mem.eql(u8, body[data_end..required_end], "\r\n")) {
            return error.InvalidChunk;
        }
        pos = required_end;
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

fn validateChunkExtension(extension: []const u8) Error!void {
    for (extension) |byte| {
        if (byte == '\r' or byte == '\n') return error.InvalidChunk;
    }
}

fn chunkedTrailerWireLength(
    trailers: []const u8,
    max_head_bytes: usize,
) Error!usize {
    if (std.mem.startsWith(u8, trailers, "\r\n")) {
        if (2 > max_head_bytes) return error.HeadersTooLarge;
        return 2;
    }
    if (std.mem.indexOf(u8, trailers, "\r\n\r\n")) |end| {
        const len = std.math.add(usize, end, 4) catch
            return error.HeadersTooLarge;
        if (len > max_head_bytes) return error.HeadersTooLarge;
        return len;
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
