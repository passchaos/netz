const std = @import("std");
const http2 = @import("../../mod.zig");

const flag_end_stream: u8 = 0x1;
const flag_end_headers: u8 = 0x4;

/// RFC wire error associated with a malformed frame envelope. A null
/// `stream_id` denotes a connection error; the only stream-scoped envelope
/// violation is a zero WINDOW_UPDATE increment on a non-zero stream.
pub const EnvelopeViolation = struct {
    error_code: http2.ErrorCode,
    stream_id: ?u31 = null,
};

pub fn classifyEnvelope(frame: http2.Frame) ?EnvelopeViolation {
    if (frame.payload.len != @as(usize, frame.header.length)) {
        return .{ .error_code = .frame_size_error };
    }

    const stream_id = frame.header.stream_id;
    switch (frame.header.frame_type) {
        .data,
        .headers,
        .continuation,
        => if (stream_id == 0) {
            return .{ .error_code = .protocol_error };
        },

        .priority => {
            if (frame.payload.len != 5) {
                return .{ .error_code = .frame_size_error };
            }
            if (stream_id == 0) {
                return .{ .error_code = .protocol_error };
            }
        },
        .rst_stream => {
            if (frame.payload.len != 4) {
                return .{ .error_code = .frame_size_error };
            }
            if (stream_id == 0) {
                return .{ .error_code = .protocol_error };
            }
        },
        .settings => {
            if ((frame.header.flags & 0x1) != 0) {
                if (frame.payload.len != 0) {
                    return .{ .error_code = .frame_size_error };
                }
            } else if (frame.payload.len % 6 != 0) {
                return .{ .error_code = .frame_size_error };
            }
            if (stream_id != 0) {
                return .{ .error_code = .protocol_error };
            }
        },
        .ping => {
            if (frame.payload.len != 8) {
                return .{ .error_code = .frame_size_error };
            }
            if (stream_id != 0) {
                return .{ .error_code = .protocol_error };
            }
        },
        .goaway => {
            if (frame.payload.len < 8) {
                return .{ .error_code = .frame_size_error };
            }
            if (stream_id != 0) {
                return .{ .error_code = .protocol_error };
            }
        },
        .priority_update => {
            if (frame.payload.len < 4) {
                return .{ .error_code = .frame_size_error };
            }
            if (stream_id != 0) {
                return .{ .error_code = .protocol_error };
            }
        },
        // RFC 8336 requires ORIGIN on a non-zero stream to be ignored, and
        // ALTSVC has extension-specific stream semantics handled above the
        // base HTTP/2 envelope layer.
        .altsvc, .origin => {},
        .window_update => {
            if (frame.payload.len != 4) {
                return .{ .error_code = .frame_size_error };
            }
            const increment = std.mem.readInt(
                u32,
                frame.payload[0..4],
                .big,
            ) & 0x7fff_ffff;
            if (increment == 0) {
                return .{
                    .error_code = .protocol_error,
                    .stream_id = if (stream_id == 0) null else stream_id,
                };
            }
        },
        .push_promise => if (stream_id == 0) {
            return .{ .error_code = .protocol_error };
        },
        _ => {},
    }
    return null;
}

pub fn validateEnvelope(frame: http2.Frame) error{InvalidFrame}!void {
    if (classifyEnvelope(frame) != null) return error.InvalidFrame;
}

pub fn clientInitiatedStreamId(stream_id: u31) bool {
    return stream_id != 0 and (stream_id & 1) == 1;
}

pub fn encodeHeader(
    output: *[http2.FrameHeader.encoded_len]u8,
    frame_type: http2.FrameType,
    flags: u8,
    stream_id: u31,
    payload_length: usize,
) error{InvalidFrameSize}!void {
    const payload_len = std.math.cast(u24, payload_length) orelse
        return error.InvalidFrameSize;
    output[0] = @truncate(payload_len >> 16);
    output[1] = @truncate(payload_len >> 8);
    output[2] = @truncate(payload_len);
    output[3] = @intFromEnum(frame_type);
    output[4] = flags;
    std.mem.writeInt(u32, output[5..9], @as(u32, stream_id), .big);
}

pub fn encodeWindowUpdate(
    output: []u8,
    stream_id: u31,
    increment: u31,
) error{InvalidFrameSize}!void {
    std.debug.assert(output.len == http2.FrameHeader.encoded_len + 4);
    if (increment == 0) return error.InvalidFrameSize;
    const header: *[http2.FrameHeader.encoded_len]u8 = @ptrCast(output.ptr);
    try encodeHeader(header, .window_update, 0, stream_id, 4);
    std.mem.writeInt(
        u32,
        output[http2.FrameHeader.encoded_len..][0..4],
        increment,
        .big,
    );
}

pub fn appendFrame(
    batch: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    frame_type: http2.FrameType,
    flags: u8,
    stream_id: u31,
    payload: []const u8,
) !void {
    if (payload.len > std.math.maxInt(u24)) {
        return error.InvalidFrameSize;
    }
    const total_len = std.math.add(
        usize,
        http2.FrameHeader.encoded_len,
        payload.len,
    ) catch return error.InvalidFrameSize;
    try batch.ensureUnusedCapacity(allocator, total_len);
    appendFrameAssumeCapacity(
        batch,
        frame_type,
        flags,
        stream_id,
        payload,
    );
}

fn appendFrameAssumeCapacity(
    batch: *std.ArrayList(u8),
    frame_type: http2.FrameType,
    flags: u8,
    stream_id: u31,
    payload: []const u8,
) void {
    std.debug.assert(payload.len <= std.math.maxInt(u24));
    const total_len = http2.FrameHeader.encoded_len + payload.len;
    const start = batch.items.len;
    batch.items.len = start + total_len;
    const header: *[http2.FrameHeader.encoded_len]u8 =
        @ptrCast(batch.items[start..].ptr);
    encodeHeader(header, frame_type, flags, stream_id, payload.len) catch
        unreachable;
    @memcpy(
        batch.items[start + http2.FrameHeader.encoded_len ..][0..payload.len],
        payload,
    );
}

pub fn appendHeaderBlock(
    batch: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    stream_id: u31,
    block: []const u8,
    end_stream: bool,
    chunk_size: usize,
) !void {
    if (chunk_size == 0 or chunk_size > std.math.maxInt(u24)) {
        return error.InvalidFrameSize;
    }
    const quotient = block.len / chunk_size;
    const frame_count = @max(
        quotient + @intFromBool(block.len % chunk_size != 0),
        1,
    );
    const framing_len = std.math.mul(
        usize,
        frame_count,
        http2.FrameHeader.encoded_len,
    ) catch return error.InvalidFrameSize;
    const encoded_len = std.math.add(usize, block.len, framing_len) catch
        return error.InvalidFrameSize;
    // Reserve the complete logical field section before mutating the batch.
    // Besides avoiding geometric growth across CONTINUATION frames, this keeps
    // an allocation failure from leaving a partially appended header block.
    try batch.ensureUnusedCapacity(allocator, encoded_len);

    const first_len = @min(block.len, chunk_size);
    appendFrameAssumeCapacity(
        batch,
        .headers,
        (if (first_len == block.len) flag_end_headers else 0) |
            (if (end_stream) flag_end_stream else 0),
        stream_id,
        block[0..first_len],
    );
    var offset = first_len;
    while (offset < block.len) {
        const end = @min(block.len, offset + chunk_size);
        appendFrameAssumeCapacity(
            batch,
            .continuation,
            if (end == block.len) flag_end_headers else 0,
            stream_id,
            block[offset..end],
        );
        offset = end;
    }
}

/// Append one PUSH_PROMISE field section and every required CONTINUATION as a
/// single prepared byte sequence. The promised stream identifier occupies the
/// first four payload bytes and therefore reduces only the first frame's HPACK
/// capacity.
pub fn appendPushPromiseBlock(
    batch: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    parent_stream_id: u31,
    promised_stream_id: u31,
    block: []const u8,
    chunk_size: usize,
) !void {
    if (chunk_size <= 4 or chunk_size > std.math.maxInt(u24)) {
        return error.InvalidFrameSize;
    }
    const first_len = @min(block.len, chunk_size - 4);
    const remaining = block.len - first_len;
    const continuation_count = if (remaining == 0)
        0
    else
        std.math.divCeil(usize, remaining, chunk_size) catch
            return error.InvalidFrameSize;
    const frame_count = std.math.add(
        usize,
        continuation_count,
        1,
    ) catch return error.InvalidFrameSize;
    const framing_len = std.math.mul(
        usize,
        frame_count,
        http2.FrameHeader.encoded_len,
    ) catch return error.InvalidFrameSize;
    const payload_len = std.math.add(usize, block.len, 4) catch
        return error.InvalidFrameSize;
    const encoded_len = std.math.add(
        usize,
        framing_len,
        payload_len,
    ) catch return error.InvalidFrameSize;
    try batch.ensureUnusedCapacity(allocator, encoded_len);

    const start = batch.items.len;
    batch.items.len = start + http2.FrameHeader.encoded_len + 4 + first_len;
    const header: *[http2.FrameHeader.encoded_len]u8 =
        @ptrCast(batch.items[start..].ptr);
    encodeHeader(
        header,
        .push_promise,
        if (first_len == block.len) flag_end_headers else 0,
        parent_stream_id,
        4 + first_len,
    ) catch unreachable;
    const payload_start = start + http2.FrameHeader.encoded_len;
    std.mem.writeInt(
        u32,
        batch.items[payload_start..][0..4],
        promised_stream_id,
        .big,
    );
    @memcpy(
        batch.items[payload_start + 4 ..][0..first_len],
        block[0..first_len],
    );
    var offset = first_len;
    while (offset < block.len) {
        const end = @min(block.len, offset + chunk_size);
        appendFrameAssumeCapacity(
            batch,
            .continuation,
            if (end == block.len) flag_end_headers else 0,
            parent_stream_id,
            block[offset..end],
        );
        offset = end;
    }
}
