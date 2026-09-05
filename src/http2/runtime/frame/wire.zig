const std = @import("std");
const http2 = @import("../../mod.zig");

const flag_end_stream: u8 = 0x1;
const flag_end_headers: u8 = 0x4;

pub fn validateEnvelope(frame: http2.Frame) error{InvalidFrame}!void {
    if (frame.payload.len != @as(usize, frame.header.length)) {
        return error.InvalidFrame;
    }

    const stream_id = frame.header.stream_id;
    switch (frame.header.frame_type) {
        .data,
        .headers,
        .continuation,
        => if (stream_id == 0) return error.InvalidFrame,

        .priority => {
            if (stream_id == 0 or frame.payload.len != 5) {
                return error.InvalidFrame;
            }
        },
        .rst_stream => {
            if (stream_id == 0 or frame.payload.len != 4) {
                return error.InvalidFrame;
            }
        },
        .settings => {
            if (stream_id != 0) return error.InvalidFrame;
            if ((frame.header.flags & 0x1) != 0) {
                if (frame.payload.len != 0) return error.InvalidFrame;
            } else if (frame.payload.len % 6 != 0) {
                return error.InvalidFrame;
            }
        },
        .ping => {
            if (stream_id != 0 or frame.payload.len != 8) {
                return error.InvalidFrame;
            }
        },
        .goaway => {
            if (stream_id != 0 or frame.payload.len < 8) {
                return error.InvalidFrame;
            }
        },
        .priority_update => {
            if (stream_id != 0 or frame.payload.len < 4) {
                return error.InvalidFrame;
            }
        },
        .altsvc, .origin => {},
        .window_update => {
            if (frame.payload.len != 4) return error.InvalidFrame;
            const increment = std.mem.readInt(
                u32,
                frame.payload[0..4],
                .big,
            ) & 0x7fff_ffff;
            if (increment == 0) return error.InvalidFrame;
        },
        .push_promise => if (stream_id == 0) return error.InvalidFrame,
        _ => {},
    }
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
