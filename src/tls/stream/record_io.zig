//! Socket framing helpers shared by the TLS handshake and record stream.

const std = @import("std");
const builtin = @import("builtin");
const vail = @import("vail");

const net = std.Io.net;

pub const max_plaintext_len: usize = 16 * 1024;
pub const max_record_len =
    vail.tls.record.header_len +
    max_plaintext_len +
    1 +
    vail.tls.record.tag_len;

pub const Error = net.Stream.Reader.Error ||
    net.Stream.Writer.Error ||
    error{
        ConnectionClosed,
        RecordTooLarge,
        SequenceOverflow,
    } || std.Io.Operation.FileReadStreaming.UnendingError ||
    std.Io.Operation.NetReceive.Error || std.Io.Timeout.Error ||
    std.Io.ConcurrentError;

pub fn readRecord(
    io: std.Io,
    stream: net.Stream,
    buffer: []u8,
) Error![]u8 {
    if (buffer.len < vail.tls.record.header_len) {
        return error.RecordTooLarge;
    }
    try readExact(
        io,
        stream,
        buffer[0..vail.tls.record.header_len],
    );
    const payload_len = std.mem.readInt(u16, buffer[3..5], .big);
    const total_len = vail.tls.record.header_len + payload_len;
    if (total_len > buffer.len) return error.RecordTooLarge;
    try readExact(
        io,
        stream,
        buffer[vail.tls.record.header_len..total_len],
    );
    return buffer[0..total_len];
}

/// Read one complete TLS record under one absolute transport deadline.
/// Keeping the same deadline across the header and payload prevents a peer
/// from extending an application inactivity budget by trickling record bytes.
pub fn readRecordWithDeadline(
    io: std.Io,
    stream: net.Stream,
    buffer: []u8,
    deadline: std.Io.Clock.Timestamp,
) Error![]u8 {
    if (buffer.len < vail.tls.record.header_len) {
        return error.RecordTooLarge;
    }
    try readExactWithDeadline(
        io,
        stream,
        buffer[0..vail.tls.record.header_len],
        deadline,
    );
    const payload_len = std.mem.readInt(u16, buffer[3..5], .big);
    const total_len = vail.tls.record.header_len + payload_len;
    if (total_len > buffer.len) return error.RecordTooLarge;
    try readExactWithDeadline(
        io,
        stream,
        buffer[vail.tls.record.header_len..total_len],
        deadline,
    );
    return buffer[0..total_len];
}

pub fn writeAll(
    io: std.Io,
    stream: net.Stream,
    bytes: []const u8,
) Error!void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const count = try io.vtable.netWrite(
            io.userdata,
            stream.socket.handle,
            bytes[offset..],
            &.{""},
            0,
        );
        if (count == 0) return error.ConnectionClosed;
        offset += count;
    }
}

pub fn nextSequence(current: u64) Error!u64 {
    return std.math.add(u64, current, 1) catch
        error.SequenceOverflow;
}

fn readExact(
    io: std.Io,
    stream: net.Stream,
    out: []u8,
) Error!void {
    var offset: usize = 0;
    while (offset < out.len) {
        var bufs = [_][]u8{out[offset..]};
        const count = try io.vtable.netRead(
            io.userdata,
            stream.socket.handle,
            &bufs,
        );
        if (count == 0) return error.ConnectionClosed;
        offset += count;
    }
}

fn readExactWithDeadline(
    io: std.Io,
    stream: net.Stream,
    out: []u8,
    deadline: std.Io.Clock.Timestamp,
) Error!void {
    var offset: usize = 0;
    while (offset < out.len) {
        const count = if (builtin.os.tag == .windows) blk: {
            var incoming: net.IncomingMessage = .init;
            const maybe_err, const message_count = (try io.operateTimeout(
                .{ .net_receive = .{
                    .socket_handle = stream.socket.handle,
                    .message_buffer = (&incoming)[0..1],
                    .data_buffer = out[offset..],
                    .flags = .{},
                } },
                .{ .deadline = deadline },
            )).net_receive;
            if (maybe_err) |err| return err;
            std.debug.assert(message_count == 1);
            break :blk incoming.data.len;
        } else blk: {
            var bufs = [_][]u8{out[offset..]};
            const result = try io.operateTimeout(
                .{ .file_read_streaming = .{
                    .file = .{
                        .handle = stream.socket.handle,
                        .flags = .{ .nonblocking = false },
                    },
                    .data = &bufs,
                } },
                .{ .deadline = deadline },
            );
            break :blk result.file_read_streaming catch |err| switch (err) {
                error.EndOfStream => return error.ConnectionClosed,
                else => return @errorCast(err),
            };
        };
        if (count == 0) return error.ConnectionClosed;
        offset += count;
    }
}
