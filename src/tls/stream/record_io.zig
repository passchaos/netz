//! Socket framing helpers shared by the TLS handshake and record stream.

const std = @import("std");
const vail = @import("vail");
const stream_io = @import("../../internal/stream_io.zig");

const net = std.Io.net;

pub const max_plaintext_len: usize = 16 * 1024;
pub const max_record_len = @max(
    vail.tls.record.header_len +
        max_plaintext_len +
        1 +
        vail.tls.record.tag_len,
    vail.tls.tls12.max_record_len,
);

pub const Error = net.Stream.Reader.Error ||
    net.Stream.Writer.Error ||
    error{
        ConnectionClosed,
        RecordTooLarge,
        SequenceOverflow,
        TruncatedRecord,
        UnexpectedEof,
    } || stream_io.TimedReadError || stream_io.TimedWriteError;

const ExactReadResult = enum {
    complete,
    eof,
    truncated,
};

/// Incremental TLS-record reader whose ciphertext survives a timeout or task
/// cancellation. A caller may therefore resume the same record without
/// treating payload bytes as a new header. The returned slice remains valid
/// until the next read.
pub const Reader = struct {
    encoded_len: usize = 0,
    total_len: ?usize = null,

    pub fn read(
        self: *Reader,
        io: std.Io,
        stream: net.Stream,
        buffer: []u8,
    ) Error![]u8 {
        return self.readInternal(io, stream, buffer, null);
    }

    pub fn readWithDeadline(
        self: *Reader,
        io: std.Io,
        stream: net.Stream,
        buffer: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error![]u8 {
        return self.readInternal(io, stream, buffer, deadline);
    }

    fn readInternal(
        self: *Reader,
        io: std.Io,
        stream: net.Stream,
        buffer: []u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error![]u8 {
        if (buffer.len < max_record_len) return error.RecordTooLarge;
        while (self.encoded_len < vail.tls.record.header_len) {
            const count = try readSome(
                io,
                stream,
                buffer[self.encoded_len..vail.tls.record.header_len],
                deadline,
            );
            if (count == 0) {
                return if (self.encoded_len == 0)
                    error.UnexpectedEof
                else
                    error.TruncatedRecord;
            }
            self.encoded_len += count;
        }
        if (self.total_len == null) {
            const payload_len = std.mem.readInt(
                u16,
                buffer[3..5],
                .big,
            );
            const total_len = vail.tls.record.header_len + payload_len;
            if (total_len > buffer.len) return error.RecordTooLarge;
            self.total_len = total_len;
        }
        const total_len = self.total_len.?;
        while (self.encoded_len < total_len) {
            const count = try readSome(
                io,
                stream,
                buffer[self.encoded_len..total_len],
                deadline,
            );
            if (count == 0) return error.TruncatedRecord;
            self.encoded_len += count;
        }
        const record = buffer[0..total_len];
        self.encoded_len = 0;
        self.total_len = null;
        return record;
    }
};

fn readSome(
    io: std.Io,
    stream: net.Stream,
    out: []u8,
    deadline: ?std.Io.Clock.Timestamp,
) Error!usize {
    if (deadline) |absolute| {
        return stream_io.readSomeWithDeadline(
            io,
            stream,
            out,
            absolute,
        );
    }
    return stream_io.readSome(io, stream, out);
}

pub fn readRecord(
    io: std.Io,
    stream: net.Stream,
    buffer: []u8,
) Error![]u8 {
    if (buffer.len < vail.tls.record.header_len) {
        return error.RecordTooLarge;
    }
    switch (try readExact(
        io,
        stream,
        buffer[0..vail.tls.record.header_len],
    )) {
        .complete => {},
        .eof => return error.UnexpectedEof,
        .truncated => return error.TruncatedRecord,
    }
    const payload_len = std.mem.readInt(u16, buffer[3..5], .big);
    const total_len = vail.tls.record.header_len + payload_len;
    if (total_len > buffer.len) return error.RecordTooLarge;
    if (try readExact(
        io,
        stream,
        buffer[vail.tls.record.header_len..total_len],
    ) != .complete) return error.TruncatedRecord;
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
    switch (try readExactWithDeadline(
        io,
        stream,
        buffer[0..vail.tls.record.header_len],
        deadline,
    )) {
        .complete => {},
        .eof => return error.UnexpectedEof,
        .truncated => return error.TruncatedRecord,
    }
    const payload_len = std.mem.readInt(u16, buffer[3..5], .big);
    const total_len = vail.tls.record.header_len + payload_len;
    if (total_len > buffer.len) return error.RecordTooLarge;
    if (try readExactWithDeadline(
        io,
        stream,
        buffer[vail.tls.record.header_len..total_len],
        deadline,
    ) != .complete) return error.TruncatedRecord;
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

/// Resume a ciphertext record under one absolute deadline. `offset` is
/// advanced only by bytes accepted by the socket, so an encrypted record can
/// survive timeout, cancellation or executor admission failure without being
/// regenerated under the same TLS nonce.
pub fn writeAllWithDeadline(
    io: std.Io,
    stream: net.Stream,
    bytes: []const u8,
    offset: *usize,
    deadline: std.Io.Clock.Timestamp,
) Error!void {
    while (offset.* < bytes.len) {
        offset.* += try stream_io.writeSomeWithDeadline(
            io,
            stream,
            bytes[offset.*..],
            deadline,
        );
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
) Error!ExactReadResult {
    var offset: usize = 0;
    while (offset < out.len) {
        const count = try stream_io.readSome(io, stream, out[offset..]);
        if (count == 0) {
            return if (offset == 0) .eof else .truncated;
        }
        offset += count;
    }
    return .complete;
}

fn readExactWithDeadline(
    io: std.Io,
    stream: net.Stream,
    out: []u8,
    deadline: std.Io.Clock.Timestamp,
) Error!ExactReadResult {
    var offset: usize = 0;
    while (offset < out.len) {
        const count = try stream_io.readSomeWithDeadline(
            io,
            stream,
            out[offset..],
            deadline,
        );
        if (count == 0) {
            return if (offset == 0) .eof else .truncated;
        }
        offset += count;
    }
    return .complete;
}
