//! Socket framing helpers shared by the TLS handshake and record stream.

const std = @import("std");
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
    };

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
