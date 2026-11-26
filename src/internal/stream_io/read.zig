//! Ordinary socket reads share the same completion owner as timed reads.
const std = @import("std");
const windows_read = @import("windows_read.zig");

pub fn readSome(io: std.Io, stream: std.Io.net.Stream, buffer: []u8) std.Io.net.Stream.Reader.Error!usize {
    if (buffer.len == 0) return 0;
    var buffers = [_][]u8{buffer};
    return readVec(io, stream, &buffers);
}

pub fn readVec(io: std.Io, stream: std.Io.net.Stream, buffers: [][]u8) std.Io.net.Stream.Reader.Error!usize {
    for (buffers) |buffer| if (buffer.len != 0) {
        if (windows_read.tryRead(io, stream, buffers)) |result| return result;
        return io.vtable.netRead(io.userdata, stream.socket.handle, buffers);
    };
    return 0;
}
