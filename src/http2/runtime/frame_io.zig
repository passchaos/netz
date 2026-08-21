const std = @import("std");
const http2 = @import("../mod.zig");

pub const Error = http2.Error || error{
    ConnectionClosed,
    MessageTooLarge,
} || std.mem.Allocator.Error || std.Io.net.Stream.Reader.Error;

pub const BorrowedFrame = struct {
    bytes: []const u8,
    frame: http2.Frame,
};

/// Buffered frame source for one HTTP/2 connection.
///
/// A returned frame borrows `buffer` until the next `read` call. The reader
/// deliberately asks the socket for a 64-KiB tail so one syscall can capture
/// several adjacent frames; a cursor consumes complete frames without
/// memmoving until another socket read is required.
pub const Reader = struct {
    buffer: std.ArrayList(u8) = .empty,
    start: usize = 0,

    pub fn deinit(self: *Reader, allocator: std.mem.Allocator) void {
        self.buffer.deinit(allocator);
        self.* = undefined;
    }

    pub fn read(
        self: *Reader,
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: std.Io.net.Stream,
        inbound_payload_limit: usize,
    ) Error!BorrowedFrame {
        const Source = struct {
            io: std.Io,
            stream: std.Io.net.Stream,

            fn read(source: @This(), buffer: []u8) !usize {
                var buffers = [_][]u8{buffer};
                return source.io.vtable.netRead(
                    source.io.userdata,
                    source.stream.socket.handle,
                    &buffers,
                );
            }
        };
        return self.readFrom(
            allocator,
            Source{ .io = io, .stream = stream },
            inbound_payload_limit,
        );
    }

    pub fn readTransport(
        self: *Reader,
        allocator: std.mem.Allocator,
        transport: anytype,
        inbound_payload_limit: usize,
    ) !BorrowedFrame {
        return self.readFrom(allocator, transport, inbound_payload_limit);
    }

    fn readFrom(
        self: *Reader,
        allocator: std.mem.Allocator,
        source: anytype,
        inbound_payload_limit: usize,
    ) !BorrowedFrame {
        const read_size: usize = 64 * 1024;
        while (true) {
            const available = self.buffer.items[self.start..];
            if (available.len >= http2.FrameHeader.encoded_len) {
                const header = try http2.FrameHeader.parse(available);
                const payload_len: usize = header.length;
                if (payload_len > inbound_payload_limit) {
                    return error.MessageTooLarge;
                }
                const total_len = std.math.add(
                    usize,
                    http2.FrameHeader.encoded_len,
                    payload_len,
                ) catch return error.MessageTooLarge;
                if (available.len >= total_len) {
                    const bytes = available[0..total_len];
                    const frame = try http2.Frame.parse(bytes);
                    self.start += total_len;
                    return .{ .bytes = bytes, .frame = frame };
                }
            }

            // The caller's previous borrow expires on entry to this method, so
            // compaction is safe here and retains only an incomplete frame.
            if (self.start != 0) {
                const remaining = self.buffer.items[self.start..];
                if (remaining.len != 0) {
                    @memmove(
                        self.buffer.items[0..remaining.len],
                        remaining,
                    );
                }
                self.buffer.items.len = remaining.len;
                self.start = 0;
            }

            const destination = try self.buffer.addManyAsSlice(
                allocator,
                read_size,
            );
            const count = source.read(destination) catch |err| {
                self.buffer.items.len -= destination.len;
                return err;
            };
            if (count == 0) {
                self.buffer.items.len -= destination.len;
                return error.ConnectionClosed;
            }
            self.buffer.items.len -= destination.len - count;
        }
    }
};
