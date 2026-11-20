//! A cooperative, blocking body source for public upload deadline tests.
const std = @import("std");

pub const Gate = struct {
    reader: std.Io.Reader = .{ .vtable = &.{ .stream = stream }, .buffer = &.{}, .seek = 0, .end = 0 },
    io: std.Io,
    bytes: []const u8,
    prefix_len: usize = 0,
    release: std.Io.Event = .unset,
    canceled: bool = false,
    finished: bool = false,
    offset: usize = 0,

    fn stream(reader: *std.Io.Reader, writer: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *Gate = @fieldParentPtr("reader", reader);
        if (self.offset == self.bytes.len) return error.EndOfStream;
        defer self.finished = true;
        const available = if (self.offset < self.prefix_len) self.prefix_len - self.offset else blk: {
            self.release.wait(self.io) catch {
                self.canceled = true;
                return error.ReadFailed;
            };
            break :blk self.bytes.len - self.offset;
        };
        const count = try writer.write(self.bytes[self.offset..][0..limit.minInt(available)]);
        self.offset += count;
        return count;
    }
};
