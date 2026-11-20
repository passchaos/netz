//! Retain a Reader contribution until the protocol accepts its full prefix.
const std = @import("std");
const reader_io = @import("reader_io.zig");

pub const Pump = struct {
    reader: ?*std.Io.Reader = null,
    buffer: []u8 = &.{},
    offset: usize = 0,
    end: usize = 0,

    pub fn deinit(self: *Pump, allocator: std.mem.Allocator) void {
        if (self.buffer.len != 0) allocator.free(self.buffer);
        self.* = .{};
    }

    pub fn ensureDrained(self: *const Pump) error{RequestBodyPending}!void {
        if (self.offset != self.end) return error.RequestBodyPending;
    }

    /// `write` must report accepted bytes even when it returns an error.
    /// Contribution storage stays owned until deinit or another call with
    /// the same borrowed Reader drains its unaccepted suffix.
    pub fn run(self: *Pump, allocator: std.mem.Allocator, io: std.Io, reader: *std.Io.Reader, target: anytype, comptime write: anytype, progress: anytype, deadline: ?std.Io.Clock.Timestamp) !void {
        if (self.offset != self.end and self.reader != reader) return error.RequestBodySourceChanged;
        if (self.buffer.len == 0) self.buffer = try allocator.alloc(u8, 16 * 1024);
        self.reader = reader;
        while (true) {
            if (self.offset == self.end) {
                self.offset = 0;
                self.end = 0;
                self.end = try reader_io.readBefore(io, reader, self.buffer, deadline);
                if (self.end == 0) {
                    self.reader = null;
                    return;
                }
            }
            var local: @TypeOf(progress.*) = .{};
            const result = write(target, self.buffer[self.offset..self.end], &local, deadline);
            std.debug.assert(local.accepted_bytes <= self.end - self.offset);
            self.offset += local.accepted_bytes;
            progress.accepted_bytes += local.accepted_bytes;
            try result;
            std.debug.assert(self.offset == self.end);
        }
    }
};

test {
    _ = @import("reader_upload_tests.zig");
}
