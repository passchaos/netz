//! Bounded input adapter for Zig's raw-DEFLATE decoder.
//!
//! Zig 0.16's inflater may request short Huffman lookahead after the logical
//! input is exhausted and then assert while consuming a symbol. Supplying a
//! small zero guard prevents that internal assertion. Callers must reject the
//! decode when `used_guard` is true, so guard bytes can never make truncated
//! or malformed input valid.

const std = @import("std");

pub const guard_len: usize = 8;

pub const GuardedReader = struct {
    source: []const u8,
    source_offset: usize = 0,
    guard_remaining: usize = guard_len,
    used_guard: bool = false,
    buffer: [16]u8 = undefined,
    interface: std.Io.Reader = undefined,

    pub fn init(source: []const u8) GuardedReader {
        return .{ .source = source };
    }

    pub fn reader(self: *GuardedReader) *std.Io.Reader {
        self.interface = .{
            .vtable = &.{ .stream = stream },
            .buffer = &self.buffer,
            .seek = 0,
            .end = 0,
        };
        return &self.interface;
    }

    pub fn sourceConsumed(self: *const GuardedReader) usize {
        if (self.used_guard) return self.source.len;
        return self.source_offset - self.interface.bufferedLen();
    }

    fn stream(
        reader_interface: *std.Io.Reader,
        writer: *std.Io.Writer,
        limit: std.Io.Limit,
    ) std.Io.Reader.StreamError!usize {
        const self: *GuardedReader = @alignCast(
            @fieldParentPtr("interface", reader_interface),
        );
        const destination = limit.slice(
            try writer.writableSliceGreedy(1),
        );
        if (self.source_offset < self.source.len) {
            const count = @min(
                destination.len,
                self.source.len - self.source_offset,
            );
            @memcpy(
                destination[0..count],
                self.source[self.source_offset..][0..count],
            );
            self.source_offset += count;
            writer.advance(count);
            return count;
        }
        if (self.guard_remaining == 0) return error.EndOfStream;
        const count = @min(destination.len, self.guard_remaining);
        @memset(destination[0..count], 0);
        self.guard_remaining -= count;
        self.used_guard = true;
        writer.advance(count);
        return count;
    }
};

test "guarded reader exposes source before bounded sentinel" {
    var guarded = GuardedReader.init("abc");
    const input = guarded.reader();
    var source: [3]u8 = undefined;
    try input.readSliceAll(&source);
    try std.testing.expectEqualStrings("abc", &source);
    try std.testing.expect(!guarded.used_guard);
    try std.testing.expectEqual(@as(usize, 3), guarded.sourceConsumed());

    var guard: [guard_len]u8 = undefined;
    try input.readSliceAll(&guard);
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{0} ** guard_len),
        &guard,
    );
    try std.testing.expect(guarded.used_guard);
    try std.testing.expectEqual(@as(usize, 3), guarded.sourceConsumed());
    try std.testing.expectError(error.EndOfStream, input.takeByte());
}
