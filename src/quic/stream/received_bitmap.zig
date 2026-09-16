//! Presence tracking for retained QUIC STREAM bytes.
//!
//! Ordered traffic uses an implicit dense prefix (`words.len == 0` with a
//! non-zero logical length). Sparse packed words are materialized only when a
//! gap makes individual presence bits meaningful.

const std = @import("std");

pub const Bitmap = struct {
    const Word = usize;
    pub const word_bits = @bitSizeOf(Word);
    const Shift = std.math.Log2Int(Word);

    words: std.ArrayList(Word) = .empty,
    bit_len: usize = 0,

    pub const View = struct {
        words: []const Word = &.{},
        bit_len: usize = 0,

        pub fn isSet(self: View, index: usize) bool {
            std.debug.assert(index < self.bit_len);
            if (self.words.len == 0) return true;
            return (self.words[wordIndex(index)] & bitMask(index)) != 0;
        }

        pub fn anySetInRange(
            self: View,
            range: std.bit_set.Range,
        ) bool {
            std.debug.assert(range.start <= range.end);
            std.debug.assert(range.end <= self.bit_len);
            if (range.start == range.end) return false;
            if (self.words.len == 0) return true;

            const first_word = wordIndex(range.start);
            const last_word = wordIndex(range.end - 1);
            const start_bit: Shift = @truncate(range.start);
            const start_mask = @as(Word, std.math.maxInt(Word)) << start_bit;
            const end_bit: Shift = @truncate(range.end);
            const end_mask = if (end_bit == 0)
                std.math.maxInt(Word)
            else
                (@as(Word, 1) << end_bit) - 1;

            if (first_word == last_word) {
                return (self.words[first_word] & start_mask & end_mask) != 0;
            }
            if ((self.words[first_word] & start_mask) != 0) return true;
            for (self.words[first_word + 1 .. last_word]) |word| {
                if (word != 0) return true;
            }
            return (self.words[last_word] & end_mask) != 0;
        }
    };

    pub fn deinit(self: *Bitmap, allocator: std.mem.Allocator) void {
        self.words.deinit(allocator);
        self.* = undefined;
    }

    pub fn clone(
        self: Bitmap,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!Bitmap {
        var copy: Bitmap = .{};
        try copy.words.ensureUnusedCapacity(allocator, self.words.items.len);
        copy.words.appendSliceAssumeCapacity(self.words.items);
        copy.bit_len = self.bit_len;
        return copy;
    }

    pub fn len(self: Bitmap) usize {
        return self.bit_len;
    }

    pub fn materializedCapacity(self: Bitmap) usize {
        return self.words.capacity;
    }

    pub fn view(self: Bitmap) View {
        return .{ .words = self.words.items, .bit_len = self.bit_len };
    }

    pub fn resize(
        self: *Bitmap,
        allocator: std.mem.Allocator,
        new_len: usize,
        fill: bool,
    ) std.mem.Allocator.Error!void {
        try self.ensureResizeCapacity(allocator, new_len, fill);
        self.resizeAssumeCapacity(new_len, fill);
    }

    pub fn ensureResizeCapacity(
        self: *Bitmap,
        allocator: std.mem.Allocator,
        new_len: usize,
        fill: bool,
    ) std.mem.Allocator.Error!void {
        const old_len = self.bit_len;
        const old_word_len = self.words.items.len;
        const new_word_len = wordCount(new_len);
        if (old_word_len == 0) {
            if (new_len <= old_len or fill) return;
            try self.words.ensureTotalCapacity(allocator, new_word_len);
            return;
        }
        if (new_word_len > old_word_len) {
            try self.words.ensureTotalCapacity(allocator, new_word_len);
        }
    }

    pub fn resizeAssumeCapacity(
        self: *Bitmap,
        new_len: usize,
        fill: bool,
    ) void {
        const old_len = self.bit_len;
        const old_word_len = self.words.items.len;
        const new_word_len = wordCount(new_len);
        if (old_word_len == 0) {
            if (new_len <= old_len or fill) {
                self.bit_len = new_len;
                return;
            }
            std.debug.assert(self.words.capacity >= new_word_len);
            self.words.items.len = new_word_len;
            @memset(self.words.items, 0);
            self.bit_len = new_len;
            if (old_len != 0) {
                self.setRangeValue(
                    .{ .start = 0, .end = old_len },
                    true,
                );
            }
            self.clearPadding();
            return;
        }
        if (new_word_len > old_word_len) {
            std.debug.assert(self.words.capacity >= new_word_len);
            self.words.items.len = new_word_len;
            @memset(
                self.words.items[old_word_len..],
                std.math.boolMask(Word, fill),
            );
        } else {
            self.words.items.len = new_word_len;
        }
        self.bit_len = new_len;
        if (new_len > old_len) {
            const old_word_end = @min(new_len, old_word_len * word_bits);
            if (old_len < old_word_end) {
                self.setRangeValue(
                    .{ .start = old_len, .end = old_word_end },
                    fill,
                );
            }
        }
        self.clearPadding();
    }

    pub fn isSet(self: Bitmap, index: usize) bool {
        return self.view().isSet(index);
    }

    pub fn anySetInRange(
        self: Bitmap,
        range: std.bit_set.Range,
    ) bool {
        return self.view().anySetInRange(range);
    }

    pub fn setRangeValue(
        self: *Bitmap,
        range: std.bit_set.Range,
        value: bool,
    ) void {
        std.debug.assert(range.end <= self.bit_len);
        std.debug.assert(range.start <= range.end);
        if (range.start == range.end) return;
        if (self.words.items.len == 0) {
            std.debug.assert(value);
            return;
        }

        const start_word = wordIndex(range.start);
        const start_bit: Shift = @truncate(range.start);
        const end_word = wordIndex(range.end);
        const end_bit: Shift = @truncate(range.end);
        const fill_word = std.math.boolMask(Word, value);

        if (start_word == end_word) {
            const low = @as(Word, std.math.maxInt(Word)) << start_bit;
            const high = @as(Word, std.math.maxInt(Word)) >>
                ((word_bits - 1) - (end_bit - 1));
            const mask = low & high;
            self.words.items[start_word] =
                (self.words.items[start_word] & ~mask) |
                (fill_word & mask);
            return;
        }

        var current = start_word;
        if (start_bit != 0) {
            const mask = @as(Word, std.math.maxInt(Word)) << start_bit;
            self.words.items[current] =
                (self.words.items[current] & ~mask) |
                (fill_word & mask);
            current += 1;
        }
        @memset(self.words.items[current..end_word], fill_word);
        if (end_bit != 0) {
            const mask = @as(Word, std.math.maxInt(Word)) >>
                ((word_bits - 1) - (end_bit - 1));
            self.words.items[end_word] =
                (self.words.items[end_word] & ~mask) |
                (fill_word & mask);
        }
    }

    pub fn firstUnsetFrom(self: Bitmap, start: usize) usize {
        std.debug.assert(start <= self.bit_len);
        if (start == self.bit_len) return start;
        if (self.words.items.len == 0) return self.bit_len;

        var word_index = wordIndex(start);
        var word = self.words.items[word_index];
        const start_bit: Shift = @truncate(start);
        if (start_bit != 0) {
            word |= (@as(Word, 1) << start_bit) - 1;
        }
        while (true) {
            const unset = ~word;
            if (unset != 0) {
                const candidate = word_index * word_bits + @ctz(unset);
                return @min(candidate, self.bit_len);
            }
            word_index += 1;
            if (word_index == self.words.items.len) return self.bit_len;
            word = self.words.items[word_index];
        }
    }

    pub fn removePrefix(self: *Bitmap, prefix_len: usize) void {
        std.debug.assert(prefix_len <= self.bit_len);
        const remaining = self.bit_len - prefix_len;
        if (remaining == 0) {
            self.words.items.len = 0;
            self.bit_len = 0;
            return;
        }
        if (self.words.items.len == 0) {
            self.bit_len = remaining;
            return;
        }

        const word_shift = prefix_len / word_bits;
        const bit_shift: Shift = @truncate(prefix_len);
        const old_word_len = self.words.items.len;
        const new_word_len = wordCount(remaining);
        for (0..new_word_len) |destination| {
            const source = destination + word_shift;
            var word = self.words.items[source] >> bit_shift;
            if (bit_shift != 0 and source + 1 < old_word_len) {
                const inverse_shift: Shift = @intCast(
                    word_bits - @as(usize, bit_shift),
                );
                word |= self.words.items[source + 1] << inverse_shift;
            }
            self.words.items[destination] = word;
        }
        self.words.items.len = new_word_len;
        self.bit_len = remaining;
        self.clearPadding();
    }

    fn clearPadding(self: *Bitmap) void {
        if (self.bit_len == 0 or self.words.items.len == 0) return;
        const used_bits = self.bit_len % word_bits;
        if (used_bits == 0) return;
        self.words.items[self.words.items.len - 1] &=
            (@as(Word, 1) << @as(Shift, @intCast(used_bits))) - 1;
    }

    pub fn wordCount(bit_len: usize) usize {
        return bit_len / word_bits + @intFromBool(bit_len % word_bits != 0);
    }

    fn wordIndex(index: usize) usize {
        return index / word_bits;
    }

    fn bitMask(index: usize) Word {
        return @as(Word, 1) << @as(Shift, @truncate(index));
    }
};

test "QUIC receive bitmap matches byte model across range and prefix operations" {
    const allocator = std.testing.allocator;
    var bitmap: Bitmap = .{};
    defer bitmap.deinit(allocator);
    var model = [_]bool{false} ** 192;

    try bitmap.resize(allocator, 130, false);
    bitmap.setRangeValue(.{ .start = 3, .end = 127 }, true);
    @memset(model[3..127], true);
    bitmap.setRangeValue(.{ .start = 17, .end = 73 }, false);
    @memset(model[17..73], false);
    try std.testing.expect(bitmap.anySetInRange(.{ .start = 3, .end = 17 }));
    try std.testing.expect(!bitmap.anySetInRange(.{ .start = 17, .end = 73 }));
    try std.testing.expect(bitmap.anySetInRange(.{ .start = 72, .end = 128 }));
    try std.testing.expect(!bitmap.anySetInRange(.{ .start = 130, .end = 130 }));
    for (model[0..130], 0..) |expected, index| {
        try std.testing.expectEqual(expected, bitmap.isSet(index));
    }

    try bitmap.resize(allocator, 191, true);
    @memset(model[130..191], true);
    try std.testing.expect(bitmap.anySetInRange(.{ .start = 127, .end = 191 }));
    for (model[0..191], 0..) |expected, index| {
        try std.testing.expectEqual(expected, bitmap.isSet(index));
    }
    for (0..192) |start| {
        var expected = start;
        while (expected < 191 and model[expected]) : (expected += 1) {}
        try std.testing.expectEqual(expected, bitmap.firstUnsetFrom(start));
    }

    var cloned = try bitmap.clone(allocator);
    defer cloned.deinit(allocator);
    for (0..131) |prefix_len| {
        var shifted = try cloned.clone(allocator);
        defer shifted.deinit(allocator);
        shifted.removePrefix(prefix_len);
        for (model[prefix_len..191], 0..) |expected, index| {
            try std.testing.expectEqual(expected, shifted.isSet(index));
        }
    }

    bitmap.removePrefix(13);
    for (model[13..191], 0..) |expected, index| {
        try std.testing.expectEqual(expected, bitmap.isSet(index));
        try std.testing.expectEqual(model[index], cloned.isSet(index));
    }
    for (0..179) |start| {
        var expected = start;
        while (expected < 178 and model[13 + expected]) : (expected += 1) {}
        try std.testing.expectEqual(expected, bitmap.firstUnsetFrom(start));
    }
    try bitmap.resize(allocator, 65, false);
    for (model[13..78], 0..) |expected, index| {
        try std.testing.expectEqual(expected, bitmap.isSet(index));
    }
    bitmap.removePrefix(65);
    try std.testing.expectEqual(@as(usize, 0), bitmap.len());
    try std.testing.expectEqual(@as(usize, 0), bitmap.words.items.len);
    try std.testing.expectEqual(
        std.math.maxInt(usize) / Bitmap.word_bits + 1,
        Bitmap.wordCount(std.math.maxInt(usize)),
    );
}
