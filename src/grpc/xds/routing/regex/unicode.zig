//! RE2 Unicode categories/scripts and simple folding, decoded on any endian.
const std = @import("std");
pub const Range = struct { first: u21, last: u21 };
pub const Entry = struct { name: []const u8, offset: usize, count: usize };
const groups = @import("unicode/groups.zig").entries;
const group_data = @embedFile("unicode/groups.bin");
const fold_data = @embedFile("unicode/fold.bin");
pub const fold_range_count = fold_data.len / 12;
pub fn foldRange(index: usize) Range {
    const bytes = fold_data[index * 12 ..];
    return .{ .first = @intCast(std.mem.readInt(u32, bytes[0..4], .little)), .last = @intCast(std.mem.readInt(u32, bytes[4..8], .little)) };
}
pub const Group = struct {
    offset: usize,
    count: usize,
    pub fn range(self: Group, index: usize) Range {
        const bytes = group_data[self.offset + index * 8 ..];
        return .{ .first = @intCast(std.mem.readInt(u32, bytes[0..4], .little)), .last = @intCast(std.mem.readInt(u32, bytes[4..8], .little)) };
    }
};
pub fn lookup(name: []const u8) ?Group {
    if (std.mem.eql(u8, name, "Any")) return null; // parser handles universal set
    var first: usize = 0;
    var last = groups.len;
    while (first < last) {
        const middle = first + (last - first) / 2;
        const entry = groups[middle];
        switch (std.mem.order(u8, name, entry.name)) {
            .lt => last = middle,
            .gt => first = middle + 1,
            .eq => return .{ .offset = entry.offset, .count = entry.count },
        }
    }
    return null;
}
pub fn foldNext(rune: u21) u21 {
    var first: usize = 0;
    var last = fold_data.len / 12;
    while (first < last) {
        const middle = first + (last - first) / 2;
        const bytes = fold_data[middle * 12 ..];
        const low = std.mem.readInt(u32, bytes[0..4], .little);
        const high = std.mem.readInt(u32, bytes[4..8], .little);
        if (rune < low) last = middle else if (rune > high) first = middle + 1 else {
            const delta = std.mem.readInt(i32, bytes[8..12], .little);
            return switch (delta) {
                1 => if (rune & 1 == 0) rune + 1 else rune - 1,
                -1 => if (rune & 1 == 1) rune + 1 else rune - 1,
                else => @intCast(@as(i32, rune) + delta),
            };
        }
    }
    return rune;
}
