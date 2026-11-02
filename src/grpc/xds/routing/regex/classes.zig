//! Canonical Unicode sets, ASCII Perl/POSIX classes and bounded complements.
const std = @import("std");
const m = @import("model.zig");
pub fn normalize(gpa: std.mem.Allocator, raw: []const m.Range, negate: bool, fold: bool, limit: usize) m.Error!m.Set {
    if (raw.len > limit) return error.RegexLimitExceeded;
    const ranges = try gpa.dupe(m.Range, raw);
    std.mem.sort(m.Range, ranges, {}, struct {
        fn less(_: void, a: m.Range, b: m.Range) bool {
            return a.first < b.first or (a.first == b.first and a.last < b.last);
        }
    }.less);
    var count: usize = 0;
    for (ranges) |range| {
        if (range.first > range.last) return error.InvalidRegex;
        if (count != 0 and @as(u32, range.first) <= @as(u32, ranges[count - 1].last) + 1) {
            ranges[count - 1].last = @max(ranges[count - 1].last, range.last);
        } else {
            ranges[count] = range;
            count += 1;
        }
    }
    return .{ .ranges = ranges[0..count], .negate = negate, .fold = fold };
}
pub fn append(list: *std.ArrayList(m.Range), gpa: std.mem.Allocator, set: m.Set, limit: usize) m.Error!void {
    // Materialize complements before unioning a negated class with other
    // entries. The enclosing class's own negation is applied after folding.
    if (!set.negate) {
        if (list.items.len + set.ranges.len > limit) return error.RegexLimitExceeded;
        try list.appendSlice(gpa, set.ranges);
        return;
    }
    var positive = set;
    positive.negate = false;
    if (set.fold) {
        // Fold the positive equivalence classes before complementing them.
        // Folding an already materialized complement would incorrectly make
        // (?i)[\P{Lu}] accept lower-case letters via their upper-case peers.
        var expanded: std.ArrayList(m.Range) = .empty;
        defer expanded.deinit(gpa);
        try expanded.appendSlice(gpa, set.ranges);
        for (0..m.unicode.fold_range_count) |index| {
            const range = m.unicode.foldRange(index);
            for (@as(u32, range.first)..@as(u32, range.last) + 1) |rune| {
                if (!positive.matches(@intCast(rune))) continue;
                if (expanded.items.len >= limit) return error.RegexLimitExceeded;
                try expanded.append(gpa, .{ .first = @intCast(rune), .last = @intCast(rune) });
            }
        }
        positive = try normalize(gpa, expanded.items, false, false, limit);
    }
    var next: u32 = 0;
    for (positive.ranges) |range| {
        if (next < range.first) {
            if (list.items.len >= limit) return error.RegexLimitExceeded;
            try list.append(gpa, .{ .first = @intCast(next), .last = range.first - 1 });
        }
        next = @as(u32, range.last) + 1;
    }
    if (next <= 0x10ffff) {
        if (list.items.len >= limit) return error.RegexLimitExceeded;
        try list.append(gpa, .{ .first = @intCast(next), .last = 0x10ffff });
    }
}
pub fn ascii(name: []const u8) ?[]const m.Range {
    const digit = &[_]m.Range{.{ .first = '0', .last = '9' }};
    const upper = &[_]m.Range{.{ .first = 'A', .last = 'Z' }};
    const lower = &[_]m.Range{.{ .first = 'a', .last = 'z' }};
    if (std.mem.eql(u8, name, "digit")) return digit;
    if (std.mem.eql(u8, name, "upper")) return upper;
    if (std.mem.eql(u8, name, "lower")) return lower;
    if (std.mem.eql(u8, name, "alpha")) return &.{ upper[0], lower[0] };
    if (std.mem.eql(u8, name, "alnum")) return &.{ digit[0], upper[0], lower[0] };
    if (std.mem.eql(u8, name, "word")) return &.{ digit[0], upper[0], .{ .first = '_', .last = '_' }, lower[0] };
    if (std.mem.eql(u8, name, "xdigit")) return &.{ digit[0], .{ .first = 'A', .last = 'F' }, .{ .first = 'a', .last = 'f' } };
    if (std.mem.eql(u8, name, "blank")) return &.{ .{ .first = '\t', .last = '\t' }, .{ .first = ' ', .last = ' ' } };
    if (std.mem.eql(u8, name, "space")) return &.{ .{ .first = '\t', .last = '\r' }, .{ .first = ' ', .last = ' ' } };
    if (std.mem.eql(u8, name, "perl_space")) return &.{ .{ .first = '\t', .last = '\n' }, .{ .first = '\x0c', .last = '\r' }, .{ .first = ' ', .last = ' ' } };
    if (std.mem.eql(u8, name, "cntrl")) return &.{ .{ .first = 0, .last = 31 }, .{ .first = 127, .last = 127 } };
    if (std.mem.eql(u8, name, "ascii")) return &.{.{ .first = 0, .last = 127 }};
    if (std.mem.eql(u8, name, "graph")) return &.{.{ .first = 33, .last = 126 }};
    if (std.mem.eql(u8, name, "print")) return &.{.{ .first = 32, .last = 126 }};
    if (std.mem.eql(u8, name, "punct")) return &.{ .{ .first = 33, .last = 47 }, .{ .first = 58, .last = 64 }, .{ .first = 91, .last = 96 }, .{ .first = 123, .last = 126 } };
    return null;
}
