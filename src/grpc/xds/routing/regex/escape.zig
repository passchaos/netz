//! RE2 escapes; capture/backreference and lookaround syntax is never executed.
const std = @import("std");
const m = @import("model.zig");
const classes = @import("classes.zig");
pub const Atom = union(enum) { set: m.Set, assertion: m.Assertion, byte };
fn scalar(value: u32) m.Error!u21 {
    if (value > 0x10ffff) return error.InvalidRegex;
    return @intCast(value);
}
pub fn literal(p: anytype, value: u21) m.Error!m.Set {
    return classes.normalize(p.allocator, &.{.{ .first = value, .last = value }}, false, p.flags.fold, p.limits.max_ranges);
}
fn hexadecimal(p: anytype) m.Error!u21 {
    var value: u32 = 0;
    if (p.take('{')) {
        const start = p.cursor;
        while (p.peek()) |byte| {
            const digit = std.fmt.charToDigit(byte, 16) catch break;
            value = std.math.mul(u32, value, 16) catch return error.InvalidRegex;
            value = std.math.add(u32, value, digit) catch return error.InvalidRegex;
            p.cursor += 1;
        }
        if (p.cursor == start or !p.take('}')) return error.InvalidRegex;
    } else {
        for (0..2) |_| {
            const byte = p.peek() orelse return error.InvalidRegex;
            p.cursor += 1;
            value = value * 16 + (std.fmt.charToDigit(byte, 16) catch return error.InvalidRegex);
        }
    }
    return scalar(value);
}
fn property(p: anytype, negative: bool) m.Error!m.Set {
    var negate = negative;
    const start = p.cursor;
    var name: []const u8 = undefined;
    if (p.take('{')) {
        const offset = p.cursor;
        while (p.peek()) |byte| {
            if (byte == '}') break;
            p.cursor += 1;
        }
        name = p.pattern[offset..p.cursor];
        if (!p.take('}')) return error.InvalidRegex;
    } else {
        if (p.peek() == null) return error.InvalidRegex;
        p.cursor += 1;
        name = p.pattern[start..p.cursor];
    }
    if (name.len != 0 and name[0] == '^') {
        negate = !negate;
        name = name[1..];
    }
    if (std.mem.eql(u8, name, "Any")) return classes.normalize(p.allocator, &.{.{ .first = 0, .last = 0x10ffff }}, negate, p.flags.fold, p.limits.max_ranges);
    const group = m.unicode.lookup(name) orelse return error.InvalidRegex;
    if (group.count > p.limits.max_ranges) return error.RegexLimitExceeded;
    const ranges = try p.allocator.alloc(m.Range, group.count);
    for (ranges, 0..) |*range, index| range.* = group.range(index);
    return classes.normalize(p.allocator, ranges, negate, p.flags.fold, p.limits.max_ranges);
}
pub fn parse(p: anytype, in_class: bool) m.Error!Atom {
    const byte = p.peek() orelse return error.InvalidRegex;
    p.cursor += 1;
    if (std.mem.indexOfScalar(u8, "dDsSwW", byte) != null) {
        const name: []const u8 = switch (std.ascii.toLower(byte)) {
            'd' => "digit",
            's' => "perl_space",
            else => "word",
        };
        return .{ .set = try classes.normalize(p.allocator, classes.ascii(name).?, std.ascii.isUpper(byte), p.flags.fold, p.limits.max_ranges) };
    }
    if (byte == 'p' or byte == 'P') return .{ .set = try property(p, byte == 'P') };
    if (byte == 'C' and !in_class) return .byte;
    if (!in_class) switch (byte) {
        'A' => return .{ .assertion = .start_text },
        'z' => return .{ .assertion = .end_text },
        'b' => return .{ .assertion = .word_boundary },
        'B' => return .{ .assertion = .no_word_boundary },
        else => {},
    };
    const value: u21 = switch (byte) {
        'a' => 7,
        'f' => '\x0c',
        'n' => '\n',
        'r' => '\r',
        't' => '\t',
        'v' => '\x0b',
        'x' => try hexadecimal(p),
        '0'...'7' => blk: {
            var number: u32 = byte - '0';
            var count: usize = 1;
            while (count < 3) {
                const next = p.peek() orelse break;
                if (next < '0' or next > '7') break;
                p.cursor += 1;
                count += 1;
                number = number * 8 + next - '0';
            }
            if (byte != '0' and count == 1) return error.InvalidRegex;
            break :blk try scalar(number);
        },
        else => blk: {
            if (std.ascii.isAlphanumeric(byte)) return error.InvalidRegex;
            if (byte < 128) break :blk byte;
            p.cursor -= 1;
            break :blk try p.rune();
        },
    };
    return .{ .set = try literal(p, value) };
}
