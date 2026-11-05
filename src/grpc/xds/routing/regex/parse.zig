//! Bounded RE2 boolean-match syntax with balanced concatenation/alternation.
const std = @import("std");
const m = @import("model.zig");
const classes = @import("classes.zig");
const escape = @import("escape.zig");
pub const Parser = struct {
    allocator: std.mem.Allocator,
    pattern: []const u8,
    limits: m.Limits,
    cursor: usize = 0,
    nodes: usize = 0,
    captures: u16 = 0,
    flags: m.Flags = .{},
    pub fn peek(self: *Parser) ?u8 {
        return if (self.cursor < self.pattern.len) self.pattern[self.cursor] else null;
    }
    pub fn take(self: *Parser, byte: u8) bool {
        if (self.peek() != byte) return false;
        self.cursor += 1;
        return true;
    }
    pub fn rune(self: *Parser) m.Error!u21 {
        const first = self.peek() orelse return error.InvalidRegex;
        const len = std.unicode.utf8ByteSequenceLength(first) catch return error.InvalidRegex;
        if (len > self.pattern.len - self.cursor) return error.InvalidRegex;
        const value = std.unicode.utf8Decode(self.pattern[self.cursor..][0..len]) catch return error.InvalidRegex;
        self.cursor += len;
        return value;
    }
    fn node(self: *Parser, value: m.Node) m.Error!*const m.Node {
        if (self.nodes >= self.limits.max_nodes) return error.RegexLimitExceeded;
        self.nodes += 1;
        const result = try self.allocator.create(m.Node);
        result.* = value;
        return result;
    }
    fn join(self: *Parser, values: []const *const m.Node, alternate: bool) m.Error!*const m.Node {
        if (values.len == 0) return self.node(.empty);
        if (values.len == 1) return values[0];
        const split = values.len / 2;
        const left = try self.join(values[0..split], alternate);
        const right = try self.join(values[split..], alternate);
        return self.node(if (alternate) .{ .alternate = .{ .left = left, .right = right } } else .{ .pair = .{ .left = left, .right = right } });
    }
    fn expression(self: *Parser, depth: usize) m.Error!*const m.Node {
        if (depth > self.limits.max_depth) return error.RegexLimitExceeded;
        var alternatives: std.ArrayList(*const m.Node) = .empty;
        defer alternatives.deinit(self.allocator);
        while (true) {
            var sequence: std.ArrayList(*const m.Node) = .empty;
            defer sequence.deinit(self.allocator);
            while (self.peek()) |byte| {
                if (byte == '|' or byte == ')') break;
                if (byte == '*' or byte == '+' or byte == '?') return error.InvalidRegex;
                const value = try self.atom(depth);
                try sequence.append(self.allocator, try self.repetition(value));
            }
            try alternatives.append(self.allocator, try self.join(sequence.items, false));
            if (!self.take('|')) break;
        }
        return self.join(alternatives.items, true);
    }
    fn group(self: *Parser, depth: usize) m.Error!*const m.Node {
        const saved = self.flags;
        var capturing = true;
        var capture_index: ?u16 = null;
        if (self.take('?')) {
            if (self.take(':')) {
                capturing = false;
            } else if (self.take('P')) {
                if (!self.take('<')) return error.InvalidRegex;
                try self.name();
            } else if (self.take('<')) {
                try self.name();
            } else {
                var negative = false;
                var flag_count: usize = 0;
                var negative_count: usize = 0;
                while (self.peek()) |byte| {
                    if (byte == '-') {
                        if (negative) return error.InvalidRegex;
                        negative = true;
                        self.cursor += 1;
                        continue;
                    }
                    switch (byte) {
                        'i' => self.flags.fold = !negative,
                        'm' => self.flags.multiline = !negative,
                        's' => self.flags.dot_newline = !negative,
                        'U' => {}, // greedy/lazy affects captures, not membership
                        else => break,
                    }
                    self.cursor += 1;
                    flag_count += 1;
                    if (negative) negative_count += 1;
                }
                if (flag_count == 0 or (negative and negative_count == 0)) return error.InvalidRegex;
                if (self.take(')')) return self.node(.flag_change);
                if (!self.take(':')) return error.InvalidRegex;
                capturing = false;
            }
        }
        if (capturing) {
            if (self.captures == std.math.maxInt(u16)) return error.RegexLimitExceeded;
            self.captures += 1;
            capture_index = self.captures;
        }
        defer self.flags = saved;
        const value = try self.expression(depth + 1);
        if (!self.take(')')) return error.InvalidRegex;
        if (capture_index) |index| {
            return self.node(.{ .capture = .{ .index = index, .child = value } });
        }
        return self.node(.{ .group = value });
    }
    fn name(self: *Parser) m.Error!void {
        const start = self.cursor;
        while (self.peek()) |byte| {
            if (byte == '>') break;
            if (!std.ascii.isAlphanumeric(byte) and byte != '_') return error.InvalidRegex;
            self.cursor += 1;
        }
        if (self.cursor == start or !self.take('>')) return error.InvalidRegex;
    }
    fn element(self: *Parser) m.Error!m.Set {
        if (self.take('\\')) {
            const escaped = try escape.parse(self, true);
            return if (escaped == .set) escaped.set else error.InvalidRegex;
        }
        if (self.peek() == '[' and std.mem.startsWith(u8, self.pattern[self.cursor..], "[:")) {
            self.cursor += 2;
            const negate = self.take('^');
            const start = self.cursor;
            while (self.peek()) |byte| {
                if (byte == ':') break;
                self.cursor += 1;
            }
            const name_value = self.pattern[start..self.cursor];
            if (!self.take(':') or !self.take(']')) return error.InvalidRegex;
            return classes.normalize(self.allocator, classes.ascii(name_value) orelse return error.InvalidRegex, negate, self.flags.fold, self.limits.max_ranges);
        }
        return escape.literal(self, try self.rune());
    }
    fn characterClass(self: *Parser) m.Error!*const m.Node {
        const negate = self.take('^');
        var ranges: std.ArrayList(m.Range) = .empty;
        defer ranges.deinit(self.allocator);
        var first = true;
        while (self.peek()) |_| {
            if (!first and self.take(']')) return self.node(.{ .set = try classes.normalize(self.allocator, ranges.items, negate, self.flags.fold, self.limits.max_ranges) });
            first = false;
            const start = try self.element();
            if (self.peek() == '-' and self.cursor + 1 < self.pattern.len and self.pattern[self.cursor + 1] != ']') {
                self.cursor += 1;
                const end = try self.element();
                if (start.negate or end.negate or start.ranges.len != 1 or end.ranges.len != 1 or start.ranges[0].first != start.ranges[0].last or end.ranges[0].first != end.ranges[0].last) return error.InvalidRegex;
                if (ranges.items.len >= self.limits.max_ranges) return error.RegexLimitExceeded;
                try ranges.append(self.allocator, .{ .first = start.ranges[0].first, .last = end.ranges[0].first });
            } else try classes.append(&ranges, self.allocator, start, self.limits.max_ranges);
        }
        return error.InvalidRegex;
    }
    fn atom(self: *Parser, depth: usize) m.Error!*const m.Node {
        const byte = self.peek() orelse return error.InvalidRegex;
        self.cursor += 1;
        return switch (byte) {
            '(' => self.group(depth),
            '[' => self.characterClass(),
            '.' => self.node(.{ .set = try classes.normalize(self.allocator, if (self.flags.dot_newline) &.{.{ .first = 0, .last = 0x10ffff }} else &.{.{ .first = '\n', .last = '\n' }}, !self.flags.dot_newline, false, self.limits.max_ranges) }),
            '^' => self.node(.{ .assertion = if (self.flags.multiline) .start_line else .start_text }),
            '$' => self.node(.{ .assertion = if (self.flags.multiline) .end_line else .end_text }),
            '\\' => blk: {
                break :blk switch (try escape.parse(self, false)) {
                    .set => |set| self.node(.{ .set = set }),
                    .byte => self.node(.byte),
                    .assertion => |assertion| self.node(.{ .assertion = assertion }),
                };
            },
            '{' => blk: {
                self.cursor -= 1;
                if (try self.counted() != null) return error.InvalidRegex;
                break :blk self.node(.{ .set = try escape.literal(self, try self.rune()) });
            },
            else => blk: {
                self.cursor -= 1;
                break :blk self.node(.{ .set = try escape.literal(self, try self.rune()) });
            },
        };
    }
    fn number(self: *Parser) ?usize {
        const start = self.cursor;
        while (self.peek()) |byte| {
            if (!std.ascii.isDigit(byte)) break;
            self.cursor += 1;
        }
        if (start == self.cursor) return null;
        return std.fmt.parseInt(usize, self.pattern[start..self.cursor], 10) catch std.math.maxInt(usize);
    }
    fn counted(self: *Parser) m.Error!?struct { minimum: usize, maximum: ?usize } {
        const saved = self.cursor;
        if (!self.take('{')) return null;
        const minimum = self.number() orelse {
            self.cursor = saved;
            return null;
        };
        var maximum: ?usize = minimum;
        if (self.take(',')) maximum = self.number();
        if (!self.take('}')) {
            self.cursor = saved;
            return null;
        }
        if (minimum > 1000 or (maximum != null and (maximum.? > 1000 or maximum.? < minimum))) return error.InvalidRegex;
        if (minimum > self.limits.max_repeat or (maximum != null and maximum.? > self.limits.max_repeat)) return error.RegexLimitExceeded;
        return .{ .minimum = minimum, .maximum = maximum };
    }
    fn repetition(self: *Parser, child: *const m.Node) m.Error!*const m.Node {
        var minimum: usize = 0;
        var maximum: ?usize = null;
        if (self.take('*')) {} else if (self.take('+')) {
            minimum = 1;
        } else if (self.take('?')) {
            maximum = 1;
        } else if (self.peek() == '{') {
            const count = try self.counted() orelse return child;
            minimum = count.minimum;
            maximum = count.maximum;
        } else return child;
        if (child.* == .flag_change) return error.InvalidRegex;
        const lazy = self.take('?');
        if (self.peek()) |byte| if (byte == '*' or byte == '+' or byte == '?') return error.InvalidRegex;
        return self.node(.{ .repeat = .{
            .child = child,
            .minimum = minimum,
            .maximum = maximum,
            .lazy = lazy,
        } });
    }
};
fn unquote(gpa: std.mem.Allocator, pattern: []const u8) m.Error![]const u8 {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(gpa);
    var index: usize = 0;
    var quoted = false;
    while (index < pattern.len) : (index += 1) {
        const byte = pattern[index];
        if (byte == '\\' and index + 1 < pattern.len) {
            if ((!quoted and pattern[index + 1] == 'Q') or (quoted and pattern[index + 1] == 'E')) {
                quoted = !quoted;
                index += 1;
                continue;
            }
            if (!quoted) {
                try bytes.appendSlice(gpa, pattern[index..][0..2]);
                index += 1;
                continue;
            }
        }
        if (quoted and std.mem.indexOfScalar(u8, "\\.^$[]{}()*+?|", byte) != null) try bytes.append(gpa, '\\');
        try bytes.append(gpa, byte);
    }
    return bytes.toOwnedSlice(gpa);
}
pub fn parse(gpa: std.mem.Allocator, pattern: []const u8, limits: m.Limits) m.Error!*const m.Node {
    if (pattern.len > limits.max_pattern_bytes) return error.RegexLimitExceeded;
    if (!std.unicode.utf8ValidateSlice(pattern)) return error.InvalidRegex;
    var parser = Parser{ .allocator = gpa, .pattern = try unquote(gpa, pattern), .limits = limits };
    const result = try parser.expression(0);
    if (parser.cursor != parser.pattern.len) return error.InvalidRegex;
    return result;
}
