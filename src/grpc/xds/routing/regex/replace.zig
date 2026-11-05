//! Bounded capture-aware RE2 replacement used by xDS regex rewrites.
//!
//! Boolean matching stays on the linear Thompson engine. Replacement needs
//! capture boundaries and leftmost-first priority, so this module runs the
//! compiled program with an explicit backtracking stack and a hard work budget.
//! The budget makes pathological patterns fail closed instead of running
//! unboundedly.
const std = @import("std");
const model = @import("model.zig");
const Program = @import("compile.zig").Program;
const unset = std.math.maxInt(usize);
const max_tracked_captures: usize = 9;
pub const Error = model.Error;

const Choice = struct { pc: usize, pos: usize, trail_len: usize };
const Trail = struct { slot: u16, old: usize };

pub const Match = struct {
    start: usize,
    end: usize,
    /// Slots for the whole match (0,1) and groups 1..9 (2*i,2*i+1).
    slots: []const usize,
};

pub const Workspace = struct {
    allocator: std.mem.Allocator,
    program: Program,
    limits: model.Limits,
    slots: []usize,
    choices: std.ArrayList(Choice) = .empty,
    trail: std.ArrayList(Trail) = .empty,
    steps: usize = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        program: Program,
        limits: model.Limits,
    ) std.mem.Allocator.Error!Workspace {
        const slot_count = 2 * (@as(usize, program.trackedCaptures()) + 1);
        const slots = try allocator.alloc(usize, slot_count);
        @memset(slots, unset);
        return .{
            .allocator = allocator,
            .program = program,
            .limits = limits,
            .slots = slots,
        };
    }

    pub fn deinit(self: *Workspace) void {
        self.choices.deinit(self.allocator);
        self.trail.deinit(self.allocator);
        self.allocator.free(self.slots);
        self.* = undefined;
    }

    /// Find the leftmost-first match at or after `search_start`.
    pub fn find(
        self: *Workspace,
        input: []const u8,
        search_start: usize,
    ) Error!?Match {
        self.steps = 0;
        return self.findInternal(input, search_start);
    }

    /// Replace every non-overlapping leftmost-first match. RE2 substitution
    /// syntax is used: `\0` is the whole match, `\1`..`\9` are capture groups,
    /// `\\` is a literal backslash, and any other `\x` is emitted literally.
    pub fn replaceAll(
        self: *Workspace,
        input: []const u8,
        substitution: []const u8,
    ) Error![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(self.allocator);
        var writer = ListWriter{ .list = &out, .allocator = self.allocator };
        try self.replaceAllWith(&writer, input, substitution);
        return out.toOwnedSlice(self.allocator);
    }

    /// Compute the exact replacement length without materializing the output.
    pub fn replaceAllLen(
        self: *Workspace,
        input: []const u8,
        substitution: []const u8,
    ) Error!usize {
        var length: usize = 0;
        var writer = LengthWriter{ .length = &length };
        try self.replaceAllWith(&writer, input, substitution);
        return length;
    }

    /// Write the replacement into a caller-owned buffer. The buffer must be at
    /// least as large as `replaceAllLen`; otherwise the work fails closed.
    pub fn replaceAllInto(
        self: *Workspace,
        input: []const u8,
        substitution: []const u8,
        output: []u8,
    ) Error![]const u8 {
        var writer = BufferWriter{ .output = output };
        try self.replaceAllWith(&writer, input, substitution);
        return output[0..writer.len];
    }

    fn replaceAllWith(
        self: *Workspace,
        writer: anytype,
        input: []const u8,
        substitution: []const u8,
    ) Error!void {
        try validateSubstitution(substitution, self.program.capture_count);
        self.steps = 0;
        var search_start: usize = 0;
        while (search_start <= input.len) {
            const match = try self.findInternal(input, search_start) orelse break;
            try writer.appendSlice(input[search_start..match.start]);
            try appendSubstitution(writer, input, substitution, match.slots);
            if (match.end > match.start) {
                search_start = match.end;
            } else {
                if (match.start == input.len) {
                    search_start = input.len + 1;
                    break;
                }
                const len = runeLenAt(input, match.start);
                try writer.appendSlice(input[match.start..][0..len]);
                search_start = match.start + len;
            }
        }
        if (search_start <= input.len) {
            try writer.appendSlice(input[search_start..]);
        }
    }

    fn findInternal(
        self: *Workspace,
        input: []const u8,
        search_start: usize,
    ) Error!?Match {
        if (search_start > input.len) return null;
        var start = search_start;
        while (start <= input.len) {
            @memset(self.slots, unset);
            if (try self.run(input, start)) |end| {
                return .{ .start = start, .end = end, .slots = self.slots };
            }
            if (start == input.len) break;
            start += runeLenAt(input, start);
        }
        return null;
    }

    fn run(self: *Workspace, input: []const u8, start: usize) Error!?usize {
        self.choices.clearRetainingCapacity();
        self.trail.clearRetainingCapacity();
        var pc = self.program.start;
        var pos = start;
        while (true) {
            self.steps += 1;
            if (self.steps > self.limits.max_execution_steps) {
                return error.RegexLimitExceeded;
            }
            switch (self.program.instructions[pc]) {
                .accept => return pos,
                .byte => |next| {
                    if (pos < input.len) {
                        pos += 1;
                        pc = next;
                        continue;
                    }
                },
                .consume => |consume| {
                    if (runeAt(input, pos)) |rune| {
                        if (consume.set.matches(rune.value)) {
                            pos += rune.len;
                            pc = consume.next;
                            continue;
                        }
                    }
                },
                .save => |save| {
                    if (self.trail.items.len >= self.limits.max_capture_trail) {
                        return error.RegexLimitExceeded;
                    }
                    try self.trail.append(self.allocator, .{
                        .slot = save.slot,
                        .old = self.slots[save.slot],
                    });
                    self.slots[save.slot] = pos;
                    pc = save.next;
                    continue;
                },
                .split => |split| {
                    if (self.choices.items.len >= self.limits.max_backtrack_choices) {
                        return error.RegexLimitExceeded;
                    }
                    try self.choices.append(self.allocator, .{
                        .pc = split.right,
                        .pos = pos,
                        .trail_len = self.trail.items.len,
                    });
                    pc = split.left;
                    continue;
                },
                .assertion => |assertion| {
                    if (position(input, pos).allows(assertion.kind)) {
                        pc = assertion.next;
                        continue;
                    }
                },
            }
            const choice = self.choices.pop() orelse return null;
            while (self.trail.items.len > choice.trail_len) {
                const entry = self.trail.pop().?;
                self.slots[entry.slot] = entry.old;
            }
            pc = choice.pc;
            pos = choice.pos;
        }
    }
};

pub fn validateSubstitution(
    substitution: []const u8,
    capture_count: u16,
) Error!void {
    var index: usize = 0;
    while (index < substitution.len) : (index += 1) {
        if (substitution[index] != '\\') continue;
        index += 1;
        if (index == substitution.len) return error.InvalidRegex;
        const escaped = substitution[index];
        if (escaped >= '0' and escaped <= '9') {
            if (escaped - '0' > capture_count) return error.InvalidRegex;
        }
    }
}

fn appendSubstitution(
    writer: anytype,
    input: []const u8,
    substitution: []const u8,
    slots: []const usize,
) Error!void {
    var index: usize = 0;
    while (index < substitution.len) : (index += 1) {
        const byte = substitution[index];
        if (byte != '\\') {
            try writer.append(byte);
            continue;
        }
        index += 1;
        const escaped = substitution[index];
        if (escaped >= '0' and escaped <= '9') {
            const group: usize = escaped - '0';
            const begin = slots[group * 2];
            const end = slots[group * 2 + 1];
            if (begin != unset and end != unset and end >= begin) {
                try writer.appendSlice(input[begin..end]);
            }
        } else if (escaped == '\\') {
            try writer.append('\\');
        } else {
            try writer.append('\\');
            try writer.append(escaped);
        }
    }
}

const ListWriter = struct {
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    fn append(self: *ListWriter, byte: u8) Error!void {
        try self.list.append(self.allocator, byte);
    }
    fn appendSlice(self: *ListWriter, bytes: []const u8) Error!void {
        try self.list.appendSlice(self.allocator, bytes);
    }
};

const LengthWriter = struct {
    length: *usize,
    fn append(self: *LengthWriter, _: u8) Error!void {
        self.length.* += 1;
    }
    fn appendSlice(self: *LengthWriter, bytes: []const u8) Error!void {
        self.length.* += bytes.len;
    }
};

const BufferWriter = struct {
    output: []u8,
    len: usize = 0,
    fn append(self: *BufferWriter, byte: u8) Error!void {
        if (self.len >= self.output.len) return error.RegexLimitExceeded;
        self.output[self.len] = byte;
        self.len += 1;
    }
    fn appendSlice(self: *BufferWriter, bytes: []const u8) Error!void {
        if (bytes.len > self.output.len - self.len) {
            return error.RegexLimitExceeded;
        }
        @memcpy(self.output[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }
};

const Position = struct {
    start: bool,
    end: bool,
    previous: ?u21,
    next: ?u21,
    fn word(rune: ?u21) bool {
        const value = rune orelse return false;
        return value == '_' or
            (value >= 'a' and value <= 'z') or
            (value >= 'A' and value <= 'Z') or
            (value >= '0' and value <= '9');
    }
    fn allows(self: Position, assertion: model.Assertion) bool {
        const boundary = word(self.previous) != word(self.next);
        return switch (assertion) {
            .start_text => self.start,
            .end_text => self.end,
            .start_line => self.start or self.previous == '\n',
            .end_line => self.end or self.next == '\n',
            .word_boundary => boundary,
            .no_word_boundary => !boundary,
        };
    }
};

fn position(input: []const u8, offset: usize) Position {
    return .{
        .start = offset == 0,
        .end = offset == input.len,
        .previous = if (offset == 0) null else input[offset - 1],
        .next = if (offset == input.len) null else input[offset],
    };
}

fn runeAt(input: []const u8, offset: usize) ?struct { value: u21, len: usize } {
    if (offset >= input.len) return null;
    const len = std.unicode.utf8ByteSequenceLength(input[offset]) catch return null;
    if (len > input.len - offset) return null;
    const value = std.unicode.utf8Decode(input[offset..][0..len]) catch return null;
    return .{ .value = value, .len = len };
}

fn runeLenAt(input: []const u8, offset: usize) usize {
    return if (runeAt(input, offset)) |rune| rune.len else 1;
}

test {
    _ = @import("replace_tests.zig");
}
