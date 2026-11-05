//! Deduplicated epsilon closures bound work by input runes times program size.
const std = @import("std");
const model = @import("model.zig");
const Program = @import("compile.zig").Program;
const budget_mod = @import("budget.zig");
pub const Stats = struct { input_bytes: usize = 0, states_visited: usize = 0 };
const Position = struct {
    start: bool,
    end: bool,
    previous: ?u21,
    next: ?u21,
    fn word(rune: ?u21) bool {
        const value = rune orelse return false;
        return value == '_' or (value >= 'a' and value <= 'z') or (value >= 'A' and value <= 'Z') or (value >= '0' and value <= '9');
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
pub const Workspace = struct {
    allocator: std.mem.Allocator,
    storage: []usize,
    seen: []usize,
    epoch: usize = 0,
    stats: Stats = .{},
    budget: ?budget_mod.Budget = null,
    pub fn init(allocator: std.mem.Allocator, program: Program) std.mem.Allocator.Error!Workspace {
        const storage = try allocator.alloc(usize, program.instructions.len * 6);
        errdefer allocator.free(storage);
        const seen = try allocator.alloc(usize, program.instructions.len * 5);
        @memset(seen, 0);
        return .{ .allocator = allocator, .storage = storage, .seen = seen };
    }
    pub fn deinit(self: *Workspace) void {
        self.allocator.free(self.storage);
        self.allocator.free(self.seen);
        self.* = undefined;
    }
    fn push(self: *Workspace, seen: []usize, stack: []usize, count: *usize, index: usize) void {
        if (seen[index] == self.epoch) return;
        seen[index] = self.epoch;
        stack[count.*] = index;
        count.* += 1;
    }
    fn add(self: *Workspace, program: Program, index: usize, context: Position, list: []usize, count: *usize, stack: []usize, seen: []usize) budget_mod.Error!void {
        var pending: usize = 0;
        self.push(seen, stack, &pending, index);
        while (pending != 0) {
            pending -= 1;
            const current = stack[pending];
            self.stats.states_visited += 1;
            if (self.stats.states_visited & 4095 == 0) if (self.budget) |budget| try budget.check();
            switch (program.instructions[current]) {
                .accept, .consume, .byte => {
                    list[count.*] = current;
                    count.* += 1;
                },
                .split => |split| {
                    self.push(seen, stack, &pending, split.right);
                    self.push(seen, stack, &pending, split.left);
                },
                .save => |save| self.push(seen, stack, &pending, save.next),
                .assertion => |assertion| if (context.allows(assertion.kind)) self.push(seen, stack, &pending, assertion.next),
            }
        }
    }
    fn position(input: []const u8, offset: usize) Position {
        return .{ .start = offset == 0, .end = offset == input.len, .previous = if (offset == 0) null else input[offset - 1], .next = if (offset == input.len) null else input[offset] };
    }
    fn runeAt(input: []const u8, offset: usize) ?struct { value: u21, len: usize } {
        const len = std.unicode.utf8ByteSequenceLength(input[offset]) catch return null;
        if (len > input.len - offset) return null;
        const value = std.unicode.utf8Decode(input[offset..][0..len]) catch return null;
        return .{ .value = value, .len = len };
    }
    pub fn matches(self: *Workspace, program: Program, input: []const u8) bool {
        return self.execute(program, input, null) catch unreachable;
    }
    pub fn matchesWithBudget(self: *Workspace, program: Program, input: []const u8, budget: budget_mod.Budget) budget_mod.Error!bool {
        return self.execute(program, input, budget);
    }
    fn execute(self: *Workspace, program: Program, input: []const u8, budget: ?budget_mod.Budget) budget_mod.Error!bool {
        const n = program.instructions.len;
        std.debug.assert(self.storage.len >= n * 6 and self.seen.len >= n * 5);
        self.stats = .{ .input_bytes = input.len };
        self.budget = budget;
        if (budget) |active| try active.check();
        @memset(self.seen, 0);
        var counts = [_]usize{0} ** 5;
        const stack = self.storage[n * 5 ..][0..n];
        self.epoch = 1;
        try self.add(program, program.start, position(input, 0), self.storage[0..n], &counts[0], stack, self.seen[0..n]);
        // Rune transitions advance 1..4 bytes; \C advances exactly one.
        // Five rotating buckets retain only future positions without letting
        // a 4-byte transition overwrite the list being consumed.
        for (0..input.len + 1) |offset| {
            if (offset & 4095 == 0) if (budget) |active| try active.check();
            const slot = offset % 5;
            const count = counts[slot];
            counts[slot] = 0;
            if (count == 0) continue;
            const rune = if (offset < input.len) runeAt(input, offset) else null;
            for (self.storage[slot * n ..][0..count]) |index| {
                const continuation, const advance = switch (program.instructions[index]) {
                    .accept => if (offset == input.len) return true else continue,
                    .byte => |next| if (offset < input.len) .{ next, @as(usize, 1) } else continue,
                    .consume => |consume| if (rune) |value|
                        if (consume.set.matches(value.value)) .{ consume.next, value.len } else continue
                    else
                        continue,
                    else => unreachable,
                };
                const destination = offset + advance;
                const bucket = destination % 5;
                self.epoch = destination + 1;
                try self.add(program, continuation, position(input, destination), self.storage[bucket * n ..][0..n], &counts[bucket], stack, self.seen[bucket * n ..][0..n]);
            }
        }
        return false;
    }
};
