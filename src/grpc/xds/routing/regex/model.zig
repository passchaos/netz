//! Immutable syntax/character sets and bounded Thompson instructions.
const std = @import("std");
pub const unicode = @import("unicode.zig");
pub const Error = std.mem.Allocator.Error || error{ InvalidRegex, UnsupportedRegexFeature, RegexLimitExceeded };
pub const Limits = struct {
    max_pattern_bytes: usize = 4096,
    max_nodes: usize = 8192,
    max_instructions: usize = 8192,
    max_depth: usize = 64,
    max_repeat: usize = 1000,
    max_ranges: usize = 4096,
    /// Bounded backtracking budget for capture-aware replacement. Boolean
    /// matching remains linear and does not use these.
    max_execution_steps: usize = 4_000_000,
    max_backtrack_choices: usize = 262_144,
    max_capture_trail: usize = 262_144,
};
pub const Flags = struct { fold: bool = false, dot_newline: bool = false, multiline: bool = false };
pub const Range = unicode.Range;
pub const Set = struct {
    ranges: []const Range,
    negate: bool = false,
    fold: bool = false,
    fn includes(self: Set, rune: u21) bool {
        // Parser merges and sorts ranges before instruction construction.
        var first: usize = 0;
        var last = self.ranges.len;
        while (first < last) {
            const middle = first + (last - first) / 2;
            const range = self.ranges[middle];
            if (rune < range.first) last = middle else if (rune > range.last) first = middle + 1 else return true;
        }
        return false;
    }
    pub fn matches(self: Set, rune: u21) bool {
        var found = self.includes(rune);
        if (!found and self.fold) {
            var next = unicode.foldNext(rune);
            while (next != rune) : (next = unicode.foldNext(next)) {
                if (self.includes(next)) {
                    found = true;
                    break;
                }
            }
        }
        return found != self.negate;
    }
};
pub const Assertion = enum { start_text, end_text, start_line, end_line, word_boundary, no_word_boundary };
pub const Node = union(enum) {
    empty,
    flag_change,
    group: *const Node,
    /// Numbered capturing group. `index` is 1-based in opening-paren order.
    capture: struct { index: u16, child: *const Node },
    byte,
    set: Set,
    pair: struct { left: *const Node, right: *const Node },
    alternate: struct { left: *const Node, right: *const Node },
    repeat: struct {
        child: *const Node,
        minimum: usize,
        maximum: ?usize,
        lazy: bool = false,
    },
    assertion: Assertion,
};
pub const Instruction = union(enum) {
    accept,
    byte: usize,
    consume: struct { set: Set, next: usize },
    split: struct { left: usize, right: usize },
    assertion: struct { kind: Assertion, next: usize },
    /// Capture boundary. Slot 0/1 are the whole match; group `i` uses
    /// slots `2*i` and `2*i+1`.
    save: struct { slot: u16, next: usize },
};
