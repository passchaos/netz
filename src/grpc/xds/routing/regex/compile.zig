//! Thompson construction. Boolean execution is linear; capture-aware
//! replacement uses the bounded backtracking VM in `replace.zig`.
const std = @import("std");
const model = @import("model.zig");
pub const Program = struct {
    instructions: []const model.Instruction,
    start: usize,
    capture_count: u16 = 0,
    /// RE2-style rewrites only reference groups 1 through 9.
    pub fn trackedCaptures(self: Program) u16 {
        return @min(self.capture_count, 9);
    }
};
const Builder = struct {
    allocator: std.mem.Allocator,
    limits: model.Limits,
    instructions: std.ArrayList(model.Instruction) = .empty,
    captures: u16 = 0,
    fn emit(self: *Builder, value: model.Instruction) model.Error!usize {
        if (self.instructions.items.len >= self.limits.max_instructions) return error.RegexLimitExceeded;
        const index = self.instructions.items.len;
        try self.instructions.append(self.allocator, value);
        return index;
    }
    fn node(self: *Builder, value: *const model.Node, continuation: usize) model.Error!usize {
        return switch (value.*) {
            .empty, .flag_change => continuation,
            .group => |child| self.node(child, continuation),
            .capture => |capture| blk: {
                self.captures = @max(self.captures, capture.index);
                // Groups above nine cannot appear in an RE2 replacement
                // string, so compile them as ordinary grouping.
                if (capture.index > 9) break :blk self.node(capture.child, continuation);
                const end = try self.emit(.{ .save = .{
                    .slot = capture.index * 2 + 1,
                    .next = continuation,
                } });
                const child = try self.node(capture.child, end);
                break :blk try self.emit(.{ .save = .{
                    .slot = capture.index * 2,
                    .next = child,
                } });
            },
            .byte => self.emit(.{ .byte = continuation }),
            .set => |set| self.emit(.{ .consume = .{ .set = set, .next = continuation } }),
            .assertion => |kind| self.emit(.{ .assertion = .{ .kind = kind, .next = continuation } }),
            .pair => |pair| self.node(pair.left, try self.node(pair.right, continuation)),
            .alternate => |pair| self.emit(.{ .split = .{ .left = try self.node(pair.left, continuation), .right = try self.node(pair.right, continuation) } }),
            .repeat => |repeat| blk: {
                var next = continuation;
                if (repeat.maximum) |maximum| {
                    for (repeat.minimum..maximum) |_| {
                        const child = try self.node(repeat.child, next);
                        next = try self.emit(if (repeat.lazy)
                            .{ .split = .{ .left = next, .right = child } }
                        else
                            .{ .split = .{ .left = child, .right = next } });
                    }
                } else {
                    const split = try self.emit(.{ .split = .{ .left = 0, .right = 0 } });
                    const child = try self.node(repeat.child, split);
                    self.instructions.items[split].split = if (repeat.lazy)
                        .{ .left = next, .right = child }
                    else
                        .{ .left = child, .right = next };
                    next = split;
                }
                for (0..repeat.minimum) |_| next = try self.node(repeat.child, next);
                break :blk next;
            },
        };
    }
};
pub fn compile(allocator: std.mem.Allocator, root: *const model.Node, limits: model.Limits) model.Error!Program {
    var builder = Builder{ .allocator = allocator, .limits = limits };
    defer builder.instructions.deinit(allocator);
    const accept = try builder.emit(.accept);
    const match_end = try builder.emit(.{ .save = .{ .slot = 1, .next = accept } });
    const body = try builder.node(root, match_end);
    const start = try builder.emit(.{ .save = .{ .slot = 0, .next = body } });
    return .{
        .instructions = try builder.instructions.toOwnedSlice(allocator),
        .start = start,
        .capture_count = builder.captures,
    };
}
