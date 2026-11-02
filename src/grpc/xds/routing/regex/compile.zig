//! Thompson construction; no backtracking or recursive execution.
const std = @import("std");
const model = @import("model.zig");
pub const Program = struct { instructions: []const model.Instruction, start: usize };
const Builder = struct {
    allocator: std.mem.Allocator,
    limits: model.Limits,
    instructions: std.ArrayList(model.Instruction) = .empty,
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
            .byte => self.emit(.{ .byte = continuation }),
            .set => |set| self.emit(.{ .consume = .{ .set = set, .next = continuation } }),
            .assertion => |kind| self.emit(.{ .assertion = .{ .kind = kind, .next = continuation } }),
            .pair => |pair| self.node(pair.left, try self.node(pair.right, continuation)),
            .alternate => |pair| self.emit(.{ .split = .{ .left = try self.node(pair.left, continuation), .right = try self.node(pair.right, continuation) } }),
            .repeat => |repeat| blk: {
                var next = continuation;
                if (repeat.maximum) |maximum| {
                    for (repeat.minimum..maximum) |_| next = try self.emit(.{ .split = .{ .left = try self.node(repeat.child, next), .right = next } });
                } else {
                    const split = try self.emit(.{ .split = .{ .left = 0, .right = next } });
                    const child = try self.node(repeat.child, split);
                    self.instructions.items[split].split.left = child;
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
    const start = try builder.node(root, accept);
    return .{ .instructions = try builder.instructions.toOwnedSlice(allocator), .start = start };
}
