const std = @import("std");

pub fn matches(path: []const []const u8, prefix: []const []const u8) bool {
    if (path.len < prefix.len) return false;
    for (path[0..prefix.len], prefix) |a, b| if (!std.mem.eql(u8, a, b)) return false;
    return true;
}
pub fn equal(a: []const []const u8, b: []const []const u8) bool {
    return a.len == b.len and matches(a, b);
}
pub fn accepts(node: anytype, path: []const []const u8) bool {
    if (!matches(path, node.path)) return false;
    return switch (node.kind) {
        .leaf => true,
        .outlier => |wrapper| accepts(wrapper.child, path),
        .weighted => |weighted| for (weighted.children) |child| {
            if (accepts(child.node, path)) break true;
        } else false,
        .priority => |priority| for (priority.children) |child| {
            if (accepts(child.node, path)) break true;
        } else false,
    };
}
pub fn weightedParent(node: anytype, path: []const []const u8) bool {
    if (!matches(path, node.path)) return false;
    if (equal(node.path, path) and node.kind == .weighted) return true;
    return switch (node.kind) {
        .leaf => false,
        .outlier => |wrapper| weightedParent(wrapper.child, path),
        .weighted => |weighted| for (weighted.children) |child| {
            if (weightedParent(child.node, path)) break true;
        } else false,
        .priority => |priority| for (priority.children) |child| {
            if (weightedParent(child.node, path)) break true;
        } else false,
    };
}
