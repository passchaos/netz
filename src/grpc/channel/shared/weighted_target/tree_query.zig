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
/// True when the node at `path` is a composite policy that can own retained
/// children: weighted_target or priority.
pub fn compositeParent(node: anytype, path: []const []const u8) bool {
    if (!matches(path, node.path)) return false;
    if (equal(node.path, path)) return switch (node.kind) {
        .weighted, .priority => true,
        .outlier => |wrapper| compositeParent(wrapper.child, path),
        .leaf => false,
    };
    return switch (node.kind) {
        .leaf => false,
        .outlier => |wrapper| compositeParent(wrapper.child, path),
        .weighted => |weighted| for (weighted.children) |child| {
            if (compositeParent(child.node, path)) break true;
        } else false,
        .priority => |priority| for (priority.children) |child| {
            if (compositeParent(child.node, path)) break true;
        } else false,
    };
}
