const std = @import("std");

pub fn matches(path: []const []const u8, prefix: []const []const u8) bool {
    if (path.len < prefix.len) return false;
    for (path[0..prefix.len], prefix) |a, b| if (!std.mem.eql(u8, a, b)) return false;
    return true;
}
pub fn equal(a: []const []const u8, b: []const []const u8) bool {
    return a.len == b.len and matches(a, b);
}

/// The ordinary runtime stores weighted children directly as a slice while
/// the shared runtime keeps them in a struct; both shapes expose `.node`.
fn WeightedChild(comptime W: type) type {
    return switch (@typeInfo(W)) {
        .pointer => |pointer| pointer.child,
        else => @typeInfo(@FieldType(W, "children")).pointer.child,
    };
}
pub fn weightedChildren(weighted: anytype) []const WeightedChild(@TypeOf(weighted)) {
    return switch (@typeInfo(@TypeOf(weighted))) {
        .pointer => weighted,
        else => weighted.children,
    };
}

pub fn accepts(node: anytype, path: []const []const u8) bool {
    if (!matches(path, node.path)) return false;
    return switch (node.kind) {
        .leaf => true,
        .outlier => |wrapper| accepts(wrapper.child, path),
        .weighted => |weighted| for (weightedChildren(weighted)) |child| {
            if (accepts(child.node, path)) break true;
        } else false,
        .priority => |priority| for (priority.children) |child| {
            if (accepts(child.node, path)) break true;
        } else false,
    };
}
/// True when any priority child enclosing `path` suppresses the child policy's
/// re-resolution requests, matching grpc-core's
/// `ignoreReresolutionRequests` flag.
pub fn ignoresReresolution(node: anytype, path: []const []const u8) bool {
    if (!matches(path, node.path)) return false;
    return switch (node.kind) {
        .leaf => false,
        .outlier => |wrapper| ignoresReresolution(wrapper.child, path),
        .weighted => |weighted| for (weightedChildren(weighted)) |child| {
            if (ignoresReresolution(child.node, path)) break true;
        } else false,
        .priority => |priority| for (priority.children) |child| {
            if (matches(path, child.node.path) and
                child.ignore_reresolution_requests) break true;
            if (ignoresReresolution(child.node, path)) break true;
        } else false,
    };
}

/// True when the pick_first leaf at `path` requests address-list shuffling.
pub fn shufflesAddressList(node: anytype, path: []const []const u8) bool {
    if (!matches(path, node.path)) return false;
    return switch (node.kind) {
        .leaf => |leaf| leaf.shuffle_address_list,
        .outlier => |wrapper| shufflesAddressList(wrapper.child, path),
        .weighted => |weighted| for (weightedChildren(weighted)) |child| {
            if (shufflesAddressList(child.node, path)) break true;
        } else false,
        .priority => |priority| for (priority.children) |child| {
            if (shufflesAddressList(child.node, path)) break true;
        } else false,
    };
}

/// Return the actual shuffled leaf's prefix. Resolver endpoint paths may
/// retain suffix metadata; those endpoints still belong to one leaf pool.
pub fn shuffledLeafPath(node: anytype, path: []const []const u8) ?[]const []const u8 {
    if (!matches(path, node.path)) return null;
    return switch (node.kind) {
        .leaf => |leaf| if (leaf.shuffle_address_list) node.path else null,
        .outlier => |wrapper| shuffledLeafPath(wrapper.child, path),
        .weighted => |weighted| for (weightedChildren(weighted)) |child| {
            if (shuffledLeafPath(child.node, path)) |prefix| break prefix;
        } else null,
        .priority => |priority| for (priority.children) |child| {
            if (shuffledLeafPath(child.node, path)) |prefix| break prefix;
        } else null,
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
        .weighted => |weighted| for (weightedChildren(weighted)) |child| {
            if (compositeParent(child.node, path)) break true;
        } else false,
        .priority => |priority| for (priority.children) |child| {
            if (compositeParent(child.node, path)) break true;
        } else false,
    };
}
