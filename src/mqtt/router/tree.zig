//! Stable trie indexes with allocation-free pruning and recycled node slots.
const std = @import("std");

pub const Node = struct {
    literal_children: std.StringHashMapUnmanaged(usize) = .empty,
    single_wildcard_child: ?usize = null,
    terminal_entries: std.ArrayList(usize) = .empty,
    multi_wildcard_entries: std.ArrayList(usize) = .empty,
    parent: ?usize = null,
    /// Borrowed from the owning parent map; null identifies its '+' edge.
    parent_edge: ?[]const u8 = null,
    recycled_next: ?usize = null,

    pub fn deinit(self: *Node, allocator: std.mem.Allocator) void {
        var keys = self.literal_children.keyIterator();
        while (keys.next()) |level| allocator.free(level.*);
        self.literal_children.deinit(allocator);
        self.terminal_entries.deinit(allocator);
        self.multi_wildcard_entries.deinit(allocator);
        self.* = .{};
    }

    fn empty(self: *const Node) bool {
        return self.literal_children.count() == 0 and self.single_wildcard_child == null and
            self.terminal_entries.items.len == 0 and self.multi_wildcard_entries.items.len == 0;
    }
};

pub fn literalChild(node: Node, level: []const u8) ?usize {
    return node.literal_children.get(level);
}

fn allocateNode(router: anytype, parent: usize, edge: ?[]const u8) std.mem.Allocator.Error!usize {
    const node = Node{ .parent = parent, .parent_edge = edge };
    if (router.recycled_node) |index| {
        router.recycled_node = router.nodes.items[index].recycled_next;
        router.nodes.items[index] = node;
        return index;
    }
    try router.nodes.append(router.allocator, node);
    return router.nodes.items.len - 1;
}

fn recycleNode(router: anytype, index: usize) void {
    std.debug.assert(index != 0);
    router.nodes.items[index].deinit(router.allocator);
    router.nodes.items[index].recycled_next = router.recycled_node;
    router.recycled_node = index;
}

/// The node's route references are gone. Remove empty ancestors iteratively,
/// keeping every live index stable and requiring no rollback allocation.
pub fn pruneEmpty(router: anytype, start: usize) void {
    var index = start;
    while (index != 0 and router.nodes.items[index].empty()) {
        const parent = router.nodes.items[index].parent.?;
        if (router.nodes.items[index].parent_edge) |edge| {
            const removed = router.nodes.items[parent].literal_children.remove(edge);
            std.debug.assert(removed);
            router.allocator.free(edge);
        } else {
            std.debug.assert(router.nodes.items[parent].single_wildcard_child == index);
            router.nodes.items[parent].single_wildcard_child = null;
        }
        recycleNode(router, index);
        index = parent;
    }
}

/// Roll back any unused prefix when a later key, node or map allocation fails.
/// The caller prunes the completed path if route admission subsequently fails.
pub fn insert(router: anytype, filter: []const u8) std.mem.Allocator.Error!struct { usize, bool } {
    var index: usize = 0;
    errdefer pruneEmpty(router, index);
    var levels = std.mem.splitScalar(u8, filter, '/');
    while (levels.next()) |level| {
        if (std.mem.eql(u8, level, "#")) return .{ index, true };
        if (std.mem.eql(u8, level, "+")) {
            if (router.nodes.items[index].single_wildcard_child) |child| {
                index = child;
            } else {
                const child = try allocateNode(router, index, null);
                router.nodes.items[index].single_wildcard_child = child;
                index = child;
            }
            continue;
        }
        if (literalChild(router.nodes.items[index], level)) |child| {
            index = child;
        } else {
            const edge = try router.allocator.dupe(u8, level);
            errdefer router.allocator.free(edge);
            const child = try allocateNode(router, index, edge);
            errdefer recycleNode(router, child);
            try router.nodes.items[index].literal_children.put(router.allocator, edge, child);
            index = child;
        }
    }
    return .{ index, false };
}

pub fn find(router: anytype, filter: []const u8) ?struct { usize, bool } {
    var index: usize = 0;
    var levels = std.mem.splitScalar(u8, filter, '/');
    while (levels.next()) |level| {
        if (std.mem.eql(u8, level, "#")) return .{ index, true };
        if (std.mem.eql(u8, level, "+")) {
            index = router.nodes.items[index].single_wildcard_child orelse return null;
        } else {
            index = literalChild(router.nodes.items[index], level) orelse return null;
        }
    }
    return .{ index, false };
}
