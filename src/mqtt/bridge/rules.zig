//! Shared topic-rule helpers for MQTT broker bridges.

const std = @import("std");

const FilterLevel = union(enum) {
    literal: []const u8,
    one,
    many,
};

fn nextFilterLevel(
    iterator: *std.mem.SplitIterator(u8, .scalar),
) ?FilterLevel {
    const level = iterator.next() orelse return null;
    if (std.mem.eql(u8, level, "+")) return .one;
    if (std.mem.eql(u8, level, "#")) return .many;
    return .{ .literal = level };
}

/// Decide intersection by walking both filter automata. Valid MQTT filters
/// have only a terminal `#`, so no backtracking or allocation is required.
/// Empty levels are ordinary literal levels and are handled by slice equality.
pub fn filtersOverlap(left: []const u8, right: []const u8) bool {
    // A Topic Name beginning with '$' is excluded when the first filter level
    // is a wildcard. If one side requires '$' and the other starts wildcard,
    // their otherwise-compatible languages remain disjoint. Shared filters
    // are valid public inputs; matching semantics apply to their inner filter.
    const a = effectiveFilter(left);
    const b = effectiveFilter(right);
    if (startsWithDollarLiteral(a) and startsWithWildcard(b)) return false;
    if (startsWithDollarLiteral(b) and startsWithWildcard(a)) return false;

    var a_levels = std.mem.splitScalar(u8, a, '/');
    var b_levels = std.mem.splitScalar(u8, b, '/');
    var matched_level_count: usize = 0;
    var prefix_is_valid_topic = false;
    while (true) {
        const a_level = nextFilterLevel(&a_levels);
        const b_level = nextFilterLevel(&b_levels);
        if (a_level == null or b_level == null) {
            if (a_level == null and b_level == null) {
                return prefix_is_valid_topic;
            }
            // A terminal `#` also matches zero additional levels, so `a/#`
            // intersects the exact filter `a`. The matched prefix must itself
            // be a valid non-empty Topic Name.
            const remaining_is_many = if (a_level) |level|
                level == .many
            else if (b_level) |level|
                level == .many
            else
                false;
            return remaining_is_many and prefix_is_valid_topic;
        }
        if (a_level.? == .many or b_level.? == .many) return true;
        if (a_level.? == .literal and b_level.? == .literal and
            !std.mem.eql(
                u8,
                a_level.?.literal,
                b_level.?.literal,
            ))
        {
            return false;
        }

        const level_can_be_nonempty = switch (a_level.?) {
            .literal => |literal| literal.len != 0,
            .one => switch (b_level.?) {
                .literal => |literal| literal.len != 0,
                .one => true,
                .many => unreachable,
            },
            .many => unreachable,
        };
        matched_level_count += 1;
        // A slash between any two levels makes the Topic Name non-empty even
        // when both levels themselves are empty.
        prefix_is_valid_topic = prefix_is_valid_topic or
            level_can_be_nonempty or matched_level_count > 1;
    }
}

fn effectiveFilter(filter: []const u8) []const u8 {
    if (!std.mem.startsWith(u8, filter, "$share/")) return filter;
    const rest = filter["$share/".len..];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse unreachable;
    return rest[slash + 1 ..];
}

fn startsWithWildcard(filter: []const u8) bool {
    const slash = std.mem.indexOfScalar(u8, filter, '/') orelse filter.len;
    const first = filter[0..slash];
    return std.mem.eql(u8, first, "+") or std.mem.eql(u8, first, "#");
}

fn startsWithDollarLiteral(filter: []const u8) bool {
    return filter.len != 0 and filter[0] == '$' and !startsWithWildcard(filter);
}
