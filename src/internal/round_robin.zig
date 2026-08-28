//! Stable-key round-robin traversal for hash-map-backed endpoint state.
//!
//! Hash-map bucket positions are intentionally opaque and may change after a
//! rehash. Keeping the last productive key as the cursor preserves fairness
//! without coupling protocol runtimes to a map's physical representation.

const std = @import("std");

pub fn poll(
    comptime Key: type,
    comptime Map: type,
    comptime Event: type,
    map: *Map,
    cursor: *?Key,
    context: anytype,
    comptime poll_entry: anytype,
) !?Event {
    if (map.count() == 0) {
        cursor.* = null;
        return null;
    }

    const previous = cursor.* orelse {
        var all = map.iterator();
        while (all.next()) |entry| {
            if (try pollEntry(
                Key,
                Event,
                cursor,
                entry,
                context,
                poll_entry,
            )) |event| return event;
        }
        return null;
    };
    // Inspect entries after the previous producer first. A rehash is harmless
    // because the cursor denotes a key, never a bucket offset.
    var found_previous = false;
    var after = map.iterator();
    while (after.next()) |entry| {
        if (!found_previous) {
            found_previous = std.meta.eql(entry.key_ptr.*, previous);
            continue;
        }
        if (try pollEntry(
            Key,
            Event,
            cursor,
            entry,
            context,
            poll_entry,
        )) |event| return event;
    }
    // A missing cursor cannot have an "after" range; restart from the
    // beginning instead of treating the final entry as its successor.
    if (!found_previous) {
        var all = map.iterator();
        while (all.next()) |entry| {
            if (try pollEntry(
                Key,
                Event,
                cursor,
                entry,
                context,
                poll_entry,
            )) |event| return event;
        }
        return null;
    }

    var wrapped = map.iterator();
    while (wrapped.next()) |entry| {
        if (try pollEntry(
            Key,
            Event,
            cursor,
            entry,
            context,
            poll_entry,
        )) |event| return event;
        if (std.meta.eql(entry.key_ptr.*, previous)) break;
    }
    return null;
}

fn pollEntry(
    comptime Key: type,
    comptime Event: type,
    cursor: *?Key,
    entry: anytype,
    context: anytype,
    comptime poll_entry: anytype,
) !?Event {
    const event = (try poll_entry(
        context,
        entry.key_ptr.*,
        entry.value_ptr,
    )) orelse return null;
    cursor.* = entry.key_ptr.*;
    return event;
}
