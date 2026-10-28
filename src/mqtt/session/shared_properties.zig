//! Session descriptors may borrow values already retained by a Publication.
const std = @import("std");
const mqtt = @import("../mod.zig");
const owned = @import("../owned_properties.zig");

pub const Result = struct {
    properties: []mqtt.Property,
    logical_bytes: usize,
    borrows_values: bool,
};

pub fn clone(allocator: std.mem.Allocator, source: []const mqtt.Property, publication_properties: []const mqtt.Property, comptime keep: fn (mqtt.Property) bool) (mqtt.Error || error{OwnedPropertyLimitExceeded})!Result {
    var count: usize = 0;
    var value_bytes: usize = 0;
    var borrowable = true;
    var owner_index: usize = 0;
    for (source) |property| {
        if (!keep(property)) continue;
        count += 1;
        switch (property) {
            .binary => |value| {
                value_bytes = try add(value_bytes, value.value.len);
                borrowable = borrowable and retained(publication_properties, value.value, &owner_index);
            },
            .utf8 => |value| {
                value_bytes = try add(value_bytes, value.value.len);
                borrowable = borrowable and retained(publication_properties, value.value, &owner_index);
            },
            .utf8_pair => |value| {
                value_bytes = try add(try add(value_bytes, value.key.len), value.value.len);
                borrowable = borrowable and retained(publication_properties, value.key, &owner_index) and retained(publication_properties, value.value, &owner_index);
            },
            else => {},
        }
    }
    if (!borrowable) {
        const result = try owned.clone(allocator, source, keep);
        return .{ .properties = result.properties, .logical_bytes = result.allocation_bytes, .borrows_values = false };
    }
    const descriptor_bytes = std.math.mul(usize, count, @sizeOf(mqtt.Property)) catch return error.OwnedPropertyLimitExceeded;
    const logical_bytes = try add(descriptor_bytes, value_bytes);
    const properties = try allocator.alloc(mqtt.Property, count);
    var index: usize = 0;
    for (source) |property| {
        if (!keep(property)) continue;
        properties[index] = property;
        index += 1;
    }
    return .{ .properties = properties, .logical_bytes = logical_bytes, .borrows_values = true };
}

fn add(first: usize, second: usize) error{OwnedPropertyLimitExceeded}!usize {
    return std.math.add(usize, first, second) catch error.OwnedPropertyLimitExceeded;
}

/// Pointer containment proves lifetime ownership; equal bytes from a callback
/// or caller buffer still require independent deep ownership. No bytes are
/// compared and zero-length values need no backing storage.
fn retained(properties: []const mqtt.Property, bytes: []const u8, owner_index: *usize) bool {
    if (bytes.len == 0) return true;
    // Broker forwarding retains source order and appends Session identifiers.
    // Advancing this cursor makes a large User Property set linear. Reordered
    // caller metadata safely takes the ordinary deep-clone path instead.
    for (properties[owner_index.*..], owner_index.*..) |property, index| {
        const found = switch (property) {
            .binary => |value| within(value.value, bytes),
            .utf8 => |value| within(value.value, bytes),
            .utf8_pair => |value| within(value.key, bytes) or within(value.value, bytes),
            else => false,
        };
        if (found) {
            owner_index.* = index;
            return true;
        }
    }
    return false;
}

fn within(parent: []const u8, child: []const u8) bool {
    const outer = @intFromPtr(parent.ptr);
    const inner = @intFromPtr(child.ptr);
    if (inner < outer) return false;
    const offset = inner - outer;
    return offset <= parent.len and child.len <= parent.len - offset;
}
