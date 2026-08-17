//! Deep ownership helpers for MQTT property slices.

const std = @import("std");
const mqtt = @import("mod.zig");

pub const CloneResult = struct {
    properties: []mqtt.Property,
    allocation_bytes: usize,
};

pub fn clone(
    allocator: std.mem.Allocator,
    properties: []const mqtt.Property,
    comptime keep: fn (mqtt.Property) bool,
) (mqtt.Error || error{OwnedPropertyLimitExceeded})!CloneResult {
    var stored_count: usize = 0;
    for (properties) |property| {
        if (keep(property)) stored_count += 1;
    }
    const owned = try allocator.alloc(mqtt.Property, stored_count);
    errdefer allocator.free(owned);
    var initialized: usize = 0;
    var bytes = std.math.mul(
        usize,
        stored_count,
        @sizeOf(mqtt.Property),
    ) catch return error.OwnedPropertyLimitExceeded;
    errdefer freeRange(allocator, owned[0..initialized]);

    var output_index: usize = 0;
    for (properties) |property| {
        if (!keep(property)) continue;
        owned[output_index] = switch (property) {
            .byte, .two_byte, .four_byte, .varint => property,
            .binary => |value| blk: {
                const copied = try allocator.dupe(u8, value.value);
                errdefer allocator.free(copied);
                bytes = std.math.add(
                    usize,
                    bytes,
                    copied.len,
                ) catch return error.OwnedPropertyLimitExceeded;
                break :blk .{ .binary = .{
                    .id = value.id,
                    .value = copied,
                } };
            },
            .utf8 => |value| blk: {
                const copied = try allocator.dupe(u8, value.value);
                errdefer allocator.free(copied);
                bytes = std.math.add(
                    usize,
                    bytes,
                    copied.len,
                ) catch return error.OwnedPropertyLimitExceeded;
                break :blk .{ .utf8 = .{
                    .id = value.id,
                    .value = copied,
                } };
            },
            .utf8_pair => |value| blk: {
                const key = try allocator.dupe(u8, value.key);
                errdefer allocator.free(key);
                const val = try allocator.dupe(u8, value.value);
                errdefer allocator.free(val);
                bytes = std.math.add(
                    usize,
                    bytes,
                    key.len + val.len,
                ) catch return error.OwnedPropertyLimitExceeded;
                break :blk .{ .utf8_pair = .{
                    .id = value.id,
                    .key = key,
                    .value = val,
                } };
            },
        };
        output_index += 1;
        initialized = output_index;
    }
    return .{
        .properties = owned,
        .allocation_bytes = bytes,
    };
}

pub fn deinit(
    allocator: std.mem.Allocator,
    properties: []mqtt.Property,
) void {
    freeRange(allocator, properties);
    allocator.free(properties);
}

fn freeRange(
    allocator: std.mem.Allocator,
    properties: []mqtt.Property,
) void {
    for (properties) |property| switch (property) {
        .binary => |value| allocator.free(value.value),
        .utf8 => |value| allocator.free(value.value),
        .utf8_pair => |value| {
            allocator.free(value.key);
            allocator.free(value.value);
        },
        else => {},
    };
}

pub fn keepAll(_: mqtt.Property) bool {
    return true;
}
