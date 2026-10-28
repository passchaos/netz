//! A complete source metadata view survives in-place packet adoption.
const std = @import("std");
const mqtt = @import("../mod.zig");
const publication = @import("publication.zig");

pub const Properties = struct {
    storage: [8]mqtt.Property = undefined,
    overflow: ?[]mqtt.Property = null,
    len: usize = 0,

    pub fn deinit(self: *Properties, allocator: std.mem.Allocator) void {
        if (self.overflow) |values| allocator.free(values);
        self.* = undefined;
    }

    /// Reserve descriptors before the factory can compact the owned packet.
    /// Source values still belong to that packet until bind replaces them.
    pub fn capture(self: *Properties, allocator: std.mem.Allocator, original: []const mqtt.Property) std.mem.Allocator.Error!void {
        std.debug.assert(self.len == 0 and self.overflow == null);
        const values = if (original.len <= self.storage.len)
            self.storage[0..original.len]
        else blk: {
            const allocated = try allocator.alloc(mqtt.Property, original.len);
            self.overflow = allocated;
            break :blk allocated;
        };
        @memcpy(values, original);
        self.len = original.len;
    }

    pub fn items(self: *Properties) []mqtt.Property {
        return if (self.overflow) |values| values else self.storage[0..self.len];
    }

    /// Forwarded values are owned by Publication. Keep connection-scoped
    /// scalar fields in the source view for consistent per-destination ACLs;
    /// ordinary forwarding still filters those fields before queueing.
    pub fn bind(self: *Properties, owned: *const publication.Publication) void {
        var index: usize = 0;
        for (self.items()) |*property| {
            if (!publication.keepForwardProperty(property.*)) continue;
            std.debug.assert(index < owned.properties.len);
            property.* = owned.properties[index];
            index += 1;
        }
        std.debug.assert(index == owned.properties.len);
    }
};
