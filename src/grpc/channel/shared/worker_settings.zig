//! Immutable background protocol settings retained until an owner adopts an update.
const std = @import("std");
const orca = @import("orca/config.zig");

pub const Settings = struct {
    allocator: std.mem.Allocator,
    health_service: ?[]u8,
    orca_oob: ?orca.Config,

    pub fn create(allocator: std.mem.Allocator, health_service: ?[]const u8, orca_oob: ?*const orca.Config) !*Settings {
        const settings = try allocator.create(Settings);
        errdefer allocator.destroy(settings);
        const name = if (health_service) |value| try allocator.dupe(u8, value) else null;
        errdefer if (name) |value| allocator.free(value);
        settings.* = .{
            .allocator = allocator,
            .health_service = name,
            .orca_oob = if (orca_oob) |value| try value.clone() else null,
        };
        return settings;
    }
    pub fn destroy(self: *Settings) void {
        const allocator = self.allocator;
        if (self.health_service) |value| allocator.free(value);
        if (self.orca_oob) |*value| value.deinit();
        allocator.destroy(self);
    }
    pub fn equivalent(self: *const Settings, other: *const Settings) bool {
        if ((self.health_service == null) != (other.health_service == null)) return false;
        if (self.health_service) |name| if (!std.mem.eql(u8, name, other.health_service.?)) return false;
        if ((self.orca_oob == null) != (other.orca_oob == null)) return false;
        if (self.orca_oob) |config| {
            const b = other.orca_oob.?;
            if (!std.mem.eql(u8, config.request, b.request) or
                !optionalEqual(config.options.authority, b.options.authority) or
                !optionalEqual(config.options.scheme, b.options.scheme) or
                config.inputs.metadata.len != b.inputs.metadata.len or
                config.inputs.binary_metadata.len != b.inputs.binary_metadata.len or
                !std.meta.eql(config.options.accepted_encodings, b.options.accepted_encodings) or
                config.options.max_message_size != b.options.max_message_size) return false;
            for (config.inputs.metadata, b.inputs.metadata) |a, field| {
                if (a.never_index != field.never_index or !std.mem.eql(u8, a.name, field.name) or !std.mem.eql(u8, a.value, field.value)) return false;
            }
            for (config.inputs.binary_metadata, b.inputs.binary_metadata) |a, field| {
                if (!std.mem.eql(u8, a.name, field.name) or !std.mem.eql(u8, a.value, field.value)) return false;
            }
        }
        return true;
    }
    fn optionalEqual(a: ?[]const u8, b: ?[]const u8) bool {
        if ((a == null) != (b == null)) return false;
        return if (a) |value| std.mem.eql(u8, value, b.?) else true;
    }
};
