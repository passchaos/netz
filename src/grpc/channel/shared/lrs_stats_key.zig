//! Borrowed lookup equivalent to the owned length-prefixed cluster/EDS key.
const std = @import("std");

pub const Borrowed = struct { cluster: []const u8, service_name: []const u8 };

pub const Adapted = struct {
    pub fn hash(_: Adapted, key: Borrowed) u64 {
        var prefix: [8]u8 = undefined;
        std.mem.writeInt(u64, &prefix, @intCast(key.cluster.len), .little);
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(&prefix);
        hasher.update(key.cluster);
        hasher.update(key.service_name);
        return hasher.final();
    }

    pub fn eql(_: Adapted, key: Borrowed, stored: []const u8) bool {
        if (stored.len < 8 or std.mem.readInt(u64, stored[0..8], .little) != key.cluster.len) return false;
        const suffix = stored[8..];
        if (suffix.len < key.cluster.len) return false;
        return std.mem.eql(u8, suffix[0..key.cluster.len], key.cluster) and
            std.mem.eql(u8, suffix[key.cluster.len..], key.service_name);
    }
};
