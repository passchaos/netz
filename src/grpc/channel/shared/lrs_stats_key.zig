//! Borrowed lookup equivalent to the owned source/cluster/EDS tuple key.
const std = @import("std");

pub const Borrowed = struct { source_key: []const u8 = "", cluster: []const u8, service_name: []const u8 };

/// [source length u64 LE][cluster length u64 LE][source][cluster][EDS service].
pub fn encode(gpa: std.mem.Allocator, key: Borrowed) (std.mem.Allocator.Error || error{Overflow})![]u8 {
    const source_end = try std.math.add(usize, 16, key.source_key.len);
    const cluster_end = try std.math.add(usize, source_end, key.cluster.len);
    const owned = try gpa.alloc(u8, try std.math.add(usize, cluster_end, key.service_name.len));
    std.mem.writeInt(u64, owned[0..8], @intCast(key.source_key.len), .little);
    std.mem.writeInt(u64, owned[8..16], @intCast(key.cluster.len), .little);
    @memcpy(owned[16..][0..key.source_key.len], key.source_key);
    @memcpy(owned[source_end..cluster_end], key.cluster);
    @memcpy(owned[cluster_end..], key.service_name);
    return owned;
}

pub const Adapted = struct {
    pub fn hash(_: Adapted, key: Borrowed) u64 {
        var prefix: [16]u8 = undefined;
        std.mem.writeInt(u64, prefix[0..8], @intCast(key.source_key.len), .little);
        std.mem.writeInt(u64, prefix[8..16], @intCast(key.cluster.len), .little);
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(&prefix);
        hasher.update(key.source_key);
        hasher.update(key.cluster);
        hasher.update(key.service_name);
        return hasher.final();
    }

    pub fn eql(_: Adapted, key: Borrowed, stored: []const u8) bool {
        if (stored.len < 16 or std.mem.readInt(u64, stored[0..8], .little) != key.source_key.len or
            std.mem.readInt(u64, stored[8..16], .little) != key.cluster.len) return false;
        const suffix = stored[16..];
        if (suffix.len < key.source_key.len) return false;
        const cluster_and_service = suffix[key.source_key.len..];
        if (cluster_and_service.len < key.cluster.len) return false;
        return std.mem.eql(u8, suffix[0..key.source_key.len], key.source_key) and
            std.mem.eql(u8, cluster_and_service[0..key.cluster.len], key.cluster) and
            std.mem.eql(u8, cluster_and_service[key.cluster.len..], key.service_name);
    }
};
