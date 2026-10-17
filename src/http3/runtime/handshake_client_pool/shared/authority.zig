//! Immutable certificate-checked ORIGIN authorization published by one
//! connection driver to concurrent request producers.

const std = @import("std");
const http3 = @import("../../../mod.zig");
const quic = @import("../../../../quic/mod.zig");
const route = @import("route.zig");

pub const Snapshot = struct {
    allocator: ?std.mem.Allocator = null,
    entries: []Entry = &.{},
    entry_count: usize = 0,
    storage: []u8 = &.{},

    const Entry = struct {
        host_offset: usize,
        host_len: usize,
        port: u16,
    };

    pub fn build(
        allocator: std.mem.Allocator,
        client: anytype,
        connection_origin: http3.Origin,
    ) std.mem.Allocator.Error!Snapshot {
        const certificates = client.peerCertificates() orelse return .{};
        if (certificates.len == 0) return .{};
        const candidates = client.peerOrigins();
        if (candidates.len == 0) return .{};

        var storage_len: usize = 0;
        for (candidates) |candidate| {
            const origin = candidate.origin();
            if (!std.ascii.eqlIgnoreCase(origin.scheme, "https") or
                http3.sameOrigin(connection_origin, origin))
            {
                continue;
            }
            storage_len = std.math.add(
                usize,
                storage_len,
                origin.host.len,
            ) catch return error.OutOfMemory;
        }
        if (storage_len == 0) return .{};

        const entries = try allocator.alloc(Entry, candidates.len);
        errdefer allocator.free(entries);
        const storage = try allocator.alloc(u8, storage_len);
        errdefer allocator.free(storage);
        var count: usize = 0;
        var offset: usize = 0;
        for (candidates) |candidate| {
            const origin = candidate.origin();
            if (!std.ascii.eqlIgnoreCase(origin.scheme, "https") or
                http3.sameOrigin(connection_origin, origin) or
                client.peerOriginSetAllows(connection_origin, origin) != true)
            {
                continue;
            }
            quic.tls.trust.verifyServerCertificateIdentity(
                certificates[0],
                origin.host,
            ) catch continue;
            @memcpy(
                storage[offset .. offset + origin.host.len],
                origin.host,
            );
            entries[count] = .{
                .host_offset = offset,
                .host_len = origin.host.len,
                .port = origin.port,
            };
            count += 1;
            offset += origin.host.len;
        }
        if (count == 0) {
            allocator.free(storage);
            allocator.free(entries);
            return .{};
        }
        return .{
            .allocator = allocator,
            .entries = entries,
            .entry_count = count,
            .storage = storage,
        };
    }

    pub fn deinit(self: *Snapshot) void {
        const allocator = self.allocator orelse {
            self.* = .{};
            return;
        };
        allocator.free(self.entries);
        allocator.free(self.storage);
        self.* = .{};
    }

    pub fn allows(self: *const Snapshot, key: *const route.Key) bool {
        const origin = key.origin();
        for (self.entries[0..self.entry_count]) |entry| {
            if (entry.port == origin.port and std.ascii.eqlIgnoreCase(
                self.storage[entry.host_offset..][0..entry.host_len],
                origin.host,
            )) return true;
        }
        return false;
    }
};
