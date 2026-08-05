const std = @import("std");
const quic = @import("mod.zig");

pub const max_pool_size: usize = 8;
pub const max_connection_id_len: usize = 20;

pub const Error = error{
    InvalidConnectionId,
    PoolFull,
    UnknownConnectionId,
} || std.mem.Allocator.Error;

pub const Entry = struct {
    sequence_number: u64 = 0,
    connection_id: [max_connection_id_len]u8 = .{0} ** max_connection_id_len,
    connection_id_len: u8 = 0,
    stateless_reset_token: [16]u8 = .{0} ** 16,
    in_use: bool = false,
    occupied: bool = false,

    pub fn slice(self: *const Entry) []const u8 {
        return self.connection_id[0..self.connection_id_len];
    }
};

pub const PeerPool = struct {
    entries: [max_pool_size]Entry = .{Entry{}} ** max_pool_size,

    pub fn add(self: *PeerPool, sequence_number: u64, connection_id: []const u8, token: [16]u8) Error!void {
        if (connection_id.len == 0 or connection_id.len > max_connection_id_len) return error.InvalidConnectionId;
        if (self.find(sequence_number)) |entry| {
            entry.connection_id_len = @intCast(connection_id.len);
            @memcpy(entry.connection_id[0..connection_id.len], connection_id);
            entry.stateless_reset_token = token;
            entry.occupied = true;
            return;
        }
        for (&self.entries) |*entry| {
            if (!entry.occupied) {
                entry.* = .{ .sequence_number = sequence_number, .connection_id_len = @intCast(connection_id.len), .stateless_reset_token = token, .occupied = true };
                @memcpy(entry.connection_id[0..connection_id.len], connection_id);
                return;
            }
        }
        return error.PoolFull;
    }

    pub fn retirePriorTo(self: *PeerPool, sequence_number: u64) void {
        for (&self.entries) |*entry| {
            if (entry.occupied and entry.sequence_number < sequence_number) entry.* = .{};
        }
    }

    pub fn consumeUnused(self: *PeerPool) ?*Entry {
        for (&self.entries) |*entry| {
            if (entry.occupied and !entry.in_use) {
                entry.in_use = true;
                return entry;
            }
        }
        return null;
    }

    pub fn markInUse(self: *PeerPool, sequence_number: u64) Error!void {
        const entry = self.find(sequence_number) orelse return error.UnknownConnectionId;
        entry.in_use = true;
    }

    pub fn detectStatelessReset(self: *const PeerPool, datagram: []const u8) ?u64 {
        for (&self.entries) |*entry| {
            if (!entry.occupied) continue;
            if (quic.stateless_reset.matches(datagram, entry.stateless_reset_token)) return entry.sequence_number;
        }
        return null;
    }

    pub fn count(self: *const PeerPool) usize {
        var n: usize = 0;
        for (&self.entries) |*entry| {
            if (entry.occupied) n += 1;
        }
        return n;
    }

    fn find(self: *PeerPool, sequence_number: u64) ?*Entry {
        for (&self.entries) |*entry| {
            if (entry.occupied and entry.sequence_number == sequence_number) return entry;
        }
        return null;
    }
};

pub const LocalPool = struct {
    entries: [max_pool_size]Entry = .{Entry{}} ** max_pool_size,
    next_sequence_number: u64 = 0,
    retire_prior_to: u64 = 0,

    pub fn registerInitial(self: *LocalPool, connection_id: []const u8, token: [16]u8) Error!void {
        if (connection_id.len == 0 or connection_id.len > max_connection_id_len) return error.InvalidConnectionId;
        self.entries[0] = .{ .sequence_number = 0, .connection_id_len = @intCast(connection_id.len), .stateless_reset_token = token, .occupied = true };
        @memcpy(self.entries[0].connection_id[0..connection_id.len], connection_id);
        self.next_sequence_number = 1;
    }

    pub fn issue(self: *LocalPool, connection_id: []const u8, token: [16]u8) Error!quic.Frame {
        if (connection_id.len == 0 or connection_id.len > max_connection_id_len) return error.InvalidConnectionId;
        for (&self.entries) |*entry| {
            if (!entry.occupied) {
                const seq = self.next_sequence_number;
                self.next_sequence_number += 1;
                entry.* = .{ .sequence_number = seq, .connection_id_len = @intCast(connection_id.len), .stateless_reset_token = token, .occupied = true };
                @memcpy(entry.connection_id[0..connection_id.len], connection_id);
                return .{ .new_connection_id = .{
                    .sequence_number = seq,
                    .retire_prior_to = self.retire_prior_to,
                    .connection_id = entry.slice(),
                    .stateless_reset_token = token,
                } };
            }
        }
        return error.PoolFull;
    }

    pub fn retire(self: *LocalPool, sequence_number: u64) Error!void {
        for (&self.entries) |*entry| {
            if (entry.occupied and entry.sequence_number == sequence_number) {
                entry.* = .{};
                return;
            }
        }
        return error.UnknownConnectionId;
    }

    pub fn count(self: *const LocalPool) usize {
        var n: usize = 0;
        for (&self.entries) |*entry| {
            if (entry.occupied) n += 1;
        }
        return n;
    }
};

test "QUIC peer CID pool stores retires and consumes IDs" {
    var pool = PeerPool{};
    try pool.add(1, "cid-one", [_]u8{1} ** 16);
    try pool.add(2, "cid-two", [_]u8{2} ** 16);
    try std.testing.expectEqual(@as(usize, 2), pool.count());
    pool.retirePriorTo(2);
    try std.testing.expectEqual(@as(usize, 1), pool.count());
    const entry = pool.consumeUnused().?;
    try std.testing.expectEqual(@as(u64, 2), entry.sequence_number);
    try std.testing.expectEqualStrings("cid-two", entry.slice());
    try std.testing.expect(pool.consumeUnused() == null);
}

test "QUIC peer CID pool detects stateless reset token" {
    const allocator = std.testing.allocator;
    var pool = PeerPool{};
    const token = [_]u8{0x44} ** 16;
    try pool.add(7, "reset-cid", token);

    var datagram: std.ArrayList(u8) = .empty;
    defer datagram.deinit(allocator);
    try quic.stateless_reset.encode(&datagram, allocator, &.{ 0x40, 9, 8, 7, 6 }, token);
    try std.testing.expectEqual(@as(?u64, 7), pool.detectStatelessReset(datagram.items));
    try std.testing.expectEqual(@as(?u64, null), pool.detectStatelessReset(&.{ 0x40, 1, 2 }));
}

test "QUIC local CID pool issues and retires NEW_CONNECTION_ID frames" {
    var pool = LocalPool{};
    try pool.registerInitial("init-cid", [_]u8{0} ** 16);
    const frame = try pool.issue("new-cid", [_]u8{3} ** 16);
    try std.testing.expectEqual(@as(u64, 1), frame.new_connection_id.sequence_number);
    try std.testing.expectEqualStrings("new-cid", frame.new_connection_id.connection_id);
    try std.testing.expectEqual(@as(usize, 2), pool.count());
    try pool.retire(0);
    try std.testing.expectEqual(@as(usize, 1), pool.count());
}
