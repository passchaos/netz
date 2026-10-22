//! Encoded CLOSE storage shared by owning and endpoint adapters.

const std = @import("std");
const session_control = @import("../session_control.zig");
const Error = session_control.Error;

pub const Pending = struct {
    const inline_capacity: usize = 128;
    const Storage = union(enum) {
        local: [inline_capacity]u8,
        heap: struct {
            allocator: std.mem.Allocator,
            bytes: []u8,
        },
    };

    storage: Storage = .{ .local = undefined },
    len: usize = 0,
    committed: usize = 0,
    code: u32 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        code: u32,
        reason: []const u8,
    ) Error!Pending {
        var pending: Pending = .{ .code = code };
        var encoded_storage: [4 + session_control.max_close_reason + 16]u8 =
            undefined;
        const encoded = try session_control.writeCloseInto(
            &encoded_storage,
            code,
            reason,
        );
        pending.len = encoded.len;
        if (encoded.len <= inline_capacity) {
            @memcpy(pending.storage.local[0..encoded.len], encoded);
        } else {
            pending.storage = .{ .heap = .{
                .allocator = allocator,
                .bytes = try allocator.dupe(u8, encoded),
            } };
        }
        return pending;
    }

    pub fn bytes(self: *const Pending) []const u8 {
        return switch (self.storage) {
            .local => |*storage| storage[0..self.len],
            .heap => |owned| owned.bytes,
        };
    }

    pub fn remaining(self: *const Pending) []const u8 {
        return self.bytes()[self.committed..];
    }

    pub fn deinit(self: *Pending) void {
        switch (self.storage) {
            .local => |*storage| std.crypto.secureZero(
                u8,
                storage[0..self.len],
            ),
            .heap => |owned| {
                std.crypto.secureZero(u8, owned.bytes);
                owned.allocator.free(owned.bytes);
            },
        }
        self.* = undefined;
    }

    pub fn matches(
        self: *const Pending,
        code: u32,
        reason: []const u8,
    ) Error!bool {
        var candidate_storage: [4 + session_control.max_close_reason + 16]u8 =
            undefined;
        const candidate = try session_control.writeCloseInto(
            &candidate_storage,
            code,
            reason,
        );
        return std.mem.eql(u8, self.bytes(), candidate);
    }
};
