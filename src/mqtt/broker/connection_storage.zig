//! Stable connection storage reserved before Session admission, then moved to
//! the client slot only after CONNECT negotiation completes.

const std = @import("std");
const runtime = @import("../runtime.zig");

pub const Storage = struct {
    allocator: std.mem.Allocator,
    value: ?*runtime.Connection,
    initialized: bool = false,

    pub fn init(allocator: std.mem.Allocator) std.mem.Allocator.Error!Storage {
        return .{ .allocator = allocator, .value = try allocator.create(runtime.Connection) };
    }

    /// Move the accepted transport and negotiated runtime state out of their
    /// temporary owner. Cleanup now closes that connection unless it is taken.
    pub fn adopt(self: *Storage, connection: *runtime.Connection) void {
        std.debug.assert(self.value != null and !self.initialized);
        self.value.?.* = connection.*;
        connection.* = undefined;
        self.initialized = true;
    }

    pub fn get(self: *Storage) *runtime.Connection {
        std.debug.assert(self.initialized);
        return self.value.?;
    }

    /// Transfer ownership to the attached client slot. Later storage cleanup
    /// is harmless; that slot becomes the sole connection destruction owner.
    pub fn take(self: *Storage) *runtime.Connection {
        const value = self.get();
        self.value = null;
        self.initialized = false;
        return value;
    }

    pub fn deinit(self: *Storage) void {
        if (self.value) |value| {
            if (self.initialized) value.close();
            self.allocator.destroy(value);
        }
        self.* = undefined;
    }
};
