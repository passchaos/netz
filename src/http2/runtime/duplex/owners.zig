//! Shared single-reader ownership count for movable duplex handles.
const std = @import("std");

pub const Owners = struct {
    value: usize = 0,

    pub fn acquire(self: *Owners) void {
        self.value += 1;
    }

    pub fn release(self: *Owners) void {
        std.debug.assert(self.value != 0);
        self.value -= 1;
    }

    pub fn count(self: *const Owners) usize {
        return self.value;
    }
};
