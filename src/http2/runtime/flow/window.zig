const std = @import("std");

pub const default_value: i64 = 65_535;
pub const max_value: i64 = std.math.maxInt(i31);
pub const min_value: i64 = std.math.minInt(i32);

pub const Error = error{
    MessageTooLarge,
    FlowControlBlocked,
    FlowControlViolation,
};

/// One HTTP/2 connection or stream flow-control window.
///
/// The signed representation is required because reducing
/// SETTINGS_INITIAL_WINDOW_SIZE can make an existing stream window negative.
/// Positive availability is exposed separately so callers never cast a
/// negative value to an unsigned byte count.
pub const Window = struct {
    value: i64 = default_value,

    pub fn available(self: Window) usize {
        if (self.value <= 0) return 0;
        return std.math.cast(usize, self.value) orelse
            std.math.maxInt(usize);
    }

    pub fn reserve(self: *Window, amount: usize) Error!void {
        if (amount == 0) return;
        const delta = std.math.cast(i64, amount) orelse
            return error.MessageTooLarge;
        if (delta > self.value) return error.FlowControlBlocked;
        self.value -= delta;
    }

    pub fn receive(self: *Window, amount: usize) Error!void {
        if (amount == 0) return;
        const delta = std.math.cast(i64, amount) orelse
            return error.MessageTooLarge;
        if (delta > self.value) return error.FlowControlViolation;
        self.value -= delta;
    }

    pub fn update(self: *Window, increment: u31) Error!void {
        return self.adjust(increment);
    }

    pub fn adjust(self: *Window, delta: i64) Error!void {
        const next = std.math.add(i64, self.value, delta) catch
            return error.FlowControlViolation;
        if (next < min_value or next > max_value) {
            return error.FlowControlViolation;
        }
        self.value = next;
    }
};
