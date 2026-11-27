//! Cooperative service limits for the sole shared QUIC owner.
//!
//! Finish the current event before yielding. A datagram is never truncated,
//! and an already-started connection service retains all of its cleanup work.
const std = @import("std");

pub const input_events = 16;
pub const input_bytes = 64 * 1024;
pub const connection_visits = 16;
pub const quantum_ns = 2 * std.time.ns_per_ms;

pub const Turn = struct {
    events_left: usize,
    bytes_left: usize,
    deadline: std.Io.Timestamp,
    started: bool = false,

    pub fn init(io: std.Io, events: usize, bytes: usize) Turn {
        return .{
            .events_left = events,
            .bytes_left = bytes,
            // The event-loop snapshot does not advance during a busy task.
            // Ordinary std.Io time reads the actual clock on both backends.
            .deadline = .fromNanoseconds(std.Io.Timestamp.now(io, .awake).nanoseconds +| quantum_ns),
        };
    }

    /// Admit at least one complete event per nonempty turn, then check all
    /// limits before removing any further input from its owner.
    pub fn take(self: *Turn, io: std.Io) bool {
        if (self.events_left == 0 or self.bytes_left == 0) return false;
        if (self.started and std.Io.Timestamp.now(io, .awake).nanoseconds >= self.deadline.nanoseconds) return false;
        self.started = true;
        self.events_left -= 1;
        return true;
    }

    pub fn consume(self: *Turn, bytes: usize) void {
        self.bytes_left -|= bytes;
    }
};

pub const Rotation = struct {
    next_index: usize = 0,

    pub fn next(self: *Rotation, count: usize) usize {
        std.debug.assert(count != 0);
        const index = self.next_index % count;
        self.next_index = (index + 1) % count;
        return index;
    }

    /// Preserve the identity of the next connection when swapRemove moves
    /// the former last slot. No pointer into the movable list is retained.
    pub fn removed(self: *Rotation, index: usize, old_count: usize) void {
        if (old_count == 1) {
            self.next_index = 0;
        } else if (self.next_index == old_count - 1) {
            self.next_index = index;
        } else if (self.next_index >= old_count - 1) {
            self.next_index = 0;
        }
    }
};
