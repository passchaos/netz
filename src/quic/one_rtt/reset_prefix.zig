//! Small protocol association prefix retained until stream cancellation. The
//! prefix is transmitted as STREAM data before a reset if it was not queued.

const std = @import("std");

pub const capacity: usize = 16;

pub const Prefix = struct {
    storage: [capacity]u8 = [_]u8{0} ** capacity,
    len: u8,
    submitted: bool,

    pub fn init(prefix_bytes: []const u8) error{InvalidFrameLength}!Prefix {
        if (prefix_bytes.len > capacity) return error.InvalidFrameLength;
        var result = Prefix{ .len = @intCast(prefix_bytes.len), .submitted = prefix_bytes.len == 0 };
        @memcpy(result.storage[0..prefix_bytes.len], prefix_bytes);
        return result;
    }

    pub fn bytes(self: *const Prefix) []const u8 {
        return self.storage[0..self.len];
    }

    pub fn matches(self: *const Prefix, offset: u64, data: []const u8) bool {
        if (offset > self.len) return false;
        const start: usize = @intCast(offset);
        if (data.len > self.len - start) return false;
        return std.mem.eql(u8, self.storage[start..][0..data.len], data);
    }

    pub fn noteSubmitted(self: *Prefix, offset: u64, data: []const u8) void {
        if (offset == 0 and data.len >= self.len and std.mem.eql(u8, self.bytes(), data[0..self.len])) self.submitted = true;
    }

    pub fn queuedIn(self: *const Prefix, stream_id: u64, packets: anytype) bool {
        if (self.submitted) return true;
        for (packets) |frames| {
            for (frames) |candidate| {
                if (candidate != .stream) continue;
                const stream = candidate.stream;
                if (stream.stream_id == stream_id and stream.offset == 0 and stream.data.len >= self.len and
                    std.mem.eql(u8, stream.data[0..self.len], self.bytes())) return true;
            }
        }
        return false;
    }
};

/// Bounded ownership view for protocol dispatch after STOP_SENDING has
/// consumed transport storage. It is never exposed by application data reads.
pub const Received = struct {
    storage: [capacity]u8 = [_]u8{0} ** capacity,
    present: u16 = 0,
    contiguous: u8 = 0,

    pub fn remember(self: *Received, offset: u64, data: []const u8) void {
        if (offset >= capacity) return;
        const first: usize = @intCast(offset);
        const count = @min(data.len, capacity - first);
        for (data[0..count], 0..) |byte, index| {
            const position = first + index;
            self.storage[position] = byte;
            self.present |= @as(u16, 1) << @as(u4, @intCast(position));
        }
        while (self.contiguous < capacity and self.present & (@as(u16, 1) << @as(u4, @intCast(self.contiguous))) != 0) self.contiguous += 1;
    }

    pub fn bytes(self: *const Received) []const u8 {
        return self.storage[0..self.contiguous];
    }
};
