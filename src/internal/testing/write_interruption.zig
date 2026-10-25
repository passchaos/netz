//! Deterministic executor faults around a real socket write completion.
const std = @import("std");

pub const Stage = enum { before_write, after_prefix, after_prefix_timer_rejected };

pub const Probe = struct {
    pub var active: *Probe = undefined;
    delegate: std.Io,
    stage: Stage,
    prefix_len: usize,
    armed: bool = true,
    submissions: usize = 0,
    written: usize = 0,

    pub fn groupConcurrent(userdata: ?*anyopaque, group: *std.Io.Group, context: []const u8, alignment: std.mem.Alignment, start: *const fn (*const anyopaque) void) std.Io.ConcurrentError!void {
        const self = active;
        if (!self.armed) return self.delegate.vtable.groupConcurrent(userdata, group, context, alignment, start);
        self.submissions += 1;
        if (self.stage == .before_write or self.submissions == 3 or
            (self.stage == .after_prefix_timer_rejected and self.submissions == 2)) return error.ConcurrencyUnavailable;
        if (self.submissions == 1) {
            // Complete the first write before timer admission. Its bytes are
            // real socket bytes and the Select completion queue is populated.
            start(@ptrCast(context.ptr));
            return;
        }
        return self.delegate.vtable.groupConcurrent(userdata, group, context, alignment, start);
    }

    pub fn netWrite(userdata: ?*anyopaque, handle: std.Io.net.Socket.Handle, header: []const u8, parts: []const []const u8, splat: usize) std.Io.net.Stream.Writer.Error!usize {
        const self = active;
        const bytes = if (self.armed) header[0..@min(header.len, self.prefix_len)] else header;
        const count = try self.delegate.vtable.netWrite(userdata, handle, bytes, parts, splat);
        self.written += count;
        return count;
    }
};
