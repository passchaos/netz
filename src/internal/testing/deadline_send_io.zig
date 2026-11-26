//! Native concurrency with a deterministic send-advanced awake clock.
//! Keep backend userdata intact for every callback we do not override.
const std = @import("std");
const net = std.Io.net;
const forwarded_io = @import("forwarded_io.zig");

pub const Native = struct {
    backend: std.Io.Threaded,
    table: std.Io.VTable = undefined,
    /// Borrowed actual execution and socket backend; must outlive all users.
    delegate_io: ?std.Io = null,
    fixed_clock: bool = true,
    now_ns: std.atomic.Value(i64) = .init(0),
    advance_after_send_ns: i64 = 0,
    send_calls: std.atomic.Value(usize) = .init(0),
    duration_sleep_calls: std.atomic.Value(usize) = .init(0),
    clock_changed: std.Io.Event = .unset,
    send_context: ?*anyopaque = null,
    send_override: ?*const fn (?*anyopaque, net.Socket.Handle, []net.OutgoingMessage, net.SendFlags) struct { ?net.Socket.SendError, usize } = null,

    pub fn io(self: *Native) std.Io {
        const base = self.backend.io();
        self.table = if (self.delegate_io != null)
            forwarded_io.table(from, baseIo, mapTimeout)
        else
            base.vtable.*;
        if (self.fixed_clock) {
            self.table.now = now;
            self.table.sleep = sleep;
        }
        self.table.netSend = send;
        return .{ .userdata = base.userdata, .vtable = &self.table };
    }

    pub fn baseIo(self: *Native) std.Io {
        return self.delegate_io orelse self.backend.io();
    }

    /// Advance a controlled awake clock and wake an already entered deadline
    /// wait. Use this instead of changing clock state without notifying it.
    pub fn setNow(self: *Native, now_ns: i64) void {
        self.now_ns.store(now_ns, .release);
        self.clock_changed.set(self.baseIo());
    }

    fn mapTimeout(self: *Native, timeout: std.Io.Timeout) std.Io.Timeout {
        if (!self.fixed_clock) return timeout;
        const until = switch (timeout) {
            .deadline => |until| until,
            else => return timeout,
        };
        if (until.clock != .awake) return timeout;
        // Backend waits use their real clock. Preserve the remaining budget
        // of this observer's synthetic absolute clock at each submission.
        return .{ .duration = .{
            .clock = .awake,
            .raw = .fromNanoseconds(@max(0, until.raw.nanoseconds - self.now_ns.load(.acquire))),
        } };
    }

    fn from(userdata: ?*anyopaque) *Native {
        const backend: *std.Io.Threaded = @ptrCast(@alignCast(userdata.?));
        return @fieldParentPtr("backend", backend);
    }

    fn now(userdata: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
        const self = from(userdata);
        if (clock == .awake) return .fromNanoseconds(self.now_ns.load(.acquire));
        const base = self.baseIo();
        return base.vtable.now(base.userdata, clock);
    }

    fn sleep(userdata: ?*anyopaque, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self = from(userdata);
        const base = self.baseIo();
        const until = switch (timeout) {
            .deadline => |until| until,
            else => {
                _ = self.duration_sleep_calls.fetchAdd(1, .monotonic);
                return base.vtable.sleep(base.userdata, timeout);
            },
        };
        if (until.clock != .awake) return base.vtable.sleep(base.userdata, timeout);
        // Expiry follows a confirmed send. If operation/pacing admission
        // fails first, joining cancellation releases this actual backend wait.
        while (self.now_ns.load(.acquire) < until.raw.nanoseconds) {
            try self.clock_changed.wait(base);
            self.clock_changed.reset();
        }
    }

    fn send(userdata: ?*anyopaque, socket: net.Socket.Handle, messages: []net.OutgoingMessage, flags: net.SendFlags) struct { ?net.Socket.SendError, usize } {
        const self = from(userdata);
        const base = self.baseIo();
        _ = self.send_calls.fetchAdd(1, .monotonic);
        const result = if (self.send_override) |override|
            override(self.send_context, socket, messages, flags)
        else
            base.vtable.netSend(base.userdata, socket, messages, flags);
        if (result[1] != 0 and self.advance_after_send_ns != 0) {
            _ = self.now_ns.fetchAdd(self.advance_after_send_ns, .acq_rel);
            self.clock_changed.set(base);
        }
        return result;
    }
};

test {
    _ = @import("deadline_send_io_tests.zig");
}
