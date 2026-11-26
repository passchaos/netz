//! Native concurrency with a deterministic send-advanced awake clock.
//! Keep backend userdata intact for every callback we do not override.
const std = @import("std");
const net = std.Io.net;

pub const Native = struct {
    backend: std.Io.Threaded,
    table: std.Io.VTable = undefined,
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
        self.table = base.vtable.*;
        if (self.fixed_clock) {
            self.table.now = now;
            self.table.sleep = sleep;
        }
        self.table.netSend = send;
        return .{ .userdata = base.userdata, .vtable = &self.table };
    }

    fn from(userdata: ?*anyopaque) *Native {
        const backend: *std.Io.Threaded = @ptrCast(@alignCast(userdata.?));
        return @fieldParentPtr("backend", backend);
    }

    fn now(userdata: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
        const self = from(userdata);
        if (clock == .awake) return .fromNanoseconds(self.now_ns.load(.acquire));
        const base = self.backend.io();
        return base.vtable.now(base.userdata, clock);
    }

    fn sleep(userdata: ?*anyopaque, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self = from(userdata);
        const base = self.backend.io();
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
        const base = self.backend.io();
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
