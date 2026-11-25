//! Native UDP deadline/progress interruption shared by transport regressions.
const std = @import("std");

pub const Probe = struct {
    backend: std.Io.Threaded,
    table: std.Io.VTable = undefined,
    clock: std.atomic.Value(i64) = .init(0),
    armed: std.atomic.Value(bool) = .init(true),
    emitted: std.Io.Event = .unset,
    hold: std.Io.Event = .unset,
    joined: std.atomic.Value(bool) = .init(false),
    expected_messages: usize = 2,
    emit_prefix: bool = true,
    send_calls: std.atomic.Value(usize) = .init(0),
    forced_error: ?std.Io.net.Socket.SendError = null,
    held_mutex: ?*std.Io.Mutex = null,
    mutex_waiting: std.Io.Event = .unset,
    timer_finished: std.Io.Event = .unset,
    forced_mutex_release: std.atomic.Value(bool) = .init(false),

    pub fn io(self: *Probe) std.Io {
        const base = self.backend.io();
        self.table = base.vtable.*;
        self.table.now = now;
        self.table.sleep = sleep;
        self.table.netSend = send;
        self.table.futexWait = wait;
        self.table.futexWaitUncancelable = waitUncancelable;
        return .{ .userdata = base.userdata, .vtable = &self.table };
    }
    fn from(userdata: ?*anyopaque) *Probe {
        const backend: *std.Io.Threaded = @ptrCast(@alignCast(userdata.?));
        return @fieldParentPtr("backend", backend);
    }
    fn now(userdata: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
        const self = from(userdata);
        if (clock == .awake) return .fromNanoseconds(self.clock.load(.acquire));
        const base = self.backend.io();
        return base.vtable.now(base.userdata, clock);
    }
    fn sleep(userdata: ?*anyopaque, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self = from(userdata);
        const until = switch (timeout) {
            .deadline => |value| value,
            else => return error.Canceled,
        };
        if (self.held_mutex != null) try self.mutex_waiting.wait(self.backend.io()) else try self.emitted.wait(self.backend.io());
        self.clock.store(@intCast(until.raw.nanoseconds), .release);
        self.timer_finished.set(self.backend.io());
    }
    fn wait(userdata: ?*anyopaque, pointer: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self = from(userdata);
        const base = self.backend.io();
        if (self.held_mutex) |mutex| if (pointer == @as(*const u32, @ptrCast(mutex))) self.mutex_waiting.set(base);
        return base.vtable.futexWait(base.userdata, pointer, expected, timeout);
    }
    fn waitUncancelable(userdata: ?*anyopaque, pointer: *const u32, expected: u32) void {
        const self = from(userdata);
        const base = self.backend.io();
        if (self.held_mutex) |mutex| if (pointer == @as(*const u32, @ptrCast(mutex))) {
            // A legacy unbounded lock gets a finite fixture escape, but the
            // test rejects the need for this external release.
            self.mutex_waiting.set(base);
            self.timer_finished.waitUncancelable(base);
            self.forced_mutex_release.store(true, .release);
            mutex.unlock(base);
            return;
        };
        base.vtable.futexWaitUncancelable(base.userdata, pointer, expected);
    }
    fn send(userdata: ?*anyopaque, socket: std.Io.net.Socket.Handle, messages: []std.Io.net.OutgoingMessage, flags: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
        const self = from(userdata);
        const base = self.backend.io();
        _ = self.send_calls.fetchAdd(1, .monotonic);
        if (!self.armed.swap(false, .acq_rel)) return base.vtable.netSend(base.userdata, socket, messages, flags);
        if (messages.len != self.expected_messages) return .{ error.Unexpected, 0 };
        if (!self.emit_prefix) {
            self.emitted.set(base);
            self.hold.wait(base) catch |err| {
                self.joined.store(true, .release);
                return .{ self.forced_error orelse err, 0 };
            };
            return .{ error.Unexpected, 0 };
        }
        const prefix = base.vtable.netSend(base.userdata, socket, messages[0..1], flags);
        if (prefix[1] != 1) return prefix;
        self.emitted.set(base);
        self.hold.wait(base) catch |err| {
            self.joined.store(true, .release);
            return .{ self.forced_error orelse err, prefix[1] };
        };
        return .{ error.Unexpected, prefix[1] };
    }
};
