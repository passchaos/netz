//! Stable native clock observation for authenticated session-control fixtures.
const std = @import("std");
const Native = @import("../../../../internal/testing/deadline_send_io.zig").Native;

pub const DeadlineIo = struct {
    native: Native,
    expire_after_send_call: ?usize = null,

    pub fn init(allocator: std.mem.Allocator, delegate: std.Io) DeadlineIo {
        return .{ .native = .{
            .backend = .init(allocator, .{ .async_limit = .nothing }),
            .delegate_io = delegate,
            .now_ns = .init(1_000_000),
        } };
    }

    pub fn io(self: *DeadlineIo) std.Io {
        self.native.send_context = self;
        self.native.send_override = send;
        return self.native.io();
    }

    pub fn deinit(self: *DeadlineIo) void {
        self.native.backend.deinit();
    }

    fn send(context: ?*anyopaque, handle: std.Io.net.Socket.Handle, messages: []std.Io.net.OutgoingMessage, flags: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
        const self: *DeadlineIo = @ptrCast(@alignCast(context.?));
        const call = self.native.send_calls.load(.acquire);
        const base = self.native.baseIo();
        const result = base.vtable.netSend(base.userdata, handle, messages, flags);
        if (self.expire_after_send_call == call and result[0] == null and result[1] != 0) {
            _ = self.native.now_ns.fetchAdd(2, .acq_rel);
            self.native.clock_changed.set(base);
        }
        return result;
    }
};
