const std = @import("std");
const forwarded_io = @import("../../../internal/testing/forwarded_io.zig");

const net = std.Io.net;

/// Test I/O adapter that records batching and can inject a partial send.
pub const ObservedBatchSend = struct {
    delegate: std.Io,
    table: std.Io.VTable = undefined,
    fail_after_prefix: ?usize = null,
    fail_on_call: ?usize = null,
    calls: usize = 0,
    last_message_count: usize = 0,
    last_control_len: usize = 0,

    /// Preserve the execution, cancellation and socket owner for every
    /// callback, including deadline tasks launched by a caller of netSend.
    pub fn io(self: *ObservedBatchSend) std.Io {
        self.table = forwarded_io.table(from, baseIo, mapTimeout);
        self.table.netSend = netSend;
        return .{ .userdata = self, .vtable = &self.table };
    }

    fn from(userdata: ?*anyopaque) *ObservedBatchSend {
        return @ptrCast(@alignCast(userdata.?));
    }
    fn baseIo(self: *ObservedBatchSend) std.Io {
        return self.delegate;
    }
    fn mapTimeout(_: *ObservedBatchSend, timeout: std.Io.Timeout) std.Io.Timeout {
        return timeout;
    }

    pub fn netSend(
        userdata: ?*anyopaque,
        socket_handle: net.Socket.Handle,
        messages: []net.OutgoingMessage,
        flags: net.SendFlags,
    ) struct { ?net.Socket.SendError, usize } {
        const self: *ObservedBatchSend = @ptrCast(@alignCast(userdata));
        self.calls += 1;
        self.last_message_count = messages.len;
        self.last_control_len = if (messages.len == 0)
            0
        else
            messages[0].control.len;
        if (self.fail_on_call == self.calls) {
            return .{ error.NetworkDown, 0 };
        }
        const configured_prefix = self.fail_after_prefix orelse {
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        };
        const prefix_len = @min(configured_prefix, messages.len);
        if (prefix_len != 0) {
            const send_error, const sent_count =
                self.delegate.vtable.netSend(
                    self.delegate.userdata,
                    socket_handle,
                    messages[0..prefix_len],
                    flags,
                );
            if (send_error != null or sent_count != prefix_len) {
                return .{ send_error, sent_count };
            }
        }
        return .{ error.NetworkDown, prefix_len };
    }
};
