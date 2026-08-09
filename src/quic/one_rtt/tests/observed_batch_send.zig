const std = @import("std");

const net = std.Io.net;

/// Test I/O adapter that records batching and can inject a partial send.
pub const ObservedBatchSend = struct {
    delegate: std.Io,
    fail_after_prefix: ?usize = null,
    calls: usize = 0,
    last_message_count: usize = 0,
    last_control_len: usize = 0,

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
