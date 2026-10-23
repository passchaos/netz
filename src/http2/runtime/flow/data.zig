//! DATA receive accounting and its adaptive-window commit boundary.

const http2 = @import("../../mod.zig");

pub fn Receiver(comptime Context: anytype) type {
    return struct {
        pub fn receive(self: anytype, stream_id: u31, frame: http2.Frame) Context.ErrorType!Context.ResultType {
            const data = try http2.DataPayload.parse(frame);
            // HTTP/2 flow control charges the whole DATA frame payload, not just
            // the bytes exposed to the application.  PADDED DATA therefore consumes
            // credit for the Pad Length byte and padding octets as well.
            const charged_len = frame.payload.len;
            try self.recv_connection_window.receive(charged_len);
            var windows_granted = false;
            var adaptive_connection_increment: u31 = 0;
            // Only roll back a local DATA debit. An adaptive control submission
            // can grant that freed credit to the peer; after its successful write
            // the whole receive transaction is committed, even if a later policy
            // check terminates the connection.
            errdefer if (!windows_granted) self.recv_connection_window.update(@intCast(charged_len)) catch unreachable;
            const stream_window = try Context.recvWindow(self, stream_id);
            try stream_window.receive(charged_len);
            errdefer if (!windows_granted) stream_window.update(@intCast(charged_len)) catch unreachable;
            if (self.adaptive_window) |*estimator| {
                if (estimator.recordData(
                    charged_len,
                    Context.clockNs(self.io),
                )) |ping_payload| {
                    Context.writeControl(
                        self,
                        .ping,
                        0,
                        &ping_payload,
                        null,
                    ) catch |err| {
                        estimator.cancelProbe(ping_payload);
                        return err;
                    };
                }
            }
            // A previously queued target can have been deferred because an
            // existing stream was too close to the protocol maximum. DATA just
            // reduced that window, so retry before returning it to the caller.
            if (!self.awaiting_settings_ack and
                self.adaptive_queued_target != null)
            {
                const connection_before = self.recv_connection_window.value;
                const stream_before = stream_window.value;
                try Context.grantAdaptive(self);
                if (self.recv_connection_window.value > connection_before) {
                    adaptive_connection_increment = @intCast(self.recv_connection_window.value - connection_before);
                }
                windows_granted = self.recv_connection_window.value != connection_before or
                    stream_window.value != stream_before;
            }
            const budget_charge = self.data_frame_budget.record(
                data.data.len,
                (frame.header.flags & Context.endStreamFlag) != 0,
                Context.budgetMaximum(self.*),
            ) catch {
                self.aggregate_timeout_unusable = true;
                Context.sendGoAway(
                    self,
                    Context.lastProcessed(self.*),
                    .enhance_your_calm,
                    "too_many_data_frames",
                    null,
                ) catch {};
                return error.ConnectionGoAway;
            };
            return .{
                .data = data.data,
                .padding_len = data.padding_len,
                .budget_charge = budget_charge,
                .adaptive_connection_increment = adaptive_connection_increment,
            };
        }
    };
}
