//! Late frames retain connection-wide compression and credit responsibilities.
const std = @import("std");
const http2 = @import("../../mod.zig");

pub fn Handler(comptime hooks: anytype) type {
    return struct {
        pub fn discard(self: anytype, frame: http2.Frame, now_ns: i96, deadline: ?std.Io.Clock.Timestamp) hooks.Error!bool {
            if (frame.header.stream_id == 0 or !hooks.wasReset(self, frame.header.stream_id, now_ns)) return false;
            switch (frame.header.frame_type) {
                .data => {
                    // Only connection credit remains usable after RST_STREAM.
                    _ = try http2.DataPayload.parse(frame);
                    try self.recv_connection_window.receive(frame.payload.len);
                    try hooks.refund(self, frame.payload.len, deadline);
                },
                .headers => {
                    // A reset does not cancel HPACK's connection-wide order.
                    const fields = hooks.readHeaders(self, frame, deadline) catch |err| {
                        // This stack-owned header chain cannot resume after a
                        // deadline discards its incomplete CONTINUATION state.
                        if (err == error.Timeout) self.aggregate_timeout_unusable = true;
                        return err;
                    };
                    hooks.freeHeaders(self.allocator, fields);
                    if (hooks.preadmitted(self, frame.header.stream_id)) |index| {
                        if (self.graceful_preadmitted_peer_streams.items[index].admission == .refused_reset_sent) {
                            _ = self.graceful_preadmitted_peer_streams.orderedRemove(index);
                        }
                    }
                },
                .rst_stream => _ = try http2.ResetStreamPayload.parse(frame),
                else => return false,
            }
            return true;
        }
    };
}
