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
                    discardHeaders(self, frame, deadline) catch |err| {
                        // This stack-owned input cannot be replayed after a
                        // partial decode, lost continuation, or allocation
                        // failure. A reset only retires the stream's fields.
                        self.aggregate_timeout_unusable = true;
                        return err;
                    };
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

        fn discardHeaders(self: anytype, first: http2.Frame, deadline: ?std.Io.Clock.Timestamp) hooks.Error!void {
            // A PING/push pump can have already decoded a queued section.
            // Retire its existing output instead of advancing HPACK twice.
            if (try hooks.resumeDeferred(self, first, deadline, false, true)) |fields| {
                hooks.freeHeaders(self.allocator, fields);
                return;
            }
            const block = try hooks.collect(self, first, deadline, false);
            // Decoded output limits apply to application-owned sections.
            // Discard still enforces HPACK and encoded assembly limits, and
            // retains only dynamic entries needed by subsequent streams.
            self.hpack_decoder.discardBlock(self.allocator, block.bytes) catch |err| {
                if (self.hpack_decoder.lastDecodeWasCompressionError()) {
                    self.serve_read_connection_error = .compression;
                }
                return @errorCast(err);
            };
        }
    };
}
