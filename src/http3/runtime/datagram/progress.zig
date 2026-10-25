//! Owning receive progress keeps outbound feedback behind payload delivery.
const std = @import("std");
const deadline_policy = @import("../../../internal/deadline.zig");

pub fn Pump(comptime hooks: anytype) type {
    return struct {
        pub fn run(session: anytype, stream_id: ?u62, deadline: ?std.Io.Clock.Timestamp, target: anytype) hooks.Error!void {
            if (comptime hooks.check_callback) {
                if (session.callback_reader_active) return error.ConcurrentRead;
            }
            if (session.dispatcherBound()) return error.InvalidDispatcherState;
            if (stream_id) |id| {
                if (!session.connect_datagrams.contains(id)) return error.UnexpectedStream;
            }
            if (deadline) |absolute| _ = try deadline_policy.usableAwake(hooks.io(session), absolute);
            while (true) {
                const wake = try feedback(session, deadline);
                const until = deadline_policy.earlier(wake, deadline);
                const result = if (stream_id) |id|
                    hooks.receive(session, id, until, target)
                else
                    hooks.receiveAttached(session, until);
                result catch |err| {
                    // Feedback pacing may expire before the application budget.
                    // Resume it without needing another inbound QUIC packet.
                    if (err == error.Timeout and wake != null and (deadline == null or std.Io.Clock.Timestamp.compare(wake.?, .lt, deadline.?))) {
                        if (deadline) |absolute| _ = try deadline_policy.usableAwake(hooks.io(session), absolute);
                        continue;
                    }
                    return err;
                };
                // Once the packet has been visited, feedback backpressure must
                // not hide a directly filled DATAGRAM target or Capsule bytes.
                _ = try feedback(session, deadline);
                return;
            }
        }

        fn feedback(session: anytype, deadline: ?std.Io.Clock.Timestamp) hooks.Error!?std.Io.Clock.Timestamp {
            const connection = &session.established.connection;
            // A terminal connection cannot carry feedback. Preserve a DATAGRAM
            // fulfilled earlier in that packet; its next read reports closure.
            if (connection.closing() or connection.draining() or connection.closed()) return null;
            // A delivered packet remains deliverable when its budget expires
            // during parsing; skip further outbound work in that case.
            if (deadline) |absolute| {
                if (absolute.durationFromNow(hooks.io(session)).raw.nanoseconds <= 0) return null;
            }
            hooks.feedback(session) catch |err| switch (err) {
                error.PacingLimited => {
                    const wake_ns = session.established.connection.pendingPacingDeadline() orelse return err;
                    return .{ .clock = .awake, .raw = .fromNanoseconds(@intCast(wake_ns)) };
                },
                error.CongestionLimited, error.FlowControlBlocked => return null,
                else => return err,
            };
            // One packet may carry only part of a large feedback queue. Give
            // its next prefix a turn before blocking for an unrelated packet.
            if (session.qpack_decode.pendingDecoderInstructions().len != 0) return .now(hooks.io(session), .awake);
            return null;
        }
    };
}
