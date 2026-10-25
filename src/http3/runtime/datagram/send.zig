//! CONNECT DATAGRAM retries share the application's owner and optional deadline.
const std = @import("std");
const deadline_policy = @import("../../../internal/deadline.zig");

pub fn Controller(comptime hooks: anytype) type {
    return struct {
        pub fn single(session: anytype, stream_id: u62, payload: []const u8, deadline: ?std.Io.Clock.Timestamp, progress: anytype) (hooks.Error || @TypeOf(progress).ErrorSet)!void {
            try validateOwner(session, deadline);
            try hooks.validate(session, stream_id, payload);
            const encoded = try session.connect_datagrams.encode(stream_id, payload);
            while (true) {
                try checkDeadline(session, deadline);
                // Receiving congestion relief may also deliver a protocol's
                // terminal capsule. Let its owner act before resubmission.
                try progress.maintain(deadline);
                try checkDeadline(session, deadline);
                try hooks.validate(session, stream_id, payload);
                session.established.connection.trySendDatagram(encoded) catch |err| switch (err) {
                    error.CongestionLimited => {
                        // Ordinary single-send APIs expose congestion to their
                        // caller. Only bounded single sends wait for credit.
                        if (deadline == null) return err;
                        try receive(session, stream_id, deadline);
                        continue;
                    },
                    error.PacingLimited => {
                        try waitForPacing(session, stream_id, deadline, progress);
                        continue;
                    },
                    else => return err,
                };
                return;
            }
        }

        pub fn batch(session: anytype, stream_id: u62, payloads: []const []const u8, committed: *usize, deadline: ?std.Io.Clock.Timestamp, progress: anytype) (hooks.Error || @TypeOf(progress).ErrorSet)!void {
            committed.* = 0;
            try validateOwner(session, deadline);
            for (payloads) |payload| try hooks.validate(session, stream_id, payload);
            const encoded = try session.connect_datagrams.encodeBatch(stream_id, payloads);
            try session.established.connection.validateDatagrams(encoded.datagrams);
            while (committed.* < encoded.datagrams.len) {
                try checkDeadline(session, deadline);
                try progress.maintain(deadline);
                try checkDeadline(session, deadline);
                try hooks.validate(session, stream_id, payloads[committed.*]);
                var count: usize = 0;
                session.established.connection.trySendDatagrams(encoded.datagrams[committed.*..], &count) catch |err| {
                    committed.* += count;
                    switch (err) {
                        error.CongestionLimited => try receive(session, stream_id, deadline),
                        error.PacingLimited => try waitForPacing(session, stream_id, deadline, progress),
                        else => return err,
                    }
                    continue;
                };
                if (count == 0) return error.Unexpected;
                committed.* += count;
            }
        }

        fn waitForPacing(session: anytype, stream_id: u62, deadline: ?std.Io.Clock.Timestamp, progress: anytype) (hooks.Error || @TypeOf(progress).ErrorSet)!void {
            if (comptime @hasDecl(@TypeOf(progress), "waitForPacing")) {
                return progress.waitForPacing(deadline);
            }
            try checkDeadline(session, deadline);
            const connection = &session.established.connection;
            const wake_ns = connection.pendingPacingDeadline() orelse return error.PacingLimited;
            const wake: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .fromNanoseconds(@intCast(wake_ns)) };
            const until = deadline_policy.earlier(wake, deadline).?;
            if (until.durationFromNow(hooks.io(session)).raw.nanoseconds <= 0) return feedback(session);
            // Use the HTTP/3 visitor while waiting, so terminal signals and
            // sibling work are routed before another application submission.
            receive(session, stream_id, until) catch |err| {
                // A pacing wake retries; only the caller's bound is a timeout.
                if (err == error.Timeout and (deadline == null or std.Io.Clock.Timestamp.compare(until, .lt, deadline.?))) {
                    try checkDeadline(session, deadline);
                    return feedback(session);
                }
                return err;
            };
        }

        fn receive(session: anytype, stream_id: u62, deadline: ?std.Io.Clock.Timestamp) hooks.Error!void {
            try hooks.receive(session, stream_id, deadline, null);
            try feedback(session);
        }

        fn feedback(session: anytype) hooks.Error!void {
            // Received termination must reach the next validation without a
            // feedback writer sleeping beyond this wait's deadline. Failed
            // attempts retain the exact pending QPACK prefix for later service.
            hooks.feedback(session) catch |err| switch (err) {
                error.PacingLimited, error.CongestionLimited, error.FlowControlBlocked => {},
                else => return err,
            };
        }

        fn checkDeadline(session: anytype, deadline: ?std.Io.Clock.Timestamp) hooks.Error!void {
            if (deadline) |absolute| _ = try deadline_policy.usableAwake(hooks.io(session), absolute);
        }

        fn validateOwner(session: anytype, deadline: ?std.Io.Clock.Timestamp) hooks.Error!void {
            if (comptime hooks.check_callback) {
                if (session.callback_reader_active) return error.ConcurrentRead;
            }
            if (session.dispatcherBound()) return error.InvalidDispatcherState;
            try checkDeadline(session, deadline);
        }
    };
}
