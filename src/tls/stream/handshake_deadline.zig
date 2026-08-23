//! Shared deadline policy for blocking TLS 1.3 handshakes.

const std = @import("std");

/// Convert a caller-provided handshake budget into the single absolute
/// deadline that every receive in the handshake must share. Rejecting an
/// exhausted budget here also guarantees that non-positive durations never
/// reach the transport.
pub fn fromTimeout(
    io: std.Io,
    timeout: ?std.Io.Duration,
) error{Timeout}!?std.Io.Clock.Timestamp {
    const duration = timeout orelse return null;
    if (duration.nanoseconds <= 0) return error.Timeout;
    return .fromNow(io, .{ .raw = duration, .clock = .awake });
}
