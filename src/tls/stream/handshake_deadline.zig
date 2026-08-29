//! Shared deadline policy for blocking TLS 1.3 handshakes.

const std = @import("std");
const deadline_policy = @import("../../internal/deadline.zig");

/// Convert a caller-provided handshake budget into the single absolute
/// deadline that every receive in the handshake must share. Rejecting an
/// exhausted budget here also guarantees that non-positive durations never
/// reach the transport.
pub fn fromTimeout(
    io: std.Io,
    timeout: ?std.Io.Duration,
) error{Timeout}!?std.Io.Clock.Timestamp {
    return deadline_policy.fromTimeout(io, timeout);
}

/// Validate a caller-owned handshake deadline. TLS socket reads use the
/// awake clock, so accepting a timestamp from another clock domain would make
/// the comparison meaningless and could silently remove the intended bound.
pub fn usable(
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
) error{Timeout}!std.Io.Clock.Timestamp {
    return deadline_policy.usableAwake(io, deadline);
}

/// Combine a caller's end-to-end deadline with an optional TLS phase timeout.
/// The original absolute timestamp is retained so time already spent in DNS
/// and TCP setup cannot be regained when the TLS handshake begins.
pub fn capTimeout(
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
    timeout: ?std.Io.Duration,
) error{Timeout}!std.Io.Clock.Timestamp {
    return deadline_policy.capTimeout(
        io,
        deadline,
        timeout,
    );
}
