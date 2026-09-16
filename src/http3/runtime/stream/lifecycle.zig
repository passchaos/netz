const std = @import("std");
const http3 = @import("../../mod.zig");
const Error = @import("../error.zig").Error;
pub const Client = @import("lifecycle/client.zig").Client;
const server = @import("lifecycle/server.zig");
pub const ShutdownState = server.ShutdownState;
pub const Server = server.Server;

/// RFC 9114 §5.2 processing certainty for a client-initiated request stream.
/// A stream at or above the server's GOAWAY identifier was not processed and
/// may be retried on another connection, subject to application replay policy.
pub const GoAwayRetryDisposition = enum {
    no_goaway,
    may_have_been_processed,
    safe_to_retry,
};

pub fn goAwayRetryDisposition(
    peer_goaway_id: ?u64,
    stream_id: u62,
) GoAwayRetryDisposition {
    const goaway_id = peer_goaway_id orelse return .no_goaway;
    return if (stream_id >= goaway_id)
        .safe_to_retry
    else
        .may_have_been_processed;
}

test "HTTP/3 client GOAWAY classifies request replay safety" {
    try std.testing.expectEqual(
        GoAwayRetryDisposition.no_goaway,
        goAwayRetryDisposition(null, 0),
    );
    try std.testing.expectEqual(
        GoAwayRetryDisposition.may_have_been_processed,
        goAwayRetryDisposition(8, 4),
    );
    try std.testing.expectEqual(
        GoAwayRetryDisposition.safe_to_retry,
        goAwayRetryDisposition(8, 8),
    );
    try std.testing.expectEqual(
        GoAwayRetryDisposition.safe_to_retry,
        goAwayRetryDisposition(8, 12),
    );
}
