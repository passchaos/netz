//! Bounded ordinary requests sharing one negotiated HTTP/2 connection owner.
const std = @import("std");

pub const Error = error{ InvalidSharedRequestOptions, SharedRequestQueueFull };
pub const Options = struct {
    /// Pending and active ordinary TCP requests retained across all origins.
    max_requests: usize = 256,
    /// Local request admission ceiling, additionally bounded by peer SETTINGS.
    max_streams_per_connection: usize = 64,
    /// Round-robin upload quantum; flow control may grant fewer bytes.
    write_chunk_bytes: usize = 16 * 1024,
    /// Finite write/control budget for requests without an earlier deadline.
    output_timeout: std.Io.Duration = .fromSeconds(5),
};

pub const State = @import("shared_tcp/state.zig").State;
