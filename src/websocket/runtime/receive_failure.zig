//! Stream/TLS failures retire WebSocket state while preserving the cause.
const std = @import("std");
const tls13_records = @import("../../tls/stream/record_stream.zig");
const tls12_records = @import("../../tls/stream/tls12_record_stream.zig");
const io_interruption = @import("../../internal/io_interruption.zig");

/// TLS record failures include authentication, alerts, framing and truncation.
/// Use the transports' error sets so their terminal errors do not silently
/// escape WebSocket teardown when a new record validation is added. Local
/// allocation failures and interrupted operations remain retryable.
pub fn isTerminalTransportError(err: anyerror) bool {
    if (io_interruption.retryable(err)) return false;
    switch (err) {
        error.OutOfMemory, error.WriteInProgress, error.KeyUpdateRequestPending => return false,
        error.ConnectionClosed, error.StreamReset, error.RequestCancelled, error.RequestRejected, error.ConnectionResetByPeer, error.ReadFailed, error.WriteFailed => return true,
        else => {},
    }
    return contains(tls13_records.Error, err) or
        contains(tls12_records.Error, err) or
        contains(std.crypto.tls.Client.ReadError, err);
}

fn contains(comptime Error: type, err: anyerror) bool {
    inline for (@typeInfo(Error).error_set.?) |member| {
        if (err == @field(Error, member.name)) return true;
    }
    return false;
}
