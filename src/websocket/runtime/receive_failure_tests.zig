//! Caller retry conditions stay local while fatal transport errors retire WS.
const std = @import("std");
const policy = @import("receive_failure.zig");

test "WebSocket transport failure policy preserves caller retry conditions" {
    for ([_]anyerror{ error.Timeout, error.Canceled, error.ConcurrencyUnavailable, error.OutOfMemory, error.WriteInProgress, error.KeyUpdateRequestPending, error.BufferTooShort, error.ResponseAvailable }) |err| {
        try std.testing.expect(!policy.isTerminalTransportError(err));
    }
    for ([_]anyerror{ error.UnexpectedEof, error.TruncatedRecord, error.AuthenticationFailed, error.PeerTlsAlert, error.TlsConnectionTruncated, error.TlsBadRecordMac, error.TlsDecodeError, error.InvalidNewSessionTicket, error.StreamReset, error.SocketUnconnected, error.ReadFailed }) |err| {
        try std.testing.expect(policy.isTerminalTransportError(err));
    }
}
