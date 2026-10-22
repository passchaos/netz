//! Malformed WebTransport CONNECT is an HTTP/3 stream error. Keep cancellation
//! retry state separate from request metadata so pacing never closes siblings.

const std = @import("std");
const http3 = @import("../../../http3/mod.zig");
const negotiation = @import("negotiation.zig");
const deadline_policy = @import("../../../internal/deadline.zig");

pub const Failure = enum {
    invalid_connect,
    webtransport_not_negotiated,
    datagrams_not_negotiated,
    reliable_reset_not_negotiated,

    pub fn fromError(err: anyerror) ?Failure {
        return switch (err) {
            error.InvalidConnect => .invalid_connect,
            error.WebTransportNotNegotiated => .webtransport_not_negotiated,
            error.DatagramsNotNegotiated => .datagrams_not_negotiated,
            error.ReliableResetNotNegotiated => .reliable_reset_not_negotiated,
            else => null,
        };
    }

    pub fn cause(self: Failure) negotiation.Error {
        return switch (self) {
            .invalid_connect => error.InvalidConnect,
            .webtransport_not_negotiated => error.WebTransportNotNegotiated,
            .datagrams_not_negotiated => error.DatagramsNotNegotiated,
            .reliable_reset_not_negotiated => error.ReliableResetNotNegotiated,
        };
    }
};

pub const Pending = struct {
    stream_id: u62,
    application_error_code: u64 = http3.ApplicationErrorCode.message_error,
    failure: ?Failure = null,

    pub fn submit(self: Pending, h3: *http3.runtime.HandshakeServerSession) http3.runtime.Error!void {
        try h3.tryCancelRequest(self.stream_id, self.application_error_code);
    }
};

/// Owning admission keeps the same absolute deadline through cancellation.
pub fn validate(h3: *http3.runtime.HandshakeServerSession, stream_id: u62, request: anytype, deadline: ?std.Io.Clock.Timestamp) negotiation.TimeoutError!void {
    if (deadline) |absolute| _ = try deadline_policy.usableAwake(h3.established.connection.endpoint.io, absolute);
    negotiation.validateRequest(h3, request) catch |err| {
        const failure = Failure.fromError(err) orelse return err;
        const pending = Pending{ .stream_id = stream_id, .failure = failure };
        while (true) {
            if (deadline) |absolute| _ = try deadline_policy.usableAwake(h3.established.connection.endpoint.io, absolute);
            pending.submit(h3) catch |submission_error| switch (submission_error) {
                error.PacingLimited => {
                    if (deadline) |absolute|
                        try h3.established.connection.waitForPacingAvailabilityWithDeadline(absolute)
                    else
                        try h3.established.connection.waitForPacingAvailability();
                    continue;
                },
                error.CongestionLimited, error.FlowControlBlocked => {
                    if (deadline) |absolute| try h3.pollControlWithDeadline(absolute) else try h3.pollControl();
                    continue;
                },
                else => return submission_error,
            };
            return failure.cause();
        }
    };
}
