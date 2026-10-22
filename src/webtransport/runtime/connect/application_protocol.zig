//! Application protocol failures are scoped HTTP/3 WT_ALPN_ERROR resets.
//! Cancel CONNECT first, then retire only data streams associated with it.

const std = @import("std");
const webtransport = @import("../../mod.zig");
const http3 = @import("../../../http3/mod.zig");
const control = @import("../session_control.zig");
const deadline_policy = @import("../../../internal/deadline.zig");

pub const Error = webtransport.Error || http3.runtime.Error;
pub const TimeoutError = Error || http3.runtime.ReceiveTimeoutError;

pub const Rejection = struct {
    stream_id: u62,
    connect_cancelled: bool = false,

    pub fn poll(self: *Rejection, h3: *http3.runtime.HandshakeClient) Error!bool {
        if (!self.connect_cancelled) {
            try h3.connect_datagrams.rejectEarlyAssociation(self.stream_id);
            try h3.tryCancelRequest(self.stream_id, webtransport.ApplicationErrorCode.alpn_error);
            self.connect_cancelled = true;
            return false;
        }
        var registry = try webtransport.StreamRegistry.init(h3.allocator, .init(self.stream_id), .client, .{});
        defer registry.deinit();
        return try control.terminateStreamsOnce(&h3.established.connection, &registry) == .complete;
    }
};

pub fn reject(h3: *http3.runtime.HandshakeClient, stream_id: u62, deadline: ?std.Io.Clock.Timestamp) TimeoutError!void {
    var rejection = Rejection{ .stream_id = stream_id };
    while (true) {
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(h3.established.connection.endpoint.io, absolute);
        const complete = rejection.poll(h3) catch |err| switch (err) {
            error.PacingLimited => {
                if (deadline) |absolute| try h3.established.connection.waitForPacingAvailabilityWithDeadline(absolute) else try h3.established.connection.waitForPacingAvailability();
                continue;
            },
            error.CongestionLimited, error.FlowControlBlocked => {
                if (deadline) |absolute| try h3.pollControlWithDeadline(absolute) else try h3.pollControl();
                continue;
            },
            else => return err,
        };
        if (complete) return;
    }
}

pub fn validateResponse(h3: *http3.runtime.HandshakeClient, stream_id: u62, request: *const webtransport.application_protocol.Request, response: http3.DecodedResponseHead, deadline: ?std.Io.Clock.Timestamp) TimeoutError!void {
    _ = request.validateResponse(response.headers) catch |err| {
        try reject(h3, stream_id, deadline);
        return err;
    };
}

test {
    _ = @import("application_protocol/tests.zig");
}
