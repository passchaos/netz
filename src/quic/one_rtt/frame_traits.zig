const std = @import("std");
const quic = @import("../mod.zig");

pub const Traits = struct {
    ack_eliciting: bool = false,
    in_flight: bool = false,
    retransmittable: bool = false,
    path_validation: bool = false,
    ack_or_close: bool = false,
    handshake_done: bool = false,
    largest_acknowledged: ?u64 = null,
    stream_bytes: u64 = 0,

    pub fn merge(
        self: *Traits,
        traits: Traits,
    ) error{InvalidFrameLength}!void {
        self.ack_eliciting = self.ack_eliciting or traits.ack_eliciting;
        self.in_flight = self.in_flight or traits.in_flight;
        self.retransmittable = self.retransmittable or traits.retransmittable;
        self.path_validation = self.path_validation or traits.path_validation;
        self.ack_or_close = self.ack_or_close or traits.ack_or_close;
        self.handshake_done = self.handshake_done or traits.handshake_done;
        if (traits.largest_acknowledged) |largest| {
            if (self.largest_acknowledged == null or
                largest > self.largest_acknowledged.?)
            {
                self.largest_acknowledged = largest;
            }
        }
        self.stream_bytes = std.math.add(
            u64,
            self.stream_bytes,
            traits.stream_bytes,
        ) catch return error.InvalidFrameLength;
    }

    pub fn observe(
        self: *Traits,
        frame: quic.Frame,
    ) error{InvalidFrameLength}!void {
        var traits = classify(frame);
        if (frame == .stream) {
            traits.stream_bytes = std.math.cast(
                u64,
                frame.stream.data.len,
            ) orelse return error.InvalidFrameLength;
        }
        try self.merge(traits);
    }

    pub fn autoEcnEligible(self: Traits) bool {
        return self.ack_eliciting and
            self.in_flight and
            !self.path_validation and
            !self.ack_or_close;
    }
};

pub fn classify(frame: quic.Frame) Traits {
    var traits: Traits = switch (frame) {
        // RFC 9000 section 13.2.1: ACK, PADDING, and CONNECTION_CLOSE are
        // non-ack-eliciting. RFC 9002 still counts PADDING in flight.
        .ack => |ack| .{
            .ack_or_close = true,
            .largest_acknowledged = ack.largest_acknowledged,
        },
        .padding => .{ .in_flight = true },
        .connection_close, .application_close => .{
            .ack_or_close = true,
        },
        else => .{ .ack_eliciting = true, .in_flight = true },
    };
    switch (frame) {
        // RFC 9221 DATAGRAM data and PATH_RESPONSE are never retransmitted.
        .ack,
        .padding,
        .path_response,
        .connection_close,
        .application_close,
        .datagram,
        => {},
        else => traits.retransmittable = true,
    }
    switch (frame) {
        .path_challenge, .path_response => traits.path_validation = true,
        .handshake_done => traits.handshake_done = true,
        .stream => {},
        else => {},
    }
    return traits;
}

pub fn analyze(frames: []const quic.Frame) error{InvalidFrameLength}!Traits {
    var traits: Traits = .{};
    for (frames) |frame| try traits.observe(frame);
    return traits;
}

pub fn ackEliciting(frames: []const quic.Frame) bool {
    for (frames) |frame| {
        if (classify(frame).ack_eliciting) return true;
    }
    return false;
}

pub fn containsHandshakeDone(frames: []const quic.Frame) bool {
    for (frames) |frame| {
        if (frame == .handshake_done) return true;
    }
    return false;
}
