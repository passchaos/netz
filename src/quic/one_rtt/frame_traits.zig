const std = @import("std");
const quic = @import("../mod.zig");

pub const Traits = struct {
    ack_eliciting: bool = false,
    in_flight: bool = false,
    retransmittable: bool = false,
    has_non_retransmittable: bool = false,
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
        self.has_non_retransmittable = self.has_non_retransmittable or
            traits.has_non_retransmittable;
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

    pub fn allPayloadBytesRetransmittable(self: Traits) bool {
        return self.retransmittable and !self.has_non_retransmittable;
    }
};

pub fn classify(frame: quic.Frame) Traits {
    return switch (frame) {
        // RFC 9000 section 13.2.1: ACK, PADDING, and CONNECTION_CLOSE are
        // non-ack-eliciting. RFC 9002 still counts PADDING in flight.
        .ack => |ack| .{
            .ack_or_close = true,
            .has_non_retransmittable = true,
            .largest_acknowledged = ack.largest_acknowledged,
        },
        .padding => .{
            .in_flight = true,
            .has_non_retransmittable = true,
        },
        .connection_close, .application_close => .{
            .ack_or_close = true,
            .has_non_retransmittable = true,
        },
        // RFC 9221 DATAGRAM data and PATH_RESPONSE are ack-eliciting and count
        // in flight, but their application/probe bytes are never retransmitted.
        .path_response => .{
            .ack_eliciting = true,
            .in_flight = true,
            .has_non_retransmittable = true,
            .path_validation = true,
        },
        .datagram => .{
            .ack_eliciting = true,
            .in_flight = true,
            .has_non_retransmittable = true,
        },
        // draft-ietf-quic-ack-frequency: IMMEDIATE_ACK is ack-eliciting, but
        // retransmitting it outside the packet that needs prompt feedback can
        // spuriously change the peer's ACK schedule. PTO paths add a fresh
        // instance to the probe instead.
        .immediate_ack => .{
            .ack_eliciting = true,
            .in_flight = true,
            .has_non_retransmittable = true,
        },
        .path_challenge => .{
            .ack_eliciting = true,
            .in_flight = true,
            .retransmittable = true,
            .path_validation = true,
        },
        .handshake_done => .{
            .ack_eliciting = true,
            .in_flight = true,
            .retransmittable = true,
            .handshake_done = true,
        },
        else => .{
            .ack_eliciting = true,
            .in_flight = true,
            .retransmittable = true,
        },
    };
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
