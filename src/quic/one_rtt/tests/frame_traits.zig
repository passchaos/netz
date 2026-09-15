const std = @import("std");
const quic = @import("../../mod.zig");
const frame_traits = @import("../frame_traits.zig");

test "QUIC 1-RTT frame traits classify ACK padding and close" {
    const ack = quic.Frame{ .ack = .{
        .largest_acknowledged = 7,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &.{},
    } };
    const traits = try frame_traits.analyze(&.{
        ack,
        .{ .padding = .{ .len = 8 } },
        .{ .application_close = .{
            .error_code = 0,
            .reason_phrase = "",
        } },
    });
    try std.testing.expect(!traits.ack_eliciting);
    try std.testing.expect(traits.in_flight);
    try std.testing.expect(!traits.retransmittable);
    try std.testing.expect(traits.has_non_retransmittable);
    try std.testing.expect(!traits.allPayloadBytesRetransmittable());
    try std.testing.expect(traits.ack_or_close);
    try std.testing.expectEqual(@as(?u64, 7), traits.largest_acknowledged);
    try std.testing.expect(!traits.autoEcnEligible());
}

test "QUIC 1-RTT frame traits distinguish unreliable and probing frames" {
    const datagram = frame_traits.classify(.{ .datagram = .{
        .data = "payload",
        .length_present = true,
    } });
    try std.testing.expect(datagram.ack_eliciting);
    try std.testing.expect(datagram.in_flight);
    try std.testing.expect(!datagram.retransmittable);
    try std.testing.expect(datagram.has_non_retransmittable);
    try std.testing.expect(datagram.autoEcnEligible());

    const immediate_ack = frame_traits.classify(.{ .immediate_ack = {} });
    try std.testing.expect(immediate_ack.ack_eliciting);
    try std.testing.expect(immediate_ack.in_flight);
    try std.testing.expect(!immediate_ack.retransmittable);
    try std.testing.expect(immediate_ack.has_non_retransmittable);
    try std.testing.expect(immediate_ack.autoEcnEligible());

    const path = try frame_traits.analyze(&.{
        .{ .path_challenge = .{ .data = [_]u8{1} ** 8 } },
        .{ .ping = {} },
    });
    try std.testing.expect(path.ack_eliciting);
    try std.testing.expect(path.in_flight);
    try std.testing.expect(path.retransmittable);
    try std.testing.expect(path.path_validation);
    try std.testing.expect(!path.autoEcnEligible());
}

test "QUIC 1-RTT frame traits aggregate stream bytes and ACK watermark" {
    const traits = try frame_traits.analyze(&.{
        .{ .stream = .{ .stream_id = 0, .offset = 0, .data = "abc" } },
        .{ .ack = .{
            .largest_acknowledged = 4,
            .ack_delay = 0,
            .first_ack_range = 0,
            .ranges = &.{},
        } },
        .{ .stream = .{ .stream_id = 4, .offset = 0, .data = "defg" } },
        .{ .ack = .{
            .largest_acknowledged = 9,
            .ack_delay = 0,
            .first_ack_range = 0,
            .ranges = &.{},
        } },
        .{ .handshake_done = {} },
    });
    try std.testing.expectEqual(@as(u64, 7), traits.stream_bytes);
    try std.testing.expectEqual(@as(?u64, 9), traits.largest_acknowledged);
    try std.testing.expect(traits.handshake_done);
    try std.testing.expect(traits.retransmittable);
    try std.testing.expect(traits.has_non_retransmittable);
    try std.testing.expect(!traits.allPayloadBytesRetransmittable());
    try std.testing.expect(!traits.autoEcnEligible());
}

test "QUIC 1-RTT frame traits identify fully retransmittable payloads" {
    const traits = try frame_traits.analyze(&.{
        .{ .stream = .{ .stream_id = 0, .offset = 0, .data = "abc" } },
        .{ .ping = {} },
        .{ .max_data = .{ .maximum_data = 4096 } },
    });
    try std.testing.expect(traits.retransmittable);
    try std.testing.expect(!traits.has_non_retransmittable);
    try std.testing.expect(traits.allPayloadBytesRetransmittable());
}
