//! QUIC transport-parameter limits derived from endpoint receive capacity.
//!
//! Generated parameters are safely narrowed to what the UDP endpoint can
//! actually receive. Raw wire overrides remain caller-controlled, but are
//! rejected when they advertise a capacity the endpoint cannot honor.

const std = @import("std");
const quic = @import("../mod.zig");

pub fn limitGenerated(
    parameters: *quic.TransportParameters,
    receive_capacity: usize,
) void {
    parameters.max_udp_payload_size = @min(
        parameters.max_udp_payload_size,
        capacityAsU64(receive_capacity),
    );
}

pub fn validateAdvertised(
    advertised: u64,
    receive_capacity: usize,
) error{InvalidTransportParameter}!void {
    if (advertised > capacityAsU64(receive_capacity)) {
        return error.InvalidTransportParameter;
    }
}

fn capacityAsU64(receive_capacity: usize) u64 {
    return std.math.cast(u64, receive_capacity) orelse std.math.maxInt(u64);
}

test "QUIC generated receive advertisement fits endpoint capacity" {
    var parameters = quic.practical_transport_parameters;
    limitGenerated(&parameters, 4096);
    try std.testing.expectEqual(
        @as(u64, 4096),
        parameters.max_udp_payload_size,
    );

    parameters.max_udp_payload_size = 1400;
    limitGenerated(&parameters, 4096);
    try std.testing.expectEqual(
        @as(u64, 1400),
        parameters.max_udp_payload_size,
    );
}

test "QUIC raw receive advertisement cannot exceed endpoint capacity" {
    try validateAdvertised(4096, 4096);
    try std.testing.expectError(
        error.InvalidTransportParameter,
        validateAdvertised(4097, 4096),
    );
}
