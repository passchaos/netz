//! Bounded connection-generation soak for the shared QUIC endpoint.

const std = @import("std");
const harness = @import("quic_endpoint_soak/harness.zig");

test "shared QUIC endpoint reclaims 64 authenticated connections" {
    const summary = try harness.run();
    try std.testing.expectEqual(@as(usize, 64), summary.connections);
    try std.testing.expectEqual(@as(usize, 64), summary.stream_round_trips);
    try std.testing.expectEqual(@as(usize, 32), summary.version_2_connections);
    try std.testing.expectEqual(@as(usize, 32), summary.aes_256_connections);
    try std.testing.expect(summary.retained_live_bytes != 0);
    try std.testing.expect(
        summary.peak_live_bytes > summary.retained_live_bytes,
    );
}
