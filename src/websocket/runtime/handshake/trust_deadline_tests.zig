const std = @import("std");
const h3 = @import("../h3.zig");
const Probe = @import("../../../internal/testing/trust_admission.zig").Probe;

test "WebSocket H3 trust startup deadline admits a timer before loading roots" {
    var probe: Probe = .{};
    var options: h3.UriConnectOptions = .{};
    options.h3.handshake.original_destination_connection_id = "trust-origin";
    options.h3.handshake.local_connection_id = "trust-client";
    try std.testing.expectError(error.ConcurrencyUnavailable, h3.Client.connectUriAttemptWithDeadline(std.testing.allocator, probe.io(), .{ .ip4 = .loopback(0) }, "https://trust.test/", options, probe.deadline()));
    try probe.expectRejected();
}
