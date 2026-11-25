const std = @import("std");
const client = @import("endpoint_client.zig");
const Probe = @import("../../internal/testing/trust_admission.zig").Probe;

test "WebTransport H3 trust startup deadline admits a timer before loading roots" {
    var probe: Probe = .{};
    var options: client.Options = .{};
    options.h3.handshake.original_destination_connection_id = "trust-origin";
    options.h3.handshake.local_connection_id = "trust-client";
    try std.testing.expectError(error.ConcurrencyUnavailable, client.Client.connectUriWithDeadline(std.testing.allocator, probe.io(), .{ .ip4 = .loopback(0) }, "https://trust.test/", options, probe.deadline()));
    try probe.expectRejected();
}
