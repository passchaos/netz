const std = @import("std");
const connection = @import("../client/http3_connection.zig");
const types = @import("../client/types.zig");
const Probe = @import("../../internal/testing/trust_admission.zig").Probe;

test "HTTP H3 trust startup deadline admits a timer before loading roots" {
    var probe: Probe = .{};
    var options: types.Options = .{};
    options.http3.handshake.handshake.original_destination_connection_id = "trust-origin";
    options.http3.handshake.handshake.local_connection_id = "trust-client";
    try std.testing.expectError(error.ConcurrencyUnavailable, connection.Owner.connect(std.testing.allocator, probe.io(), try std.Uri.parse("https://trust.test/"), options, probe.deadline()));
    try probe.expectRejected();
}
