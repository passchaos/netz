const std = @import("std");
const clients = @import("mod.zig");
const support = @import("../../internal/testing/trust_completion.zig");
const socket = @import("../../internal/test_socket.zig");

fn bundled(mode: support.Mode) !void {
    inline for (.{ clients.ClientConnection, clients.Tls13ClientConnection }) |Client| {
        var probe: support.Probe = .{ .mode = mode };
        try std.testing.expectError(switch (mode) {
            .ordinary => error.OutOfMemory,
            .expired => error.Timeout,
            .canceled => error.Canceled,
        }, Client.initVerifiedWithDeadline(probe.allocator(), probe.io(), socket.stream(), .{ .server_name = "trust-completion.test", .root_source = .bundled }, probe.deadline()));
        try std.testing.expectEqual(@as(usize, 1), probe.allocations);
    }
}

test "TLS trust completion preserves allocation failure within budget" {
    try bundled(.ordinary);
}
test "TLS trust completion expired bundled-source failure returns Timeout" {
    try bundled(.expired);
}
test "TLS trust completion canceled bundled-source failure returns Canceled" {
    try bundled(.canceled);
}
