const std = @import("std");
const stream = @import("mod.zig");
const Probe = @import("../../internal/testing/trust_admission.zig").Probe;

test "TLS trust startup deadline admits a timer before loading roots" {
    inline for (.{ stream.ClientConnection, stream.Tls13ClientConnection }) |Client| {
        var probe: Probe = .{};
        const socket: std.Io.net.Stream = .{ .socket = .{ .handle = undefined, .address = .{ .ip4 = .loopback(0) } } };
        try std.testing.expectError(error.ConcurrencyUnavailable, Client.initVerifiedWithDeadline(std.testing.allocator, probe.io(), socket, .{ .server_name = "trust.test" }, probe.deadline()));
        try probe.expectRejected();
    }
}

test "TLS trust startup handshake timeout begins before loading roots" {
    inline for (.{ stream.ClientConnection, stream.Tls13ClientConnection }) |Client| {
        var probe: Probe = .{};
        const socket: std.Io.net.Stream = .{ .socket = .{ .handle = undefined, .address = .{ .ip4 = .loopback(0) } } };
        try std.testing.expectError(error.ConcurrencyUnavailable, Client.initVerified(std.testing.allocator, probe.io(), socket, .{ .server_name = "trust.test", .handshake_timeout = .fromSeconds(1) }));
        try probe.expectRejected();
    }
}
