//! H3 startup entropy uses the shared cancellation boundary.
const support = @import("../../../internal/secure_random/tests.zig");
const std = @import("std");
const runtime = @import("../../runtime.zig");
const http3 = @import("../../../http3/mod.zig");

test "HTTP3 secure entropy rejects pending cancellation before backend work" {
    try support.rejectsPending();
}
test "HTTP3 secure entropy joins protected backend work then delivers cancellation" {
    try support.joinsCanceledWork();
}
test "HTTP3 secure entropy restores caller protection after success and entropy failure" {
    try support.restoresProtection();
}
test "HTTP3 secure entropy preserves an enclosing cancellation guard" {
    try support.preservesEnclosingGuard();
}
test "HTTP3 secure entropy zio cancellation at offload entry returns Canceled" {
    try support.zioOffloadCancellation();
}

test "HTTP3 secure entropy default pool connectors preserve cancellation and entropy errors" {
    var context: runtime.HandshakeClientPoolDefaultConnector = .{ .options = .{
        .handshake = .{
            .original_destination_connection_id = "entropy-origin",
            .local_connection_id = "entropy-client",
        },
    } };
    const connector = context.connector();
    const uri = try std.Uri.parse("https://entropy.test/");
    const local: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    const redirect: runtime.HandshakeClientPoolRedirectConnectContext = .{ .cross_origin = true, .forward_client_identity = false };
    const target: http3.AltSvcTarget = .{ .alpn = "h3", .connect_host = "alternative.entropy.test", .port = 443, .origin_host = "entropy.test" };
    inline for (.{ false, true }) |canceled| {
        inline for (0..4) |entry| {
            var probe: support.Probe = .{ .pending_cancel = canceled, .fail_entropy = !canceled };
            const result = switch (entry) {
                0 => connector.connect(connector.context, std.testing.allocator, probe.io(), local, uri, .{}),
                1 => connector.connect_redirect.?(connector.context, std.testing.allocator, probe.io(), local, uri, .{}, redirect),
                2 => connector.connect_alt_svc.?(connector.context, std.testing.allocator, probe.io(), local, uri, target, .{}),
                3 => connector.connect_alt_svc_redirect.?(connector.context, std.testing.allocator, probe.io(), local, uri, target, .{}, redirect),
                else => unreachable,
            };
            try std.testing.expectError(if (canceled) error.Canceled else error.EntropyUnavailable, result);
            try std.testing.expectEqual(@as(usize, if (canceled) 0 else 1), probe.calls);
        }
    }
}
