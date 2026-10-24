//! Keep WebTransport adapter storage budgets independent of transport padding.

const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../runtime.zig");
const http3 = @import("../../http3/mod.zig");
const session_control = @import("session_control.zig");
const protected_control = @import("protected_session_control.zig");
const PendingSessionClose = @import("session_control/pending_close.zig").Pending;
const AcceptedSession = runtime.AcceptedSession;
const AcceptedProtectedSession = runtime.AcceptedProtectedSession;
const AcceptedHandshakeSession = runtime.AcceptedHandshakeSession;
const ClientSession = runtime.ClientSession;
const HandshakeClientSession = runtime.HandshakeClientSession;
const ProtectedClientSession = runtime.ProtectedClientSession;

test "WebTransport sessions keep inbound and outbound close storage compact" {
    if (@sizeOf(usize) == 8) {
        const Layout = struct {
            accepted: usize,
            accepted_handshake_overhead: usize,
            client_overhead: usize,
            handshake_client_overhead: usize,
            protected_client_overhead: usize,
        };
        // Debug and ReleaseSafe retain extra safety state in the HTTP/3 and
        // compression members. Check the WebTransport adapter overhead
        // independently of those transports, whose own state can grow. The
        // embedded transport can raise the wrapper's alignment, so include
        // the resulting tail padding without increasing the adapter budget.
        const expected: Layout = switch (builtin.mode) {
            .Debug, .ReleaseSafe => .{
                .accepted = 1_152,
                .accepted_handshake_overhead = 968,
                .client_overhead = 1_064,
                .handshake_client_overhead = 888,
                .protected_client_overhead = 896,
            },
            .ReleaseFast, .ReleaseSmall => .{
                .accepted = 1_144,
                .accepted_handshake_overhead = 960,
                .client_overhead = 1_056,
                .handshake_client_overhead = 880,
                .protected_client_overhead = 896,
            },
        };
        try std.testing.expectEqual(
            @as(usize, 352),
            @sizeOf(session_control.Control),
        );
        try std.testing.expectEqual(
            @as(usize, 512),
            @sizeOf(protected_control.Reader),
        );
        try std.testing.expectEqual(
            @as(usize, 160),
            @sizeOf(PendingSessionClose),
        );
        try std.testing.expectEqual(expected.accepted, @sizeOf(AcceptedSession));
        try std.testing.expectEqual(
            @as(usize, 952),
            @sizeOf(AcceptedProtectedSession),
        );
        try std.testing.expectEqual(
            std.mem.alignForward(usize, @sizeOf(http3.runtime.HandshakeServerSession) + expected.accepted_handshake_overhead, @alignOf(AcceptedHandshakeSession)),
            @sizeOf(AcceptedHandshakeSession),
        );
        try std.testing.expectEqual(
            std.mem.alignForward(usize, @sizeOf(http3.runtime.Client) + expected.client_overhead, @alignOf(ClientSession)),
            @sizeOf(ClientSession),
        );
        try std.testing.expectEqual(
            std.mem.alignForward(usize, @sizeOf(http3.runtime.HandshakeClient) + expected.handshake_client_overhead, @alignOf(HandshakeClientSession)),
            @sizeOf(HandshakeClientSession),
        );
        try std.testing.expectEqual(
            std.mem.alignForward(usize, @sizeOf(http3.runtime.ProtectedClient) + expected.protected_client_overhead, @alignOf(ProtectedClientSession)),
            @sizeOf(ProtectedClientSession),
        );
    }
}
