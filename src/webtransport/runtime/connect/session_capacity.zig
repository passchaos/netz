//! Retained-owner bounds and draft-16 simultaneous-session admission.
const std = @import("std");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const webtransport = @import("../../mod.zig");

pub fn clientConcurrentLimit(local: usize, peer: u64) usize {
    const peer_capacity = std.math.cast(usize, peer) orelse std.math.maxInt(usize);
    return @min(local, peer_capacity);
}

pub fn serverRetainedLimit(limits: anytype) usize {
    return limits.max_retained_sessions_per_connection orelse @max(@as(usize, 16), limits.max_sessions_per_connection);
}

pub fn validateServerLimits(limits: anytype) error{InvalidSessionState}!void {
    if (limits.max_retained_sessions_per_connection == 0) return error.InvalidSessionState;
}

/// draft-16 section 5.1 permits one simultaneous Session without negotiated
/// flow control. Closed owners can retain metadata without remaining live;
/// unresolved CONNECT cancellation still counts until submitted. The legacy
/// wire version retains its existing admission policy.
pub fn permitsAdditional(version: webtransport.Version, local: http3.Settings, peer: http3.Settings, live_sessions: usize) bool {
    return switch (version) {
        .legacy => true,
        .draft16 => live_sessions == 0 or webtransport.flow_control.negotiated(local, peer),
    };
}

pub fn serverCanAdmit(server: anytype, handle: quic.endpoint_dispatcher.ConnectionHandle, h3: *const http3.runtime.HandshakeServerSession) webtransport.Error!bool {
    if (server.sessionCountForConnection(handle) >= serverRetainedLimit(server.limits)) return false;
    var live: usize = 0;
    var sessions = server.sessions.iterator();
    while (sessions.next()) |entry| {
        if (entry.key_ptr.handle == handle and !entry.value_ptr.*.control.state.closed) live += 1;
    }
    const local = h3.options.local_settings;
    const peer = h3.control.settings.peer;
    const version = try webtransport.negotiatedVersion(local, peer);
    return live < server.limits.max_sessions_per_connection and permitsAdditional(version, local, peer, live);
}

test "WebTransport endpoint client uses local and peer Session minimum" {
    try std.testing.expectEqual(@as(usize, 2), clientConcurrentLimit(2, 3));
    try std.testing.expectEqual(@as(usize, 2), clientConcurrentLimit(3, 2));
    try std.testing.expectEqual(@as(usize, 4), clientConcurrentLimit(4, quic.varint.max_value));
}

test "WebTransport pooling policy respects negotiated version and both flow intents" {
    const enabled = webtransport.defaultSettings(.{});
    var disabled = enabled;
    disabled.webtransport_initial_max_data = 0;
    disabled.webtransport_initial_max_streams_bidi = 0;
    disabled.webtransport_initial_max_streams_uni = 0;
    try std.testing.expect(permitsAdditional(.draft16, enabled, enabled, 2));
    try std.testing.expect(!permitsAdditional(.draft16, enabled, disabled, 1));
    try std.testing.expect(!permitsAdditional(.draft16, disabled, enabled, 1));
    try std.testing.expect(permitsAdditional(.draft16, disabled, disabled, 0));
    try std.testing.expect(permitsAdditional(.legacy, disabled, disabled, 2));
}
