//! Version-aware CONNECT admission over the authenticated HTTP/3 connection.

const std = @import("std");
const webtransport = @import("../../mod.zig");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const headers = @import("headers.zig");
const deadline_policy = @import("../../../internal/deadline.zig");

pub const Role = enum { client, server };
pub const Error = webtransport.Error || http3.runtime.Error || error{InvalidConnect};
pub const TimeoutError = Error || quic.runtime.ReceiveTimeoutError;

pub fn check(local: http3.Settings, peer: http3.Settings, config: quic.one_rtt.ConnectionConfig, role: Role) Error!webtransport.Version {
    const server = if (role == .server) local else peer;
    if (!server.enable_connect_protocol) return error.WebTransportNotNegotiated;
    const version = try webtransport.negotiatedVersion(local, peer);
    if (!local.h3_datagram or !peer.h3_datagram) return error.DatagramsNotNegotiated;
    if ((config.local_max_datagram_frame_size orelse 0) == 0 or
        (config.peer_max_datagram_frame_size orelse 0) == 0) return error.DatagramsNotNegotiated;
    if (version == .draft16) {
        if (!config.reliable_reset.local or !config.reliable_reset.peer) return error.ReliableResetNotNegotiated;
    }
    return version;
}

pub fn clientVersion(h3: *const http3.runtime.HandshakeClient) Error!webtransport.Version {
    if (!h3.control.settings.received) return error.MissingSettings;
    return check(h3.options.local_settings, h3.control.settings.peer, h3.established.connection.config, .client);
}

/// Local admission policy: a peer without intent is valid but unsuitable.
pub fn requireFlowControl(local: http3.Settings, peer: http3.Settings, required: bool) Error!void {
    if (required and !webtransport.flow_control.negotiated(local, peer)) return error.SessionFlowControlRequired;
}

pub fn clientVersionWithPolicy(h3: *const http3.runtime.HandshakeClient, required: bool) Error!webtransport.Version {
    const version = try clientVersion(h3);
    try requireFlowControl(h3.options.local_settings, h3.control.settings.peer, required);
    return version;
}

/// Session operations use the authenticated endpoint role. The client's
/// local SETTINGS_ENABLE_CONNECT_PROTOCOL is optional under RFC 9220.
pub fn ensure(h3: anytype) Error!void {
    const state = switch (@typeInfo(@typeInfo(@TypeOf(h3)).pointer.child)) {
        .pointer => h3.*,
        else => h3,
    };
    if (!state.control.settings.received) return error.MissingSettings;
    const role: Role = if (state.established.connection.config.local_endpoint == .client) .client else .server;
    _ = try check(state.options.local_settings, state.control.settings.peer, state.established.connection.config, role);
}

pub fn validateRequest(h3: *const http3.runtime.HandshakeServerSession, request: anytype) Error!void {
    if (!h3.control.settings.received) return error.MissingSettings;
    const version = try check(h3.options.local_settings, h3.control.settings.peer, h3.established.connection.config, .server);
    try headers.validateRequestForVersion(request, version);
}

pub fn validateRequestWithPolicy(h3: *const http3.runtime.HandshakeServerSession, request: anytype, required: bool) Error!void {
    try validateRequest(h3, request);
    try requireFlowControl(h3.options.local_settings, h3.control.settings.peer, required);
}

/// Publish SETTINGS before waiting for the server's capability advertisement.
/// Every send retry and receive retains the caller's absolute deadline.
pub fn prepareClient(h3: *http3.runtime.HandshakeClient, deadline: ?std.Io.Clock.Timestamp) TimeoutError!webtransport.Version {
    if (h3.dispatcherBound()) return error.InvalidDispatcherState;
    if (h3.callback_reader_active) return error.ConcurrentRead;
    while (!h3.control.settings.sent) {
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(h3.established.connection.endpoint.io, absolute);
        const submission = if (deadline) |absolute| h3.ensureSettingsSentWithDeadline(absolute) else h3.ensureSettingsSent();
        submission catch |err| switch (err) {
            error.PacingLimited => {
                if (deadline) |absolute|
                    try h3.established.connection.waitForPacingAvailabilityWithDeadline(absolute)
                else
                    try h3.established.connection.waitForPacingAvailability();
                continue;
            },
            error.CongestionLimited, error.FlowControlBlocked => {
                if (deadline) |absolute|
                    try h3.pollControlWithDeadline(absolute)
                else
                    try h3.pollControl();
                continue;
            },
            else => return err,
        };
    }
    _ = if (deadline) |absolute| try h3.receivePeerSettingsWithDeadline(absolute) else try h3.receivePeerSettings();
    return clientVersion(h3);
}

pub fn waitServerSettings(h3: *http3.runtime.HandshakeServerSession, deadline: ?std.Io.Clock.Timestamp) TimeoutError!void {
    while (!h3.control.settings.received) {
        if (deadline) |absolute| try h3.pollControlWithDeadline(absolute) else try h3.pollControl();
    }
}

test "WebTransport modern negotiation requires both directions of every transport capability" {
    const keys = quic.protection.deriveAes128Keys([_]u8{0x61} ** quic.protection.secret_len);
    const config = quic.one_rtt.ConnectionConfig{
        .peer = .{ .ip4 = .loopback(1) },
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "local",
        .peer_connection_id = "peer",
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .reliable_reset = .{ .local = true, .peer = true },
    };
    const settings = webtransport.defaultSettings(.{});
    try std.testing.expectEqual(webtransport.Version.draft16, try check(settings, settings, config, .client));
    inline for (.{ Role.client, Role.server }) |role| {
        inline for (.{ true, false }) |local_direction| {
            inline for (.{ @as(?usize, null), @as(?usize, 0) }) |absent| {
                var missing = config;
                if (local_direction) missing.local_max_datagram_frame_size = absent else missing.peer_max_datagram_frame_size = absent;
                try std.testing.expectError(error.DatagramsNotNegotiated, check(settings, settings, missing, role));
            }
            var missing = config;
            if (local_direction) missing.reliable_reset.local = false else missing.reliable_reset.peer = false;
            try std.testing.expectError(error.ReliableResetNotNegotiated, check(settings, settings, missing, role));
        }
    }
    var client = settings;
    client.enable_connect_protocol = false;
    try std.testing.expectEqual(webtransport.Version.draft16, try check(client, settings, config, .client));
    try std.testing.expectEqual(webtransport.Version.draft16, try check(settings, client, config, .server));
    try std.testing.expectError(error.WebTransportNotNegotiated, check(settings, client, config, .client));
    try std.testing.expectError(error.WebTransportNotNegotiated, check(client, settings, config, .server));
    var legacy = settings;
    legacy.webtransport_versions = .{ .legacy = true };
    var legacy_config = config;
    legacy_config.reliable_reset = .{};
    try std.testing.expectEqual(webtransport.Version.legacy, try check(settings, legacy, legacy_config, .client));
    try std.testing.expectEqual(webtransport.Version.legacy, try check(legacy, settings, legacy_config, .server));
    legacy_config.peer_max_datagram_frame_size = null;
    try std.testing.expectError(error.DatagramsNotNegotiated, check(settings, legacy, legacy_config, .client));
    legacy_config.peer_max_datagram_frame_size = 1200;
    legacy_config.local_max_datagram_frame_size = 0;
    try std.testing.expectError(error.DatagramsNotNegotiated, check(legacy, settings, legacy_config, .server));
}

test {
    _ = @import("handshake_tests.zig");
}
