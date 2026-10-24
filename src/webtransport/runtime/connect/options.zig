//! Normalize WebTransport capabilities and local admission policy before I/O.
const webtransport = @import("../../mod.zig");
const http3 = @import("../../../http3/mod.zig");
const flow = @import("../../settings/flow.zig");
const Limits = webtransport.runtime.Limits;
const Error = webtransport.runtime.Error;

pub fn protected(config: http3.runtime.ProtectedConfig, limits: Limits) Error!http3.runtime.ProtectedConfig {
    // This legacy adapter lacks stateful Session flow-control accounting.
    if (limits.require_session_flow_control) return error.SessionFlowControlRequired;
    if (limits.initial_flow_limits != null) return error.WebTransportNotNegotiated;
    var out = config;
    out.local_settings = webtransport.defaultSettings(out.local_settings);
    if (!out.local_settings.webTransportVersions().legacy) return error.WebTransportNotNegotiated;
    out.local_settings.webtransport_versions = .{ .legacy = true };
    return out;
}

pub fn server(options: http3.runtime.HandshakeServerOptions, max_sessions: u64, limits: Limits) Error!http3.runtime.HandshakeServerOptions {
    var out = options;
    out.session.local_settings = try flow.applyRequired(out.session.local_settings, max_sessions, limits.initial_flow_limits, limits.require_session_flow_control);
    out.session.early_connect_datagrams = limits.early_connect_datagrams;
    return out;
}

pub fn client(options: http3.runtime.HandshakeClientOptions, limits: Limits) Error!http3.runtime.HandshakeClientOptions {
    var out = options;
    out.session = try session(out.session, limits);
    return out;
}

pub fn session(options: http3.runtime.HandshakeSessionOptions, limits: Limits) Error!http3.runtime.HandshakeSessionOptions {
    var out = options;
    out.local_settings = try flow.applyRequired(out.local_settings, 1, limits.initial_flow_limits, limits.require_session_flow_control);
    return out;
}
