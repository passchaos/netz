//! Exact transport-wide initial Session quotas, including explicit zeroes.
const http3 = @import("../../http3/mod.zig");
const webtransport = @import("../mod.zig");

pub fn apply(settings: http3.Settings, max_sessions: u64, initial: ?webtransport.flow_control.Limits) webtransport.Error!http3.Settings {
    var out = try webtransport.settingsWithSessionCapacity(settings, max_sessions);
    const limits = initial orelse return out;
    try limits.validate();
    // An explicitly unflow-controlled connection can host only one Session.
    // Mixed zero/non-zero quotas still declare flow-control intent.
    if (max_sessions > 1 and limits.data == 0 and limits.bidi == 0 and limits.uni == 0) return error.InvalidSessionState;
    out.webtransport_initial_max_data = limits.data;
    out.webtransport_initial_max_streams_bidi = limits.bidi;
    out.webtransport_initial_max_streams_uni = limits.uni;
    return out;
}

pub fn validateExisting(settings: http3.Settings, initial: ?webtransport.flow_control.Limits) webtransport.Error!void {
    const limits = initial orelse return;
    try limits.validate();
    if (settings.webtransport_initial_max_data != limits.data or
        settings.webtransport_initial_max_streams_bidi != limits.bidi or
        settings.webtransport_initial_max_streams_uni != limits.uni) return error.InvalidSessionState;
}

/// A required negotiation cannot succeed when this endpoint declares no intent.
pub fn validateRequired(settings: http3.Settings, required: bool) webtransport.Error!void {
    if (required and !webtransport.flow_control.intent(settings)) return error.InvalidSessionState;
}

pub fn applyRequired(settings: http3.Settings, max_sessions: u64, initial: ?webtransport.flow_control.Limits, required: bool) webtransport.Error!http3.Settings {
    const out = try apply(settings, max_sessions, initial);
    try validateRequired(out, required);
    return out;
}
