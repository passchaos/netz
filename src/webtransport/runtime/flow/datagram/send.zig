//! DATAGRAM waits service CONNECT capsules while preserving one socket owner.
const std = @import("std");
const control_mod = @import("../../session_control.zig");
const webtransport = @import("../../../mod.zig");
const progress_mod = @import("../progress.zig");
const quic = @import("../../../../quic/mod.zig");

pub const Error = control_mod.Error || quic.runtime.ReceiveTimeoutError;

pub fn single(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, id: u62, payload: []const u8, deadline: ?std.Io.Clock.Timestamp) Error!void {
    var base = progress_mod.Context(@TypeOf(h3)){ .control = control, .h3 = h3, .registry = registry, .one_attempt = true };
    return h3.sendConnectDatagramWithProgress(id, payload, deadline, base.progress());
}

pub fn batch(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, id: u62, payloads: []const []const u8, committed: *usize, deadline: ?std.Io.Clock.Timestamp) Error!void {
    var base = progress_mod.Context(@TypeOf(h3)){ .control = control, .h3 = h3, .registry = registry, .one_attempt = true };
    return h3.sendConnectDatagramsWithProgress(id, payloads, committed, deadline, base.progress());
}
