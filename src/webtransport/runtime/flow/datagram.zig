//! Reuse HTTP/3's owned/caller-buffer DATAGRAM receivers while servicing the
//! session's flow-maintenance callback at each otherwise idle socket wait.

const std = @import("std");
const webtransport = @import("../../mod.zig");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const control_mod = @import("../session_control.zig");
const progress_mod = @import("progress.zig");

pub const Error = control_mod.Error;
pub const TimeoutError = Error || quic.runtime.ReceiveTimeoutError;

pub fn receive(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, stream_id: u62) Error!http3.runtime.OwnedConnectDatagram {
    return receiveUntil(control, h3, registry, stream_id, null) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => return @errorCast(err),
    };
}

pub fn receiveWithTimeout(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, stream_id: u62, timeout: std.Io.Duration) TimeoutError!http3.runtime.OwnedConnectDatagram {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return receiveUntil(control, h3, registry, stream_id, .fromNow(h3.established.connection.endpoint.io, .{ .raw = timeout, .clock = .awake }));
}

pub fn receiveWithDeadline(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, stream_id: u62, deadline: std.Io.Clock.Timestamp) TimeoutError!http3.runtime.OwnedConnectDatagram {
    return receiveUntil(control, h3, registry, stream_id, deadline);
}

pub fn receiveUntil(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, stream_id: u62, deadline: ?std.Io.Clock.Timestamp) TimeoutError!http3.runtime.OwnedConnectDatagram {
    var context = progress_mod.Context(@TypeOf(h3)){ .control = control, .h3 = h3, .registry = registry };
    return h3.receiveConnectDatagramWithProgress(stream_id, deadline, context.progress());
}

pub fn receiveInto(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, stream_id: u62, output: []u8) Error![]u8 {
    return receiveIntoUntil(control, h3, registry, stream_id, output, null) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => return @errorCast(err),
    };
}

pub fn receiveIntoWithTimeout(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, stream_id: u62, output: []u8, timeout: std.Io.Duration) TimeoutError![]u8 {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return receiveIntoUntil(control, h3, registry, stream_id, output, .fromNow(h3.established.connection.endpoint.io, .{ .raw = timeout, .clock = .awake }));
}

pub fn receiveIntoWithDeadline(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, stream_id: u62, output: []u8, deadline: std.Io.Clock.Timestamp) TimeoutError![]u8 {
    return receiveIntoUntil(control, h3, registry, stream_id, output, deadline);
}

fn receiveIntoUntil(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, stream_id: u62, output: []u8, deadline: ?std.Io.Clock.Timestamp) TimeoutError![]u8 {
    var context = progress_mod.Context(@TypeOf(h3)){ .control = control, .h3 = h3, .registry = registry };
    return h3.receiveConnectDatagramIntoWithProgress(stream_id, output, deadline, context.progress());
}

pub fn receiveManyInto(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, stream_id: u62, outputs: [][]u8, received: *usize) Error!void {
    return receiveManyIntoUntil(control, h3, registry, stream_id, outputs, received, null) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => return @errorCast(err),
    };
}

pub fn receiveManyIntoWithTimeout(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, stream_id: u62, outputs: [][]u8, received: *usize, timeout: std.Io.Duration) TimeoutError!void {
    received.* = 0;
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return receiveManyIntoUntil(control, h3, registry, stream_id, outputs, received, .fromNow(h3.established.connection.endpoint.io, .{ .raw = timeout, .clock = .awake }));
}

pub fn receiveManyIntoWithDeadline(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, stream_id: u62, outputs: [][]u8, received: *usize, deadline: std.Io.Clock.Timestamp) TimeoutError!void {
    return receiveManyIntoUntil(control, h3, registry, stream_id, outputs, received, deadline);
}

fn receiveManyIntoUntil(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, stream_id: u62, outputs: [][]u8, received: *usize, deadline: ?std.Io.Clock.Timestamp) TimeoutError!void {
    var context = progress_mod.Context(@TypeOf(h3)){ .control = control, .h3 = h3, .registry = registry };
    return h3.receiveConnectDatagramsIntoWithProgress(stream_id, outputs, received, deadline, context.progress());
}

test {
    _ = @import("datagram/tests.zig");
}
