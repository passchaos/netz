//! Owning stream readers service pending flow updates while no application
//! event is ready. This keeps a completed stream's next opening credit live.

const std = @import("std");
const webtransport = @import("../../mod.zig");
const control_mod = @import("../session_control.zig");
const progress_mod = @import("progress.zig");
const incremental = @import("../stream_incremental.zig");
const stream = @import("../stream.zig");

pub fn read(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, session_id: webtransport.SessionId, out: []u8) incremental.Error!incremental.Read {
    return readUntil(control, h3, registry, session_id, null, out, null) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => return @errorCast(err),
    };
}

pub fn readWithDeadline(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, session_id: webtransport.SessionId, out: []u8, deadline: std.Io.Clock.Timestamp) incremental.TimeoutError!incremental.Read {
    return readUntil(control, h3, registry, session_id, null, out, deadline);
}

pub fn readId(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, session_id: webtransport.SessionId, stream_id: u62, out: []u8) incremental.Error!incremental.Read {
    return readUntil(control, h3, registry, session_id, stream_id, out, null) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => return @errorCast(err),
    };
}

pub fn readIdWithDeadline(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, session_id: webtransport.SessionId, stream_id: u62, out: []u8, deadline: std.Io.Clock.Timestamp) incremental.TimeoutError!incremental.Read {
    return readUntil(control, h3, registry, session_id, stream_id, out, deadline);
}

fn readUntil(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, session_id: webtransport.SessionId, target: ?u62, out: []u8, deadline: ?std.Io.Clock.Timestamp) incremental.TimeoutError!incremental.Read {
    var context = progress_mod.Context(@TypeOf(h3)){ .control = control, .h3 = h3, .registry = registry, .input = .incremental, .target = target };
    return incremental.readWithProgress(&h3.established.connection, registry, session_id, target, out, deadline, context.progress());
}

pub fn receive(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, session_id: webtransport.SessionId, maximum: usize) stream.Error!stream.OwnedHandshakeStream {
    return receiveUntil(control, h3, registry, session_id, maximum, null) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => return @errorCast(err),
    };
}

pub fn receiveWithDeadline(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, session_id: webtransport.SessionId, maximum: usize, deadline: std.Io.Clock.Timestamp) stream.TimeoutError!stream.OwnedHandshakeStream {
    return receiveUntil(control, h3, registry, session_id, maximum, deadline);
}

fn receiveUntil(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, session_id: webtransport.SessionId, maximum: usize, deadline: ?std.Io.Clock.Timestamp) stream.TimeoutError!stream.OwnedHandshakeStream {
    var context = progress_mod.Context(@TypeOf(h3)){ .control = control, .h3 = h3, .registry = registry, .input = .whole };
    return stream.receiveWithProgress(&h3.established.connection, registry, session_id, maximum, deadline, context.progress());
}
