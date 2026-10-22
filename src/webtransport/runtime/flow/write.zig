//! Bind an owning CONNECT reader to synchronous stream writes. The progress
//! context cannot outlive this call or compete with a dispatcher socket owner.

const std = @import("std");
const webtransport = @import("../../mod.zig");
const control_mod = @import("../session_control.zig");
const progress_mod = @import("progress.zig");
const stream = @import("../stream.zig");
const batch = @import("../stream/batch.zig");

pub const Error = stream.Error;
pub const TimeoutError = stream.TimeoutError;

fn context(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry) progress_mod.Context(@TypeOf(h3)) {
    return .{ .control = control, .h3 = h3, .registry = registry };
}

pub fn send(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, session_id: webtransport.SessionId, stream_id: u62, payload: []const u8, fin: bool) Error!void {
    var committed: usize = 0;
    return sendUntil(control, h3, registry, session_id, stream_id, payload, fin, &committed, null) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => return @errorCast(err),
    };
}

pub fn sendWithDeadline(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, session_id: webtransport.SessionId, stream_id: u62, payload: []const u8, fin: bool, committed: *usize, deadline: std.Io.Clock.Timestamp) TimeoutError!void {
    return sendUntil(control, h3, registry, session_id, stream_id, payload, fin, committed, deadline);
}

fn sendUntil(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, session_id: webtransport.SessionId, stream_id: u62, payload: []const u8, fin: bool, committed: *usize, deadline: ?std.Io.Clock.Timestamp) TimeoutError!void {
    var bound = context(control, h3, registry);
    return stream.sendWithProgress(&h3.established.connection, registry, session_id, stream_id, payload, fin, committed, deadline, bound.progress());
}

pub fn sendSlices(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, session_id: webtransport.SessionId, stream_id: u62, parts: []const []const u8, fin: bool) Error!void {
    var committed: usize = 0;
    return sendSlicesUntil(control, h3, registry, session_id, stream_id, parts, fin, &committed, null) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => return @errorCast(err),
    };
}

pub fn sendSlicesWithDeadline(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, session_id: webtransport.SessionId, stream_id: u62, parts: []const []const u8, fin: bool, committed: *usize, deadline: std.Io.Clock.Timestamp) TimeoutError!void {
    return sendSlicesUntil(control, h3, registry, session_id, stream_id, parts, fin, committed, deadline);
}

fn sendSlicesUntil(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, session_id: webtransport.SessionId, stream_id: u62, parts: []const []const u8, fin: bool, committed: *usize, deadline: ?std.Io.Clock.Timestamp) TimeoutError!void {
    var bound = context(control, h3, registry);
    return stream.sendSlicesWithProgress(&h3.established.connection, registry, session_id, stream_id, parts, fin, committed, deadline, bound.progress());
}

pub fn write(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, session_id: webtransport.SessionId, stream_id: u62, payload: []const u8) Error!usize {
    return writeUntil(control, h3, registry, session_id, stream_id, payload, null) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => return @errorCast(err),
    };
}

pub fn writeWithDeadline(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, session_id: webtransport.SessionId, stream_id: u62, payload: []const u8, deadline: std.Io.Clock.Timestamp) TimeoutError!usize {
    return writeUntil(control, h3, registry, session_id, stream_id, payload, deadline);
}

fn writeUntil(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, session_id: webtransport.SessionId, stream_id: u62, payload: []const u8, deadline: ?std.Io.Clock.Timestamp) TimeoutError!usize {
    var bound = context(control, h3, registry);
    return stream.writeWithProgress(&h3.established.connection, registry, session_id, stream_id, payload, deadline, bound.progress());
}

pub fn writeSlices(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, session_id: webtransport.SessionId, stream_id: u62, parts: []const []const u8) Error!usize {
    return writeSlicesUntil(control, h3, registry, session_id, stream_id, parts, null) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => return @errorCast(err),
    };
}

pub fn writeSlicesWithDeadline(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, session_id: webtransport.SessionId, stream_id: u62, parts: []const []const u8, deadline: std.Io.Clock.Timestamp) TimeoutError!usize {
    return writeSlicesUntil(control, h3, registry, session_id, stream_id, parts, deadline);
}

fn writeSlicesUntil(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, session_id: webtransport.SessionId, stream_id: u62, parts: []const []const u8, deadline: ?std.Io.Clock.Timestamp) TimeoutError!usize {
    var bound = context(control, h3, registry);
    return stream.writeSlicesWithProgress(&h3.established.connection, registry, session_id, stream_id, parts, deadline, bound.progress());
}

pub fn writeStreams(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, session_id: webtransport.SessionId, writes: []const batch.Write, counts: []usize) Error!batch.Result {
    return writeStreamsUntil(control, h3, registry, session_id, writes, counts, null) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => return @errorCast(err),
    };
}

pub fn writeStreamsWithDeadline(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, session_id: webtransport.SessionId, writes: []const batch.Write, counts: []usize, deadline: std.Io.Clock.Timestamp) TimeoutError!batch.Result {
    return writeStreamsUntil(control, h3, registry, session_id, writes, counts, deadline);
}

fn writeStreamsUntil(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, session_id: webtransport.SessionId, writes: []const batch.Write, counts: []usize, deadline: ?std.Io.Clock.Timestamp) TimeoutError!batch.Result {
    var bound = context(control, h3, registry);
    return batch.writeWithProgress(&h3.established.connection, registry, session_id, writes, counts, deadline, bound.progress());
}

test {
    _ = @import("write/tests.zig");
}
