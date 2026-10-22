//! Opening credit from ordered session Capsules before allocating a QUIC ID.

const std = @import("std");
const webtransport = @import("../../mod.zig");
const control_mod = @import("../session_control.zig");
const quic = @import("../../../quic/mod.zig");
const deadline_policy = @import("../../../internal/deadline.zig");
const flow_progress = @import("progress.zig");
const association_prefix = @import("../stream/prefix.zig");

pub fn prepare(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, direction: webtransport.StreamDirection, deadline: ?std.Io.Clock.Timestamp) (control_mod.Error || quic.runtime.ReceiveTimeoutError)!u62 {
    return prepareInternal(control, h3, registry, null, direction, deadline, false);
}

pub fn prepareId(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, id: u62, direction: webtransport.StreamDirection, deadline: ?std.Io.Clock.Timestamp) (control_mod.Error || quic.runtime.ReceiveTimeoutError)!void {
    _ = try prepareInternal(control, h3, registry, id, direction, deadline, false);
}

/// Coordinate registry/H3/QUIC reservation and a reliable reset prefix before
/// returning a stream ID. The transport's single-attempt reservation binds
/// prefix storage without introducing a fallible allocation after the ID.
pub fn open(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, direction: webtransport.StreamDirection, deadline: ?std.Io.Clock.Timestamp, one_attempt: bool) (control_mod.Error || quic.runtime.ReceiveTimeoutError)!u62 {
    const H3Type = @typeInfo(@TypeOf(h3)).pointer.child;
    if (comptime @hasField(H3Type, "callback_reader_active")) {
        if (deadline != null and h3.callback_reader_active) return error.ConcurrentRead;
    }
    const connection = &h3.established.connection;
    while (true) {
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(connection.endpoint.io, absolute);
        const expected: u62 = @intCast(switch (direction) {
            .bidirectional => connection.nextLocalBidirectionalStreamId(),
            .unidirectional => connection.nextLocalUnidirectionalStreamId(),
        });
        _ = try prepareInternal(control, h3, registry, expected, direction, deadline, one_attempt);
        var storage: [16]u8 = undefined;
        const prefix = try association_prefix.header(registry.session_id, direction, &storage);
        const actual = reserve(h3, direction, prefix) catch |err| switch (err) {
            error.StreamLimitExceeded, error.CongestionLimited => {
                if (one_attempt) return err;
                const absolute = deadline orelse return err;
                if (h3.dispatcherBound()) return error.InvalidDispatcherState;
                const H3 = @typeInfo(@TypeOf(h3)).pointer.child;
                if (comptime @hasDecl(H3, "receiveDetachedRequestProgressWithDeadline"))
                    try h3.receiveDetachedRequestProgressWithDeadline(control.session_id.value, absolute)
                else
                    try h3.receiveDetachedResponseProgressWithDeadline(control.session_id.value, absolute);
                continue;
            },
            error.PacingLimited => {
                if (one_attempt or h3.dispatcherBound()) return err;
                if (deadline) |absolute|
                    try connection.waitForPacingAvailabilityWithDeadline(absolute)
                else
                    try connection.waitForPacingAvailability();
                continue;
            },
            else => return err,
        };
        std.debug.assert(actual == expected);
        const cursor = switch (direction) {
            .bidirectional => registry.next_local_bidi,
            .unidirectional => registry.next_local_uni,
        };
        const stream = if (cursor == expected)
            try registry.commitPreparedLocal(expected, direction)
        else
            try registry.registerLocal(expected, direction);
        return stream.stream_id;
    }
}

fn reserve(h3: anytype, direction: webtransport.StreamDirection, prefix: []const u8) control_mod.Error!u64 {
    const connection = &h3.established.connection;
    const H3 = @typeInfo(@TypeOf(h3)).pointer.child;
    if (comptime @hasDecl(H3, "tryOpenServerUnidirectionalStream")) {
        return switch (direction) {
            .bidirectional => if (connection.config.reliable_reset.peer)
                try connection.tryOpenStreamWithResetPrefix(.bidirectional, prefix)
            else
                try connection.tryOpenStream(),
            .unidirectional => if (connection.config.reliable_reset.peer)
                try h3.tryOpenServerUnidirectionalStreamWithResetPrefix(prefix)
            else
                try h3.tryOpenServerUnidirectionalStream(),
        };
    } else {
        return switch (direction) {
            .bidirectional => if (connection.config.reliable_reset.peer)
                try h3.tryOpenClientBidirectionalStreamWithResetPrefix(prefix)
            else
                try h3.tryOpenClientBidirectionalStream(),
            .unidirectional => if (connection.config.reliable_reset.peer)
                try connection.tryOpenStreamWithResetPrefix(.unidirectional, prefix)
            else
                try connection.tryOpenUnidirectionalStream(),
        };
    }
}

fn attempt(registry: *webtransport.StreamRegistry, id: ?u62, direction: webtransport.StreamDirection) control_mod.Error!u62 {
    if (id) |value| {
        try registry.prepareLocalId(value, direction);
        return value;
    }
    return registry.prepareLocal(direction);
}

fn prepareInternal(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, id: ?u62, direction: webtransport.StreamDirection, deadline: ?std.Io.Clock.Timestamp, one_attempt: bool) (control_mod.Error || quic.runtime.ReceiveTimeoutError)!u62 {
    control.bindFlow(registry.flow);
    var context = flow_progress.Context(@TypeOf(h3)){ .control = control, .h3 = h3, .registry = registry, .one_attempt = one_attempt };
    while (true) {
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(h3.established.connection.endpoint.io, absolute);
        return attempt(registry, id, direction) catch |err| switch (err) {
            error.FlowControlBlocked => {
                try context.progress().maintain(deadline);
                try control.ensureOpen();
                if (attempt(registry, id, direction)) |value| return value else |retry_err| {
                    if (retry_err != error.FlowControlBlocked) return retry_err;
                }
                if (one_attempt) return error.FlowControlBlocked;
                const absolute = deadline orelse return error.FlowControlBlocked;
                if (h3.dispatcherBound()) return error.InvalidDispatcherState;
                const H3 = @typeInfo(@TypeOf(h3)).pointer.child;
                if (comptime @hasDecl(H3, "receiveDetachedRequestProgressWithDeadline")) {
                    try h3.receiveDetachedRequestProgressWithDeadline(control.session_id.value, absolute);
                } else {
                    try h3.receiveDetachedResponseProgressWithDeadline(control.session_id.value, absolute);
                }
                try context.progress().maintain(deadline);
                try control.ensureOpen();
                continue;
            },
            else => return err,
        };
    }
}
