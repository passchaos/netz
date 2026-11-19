//! Client duplex handles share a single connection owner. Handle-local
//! registration releases the shared count once; stream IDs route input even
//! when the owning handle moves.
const std = @import("std");

pub const PumpEvent = union(enum) {
    stream: u31,
    progress,
    wake,
};

pub const Owners = @import("owners.zig").Owners;

/// One connection owner may also advance input before any duplex handle
/// exists. Control replies keep the caller's original absolute budget.
pub fn pump(connection: anytype, deadline: std.Io.Clock.Timestamp, comptime hooks: anytype) hooks.Error!PumpEvent {
    if (connection.aggregate_timeout_unusable) return error.ConnectionClosed;
    if (connection.role != .client or connection.callback_reader_active) return error.UnexpectedFrame;
    return ingest(connection, try hooks.readWire(connection, deadline), deadline, hooks);
}

pub fn queuedIndex(frames: anytype, start: usize, stream_id: u31) ?usize {
    for (frames[start..], start..) |frame, index| {
        if (frame.frame.header.stream_id == stream_id) return index;
    }
    return null;
}

pub fn poll(connection: anytype, stream_id: u31, deadline: ?std.Io.Clock.Timestamp, comptime hooks: anytype) hooks.Error!?hooks.Frame {
    if (connection.aggregate_timeout_unusable) return error.ConnectionClosed;
    if (connection.callback_reader_active) return error.UnexpectedFrame;
    try hooks.discardCanceled(connection, deadline);
    if (hooks.peek(connection, stream_id)) |queued| {
        if (queued.header.frame_type != .headers or hooks.decoded(connection, queued)) {
            return hooks.pop(connection, stream_id);
        }
    }
    return null;
}

/// Consume one already-owned input frame. The shared pump queues application
/// events and advances HPACK in wire order; individual handles poll that queue.
pub fn ingest(connection: anytype, input: anytype, deadline: ?std.Io.Clock.Timestamp, comptime hooks: anytype) hooks.Error!PumpEvent {
    var frame = input;
    var owned = true;
    defer if (owned) frame.deinit(connection.allocator);
    try hooks.sequence(connection, frame.frame, deadline);
    // PUSH_PROMISE and promised-stream frames advance connection HPACK and
    // flow-control state. Consume them before routing the frame to a local
    // stream queue; the aggregate caller only owns the parent response.
    if (try hooks.pushed(connection, frame.frame, deadline)) return .progress;
    switch (frame.frame.header.frame_type) {
        .headers, .continuation => {
            if (try hooks.header(connection, frame)) owned = false;
            if (hooks.peek(connection, frame.frame.header.stream_id)) |queued| {
                if (queued.header.frame_type != .headers or hooks.decoded(connection, queued)) {
                    return .{ .stream = frame.frame.header.stream_id };
                }
            }
            return .progress;
        },
        else => {},
    }
    if (try hooks.connectionFrame(connection, frame.frame, deadline)) return .progress;
    if (frame.frame.header.frame_type == .goaway) {
        try hooks.goaway(connection, frame.frame);
        return .progress;
    }
    hooks.sibling(connection, frame) catch |err| {
        connection.aggregate_timeout_unusable = true;
        return err;
    };
    owned = false;
    return .{ .stream = frame.frame.header.stream_id };
}

/// Decode every HEADERS section in wire order before exposing a stream's
/// frames. Polling another handle after a partial section cannot advance HPACK
/// past that section, and deferred fields are never decoded a second time.
pub fn read(
    connection: anytype,
    stream_id: u31,
    deadline: ?std.Io.Clock.Timestamp,
    comptime hooks: anytype,
) hooks.Error!hooks.Frame {
    if (connection.aggregate_timeout_unusable) return error.ConnectionClosed;
    if (connection.callback_reader_active) return error.UnexpectedFrame;
    while (true) {
        if (try poll(connection, stream_id, deadline, hooks)) |queued| return queued;
        var frame = try hooks.readWire(connection, deadline);
        var owned = true;
        defer if (owned) frame.deinit(connection.allocator);
        try hooks.sequence(connection, frame.frame, deadline);
        if (try hooks.pushed(connection, frame.frame, deadline)) continue;
        switch (frame.frame.header.frame_type) {
            .headers, .continuation => {
                if (try hooks.header(connection, frame)) owned = false;
                continue;
            },
            else => {},
        }
        if (try hooks.connectionFrame(connection, frame.frame, deadline)) continue;
        if (frame.frame.header.frame_type == .goaway or frame.frame.header.stream_id == stream_id) {
            owned = false;
            return frame;
        }
        hooks.sibling(connection, frame) catch |err| {
            // This consumed frame cannot be replayed after queue failure.
            connection.aggregate_timeout_unusable = true;
            return err;
        };
        owned = false;
    }
}
