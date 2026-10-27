//! Client duplex handles share a single connection owner. Handle-local
//! registration releases the shared count once; stream IDs route input even
//! when the owning handle moves.
const std = @import("std");

pub const Owners = struct {
    value: usize = 0,

    pub fn acquire(self: *Owners) void {
        self.value += 1;
    }

    pub fn release(self: *Owners) void {
        std.debug.assert(self.value != 0);
        self.value -= 1;
    }

    pub fn count(self: *const Owners) usize {
        return self.value;
    }
};

pub fn queuedIndex(frames: anytype, start: usize, stream_id: u31) ?usize {
    for (frames[start..], start..) |frame, index| {
        if (frame.frame.header.stream_id == stream_id) return index;
    }
    return null;
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
        try hooks.discardCanceled(connection, deadline);
        if (hooks.peek(connection, stream_id)) |queued| {
            if (queued.header.frame_type != .headers or hooks.decoded(connection, queued)) {
                return hooks.pop(connection, stream_id).?;
            }
        }
        var frame = try hooks.readWire(connection, deadline);
        var owned = true;
        defer if (owned) frame.deinit(connection.allocator);
        try hooks.sequence(connection, frame.frame, deadline);
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
