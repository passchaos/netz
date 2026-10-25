//! Drain zero-content DATA for HEAD/204/304 while preserving shared state.
const std = @import("std");
const http2 = @import("../../mod.zig");
const credit = @import("../flow/credit.zig");

pub fn consume(connection: anytype, id: u31, deadline: ?std.Io.Clock.Timestamp, comptime Hooks: anytype) Hooks.ErrorType!void {
    var held: credit.Tracker = .{};
    errdefer Hooks.releaseCapacity(connection, held.unreleased_connection_bytes);
    while (true) {
        var frame = try Hooks.readFrame(connection, deadline);
        defer frame.deinit(connection.allocator);
        if (try Hooks.handleConnection(connection, frame.frame, deadline)) continue;
        if (frame.frame.header.frame_type == .goaway) {
            try Hooks.goAway(connection, id, try http2.GoAwayPayload.parse(frame.frame));
            continue;
        }
        if (frame.frame.header.stream_id != id) return error.UnexpectedFrame;
        switch (frame.frame.header.frame_type) {
            .data => {
                const before = connection.recv_connection_window.value;
                const data = try Hooks.receive(connection, id, frame.frame);
                defer held.observe(before, connection.recv_connection_window.value, data.adaptive_connection_increment);
                defer Hooks.releaseBudget(connection, data);
                if (data.data.len != 0) {
                    Hooks.releaseCapacity(connection, frame.frame.payload.len);
                    Hooks.reject(connection, id, .protocol_error);
                    return error.InvalidContentLength;
                }
                const ended = (frame.frame.header.flags & 1) != 0;
                // The application sees no content and therefore cannot return
                // padding credit. Restore the entire payload immediately; FIN
                // needs only connection credit because that receive half ends.
                if (frame.frame.payload.len != 0) {
                    const amount: u31 = @intCast(frame.frame.payload.len);
                    Hooks.refund(connection, id, amount, if (ended) null else amount, deadline) catch |err| {
                        connection.aggregate_timeout_unusable = true;
                        connection.terminal_write_failed = true;
                        Hooks.fail(connection, id);
                        return @as(Hooks.ErrorType!void, err);
                    };
                }
                if (ended) return;
            },
            .headers => {
                // Message semantics cannot bypass connection-wide HPACK
                // updates, even when every trailer is forbidden here.
                const fields = try Hooks.readHeaders(connection, frame.frame, deadline);
                defer Hooks.freeHeaders(connection.allocator, fields);
                Hooks.reject(connection, id, .protocol_error);
                return error.InvalidContentLength;
            },
            .rst_stream => {
                try Hooks.recordReset(connection, try http2.ResetStreamPayload.parse(frame.frame));
                return error.StreamReset;
            },
            else => return error.UnexpectedFrame,
        }
    }
}
