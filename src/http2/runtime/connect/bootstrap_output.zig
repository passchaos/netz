//! HTTP/2 connection-preface output under one optional handshake deadline.
const std = @import("std");
const http2 = @import("../../mod.zig");
const frame_io = @import("../frame/io.zig");

/// Send the client connection preface under the handshake deadline when one
/// exists. A null deadline preserves the unbounded legacy path.
pub fn writeClientPreface(
    transport: anytype,
    deadline: ?std.Io.Clock.Timestamp,
) !void {
    if (deadline) |absolute| {
        var committed: usize = 0;
        try transport.writeAllWithDeadline(
            http2.connection_preface,
            &committed,
            absolute,
        );
    } else {
        try transport.writeAll(http2.connection_preface);
    }
}

/// Write one bootstrap frame under the handshake deadline when one exists.
/// Bootstrap owns the transport on failure, so a partially committed frame is
/// terminal and does not need a resumable cursor outside this helper.
pub fn writeFrame(
    allocator: std.mem.Allocator,
    transport: anytype,
    frame_type: http2.FrameType,
    flags: u8,
    stream_id: u31,
    payload: []const u8,
    deadline: ?std.Io.Clock.Timestamp,
) !void {
    if (deadline) |absolute| {
        var committed: usize = 0;
        try frame_io.writeTransportWithDeadline(
            allocator,
            transport,
            frame_type,
            flags,
            stream_id,
            payload,
            &committed,
            absolute,
        );
    } else {
        try frame_io.writeTransport(
            allocator,
            transport,
            frame_type,
            flags,
            stream_id,
            payload,
        );
    }
}

pub fn writeSettings(
    allocator: std.mem.Allocator,
    transport: anytype,
    payload: []const u8,
    deadline: ?std.Io.Clock.Timestamp,
) !void {
    try writeFrame(
        allocator,
        transport,
        .settings,
        0,
        0,
        payload,
        deadline,
    );
}

pub fn writeConnectionWindow(
    allocator: std.mem.Allocator,
    transport: anytype,
    configured: u32,
    protocol_default: u32,
    deadline: ?std.Io.Clock.Timestamp,
) !void {
    if (configured == protocol_default) return;
    const increment: u31 = @intCast(configured - protocol_default);
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, increment, .big);
    try writeFrame(
        allocator,
        transport,
        .window_update,
        0,
        0,
        &payload,
        deadline,
    );
}
