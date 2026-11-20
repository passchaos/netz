//! Tracked deadline output shared by HTTP/1 request and response writers.
const std = @import("std");
const runtime = @import("../runtime.zig");
const stream_io = @import("../../internal/stream_io.zig");

pub fn client(context: ?*anyopaque, parts: []const []const u8, committed: *usize, started: *bool, deadline: std.Io.Clock.Timestamp) runtime.Error!void {
    const owner: *runtime.Client = @ptrCast(@alignCast(context.?));
    return write(owner, parts, committed, started, deadline);
}

pub fn connection(context: ?*anyopaque, parts: []const []const u8, committed: *usize, started: *bool, deadline: std.Io.Clock.Timestamp) runtime.Error!void {
    const owner: *runtime.Connection = @ptrCast(@alignCast(context.?));
    return write(owner, parts, committed, started, deadline);
}

fn write(owner: anytype, parts: []const []const u8, committed: *usize, started: *bool, deadline: std.Io.Clock.Timestamp) runtime.Error!void {
    committed.* = 0;
    _ = try runtime.deadline_policy.usableAwake(owner.io, deadline);
    const transport = owner.transport();
    if (owner.limits.write_strategy == .flatten) {
        const bytes = try runtime.flattenWriteParts(owner.allocator, &owner.write_scratch, parts);
        started.* = true;
        return transport.writeAllWithDeadline(bytes, committed, deadline);
    }
    if (transport == .tcp) {
        started.* = true;
        return stream_io.writeAllSlicesTrackedWithDeadline(transport.tcp.io, transport.tcp.stream, parts, committed, deadline);
    }
    // TLS retains its own record-sized buffers and exact plaintext progress.
    // Borrow every part rather than joining an arbitrary body contribution.
    for (parts) |part| {
        if (part.len == 0) continue;
        var part_committed: usize = 0;
        started.* = true;
        transport.writeAllWithDeadline(part, &part_committed, deadline) catch |err| {
            committed.* += part_committed;
            return err;
        };
        committed.* += part_committed;
    }
}
