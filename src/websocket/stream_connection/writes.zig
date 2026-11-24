//! Complete-write callbacks cannot report a safely resumable byte cursor.
//! Resolve capabilities and deadlines before invocation; an invoked callback
//! error retires the transport because its wire prefix is unknown.

const std = @import("std");
const deadline_policy = @import("../../internal/deadline.zig");

fn invoke(connection: anytype, callback: anytype, args: anytype) anyerror!void {
    @call(.auto, callback, args) catch |err| {
        connection.abort();
        return err;
    };
}

pub fn all(connection: anytype, bytes: []const u8, deadline: ?std.Io.Clock.Timestamp) !void {
    const transport = connection.transport;
    if (deadline) |until| {
        _ = try deadline_policy.usableAwake(connection.io, until);
        const callback = transport.write_deadline_fn orelse return error.DeadlineUnsupported;
        return invoke(connection, callback, .{ transport.context, bytes, until });
    }
    return invoke(connection, transport.write_fn, .{ transport.context, bytes });
}

pub fn parts(connection: anytype, header: []const u8, payload: []const u8, deadline: ?std.Io.Clock.Timestamp) !void {
    const transport = connection.transport;
    if (deadline) |until| {
        _ = try deadline_policy.usableAwake(connection.io, until);
        const callback = transport.write_parts_deadline_fn orelse return error.DeadlineUnsupported;
        return invoke(connection, callback, .{ transport.context, header, payload, until });
    }
    const callback = transport.write_parts_fn orelse return error.PartsUnsupported;
    return invoke(connection, callback, .{ transport.context, header, payload });
}

pub fn slices(connection: anytype, header: []const u8, payloads: []const []const u8, deadline: ?std.Io.Clock.Timestamp) !void {
    const transport = connection.transport;
    if (deadline) |until| {
        _ = try deadline_policy.usableAwake(connection.io, until);
        const callback = transport.write_slices_deadline_fn orelse return error.DeadlineUnsupported;
        return invoke(connection, callback, .{ transport.context, header, payloads, until });
    }
    const callback = transport.write_slices_fn orelse return error.PartsUnsupported;
    return invoke(connection, callback, .{ transport.context, header, payloads });
}
