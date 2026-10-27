//! Terminal TLS output is bounded and never retried. Bootstrap callers share
//! the GOAWAY cleanup deadline; established teardown supplies its own budget.
const std = @import("std");
const deadline_policy = @import("../../../internal/deadline.zig");

pub fn retire(transport: anytype) void {
    switch (transport) {
        .tcp => {},
        .tls_client => |connection| fail(connection),
        .tls_server => |connection| fail(connection),
    }
}

pub fn closeNotify(transport: anytype, before: ?std.Io.Clock.Timestamp) void {
    switch (transport) {
        .tcp => {},
        .tls_client => |connection| notify(connection, before),
        .tls_server => |connection| notify(connection, before),
    }
}

fn fail(connection: anytype) void {
    switch (connection.records) {
        inline else => |*records| records.failed = true,
    }
}

fn notify(connection: anytype, before: ?std.Io.Clock.Timestamp) void {
    // Even failed cleanup before any socket write must suppress the ordinary
    // destructor's unbounded close_notify attempt. Join cancellation first.
    defer fail(connection);
    const absolute = before orelse return;
    _ = deadline_policy.usableAwake(connection.io, absolute) catch return;
    switch (connection.records) {
        inline else => |*records| if (records.failed or records.pending_write_len != 0 or !records.shouldSendCloseNotify()) return,
    }
    const Wake = union(enum) { output: anyerror!void, timeout: std.Io.Cancelable!void };
    var storage: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(connection.io, &storage);
    defer select.cancelDiscard();
    select.concurrent(.output, @TypeOf(connection.*).sendCloseNotify, .{connection}) catch return;
    select.concurrent(.timeout, wait, .{ connection.io, absolute }) catch return;
    _ = select.await() catch return;
}

fn wait(io: std.Io, before: std.Io.Clock.Timestamp) std.Io.Cancelable!void {
    try before.wait(io);
}
