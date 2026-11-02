//! Transfer-on-entry socket admission for listener managers.
const std = @import("std");
const runtime = @import("../../runtime.zig");
const deadline_policy = @import("../../../internal/deadline.zig");

/// The callback owns the stream after validation, on both success and failure.
pub fn accept(server: anytype, stream: std.Io.net.Stream, deadline: std.Io.Clock.Timestamp, comptime handshake: anytype) runtime.Error!runtime.Connection {
    _ = deadline_policy.usableAwake(server.io, deadline) catch |err| {
        stream.close(server.io);
        return err;
    };
    server.io.checkCancel() catch |err| {
        stream.close(server.io);
        return err;
    };
    return handshake(server, stream, deadline);
}

test "HTTP/2 owned stream admission closes transports on validation cancellation and handshake failure" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    const Mode = enum { expired, wrong_clock, canceled, handshake_failure };
    const Server = struct {
        io: std.Io,
        calls: usize = 0,
        fn check(_: ?*anyopaque) std.Io.Cancelable!void {
            return error.Canceled;
        }
        fn handshake(self: *@This(), stream: std.Io.net.Stream, deadline: ?std.Io.Clock.Timestamp) runtime.Error!runtime.Connection {
            self.calls += 1;
            std.debug.assert(deadline != null);
            stream.close(self.io);
            return error.InvalidFrame;
        }
    };
    for (std.enums.values(Mode)) |mode| {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(base, .{});
        defer listener.deinit(base);
        const peer = try listener.socket.address.connect(base, .{ .mode = .stream });
        defer peer.close(base);
        const stream = try listener.accept(base);
        var table = base.vtable.*;
        if (mode == .canceled) table.checkCancel = Server.check;
        var server = Server{ .io = .{ .userdata = base.userdata, .vtable = &table } };
        const deadline: std.Io.Clock.Timestamp = switch (mode) {
            .expired => .fromNow(base, .{ .clock = .awake, .raw = .fromNanoseconds(-1) }),
            .wrong_clock => .{ .clock = .real, .raw = .zero },
            else => .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) }),
        };
        const expected = switch (mode) {
            .expired, .wrong_clock => error.Timeout,
            .canceled => error.Canceled,
            .handshake_failure => error.InvalidFrame,
        };
        try std.testing.expectError(expected, accept(&server, stream, deadline, Server.handshake));
        try std.testing.expectEqual(@as(usize, if (mode == .handshake_failure) 1 else 0), server.calls);
        var buffer: [1]u8 = undefined;
        const n = try @import("../../../internal/stream_io.zig").readSomeWithDeadline(base, peer, &buffer, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) }));
        try std.testing.expectEqual(@as(usize, 0), n);
    }
}
