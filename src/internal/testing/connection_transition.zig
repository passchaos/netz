//! Expire a caller deadline after a real TCP connect wins the connect race.
const std = @import("std");
const net = std.Io.net;

/// The callback calls a public connection/Upgrade constructor and returns its
/// owned client or response. Observe one close and EOF, with no protocol bytes.
pub fn expectClosedAfterConnect(comptime connect_client: anytype) !void {
    return exercise(connect_client, true);
}

/// The callback first opens a stream directly, then calls its adoption API.
pub fn expectClosedAfterAdoption(comptime adopt_client: anytype) !void {
    return exercise(adopt_client, false);
}

fn exercise(comptime connect_client: anytype, comptime await_timer: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const parent = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(parent, .{});
    defer listener.deinit(parent);
    const Probe = struct {
        var base: std.Io = undefined;
        var expired: std.atomic.Value(bool) = .init(false);
        var socket: ?net.Socket = null;
        var after: std.Io.Timestamp = .zero;
        var timer: std.Io.Event = .unset;
        var timer_started: std.Io.Event = .unset;
        var closes: std.atomic.Value(usize) = .init(0);
        var writes: std.atomic.Value(usize) = .init(0);

        fn now(userdata: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
            if (clock == .awake and expired.load(.acquire)) return after;
            return base.vtable.now(userdata, clock);
        }

        fn connect(userdata: ?*anyopaque, address: *const net.IpAddress, options: net.IpAddress.ConnectOptions) net.IpAddress.ConnectError!net.Socket {
            // Start the timer's blocking wait before allowing the clock to
            // expire. Otherwise it could win selection and close the socket
            // itself, hiding a broken next owner behind correct race cleanup.
            if (await_timer) try timer_started.wait(base);
            const connected = try base.vtable.netConnectIp(userdata, address, options);
            socket = connected;
            expired.store(true, .release);
            return connected;
        }

        fn sleep(_: ?*anyopaque, _: std.Io.Timeout) std.Io.Cancelable!void {
            // The connected socket must win selection and reach its next owner.
            // The connect race joins this pending timer through cancellation.
            timer_started.set(base);
            try timer.wait(base);
        }

        fn close(userdata: ?*anyopaque, handles: []const net.Socket.Handle) void {
            for (handles) |handle| if (socket) |connected| {
                if (handle == connected.handle) _ = closes.fetchAdd(1, .monotonic);
            };
            base.vtable.netClose(userdata, handles);
        }

        fn write(userdata: ?*anyopaque, handle: net.Socket.Handle, header: []const u8, data: []const []const u8, splat: usize) net.Stream.Writer.Error!usize {
            _ = writes.fetchAdd(1, .monotonic);
            return base.vtable.netWrite(userdata, handle, header, data, splat);
        }
    };
    Probe.base = parent;
    Probe.socket = null;
    Probe.expired.store(false, .monotonic);
    Probe.closes.store(0, .monotonic);
    Probe.writes.store(0, .monotonic);
    Probe.timer = .unset;
    Probe.timer_started = .unset;
    // Rescue an unfixed constructor's leak so a failing test still cleans up.
    defer if (Probe.socket) |socket| {
        if (Probe.closes.load(.monotonic) == 0) socket.close(parent);
    };
    const deadline: std.Io.Clock.Timestamp = .fromNow(parent, .{ .raw = .fromSeconds(2), .clock = .awake });
    Probe.after = deadline.raw.addDuration(.fromSeconds(1));
    var table = parent.vtable.*;
    table.now = Probe.now;
    table.netConnectIp = Probe.connect;
    table.sleep = Probe.sleep;
    table.netClose = Probe.close;
    table.netWrite = Probe.write;
    const io: std.Io = .{ .userdata = parent.userdata, .vtable = &table };
    if (connect_client(allocator, io, listener.socket.address, deadline)) |value| {
        var client = value;
        if (@hasDecl(@TypeOf(client), "close")) client.close() else client.deinit(allocator);
        return error.TestExpectedError;
    } else |err| try std.testing.expectEqual(@as(anyerror, error.Timeout), err);
    try std.testing.expect(Probe.expired.load(.acquire));
    if (await_timer) try std.testing.expect(Probe.timer_started.isSet());
    try std.testing.expectEqual(@as(usize, 1), Probe.closes.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 0), Probe.writes.load(.monotonic));
    const peer = try listener.accept(parent);
    defer peer.close(parent);
    var byte: [1]u8 = undefined;
    var buffers = [_][]u8{&byte};
    try std.testing.expectEqual(@as(usize, 0), try parent.vtable.netRead(parent.userdata, peer.socket.handle, &buffers));
}
