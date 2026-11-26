//! Real socket probes for finite server task admission and joined teardown.
const std = @import("std");
const allocator = std.testing.allocator;
const net = std.Io.net;

const Probe = struct {
    backend: std.Io.Threaded,
    table: std.Io.VTable = undefined,
    watched: [2]?net.Socket.Handle = .{ null, null },
    second_read_started: std.atomic.Value(bool) = .init(false),
    read_entered: std.Io.Event = .unset,
    second_read_entered: std.Io.Event = .unset,
    read_finished: std.atomic.Value(bool) = .init(false),
    second_read_finished: std.atomic.Value(bool) = .init(false),
    closes: [2]std.atomic.Value(usize) = .{ .init(0), .init(0) },

    fn io(self: *@This()) std.Io {
        const base = self.backend.io();
        self.table = base.vtable.*;
        self.table.netRead = read;
        self.table.netClose = close;
        return .{ .userdata = base.userdata, .vtable = &self.table };
    }

    fn from(userdata: ?*anyopaque) *@This() {
        const backend: *std.Io.Threaded = @ptrCast(@alignCast(userdata.?));
        return @fieldParentPtr("backend", backend);
    }

    fn read(userdata: ?*anyopaque, handle: net.Socket.Handle, buffers: [][]u8) net.Stream.Reader.Error!usize {
        const self = from(userdata);
        const base = self.backend.io();
        const watched = self.watched[0] == handle;
        const second = self.watched[1] == handle;
        if (second) {
            self.second_read_started.store(true, .release);
            self.second_read_entered.set(base);
        }
        if (watched) self.read_entered.set(base);
        defer if (watched) self.read_finished.store(true, .release);
        defer if (second) self.second_read_finished.store(true, .release);
        return base.vtable.netRead(base.userdata, handle, buffers);
    }

    fn close(userdata: ?*anyopaque, handles: []const net.Socket.Handle) void {
        const self = from(userdata);
        for (handles) |handle| {
            for (self.watched, 0..) |watched, index| {
                if (watched == handle) {
                    _ = self.closes[index].fetchAdd(1, .monotonic);
                    break;
                }
            }
        }
        const base = self.backend.io();
        base.vtable.netClose(base.userdata, handles);
    }
};

pub const Scenario = enum { accept_failure, initial_admission_failure, partial_admission_failure, await_cancellation };

pub fn exercise(comptime websocket: bool, comptime scenario: Scenario) !void {
    const runtime = if (websocket) @import("../../websocket/runtime.zig") else @import("../../http1/runtime.zig");
    var probe: Probe = .{ .backend = .init(allocator, .{
        .async_limit = .nothing,
        .concurrent_limit = switch (scenario) {
            .accept_failure, .await_cancellation => .unlimited,
            .initial_admission_failure => .nothing,
            .partial_admission_failure => .limited(1),
        },
    }) };
    defer probe.backend.deinit();
    const io = probe.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const peer = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer peer.close(io);
    const accepted = try listener.accept(io);
    var accepted_owned = true;
    defer if (accepted_owned) accepted.close(io);
    probe.watched[0] = accepted.socket.handle;
    var second_peer: ?net.Stream = null;
    defer if (second_peer) |stream| stream.close(io);
    const second_accepted: ?net.Stream = if (scenario == .partial_admission_failure or scenario == .await_cancellation) second: {
        second_peer = try listener.socket.address.connect(io, .{ .mode = .stream });
        const stream = try listener.accept(io);
        probe.watched[1] = stream.socket.handle;
        break :second stream;
    } else null;

    const Server = struct {
        first: ?runtime.Connection,
        second: ?runtime.Connection = null,
        probe: *Probe,
        accepts: usize = 0,
        pub const accept = if (websocket) acceptWebsocket else acceptHttp1;

        fn acceptHttp1(self: *@This()) runtime.Error!runtime.Connection {
            return self.next();
        }
        fn acceptWebsocket(self: *@This(), _: runtime.AcceptOptions) runtime.Error!runtime.Connection {
            return self.next();
        }
        fn next(self: *@This()) runtime.Error!runtime.Connection {
            self.accepts += 1;
            if (self.first) |connection| {
                self.first = null;
                return connection;
            }
            // Fail only after the first worker actually enters socket read.
            self.probe.read_entered.waitTimeout(self.probe.backend.io(), .{ .duration = .{
                .clock = .awake,
                .raw = .fromSeconds(2),
            } }) catch return error.ConnectionClosed;
            if (self.second) |connection| {
                self.second = null;
                return connection;
            }
            return error.ConnectionClosed;
        }
    };
    var server: Server = .{ .first = if (websocket)
        .{ .io = io, .allocator = allocator, .stream = accepted, .role = .server }
    else
        .{ .io = io, .allocator = allocator, .stream = accepted }, .probe = &probe };
    if (second_accepted) |stream| server.second = if (websocket)
        .{ .io = io, .allocator = allocator, .stream = stream, .role = .server }
    else
        .{ .io = io, .allocator = allocator, .stream = stream };
    defer if (server.first) |*connection| connection.close();
    defer if (server.second) |*connection| connection.close();
    accepted_owned = false;
    const Context = if (websocket) struct {
        fn handle(_: *@This(), connection: *runtime.Connection) runtime.Error!void {
            var frame = try connection.receiveFrame();
            defer frame.deinit(connection.allocator);
        }
    } else struct {
        fn handle(_: *@This(), _: @import("../../http1/mod.zig").Request) runtime.Error!runtime.ResponseOptions {
            return .{ .body = "unused" };
        }
    };
    var context: Context = .{};
    const Work = struct {
        server: *Server,
        context: *Context,
        serving_io: std.Io,
        result: ?runtime.AsyncServeError!runtime.ConcurrentServeResult = null,

        fn run(self: *@This()) void {
            self.result = if (websocket)
                runtime.serveAcceptedConcurrent(Server, self.server, self.serving_io, allocator, Context, self.context, Context.handle, 2, .{})
            else
                runtime.serveAcceptedConcurrent(Server, self.server, self.serving_io, allocator, Context, self.context, Context.handle, 2);
        }
    };
    var work: Work = .{ .server = &server, .context = &context, .serving_io = io };
    if (scenario == .await_cancellation) {
        const base = probe.backend.io();
        var serving = try std.Io.concurrent(base, Work.run, .{&work});
        defer serving.cancel(base);
        try probe.second_read_entered.waitTimeout(base, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(2) } });
        serving.cancel(base);
    } else Work.run(&work);
    defer if (work.result.?) |success| {
        var owned = success;
        owned.deinit();
    } else |_| {};
    try std.testing.expectError(switch (scenario) {
        .accept_failure => error.ConnectionClosed,
        .initial_admission_failure, .partial_admission_failure => error.ConcurrencyUnavailable,
        .await_cancellation => error.Canceled,
    }, work.result.?);
    try std.testing.expectEqual(@as(usize, if (scenario == .initial_admission_failure) 1 else 2), server.accepts);
    try std.testing.expectEqual(scenario != .initial_admission_failure, probe.read_entered.isSet());
    try std.testing.expectEqual(scenario != .initial_admission_failure, probe.read_finished.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), probe.closes[0].load(.acquire));
    try std.testing.expectEqual(@as(usize, if (second_accepted != null) 1 else 0), probe.closes[1].load(.acquire));
    try std.testing.expectEqual(scenario == .await_cancellation, probe.second_read_started.load(.acquire));
    try std.testing.expectEqual(scenario == .await_cancellation, probe.second_read_finished.load(.acquire));
}
