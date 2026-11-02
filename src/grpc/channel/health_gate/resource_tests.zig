const std = @import("std");
const grpc = @import("../../mod.zig");
const http2 = @import("../../../http2/mod.zig");
const stream_io = @import("../../../internal/stream_io.zig");
const faults_module = @import("testing/resource_faults.zig");
const Faults = faults_module.Faults;
const Kind = faults_module.Kind;
const allocator = std.testing.allocator;

test "ordinary Channel health gate backs off persistent allocation failure and recovers" {
    try exercise(.memory, false);
}

test "ordinary Channel health gate backs off executor admission failure and recovers" {
    try exercise(.executor, false);
}

test "ordinary Channel health gate shutdown cancels resource backoff and releases its connection" {
    try exercise(.memory, true);
    try exercise(.executor, true);
}

fn wait(event: *std.Io.Event, io: std.Io) !void {
    try event.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(4) } });
}

fn exercise(kind: Kind, cancel: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, base, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    const Peer = struct {
        fn connect(context: ?*anyopaque, gpa: std.mem.Allocator, io: std.Io, deadline: std.Io.Clock.Timestamp) http2.runtime.Error!http2.runtime.Connection {
            const fault: *Faults = @ptrCast(@alignCast(context.?));
            _ = fault.owner_thread.cmpxchgStrong(0, std.Thread.getCurrentId(), .acq_rel, .acquire);
            if (fault.kind == .executor and fault.enabled.load(.acquire)) {
                _ = fault.hits.fetchAdd(1, .acq_rel);
                return error.ConcurrencyUnavailable;
            }
            return http2.runtime.Client.connectWithDeadline(gpa, io, fault.address, .{}, deadline);
        }
        fn consume(_: void, message: grpc.StreamingMessage) !void {
            try std.testing.expectEqualStrings("demo.Echo", (try grpc.health.decodeRequest(message.payload)).service);
        }
        fn run(listener: *grpc.runtime.Server, canceled: bool, fault: *Faults) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(4));
            var owned = true;
            defer if (owned) connection.deinit();
            var first = try connection.readStreamingWithTimeout(.fromSeconds(4), {}, consume);
            defer first.deinit();
            try std.testing.expectEqualStrings(grpc.health.watch_path, first.path);
            fault.first_failed.store(true, .release);
            // Retire this connection before the terminal Watch response so
            // the next attempt enters the connector's admission contract.
            try connection.connection.sendGoAway(first.transport.stream_id, .no_error, "");
            try connection.writeUnary(first.transport.stream_id, .{ .status = .unavailable, .trailers_only = true });
            if (canceled) {
                // Observe physical TCP closure independently of the HTTP/2
                // connection's local GOAWAY/accept retirement state.
                var buffer: [256]u8 = undefined;
                const until: std.Io.Clock.Timestamp = .fromNow(fault.base, .{ .clock = .awake, .raw = .fromSeconds(4) });
                while (true) {
                    const count = stream_io.readSomeWithDeadline(fault.base, connection.connection.stream, &buffer, until) catch |err| switch (err) {
                        error.ConnectionResetByPeer, error.SocketUnconnected => return,
                        else => return err,
                    };
                    if (count == 0) return;
                }
            }
            var recovered = while (true) {
                const request = connection.readStreamingWithTimeout(.fromSeconds(8), {}, consume) catch |err| switch (err) {
                    error.ConnectionClosed, error.ConnectionResetByPeer, error.SocketUnconnected => {
                        connection.deinit();
                        owned = false;
                        connection = try listener.acceptWithTimeout(.fromSeconds(8));
                        owned = true;
                        continue;
                    },
                    else => return err,
                };
                break request;
            };
            defer recovered.deinit();
            try std.testing.expectEqualStrings(grpc.health.watch_path, recovered.path);
            var writer = try connection.startStreamingResponse(recovered.transport.stream_id, .{});
            defer writer.deinit();
            const message = try grpc.health.encodeResponseAlloc(allocator, .{ .status = .serving });
            defer allocator.free(message);
            try writer.writeMessage(message);
            var application = try listener.acceptWithTimeout(.fromSeconds(4));
            defer application.deinit();
            var request = try application.readUnaryWithTimeout(.fromSeconds(4));
            defer request.deinit();
            try std.testing.expectEqualStrings("ping", request.request.message.payload);
            try application.writeUnary(request.transport.stream_id, .{ .message = "pong" });
            try writer.finishWithOptions(.{ .status = .unimplemented });
        }
    };
    var faults = Faults{ .kind = kind, .base = base, .address = server.address() };
    Faults.active = &faults;
    defer Faults.active = null;
    var table = base.vtable.*;
    table.sleep = Faults.sleep;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &table };
    var peer = try base.concurrent(Peer.run, .{ &server, cancel, &faults });
    defer _ = peer.cancel(base) catch {};
    var channel = try grpc.Channel.init(faults.allocator(), io, .{ .custom = .{ .context = &faults, .connect_fn = Peer.connect } }, .{ .health_check_service = "demo.Echo" });
    var live = true;
    defer if (live) channel.deinit();
    try wait(&faults.rpc_entered, base);
    const until: std.Io.Clock.Timestamp = .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(4) });
    while (true) {
        const generation = channel.health_sync.?.snapshot();
        if (channel.healthServingAt(0) == false) break;
        if (until.durationFromNow(base).raw.nanoseconds <= 0) return error.Timeout;
        try channel.health_sync.?.wait(base, generation, until);
    }
    faults.enabled.store(true, .release);
    faults.rpc_permitted.set(base);
    try wait(&faults.local_entered[0], base);
    const failed = faults.hits.load(.acquire);
    try std.testing.expect(failed > 0);
    try std.testing.expectEqual(@as(?bool, false), channel.healthServingAt(0));
    try std.Io.sleep(base, .fromMilliseconds(20), .awake);
    try std.testing.expectEqual(failed, faults.hits.load(.acquire));
    if (cancel) {
        channel.deinit();
        live = false;
        try peer.await(base);
        return;
    }
    if (kind == .memory) {
        faults.local_permitted[0].set(base);
        try wait(&faults.local_entered[1], base);
        try std.testing.expect(faults.hits.load(.acquire) > failed);
        try std.testing.expect(faults.delays_ns[1] > faults.delays_ns[0]);
        try std.testing.expectEqual(@as(?bool, false), channel.healthServingAt(0));
    }
    faults.enabled.store(false, .release);
    faults.local_permitted[if (kind == .memory) 1 else 0].set(base);
    var response = try channel.unary(.{ .path = "/demo.Echo/Unary", .message = "ping", .wait_for_ready = true, .timeout = .{ .value = 4, .unit = .second } });
    defer response.deinit();
    try std.testing.expectEqualStrings("pong", response.message.?.payload);
    try std.testing.expectEqual(@as(?bool, true), channel.healthServingAt(0));
    try peer.await(base);
}
