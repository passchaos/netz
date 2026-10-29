const std = @import("std");
const grpc = @import("../../../../mod.zig");
const shared = @import("../../../shared.zig");
const stream = @import("../../stream.zig");
const Wake = @import("../../wake.zig").Wake;

test "gRPC shared duplex request cancellation and destruction do not join state or retirement" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    var channel = try shared.SharedChannel.init(std.testing.allocator, base, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    var sender = channel.sender();
    defer sender.deinit();
    channel.deinit();
    const state = sender.state;
    const State = @TypeOf(state.*);
    state.closed = false;
    defer state.closed = true;
    const references = state.refs.load(.acquire);
    const call = try State.StreamCall.create(state, .{ .path = "/svc/Bidi" }, null);
    call.retain(); // Synthetic endpoint ownership after admission.
    const wake = try Wake.create(std.testing.allocator);
    call.setOwnerWake(wake);
    wake.release(); // The call now keeps the endpoint wake storage alive.

    const Probe = struct {
        base: std.Io,
        mutex: *std.Io.Mutex,
        retired: *std.Io.Event,
        lock_waits: usize = 0,
        retirement_waits: usize = 0,
        var active: ?*@This() = null;
        fn waitUncancelable(userdata: ?*anyopaque, pointer: *const u32, expected: u32) void {
            const self = active.?;
            const mutex: *const u32 = @ptrCast(&self.mutex.state.raw);
            const retired: *const u32 = @ptrCast(self.retired);
            if (pointer == mutex) {
                self.lock_waits += 1;
                self.mutex.state.store(.unlocked, .release);
            } else if (pointer == retired) {
                self.retirement_waits += 1;
                self.retired.set(self.base);
            } else self.base.vtable.futexWaitUncancelable(userdata, pointer, expected);
        }
    };
    var probe = Probe{ .base = base, .mutex = &state.mutex, .retired = &call.retired_event };
    var table = base.vtable.*;
    table.futexWaitUncancelable = Probe.waitUncancelable;
    Probe.active = &probe;
    state.io = .{ .userdata = base.userdata, .vtable = &table };
    state.mutex.lockUncancelable(base);
    var rpc = stream.Duplex{ .call = call };
    rpc.requestCancel();
    try std.testing.expect(call.cancel_requested.load(.acquire));
    try std.testing.expect(wake.event.isSet());
    try std.testing.expectError(error.Timeout, rpc.cancelWithTimeout(.fromMilliseconds(1)));
    rpc.deinit();
    try std.testing.expectEqual(@as(usize, 0), probe.lock_waits);
    try std.testing.expectEqual(@as(usize, 0), probe.retirement_waits);
    try std.testing.expect(!state.mutex.tryLock());

    state.io = base;
    Probe.active = null;
    state.mutex.unlock(base);
    state.lock();
    call.retireLocked(error.Canceled);
    state.unlock();
    call.release();
    try std.testing.expectEqual(references, state.refs.load(.acquire));
}

test "gRPC shared duplex asynchronous cancellation preserves connection ordering" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var admitted: std.Io.Event = .unset;
    const Peer = struct {
        fn consume(_: void, message: grpc.StreamingMessage) !void {
            try std.testing.expectEqualStrings("held", message.payload);
        }
        fn run(server_ptr: *grpc.runtime.Server, signal: *std.Io.Event) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            {
                var rpc = try connection.acceptDuplexWithTimeout(.fromSeconds(5));
                defer rpc.deinit();
                while (true) {
                    var event = try rpc.readRequestEventWithTimeout(.fromSeconds(5), {}, consume);
                    defer event.deinit();
                    if (event == .messages and event.messages.count != 0) break;
                }
                signal.set(connection.connection.io);
                var reset = try rpc.readRequestEventWithTimeout(.fromSeconds(5), {}, consume);
                defer reset.deinit();
                try std.testing.expect(reset == .reset);
                try std.testing.expectEqual(@import("../../../../../http2/mod.zig").ErrorCode.cancel, reset.reset.error_code);
            }
            var request = try connection.readUnaryWithTimeout(.fromSeconds(5));
            defer request.deinit();
            try connection.writeUnary(request.request.stream_id, .{ .message = "reused" });
        }
    };
    var peer = io.async(Peer.run, .{ &server, &admitted });
    defer _ = peer.cancel(io) catch {};
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address(), .limits = .{ .terminal_cleanup_timeout = .fromSeconds(1) } } }, .{});
    defer client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var rpc = try sender.startDuplex(.{ .path = "/demo.Shared/Bidi", .timeout = .{ .value = 5, .unit = .second }, .wait_for_ready = true });
    defer rpc.deinit();
    var writer = rpc.writer();
    defer writer.deinit();
    try writer.writeMessage("held");
    try admitted.waitTimeout(io, .{ .deadline = .fromNow(io, .{ .raw = .fromSeconds(5), .clock = .awake }) });
    rpc.requestCancel();
    try std.testing.expectError(error.Canceled, writer.writeMessage("after-cancel"));
    var reply = try sender.unary(.{ .path = "/demo.Shared/Unary", .message = "next", .timeout = .{ .value = 5, .unit = .second } });
    defer reply.deinit();
    try std.testing.expectEqualStrings("reused", reply.message.?.payload);
    try peer.await(io);
}
