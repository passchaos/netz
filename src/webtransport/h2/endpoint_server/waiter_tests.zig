const std = @import("std");
const endpoint = @import("../endpoint_server.zig");
const Fixture = @import("../../../http2/runtime/duplex/testing.zig").Fixture;
const allocator = std.testing.allocator;

test "WebTransport HTTP2 EndpointServer request waiters have independent capacity and cancellation releases it" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try Fixture.init(io);
    defer {
        fixture.peer.close(io);
        fixture.listener.deinit(io);
    }
    fixture.connection.role = .server;
    var server = try endpoint.EndpointServer.init(allocator, fixture.connection, .{ .max_queued_commands = 1, .max_request_waiters = 1 });
    defer server.deinit();
    const Receiver = struct {
        fn run(value: endpoint.EndpointServer) !endpoint.PendingRequest {
            return value.receiveRequestWithTimeout(.fromSeconds(30));
        }
    };
    var receiver = try io.concurrent(Receiver.run, .{server});
    defer {
        var unexpected = receiver.cancel(io) catch null;
        if (unexpected) |*request| request.deinit();
    }
    const until: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    while (true) {
        server.state.mutex.lockUncancelable(io);
        const waiting = server.state.receive_head != null;
        server.state.mutex.unlock(io);
        if (waiting) break;
        if (until.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try std.testing.expectError(error.RequestWaiterCapacity, server.receiveRequestWithTimeout(.fromMilliseconds(50)));
    // Pending request reception does not consume Session command capacity.
    try std.testing.expectError(error.StaleSession, server.openStreamWithTimeout(.{ .index = 0, .generation = 1 }, .bidirectional, .fromSeconds(1)));
    try std.testing.expectError(error.Canceled, receiver.cancel(io));
    // An admission pass reclaims the abandoned waiter even before the owner
    // has had a chance to process its cancellation wake.
    try std.testing.expectError(error.StaleSession, server.openStreamWithTimeout(.{ .index = 0, .generation = 1 }, .bidirectional, .fromSeconds(1)));
    try std.testing.expectError(error.Timeout, server.receiveRequestWithTimeout(.fromMilliseconds(10)));
    try std.testing.expectError(error.StaleSession, server.openStreamWithTimeout(.{ .index = 0, .generation = 1 }, .bidirectional, .fromSeconds(1)));
    server.state.mutex.lockUncancelable(io);
    defer server.state.mutex.unlock(io);
    try std.testing.expectEqual(@as(usize, 0), server.state.waiting_requests);
    try std.testing.expect(server.state.receive_head == null and server.state.receive_tail == null);
}

test "WebTransport HTTP2 EndpointServer expires request waiter reservations before new admission" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try Fixture.init(io);
    defer {
        fixture.peer.close(io);
        fixture.listener.deinit(io);
    }
    fixture.connection.role = .server;
    var server = try endpoint.EndpointServer.init(allocator, fixture.connection, .{ .max_request_waiters = 1 });
    defer server.deinit();
    try std.testing.expectError(error.InvalidEndpointOptions, (endpoint.Options{ .max_request_waiters = 0 }).validate());
    const State = @TypeOf(server.state.*);
    const expired = try State.Job.create(server.state, .receive_request, .fromNow(io, .{ .clock = .awake, .raw = .fromNanoseconds(-1) }));
    defer expired.release();
    server.state.mutex.lockUncancelable(io);
    expired.retain();
    expired.waiting_request = true;
    server.state.waiting_requests = 1;
    server.state.receive_head = expired;
    server.state.receive_tail = expired;
    server.state.mutex.unlock(io);
    try std.testing.expectError(error.StaleSession, server.openStreamWithTimeout(.{ .index = 0, .generation = 1 }, .bidirectional, .fromSeconds(1)));
    try std.testing.expectEqual(@as(?anyerror, error.Timeout), expired.err);
    server.state.mutex.lockUncancelable(io);
    defer server.state.mutex.unlock(io);
    try std.testing.expectEqual(@as(usize, 0), server.state.waiting_requests);
    try std.testing.expect(!expired.waiting_request);
    try std.testing.expectEqual(@as(usize, 1), expired.refs.load(.acquire));
}

test "WebTransport HTTP2 EndpointServer owner rejects stale queued work by deadline before lookup" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try Fixture.init(io);
    defer {
        fixture.peer.close(io);
        fixture.listener.deinit(io);
    }
    fixture.connection.role = .server;
    var server = try endpoint.EndpointServer.init(allocator, fixture.connection, .{});
    defer server.deinit();
    const State = @TypeOf(server.state.*);
    const job = try State.Job.create(server.state, .{ .accept = .{ .handle = .{ .index = 0, .generation = 1 }, .options = .{} } }, .fromNow(io, .{ .clock = .awake, .raw = .fromNanoseconds(-1) }));
    defer job.release();
    server.state.mutex.lockUncancelable(io);
    job.retain();
    server.state.head = job;
    server.state.tail = job;
    server.state.queued = 1;
    server.state.wake.set(io);
    server.state.mutex.unlock(io);
    try job.done.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
    try std.testing.expectEqual(@as(?anyerror, error.Timeout), job.err);
}
