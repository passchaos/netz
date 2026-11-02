//! Policy drops are pre-wire, non-retryable and transactionally updateable.
const std = @import("std");
const grpc = @import("../mod.zig");
const shared = @import("shared.zig");
const drop = @import("drop_policy.zig");
const fixture = @import("../xds/eds/testing.zig");
const eds = @import("../xds/eds.zig");
const allocator = std.testing.allocator;
const categories = [_]drop.Category{.{ .category = "overload", .requests_per_million = 1000000 }};
fn retry() grpc.RetryPolicy {
    return .{ .max_attempts = 5, .initial_backoff = .fromMilliseconds(1), .max_backoff = .fromMilliseconds(1), .backoff_multiplier = 1, .retryable_status_codes = &.{.unavailable} };
}
fn expectDrop(response: *grpc.UnaryResponse) !void {
    try std.testing.expectEqual(grpc.Status.unavailable, response.status);
    try std.testing.expect(response.was_dropped and response.transport == null and response.message == null);
    try std.testing.expectEqualStrings("EDS-configured drop: overload", response.status_message);
}

test "gRPC drop policy ordinary and shared unary stop retry hedging and pre-wire streaming" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const Refused = struct {
        count: std.atomic.Value(usize) = .init(0),
        fn connect(context: ?*anyopaque, _: std.mem.Allocator, _: std.Io, _: std.Io.Clock.Timestamp) @import("../../http2/mod.zig").runtime.Error!@import("../../http2/mod.zig").runtime.Connection {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            _ = self.count.fetchAdd(1, .monotonic);
            return error.ConnectionRefused;
        }
    };
    var refused: Refused = .{};
    const target: grpc.ChannelTarget = .{ .custom = .{ .context = &refused, .connect_fn = Refused.connect } };
    var ordinary = try grpc.Channel.init(allocator, io, target, .{ .drop_categories = &categories });
    defer ordinary.deinit();
    try std.testing.expectEqual(grpc.ChannelConnectivityState.ready, ordinary.connectivityState());
    const options: grpc.call.UnaryCallOptions = .{ .path = "/demo.Drop/Unary", .message = "request", .timeout = .{ .value = 2, .unit = .second }, .wait_for_ready = true };
    var throttler = try grpc.call.RetryThrottler.init(10, 1);
    var retry_policy = retry();
    retry_policy.throttler = &throttler;
    var result = try ordinary.unaryWithRetry(options, retry_policy);
    defer result.deinit();
    try expectDrop(&result);
    try std.testing.expectEqual(@as(usize, 0), refused.count.load(.acquire));
    try std.testing.expectEqual(drop.Stats{ .evaluated = 1, .dropped = 1 }, ordinary.dropStats());
    try std.testing.expectError(error.CallDropped, ordinary.startDuplex(.{ .path = "/demo.Drop/Duplex", .timeout = .{ .value = 2, .unit = .second } }));
    var client = try shared.SharedChannel.init(allocator, io, target, .{ .channel = .{ .drop_categories = &categories } });
    defer client.deinit();
    try std.testing.expectEqual(grpc.ChannelConnectivityState.ready, client.connectivityState());
    var sender = client.sender();
    defer sender.deinit();
    var retried = try sender.unaryWithRetry(options, retry_policy);
    defer retried.deinit();
    try expectDrop(&retried);
    var hedged = try sender.unaryWithHedging(options, .{ .max_attempts = 5, .hedging_delay = .fromSeconds(1), .non_fatal_status_codes = &.{.unavailable} });
    defer hedged.deinit();
    try expectDrop(&hedged);
    try std.testing.expectEqual(@as(u64, 2), client.dropStats().dropped);
    try std.testing.expectEqual(throttler.max_milli_tokens, throttler.milli_tokens.load(.acquire));
    try std.testing.expectEqual(@as(u64, 1), client.hedgingStats().attempts_started);
    try std.testing.expectError(error.CallDropped, sender.startDuplex(.{ .path = "/demo.Drop/Duplex", .timeout = .{ .value = 2, .unit = .second } }));
    try std.testing.expectEqual(@as(usize, 0), client.state.queued);
}

test "gRPC drop policy full EDS rejection works without endpoints and updates atomically" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var client = try shared.SharedChannel.init(failing.allocator(), io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    const bytes = try fixture.encode(allocator, "empty", &.{}, categories[0]);
    defer allocator.free(bytes);
    const snapshot = try eds.Snapshot.create(allocator, bytes, .{}, .{ .authority = "localhost" });
    defer snapshot.release();
    _ = try snapshot.publishWithDeadline(client, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    try std.testing.expectEqual(@as(usize, 0), client.configuredEndpointCount());
    var response = try sender.unary(.{ .path = "/demo.Drop/Unary", .message = "request", .wait_for_ready = false });
    defer response.deinit();
    try expectDrop(&response);
    try std.testing.expectEqual(grpc.ChannelConnectivityState.ready, client.connectivityState());
    const revision = client.configurationRevision();
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, client.updateWithTimeout(.{ .drop_categories = .{ .replace = &.{} } }, .fromSeconds(2)));
    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expectEqual(revision, client.configurationRevision());
    var unchanged = try sender.unary(.{ .path = "/demo.Drop/Unary", .message = "request" });
    defer unchanged.deinit();
    try expectDrop(&unchanged);
    _ = try client.updateWithTimeout(.{ .drop_categories = .{ .replace = &.{} } }, .fromSeconds(2));
    try std.testing.expectError(error.ConnectionUnavailable, sender.unary(.{ .path = "/demo.Drop/Unary", .message = "request", .wait_for_ready = false }));
    try std.testing.expectEqual(drop.Stats{ .evaluated = 2, .dropped = 2 }, client.dropStats());
}

test "gRPC drop policy expired and invalid calls do not consume admission samples" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{ .channel = .{ .drop_categories = &categories } });
    defer client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    try std.testing.expectError(error.Timeout, sender.startDuplexWithDeadline(.{ .path = "/demo.Drop/Duplex" }, .fromNow(io, .{ .clock = .awake, .raw = .fromNanoseconds(-1) })));
    try std.testing.expectError(error.InvalidMetadata, sender.unary(.{ .path = "/demo.Drop/Unary", .message = "request", .metadata = &.{.{ .name = "grpc-status", .value = "0" }} }));
    var ordinary = try grpc.Channel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{ .drop_categories = &categories });
    defer ordinary.deinit();
    try std.testing.expectError(error.InvalidMetadata, ordinary.unary(.{ .path = "/demo.Drop/Unary", .message = "request", .metadata = &.{.{ .name = "grpc-status", .value = "0" }} }));
    try std.testing.expectError(error.GrpcMessageTooLarge, ordinary.unary(.{ .path = "/demo.Drop/Unary", .message = "request", .max_request_message_size = 1 }));
    try std.testing.expectEqual(drop.Stats{ .evaluated = 0, .dropped = 0 }, ordinary.dropStats());
    try std.testing.expectEqual(drop.Stats{ .evaluated = 0, .dropped = 0 }, client.dropStats());
}

fn waiting(sender: grpc.SharedChannelSender) !grpc.UnaryResponse {
    return sender.unary(.{ .path = "/demo.Drop/Unary", .message = "request", .wait_for_ready = true, .timeout = .{ .value = 5, .unit = .second } });
}

test "gRPC drop policy update rejects queued calls once and retains active calls" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var queued_client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer queued_client.deinit();
    var queued_sender = queued_client.sender();
    defer queued_sender.deinit();
    var pending = try io.concurrent(waiting, .{queued_sender});
    defer _ = pending.cancel(io) catch {};
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) });
    while (true) {
        queued_client.state.mutex.lockUncancelable(io);
        const queued = queued_client.state.queued != 0;
        queued_client.state.mutex.unlock(io);
        if (queued) break;
        if (deadline.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    _ = try queued_client.updateWithDeadline(.{ .drop_categories = .{ .replace = &categories } }, deadline);
    var dropped = try pending.await(io);
    defer dropped.deinit();
    try expectDrop(&dropped);
    try std.testing.expectEqual(drop.Stats{ .evaluated = 1, .dropped = 1 }, queued_client.dropStats());
    const revision = queued_client.state.drop_revision;
    _ = try queued_client.updateWithTimeout(.{ .drop_categories = .{ .replace = &categories } }, .fromSeconds(2));
    try std.testing.expectEqual(revision, queued_client.state.drop_revision);
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var admitted: std.Io.Event = .unset;
    var release: std.Io.Event = .unset;
    const Peer = struct {
        fn run(listener: *grpc.runtime.Server, entered: *std.Io.Event, finish: *std.Io.Event) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var request = try connection.readUnaryWithTimeout(.fromSeconds(3));
            defer request.deinit();
            entered.set(connection.connection.io);
            try finish.waitTimeout(connection.connection.io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(3) } });
            try connection.writeUnary(request.request.stream_id, .{ .message = "active" });
            var extra = connection.readUnaryWithTimeout(.fromSeconds(3)) catch |err| switch (err) {
                error.ConnectionClosed, error.ConnectionResetByPeer, error.SocketUnconnected, error.UnexpectedEof => return,
                else => return err,
            };
            defer extra.deinit();
            return error.UnexpectedExtraRequest;
        }
    };
    var peer = io.async(Peer.run, .{ &server, &admitted, &release });
    defer _ = peer.cancel(io) catch {};
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{});
    var live = true;
    defer if (live) client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var active = try io.concurrent(waiting, .{sender});
    defer _ = active.cancel(io) catch {};
    try admitted.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(3) } });
    _ = try client.updateWithTimeout(.{ .drop_categories = .{ .replace = &categories } }, .fromSeconds(2));
    var rejected = try sender.unary(.{ .path = "/demo.Drop/Unary", .message = "request" });
    defer rejected.deinit();
    try expectDrop(&rejected);
    release.set(io);
    var completed = try active.await(io);
    defer completed.deinit();
    try std.testing.expectEqualStrings("active", completed.message.?.payload);
    try std.testing.expect(!completed.was_dropped);
    client.deinit();
    live = false;
    try peer.await(io);
}

test "gRPC drop policy cancellation precedes reevaluation of a changed policy" {
    const admission = @import("shared/drop_admission.zig");
    const FakeState = struct {
        pub const Failure = error{ Canceled, CallDropped, OutOfMemory };
        allocator: std.mem.Allocator,
        io: std.Io,
        drop: drop.Policy,
        drop_revision: u64 = 2,
        drop_counters: drop.Counters = .{},
    };
    const FakeJob = struct {
        drop_revision: u64 = 1,
        stream: ?*anyopaque = null,
        pub fn canceled(_: *@This()) bool {
            return true;
        }
    };
    var policy = try drop.Policy.init(allocator, &categories);
    defer policy.deinit();
    var state = FakeState{ .allocator = allocator, .io = std.testing.io, .drop = policy };
    var job: FakeJob = .{};
    try std.testing.expectError(error.Canceled, admission.evaluate(&state, &job));
    try std.testing.expectEqual(@as(u64, 1), job.drop_revision);
    try std.testing.expectEqual(drop.Stats{ .evaluated = 0, .dropped = 0 }, state.drop_counters.snapshot());
}
