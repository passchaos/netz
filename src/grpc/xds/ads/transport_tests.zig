const std = @import("std");
const grpc = @import("../../mod.zig");
const ads = @import("../ads.zig");
const allocator = std.testing.allocator;
const codec = ads.codec;
const cds = @import("tests.zig").cds;
const eds = @import("tests.zig").eds;
fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
}

const Collector = struct {
    request: ?codec.OwnedRequest = null,
    fn consume(self: *Collector, message: grpc.StreamingMessage) !void {
        if (self.request != null) return error.UnexpectedRequest;
        self.request = try codec.decodeRequest(allocator, message.payload, 4096, 8);
    }
};
fn request(stream: anytype) !codec.OwnedRequest {
    var collector: Collector = .{};
    errdefer if (collector.request) |*value| value.deinit();
    while (collector.request == null) {
        var event = try stream.readRequestEventWithTimeout(.fromSeconds(3), &collector, Collector.consume);
        defer event.deinit();
        if (event == .finished or event == .reset) return error.EndedEarly;
    }
    return collector.request.?;
}
fn send(stream: anytype, response: codec.Response) !void {
    const encoded = try codec.encodeResponse(allocator, response, 4096);
    defer allocator.free(encoded);
    try std.testing.expectEqual(grpc.DuplexWriteResult.complete, try stream.writeMessage(encoded));
}

test "gRPC ADS real duplex keeps per-type versions and replays state on a new stream" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    const Peer = struct {
        fn run(listener: *grpc.runtime.Server) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var first = try connection.acceptDuplexWithTimeout(.fromSeconds(3));
            defer first.deinit();
            try std.testing.expectEqualStrings(ads.path, first.transport.path);
            var a = try request(&first);
            defer a.deinit();
            var b = try request(&first);
            defer b.deinit();
            try std.testing.expect(a.value.node != null and b.value.node == null);
            try std.testing.expectEqualStrings(cds, a.value.type_url);
            try std.testing.expectEqualStrings(eds, b.value.type_url);
            try first.startResponse(.{});
            try send(&first, .{ .type_url = cds, .version = "c1", .nonce = "n1", .resources = &.{.{ .type_url = cds, .value = "cluster" }} });
            var ack = try request(&first);
            defer ack.deinit();
            try std.testing.expectEqualStrings("c1", ack.value.version);
            try std.testing.expectEqualStrings("n1", ack.value.nonce);
            try std.testing.expectEqual(@as(usize, 2), ack.value.names.len);
            try send(&first, .{ .type_url = eds, .version = "bad", .nonce = "n2", .resources = &.{.{ .type_url = cds, .value = "wrong-type" }} });
            var nack = try request(&first);
            defer nack.deinit();
            try std.testing.expectEqualStrings("", nack.value.version);
            try std.testing.expectEqualStrings("n2", nack.value.nonce);
            try std.testing.expectEqualStrings("wrong type", nack.value.nack.?.message);
            try first.finishWithOptions(.{ .status = .unavailable, .status_message = "restart" });
            var second = try connection.acceptDuplexWithTimeout(.fromSeconds(3));
            defer second.deinit();
            var replay_a = try request(&second);
            defer replay_a.deinit();
            var replay_b = try request(&second);
            defer replay_b.deinit();
            try std.testing.expect(replay_a.value.node != null and replay_b.value.node == null);
            try std.testing.expectEqualStrings("c1", replay_a.value.version);
            try std.testing.expectEqualStrings("", replay_b.value.version);
            try std.testing.expectEqualStrings("", replay_a.value.nonce);
            try std.testing.expectEqualStrings("", replay_b.value.nonce);
            try std.testing.expect(replay_b.value.nack == null);
            // The stream outlives its short admission budget and remains writable.
            try std.Io.sleep(connection.connection.io, .fromMilliseconds(80), .awake);
            try second.startResponse(.{});
            try send(&second, .{ .type_url = eds, .version = "e1", .nonce = "new", .resources = &.{} });
            var accepted = try request(&second);
            defer accepted.deinit();
            try std.testing.expectEqualStrings("e1", accepted.value.version);
            try std.testing.expectEqualStrings("new", accepted.value.nonce);
            try second.finishOk();
        }
    };
    var task = io.async(Peer.run, .{&server});
    defer _ = task.cancel(io) catch {};
    var channel = try grpc.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var client = try ads.Client.init(failing.allocator(), sender, .{ .node = .{ .id = "node" } });
    defer client.deinit();
    try client.setSubscription(cds, &.{"a"});
    try client.setSubscription(eds, &.{});
    try client.connectWithDeadline(deadline(io));
    var update = try client.nextWithDeadline(deadline(io));
    defer update.deinit();
    try std.testing.expect(update == .update and update.update.resourcesMatchType());
    try client.setSubscription(cds, &.{ "b", "a" });
    try std.testing.expectEqual(@as(usize, 0), try client.flushWithDeadline(deadline(io)));
    try client.acknowledgeWithDeadline(update.update, deadline(io));
    var invalid = try client.nextWithDeadline(deadline(io));
    defer invalid.deinit();
    try std.testing.expect(!invalid.update.resourcesMatchType());
    try std.testing.expectError(error.InvalidDiscoveryMessage, client.acknowledgeWithDeadline(invalid.update, deadline(io)));
    try client.rejectWithDeadline(invalid.update, .{ .message = "wrong type" }, deadline(io));
    var terminal = try client.nextWithDeadline(deadline(io));
    defer terminal.deinit();
    try std.testing.expectEqual(grpc.Status.unavailable, terminal.terminal.status);
    try std.testing.expectEqualStrings("c1", client.acceptedVersion(cds).?);
    try client.connectWithTimeout(.fromMilliseconds(50));
    try std.testing.expectError(error.StaleDiscoveryResponse, client.acknowledgeWithDeadline(update.update, deadline(io)));
    var recovered = try client.nextWithDeadline(deadline(io));
    defer recovered.deinit();
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, client.acknowledgeWithDeadline(recovered.update, deadline(io)));
    try std.testing.expectEqualStrings("e1", client.acceptedVersion(eds).?);
    try std.testing.expect(client.stream != null and client.subscriptions.find(eds).?.dirty);
    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expectEqual(@as(usize, 1), try client.flushWithDeadline(deadline(io)));
    var ended = try client.nextWithDeadline(deadline(io));
    defer ended.deinit();
    try std.testing.expectEqual(grpc.Status.ok, ended.terminal.status);
    try task.await(io);
}

test "gRPC ADS construction and stream admission rollback preserves caller ownership" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    const Harness = struct {
        fn run(gpa: std.mem.Allocator, value: grpc.SharedChannelSender) !void {
            var client = try ads.Client.init(gpa, value, .{ .node = .{ .id = "node" } });
            defer client.deinit();
            try client.setSubscription(cds, &.{"a"});
            try client.setSubscription(eds, &.{});
        }
    };
    const refs = channel.state.refs.load(.acquire);
    try std.testing.checkAllAllocationFailures(allocator, Harness.run, .{sender});
    try std.testing.expectEqual(refs, channel.state.refs.load(.acquire));
    var client = try ads.Client.init(allocator, sender, .{ .node = .{ .id = "node" } });
    defer client.deinit();
    try client.setSubscription(cds, &.{"a"});
    const baseline = channel.state.refs.load(.acquire);
    channel.state.mutex.lockUncancelable(io);
    try std.testing.expectError(error.Timeout, client.connectWithTimeout(.fromMilliseconds(2)));
    channel.state.mutex.unlock(io);
    try std.testing.expectEqual(baseline, channel.state.refs.load(.acquire));
    try std.testing.expect(client.stream == null);
    try std.testing.expectEqual(@as(usize, 0), channel.state.queued);
    try std.testing.expect(client.subscriptions.find(cds).?.dirty);
    try std.testing.expectEqualStrings("a", client.subscriptions.find(cds).?.names[0]);
    try std.testing.expectError(error.Timeout, client.connectWithDeadline(.{ .clock = .real, .raw = .zero }));
    try std.testing.expectError(error.Timeout, sender.startDuplexWithDeadline(.{ .path = ads.path }, .fromNow(io, .{ .clock = .awake, .raw = .fromNanoseconds(-1) })));
}
