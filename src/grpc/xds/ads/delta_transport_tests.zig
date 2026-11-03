const std = @import("std");
const grpc = @import("../../mod.zig");
const delta = @import("../ads/delta.zig");
const allocator = std.testing.allocator;
const codec = delta.codec;
const cds = @import("delta_tests.zig").cds;
const eds = @import("delta_tests.zig").eds;

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
}

const Collector = struct {
    request: ?codec.OwnedRequest = null,
    fn consume(self: *Collector, message: grpc.StreamingMessage) !void {
        if (self.request != null) return error.UnexpectedRequest;
        self.request = try codec.decodeRequest(allocator, message.payload, .{});
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
    const encoded = try codec.encodeResponse(allocator, response, .{});
    defer allocator.free(encoded);
    try std.testing.expectEqual(grpc.DuplexWriteResult.complete, try stream.writeMessage(encoded));
}

fn expectNames(actual: []const []const u8, expected: []const []const u8) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |want, got| try std.testing.expectEqualStrings(want, got);
}

test "delta xDS real duplex applies diffs, NACKs, and replays versions on reconnect" {
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
            try std.testing.expectEqualStrings(delta.path, first.transport.path);
            var initial = try request(&first);
            defer initial.deinit();
            try std.testing.expect(initial.value.node != null);
            try std.testing.expectEqualStrings(cds, initial.value.type_url);
            try expectNames(initial.value.subscribe, &.{ "a", "b" });
            try std.testing.expect(initial.value.unsubscribe.len == 0);
            try std.testing.expect(initial.value.initial_versions.len == 0);
            try std.testing.expectEqualStrings("", initial.value.nonce);
            try first.startResponse(.{});
            try send(&first, .{ .type_url = cds, .nonce = "n1", .resources = &.{
                .{ .name = "a", .version = "v1", .resource = .{ .type_url = cds, .value = "one" } },
                .{ .name = "b", .version = "v2", .resource = .{ .type_url = cds, .value = "two" } },
            } });

            var ack = try request(&first);
            defer ack.deinit();
            try std.testing.expect(ack.value.node == null);
            try std.testing.expectEqualStrings("n1", ack.value.nonce);
            try std.testing.expect(ack.value.nack == null);
            try std.testing.expect(ack.value.subscribe.len == 0 and ack.value.unsubscribe.len == 0);

            var diff = try request(&first);
            defer diff.deinit();
            try expectNames(diff.value.subscribe, &.{"c"});
            try expectNames(diff.value.unsubscribe, &.{"b"});
            try std.testing.expectEqualStrings("", diff.value.nonce);
            try send(&first, .{ .type_url = cds, .nonce = "n2", .resources = &.{
                .{ .name = "c", .version = "v3", .resource = .{ .type_url = cds, .value = "three" } },
            }, .removed = &.{"b"} });

            var applied = try request(&first);
            defer applied.deinit();
            try std.testing.expectEqualStrings("n2", applied.value.nonce);
            try std.testing.expect(applied.value.nack == null);

            // A wrong-type payload is NACKed with the response nonce instead
            // of poisoning accepted versions.
            try send(&first, .{ .type_url = cds, .nonce = "n3", .resources = &.{
                .{ .name = "d", .version = "bad", .resource = .{ .type_url = eds, .value = "wrong" } },
            } });
            var rejected = try request(&first);
            defer rejected.deinit();
            try std.testing.expectEqualStrings("n3", rejected.value.nonce);
            try std.testing.expectEqualStrings("wrong type", rejected.value.nack.?.message);

            try first.finishWithOptions(.{ .status = .unavailable, .status_message = "restart" });
            var second = try connection.acceptDuplexWithTimeout(.fromSeconds(3));
            defer second.deinit();
            var replay = try request(&second);
            defer replay.deinit();
            try std.testing.expect(replay.value.node != null);
            try expectNames(replay.value.subscribe, &.{ "a", "c" });
            try std.testing.expectEqual(@as(usize, 2), replay.value.initial_versions.len);
            try std.testing.expectEqualStrings("a", replay.value.initial_versions[0].name);
            try std.testing.expectEqualStrings("v1", replay.value.initial_versions[0].version);
            try std.testing.expectEqualStrings("c", replay.value.initial_versions[1].name);
            try std.testing.expectEqualStrings("v3", replay.value.initial_versions[1].version);
            try std.testing.expectEqualStrings("", replay.value.nonce);
            try std.testing.expect(replay.value.nack == null);

            try second.startResponse(.{});
            try send(&second, .{ .type_url = cds, .nonce = "n4", .resources = &.{
                .{ .name = "a", .version = "v1", .ttl = .{ .seconds = 1 } },
            } });
            var heartbeat = try request(&second);
            defer heartbeat.deinit();
            try std.testing.expectEqualStrings("n4", heartbeat.value.nonce);
            try std.testing.expect(heartbeat.value.nack == null);
            try second.finishOk();
        }
    };
    var task = io.async(Peer.run, .{&server});
    defer _ = task.cancel(io) catch {};
    var channel = try grpc.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var client = try delta.Client.init(allocator, sender, .{ .node = .{ .id = "node" } });
    defer client.deinit();
    try client.setSubscription(cds, &.{ "b", "a" });
    try client.connectWithDeadline(deadline(io));
    var update = try client.nextWithDeadline(deadline(io));
    defer update.deinit();
    try std.testing.expect(update == .update and update.update.resourcesMatchType());
    try client.acknowledgeWithDeadline(update.update, deadline(io));
    try std.testing.expectEqualStrings("v1", client.acceptedVersion(cds, "a").?);
    try std.testing.expectEqualStrings("v2", client.acceptedVersion(cds, "b").?);
    try client.setSubscription(cds, &.{ "a", "c" });
    try std.testing.expectEqual(@as(usize, 1), try client.flushWithDeadline(deadline(io)));
    var changed = try client.nextWithDeadline(deadline(io));
    defer changed.deinit();
    try client.acceptAppliedUpdate(changed.update);
    try std.testing.expectEqual(@as(usize, 1), try client.flushWithDeadline(deadline(io)));
    try std.testing.expect(client.acceptedVersion(cds, "b") == null);
    try std.testing.expectEqualStrings("v3", client.acceptedVersion(cds, "c").?);
    var invalid = try client.nextWithDeadline(deadline(io));
    defer invalid.deinit();
    try std.testing.expect(!invalid.update.resourcesMatchType());
    try client.rejectWithDeadline(invalid.update, .{ .message = "wrong type" }, deadline(io));
    var terminal = try client.nextWithDeadline(deadline(io));
    defer terminal.deinit();
    try std.testing.expectEqual(grpc.Status.unavailable, terminal.terminal.status);
    try client.connectWithTimeout(.fromMilliseconds(50));
    var recovered = try client.nextWithDeadline(deadline(io));
    defer recovered.deinit();
    try std.testing.expectEqualStrings("v1", client.acceptedVersion(cds, "a").?);
    try client.acknowledgeWithDeadline(recovered.update, deadline(io));
    var ended = try client.nextWithDeadline(deadline(io));
    defer ended.deinit();
    try std.testing.expectEqual(grpc.Status.ok, ended.terminal.status);
    try task.await(io);
}

test "delta xDS construction and stream admission rollback preserves caller ownership" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    const Harness = struct {
        fn run(gpa: std.mem.Allocator, value: grpc.SharedChannelSender) !void {
            var client = try delta.Client.init(gpa, value, .{ .node = .{ .id = "node" } });
            defer client.deinit();
            try client.setSubscription(cds, &.{"a"});
        }
    };
    const refs = channel.state.refs.load(.acquire);
    try std.testing.checkAllAllocationFailures(allocator, Harness.run, .{sender});
    try std.testing.expectEqual(refs, channel.state.refs.load(.acquire));
    var client = try delta.Client.init(allocator, sender, .{ .node = .{ .id = "node" } });
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
}

test "delta xDS rebind retains desired names and accepted versions" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var first = try grpc.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer first.deinit();
    var first_sender = first.sender();
    defer first_sender.deinit();
    var second = try grpc.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer second.deinit();
    const second_sender = second.sender();
    var client = try delta.Client.init(allocator, first_sender, .{ .node = .{ .id = "node" } });
    defer client.deinit();
    try client.setSubscription(cds, &.{"a"});
    const token = try client.subscriptions.received(.{ .type_url = cds, .nonce = "n1" });
    _ = try client.subscriptions.decide(cds, token, null, .{ .type_url = cds, .resources = &.{.{ .name = "a", .version = "v1", .resource = .{ .type_url = cds, .value = "one" } }} });
    try client.rebind(second_sender, .{ .path = delta.path });
    try std.testing.expect(client.stream == null);
    try std.testing.expect(client.sender.state == second.state);
    try std.testing.expectEqualStrings("v1", client.acceptedVersion(cds, "a").?);
    try std.testing.expectEqualStrings("a", client.subscriptions.find(cds).?.names[0]);
    try std.testing.expect(!client.subscriptions.find(cds).?.stream_started);
    try std.testing.expect(client.subscriptions.find(cds).?.dirty);
}
