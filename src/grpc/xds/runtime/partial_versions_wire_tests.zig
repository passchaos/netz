//! Real delta NACK/reconnect requests advertise only the accepted typed subset.
const std = @import("std");
const support = @import("partial_versions_testing.zig");
const grpc = support.grpc;
const delta = support.delta;
const gpa = support.gpa;

const Collector = struct {
    value: ?delta.codec.OwnedRequest = null,
    fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
        if (self.value != null) return error.UnexpectedRequest;
        self.value = try delta.codec.decodeRequest(gpa, message.payload, .{});
    }
};
fn read(stream: anytype, type_url: []const u8, nonce: []const u8) !delta.codec.OwnedRequest {
    while (true) {
        var collector: Collector = .{};
        errdefer if (collector.value) |*value| value.deinit();
        while (collector.value == null) {
            var event = try stream.readRequestEventWithTimeout(.fromSeconds(5), &collector, Collector.consume);
            defer event.deinit();
            if (event == .reset or event == .finished) return error.EndedEarly;
        }
        var value = collector.value.?;
        if (std.mem.eql(u8, value.value.type_url, type_url) and std.mem.eql(u8, value.value.nonce, nonce)) return value;
        value.deinit();
    }
}
fn send(stream: anytype, response: delta.codec.Response) !void {
    const wire = try delta.codec.encodeResponse(gpa, response, .{});
    defer gpa.free(wire);
    try std.testing.expectEqual(grpc.DuplexWriteResult.complete, try stream.writeMessage(wire));
}
fn Peer(comptime kind: support.Kind) type {
    return struct {
        fn run(server: *grpc.runtime.Server) !void {
            var connection = try server.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            var first = try connection.acceptDuplexWithTimeout(.fromSeconds(5));
            defer first.deinit();
            var listener_request = try read(&first, support.lds.type_url, "");
            defer listener_request.deinit();
            try std.testing.expectEqualStrings("frontend", listener_request.value.subscribe[0]);
            try first.startResponse(.{});
            const listener = try support.listener();
            defer gpa.free(listener);
            try send(&first, .{ .type_url = support.lds.type_url, .nonce = "listener", .resources = &.{.{ .name = "frontend", .version = "l1", .resource = .{ .type_url = support.lds.type_url, .value = listener } }} });
            var cds_request = try read(&first, support.cds.type_url, "");
            defer cds_request.deinit();
            try std.testing.expectEqual(@as(usize, 3), cds_request.value.subscribe.len);
            var clusters = try support.Payloads.cdsFor(kind);
            defer clusters.deinit();
            try send(&first, .{ .type_url = support.cds.type_url, .nonce = "clusters", .resources = &clusters.resources });
            if (kind != .cds) {
                var typed_request = try read(&first, support.url(kind), "");
                defer typed_request.deinit();
                try std.testing.expectEqual(@as(usize, 3), typed_request.value.subscribe.len);
                var initial = try support.Payloads.init(kind, false);
                defer initial.deinit();
                try send(&first, .{ .type_url = support.url(kind), .nonce = "initial", .resources = &initial.resources });
            }
            var ack = try read(&first, support.url(kind), if (kind == .cds) "clusters" else "initial");
            defer ack.deinit();
            try std.testing.expect(ack.value.nack == null);
            var mixed = try support.Payloads.init(kind, true);
            defer mixed.deinit();
            try send(&first, .{ .type_url = support.url(kind), .nonce = "mixed", .resources = &mixed.resources });
            var nack = try read(&first, support.url(kind), "mixed");
            defer nack.deinit();
            try std.testing.expectEqualStrings("invalid sibling", nack.value.nack.?.message);
            try first.finishWithOptions(.{ .status = .unavailable });
            var second = try connection.acceptDuplexWithTimeout(.fromSeconds(5));
            defer second.deinit();
            var replay = try read(&second, support.url(kind), "");
            defer replay.deinit();
            try std.testing.expect(replay.value.nack == null);
            try std.testing.expectEqual(@as(usize, 3), replay.value.subscribe.len);
            try std.testing.expectEqual(@as(usize, 2), replay.value.initial_versions.len);
            var found_a = false;
            var found_foreign = false;
            for (replay.value.initial_versions) |version| {
                if (std.mem.eql(u8, version.name, support.name(kind, 0))) {
                    try std.testing.expectEqualStrings("v2", version.version);
                    found_a = true;
                } else {
                    try std.testing.expectEqualStrings(support.name(kind, 2), version.name);
                    try std.testing.expectEqualStrings("v1", version.version);
                    found_foreign = true;
                }
            }
            try std.testing.expect(found_a and found_foreign);
            try second.startResponse(.{});
            try second.finishOk();
        }
    };
}

fn applyNext(h: *support.Fixture) !void {
    var event = try h.client.nextWithDeadline(support.deadline(h.io));
    defer event.deinit();
    try std.testing.expect(event == .update);
    _ = try h.apply(event.update);
}
fn run(comptime kind: support.Kind) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var control = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{});
    defer control.deinit();
    var sender = control.sender();
    defer sender.deinit();
    var h = try support.Fixture.init(io, sender);
    defer h.deinit();
    var peer = io.async(Peer(kind).run, .{&server});
    defer _ = peer.cancel(io) catch {};
    try h.client.connectWithDeadline(support.deadline(io));
    try applyNext(&h);
    try applyNext(&h);
    if (kind != .cds) try applyNext(&h);
    const foreign_time = h.acceptedTime(kind, 2);
    h.controller.response_authority = "A";
    var mixed = try h.client.nextWithDeadline(support.deadline(io));
    defer mixed.deinit();
    try std.testing.expect(mixed == .update);
    try std.testing.expectError(if (kind == .cds) error.UnsupportedCdsPolicy else error.TruncatedMessage, h.apply(mixed.update));
    try std.testing.expectEqualStrings("v2", h.client.acceptedVersion(support.url(kind), support.name(kind, 0)).?);
    try std.testing.expect(h.client.acceptedVersion(support.url(kind), support.name(kind, 1)) == null);
    try std.testing.expectEqualStrings("v1", h.client.acceptedVersion(support.url(kind), support.name(kind, 2)).?);
    try std.testing.expectEqual(foreign_time, h.acceptedTime(kind, 2));
    try h.client.rejectWithDeadline(mixed.update, .{ .message = "invalid sibling" }, support.deadline(io));
    var terminal = try h.client.nextWithDeadline(support.deadline(io));
    defer terminal.deinit();
    try std.testing.expect(terminal == .terminal);
    try std.testing.expectEqual(grpc.Status.unavailable, terminal.terminal.status);
    try h.client.connectWithDeadline(support.deadline(io));
    var finished = try h.client.nextWithDeadline(support.deadline(io));
    defer finished.deinit();
    try std.testing.expect(finished == .terminal);
    try std.testing.expectEqual(grpc.Status.ok, finished.terminal.status);
    try peer.await(io);
}

test "gRPC delta partial CDS NACK reconnect advertises actual accepted versions" {
    try run(.cds);
}
test "gRPC delta partial EDS NACK reconnect advertises actual accepted versions" {
    try run(.eds);
}
test "gRPC delta partial SDS NACK reconnect advertises actual accepted versions" {
    try run(.sds);
}
