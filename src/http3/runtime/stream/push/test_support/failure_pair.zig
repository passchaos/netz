const std = @import("std");
const http3 = @import("../../../../mod.zig");
const support = @import("../../../receive/test_support/response_pair.zig");

pub const Pair = struct {
    inner: support.Pair,

    pub fn init(self: *@This(), io: std.Io) !void {
        try self.inner.init(io);
        errdefer self.inner.deinit();
        for (0..3) |_| _ = try self.inner.server.openUnidirectionalStream();
        try std.testing.expectEqual(@as(u62, 15), try self.inner.server.openUnidirectionalStream());
        try std.testing.expectEqual(@as(u62, 19), try self.inner.server.openUnidirectionalStream());
        self.inner.client.control.local_max_push_id = 7;
        try self.inner.client.push_streams.reservePromisesThrough(7);
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(std.testing.allocator);
        var block: std.ArrayList(u8) = .empty;
        defer block.deinit(std.testing.allocator);
        try http3.Qpack.encodeLiteralBlock(&block, std.testing.allocator, &.{
            .{ .name = ":method", .value = "GET" },          .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "localhost" }, .{ .name = ":path", .value = "/pushed" },
        });
        for ([_]u64{ 3, 5 }, 0..) |id, index| {
            bytes.clearRetainingCapacity();
            try http3.writePushPromiseFrame(&bytes, std.testing.allocator, id, block.items);
            try (http3.Response{ .status = 204, .request_method = "GET" }).write(&bytes, std.testing.allocator);
            try self.inner.send(&.{.{ .stream = .{ .stream_id = @intCast(index * 4), .data = bytes.items } }});
            var event = (try self.inner.client.pollResponseEventOnce(@intCast(index * 4))) orelse return error.TestUnexpectedResult;
            defer event.deinit(std.testing.allocator);
            try std.testing.expect(event == .push_promise and event.push_promise.push_id == id);
        }
    }

    pub fn deinit(self: *@This()) void {
        self.inner.deinit();
    }

    pub fn malformed(self: *@This(), with_healthy: bool) !void {
        var bad: std.ArrayList(u8) = .empty;
        defer bad.deinit(std.testing.allocator);
        try prefix(&bad, 3);
        try support.missingStatus(&bad);
        var good: std.ArrayList(u8) = .empty;
        defer good.deinit(std.testing.allocator);
        try prefix(&good, 5);
        try (http3.Response{ .status = 204, .request_method = "GET" }).write(&good, std.testing.allocator);
        try self.inner.send(if (with_healthy) &.{
            .{ .stream = .{ .stream_id = 15, .data = bad.items } },
            .{ .stream = .{ .stream_id = 19, .data = good.items, .fin = true } },
        } else &.{.{ .stream = .{ .stream_id = 15, .data = bad.items } }});
        _ = try self.inner.client.established.connection.tryFlushPendingAck();
    }

    pub fn lateFinal(self: *@This(), truncated: bool) !void {
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(std.testing.allocator);
        try prefix(&bytes, 3);
        var block: std.ArrayList(u8) = .empty;
        defer block.deinit(std.testing.allocator);
        try http3.Qpack.encodeLiteralBlock(&block, std.testing.allocator, &.{
            .{ .name = ":status", .value = "200" }, .{ .name = "content-length", .value = "3" },
        });
        try (http3.Frame{ .frame_type = http3.FrameType.headers, .payload = block.items, .consumed = 0 }).write(&bytes, std.testing.allocator);
        try @import("../../../../../quic/mod.zig").varint.encode(&bytes, std.testing.allocator, http3.FrameType.data);
        try @import("../../../../../quic/mod.zig").varint.encode(&bytes, std.testing.allocator, if (truncated) 3 else 2);
        try bytes.appendSlice(std.testing.allocator, "ab");
        try self.inner.send(&.{.{ .stream = .{ .stream_id = 15, .data = bytes.items } }});
        var head = (try self.inner.client.pollPushEventOnce()) orelse return error.TestUnexpectedResult;
        defer head.deinit(std.testing.allocator);
        try std.testing.expect(head.value == .head);
        var data = (try self.inner.client.pollPushEventOnce()) orelse return error.TestUnexpectedResult;
        defer data.deinit(std.testing.allocator);
        try std.testing.expect(data.value == .data_available);
        const reader = self.inner.client.push_streams.readerForStream(15).?;
        const credit = reader.uncreditedConsumed();
        if (credit != 0) {
            try self.inner.client.established.connection.tryReleaseReceivedCapacity(15, credit);
            reader.markCredited(credit);
        }
        try self.inner.send(&.{.{ .stream = .{ .stream_id = 15, .offset = bytes.items.len, .data = &.{}, .fin = true } }});
        _ = try self.inner.client.established.connection.tryFlushPendingAck();
    }
};

pub fn prefix(list: *std.ArrayList(u8), push_id: u64) !void {
    try @import("../../../../../quic/mod.zig").varint.encode(list, std.testing.allocator, @intFromEnum(http3.StreamType.push));
    try @import("../../../../../quic/mod.zig").varint.encode(list, std.testing.allocator, push_id);
}
