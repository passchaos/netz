const std = @import("std");
const http3 = @import("../../../mod.zig");
const runtime = @import("../../../runtime.zig");
const quic = @import("../../../../quic/mod.zig");
const request_pair = @import("request_pair.zig");
const response_pair = @import("response_pair.zig");

pub fn For(comptime response: bool) type {
    return struct {
        const Pair = @This();
        inner: if (response) response_pair.Pair else request_pair.Pair,

        pub fn init(self: *Pair, io: std.Io) !void {
            try self.inner.init(io);
        }

        pub fn deinit(self: *Pair) void {
            self.inner.deinit();
        }

        pub fn owner(self: *Pair) *if (response) runtime.HandshakeClient else runtime.HandshakeServerSession {
            return if (response) &self.inner.client else &self.inner.server;
        }

        pub fn connection(self: *Pair) *quic.one_rtt.Connection {
            return &self.owner().established.connection;
        }

        pub fn streams(self: *Pair) *@import("../../stream/set.zig").Set {
            return if (response) &self.owner().streaming_responses else &self.owner().streaming_requests;
        }

        pub fn pendingCount(self: *Pair) usize {
            return if (response) self.owner().pending_response_failures.count() else self.owner().pending_request_failures.count();
        }

        pub fn poll(self: *Pair, id: u62) !?runtime.StreamingEvent {
            if (response) return self.owner().pollResponseEventOnce(id);
            const event = (try self.owner().pollRequestEventForOnce(id)) orelse return null;
            if (event != .message) return error.TestUnexpectedResult;
            return event.message.value;
        }

        pub fn send(self: *Pair, frames: []const quic.Frame) !void {
            try self.inner.send(frames);
        }

        /// Expose DATA before its final size is known, then inject FIN and a
        /// healthy sibling without re-polling the first message reader.
        pub fn lateFinal(self: *Pair, truncated: bool) !void {
            try self.finishLate(truncated, false);
        }

        pub fn lateFinalAfterRead(self: *Pair) !void {
            try self.finishLate(false, true);
        }

        fn finishLate(self: *Pair, truncated: bool, read_prefix: bool) !void {
            var bytes: std.ArrayList(u8) = .empty;
            defer bytes.deinit(std.testing.allocator);
            try self.writeHead(&bytes, true);
            try quic.varint.encode(&bytes, std.testing.allocator, http3.FrameType.data);
            try quic.varint.encode(&bytes, std.testing.allocator, if (truncated) 3 else 2);
            try bytes.appendSlice(std.testing.allocator, "ab");
            try self.send(&.{.{ .stream = .{ .stream_id = 0, .data = bytes.items } }});
            var head = (try self.poll(0)) orelse return error.TestUnexpectedResult;
            defer head.deinit(std.testing.allocator);
            try std.testing.expect(head == .head);
            var data = (try self.poll(0)) orelse return error.TestUnexpectedResult;
            defer data.deinit(std.testing.allocator);
            try std.testing.expect(data == .data_available);
            if (read_prefix) {
                var prefix: [1]u8 = undefined;
                const count = if (response) try self.owner().readResponseDataOnce(0, &prefix) else try self.owner().readRequestDataOnce(0, &prefix);
                try std.testing.expectEqual(@as(?usize, 1), count);
                try std.testing.expectEqualStrings("a", &prefix);
            }
            var sibling: std.ArrayList(u8) = .empty;
            defer sibling.deinit(std.testing.allocator);
            try self.writeHead(&sibling, false);
            try self.send(&.{
                .{ .stream = .{ .stream_id = 0, .offset = bytes.items.len, .data = &.{}, .fin = true } },
                .{ .stream = .{ .stream_id = 4, .data = sibling.items, .fin = true } },
            });
            if (!read_prefix) try self.flushCredit();
        }

        pub fn bodyReady(self: *Pair, with_data: bool) !void {
            var bytes: std.ArrayList(u8) = .empty;
            defer bytes.deinit(std.testing.allocator);
            try self.writeHead(&bytes, true);
            try self.send(&.{.{ .stream = .{ .stream_id = 0, .data = bytes.items } }});
            var head = (try self.poll(0)) orelse return error.TestUnexpectedResult;
            defer head.deinit(std.testing.allocator);
            try std.testing.expect(head == .head);
            if (with_data) {
                var body: std.ArrayList(u8) = .empty;
                defer body.deinit(std.testing.allocator);
                try (http3.Frame{ .frame_type = http3.FrameType.data, .payload = "abc", .consumed = 0 }).write(&body, std.testing.allocator);
                try self.send(&.{.{ .stream = .{ .stream_id = 0, .offset = bytes.items.len, .data = body.items, .fin = true } }});
                var data = (try self.poll(0)) orelse return error.TestUnexpectedResult;
                defer data.deinit(std.testing.allocator);
                try std.testing.expect(data == .data_available);
            }
            try self.flushCredit();
        }

        fn flushCredit(self: *Pair) !void {
            const reader = &self.streams().find(0).?.reader;
            const amount = reader.uncreditedConsumed();
            if (amount != 0) {
                try self.connection().tryReleaseReceivedCapacity(0, amount);
                reader.markCredited(amount);
            }
            _ = try self.connection().tryFlushPendingAck();
        }

        pub fn writeHead(self: *Pair, list: *std.ArrayList(u8), with_body: bool) !void {
            _ = self;
            var block: std.ArrayList(u8) = .empty;
            defer block.deinit(std.testing.allocator);
            if (response) {
                try http3.Qpack.encodeLiteralBlock(&block, std.testing.allocator, if (with_body) &.{
                    .{ .name = ":status", .value = "200" }, .{ .name = "content-length", .value = "3" },
                } else &.{.{ .name = ":status", .value = "204" }});
            } else {
                try http3.Qpack.encodeLiteralBlock(&block, std.testing.allocator, if (with_body) &.{
                    .{ .name = ":method", .value = "POST" },         .{ .name = ":scheme", .value = "https" },
                    .{ .name = ":authority", .value = "localhost" }, .{ .name = ":path", .value = "/body" },
                    .{ .name = "content-length", .value = "3" },
                } else &.{
                    .{ .name = ":method", .value = "GET" },          .{ .name = ":scheme", .value = "https" },
                    .{ .name = ":authority", .value = "localhost" }, .{ .name = ":path", .value = "/healthy" },
                });
            }
            try (http3.Frame{ .frame_type = http3.FrameType.headers, .payload = block.items, .consumed = 0 }).write(list, std.testing.allocator);
        }
    };
}
