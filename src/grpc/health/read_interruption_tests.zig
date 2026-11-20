const std = @import("std");
const grpc = @import("../mod.zig");
const http2 = @import("../../http2/mod.zig");
const frame_wire = @import("../../http2/runtime/frame/wire.zig");
const stream_io = @import("../../internal/stream_io.zig");
const allocator = std.testing.allocator;

const Fault = enum { cancellation, executor };
const ReadIo = struct {
    base: std.Io,
    fault: ?Fault = null,
    hits: usize = 0,
    var active: ?*ReadIo = null;
    fn groupConcurrent(userdata: ?*anyopaque, group: *std.Io.Group, context: []const u8, alignment: std.mem.Alignment, start: *const fn (*const anyopaque) void) std.Io.ConcurrentError!void {
        const self = active.?;
        if (self.fault == .executor) {
            self.fault = null;
            self.hits += 1;
            return error.ConcurrencyUnavailable;
        }
        return self.base.vtable.groupConcurrent(userdata, group, context, alignment, start);
    }
    fn futexWait(userdata: ?*anyopaque, ptr: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self = active.?;
        if (self.fault == .cancellation) {
            self.fault = null;
            self.hits += 1;
            return error.Canceled;
        }
        return self.base.vtable.futexWait(userdata, ptr, expected, timeout);
    }
};

test "gRPC reconnecting health Watch read interruptions retain the sent request and partial response" {
    for (std.enums.values(Fault)) |fault| {
        for (0..4) |split| try exercise(fault, split);
    }
}

fn exercise(fault: Fault, split: usize) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, base, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    var resume_response: std.Io.Event = .unset;
    const Peer = struct {
        fn consume(_: void, message: grpc.StreamingMessage) !void {
            try std.testing.expectEqualStrings("demo.Echo", (try grpc.health.decodeRequest(message.payload)).service);
        }
        fn run(listener: *grpc.runtime.Server, io: std.Io, resumed: *std.Io.Event, split_index: usize) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(3));
            defer connection.deinit();
            var request = try connection.readStreamingWithTimeout(.fromSeconds(3), {}, consume);
            defer request.deinit();
            try std.testing.expectEqualStrings(grpc.health.watch_path, request.path);
            try std.testing.expectEqual(@as(u31, 1), request.transport.stream_id);
            var encoder: http2.Hpack.Encoder = .{};
            defer encoder.deinit(allocator);
            var wire: std.ArrayList(u8) = .empty;
            defer wire.deinit(allocator);
            const head = try encoder.encodeBlockRetained(allocator, &.{
                .{ .name = ":status", .value = "200" },
                .{ .name = "content-type", .value = "application/grpc" },
                .{ .name = "x-watch", .value = "retained" },
            });
            try frame_wire.appendFrame(&wire, allocator, .headers, 4, request.transport.stream_id, head);
            const head_length = wire.items.len;
            try frame_wire.appendFrame(&wire, allocator, .data, 0, request.transport.stream_id, &.{ 0, 0, 0, 0, 2, 8, 1 });
            const trailers = try encoder.encodeBlockRetained(allocator, &.{.{ .name = "grpc-status", .value = "12" }});
            try frame_wire.appendFrame(&wire, allocator, .headers, 5, request.transport.stream_id, trailers);
            const prefix = switch (split_index) {
                0 => 0,
                1 => 4, // Partial HTTP/2 frame header.
                2 => head_length - 1, // Partial HPACK field block.
                3 => head_length + 12, // Partial DATA/gRPC length prefix.
                else => unreachable,
            };
            try stream_io.writeAllSlices(io, connection.connection.stream, &.{wire.items[0..prefix]});
            try resumed.wait(io);
            try stream_io.writeAllSlices(io, connection.connection.stream, &.{wire.items[prefix..]});
        }
    };
    var peer = try base.concurrent(Peer.run, .{ &server, base, &resume_response, split });
    defer _ = peer.cancel(base) catch {};
    var probe = ReadIo{ .base = base };
    ReadIo.active = &probe;
    defer ReadIo.active = null;
    var table = base.vtable.*;
    table.groupConcurrent = ReadIo.groupConcurrent;
    table.futexWait = ReadIo.futexWait;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &table };
    var watch = try grpc.health.ReconnectingWatch.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{ .watch = .{ .service = "demo.Echo" } });
    defer watch.deinit();
    _ = try watch.owner.connectWithDeadline(.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) }));
    // The setup and first partial response read complete before injection.
    // No fault can affect the request's independent write timer tasks.
    try std.testing.expectError(error.Timeout, watch.nextWithTimeout(.fromMilliseconds(30)));
    try std.testing.expect(watch.watch != null);
    const stream_id = watch.watch.?.stream.transport.streamId();
    probe.fault = fault;
    const result = watch.nextWithTimeout(.fromSeconds(1));
    if (fault == .executor) try std.testing.expectError(error.ConcurrencyUnavailable, result) else try std.testing.expectError(error.Canceled, result);
    try std.testing.expectEqual(@as(usize, 1), probe.hits);
    try std.testing.expect(watch.watch != null);
    try std.testing.expectEqual(stream_id, watch.watch.?.stream.transport.streamId());
    try std.testing.expectEqual(@as(usize, 1), watch.owner.slots[0].connection.?.activeLocalStreamCount());
    try std.testing.expectEqual(@as(u31, 3), watch.owner.slots[0].connection.?.next_client_stream_id);
    try std.testing.expectEqual(@as(usize, 0), watch.failures);
    try std.testing.expect(watch.retry_at == null);
    resume_response.set(base);
    const status = try watch.nextWithTimeout(.fromSeconds(3));
    try std.testing.expectEqual(grpc.health.ServingStatus.serving, status.status.status);
    try std.testing.expect(watch.isServing());
    try std.testing.expectEqual(grpc.health.ReconnectingWatchEvent.disabled, try watch.nextWithTimeout(.fromSeconds(3)));
    try std.testing.expect(watch.isServing());
    try peer.await(base);
}
