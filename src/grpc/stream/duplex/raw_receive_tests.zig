const std = @import("std");
const grpc = @import("../../mod.zig");
const http2 = @import("../../../http2/mod.zig");
const duplex = @import("../duplex.zig");
const codec = @import("../codec.zig");
const Fixture = @import("../../../http2/runtime/duplex/testing.zig").Fixture;
const allocator = std.testing.allocator;

test "gRPC raw duplex events retain encoded DATA after terminal metadata" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try Fixture.init(io);
    defer fixture.deinit();
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) });
    var stream = try duplex.startDuplexWithIoDeadline(&fixture.connection, allocator, .{ .authority = "localhost", .path = "/demo.Raw/Receive" }, deadline);
    defer stream.deinit();
    try std.testing.expectEqual(duplex.WriteResult.complete, try stream.finishRequestWithDeadline(deadline));
    try stream.transport.deferResponseStreamCredit();
    var encoder: http2.Hpack.Encoder = .{};
    defer encoder.deinit(allocator);
    try fixture.headers(&encoder, stream.streamId(), false, &.{ .{ .name = ":status", .value = "200" }, .{ .name = "content-type", .value = "application/grpc" } });
    var framed: std.ArrayList(u8) = .empty;
    defer framed.deinit(allocator);
    try grpc.wire.writeMessage(&framed, allocator, "one", false);
    try grpc.wire.writeMessage(&framed, allocator, "two", false);
    try fixture.frame(.data, 0, stream.streamId(), framed.items);
    try fixture.headers(&encoder, stream.streamId(), true, &.{.{ .name = "grpc-status", .value = "0" }});
    var data: ?http2.runtime.DuplexData = null;
    defer if (data) |*owned| owned.deinit(allocator);
    while (data == null) {
        if (try stream.pollRawResponseEventWithDeadline(deadline)) |ready| {
            var event = ready;
            defer event.deinit(allocator);
            switch (event) {
                .data => |value| {
                    data = value;
                    event = .progress;
                },
                .terminal => return error.EarlyTerminal,
                else => {},
            }
        } else _ = try fixture.connection.pumpClientDuplexWithDeadline(deadline);
    }
    try std.testing.expectEqualSlices(u8, framed.items, data.?.data);
    var decoder = try codec.Decoder.init(allocator, 64, null, .{});
    defer decoder.deinit();
    const Collector = struct {
        count: usize = 0,
        fn consume(self: *@This(), message: codec.DecodedMessage) !void {
            try std.testing.expectEqualStrings(if (self.count == 0) "one" else "two", message.payload);
            self.count += 1;
        }
    };
    var collector: Collector = .{};
    const progress = try decoder.feedLimited(data.?.data, 1, &collector, Collector.consume);
    try stream.transport.releaseResponseStreamCreditWithDeadline(progress.consumed, deadline);
    while (true) {
        if (try stream.pollRawResponseEventWithDeadline(deadline)) |ready| {
            var event = ready;
            defer event.deinit(allocator);
            if (event == .terminal) {
                try std.testing.expectEqual(grpc.Status.ok, event.terminal.status);
                break;
            }
        } else _ = try fixture.connection.pumpClientDuplexWithDeadline(deadline);
    }
    try std.testing.expectError(error.InvalidStreamState, stream.pollResponseEventLimitedWithDeadline(1, deadline, &collector, Collector.consume));
    _ = try decoder.feedLimited(data.?.data[progress.consumed..], 1, &collector, Collector.consume);
    try decoder.finish();
    try std.testing.expectEqual(@as(usize, 2), collector.count);
    try stream.transport.releaseResponseStreamCreditWithDeadline(framed.items.len - progress.consumed, deadline);
}
