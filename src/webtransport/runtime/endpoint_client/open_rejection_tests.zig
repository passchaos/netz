const std = @import("std");
const http3 = @import("../../../http3/mod.zig");
const Fixture = @import("test_support.zig").Fixture;

test "WebTransport shared client peer STOP_SENDING rejection preserves sibling and releases admission" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    fixture.peer.config.local_max_datagram_frame_size = 1200;
    fixture.peer.config.peer_max_datagram_frame_size = 1200;
    const sibling = try fixture.addSession();
    const Worker = struct {
        fixture: *Fixture,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const peer = &self.fixture.peer;
            const deadline = std.Io.Clock.Timestamp.fromNow(peer.endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(2) });
            while ((if (peer.recvStreamStats(4)) |stats| stats.highest_received_offset else 0) == 0) {
                var packet = try peer.receivePacketServicingTimersDeadline(deadline);
                packet.deinit(std.testing.allocator);
            }
            try peer.cancelStream(4, http3.ApplicationErrorCode.request_rejected);
        }
    };
    var worker = Worker{ .fixture = &fixture };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();
    const result = fixture.client.openSessionAttemptWithTimeout(.{
        .authority = "localhost",
        .path = "/rejected",
    }, .fromSeconds(1));
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
    try std.testing.expectError(error.RequestRejected, result);
    try fixture.queueDatagram(sibling, "alive");
    var event = (try fixture.poll(sibling)) orelse return error.TestUnexpectedResult;
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .datagram);
    try std.testing.expectEqualStrings("alive", event.datagram.payload);
    try std.testing.expectEqual(@as(usize, 0), fixture.client.pending_open_cleanup.count());
    try std.testing.expect(!sibling.control.state.closed);
    try fixture.peer.sendDatagram("\x00inbound");
    var stream_buffer: [32]u8 = undefined;
    var received = try fixture.client.receiveWithTimeout(sibling.session_id, &stream_buffer, .fromSeconds(1));
    defer received.deinit(std.testing.allocator);
    try std.testing.expect(received == .datagram);
    try std.testing.expectEqualStrings("inbound", received.datagram.payload);
    try sibling.sendDatagram(&fixture.client, "outbound");
    const connection = &fixture.client.h3.established.connection;
    const reset = connection.sendStreamStats(4).?.reset.?;
    try std.testing.expectEqual(http3.ApplicationErrorCode.request_rejected, reset.application_error_code);
    try std.testing.expectEqual(http3.ApplicationErrorCode.request_cancelled, connection.recvStreamStats(4).?.stop_sending_sent.?.application_error_code);
    var saw_reset = false;
    var saw_stop = false;
    var saw_datagram = false;
    const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
    while (!saw_reset or !saw_stop or !saw_datagram) {
        var packet = try fixture.peer.receivePacketServicingTimersDeadline(deadline);
        defer packet.deinit(std.testing.allocator);
        for (packet.frames) |frame| switch (frame) {
            .reset_stream => |value| if (value.stream_id == 4) {
                try std.testing.expectEqual(reset.application_error_code, value.application_error_code);
                try std.testing.expectEqual(reset.final_size, value.final_size);
                saw_reset = true;
            },
            .stop_sending => |value| if (value.stream_id == 4) {
                try std.testing.expectEqual(http3.ApplicationErrorCode.request_cancelled, value.application_error_code);
                saw_stop = true;
            },
            .datagram => |value| {
                const datagram = try http3.Datagram.parse(value.data);
                try std.testing.expectEqual(@as(u62, 0), datagram.quarter_stream_id);
                try std.testing.expectEqualStrings("outbound", datagram.payload);
                saw_datagram = true;
            },
            else => {},
        };
    }
    try std.testing.expectError(error.Timeout, fixture.client.openSessionAttemptWithTimeout(.{
        .authority = "localhost",
        .path = "/capacity-restored",
    }, .fromMilliseconds(10)));
    try std.testing.expectEqual(@as(u62, 12), fixture.client.h3.next_stream_id);
}
