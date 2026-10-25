//! Shared cancellation preserves terminal events and sibling ownership.
const std = @import("std");
const http3 = @import("../../../../http3/mod.zig");
const control = @import("../../session_control.zig");
const client_mod = @import("../../endpoint_client.zig");
const Fixture = @import("../../endpoint_client/test_support.zig").Fixture;
const support = @import("../../flow/progress/support.zig");
const Operation = enum { reset, reliable, stop };

test "WebTransport shared cancellation pacing wait retains CLOSE and sibling datagrams" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (std.enums.values(Operation)) |operation| {
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const first = try fixture.addSession();
        const second = try fixture.addSession();
        const connection = &fixture.client.h3.established.connection;
        connection.config.reliable_reset = .{ .local = true, .peer = true };
        fixture.peer.config.reliable_reset = .{ .local = true, .peer = true };
        const id = try first.openBidirectionalStream(&fixture.client);
        try first.sendStream(&fixture.client, id, "seed", false);
        if (operation == .stop) {
            try fixture.peer.send(&.{.{ .stream = .{ .stream_id = id, .data = "peer" } }});
            try fixture.client.h3.receiveDetachedResponseProgressWithTimeout(first.session_id.value, .fromSeconds(1));
        }
        try fixture.queueDatagram(second, "sibling");
        var storage: [64]u8 = undefined;
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(std.testing.allocator);
        try (http3.Frame{ .frame_type = http3.FrameType.data, .payload = try control.writeCloseInto(&storage, 91, "cancel wait"), .consumed = 0 }).write(&bytes, std.testing.allocator);
        try fixture.peer.send(&.{.{ .stream = .{ .stream_id = first.session_id.value, .offset = connection.recvStreamStats(first.session_id.value).?.highest_received_offset, .data = bytes.items } }});
        support.pace(connection, threaded.io(), 1);
        const Canceller = struct {
            fn run(target: *client_mod.Session, client: *client_mod.Client, stream_id: u62) !void {
                switch (operation) {
                    .reset => try target.resetStreamWithTimeout(client, stream_id, 71, .fromMilliseconds(100)),
                    .reliable => try target.resetStreamReliablyWithTimeout(client, stream_id, 71, 2, .fromMilliseconds(100)),
                    .stop => try target.stopStreamWithTimeout(client, stream_id, 72, .fromMilliseconds(100)),
                }
            }
        };
        try std.testing.expectError(error.InvalidSessionState, support.withinBudget(threaded.io(), Canceller.run, .{ first, &fixture.client, id }));
        try std.testing.expect(first.streams.get(id).?.send_reset == null and first.streams.get(id).?.stop_sent == null);
        try std.testing.expect(first.control.pending_closed);
        connection.pacer.enabled = false;
        var output: [32]u8 = undefined;
        const close = (try fixture.client.poll(first.session_id, &output)).?;
        try std.testing.expect(close == .session and close.session == .closed);
        try std.testing.expectEqualStrings("cancel wait", close.session.closed.reason);
        var ready = (try fixture.client.poll(second.session_id, &output)).?;
        defer ready.deinit(std.testing.allocator);
        try std.testing.expect(ready == .datagram);
        try std.testing.expectEqualStrings("sibling", ready.datagram.payload);
        try second.sendDatagram(&fixture.client, "still alive");
        try std.testing.expect(!second.control.state.closed and !connection.closing());
    }
}
