//! One session's blocked stream send must preserve a shared connection's peers.
const std = @import("std");
const http3 = @import("../../../../http3/mod.zig");
const control = @import("../../session_control.zig");
const client_mod = @import("../../endpoint_client.zig");
const Fixture = @import("../../endpoint_client/test_support.zig").Fixture;
const support = @import("../../flow/progress/support.zig");

test "WebTransport shared stream send wait preserves CLOSE and sibling session events" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const sibling = try fixture.addSession();
    const id = try session.openUnidirectionalStream(&fixture.client);
    try fixture.queueDatagram(sibling, "sibling ready");
    const connection = &fixture.client.h3.established.connection;
    var storage: [64]u8 = undefined;
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try (http3.Frame{ .frame_type = http3.FrameType.data, .payload = try control.writeCloseInto(&storage, 91, "shared stream wait"), .consumed = 0 }).write(&bytes, std.testing.allocator);
    try fixture.peer.send(&.{.{ .stream = .{ .stream_id = session.session_id.value, .offset = connection.recvStreamStats(session.session_id.value).?.highest_received_offset, .data = bytes.items } }});
    support.pace(connection, threaded.io(), 1);
    var committed: usize = 99;
    const Sender = struct {
        fn run(target: *client_mod.Session, client: *client_mod.Client, stream_id: u62, count: *usize) !void {
            try target.sendStreamWithTimeout(client, stream_id, "late", true, count, .fromMilliseconds(100));
        }
    };
    try std.testing.expectError(error.InvalidSessionState, support.withinBudget(threaded.io(), Sender.run, .{ session, &fixture.client, id, &committed }));
    try std.testing.expectEqual(@as(usize, 0), committed);
    try std.testing.expect(!session.streams.get(id).?.prefix_sent and !session.streams.get(id).?.local_fin);
    connection.pacer.enabled = false;
    var output: [32]u8 = undefined;
    const event = (try fixture.client.poll(session.session_id, &output)).?;
    try std.testing.expect(event == .session and event.session == .closed);
    try std.testing.expectEqualStrings("shared stream wait", event.session.closed.reason);
    var ready = (try fixture.client.poll(sibling.session_id, &output)).?;
    defer ready.deinit(std.testing.allocator);
    try std.testing.expect(ready == .datagram);
    try std.testing.expectEqualStrings("sibling ready", ready.datagram.payload);
    try sibling.sendDatagram(&fixture.client, "still writable");
    try std.testing.expect(!connection.closing() and !sibling.control.state.closed);
}
