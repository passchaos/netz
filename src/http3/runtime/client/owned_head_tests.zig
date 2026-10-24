const std = @import("std");
const http3 = @import("../../mod.zig");
const Fixture = @import("../../../webtransport/runtime/endpoint_client/test_support.zig").Fixture;

test "HTTP/3 owned request head preflight leaves unallocated streams unowned" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const sibling = try fixture.addSession();
    const h3 = &fixture.client.h3;
    const packet_number = h3.established.connection.next_packet_number;
    const requests = h3.request_lifecycle.count();
    var owner: ?u62 = 123;
    try std.testing.expectError(error.Timeout, h3.startRequestOwnedWithDeadline(.{
        .method = "GET",
        .authority = "localhost",
        .path = "/expired",
    }, 0, &owner, .{ .clock = .awake, .raw = .zero }));
    try std.testing.expect(owner == null);
    try std.testing.expectError(error.InvalidHeader, h3.startRequestOwned(.{
        .method = "GET",
        .authority = "localhost",
        .path = "/invalid",
        .headers = &.{.{ .name = "Uppercase", .value = "invalid" }},
    }, 0, &owner));
    try std.testing.expect(owner == null);
    try std.testing.expectEqual(packet_number, h3.established.connection.next_packet_number);
    for ([_][]const u8{ " leading", "trailing\t" }) |value| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        const original = h3.allocator;
        h3.allocator = failing.allocator();
        defer h3.allocator = original;
        owner = 123;
        try std.testing.expectError(error.InvalidHeader, h3.startRequestOwned(.{
            .method = "GET",
            .authority = "localhost",
            .path = "/invalid-value",
            .headers = &.{.{ .name = "x-test", .value = value }},
        }, 0, &owner));
        try std.testing.expect(!failing.has_induced_failure);
        try std.testing.expect(owner == null);
        try std.testing.expectEqual(packet_number, h3.established.connection.next_packet_number);
    }
    try std.testing.expectEqual(@as(u62, 4), h3.next_stream_id);
    try std.testing.expectEqual(@as(u64, 4), h3.established.connection.nextLocalBidirectionalStreamId());
    try std.testing.expectEqual(requests, h3.request_lifecycle.count());
    try std.testing.expect(!sibling.control.state.closed);
}

test "HTTP/3 owned request head submits FIN for an empty ordinary request" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    _ = try fixture.addSession();
    var owner: ?u62 = null;
    const id = try fixture.client.h3.startRequestOwned(.{
        .method = "GET",
        .authority = "localhost",
        .path = "/finite",
    }, 0, &owner);
    try std.testing.expectEqual(@as(?u62, 4), owner);
    try std.testing.expectEqual(@as(u62, 4), id);
    const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
    while ((if (fixture.peer.recvStreamStats(id)) |stats| stats.final_size else null) == null) {
        var packet = try fixture.peer.receivePacketServicingTimersDeadline(deadline);
        packet.deinit(std.testing.allocator);
    }
    const bytes = fixture.peer.availableReceivedStream(id).?;
    var request = try http3.decodeRequest(std.testing.allocator, bytes);
    defer request.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("GET", request.method);
    try std.testing.expectEqualStrings("/finite", request.path);
    try std.testing.expectEqual(@as(usize, 0), request.body.len);
    try std.testing.expectEqual(@as(?u64, bytes.len), fixture.peer.recvStreamStats(id).?.final_size);
}
