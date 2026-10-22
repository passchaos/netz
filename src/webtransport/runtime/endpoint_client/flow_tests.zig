const std = @import("std");
const webtransport = @import("../../mod.zig");
const http3 = @import("../../../http3/mod.zig");
const Fixture = @import("test_support.zig").Fixture;

test "WebTransport endpoint client routes flow grants to one shared session" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const first = try fixture.addSession();
    const second = try fixture.addSession();
    const initial = first.streams.flow.?.send_limit.bidi;
    var capsule_bytes: [32]u8 = undefined;
    const grant = try (webtransport.Capsule{ .max_streams_bidi = initial + 1 }).writeInto(&capsule_bytes);
    var framed: std.ArrayList(u8) = .empty;
    defer framed.deinit(std.testing.allocator);
    try (http3.Frame{ .frame_type = http3.FrameType.data, .payload = grant, .consumed = 0 }).write(&framed, std.testing.allocator);
    try fixture.appendConnect(first, framed.items, false);
    try std.testing.expect((try fixture.poll(first)) == null);
    try std.testing.expectEqual(initial + 1, first.streams.flow.?.send_limit.bidi);
    try std.testing.expectEqual(initial, second.streams.flow.?.send_limit.bidi);
    // A duplicate update terminates only the affected CONNECT.
    try fixture.appendConnect(first, framed.items, false);
    try std.testing.expectError(error.FlowControlViolation, fixture.poll(first));
    try std.testing.expect(first.control.state.closed);
    try std.testing.expect(!second.control.state.closed);
    _ = try second.openBidirectionalStream(&fixture.client);
    try std.testing.expect(!fixture.client.h3.established.connection.closing());
}
