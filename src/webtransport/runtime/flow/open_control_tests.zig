//! Opening credit cannot bypass buffered terminal CONNECT Capsules.
const std = @import("std");
const control = @import("../session_control.zig");
const ClientFixture = @import("../endpoint_client/test_support.zig").Fixture;
const Pair = @import("../session_control/test_support/handshake_pair.zig").Pair;
const http3 = @import("../../../http3/mod.zig");

test "WebTransport shared client opens observe buffered CLOSE with available credit" {
    for ([_]bool{ false, true }) |uni| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var fixture: ClientFixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const session = try fixture.addSession();
        const sibling = try fixture.addSession();
        var bytes: [64]u8 = undefined;
        const capsule = try control.writeCloseInto(&bytes, 97, "before open");
        var wire: std.ArrayList(u8) = .empty;
        defer wire.deinit(std.testing.allocator);
        try (http3.Frame{ .frame_type = http3.FrameType.data, .payload = capsule, .consumed = 0 }).write(&wire, std.testing.allocator);
        try fixture.appendConnect(session, wire.items, false);
        const connection = &fixture.client.h3.established.connection;
        const next = if (uni) connection.nextLocalUnidirectionalStreamId() else connection.nextLocalBidirectionalStreamId();
        try std.testing.expectError(error.InvalidSessionState, if (uni) session.openUnidirectionalStream(&fixture.client) else session.openBidirectionalStream(&fixture.client));
        try std.testing.expectEqual(next, if (uni) connection.nextLocalUnidirectionalStreamId() else connection.nextLocalBidirectionalStreamId());
        try std.testing.expect(session.control.pending_closed);
        const event = session.control.takePending().?;
        try std.testing.expectEqual(@as(u32, 97), event.closed.code);
        try std.testing.expectEqualStrings("before open", event.closed.reason);
        _ = try sibling.openBidirectionalStream(&fixture.client);
        try std.testing.expect(!sibling.control.state.closed and !connection.closing());
    }
}

test "WebTransport owning client and server opens reject buffered CLOSE before reserving ids" {
    inline for (.{ .client, .server }) |role| {
        for ([_]bool{ false, true }) |uni| {
            for ([_]bool{ false, true }) |bounded| {
                var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
                defer threaded.deinit();
                var pair: Pair = undefined;
                try pair.init(threaded.io());
                defer pair.deinit();
                var bytes: [64]u8 = undefined;
                try pair.sendCapsules(role, try control.writeCloseInto(&bytes, 98, "owning"));
                const session = if (role == .client) &pair.client else &pair.server;
                const connection = pair.connection(role);
                const next = if (uni) connection.nextLocalUnidirectionalStreamId() else connection.nextLocalBidirectionalStreamId();
                const result = if (bounded)
                    if (uni) session.openUnidirectionalStreamWithTimeout(.fromSeconds(1)) else session.openBidirectionalStreamWithTimeout(.fromSeconds(1))
                else if (uni) session.openUnidirectionalStream() else session.openBidirectionalStream();
                try std.testing.expectError(error.InvalidSessionState, result);
                try std.testing.expectEqual(next, if (uni) connection.nextLocalUnidirectionalStreamId() else connection.nextLocalBidirectionalStreamId());
                const event = (try pair.poll(role)).?;
                try std.testing.expect(event == .closed);
                try std.testing.expectEqualStrings("owning", event.closed.reason);
            }
        }
    }
}
