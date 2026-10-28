const std = @import("std");
const webtransport = @import("../../mod.zig");
const http3 = @import("../../../http3/mod.zig");
const lifecycle = @import("../connection_lifecycle.zig");
const control_mod = @import("../session_control.zig");
const Fixture = @import("../endpoint_client/test_support.zig").Fixture;
const ServerFixture = @import("../endpoint_server/test_support.zig").Fixture;
const runtime = @import("../../runtime.zig");
const allocator = std.testing.allocator;

test "WebTransport committed CLOSE metadata survives later flow rejection" {
    for ([_]usize{ 24, 512 }) |size| {
        for ([_]bool{ false, true }) |delivered| {
            var threaded = std.Io.Threaded.init(allocator, .{});
            defer threaded.deinit();
            var fixture: Fixture = undefined;
            try fixture.init(threaded.io());
            defer fixture.deinit();
            const session = try fixture.addSession();
            const sibling = try fixture.addSession();
            var capsule_storage: [1100]u8 = undefined;
            const reason = "r" ** 512;
            const capsule = try control_mod.writeCloseInto(&capsule_storage, 77, reason[0..size]);
            var wire: std.ArrayList(u8) = .empty;
            defer wire.deinit(allocator);
            try (http3.Frame{ .frame_type = http3.FrameType.data, .payload = capsule, .consumed = 0 }).write(&wire, allocator);
            try fixture.appendConnect(session, wire.items, false);
            const connection = &fixture.client.h3.established.connection;
            var borrowed: ?control_mod.Event.Close = null;
            if (delivered) {
                var event = (try fixture.poll(session)) orelse return error.TestUnexpectedResult;
                defer event.deinit(allocator);
                try std.testing.expect(event == .session and event.session == .closed);
                borrowed = event.session.closed;
            } else {
                try session.control.progressBuffered(connection);
                try std.testing.expect(session.control.pending_closed);
            }
            const heap = session.control.close_reason_heap;
            // Feed the lifecycle layer an already recognized stream-flow
            // violation. Its real QUIC scoped cancellation must not change
            // an earlier application CLOSE or invalidate a borrowed reason.
            session.streams.flow_violation = true;
            _ = lifecycle.observeWithoutCredits(&session.control, &fixture.client.h3, &session.streams);
            try std.testing.expect(session.control.handledInvalidCapsule());
            try std.testing.expectEqual(@as(?u32, 77), session.control.state.close_code);
            try std.testing.expectEqual(size, session.control.close_reason_len);
            if (heap) |saved| {
                try std.testing.expect(session.control.close_reason_heap != null);
                try std.testing.expectEqual(saved.ptr, session.control.close_reason_heap.?.ptr);
            }
            if (!delivered) {
                const event = session.control.takePending() orelse return error.TestUnexpectedResult;
                try std.testing.expect(event == .closed);
                borrowed = event.closed;
            }
            try std.testing.expectEqualStrings(reason[0..size], borrowed.?.reason);
            try std.testing.expectEqual(webtransport.ApplicationErrorCode.flow_control_error, connection.sendStreamStats(session.session_id.value).?.reset.?.application_error_code);
            try fixture.queueDatagram(sibling, "sibling survives");
            var event = (try fixture.poll(sibling)) orelse return error.TestUnexpectedResult;
            defer event.deinit(allocator);
            try std.testing.expectEqualStrings("sibling survives", event.datagram.payload);
            try std.testing.expect(!connection.closing());
        }
    }
}

test "WebTransport server committed CLOSE metadata survives later scoped rejection" {
    for ([_]usize{ 24, 512 }) |size| {
        var threaded = std.Io.Threaded.init(allocator, .{});
        defer threaded.deinit();
        var fixture: ServerFixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const session = try fixture.addSession();
        const sibling = try fixture.addSession();
        const reason = "s" ** 512;
        var storage: [1100]u8 = undefined;
        const capsule = try control_mod.writeCloseInto(&storage, 78, reason[0..size]);
        try fixture.client.sendRequestBodyPaced(session.session_id.value, capsule, false);
        const connection = &fixture.connectionSession().established.connection;
        while ((connection.availableReceivedStream(session.session_id.value) orelse @as([]const u8, &.{})).len == 0) try fixture.routeTransport();
        var output: [32]u8 = undefined;
        const event = (try runtime.EndpointServer.testing.pollAcceptedSessionEntry(session, &output)) orelse return error.TestUnexpectedResult;
        try std.testing.expect(event == .session and event.session == .closed);
        const borrowed = event.session.closed;
        session.streams.flow_violation = true;
        _ = lifecycle.observeWithoutCredits(&session.control, session.h3, &session.streams);
        try std.testing.expect(session.control.handledInvalidCapsule());
        try std.testing.expectEqual(size, session.control.close_reason_len);
        try std.testing.expectEqual(@as(u32, 78), borrowed.code);
        try std.testing.expectEqualStrings(reason[0..size], borrowed.reason);
        _ = try sibling.openBidirectionalStream();
        try std.testing.expect(!connection.closing());
    }
}

test "WebTransport rejected incomplete CLOSE releases uncommitted reason storage" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    var storage: [1100]u8 = undefined;
    const capsule = try control_mod.writeCloseInto(&storage, 79, "t" ** 512);
    const partial = try session.control.feedCapsulePayload(capsule[0 .. capsule.len - 1]);
    try std.testing.expect(partial.event == null and !session.control.terminal_reported);
    try std.testing.expect(session.control.close_reason_heap != null);
    try std.testing.expectError(error.InvalidCapsule, session.control.finishCapsulePayload());
    try std.testing.expect(try session.control.rejectInvalidCapsule(&fixture.client.h3.established.connection));
    try std.testing.expect(session.control.close_reason_heap == null);
    try std.testing.expectEqual(@as(usize, 0), session.control.close_reason_len);
    try std.testing.expect(session.control.takePending() == null);
}
