//! Owning sends observe an already received CLOSE before submitting new data.
const std = @import("std");
const control_mod = @import("../session_control.zig");
const ClientFixture = @import("../endpoint_client/test_support.zig").Fixture;
const Pair = @import("test_support/handshake_pair.zig").Pair;
const ServerFixture = @import("../endpoint_server/test_support.zig").Fixture;
const runtime = @import("../../runtime.zig");

const Send = enum { one, one_timeout, one_deadline, many, many_timeout, many_deadline };

fn send(session: anytype, kind: Send, deadline: std.Io.Clock.Timestamp, committed: *usize) !void {
    switch (kind) {
        .one => try session.sendDatagram("too late"),
        .one_timeout => try session.sendDatagramWithTimeout("too late", .fromSeconds(1)),
        .one_deadline => try session.sendDatagramWithDeadline("too late", deadline),
        .many => try session.sendDatagrams(&.{ "too late", "also late" }, committed),
        .many_timeout => try session.sendDatagramsWithTimeout(&.{ "too late", "also late" }, committed, .fromSeconds(1)),
        .many_deadline => try session.sendDatagramsWithDeadline(&.{ "too late", "also late" }, committed, deadline),
    }
}

test "WebTransport shared DATAGRAM send observes buffered CLOSE without losing its event" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |bounded| {
        var fixture: ClientFixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const closing = try fixture.addSession();
        const sibling = try fixture.addSession();
        try fixture.close(closing, &.{});
        try std.testing.expect(!closing.control.state.closed);
        const connection = &fixture.client.h3.established.connection;
        const packet_number = connection.next_packet_number;
        if (bounded) {
            try std.testing.expectError(error.InvalidSessionState, closing.sendDatagramWithTimeout(&fixture.client, "too late", .fromSeconds(1)));
        } else {
            try std.testing.expectError(error.InvalidSessionState, closing.sendDatagram(&fixture.client, "too late"));
        }
        try std.testing.expectEqual(packet_number, connection.next_packet_number);
        try fixture.expectClose(closing);
        try fixture.queueDatagram(sibling, "sibling");
        var event = (try fixture.poll(sibling)).?;
        defer event.deinit(std.testing.allocator);
        try std.testing.expect(event == .datagram);
        try std.testing.expectEqualStrings("sibling", event.datagram.payload);
        try sibling.sendDatagram(&fixture.client, "still open");
        try std.testing.expect(!connection.closing() and !sibling.control.state.closed);
    }
}

test "WebTransport DATAGRAM send observes buffered peer CLOSE on both endpoint roles" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    inline for (.{ .client, .server }) |role| {
        for (std.enums.values(Send)) |kind| {
            var pair: Pair = undefined;
            try pair.init(threaded.io());
            defer pair.deinit();
            var storage: [64]u8 = undefined;
            try pair.sendCapsules(role, try control_mod.writeCloseInto(&storage, 91, "done"));
            const session = if (role == .client) &pair.client else &pair.server;
            const connection = pair.connection(role);
            const packet_number = connection.next_packet_number;
            var committed: usize = 99;
            const deadline: std.Io.Clock.Timestamp = .fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
            try std.testing.expectError(error.InvalidSessionState, send(session, kind, deadline, &committed));
            if (kind == .many or kind == .many_timeout or kind == .many_deadline) try std.testing.expectEqual(@as(usize, 0), committed);
            try std.testing.expectEqual(packet_number, connection.next_packet_number);
            const event = (try pair.poll(role)).?;
            try std.testing.expect(event == .closed);
            try std.testing.expectEqual(@as(u32, 91), event.closed.code);
            try std.testing.expectEqualStrings("done", event.closed.reason);
            try std.testing.expect(!connection.closing());
        }
    }
}

test "WebTransport shared server DATAGRAM send observes CLOSE before application polling" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |batch| {
        var fixture: ServerFixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const closing = try fixture.addSession();
        const sibling = try fixture.addSession();
        var storage: [64]u8 = undefined;
        try fixture.client.sendRequestBodyPaced(closing.session_id.value, try control_mod.writeCloseInto(&storage, 91, "done"), false);
        const connection = &fixture.connectionSession().established.connection;
        while ((connection.availableReceivedStream(closing.session_id.value) orelse @as([]const u8, &.{})).len == 0) try fixture.routeTransport();
        const packet_number = connection.next_packet_number;
        var committed: usize = 99;
        if (batch) {
            try std.testing.expectError(error.InvalidSessionState, closing.sendDatagrams(&.{ "too late", "also late" }, &committed));
            try std.testing.expectEqual(@as(usize, 0), committed);
        } else try std.testing.expectError(error.InvalidSessionState, closing.sendDatagram("too late"));
        try std.testing.expectEqual(packet_number, connection.next_packet_number);
        var output: [16]u8 = undefined;
        const event = (try runtime.EndpointServer.testing.pollAcceptedSessionEntry(closing, &output)).?;
        try std.testing.expect(event == .session and event.session == .closed);
        try std.testing.expectEqual(@as(u32, 91), event.session.closed.code);
        try std.testing.expectEqualStrings("done", event.session.closed.reason);
        try sibling.sendDatagram("still open");
        _ = try sibling.openBidirectionalStream();
        try std.testing.expect(!connection.closing() and !sibling.control.state.closed);
    }
}

test "WebTransport DATAGRAM send preserves advisory DRAIN events and keeps sending" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    inline for (.{ .client, .server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        var storage: [16]u8 = undefined;
        try pair.sendCapsules(role, try control_mod.writeDrainInto(&storage));
        const session = if (role == .client) &pair.client else &pair.server;
        try session.sendDatagram("still open");
        try std.testing.expect(!session.control.state.closed);
        try std.testing.expect(session.control.state.draining);
        try std.testing.expect((try pair.poll(role)).? == .draining);
        try std.testing.expect((try pair.poll(role)) == null);
    }
}

test "WebTransport DATAGRAM invalid deadline leaves buffered CLOSE untouched" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    inline for (.{ .client, .server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        var storage: [64]u8 = undefined;
        try pair.sendCapsules(role, try control_mod.writeCloseInto(&storage, 91, "done"));
        const session = if (role == .client) &pair.client else &pair.server;
        const connection = pair.connection(role);
        const before = connection.recvStreamStats(0).?.bytes_read;
        try std.testing.expectError(error.Timeout, session.sendDatagramWithDeadline("late", .{ .raw = .zero, .clock = .real }));
        try std.testing.expectEqual(before, connection.recvStreamStats(0).?.bytes_read);
        try std.testing.expect(!session.control.state.closed);
        const event = (try pair.poll(role)).?;
        try std.testing.expect(event == .closed);
        try std.testing.expectEqualStrings("done", event.closed.reason);
    }
}

test "WebTransport DATAGRAM CLOSE preflight allocation failure retains parser input" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    inline for (.{ .client, .server }) |role| {
        var pair: Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        const reason = "reason" ** 40;
        var storage: [256]u8 = undefined;
        try pair.sendCapsules(role, try control_mod.writeCloseInto(&storage, 91, reason));
        const session = if (role == .client) &pair.client else &pair.server;
        const connection = pair.connection(role);
        const before = connection.recvStreamStats(0).?.bytes_read;
        const packet_number = connection.next_packet_number;
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        session.control.allocator = failing.allocator();
        defer session.control.allocator = std.testing.allocator;
        try std.testing.expectError(error.OutOfMemory, session.sendDatagram("late"));
        try std.testing.expect(failing.has_induced_failure);
        try std.testing.expectEqual(before, connection.recvStreamStats(0).?.bytes_read);
        try std.testing.expectEqual(packet_number, connection.next_packet_number);
        try std.testing.expect(!session.control.state.closed and !connection.closing());
        session.control.allocator = std.testing.allocator;
        try std.testing.expectError(error.InvalidSessionState, session.sendDatagram("late"));
        const event = (try pair.poll(role)).?;
        try std.testing.expect(event == .closed);
        try std.testing.expectEqual(@as(u32, 91), event.closed.code);
        try std.testing.expectEqualStrings(reason, event.closed.reason);
    }
}
