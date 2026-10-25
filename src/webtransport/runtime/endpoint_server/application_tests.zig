//! Buffered Session control precedes shared-server application operations.
const std = @import("std");
const runtime = @import("../../runtime.zig");
const control = @import("../session_control.zig");
const Fixture = @import("test_support.zig").Fixture;
const webtransport = @import("../../mod.zig");
const ObservedSend = @import("../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;

const Operation = enum { open_bidi, open_uni, write, write_slices, send, send_slices, batch, finish, priority, session_data, session_slices, drain, grant_data, grant_streams };

fn apply(session: *runtime.EndpointAcceptedSession, id: u62, operation: Operation, counts: []usize) !void {
    switch (operation) {
        .open_bidi => _ = try session.openBidirectionalStream(),
        .open_uni => _ = try session.openUnidirectionalStream(),
        .write => _ = try session.writeStream(id, "late"),
        .write_slices => _ = try session.writeStreamSlices(id, &.{ "la", "te" }),
        .send => try session.sendStream(id, "late", true),
        .send_slices => try session.sendStreamSlices(id, &.{ "la", "te" }, true),
        .batch => _ = try session.writeStreams(&.{.{ .stream_id = id, .data = "late" }}, counts),
        .finish => try session.finishStream(id),
        .priority => try session.setStreamPriority(id, 7),
        .session_data => try session.sendSessionData(&.{ 0x21, 0 }, false),
        .session_slices => try session.sendSessionDataSlices(&.{ &.{0x21}, &.{0} }, false),
        .drain => try session.drain(),
        .grant_data => try session.grantData((session.streams.flow orelse return error.WebTransportNotNegotiated).receive_limit.data + 1),
        .grant_streams => try session.grantStreams(.bidirectional, (session.streams.flow orelse return error.WebTransportNotNegotiated).receive_limit.bidi + 1),
    }
}

fn buffer(fixture: *Fixture, session: *runtime.EndpointAcceptedSession, bytes: []const u8) !void {
    try fixture.client.sendRequestBodyPaced(session.session_id.value, bytes, false);
    const connection = &fixture.connectionSession().established.connection;
    while ((connection.availableReceivedStream(session.session_id.value) orelse @as([]const u8, &.{})).len == 0) try fixture.routeTransport();
}

test "WebTransport shared server application operations reject buffered CLOSE before submission" {
    for (std.enums.values(Operation)) |operation| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const session = try fixture.addSession();
        const sibling = try fixture.addSession();
        const id = try session.openBidirectionalStream();
        var storage: [64]u8 = undefined;
        try buffer(&fixture, session, try control.writeCloseInto(&storage, 95, "done"));
        const connection = &fixture.connectionSession().established.connection;
        const packet_number = connection.next_packet_number;
        const bidi = connection.nextLocalBidirectionalStreamId();
        const uni = connection.nextLocalUnidirectionalStreamId();
        var counts = [_]usize{99};
        try std.testing.expectError(error.InvalidSessionState, apply(session, id, operation, &counts));
        try std.testing.expectEqual(packet_number, connection.next_packet_number);
        try std.testing.expectEqual(bidi, connection.nextLocalBidirectionalStreamId());
        try std.testing.expectEqual(uni, connection.nextLocalUnidirectionalStreamId());
        try std.testing.expectEqual(@as(u64, 0), session.streams.get(id).?.bytes_sent);
        try std.testing.expect(!session.streams.get(id).?.local_fin);
        if (operation == .batch) try std.testing.expectEqual(@as(usize, 0), counts[0]);
        var output: [16]u8 = undefined;
        const event = (try runtime.EndpointServer.testing.pollAcceptedSessionEntry(session, &output)).?;
        try std.testing.expect(event == .session and event.session == .closed);
        try std.testing.expectEqual(@as(u32, 95), event.session.closed.code);
        try std.testing.expectEqualStrings("done", event.session.closed.reason);
        const sibling_id = try sibling.openBidirectionalStream();
        try sibling.sendStream(sibling_id, "live", true);
        try sibling.sendDatagram("live");
        try std.testing.expect(!sibling.control.state.closed and !connection.closing());
    }
}

test "WebTransport shared server application operations preserve advisory DRAIN" {
    for (std.enums.values(Operation)) |operation| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const session = try fixture.addSession();
        const id = try session.openBidirectionalStream();
        try session.sendStream(id, "prefix", false);
        var bytes: [16]u8 = undefined;
        try buffer(&fixture, session, try control.writeDrainInto(&bytes));
        var counts = [_]usize{99};
        try apply(session, id, operation, &counts);
        try std.testing.expect(session.control.state.draining and !session.control.state.closed);
        var output: [16]u8 = undefined;
        const event = (try runtime.EndpointServer.testing.pollAcceptedSessionEntry(session, &output)).?;
        try std.testing.expect(event == .session and event.session == .draining);
        try std.testing.expect((try runtime.EndpointServer.testing.pollAcceptedSessionEntry(session, &output)) == null);
    }
}

test "WebTransport shared server application operations retain CLOSE input across allocation failure" {
    for (std.enums.values(Operation)) |operation| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const session = try fixture.addSession();
        const id = try session.openBidirectionalStream();
        const reason = [_]u8{'r'} ** 200;
        var bytes: [240]u8 = undefined;
        try buffer(&fixture, session, try control.writeCloseInto(&bytes, 96, &reason));
        const connection = &fixture.connectionSession().established.connection;
        const before = connection.recvStreamStats(session.session_id.value).?.bytes_read;
        const bidi = connection.nextLocalBidirectionalStreamId();
        const uni = connection.nextLocalUnidirectionalStreamId();
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        session.control.allocator = failing.allocator();
        var counts = [_]usize{99};
        try std.testing.expectError(error.OutOfMemory, apply(session, id, operation, &counts));
        try std.testing.expect(!session.control.state.closed);
        try std.testing.expectEqual(before, connection.recvStreamStats(session.session_id.value).?.bytes_read);
        try std.testing.expectEqual(bidi, connection.nextLocalBidirectionalStreamId());
        try std.testing.expectEqual(uni, connection.nextLocalUnidirectionalStreamId());
        if (operation == .batch) try std.testing.expectEqual(@as(usize, 0), counts[0]);
        failing.fail_index = std.math.maxInt(usize);
        try std.testing.expectError(error.InvalidSessionState, apply(session, id, operation, &counts));
        var output: [16]u8 = undefined;
        const event = (try runtime.EndpointServer.testing.pollAcceptedSessionEntry(session, &output)).?;
        try std.testing.expect(event == .session and event.session == .closed);
        try std.testing.expectEqualStrings(&reason, event.session.closed.reason);
        try std.testing.expectEqual(@as(u32, 96), event.session.closed.code);
    }
}

test "WebTransport application preflight cannot bypass CLOSE under receive credit backpressure" {
    for (std.enums.values(Operation)) |operation| {
        var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
        defer threaded.deinit();
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const session = try fixture.addSession();
        const id = try session.openBidirectionalStream();
        var storage: [64]u8 = undefined;
        try buffer(&fixture, session, try control.writeCloseInto(&storage, 99, "credit blocked"));
        const connection = &fixture.connectionSession().established.connection;
        // Consuming the CLOSE now owes MAX_DATA. Congestion prevents that
        // transaction from committing, so the Capsule bytes remain unread.
        connection.recv_flow.limit = connection.recv_flow.highest_received;
        const before = connection.recvStreamStats(session.session_id.value).?.bytes_read;
        const limit = connection.recv_flow.limit;
        const window = connection.congestion.congestion_window;
        const bidi = connection.nextLocalBidirectionalStreamId();
        const uni = connection.nextLocalUnidirectionalStreamId();
        connection.congestion.congestion_window = 0;
        var counts = [_]usize{99};
        try std.testing.expectError(error.CongestionLimited, apply(session, id, operation, &counts));
        try std.testing.expectEqual(before, connection.recvStreamStats(session.session_id.value).?.bytes_read);
        try std.testing.expectEqual(limit, connection.recv_flow.limit);
        try std.testing.expectEqual(bidi, connection.nextLocalBidirectionalStreamId());
        try std.testing.expectEqual(uni, connection.nextLocalUnidirectionalStreamId());
        connection.congestion.congestion_window = window;
        const original_io = connection.endpoint.io;
        var observed = ObservedSend{ .delegate = original_io, .fail_on_call = 1 };
        var vtable = original_io.vtable.*;
        vtable.netSend = ObservedSend.netSend;
        connection.endpoint.io = .{ .userdata = &observed, .vtable = &vtable };
        {
            defer connection.endpoint.io = original_io;
            try std.testing.expectError(error.NetworkDown, apply(session, id, operation, &counts));
        }
        try std.testing.expectEqual(before, connection.recvStreamStats(session.session_id.value).?.bytes_read);
        try std.testing.expectEqual(limit, connection.recv_flow.limit);
        try std.testing.expectEqual(bidi, connection.nextLocalBidirectionalStreamId());
        try std.testing.expectEqual(uni, connection.nextLocalUnidirectionalStreamId());
        try std.testing.expectError(error.InvalidSessionState, apply(session, id, operation, &counts));
        var output: [16]u8 = undefined;
        const event = (try runtime.EndpointServer.testing.pollAcceptedSessionEntry(session, &output)).?;
        try std.testing.expect(event == .session and event.session == .closed);
        try std.testing.expectEqualStrings("credit blocked", event.session.closed.reason);
    }
}

test "WebTransport shared server batch output capacity fails before consuming CLOSE" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const session = try fixture.addSession();
    const id = try session.openBidirectionalStream();
    var storage: [64]u8 = undefined;
    try buffer(&fixture, session, try control.writeCloseInto(&storage, 100, "capacity"));
    const connection = &fixture.connectionSession().established.connection;
    const before = connection.recvStreamStats(session.session_id.value).?.bytes_read;
    try std.testing.expectError(error.BufferTooShort, session.writeStreams(&.{.{ .stream_id = id, .data = "late" }}, &.{}));
    try std.testing.expectEqual(before, connection.recvStreamStats(session.session_id.value).?.bytes_read);
    try std.testing.expect(!session.control.state.closed);
    var counts = [_]usize{99};
    try std.testing.expectError(error.InvalidSessionState, session.writeStreams(&.{.{ .stream_id = id, .data = "late" }}, &counts));
    try std.testing.expectEqual(@as(usize, 0), counts[0]);
}
