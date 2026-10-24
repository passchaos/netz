const std = @import("std");
const webtransport = @import("../mod.zig");
const http3 = @import("../../http3/mod.zig");
const quic = @import("../../quic/mod.zig");
const Fixture = @import("endpoint_client/test_support.zig").Fixture;
const negotiation = @import("connect/negotiation.zig");
const PendingRequest = @import("connect/pending_request.zig").Request;
const runtime = @import("../runtime.zig");
const session_control = @import("session_control.zig");

test "WebTransport GOAWAY notifies every accepted server endpoint session once" {
    const ServerFixture = @import("endpoint_server/test_support.zig").Fixture;
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: ServerFixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    // Replace the fixture's simulated SETTINGS with their real wire prefix
    // before admission, so active Sessions always retain valid negotiation.
    fixture.client.control.settings.sent = false;
    fixture.connectionSession().control.settings.received = false;
    try fixture.client.ensureSettingsSent();
    while (!fixture.connectionSession().control.settings.received) try fixture.routeTransport();
    const first = try fixture.addSession();
    const second = try fixture.addSession();
    try fixture.client.sendGoAway(0);
    var seen: [2]u62 = undefined;
    var buffer: [32]u8 = undefined;
    for (&seen) |*id| {
        var event = try fixture.receive(&buffer);
        defer event.deinit(std.testing.allocator);
        try std.testing.expect(event == .session_event and event.session_event.event == .session and event.session_event.event.session == .draining);
        id.* = event.session_event.session_id.value;
    }
    try std.testing.expect(seen[0] != seen[1]);
    try std.testing.expect(first.control.state.draining and second.control.state.draining);
    // Session operations stay available after this connection-wide advisory.
    _ = try fixture.openPeerStream(first);
    try fixture.closePeer(second, "closed", &.{});
    try fixture.client.sendGoAway(0);
    try std.testing.expectError(error.Timeout, fixture.endpoint.receiveWithTimeout(&.{quic.Version.version_1.wireValue()}, .fromMilliseconds(5), &buffer));
    try std.testing.expect(first.control.state.draining and !first.control.state.closed);
    try std.testing.expect(second.control.state.closed);
}

test "WebTransport GOAWAY does not duplicate an earlier capsule or reopen a closed control" {
    const Reader = @import("protected_session_control.zig").Reader;
    var reader = Reader.init(try session_control.Control.init(std.testing.allocator, .init(0)));
    defer reader.deinit();
    var bytes: [16]u8 = undefined;
    try std.testing.expect((try reader.consume(try session_control.writeDrainInto(&bytes))).? == .draining);
    reader.control.observeGoAway(quic.varint.max_value - 3);
    try std.testing.expect((try reader.pollPending()) == null);
    reader.control.state.close(17);
    reader.control.peer_drain_reported = false;
    reader.control.observeGoAway(0);
    try std.testing.expect((try reader.pollPending()) == null);
    try std.testing.expect(!reader.control.state.draining);
    try std.testing.expectEqual(@as(?u32, 17), reader.control.state.close_code);
}

test "WebTransport GOAWAY retains native session data and deduplicates capsule drain" {
    const support = @import("session_control/test_support/handshake_pair.zig");
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]support.Role{ .client, .server }) |receiver| {
        var pair: support.Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        // The fixture pre-negotiates SETTINGS; transmit the actual critical
        // prefix before this test's first real GOAWAY on that direction.
        switch (receiver) {
            .client => {
                pair.server.h3.control.settings.sent = false;
                pair.client.h3.control.settings.received = false;
                try pair.server.h3.sendGoAway(quic.varint.max_value - 3);
            },
            .server => {
                pair.client.h3.control.settings.sent = false;
                pair.server.h3.control.settings.received = false;
                try pair.client.h3.sendGoAway(0);
            },
        }
        try std.testing.expect((try pair.receiveWithTimeout(receiver, .fromSeconds(1))) == .draining);
        try std.testing.expect(pair.control(receiver).state.draining);
        try pair.control(receiver).ensureOpen();
        switch (receiver) {
            .client => {
                _ = try pair.client.openBidirectionalStream();
                try pair.client.sendDatagram("still open");
                var datagram = try pair.server.receiveDatagramWithTimeout(.fromSeconds(1));
                defer datagram.deinit(std.testing.allocator);
                try std.testing.expectEqualStrings("still open", datagram.datagram.payload);
                try pair.server.h3.sendGoAway(4);
            },
            .server => {
                _ = try pair.server.openBidirectionalStream();
                try pair.server.sendDatagram("still open");
                var datagram = try pair.client.receiveDatagramWithTimeout(.fromSeconds(1));
                defer datagram.deinit(std.testing.allocator);
                try std.testing.expectEqualStrings("still open", datagram.datagram.payload);
                try pair.client.h3.sendGoAway(0);
            },
        }
        // A later DRAIN capsule is fully parsed but cannot duplicate GOAWAY's
        // advisory. Its following CLOSE still reaches the application intact.
        var drain_storage: [16]u8 = undefined;
        try pair.sendCapsules(receiver, try session_control.writeDrainInto(&drain_storage));
        try std.testing.expect((try pair.poll(receiver)) == null);
        var close_storage: [64]u8 = undefined;
        try pair.sendCapsules(receiver, try session_control.writeCloseInto(&close_storage, 91, "after GOAWAY"));
        const close = try pair.receiveWithTimeout(receiver, .fromSeconds(1));
        try std.testing.expect(close == .closed);
        try std.testing.expectEqual(@as(u32, 91), close.closed.code);
        try std.testing.expectEqualStrings("after GOAWAY", close.closed.reason);
    }
}

test "WebTransport GOAWAY protected readers wake on control-only packets in both roles" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const keys = quic.protection.deriveAes128Keys([_]u8{0x93} ** quic.protection.secret_len);
    var server = try runtime.ProtectedServer.bind(std.testing.allocator, io, .{ .ip4 = .loopback(0) }, .{}, .{
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "goaway-server",
        .peer_connection_id = "goaway-client",
    });
    defer server.deinit();
    const Shared = struct {
        fn run(target: *runtime.ProtectedServer) !void {
            var pending = try target.receiveSessionRequestWithTimeout(.fromSeconds(2));
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            var accepted = try pending.accept();
            pending_owned = false;
            defer accepted.deinit(std.testing.allocator);
            try target.h3.sendGoAway(accepted.request.from, quic.varint.max_value - 3);
            const event = try accepted.receiveSessionEventWithTimeout(target, .fromSeconds(2));
            try std.testing.expect(event == .draining);
            try std.testing.expect(accepted.control.control.state.draining and !accepted.control.control.state.closed);
            try accepted.close(target, 92, "protected GOAWAY");
            const finished = try accepted.receiveSessionEventWithTimeout(target, .fromSeconds(2));
            try std.testing.expect(finished == .closed);
        }
    };
    var future = std.Io.async(io, Shared.run, .{&server});
    defer future.cancel(io) catch {};
    var client = try runtime.ProtectedClientSession.connectWithTimeout(std.testing.allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .authority = "localhost",
        .path = "/goaway",
        .origin = "https://localhost",
        .config = .{ .receive_keys = keys, .send_keys = keys, .local_connection_id = "goaway-client", .peer_connection_id = "goaway-server" },
    }, .fromSeconds(2));
    defer client.deinit();
    try std.testing.expect((try client.receiveSessionEventWithTimeout(.fromSeconds(2))) == .draining);
    try std.testing.expect(client.control.control.state.draining and !client.control.control.state.closed);
    try client.h3.sendGoAway(0);
    const close = try client.receiveSessionEventWithTimeout(.fromSeconds(2));
    try std.testing.expect(close == .closed);
    try std.testing.expectEqual(@as(u32, 92), close.closed.code);
    try std.testing.expectEqualStrings("protected GOAWAY", close.closed.reason);
    try future.await(io);
}

test "WebTransport GOAWAY notifies every active endpoint session" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const first = try fixture.addSession();
    const second = try fixture.addSession();
    var control: http3.ControlState = .{};
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try control.writeSettingsStream(&bytes, std.testing.allocator, fixture.client.h3.options.local_settings);
    try control.writeGoAway(&bytes, std.testing.allocator, quic.varint.max_value - 3);
    fixture.client.h3.control.settings.received = false;
    try fixture.peer.send(&.{.{ .stream = .{ .stream_id = 3, .data = bytes.items } }});
    const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
    while (fixture.client.h3.control.peer_goaway_id == null) {
        try fixture.client.h3.receiveDetachedResponseProgressWithDeadline(first.session_id.value, deadline);
    }
    for ([_]*@import("endpoint_client.zig").Session{ first, second }) |session| {
        const event = (try fixture.poll(session)) orelse return error.TestUnexpectedResult;
        try std.testing.expect(event == .session and event.session == .draining);
        try std.testing.expect(session.control.state.draining and !session.control.state.closed);
        try std.testing.expect((try fixture.poll(session)) == null);
        try session.sendDatagram(&fixture.client, "after GOAWAY");
        _ = try session.openBidirectionalStream(&fixture.client);
    }
}

test "WebTransport GOAWAY rejects fresh CONNECT before allocation or stream reservation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const h3 = &fixture.client.h3;
    h3.control.peer_goaway_id = quic.varint.max_value - 3;
    var pending = try PendingRequest.init(std.testing.allocator, "localhost", "/late", "https://localhost", &.{});
    defer pending.deinit(std.testing.allocator);
    const packet_number = h3.established.connection.next_packet_number;
    const stream_id = h3.next_stream_id;
    const transport_id = h3.established.connection.nextLocalBidirectionalStreamId();
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    h3.allocator = failing.allocator();
    fixture.client.allocator = failing.allocator();
    defer {
        h3.allocator = std.testing.allocator;
        fixture.client.allocator = std.testing.allocator;
    }
    try std.testing.expectError(error.GoAwayReceived, negotiation.prepareClient(h3, null));
    try std.testing.expectError(error.GoAwayReceived, pending.submit(h3, .draft16, stream_id));
    try std.testing.expectError(error.GoAwayReceived, fixture.client.openSessionAttempt(.{
        .authority = "localhost",
        .path = "/late",
        .origin = "https://localhost",
    }));
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(packet_number, h3.established.connection.next_packet_number);
    try std.testing.expectEqual(stream_id, h3.next_stream_id);
    try std.testing.expectEqual(transport_id, h3.established.connection.nextLocalBidirectionalStreamId());
    try std.testing.expectEqual(@as(usize, 0), h3.request_lifecycle.count());
    try std.testing.expect(!pending.prepared and !pending.reserved);
}
