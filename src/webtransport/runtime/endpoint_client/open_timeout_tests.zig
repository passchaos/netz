const std = @import("std");
const quic = @import("../../../quic/mod.zig");
const http3 = @import("../../../http3/mod.zig");
const webtransport = @import("../../mod.zig");
const prefix = @import("../stream/prefix.zig");
const Fixture = @import("test_support.zig").Fixture;

const SaturateAfterSend = struct {
    delegate: std.Io,
    connection: *quic.one_rtt.Connection,
    calls: usize = 0,
    pace: bool = false,
    fail_cancel: bool = false,
    fail_allocator: ?*std.testing.FailingAllocator = null,

    // Preserve Threaded's userdata for receive and deadline callbacks.
    var active: ?*SaturateAfterSend = null;

    fn netSend(
        userdata: ?*anyopaque,
        socket_handle: std.Io.net.Socket.Handle,
        messages: []std.Io.net.OutgoingMessage,
        flags: std.Io.net.SendFlags,
    ) struct { ?std.Io.net.Socket.SendError, usize } {
        const self = active.?;
        if (self.fail_cancel and self.calls == 1) {
            self.calls += 1;
            return .{ error.NetworkDown, 0 };
        }
        const result = self.delegate.vtable.netSend(userdata, socket_handle, messages, flags);
        if (self.calls == 0 and result[1] != 0) {
            // Congestion is reserved before socket submission. Pacing credit
            // is committed afterwards, so record an exhausted bucket now.
            if (self.fail_allocator) |allocator| allocator.fail_index = allocator.alloc_index;
            if (self.pace) {
                self.connection.pacer = quic.pacing.Pacer.initWithRateLimit(true, 4096, 1, 128);
                self.connection.pacer.budget = 0;
                self.connection.pacer.setLastSentTimeNs(@intCast(std.Io.Clock.awake.now(self.delegate).nanoseconds));
            } else if (!self.fail_cancel) {
                self.connection.congestion.congestion_window = self.connection.congestion.bytes_in_flight;
            }
        }
        self.calls += 1;
        return result;
    }
};

test "WebTransport shared client CONNECT timeout preserves sibling under cancellation congestion" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const sibling = try fixture.addSession();
    const connection = &fixture.client.h3.established.connection;
    const original_io = connection.endpoint.io;
    var observer = SaturateAfterSend{ .delegate = original_io, .connection = connection };
    SaturateAfterSend.active = &observer;
    defer SaturateAfterSend.active = null;
    var vtable = original_io.vtable.*;
    vtable.netSend = SaturateAfterSend.netSend;
    connection.endpoint.io = .{ .userdata = original_io.userdata, .vtable = &vtable };
    defer connection.endpoint.io = original_io;

    try std.testing.expectError(error.Timeout, fixture.client.openSessionAttemptWithTimeout(.{
        .authority = "localhost",
        .path = "/no-response",
        .origin = "https://localhost",
    }, .fromMilliseconds(10)));
    try std.testing.expect(observer.calls != 0);
    try std.testing.expectEqual(@as(u62, 8), fixture.client.h3.next_stream_id);
    try std.testing.expect(!connection.closing());
    try std.testing.expect(fixture.client.session(sibling.session_id) == sibling);
    try std.testing.expect(!sibling.control.state.closed);
    try std.testing.expectEqual(@as(usize, 1), fixture.client.pending_open_cleanup.count());
    try std.testing.expect(fixture.client.h3.request_lifecycle.contains(4));
    try std.testing.expect(connection.sendStreamStats(4).?.reset == null);
    try std.testing.expect(connection.recvStreamStats(4).?.stop_sending_sent == null);
    // Pending cleanup consumes the second admission slot without blocking an
    // already buffered sibling event or transmitting another CONNECT.
    for (0..3) |_| try std.testing.expectError(error.SessionLimitExceeded, fixture.client.openSessionAttemptWithTimeout(.{
        .authority = "localhost",
        .path = "/still-full",
    }, .fromMilliseconds(10)));
    try std.testing.expectEqual(@as(u62, 8), fixture.client.h3.next_stream_id);
    try fixture.queueDatagram(sibling, "buffered");
    var event = (try fixture.poll(sibling)) orelse return error.TestUnexpectedResult;
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .datagram);
    try std.testing.expectEqualStrings("buffered", event.datagram.payload);
    connection.congestion.congestion_window = 64 * 1024;
    try finishCancellation(&fixture);
    try std.testing.expectError(error.Timeout, fixture.client.openSessionAttemptWithTimeout(.{
        .authority = "localhost",
        .path = "/capacity-restored",
    }, .fromMilliseconds(10)));
    try std.testing.expectEqual(@as(u62, 12), fixture.client.h3.next_stream_id);
    try std.testing.expectEqual(@as(usize, 0), fixture.client.pending_open_cleanup.count());
}

test "WebTransport shared client CONNECT timeout does not wait for cancellation pacing" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const sibling = try fixture.addSession();
    const connection = &fixture.client.h3.established.connection;
    const original_io = connection.endpoint.io;
    var observer = SaturateAfterSend{ .delegate = original_io, .connection = connection, .pace = true };
    SaturateAfterSend.active = &observer;
    defer SaturateAfterSend.active = null;
    var vtable = original_io.vtable.*;
    vtable.netSend = SaturateAfterSend.netSend;
    connection.endpoint.io = .{ .userdata = original_io.userdata, .vtable = &vtable };
    defer connection.endpoint.io = original_io;
    const start = std.Io.Clock.awake.now(original_io);
    try std.testing.expectError(error.Timeout, fixture.client.openSessionAttemptWithTimeout(.{
        .authority = "localhost",
        .path = "/no-response",
        .origin = "https://localhost",
    }, .fromMilliseconds(10)));
    const elapsed = start.durationTo(std.Io.Clock.awake.now(original_io));
    try std.testing.expect(elapsed.nanoseconds < std.Io.Duration.fromMilliseconds(200).nanoseconds);
    try std.testing.expectEqual(@as(usize, 1), observer.calls);
    try std.testing.expect(!connection.closing());
    try std.testing.expect(fixture.client.session(sibling.session_id) == sibling);
    try std.testing.expectEqual(@as(usize, 1), fixture.client.pending_open_cleanup.count());
    try std.testing.expect(fixture.client.h3.request_lifecycle.contains(4));
    connection.pacer.enabled = false;
    try finishCancellation(&fixture);
}

fn finishCancellation(fixture: *Fixture) !void {
    var buffer: [32]u8 = undefined;
    for (0..4) |_| _ = try fixture.client.pollAny(&buffer);
    try std.testing.expectEqual(@as(usize, 0), fixture.client.pending_open_cleanup.count());
    try std.testing.expect(!fixture.client.h3.request_lifecycle.contains(4));
    var saw_reset = false;
    var saw_stop = false;
    const deadline = std.Io.Clock.Timestamp.fromNow(fixture.peer_endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    while (!saw_reset or !saw_stop) {
        var packet = try fixture.peer.receivePacketServicingTimersDeadline(deadline);
        defer packet.deinit(std.testing.allocator);
        for (packet.frames) |frame| switch (frame) {
            .reset_stream => |reset| if (reset.stream_id == 4) {
                try std.testing.expectEqual(http3.ApplicationErrorCode.request_cancelled, reset.application_error_code);
                saw_reset = true;
            },
            .stop_sending => |stop| if (stop.stream_id == 4) {
                try std.testing.expectEqual(http3.ApplicationErrorCode.request_cancelled, stop.application_error_code);
                saw_stop = true;
            },
            else => {},
        };
    }
    const packet_number = fixture.client.h3.established.connection.next_packet_number;
    _ = try fixture.client.pollAny(&buffer);
    try std.testing.expectEqual(packet_number, fixture.client.h3.established.connection.next_packet_number);
    const sibling = fixture.client.session(.init(0)).?;
    try sibling.sendDatagram(&fixture.client, "alive");
    try std.testing.expect(!sibling.control.state.closed);
}

test "WebTransport shared client CONNECT timeout retains cancellation after socket failure" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const sibling = try fixture.addSession();
    const connection = &fixture.client.h3.established.connection;
    const original_io = connection.endpoint.io;
    var observer = SaturateAfterSend{ .delegate = original_io, .connection = connection, .fail_cancel = true };
    SaturateAfterSend.active = &observer;
    defer SaturateAfterSend.active = null;
    var vtable = original_io.vtable.*;
    vtable.netSend = SaturateAfterSend.netSend;
    connection.endpoint.io = .{ .userdata = original_io.userdata, .vtable = &vtable };
    defer connection.endpoint.io = original_io;
    try std.testing.expectError(error.Timeout, fixture.client.openSessionAttemptWithTimeout(.{
        .authority = "localhost",
        .path = "/no-response",
    }, .fromMilliseconds(10)));
    try std.testing.expectEqual(@as(usize, 2), observer.calls);
    try std.testing.expect(!sibling.control.state.closed);
    try std.testing.expect(fixture.client.h3.request_lifecycle.contains(4));
    try std.testing.expectEqual(@as(usize, 1), fixture.client.pending_open_cleanup.count());
    try finishCancellation(&fixture);
}

test "WebTransport shared client CONNECT timeout cleans early streams while preserving sibling traffic" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    fixture.peer.config.reliable_reset = .{ .local = true, .peer = true };
    const datagram_limits = fixture.client.h3.connect_datagrams.limits;
    fixture.client.h3.connect_datagrams.deinit();
    fixture.client.h3.connect_datagrams = @TypeOf(fixture.client.h3.connect_datagrams).initWithEarly(std.testing.allocator, datagram_limits, threaded.io(), .{ .max_datagrams = 8, .max_bytes = 128 });
    const sibling = try fixture.addSession();
    try fixture.client.h3.connect_datagrams.route("\x01early");
    try std.testing.expectEqual(@as(usize, 1), fixture.client.h3.connect_datagrams.early_datagrams.count(4));
    const connection = &fixture.client.h3.established.connection;
    const original_io = connection.endpoint.io;
    var observer = SaturateAfterSend{ .delegate = original_io, .connection = connection, .pace = true };
    SaturateAfterSend.active = &observer;
    defer SaturateAfterSend.active = null;
    var vtable = original_io.vtable.*;
    vtable.netSend = SaturateAfterSend.netSend;
    connection.endpoint.io = .{ .userdata = original_io.userdata, .vtable = &vtable };
    defer connection.endpoint.io = original_io;
    try std.testing.expectError(error.Timeout, fixture.client.openSessionAttemptWithTimeout(.{
        .authority = "localhost",
        .path = "/no-response",
    }, .fromMilliseconds(10)));
    try fixture.client.h3.connect_datagrams.route("\x01late");
    try std.testing.expectEqual(@as(usize, 0), fixture.client.h3.connect_datagrams.early_datagrams.count(4));

    var abandoned_storage: [16]u8 = undefined;
    var sibling_storage: [16]u8 = undefined;
    const abandoned_header = try prefix.header(.init(4), .bidirectional, &abandoned_storage);
    const sibling_header = try prefix.header(sibling.session_id, .bidirectional, &sibling_storage);
    try fixture.peer.send(&.{
        .{ .stream = .{ .stream_id = 1, .data = abandoned_header } },
        .{ .stream = .{ .stream_id = 1, .offset = abandoned_header.len, .data = "discard" } },
        .{ .stream = .{ .stream_id = 5, .data = sibling_header } },
        .{ .stream = .{ .stream_id = 5, .offset = sibling_header.len, .data = "alive" } },
    });
    var packet = try connection.receivePacketTimeout(.{ .duration = .{ .raw = .fromSeconds(1), .clock = .awake } });
    defer packet.deinit(std.testing.allocator);
    var buffer: [32]u8 = undefined;
    const event = (try fixture.client.poll(sibling.session_id, &buffer)) orelse return error.TestUnexpectedResult;
    try std.testing.expect(event == .stream and event.stream == .data);
    try std.testing.expectEqual(@as(u62, 5), event.stream.data.stream_id);
    try std.testing.expectEqualStrings("alive", buffer[0..event.stream.data.bytes]);
    try std.testing.expect(connection.recvStreamStats(1).?.stop_sending_sent == null);
    try std.testing.expectEqual(@as(usize, 1), fixture.client.pending_open_cleanup.count());
    try std.testing.expectEqual(@as(usize, @intFromBool(connection.sendStreamStats(4).?.reset == null)), fixture.client.pending_open_cleanup.liveCount());

    connection.pacer.enabled = false;
    try finishCancellation(&fixture);
    const deadline = std.Io.Clock.Timestamp.fromNow(original_io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    while ((if (fixture.peer.recvStreamStats(1)) |stats| stats.reset else null) == null or fixture.peer.sendStreamStats(1).?.stopped == null) {
        var terminal = try fixture.peer.receivePacketServicingTimersDeadline(deadline);
        terminal.deinit(std.testing.allocator);
    }
    try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, fixture.peer.recvStreamStats(1).?.reset.?.application_error_code);
    try std.testing.expectEqual(webtransport.ApplicationErrorCode.session_gone, fixture.peer.sendStreamStats(1).?.stopped.?.application_error_code);
    try std.testing.expect(connection.recvStreamStats(5).?.stop_sending_sent == null);
    try std.testing.expect(connection.sendStreamStats(5).?.reset == null);
}

test "WebTransport shared client CONNECT cleanup is reserved before send and retains post-send OOM ownership" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |after_send| {
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        const sibling = try fixture.addSession();
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        fixture.client.allocator = failing.allocator();
        defer fixture.deinit();
        if (!after_send) failing.fail_index = 0;
        const connection = &fixture.client.h3.established.connection;
        const original_io = connection.endpoint.io;
        var observer = SaturateAfterSend{ .delegate = original_io, .connection = connection, .fail_allocator = &failing };
        SaturateAfterSend.active = &observer;
        defer SaturateAfterSend.active = null;
        var vtable = original_io.vtable.*;
        vtable.netSend = SaturateAfterSend.netSend;
        connection.endpoint.io = .{ .userdata = original_io.userdata, .vtable = &vtable };
        defer connection.endpoint.io = original_io;
        try std.testing.expectError(error.OutOfMemory, fixture.client.openSessionAttemptWithTimeout(.{
            .authority = "localhost",
            .path = "/oom",
        }, .fromSeconds(1)));
        try std.testing.expect(!sibling.control.state.closed);
        if (after_send) {
            try std.testing.expectEqual(@as(u62, 8), fixture.client.h3.next_stream_id);
            try std.testing.expect(fixture.client.h3.request_lifecycle.contains(4));
            try std.testing.expectEqual(@as(usize, 1), fixture.client.pending_open_cleanup.count());
            failing.fail_index = std.math.maxInt(usize);
            connection.congestion.congestion_window = 64 * 1024;
            try finishCancellation(&fixture);
        } else {
            try std.testing.expectEqual(@as(usize, 0), observer.calls);
            try std.testing.expectEqual(@as(u62, 4), fixture.client.h3.next_stream_id);
            try std.testing.expectEqual(@as(usize, 0), fixture.client.pending_open_cleanup.count());
        }
    }
}
