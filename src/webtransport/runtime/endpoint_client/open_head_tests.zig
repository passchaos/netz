const std = @import("std");
const quic = @import("../../../quic/mod.zig");
const http3 = @import("../../../http3/mod.zig");
const webtransport = @import("../../mod.zig");
const control_sender = @import("../../../http3/runtime/control/send.zig");
const Fixture = @import("test_support.zig").Fixture;

const PaceAfterFirstSend = struct {
    delegate: std.Io,
    connection: *quic.one_rtt.Connection,
    calls: usize = 0,
    congestion: bool = false,
    fail_on_call: ?usize = null,
    var active: ?*PaceAfterFirstSend = null;

    fn netSend(userdata: ?*anyopaque, handle: std.Io.net.Socket.Handle, messages: []std.Io.net.OutgoingMessage, flags: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
        const self = active.?;
        if (self.fail_on_call == self.calls + 1) {
            self.calls += 1;
            return .{ error.NetworkDown, 0 };
        }
        const result = self.delegate.vtable.netSend(userdata, handle, messages, flags);
        if (self.calls == 0 and result[1] != 0) {
            if (self.congestion) {
                self.connection.congestion.congestion_window = self.connection.congestion.bytes_in_flight;
            } else if (self.fail_on_call == null) {
                self.connection.pacer = .initWithRateLimit(true, 4096, 1, 128);
                self.connection.pacer.budget = 0;
                self.connection.pacer.setLastSentTimeNs(@intCast(std.Io.Clock.awake.now(self.delegate).nanoseconds));
            }
        }
        self.calls += 1;
        return result;
    }
};

test "WebTransport shared client partial CONNECT head timeout preserves sibling" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]bool{ false, true }) |congestion| {
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const sibling = try fixture.addSession();
        fixture.client.h3.options.max_frames_per_packet = 1;
        fixture.client.h3.options.max_stream_frame_data = 1;
        const connection = &fixture.client.h3.established.connection;
        const original_io = connection.endpoint.io;
        var observer = PaceAfterFirstSend{ .delegate = original_io, .connection = connection, .congestion = congestion };
        PaceAfterFirstSend.active = &observer;
        defer PaceAfterFirstSend.active = null;
        var vtable = original_io.vtable.*;
        vtable.netSend = PaceAfterFirstSend.netSend;
        connection.endpoint.io = .{ .userdata = original_io.userdata, .vtable = &vtable };
        defer connection.endpoint.io = original_io;
        try std.testing.expectError(error.Timeout, fixture.client.openSessionAttemptWithTimeout(.{
            .authority = "localhost",
            .path = "/fragmented",
        }, .fromMilliseconds(10)));
        try std.testing.expect(!sibling.control.state.closed);
        try std.testing.expect(!connection.closed() and !connection.closing());
        try std.testing.expectEqual(@as(u64, 1), connection.sendStreamStats(4).?.highest_sent_offset);
        try std.testing.expect(fixture.client.h3.request_lifecycle.contains(4));
        try std.testing.expectEqual(@as(usize, 1), fixture.client.pending_open_cleanup.count());
        connection.pacer.enabled = false;
        connection.congestion.congestion_window = 64 * 1024;
        try finish(&fixture, 1);
    }
}

fn finish(fixture: *Fixture, prefix_bytes: u64) !void {
    const sibling = fixture.client.session(.init(0)).?;
    try fixture.queueDatagram(sibling, "alive");
    var event = (try fixture.poll(sibling)) orelse return error.TestUnexpectedResult;
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .datagram);
    try std.testing.expectEqualStrings("alive", event.datagram.payload);
    try std.testing.expectEqual(@as(usize, 0), fixture.client.pending_open_cleanup.count());
    try std.testing.expect(!fixture.client.h3.request_lifecycle.contains(4));
    try std.testing.expectEqual(@as(u62, 8), fixture.client.h3.next_stream_id);
    var reset = false;
    var stop = false;
    const deadline = std.Io.Clock.Timestamp.fromNow(fixture.peer_endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    while (!reset or !stop) {
        var packet = try fixture.peer.receivePacketServicingTimersDeadline(deadline);
        defer packet.deinit(std.testing.allocator);
        for (packet.frames) |frame| switch (frame) {
            .reset_stream => |value| if (value.stream_id == 4) {
                try std.testing.expectEqual(http3.ApplicationErrorCode.request_cancelled, value.application_error_code);
                try std.testing.expectEqual(prefix_bytes, value.final_size);
                reset = true;
            },
            .stop_sending => |value| if (value.stream_id == 4) {
                try std.testing.expectEqual(http3.ApplicationErrorCode.request_cancelled, value.application_error_code);
                stop = true;
            },
            else => {},
        };
    }
    try std.testing.expect(!sibling.control.state.closed);
}

test "WebTransport shared client CONNECT head socket failure cancels only its allocated stream" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]usize{ 1, 2 }) |failed_call| {
        var fixture: Fixture = undefined;
        try fixture.init(threaded.io());
        defer fixture.deinit();
        const sibling = try fixture.addSession();
        fixture.client.h3.options.max_frames_per_packet = 1;
        fixture.client.h3.options.max_stream_frame_data = 1;
        const connection = &fixture.client.h3.established.connection;
        const original_io = connection.endpoint.io;
        var observer = PaceAfterFirstSend{ .delegate = original_io, .connection = connection, .fail_on_call = failed_call };
        PaceAfterFirstSend.active = &observer;
        defer PaceAfterFirstSend.active = null;
        var vtable = original_io.vtable.*;
        vtable.netSend = PaceAfterFirstSend.netSend;
        connection.endpoint.io = .{ .userdata = original_io.userdata, .vtable = &vtable };
        defer connection.endpoint.io = original_io;
        try std.testing.expectError(error.NetworkDown, fixture.client.openSessionAttempt(.{
            .authority = "localhost",
            .path = "/fragmented",
        }));
        try std.testing.expect(!sibling.control.state.closed);
        try std.testing.expect(!connection.closed() and !connection.closing());
        try finish(&fixture, failed_call - 1);
    }
}

test "WebTransport shared client fragmented CONNECT head resumes credit progress and completes" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.init(threaded.io());
    defer fixture.deinit();
    const sibling = try fixture.addSession();
    fixture.client.h3.options.max_frames_per_packet = 1;
    fixture.client.h3.options.max_stream_frame_data = 16;
    const connection = &fixture.client.h3.established.connection;
    const original_io = connection.endpoint.io;
    var observer = PaceAfterFirstSend{ .delegate = original_io, .connection = connection, .congestion = true };
    PaceAfterFirstSend.active = &observer;
    defer PaceAfterFirstSend.active = null;
    var vtable = original_io.vtable.*;
    vtable.netSend = PaceAfterFirstSend.netSend;
    connection.endpoint.io = .{ .userdata = original_io.userdata, .vtable = &vtable };
    defer connection.endpoint.io = original_io;
    const value = [_]u8{'h'} ** 4096;
    const Worker = struct {
        fixture: *Fixture,
        err: ?anyerror = null,
        head_len: usize = 0,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            const peer = &self.fixture.peer;
            const deadline = std.Io.Clock.Timestamp.fromNow(peer.endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(3) });
            while (true) {
                const bytes = peer.availableReceivedStream(4) orelse &.{};
                const frame = http3.Frame.parse(bytes) catch |err| switch (err) {
                    error.BufferTooShort => {
                        var packet = try peer.receivePacketServicingTimersDeadline(deadline);
                        defer packet.deinit(std.testing.allocator);
                        _ = try peer.sendAckForPacketIfNeeded(packet.packet.packet_number, packet.frames);
                        continue;
                    },
                    else => return err,
                };
                try std.testing.expectEqual(http3.FrameType.headers, frame.frame_type);
                var table = http3.Qpack.DynamicTable.init(std.testing.allocator, 0);
                defer table.deinit();
                var request = try http3.decodeRequestHeadWithDynamicTable(std.testing.allocator, bytes, self.fixture.client.h3.options.local_settings, table);
                defer request.deinit(std.testing.allocator);
                self.head_len = request.consumed;
                try std.testing.expectEqualStrings("/large-head", request.path);
                var found = false;
                for (request.headers) |field| if (std.mem.eql(u8, field.name, "x-large-head")) {
                    try std.testing.expectEqualStrings(&value, field.value);
                    found = true;
                };
                try std.testing.expect(found);
                var response: std.ArrayList(u8) = .empty;
                defer response.deinit(std.testing.allocator);
                try (http3.Response{ .status = 200, .extended_connect = true }).write(&response, std.testing.allocator);
                try peer.send(&.{.{ .stream = .{ .stream_id = 4, .data = response.items } }});
                return;
            }
        }
    };
    var worker = Worker{ .fixture = &fixture };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();
    const result = fixture.client.openSessionWithTimeout(.{
        .authority = "localhost",
        .path = "/large-head",
        .headers = &.{.{ .name = "x-large-head", .value = &value }},
    }, .fromSeconds(2));
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
    const accepted = try result;
    try std.testing.expectEqual(@as(u62, 4), accepted.session_id.value);
    try std.testing.expectEqual(@as(usize, 2), fixture.client.sessionCount());
    try std.testing.expect(!sibling.control.state.closed);
    try std.testing.expectEqual(@as(u64, worker.head_len), fixture.client.h3.outbound_bodies.find(4).?.send.next_offset);
}

test "WebTransport shared client CONNECT head timeout retains QPACK references until cancellation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var fixture: Fixture = undefined;
    try fixture.initWithSettings(threaded.io(), try webtransport.settingsWithSessionCapacity(.{
        .qpack_max_table_capacity = 256,
        .qpack_blocked_streams = 1,
    }, 2));
    defer fixture.deinit();
    _ = try fixture.addSession();
    const h3 = &fixture.client.h3;
    // This raw-QUIC fixture marks SETTINGS directly instead of routing a
    // control packet, so bind the encoder to the advertised peer limits here.
    try h3.qpack_encode.configurePeerLimits(256, 1);
    try std.testing.expect((try h3.qpack_encode.insertField("x-owned-head", "reused")) != null);
    try control_sender.sendConnectionQpackEncoderInstructions(
        &h3.established.connection,
        &h3.critical_stream_send_scratch,
        &h3.qpack_encode,
        &h3.qpack_encoder_send,
        &h3.qpack_encoder_prefix_sent,
        h3.options,
    );
    h3.options.max_frames_per_packet = 1;
    h3.options.max_stream_frame_data = 1;
    const connection = &h3.established.connection;
    const original_io = connection.endpoint.io;
    var observer = PaceAfterFirstSend{ .delegate = original_io, .connection = connection };
    PaceAfterFirstSend.active = &observer;
    defer PaceAfterFirstSend.active = null;
    var vtable = original_io.vtable.*;
    vtable.netSend = PaceAfterFirstSend.netSend;
    connection.endpoint.io = .{ .userdata = original_io.userdata, .vtable = &vtable };
    defer connection.endpoint.io = original_io;
    try std.testing.expectError(error.Timeout, fixture.client.openSessionAttemptWithTimeout(.{
        .authority = "localhost",
        .path = "/dynamic-head",
        .headers = &.{.{ .name = "x-owned-head", .value = "reused" }},
    }, .fromMilliseconds(10)));
    try std.testing.expectEqual(@as(usize, 1), h3.qpack_encode.pending_sections.items.len);
    try std.testing.expectEqual(@as(usize, 1), fixture.client.pending_open_cleanup.count());
    const submitted = connection.sendStreamStats(4).?.highest_sent_offset;
    try std.testing.expect(submitted <= 1);
    connection.pacer.enabled = false;
    try finish(&fixture, submitted);
    try std.testing.expectEqual(@as(usize, 1), h3.qpack_encode.pending_sections.items.len);
    var feedback_bytes: std.ArrayList(u8) = .empty;
    defer feedback_bytes.deinit(std.testing.allocator);
    try http3.writeQpackDecoderStreamPrefix(&feedback_bytes, std.testing.allocator);
    try http3.Qpack.writeDecoderInstruction(&feedback_bytes, std.testing.allocator, .{ .stream_cancellation = 4 });
    try fixture.peer.send(&.{.{ .stream = .{ .stream_id = 11, .data = feedback_bytes.items } }});
    const deadline = std.Io.Clock.Timestamp.fromNow(original_io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    while (h3.qpack_encode.hasPendingSections(4)) {
        var packet = try connection.receivePacketServicingTimersDeadline(deadline);
        defer packet.deinit(std.testing.allocator);
        try h3.processDetachedResponsePacket(0, &packet);
    }
    try std.testing.expectEqual(@as(usize, 0), h3.qpack_encode.pending_sections.items.len);
}
