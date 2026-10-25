const std = @import("std");

test {
    _ = @import("send_wait_tests.zig");
    _ = @import("unbounded_send_tests.zig");
}
const webtransport = @import("../../../mod.zig");
const Pair = @import("../../session_control/test_support/handshake_pair.zig").Pair;

const Kind = enum { owned, into, batch_into, batch_owned };

fn exchange(kind: Kind) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var settings = webtransport.defaultSettings(.{});
    settings.webtransport_initial_max_streams_bidi = 1;
    var pair: Pair = undefined;
    try pair.initWithSettings(threaded.io(), settings, settings);
    defer pair.deinit();
    const Worker = struct {
        pair: *Pair,
        kind: Kind,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var output: [16]u8 = undefined;
            var id: ?u62 = null;
            const deadline = std.Io.Clock.Timestamp.fromNow(self.pair.connection(.server).endpoint.io, .{ .raw = .fromSeconds(2), .clock = .awake });
            while (true) {
                const event = try self.pair.server.readStreamWithDeadline(&output, deadline);
                try std.testing.expect(event == .data);
                id = event.data.stream_id;
                if (event.data.fin) break;
            }
            try self.pair.server.finishStream(id.?);
            // The client waits for a new stream grant before sending the
            // marker. Receiving only DATAGRAMs must still retire the old bidi
            // on its ACK and emit WT_MAX_STREAMS without another stream event.
            switch (self.kind) {
                .owned => {
                    var marker = try self.pair.server.receiveDatagramWithDeadline(deadline);
                    defer marker.deinit(std.testing.allocator);
                    try std.testing.expectEqualStrings("one", marker.datagram.payload);
                },
                .into => {
                    const marker = try self.pair.server.receiveDatagramIntoWithDeadline(&output, deadline);
                    try std.testing.expectEqualStrings("one", marker);
                },
                .batch_into => {
                    var second: [16]u8 = undefined;
                    var outputs = [_][]u8{ &output, &second };
                    var received: usize = 99;
                    try self.pair.server.receiveDatagramsIntoWithDeadline(&outputs, &received, deadline);
                    try std.testing.expectEqual(@as(usize, 2), received);
                    try std.testing.expectEqualStrings("one", outputs[0]);
                    try std.testing.expectEqualStrings("two", outputs[1]);
                },
                .batch_owned => {
                    var markers = try self.pair.server.receiveManyDatagramsWithDeadline(2, deadline);
                    defer markers.deinit();
                    try std.testing.expect(markers.firstError() == null);
                    try std.testing.expectEqualStrings("one", markers.datagrams[0].?.datagram.payload);
                    try std.testing.expectEqualStrings("two", markers.datagrams[1].?.datagram.payload);
                },
            }
            try std.testing.expectEqual(@as(u64, 1), self.pair.server.streams.flow.?.retired_peer.bidi);
            try std.testing.expectEqual(@as(u64, 2), self.pair.server.streams.flow.?.receive_limit.bidi);
        }
    };
    var worker = Worker{ .pair = &pair, .kind = kind };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();
    const Client = struct {
        fn run(pair_value: *Pair, mode: Kind) !void {
            const first = try pair_value.client.openBidirectionalStream();
            try pair_value.client.sendStream(first, "q", true);
            var out: [16]u8 = undefined;
            const deadline = std.Io.Clock.Timestamp.fromNow(pair_value.connection(.client).endpoint.io, .{ .raw = .fromSeconds(2), .clock = .awake });
            while (true) {
                const event = try pair_value.client.readStreamIdWithDeadline(first, &out, deadline);
                try std.testing.expect(event == .data and event.data.bytes == 0);
                if (event.data.fin) break;
            }
            _ = try pair_value.client.flushPendingAck();
            _ = try pair_value.client.openBidirectionalStreamWithDeadline(deadline);
            try pair_value.client.sendDatagram("one");
            if (mode == .batch_into or mode == .batch_owned) try pair_value.client.sendDatagram("two");
        }
    };
    var client_error: ?anyerror = null;
    Client.run(&pair, kind) catch |err| {
        client_error = err;
    };
    thread.join();
    joined = true;
    if (worker.err) |err| return err;
    if (client_error) |err| return err;
}

test "WebTransport flow datagram waits service stream grants for owned and caller buffers" {
    for ([_]Kind{ .owned, .into, .batch_into, .batch_owned }) |kind| try exchange(kind);
}

test "WebTransport flow HTTP3 receive hook preserves custom maintenance errors" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const Maintenance = struct {
        pub const ErrorSet = error{MaintenanceStopped};
        pub fn maintain(_: @This(), _: ?std.Io.Clock.Timestamp) ErrorSet!void {
            return error.MaintenanceStopped;
        }
    };
    const deadline = std.Io.Clock.Timestamp.fromNow(pair.connection(.server).endpoint.io, .{ .raw = .fromSeconds(1), .clock = .awake });
    try std.testing.expectError(error.MaintenanceStopped, pair.server.h3.receiveConnectDatagramWithProgress(0, deadline, Maintenance{}));
    var out: [16]u8 = undefined;
    try std.testing.expectError(error.MaintenanceStopped, pair.server.h3.receiveConnectDatagramIntoWithProgress(0, &out, deadline, Maintenance{}));
}

test "WebTransport flow unnegotiated datagram waits ignore MAX and reject HTTP2 capsules" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const normal = webtransport.defaultSettings(.{});
    var legacy = normal;
    legacy.webtransport_initial_max_data = 0;
    legacy.webtransport_initial_max_streams_bidi = 0;
    legacy.webtransport_initial_max_streams_uni = 0;
    var pair: Pair = undefined;
    try pair.initWithSettings(threaded.io(), normal, legacy);
    defer pair.deinit();
    try pair.sendCapsules(.client, &.{ 0x99, 0x0b, 0x4d, 0x3d, 0 });
    try pair.server.sendDatagram("alive");
    var datagram = try pair.client.receiveDatagramWithTimeout(.fromSeconds(1));
    defer datagram.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("alive", datagram.datagram.payload);
    try std.testing.expect(pair.client.streams.flow == null);
    try pair.sendCapsules(.client, &.{ 0x99, 0x0b, 0x4d, 0x3e, 0 });
    try std.testing.expectError(error.FlowControlViolation, pair.client.receiveDatagramWithTimeout(.fromSeconds(1)));
    const conn = pair.connection(.client);
    try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.flow_control_error), conn.sendStreamStats(0).?.reset.?.application_error_code);
    try std.testing.expect(!conn.closing());
}

test "WebTransport flow datagram wait closes connection on forbidden CONNECT frame" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const conn = pair.connection(.client);
    // DATA is unnecessary here: inject a HEADERS frame into the accepted
    // CONNECT direction, which permits only DATA and unknown extension frames.
    const offset = pair.connection(.server).sendStreamStats(0).?.highest_sent_offset;
    try pair.connection(.server).send(&.{.{ .stream = .{ .stream_id = 0, .offset = offset, .data = &.{ 1, 0 } } }});
    try std.testing.expectError(error.UnexpectedFrame, pair.client.receiveDatagramWithTimeout(.fromSeconds(1)));
    try std.testing.expect(conn.closing());
}
