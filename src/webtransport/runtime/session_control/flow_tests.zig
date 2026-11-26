const std = @import("std");
const native_protocol_io = @import("../../../internal/testing/native_protocol_io.zig");
const webtransport = @import("../../mod.zig");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const control_mod = @import("../session_control.zig");
const Pair = @import("test_support/handshake_pair.zig").Pair;
const Role = @import("test_support/handshake_pair.zig").Role;
const ObservedBatchSend = @import("../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;

test "WebTransport runtime flow Capsule grants zero initial stream credit" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]Role{ .client, .server }) |role| {
        var pair: Pair = undefined;
        const settings = webtransport.defaultSettings(.{});
        var limited = settings;
        limited.webtransport_initial_max_streams_bidi = 0;
        var client_settings = settings;
        var server_settings = settings;
        switch (role) {
            .client => server_settings = limited,
            .server => client_settings = limited,
        }
        try pair.initWithSettings(threaded.io(), client_settings, server_settings);
        defer pair.deinit();
        switch (role) {
            .client => try std.testing.expectError(error.FlowControlBlocked, pair.client.openBidirectionalStream()),
            .server => try std.testing.expectError(error.FlowControlBlocked, pair.server.openBidirectionalStream()),
        }
        switch (role) {
            .client => try pair.server.grantStreams(.bidirectional, 1),
            .server => try pair.client.grantStreams(.bidirectional, 1),
        }
        const deadline = std.Io.Clock.Timestamp.fromNow(pair.connection(role).endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) });
        try pair.receiveProgress(role, deadline);
        try std.testing.expect((try pair.poll(role)) == null);
        const id = switch (role) {
            .client => try pair.client.openBidirectionalStream(),
            .server => try pair.server.openBidirectionalStream(),
        };
        try std.testing.expectEqual(@as(u62, if (role == .client) 4 else 1), id);
        switch (role) {
            .client => try std.testing.expectError(error.FlowControlBlocked, pair.client.openBidirectionalStream()),
            .server => try std.testing.expectError(error.FlowControlBlocked, pair.server.openBidirectionalStream()),
        }
    }
}

test "WebTransport runtime flow grant commits only after the packet is sent" {
    try native_protocol_io.run(committedFlowGrant);
}

fn committedFlowGrant(io: std.Io) !void {
    var pair: Pair = undefined;
    try pair.init(io);
    defer pair.deinit();
    const conn = pair.connection(.server);
    const previous = pair.server.streams.flow.?.receive_limit.data;
    const original_io = conn.endpoint.io;
    var observed = ObservedBatchSend{ .delegate = original_io, .fail_on_call = 1 };
    conn.endpoint.io = observed.io();
    defer conn.endpoint.io = original_io;
    try std.testing.expectError(error.NetworkDown, pair.server.grantData(previous + 1024));
    try std.testing.expectEqual(previous, pair.server.streams.flow.?.receive_limit.data);
    observed.fail_on_call = null;
    try pair.server.grantData(previous + 1024);
    try std.testing.expectEqual(previous + 1024, pair.server.streams.flow.?.receive_limit.data);
    const deadline = std.Io.Clock.Timestamp.fromNow(pair.connection(.client).endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    try pair.receiveProgress(.client, deadline);
    try std.testing.expect((try pair.poll(.client)) == null);
    try std.testing.expectEqual(previous + 1024, pair.client.streams.flow.?.send_limit.data);
}

test "WebTransport runtime flow stream-open deadline waits for grant and retains DRAIN" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const normal = webtransport.defaultSettings(.{});
    var limited = normal;
    limited.webtransport_initial_max_streams_bidi = 0;
    var pair: Pair = undefined;
    try pair.initWithSettings(threaded.io(), normal, limited);
    defer pair.deinit();
    try std.testing.expectError(error.Timeout, pair.client.openBidirectionalStreamWithTimeout(.fromMilliseconds(5)));
    try std.testing.expectEqual(@as(u64, 0), pair.client.streams.opened_local_bidi);
    try pair.server.drain();
    try pair.server.grantStreams(.bidirectional, 1);
    const id = try pair.client.openBidirectionalStreamWithTimeout(.fromSeconds(1));
    try std.testing.expectEqual(@as(u62, 4), id);
    const event = (try pair.poll(.client)).?;
    try std.testing.expect(event == .draining);
}

test "WebTransport runtime flow parses fragmented grants beside DRAIN" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const current = pair.client.streams.flow.?.send_limit.data;
    var storage: [32]u8 = undefined;
    const grant = try (webtransport.Capsule{ .max_data = current + 1024 }).writeInto(&storage);
    try pair.sendCapsules(.client, grant[0..2]);
    try std.testing.expect((try pair.poll(.client)) == null);
    try std.testing.expectEqual(current, pair.client.streams.flow.?.send_limit.data);
    try pair.sendCapsules(.client, grant[2..]);
    try pair.client.control.progressFlow(pair.connection(.client));
    try std.testing.expectEqual(current + 1024, pair.client.streams.flow.?.send_limit.data);
    const drain = try control_mod.writeDrainInto(&storage);
    try pair.sendCapsules(.client, drain);
    try pair.client.control.progressFlow(pair.connection(.client));
    const event = (try pair.poll(.client)).?;
    try std.testing.expect(event == .draining);
}

test "WebTransport runtime flow parser commits grants and retains failed transport credit" {
    try native_protocol_io.run(retainedFlowCredit);
}

fn retainedFlowCredit(io: std.Io) !void {
    var pair: Pair = undefined;
    try pair.init(io);
    defer pair.deinit();
    const conn = pair.connection(.client);
    const original_limit = pair.client.streams.flow.?.send_limit.data;
    var storage: [32]u8 = undefined;
    const grant = try (webtransport.Capsule{ .max_data = original_limit + 1024 }).writeInto(&storage);
    try pair.sendCapsules(.client, grant);
    const original_io = conn.endpoint.io;
    var observed = ObservedBatchSend{ .delegate = original_io, .fail_on_call = 1 };
    conn.endpoint.io = observed.io();
    defer conn.endpoint.io = original_io;
    // Force receive-window replenishment during the control poll.
    const entry = conn.stream_recv_index.get(0).?;
    conn.stream_recv_flows.items[entry].flow.limit = conn.stream_recv_flows.items[entry].flow.highest_received;
    try std.testing.expect((try pair.client.control.pollOnce(conn)) == null);
    try std.testing.expectEqual(original_limit + 1024, pair.client.streams.flow.?.send_limit.data);
    try std.testing.expect(observed.calls != 0);
    try std.testing.expect(conn.receive_credit_retry_deadline_ns != null);
    observed.fail_on_call = null;
    const read_offset = conn.recvStreamStats(0).?.bytes_read;
    try std.testing.expect((try pair.client.control.pollOnce(conn)) == null);
    try std.testing.expectEqual(original_limit + 1024, pair.client.streams.flow.?.send_limit.data);
    try std.testing.expectEqual(read_offset, conn.recvStreamStats(0).?.bytes_read);
    for (0..16) |_| {
        if (conn.receive_credit_retry_deadline_ns == null) break;
        const timer = conn.nextTimerDeadline().?;
        _ = try conn.serviceNextTimerAt(timer.deadline_ns);
    }
    try std.testing.expect(conn.receive_credit_retry_deadline_ns == null);
}

test "WebTransport runtime flow duplicate grant closes CONNECT with protocol flow error" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const value = pair.client.streams.flow.?.send_limit.data;
    var storage: [32]u8 = undefined;
    const duplicate = try (webtransport.Capsule{ .max_data = value }).writeInto(&storage);
    try pair.sendCapsules(.client, duplicate);
    try std.testing.expectError(error.FlowControlViolation, pair.receiveWithTimeout(.client, .fromSeconds(1)));
    const conn = pair.connection(.client);
    try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.flow_control_error), conn.sendStreamStats(0).?.reset.?.application_error_code);
    try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.flow_control_error), conn.recvStreamStats(0).?.stop_sending_sent.?.application_error_code);
    try std.testing.expect(pair.client.control.flow_violation);
}

test "WebTransport runtime flow blocked open rejects a duplicate grant" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const normal = webtransport.defaultSettings(.{});
    var limited = normal;
    limited.webtransport_initial_max_streams_bidi = 0;
    var pair: Pair = undefined;
    try pair.initWithSettings(threaded.io(), normal, limited);
    defer pair.deinit();
    var storage: [32]u8 = undefined;
    const duplicate = try (webtransport.Capsule{ .max_streams_bidi = 0 }).writeInto(&storage);
    try pair.sendCapsules(.client, duplicate);
    try std.testing.expectError(error.FlowControlViolation, pair.client.openBidirectionalStreamWithTimeout(.fromSeconds(1)));
    const conn = pair.connection(.client);
    try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.flow_control_error), conn.sendStreamStats(0).?.reset.?.application_error_code);
    try std.testing.expectEqual(@as(u64, 0), pair.client.streams.opened_local_bidi);
    try std.testing.expect(!conn.closing());
}

test "WebTransport runtime flow incoming stream excess resets only its CONNECT" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const normal = webtransport.defaultSettings(.{});
    var limited = normal;
    limited.webtransport_initial_max_streams_bidi = 0;
    var pair: Pair = undefined;
    try pair.initWithSettings(threaded.io(), normal, limited);
    defer pair.deinit();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    try webtransport.BidirectionalStreamHeader.write(&bytes, std.testing.allocator, .init(0));
    try bytes.appendSlice(std.testing.allocator, "excess");
    try pair.connection(.client).send(&.{.{ .stream = .{ .stream_id = 4, .data = bytes.items } }});
    var output: [32]u8 = undefined;
    try std.testing.expectError(error.FlowControlViolation, pair.server.readStreamWithTimeout(&output, .fromSeconds(1)));
    const conn = pair.connection(.server);
    try std.testing.expectEqual(@as(u64, webtransport.ApplicationErrorCode.flow_control_error), conn.sendStreamStats(0).?.reset.?.application_error_code);
    try std.testing.expect(!conn.closing());
    try std.testing.expectEqual(@as(u64, 0), pair.server.streams.flow.?.received.bidi);
}

test "WebTransport runtime flow disabled peers ignore malformed flow capsules" {
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
    try std.testing.expect(pair.client.streams.flow == null);
    // Complete outer capsule, deliberately empty numeric payload.
    try pair.sendCapsules(.client, &.{ 0x99, 0x0b, 0x4d, 0x3d, 0 });
    try std.testing.expect((try pair.poll(.client)) == null);
    _ = try pair.client.openBidirectionalStream();
}
