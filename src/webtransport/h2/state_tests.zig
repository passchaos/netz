const std = @import("std");
const model = @import("state.zig");
const allocator = std.testing.allocator;
const generous: model.Limits = .{ .data = 4096, .bidi = 16, .uni = 16, .uni_data = 256, .bidi_local_data = 128, .bidi_remote_data = 512 };

test "WebTransport HTTP2 state exchanges bidirectional streams in both endpoint roles" {
    for ([_]model.Role{ .client, .server }) |role| {
        var sender = try model.State.init(allocator, role, generous, generous, 128);
        defer sender.deinit();
        var receiver = try model.State.init(allocator, if (role == .client) .server else .client, generous, generous, 128);
        defer receiver.deinit();
        const id = try sender.openStream(.bidirectional);
        try std.testing.expectEqual(@as(u62, @intFromEnum(role)), id);
        const prepared = try sender.prepareStream(id, "hello", true);
        try std.testing.expectEqual(@as(u64, 0), sender.sent_data);
        try sender.commit(prepared);
        const event = try receiver.receive(prepared);
        try std.testing.expectEqualStrings("hello", event.stream.data);
        try std.testing.expectEqual(@as(?u62, id), try receiver.acceptStream(.bidirectional));
        const answer = try receiver.prepareStream(id, "reply", true);
        try receiver.commit(answer);
        try std.testing.expectEqualStrings("reply", (try sender.receive(answer)).stream.data);
        try std.testing.expectEqual(@as(u64, 128), sender.streams.get(id).?.receive_limit);
        try std.testing.expectEqual(@as(u64, 512), receiver.streams.get(id).?.receive_limit);
        try std.testing.expectError(error.StreamStateError, receiver.receive(prepared));
        try std.testing.expectError(error.StreamStateError, sender.prepareStream(id, "late", false));
    }
}

test "WebTransport HTTP2 state enforces unidirectional ownership and cumulative implicit openings" {
    var client = try model.State.init(allocator, .client, generous, generous, 128);
    defer client.deinit();
    var server = try model.State.init(allocator, .server, generous, generous, 128);
    defer server.deinit();
    const one = try client.openStream(.unidirectional);
    const two = try client.openStream(.unidirectional);
    const three = try client.openStream(.unidirectional);
    const capsule = try client.prepareStream(three, "third", true);
    try client.commit(capsule);
    _ = try server.receive(capsule);
    try std.testing.expectEqual(@as(u64, 3), server.peer_opened[1]);
    try std.testing.expectEqual(@as(?u62, one), try server.acceptStream(.unidirectional));
    try std.testing.expectEqual(@as(?u62, two), try server.acceptStream(.unidirectional));
    try std.testing.expectEqual(@as(?u62, three), try server.acceptStream(.unidirectional));
    try std.testing.expectError(error.StreamStateError, server.prepareStream(three, "reverse", false));
    try std.testing.expectError(error.StreamStateError, client.receive(capsule));
    try std.testing.expectError(error.StreamStateError, server.receive(.{ .stream = .{ .id = 1, .data = "unopened local" } }));
    var tight = generous;
    tight.uni = 2;
    var bounded = try model.State.init(allocator, .server, tight, generous, 128);
    defer bounded.deinit();
    try std.testing.expectError(error.FlowControlError, bounded.receive(capsule));
    try std.testing.expectEqual(@as(u64, 0), bounded.peer_opened[1]);
    try std.testing.expectEqual(@as(usize, 0), bounded.streams.count());
}

test "WebTransport HTTP2 state applies session and per-stream credit transactionally" {
    var receive_limit = generous;
    receive_limit.data = 3;
    receive_limit.bidi_remote_data = 2;
    var sender = try model.State.init(allocator, .client, generous, receive_limit, 128);
    defer sender.deinit();
    var receiver = try model.State.init(allocator, .server, receive_limit, generous, 128);
    defer receiver.deinit();
    const id = try sender.openStream(.bidirectional);
    try std.testing.expectError(error.FlowControlBlocked, sender.prepareStream(id, "abc", false));
    try std.testing.expectError(error.FlowControlError, receiver.receive(.{ .stream = .{ .id = id, .data = "abc" } }));
    try std.testing.expectEqual(@as(u64, 0), receiver.received_data);
    try std.testing.expectEqual(@as(usize, 0), receiver.streams.count());
    const accepted = try sender.prepareStream(id, "ab", false);
    try sender.commit(accepted);
    _ = try receiver.receive(accepted);
    const grant = try receiver.prepareGrantStreamData(id, 10);
    try std.testing.expectEqual(@as(u64, 2), receiver.streams.get(id).?.receive_limit);
    try receiver.commit(grant);
    _ = try sender.receive(grant);
    _ = try sender.receive(grant); // Ordered HTTP/2 permits an equal MAX value.
    try std.testing.expectError(error.FlowControlError, sender.receive(.{ .max_stream_data = .{ .id = id, .limit = 9 } }));
    try std.testing.expectError(error.FlowControlBlocked, sender.prepareStream(id, "cd", false));
    const session_grant = try receiver.prepareGrantData(20);
    try receiver.commit(session_grant);
    _ = try sender.receive(session_grant);
    _ = try sender.receive(session_grant);
    const more = try sender.prepareStream(id, "cd", true);
    try sender.commit(more);
    _ = try receiver.receive(more);
    try std.testing.expectEqual(@as(u64, 4), receiver.received_data);
    try std.testing.expectError(error.FlowControlError, sender.receive(.{ .max_data = 19 }));
    try std.testing.expectEqual(@as(u64, 20), sender.send_limit.data);
}

test "WebTransport HTTP2 reset Reliable Size equals the ordered received prefix" {
    var client = try model.State.init(allocator, .client, generous, generous, 128);
    defer client.deinit();
    var server = try model.State.init(allocator, .server, generous, generous, 128);
    defer server.deinit();
    const id = try client.openStream(.unidirectional);
    const data = try client.prepareStream(id, "abc", false);
    try client.commit(data);
    _ = try server.receive(data);
    const reset = try client.prepareReset(id, 42);
    try std.testing.expectEqual(@as(u62, 3), reset.reset_stream.reliable_size);
    for ([_]u62{ 2, 4 }) |size| {
        try std.testing.expectError(error.StreamStateError, server.receive(.{ .reset_stream = .{ .id = id, .code = 42, .reliable_size = size } }));
        try std.testing.expect(server.streams.get(id).?.receive_reset == null);
    }
    try client.commit(reset);
    const event = try server.receive(reset);
    try std.testing.expectEqual(@as(u32, 42), event.reset.code);
    try std.testing.expectError(error.StreamStateError, server.receive(reset));
    try std.testing.expectError(error.StreamStateError, server.receive(data));
    try std.testing.expectError(error.StreamStateError, client.prepareStream(id, "late", true));
    try server.consume(id, 3);
    try server.retireStream(id);
    try std.testing.expectError(error.StreamStateError, server.receive(data));
    try std.testing.expectEqual(@as(u64, 3), server.consumed_data);
}

test "WebTransport HTTP2 STOP requires a reset and rejects later contradictory grants" {
    var client = try model.State.init(allocator, .client, generous, generous, 128);
    defer client.deinit();
    var server = try model.State.init(allocator, .server, generous, generous, 128);
    defer server.deinit();
    const id = try client.openStream(.unidirectional);
    const initial = try client.prepareStream(id, "", false);
    try client.commit(initial);
    _ = try server.receive(initial);
    const stop = try server.prepareStop(id, 71);
    try server.commit(stop);
    try std.testing.expectEqual(@as(u32, 71), (try client.receive(stop)).stopped.code);
    try std.testing.expectError(error.StreamStateError, client.receive(stop));
    try std.testing.expectError(error.StreamStateError, client.prepareStream(id, "blocked", false));
    try std.testing.expectError(error.StreamStateError, client.receive(.{ .max_stream_data = .{ .id = id, .limit = 512 } }));
    try std.testing.expectError(error.StreamStateError, server.prepareGrantStreamData(id, 512));
    const reset = try client.prepareReset(id, 71);
    try client.commit(reset);
    _ = try server.receive(reset);
    try server.retireStream(id);
}

test "WebTransport HTTP2 state retires long stream churn into compact closed-ID prefixes" {
    var limits = generous;
    limits.bidi = 0;
    limits.uni = 1;
    var client = try model.State.init(allocator, .client, .{}, limits, 8);
    defer client.deinit();
    var server = try model.State.init(allocator, .server, limits, .{}, 8);
    defer server.deinit();
    for (0..1024) |index| {
        if (index != 0) {
            const grant = try server.prepareGrantStreams(.unidirectional, index + 1);
            try server.commit(grant);
            _ = try client.receive(grant);
        }
        const id = try client.openStream(.unidirectional);
        const capsule = try client.prepareStream(id, "", true);
        try client.commit(capsule);
        _ = try server.receive(capsule);
        try std.testing.expectEqual(@as(?u62, id), try server.acceptStream(.unidirectional));
        try client.retireStream(id);
        try server.retireStream(id);
        try std.testing.expectEqual(@as(usize, 0), client.streams.count());
        try std.testing.expectEqual(@as(usize, 0), server.streams.count());
    }
    try std.testing.expectEqual(@as(u64, 1024), server.closed_ids[2].prefix_len);
    try std.testing.expectEqual(@as(usize, 0), server.closed_ids[2].sparseRangeCount());
}

test "WebTransport HTTP2 state clean close, receive close and draining retain transport semantics" {
    var state = try model.State.init(allocator, .client, generous, generous, 128);
    defer state.deinit();
    _ = try state.receive(.drain_session);
    try std.testing.expect(state.draining);
    const id = try state.openStream(.bidirectional);
    _ = try state.prepareStream(id, "still allowed during drain", false);
    try state.commit(.{ .close_session = .{ .code = 0, .reason = "done" } });
    try std.testing.expectError(error.SessionClosed, state.prepareStream(id, "late", true));
    const closed = try state.receive(.{ .close_session = .{ .code = 7, .reason = "peer" } });
    try std.testing.expectEqual(@as(u32, 7), closed.closed.code);
    try std.testing.expectError(error.SessionClosed, state.receive(.{ .datagram = "late" }));
}
