const std = @import("std");
const flow = @import("../flow_control.zig");
const quic = @import("../../quic/mod.zig");
const http3 = @import("../../http3/mod.zig");

fn settings(data: u64, bidi: u64, uni: u64) http3.Settings {
    return .{ .webtransport_initial_max_data = data, .webtransport_initial_max_streams_bidi = bidi, .webtransport_initial_max_streams_uni = uni };
}

test "WebTransport flow negotiation requires intent from both endpoints" {
    const enabled = settings(8, 0, 0);
    const sessions_only = http3.Settings{ .webtransport_max_sessions = 2 };
    try std.testing.expect(!flow.negotiated(enabled, sessions_only));
    try std.testing.expect(!flow.negotiated(sessions_only, enabled));
    try std.testing.expect(flow.negotiated(enabled, settings(0, 1, 0)));
    var disabled = try flow.State.init(enabled, sessions_only);
    const snapshot = disabled;
    try disabled.openLocal(.unidirectional);
    try disabled.accountReceived(0, quic.varint.max_value, 0);
    try std.testing.expect(!try disabled.receiveCapsule(.{ .max_streams_uni = std.math.maxInt(u64) }));
    try std.testing.expectEqualDeep(snapshot, disabled);
}

test "WebTransport flow zero stream credit requires an explicit increasing grant" {
    var state = try flow.State.init(settings(8, 0, 0), settings(8, 0, 0));
    try std.testing.expectError(error.FlowControlBlocked, state.openLocal(.unidirectional));
    try std.testing.expectError(error.FlowControlViolation, state.openPeer(.bidirectional));
    try std.testing.expect(try state.receiveCapsule(.{ .max_streams_uni = 1 }));
    try state.openLocal(.unidirectional);
    const snapshot = state;
    try std.testing.expectError(error.FlowControlBlocked, state.openLocal(.unidirectional));
    try std.testing.expectEqualDeep(snapshot, state);
    const grant = try state.prepareGrantStreams(.bidirectional, 1);
    try std.testing.expectEqual(@as(u64, 0), state.receive_limit.bidi);
    try state.commitGrant(grant);
    try state.openPeer(.bidirectional);
    try std.testing.expectError(error.FlowControlViolation, state.openPeer(.bidirectional));
}

test "WebTransport flow charges body highest offsets and reset final size" {
    var state = try flow.State.init(settings(10, 1, 1), settings(12, 1, 1));
    try state.accountSent(0, 3, 3);
    try std.testing.expectEqual(@as(u64, 0), state.sent.data);
    try state.accountSent(3, 10, 3);
    try state.accountSent(10, 8, 3);
    try std.testing.expectEqual(@as(u64, 7), state.sent.data);
    try state.accountSent(10, 15, 3);
    try std.testing.expectEqual(@as(u64, 0), state.sendDataAvailable());
    try std.testing.expectError(error.FlowControlBlocked, state.accountSent(15, 16, 3));
    try std.testing.expectEqual(@as(u64, 12), state.sent.data);
    try state.accountReceived(0, 8, 3);
    try state.accountReceived(8, 6, 3);
    try state.accountReset(8, 13, 3);
    try std.testing.expectEqual(@as(u64, 10), state.received.data);
    try std.testing.expectError(error.FlowControlViolation, state.accountReceived(0, 4, 3));
    try std.testing.expectError(error.FlowControlViolation, state.accountReset(8, 7, 3));
    try std.testing.expectError(error.FlowControlViolation, state.accountReset(0, 2, 3));
    try std.testing.expectEqual(@as(u64, 10), state.received.data);
}

test "WebTransport flow rejects duplicate decreasing and oversized peer limits" {
    var state = try flow.State.init(settings(8, 1, 1), settings(8, 1, 1));
    const snapshot = state;
    try std.testing.expectError(error.FlowControlViolation, state.receiveCapsule(.{ .max_data = 8 }));
    try std.testing.expectError(error.FlowControlViolation, state.receiveCapsule(.{ .max_data = 7 }));
    try std.testing.expectError(error.FlowControlViolation, state.receiveCapsule(.{ .max_streams_bidi = flow.max_streams + 1 }));
    try std.testing.expectEqualDeep(snapshot, state);
    try std.testing.expect(try state.receiveCapsule(.{ .max_streams_bidi = flow.max_streams }));
    try std.testing.expectError(error.FlowControlViolation, state.receiveCapsule(.{ .max_streams_bidi = flow.max_streams }));
    try std.testing.expect(try state.receiveCapsule(.{ .max_data = quic.varint.max_value }));
}

test "WebTransport flow grants remain transactional before capsule submission" {
    var state = try flow.State.init(settings(8, 1, 1), settings(8, 1, 1));
    const snapshot = state;
    const grant = try state.prepareGrantData(16);
    var short: [1]u8 = undefined;
    try std.testing.expectError(error.BufferTooShort, grant.writeInto(&short));
    try std.testing.expectEqualDeep(snapshot, state);
    var output: [32]u8 = undefined;
    _ = try grant.writeInto(&output);
    try state.commitGrant(grant);
    try std.testing.expectEqual(@as(u64, 16), state.receive_limit.data);
    try std.testing.expectError(error.FlowControlViolation, state.commitGrant(grant));
}

test "WebTransport flow automatic data grants preserve the receive policy window" {
    var state = try flow.State.init(settings(8, 1, 1), settings(8, 1, 1));
    state.consumed_data = 3;
    try std.testing.expect(state.automaticDataGrant() == null);
    state.consumed_data = 4;
    try std.testing.expectEqual(@as(?u64, 12), state.automaticDataGrant());
    try state.commitGrant(try state.prepareGrantData(12));
    try std.testing.expectEqual(@as(u64, 8), state.receive_window);
    try std.testing.expect(state.automaticDataGrant() == null);
    // Explicit grants can enlarge the live window without resetting usage.
    try state.commitGrant(try state.prepareGrantData(20));
    try std.testing.expectEqual(@as(u64, 16), state.receive_window);
    state.consumed_data = 12;
    try std.testing.expectEqual(@as(?u64, 28), state.automaticDataGrant());

    var zero = try flow.State.init(settings(0, 1, 1), settings(8, 1, 1));
    try std.testing.expect(zero.automaticDataGrant() == null);
    try zero.commitGrant(try zero.prepareGrantData(4));
    zero.consumed_data = 2;
    try std.testing.expectEqual(@as(?u64, 6), zero.automaticDataGrant());

    state.receive_limit.data = quic.varint.max_value;
    state.receive_window = quic.varint.max_value;
    state.consumed_data = quic.varint.max_value;
    try std.testing.expect(state.automaticDataGrant() == null);
}

test "WebTransport flow keeps independent session budgets and advisory blocked values" {
    var first = try flow.State.init(settings(16, 1, 1), settings(16, 1, 1));
    var second = try flow.State.init(settings(16, 1, 1), settings(16, 1, 1));
    try first.accountSent(0, 18, 3);
    try first.openLocal(.bidirectional);
    try std.testing.expectEqual(@as(u64, 16), second.sendDataAvailable());
    try second.openLocal(.bidirectional);
    try std.testing.expect(try first.receiveCapsule(.{ .data_blocked = 8 }));
    try std.testing.expect(try first.receiveCapsule(.{ .streams_blocked_uni = 0 }));
    try std.testing.expectEqual(@as(?u64, 8), first.peer_data_blocked);
    try std.testing.expectEqual(@as(?u64, 0), first.peer_uni_blocked);
    try std.testing.expect(first.peer_bidi_blocked == null);
    try std.testing.expect(second.peer_data_blocked == null);
    try std.testing.expectError(error.FlowControlViolation, first.receiveCapsule(.{ .streams_blocked_bidi = flow.max_streams + 1 }));
}

test "WebTransport flow rejects HTTP2-only capsules even without negotiation" {
    for ([_]http3.Settings{ .{}, settings(8, 1, 1) }) |local| {
        var state = try flow.State.init(local, local);
        const snapshot = state;
        for ([_]u64{ flow.prohibited_max_stream_data, flow.prohibited_stream_data_blocked }) |kind| {
            try std.testing.expectError(error.FlowControlViolation, state.receiveCapsule(.{ .unknown = .{ .capsule_type = kind, .payload = &.{} } }));
            try std.testing.expectEqualDeep(snapshot, state);
        }
        try std.testing.expect(!try state.receiveCapsule(.{ .unknown = .{ .capsule_type = 0x21, .payload = "extension" } }));
    }
}

test "WebTransport flow SETTINGS reject impossible initial stream counts" {
    try std.testing.expectError(error.FlowControlViolation, flow.State.init(settings(8, flow.max_streams + 1, 0), settings(8, 0, 0)));
    var maximum = try flow.State.init(settings(8, flow.max_streams, flow.max_streams), settings(8, flow.max_streams, flow.max_streams));
    try maximum.openLocal(.bidirectional);
    try maximum.openPeer(.unidirectional);
}
