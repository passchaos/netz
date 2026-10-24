const std = @import("std");
const webtransport = @import("../mod.zig");
const http3 = @import("../../http3/mod.zig");
const quic = @import("../../quic/mod.zig");
const configuration = @import("flow.zig");

test "WebTransport explicit initial quotas preserve zero and validate bounds" {
    const limits: webtransport.flow_control.Limits = .{ .data = 0, .bidi = 1, .uni = 0 };
    const configured = try webtransport.settingsWithInitialFlowLimits(.{}, 2, limits);
    try std.testing.expectEqual(@as(u64, 0), configured.webtransport_initial_max_data);
    try std.testing.expectEqual(@as(u64, 1), configured.webtransport_initial_max_streams_bidi);
    try std.testing.expectEqual(@as(u64, 0), configured.webtransport_initial_max_streams_uni);
    var state = try webtransport.flow_control.State.init(configured, configured);
    try std.testing.expect(state.enabled);
    try std.testing.expectEqual(@as(u64, 0), state.sendDataAvailable());
    try state.openLocal(.bidirectional);
    try std.testing.expectError(error.FlowControlBlocked, state.openLocal(.bidirectional));
    try std.testing.expectError(error.FlowControlBlocked, state.openLocal(.unidirectional));
    try std.testing.expectEqualDeep(webtransport.defaultSettings(.{}), try webtransport.settingsWithInitialFlowLimits(.{}, 1, null));
    const disabled = try webtransport.settingsWithInitialFlowLimits(.{}, 1, .{});
    try std.testing.expect(!webtransport.flow_control.negotiated(disabled, disabled));
    try std.testing.expectError(error.InvalidSessionState, webtransport.settingsWithInitialFlowLimits(.{}, 2, .{}));
    try std.testing.expectError(error.FlowControlViolation, webtransport.settingsWithInitialFlowLimits(.{}, 1, .{ .data = @as(u64, quic.varint.max_value) + 1 }));
    try std.testing.expectError(error.FlowControlViolation, webtransport.settingsWithInitialFlowLimits(.{}, 1, .{ .bidi = webtransport.flow_control.max_streams + 1 }));
    try std.testing.expectError(error.FlowControlViolation, webtransport.settingsWithInitialFlowLimits(.{}, 1, .{ .uni = webtransport.flow_control.max_streams + 1 }));
}

test "WebTransport explicit initial quotas cannot rewrite an established transport" {
    const limits: webtransport.flow_control.Limits = .{ .data = 0, .bidi = 1, .uni = 0 };
    const configured = try webtransport.settingsWithInitialFlowLimits(.{}, 1, limits);
    try configuration.validateExisting(configured, limits);
    try configuration.validateExisting(configured, null);
    try std.testing.expectError(error.InvalidSessionState, configuration.validateExisting(configured, .{ .data = 1, .bidi = 1, .uni = 0 }));
}

test "WebTransport explicit initial quotas reject stateless adapters before allocation" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const limits: webtransport.runtime.Limits = .{ .initial_flow_limits = .{ .data = 0, .bidi = 1, .uni = 0 } };
    try std.testing.expectError(error.WebTransportNotNegotiated, webtransport.runtime.Server.bind(failing.allocator(), undefined, .{ .ip4 = .loopback(0) }, limits));
    try std.testing.expectError(error.WebTransportNotNegotiated, webtransport.runtime.ProtectedServer.bind(failing.allocator(), undefined, .{ .ip4 = .loopback(0) }, limits, undefined));
    try std.testing.expect(!failing.has_induced_failure);
}
