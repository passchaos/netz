//! Bootstrap rejects malformed peers before Connection owns protocol state.
//! Its caller closes the transport after this single bounded output attempt.
const std = @import("std");
const http2 = @import("../../mod.zig");
const frame_io = @import("../frame/io.zig");
const frame_wire = @import("../frame/wire.zig");
const cleanup = @import("../response/cleanup.zig");
const tls_close = @import("../control/tls_close.zig");

pub fn reject(transport: anytype, limits: anytype, code: http2.ErrorCode, detail: []const u8, operation_deadline: ?std.Io.Clock.Timestamp) void {
    // A pending TLS record may already contain an unknown committed prefix.
    // Bootstrap will close it; never append GOAWAY to ambiguous framing.
    const io = switch (transport) {
        .tcp => |tcp| tcp.io,
        .tls_client => |connection| connection.io,
        .tls_server => |connection| connection.io,
    };
    const before = cleanup.cleanupDeadline(.{ .io = io, .limits = limits }, operation_deadline);
    defer tls_close.closeNotify(transport, before);
    if (transport.hasPendingWrite()) return;
    const absolute = before orelse return;
    var storage: [256]u8 = undefined;
    const encoded = http2.GoAwayPayload.writeInto(&storage, 0, code, detail) catch return;
    var committed: usize = 0;
    transport.writeAllWithDeadline(encoded, &committed, absolute) catch {
        tls_close.retire(transport);
    };
}

pub fn readFrame(allocator: std.mem.Allocator, transport: anytype, limits: anytype, deadline: ?std.Io.Clock.Timestamp) !frame_io.OwnedFrame {
    var violation: ?frame_wire.EnvelopeViolation = null;
    return frame_io.readOwnedTransportWithDeadlineClassified(
        allocator,
        transport,
        @min(limits.max_frame_payload, limits.max_frame_size),
        deadline,
        &violation,
    ) catch |err| {
        if (violation) |value| reject(transport, limits, value.error_code, "frame-envelope", deadline);
        return err;
    };
}

pub fn parseSettings(allocator: std.mem.Allocator, transport: anytype, limits: anytype, payload: []const u8, deadline: ?std.Io.Clock.Timestamp) ![]http2.Setting {
    return http2.parseSettings(allocator, payload) catch |err| {
        if (settingsFailureCode(payload, err)) |code| reject(transport, limits, code, "settings-value", deadline);
        return err;
    };
}

pub fn settingsFailureCode(payload: []const u8, err: anyerror) ?http2.ErrorCode {
    if (err == error.FlowControlViolation) return .flow_control_error;
    if (err != error.InvalidSetting) return null;
    if (payload.len % 6 != 0) return .frame_size_error;
    var offset: usize = 0;
    while (offset < payload.len) : (offset += 6) {
        const id: http2.SettingId = @enumFromInt(std.mem.readInt(u16, payload[offset..][0..2], .big));
        const value = std.mem.readInt(u32, payload[offset + 2 ..][0..4], .big);
        http2.validateSetting(id, value) catch {
            return if (id == .initial_window_size) .flow_control_error else .protocol_error;
        };
    }
    // Role constraints and irreversible extension settings are checked while
    // applying otherwise well-formed values to established protocol state.
    return .protocol_error;
}
