//! Atomic one-attempt flow-control grants on an established CONNECT stream.

const std = @import("std");
const webtransport = @import("../../mod.zig");
const control_mod = @import("../session_control.zig");

pub fn send(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, capsule: webtransport.Capsule) control_mod.Error!void {
    return sendMany(control, h3, registry, &.{capsule});
}

/// Coalesce independent MAX_DATA/bidi/uni updates into one transactional DATA
/// submission. Duplicate grant kinds are rejected before any Capsule is sent.
pub fn sendMany(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, capsules: []const webtransport.Capsule) control_mod.Error!void {
    try control.ensureOpen();
    const state = registry.flow orelse return error.WebTransportNotNegotiated;
    if (capsules.len == 0) return;
    if (capsules.len > 3) return error.InvalidSessionState;
    var prepared: [3]webtransport.Capsule = undefined;
    var storage: [3 * 13]u8 = undefined;
    var length: usize = 0;
    var seen: u3 = 0;
    for (capsules, 0..) |capsule, index| {
        const bit: u3 = switch (capsule) {
            .max_data => 1,
            .max_streams_bidi => 2,
            .max_streams_uni => 4,
            else => return error.InvalidSessionState,
        };
        if (seen & bit != 0) return error.InvalidSessionState;
        seen |= bit;
        prepared[index] = switch (capsule) {
            .max_data => |value| try state.prepareGrantData(value),
            .max_streams_bidi => |value| try state.prepareGrantStreams(.bidirectional, value),
            .max_streams_uni => |value| try state.prepareGrantStreams(.unidirectional, value),
            else => unreachable,
        };
        length += (try prepared[index].writeInto(storage[length..])).len;
    }
    const H3 = @typeInfo(@TypeOf(h3)).pointer.child;
    if (comptime @hasDecl(H3, "trySendResponseBody")) {
        try h3.trySendResponseBody(control.session_id.value, storage[0..length], false);
    } else {
        try h3.trySendRequestBody(control.session_id.value, storage[0..length], false);
    }
    for (prepared[0..capsules.len]) |capsule| state.commitGrant(capsule) catch unreachable;
}

test {
    _ = @import("grant/tests.zig");
}
