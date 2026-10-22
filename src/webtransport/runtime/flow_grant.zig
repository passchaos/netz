//! Atomic one-attempt flow-control grants on an established CONNECT stream.

const std = @import("std");
const webtransport = @import("../mod.zig");
const control_mod = @import("session_control.zig");

pub fn send(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry, capsule: webtransport.Capsule) control_mod.Error!void {
    try control.ensureOpen();
    const state = registry.flow orelse return error.WebTransportNotNegotiated;
    const prepared = switch (capsule) {
        .max_data => |value| try state.prepareGrantData(value),
        .max_streams_bidi => |value| try state.prepareGrantStreams(.bidirectional, value),
        .max_streams_uni => |value| try state.prepareGrantStreams(.unidirectional, value),
        else => return error.InvalidSessionState,
    };
    var storage: [13]u8 = undefined;
    const encoded = try prepared.writeInto(&storage);
    const H3 = @typeInfo(@TypeOf(h3)).pointer.child;
    if (comptime @hasDecl(H3, "trySendResponseBody")) {
        try h3.trySendResponseBody(control.session_id.value, encoded, false);
    } else {
        try h3.trySendRequestBody(control.session_id.value, encoded, false);
    }
    try state.commitGrant(prepared);
}
