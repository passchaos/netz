//! Automatic control preparation retains already-consumed frame ownership.
const std = @import("std");
const secure_random = @import("../../../internal/secure_random.zig");
const websocket = @import("../../mod.zig");
const common = @import("../common.zig");

pub const Error = websocket.Error || std.Io.RandomSecureError || error{WriteInProgress};

/// Caller holds the send mutex. Owned `frame` transfers at entry, including
/// preparation failure; borrowed message readers transfer no frame and keep
/// their source bytes until preparation succeeds.
pub fn begin(connection: anytype, io: std.Io, role: common.Role, opcode: websocket.Opcode, payload: []const u8, delivery: common.PendingAutomaticControl.Delivery, frame: ?websocket.Frame, fin_committed: bool) Error!void {
    var owned = frame != null;
    errdefer if (owned) {
        var failed = frame.?;
        failed.deinit(connection.allocator);
    };
    if (connection.pending_auto_control != null) return error.WriteInProgress;
    var pending: common.PendingAutomaticControl = .{ .opcode = opcode, .delivery = delivery, .frame = frame, .fin_committed = fin_committed };
    if (frame != null) {
        // A mask-key error is local and happened before wire submission. The
        // consumed peer frame must remain available with its original owner.
        connection.pending_auto_control = pending;
        connection.automatic_write_pending.store(true, .release);
        owned = false;
        try encode(&connection.pending_auto_control.?, io, role, payload);
        return;
    }
    try encode(&pending, io, role, payload);
    connection.pending_auto_control = pending;
    connection.automatic_write_pending.store(true, .release);
}

/// Complete deferred encoding before testing write completion. Once encoded,
/// retries preserve the same mask and exact wire-byte cursor.
pub fn resumeEncoding(pending: *common.PendingAutomaticControl, io: std.Io, role: common.Role) Error!void {
    if (!pending.writes_reply or pending.len != 0) return;
    const frame = pending.frame orelse return error.InvalidFrame;
    try encode(pending, io, role, frame.payload);
}

fn encode(pending: *common.PendingAutomaticControl, io: std.Io, role: common.Role, payload: []const u8) Error!void {
    const mask: ?[4]u8 = if (role == .client) blk: {
        var key: [4]u8 = undefined;
        try secure_random.fill(io, &key);
        break :blk key;
    } else null;
    const encoded = try websocket.writeFrameInto(&pending.bytes, pending.opcode, payload, .{ .mask_key = mask });
    pending.len = encoded.len;
}
