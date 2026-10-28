//! Receive-owned automatic control waiting for admission to the output wire.
const std = @import("std");
const websocket = @import("../../mod.zig");
const common = @import("../common.zig");
const automatic = @import("automatic.zig");

pub const Admission = struct {
    opcode: websocket.Opcode,
    delivery: common.PendingAutomaticControl.Delivery,
    consumed_input: usize,
    payload: union(enum) {
        frame: websocket.Frame,
        copy: struct { bytes: [125]u8, len: u8 },
    },

    pub fn deinit(self: *Admission, allocator: std.mem.Allocator) void {
        switch (self.payload) {
            .frame => |*frame| frame.deinit(allocator),
            .copy => |*copy| std.crypto.secureZero(u8, &copy.bytes),
        }
        self.* = undefined;
    }
};

/// Writers consult only these atomics. The admission slot itself belongs to
/// the sole receive owner, including while a writer holds the send mutex.
pub fn pending(connection: anytype) bool {
    return connection.automatic_write_pending.load(.acquire) or
        connection.automatic_control_waiting.load(.acquire);
}

/// Capture a consumed frame or a bounded copy before waiting for the mutex.
/// Frame ownership transfers even on a local conflict or validation error.
pub fn stage(connection: anytype, opcode: websocket.Opcode, payload: []const u8, delivery: common.PendingAutomaticControl.Delivery, frame: ?websocket.Frame, consumed_input: usize) automatic.Error!void {
    errdefer if (frame) |value| {
        var failed = value;
        failed.deinit(connection.allocator);
    };
    if (pending(connection)) return error.WriteInProgress;
    if (payload.len > 125) return error.InvalidFrame;
    var value: Admission = .{ .opcode = opcode, .delivery = delivery, .consumed_input = consumed_input, .payload = undefined };
    if (frame) |owned| {
        value.payload = .{ .frame = owned };
    } else {
        value.payload = .{ .copy = .{ .bytes = undefined, .len = @intCast(payload.len) } };
        @memcpy(value.payload.copy.bytes[0..payload.len], payload);
    }
    connection.automatic_control_admission = value;
    connection.automatic_control_waiting.store(true, .release);
}

/// Caller is the receive owner and holds the send mutex. Return buffered input
/// to discard exactly once after successful admission. Borrowed input stays
/// intact on mask-key failure; owned frames move into the encoded transaction.
pub fn admit(connection: anytype, io: std.Io, role: common.Role, fin_committed: bool) (automatic.Error || error{ConnectionClosed})!usize {
    if (connection.write_aborted.load(.acquire) or connection.receive_failed.load(.acquire)) {
        clear(connection);
        return error.ConnectionClosed;
    }
    const admission = if (connection.automatic_control_admission) |*value| value else return 0;
    const consumed_input = admission.consumed_input;
    if (!@import("../message/state.zig").canSendOpcode(admission.opcode, connection.close_sent.load(.acquire), connection.close_received.load(.acquire))) {
        const frame: ?websocket.Frame = switch (admission.payload) {
            .frame => |frame| frame,
            .copy => null,
        };
        connection.pending_auto_control = .{ .opcode = admission.opcode, .delivery = admission.delivery, .writes_reply = false, .frame = frame, .fin_committed = fin_committed };
        connection.automatic_write_pending.store(true, .release);
        if (frame != null) admission.payload = .{ .copy = .{ .bytes = undefined, .len = 0 } };
        clear(connection);
        return consumed_input;
    }
    switch (admission.payload) {
        .frame => |frame| {
            // begin owns this frame on every result. Remove it from the
            // receive-owned slot before entering its preparation transaction.
            admission.payload = .{ .copy = .{ .bytes = undefined, .len = 0 } };
            defer clear(connection);
            try automatic.begin(connection, io, role, admission.opcode, frame.payload, admission.delivery, frame, fin_committed);
        },
        .copy => |*copy| {
            try automatic.begin(connection, io, role, admission.opcode, copy.bytes[0..copy.len], admission.delivery, null, fin_committed);
            clear(connection);
        },
    }
    return consumed_input;
}

/// Only the receive owner or the final connection destructor may release this
/// slot. A writer abort clears its own transactions and leaves this flag set
/// until the receiver observes the abort, preventing concurrent frame frees.
pub fn clear(connection: anytype) void {
    if (connection.automatic_control_admission) |*value| value.deinit(connection.allocator);
    connection.automatic_control_admission = null;
    connection.automatic_control_waiting.store(false, .release);
}
