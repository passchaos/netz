//! Validate coordinator ownership at the checkpoint, before aging its Sessions.
const std = @import("std");
const session = @import("../session/mod.zig");
const snapshot = @import("../reconnect/snapshot.zig");

pub const Error = snapshot.Error || @import("../reconnect.zig").Error || @import("local_source.zig").Error || error{
    CorruptCoordinatorSnapshot,
    SourceSessionLost,
    TargetSessionLost,
};

pub const Retention = struct {
    source_expired: bool,
    target_expired: bool,
};

const Checkpoint = struct {
    restored: *snapshot.Restored,

    fn outgoingStats(self: *@This()) session.Error!session.Stats {
        return self.restored.store.stats(self.restored.handle);
    }

    fn incomingQoS2State(self: *@This(), packet_id: u16) session.Error!?session.IncomingQoS2State {
        return self.restored.store.incomingQoS2State(self.restored.handle, packet_id);
    }

    fn outgoingQoSState(self: *@This(), packet_id: u16) session.Error!?session.OutgoingQoSState {
        return self.restored.store.outgoingQoSState(self.restored.handle, packet_id);
    }
};

fn decode(client: anytype, bytes: []const u8, now: std.Io.Timestamp, realtime: std.Io.Timestamp) snapshot.Error!snapshot.Restored {
    if (comptime @hasField(@TypeOf(client.*), "receipts")) {
        return snapshot.decodeCheckpoint(client.allocator, bytes, client.receipts.options, .v5, client.client_id, now, realtime, client.receipts.options.max_subscriptions_per_session);
    }
    return snapshot.decodeCheckpoint(client.allocator, bytes, client.outgoing.options, client.options.value.protocol, client.clientId(), now, realtime, client.client_options.max_subscriptions);
}

pub fn validateCheckpoint(decoded: anytype, source: anytype, target: anytype, now: std.Io.Timestamp, realtime: std.Io.Timestamp) Error!Retention {
    var source_state = try decode(source, decoded.source_snapshot, now, realtime);
    defer source_state.deinit();
    var target_state = try decode(target, decoded.target_snapshot, now, realtime);
    defer target_state.deinit();
    var source_view = Checkpoint{ .restored = &source_state };
    var target_view = Checkpoint{ .restored = &target_state };
    try validate(if (decoded.transaction) |*transaction| transaction.view() else null, decoded.source_session_epoch, decoded.target_session_epoch, &source_view, &target_view);
    return .{
        .source_expired = if (source_state.retention_state) |state| state.expired(now) else false,
        .target_expired = if (target_state.retention_state) |state| state.expired(now) else false,
    };
}

pub fn validate(maybe_transaction: anytype, source_session_epoch: u64, target_session_epoch: u64, source: anytype, target: anytype) Error!void {
    const transaction = maybe_transaction orelse {
        if ((try source.outgoingStats()).incoming_qos2_count != 0 or
            (try target.outgoingStats()).inflight_count != 0)
        {
            return error.CorruptCoordinatorSnapshot;
        }
        return;
    };
    if (transaction.source_session_epoch != source_session_epoch or
        transaction.target_session_epoch != target_session_epoch)
    {
        return error.CorruptCoordinatorSnapshot;
    }
    const target_state = try target.outgoingQoSState(transaction.target_packet_id);
    const target_stats = try target.outgoingStats();
    switch (transaction.phase) {
        .target_await_pubrec => if (target_state != .await_pubrec or target_stats.inflight_count != 1) {
            return error.CorruptCoordinatorSnapshot;
        },
        .target_await_pubcomp => if (target_state != .await_pubcomp or target_stats.inflight_count != 1) {
            return error.CorruptCoordinatorSnapshot;
        },
        .target_complete => if (target_state != null or target_stats.inflight_count != 0 or transaction.target_reason_code >= 0x80) {
            return error.CorruptCoordinatorSnapshot;
        },
        .target_rejected => if (target_state != null or target_stats.inflight_count != 0 or transaction.target_reason_code < 0x80) {
            return error.CorruptCoordinatorSnapshot;
        },
    }
    const source_state = try source.incomingQoS2State(transaction.source_packet_id);
    if (source_state != .await_pubrel and source_state != .release_pending) return error.CorruptCoordinatorSnapshot;
    if ((try source.outgoingStats()).incoming_qos2_count != 1) return error.CorruptCoordinatorSnapshot;
}
