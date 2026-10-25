//! Finish an expirable target PUBLISH behind the durable source ACK boundary.
const std = @import("std");
const coordinator = @import("outbound_coordinator.zig");

pub fn completeExpiredTarget(bridge: anytype) coordinator.Error!bool {
    const transaction = if (bridge.coordinator) |*store| store.currentTransaction() orelse return false else return false;
    if (transaction.phase != .target_await_pubrec or transaction.source_expiry_interval == null) return false;
    const state = try bridge.target.outgoingQoSState(transaction.target_packet_id);
    if (state != null) {
        if (state != .await_pubrec or !try bridge.target.outgoing.outgoingPublishExpired(bridge.target.outgoing_handle, transaction.target_packet_id, std.Io.Clock.awake.now(bridge.target.io))) return false;
        // commit normalizes the expiring PUBLISH and removes its live Store
        // entry only after the coherent terminal journal record is synced.
        _ = try bridge.coordinator.?.commit(&bridge.source, &bridge.target, bridge.source_session_epoch, bridge.target_session_epoch, transaction);
    } else {
        // Reconnect replay may already have pruned this expiring PUBLISH. A
        // target acknowledgement/rejection is reconciled by the caller first.
        var expired = transaction;
        expired.phase = .target_complete;
        expired.target_reason_code = 0;
        _ = try bridge.coordinator.?.commit(&bridge.source, &bridge.target, bridge.source_session_epoch, bridge.target_session_epoch, expired);
    }
    return true;
}
