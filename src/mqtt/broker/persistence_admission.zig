//! Coordinate CONNECT reservations with atomic persistence transactions.
const std = @import("std");

/// Publish a reservation under persistence -> state ordering. A transaction
/// that already owns persistence cannot gain a new provisional CONNECT while
/// its state mutation, rollback, and fsync are in progress.
pub fn claimSlot(comptime Context: type, broker: *Context.BrokerType) (std.Io.Cancelable || error{BrokerFull})!usize {
    try broker.persistence_mutex.lock(broker.io);
    defer broker.persistence_mutex.unlock(broker.io);
    try broker.state_mutex.lock(broker.io);
    defer broker.state_mutex.unlock(broker.io);
    // Uncontended Mutex.lock does not introduce a cancellation point. Do not
    // publish a slot after cancellation won either acquisition race.
    try broker.io.checkCancel();
    for (broker.slots, 0..) |slot, index| {
        if (!slot.state.active) {
            broker.slots[index].state.active = true;
            broker.slots[index].state.registration_aborted = false;
            broker.connections_received +|= 1;
            return index;
        }
    }
    return error.BrokerFull;
}

/// Return owning persistence_mutex, before the caller mutates any state.
/// Existing admissions may attach or abort while this caller waits outside
/// both mutexes. Once acquired, the caller keeps the lock for its entire
/// existing transaction, including rollback and synchronous journal append.
pub fn lockTransaction(comptime Context: type, broker: *Context.BrokerType) std.Io.Cancelable!void {
    while (true) {
        broker.persistence_mutex.lockUncancelable(broker.io);
        if (broker.commit_log == null) return;
        broker.state_mutex.lockUncancelable(broker.io);
        const pending = Context.hasProvisionalRegistration(broker);
        broker.state_mutex.unlock(broker.io);
        if (!pending) return;
        broker.persistence_mutex.unlock(broker.io);
        try std.Io.sleep(broker.io, .fromMilliseconds(1), .awake);
    }
}
