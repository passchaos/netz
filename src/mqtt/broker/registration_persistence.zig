//! Persist CONNECT rollback without releasing its reserved connection slot.
//! Other in-progress admissions still block coherent encoding. Retain the
//! journal correction until an admission settles or another final append
//! captures the corrected state. All journal debt uses persistence_mutex.

pub fn rollback(
    comptime Context: type,
    broker: *Context.BrokerType,
    changed: bool,
    append_commit: bool,
) void {
    broker.persistence_mutex.lockUncancelable(broker.io);
    defer broker.persistence_mutex.unlock(broker.io);
    if (append_commit and broker.commit_log != null) {
        broker.registration_rollback_commit_pending = true;
    }
    flush(Context, broker);
    if (changed) Context.autosavePersistentChangesIfNeededLocked(broker);
}

pub fn settled(comptime Context: type, broker: *Context.BrokerType) void {
    if (broker.commit_log == null and
        !broker.persistent_change_autosave_enabled.load(.acquire)) return;
    broker.persistence_mutex.lockUncancelable(broker.io);
    defer broker.persistence_mutex.unlock(broker.io);
    flush(Context, broker);
    Context.autosavePersistentChangesIfNeededLocked(broker);
}

fn flush(comptime Context: type, broker: *Context.BrokerType) void {
    if (!broker.registration_rollback_commit_pending) return;
    // The append clears debt only on success. Preserve the original CONNECT
    // error; SnapshotBusy and I/O failures are retried at later boundaries.
    Context.appendCommitIfEnabledLocked(broker) catch {};
}
