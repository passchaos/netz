//! Serialize fanout with recipient teardown, without failing its publisher.
pub fn run(comptime Context: type, broker: *Context.BrokerType, matches: []const Context.MatchType) Context.ErrorType!void {
    for (matches) |match| {
        const index = Context.index(match.subscriber_id, broker.slots.len) orelse continue;
        const slot = &broker.slots[index];
        slot.writer_mutex.lockUncancelable(broker.io);
        defer slot.writer_mutex.unlock(broker.io);
        broker.state_mutex.lockUncancelable(broker.io);
        const current = slot.state.active and slot.connection != null and
            Context.id(index, slot.state.generation) == match.subscriber_id;
        broker.state_mutex.unlock(broker.io);
        if (!current) continue;

        Context.flush(broker, slot, true) catch |err| {
            if (!Context.transportClosed(err)) return err;
            // This recipient's writer owns the failure. Wake its sole reader
            // to retire the transport and preserve durable Session state.
            // The writer lock keeps this pointer in the checked generation.
            slot.connection.?.interrupt() catch {};
        };
    }
}
