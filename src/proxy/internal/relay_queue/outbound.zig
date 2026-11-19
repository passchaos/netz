//! FIFO ownership across partial/blocked QUIC relay sends.

const std = @import("std");
const Relay = @import("../relay_queue.zig").Relay;

pub const Item = union(enum) {
    data: []u8,
    fin,
};

pub const Result = enum {
    /// The complete item has committed; the queue may release its storage.
    complete,
    /// The item (including any unsent suffix) remains owned by the queue.
    blocked,
    /// A prefix committed; retain the item and continue within this turn's budget.
    progress,
    /// Retire the relay and release this item; teardown owns queued successors.
    fatal,
};

pub fn drain(relay: *Relay, context: anytype, comptime send: anytype) void {
    // A turn handles at most one queue capacity, even with a concurrent producer.
    for (0..relay.outbound_storage.len) |_| {
        if (relay.closed.load(.acquire)) return;
        if (relay.pending_out == null) {
            var next: [1]Item = undefined;
            const count = relay.outbound.get(relay.io, &next, 0) catch return;
            if (count == 0) return;
            relay.pending_out = next[0];
        }
        const item = relay.pending_out.?;
        const result = send(context, relay, item);
        if (result == .blocked) return;
        if (result == .progress) continue;
        relay.freeOutbound(item);
        relay.pending_out = null;
        relay.pending_data_start = 0;
        if (result == .fatal) {
            relay.closed.store(true, .release);
            return;
        }
    }
}

pub fn discard(relay: *Relay) void {
    if (relay.pending_out) |item| relay.freeOutbound(item);
    relay.pending_out = null;
    relay.pending_data_start = 0;
    while (true) {
        var batch: [8]Item = undefined;
        const count = relay.outbound.get(relay.io, &batch, 0) catch break;
        if (count == 0) break;
        for (batch[0..count]) |item| relay.freeOutbound(item);
    }
}
