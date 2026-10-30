//! Endpoint attempt state and failure policy for an ordinary Channel pass.
const std = @import("std");
const net = std.Io.net;

/// Private owner hooks retain Channel's bookkeeping boundary while this
/// module owns parallel attempt completion and successful-loser cleanup.
pub fn Context(comptime Owner: type, comptime Error: type, comptime hooks: anytype) type {
    return struct {
        channel: *Owner,
        deadline: ?std.Io.Clock.Timestamp,
        retryable: *std.atomic.Value(bool),

        pub fn count(self: @This()) usize {
            return self.channel.slots.len;
        }
        pub fn start(self: @This()) void {
            hooks.publish(self.channel, .connecting);
        }
        pub fn eligible(self: @This(), index: usize) bool {
            const slot = &self.channel.slots[index];
            if (slot.disabled) return false;
            if (!hooks.may_attempt(slot, self.channel.io)) {
                self.retryable.store(true, .release);
                return false;
            }
            return true;
        }
        pub fn family(self: @This(), index: usize) ?std.meta.Tag(net.IpAddress) {
            return switch (self.channel.slots[index].endpoint) {
                .cleartext_ip => |target| std.meta.activeTag(target.address),
                .tls_address => |target| std.meta.activeTag(target.address),
                else => null,
            };
        }
        pub fn connect(self: @This(), io: std.Io, index: usize, _: usize) Error!usize {
            const channel = self.channel;
            if (channel.canceled.isSet()) return error.Canceled;
            const slot = &channel.slots[index];
            const until = try hooks.connect_deadline(channel, self.deadline);
            // A stable heap guard serializes connector allocations without
            // holding a lock over any network wait. Application responses
            // continue to own the caller's original allocator.
            slot.connection = hooks.connect_endpoint(slot.endpoint, channel.connect_allocator.?.allocator(), io, until) catch |err| {
                if (err == error.Canceled or err == error.ConcurrencyUnavailable or err == error.OutOfMemory) return err;
                if (hooks.expired(io, self.deadline)) return error.Timeout;
                if (!hooks.retryable_endpoint(slot.endpoint, err)) {
                    slot.disabled = true;
                    return error.ConnectionUnavailable;
                }
                slot.consecutive_failures +|= 1;
                hooks.schedule_backoff(channel, slot);
                self.retryable.store(true, .release);
                // The multi-endpoint pass reports exhausted candidates as
                // unavailable. A per-attempt Timeout must not terminate an
                // unexpired wait-for-ready RPC instead of entering backoff.
                return error.ConnectionUnavailable;
            };
            hooks.reset_backoff(slot);
            return index;
        }
        pub fn deinitConnected(self: @This(), index: *usize) void {
            hooks.close(&self.channel.slots[index.*]);
        }
        pub fn tryNext(err: anyerror) bool {
            return err != error.Canceled and err != error.ConcurrencyUnavailable and err != error.OutOfMemory;
        }
    };
}
