//! Reversible subscription updates under the router's single-owner boundary.

const std = @import("std");
const mqtt = @import("../mod.zig");

pub fn SubscriptionBatch(comptime Context: type) type {
    return struct {
        const Self = @This();
        const Previous = struct {
            subscription: mqtt.Subscription,
            identifier: ?usize,
        };
        const Operation = struct {
            filter: []const u8,
            previous: ?Previous,
        };

        router: *Context.RouterType,
        subscriber_id: u64,
        operations: []Operation,
        count: usize = 0,
        committed: bool = false,

        pub fn init(router: *Context.RouterType, subscriber_id: u64, capacity: usize) Context.ErrorType!Self {
            return .{
                .router = router,
                .subscriber_id = subscriber_id,
                .operations = try router.allocator.alloc(Operation, capacity),
            };
        }

        /// Filters remain borrowed until commit/deinit. Serialize this batch
        /// with every other router mutation and query, including shared-group
        /// selection, so rollback observes exactly the state it prepared.
        pub fn subscribe(self: *Self, subscription: mqtt.Subscription, identifier: ?usize) Context.ErrorType!bool {
            std.debug.assert(!self.committed);
            if (self.count == self.operations.len) return error.SubscriptionBatchFull;
            const previous: ?Previous = if (Context.findEntry(self.router.*, self.subscriber_id, subscription.topic_filter)) |index| .{
                .subscription = self.router.entries.items[index].?.subscription,
                .identifier = self.router.entries.items[index].?.subscription_identifier,
            } else null;
            const existed = try self.router.subscribeWithIdentifierStatus(self.subscriber_id, subscription, identifier);
            self.operations[self.count] = .{ .filter = subscription.topic_filter, .previous = previous };
            self.count += 1;
            return existed;
        }

        /// Every resource and validation step has already succeeded.
        pub fn commit(self: *Self) void {
            std.debug.assert(!self.committed);
            self.committed = true;
        }

        /// An uncommitted batch restores old policies/identifiers and removes
        /// only entries it inserted. Existing route and group identities stay
        /// stable. No allocation is needed during rollback or committed cleanup.
        pub fn deinit(self: *Self) void {
            if (!self.committed) {
                while (self.count != 0) {
                    self.count -= 1;
                    const operation = self.operations[self.count];
                    if (operation.previous) |previous| {
                        _ = self.router.subscribeWithIdentifierStatus(self.subscriber_id, previous.subscription, previous.identifier) catch unreachable;
                    } else {
                        self.router.unsubscribe(self.subscriber_id, operation.filter) catch unreachable;
                    }
                }
            }
            self.router.allocator.free(self.operations);
            self.* = undefined;
        }
    };
}
