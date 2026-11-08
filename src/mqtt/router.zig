const std = @import("std");
const mqtt = @import("mod.zig");
const tree = @import("router/tree.zig");

pub const Error = mqtt.Error || error{
    SubscriptionNotFound,
    SubscriptionBatchFull,
    MatchBufferTooSmall,
};

const BatchContext = struct {
    pub const RouterType = Router;
    pub const ErrorType = Error;
    pub const findEntry = Router.findEntry;
};
pub const SubscriptionBatch = @import("router/batch.zig").SubscriptionBatch(BatchContext);
pub const PreparedSubscription = @import("router/batch.zig").PreparedSubscription(BatchContext);

pub const SubscriberId = u64;

pub const Match = struct {
    subscriber_id: SubscriberId,
    subscription: mqtt.Subscription,
    subscription_identifier: ?usize,
};

/// Selection policy for one MQTT 5 shared-subscription group/filter.
///
/// The first three mirror rumqttd's broker configuration. Rendezvous hashing
/// additionally gives a stable topic-to-member assignment: adding or removing
/// a member remaps only the topics that choose that member instead of moving
/// every group's cursor.
pub const SharedSubscriptionStrategy = enum {
    round_robin,
    random,
    sticky,
    rendezvous_hash,
};

pub const Options = struct {
    shared_subscription_strategy: SharedSubscriptionStrategy = .round_robin,
    /// Deterministic seed for the `random` strategy. Brokers that require
    /// process-unique sequences can supply secure random startup bytes.
    random_seed: u64 = 0x6d71_7474_5f72_6f75,
};

const Entry = struct {
    subscriber_id: SubscriberId,
    subscription: mqtt.Subscription,
    subscription_identifier: ?usize = null,
    effective_filter: []const u8,
    shared_group: ?[]const u8 = null,
    shared_group_index: ?usize = null,

    fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
        allocator.free(self.subscription.topic_filter);
        self.* = undefined;
    }
};

const SharedGroup = struct {
    name: []u8,
    effective_filter: []u8,
    strategy: SharedSubscriptionStrategy,
    cursor: usize = 0,
    selection_seed: u64,
    random_state: u64,
    entry_indices: std.ArrayList(usize) = .empty,

    fn deinit(self: *SharedGroup, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.effective_filter);
        self.entry_indices.deinit(allocator);
        self.* = undefined;
    }
};

const SharedGroupKey = struct {
    name: []const u8,
    filter: []const u8,
};

const SharedGroupContext = struct {
    pub fn hash(_: @This(), key: SharedGroupKey) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(key.name);
        hasher.update(&.{0});
        hasher.update(key.filter);
        return hasher.final();
    }

    pub fn eql(_: @This(), a: SharedGroupKey, b: SharedGroupKey) bool {
        return std.mem.eql(u8, a.name, b.name) and
            std.mem.eql(u8, a.filter, b.filter);
    }
};

const SharedGroupMap = std.HashMapUnmanaged(
    SharedGroupKey,
    usize,
    SharedGroupContext,
    std.hash_map.default_max_load_percentage,
);

const SubscriberEntries = union(enum) {
    one: usize,
    many: std.ArrayList(usize),
};

const Node = tree.Node;

/// MQTT topic-filter trie with configurable shared-subscription selection.
///
/// Literal and `+` edges are traversed once per topic level; `#` subscriptions
/// terminate at their prefix node. Shared subscriptions are grouped by
/// `{ShareName, TopicFilter}` and emit exactly one member per publish using the
/// configured broker strategy.
pub const Router = struct {
    allocator: std.mem.Allocator,
    options: Options,
    nodes: std.ArrayList(Node) = .empty,
    recycled_node: ?usize = null,
    entries: std.ArrayList(?Entry) = .empty,
    /// Recycled entry slots. Subscription churn reuses these instead of
    /// rescanning the tombstone-preserving entry table from index zero.
    free_entries: std.ArrayList(usize) = .empty,
    /// Per-subscriber entry lists. Disconnect cleanup walks only this client's
    /// subscriptions instead of scanning every stored entry.
    subscriber_entries: std.AutoHashMapUnmanaged(
        SubscriberId,
        SubscriberEntries,
    ) = .empty,
    /// Live entry counts are maintained transactionally so broker hot paths do
    /// not rescan the tombstone-preserving entry table before every PUBLISH.
    active_entry_count: usize = 0,
    shared_entry_count: usize = 0,
    // Route representatives store `shared_group_index`, so group positions must
    // remain stable across unsubscribe.  Empty groups become tombstones that a
    // later group can reuse instead of compacting and invalidating indexes.
    shared_groups: std.ArrayList(?SharedGroup) = .empty,
    shared_group_map: SharedGroupMap = .empty,
    free_shared_groups: std.ArrayList(usize) = .empty,

    pub fn init(allocator: std.mem.Allocator) Error!Router {
        return initWithOptions(allocator, .{});
    }

    pub fn initWithOptions(
        allocator: std.mem.Allocator,
        options: Options,
    ) Error!Router {
        var router = Router{
            .allocator = allocator,
            .options = options,
        };
        errdefer router.deinit();
        try router.nodes.append(allocator, .{});
        return router;
    }

    pub fn deinit(self: *Router) void {
        for (self.entries.items) |*maybe_entry| {
            if (maybe_entry.*) |*entry| entry.deinit(self.allocator);
        }
        self.entries.deinit(self.allocator);
        self.free_entries.deinit(self.allocator);
        var subscriber_iterator = self.subscriber_entries.iterator();
        while (subscriber_iterator.next()) |subscriber| {
            switch (subscriber.value_ptr.*) {
                .one => {},
                .many => |*list| list.deinit(self.allocator),
            }
        }
        self.subscriber_entries.deinit(self.allocator);
        for (self.shared_groups.items) |*maybe_group| {
            if (maybe_group.*) |*group| group.deinit(self.allocator);
        }
        self.shared_groups.deinit(self.allocator);
        self.shared_group_map.deinit(self.allocator);
        self.free_shared_groups.deinit(self.allocator);
        for (self.nodes.items) |*node| node.deinit(self.allocator);
        self.nodes.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn subscriptionCount(self: Router) usize {
        return self.active_entry_count;
    }

    /// Count shared-subscription members, matching Mosquitto's
    /// `$SYS/broker/shared_subscriptions/count` semantics. This counts each
    /// client/filter membership, not only distinct `{group, filter}` keys.
    pub fn sharedSubscriptionCount(self: Router) usize {
        return self.shared_entry_count;
    }

    /// Prepare up to `capacity` reversible subscription updates. Hold the
    /// router's serialization boundary until the batch commits or deinitializes.
    pub fn beginSubscriptionBatch(self: *Router, subscriber_id: SubscriberId, capacity: usize) Error!SubscriptionBatch {
        return SubscriptionBatch.init(self, subscriber_id, capacity);
    }

    pub fn prepareSubscription(self: *Router, subscriber_id: SubscriberId, subscription: mqtt.Subscription, identifier: ?usize) Error!PreparedSubscription {
        return PreparedSubscription.init(self, subscriber_id, subscription, identifier);
    }

    pub fn subscribe(self: *Router, subscriber_id: SubscriberId, subscription: mqtt.Subscription) Error!void {
        _ = try self.subscribeWithStatus(subscriber_id, subscription);
    }

    /// Add or replace a subscription and report whether it already existed.
    ///
    /// MQTT 5 Retain Handling=1 needs this exact status to distinguish a new
    /// Subscription from a replacement. Returning it from the same mutation
    /// avoids a racy lookup-then-subscribe sequence in broker integrations.
    pub fn subscribeWithStatus(
        self: *Router,
        subscriber_id: SubscriberId,
        subscription: mqtt.Subscription,
    ) Error!bool {
        return self.subscribeWithIdentifierStatus(
            subscriber_id,
            subscription,
            null,
        );
    }

    /// Add or replace a subscription together with its MQTT 5 identifier.
    ///
    /// The identifier is packet-level SUBSCRIBE metadata but becomes part of
    /// every stored subscription from that packet. Keeping the legacy
    /// `subscribeWithStatus` wrapper preserves source compatibility for router
    /// users that do not need identifiers.
    pub fn subscribeWithIdentifierStatus(
        self: *Router,
        subscriber_id: SubscriberId,
        subscription: mqtt.Subscription,
        subscription_identifier: ?usize,
    ) Error!bool {
        try mqtt.validateSubscription(subscription, subscription_identifier);
        const parsed_input = parseFilter(subscription.topic_filter) orelse
            return error.InvalidSubscription;
        if (self.findEntryForSubscription(subscriber_id, parsed_input)) |entry_index| {
            // MQTT requires a repeated SUBSCRIBE for the same client/filter to
            // replace the prior subscription options. The routing path and
            // shared-group cursor stay stable; only delivery policy changes.
            const entry = &self.entries.items[entry_index].?;
            entry.subscription.qos = subscription.qos;
            entry.subscription.no_local = subscription.no_local;
            entry.subscription.retain_as_published = subscription.retain_as_published;
            entry.subscription.retain_handling = subscription.retain_handling;
            entry.subscription_identifier = subscription_identifier;
            return true;
        }

        const filter_owned = try self.allocator.dupe(u8, subscription.topic_filter);
        var owns_filter = true;
        errdefer if (owns_filter) self.allocator.free(filter_owned);
        const parsed = parseFilter(filter_owned) orelse return error.InvalidSubscription;

        // Reserve the eventual recycle slot now. Rollback and normal
        // unsubscribe then never allocate, which the batch contracts require.
        try self.free_entries.ensureUnusedCapacity(self.allocator, 1);

        const entry_index = try self.insertEntry(Entry{
            .subscriber_id = subscriber_id,
            .subscription = .{
                .topic_filter = filter_owned,
                .qos = subscription.qos,
                .no_local = subscription.no_local,
                .retain_as_published = subscription.retain_as_published,
                .retain_handling = subscription.retain_handling,
            },
            .subscription_identifier = subscription_identifier,
            .effective_filter = parsed.effective_filter,
            .shared_group = parsed.group,
        });
        owns_filter = false;
        errdefer {
            self.entries.items[entry_index].?.deinit(self.allocator);
            self.entries.items[entry_index] = null;
            self.free_entries.append(self.allocator, entry_index) catch {};
        }

        const subscriber_slot = try self.subscriber_entries.getOrPut(
            self.allocator,
            subscriber_id,
        );
        if (!subscriber_slot.found_existing) {
            subscriber_slot.value_ptr.* = .{ .one = entry_index };
        } else switch (subscriber_slot.value_ptr.*) {
            .one => |existing| {
                var list: std.ArrayList(usize) = .empty;
                errdefer list.deinit(self.allocator);
                try list.append(self.allocator, existing);
                try list.append(self.allocator, entry_index);
                subscriber_slot.value_ptr.* = .{ .many = list };
            },
            .many => |*list| try list.append(self.allocator, entry_index),
        }
        errdefer self.removeSubscriberEntry(subscriber_id, entry_index);

        if (parsed.group) |group| {
            const node_index, const multi_level = try self.insertFilterPath(parsed.effective_filter);
            errdefer tree.pruneEmpty(self, node_index);
            const group_index, const created = try self.getOrCreateSharedGroup(group, parsed.effective_filter);
            errdefer if (created) self.removeSharedGroupAt(group_index);
            self.entries.items[entry_index].?.shared_group_index = group_index;
            try self.shared_groups.items[group_index].?.entry_indices.append(self.allocator, entry_index);
            errdefer removeIndexValue(&self.shared_groups.items[group_index].?.entry_indices, entry_index);

            if (created) {
                try self.appendRouteEntry(node_index, multi_level, entry_index);
                errdefer self.removeRouteEntry(node_index, multi_level, entry_index);
            }
        } else {
            const node_index, const multi_level = try self.insertFilterPath(parsed.effective_filter);
            errdefer tree.pruneEmpty(self, node_index);
            try self.appendRouteEntry(node_index, multi_level, entry_index);
            errdefer self.removeRouteEntry(node_index, multi_level, entry_index);
        }
        self.active_entry_count += 1;
        self.shared_entry_count += @intFromBool(parsed.group != null);
        return false;
    }

    pub fn unsubscribe(self: *Router, subscriber_id: SubscriberId, topic_filter: []const u8) Error!void {
        const parsed = parseFilter(topic_filter) orelse return error.InvalidSubscription;
        const entry_index = self.findEntryForSubscription(subscriber_id, parsed) orelse
            return error.SubscriptionNotFound;
        const entry = &self.entries.items[entry_index].?;
        const node_index, const multi_level = self.findFilterPath(parsed.effective_filter) orelse return error.SubscriptionNotFound;
        if (entry.shared_group != null) {
            const group_index = entry.shared_group_index orelse return error.SubscriptionNotFound;
            if (group_index >= self.shared_groups.items.len) return error.SubscriptionNotFound;
            if (self.shared_groups.items[group_index]) |*group| {
                const was_representative = self.routeContainsEntry(node_index, multi_level, entry_index);
                removeIndexValue(&group.entry_indices, entry_index);
                if (group.entry_indices.items.len == 0) {
                    if (was_representative) self.removeRouteEntry(node_index, multi_level, entry_index);
                    self.removeSharedGroupAt(group_index);
                } else {
                    group.cursor %= group.entry_indices.items.len;
                    if (was_representative) {
                        self.replaceRouteEntry(node_index, multi_level, entry_index, group.entry_indices.items[0]);
                    }
                }
            } else return error.SubscriptionNotFound;
        } else {
            self.removeRouteEntry(node_index, multi_level, entry_index);
        }
        const was_shared = entry.shared_group != null;
        self.removeSubscriberEntry(subscriber_id, entry_index);
        entry.deinit(self.allocator);
        self.entries.items[entry_index] = null;
        self.free_entries.append(self.allocator, entry_index) catch {};
        self.active_entry_count -= 1;
        self.shared_entry_count -= @intFromBool(was_shared);
        tree.pruneEmpty(self, node_index);
    }

    /// Remove every subscription owned by one live network connection.
    ///
    /// Broker disconnect cleanup uses this instead of retaining a parallel
    /// filter list. Live indexes remain stable; detached entry and trie slots
    /// are recycled after their route/shared-group references are removed.
    pub fn removeSubscriber(
        self: *Router,
        subscriber_id: SubscriberId,
    ) Error!usize {
        var removed: usize = 0;
        while (true) {
            const slot = self.subscriber_entries.getPtr(subscriber_id) orelse
                break;
            const entry_index = switch (slot.*) {
                .one => |value| value,
                .many => |list| if (list.items.len == 0)
                    break
                else
                    list.items[0],
            };
            const entry = self.entries.items[entry_index] orelse {
                self.removeSubscriberEntry(subscriber_id, entry_index);
                continue;
            };
            try self.unsubscribe(
                subscriber_id,
                entry.subscription.topic_filter,
            );
            removed += 1;
        }
        return removed;
    }

    fn removeSubscriberEntry(
        self: *Router,
        subscriber_id: SubscriberId,
        entry_index: usize,
    ) void {
        const slot = self.subscriber_entries.getPtr(subscriber_id) orelse
            return;
        switch (slot.*) {
            .one => |value| {
                if (value != entry_index) return;
                _ = self.subscriber_entries.remove(subscriber_id);
            },
            .many => |*list| {
                for (list.items, 0..) |value, index| {
                    if (value != entry_index) continue;
                    _ = list.orderedRemove(index);
                    break;
                }
                if (list.items.len == 0) {
                    list.deinit(self.allocator);
                    _ = self.subscriber_entries.remove(subscriber_id);
                } else if (list.items.len == 1) {
                    const remaining = list.items[0];
                    list.deinit(self.allocator);
                    slot.* = .{ .one = remaining };
                }
            },
        }
    }

    /// Match into caller storage without allocation. Shared-group cursors only
    /// advance after all output capacity checks succeed.
    pub fn matchInto(self: *Router, topic: []const u8, out: []Match) Error![]Match {
        return self.matchIntoForPublisher(topic, null, out);
    }

    pub fn matchIntoForPublisher(
        self: *Router,
        topic: []const u8,
        publisher_id: ?SubscriberId,
        out: []Match,
    ) Error![]Match {
        try mqtt.validateTopicName(topic);
        return self.matchValidatedIntoForPublisher(
            topic,
            publisher_id,
            out,
        );
    }

    /// Broker-internal variant for a Topic Name already accepted by the wire,
    /// local-publish, Will, or persistence validation boundary.
    pub fn matchValidatedIntoForPublisher(
        self: *Router,
        topic: []const u8,
        publisher_id: ?SubscriberId,
        out: []Match,
    ) Error![]Match {
        // Without shared groups there is no cursor to protect, so emit
        // optimistically in one traversal instead of a count pass followed by
        // an emit pass. If the caller buffer fills, return MatchBufferTooSmall;
        // partial output is discarded by the caller.
        if (self.shared_entry_count == 0) {
            if (self.matchTrie(
                topic,
                publisher_id,
                out,
                null,
                true,
            )) |counts| {
                if (counts.overflow) return error.MatchBufferTooSmall;
                std.debug.assert(counts.shared == 0);
                return out[0..counts.normal];
            }
            const written = self.matchNormalLinearChecked(
                topic,
                publisher_id,
                out,
            ) orelse return error.MatchBufferTooSmall;
            return out[0..written];
        }

        const trie_counts = self.matchTrie(
            topic,
            publisher_id,
            null,
            null,
            false,
        );
        const normal_count = if (trie_counts) |counts|
            counts.normal
        else
            self.matchNormalLinear(topic, publisher_id, null);
        const shared_group_count = if (trie_counts) |counts|
            counts.shared
        else
            self.matchSharedLinear(topic, null);
        const required = std.math.add(usize, normal_count, shared_group_count) catch return error.MatchBufferTooSmall;
        if (out.len < required) return error.MatchBufferTooSmall;

        if (trie_counts != null) {
            // A successful count pass guarantees this combined emitting pass
            // cannot fail after it advances shared-subscription cursors.
            const written = self.matchTrie(
                topic,
                publisher_id,
                out[0..normal_count],
                out[normal_count..required],
                false,
            ) orelse unreachable;
            std.debug.assert(written.normal == normal_count);
            std.debug.assert(written.shared == shared_group_count);
        } else {
            const normal_written = self.matchNormalLinear(
                topic,
                publisher_id,
                out[0..normal_count],
            );
            std.debug.assert(normal_written == normal_count);
            const shared_written = self.matchSharedLinear(
                topic,
                out[normal_count..required],
            );
            std.debug.assert(shared_written == shared_group_count);
        }
        return out[0..required];
    }

    pub fn matchAlloc(self: *Router, allocator: std.mem.Allocator, topic: []const u8) Error![]Match {
        return self.matchAllocForPublisher(allocator, topic, null);
    }

    /// Allocate the exact route set for a publisher-aware match.
    ///
    /// Passing the publisher identity lets the router apply MQTT No Local
    /// while shared-subscription selection is still performed exactly once.
    /// Broker callers should prefer this over filtering `matchAlloc` results:
    /// repeating a match could advance a shared group's cursor twice.
    pub fn matchAllocForPublisher(
        self: *Router,
        allocator: std.mem.Allocator,
        topic: []const u8,
        publisher_id: ?SubscriberId,
    ) Error![]Match {
        try mqtt.validateTopicName(topic);
        return self.matchValidatedAllocForPublisher(
            allocator,
            topic,
            publisher_id,
        );
    }

    /// Allocating counterpart to `matchValidatedIntoForPublisher` for broker
    /// ingress that already crossed a Topic Name validation boundary.
    pub fn matchValidatedAllocForPublisher(
        self: *Router,
        allocator: std.mem.Allocator,
        topic: []const u8,
        publisher_id: ?SubscriberId,
    ) Error![]Match {
        const upper_bound = self.subscriptionCount();
        const matches = try allocator.alloc(Match, upper_bound);
        errdefer allocator.free(matches);
        const written = try self.matchValidatedIntoForPublisher(
            topic,
            publisher_id,
            matches,
        );
        if (written.len == matches.len) return matches;
        if (written.len == 0) {
            allocator.free(matches);
            return try allocator.alloc(Match, 0);
        }
        if (allocator.resize(matches, written.len)) return matches[0..written.len];
        const exact = try allocator.dupe(Match, written);
        allocator.free(matches);
        return exact;
    }

    /// Return whether the topic has any matching subscription before applying
    /// publisher-aware No Local filtering. MQTT 5 PUBACK reason 0x10 describes
    /// subscription existence, not whether this particular publisher receives
    /// a loopback delivery. This query deliberately does not emit matches, so
    /// shared-subscription round-robin cursors are not advanced.
    pub fn hasTopicMatch(self: *Router, topic: []const u8) bool {
        if (self.matchTrie(topic, null, null, null, false)) |counts| {
            return counts.normal != 0 or counts.shared != 0;
        }
        return self.matchNormalLinear(topic, null, null) != 0 or
            self.matchSharedLinear(topic, null) != 0;
    }

    const MatchCounts = struct {
        normal: usize = 0,
        shared: usize = 0,
        overflow: bool = false,
    };

    /// Traverse the topic trie once for both ordinary and shared routes.
    /// Separate output slices preserve ordinary-before-shared ordering while
    /// halving both count-pass and emit-pass trie traversal work.
    fn matchTrie(
        self: *const Router,
        topic: []const u8,
        publisher_id: ?SubscriberId,
        normal_out: ?[]Match,
        shared_out: ?[]Match,
        checked: bool,
    ) ?MatchCounts {
        const has_shared = self.shared_entry_count != 0;
        var current: [128]usize = undefined;
        var next: [128]usize = undefined;
        current[0] = 0;
        var current_count: usize = 1;
        var counts = MatchCounts{};
        var depth: usize = 0;
        var it = std.mem.splitScalar(u8, topic, '/');
        while (it.next()) |level| {
            var next_count: usize = 0;
            for (current[0..current_count]) |node_index| {
                const node = &self.nodes.items[node_index];
                if (!(depth == 0 and topic[0] == '$')) {
                    counts.normal = self.emitNormalEntries(
                        node.multi_wildcard_entries.items,
                        publisher_id,
                        normal_out,
                        counts.normal,
                        checked,
                        &counts.overflow,
                    );
                    if (counts.overflow) return counts;
                    if (has_shared) {
                        counts.shared = self.emitSharedEntries(
                            topic,
                            node.multi_wildcard_entries.items,
                            shared_out,
                            counts.shared,
                            checked,
                            &counts.overflow,
                        );
                        if (counts.overflow) return counts;
                    }
                }
                if (depth == 0 and std.mem.startsWith(u8, topic, "$")) {
                    if (findLiteralChild(node.*, level)) |child| {
                        if (!appendUniqueNode(&next, &next_count, child)) return null;
                    }
                    continue;
                }
                if (findLiteralChild(node.*, level)) |child| {
                    if (!appendUniqueNode(&next, &next_count, child)) return null;
                }
                if (node.single_wildcard_child) |child| {
                    if (!appendUniqueNode(&next, &next_count, child)) return null;
                }
            }
            @memcpy(current[0..next_count], next[0..next_count]);
            current_count = next_count;
            if (current_count == 0) return counts;
            depth += 1;
        }
        for (current[0..current_count]) |node_index| {
            const node = &self.nodes.items[node_index];
            counts.normal = self.emitNormalEntries(
                node.terminal_entries.items,
                publisher_id,
                normal_out,
                counts.normal,
                checked,
                &counts.overflow,
            );
            if (counts.overflow) return counts;
            if (has_shared) {
                counts.shared = self.emitSharedEntries(
                    topic,
                    node.terminal_entries.items,
                    shared_out,
                    counts.shared,
                    checked,
                    &counts.overflow,
                );
                if (counts.overflow) return counts;
            }
            counts.normal = self.emitNormalEntries(
                node.multi_wildcard_entries.items,
                publisher_id,
                normal_out,
                counts.normal,
                checked,
                &counts.overflow,
            );
            if (counts.overflow) return counts;
            if (has_shared) {
                counts.shared = self.emitSharedEntries(
                    topic,
                    node.multi_wildcard_entries.items,
                    shared_out,
                    counts.shared,
                    checked,
                    &counts.overflow,
                );
                if (counts.overflow) return counts;
            }
        }
        return counts;
    }

    fn matchNormalLinear(
        self: *const Router,
        topic: []const u8,
        publisher_id: ?SubscriberId,
        out: ?[]Match,
    ) usize {
        var written: usize = 0;
        for (self.entries.items) |*maybe_entry| {
            const entry = if (maybe_entry.*) |*value| value else continue;
            if (entry.shared_group != null or !mqtt.topicMatchesFilter(topic, entry.effective_filter)) continue;
            if (publisher_id != null and entry.subscription.no_local and entry.subscriber_id == publisher_id.?) continue;
            if (out) |storage| storage[written] = entryMatch(entry);
            written += 1;
        }
        return written;
    }

    fn emitNormalEntries(
        self: *const Router,
        entry_indices: []const usize,
        publisher_id: ?SubscriberId,
        out: ?[]Match,
        start: usize,
        checked: bool,
        overflow: *bool,
    ) usize {
        var written = start;
        for (entry_indices) |entry_index| {
            const entry = if (self.entries.items[entry_index]) |*value|
                value
            else
                continue;
            if (entry.shared_group != null) continue;
            if (publisher_id != null and entry.subscription.no_local and entry.subscriber_id == publisher_id.?) continue;
            if (out) |storage| {
                if (checked and written >= storage.len) {
                    overflow.* = true;
                    return written;
                }
                storage[written] = entryMatch(entry);
            }
            written += 1;
        }
        return written;
    }

    /// Single-pass non-shared fallback when the trie cannot be used. Returns
    /// null if the caller buffer is too small.
    fn matchNormalLinearChecked(
        self: *const Router,
        topic: []const u8,
        publisher_id: ?SubscriberId,
        out: []Match,
    ) ?usize {
        var written: usize = 0;
        for (self.entries.items) |*maybe_entry| {
            const entry = if (maybe_entry.*) |*value| value else continue;
            if (entry.shared_group != null or !mqtt.topicMatchesFilter(topic, entry.effective_filter)) continue;
            if (publisher_id != null and entry.subscription.no_local and entry.subscriber_id == publisher_id.?) continue;
            if (written >= out.len) return null;
            out[written] = entryMatch(entry);
            written += 1;
        }
        return written;
    }

    fn matchSharedLinear(
        self: *Router,
        topic: []const u8,
        out: ?[]Match,
    ) usize {
        var written: usize = 0;
        for (self.shared_groups.items) |*maybe_group| {
            if (maybe_group.*) |*group| {
                const representative = self.firstLiveGroupEntry(group) orelse continue;
                if (!mqtt.topicMatchesFilter(topic, representative.effective_filter)) continue;
                if (out) |storage| {
                    const entry = self.selectGroupEntry(
                        group,
                        topic,
                    ) orelse continue;
                    storage[written] = entryMatch(entry);
                }
                written += 1;
            }
        }
        return written;
    }

    fn emitSharedEntries(
        self: *const Router,
        topic: []const u8,
        entry_indices: []const usize,
        out: ?[]Match,
        start: usize,
        checked: bool,
        overflow: *bool,
    ) usize {
        var written = start;
        for (entry_indices) |entry_index| {
            const representative = if (self.entries.items[entry_index]) |*value|
                value
            else
                continue;
            const group_index = representative.shared_group_index orelse continue;
            if (group_index >= self.shared_groups.items.len) continue;
            if (self.shared_groups.items[group_index]) |*group| {
                if (out) |storage| {
                    if (checked and written >= storage.len) {
                        overflow.* = true;
                        return written;
                    }
                    const entry = self.selectGroupEntry(
                        group,
                        topic,
                    ) orelse continue;
                    storage[written] = entryMatch(entry);
                }
                written += 1;
            }
        }
        return written;
    }

    fn firstLiveGroupEntry(self: *const Router, group: *const SharedGroup) ?*const Entry {
        for (group.entry_indices.items) |entry_index| {
            if (self.entries.items[entry_index]) |*entry| return entry;
        }
        return null;
    }

    fn selectGroupEntry(
        self: *const Router,
        group: *SharedGroup,
        topic: []const u8,
    ) ?*const Entry {
        if (group.entry_indices.items.len == 0) return null;
        return switch (group.strategy) {
            .round_robin => self.nextRoundRobinGroupEntry(group),
            .random => self.randomGroupEntry(group),
            .sticky => self.stickyGroupEntry(group),
            .rendezvous_hash => self.rendezvousGroupEntry(group, topic),
        };
    }

    fn nextRoundRobinGroupEntry(
        self: *const Router,
        group: *SharedGroup,
    ) ?*const Entry {
        var checked: usize = 0;
        while (checked < group.entry_indices.items.len) : (checked += 1) {
            const index = group.cursor % group.entry_indices.items.len;
            group.cursor = (index + 1) % group.entry_indices.items.len;
            if (self.entries.items[group.entry_indices.items[index]]) |*entry| return entry;
        }
        return null;
    }

    fn stickyGroupEntry(self: *const Router, group: *SharedGroup) ?*const Entry {
        var checked: usize = 0;
        while (checked < group.entry_indices.items.len) : (checked += 1) {
            const index =
                (group.cursor + checked) % group.entry_indices.items.len;
            if (self.entries.items[group.entry_indices.items[index]]) |*entry| {
                group.cursor = index;
                return entry;
            }
        }
        return null;
    }

    fn randomGroupEntry(self: *const Router, group: *SharedGroup) ?*const Entry {
        var checked: usize = 0;
        const first = std.math.cast(
            usize,
            nextRandom(&group.random_state) %
                @as(u64, @intCast(group.entry_indices.items.len)),
        ) orelse 0;
        while (checked < group.entry_indices.items.len) : (checked += 1) {
            const index = (first + checked) % group.entry_indices.items.len;
            if (self.entries.items[group.entry_indices.items[index]]) |*entry| {
                return entry;
            }
        }
        return null;
    }

    fn rendezvousGroupEntry(
        self: *const Router,
        group: *const SharedGroup,
        topic: []const u8,
    ) ?*const Entry {
        // The topic prefix is identical for every member; hash it once and
        // copy the hasher state for each subscriber-id suffix.
        var base = std.hash.Wyhash.init(group.selection_seed);
        base.update(topic);
        var id_bytes: [@sizeOf(SubscriberId)]u8 = undefined;
        var selected: ?*const Entry = null;
        var selected_score: u64 = 0;
        for (group.entry_indices.items) |entry_index| {
            const entry = if (self.entries.items[entry_index]) |*value|
                value
            else
                continue;
            std.mem.writeInt(
                SubscriberId,
                &id_bytes,
                entry.subscriber_id,
                .little,
            );
            var hasher = base;
            hasher.update(&id_bytes);
            const score = hasher.final();
            if (selected == null or
                score > selected_score or
                (score == selected_score and
                    entry.subscriber_id < selected.?.subscriber_id))
            {
                selected = entry;
                selected_score = score;
            }
        }
        return selected;
    }

    const insertFilterPath = tree.insert;
    const findFilterPath = tree.find;

    fn insertEntry(self: *Router, entry: Entry) Error!usize {
        if (self.free_entries.pop()) |index| {
            self.entries.items[index] = entry;
            return index;
        }
        try self.entries.append(self.allocator, entry);
        return self.entries.items.len - 1;
    }

    /// Source-compatible value receiver used by the batched subscription
    /// helpers. The lookup itself is the indexed form below.
    fn findEntry(self: Router, subscriber_id: SubscriberId, topic_filter: []const u8) ?usize {
        const parsed = parseFilter(topic_filter) orelse return null;
        var copy = self;
        return copy.findEntryForSubscription(subscriber_id, parsed);
    }

    /// Find a subscription without scanning every stored entry. Non-shared
    /// filters scan only the trie route list for that exact filter; shared
    /// filters scan the group's member list, which includes members that are
    /// not the current round-robin representative.
    fn findEntryForSubscription(
        self: *Router,
        subscriber_id: SubscriberId,
        parsed: ParsedFilter,
    ) ?usize {
        if (parsed.group) |group_name| {
            const group_index = self.findSharedGroup(
                group_name,
                parsed.effective_filter,
            ) orelse return null;
            const group = &self.shared_groups.items[group_index].?;
            for (group.entry_indices.items) |entry_index| {
                const entry = self.entries.items[entry_index] orelse
                    continue;
                if (entry.subscriber_id == subscriber_id) return entry_index;
            }
            return null;
        }

        const node_index, const multi_level = self.findFilterPath(
            parsed.effective_filter,
        ) orelse return null;
        const values = if (multi_level)
            self.nodes.items[node_index].multi_wildcard_entries.items
        else
            self.nodes.items[node_index].terminal_entries.items;
        for (values) |entry_index| {
            const entry = self.entries.items[entry_index] orelse continue;
            if (entry.shared_group == null and
                entry.subscriber_id == subscriber_id)
            {
                return entry_index;
            }
        }
        return null;
    }

    fn getOrCreateSharedGroup(self: *Router, name: []const u8, filter: []const u8) Error!struct { usize, bool } {
        if (self.findSharedGroup(name, filter)) |index| return .{ index, false };
        const owned_name = try self.allocator.dupe(u8, name);
        var owns_name = true;
        errdefer if (owns_name) self.allocator.free(owned_name);
        const owned_filter = try self.allocator.dupe(u8, filter);
        var owns_filter = true;
        errdefer if (owns_filter) self.allocator.free(owned_filter);

        // Reserve the map bucket and the eventual recycle slot before the
        // group becomes visible, so rollback never allocates.
        try self.shared_group_map.ensureUnusedCapacity(self.allocator, 1);
        try self.free_shared_groups.ensureUnusedCapacity(self.allocator, 1);

        const index = if (self.free_shared_groups.pop()) |recycled|
            recycled
        else blk: {
            try self.shared_groups.append(self.allocator, null);
            break :blk self.shared_groups.items.len - 1;
        };
        const selection_seed = sharedGroupSeed(
            self.options.random_seed,
            name,
            filter,
        );
        self.shared_groups.items[index] = .{
            .name = owned_name,
            .effective_filter = owned_filter,
            .strategy = self.options.shared_subscription_strategy,
            .selection_seed = selection_seed,
            .random_state = selection_seed,
        };
        self.shared_group_map.putAssumeCapacity(
            .{ .name = owned_name, .filter = owned_filter },
            index,
        );
        owns_name = false;
        owns_filter = false;
        return .{ index, true };
    }

    fn findSharedGroup(self: Router, name: []const u8, filter: []const u8) ?usize {
        return self.shared_group_map.get(.{ .name = name, .filter = filter });
    }

    fn removeSharedGroupAt(self: *Router, group_index: usize) void {
        if (group_index >= self.shared_groups.items.len) return;
        if (self.shared_groups.items[group_index]) |*group| {
            _ = self.shared_group_map.remove(.{
                .name = group.name,
                .filter = group.effective_filter,
            });
            group.deinit(self.allocator);
            self.shared_groups.items[group_index] = null;
            self.free_shared_groups.append(
                self.allocator,
                group_index,
            ) catch {};
        }
    }

    fn appendRouteEntry(self: *Router, node_index: usize, multi_level: bool, entry_index: usize) Error!void {
        if (multi_level) {
            try self.nodes.items[node_index].multi_wildcard_entries.append(self.allocator, entry_index);
        } else {
            try self.nodes.items[node_index].terminal_entries.append(self.allocator, entry_index);
        }
    }

    fn removeRouteEntry(self: *Router, node_index: usize, multi_level: bool, entry_index: usize) void {
        if (multi_level) {
            removeIndexValueUnordered(&self.nodes.items[node_index].multi_wildcard_entries, entry_index);
        } else {
            removeIndexValueUnordered(&self.nodes.items[node_index].terminal_entries, entry_index);
        }
    }

    fn routeContainsEntry(self: Router, node_index: usize, multi_level: bool, entry_index: usize) bool {
        const values = if (multi_level)
            self.nodes.items[node_index].multi_wildcard_entries.items
        else
            self.nodes.items[node_index].terminal_entries.items;
        return containsIndexValue(values, entry_index);
    }

    fn replaceRouteEntry(self: *Router, node_index: usize, multi_level: bool, old_index: usize, new_index: usize) void {
        const values = if (multi_level)
            self.nodes.items[node_index].multi_wildcard_entries.items
        else
            self.nodes.items[node_index].terminal_entries.items;
        replaceIndexValue(values, old_index, new_index);
    }
};

const ParsedFilter = struct {
    group: ?[]const u8,
    effective_filter: []const u8,
};

fn parseFilter(filter: []const u8) ?ParsedFilter {
    if (!std.mem.startsWith(u8, filter, "$share/")) return .{ .group = null, .effective_filter = filter };
    const rest = filter["$share/".len..];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return null;
    return .{
        .group = rest[0..slash],
        .effective_filter = rest[slash + 1 ..],
    };
}

const findLiteralChild = tree.literalChild;

fn appendUniqueNode(nodes: *[128]usize, count: *usize, node_index: usize) bool {
    for (nodes[0..count.*]) |existing| if (existing == node_index) return true;
    if (count.* >= nodes.len) return false;
    nodes[count.*] = node_index;
    count.* += 1;
    return true;
}

fn removeIndexValue(values: *std.ArrayList(usize), target: usize) void {
    for (values.items, 0..) |value, i| {
        if (value == target) {
            _ = values.orderedRemove(i);
            return;
        }
    }
}

fn removeIndexValueUnordered(values: *std.ArrayList(usize), target: usize) void {
    for (values.items, 0..) |value, i| {
        if (value == target) {
            values.items[i] = values.items[values.items.len - 1];
            _ = values.pop();
            return;
        }
    }
}

fn containsIndexValue(values: []const usize, target: usize) bool {
    for (values) |value| {
        if (value == target) return true;
    }
    return false;
}

fn replaceIndexValue(values: []usize, old_value: usize, new_value: usize) void {
    for (values) |*value| {
        if (value.* == old_value) {
            value.* = new_value;
            return;
        }
    }
}

fn entryMatch(entry: *const Entry) Match {
    return .{
        .subscriber_id = entry.subscriber_id,
        .subscription = entry.subscription,
        .subscription_identifier = entry.subscription_identifier,
    };
}

fn sharedGroupSeed(
    random_seed: u64,
    name: []const u8,
    filter: []const u8,
) u64 {
    var hasher = std.hash.Wyhash.init(random_seed);
    hasher.update(name);
    hasher.update(&.{0});
    hasher.update(filter);
    return hasher.final();
}

fn nextRandom(state: *u64) u64 {
    // SplitMix64 has a full-period state transition and good output diffusion
    // without pulling an allocator or OS-random call into the publish hot path.
    state.* +%= 0x9e37_79b9_7f4a_7c15;
    var value = state.*;
    value = (value ^ (value >> 30)) *% 0xbf58_476d_1ce4_e5b9;
    value = (value ^ (value >> 27)) *% 0x94d0_49bb_1331_11eb;
    return value ^ (value >> 31);
}

test "MQTT router matches literal and wildcard subscriptions" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    try router.subscribe(1, .{ .topic_filter = "sensors/temperature" });
    try router.subscribe(2, .{ .topic_filter = "sensors/+" });
    try router.subscribe(3, .{ .topic_filter = "sensors/#" });
    try router.subscribe(4, .{ .topic_filter = "+/temperature" });
    try router.subscribe(5, .{ .topic_filter = "$SYS/#" });
    try router.subscribe(6, .{ .topic_filter = "#" });

    var storage: [8]Match = undefined;
    const matches = try router.matchInto("sensors/temperature", &storage);
    try std.testing.expectEqual(@as(usize, 5), matches.len);
    var saw_exact = false;
    var saw_single = false;
    var saw_leading_single = false;
    var saw_prefix_multi = false;
    var saw_global = false;
    for (matches) |match| {
        if (match.subscriber_id == 1) saw_exact = true;
        if (match.subscriber_id == 2) saw_single = true;
        if (match.subscriber_id == 4) saw_leading_single = true;
        if (match.subscriber_id == 3) saw_prefix_multi = true;
        if (match.subscriber_id == 6) saw_global = true;
    }
    try std.testing.expect(saw_exact and saw_single and saw_leading_single and saw_prefix_multi and saw_global);

    const system = try router.matchInto("$SYS/uptime", &storage);
    try std.testing.expectEqual(@as(usize, 1), system.len);
    try std.testing.expectEqual(@as(SubscriberId, 5), system[0].subscriber_id);
}

test "MQTT router full-capacity normal fast path matches bounded count path" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    try router.subscribe(1, .{ .topic_filter = "jobs/ready" });
    try router.subscribe(2, .{ .topic_filter = "jobs/+" });
    try router.subscribe(3, .{
        .topic_filter = "jobs/ready",
        .no_local = true,
    });
    try router.subscribe(4, .{ .topic_filter = "other/topic" });

    var full_storage: [4]Match = undefined;
    const fast = try router.matchIntoForPublisher(
        "jobs/ready",
        3,
        &full_storage,
    );
    // Capacity below subscriptionCount() forces the count-before-emit path,
    // while still fitting every actual match after No Local and topic checks.
    var bounded_storage: [3]Match = undefined;
    const bounded = try router.matchIntoForPublisher(
        "jobs/ready",
        3,
        &bounded_storage,
    );

    try std.testing.expectEqual(@as(usize, 2), fast.len);
    try std.testing.expectEqual(fast.len, bounded.len);
    for (fast, bounded) |fast_match, bounded_match| {
        try std.testing.expectEqual(
            fast_match.subscriber_id,
            bounded_match.subscriber_id,
        );
        try std.testing.expectEqualStrings(
            fast_match.subscription.topic_filter,
            bounded_match.subscription.topic_filter,
        );
    }
}

test "MQTT router combined trie preserves normal and shared ordering" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();
    try router.subscribe(1, .{ .topic_filter = "devices/+/state" });
    try router.subscribe(2, .{ .topic_filter = "devices/#" });
    try router.subscribe(10, .{
        .topic_filter = "$share/work/devices/+/state",
    });
    try router.subscribe(11, .{
        .topic_filter = "$share/work/devices/+/state",
    });

    var storage: [3]Match = undefined;
    const first = try router.matchInto("devices/a/state", &storage);
    try std.testing.expectEqual(@as(usize, 3), first.len);
    try std.testing.expectEqual(@as(SubscriberId, 2), first[0].subscriber_id);
    try std.testing.expectEqual(@as(SubscriberId, 1), first[1].subscriber_id);
    try std.testing.expectEqual(@as(SubscriberId, 10), first[2].subscriber_id);

    try std.testing.expectError(
        error.MatchBufferTooSmall,
        router.matchInto("devices/b/state", storage[0..2]),
    );
    const second = try router.matchInto("devices/b/state", &storage);
    // Capacity preflight is cursor-neutral despite sharing the trie pass.
    try std.testing.expectEqual(@as(SubscriberId, 11), second[2].subscriber_id);
}

test "MQTT router shared subscriptions round robin per filter" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    try router.subscribe(10, .{ .topic_filter = "$share/workers/jobs/+" });
    try router.subscribe(11, .{ .topic_filter = "$share/workers/jobs/+" });
    try router.subscribe(12, .{ .topic_filter = "$share/workers/jobs/+" });
    try router.subscribe(20, .{ .topic_filter = "$share/other/jobs/+" });

    var storage: [4]Match = undefined;
    const expected = [_]SubscriberId{ 10, 11, 12, 10 };
    for (expected) |subscriber| {
        const matches = try router.matchInto("jobs/one", &storage);
        try std.testing.expectEqual(@as(usize, 2), matches.len);
        try std.testing.expectEqual(subscriber, matches[0].subscriber_id);
        try std.testing.expectEqual(@as(SubscriberId, 20), matches[1].subscriber_id);
    }
}

test "MQTT router shared subscription strategies are configurable" {
    const allocator = std.testing.allocator;

    var sticky = try Router.initWithOptions(allocator, .{
        .shared_subscription_strategy = .sticky,
    });
    defer sticky.deinit();
    for (10..13) |subscriber_id| {
        try sticky.subscribe(
            subscriber_id,
            .{ .topic_filter = "$share/workers/jobs/+" },
        );
    }
    var storage: [1]Match = undefined;
    for (0..8) |_| {
        const matches = try sticky.matchInto("jobs/one", &storage);
        try std.testing.expectEqual(
            @as(SubscriberId, 10),
            matches[0].subscriber_id,
        );
    }

    var random_a = try Router.initWithOptions(allocator, .{
        .shared_subscription_strategy = .random,
        .random_seed = 0x1234_5678,
    });
    defer random_a.deinit();
    var random_b = try Router.initWithOptions(allocator, .{
        .shared_subscription_strategy = .random,
        .random_seed = 0x1234_5678,
    });
    defer random_b.deinit();
    for (10..13) |subscriber_id| {
        try random_a.subscribe(
            subscriber_id,
            .{ .topic_filter = "$share/workers/jobs/+" },
        );
        try random_b.subscribe(
            subscriber_id,
            .{ .topic_filter = "$share/workers/jobs/+" },
        );
    }
    var saw: [3]bool = .{ false, false, false };
    for (0..32) |_| {
        const first = try random_a.matchInto("jobs/random", &storage);
        const first_id = first[0].subscriber_id;
        var second_storage: [1]Match = undefined;
        const second = try random_b.matchInto(
            "jobs/random",
            &second_storage,
        );
        try std.testing.expectEqual(
            first_id,
            second[0].subscriber_id,
        );
        saw[first_id - 10] = true;
    }
    try std.testing.expect(saw[0] and saw[1] and saw[2]);
}

test "MQTT router random capacity failure preserves scheduler state" {
    const allocator = std.testing.allocator;
    var reference = try Router.initWithOptions(allocator, .{
        .shared_subscription_strategy = .random,
        .random_seed = 42,
    });
    defer reference.deinit();
    var probed = try Router.initWithOptions(allocator, .{
        .shared_subscription_strategy = .random,
        .random_seed = 42,
    });
    defer probed.deinit();
    for (1..4) |subscriber_id| {
        try reference.subscribe(
            subscriber_id,
            .{ .topic_filter = "$share/g/tasks/+" },
        );
        try probed.subscribe(
            subscriber_id,
            .{ .topic_filter = "$share/g/tasks/+" },
        );
    }
    // Add one ordinary match so empty storage fails after both count passes.
    try reference.subscribe(100, .{ .topic_filter = "tasks/#" });
    try probed.subscribe(100, .{ .topic_filter = "tasks/#" });

    try std.testing.expectError(
        error.MatchBufferTooSmall,
        probed.matchInto("tasks/a", &.{}),
    );
    var reference_storage: [2]Match = undefined;
    var probed_storage: [2]Match = undefined;
    const expected = try reference.matchInto("tasks/a", &reference_storage);
    const actual = try probed.matchInto("tasks/a", &probed_storage);
    try std.testing.expectEqual(
        expected[1].subscriber_id,
        actual[1].subscriber_id,
    );
}

test "MQTT router rendezvous strategy is stable and low-remapping" {
    const allocator = std.testing.allocator;
    var router = try Router.initWithOptions(allocator, .{
        .shared_subscription_strategy = .rendezvous_hash,
    });
    defer router.deinit();
    for (1..4) |subscriber_id| {
        try router.subscribe(
            subscriber_id,
            .{ .topic_filter = "$share/workers/jobs/+" },
        );
    }

    var before: [256]SubscriberId = undefined;
    var storage: [1]Match = undefined;
    var topic_buffer: [32]u8 = undefined;
    for (&before, 0..) |*selected, topic_index| {
        const topic = try std.fmt.bufPrint(
            &topic_buffer,
            "jobs/{d}",
            .{topic_index},
        );
        const first = try router.matchInto(topic, &storage);
        const first_id = first[0].subscriber_id;
        var second_storage: [1]Match = undefined;
        const second = try router.matchInto(topic, &second_storage);
        try std.testing.expectEqual(
            first_id,
            second[0].subscriber_id,
        );
        selected.* = first_id;
    }

    try router.subscribe(
        4,
        .{ .topic_filter = "$share/workers/jobs/+" },
    );
    var remapped: usize = 0;
    for (before, 0..) |previous, topic_index| {
        const topic = try std.fmt.bufPrint(
            &topic_buffer,
            "jobs/{d}",
            .{topic_index},
        );
        const selected = (try router.matchInto(topic, &storage))[0]
            .subscriber_id;
        if (selected != previous) {
            remapped += 1;
            // Rendezvous hashing can only remap an existing key to the newly
            // added member, unlike modulo hashing which reshuffles old peers.
            try std.testing.expectEqual(@as(SubscriberId, 4), selected);
        }
    }
    try std.testing.expect(remapped > 0);
    try std.testing.expect(remapped < before.len / 2);
}

test "MQTT router indexes shared groups by trie representative" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    try router.subscribe(10, .{ .topic_filter = "$share/workers/jobs/+" });
    try router.subscribe(11, .{ .topic_filter = "$share/workers/jobs/+" });

    const jobs_node, const jobs_multi = router.findFilterPath("jobs/+").?;
    try std.testing.expect(!jobs_multi);
    try std.testing.expectEqual(@as(usize, 1), router.nodes.items[jobs_node].terminal_entries.items.len);
    const jobs_group_index = router.findSharedGroup("workers", "jobs/+").?;

    var storage: [2]Match = undefined;
    const first = try router.matchInto("jobs/one", &storage);
    try std.testing.expectEqual(@as(usize, 1), first.len);
    try std.testing.expectEqual(@as(SubscriberId, 10), first[0].subscriber_id);

    // The trie stores one representative per shared group. Removing that
    // representative must swap in another live member so future matches stay
    // indexed and do not fall back to a scan over every shared group.
    try router.unsubscribe(10, "$share/workers/jobs/+");
    try std.testing.expectEqual(@as(usize, 1), router.nodes.items[jobs_node].terminal_entries.items.len);
    const second = try router.matchInto("jobs/two", &storage);
    try std.testing.expectEqual(@as(usize, 1), second.len);
    try std.testing.expectEqual(@as(SubscriberId, 11), second[0].subscriber_id);

    try router.subscribe(12, .{ .topic_filter = "$share/workers/jobs/+" });
    try std.testing.expectEqual(@as(usize, 1), router.nodes.items[jobs_node].terminal_entries.items.len);
    const third = try router.matchInto("jobs/three", &storage);
    try std.testing.expectEqual(@as(SubscriberId, 11), third[0].subscriber_id);
    const fourth = try router.matchInto("jobs/four", &storage);
    try std.testing.expectEqual(@as(SubscriberId, 12), fourth[0].subscriber_id);

    try router.unsubscribe(11, "$share/workers/jobs/+");
    try router.unsubscribe(12, "$share/workers/jobs/+");
    try std.testing.expectEqual(@as(usize, 0), router.nodes.items[jobs_node].terminal_entries.items.len);
    try std.testing.expect(router.shared_groups.items[jobs_group_index] == null);

    try router.subscribe(20, .{ .topic_filter = "$share/audit/alerts/#" });
    try std.testing.expectEqual(jobs_group_index, router.findSharedGroup("audit", "alerts/#").?);

    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    const saved_allocator = router.allocator;
    router.allocator = no_alloc.allocator();
    defer router.allocator = saved_allocator;

    const alert = try router.matchInto("alerts/security/high", &storage);
    try std.testing.expectEqual(@as(usize, 1), alert.len);
    try std.testing.expectEqual(@as(SubscriberId, 20), alert[0].subscriber_id);
    try std.testing.expect(!no_alloc.has_induced_failure);
}

test "MQTT router unsubscribe preserves shared cursor safety" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    try router.subscribe(1, .{ .topic_filter = "$share/g/a/#" });
    try router.subscribe(2, .{ .topic_filter = "$share/g/a/#" });
    var storage: [2]Match = undefined;
    _ = try router.matchInto("a/b", &storage);
    try router.unsubscribe(2, "$share/g/a/#");
    const matches = try router.matchInto("a/c", &storage);
    try std.testing.expectEqual(@as(usize, 1), matches.len);
    try std.testing.expectEqual(@as(SubscriberId, 1), matches[0].subscriber_id);
}

test "MQTT router cached subscription counts track replacement and removal" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    try std.testing.expectEqual(@as(usize, 0), router.subscriptionCount());
    try std.testing.expectEqual(@as(usize, 0), router.sharedSubscriptionCount());

    try router.subscribe(1, .{ .topic_filter = "devices/+" });
    try router.subscribe(2, .{ .topic_filter = "$share/work/devices/#" });
    try router.subscribe(3, .{ .topic_filter = "$share/work/devices/#" });
    try std.testing.expectEqual(@as(usize, 3), router.subscriptionCount());
    try std.testing.expectEqual(@as(usize, 2), router.sharedSubscriptionCount());

    try std.testing.expectError(
        error.InvalidSubscription,
        router.subscribe(4, .{
            .topic_filter = "$share/work/devices/#",
            .no_local = true,
        }),
    );
    try std.testing.expectEqual(@as(usize, 3), router.subscriptionCount());
    try std.testing.expectEqual(@as(usize, 2), router.sharedSubscriptionCount());

    try router.subscribe(2, .{
        .topic_filter = "$share/work/devices/#",
        .qos = .exactly_once,
    });
    try std.testing.expectEqual(@as(usize, 3), router.subscriptionCount());
    try std.testing.expectEqual(@as(usize, 2), router.sharedSubscriptionCount());

    try router.unsubscribe(2, "$share/work/devices/#");
    try std.testing.expectEqual(@as(usize, 2), router.subscriptionCount());
    try std.testing.expectEqual(@as(usize, 1), router.sharedSubscriptionCount());

    try std.testing.expectEqual(@as(usize, 1), try router.removeSubscriber(1));
    try std.testing.expectEqual(@as(usize, 1), router.subscriptionCount());
    try std.testing.expectEqual(@as(usize, 1), router.sharedSubscriptionCount());

    try std.testing.expectEqual(@as(usize, 1), try router.removeSubscriber(3));
    try std.testing.expectEqual(@as(usize, 0), router.subscriptionCount());
    try std.testing.expectEqual(@as(usize, 0), router.sharedSubscriptionCount());
}

test "MQTT router replaces repeated subscription options" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    try router.subscribe(1, .{ .topic_filter = "a/+", .qos = .at_most_once });
    try router.subscribe(1, .{
        .topic_filter = "a/+",
        .qos = .exactly_once,
        .no_local = true,
        .retain_as_published = true,
        .retain_handling = 2,
    });
    try std.testing.expectEqual(@as(usize, 1), router.subscriptionCount());

    var storage: [1]Match = undefined;
    const matches = try router.matchIntoForPublisher("a/b", 2, &storage);
    try std.testing.expectEqual(mqtt.QoS.exactly_once, matches[0].subscription.qos);
    try std.testing.expect(matches[0].subscription.no_local);
    try std.testing.expect(matches[0].subscription.retain_as_published);
    try std.testing.expectEqual(@as(u2, 2), matches[0].subscription.retain_handling);
}

test "MQTT router subscribeWithStatus reports replacement atomically" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    try std.testing.expect(!(try router.subscribeWithIdentifierStatus(1, .{
        .topic_filter = "state/+",
        .retain_handling = 1,
    }, 7)));
    try std.testing.expect(try router.subscribeWithIdentifierStatus(1, .{
        .topic_filter = "state/+",
        .qos = .at_least_once,
        .retain_handling = 1,
    }, 9));
    try std.testing.expectEqual(@as(usize, 1), router.subscriptionCount());
    var matches: [1]Match = undefined;
    const routed = try router.matchInto("state/value", &matches);
    try std.testing.expectEqual(
        @as(?usize, 9),
        routed[0].subscription_identifier,
    );
}

test "MQTT router enforces no-local semantics" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    try router.subscribe(1, .{ .topic_filter = "events/#", .no_local = true });
    try router.subscribe(2, .{ .topic_filter = "events/#" });
    try std.testing.expectError(
        error.InvalidSubscription,
        router.subscribe(3, .{ .topic_filter = "$share/g/events/#", .no_local = true }),
    );

    var storage: [2]Match = undefined;
    const own = try router.matchIntoForPublisher("events/one", 1, &storage);
    try std.testing.expectEqual(@as(usize, 1), own.len);
    try std.testing.expectEqual(@as(SubscriberId, 2), own[0].subscriber_id);

    const remote = try router.matchIntoForPublisher("events/one", 99, &storage);
    try std.testing.expectEqual(@as(usize, 2), remote.len);
    try std.testing.expectError(
        error.InvalidTopic,
        router.matchIntoForPublisher("events/+", 99, &storage),
    );
}

test "MQTT router matchInto allocates nothing and preserves shared cursor on capacity error" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    try router.subscribe(10, .{ .topic_filter = "$share/g/tasks/+" });
    try router.subscribe(11, .{ .topic_filter = "$share/g/tasks/+" });
    try router.subscribe(20, .{ .topic_filter = "tasks/#" });
    try router.subscribe(21, .{ .topic_filter = "tasks/+" });

    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    const saved_allocator = router.allocator;
    router.allocator = no_alloc.allocator();
    defer router.allocator = saved_allocator;

    var too_small: [2]Match = undefined;
    try std.testing.expectError(error.MatchBufferTooSmall, router.matchInto("tasks/a", &too_small));
    try std.testing.expect(!no_alloc.has_induced_failure);

    var enough: [3]Match = undefined;
    const first = try router.matchInto("tasks/a", &enough);
    try std.testing.expectEqual(@as(usize, 3), first.len);
    try std.testing.expectEqual(@as(SubscriberId, 10), first[2].subscriber_id);
    try std.testing.expectEqualStrings("$share/g/tasks/+", first[2].subscription.topic_filter);

    const second = try router.matchInto("tasks/b", &enough);
    try std.testing.expectEqual(@as(SubscriberId, 11), second[2].subscriber_id);
    try std.testing.expect(!no_alloc.has_induced_failure);
}

test "MQTT router matchAlloc returns exact output" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    try router.subscribe(1, .{ .topic_filter = "a/+" });
    try router.subscribe(2, .{ .topic_filter = "unmatched" });
    const matches = try router.matchAlloc(allocator, "a/b");
    defer allocator.free(matches);
    try std.testing.expectEqual(@as(usize, 1), matches.len);
    try std.testing.expectEqual(@as(SubscriberId, 1), matches[0].subscriber_id);

    const none = try router.matchAlloc(allocator, "none/here");
    defer allocator.free(none);
    try std.testing.expectEqual(@as(usize, 0), none.len);
}

test "MQTT router indexes wide literal siblings" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    var filter_buffer: [32]u8 = undefined;
    for (0..1000) |i| {
        const filter = try std.fmt.bufPrint(&filter_buffer, "devices/{d}/state", .{i});
        try router.subscribe(@intCast(i), .{ .topic_filter = filter });
    }

    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    const saved_allocator = router.allocator;
    router.allocator = no_alloc.allocator();
    defer router.allocator = saved_allocator;

    var storage: [1]Match = undefined;
    const exact_topic = try std.fmt.bufPrint(&filter_buffer, "devices/{d}/state", .{777});
    const matches = try router.matchInto(exact_topic, &storage);
    try std.testing.expectEqual(@as(usize, 1), matches.len);
    try std.testing.expectEqual(@as(SubscriberId, 777), matches[0].subscriber_id);
    try std.testing.expect(!no_alloc.has_induced_failure);
}

test "MQTT router falls back exactly when trie frontier is wider than stack storage" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    const level_count = 8;
    const subscription_count = 1 << level_count;
    var filter_buffer: [level_count * 2 - 1]u8 = undefined;
    for (0..subscription_count) |mask| {
        var pos: usize = 0;
        for (0..level_count) |level| {
            filter_buffer[pos] = if ((mask & (@as(usize, 1) << @intCast(level))) == 0) 'a' else '+';
            pos += 1;
            if (level + 1 != level_count) {
                filter_buffer[pos] = '/';
                pos += 1;
            }
        }
        try router.subscribe(@intCast(mask), .{ .topic_filter = filter_buffer[0..pos] });
    }

    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    const saved_allocator = router.allocator;
    router.allocator = no_alloc.allocator();
    defer router.allocator = saved_allocator;

    var matches: [subscription_count]Match = undefined;
    const found = try router.matchInto("a/a/a/a/a/a/a/a", &matches);
    try std.testing.expectEqual(@as(usize, subscription_count), found.len);
    try std.testing.expect(!no_alloc.has_induced_failure);
}

test "MQTT router handles empty topic levels" {
    const allocator = std.testing.allocator;
    var router = try Router.init(allocator);
    defer router.deinit();

    try router.subscribe(1, .{ .topic_filter = "a//b" });
    try router.subscribe(2, .{ .topic_filter = "a/+/b" });
    try router.subscribe(3, .{ .topic_filter = "/#" });
    var storage: [3]Match = undefined;
    const matches = try router.matchInto("a//b", &storage);
    try std.testing.expectEqual(@as(usize, 2), matches.len);
}

test "MQTT router subscription allocation failures leak nothing" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        testSubscriptionAllocationFailures,
        .{},
    );
}

fn testSubscriptionAllocationFailures(allocator: std.mem.Allocator) !void {
    var router = try Router.init(allocator);
    defer router.deinit();
    try router.subscribe(1, .{
        .topic_filter = "$share/workers/building/floor/+/temperature/#",
        .qos = .exactly_once,
        .retain_as_published = true,
    });
}

test {
    _ = @import("router/batch_tests.zig");
    _ = @import("router/churn_tests.zig");
}
