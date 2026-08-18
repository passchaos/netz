const std = @import("std");
const mqtt = @import("mod.zig");

pub const Error = mqtt.Error || error{
    SubscriptionNotFound,
    MatchBufferTooSmall,
};

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

const Node = struct {
    literal_children: std.StringHashMapUnmanaged(usize) = .empty,
    single_wildcard_child: ?usize = null,
    terminal_entries: std.ArrayList(usize) = .empty,
    multi_wildcard_entries: std.ArrayList(usize) = .empty,

    fn deinit(self: *Node, allocator: std.mem.Allocator) void {
        var keys = self.literal_children.keyIterator();
        while (keys.next()) |level| allocator.free(level.*);
        self.literal_children.deinit(allocator);
        self.terminal_entries.deinit(allocator);
        self.multi_wildcard_entries.deinit(allocator);
        self.* = undefined;
    }
};

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
    entries: std.ArrayList(?Entry) = .empty,
    // Route representatives store `shared_group_index`, so group positions must
    // remain stable across unsubscribe.  Empty groups become tombstones that a
    // later group can reuse instead of compacting and invalidating indexes.
    shared_groups: std.ArrayList(?SharedGroup) = .empty,

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
        for (self.shared_groups.items) |*maybe_group| {
            if (maybe_group.*) |*group| group.deinit(self.allocator);
        }
        self.shared_groups.deinit(self.allocator);
        for (self.nodes.items) |*node| node.deinit(self.allocator);
        self.nodes.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn subscriptionCount(self: Router) usize {
        var count: usize = 0;
        for (self.entries.items) |entry| count += @intFromBool(entry != null);
        return count;
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
        try mqtt.validateTopicFilter(subscription.topic_filter);
        if (subscription_identifier) |identifier| {
            if (identifier == 0 or identifier > 268_435_455) {
                return error.InvalidProperty;
            }
        }
        const parsed_input = parseFilter(subscription.topic_filter) orelse return error.InvalidSubscription;
        if (parsed_input.group != null and subscription.no_local) return error.InvalidSubscription;
        if (self.findEntry(subscriber_id, subscription.topic_filter)) |entry_index| {
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

        const entry_index = self.entries.items.len;
        try self.entries.append(self.allocator, Entry{
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
            var removed = self.entries.pop().?;
            removed.?.deinit(self.allocator);
        }

        if (parsed.group) |group| {
            const node_index, const multi_level = try self.insertFilterPath(parsed.effective_filter);
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
            try self.appendRouteEntry(node_index, multi_level, entry_index);
            errdefer self.removeRouteEntry(node_index, multi_level, entry_index);
        }
        return false;
    }

    pub fn unsubscribe(self: *Router, subscriber_id: SubscriberId, topic_filter: []const u8) Error!void {
        const entry_index = self.findEntry(subscriber_id, topic_filter) orelse return error.SubscriptionNotFound;
        const entry = &self.entries.items[entry_index].?;
        const parsed = parseFilter(topic_filter) orelse return error.InvalidSubscription;
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
        entry.deinit(self.allocator);
        self.entries.items[entry_index] = null;
    }

    /// Remove every subscription owned by one live network connection.
    ///
    /// Broker disconnect cleanup uses this instead of retaining a parallel
    /// filter list. Entries are tombstoned rather than compacted, preserving
    /// stable shared-group and route indices for concurrent connection slots.
    pub fn removeSubscriber(
        self: *Router,
        subscriber_id: SubscriberId,
    ) Error!usize {
        var removed: usize = 0;
        var index: usize = 0;
        while (index < self.entries.items.len) : (index += 1) {
            const entry = self.entries.items[index] orelse continue;
            if (entry.subscriber_id != subscriber_id) continue;
            try self.unsubscribe(
                subscriber_id,
                entry.subscription.topic_filter,
            );
            removed += 1;
        }
        return removed;
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
        const normal_count = self.matchNormalTrie(topic, publisher_id, null) orelse
            self.matchNormalLinear(topic, publisher_id, null);
        const shared_count_from_trie = self.matchSharedTrie(topic, null);
        const shared_group_count = shared_count_from_trie orelse
            self.matchSharedLinear(topic, null);
        const required = std.math.add(usize, normal_count, shared_group_count) catch return error.MatchBufferTooSmall;
        if (out.len < required) return error.MatchBufferTooSmall;

        const normal_written = self.matchNormalTrie(topic, publisher_id, out[0..normal_count]) orelse
            self.matchNormalLinear(topic, publisher_id, out[0..normal_count]);
        std.debug.assert(normal_written == normal_count);
        const shared_written = if (shared_count_from_trie != null)
            // The active-node frontier is deterministic for a given topic and
            // router snapshot.  A successful count pass therefore guarantees
            // the emitting pass will not need the linear fallback after it has
            // advanced shared-subscription cursors.
            self.matchSharedTrie(
                topic,
                out[normal_written..required],
            ) orelse unreachable
        else
            self.matchSharedLinear(topic, out[normal_written..required]);
        std.debug.assert(shared_written == shared_group_count);
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
        const upper_bound = self.subscriptionCount();
        const matches = try allocator.alloc(Match, upper_bound);
        errdefer allocator.free(matches);
        const written = try self.matchIntoForPublisher(
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

    /// Returns null when the fixed active-node frontier is too small; callers
    /// then use the exact linear fallback rather than dropping matches.
    fn matchNormalTrie(
        self: Router,
        topic: []const u8,
        publisher_id: ?SubscriberId,
        out: ?[]Match,
    ) ?usize {
        var current: [128]usize = undefined;
        var next: [128]usize = undefined;
        current[0] = 0;
        var current_count: usize = 1;
        var written: usize = 0;
        var depth: usize = 0;
        var it = std.mem.splitScalar(u8, topic, '/');
        while (it.next()) |level| {
            var next_count: usize = 0;
            for (current[0..current_count]) |node_index| {
                const node = &self.nodes.items[node_index];
                if (!(depth == 0 and topic[0] == '$')) {
                    written = self.emitNormalEntries(node.multi_wildcard_entries.items, publisher_id, out, written);
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
            if (current_count == 0) return written;
            depth += 1;
        }
        for (current[0..current_count]) |node_index| {
            const node = &self.nodes.items[node_index];
            written = self.emitNormalEntries(node.terminal_entries.items, publisher_id, out, written);
            written = self.emitNormalEntries(node.multi_wildcard_entries.items, publisher_id, out, written);
        }
        return written;
    }

    fn matchNormalLinear(
        self: Router,
        topic: []const u8,
        publisher_id: ?SubscriberId,
        out: ?[]Match,
    ) usize {
        var written: usize = 0;
        for (self.entries.items) |maybe_entry| {
            const entry = maybe_entry orelse continue;
            if (entry.shared_group != null or !mqtt.topicMatchesFilter(topic, entry.effective_filter)) continue;
            if (publisher_id != null and entry.subscription.no_local and entry.subscriber_id == publisher_id.?) continue;
            if (out) |storage| storage[written] = entryMatch(entry);
            written += 1;
        }
        return written;
    }

    fn emitNormalEntries(
        self: Router,
        entry_indices: []const usize,
        publisher_id: ?SubscriberId,
        out: ?[]Match,
        start: usize,
    ) usize {
        var written = start;
        for (entry_indices) |entry_index| {
            const entry = self.entries.items[entry_index] orelse continue;
            if (entry.shared_group != null) continue;
            if (publisher_id != null and entry.subscription.no_local and entry.subscriber_id == publisher_id.?) continue;
            if (out) |storage| storage[written] = entryMatch(entry);
            written += 1;
        }
        return written;
    }

    /// Match shared subscriptions through the same topic-filter trie as normal
    /// subscriptions.  Each shared group/filter contributes one representative
    /// entry to the route; the representative is only a lookup key, while
    /// `nextLiveGroupEntry` applies the group's round-robin cursor at emit
    /// time.  This avoids the old O(total shared groups) scan for every
    /// publish and keeps capacity preflight cursor-neutral by doing a count
    /// pass before the emitting pass.
    fn matchSharedTrie(
        self: *Router,
        topic: []const u8,
        out: ?[]Match,
    ) ?usize {
        var current: [128]usize = undefined;
        var next: [128]usize = undefined;
        current[0] = 0;
        var current_count: usize = 1;
        var written: usize = 0;
        var depth: usize = 0;
        var it = std.mem.splitScalar(u8, topic, '/');
        while (it.next()) |level| {
            var next_count: usize = 0;
            for (current[0..current_count]) |node_index| {
                const node = &self.nodes.items[node_index];
                if (!(depth == 0 and topic[0] == '$')) {
                    written = self.emitSharedEntries(
                        topic,
                        node.multi_wildcard_entries.items,
                        out,
                        written,
                    );
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
            if (current_count == 0) return written;
            depth += 1;
        }
        for (current[0..current_count]) |node_index| {
            const node = &self.nodes.items[node_index];
            written = self.emitSharedEntries(
                topic,
                node.terminal_entries.items,
                out,
                written,
            );
            written = self.emitSharedEntries(
                topic,
                node.multi_wildcard_entries.items,
                out,
                written,
            );
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
                const representative = self.firstLiveGroupEntry(group.*) orelse continue;
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
        self: *Router,
        topic: []const u8,
        entry_indices: []const usize,
        out: ?[]Match,
        start: usize,
    ) usize {
        var written = start;
        for (entry_indices) |entry_index| {
            const representative = self.entries.items[entry_index] orelse continue;
            const group_index = representative.shared_group_index orelse continue;
            if (group_index >= self.shared_groups.items.len) continue;
            if (self.shared_groups.items[group_index]) |*group| {
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

    fn firstLiveGroupEntry(self: Router, group: SharedGroup) ?Entry {
        for (group.entry_indices.items) |entry_index| {
            if (self.entries.items[entry_index]) |entry| return entry;
        }
        return null;
    }

    fn selectGroupEntry(
        self: *Router,
        group: *SharedGroup,
        topic: []const u8,
    ) ?Entry {
        if (group.entry_indices.items.len == 0) return null;
        return switch (group.strategy) {
            .round_robin => self.nextRoundRobinGroupEntry(group),
            .random => self.randomGroupEntry(group),
            .sticky => self.stickyGroupEntry(group),
            .rendezvous_hash => self.rendezvousGroupEntry(group.*, topic),
        };
    }

    fn nextRoundRobinGroupEntry(
        self: Router,
        group: *SharedGroup,
    ) ?Entry {
        var checked: usize = 0;
        while (checked < group.entry_indices.items.len) : (checked += 1) {
            const index = group.cursor % group.entry_indices.items.len;
            group.cursor = (index + 1) % group.entry_indices.items.len;
            if (self.entries.items[group.entry_indices.items[index]]) |entry| return entry;
        }
        return null;
    }

    fn stickyGroupEntry(self: Router, group: *SharedGroup) ?Entry {
        var checked: usize = 0;
        while (checked < group.entry_indices.items.len) : (checked += 1) {
            const index =
                (group.cursor + checked) % group.entry_indices.items.len;
            if (self.entries.items[group.entry_indices.items[index]]) |entry| {
                group.cursor = index;
                return entry;
            }
        }
        return null;
    }

    fn randomGroupEntry(self: Router, group: *SharedGroup) ?Entry {
        var checked: usize = 0;
        const first = std.math.cast(
            usize,
            nextRandom(&group.random_state) %
                @as(u64, @intCast(group.entry_indices.items.len)),
        ) orelse 0;
        while (checked < group.entry_indices.items.len) : (checked += 1) {
            const index = (first + checked) % group.entry_indices.items.len;
            if (self.entries.items[group.entry_indices.items[index]]) |entry| {
                return entry;
            }
        }
        return null;
    }

    fn rendezvousGroupEntry(
        self: Router,
        group: SharedGroup,
        topic: []const u8,
    ) ?Entry {
        var selected: ?Entry = null;
        var selected_score: u64 = 0;
        for (group.entry_indices.items) |entry_index| {
            const entry = self.entries.items[entry_index] orelse continue;
            const score = rendezvousScore(group, topic, entry.subscriber_id);
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

    fn insertFilterPath(self: *Router, filter: []const u8) Error!struct { usize, bool } {
        var node_index: usize = 0;
        var it = std.mem.splitScalar(u8, filter, '/');
        while (it.next()) |level| {
            if (std.mem.eql(u8, level, "#")) return .{ node_index, true };
            if (std.mem.eql(u8, level, "+")) {
                if (self.nodes.items[node_index].single_wildcard_child) |child| {
                    node_index = child;
                } else {
                    const child = self.nodes.items.len;
                    try self.nodes.append(self.allocator, .{});
                    self.nodes.items[node_index].single_wildcard_child = child;
                    node_index = child;
                }
                continue;
            }
            if (findLiteralChild(self.nodes.items[node_index], level)) |child| {
                node_index = child;
            } else {
                const owned = try self.allocator.dupe(u8, level);
                errdefer self.allocator.free(owned);
                const child = self.nodes.items.len;
                try self.nodes.append(self.allocator, .{});
                errdefer _ = self.nodes.pop();
                try self.nodes.items[node_index].literal_children.put(self.allocator, owned, child);
                node_index = child;
            }
        }
        return .{ node_index, false };
    }

    fn findFilterPath(self: Router, filter: []const u8) ?struct { usize, bool } {
        var node_index: usize = 0;
        var it = std.mem.splitScalar(u8, filter, '/');
        while (it.next()) |level| {
            if (std.mem.eql(u8, level, "#")) return .{ node_index, true };
            if (std.mem.eql(u8, level, "+")) {
                node_index = self.nodes.items[node_index].single_wildcard_child orelse return null;
            } else {
                node_index = findLiteralChild(self.nodes.items[node_index], level) orelse return null;
            }
        }
        return .{ node_index, false };
    }

    fn findEntry(self: Router, subscriber_id: SubscriberId, topic_filter: []const u8) ?usize {
        const parsed = parseFilter(topic_filter) orelse return null;
        for (self.entries.items, 0..) |maybe_entry, i| {
            const entry = maybe_entry orelse continue;
            if (entry.subscriber_id != subscriber_id) continue;
            if (!std.mem.eql(u8, entry.effective_filter, parsed.effective_filter)) continue;
            if (!optionalEql(entry.shared_group, parsed.group)) continue;
            return i;
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

        for (self.shared_groups.items, 0..) |maybe_group, i| {
            if (maybe_group != null) continue;
            const selection_seed = sharedGroupSeed(
                self.options.random_seed,
                name,
                filter,
            );
            self.shared_groups.items[i] = .{
                .name = owned_name,
                .effective_filter = owned_filter,
                .strategy = self.options.shared_subscription_strategy,
                .selection_seed = selection_seed,
                .random_state = selection_seed,
            };
            owns_name = false;
            owns_filter = false;
            return .{ i, true };
        }

        const selection_seed = sharedGroupSeed(
            self.options.random_seed,
            name,
            filter,
        );
        try self.shared_groups.append(self.allocator, .{
            .name = owned_name,
            .effective_filter = owned_filter,
            .strategy = self.options.shared_subscription_strategy,
            .selection_seed = selection_seed,
            .random_state = selection_seed,
        });
        owns_name = false;
        owns_filter = false;
        return .{ self.shared_groups.items.len - 1, true };
    }

    fn findSharedGroup(self: Router, name: []const u8, filter: []const u8) ?usize {
        for (self.shared_groups.items, 0..) |maybe_group, i| {
            const group = maybe_group orelse continue;
            if (!std.mem.eql(u8, group.name, name)) continue;
            if (std.mem.eql(u8, group.effective_filter, filter)) return i;
        }
        return null;
    }

    fn removeSharedGroupAt(self: *Router, group_index: usize) void {
        if (group_index >= self.shared_groups.items.len) return;
        if (self.shared_groups.items[group_index]) |*group| {
            group.deinit(self.allocator);
            self.shared_groups.items[group_index] = null;
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

fn findLiteralChild(node: Node, level: []const u8) ?usize {
    return node.literal_children.get(level);
}

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

fn optionalEql(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null or b == null) return a == null and b == null;
    return std.mem.eql(u8, a.?, b.?);
}

fn entryMatch(entry: Entry) Match {
    return .{
        .subscriber_id = entry.subscriber_id,
        .subscription = entry.subscription,
        .subscription_identifier = entry.subscription_identifier,
    };
}

fn rendezvousScore(
    group: SharedGroup,
    topic: []const u8,
    subscriber_id: SubscriberId,
) u64 {
    var hasher = std.hash.Wyhash.init(group.selection_seed);
    hasher.update(topic);
    var id_bytes: [@sizeOf(SubscriberId)]u8 = undefined;
    std.mem.writeInt(SubscriberId, &id_bytes, subscriber_id, .little);
    hasher.update(&id_bytes);
    return hasher.final();
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
