//! Durable inbound QoS 2 transaction storage for broker-bridge ingestion.
//!
//! A bridge must not acknowledge an upstream QoS 2 PUBLISH until its mapped
//! local Application Message has been accepted, and it must not lose the
//! transaction when the later PUBREL/PUBCOMP leg is retried or interrupted.
//! This store therefore tracks each upstream Packet Identifier by a stable
//! bridge key and retains two phases:
//!
//! - `pending`: owns the final mapped local `mqtt.Publish` that must be
//!   routed exactly once once the caller is ready to consume PUBREL.
//! - `released`: tombstone state after the caller has claimed the pending
//!   publish for routing but before upstream completion is fully forgotten.
//!
//! The API is intentionally transactional. `release` returns a claim handle
//! that temporarily removes the pending entry from ordinary lookup while the
//! caller routes the message. The caller must then either `commitRelease`,
//! which installs the released tombstone, or `rollbackRelease`, which puts the
//! original pending message back unchanged. This makes local route failure and
//! retry explicit without requiring the caller to clone the message itself.

const std = @import("std");
const mqtt = @import("../mod.zig");
const owned_properties = @import("../owned_properties.zig");
const persistence = @import("../persistence/codec.zig");

pub const Error = mqtt.Error || persistence.Error || error{
    EntryLimitExceeded,
    OwnedByteLimitExceeded,
    InvalidReleaseState,
    InvalidStoreOptions,
    SequenceOverflow,
};

pub const Key = struct {
    bridge_id: [16]u8,
    session_epoch: u64,
    packet_id: u16,
};

pub const Phase = enum(u8) {
    pending = 0,
    released = 1,
};

pub const StageResult = enum {
    inserted,
    duplicate,
    replaced,
};

/// Minimal pending-transaction metadata needed to rebuild a bridge client's
/// inbound QoS 2 receive state after its process or transport is recreated.
pub const PendingTransaction = struct {
    packet_id: u16,
};

const Epoch = struct {
    bridge_id: [16]u8,
    value: u64,
};

pub const ReleaseResult = struct {
    duplicated: bool,
    claim: ?Claim,
};

pub const Stats = struct {
    entries: usize,
    bridges: usize,
    pending: usize,
    released: usize,
    owned_bytes: usize,
};

pub const Options = struct {
    max_entries: usize = 1024,
    max_owned_bytes: usize = 64 * 1024 * 1024,
};

const snapshot_version: u32 = 2;

pub const Publish = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    topic_len: usize,
    properties: []mqtt.Property,
    stored_at_ns: i96,
    expiry_interval: ?u32,
    allocation_bytes: usize,
    retain: bool,

    pub fn create(
        allocator: std.mem.Allocator,
        publish: mqtt.Publish,
        now: std.Io.Timestamp,
    ) Error!Publish {
        try validateStagedPublish(publish);
        const bytes_len = std.math.add(
            usize,
            publish.topic.len,
            publish.payload.len,
        ) catch return error.OwnedByteLimitExceeded;
        const bytes = try allocator.alloc(u8, bytes_len);
        errdefer allocator.free(bytes);
        @memcpy(bytes[0..publish.topic.len], publish.topic);
        @memcpy(bytes[publish.topic.len..], publish.payload);

        const property_result = owned_properties.clone(
            allocator,
            publish.properties,
            keepBridgeProperty,
        ) catch |err| switch (err) {
            error.OwnedPropertyLimitExceeded => return error.OwnedByteLimitExceeded,
            else => return @errorCast(err),
        };
        errdefer owned_properties.deinit(
            allocator,
            property_result.properties,
        );

        var allocation_bytes = bytes.len;
        allocation_bytes = std.math.add(
            usize,
            allocation_bytes,
            property_result.allocation_bytes,
        ) catch return error.OwnedByteLimitExceeded;

        return .{
            .allocator = allocator,
            .bytes = bytes,
            .topic_len = publish.topic.len,
            .properties = property_result.properties,
            .stored_at_ns = now.nanoseconds,
            .expiry_interval = mqtt.messageExpiryInterval(
                property_result.properties,
            ),
            .allocation_bytes = allocation_bytes,
            .retain = publish.retain,
        };
    }

    pub fn deinit(self: *Publish) void {
        owned_properties.deinit(self.allocator, self.properties);
        self.allocator.free(self.bytes);
        self.* = undefined;
    }

    pub fn topic(self: Publish) []const u8 {
        return self.bytes[0..self.topic_len];
    }

    pub fn payload(self: Publish) []const u8 {
        return self.bytes[self.topic_len..];
    }

    pub fn equalsIncoming(self: Publish, other: mqtt.Publish) bool {
        return self.retain == other.retain and
            std.mem.eql(u8, self.topic(), other.topic) and
            std.mem.eql(u8, self.payload(), other.payload) and
            filteredPropertiesEqual(self.properties, other.properties);
    }

    /// Build the Application Message that may be routed at PUBREL time.
    ///
    /// Message Expiry starts when the upstream PUBLISH is staged, not when the
    /// two-phase handshake reaches PUBREL. The returned properties therefore
    /// replace the original interval with its remaining whole-second value.
    /// `null` means the message expired and the transaction should advance to
    /// its released tombstone without routing an Application Message.
    pub fn asPublish(
        self: Publish,
        now: std.Io.Timestamp,
        adjusted_properties: *std.ArrayList(mqtt.Property),
    ) Error!?mqtt.Publish {
        const remaining = remainingExpiry(
            self.expiry_interval,
            self.stored_at_ns,
            now.nanoseconds,
        );
        if (remaining == 0) return null;

        try adjusted_properties.ensureTotalCapacity(
            self.allocator,
            self.properties.len,
        );
        for (self.properties) |property| {
            if (property == .four_byte and
                property.four_byte.id == .message_expiry_interval)
            {
                adjusted_properties.appendAssumeCapacity(.{
                    .four_byte = .{
                        .id = .message_expiry_interval,
                        .value = remaining.?,
                    },
                });
            } else {
                adjusted_properties.appendAssumeCapacity(property);
            }
        }

        return .{
            .dup = false,
            .qos = .exactly_once,
            .retain = self.retain,
            .topic = self.topic(),
            .packet_id = null,
            .properties = adjusted_properties.items,
            .payload = self.payload(),
        };
    }
};

const Entry = struct {
    key: Key,
    phase: Phase,
    publish: ?Publish,

    fn deinit(self: *Entry) void {
        if (self.publish) |*publish| publish.deinit();
        self.* = undefined;
    }

    fn ownedBytes(self: Entry) usize {
        return if (self.publish) |publish| publish.allocation_bytes else 0;
    }
};

pub const Claim = struct {
    key: Key,
    publish: Publish,

    pub fn asPublish(
        self: Claim,
        now: std.Io.Timestamp,
        adjusted_properties: *std.ArrayList(mqtt.Property),
    ) Error!?mqtt.Publish {
        return self.publish.asPublish(now, adjusted_properties);
    }

    /// Release an abandoned claim that cannot be committed or rolled back.
    pub fn deinit(self: *Claim) void {
        self.publish.deinit();
        self.* = undefined;
    }
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    options: Options,
    entries: std.ArrayListUnmanaged(Entry) = .empty,
    epochs: std.ArrayListUnmanaged(Epoch) = .empty,
    owned_bytes: usize = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        options: Options,
    ) (std.mem.Allocator.Error || error{InvalidStoreOptions})!Store {
        if (options.max_entries == 0 or options.max_owned_bytes == 0) {
            return error.InvalidStoreOptions;
        }
        var self = Store{
            .allocator = allocator,
            .options = options,
        };
        errdefer self.deinit();
        try self.entries.ensureTotalCapacity(
            allocator,
            options.max_entries,
        );
        try self.epochs.ensureTotalCapacity(
            allocator,
            options.max_entries,
        );
        return self;
    }

    pub fn deinit(self: *Store) void {
        for (self.entries.items) |*entry| entry.deinit();
        self.entries.deinit(self.allocator);
        self.epochs.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn swap(self: *Store, other: *Store) void {
        const value = self.*;
        self.* = other.*;
        other.* = value;
    }

    pub fn stats(self: Store) Stats {
        var pending: usize = 0;
        var released: usize = 0;
        for (self.entries.items) |entry| switch (entry.phase) {
            .pending => pending += 1,
            .released => released += 1,
        };
        return .{
            .entries = self.entries.items.len,
            .bridges = self.epochs.items.len,
            .pending = pending,
            .released = released,
            .owned_bytes = self.owned_bytes,
        };
    }

    /// Stage a mapped local QoS 2 publish.
    ///
    /// Duplicate MQTT retransmissions must arrive with `dup = true` and
    /// identical application bytes. A different duplicate under the same key is
    /// rejected as an invalid packet-identifier reuse. A non-DUP publish
    /// replaces any older pending or released state for that key so a fresh
    /// upstream session epoch or transaction can reuse the packet identifier
    /// deterministically.
    pub fn stage(
        self: *Store,
        key: Key,
        publish: mqtt.Publish,
        now: std.Io.Timestamp,
    ) Error!StageResult {
        if (key.packet_id == 0) return error.InvalidPacketIdentifier;
        const index = self.findIndex(key);
        if (index) |found| {
            const existing = self.entries.items[found];
            if (publish.dup) {
                if (!entryMatchesDuplicate(existing, publish)) {
                    return error.InvalidPacketIdentifier;
                }
                return .duplicate;
            }
            const replacement = try Publish.create(
                self.allocator,
                withoutDup(publish),
                now,
            );
            errdefer {
                var doomed = replacement;
                doomed.deinit();
            }
            const after_removal = self.owned_bytes - existing.ownedBytes();
            const replaced_total = std.math.add(
                usize,
                after_removal,
                replacement.allocation_bytes,
            ) catch return error.OwnedByteLimitExceeded;
            if (replaced_total > self.options.max_owned_bytes) {
                return error.OwnedByteLimitExceeded;
            }
            self.entries.items[found].deinit();
            self.entries.items[found] = .{
                .key = key,
                .phase = .pending,
                .publish = replacement,
            };
            self.owned_bytes = replaced_total;
            return .replaced;
        }

        if (self.entries.items.len >= self.options.max_entries) {
            return error.EntryLimitExceeded;
        }
        const created = try Publish.create(
            self.allocator,
            withoutDup(publish),
            now,
        );
        errdefer {
            var doomed = created;
            doomed.deinit();
        }
        try self.reserveOwnedDelta(created.allocation_bytes);
        self.entries.append(self.allocator, .{
            .key = key,
            .phase = .pending,
            .publish = created,
        }) catch |err| {
            self.releaseOwnedBytes(created.allocation_bytes);
            return err;
        };
        return .inserted;
    }

    /// Move a pending transaction into a caller-owned claim. Releasing an
    /// already released key is idempotent and reports `duplicated = true`.
    pub fn release(self: *Store, key: Key) ReleaseResult {
        const index = self.findIndex(key) orelse
            return .{ .duplicated = false, .claim = null };
        const entry = &self.entries.items[index];
        switch (entry.phase) {
            .released => return .{ .duplicated = true, .claim = null },
            .pending => {
                const publish = entry.publish.?;
                entry.publish = null;
                self.releaseOwnedBytes(publish.allocation_bytes);
                return .{
                    .duplicated = false,
                    .claim = .{
                        .key = key,
                        .publish = publish,
                    },
                };
            },
        }
    }

    /// Destroy an uncommitted claim when the caller cannot safely restore it.
    /// Normal release paths should prefer `rollbackRelease` or `commitRelease`;
    /// this explicit escape hatch keeps error cleanup leak-free.
    pub fn discardClaim(claim: *Claim) void {
        claim.deinit();
    }

    /// Install the released tombstone after the caller has successfully routed
    /// the claimed publish. Repeating the commit is safe only through the
    /// tombstone path exposed by `release`; committing a claim twice is an
    /// explicit caller bug.
    pub fn commitRelease(self: *Store, claim: *Claim) Error!void {
        const index = self.findIndex(claim.key) orelse
            return error.InvalidReleaseState;
        const entry = &self.entries.items[index];
        if (entry.phase != .pending or entry.publish != null) {
            return error.InvalidReleaseState;
        }
        entry.phase = .released;
        claim.publish.deinit();
        claim.* = undefined;
    }

    /// Put the claimed publish back into pending state after a failed local
    /// routing attempt. Ownership returns to the store.
    pub fn rollbackRelease(self: *Store, claim: *Claim) Error!void {
        const index = self.findIndex(claim.key) orelse
            return error.InvalidReleaseState;
        const entry = &self.entries.items[index];
        if (entry.phase != .pending or entry.publish != null) {
            return error.InvalidReleaseState;
        }
        try self.reserveOwnedDelta(claim.publish.allocation_bytes);
        entry.publish = claim.publish;
        claim.* = undefined;
    }

    /// Forget a released tombstone once PUBCOMP has been durably handled.
    pub fn complete(self: *Store, key: Key) bool {
        const index = self.findIndex(key) orelse return false;
        if (self.entries.items[index].phase != .released) return false;
        _ = self.orderedRemove(index);
        return true;
    }

    pub fn getPending(self: *const Store, key: Key) ?mqtt.Publish {
        const index = self.findIndex(key) orelse return null;
        const entry = self.entries.items[index];
        if (entry.phase != .pending or entry.publish == null) return null;
        const publish = entry.publish.?;
        return .{
            .dup = false,
            .qos = .exactly_once,
            .retain = publish.retain,
            .topic = publish.topic(),
            .packet_id = null,
            .properties = publish.properties,
            .payload = publish.payload(),
        };
    }

    /// Return an expiry-aware view of a pending message. The caller owns the
    /// scratch property list, while topic, payload, and variable-sized property
    /// values remain borrowed from the store until it is mutated.
    pub fn pendingAsPublish(
        self: *const Store,
        key: Key,
        now: std.Io.Timestamp,
        adjusted_properties: *std.ArrayList(mqtt.Property),
    ) Error!?mqtt.Publish {
        const index = self.findIndex(key) orelse return null;
        const entry = self.entries.items[index];
        if (entry.phase != .pending or entry.publish == null) return null;
        return entry.publish.?.asPublish(now, adjusted_properties);
    }

    pub fn getPhase(self: *const Store, key: Key) ?Phase {
        const index = self.findIndex(key) orelse return null;
        return self.entries.items[index].phase;
    }

    /// Return the greatest persisted Session epoch for one stable bridge. A
    /// newly constructed Bridge uses this to address transactions restored
    /// with the local broker before it learns whether the upstream Session
    /// survived.
    pub fn latestSessionEpoch(
        self: *const Store,
        bridge_id: [16]u8,
    ) ?u64 {
        var latest: ?u64 = if (self.findEpochIndex(bridge_id)) |index|
            self.epochs.items[index].value
        else
            null;
        for (self.entries.items) |entry| {
            if (!std.mem.eql(u8, &entry.key.bridge_id, &bridge_id)) continue;
            latest = @max(latest orelse 0, entry.key.session_epoch);
        }
        return latest;
    }

    /// Record a fresh upstream Session generation. The marker survives even
    /// when no QoS 2 transaction is active, closing the crash window between
    /// CONNACK and the next PUBLISH.
    pub fn advanceSession(self: *Store, bridge_id: [16]u8) Error!u64 {
        const epoch_index = self.findEpochIndex(bridge_id);
        var current = if (epoch_index) |index|
            self.epochs.items[index].value
        else
            0;
        for (self.entries.items) |entry| {
            if (std.mem.eql(u8, &entry.key.bridge_id, &bridge_id)) {
                current = @max(current, entry.key.session_epoch);
            }
        }
        const next = std.math.add(u64, current, 1) catch
            return error.SequenceOverflow;
        if (epoch_index) |index| {
            self.epochs.items[index].value = next;
        } else {
            if (self.epochs.items.len >= self.options.max_entries) {
                return error.EntryLimitExceeded;
            }
            try self.epochs.append(self.allocator, .{
                .bridge_id = bridge_id,
                .value = next,
            });
        }
        return next;
    }

    /// Return whether a durable transaction exists for this exact key.
    pub fn contains(self: *const Store, key: Key) bool {
        return self.findIndex(key) != null;
    }

    /// Allocate the protocol state required to resume one upstream Session.
    /// Application Message bytes stay owned by this Store and are released
    /// only when the matching PUBREL reaches the broker transaction API.
    pub fn pendingSessionTransactionsAlloc(
        self: *const Store,
        allocator: std.mem.Allocator,
        bridge_id: [16]u8,
        session_epoch: u64,
    ) std.mem.Allocator.Error![]PendingTransaction {
        var count: usize = 0;
        for (self.entries.items) |entry| {
            if (entry.phase == .pending and
                entry.key.session_epoch == session_epoch and
                std.mem.eql(u8, &entry.key.bridge_id, &bridge_id))
            {
                count += 1;
            }
        }
        const transactions = try allocator.alloc(PendingTransaction, count);
        var index: usize = 0;
        for (self.entries.items) |entry| {
            if (entry.phase != .pending or
                entry.key.session_epoch != session_epoch or
                !std.mem.eql(u8, &entry.key.bridge_id, &bridge_id))
            {
                continue;
            }
            transactions[index] = .{
                .packet_id = entry.key.packet_id,
            };
            index += 1;
        }
        return transactions;
    }

    /// Replace a pending message with its released tombstone without moving
    /// ownership through a Claim. Broker integration uses this while holding
    /// its state barrier so routing effects and the tombstone enter one
    /// persisted snapshot. Returns false for an unknown key or an existing
    /// tombstone.
    pub fn markReleased(self: *Store, key: Key) bool {
        const index = self.findIndex(key) orelse return false;
        const entry = &self.entries.items[index];
        if (entry.phase == .released) return false;
        const publish = entry.publish orelse return false;
        self.releaseOwnedBytes(publish.allocation_bytes);
        entry.publish.?.deinit();
        entry.publish = null;
        entry.phase = .released;
        return true;
    }

    /// Remove every transaction belonging to one superseded upstream Session
    /// epoch. Bridge reconnect code uses this when CONNACK reports Session
    /// Present=false; Packet Identifiers from the old epoch can no longer be
    /// resumed and must not consume the bounded store indefinitely.
    pub fn removeSession(
        self: *Store,
        bridge_id: [16]u8,
        session_epoch: u64,
    ) usize {
        var removed: usize = 0;
        var index: usize = 0;
        while (index < self.entries.items.len) {
            const key = self.entries.items[index].key;
            if (key.session_epoch != session_epoch or
                !std.mem.eql(u8, &key.bridge_id, &bridge_id))
            {
                index += 1;
                continue;
            }
            var entry = self.orderedRemove(index);
            entry.deinit();
            removed += 1;
        }
        return removed;
    }

    /// Drop only released tombstones from one resumed Session after the
    /// reconnect client has restored their release-pending markers. A repeated
    /// PUBREL can then still be completed without retaining the bounded local
    /// tombstone indefinitely.
    pub fn removeReleasedSession(
        self: *Store,
        bridge_id: [16]u8,
        session_epoch: u64,
    ) usize {
        var removed: usize = 0;
        var index: usize = 0;
        while (index < self.entries.items.len) {
            const entry = self.entries.items[index];
            if (entry.phase != .released or
                entry.key.session_epoch != session_epoch or
                !std.mem.eql(u8, &entry.key.bridge_id, &bridge_id))
            {
                index += 1;
                continue;
            }
            var removed_entry = self.orderedRemove(index);
            removed_entry.deinit();
            removed += 1;
        }
        return removed;
    }

    /// Remove every transaction for a bridge after CONNACK reports a fresh
    /// upstream Session. The separate epoch marker remains intact.
    pub fn removeBridge(self: *Store, bridge_id: [16]u8) usize {
        var removed: usize = 0;
        var index: usize = 0;
        while (index < self.entries.items.len) {
            if (!std.mem.eql(
                u8,
                &self.entries.items[index].key.bridge_id,
                &bridge_id,
            )) {
                index += 1;
                continue;
            }
            var entry = self.orderedRemove(index);
            entry.deinit();
            removed += 1;
        }
        return removed;
    }

    pub fn writeSnapshot(
        self: *const Store,
        out: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        now: std.Io.Timestamp,
    ) Error!void {
        try persistence.appendInt(
            out,
            allocator,
            u32,
            snapshot_version,
        );
        if (self.epochs.items.len > std.math.maxInt(u32)) {
            return error.SnapshotLimitExceeded;
        }
        try persistence.appendInt(
            out,
            allocator,
            u32,
            @intCast(self.epochs.items.len),
        );
        for (self.epochs.items) |epoch| {
            try persistence.appendBlob(
                out,
                allocator,
                &epoch.bridge_id,
            );
            try persistence.appendInt(
                out,
                allocator,
                u64,
                epoch.value,
            );
        }
        var count: u32 = 0;
        for (self.entries.items) |entry| {
            if (entry.phase == .pending) {
                if (entry.publish) |publish| {
                    if (remainingExpiryNs(publish, now.nanoseconds) == 0) {
                        continue;
                    }
                }
            }
            count = std.math.add(u32, count, 1) catch
                return error.SnapshotLimitExceeded;
        }
        try persistence.appendInt(out, allocator, u32, count);
        for (self.entries.items) |entry| {
            if (entry.phase == .pending) {
                if (entry.publish) |publish| {
                    if (remainingExpiryNs(publish, now.nanoseconds) == 0) {
                        continue;
                    }
                }
            }
            try persistence.appendBlob(out, allocator, &entry.key.bridge_id);
            try persistence.appendInt(
                out,
                allocator,
                u64,
                entry.key.session_epoch,
            );
            try persistence.appendInt(
                out,
                allocator,
                u16,
                entry.key.packet_id,
            );
            try persistence.appendInt(
                out,
                allocator,
                u8,
                @intFromEnum(entry.phase),
            );
            switch (entry.phase) {
                .released => {
                    try persistence.appendBool(out, allocator, false);
                },
                .pending => {
                    const publish = entry.publish orelse return error.CorruptSnapshot;
                    try persistence.appendBool(out, allocator, true);
                    try persistence.appendBlob(
                        out,
                        allocator,
                        publish.topic(),
                    );
                    try persistence.appendBlob(
                        out,
                        allocator,
                        publish.payload(),
                    );
                    try persistence.appendBool(out, allocator, publish.retain);
                    try persistence.appendOptionalInt(
                        out,
                        allocator,
                        u64,
                        remainingExpiryNs(publish, now.nanoseconds),
                    );
                    try persistence.appendProperties(
                        out,
                        allocator,
                        publish.properties,
                    );
                },
            }
        }
    }

    pub fn restoreSnapshot(
        self: *Store,
        cursor: *persistence.Cursor,
        restore_now: std.Io.Timestamp,
        downtime_ns: i96,
    ) Error!void {
        const version = try cursor.readInt(u32);
        if (version != snapshot_version) {
            return error.UnsupportedSnapshotVersion;
        }
        const epoch_count = try cursor.readInt(u32);
        if (epoch_count > self.options.max_entries) {
            return error.EntryLimitExceeded;
        }
        for (0..epoch_count) |_| {
            const bridge_id_blob = try cursor.readBlob();
            if (bridge_id_blob.len != 16) return error.CorruptSnapshot;
            var bridge_id: [16]u8 = undefined;
            @memcpy(&bridge_id, bridge_id_blob);
            const epoch = try cursor.readInt(u64);
            if (epoch == 0 or self.findEpochIndex(bridge_id) != null) {
                return error.CorruptSnapshot;
            }
            try self.epochs.append(self.allocator, .{
                .bridge_id = bridge_id,
                .value = epoch,
            });
        }
        const count = try cursor.readInt(u32);
        if (count > self.options.max_entries) {
            return error.EntryLimitExceeded;
        }
        for (0..count) |_| {
            const bridge_id_blob = try cursor.readBlob();
            if (bridge_id_blob.len != 16) return error.CorruptSnapshot;
            var bridge_id: [16]u8 = undefined;
            @memcpy(&bridge_id, bridge_id_blob);
            const key = Key{
                .bridge_id = bridge_id,
                .session_epoch = try cursor.readInt(u64),
                .packet_id = try cursor.readInt(u16),
            };
            if (key.packet_id == 0) return error.CorruptSnapshot;
            const phase = switch (try cursor.readInt(u8)) {
                @intFromEnum(Phase.pending) => Phase.pending,
                @intFromEnum(Phase.released) => Phase.released,
                else => return error.CorruptSnapshot,
            };
            const has_publish = try cursor.readBool();
            switch (phase) {
                .released => {
                    if (has_publish) return error.CorruptSnapshot;
                    try self.appendRestored(.{
                        .key = key,
                        .phase = .released,
                        .publish = null,
                    });
                },
                .pending => {
                    if (!has_publish) return error.CorruptSnapshot;
                    const topic = try cursor.readBlob();
                    const payload = try cursor.readBlob();
                    const retain = try cursor.readBool();
                    const saved_remaining_ns = try cursor.readOptionalInt(u64);
                    const properties = try cursor.readProperties(self.allocator);
                    defer self.allocator.free(properties);

                    try mqtt.validateTopicName(topic);
                    try mqtt.validatePublishProperties(properties);
                    if (mqtt.subscriptionIdentifier(properties) != null) {
                        return error.CorruptSnapshot;
                    }
                    if ((mqtt.messageExpiryInterval(properties) == null) !=
                        (saved_remaining_ns == null))
                    {
                        return error.CorruptSnapshot;
                    }
                    const remaining_ns = remainingAfterDowntimeNs(
                        saved_remaining_ns,
                        downtime_ns,
                    );
                    if (remaining_ns == 0) continue;

                    const stage_result = try self.stage(
                        key,
                        .{
                            .dup = false,
                            .qos = .exactly_once,
                            .retain = retain,
                            .topic = topic,
                            .packet_id = null,
                            .properties = properties,
                            .payload = payload,
                        },
                        restore_now,
                    );
                    if (stage_result != .inserted) {
                        return error.CorruptSnapshot;
                    }
                    if (remaining_ns) |remaining| {
                        const restored = self.getEntryPtr(key) orelse
                            return error.CorruptSnapshot;
                        const publish = restored.publish orelse
                            return error.CorruptSnapshot;
                        const interval = publish.expiry_interval orelse
                            return error.CorruptSnapshot;
                        const lifetime_ns = @as(u64, interval) *
                            std.time.ns_per_s;
                        if (remaining > lifetime_ns) {
                            return error.CorruptSnapshot;
                        }
                        restored.publish.?.stored_at_ns =
                            restore_now.nanoseconds -
                            @as(i96, lifetime_ns - remaining);
                    }
                },
            }
        }
    }

    fn appendRestored(self: *Store, entry: Entry) Error!void {
        if (self.findIndex(entry.key) != null) return error.CorruptSnapshot;
        if (self.entries.items.len >= self.options.max_entries) {
            return error.EntryLimitExceeded;
        }
        try self.reserveOwnedDelta(entry.ownedBytes());
        self.entries.append(self.allocator, entry) catch |err| {
            self.releaseOwnedBytes(entry.ownedBytes());
            return err;
        };
    }

    fn reserveOwnedDelta(self: *Store, delta: usize) Error!void {
        const next = std.math.add(
            usize,
            self.owned_bytes,
            delta,
        ) catch return error.OwnedByteLimitExceeded;
        if (next > self.options.max_owned_bytes) {
            return error.OwnedByteLimitExceeded;
        }
        self.owned_bytes = next;
    }

    fn releaseOwnedBytes(self: *Store, delta: usize) void {
        self.owned_bytes -|= delta;
    }

    fn orderedRemove(self: *Store, index: usize) Entry {
        const removed = self.entries.orderedRemove(index);
        self.releaseOwnedBytes(removed.ownedBytes());
        return removed;
    }

    fn findIndex(self: *const Store, key: Key) ?usize {
        for (self.entries.items, 0..) |entry, index| {
            if (keyEqual(entry.key, key)) return index;
        }
        return null;
    }

    fn findEpochIndex(self: *const Store, bridge_id: [16]u8) ?usize {
        for (self.epochs.items, 0..) |epoch, index| {
            if (std.mem.eql(u8, &epoch.bridge_id, &bridge_id)) return index;
        }
        return null;
    }

    fn getEntryPtr(self: *Store, key: Key) ?*Entry {
        const index = self.findIndex(key) orelse return null;
        return &self.entries.items[index];
    }
};

fn validateStagedPublish(publish: mqtt.Publish) Error!void {
    if (publish.qos != .exactly_once) return error.InvalidQoS;
    try mqtt.validateTopicName(publish.topic);
    try mqtt.validatePublishProperties(publish.properties);
}

fn withoutDup(publish: mqtt.Publish) mqtt.Publish {
    var canonical = publish;
    canonical.dup = false;
    canonical.packet_id = null;
    return canonical;
}

fn entryMatchesDuplicate(entry: Entry, publish: mqtt.Publish) bool {
    // A released tombstone intentionally no longer owns message bytes. Its
    // stable transaction key is sufficient to suppress a retransmission after
    // local release while waiting for the peer to observe PUBCOMP.
    if (entry.phase == .released) return true;
    const staged = entry.publish orelse return false;
    return staged.equalsIncoming(withoutDup(publish));
}

fn keyEqual(left: Key, right: Key) bool {
    return std.mem.eql(u8, &left.bridge_id, &right.bridge_id) and
        left.session_epoch == right.session_epoch and
        left.packet_id == right.packet_id;
}

fn keepBridgeProperty(property: mqtt.Property) bool {
    return !((property == .two_byte and
        property.two_byte.id == .topic_alias) or
        (property == .varint and
            property.varint.id == .subscription_identifier));
}

fn filteredPropertiesEqual(
    stored: []const mqtt.Property,
    incoming: []const mqtt.Property,
) bool {
    var stored_index: usize = 0;
    for (incoming) |property| {
        if (!keepBridgeProperty(property)) continue;
        if (stored_index == stored.len or
            !propertyEqual(stored[stored_index], property))
        {
            return false;
        }
        stored_index += 1;
    }
    return stored_index == stored.len;
}

fn propertyEqual(left: mqtt.Property, right: mqtt.Property) bool {
    if (@intFromEnum(left) != @intFromEnum(right)) return false;
    return switch (left) {
        .byte => |value| right == .byte and
            value.id == right.byte.id and
            value.value == right.byte.value,
        .two_byte => |value| right == .two_byte and
            value.id == right.two_byte.id and
            value.value == right.two_byte.value,
        .four_byte => |value| right == .four_byte and
            value.id == right.four_byte.id and
            value.value == right.four_byte.value,
        .varint => |value| right == .varint and
            value.id == right.varint.id and
            value.value == right.varint.value,
        .binary => |value| right == .binary and
            value.id == right.binary.id and
            std.mem.eql(u8, value.value, right.binary.value),
        .utf8 => |value| right == .utf8 and
            value.id == right.utf8.id and
            std.mem.eql(u8, value.value, right.utf8.value),
        .utf8_pair => |value| right == .utf8_pair and
            value.id == right.utf8_pair.id and
            std.mem.eql(u8, value.key, right.utf8_pair.key) and
            std.mem.eql(u8, value.value, right.utf8_pair.value),
    };
}

fn remainingExpiry(
    interval: ?u32,
    stored_at_ns: i96,
    now_ns: i96,
) ?u32 {
    const value = interval orelse return null;
    if (value == 0) return 0;
    const elapsed_ns = @max(now_ns - stored_at_ns, 0);
    const expiry_ns = @as(i96, value) * std.time.ns_per_s;
    if (elapsed_ns >= expiry_ns) return 0;
    const elapsed_seconds: u32 = @intCast(
        @divTrunc(elapsed_ns, std.time.ns_per_s),
    );
    return value - elapsed_seconds;
}

fn remainingExpiryNs(
    publish: Publish,
    now_ns: i96,
) ?u64 {
    const interval = publish.expiry_interval orelse return null;
    const lifetime_ns = @as(u64, interval) * std.time.ns_per_s;
    const elapsed_ns: u64 = @intCast(@max(
        now_ns - publish.stored_at_ns,
        0,
    ));
    return lifetime_ns -| elapsed_ns;
}

fn remainingAfterDowntimeNs(
    remaining: ?u64,
    downtime_ns: i96,
) ?u64 {
    const value = remaining orelse return null;
    const elapsed: u64 = @intCast(@min(
        @max(downtime_ns, 0),
        std.math.maxInt(u64),
    ));
    return value -| elapsed;
}

fn testKey(packet_id: u16) Key {
    return .{
        .bridge_id = [_]u8{
            0, 1, 2,  3,  4,  5,  6,  7,
            8, 9, 10, 11, 12, 13, 14, 15,
        },
        .session_epoch = 42,
        .packet_id = packet_id,
    };
}

test "bridge QoS2 store deep owns pending publish" {
    const allocator = std.testing.allocator;
    var store = try Store.init(allocator, .{
        .max_entries = 2,
        .max_owned_bytes = 4096,
    });
    defer store.deinit();

    var topic = [_]u8{ 'm', '/', 'a', 'p' };
    var payload = [_]u8{ 'o', 'n', 'e' };
    try std.testing.expectEqual(
        StageResult.inserted,
        try store.stage(
            testKey(7),
            .{
                .dup = false,
                .qos = .exactly_once,
                .retain = true,
                .topic = &topic,
                .packet_id = null,
                .payload = &payload,
            },
            .zero,
        ),
    );
    @memset(&topic, 'x');
    @memset(&payload, 'x');

    const pending = store.getPending(testKey(7)).?;
    try std.testing.expectEqualStrings("m/ap", pending.topic);
    try std.testing.expectEqualStrings("one", pending.payload);
    try std.testing.expect(pending.retain);
    try std.testing.expectEqual(@as(usize, 1), store.stats().entries);
    try std.testing.expect(store.stats().owned_bytes > 0);
}

test "bridge QoS2 store rejects mismatched duplicate but accepts identical retry" {
    const allocator = std.testing.allocator;
    var store = try Store.init(allocator, .{
        .max_entries = 2,
        .max_owned_bytes = 4096,
    });
    defer store.deinit();

    const key = testKey(11);
    var connection_properties = [_]mqtt.Property{
        .{ .two_byte = .{ .id = .topic_alias, .value = 1 } },
        .{ .varint = .{ .id = .subscription_identifier, .value = 3 } },
        .{ .utf8_pair = .{
            .id = .user_property,
            .key = "source",
            .value = "remote",
        } },
    };
    _ = try store.stage(
        key,
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "mirror/topic",
            .packet_id = null,
            .properties = &connection_properties,
            .payload = "payload",
        },
        .zero,
    );

    try std.testing.expectEqual(
        StageResult.duplicate,
        try store.stage(
            key,
            .{
                .dup = true,
                .qos = .exactly_once,
                .retain = false,
                .topic = "mirror/topic",
                .packet_id = null,
                .properties = &connection_properties,
                .payload = "payload",
            },
            .zero,
        ),
    );
    try std.testing.expectError(
        error.InvalidPacketIdentifier,
        store.stage(
            key,
            .{
                .dup = true,
                .qos = .exactly_once,
                .retain = false,
                .topic = "mirror/topic",
                .packet_id = null,
                .payload = "other",
            },
            .zero,
        ),
    );
}

test "bridge QoS2 store release rollback and commit are transactional" {
    const allocator = std.testing.allocator;
    var store = try Store.init(allocator, .{
        .max_entries = 2,
        .max_owned_bytes = 4096,
    });
    defer store.deinit();

    const key = testKey(17);
    _ = try store.stage(
        key,
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "mirror/release",
            .packet_id = null,
            .payload = "body",
        },
        .zero,
    );

    var first = store.release(key);
    try std.testing.expect(!first.duplicated);
    try std.testing.expect(first.claim != null);
    try std.testing.expect(store.getPending(key) == null);
    try store.rollbackRelease(&first.claim.?);
    try std.testing.expectEqualStrings(
        "mirror/release",
        store.getPending(key).?.topic,
    );

    var second = store.release(key);
    try std.testing.expect(!second.duplicated);
    try store.commitRelease(&second.claim.?);
    try std.testing.expectEqual(Phase.released, store.getPhase(key).?);

    const repeated = store.release(key);
    try std.testing.expect(repeated.duplicated);
    try std.testing.expect(repeated.claim == null);
}

test "bridge QoS2 store allows non-DUP replacement after released tombstone and completion" {
    const allocator = std.testing.allocator;
    var store = try Store.init(allocator, .{
        .max_entries = 2,
        .max_owned_bytes = 4096,
    });
    defer store.deinit();

    const key = testKey(23);
    _ = try store.stage(
        key,
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "mirror/reuse",
            .packet_id = null,
            .payload = "first",
        },
        .zero,
    );
    var claim = store.release(key).claim.?;
    try store.commitRelease(&claim);

    try std.testing.expectEqual(
        StageResult.replaced,
        try store.stage(
            key,
            .{
                .dup = false,
                .qos = .exactly_once,
                .retain = true,
                .topic = "mirror/reuse",
                .packet_id = null,
                .payload = "second",
            },
            .zero,
        ),
    );
    try std.testing.expectEqualStrings("second", store.getPending(key).?.payload);

    var claim_again = store.release(key).claim.?;
    try store.commitRelease(&claim_again);
    try std.testing.expect(store.complete(key));
    try std.testing.expect(store.getPhase(key) == null);

    try std.testing.expectEqual(
        StageResult.inserted,
        try store.stage(
            key,
            .{
                .dup = false,
                .qos = .exactly_once,
                .retain = false,
                .topic = "mirror/reuse",
                .packet_id = null,
                .payload = "third",
            },
            .zero,
        ),
    );
}

test "bridge QoS2 replacement accounts the net owned-byte delta" {
    const allocator = std.testing.allocator;
    const key = testKey(24);
    const small_topic = "small";
    const large_topic = "larger-topic";
    const small_payload = "x";
    const large_payload = "larger-payload";
    const maximum = large_topic.len + large_payload.len;
    var store = try Store.init(allocator, .{
        .max_entries = 1,
        .max_owned_bytes = maximum,
    });
    defer store.deinit();

    _ = try store.stage(key, .{
        .dup = false,
        .qos = .exactly_once,
        .retain = false,
        .topic = small_topic,
        .packet_id = null,
        .payload = small_payload,
    }, .zero);
    try std.testing.expectEqual(
        StageResult.replaced,
        try store.stage(key, .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = large_topic,
            .packet_id = null,
            .payload = large_payload,
        }, .zero),
    );
    try std.testing.expectEqual(maximum, store.stats().owned_bytes);
}

test "bridge QoS2 store retires one upstream Session epoch" {
    const allocator = std.testing.allocator;
    var store = try Store.init(allocator, .{
        .max_entries = 3,
        .max_owned_bytes = 4096,
    });
    defer store.deinit();
    const first = testKey(24);
    var next_epoch = first;
    next_epoch.session_epoch += 1;
    _ = try store.stage(first, .{
        .dup = false,
        .qos = .exactly_once,
        .retain = false,
        .topic = "old",
        .packet_id = null,
        .payload = "one",
    }, .zero);
    _ = try store.stage(next_epoch, .{
        .dup = false,
        .qos = .exactly_once,
        .retain = false,
        .topic = "new",
        .packet_id = null,
        .payload = "two",
    }, .zero);

    try std.testing.expectEqual(
        @as(usize, 1),
        store.removeSession(first.bridge_id, first.session_epoch),
    );
    try std.testing.expect(store.getPhase(first) == null);
    try std.testing.expectEqual(Phase.pending, store.getPhase(next_epoch).?);
}

test "bridge QoS2 store enumerates epochs and removes bridge state" {
    const allocator = std.testing.allocator;
    var store = try Store.init(allocator, .{});
    defer store.deinit();
    const bridge_id = [_]u8{0x31} ** 16;
    const other_id = [_]u8{0x32} ** 16;
    const pending = Key{
        .bridge_id = bridge_id,
        .session_epoch = 4,
        .packet_id = 8,
    };
    var released = pending;
    released.packet_id = 9;
    var newer = pending;
    newer.session_epoch = 7;
    newer.packet_id = 10;
    var other = pending;
    other.bridge_id = other_id;

    for ([_]Key{ pending, released, newer, other }) |key| {
        _ = try store.stage(key, .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "bridge/enumerate",
            .packet_id = null,
            .payload = "value",
        }, .zero);
    }
    var claim = store.release(released).claim.?;
    try store.commitRelease(&claim);

    try std.testing.expectEqual(
        @as(?u64, 7),
        store.latestSessionEpoch(bridge_id),
    );
    const transactions = try store.pendingSessionTransactionsAlloc(
        allocator,
        bridge_id,
        4,
    );
    defer allocator.free(transactions);
    try std.testing.expectEqual(@as(usize, 1), transactions.len);
    try std.testing.expectEqual(@as(u16, 8), transactions[0].packet_id);

    try std.testing.expectEqual(Phase.pending, store.getPhase(pending).?);
    try std.testing.expectEqual(Phase.released, store.getPhase(released).?);
    try std.testing.expectEqual(
        @as(usize, 1),
        store.removeReleasedSession(bridge_id, 4),
    );
    try std.testing.expect(store.getPhase(released) == null);
    try std.testing.expectEqual(
        @as(u64, 8),
        try store.advanceSession(bridge_id),
    );
    try std.testing.expectEqual(@as(usize, 2), store.removeBridge(bridge_id));
    try std.testing.expectEqual(
        @as(?u64, 8),
        store.latestSessionEpoch(bridge_id),
    );
    try std.testing.expectEqual(Phase.pending, store.getPhase(other).?);
}

test "bridge QoS2 epoch survives snapshot without transactions" {
    const allocator = std.testing.allocator;
    var store = try Store.init(allocator, .{});
    defer store.deinit();
    const bridge_id = [_]u8{0x71} ** 16;
    try std.testing.expectEqual(
        @as(u64, 1),
        try store.advanceSession(bridge_id),
    );

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try store.writeSnapshot(&encoded, allocator, .zero);

    var restored = try Store.init(allocator, .{});
    defer restored.deinit();
    var cursor = persistence.Cursor.init(encoded.items);
    try restored.restoreSnapshot(&cursor, .zero, 0);
    try cursor.finish();
    try std.testing.expectEqual(
        @as(?u64, 1),
        restored.latestSessionEpoch(bridge_id),
    );
    try std.testing.expectEqual(
        @as(u64, 2),
        try restored.advanceSession(bridge_id),
    );
}

test "bridge QoS2 epoch table is bounded" {
    const allocator = std.testing.allocator;
    var store = try Store.init(allocator, .{
        .max_entries = 1,
        .max_owned_bytes = 1,
    });
    defer store.deinit();
    const first = [_]u8{0x81} ** 16;
    const second = [_]u8{0x82} ** 16;
    try std.testing.expectEqual(@as(u64, 1), try store.advanceSession(first));
    try std.testing.expectEqual(@as(u64, 2), try store.advanceSession(first));
    try std.testing.expectError(
        error.EntryLimitExceeded,
        store.advanceSession(second),
    );
}

test "bridge QoS2 store snapshot restores pending and released state and rejects corruption" {
    const allocator = std.testing.allocator;
    var store = try Store.init(allocator, .{
        .max_entries = 4,
        .max_owned_bytes = 8192,
    });
    defer store.deinit();

    var expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .message_expiry_interval,
        .value = 5,
    } }};

    const pending_key = testKey(31);
    const released_key = testKey(32);
    _ = try store.stage(
        pending_key,
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "mirror/pending",
            .packet_id = null,
            .properties = &expiry,
            .payload = "persisted",
        },
        .zero,
    );
    _ = try store.stage(
        released_key,
        .{
            .dup = false,
            .qos = .exactly_once,
            .retain = true,
            .topic = "mirror/released",
            .packet_id = null,
            .payload = "done-routing",
        },
        .zero,
    );
    var claim = store.release(released_key).claim.?;
    try store.commitRelease(&claim);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try store.writeSnapshot(
        &encoded,
        allocator,
        .zero,
    );

    var restored = try Store.init(allocator, .{
        .max_entries = 4,
        .max_owned_bytes = 8192,
    });
    defer restored.deinit();
    var cursor = persistence.Cursor.init(encoded.items);
    try restored.restoreSnapshot(
        &cursor,
        std.Io.Timestamp.fromNanoseconds(2 * std.time.ns_per_s),
        2 * std.time.ns_per_s,
    );
    try cursor.finish();
    try std.testing.expectEqual(Phase.pending, restored.getPhase(pending_key).?);
    try std.testing.expectEqual(Phase.released, restored.getPhase(released_key).?);
    try std.testing.expectEqualStrings(
        "persisted",
        restored.getPending(pending_key).?.payload,
    );

    var corrupt = try allocator.dupe(u8, encoded.items);
    defer allocator.free(corrupt);
    corrupt[0] ^= 0xff;
    var corrupt_cursor = persistence.Cursor.init(corrupt);
    try std.testing.expectError(
        error.UnsupportedSnapshotVersion,
        restored.restoreSnapshot(
            &corrupt_cursor,
            .zero,
            0,
        ),
    );
}
