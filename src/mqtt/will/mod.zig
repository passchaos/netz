//! MQTT Will Message lifecycle and delay scheduling.
//!
//! The scheduler owns Will payload/properties and uses an indexed binary
//! min-heap. ClientID lookup, reconnect cancellation, and rescheduling are
//! O(1)/O(log n), while polling due messages is O(log n) per delivery.

const std = @import("std");
const mqtt = @import("../mod.zig");
const owned_properties = @import("../owned_properties.zig");
const indexed_heap = @import("indexed_heap.zig");

pub const Error = mqtt.Error || error{
    WillNotFound,
    WillNotDue,
    WillLimitExceeded,
    WillByteLimitExceeded,
    DueBufferTooSmall,
};

pub const Options = struct {
    max_wills: usize = 65_536,
    max_will_bytes: usize = 16 * 1024 * 1024,
    max_total_bytes: usize = 256 * 1024 * 1024,
};

pub const Handle = struct {
    index: usize,
    generation: u64,
};

pub const CloseReason = enum {
    /// DISCONNECT 0x00; remove the Will without publishing.
    normal_disconnect,
    /// Network failure, Keep Alive timeout, or abnormal close.
    ungraceful,
    /// DISCONNECT 0x04; request publication subject to Will Delay.
    disconnect_with_will,
    /// A new connection with Clean Start=1 or an explicit Session end.
    session_ended,
};

pub const CloseResult = enum {
    no_will,
    canceled,
    scheduled,
    due_now,
};

pub const Due = struct {
    client_id: []const u8,
    topic: []const u8,
    payload: []const u8,
    qos: mqtt.QoS,
    retain: bool,
    properties: []const mqtt.Property,
    message_expiry_interval: ?u32,

    /// Encode the Will as a normal PUBLISH. Will Delay is a scheduling
    /// property and is omitted from the outgoing Application Message.
    pub fn writePublish(
        self: Due,
        list: *std.ArrayList(u8),
        allocator: std.mem.Allocator,
        protocol: mqtt.ProtocolVersion,
        packet_id: ?u16,
    ) Error!void {
        var properties: std.ArrayList(mqtt.Property) = .empty;
        defer properties.deinit(allocator);
        if (protocol == .v5) {
            try properties.ensureTotalCapacity(
                allocator,
                self.properties.len,
            );
            for (self.properties) |property| {
                if (property == .four_byte and
                    property.four_byte.id == .will_delay_interval)
                {
                    continue;
                }
                properties.appendAssumeCapacity(property);
            }
        }
        try mqtt.writePublish(
            list,
            allocator,
            protocol,
            self.topic,
            self.payload,
            .{
                .qos = self.qos,
                .retain = self.retain,
                .packet_id = packet_id,
                .properties = properties.items,
            },
        );
    }
};

const State = enum {
    connected,
    scheduled,
    /// Removed from the deadline heap by `pollDue`; publication is now
    /// committed and a later reconnect must not suppress or reschedule it.
    due,
};

const Entry = struct {
    generation: u64,
    client_id: []u8,
    topic: []u8,
    payload: []u8,
    qos: mqtt.QoS,
    retain: bool,
    properties: []mqtt.Property,
    will_delay_interval: u32,
    message_expiry_interval: ?u32,
    session_expiry_interval: u32,
    state: State = .connected,
    deadline_ns: i96 = 0,
    heap_index: ?usize = null,
    allocation_bytes: usize,

    fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
        owned_properties.deinit(allocator, self.properties);
        allocator.free(self.payload);
        allocator.free(self.topic);
        allocator.free(self.client_id);
        self.* = undefined;
    }
};

const DeadlineHeap = indexed_heap.IndexedMinHeap(
    *Scheduler,
    lessEntry,
    setHeapPosition,
);

pub const Scheduler = struct {
    allocator: std.mem.Allocator,
    options: Options,
    entries: std.ArrayList(?Entry) = .empty,
    /// Every vacant entry index appears exactly once here. Capacity tracks
    /// `entries`, allowing close/release paths to return slots without
    /// allocating and making subsequent CONNECT insertion O(1).
    free_indices: std.ArrayList(usize) = .empty,
    client_index: std.StringHashMapUnmanaged(usize) = .empty,
    heap: DeadlineHeap = .{},
    count_value: usize = 0,
    total_bytes: usize = 0,
    next_generation: u64 = 1,

    pub fn init(
        allocator: std.mem.Allocator,
        options: Options,
    ) Scheduler {
        return .{ .allocator = allocator, .options = options };
    }

    pub fn deinit(self: *Scheduler) void {
        for (self.entries.items) |*maybe_entry| {
            if (maybe_entry.*) |*entry| entry.deinit(self.allocator);
        }
        self.entries.deinit(self.allocator);
        self.free_indices.deinit(self.allocator);
        self.client_index.deinit(self.allocator);
        self.heap.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn count(self: Scheduler) usize {
        return self.count_value;
    }

    pub fn totalBytes(self: Scheduler) usize {
        return self.total_bytes;
    }

    /// Install the Will associated with a newly accepted CONNECT.
    ///
    /// Prefer `acceptConnect`, which atomically applies prior-connection
    /// lifecycle rules before deep-copying this Will.
    pub fn set(
        self: *Scheduler,
        client_id: []const u8,
        will: mqtt.LastWill,
        session_expiry_interval: u32,
    ) Error!Handle {
        if (self.client_index.contains(client_id)) {
            return error.InvalidClientId;
        }
        var entry = try self.prepare(
            client_id,
            will,
            session_expiry_interval,
            self.count_value + 1,
            self.total_bytes,
        );
        errdefer entry.deinit(self.allocator);
        try self.reserveInstall(
            self.count_value + 1,
            self.free_indices.items.len != 0,
        );
        return self.installPrepared(entry);
    }

    pub fn setConnect(
        self: *Scheduler,
        connect: mqtt.Connect,
    ) Error!?Handle {
        const will = connect.will orelse return null;
        return try self.set(
            connect.client_id,
            will,
            connectSessionExpiry(connect),
        );
    }

    /// Apply ClientID takeover/reconnect semantics and install the new Will.
    ///
    /// If the old Will becomes due, its handle is returned in
    /// `previous_due`; callers should poll, publish, and release it independently
    /// of the new connection's Will.
    pub fn acceptConnect(
        self: *Scheduler,
        connect: mqtt.Connect,
        now: std.Io.Timestamp,
    ) Error!struct {
        previous: CloseResult,
        previous_due: ?Handle,
        current: ?Handle,
    } {
        const previous_index = self.client_index.get(connect.client_id);
        const previous_handle = if (previous_index) |index| blk: {
            const entry = self.entries.items[index].?;
            break :blk Handle{
                .index = index,
                .generation = entry.generation,
            };
        } else null;
        const previous_was_claimed = if (previous_index) |index|
            self.entries.items[index].?.state == .due
        else
            false;
        const previous_preview = if (previous_index) |index|
            self.reconnectResult(index, connect.clean_start, now)
        else
            CloseResult.no_will;

        // Deep-copy and reserve every resource for the new Will before
        // changing the old Session. A malformed or over-limit CONNECT can
        // therefore be rejected without accidentally canceling/publishing the
        // prior Will.
        var prepared: ?Entry = if (connect.will) |message| blk: {
            const final_count = self.count_value +
                @intFromBool(previous_preview != .canceled);
            const final_base_bytes = if (previous_preview == .canceled)
                self.total_bytes -
                    self.entries.items[previous_index.?].?.allocation_bytes
            else
                self.total_bytes;
            break :blk try self.prepare(
                connect.client_id,
                message,
                connectSessionExpiry(connect),
                final_count,
                final_base_bytes,
            );
        } else null;
        errdefer if (prepared) |*entry| entry.deinit(self.allocator);
        if (prepared != null) {
            try self.reserveInstall(
                self.count_value +
                    @intFromBool(previous_preview != .canceled),
                self.free_indices.items.len != 0 or
                    previous_preview == .canceled,
            );
        }

        const previous = self.onReconnect(
            connect.client_id,
            connect.clean_start,
            now,
        );
        std.debug.assert(previous == previous_preview);
        // A Will already returned by pollDue belongs to that polling caller;
        // don't hand the same publication handle to the reconnect path too.
        const previous_due = if (previous == .due_now and !previous_was_claimed)
            previous_handle
        else
            null;
        // A due old Will remains indexed until release. It cannot coexist with
        // the new Will under the same ClientID, so detach its ClientID index
        // while retaining the generation-safe publication handle.
        if (previous == .due_now) {
            const entry = try self.getEntry(previous_handle.?);
            _ = self.client_index.fetchRemove(entry.client_id).?;
        }
        return .{
            .previous = previous,
            .previous_due = previous_due,
            .current = if (prepared) |entry|
                self.installPrepared(entry)
            else
                null,
        };
    }

    /// Handle a new connection using the same ClientID before installing its
    /// new Will.
    ///
    /// Clean Start=0 cancels a delayed Will only while its deadline has not
    /// passed. Clean Start=1 ends the old Session and makes the old Will due.
    pub fn onReconnect(
        self: *Scheduler,
        client_id: []const u8,
        clean_start: bool,
        now: std.Io.Timestamp,
    ) CloseResult {
        const index = self.client_index.get(client_id) orelse
            return .no_will;
        const result = self.reconnectResult(index, clean_start, now);
        if (result == .canceled) {
            self.removeAt(index);
            return result;
        }
        if (self.entries.items[index].?.state != .due) {
            self.makeDueNow(index, now.nanoseconds);
        }
        return result;
    }

    pub fn close(
        self: *Scheduler,
        handle: Handle,
        reason: CloseReason,
        now: std.Io.Timestamp,
    ) Error!CloseResult {
        const entry = try self.getEntry(handle);
        // Once pollDue hands publication to the caller, the Will is committed.
        // Duplicate transport-close signals must not cancel or requeue it.
        if (entry.state == .due) return .due_now;
        // The first Network Connection close fixes the publication deadline.
        // Ignore duplicate transport-close notifications rather than extending
        // the delay or letting a stale normal-close signal cancel the Will.
        if (entry.state == .scheduled and reason != .session_ended) {
            return .scheduled;
        }
        switch (reason) {
            .normal_disconnect => {
                self.removeAt(handle.index);
                return .canceled;
            },
            .session_ended => {
                self.makeDueNow(handle.index, now.nanoseconds);
                return .due_now;
            },
            .disconnect_with_will, .ungraceful => {
                const delay = effectiveDelay(
                    entry.will_delay_interval,
                    entry.session_expiry_interval,
                );
                if (delay == 0) {
                    self.makeDueNow(handle.index, now.nanoseconds);
                    return .due_now;
                }
                entry.state = .scheduled;
                entry.deadline_ns = addSeconds(now.nanoseconds, delay);
                if (entry.heap_index == null) {
                    std.debug.assert(
                        self.heap.count() < self.heap.capacity(),
                    );
                    self.heap.appendAssumeCapacity(self, handle.index);
                } else {
                    self.heap.fix(self, entry.heap_index.?);
                }
                return .scheduled;
            },
        }
    }

    pub fn closeDisconnect(
        self: *Scheduler,
        handle: Handle,
        packet: mqtt.Disconnect,
        now: std.Io.Timestamp,
    ) Error!CloseResult {
        const entry = try self.getEntry(handle);
        if (entry.state == .connected) {
            if (mqtt.sessionExpiryInterval(packet.properties)) |new_expiry| {
                // MQTT-3.14.2-2 forbids increasing a zero CONNECT interval in
                // DISCONNECT. The Session Store enforces the same invariant.
                if (entry.session_expiry_interval == 0 and new_expiry != 0) {
                    return error.InvalidProperty;
                }
                entry.session_expiry_interval = new_expiry;
            }
        }
        return self.close(
            handle,
            if (packet.reason_code == 0)
                .normal_disconnect
            else if (packet.reason_code == 0x04)
                .disconnect_with_will
            else
                .ungraceful,
            now,
        );
    }

    pub fn nextDeadline(self: Scheduler) ?std.Io.Timestamp {
        const entry_index = self.heap.root() orelse return null;
        return .{ .nanoseconds = self.entries.items[entry_index].?.deadline_ns };
    }

    /// Poll due Wills into caller storage. Returned views remain valid until
    /// `releaseDue`, which removes and frees the corresponding Will.
    pub fn pollDue(
        self: *Scheduler,
        now: std.Io.Timestamp,
        out: []Handle,
    ) Error![]Handle {
        const required = self.countDueFrom(0, now.nanoseconds);
        if (out.len < required) return error.DueBufferTooSmall;
        var written: usize = 0;
        while (self.heap.root()) |entry_index| {
            const entry = &self.entries.items[entry_index].?;
            if (entry.deadline_ns > now.nanoseconds) break;
            _ = self.heap.popRoot(self);
            entry.state = .due;
            out[written] = .{
                .index = entry_index,
                .generation = entry.generation,
            };
            written += 1;
        }
        return out[0..written];
    }

    fn countDueFrom(
        self: Scheduler,
        heap_index: usize,
        now_ns: i96,
    ) usize {
        const heap_entries = self.heap.entries();
        if (heap_index >= heap_entries.len) return 0;
        const entry_index = heap_entries[heap_index];
        if (self.entries.items[entry_index].?.deadline_ns > now_ns) {
            // Heap ordering guarantees every descendant is later too. This
            // avoids scanning thousands of future Wills on an idle poll while
            // preserving the all-or-nothing caller-buffer contract.
            return 0;
        }
        return 1 +
            self.countDueFrom(heap_index * 2 + 1, now_ns) +
            self.countDueFrom(heap_index * 2 + 2, now_ns);
    }

    pub fn view(self: *Scheduler, handle: Handle) Error!Due {
        const entry = try self.getEntry(handle);
        return .{
            .client_id = entry.client_id,
            .topic = entry.topic,
            .payload = entry.payload,
            .qos = entry.qos,
            .retain = entry.retain,
            .properties = entry.properties,
            // The Will Message lifetime starts when it is published, so the
            // original interval is forwarded unchanged after Will Delay.
            .message_expiry_interval = entry.message_expiry_interval,
        };
    }

    pub fn releaseDue(self: *Scheduler, handle: Handle) Error!void {
        const entry = try self.getEntry(handle);
        if (entry.state != .due or entry.heap_index != null) {
            return error.WillNotDue;
        }
        self.removeAt(handle.index);
    }

    fn prepare(
        self: *Scheduler,
        client_id: []const u8,
        will: mqtt.LastWill,
        session_expiry_interval: u32,
        final_count: usize,
        final_base_bytes: usize,
    ) Error!Entry {
        try mqtt.validateTopicName(will.topic);
        try validateWillProperties(will.properties, will.payload);
        if (final_count > self.options.max_wills) {
            return error.WillLimitExceeded;
        }

        const client_owned = try self.allocator.dupe(u8, client_id);
        errdefer self.allocator.free(client_owned);
        const topic_owned = try self.allocator.dupe(u8, will.topic);
        errdefer self.allocator.free(topic_owned);
        const payload_owned = try self.allocator.dupe(u8, will.payload);
        errdefer self.allocator.free(payload_owned);
        const property_result = owned_properties.clone(
            self.allocator,
            will.properties,
            owned_properties.keepAll,
        ) catch |err| switch (err) {
            error.OwnedPropertyLimitExceeded => return error.WillByteLimitExceeded,
            else => return @errorCast(err),
        };
        errdefer owned_properties.deinit(
            self.allocator,
            property_result.properties,
        );
        const bytes = std.math.add(
            usize,
            client_owned.len + topic_owned.len + payload_owned.len,
            property_result.allocation_bytes,
        ) catch return error.WillByteLimitExceeded;
        if (bytes > self.options.max_will_bytes or
            bytes > self.options.max_total_bytes -| final_base_bytes)
        {
            return error.WillByteLimitExceeded;
        }

        return .{
            // Generation is assigned only after every installation resource
            // has been reserved and the entry can be committed.
            .generation = 0,
            .client_id = client_owned,
            .topic = topic_owned,
            .payload = payload_owned,
            .qos = will.qos,
            .retain = will.retain,
            .properties = property_result.properties,
            .will_delay_interval = mqtt.willDelayInterval(will.properties) orelse 0,
            .message_expiry_interval = mqtt.messageExpiryInterval(will.properties),
            .session_expiry_interval = session_expiry_interval,
            .allocation_bytes = bytes,
        };
    }

    fn reserveInstall(
        self: *Scheduler,
        final_count: usize,
        reuses_slot: bool,
    ) Error!void {
        if (final_count > self.options.max_wills) {
            return error.WillLimitExceeded;
        }
        try self.client_index.ensureUnusedCapacity(self.allocator, 1);
        // One heap position per owned Will makes every close/reconnect/Session
        // transition allocation-free after CONNECT is accepted.
        try self.heap.ensureTotalCapacity(self.allocator, final_count);
        if (!reuses_slot) {
            try self.entries.ensureUnusedCapacity(self.allocator, 1);
        }
        // Returning any live slot must also remain allocation-free.
        try self.free_indices.ensureTotalCapacity(
            self.allocator,
            self.entries.items.len + @intFromBool(!reuses_slot),
        );
    }

    fn installPrepared(self: *Scheduler, prepared: Entry) Handle {
        var entry = prepared;
        entry.generation = self.nextGeneration();
        const index = self.free_indices.pop() orelse blk: {
            self.entries.appendAssumeCapacity(null);
            break :blk self.entries.items.len - 1;
        };
        std.debug.assert(self.entries.items[index] == null);
        self.entries.items[index] = entry;
        self.client_index.putAssumeCapacityNoClobber(
            self.entries.items[index].?.client_id,
            index,
        );
        self.count_value += 1;
        self.total_bytes += entry.allocation_bytes;
        return .{ .index = index, .generation = entry.generation };
    }

    fn reconnectResult(
        self: *Scheduler,
        index: usize,
        clean_start: bool,
        now: std.Io.Timestamp,
    ) CloseResult {
        if (clean_start) return .due_now;
        const entry = self.entries.items[index].?;
        const delay = effectiveDelay(
            entry.will_delay_interval,
            entry.session_expiry_interval,
        );
        const reconnects_before_will = switch (entry.state) {
            // The broker closes the old connection as part of takeover. A
            // positive effective delay lets the new Network Connection
            // continue the same Session before the old Will becomes due.
            .connected => delay != 0,
            .scheduled => now.nanoseconds < entry.deadline_ns,
            .due => false,
        };
        return if (reconnects_before_will) .canceled else .due_now;
    }

    fn getEntry(self: *Scheduler, handle: Handle) Error!*Entry {
        if (handle.index >= self.entries.items.len) {
            return error.WillNotFound;
        }
        const entry = &(self.entries.items[handle.index] orelse
            return error.WillNotFound);
        if (entry.generation != handle.generation) {
            return error.WillNotFound;
        }
        return entry;
    }

    fn makeDueNow(
        self: *Scheduler,
        entry_index: usize,
        now_ns: i96,
    ) void {
        const entry = &self.entries.items[entry_index].?;
        if (entry.heap_index) |heap_index| {
            _ = self.heap.remove(self, heap_index);
        }
        entry.state = .scheduled;
        entry.deadline_ns = now_ns;
        // `set` reserves one heap slot per accepted Will, so lifecycle events
        // never allocate after CONNECT has succeeded.
        std.debug.assert(self.heap.count() < self.heap.capacity());
        self.heap.appendAssumeCapacity(self, entry_index);
    }

    fn removeAt(self: *Scheduler, index: usize) void {
        var entry = self.entries.items[index].?;
        if (entry.heap_index) |heap_index| {
            _ = self.heap.remove(self, heap_index);
        }
        if (self.client_index.get(entry.client_id)) |mapped_index| {
            if (mapped_index == index) {
                _ = self.client_index.fetchRemove(entry.client_id).?;
            }
        }
        self.entries.items[index] = null;
        self.count_value -= 1;
        self.total_bytes -= entry.allocation_bytes;
        entry.deinit(self.allocator);
        std.debug.assert(
            self.free_indices.items.len < self.free_indices.capacity,
        );
        self.free_indices.appendAssumeCapacity(index);
    }

    fn nextGeneration(self: *Scheduler) u64 {
        const generation = self.next_generation;
        self.next_generation +%= 1;
        if (self.next_generation == 0) self.next_generation = 1;
        return generation;
    }
};

fn lessEntry(
    scheduler: *Scheduler,
    a_index: usize,
    b_index: usize,
) bool {
    const a_entry = scheduler.entries.items[a_index].?;
    const b_entry = scheduler.entries.items[b_index].?;
    if (a_entry.deadline_ns != b_entry.deadline_ns) {
        return a_entry.deadline_ns < b_entry.deadline_ns;
    }
    return a_entry.generation < b_entry.generation;
}

fn setHeapPosition(
    scheduler: *Scheduler,
    entry_index: usize,
    position: ?usize,
) void {
    scheduler.entries.items[entry_index].?.heap_index = position;
}

fn validateWillProperties(
    properties: []const mqtt.Property,
    payload: []const u8,
) Error!void {
    return mqtt.validateWillProperties(properties, payload);
}

fn connectSessionExpiry(connect: mqtt.Connect) u32 {
    return switch (connect.protocol) {
        .v5 => mqtt.sessionExpiryInterval(connect.properties) orelse 0,
        .v3_1_1 => if (connect.clean_start)
            0
        else
            std.math.maxInt(u32),
    };
}

fn effectiveDelay(will_delay: u32, session_expiry: u32) u32 {
    return @min(will_delay, session_expiry);
}

fn addSeconds(now_ns: i96, seconds: u32) i96 {
    const duration = @as(i96, seconds) * std.time.ns_per_s;
    return std.math.add(i96, now_ns, duration) catch std.math.maxInt(i96);
}

test {
    _ = @import("tests.zig");
}
