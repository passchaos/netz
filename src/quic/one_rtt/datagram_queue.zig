const std = @import("std");

pub const Queue = struct {
    pub const Entry = struct {
        payload: []u8,
        packet_number: u64,
    };

    slots: std.ArrayList(?Entry) = .empty,
    head: usize = 0,
    len: usize = 0,
    payload_bytes: usize = 0,
    recycled_payloads: std.ArrayList([]u8) = .empty,

    pub const PushResult = struct {
        accepted: bool,
        dropped: usize,
    };

    pub fn deinit(self: *Queue, allocator: std.mem.Allocator) void {
        for (self.slots.items) |maybe_entry| {
            if (maybe_entry) |entry| allocator.free(entry.payload);
        }
        for (self.recycled_payloads.items) |payload| allocator.free(payload);
        self.recycled_payloads.deinit(allocator);
        self.slots.deinit(allocator);
        self.* = undefined;
    }

    pub fn count(self: Queue) usize {
        return self.len;
    }

    pub fn payloadByteCount(self: Queue) usize {
        return self.payload_bytes;
    }

    /// Insert an already-owned payload. On allocation failure the queue is
    /// unchanged and ownership remains with the caller. When full, ownership
    /// of the returned oldest payload transfers back to the caller.
    pub fn pushDroppingOldest(
        self: *Queue,
        allocator: std.mem.Allocator,
        payload: []u8,
        packet_number: u64,
        capacity: usize,
    ) std.mem.Allocator.Error!?[]u8 {
        std.debug.assert(capacity > 0);
        std.debug.assert(self.len <= capacity);

        if (self.len < capacity) {
            // Allocate the configured ring exactly on first admission. This
            // avoids ArrayList's geometric slack and makes every subsequent
            // insert/overwrite allocation-free for the lifetime of the queue.
            if (self.slots.capacity < capacity) {
                try self.slots.ensureTotalCapacityPrecise(
                    allocator,
                    capacity,
                );
            }
            if (self.recycled_payloads.capacity < capacity) {
                try self.recycled_payloads.ensureTotalCapacityPrecise(
                    allocator,
                    capacity,
                );
            }
            if (self.recycled_payloads.items.len > capacity - self.len - 1) {
                allocator.free(self.recycled_payloads.pop().?);
            }
            const tail = if (self.slots.items.len == 0)
                0
            else
                (self.head + self.len) % capacity;
            if (tail < self.slots.items.len) {
                std.debug.assert(self.slots.items[tail] == null);
                self.slots.items[tail] = .{
                    .payload = payload,
                    .packet_number = packet_number,
                };
            } else {
                std.debug.assert(tail == self.slots.items.len);
                try self.slots.append(allocator, .{
                    .payload = payload,
                    .packet_number = packet_number,
                });
            }
            self.len += 1;
            self.payload_bytes += payload.len;
            return null;
        }

        const dropped = self.slots.items[self.head].?.payload;
        self.slots.items[self.head] = .{
            .payload = payload,
            .packet_number = packet_number,
        };
        self.head = (self.head + 1) % self.slots.items.len;
        self.payload_bytes -= dropped.len;
        self.payload_bytes += payload.len;
        return dropped;
    }

    /// Copy a borrowed payload into queue-owned storage. After application
    /// pops, up to the configured queue capacity of exact-size allocations is
    /// retained for later admissions. The queue ordering and drop-oldest
    /// semantics match `pushDroppingOldest`.
    pub fn pushCopyDroppingOldest(
        self: *Queue,
        allocator: std.mem.Allocator,
        payload: []const u8,
        packet_number: u64,
        capacity: usize,
    ) std.mem.Allocator.Error!bool {
        std.debug.assert(capacity > 0);
        std.debug.assert(self.len <= capacity);

        // Reserve queue metadata before taking or allocating payload storage,
        // so OOM leaves ownership and queue state unchanged.
        if (self.len < capacity and self.slots.capacity < capacity) {
            try self.slots.ensureTotalCapacityPrecise(allocator, capacity);
        }
        if (self.len == capacity) {
            const oldest = &self.slots.items[self.head].?;
            // A full fixed-size queue can replace its oldest payload in the
            // slot that is becoming the new tail. Besides avoiding allocator
            // traffic on the first overflow, this keeps retained payload
            // storage at the configured queue bound instead of bound + 1.
            if (oldest.payload.len == payload.len) {
                @memcpy(oldest.payload, payload);
                oldest.packet_number = packet_number;
                self.head = (self.head + 1) % self.slots.items.len;
                return true;
            }
        }
        const owned = blk: {
            for (self.recycled_payloads.items, 0..) |recycled, index| {
                if (recycled.len == payload.len) {
                    const reused = self.recycled_payloads.swapRemove(index);
                    @memcpy(reused, payload);
                    break :blk reused;
                }
            }
            const fresh = try allocator.dupe(u8, payload);
            if (self.recycled_payloads.pop()) |stale| allocator.free(stale);
            break :blk fresh;
        };
        var owns_payload = true;
        errdefer if (owns_payload) allocator.free(owned);
        const dropped = try self.pushDroppingOldest(
            allocator,
            owned,
            packet_number,
            capacity,
        );
        owns_payload = false;
        const did_drop = dropped != null;
        if (dropped) |oldest| self.recycleOrFree(allocator, oldest);
        return did_drop;
    }

    /// Copy one borrowed payload while bounding both logical entries and their
    /// queued payload bytes. Oldest entries are discarded until both limits
    /// admit the new payload. A payload larger than the byte budget is dropped
    /// without disturbing already queued data.
    ///
    /// All fallible metadata/storage acquisition completes before FIFO state
    /// changes. When an evicted exact-size allocation exists, replacement is
    /// allocation-free just like the fixed-count full-queue fast path.
    pub fn pushCopyWithinLimits(
        self: *Queue,
        allocator: std.mem.Allocator,
        payload: []const u8,
        packet_number: u64,
        max_items: usize,
        max_bytes: usize,
    ) std.mem.Allocator.Error!PushResult {
        if (max_items == 0 or max_bytes == 0 or payload.len > max_bytes) {
            return .{ .accepted = false, .dropped = 1 };
        }

        var remaining_items = self.len;
        var remaining_bytes = self.payload_bytes;
        var drop_count: usize = 0;
        while (remaining_items >= max_items or
            remaining_bytes > max_bytes - payload.len)
        {
            const index = (self.head + drop_count) % self.slots.items.len;
            const entry = self.slots.items[index].?;
            remaining_items -= 1;
            remaining_bytes -= entry.payload.len;
            drop_count += 1;
        }

        if (self.slots.capacity < max_items) {
            try self.slots.ensureTotalCapacityPrecise(allocator, max_items);
        }
        if (self.recycled_payloads.capacity < max_items) {
            try self.recycled_payloads.ensureTotalCapacityPrecise(
                allocator,
                max_items,
            );
        }

        var reused_queue_payload: ?[]u8 = null;
        for (0..drop_count) |logical| {
            const index = (self.head + logical) % self.slots.items.len;
            const candidate = self.slots.items[index].?.payload;
            if (candidate.len == payload.len) {
                reused_queue_payload = candidate;
                break;
            }
        }
        const owned: []u8 = if (reused_queue_payload) |candidate|
            candidate
        else recycle: {
            for (self.recycled_payloads.items, 0..) |candidate, index| {
                if (candidate.len != payload.len) continue;
                break :recycle self.recycled_payloads.swapRemove(index);
            }
            const fresh = try allocator.dupe(u8, payload);
            if (self.recycled_payloads.pop()) |stale| allocator.free(stale);
            break :recycle fresh;
        };
        var owns_payload = reused_queue_payload == null;
        errdefer if (owns_payload) allocator.free(owned);
        @memcpy(owned, payload);

        for (0..drop_count) |_| {
            const dropped = self.popEntry().?;
            if (reused_queue_payload != null and
                dropped.payload.ptr == reused_queue_payload.?.ptr)
            {
                reused_queue_payload = null;
                owns_payload = true;
            } else {
                self.recycleOrFree(allocator, dropped.payload);
            }
        }
        const unexpected_drop = self.pushDroppingOldest(
            allocator,
            owned,
            packet_number,
            max_items,
        ) catch unreachable;
        std.debug.assert(unexpected_drop == null);
        owns_payload = false;
        std.debug.assert(self.payload_bytes <= max_bytes);
        return .{ .accepted = true, .dropped = drop_count };
    }

    pub fn pop(self: *Queue) ?[]u8 {
        return if (self.popEntry()) |entry| entry.payload else null;
    }

    fn popEntry(self: *Queue) ?Entry {
        if (self.len == 0) return null;
        const entry = self.slots.items[self.head].?;
        self.slots.items[self.head] = null;
        self.len -= 1;
        self.payload_bytes -= entry.payload.len;
        if (self.len == 0) {
            self.head = 0;
        } else {
            self.head = (self.head + 1) % self.slots.items.len;
        }
        return entry;
    }

    /// Copy the oldest payload into caller storage and retain its allocation
    /// for a later exact-size admission. A short output buffer preserves the
    /// existing consume-on-error behavior while still recycling storage.
    pub fn popInto(
        self: *Queue,
        allocator: std.mem.Allocator,
        out: []u8,
    ) error{BufferTooSmall}!?[]u8 {
        const payload = self.pop() orelse return null;
        defer self.recycleOrFree(allocator, payload);
        if (payload.len > out.len) return error.BufferTooSmall;
        @memcpy(out[0..payload.len], payload);
        return out[0..payload.len];
    }

    pub fn countPacket(self: Queue, packet_number: u64) usize {
        var matches: usize = 0;
        for (0..self.len) |logical| {
            const index = (self.head + logical) % self.slots.items.len;
            matches += @intFromBool(
                self.slots.items[index].?.packet_number == packet_number,
            );
        }
        return matches;
    }

    pub fn storageCapacity(self: Queue) usize {
        return self.slots.capacity;
    }

    pub fn discardPacket(
        self: *Queue,
        allocator: std.mem.Allocator,
        packet_number: u64,
    ) usize {
        const original_len = self.len;
        var kept: usize = 0;
        var discarded: usize = 0;
        for (0..original_len) |logical| {
            const source = (self.head + logical) % self.slots.items.len;
            const entry = self.slots.items[source].?;
            if (entry.packet_number == packet_number) {
                self.payload_bytes -= entry.payload.len;
                allocator.free(entry.payload);
                self.slots.items[source] = null;
                discarded += 1;
                continue;
            }
            const target = (self.head + kept) % self.slots.items.len;
            if (target != source) {
                std.debug.assert(self.slots.items[target] == null);
                self.slots.items[target] = entry;
                self.slots.items[source] = null;
            }
            kept += 1;
        }
        self.len = kept;
        if (kept == 0) self.head = 0;
        return discarded;
    }

    fn recycleOrFree(
        self: *Queue,
        allocator: std.mem.Allocator,
        payload: []u8,
    ) void {
        if (self.recycled_payloads.items.len <
            self.slots.capacity - self.len)
        {
            self.recycled_payloads.appendAssumeCapacity(payload);
        } else {
            allocator.free(payload);
        }
    }
};
