const std = @import("std");

pub const Queue = struct {
    pub const Entry = struct {
        payload: []u8,
        packet_number: u64,
    };

    slots: std.ArrayList(?Entry) = .empty,
    head: usize = 0,
    len: usize = 0,

    pub fn deinit(self: *Queue, allocator: std.mem.Allocator) void {
        for (self.slots.items) |maybe_entry| {
            if (maybe_entry) |entry| allocator.free(entry.payload);
        }
        self.slots.deinit(allocator);
        self.* = undefined;
    }

    pub fn count(self: Queue) usize {
        return self.len;
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
            return null;
        }

        const dropped = self.slots.items[self.head].?.payload;
        self.slots.items[self.head] = .{
            .payload = payload,
            .packet_number = packet_number,
        };
        self.head = (self.head + 1) % self.slots.items.len;
        return dropped;
    }

    pub fn pop(self: *Queue) ?[]u8 {
        if (self.len == 0) return null;
        const payload = self.slots.items[self.head].?.payload;
        self.slots.items[self.head] = null;
        self.len -= 1;
        if (self.len == 0) {
            self.head = 0;
        } else {
            self.head = (self.head + 1) % self.slots.items.len;
        }
        return payload;
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
};
