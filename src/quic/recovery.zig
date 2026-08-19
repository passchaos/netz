const std = @import("std");
const quic = @import("mod.zig");
const payload_cache = @import("recovery/payload_cache.zig");

/// Minimal recovery state for a single QUIC packet number space.
///
/// The queue stores already encoded frame payloads instead of `quic.Frame`
/// values.  Several frame variants carry slices into caller-owned buffers, so
/// keeping encoded bytes gives retransmission stable ownership and lets the
/// caller seal the same frames under a fresh packet number for PTO.
pub const Error = error{
    EmptyPayload,
    InvalidAckFrame,
    InvalidRetransmission,
} || std.mem.Allocator.Error;

pub const Candidate = struct {
    /// Index into `Queue.pending`.  The caller must pass this back to
    /// `recordRetransmission` after the bytes have been successfully sent.
    group_index: usize,
    /// The newest packet number carrying this encoded frame payload.
    packet_number: u64,
    /// Encoded QUIC frame bytes.  These bytes are ready to become the payload of
    /// a fresh protected 1-RTT packet; retransmission must use a new packet
    /// number, but the frame encoding itself is intentionally stable.
    payload: []const u8,
    retransmission_count: usize,
};

pub const QueueStats = struct {
    pending_groups: usize,
    packet_number_copies: usize,
    retransmission_copies: usize,
    payload_bytes: usize,
    cached_payload_blocks: usize,
    cached_payload_bytes: usize,
    payload_cache_hits: u64,
    payload_cache_misses: u64,
};

const PendingDatagram = struct {
    group_id: u64,
    /// Almost every payload is acknowledged without retransmission. Keep its
    /// original packet number inline so the common case does not allocate a
    /// one-element ArrayList; only actual retransmissions grow dynamic storage.
    original_packet_number: ?u64,
    retransmission_packet_numbers: std.ArrayList(u64) = .empty,
    newest_packet_number: u64,
    /// Owning allocation may be a power-of-two cache bucket larger than the
    /// encoded frame payload. Keep the logical length separate so candidates
    /// never retransmit uninitialized bucket slack and allocator.free always
    /// receives the original allocation size.
    payload_storage: []u8,
    payload_len: usize,

    fn initOwned(
        group_id: u64,
        packet_number: u64,
        payload_storage: []u8,
        payload_len: usize,
    ) PendingDatagram {
        std.debug.assert(payload_len != 0);
        std.debug.assert(payload_len <= payload_storage.len);
        return .{
            .group_id = group_id,
            .original_packet_number = packet_number,
            .newest_packet_number = packet_number,
            .payload_storage = payload_storage,
            .payload_len = payload_len,
        };
    }

    fn deinit(self: *PendingDatagram, allocator: std.mem.Allocator) void {
        self.retransmission_packet_numbers.deinit(allocator);
        allocator.free(self.payload_storage);
        self.* = undefined;
    }

    fn payload(self: PendingDatagram) []const u8 {
        return self.payload_storage[0..self.payload_len];
    }

    fn newestPacketNumber(self: PendingDatagram) u64 {
        return self.newest_packet_number;
    }

    fn refreshNewestPacketNumber(self: *PendingDatagram) void {
        if (self.retransmission_packet_numbers.items.len != 0) {
            self.newest_packet_number = self.retransmission_packet_numbers.items[
                self.retransmission_packet_numbers.items.len - 1
            ];
            return;
        }
        if (self.original_packet_number) |packet_number| {
            self.newest_packet_number = packet_number;
        }
    }

    fn containsRange(self: PendingDatagram, start: u64, end: u64) bool {
        if (self.original_packet_number) |packet_number| {
            if (packet_number >= start and packet_number <= end) return true;
        }
        for (self.retransmission_packet_numbers.items) |packet_number| {
            if (packet_number >= start and packet_number <= end) return true;
        }
        return false;
    }

    pub fn packetCount(self: PendingDatagram) usize {
        return @intFromBool(self.original_packet_number != null) + self.retransmission_packet_numbers.items.len;
    }

    pub fn packetNumberAt(self: PendingDatagram, index: usize) ?u64 {
        if (self.original_packet_number) |packet_number| {
            if (index == 0) return packet_number;
            const retransmission_index = index - 1;
            if (retransmission_index < self.retransmission_packet_numbers.items.len) {
                return self.retransmission_packet_numbers.items[retransmission_index];
            }
            return null;
        }
        if (index < self.retransmission_packet_numbers.items.len) {
            return self.retransmission_packet_numbers.items[index];
        }
        return null;
    }
};

pub const Queue = struct {
    allocator: std.mem.Allocator,
    pending: std.ArrayList(PendingDatagram) = .empty,
    /// Stable payload groups are stored in `pending` so PTO scheduling can keep
    /// FIFO order, but ACK/loss paths usually start from a packet number or
    /// group id.  These indexes make those hot lookups O(1); any operation that
    /// shifts `pending` must refresh the affected physical slots.
    group_index: std.AutoHashMapUnmanaged(u64, usize) = .empty,
    packet_index: std.AutoHashMapUnmanaged(u64, usize) = .empty,
    /// Cached aggregate counters for recovery observability.  `stats()` is
    /// commonly polled alongside qlog/congestion snapshots; keep it O(1)
    /// instead of walking every pending payload and retransmission copy.
    packet_number_copies: usize = 0,
    retransmission_copies: usize = 0,
    payload_bytes: usize = 0,
    next_group_id: u64 = 0,
    payload_cache: payload_cache.Cache,

    pub fn init(allocator: std.mem.Allocator) Queue {
        return .{
            .allocator = allocator,
            .payload_cache = .init(allocator),
        };
    }

    pub fn deinit(self: *Queue) void {
        for (self.pending.items) |*entry| entry.deinit(self.allocator);
        self.payload_cache.deinit();
        self.pending.deinit(self.allocator);
        self.group_index.deinit(self.allocator);
        self.packet_index.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn pendingCount(self: *const Queue) usize {
        return self.pending.items.len;
    }

    pub fn stats(self: *const Queue) QueueStats {
        const cache_stats = self.payload_cache.stats();
        return .{
            .pending_groups = self.pending.items.len,
            .packet_number_copies = self.packet_number_copies,
            .retransmission_copies = self.retransmission_copies,
            .payload_bytes = self.payload_bytes,
            .cached_payload_blocks = cache_stats.blocks,
            .cached_payload_bytes = cache_stats.bytes,
            .payload_cache_hits = cache_stats.hits,
            .payload_cache_misses = cache_stats.misses,
        };
    }

    pub fn getStats(self: *const Queue) QueueStats {
        return self.stats();
    }

    pub fn trackSent(
        self: *Queue,
        packet_number: u64,
        payload: []const u8,
    ) Error!u64 {
        if (payload.len == 0) return error.EmptyPayload;
        const packet_slot = try self.packet_index.getOrPut(
            self.allocator,
            packet_number,
        );
        if (packet_slot.found_existing) return error.InvalidRetransmission;
        errdefer _ = self.packet_index.remove(packet_number);

        const group_id = self.next_group_id;
        const next_group_id = std.math.add(
            u64,
            group_id,
            1,
        ) catch return error.InvalidRetransmission;
        const group_slot = try self.group_index.getOrPut(
            self.allocator,
            group_id,
        );
        std.debug.assert(!group_slot.found_existing);
        errdefer _ = self.group_index.remove(group_id);

        try self.pending.ensureUnusedCapacity(self.allocator, 1);
        const payload_storage = self.payload_cache.acquire(
            payload.len,
        ) catch return error.OutOfMemory;
        errdefer self.payload_cache.release(payload_storage);
        @memcpy(payload_storage[0..payload.len], payload);
        const entry = PendingDatagram.initOwned(
            group_id,
            packet_number,
            payload_storage,
            payload.len,
        );
        self.appendGroupAssumeCapacity(
            entry,
            group_slot.value_ptr,
            packet_slot.value_ptr,
        );
        self.next_group_id = next_group_id;
        return group_id;
    }

    pub fn groupIdForPacketNumber(
        self: *const Queue,
        packet_number: u64,
    ) ?u64 {
        if (self.packet_index.count() == 0) return null;
        const index = self.packet_index.get(packet_number) orelse return null;
        return self.pending.items[index].group_id;
    }

    pub fn containsGroupId(self: *const Queue, group_id: u64) bool {
        return self.group_index.count() != 0 and
            self.group_index.contains(group_id);
    }

    pub fn ptoCandidate(self: *const Queue) ?Candidate {
        return self.ptoCandidateAt(0);
    }

    pub fn ptoCandidateAt(self: *const Queue, group_index: usize) ?Candidate {
        if (group_index >= self.pending.items.len) return null;
        const entry = self.pending.items[group_index];
        return .{
            .group_index = group_index,
            .packet_number = entry.newestPacketNumber(),
            .payload = entry.payload(),
            .retransmission_count = entry.retransmission_packet_numbers.items.len,
        };
    }

    pub fn packetThresholdCandidate(self: *const Queue, largest_acknowledged: u64, packet_threshold: u64) ?Candidate {
        if (packet_threshold == 0 or largest_acknowledged < packet_threshold) return null;
        const largest_lost = largest_acknowledged - packet_threshold;
        for (self.pending.items, 0..) |entry, group_index| {
            // tquic/quic-zig both apply RFC 9002's packet threshold to sent
            // packets whenever an ACK advances the largest acknowledged packet.
            // This queue groups retransmissions of the same encoded payload, so
            // only the newest copy is used for scheduling; older lost packet
            // numbers remain in the group so an ACK for any copy still retires
            // the payload without a second retransmission storm.
            if (entry.newestPacketNumber() > largest_lost) continue;
            return .{
                .group_index = group_index,
                .packet_number = entry.newestPacketNumber(),
                .payload = entry.payload(),
                .retransmission_count = entry.retransmission_packet_numbers.items.len,
            };
        }
        return null;
    }

    pub fn packetNumberCandidate(self: *const Queue, packet_number: u64) ?Candidate {
        if (self.packet_index.count() == 0) return null;
        const group_index = self.packet_index.get(packet_number) orelse return null;
        const entry = self.pending.items[group_index];
        return .{
            .group_index = group_index,
            .packet_number = entry.newestPacketNumber(),
            .payload = entry.payload(),
            .retransmission_count = entry.retransmission_packet_numbers.items.len,
        };
    }

    pub fn recordRetransmission(self: *Queue, group_index: usize, packet_number: u64) Error!void {
        if (group_index >= self.pending.items.len) return error.InvalidRetransmission;
        const packet_slot = try self.packet_index.getOrPut(
            self.allocator,
            packet_number,
        );
        if (packet_slot.found_existing) return error.InvalidRetransmission;
        errdefer _ = self.packet_index.remove(packet_number);

        const entry = &self.pending.items[group_index];
        try entry.retransmission_packet_numbers.append(self.allocator, packet_number);
        entry.newest_packet_number = packet_number;
        packet_slot.value_ptr.* = group_index;
        self.packet_number_copies += 1;
        self.retransmission_copies += 1;
    }

    pub fn acknowledgePacketNumber(self: *Queue, packet_number: u64) bool {
        if (self.packet_index.count() == 0) return false;
        const index = self.packet_index.get(packet_number) orelse return false;
        var removed = self.removeGroupOrdered(index);
        self.recycleEntry(&removed);
        return true;
    }

    pub fn forgetPacketNumber(self: *Queue, packet_number: u64) bool {
        if (self.packet_index.count() == 0) return false;
        const group_index = self.packet_index.get(packet_number) orelse return false;
        if (self.pending.items[group_index].packetCount() == 1) {
            var removed = self.removeGroupOrdered(group_index);
            self.recycleEntry(&removed);
            return true;
        }

        var entry = &self.pending.items[group_index];
        if (entry.original_packet_number == packet_number) {
            entry.original_packet_number = null;
            _ = self.packet_index.remove(packet_number);
            self.packet_number_copies -|= 1;
            return true;
        }
        for (entry.retransmission_packet_numbers.items, 0..) |candidate, retransmission_index| {
            if (candidate != packet_number) continue;
            if (retransmission_index == entry.retransmission_packet_numbers.items.len - 1) {
                _ = entry.retransmission_packet_numbers.pop();
                entry.refreshNewestPacketNumber();
            } else {
                // Retransmission packet numbers only need membership for ACK
                // retirement and the newest copy for PTO scheduling. Preserve
                // newest_packet_number and avoid orderedRemove's memmove when
                // forgetting an older middle copy.
                const last = entry.retransmission_packet_numbers.pop().?;
                entry.retransmission_packet_numbers.items[retransmission_index] = last;
            }
            _ = self.packet_index.remove(packet_number);
            self.packet_number_copies -|= 1;
            self.retransmission_copies -|= 1;
            return true;
        }
        unreachable;
    }

    pub fn applyAck(self: *Queue, ack: quic.AckFrame) Error!usize {
        if (ack.largest_acknowledged < ack.first_ack_range) return error.InvalidAckFrame;
        // Validate the entire descending range chain before mutating recovery
        // ownership. This preserves transactional rejection without building
        // a temporary decoded-range array.
        var smallest = ack.largest_acknowledged - ack.first_ack_range;
        for (ack.ranges) |range| {
            const skipped = std.math.add(u64, range.gap, 2) catch
                return error.InvalidAckFrame;
            if (smallest < skipped) return error.InvalidAckFrame;
            const range_end = smallest - skipped;
            if (range_end < range.ack_range_length) {
                return error.InvalidAckFrame;
            }
            smallest = range_end - range.ack_range_length;
        }
        return self.retainUnacknowledgedAck(ack);
    }

    fn retainUnacknowledgedAck(self: *Queue, ack: quic.AckFrame) usize {
        var write_index: usize = 0;
        var removed: usize = 0;
        for (self.pending.items, 0..) |entry, read_index| {
            if (entryAcked(entry, ack)) {
                var removed_entry = entry;
                self.removeEntryStats(removed_entry);
                self.recycleEntry(&removed_entry);
                removed += 1;
                continue;
            }
            if (write_index != read_index) {
                self.pending.items[write_index] = entry;
            }
            write_index += 1;
        }
        if (removed == 0) return 0;
        self.pending.items.len = write_index;
        self.rebuildIndexesAssumeCapacity();
        return removed;
    }

    fn entryAcked(
        entry: PendingDatagram,
        ack: quic.AckFrame,
    ) bool {
        var end = ack.largest_acknowledged;
        var start = end - ack.first_ack_range;
        if (entry.containsRange(start, end)) return true;
        for (ack.ranges) |range| {
            end = start - (range.gap + 2);
            start = end - range.ack_range_length;
            if (entry.containsRange(start, end)) return true;
        }
        return false;
    }

    fn appendGroupAssumeCapacity(
        self: *Queue,
        entry: PendingDatagram,
        group_slot: *usize,
        original_packet_slot: *usize,
    ) void {
        const index = self.pending.items.len;
        self.pending.appendAssumeCapacity(entry);
        group_slot.* = index;
        original_packet_slot.* = index;
        self.addEntryStats(entry);
    }

    fn removeGroupOrdered(self: *Queue, index: usize) PendingDatagram {
        const removed = if (index == self.pending.items.len - 1)
            self.pending.pop().?
        else
            self.pending.orderedRemove(index);
        self.removeEntryIndexes(removed);
        self.removeEntryStats(removed);
        if (index < self.pending.items.len) {
            self.refreshIndexesFrom(index);
        }
        return removed;
    }

    fn addEntryStats(self: *Queue, entry: PendingDatagram) void {
        self.packet_number_copies += entry.packetCount();
        self.retransmission_copies += entry.retransmission_packet_numbers.items.len;
        self.payload_bytes += entry.payload_len;
    }

    fn removeEntryStats(self: *Queue, entry: PendingDatagram) void {
        self.packet_number_copies -|= entry.packetCount();
        self.retransmission_copies -|= entry.retransmission_packet_numbers.items.len;
        self.payload_bytes -|= entry.payload_len;
    }

    fn recycleEntry(self: *Queue, entry: *PendingDatagram) void {
        entry.retransmission_packet_numbers.deinit(self.allocator);
        self.payload_cache.release(entry.payload_storage);
        entry.* = undefined;
    }

    fn removeEntryIndexes(self: *Queue, entry: PendingDatagram) void {
        _ = self.group_index.remove(entry.group_id);
        if (entry.original_packet_number) |packet_number| {
            _ = self.packet_index.remove(packet_number);
        }
        for (entry.retransmission_packet_numbers.items) |packet_number| {
            _ = self.packet_index.remove(packet_number);
        }
    }

    fn refreshIndexesFrom(self: *Queue, start: usize) void {
        var index = start;
        while (index < self.pending.items.len) : (index += 1) {
            self.refreshEntryIndex(index);
        }
    }

    fn refreshEntryIndex(self: *Queue, index: usize) void {
        const entry = self.pending.items[index];
        self.group_index.getPtr(entry.group_id).?.* = index;
        if (entry.original_packet_number) |packet_number| {
            self.packet_index.getPtr(packet_number).?.* = index;
        }
        for (entry.retransmission_packet_numbers.items) |packet_number| {
            self.packet_index.getPtr(packet_number).?.* = index;
        }
    }

    fn rebuildIndexesAssumeCapacity(self: *Queue) void {
        self.group_index.clearRetainingCapacity();
        self.packet_index.clearRetainingCapacity();
        for (self.pending.items, 0..) |entry, index| {
            self.group_index.putAssumeCapacityNoClobber(entry.group_id, index);
            if (entry.original_packet_number) |packet_number| {
                self.packet_index.putAssumeCapacityNoClobber(packet_number, index);
            }
            for (entry.retransmission_packet_numbers.items) |packet_number| {
                self.packet_index.putAssumeCapacityNoClobber(packet_number, index);
            }
        }
    }
};

test "QUIC recovery queue groups retransmissions and ACKs any copy" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    _ = try queue.trackSent(0, "stream frame bytes");
    const candidate = queue.ptoCandidate().?;
    try std.testing.expectEqual(@as(u64, 0), candidate.packet_number);
    try std.testing.expectEqualStrings("stream frame bytes", candidate.payload);

    try queue.recordRetransmission(candidate.group_index, 4);
    try std.testing.expectEqual(@as(usize, 1), queue.pendingCount());
    try std.testing.expectEqual(@as(usize, 2), queue.pending.items[0].packetCount());
    try std.testing.expectEqual(@as(usize, 1), queue.group_index.count());
    try std.testing.expectEqual(@as(usize, 2), queue.packet_index.count());
    try std.testing.expectEqual(@as(?usize, 0), queue.packet_index.get(0));
    try std.testing.expectEqual(@as(?usize, 0), queue.packet_index.get(4));
    const stats = queue.stats();
    try std.testing.expectEqual(@as(usize, 1), stats.pending_groups);
    try std.testing.expectEqual(@as(usize, 2), stats.packet_number_copies);
    try std.testing.expectEqual(@as(usize, 1), stats.retransmission_copies);
    try std.testing.expectEqual("stream frame bytes".len, stats.payload_bytes);

    const ack = quic.AckFrame{
        .largest_acknowledged = 4,
        .ack_delay = 0,
        .first_ack_range = 0,
    };
    try std.testing.expectEqual(@as(usize, 1), try queue.applyAck(ack));
    try std.testing.expectEqual(@as(usize, 0), queue.getStats().pending_groups);
    try std.testing.expectEqual(@as(usize, 0), queue.pendingCount());
    try std.testing.expectEqual(@as(usize, 0), queue.group_index.count());
    try std.testing.expectEqual(@as(usize, 0), queue.packet_index.count());
    const empty_stats = queue.stats();
    try std.testing.expectEqual(@as(usize, 0), empty_stats.packet_number_copies);
    try std.testing.expectEqual(@as(usize, 0), empty_stats.retransmission_copies);
    try std.testing.expectEqual(@as(usize, 0), empty_stats.payload_bytes);
    try std.testing.expectEqual(@as(?u64, null), queue.groupIdForPacketNumber(4));
    try std.testing.expect(queue.packetNumberCandidate(4) == null);
    try std.testing.expect(!queue.acknowledgePacketNumber(4));
    try std.testing.expect(!queue.forgetPacketNumber(4));
}

test "QUIC recovery queue keeps initial packet number allocation-free" {
    var counting = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const allocator = counting.allocator();
    var queue = Queue.init(allocator);
    defer queue.deinit();

    try std.testing.expectError(
        error.EmptyPayload,
        queue.trackSent(41, ""),
    );
    try std.testing.expect(!counting.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), queue.packet_index.count());
    try std.testing.expectEqual(@as(usize, 0), queue.group_index.count());

    // Remove queue growth from the measurement. Tracking a new payload then
    // needs exactly one allocation for bytes that must survive caller reuse;
    // the overwhelmingly common original packet number stays inline.
    try queue.pending.ensureTotalCapacity(allocator, 1);
    try queue.group_index.ensureTotalCapacity(allocator, 1);
    try queue.packet_index.ensureTotalCapacity(allocator, 1);
    const allocations_before = counting.allocations;
    _ = try queue.trackSent(42, "owned recovery payload");
    try std.testing.expectEqual(@as(usize, 1), counting.allocations - allocations_before);
    try std.testing.expectEqual(@as(?u64, 42), queue.pending.items[0].original_packet_number);
    try std.testing.expectEqual(@as(usize, 0), queue.pending.items[0].retransmission_packet_numbers.capacity);

    // Dynamic packet-number storage is deferred until a retransmission exists.
    try queue.recordRetransmission(0, 43);
    try std.testing.expectEqual(@as(usize, 2), queue.pending.items[0].packetCount());
    try std.testing.expect(queue.pending.items[0].retransmission_packet_numbers.capacity > 0);
}

test "QUIC recovery queue reuses payload buckets after ACK" {
    var counting = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    const allocator = counting.allocator();
    var queue = Queue.init(allocator);
    defer queue.deinit();

    try queue.pending.ensureTotalCapacity(allocator, 1);
    try queue.group_index.ensureTotalCapacity(allocator, 1);
    try queue.packet_index.ensureTotalCapacity(allocator, 1);
    _ = try queue.trackSent(1, "eight!!!");
    const allocations_after_first = counting.allocations;
    try std.testing.expect(queue.acknowledgePacketNumber(1));
    try std.testing.expectEqual(
        @as(usize, 1),
        queue.payload_cache.stats().blocks,
    );
    try std.testing.expectEqual(
        @as(usize, 8),
        queue.payload_cache.stats().bytes,
    );

    // Seven bytes reuse the cached eight-byte bucket, but only the logical
    // prefix may become a retransmission candidate.
    _ = try queue.trackSent(2, "second!");
    try std.testing.expectEqual(allocations_after_first, counting.allocations);
    try std.testing.expectEqualStrings(
        "second!",
        queue.ptoCandidate().?.payload,
    );
    const stats = queue.stats();
    try std.testing.expectEqual(@as(u64, 1), stats.payload_cache_hits);
    try std.testing.expectEqual(@as(u64, 1), stats.payload_cache_misses);
}

test "QUIC recovery payload cache is depth and byte bounded" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    for (0..payload_cache.Cache.depth + 2) |packet_number| {
        _ = try queue.trackSent(@intCast(packet_number), "payload");
    }
    for (0..payload_cache.Cache.depth + 2) |packet_number| {
        try std.testing.expect(
            queue.acknowledgePacketNumber(@intCast(packet_number)),
        );
    }
    const stats = queue.stats();
    try std.testing.expectEqual(
        payload_cache.Cache.depth,
        stats.cached_payload_blocks,
    );
    try std.testing.expectEqual(
        payload_cache.Cache.depth * 8,
        stats.cached_payload_bytes,
    );
    try std.testing.expect(
        stats.cached_payload_bytes <= payload_cache.Cache.max_cached_bytes,
    );
}

test "QUIC recovery queue keeps stable group identity across retransmissions" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    const group_id = try queue.trackSent(4, "control");
    try std.testing.expectEqual(
        group_id,
        queue.groupIdForPacketNumber(4).?,
    );
    try std.testing.expect(queue.containsGroupId(group_id));

    try queue.recordRetransmission(0, 8);
    try std.testing.expectEqual(
        group_id,
        queue.groupIdForPacketNumber(8).?,
    );
    try std.testing.expectEqual(@as(u64, 8), queue.pending.items[0].newestPacketNumber());
    try std.testing.expectEqual(@as(?usize, 0), queue.group_index.get(group_id));
    try std.testing.expectEqual(@as(?usize, 0), queue.packet_index.get(4));
    try std.testing.expectEqual(@as(?usize, 0), queue.packet_index.get(8));
    try std.testing.expect(queue.forgetPacketNumber(8));
    try std.testing.expectEqual(@as(u64, 4), queue.pending.items[0].newestPacketNumber());
    try queue.recordRetransmission(0, 8);
    try std.testing.expect(queue.acknowledgePacketNumber(8));
    try std.testing.expect(!queue.containsGroupId(group_id));
    try std.testing.expect(queue.group_index.get(group_id) == null);
    try std.testing.expect(queue.packet_index.get(4) == null);
    try std.testing.expect(queue.packet_index.get(8) == null);
}

test "QUIC recovery queue forgets middle retransmission without losing newest" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    _ = try queue.trackSent(1, "payload");
    try queue.recordRetransmission(0, 2);
    try queue.recordRetransmission(0, 3);
    try queue.recordRetransmission(0, 4);

    try std.testing.expect(queue.forgetPacketNumber(2));
    try std.testing.expectEqual(@as(u64, 4), queue.pending.items[0].newestPacketNumber());
    try std.testing.expectEqual(@as(usize, 3), queue.pending.items[0].packetCount());
    try std.testing.expectEqual(@as(?usize, 0), queue.packet_index.get(1));
    try std.testing.expect(queue.packet_index.get(2) == null);
    try std.testing.expectEqual(@as(?usize, 0), queue.packet_index.get(3));
    try std.testing.expectEqual(@as(?usize, 0), queue.packet_index.get(4));
}

test "QUIC recovery queue indexes survive ordered removals and ACK compaction" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    const first = try queue.trackSent(10, "first");
    const second = try queue.trackSent(20, "second");
    const third = try queue.trackSent(30, "third");
    try queue.recordRetransmission(2, 31);
    try std.testing.expectEqual(@as(usize, 3), queue.group_index.count());
    try std.testing.expectEqual(@as(usize, 4), queue.packet_index.count());

    // ACKing the first group uses orderedRemove to preserve PTO scheduling
    // order.  The later groups shift left, so every packet-number and group-id
    // index must be repaired before the next ACK/loss lookup.
    try std.testing.expect(queue.acknowledgePacketNumber(10));
    try std.testing.expect(!queue.containsGroupId(first));
    try std.testing.expectEqual(@as(?usize, 0), queue.group_index.get(second));
    try std.testing.expectEqual(@as(?usize, 1), queue.group_index.get(third));
    try std.testing.expectEqual(@as(?usize, 0), queue.packet_index.get(20));
    try std.testing.expectEqual(@as(?usize, 1), queue.packet_index.get(30));
    try std.testing.expectEqual(@as(?usize, 1), queue.packet_index.get(31));
    try std.testing.expectEqual(third, queue.groupIdForPacketNumber(31).?);
    const after_first_ack = queue.stats();
    try std.testing.expectEqual(@as(usize, 3), after_first_ack.packet_number_copies);
    try std.testing.expectEqual(@as(usize, 1), after_first_ack.retransmission_copies);
    try std.testing.expectEqual("second".len + "third".len, after_first_ack.payload_bytes);

    try std.testing.expect(queue.forgetPacketNumber(30));
    try std.testing.expect(queue.packet_index.get(30) == null);
    try std.testing.expectEqual(@as(?usize, 1), queue.packet_index.get(31));
    try std.testing.expectEqual(@as(usize, 1), queue.pending.items[1].packetCount());
    const after_forget_original = queue.stats();
    try std.testing.expectEqual(@as(usize, 2), after_forget_original.packet_number_copies);
    try std.testing.expectEqual(@as(usize, 1), after_forget_original.retransmission_copies);
    try std.testing.expectEqual("second".len + "third".len, after_forget_original.payload_bytes);

    const ack = quic.AckFrame{
        .largest_acknowledged = 31,
        .ack_delay = 0,
        .first_ack_range = 0,
    };
    try std.testing.expectEqual(@as(usize, 1), try queue.applyAck(ack));
    try std.testing.expect(!queue.containsGroupId(third));
    try std.testing.expect(queue.packet_index.get(31) == null);
    try std.testing.expectEqual(@as(usize, 1), queue.pendingCount());
    try std.testing.expectEqual(@as(?usize, 0), queue.group_index.get(second));
    try std.testing.expectEqual(@as(?usize, 0), queue.packet_index.get(20));
    const after_ack_compaction = queue.stats();
    try std.testing.expectEqual(@as(usize, 1), after_ack_compaction.packet_number_copies);
    try std.testing.expectEqual(@as(usize, 0), after_ack_compaction.retransmission_copies);
    try std.testing.expectEqual("second".len, after_ack_compaction.payload_bytes);
}

test "QUIC recovery queue selects PTO candidates by pending group" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    _ = try queue.trackSent(0, "zero");
    _ = try queue.trackSent(1, "one");

    const first = queue.ptoCandidateAt(0).?;
    try std.testing.expectEqual(@as(usize, 0), first.group_index);
    try std.testing.expectEqualStrings("zero", first.payload);

    const second = queue.ptoCandidateAt(1).?;
    try std.testing.expectEqual(@as(usize, 1), second.group_index);
    try std.testing.expectEqualStrings("one", second.payload);
    try std.testing.expect(queue.ptoCandidateAt(2) == null);
}

test "QUIC recovery queue applies ACK ranges" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    _ = try queue.trackSent(1, "one");
    _ = try queue.trackSent(5, "five");
    _ = try queue.trackSent(9, "nine");

    const ranges = [_]quic.AckRange{
        .{ .gap = 2, .ack_range_length = 0 }, // acknowledges packet 5 after largest 9.
    };
    const ack = quic.AckFrame{
        .largest_acknowledged = 9,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &ranges,
    };
    try std.testing.expectEqual(@as(usize, 2), try queue.applyAck(ack));
    try std.testing.expectEqual(@as(usize, 1), queue.pendingCount());
    try std.testing.expectEqual(@as(u64, 1), queue.pending.items[0].newestPacketNumber());
}

test "QUIC recovery queue compacts ACKed ranges without reordering survivors" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    for (1..6) |packet_number| {
        _ = try queue.trackSent(@intCast(packet_number), "payload");
    }

    const ranges = [_]quic.AckRange{
        .{ .gap = 0, .ack_range_length = 0 }, // acknowledges packet 2 after 4.
    };
    const ack = quic.AckFrame{
        .largest_acknowledged = 4,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &ranges,
    };

    try std.testing.expectEqual(@as(usize, 2), try queue.applyAck(ack));
    try std.testing.expectEqual(@as(usize, 3), queue.pendingCount());
    try std.testing.expectEqual(@as(u64, 1), queue.pending.items[0].newestPacketNumber());
    try std.testing.expectEqual(@as(u64, 3), queue.pending.items[1].newestPacketNumber());
    try std.testing.expectEqual(@as(u64, 5), queue.pending.items[2].newestPacketNumber());
}

test "QUIC recovery queue applies large ACK range sets in one pass" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    for (0..81) |packet_number| {
        _ = try queue.trackSent(@intCast(packet_number), "x");
    }

    const ranges = [_]quic.AckRange{
        .{ .gap = 0, .ack_range_length = 0 },
    } ** 40;
    const ack = quic.AckFrame{
        .largest_acknowledged = 80,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &ranges,
    };

    try std.testing.expectEqual(@as(usize, 41), try queue.applyAck(ack));
    try std.testing.expectEqual(@as(usize, 40), queue.pendingCount());
    for (queue.pending.items, 0..) |entry, index| {
        try std.testing.expectEqual(
            @as(u64, @intCast(index * 2 + 1)),
            entry.newestPacketNumber(),
        );
    }
}

test "QUIC recovery applies large ACK range sets without allocation" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    const allocator = failing.allocator();
    var queue = Queue.init(allocator);
    defer queue.deinit();

    for (0..81) |packet_number| {
        _ = try queue.trackSent(@intCast(packet_number), "x");
    }
    const ranges = [_]quic.AckRange{
        .{ .gap = 0, .ack_range_length = 0 },
    } ** 40;
    const ack = quic.AckFrame{
        .largest_acknowledged = 80,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &ranges,
    };

    // Payload recycling and index rebuilding retain their existing capacity.
    // Once tracking is complete, even an ACK with more than the historical
    // 32-range stack threshold must not consult the allocator.
    failing.fail_index = failing.alloc_index;
    try std.testing.expectEqual(@as(usize, 41), try queue.applyAck(ack));
    try std.testing.expect(!failing.has_induced_failure);
}

test "QUIC recovery rejects invalid large ACK transactionally" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();
    _ = try queue.trackSent(1, "one");
    _ = try queue.trackSent(5, "five");

    const invalid = quic.AckFrame{
        .largest_acknowledged = 80,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &.{.{
            .gap = std.math.maxInt(u64),
            .ack_range_length = 0,
        }},
    };
    try std.testing.expectError(error.InvalidAckFrame, queue.applyAck(invalid));
    try std.testing.expectEqual(@as(usize, 2), queue.pendingCount());
    try std.testing.expect(queue.packetNumberCandidate(1) != null);
    try std.testing.expect(queue.packetNumberCandidate(5) != null);
}

test "QUIC recovery queue schedules packet-threshold loss once per newest copy" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    _ = try queue.trackSent(0, "zero");
    _ = try queue.trackSent(2, "two");
    _ = try queue.trackSent(6, "six");

    const candidate = queue.packetThresholdCandidate(4, quic.packet_space.default_packet_threshold).?;
    try std.testing.expectEqual(@as(usize, 0), candidate.group_index);
    try std.testing.expectEqual(@as(u64, 0), candidate.packet_number);
    try std.testing.expectEqualStrings("zero", candidate.payload);

    try queue.recordRetransmission(candidate.group_index, 7);
    try std.testing.expect(queue.packetThresholdCandidate(4, quic.packet_space.default_packet_threshold) == null);
    try std.testing.expectEqualStrings(
        "zero",
        queue.pending.items[0].payload(),
    );

    const ack = quic.AckFrame{
        .largest_acknowledged = 7,
        .ack_delay = 0,
        .first_ack_range = 0,
    };
    try std.testing.expectEqual(@as(usize, 1), try queue.applyAck(ack));
    try std.testing.expectEqual(@as(usize, 2), queue.pendingCount());
}

test "QUIC recovery queue locates candidate by any packet number copy" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    _ = try queue.trackSent(1, "payload");
    try queue.recordRetransmission(0, 5);

    const original = queue.packetNumberCandidate(1).?;
    try std.testing.expectEqual(@as(usize, 0), original.group_index);
    try std.testing.expectEqual(@as(u64, 5), original.packet_number);
    try std.testing.expectEqualStrings("payload", original.payload);

    const newest = queue.packetNumberCandidate(5).?;
    try std.testing.expectEqual(@as(usize, 0), newest.group_index);
    try std.testing.expect(queue.packetNumberCandidate(99) == null);
}
