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

/// Newly tracked recovery storage that the caller must initialize completely
/// before invoking any other queue operation.
///
/// This is intentionally a narrow construction API for packet builders: the
/// queue owns `payload` immediately, so any downstream failure must remove the
/// packet with `forgetPacketNumber`. Encoding directly into these bytes avoids
/// first materializing a plaintext packet and then copying it into recovery.
pub const UninitializedPayload = struct {
    group_id: u64,
    payload: []u8,
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

    fn containsRange(self: *const PendingDatagram, start: u64, end: u64) bool {
        if (self.original_packet_number) |packet_number| {
            if (packet_number >= start and packet_number <= end) return true;
        }
        for (self.retransmission_packet_numbers.items) |packet_number| {
            if (packet_number >= start and packet_number <= end) return true;
        }
        return false;
    }

    fn containsPacketNumber(
        self: *const PendingDatagram,
        packet_number: u64,
    ) bool {
        if (self.original_packet_number == packet_number) return true;
        for (self.retransmission_packet_numbers.items) |candidate| {
            if (candidate == packet_number) return true;
        }
        return false;
    }

    pub fn packetCount(self: *const PendingDatagram) usize {
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
    /// Packet numbers are monotonically increasing in production. This cached
    /// maximum makes new-packet duplicate checks O(1); only an out-of-order
    /// caller needs to scan the bounded in-flight queue.
    largest_packet_number: ?u64 = null,
    /// Original packet numbers append monotonically in production. Ordered
    /// removal preserves that order, allowing a clean single-range ACK to
    /// locate the affected queue slice with two binary searches. Synthetic
    /// out-of-order insertion keeps the conservative scan fallback.
    originals_sorted_ascending: bool = true,
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
        const tracked = try self.trackSentUninitialized(
            packet_number,
            payload.len,
        );
        @memcpy(tracked.payload, payload);
        return tracked.group_id;
    }

    /// Track a packet and return its exact mutable recovery payload.
    ///
    /// The returned slice aliases queue-owned storage and remains stable until
    /// the packet group is acknowledged, forgotten, or the queue is destroyed.
    /// Callers must initialize every byte before exposing the queue to another
    /// operation; use `trackSent` when the encoded payload already exists.
    pub fn trackSentUninitialized(
        self: *Queue,
        packet_number: u64,
        payload_len: usize,
    ) Error!UninitializedPayload {
        if (payload_len == 0) return error.EmptyPayload;
        if (self.packetNumberExists(packet_number)) {
            return error.InvalidRetransmission;
        }

        const group_id = self.next_group_id;
        const next_group_id = std.math.add(
            u64,
            group_id,
            1,
        ) catch return error.InvalidRetransmission;
        try self.pending.ensureUnusedCapacity(self.allocator, 1);
        const payload_storage = self.payload_cache.acquire(
            payload_len,
        ) catch return error.OutOfMemory;
        errdefer self.payload_cache.release(payload_storage);
        const entry = PendingDatagram.initOwned(
            group_id,
            packet_number,
            payload_storage,
            payload_len,
        );
        self.appendGroupAssumeCapacity(entry);
        self.next_group_id = next_group_id;
        self.largest_packet_number = if (self.largest_packet_number) |old|
            @max(old, packet_number)
        else
            packet_number;
        return .{
            .group_id = group_id,
            .payload = payload_storage[0..payload_len],
        };
    }

    pub fn groupIdForPacketNumber(
        self: *const Queue,
        packet_number: u64,
    ) ?u64 {
        const index = self.findPacketIndex(packet_number) orelse return null;
        return self.pending.items[index].group_id;
    }

    pub fn containsGroupId(self: *const Queue, group_id: u64) bool {
        for (self.pending.items) |entry| {
            if (entry.group_id == group_id) return true;
        }
        return false;
    }

    /// Whether retransmittable STREAM data, including FIN, is still awaiting
    /// acknowledgement for `stream_id`. This is used only at stream-close
    /// boundaries; keeping recovery payloads encoded avoids per-packet stream
    /// metadata on the normal send/ACK path.
    pub fn hasPendingStreamData(self: *const Queue, stream_id: u64) bool {
        return self.hasPendingStreamFrame(stream_id, false);
    }

    /// Whether a RESET_STREAM for `stream_id` is still awaiting acknowledgement.
    pub fn hasPendingResetStream(self: *const Queue, stream_id: u64) bool {
        return self.hasPendingStreamFrame(stream_id, true);
    }

    fn hasPendingStreamFrame(
        self: *const Queue,
        stream_id: u64,
        reset_only: bool,
    ) bool {
        for (self.pending.items) |entry| {
            const payload = entry.payload();
            var pos: usize = 0;
            while (pos < payload.len) {
                const parsed = quic.parseFrame(payload[pos..]) catch
                    return true;
                if (reset_only) {
                    if (parsed.frame == .reset_stream and
                        parsed.frame.reset_stream.stream_id == stream_id)
                    {
                        return true;
                    }
                } else {
                    if (parsed.frame == .stream and
                        parsed.frame.stream.stream_id == stream_id)
                    {
                        return true;
                    }
                }
                if (parsed.consumed == 0) return true;
                pos += parsed.consumed;
            }
        }
        return false;
    }

    /// Stop retransmitting STREAM data after the application terminates that
    /// send side with RESET_STREAM. Mixed payload groups are compacted in
    /// place so unrelated reliable frames retain their packet group and ACK
    /// identity without another allocation.
    pub fn abandonStreamData(self: *Queue, stream_id: u64) usize {
        return self.abandonStreamFrames(stream_id, .data);
    }

    /// Drop every stream-scoped frame that has become obsolete once both
    /// directions are terminal and the active stream state is reclaimed.
    pub fn abandonClosedStreamFrames(
        self: *Queue,
        stream_id: u64,
    ) usize {
        return self.abandonStreamFrames(stream_id, .closed);
    }

    /// Whether recovery still owns data whose delivery matters to a completed
    /// application operation. Pure receive-credit updates are excluded: they
    /// remain retransmittable in the queue, but a short-lived server that has
    /// delivered its final response need not wait for their acknowledgement.
    pub fn hasPendingDeliveryFrames(self: *const Queue) bool {
        for (self.pending.items) |entry| {
            var remaining = entry.payload();
            while (remaining.len != 0) {
                const parsed = quic.parseFrame(remaining) catch unreachable;
                switch (parsed.frame) {
                    .max_data,
                    .max_stream_data,
                    .max_streams_bidi,
                    .max_streams_uni,
                    => {},
                    else => return true,
                }
                remaining = remaining[parsed.consumed..];
            }
        }
        return false;
    }

    const AbandonStreamFrames = enum { data, closed };

    fn abandonStreamFrames(
        self: *Queue,
        stream_id: u64,
        mode: AbandonStreamFrames,
    ) usize {
        var index: usize = 0;
        var removed_frames: usize = 0;
        while (index < self.pending.items.len) {
            const entry = &self.pending.items[index];
            const payload = entry.payload();
            var read: usize = 0;
            var write: usize = 0;
            while (read < payload.len) {
                const parsed = quic.parseFrame(payload[read..]) catch
                    unreachable;
                const remove = switch (parsed.frame) {
                    .stream => |stream| stream.stream_id == stream_id,
                    .reset_stream => |reset| mode == .closed and
                        reset.stream_id == stream_id,
                    .stop_sending => |stop| mode == .closed and
                        stop.stream_id == stream_id,
                    .max_stream_data => |maximum| mode == .closed and
                        maximum.stream_id == stream_id,
                    .stream_data_blocked => |blocked| mode == .closed and
                        blocked.stream_id == stream_id,
                    else => false,
                };
                if (remove) {
                    removed_frames += 1;
                } else {
                    if (write != read) {
                        @memmove(
                            entry.payload_storage[write .. write + parsed.consumed],
                            entry.payload_storage[read .. read + parsed.consumed],
                        );
                    }
                    write += parsed.consumed;
                }
                read += parsed.consumed;
            }
            if (write == payload.len) {
                index += 1;
                continue;
            }
            if (write == 0) {
                var removed = self.removeGroupOrdered(index);
                self.recycleEntry(&removed);
                continue;
            }
            self.payload_bytes -= payload.len - write;
            entry.payload_len = write;
            index += 1;
        }
        return removed_frames;
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
        const group_index = self.findPacketIndex(packet_number) orelse return null;
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
        if (self.packetNumberExists(packet_number)) {
            return error.InvalidRetransmission;
        }

        const entry = &self.pending.items[group_index];
        try entry.retransmission_packet_numbers.append(self.allocator, packet_number);
        entry.newest_packet_number = packet_number;
        self.largest_packet_number = if (self.largest_packet_number) |old|
            @max(old, packet_number)
        else
            packet_number;
        self.packet_number_copies += 1;
        self.retransmission_copies += 1;
    }

    pub fn acknowledgePacketNumber(self: *Queue, packet_number: u64) bool {
        const index = self.findPacketIndex(packet_number) orelse return false;
        var removed = self.removeGroupOrdered(index);
        self.recycleEntry(&removed);
        return true;
    }

    pub fn forgetPacketNumber(self: *Queue, packet_number: u64) bool {
        const group_index = self.findPacketIndex(packet_number) orelse
            return false;
        if (self.pending.items[group_index].packetCount() == 1) {
            var removed = self.removeGroupOrdered(group_index);
            self.recycleEntry(&removed);
            return true;
        }

        var entry = &self.pending.items[group_index];
        if (entry.original_packet_number == packet_number) {
            entry.original_packet_number = null;
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
        if (ack.ranges.len == 0 and
            self.retransmission_copies == 0 and
            self.originals_sorted_ascending)
        {
            return self.retainOutsideSingleOriginalRange(
                ack.largest_acknowledged - ack.first_ack_range,
                ack.largest_acknowledged,
            );
        }

        var write_index: usize = 0;
        var removed: usize = 0;
        for (self.pending.items, 0..) |*entry, read_index| {
            if (entryAcked(entry, ack)) {
                self.removeEntryStats(entry);
                self.recycleEntry(entry);
                removed += 1;
                continue;
            }
            if (write_index != read_index) {
                self.pending.items[write_index] = entry.*;
                entry.* = undefined;
            }
            write_index += 1;
        }
        if (removed == 0) return 0;
        self.pending.items.len = write_index;
        if (write_index == 0) self.originals_sorted_ascending = true;
        return removed;
    }

    fn retainOutsideSingleOriginalRange(
        self: *Queue,
        start: u64,
        end: u64,
    ) usize {
        const remove_start = self.lowerBoundOriginalPacketNumber(start);
        const remove_end = self.upperBoundOriginalPacketNumber(end);
        if (remove_start == remove_end) return 0;

        for (self.pending.items[remove_start..remove_end]) |*entry| {
            self.removeEntryStats(entry);
            self.recycleEntry(entry);
        }
        const removed = remove_end - remove_start;
        const remaining = self.pending.items.len - remove_end;
        if (remaining != 0) {
            @memmove(
                self.pending.items[remove_start .. remove_start + remaining],
                self.pending.items[remove_end..],
            );
        }
        self.pending.items.len -= removed;
        if (self.pending.items.len == 0) {
            self.originals_sorted_ascending = true;
        }
        return removed;
    }

    fn lowerBoundOriginalPacketNumber(
        self: *const Queue,
        packet_number: u64,
    ) usize {
        var low: usize = 0;
        var high = self.pending.items.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            const candidate = self.pending.items[mid].original_packet_number.?;
            if (candidate < packet_number) {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        return low;
    }

    fn upperBoundOriginalPacketNumber(
        self: *const Queue,
        packet_number: u64,
    ) usize {
        var low: usize = 0;
        var high = self.pending.items.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            const candidate = self.pending.items[mid].original_packet_number.?;
            if (candidate <= packet_number) {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        return low;
    }

    fn entryAcked(
        entry: *const PendingDatagram,
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
    ) void {
        if (self.pending.items.len != 0) {
            const previous = self.pending.items[
                self.pending.items.len - 1
            ].original_packet_number;
            const current = entry.original_packet_number.?;
            if (previous == null or current <= previous.?) {
                self.originals_sorted_ascending = false;
            }
        }
        self.pending.appendAssumeCapacity(entry);
        self.addEntryStats(entry);
    }

    fn packetNumberExists(
        self: *const Queue,
        packet_number: u64,
    ) bool {
        if (self.largest_packet_number) |largest| {
            if (packet_number > largest) return false;
        } else return false;
        return self.findPacketIndex(packet_number) != null;
    }

    fn findPacketIndex(
        self: *const Queue,
        packet_number: u64,
    ) ?usize {
        for (self.pending.items, 0..) |entry, index| {
            if (entry.containsPacketNumber(packet_number)) return index;
        }
        return null;
    }

    fn removeGroupOrdered(self: *Queue, index: usize) PendingDatagram {
        const removed = if (index == self.pending.items.len - 1)
            self.pending.pop().?
        else
            self.pending.orderedRemove(index);
        self.removeEntryStats(&removed);
        if (self.pending.items.len == 0) {
            self.originals_sorted_ascending = true;
        }
        return removed;
    }

    fn addEntryStats(self: *Queue, entry: PendingDatagram) void {
        self.packet_number_copies += entry.packetCount();
        self.retransmission_copies += entry.retransmission_packet_numbers.items.len;
        self.payload_bytes += entry.payload_len;
    }

    fn removeEntryStats(self: *Queue, entry: *const PendingDatagram) void {
        self.packet_number_copies -|= entry.packetCount();
        self.retransmission_copies -|= entry.retransmission_packet_numbers.items.len;
        self.payload_bytes -|= entry.payload_len;
    }

    fn recycleEntry(self: *Queue, entry: *PendingDatagram) void {
        entry.retransmission_packet_numbers.deinit(self.allocator);
        self.payload_cache.release(entry.payload_storage);
        entry.* = undefined;
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
    try std.testing.expectEqual(@as(u64, 0), queue.groupIdForPacketNumber(0).?);
    try std.testing.expectEqual(@as(u64, 0), queue.groupIdForPacketNumber(4).?);
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

    // Remove queue growth from the measurement. Tracking a new payload then
    // needs exactly one allocation for bytes that must survive caller reuse;
    // the overwhelmingly common original packet number stays inline.
    try queue.pending.ensureTotalCapacity(allocator, 1);
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

test "QUIC recovery queue exposes stable uninitialized payload ownership" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    const tracked = try queue.trackSentUninitialized(7, 8);
    @memcpy(tracked.payload, "direct!!");
    try std.testing.expectEqual(@as(u64, 0), tracked.group_id);
    try std.testing.expectEqualStrings(
        "direct!!",
        queue.packetNumberCandidate(7).?.payload,
    );
    // Candidate storage must alias the slice returned to the packet builder;
    // this is what removes the encode-then-copy pass on hot batch sends.
    try std.testing.expectEqual(
        tracked.payload.ptr,
        queue.packetNumberCandidate(7).?.payload.ptr,
    );
}

test "QUIC recovery queue identifies pending stream terminal frames" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try (quic.Frame{ .ping = {} }).write(&payload, allocator);
    try (quic.Frame{ .stream = .{
        .stream_id = 4,
        .offset = 9,
        .data = "done",
        .fin = true,
    } }).write(&payload, allocator);
    try (quic.Frame{ .reset_stream = .{
        .stream_id = 8,
        .application_error_code = 42,
        .final_size = 17,
    } }).write(&payload, allocator);

    _ = try queue.trackSent(11, payload.items);
    try std.testing.expect(queue.hasPendingStreamData(4));
    try std.testing.expect(!queue.hasPendingStreamData(8));
    try std.testing.expect(queue.hasPendingResetStream(8));
    try std.testing.expect(!queue.hasPendingResetStream(4));
    try std.testing.expect(!queue.hasPendingStreamData(12));

    try std.testing.expect(queue.acknowledgePacketNumber(11));
    try std.testing.expect(!queue.hasPendingStreamData(4));
    try std.testing.expect(!queue.hasPendingResetStream(8));
}

test "QUIC recovery abandons one stream without losing sibling frames" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    var mixed: std.ArrayList(u8) = .empty;
    defer mixed.deinit(allocator);
    try (quic.Frame{ .stream = .{
        .stream_id = 4,
        .data = "old",
    } }).write(&mixed, allocator);
    try (quic.Frame{ .stream = .{
        .stream_id = 8,
        .data = "keep",
        .fin = true,
    } }).write(&mixed, allocator);
    try (quic.Frame{ .ping = {} }).write(&mixed, allocator);
    _ = try queue.trackSent(7, mixed.items);

    try std.testing.expectEqual(@as(usize, 1), queue.abandonStreamData(4));
    try std.testing.expect(!queue.hasPendingStreamData(4));
    try std.testing.expect(queue.hasPendingStreamData(8));
    const candidate = queue.packetNumberCandidate(7) orelse
        return error.TestUnexpectedResult;
    const first = try quic.parseFrame(candidate.payload);
    try std.testing.expect(first.frame == .stream);
    try std.testing.expectEqual(@as(u64, 8), first.frame.stream.stream_id);
    const second = try quic.parseFrame(candidate.payload[first.consumed..]);
    try std.testing.expect(second.frame == .ping);
    try std.testing.expectEqual(
        candidate.payload.len,
        first.consumed + second.consumed,
    );

    try std.testing.expectEqual(@as(usize, 1), queue.abandonStreamData(8));
    try std.testing.expect(!queue.hasPendingStreamData(8));
    try std.testing.expectEqual(@as(usize, 1), queue.pendingCount());
    const ping = try quic.parseFrame(queue.packetNumberCandidate(7).?.payload);
    try std.testing.expect(ping.frame == .ping);
}

test "QUIC recovery drops stale closed-stream controls only" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try (quic.Frame{ .max_stream_data = .{
        .stream_id = 4,
        .maximum_stream_data = 90,
    } }).write(&payload, allocator);
    try (quic.Frame{ .stop_sending = .{
        .stream_id = 4,
        .application_error_code = 7,
    } }).write(&payload, allocator);
    try (quic.Frame{ .stream_data_blocked = .{
        .stream_id = 8,
        .maximum_stream_data = 30,
    } }).write(&payload, allocator);
    _ = try queue.trackSent(9, payload.items);

    try std.testing.expectEqual(
        @as(usize, 2),
        queue.abandonClosedStreamFrames(4),
    );
    const kept = queue.packetNumberCandidate(9) orelse
        return error.TestUnexpectedResult;
    const parsed = try quic.parseFrame(kept.payload);
    try std.testing.expect(parsed.frame == .stream_data_blocked);
    try std.testing.expectEqual(@as(u64, 8), parsed.frame.stream_data_blocked.stream_id);
    try std.testing.expectEqual(kept.payload.len, parsed.consumed);
}

test "QUIC recovery delivery drain ignores pure receive credit" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    var credit: std.ArrayList(u8) = .empty;
    defer credit.deinit(allocator);
    try (quic.Frame{ .max_data = .{ .maximum_data = 64 } })
        .write(&credit, allocator);
    try (quic.Frame{ .max_streams_bidi = .{ .maximum_streams = 2 } })
        .write(&credit, allocator);
    _ = try queue.trackSent(0, credit.items);
    try std.testing.expect(!queue.hasPendingDeliveryFrames());

    var response: std.ArrayList(u8) = .empty;
    defer response.deinit(allocator);
    try (quic.Frame{ .stream = .{
        .stream_id = 0,
        .data = "response",
        .fin = true,
    } }).write(&response, allocator);
    _ = try queue.trackSent(1, response.items);
    try std.testing.expect(queue.hasPendingDeliveryFrames());
    try std.testing.expect(queue.acknowledgePacketNumber(1));
    try std.testing.expect(!queue.hasPendingDeliveryFrames());
}

test "QUIC recovery uninitialized tracking rejects empty payload transactionally" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    try std.testing.expectError(
        error.EmptyPayload,
        queue.trackSentUninitialized(7, 0),
    );
    try std.testing.expectEqual(@as(usize, 0), queue.pendingCount());
}

test "QUIC recovery duplicate check allows rolled-back packet retry" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    _ = try queue.trackSent(7, "first");
    try std.testing.expectError(
        error.InvalidRetransmission,
        queue.trackSent(7, "duplicate"),
    );
    try std.testing.expect(queue.forgetPacketNumber(7));
    _ = try queue.trackSent(7, "retry");
    try std.testing.expectEqualStrings(
        "retry",
        queue.packetNumberCandidate(7).?.payload,
    );
    _ = try queue.trackSent(8, "next");
    try std.testing.expectEqualStrings(
        "next",
        queue.packetNumberCandidate(8).?.payload,
    );
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

test "QUIC recovery payload cache uses overflow and stays byte bounded" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    const small_blocks = payload_cache.Cache.inline_depth + 2;
    for (0..small_blocks) |packet_number| {
        _ = try queue.trackSent(@intCast(packet_number), "payload");
    }
    for (0..small_blocks) |packet_number| {
        try std.testing.expect(
            queue.acknowledgePacketNumber(@intCast(packet_number)),
        );
    }
    const stats = queue.stats();
    try std.testing.expectEqual(
        small_blocks,
        stats.cached_payload_blocks,
    );
    try std.testing.expectEqual(
        small_blocks * 8,
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
    try std.testing.expectEqual(group_id, queue.groupIdForPacketNumber(4).?);
    try std.testing.expectEqual(group_id, queue.groupIdForPacketNumber(8).?);
    try std.testing.expect(queue.forgetPacketNumber(8));
    try std.testing.expectEqual(@as(u64, 4), queue.pending.items[0].newestPacketNumber());
    try queue.recordRetransmission(0, 8);
    try std.testing.expect(queue.acknowledgePacketNumber(8));
    try std.testing.expect(!queue.containsGroupId(group_id));
    try std.testing.expect(queue.groupIdForPacketNumber(4) == null);
    try std.testing.expect(queue.groupIdForPacketNumber(8) == null);
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
    try std.testing.expect(queue.packetNumberCandidate(1) != null);
    try std.testing.expect(queue.packetNumberCandidate(2) == null);
    try std.testing.expect(queue.packetNumberCandidate(3) != null);
    try std.testing.expect(queue.packetNumberCandidate(4) != null);
}

test "QUIC recovery lookups survive ordered removals and ACK compaction" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    const first = try queue.trackSent(10, "first");
    const second = try queue.trackSent(20, "second");
    const third = try queue.trackSent(30, "third");
    try queue.recordRetransmission(2, 31);
    // ACKing the first group uses orderedRemove to preserve PTO scheduling
    // order. Later packet-number and group lookups must survive the shift.
    try std.testing.expect(queue.acknowledgePacketNumber(10));
    try std.testing.expect(!queue.containsGroupId(first));
    try std.testing.expect(queue.containsGroupId(second));
    try std.testing.expect(queue.containsGroupId(third));
    try std.testing.expect(queue.packetNumberCandidate(20) != null);
    try std.testing.expect(queue.packetNumberCandidate(30) != null);
    try std.testing.expect(queue.packetNumberCandidate(31) != null);
    try std.testing.expectEqual(third, queue.groupIdForPacketNumber(31).?);
    const after_first_ack = queue.stats();
    try std.testing.expectEqual(@as(usize, 3), after_first_ack.packet_number_copies);
    try std.testing.expectEqual(@as(usize, 1), after_first_ack.retransmission_copies);
    try std.testing.expectEqual("second".len + "third".len, after_first_ack.payload_bytes);

    try std.testing.expect(queue.forgetPacketNumber(30));
    try std.testing.expect(queue.packetNumberCandidate(30) == null);
    try std.testing.expect(queue.packetNumberCandidate(31) != null);
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
    try std.testing.expect(queue.packetNumberCandidate(31) == null);
    try std.testing.expectEqual(@as(usize, 1), queue.pendingCount());
    try std.testing.expect(queue.containsGroupId(second));
    try std.testing.expect(queue.packetNumberCandidate(20) != null);
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

test "QUIC recovery queue applies one contiguous ACK range" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    for (0..8) |packet_number| {
        _ = try queue.trackSent(@intCast(packet_number * 2), "payload");
    }

    try std.testing.expectEqual(
        @as(usize, 3),
        try queue.applyAck(.{
            .largest_acknowledged = 9,
            .ack_delay = 0,
            .first_ack_range = 5,
        }),
    );
    try std.testing.expectEqual(@as(usize, 5), queue.pendingCount());
    const expected = [_]u64{ 0, 2, 10, 12, 14 };
    for (queue.pending.items, expected) |entry, packet_number| {
        try std.testing.expectEqual(
            packet_number,
            entry.original_packet_number.?,
        );
    }
    try std.testing.expectEqual(@as(usize, 5), queue.stats().packet_number_copies);
    try std.testing.expectEqual(5 * "payload".len, queue.stats().payload_bytes);

    try std.testing.expectEqual(
        @as(usize, 0),
        try queue.applyAck(.{
            .largest_acknowledged = 99,
            .ack_delay = 0,
            .first_ack_range = 2,
        }),
    );
    try std.testing.expectEqual(@as(usize, 5), queue.pendingCount());
}

test "QUIC recovery single-range ACK falls back for out-of-order originals" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    _ = try queue.trackSent(10, "ten");
    _ = try queue.trackSent(2, "two");
    _ = try queue.trackSent(6, "six");

    try std.testing.expectEqual(
        @as(usize, 2),
        try queue.applyAck(.{
            .largest_acknowledged = 8,
            .ack_delay = 0,
            .first_ack_range = 6,
        }),
    );
    try std.testing.expectEqual(@as(usize, 1), queue.pendingCount());
    try std.testing.expectEqual(
        @as(u64, 10),
        queue.pending.items[0].original_packet_number.?,
    );
}

test "QUIC recovery single-range ACK falls back after original is forgotten" {
    const allocator = std.testing.allocator;
    var queue = Queue.init(allocator);
    defer queue.deinit();

    _ = try queue.trackSent(1, "payload");
    try queue.recordRetransmission(0, 4);
    try std.testing.expect(queue.forgetPacketNumber(1));
    try std.testing.expectEqual(
        @as(usize, 1),
        try queue.applyAck(.{
            .largest_acknowledged = 4,
            .ack_delay = 0,
            .first_ack_range = 0,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), queue.pendingCount());
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
