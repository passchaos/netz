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

/// One retransmittable frame kind that names a stream. Pending payloads are
/// immutable after encoding, so the parsed references are cached to keep
/// per-stream credit queries from re-decoding every queued frame.
const StreamRef = struct {
    stream_id: u64,
    reset: bool,
};

const max_cached_stream_refs: usize = 4;

const StreamRefs = struct {
    refs: [max_cached_stream_refs]StreamRef = undefined,
    count: u8 = 0,
    state: enum { unknown, ready, overflow } = .unknown,

    fn push(self: *StreamRefs, ref: StreamRef) bool {
        if (self.count == self.refs.len) {
            self.state = .overflow;
            return false;
        }
        self.refs[self.count] = ref;
        self.count += 1;
        return true;
    }

    /// Build references from the frames the packetizer already knows. Send
    /// paths use this so recovery never has to decode its own payload to
    /// answer per-stream delivery queries.
    fn fromFrames(frames: []const quic.Frame) StreamRefs {
        var refs: StreamRefs = .{ .state = .ready };
        for (frames) |frame| switch (frame) {
            .stream => |stream| {
                if (!refs.push(.{
                    .stream_id = stream.stream_id,
                    .reset = false,
                })) return refs;
            },
            .reset_stream => |reset| {
                if (!refs.push(.{
                    .stream_id = reset.stream_id,
                    .reset = true,
                })) return refs;
            },
            .reset_stream_at => |reset| {
                if (!refs.push(.{
                    .stream_id = reset.stream_id,
                    .reset = true,
                })) return refs;
            },
            else => {},
        };
        return refs;
    }
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
    /// Cached STREAM/RESET_STREAM frame references. Populated eagerly by the
    /// send path (or lazily for callers that only provide encoded bytes);
    /// payload bytes never change after encoding.
    stream_refs: StreamRefs = .{},

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
    pub fn payload(self: PendingDatagram) []const u8 {
        return self.payload_storage[0..self.payload_len];
    }
    pub fn newestPacketNumber(self: PendingDatagram) u64 {
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
    /// Number of pending payloads carrying a STREAM frame per stream. Close
    /// and credit queries run many times per acknowledgement, so the queue
    /// keeps these counters instead of decoding every pending payload.
    pending_data_streams: std.AutoHashMapUnmanaged(u64, u32) = .empty,
    /// Number of pending payloads carrying a RESET_STREAM(_AT) frame per
    /// stream.
    pending_reset_streams: std.AutoHashMapUnmanaged(u64, u32) = .empty,
    /// Pending payloads whose stream references have not been decoded yet.
    unknown_stream_refs: usize = 0,
    /// Pending payloads with more stream references than fit inline. While
    /// nonzero every per-stream query answers conservatively, matching the
    /// previous scan behavior.
    overflow_stream_refs: usize = 0,
    payload_cache: payload_cache.Cache,

    pub fn init(allocator: std.mem.Allocator) Queue {
        return .{
            .allocator = allocator,
            .payload_cache = .init(allocator),
        };
    }

    pub fn deinit(self: *Queue) void {
        self.pending_data_streams.deinit(self.allocator);
        self.pending_reset_streams.deinit(self.allocator);
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
        var refs: StreamRefs = .{};
        Queue.parseStreamRefs(payload, &refs);
        const tracked = try self.trackSentWithRefs(
            packet_number,
            payload.len,
            &refs,
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
        return self.trackSentWithRefs(
            packet_number,
            payload_len,
            &.{},
        );
    }

    /// Track a packet whose retransmittable frames the packetizer already
    /// knows. Deriving the stream references from `frames` keeps close-time
    /// delivery queries O(1) without decoding the encoded payload.
    pub fn trackSentUninitializedWithFrames(
        self: *Queue,
        packet_number: u64,
        payload_len: usize,
        frames: []const quic.Frame,
    ) Error!UninitializedPayload {
        const refs = StreamRefs.fromFrames(frames);
        return self.trackSentWithRefs(
            packet_number,
            payload_len,
            &refs,
        );
    }

    fn trackSentWithRefs(
        self: *Queue,
        packet_number: u64,
        payload_len: usize,
        refs: *const StreamRefs,
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
        try self.reserveStreamRefCapacity(refs);
        const payload_storage = self.payload_cache.acquire(
            payload_len,
        ) catch return error.OutOfMemory;
        errdefer self.payload_cache.release(payload_storage);
        var entry = PendingDatagram.initOwned(
            group_id,
            packet_number,
            payload_storage,
            payload_len,
        );
        entry.stream_refs = refs.*;
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

    /// Return whether this already-validated ACK covers any packet-number copy
    /// of one recovery group. ACK_FREQUENCY uses this before retiring the group
    /// so the acknowledged request can update the sender's PTO model.
    pub fn ackAcknowledgesGroup(
        self: *const Queue,
        group_id: u64,
        ack: quic.AckFrame,
    ) bool {
        for (self.pending.items) |*entry| {
            if (entry.group_id != group_id) continue;
            return entryAcked(entry, ack);
        }
        return false;
    }

    /// Whether retransmittable STREAM data, including FIN, is still awaiting
    /// acknowledgement for `stream_id`. This is used only at stream-close
    /// boundaries; keeping recovery payloads encoded avoids per-packet stream
    /// metadata on the normal send/ACK path.
    pub fn hasPendingStreamData(self: *Queue, stream_id: u64) bool {
        return self.hasPendingStreamFrame(stream_id, false);
    }

    /// Whether a RESET_STREAM for `stream_id` is still awaiting acknowledgement.
    pub fn hasPendingResetStream(self: *Queue, stream_id: u64) bool {
        return self.hasPendingStreamFrame(stream_id, true);
    }

    fn hasPendingStreamFrame(
        self: *Queue,
        stream_id: u64,
        reset_only: bool,
    ) bool {
        if (self.unknown_stream_refs != 0 and
            !self.materializeUnknownStreamRefs())
        {
            return self.scanPendingStreamFrame(stream_id, reset_only);
        }
        if (self.overflow_stream_refs != 0) return true;
        const map = if (reset_only)
            &self.pending_reset_streams
        else
            &self.pending_data_streams;
        return (map.get(stream_id) orelse 0) != 0;
    }

    /// Decode and count every payload whose references are still unknown.
    /// Returns false only when growing the counters fails; the caller then
    /// falls back to scanning so OOM never changes a delivery answer.
    fn materializeUnknownStreamRefs(self: *Queue) bool {
        for (self.pending.items) |*entry| {
            if (entry.stream_refs.state != .unknown) continue;
            var refs: StreamRefs = .{};
            Queue.parseStreamRefs(entry.payload(), &refs);
            self.reserveStreamRefCapacity(&refs) catch return false;
            self.uncountStreamRefs(&entry.stream_refs);
            entry.stream_refs = refs;
            self.countStreamRefsAssumeCapacity(&entry.stream_refs);
        }
        return true;
    }

    /// Conservative fallback used only when counter growth fails. Unknown
    /// entries are parsed into a local so the counter bookkeeping stays
    /// consistent (`unknown_stream_refs` still covers them).
    fn scanPendingStreamFrame(
        self: *Queue,
        stream_id: u64,
        reset_only: bool,
    ) bool {
        var index = self.pending.items.len;
        while (index != 0) {
            index -= 1;
            const entry = &self.pending.items[index];
            var parsed: StreamRefs = .{};
            const refs = if (entry.stream_refs.state == .unknown) blk: {
                Queue.parseStreamRefs(entry.payload(), &parsed);
                break :blk &parsed;
            } else &entry.stream_refs;
            if (refs.state == .overflow) return true;
            for (refs.refs[0..refs.count]) |ref| {
                if (ref.reset != reset_only) continue;
                if (ref.stream_id == stream_id) return true;
            }
        }
        return false;
    }

    fn streamRefMap(
        self: *Queue,
        reset: bool,
    ) *std.AutoHashMapUnmanaged(u64, u32) {
        return if (reset)
            &self.pending_reset_streams
        else
            &self.pending_data_streams;
    }

    fn reserveStreamRefCapacity(
        self: *Queue,
        refs: *const StreamRefs,
    ) Error!void {
        switch (refs.state) {
            .unknown, .overflow => {},
            .ready => for (refs.refs[0..refs.count]) |ref| {
                try self.streamRefMap(ref.reset).ensureUnusedCapacity(
                    self.allocator,
                    1,
                );
            },
        }
    }

    fn countStreamRefsAssumeCapacity(
        self: *Queue,
        refs: *const StreamRefs,
    ) void {
        switch (refs.state) {
            .unknown => self.unknown_stream_refs += 1,
            .overflow => self.overflow_stream_refs += 1,
            .ready => for (refs.refs[0..refs.count]) |ref| {
                const map = self.streamRefMap(ref.reset);
                const result = map.getOrPutAssumeCapacity(ref.stream_id);
                if (!result.found_existing) result.value_ptr.* = 0;
                result.value_ptr.* += 1;
            },
        }
    }

    fn uncountStreamRefs(self: *Queue, refs: *const StreamRefs) void {
        switch (refs.state) {
            .unknown => self.unknown_stream_refs -= 1,
            .overflow => self.overflow_stream_refs -= 1,
            .ready => for (refs.refs[0..refs.count]) |ref| {
                const map = self.streamRefMap(ref.reset);
                const count = map.getPtr(ref.stream_id) orelse continue;
                std.debug.assert(count.* != 0);
                count.* -= 1;
                if (count.* == 0) _ = map.remove(ref.stream_id);
            },
        }
    }

    /// Parse one pending payload into its cached stream references. Returns
    /// `.overflow` when the payload carries more references than fit inline or
    /// cannot be decoded, which keeps the original conservative behavior.
    fn parseStreamRefs(payload: []const u8, refs: *StreamRefs) void {
        refs.count = 0;
        refs.state = .ready;
        var pos: usize = 0;
        while (pos < payload.len) {
            const parsed = quic.parseFrame(payload[pos..]) catch {
                refs.state = .overflow;
                return;
            };
            switch (parsed.frame) {
                .stream => |stream| {
                    if (!refs.push(.{ .stream_id = stream.stream_id, .reset = false })) return;
                },
                .reset_stream => |reset| {
                    if (!refs.push(.{ .stream_id = reset.stream_id, .reset = true })) return;
                },
                .reset_stream_at => |reset| {
                    if (!refs.push(.{ .stream_id = reset.stream_id, .reset = true })) return;
                },
                else => {},
            }
            if (parsed.consumed == 0) {
                refs.state = .overflow;
                return;
            }
            pos += parsed.consumed;
        }
    }

    /// Stop retransmitting STREAM data after the application terminates that
    /// send side with RESET_STREAM. Mixed payload groups are compacted in
    /// place so unrelated reliable frames retain their packet group and ACK
    /// identity without another allocation.
    pub fn abandonStreamData(self: *Queue, stream_id: u64) usize {
        return self.abandonStreamFrames(stream_id, .data, 0);
    }

    /// Retain only STREAM frames that can contribute to the reliable prefix
    /// of RESET_STREAM_AT. A frame crossing the boundary is retained whole;
    /// retransmitting the small suffix is permitted and avoids rewriting
    /// recovery payloads in place.
    pub fn abandonStreamDataAfter(
        self: *Queue,
        stream_id: u64,
        reliable_size: u64,
    ) usize {
        return self.abandonStreamFrames(
            stream_id,
            .data_after,
            reliable_size,
        );
    }

    /// Drop reset signals superseded by a smaller Reliable Size. The newly
    /// submitted smallest reset remains tracked and therefore retransmittable.
    pub fn abandonStreamResetsAbove(
        self: *Queue,
        stream_id: u64,
        reliable_size: u64,
    ) usize {
        return self.abandonStreamFrames(
            stream_id,
            .reset_above,
            reliable_size,
        );
    }

    /// Drop every stream-scoped frame that has become obsolete once both
    /// directions are terminal and the active stream state is reclaimed.
    pub fn abandonClosedStreamFrames(
        self: *Queue,
        stream_id: u64,
    ) usize {
        return self.abandonStreamFrames(stream_id, .closed, 0);
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

    const AbandonStreamFrames = enum {
        data,
        data_after,
        reset_above,
        closed,
    };

    fn abandonStreamFrames(
        self: *Queue,
        stream_id: u64,
        mode: AbandonStreamFrames,
        reliable_size: u64,
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
                    .stream => |stream| stream.stream_id == stream_id and switch (mode) {
                        .data, .closed => true,
                        .data_after => stream.offset >= reliable_size,
                        .reset_above => false,
                    },
                    .reset_stream => |reset| mode == .closed and
                        reset.stream_id == stream_id,
                    .reset_stream_at => |reset| reset.stream_id == stream_id and
                        (mode == .closed or
                            (mode == .reset_above and
                                reset.reliable_size > reliable_size)),
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
            // Compaction rewrote the encoded frames, so the parsed stream
            // references must be recomputed on the next query.
            if (entry.stream_refs.state != .unknown) {
                self.uncountStreamRefs(&entry.stream_refs);
                entry.stream_refs = .{};
                self.countStreamRefsAssumeCapacity(&entry.stream_refs);
            }
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

    pub fn applyAck(self: *Queue, ack: quic.AckFrame) align(32) Error!usize {
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
        return self.retainUnacknowledgedAck(ack, smallest);
    }

    fn retainUnacknowledgedAck(
        self: *Queue,
        ack: quic.AckFrame,
        smallest_acknowledged: u64,
    ) usize {
        if (ack.ranges.len == 0 and
            self.retransmission_copies == 0 and
            self.originals_sorted_ascending)
        {
            return self.retainOutsideSingleOriginalRange(
                ack.largest_acknowledged - ack.first_ack_range,
                ack.largest_acknowledged,
            );
        }
        if (self.retransmission_copies == 0 and
            self.originals_sorted_ascending)
        {
            return self.retainOutsideSortedOriginalRanges(
                ack,
                smallest_acknowledged,
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

    /// Merge an ascending original-packet queue with ACK ranges that are
    /// encoded from highest to lowest. Starting at the already-validated
    /// lowest range lets both inputs advance once, avoiding the general
    /// O(packets * ranges) membership scan.
    fn retainOutsideSortedOriginalRanges(
        self: *Queue,
        ack: quic.AckFrame,
        smallest_acknowledged: u64,
    ) usize {
        std.debug.assert(ack.ranges.len != 0);
        std.debug.assert(self.retransmission_copies == 0);
        std.debug.assert(self.originals_sorted_ascending);

        var range_index = ack.ranges.len;
        var range_start = smallest_acknowledged;
        var range_end = range_start +
            ack.ranges[ack.ranges.len - 1].ack_range_length;
        var write_index: usize = 0;
        var removed: usize = 0;
        var removed_payload_bytes: usize = 0;

        for (self.pending.items, 0..) |*entry, read_index| {
            const packet_number = entry.original_packet_number.?;
            while (packet_number > range_end and range_index != 0) {
                const relation = ack.ranges[range_index - 1];
                range_start = range_end + relation.gap + 2;
                range_index -= 1;
                range_end = if (range_index == 0)
                    ack.largest_acknowledged
                else
                    range_start +
                        ack.ranges[range_index - 1].ack_range_length;
            }
            const acknowledged = packet_number >= range_start and
                packet_number <= range_end;
            if (acknowledged) {
                removed_payload_bytes += entry.payload_len;
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
        // This ordered-original path is selected only when there are no
        // retransmission copies, so every retired entry contributes exactly
        // one packet number. Update aggregate counters once per ACK instead of
        // repeating saturating arithmetic for every acknowledged packet.
        self.packet_number_copies -|= removed;
        self.payload_bytes -|= removed_payload_bytes;
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

        var removed_payload_bytes: usize = 0;
        for (self.pending.items[remove_start..remove_end]) |*entry| {
            removed_payload_bytes += entry.payload_len;
            self.recycleEntry(entry);
        }
        const removed = remove_end - remove_start;
        self.packet_number_copies -|= removed;
        self.payload_bytes -|= removed_payload_bytes;
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
        self.countStreamRefsAssumeCapacity(
            &self.pending.items[self.pending.items.len - 1].stream_refs,
        );
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
        self.uncountStreamRefs(&entry.stream_refs);
        entry.retransmission_packet_numbers.deinit(self.allocator);
        self.payload_cache.release(entry.payload_storage);
        entry.* = undefined;
    }
};

test {
    _ = @import("recovery/tests.zig");
}
