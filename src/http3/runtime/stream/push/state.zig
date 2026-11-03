const std = @import("std");
const http3 = @import("../../../mod.zig");
const quic = @import("../../../../quic/mod.zig");
const exact_range_set = @import("../../../../internal/exact_range_set.zig");
const wire = @import("../../../../internal/wire.zig");
const Error = @import("../../error.zig").Error;
const reader_module = @import("../reader.zig");
const Reader = reader_module.Reader;

const net = std.Io.net;

fn peekUniStreamType(stream: quic.StreamFrame) ?http3.StreamType {
    var prefix_cursor = wire.Cursor.init(stream.data);
    return @enumFromInt(quic.varint.decode(&prefix_cursor) catch return null);
}

pub const PushEvent = struct {
    push_id: u64,
    request_stream_id: u62,
    stream_id: u62,
    value: reader_module.Event,

    pub fn deinit(self: *PushEvent, allocator: std.mem.Allocator) void {
        self.value.deinit(allocator);
        self.* = undefined;
    }
};

pub const Set = struct {
    const PrefixResult = enum {
        incomplete,
        push,
        other,
    };

    const Entry = struct {
        receive: quic.stream_state.RecvState,
        reader: ?Reader = null,
        push_id: ?u64 = null,
        failure_pending: bool = false,
        from: ?net.IpAddress = null,

        pub fn deinit(self: *Entry) void {
            if (self.reader) |*reader| {
                reader.deinit();
            } else {
                self.receive.deinit();
            }
            self.* = undefined;
        }

        fn receiveState(self: *Entry) *quic.stream_state.RecvState {
            if (self.reader) |*reader| return reader.receiveState();
            return &self.receive;
        }

        fn streamId(self: *const Entry) u64 {
            if (self.reader) |reader| return reader.streamId();
            return self.receive.stream_id;
        }

        fn parsePrefix(
            self: *Entry,
            control: http3.ControlState,
            settings: http3.Settings,
            max_informational_responses: usize,
            max_body_bytes: usize,
        ) Error!PrefixResult {
            if (self.reader != null) return .push;
            const available = self.receive.available();
            var cursor = wire.Cursor.init(
                available,
            );
            const stream_type: http3.StreamType = @enumFromInt(
                quic.varint.decode(&cursor) catch |err| switch (err) {
                    error.BufferTooShort => {
                        if (self.receive.final_size != null) {
                            return error.InvalidStreamType;
                        }
                        return .incomplete;
                    },
                    else => return err,
                },
            );
            if (stream_type != .push) return .other;
            const push_id = quic.varint.decode(&cursor) catch |err| switch (err) {
                error.BufferTooShort => {
                    if (self.receive.final_size != null) {
                        return error.InvalidStreamType;
                    }
                    return .incomplete;
                },
                else => return err,
            };
            try http3.validatePushPromise(control, push_id);

            // Transfer the reassembler rather than copying payload bytes. The
            // message reader starts after both varints but keeps absolute QUIC
            // offsets for reset handling and receive-credit replenishment.
            try self.receive.consume(cursor.pos);
            const receive = self.receive;
            self.reader = .initPushFromReceive(
                receive.allocator,
                receive,
                settings,
                max_informational_responses,
            );
            self.reader.?.max_body_bytes = max_body_bytes;
            self.push_id = push_id;
            return .push;
        }
    };

    const Promise = struct {
        const State = enum {
            promised,
            active,
        };

        push_id: u64,
        request_stream_id: u62,
        state: State = .promised,
    };

    pub const ReadyEvent = struct {
        index: usize,
        event: PushEvent,
    };

    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    stream_index: std.AutoHashMapUnmanaged(u62, usize) = .empty,
    push_index: std.AutoHashMapUnmanaged(u64, usize) = .empty,
    /// QUIC stream ID of the last push that produced an untargeted event.
    /// Targeted push reads intentionally do not disturb this cursor.
    last_event_stream_id: ?u62 = null,
    last_error_stream_id: ?u62 = null,
    promises: std.ArrayList(Promise) = .empty,
    promise_index: std.AutoHashMapUnmanaged(u64, usize) = .empty,
    /// Exact lifetime history without one tombstone per completed push. RFC
    /// 9114 only recommends sequential Push IDs, so retain sparse merged
    /// ranges rather than assuming every lower ID was used.
    completed_promises: exact_range_set.Set = .{},
    /// Push IDs cancelled before or after their stream association arrives.
    /// Completion history alone cannot distinguish this legal late-stream
    /// case from a duplicate completed push.
    cancelled_push_history: exact_range_set.Set = .{},
    /// Cancelled Push IDs whose single push-stream association has already
    /// been observed. This preserves duplicate-Push-ID validation even when
    /// the first stream was drained instead of exposed to the application.
    cancelled_push_stream_seen: exact_range_set.Set = .{},
    /// Server-initiated unidirectional stream ordinals cancelled locally.
    /// This prevents reordered/in-flight STREAM frames from recreating a push
    /// reader after its CANCEL_PUSH transaction retired the active entry.
    cancelled_stream_ordinals: exact_range_set.Set = .{},
    /// Push IDs paired with `cancelled_stream_ids`. Entries exist only while
    /// a locally committed CANCEL_PUSH still needs a transport STOP_SENDING,
    /// so retry bookkeeping remains bounded by concurrent push streams.
    cancelled_push_ids: std.ArrayList(u64) = .empty,
    cancelled_stream_ids: std.ArrayList(u62) = .empty,
    cancelled_stream_head: usize = 0,
    max_streams: usize,
    max_stream_buffer: usize,
    max_informational_responses: usize,
    max_body_bytes: usize = std.math.maxInt(usize),
    settings: http3.Settings,

    /// Apply a cumulative body budget to existing push readers and future ones.
    pub fn setMaxBodyBytes(self: *Set, limit: usize) void {
        self.max_body_bytes = limit;
        for (self.entries.items) |*entry| {
            if (entry.reader) |*reader| reader.max_body_bytes = limit;
        }
    }

    pub fn init(
        allocator: std.mem.Allocator,
        max_streams: usize,
        max_stream_buffer: usize,
        settings: http3.Settings,
    ) Set {
        return initWithInformationalLimit(
            allocator,
            max_streams,
            max_stream_buffer,
            http3.default_max_informational_responses,
            settings,
        );
    }

    pub fn initWithInformationalLimit(
        allocator: std.mem.Allocator,
        max_streams: usize,
        max_stream_buffer: usize,
        max_informational_responses: usize,
        settings: http3.Settings,
    ) Set {
        return .{
            .allocator = allocator,
            .max_streams = max_streams,
            .max_stream_buffer = max_stream_buffer,
            .max_informational_responses = max_informational_responses,
            .settings = settings,
        };
    }

    pub fn deinit(self: *Set) void {
        for (self.entries.items) |*entry| entry.deinit();
        self.entries.deinit(self.allocator);
        self.stream_index.deinit(self.allocator);
        self.push_index.deinit(self.allocator);
        self.promises.deinit(self.allocator);
        self.promise_index.deinit(self.allocator);
        self.completed_promises.deinit(self.allocator);
        self.cancelled_push_history.deinit(self.allocator);
        self.cancelled_push_stream_seen.deinit(self.allocator);
        self.cancelled_stream_ordinals.deinit(self.allocator);
        self.cancelled_push_ids.deinit(self.allocator);
        self.cancelled_stream_ids.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn isIdle(self: Set) bool {
        return self.entries.items.len == 0 and
            self.promises.items.len == 0 and
            self.cancelledStreamCount() == 0;
    }

    pub fn entryAt(self: *Set, index: usize) ?*Entry {
        if (index >= self.entries.items.len) return null;
        return &self.entries.items[index];
    }

    pub fn entryReader(entry: *Entry) ?*Reader {
        if (entry.reader) |*reader| return reader;
        return null;
    }

    pub fn entryPeer(entry: *const Entry) ?net.IpAddress {
        return entry.from;
    }

    pub fn entryCount(self: Set) usize {
        return self.entries.items.len;
    }

    pub fn blockedStreamCount(
        self: *Set,
        table: http3.Qpack.DynamicTable,
    ) Error!u64 {
        var count: u64 = 0;
        for (self.entries.items) |entry| {
            if (entry.reader) |reader| {
                if (try reader.blockedByQpack(table)) count += 1;
            }
        }
        return count;
    }

    pub fn peerForStream(
        self: *Set,
        stream_id: u62,
    ) ?net.IpAddress {
        return (self.findByStreamId(stream_id) orelse return null).from;
    }

    pub fn containsStream(self: *Set, stream_id: u62) bool {
        return self.findByStreamId(stream_id) != null;
    }

    /// Borrow the active reader for transport flow-credit and retirement
    /// integration. The pointer is invalidated by entry insertion/removal.
    pub fn readerForStream(
        self: *Set,
        stream_id: u62,
    ) ?*Reader {
        const entry = self.findByStreamId(stream_id) orelse return null;
        if (entry.reader) |*reader| return reader;
        return null;
    }

    pub const Identity = struct { push_id: u64, request_stream_id: u62 };

    pub fn identityForStream(self: *Set, stream_id: u62) ?Identity {
        const entry = self.findByStreamId(stream_id) orelse return null;
        const push_id = entry.push_id orelse return null;
        const promise = self.findPromise(push_id) orelse return null;
        return .{ .push_id = push_id, .request_stream_id = promise.request_stream_id };
    }

    pub fn suspendFailedStream(self: *Set, stream_id: u62) void {
        if (self.findByStreamId(stream_id)) |entry| entry.failure_pending = true;
    }

    pub fn failurePending(self: *Set, stream_id: u62) bool {
        const entry = self.findByStreamId(stream_id) orelse return false;
        return entry.failure_pending;
    }

    pub fn entryFailurePending(entry: *const Entry) bool {
        return entry.failure_pending;
    }

    pub fn promiseCount(self: Set) usize {
        return self.promises.items.len;
    }

    /// Restore the promise registry to a checkpoint taken with
    /// `promiseCount`. Push streams that arrived before their promise remain
    /// buffered and can be rebound by a later valid response.
    pub fn rollbackPromises(self: *Set, checkpoint: usize) void {
        std.debug.assert(checkpoint <= self.promises.items.len);
        while (self.promises.items.len > checkpoint) {
            const promise = self.promises.pop().?;
            _ = self.promise_index.remove(promise.push_id);
        }
    }

    pub fn hasPromise(self: Set, push_id: u64) bool {
        return self.completed_promises.contains(push_id) or
            self.findPromise(push_id) != null;
    }

    pub fn promiseCompleted(self: Set, push_id: u64) bool {
        return self.completed_promises.contains(push_id);
    }

    /// True after a promise has reached a terminal state, including a locally
    /// committed CANCEL_PUSH whose transport STOP_SENDING may still be queued.
    pub fn pendingLocalCancellation(self: Set, push_id: u64) bool {
        for (self.cancelled_push_ids.items[self.cancelled_stream_head..]) |id| {
            if (id == push_id) return true;
        }
        return false;
    }

    pub fn isCancelledStream(self: Set, stream_id: u64) bool {
        if ((stream_id & 0x03) != 0x03) return false;
        return self.cancelled_stream_ordinals.contains(stream_id >> 2);
    }

    pub fn isCancelledPush(self: Set, push_id: u64) bool {
        return self.cancelled_push_history.contains(push_id);
    }

    pub fn completedPromiseRangeCount(self: Set) usize {
        return self.completed_promises.rangeCount();
    }

    pub fn reservePromisesThrough(
        self: *Set,
        push_id: u64,
    ) Error!void {
        _ = push_id;
        try self.promises.ensureTotalCapacity(
            self.allocator,
            self.max_streams,
        );
        try self.promise_index.ensureTotalCapacity(
            self.allocator,
            std.math.cast(u32, self.max_streams) orelse
                return error.OutOfMemory,
        );
        try self.cancelled_stream_ids.ensureTotalCapacity(
            self.allocator,
            self.max_streams,
        );
        try self.cancelled_push_ids.ensureTotalCapacity(
            self.allocator,
            self.max_streams,
        );
        try self.cancelled_stream_ordinals.prepareInsert(
            self.allocator,
            self.max_streams,
        );
        try self.cancelled_push_history.prepareInsert(
            self.allocator,
            self.max_streams,
        );
        try self.cancelled_push_stream_seen.prepareInsert(
            self.allocator,
            self.max_streams,
        );
    }

    pub fn registerPromise(
        self: *Set,
        push_id: u64,
        request_stream_id: u62,
    ) Error!void {
        // RFC 9114 permits the same push to be promised by multiple request
        // streams. The first parent remains the canonical correlation exposed
        // on push events.
        if (self.completed_promises.contains(push_id)) return;
        if (self.promises.items.len == self.promises.capacity) {
            if (self.promise_index.contains(push_id)) return;
            // MAX_PUSH_ID reserves one slot for every legal unique ID before
            // it is put on the wire, making event application allocation-free
            // after the request reader has transactionally consumed bytes.
            return error.ExcessiveLoad;
        }
        if (self.promise_index.contains(push_id)) return;
        // Every active promise can later become a disjoint completed range.
        // Reserve for all of them now so FIN/reset/cancellation retirement is
        // allocation-free after transport/application state has committed.
        try self.completed_promises.prepareInsert(
            self.allocator,
            self.promises.items.len + 1,
        );
        const slot = self.promise_index.getOrPutAssumeCapacity(push_id);
        std.debug.assert(!slot.found_existing);
        const index = self.promises.items.len;
        self.promises.appendAssumeCapacity(.{
            .push_id = push_id,
            .request_stream_id = request_stream_id,
        });
        slot.value_ptr.* = index;
        errdefer {
            _ = self.promise_index.remove(push_id);
            _ = self.promises.pop();
        }
        if (self.findByPushId(push_id)) |entry| {
            try self.validateBinding(entry);
        }
    }

    fn appendEntryAssumeCapacity(
        self: *Set,
        entry: Entry,
        stream_slot: *usize,
    ) *Entry {
        const index = self.entries.items.len;
        self.entries.appendAssumeCapacity(entry);
        stream_slot.* = index;
        if (self.entries.items[index].push_id) |push_id| {
            self.push_index.putAssumeCapacity(push_id, index);
        }
        return &self.entries.items[index];
    }

    fn rememberPushBinding(
        self: *Set,
        entry: *const Entry,
    ) Error!void {
        const push_id = entry.push_id orelse return;
        const stream_id: u62 = @intCast(entry.streamId());
        const index = self.stream_index.get(stream_id) orelse return;
        const slot = try self.push_index.getOrPut(self.allocator, push_id);
        if (slot.found_existing) {
            if (slot.value_ptr.* != index) return error.DuplicatePushId;
            return;
        }
        slot.value_ptr.* = index;
    }

    fn takeEntryAt(self: *Set, index: usize) Entry {
        const last_index = self.entries.items.len - 1;
        const removed = self.entries.swapRemove(index);
        _ = self.stream_index.remove(@intCast(removed.streamId()));
        if (removed.push_id) |push_id| _ = self.push_index.remove(push_id);
        if (index != last_index) {
            const moved = self.entries.items[index];
            self.stream_index.getPtr(@intCast(moved.streamId())).?.* = index;
            if (moved.push_id) |push_id| {
                self.push_index.getPtr(push_id).?.* = index;
            }
        }
        return removed;
    }

    pub fn insert(
        self: *Set,
        from: net.IpAddress,
        frame: quic.StreamFrame,
        control: http3.ControlState,
    ) Error!bool {
        if ((frame.stream_id & 0x03) != 0x03) return false;
        if (self.findByStreamId(frame.stream_id)) |entry| {
            if (entry.from) |existing| {
                if (!existing.eql(&from)) return error.UnexpectedStream;
            }
            const receive = entry.receiveState();
            try receive.insert(frame);
            switch (try entry.parsePrefix(
                control,
                self.settings,
                self.max_informational_responses,
                self.max_body_bytes,
            )) {
                .incomplete => {},
                .push => {
                    if (entry.push_id) |push_id| {
                        if (self.isCancelledPush(push_id)) {
                            if (self.cancelled_push_stream_seen.contains(
                                push_id,
                            )) return error.DuplicatePushId;
                            try self.prepareCancelledStreamQueue(
                                push_id,
                                @intCast(frame.stream_id),
                            );
                            self.queueCancelledStreamAssumeCapacity(
                                push_id,
                                @intCast(frame.stream_id),
                            );
                            self.removeStream(frame.stream_id);
                            return true;
                        }
                    }
                    try self.validateBinding(entry);
                    try self.rememberPushBinding(entry);
                },
                .other => {
                    self.removeStream(frame.stream_id);
                    return false;
                },
            }
            return true;
        }
        // Buffer unmatched nonzero ranges even when offset zero is reordered
        // behind them. At offset zero the one-byte push type must already be
        // visible; never steal a fragmented unknown/critical stream from its
        // dedicated router.
        if (frame.offset == 0) {
            const stream_type = peekUniStreamType(frame) orelse {
                if (frame.fin) return error.InvalidStreamType;
                return false;
            };
            if (stream_type != .push) return false;
        }
        if (self.entries.items.len >= self.max_streams) {
            return error.ExcessiveLoad;
        }
        const stream_id: u62 = @intCast(frame.stream_id);
        const stream_slot = try self.stream_index.getOrPut(
            self.allocator,
            stream_id,
        );
        std.debug.assert(!stream_slot.found_existing);
        errdefer _ = self.stream_index.remove(stream_id);
        try self.entries.ensureUnusedCapacity(self.allocator, 1);
        const entry = self.appendEntryAssumeCapacity(.{
            .receive = .init(
                self.allocator,
                frame.stream_id,
                self.max_stream_buffer,
            ),
            .from = from,
        }, stream_slot.value_ptr);
        errdefer {
            var removed = self.takeEntryAt(self.entries.items.len - 1);
            removed.deinit();
        }
        try entry.receive.insert(frame);
        switch (try entry.parsePrefix(
            control,
            self.settings,
            self.max_informational_responses,
            self.max_body_bytes,
        )) {
            .incomplete => {},
            .push => {
                if (entry.push_id) |push_id| {
                    if (self.isCancelledPush(push_id)) {
                        if (self.cancelled_push_stream_seen.contains(
                            push_id,
                        )) return error.DuplicatePushId;
                        try self.prepareCancelledStreamQueue(
                            push_id,
                            @intCast(frame.stream_id),
                        );
                        self.queueCancelledStreamAssumeCapacity(
                            push_id,
                            @intCast(frame.stream_id),
                        );
                        self.removeStream(frame.stream_id);
                        return true;
                    }
                }
                try self.validateBinding(entry);
                try self.rememberPushBinding(entry);
            },
            .other => {
                self.removeStream(frame.stream_id);
                return false;
            },
        }
        return true;
    }

    pub fn next(
        self: *Set,
        table: http3.Qpack.DynamicTable,
        max_blocked_streams: u64,
        target_push_id: ?u64,
    ) Error!?ReadyEvent {
        self.last_error_stream_id = null;
        if (target_push_id) |push_id| {
            if (self.push_index.count() == 0) return null;
            const index = self.push_index.get(push_id) orelse return null;
            return self.nextEntryEvent(
                index,
                table,
                max_blocked_streams,
            );
        }

        const entry_count = self.entries.items.len;
        if (entry_count == 0) {
            self.last_event_stream_id = null;
            return null;
        }

        // Push streams use the same stable-ID cursor discipline as request and
        // response streams. `takeEntryAt` swap-removes entries, so a stale
        // cursor restarts a complete scan instead of relying on an old index.
        var index: usize = 0;
        if (self.last_event_stream_id) |stream_id| {
            if (self.stream_index.get(stream_id)) |previous_index| {
                index = if (previous_index + 1 == entry_count)
                    0
                else
                    previous_index + 1;
            }
        }

        var blocked_streams: u64 = 0;
        var remaining = entry_count;
        while (remaining != 0) : (remaining -= 1) {
            const entry = &self.entries.items[index];
            if (entry.failure_pending) {
                index = if (index + 1 == entry_count) 0 else index + 1;
                continue;
            }
            if (entry.reader) |*reader| {
                const push_id = entry.push_id orelse unreachable;
                if (self.findPromise(push_id)) |promise| {
                    const event = reader.next(table) catch |err| switch (err) {
                        error.QpackBlocked => {
                            blocked_streams += 1;
                            if (blocked_streams > max_blocked_streams) {
                                self.last_error_stream_id =
                                    reader.streamId();
                                return error.QpackDecompressionFailed;
                            }
                            index = if (index + 1 == entry_count)
                                0
                            else
                                index + 1;
                            continue;
                        },
                        else => {
                            self.last_error_stream_id = reader.streamId();
                            return err;
                        },
                    };
                    if (event) |value| {
                        const stream_id = reader.streamId();
                        self.last_event_stream_id = stream_id;
                        return .{
                            .index = index,
                            .event = .{
                                .push_id = push_id,
                                .request_stream_id = promise.request_stream_id,
                                .stream_id = stream_id,
                                .value = value,
                            },
                        };
                    }
                }
            }
            index = if (index + 1 == entry_count) 0 else index + 1;
        }
        return null;
    }

    /// Reconstruct a terminal event whose reader reached `done` before the
    /// caller could return its final receive credit. This keeps once-poll
    /// users from losing FIN when transport feedback is temporarily paced.
    pub fn nextFinished(
        self: *Set,
        target_push_id: ?u64,
    ) ?ReadyEvent {
        if (target_push_id) |push_id| {
            const index = self.push_index.get(push_id) orelse return null;
            return self.finishedEntryEvent(index);
        }
        for (self.entries.items, 0..) |*entry, index| {
            if (entry.reader == null or !entry.reader.?.finished()) continue;
            if (self.finishedEntryEvent(index)) |ready| return ready;
        }
        return null;
    }

    fn finishedEntryEvent(self: *Set, index: usize) ?ReadyEvent {
        if (index >= self.entries.items.len) return null;
        const entry = &self.entries.items[index];
        if (entry.failure_pending) return null;
        const reader = if (entry.reader) |*value| value else return null;
        if (!reader.finished()) return null;
        const push_id = entry.push_id orelse return null;
        const promise = self.findPromise(push_id) orelse return null;
        self.last_event_stream_id = reader.streamId();
        return .{
            .index = index,
            .event = .{
                .push_id = push_id,
                .request_stream_id = promise.request_stream_id,
                .stream_id = reader.streamId(),
                .value = .finished,
            },
        };
    }

    fn nextEntryEvent(
        self: *Set,
        index: usize,
        table: http3.Qpack.DynamicTable,
        remaining_blocked_budget: u64,
    ) Error!?ReadyEvent {
        if (index >= self.entries.items.len) return null;
        const entry = &self.entries.items[index];
        if (entry.failure_pending or entry.reader == null) return null;
        const push_id = entry.push_id orelse return null;
        const promise = self.findPromise(push_id) orelse return null;
        const event = entry.reader.?.next(table) catch |err| switch (err) {
            error.QpackBlocked => {
                if (remaining_blocked_budget == 0) {
                    self.last_error_stream_id = entry.reader.?.streamId();
                    return error.QpackDecompressionFailed;
                }
                return null;
            },
            else => {
                self.last_error_stream_id = entry.reader.?.streamId();
                return err;
            },
        };
        if (event) |value| {
            return .{
                .index = index,
                .event = .{
                    .push_id = push_id,
                    .request_stream_id = promise.request_stream_id,
                    .stream_id = entry.reader.?.streamId(),
                    .value = value,
                },
            };
        }
        return null;
    }

    pub fn observePeerCancellation(
        self: *Set,
        push_id: u64,
    ) Error!void {
        if (self.completed_promises.contains(push_id)) return;
        _ = self.findPromise(push_id) orelse return error.UnexpectedStream;
        if (self.findByPushId(push_id)) |entry| {
            const stream_id: u62 = @intCast(entry.streamId());
            if (self.cancelled_stream_head != 0 and
                self.cancelled_stream_ids.items.len ==
                    self.cancelled_stream_ids.capacity)
            {
                self.compactCancelledStreamQueue();
            }
            if (self.cancelled_stream_ids.items.len ==
                self.cancelled_stream_ids.capacity)
            {
                return error.ExcessiveLoad;
            }
            std.debug.assert(
                self.cancelled_push_ids.items.len <
                    self.cancelled_push_ids.capacity,
            );
            self.queueCancelledStreamAssumeCapacity(push_id, stream_id);
            self.removeStream(stream_id);
        }
        self.cancelled_push_history.insertAssumeCapacity(push_id);
        self.retirePromiseAssumeCapacity(push_id);
    }

    /// Complete every fallible local check/allocation needed before a
    /// CANCEL_PUSH becomes socket-visible. The caller may then send once and
    /// commit with `observePeerCancellation` without risking split wire/local
    /// state.
    pub fn preparePeerCancellation(
        self: *Set,
        push_id: u64,
    ) Error!void {
        if (self.completed_promises.contains(push_id)) return;
        _ = self.findPromise(push_id) orelse return error.UnexpectedStream;
        if (self.findByPushId(push_id)) |entry| {
            try self.prepareCancelledStreamQueue(
                push_id,
                @intCast(entry.streamId()),
            );
        }
        try self.completed_promises.prepareInsert(
            self.allocator,
            self.promises.items.len,
        );
        try self.cancelled_push_history.prepareInsertValue(
            self.allocator,
            push_id,
        );
    }

    pub fn takeCancelledStream(self: *Set) ?u62 {
        if (self.cancelledStreamCount() == 0) return null;
        _ = self.cancelled_push_ids.items[self.cancelled_stream_head];
        const stream_id = self.cancelled_stream_ids.items[self.cancelled_stream_head];
        self.cancelled_stream_head += 1;
        self.compactCancelledStreamQueueIfSparse();
        return stream_id;
    }

    pub fn firstCancelledStream(self: Set) ?u62 {
        if (self.cancelledStreamCount() == 0) return null;
        return self.cancelled_stream_ids.items[self.cancelled_stream_head];
    }

    pub fn readData(
        self: *Set,
        push_id: u64,
        out: []u8,
    ) Error!usize {
        const entry = self.findByPushId(push_id) orelse
            return error.UnexpectedStream;
        return entry.reader.?.readData(out);
    }

    pub fn removeFinished(self: *Set, index: usize) void {
        const push_id = self.entries.items[index].push_id.?;
        self.retirePromiseAssumeCapacity(push_id);
        var removed = self.takeEntryAt(index);
        removed.deinit();
    }

    pub fn hasUnacknowledgedDynamicSection(
        self: *Set,
        stream_id: u62,
        table: http3.Qpack.DynamicTable,
    ) Error!bool {
        const entry = self.findByStreamId(stream_id) orelse return false;
        if (entry.reader) |reader| {
            return reader.hasUnacknowledgedDynamicSection(table);
        }
        return false;
    }

    pub fn removeByStreamId(self: *Set, stream_id: u62) void {
        self.removeStream(stream_id);
    }

    pub fn failStream(self: *Set, stream_id: u62) void {
        const entry = self.findByStreamId(stream_id) orelse return;
        if (entry.push_id) |push_id| {
            if (self.findPromise(push_id) != null) {
                self.retirePromiseAssumeCapacity(push_id);
            }
        }
        self.removeStream(stream_id);
    }

    pub fn retireFailedPromise(self: *Set, push_id: u64) void {
        if (self.findPromise(push_id) != null) self.retirePromiseAssumeCapacity(push_id);
    }

    pub fn lastErrorStreamId(self: Set) ?u62 {
        return self.last_error_stream_id;
    }

    pub fn cancelledStreamCount(self: Set) usize {
        return self.cancelled_stream_ids.items.len -
            self.cancelled_stream_head;
    }

    fn compactCancelledStreamQueueIfSparse(self: *Set) void {
        if (self.cancelled_stream_head == 0) return;
        if (self.cancelled_stream_head == self.cancelled_stream_ids.items.len or
            self.cancelled_stream_head >=
                self.cancelled_stream_ids.items.len / 2)
        {
            self.compactCancelledStreamQueue();
        }
    }

    fn compactCancelledStreamQueue(self: *Set) void {
        if (self.cancelled_stream_head == 0) return;
        const remaining = self.cancelledStreamCount();
        if (remaining != 0) {
            @memmove(
                self.cancelled_push_ids.items[0..remaining],
                self.cancelled_push_ids.items[self.cancelled_stream_head..],
            );
            @memmove(
                self.cancelled_stream_ids.items[0..remaining],
                self.cancelled_stream_ids.items[self.cancelled_stream_head..],
            );
        }
        self.cancelled_push_ids.items.len = remaining;
        self.cancelled_stream_ids.items.len = remaining;
        self.cancelled_stream_head = 0;
    }

    fn queueCancelledStreamAssumeCapacity(
        self: *Set,
        push_id: u64,
        stream_id: u62,
    ) void {
        if (self.cancelled_stream_head != 0 and
            self.cancelled_stream_ids.items.len ==
                self.cancelled_stream_ids.capacity)
        {
            self.compactCancelledStreamQueue();
        }
        std.debug.assert(
            self.cancelled_push_ids.items.len <
                self.cancelled_push_ids.capacity,
        );
        std.debug.assert(
            self.cancelled_stream_ids.items.len <
                self.cancelled_stream_ids.capacity,
        );
        self.cancelled_push_ids.appendAssumeCapacity(push_id);
        self.cancelled_stream_ids.appendAssumeCapacity(stream_id);
        self.cancelled_stream_ordinals.insertAssumeCapacity(stream_id >> 2);
        self.cancelled_push_stream_seen.insertAssumeCapacity(push_id);
    }

    fn prepareCancelledStreamQueue(
        self: *Set,
        push_id: u64,
        stream_id: u62,
    ) Error!void {
        if (self.cancelled_stream_head != 0 and
            self.cancelled_stream_ids.items.len ==
                self.cancelled_stream_ids.capacity)
        {
            self.compactCancelledStreamQueue();
        }
        try self.cancelled_stream_ids.ensureUnusedCapacity(
            self.allocator,
            1,
        );
        try self.cancelled_push_ids.ensureUnusedCapacity(
            self.allocator,
            1,
        );
        try self.cancelled_stream_ordinals.prepareInsertValue(
            self.allocator,
            stream_id >> 2,
        );
        try self.cancelled_push_stream_seen.prepareInsertValue(
            self.allocator,
            push_id,
        );
    }

    fn findByStreamId(self: *Set, stream_id: u64) ?*Entry {
        const key = std.math.cast(u62, stream_id) orelse return null;
        if (self.stream_index.count() == 0) return null;
        const index = self.stream_index.get(key) orelse return null;
        if (index >= self.entries.items.len) return null;
        return &self.entries.items[index];
    }

    pub fn findByPushId(self: *Set, push_id: u64) ?*Entry {
        if (self.push_index.count() == 0) return null;
        const index = self.push_index.get(push_id) orelse return null;
        if (index >= self.entries.items.len) return null;
        return &self.entries.items[index];
    }

    pub fn streamIdForPush(self: *Set, push_id: u64) ?u62 {
        const entry = self.findByPushId(push_id) orelse return null;
        return @intCast(entry.streamId());
    }

    fn removeStream(self: *Set, stream_id: u64) void {
        const key = std.math.cast(u62, stream_id) orelse return;
        if (self.stream_index.count() == 0) return;
        const index = self.stream_index.get(key) orelse return;
        var removed = self.takeEntryAt(index);
        removed.deinit();
    }

    fn validateBinding(self: Set, entry: *const Entry) Error!void {
        const push_id = entry.push_id orelse return;
        // QUIC does not preserve ordering across streams, so the push stream
        // may arrive before the request stream carrying PUSH_PROMISE. Retain
        // it, but `next` will not expose response events until the promise is
        // registered by the request-stream decoder.
        const stream_id: u62 = @intCast(entry.streamId());
        const entry_index = self.stream_index.get(stream_id) orelse return;
        if (self.push_index.get(push_id)) |existing_index| {
            if (existing_index != entry_index) return error.DuplicatePushId;
        }
        if (self.findPromise(push_id)) |promise| {
            promise.state = .active;
        } else if (self.completed_promises.contains(push_id)) {
            return error.DuplicatePushId;
        }
    }

    pub fn appendPromisedIds(
        self: Set,
        out: *std.ArrayList(u64),
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!void {
        try out.ensureUnusedCapacity(allocator, self.promises.items.len);
        for (self.promises.items) |promise| {
            out.appendAssumeCapacity(promise.push_id);
        }
    }

    fn findPromise(self: Set, push_id: u64) ?*Promise {
        if (self.promise_index.count() == 0) return null;
        const index = self.promise_index.get(push_id) orelse return null;
        if (index >= self.promises.items.len) return null;
        return &self.promises.items[index];
    }

    fn retirePromiseAssumeCapacity(self: *Set, push_id: u64) void {
        const index = self.promise_index.get(push_id) orelse return;
        self.completed_promises.insertAssumeCapacity(push_id);
        _ = self.promise_index.remove(push_id);
        const last_index = self.promises.items.len - 1;
        _ = self.promises.swapRemove(index);
        if (index != last_index) {
            const moved = self.promises.items[index];
            self.promise_index.getPtr(moved.push_id).?.* = index;
        }
    }
};
