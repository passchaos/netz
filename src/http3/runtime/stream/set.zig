const std = @import("std");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const Error = @import("../error.zig").Error;
const stream_reader = @import("reader.zig");
const buffered_request = @import("buffered/request.zig");
const buffered_response = @import("buffered/response.zig");

const net = std.Io.net;
const Reader = stream_reader.Reader;
const Event = stream_reader.Event;
const RequestStreamSet = buffered_request.Set;
const ResponseStreamSet = buffered_response.Set;

pub const Set = struct {
    pub const Kind = enum { request, response };
    pub const ReadyEvent = struct {
        entry: *Entry,
        event: Event,
    };

    pub const Reset = struct {
        from: net.IpAddress,
        stream_id: u62,
        application_error_code: u64,
    };

    pub const Entry = struct {
        reader: Reader,
        from: ?net.IpAddress = null,
        /// Keep transport routing alive while a message's failed parse awaits
        /// cancellation; event selection must not decode that message again.
        message_failure_pending: bool = false,

        pub fn deinit(self: *Entry) void {
            self.reader.deinit();
            self.* = undefined;
        }
    };

    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    entry_index: std.AutoHashMapUnmanaged(u62, usize) = .empty,
    lowest_entry_index: ?usize = null,
    /// Stable identity of the stream that most recently produced an event.
    /// `entries` uses swap removal, so retaining a physical index here would
    /// silently skip or repeat streams whenever an entry is removed.
    last_event_stream_id: ?u62 = null,
    resets: std.ArrayList(Reset) = .empty,
    reset_head: usize = 0,
    reset_index: std.AutoHashMapUnmanaged(u62, usize) = .empty,
    lowest_reset_index: ?usize = null,
    /// Stream identity for an error returned while decoding the next event.
    /// Multiplexed runtime callers need this to apply stream-local HTTP/3
    /// errors without guessing which sibling produced the failure.
    last_error_stream_id: ?u62 = null,
    max_streams: usize,
    max_stream_buffer: usize,
    max_informational_responses: usize,
    /// Cumulative DATA budget applied to every message reader. Runtime servers
    /// set this from `Limits.max_body_bytes`.
    max_body_bytes: usize = std.math.maxInt(usize),
    settings: http3.Settings,
    kind: Kind,

    /// Apply a cumulative body budget to this set and any readers that were
    /// already admitted. Safe to call before or after entries are inserted.
    pub fn setMaxBodyBytes(self: *Set, limit: usize) void {
        self.max_body_bytes = limit;
        for (self.entries.items) |*entry| entry.reader.max_body_bytes = limit;
    }

    pub fn init(
        allocator: std.mem.Allocator,
        max_streams: usize,
        max_stream_buffer: usize,
        settings: http3.Settings,
        kind: Kind,
    ) Set {
        return initWithInformationalLimit(
            allocator,
            max_streams,
            max_stream_buffer,
            http3.default_max_informational_responses,
            settings,
            kind,
        );
    }

    pub fn initWithInformationalLimit(
        allocator: std.mem.Allocator,
        max_streams: usize,
        max_stream_buffer: usize,
        max_informational_responses: usize,
        settings: http3.Settings,
        kind: Kind,
    ) Set {
        return .{
            .allocator = allocator,
            .max_streams = max_streams,
            .max_stream_buffer = max_stream_buffer,
            .max_informational_responses = max_informational_responses,
            .settings = settings,
            .kind = kind,
        };
    }

    pub fn deinit(self: *Set) void {
        for (self.entries.items) |*entry| entry.deinit();
        self.entries.deinit(self.allocator);
        self.entry_index.deinit(self.allocator);
        self.resets.deinit(self.allocator);
        self.reset_index.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn entryCount(self: Set) usize {
        return self.entries.items.len;
    }

    pub fn entryAt(self: *Set, index: usize) ?*Entry {
        if (index >= self.entries.items.len) return null;
        return &self.entries.items[index];
    }

    pub fn countNotTrackedBy(self: Set, lifecycle: anytype) usize {
        var count: usize = 0;
        for (self.entries.items) |entry| {
            if (!lifecycle.contains(entry.reader.streamId())) count += 1;
        }
        for (self.resets.items[self.reset_head..]) |reset| {
            if (!lifecycle.contains(reset.stream_id)) count += 1;
        }
        return count;
    }

    pub fn takeFirstResetNotTrackedBy(
        self: *Set,
        lifecycle: anytype,
    ) ?Reset {
        var index = self.reset_head;
        while (index < self.resets.items.len) : (index += 1) {
            const reset = self.resets.items[index];
            if (lifecycle.contains(reset.stream_id)) continue;
            self.removeResetPreservingOrder(index);
            self.compactResetQueueIfSparse();
            return reset;
        }
        return null;
    }

    pub fn reserveEntries(self: *Set, count: usize) Error!void {
        if (count > self.max_streams -| self.retainedCount()) {
            return error.ExcessiveLoad;
        }
        try self.entries.ensureUnusedCapacity(self.allocator, count);
        try self.entry_index.ensureUnusedCapacity(
            self.allocator,
            @intCast(count),
        );
    }

    pub fn adoptRequestReceiveAssumeCapacity(
        self: *Set,
        receive: quic.stream_state.RecvState,
        from: net.IpAddress,
    ) *Entry {
        std.debug.assert(self.kind == .request);
        const stream_id: u62 = @intCast(receive.stream_id);
        const slot = self.entry_index.getOrPutAssumeCapacity(stream_id);
        std.debug.assert(!slot.found_existing);
        return self.appendEntryAssumeCapacity(.{
            .reader = .initRequestFromReceive(
                self.allocator,
                receive,
                self.settings,
            ),
            .from = from,
        }, slot.value_ptr);
    }

    pub fn activateResponse(
        self: *Set,
        buffered: *ResponseStreamSet,
        stream_id: u62,
    ) Error!*Entry {
        if (self.kind != .response) return error.UnexpectedStream;
        if (self.find(stream_id)) |entry| return entry;
        if (self.entries.items.len + buffered.count() >= self.max_streams and
            !buffered.contains(stream_id))
        {
            return error.ExcessiveLoad;
        }
        const slot = try self.entry_index.getOrPut(
            self.allocator,
            stream_id,
        );
        std.debug.assert(!slot.found_existing);
        errdefer _ = self.entry_index.remove(stream_id);

        try self.entries.ensureUnusedCapacity(self.allocator, 1);
        if (buffered.takeReceive(stream_id)) |owned| {
            return self.appendEntryAssumeCapacity(.{
                .reader = .initResponseFromReceive(
                    self.allocator,
                    owned.receive,
                    self.settings,
                    self.max_informational_responses,
                ),
                .from = owned.from,
            }, slot.value_ptr);
        }
        return self.appendEntryAssumeCapacity(.{
            .reader = .initResponseWithInformationalLimit(
                self.allocator,
                stream_id,
                self.max_stream_buffer,
                self.settings,
                self.max_informational_responses,
            ),
        }, slot.value_ptr);
    }

    pub fn nextResponse(
        self: *Set,
        buffered: *ResponseStreamSet,
        table: http3.Qpack.DynamicTable,
        max_blocked_streams: u64,
    ) Error!?ReadyEvent {
        self.last_error_stream_id = null;
        if (self.kind != .response) return error.UnexpectedStream;
        while (buffered.firstStreamId()) |stream_id| {
            _ = self.activateResponse(buffered, stream_id) catch |err| {
                self.last_error_stream_id =
                    buffered.lastErrorStreamId() orelse stream_id;
                return err;
            };
        }
        return self.nextEvent(table, max_blocked_streams);
    }

    pub fn activateRequest(
        self: *Set,
        buffered: *RequestStreamSet,
        stream_id: u62,
    ) Error!*Entry {
        if (self.kind != .request) return error.UnexpectedStream;
        if (self.find(stream_id)) |entry| return entry;
        if (self.retainedCount() >= self.max_streams) {
            return error.ExcessiveLoad;
        }
        const slot = try self.entry_index.getOrPut(
            self.allocator,
            stream_id,
        );
        std.debug.assert(!slot.found_existing);
        errdefer _ = self.entry_index.remove(stream_id);

        try self.entries.ensureUnusedCapacity(self.allocator, 1);
        if (buffered.takeReceive(stream_id)) |owned| {
            var entry: Entry = .{
                .reader = .initRequestFromReceive(
                    self.allocator,
                    owned.receive,
                    self.settings,
                ),
                .from = owned.from,
            };
            entry.reader.max_body_bytes = self.max_body_bytes;
            return self.appendEntryAssumeCapacity(entry, slot.value_ptr);
        }
        var entry: Entry = .{
            .reader = .initRequest(
                self.allocator,
                stream_id,
                self.max_stream_buffer,
                self.settings,
            ),
        };
        entry.reader.max_body_bytes = self.max_body_bytes;
        return self.appendEntryAssumeCapacity(entry, slot.value_ptr);
    }

    pub fn insert(
        self: *Set,
        from: net.IpAddress,
        frame: quic.StreamFrame,
    ) Error!bool {
        const stream_id: u62 = @intCast(frame.stream_id);
        const entry = self.find(stream_id) orelse return false;
        if (entry.from) |existing| {
            if (!existing.eql(&from)) return error.UnexpectedStream;
        } else {
            entry.from = from;
        }
        try entry.reader.insert(frame);
        return true;
    }

    pub fn remove(self: *Set, stream_id: u62) void {
        self.removeEntry(stream_id);
        if (self.reset_index.count() == 0) return;
        if (self.reset_index.get(stream_id)) |index| {
            self.removeResetAt(index);
            self.compactResetQueueIfSparse();
        }
    }

    pub fn suspendFailedMessage(self: *Set, stream_id: u62) void {
        if (self.find(stream_id)) |entry| entry.message_failure_pending = true;
    }

    pub fn removeEntry(self: *Set, stream_id: u62) void {
        var removed = self.takeEntry(stream_id) orelse return;
        removed.deinit();
    }

    pub fn takeEntry(self: *Set, stream_id: u62) ?Entry {
        if (self.entry_index.count() == 0) return null;
        const index = self.entry_index.get(stream_id) orelse return null;
        const last_index = self.entries.items.len - 1;
        const lowest = self.lowest_entry_index;
        const removed = self.entries.swapRemove(index);
        _ = self.entry_index.remove(removed.reader.streamId());
        if (index != last_index) {
            const moved = self.entries.items[index];
            self.entry_index.getPtr(moved.reader.streamId()).?.* = index;
        }
        if (self.entries.items.len == 0) {
            self.lowest_entry_index = null;
        } else if (lowest == index) {
            self.recomputeLowestEntry();
        } else if (lowest == last_index) {
            self.lowest_entry_index = index;
        }
        return removed;
    }

    pub fn find(self: *Set, stream_id: u62) ?*Entry {
        if (self.entry_index.count() == 0) return null;
        const index = self.entry_index.get(stream_id) orelse return null;
        if (index >= self.entries.items.len) return null;
        if (self.entries.items[index].reader.streamId() != stream_id) return null;
        return &self.entries.items[index];
    }

    pub fn mightProduceRequestHead(
        self: *Set,
        buffered: *RequestStreamSet,
        target_stream_id: ?u62,
    ) bool {
        if (target_stream_id) |stream_id| {
            if (self.find(stream_id)) |entry| {
                return !entry.message_failure_pending and entry.reader.awaitingInitialHead();
            }
            return buffered.contains(stream_id);
        }
        for (self.entries.items) |entry| {
            if (!entry.message_failure_pending and entry.reader.awaitingInitialHead()) return true;
        }
        return !buffered.isEmpty();
    }

    pub fn prepareReset(
        self: *Set,
        from: net.IpAddress,
        stream_id: u62,
        application_error_code: u64,
        buffered_streams: usize,
        replaces_stream: bool,
    ) Error!bool {
        if (self.kind != .request) return error.UnexpectedStream;
        if (self.reset_index.get(stream_id)) |index| {
            const reset = self.resets.items[index];
            if (!reset.from.eql(&from) or
                reset.application_error_code != application_error_code)
            {
                return error.UnexpectedStream;
            }
            return false;
        }
        const projected_count =
            buffered_streams + self.retainedCount() +
            @intFromBool(!replaces_stream);
        if (projected_count > self.max_streams) return error.ExcessiveLoad;
        if (self.reset_head != 0 and
            self.resets.items.len == self.resets.capacity)
        {
            self.compactResetQueue();
        }
        try self.resets.ensureUnusedCapacity(self.allocator, 1);
        try self.reset_index.ensureUnusedCapacity(self.allocator, 1);
        return true;
    }

    pub fn recordResetAssumeCapacity(
        self: *Set,
        from: net.IpAddress,
        stream_id: u62,
        application_error_code: u64,
    ) void {
        if (self.reset_index.get(stream_id)) |index| {
            self.resets.items[index].application_error_code =
                application_error_code;
            return;
        }
        self.recordNewResetAssumeCapacity(
            from,
            stream_id,
            application_error_code,
        );
    }

    pub fn recordPreparedNewResetAssumeCapacity(
        self: *Set,
        from: net.IpAddress,
        stream_id: u62,
        application_error_code: u64,
    ) void {
        std.debug.assert(self.reset_index.get(stream_id) == null);
        self.recordNewResetAssumeCapacity(
            from,
            stream_id,
            application_error_code,
        );
    }

    pub fn takeReset(self: *Set, stream_id: u62) ?Reset {
        const index = self.reset_index.get(stream_id) orelse return null;
        const reset = self.resets.items[index];
        self.removeResetPreservingOrder(index);
        self.compactResetQueueIfSparse();
        return reset;
    }

    pub fn takeFirstReset(self: *Set) ?Reset {
        if (self.resetCount() == 0) return null;
        const old_head = self.reset_head;
        const reset = self.resets.items[old_head];
        _ = self.reset_index.remove(reset.stream_id);
        self.reset_head += 1;
        if (self.resetCount() == 0) {
            self.lowest_reset_index = null;
        } else if (self.lowest_reset_index == old_head) {
            self.recomputeLowestReset();
        }
        self.compactResetQueueIfSparse();
        return reset;
    }

    pub fn contains(self: Set, stream_id: u62) bool {
        if (self.entry_index.count() != 0 and
            self.entry_index.contains(stream_id)) return true;
        return self.reset_index.count() != 0 and
            self.reset_index.contains(stream_id);
    }

    pub fn retainedCount(self: Set) usize {
        return self.entries.items.len + self.resetCount();
    }

    pub fn blockedStreamCount(
        self: *Set,
        table: http3.Qpack.DynamicTable,
    ) Error!u64 {
        var count: u64 = 0;
        for (self.entries.items) |entry| {
            if (try entry.reader.blockedByQpack(table)) count += 1;
        }
        return count;
    }

    pub fn insertRequest(
        self: *Set,
        buffered: *RequestStreamSet,
        from: net.IpAddress,
        frame: quic.StreamFrame,
    ) Error!void {
        if (self.kind != .request) return error.UnexpectedStream;
        if (try self.insert(from, frame)) return;
        const stream_id: u62 = @intCast(frame.stream_id);
        if (self.contains(stream_id)) return;
        if (!buffered.contains(stream_id) and
            buffered.count() + self.retainedCount() >= self.max_streams)
        {
            return error.ExcessiveLoad;
        }
        try buffered.insert(from, frame);
    }

    pub fn nextRequest(
        self: *Set,
        buffered: *RequestStreamSet,
        table: http3.Qpack.DynamicTable,
        max_blocked_streams: u64,
    ) Error!?ReadyEvent {
        return self.nextMatchingEvent(
            buffered,
            table,
            max_blocked_streams,
            null,
            false,
        );
    }

    pub fn nextMatchingEvent(
        self: *Set,
        buffered: *RequestStreamSet,
        table: http3.Qpack.DynamicTable,
        max_blocked_streams: u64,
        target_stream_id: ?u62,
        head_only: bool,
    ) Error!?ReadyEvent {
        self.last_error_stream_id = null;
        if (self.kind != .request) return error.UnexpectedStream;
        if (target_stream_id) |stream_id| {
            const entry = self.find(stream_id) orelse blk: {
                if (!buffered.contains(stream_id)) return null;
                break :blk try self.activateRequest(buffered, stream_id);
            };
            if (entry.message_failure_pending) return null;
            const event = entry.reader.next(table) catch |err| switch (err) {
                error.QpackBlocked => {
                    if (max_blocked_streams == 0) {
                        return error.QpackDecompressionFailed;
                    }
                    return null;
                },
                else => {
                    self.last_error_stream_id = stream_id;
                    return err;
                },
            };
            const value = event orelse return null;
            return .{ .entry = entry, .event = value };
        }
        while (buffered.firstStreamId()) |stream_id| {
            _ = try self.activateRequest(buffered, stream_id);
        }
        if (!head_only) return self.nextEvent(table, max_blocked_streams);

        var blocked_streams: u64 = 0;
        for (self.entries.items) |*entry| {
            if (entry.message_failure_pending) continue;
            if (!entry.reader.awaitingInitialHead()) continue;
            const event = entry.reader.next(table) catch |err| switch (err) {
                error.QpackBlocked => {
                    blocked_streams += 1;
                    if (blocked_streams > max_blocked_streams) {
                        self.last_error_stream_id = entry.reader.streamId();
                        return error.QpackDecompressionFailed;
                    }
                    continue;
                },
                else => {
                    self.last_error_stream_id = entry.reader.streamId();
                    return err;
                },
            };
            if (event) |value| return .{ .entry = entry, .event = value };
        }
        return null;
    }

    pub fn hasUnacknowledgedDynamicSection(
        self: *Set,
        stream_id: u62,
        table: http3.Qpack.DynamicTable,
    ) Error!bool {
        const entry = self.find(stream_id) orelse return false;
        return entry.reader.hasUnacknowledgedDynamicSection(table);
    }

    pub fn lastErrorStreamId(self: Set) ?u62 {
        return self.last_error_stream_id;
    }

    pub fn lowestEntryStream(self: Set) ?u62 {
        const index = self.lowest_entry_index orelse return null;
        return self.entries.items[index].reader.streamId();
    }

    pub fn lowestResetStream(self: Set) ?u62 {
        const index = self.lowest_reset_index orelse return null;
        if (index < self.reset_head or index >= self.resets.items.len) return null;
        return self.resets.items[index].stream_id;
    }

    pub fn resetCount(self: Set) usize {
        return self.resets.items.len - self.reset_head;
    }

    fn appendEntryAssumeCapacity(
        self: *Set,
        entry: Entry,
        index_slot: *usize,
    ) *Entry {
        const index = self.entries.items.len;
        self.entries.appendAssumeCapacity(entry);
        index_slot.* = index;
        self.considerLowestEntry(index);
        return &self.entries.items[index];
    }

    fn nextEvent(
        self: *Set,
        table: http3.Qpack.DynamicTable,
        max_blocked_streams: u64,
    ) Error!?ReadyEvent {
        const entry_count = self.entries.items.len;
        if (entry_count == 0) {
            self.last_event_stream_id = null;
            return null;
        }
        var index: usize = 0;
        if (self.last_event_stream_id) |stream_id| {
            if (self.entry_index.get(stream_id)) |previous_index| {
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
            if (entry.message_failure_pending) {
                index = if (index + 1 == entry_count) 0 else index + 1;
                continue;
            }
            const event = entry.reader.next(table) catch |err| switch (err) {
                error.QpackBlocked => {
                    blocked_streams += 1;
                    if (blocked_streams > max_blocked_streams) {
                        self.last_error_stream_id = entry.reader.streamId();
                        return error.QpackDecompressionFailed;
                    }
                    index = if (index + 1 == entry_count) 0 else index + 1;
                    continue;
                },
                else => {
                    self.last_error_stream_id = entry.reader.streamId();
                    return err;
                },
            };
            if (event) |value| {
                self.last_event_stream_id = entry.reader.streamId();
                return .{ .entry = entry, .event = value };
            }
            index = if (index + 1 == entry_count) 0 else index + 1;
        }
        return null;
    }

    fn recordNewResetAssumeCapacity(
        self: *Set,
        from: net.IpAddress,
        stream_id: u62,
        application_error_code: u64,
    ) void {
        var removed_entry = self.takeEntry(stream_id);
        if (self.reset_head != 0 and
            self.resets.items.len == self.resets.capacity)
        {
            self.compactResetQueue();
        }
        const index = self.resets.items.len;
        self.resets.appendAssumeCapacity(.{
            .from = from,
            .stream_id = stream_id,
            .application_error_code = application_error_code,
        });
        self.reset_index.putAssumeCapacityNoClobber(stream_id, index);
        self.considerLowestReset(index);
        if (removed_entry) |*entry| entry.deinit();
    }

    fn compactResetQueueIfSparse(self: *Set) void {
        if (self.reset_head == 0) return;
        if (self.reset_head == self.resets.items.len or
            self.reset_head >= self.resets.items.len / 2)
        {
            self.compactResetQueue();
        }
    }

    fn compactResetQueue(self: *Set) void {
        if (self.reset_head == 0) return;
        const remaining = self.resetCount();
        if (remaining != 0) {
            @memmove(
                self.resets.items[0..remaining],
                self.resets.items[self.reset_head..],
            );
        }
        self.resets.items.len = remaining;
        self.reset_head = 0;
        self.rebuildResetIndexAssumeCapacity();
        self.recomputeLowestReset();
    }

    fn removeResetAt(self: *Set, index: usize) void {
        const last_index = self.resets.items.len - 1;
        const lowest = self.lowest_reset_index;
        const removed = self.resets.swapRemove(index);
        _ = self.reset_index.remove(removed.stream_id);
        if (index < self.resets.items.len) {
            const moved = self.resets.items[index];
            self.reset_index.getPtr(moved.stream_id).?.* = index;
        }
        if (self.resetCount() == 0) {
            self.lowest_reset_index = null;
        } else if (lowest == index) {
            self.recomputeLowestReset();
        } else if (lowest == last_index) {
            self.lowest_reset_index = index;
        }
    }

    fn removeResetPreservingOrder(self: *Set, index: usize) void {
        std.debug.assert(index >= self.reset_head);
        const removed_stream_id = self.resets.items[index].stream_id;
        _ = self.reset_index.remove(removed_stream_id);
        var moved_index = index;
        while (moved_index + 1 < self.resets.items.len) : (moved_index += 1) {
            const moved = self.resets.items[moved_index + 1];
            self.resets.items[moved_index] = moved;
            self.reset_index.getPtr(moved.stream_id).?.* = moved_index;
        }
        _ = self.resets.pop();
        self.recomputeLowestReset();
    }

    fn rebuildResetIndexAssumeCapacity(self: *Set) void {
        self.reset_index.clearRetainingCapacity();
        for (
            self.resets.items[self.reset_head..],
            self.reset_head..,
        ) |reset, index| {
            self.reset_index.putAssumeCapacityNoClobber(reset.stream_id, index);
        }
    }

    fn considerLowestEntry(self: *Set, index: usize) void {
        const lowest = self.lowest_entry_index orelse {
            self.lowest_entry_index = index;
            return;
        };
        if (self.entries.items[index].reader.streamId() <
            self.entries.items[lowest].reader.streamId())
        {
            self.lowest_entry_index = index;
        }
    }

    fn recomputeLowestEntry(self: *Set) void {
        self.lowest_entry_index = null;
        for (self.entries.items, 0..) |_, index| {
            self.considerLowestEntry(index);
        }
    }

    fn considerLowestReset(self: *Set, index: usize) void {
        if (index < self.reset_head) return;
        const lowest = self.lowest_reset_index orelse {
            self.lowest_reset_index = index;
            return;
        };
        if (self.resets.items[index].stream_id <
            self.resets.items[lowest].stream_id)
        {
            self.lowest_reset_index = index;
        }
    }

    fn recomputeLowestReset(self: *Set) void {
        self.lowest_reset_index = null;
        var index = self.reset_head;
        while (index < self.resets.items.len) : (index += 1) {
            self.considerLowestReset(index);
        }
    }
};
