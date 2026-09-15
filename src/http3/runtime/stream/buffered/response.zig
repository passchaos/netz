const std = @import("std");
const http3 = @import("../../../mod.zig");
const quic = @import("../../../../quic/mod.zig");
const Error = @import("../../error.zig").Error;
const common = @import("common.zig");

const net = std.Io.net;

pub const Reset = struct {
    stream_id: u62,
    application_error_code: u64,
};

pub const PreparedReady = struct {
    from: net.IpAddress,
    stream_id: u62,
    bytes: []u8,
    owns_bytes: bool,

    pub fn deinit(self: *PreparedReady, allocator: std.mem.Allocator) void {
        if (self.owns_bytes) allocator.free(self.bytes);
        self.bytes = &.{};
        self.owns_bytes = false;
    }
};

pub const Set = struct {
    const Entry = struct {
        receive: quic.stream_state.RecvState,
        from: net.IpAddress,

        fn deinit(self: *Entry) void {
            self.receive.deinit();
            self.* = undefined;
        }
    };

    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    entry_index: std.AutoHashMapUnmanaged(u62, usize) = .empty,
    resets: std.AutoHashMapUnmanaged(u62, u64) = .empty,
    reset_order: std.ArrayList(u62) = .empty,
    reset_head: usize = 0,
    last_error_stream_id: ?u62 = null,
    last_error_from: ?net.IpAddress = null,
    max_stream_buffer: usize,
    max_streams: usize,

    pub fn init(
        allocator: std.mem.Allocator,
        max_stream_buffer: usize,
        max_streams: usize,
    ) Set {
        return .{
            .allocator = allocator,
            .max_stream_buffer = max_stream_buffer,
            .max_streams = max_streams,
        };
    }

    pub fn deinit(self: *Set) void {
        for (self.entries.items) |*entry| entry.deinit();
        self.entries.deinit(self.allocator);
        self.entry_index.deinit(self.allocator);
        self.resets.deinit(self.allocator);
        self.reset_order.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn insert(
        self: *Set,
        from: net.IpAddress,
        frame: quic.StreamFrame,
    ) Error!void {
        const stream_id: u62 = @intCast(frame.stream_id);
        if (self.resets.count() != 0 and self.resets.contains(stream_id)) return;
        const entry = try self.getOrCreate(from, stream_id);
        try entry.receive.insert(frame);
    }

    pub fn recordReset(
        self: *Set,
        stream_id: u62,
        application_error_code: u64,
    ) Error!void {
        if (self.resets.getPtr(stream_id)) |existing| {
            existing.* = application_error_code;
            return;
        }
        if (!try self.prepareReset(stream_id, application_error_code)) return;
        self.remove(stream_id);
        self.commitPreparedResetAssumeCapacity(
            stream_id,
            application_error_code,
        );
    }

    /// Reserve every allocation needed to replace a buffered response with a
    /// terminal reset. Returning false means the same reset already exists.
    pub fn prepareReset(
        self: *Set,
        stream_id: u62,
        application_error_code: u64,
    ) Error!bool {
        if (self.resets.get(stream_id)) |existing| {
            if (existing != application_error_code) {
                return error.UnexpectedStream;
            }
            return false;
        }
        if (self.reset_head != 0 and
            self.reset_order.items.len == self.reset_order.capacity)
        {
            self.compactResetOrder();
        }
        try self.resets.ensureUnusedCapacity(self.allocator, 1);
        try self.reset_order.ensureUnusedCapacity(self.allocator, 1);
        return true;
    }

    pub fn commitPreparedResetAssumeCapacity(
        self: *Set,
        stream_id: u62,
        application_error_code: u64,
    ) void {
        self.resets.putAssumeCapacityNoClobber(
            stream_id,
            application_error_code,
        );
        self.reset_order.appendAssumeCapacity(stream_id);
    }

    pub fn takeReset(self: *Set, stream_id: u62) ?u64 {
        if (self.resets.count() == 0) return null;
        const code = self.resets.get(stream_id) orelse return null;
        _ = self.resets.remove(stream_id);
        self.removeResetOrder(stream_id);
        return code;
    }

    pub fn resetFor(self: Set, stream_id: u62) ?u64 {
        if (self.resets.count() == 0) return null;
        return self.resets.get(stream_id);
    }

    pub fn firstReadyStream(
        self: *Set,
        table: http3.Qpack.DynamicTable,
        max_blocked_streams: u64,
    ) Error!?u62 {
        self.last_error_stream_id = null;
        self.last_error_from = null;
        var ready_stream_id: ?u62 = null;
        var blocked_streams: u64 = 0;
        for (self.entries.items) |*entry| {
            const final_size = entry.receive.final_size orelse continue;
            if (entry.receive.contiguous_end < final_size) continue;
            const bytes = entry.receive.buffer.items[0..final_size];
            if (common.messageBlockedByQpack(bytes, table) catch |err| {
                self.last_error_stream_id =
                    @intCast(entry.receive.stream_id);
                self.last_error_from = entry.from;
                return err;
            }) {
                blocked_streams += 1;
                if (blocked_streams > max_blocked_streams) {
                    self.last_error_stream_id =
                        @intCast(entry.receive.stream_id);
                    self.last_error_from = entry.from;
                    return error.QpackDecompressionFailed;
                }
                continue;
            }
            if (ready_stream_id == null) {
                ready_stream_id = @intCast(entry.receive.stream_id);
            }
        }
        return ready_stream_id;
    }

    pub fn firstReset(self: *Set) ?Reset {
        while (self.resetCount() != 0) {
            const stream_id = self.reset_order.items[self.reset_head];
            if (self.resets.get(stream_id)) |code| {
                return .{
                    .stream_id = stream_id,
                    .application_error_code = code,
                };
            }
            self.reset_head += 1;
            self.compactResetOrderIfSparse();
        }
        return null;
    }

    pub fn count(self: Set) usize {
        return self.entries.items.len + self.resets.count();
    }

    pub fn blockedStreamCount(
        self: *Set,
        table: http3.Qpack.DynamicTable,
    ) Error!u64 {
        var blocked: u64 = 0;
        for (self.entries.items) |entry| {
            if (try common.receiveBlockedByQpack(entry.receive, table)) {
                blocked += 1;
            }
        }
        return blocked;
    }

    pub fn isEmpty(self: Set) bool {
        return self.entries.items.len == 0 and self.resets.count() == 0;
    }

    pub fn contains(self: Set, stream_id: u62) bool {
        return (self.resets.count() != 0 and
            self.resets.contains(stream_id)) or
            (self.entry_index.count() != 0 and
                self.entry_index.contains(stream_id));
    }

    /// Absolute end of the contiguous prefix already copied into aggregate
    /// HTTP/3 ownership. The QUIC receive buffer can release this prefix
    /// without waiting for the complete response or exposing partial bytes to
    /// the application.
    pub fn contiguousEnd(self: Set, stream_id: u62) ?u64 {
        if (self.entry_index.count() == 0) return null;
        const index = self.entry_index.get(stream_id) orelse return null;
        return std.math.cast(
            u64,
            self.entries.items[index].receive.contiguous_end,
        ) orelse std.math.maxInt(u64);
    }

    pub fn firstStreamId(self: Set) ?u62 {
        if (self.entries.items.len == 0) return null;
        return @intCast(self.entries.items[0].receive.stream_id);
    }

    pub fn resetCount(self: Set) usize {
        return self.reset_order.items.len - self.reset_head;
    }

    pub fn lastErrorStreamId(self: Set) ?u62 {
        return self.last_error_stream_id;
    }

    pub fn lastErrorFrom(self: Set) ?net.IpAddress {
        return self.last_error_from;
    }

    pub fn takeReady(
        self: *Set,
        stream_id: u62,
        table: http3.Qpack.DynamicTable,
        max_blocked_streams: u64,
    ) Error!?common.AssembledStream {
        var prepared = try self.prepareReady(
            stream_id,
            table,
            max_blocked_streams,
        ) orelse return null;
        defer prepared.deinit(self.allocator);
        return self.commitPreparedReady(&prepared);
    }

    /// Copy one complete response while retaining its reassembly state. Use
    /// this when a caller needs an independently owned snapshot without a
    /// later commit; aggregate clients use `prepareReady` instead.
    pub fn copyReady(
        self: *Set,
        stream_id: u62,
        table: http3.Qpack.DynamicTable,
        max_blocked_streams: u64,
    ) Error!?common.AssembledStream {
        const entry = try self.readyEntry(
            stream_id,
            table,
            max_blocked_streams,
        ) orelse return null;
        const final_size = entry.receive.final_size.?;
        const bytes = entry.receive.buffer.items[0..final_size];
        const owned = try self.allocator.dupe(u8, bytes);
        const from = entry.from;
        return .{ .from = from, .stream_id = stream_id, .bytes = owned };
    }

    /// Prepare one complete response without committing removal. When the
    /// receive allocation can be shrunk in place, `bytes` borrows that stable
    /// allocation and commit transfers it without copying. Other allocators
    /// retain the previous owned-copy fallback and the same failure semantics.
    pub fn prepareReady(
        self: *Set,
        stream_id: u62,
        table: http3.Qpack.DynamicTable,
        max_blocked_streams: u64,
    ) Error!?PreparedReady {
        const entry = try self.readyEntry(
            stream_id,
            table,
            max_blocked_streams,
        ) orelse return null;
        const final_size = entry.receive.final_size.?;
        const bytes = entry.receive.buffer.items[0..final_size];
        if (try entry.receive.prepareCompleteBufferTransfer()) {
            return .{
                .from = entry.from,
                .stream_id = stream_id,
                .bytes = entry.receive.buffer.items,
                .owns_bytes = false,
            };
        }
        return .{
            .from = entry.from,
            .stream_id = stream_id,
            .bytes = try self.allocator.dupe(u8, bytes),
            .owns_bytes = true,
        };
    }

    fn readyEntry(
        self: *Set,
        stream_id: u62,
        table: http3.Qpack.DynamicTable,
        max_blocked_streams: u64,
    ) Error!?*Entry {
        self.last_error_stream_id = null;
        self.last_error_from = null;
        if (self.entry_index.count() == 0) return null;
        const index = self.entry_index.get(stream_id) orelse return null;
        const entry = &self.entries.items[index];
        const final_size = entry.receive.final_size orelse return null;
        if (entry.receive.contiguous_end < final_size) return null;
        const bytes = entry.receive.buffer.items[0..final_size];
        if (common.messageBlockedByQpack(bytes, table) catch |err| {
            self.last_error_stream_id = stream_id;
            self.last_error_from = entry.from;
            return err;
        }) {
            if (self.blockedReadyStreamCount(table) catch |err| {
                self.last_error_stream_id = stream_id;
                self.last_error_from = entry.from;
                return err;
            } > max_blocked_streams) {
                self.last_error_stream_id = stream_id;
                self.last_error_from = entry.from;
                return error.QpackDecompressionFailed;
            }
            return null;
        }
        return entry;
    }

    /// Commit a previously prepared response and transfer its wire bytes to
    /// the caller. This operation is allocation-free.
    pub fn commitPreparedReady(
        self: *Set,
        prepared: *PreparedReady,
    ) common.AssembledStream {
        var removed = self.takeEntry(prepared.stream_id) orelse unreachable;
        std.debug.assert(removed.from.eql(&prepared.from));
        const bytes = if (prepared.owns_bytes) blk: {
            const owned = prepared.bytes;
            prepared.bytes = &.{};
            prepared.owns_bytes = false;
            removed.deinit();
            break :blk owned;
        } else blk: {
            std.debug.assert(
                removed.receive.buffer.items.ptr == prepared.bytes.ptr,
            );
            const owned = removed.receive.takePreparedCompleteBuffer();
            removed.deinit();
            prepared.bytes = &.{};
            break :blk owned;
        };
        return .{
            .from = prepared.from,
            .stream_id = prepared.stream_id,
            .bytes = bytes,
        };
    }

    pub fn remove(self: *Set, stream_id: u62) void {
        var removed = self.takeEntry(stream_id) orelse return;
        removed.deinit();
    }

    pub fn takeReceive(
        self: *Set,
        stream_id: u62,
    ) ?struct {
        receive: quic.stream_state.RecvState,
        from: net.IpAddress,
    } {
        const removed = self.takeEntry(stream_id) orelse return null;
        return .{ .receive = removed.receive, .from = removed.from };
    }

    pub fn requiresQpackCancellation(
        self: Set,
        stream_id: u62,
        table: http3.Qpack.DynamicTable,
    ) Error!bool {
        if (self.entry_index.count() == 0) return false;
        const index = self.entry_index.get(stream_id) orelse return false;
        return try common.receiveUsesDynamicQpack(
            self.entries.items[index].receive,
            table,
        );
    }

    fn removeResetOrder(self: *Set, stream_id: u62) void {
        var index = self.reset_head;
        while (index < self.reset_order.items.len) : (index += 1) {
            if (self.reset_order.items[index] != stream_id) continue;
            if (index == self.reset_head) {
                self.reset_head += 1;
            } else if (index == self.reset_order.items.len - 1) {
                _ = self.reset_order.pop();
            } else {
                _ = self.reset_order.orderedRemove(index);
                if (self.reset_head > index) self.reset_head -= 1;
            }
            self.compactResetOrderIfSparse();
            return;
        }
    }

    fn compactResetOrderIfSparse(self: *Set) void {
        if (self.reset_head == 0) return;
        if (self.reset_head == self.reset_order.items.len or
            self.reset_head >= self.reset_order.items.len / 2)
        {
            self.compactResetOrder();
        }
    }

    fn compactResetOrder(self: *Set) void {
        if (self.reset_head == 0) return;
        const remaining = self.resetCount();
        if (remaining != 0) {
            @memmove(
                self.reset_order.items[0..remaining],
                self.reset_order.items[self.reset_head..],
            );
        }
        self.reset_order.items.len = remaining;
        self.reset_head = 0;
    }

    fn blockedReadyStreamCount(
        self: *Set,
        table: http3.Qpack.DynamicTable,
    ) Error!u64 {
        var blocked_streams: u64 = 0;
        for (self.entries.items) |*entry| {
            const final_size = entry.receive.final_size orelse continue;
            if (entry.receive.contiguous_end < final_size) continue;
            const bytes = entry.receive.buffer.items[0..final_size];
            if (try common.messageBlockedByQpack(bytes, table)) {
                blocked_streams += 1;
            }
        }
        return blocked_streams;
    }

    fn takeEntry(self: *Set, stream_id: u62) ?Entry {
        if (self.entry_index.count() == 0) return null;
        const index = self.entry_index.get(stream_id) orelse return null;
        const last_index = self.entries.items.len - 1;
        const removed = self.entries.swapRemove(index);
        _ = self.entry_index.remove(@intCast(removed.receive.stream_id));
        if (index != last_index) {
            const moved = self.entries.items[index];
            self.entry_index.getPtr(@intCast(moved.receive.stream_id)).?.* =
                index;
        }
        return removed;
    }

    fn getOrCreate(
        self: *Set,
        from: net.IpAddress,
        stream_id: u62,
    ) Error!*Entry {
        if (self.entries.items.len >= self.max_streams) {
            if (self.entry_index.get(stream_id)) |index| {
                const entry = &self.entries.items[index];
                if (!entry.from.eql(&from)) return error.UnexpectedStream;
                return entry;
            }
            return error.ExcessiveLoad;
        }
        const slot = try self.entry_index.getOrPut(self.allocator, stream_id);
        if (slot.found_existing) {
            const entry = &self.entries.items[slot.value_ptr.*];
            if (!entry.from.eql(&from)) return error.UnexpectedStream;
            return entry;
        }
        errdefer _ = self.entry_index.remove(stream_id);
        try self.entries.ensureUnusedCapacity(self.allocator, 1);
        const index = self.entries.items.len;
        self.entries.appendAssumeCapacity(.{
            .receive = .init(
                self.allocator,
                stream_id,
                self.max_stream_buffer,
            ),
            .from = from,
        });
        slot.value_ptr.* = index;
        return &self.entries.items[index];
    }
};

test "HTTP/3 buffered response streams index reassembly entries" {
    const allocator = std.testing.allocator;
    const from: net.IpAddress = .{ .ip4 = .loopback(443) };

    var responses = Set.init(allocator, 512, 3);
    defer responses.deinit();
    inline for (.{ @as(u62, 0), @as(u62, 4), @as(u62, 8) }) |stream_id| {
        try responses.insert(from, .{ .stream_id = stream_id, .data = "x" });
    }
    var taken_response = responses.takeReceive(4) orelse
        return error.TestUnexpectedResult;
    taken_response.receive.deinit();
    try std.testing.expect(!responses.contains(4));
    try std.testing.expect(responses.contains(8));
    responses.remove(8);
    try std.testing.expect(!responses.contains(8));
    try std.testing.expectEqual(@as(usize, 1), responses.count());
    try std.testing.expect(responses.contains(0));
    try std.testing.expect(!responses.contains(4));
    try responses.recordReset(20, http3.ApplicationErrorCode.request_cancelled);
    try std.testing.expect(responses.contains(20));
    try std.testing.expectEqual(@as(usize, 1), responses.resetCount());
    _ = responses.takeReset(20);
    try std.testing.expect(!responses.contains(20));
    try std.testing.expectEqual(@as(usize, 0), responses.resetCount());
    try std.testing.expect(responses.takeReset(20) == null);

    try responses.recordReset(24, 0x24);
    try responses.recordReset(28, 0x28);
    try responses.recordReset(24, 0x42);
    try std.testing.expectEqual(@as(usize, 2), responses.resetCount());
    try std.testing.expectEqual(@as(u64, 0x28), responses.takeReset(28).?);
    try responses.recordReset(28, 0x28);
    try std.testing.expectEqual(@as(u62, 24), responses.firstReset().?.stream_id);
    try std.testing.expectEqual(@as(u64, 0x42), responses.takeReset(24).?);
    try std.testing.expectEqual(@as(u62, 28), responses.firstReset().?.stream_id);
    try std.testing.expectEqual(@as(u64, 0x28), responses.takeReset(28).?);
    try std.testing.expect(responses.firstReset() == null);

    const target_message = "\x00\x06target";
    const other_message = "\x00\x05other";
    try responses.insert(from, .{
        .stream_id = 12,
        .data = target_message,
        .fin = true,
    });
    try responses.insert(from, .{
        .stream_id = 16,
        .data = other_message,
        .fin = true,
    });
    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();
    try std.testing.expectEqual(
        @as(?u62, 12),
        try responses.firstReadyStream(table, 0),
    );
    const ready = (try responses.takeReady(12, table, 0)) orelse
        return error.TestUnexpectedResult;
    defer allocator.free(ready.bytes);
    try std.testing.expectEqual(@as(u62, 12), ready.stream_id);
    try std.testing.expectEqualStrings(target_message, ready.bytes);
    try std.testing.expect(!responses.contains(12));
    try std.testing.expect(responses.contains(16));
    responses.remove(16);
    responses.remove(0);
    try std.testing.expect(responses.isEmpty());
    try std.testing.expect((try responses.takeReady(16, table, 0)) == null);
    try std.testing.expect(responses.takeReceive(16) == null);
    try std.testing.expect(!try responses.requiresQpackCancellation(16, table));
}

test "HTTP/3 buffered response transfers prepared storage without copying" {
    const allocator = std.heap.c_allocator;
    const from: net.IpAddress = .{ .ip4 = .loopback(443) };
    const message = "\x00\x03ok!";
    var responses = Set.init(allocator, 512, 1);
    defer responses.deinit();
    try responses.insert(from, .{
        .stream_id = 0,
        .data = message,
        .fin = true,
    });
    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();

    const buffered_ptr = responses.entries.items[0].receive.buffer.items.ptr;
    var prepared = (try responses.prepareReady(0, table, 0)) orelse
        return error.TestUnexpectedResult;
    defer prepared.deinit(allocator);
    try std.testing.expect(!prepared.owns_bytes);
    try std.testing.expectEqual(buffered_ptr, prepared.bytes.ptr);
    try std.testing.expect(responses.contains(0));

    // Abandoning a borrowed preparation leaves the response retryable.
    prepared.deinit(allocator);
    try std.testing.expect(responses.contains(0));
    prepared = (try responses.prepareReady(0, table, 0)) orelse
        return error.TestUnexpectedResult;
    const ready = responses.commitPreparedReady(&prepared);
    defer allocator.free(ready.bytes);
    try std.testing.expectEqual(buffered_ptr, ready.bytes.ptr);
    try std.testing.expectEqualStrings(message, ready.bytes);
    try std.testing.expect(!responses.contains(0));
}

test "HTTP/3 buffered response preserves prepared fallback on allocation failure" {
    const allocator = std.testing.allocator;
    var failing = std.testing.FailingAllocator.init(allocator, .{
        .resize_fail_index = 0,
    });
    const fallible = failing.allocator();
    const from: net.IpAddress = .{ .ip4 = .loopback(443) };
    const message = "\x00\x03ok!";
    var responses = Set.init(fallible, 512, 1);
    defer responses.deinit();
    try responses.insert(from, .{
        .stream_id = 0,
        .data = message,
        .fin = true,
    });
    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();

    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(
        error.OutOfMemory,
        responses.prepareReady(0, table, 0),
    );
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expect(responses.contains(0));

    failing.fail_index = std.math.maxInt(usize);
    var prepared = (try responses.prepareReady(0, table, 0)) orelse
        return error.TestUnexpectedResult;
    defer prepared.deinit(fallible);
    try std.testing.expect(prepared.owns_bytes);
    const ready = responses.commitPreparedReady(&prepared);
    defer fallible.free(ready.bytes);
    try std.testing.expectEqualStrings(message, ready.bytes);
    try std.testing.expect(!responses.contains(0));
}

test "HTTP/3 buffered response rejects first blocked stream at zero budget" {
    const allocator = std.testing.allocator;
    const from: net.IpAddress = .{ .ip4 = .loopback(443) };
    var responses = Set.init(allocator, 512, 2);
    defer responses.deinit();
    var encoder_table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer encoder_table.deinit();
    try encoder_table.setCapacity(256);
    _ = try encoder_table.insert("x-blocked", "response");
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":status", .value = "204" },
        .{ .name = "x-blocked", .value = "response" },
    }, encoder_table);
    var message: std.ArrayList(u8) = .empty;
    defer message.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&message, allocator);
    try responses.insert(from, .{
        .stream_id = 0,
        .data = message.items,
        .fin = true,
    });
    var decoder_table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer decoder_table.deinit();
    try decoder_table.setCapacity(256);
    try std.testing.expectError(
        error.QpackDecompressionFailed,
        responses.copyReady(0, decoder_table, 0),
    );
    try std.testing.expectEqual(@as(?u62, 0), responses.lastErrorStreamId());
    try std.testing.expect(responses.lastErrorFrom().?.eql(&from));
    try std.testing.expect(responses.contains(0));
}

fn checkResetAllocationFailure(allocator: std.mem.Allocator) !void {
    const from: net.IpAddress = .{ .ip4 = .loopback(443) };
    var responses = Set.init(allocator, 512, 3);
    defer responses.deinit();
    try responses.insert(from, .{ .stream_id = 0, .data = "partial" });

    responses.recordReset(0, 0x10) catch |err| {
        try std.testing.expectEqual(error.OutOfMemory, err);
        try std.testing.expect(responses.contains(0));
        try std.testing.expectEqual(@as(usize, 0), responses.resetCount());
        return err;
    };
    try std.testing.expect(responses.contains(0));
    try std.testing.expectEqual(@as(usize, 1), responses.resetCount());
}

test "HTTP/3 buffered response reset is transactional under allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkResetAllocationFailure,
        .{},
    );
}
