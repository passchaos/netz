const std = @import("std");
const http3 = @import("../../../mod.zig");
const quic = @import("../../../../quic/mod.zig");
const Error = @import("../../error.zig").Error;
const common = @import("common.zig");

const net = std.Io.net;

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
    lowest_stream_index: ?usize = null,
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
        self.* = undefined;
    }

    pub fn insert(
        self: *Set,
        from: net.IpAddress,
        frame: quic.StreamFrame,
    ) Error!void {
        const entry = try self.getOrCreate(from, frame.stream_id);
        try entry.receive.insert(frame);
    }

    pub fn takeReady(
        self: *Set,
        table: http3.Qpack.DynamicTable,
        max_blocked_streams: u64,
    ) Error!?common.AssembledStream {
        const ready = try self.copyReady(table, max_blocked_streams) orelse
            return null;
        self.remove(ready.stream_id);
        return ready;
    }

    /// Copy the first complete request while retaining its reassembly state.
    /// Aggregate runtimes use this to complete fallible local preparation
    /// before committing request admission.
    pub fn copyReady(
        self: *Set,
        table: http3.Qpack.DynamicTable,
        max_blocked_streams: u64,
    ) Error!?common.AssembledStream {
        self.last_error_stream_id = null;
        self.last_error_from = null;
        var ready_index: ?usize = null;
        var blocked_streams: u64 = 0;
        for (self.entries.items, 0..) |*entry, index| {
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
            if (ready_index == null) ready_index = index;
        }
        const index = ready_index orelse return null;
        const entry = &self.entries.items[index];
        const final_size = entry.receive.final_size.?;
        const owned = try self.allocator.dupe(
            u8,
            entry.receive.buffer.items[0..final_size],
        );
        const from = entry.from;
        const stream_id: u62 = @intCast(entry.receive.stream_id);
        return .{ .from = from, .stream_id = stream_id, .bytes = owned };
    }

    pub fn cancel(
        self: *Set,
        stream_id: u64,
        table: http3.Qpack.DynamicTable,
    ) Error!bool {
        const requires_qpack_cancellation =
            try self.requiresQpackCancellation(stream_id, table);
        self.remove(stream_id);
        return requires_qpack_cancellation;
    }

    pub fn requiresQpackCancellation(
        self: Set,
        stream_id: u64,
        table: http3.Qpack.DynamicTable,
    ) Error!bool {
        const key = std.math.cast(u62, stream_id) orelse return false;
        if (self.entry_index.count() == 0) return false;
        const index = self.entry_index.get(key) orelse return false;
        return try common.receiveUsesDynamicQpack(
            self.entries.items[index].receive,
            table,
        );
    }

    pub fn remove(self: *Set, stream_id: u64) void {
        const key = std.math.cast(u62, stream_id) orelse return;
        var removed = self.takeEntry(key) orelse return;
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
        return .{
            .receive = removed.receive,
            .from = removed.from,
        };
    }

    pub fn contains(self: Set, stream_id: u62) bool {
        return self.entry_index.count() != 0 and
            self.entry_index.contains(stream_id);
    }

    pub fn count(self: Set) usize {
        return self.entries.items.len;
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

    pub fn lastErrorStreamId(self: Set) ?u62 {
        return self.last_error_stream_id;
    }

    pub fn lastErrorFrom(self: Set) ?net.IpAddress {
        return self.last_error_from;
    }

    pub fn isEmpty(self: Set) bool {
        return self.entries.items.len == 0;
    }

    pub fn firstStreamId(self: Set) ?u62 {
        if (self.entries.items.len == 0) return null;
        return @intCast(self.entries.items[0].receive.stream_id);
    }

    pub fn countNotTrackedBy(self: Set, lifecycle: anytype) usize {
        var result: usize = 0;
        for (self.entries.items) |entry| {
            if (!lifecycle.contains(@intCast(entry.receive.stream_id))) {
                result += 1;
            }
        }
        return result;
    }

    pub fn lowestStream(self: Set) ?u62 {
        const index = self.lowest_stream_index orelse return null;
        return @intCast(self.entries.items[index].receive.stream_id);
    }

    fn getOrCreate(
        self: *Set,
        from: net.IpAddress,
        stream_id: u64,
    ) Error!*Entry {
        const key: u62 = @intCast(stream_id);
        if (self.entries.items.len >= self.max_streams) {
            if (self.entry_index.get(key)) |index| {
                const entry = &self.entries.items[index];
                if (!entry.from.eql(&from)) return error.UnexpectedStream;
                return entry;
            }
            return error.ExcessiveLoad;
        }
        const slot = try self.entry_index.getOrPut(self.allocator, key);
        if (slot.found_existing) {
            const entry = &self.entries.items[slot.value_ptr.*];
            // A single HTTP/3 connection has one peer address in these
            // runtimes; accepting one stream from multiple sources would
            // merge unrelated connection state.
            if (!entry.from.eql(&from)) return error.UnexpectedStream;
            return entry;
        }
        errdefer _ = self.entry_index.remove(key);
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
        self.considerLowestStream(index);
        return &self.entries.items[index];
    }

    fn takeEntry(self: *Set, stream_id: u62) ?Entry {
        if (self.entry_index.count() == 0) return null;
        const index = self.entry_index.get(stream_id) orelse return null;
        const last_index = self.entries.items.len - 1;
        const lowest = self.lowest_stream_index;
        const removed = self.entries.swapRemove(index);
        _ = self.entry_index.remove(@intCast(removed.receive.stream_id));
        if (index != last_index) {
            const moved = self.entries.items[index];
            self.entry_index.getPtr(@intCast(moved.receive.stream_id)).?.* =
                index;
        }
        if (self.entries.items.len == 0) {
            self.lowest_stream_index = null;
        } else if (lowest == index) {
            self.recomputeLowestStream();
        } else if (lowest == last_index) {
            self.lowest_stream_index = index;
        }
        return removed;
    }

    fn considerLowestStream(self: *Set, index: usize) void {
        const lowest = self.lowest_stream_index orelse {
            self.lowest_stream_index = index;
            return;
        };
        if (self.entries.items[index].receive.stream_id <
            self.entries.items[lowest].receive.stream_id)
        {
            self.lowest_stream_index = index;
        }
    }

    fn recomputeLowestStream(self: *Set) void {
        self.lowest_stream_index = null;
        for (self.entries.items, 0..) |_, index| {
            self.considerLowestStream(index);
        }
    }
};

test "HTTP/3 buffered request streams index reassembly entries" {
    const allocator = std.testing.allocator;
    const from: net.IpAddress = .{ .ip4 = .loopback(443) };

    var requests = Set.init(allocator, 512, 3);
    defer requests.deinit();
    inline for (.{ @as(u62, 0), @as(u62, 4), @as(u62, 8) }) |stream_id| {
        try requests.insert(from, .{
            .stream_id = stream_id,
            .data = "x",
        });
    }
    try std.testing.expectEqual(@as(usize, 3), requests.count());
    try std.testing.expect(requests.contains(4));
    try std.testing.expectEqual(@as(?u62, 0), requests.lowestStream());
    var taken_request = requests.takeReceive(4) orelse
        return error.TestUnexpectedResult;
    taken_request.receive.deinit();
    try std.testing.expect(!requests.contains(4));
    try std.testing.expect(requests.contains(8));
    try std.testing.expectEqual(@as(?u62, 0), requests.lowestStream());
    requests.remove(8);
    try std.testing.expect(!requests.contains(8));
    try std.testing.expectEqual(@as(?u62, 0), requests.lowestStream());
    requests.remove(0);
    try std.testing.expectEqual(@as(?u62, null), requests.lowestStream());
    try std.testing.expect(requests.isEmpty());
    requests.remove(20);
    try std.testing.expect(requests.takeReceive(20) == null);
    var empty_table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer empty_table.deinit();
    try std.testing.expect(!try requests.requiresQpackCancellation(
        20,
        empty_table,
    ));

    const target_message = "\x00\x06target";
    const other_message = "\x00\x05other";
    try requests.insert(from, .{
        .stream_id = 12,
        .data = target_message,
        .fin = true,
    });
    try requests.insert(from, .{
        .stream_id = 16,
        .data = other_message,
        .fin = true,
    });
    var request_table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer request_table.deinit();
    const ready_request = (try requests.takeReady(request_table, 0)) orelse
        return error.TestUnexpectedResult;
    defer allocator.free(ready_request.bytes);
    try std.testing.expectEqual(@as(u62, 12), ready_request.stream_id);
    try std.testing.expectEqualStrings(target_message, ready_request.bytes);
    try std.testing.expect(!requests.contains(12));
    try std.testing.expect(requests.contains(16));
}

test "HTTP/3 buffered request rejects first blocked stream at zero budget" {
    const allocator = std.testing.allocator;
    const from: net.IpAddress = .{ .ip4 = .loopback(443) };
    var requests = Set.init(allocator, 512, 2);
    defer requests.deinit();
    var encoder_table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer encoder_table.deinit();
    try encoder_table.setCapacity(256);
    _ = try encoder_table.insert("x-blocked", "request");
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/blocked" },
        .{ .name = "x-blocked", .value = "request" },
    }, encoder_table);
    var message: std.ArrayList(u8) = .empty;
    defer message.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&message, allocator);
    try requests.insert(from, .{
        .stream_id = 0,
        .data = message.items,
        .fin = true,
    });
    var decoder_table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer decoder_table.deinit();
    try decoder_table.setCapacity(256);
    try std.testing.expectError(
        error.QpackDecompressionFailed,
        requests.copyReady(decoder_table, 0),
    );
    try std.testing.expectEqual(@as(?u62, 0), requests.lastErrorStreamId());
    try std.testing.expect(requests.lastErrorFrom().?.eql(&from));
    try std.testing.expect(requests.contains(0));
}
