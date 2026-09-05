const std = @import("std");
const quic = @import("../../../quic/mod.zig");
const body_batch = @import("../body_batch.zig");
const Error = @import("../error.zig").Error;

pub const Set = struct {
    pub const Entry = struct {
        send: quic.stream_state.SendState,
        expected_length: ?usize,
        written: usize = 0,
        /// Optional peer-advertised stream offset for lightweight protected
        /// runtimes. The handshake runtime keeps this state in
        /// `one_rtt.Connection`; preconfigured-key paths use it only for
        /// blocking helpers that need deterministic small receive windows.
        flow_limit: ?u64 = null,
    };

    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    last_entry_index: ?usize = null,
    entry_index: std.AutoHashMapUnmanaged(u62, usize) = .empty,
    frame_scratch: std.ArrayList(quic.Frame) = .empty,
    payload_scratch: std.ArrayList(u8) = .empty,
    data_prefix_scratch: body_batch.Prefix = undefined,
    batch_scratch: body_batch.Scratch = .{},
    max_streams: usize,

    pub fn init(allocator: std.mem.Allocator, max_streams: usize) Set {
        return .{ .allocator = allocator, .max_streams = max_streams };
    }

    pub fn deinit(self: *Set) void {
        self.batch_scratch.deinit(self.allocator);
        self.payload_scratch.deinit(self.allocator);
        self.frame_scratch.deinit(self.allocator);
        self.entries.deinit(self.allocator);
        self.entry_index.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn count(self: Set) usize {
        return self.entries.items.len;
    }

    pub fn isEmpty(self: Set) bool {
        return self.entries.items.len == 0;
    }

    pub fn reserveOpen(self: *Set, stream_id: u62) Error!void {
        if (!self.isEmpty() and self.find(stream_id) != null) {
            return error.UnexpectedStream;
        }
        if (self.count() >= self.max_streams) return error.ExcessiveLoad;
        try self.entries.ensureUnusedCapacity(self.allocator, 1);
        try self.entry_index.ensureUnusedCapacity(self.allocator, 1);
    }

    pub fn appendOpenAssumeCapacity(
        self: *Set,
        stream_id: u62,
        send: quic.stream_state.SendState,
        expected_length: ?usize,
    ) void {
        const index = self.entries.items.len;
        self.entries.appendAssumeCapacity(.{
            .send = send,
            .expected_length = expected_length,
        });
        self.entry_index.putAssumeCapacity(stream_id, index);
        self.last_entry_index = index;
    }

    pub fn prepareChunk(
        self: *Set,
        stream_id: u62,
        chunk_len: usize,
        fin: bool,
    ) Error!*Entry {
        const entry = self.find(stream_id) orelse return error.UnexpectedStream;
        try self.prepareChunkForEntry(entry, chunk_len, fin);
        return entry;
    }

    pub fn prepareChunkForEntry(
        self: *Set,
        entry: *Entry,
        chunk_len: usize,
        fin: bool,
    ) Error!void {
        _ = self;
        const next_written = std.math.add(
            usize,
            entry.written,
            chunk_len,
        ) catch return error.InvalidContentLength;
        if (entry.expected_length) |expected| {
            if (next_written > expected) return error.InvalidContentLength;
            if (fin and next_written != expected) {
                return error.InvalidContentLength;
            }
        }
        if (!fin and chunk_len == 0) return error.InvalidFrame;
        entry.written = next_written;
    }

    pub fn prepareTrailers(self: *Set, stream_id: u62) Error!*Entry {
        const entry = self.find(stream_id) orelse return error.UnexpectedStream;
        if (entry.expected_length) |expected| {
            if (entry.written != expected) return error.InvalidContentLength;
        }
        return entry;
    }

    pub fn finish(self: *Set, stream_id: u62) bool {
        if (self.isEmpty()) return false;
        const index = if (self.last_entry_index) |cached| blk: {
            if (cached < self.entries.items.len and
                self.entries.items[cached].send.stream_id == stream_id)
            {
                break :blk cached;
            }
            break :blk self.entry_index.get(stream_id) orelse return false;
        } else self.entry_index.get(stream_id) orelse return false;
        const last_index = self.entries.items.len - 1;
        const removed = self.entries.swapRemove(index);
        _ = self.entry_index.remove(@intCast(removed.send.stream_id));
        if (index != last_index) {
            const moved = self.entries.items[index];
            self.entry_index.getPtr(@intCast(moved.send.stream_id)).?.* = index;
        }
        self.last_entry_index = null;
        return true;
    }

    pub fn enableFlowLimit(
        self: *Set,
        stream_id: u62,
        additional_window: usize,
    ) Error!void {
        const entry = self.find(stream_id) orelse return error.UnexpectedStream;
        if (entry.flow_limit != null) return;
        const window = std.math.cast(u64, additional_window) orelse
            return error.InvalidWindow;
        entry.flow_limit = std.math.add(
            u64,
            entry.send.next_offset,
            window,
        ) catch return error.InvalidWindow;
    }

    pub fn updateFlowLimit(
        self: *Set,
        stream_id: u62,
        maximum_stream_data: u64,
    ) void {
        const entry = self.find(stream_id) orelse return;
        const current = entry.flow_limit orelse return;
        if (maximum_stream_data <= current) return;
        entry.flow_limit = maximum_stream_data;
    }

    pub fn find(self: *Set, stream_id: u62) ?*Entry {
        if (self.isEmpty()) return null;
        if (self.last_entry_index) |index| {
            if (index < self.entries.items.len and
                self.entries.items[index].send.stream_id == stream_id)
            {
                return &self.entries.items[index];
            }
        }
        const index = self.entry_index.get(stream_id) orelse return null;
        if (index >= self.entries.items.len) return null;
        if (self.entries.items[index].send.stream_id != stream_id) return null;
        self.last_entry_index = index;
        return &self.entries.items[index];
    }
};

test "HTTP/3 outbound body set indexes open streaming bodies" {
    const allocator = std.testing.allocator;
    var bodies = Set.init(allocator, 3);
    defer bodies.deinit();

    inline for (.{ @as(u62, 0), @as(u62, 4), @as(u62, 8) }) |stream_id| {
        try bodies.reserveOpen(stream_id);
        bodies.appendOpenAssumeCapacity(
            stream_id,
            quic.stream_state.SendState.init(stream_id),
            null,
        );
    }
    try std.testing.expectEqual(@as(usize, 3), bodies.count());
    try std.testing.expectError(error.ExcessiveLoad, bodies.reserveOpen(12));

    try std.testing.expect(bodies.find(4) != null);
    try std.testing.expect(bodies.finish(4));
    try std.testing.expect(bodies.find(4) == null);
    // Finishing stream 4 moved another entry into its slot. The index for that
    // moved entry must still let later DATA/trailer calls find the body state.
    try std.testing.expect(bodies.find(8) != null);
    try std.testing.expect(bodies.finish(8));

    try bodies.reserveOpen(12);
    bodies.appendOpenAssumeCapacity(
        12,
        quic.stream_state.SendState.init(12),
        5,
    );
    const entry = try bodies.prepareChunk(12, 5, true);
    try std.testing.expectEqual(@as(usize, 5), entry.written);
    try std.testing.expect(!bodies.finish(4));
    try std.testing.expect(bodies.finish(0));
    try std.testing.expect(bodies.finish(12));
    try std.testing.expect(bodies.isEmpty());
    try std.testing.expect(!bodies.finish(16));
    try std.testing.expect(bodies.find(16) == null);
}
