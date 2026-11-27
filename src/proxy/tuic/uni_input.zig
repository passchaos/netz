//! Reusable command storage bounded by UDP payload plus its wire header.
const std = @import("std");
const Buffer = @import("../internal/relay_queue/pending_input.zig").Buffer;
const protocol = @import("protocol.zig");

pub const Input = struct {
    stream_id: u64 = 0,
    input: Buffer = .{},
    active: bool = false,

    pub fn start(self: *Input, id: u64) void {
        self.stream_id = id;
        self.active = true;
        self.input.len = 0;
    }
    pub fn append(self: *Input, allocator: std.mem.Allocator, maximum_payload: usize, bytes: []const u8) !void {
        const maximum = std.math.add(usize, maximum_payload, protocol.maximum_packet_header_bytes) catch return error.InvalidCommand;
        self.input.append(allocator, maximum, bytes) catch |err| {
            self.active = false;
            self.input.len = 0;
            return err;
        };
    }
    pub fn consume(self: *Input, count: usize) void {
        const bytes = self.input.bytes();
        std.mem.copyForwards(u8, bytes[0 .. bytes.len - count], bytes[count..]);
        self.input.len -= count;
    }
    pub fn finish(self: *Input, fin: bool) !void {
        if (!fin) return;
        const incomplete = self.input.len != 0;
        self.cancel();
        if (incomplete) return error.InvalidCommand;
    }
    /// Release the parser slot and byte borrow while retaining its allocation.
    pub fn cancel(self: *Input) void {
        self.active = false;
        self.input.len = 0;
    }
    pub fn deinit(self: *Input, allocator: std.mem.Allocator) void {
        self.input.deinit(allocator);
        self.active = false;
    }
};

/// A late/unknown reset cannot retire a sibling occupying a reused slot.
pub fn cancelStream(inputs: []Input, stream_id: u64) void {
    for (inputs) |*input| {
        if (input.active and input.stream_id == stream_id) {
            input.cancel();
            return;
        }
    }
}

test "TUIC uni input holds full payload plus domain header and reuses bounded storage" {
    const allocator = std.testing.allocator;
    var host: [253]u8 = @splat('a');
    host[63] = '.';
    host[127] = '.';
    host[191] = '.';
    var payload: [4096]u8 = undefined;
    for (&payload, 0..) |*byte, i| byte.* = @intCast(i % 251);
    const encoded = try protocol.buildPacket(allocator, .{ .assoc_id = 1, .pkt_id = 2, .frag_total = 1, .frag_id = 0, .address = .{ .domain = .{ .host = &host, .port = 53 } }, .payload = &payload });
    defer allocator.free(encoded);
    var input: Input = .{};
    defer input.deinit(allocator);
    input.start(2);
    for (0..encoded.len) |i| try input.append(allocator, payload.len, encoded[i..][0..1]);
    const parsed = try protocol.parsePacket(input.input.bytes());
    try std.testing.expectEqualSlices(u8, &payload, parsed.packet.payload);
    try std.testing.expectEqualSlices(u8, &host, parsed.packet.address.domain.host);
    const retained = input.input.heap.len;
    try std.testing.expect(retained <= payload.len + protocol.maximum_packet_header_bytes);
    input.consume(parsed.end);
    try input.finish(true);
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    input.start(6);
    try input.append(failing.allocator(), payload.len, encoded);
    try std.testing.expectEqualSlices(u8, encoded, input.input.bytes());
    try std.testing.expectEqual(retained, input.input.heap.len);
    try std.testing.expectError(error.PendingBufferFull, input.append(allocator, payload.len, "xxx"));
    try std.testing.expect(!input.active and input.input.len == 0);
    input.start(10);
    try input.append(allocator, payload.len, encoded[0..1]);
    try std.testing.expectError(error.InvalidCommand, input.finish(true));
    try std.testing.expect(!input.active and input.input.len == 0);
}
