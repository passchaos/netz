//! Shared assertions for the actual standalone/shared receive owners.
const std = @import("std");
const protocol = @import("protocol.zig");
const quic = @import("../netz.zig").quic;

pub fn exercise(io: std.Io, owner: anytype, allocator_slot: *std.mem.Allocator, comptime data: anytype, comptime reset: anytype) !void {
    const allocator = std.testing.allocator;
    var payload: [4096]u8 = undefined;
    for (&payload, 0..) |*byte, i| byte.* = @intCast(i % 251);
    const encoded = try protocol.buildPacket(allocator, .{ .assoc_id = 1, .pkt_id = 2, .frag_total = 1, .frag_id = 0, .address = .{ .ip = .{ .ip4 = .loopback(53) } }, .payload = &payload });
    defer allocator.free(encoded);
    const partial = encoded[0..3000];
    var sender_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096, .enable_gso_send = false });
    defer sender_endpoint.deinit();
    var receiver_endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
    defer receiver_endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys([_]u8{0x53} ** 32);
    var sender = try quic.one_rtt.Connection.init(&sender_endpoint, .{ .peer = receiver_endpoint.address(), .receive_keys = keys, .send_keys = keys, .local_connection_id = "sender", .peer_connection_id = "peer", .enable_pacing = false, .max_datagram_size = 1280, .initial_send_max_data = 64 * 1024, .initial_send_max_stream_data = 64 * 1024 });
    defer sender.deinit();
    var receiver = try quic.one_rtt.Connection.init(&receiver_endpoint, .{ .peer = sender_endpoint.address(), .receive_keys = keys, .send_keys = keys, .local_connection_id = "peer", .peer_connection_id = "sender", .local_endpoint = .server, .enable_pacing = false });
    defer receiver.deinit();
    const id = try sender.openUnidirectionalStream();
    try std.testing.expectEqual(@as(u64, 2), id);
    var committed: usize = 0;
    try sender.sendStreamWithTimeout(id, 0, partial, false, &committed, .fromSeconds(1));
    try std.testing.expectEqual(partial.len, committed);
    var buffer: [4096]u8 = undefined;
    var received: usize = 0;
    while (received < partial.len) {
        switch (try receiver.receiveStreamWithTimeout(&buffer, .fromSeconds(1))) {
            .data => |event| {
                try std.testing.expectEqual(id, event.stream_id);
                try std.testing.expect(!event.fin);
                try data(owner, id, buffer[0..event.bytes], false);
                received += event.bytes;
            },
            .reset => return error.UnexpectedReset,
        }
    }
    const retained = owner.uni_pending[0].input.heap;
    try std.testing.expect(retained.len >= partial.len);
    try data(owner, 6, &.{protocol.version}, false);
    reset(owner, 998);
    try std.testing.expectEqualSlices(u8, partial, owner.uni_pending[0].input.bytes());
    try std.testing.expect(owner.uni_pending[1].active);

    try sender.resetStreamWithTimeout(id, 0, .fromSeconds(1));
    switch (try receiver.receiveStreamWithTimeout(&buffer, .fromSeconds(1))) {
        .reset => |event| {
            try std.testing.expectEqual(id, event.stream_id);
            reset(owner, event.stream_id);
        },
        .data => return error.UnexpectedData,
    }
    try std.testing.expect(!owner.uni_pending[0].active);
    try std.testing.expectEqual(@as(usize, 0), owner.uni_pending[0].input.len);
    try std.testing.expectEqual(retained.ptr, owner.uni_pending[0].input.heap.ptr);
    try std.testing.expectEqual(retained.len, owner.uni_pending[0].input.heap.len);
    try std.testing.expect(owner.uni_pending[1].active);
    try std.testing.expectEqualSlices(u8, &.{protocol.version}, owner.uni_pending[1].input.bytes());

    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    allocator_slot.* = failing.allocator();
    defer allocator_slot.* = allocator;
    for (0..128) |i| {
        const reuse_id: u64 = 10 + 4 * i;
        try data(owner, reuse_id, partial, false);
        try std.testing.expectEqualSlices(u8, partial, owner.uni_pending[0].input.bytes());
        reset(owner, reuse_id);
        try std.testing.expect(!owner.uni_pending[0].active and owner.uni_pending[0].input.len == 0);
        try std.testing.expectEqual(retained.ptr, owner.uni_pending[0].input.heap.ptr);
        try std.testing.expect(owner.uni_pending[1].active);
    }
    reset(owner, 6);
    for (&owner.uni_pending) |*pending| try std.testing.expect(!pending.active and pending.input.len == 0);
}
