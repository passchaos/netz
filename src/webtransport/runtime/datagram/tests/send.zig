const std = @import("std");
const webtransport = @import("../../../mod.zig");
const quic = @import("../../../../quic/mod.zig");
const send = @import("../send.zig");

test "WebTransport protected DATAGRAM common send is allocation-free" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x77} ** quic.protection.secret_len,
    );
    var packet_number: u64 = 9;
    var fail = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    const original_allocator = sender.allocator;
    sender.allocator = fail.allocator();
    errdefer sender.allocator = original_allocator;
    try send.protected(
        &sender,
        receiver.address(),
        keys,
        "receiver",
        &packet_number,
        .init(4),
        "stack protected",
    );
    sender.allocator = original_allocator;
    try std.testing.expect(!fail.has_induced_failure);
    try std.testing.expectEqual(@as(u64, 10), packet_number);

    var packet = try quic.one_rtt.receive(
        &receiver,
        keys,
        "receiver".len,
        9,
        4,
    );
    defer packet.deinit(allocator);
    const parsed = try webtransport.Datagram.parse(
        packet.frames[0].datagram.data,
    );
    try std.testing.expectEqual(@as(u62, 4), parsed.session_id.value);
    try std.testing.expectEqualStrings("stack protected", parsed.payload);
}
