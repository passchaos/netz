//! Native source-family constraints on all streaming hostname entry points.
const std = @import("std");
const tcp = @import("../tcp_connect.zig");
const stream_io = @import("../stream_io.zig");
const zio = @import("zio");
const net = std.Io.net;

test "TCP ordered hostname source binding retains IPv4 and IPv6 families" {
    var backend = try zio.Runtime.init(std.testing.allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    var tested_families: usize = 0;
    for ([_]net.IpAddress{ .{ .ip4 = .loopback(0) }, .{ .ip6 = .loopback(0) } }) |local| {
        var listener = local.listen(io, .{}) catch |err| switch (err) {
            error.AddressFamilyUnsupported, error.AddressUnavailable => continue,
            else => return err,
        };
        defer listener.deinit(io);
        tested_families += 1;
        const host = try net.HostName.init("localhost");
        inline for (.{ .legacy_timeout, .legacy_deadline, .binding }) |route| {
            const stream = try switch (route) {
                .legacy_timeout => tcp.hostBound(io, host, listener.socket.address.getPort(), local, .fromSeconds(2)),
                .legacy_deadline => tcp.hostBoundWithDeadline(io, host, listener.socket.address.getPort(), local, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) })),
                .binding => tcp.hostWithOptions(io, host, listener.socket.address.getPort(), .fromSeconds(2), tcp.Binding{ .local_address = local }),
                else => unreachable,
            };
            defer stream.close(io);
            const accepted = try listener.accept(io);
            defer accepted.close(io);
            try std.testing.expectEqual(std.meta.activeTag(local), std.meta.activeTag(accepted.socket.address));
            switch (local) {
                .ip4 => |ip4| try std.testing.expectEqualSlices(u8, &ip4.bytes, &accepted.socket.address.ip4.bytes),
                .ip6 => |ip6| try std.testing.expectEqualSlices(u8, &ip6.bytes, &accepted.socket.address.ip6.bytes),
            }
            try std.testing.expectEqual(stream.socket.address.getPort(), accepted.socket.address.getPort());
            try stream_io.writeAllParts(io, stream, "source", "");
            var reader = accepted.reader(io, &.{});
            var bytes: [6]u8 = undefined;
            try reader.interface.readSliceAll(&bytes);
            try std.testing.expectEqualStrings("source", &bytes);
        }
    }
    if (tested_families == 0) return error.SkipZigTest;
}
