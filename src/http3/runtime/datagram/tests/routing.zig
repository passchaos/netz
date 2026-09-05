const std = @import("std");
const connect_datagram = @import("../../datagram.zig");
const routing = @import("../routing.zig");

test "HTTP/3 CONNECT datagram routing preserves first terminal" {
    var registry = connect_datagram.Registry.init(std.testing.allocator, .{
        .max_associations = 2,
        .max_queued_per_association = 1,
        .max_queued_bytes_per_association = 32,
    });
    defer registry.deinit();
    try registry.register(0);
    try registry.register(4);

    registry.markTerminal(0, .peer_fin);
    registry.markAllTerminal(.connection_closed);
    try std.testing.expectEqual(
        connect_datagram.Terminal.peer_fin,
        (try registry.terminal(0)).?,
    );
    try std.testing.expectEqual(
        connect_datagram.Terminal.connection_closed,
        (try registry.terminal(4)).?,
    );
}

test "HTTP/3 CONNECT datagram routing maps terminal errors" {
    try std.testing.expectEqual(
        error.ConnectDatagramAssociationClosed,
        routing.terminalError(.peer_fin),
    );
    try std.testing.expectEqual(
        error.RequestCancelled,
        routing.terminalError(.{ .peer_reset = 0x10c }),
    );
    try std.testing.expectEqual(
        error.ConnectionClosed,
        routing.terminalError(.connection_closed),
    );
}
