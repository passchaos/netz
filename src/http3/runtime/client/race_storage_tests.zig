const std = @import("std");
const runtime = @import("../../runtime.zig");
const shared = @import("../../../internal/testing/connection_race_storage.zig");

const Payload = struct {
    limits: runtime.Limits,
    options: runtime.HandshakeClientOptions,
};
const payload: Payload = .{
    .limits = .{ .quic = .{ .max_datagram_size = 1400 } },
    .options = .{ .handshake = .{ .original_destination_connection_id = "storage-original", .local_connection_id = "storage-client" } },
};
fn valid(value: *const Payload) bool {
    return value.limits.quic.max_datagram_size == 1400 and std.mem.eql(u8, value.options.handshake.original_destination_connection_id, "storage-original") and std.mem.eql(u8, value.options.handshake.local_connection_id, "storage-client");
}

test "HTTP3 connection race storage keeps handshake configuration out of candidate allocations" {
    try shared.compare(Payload, payload, valid);
}

test "HTTP3 connection race storage retains handshake configuration through canceled result cleanup" {
    try shared.ownership(Payload, payload, valid);
}
