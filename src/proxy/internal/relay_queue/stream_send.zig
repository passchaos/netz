//! One packet-sized relay send with exact socket-visible progress.
const queues = @import("../relay_queue.zig");
const packet = @import("../stream_packet.zig");

pub const Progress = struct {
    committed_bytes: usize = 0,
    complete: bool = false,
};

pub fn send(
    comptime quic: type,
    connection: *quic.one_rtt.Connection,
    relay: *queues.Relay,
    item: queues.Outbound,
    maximum_bytes: usize,
    progress: *Progress,
) quic.one_rtt.Error!void {
    const remaining: []const u8 = switch (item) {
        .data => |bytes| bytes[relay.pending_data_start..],
        .fin => &.{},
    };
    var sent: packet.Progress = .{};
    const result = packet.send(quic, connection, relay.stream_id, relay.send_offset, remaining, item == .fin, maximum_bytes, &sent);
    progress.* = .{ .committed_bytes = sent.committed_bytes, .complete = sent.complete };
    if (sent.committed_bytes != 0 or sent.fin_committed) {
        relay.send_offset += sent.committed_bytes;
        relay.pending_data_start += sent.committed_bytes;
        if (sent.fin_committed) relay.quic_fin_sent = true;
        relay.touch();
    }
    return result;
}
