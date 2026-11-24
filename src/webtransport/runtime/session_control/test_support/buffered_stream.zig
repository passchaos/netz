//! Leave a real peer stream buffered without claiming an application reader.
const std = @import("std");
const support = @import("handshake_pair.zig");

pub fn ready(pair: *support.Pair, comptime role: support.Role, payload: []const u8, fin: bool) !u62 {
    const peer = if (role == .client) &pair.server else &pair.client;
    const id = try peer.openUnidirectionalStream();
    try peer.sendStream(id, payload, fin);
    const source = pair.connection(if (role == .client) .server else .client);
    const expected = source.sendStreamStats(id).?.highest_sent_offset;
    const receiver = pair.connection(role);
    const until: std.Io.Clock.Timestamp = .fromNow(receiver.endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    while (true) {
        if (receiver.recvStreamStats(id)) |stats| {
            const complete = !fin or (stats.final_size != null and stats.final_size.? == expected);
            if (stats.highest_received_offset >= expected and complete) return id;
        }
        try pair.receiveProgress(role, until);
    }
}
