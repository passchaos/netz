//! One TUIC Packet per unidirectional stream, retained across send refusal.
const netz = @import("../netz.zig");
const quic = netz.quic;

pub const PacketStream = struct {
    stream_id: ?u64 = null,

    /// A successful packet closes its stream. Refusal keeps the empty stream
    /// for the same owned FIFO front, without opening more streams on retry.
    pub fn send(self: *PacketStream, connection: *quic.one_rtt.Connection, bytes: []const u8) quic.one_rtt.Error!bool {
        const id = self.stream_id orelse blk: {
            const opened = try connection.tryOpenUnidirectionalStream();
            self.stream_id = opened;
            break :blk opened;
        };
        const frame = quic.Frame{ .stream = .{ .stream_id = id, .offset = 0, .data = bytes, .fin = true } };
        const result = try connection.sendManyProgress(&.{&.{frame}});
        if (result.sent_count > 1 or result.sent_count > result.protected_count) return error.Unexpected;
        // A complete committed packet must never be replayed with another FIN.
        if (result.sent_count == 1) {
            self.stream_id = null;
            return true;
        }
        if (result.send_error) |err| return err;
        return error.Unexpected;
    }
};
