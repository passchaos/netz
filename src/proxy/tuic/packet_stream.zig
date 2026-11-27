//! One TUIC Packet per stream, with a retained prefix through partial output.
const std = @import("std");
const quic = @import("../netz.zig").quic;
const packet = @import("../internal/stream_packet.zig");

pub const Progress = packet.Progress;
pub const PacketStream = struct {
    stream_id: ?u64 = null,
    cursor: usize = 0,
    payload: []const u8 = &.{},
    canceling: bool = false,

    fn start(self: *PacketStream, connection: *quic.one_rtt.Connection, bytes: []const u8) quic.one_rtt.Error!u64 {
        if (self.stream_id) |id| {
            if (self.payload.ptr != bytes.ptr or self.payload.len != bytes.len) return error.InvalidFrameLength;
            return id;
        }
        const id = try connection.tryOpenUnidirectionalStream();
        self.* = .{ .stream_id = id, .payload = bytes };
        return id;
    }

    /// At most one packet per call. The caller keeps bytes immutable until
    /// completion or beginCancel; progress remains exact on every error path.
    pub fn send(self: *PacketStream, connection: *quic.one_rtt.Connection, bytes: []const u8, progress: *Progress) quic.one_rtt.Error!void {
        progress.* = .{};
        if (self.canceling) {
            try self.flushCancel(connection);
            return;
        }
        const id = try self.start(connection, bytes);
        const result = packet.send(quic, connection, id, @intCast(self.cursor), bytes[self.cursor..], true, bytes.len, progress);
        self.cursor += progress.committed_bytes;
        if (progress.fin_committed) self.* = .{};
        return result;
    }

    /// Retain the original timed send quantum for standalone owners. Each
    /// call can packetize the remaining prefix while servicing transport I/O.
    pub fn sendWithTimeout(self: *PacketStream, connection: *quic.one_rtt.Connection, bytes: []const u8, timeout: std.Io.Duration, progress: *Progress) (quic.one_rtt.Error || quic.runtime.ReceiveTimeoutError)!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const id = try self.start(connection, bytes);
        const remaining = bytes[self.cursor..];
        var committed: usize = 0;
        const result = connection.sendStreamWithTimeout(id, @intCast(self.cursor), remaining, true, &committed, timeout);
        self.cursor += committed;
        const stats = connection.getSendStreamStats(id);
        const complete = committed == remaining.len and stats != null and stats.?.reset == null and stats.?.final_size != null and stats.?.final_size.? == self.cursor;
        progress.* = .{ .committed_bytes = committed, .complete = complete, .fin_committed = complete };
        if (complete) self.* = .{};
        return result;
    }

    /// Stop borrowing payload bytes; the stream ID remains owned until reset
    /// reaches the socket or its connection is destroyed.
    pub fn beginCancel(self: *PacketStream) void {
        self.payload = &.{};
        self.canceling = self.stream_id != null;
    }

    pub fn flushCancel(self: *PacketStream, connection: *quic.one_rtt.Connection) quic.one_rtt.Error!void {
        if (self.stream_id) |id| try connection.tryResetStream(id, 0);
        self.* = .{};
    }
};

/// Fixed storage for stream resets after their association/packet is gone.
/// Saturation leaves ownership with the caller, which closes the connection.
pub const Retirements = struct {
    pub const capacity = 64;
    slots: [capacity]?PacketStream = @splat(null),
    count: usize = 0,

    pub fn add(self: *Retirements, stream: *PacketStream) bool {
        if (stream.stream_id == null) return true;
        if (self.count == capacity) return false;
        stream.beginCancel();
        for (&self.slots) |*slot| {
            if (slot.* != null) continue;
            slot.* = stream.*;
            stream.* = .{};
            self.count += 1;
            return true;
        }
        unreachable;
    }

    pub fn flush(self: *Retirements, connection: *quic.one_rtt.Connection) quic.one_rtt.Error!void {
        var attempts: usize = 0;
        for (&self.slots) |*slot| {
            if (attempts == 8) break;
            const stream = if (slot.*) |*value| value else continue;
            attempts += 1;
            try stream.flushCancel(connection);
            slot.* = null;
            self.count -= 1;
        }
    }
};

test {
    _ = @import("packet_stream_tests.zig");
}
