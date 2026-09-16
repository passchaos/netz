const std = @import("std");
const netz = @import("netz");

pub const stream_count: usize = 32;
pub const bytes_per_stream: usize = 16 * 1024;
pub const prefix_bytes: usize = 256;
pub const reset_code_base: u64 = 0x4000;
pub const start = "NZS2NCH1";
pub const ready = "NZS2NRD1";
pub const done = "NZS2NDN1";
pub const ack = "NZS2NAK1";
const result_len = 48;
const max_chunk_len = 1024;

pub const Result = struct {
    streams: u16,
    fins: u16,
    resets: u16,
    received_bytes: u64,
    checksum: u64,
    reset_mask: u64,
    reset_code_sum: u64,

    pub fn encode(self: Result) [result_len]u8 {
        var out = [_]u8{0} ** result_len;
        @memcpy(out[0..8], "NZS2NRS1");
        std.mem.writeInt(u16, out[8..10], self.streams, .big);
        std.mem.writeInt(u16, out[10..12], self.fins, .big);
        std.mem.writeInt(u16, out[12..14], self.resets, .big);
        std.mem.writeInt(u64, out[16..24], self.received_bytes, .big);
        std.mem.writeInt(u64, out[24..32], self.checksum, .big);
        std.mem.writeInt(u64, out[32..40], self.reset_mask, .big);
        std.mem.writeInt(u64, out[40..48], self.reset_code_sum, .big);
        return out;
    }

    pub fn decode(bytes: *const [result_len]u8) !Result {
        if (!std.mem.eql(u8, bytes[0..8], "NZS2NRS1") or
            bytes[14] != 0 or bytes[15] != 0)
        {
            return error.InvalidChurnResult;
        }
        return .{
            .streams = std.mem.readInt(u16, bytes[8..10], .big),
            .fins = std.mem.readInt(u16, bytes[10..12], .big),
            .resets = std.mem.readInt(u16, bytes[12..14], .big),
            .received_bytes = std.mem.readInt(u64, bytes[16..24], .big),
            .checksum = std.mem.readInt(u64, bytes[24..32], .big),
            .reset_mask = std.mem.readInt(u64, bytes[32..40], .big),
            .reset_code_sum = std.mem.readInt(u64, bytes[40..48], .big),
        };
    }
};

pub fn expectedResult() Result {
    var result: Result = .{
        .streams = stream_count,
        .fins = 0,
        .resets = 0,
        .received_bytes = 0,
        .checksum = 0,
        .reset_mask = 0,
        .reset_code_sum = 0,
    };
    for (0..stream_count) |index| {
        const count = if (shouldReset(index)) prefix_bytes else bytes_per_stream;
        result.received_bytes += count;
        for (0..count) |offset| result.checksum +%= payloadByte(index, offset);
        if (shouldReset(index)) {
            result.resets += 1;
            result.reset_mask |= @as(u64, 1) << @intCast(index);
            result.reset_code_sum += reset_code_base + index;
        } else {
            result.fins += 1;
        }
    }
    return result;
}

pub fn runSender(connection: *netz.quic.one_rtt.Connection) !Result {
    const deadline = std.Io.Clock.Timestamp.fromNow(connection.endpoint.io, .{
        .clock = .awake,
        .raw = .fromSeconds(30),
    });
    var control_offset: u64 = 0;
    const control_id = try connection.openStreamWithDeadline(deadline);
    if (control_id != 0) return error.UnexpectedStreamId;
    try sendExact(connection, control_id, &control_offset, start, false, deadline);

    var ids: [stream_count]u64 = undefined;
    var prefix: [prefix_bytes]u8 = undefined;
    for (&ids, 0..) |*stream_id, index| {
        stream_id.* = try connection.openStreamWithDeadline(deadline);
        const expected_id: u64 = 4 + index * 4;
        if (stream_id.* != expected_id) return error.UnexpectedStreamId;
        fillPayload(&prefix, index, 0);
        var offset: u64 = 0;
        try sendExact(connection, stream_id.*, &offset, &prefix, false, deadline);
    }

    var marker: [ready.len]u8 = undefined;
    try receiveExact(connection, 0, &marker, false, deadline);
    if (!std.mem.eql(u8, &marker, ready)) return error.InvalidChurnControl;

    var payload: [max_chunk_len]u8 = undefined;
    for (ids, 0..) |stream_id, index| {
        if (shouldReset(index)) {
            try connection.resetStreamWithDeadline(
                stream_id,
                reset_code_base + index,
                deadline,
            );
            continue;
        }
        var offset: usize = prefix_bytes;
        while (offset < bytes_per_stream) {
            const application_offset: usize = @intCast(offset);
            const count = @min(payload.len, bytes_per_stream - application_offset);
            fillPayload(payload[0..count], index, application_offset);
            const terminal = application_offset + count == bytes_per_stream;
            var committed: usize = 0;
            try connection.sendStreamWithDeadline(
                stream_id,
                offset,
                payload[0..count],
                terminal,
                &committed,
                deadline,
            );
            if (committed != count) return error.IncompleteChurnSend;
            offset += committed;
        }
    }

    try sendExact(connection, 0, &control_offset, done, false, deadline);
    var encoded: [result_len]u8 = undefined;
    try receiveExact(connection, 0, &encoded, false, deadline);
    const result = try Result.decode(&encoded);
    if (!std.meta.eql(result, expectedResult())) return error.InvalidChurnResult;
    try sendExact(connection, 0, &control_offset, ack, true, deadline);
    return result;
}

pub fn shouldReset(index: usize) bool {
    return index % 2 == 1;
}

pub fn payloadByte(stream_index: usize, offset: usize) u8 {
    return @truncate(offset *% 131 +% stream_index *% 17);
}

pub fn fillPayload(bytes: []u8, stream_index: usize, offset: usize) void {
    for (bytes, 0..) |*byte, index| byte.* = payloadByte(stream_index, offset + index);
}

pub fn sendExact(
    connection: *netz.quic.one_rtt.Connection,
    stream_id: u64,
    offset: *u64,
    bytes: []const u8,
    fin: bool,
    deadline: std.Io.Clock.Timestamp,
) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        const count = @min(max_chunk_len, bytes.len - written);
        var committed: usize = 0;
        try connection.sendStreamWithDeadline(
            stream_id,
            offset.*,
            bytes[written..][0..count],
            fin and written + count == bytes.len,
            &committed,
            deadline,
        );
        if (committed != count) return error.IncompleteChurnSend;
        offset.* += committed;
        written += committed;
    }
    if (bytes.len == 0 and fin) {
        var committed: usize = 0;
        try connection.sendStreamWithDeadline(
            stream_id,
            offset.*,
            &.{},
            true,
            &committed,
            deadline,
        );
    }
}

pub fn receiveExact(
    connection: *netz.quic.one_rtt.Connection,
    stream_id: u62,
    out: []u8,
    expect_fin: bool,
    deadline: std.Io.Clock.Timestamp,
) !void {
    var received: usize = 0;
    var fin = false;
    var scratch: [1]u8 = undefined;
    while (received < out.len or expect_fin and !fin) {
        const target = if (received < out.len) out[received..] else scratch[0..];
        const event = try connection.receiveStreamIdWithDeadline(
            stream_id,
            target,
            deadline,
        );
        switch (event) {
            .reset => return error.UnexpectedReset,
            .data => |data| {
                if (data.stream_id != stream_id or received + data.bytes > out.len) {
                    return error.InvalidChurnControl;
                }
                received += data.bytes;
                fin = fin or data.fin;
            },
        }
    }
    if (fin != expect_fin) return error.InvalidChurnControl;
}

test "s2n churn result is stable" {
    const result = expectedResult();
    try std.testing.expectEqual(@as(u16, 32), result.streams);
    try std.testing.expectEqual(@as(u16, 16), result.fins);
    try std.testing.expectEqual(@as(u16, 16), result.resets);
    try std.testing.expectEqual(@as(u64, 266_240), result.received_bytes);
    try std.testing.expectEqual(@as(u64, 33_945_600), result.checksum);
    try std.testing.expectEqual(@as(u64, 0xaaaa_aaaa), result.reset_mask);
    try std.testing.expectEqual(@as(u64, 262_400), result.reset_code_sum);
    try std.testing.expectEqual(result, try Result.decode(&result.encode()));
}
