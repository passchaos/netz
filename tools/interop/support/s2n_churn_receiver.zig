const std = @import("std");
const netz = @import("netz");
const churn = @import("s2n_churn.zig");

const max_chunk_len = 1024;

pub fn run(connection: *netz.quic.one_rtt.Connection) !churn.Result {
    const deadline = std.Io.Clock.Timestamp.fromNow(connection.endpoint.io, .{
        .clock = .awake,
        .raw = .fromSeconds(30),
    });
    var marker: [churn.start.len]u8 = undefined;
    try churn.receiveExact(connection, 0, &marker, false, deadline);
    if (!std.mem.eql(u8, &marker, churn.start)) {
        return error.InvalidChurnControl;
    }

    var result: churn.Result = .{
        .streams = churn.stream_count,
        .fins = 0,
        .resets = 0,
        .received_bytes = 0,
        .checksum = 0,
        .reset_mask = 0,
        .reset_code_sum = 0,
    };
    var prefix: [churn.prefix_bytes]u8 = undefined;
    for (0..churn.stream_count) |index| {
        const stream_id = peerDataStreamId(index);
        try churn.receiveExact(connection, stream_id, &prefix, false, deadline);
        result.received_bytes += prefix.len;
        result.checksum +%= try verifyPayload(&prefix, index, 0);
    }

    var control_offset: u64 = 0;
    try churn.sendExact(
        connection,
        0,
        &control_offset,
        churn.ready,
        false,
        deadline,
    );
    var buffer: [max_chunk_len]u8 = undefined;
    var reset_marker: [churn.reset_sent.len]u8 = undefined;
    try churn.receiveExact(connection, 0, &reset_marker, false, deadline);
    if (!std.mem.eql(u8, &reset_marker, churn.reset_sent)) {
        return error.InvalidChurnControl;
    }
    for (0..churn.stream_count) |index| {
        if (!churn.shouldReset(index)) continue;
        const stream_id = peerDataStreamId(index);
        const event = try connection.receiveStreamIdWithDeadline(
            stream_id,
            &buffer,
            deadline,
        );
        const reset = switch (event) {
            .data => return error.ExpectedReset,
            .reset => |value| value,
        };
        if (reset.stream_id != stream_id or
            reset.application_error_code != churn.reset_code_base + index or
            reset.final_size != churn.prefix_bytes)
        {
            return error.InvalidChurnReset;
        }
        result.resets += 1;
        result.reset_mask |= @as(u64, 1) << @intCast(index);
        result.reset_code_sum += reset.application_error_code;
    }
    try churn.sendExact(
        connection,
        0,
        &control_offset,
        churn.resets_observed,
        false,
        deadline,
    );

    var fin_marker: [churn.fin_sent.len]u8 = undefined;
    try churn.receiveExact(connection, 0, &fin_marker, false, deadline);
    if (!std.mem.eql(u8, &fin_marker, churn.fin_sent)) {
        return error.InvalidChurnControl;
    }
    for (0..churn.stream_count) |index| {
        if (churn.shouldReset(index)) continue;
        const stream_id = peerDataStreamId(index);

        var offset: usize = churn.prefix_bytes;
        while (true) {
            const event = try connection.receiveStreamIdWithDeadline(
                stream_id,
                &buffer,
                deadline,
            );
            const data = switch (event) {
                .reset => return error.UnexpectedReset,
                .data => |value| value,
            };
            if (data.stream_id != stream_id or
                offset + data.bytes > churn.bytes_per_stream)
            {
                return error.InvalidChurnPayload;
            }
            result.checksum +%= try verifyPayload(
                buffer[0..data.bytes],
                index,
                offset,
            );
            result.received_bytes += data.bytes;
            offset += data.bytes;
            if (data.fin) {
                if (offset != churn.bytes_per_stream) {
                    return error.InvalidChurnPayload;
                }
                break;
            }
        }
        result.fins += 1;
    }

    if (!std.meta.eql(result, churn.expectedResult())) {
        return error.InvalidChurnResult;
    }
    const encoded = result.encode();
    try churn.sendExact(
        connection,
        0,
        &control_offset,
        &encoded,
        false,
        deadline,
    );
    var ack_marker: [churn.ack.len]u8 = undefined;
    try churn.receiveExact(connection, 0, &ack_marker, true, deadline);
    if (!std.mem.eql(u8, &ack_marker, churn.ack)) {
        return error.InvalidChurnControl;
    }
    return result;
}

fn peerDataStreamId(index: usize) u62 {
    return @intCast(4 + index * 4);
}

fn verifyPayload(bytes: []const u8, stream_index: usize, offset: usize) !u64 {
    var checksum: u64 = 0;
    for (bytes, 0..) |byte, index| {
        if (byte != churn.payloadByte(stream_index, offset + index)) {
            return error.InvalidChurnPayload;
        }
        checksum +%= byte;
    }
    return checksum;
}
