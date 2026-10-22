const std = @import("std");
const quic = @import("../mod.zig");

pub const Kind = union(enum) {
    transport: struct {
        error_code: u64,
        frame_type: u64,
    },
    application: u64,
};

pub const Options = struct {
    kind: Kind,
    reason_phrase: []const u8,
    destination_connection_id_len: usize,
    packet_number: u64,
    largest_acknowledged: ?u64,
    max_datagram_size: usize,
};

pub const Error = quic.Error || quic.protection.Error || error{
    DatagramTooLarge,
};

/// Return the longest reason prefix whose complete protected short packet
/// fits the current path datagram size. Valid UTF-8 diagnostics are kept on a
/// code-point boundary; arbitrary byte strings retain byte-prefix semantics.
pub fn reasonPrefix(options: Options) Error![]const u8 {
    if (!try fits(options, &.{})) return error.DatagramTooLarge;

    const varint_reason_limit = std.math.cast(
        usize,
        quic.varint.max_value,
    ) orelse std.math.maxInt(usize);
    var low: usize = 0;
    var high = @min(options.reason_phrase.len, varint_reason_limit);
    while (low < high) {
        const distance = high - low;
        const candidate = low + distance / 2 + distance % 2;
        if (try fits(options, options.reason_phrase[0..candidate])) {
            low = candidate;
        } else {
            high = candidate - 1;
        }
    }
    if (low < options.reason_phrase.len and
        std.unicode.utf8ValidateSlice(options.reason_phrase))
    {
        while (low != 0 and
            options.reason_phrase[low] & 0xc0 == 0x80)
        {
            low -= 1;
        }
    }
    return options.reason_phrase[0..low];
}

fn fits(options: Options, reason_phrase: []const u8) Error!bool {
    const frame = closeFrame(options.kind, reason_phrase);
    const payload_len = try frame.wireLen();
    const packet_number_len = quic.protection.packetNumberLenForPayload(
        options.packet_number,
        options.largest_acknowledged,
        payload_len,
    );
    const packet_len = try quic.protection.shortPacketLenForPayloadLen(
        options.destination_connection_id_len,
        options.packet_number,
        packet_number_len,
        payload_len,
    );
    return packet_len <= options.max_datagram_size;
}

fn closeFrame(kind: Kind, reason_phrase: []const u8) quic.Frame {
    return switch (kind) {
        .transport => |close| .{ .connection_close = .{
            .error_code = close.error_code,
            .frame_type = close.frame_type,
            .reason_phrase = reason_phrase,
        } },
        .application => |error_code| .{ .application_close = .{
            .error_code = error_code,
            .reason_phrase = reason_phrase,
        } },
    };
}

test "close reason prefix accounts for exact protected packet overhead" {
    const reason: []const u8 = "x" ** 2000;
    const error_codes = [_]u64{
        0,
        63,
        64,
        16_383,
        16_384,
        (@as(u64, 1) << 30) - 1,
        @as(u64, 1) << 30,
        quic.varint.max_value,
    };
    for (error_codes) |error_code| {
        for ([_]Kind{
            .{ .application = error_code },
            .{ .transport = .{
                .error_code = error_code,
                .frame_type = quic.varint.max_value,
            } },
        }) |kind| {
            const options: Options = .{
                .kind = kind,
                .reason_phrase = reason,
                .destination_connection_id_len = 20,
                .packet_number = @as(u64, 1) << 30,
                .largest_acknowledged = 0,
                .max_datagram_size = quic.pmtu.min_udp_payload_size,
            };
            const prefix = try reasonPrefix(options);
            try std.testing.expect(prefix.len != 0);
            try std.testing.expect(prefix.len < reason.len);
            try std.testing.expect(try fits(options, prefix));
            try std.testing.expect(!try fits(
                options,
                reason[0 .. prefix.len + 1],
            ));
        }
    }
}

test "close reason prefix preserves valid UTF-8 boundaries" {
    const reason: []const u8 = "€" ** 700;
    const options: Options = .{
        .kind = .{ .application = quic.varint.max_value },
        .reason_phrase = reason,
        .destination_connection_id_len = 20,
        .packet_number = 0,
        .largest_acknowledged = null,
        .max_datagram_size = quic.pmtu.min_udp_payload_size,
    };
    const prefix = try reasonPrefix(options);
    try std.testing.expect(prefix.len != 0);
    try std.testing.expect(prefix.len < reason.len);
    try std.testing.expect(std.unicode.utf8ValidateSlice(prefix));
    try std.testing.expectEqual(@as(usize, 0), prefix.len % 3);
    try std.testing.expectEqualSlices(u8, reason[0..prefix.len], prefix);
}
