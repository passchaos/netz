//! Adapter from netz QUIC codec frames to allocation-free qlog frame views.

const quic = @import("../../mod.zig");
const events = @import("events.zig");

pub const Error = error{
    InsufficientAckRangeStorage,
    InvalidAckDelayExponent,
};

pub const Options = struct {
    ack_delay_exponent: u6 = 3,
};

pub const AdaptedFrame = struct {
    frame: events.Frame,
    ack_ranges_used: usize = 0,
};

/// Adapt one codec frame. ACK ranges are copied into caller storage because
/// the qlog event vocabulary intentionally does not depend on codec internals.
pub fn adapt(
    frame: quic.Frame,
    ack_range_storage: []events.AckRange,
    options: Options,
) Error!AdaptedFrame {
    return switch (frame) {
        .padding => |padding| .{ .frame = .{ .padding = .{ .length = padding.len } } },
        .ping => .{ .frame = .{ .ping = {} } },
        .ack => |ack| blk: {
            if (ack.ranges.len > ack_range_storage.len) {
                return error.InsufficientAckRangeStorage;
            }
            for (ack.ranges, ack_range_storage[0..ack.ranges.len]) |source, *out| {
                out.* = .{
                    .gap = source.gap,
                    .ack_range_length = source.ack_range_length,
                };
            }
            break :blk .{
                .frame = .{ .ack = .{
                    .largest_acknowledged = ack.largest_acknowledged,
                    .ack_delay_ms = try decodeAckDelayMilliseconds(
                        ack.ack_delay,
                        options.ack_delay_exponent,
                    ),
                    .first_ack_range = ack.first_ack_range,
                    .ranges = ack_range_storage[0..ack.ranges.len],
                    .ecn_counts = if (ack.ecn_counts) |ecn| .{
                        .ect0 = ecn.ect0_count,
                        .ect1 = ecn.ect1_count,
                        .ce = ecn.ecn_ce_count,
                    } else null,
                } },
                .ack_ranges_used = ack.ranges.len,
            };
        },
        .reset_stream => |reset| .{ .frame = .{ .reset_stream = .{
            .stream_id = reset.stream_id,
            .error_code = reset.application_error_code,
            .final_size = reset.final_size,
        } } },
        .stop_sending => |stop| .{ .frame = .{ .stop_sending = .{
            .stream_id = stop.stream_id,
            .error_code = stop.application_error_code,
        } } },
        .new_token => |token| .{ .frame = .{ .new_token = .{ .length = token.token.len } } },
        .crypto => |crypto| .{ .frame = .{ .crypto = .{
            .offset = crypto.offset,
            .length = crypto.data.len,
        } } },
        .stream => |stream| .{ .frame = .{ .stream = .{
            .stream_id = stream.stream_id,
            .offset = stream.offset,
            .length = stream.data.len,
            .fin = stream.fin,
        } } },
        .max_data => |max_data| .{ .frame = .{ .max_data = .{
            .maximum = max_data.maximum_data,
        } } },
        .max_stream_data => |max_data| .{ .frame = .{ .max_stream_data = .{
            .stream_id = max_data.stream_id,
            .maximum = max_data.maximum_stream_data,
        } } },
        .max_streams_bidi => |max_streams| .{ .frame = .{ .max_streams = .{
            .stream_type = .bidirectional,
            .maximum = max_streams.maximum_streams,
        } } },
        .max_streams_uni => |max_streams| .{ .frame = .{ .max_streams = .{
            .stream_type = .unidirectional,
            .maximum = max_streams.maximum_streams,
        } } },
        .data_blocked => |blocked| .{ .frame = .{ .data_blocked = .{
            .limit = blocked.maximum_data,
        } } },
        .stream_data_blocked => |blocked| .{ .frame = .{ .stream_data_blocked = .{
            .stream_id = blocked.stream_id,
            .limit = blocked.maximum_stream_data,
        } } },
        .streams_blocked_bidi => |blocked| .{ .frame = .{ .streams_blocked = .{
            .stream_type = .bidirectional,
            .limit = blocked.maximum_streams,
        } } },
        .streams_blocked_uni => |blocked| .{ .frame = .{ .streams_blocked = .{
            .stream_type = .unidirectional,
            .limit = blocked.maximum_streams,
        } } },
        .new_connection_id => |connection_id| .{ .frame = .{ .new_connection_id = .{
            .sequence_number = connection_id.sequence_number,
            .retire_prior_to = connection_id.retire_prior_to,
            .connection_id_length = connection_id.connection_id.len,
        } } },
        .retire_connection_id => |connection_id| .{ .frame = .{ .retire_connection_id = .{
            .sequence_number = connection_id.sequence_number,
        } } },
        .path_challenge => .{ .frame = .{ .path_challenge = {} } },
        .path_response => .{ .frame = .{ .path_response = {} } },
        .connection_close => |close| .{ .frame = .{ .connection_close = .{
            .error_space = .transport,
            .error_code = close.error_code,
            .triggering_frame_type = close.frame_type,
            .reason = close.reason_phrase,
        } } },
        .application_close => |close| .{ .frame = .{ .connection_close = .{
            .error_space = .application,
            .error_code = close.error_code,
            .reason = close.reason_phrase,
        } } },
        .handshake_done => .{ .frame = .{ .handshake_done = {} } },
        .immediate_ack => .{ .frame = .{ .immediate_ack = {} } },
        .datagram => |datagram| .{ .frame = .{ .datagram = .{
            .length = datagram.data.len,
        } } },
        .ack_frequency => |frequency| .{ .frame = .{ .ack_frequency = .{
            .sequence_number = frequency.sequence_number,
            .packet_tolerance = frequency.ack_eliciting_threshold,
            .max_ack_delay = frequency.request_max_ack_delay,
            .reordering_threshold = frequency.reordering_threshold,
        } } },
    };
}

fn decodeAckDelayMilliseconds(
    encoded: u64,
    exponent: u6,
) error{InvalidAckDelayExponent}!f64 {
    // RFC 9000 Section 18.2 caps ACK Delay Exponent at 20. Multiplication in
    // floating point also avoids overflowing u64 for a valid QUIC varint.
    if (exponent > 20) return error.InvalidAckDelayExponent;
    const multiplier = @as(u64, 1) << exponent;
    const microseconds =
        @as(f64, @floatFromInt(encoded)) *
        @as(f64, @floatFromInt(multiplier));
    return microseconds / 1000.0;
}
