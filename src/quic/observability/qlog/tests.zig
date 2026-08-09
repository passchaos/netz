const std = @import("std");
const qlog = @import("mod.zig");

test "qlog emits RFC 7464 records with escaped text and hex group IDs" {
    var storage: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&storage);
    var trace = qlog.Trace.init(&writer, .{ .reference_time_ns = 1_000_000 });

    try trace.writeHeader(.client, &.{ 0x00, 0xab, 0xff });
    try trace.writeEvent(2_500_000, .{ .connection_closed = .{
        .trigger = "peer\"close\n",
        .owner = .remote,
        .error_space = .transport,
        .error_code = 42,
        .reason = "bad\\reason\t",
    } });

    const encoded = writer.buffered();
    try std.testing.expectEqual(@as(u8, 0x1e), encoded[0]);
    try std.testing.expect(std.mem.indexOf(
        u8,
        encoded,
        "\"group_id\":\"00abff\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        encoded,
        "\"protocol_type\":[\"QUIC\"],\"time_format\":\"relative\",\"reference_time\":1",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        encoded,
        "\"trigger\":\"peer\\\"close\\n\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        encoded,
        "\"reason\":\"bad\\\\reason\\t\"",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        encoded,
        "\"time\":1.5",
    ) != null);
    try std.testing.expect(std.mem.count(u8, encoded, &.{0x1e}) == 2);
    try std.testing.expect(encoded[encoded.len - 1] == '\n');
    try validateJsonSequence(encoded, 2);
}

test "qlog streams packets beyond the reference fixed frame buffer" {
    const frame_count = 1024;
    const frames = try std.testing.allocator.alloc(qlog.events.Frame, frame_count);
    defer std.testing.allocator.free(frames);
    for (frames, 0..) |*frame, index| {
        frame.* = .{ .stream = .{
            .stream_id = index * 4,
            .offset = index * 128,
            .length = 1200,
            .fin = index + 1 == frame_count,
        } };
    }

    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var trace = qlog.Trace.init(&output.writer, .{});
    try trace.writeEvent(1, .{ .packet_sent = .{
        .packet_type = .one_rtt,
        .packet_number = 99,
        .length = 1_250_000,
        .frames = frames,
    } });

    const encoded = output.written();
    try std.testing.expect(encoded.len > 64 * 1024);
    try std.testing.expectEqual(frame_count, std.mem.count(
        u8,
        encoded,
        "\"frame_type\":\"stream\"",
    ));
    try validateJsonSequence(encoded, 1);
}

test "qlog preserves ACK range and ECN details through the codec adapter" {
    const source_ranges = [_]@import("../../mod.zig").AckRange{
        .{ .gap = 1, .ack_range_length = 2 },
        .{ .gap = 0, .ack_range_length = 1 },
    };
    const source = @import("../../mod.zig").Frame{ .ack = .{
        .largest_acknowledged = 100,
        .ack_delay = 25,
        .first_ack_range = 3,
        .ranges = &source_ranges,
        .ecn_counts = .{
            .ect0_count = 10,
            .ect1_count = 2,
            .ecn_ce_count = 1,
        },
    } };
    var range_storage: [2]qlog.events.AckRange = undefined;
    const adapted = try qlog.frame_adapter.adapt(
        source,
        &range_storage,
        .{ .ack_delay_exponent = 4 },
    );
    try std.testing.expectEqual(@as(usize, 2), adapted.ack_ranges_used);

    var storage: [2048]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&storage);
    var trace = qlog.Trace.init(&writer, .{});
    try trace.writeEvent(0, .{ .packet_received = .{
        .packet_type = .handshake,
        .packet_number = 7,
        .length = 1280,
        .frames = &.{adapted.frame},
    } });

    const encoded = writer.buffered();
    try std.testing.expect(std.mem.indexOf(
        u8,
        encoded,
        "\"acked_ranges\":[[97,100],[92,94],[89,90]]",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        encoded,
        "\"ect0\":10,\"ect1\":2,\"ce\":1",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        encoded,
        "\"ack_delay\":0.4",
    ) != null);
    try validateJsonSequence(encoded, 1);
}

test "qlog codec adapter reports insufficient ACK range storage" {
    const ranges = [_]@import("../../mod.zig").AckRange{
        .{ .gap = 0, .ack_range_length = 0 },
    };
    const source = @import("../../mod.zig").Frame{ .ack = .{
        .largest_acknowledged = 1,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ranges = &ranges,
    } };
    try std.testing.expectError(
        error.InsufficientAckRangeStorage,
        qlog.frame_adapter.adapt(source, &.{}, .{}),
    );
}

test "qlog codec adapter rejects invalid ACK delay exponents" {
    const source = @import("../../mod.zig").Frame{ .ack = .{
        .largest_acknowledged = 1,
        .ack_delay = 1,
        .first_ack_range = 0,
    } };
    try std.testing.expectError(
        error.InvalidAckDelayExponent,
        qlog.frame_adapter.adapt(
            source,
            &.{},
            .{ .ack_delay_exponent = 21 },
        ),
    );
}

test "qlog codec adapter covers every QUIC frame variant" {
    const ranges = [_]@import("../../mod.zig").AckRange{
        .{ .gap = 0, .ack_range_length = 0 },
    };
    const source_frames = [_]@import("../../mod.zig").Frame{
        .{ .padding = .{ .len = 2 } },
        .{ .ping = {} },
        .{ .ack = .{
            .largest_acknowledged = 1,
            .ack_delay = 0,
            .first_ack_range = 0,
            .ranges = &ranges,
        } },
        .{ .reset_stream = .{
            .stream_id = 4,
            .application_error_code = 1,
            .final_size = 10,
        } },
        .{ .stop_sending = .{ .stream_id = 4, .application_error_code = 1 } },
        .{ .new_token = .{ .token = "token" } },
        .{ .crypto = .{ .offset = 1, .data = "crypto" } },
        .{ .stream = .{ .stream_id = 4, .data = "stream" } },
        .{ .max_data = .{ .maximum_data = 100 } },
        .{ .max_stream_data = .{ .stream_id = 4, .maximum_stream_data = 100 } },
        .{ .max_streams_bidi = .{ .maximum_streams = 10 } },
        .{ .max_streams_uni = .{ .maximum_streams = 10 } },
        .{ .data_blocked = .{ .maximum_data = 100 } },
        .{ .stream_data_blocked = .{ .stream_id = 4, .maximum_stream_data = 100 } },
        .{ .streams_blocked_bidi = .{ .maximum_streams = 10 } },
        .{ .streams_blocked_uni = .{ .maximum_streams = 10 } },
        .{ .new_connection_id = .{
            .sequence_number = 2,
            .retire_prior_to = 1,
            .connection_id = "cid",
            .stateless_reset_token = [_]u8{0} ** 16,
        } },
        .{ .retire_connection_id = .{ .sequence_number = 1 } },
        .{ .path_challenge = .{ .data = [_]u8{1} ** 8 } },
        .{ .path_response = .{ .data = [_]u8{1} ** 8 } },
        .{ .connection_close = .{
            .error_code = 1,
            .frame_type = 8,
            .reason_phrase = "close",
        } },
        .{ .application_close = .{ .error_code = 1, .reason_phrase = "app" } },
        .{ .handshake_done = {} },
        .{ .immediate_ack = {} },
        .{ .datagram = .{ .data = "datagram" } },
        .{ .ack_frequency = .{
            .sequence_number = 1,
            .ack_eliciting_threshold = 2,
            .request_max_ack_delay = 3,
            .reordering_threshold = 4,
        } },
    };

    var range_storage: [1]qlog.events.AckRange = undefined;
    for (source_frames) |source| {
        _ = try qlog.frame_adapter.adapt(source, &range_storage, .{});
    }
}

test "qlog rejects regressed timestamps before writing another record" {
    var storage: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&storage);
    var trace = qlog.Trace.init(&writer, .{});
    try trace.writeEvent(20, .{ .connection_started = .{} });
    const before = writer.buffered().len;
    try std.testing.expectError(
        error.TimestampRegressed,
        trace.writeEvent(19, .{ .packet_dropped = .{
            .trigger = "late",
        } }),
    );
    try std.testing.expectEqual(before, writer.buffered().len);
}

test "qlog rejects invalid UTF-8 and ACK ranges before starting a record" {
    var storage: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&storage);
    var trace = qlog.Trace.init(&writer, .{});
    try std.testing.expectError(
        error.InvalidUtf8,
        trace.writeEvent(1, .{ .connection_closed = .{
            .trigger = "\xff",
            .error_space = .transport,
            .error_code = 1,
        } }),
    );
    try std.testing.expectEqual(@as(usize, 0), writer.buffered().len);

    try std.testing.expectError(
        error.InvalidAckRange,
        trace.writeEvent(1, .{ .packet_received = .{
            .packet_type = .one_rtt,
            .packet_number = 1,
            .length = 100,
            .frames = &.{.{ .ack = .{
                .largest_acknowledged = 1,
                .ack_delay_ms = 0,
                .first_ack_range = 2,
            } }},
        } }),
    );
    try std.testing.expectEqual(@as(usize, 0), writer.buffered().len);
}

test "qlog rejects relative timestamps before the trace reference" {
    var storage: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&storage);
    var trace = qlog.Trace.init(&writer, .{ .reference_time_ns = 10 });
    try std.testing.expectError(
        error.TimestampBeforeReference,
        trace.writeEvent(9, .{ .connection_started = .{} }),
    );
    try std.testing.expectEqual(@as(usize, 0), writer.buffered().len);
}

test "qlog propagates sink failures" {
    var writer: std.Io.Writer = .failing;
    var trace = qlog.Trace.init(&writer, .{});
    try std.testing.expectError(
        error.WriteFailed,
        trace.writeHeader(.server, "cid"),
    );
}

test "qlog marks failed records incomplete instead of advancing time" {
    var short_storage: [32]u8 = undefined;
    var short_writer: std.Io.Writer = .fixed(&short_storage);
    var trace = qlog.Trace.init(&short_writer, .{});
    try std.testing.expectError(
        error.WriteFailed,
        trace.writeEvent(10, .{ .connection_closed = .{
            .trigger = "this event cannot fit",
            .error_space = .transport,
            .error_code = 1,
        } }),
    );
    try std.testing.expect(trace.last_time_ns == null);
    try std.testing.expectEqual(@as(u8, 0x1e), short_writer.buffered()[0]);
    try std.testing.expect(short_writer.buffered()[short_writer.buffered().len - 1] != '\n');

    var retry_storage: [1024]u8 = undefined;
    var retry_writer: std.Io.Writer = .fixed(&retry_storage);
    trace.writer = &retry_writer;
    try trace.writeEvent(9, .{ .connection_started = .{} });
    try std.testing.expectEqual(@as(?u64, 9), trace.last_time_ns);
    try validateJsonSequence(retry_writer.buffered(), 1);
}

test "qlog event encoding performs no heap allocation" {
    var storage: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&storage);
    var trace = qlog.Trace.init(&writer, .{});
    // The public API does not accept an allocator; this representative event
    // also guards against accidentally replacing streaming writes with an
    // internal allocating buffer in future refactors.
    try trace.writeEvent(10, .{ .metrics_updated = .{
        .min_rtt_ns = 1_000_000,
        .smoothed_rtt_ns = 2_000_000,
        .latest_rtt_ns = 3_000_000,
        .rtt_variance_ns = 500_000,
        .congestion_window = 64 * 1024,
        .bytes_in_flight = 12_000,
        .pacing_rate_bps = 10_000_000,
    } });
    try validateJsonSequence(writer.buffered(), 1);
}

test "qlog encoder covers every event and frame variant" {
    var storage: [32 * 1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&storage);
    var trace = qlog.Trace.init(&writer, .{});
    const all_frames = [_]qlog.events.Frame{
        .{ .padding = .{ .length = 3 } },
        .{ .ping = {} },
        .{ .ack = .{
            .largest_acknowledged = 5,
            .ack_delay_ms = 1,
            .first_ack_range = 0,
        } },
        .{ .reset_stream = .{
            .stream_id = 4,
            .error_code = 1,
            .final_size = 100,
        } },
        .{ .stop_sending = .{ .stream_id = 4, .error_code = 1 } },
        .{ .new_token = .{ .length = 16 } },
        .{ .crypto = .{ .offset = 10, .length = 20 } },
        .{ .stream = .{
            .stream_id = 4,
            .offset = 10,
            .length = 20,
            .fin = true,
        } },
        .{ .max_data = .{ .maximum = 1000 } },
        .{ .max_stream_data = .{ .stream_id = 4, .maximum = 1000 } },
        .{ .max_streams = .{ .stream_type = .bidirectional, .maximum = 10 } },
        .{ .data_blocked = .{ .limit = 1000 } },
        .{ .stream_data_blocked = .{ .stream_id = 4, .limit = 1000 } },
        .{ .streams_blocked = .{ .stream_type = .unidirectional, .limit = 10 } },
        .{ .new_connection_id = .{
            .sequence_number = 2,
            .retire_prior_to = 1,
            .connection_id_length = 8,
        } },
        .{ .retire_connection_id = .{ .sequence_number = 1 } },
        .{ .path_challenge = {} },
        .{ .path_response = {} },
        .{ .connection_close = .{
            .error_space = .application,
            .error_code = 42,
            .reason = "done",
        } },
        .{ .handshake_done = {} },
        .{ .immediate_ack = {} },
        .{ .datagram = .{ .length = 1200 } },
        .{ .ack_frequency = .{
            .sequence_number = 1,
            .packet_tolerance = 10,
            .max_ack_delay = 1000,
            .reordering_threshold = 2,
        } },
    };
    try trace.writeEvent(1, .{ .packet_sent = .{
        .packet_type = .one_rtt,
        .packet_number = 1,
        .length = 1400,
        .frames = &all_frames,
    } });
    try trace.writeEvent(2, .{ .connection_started = .{
        .src_ip = "127.0.0.1",
        .src_port = 443,
        .dst_ip = "::1",
        .dst_port = 8443,
    } });
    try trace.writeEvent(3, .{ .parameters_set = .{
        .owner = .local,
        .max_idle_timeout_ms = 30_000,
        .max_udp_payload_size = 65_527,
        .initial_max_data = 1_000_000,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 3,
        .disable_active_migration = true,
    } });
    try trace.writeEvent(4, .{ .packet_dropped = .{
        .packet_type = .initial,
        .trigger = "unsupported",
        .raw_length = 1200,
    } });
    try trace.writeEvent(5, .{ .congestion_state_updated = .{
        .old = "slow_start",
        .new = "recovery",
        .trigger = "ecn",
    } });
    try trace.writeEvent(6, .{ .packet_lost = .{
        .packet_type = .handshake,
        .packet_number = 2,
        .trigger = "time_threshold",
    } });
    try trace.writeEvent(7, .{ .key_updated = .{
        .trigger = "local_update",
        .key_type = "server_1rtt_secret",
        .generation = 1,
    } });
    try trace.writeEvent(8, .{ .key_discarded = .{
        .key_type = "server_handshake_secret",
    } });
    try trace.writeEvent(9, .{ .connection_closed = .{
        .trigger = "application",
        .error_space = .application,
        .error_code = 0,
    } });
    try validateJsonSequence(writer.buffered(), 9);
}

test "qlog observer bounds packet scratch with a sticky error" {
    var output_storage: [1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&output_storage);
    var trace = qlog.Trace.init(&writer, .{});
    var observer = qlog.Observer.init(&trace);
    const too_many = [_]@import("../../mod.zig").Frame{
        .{ .ping = {} },
    } ** (qlog.observer.max_frames_per_packet + 1);

    observer.packetSent(0, 0, 1200, &too_many, 3);
    try std.testing.expectEqual(@as(usize, 0), writer.buffered().len);
    try std.testing.expectEqualStrings(
        "TooManyFrames",
        @errorName(observer.takeError() orelse
            return error.TestUnexpectedResult),
    );
    try std.testing.expect(observer.takeError() == null);
}

fn validateJsonSequence(bytes: []const u8, expected_records: usize) !void {
    var records: usize = 0;
    var cursor: usize = 0;
    while (cursor < bytes.len) {
        if (bytes[cursor] != 0x1e) return error.TestUnexpectedResult;
        cursor += 1;
        const line_end = std.mem.indexOfScalarPos(u8, bytes, cursor, '\n') orelse
            return error.TestUnexpectedResult;
        const document = bytes[cursor..line_end];
        var parsed = try std.json.parseFromSlice(
            std.json.Value,
            std.testing.allocator,
            document,
            .{},
        );
        parsed.deinit();
        records += 1;
        cursor = line_end + 1;
    }
    try std.testing.expectEqual(expected_records, records);
}
