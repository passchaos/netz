const std = @import("std");
const http3 = @import("../../mod.zig");
const qpack_state = @import("state.zig");

const QpackDecodeState = qpack_state.QpackDecodeState;
const QpackEncodeState = qpack_state.QpackEncodeState;
const client_qpack_encoder_stream_id: u62 = 6;
const client_qpack_decoder_stream_id: u62 = 10;

test "HTTP/3 QPACK decoder state reassembles split and reordered encoder instructions" {
    const allocator = std.testing.allocator;
    var state = QpackDecodeState.init(allocator, 256, 4096);
    defer state.deinit();
    var control = http3.ControlState{};

    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&bytes, allocator);
    try http3.Qpack.writeEncoderInstruction(&bytes, allocator, .{ .set_capacity = 256 });
    try http3.Qpack.writeEncoderInstruction(&bytes, allocator, .{ .insert_literal = .{
        .name = "x-runtime",
        .value = "split-across-stream-frames",
    } });
    try http3.Qpack.writeEncoderInstruction(&bytes, allocator, .{ .insert_name_reference = .{
        .static = true,
        .name_index = 1,
        .value = "/dynamic",
    } });
    const split = bytes.items.len / 2;

    // Deliver the suffix first. Nothing is contiguous from offset zero, so no
    // stream registration, table mutation, or decoder feedback is possible.
    try state.applyEncoderStreamFrame(&control, .{
        .stream_id = client_qpack_encoder_stream_id,
        .offset = split,
        .data = bytes.items[split..],
    });
    try std.testing.expect(control.peer_qpack_encoder_stream_id == null);
    try std.testing.expectEqual(@as(usize, 0), state.table.entryCount());
    try std.testing.expectEqual(@as(usize, 0), state.decoder_instructions.items.len);

    try state.applyEncoderStreamFrame(&control, .{
        .stream_id = client_qpack_encoder_stream_id,
        .offset = 0,
        .data = bytes.items[0..split],
    });
    try std.testing.expectEqual(
        @as(?u64, client_qpack_encoder_stream_id),
        control.peer_qpack_encoder_stream_id,
    );
    try std.testing.expectEqual(@as(usize, 256), state.table.capacity);
    try std.testing.expectEqual(@as(u64, 2), state.table.insert_count);
    try std.testing.expectEqualStrings("x-runtime", state.table.absolute(0).?.name);
    try std.testing.expectEqualStrings(":path", state.table.absolute(1).?.name);
    try std.testing.expectEqualStrings("/dynamic", state.table.absolute(1).?.value);

    const feedback = try state.takeDecoderInstructions();
    defer allocator.free(feedback);
    const increment = try http3.Qpack.decodeDecoderInstruction(feedback);
    try std.testing.expectEqual(@as(usize, feedback.len), increment.consumed);
    try std.testing.expectEqual(
        @as(u64, 2),
        increment.instruction.insert_count_increment,
    );
    try std.testing.expectEqual(@as(u64, 2), state.acknowledged_insert_count);

    // An identical retransmission is accepted by RecvState and cannot apply
    // instructions or acknowledgments a second time.
    try state.applyEncoderStreamFrame(&control, .{
        .stream_id = client_qpack_encoder_stream_id,
        .offset = 0,
        .data = bytes.items,
    });
    try std.testing.expectEqual(@as(u64, 2), state.table.insert_count);
    try std.testing.expectEqual(@as(usize, 0), state.decoder_instructions.items.len);
}

test "HTTP/3 QPACK decoder state retains a partial instruction and acknowledges field section" {
    const allocator = std.testing.allocator;
    var state = QpackDecodeState.init(allocator, 256, 4096);
    defer state.deinit();
    var control = http3.ControlState{};

    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&bytes, allocator);
    try http3.Qpack.writeEncoderInstruction(&bytes, allocator, .{ .set_capacity = 256 });
    try http3.Qpack.writeEncoderInstruction(&bytes, allocator, .{ .insert_literal = .{
        .name = "x-partial",
        .value = "value-that-needs-the-second-frame",
    } });
    const split = bytes.items.len - 3;
    try state.applyEncoderStreamFrame(&control, .{
        .stream_id = client_qpack_encoder_stream_id,
        .offset = 0,
        .data = bytes.items[0..split],
    });
    try std.testing.expectEqual(@as(u64, 0), state.table.insert_count);
    try std.testing.expect(state.encoder_stream.?.available().len != 0);

    try state.applyEncoderStreamFrame(&control, .{
        .stream_id = client_qpack_encoder_stream_id,
        .offset = split,
        .data = bytes.items[split..],
    });
    try std.testing.expectEqual(@as(u64, 1), state.table.insert_count);
    try std.testing.expectEqual(@as(usize, 0), state.encoder_stream.?.available().len);

    var field_section: std.ArrayList(u8) = .empty;
    defer field_section.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&field_section, allocator, &.{
        .{ .name = "x-partial", .value = "value-that-needs-the-second-frame" },
    }, state.table);
    var decoded = try state.decodeFieldSection(allocator, 12, field_section.items);
    defer http3.Qpack.freeDynamicBlock(allocator, &decoded);
    try std.testing.expectEqual(@as(usize, 1), decoded.fields.len);
    try std.testing.expectEqualStrings("x-partial", decoded.fields[0].name);

    const feedback = try state.takeDecoderInstructions();
    defer allocator.free(feedback);
    const increment = try http3.Qpack.decodeDecoderInstruction(feedback);
    const acknowledgment = try http3.Qpack.decodeDecoderInstruction(
        feedback[increment.consumed..],
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        increment.instruction.insert_count_increment,
    );
    try std.testing.expectEqual(
        @as(u64, 12),
        acknowledgment.instruction.section_acknowledgment,
    );
}

test "HTTP/3 QPACK decoder state rejects capacity overflow and critical stream FIN" {
    const allocator = std.testing.allocator;
    var state = QpackDecodeState.init(allocator, 64, 4096);
    defer state.deinit();
    var control = http3.ControlState{};

    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&bytes, allocator);
    try http3.Qpack.writeEncoderInstruction(&bytes, allocator, .{ .set_capacity = 65 });
    try std.testing.expectError(error.QpackEncoderStreamError, state.applyEncoderStreamFrame(
        &control,
        .{
            .stream_id = client_qpack_encoder_stream_id,
            .offset = 0,
            .data = bytes.items,
        },
    ));

    var fin_state = QpackDecodeState.init(allocator, 64, 4096);
    defer fin_state.deinit();
    try std.testing.expectError(error.ClosedCriticalStream, fin_state.applyEncoderStreamFrame(
        &control,
        .{
            .stream_id = client_qpack_encoder_stream_id,
            .offset = 0,
            .data = &.{@intFromEnum(http3.StreamType.qpack_encoder)},
            .fin = true,
        },
    ));
}

test "HTTP/3 QPACK state rejects duplicate peer critical streams" {
    const allocator = std.testing.allocator;

    var decoder = QpackDecodeState.init(allocator, 0, 4096);
    defer decoder.deinit();
    var decoder_control = http3.ControlState{};
    try decoder.applyEncoderStreamFrame(&decoder_control, .{
        .stream_id = client_qpack_encoder_stream_id,
        .data = &.{@intFromEnum(http3.StreamType.qpack_encoder)},
    });
    try std.testing.expectError(
        error.StreamCreationError,
        decoder.applyEncoderStreamFrame(&decoder_control, .{
            .stream_id = client_qpack_encoder_stream_id + 4,
            .data = &.{@intFromEnum(http3.StreamType.qpack_encoder)},
        }),
    );

    var encoder = QpackEncodeState.initAwaitingPeerSettings(allocator, 4096);
    defer encoder.deinit();
    var encoder_control = http3.ControlState{};
    try encoder.applyDecoderStreamFrame(&encoder_control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .data = &.{@intFromEnum(http3.StreamType.qpack_decoder)},
    });
    try std.testing.expectError(
        error.StreamCreationError,
        encoder.applyDecoderStreamFrame(&encoder_control, .{
            .stream_id = client_qpack_decoder_stream_id + 4,
            .data = &.{@intFromEnum(http3.StreamType.qpack_decoder)},
        }),
    );
}

test "HTTP/3 QPACK encoder state waits for insert acknowledgment before dynamic reference" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.init(allocator, 256, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(256);
    try std.testing.expectEqual(
        @as(?u64, 0),
        try encoder.insertField("x-encode", "reused"),
    );

    const fields = [_]http3.Qpack.HeaderField{
        .{ .name = "x-encode", .value = "reused" },
    };
    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try encoder.encodeFieldSection(&first, 0, &fields);
    var first_decoded = try http3.Qpack.decodeDynamicBlock(
        allocator,
        first.items,
        encoder.table,
    );
    defer http3.Qpack.freeDynamicBlock(allocator, &first_decoded);
    try std.testing.expectEqual(@as(u64, 0), first_decoded.required_insert_count);
    try std.testing.expectEqual(@as(usize, 0), encoder.pending_sections.items.len);

    var decoder_bytes: std.ArrayList(u8) = .empty;
    defer decoder_bytes.deinit(allocator);
    try http3.writeQpackDecoderStreamPrefix(&decoder_bytes, allocator);
    try http3.Qpack.writeDecoderInstruction(
        &decoder_bytes,
        allocator,
        .{ .insert_count_increment = 1 },
    );
    var control = http3.ControlState{};
    const split = decoder_bytes.items.len - 1;
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = split,
        .data = decoder_bytes.items[split..],
    });
    try std.testing.expectEqual(@as(u64, 0), encoder.known_received_count);
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = 0,
        .data = decoder_bytes.items[0..split],
    });
    try std.testing.expectEqual(@as(u64, 1), encoder.known_received_count);
    try std.testing.expectEqual(
        @as(?u64, client_qpack_decoder_stream_id),
        control.peer_qpack_decoder_stream_id,
    );

    var second: std.ArrayList(u8) = .empty;
    defer second.deinit(allocator);
    try encoder.encodeFieldSection(&second, 4, &fields);
    var second_decoded = try http3.Qpack.decodeDynamicBlock(
        allocator,
        second.items,
        encoder.table,
    );
    defer http3.Qpack.freeDynamicBlock(allocator, &second_decoded);
    try std.testing.expectEqual(@as(u64, 1), second_decoded.required_insert_count);
    try std.testing.expectEqual(@as(usize, 1), encoder.pending_sections.items.len);
    try std.testing.expectEqual(@as(?usize, 1), encoder.reference_counts.get(0));

    var acknowledgment: std.ArrayList(u8) = .empty;
    defer acknowledgment.deinit(allocator);
    try http3.Qpack.writeDecoderInstruction(
        &acknowledgment,
        allocator,
        .{ .section_acknowledgment = 4 },
    );
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = decoder_bytes.items.len,
        .data = acknowledgment.items,
    });
    try std.testing.expectEqual(@as(usize, 0), encoder.pending_sections.items.len);
    try std.testing.expect(!encoder.reference_counts.contains(0));
    try std.testing.expect(!encoder.hasPendingSections(4));
    encoder.abandonStream(4);

    // Retransmitting the same decoder bytes cannot acknowledge twice.
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = 0,
        .data = decoder_bytes.items,
    });
    try std.testing.expectEqual(@as(u64, 1), encoder.known_received_count);
}

test "HTTP/3 QPACK encoder binds once to peer SETTINGS capacity" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.initAwaitingPeerSettings(allocator, 4096);
    defer encoder.deinit();

    try std.testing.expect(encoder.peer_max_capacity == null);
    try std.testing.expectEqual(@as(usize, 0), encoder.table.capacity);
    try encoder.configurePeerLimits(256, 2);
    try std.testing.expectEqual(@as(?usize, 256), encoder.peer_max_capacity);
    try std.testing.expectEqual(@as(?u64, 2), encoder.peer_max_blocked_streams);
    try std.testing.expectEqual(@as(usize, 256), encoder.table.max_capacity);
    try std.testing.expectEqual(@as(usize, 256), encoder.table.capacity);
    const instruction_len = encoder.pendingEncoderInstructions().len;
    try std.testing.expect(instruction_len != 0);

    // Reprocessing retransmitted control bytes is idempotent, while a changed
    // value would violate HTTP/3's one-SETTINGS-frame connection contract.
    try encoder.configurePeerLimits(256, 2);
    try std.testing.expectEqual(
        instruction_len,
        encoder.pendingEncoderInstructions().len,
    );
    try std.testing.expectError(
        error.QpackEncoderStreamError,
        encoder.configurePeerLimits(128, 2),
    );
    try std.testing.expectError(
        error.QpackEncoderStreamError,
        encoder.configurePeerLimits(256, 1),
    );
    var excessive = QpackEncodeState.initAwaitingPeerSettings(
        allocator,
        4096,
    );
    defer excessive.deinit();
    try std.testing.expectError(
        error.QpackEncoderStreamError,
        excessive.configurePeerLimits(
            256,
            http3.Settings.max_supported_qpack_blocked_streams + 1,
        ),
    );
}

test "HTTP/3 QPACK encoder spends the peer blocked-stream budget" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.initAwaitingPeerSettings(allocator, 4096);
    defer encoder.deinit();
    try encoder.configurePeerLimits(512, 1);
    _ = try encoder.insertField("x-speculative", "repeated-value");

    const fields = [_]http3.Qpack.HeaderField{.{
        .name = "x-speculative",
        .value = "repeated-value",
    }};
    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try encoder.encodeFieldSection(&first, 0, &fields);
    const first_prefix = try http3.Qpack.decodeFieldSectionPrefix(
        first.items,
        encoder.table,
    );
    try std.testing.expectEqual(@as(u64, 1), first_prefix.required_insert_count);
    try std.testing.expectEqual(@as(usize, 1), encoder.blocked_section_counts.count());
    try std.testing.expectEqual(
        @as(?usize, 1),
        encoder.blocked_section_counts.get(0),
    );

    // More sections on the same ordered request stream consume no additional
    // SETTINGS_QPACK_BLOCKED_STREAMS credit. A different stream must remain
    // literal until decoder feedback releases the sole slot.
    var same_stream: std.ArrayList(u8) = .empty;
    defer same_stream.deinit(allocator);
    try encoder.encodeFieldSection(&same_stream, 0, &fields);
    const same_prefix = try http3.Qpack.decodeFieldSectionPrefix(
        same_stream.items,
        encoder.table,
    );
    try std.testing.expectEqual(@as(u64, 1), same_prefix.required_insert_count);
    try std.testing.expectEqual(
        @as(?usize, 2),
        encoder.blocked_section_counts.get(0),
    );

    var gated: std.ArrayList(u8) = .empty;
    defer gated.deinit(allocator);
    try encoder.encodeFieldSection(&gated, 4, &fields);
    const gated_prefix = try http3.Qpack.decodeFieldSectionPrefix(
        gated.items,
        encoder.table,
    );
    try std.testing.expectEqual(@as(u64, 0), gated_prefix.required_insert_count);
    try std.testing.expect(!encoder.hasPendingSections(4));

    var feedback: std.ArrayList(u8) = .empty;
    defer feedback.deinit(allocator);
    try http3.writeQpackDecoderStreamPrefix(&feedback, allocator);
    try http3.Qpack.writeDecoderInstruction(
        &feedback,
        allocator,
        .{ .insert_count_increment = 1 },
    );
    var control = http3.ControlState{};
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = 0,
        .data = feedback.items,
    });
    try std.testing.expectEqual(@as(u64, 1), encoder.known_received_count);
    try std.testing.expectEqual(@as(usize, 0), encoder.blocked_section_counts.count());

    var released: std.ArrayList(u8) = .empty;
    defer released.deinit(allocator);
    try encoder.encodeFieldSection(&released, 4, &fields);
    const released_prefix = try http3.Qpack.decodeFieldSectionPrefix(
        released.items,
        encoder.table,
    );
    try std.testing.expectEqual(@as(u64, 1), released_prefix.required_insert_count);
    try std.testing.expect(encoder.hasPendingSections(4));
}

test "HTTP/3 QPACK Section Ack releases speculative blocked streams" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.initAwaitingPeerSettings(allocator, 4096);
    defer encoder.deinit();
    try encoder.configurePeerLimits(512, 2);
    _ = try encoder.insertField("x-speculative", "ack-value");

    const fields = [_]http3.Qpack.HeaderField{.{
        .name = "x-speculative",
        .value = "ack-value",
    }};
    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try encoder.encodeFieldSection(&first, 0, &fields);
    var second: std.ArrayList(u8) = .empty;
    defer second.deinit(allocator);
    try encoder.encodeFieldSection(&second, 4, &fields);
    try std.testing.expectEqual(@as(usize, 2), encoder.blocked_section_counts.count());

    var feedback: std.ArrayList(u8) = .empty;
    defer feedback.deinit(allocator);
    try http3.writeQpackDecoderStreamPrefix(&feedback, allocator);
    try http3.Qpack.writeDecoderInstruction(
        &feedback,
        allocator,
        .{ .section_acknowledgment = 0 },
    );
    var control = http3.ControlState{};
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = 0,
        .data = feedback.items,
    });

    // Section Ack advances Known Received Count to the section's RIC. That
    // makes every other section depending only on the same insert unblocked.
    try std.testing.expectEqual(@as(u64, 1), encoder.known_received_count);
    try std.testing.expectEqual(@as(usize, 0), encoder.blocked_section_counts.count());
    try std.testing.expect(!encoder.hasPendingSections(0));
    try std.testing.expect(encoder.hasPendingSections(4));
}

test "HTTP/3 QPACK Stream Cancellation releases blocked-stream credit" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.initAwaitingPeerSettings(allocator, 4096);
    defer encoder.deinit();
    try encoder.configurePeerLimits(512, 1);
    _ = try encoder.insertField("x-speculative", "cancel-value");
    const fields = [_]http3.Qpack.HeaderField{.{
        .name = "x-speculative",
        .value = "cancel-value",
    }};

    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try encoder.encodeFieldSection(&first, 0, &fields);
    var gated: std.ArrayList(u8) = .empty;
    defer gated.deinit(allocator);
    try encoder.encodeFieldSection(&gated, 4, &fields);
    try std.testing.expectEqual(
        @as(u64, 0),
        (try http3.Qpack.decodeFieldSectionPrefix(
            gated.items,
            encoder.table,
        )).required_insert_count,
    );

    var feedback: std.ArrayList(u8) = .empty;
    defer feedback.deinit(allocator);
    try http3.writeQpackDecoderStreamPrefix(&feedback, allocator);
    try http3.Qpack.writeDecoderInstruction(
        &feedback,
        allocator,
        .{ .stream_cancellation = 0 },
    );
    var control = http3.ControlState{};
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = 0,
        .data = feedback.items,
    });
    try std.testing.expectEqual(@as(usize, 0), encoder.blocked_section_counts.count());

    var released: std.ArrayList(u8) = .empty;
    defer released.deinit(allocator);
    try encoder.encodeFieldSection(&released, 4, &fields);
    try std.testing.expectEqual(
        @as(u64, 1),
        (try http3.Qpack.decodeFieldSectionPrefix(
            released.items,
            encoder.table,
        )).required_insert_count,
    );
}

test "HTTP/3 QPACK encoder state protects referenced entries from eviction" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.init(allocator, 34, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(34);
    _ = try encoder.insertField("a", "1");

    var control = http3.ControlState{};
    const decoder_stream = [_]u8{
        @intFromEnum(http3.StreamType.qpack_decoder),
        0x01, // Insert Count Increment = 1.
    };
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = 0,
        .data = &decoder_stream,
    });

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try encoder.encodeFieldSection(&block, 8, &.{
        .{ .name = "a", .value = "1" },
    });
    try std.testing.expectEqual(@as(usize, 1), encoder.pending_sections.items.len);

    // Inserting b would evict referenced a. The encoder must skip the insert,
    // not violate QPACK's prohibited-eviction rule.
    try std.testing.expectEqual(
        @as(?u64, null),
        try encoder.insertField("b", "2"),
    );
    try std.testing.expectEqualStrings("a", encoder.table.relative(0).?.name);

    var cancel_bytes: std.ArrayList(u8) = .empty;
    defer cancel_bytes.deinit(allocator);
    try http3.Qpack.writeDecoderInstruction(
        &cancel_bytes,
        allocator,
        .{ .stream_cancellation = 8 },
    );
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = decoder_stream.len,
        .data = cancel_bytes.items,
    });
    try std.testing.expectEqual(@as(usize, 0), encoder.pending_sections.items.len);

    // Once acknowledged and unreferenced, a becomes evictable.
    try std.testing.expectEqual(
        @as(?u64, 1),
        try encoder.insertField("b", "2"),
    );
    try std.testing.expect(encoder.table.absolute(0) == null);
    try std.testing.expectEqualStrings("b", encoder.table.relative(0).?.name);
}

test "HTTP/3 QPACK stream cancellation compacts pending sections stably" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.init(allocator, 512, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(512);
    _ = try encoder.insertField("x-one", "one");
    _ = try encoder.insertField("x-two", "two");
    _ = try encoder.insertField("x-three", "three");
    encoder.known_received_count = encoder.table.insert_count;

    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try encoder.encodeFieldSection(&first, 4, &.{
        .{ .name = "x-one", .value = "one" },
    });
    var canceled: std.ArrayList(u8) = .empty;
    defer canceled.deinit(allocator);
    try encoder.encodeFieldSection(&canceled, 8, &.{
        .{ .name = "x-one", .value = "one" },
    });
    var second: std.ArrayList(u8) = .empty;
    defer second.deinit(allocator);
    try encoder.encodeFieldSection(&second, 4, &.{
        .{ .name = "x-two", .value = "two" },
    });
    var third: std.ArrayList(u8) = .empty;
    defer third.deinit(allocator);
    try encoder.encodeFieldSection(&third, 4, &.{
        .{ .name = "x-three", .value = "three" },
    });
    try std.testing.expectEqual(@as(usize, 4), encoder.pending_sections.items.len);
    try std.testing.expectEqual(@as(usize, 2), encoder.pending_section_index.count());
    try std.testing.expectEqual(@as(?usize, 0), encoder.pending_section_index.get(4));
    try std.testing.expectEqual(@as(?usize, 1), encoder.pending_section_index.get(8));

    var feedback: std.ArrayList(u8) = .empty;
    defer feedback.deinit(allocator);
    try http3.writeQpackDecoderStreamPrefix(&feedback, allocator);
    try http3.Qpack.writeDecoderInstruction(
        &feedback,
        allocator,
        .{ .stream_cancellation = 8 },
    );
    var control = http3.ControlState{};
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = 0,
        .data = feedback.items,
    });

    try std.testing.expectEqual(@as(usize, 3), encoder.pending_sections.items.len);
    try std.testing.expectEqual(@as(usize, 1), encoder.pending_section_index.count());
    try std.testing.expectEqual(@as(?usize, 0), encoder.pending_section_index.get(4));
    try std.testing.expectEqual(@as(u64, 4), encoder.pending_sections.items[0].stream_id);
    try std.testing.expectEqual(@as(u64, 1), encoder.pending_sections.items[0].required_insert_count);
    try std.testing.expectEqual(@as(u64, 4), encoder.pending_sections.items[1].stream_id);
    try std.testing.expectEqual(@as(u64, 2), encoder.pending_sections.items[1].required_insert_count);
    try std.testing.expectEqual(@as(u64, 4), encoder.pending_sections.items[2].stream_id);
    try std.testing.expectEqual(@as(u64, 3), encoder.pending_sections.items[2].required_insert_count);
    try std.testing.expectEqual(@as(?usize, 1), encoder.reference_counts.get(0));
    try std.testing.expectEqual(@as(?usize, 1), encoder.reference_counts.get(1));
    try std.testing.expectEqual(@as(?usize, 1), encoder.reference_counts.get(2));

    try std.testing.expectEqual(@as(usize, 0), encoder.releaseSectionsForStream(8));
    try std.testing.expectEqual(@as(usize, 3), encoder.pending_sections.items.len);
    try std.testing.expectEqual(@as(usize, 1), encoder.pending_section_index.count());

    var ack_first: std.ArrayList(u8) = .empty;
    defer ack_first.deinit(allocator);
    try http3.Qpack.writeDecoderInstruction(
        &ack_first,
        allocator,
        .{ .section_acknowledgment = 4 },
    );
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = feedback.items.len,
        .data = ack_first.items,
    });
    try std.testing.expectEqual(@as(usize, 2), encoder.pending_sections.items.len);
    try std.testing.expectEqual(@as(?usize, 0), encoder.pending_section_index.get(4));
    try std.testing.expectEqual(@as(u64, 2), encoder.pending_sections.items[0].required_insert_count);
    try std.testing.expectEqual(@as(u64, 3), encoder.pending_sections.items[1].required_insert_count);
    try std.testing.expect(!encoder.reference_counts.contains(0));
    try std.testing.expectEqual(@as(?usize, 1), encoder.reference_counts.get(1));
    try std.testing.expectEqual(@as(?usize, 1), encoder.reference_counts.get(2));
}

test "HTTP/3 QPACK pending section index repairs shifted streams" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.init(allocator, 512, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(512);
    _ = try encoder.insertField("x-one", "one");
    _ = try encoder.insertField("x-two", "two");
    encoder.known_received_count = encoder.table.insert_count;

    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try encoder.encodeFieldSection(&first, 4, &.{
        .{ .name = "x-one", .value = "one" },
    });
    var second: std.ArrayList(u8) = .empty;
    defer second.deinit(allocator);
    try encoder.encodeFieldSection(&second, 8, &.{
        .{ .name = "x-two", .value = "two" },
    });
    var third: std.ArrayList(u8) = .empty;
    defer third.deinit(allocator);
    try encoder.encodeFieldSection(&third, 4, &.{
        .{ .name = "x-two", .value = "two" },
    });
    try std.testing.expectEqual(@as(?usize, 0), encoder.pending_section_index.get(4));
    try std.testing.expectEqual(@as(?usize, 1), encoder.pending_section_index.get(8));

    var control = http3.ControlState{};
    var feedback: std.ArrayList(u8) = .empty;
    defer feedback.deinit(allocator);
    try http3.writeQpackDecoderStreamPrefix(&feedback, allocator);
    try http3.Qpack.writeDecoderInstruction(
        &feedback,
        allocator,
        .{ .section_acknowledgment = 4 },
    );
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = 0,
        .data = feedback.items,
    });
    try std.testing.expectEqual(@as(usize, 2), encoder.pending_sections.items.len);
    try std.testing.expectEqual(@as(?usize, 0), encoder.pending_section_index.get(8));
    try std.testing.expectEqual(@as(?usize, 1), encoder.pending_section_index.get(4));

    var cancel: std.ArrayList(u8) = .empty;
    defer cancel.deinit(allocator);
    try http3.Qpack.writeDecoderInstruction(
        &cancel,
        allocator,
        .{ .stream_cancellation = 8 },
    );
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = feedback.items.len,
        .data = cancel.items,
    });
    try std.testing.expectEqual(@as(usize, 1), encoder.pending_sections.items.len);
    try std.testing.expect(!encoder.pending_section_index.contains(8));
    try std.testing.expectEqual(@as(?usize, 0), encoder.pending_section_index.get(4));
}

test "HTTP/3 QPACK encoder state rejects invalid decoder feedback" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.init(allocator, 128, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(128);
    _ = try encoder.insertField("a", "1");
    var control = http3.ControlState{};

    const excessive_increment = [_]u8{
        @intFromEnum(http3.StreamType.qpack_decoder),
        0x02,
    };
    try std.testing.expectError(
        error.QpackDecoderStreamError,
        encoder.applyDecoderStreamFrame(&control, .{
            .stream_id = client_qpack_decoder_stream_id,
            .offset = 0,
            .data = &excessive_increment,
        }),
    );

    var ack_without_section = QpackEncodeState.init(allocator, 128, 4096);
    defer ack_without_section.deinit();
    var acknowledgment: std.ArrayList(u8) = .empty;
    defer acknowledgment.deinit(allocator);
    try http3.writeQpackDecoderStreamPrefix(&acknowledgment, allocator);
    try http3.Qpack.writeDecoderInstruction(
        &acknowledgment,
        allocator,
        .{ .section_acknowledgment = 0 },
    );
    var second_control = http3.ControlState{};
    try std.testing.expectError(
        error.QpackDecoderStreamError,
        ack_without_section.applyDecoderStreamFrame(
            &second_control,
            .{
                .stream_id = client_qpack_decoder_stream_id,
                .offset = 0,
                .data = acknowledgment.items,
            },
        ),
    );
}

fn checkQpackEncoderStateAllocationFailure(allocator: std.mem.Allocator) !void {
    var encoder = QpackEncodeState.initAwaitingPeerSettings(allocator, 4096);
    defer encoder.deinit();
    try encoder.configurePeerCapacity(256);
    _ = try encoder.insertField("x-one", "value-one");
    _ = try encoder.insertField("x-two", "value-two");

    // Simulate a decoder that has processed both inserts, then exercise
    // multi-container field-section reference tracking.
    encoder.known_received_count = encoder.table.insert_count;
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try encoder.encodeFieldSection(&block, 12, &.{
        .{ .name = "x-one", .value = "value-one" },
        .{ .name = "x-two", .value = "value-two" },
    });
}

test "HTTP/3 QPACK encoder state is transactional under allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkQpackEncoderStateAllocationFailure,
        .{},
    );
}

test "HTTP/3 QPACK large reference scratch OOM rolls back encoder state" {
    const allocator = std.testing.allocator;
    const field_count = 65;
    var encoder = QpackEncodeState.initAwaitingPeerSettings(allocator, 4096);
    defer encoder.deinit();
    try encoder.configurePeerCapacity(8 * 1024);

    var names: [field_count][24]u8 = undefined;
    var values: [field_count][24]u8 = undefined;
    var fields: [field_count]http3.Qpack.HeaderField = undefined;
    for (&fields, 0..) |*field, index| {
        const name = try std.fmt.bufPrint(
            &names[index],
            "x-state-ref-{d:0>2}",
            .{index},
        );
        const value = try std.fmt.bufPrint(
            &values[index],
            "value-{d:0>2}",
            .{index},
        );
        _ = try encoder.insertField(name, value);
        field.* = .{ .name = name, .value = value };
    }
    encoder.known_received_count = encoder.table.insert_count;

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try block.appendSlice(allocator, &.{ 0xaa, 0xbb });
    var failing = std.testing.FailingAllocator.init(allocator, .{
        // Let the dynamic-match array allocate, then fail the large-only
        // reference membership set before the prefix can be written.
        .fail_index = 1,
    });
    encoder.allocator = failing.allocator();
    const result = encoder.encodeFieldSection(&block, 12, &fields);
    encoder.allocator = allocator;

    try std.testing.expectError(error.OutOfMemory, result);
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, block.items);
    try std.testing.expectEqual(@as(usize, 0), encoder.pending_sections.items.len);
    try std.testing.expectEqual(@as(usize, 0), encoder.pending_section_index.count());
    try std.testing.expectEqual(@as(usize, 0), encoder.reference_counts.count());
    try std.testing.expectEqual(@as(usize, 0), encoder.blocked_section_counts.count());
}

test "HTTP/3 QPACK large reference reserve OOM rolls back encoder state" {
    const allocator = std.testing.allocator;
    const field_count = 65;
    var encoder = QpackEncodeState.initAwaitingPeerSettings(allocator, 4096);
    defer encoder.deinit();
    try encoder.configurePeerCapacity(8 * 1024);

    var names: [field_count][24]u8 = undefined;
    var values: [field_count][24]u8 = undefined;
    var fields: [field_count]http3.Qpack.HeaderField = undefined;
    for (&fields, 0..) |*field, index| {
        const name = try std.fmt.bufPrint(
            &names[index],
            "x-state-ref-{d:0>2}",
            .{index},
        );
        const value = try std.fmt.bufPrint(
            &values[index],
            "value-{d:0>2}",
            .{index},
        );
        _ = try encoder.insertField(name, value);
        field.* = .{ .name = name, .value = value };
    }
    encoder.known_received_count = encoder.table.insert_count;

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try block.appendSlice(allocator, &.{ 0xaa, 0xbb });
    var failing = std.testing.FailingAllocator.init(allocator, .{
        // Match and bitmap allocations succeed; reference capacity fails.
        .fail_index = 2,
    });
    encoder.allocator = failing.allocator();
    const result = encoder.encodeFieldSection(&block, 12, &fields);
    encoder.allocator = allocator;

    try std.testing.expectError(error.OutOfMemory, result);
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, block.items);
    try std.testing.expectEqual(@as(usize, 0), encoder.pending_sections.items.len);
    try std.testing.expectEqual(@as(usize, 0), encoder.pending_section_index.count());
    try std.testing.expectEqual(@as(usize, 0), encoder.reference_counts.count());
    try std.testing.expectEqual(@as(usize, 0), encoder.blocked_section_counts.count());
}

fn checkQpackSpeculativeEncodeAllocationFailure(
    allocator: std.mem.Allocator,
) !void {
    var encoder = QpackEncodeState.initAwaitingPeerSettings(allocator, 4096);
    defer encoder.deinit();
    try encoder.configurePeerLimits(256, 1);
    _ = try encoder.insertField("x-speculative", "repeated-value");
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try encoder.encodeFieldSection(&block, 0, &.{.{
        .name = "x-speculative",
        .value = "repeated-value",
    }});
    try std.testing.expectEqual(
        @as(?usize, 1),
        encoder.blocked_section_counts.get(0),
    );
}

test "HTTP/3 speculative QPACK encoding is allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkQpackSpeculativeEncodeAllocationFailure,
        .{},
    );
}
