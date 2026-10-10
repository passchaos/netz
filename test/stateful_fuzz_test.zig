//! Bounded state-machine sequence fuzzing across Netz's public protocols.
//!
//! Inputs are interpreted as operation streams rather than independent wire
//! messages. Ordinary tests replay and mutate deterministic sequences; pass
//! --fuzz=N to let Zig retain coverage-increasing operation histories.

const std = @import("std");
const netz = @import("netz");

const max_operations = 512;
const max_sequence_bytes = max_operations;

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

const lifecycle_seed = smithSliceSeed(&.{
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
});
const repeated_seed = smithSliceSeed(&.{
    0x10, 0x10, 0x10, 0x10, 0x21, 0x21, 0x32, 0x32,
    0x43, 0x43, 0x54, 0x54, 0x65, 0x65, 0x76, 0x76,
});
const boundary_seed = smithSliceSeed(&.{
    0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff, 0x3f, 0x40,
    0x04, 0xfc, 0x02, 0xfd, 0x55, 0xaa, 0x00, 0xff,
});
const long_seed = smithSliceSeed(
    "stateful-http-websocket-webtransport-mqtt-sequence",
);
const protocol_progress_seed = smithSliceSeed(&.{
    // HTTP/1 full-message append/consume, WebSocket text fragmentation and
    // WebTransport/MQTT lifecycle operations all receive useful transitions.
    0x05, 0x0a, 0x43, 0x21, 0x1a, 0x20, 0x03, 0x15,
    0x06, 0x07, 0x0a, 0x0b, 0x0c, 0x01, 0x20, 0x0f,
});

test "fuzz bounded stateful protocol sequences" {
    try std.testing.fuzz({}, fuzzStatefulSequences, .{ .corpus = &.{
        &lifecycle_seed,
        &repeated_seed,
        &boundary_seed,
        &long_seed,
        &protocol_progress_seed,
    } });
}

test "bounded deterministic stateful mutation smoke" {
    const seeds = [_][]const u8{
        lifecycle_seed[4..],
        repeated_seed[4..],
        boundary_seed[4..],
        long_seed[4..],
        protocol_progress_seed[4..],
    };
    var buffer: [max_sequence_bytes]u8 = undefined;
    for (seeds) |seed| {
        try exerciseAll(seed);
        for (0..seed.len + 1) |length| try exerciseAll(seed[0..length]);
        for (seed, 0..) |_, index| {
            @memcpy(buffer[0..seed.len], seed);
            buffer[index] ^= 0xff;
            try exerciseAll(buffer[0..seed.len]);
        }
    }

    var prng = std.Random.DefaultPrng.init(0x737461746566757a);
    const random = prng.random();
    for (0..64) |_| {
        const length = random.uintLessThan(usize, max_sequence_bytes + 1);
        random.bytes(buffer[0..length]);
        try exerciseAll(buffer[0..length]);
    }
}

fn fuzzStatefulSequences(_: void, smith: *std.testing.Smith) !void {
    var storage: [max_sequence_bytes]u8 = undefined;
    const bytes = storage[0..smith.slice(&storage)];
    try exerciseAll(bytes);
}

fn exerciseAll(bytes: []const u8) !void {
    const sequence = bytes[0..@min(bytes.len, max_operations)];
    try exerciseHttp(sequence);
    try exerciseWebSocket(sequence);
    try exerciseWebTransport(sequence);
    try exerciseMqtt(sequence);
}

fn exerciseHttp(sequence: []const u8) !void {
    try exerciseHttp1Pipeline(sequence);
    try exerciseHttp2Flow(sequence);
    try exerciseHpack(sequence);
    try exerciseHttp3Control(sequence);
    try exerciseQpack(sequence);
}

fn exerciseHttp1Pipeline(sequence: []const u8) !void {
    const allocator = std.testing.allocator;
    const request_wire =
        "POST /state HTTP/1.1\r\nHost: fuzz.test\r\n" ++
        "Content-Length: 3\r\n\r\nabc";
    const response_wire =
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    var request_bytes: std.ArrayList(u8) = .empty;
    defer request_bytes.deinit(allocator);
    var response_bytes: std.ArrayList(u8) = .empty;
    defer response_bytes.deinit(allocator);
    var request_offset: usize = 0;
    var response_offset: usize = 0;

    for (sequence) |byte| {
        switch (byte & 0x03) {
            0 => appendCyclicChunk(
                &request_bytes,
                request_wire,
                &request_offset,
                1 + ((byte >> 2) & 0x07),
            ) catch request_bytes.clearRetainingCapacity(),
            1 => appendBounded(&request_bytes, request_wire) catch
                request_bytes.clearRetainingCapacity(),
            2 => try consumeHttp1Request(&request_bytes),
            3 => appendBounded(&request_bytes, &.{byte}) catch
                request_bytes.clearRetainingCapacity(),
            else => unreachable,
        }
        switch ((byte >> 2) & 0x03) {
            0 => appendCyclicChunk(
                &response_bytes,
                response_wire,
                &response_offset,
                1 + ((byte >> 4) & 0x07),
            ) catch response_bytes.clearRetainingCapacity(),
            1 => appendBounded(&response_bytes, response_wire) catch
                response_bytes.clearRetainingCapacity(),
            2 => try consumeHttp1Response(&response_bytes),
            3 => appendBounded(&response_bytes, &.{byte}) catch
                response_bytes.clearRetainingCapacity(),
            else => unreachable,
        }
        try std.testing.expect(request_bytes.items.len <= 4096);
        try std.testing.expect(response_bytes.items.len <= 4096);
    }
}

fn appendCyclicChunk(
    pending: *std.ArrayList(u8),
    source: []const u8,
    offset: *usize,
    requested: usize,
) !void {
    const length = @min(requested, source.len - offset.*);
    try appendBounded(pending, source[offset.*..][0..length]);
    offset.* += length;
    if (offset.* == source.len) offset.* = 0;
}

fn appendBounded(pending: *std.ArrayList(u8), bytes: []const u8) !void {
    if (bytes.len > 4096 -| pending.items.len) return error.BufferTooShort;
    try pending.appendSlice(std.testing.allocator, bytes);
}

fn consumeHttp1Request(pending: *std.ArrayList(u8)) !void {
    if (netz.http1.parseRequest(
        std.testing.allocator,
        pending.items,
        .{ .max_headers = 32, .max_request_target_bytes = 1024 },
    )) |value| {
        var request = value;
        defer request.deinit(std.testing.allocator);
        try std.testing.expect(request.consumed != 0);
        consumePrefix(pending, request.consumed);
    } else |err| switch (err) {
        error.BufferTooShort => {},
        else => consumePrefix(pending, @min(1, pending.items.len)),
    }
}

fn consumeHttp1Response(pending: *std.ArrayList(u8)) !void {
    if (netz.http1.parseResponse(
        std.testing.allocator,
        pending.items,
        .{ .max_headers = 32 },
    )) |value| {
        var response = value;
        defer response.deinit(std.testing.allocator);
        try std.testing.expect(response.consumed != 0);
        consumePrefix(pending, response.consumed);
    } else |err| switch (err) {
        error.BufferTooShort => {},
        else => consumePrefix(pending, @min(1, pending.items.len)),
    }
}

fn consumePrefix(pending: *std.ArrayList(u8), consumed: usize) void {
    std.debug.assert(consumed <= pending.items.len);
    const remaining = pending.items.len - consumed;
    std.mem.copyForwards(
        u8,
        pending.items[0..remaining],
        pending.items[consumed..],
    );
    pending.items.len = remaining;
}

fn exerciseHttp2Flow(sequence: []const u8) !void {
    var window = netz.http2.runtime.FlowWindow{};
    var expected = window.value;
    for (sequence) |byte| {
        const amount: usize = (byte & 0x1f) + 1;
        switch (byte >> 6) {
            0 => {
                const before = window.value;
                if (window.reserve(amount)) |_| {
                    try std.testing.expect(expected >= amount);
                    expected -= @intCast(amount);
                } else |_| try std.testing.expectEqual(before, window.value);
            },
            1 => {
                const before = window.value;
                if (window.receive(amount)) |_| {
                    try std.testing.expect(expected >= amount);
                    expected -= @intCast(amount);
                } else |_| try std.testing.expectEqual(before, window.value);
            },
            2 => {
                const increment: u31 = @intCast(amount);
                const before = window.value;
                if (window.update(increment)) |_| {
                    expected += increment;
                } else |_| try std.testing.expectEqual(before, window.value);
            },
            3 => {
                const delta: i64 = if ((byte & 0x20) == 0)
                    @intCast(amount)
                else
                    -@as(i64, @intCast(amount));
                const before = window.value;
                if (window.adjust(delta)) |_| {
                    expected += delta;
                } else |_| try std.testing.expectEqual(before, window.value);
            },
            else => unreachable,
        }
        try std.testing.expectEqual(expected, window.value);
        try std.testing.expectEqual(
            if (expected <= 0) 0 else @as(usize, @intCast(expected)),
            window.available(),
        );
    }
}

fn exerciseHpack(sequence: []const u8) !void {
    const allocator = std.testing.allocator;
    var encoder = netz.http2.Hpack.Encoder{};
    defer encoder.deinit(allocator);
    var decoder = netz.http2.Hpack.Decoder{};
    defer decoder.deinit(allocator);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    var index: usize = 0;
    while (index < sequence.len) : (index += 1) {
        const byte = sequence[index];
        if ((byte & 0x07) == 0) {
            const limit: usize = @as(usize, byte >> 3) * 32;
            encoder.setMaxDynamicTableSize(allocator, limit);
            decoder.setMaxDynamicTableSize(allocator, limit);
            continue;
        }
        const end = @min(sequence.len, index + 1 + (byte & 0x07));
        const value = sequence[index + 1 .. end];
        const field = netz.http2.Hpack.HeaderField{
            .name = "x-netz-fuzz",
            .value = value,
            .never_index = (byte & 0x08) != 0,
        };
        encoded.clearRetainingCapacity();
        try encoder.encodeBlock(&encoded, allocator, &.{field});
        const decoded = try decoder.decodeBlockOwnedWithLimit(
            allocator,
            encoded.items,
            4,
            512,
        );
        defer netz.http2.Hpack.freeOwnedFields(allocator, decoded);
        try std.testing.expectEqual(@as(usize, 1), decoded.len);
        try std.testing.expectEqualStrings(field.name, decoded[0].name);
        try std.testing.expectEqualSlices(u8, field.value, decoded[0].value);
        index = end - 1;
    }
}

fn exerciseHttp3Control(sequence: []const u8) !void {
    const allocator = std.testing.allocator;
    var state = try netz.http3.ControlState.init(.{
        .max_priority_updates = 8,
    });
    defer state.deinit(allocator);

    var settings_bytes: std.ArrayList(u8) = .empty;
    defer settings_bytes.deinit(allocator);
    try netz.http3.writeSettingsFrame(&settings_bytes, allocator, .{});
    try feedControlFragments(&state, settings_bytes.items, 1);
    try std.testing.expect(state.settings.received);

    for (sequence, 0..) |byte, index| {
        var storage: [netz.http3.max_priority_update_frame_len]u8 = undefined;
        const value: u64 = byte & 0x3f;
        const encoded = switch (byte >> 6) {
            0 => try netz.http3.writeCancelPushFrameInto(
                storage[0..netz.http3.max_single_varint_frame_len],
                value,
            ),
            1 => try netz.http3.writeMaxPushIdFrameInto(
                storage[0..netz.http3.max_single_varint_frame_len],
                value,
            ),
            2 => try netz.http3.writePriorityUpdateFrameInto(
                &storage,
                value & ~@as(u64, 0x03),
                .{
                    .urgency = @truncate(value),
                    .incremental = (byte & 0x08) != 0,
                },
            ),
            3 => try writeGoAwayInto(&storage, value & ~@as(u64, 0x03)),
            else => unreachable,
        };
        const old_goaway = state.acceptsRequestStream(64);
        const applied = if (feedControlFragments(
            &state,
            encoded,
            (index % 4) + 1,
        )) |_| true else |_| false;
        if (!applied) {
            // A control-stream error terminates that HTTP/3 connection. Start
            // a fresh bounded state so later operations still explore useful
            // transitions instead of repeatedly hitting the poisoned frame.
            state.deinit(allocator);
            state = try netz.http3.ControlState.init(.{
                .max_priority_updates = 8,
            });
            try feedControlFragments(&state, settings_bytes.items, 1);
        }
        try std.testing.expect(state.settings.received);
        try std.testing.expect(state.priorityUpdates().len <= 8);
        // Once GOAWAY excludes stream 64, no later legal decrease can reopen it.
        if (applied and !old_goaway) {
            try std.testing.expect(!state.acceptsRequestStream(64));
        }
    }
}

fn writeGoAwayInto(
    storage: *[netz.http3.max_priority_update_frame_len]u8,
    stream_id: u64,
) ![]const u8 {
    const payload = try netz.quic.varint.encodeInto(storage[2..], stream_id);
    storage[0] = @intCast(netz.http3.FrameType.goaway);
    storage[1] = @intCast(payload.len);
    return storage[0 .. 2 + payload.len];
}

fn feedControlFragments(
    state: *netz.http3.ControlState,
    bytes: []const u8,
    fragment_size: usize,
) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const end = @min(bytes.len, offset + fragment_size);
        try state.appendControlPayload(std.testing.allocator, bytes[offset..end]);
        offset = end;
    }
}

fn exerciseQpack(sequence: []const u8) !void {
    const allocator = std.testing.allocator;
    var table = netz.http3.Qpack.DynamicTable.init(allocator, 512);
    defer table.deinit();
    try table.setCapacity(512);

    var index: usize = 0;
    while (index < sequence.len) : (index += 1) {
        const byte = sequence[index];
        switch (byte & 0x03) {
            0 => table.setCapacity(
                @as(usize, byte >> 2) * 8,
            ) catch {},
            1 => {
                const end = @min(
                    sequence.len,
                    index + 1 + ((byte >> 2) & 0x07),
                );
                _ = table.insert("x-netz-fuzz", sequence[index + 1 .. end]) catch {};
                index = end - 1;
            },
            2 => _ = table.duplicate((byte >> 2) & 0x0f) catch {},
            3 => {
                _ = table.relative((byte >> 2) & 0x0f);
                _ = table.absolute(byte >> 2);
                _ = table.findExact("x-netz-fuzz", &.{byte});
            },
            else => unreachable,
        }
        try std.testing.expect(table.entryCount() <= table.maxEntries());
    }
}

fn exerciseWebSocket(sequence: []const u8) !void {
    const allocator = std.testing.allocator;
    var assembler = netz.websocket.MessageAssembler.initLimited(allocator, 512);
    defer assembler.deinit();
    var payload_storage: [8]u8 = undefined;
    for (sequence, 0..) |byte, index| {
        const payload_len: usize = byte & 0x07;
        for (payload_storage[0..payload_len], 0..) |*item, payload_index| {
            // Text operations stay valid UTF-8 so a rejected transition tests
            // framing state rather than poisoning a connection with bad text.
            item.* = 'a' + @as(
                u8,
                @intCast((index + payload_index) % 26),
            );
        }
        const control = (byte & 0x20) != 0;
        const continuation = (byte & 0x10) != 0;
        const frame = netz.websocket.Frame{
            .header = .{
                .fin = control or (byte & 0x08) != 0,
                .opcode = if (control)
                    .ping
                else if (continuation)
                    .continuation
                else if ((byte & 0x40) != 0)
                    .text
                else
                    .binary,
                .masked = false,
                .payload_len = payload_len,
                .mask_key = null,
                .header_len = 2,
            },
            .payload = payload_storage[0..payload_len],
            .consumed = 2 + payload_len,
        };
        const result = assembler.feed(frame) catch {
            assembler.deinit();
            assembler = netz.websocket.MessageAssembler.initLimited(
                allocator,
                512,
            );
            continue;
        };
        if (result) |message| {
            defer allocator.free(message.payload);
            try std.testing.expect(message.payload.len <= 512);
            try std.testing.expect(
                message.opcode == .text or message.opcode == .binary,
            );
            if (message.opcode == .text) {
                try std.testing.expect(std.unicode.utf8ValidateSlice(
                    message.payload,
                ));
                try std.testing.expect(message.utf8_validated);
            }
        }
    }
}

fn exerciseWebTransport(sequence: []const u8) !void {
    try exerciseWebTransportSession(sequence);
    const allocator = std.testing.allocator;
    var registry = try netz.webtransport.StreamRegistry.init(
        allocator,
        .init(0),
        .client,
        .{
            .max_local_bidi = 8,
            .max_local_uni = 8,
            .max_peer_bidi = 8,
            .max_peer_uni = 8,
        },
    );
    defer registry.deinit();

    for (sequence, 0..) |byte, index| {
        const streams = registry.registered();
        switch (byte & 0x07) {
            0 => _ = registry.openLocal(.bidirectional) catch null,
            1 => _ = registry.openLocal(.unidirectional) catch null,
            2 => {
                const direction: netz.webtransport.StreamDirection =
                    if ((byte & 0x08) == 0) .bidirectional else .unidirectional;
                const base: u62 = if (direction == .bidirectional) 1 else 3;
                _ = registry.registerPeer(
                    base + 4 * @as(u62, @intCast((byte >> 4) & 0x07)),
                    direction,
                ) catch null;
            },
            3 => if (streams.len != 0) {
                const id = streams[index % streams.len].stream_id;
                registry.recordSent(id, (byte >> 3) & 0x0f, (byte & 0x80) != 0) catch {};
            },
            4 => if (streams.len != 0) {
                const id = streams[index % streams.len].stream_id;
                registry.recordReceived(id, (byte >> 3) & 0x0f, (byte & 0x80) != 0) catch {};
            },
            5 => if (streams.len != 0) {
                registry.markReset(
                    streams[index % streams.len].stream_id,
                    byte,
                ) catch {};
            },
            6 => if (streams.len != 0) {
                registry.markStopped(
                    streams[index % streams.len].stream_id,
                    byte,
                ) catch {};
            },
            7 => if (streams.len != 0) {
                registry.setPriority(
                    streams[index % streams.len].stream_id,
                    @as(i32, byte) - 128,
                ) catch {};
            },
            else => unreachable,
        }
        try validateStreamRegistry(registry.registered());
    }
}

fn exerciseWebTransportSession(sequence: []const u8) !void {
    var state = netz.webtransport.SessionState{};
    for (sequence) |byte| {
        const previous_sent = state.datagrams_sent;
        const previous_received = state.datagrams_received;
        const session_id = netz.webtransport.SessionId.init(
            @as(u62, byte >> 3) * 4,
        );
        switch (byte & 0x07) {
            0 => state.establish(session_id) catch {},
            1 => state.recordDatagramSent(session_id) catch {},
            2 => state.recordDatagramReceived(session_id) catch {},
            3 => state.drain(),
            4 => state.close(byte),
            else => state.ensureOpen(session_id) catch {},
        }
        try std.testing.expect(state.datagrams_sent >= previous_sent);
        try std.testing.expect(state.datagrams_received >= previous_received);
        if (state.closed) {
            try std.testing.expect(!state.established);
            try std.testing.expect(!state.draining);
            try std.testing.expect(state.close_code != null);
        }
        if (state.draining) {
            try std.testing.expect(state.established);
            try std.testing.expect(!state.closed);
        }
    }
}

fn validateStreamRegistry(streams: []const netz.webtransport.StreamState) !void {
    try std.testing.expect(streams.len <= 32);
    for (streams, 0..) |stream, index| {
        for (streams[index + 1 ..]) |other| {
            try std.testing.expect(stream.stream_id != other.stream_id);
        }
        if (stream.lifecycle() == .closed) {
            try std.testing.expect(stream.local_fin and stream.peer_fin);
        }
        if (stream.lifecycle() == .reset) {
            try std.testing.expect(
                stream.send_reset != null or stream.receive_reset != null,
            );
        }
    }
}

fn exerciseMqtt(sequence: []const u8) !void {
    const allocator = std.testing.allocator;
    var store = netz.mqtt.session.Store.init(allocator, .{
        .max_sessions = 4,
        .max_subscriptions_per_session = 8,
        .max_queued_per_session = 8,
        .max_inflight_per_session = 4,
        .max_incoming_qos2_per_session = 8,
        .max_session_bytes = 4096,
        .max_total_bytes = 16 * 1024,
    });
    defer store.deinit();
    const clients = [_][]const u8{ "a", "b", "c", "d" };
    const topics = [_][]const u8{ "a/one", "b/+", "c/#", "d/four" };
    var now_ns: i96 = 0;

    for (sequence) |byte| {
        const client = clients[(byte >> 6) & 0x03];
        const handle = store.find(client, .{ .nanoseconds = now_ns });
        switch (byte & 0x0f) {
            0 => _ = store.open(
                client,
                (byte & 0x10) != 0,
                (byte >> 4) & 0x03,
                .{ .nanoseconds = now_ns },
            ) catch {},
            1 => if (handle) |value| store.disconnect(
                value,
                null,
                .{ .nanoseconds = now_ns },
            ) catch {},
            2 => _ = store.discard(client),
            3 => if (handle) |value| {
                _ = store.setSubscription(
                    value,
                    .{
                        .topic_filter = topics[(byte >> 4) & 0x03],
                        .qos = qosFromBits(byte),
                    },
                    null,
                ) catch {};
            },
            4 => if (handle) |value| {
                _ = store.removeSubscription(
                    value,
                    topics[(byte >> 4) & 0x03],
                ) catch {};
            },
            5 => if (handle) |value| {
                _ = store.enqueuePublish(
                    value,
                    "state/topic",
                    &.{byte},
                    .{
                        .qos = qosFromBits(byte),
                        .now = .{ .nanoseconds = now_ns },
                    },
                ) catch {};
            },
            6 => if (handle) |value| {
                var output: [2]netz.mqtt.session.Transmission = undefined;
                _ = store.drainInto(
                    value,
                    .{ .nanoseconds = now_ns },
                    2,
                    &output,
                ) catch {};
            },
            7 => if (handle) |value| {
                if ((byte & 0x10) == 0) {
                    _ = store.handleAck(
                        value,
                        .puback,
                        nonzeroPacketId(byte),
                        0,
                    ) catch {};
                } else if (store.routeId(value)) |route_id| {
                    store.completeQoS0Transmission(
                        value,
                        route_id,
                        0,
                    ) catch {};
                } else |_| {}
            },
            8 => if (handle) |value| {
                _ = store.handleAck(
                    value,
                    .pubrec,
                    nonzeroPacketId(byte),
                    0,
                ) catch {};
            },
            9 => if (handle) |value| {
                _ = store.handleAck(
                    value,
                    .pubcomp,
                    nonzeroPacketId(byte),
                    0,
                ) catch {};
            },
            10 => if (handle) |value| {
                _ = store.recordIncomingQoS2(
                    value,
                    nonzeroPacketId(byte),
                ) catch {};
            },
            11 => if (handle) |value| store.markIncomingQoS2ReleasePending(
                value,
                nonzeroPacketId(byte),
            ) catch {},
            12 => if (handle) |value| store.completeIncomingQoS2(
                value,
                nonzeroPacketId(byte),
            ) catch {},
            13 => if (handle) |value| {
                _ = store.stageImmediatePublish(
                    value,
                    "state/immediate",
                    &.{byte},
                    .{
                        .qos = if ((byte & 0x10) == 0)
                            .at_least_once
                        else
                            .exactly_once,
                        .now = .{ .nanoseconds = now_ns },
                    },
                    2,
                ) catch {};
            },
            14 => {
                now_ns +|= @as(i96, (byte >> 4) + 1) * std.time.ns_per_s;
                _ = store.pruneExpired(.{ .nanoseconds = now_ns });
            },
            15 => try verifyMqttSnapshot(&store, now_ns),
            else => unreachable,
        }
        try validateMqttStore(&store);
    }
}

fn qosFromBits(byte: u8) netz.mqtt.QoS {
    return switch ((byte >> 4) % 3) {
        0 => .at_most_once,
        1 => .at_least_once,
        2 => .exactly_once,
        else => unreachable,
    };
}

fn nonzeroPacketId(byte: u8) u16 {
    return @as(u16, (byte >> 4) & 0x03) + 1;
}

fn validateMqttStore(store: *netz.mqtt.session.Store) !void {
    const stats = store.aggregateStats();
    try std.testing.expectEqual(store.count(), stats.session_count);
    try std.testing.expectEqual(store.totalBytes(), stats.owned_wire_bytes);
    try std.testing.expect(stats.session_count <= 4);
    try std.testing.expect(stats.subscription_count <= 4 * 8);
    try std.testing.expect(stats.queued_count <= 4 * 8);
    try std.testing.expect(stats.inflight_count <= 4 * 4);
    try std.testing.expect(
        stats.outgoing_publish_window_used <= stats.inflight_count,
    );
    try std.testing.expect(stats.incoming_qos2_count <= 4 * 8);
    try std.testing.expectEqual(
        stats.session_count,
        stats.connected_count + stats.disconnected_count,
    );
}

fn verifyMqttSnapshot(
    store: *netz.mqtt.session.Store,
    now_ns: i96,
) !void {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try store.writeSnapshot(
        &encoded,
        allocator,
        .{ .nanoseconds = now_ns },
    );
    var restored = netz.mqtt.session.Store.init(allocator, .{
        .max_sessions = 4,
        .max_subscriptions_per_session = 8,
        .max_queued_per_session = 8,
        .max_inflight_per_session = 4,
        .max_incoming_qos2_per_session = 8,
        .max_session_bytes = 4096,
        .max_total_bytes = 16 * 1024,
    });
    defer restored.deinit();
    var cursor = netz.mqtt.persistence.codec.Cursor.init(encoded.items);
    try restored.restoreSnapshot(
        &cursor,
        .{ .nanoseconds = now_ns },
        0,
    );
    try cursor.finish();
    try validateMqttStore(&restored);
}
