//! Bounded live HTTP/1 WebSocket context-takeover fuzzing.
//!
//! Every input crosses a real loopback TCP connection and HTTP Upgrade. The
//! lockstep operation stream varies the initiating direction, text/binary
//! opcode, contiguous/sliced/fragmented/deadline send APIs, owned/caller-buffer
//! receive APIs, and interleaved Ping/Pong while both compression directions
//! retain RFC 7692 history.

const std = @import("std");
const netz = @import("netz");

const websocket = netz.websocket;
const runtime = websocket.runtime;
const max_operations = 12;
const max_sequence_bytes = max_operations * 2;
const max_message_bytes = 512;
const io_timeout = std.Io.Duration.fromSeconds(5);

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

const api_matrix_seed = smithSliceSeed(&.{
    0x00, 0x20, // Client binary, contiguous, owned receive.
    0x03, 0x20, // Server text, contiguous, owned receive.
    0x14, 0x41, // Client binary, slices, caller-buffer receive.
    0x17, 0x41, // Server text, fragmented, caller-buffer receive.
    0x0a, 0x82, // Client text, fragmented, owned receive.
    0x09, 0x82, // Server binary, fragmented, owned receive.
    0x3e, 0xc3, // Client text, deadline send, Ping, into receive.
    0x3d, 0xc3, // Server binary, deadline send, Ping, into receive.
});

const repeated_history_seed = smithSliceSeed(&.{
    0x00, 0x7f,
    0x01, 0x7f,
    0x04, 0x7f,
    0x05, 0x7f,
    0x08, 0x7f,
    0x09, 0x7f,
    0x2c, 0x7f,
    0x2d, 0x7f,
});

const corpus = &.{ &api_matrix_seed, &repeated_history_seed };

test "structured live HTTP1 context-takeover sequences cover runtime APIs" {
    const api_matrix = try runSequence(api_matrix_seed[4..]);
    try std.testing.expect(api_matrix.client_initiated != 0);
    try std.testing.expect(api_matrix.server_initiated != 0);
    try std.testing.expect(api_matrix.text_messages != 0);
    try std.testing.expect(api_matrix.binary_messages != 0);
    try std.testing.expect(api_matrix.contiguous_sends != 0);
    try std.testing.expect(api_matrix.sliced_sends != 0);
    try std.testing.expect(api_matrix.fragmented_sends != 0);
    try std.testing.expect(api_matrix.deadline_sends != 0);
    try std.testing.expect(api_matrix.owned_receives != 0);
    try std.testing.expect(api_matrix.buffer_receives != 0);
    try std.testing.expect(api_matrix.pings != 0);

    const repeated = try runSequence(repeated_history_seed[4..]);
    try std.testing.expect(repeated.messages >= 8);
}

test "fuzz live HTTP1 WebSocket context takeover" {
    try std.testing.fuzz({}, fuzzContextTakeover, .{ .corpus = corpus });
}

test "bounded deterministic live HTTP1 context-takeover mutation smoke" {
    var mutated: [max_sequence_bytes]u8 = undefined;
    inline for (corpus) |seed_with_prefix| {
        const seed = seed_with_prefix[4..];
        for (0..seed.len + 1) |length| {
            _ = try runSequence(seed[0..length]);
        }
        for (seed, 0..) |_, index| {
            @memcpy(mutated[0..seed.len], seed);
            mutated[index] ^= 0xff;
            _ = try runSequence(mutated[0..seed.len]);
        }
    }

    var random_bytes: [max_sequence_bytes]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x77315f6374785f66);
    const random = prng.random();
    for (0..8) |_| {
        const length = random.uintLessThan(usize, max_sequence_bytes + 1);
        random.bytes(random_bytes[0..length]);
        _ = try runSequence(random_bytes[0..length]);
    }
}

fn fuzzContextTakeover(_: void, smith: *std.testing.Smith) !void {
    var storage: [max_sequence_bytes]u8 = undefined;
    const bytes = storage[0..smith.slice(&storage)];
    _ = try runSequence(bytes);
}

const Summary = struct {
    messages: usize = 0,
    client_initiated: usize = 0,
    server_initiated: usize = 0,
    text_messages: usize = 0,
    binary_messages: usize = 0,
    contiguous_sends: usize = 0,
    sliced_sends: usize = 0,
    fragmented_sends: usize = 0,
    deadline_sends: usize = 0,
    owned_receives: usize = 0,
    buffer_receives: usize = 0,
    pings: usize = 0,
};

fn runSequence(bytes: []const u8) !Summary {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 2048,
            .max_message_bytes = max_message_bytes,
        },
    );
    defer server.deinit();

    const operation_count = @min(bytes.len / 2, max_operations);
    const Shared = struct {
        server: *runtime.Server,
        bytes: []const u8,
        operation_count: usize,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{
                .enable_permessage_deflate = true,
                .allow_context_takeover = true,
                .compression_threshold = 0,
            });
            defer connection.close();
            try requireContextTakeover(&connection);

            var payload_storage: [max_message_bytes]u8 = undefined;
            var receive_storage: [max_message_bytes]u8 = undefined;
            for (0..self.operation_count) |index| {
                const control = self.bytes[index * 2];
                const argument = self.bytes[index * 2 + 1];
                const payload = buildMessage(
                    &payload_storage,
                    control,
                    argument,
                );
                if (clientInitiates(control)) {
                    try receiveExpected(
                        &connection,
                        payload,
                        control,
                        &receive_storage,
                    );
                    try sendPayload(&connection, payload, control);
                } else {
                    try maybeSendPing(&connection, control, index);
                    try sendPayload(&connection, payload, control);
                    try receiveExpected(
                        &connection,
                        payload,
                        control,
                        &receive_storage,
                    );
                }
            }
            try std.testing.expectError(
                error.ConnectionClosed,
                connection.receiveMessageWithTimeout(io_timeout),
            );
        }
    };

    var shared = Shared{
        .server = &server,
        .bytes = bytes,
        .operation_count = operation_count,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .host = "127.0.0.1",
            .target = "/fuzz-context-takeover",
            .enable_permessage_deflate = true,
            .allow_context_takeover = true,
            .compression_threshold = 0,
            .limits = .{
                .max_head_bytes = 4096,
                .max_frame_bytes = 2048,
                .max_message_bytes = max_message_bytes,
            },
        },
    );
    defer client.close();
    try requireContextTakeover(&client);

    var summary: Summary = .{};
    var payload_storage: [max_message_bytes]u8 = undefined;
    var receive_storage: [max_message_bytes]u8 = undefined;
    for (0..operation_count) |index| {
        const control = bytes[index * 2];
        const argument = bytes[index * 2 + 1];
        const payload = buildMessage(&payload_storage, control, argument);
        if (clientInitiates(control)) {
            try maybeSendPing(&client, control, index);
            try sendPayload(&client, payload, control);
            try receiveExpected(
                &client,
                payload,
                control,
                &receive_storage,
            );
            summary.client_initiated += 1;
        } else {
            try receiveExpected(
                &client,
                payload,
                control,
                &receive_storage,
            );
            try sendPayload(&client, payload, control);
            summary.server_initiated += 1;
        }
        observeOperation(&summary, control);
    }
    try client.sendClose(.normal_closure, "fuzz complete");
    try std.testing.expectError(
        error.ConnectionClosed,
        client.receiveMessageWithTimeout(io_timeout),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    return summary;
}

fn requireContextTakeover(connection: *runtime.Connection) !void {
    try std.testing.expect(connection.permessage_deflate);
    try std.testing.expect(connection.compression_send_context_takeover);
    try std.testing.expect(connection.compression_receive_context_takeover);
}

fn clientInitiates(control: u8) bool {
    return control & 1 == 0;
}

fn opcodeFor(control: u8) websocket.Opcode {
    return if (control & 2 == 0) .binary else .text;
}

fn maybeSendPing(
    connection: *runtime.Connection,
    control: u8,
    index: usize,
) !void {
    if (control & 0x20 == 0) return;
    const payload = [_]u8{ @truncate(index), control };
    try connection.sendPing(&payload);
}

fn sendPayload(
    connection: *runtime.Connection,
    payload: []const u8,
    control: u8,
) !void {
    const opcode = opcodeFor(control);
    switch ((control >> 2) & 3) {
        0 => if (opcode == .text)
            try connection.sendText(payload)
        else
            try connection.sendBinary(payload),
        1 => if (opcode == .binary) {
            const first = payload.len / 3;
            const second = first + (payload.len - first) / 2;
            try connection.sendBinarySlices(&.{
                payload[0..first],
                &.{},
                payload[first..second],
                payload[second..],
            });
        } else {
            try sendFragmented(connection, opcode, payload);
        },
        2 => try sendFragmented(connection, opcode, payload),
        3 => {
            var progress: runtime.MessageWriteProgress = .{};
            if (opcode == .text) {
                try connection.sendTextWithTimeout(
                    payload,
                    &progress,
                    io_timeout,
                );
            } else {
                try connection.sendBinaryWithTimeout(
                    payload,
                    &progress,
                    io_timeout,
                );
            }
            try std.testing.expect(progress.frame_committed);
        },
        else => unreachable,
    }
}

fn sendFragmented(
    connection: *runtime.Connection,
    opcode: websocket.Opcode,
    payload: []const u8,
) !void {
    const first = payload.len / 3;
    const second = first + (payload.len - first) / 2;
    try connection.sendFragmented(opcode, &.{
        payload[0..first],
        payload[first..second],
        payload[second..],
    });
}

fn receiveExpected(
    connection: *runtime.Connection,
    expected: []const u8,
    control: u8,
    storage: *[max_message_bytes]u8,
) !void {
    if (control & 0x10 == 0) {
        var message = try connection.receiveMessageWithTimeout(io_timeout);
        defer message.deinit(std.testing.allocator);
        try validateMessage(message.opcode, message.payload, message.was_compressed, expected, control);
    } else {
        const message = try connection.receiveMessageIntoWithTimeout(
            storage,
            io_timeout,
        );
        try validateMessage(message.opcode, message.payload, message.was_compressed, expected, control);
    }
}

fn validateMessage(
    opcode: websocket.Opcode,
    payload: []const u8,
    was_compressed: bool,
    expected: []const u8,
    control: u8,
) !void {
    try std.testing.expectEqual(opcodeFor(control), opcode);
    try std.testing.expectEqualSlices(u8, expected, payload);
    try std.testing.expect(was_compressed);
}

fn observeOperation(summary: *Summary, control: u8) void {
    summary.messages += 1;
    if (opcodeFor(control) == .text) {
        summary.text_messages += 1;
    } else {
        summary.binary_messages += 1;
    }
    switch ((control >> 2) & 3) {
        0 => summary.contiguous_sends += 1,
        1 => {
            if (opcodeFor(control) == .binary) {
                summary.sliced_sends += 1;
            } else {
                summary.fragmented_sends += 1;
            }
        },
        2 => summary.fragmented_sends += 1,
        3 => summary.deadline_sends += 1,
        else => unreachable,
    }
    if (control & 0x10 == 0) {
        summary.owned_receives += 1;
    } else {
        summary.buffer_receives += 1;
    }
    if (control & 0x20 != 0) summary.pings += 1;
}

fn buildMessage(
    storage: *[max_message_bytes]u8,
    control: u8,
    argument: u8,
) []const u8 {
    const len = 96 + @as(usize, argument) % (max_message_bytes - 95);
    const phrases = [_][]const u8{
        "context-takeover-live-transport-",
        "repeated-message-history-",
        "fragmented-compressed-message-",
        "caller-buffer-compressed-message-",
    };
    const phrase = phrases[(argument >> 6) & 3];
    for (storage[0..len], 0..) |*byte, index| {
        byte.* = phrase[index % phrase.len];
    }
    storage[len - 2] = '0' + (control & 7);
    storage[len - 1] = 'a' + (argument % 26);
    return storage[0..len];
}
