//! Shared bounded operation model for live WebSocket context-takeover fuzzing.

const std = @import("std");
const netz = @import("netz");

const websocket = netz.websocket;

pub const max_operations = 12;
pub const max_sequence_bytes = max_operations * 2;
pub const max_message_bytes = 512;
pub const io_timeout = std.Io.Duration.fromSeconds(5);

fn smithSliceSeed(comptime input: []const u8) [4 + input.len]u8 {
    var result: [4 + input.len]u8 = undefined;
    std.mem.writeInt(u32, result[0..4], input.len, .little);
    @memcpy(result[4..], input);
    return result;
}

pub const api_matrix_seed = smithSliceSeed(&.{
    0x00, 0x20, // Client binary, contiguous, owned receive.
    0x03, 0x20, // Server text, contiguous, owned receive.
    0x14, 0x41, // Client binary, slices, caller-buffer receive.
    0x17, 0x41, // Server text, fragmented, caller-buffer receive.
    0x0a, 0x82, // Client text, fragmented, owned receive.
    0x09, 0x82, // Server binary, fragmented, owned receive.
    0x3e, 0xc3, // Client text, deadline send, Ping, into receive.
    0x3d, 0xc3, // Server binary, deadline send, Ping, into receive.
});

pub const repeated_history_seed = smithSliceSeed(&.{
    0x00, 0x7f,
    0x01, 0x7f,
    0x04, 0x7f,
    0x05, 0x7f,
    0x08, 0x7f,
    0x09, 0x7f,
    0x2c, 0x7f,
    0x2d, 0x7f,
});

pub const corpus = &.{ &api_matrix_seed, &repeated_history_seed };

pub const Summary = struct {
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

pub fn requireApiMatrix(summary: Summary) !void {
    try std.testing.expect(summary.client_initiated != 0);
    try std.testing.expect(summary.server_initiated != 0);
    try std.testing.expect(summary.text_messages != 0);
    try std.testing.expect(summary.binary_messages != 0);
    try std.testing.expect(summary.contiguous_sends != 0);
    try std.testing.expect(summary.sliced_sends != 0);
    try std.testing.expect(summary.fragmented_sends != 0);
    try std.testing.expect(summary.deadline_sends != 0);
    try std.testing.expect(summary.owned_receives != 0);
    try std.testing.expect(summary.buffer_receives != 0);
    try std.testing.expect(summary.pings != 0);
}

pub fn operationCount(bytes: []const u8) usize {
    return @min(bytes.len / 2, max_operations);
}

pub fn runServer(
    allocator: std.mem.Allocator,
    connection: anytype,
    bytes: []const u8,
) !void {
    try requireContextTakeover(connection);
    const operation_count = operationCount(bytes);
    var payload_storage: [max_message_bytes]u8 = undefined;
    var receive_storage: [max_message_bytes]u8 = undefined;
    for (0..operation_count) |index| {
        const control = bytes[index * 2];
        const argument = bytes[index * 2 + 1];
        const payload = buildMessage(&payload_storage, control, argument);
        if (clientInitiates(control)) {
            try receiveExpected(
                allocator,
                connection,
                payload,
                control,
                &receive_storage,
            );
            try sendPayload(connection, payload, control);
        } else {
            try maybeSendPing(connection, control, index);
            try sendPayload(connection, payload, control);
            try receiveExpected(
                allocator,
                connection,
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

pub fn runClient(
    allocator: std.mem.Allocator,
    connection: anytype,
    bytes: []const u8,
) !Summary {
    try requireContextTakeover(connection);
    const operation_count = operationCount(bytes);
    var summary: Summary = .{};
    var payload_storage: [max_message_bytes]u8 = undefined;
    var receive_storage: [max_message_bytes]u8 = undefined;
    for (0..operation_count) |index| {
        const control = bytes[index * 2];
        const argument = bytes[index * 2 + 1];
        const payload = buildMessage(&payload_storage, control, argument);
        if (clientInitiates(control)) {
            try maybeSendPing(connection, control, index);
            try sendPayload(connection, payload, control);
            try receiveExpected(
                allocator,
                connection,
                payload,
                control,
                &receive_storage,
            );
            summary.client_initiated += 1;
        } else {
            try receiveExpected(
                allocator,
                connection,
                payload,
                control,
                &receive_storage,
            );
            try sendPayload(connection, payload, control);
            summary.server_initiated += 1;
        }
        observeOperation(&summary, control);
    }
    try connection.sendClose(.normal_closure, "fuzz complete");
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.receiveMessageWithTimeout(io_timeout),
    );
    return summary;
}

fn requireContextTakeover(connection: anytype) !void {
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

fn maybeSendPing(connection: anytype, control: u8, index: usize) !void {
    if (control & 0x20 == 0) return;
    const payload = [_]u8{ @truncate(index), control };
    try connection.sendPing(&payload);
}

fn sendPayload(connection: anytype, payload: []const u8, control: u8) !void {
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
            var progress: websocket.runtime.MessageWriteProgress = .{};
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
    connection: anytype,
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
    allocator: std.mem.Allocator,
    connection: anytype,
    expected: []const u8,
    control: u8,
    storage: *[max_message_bytes]u8,
) !void {
    if (control & 0x10 == 0) {
        var message = try connection.receiveMessageWithTimeout(io_timeout);
        defer message.deinit(allocator);
        try validateMessage(
            message.opcode,
            message.payload,
            message.was_compressed,
            expected,
            control,
        );
    } else {
        const message = try connection.receiveMessageIntoWithTimeout(
            storage,
            io_timeout,
        );
        try validateMessage(
            message.opcode,
            message.payload,
            message.was_compressed,
            expected,
            control,
        );
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
