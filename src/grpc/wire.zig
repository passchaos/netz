//! gRPC length-prefixed messages, timeout, status, and percent-message codecs.

const std = @import("std");

pub const Error = std.mem.Allocator.Error || error{
    BufferTooShort,
    BufferTooSmall,
    GrpcMessageTooLarge,
    InvalidCompressedFlag,
    InvalidGrpcStatus,
    InvalidTimeout,
    MessageTooLarge,
};

pub const Status = enum(u8) {
    ok = 0,
    cancelled = 1,
    unknown = 2,
    invalid_argument = 3,
    deadline_exceeded = 4,
    not_found = 5,
    already_exists = 6,
    permission_denied = 7,
    resource_exhausted = 8,
    failed_precondition = 9,
    aborted = 10,
    out_of_range = 11,
    unimplemented = 12,
    internal = 13,
    unavailable = 14,
    data_loss = 15,
    unauthenticated = 16,

    pub fn parse(raw: []const u8) Error!Status {
        if (raw.len == 0 or
            (raw.len > 1 and raw[0] == '0'))
        {
            return error.InvalidGrpcStatus;
        }
        for (raw) |byte| {
            if (byte < '0' or byte > '9') {
                return error.InvalidGrpcStatus;
            }
        }
        const value = std.fmt.parseInt(u8, raw, 10) catch
            return error.InvalidGrpcStatus;
        return std.enums.fromInt(Status, value) orelse
            error.InvalidGrpcStatus;
    }
};

pub const Message = struct {
    compressed: bool,
    payload: []const u8,
};

pub fn encodedMessageLen(payload_len: usize) Error!usize {
    if (payload_len > std.math.maxInt(u32)) {
        return error.GrpcMessageTooLarge;
    }
    return std.math.add(usize, 5, payload_len) catch
        error.GrpcMessageTooLarge;
}

pub fn writeMessageInto(
    out: []u8,
    payload: []const u8,
    compressed: bool,
) Error![]u8 {
    const required = try encodedMessageLen(payload.len);
    if (out.len < required) return error.BufferTooSmall;
    out[0] = @intFromBool(compressed);
    std.mem.writeInt(u32, out[1..5], @intCast(payload.len), .big);
    @memcpy(out[5..required], payload);
    return out[0..required];
}

pub fn writeMessage(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    payload: []const u8,
    compressed: bool,
) Error!void {
    const start = out.items.len;
    const required = try encodedMessageLen(payload.len);
    try out.ensureUnusedCapacity(allocator, required);
    out.items.len += required;
    _ = try writeMessageInto(
        out.items[start..][0..required],
        payload,
        compressed,
    );
}

pub const MessageIterator = struct {
    input: []const u8,
    max_message_size: usize,
    offset: usize = 0,

    pub fn init(
        input: []const u8,
        max_message_size: usize,
    ) MessageIterator {
        return .{
            .input = input,
            .max_message_size = max_message_size,
        };
    }

    pub fn next(self: *MessageIterator) Error!?Message {
        if (self.offset == self.input.len) return null;
        if (self.input.len - self.offset < 5) {
            return error.BufferTooShort;
        }
        const compressed_flag = self.input[self.offset];
        if (compressed_flag > 1) return error.InvalidCompressedFlag;
        const message_len: usize = std.mem.readInt(
            u32,
            self.input[self.offset + 1 ..][0..4],
            .big,
        );
        if (message_len > self.max_message_size) {
            return error.GrpcMessageTooLarge;
        }
        const payload_start = self.offset + 5;
        const end = std.math.add(
            usize,
            payload_start,
            message_len,
        ) catch return error.GrpcMessageTooLarge;
        if (end > self.input.len) return error.BufferTooShort;
        self.offset = end;
        return .{
            .compressed = compressed_flag == 1,
            .payload = self.input[payload_start..end],
        };
    }
};

pub const TimeoutUnit = enum(u8) {
    hour = 'H',
    minute = 'M',
    second = 'S',
    millisecond = 'm',
    microsecond = 'u',
    nanosecond = 'n',

    fn nanoseconds(self: TimeoutUnit) i96 {
        return switch (self) {
            .hour => 60 * 60 * std.time.ns_per_s,
            .minute => 60 * std.time.ns_per_s,
            .second => std.time.ns_per_s,
            .millisecond => std.time.ns_per_ms,
            .microsecond => std.time.ns_per_us,
            .nanosecond => 1,
        };
    }
};

pub const Timeout = struct {
    value: u32,
    unit: TimeoutUnit,

    pub fn init(value: u32, unit: TimeoutUnit) Error!Timeout {
        if (value == 0 or value > 99_999_999) {
            return error.InvalidTimeout;
        }
        return .{ .value = value, .unit = unit };
    }

    pub fn parse(raw: []const u8) Error!Timeout {
        if (raw.len < 2 or raw.len > 9) {
            return error.InvalidTimeout;
        }
        const unit = std.enums.fromInt(
            TimeoutUnit,
            raw[raw.len - 1],
        ) orelse return error.InvalidTimeout;
        const digits = raw[0 .. raw.len - 1];
        if (digits.len > 8) return error.InvalidTimeout;
        for (digits) |byte| {
            if (byte < '0' or byte > '9') {
                return error.InvalidTimeout;
            }
        }
        const value = std.fmt.parseInt(u32, digits, 10) catch
            return error.InvalidTimeout;
        return init(value, unit);
    }

    pub fn fromDuration(value_duration: std.Io.Duration) Error!Timeout {
        const nanoseconds = value_duration.toNanoseconds();
        if (nanoseconds <= 0) return error.InvalidTimeout;
        const units = [_]TimeoutUnit{
            .hour,
            .minute,
            .second,
            .millisecond,
            .microsecond,
            .nanosecond,
        };
        // Prefer a readable exact value. If no exact representation fits eight
        // digits, round upward in the finest fitting unit so the encoded
        // deadline never expires earlier than requested.
        for (units) |unit| {
            const scale = unit.nanoseconds();
            if (@mod(nanoseconds, scale) != 0) continue;
            const value = @divExact(nanoseconds, scale);
            if (value <= 99_999_999) {
                return init(@intCast(value), unit);
            }
        }
        var index: usize = units.len;
        while (index != 0) {
            index -= 1;
            const unit = units[index];
            const scale = unit.nanoseconds();
            const value = @divTrunc(nanoseconds - 1, scale) + 1;
            if (value <= 99_999_999) {
                return init(@intCast(value), unit);
            }
        }
        return error.InvalidTimeout;
    }

    pub fn duration(self: Timeout) std.Io.Duration {
        return .fromNanoseconds(
            @as(i96, self.value) * self.unit.nanoseconds(),
        );
    }

    pub fn formatInto(
        self: Timeout,
        out: *[9]u8,
    ) Error![]const u8 {
        const rendered = std.fmt.bufPrint(
            out[0..8],
            "{d}",
            .{self.value},
        ) catch return error.InvalidTimeout;
        out[rendered.len] = @intFromEnum(self.unit);
        return out[0 .. rendered.len + 1];
    }
};

pub fn isContentType(value: []const u8) bool {
    const prefix = "application/grpc";
    if (!std.mem.startsWith(u8, value, prefix)) return false;
    return value.len == prefix.len or
        value[prefix.len] == '+' or
        value[prefix.len] == ';';
}

pub fn encodeStatusMessageInto(
    out: []u8,
    message: []const u8,
) Error![]u8 {
    var written: usize = 0;
    for (message) |byte| {
        if (statusMessageByteUnescaped(byte)) {
            if (written == out.len) return error.BufferTooSmall;
            out[written] = byte;
            written += 1;
        } else {
            if (out.len - written < 3) return error.BufferTooSmall;
            out[written] = '%';
            out[written + 1] = hexDigit(byte >> 4);
            out[written + 2] = hexDigit(byte & 0x0f);
            written += 3;
        }
    }
    return out[0..written];
}

pub fn encodeStatusMessageAlloc(
    allocator: std.mem.Allocator,
    message: []const u8,
) Error![]u8 {
    const capacity = std.math.mul(usize, message.len, 3) catch
        return error.MessageTooLarge;
    const out = try allocator.alloc(u8, capacity);
    errdefer allocator.free(out);
    const encoded = try encodeStatusMessageInto(out, message);
    return if (allocator.resize(out, encoded.len))
        out[0..encoded.len]
    else blk: {
        const exact = try allocator.dupe(u8, encoded);
        allocator.free(out);
        break :blk exact;
    };
}

pub fn decodeStatusMessageAlloc(
    allocator: std.mem.Allocator,
    encoded: []const u8,
) Error![]u8 {
    const out = try allocator.alloc(u8, encoded.len);
    errdefer allocator.free(out);
    var read_index: usize = 0;
    var written: usize = 0;
    while (read_index < encoded.len) {
        if (encoded[read_index] == '%' and
            encoded.len - read_index >= 3)
        {
            const high = hexValue(encoded[read_index + 1]);
            const low = hexValue(encoded[read_index + 2]);
            if (high != null and low != null) {
                out[written] = (high.? << 4) | low.?;
                written += 1;
                read_index += 3;
                continue;
            }
        }
        // The gRPC protocol requires malformed percent sequences to remain
        // observable instead of failing the whole call.
        out[written] = encoded[read_index];
        written += 1;
        read_index += 1;
    }
    return if (allocator.resize(out, written))
        out[0..written]
    else blk: {
        const exact = try allocator.dupe(u8, out[0..written]);
        allocator.free(out);
        break :blk exact;
    };
}

fn statusMessageByteUnescaped(byte: u8) bool {
    return (byte >= 0x20 and byte <= 0x24) or
        (byte >= 0x26 and byte <= 0x7e);
}

fn hexDigit(value: u8) u8 {
    std.debug.assert(value < 16);
    return if (value < 10) '0' + value else 'A' + value - 10;
}

fn hexValue(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}
