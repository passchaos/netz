//! Bounded protobuf fixture codec for the upstream gRPC interoperability gate.
//!
//! This is intentionally not a general protobuf implementation.  The field
//! numbers below are pinned to gRPC Core commit
//! `03d65cc67c450ccbb58a8a45627c4da83a886ccd`, specifically
//! `src/proto/grpc/testing/messages.proto`.  Keeping the tiny fixture local
//! avoids adding generated bindings to netz's transport-only gRPC package.
//! Unsupported fields are rejected so an upstream schema change cannot turn a
//! passing gate into a weaker, partially parsed test.

const std = @import("std");

/// The canonical interop cases stay below this value (the largest is 314159).
/// Apply the bound before allocation and again while decoding peer input.
pub const max_payload_size: usize = 512 * 1024;
pub const max_interval_us: u32 = 5 * 1000 * 1000;

pub const Error = std.mem.Allocator.Error || error{
    DuplicateField,
    InvalidArgument,
    InvalidFieldNumber,
    InvalidPayloadType,
    MalformedVarint,
    MessageTooLarge,
    MissingPayload,
    NonCanonicalVarint,
    NonZeroPayload,
    TruncatedMessage,
    UnexpectedPayloadSize,
    UnsupportedField,
    UnsupportedWireType,
};

pub const RequestOptions = struct {
    /// Presence adds one `ResponseParameters` entry (request field 2).
    response_size: ?u32,
    /// `ResponseParameters.interval_us` (field 2); zero is omitted.
    interval_us: u32 = 0,
    /// Number of zero bytes in `Payload.body` (payload field 2).
    request_body_size: usize,
};

pub const SimpleRequestOptions = struct {
    response_size: u32,
    request_body_size: usize,
};

/// Decode the exact `SimpleRequest` subset emitted by the canonical unary
/// custom-metadata case.
pub fn decodeSimpleRequest(input: []const u8) Error!SimpleRequestOptions {
    if (input.len > max_payload_size + 64) return error.MessageTooLarge;

    var reader = Reader{ .input = input };
    var response_type_seen = false;
    var response_size_seen = false;
    var payload_seen = false;
    var result = SimpleRequestOptions{
        .response_size = 0,
        .request_body_size = 0,
    };
    while (!reader.finished()) {
        const tag = try reader.readTag();
        switch (tag.field_number) {
            1 => {
                if (tag.wire_type != .varint) {
                    return error.UnsupportedWireType;
                }
                if (response_type_seen) return error.DuplicateField;
                response_type_seen = true;
                if (try reader.readVarint() != 0) {
                    return error.InvalidPayloadType;
                }
            },
            2 => {
                if (tag.wire_type != .varint) {
                    return error.UnsupportedWireType;
                }
                if (response_size_seen) return error.DuplicateField;
                response_size_seen = true;
                const size = try reader.readVarint();
                if (size > max_payload_size) return error.MessageTooLarge;
                result.response_size = @intCast(size);
            },
            3 => {
                if (tag.wire_type != .length_delimited) {
                    return error.UnsupportedWireType;
                }
                if (payload_seen) return error.DuplicateField;
                payload_seen = true;
                const payload = try reader.readBytes(max_payload_size + 16);
                result.request_body_size = try decodeZeroPayload(payload);
            },
            else => return error.UnsupportedField,
        }
    }
    if (!response_size_seen or !payload_seen) return error.MissingPayload;
    return result;
}

/// `SimpleResponse` and `StreamingOutputCallResponse` share the exact Payload
/// field used by this fixture.
pub fn encodeSimpleResponseAlloc(
    allocator: std.mem.Allocator,
    body_size: usize,
) Error![]u8 {
    return encodeStreamingOutputCallResponseAlloc(allocator, body_size);
}

/// Decode one canonical `StreamingInputCallRequest` and return the zero-filled
/// payload body size.
pub fn decodeStreamingInputCallRequest(input: []const u8) Error!usize {
    if (input.len > max_payload_size + 16) return error.MessageTooLarge;
    var reader = Reader{ .input = input };
    var payload_seen = false;
    var body_size: usize = 0;
    while (!reader.finished()) {
        const tag = try reader.readTag();
        switch (tag.field_number) {
            1 => {
                if (tag.wire_type != .length_delimited) {
                    return error.UnsupportedWireType;
                }
                if (payload_seen) return error.DuplicateField;
                payload_seen = true;
                body_size = try decodeZeroPayload(
                    try reader.readBytes(max_payload_size + 16),
                );
            },
            else => return error.UnsupportedField,
        }
    }
    if (!payload_seen) return error.MissingPayload;
    return body_size;
}

pub fn encodeStreamingInputCallResponseAlloc(
    allocator: std.mem.Allocator,
    aggregated_payload_size: usize,
) Error![]u8 {
    if (aggregated_payload_size > std.math.maxInt(i32)) {
        return error.MessageTooLarge;
    }
    const encoded = try allocator.alloc(
        u8,
        1 + varintLen(aggregated_payload_size),
    );
    var cursor: usize = 0;
    encoded[cursor] = fieldKey(1, .varint);
    cursor += 1;
    writeVarint(encoded, &cursor, aggregated_payload_size);
    std.debug.assert(cursor == encoded.len);
    return encoded;
}

/// Decode the repeated response sizes from the canonical server-streaming
/// request into caller-owned bounded storage.
pub fn decodeStreamingOutputCallResponseSizes(
    input: []const u8,
    out: []u32,
) Error![]const u32 {
    if (input.len > max_payload_size + 64) return error.MessageTooLarge;
    var reader = Reader{ .input = input };
    var response_type_seen = false;
    var count: usize = 0;
    while (!reader.finished()) {
        const tag = try reader.readTag();
        switch (tag.field_number) {
            1 => {
                if (tag.wire_type != .varint) {
                    return error.UnsupportedWireType;
                }
                if (response_type_seen) return error.DuplicateField;
                response_type_seen = true;
                if (try reader.readVarint() != 0) {
                    return error.InvalidPayloadType;
                }
            },
            2 => {
                if (tag.wire_type != .length_delimited) {
                    return error.UnsupportedWireType;
                }
                if (count == out.len) return error.MessageTooLarge;
                const parameters = try decodeResponseParameters(
                    try reader.readBytes(32),
                );
                if (parameters.interval_us != 0) {
                    return error.InvalidArgument;
                }
                out[count] = parameters.size;
                count += 1;
            },
            else => return error.UnsupportedField,
        }
    }
    if (count == 0) return error.MissingPayload;
    return out[0..count];
}

/// Decode the exact `StreamingOutputCallRequest` subset emitted by the
/// canonical FullDuplexCall interoperability cases.
///
/// A response-parameters field is represented by a non-null `response_size`,
/// including when the embedded proto3 size has its default value of zero.
pub fn decodeStreamingOutputCallRequest(input: []const u8) Error!RequestOptions {
    if (input.len > max_payload_size + 64) return error.MessageTooLarge;

    var reader = Reader{ .input = input };
    var response_type_seen = false;
    var parameters_seen = false;
    var payload_seen = false;
    var result = RequestOptions{
        .response_size = null,
        .request_body_size = 0,
    };

    while (!reader.finished()) {
        const tag = try reader.readTag();
        switch (tag.field_number) {
            1 => {
                if (tag.wire_type != .varint) return error.UnsupportedWireType;
                if (response_type_seen) return error.DuplicateField;
                response_type_seen = true;
                if (try reader.readVarint() != 0) {
                    return error.InvalidPayloadType;
                }
            },
            2 => {
                if (tag.wire_type != .length_delimited) {
                    return error.UnsupportedWireType;
                }
                // The fixture deliberately supports one response per request,
                // matching what the C++ FullDuplexCall implementation reads.
                if (parameters_seen) return error.DuplicateField;
                parameters_seen = true;
                const parameters = try reader.readBytes(32);
                const decoded = try decodeResponseParameters(parameters);
                result.response_size = decoded.size;
                result.interval_us = decoded.interval_us;
            },
            3 => {
                if (tag.wire_type != .length_delimited) {
                    return error.UnsupportedWireType;
                }
                if (payload_seen) return error.DuplicateField;
                payload_seen = true;
                const payload = try reader.readBytes(max_payload_size + 16);
                result.request_body_size = try decodeZeroPayload(payload);
            },
            else => return error.UnsupportedField,
        }
    }
    if (!payload_seen) return error.MissingPayload;
    return result;
}

/// Encode a canonical `StreamingOutputCallResponse` containing a zero-filled
/// `Payload.body`. The default COMPRESSABLE type is omitted.
pub fn encodeStreamingOutputCallResponseAlloc(
    allocator: std.mem.Allocator,
    body_size: usize,
) Error![]u8 {
    if (body_size > max_payload_size) return error.MessageTooLarge;

    const payload_len = if (body_size == 0)
        0
    else
        try lengthDelimitedFieldLen(body_size);
    const encoded_len = try lengthDelimitedFieldLen(payload_len);
    const encoded = try allocator.alloc(u8, encoded_len);
    errdefer allocator.free(encoded);

    var cursor: usize = 0;
    encoded[cursor] = fieldKey(1, .length_delimited);
    cursor += 1;
    writeVarint(encoded, &cursor, payload_len);
    if (body_size != 0) {
        encoded[cursor] = fieldKey(2, .length_delimited);
        cursor += 1;
        writeVarint(encoded, &cursor, body_size);
        @memset(encoded[cursor..][0..body_size], 0);
        cursor += body_size;
    }
    std.debug.assert(cursor == encoded.len);
    return encoded;
}

/// Encode the exact `StreamingOutputCallRequest` subset used by the gate.
///
/// `response_type` and `Payload.type` are proto3's zero-valued COMPRESSABLE
/// enum and are deliberately omitted.  The C++ interop server reads only the
/// first response-parameters entry, so this encoder emits at most one.
pub fn encodeStreamingOutputCallRequestAlloc(
    allocator: std.mem.Allocator,
    options: RequestOptions,
) Error![]u8 {
    if (options.request_body_size > max_payload_size) {
        return error.MessageTooLarge;
    }
    if (options.interval_us > max_interval_us) return error.InvalidArgument;
    if (options.response_size) |size| {
        if (size > max_payload_size) return error.MessageTooLarge;
    } else if (options.interval_us != 0) {
        return error.InvalidArgument;
    }

    const parameters_len = if (options.response_size) |size|
        (if (size == 0) 0 else 1 + varintLen(size)) +
            (if (options.interval_us == 0) 0 else 1 + varintLen(options.interval_us))
    else
        0;
    const parameters_field_len = if (options.response_size != null)
        try lengthDelimitedFieldLen(parameters_len)
    else
        0;

    const payload_len = if (options.request_body_size == 0)
        0
    else
        try lengthDelimitedFieldLen(options.request_body_size);
    const payload_field_len = try lengthDelimitedFieldLen(payload_len);
    const encoded_len = std.math.add(
        usize,
        parameters_field_len,
        payload_field_len,
    ) catch return error.MessageTooLarge;

    const encoded = try allocator.alloc(u8, encoded_len);
    errdefer allocator.free(encoded);
    var cursor: usize = 0;

    if (options.response_size) |size| {
        // StreamingOutputCallRequest.response_parameters = field 2.
        encoded[cursor] = fieldKey(2, .length_delimited);
        cursor += 1;
        writeVarint(encoded, &cursor, parameters_len);
        if (size != 0) {
            // ResponseParameters.size = field 1.
            encoded[cursor] = fieldKey(1, .varint);
            cursor += 1;
            writeVarint(encoded, &cursor, size);
        }
        if (options.interval_us != 0) {
            // ResponseParameters.interval_us = field 2.
            encoded[cursor] = fieldKey(2, .varint);
            cursor += 1;
            writeVarint(encoded, &cursor, options.interval_us);
        }
    }

    // StreamingOutputCallRequest.payload = field 3.
    encoded[cursor] = fieldKey(3, .length_delimited);
    cursor += 1;
    writeVarint(encoded, &cursor, payload_len);
    if (options.request_body_size != 0) {
        // Payload.body = field 2.
        encoded[cursor] = fieldKey(2, .length_delimited);
        cursor += 1;
        writeVarint(encoded, &cursor, options.request_body_size);
        @memset(encoded[cursor..][0..options.request_body_size], 0);
        cursor += options.request_body_size;
    }
    std.debug.assert(cursor == encoded.len);
    return encoded;
}

/// Strictly validate one `StreamingOutputCallResponse`.
///
/// The response must contain exactly one `Payload` (outer field 1), whose
/// optional type is COMPRESSABLE (zero) and whose body is exactly the expected
/// number of zero bytes.  The size and complete message are bounded before any
/// nested parsing.
pub fn validateStreamingOutputCallResponse(
    input: []const u8,
    expected_body_size: usize,
) Error!void {
    if (expected_body_size > max_payload_size) return error.MessageTooLarge;
    const maximum_encoded = std.math.add(
        usize,
        max_payload_size,
        32,
    ) catch unreachable;
    if (input.len > maximum_encoded) return error.MessageTooLarge;

    var reader = Reader{ .input = input };
    var payload_seen = false;
    while (!reader.finished()) {
        const tag = try reader.readTag();
        switch (tag.field_number) {
            1 => {
                if (tag.wire_type != .length_delimited) {
                    return error.UnsupportedWireType;
                }
                if (payload_seen) return error.DuplicateField;
                payload_seen = true;
                const payload = try reader.readBytes(max_payload_size + 16);
                try validatePayload(payload, expected_body_size);
            },
            else => return error.UnsupportedField,
        }
    }
    if (!payload_seen) return error.MissingPayload;
}

const WireType = enum(u3) {
    varint = 0,
    length_delimited = 2,
};

const Tag = struct {
    field_number: u29,
    wire_type: WireType,
};

const Reader = struct {
    input: []const u8,
    cursor: usize = 0,

    fn finished(self: Reader) bool {
        return self.cursor == self.input.len;
    }

    fn readTag(self: *Reader) Error!Tag {
        const raw = try self.readVarint();
        const field_number_raw = raw >> 3;
        if (field_number_raw == 0 or field_number_raw > 0x1fff_ffff) {
            return error.InvalidFieldNumber;
        }
        const wire_raw: u3 = @truncate(raw & 0x7);
        const wire_type = switch (wire_raw) {
            0 => WireType.varint,
            2 => WireType.length_delimited,
            else => return error.UnsupportedWireType,
        };
        return .{
            .field_number = @intCast(field_number_raw),
            .wire_type = wire_type,
        };
    }

    fn readBytes(self: *Reader, limit: usize) Error![]const u8 {
        const length_u64 = try self.readVarint();
        if (length_u64 > limit or length_u64 > std.math.maxInt(usize)) {
            return error.MessageTooLarge;
        }
        const length: usize = @intCast(length_u64);
        const end = std.math.add(usize, self.cursor, length) catch
            return error.MessageTooLarge;
        if (end > self.input.len) return error.TruncatedMessage;
        const result = self.input[self.cursor..end];
        self.cursor = end;
        return result;
    }

    fn readVarint(self: *Reader) Error!u64 {
        const start = self.cursor;
        var value: u64 = 0;
        var shift: u6 = 0;
        for (0..10) |index| {
            if (self.cursor == self.input.len) return error.TruncatedMessage;
            const byte = self.input[self.cursor];
            self.cursor += 1;
            if (index == 9 and byte > 1) return error.MalformedVarint;
            value |= @as(u64, byte & 0x7f) << shift;
            if ((byte & 0x80) == 0) {
                if (self.cursor - start != varintLen(value)) {
                    return error.NonCanonicalVarint;
                }
                return value;
            }
            if (index != 9) shift += 7;
        }
        return error.MalformedVarint;
    }
};

const DecodedResponseParameters = struct {
    size: u32 = 0,
    interval_us: u32 = 0,
};

fn decodeResponseParameters(input: []const u8) Error!DecodedResponseParameters {
    var reader = Reader{ .input = input };
    var size_seen = false;
    var interval_seen = false;
    var result = DecodedResponseParameters{};
    while (!reader.finished()) {
        const tag = try reader.readTag();
        switch (tag.field_number) {
            1 => {
                if (tag.wire_type != .varint) return error.UnsupportedWireType;
                if (size_seen) return error.DuplicateField;
                size_seen = true;
                const size = try reader.readVarint();
                // The schema type is int32. Negative int32 values use a
                // ten-byte sign-extended varint and are invalid fixture sizes.
                if (size > std.math.maxInt(i32)) return error.InvalidArgument;
                if (size > max_payload_size) return error.MessageTooLarge;
                result.size = @intCast(size);
            },
            2 => {
                if (tag.wire_type != .varint) return error.UnsupportedWireType;
                if (interval_seen) return error.DuplicateField;
                interval_seen = true;
                const interval = try reader.readVarint();
                if (interval > std.math.maxInt(i32) or
                    interval > max_interval_us)
                {
                    return error.InvalidArgument;
                }
                result.interval_us = @intCast(interval);
            },
            else => return error.UnsupportedField,
        }
    }
    return result;
}

fn decodeZeroPayload(input: []const u8) Error!usize {
    var reader = Reader{ .input = input };
    var type_seen = false;
    var body_seen = false;
    var body: []const u8 = &.{};
    while (!reader.finished()) {
        const tag = try reader.readTag();
        switch (tag.field_number) {
            1 => {
                if (tag.wire_type != .varint) {
                    return error.UnsupportedWireType;
                }
                if (type_seen) return error.DuplicateField;
                type_seen = true;
                if (try reader.readVarint() != 0) {
                    return error.InvalidPayloadType;
                }
            },
            2 => {
                if (tag.wire_type != .length_delimited) {
                    return error.UnsupportedWireType;
                }
                if (body_seen) return error.DuplicateField;
                body_seen = true;
                body = try reader.readBytes(max_payload_size);
            },
            else => return error.UnsupportedField,
        }
    }
    for (body) |byte| {
        if (byte != 0) return error.NonZeroPayload;
    }
    return body.len;
}

fn validatePayload(input: []const u8, expected_body_size: usize) Error!void {
    const body_size = try decodeZeroPayload(input);
    // Proto3 omits an empty bytes field, so a missing body is the canonical
    // encoding of the expected zero-length payload.
    if (body_size != expected_body_size) return error.UnexpectedPayloadSize;
}

fn lengthDelimitedFieldLen(payload_len: usize) Error!usize {
    return std.math.add(
        usize,
        1 + varintLen(payload_len),
        payload_len,
    ) catch error.MessageTooLarge;
}

fn fieldKey(field_number: u5, wire_type: WireType) u8 {
    return (@as(u8, field_number) << 3) | @intFromEnum(wire_type);
}

fn varintLen(value: anytype) usize {
    var remaining: u64 = @intCast(value);
    var length: usize = 1;
    while (remaining >= 0x80) : (length += 1) remaining >>= 7;
    return length;
}

fn writeVarint(output: []u8, cursor: *usize, value: anytype) void {
    var remaining: u64 = @intCast(value);
    while (remaining >= 0x80) {
        output[cursor.*] = @as(u8, @truncate(remaining)) | 0x80;
        cursor.* += 1;
        remaining >>= 7;
    }
    output[cursor.*] = @intCast(remaining);
    cursor.* += 1;
}

test "encodes canonical streaming request subset" {
    const encoded = try encodeStreamingOutputCallRequestAlloc(
        std.testing.allocator,
        .{ .response_size = 5, .request_body_size = 3 },
    );
    defer std.testing.allocator.free(encoded);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x12, 0x02, 0x08, 0x05, 0x1a, 0x05, 0x12, 0x03, 0, 0, 0 },
        encoded,
    );

    const delayed = try encodeStreamingOutputCallRequestAlloc(
        std.testing.allocator,
        .{
            .response_size = 5,
            .interval_us = 300,
            .request_body_size = 0,
        },
    );
    defer std.testing.allocator.free(delayed);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x12, 0x05, 0x08, 0x05, 0x10, 0xac, 0x02, 0x1a, 0x00 },
        delayed,
    );
}

test "decodes canonical unary custom metadata request" {
    const request = try decodeSimpleRequest(
        &.{ 0x10, 0x05, 0x1a, 0x05, 0x12, 0x03, 0, 0, 0 },
    );
    try std.testing.expectEqual(@as(u32, 5), request.response_size);
    try std.testing.expectEqual(@as(usize, 3), request.request_body_size);
    try std.testing.expectError(
        error.MissingPayload,
        decodeSimpleRequest(&.{ 0x10, 0x05 }),
    );
    try std.testing.expectError(
        error.UnsupportedField,
        decodeSimpleRequest(&.{ 0x20, 0x01, 0x10, 0x05, 0x1a, 0x00 }),
    );
}

test "decodes client and server streaming fixture messages" {
    try std.testing.expectEqual(
        @as(usize, 3),
        try decodeStreamingInputCallRequest(
            &.{ 0x0a, 0x05, 0x12, 0x03, 0, 0, 0 },
        ),
    );
    const aggregate = try encodeStreamingInputCallResponseAlloc(
        std.testing.allocator,
        74_922,
    );
    defer std.testing.allocator.free(aggregate);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x08, 0xaa, 0xc9, 0x04 },
        aggregate,
    );

    var sizes_storage: [4]u32 = undefined;
    const sizes = try decodeStreamingOutputCallResponseSizes(
        &.{
            0x12, 0x03, 0x08, 0xb7, 0xf5, 0x01,
            0x12, 0x02, 0x08, 0x09,
        },
        &sizes_storage,
    );
    try std.testing.expectEqualSlices(u32, &.{ 31_415, 9 }, sizes);
}

test "encodes sleeping request without response parameters" {
    const encoded = try encodeStreamingOutputCallRequestAlloc(
        std.testing.allocator,
        .{ .response_size = null, .request_body_size = 2 },
    );
    defer std.testing.allocator.free(encoded);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x1a, 0x04, 0x12, 0x02, 0, 0 },
        encoded,
    );
    try std.testing.expectError(
        error.InvalidArgument,
        encodeStreamingOutputCallRequestAlloc(
            std.testing.allocator,
            .{
                .response_size = null,
                .interval_us = 1,
                .request_body_size = 0,
            },
        ),
    );
}

test "decodes canonical streaming request subset" {
    const ping_pong = try decodeStreamingOutputCallRequest(
        &.{ 0x12, 0x05, 0x08, 0x05, 0x10, 0xac, 0x02, 0x1a, 0x05, 0x12, 0x03, 0, 0, 0 },
    );
    try std.testing.expectEqual(@as(?u32, 5), ping_pong.response_size);
    try std.testing.expectEqual(@as(u32, 300), ping_pong.interval_us);
    try std.testing.expectEqual(@as(usize, 3), ping_pong.request_body_size);

    const sleeping = try decodeStreamingOutputCallRequest(
        &.{ 0x1a, 0x04, 0x12, 0x02, 0, 0 },
    );
    try std.testing.expectEqual(@as(?u32, null), sleeping.response_size);
    try std.testing.expectEqual(@as(u32, 0), sleeping.interval_us);
    try std.testing.expectEqual(@as(usize, 2), sleeping.request_body_size);

    // Explicit proto3 defaults remain valid and preserve the presence of the
    // response-parameters message, which distinguishes size zero from none.
    const defaults = try decodeStreamingOutputCallRequest(
        &.{ 0x08, 0x00, 0x12, 0x04, 0x08, 0x00, 0x10, 0x00, 0x1a, 0x02, 0x08, 0x00 },
    );
    try std.testing.expectEqual(@as(?u32, 0), defaults.response_size);
    try std.testing.expectEqual(@as(usize, 0), defaults.request_body_size);
}

test "request decoding rejects malformed and unsupported fields" {
    try std.testing.expectError(
        error.MissingPayload,
        decodeStreamingOutputCallRequest(&.{}),
    );
    try std.testing.expectError(
        error.TruncatedMessage,
        decodeStreamingOutputCallRequest(&.{ 0x1a, 0x02, 0x12 }),
    );
    try std.testing.expectError(
        error.DuplicateField,
        decodeStreamingOutputCallRequest(&.{ 0x1a, 0x00, 0x1a, 0x00 }),
    );
    try std.testing.expectError(
        error.DuplicateField,
        decodeStreamingOutputCallRequest(&.{ 0x12, 0x00, 0x12, 0x00, 0x1a, 0x00 }),
    );
    try std.testing.expectError(
        error.UnsupportedField,
        decodeStreamingOutputCallRequest(&.{ 0x22, 0x00, 0x1a, 0x00 }),
    );
    try std.testing.expectError(
        error.UnsupportedField,
        decodeStreamingOutputCallRequest(&.{ 0x12, 0x02, 0x18, 0x00, 0x1a, 0x00 }),
    );
    try std.testing.expectError(
        error.InvalidPayloadType,
        decodeStreamingOutputCallRequest(&.{ 0x08, 0x01, 0x1a, 0x00 }),
    );
    try std.testing.expectError(
        error.NonZeroPayload,
        decodeStreamingOutputCallRequest(&.{ 0x1a, 0x03, 0x12, 0x01, 0x01 }),
    );
}

test "request decoding enforces response parameter bounds" {
    try std.testing.expectError(
        error.MessageTooLarge,
        decodeStreamingOutputCallRequest(
            &.{ 0x12, 0x04, 0x08, 0x81, 0x80, 0x20, 0x1a, 0x00 },
        ),
    );
    try std.testing.expectError(
        error.InvalidArgument,
        decodeStreamingOutputCallRequest(
            &.{ 0x12, 0x05, 0x10, 0xc1, 0x96, 0xb1, 0x02, 0x1a, 0x00 },
        ),
    );
}

test "encodes canonical streaming response" {
    const encoded = try encodeStreamingOutputCallResponseAlloc(
        std.testing.allocator,
        3,
    );
    defer std.testing.allocator.free(encoded);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x0a, 0x05, 0x12, 0x03, 0, 0, 0 },
        encoded,
    );
    try validateStreamingOutputCallResponse(encoded, 3);

    const empty = try encodeStreamingOutputCallResponseAlloc(
        std.testing.allocator,
        0,
    );
    defer std.testing.allocator.free(empty);
    try std.testing.expectEqualSlices(u8, &.{ 0x0a, 0x00 }, empty);
    try std.testing.expectError(
        error.MessageTooLarge,
        encodeStreamingOutputCallResponseAlloc(
            std.testing.allocator,
            max_payload_size + 1,
        ),
    );
}

test "validates canonical streaming response and explicit default type" {
    try validateStreamingOutputCallResponse(
        &.{ 0x0a, 0x05, 0x12, 0x03, 0, 0, 0 },
        3,
    );
    try validateStreamingOutputCallResponse(
        &.{ 0x0a, 0x07, 0x08, 0x00, 0x12, 0x03, 0, 0, 0 },
        3,
    );
    try validateStreamingOutputCallResponse(&.{ 0x0a, 0x00 }, 0);
}

test "response validation rejects malformed or unsupported protobuf" {
    try std.testing.expectError(
        error.TruncatedMessage,
        validateStreamingOutputCallResponse(&.{ 0x0a, 0x03, 0x12 }, 1),
    );
    try std.testing.expectError(
        error.NonCanonicalVarint,
        validateStreamingOutputCallResponse(
            &.{ 0x0a, 0x06, 0x12, 0x83, 0x00, 0, 0, 0 },
            3,
        ),
    );
    try std.testing.expectError(
        error.UnsupportedWireType,
        validateStreamingOutputCallResponse(&.{ 0x08, 0x00 }, 0),
    );
    try std.testing.expectError(
        error.UnsupportedField,
        validateStreamingOutputCallResponse(&.{ 0x12, 0x00 }, 0),
    );
    try std.testing.expectError(
        error.DuplicateField,
        validateStreamingOutputCallResponse(
            &.{ 0x0a, 0x00, 0x0a, 0x00 },
            0,
        ),
    );
    try std.testing.expectError(
        error.InvalidPayloadType,
        validateStreamingOutputCallResponse(
            &.{ 0x0a, 0x02, 0x08, 0x01 },
            0,
        ),
    );
    try std.testing.expectError(
        error.NonZeroPayload,
        validateStreamingOutputCallResponse(
            &.{ 0x0a, 0x04, 0x12, 0x02, 0, 1 },
            2,
        ),
    );
    try std.testing.expectError(
        error.UnexpectedPayloadSize,
        validateStreamingOutputCallResponse(
            &.{ 0x0a, 0x04, 0x12, 0x02, 0, 0 },
            3,
        ),
    );
}

test "request and response payload limits are enforced" {
    try std.testing.expectError(
        error.MessageTooLarge,
        encodeStreamingOutputCallRequestAlloc(
            std.testing.allocator,
            .{
                .response_size = 1,
                .request_body_size = max_payload_size + 1,
            },
        ),
    );
    try std.testing.expectError(
        error.MessageTooLarge,
        validateStreamingOutputCallResponse(&.{}, max_payload_size + 1),
    );
}
