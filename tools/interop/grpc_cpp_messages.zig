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
pub const max_status_message_size: usize = 4 * 1024;
pub const max_server_id_size: usize = 256;
pub const max_peer_socket_address_size: usize = 256;

pub const Error = std.mem.Allocator.Error || error{
    DuplicateField,
    InvalidArgument,
    InvalidFieldNumber,
    InvalidPayloadType,
    InvalidStatus,
    InvalidUtf8,
    MalformedVarint,
    MessageTooLarge,
    MissingPayload,
    MissingStatus,
    NonCanonicalVarint,
    NonZeroPayload,
    TruncatedMessage,
    UnexpectedPayloadSize,
    UnsupportedField,
    UnsupportedWireType,
};

pub const EchoStatus = struct {
    code: u8,
    message: []const u8,
};

pub const RequestOptions = struct {
    /// Presence adds one `ResponseParameters` entry (request field 2).
    response_size: ?u32,
    /// `ResponseParameters.interval_us` (field 2); zero is omitted.
    interval_us: u32 = 0,
    /// Presence maps to `ResponseParameters.compressed` (field 3).
    response_compressed: ?bool = null,
    /// Number of zero bytes in `Payload.body` (payload field 2).
    request_body_size: usize,
};

pub const ResponseParameter = struct {
    size: u32 = 0,
    interval_us: u32 = 0,
    compressed: ?bool = null,
};

pub const StreamingInputRequest = struct {
    request_body_size: usize,
    expect_compressed: ?bool = null,
};

pub const SimpleRequestOptions = struct {
    response_size: u32,
    request_body_size: usize,
    /// Presence maps to `SimpleRequest.response_compressed` (field 6).
    response_compressed: ?bool = null,
    /// Presence maps to `SimpleRequest.expect_compressed` (field 8).
    expect_compressed: ?bool = null,
};

/// Encode the exact response-status-only request shared by `SimpleRequest`
/// and `StreamingOutputCallRequest`. Both schemas assign `EchoStatus` field 7.
pub fn encodeStatusRequestAlloc(
    allocator: std.mem.Allocator,
    status: EchoStatus,
) Error![]u8 {
    try validateEchoStatus(status);
    const status_len = 1 + varintLen(status.code) +
        try lengthDelimitedFieldLen(status.message.len);
    const encoded = try allocator.alloc(
        u8,
        try lengthDelimitedFieldLen(status_len),
    );
    errdefer allocator.free(encoded);
    var cursor: usize = 0;
    encoded[cursor] = fieldKey(7, .length_delimited);
    cursor += 1;
    writeVarint(encoded, &cursor, status_len);
    encoded[cursor] = fieldKey(1, .varint);
    cursor += 1;
    writeVarint(encoded, &cursor, status.code);
    encoded[cursor] = fieldKey(2, .length_delimited);
    cursor += 1;
    writeVarint(encoded, &cursor, status.message.len);
    @memcpy(encoded[cursor..][0..status.message.len], status.message);
    cursor += status.message.len;
    std.debug.assert(cursor == encoded.len);
    return encoded;
}

/// Decode a response-status-only interop request. The returned message borrows
/// from `input` and is valid for the same lifetime.
pub fn decodeStatusRequest(input: []const u8) Error!EchoStatus {
    if (input.len > max_status_message_size + 32) return error.MessageTooLarge;
    var reader = Reader{ .input = input };
    var status_seen = false;
    var result: EchoStatus = undefined;
    while (!reader.finished()) {
        const tag = try reader.readTag();
        if (tag.field_number != 7) return error.UnsupportedField;
        if (tag.wire_type != .length_delimited) {
            return error.UnsupportedWireType;
        }
        if (status_seen) return error.DuplicateField;
        status_seen = true;
        result = try decodeEchoStatus(
            try reader.readBytes(max_status_message_size + 16),
        );
    }
    if (!status_seen) return error.MissingStatus;
    return result;
}

/// Encode the strict `SimpleRequest` subset used by unary compression and
/// metadata interoperability cases. Wrapper booleans preserve presence even
/// when their contained proto3 value is false.
pub fn encodeSimpleRequestAlloc(
    allocator: std.mem.Allocator,
    options: SimpleRequestOptions,
) Error![]u8 {
    if (options.response_size > max_payload_size or
        options.request_body_size > max_payload_size)
    {
        return error.MessageTooLarge;
    }
    const payload_len = if (options.request_body_size == 0)
        0
    else
        try lengthDelimitedFieldLen(options.request_body_size);
    const encoded_len = std.math.add(
        usize,
        1 + varintLen(options.response_size) +
            try lengthDelimitedFieldLen(payload_len),
        boolWrapperFieldLen(options.response_compressed) +
            boolWrapperFieldLen(options.expect_compressed),
    ) catch return error.MessageTooLarge;
    const encoded = try allocator.alloc(u8, encoded_len);
    errdefer allocator.free(encoded);
    var cursor: usize = 0;

    encoded[cursor] = fieldKey(2, .varint);
    cursor += 1;
    writeVarint(encoded, &cursor, options.response_size);
    encoded[cursor] = fieldKey(3, .length_delimited);
    cursor += 1;
    writeVarint(encoded, &cursor, payload_len);
    if (options.request_body_size != 0) {
        encoded[cursor] = fieldKey(2, .length_delimited);
        cursor += 1;
        writeVarint(encoded, &cursor, options.request_body_size);
        @memset(encoded[cursor..][0..options.request_body_size], 0);
        cursor += options.request_body_size;
    }
    writeBoolWrapperField(
        encoded,
        &cursor,
        6,
        options.response_compressed,
    );
    writeBoolWrapperField(
        encoded,
        &cursor,
        8,
        options.expect_compressed,
    );
    std.debug.assert(cursor == encoded.len);
    return encoded;
}

/// Decode the exact `SimpleRequest` subset emitted by the canonical unary
/// custom-metadata case.
pub fn decodeSimpleRequest(input: []const u8) Error!SimpleRequestOptions {
    if (input.len > max_payload_size + 64) return error.MessageTooLarge;

    var reader = Reader{ .input = input };
    var response_type_seen = false;
    var response_size_seen = false;
    var payload_seen = false;
    var response_compressed_seen = false;
    var expect_compressed_seen = false;
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
            6 => {
                if (tag.wire_type != .length_delimited) {
                    return error.UnsupportedWireType;
                }
                if (response_compressed_seen) return error.DuplicateField;
                response_compressed_seen = true;
                result.response_compressed = try decodeBoolValue(
                    try reader.readBytes(2),
                );
            },
            8 => {
                if (tag.wire_type != .length_delimited) {
                    return error.UnsupportedWireType;
                }
                if (expect_compressed_seen) return error.DuplicateField;
                expect_compressed_seen = true;
                result.expect_compressed = try decodeBoolValue(
                    try reader.readBytes(2),
                );
            },
            else => return error.UnsupportedField,
        }
    }
    if (!response_size_seen or !payload_seen) return error.MissingPayload;
    return result;
}

/// Decode the canonical pick-first request. The upstream client sends only
/// `SimpleRequest.fill_server_id = true`; accepting other fields would weaken
/// the fixture's proof that this exact interoperability case ran.
pub fn decodePickFirstRequest(input: []const u8) Error!void {
    var reader = Reader{ .input = input };
    var fill_server_id_seen = false;
    while (!reader.finished()) {
        const tag = try reader.readTag();
        if (tag.field_number != 9) return error.UnsupportedField;
        if (tag.wire_type != .varint) return error.UnsupportedWireType;
        if (fill_server_id_seen) return error.DuplicateField;
        fill_server_id_seen = true;
        if (try reader.readVarint() != 1) return error.InvalidArgument;
    }
    if (!fill_server_id_seen) return error.InvalidArgument;
}

/// Encode a payload-free `SimpleResponse` carrying only field 4 `server_id`.
pub fn encodeServerIdResponseAlloc(
    allocator: std.mem.Allocator,
    server_id: []const u8,
) Error![]u8 {
    if (server_id.len == 0 or server_id.len > max_server_id_size) {
        return error.InvalidArgument;
    }
    if (!std.unicode.utf8ValidateSlice(server_id)) return error.InvalidUtf8;
    const encoded = try allocator.alloc(
        u8,
        try lengthDelimitedFieldLen(server_id.len),
    );
    errdefer allocator.free(encoded);
    var cursor: usize = 0;
    encoded[cursor] = fieldKey(4, .length_delimited);
    cursor += 1;
    writeVarint(encoded, &cursor, server_id.len);
    @memcpy(encoded[cursor..][0..server_id.len], server_id);
    cursor += server_id.len;
    std.debug.assert(cursor == encoded.len);
    return encoded;
}

/// `SimpleResponse` and `StreamingOutputCallResponse` share the exact Payload
/// field used by this fixture.
pub fn encodeSimpleResponseAlloc(
    allocator: std.mem.Allocator,
    body_size: usize,
) Error![]u8 {
    return encodeStreamingOutputCallResponseAlloc(allocator, body_size);
}

/// Encode the bounded `StreamingInputCallRequest` compression fixture.
pub fn encodeStreamingInputCallRequestAlloc(
    allocator: std.mem.Allocator,
    options: StreamingInputRequest,
) Error![]u8 {
    if (options.request_body_size > max_payload_size) {
        return error.MessageTooLarge;
    }
    const payload_len = if (options.request_body_size == 0)
        0
    else
        try lengthDelimitedFieldLen(options.request_body_size);
    const encoded_len = std.math.add(
        usize,
        try lengthDelimitedFieldLen(payload_len),
        boolWrapperFieldLen(options.expect_compressed),
    ) catch return error.MessageTooLarge;
    const encoded = try allocator.alloc(u8, encoded_len);
    errdefer allocator.free(encoded);
    var cursor: usize = 0;
    encoded[cursor] = fieldKey(1, .length_delimited);
    cursor += 1;
    writeVarint(encoded, &cursor, payload_len);
    if (options.request_body_size != 0) {
        encoded[cursor] = fieldKey(2, .length_delimited);
        cursor += 1;
        writeVarint(encoded, &cursor, options.request_body_size);
        @memset(encoded[cursor..][0..options.request_body_size], 0);
        cursor += options.request_body_size;
    }
    writeBoolWrapperField(
        encoded,
        &cursor,
        2,
        options.expect_compressed,
    );
    std.debug.assert(cursor == encoded.len);
    return encoded;
}

/// Decode one canonical `StreamingInputCallRequest`, preserving the nullable
/// compression expectation separately from the protobuf payload size.
pub fn decodeStreamingInputCallRequest(
    input: []const u8,
) Error!StreamingInputRequest {
    if (input.len > max_payload_size + 32) return error.MessageTooLarge;
    var reader = Reader{ .input = input };
    var payload_seen = false;
    var expect_compressed_seen = false;
    var result = StreamingInputRequest{ .request_body_size = 0 };
    while (!reader.finished()) {
        const tag = try reader.readTag();
        switch (tag.field_number) {
            1 => {
                if (tag.wire_type != .length_delimited) {
                    return error.UnsupportedWireType;
                }
                if (payload_seen) return error.DuplicateField;
                payload_seen = true;
                result.request_body_size = try decodeZeroPayload(
                    try reader.readBytes(max_payload_size + 16),
                );
            },
            2 => {
                if (tag.wire_type != .length_delimited) {
                    return error.UnsupportedWireType;
                }
                if (expect_compressed_seen) return error.DuplicateField;
                expect_compressed_seen = true;
                result.expect_compressed = try decodeBoolValue(
                    try reader.readBytes(2),
                );
            },
            else => return error.UnsupportedField,
        }
    }
    if (!payload_seen) return error.MissingPayload;
    return result;
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

pub fn decodeStreamingInputCallResponse(input: []const u8) Error!usize {
    if (input.len > 16) return error.MessageTooLarge;
    var reader = Reader{ .input = input };
    var aggregate_seen = false;
    var aggregate: usize = 0;
    while (!reader.finished()) {
        const tag = try reader.readTag();
        if (tag.field_number != 1) return error.UnsupportedField;
        if (tag.wire_type != .varint) return error.UnsupportedWireType;
        if (aggregate_seen) return error.DuplicateField;
        aggregate_seen = true;
        const value = try reader.readVarint();
        if (value > std.math.maxInt(i32)) return error.InvalidArgument;
        aggregate = @intCast(value);
    }
    if (!aggregate_seen) return error.MissingPayload;
    return aggregate;
}

/// Decode repeated response parameters from a server-streaming request into
/// caller-owned bounded storage.
pub fn decodeStreamingOutputCallResponseParameters(
    input: []const u8,
    out: []ResponseParameter,
) Error![]const ResponseParameter {
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
                out[count] = parameters;
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
                result.response_compressed = decoded.compressed;
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

/// Decode the exact request used by the official connection-scaling case:
/// one response-parameters entry containing only
/// `fill_peer_socket_address = BoolValue(true)`.
pub fn decodePeerSocketAddressRequest(input: []const u8) Error!void {
    var reader = Reader{ .input = input };
    const tag = try reader.readTag();
    if (tag.field_number != 2 or tag.wire_type != .length_delimited) {
        return error.UnsupportedField;
    }
    const parameter = try reader.readBytes(8);
    if (!reader.finished()) return error.UnsupportedField;

    var parameter_reader = Reader{ .input = parameter };
    const fill_tag = try parameter_reader.readTag();
    if (fill_tag.field_number != 4 or
        fill_tag.wire_type != .length_delimited)
    {
        return error.UnsupportedField;
    }
    if (!try decodeBoolValue(try parameter_reader.readBytes(2)) or
        !parameter_reader.finished())
    {
        return error.InvalidArgument;
    }
}

/// Encode a payload-free `StreamingOutputCallResponse` containing the real
/// client endpoint in field 2 `peer_socket_address`.
pub fn encodePeerSocketAddressResponseAlloc(
    allocator: std.mem.Allocator,
    peer_socket_address: []const u8,
) Error![]u8 {
    if (peer_socket_address.len == 0 or
        peer_socket_address.len > max_peer_socket_address_size)
    {
        return error.InvalidArgument;
    }
    if (!std.unicode.utf8ValidateSlice(peer_socket_address)) {
        return error.InvalidUtf8;
    }
    const encoded = try allocator.alloc(
        u8,
        try lengthDelimitedFieldLen(peer_socket_address.len),
    );
    errdefer allocator.free(encoded);
    var cursor: usize = 0;
    encoded[cursor] = fieldKey(2, .length_delimited);
    cursor += 1;
    writeVarint(encoded, &cursor, peer_socket_address.len);
    @memcpy(
        encoded[cursor..][0..peer_socket_address.len],
        peer_socket_address,
    );
    cursor += peer_socket_address.len;
    std.debug.assert(cursor == encoded.len);
    return encoded;
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
    } else if (options.interval_us != 0 or
        options.response_compressed != null)
    {
        return error.InvalidArgument;
    }

    const parameter = ResponseParameter{
        .size = options.response_size orelse 0,
        .interval_us = options.interval_us,
        .compressed = options.response_compressed,
    };
    if (options.response_size != null) try validateResponseParameter(parameter);
    const parameters_len = if (options.response_size != null)
        responseParameterLen(parameter)
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

    if (options.response_size != null) {
        // StreamingOutputCallRequest.response_parameters = field 2.
        encoded[cursor] = fieldKey(2, .length_delimited);
        cursor += 1;
        writeVarint(encoded, &cursor, parameters_len);
        writeResponseParameter(encoded, &cursor, parameter);
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

/// Encode a server-streaming request containing only the supplied response
/// parameters. This matches the canonical compressed-streaming case, whose
/// request has no input payload.
pub fn encodeStreamingOutputCallParametersAlloc(
    allocator: std.mem.Allocator,
    parameters: []const ResponseParameter,
) Error![]u8 {
    if (parameters.len == 0) return error.MissingPayload;
    var encoded_len: usize = 0;
    for (parameters) |parameter| {
        try validateResponseParameter(parameter);
        encoded_len = std.math.add(
            usize,
            encoded_len,
            try lengthDelimitedFieldLen(responseParameterLen(parameter)),
        ) catch return error.MessageTooLarge;
    }
    const encoded = try allocator.alloc(u8, encoded_len);
    errdefer allocator.free(encoded);
    var cursor: usize = 0;
    for (parameters) |parameter| {
        const parameter_len = responseParameterLen(parameter);
        encoded[cursor] = fieldKey(2, .length_delimited);
        cursor += 1;
        writeVarint(encoded, &cursor, parameter_len);
        writeResponseParameter(encoded, &cursor, parameter);
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

fn decodeResponseParameters(input: []const u8) Error!ResponseParameter {
    var reader = Reader{ .input = input };
    var size_seen = false;
    var interval_seen = false;
    var compressed_seen = false;
    var result = ResponseParameter{};
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
            3 => {
                if (tag.wire_type != .length_delimited) {
                    return error.UnsupportedWireType;
                }
                if (compressed_seen) return error.DuplicateField;
                compressed_seen = true;
                result.compressed = try decodeBoolValue(
                    try reader.readBytes(2),
                );
            },
            else => return error.UnsupportedField,
        }
    }
    return result;
}

fn decodeEchoStatus(input: []const u8) Error!EchoStatus {
    var reader = Reader{ .input = input };
    var code_seen = false;
    var message_seen = false;
    var result = EchoStatus{ .code = 0, .message = "" };
    while (!reader.finished()) {
        const tag = try reader.readTag();
        switch (tag.field_number) {
            1 => {
                if (tag.wire_type != .varint) {
                    return error.UnsupportedWireType;
                }
                if (code_seen) return error.DuplicateField;
                code_seen = true;
                const code = try reader.readVarint();
                if (code > 16) return error.InvalidStatus;
                result.code = @intCast(code);
            },
            2 => {
                if (tag.wire_type != .length_delimited) {
                    return error.UnsupportedWireType;
                }
                if (message_seen) return error.DuplicateField;
                message_seen = true;
                result.message = try reader.readBytes(max_status_message_size);
            },
            else => return error.UnsupportedField,
        }
    }
    if (!code_seen or !message_seen) return error.MissingStatus;
    try validateEchoStatus(result);
    return result;
}

fn validateEchoStatus(status: EchoStatus) Error!void {
    if (status.code > 16) return error.InvalidStatus;
    if (status.message.len > max_status_message_size) {
        return error.MessageTooLarge;
    }
    if (!std.unicode.utf8ValidateSlice(status.message)) {
        return error.InvalidUtf8;
    }
}

fn validateResponseParameter(parameter: ResponseParameter) Error!void {
    if (parameter.size > max_payload_size) return error.MessageTooLarge;
    if (parameter.interval_us > max_interval_us) return error.InvalidArgument;
}

fn responseParameterLen(parameter: ResponseParameter) usize {
    return (if (parameter.size == 0) 0 else 1 + varintLen(parameter.size)) +
        (if (parameter.interval_us == 0) 0 else 1 + varintLen(parameter.interval_us)) +
        boolWrapperFieldLen(parameter.compressed);
}

fn writeResponseParameter(
    output: []u8,
    cursor: *usize,
    parameter: ResponseParameter,
) void {
    if (parameter.size != 0) {
        output[cursor.*] = fieldKey(1, .varint);
        cursor.* += 1;
        writeVarint(output, cursor, parameter.size);
    }
    if (parameter.interval_us != 0) {
        output[cursor.*] = fieldKey(2, .varint);
        cursor.* += 1;
        writeVarint(output, cursor, parameter.interval_us);
    }
    writeBoolWrapperField(output, cursor, 3, parameter.compressed);
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

fn decodeBoolValue(input: []const u8) Error!bool {
    if (input.len == 0) return false;
    var reader = Reader{ .input = input };
    const tag = try reader.readTag();
    if (tag.field_number != 1 or tag.wire_type != .varint) {
        return error.UnsupportedField;
    }
    const raw = try reader.readVarint();
    if (!reader.finished() or raw > 1) return error.InvalidArgument;
    return raw == 1;
}

fn boolWrapperFieldLen(value: ?bool) usize {
    return if (value) |enabled| if (enabled) 4 else 2 else 0;
}

fn writeBoolWrapperField(
    output: []u8,
    cursor: *usize,
    field_number: u5,
    value: ?bool,
) void {
    const enabled = value orelse return;
    output[cursor.*] = fieldKey(field_number, .length_delimited);
    cursor.* += 1;
    output[cursor.*] = if (enabled) 2 else 0;
    cursor.* += 1;
    if (enabled) {
        output[cursor.*] = fieldKey(1, .varint);
        output[cursor.* + 1] = 1;
        cursor.* += 2;
    }
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

test "decodes pick-first request and encodes stable server identity" {
    try decodePickFirstRequest(&.{ 0x48, 0x01 });
    try std.testing.expectError(
        error.InvalidArgument,
        decodePickFirstRequest(&.{ 0x48, 0x00 }),
    );
    try std.testing.expectError(
        error.DuplicateField,
        decodePickFirstRequest(&.{ 0x48, 0x01, 0x48, 0x01 }),
    );
    try std.testing.expectError(
        error.UnsupportedField,
        decodePickFirstRequest(&.{ 0x10, 0x00 }),
    );

    const encoded = try encodeServerIdResponseAlloc(
        std.testing.allocator,
        "netz-interop-server",
    );
    defer std.testing.allocator.free(encoded);
    try std.testing.expectEqualSlices(
        u8,
        "\x22\x13netz-interop-server",
        encoded,
    );
}

test "encodes and decodes unary compression controls" {
    const encoded = try encodeSimpleRequestAlloc(
        std.testing.allocator,
        .{
            .response_size = 5,
            .request_body_size = 3,
            .response_compressed = true,
            .expect_compressed = false,
        },
    );
    defer std.testing.allocator.free(encoded);
    try std.testing.expectEqualSlices(
        u8,
        &.{
            0x10, 0x05,
            0x1a, 0x05,
            0x12, 0x03,
            0,    0,
            0,    0x32,
            0x02, 0x08,
            0x01, 0x42,
            0x00,
        },
        encoded,
    );
    const decoded = try decodeSimpleRequest(encoded);
    try std.testing.expectEqual(@as(u32, 5), decoded.response_size);
    try std.testing.expectEqual(@as(usize, 3), decoded.request_body_size);
    try std.testing.expectEqual(@as(?bool, true), decoded.response_compressed);
    try std.testing.expectEqual(@as(?bool, false), decoded.expect_compressed);
    try std.testing.expectError(
        error.InvalidArgument,
        decodeSimpleRequest(&.{
            0x10, 0x05, 0x1a, 0x00,
            0x42, 0x02, 0x08, 0x02,
        }),
    );
    try std.testing.expectError(
        error.DuplicateField,
        decodeSimpleRequest(&.{
            0x10, 0x05, 0x1a, 0x00,
            0x32, 0x00, 0x32, 0x00,
        }),
    );
    try std.testing.expectError(
        error.UnsupportedField,
        decodeSimpleRequest(&.{
            0x10, 0x05, 0x1a, 0x00,
            0x32, 0x02, 0x10, 0x01,
        }),
    );
}

test "decodes client and server streaming fixture messages" {
    const input_request = try decodeStreamingInputCallRequest(
        &.{ 0x0a, 0x05, 0x12, 0x03, 0, 0, 0 },
    );
    try std.testing.expectEqual(
        @as(usize, 3),
        input_request.request_body_size,
    );
    try std.testing.expectEqual(@as(?bool, null), input_request.expect_compressed);

    const compressed_input = try encodeStreamingInputCallRequestAlloc(
        std.testing.allocator,
        .{ .request_body_size = 3, .expect_compressed = false },
    );
    defer std.testing.allocator.free(compressed_input);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x0a, 0x05, 0x12, 0x03, 0, 0, 0, 0x12, 0x00 },
        compressed_input,
    );
    const decoded_input = try decodeStreamingInputCallRequest(compressed_input);
    try std.testing.expectEqual(@as(usize, 3), decoded_input.request_body_size);
    try std.testing.expectEqual(@as(?bool, false), decoded_input.expect_compressed);

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
    try std.testing.expectEqual(
        @as(usize, 74_922),
        try decodeStreamingInputCallResponse(aggregate),
    );

    var parameters_storage: [4]ResponseParameter = undefined;
    const parameters = try decodeStreamingOutputCallResponseParameters(
        &.{
            0x12, 0x04, 0x08, 0xb7, 0xf5, 0x01,
            0x12, 0x02, 0x08, 0x09,
        },
        &parameters_storage,
    );
    try std.testing.expectEqual(@as(usize, 2), parameters.len);
    try std.testing.expectEqual(@as(u32, 31_415), parameters[0].size);
    try std.testing.expectEqual(@as(u32, 9), parameters[1].size);
}

test "encodes and decodes streaming compression controls" {
    const expected = [_]ResponseParameter{
        .{ .size = 31_415, .compressed = true },
        .{ .size = 92_653, .compressed = false },
    };
    const encoded = try encodeStreamingOutputCallParametersAlloc(
        std.testing.allocator,
        &expected,
    );
    defer std.testing.allocator.free(encoded);
    var storage: [2]ResponseParameter = undefined;
    const decoded = try decodeStreamingOutputCallResponseParameters(
        encoded,
        &storage,
    );
    try std.testing.expectEqualSlices(ResponseParameter, &expected, decoded);
}

test "encodes and decodes canonical status requests" {
    const message =
        "\t\ntest with whitespace\r\nand Unicode BMP ☺ and non-BMP 😈\t\n";
    const encoded = try encodeStatusRequestAlloc(
        std.testing.allocator,
        .{ .code = 2, .message = message },
    );
    defer std.testing.allocator.free(encoded);
    const decoded = try decodeStatusRequest(encoded);
    try std.testing.expectEqual(@as(u8, 2), decoded.code);
    try std.testing.expectEqualStrings(message, decoded.message);
    try std.testing.expectError(
        error.InvalidStatus,
        decodeStatusRequest(&.{ 0x3a, 0x04, 0x08, 0x11, 0x12, 0x00 }),
    );
    try std.testing.expectError(
        error.InvalidUtf8,
        decodeStatusRequest(&.{ 0x3a, 0x05, 0x08, 0x02, 0x12, 0x01, 0xff }),
    );
    try std.testing.expectError(
        error.DuplicateField,
        decodeStatusRequest(&.{
            0x3a, 0x04, 0x08, 0x02, 0x12, 0x00,
            0x3a, 0x04, 0x08, 0x02, 0x12, 0x00,
        }),
    );
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
        decodeStreamingOutputCallRequest(&.{ 0x12, 0x02, 0x28, 0x00, 0x1a, 0x00 }),
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

test "strictly handles peer socket address connection-scaling messages" {
    try decodePeerSocketAddressRequest(
        &.{ 0x12, 0x04, 0x22, 0x02, 0x08, 0x01 },
    );
    try std.testing.expectError(
        error.InvalidArgument,
        decodePeerSocketAddressRequest(
            &.{ 0x12, 0x02, 0x22, 0x00 },
        ),
    );
    try std.testing.expectError(
        error.UnsupportedField,
        decodePeerSocketAddressRequest(
            &.{ 0x12, 0x04, 0x22, 0x02, 0x08, 0x01, 0x1a, 0x00 },
        ),
    );

    const encoded = try encodePeerSocketAddressResponseAlloc(
        std.testing.allocator,
        "127.0.0.1:43210",
    );
    defer std.testing.allocator.free(encoded);
    try std.testing.expectEqualSlices(
        u8,
        "\x12\x0f127.0.0.1:43210",
        encoded,
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
