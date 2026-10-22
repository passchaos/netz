//! WebTransport reset operations with a mandatory reliable association prefix.

const std = @import("std");
const webtransport = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const association = @import("../stream_association.zig");
const prefix = @import("prefix.zig");
const deadline_policy = @import("../../../internal/deadline.zig");

pub const Error = association.Error;
pub const TimeoutError = Error || quic.runtime.ReceiveTimeoutError;

/// Abort the local send direction with a mapped WebTransport error code.
pub fn reset(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
    application_error_code: u32,
) Error!void {
    return resetWithCode(connection, registry, stream_id, webtransport.applicationErrorCodeToHttp3(application_error_code));
}

pub fn resetWithCode(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
    http3_code: u64,
) Error!void {
    const stream = registry.get(stream_id) orelse
        return error.UnknownStream;
    if (stream.direction == .unidirectional and
        !stream.locally_initiated)
    {
        return error.InvalidStreamState;
    }
    try prefix.bind(connection, registry, stream);
    try connection.resetStream(stream_id, http3_code);
    prefix.observeReset(connection, stream);
    stream.send_reset = .fromHttp3(http3_code);
    try association.requestAfterSendTerminal(connection, stream);
}

/// Abort the local send direction under one absolute awake-clock deadline.
/// The registry is committed only after RESET_STREAM reaches the socket.
pub fn resetWithDeadline(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
    application_error_code: u32,
    deadline: std.Io.Clock.Timestamp,
) TimeoutError!void {
    return resetWithCodeAndDeadline(connection, registry, stream_id, webtransport.applicationErrorCodeToHttp3(application_error_code), deadline);
}

pub fn resetWithCodeAndDeadline(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
    http3_code: u64,
    deadline: std.Io.Clock.Timestamp,
) TimeoutError!void {
    _ = try deadline_policy.usableAwake(connection.endpoint.io, deadline);
    const stream = registry.get(stream_id) orelse
        return error.UnknownStream;
    if (stream.direction == .unidirectional and
        !stream.locally_initiated)
    {
        return error.InvalidStreamState;
    }
    try prefix.bind(connection, registry, stream);
    try connection.resetStreamWithDeadline(
        stream_id,
        http3_code,
        deadline,
    );
    prefix.observeReset(connection, stream);
    stream.send_reset = .fromHttp3(http3_code);
    try association.requestAfterSendTerminal(connection, stream);
}

/// Abort the local send direction once without sleeping for QUIC pacing.
/// Registry state changes only after the RESET_STREAM packet is submitted.
pub fn resetOnce(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
    application_error_code: u32,
) Error!void {
    return resetOnceWithCode(connection, registry, stream_id, webtransport.applicationErrorCodeToHttp3(application_error_code));
}

pub fn resetOnceWithCode(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
    http3_code: u64,
) Error!void {
    const stream = registry.get(stream_id) orelse
        return error.UnknownStream;
    if (stream.direction == .unidirectional and
        !stream.locally_initiated)
    {
        return error.InvalidStreamState;
    }
    try prefix.bind(connection, registry, stream);
    try connection.tryResetStream(stream_id, http3_code);
    prefix.observeReset(connection, stream);
    stream.send_reset = .fromHttp3(http3_code);
    try association.requestAfterSendTerminal(connection, stream);
}

/// Abort the local send direction while guaranteeing delivery of an
/// application-data prefix. `reliable_size` excludes the WebTransport stream
/// association prefix, which must already have reached the QUIC send path.
pub fn resetReliably(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
    application_error_code: u32,
    reliable_size: u64,
) Error!void {
    const prepared = try prepareReliableReset(
        connection,
        registry,
        stream_id,
        reliable_size,
    );
    const http3_code =
        webtransport.applicationErrorCodeToHttp3(application_error_code);
    try connection.resetStreamReliably(
        stream_id,
        http3_code,
        prepared.wire_reliable_size,
    );
    prefix.observeReset(connection, prepared.stream);
    prepared.stream.send_reset = .fromHttp3(http3_code);
    try association.requestAfterSendTerminal(connection, prepared.stream);
}

/// Deadline-bounded reliable reset. Registry state changes only after the
/// RESET_STREAM_AT frame reaches the socket.
pub fn resetReliablyWithDeadline(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
    application_error_code: u32,
    reliable_size: u64,
    deadline: std.Io.Clock.Timestamp,
) TimeoutError!void {
    _ = try deadline_policy.usableAwake(connection.endpoint.io, deadline);
    const prepared = try prepareReliableReset(
        connection,
        registry,
        stream_id,
        reliable_size,
    );
    const http3_code =
        webtransport.applicationErrorCodeToHttp3(application_error_code);
    try connection.resetStreamReliablyWithDeadline(
        stream_id,
        http3_code,
        prepared.wire_reliable_size,
        deadline,
    );
    prefix.observeReset(connection, prepared.stream);
    prepared.stream.send_reset = .fromHttp3(http3_code);
    try association.requestAfterSendTerminal(connection, prepared.stream);
}

/// Single-attempt counterpart for shared-endpoint dispatchers.
pub fn resetReliablyOnce(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
    application_error_code: u32,
    reliable_size: u64,
) Error!void {
    const prepared = try prepareReliableReset(
        connection,
        registry,
        stream_id,
        reliable_size,
    );
    const http3_code =
        webtransport.applicationErrorCodeToHttp3(application_error_code);
    try connection.tryResetStreamReliably(
        stream_id,
        http3_code,
        prepared.wire_reliable_size,
    );
    prefix.observeReset(connection, prepared.stream);
    prepared.stream.send_reset = .fromHttp3(http3_code);
    try association.requestAfterSendTerminal(connection, prepared.stream);
}

const PreparedReliableReset = struct {
    stream: *webtransport.StreamState,
    wire_reliable_size: u64,
};

fn prepareReliableReset(
    connection: *quic.one_rtt.Connection,
    registry: *webtransport.StreamRegistry,
    stream_id: u62,
    reliable_size: u64,
) Error!PreparedReliableReset {
    const stream = registry.get(stream_id) orelse
        return error.UnknownStream;
    if ((stream.direction == .unidirectional and
        !stream.locally_initiated) or
        stream.send_reset != null or
        stream.stopped != null or
        stream.local_fin)
    {
        return error.InvalidStreamState;
    }
    if (reliable_size > stream.bytes_sent) return error.InvalidStreamState;
    try prefix.bind(connection, registry, stream);
    var storage: [16]u8 = undefined;
    const prefix_size: u64 = if (stream.prefix_sent)
        stream.send_offset - stream.bytes_sent
    else if (stream.locally_initiated)
        (try prefix.header(registry.session_id, stream.direction, &storage)).len
    else
        0;
    return .{
        .stream = stream,
        .wire_reliable_size = std.math.add(
            u64,
            prefix_size,
            reliable_size,
        ) catch return error.IntegerOverflow,
    };
}

test {
    _ = @import("reset/tests.zig");
}
