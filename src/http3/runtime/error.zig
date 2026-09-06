const std = @import("std");
const http3 = @import("../mod.zig");
const quic = @import("../../quic/mod.zig");

const net = std.Io.net;

pub const Error = http3.Error || quic.runtime.Error ||
    quic.handshake.Error || quic.one_rtt.Error || quic.stream_state.Error ||
    net.HostName.ValidateError || net.HostName.LookupError || error{
    MissingStreamFrame,
    MissingDatagram,
    UnexpectedStream,
    GoAwayReceived,
    RequestRejected,
    ConnectionUnusable,
    RecoveryDrainTimeout,
    RecoveryDrainUnavailable,
    ClosedCriticalStream,
    ConnectDatagramAssociationClosed,
    InvalidUri,
    InvalidAlpn,
    DatagramsNotNegotiated,
    InvalidDispatcherState,
};

/// Failures produced by a handshake worker after admission has transferred
/// Initial ownership. Keep this narrower than `HandshakeAdmissionError`: an
/// endpoint event must not claim that dispatcher or task-spawn failures can
/// originate asynchronously from an already-admitted worker.
pub const HandshakeWorkerError = Error || std.Io.Timeout.Error;
pub const HandshakeAdmissionError = HandshakeWorkerError ||
    quic.endpoint_dispatcher.Error || std.Io.ConcurrentError;
pub const ReceiveTimeoutError = Error || quic.runtime.ReceiveTimeoutError;

pub const ProtocolClose = struct {
    code: u64,
    reason: []const u8,
};

/// Errors produced after a request/response stream has been identified whose
/// scope is the HTTP message rather than the whole HTTP/3 connection.
pub fn messageStreamErrorCode(err: anyerror) ?u64 {
    return switch (err) {
        error.MissingMethod,
        error.MissingPath,
        error.MissingStatus,
        error.InvalidStatus,
        error.InvalidHeader,
        error.InvalidContentLength,
        error.ExtendedConnectDisabled,
        => http3.ApplicationErrorCode.message_error,
        error.TooManyInformationalResponses => http3.ApplicationErrorCode.excessive_load,
        // This tag also represents connection admission limits. Runtime call
        // sites consult the stream mapping only once a concrete message stream
        // has been identified, such as an oversized field section.
        error.ExcessiveLoad => http3.ApplicationErrorCode.excessive_load,
        else => null,
    };
}

/// Map only peer-originated HTTP/3 protocol failures to wire close codes.
/// Local allocation, timeout, socket, and transport failures intentionally
/// return null so callers do not misreport an implementation failure as a
/// peer protocol violation.
pub fn protocolClose(err: anyerror) ?ProtocolClose {
    return switch (err) {
        error.StreamCreationError, error.InvalidStreamType => .{
            .code = http3.ApplicationErrorCode.stream_creation_error,
            .reason = "http3-stream-creation-error",
        },
        error.ClosedCriticalStream => .{
            .code = http3.ApplicationErrorCode.closed_critical_stream,
            .reason = "http3-closed-critical-stream",
        },
        error.UnexpectedFrame, error.ExpectedHeadersFrame => .{
            .code = http3.ApplicationErrorCode.frame_unexpected,
            .reason = "http3-frame-unexpected",
        },
        error.BufferTooShort,
        error.IntegerOverflow,
        error.VarIntTooLarge,
        error.MalformedVarInt,
        error.InvalidFrame,
        error.InvalidOrigin,
        => .{
            .code = http3.ApplicationErrorCode.frame_error,
            .reason = "http3-frame-error",
        },
        error.ExcessiveLoad => .{
            .code = http3.ApplicationErrorCode.excessive_load,
            .reason = "http3-excessive-load",
        },
        error.IdError,
        error.GoAwayIdIncreased,
        error.MaxPushIdReduced,
        error.PushIdExceeded,
        error.DuplicatePushId,
        => .{
            .code = http3.ApplicationErrorCode.id_error,
            .reason = "http3-id-error",
        },
        error.InvalidSetting => .{
            .code = http3.ApplicationErrorCode.settings_error,
            .reason = "http3-settings-error",
        },
        error.DuplicateSettings => .{
            .code = http3.ApplicationErrorCode.frame_unexpected,
            .reason = "http3-frame-unexpected",
        },
        error.MissingSettings => .{
            .code = http3.ApplicationErrorCode.missing_settings,
            .reason = "http3-missing-settings",
        },
        error.QpackDecompressionFailed => .{
            .code = http3.ApplicationErrorCode.qpack_decompression_failed,
            .reason = "qpack-decompression-failed",
        },
        error.QpackEncoderStreamError => .{
            .code = http3.ApplicationErrorCode.qpack_encoder_stream_error,
            .reason = "qpack-encoder-stream-error",
        },
        error.QpackDecoderStreamError => .{
            .code = http3.ApplicationErrorCode.qpack_decoder_stream_error,
            .reason = "qpack-decoder-stream-error",
        },
        else => null,
    };
}

test "HTTP/3 runtime errors map only peer protocol failures to close codes" {
    inline for (.{
        .{ error.StreamCreationError, http3.ApplicationErrorCode.stream_creation_error },
        .{ error.InvalidStreamType, http3.ApplicationErrorCode.stream_creation_error },
        .{ error.ClosedCriticalStream, http3.ApplicationErrorCode.closed_critical_stream },
        .{ error.UnexpectedFrame, http3.ApplicationErrorCode.frame_unexpected },
        .{ error.BufferTooShort, http3.ApplicationErrorCode.frame_error },
        .{ error.IntegerOverflow, http3.ApplicationErrorCode.frame_error },
        .{ error.VarIntTooLarge, http3.ApplicationErrorCode.frame_error },
        .{ error.MalformedVarInt, http3.ApplicationErrorCode.frame_error },
        .{ error.InvalidFrame, http3.ApplicationErrorCode.frame_error },
        .{ error.InvalidOrigin, http3.ApplicationErrorCode.frame_error },
        .{ error.ExcessiveLoad, http3.ApplicationErrorCode.excessive_load },
        .{ error.IdError, http3.ApplicationErrorCode.id_error },
        .{ error.GoAwayIdIncreased, http3.ApplicationErrorCode.id_error },
        .{ error.MaxPushIdReduced, http3.ApplicationErrorCode.id_error },
        .{ error.PushIdExceeded, http3.ApplicationErrorCode.id_error },
        .{ error.DuplicatePushId, http3.ApplicationErrorCode.id_error },
        .{ error.InvalidSetting, http3.ApplicationErrorCode.settings_error },
        .{ error.DuplicateSettings, http3.ApplicationErrorCode.frame_unexpected },
        .{ error.MissingSettings, http3.ApplicationErrorCode.missing_settings },
        .{ error.ExpectedHeadersFrame, http3.ApplicationErrorCode.frame_unexpected },
        .{ error.QpackDecompressionFailed, http3.ApplicationErrorCode.qpack_decompression_failed },
        .{ error.QpackEncoderStreamError, http3.ApplicationErrorCode.qpack_encoder_stream_error },
        .{ error.QpackDecoderStreamError, http3.ApplicationErrorCode.qpack_decoder_stream_error },
    }) |expected| {
        const close = protocolClose(expected[0]) orelse
            return error.TestUnexpectedResult;
        try std.testing.expectEqual(expected[1], close.code);
    }

    try std.testing.expect(protocolClose(error.OutOfMemory) == null);
    try std.testing.expect(protocolClose(error.Timeout) == null);
    try std.testing.expect(protocolClose(error.UnexpectedStream) == null);
    try std.testing.expect(protocolClose(error.QpackBlocked) == null);
    try std.testing.expect(protocolClose(error.InvalidPriorityUpdate) == null);
    try std.testing.expect(protocolClose(error.InvalidHeader) == null);
    try std.testing.expect(protocolClose(error.RequestIncomplete) == null);
}

test "HTTP/3 runtime maps malformed messages only to stream errors" {
    inline for (.{
        error.MissingMethod,
        error.MissingPath,
        error.MissingStatus,
        error.InvalidStatus,
        error.InvalidHeader,
        error.InvalidContentLength,
        error.ExtendedConnectDisabled,
    }) |err| {
        try std.testing.expectEqual(
            @as(?u64, http3.ApplicationErrorCode.message_error),
            messageStreamErrorCode(err),
        );
        try std.testing.expect(protocolClose(err) == null);
    }
    try std.testing.expectEqual(
        @as(?u64, http3.ApplicationErrorCode.excessive_load),
        messageStreamErrorCode(error.TooManyInformationalResponses),
    );
    try std.testing.expectEqual(
        @as(?u64, http3.ApplicationErrorCode.excessive_load),
        messageStreamErrorCode(error.ExcessiveLoad),
    );
    try std.testing.expect(messageStreamErrorCode(
        error.QpackDecompressionFailed,
    ) == null);
    try std.testing.expect(messageStreamErrorCode(error.OutOfMemory) == null);
}
