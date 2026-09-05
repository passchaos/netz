const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const runtime_error = @import("../error.zig");
const protected_send_module = @import("../send/protected.zig");

const net = @import("std").Io.net;
const Error = runtime_error.Error;
const ProtectedSendState = protected_send_module.State;

/// Install an RFC 9114/9204 application close for a peer protocol failure.
/// Local resource, timeout, socket, and transport errors leave the connection
/// open and continue to propagate to the caller.
pub fn closeConnection(
    connection: *quic.one_rtt.Connection,
    err: anyerror,
) Error!void {
    const close = runtime_error.protocolClose(err) orelse return;
    if (connection.closing() or connection.draining() or connection.closed()) {
        return;
    }
    // The protocol classification remains the useful caller error even if the
    // socket write fails. closeApplication installs local closing state before
    // surfacing that send error, so a best-effort call is sufficient.
    connection.closeApplication(close.code, close.reason) catch {};
}

/// Emit the equivalent close for the deterministic preconfigured-key runtime,
/// which deliberately has no stateful one_rtt.Connection.
pub fn sendProtectedClose(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: anytype,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    err: anyerror,
) void {
    const close = runtime_error.protocolClose(err) orelse return;
    const frames = [_]quic.Frame{.{ .application_close = .{
        .error_code = close.code,
        .reason_phrase = close.reason,
    } }};
    protected_send.sendFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        &frames,
        config.max_frames_per_packet,
    ) catch {};
}
