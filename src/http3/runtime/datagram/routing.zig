const std = @import("std");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const connect_datagram = @import("../datagram.zig");
const runtime_error = @import("../error.zig");

pub const Direction = enum { send, receive };

pub fn ensureNegotiated(
    settings: http3.SettingsState,
    connection: quic.one_rtt.Connection,
    direction: Direction,
) error{DatagramsNotNegotiated}!void {
    if (!settings.sent or !settings.received or
        !settings.local.h3_datagram or !settings.peer.h3_datagram)
    {
        return error.DatagramsNotNegotiated;
    }
    const transport_enabled = switch (direction) {
        .send => connection.datagramSendEnabled(),
        .receive => connection.datagramReceiveEnabled(),
    };
    if (!transport_enabled) return error.DatagramsNotNegotiated;
}

pub fn observeTerminal(
    registry: *connect_datagram.Registry,
    connection: *quic.one_rtt.Connection,
    stream_id: u62,
) void {
    if (!registry.contains(stream_id)) return;
    if (connection.streamResetReceived(stream_id)) |reset| {
        registry.markTerminal(stream_id, .{
            .peer_reset = reset.application_error_code,
        });
    } else if (connection.recvStreamStats(stream_id)) |stats| {
        if (stats.final_size != null and
            stats.bytes_received == stats.final_size.?)
        {
            registry.markTerminal(stream_id, .peer_fin);
        }
    }
    if (connection.closing() or connection.draining() or connection.closed()) {
        registry.markTerminal(stream_id, .connection_closed);
    }
}

pub fn ensureSendSideOpen(
    connection: quic.one_rtt.Connection,
    stream_id: u62,
) runtime_error.Error!void {
    if (connection.closing() or connection.draining() or connection.closed()) {
        return error.ConnectionClosed;
    }
    if (connection.streamStopped(stream_id) != null) {
        return error.StreamStopped;
    }
    const stats = connection.sendStreamStats(stream_id) orelse
        return error.UnexpectedStream;
    if (stats.reset != null) return error.RequestCancelled;
    if (stats.final_size != null) {
        return error.ConnectDatagramAssociationClosed;
    }
}

pub fn observeAllTerminals(
    registry: *connect_datagram.Registry,
    connection: *quic.one_rtt.Connection,
) void {
    if (connection.closing() or connection.draining() or connection.closed()) {
        registry.markAllTerminal(.connection_closed);
        return;
    }
    for (0..registry.associationCount()) |index| {
        observeTerminal(
            registry,
            connection,
            registry.associationStreamId(index),
        );
    }
}

pub fn terminalError(terminal: connect_datagram.Terminal) runtime_error.Error {
    return switch (terminal) {
        .peer_fin => error.ConnectDatagramAssociationClosed,
        .peer_reset => error.RequestCancelled,
        .connection_closed => error.ConnectionClosed,
    };
}

pub fn poll(
    registry: *connect_datagram.Registry,
    connection: *quic.one_rtt.Connection,
    stream_id: u62,
) runtime_error.Error!?connect_datagram.Owned {
    observeTerminal(registry, connection, stream_id);
    if (try registry.poll(stream_id)) |datagram| return datagram;
    if (try registry.drainedTerminal(stream_id)) |terminal| {
        return terminalError(terminal);
    }
    return null;
}

pub fn drain(
    registry: *connect_datagram.Registry,
    connection: *quic.one_rtt.Connection,
) runtime_error.Error!void {
    registry.drain(connection) catch |err| switch (err) {
        error.BufferTooShort,
        error.MalformedVarInt,
        error.VarIntTooLarge,
        error.InvalidFrame,
        => {
            try closeForDatagramError(connection);
            observeAllTerminals(registry, connection);
            registry.clear();
            return err;
        },
        else => return err,
    };
    observeAllTerminals(registry, connection);
}

/// Replay HTTP DATAGRAM frames in authenticated packet order. Terminal stream
/// frames take effect at their exact position, so later DATAGRAMs for that
/// association are dropped while earlier ones remain deliverable.
pub fn routePacket(
    registry: *connect_datagram.Registry,
    connection: *quic.one_rtt.Connection,
    frames: []const quic.Frame,
    packet_number: u64,
) runtime_error.Error!void {
    const frame_datagrams = countPacketDatagrams(frames);
    const retained_datagrams = if (frame_datagrams == 0)
        0
    else
        connection.queuedDatagramsForPacket(packet_number);
    const dropped_datagrams = frame_datagrams -| retained_datagrams;
    defer if (frame_datagrams != 0) {
        _ = connection.discardDatagramsForPacket(packet_number);
    };

    var datagram_index: usize = 0;
    for (frames) |frame| switch (frame) {
        .datagram => |datagram| {
            defer datagram_index += 1;
            const routed = if (datagram_index >= dropped_datagrams)
                registry.route(datagram.data)
            else
                connect_datagram.Registry.validate(datagram.data);
            routed catch |err| switch (err) {
                error.BufferTooShort,
                error.MalformedVarInt,
                error.VarIntTooLarge,
                error.InvalidFrame,
                => {
                    try closeForDatagramError(connection);
                    registry.clear();
                    return err;
                },
                else => return err,
            };
        },
        .reset_stream => |reset| {
            const stream_id = std.math.cast(u62, reset.stream_id) orelse
                continue;
            registry.markTerminal(stream_id, .{
                .peer_reset = reset.application_error_code,
            });
        },
        .stream => |stream| {
            if (!stream.fin) continue;
            const stream_id = std.math.cast(u62, stream.stream_id) orelse
                continue;
            registry.markTerminal(stream_id, .peer_fin);
        },
        .connection_close, .application_close => {
            registry.markAllTerminal(.connection_closed);
        },
        else => {},
    };
    observeAllTerminals(registry, connection);
}

pub fn countPacketDatagrams(frames: []const quic.Frame) usize {
    var count: usize = 0;
    for (frames) |frame| count += @intFromBool(frame == .datagram);
    return count;
}

fn closeForDatagramError(
    connection: *quic.one_rtt.Connection,
) runtime_error.Error!void {
    try connection.closeApplication(
        http3.ApplicationErrorCode.datagram_error,
        "invalid-http-datagram",
    );
}
