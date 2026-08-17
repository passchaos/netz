const std = @import("std");
const mqtt = @import("mod.zig");
const runtime = @import("runtime.zig");
const websocket = @import("../websocket/mod.zig");
const websocket_runtime = websocket.runtime;
const http1_runtime = @import("../http1/mod.zig").runtime;

const net = std.Io.net;
const mqtt_subprotocol = "mqtt";

/// MQTT-over-WebSocket listener.
///
/// The HTTP opening handshake succeeds only when the client offers the
/// registered `mqtt` subprotocol. permessage-deflate is deliberately disabled:
/// MQTT has its own packet-size limits, and compression would make those limits
/// depend on decompression rather than the peer's MQTT Control Packet bytes.
pub const Server = struct {
    allocator: std.mem.Allocator,
    websocket_server: websocket_runtime.Server,
    limits: runtime.Limits,

    pub fn listen(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        options: ListenOptions,
    ) runtime.Error!Server {
        return .{
            .allocator = allocator,
            .websocket_server = try .listen(
                allocator,
                io,
                bind_address,
                websocketLimits(options.limits, options.max_head_bytes),
            ),
            .limits = options.limits,
        };
    }

    pub fn deinit(self: *Server) void {
        self.websocket_server.deinit();
        self.* = undefined;
    }

    pub fn address(self: Server) net.IpAddress {
        return self.websocket_server.address();
    }

    pub fn accept(
        self: *Server,
        options: runtime.AcceptOptions,
    ) runtime.Error!runtime.AcceptedClient {
        var ws = try self.websocket_server.accept(.{
            .protocols = &.{mqtt_subprotocol},
            .require_subprotocol = true,
        });
        var ws_owned = true;
        errdefer if (ws_owned) ws.close();

        var connection = runtime.Connection.initWebSocket(
            self.allocator,
            ws,
            options.protocol,
            self.limits,
            options.max_outgoing_inflight,
            options.topic_alias_maximum,
        );
        ws_owned = false;
        errdefer connection.close();
        return connection.accept(options);
    }
};

pub const ListenOptions = struct {
    limits: runtime.Limits = .{},
    max_head_bytes: usize = 64 * 1024,
};

/// MQTT-over-WebSocket client with strict `Sec-WebSocket-Protocol: mqtt`
/// negotiation. `connectUri*` supports both `ws://` and `wss://` through the
/// existing WebSocket TLS client.
pub const Client = struct {
    pub fn connect(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
    ) runtime.Error!runtime.Connection {
        var result = try connectWithConnAck(allocator, io, address, options);
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectWithConnAck(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
    ) runtime.Error!runtime.ConnectResult {
        var attempt = try connectAttempt(allocator, io, address, options);
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        options: ConnectOptions,
    ) runtime.Error!runtime.ConnectAttempt {
        const ws = try websocket_runtime.Client.connect(
            allocator,
            io,
            address,
            websocketConnectOptions(options),
        );
        return connectWebSocketAttempt(allocator, ws, options.mqtt);
    }

    pub fn connectUri(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri: []const u8,
        options: ConnectOptions,
    ) runtime.Error!runtime.Connection {
        var result = try connectUriWithConnAck(
            allocator,
            io,
            uri,
            options,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectUriWithConnAck(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri: []const u8,
        options: ConnectOptions,
    ) runtime.Error!runtime.ConnectResult {
        var attempt = try connectUriAttempt(allocator, io, uri, options);
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectUriAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri: []const u8,
        options: ConnectOptions,
    ) runtime.Error!runtime.ConnectAttempt {
        const ws = try websocket_runtime.Client.connectUriTls(
            allocator,
            io,
            uri,
            websocketConnectOptions(options),
            options.tls,
        );
        return connectWebSocketAttempt(allocator, ws, options.mqtt);
    }
};

pub const ConnectOptions = struct {
    mqtt: runtime.ConnectOptions,
    host: []const u8 = "",
    target: []const u8 = "/mqtt",
    max_head_bytes: usize = 64 * 1024,
    tcp_nodelay: bool = true,
    tls: http1_runtime.TlsClientOptions = .{},
};

fn websocketLimits(
    limits: runtime.Limits,
    max_head_bytes: usize,
) websocket_runtime.Limits {
    return .{
        .max_head_bytes = max_head_bytes,
        .max_frame_bytes = limits.max_packet_size,
        .max_message_bytes = limits.max_packet_size,
    };
}

fn websocketConnectOptions(
    options: ConnectOptions,
) websocket_runtime.ConnectOptions {
    return .{
        .host = options.host,
        .target = options.target,
        .protocols = &.{mqtt_subprotocol},
        .tcp_nodelay = options.tcp_nodelay,
        .limits = websocketLimits(
            options.mqtt.limits,
            options.max_head_bytes,
        ),
    };
}

fn connectWebSocketAttempt(
    allocator: std.mem.Allocator,
    ws: websocket_runtime.Connection,
    options: runtime.ConnectOptions,
) runtime.Error!runtime.ConnectAttempt {
    if (ws.selected_protocol == null or
        !std.mem.eql(u8, ws.selected_protocol.?, mqtt_subprotocol))
    {
        var invalid_ws = ws;
        invalid_ws.close();
        return error.InvalidSubprotocol;
    }

    var connection = runtime.Connection.initWebSocket(
        allocator,
        ws,
        options.protocol,
        options.limits,
        options.max_outgoing_inflight,
        options.topic_alias_maximum,
    );
    connection.max_incoming_inflight =
        mqtt.receiveMaximum(options.properties) orelse
        options.max_outgoing_inflight;
    connection.peer_maximum_qos = options.peer_maximum_qos;
    connection.peer_retain_available = options.peer_retain_available;
    errdefer connection.close();
    return connection.establishClient(options);
}
