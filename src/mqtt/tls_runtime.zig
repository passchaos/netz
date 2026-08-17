const std = @import("std");
const mqtt_runtime = @import("runtime.zig");
const http1_runtime = @import("../http1/mod.zig").runtime;
const socket_options = @import("../internal/socket_options.zig");

const net = std.Io.net;

/// Native MQTT-over-TLS client.
///
/// TLS setup is shared with HTTP/1 and WSS, including operating-system roots,
/// explicit CA bundles, hostname verification, and truncation policy. Once the
/// handshake succeeds, all MQTT CONNECT/CONNACK and QoS state is handled by
/// the same `mqtt.runtime.Connection` used for cleartext TCP and WebSocket.
pub const Client = struct {
    pub fn connectHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
    ) mqtt_runtime.Error!mqtt_runtime.Connection {
        var result = try connectHostWithConnAck(
            allocator,
            io,
            host,
            port,
            options,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectHostWithConnAck(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectResult {
        var attempt = try connectHostAttempt(
            allocator,
            io,
            host,
            port,
            options,
        );
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectHostAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        options: ConnectOptions,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        const host_name = try net.HostName.init(host);
        const stream = try host_name.connect(io, port, .{ .mode = .stream });
        return connectStreamAttempt(
            allocator,
            io,
            stream,
            host,
            options,
        );
    }

    pub fn connectAddress(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
    ) mqtt_runtime.Error!mqtt_runtime.Connection {
        var result = try connectAddressWithConnAck(
            allocator,
            io,
            address,
            tls_host,
            options,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectAddressWithConnAck(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectResult {
        var attempt = try connectAddressAttempt(
            allocator,
            io,
            address,
            tls_host,
            options,
        );
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectAddressAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        tls_host: []const u8,
        options: ConnectOptions,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        const stream = try address.connect(io, .{ .mode = .stream });
        return connectStreamAttempt(
            allocator,
            io,
            stream,
            tls_host,
            options,
        );
    }

    pub fn connectUri(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
    ) mqtt_runtime.Error!mqtt_runtime.Connection {
        var result = try connectUriWithConnAck(
            allocator,
            io,
            uri_text,
            options,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectUriWithConnAck(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectResult {
        var attempt = try connectUriAttempt(
            allocator,
            io,
            uri_text,
            options,
        );
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectUriAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri_text: []const u8,
        options: ConnectOptions,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        const uri = std.Uri.parse(uri_text) catch
            return error.InvalidUri;
        const is_mqtts =
            std.ascii.eqlIgnoreCase(uri.scheme, "mqtts") or
            std.ascii.eqlIgnoreCase(uri.scheme, "ssl");
        if (!is_mqtts) return error.UnsupportedScheme;
        var endpoint = try http1_runtime.uriEndpoint(
            allocator,
            uri,
            8883,
        );
        defer endpoint.deinit();

        const stream = try endpoint.connect(io);
        return connectStreamAttempt(
            allocator,
            io,
            stream,
            endpoint.tls_host,
            options,
        );
    }
};

pub const ConnectOptions = struct {
    mqtt: mqtt_runtime.ConnectOptions,
    tls: http1_runtime.TlsClientOptions = .{},
    /// MQTT control packets are small latency-sensitive records by default.
    /// Set false to retain Nagle when batching throughput matters more.
    tcp_nodelay: bool = true,
};

fn connectStreamAttempt(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    tls_host: []const u8,
    options: ConnectOptions,
) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
    var stream_owned = true;
    errdefer if (stream_owned) stream.close(io);
    if (options.tcp_nodelay) {
        try socket_options.setTcpNoDelay(stream);
    }
    const tls_connection = try http1_runtime.TlsClientConnection.init(
        allocator,
        io,
        stream,
        tls_host,
        options.tls,
    );
    stream_owned = false;

    // `initTls` is infallible and transfers ownership into the MQTT
    // connection. From this point one errdefer must own teardown; retaining a
    // second TLS errdefer would double-close on a CONNECT/CONNACK error.
    var connection = mqtt_runtime.Connection.initTls(
        allocator,
        tls_connection,
        options.mqtt,
    );
    errdefer connection.close();
    return connection.establishClient(options.mqtt);
}
