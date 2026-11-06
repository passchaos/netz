const std = @import("std");
const netz = @import("netz");

const mqtt = netz.mqtt;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 6) return error.InvalidArgument;
    const no_auth_proxy_port = try std.fmt.parseInt(u16, args[1], 10);
    const auth_proxy_port = try std.fmt.parseInt(u16, args[2], 10);
    const clear_port = try std.fmt.parseInt(u16, args[3], 10);
    const tls_port = try std.fmt.parseInt(u16, args[4], 10);

    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    const clear_route = mqtt.socks5_runtime.Route{
        .proxy_host = "127.0.0.1",
        .proxy_port = no_auth_proxy_port,
        .target_host = "broker.internal",
        .target_port = clear_port,
    };
    try std.testing.expectError(
        error.Timeout,
        mqtt.socks5_runtime.Client.connectHostAttemptWithTimeout(
            allocator,
            io,
            clear_route,
            .{ .protocol = .v5, .client_id = "timeout-client" },
            .fromMilliseconds(50),
        ),
    );

    var clear = try mqtt.socks5_runtime.Client.connectHostWithConnAckWithTimeout(
        allocator,
        io,
        clear_route,
        .{ .protocol = .v5, .client_id = "socks-clear" },
        .fromSeconds(3),
    );
    defer clear.deinit(allocator);
    try clear.connection.pingWithTimeout(.fromSeconds(1));
    try clear.connection.disconnect(0);

    var fallback_route = clear_route;
    fallback_route.options.credentials = .{
        .username = "unused",
        .password = "unused",
    };
    var fallback = try mqtt.socks5_runtime.Client
        .connectHostWithConnAckWithTimeout(
        allocator,
        io,
        fallback_route,
        .{ .protocol = .v5, .client_id = "socks-auth-fallback" },
        .fromSeconds(3),
    );
    defer fallback.deinit(allocator);
    try fallback.connection.pingWithTimeout(.fromSeconds(1));
    try fallback.connection.disconnect(0);

    var clear_connector_state = mqtt.socks5_runtime.ReconnectConnector{
        .route = clear_route,
    };
    const clear_connector = clear_connector_state.connector();
    var clear_reconnect_attempt = try clear_connector.connectAttemptWithDeadline(
        allocator,
        io,
        .{ .protocol = .v5, .client_id = "socks-reconnect" },
        .fromNow(io, .{
            .raw = .fromSeconds(3),
            .clock = .awake,
        }),
    );
    var clear_reconnect = try clear_reconnect_attempt.requireAccepted();
    defer clear_reconnect.deinit(allocator);
    try clear_reconnect.connection.pingWithTimeout(.fromSeconds(1));
    try clear_reconnect.connection.disconnect(0);

    const wrong_auth_route = mqtt.socks5_runtime.Route{
        .proxy_host = "127.0.0.1",
        .proxy_port = auth_proxy_port,
        .target_host = "broker.internal",
        .target_port = tls_port,
        .options = .{
            .credentials = .{
                .username = "wrong",
                .password = "credentials",
            },
            .allow_no_authentication = false,
        },
    };
    try std.testing.expectError(
        error.ProxyAuthenticationFailed,
        mqtt.socks5_runtime.Client.connectHostAttemptWithTimeout(
            allocator,
            io,
            wrong_auth_route,
            .{ .protocol = .v5, .client_id = "wrong-auth" },
            .fromSeconds(1),
        ),
    );

    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.addCertsFromFilePathAbsolute(
        allocator,
        io,
        std.Io.Clock.real.now(io),
        args[5],
    );
    var ca_lock: std.Io.RwLock = .init;
    const tls_route = mqtt.socks5_runtime.Route{
        .proxy_host = "127.0.0.1",
        .proxy_port = auth_proxy_port,
        .target_host = "broker.internal",
        .target_port = tls_port,
        .options = .{
            .credentials = .{
                .username = "user",
                .password = "pass:word",
            },
            .allow_no_authentication = false,
        },
    };
    var secure = try mqtt.socks5_runtime.TlsClient
        .connectHostWithConnAckWithTimeout(
        allocator,
        io,
        tls_route,
        .{
            .mqtt = .{ .protocol = .v5, .client_id = "socks-tls" },
            .tls = .{ .ca_bundle = .{
                .bundle = &ca_bundle,
                .lock = &ca_lock,
            } },
        },
        .fromSeconds(5),
    );
    defer secure.deinit(allocator);
    try secure.connection.pingWithTimeout(.fromSeconds(1));
    try secure.connection.disconnect(0);

    var tls_connector_state = mqtt.socks5_runtime.TlsReconnectConnector{
        .route = tls_route,
        .options = .{
            .mqtt = .{ .protocol = .v5, .client_id = "template" },
            .tls = .{ .ca_bundle = .{
                .bundle = &ca_bundle,
                .lock = &ca_lock,
            } },
        },
    };
    const tls_connector = tls_connector_state.connector();
    var tls_reconnect_attempt = try tls_connector.connectAttemptWithDeadline(
        allocator,
        io,
        .{ .protocol = .v5, .client_id = "socks-tls-reconnect" },
        .fromNow(io, .{
            .raw = .fromSeconds(5),
            .clock = .awake,
        }),
    );
    var tls_reconnect = try tls_reconnect_attempt.requireAccepted();
    defer tls_reconnect.deinit(allocator);
    try tls_reconnect.connection.pingWithTimeout(.fromSeconds(1));
    try tls_reconnect.connection.disconnect(0);

    std.debug.print(
        "MQTT SOCKS5 client passed: remote_dns=true no_auth=true " ++
            "auth_fallback=true " ++
            "auth=true auth_failure=true timeout=true reconnect=true " ++
            "tls_reconnect=true tls_verified=true " ++
            "client_io=zio-std-io\n",
        .{},
    );
}
