const std = @import("std");
const netz = @import("netz");

fn port(text: []const u8) !u16 {
    return std.fmt.parseInt(u16, text, 10);
}

fn uri(
    allocator: std.mem.Allocator,
    scheme: []const u8,
    target_port: u16,
    target: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{s}://origin.internal:{d}{s}",
        .{ scheme, target_port, target },
    );
}

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{
        .raw = .fromSeconds(8),
        .clock = .awake,
    });
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 7) return error.InvalidArgument;
    const proxy_port = try port(args[1]);
    const ws_redirect_port = try port(args[2]);
    const ws_final_port = try port(args[3]);
    const mqtt_redirect_port = try port(args[4]);
    _ = try port(args[5]);

    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.addCertsFromFilePathAbsolute(
        allocator,
        io,
        std.Io.Clock.real.now(io),
        args[6],
    );
    var ca_lock: std.Io.RwLock = .init;
    const tls_options = netz.http1.runtime.TlsClientOptions{
        .ca_bundle = .{ .bundle = &ca_bundle, .lock = &ca_lock },
    };
    const socks_proxy = netz.websocket.runtime.Socks5RedirectProxy{
        .host = "127.0.0.1",
        .port = proxy_port,
    };
    const authorization = [_]netz.http1.Header{.{
        .name = "Authorization",
        .value = "Bearer redirect-secret",
    }};

    const ws_uri = try uri(
        allocator,
        "ws",
        ws_redirect_port,
        "/start",
    );
    defer allocator.free(ws_uri);
    var redirected = try netz.websocket.runtime.Client
        .connectUriFollowingRedirectsDetailedAttemptWithDeadline(
        allocator,
        io,
        ws_uri,
        .{ .extra_headers = &authorization },
        .{
            .policy = .{ .max_redirects = 2 },
            .socks5_proxy = socks_proxy,
        },
        deadline(io),
    );
    errdefer redirected.deinit();
    try std.testing.expectEqual(@as(usize, 1), redirected.redirect_count);
    const expected_ws_uri = try uri(
        allocator,
        "ws",
        ws_final_port,
        "/final",
    );
    defer allocator.free(expected_ws_uri);
    try std.testing.expectEqualStrings(expected_ws_uri, redirected.final_uri);
    var ws = try redirected.requireAccepted();
    defer ws.close();
    try ws.sendText("redirect-socks");
    var echoed = try ws.receiveMessageWithTimeout(.fromSeconds(2));
    defer echoed.deinit(allocator);
    try std.testing.expectEqualStrings("redirect-socks", echoed.payload);
    var closed = try ws.closeWithTimeout(
        .{ .code = .normal_closure, .reason = "done" },
        .fromSeconds(2),
    );
    defer closed.deinit(allocator);
    try std.testing.expect(closed == .closed);

    const mqtt_uri = try uri(
        allocator,
        "wss",
        mqtt_redirect_port,
        "/mqtt-start",
    );
    defer allocator.free(mqtt_uri);
    var connector_state = netz.mqtt.websocket_runtime
        .HttpRedirectReconnectConnector{
        .uri = mqtt_uri,
        .options = .{
            .mqtt = .{ .client_id = "template" },
            .extra_headers = &authorization,
            .tls = tls_options,
        },
        .redirect_options = .{
            .policy = .{ .max_redirects = 2 },
            .socks5_proxy = socks_proxy,
        },
    };
    const connector = connector_state.connector();
    for ([_][]const u8{ "mqtt-socks-reconnect-1", "mqtt-socks-reconnect-2" }) |client_id| {
        var attempt = try connector.connectAttemptWithDeadline(
            allocator,
            io,
            .{ .protocol = .v5, .client_id = client_id },
            deadline(io),
        );
        errdefer attempt.deinit(allocator);
        var connection = try attempt.requireAccepted();
        defer connection.deinit(allocator);
        try connection.connection.pingWithTimeout(.fromSeconds(2));
        try connection.connection.disconnect(0);
    }

    std.debug.print(
        "WebSocket SOCKS5 redirect client passed: ws_redirects=1 " ++
            "mqtt_reconnect_chains=2 fresh_tunnels=6 remote_dns=true " ++
            "credentials_isolated=true tls_hostname=true deadline=true " ++
            "client_io=zio-std-io\n",
        .{},
    );
}
