const std = @import("std");
const netz = @import("netz");

fn port(text: []const u8) !u16 {
    return std.fmt.parseInt(u16, text, 10);
}

fn deadline(io: std.Io, seconds: i64) std.Io.Clock.Timestamp {
    return .fromNow(io, .{
        .raw = .fromSeconds(seconds),
        .clock = .awake,
    });
}

fn authority(
    allocator: std.mem.Allocator,
    target_port: u16,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "origin.internal:{d}",
        .{target_port},
    );
}

fn tunnel(
    allocator: std.mem.Allocator,
    io: std.Io,
    proxy_port: u16,
    target_port: u16,
) !std.Io.net.Stream {
    return netz.proxy.socks5.connectHostWithDeadline(
        allocator,
        io,
        "127.0.0.1",
        proxy_port,
        "origin.internal",
        target_port,
        .{},
        deadline(io, 5),
    );
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 9) return error.InvalidArgument;
    const proxy_port = try port(args[1]);
    const http_port = try port(args[2]);
    const https_port = try port(args[3]);
    const ws_port = try port(args[4]);
    const wss_port = try port(args[5]);
    const mqtt_ws_port = try port(args[6]);
    const mqtt_wss_port = try port(args[7]);

    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.addCertsFromFilePathAbsolute(
        allocator,
        io,
        std.Io.Clock.real.now(io),
        args[8],
    );
    var ca_lock: std.Io.RwLock = .init;
    const tls_options = netz.http1.runtime.TlsClientOptions{
        .ca_bundle = .{ .bundle = &ca_bundle, .lock = &ca_lock },
    };

    {
        const host = try authority(allocator, http_port);
        defer allocator.free(host);
        var client = try netz.http1.runtime.Client.adoptStream(
            allocator,
            io,
            try tunnel(allocator, io, proxy_port, http_port),
            host,
            .{},
        );
        defer client.close();
        var response = try client.requestWithDeadline(
            .{ .target = "/plain" },
            deadline(io, 2),
        );
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), response.response.status);
        try std.testing.expectEqualStrings("http-socks", response.response.body);
    }

    {
        const host = try authority(allocator, https_port);
        defer allocator.free(host);
        var client = try netz.http1.runtime.Client.adoptTlsStreamWithDeadline(
            allocator,
            io,
            try tunnel(allocator, io, proxy_port, https_port),
            "origin.internal",
            host,
            .{},
            tls_options,
            deadline(io, 5),
        );
        defer client.close();
        var response = try client.requestWithDeadline(
            .{ .target = "/secure" },
            deadline(io, 2),
        );
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), response.response.status);
        try std.testing.expectEqualStrings("https-socks", response.response.body);
    }

    try runWebSocket(
        allocator,
        io,
        proxy_port,
        ws_port,
        false,
        tls_options,
        "ws-socks",
    );
    try runWebSocket(
        allocator,
        io,
        proxy_port,
        wss_port,
        true,
        tls_options,
        "wss-socks",
    );
    try runMqttWebSocket(
        allocator,
        io,
        proxy_port,
        mqtt_ws_port,
        false,
        tls_options,
        "mqtt-ws-socks",
    );
    try runMqttWebSocket(
        allocator,
        io,
        proxy_port,
        mqtt_wss_port,
        true,
        tls_options,
        "mqtt-wss-socks",
    );

    std.debug.print(
        "HTTP WebSocket SOCKS5 client passed: http=true https=true " ++
            "ws=true wss=true mqtt_ws=true mqtt_wss=true remote_dns=true " ++
            "tls_hostname=true deadline=true client_io=zio-std-io\n",
        .{},
    );
}

fn runWebSocket(
    allocator: std.mem.Allocator,
    io: std.Io,
    proxy_port: u16,
    target_port: u16,
    secure: bool,
    tls_options: netz.http1.runtime.TlsClientOptions,
    payload: []const u8,
) !void {
    const host = try authority(allocator, target_port);
    defer allocator.free(host);
    const stream = try tunnel(allocator, io, proxy_port, target_port);
    var ws = if (secure)
        try netz.websocket.runtime.Client
            .connectAcceptedTlsStreamWithDeadline(
            allocator,
            io,
            stream,
            "origin.internal",
            .{ .host = host, .target = "/chat" },
            tls_options,
            deadline(io, 5),
        )
    else
        try netz.websocket.runtime.Client.connectAcceptedStreamWithDeadline(
            allocator,
            io,
            stream,
            .{ .host = host, .target = "/chat" },
            deadline(io, 3),
        );
    defer ws.close();
    try ws.sendText(payload);
    var message = try ws.receiveMessageWithTimeout(.fromSeconds(2));
    defer message.deinit(allocator);
    try std.testing.expectEqual(netz.websocket.Opcode.text, message.opcode);
    try std.testing.expectEqualStrings(payload, message.payload);
    var pong = try ws.pingWithTimeout("probe", .fromSeconds(2));
    defer pong.deinit(allocator);
    try std.testing.expect(pong == .pong);
    var closed = try ws.closeWithTimeout(
        .{ .code = .normal_closure, .reason = "done" },
        .fromSeconds(2),
    );
    defer closed.deinit(allocator);
    try std.testing.expect(closed == .closed);
}

fn runMqttWebSocket(
    allocator: std.mem.Allocator,
    io: std.Io,
    proxy_port: u16,
    target_port: u16,
    secure: bool,
    tls_options: netz.http1.runtime.TlsClientOptions,
    client_id: []const u8,
) !void {
    const host = try authority(allocator, target_port);
    defer allocator.free(host);
    const stream = try tunnel(allocator, io, proxy_port, target_port);
    const protocols = [_][]const u8{"mqtt"};
    const ws_options = netz.websocket.runtime.ConnectOptions{
        .host = host,
        .target = "/mqtt",
        .protocols = &protocols,
        .require_subprotocol = true,
    };
    const ws = if (secure)
        try netz.websocket.runtime.Client
            .connectAcceptedTlsStreamWithDeadline(
            allocator,
            io,
            stream,
            "origin.internal",
            ws_options,
            tls_options,
            deadline(io, 5),
        )
    else
        try netz.websocket.runtime.Client.connectAcceptedStreamWithDeadline(
            allocator,
            io,
            stream,
            ws_options,
            deadline(io, 3),
        );
    var mqtt = try netz.mqtt.websocket_runtime.Client
        .adoptWebSocketWithConnAckWithDeadline(
        allocator,
        ws,
        .{ .protocol = .v5, .client_id = client_id },
        deadline(io, 3),
    );
    defer mqtt.deinit(allocator);
    try mqtt.connection.pingWithTimeout(.fromSeconds(2));
    try mqtt.connection.disconnect(0);
}
