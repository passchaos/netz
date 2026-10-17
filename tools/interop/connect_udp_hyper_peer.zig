//! Netz side of the process-boundary RFC 9298 interoperability matrix.

const std = @import("std");
const netz = @import("netz");

const client_payload = [_]u8{0x5a} ** 513;
const server_payload = [_]u8{0xa5} ** 777;
const template_http =
    "http://localhost/.well-known/masque/udp/{target_host}/{target_port}/";
const template_https =
    "https://localhost/.well-known/masque/udp/{target_host}/{target_port}/";

const Mode = enum {
    h1_client,
    h1_server,
    h2_client,
    h2_server,
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 3 or args.len > 4) return error.InvalidArgument;
    const mode: Mode = if (std.mem.eql(u8, args[1], "h1-client"))
        .h1_client
    else if (std.mem.eql(u8, args[1], "h1-server"))
        .h1_server
    else if (std.mem.eql(u8, args[1], "h2-client"))
        .h2_client
    else if (std.mem.eql(u8, args[1], "h2-server"))
        .h2_server
    else
        return error.InvalidArgument;
    const port = try std.fmt.parseUnsigned(u16, args[2], 10);
    if (port == 0) return error.InvalidArgument;
    const tls_enabled = args.len == 4;
    switch (mode) {
        .h1_client, .h2_client => if (tls_enabled and
            !std.Io.Dir.path.isAbsolute(args[3]))
        {
            return error.InvalidArgument;
        },
        .h1_server, .h2_server => if (tls_enabled and
            !std.mem.eql(u8, args[3], "--tls"))
        {
            return error.InvalidArgument;
        },
    }

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    switch (mode) {
        .h1_client => try runH1Client(
            allocator,
            io,
            port,
            if (tls_enabled) args[3] else null,
        ),
        .h1_server => try runH1Server(allocator, io, port, tls_enabled),
        .h2_client => try runH2Client(
            allocator,
            io,
            port,
            if (tls_enabled) args[3] else null,
        ),
        .h2_server => try runH2Server(allocator, io, port, tls_enabled),
    }
}

fn runH1Client(
    allocator: std.mem.Allocator,
    io: std.Io,
    port: u16,
    ca_path: ?[]const u8,
) !void {
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    var ca_lock: std.Io.RwLock = .init;
    if (ca_path) |path| {
        try ca_bundle.addCertsFromFilePathAbsolute(
            allocator,
            io,
            std.Io.Clock.real.now(io),
            path,
        );
    }
    const limits: netz.http1.runtime.Limits = .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
        .response_head_timeout = .fromSeconds(5),
    };
    var client = if (ca_path != null)
        try netz.http1.runtime.Client.connectVailTlsHost(
            allocator,
            io,
            "localhost",
            port,
            limits,
            .{ .ca_bundle = .{
                .bundle = &ca_bundle,
                .lock = &ca_lock,
            } },
        )
    else
        try netz.http1.runtime.Client.connect(
            allocator,
            io,
            .{ .ip4 = .loopback(port) },
            limits,
        );
    defer client.close();
    const template = try netz.http3.connect_udp.UriTemplate.compile(
        if (ca_path != null) template_https else template_http,
    );
    var uri_storage: [256]u8 = undefined;
    var session = try client.openConnectUdpWithTimeout(
        template,
        .{ .host = "dns.example", .port = 53 },
        &.{},
        &uri_storage,
        .fromSeconds(5),
    );
    defer session.deinit();
    try sendExtensionsH1(&session);
    try session.sendWithTimeout(&client_payload, .fromSeconds(5));
    var response_storage: [server_payload.len]u8 = undefined;
    const response = try session.receiveIntoWithTimeout(
        &response_storage,
        .fromSeconds(5),
    );
    try expectPayload(response.payload, &server_payload);
    std.debug.print(
        "netz HTTP/1 CONNECT-UDP client interoperated with Hyper: transport={s} sent={} received={} unknown_capsule=true unknown_context=true\n",
        .{ transportName(ca_path != null), client_payload.len, response.payload.len },
    );
}

fn runH1Server(
    allocator: std.mem.Allocator,
    io: std.Io,
    port: u16,
    tls_enabled: bool,
) !void {
    const limits: netz.http1.runtime.Limits = .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    };
    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const key_pair = try netz.tls.testing.serverKeyPair();
    var clear_server: netz.http1.runtime.Server = undefined;
    var tls_server: netz.http1.runtime.TlsServer = undefined;
    if (tls_enabled) {
        tls_server = try .listen(allocator, io, .{ .ip4 = .loopback(port) }, .{
            .limits = limits,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        });
    } else {
        clear_server = try .listen(
            allocator,
            io,
            .{ .ip4 = .loopback(port) },
            limits,
        );
    }
    defer if (tls_enabled) tls_server.deinit() else clear_server.deinit();
    std.debug.print(
        "netz HTTP/1 CONNECT-UDP server listening transport={s} on {f}\n",
        .{ transportName(tls_enabled), if (tls_enabled) tls_server.address() else clear_server.address() },
    );
    var connection = if (tls_enabled)
        try tls_server.accept()
    else
        try clear_server.accept();
    defer connection.close();
    var request = try connection.readConnectUdpRequestWithTimeout(
        .fromSeconds(5),
    );
    defer request.deinit(allocator);
    var host_storage: [128]u8 = undefined;
    var accepted = try connection.acceptConnectUdpDefault(
        request.request,
        &host_storage,
    );
    defer accepted.session.deinit();
    try expectTarget(accepted.target);
    var incoming = try accepted.session.receiveWithTimeout(.fromSeconds(5));
    defer incoming.deinit(allocator);
    try expectPayload(incoming.payload, &client_payload);
    try sendExtensionsH1(&accepted.session);
    try accepted.session.sendWithTimeout(&server_payload, .fromSeconds(5));
    std.debug.print(
        "netz HTTP/1 CONNECT-UDP server interoperated with Hyper: transport={s} received={} sent={} unknown_capsule=true unknown_context=true\n",
        .{ transportName(tls_enabled), incoming.payload.len, server_payload.len },
    );
}

fn runH2Client(
    allocator: std.mem.Allocator,
    io: std.Io,
    port: u16,
    ca_path: ?[]const u8,
) !void {
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    var ca_lock: std.Io.RwLock = .init;
    if (ca_path) |path| {
        try ca_bundle.addCertsFromFilePathAbsolute(
            allocator,
            io,
            std.Io.Clock.real.now(io),
            path,
        );
    }
    const limits: netz.http2.runtime.Limits = .{
        .max_frame_payload = 128,
        .max_body_bytes = 128 * 1024,
        .handshake_timeout = .fromSeconds(5),
    };
    var client = if (ca_path != null)
        try netz.http2.runtime.Client.connectTlsHost(
            allocator,
            io,
            "localhost",
            port,
            limits,
            .{ .ca_bundle = .{
                .bundle = &ca_bundle,
                .lock = &ca_lock,
            } },
        )
    else
        try netz.http2.runtime.Client.connect(
            allocator,
            io,
            .{ .ip4 = .loopback(port) },
            limits,
        );
    defer client.close();
    const template = try netz.http3.connect_udp.UriTemplate.compile(
        template_https,
    );
    var path_storage: [192]u8 = undefined;
    var session = try client.openConnectUdpWithTimeout(
        template,
        .{ .host = "dns.example", .port = 53 },
        &.{},
        &path_storage,
        .fromSeconds(5),
    );
    defer session.deinit();
    try sendExtensionsH2(&session);
    try session.sendWithTimeout(&client_payload, .fromSeconds(5));
    var response_storage: [server_payload.len]u8 = undefined;
    const response = try session.receiveIntoWithTimeout(
        &response_storage,
        .fromSeconds(5),
    );
    try expectPayload(response.payload, &server_payload);
    std.debug.print(
        "netz HTTP/2 CONNECT-UDP client interoperated with Hyper: transport={s} sent={} received={} settings_enable_connect_protocol=true unknown_capsule=true unknown_context=true\n",
        .{ transportName(ca_path != null), client_payload.len, response.payload.len },
    );
}

fn runH2Server(
    allocator: std.mem.Allocator,
    io: std.Io,
    port: u16,
    tls_enabled: bool,
) !void {
    const limits: netz.http2.runtime.Limits = .{
        .enable_connect_protocol = true,
        .max_frame_payload = 128,
        .max_body_bytes = 128 * 1024,
        .handshake_timeout = .fromSeconds(5),
    };
    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const key_pair = try netz.tls.testing.serverKeyPair();
    var clear_server: netz.http2.runtime.Server = undefined;
    var tls_server: netz.http2.runtime.TlsServer = undefined;
    if (tls_enabled) {
        tls_server = try .listen(allocator, io, .{ .ip4 = .loopback(port) }, .{
            .limits = limits,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        });
    } else {
        clear_server = try .listen(
            allocator,
            io,
            .{ .ip4 = .loopback(port) },
            limits,
        );
    }
    defer if (tls_enabled) tls_server.deinit() else clear_server.deinit();
    std.debug.print(
        "netz HTTP/2 CONNECT-UDP server listening transport={s} on {f}\n",
        .{ transportName(tls_enabled), if (tls_enabled) tls_server.address() else clear_server.address() },
    );
    var connection = if (tls_enabled)
        try tls_server.accept()
    else
        try clear_server.accept();
    defer connection.close();
    var request = try connection.readConnectUdpRequestWithTimeout(
        .fromSeconds(5),
    );
    defer request.deinit(allocator);
    var host_storage: [128]u8 = undefined;
    var accepted = try connection.acceptConnectUdpDefault(
        request,
        &host_storage,
    );
    defer accepted.session.deinit();
    try expectTarget(accepted.target);
    var incoming = try accepted.session.receiveWithTimeout(.fromSeconds(5));
    defer incoming.deinit(allocator);
    try expectPayload(incoming.payload, &client_payload);
    try sendExtensionsH2(&accepted.session);
    try accepted.session.sendWithTimeout(&server_payload, .fromSeconds(5));
    std.debug.print(
        "netz HTTP/2 CONNECT-UDP server interoperated with Hyper: transport={s} received={} sent={} settings_enable_connect_protocol=true unknown_capsule=true unknown_context=true\n",
        .{ transportName(tls_enabled), incoming.payload.len, server_payload.len },
    );
}

fn sendExtensionsH1(
    session: *netz.http1.runtime.ConnectUdpSession,
) !void {
    var capsule_storage: [64]u8 = undefined;
    const unknown_capsule = try netz.http3.capsule.writeInto(
        &capsule_storage,
        0x21,
        "unknown-capsule",
    );
    try session.tunnel.inner.write(unknown_capsule);
    var context_storage: [64]u8 = undefined;
    const context = try (netz.http3.connect_udp.ContextDatagram{
        .context_id = 2,
        .payload = "unknown-context",
    }).writeInto(&context_storage);
    const datagram = try netz.http3.capsule.writeDatagramInto(
        &capsule_storage,
        context,
    );
    try session.tunnel.inner.write(datagram);
}

fn sendExtensionsH2(
    session: *netz.http2.runtime.ConnectUdpSession,
) !void {
    var capsule_storage: [64]u8 = undefined;
    const unknown_capsule = try netz.http3.capsule.writeInto(
        &capsule_storage,
        0x21,
        "unknown-capsule",
    );
    try session.tunnel.write(unknown_capsule, false);
    var context_storage: [64]u8 = undefined;
    const context = try (netz.http3.connect_udp.ContextDatagram{
        .context_id = 2,
        .payload = "unknown-context",
    }).writeInto(&context_storage);
    const datagram = try netz.http3.capsule.writeDatagramInto(
        &capsule_storage,
        context,
    );
    try session.tunnel.write(datagram, false);
}

fn expectTarget(target: netz.http3.connect_udp.Target) !void {
    if (!std.mem.eql(u8, target.host, "dns.example") or target.port != 53) {
        return error.InvalidTarget;
    }
}

fn expectPayload(actual: []const u8, expected: []const u8) !void {
    if (!std.mem.eql(u8, actual, expected)) return error.InvalidPayload;
}

fn transportName(tls_enabled: bool) []const u8 {
    return if (tls_enabled) "tls" else "cleartext";
}
