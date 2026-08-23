//! One-shot netz HTTP/1.1 server for process-boundary interoperability with
//! the audited local Hyper client.

const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2 and args.len != 3) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;
    const tls_enabled = args.len == 3 and
        std.mem.eql(u8, args[2], "--tls");
    if (args.len == 3 and !tls_enabled) return error.InvalidArgument;

    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const limits: netz.http1.runtime.Limits = .{ .max_body_bytes = 4096 };
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
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
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
        "netz HTTP/1 Hyper interop server listening transport={s} on {f}\n",
        .{ if (tls_enabled) "tls" else "cleartext", if (tls_enabled) tls_server.address() else clear_server.address() },
    );

    var connection = if (tls_enabled)
        try tls_server.accept()
    else
        try clear_server.accept();
    defer connection.close();
    var request = try connection.readRequest(.{});
    defer request.deinit(allocator);
    if (request.request.method != .POST or
        !std.mem.eql(u8, request.request.target, "/interop?from=hyper") or
        !std.mem.eql(u8, request.request.body, "hyper-request") or
        !headerEquals(request.request.headers, "x-hyper-request", "request-header") or
        !headerEquals(request.request.trailers, "x-hyper-trailer", "request-trailer"))
    {
        return error.InvalidRequest;
    }

    var response = try connection.startResponse(.{
        .status = 201,
        .reason = "Created",
        .headers = &.{.{
            .name = "X-Netz-Response",
            .value = "response-header",
        }},
        .trailer_names = &.{"X-Netz-Trailer"},
        .request_method = request.request.method,
    });
    defer response.deinit();
    try response.writeChunks(&.{ "netz-", "response" });
    try response.finishTrailers(&.{.{
        .name = "X-Netz-Trailer",
        .value = "response-trailer",
    }});
    std.debug.print(
        "netz HTTP/1 server interoperated with Hyper: transport={s} method=POST body=13 trailers=1 status=201 response_body=13 response_trailers=1\n",
        .{if (tls_enabled) "tls" else "cleartext"},
    );

    // Reuse the connection for a second exchange. readRequest() emits the
    // interim response after a valid Expect head and before it blocks for the
    // fixed-size body, which Hyper records through its informational callback.
    var expected = try connection.readRequest(.{});
    defer expected.deinit(allocator);
    if (expected.request.method != .POST or
        !std.mem.eql(u8, expected.request.target, "/expect?from=hyper") or
        !std.mem.eql(u8, expected.request.body, "hyper-expect") or
        !headerEquals(
            expected.request.headers,
            "expect",
            "100-continue",
        ))
    {
        return error.InvalidExpectRequest;
    }
    try connection.writeResponse(.{
        .headers = &.{.{
            .name = "X-Netz-Continue",
            .value = "observed",
        }},
        .body = "netz-continued",
        .request_method = expected.request.method,
    });
    std.debug.print(
        "netz HTTP/1 server completed Hyper Expect exchange: transport={s} interim=1 body=12 response_body=14\n",
        .{if (tls_enabled) "tls" else "cleartext"},
    );

    var graceful_connection = if (tls_enabled)
        try tls_server.accept()
    else
        try clear_server.accept();
    defer graceful_connection.close();
    const GracefulContext = struct {
        connection: *netz.http1.runtime.Connection,

        fn handle(
            self: *@This(),
            graceful_request: netz.http1.Request,
        ) netz.http1.runtime.Error!netz.http1.runtime.ResponseOptions {
            if (graceful_request.method != .GET or
                !std.mem.eql(
                    u8,
                    graceful_request.target,
                    "/graceful?from=hyper",
                ))
            {
                return error.InvalidResponse;
            }
            self.connection.gracefulShutdown();
            return .{ .body = "netz-graceful" };
        }
    };
    var graceful_context = GracefulContext{
        .connection = &graceful_connection,
    };
    const graceful_served = try graceful_connection.serve(
        &graceful_context,
        GracefulContext.handle,
        4,
    );
    if (graceful_served != 1) return error.InvalidResponse;
    std.debug.print(
        "netz HTTP/1 server gracefully drained Hyper: transport={s} active_response=true connection_close=true next_request=false\n",
        .{if (tls_enabled) "tls" else "cleartext"},
    );

    var connect_request = try connection.readRequest(.{});
    defer connect_request.deinit(allocator);
    if (connect_request.request.method != .CONNECT or
        !std.mem.eql(
            u8,
            connect_request.request.target,
            "tunnel.example:443",
        ) or
        !headerEquals(
            connect_request.request.headers,
            "host",
            "tunnel.example:443",
        ))
    {
        return error.InvalidConnectRequest;
    }
    var tunnel = try connection.acceptConnectTunnel(
        connect_request.request,
        &.{},
    );
    // Write before reading so Hyper must preserve bytes received immediately
    // after the successful CONNECT response while handing off its HTTP parser.
    try tunnel.write("netz tunnel ready");
    var payload: [18]u8 = undefined;
    var payload_len: usize = 0;
    while (payload_len < payload.len) {
        const count = try tunnel.read(payload[payload_len..]);
        if (count == 0) return error.ConnectionClosed;
        payload_len += count;
    }
    if (!std.mem.eql(u8, &payload, "hyper tunnel bytes")) {
        return error.InvalidTunnelPayload;
    }
    try tunnel.write("netz tunnel reply");
    std.debug.print(
        "netz HTTP/1 server interoperated with Hyper CONNECT tunnel: transport={s} server_preface=17 client_bytes=18 reply_bytes=17\n",
        .{if (tls_enabled) "tls" else "cleartext"},
    );

    var upgrade_connection = if (tls_enabled)
        try tls_server.accept()
    else
        try clear_server.accept();
    defer upgrade_connection.close();
    var upgrade_request = try upgrade_connection.readRequest(.{});
    defer upgrade_request.deinit(allocator);
    if (upgrade_request.request.method != .GET or
        !std.mem.eql(
            u8,
            upgrade_request.request.target,
            "/upgrade?from=hyper",
        ) or
        upgrade_request.request.upgradeProtocol() == null or
        !std.ascii.eqlIgnoreCase(
            upgrade_request.request.upgradeProtocol().?,
            "netz-test",
        ))
    {
        return error.InvalidUpgradeRequest;
    }
    var upgrade = try upgrade_connection.acceptUpgrade(
        upgrade_request.request,
        "netz-test",
        &.{},
    );
    try upgrade.write("netz upgrade ready");
    var upgrade_payload: [19]u8 = undefined;
    var upgrade_payload_len: usize = 0;
    while (upgrade_payload_len < upgrade_payload.len) {
        const count = try upgrade.read(
            upgrade_payload[upgrade_payload_len..],
        );
        if (count == 0) return error.ConnectionClosed;
        upgrade_payload_len += count;
    }
    if (!std.mem.eql(u8, &upgrade_payload, "hyper upgrade bytes")) {
        return error.InvalidUpgradePayload;
    }
    try upgrade.write("netz upgrade reply");
    std.debug.print(
        "netz HTTP/1 server interoperated with Hyper generic Upgrade: transport={s} protocol=netz-test server_preface=18 client_bytes=19 reply_bytes=18\n",
        .{if (tls_enabled) "tls" else "cleartext"},
    );
}

fn headerEquals(
    headers: []const netz.http1.Header,
    name: []const u8,
    value: []const u8,
) bool {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) {
            return std.mem.eql(u8, header.value, value);
        }
    }
    return false;
}
