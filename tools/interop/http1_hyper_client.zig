//! One-shot netz HTTP/1.1 client for process-boundary interoperability with
//! the audited local Hyper server.

const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2 and args.len != 3) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;
    const tls_enabled = args.len == 3;
    if (tls_enabled and !std.Io.Dir.path.isAbsolute(args[2])) {
        return error.InvalidArgument;
    }

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    var ca_lock: std.Io.RwLock = .init;
    if (tls_enabled) {
        try ca_bundle.addCertsFromFilePathAbsolute(
            allocator,
            io,
            std.Io.Clock.real.now(io),
            args[2],
        );
    }

    // Exercise the production response deadline against Hyper on every
    // aggregate, streaming, informational, Expect and tunnel handshake below.
    // The generous value is a liveness guard, not a latency assertion.
    const limits: netz.http1.runtime.Limits = .{
        .max_body_bytes = 4096,
        .response_head_timeout = .fromSeconds(5),
    };
    std.debug.print("response_head_timeout=5000ms\n", .{});

    var client = try connect(
        allocator,
        io,
        port,
        limits,
        tls_enabled,
        &ca_bundle,
        &ca_lock,
    );
    defer client.close();
    if (tls_enabled) {
        const chain = client.peerCertificates() orelse
            return error.MissingPeerCertificate;
        if (chain.len == 0 or
            client.negotiatedCipherSuite() == null or
            client.negotiatedTranscriptHash() == null)
        {
            return error.InvalidTlsMetadata;
        }
    }

    var writer = try client.startRequest(.{
        .method = .POST,
        .target = "/interop?from=netz",
        .host = "localhost",
        .headers = &.{
            .{
                .name = "X-Netz-Request",
                .value = "request-header",
            },
            .{ .name = "TE", .value = "trailers" },
        },
        .trailer_names = &.{"X-Netz-Trailer"},
    });
    defer writer.deinit();
    try writer.writeChunks(&.{ "netz-", "request" });
    try writer.finishTrailers(&.{.{
        .name = "X-Netz-Trailer",
        .value = "request-trailer",
    }});
    var response = try writer.readResponse();
    defer response.deinit(allocator);
    if (response.response.status != 201 or
        !std.mem.eql(u8, response.response.body, "hyper-response") or
        !headerEquals(response.response.headers, "x-hyper-response", "response-header") or
        !headerEquals(response.response.trailers, "x-hyper-trailer", "response-trailer"))
    {
        std.debug.print(
            "unexpected Hyper response: status={d} body={s} headers={d} trailers={d}\n",
            .{
                response.response.status,
                response.response.body,
                response.response.headers.len,
                response.response.trailers.len,
            },
        );
        for (response.response.headers) |header| {
            std.debug.print("header {s}: {s}\n", .{ header.name, header.value });
        }
        for (response.response.trailers) |header| {
            std.debug.print("trailer {s}: {s}\n", .{ header.name, header.value });
        }
        return error.InvalidResponse;
    }
    std.debug.print(
        "netz HTTP/1 client interoperated with Hyper: transport={s} status=201 body=14 trailers=1\n",
        .{if (tls_enabled) "tls" else "cleartext"},
    );
    if (tls_enabled) {
        const updates = client.keyUpdateCounts() orelse
            return error.MissingKeyUpdate;
        if (updates.received != 1 or updates.sent != 1 or
            updates.awaiting_peer_response)
        {
            return error.InvalidKeyUpdateCount;
        }
        std.debug.print(
            "netz HTTP/1 client interoperated with rustls KeyUpdate: received=1 sent=1 next_request=true\n",
            .{},
        );
    }

    var extension_response = try client.request(.{
        .method = try netz.http1.Method.parse("PURGE"),
        .target = "/extension?from=netz",
        .host = "localhost",
    });
    defer extension_response.deinit(allocator);
    if (extension_response.response.status != 200 or
        !std.mem.eql(
            u8,
            extension_response.response.body,
            "hyper-extension",
        ))
    {
        return error.InvalidExtensionMethodResponse;
    }
    std.debug.print(
        "netz HTTP/1 client sent extension method to Hyper: transport={s} method=PURGE response_body=15\n",
        .{if (tls_enabled) "tls" else "cleartext"},
    );

    // Hyper's public `on_informational` API has a netz counterpart. Exercise
    // more than status skipping: validate both borrowed 103/102 header blocks
    // in order before accepting the final response on the same connection.
    var informational_client = try connect(
        allocator,
        io,
        port,
        limits,
        tls_enabled,
        &ca_bundle,
        &ca_lock,
    );
    defer informational_client.close();
    const Informational = struct {
        statuses: [2]u16 = undefined,
        count: usize = 0,

        fn observe(
            raw: *anyopaque,
            head: netz.http1.runtime.InformationalResponseHead,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (self.count >= self.statuses.len) {
                @panic("too many informational responses");
            }
            self.statuses[self.count] = head.status;
            if (head.status == 103 and !headerEquals(
                head.headers,
                "link",
                "</asset.css>; rel=preload",
            )) @panic("unexpected Early Hints Link");
            if (head.status == 102 and !headerEquals(
                head.headers,
                "x-hyper-progress",
                "accepted",
            )) @panic("unexpected Processing metadata");
            self.count += 1;
        }
    };
    var informational = Informational{};
    var informational_response =
        try informational_client.requestWithInformational(
            .{
                .target = "/informational?from=netz",
                .host = "localhost",
            },
            .{
                .context = &informational,
                .on_response = Informational.observe,
            },
        );
    defer informational_response.deinit(allocator);
    if (informational.count != 2 or
        !std.mem.eql(u16, &informational.statuses, &.{ 103, 102 }) or
        informational_response.response.status != 200 or
        !std.mem.eql(
            u8,
            informational_response.response.body,
            "hyper-informational",
        ))
    {
        return error.InvalidInformationalResponse;
    }
    std.debug.print(
        "netz HTTP/1 client observed Hyper informational responses: transport={s} statuses=103,102 headers=2 final=200 body=19\n",
        .{if (tls_enabled) "tls" else "cleartext"},
    );

    // Use a fresh connection so the first scenario's Hyper service lifecycle
    // cannot accidentally satisfy this request. Only send the declared body
    // after Hyper has emitted its automatic interim response.
    var expect_client = try connect(
        allocator,
        io,
        port,
        limits,
        tls_enabled,
        &ca_bundle,
        &ca_lock,
    );
    defer expect_client.close();
    var expect_writer = try expect_client.startRequest(.{
        .method = .POST,
        .target = "/expect?from=netz",
        .host = "localhost",
        .headers = &.{.{
            .name = "Expect",
            .value = "100-continue",
        }},
        .body_length = "netz-expect".len,
    });
    defer expect_writer.deinit();
    switch (try expect_writer.waitForContinue()) {
        .proceed => {},
        .final_response => |response_value| {
            var early_response = response_value;
            early_response.deinit(allocator);
            return error.ExpectedContinue;
        },
    }
    try expect_writer.write("netz-expect");
    try expect_writer.finish();
    var continued = try expect_writer.readResponse();
    defer continued.deinit(allocator);
    if (continued.response.status != 200 or
        !std.mem.eql(u8, continued.response.body, "hyper-continued") or
        !headerEquals(
            continued.response.headers,
            "x-hyper-continue",
            "observed",
        ))
    {
        return error.InvalidContinueResponse;
    }
    std.debug.print(
        "netz HTTP/1 client observed Hyper 100 Continue: transport={s} interim=1 body=11 response_body=15\n",
        .{if (tls_enabled) "tls" else "cleartext"},
    );

    {
        var hints_client = try connect(
            allocator,
            io,
            port,
            limits,
            tls_enabled,
            &ca_bundle,
            &ca_lock,
        );
        defer hints_client.close();
        var hints_writer = try hints_client.startRequest(.{
            .method = .POST,
            .target = "/expect-hints?from=netz",
            .host = "localhost",
            .headers = &.{.{
                .name = "Expect",
                .value = "100-continue",
            }},
            .body_length = "netz-hints".len,
        });
        defer hints_writer.deinit();
        switch (try hints_writer.waitForContinue()) {
            .proceed => {},
            .final_response => |response_value| {
                var early_response = response_value;
                early_response.deinit(allocator);
                return error.ExpectedContinue;
            },
        }
        try hints_writer.write("netz-hints");
        try hints_writer.finish();
        var hints_response = try hints_writer.readResponse();
        defer hints_response.deinit(allocator);
        if (hints_response.response.status != 200 or
            !std.mem.eql(
                u8,
                hints_response.response.body,
                "hyper-hints-ok",
            ))
        {
            return error.InvalidContinueResponse;
        }
    }

    {
        var reject_client = try connect(
            allocator,
            io,
            port,
            limits,
            tls_enabled,
            &ca_bundle,
            &ca_lock,
        );
        defer reject_client.close();
        var reject_writer = try reject_client.startRequest(.{
            .method = .POST,
            .target = "/expect-reject?from=netz",
            .host = "localhost",
            .headers = &.{.{
                .name = "Expect",
                .value = "100-continue",
            }},
            .body_length = "netz-reject".len,
        });
        defer reject_writer.deinit();
        switch (try reject_writer.waitForContinue()) {
            .proceed => return error.UnexpectedContinue,
            .final_response => |response_value| {
                var rejected = response_value;
                defer rejected.deinit(allocator);
                if (rejected.response.status != 417 or
                    !std.mem.eql(u8, rejected.response.body, "rejected"))
                {
                    return error.InvalidEarlyResponse;
                }
            },
        }
        try std.testing.expectError(
            error.InvalidWriterState,
            reject_writer.write("netz-reject"),
        );
        try std.testing.expectError(
            error.ConnectionUnusable,
            reject_client.request(.{
                .target = "/must-not-reuse",
                .host = "localhost",
            }),
        );
    }

    std.debug.print(
        "netz HTTP/1 client handled Hyper/Tokio Expect boundaries: transport={s} informational=103,100 early_final=417 body_sent=0 connection_reusable=false\n",
        .{if (tls_enabled) "tls" else "cleartext"},
    );

    var tunnel_client = try connect(
        allocator,
        io,
        port,
        limits,
        tls_enabled,
        &ca_bundle,
        &ca_lock,
    );
    defer tunnel_client.close();
    var tunnel = try tunnel_client.openConnectTunnel(
        "tunnel.example:443",
        &.{},
    );
    var initial: [18]u8 = undefined;
    var initial_len: usize = 0;
    while (initial_len < initial.len) {
        const count = try tunnel.read(initial[initial_len..]);
        if (count == 0) return error.ConnectionClosed;
        initial_len += count;
    }
    if (!std.mem.eql(u8, &initial, "hyper tunnel ready")) {
        return error.InvalidTunnelResponse;
    }
    try tunnel.write("netz tunnel bytes");
    var reply: [18]u8 = undefined;
    var reply_len: usize = 0;
    while (reply_len < reply.len) {
        const count = try tunnel.read(reply[reply_len..]);
        if (count == 0) return error.ConnectionClosed;
        reply_len += count;
    }
    if (!std.mem.eql(u8, &reply, "hyper tunnel reply")) {
        return error.InvalidTunnelResponse;
    }
    std.debug.print(
        "netz HTTP/1 client interoperated with Hyper CONNECT tunnel: transport={s} buffered_server_bytes=18 client_bytes=17 reply_bytes=18\n",
        .{if (tls_enabled) "tls" else "cleartext"},
    );

    var upgrade_client = try connect(
        allocator,
        io,
        port,
        limits,
        tls_enabled,
        &ca_bundle,
        &ca_lock,
    );
    defer upgrade_client.close();
    var upgrade = try upgrade_client.openUpgrade(
        "/upgrade?from=netz",
        "localhost",
        "netz-test",
        &.{},
    );
    var upgrade_preface: [19]u8 = undefined;
    var upgrade_preface_len: usize = 0;
    while (upgrade_preface_len < upgrade_preface.len) {
        const count = try upgrade.read(
            upgrade_preface[upgrade_preface_len..],
        );
        if (count == 0) return error.ConnectionClosed;
        upgrade_preface_len += count;
    }
    if (!std.mem.eql(u8, &upgrade_preface, "hyper upgrade ready")) {
        return error.InvalidUpgradeResponse;
    }
    try upgrade.write("netz upgrade bytes");
    var upgrade_reply: [19]u8 = undefined;
    var upgrade_reply_len: usize = 0;
    while (upgrade_reply_len < upgrade_reply.len) {
        const count = try upgrade.read(upgrade_reply[upgrade_reply_len..]);
        if (count == 0) return error.ConnectionClosed;
        upgrade_reply_len += count;
    }
    if (!std.mem.eql(u8, &upgrade_reply, "hyper upgrade reply")) {
        return error.InvalidUpgradeResponse;
    }
    std.debug.print(
        "netz HTTP/1 client interoperated with Hyper generic Upgrade: transport={s} buffered_server_bytes=19 client_bytes=18 reply_bytes=19\n",
        .{if (tls_enabled) "tls" else "cleartext"},
    );

    var pool = try netz.http1.client_pool.Pool.init(
        allocator,
        io,
        .{
            .limits = limits,
            .tls = .{
                .ca_bundle = if (tls_enabled) .{
                    .bundle = &ca_bundle,
                    .lock = &ca_lock,
                } else null,
            },
        },
    );
    defer pool.deinit();
    const pool_scheme = if (tls_enabled) "https" else "http";
    const pool_one_uri = try std.fmt.allocPrint(
        allocator,
        "{s}://localhost:{d}/pool-one?from=netz",
        .{ pool_scheme, port },
    );
    defer allocator.free(pool_one_uri);
    const pool_two_uri = try std.fmt.allocPrint(
        allocator,
        "{s}://LOCALHOST:{d}/pool-two?from=netz",
        .{ pool_scheme, port },
    );
    defer allocator.free(pool_two_uri);
    var pool_one = try pool.requestUri(pool_one_uri, .{});
    defer pool_one.deinit(allocator);
    var pool_two = try pool.requestUri(pool_two_uri, .{});
    defer pool_two.deinit(allocator);
    if (!std.mem.eql(u8, pool_one.response.body, "pool-one") or
        !std.mem.eql(u8, pool_two.response.body, "pool-two") or
        pool.idleCount() != 1)
    {
        return error.InvalidPooledResponse;
    }
    std.debug.print(
        "netz HTTP/1 pool reused Hyper connection: transport={s} requests=2 idle=1 client_io=zio-std-io server_io=hyper-tokio\n",
        .{if (tls_enabled) "tls" else "cleartext"},
    );
}

fn connect(
    allocator: std.mem.Allocator,
    io: std.Io,
    port: u16,
    limits: netz.http1.runtime.Limits,
    tls_enabled: bool,
    ca_bundle: *std.crypto.Certificate.Bundle,
    ca_lock: *std.Io.RwLock,
) !netz.http1.runtime.Client {
    if (tls_enabled) {
        return netz.http1.runtime.Client.connectVailTlsHost(
            allocator,
            io,
            "localhost",
            port,
            limits,
            .{ .ca_bundle = .{
                .bundle = ca_bundle,
                .lock = ca_lock,
            } },
        );
    }
    return netz.http1.runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        limits,
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
