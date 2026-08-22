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
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
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
    const limits: netz.http1.runtime.Limits = .{ .max_body_bytes = 4096 };
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
        return netz.http1.runtime.Client.connectTlsHost(
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
